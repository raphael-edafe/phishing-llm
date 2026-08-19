import os
import re
from dataclasses import dataclass
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field 
from openai import OpenAI, OpenAIError

from domain_check import check as domain_check


# reads the .env file and loads its variables into this process's environment
# (they disappear when the script exits - nothing is set system-wide)
load_dotenv()

# pulls api key from environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# fail early with a clear message rather than letting the API call fail later
# with a confusing authentication error. this has to come BEFORE the client is
# created, or the SDK raises its own error first and this never runs.
if not OPENAI_API_KEY:
    raise SystemExit(
        "OPENAI_API_KEY not found. Create a file named '.env' in this folder "
        "containing:\n  OPENAI_API_KEY=sk-your-key-here"
    )

# initialize the OpenAI client
client = OpenAI(api_key=OPENAI_API_KEY)


class Flag(BaseModel):
    """One indicator, paired with the text that demonstrates it.

    The quote is what makes an indicator checkable rather than asserted - the
    UI locates it in the email and highlights it, so a reader can see the
    evidence instead of taking the description on trust. It also constrains the
    model: it is harder to invent 'generic greeting' for an email addressed by
    name when a verbatim quote has to be produced alongside it.
    """
    description: str = Field(
        description="One concrete observation in a short phrase of about 3-8 "
                    "words, e.g. 'sender domain mismatches claimed brand' or "
                    "'threatens account closure within 24 hours'. Describe what "
                    "is actually in this email rather than naming a generic "
                    "category."
    )
    quote: str = Field(
        description="The exact text from the email that demonstrates this "
                    "indicator, copied VERBATIM - same words, same spelling, "
                    "same punctuation, character for character. Keep it short: "
                    "a few words up to one sentence. Do not paraphrase, do not "
                    "summarise, do not correct spelling. If the indicator comes "
                    "from a header, quote the header line. If no exact text can "
                    "be quoted, do not report the indicator at all."
    )


# defines the shape of the model's *response*, not the request we send.
# pydantic converts these annotations into a JSON schema that goes out with
# the request, and the API is then constrained to produce matching JSON.
class PhishingAnalysis(BaseModel):
    # spam and phishing are separate axes, not points on one scale: an advert
    # is unwanted but honest, a spear-phish is deceptive but not bulk at all.
    # a single risk_score kept conflating them, so the kind of email is now its
    # own field. Literal compiles to a JSON schema ENUM, so the API is
    # constrained to exactly these three strings - no free-text drift.
    category: Literal["legitimate", "spam", "phishing"] = Field(
        description="legitimate = mail the recipient wants, INCLUDING bulk "
                    "mail they signed up for: mailing list posts, forum and "
                    "discussion threads, subscribed newsletters, RSS digests, "
                    "automated notifications. Being sent to many people does "
                    "not make mail spam if the recipient asked for it. "
                    "spam = bulk mail the recipient did NOT ask for - "
                    "advertising, promotions, mass mailings - with no attempt "
                    "to deceive or steal. "
                    "phishing = an attempt to steal credentials, money, or "
                    "data through deception or impersonation. An unwanted "
                    "advert is spam, not phishing, however annoying it is."
    )
    risk_score: float = Field(
        description="How dangerous this email is as a PHISHING attempt "
                    "specifically, from 0.00 (certainly harmless) to 1.00 "
                    "(certainly phishing). Unsolicited advertising is not "
                    "dangerous in this sense and should score low even though "
                    "it is unwanted. Give it to two decimal places, and use "
                    "the full range - 0.15 and 0.35 are meaningfully different "
                    "judgements, so do not round to the nearest 0.1."
    )
    flags: list[Flag] = Field(
        description="Specific phishing indicators found in this email, each "
                    "paired with the verbatim text that demonstrates it. "
                    "Return an empty list if the email shows no indicators."
    )
    verdict: str = Field(
        description="A single sentence summarising the assessment and the "
                    "main reason for it. For example: 'Almost certainly a "
                    "credential-phishing attempt impersonating PayPal, given "
                    "the lookalike domain and the 24-hour account closure "
                    "threat.' Do not exceed one sentence."
    )

# the prompt sent to the model
SYSTEM_PROMPT = """Analyze this email for phishing/scam red flags.

Classify it as legitimate, spam, or phishing, then give a phishing risk score
from 0.00 to 1.00 to two decimal places, and list the specific indicators.

Keep those two judgements separate. Spam and phishing are different things:
unsolicited bulk advertising is spam and scores LOW on phishing risk, however
annoying it is. Phishing means deception aimed at stealing credentials, money,
or data - and it need not be bulk at all.

Check the email against these questions, and report only what you observe:
- Does the sender address or domain differ from the brand it claims to be?
- Does it use urgency, threats, or deadlines to pressure the reader?
- Does it ask for credentials, payment details, or personal data?
- Do any links point somewhere other than where they claim?
- Is the greeting generic rather than addressed to a named person?
- Are there spelling or grammatical errors?
- Does it reference an attachment that arrives without explanation?

Every indicator must come with a VERBATIM quote from the email - the exact
words, copied character for character, not paraphrased or tidied up. If you
cannot quote the text an indicator rests on, do not report that indicator. If
the email shows no genuine indicators, return an empty list.

Score honestly. A routine, legitimate email should score low - do not invent
red flags to justify a high score."""


PHISHING_EMAIL = """From: PAYPAL Security <service@paypa1-secure.com>
To: customer@example.com
Subject: URGENT: Your account has been limited

Dear Valued Customer,

We have detected unusual activity on your account. Your account access has
been LIMITED until you verify your information.

You must confirm your identity within 24 hours or your account will be
permanently suspended and your funds forfeited.

Click here to restore access: http://paypa1-secure.com/verify/login.php

Please have your password and the card number on file ready.

Sincerely,
PAYPAL Security Team
"""


# a real 'ham' (legitimate) row from the enron dataset, id 22
HAM_EMAIL = """Subject: pennzenergy property details

- - - - - - - - - - - - - - - - - - - - - - forwarded by ami chokshi / corp / enron on 12 / 17 / 99 04 : 03
pm - - - - - - - - - - - - - - - - - - - - - - - - - - -
dscottl @ . com on 12 / 14 / 99 10 : 56 : 01 am
to : ami chokshi / corp / enron @ enron
cc :
subject : pennzenergy property details
ami , attached is some more details on the devon south texas properties . let
me know if you have any questions .
david
- devon stx . xls
"""


# switch this between HAM_EMAIL and PHISHING_EMAIL to test each case
TEST_EMAIL = PHISHING_EMAIL


def analyze(email_text: str) -> PhishingAnalysis:
    """Analyze an email for phishing indicators and return a structured response.

    Raises OpenAIError if the API call fails. That is deliberate - this function
    is library code, so it reports the problem and lets the caller decide what to
    do about it. A batch run wants to log one failed row and keep going; a
    single-email run wants to stop. Only the caller knows which.
    """
    # the two messages are kept separate on purpose: the system message is our
    # standing instruction, the user message is untrusted data to be analysed.
    # concatenating them would let email text impersonate our own instructions.
    completion = client.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": email_text},
        ],
        response_format=PhishingAnalysis,
        temperature=0,
    )

    result = completion.choices[0].message.parsed

    # .parsed is None when the model stopped early (length limit or content
    # filter) and so never produced complete JSON. this check stays inside the
    # function because no caller should ever receive None back from it.
    if result is None:
        raise RuntimeError(
            "No parsed result. "
            f"finish_reason={completion.choices[0].finish_reason!r} "
            f"refusal={completion.choices[0].message.refusal!r}"
        )

    # the schema guarantees risk_score is a number, but not that it is in range
    if not 0.0 <= result.risk_score <= 1.0:
        print(f"WARNING: risk_score {result.risk_score} is outside 0.0-1.0")

    return result


# --- composing the two layers -------------------------------------------------

# a domain finding overrides the model only when the model was NOT already
# concerned. above this, the two agree closely enough that overriding adds
# nothing.
ESCALATE_BELOW = 0.50

# what an override escalates TO. domain_check fired on 0 of 4,091 legitimate
# emails, so a firing is strong evidence - but "strong evidence" is not
# "certainty", which is why this is 0.70 and not 1.00.
ESCALATED_FLOOR = 0.70

FROM_RE = re.compile(r"^From:\s*(.+)$", re.I | re.M)


def split_headers(raw: str) -> tuple[str, str]:
    """Return (From: value, body). Both may be empty - pasted input is freeform."""
    m = FROM_RE.search(raw)
    from_header = m.group(1).strip() if m else ""
    # the body is everything after the first blank line, or the whole text if
    # the message arrived with no headers at all
    parts = raw.split("\n\n", 1)
    body = parts[1] if len(parts) > 1 else raw
    return from_header, body


@dataclass
class ScanResult:
    """Both layers, kept distinct.

    analysis        - what the model judged, unmodified
    domain_findings - what the code proved from the text itself
    risk_score      - the score a caller should act on, possibly escalated
    escalated       - whether the deterministic layer overrode the model
    """
    analysis: PhishingAnalysis
    domain_findings: list[str]
    risk_score: float
    escalated: bool


def scan(email_text: str) -> ScanResult:
    """Run both layers over one email.

    This is what callers should use. analyze() stays the single-layer primitive
    so the variance harness can still test the model in isolation.

    analysis.risk_score is never overwritten - doing so would destroy the record
    of what the model actually said, and make it impossible to measure how often
    escalation fires or whether it helps.
    """
    from_header, body = split_headers(email_text)

    # deterministic layer first: free, instant, and it has already run if the
    # API call below fails
    findings = domain_check(from_header, body) if from_header else []

    analysis = analyze(email_text)

    score, escalated = analysis.risk_score, False
    if findings and score < ESCALATE_BELOW:
        score, escalated = ESCALATED_FLOOR, True

    return ScanResult(analysis, findings, score, escalated)


# only runs when this file is executed directly (python detect_phishing.py).
# on `import detect_phishing` __name__ is the module name instead, so importing
# analyze() into the batch script will not fire a test API call as a side effect.
if __name__ == "__main__":
    # the caller decides what a failure means - here, print one line and stop
    try:
        result = scan(TEST_EMAIL)
    except OpenAIError as exc:
        raise SystemExit(f"API call failed: {type(exc).__name__}: {exc}")

    print(result.analysis.model_dump_json(indent=2))
    for finding in result.domain_findings:
        print(f"domain check: {finding}")
    if result.escalated:
        print(f"risk escalated {result.analysis.risk_score:.2f} -> "
              f"{result.risk_score:.2f} by the domain check")
