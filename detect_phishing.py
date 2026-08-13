import os

from dotenv import load_dotenv
from pydantic import BaseModel, Field 
from openai import OpenAI, OpenAIError


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


# defines the shape of the model's *response*, not the request we send.
# pydantic converts these annotations into a JSON schema that goes out with
# the request, and the API is then constrained to produce matching JSON.
class PhishingAnalysis(BaseModel):
    risk_score: float = Field(
        description="The risk score of the email, ranging from 0.0 to 1.0, "
                    "0 being lowest risk, 1 being highest risk"
    )
    flags: list[str] = Field(
        description="Specific phishing indicators found in this email. Each "
                    "entry names one concrete observation in a short phrase of "
                    "about 3-8 words, e.g. 'sender domain mismatches claimed "
                    "brand' or 'threatens account closure within 24 hours'. "
                    "Describe what is actually in this email rather than "
                    "naming generic categories. Return an empty list if the "
                    "email shows no indicators."
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
Give a risk score from 0.0 to 1.0 and list the specific indicators.

Check the email against these questions, and report only what you observe:
- Does the sender address or domain differ from the brand it claims to be?
- Does it use urgency, threats, or deadlines to pressure the reader?
- Does it ask for credentials, payment details, or personal data?
- Do any links point somewhere other than where they claim?
- Is the greeting generic rather than addressed to a named person?
- Are there spelling or grammatical errors?
- Does it reference an attachment that arrives without explanation?

Each indicator must describe what this specific email does, naming or quoting
the actual text. If the email shows no genuine indicators, return an empty list.

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


# only runs when this file is executed directly (python detect_phishing.py).
# on `import detect_phishing` __name__ is the module name instead, so importing
# analyze() into the batch script will not fire a test API call as a side effect.
if __name__ == "__main__":
    # the caller decides what a failure means - here, print one line and stop
    try:
        analysis = analyze(TEST_EMAIL)
    except OpenAIError as exc:
        raise SystemExit(f"API call failed: {type(exc).__name__}: {exc}")

    print(analysis.model_dump_json(indent=2))
