"""Deterministic lookalike-domain detection.

This exists because prompting failed at it. The model reliably misses that
'we-transfer.com' differs from 'wetransfer.com' when reading a full email -
not because it cannot see the difference (asked in isolation, it identifies
the hyphen immediately) but because character-level comparison against a brand
it has to recall from memory is not what it does well under load. Adding two
explicit questions to the prompt changed nothing.

Exact string comparison is what code is good at, so it belongs here. The model
keeps the semantic half - intent, urgency, plausibility, impersonation.

No API calls, no brand list, no network. Everything below works from data
already present in the email.

Run the self-test with:  python domain_check.py
"""

import re

# characters attackers substitute to build a lookalike that reads correctly to
# a human skimming: paypa1 for paypal, g00gle for google, micr0soft, etc.
HOMOGLYPHS = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s",
                            "4": "a", "7": "t", "8": "b", "$": "s"})

DOMAIN_RE = re.compile(r"\b((?:[a-z0-9$-]+\.)+[a-z]{2,})\b", re.I)
ANGLE_ADDR_RE = re.compile(r"<([^>]+)>")
DISPLAY_NAME_RE = re.compile(r'^\s*"?([^"<]+?)"?\s*<')

# domains that appear in almost every email and would only add noise
IGNORE = {"example.com", "example.org", "localhost"}


def normalise(domain: str) -> str:
    """Lowercase, strip a leading www., drop any trailing dot."""
    d = domain.strip().lower().rstrip(".")
    return d[4:] if d.startswith("www.") else d


def deobfuscate(text: str) -> str:
    """Collapse the tricks that make a lookalike read like the real thing.

    Removes separators and maps digit-for-letter substitutions, so that
    'we-transfer.com' and 'paypa1' become 'wetransfer.com' and 'paypal'.
    """
    return text.lower().translate(HOMOGLYPHS).replace("-", "").replace("_", "")


def sender_domain(from_header: str) -> str | None:
    """Pull the domain out of a From: line, with or without a display name."""
    addr = ANGLE_ADDR_RE.search(from_header)
    addr = addr.group(1) if addr else from_header
    if "@" not in addr:
        return None
    return normalise(addr.rsplit("@", 1)[-1])


def display_name(from_header: str) -> str | None:
    m = DISPLAY_NAME_RE.match(from_header)
    return m.group(1).strip() if m else None


def check(from_header: str, body: str) -> list[str]:
    """Return deterministic lookalike findings for one email.

    Two checks, both using only what the email already contains:

    1. Display name vs sender domain. If the brand in the display name is
       absent from the raw domain but present once the domain is
       de-obfuscated, that IS the typosquat - it means the domain was built to
       resemble the brand without being it. Catches 'PayPal <..@paypa1-..>'
       and 'WeTransfer <..@we-transfer.com>' with no brand list.

    2. Sender domain vs domains cited in the body. A message arriving from
       'we-transfer.com' whose text says 'add noreply@wetransfer.com to your
       contacts' is citing the real domain while sending from the fake one.
    """
    findings: list[str] = []
    sender = sender_domain(from_header)
    if not sender:
        return findings

    sender_flat = deobfuscate(sender)

    # --- check 1: display name brand vs sender domain -----------------------
    name = display_name(from_header)
    if name:
        # the brand token is the longest alphabetic run in the display name,
        # e.g. "PayPal Security" -> "security"? no - take the first, which is
        # conventionally the brand: "PayPal Security" -> "paypal"
        tokens = [t for t in re.findall(r"[A-Za-z]{4,}", name)]
        for token in tokens[:2]:
            t = token.lower()
            if t in sender.replace("-", ""):
                break                      # brand really is in the domain
            if t in sender_flat:
                findings.append(
                    f"sender domain '{sender}' imitates '{token}' using "
                    f"character substitution"
                )
                break

    # --- check 2: sender domain vs domains cited in the body ---------------
    for raw in set(DOMAIN_RE.findall(body or "")):
        cited = normalise(raw)
        if cited in IGNORE or cited == sender:
            continue
        # ONLY an exact match after de-obfuscation counts. A fuzzy
        # edit-distance version of this check was tried and removed: short
        # domains land within two edits of each other by coincidence
        # constantly ('best.com' vs 'xent.com', 'cse.ucsc.edu' vs
        # 'cs.ucsc.edu'), and it fired on legitimate mail as often as on
        # phishing. A signal that raises a risk score has to be precise or it
        # is worse than nothing.
        if deobfuscate(cited) == sender_flat and cited != sender:
            findings.append(
                f"body cites '{cited}' but the email was sent from '{sender}'"
            )
    return findings


if __name__ == "__main__":
    # the two real cases this was built from, plus negatives that must stay
    # silent - a check that fires on legitimate mail is worse than no check
    cases = [
        ("WeTransfer <noreply@we-transfer.com>",
         "You have received a file. To make sure our emails arrive, please "
         "add noreply@wetransfer.com to your contacts.",
         True, "nazario:1091 - the email that got past the model"),

        ("PayPal Security <service@paypa1-secure.com>",
         "Click here to restore access: http://paypa1-secure.com/verify",
         True, "the synthetic PayPal sample"),

        ("Gary Lawrence Murphy <garym@canada.com>",
         "Yes, them too. When wolves attack their sheep...",
         False, "ordinary personal mail"),

        ("WeTransfer <noreply@wetransfer.com>",
         "You have received a file via wetransfer.com",
         False, "the REAL wetransfer - must not fire"),

        ("guardian <rssfeeds@spamassassin.taint.org>",
         "URL: http://www.newsisfree.com/click/215,11,215/ Education debate",
         False, "rss feed - unrelated domains, not a lookalike"),
    ]

    passed = 0
    for from_header, body, should_fire, label in cases:
        found = check(from_header, body)
        ok = bool(found) == should_fire
        passed += ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")
        for f in found:
            print(f"         -> {f}")
    print(f"\n{passed}/{len(cases)} passed")
