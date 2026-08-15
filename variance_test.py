"""Run the same email repeatedly and measure how much the output moves.

    python variance_test.py --runs 10

temperature=0 reduces run-to-run variance but does NOT eliminate it. This
harness exists because of a bug that was invisible in a single run: an earlier
prompt listed phishing categories as statements, and 1 run in 5 returned those
categories copied verbatim as "findings" instead of reporting observed
evidence. Four runs out of five looked perfect.

Anything that changes the prompt or the schema should be re-checked here before
being trusted - adding output structure is exactly where that bug came from.
"""

import argparse
from collections import Counter

from detect_phishing import HAM_EMAIL, PHISHING_EMAIL, analyze

# phrasings that indicate the model is naming a category rather than describing
# this specific email. a flag containing '?' means it copied a question
# straight out of the prompt's checklist.
GENERIC = {
    "sender and domain mismatches", "urgency or threatening language",
    "requests for credentials or payment", "suspicious or mismatched links",
    "generic greetings", "spelling and grammatical errors",
    "unexpected attachments", "generic greeting", "unexpected attachment",
}


def is_generic(flag: str) -> bool:
    return flag.strip().lower() in GENERIC or "?" in flag


def run(name: str, email: str, runs: int) -> None:
    scores, flag_counts = [], []
    categories, seen_flags = Counter(), Counter()
    bad_runs = 0

    for _ in range(runs):
        r = analyze(email)
        scores.append(r.risk_score)
        categories[r.category] += 1
        flag_counts.append(len(r.flags))
        for f in r.flags:
            seen_flags[f] += 1
        if any(is_generic(f) for f in r.flags):
            bad_runs += 1

    print(f"===== {name}  ({runs} runs) =====")
    print(f"score:     min={min(scores):.2f} max={max(scores):.2f} "
          f"spread={max(scores) - min(scores):.2f}")
    print(f"category:  {dict(categories)}")
    print(f"flags:     min={min(flag_counts)} max={max(flag_counts)}")
    print(f"runs containing a generic/copied flag: {bad_runs}/{runs}")
    print("distinct flags seen (count):")
    for f, n in seen_flags.most_common():
        tag = "  <-- GENERIC" if is_generic(f) else ""
        print(f"    {n:2d}x  {f}{tag}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args()

    run("PHISHING", PHISHING_EMAIL, args.runs)
    run("HAM", HAM_EMAIL, args.runs)


if __name__ == "__main__":
    main()
