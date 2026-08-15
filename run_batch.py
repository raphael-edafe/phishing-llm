"""Batch-score Enron emails with the phishing detector.

Step 1 of 2: load the corpus, clean it, and build a reproducible sample.
No API calls happen in this file yet - that keeps the data plumbing separate
from the scoring, so if the numbers later look wrong we know which half to
blame.

Run with:  python run_batch.py
"""

import json
from pathlib import Path

import pandas as pd
from openai import OpenAIError

# importing this does NOT fire an API call - detect_phishing guards its demo
# behind `if __name__ == "__main__"`, which is why that refactor mattered
from detect_phishing import analyze

# the dataset lives in a sibling folder. forward slashes work fine on windows
# and avoid backslash escape problems (\r, \U and friends are escape sequences
# inside a normal python string).
CSV_PATH = (
    "C:/Users/rapha/Downloads/projects/background for phishing llm"
    "/enron_spam_data/enron_spam_data.csv"
)

SAMPLE_PER_CLASS = 50

# a FIXED seed is what makes runs comparable. without it, pandas draws a
# different sample every time, and any change in the results could be your
# prompt edit or could just be different emails - you would never know which.
RANDOM_SEED = 42

# 99 rows in this corpus are under 20 chars (nothing to analyse) and the
# longest is 228,367 chars (~57k tokens, and one row costing more than the
# rest of the sample combined). 8000 chars is ~2000 tokens, comfortably above
# the 90th percentile of 3,104, so this only trims the extreme tail.
MIN_CHARS = 20
MAX_CHARS = 8000

# one JSON object per line. this format is what makes appending safe: each line
# is written and flushed on its own, so a crash costs the line in progress
# rather than the whole file.
RESULTS_PATH = Path("results.jsonl")


def build_email(subject: str, message: str) -> str:
    """Assemble one email in the same shape the prompt was tuned against.

    That shape is a 'Subject:' line, a blank line, then the body. The prompt
    was validated on emails laid out this way; feeding it a different shape
    would be testing something that was never calibrated.
    """
    return f"Subject: {subject}\n\n{message}"[:MAX_CHARS]


def load_sample(n_per_class: int = SAMPLE_PER_CLASS) -> pd.DataFrame:
    """Return a balanced, reproducible sample with an 'email_text' column."""
    df = pd.read_csv(CSV_PATH)
    print(f"loaded {len(df):,} rows")

    # 289 rows have no Subject and 371 have no Message. pandas represents those
    # as NaN, and an f-string would happily render NaN as the literal text
    # "nan" - so we would be paying to analyse the word "nan".
    df = df.dropna(subset=["Subject", "Message"])
    print(f"{len(df):,} rows after dropping missing subject/message")

    df = df.copy()
    df["email_text"] = [
        build_email(s, m) for s, m in zip(df["Subject"], df["Message"])
    ]

    # drop anything with essentially no content left to analyse
    df = df[df["email_text"].str.len() >= MIN_CHARS]
    print(f"{len(df):,} rows after dropping near-empty emails")

    # sample each class SEPARATELY so the split is exactly balanced, rather
    # than sampling 100 at random and hoping it comes out even
    spam = df[df["Spam/Ham"] == "spam"].sample(
        n=n_per_class, random_state=RANDOM_SEED
    )
    ham = df[df["Spam/Ham"] == "ham"].sample(
        n=n_per_class, random_state=RANDOM_SEED
    )

    return pd.concat([spam, ham])


def already_done() -> set[int]:
    """Message IDs already present in results.jsonl.

    Lets a re-run pick up where a crashed one stopped instead of paying for
    the same rows twice.
    """
    if not RESULTS_PATH.exists():
        return set()
    done = set()
    for line in RESULTS_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            done.add(json.loads(line)["message_id"])
    return done


def score_sample(sample: pd.DataFrame) -> None:
    """Analyse each email and append one JSON line per row to results.jsonl.

    This is EVALUATION, not training. Every call to analyze() is an independent
    request to a frozen model: nothing here updates any weights, and the model
    carries no memory from one email to the next. The spam/ham labels are never
    sent to the model - they are only used afterwards, in evaluate.py, to check
    whether the scores it produced line up with reality.

    So the model does not get better as this loop runs. What improves is the
    prompt, and only because a human reads the results and edits it.
    """
    done = already_done()
    todo = [r for _, r in sample.iterrows()
            if int(r["Message ID"]) not in done]

    if done:
        print(f"resuming: {len(done)} already scored, {len(todo)} to go")
    print(f"scoring {len(todo)} emails (~{len(todo) * 7 // 60} min)\n")

    failures = 0
    # append mode, so a resumed run adds to the existing file
    with RESULTS_PATH.open("a", encoding="utf-8") as out:
        for i, row in enumerate(todo, 1):
            mid = int(row["Message ID"])   # numpy int64 is not JSON serialisable
            label = row["Spam/Ham"]

            record = {"message_id": mid, "label": label}
            try:
                result = analyze(row["email_text"])
                record |= {
                    "risk_score": result.risk_score,
                    "flags": result.flags,
                    "verdict": result.verdict,
                    "error": None,
                }
                status = f"{result.risk_score:.2f}"
            except (OpenAIError, RuntimeError) as exc:
                # one bad row costs one row. record it rather than skipping,
                # so the totals at the end are trustworthy.
                record |= {
                    "risk_score": None, "flags": None, "verdict": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
                status = "FAILED"
                failures += 1

            out.write(json.dumps(record) + "\n")
            out.flush()   # land each line on disk immediately
            print(f"[{i:>3}/{len(todo)}] {label:<4} -> {status}")

    print(f"\ndone. {failures} failure(s). results in {RESULTS_PATH}")


if __name__ == "__main__":
    sample = load_sample()

    print()
    print(f"sample size: {len(sample)}")
    print(sample["Spam/Ham"].value_counts().to_string())
    lengths = sample["email_text"].str.len()
    print(f"email length: min={lengths.min()} median={int(lengths.median())} "
          f"max={lengths.max()}")
    print()

    score_sample(sample)
