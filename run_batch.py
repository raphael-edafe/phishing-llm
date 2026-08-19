"""Batch-score an email corpus with the phishing detector.

Reads a dataset, builds a balanced reproducible sample, scores each email, and
appends one JSON line per row to results_<dataset>.jsonl.

    python run_batch.py spamassassin
    python run_batch.py nazario --n 100
    python run_batch.py --list

Datasets are read straight out of their .zip - no need to extract them, and
they stay out of git (see .gitignore; the phishing corpora contain live
malicious URLs and must not be republished).
"""

import argparse
import json
import zipfile
from pathlib import Path

import pandas as pd
from openai import OpenAIError

# importing this does NOT fire an API call - detect_phishing guards its demo
# behind `if __name__ == "__main__"`, which is why that refactor mattered
from detect_phishing import analyze

# a FIXED seed is what makes runs comparable. without it, pandas draws a
# different sample every time, and any change in the results could be your
# prompt edit or could just be different emails - you would never know which.
RANDOM_SEED = 42

MIN_CHARS = 20
MAX_CHARS = 8000

# corpora live here as .zip, read without extracting (gitignored - the
# phishing sets contain live malicious URLs)
SOURCES_DIR = Path("sources")

# scored output lands here, one file per dataset+tag
RESULTS_DIR = Path("results")

ENRON_CSV = (
    "C:/Users/rapha/Downloads/projects/background for phishing llm"
    "/enron_spam_data/enron_spam_data.csv"
)

# Which corpus does what:
#   spamassassin - the primary benchmark. BOTH classes come from the SAME
#                  collection, so a model cannot score well merely by telling
#                  two corpora apart. it also keeps sender headers.
#   nazario      - phishing only. no accuracy possible (one class), but a valid
#                  RECALL test: of N known phishing emails, how many did we
#                  catch? no confound, because no classes are being compared.
#   nigerian     - phishing only, specifically 419 advance-fee fraud.
#   enron        - the original run. NO sender headers, which is why we moved on.
DATASETS = {
    "spamassassin": {"zip": "SpamAssasin.csv.zip", "both_classes": True},
    "nazario": {"zip": "Nazario.csv.zip", "both_classes": False},
    "nigerian": {"zip": "Nigerian_Fraud.csv.zip", "both_classes": False},
    "enron": {"csv": ENRON_CSV, "both_classes": True},
}


def build_email(row: pd.Series) -> str:
    """Assemble one email in the shape the prompt was tuned against.

    Headers first, blank line, then body - matching PHISHING_EMAIL in
    detect_phishing.py. The From: line matters most: the prompt asks whether
    the sender domain differs from the brand it claims, and until these
    corpora there was no data that could answer it. Enron stripped domains.
    """
    lines = []
    for label, key in (("From", "sender"), ("To", "receiver"), ("Date", "date")):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            lines.append(f"{label}: {value.strip()}")
    lines.append(f"Subject: {row['subject']}")
    return ("\n".join(lines) + "\n\n" + str(row["body"]))[:MAX_CHARS]


def load_dataset(name: str) -> pd.DataFrame:
    """Load a corpus and normalise it to: id, subject, body, label, + headers.

    label is normalised to the strings 'spam' and 'ham'. The kaggle corpora
    use 1/0; enron uses a 'Spam/Ham' text column.
    """
    cfg = DATASETS[name]

    if "zip" in cfg:
        path = SOURCES_DIR / cfg["zip"]
        if not path.exists():
            raise SystemExit(f"{path} not found in {Path.cwd()}")
        with zipfile.ZipFile(path) as z:
            inner = z.namelist()[0]
            with z.open(inner) as fh:
                df = pd.read_csv(fh, on_bad_lines="skip", low_memory=False)
        df["label"] = df["label"].map({1: "spam", 0: "ham"})
    else:
        df = pd.read_csv(cfg["csv"])
        df = df.rename(columns={"Subject": "subject", "Message": "body"})
        df["label"] = df["Spam/Ham"]

    df = df.dropna(subset=["subject", "body"])

    # the id only has to be unique within one dataset, since each dataset gets
    # its own results file. the row index is enough.
    df = df.reset_index(drop=True)
    df["id"] = [f"{name}:{i}" for i in df.index]

    df["email_text"] = [build_email(r) for _, r in df.iterrows()]
    df = df[df["email_text"].str.len() >= MIN_CHARS]
    return df


def build_sample(df: pd.DataFrame, name: str, n: int) -> pd.DataFrame:
    """Balanced sample where both classes exist, otherwise a plain sample."""
    if DATASETS[name]["both_classes"]:
        # sample each class SEPARATELY so the split is exactly balanced, rather
        # than sampling n at random and hoping it comes out even
        per_class = n // 2
        parts = [
            df[df["label"] == lbl].sample(n=per_class, random_state=RANDOM_SEED)
            for lbl in ("spam", "ham")
        ]
        return pd.concat(parts)
    return df.sample(n=min(n, len(df)), random_state=RANDOM_SEED)


def already_done(results_path: Path) -> set[str]:
    """IDs already present in the results file.

    Lets a re-run pick up where a crashed one stopped instead of paying for
    the same rows twice.
    """
    if not results_path.exists():
        return set()
    return {
        json.loads(line)["id"]
        for line in results_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def score_sample(sample: pd.DataFrame, results_path: Path) -> None:
    """Analyse each email and append one JSON line per row.

    This is EVALUATION, not training. Every call to analyze() is an independent
    request to a frozen model: nothing here updates any weights, and the model
    carries no memory from one email to the next. The labels are never sent to
    the model - they are only used afterwards, in evaluate.py, to check whether
    the scores it produced line up with reality.
    """
    done = already_done(results_path)
    todo = [r for _, r in sample.iterrows() if r["id"] not in done]

    if done:
        print(f"resuming: {len(done)} already scored, {len(todo)} to go")
    print(f"scoring {len(todo)} emails (~{max(1, len(todo) * 7 // 60)} min)\n")

    failures = 0
    # append mode, so a resumed run adds to the existing file
    with results_path.open("a", encoding="utf-8") as out:
        for i, row in enumerate(todo, 1):
            record = {"id": row["id"], "label": row["label"]}
            try:
                result = analyze(row["email_text"])
                record |= {
                    "category": result.category,
                    "risk_score": result.risk_score,
                    "flags": result.flags,
                    "verdict": result.verdict,
                    "error": None,
                }
                status = f"{result.category:<10} {result.risk_score:.2f}"
            except (OpenAIError, RuntimeError) as exc:
                # one bad row costs one row. record it rather than skipping,
                # so the totals at the end stay trustworthy.
                record |= {
                    "category": None, "risk_score": None,
                    "flags": None, "verdict": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
                status = "FAILED"
                failures += 1

            out.write(json.dumps(record) + "\n")
            out.flush()   # land each line on disk immediately
            print(f"[{i:>3}/{len(todo)}] {row['label']:<4} -> {status}")

    print(f"\ndone. {failures} failure(s). results in {results_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", choices=sorted(DATASETS),
                        help="which corpus to score")
    parser.add_argument("--n", type=int, default=100,
                        help="sample size (default 100)")
    parser.add_argument("--list", action="store_true",
                        help="show available datasets and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="build the sample and print examples, no API calls")
    # results are only comparable within one prompt/schema version - changing
    # the prompt shifts the score calibration, so a threshold derived from an
    # old run does not transfer. tag runs to keep versions side by side.
    parser.add_argument("--tag", default="",
                        help="suffix for the results file, e.g. --tag v2")
    args = parser.parse_args()

    if args.list or not args.dataset:
        print("datasets:")
        for name, cfg in DATASETS.items():
            src = cfg.get("zip", "enron csv")
            classes = "spam+ham" if cfg["both_classes"] else "phishing only"
            print(f"  {name:<14} {classes:<14} {src}")
        return

    df = load_dataset(args.dataset)
    print(f"{args.dataset}: {len(df):,} usable rows")
    print(dict(df["label"].value_counts()))

    sample = build_sample(df, args.dataset, args.n)
    lengths = sample["email_text"].str.len()
    print(f"\nsample: {len(sample)}  "
          f"length min={lengths.min()} median={int(lengths.median())} "
          f"max={lengths.max()}")

    if args.dry_run:
        for lbl in sample["label"].unique():
            row = sample[sample["label"] == lbl].iloc[0]
            print("\n" + "=" * 70)
            print(f"EXAMPLE {lbl.upper()}  ({row['id']})")
            print("=" * 70)
            print(row["email_text"][:600])
        return

    suffix = f"_{args.tag}" if args.tag else ""
    RESULTS_DIR.mkdir(exist_ok=True)
    score_sample(sample, RESULTS_DIR / f"results_{args.dataset}{suffix}.jsonl")


if __name__ == "__main__":
    main()
