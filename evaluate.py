"""Score the batch results against the dataset's own spam/ham labels.

Reads results.jsonl and reports how well risk_score separates the classes.
Deliberately separate from run_batch.py: collection costs money and minutes,
evaluation is free and instant, so you can try twenty thresholds on results
you paid for once.

Run with:  python evaluate.py
"""

import json
from pathlib import Path

RESULTS_PATH = Path("results.jsonl")


def load_results() -> list[dict]:
    if not RESULTS_PATH.exists():
        raise SystemExit(f"{RESULTS_PATH} not found - run run_batch.py first")
    return [json.loads(line) for line in
            RESULTS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    rows = load_results()
    failed = [r for r in rows if r["error"] is not None]
    ok = [r for r in rows if r["error"] is None]

    print(f"{len(rows)} rows, {len(ok)} scored, {len(failed)} failed")
    if failed:
        print(f"  first failure: {failed[0]['error'][:100]}")

    spam = [r["risk_score"] for r in ok if r["label"] == "spam"]
    ham = [r["risk_score"] for r in ok if r["label"] == "ham"]

    def stats(xs):
        s = sorted(xs)
        n = len(s)
        return f"n={n:<4} mean={sum(s)/n:.3f}  median={s[n//2]:.3f}  min={s[0]:.2f}  max={s[-1]:.2f}"

    print(f"\nspam: {stats(spam)}")
    print(f"ham:  {stats(ham)}")

    # a threshold turns the 0-1 score into a binary prediction. rather than
    # assuming 0.5, sweep it and see where the classes actually separate.
    print(f"\n{'thresh':>7} {'acc':>7} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}"
          f" {'FP rate':>8} {'FN rate':>8}")
    print("-" * 56)
    best = None
    for t in [i / 10 for i in range(1, 10)]:
        tp = sum(1 for s in spam if s >= t)
        fn = len(spam) - tp
        fp = sum(1 for s in ham if s >= t)
        tn = len(ham) - fp
        acc = (tp + tn) / (len(spam) + len(ham))
        print(f"{t:>7.1f} {acc:>7.1%} {tp:>4} {fp:>4} {tn:>4} {fn:>4}"
              f" {fp/len(ham):>8.1%} {fn/len(spam):>8.1%}")
        if best is None or acc > best[1]:
            best = (t, acc)

    print(f"\nbest threshold: {best[0]:.1f} at {best[1]:.1%} accuracy")

    # the interesting rows. spam scoring low is often NOT a mistake - enron
    # 'spam' includes plain advertising, which is correctly near-zero phishing
    # risk. read these before trusting the accuracy number.
    low_spam = sorted((r for r in ok if r["label"] == "spam"),
                      key=lambda r: r["risk_score"])[:5]
    high_ham = sorted((r for r in ok if r["label"] == "ham"),
                      key=lambda r: -r["risk_score"])[:5]

    print("\nlowest-scoring SPAM (check: advertising, or a real miss?)")
    for r in low_spam:
        print(f"  {r['risk_score']:.2f}  id={r['message_id']}  {r['verdict'][:90]}")

    print("\nhighest-scoring HAM (genuine false positives)")
    for r in high_ham:
        print(f"  {r['risk_score']:.2f}  id={r['message_id']}  {r['verdict'][:90]}")


if __name__ == "__main__":
    main()
