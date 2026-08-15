"""Score batch results against the corpus labels.

    python evaluate.py spamassassin
    python evaluate.py nazario

Deliberately separate from run_batch.py: collection costs money and minutes,
evaluation is free, so thresholds can be swept without re-running the API.

For a corpus with both classes it reports accuracy and error rates across
thresholds. For a phishing-only corpus (nazario, nigerian) accuracy is not
defined - there is nothing to be wrong about in the other direction - so it
reports RECALL instead: of N known phishing emails, how many did we catch?
"""

import argparse
import json
from pathlib import Path


def report_categories(ok: list[dict]) -> None:
    """Cross-tab predicted category against the corpus label.

    This is the whole point of the category field. The corpora label 'spam',
    which lumps together honest advertising and credential theft. Splitting the
    spam row into 'spam' and 'phishing' columns shows how much of that label is
    actually the thing this tool is built to detect.
    """
    cats = ["legitimate", "spam", "phishing"]
    if not any(r.get("category") for r in ok):
        return
    print(f"\npredicted category vs corpus label")
    print(f"{'':<12} " + " ".join(f"{c:>11}" for c in cats))
    for lbl in sorted({r["label"] for r in ok}):
        sub = [r for r in ok if r["label"] == lbl]
        counts = [sum(1 for r in sub if r.get("category") == c) for c in cats]
        print(f"true {lbl:<7} " + " ".join(f"{n:>11}" for n in counts))

    # mean phishing score per predicted category - if the two fields are
    # working together, 'spam' should sit far below 'phishing'
    print("\nmean risk_score by predicted category")
    for c in cats:
        sub = [r["risk_score"] for r in ok if r.get("category") == c]
        if sub:
            print(f"  {c:<11} n={len(sub):<4} mean={sum(sub)/len(sub):.3f}")


def report_contradictions(ok: list[dict]) -> None:
    """Rows where category and risk_score disagree with each other.

    These two fields answer different questions - what KIND of email this is,
    and how DANGEROUS it is - so they are not redundant. But some combinations
    are incoherent: a 'legitimate' email should not be scoring as a threat, and
    a 'phishing' verdict should not come with a near-zero score.

    Note this is a CHECK, not a correction. It would be tempting to derive one
    field from the other (e.g. score < 0.10 implies legitimate), but that
    collapses the two axes back into one: 77% of correctly-identified spam
    scores under 0.10, because advertising is genuinely not dangerous. Low risk
    means 'not a threat', not 'wanted'. Flag the disagreement, don't overwrite.
    """
    rules = [
        ("legitimate but scored as a threat",
         lambda r: r["category"] == "legitimate" and r["risk_score"] >= 0.10),
        ("phishing but scored low",
         lambda r: r["category"] == "phishing" and r["risk_score"] < 0.50),
        ("spam but scored dangerous",
         lambda r: r["category"] == "spam" and r["risk_score"] >= 0.50),
    ]
    if not any(r.get("category") for r in ok):
        return
    print("\nconsistency check (category vs risk_score)")
    total = 0
    for label, test in rules:
        hits = [r for r in ok if r.get("category") and test(r)]
        total += len(hits)
        print(f"  {label:<36} {len(hits)}")
        for r in hits[:3]:
            print(f"      {r['risk_score']:.2f} {r['category']:<10} {r['id']}")
    if total == 0:
        print("  no contradictions - the two fields agree throughout")


def load_results(dataset: str, tag: str = "") -> list[dict]:
    suffix = f"_{tag}" if tag else ""
    path = Path(f"results_{dataset}{suffix}.jsonl")
    if not path.exists():
        raise SystemExit(f"{path} not found - run: python run_batch.py {dataset}")
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def describe(name: str, scores: list[float]) -> str:
    s = sorted(scores)
    n = len(s)
    return (f"{name:<5} n={n:<4} mean={sum(s)/n:.3f}  median={s[n//2]:.2f}  "
            f"min={s[0]:.2f}  max={s[-1]:.2f}")


def report_both_classes(spam: list[float], ham: list[float]) -> None:
    print(f"\n{describe('spam', spam)}")
    print(describe("ham", ham))

    # a threshold turns the 0-1 score into a binary prediction. rather than
    # assuming 0.5, sweep it and see where the classes actually separate.
    print(f"\n{'thresh':>7} {'acc':>7} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}"
          f" {'FP rate':>8} {'FN rate':>8}")
    print("-" * 56)
    best = None
    for i in range(1, 20):
        t = i / 20          # 0.05 steps, since scores now carry 2 decimals
        tp = sum(1 for s in spam if s >= t)
        fn = len(spam) - tp
        fp = sum(1 for s in ham if s >= t)
        tn = len(ham) - fp
        acc = (tp + tn) / (len(spam) + len(ham))
        print(f"{t:>7.2f} {acc:>7.1%} {tp:>4} {fp:>4} {tn:>4} {fn:>4}"
              f" {fp/len(ham):>8.1%} {fn/len(spam):>8.1%}")
        if best is None or acc > best[1]:
            best = (t, acc)
    print(f"\nbest threshold: {best[0]:.2f} at {best[1]:.1%} accuracy")


def report_recall(scores: list[float]) -> None:
    """Phishing-only corpus: accuracy is undefined, recall is the question."""
    print(f"\n{describe('phish', scores)}")
    print("\nthis corpus is phishing only, so there are no false positives to")
    print("measure. the question is recall: how many did we catch?\n")
    print(f"{'thresh':>7} {'caught':>8} {'recall':>8}")
    print("-" * 26)
    for i in range(1, 20):
        t = i / 20
        caught = sum(1 for s in scores if s >= t)
        print(f"{t:>7.2f} {caught:>8} {caught/len(scores):>8.1%}")


def show_cases(ok: list[dict], both: bool) -> None:
    """The rows worth reading. The aggregate number hides these."""
    if both:
        low = sorted((r for r in ok if r["label"] == "spam"),
                     key=lambda r: r["risk_score"])[:5]
        high = sorted((r for r in ok if r["label"] == "ham"),
                      key=lambda r: -r["risk_score"])[:5]
        # spam scoring low is often NOT a mistake - these corpora label
        # advertising as spam, and an advert is correctly near-zero phishing
        # risk. read these before trusting the accuracy number.
        print("\nlowest-scoring SPAM (advertising, or a real miss?)")
        for r in low:
            print(f"  {r['risk_score']:.2f}  {r['id']}  {r['verdict'][:88]}")
        print("\nhighest-scoring HAM (genuine false positives)")
        for r in high:
            print(f"  {r['risk_score']:.2f}  {r['id']}  {r['verdict'][:88]}")
    else:
        missed = sorted(ok, key=lambda r: r["risk_score"])[:8]
        print("\nlowest-scoring PHISHING (what slipped through)")
        for r in missed:
            print(f"  {r['risk_score']:.2f}  {r['id']}  {r['verdict'][:88]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", help="which results file to evaluate")
    parser.add_argument("--tag", default="", help="results file suffix, e.g. --tag v2")
    args = parser.parse_args()

    rows = load_results(args.dataset, args.tag)
    failed = [r for r in rows if r["error"] is not None]
    ok = [r for r in rows if r["error"] is None]

    print(f"{len(rows)} rows, {len(ok)} scored, {len(failed)} failed")
    if failed:
        print(f"  first failure: {failed[0]['error'][:100]}")

    spam = [r["risk_score"] for r in ok if r["label"] == "spam"]
    ham = [r["risk_score"] for r in ok if r["label"] == "ham"]

    both = bool(spam) and bool(ham)
    if both:
        report_both_classes(spam, ham)
    else:
        report_recall(spam or ham)

    report_categories(ok)
    report_contradictions(ok)
    show_cases(ok, both)


if __name__ == "__main__":
    main()
