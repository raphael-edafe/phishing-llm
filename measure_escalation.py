"""Replay the deterministic layer over already-scored results. No API calls.

    python measure_escalation.py [tag]
"""
import json, pathlib, sys
import run_batch

TAG = sys.argv[1] if len(sys.argv) > 1 else 'cat'
from detect_phishing import split_headers, ESCALATE_BELOW, ESCALATED_FLOOR
from domain_check import check as domain_check

def replay(dataset, tag):
    rows = [json.loads(l) for l in
            pathlib.Path(f"results/results_{dataset}_{tag}.jsonl")
            .read_text(encoding="utf-8").splitlines() if l.strip()]
    df = run_batch.load_dataset(dataset).set_index("id")

    out = []
    for r in rows:
        if r["risk_score"] is None:
            continue
        text = df.loc[r["id"], "email_text"]
        from_header, body = split_headers(text)
        findings = domain_check(from_header, body) if from_header else []
        score = r["risk_score"]
        esc = bool(findings) and score < ESCALATE_BELOW
        out.append({**r, "findings": findings,
                    "combined": ESCALATED_FLOOR if esc else score, "esc": esc})
    return out

print(f"policy: escalate to {ESCALATED_FLOOR} when a domain finding lands "
      f"below {ESCALATE_BELOW}\n")

naz = replay("nazario", TAG)
fired = [r for r in naz if r["findings"]]
esc   = [r for r in naz if r["esc"]]
print(f"NAZARIO (all phishing, n={len(naz)})")
print(f"  domain check fired on : {len(fired)}")
print(f"  of those, escalated   : {len(esc)}")
for t in (0.10, 0.30, 0.50, 0.70):
    before = sum(1 for r in naz if r["risk_score"] >= t)
    after  = sum(1 for r in naz if r["combined"]  >= t)
    print(f"  recall @ {t:.2f}: {before:>3}/{len(naz)} -> {after:>3}/{len(naz)}"
          + ("   <-- improved" if after > before else ""))
for r in esc:
    print(f"  ESCALATED {r['id']}  {r['risk_score']:.2f} -> {r['combined']:.2f}"
          f"  [{r['category']}]")
    for f in r["findings"]:
        print(f"      {f}")

print()
sa = replay("spamassassin", TAG)
ham = [r for r in sa if r["label"] == "ham"]
spam = [r for r in sa if r["label"] == "spam"]
print(f"SPAMASSASSIN ham (n={len(ham)}) - the false-positive control")
print(f"  domain check fired on : {sum(1 for r in ham if r['findings'])}")
print(f"  escalated             : {sum(1 for r in ham if r['esc'])}")
for t in (0.10, 0.50, 0.70):
    fp_b = sum(1 for r in ham if r["risk_score"] >= t)
    fp_a = sum(1 for r in ham if r["combined"]  >= t)
    print(f"  false positives @ {t:.2f}: {fp_b} -> {fp_a}"
          + ("   <-- WORSE" if fp_a > fp_b else ""))
print(f"  (spam rows escalated: {sum(1 for r in spam if r['esc'])})")
