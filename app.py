"""Local web UI for the phishing detector.

    python app.py     ->  http://localhost:5057

A thin Flask wrapper around analyze(). The detection logic stays in
detect_phishing.py so there is exactly one copy of the prompt and schema - the
UI never reimplements them.

Two layers run per request, and the UI shows them separately:

  1. domain_check.check()  - deterministic, free, instant, no API call
  2. analyze()             - the model, ~7 seconds, costs a fraction of a cent

Keeping them visually distinct in the output is deliberate: one is a fact
about the email's text, the other is a judgement. They should not be presented
as if they carry the same kind of certainty.
"""

import re

from flask import Flask, jsonify, request, send_from_directory
from openai import OpenAIError

from detect_phishing import analyze
from domain_check import check as domain_check

app = Flask(__name__, static_folder="static")

FROM_RE = re.compile(r"^From:\s*(.+)$", re.I | re.M)


def split_headers(raw: str) -> tuple[str, str]:
    """Return (From: value, body). Both may be empty - paste is freeform."""
    m = FROM_RE.search(raw)
    from_header = m.group(1).strip() if m else ""
    # the body is everything after the first blank line, or the whole text if
    # the user pasted a bare message with no headers at all
    parts = raw.split("\n\n", 1)
    body = parts[1] if len(parts) > 1 else raw
    return from_header, body


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.post("/api/analyze")
def api_analyze():
    email = (request.get_json(silent=True) or {}).get("email", "").strip()
    if not email:
        return jsonify(error="Paste an email first."), 400
    if len(email) > 20000:
        return jsonify(error="That's over 20,000 characters - trim it down."), 400

    from_header, body = split_headers(email)

    # deterministic layer: runs whether or not the API call succeeds
    domain_findings = domain_check(from_header, body) if from_header else []

    try:
        result = analyze(email)
    except OpenAIError as exc:
        # surface the real reason - a missing key and no credit are different
        # problems and the user can only fix them if we say which it is
        return jsonify(
            error=f"{type(exc).__name__}: {exc}",
            domain_findings=domain_findings,
        ), 502
    except RuntimeError as exc:
        return jsonify(error=str(exc), domain_findings=domain_findings), 502

    return jsonify(
        category=result.category,
        risk_score=result.risk_score,
        flags=result.flags,
        verdict=result.verdict,
        domain_findings=domain_findings,
    )


if __name__ == "__main__":
    print("phishing detector UI -> http://localhost:5057")
    app.run(port=5057, debug=True)
