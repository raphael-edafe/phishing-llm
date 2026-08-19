"""Local web UI for the phishing detector.

    python app.py     ->  http://localhost:5057

A thin Flask wrapper around scan(). The detection logic stays in
detect_phishing.py so there is exactly one copy of the prompt, the schema, and
the two-layer composition - the UI never reimplements any of them.

scan() runs both layers per request:

  1. domain_check  - deterministic, free, instant, no API call
  2. analyze()     - the model, ~7 seconds, a fraction of a cent

They are reported separately because one is a verifiable fact about the text
and the other is a judgement. Presenting them identically would overstate the
second.
"""

from flask import Flask, jsonify, request, send_from_directory
from openai import OpenAIError

from detect_phishing import scan

app = Flask(__name__, static_folder="static")


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

    try:
        result = scan(email)
    except OpenAIError as exc:
        # surface the real reason - a missing key and no credit are different
        # problems, and the user can only fix them if we say which it is
        return jsonify(error=f"{type(exc).__name__}: {exc}"), 502
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 502

    return jsonify(
        category=result.analysis.category,
        risk_score=result.risk_score,
        model_score=result.analysis.risk_score,
        escalated=result.escalated,
        flags=result.analysis.flags,
        verdict=result.analysis.verdict,
        domain_findings=result.domain_findings,
    )


if __name__ == "__main__":
    print("phishing detector UI -> http://localhost:5057")
    app.run(port=5057, debug=True)
