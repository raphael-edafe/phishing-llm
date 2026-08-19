"""Local web UI for the phishing detector.

    python app.py     ->  http://localhost:5057

A thin Flask wrapper around scan(). The detection logic stays in
detect_phishing.py so there is exactly one copy of the prompt, the schema and
the two-layer composition - the UI never reimplements any of them.

Beyond calling scan(), this module does one thing: it locates each indicator's
quoted evidence inside the original email so the front end can highlight it.
Both layers are located the same way but tagged differently, because a
deterministic domain finding is a fact about the text and a model flag is a
judgement about it.
"""

import re

from flask import Flask, jsonify, request, send_from_directory
from openai import OpenAIError

from detect_phishing import scan
from spans import find_spans

app = Flask(__name__, static_folder="static")

# domain_check phrases its findings with the domains in single quotes, e.g.
# "body cites 'wetransfer.com' but the email was sent from 'we-transfer.com'".
# those quoted tokens are exactly the text worth highlighting.
QUOTED_RE = re.compile(r"'([^']+)'")


def domain_highlights(finding: str) -> list[dict]:
    """Turn one domain finding into highlightable quotes."""
    return [{"description": finding, "quote": q, "source": "verified"}
            for q in QUOTED_RE.findall(finding)]


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

    # verified findings are located first so they win any overlap - if both
    # layers point at the same domain, the provable one should own the mark
    items = [h for f in result.domain_findings for h in domain_highlights(f)]
    items += [{"description": f.description, "quote": f.quote, "source": "model"}
              for f in result.analysis.flags]

    # one finding can point at several strings - "body cites 'x' but was sent
    # from 'y'" marks two. group by description so the indicator is LISTED once
    # while still highlighting every span it refers to.
    groups: dict[str, int] = {}
    for item in items:
        item["group"] = groups.setdefault(item["description"], len(groups))

    return jsonify(
        email=email,
        category=result.analysis.category,
        risk_score=result.risk_score,
        model_score=result.analysis.risk_score,
        escalated=result.escalated,
        verdict=result.analysis.verdict,
        domain_findings=result.domain_findings,
        highlights=find_spans(email, items),
    )


if __name__ == "__main__":
    print("phishing detector UI -> http://localhost:5057")
    app.run(port=5057, debug=True)
