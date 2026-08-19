"""Locate quoted evidence inside the original email text.

The model returns each indicator with a verbatim quote, but "verbatim" is a
request, not a guarantee - it re-wraps lines, collapses the runs of whitespace
that email bodies are full of, and occasionally tidies punctuation. A plain
str.find() therefore misses quotes that are, to a reader, plainly present.

So matching runs against a whitespace-normalised copy while keeping an index
map back to the original, and a quote that still cannot be found is reported
without a highlight rather than dropped or approximated. Highlighting the wrong
span would be worse than highlighting nothing: it would attach a claim to text
that does not support it.

Self-test:  python spans.py
"""


def _normalise(text: str) -> tuple[str, list[int]]:
    """Collapse whitespace runs, keeping a map from new index -> original index."""
    out: list[str] = []
    idx: list[int] = []
    prev_space = False
    for i, ch in enumerate(text):
        if ch.isspace():
            if prev_space:
                continue
            out.append(" ")
            idx.append(i)
            prev_space = True
        else:
            out.append(ch)
            idx.append(i)
            prev_space = False
    return "".join(out), idx


def locate(text: str, quote: str) -> tuple[int, int] | None:
    """Return (start, end) of quote within text, or None if it isn't there."""
    quote = quote.strip()
    if len(quote) < 3:
        return None

    exact = text.find(quote)
    if exact >= 0:
        return exact, exact + len(quote)

    norm_text, idx = _normalise(text)
    norm_quote = " ".join(quote.split())

    pos = norm_text.find(norm_quote)
    if pos < 0:
        pos = norm_text.lower().find(norm_quote.lower())
    if pos < 0:
        return None

    start = idx[pos]
    end = idx[pos + len(norm_quote) - 1] + 1
    return start, end


def find_spans(text: str, items: list[dict]) -> list[dict]:
    """Attach a span to each item that carries a locatable quote.

    items are dicts with a 'quote' key. Each gets 'start'/'end' added, or None
    when the quote could not be found. Overlaps are resolved first-come: two
    indicators pointing at the same words would otherwise produce nested marks
    that are awkward to render and no clearer to read.
    """
    placed: list[tuple[int, int]] = []
    out = []
    for item in items:
        span = locate(text, item.get("quote", "") or "")
        reason = None
        if span is None:
            reason = "not_found"
        elif any(span[0] < e and s < span[1] for s, e in placed):
            # the text IS present, but an earlier item already marks it. that
            # is not the same as a quote we could not find, and reporting it
            # as such would be a small lie about highlighted text.
            span, reason = None, "overlap"
        if span:
            placed.append(span)
        out.append({**item, "start": span[0] if span else None,
                    "end": span[1] if span else None, "reason": reason})
    return out


if __name__ == "__main__":
    body = ("From: PayPal Security <service@paypa1-secure.com>\n"
            "Subject: URGENT: Your account has been limited\n\n"
            "You must confirm your identity within 24 hours or your account\n"
            "will be permanently suspended.\n\n"
            "Please have your password and the card number on file ready.\n")

    cases = [
        ("exact match", "Dear Valued", None),
        ("plain substring", "permanently suspended", (True,)),
        ("quote spanning a wrapped line", "within 24 hours or your account will be permanently suspended", (True,)),
        ("header line", "service@paypa1-secure.com", (True,)),
        ("case-insensitive fallback", "PLEASE HAVE YOUR PASSWORD", (True,)),
        ("paraphrase - must NOT match", "threatens to suspend the account", None),
        ("too short", "or", None),
    ]

    passed = 0
    for label, quote, expect in cases:
        got = locate(body, quote)
        ok = (got is not None) == (expect is not None)
        passed += ok
        shown = f"{got}  ->  {body[got[0]:got[1]]!r}" if got else "not found"
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: {shown}")

    print(f"\n{passed}/{len(cases)} passed")
