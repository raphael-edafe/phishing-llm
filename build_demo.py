"""Generate the static demo page from the live UI.

    python build_demo.py     ->  docs/index.html

The demo is BUILT from static/index.html rather than maintained as a copy, so
the two cannot drift apart. Every change to the real interface lands in the
demo the next time this runs.

What it produces is a genuinely interactive page with no server behind it: the
UI already renders from a JSON payload, so recorded analyses can be swapped in
where the API response would go. Hovering, highlighting and the layer colours
all work. Nothing can break, expire, or cost anything.

It is labelled as recorded rather than live. A demo that lets a reader assume
it is calling an API when it is not would be the same kind of overstatement the
detector itself is built to avoid.
"""

import json
import pathlib
import shutil

SRC = pathlib.Path("static/index.html")
CASES = pathlib.Path("demo_cases.json")
OUT_DIR = pathlib.Path("docs")


def cut(text: str, start: str, end: str) -> str:
    """Remove start..end inclusive of start, exclusive of end."""
    a = text.index(start)
    b = text.index(end, a)
    return text[:a] + text[b:]


def main() -> None:
    if not CASES.exists():
        raise SystemExit("demo_cases.json not found - capture the cases first")

    html = SRC.read_text(encoding="utf-8")
    cases = json.loads(CASES.read_text(encoding="utf-8"))

    # --- swap the composer for a case picker ---------------------------------
    picker = """  <div class="box">
    <div class="bar"><span class="k">$</span> recorded analyses <span class="sp"></span>
      <span class="note">no api - nothing is sent anywhere</span></div>
    <div class="in">
      <div class="cases" id="cases"></div>
      <p class="note demo-note">These are real outputs, captured from actual runs and saved.
        The page is static: hovering, highlighting and the layer colours all work, but
        nothing is being analysed live. Run it against your own email with
        <code>python app.py</code>.</p>
    </div>
  </div>
"""
    html = cut(html, '  <div class="box">\n    <div class="bar"><span class="k">$</span> paste an email',
               '\n  <div id="out"></div>')
    html = html.replace('\n  <div id="out"></div>', "\n" + picker + '\n  <div id="out"></div>', 1)

    # --- drop the live-call code, keep all the rendering ---------------------
    html = cut(html, "const SAMPLE = ", "// coloured by DANGER")
    html = cut(html, "$('#go').onclick = async () => {", "</script>")

    # --- styles for the picker ----------------------------------------------
    html = html.replace(".note { color: var(--dim); font-size: 12px; }",
""".note { color: var(--dim); font-size: 12px; }
.demo-note { margin: 14px 0 0; line-height: 1.55; }
.demo-note code { color: var(--text); }
.cases { display: flex; flex-direction: column; gap: 6px; }
.case {
  text-align: left; width: 100%; padding: 9px 11px;
  display: flex; align-items: baseline; gap: 10px;
}
.case .cat { font-weight: 700; letter-spacing: .08em; flex: none; }
.case.legitimate .cat { color: var(--legit); }
.case.spam       .cat { color: var(--spam); }
.case.phishing   .cat { color: var(--phish); }
.case .sc { margin-left: auto; color: var(--mid); flex: none; }
.case.on { border-color: var(--mid); color: var(--bright); }""", 1)

    # --- data + wiring -------------------------------------------------------
    wiring = """
const DEMO = __CASES__;

// the picker stands in for the API: same payload shape, same render path
const list = $('#cases');
DEMO.forEach((d) => {
  const b = document.createElement('button');
  b.className = 'case ' + d.category;
  b.innerHTML = '<span class="cat">[ ' + d.category.toUpperCase() + ' ]</span>'
              + '<span>' + d.label + '</span>'
              + '<span class="sc">' + d.risk_score.toFixed(2)
              + (d.escalated ? ' \\u2191' : '') + '</span>';
  b.onclick = () => {
    [...list.children].forEach(c => c.classList.remove('on'));
    b.classList.add('on');
    render(d);
    $('#cols').classList.add('split');
  };
  list.append(b);
});

// selected AFTER the list is built, not from inside the loop - clicking a
// button while its siblings are still being appended made which one ended up
// selected non-deterministic
list.firstElementChild.click();
</script>"""
    # the LAST </script>, not the first - the first belongs to the motion.js
    # <script src=...> tag, and inline content there is silently ignored by the
    # browser, so the wiring would never run and never error
    head, sep, tail = html.rpartition("</script>")
    assert sep, "no closing script tag found"
    html = head + wiring.replace("__CASES__", json.dumps(cases)) + tail

    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "static").mkdir(exist_ok=True)
    (OUT_DIR / "static" / "vendor").mkdir(parents=True, exist_ok=True)
    shutil.copy("static/vendor/motion.js", OUT_DIR / "static/vendor/motion.js")
    # relative so it works from a project subpath on github pages
    html = html.replace('src="/static/vendor/motion.js"', 'src="static/vendor/motion.js"')

    (OUT_DIR / "index.html").write_text(html, encoding="utf-8")
    print(f"wrote {OUT_DIR / 'index.html'} ({len(html):,} bytes, {len(cases)} cases)")
    for c in cases:
        print(f"  {c['category']:<11} {c['risk_score']:.2f}  {c['label']}")


if __name__ == "__main__":
    main()
