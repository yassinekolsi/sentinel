"""Render the submission report as standalone HTML and PDF.

The renderer intentionally uses no remote assets.  Run it from any directory:

    python scripts/render-report.py
"""

from __future__ import annotations

import argparse
import html
import re
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any, cast

from markdown_it import MarkdownIt
from markdown_it.token import Token

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPOSITORY_ROOT / "reports" / "technical-report.md"
DEFAULT_HTML = REPOSITORY_ROOT / "reports" / "technical-report.html"
DEFAULT_PDF = REPOSITORY_ROOT / "reports" / "technical-report.pdf"
DEFAULT_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")


STYLES = r"""
:root {
  --ink: #18232f;
  --muted: #5d6975;
  --navy: #12314a;
  --blue: #176b87;
  --teal: #14847b;
  --amber: #c46a24;
  --line: #cad5dc;
  --soft: #eef4f6;
  --paper: #ffffff;
}

* { box-sizing: border-box; }

html {
  background: #dfe6e9;
  color: var(--ink);
  font-family: "Segoe UI", Arial, sans-serif;
  font-size: 10.6pt;
  line-height: 1.54;
}

body {
  margin: 0 auto;
  max-width: 210mm;
  background: var(--paper);
  box-shadow: 0 10px 45px rgba(18, 49, 74, 0.15);
}

.report {
  padding: 19mm 17mm 22mm;
}

.skip-link {
  position: absolute;
  left: -9999px;
}

.skip-link:focus {
  left: 8px;
  top: 8px;
  z-index: 2;
  padding: 8px 12px;
  background: var(--paper);
  border: 2px solid var(--blue);
}

a { color: #0d6380; text-decoration-thickness: 0.07em; text-underline-offset: 0.14em; }
a:visited { color: #425e78; }

p { margin: 0 0 0.82em; }
ul, ol { margin: 0.35em 0 1em; padding-left: 1.45em; }
li { margin: 0.2em 0; }
li::marker { color: var(--blue); font-weight: 650; }

h1, h2, h3, h4 {
  color: var(--navy);
  font-weight: 680;
  line-height: 1.18;
  text-wrap: balance;
}

.report > h1:first-child {
  min-height: 104mm;
  margin: 0;
  padding-top: 31mm;
  border-top: 6px solid var(--teal);
  font-size: 29pt;
  letter-spacing: -0.025em;
}

.report > h1:first-child::before {
  display: block;
  margin-bottom: 9mm;
  color: var(--amber);
  content: "TECHNICAL REPORT";
  font-size: 9pt;
  font-weight: 750;
  letter-spacing: 0.22em;
}

.report > h1:first-child + p {
  margin: -23mm 0 0;
  padding: 7mm 0 0;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-size: 10.5pt;
  line-height: 1.75;
}

h2 {
  margin: 2.2em 0 0.7em;
  padding: 0.28em 0 0.34em;
  border-bottom: 2px solid var(--teal);
  font-size: 17pt;
  letter-spacing: -0.012em;
  break-after: avoid-page;
}

h3 {
  margin: 1.6em 0 0.5em;
  color: #184c67;
  font-size: 12.6pt;
  break-after: avoid-page;
}

h4 { margin: 1.3em 0 0.4em; font-size: 11pt; break-after: avoid-page; }
h2 + h3, h3 + h4 { margin-top: 0.8em; }

strong { font-weight: 700; }
code {
  padding: 0.08em 0.28em;
  border-radius: 3px;
  background: #eef2f4;
  color: #15384d;
  font-family: Consolas, "Cascadia Mono", monospace;
  font-size: 0.88em;
  overflow-wrap: anywhere;
}

pre {
  margin: 1em 0 1.25em;
  padding: 4.5mm 5mm;
  border: 1px solid #c4d0d7;
  border-left: 4px solid var(--blue);
  border-radius: 5px;
  background: #f5f8f9;
  color: #173345;
  font: 8.1pt/1.48 Consolas, "Cascadia Mono", monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  break-inside: avoid-page;
}

pre code { padding: 0; background: transparent; color: inherit; font-size: inherit; }

.toc {
  min-height: 230mm;
  padding-top: 7mm;
  break-before: page;
  break-after: page;
}

.toc h2 {
  margin-top: 0;
  font-size: 20pt;
}

.toc ol {
  margin: 8mm 0 0;
  padding: 0;
  column-count: 2;
  column-gap: 9mm;
  column-rule: 1px solid #e1e7ea;
  list-style: none;
}
.toc li {
  display: flex;
  align-items: baseline;
  gap: 0.6em;
  margin: 0;
  border-bottom: 1px dotted #c2cdd3;
  break-inside: avoid-column;
}
.toc li::after { flex: 1; order: 2; content: ""; }
.toc a { order: 1; padding: 0.34em 0; color: var(--navy); text-decoration: none; }
.toc .level-3 { padding-left: 8mm; border-bottom-color: #e0e6e9; font-size: 9.5pt; }
.toc .level-3 a { color: var(--muted); }

.table-wrap {
  width: 100%;
  margin: 1em 0 1.25em;
  break-inside: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid #bdcad1;
  font-size: 8.6pt;
  line-height: 1.35;
}

thead { display: table-header-group; }
tr { break-inside: avoid-page; }
th, td {
  padding: 2.2mm 2.4mm;
  border-right: 1px solid #d5dee3;
  border-bottom: 1px solid #d5dee3;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th:last-child, td:last-child { border-right: 0; }
th { background: var(--navy); color: white; font-weight: 680; }
tbody tr:nth-child(even) { background: var(--soft); }
.table-wrap.wide table { font-size: 7.15pt; line-height: 1.25; }
.table-wrap.wide th, .table-wrap.wide td { padding: 1.55mm 1.25mm; }
.table-wrap td code { padding: 0; background: transparent; font-size: 0.92em; word-break: break-all; }

.architecture {
  margin: 1.4em 0 1.7em;
  padding: 5mm;
  border: 1px solid #bfcfd6;
  border-radius: 7px;
  background: linear-gradient(145deg, #f6fafb, #edf4f5);
  break-inside: avoid-page;
}

.architecture-grid { display: grid; gap: 2.5mm; align-items: center; }
.architecture-row { display: grid; gap: 2mm; align-items: center; }
.architecture-inputs { grid-template-columns: 1fr 18px 1.55fr 18px 1fr; }
.architecture-sensor { grid-template-columns: 1.35fr 32px 1fr; }
.architecture-outputs { grid-template-columns: 1fr 1fr 1fr; align-items: stretch; }
.architecture .node {
  padding: 3mm 3.5mm;
  border: 1px solid #9fb4bf;
  border-radius: 5px;
  background: white;
  color: var(--navy);
  font-size: 8.8pt;
  font-weight: 620;
  line-height: 1.3;
  text-align: center;
}
.architecture .node.primary { border-color: var(--teal); background: #e6f3f1; }
.architecture .node.gateway { border-color: var(--blue); background: #e8f2f6; }
.architecture .arrow { color: var(--blue); font-size: 16pt; font-weight: 700; text-align: center; }
.architecture .down { line-height: 0.75; }
.architecture .label { display: block; margin-top: 1mm; color: var(--muted); font-size: 7.3pt; font-weight: 500; }
.architecture .flow-note { color: var(--muted); font-size: 7.4pt; line-height: 1.35; text-align: center; }
.architecture figcaption { margin-top: 3.5mm; color: var(--muted); font-size: 8pt; text-align: center; }

blockquote {
  margin: 1em 0;
  padding: 2mm 4mm;
  border-left: 4px solid var(--amber);
  background: #fcf7f1;
  color: #394958;
}

@media screen {
  .report > h2 { scroll-margin-top: 12px; }
}

@page {
  size: A4;
  margin: 16mm 15mm 18mm;
  @bottom-left {
    content: "SENTINEL · TECHNICAL REPORT";
    color: #6b7881;
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 7.5pt;
    letter-spacing: 0.08em;
  }
  @bottom-right {
    content: counter(page) " / " counter(pages);
    color: #6b7881;
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 7.5pt;
  }
}

@media print {
  html, body { width: auto; max-width: none; background: white; }
  body { box-shadow: none; }
  .report { padding: 0; }
  a { color: inherit; text-decoration: none; }
  a[href^="http"]::after { content: ""; }
  h2, h3, h4 { break-after: avoid-page; }
  p, li { orphans: 3; widows: 3; }
  .report > h1:first-child { min-height: 111mm; }
  .toc { min-height: 0; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""


def _slugify(value: str, used: set[str]) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    base = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-") or "section"
    slug = base
    suffix = 2
    while slug in used:
        slug = f"{base}-{suffix}"
        suffix += 1
    used.add(slug)
    return slug


def _architecture_diagram(source: str) -> str:
    """Render the report's small Mermaid graph without a JavaScript dependency."""
    required = {
        "A[Agent candidate action]",
        "F[Structural firewall]",
        "M[Optional local semantic sensor]",
        "G[Agent / tool gateway]",
        "V[Viewer and report]",
    }
    if not all(item in source for item in required):
        return ""
    return """
<figure class="architecture" role="img" aria-label="SENTINEL decision and evidence flow">
  <div class="architecture-grid">
    <div class="architecture-row architecture-inputs">
      <div class="node">Agent candidate action</div>
      <div class="arrow">+</div>
      <div class="node">Request-visible policy, provenance, history, observation</div>
      <div class="arrow">+</div>
      <div class="node">Bounded per-run state</div>
    </div>
    <div class="arrow down">↓</div>
    <div class="architecture-row architecture-sensor">
      <div class="node primary">Structural firewall</div>
      <div class="arrow">⇄</div>
      <div class="node">Optional local semantic sensor<span class="label">eligible non-read action</span></div>
    </div>
    <div class="arrow down">↓</div>
    <div class="node gateway">ALLOW · BLOCK · ESCALATE · REWRITE<br>Agent / tool gateway</div>
    <div class="arrow down">↓</div>
    <div class="architecture-row architecture-outputs">
      <div class="node">Bounded per-run state<span class="label">observed tool result; feeds the firewall</span></div>
      <div class="node">Decision sidecar<span class="label">from the structural firewall</span></div>
      <div class="node">Append-only event trace<span class="label">from the agent / tool gateway</span></div>
    </div>
    <div class="flow-note">State loops back into the firewall; the sidecar and trace feed the viewer.</div>
    <div class="arrow down">↓</div>
    <div class="node primary">Viewer and report</div>
  </div>
  <figcaption>Decision, state, and evidence flow.</figcaption>
</figure>
"""


def _fence_renderer(tokens: list[Token], index: int, *_: object) -> str:
    token = tokens[index]
    language = token.info.strip().split(maxsplit=1)[0] if token.info.strip() else ""
    if language == "mermaid":
        diagram = _architecture_diagram(token.content)
        if diagram:
            return diagram
    safe_language = re.sub(r"[^A-Za-z0-9_-]", "", language)
    class_name = f' class="language-{safe_language}"' if safe_language else ""
    return f"<pre><code{class_name}>{html.escape(token.content)}</code></pre>\n"


def _decorate_tokens(tokens: list[Token]) -> list[tuple[int, str, str]]:
    used_slugs: set[str] = set()
    headings: list[tuple[int, str, str]] = []
    for index, token in enumerate(tokens):
        if token.type != "heading_open" or index + 1 >= len(tokens):
            continue
        inline = tokens[index + 1]
        if inline.type != "inline":
            continue
        level = int(token.tag[1:])
        label = inline.content.strip()
        slug = _slugify(label, used_slugs)
        token.attrSet("id", slug)
        if level in {2, 3}:
            headings.append((level, label, slug))
    return headings


def _table_column_counts(tokens: list[Token]) -> dict[int, int]:
    counts: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.type != "table_open":
            continue
        columns = 0
        for candidate in tokens[index + 1 :]:
            if candidate.type == "th_open":
                columns += 1
            elif candidate.type == "tr_close":
                break
        counts[index] = columns
    return counts


def _render_markdown(source: str) -> tuple[str, list[tuple[int, str, str]]]:
    markdown = MarkdownIt(
        "commonmark",
        {"html": False, "linkify": False, "typographer": False},
    ).enable("table")
    renderer = cast(Any, markdown.renderer)
    renderer.rules["fence"] = _fence_renderer
    tokens = markdown.parse(source)
    headings = _decorate_tokens(tokens)
    table_columns = _table_column_counts(tokens)

    def table_open(items: list[Token], index: int, *_: object) -> str:
        width_class = " wide" if table_columns.get(index, 0) >= 7 else ""
        return f'<div class="table-wrap{width_class}"><table>\n'

    def table_close(*_: object) -> str:
        return "</table></div>\n"

    renderer.rules["table_open"] = table_open
    renderer.rules["table_close"] = table_close
    return renderer.render(tokens, markdown.options, {}), headings


def _table_of_contents(headings: list[tuple[int, str, str]]) -> str:
    items = "\n".join(
        f'<li class="level-{level}"><a href="#{slug}">{html.escape(label)}</a></li>' for level, label, slug in headings
    )
    return f"""
<nav class="toc" aria-labelledby="contents-heading">
  <h2 id="contents-heading">Contents</h2>
  <ol>
    {items}
  </ol>
</nav>
"""


def build_html(markdown_source: str) -> str:
    body, headings = _render_markdown(markdown_source)
    toc = _table_of_contents(headings)
    first_paragraph_end = body.find("</p>")
    if first_paragraph_end >= 0:
        insertion = first_paragraph_end + len("</p>")
        body = f"{body[:insertion]}\n{toc}\n{body[insertion:]}"
    else:
        body = f"{toc}\n{body}"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <meta name="generator" content="scripts/render-report.py">
  <base href="https://github.com/yassinekolsi/sentiel/blob/main/reports/">
  <title>SENTINEL technical report: evidence-first action firewall</title>
  <style>
{STYLES}
  </style>
</head>
<body>
  <a class="skip-link" href="#abstract">Skip to report</a>
  <main class="report">
{body}
  </main>
</body>
</html>
"""


def render_pdf(html_path: Path, pdf_path: Path, chrome_path: Path) -> None:
    if not chrome_path.is_file():
        raise FileNotFoundError(f"Chrome executable not found: {chrome_path}")
    runtime = REPOSITORY_ROOT / ".runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="report-chrome-", dir=runtime) as profile:
        command = [
            str(chrome_path),
            "--headless=new",
            "--disable-gpu",
            "--disable-extensions",
            "--no-first-run",
            "--no-default-browser-check",
            "--no-pdf-header-footer",
            "--run-all-compositor-stages-before-draw",
            f"--user-data-dir={Path(profile).resolve()}",
            f"--print-to-pdf={pdf_path.resolve()}",
            html_path.resolve().as_uri(),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if completed.returncode != 0:
        details = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Chrome PDF rendering failed ({completed.returncode}): {details}")
    if not pdf_path.is_file() or pdf_path.stat().st_size < 5:
        raise RuntimeError("Chrome exited successfully but did not create a PDF")
    if pdf_path.read_bytes()[:5] != b"%PDF-":
        raise RuntimeError("Generated file does not have a PDF header")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--html", type=Path, default=DEFAULT_HTML)
    parser.add_argument("--pdf", type=Path, default=DEFAULT_PDF)
    parser.add_argument("--chrome", type=Path, default=DEFAULT_CHROME)
    parser.add_argument("--html-only", action="store_true", help="Skip Chrome PDF generation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_path = args.source.resolve()
    html_path = args.html.resolve()
    pdf_path = args.pdf.resolve()
    markdown_source = source_path.read_text(encoding="utf-8")
    rendered = build_html(markdown_source)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"Rendered HTML: {html_path}")
    if not args.html_only:
        render_pdf(html_path, pdf_path, args.chrome)
        print(f"Rendered PDF:  {pdf_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
