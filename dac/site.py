"""Build the dashboard: one self-contained index.html (no build step, no network calls
other than web fonts) plus results.json for anyone who prefers the raw data."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

WEB = Path(__file__).parent / "web"


def _json_for_script(data: Any) -> str:
    """JSON that is safe inside a <script> element: log content can never close the tag."""
    text = json.dumps(data, ensure_ascii=False)
    for char, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(char, escaped)
    return text


def _repo_url() -> Optional[str]:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        return None
    return f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}"


def build_site(results: Dict[str, Any], out_dir: Path) -> Path:
    results = {**results, "repo_url": _repo_url()}
    parts = {
        "STYLE": (WEB / "style.css").read_text(encoding="utf-8"),
        "ENGINE": (WEB / "engine.js").read_text(encoding="utf-8"),
        "APP": (WEB / "app.js").read_text(encoding="utf-8"),
        "DATA": _json_for_script(results),
    }
    template = (WEB / "template.html").read_text(encoding="utf-8")
    # One pass, so text inside a substituted part is never scanned for placeholders again.
    html = re.sub(r"@@(STYLE|ENGINE|APP|DATA)@@", lambda m: parts[m.group(1)], template)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    (out_dir / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_dir
