"""Check that relative Markdown links and in-page anchors resolve.

External URLs (http/https/mailto) are not fetched — only local targets are
verified, so the check is offline and deterministic.  Run from anywhere:

    python backend/scripts/check_doc_links.py

Exits non-zero and lists every broken link, so CI fails on documentation rot.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
SKIP_DIRS = {".git", "node_modules", ".venv", ".next", ".pytest_cache", "__pycache__"}


def _markdown_files() -> list[Path]:
    return sorted(
        p
        for p in ROOT.rglob("*.md")
        if not any(part in SKIP_DIRS for part in p.parts)
    )


def _slugify(heading: str) -> str:
    text = re.sub(r"[^a-z0-9 -]", "", heading.lower())
    return text.strip().replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#"):
            anchors.add(_slugify(line.lstrip("#").strip()))
    return anchors


def main() -> int:
    files = _markdown_files()
    broken: list[str] = []
    total = 0

    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for raw in LINK_RE.findall(text):
            if raw.startswith(("http://", "https://", "mailto:", "#")):
                if not raw.startswith("#"):
                    continue
            total += 1
            target, _, anchor = raw.partition("#")
            resolved = (path.parent / target).resolve() if target else path.resolve()
            if target and not resolved.exists():
                broken.append(f"{path.relative_to(ROOT)}: missing target -> {raw}")
                continue
            if anchor and resolved.suffix == ".md":
                if anchor not in _anchors(resolved):
                    broken.append(f"{path.relative_to(ROOT)}: missing anchor '#{anchor}' in {target}")

    print(f"checked {len(files)} markdown files, {total} relative links")
    if broken:
        print(f"{len(broken)} broken:")
        for line in broken:
            print(f"  - {line}")
        return 1
    print("0 broken")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
