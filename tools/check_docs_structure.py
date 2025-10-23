#!/usr/bin/env python3
"""
Validate CEP documentation structure.

Ensures every Markdown document under docs/ ends with a top-level
`## Global Q&A` section and has no additional level-2 headings after it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    docs_root = repo_root / "docs"

    issues: list[tuple[Path, str]] = []
    for path in sorted(docs_root.rglob("*.md")):
        rel = path.relative_to(repo_root)
        text = path.read_text()

        marker = "## Global Q&A"
        if marker not in text:
            issues.append((rel, "missing '## Global Q&A' section"))
            continue

        idx = text.rfind(marker)
        tail = text[idx + len(marker) :]
        if re.search(r"\n##[^#]", tail):
            issues.append((rel, "found additional level-2 heading after final Global Q&A"))

    if issues:
        for rel, msg in issues:
            print(f"{rel}: {msg}", file=sys.stderr)
        return 1

    print("All docs contain a terminal '## Global Q&A' section.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
