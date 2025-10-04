#!/usr/bin/env python3
"""Report CEP lexicon tags that have no usage in tracked sources."""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
LEXICON_PATH = REPO_ROOT / "docs" / "CEP-TAG-LEXICON.md"
CODE_PATTERN = re.compile(r"`([^`]+)`")

@dataclass
class TagEntry:
    raw: str
    normalized: str
    is_pattern: bool


def parse_lexicon(path: Path) -> list[TagEntry]:
    entries: list[TagEntry] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("| "):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if not cols:
            continue
        first_col = cols[0]
        codes = CODE_PATTERN.findall(first_col)
        for code in codes:
            if not code:
                continue
            entries.append(
                TagEntry(
                    raw=code,
                    normalized=code,
                    is_pattern=("*" in code or "(" in code or ")" in code),
                )
            )
    return entries


def tracked_files() -> Iterable[Path]:
    output = subprocess.check_output(["git", "ls-files"], cwd=REPO_ROOT, text=True)
    for rel in output.splitlines():
        if rel == "docs/CEP-TAG-LEXICON.md":
            continue
        yield REPO_ROOT / rel


def literal_hit(text: str, tag: str) -> bool:
    needles = [
        f'"{tag}"',
        f"'{tag}'",
        f'`{tag}`',
        f'CEP_DTAW("CEP", "{tag}")',
        f"CEP_DTAW('CEP', '{tag}')",
    ]
    return any(needle in text for needle in needles)


def main() -> None:
    entries = parse_lexicon(LEXICON_PATH)
    literals = {e.normalized: False for e in entries if not e.is_pattern}
    patterns = {e.normalized: False for e in entries if e.is_pattern}

    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for tag in list(literals):
            if literals[tag]:
                continue
            if literal_hit(text, tag):
                literals[tag] = True
        for tag in list(patterns):
            if patterns[tag]:
                continue
            base = tag.split("*")[0]
            base = base.split("(")[0]
            base = base.strip()
            if base and base in text:
                patterns[tag] = True

    unused = [
        {"tag": tag, "pattern": "no"}
        for tag, hit in sorted(literals.items())
        if not hit
    ] + [
        {"tag": tag, "pattern": "yes"}
        for tag, hit in sorted(patterns.items())
        if not hit
    ]

    print(json.dumps({"unused": unused}, indent=2))


if __name__ == "__main__":
    main()
