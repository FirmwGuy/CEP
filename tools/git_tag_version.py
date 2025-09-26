#!/usr/bin/env python3
"""Emit the current project version derived from Git tags.

The script prints the most recent tag discovered via ``git describe --tags``.
Tags that follow the ``v##.##`` convention lose the leading ``v`` so Doxygen
receives a clean semantic version. When the repository has no tags (or Git is
unavailable) the script falls back to ``0.0.0`` so callers still receive a
value.
"""
from __future__ import annotations

import re
import subprocess
import sys
from typing import Optional

TAG_PATTERN = re.compile(r"^v(?P<num>\d+(?:\.\d+)*)$")


def describe_tags() -> Optional[str]:
    try:
        completed = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def normalise(tag: str) -> str:
    match = TAG_PATTERN.match(tag)
    if match:
        return match.group("num")
    return tag


def main() -> int:
    tag = describe_tags()
    if not tag:
        print("0.0.0")
        return 0
    print(normalise(tag))
    return 0


if __name__ == "__main__":
    sys.exit(main())
