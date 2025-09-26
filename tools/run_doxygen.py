#!/usr/bin/env python3
"""Run Doxygen with a configuration file and record a Meson-friendly stamp."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Collect command-line arguments so we know which Doxygen config to run."""
    parser = argparse.ArgumentParser(description='Invoke Doxygen and touch a stamp file.')
    parser.add_argument('--doxygen', required=True, help='Path to the Doxygen executable.')
    parser.add_argument('--config', required=True, help='Doxygen configuration file to use.')
    parser.add_argument('--stamp', required=True, help='Path to the stamp file to create on success.')
    return parser.parse_args()


def main() -> int:
    """Execute Doxygen and touch the stamp so Meson sees deterministic outputs."""
    args = parse_args()
    config_path = Path(args.config)
    if not config_path.exists():
        sys.stderr.write(f'Doxygen config not found: {config_path}\n')
        return 1

    result = subprocess.run([args.doxygen, str(config_path)], text=True)
    if result.returncode != 0:
        return result.returncode

    stamp_path = Path(args.stamp)
    stamp_path.parent.mkdir(parents=True, exist_ok=True)
    stamp_path.touch()
    return 0


if __name__ == '__main__':
    sys.exit(main())
