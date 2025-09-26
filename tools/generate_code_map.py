#!/usr/bin/env python3
"""Generate code mapping artifacts for CEP.

This script runs ctags to collect symbol definitions and uses cscope to emit
call graph edges in a machine-friendly format so downstream tooling can merge
both datasets quickly.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Sequence, Set


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the code map generator."""
    parser = argparse.ArgumentParser(description='Build ctags + cscope code map artefacts.')
    parser.add_argument('--source-root', required=True, help='Project source root (Meson source).')
    parser.add_argument('--ctags-output', required=True, help='Path to write the ctags JSON lines file.')
    parser.add_argument('--callees-output', required=True, help='Path to write the cscope callees TSV dump.')
    parser.add_argument('--callers-output', required=True, help='Path to write the cscope callers TSV dump.')
    parser.add_argument('--cscope-database', help='Optional path for the cscope database (defaults next to ctags).')
    parser.add_argument('--cscope-listing', help='Optional path for cscope file listing (defaults next to ctags).')
    parser.add_argument('--ctags', default='ctags', help='ctags executable to invoke.')
    parser.add_argument('--cscope', default='cscope', help='cscope executable to invoke.')
    parser.add_argument('--include', action='append', default=[], help='Relative source subtree to scan.')
    return parser.parse_args()


def find_sources(source_root: Path, includes: Sequence[str]) -> List[Path]:
    """Return sorted source file paths (relative to *source_root*) for mapping."""
    search_roots: Sequence[str] = includes or ['src']
    collected: Set[Path] = set()
    for rel in search_roots:
        base = (source_root / rel).resolve()
        if not base.exists():
            continue
        for suffix in ('*.c', '*.h'):
            for match in base.rglob(suffix):
                if match.is_file():
                    collected.add(match.resolve())
    relative_paths = sorted(path.relative_to(source_root) for path in collected)
    return relative_paths


def run_checked(cmd: Sequence[str], cwd: Path) -> None:
    """Run *cmd* inside *cwd* and raise a helpful error if it fails."""
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        sys.stderr.write('Command failed: {}\n'.format(' '.join(cmd)))
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)


def write_ctags(ctags_bin: str, source_root: Path, sources: Sequence[Path], output_path: Path) -> None:
    """Invoke ctags to produce a JSON lines file with symbol definitions."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    command = [
        ctags_bin,
        '--output-format=json',
        '--fields=+neK',
        '--extras=+q',
        '--languages=C',
        '--sort=no',
        '-o', output_path.as_posix(),
    ] + [path.as_posix() for path in sources]
    run_checked(command, cwd=source_root)


def load_function_symbols(ctags_output: Path) -> Set[str]:
    """Extract function symbol names from the ctags JSON stream."""
    functions: Set[str] = set()
    with ctags_output.open('r', encoding='utf-8') as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get('_type') != 'tag':
                continue
            if entry.get('kind') != 'function':
                continue
            name = entry.get('name')
            if name:
                functions.add(name)
    return functions


def write_cscope_database(
    cscope_bin: str,
    source_root: Path,
    sources: Sequence[Path],
    listing_path: Path,
    database_path: Path,
) -> None:
    """Generate the cscope database used for callers/callees dumps."""
    listing_path.parent.mkdir(parents=True, exist_ok=True)
    if database_path.exists():
        database_path.unlink()
    with listing_path.open('w', encoding='utf-8', newline='\n') as handle:
        for path in sources:
            handle.write(f'{path.as_posix()}\n')
    command = [
        cscope_bin,
        '-b',
        '-q',
        '-k',
        '-i', listing_path.as_posix(),
        '-f', database_path.as_posix(),
    ]
    run_checked(command, cwd=source_root)


def dump_edges(
    cscope_bin: str,
    database_path: Path,
    source_root: Path,
    symbols: Iterable[str],
    query_flag: str,
    destination: Path,
) -> None:
    """Write caller/callee edges for each symbol to *destination* as TSV."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('w', encoding='utf-8', newline='\n') as handle:
        for symbol in sorted(set(symbols)):
            if not symbol:
                continue
            command = [
                cscope_bin,
                '-d',
                '-f', database_path.as_posix(),
                '-L',
                query_flag,
                symbol,
            ]
            result = subprocess.run(
                command,
                cwd=source_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode not in (0, 1):
                sys.stderr.write('cscope query failed: {}\n'.format(' '.join(command)))
                if result.stdout:
                    sys.stderr.write(result.stdout)
                if result.stderr:
                    sys.stderr.write(result.stderr)
                raise SystemExit(result.returncode)
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                handle.write(f'{symbol}\t{line}\n')


def main() -> int:
    """Coordinate the mapping generation workflow."""
    args = parse_args()
    source_root = Path(args.source_root).resolve()
    ctags_output = Path(args.ctags_output).resolve()
    callees_output = Path(args.callees_output).resolve()
    callers_output = Path(args.callers_output).resolve()
    base_dir = ctags_output.parent
    base_dir.mkdir(parents=True, exist_ok=True)

    database_path = Path(args.cscope_database).resolve() if args.cscope_database else base_dir / 'cscope.out'
    listing_path = Path(args.cscope_listing).resolve() if args.cscope_listing else base_dir / 'cscope.files'
    database_path.parent.mkdir(parents=True, exist_ok=True)
    listing_path.parent.mkdir(parents=True, exist_ok=True)

    sources = find_sources(source_root, args.include)
    if not sources:
        sys.stderr.write('No sources found for code map generation.\n')
        return 0

    write_ctags(args.ctags, source_root, sources, ctags_output)
    function_symbols = load_function_symbols(ctags_output)
    write_cscope_database(args.cscope, source_root, sources, listing_path, database_path)
    dump_edges(args.cscope, database_path, source_root, function_symbols, '-2', callees_output)
    dump_edges(args.cscope, database_path, source_root, function_symbols, '-3', callers_output)

    return 0


if __name__ == '__main__':
    sys.exit(main())
