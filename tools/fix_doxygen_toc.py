#!/usr/bin/env python3
"""Post-process Doxygen HTML to enforce CEP's documentation ordering rules.

The script reorders the L0 Kernel documentation entries in the generated
`pages.html` directory listing and in the navigation tree JavaScript so that:

* The Developer Handbook appears first within the L0 Kernel section.
* All other L0 Kernel pages appear after the handbook in alphabetical order.
* The L0 Kernel Roadmap is placed last within the section.

Non-L0 documentation entries keep their original ordering, and the script
updates the navtree index files so that navigation highlighting continues to
work after the reordering.

Run the script after `doxygen` (or `meson compile -C build docs_html`) finishes:

    python tools/fix_doxygen_toc.py build/docs/html
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


L0_HANDBOOK_KEYWORDS = ("Developer Handbook",)
L0_ROADMAP_KEYWORDS = ("Roadmap",)
L0_HREF_MARKER = "md_docs_2_l0___k_e_r_n_e_l"


def extract_js_array(text: str, var_name: str) -> Tuple[str, str, str]:
    """Return prefix, JSON payload, suffix for an array assigned to `var_name`."""

    var_pos = text.find(f"var {var_name}")
    if var_pos == -1:
        raise ValueError(f"Could not find variable '{var_name}' in file")

    start = text.find("[", var_pos)
    if start == -1:
        raise ValueError(f"Could not find array start for '{var_name}'")

    depth = 0
    end = -1
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                end = idx + 1
                break
    if end == -1:
        raise ValueError(f"Could not locate closing ']' for '{var_name}'")

    prefix = text[:start]
    payload = text[start:end]
    suffix = text[end:]
    return prefix, payload, suffix


def extract_js_object(text: str, var_name: str) -> Tuple[str, str, str]:
    """Return prefix, JSON payload, suffix for an object assigned to `var_name`."""

    var_pos = text.find(f"var {var_name}")
    if var_pos == -1:
        raise ValueError(f"Could not find variable '{var_name}' in file")

    start = text.find("{", var_pos)
    if start == -1:
        raise ValueError(f"Could not find object start for '{var_name}'")

    depth = 0
    end = -1
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = idx + 1
                break
    if end == -1:
        raise ValueError(f"Could not locate closing '}}' for '{var_name}'")

    prefix = text[:start]
    payload = text[start:end]
    suffix = text[end:]
    return prefix, payload, suffix


def reorder_pages_table(pages_path: Path) -> bool:
    text = pages_path.read_text(encoding="utf-8")
    table_match = re.search(
        r"(<table class=\"directory\">)(.*?)(</table>)",
        text,
        flags=re.DOTALL,
    )
    if not table_match:
        raise ValueError("Could not find directory table in pages.html")

    table_prefix, table_body, table_suffix = (
        table_match.group(1),
        table_match.group(2),
        table_match.group(3),
    )

    row_pattern = re.compile(r"(<tr[^>]*?>.*?</tr>)", re.DOTALL)
    rows = row_pattern.findall(table_body)
    if not rows:
        return False

    row_infos = []
    for row in rows:
        href_match = re.search(r"href=\"([^\"]+)\"", row)
        title_match = re.search(r">([^<]+)</a>", row)
        href = href_match.group(1) if href_match else ""
        title = title_match.group(1).strip() if title_match else ""
        row_infos.append(
            {
                "row": row,
                "href": href,
                "title": title,
                "is_l0": L0_HREF_MARKER in href,
            }
        )

    l0_rows = [info for info in row_infos if info["is_l0"]]
    if not l0_rows:
        return False

    def matches_any(title: str, keywords: Iterable[str]) -> bool:
        lowered = title.lower()
        return any(keyword.lower() in lowered for keyword in keywords)

    handbook = next(
        (info for info in l0_rows if matches_any(info["title"], L0_HANDBOOK_KEYWORDS)),
        None,
    )
    roadmap = next(
        (info for info in l0_rows if matches_any(info["title"], L0_ROADMAP_KEYWORDS)),
        None,
    )

    others = [
        info
        for info in l0_rows
        if info is not handbook and info is not roadmap
    ]
    others.sort(key=lambda info: info["title"].lower())

    new_l0_rows: List[Dict[str, str]] = []
    if handbook:
        new_l0_rows.append(handbook)
    new_l0_rows.extend(others)
    if roadmap:
        new_l0_rows.append(roadmap)

    if not new_l0_rows:
        return False

    composed_rows: List[str] = []
    inserted = False
    for info in row_infos:
        if info["is_l0"]:
            if not inserted:
                composed_rows.extend(item["row"] for item in new_l0_rows)
                inserted = True
            # Skip original L0 rows that have been re-inserted.
            continue
        composed_rows.append(info["row"])

    leading_newline = "\n" if table_body.startswith("\n") else ""
    trailing_newline = "\n" if table_body.endswith("\n") else ""
    new_table_body = leading_newline + "\n".join(composed_rows) + trailing_newline

    new_text = (
        text[: table_match.start(2)]
        + new_table_body
        + text[table_match.end(2) :]
    )

    pages_path.write_text(new_text, encoding="utf-8")
    return True


def reorder_navtree(navtree_path: Path) -> Dict[str, int]:
    text = navtree_path.read_text(encoding="utf-8")
    prefix, payload, suffix = extract_js_array(text, "NAVTREE")
    navtree = json.loads(payload)

    root = navtree[0]
    children = root[2]
    l0_indices = [
        idx for idx, node in enumerate(children) if node[0].startswith("L0 Kernel:")
    ]
    if not l0_indices:
        return {}

    block_start, block_end = min(l0_indices), max(l0_indices) + 1
    if l0_indices != list(range(block_start, block_end)):
        raise ValueError("L0 Kernel entries are not contiguous in NAVTREE")

    l0_block = children[block_start:block_end]

    def find_node(block: Iterable[List], keywords: Iterable[str]):
        for node in block:
            title = node[0]
            lowered = title.lower()
            if any(keyword.lower() in lowered for keyword in keywords):
                return node
        return None

    handbook_node = find_node(l0_block, L0_HANDBOOK_KEYWORDS)
    roadmap_node = find_node(l0_block, L0_ROADMAP_KEYWORDS)
    others = [
        node
        for node in l0_block
        if node is not handbook_node and node is not roadmap_node
    ]
    others.sort(key=lambda node: node[0].lower())

    new_block: List[List] = []
    if handbook_node:
        new_block.append(handbook_node)
    new_block.extend(others)
    if roadmap_node:
        new_block.append(roadmap_node)

    if not new_block:
        return {}

    children[block_start:block_end] = new_block

    new_payload = json.dumps(navtree, indent=2, ensure_ascii=False)
    if not new_payload.endswith("\n"):
        new_payload += "\n"
    navtree_path.write_text(prefix + new_payload + suffix, encoding="utf-8")

    updated_indices = {
        node[1]: idx for idx, node in enumerate(children) if block_start <= idx < block_start + len(new_block)
    }
    return updated_indices


def update_navtree_indexes(html_dir: Path, new_indices: Dict[str, int]) -> bool:
    changed_any = False
    for index_path in sorted(html_dir.glob("navtreeindex*.js")):
        text = index_path.read_text(encoding="utf-8")
        prefix, payload, suffix = extract_js_object(text, index_path.stem.upper())
        data = json.loads(payload)

        changed = False
        for key, value in data.items():
            if not isinstance(value, list) or not value:
                continue
            base_href = key.split("#", 1)[0]
            if base_href in new_indices and value[0] != new_indices[base_href]:
                value[0] = new_indices[base_href]
                changed = True

        if changed:
            new_payload = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
            if not new_payload.endswith("\n"):
                new_payload += "\n"
            index_path.write_text(prefix + new_payload + suffix, encoding="utf-8")
            changed_any = True

    return changed_any


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "html_root",
        nargs="?",
        default="build/docs/html",
        help="Path to the Doxygen HTML output directory",
    )
    args = parser.parse_args()

    html_root = Path(args.html_root)
    if not html_root.is_dir():
        raise SystemExit(f"HTML output directory not found: {html_root}")

    pages_path = html_root / "pages.html"
    navtree_path = html_root / "navtreedata.js"
    if not pages_path.exists() or not navtree_path.exists():
        raise SystemExit("Required Doxygen artifacts (pages.html/navtreedata.js) not found")

    pages_changed = reorder_pages_table(pages_path)
    new_indices = reorder_navtree(navtree_path)
    indexes_changed = update_navtree_indexes(html_root, new_indices)

    if not any((pages_changed, new_indices, indexes_changed)):
        print("No updates were necessary")


if __name__ == "__main__":
    main()
