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
from html import escape
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


L0_HANDBOOK_KEYWORDS = ("Developer Handbook",)
L0_ROADMAP_KEYWORDS = ("Roadmap",)
L0_HREF_MARKER = "md_docs_2_l0___k_e_r_n_e_l"
RAW_AMPERSAND_RE = re.compile(r"&(?![A-Za-z0-9#]+;)")
HEADING_PLACEHOLDER_RE = re.compile(
    r"(<h[1-6][^>]*><a[^>]*id=\"(autotoc_md\d+)\"[^>]*></a>\s*)(autotoc_md\d+)(\s*</h[1-6]>)"
)


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
    index_and_nodes = [
        (idx, node)
        for idx, node in enumerate(children)
        if node[0].startswith("L0 Kernel:")
    ]
    if not index_and_nodes:
        return {}

    first_index = min(idx for idx, _ in index_and_nodes)
    l0_block = [node for _, node in index_and_nodes]

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

    for idx, _ in sorted(index_and_nodes, key=lambda item: item[0], reverse=True):
        del children[idx]
    children[first_index:first_index] = new_block

    new_payload = json.dumps(navtree, indent=2, ensure_ascii=False)
    if not new_payload.endswith("\n"):
        new_payload += "\n"
    navtree_path.write_text(prefix + new_payload + suffix, encoding="utf-8")

    updated_indices = {
        node[1]: first_index + offset for offset, node in enumerate(new_block)
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


def update_navtree_labels(navtree_path: Path, label_map: Dict[str, str]) -> None:
    if not label_map:
        return

    text = navtree_path.read_text(encoding="utf-8")
    prefix, payload, suffix = extract_js_array(text, "NAVTREE")
    navtree = json.loads(payload)
    changed = False

    def apply(node: List) -> None:
        nonlocal changed
        if not isinstance(node, list) or len(node) < 2:
            return
        title = node[0]
        link = node[1]
        if isinstance(title, str) and isinstance(link, str) and "#" in link:
            anchor = link.split("#", 1)[1]
            if anchor in label_map and title == anchor:
                new_title = label_map[anchor]
                if title != new_title:
                    node[0] = new_title
                    changed = True
        if len(node) > 2 and isinstance(node[2], list):
            for child in node[2]:
                apply(child)

    apply(navtree[0])

    if changed:
        new_payload = json.dumps(navtree, indent=2, ensure_ascii=False)
        if not new_payload.endswith("\n"):
            new_payload += "\n"
        navtree_path.write_text(prefix + new_payload + suffix, encoding="utf-8")


def encode_doxygen_html_name(md_relative: Path) -> str:
    full = Path("docs") / md_relative
    stem = str(full.with_suffix(""))
    parts: List[str] = []
    for char in stem:
        if char == "/":
            parts.append("_2")
        elif char == "_":
            parts.append("__")
        else:
            parts.append(char)
    return "md_" + "".join(parts) + ".html"


def collect_ampersand_headings(docs_root: Path) -> Dict[Path, List[str]]:
    mapping: Dict[Path, List[str]] = {}
    for md_path in sorted(docs_root.rglob("*.md")):
        headings: List[str] = []
        for line in md_path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("#"):
                continue
            text = line.lstrip("#").strip()
            if not text:
                continue
            if RAW_AMPERSAND_RE.search(text):
                headings.append(text)
        if headings:
            rel = md_path.relative_to(docs_root)
            html_name = encode_doxygen_html_name(rel)
            mapping[Path(html_name)] = headings
    return mapping


def fix_heading_placeholders(html_root: Path, html_name: Path, headings: List[str]) -> Tuple[bool, Dict[str, str]]:
    if not headings:
        return False, {}

    candidates = list(html_root.rglob(str(html_name)))
    if not candidates:
        return False, {}

    # Prefer the first candidate (Doxygen should emit exactly one file).
    html_path = candidates[0]
    text = html_path.read_text(encoding="utf-8")
    idx = 0
    changed = False
    replacements: Dict[str, str] = {}

    def repl(match: re.Match[str]) -> str:
        nonlocal idx, changed
        if idx >= len(headings):
            return match.group(0)
        replacement = escape(headings[idx], quote=False)
        anchor = match.group(2)
        replacements[anchor] = replacement
        idx += 1
        changed = True
        return f"{match.group(1)}{replacement}{match.group(4)}"

    new_text = HEADING_PLACEHOLDER_RE.sub(repl, text)
    if changed:
        html_path.write_text(new_text, encoding="utf-8")
    return changed, replacements


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "html_root",
        nargs="?",
        default="build/docs/html",
        help="Path to the Doxygen HTML output directory",
    )
    parser.add_argument(
        "--docs-root",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs",
        help="Path to the Markdown documentation root (defaults to repo/docs)",
    )
    args = parser.parse_args()

    html_root = Path(args.html_root)
    docs_root = args.docs_root
    if not html_root.is_dir():
        raise SystemExit(f"HTML output directory not found: {html_root}")
    if not docs_root.is_dir():
        raise SystemExit(f"Docs root not found: {docs_root}")

    pages_path = html_root / "pages.html"
    navtree_path = html_root / "navtreedata.js"
    if not pages_path.exists() or not navtree_path.exists():
        raise SystemExit("Required Doxygen artifacts (pages.html/navtreedata.js) not found")

    pages_changed = reorder_pages_table(pages_path)
    new_indices = reorder_navtree(navtree_path)
    indexes_changed = update_navtree_indexes(html_root, new_indices)

    heading_map = collect_ampersand_headings(docs_root)
    heading_fixes = 0
    heading_labels: Dict[str, str] = {}
    for html_rel, headings in heading_map.items():
        changed, replacements = fix_heading_placeholders(html_root, html_rel, headings)
        if changed:
            heading_fixes += 1
        heading_labels.update(replacements)

    if heading_labels:
        update_navtree_labels(navtree_path, heading_labels)

    if any((pages_changed, new_indices, indexes_changed, heading_fixes)):
        print(
            "pages reordered:",
            "yes" if pages_changed else "no",
            "| navtree entries:",
            len(new_indices),
            "| navtree indexes updated:",
            "yes" if indexes_changed else "no",
            "| heading placeholders fixed:",
            heading_fixes,
        )
    else:
        print("No updates were necessary")


if __name__ == "__main__":
    main()
