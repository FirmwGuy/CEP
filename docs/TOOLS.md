# CEP Tooling Guide

CEP bundles a handful of helper scripts in `tools/` so you can keep the build artifacts, documentation, and symbol maps up to date without memorising long command lines. Think of this as the short tour that says what each script is for and when to reach for it.

## Technical Details
- **`tools/capture-fixtures.sh`**  
  Runs `build/cep_tests.exe` with a fixed seed, archives the full log to `build/fixtures/cep_tests_full.log`, and extracts focussed heartbeat snippets. Use it before risky refactors to grab a baseline, or after a change to compare the new agenda routing with the saved logs.
- **`tools/check_unused_tags.py`**  
  Scans `docs/CEP-TAG-LEXICON.md` for tag identifiers and reports which ones do not appear anywhere else in the repository. Handy when extending the lexicon or pruning obsolete entries. Invoke with `python tools/check_unused_tags.py` from the project root.
- **`tools/fix_doxygen_toc.py`**  
  Post-processes a generated Doxygen tree so the Layer 0 documents follow CEP’s preferred order (Developer Handbook first, Roadmap last). Run it on the HTML directory after `meson compile -C build docs_html`, e.g. `python tools/fix_doxygen_toc.py build/docs/html`.
- **`tools/generate_code_map.py`**  
  Produces the symbol map files under `build/code_map_*` by driving ctags and cscope. Meson already wires this through `meson compile -C build code_map`, but you can call it directly if you need custom paths or want to point at a different source subtree.
- **`tools/git_tag_version.py`**  
  Prints the current version number, favouring the latest Git tag (minus any leading `v`). Used by Meson to feed Doxygen, yet safe to run standalone (`python tools/git_tag_version.py`) when you need to confirm the tag that build tooling will advertise.
- **`tools/run_doxygen.py`**  
  Lightweight wrapper that runs Doxygen, optionally triggers a post-processing step (such as `fix_doxygen_toc.py`), and touches a stamp file so Meson knows the doc build succeeded. Meson’s `docs_html` target uses it; invoke it manually if you maintain a custom documentation pipeline.

## Q&A
- **Do I need to install anything extra to use these helpers?**  
  No additional Python packages are required; the scripts only rely on the standard library and tools already present in the repository’s Meson workflows (ctags, cscope, Doxygen).
- **Can I run the scripts from outside the repo root?**  
  Most helpers assume the current working directory is the project root so they can resolve relative paths. When in doubt, `cd` into the repository before executing them.
- **How do I keep fixture logs from growing stale?**  
  Re-run `tools/capture-fixtures.sh` whenever you intentionally change heartbeat ordering, then review and commit the updated files under `build/fixtures/` if they form part of your baseline artefacts.
