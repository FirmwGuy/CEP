# L0 Design: Domain/Tag Naming and Namepool Lifecycle

## Nontechnical Summary
Layer 0 names every cell with a compact pair—Domain and Tag—that fits in two 58-bit fields. This keeps routing fast, enables glob-style pattern matching, and lets storage stay lean. When human-readable strings grow beyond those limits, the namepool interns them once and hands back a reference. The design balances determinism and flexibility: IDs stay numeric for performance, yet anyone can add new vocabulary without recompiling the kernel.

## Decision Record
- Domain/Tag pairs use fixed-width numeric encodings (`cepDT`), avoiding pointer comparisons and keeping paths portable across processes.
- Word, acronym, numeric, and glob sentinel encodings live side-by-side; glob evaluation happens arithmetically, not via strings.
- The namepool stores longer strings as reference IDs (`CEP_NAMING_REFERENCE`) so higher layers can retain rich naming without bloating every cell.
- Reference IDs are append-only and replayable: the namepool journal ensures the same `(page,slot)` values reappear during replay.
- Matching functions (`cep_id_matches`, `cep_path_matches`) honour glob bits while staying branch-light, keeping enzyme dispatch deterministic.

## Subsystem Map
- Code
  - `src/l0_kernel/cep_identifier.c`, `cep_identifier.h` — DT encoding/decoding, glob helpers, comparisons.
  - `src/l0_kernel/cep_namepool.c`, `cep_namepool.h` — intern/lookup/release API, snapshot/replay integration.
  - `src/l0_kernel/cep_cell.c` — integrates naming helpers when creating cells and stores.
- Tests
  - `src/test/l0_kernel/test_identifier.c`, `test_domain_tag_naming.c` — encoding, glob semantics, invalid inputs.
  - `src/test/l0_kernel/test_cell.c` (selected cases) — ensures naming contracts hold during cell operations.
  - `src/test/l0_kernel/test_ops.c` (indirect) — validates globbed watchers and signal matching.

## Operational Guidance
- Reserve glob sentinels (`CEP_ID_GLOB_*`) for routing; do not treat them as literal names.
- Use the namepool only when names exceed the packed word/acronym limits or must persist verbatim; unnecessary interning increases journal traffic.
- Always release dynamic namepool entries (`cep_namepool_release`) when modules unload to prevent reference leaks; static interns stay permanent.
- Validate external inputs through `cep_id_text_valid` before interning to avoid illegal characters and keep replay deterministic.
- Monitor namepool growth in long-running deployments; an unexpectedly large pool may indicate callers neglecting releases.

## Change Playbook
1. Re-read this design doc plus `docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md`, `docs/L0_KERNEL/topics/GLOB-MATCHING.md`, and the naming sections in `docs/CEP-TAG-LEXICON.md`.
2. Update `cep_identifier.c/h` or `cep_namepool.c/h` with new encodings or semantics; ensure packed bitfields remain backward compatible.
3. Extend tests (`test_identifier.c`, `test_domain_tag_naming.c`, relevant cell tests) to cover new cases or failure modes.
4. Run `meson test -C build --suite identifier` (and related suites) followed by `python tools/check_docs_structure.py` and `meson compile -C build docs_html`.
5. Document any new tags or conventions in `docs/CEP-TAG-LEXICON.md` and refresh orientation/index references if categories change.
6. Coordinate with tooling (e.g., code map generators) if the DTO format changes so downstream scripts continue to parse IDs correctly.

## Global Q&A
- **Why 58-bit fields instead of full 64-bit?** The extra bits provide guard space for glob markers and validation flags while keeping the footprint aligned with existing packing macros.
- **Do reference IDs survive replay?** Yes. The namepool journal replays in append-only order, reassigning the same `(page,slot)` IDs so references remain stable.
- **Can I intern glob patterns?** Use `cep_namepool_intern_pattern*`; it records the string plus a `glob` hint so matchers treat it as a pattern rather than literal text.
- **What happens if I run out of reference slots?** The namepool grows dynamically; depletion indicates either runaway interning or missing releases—investigate before expanding limits.
- **How do I rename an existing tag?** Introduce the new tag alongside the old one, migrate callers, then retire the previous tag in the lexicon and associated code paths; direct renames risk breaking replay.
