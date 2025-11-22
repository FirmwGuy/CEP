# L0 Topic: Developer Handbook

## Introduction
Layer-0 kernel work succeeds when you treat determinism, documentation, and tests as part of the code. This handbook is the operations checklist for engineers who need to touch `cep_cell.*`, storage backends, CPS, or the heartbeat/E3 plumbing without breaking replay or portability. Use it whenever you are onboarding a teammate or returning after a gap: it points you to the docs you must reread, the files to change with care, and the build/test conventions that keep regressions out of `snaps`.

---

## Technical Details

### 1. Before touching kernel code
- Skim `docs/DOCS-ORIENTATION-GUIDE.md` (it now contains the full inventory) and reopen:
  - `docs/CEP-Implementation-Reference.md` for contract-level guarantees.
  - `docs/L0_KERNEL/L0-OVERVIEW.md` plus the relevant topic note (locking, native types, serialization, etc.).
  - `docs/L0_KERNEL/L0-TUNING-NOTES.md` when your work touches performance-sensitive paths.
- If policy/enclave code is involved, reread `docs/L0_KERNEL/design/L0-DESIGN-ENCLAVE.md` and `docs/L0_KERNEL/topics/ENCLAVE-OPERATIONS.md`.
- When editing long-running work or heartbeat scheduling, refresh `docs/L0_KERNEL/topics/HEARTBEAT-AND-ENZYMES.md` and `docs/L0_KERNEL/topics/E3-EPISODIC-ENGINE.md`.

### 2. Repository quick map
- `src/l0_kernel/cep_cell.*` – Cells, stores, payloads, shadowing, and core helpers.
- `src/l0_kernel/storage/*` – Linked list, array, packed queue, RB-tree, hash table, octree implementations.
- `src/l0_kernel/cep_async.c`, `cep_io_reactor.c`, `cps/*` – CPS controllers, CAS helpers, async reactor backends.
- `src/l0_kernel/cep_enclave_policy.c`, `secdata/*` – Policy loader and runtime enforcement.
- `src/enzymes/*` – Cell/OPS/federation/security enzymes.
- `src/test/*` – MUnit suites; treat them as living documentation.
- `tools/` – Fixture capture, lexicon checker, Doxygen helpers, code map generator, valgrind suppression.

### 3. Coding conventions (non-negotiable)
- **Determinism first:** no hidden randomness. All ordering goes through stores/indexing or heartbeat dependency ordering. Episodes record every decision in `/rt/ops/**`.
- **Name hygiene:** DT helpers (`CEP_WORD`, `CEP_ACRO`, `CEP_ID_GLOB_*`) for fixed labels; namepool references for user strings. Extend `docs/CEP-TAG-LEXICON.md` first, then use the new tag.
- **Payload/store rules:** Do not bypass `cep_cell_add*` / `cep_cell_update*`. Those helpers stamp history, auto-IDs, and visibility bits.
- **Lifetimes:** If Layer-0 allocates, Layer-0 frees. Set destructors on DATA payloads, release namepool refs, and zero proxies when the adapter is done.
- **Logging & diagnostics:** prefer CEI facts or temporary `meta/debug` breadcrumbs on the affected OPS dossier. User-facing logging belongs to higher layers.

### 4. Build & test loop
| Step | Command | Notes |
| --- | --- | --- |
| Configure (full build) | `meson setup build` | Pass `-Dexecutor_backend=threaded` only when the host supports threads; wasm/emscripten auto-downgrade. |
| Incremental build | `meson compile -C build` | Re-run after each logical change. |
| Default tests | `meson test -C build` | Add `--repeat=3` for flaky hunts; use `MESON_TEST_WRAPPER="valgrind ... --suppressions=tools/valgrind.supp"` for leak sweeps. |
| ASAN build | `meson setup build-asan -Dasan=true` | Keep ASAN and default builds separate; never mix valgrind with ASAN binaries. |
| Fallback Makefile | `make -C unix` | Produces `build-make/bin/cep_tests`; mirrors Meson sources and includes CPS/libsodium/zlib bundles. |
| Docs | `meson compile -C build docs_html` | Run `python tools/fix_doxygen_toc.py build/docs/html` afterwards; `tools/check_docs_structure.py` catches missing Q&A sections. |
| Fixtures | `CEP_UPDATE_PAYLOAD_REF_FIXTURES=1 meson test -C build /CEP/cps/replay/*` then `tools/capture-fixtures.sh` | Always commit the refreshed fixture logs/frames together. |

### 5. Instrumentation & diagnostics
- **CEI:** use `cep_cei_emit()` with deterministic topics (`persist.flush.*`, `ep:bud/*`, `sec.*`). Pick severities based on `docs/L0_KERNEL/topics/CEI.md`.
- **OPS dossiers:** long-running work uses `op/*` and `op/ep` trees. Track progress via `ist:*` states instead of custom logs.
- **Async reactor:** watch `/rt/analytics/async/(shim|native)` and `/rt/ops/<oid>/io_req/*` before assuming persistence “hung”.
- **Branch telemetry:** `/data/persist/<branch>/{config,branch_stat}` shows flush cadence, cache bytes, and laziness; rely on it when tuning `flush_every`, `hist_ram_*`, or `ram_quota`.
- **Security policy:** `/sys/state/security` exposes readiness/faults; `/rt/analytics/security` gives allow/deny counters. Keep watchers running when editing policy files.

### 6. Episodes, heartbeat, and policies
- **Heartbeat invariants:** Capture → Compute → Commit. New work only becomes visible at beat `N+1`. Never publish mid-beat results.
- **Enzyme registration:** Changes done mid-beat activate next beat. Always stage new descriptors via helper functions to ensure tombstones propagate.
- **E3 usage:** Choose RO vs RW profiles intentionally. RO slices may run on the threaded executor (if enabled) but still respect budgets. RW slices remain on the heartbeat and guard their leases.
- **Budgets & cancellation:** Set `cpu_budget_ns` / `io_budget_bytes`. Use `cep_ep_check_cancel()` near loops; watchers feed into `/rt/ops/<eid>/watchers`.
- **Policy pipeline:** `cep_enclave_policy` snapshots `/sys/security/**`; `sig_sec/pipeline_preflight` approves graphs; `cep_fed_invoke_validator()` enforces IDs + ceilings. Always rerun the preflight enzyme after editing policy trees.

### 7. Documentation & TODO hygiene
- Update `docs/DOCS-ORIENTATION-GUIDE.md` whenever you add or remove a doc, so the inventory stays accurate.
- Mention new coding conventions here in the Handbook and cross-reference the relevant topic/design note.
- For larger features, add a `TODO`/checklist file in the repo root (or extend existing ones) before coding, per AGENTS.md instructions.
- When editing terminology, change `docs/CEP-TAG-LEXICON.md`, related topic notes, and the Implementation Reference together.

### 8. Common pitfalls (2025 audit)
- Forgetting to seal scratch branches before exposing them; always call `cep_cell_finalize()` or `cep_branch_seal_immutable()` when appropriate.
- Mixing globbed and literal IDs in hot loops, causing resolve storms.
- Running RO episodes without budgets or cancellation checks—shutdowns will hang.
- Skipping CEI entries when refactoring persistence; the review team relies on `persist.*` and `ep:bud/*` topics to understand incidents.
- Editing `unix/Makefile` without matching changes in Meson. Keep both build paths aligned (zip/libsodium/zlib/cps sources, flags, etc.).

---

## Global Q&A
- **How do I guarantee replayability?** Make every decision explicit: log it via CEI or Decision Cells, avoid hidden randomness, and keep ordering tied to stores/indices. Re-run `meson test -C build --repeat=2` before landing.
- **Can I mutate payloads in place?** Only via `_hard` helpers when history is not required and after ensuring no readers rely on previous states. Otherwise append a new cell or record the change via higher-layer packs.
- **Where do I start debugging a perf issue?** Inspect `/data/persist/<branch>` metrics, compare against `docs/L0_KERNEL/L0-TUNING-NOTES.md`, and profile the relevant store before adding new helpers.
- **When should I update docs?** Every time you touch internals or APIs. At minimum: this handbook, the Overview, any topic note you touched, and the orientation inventory.
- **What if I find an undocumented convention?** Add it to the “Coding conventions” section here, extend the lexicon if naming changes, and record the update in `docs/DOCS-ORIENTATION-GUIDE.md` so the inventory highlights it during the next audit.
