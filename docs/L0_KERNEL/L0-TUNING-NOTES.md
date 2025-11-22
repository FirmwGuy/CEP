# L0 Kernel: Performance & Tuning Notes

Layer-0 already ships with deterministic behaviour; tuning is about helping it stay efficient once workloads grow. This guide focuses on the knobs you can control without rewriting kernel code: how you name things, pick payload/storage combinations, size persistence, configure episodes, and run the serializer stack.

---

## 1. Naming, IDs & the Namepool

**What matters**

- Domain/Tag IDs (DTs) are 58-bit integers. `CEP_WORD()` and `CEP_ACRO()` encode the fastest comparisons. Wildcards (`CEP_ID_GLOB_SINGLE`, `CEP_ID_GLOB_MULTI`) are resolved numerically, so they remain deterministic.
- Textual names that appear everywhere (schemas, column names, branch identifiers) should be interned once through the namepool (`cep_namepool_intern_*`). The numeric reference travels with the cell and avoids repeated heap allocations.

**Tuning tips**

- Prefer DT helpers whenever your label fits the word/acronym alphabet. They are cache-friendly, avoid string hashes, and keep dispatch predictable.
- For user-supplied names, intern them and store the reference ID (`CEP_NAMING_REFERENCE`). Release references when a module unloads so the pool does not grow indefinitely.
- Avoid mixing globbed and literal DTs in hot code paths. If you must match many patterns, sort them by specificity so the resolver short-circuits quickly.

---

## 2. Data payloads: VALUE, DATA, HANDLE, STREAM

**What matters**

- `VALUE` stores up to 64 bytes inline. `DATA` owns a heap buffer (optionally swapped in). `HANDLE` and `STREAM` wrap external resources via adapters.
- `cep_cell_update()` records history; `_hard` skips snapshotting and is cheaper when time travel is unnecessary.
- Swapping (`swap=true`) moves your buffer into CEP without copying; ensure you allocate with `cep_alloc()` or compatible ownership conventions so the destructor can reclaim it.

**Tuning tips**

- Use `VALUE` for counters, enums, fixed-size hashes. Small structs avoid malloc traffic and compact the CAS history.
- Use `DATA` + `_hard` + `swap=true` for large blobs that behave like caches or checkpoints. Keep the history off unless compliance demands it.
- HANDLE/STREAM payloads always become links when cloned. If you need a real copy, clone it at the adapter layer instead of trying to duplicate the cell.
- Rekeying (`cep_data_rekey_*`) is deterministic but not free. Stage rekey jobs in off-beat episodes so hot branches do not block.

---

## 3. Stores & indexing

| Store | When to use | Notes |
| --- | --- | --- |
| Linked list | Small fan-out, append-heavy | Preserves insertion order; best with `INDEX_BY_INSERTION`. |
| Array | Stable size, frequent indexed access | Pre-size capacity to avoid reallocations; `INDEX_BY_INSERTION` or sorted scans. |
| Packed queue | Strict FIFO/LIFO | Only use `INDEX_BY_INSERTION`. Do not request sorted operations; assertions fire. |
| Red-black tree | Ordered dictionaries | Pair with `INDEX_BY_NAME` or comparator functions; good for catalog-like data. |
| Hash table | Large, unordered dictionaries | Requires `INDEX_BY_HASH`; collisions remain deterministic. Consider iterating buckets if you need stable scans. |
| Octree | Spatial data | Backed by `INDEX_BY_FUNCTION`. Only use when geometry truly matters. |

**Indexing advice**

- `INDEX_BY_INSERTION` is the lightest option; use it unless you truly search by name/hash.
- `INDEX_BY_NAME` implies sorted traversals; ensure the comparator is stable and cheap.
- `INDEX_BY_HASH` favours huge dictionaries. Avoid when the table has only a handful of entries—it pays a constant overhead per bucket.
- In validate-only code (e.g., static analyzers), prefer read-only traversals (`cep_cell_traverse_past`, `cep_cell_traverse_all`) to avoid materialising detours.

---

## 4. Branch controllers, CPS, and CAS

**What matters**

- Each branch publishes configuration under `/data/persist/<branch>/config`: `policy_mode`, `flush_every`, `flush_shdn`, `allow_vol`, `hist_ram_*`, `ram_quota`, and `snapshot_ro`.
- `op/br_flush` and `op/br_sched` drive deterministic persistence: they append history to the branch controller, and CPS will only advance the beat once the async flush completes.
- CAS lookups and CPS commits emit per-branch counters. Watch `cas_hits/miss`, `cas_lat_ns`, and `persist.flush.*` CEI events to understand pressure.

**Tuning tips**

- Keep `flush_every` small for write-heavy branches so CAS/L0 do not accumulate giant diffs; treat the value as a heartbeats-between-commits knob.
- Enable `allow_vol` only when you have watchers recording `cell.cross_read` decisions. Every cross-branch read logs an entry, so budgets stay predictable.
- Set `hist_ram_bt` / `hist_ram_v` and `ram_quota` aggressively for branches that act like caches. Eviction (`persist.evict`) happens when either window is exceeded; instrumentation under `/data/persist` helps you size these windows correctly.
- Use `policy_mode=lazy_load` for massive read-only branches. They hydrate on first access, avoid needless RAM use, and still publish stats.
- Snapshot mode (`op/br_snapshot`, `policy_mode=ro_snapshot`) is ideal for imported read-only data. Remember: snapshots skip scheduled flushes—explicitly call `op/br_flush` if you want a final CAS write before sealing.

---

## 5. Heartbeats, enzymes, and E³ episodes

**What matters**

- Registrations done mid-beat activate on the next beat. Plan ahead or queue an impulse if you need immediate work.
- Keep enzyme descriptors tight: specify `before` / `after` dependencies and mark idempotent callbacks so the heartbeat can short-circuit repeated signals.
- E³ episodes come in RO and RW profiles. RO slices can run on the threaded executor when available; RW slices always run on the heartbeat and require leases (`cep_ep_request_lease`).
- Budgets (`cpu_budget_ns`, `io_budget_bytes`) feed CEI events (`ep:bud/cpu`, `ep:bud/io`) and cancellations when exceeded.

**Tuning tips**

- Treat RO episodes as cheap workers. Batch low-priority tasks there so the heartbeat remains responsive. Threaded slices still obey FIFO ordering and determinism—just give them short slices so cancel/lease checks run frequently.
- Keep cancellation checks (`cep_ep_check_cancel`) near loops and large I/O calls. Long RO slices that ignore cancellation make shutdowns painful.
- Use watchers (`cep_ep_await`) for cross-op dependencies instead of polling stores. They queue deterministic continuations and keep `/rt/ops/<eid>` history complete.
- When running tests, switch executors via `-Dexecutor_backend=threaded` only if your target platform has threads (MSYS/Arch). The fallback stub works everywhere but may hide concurrency bugs.

---

## 6. Serialization, async I/O, and Doxygen fixtures

**What matters**

- `cep_flat_stream_emit_branch_async()` handles every CPS flush. It buffers branch frames, registers begin/write/finish requests, and only advances the beat when the reactor confirms success.
- The async reactor has two backends: native (epoll) and portable (shim threads). Both expose counters under `/rt/analytics/async/(shim|native)` and CEI topics (`persist.async`, `persist.async.tmo`, `tp_async_unsp`).
- Fixtures live under `fixtures/cps`. Regenerate them via `CEP_UPDATE_PAYLOAD_REF_FIXTURES=1` when serialization changes, and run `tools/capture-fixtures.sh` for heartbeat logs.

**Tuning tips**

- Always set `CEP_IO_REACTOR_BACKEND_DEFAULT_PORTABLE=1` in environments without epoll/kqueue/IOCP (e.g., fallback Makefile). The shim is deterministic—just slower.
- Enable `CEP_SERIALIZATION_FLAT_PAYLOAD_HISTORY_BEATS` / `_MANIFEST_HISTORY_BEATS` only when you truly need replay windows. These knobs multiply frame size quickly.
- Use libsodium’s bundled backend (`libsodium_provider=bundled`) when shipping fixtures so everyone sees identical outputs. System libsodium may differ slightly depending on distribution patches.
- Run `tools/fix_doxygen_toc.py` after `meson compile -C build docs_html` so the doc tree is stable. CI expects the first page to show Developer Handbook, not random alphabetic order.

---

## 7. Instrumentation & anti-patterns

**Watch metrics and CEI**

- `/rt/analytics/security/*` exposes enclave allow/deny counters; `/sys/state/security` shows whether the policy loader is ready.
- `/data/persist/<branch>/branch_stat` reveals cache size, dirty counts, and the last flush beat. Use it instead of printf debugging.
- `/journal/decisions/*` logs cross-branch reads, so you can audit `allow_vol` usage.
- `persist.flush.*`, `persist.evict`, and `ep:bud/*` CEI topics are your early-warning system; treat spam as a sign you sized something poorly.

**Avoid these patterns**

- Leaving branches in `flush_every = 0` without explicit `op/br_flush` calls. You will eventually run out of memory and have no CAS checkpoints to recover from.
- Registering enzymes with broad prefixes and no dependency order. You push a lot of work onto the resolver and risk ambiguous agendas.
- Cloning HANDLE/STREAM nodes manually. They will turn into links and cause double-free bugs when the adapter destroys the original handle.
- Running RO episodes without budgets. Headless loops chew CPU and make cancellation impossible. Always set `cpu_budget_ns` and sprinkle cancellation checks.
- Writing fixtures by hand. Always use the helpers (`tools/capture-fixtures.sh`, `CEP_UPDATE_PAYLOAD_REF_FIXTURES`) so the recorded outputs match the current binary.

---

This document changes whenever profiling or incidents reveal new guidance. If you discover an undocumented best practice, add it here and cross-link it from `docs/L0_KERNEL/L0-OVERVIEW.md` or the relevant topic note so future contributors do not repeat the same experiments.
