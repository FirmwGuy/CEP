# L0 Kernel: Performance & Tuning Notes

This document distills practical guidance for getting the best latency, throughput, and memory behavior from CEP’s Layer‑0 primitives: **cells**, **stores**, **data payloads**, **links/shadows**, **heartbeats/enzymes**, and **serialization**. It complements your “Kernel Overview” and “Algorithms Report” by focusing on concrete knobs, trade‑offs, and anti‑patterns grounded in the codebase.

---

## 1) Naming, IDs & the Namepool

**What to know**

* CEP uses 58‑bit **Domain/Tag (DT)** identifiers per segment; helper macros encode **words** and **acronyms** compactly (e.g., `CEP_WORD`, `CEP_ACRO`) and support wildcards for matching (e.g., `CEP_ID_GLOB_MULTI`). Fast comparison favors numeric DTs over string compares .
* For **textual names** you expect to repeat, use the **namepool** to intern them once and reuse the numeric reference: `cep_namepool_intern*`, `cep_namepool_lookup`, `cep_namepool_release`. This cuts per‑node RAM and speeds comparisons when using `CEP_NAMING_REFERENCE` .

**Tuning tips**

* Prefer `CEP_WORD` / `CEP_ACRO` where the character set fits; they encode into 5‑/6‑bit alphabets and compare in constant time without heap lookups .
* For high‑duplication labels (schemas, field names), intern them once via the namepool and store as **reference‑named IDs**; it reduces cache pressure on large trees .

---

## 2) Data Payloads: choosing VALUE, DATA, HANDLE, STREAM

**What to know**

* `cepData` supports four **datatypes**:

  * `VALUE`: small, inline bytes in the `cepData` struct; great for fixed‑size POD (no extra allocation) .
  * `DATA`: heap buffer with optional destructor; use for medium/large blobs (you control ownership) .
  * `HANDLE` / `STREAM`: opaque resource or window managed by a **library binding**; CEP retains/releases via adapter ops and can snapshot/restore proxies during serialization  .

* **Updates:**

  * `cep_cell_update` **records history** (pushes a snapshot node before write) — ideal when you need temporal queries .
  * `cep_cell_update_hard` updates in place **without** snapshot — faster when history is not required .
  * For `DATA`, pass `swap=true` to **transfer ownership** of your buffer into CEP (no memcpy), or `swap=false` to copy into existing capacity .

**Tuning tips**

* Small (≤ ~16–64B) payloads: prefer `VALUE`. It avoids an allocation and improves cache locality .
* Large blobs with frequent rewrites and **no** time travel: use `cep_cell_update_hard` (no history) with `DATA` + `swap=true` to zero‑copy swap buffers .
* Resource‑backed nodes (`HANDLE`/`STREAM`) **cannot be deep‑cloned**; deep clones become **links** to the source (fast, but adds link management overhead). If you truly need duplication, clone the upstream resource at the library layer instead .

---

## 3) Children Storage & Indexing: choose by workload

CEP decouples **storage structure** from **indexing policy**. Pick both to match your access pattern.

| Storage                                        | Best for                            | Complexity (lookup / insert) | Notes                                                                                                               |
| ---------------------------------------------- | ----------------------------------- | ---------------------------: | ------------------------------------------------------------------------------------------------------------------- |
| **Linked list** (`CEP_STORAGE_LINKED_LIST`)    | frequent head/tail ops; small lists |           O(n) / O(1) append | Simple, stable order; supports insertion indexing and named lookups via scans  .                                    |
| **Array** (`CEP_STORAGE_ARRAY`)                | dense, mostly stable sizes          |    O(1) by index / amortized | Great cache locality; pre‑size capacity to avoid reallocs; supports insertion & named lookups (linear or sorted)  . |
| **Packed queue** (`CEP_STORAGE_PACKED_QUEUE`)  | many head/tail pops/pushes          |                    O(1) ends | Must use **insertion indexing**; some sorted operations are unsupported (asserts) — see notes below .               |
| **Red‑black tree** (`CEP_STORAGE_RED_BLACK_T`) | ordered catalogs                    |          O(log n) / O(log n) | Use with `INDEX_BY_NAME` or custom compare; internal traversal can expose physical layout for cache‑aware scans .   |
| **Hash table** (`CEP_STORAGE_HASH_TABLE`)      | large dictionaries                  |                near O(1) avg | Requires `INDEX_BY_HASH`; supports **internal traversal** across buckets (ordered buckets) .                        |
| **Octree** (`CEP_STORAGE_OCTREE`)              | 3D spatial indexing                 |              O(log n) region | Needs compare function to place within bounds; only `INDEX_BY_FUNCTION` applies .                                   |

**Indexing**

* `INDEX_BY_INSERTION`: simplest, fastest to mutate; **append‑only trail** is captured by timestamps; ideal for logs, queues, journals .
* `INDEX_BY_NAME`: dictionary semantics; reindex with `cep_cell_to_dictionary` (see below) .
* `INDEX_BY_FUNCTION`: custom order/comparator; **reindexing** snapshots current layout (see “Reindexing cost”) .
* `INDEX_BY_HASH`: hash first, then comparator tie‑break; requires a compare function .

**Reindexing cost**

* Converting/Sorting (`store_to_dictionary`, `store_sort`) **reorders siblings** and pushes a **store history snapshot** to preserve old ordering (memory + time). Avoid doing this in hot paths or per‑tick; batch reindexing if possible .

**Unsupported combos (assert at runtime)**

* Packed queue with sorted inserts/lookups (`INDEX_BY_FUNCTION`) is unsupported in several paths; keep it for insertion‑ordered workloads only .
* Hash table doesn’t support “sort by compare” post‑creation; choose the right pairing from the start .

**Capacity sizing**

* When creating arrays/queues/hash tables, **pass a capacity hint** to `cep_store_new` to avoid incremental reallocs or rehashes. If omitted, CEP guesses from current child count (may be sub‑optimal under bursts) .

---

## 4) Auto‑IDs

When a child’s tag is `CEP_AUTOID`, insertion assigns a monotonically increasing numeric ID; the store updates `autoid` and preserves it across clones. This is O(1) per insert and not typically a tuning hotspot; just avoid exceeding `CEP_AUTOID_MAX` (checked) .

---

## 5) Traversal: shallow, deep, internal & historical

**APIs**

* **Shallow**: `cep_cell_traverse` (logical order).
* **Deep (DFS)**: `cep_cell_deep_traverse` (logical) and `_internal` (physical layout for trees/hash).
* **Historical**: `*_past` variants (filter visibility by a snapshot heartbeat) for shallow and deep traversals; they wrap callbacks and **flush “pending” entries** only if alive at the timestamp (extra branching cost) .

**Stack depth**

* DFS builds on a 16‑frame fast stack and expands automatically; deeper trees transparently grow the stack with heap storage, so you no longer need to tweak a global depth limit. Keep the default unless profiling shows the fast stack threshold needs to move.

**Tuning tips**

* For RBT/Hash, prefer `*_internal` traversal when you care about **physical structure** (pre‑order nodes/bucket order) — fewer virtual jumps and better cache regularity on large sets .
* Historical scans (`*_past`) add timestamp checks for **cell**, **parent**, and **store**, plus data/store visibility tests; keep their use to analytics/inspection, not steady‑state per‑event paths .

---

## 6) Links & Shadows: cost and scale

**Mechanics**

* Links point to canonical targets; CEP maintains **backlink lists** (“shadows”) on targets: a single in‑place pointer for 1 link, and a dynamically growing array (`cepShadow`) for multiple links (capacity doubles) .
* Attach/detach operations update backlink structures and propagate the target’s **dead/alive** flag to link headers. Breaking many links calls into the detach loop repeatedly (O(k) over link count) .

**Tuning tips**

* If thousands of links reference a hot target, expect overhead proportional to the shadow count on target death, mass detach, or structure moves. Consider:

  * **Grouping** those links under one intermediate node and link to that.
  * Using **handles/streams** where the sharing is at the library level rather than at CEP links (fewer CEP backlinks) .

---

## 7) Locks: avoid hierarchical blocking

* CEP supports **hierarchical locks** for both **store** and **data**. A lock on any ancestor prevents structural/data edits below; checks walk up to the root (`cep_cell_*_locked_hierarchy`) which adds a short parent chain scan per operation  .
* Use `cep_store_lock` / `cep_data_lock` sparingly, hold them for the **shortest possible critical section**, and avoid long chains of updates while locked (they’ll all pay the lock‑walk) .
* The Pause control plane (`cep_runtime_pause`) acquires both locks at `/data` before gating impulses. If you already hold a manual lock on the subtree the pause operation will fail, so schedule long-running mutations outside of pause windows.

---

## 8) Heartbeat & Enzymes: registry capacity, matching & ordering

**Registry sizing**

* The enzyme registry preallocates based on `CEP_ENZYME_CAPACITY_HINT` (env var), defaults to 16 entries, and caps at 65,536. Set the env var in deployments that register many enzymes to avoid repeated reallocs/copies while building indexes .

**Matching**

* Resolve uses per‑signal **bucket indexes** (by the head DT of the query path) and per‑name buckets; both are built via `qsort` with deterministic `registration_order` tiebreakers. Matching computes **specificity** against signal/target paths and merges duplicates preferring stronger matches, higher specificity, lexical name, then earlier registration .

**Dependencies & order**

* Final execution order is a **stable topological sort** (heap‑based Kahn) over `before[]`/`after[]` edges for the matched subset; edges are deduped per pair. To keep graph memory small and sorting faster: keep dependency lists short and use **names** (DTs) consistently across registrations  .

**Bindings**

* Effective bindings on a target are computed by walking up ancestors (masking via tombstones, optional propagation). Binding scans allocate small dynamic arrays; limit the number of distinct bindings you attach per node to keep resolve overhead low under heavy load .

**Heartbeat impulses**

* The impulse queue doubles capacity (starts at 8) and clones paths on append; if you know peak count per beat, **pre‑size** the queue to avoid growth during spikes (reserve pattern) .

---

## 8) Episodic executor queue & budgets

**What to know**

* `cep_executor_submit_ro` drives a cooperative ready queue processed during `cep_heartbeat_stage_commit()`. Queue capacity is static (`CEP_EXECUTOR_QUEUE_CAPACITY`, default 64). Tasks inherit a `cepEpExecutionContext` that tracks per-slice CPU/IO budgets and cancellation state.
* Read-only contexts (`profile = CEP_EP_PROFILE_RO`) are enforced via `cep_ep_require_rw()`. Violations emit `sev:usage` CEI facts (`ep:pro/ro`) and return early so no journal mutations occur inside the guard path.
* IO-heavy helpers (stream writes, serialization) now call `cep_ep_account_io(bytes)` to record consumption. When contexts exceed their IO budget they emit `ep:budget/io` CEI facts and mark themselves cancelled so cooperating enzymes can respect the limit.

**Tuning tips**

* Increase `CEP_EXECUTOR_QUEUE_CAPACITY` only when bursts regularly exceed 64 tasks; larger queues increase the scan window each beat.
* Supply a `cepEpExecutionPolicy` when submitting work to tighten CPU/IO budgets per task. Combine short CPU slices with periodic `cep_ep_check_cancel()` calls inside enzymes so long-running work yields fairly.
* Stream adapters or custom serialization should call `cep_ep_account_io()` immediately after writing bytes to keep IO budgets accurate.
* The Meson option `-Dexecutor_backend=threaded` is reserved for future threaded backends. On wasm/emscripten targets the build automatically falls back to the cooperative stub backend.

----

## 9) Serialization: chunk sizes, staging & hashes

**Emit side**

* `cep_flat_stream_emit_cell` writes a control header, a **manifest** (path + meta), then a **data descriptor**. Blobs larger than `blob_payload_bytes` are sent in **BLOB** chunks; set this to match your MTU / network frame or disk block to reduce fragmentation. Default falls back to `CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD` if zero .
* Proxies (handles/streams) snapshot through the library binding and are emitted as **LIBRARY** chunks; make sure your adapter implements snapshot/release correctly to avoid temporary heap copies for large payloads  .

**Read side**

* The reader **stages** per‑transaction work until it sees a CONTROL commit, then applies all stages atomically. Payload hashes are BLAKE3-based; hashing costs are proportional to payload size, so avoid enabling hashes on very large streams if not needed.

**Tuning tips**

* Use **inline** data (small `VALUE`/`DATA`) to avoid extra BLOB chunks.
* Set `blob_payload_bytes` to a value that **fills storage/network buffers** without exceeding them (e.g., 64–256 KB for disk, a multiple of your socket send buffer for network) .
* Keep **paths short** (fewer segments) for high‑rate ingestion; manifests scale with the number of path segments (two 64‑bit ints per segment) .

---

## 10) History & Append‑Only Semantics

* CEP records change trails primarily via **timestamps** (heartbeats). Historical traversals filter on `created/deleted/modified` across data and store; they cost extra checks per node (‘alive at snapshot?’). Only request historical views where necessary (audits, timelines); read “live” views for hot data paths .
* Some operations take **full snapshots** (e.g., when reindexing); that preserves sibling order across sorts but costs memory proportional to child count. Prefer designing with **stable indexing** from the start to avoid recurring reindex snapshots (see §3) .

---

## 11) Recipes & Rules‑of‑Thumb

* **Hot append log**: `ARRAY + INDEX_BY_INSERTION`, pre‑size capacity to expected burst. Use `VALUE` for fixed small entries; `DATA + swap=true` for bulk entries. Avoid reindexing; query by position if needed .
* **Big dictionary**: `HASH_TABLE + INDEX_BY_HASH` with an up‑front bucket hint (≥ expected child count / 0.75). Avoid converting to dictionary later (it’s already a dictionary); use `cep_cell_find_by_name` for lookups .
* **Ordered catalog**: `RED_BLACK_T + INDEX_BY_FUNCTION` with a stable comparator. Use `*_internal` traversal for batch operations; avoid frequent re‑sorts with new comparators (each reindex snapshots) .
* **Many readers, few writers**: don’t hold locks across traversal; check‑then‑update with short critical sections (`cep_store_lock`/`cep_data_lock`) to minimize hierarchical lock scans .
* **Enzyme heavy systems**: set `CEP_ENZYME_CAPACITY_HINT` to your expected registry size (e.g., 1–4k) to avoid growth churn; keep dependency lists short and consistent DT naming across modules for faster resolve/toposort  .
* **Serialization throughput**: match `blob_payload_bytes` to the transport; batch cells per stream when possible; leave hashes off for massive unverified streams to save CPU (or validate by library‑level checksums) .

---

## 12) Anti‑Patterns to Avoid

* **Reindexing in a tight loop** (calling `cep_cell_to_dictionary`/`cep_cell_sort` frequently) — creates store history snapshots and reorders siblings; batch or design for the final indexing upfront .
* **Using packed queue with sorted expectations** — the queue is a head/tail buffer only. Use append/prepend APIs and pop/take helpers; positional inserts or mid-list replacements will assert because `cep_store_add_child` does not route packed queues through a random-access path. Switch to an array if you need indexable inserts.
* **Deep trees with default stack** — DFS grows beyond the 16‑frame cache by allocating additional frames on demand; no manual knob is required for deep hierarchies.
* **Over‑linking hot targets** — thousands of backlinks amplify detach/retarget costs; use intermediate grouping or shared library resources instead of CEP links where feasible .
* **Recording history when not needed** — `cep_cell_update` creates a snapshot each write; prefer `_hard` variant when you can safely drop history for performance .

---

## 13) Quick Reference (APIs & Knobs)

* **Namepool**: `cep_namepool_intern*`, `lookup`, `release` (reduce RAM + compare cost) .
* **Stores**: `cep_store_new(dt, storage, indexing, ...)` — **pass capacity/bucket hints** for array/queue/hash; octree requires center/subwide/compare; some combos assert by design .
* **Updates**: `cep_cell_update` (history) vs `cep_cell_update_hard` (no history); `swap=true` for zero‑copy in `DATA` .
* **Traversal**: `*_traverse`, `*_traverse_internal`, `*_deep_traverse*`; prefer internal for RBT/hash when you care about physical structure. Stack capacity extends automatically when depth increases.
* **Locks**: `cep_store_lock` / `cep_data_lock` — short, scoped use; hierarchy checks cost O(depth) per op .
* **Links**: avoid massive backlink sets on hot targets; detaches are O(k) in number of links .
* **Enzymes**: set `CEP_ENZYME_CAPACITY_HINT`; keep `before[]/after[]` minimal; consistent DT naming; register outside live beats when possible; activation of pending is explicit and rebuilds indexes once  .
* **Serialization**: `cep_flat_stream_emit_cell` with tuned `blob_payload_bytes`; reader stages per‑tx and commits atomically; optional payload hashing trades CPU for verification .
* **Control Ops**: `cep_txn_clear_metadata` now frees transaction metadata buckets/stores; keep pause/rollback/resume diagnostics behind `CEP_ENABLE_DEBUG` so control logging compiles out in release builds.

---

## Global Q&A
- **How do I validate a tuning recommendation before adopting it?** Trace the cited APIs in `src/l0_kernel`, gather metrics with your workload, and confirm results against the performance notes here; update the doc if reality diverges.
- **What if a tuning knob conflicts with determinism guarantees?** Determinism wins. Revisit the corresponding topic (e.g., append-only or locking) and adjust the recommendation, capturing the trade-off in a Design doc if necessary.
- **Where should I log new anti-patterns?** Add them to the Anti-Patterns section once you have a failing scenario and a fix. Reference test cases or benchmarks so others can reproduce the issue.
- **Do these notes apply to planned traversal helpers?** Mostly—planned helpers will inherit the same storage behaviours. Cross-check `RAW-TRAVERSAL-HELPERS.md` for any new caveats as the APIs land.
- **How often should we refresh these guidelines?** Revisit after major performance work, releasing a new measurement appendix if the recommended defaults change.
