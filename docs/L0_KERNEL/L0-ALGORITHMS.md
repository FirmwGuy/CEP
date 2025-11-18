# L0 Kernel: Algorithms Report

Below is a focused, implementation‑grounded report of the **main, cross‑cutting algorithms** in CEP—what they are for, how they work, and where they live in the code. I center on the parts that operate across several layers (naming → cells/stores → history & traversal → dispatch → streaming), and include concrete pointers to the relevant entry points.

---

## Legend: the identifiers and paths the algorithms are built on

* **Domain–Tag (DT) naming & cepID encoding.** CEP names every cell with a compact, 58‑bit per‑field identifier (`cepDT`), with four encodings (word, acronym, reference, numeric). Helpers encode/decode and match wildcards; these are pervasive in the algorithms below (e.g., lookups, path matching, enzyme resolution) .
* **Name pool (interning).** When you need stable “reference” IDs from text, the namepool maintains interned strings backing `CEP_NAMING_REFERENCE` so DTs remain small and stable: `cep_namepool_intern`, `lookup`, `release` .
* **Paths.** A `cepPath` is a DT sequence from root to a cell; many algorithms accept/emit paths to keep work deterministic and decoupled from in‑memory pointers (e.g., traversal, enzymes, serialization) .
* **Runtime context activation.** A `cepRuntime` instance now owns all mutable Layer 0 state; algorithms operate on whichever context is active on the calling thread. Use `cep_runtime_set_active()` before invoking public APIs when juggling multiple runtimes and restore the prior handle with `cep_runtime_restore_active()` when you exit.

---

## 1) Append‑only timelines & structural history

**Why it exists.** CEP chooses an append‑only model so readers can reconstruct *any* past shape or payload without making full clones on every edit. That enables snapshot traversal, deterministic reindexing, and streaming diffs.

**What it does.**

* **Payload histories.** Every data update copies the current `cepDataNode` metadata into the `past` chain before writing the new value (`cep_data_history_push`, `cep_cell_update`). For `DATA` payloads, the algorithm conditionally deep‑copies or “swap‑takes” the buffer (depending on the `swap` flag), then recomputes a stable content hash. That builds a per‑cell timeline in O(1) per mutation with optional O(n) copy when deep‑copying the old bytes .
* **Store layout snapshots (only when order changes).** When a collection is reindexed (e.g., “turn into dictionary” or “sort by custom compare”), the store takes a *layout snapshot* (`cep_store_history_push`) that records the prior sibling order and per-entry pointers so later historical traversals can reconstruct that exact order without keeping a full copy of the child tree. This is taken *only* when reordering; normal append keeps order by timestamp .
* **Cache eviction windows and telemetry.** Every controller carries a `cepBranchPersistPolicy` that includes `history_ram_beats`, `history_ram_versions`, and `ram_quota_bytes`. `cep_branch_controller_apply_eviction()` walks each cached entry, calls `cep_data_history_apply_policy`/`cep_store_history_apply_policy` to trim payload/store timelines, and tracks how many beats/versions/bytes survive. The resulting horizon is mirrored to `/data/persist/<branch>/branch_stat` via `cache_bt`, `cache_ver`, and `cache_bytes`, while the policy inputs (`hist_ram_bt`, `hist_ram_v`, `ram_quota`, `snapshot_ro`) live under `/config`. Breaching any window or quota raises a `persist.evict` CEI fact so operators can correlate telemetry with cache drops. Lazy-load branches advertise `policy_mode="lazy_load"` in `/config` and only spawn controllers when the branch is first accessed; imported snapshots flip `policy_mode="ro_snapshot"`, set `snapshot_ro=1`, emit `persist.snapshot`, and rely entirely on lazy hydration plus eviction metadata to remain observable without new mutations.

**Where it lives.**
`cep_data_history_push`, `cep_cell_update`, `cep_store_history_*`, and the timestamp helpers are in the cell implementation; `cepCell`/`cepStore` headers define the shapes and invariants  .

---

## 2) Link “shadow” bookkeeping (bidirectional backlinks)

**Why it exists.** Links are first‑class cells. To keep link targets consistent (e.g., mark links as “target is dead”, rebind on clones, cleanly break on teardown), the runtime maintains backlink metadata (“shadows”). This prevents cycles and keeps link‑heavy graphs correct.

**What it does.**

* **Adaptive representation.** The target holds either a single backlink pointer or a small dynamically‑resized array structure (`cepShadow`) if multiple links point to it. The attach/detach algorithm transparently upgrades/downgrades between single → multiple (doubling capacity), and performs O(1) removals by swapping with the last entry .
* **Consistency operations.**

  * `cep_link_set` detaches from the old target (if any), normalizes chains (always ends on a non‑link cell), and attaches to the new target while switching the shadow container as needed.
  * `cep_cell_shadow_mark_target_dead` mirrors the target’s soft‑delete bit into all linkers so readers won’t follow stale references.
  * `cep_shadow_break_all` safely unhooks all incoming links before hard finalization; `cep_shadow_rebind_links` reattaches backlinks when a cell is moved/cloned .

**Where it lives.**
Shadow attach/detach/mark logic and `cep_link_set/pull` are implemented in the cell core file; types are in the headers  .

---

## 3) Insertion, deduplication, auto‑id, and reindexing

**Why it exists.** CEP supports multiple child storage engines (list/array/packed queue/red‑black tree/hash table/octree) and several indexing policies (by insertion, by name, by custom function, by hash). The algorithms centralize policy enforcement, deduplication, and auto‑id assignment.

**What it does.**

* **Add/append with structural dedup.** `cep_store_add_child`/`cep_store_append_child` consult indexing mode and delegate to the backend (list/array/etc.). Before insertion, they detect structurally identical records (`cep_cell_structural_equal`) and return the existing one, or replace when policy allows. This keeps idempotency across layers .
* **Auto‑ID assignment.** When the child tag is `CEP_AUTOID`, the parent assigns a monotonically increasing numeric tag; if callers provide an explicit numeric tag, the parent’s cursor is advanced accordingly so IDs remain unique and monotone via `store_check_auto_id` .
* **Reindexing with layout snapshots.**

  * `store_to_dictionary`: rebuilds a collection into a dictionary keyed by `cepDT` (name), taking a single “before” snapshot and sorting children with a composite name+recency comparator.
  * `store_sort`: reorders by a custom comparator (or changes from hash→compare) while snapshotting the prior order. Both update the store timestamp as the append‑only record of the mutation .

**Where it lives.**
Child storage creation/ops (`cep_store_new`, add/append/find/sort) and structural equality are in the cell core file; the API surface is in the header  .

---

## 4) Snapshot‑aware traversal (shallow & deep)

**Why it exists.** Read‑side algorithms need to “see the world as of heartbeat T”. CEP provides snapshot filters over both *topology* and *payloads* without changing the live graph.

**What it does.**

* **Shallow traversal at time T.** `cep_cell_traverse_past` wraps the normal `store_traverse` and emits only entries alive at T. Internally it builds a small state machine (`cepTraversePastCtx`): buffer 1 pending entry, flush it when the next visible entry arrives (so callers get `prev/next/position` filled consistently) .
* **Deep traversal at time T.** `cep_cell_deep_traverse_past` generalizes the above to depth‑first traversal. It maintains a per‑depth frame array (`cepTraversePastFrame`), flushing pending nodes before descending and after list ends. This mirrors the live traversal API so tools written for live graphs can also replay the past with the same callbacks .
* **Finders at time T.** Point lookups (`*_find_by_name_past`, `*_find_by_position_past`) and iterators (`*_find_next_by_name_past`, `*_find_next_by_path_past`) apply the same alive‑at‑T checks while reusing the store backends. The path enumerator retains per‑depth iterator state on stack or heap, scaling with path length in O(depth) space and O(matches) time .

**Where it lives.**
Traversal wrappers, snapshot filters, and the past‑aware search helpers are in the cell core file; the traversal surface is in the header  .

---

## 5) Cloning (with handle/stream semantics)

**Why it exists.** Tools often need a structural copy without disturbing shared external resources. CEP clones VALUE/DATA payloads, but handles/streams are *not* duplicated—they become links to the original.

**What it does.**
`cep_cell_clone_into` performs two strategies:

* **Value/Data:** deep‑copy the payload and optionally the child store (for deep clones).
* **Handle/Stream:** create a **link** to the source cell (not a second handle), keeping the foreign resource unified. The clone clears shadow bits and rewires children/stores/locks safely. `cep_cell_clone` (shallow) and `cep_cell_clone_deep` (deep) compose this routine; helpers exist to clone store structure and children (`cep_store_clone_structure`, `cep_cell_clone_children`) .

**Where it lives.**
Cloning routines and the special cases for handles/streams are in the core implementation; types are in the header  .

---

## 6) Serialization & streaming (flat wire format)

**Why it exists.** CEP streams cells across processes/storage in a way that (a) is self‑describing and resynchronizable, (b) preserves path identity, (c) handles large payloads incrementally, and (d) restores proxies via library callbacks.

**What it does.**

* **Writer (emitter).** `cep_flat_stream_emit_cell` writes:

  1. a **control header** record with magic/version/options (`cep_flat_stream_header_write`),
  2. a **manifest** record with the DT path + flags describing the cell’s type and whether it has data/proxy,
  3. a **data descriptor** (VALUE/DATA) either inline or as separate **blob** records if the payload exceeds a blob limit, and
  4. a **frame trailer** record marking end of transaction. The emitter keeps record ordering deterministic so readers can sanity‑check streams and resume at boundaries.
* **Reader (ingest/commit state machine).**

  * `cep_flat_stream_reader_ingest` validates each record, reorders nothing, and **stages** manifests, data headers, blobs, and library snapshots in a per-frame structure. For blob data it allocates a buffer of the final size and copies each slice at the declared offset; hashes are verified against `(dt,size,payload)`.
  * When the **trailer** arrives, `commit` applies all staged changes: it materializes nodes at the path (creating intermediate dictionaries when necessary), writes payloads, and calls proxy restore hooks for library‑backed cells. Only successful commits mutate the tree; otherwise the reader is failed/reset. The apply code respects existing types and replaces payloads with correct destructors.
* **Async sink.** `cep_flat_stream_emit_branch_async()` wraps the emitter so every branch frame is staged in memory, registered as `begin`/`write`/`finish` requests under `/rt/ops/<oid>/io_req`, and handed to `cep_io_reactor` for execution. Callers provide a `cepFlatStreamAsyncStats` with optional completion callbacks; CPS passes a watcher context so persistence waits for the CQ completion before updating `ist:store`. There is no synchronous fallback—the reactor (portable shim today, epoll/kqueue/IOCP later) is the only way branch frames reach CPS or federation.

**Where it lives.**
All emitter/reader algorithms, record format, and integrity checks (hashes, path, sequencing) are in the serialization module; cell/path helpers are used extensively from the cell layer.

---

## 7) Enzyme dispatch: matching, binding, partial order, and agenda build

**Why it exists.** CEP’s “enzymes” are deterministic units of work. An **impulse** (signal path + target path) must resolve to a **stable, dependency‑honoring** execution order that respects (a) which enzymes are bound at/above the target, (b) which ones match the signal (exact/prefix), and (c) explicit before/after constraints.

**What it does.**

1. **Registry & activation.** Enzymes register with a name, match policy, flags, and before/after lists. Registrations made during a live beat are held in a *pending* table and later activated en bloc so the agenda is **frozen** during resolution (`cep_enzyme_registry_activate_pending`)  .
2. **Indexing.** The registry builds two indexes: by enzyme **name** and by the **head DT** of the query path. Buckets are sorted and binary‑searched to cut down candidate sets during matching (`cep_enzyme_registry_rebuild_indexes`) .
3. **Collect effective bindings along the target path.** The resolver walks from target up to root, merging **propagated** bindings and honoring **tombstones** (unbinds) to compute the active enzyme name set at the focal node (the algorithm deduplicates per‑name and tracks masked entries) (`cep_enzyme_collect_bindings`)  .
4. **Intersect with signal matches & score specificity.**

   * For each bound name, look up registry bucket, filter entries by the **signal path** with EXAC T or PREFIX policy, and compute a **specificity** score as the number of concrete DT components in both target and signal patterns.
   * If there’s *no* target path (pure signal dispatch), pull candidates by the signal head bucket instead.
   * Merge candidates by **preference**: first by whether they match both target and signal, then by total specificity, then by name, then by registration order (`cep_enzyme_match_prefer`, `cep_enzyme_matches_signal`) .
5. **Dependency‑aware agenda.** Build a graph from the surviving matches using `before` and `after` lists. The algorithm computes indegrees and performs a **stable topological sort**; the ready set is a **priority heap** ordered by the same match preference to ensure a *deterministic* tie‑break among otherwise independent tasks. The resulting order is returned in a caller‑provided array (`cep_enzyme_resolve`) .

**Where it lives.**
All dispatch logic—the registry, matching, binding walk, and topo sort—live in `cep_enzyme.c`; the descriptor/impulse API and binding struct are in the headers and cell layer respectively   .

---

## 8) Heartbeat impulse queue (capture & reuse)

**Why it exists.** To decouple emission from resolution, impulses are recorded into a compact queue that clones paths just once and can be reset/swapped efficiently between beats.

**What it does.**
A capacity‑doubling array of `cepHeartbeatImpulseRecord` stores pointers to cloned paths for signal and target. Append reserves capacity, clones paths, and bumps count; reset/destroy zero the slots and free paths. The queue supports constant‑time swaps to hand off between producers/consumers (`cep_heartbeat_impulse_queue_append/reset/swap/destroy`) .

---

## 9) Locking and hierarchical guards

**Why it exists.** To preserve invariants during concurrent or multi‑phase edits, CEP offers fine‑grained locks on **data** and **store** hierarchies. Mutators check these before changing structure or payload.

**What it does.**
`cep_store_lock`/`cep_data_lock` plant a lock token on the target cell’s store/data; higher‑level checks walk up parent pointers to detect **any** lock in the ancestor chain (`cep_cell_store_locked_hierarchy`, `cep_cell_data_locked_hierarchy`). All mutating paths—including updates, adds, deletes, and reindexing—early‑exit when the hierarchy is locked, preventing partial states and races across layers  .

---

## 10) Path construction and “as‑of‑path” resolution

**Why it exists.** Serialization, enzymes, and navigation need a consistent, canonical identity that does not rely on memory addresses.

**What it does.**
`cep_cell_path` walks parents to the root into a resizable buffer (amortized O(depth)), then normalizes it into the caller‑provided `cepPath`. It can optionally append the *data dt* and *store dt* of the leaf, so consumers know exactly what payload and child type were visible. Path‑based finders (`cep_cell_find_by_path_past`) replay each segment—respecting per‑segment snapshot timestamps—to locate the target at time T .

---

## 11) Ordering policy for “recent first, alive first”

**Why it exists.** When stable tie‑breakers are needed (e.g., equal names), CEP prefers **alive** entries over dead ones and more **recent** timestamps over older ones.

**What it does.**
`cep_cell_order_compare` ranks by (1) alive vs dead, (2) latest timestamp aggregated from the cell/data/store, (3) address as a final tie‑breaker. This comparator is used in several reindexing and traversal internal paths to make results deterministic without hidden state .

---

## 12) Episodic Enzyme Engine (E³) promotion/demotion

**Why it exists.** Hybrid episodes allow workloads to jump between threaded RO slices and cooperative RW slices without losing determinism. The promotion/demotion helpers coordinate queue state, leases, and TLS context so each switch occurs at a heartbeat boundary and the same slice cannot accidentally run in both modes.

**What it does.**

* **Promotion (`cep_ep_promote_to_rw`).** Runs inside the active RO slice. Queues optional `cepEpLeaseRequest` entries (paths plus optional `cepCell*` shortcuts), flips `episode->mode_next = RW`, and calls `cep_ep_yield()` so the heartbeat drains the current ticket. When the cooperative slice begins, `cep_ep_apply_pending_leases()` locks the requested subtrees, `mode_current` updates to RW, and mutation guards (`cep_ep_require_rw`) allow writes.
* **Demotion (`cep_ep_demote_to_ro`).** Requires all leases released and any staged transactions committed/aborted. Records `mode_next = RO`, yields, and the heartbeat rebuilds a threaded ticket (`cep_executor_submit_ro`). Guards revert to RO, so attempts to mutate again must re-promote.
* **Accounting.** `cep_ep_bind_tls_context()` copies `mode_current` into the TLS execution context each slice, keeping CPU/IO budgets and cancellation flags continuous. If callers try to mutate before promoting, the guard emits a `ep:pro/ro` CEI advisory and returns `false`.

**Where it lives.**
`src/l0_kernel/cep_ep.c` (`mode_current`/`mode_next`, `cep_ep_promote_to_rw`, `cep_ep_demote_to_ro`, `cep_ep_apply_pending_leases`, `cep_ep_schedule_run`) implements the switch, with `cep_executor_submit_ro` / `cep_ep_execute_cooperative` handling scheduling. Tests reside in `src/test/l0_kernel/test_episode.c` (`test_episode_hybrid_promote_demote`).


## 13) Pause / Rollback / Resume (PRR) control loop

**Why it exists.** Operations such as maintenance or emergency rollback need a deterministic way to freeze the heartbeat agenda, record a rollback horizon, and drain queued impulses when work resumes. The PRR helpers coordinate envelope state, backlog mailboxes, and locks so every transition is beat-aligned and replayable.

**What it does.**

* **Pause (`cep_runtime_pause`).** Acquires `/data` store/data locks, enqueues an `op/pause` dossier, and flips the agenda gate so new impulses are parked in `/data/mailbox/impulses`. Watchers record `ist:quiesce` and later `ist:paused`.
* **Rollback (`cep_runtime_rollback`).** Records the target beat in the control dossier, updates `/sys/state/view_hzn`, and trims the backlog mailbox so only impulses at or before the horizon are replayed.
* **Resume (`cep_runtime_resume`).** Lifts the agenda gate, drains the backlog mailbox in deterministic ID order, and records `ist:run` → `ist:ok`.

**Where it lives.**
`src/l0_kernel/cep_heartbeat.c` (`cep_runtime_pause`, `cep_runtime_resume`, `cep_runtime_rollback`, backlog drain helpers) plus the design doc `docs/L0_KERNEL/design/L0-DESIGN-PAUSE-AND-ROLLBACK.md`. Tests: `src/test/l0_kernel/test_prr.c` and the integration POC pause/rollback scenario.


## 14) Federation transport negotiation & coalescing

**Why it exists.** Mounts need deterministic selection of transport media without duplicating negotiation logic across packs. The manager centralises capability scoring, schema updates, and `upd_latest` cache behaviour so every federation enzyme sees the same semantics.

**What it does.**

* **Provider scan & scoring.** Enumerate registered providers, filter those missing required caps, and popcount preferred caps to rank them. Allowing `upd_latest` automatically filters out providers that lack `CEP_FED_TRANSPORT_CAP_UNRELIABLE`. Preferred provider IDs override the ranking if they pass the filter.
* **Schema synchronisation.** Each successful negotiation rewrites `/net/mounts/<peer>/<mode>/<mount>/`, storing required/preferred caps, the `caps/upd_latest` opt-in, chosen `transport/provider`, and the provider bitset (`transport/prov_caps`). Provider metadata cached under `/net/transports/<id>/` is reused when calling the provider’s `open` function.
* **`upd_latest` cache.** When transports report backpressure, the manager caches exactly one droppable payload. READY events re-send the cached gauge immediately; older gauges are dropped. Reliable transports still forward the frame but emit a CEI warning so misuse is visible.
* **Diagnostics.** Negotiation gaps, schema write failures, provider send errors, and illegal `upd_latest` usage yield CEI facts (`transport/*` topics) with the mount branch as the subject, making issues observable through the diagnostics mailbox.

**Where it lives.** `src/enzymes/fed_transport_manager.c` implements negotiation, schema, and CEI hooks. Provider stubs plus mock helpers are in `src/enzymes/fed_transport_providers.c`. Tests covering negotiation, coalescing, and inbound delivery sit in `src/test/federation/test_fed_transport.c`.

## 15) CPS CAS cache lookup & metrics publishing

**Why it exists.** CPS needs fast replay in addition to durable persistence. The flatfile engine therefore consults a branch-local CAS cache first, then falls back to the runtime `/cas` tree when blobs are missing. Operators and tests rely on `/data/persist/<branch>/metrics/{cas_hits,cas_miss,cas_lat_ns}` to observe cache behaviour, so metrics must refresh immediately after each lookup.

**What it does.**

* `cps_flatfile_fetch_cas_blob_bytes` consults `branch/cas/manifest.bin` plus hashed blob files. Cache hits increment `stat_cas_hits`.
* Cache misses call `cps_flatfile_fetch_cas_blob_runtime`, which scans the runtime CAS tree (`cep_heartbeat_cas_root`) for a payload whose BLAKE3 fingerprint matches the `cell_desc.payload_ref`. Successful fallbacks write the blob back into the branch cache and increment `stat_cas_misses`.
* Each lookup measures elapsed nanoseconds (`stat_cas_lookup_ns`) and immediately invokes `cps_flatfile_publish_metrics`, ensuring `/data/persist/<branch>/metrics` stays up to date even if no new beat commits.

**Where it lives.** `src/cps/cps_flatfile.c` (`cps_flatfile_fetch_cas_blob_bytes`, `cps_flatfile_fetch_cas_blob_runtime`, `cps_flatfile_publish_metrics`). Tests: `/CEP/cps/replay/cas_cache` (cache hits) and `/CEP/cps/replay/cas_runtime` (runtime fallback).

## 16) CPS async commit gating

**Why it exists.** Persistence can only advance `ist:store` after the async serializer sinks and fsync stages have finished. Waiting on the reactor keeps Capture/Compute non-blocking without exposing partially written frames.

**What it does.**

* `cps_storage_commit_current_beat()` registers the async commit request before emitting the frame, attaches a `cpsStorageAsyncCommitCtx` to the serializer stats, and calls `cps_storage_async_wait_for_commit()` once the CPS engine applies the frame.
* `cps_storage_async_wait_for_commit()` pumps `cep_async_runtime_on_phase()` (Compute phase) until the reactor posts a completion, or until the monotonic timeout hits. Success sets `ist:store`; timeouts emit `persist.async.tmo`, abort the beat, and surface CEI that points back to the offending request name (`/rt/ops/<oid>/io_req/<req>`).
* Synchronous fallbacks are rejected; instead the helper emits a `persist.async` info CEI and marks the async request failed so tooling can capture the shim backlog.

**Where it lives.** `src/cps/cps_storage_service.c` (`cps_storage_commit_current_beat`, `cps_storage_async_wait_for_commit`, `cps_storage_async_mark_failed`). Tests: `/CEP/cps/replay/*` plus any integration suite that exercises persistence (`/CEP/prr/*`, integration POC).

## 17) Async telemetry mirrors (net + /rt/analytics)

**Why it exists.** The async I/O fabric needs deterministic observability so operators can correlate OPS request state, federation transport load, and shim usage without scraping individual dossiers.

**What it does.**

* Every federation mount writes `async_pnd`, `async_shm`, and `async_nat` under `/net/telemetry/<peer>/<mount>/`, mirroring the OPS async requests in a beat-friendly dictionary.
* The same counters land under `/rt/analytics/async/(shim|native)/<provider>/<mount>/jobs_total`, giving tooling a single branch to inspect when tracking shim vs. provider-native completions.
* When a provider lacks async hooks, the manager emits `tp_async_unsp` once per mount and marks the associated async handle as a shim so telemetry stays honest about the fallback.

**Where it lives.** `src/enzymes/fed_transport_manager.c` refreshes both the telemetry and analytics trees whenever mount state changes.

* **History & snapshots:** `cep_cell_update`, `cep_data_history_push`, `cep_store_history_push/clear` 
* **Links & shadows:** `cep_link_set/pull`, `cep_cell_shadow_mark_target_dead`, `cep_shadow_*` helpers 
* **Insertion & reindex:** `cep_store_add_child`, `cep_store_append_child`, `store_to_dictionary`, `store_sort` 
* **Traversal API (live/past):** `cep_cell_traverse`, `cep_cell_deep_traverse`, `cep_cell_traverse_past`, `cep_cell_deep_traverse_past` 
* **Cloning:** `cep_cell_clone`, `cep_cell_clone_deep` (plus `cep_store_clone_structure`) 
* **Serialization:** `cep_flat_stream_emit_cell`, `cep_flat_stream_reader_ingest`, `cep_flat_stream_reader_commit` 
* **Enzyme dispatch:** `cep_enzyme_resolve` and registry lifecycle (register/activate/unregister)  
* **Heartbeat impulses:** `cep_heartbeat_impulse_queue_append/reset/swap/destroy` 
* **Locking:** `cep_store_lock/unlock`, `cep_data_lock/unlock`, `cep_cell_*_locked_hierarchy`  
* **Namepool:** `cep_namepool_intern/lookup/release` for CEP_NAMING_REFERENCE 

---

## Complexity & practical notes (per algorithm)

* **History:** O(1) per update for metadata; copying cost proportional to payload when deep‑copying. Store reindexing sorts in O(n log n) for list/array, O(n) bucket rebuilds for hash/trees as implemented by backends invoked from `store_sort`/`store_to_dictionary` .
* **Shadows:** O(1) attach; O(1) detach via swap‑with‑last; capacity grows geometrically. Move/clone preserves backlinks in O(k) where k is link count to the node .
* **Traversal past:** O(visible nodes) with constant extra per node; deep traversal uses O(depth) state; no recursion (explicit stack/frames) for robustness .
* **Serialization:** Writer is linear in path length + payload size; reader is linear in the sum of record sizes with strict sequencing and hash checks. Large blobs are streamed in slices of configurable size (default if zero).
* **Enzyme resolution:**

  * Matching: O(log n) to find buckets + O(candidates) to filter.
  * Agenda: O(m + e) for the topo sort where m is matched enzymes and e the realized dependency edges; heap operations add O(log m) per ready push/pop; overall deterministic and stable .

---

## Interactions to keep in mind

* **Append‑only + traversal** give you “time travel” for both data and shape without copying trees; **reindex snapshots** make order reconstructions deterministic across beats (history of siblings is preserved only when order changes) .
* **Serialization** uses **paths**, not addresses—paired with append‑only rules and per‑segment timestamps, you can faithfully reconstruct historical or live state on another process, including **proxy** payloads via library snapshots/restores .
* **Enzyme bindings** are stored on data/store timelines (append‑only), and the dispatcher intentionally consults the **effective** set along the path (with propagation and tombstones) before matching against signal indexes, then performs a topology‑respecting, preference‑sorted topological order build  .

---

## Global Q&A
- **Where do I confirm the code path for a specific algorithm?** Each section above ends with pointers into `src/l0_kernel`; check the cited functions before making changes so you do not miss coupled helpers.
- **How do I know if an algorithm still matches the implementation?** Rebuild the code map (`meson compile -C build code_map`) and search the referenced symbols; if behaviour diverged, update both this report and the owning topic doc.
- **What is the safe way to add a new cross-cutting algorithm?** Propose it via a Design doc, add the implementation with focused tests, and extend this report so reviewers understand how the new behaviour interacts with existing invariants.
- **When should I snapshot store layout manually?** Almost never—let the store helpers capture snapshots when indexing changes. Manual snapshots risk diverging from the append-only model.
- **How do I debug scheduling issues?** Cross-reference the Heartbeat and Enzymes topic; agenda construction relies on the dependency graph described there and the algorithm notes listed here.
