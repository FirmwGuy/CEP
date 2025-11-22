# L0 Kernel: Roadmap

The L0 Kernel keeps CEP's tree of cells organised so applications can treat it like a digital filing cabinet. Picture a network-spanning set of folders where each update is timestamped; L0 is the librarian that knows which sheet moved, when it moved, and how every drawer lines up.

## Technical Roadmap Overview

The tables and bullet lists below snapshot where the kernel stands today, what is actively being built, and which items remain queued so contributors can align their efforts with the current milestone plan. Layer 0 is now functionally complete for Cells/Stores/CAS/CPS, async I/O, security policy enforcement, pipelines, and the episodic engine; remaining work is largely polish and ergonomics so Layers 1+ can plug in with fewer bespoke shims.

### Capability Snapshot
| Area | Status | In Place | Next Focus |
| --- | --- | --- | --- |
| Bootstrap & identity | ✅ Done | `cep_cell_system_initiate` seeds the root dictionary; `cep_cell_initialize` stamps deterministic domains/tags | 📎 Document safe-name helpers before exposing identifiers to tooling |
| Auto-ID & metadata hygiene | ✅ Done | `cep_store_add_child` assigns auto IDs, masks system bits, and advances cursors when callers preset IDs | ⚙️ Extend lexicon tooling + docs coverage before externalizing name APIs |
| Data payload lifecycle | ✅ Done | `cep_data_new`, `cep_cell_update`, `cep_data_history_*`, and `cep_cell_stream_*` cover VALUE/DATA/HANDLE/STREAM history with journaling | 📎 Optional: richer HANDLE/STREAM diagnostics for pack authors |
| Child store engines | ✅ Done | Linked list, array, packed queue, RB-tree, hash, and octree back-ends wired through `cep_store_new`; comparator/hash indexes dedupe through `store_find_child_by_key` | 📎 Optional: shared hash lookups + offline re-sort helpers for huge catalogs |
| Historical queries | ✅ Done | `cep_cell_find_by_*_past`, `cep_cell_traverse_past`, adaptive traversal stacks, and replay timelines land without mutating live data | 📎 Optional: HANDLE/STREAM snapshot convenience helpers |
| Link handling & shadowing | ⚙️ Partial | Link macros resolve references; soft take/pop expose archived children as links; link shadows track `targetDead` status for tombstones | ⚙️ Finish shadow lifecycle hooks (refcounts/GC) and snapshot provenance |
| Lifecycle & GC | ⚙️ Partial | `cep_cell_finalize`, `_hard`, store delete helpers, and episode-aware teardown reclaim stores/payloads deterministically | ⚙️ Wire proxy lifecycle + shadow-aware cloning for HANDLE/STREAM cells |
| Tooling & safety nets | ⚙️ Partial | Assertions wrap public APIs; Meson + MUnit + ASAN/Valgrind runs guard regressions; adaptive traversal stack metrics ship | ⚙️ Expand integration tests to cover pipeline metadata + policy hooks for L1 adopters |
| Heartbeat dispatcher | ⚙️ Partial | `cep_heartbeat_*` stages beats, memoizes impulse resolution, enforces dependency/name ordering, and emits telemetry; hybrid RO↔RW promotions ready | ⚙️ Add agency execution + agenda persistence/telemetry before full parallelism |

### Current Foundations
- ✅ Deterministic cell manipulation through `cep_cell_add`, `cep_cell_append`, and traversal helpers keeps storage engines aligned.
- ✅ Cell-bound enzyme resolver now exercises propagation, tombstone masking, and union semantics via the heartbeat test suite.
- ✅ Append-only timelines rely on `cep_data_history_*`, `cep_store_history_*`, and timestamped cells for consistent replay.
- ✅ Multiple child store back-ends provide insertion, lookup, and removal contracts while preserving sibling order.
- ✅ Soft removal helpers (`cep_cell_child_take` / `cep_cell_child_pop`) expose archived children without breaking history.
- ✅ Meson-based CI scripts run the MUnit suite under MSYS to validate core behaviours.

### Active Focus Areas
- ⚙️ Finalize link/shadow lifecycle (refcounts, GC, provenance) so L1 coherence packs can rely on archived trees without bespoke cleanup.
- ⚙️ Expand heartbeat telemetry + agency execution so L1/L2 can subscribe to pipeline/stage health without diving into raw logs.
- ⚙️ Extend proxy lifecycle helpers and HANDLE/STREAM diagnostics to unblock generational cloning + pack-owned adapters.
- ✅ Hybrid episode promotions/demotions (`CEP_EP_PROFILE_HYBRID`, `cep_ep_promote_to_rw()`, `cep_ep_demote_to_ro()`) let Layer 0 switch deterministically between threaded RO and cooperative RW execution while preserving budgets, leases, and replay history. Next: wire additional pack-level helpers onto the new API surface.

### Backlog Watchlist
- 📎 Link and shadow cleanup (refcounts/GC) plus proxy-aware cloning.
- 📎 Packed queue recycling for reduced allocator churn on hot branches.
- 📎 Optional range queries / shared hash lookups for very large dictionaries.
- 📎 Persistence + lock semantics audit for HANDLE/STREAM proxy payloads.

### Ready for Upper Layers
- Security policy loader/enforcer, pipeline preflight, and pipeline metadata propagation ship today; L1 packs can rely on `pipeline_id`/`stage_id` plumbing plus `/sys/security` readiness facts.
- CPS + CAS flush deterministically via `cep_flat_stream_emit_branch_async()` and branch controllers expose metrics/CEI hooks; higher layers can subscribe to `/data/persist/**` and `/rt/analytics/async/**` without extra instrumentation.
- The Episodic Enzyme Engine (E3) supports hybrid RO↔RW slices and watchers, giving L1+ a deterministic orchestration substrate.
- Next integration work mostly targets ergonomics (shadow cleanup, telemetry polish) rather than kernel gaps.

### Milestone Q&A
- **Why does Milestone 1 stop at VALUE/DATA payloads?** Milestone 1 locked down history and idempotence for VALUE/DATA; HANDLE/STREAM read/write landed afterward, with historical snapshots still tracking under later milestones.
- **Do link shadows matter before the runtime ships?** Yes. Without cleanup the archive helpers leak state, so shadow hygiene is part of structural resilience.
- **Can we expose child hashes before Milestone 2?** Only after comparator/hash dedupe is complete; otherwise repeated inserts risk drifting snapshots.
- **What happens to proxy-backed cells?** They graduate in the extended feature milestone once historicity, traversal, and runtime loops are stable.

---

### Stream Wrapper Q&A
- **Why start with stream wrappers?** They are the most common side-effecting calls that still bypass the heartbeat; wrapping them aligns IO with the impulse dispatch contract.
- **Will this replace the existing API?** No. Direct calls stay available for tight loops, but enzymes give orchestration layers a safer entry point.
- **Do we need new storage metadata?** Only lightweight descriptors (e.g., flush depth, rotation policy) so the resolver can track idempotency and retries.
- **How will retries be handled?** The wrappers will validate stream state before acting and no-op when their requested change already landed, mirroring the pattern used by cell enzymes.

- **Milestone 1 – Historic cells and idempotent stores**: ✅ Complete. Comparator/hash dedupe, VALUE/DATA history, auto-ID cursor fixes, and lexicon masking all landed.
- **Milestone 2 – Structural resilience**: ⚙️ Partial. Adaptive traversal stacks, hash engines, and soft-link archival ship; remaining work is link/shadow lifecycle + packed queue recycling.
- **Milestone 3 – Runtime baseline**: ⚙️ Partial. Heartbeat bootstrap/step/shutdown loops, multi-beat `op/boot`/`op/shdn`, hybrid RO↔RW episodes, CPS async commits, and telemetry surfaces are live. Outstanding items: agency execution wiring and agenda persistence polish before enabling multi-threaded dispatch.
- **Milestone 4 – Extended feature set**: 📎 Planned. Focus is on proxy lifecycle polish, deep cloning for HANDLE/STREAM payloads, and optional stream enzyme wrappers requested by pack authors.

---

## Global Q&A
- **How often should this roadmap be refreshed?** Revisit it whenever a milestone ships or slips. Update the status badges and notes so kernel contributors know which areas are active.
- **What if I need to work ahead of a planned milestone?** Coordinate with the milestone owner, record the change here, and update any linked TODOs so parallel work stays aligned.
- **How do I record a new Layer 0 initiative?** Add it under the appropriate milestone with status emoji, scope notes, and the owning module so the index file stays coherent.
- **Do roadmap entries replace TODO files?** No. Keep TODOs for execution details; the roadmap summarises intent and sequencing across the kernel.
- **Where do I flag dependencies on upper-layer packs?** Note them in the milestone body and cross-link to pack documentation so Layer 0 changes don’t outpace integration plans.
