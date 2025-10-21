# L0 Kernel: Roadmap

The L0 Kernel keeps CEP's tree of cells organised so applications can treat it like a digital filing cabinet. Picture a network-spanning set of folders where each update is timestamped; L0 is the librarian that knows which sheet moved, when it moved, and how every drawer lines up.

## Technical Roadmap Overview

### Capability Snapshot
| Area | Status | In Place | Next Focus |
| --- | --- | --- | --- |
| Bootstrap & identity | ✅ Done | `cep_cell_system_initiate` seeds the root dictionary; `cep_cell_initialize` stamps deterministic domains/tags | 📎 Document safe-name helpers before exposing identifiers to tooling |
| Auto-ID & metadata hygiene | ⚙️ Partial | `cep_store_add_child` assigns auto IDs when tags are primed with `CEP_AUTOID` and flags state changes | ⚙️ Advance the cursor when callers preset IDs; strip system bits in accessors |
| Data payload lifecycle | ⚙️ Partial | `cep_data_new`, `cep_cell_update`, and `cep_data_history_*` maintain VALUE/DATA payload history; `cep_cell_stream_*` covers HANDLE/STREAM reads, writes, and staged commits with journaling | ⚙️ Surface HANDLE/STREAM historical snapshots and adapter-side diagnostics |
| Child store engines | ⚙️ Partial | Linked list, array, packed queue, RB-tree, and octree back-ends wired through `cep_store_new`; comparator/hash indexes now dedupe through `store_find_child_by_key` | ⚙️ Add shared hash lookups and re-sort helpers for large catalog back-ends |
| Historical queries | ⚙️ Partial | `cep_cell_find_by_*_past`, `cep_cell_traverse_past`, and deep traversal replay timelines without mutating live data | ⚙️ Provide snapshot payloads for HANDLE/STREAM and surface depth telemetry for the adaptive traversal stack |
| Link handling & shadowing | ⚙️ Partial | Link macros resolve references; soft take/pop expose archived children as links; link shadows now track `targetDead` status for tombstones | 📎 Finish shadow lifecycle hooks (refcounts/GC) and snapshot provenance |
| Lifecycle & GC | ⚙️ Partial | `cep_cell_finalize` (invariant-safe), `cep_cell_finalize_hard`, `cep_store_del`, and hard delete helpers reclaim stores and payloads | ⚙️ Wire proxy lifecycle, clone support, and shadow-aware teardown |
| Tooling & safety nets | ⚙️ Partial | Assertions wrap public APIs; Meson builds + unit tests guard regressions | ⚙️ Add adaptive traversal stacks, locks, persistence hooks, and broader coverage |
| Heartbeat dispatcher | ⚙️ Partial | `cep_heartbeat_*` stages beats, memoises per-impulse resolver output, and honours dependency/name ordering | ⚙️ Wire agency execution, agenda persistence, and telemetry hooks before parallelism |

### Current Foundations
- ✅ Deterministic cell manipulation through `cep_cell_add`, `cep_cell_append`, and traversal helpers keeps storage engines aligned.
- ✅ Cell-bound enzyme resolver now exercises propagation, tombstone masking, and union semantics via the heartbeat test suite.
- ✅ Append-only timelines rely on `cep_data_history_*`, `cep_store_history_*`, and timestamped cells for consistent replay.
- ✅ Multiple child store back-ends provide insertion, lookup, and removal contracts while preserving sibling order.
- ✅ Soft removal helpers (`cep_cell_child_take` / `cep_cell_child_pop`) expose archived children without breaking history.
- ✅ Meson-based CI scripts run the MUnit suite under MSYS to validate core behaviours.

### Active Focus Areas
- ⚙️ Tighten idempotency for comparator and hash-indexed stores so repeated inserts shortcut on structure checks.
- ⚙️ Harden auto-ID handling and metadata masking before exposing external name APIs.
- ⚙️ Finish HANDLE/STREAM historical visibility and error-channel integration now that read/write/journal helpers ship.
- ⚙️ Capture high-water metrics for the adaptive traversal stack now that it grows automatically.

### Backlog Watchlist
- 📎 Link and shadow cleanup, including refcounting and garbage collection hooks.
- 📎 Packed queue recycling to reuse nodes after deletions.
- 📎 Range queries and hash-lookup helpers for large dictionaries.
- 📎 Persistence and lock semantics across `cepData` and `cepStore`.

### Future Stream Subsystem Enzymes
Bringing stream helpers into the enzyme catalogue would let impulse-driven workflows capture file and socket actions without dropping into raw API calls, giving operators a friendlier switchboard for everything that currently lives in the IO layer.

#### Technical Details
- Surface wrappers around `cep_stream_stdio_*` and `cep_stream_zip_*` so impulses can append, rotate, or close resources under heartbeat control.
- Provide enzymes for checkpoint-friendly stream snapshots (flush, rewind, truncate) that honour existing locking semantics.
- Mirror the cell operation structure: each wrapper advertises a deterministic label, relies on the same registry plumbing, and stays idempotent by default to avoid duplicate writes when impulses retry.
- Phase one (stdio) and phase two (ZIP) adapters already exist; extend coverage to foreign stream integrations while keeping dependency footprints reviewable.

#### Q&A
- **Why start with stream wrappers?** They are the most common side-effecting calls that still bypass the heartbeat; wrapping them aligns IO with the impulse dispatch contract.
- **Will this replace the existing API?** No. Direct calls stay available for tight loops, but enzymes give orchestration layers a safer entry point.
- **Do we need new storage metadata?** Only lightweight descriptors (e.g., flush depth, rotation policy) so the resolver can track idempotency and retries.
- **How will retries be handled?** The wrappers will validate stream state before acting and no-op when their requested change already landed, mirroring the pattern used by cell enzymes.

### Milestones
- **Milestone 1 - Historic cells and idempotent stores**
  - ✅ Comparator/hash dedupe reuses existing nodes through `store_find_child_by_key`.
  - ✅ VALUE/DATA snapshots persist history via `cep_data_history_*` and hash recomputes.
  - ⚙️ Auto-ID cursor fixes still pending for caller-supplied numeric tags.
  - 📎 Link archiving metadata remains planned so historic trees stay replayable.
- **Milestone 2 - Structural resilience**: 📎 Planned — deliver traversal depth management, shadow cleanup, packed queue recycling, and re-sort helpers for RB-tree/octree back-ends to keep large collections stable.
- **Milestone 3 - Runtime baseline**: ⚙️ Partial — heartbeat bootstrap/start/step/shutdown loops now run with memoised agenda resolution and deterministic enzyme ordering; still pending are agency executors, channel wiring, and runtime telemetry.
  - ✅ Multi-beat `op/boot`/`op/shdn` timelines publish `ist:*` milestones across successive beats and honour awaiters without the legacy signal shim.
- **Milestone 4 - Extended feature set**: 📎 Planned — add HANDLE/STREAM lifetimes, proxy lifecycle polish, deep cloning, persistence hooks, and expanded tests once the core runtime is proven.

## Q&A
- **Why does Milestone 1 stop at VALUE/DATA payloads?** Milestone 1 locked down history and idempotence for VALUE/DATA; HANDLE/STREAM read/write landed afterward, with historical snapshots still tracking under later milestones.
- **Do link shadows matter before the runtime ships?** Yes. Without cleanup the archive helpers leak state, so shadow hygiene is part of structural resilience.
- **Can we expose child hashes before Milestone 2?** Only after comparator/hash dedupe is complete; otherwise repeated inserts risk drifting snapshots.
- **What happens to proxy-backed cells?** They graduate in the extended feature milestone once historicity, traversal, and runtime loops are stable.
