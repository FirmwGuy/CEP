# L0 Kernel Roadmap

The L0 Kernel keeps CEP's tree of cells organised so applications can treat it like a digital filing cabinet. Picture a network-spanning set of folders where each update is timestamped; L0 is the librarian that knows which sheet moved, when it moved, and how every drawer lines up.

## Technical Roadmap Overview

### Capability Snapshot
| Area | Status | In Place | Next Focus |
| --- | --- | --- | --- |
| Bootstrap & identity | Done | `cep_cell_system_initiate` seeds the root dictionary; `cep_cell_initialize` stamps deterministic domains/tags | Document safe-name helpers before exposing identifiers to tooling |
| Auto-ID & metadata hygiene | Partial | `cep_store_add_child` assigns auto IDs and flags state changes | Advance the cursor when callers preset IDs; strip system bits in accessors |
| Data payload lifecycle | Partial | `cep_data_new`, `cep_cell_update`, and `cep_data_history_*` maintain VALUE/DATA payload history with hashes | Finish HANDLE/STREAM read, history, and destructor paths |
| Child store engines | Partial | Linked list, array, packed queue, RB-tree, and octree back-ends wired through `cep_store_new`; structural dedupe in `cep_store_add_child` | Extend dedupe to comparator/hash indexes; add hash lookups and re-sort helpers |
| Historical queries | Partial | `cep_cell_find_by_*_past`, `cep_cell_traverse_past`, and deep traversal replay timelines without mutating live data | Provide snapshot payloads for HANDLE/STREAM; replace the global `MAX_DEPTH` guard |
| Link handling & shadowing | Planned | Link macros resolve references; soft take/pop expose archived children as links | Track link lifetimes, clean shadow metadata, and record snapshot provenance |
| Lifecycle & GC | Partial | `cep_cell_finalize`, `cep_store_del`, and hard delete helpers reclaim stores and payloads | Implement FLEX semantics, clone support, and shadow-aware teardown |
| Tooling & safety nets | Partial | Assertions wrap public APIs; Meson builds + unit tests guard regressions | Add adaptive traversal stacks, locks, persistence hooks, and broader coverage |

### Current Foundations
- Deterministic cell manipulation through `cep_cell_add`, `cep_cell_append`, and traversal helpers keeps storage engines aligned.
- Append-only timelines rely on `cep_data_history_*`, `cep_store_history_*`, and timestamped cells for consistent replay.
- Multiple child store back-ends provide insertion, lookup, and removal contracts while preserving sibling order.
- Soft removal helpers (`cep_cell_child_take` / `cep_cell_child_pop`) expose archived children without breaking history.
- Meson-based CI scripts run the MUnit suite under MSYS to validate core behaviours.

### Active Focus Areas
- Tighten idempotency for comparator and hash-indexed stores so repeated inserts shortcut on structure checks.
- Harden auto-ID handling and metadata masking before exposing external name APIs.
- Deliver HANDLE/STREAM payload persistence, including destructors and snapshot visibility.
- Replace the global traversal depth guard with an adaptive stack and high-water metrics.

### Backlog Watchlist
- Link and shadow cleanup, including refcounting and garbage collection hooks.
- Packed queue recycling to reuse nodes after deletions.
- Range queries and hash-lookup helpers for large dictionaries.
- Persistence and lock semantics across `cepData` and `cepStore`.

### Milestones
- **Milestone 1 - Historic cells and idempotent stores**: Finish comparator/hash dedupe, auto-ID cursor fixes, VALUE/DATA snapshot guarantees, and link archiving metadata so the proof-of-concept tree is fully replayable.
- **Milestone 2 - Structural resilience**: Deliver traversal depth management, shadow cleanup, packed queue recycling, and re-sort helpers for RB-tree/octree back-ends to keep large collections stable.
- **Milestone 3 - Runtime baseline**: Implement heartbeat start/step/shutdown loops, agency execution, and channel wiring so the kernel can drive real workloads.
- **Milestone 4 - Extended feature set**: Add HANDLE/STREAM lifetimes, FLEX semantics, deep cloning, persistence hooks, and expanded tests once the core runtime is proven.

## Q&A
- **Why does Milestone 1 stop at VALUE/DATA payloads?** Locking down history and idempotence proves the timeline model; HANDLE/STREAM work can land once the replay story is airtight.
- **Do link shadows matter before the runtime ships?** Yes. Without cleanup the archive helpers leak state, so shadow hygiene is part of structural resilience.
- **Can we expose child hashes before Milestone 2?** Only after comparator/hash dedupe is complete; otherwise repeated inserts risk drifting snapshots.
- **What happens to FLEX cells?** They graduate in the extended feature milestone once historicity, traversal, and runtime loops are stable.
