# L0 Kernel Roadmap

The L0 Kernel is the library layer that keeps every CEP cell organised so higher-level tools can build apps on top. If you imagine CEP as a worldwide filing system, L0 is the cabinet: it knows how drawers are labelled, how folders nest, and how to stash the actual sheets of paper. This roadmap explains what parts of that filing cabinet are already solid, what is only sketched out, and which drawers still need to be built.

## Technical Roadmap Overview

### Capability Snapshot
| Area | Delivered Today | Gaps / Follow-up |
| --- | --- | --- |
| Naming & metadata | Domain/tag encoding helpers, metacell flags, ID validation (`src/l0_kernel/cep_cell.h`) | Auto-ID reconciliation when names arrive out of order, masking of system bits before exposing names |
| Data payloads | VALUE/DATA storage works end-to-end (`cep_data_new`, `cep_cell_update`) with append-only history and payload hashes on every mutation | HANDLE/STREAM read/update paths missing, idempotency by hash planned for handles/streams |
| Child stores | Linked list/array/packed queue/RB-tree/octree back-ends operational with add/find/traverse coverage; timestamps cover regular edits and indexing changes snapshot into `store->past`, threading child `node->past` chains; insertion/dictionary paths are idempotent | Hash-based indexing, RB-tree/octree re-sort helpers, extend structural idempotency to comparator/hash stores, one-member dictionary, range queries, packed-queue optimisations |
| Links & shadowing | Link creation and traversal macros compile; link cells can be attached | Shadow arrays never cleaned, unlink/self-list logic absent, shadow metadata never written |
| Flex & composite cells | Normal cell lifecycle (init/add/remove/traverse) battle-tested by `test_cell.c` | FLEX semantics unimplemented, deep clone pending, nested link updates missing |
| Runtime (heartbeat/enzyme) | Bootstraps core tree (`cep_heartbeat.c`), agency registration, task queue scaffolding | Startup/step/shutdown loops empty, instance disposal incomplete, channel connection TODOs, multiple output fan-out |
| Tooling & safety | Assertions guard public APIs, Meson build + unit tests run under MSYS | Adaptive traversal stack, data/store locks semantics, persistence hooks, extended test coverage for new features |

### Implemented Foundations
- **Deterministic cell model:** `cep_cell_initialize`, `cep_cell_add|append|find*` and traversal helpers provide consistent behaviour across storage engines; unit tests exercise list/dictionary/catalog flows.
- **Modular child storage:** Five storage backends share a common contract for insertion, lookup, and removal, enabling deterministic iteration modes per indexing strategy.
- **Data lifecycle for VALUE/DATA:** Heap-backed and in-place payloads allocate, clone-on-update, and free correctly, including capacity checks and destructor handling.
- **Meson-based test harness:** `meson test -C build` runs the MUnit suite, validating all existing cell operations across storage variants.

### High-Priority Gaps (Design Complete, Code Missing)
1. **Store history refinements:** `cepStore` snapshots every mutation, but comparator/hash stores still lack idempotent fast paths. Extend structural equality to those modes and trim snapshot overhead where possible.
2. **HANDLE/STREAM support:** Allocation scaffolding exists but read/update paths return `NULL` and destructors do not release handles (`src/l0_kernel/cep_cell.c:212-281`). Add lifetimes, reference counting, and vtable wiring per `docs/L0_Kernel/IO-STREAMS-AND-FOREIGN-RESOURCES.md`.
3. **Link/shadow hygiene:** Shadow tables never clean up; link finalisation is a TODO (`cep_cell.c:391`, `cep_cell.c:1138-1162`). Add reference tracking, unlink logic, and ensure shadows survive history rules.
4. **Runtime loop semantics:** Heartbeat start/step/shutdown calls are placeholders, and enzyme task handling does not process work queues or output fan-out. Implement beat traversal, agency execution, and fluent channel wiring before exposing the API.
5. **FLEX cells and cloning:** `CEP_TYPE_FLEX` and `cep_cell_initialize_clone` are unused stubs. Finalise semantics for auto-promotion from single value to collection, then deliver deep clone for history snapshots and replication.

### Medium-Priority Gaps (Needed for Feature Completeness)
- **Range and hashed lookups:** Add `CEP_INDEX_BY_HASH`, dictionary range queries, and hashing helpers so large stores avoid linear scans and users can query slices.
- **Re-sort support:** RB-tree/octree backends lack re-index logic when ordering functions change; add rebalancing hooks and tests.
- **Auto-ID robustness:** When callers explicitly set IDs above the auto-id cursor the cursor should advance (`cep_cell.h:780`). Implement detection and backfill tests.
- **Traversal depth management:** Replace the global `MAX_DEPTH` guard with an adaptive stack that records high-water marks and eliminates global state.
- **Packed queue recycling:** Optimise packed queue deletion to reuse nodes rather than discarding allocations (`storage/cep_packed_queue.h:231`).

### Lower-Priority / Nice-to-Have Items
- **One-member dictionaries:** Add specialised container for configuration-style cells to reduce allocation overhead.
- **Persistence and locks:** Define lock-bit semantics on `cepData`/`cepStore` and surface persistence hooks for snapshot/restore.
- **Testing gaps:** Extend unit tests to cover link/shadow behaviour, heartbeat scheduling, and all newly added storage behaviours once implemented.

### Suggested Milestones
- **Milestone 1 – Data correctness:** Wire append-only history, HANDLE/STREAM, and FLEX semantics; expand tests to cover rewind scenarios.
- **Milestone 2 – Storage expressiveness:** Deliver hash indexing, range queries, and re-sort hooks; document new APIs.
- **Milestone 3 – Runtime readiness:** Complete heartbeat loop, enzyme task engine, and channel management; add integration tests under `test/` exercising agency lifecycles.
- **Milestone 4 – Hardening:** Implement lock semantics, adaptive traversal depth, and persistence hooks; benchmark heavy directory workloads.

## Q&A
- **Why call out unimplemented HANDLE/STREAM features if the rest of the kernel works?** The headless scaffolding hides correctness bugs; wiring resource lifetimes now prevents data corruption once external libraries plug in.
- **Do we need append-only history before shipping?** Yes. Replayable history underpins determinism and is part of the public promise; without it higher layers cannot safely time-travel or audit.
- **What is the priority of the heartbeat loop compared to storage gaps?** Heartbeat work unblocks enzyme execution and integration tests; storage enhancements can follow once runtime determinism is proven.
- **How should contributors stage their work?** Tackle high-priority gaps in the order listed, land thorough tests, and update the developer handbook alongside any new surface area.
