CEP Developer Handbook

Overview
- Scope: Hands-on guidance for implementing and extending CEP Layer 0 (Kernel) and preparing for Layers 1–2. Focus on `cep_cell.*` as the foundation. Ignore enzymes/heartbeat modules for now unless explicitly noted.
- Model: Deterministic, stepwise system built from immutable facts (cells) and structured child-storage (stores). Determinism and replayability are non‑negotiable design constraints.

Repository Layout
- `src/l0_kernel/cep_cell.h|.c` — Core cell/data/store types and operations.
- `src/l0_kernel/storage/*` — Pluggable child-storage implementations (linked list, dynamic array, packed queue, RB-tree, octree).
- `src/l0_kernel/cep_molecule.h` — Low-level utilities: memory, alignment, branch prediction, small helpers.
- `src/test/*` — MUnit tests, examples of API usage.
- `docs/CEP.txt` — Conceptual blueprint: layers, execution model, goals.

Related Docs
- `docs/L0_Kernel/EXTERNAL-LIBRARIES-INTERFACE.md` — Accessing foreign library structures; handles vs snapshots; zero‑copy rules.
- `docs/L0_Kernel/IO-STREAMS-AND-FOREIGN-RESOURCES.md` — Effect log, streams, preconditions, CAS, and replay modes.
- `docs/L0_Kernel/NATIVE-TYPES.md` — L0 native types, canonical encoding, hashing/comparison.

Build & Test (MSYS/bash)
- Meson/Ninja (recommended)
  - Configure: `meson setup build`
  - Build: `meson compile -C build`
  - Run tests: `meson test -C build`
- Fallback Makefile (no Meson/Ninja)
  - Build: `make -C unix`
  - Run tests with debug logs: `../build-make/bin/cep_tests --log-visible debug`
  - Clean: `make -C unix clean`
Notes
- Toolchain: gcc + Meson/Ninja on MSYS2 UCRT64 and Manjaro works out of the box; fallback Makefile uses `gcc + make`.
- CFLAGS are tuned for this codebase: assertions are used heavily; do not strip them while developing.

Kernel Concepts (L0)
- cepID: 64-bit value encoded with naming bits. Supports multiple naming modes: word (lowercase), acronym (upper), reference, numeric. Helpers convert to/from compact encodings.
- cepDT: Domain-Tag pair (name). Comparison is lexicographic: first domain, then tag.
- cepMetacell: Metadata + name bits (type, visibility, shadowing, domain, tag). Same size/layout as cepDT; system bits occupy 2×6 positions.
- cepData: Data payload with metadata and representation type:
  - VALUE: in-struct small buffer (`value[]`).
  - DATA: heap buffer (`data`, `destructor`).
  - HANDLE: opaque resource (external library), references another cell.
  - STREAM: window onto external stream.
- cepStore: Child container with configurable storage and indexing strategy.
  - Storage: linked list, array, packed queue, red-black tree, octree.
  - Indexing: insertion order, by name, by user compare, by hash+compare.
- cepCell: The unit node. Holds metacell, optional data or link, and optional store for children.

Core Invariants
- Deterministic operations: no nondeterministic iteration over children; ordering is defined by storage/indexing.
- Valid names only: `cep_dt_valid()` for any DT used; ID/naming helpers gate correctness.
- Ownership clarity:
  - `store->owner` links a store back to its parent cell.
  - `cell->parent` points to the parent store (not the parent cell directly).
  - Transfers move structs without deep copies unless explicitly cloning.
- Memory discipline: allocate via `cep_malloc*`, free via `cep_free`, use `CEP_0()` to zero-initialize, and clean up on all exit paths. Most functions assert on preconditions.

Primary API (Patterns)
- Initialize a cell
  - Empty: `cep_cell_initialize_empty(&c, CEP_DT...)`
  - With data: `cep_cell_initialize_value(...)` or `cep_cell_initialize_data(...)`
  - With children store: `cep_cell_initialize_list|dictionary|catalog|spatial(...)`
- Add/append children
  - Insert (pos/name/sorted): `cep_cell_add(...)`
  - Append/prepend (insertion index): `cep_cell_append(..., prepend)`
  - Shorthands: `cep_cell_add_value|data|list|dictionary|catalog|link`, and their `append|prepend` variants.
- Lookup and navigation
  - First/last/prev/next: `cep_cell_first|last|prev|next`
  - By name/key/position/path: `cep_cell_find_by_*`
  - Traverse shallow/deep: `cep_cell_traverse`, `cep_cell_deep_traverse`
- Removal
  - Remove/pull from parent store: `cep_cell_child_take|pop` (reorganizes siblings), `cep_cell_remove`
- Data access/update
  - Read: `cep_cell_data(cell)`
  - Update: `cep_cell_update(cell, size, capacity, value, swap)`
  - Delete data/store: `cep_cell_delete_data|store|children`
  - Sort: `cep_cell_to_dictionary`, `cep_cell_sort(compare, ctx)`

Child Storage Strategies
- Linked list (`cep_linked_list.h`)
  - Strengths: fast prepend/append; simple sorted insertion; easy traversal.
  - Cost: O(n) random access; more pointers per node.
- Dynamic array (`cep_dynamic_array.h`)
  - Strengths: cache-friendly, O(1) by position; supports named and sorted operations.
  - Cost: shifts on insertion/removal; capacity management.
- Packed queue (`cep_packed_queue.h`)
  - Strengths: amortized fast head/tail operations.
  - Limitation: insertion indexing only; not for name/sorted modes.
- Red-black tree (`cep_red_black_tree.h`)
  - Strengths: ordered by name or custom compare; O(log n) insert/find.
  - Note: resorting/rebalancing changes are controlled; no insertion-order mode.
- Octree (`cep_octree.h`)
  - Strengths: spatial indexing with user comparator.
  - Precondition: requires center/subwide bound and comparator.

Coding Conventions
- Assertions everywhere: validate pointers, modes, and index ranges. Fail fast in debug.
- Avoid hidden side effects: functions that mutate also document store/indexing prerequisites (e.g., insertion-only vs. dictionary vs. sorted modes).
- Clear lifetimes: if you allocate, you free. For DATA, always set destructor or adopt ownership.
- Use `cep_cell_transfer` to move contents between cells without deep copy; only use deep clone when needed.
- Respect naming constraints:
  - Words: lowercase + `: _ - . /` up to 11 chars.
  - Acronyms: ASCII 0x20–0x5F up to 9 chars.
  - Numeric: parent-local auto-id unless explicitly set.

Testing Guidelines
- Prefer MUnit patterns shown in `src/test/test_cell.c`:
  - Zero/one/multi-item operations per storage flavor.
  - Nested structure tests for traversal correctness.
  - Sequencing tests: confirm storage equivalence across implementations.
- Build incremental tests when adding features:
  - Add for HANDLE/STREAM data paths when implemented.
  - Add for HASH indexing when implemented.
  - Add range queries and path iteration robustness.

Roadmap (Kernel-Focused)
1) Complete data backends
   - Implement HANDLE/STREAM read/update semantics (currently TODO paths in `cep_cell.c`).
   - Clarify resource lifecycle: reference counting or explicit unref on HANDLE/STREAM.
2) Shadowing and links
   - Maintain reverse shadow lists in targets (`cepShadow`) when creating/removing links.
   - Expose APIs to enumerate shadows and to update nested links on replace/move (`cep_cell_update_nested_links(old,new)`).
3) Indexing features
   - Implement `CEP_INDEX_BY_HASH` (primary hash, secondary comparator) across list/array/tree where applicable.
   - Range queries for dictionaries/catalogs (min/max and between).
4) Sorting/resorting
   - RB-tree: re-sort/re-index helpers when switching compare functions.
   - Octree: reinsert on compare/bound changes; verify traversal ordering contracts.
5) Path/traverse robustness
   - Replace global `MAX_DEPTH` with adaptive stack allocation; grow on demand and track high-water marks for tuning.
   - Add internal-order traversal (storage-native sequencing) explicitly verified by tests.
6) Specialized stores
   - One-member-only dictionary (organizational convenience) with fast replace semantics.
7) Concurrency and locks (pre-Heartbeat)
   - Define lock bit semantics in `cepStore`/`cepData`. Provide coarse-grained writer locks and assert-only checks in debug. No atomics required yet; keep determinism.
8) Persistence hooks (pre-Enzyme)
   - Define snapshot/restore surfaces at cell/store boundaries; hash and encoding metadata are already present.

Integration Previews (Beyond Kernel)
- Heartbeat (L0 runtime):
  - Step boundary semantics: outputs from step N appear in N+1; never earlier.
  - Memory safety: per-beat staging structures; commit on tick.
  - Scheduling API draft: queue impulses, poll enzymes, flush writes.
- Enzymes (L0 actors):
  - Contract: consume cells, emit cells; no hidden side effects; declare domains touched.
  - Safety: deterministic within a heartbeat, with full provenance (who/why).

Contributing Checklist
- Does the new code preserve determinism and ordering contracts of the chosen storage/indexing?
- Are all pointer and mode preconditions asserted?
- Are lifetimes clear and destructors set where needed?
- Are name/ID rules respected and validated?
- Are tests added to cover normal, boundary, and error paths for the new behavior?

Common Pitfalls
- Forgetting to set `store->owner` when attaching a store or after transfers.
- Mutating data when `writable` is false.
- Using insertion-only operations on dictionary/sorted stores (asserts will fire).
- Not updating auto-id when IDs are auto-pending; call `store_check_auto_id` flow via existing add/append helpers.

Minimal Usage Example
- Create a dictionary under root, insert a value, and query it:
  - `cep_cell_system_initiate();`
  - `cepCell* dict = cep_cell_add_dictionary(cep_root(), CEP_DTWA("CEP","temp"), 0, CEP_DTWA("CEP","dictionary"), CEP_STORAGE_ARRAY, 16);`
  - `uint32_t v = 42;`
  - `cepCell* item = cep_cell_add_value(dict, CEP_DTWA("CEP","enum"), 0, CEP_DTWA("CEP","enum"), (cepID)0, CEP_ID(0), &v, sizeof v, sizeof v);`
  - `cepCell* found = cep_cell_find_by_name(dict, cep_cell_get_name(item));`
  - `assert(found == item);`
  - `cep_cell_system_shutdown();`

Style Guide (Local)
- Prefer small `static inline` helpers in headers for fast-path checks.
- Keep public entry points in `.c` minimal and assert-rich.
- No one-letter variables in public APIs; keep internal helpers concise and consistent with existing code.
- Avoid adding external dependencies; keep Layer 0 standalone and portable.

Where To Look When Extending
- Storage feature patterns: mirror linked list/array APIs to keep store-agnostic logic in `cep_cell.c` straightforward.
- Name encoding: see `CEP_TEXT_TO_*` macros for adding custom naming schemes if ever needed.
- Tests as documentation: `src/test/test_cell.c` shows expected semantics across all storage/indexing pairs.

FAQs
- Q: How do I ensure replayability while adding new features?
  - A: Make all choices explicit and logged (test-visible). No implicit randomness; tie ordering to store/indexing.
- Q: Can I modify facts in place?
  - A: Treat `cepData` as the cell’s current value; if you need immutable audit, version externally (future layers) or append new cells.
- Q: What about performance?
  - A: Choose the right store. Profile later, but keep algorithmic complexity honest (avoid O(n^2) hot paths).

Next Steps You Can Pick Up
- Implement HANDLE/STREAM update/read paths in `cep_cell.c` and add tests.
- Add hash-based indexing across list/array/tree with a thin hash adapter.
- Introduce range queries for dictionaries/catalogs (include tests mirroring by-name/by-key behavior).
- Replace global `MAX_DEPTH` with an adaptive stack in deep traversal + tests for very deep structures.
