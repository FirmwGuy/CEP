# L0 Topic: Developer Handbook

## Overview
- Scope: Hands-on guidance for implementing and extending CEP Layer 0 (Kernel) and preparing for Layers 1–2. Focus on `cep_cell.*` as the foundation. Ignore enzymes/heartbeat modules for now unless explicitly noted.
- Model: Deterministic, stepwise system built from immutable facts (cells) and structured child-storage (stores). Determinism and replayability are non‑negotiable design constraints.

## Repository Layout
- `src/l0_kernel/cep_cell.h|.c` — Core cell/data/store types and operations.
- `src/l0_kernel/storage/*` — Pluggable child-storage implementations (linked list, dynamic array, packed queue, RB-tree, octree).
- `src/l0_kernel/cep_molecule.h` — Low-level utilities: memory, alignment, branch prediction, small helpers.
- `src/test/*` — MUnit tests, examples of API usage.
- `docs/CEP.md` — Conceptual blueprint: layers, execution model, goals.

## Related Docs
- Core cell model
  - `docs/L0_KERNEL/topics/NATIVE-TYPES.md` — L0 native types, canonical encoding, hashing/comparison.
  - `docs/L0_KERNEL/topics/LINKS-AND-SHADOWING.md` — Link resolution, backlinks, and shadowing (tree → safe graph).
  - `docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md` — Append‑only history and idempotent updates for cells.
- Runtime and scheduling
  - `docs/L0_KERNEL/topics/HEARTBEAT-AND-ENZYMES.md` — Beat model, scheduling, enzyme contracts, replay safety.
  - `docs/ROOT-DIRECTORY-LAYOUT.md` — Recommended root structure, journal/CAS, visibility rules.
- External I/O
  - `docs/L0_KERNEL/topics/EXTERNAL-LIBRARIES-INTERFACE.md` — Access to foreign structures; handles vs snapshots; zero‑copy rules.
  - `docs/L0_KERNEL/topics/IO-STREAMS-AND-FOREIGN-RESOURCES.md` — Effect log, streams, preconditions, CAS, replay modes.

## Build & Test (MSYS/bash)
- Meson/Ninja (recommended)
  - Configure: `meson setup build`
  - Build: `meson compile -C build`
  - Run tests: `meson test -C build`
- Fallback Makefile (no Meson/Ninja)
  - Build: `make -C unix`
  - Run tests with debug logs: `../build-make/bin/cep_tests --log-visible debug`
  - Clean: `make -C unix clean`
## Notes

- Toolchain: gcc + Meson/Ninja on MSYS2 UCRT64 and Manjaro works out of the box; fallback Makefile uses `gcc + make`.
- CFLAGS are tuned for this codebase: assertions are used heavily; do not strip them while developing.

## Kernel Concepts (L0)
- cepID: 64-bit value encoded with naming bits. Supports multiple naming modes: word (lowercase), acronym (upper), reference, numeric. Helpers convert to/from compact encodings.
- cepDT: Domain-Tag pair (name). Comparison is lexicographic: first domain, then tag.
- cepMetacell: Metadata + name bits (type, visibility, shadowing, domain, tag). Same size/layout as cepDT; system bits occupy 2×6 positions.
- cepData: Data payload with metadata and representation type:
  - VALUE: in-struct small buffer (`value[]`).
  - DATA: heap buffer (`data`, `destructor`).
  - HANDLE: opaque resource (external library), references another cell.
  - STREAM: window onto external stream.
  - Ordering and semantics: L0 treats payloads as opaque bytes and orders data by (cepDT, size, bytes). Enzymes or upper-layer packs define any per-tag canonicalization or schemas.
- cepStore: Child container with configurable storage and indexing strategy.
  - Storage: linked list, array, packed queue, red-black tree, octree.
  - Indexing: insertion order, by name, by user compare, by hash+compare.
- cepCell: The unit node. Holds metacell, optional data or link, and optional store for children.

### Naming vs Structural Tags
- `cell->metacell.dt` carries the cell's own name (domain + tag). For dictionary children this matches the key assigned by the parent.
- `cell->data->dt` describes the payload schema or datatype. Helpers such as `cep_cell_add_value` pass a DT here so higher layers know how to interpret the bytes while keeping the payload opaque to the kernel.
- `cell->store->dt` labels the child collection. `cep_cell_add_dictionary(child, name, context_dt, type_dt, ...)` uses `name` for the child's metacell and `type_dt` for the store so traversal can recognize record classes ("CEP:being", "CEP:bond", etc.).
- Rule of thumb: metacell names identity; data/store `dt` signal structure. Mixing them makes history harder to read and breaks discovery helpers.

### Name Interning
Short nicknames stay on the label; long nicknames get filed once and every cell just keeps a reference number. You still talk to the cell the same way, but the kernel decides the cheapest way to store the name.

#### Technical Details
- Fast paths: decimal strings that fit 56 bits become `CEP_NAMING_NUMERIC`. Lowercase/punctuated text (≤11 chars) uses word IDs, uppercase/punctuated text (≤9 chars) uses acronym IDs. These never touch the intern pool.
- Reference IDs: anything longer or mixed (UTF-8) up to 256 bytes goes through `cep_namepool_intern[_static]`, which stores the bytes under `/CEP/sys/namepool` and returns a `CEP_NAMING_REFERENCE` (page,slot) ID. Static entries reuse the caller’s buffer; dynamic ones copy into the CAS-backed value.
- Refcounts: dynamic interns bump a refcount and can be released via `cep_namepool_release(id)` when modules unload. Static interns are permanent. Lookup returns the canonical byte pointer for logging or API use.
- Validation: `cep_id_text_valid` and `cep_dt_is_valid` now treat reference IDs as first-class, so downstream code doesn’t need special cases.

#### Q&A
- **Do I have to call the pool for every name?** No. Only call it if you need a reference ID explicitly; helpers such as `cep_cell_set_name` already fall back to word/acronym/numeric.
- **What happens during replay?** The `/CEP/sys/namepool` cells are part of the append-only history. Replaying rebuilds the same table so `(page,slot)` IDs are stable.
- **How do I remove dynamic names?** Keep the ID and call `cep_namepool_release(id)` once you no longer use it (e.g., when unloading a shared library). The pool clears the slot when the refcount drops to zero.

## Core Invariants
- Deterministic operations: no nondeterministic iteration over children; ordering is defined by storage/indexing.
- Valid names only: `cep_dt_is_valid()` for any DT used; ID/naming helpers gate correctness.
- Ownership clarity:
  - `store->owner` links a store back to its parent cell.
  - `cell->parent` points to the parent store (not the parent cell directly).
  - Transfers move structs without deep copies unless explicitly cloning.
- Memory discipline: allocate via `cep_malloc*`, free via `cep_free`, use `CEP_0()` to zero-initialize, and clean up on all exit paths. Most functions assert on preconditions.

## Primary API (Patterns)
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
  - Remove/pull from parent store: soft delete via `cep_cell_child_take|pop` (marks child deleted and returns a link), hard removal via `cep_cell_child_take_hard|pop_hard` (reorganizes siblings), `cep_cell_remove`
- Data access/update
  - Read: `cep_cell_data(cell)`
  - Update: `cep_cell_update(cell, size, capacity, value, swap)` (records a snapshot) or `cep_cell_update_hard(...)` for in-place overwrites
  - Delete data/store: `cep_cell_delete_data|store|children`
  - Sort: `cep_cell_to_dictionary`, `cep_cell_sort(compare, ctx)`

## Child Storage Strategies
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

## Hash-Indexed Stores
Hash-indexed stores keep duplicate detection consistent without changing the public API. Linked lists, dynamic arrays, and red-black trees accept `CEP_INDEX_BY_HASH`, but they still rely on their comparator to walk the full collection (hashes are used only for equality checks). The dedicated hash-table backend is the only one that actually buckets by hash and resizes to keep lookups near O(1).

#### Technical Details
- Supported backends: linked lists, dynamic arrays, and red-black trees reuse the sorted-insert path while consulting the hash to deduplicate entries; the hash-table backend stores children in real buckets and grows/shrinks as needed.
- Creation contract: call `cep_store_new(..., CEP_INDEX_BY_HASH, compare)` and provide a comparator that first checks the stored hash and then compares a secondary field to resolve collisions. Callers constructing children manually can follow the `hash_index_add_value` pattern from the kernel tests: initialise a temporary cell, then pass it to `cep_cell_add`.
- Operations: use `cep_cell_add` or `cep_store_add_child` for inserts. The deduplication logic treats two children with equal structure and hash/compare results as the same record. Append/prepend helpers are restricted to insertion-ordered stores and will assert if used with hash indexing.
- Traversal: `cep_cell_traverse` and `store_traverse` iterate in hash/secondary order with no sentinel callback at the end, matching the behaviour of the other sorted backends.
- Testing: `test_cell_tech_hash` in `src/test/l0_kernel/test_cell.c` seeds each supported backend, verifies comparator lookups, forces rehashing or tree rotations, and checks aggregate sums to confirm bookkeeping stays consistent.

#### Q&A
- **When should I choose the hash-table storage over a red-black tree?** Pick the hash-table when you need predictable O(1) inserts and primarily fetch by key. Reach for the tree when ordered neighbour queries or range scans matter more than raw insertion speed.
- **Do I need to recompute hashes after mutating payload data?** Yes. Update the stored hash (for example via `cep_data_compute_hash`) before reinserting or replacing the child so bucket placement stays correct.
- **Can I mix `CEP_INDEX_BY_HASH` with append/prepend helpers?** No. Hash-indexed stores expect comparator-driven inserts. Use `cep_cell_add` with a prepared child; append/prepend remain reserved for insertion-order storage.

## Coding Conventions
- Assertions everywhere: validate pointers, modes, and index ranges. Fail fast in debug.
- Avoid hidden side effects: functions that mutate also document store/indexing prerequisites (e.g., insertion-only vs. dictionary vs. sorted modes).
- Clear lifetimes: if you allocate, you free. For DATA, always set destructor or adopt ownership.
- Use `cep_cell_transfer` to move contents between cells without deep copy; only use deep clone when needed.
- Respect naming constraints:
  - Words: lowercase + `: _ - . /` up to 11 chars.
  - Acronyms: ASCII 0x20–0x5F up to 9 chars.
  - Numeric: parent-local auto-id unless explicitly set.

## Testing Guidelines
- Prefer MUnit patterns shown in `src/test/test_cell.c`:
  - Zero/one/multi-item operations per storage flavor.
  - Nested structure tests for traversal correctness.
  - Sequencing tests: confirm storage equivalence across implementations.
- Build incremental tests when adding features:
  - Add for HANDLE/STREAM data paths when implemented.
  - Add for HASH indexing when implemented.
  - Add range queries and path iteration robustness.

## Roadmap (Kernel-Focused)
### 1) Complete Data Backends
   - Implement HANDLE/STREAM read/update semantics (currently TODO paths in `cep_cell.c`).
   - Clarify resource lifecycle: reference counting or explicit unref on HANDLE/STREAM.
### 2) Shadowing and Links
   - Maintain reverse shadow lists in targets (`cepShadow`) when creating/removing links.
   - Expose APIs to enumerate shadows and to update nested links on replace/move (`cep_cell_update_nested_links(old,new)`).
### 3) Indexing Features
   - Implement `CEP_INDEX_BY_HASH` (primary hash, secondary comparator) across list/array/tree where applicable.
   - Range queries for dictionaries/catalogs (min/max and between).
### 4) Sorting/Resorting
   - RB-tree: re-sort/re-index helpers when switching compare functions.
   - Octree: reinsert on compare/bound changes; verify traversal ordering contracts.
### 5) Path/Traverse Robustness
   - Replace global `MAX_DEPTH` with adaptive stack allocation; grow on demand and track high-water marks for tuning.
   - Add internal-order traversal (storage-native sequencing) explicitly verified by tests.
### 6) Specialized Stores
   - One-member-only dictionary (organizational convenience) with fast replace semantics.
### 7) Concurrency and Locks (Pre-Heartbeat)
   - Define lock bit semantics in `cepStore`/`cepData`. Provide coarse-grained writer locks and assert-only checks in debug. No atomics required yet; keep determinism.
### 8) Persistence Hooks (Pre-Enzyme)
   - Define snapshot/restore surfaces at cell/store boundaries; hash and encoding metadata are already present.

## Integration Previews (Beyond Kernel)
- Heartbeat (L0 runtime):
  - Step boundary semantics: outputs from step N appear in N+1; never earlier.
  - Memory safety: per-beat staging structures; commit on tick.
  - Scheduling API draft: queue impulses, poll enzymes, flush writes.
- Enzymes (L0 actors):
  - Contract: consume cells, emit cells; no hidden side effects; declare domains touched.
  - Safety: deterministic within a heartbeat, with full provenance (who/why).

## Contributing Checklist
- Does the new code preserve determinism and ordering contracts of the chosen storage/indexing?
- Are all pointer and mode preconditions asserted?
- Are lifetimes clear and destructors set where needed?
- Are name/ID rules respected and validated?
- Are tests added to cover normal, boundary, and error paths for the new behavior?

## Common Pitfalls
- Forgetting to set `store->owner` when attaching a store or after transfers.
- Mutating data when `writable` is false.
- Using insertion-only operations on dictionary/sorted stores (asserts will fire).
- Not updating auto-id when IDs are auto-pending; call `store_check_auto_id` flow via existing add/append helpers.

## Minimal Usage Example
- Create a dictionary under root, insert a value, and query it:
  - `cep_cell_system_initiate();`
  - `cepCell* dict = cep_cell_add_dictionary(cep_root(), CEP_DTWA("CEP","temp"), 0, CEP_DTWA("CEP","dictionary"), CEP_STORAGE_ARRAY, 16);`
  - `uint32_t v = 42;`
  - `cepCell* item = cep_cell_add_value(dict, CEP_DTWA("CEP","enum"), 0, CEP_DTWA("CEP","enum"), (cepID)0, CEP_ID(0), &v, sizeof v, sizeof v);`
  - `cepCell* found = cep_cell_find_by_name(dict, cep_cell_get_name(item));`
  - `assert(found == item);`
  - `cep_cell_system_shutdown();`

## Style Guide (Local)
- Prefer small `static inline` helpers in headers for fast-path checks.
- Keep public entry points in `.c` minimal and assert-rich.
- No one-letter variables in public APIs; keep internal helpers concise and consistent with existing code.
- Avoid adding external dependencies; keep Layer 0 standalone and portable.

## Where to Look When Extending
- Storage feature patterns: mirror linked list/array APIs to keep store-agnostic logic in `cep_cell.c` straightforward.
- Name encoding: see `CEP_TEXT_TO_*` macros for adding custom naming schemes if ever needed.
- Tests as documentation: `src/test/test_cell.c` shows expected semantics across all storage/indexing pairs.

## FAQs
- Q: How do I ensure replayability while adding new features?
  - A: Make all choices explicit and logged (test-visible). No implicit randomness; tie ordering to store/indexing.
- Q: Can I modify facts in place?
  - A: Treat `cepData` as the cell’s current value; if you need immutable audit, version externally (future layers) or append new cells.
- Q: What about performance?
  - A: Choose the right store. Profile later, but keep algorithmic complexity honest (avoid O(n^2) hot paths).

## Next Steps You Can Pick Up
- Implement HANDLE/STREAM update/read paths in `cep_cell.c` and add tests.
- Add hash-based indexing across list/array/tree with a thin hash adapter.
- Introduce range queries for dictionaries/catalogs (include tests mirroring by-name/by-key behavior).
- Replace global `MAX_DEPTH` with an adaptive stack in deep traversal + tests for very deep structures.
