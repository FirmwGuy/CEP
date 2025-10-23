# L0 Design: Cells, Stores, and Append-Only History

## Nontechnical Summary
Cells are Layer 0’s atoms: each one holds a name, optional payload, and an optional child collection. Rather than overwriting state, the kernel appends new facts with timestamps so any previous view can be reconstructed later. Stores give each branch the right data structure—lists, dictionaries, queues, spatial indexes—without breaking the history guarantees. This design keeps data trustworthy: you can always explain how a value arrived, rewind to an earlier beat, or swap storage strategies without losing lineage.

## Decision Record
- Append-only timelines for payloads (`cepData`) and structure (`cepStore`) guarantee historical queries with O(1) metadata updates.
- Reindex snapshots are captured only when ordering policy changes, limiting history storage to meaningful structural shifts.
- Stores are pluggable but share a common API so traversal, mutation, and serialization code stay agnostic to the backing container.
- Auto-ID tags advance monotonically per parent; explicit numeric tags sync the cursor to avoid collision.
- Veiled transactions build subtrees off to the side and reveal them atomically, preserving audit trails.

## Subsystem Map
- Code
  - `src/l0_kernel/cep_cell.c`, `cep_cell.h` — cell lifecycle, history maintenance, transaction helpers.
  - `src/l0_kernel/cep_cell_system.c` — root bootstrap, global counters, topology helpers.
  - `src/l0_kernel/storage/*.h` — backend implementations (linked list, dynamic array, packed queue, red-black tree, hash table, octree).
  - `src/l0_kernel/cep_cell_stream.c` — payload helpers for HANDLE/STREAM types.
- Tests
  - `src/test/l0_kernel/test_cell.c`, `test_cell_mutations.c`, `test_cell_immutable.c` — mutation paths, history replay, snapshot invariants.
  - `src/test/l0_kernel/test_traverse.c`, `test_traverse_all.c` — traversal behaviour across stores and history modes.
  - `src/test/l0_kernel/test_locking.c`, `test_locking_randomized.c` — store/data lock enforcement.
  - `src/test/l0_kernel/test_cells_randomized.c` — randomized coverage for storage backends and auto-ID behaviour.

## Operational Guidance
- Choose the lightest store that fits the query pattern: insertion order for logs, hash for large dictionaries, red-black tree for ordered catalogs, octree for spatial workloads.
- Avoid repeated reindexing; it creates extra history snapshots. Prefer designing with the final indexing policy in mind.
- Treat HANDLE/STREAM payloads as proxies; clones become links by design. Any required duplication must happen at the adapter level.
- Use veiled transactions for complex subtree builds; they keep partial state hidden and enforce a single reveal.
- Monitor auto-ID cursors when importing data; resetting them incorrectly can produce collisions that violate append-only guarantees.

## Change Playbook
1. Review this design doc plus `docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md`, `docs/L0_KERNEL/topics/LOCKING.md`, and the relevant store topic.
2. Write tests covering the new behaviour in `test_cell*.c` or store-specific suites before changing core helpers.
3. Modify `cep_cell.c` or storage headers, ensuring timestamp updates and history chains stay intact.
4. Re-run `meson test -C build --suite cell` (and relevant randomized suites) followed by `python tools/check_docs_structure.py`.
5. Update documentation (topics, overview, tuning notes) if storage guidance changes.
6. Rebuild docs with `meson compile -C build docs_html` to verify cross-links.

## Global Q&A
- **Why not support in-place updates?** In-place mutations break replay guarantees and make audits harder. Append-only timelines keep history cheap and reliable.
- **How do I remove data permanently?** Use hard delete paths intended for GC; they collapse history but must be reserved for controlled cleanup, not routine edits.
- **Can I mix multiple stores under the same parent?** Each child cell chooses its own store, so nesting different structures is supported and encouraged.
- **What about structural clones?** Deep clones respect append-only rules, duplicating payloads where legal and turning HANDLE/STREAM entries into links for safety.
- **How are locks enforced?** Store and data locks propagate up the ancestor chain; any locked parent blocks mutations below to keep deterministic sequencing.
