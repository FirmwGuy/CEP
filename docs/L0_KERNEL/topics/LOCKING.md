# L0 Topic: Store and Payload Locks

Locking lets you "freeze" a portion of the tree so structure or payloads stay put while you inspect or snapshot it. Picture a librarian roping off a shelf: visitors can still look, but no one rearranges the books until the rope comes off.

## Technical Details
- `cep_store_lock` / `cep_store_unlock` protect a cell's child store. When the lock is active, adding, removing, sorting, or deleting descendants fails for that store and for every store below it.
- `cep_data_lock` / `cep_data_unlock` guard the payload. While locked, VALUE/DATA buffers refuse writes, HANDLE/STREAM adapters won't accept map/write operations, and higher layers treat the subtree as read-only.
- Locks propagate upward: acquiring a lock checks every ancestor first, and mutation helpers refuse to run if any ancestor is already locked. The bitfields in `cepStore` and `cepData` record both the lock state and the owning cell.
- Structural helpers (`cep_store_add_child`, `cep_store_delete_children_hard`, soft/hard child removal, dictionary/sort reindexing) now short-circuit when a store in scope is locked. Payload writers (`cep_cell_update`, stream write/map/unmap) do the same for data locks.
- `cep_cell_delete*` obey locks too: soft or hard deletes of data, children, or stores back off if the affected subtree is frozen, preserving append-only semantics.

## Global Q&A
- **Do locks stop reads?** No. Traversal, serialization, and read-only mapping still work; only structural or payload mutations are blocked.
- **Can I nest locks?** Yes. You can lock a parent and then a child, but the second call will fail until the parent is unlocked—locks freeze whole subtrees.
- **What happens if I try to write while locked?** The helper returns `false`/`NULL`, and stream write/map helpers emit error journal entries instead of committing changes.
- **How do locks interact with immutable subtrees?** Immutability wins. Once `cep_cell_set_immutable` (or the recursive seal helper) runs, the branch ignores mutation requests regardless of lock state; the writable bits stay cleared so lock calls simply short-circuit with the usual `false`/`NULL` response.
