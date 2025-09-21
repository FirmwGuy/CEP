Append-Only And Idempotency In CEP Cells

Introduction
CEP stores information the way a careful archivist files letters: every note and every folder is kept in the order it was received, with timestamps that tell you exactly when each item arrived. Nothing is ever overwritten or shuffled out of place, so you can always open the cabinet and see both the present state and any prior version. Whether the cell holds a single piece of data, behaves like a directory of children, or mixes both, the goal is the same—add new material without disturbing the trail that brought us here.

Technical Overview
CEP implements append-only storage through two complementary timelines: `cepData` for payload bytes and `cepStore` for the structure of children. Each timeline carries its own `cepOpCount` timestamp so the engine can answer "What did this look like at timestamp T?" without rebuilding history.

Timeline Building Blocks
- `cepData`
  - Represents a single materialized value (bytes, handles, or streams) and carries a `modified` stamped when the value became current.
  - Links to the previous value through `data->past`, forming a backward chain ordered from newest to oldest.
- `cepStore`
  - Describes the live view of a cell's children and holds its own `modified` for structural changes.
  - Keeps historical layout snapshots *only* when the indexing technique changes (for example, converting an insertion-ordered list into a dictionary). Regular inserts, appends, and soft deletions rely on per-cell timestamps instead of cloning the entire store.
- `cepStoreNode`
  - Represents one child within a store, bundles child metadata (name, ordering key, state), and is stamped with the `modified` at which the child entered or changed state.
  - Populates `node->past` with the prior snapshot for the same child identity, enabling per-entry rewind across insert/update/delete sequences.

Data-Only Cells
- The head `cepData` records the current payload alongside its `modified`.
- Traversing history for timestamp T involves following `data->past` until the chain finds the newest node whose `modified` is ≤ T.
- Because nodes are only appended, equality checks between the requested payload and the head enforce idempotency: if the incoming payload matches the current head, no new node is added.

Children-Only Cells
- Directory-style cells leverage the appended timestamps on each child to replay history. Only indexing changes append a snapshot of the layout (with pointers to the original children) to `store->past`; ordinary inserts/deletes keep the sibling list untouched and let timestamp filtering reconstruct earlier views.
- Each child snapshot threads its own `node->past` chain, so renames, replacements, and soft deletions can be revisited without mutating older nodes.
- Deleting a child via the normal APIs records the removal in history while keeping a clone for time-travel. The explicit "hard" deletion helper is the only path that tears the clone down immediately.

Cells With Data And Children
- These cells maintain both timelines in parallel: `cepData` for the payload and `cepStore` for child structure.
- State reconstruction first resolves the child set by replaying `cepStore` against the requested timestamp, then reads the payload chain. Because data and structure have separate timestamps, a query can combine the latest payload at timestamp T with the appropriate child set even if the two were updated at different moments.
- Idempotency applies independently—duplicate payloads do not create new `cepData` nodes, and repeated structural updates that do not change the effective child set do not append new `cepStore` snapshots.

timestamp-Aware Traversal
- To answer time-travel queries, the engine compares the target timestamp against the timestamp on each node rather than scanning entire history.
- A child is considered present at timestamp T when its `node->modified` ≤ T and no later deletion timestamp precedes T. The same rule applies to payloads using the `cepData` chain.
- This approach keeps lookups O(1) for the current state and O(k) for stepping back k historical updates, while guaranteeing that all past states remain reconstructable.

Idempotency Guarantees
- Content equality: CEP compares the incoming payload (bytes plus relevant metadata such as encoding or resource identity) against the head `cepData`. Matching content means the update is discarded as a no-op.
- Structural equality: CEP compares the incoming child against the live entry. If nothing changes, the operation is discarded as a no-op (supported today for insertion-order and dictionary updates).
- Stable ordering: Because directories are append-only, the ordering function is evaluated only when the child first appears or when the catalog explicitly changes sorting rules. Replay relies on the `store->past` snapshots emitted during indexing changes together with each child's `node->past` chain.
- Operation keys: Higher layers may store idempotency keys alongside heads to short-circuit duplicate operations before deep comparisons are needed.

Implementation Notes
- Always stamp both `cepData` and `cepStore` with the `cepOpCount` that made them current; history queries rely on those timestamps to gate traversal.
- Prefer soft deletions: use the regular remove helpers to detach a child without destroying its contents. Call the `*_hard` variants only when the child and all descendants should be reclaimed immediately; soft removes now preserve history clones automatically.
- Garbage-collection note: the `*_hard` deleters are reserved for GC, after link/shadow tracking has proven no live references remain. Under that gate, reclaiming the branch does not break historical traversal.
- Only indexing changes push a snapshot into `store->past` (storing references to the original child cells); other structural edits keep the existing layout and depend on timestamps plus soft-delete markers.
- Keep comparisons local: only the head of the relevant chain must be inspected to decide idempotency; deep history traversal is optional and on-demand.
- Catalog-oriented stores update both `store->past` and each child's `node->past` whenever the user-facing sorting key changes so past ordering remains derivable.

Q&A
- What problem does append-only solve?
  - It guarantees that every historical state stays available while still making the latest view fast to read, which is essential for auditing and recovery.
- How do timestamps help with history?
  - The per-node `cepOpCount` lets CEP answer "What existed at timestamp T?" by simple comparisons instead of replaying every change from the beginning.
- Does keeping deleted items slow the system down?
  - No. Current reads go straight to the head nodes. Historical traversal only walks as far back as the timestamp you requested.
- Can directories lose their ordering after deletions?
  - No. Inserts respect the original ordering key, and deletions mark nodes without moving anything, so sorted directories remain stable across time.
- How are catalog re-sorts handled?
  - Switching the sort function appends a new `cepStore` snapshot and chains the previous layout through `store->past`; the child entries in that snapshot link back through their `node->past` chain.
- What happens if the same update arrives twice?
  - Idempotency checks compare it to the head state; if nothing changes, CEP skips the append so history only grows when the effective state changes.
