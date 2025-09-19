Append-Only And Idempotency In CEP Cells

Introduction
CEP stores information the way a careful archivist files letters: every note and every folder is kept in the order it was received, with timestamps that tell you exactly when each item arrived. Nothing is ever overwritten or shuffled out of place, so you can always open the cabinet and see both the present state and any prior version. Whether the cell holds a single piece of data, behaves like a directory of children, or mixes both, the goal is the same—add new material without disturbing the trail that brought us here.

Technical Overview
CEP implements append-only storage through two complementary timelines: `cepData` for payload bytes and `cepStore` for the structure of children. Each timeline carries its own `cepHeartbeat` timestamp so the engine can answer "What did this look like at heartbeat H?" without rebuilding history.

Timeline Building Blocks
- `cepData`
  - Represents a single materialized value (bytes, handles, or streams) and carries a `modified` stamped when the value became current.
  - Links to the previous value through `data->past`, forming a backward chain ordered from newest to oldest.
- `cepStore`
  - Describes the live view of a cell's children and holds its own `modified` for structural changes.
  - Maintains a `store->past` pointer to the prior structural snapshot, letting the engine rewind the child set to any heartbeat.
- `cepStoreNode`
  - Represents one child within a store, bundles child metadata (name, ordering key, state), and is stamped with the `modified` at which the child entered or changed state.
  - Links through `node->past` so name reuse, deletions, or catalog re-ordering can be backtracked without mutating old nodes.

Data-Only Cells
- The head `cepData` records the current payload alongside its `modified`.
- Traversing history for heartbeat H involves following `data->past` until the chain finds the newest node whose `modified` is ≤ H.
- Because nodes are only appended, equality checks between the requested payload and the head enforce idempotency: if the incoming payload matches the current head, no new node is added.

Children-Only Cells
- Directory-style cells use `cepStore` to capture the membership of their children at each structural change.
- A read at heartbeat H selects the newest store whose `store->modified` ≤ H, then iterates its child nodes, skipping those whose `node->modified` is greater than H or that were marked deleted before H.
- Sorted directories remain stable because inserts append new nodes while preserving the precomputed ordering key. Deletions mark a node as inactive but keep the node in place so older heartbeats still see it.
- Catalogs that allow user-driven sorting keep an additional backtracking chain: `store->past` references the previous ordering snapshot, and each `node->past` preserves the earlier position or index. Replaying those links lets the engine rebuild the catalog order that was effective at heartbeat H without re-sorting.

Cells With Data And Children
- These cells maintain both timelines in parallel: `cepData` for the payload and `cepStore` for child structure.
- State reconstruction first resolves the child set by replaying `cepStore` against the requested heartbeat, then reads the payload chain. Because data and structure have separate timestamps, a query can combine the latest payload at heartbeat H with the appropriate child set even if the two were updated at different moments.
- Idempotency applies independently—duplicate payloads do not create new `cepData` nodes, and repeated structural updates that do not change the effective child set do not append new `cepStore` snapshots.

Heartbeat-Aware Traversal
- To answer time-travel queries, the engine compares the target heartbeat against the timestamp on each node rather than scanning entire history.
- A child is considered present at heartbeat H when its `node->modified` ≤ H and no later deletion heartbeat precedes H. The same rule applies to payloads using the `cepData` chain.
- This approach keeps lookups O(1) for the current state and O(k) for stepping back k historical updates, while guaranteeing that all past states remain reconstructable.

Idempotency Guarantees
- Content equality: CEP compares the incoming payload (bytes plus relevant metadata such as encoding or resource identity) against the head `cepData`. Matching content means the update is discarded as a no-op.
- Structural equality: For children, CEP compares the intended mutation against the latest live node for that identity (name, ordering key, or auto-id). If the mutation would recreate the same child state, the update is skipped.
- Stable ordering: Because directories are append-only, the ordering function is evaluated only when the child first appears or when the catalog explicitly changes sorting rules. Replay uses `store->past` and `node->past` to revisit earlier orderings without reprocessing live data.
- Operation keys: Higher layers may store idempotency keys alongside heads to short-circuit duplicate operations before deep comparisons are needed.

Implementation Notes
- Always stamp both `cepData` and `cepStore` with the `cepHeartbeat` that made them current; history queries rely on those timestamps to gate traversal.
- Mark deletions by setting the child state on the existing node and appending a new `cepStore` snapshot if the structural view changes. Never free or repurpose nodes that already belong to history.
- Keep comparisons local: only the head of the relevant chain must be inspected to decide idempotency; deep history traversal is optional and on-demand.
- Ensure catalog-oriented stores update both `store->past` and `node->past` whenever the user-facing sorting key changes so past ordering remains derivable.

Q&A
- What problem does append-only solve?
  - It guarantees that every historical state stays available while still making the latest view fast to read, which is essential for auditing and recovery.
- How do timestamps help with history?
  - The per-node `cepHeartbeat` lets CEP answer "What existed at heartbeat H?" by simple comparisons instead of replaying every change from the beginning.
- Does keeping deleted items slow the system down?
  - No. Current reads go straight to the head nodes. Historical traversal only walks as far back as the heartbeat you requested.
- Can directories lose their ordering after deletions?
  - No. Inserts respect the original ordering key, and deletions mark nodes without moving anything, so sorted directories remain stable across time.
- How are catalog re-sorts handled?
  - When a user changes the sort criteria, CEP records a new `cepStore` snapshot and threads the previous layout through `store->past` and `node->past`, enabling backtracking to any prior index order.
- What happens if the same update arrives twice?
  - Idempotency checks compare it to the head state; if nothing changes, CEP skips the append so history only grows when the effective state changes.
