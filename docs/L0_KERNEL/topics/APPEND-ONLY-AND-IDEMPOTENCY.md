# L0 Topic: Append-Only and Idempotency in Cells

## Introduction
CEP stores information the way a careful archivist files letters: every note and every folder is kept in the order it was received, with timestamps that tell you exactly when each item arrived. Nothing is ever overwritten or shuffled out of place, so you can always open the cabinet and see both the present state and any prior version. Whether the cell holds a single piece of data, behaves like a directory of children, or mixes both, the goal is the same—add new material without disturbing the trail that brought us here.

## Technical Overview
CEP implements append-only storage through two complementary timelines: `cepData` for payload bytes and `cepStore` for the structure of children. Each timeline carries its own `cepOpCount` timestamp so the engine can answer "What did this look like at timestamp T?" without rebuilding history.

### Timeline Building Blocks
- `cepData`
  - Represents a single materialized value (bytes, handles, or streams) and carries a `modified` stamped when the value became current.
  - Links to the previous value through `data->past`, forming a backward chain ordered from newest to oldest.
- `cepStore`
  - Describes the live view of a cell's children and holds its own `modified` for structural changes.
  - Keeps historical layout snapshots *only* when the indexing technique changes (for example, converting an insertion-ordered list into a dictionary). Regular inserts, appends, and soft deletions rely on per-cell timestamps instead of cloning the entire store.
- `cepStoreNode`
  - Represents one snapshot of the store layout, bundles child metadata (name, ordering key, state), and is stamped with the `modified` at which the snapshot was captured.
  - Tracks previous layouts through `node->past` only when the store is reindexed; individual children currently rely on their timestamps rather than keeping their own history chain.

### Data-Only Cells
- The head `cepData` records the current payload alongside its `modified`.
- Traversing history for timestamp T involves following `data->past` until the chain finds the newest node whose `modified` is ≤ T.
- Because nodes are only appended, equality checks between the requested payload and the head enforce idempotency: if the incoming payload matches the current head, no new node is added.

### Children-Only Cells
- Directory-style cells use the timestamps on each living child together with the store snapshot that was current when a structural reindex happened. Only indexing changes append a snapshot of the layout (referencing the existing children) to `store->past`; ordinary inserts/deletes keep the sibling list untouched and let timestamp filtering reconstruct earlier views.
- Per-child nodes do not maintain their own `past` chain yet; the history that is available today comes from the store snapshot taken at the time of a reindex plus the timestamps stamped on the live child instances.
- Deleting a child via the normal APIs stamps the child as deleted so that time-travel skips it. The explicit "hard" deletion helper is the only path that tears the branch down immediately.

### Cells with Data and Children
- These cells maintain both timelines in parallel: `cepData` for the payload and `cepStore` for child structure.
- State reconstruction first resolves the child set by replaying `cepStore` against the requested timestamp, then reads the payload chain. Because data and structure have separate timestamps, a query can combine the latest payload at timestamp T with the appropriate child set even if the two were updated at different moments.
- Idempotency applies independently—duplicate payloads do not create new `cepData` nodes, and repeated structural updates that do not change the effective child set do not append new `cepStore` snapshots.

### Timestamp-Aware Traversal
- To answer time-travel queries, the engine compares the target timestamp against the lifetime window recorded on each cell (`created` ≤ T < `deleted`). Payloads and child stores mirror that rule with their own `created`/`deleted` fields when present.
- A child is considered present at timestamp T when the cell’s lifetime window contains T and its parent store is also alive at T. Payloads (and store layouts) reuse the same rule, so data-only or children-only cells still replay correctly.
- This approach keeps lookups O(1) for the current state and O(k) for stepping back k historical updates, while guaranteeing that all past states remain reconstructable.

### Idempotency Guarantees
- Content equality: CEP compares the incoming payload (bytes plus relevant metadata such as encoding or resource identity) against the head `cepData`. Matching content means the update is discarded as a no-op.
- Structural equality: CEP compares the incoming child against the live entry. If nothing changes, the operation is discarded as a no-op (supported today for insertion-order and dictionary updates).
- Stable ordering: Because directories are append-only, the ordering function is evaluated only when the child first appears or when the catalog explicitly changes sorting rules. Replay relies on the `store->past` snapshots emitted during indexing changes.
- Operation keys: Higher layers may store idempotency keys alongside heads to short-circuit duplicate operations before deep comparisons are needed.

### Implementation Notes
- Always stamp both `cepData` and `cepStore` with the `cepOpCount` that made them current; history queries rely on those timestamps to gate payload and structural replay.
- Normal cells also stamp `created`/`deleted` on the `cepCell` itself so history filters can reason about lifetimes even before payloads or stores exist.
- Prefer soft deletions: use the regular remove helpers to detach a child without destroying its contents. Call the `*_hard` variants only when the child and all descendants should be reclaimed immediately; soft removes now preserve history clones automatically.
- Garbage-collection note: the `*_hard` deleters are reserved for GC, after link/shadow tracking has proven no live references remain. Under that gate, reclaiming the branch does not break historical traversal.
- Only indexing changes push a snapshot into `store->past` (storing references to the original child cells); other structural edits keep the existing layout and depend on timestamps plus soft-delete markers.
- Keep comparisons local: only the head of the relevant chain must be inspected to decide idempotency; deep history traversal is optional and on-demand.
- Catalog-oriented stores update `store->past` whenever the user-facing sorting key changes so past ordering remains derivable; child nodes do not yet keep individual `past` chains.

### Immutable subtrees and canonical digests
- `cep_cell_set_immutable` flips a node into read-only mode while the cell is still veiled (or floating) so the branch appears sealed as soon as it becomes visible. The helper resolves links, checks that the node has not been unveiled yet, sets the `immutable` bit, and marks any attached payload/store as non-writable.
- `cep_branch_seal_immutable(root, {.recursive = true})` walks an entire staged subtree, sealing every normal node before commit. Use it inside a veil (for example, a transaction root) to guarantee the branch is immutable on first visibility.
- Once sealed, mutation helpers (`cep_cell_update`, `cep_cell_add`, `cep_cell_remove_hard`, `cep_cell_delete`, etc.) short-circuit: they return `NULL`/`false` instead of mutating, leaving the append-only history untouched. Attempting to rename or reparent an immutable node is also ignored. A TODO placeholder remains for surfacing `err.immutable_cell` diagnostics once the new error channel lands.
- Immutable children do *not* inherit automatic cleanup from their parents; delete the parent before sealing or plan to keep the branch resident. Future GC paths may add explicit teardown hooks.
- `cep_cell_digest(node, CEP_DIGEST_SHA256, out)` produces a canonical SHA-256 fingerprint for a sealed subtree (name, payload, store layout, and child digests in name order). Workflows can capture this digest before and after a change to prove the structure stayed untouched.

## Q&A
- What problem does append-only solve?
  - It guarantees that every historical state stays available while still making the latest view fast to read, which is essential for auditing and recovery.
- How do timestamps help with history?
  - The per-node `cepOpCount` lets CEP answer "What existed at timestamp T?" by simple comparisons instead of replaying every change from the beginning.
- Does keeping deleted items slow the system down?
  - No. Current reads go straight to the head nodes. Historical traversal only walks as far back as the timestamp you requested.
- Can directories lose their ordering after deletions?
  - No. Inserts respect the original ordering key, and deletions mark nodes without moving anything, so sorted directories remain stable across time.
- How are catalog re-sorts handled?
  - Switching the sort function appends a new `cepStore` snapshot and chains the previous layout through `store->past`.
- What happens if the same update arrives twice?
  - Idempotency checks compare it to the head state; if nothing changes, CEP skips the append so history only grows when the effective state changes.
