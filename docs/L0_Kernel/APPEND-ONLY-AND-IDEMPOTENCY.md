Append-Only And Idempotency In CEP Cells

Introduction
- CEP cells are like folders or items in a well‑organized cabinet. Some cells hold a single value (like a note card), and some cells can also hold other cells inside (like a folder with labeled papers). When something changes, CEP does not overwrite or erase history; instead, it adds the new version in a way that preserves the previous ones. This makes it easy to see what the latest value is while still keeping a trail of what came before.
- “Append‑only” means changes are recorded by adding new entries rather than editing or deleting old ones. “Idempotency” means repeating the same change has the same effect as doing it once, so accidental repeats don’t cause damage or duplicate states.

Technical Overview
- Single‑value cells (no children):
  - These cells keep their history as a single linked list per cell, using the `next` member of `cepData` to point to the previous content in history.
  - The current value sits at the head; `data->next` points to the immediate previous version; that one’s `next` points further back, and so on.
  - Rationale: most runtime needs only require the latest or the N‑1 value; full history is rarely needed at once. This layout makes the latest fast to access while keeping older versions reachable on demand.

- Cells with children (lists, dictionaries, trees):
  - Adds/edits of children are naturally append‑only: the parent simply incorporates the new or updated child without needing to rewrite past structure.
  - Deletions are logical: when a child is removed, the child remains in place but is marked as deleted. This preserves history and avoids reshuffling siblings.
  - Named children in dictionaries: a subtle case arises if a named child is deleted and a new child with the same name is later added. In that scenario, the original child receives a “re‑incarnated” flag so that CEP can maintain the continuity of “live” history for that name across incarnations.
  - Implementation detail: CEP uses the `next` member of the `cepStore` structure as needed to thread together the incarnations so that lookups see the correct current child while older, deleted incarnations remain part of the history chain.

Data‑Only Cells: Historical Chain
- Head (current): latest `cepData` instance.
- Back‑link: `cepData->next` points to the immediate previous `cepData` snapshot.
- Traversal: clients that need more than the current value can follow `next` to walk older versions. Most code only touches the head for speed.

Dictionary‑Style Cells: Name Reuse And Re‑Incarnation
- Deleting a named child marks it deleted but leaves it in the parent’s store for history.
- If a new child with the same name is added later:
  - The old child is flagged as “re‑incarnated”.
  - The store uses its `next` linkage to keep both the current incarnation and its prior live history connected.
  - Lookups for “current by name” resolve to the newest live child, while history queries can still reach the older incarnations.

Operational Properties
- Fast “current” access: the latest value or current child is directly reachable without scanning full history.
- Cheap history retention: older versions remain linked without costly rewrites.
- Stable identifiers: children aren’t physically removed; deletion is a state, not an erasure, which helps auditing and time‑travel scenarios.
- Predictable memory growth: history grows only by appended nodes; no in‑place rewrites.

Notes For Implementers
- `cepData->next` is used to chain historical data versions for single‑value cells.
- `cepStore->next` is used to chain store incarnations when a named child is deleted and later re‑added, enabling re‑incarnation semantics.
- Dictionary deletion should mark a child as deleted rather than physically removing it, so that subsequent name re‑use can re‑incarnate correctly.
- Most read paths should fetch the head/current entry first; history traversal should be opt‑in to preserve performance.

Idempotency
- Concept: applying the same logical update one or many times results in the same state as applying it once. This avoids duplicate states when messages are retried or operations race.
- Data‑only cells:
  - Equivalence: two updates are equivalent if their effective payload bytes (plus relevant metadata like `encoding` and `attribute`) are identical. If equivalent to the current head, skip creating a new `cepData` node (no‑op).
- Representation bridging: for `VALUE` vs `DATA`, compare bytewise payload; for `HANDLE`/`STREAM`, compare a stable identity (library id, resource id/path, offset/length, version/ETag). If they denote the same materialized content, treat as idempotent. Any per-tag canonicalization (endianness/encoding) is defined by enzymes/L1+, not by L0.
  - Optional hashing: `cepData.hash` can store a content hash to accelerate equality checks; on collision, verify bytes for correctness.
- Cells with children:
  - Inserts/appends: if the new child matches the current live child with the same identity (e.g., same name in dictionaries, same position/autoid in insertion lists, or same compare‑key in sorted stores) and equal content, treat as a no‑op.
  - Deletions: deleting an already deleted child is a no‑op. The first deletion marks the child deleted but keeps it in history; subsequent deletions do not alter state.
  - Re‑incarnation: when a deleted name is added again, a new live incarnation is created and linked; adding the same incarnation again (same identity and equal content) is a no‑op.
- Operation keys (optional): higher layers can supply idempotency keys with mutation intents. CEP can persist the last‑seen key alongside the head (data or child) and drop duplicates without even comparing content.
- Invariants:
  - No duplicate head states for identical inputs.
  - Replaying the same sequence yields the same final state.
  - History grows only when the effective state changes.

Q&A
- Why not overwrite values in place?
  - Append‑only preserves history for auditing, debugging, and time‑travel while keeping current access fast. Overwrites lose context and complicate concurrent reasoning.

- Does keeping deleted children increase lookup cost?
  - No for current reads: current entries are indexed for direct access. Historical/deleted entries are consulted only when explicitly traversing history.

- What if the same name keeps getting deleted and re‑added?
  - Each re‑addition creates a new live incarnation. Older ones stay linked and marked accordingly. Current reads still resolve to the latest live incarnation.

- How do I read the previous value quickly?
  - From the head `cepData`, follow `data->next` one step to get N‑1. This is O(1) to reach the current and O(k) to step back k versions.

- Is full history ever removed?
  - The model is append‑only by design. Compaction/GC policies, if any, would be explicit and outside the default semantics.

- Where does idempotency come in?
  - Idempotency complements append‑only by ensuring repeated application of the same logical update does not create multiple distinct “new” states. When a new value equals the current head (or a child addition equals the current live child), CEP performs a no‑op instead of appending.

- How does CEP decide if two updates are the same?
- By comparing payload bytes and relevant metadata. For handles/streams, a stable resource identity (e.g., library id + resource id + range + version) is used. A stored hash can speed this up but does not replace equality checks.

- Do idempotent checks slow down writes?
  - Current‑only checks are fast (hash + short‑circuit). Full history is not scanned; idempotency compares against the head state for the targeted identity.

- What about concurrent retries or reordered deliveries?
  - Append‑only makes order explicit in history. Idempotency prevents duplicate heads for the same logical update. Higher layers can supply idempotency keys for strong deduplication in the presence of retries.
