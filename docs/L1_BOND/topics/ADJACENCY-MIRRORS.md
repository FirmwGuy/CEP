# L1 Topic: Adjacency Mirrors and Summaries

## Introduction
Adjacency mirrors are the quick-glance indexes that keep relationships browseable without scanning the full bond ledger. They live inside Layer 1's transient workspace and let UIs and services answer "who is connected to this being?" instantly.

## Technical Details
### Mirror layout
- Mirrors live under `/bonds/adjacency/being/<id>/<key>` where `<id>` is the owning being's deterministic name.
- Each entry stores a short summary payload containing the partner's tag, hash key, and optional label strings for display.
- Entries share the kernel's append-only semantics; replacing a summary adds a new child instead of rewriting the old one.

### Update pipeline
- `cep_bond_upsert` (and its helpers) compare the freshly computed summary with the current head. If nothing changes, the mirror stays untouched.
- When a bond is retired, the heartbeat loop marks the matching adjacency node as inactive. A later sweep prunes the tombstone once both sides agree the edge is gone.
- High-volume updates batch through the heartbeat so a single impulse can stage multiple mirror diffs before the agenda commits them.

### Reading mirrors safely
- Clients may read mirrors directly for dashboards or heuristics, but mutations must still go through the bond APIs.
- When you need strong consistency, pair a mirror read with the authoritative bond entry and compare timestamps. A mismatch signals that a follow-up sweep is still in flight.

## Q&A
- **Do mirrors survive restarts?** They live in normal cells, so yes. The append-only log persists them; heartbeat maintenance cleans stale ones after recovery.
- **What if a mirror gets corrupted?** Rebuild it by replaying the underlying bond records through the heartbeat; the diff logic recreates missing entries deterministically.
- **Can I add custom summary fields?** Extend the summary payload by adding children such as `meta/` values. Just keep them compact to preserve cache locality.
- **How do mirrors behave with soft deletes?** Soft-deleted bonds remain visible but flagged; the heartbeat prunes them only after both participants are archived.
