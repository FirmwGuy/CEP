# L1 Coherence: Algorithms & Enzymes

The coherence layer runs as a set of heartbeat-driven routines. You can think of each routine as a careful librarian: one files new entries, another double-checks context closure, another updates the card catalog. This document explains how those routines work so you know what to expect when the heartbeat turns.

If you want to customize behavior or reason about performance, this is the place to start.

---

## Technical Details

### Enzyme pipeline
1. **`coh_ing_be`** – Validates `id` and `kind`, copies free-form attributes, and records provenance. Locks the target ledger entry while updating, then hashes the content for history tracking.
2. **`coh_ing_bo`** – Ensures `src` and `dst` links resolve, writes `type` and `directed` flags, and reuses existing ledger nodes to stay idempotent. Both endpoints are treated as hard requirements.
3. **`coh_ing_ctx`** – Builds or updates context nodes, validates role/facet identifiers via the namepool, attaches links, and records debts for required-but-missing facets.
4. **`coh_closure`** – Mirrors satisfied facets into `/data/coh/facet`, persists decisions for multi-candidate matches, and refreshes the debt tree. It relies on the namepool to build stable `{ctx}:{facet}` keys.
5. **`coh_index`** – Recomputes secondary indexes: beings by kind, bonds by endpoint tuple, contexts by type, facets by context. Before relinking, it purges outdated entries so the catalog always reflects the latest ledger facts.
6. **`coh_adj`** – Rebuilds transient adjacency mirrors under `/tmp/coh/adj` by copying bonds and contexts into near-neighbor buckets. Old references are removed first, so caches never accumulate stale links when identities move.

### Locking discipline
- Ledger modifications take store locks around dictionary updates and data locks when mutating values. Locks are released as soon as the mutation completes to keep contention low.
- Closure and indexing work under coarse-grained store locks to provide snapshot semantics. Because the heartbeat is deterministic, the order of locks is consistent across runs, preventing replay divergence.

### Identifier handling
- Static tags still lean on `CEP_DTAW("CEP", "tag")`, but runtime identifiers now flow through the namepool. The ingest helpers try to compact short strings into CEP words/acronyms and store everything else as `CEP_NAMING_REFERENCE` entries; inputs are limited to 256 bytes by the namepool implementation.
- Producers can call `cep_l1_compose_identifier()` / `cep_l1_tokens_to_dt()` to normalize multi-token IDs (lowercase + `:` delimiter) before intents ever hit the inbox, keeping ledger keys consistent across collaborating systems.
- Numeric-only identifiers survive intact (the namepool emits numeric IDs) and glob hints are honored when callers pre-intern pattern references.
- Roles and facet names must resolve to a valid word, acronym, reference, or numeric ID. If a client supplies an empty or malformed string, the intent is marked invalid and no ledger mutation happens.

### Decision and debt management
- Decisions prefer previously recorded choices. When multiple links could satisfy a facet, the closure enzyme consults `/data/coh/decision` and picks the stored target if available. Otherwise it uses the first candidate, records it, and stays with that choice on replays.
- Debts record missing required facets. The structure is a nested dictionary (`ctx` → `facet` → metadata) so future cleanup can remove empty branches without scanning the entire tree.
- Both systems attach the originating intent as a parent link so auditors can trace why a decision or debt exists.

### Transient structures
- Adjacency mirrors maintain three dictionaries per being bucket: `out_bonds`, `in_bonds`, and `ctx_by_role`. Each rebuild clears existing references to the touched bond or context before recreating the links.
- Because they live under `/tmp`, deleting the whole subtree is safe. The next heartbeat rebuilds whatever is required for the touched entities.

---

## Q&A

**Q: Why does the pipeline enforce this specific enzyme order?**  
A: Each step feeds the next—contexts rely on beings and bonds, closure relies on contexts, indexes rely on closure, and adjacency relies on indexes. Changing the order would break deterministic replay.

**Q: What if an entity changes kind or endpoints between beats?**  
A: Indexes and adjacency buckets remove stale entries before relinking, so the caches always match the current ledger state. Ledgers remain the source of truth, but the mirrors now stay clean automatically.

**Q: Can I replace the storage engines used by the ledgers?**  
A: Yes. The bootstrap routine currently uses red-black trees for determinism, but you can reindex or swap engines later as long as you respect append-only semantics.

**Q: How expensive is closure?**  
A: It scales with the number of facets per context. Each facet requires a lookup, optional decision ledger check, and potential debt update. Use facets judiciously and monitor the debt tree to catch hot spots.
