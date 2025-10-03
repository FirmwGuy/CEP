# L1 Coherence: Algorithms & Enzymes

The coherence layer runs as a set of heartbeat-driven routines. You can think of each routine as a careful librarian: one files new entries, another double-checks context closure, another updates the card catalog. This document explains how those routines work so you know what to expect when the heartbeat turns.

If you want to customize behavior or reason about performance, this is the place to start.

---

## Technical Details

### Enzyme pipeline
1. **`coh_ing_be`** – Validates `id` and `kind`, copies free-form attributes, and records provenance. Locks the target ledger entry while updating, then hashes the content for history tracking.
2. **`coh_ing_bo`** – Ensures `src` and `dst` links resolve, writes `type` and `directed` flags, and reuses existing ledger nodes to stay idempotent. Both endpoints are treated as hard requirements.
3. **`coh_ing_ctx`** – Builds or updates context nodes, enforces 11-character word rules on role names and facet identifiers, attaches links, and records debts for required-but-missing facets.
4. **`coh_closure`** – Mirrors satisfied facets into `/data/coh/facet`, persists decisions for multi-candidate matches, and refreshes the debt tree. It relies on the namepool to build stable `{ctx}:{facet}` keys.
5. **`coh_index`** – Recomputes secondary indexes: beings by kind, bonds by endpoint tuple, contexts by type, facets by context. Each bucket currently appends links; TODO markers in the code highlight where stale entries will be cleared in future work.
6. **`coh_adj`** – Rebuilds transient adjacency mirrors under `/tmp/coh/adj` by copying bonds and contexts into near-neighbor buckets. Like the indexes, TODO markers note that stale entries still need pruning before final polish.

### Locking discipline
- Ledger modifications take store locks around dictionary updates and data locks when mutating values. Locks are released as soon as the mutation completes to keep contention low.
- Closure and indexing work under coarse-grained store locks to provide snapshot semantics. Because the heartbeat is deterministic, the order of locks is consistent across runs, preventing replay divergence.

### Word-ID enforcement
- Static tags rely on `CEP_DTAW("CEP", "tag")`. Runtime values use `cep_text_to_word` and reject inputs above 11 characters. Helper routines such as `cep_l1_word_dt_guard` report failures back into the originating intent’s `outcome` field.
- Roles and facet types are validated before being copied into ledger nodes. If a client sends an invalid name, the entire intent is marked as an error and the ledger remains unchanged.

### Decision and debt management
- Decisions prefer previously recorded choices. When multiple links could satisfy a facet, the closure enzyme consults `/data/coh/decision` and picks the stored target if available. Otherwise it uses the first candidate, records it, and stays with that choice on replays.
- Debts record missing required facets. The structure is a nested dictionary (`ctx` → `facet` → metadata) so future cleanup can remove empty branches without scanning the entire tree.
- Both systems attach the originating intent as a parent link so auditors can trace why a decision or debt exists.

### Transient structures
- Adjacency mirrors maintain three dictionaries per being bucket: `out_bonds`, `in_bonds`, and `ctx_by_role`. Currently the enzyme only appends links; TODO comments flag where stale entries should be removed once change detection lands.
- Because they live under `/tmp`, deleting the whole subtree is safe. The next heartbeat rebuilds whatever is required for the touched entities.

---

## Q&A

**Q: Why does the pipeline enforce this specific enzyme order?**  
A: Each step feeds the next—contexts rely on beings and bonds, closure relies on contexts, indexes rely on closure, and adjacency relies on indexes. Changing the order would break deterministic replay.

**Q: Are the TODO comments blocking correctness?**  
A: No. They only affect cache hygiene. Ledgers remain authoritative, and stale index or adjacency entries simply point to items that may no longer match the latest state.

**Q: Can I replace the storage engines used by the ledgers?**  
A: Yes. The bootstrap routine currently uses red-black trees for determinism, but you can reindex or swap engines later as long as you respect append-only semantics.

**Q: How expensive is closure?**  
A: It scales with the number of facets per context. Each facet requires a lookup, optional decision ledger check, and potential debt update. Use facets judiciously and monitor the debt tree to catch hot spots.

