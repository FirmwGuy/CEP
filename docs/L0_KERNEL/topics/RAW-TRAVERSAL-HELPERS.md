# L0 Topic: Raw Traversal Helpers (Seeing Every Child)

Immutable sealing and digesting sometimes fail because we only walk the "visible" portion of a cell tree. Staged branches keep their payloads veiled, and the current helpers politely skip them. To make sealing reliable we need an explicit way to iterate every stored child, even if it is veiled, deleted, or otherwise invisible to regular lookups.

## Technical Design

### Proposed API surface

- `cepCell* cep_cell_first_all(const cepCell* parent);`
- `cepCell* cep_cell_next_all(const cepCell* parent, const cepCell* current);`
- `cepCell* cep_cell_last_all(const cepCell* parent);`
- `cepCell* cep_cell_prev_all(const cepCell* parent, const cepCell* current);`
- `cepCell* cep_cell_find_by_name_all(const cepCell* parent, const cepDT* name);`

Each helper returns the raw stored child (resolved from links) without applying snapshot or visibility filters. The functions mirror the signatures and usage style of the existing `cep_cell_first/next/last/prev` helpers so that callers can switch between the "visible" and "raw" views with minimal friction.

### Behaviour guarantees

1. **No visibility filtering** – all stored children are yielded regardless of veils, deletion flags, or snapshot semantics. This is implemented by delegating to the internal store traversal routines (`store_*_child_internal`) so that even hash-table and red-black-tree stores expose their internal ordering.
2. **Link resolution** – callers receive resolved `cepCell*` pointers. The helpers follow links at the top level (the parent), and return children exactly as stored (callers may further resolve links on child entries if needed, matching the current `cep_cell_first/next` behaviour).
3. **Stable ordering contract** – iteration order matches the underlying store's logical ordering; callers must not assume that order corresponds to snapshot-visible sequencing. Immutable digesting continues to sort children by name before hashing, so differing internal orders across stores do not jeopardize determinism.
4. **Error handling** – passing a void/NULL parent returns `NULL` (matching existing helpers). If the parent has no store, the helpers yield `NULL`. All functions assert that the parent is a normal cell. Name lookups return the stored entry (veiled or not) so callers can revive or inspect it before re-exposing it.

### Intended call sites

- `cep_branch_seal_immutable_impl()` flips the immutable bit for every descendant. By using `cep_cell_*_all()` the recursion no longer misses veiled payloads.
- `cep_cell_digest_walk()` enumerates children through `*_all()` before sorting them for hashing. This removes the need for the current fallback loop that mixes internal store helpers into the digest logic.
- Future maintenance: any subsystem that must inspect the physical contents of a store (e.g., diagnostics, low-level replication) can opt-in to the raw traversal family, making intent explicit.

### Candidate upgrade sites

While surveying `src/l0_kernel`, the following routines surfaced as likely beneficiaries once the helpers exist:

- `cep_branch_seal_immutable_impl()` – currently mixes `store_first_child_internal()` into recursive sealing.
- `cep_cell_digest_walk()` – relies on both visible iteration and a direct `_internal` fallback to ensure all children hash.
- `cep_cell_mark_subtree_veiled()` and `cep_cell_unveil_subtree()` – mark unveiled state on every stored child and currently chain directly to `store_first_child()`. Switching to the raw helpers would make it explicit that veiled/deleted nodes still need veiling updates.
- `cep_cell_clone_branch()`/`cep_cell_merge` style routines (any path that calls `store_first_child` inside internal-only transformations) should be re-evaluated once the helpers land to confirm whether the raw variants provide clearer intent.

This inventory will guide the follow-up tasks that adopt `*_all` after API approval.

### Implementation notes

- The helpers live alongside the existing traversal functions in `cep_cell.c`/`cep_cell.h`.
- For `cep_cell_last_all`/`cep_cell_prev_all` we add `store_last_child_internal` and `store_prev_child_internal` wrappers so that hash-table and red-black tree stores retain parity with the forward iteration logic.
- Documentation in the public header points out that these helpers deliberately bypass veil/deletion semantics and should be used sparingly.
- No behavioural change is introduced until callers switch to the new API.

### Current adoption

- `cep_ops_history_root()` now relies on `cep_cell_find_by_name_all()` to revive the `history` dictionary when a rollback leaves it veiled. The helper re-establishes `store->owner`, writable flags, and auto-id state before any append occurs.
- `ensure_root_dictionary()` and `cep_namepool_ensure_dictionary()` use the `*_all` family to resurrect previously veiled dictionaries (for example `/sys/state` or `/sys/namepool`) instead of accidentally allocating replacements.
- Organ binding paths (`cep_l0_organ_resolve_root_from_segments`) switched to `cep_cell_find_by_name_all()` so they never grab RB-tree payload nodes; callers always receive fully resolved, unveiled cells.

## Global Q&A

**Q: Why not keep calling `store_first_child_internal` directly?**  
A: Because it leaks storage internals into higher-level code. Naming the intent (`*_all`) keeps the responsibility obvious and reduces the chance of mix-ups with the visible helpers.

**Q: Do we need to change existing tests before landing the helpers?**  
A: No. Tests will keep using the visible helpers unless they need raw traversal. Once sealing/digesting moves to the `*_all` family we will rerun the existing suites to verify behaviour; no new tests are required unless we expose the helpers publicly.

**Q: Could these helpers break snapshot-aware features?**  
A: They do not affect existing snapshot helpers. Callers must explicitly choose the raw variants. Documentation will highlight that they bypass visibility rules so feature code continues to rely on the snapshot-aware paths by default.
