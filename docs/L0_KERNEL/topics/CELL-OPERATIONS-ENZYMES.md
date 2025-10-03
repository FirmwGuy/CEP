# Cell Operation Enzymes

The cell operation enzymes let schedulers apply familiar tree edits (add, update, delete, move, and clone) without poking at the L0 cell API directly. They give cadence scripts a single signal family (`sig_cell`) for routine maintenance so product engineers can express intent ("place this template here") instead of worrying about memory ownership rules or store edge cases.

---

## Technical Details

### Registry lifecycle
- `cep_cell_operations_register()` ensures the five descriptors are present exactly once per registry. A small side table keeps the registry pointer and baseline size so repeated calls stay idempotent even if other subsystems add entries later.
- Registration populates each descriptor under `sig_cell/op_*` with the appropriate `enz_*` name and `cell.*` label. The helper resists re-entrancy by pinning the active registry while it mutates entries.

### Request envelope layout
- Every impulse targeting these enzymes points `target` at a request dictionary. The dictionary uses `role_parent`, `role_subject`, `role_source`, and `role_templ` links to supply the working cells.
- Optional behaviour switches ride in linked children tagged `arg_deep`, `arg_prepend`, and `arg_pos`. Booleans are read from `VALUE` payloads, while `arg_pos` expects an 8-byte little-endian `VALUE` representing the insertion index.
- The helpers always resolve links with `cep_link_pull()` so callers can hand off proxies or prior agenda captures.

### Operation semantics
- **Add (`enz_add`)** clones a template or source cell, performing a deep copy when `arg_deep` evaluates truthy, and inserts it under the resolved parent. Packed-array stores honour `arg_pos`; insertion-ordered stores treat `arg_prepend` as a fast path for front or back appends.
- **Update (`enz_upd`)** copies the payload from `role_source` into `role_subject`. `VALUE` payloads reuse the existing buffer, `DATA` payloads allocate a fresh buffer, and any other datatype yields a fatal outcome so handles or streams stay opt-in.
- **Delete (`enz_del`)** removes the resolved subject unless it is the root. The enzyme calls `cep_cell_delete_hard()` which clears both payload and structural resources.
- **Move (`enz_mov`)** clones the subject (deep by default), inserts the clone into the new parent using the same placement logic as add, then removes the original node via `cep_cell_remove_hard()` to preserve deletion history.
- **Clone (`enz_cln`)** behaves like add, but pulls the blueprint from `role_source` without touching the original node.

### Supporting helpers
- `cep_cell_enzyme_compute_context()` guards `arg_pos` against stores that are not insertion-indexed and clamps offsets to the store size, ensuring out-of-range requests still land at the tail.
- Temporary clones are disposed with `cep_cell_enzyme_free_clone()`, which finalizes non-void cells before freeing memory, avoiding store leaks when an insertion fails mid-flight.
- Boolean and integer extractors validate both datatype and payload width so malformed requests fail fast instead of corrupting the target nodes.

---

## Q&A
- **When should I call the register helper?** During registry bootstrap, right after `cep_enzyme_registry_init()`. It is cheap to invoke multiple times and will no-op once the descriptors are present.
- **Do I need to provide both subject and source links?** Only for update and move. Add and clone accept either `role_template` or `role_source`, while delete only cares about `role_subject`.
- **What happens if I omit `arg_pos` on a list store?** The helper treats the absence as "append" for insertion-ordered stores and "use the implicit store policy" for others, so you get the default ordering.
- **Can I update handle or stream payloads through these enzymes?** Not yet. The update enzyme rejects non-`VALUE` and non-`DATA` types so callers opt in to higher-level stream management instead of losing references silently.
