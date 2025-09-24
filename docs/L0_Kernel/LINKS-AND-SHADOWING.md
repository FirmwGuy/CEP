Links And Shadowing In CEP Cells

Introduction
- Think of a link as a shortcut to another item. Instead of copying the original, a link points to it. CEP keeps these shortcuts safe: when you follow a link, you always reach the real item (never another shortcut), and the real item knows who is linking to it so nothing breaks.
- Shadowing is how CEP tracks “who points to me.” When several links target the same cell, CEP maintains a small structure inside the target listing those links. This turns an otherwise tree‑shaped hierarchy into a graph while preserving safe navigation and backtracking.

Technical Overview
- Link cells
  - A link is a cell with type `LINK` that references a target cell.
  - Non‑interlinkage policy: if a link points to another link, resolution follows the chain until a non‑link cell is found. Accessors use `cep_link_pull(...)` so operations act on the ultimate target.
  - Practical effect: user code reading data or children of a link transparently reads the target’s data/children; the link behaves like an alias.

- Backtracking and “no broken links”
  - After resolution, the target cell records a back‑reference to the linking cell. This enables backtracking (from target to its linkers) and ensures the target cannot be finalized while still referenced.
  - Invariants:
    - Finalization asserts that a cell is not shadowed (no backlinks present); this prevents broken links.
    - Links always resolve to a non‑link target at access time (no chains observed by callers).

- Shadow structure layout
  - The target cell keeps backlink(s) in one of two places depending on whether it has children:
    - Target without children: backlinks stored in the target cell’s union as either a single `linked` pointer or a `shadow` aggregate (multiple links).
    - Target with children: backlinks stored in the target’s `store` union as either a single `linked` pointer or a `shadow` aggregate.
  - The metacell’s `shadowing` bits summarize state: none, single, or multiple.
  - The `shadow` aggregate contains a small header and an array of `cepCell*` linking cells.

- Link lifecycle
  - Create: initialize a cell with type `LINK`, then set its target (`cep_link_set`). The target’s shadowing metadata/backlinks update accordingly.
  - Resolve: callers use `cep_link_pull` implicitly through public APIs; resolution yields the non‑link target. Optionally, implementations may normalize link pointers to the final target during resolution for faster subsequent access.
  - Update: changing a link’s target first removes its backlink from the previous target (if any), then adds it to the new target.
  - Remove: deleting a link removes its backlink from the target. Deleting a still‑shadowed target is prevented by invariant checks.


- Tombstones and `targetDead`
  - When a target cell transitions to a tombstone state (soft delete), every shadow entry updates the linking cell’s `targetDead` flag so callers can see that their shortcut points at deleted content.
  - Clearing a tombstone (or retargeting a link) clears the flag. Hard deletes remain forbidden while backlinks exist—the flag is only advisory; the invariant that a finalised cell has no shadows still holds.
- Graph semantics
  - The base hierarchy remains tree‑like by parent/child relations. Links introduce additional edges from link cells to their targets, forming a directed acyclic graph in normal use (cycles are disallowed by policy).
  - Policy notes:
    - Links to root are disallowed for now.
    - Cycles (link A → B, B → A or via longer chains) are invalid and must be prevented by callers or higher layers. Resolution follows chains; cycles would be detected and rejected.

Developer Notes
- Access patterns
  - Public cell APIs that read data or traverse children first resolve links (`cep_link_pull`) so the behavior matches the target cell’s semantics.
  - When inspecting linkage, use shadowing metadata on the target to find all linkers.

- Storage placement
  - Single backlink uses a direct pointer (`linked`) to avoid heap overhead.
  - Multiple backlinks promote to a `shadow` aggregate. Demotion (back to single/none) can occur when links are removed.

- Safety guarantees (same‑process scope)
  - Backlinks are in‑memory pointers within the same process space; this guarantees no broken references under normal operation.
  - Finalization of a target asserts `shadowing == NONE` to prevent orphaned links.

Q&A
- Why force links to resolve to non‑link targets?
  - It simplifies reasoning and ensures consistent behavior: a link behaves like the target it represents, not like a chain of aliases.

- How do I find who links to a cell?
  - Check the target’s shadowing state. If `SINGLE`, follow `linked`. If `MULTIPLE`, iterate the `shadow` aggregate.

- Can links create cycles?
  - Policy is “no cycles.” Chains are resolved to a non‑link target, and implementations should reject attempts that would create cycles.

- What prevents broken links if a target is deleted?
  - Targets cannot be finalized while shadowed; deletion asserts fail if backlinks remain. Remove links first, then finalize the target.

- Do links change identity or naming of the target?
  - No. Links add a reference edge; the target’s own name, data, and children remain authoritative.

