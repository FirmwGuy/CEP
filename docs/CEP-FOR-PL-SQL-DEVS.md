# CEP for Traditional PL/SQL Developers (L0–L2 Mental Model)

## Introduction
- If you think in classes/instances, tables/rows, methods/overrides, or fat dictionaries (Python/JS), CEP may look alien at first. The trick is to see how familiar capabilities show up differently across Layer 0 (kernel), Layer 1 (bonds & coherence), and Layer 2 (ecology of flows).
- This guide maps common programming/DB concepts to CEP’s primitives so you can recognize the same power—and more—expressed through cells, links, contexts, and enzymes.

## Technical Details

### 1) Instance, Class, and Structure
- Familiar: object instance; struct/record; row in a table.
- In CEP:
  - Instance → a `cepCell` in a hierarchy (often under a dictionary). Identity comes from its `cepDT` (domain/tag) and its position among siblings.
  - Structure → children under the cell using a chosen store (list/dictionary/catalog). You decide per-parent storage: insertion order, name-indexed, or functional ordering.
  - Fat dicts → cells with dictionary stores are the canonical “unstructured” objects; you can mix arbitrary fields and evolve shape over time.

### 2) Relations, Foreign Keys, and Graphs
- Familiar: foreign keys; many-to-many join tables; referential integrity.
- In CEP:
  - Link cells (`CEP_TYPE_LINK`) are typed edges between cells. `cep_link_set` updates backlinks (shadowing) on the target, so the target knows who points at it.
  - Safety: finalizing a target with backlinks asserts; you remove or retarget linkers first. Soft-delete propagates a `targetDead` hint to linkers.
  - L1 Bonds: pair relations (`bond:*` with `a`/`b` roles) and n‑ary contexts (`ctx:*` with role‑named links). Contexts generalize join rows to multi‑party facts.
  - L1 Facets: implied sub‑relations written explicitly, so queries don’t depend on inference.

### 3) Methods, Triggers, and Overriding
- Familiar: methods with before/after hooks; overriding; triggers in SQL.
- In CEP:
  - Enzymes are the executable units. They react to impulses (signals) scheduled across deterministic heartbeats.
  - Cell‑bound enzymes (see `docs/L0_KERNEL/CELL-BOUND-ENZYME-BINDINGS.md`) attach to cells, aggregate across ancestors, and deduplicate per impulse.
  - “Override” → layering and precedence: bindings collected along the tree resolve into an agenda; you can stage before/after behavior by ordering and dependency edges.
  - “Triggers” → impulses emitted on write; enzymes subscribed by target/signal run next beat, with full journaling.

### 4) Inheritance and Composition
- Familiar: subclass extends base; mixins/decorators; middleware chains.
- In CEP:
  - Composition via hierarchy and bonds. Behaviors layer by attaching multiple enzymes to the same region of the tree—each focuses on a concern.
  - Reuse via contexts and facets: the same context can emit standard facets consumed by many enzymes downstream.
  - Instead of a single method override point, CEP builds a small execution ecology where multiple small enzymes cooperate in a stable order.

### 5) Transactions, History, and Idempotency
- Familiar: ACID transactions; commit log; upsert/idempotent operations.
- In CEP:
  - Beats are the commit boundary. Outputs from beat N appear at beat N+1, giving deterministic ordering and replayability.
  - Append‑only semantics and tombstones preserve history. Mutations are modeled as new facts with timestamps; helpers enforce idempotency by design. See `docs/L0_KERNEL/APPEND-ONLY-AND-IDEMPOTENCY.md`.
  - Journaling and serialization capture exact bytes sent/received for audit and replay.

### 6) Querying and Views
- Familiar: SELECTs, joins, views/materialized views.
- In CEP:
  - L0 traversal: children iteration and name/index lookups; link resolution (`cep_link_pull`) yields canonical targets.
  - L1 structure: bonds and contexts turn joins into first‑class facts; many “views” are explicit cells maintained by enzymes.
  - Looking ahead: L3 “perspectives” organize cells into read‑optimized shapes; but even at L1/L2, most reads are simple graph walks and dictionary lookups.

### 7) Schema and Evolution
- Familiar: migrations; evolving table schemas; feature flags.
- In CEP:
  - Cells evolve organically: dictionary fields can be added without central schema changes.
  - L1+ can document rich types as regular cells (schemas) linked from data (see `docs/L0_KERNEL/NATIVE-TYPES.md`).
  - Governance and reforms (L4) formalize change control for larger systems while keeping history intact.

### 8) Concrete Mappings at a Glance
- Object instance → a cell; its fields → child cells.
- Foreign key → a link child; referential integrity → shadowing and finalize checks.
- Many‑to‑many row → a bond/context cell with role‑named link children.
- Before/after hooks → ordered enzymes bound to the same region; agenda resolves per beat.
- Override → precedence via binding union and dependency/ordering, not class method replacement.
- Upsert/idempotency → append‑only with guards; idempotent writes enforced by beat and hashing policies.
- View/materialization → enzyme‑maintained cells (facets/perspectives) derived from sources.

### 9) Minimal Code Sketch
```c
#include "src/l0_kernel/cep_cell.h"

void add_can_edit(cepCell* root, cepCell* actor, cepCell* object) {
    cepDT* B_CAN_EDIT = CEP_DTAW("CEP", "bond_caned");
    cepDT* ROLE_ENTRY = CEP_DTAW("CEP", "role_entry");
    cepDT* ROLE_A     = CEP_DTAW("CEP", "role_a");
    cepDT* ROLE_B     = CEP_DTAW("CEP", "role_b");

    cepCell* can_edit = cep_dict_add_dictionary(root, B_CAN_EDIT, ROLE_ENTRY, CEP_STORAGE_RED_BLACK_T);
    (void)cep_dict_add_link(can_edit, ROLE_A, actor);
    (void)cep_dict_add_link(can_edit, ROLE_B, object);
}
```
- Links normalize and update backlinks; reads resolve via `cep_link_pull`.

### 10) Where to Dive Next
- L0 cells, links, and shadowing: `docs/L0_KERNEL/LINKS-AND-SHADOWING.md`
- Beats, impulses, and enzymes: `docs/L0_KERNEL/HEARTBEAT-AND-ENZYMES.md`
- Append‑only and idempotency: `docs/L0_KERNEL/APPEND-ONLY-AND-IDEMPOTENCY.md`
- L1 bonds, contexts, and example: `docs/L1_BONDS/OVERVIEW.md`, `docs/L1_BONDS/BONDS-AND-CONTEXTS.md`, `docs/L1_BONDS/EXAMPLE-EDIT-CONTEXT.md`
- Conceptual overview: `docs/CEP.md`

## Q&A
- Isn’t this just a graph database?
  - CEP uses graphs, but adds deterministic beats, explicit execution (enzymes), and a story of coherence and governance across layers.

- Where’s the “class definition” for my cells?
  - You don’t need one at L0. Use L1 schema cells if you want a declared structure, and attach them by link. The kernel remains agnostic and predictable.

- How do I do a join?
  - Model the relationship as a bond/context at write time. Reads follow links and use those bond/context cells directly—no ad‑hoc join needed.

- How do I override behavior for a subtree?
  - Bind enzymes at the subtree root. Binding union/dedup plus dependency ordering gives you predictable before/after effects without global overrides.

- What about transactions?
  - Beats are your commit boundary. Work is staged and becomes visible deterministically on the next beat, with full journaling.
