# L1 Bond Layer: A Quick Overview

## Introduction
Layer 1 gives CEP a shared way to talk about people, assets, and the relationships between them. The kernel already handles cells, history, and heartbeats; the bond layer builds on that by offering typed helpers for beings, bonds, contexts, and facets that behave deterministically across replays.

## Technical Details
### Responsibilities today
1. **Bootstrap** – `cep_init_l1` wires the `/data/CEP/CEP/L1/*` dictionaries and the runtime `/bonds/*` workspace so higher layers can rely on a stable tree.
2. **Beings** – `cep_being_claim` returns (or creates) identity cards keyed by a deterministic `cepDT` name and keeps friendly labels, kinds, external IDs, and cloned metadata in one place.
3. **Bonds** – `cep_bond_upsert` records pair relationships, updates role summaries, and mirrors compact adjacency notes beneath `/bonds/adjacency/<being>/<hash>`.
4. **Contexts** – `cep_context_upsert` materialises N-ary simplices whose participants are existing beings, clones metadata, stages adjacency summaries for each participant, and seeds required facets as pending work.
5. **Facets** – `cep_facet_register` and `cep_facet_dispatch` link facet tags to enzyme callbacks; `cep_tick_l1` pulls pending entries from `/bonds/facet_queue` and marks them complete, pending, or failed based on the callback result.

### Storage shape
Durable data lives under `/data/CEP/CEP/L1`:
- `beings/<name>` – dictionary cell that stores `being_label`, `being_kind`, `being_ext`, and an optional `meta/` dictionary cloned from the caller.
- `bonds/<tag>/<hash>` – dictionary containing two role dictionaries (`role_a`, `role_b`) with summary `value` payloads plus optional `bond_label`, `bond_note`, and `meta/` entries.
- `contexts/<tag>/<hash>` – dictionary with one child per role (`role_*`), a `ctx_label` text payload, and cloned metadata. All role targets must live under the beings dictionary.
- `facets/<facet>/<hash>` – dictionary tracking `facet_state` (`pending`, `complete`, `failed`, `fatal`, `missing`) and a `value` that mirrors the context label.

Transient helpers sit under the runtime `/bonds` dictionary:
- `adjacency/<being>/<hash>` – summaries like `ctx_editssn:First Draft` or `bond_caned:user-001` for quick lookups.
- `facet_queue/<facet>/<hash>` – linked-list entries with `value` (context label) and `queue_state` (`pending`, `complete`, `fatal`, `missing`).
- `checkpoints/` – reserved for future retry metadata; the current code only prunes empty shells.

### Public API surface
The exported functions are all in `cep_bond.h` and operate on plain structs so results can be journaled.
- `cep_init_l1(const cepConfig*, cepEnzymeRegistry*)` – prepares topology and resets the facet registry. It does not auto-install enzymes beyond registering the built-in cell operation helpers.
- `cep_being_claim(...)` – ensures a being cell exists, rewrites label/kind/external text when present, and clones metadata dictionaries wholesale.
- `cep_bond_upsert(...)` – validates that both participants live under the beings dictionary, writes summaries, and refreshes adjacency mirrors.
- `cep_context_upsert(...)` – hashes the role tuple, updates per-role summaries, clones metadata, enqueues facets, and mirrors adjacency for every participant.
- `cep_facet_register(...)` – stores the `(facet_tag, source_context_tag) → enzyme` mapping and optional policy.
- `cep_facet_dispatch(...)` – runs the registered enzyme, updates facet/queue state, and copies the queue label onto the facet record.
- `cep_tick_l1(cepHeartbeatRuntime*)` – drains the facet queue (invoking `cep_facet_dispatch`), prunes empty adjacency buckets, and removes empty checkpoint folders.

### Execution flow
1. Callers invoke `cep_being_claim`, `cep_bond_upsert`, or `cep_context_upsert` inside an enzyme or tool that already holds the heartbeat lock.
2. Each helper writes normal cells; the kernel timestamps them so history stays append-only.
3. Facet requirements cause queue entries to appear under `/bonds/facet_queue` and placeholder facet records under `/data/CEP/CEP/L1/facets`.
4. `cep_tick_l1` (usually called near the end of a beat) walks the queue, dispatches registered facet enzymes, marks state, and cleans up completed entries.
5. Adjacency mirrors reflect the current summaries until the owning being is deleted. The prune pass removes empty buckets or buckets whose beings have been hard-finalised.

### Error signalling and replay
- All helpers return `cepL1Result`. `CEP_L1_ERR_ARGUMENT` covers null pointers or invalid roots, `CEP_L1_ERR_STATE` indicates missing topology or facet registrations, and `CEP_L1_ERR_MEMORY` surfaces allocation failures.
- The APIs never mutate caller-managed memory. Handles (`cepBeingHandle`, `cepBondHandle`, `cepContextHandle`) contain the created cell pointer plus its latest timestamp so tooling can detect divergent revisions.
- `cepFacetPolicy` values are stored but not yet consulted; the dispatcher currently only honours the enzyme's return code (`CEP_ENZYME_SUCCESS`, `CEP_ENZYME_RETRY`, `CEP_ENZYME_FATAL`).

## Q&A
- **Does `cep_init_l1` install default enzymes?** Not yet. It only makes sure the directories exist and the internal facet registry is empty. Applications still need to register their own descriptors.
- **How many times can I call the init routine?** It is idempotent. Subsequent calls reuse the cached topology and keep existing data intact.
- **What happens if a facet enzyme is missing?** `cep_facet_dispatch` marks the queue entry as `missing` and leaves the facet record untouched. The queue entry stays in place so operators can diagnose the gap.
- **Do adjacency mirrors keep history?** Mirrors are ordinary dictionaries. `cep_bond_set_text` rewrites their summary value in place, so history consists of the cell revision timestamps rather than one entry per change.
- **Can contexts reference other contexts?** Not with the current API. Role targets must already live under the beings dictionary, so higher layers need to project any context-to-context links through beings or derived facets.
