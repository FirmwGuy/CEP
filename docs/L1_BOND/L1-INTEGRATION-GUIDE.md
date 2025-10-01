# L1 Bond Layer: Integration & Interop Guide

## Introduction
This guide walks through the practical steps for wiring the bond layer into your heartbeat loops, tools, and importers. The focus is on what works today so you can build against a stable contract.

## Technical Details
### Bring-up checklist
1. **Bootstrap the kernel** – run `cep_heartbeat_bootstrap` (or `cep_heartbeat_configure`) so the root directories exist.
2. **Initialise Layer 1** – call `cep_init_l1(&config, registry)` once. Pass `ensure_directories=true` unless you already created the `/data/CEP/CEP/L1/*` and `/bonds/*` nodes yourself.
3. **Install facet handlers** – register your facet enzymes with `cep_facet_register`. The registry is empty after `cep_init_l1`.
4. **Schedule maintenance** – invoke `cep_tick_l1` near the end of every beat to drain facet queues and prune adjacency mirrors.

### Working with the API
- **Beings** – Resolve or create identity cards via `cep_being_claim`. The function accepts optional label/kind/external-id strings and a metadata dictionary to clone. Cache the returned `cepBeingHandle` if you need the revision timestamp for later verification.
- **Bonds** – Call `cep_bond_upsert` after both participants are known. Ensure the `role_a` and `role_b` cells you pass are the `cepCell*` pointers returned by `cep_being_claim`; anything outside the beings dictionary is rejected.
- **Contexts** – Build `cepContextSpec` arrays with pointers to being cells, facet tag pointers, and optional metadata. After `cep_context_upsert` runs you will see the hash entry under `/contexts`, placeholder facet records, and queue entries ready for dispatch.
- **Facets** – Register each `(facet_tag, context_tag)` pair with the enzyme that will materialise it. Inside your enzyme, write to the paths passed by `cep_facet_dispatch`; return `CEP_ENZYME_SUCCESS` once the record is complete, or `CEP_ENZYME_RETRY` to keep the queue entry pending.

### Syncing external systems
- **Replay first** – When you ingest historical data, drive it through the public APIs inside a heartbeat so adjacency and facet queues stay coherent.
- **Handle ownership** – If another service is authoritative, resolve being IDs to `cepDT` names (or load them through the namepool) and let the bond/context helpers produce the deterministic hash keys for you.
- **Serialisation** – Use the kernel serializer on the namespace roots you care about (`/data/CEP/CEP/L1`, `/bonds/adjacency`, `/bonds/facet_queue`). Avoid hand-editing the JSON-like fragments inside those directories; the helpers expect the exact layout they produce.

### Guardrails and observability
- Layer 1 does not ship policy enforcement yet. Add your own validation in the enzymes that call the API (for example, check role combinations before calling `cep_bond_upsert`).
- To observe health, inspect `/bonds/facet_queue` after `cep_tick_l1`; items stuck in `pending`, `fatal`, or `missing` state deserve follow-up. You can surface the same counts via a monitoring enzyme.
- Adjacency mirrors reflect current relationships only. If you delete a being, run `cep_tick_l1` to prune its bucket once all entries vanish.

## Q&A
- **Do I need to hold heartbeat locks?** Yes. Call these helpers from inside an enzyme or controlled section where the heartbeat runtime is active; they assume deterministic sequencing.
- **Can I write directly into `/data/CEP/CEP/L1`?** Not safely. Bypass the helpers and you will miss adjacency updates and facet queue entries.
- **What happens if `ensure_directories` is false and the folders are missing?** `cep_init_l1` returns `CEP_L1_ERR_STATE`. Either create the directories beforehand or allow it to do so once.
- **How do I run Layer 1 without facets?** Simply avoid registering any facet tags. `cep_context_upsert` still writes placeholder facet records and queue entries; without registrations `cep_tick_l1` marks them `missing`, giving you a visible reminder to install handlers later.
