# L1 Bond Layer: Roadmap

## Introduction
Layer 1 has its foundations in place—topology setup, beings, bonds, contexts, facets, and a minimal maintenance loop. This roadmap summarises what is done, what is in active development, and what is still aspirational so adopters can plan ahead.

## Technical Details
### Capability snapshot
| Area | Status | In place | Next focus |
| --- | --- | --- | --- |
| Namespace bootstrap | ✅ Done | `cep_init_l1` provisions `/data/CEP/CEP/L1/*` and the runtime `/bonds/*` workspace. | 📌 Allow callers to swap storage policies (e.g., hashed adjacency) without forking helpers. |
| Being lifecycle | ✅ Shipping | `cep_being_claim` deduplicates by `cepDT` name and overwrites label/kind/external metadata atomically. | ⚙️ Add merge helpers and validation hooks for duplicate external IDs. |
| Bond ledger | ✅ Shipping | `cep_bond_upsert` maintains hashed pair records and refreshes adjacency mirrors. | ⚙️ Surface diff-friendly summaries (old/new values) for audit trails. |
| Context engine | ✅ Shipping | `cep_context_upsert` records simplices, mirrors adjacency, and enqueues facets. | ⚙️ Support contexts whose participants live outside the beings dictionary (e.g., nested contexts). |
| Facet orchestration | ⚙️ Partial | Registry + dispatch + basic state transitions; `cep_tick_l1` drains queues. | ⚙️ Honour `cepFacetPolicy` settings and track attempt counters/backoff. |
| Checkpoints & retries | 💤 Idle | Folder structure exists; the tick loop only prunes empties. | 📌 Define the retry payload format and integrate with the heartbeat journal. |
| Telemetry & tooling | 💤 Planned | No dedicated counters yet; tests assert layout and idempotency. | 📌 Publish stats from `cep_tick_l1` (queue depth, completions) and expose them through perspectives or logging. |

### Current foundations
- Deterministic hashing for bonds and contexts keeps keys repeatable across replays.
- Beings, bonds, contexts, and facets all piggyback on standard kernel stores; no special serializers are required.
- Unit coverage in `src/test/l1_bond` exercises core paths, including metadata cloning and adjacency updates.
- The maintenance loop is cheap: a single pass over facet queues, adjacency, and checkpoints per beat.

### Active focus areas
- Tighten validation in the public APIs (role cardinality, duplicate external IDs, facet registration mismatches).
- Capture facet execution metrics (attempt count, last error) so operators can reason about stuck entries.
- Decide how higher layers will consume adjacency mirrors (direct reads, materialised perspectives, or exported diffs).

### Watch list
- Cross-runtime synchronisation for adjacency mirrors once deployments span multiple shards.
- Migration helpers for renaming `cepDT` identifiers without breaking hash stability.
- Tooling that replay facet queues after cold starts without manual intervention.

## Q&A
- **Will hash formulas change?** Not without versioning. Any future change will ship with migration helpers or compatibility shims.
- **Is it safe to rely on the current data layout?** Yes. The helpers create standard dictionaries and lists; existing tools can inspect them without custom readers.
- **How often will this roadmap update?** Expect refreshes alongside major releases or when a capability graduates from experiment to default.
- **Where should feature requests land?** File them under the Layer 1 tracker so priorities here stay aligned with real usage.
