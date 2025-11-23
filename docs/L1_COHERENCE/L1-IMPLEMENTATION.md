# Layer 1 Coherence — Implementation Notes

## Introduction
Layer 1 gives CEP durable structure: beings, bonds, contexts, facets, adjacency, and a light pipeline/runtime scaffold on top of the Layer 0 kernel. This note lists the concrete roots, helpers, and signals you can rely on today.

## Technical Details
- **Roots and schema**  
  - `/data/coh/beings|bonds|contexts|facets|debts` hold authoritative coherence state.  
  - `/data/coh/adj/by_being|by_ctx|by_facet` are recomputable adjacency mirrors.  
  - `/data/coh/schema/ctx_rules/<kind>` stores per-context rules; `roles/` and `facets/` entries may mark `required=1`.  
  - Companion: see `docs/L1_COHERENCE/L1-USAGE.md` for step-by-step workflows and API calls.
- **Canonical IDs and helpers**  
  - Beings use `<kind>:<external_id>` keys; bonds use `bond:<kind>:<from>:<to>`; contexts sort bindings into `ctx:<kind>|role=being[@bond]|…`; facets use `facet:<kind>:<ctx>:<subject>:<label>`; debts use `debt:<kind>:<ctx_or_bond>:<requirement>` (with `ctx_kind` lineage).  
  - Add helpers ensure dictionary stores exist, intern IDs through the namepool, and attach append-only debt history.
- **Closure and debts**  
  - Context creation records bindings under `roles/` and updates adjacency mirrors by being/context.  
  - Closure loads optional context rules: validates allowed/required roles, materializes facets, records debts for missing roles/facets/beings, and emits CEI (`coh.debt.new`, `coh.debt.resolved`, `coh.role.invalid`, `coh.closure.fail`). Required rules set `required=1`; debts keep `ctx_kind` for lineage.  
  - Hydration uses the L0 helper with optional snapshot-only mode; cross-branch reads emit `coh.cross_read` with Decision Cells when allowed; failures emit `coh.hydrate.fail`.
- **Adjacency mirrors**  
  - `by_being` tracks contexts, bonds, facets per being; `by_ctx` tracks participants and facets; `by_facet` indexes facets by kind. Mirrors are derived and safe to rebuild via closure/sweep.
- **Pipelines and coherence**  
  - Pipeline definitions under `/data/flow/pipelines` store `pipeline_id`, `rev` (default 1), optional `ver`, `owner`, `province`, and `max_hops`.  
  - Stages live under `stages/`; edges under `edges/` with `source/target` text. Validation rejects self-loops, missing endpoints, and max-hop overflow.  
  - `cep_l1_pipeline_bind_coherence` creates beings for pipeline/stages, bonds `has_stage`, and pipeline-edge contexts (`pipeline_edge` with roles `pipeline`, `from_stage`, `to_stage`). Owner/province beings get `owned_by` and `in_province` bonds.
- **Runtime scaffolding**  
  - Runs are recorded under `/data/flow/runtime/runs/<run>` with pipeline metadata; per-stage state lives in `stages/<stage>/`. Pipeline stages/edges are mirrored into runs to pre-fill `fan_in` expectations.  
  - Fan-in counters (`fan_in`, `fan_seen`) and `ready` flags gate dispatch; triggers append deterministic entries; per-stage metrics/annotations live locally; pipeline + stage metrics accumulate instead of overwrite.  
  - `cep_l1_runtime_dispatch_if_ready` emits pipeline-aware impulses when a stage is ready, records `paused=1` + CEI `flow.dispatch.blocked` when pause/rollback gates dispatch, and fan-outs along recorded edges (auto-triggers downstream stages, bumping hop indexes). Missing pipeline metadata emits `flow.pipeline.missing_metadata`.
- **Federation helpers**  
  - Invoke helpers attach pipeline metadata to requests and emit CEI `sec.pipeline.reject` on preflight or submit failure; missing pipeline IDs are rejected with `flow.pipeline.missing_metadata`.  
  - Mount helper sets pipeline metadata on link/mirror mounts so security/diagnostics can attribute traffic and now fails fast if pipeline/stage IDs cannot be interned.
- **Pack lifecycle**  
  - `cep_l1_pack_bootstrap` ensures schema roots, registers the closure enzyme (`coh:close`), and marks pack readiness.  
  - `op/coh_sweep` runs closure over all contexts for maintenance; append-only debts preserve history.

## Q&A
- **Where should new L1 docs go?**  
  Under `docs/L1_COHERENCE/`, following intro → technical → Q&A. Update the orientation guide when adding/removing files.
- **How are required roles/facets enforced?**  
  Context rules under `ctx_rules/<kind>/roles|facets` with `required=1` create debts when missing and mark debts with `ctx_kind`; CEI emits `coh.role.invalid`/`coh.closure.fail` accordingly.
- **How do I rebuild adjacency safely?**  
  Trigger `op/coh_sweep` or re-run closure; mirrors are derived and can be rebuilt without mutating authoritative ledgers.
- **What pipeline validation exists?**  
  Stage existence, edge endpoints/self-loop guards, `max_hops` limit, and owner/province provenance; revision defaults to 1 unless set. Security pipeline preflight stays in L0 packs.
