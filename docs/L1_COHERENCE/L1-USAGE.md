# Layer 1 Coherence — Usage Guide

## Introduction
Layer 1 gives you a reliable way to describe identities and relationships (beings, bonds, contexts, facets, debts) and to route pipeline work with a small runtime scaffold. Use this guide as the “how do I do it?” reference.

## Quick map of what’s available
- Coherence storage under `/data/coh/**` with adjacency mirrors and rule-driven closure.
- Pipeline definitions under `/data/flow/pipelines/**` and runtime scaffolding under `/data/flow/runtime/**`.
- Federation helpers that carry pipeline metadata and emit CEI on preflight/metadata failures.
- Opt-in tests: `CEP_L1_TESTS=1`.

## How to work with coherence
- **Beings and bonds**  
  1) Add beings: `cep_l1_coh_add_being(layout, kind, external_id, &out)` → key `<kind>:<external_id>`.  
  2) Link them: `cep_l1_coh_add_bond(layout, bond_kind, from_kind, from_external, to_kind, to_external, note)`. Bonds are append-only; adjacency mirrors (`/data/coh/adj/by_being|by_ctx|by_facet`) are derived and can be rebuilt with `op/coh_sweep`.

- **Contexts, facets, debts**  
  1) Prepare bindings (`cepL1CohBinding[]`).  
  2) Add context: `cep_l1_coh_add_context(layout, ctx_kind, note, bindings, count, out_ctx)`; IDs are canonical (sorted role → being → bond).  
  3) Closure reads `/data/coh/schema/ctx_rules/<kind>/roles|facets` to validate roles, create facets, and record debts when required data is missing. Debts live under `/data/coh/debts/**` with append-only history and `ctx_kind` lineage.  
  CEI you may see: `coh.debt.new`, `coh.debt.resolved`, `coh.role.invalid`, `coh.rule.invalid`, `coh.closure.fail`, `coh.hydrate.fail`, `coh.cross_read`.

## How to set up pipelines
- Ensure a definition: `cep_l1_pipeline_ensure(flow_pipelines_root, pipeline_id, meta, &layout)` (stores `pipeline_id`, revision >= 1, version, owner, province, optional `max_hops` ceiling; rejects revision regressions).
- Add stages: `cep_l1_pipeline_stage_stub(&layout, stage_id, &stage)`.
- Wire edges: `cep_l1_pipeline_add_edge(&layout, from_stage, to_stage, note)`; rejects self-loops and honors `max_hops`.
- Bind to coherence: `cep_l1_pipeline_bind_coherence(schema_layout, &layout)` creates beings for pipelines/stages plus `has_stage` bonds and `pipeline_edge` contexts (`pipeline`, `from_stage`, `to_stage` roles).

## How to run pipelines
- Record a run: `cep_l1_runtime_record_run(flow_runs_root, pipeline_id, dag_run_id, state_tag, metadata, &run)` (mirrors stages/edges into the run to seed `fan_in`).
- Configure fan-in: `cep_l1_runtime_configure_stage_fanin(run, stage_id, expected)`. Add triggers: `cep_l1_runtime_record_trigger(...)`. Mark ready explicitly if needed: `cep_l1_runtime_mark_stage_ready(...)`.
- Dispatch: `cep_l1_runtime_dispatch_if_ready(run, stage_id, signal_path, target_path, metadata, qos)`  
  - Emits pipeline-aware impulses.  
  - Blocks if pause/rollback gating is active (sets `/paused=1`, emits `flow.dispatch.blocked`).  
  - Auto fan-outs along recorded edges, bumping hop indexes and triggering downstream stages.  
  - Emits `flow.pipeline.missing_metadata` when required metadata is absent.  
  - Metrics accumulate via `cep_l1_runtime_record_metric` / `cep_l1_runtime_record_stage_metric`; annotations append via `cep_l1_runtime_add_annotation` / `_add_stage_annotation`.

## Federation
- Invoke: `cep_l1_fed_prepare_request` + `cep_l1_fed_request_submit` require pipeline metadata; failures emit `sec.pipeline.reject` or `flow.pipeline.missing_metadata`.
- Link/Mirror: `cep_l1_fed_mount_attach_pipeline` stamps pipeline metadata on mounts and fails fast when IDs cannot be interned.

## Hydration
- Use `cep_l1_coh_hydrate_safe` in enzymes to hydrate with optional snapshot view and Decision Cell enforcement for cross-branch reads; cross-branch is default-deny, emits `coh.hydrate.fail` on policy denials, and emits `coh.cross_read` when explicitly allowed and hydrated.

## Q&A
- **Add a new required role/facet?** Set `required=1` under `/data/coh/schema/ctx_rules/<ctx_kind>/roles|facets` and rerun closure (`op/coh_sweep`).
- **When is a stage ready?** When `fan_seen >= fan_in` or after `cep_l1_runtime_mark_stage_ready`. Fan-out dispatch clears `ready` on the source and triggers targets.
- **Where do pipeline gating CEI land?** `flow.dispatch.blocked` for pause/rollback gating; `flow.pipeline.missing_metadata` for missing metadata; `sec.pipeline.reject` for preflight failures.
- **Rebuild adjacency?** Run `op/coh_sweep`; mirrors are derived. Authoritative data stays under `/data/coh/{beings,bonds,contexts,facets,debts}`.
- **Can I skip pipeline metadata on federation?** No; invoke/attach helpers require it and emit CEI when absent.
