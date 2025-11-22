# L0 Topic: Pipelines and Hydration

Pipelines at Layer 0 are light: the kernel does **not** own pipeline graphs or learning logic. It simply carries two bits of metadata—`pipeline_id` and `stage_id`—through impulses, OPS, federation, and CEI so higher layers can line up their graphs, security approvals, and observability. This guide explains how that metadata moves and how to hydrate off-RAM cells safely inside pipeline-aware enzymes.

## What “pipeline” means in L0
- **Metadata only.** L0 records `pipeline_id`, `stage_id`, optional `dag_run_id`, and `hop_index` on envelopes and contexts. It never interprets graphs or runs schedulers beyond existing heartbeat/OPS machinery.
- **Security hook.** Enclave policy (`sig_sec/pipeline_preflight`) uses the same IDs to approve cross-enclave stages. Missing or mismatched IDs cause `sec.pipeline.reject` denials.
- **Observability.** CEI facts, OPS envelopes/watchers, async I/O entries, and federation frames all echo the same pipeline block so tooling can group events by pipeline/stage without reverse-engineering payloads.

## How pipeline metadata flows
- **Impulses and enzymes.** When an impulse carries a pipeline block, the heartbeat copies it into the enzyme context (`cep_pipeline_meta_t`). Enzymes can tag CEI facts or runtime cells with the same IDs.
- **OPS and watchers.** `/rt/ops/<oid>/envelope/pipeline` holds the IDs; watchers copy the block so continuations stay tied to the same pipeline/run.
- **Federation.** Invoke requests encode the pipeline block; validators check `pipeline_id`/`stage_id` against approved specs before sending. Encode paths also parse text fields so DAG/run numbers survive even if stored as `val/text`.
- **CEI.** Security CEI topics (`sec.limit.hit`, `sec.pipeline.reject`, etc.) include `origin/pipeline/*` so denies and budget hits are traceable.

## Hydrating off-RAM cells inside a pipeline
Enzymes often need cells that have been evicted to CPS/CAS. Use `cep_cell_hydrate_for_enzyme()` with:

- **Reference:** `cep_cell_ref_t` naming a branch (defaults to the enzyme branch when zero) plus a path DT or canonical cell id (`is_canonical=true`).
- **Options:** `cep_hydrate_opts_t` controls view and safety:
  - View: `CEP_HYDRATE_VIEW_LIVE` (may read dirty RAM if policy allows) vs. `CEP_HYDRATE_VIEW_SNAPSHOT_RO` (CPS-only, beat ≤ N-1).
  - Policy: `allow_cross_branch`, `require_decision_cell`.
  - Budgets: `max_depth`, `max_meta_bytes`, `max_payload_bytes`.
  - Locks/prefetch: `lock_ancestors_ro`, `hydrate_children`, `hydrate_payload`.
- **Policy guardrails:** `cep_branch_policy_check_read()` runs first, honoring `allow_volatile_reads`, snapshot-only policies, and cross-branch rules. Volatile cross-reads can require Decision Cells (`cep_decision_cell_record_cross_branch()` / replay) so Compute stays deterministic.
- **Results:** telemetry flags show whether data came from CPS/CAS, plus byte counters. Budget overruns or CAS gaps fail the call without publishing partial state. Once revived, store-bound enzyme bindings behave exactly as if the cell had stayed in RAM.

## Quick recipes
- **Tag a local stage:** set `envelope/pipeline = {pipeline_id, stage_id}` on an impulse; the enzyme sees the IDs in `ctx->pipeline` and can log CEI with `origin/pipeline`.
- **Remote invoke with policy:** include the pipeline block in the federation request; if the `pipeline_id` or `stage_id` isn’t approved for that edge, validation emits `sec.pipeline.reject` and refuses the send.
- **Hydrate safely across branches:** set `allow_cross_branch=true`, `require_decision_cell=true`, and choose `view=CEP_HYDRATE_VIEW_SNAPSHOT_RO` if you must avoid volatile reads. Expect a policy error when the branch forbids it.

## Regression coverage
- `test_fed_invoke_pipeline_metadata_roundtrip` proves encode/decode of the pipeline block (id, stage, run, hop) and that the invoke handler receives it.
- Federation/security tests assert CEI pipeline decorations (`sec.limit.hit`, `sec.pipeline.reject`) so telemetry stays replayable.

## Q&A
- **What if a remote invoke omits `pipeline_id`?** Cross-enclave validation fails, emits `sec.pipeline.reject`, and refuses the edge. Intra-enclave calls can run but won’t carry pipeline metadata into telemetry.
- **Do bindings survive hydration?** Yes. After `cep_cell_hydrate_for_enzyme()` revives the canonical cell, direct and inherited enzyme bindings remain intact.
- **How are `dag_run_id` / `hop_index` handled when stored as text?** Encode paths parse numeric text fields so the pipeline block carries numbers even if the request stored them as `val/text`.
- **Can I block volatile reads entirely?** Set `allow_cross_branch=false` or `view=CEP_HYDRATE_VIEW_SNAPSHOT_RO`; the policy guard returns a policy error instead of hydrating. Cross-branch reads that are allowed but risky log Decision Cells for replay. 
