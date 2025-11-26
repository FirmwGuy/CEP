# Layer 2 Ecology — Implementation Notes

## Introduction
This note distills the Layer 2 ecology pack into the concrete surfaces that exist today and the steps left to harden it. It assumes the Layer 0 kernel is already running and optionally the Layer 1 coherence pack is available for graph/context integrations.

## Technical Details
- **Bootstrap/shutdown**  
  - `cep_l2_bootstrap()` seeds `/data/eco/**` and `/data/learn/**`, registers organs/enzymes idempotently, probes for L1, seeds schemas under `/data/eco/schema/**`, and opens `op/l2_boot` with readiness evidence.  
  - `cep_l2_shutdown()` closes `op/l2_shdn`, stops new flow episodes, marks organisms cancelled/finished, flushes metrics, and never blocks kernel teardown even if the pack never started.
- **Organs, bindings, and schema**  
  - Organs: `org:eco_root`, `org:eco_flows`, `org:eco_runtime`, `org:learn_models` (ct/vl/dt handlers mirroring L1 patterns; deterministic tombstone-safe bindings).  
  - Pack roots: `/data/eco/**` (species, variants, niches, guardians, flows, runtime organisms/history/decisions/metrics) and `/data/learn/**` (model snapshots + provenance). Canonical IDs may mirror L1 beings/bonds/contexts when present. Append-only history applies to organisms and model revisions.
- **Flow VM runtime**  
  - Nodes Guard/Transform/Wait/Decide/Clamp compile into per-flow tables (`graph/nodes`) and run inside E3 slices with budgets (`bud_cpu_ns`, `bud_io_by`), advancing organism pointers and metrics.  
  - Transform nodes call L0/L1 helpers (e.g., `sig_cell/*`, `org:flow_spec_l1`), never mutate L0 graphs directly, and may append model revisions under `/data/learn/models/**` with provenance.  
  - Wait nodes attach watchers (labels/rewards/pipeline events) and yield via `op/ep` await states.  
  - Decide nodes emit/consume Decision Cells with pipeline/species/variant/niche metadata into `/journal/decisions` plus `/data/eco/runtime/decisions`.  
  - Clamp nodes enforce guardian predicates and budgets, emitting CEI (`eco.guardian.violation`, `eco.limit.hit`) and closing episodes when policy demands.
- **Scheduler and triggers**  
  - Scheduler enzyme scans L1 runtime triggers (`/data/flow/runtime/runs/**`) and app events during Capture, computes niches, selects species deterministically, and uses Decide nodes when exploration is needed.  
  - Opens `op/ep` dossiers with pipeline blocks, creates `/data/eco/runtime/organisms/<id>` records, and steps the Flow VM each beat. L1 helpers (when present) also GC/verify runs and roll up runtime metrics to keep pipeline state canonical.
- **Metrics, persistence, and replay**  
  - Metrics roll up per species/variant/niche/global (`org_started`, `flow_steps`, `org_finished`, `org_failed`, `org_waiting`); runtime history entries mirror beat-to-beat progress.  
  - Branches `/data/eco` and `/data/learn` default to durable CPS controllers; organism histories and model revisions are append-only. Cross-branch reads wrap `cep_cell_hydrate_for_enzyme`/`cep_l1_coh_hydrate_safe`, emit CEI (`cell.cross_read`) plus Decision Cells, and log ecological context in `/data/eco/runtime/decisions`.  
  - Replay consumes Decision Cells instead of re-sampling; mismatches fail loudly.
- **Guardians and safety**  
  - Guardian definitions under `/data/eco/guardians/**` scope to species/variants/niches with predicate + action (`hard_deny`, `soft_deny`, `escalate`). Clamp nodes consult guardians and E3 budgets, emit CEI with pipeline metadata, and set organism/episode status accordingly.
- **Observability surfaces**  
  - OPS dossiers: `op/l2_boot`, `op/l2_shdn`, flow episodes (with pipeline metadata).  
  - CEI topics: `eco.guardian.violation`, `eco.limit.hit`, `eco.flow.error`, `eco.evolution.proposed`. Diagnostics mailbox defaults to `/data/mailbox/diag` unless a pack-owned mailbox is supplied.
- **Code/test layout**  
  Implementation lives in `src/l2_ecology/**`; tests sit in `src/test/l2_ecology/**` gated by `CEP_L2_TESTS` to avoid default-suite bloat. Avoid touching `src/l0_kernel/**` and `docs/L0_KERNEL/**` unless cross-layer interfaces change.
- **Phased delivery (suggested)**  
  1. Bootstrap + roots + organs + schemas + OPS readiness/teardown.  
  2. Flow VM core: Guard/Transform/Decide execution with Decision Cells + compiled graphs; scheduler stub starting organisms.  
  3. Add Wait (watchers/await) and Clamp (budgets/guardians + CEI).  
  4. Flesh out persistence/metrics surfaces and guardian policy plumbing.  
  5. Integrate L1 helpers for pipeline edits/runtime triggers; align CEI with pipeline metadata.  
  6. Harden replay paths and observability; document lexicon additions and finalize gating for `CEP_L2_TESTS`.

## Q&A
- **Compatibility with the shipping kernel?** The pack consumes only public L0/L1 APIs, ships its own organs/enzymes under `src/l2_ecology`, and remains optional during boot/shutdown; no L0 rewrite is required.  
- **What if L1 is missing?** Scheduler + Flow VM still run against L0 state but skip coherence/pipeline rewrites; species/variants/niches remain pack-local and pipeline metadata defaults to caller-provided IDs.  
- **How is readiness proven?** `op/l2_boot` closes with `sts:ok`, `/data/eco/meta/state="ready"` (with beat/version), and deterministic CEI/OPS entries around guardian hits and Decision Cells; `op/l2_shdn` mirrors shutdown progress without blocking kernel teardown.
