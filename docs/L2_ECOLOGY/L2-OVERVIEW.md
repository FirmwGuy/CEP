# Layer 2 Ecology — Overview

## Introduction
Layer 2 (“Ecology & Flows”) turns CEP into a supervised learning ecosystem on top of the deterministic kernel. It stays optional: L0 always boots alone, L1 can provide coherence/pipeline graphs when present, and L2 adds species/variants/flows that evolve under supervision without blocking the lower layers.

## Technical Details
- **Scope and dependencies**  
  Optional pack; hard-depends on L0 (heartbeat, OPS/E3, CPS/CAS, CEI, pipeline metadata) and integrates with L1 when available. With no L1 present it still runs flows against L0 state but skips graph/being rewrites.
- **Document map**  
  - `docs/L2_ECOLOGY/L2-IMPLEMENTATION.md` — implementation surface and delivery plan.  
  - Update `docs/DOCS-ORIENTATION-GUIDE.md` whenever L2 docs move or expand.
- **What exists today**  
  - Pack bootstrap/shutdown seeds `/data/eco/**` and `/data/learn/**`, registers organs (`org:eco_root`, `org:eco_flows`, `org:eco_runtime`, `org:learn_models`), and publishes `op/l2_boot`/`op/l2_shdn` dossiers without blocking kernel teardown.  
  - Flow VM compiles Guard/Transform/Wait/Decide/Clamp nodes per flow and executes them inside E3 episodes with budgets. Scheduler instantiates organisms from flow defs, opens `op/ep` dossiers with pipeline/species/variant/niche metadata, and steps them each beat.  
  - Decisions log into `/journal/decisions/**` plus `/data/eco/runtime/decisions/**`; guardian/clamp outcomes emit CEI (`eco.guardian.violation`, `eco.limit.hit`, `eco.flow.error`, `eco.evolution.proposed`). Metrics roll up per species/variant/niche and globally.  
  - Model revisions land under `/data/learn/models/**` with provenance; runtime history stays append-only.
- **Data roots and IDs**  
  `/data/eco/**` covers species, variants, niches, guardians, flows, runtime organisms/history/decisions/metrics; `/data/learn/**` holds model snapshots and provenance. IDs can mirror L1 beings/bonds/contexts when L1 is present; L2 never mutates L0 roots directly.
- **Safety and replay**  
  Decide nodes emit Decision Cells for policy picks and risky cross-branch reads; replay consumes the ledger instead of re-sampling. Hydration wraps `cep_l1_coh_hydrate_safe` when available and records ecological context next to Decision Cells. Guardian/clamp limits enforce resource and safety envelopes while keeping pipeline metadata attached for attribution.
- **Code and tests**  
  Implementation lives under `src/l2_ecology/**`; tests under `src/test/l2_ecology/**` gated by `CEP_L2_TESTS`. Docs stay in `docs/L2_ECOLOGY/**` following the intro → technical → Q&A pattern used by L0/L1.

## Q&A
- **Does L2 require L1?** No. With L1 absent, L2 skips coherence/pipeline rewrites but still runs flows against L0 state; with L1 present, it uses L1 helpers for graph edits and context routing.
- **How is determinism preserved during learning?** Policy picks and cross-branch reads emit Decision Cells; model updates are append-only revisions with provenance. Replay consumes the recorded ledger instead of re-sampling or re-training.
- **Where should new work land?** Implementation under `src/l2_ecology/**`, tests in `src/test/l2_ecology/**`, docs here plus the orientation guide; avoid touching `src/l0_kernel/**` or `docs/L0_KERNEL/**` unless cross-layer APIs change.
