# Layer 1 Coherence — Overview

## Introduction
Layer 1 is the coherence and pipeline graph pack. It supplies durable identities, relationships, and a small runtime scaffold so you can connect beings/bonds/contexts/facets and drive pipeline runs without rebuilding the shape from scratch.

## Technical Details
- **What L1 covers right now:** beings, bonds, contexts, facets, adjacency debts, pipeline DAGs, and runtime plumbing (fan-in/out, triggers, metrics, annotations, pipeline-aware impulses with CEI for pause/rollback and missing metadata).
- **Ownership:** optional pack; bootstrap and shutdown stay independent of the kernel. Code lives under `src/l1_coherence/`.
- **Document map:**
  - `docs/L1_COHERENCE/L1-USAGE.md` — how to add beings/bonds/contexts/facets/debts, define pipelines, and run them (runtime + federation steps).
  - `docs/L1_COHERENCE/L1-IMPLEMENTATION.md` — what is implemented today, with paths/CEI/topics.
  - `docs/L1_COHERENCE/L1-ADJACENCY-CLOSURE.md` — how closure/debts/adjacency behave.
- **What ships (snapshot):**
  - Bootstrap/shutdown helpers create `/data/coh/**` and `/data/flow/**`, register the closure enzyme, publish readiness, and expose `op/coh_sweep`.
  - Coherence helpers build canonical IDs, keep append-only debt history, populate adjacency mirrors, and run rule-driven closure via `/data/coh/schema/ctx_rules/**`.
  - Pipelines live under `/data/flow/pipelines/**` with stages/edges and coherence bindings (`has_stage`, `pipeline_edge` contexts).
  - Runtime mirrors pipeline topology into runs, gates dispatch with fan-in, emits CEI on pause/rollback gating, auto fan-outs along edges, and accumulates metrics/annotations.
  - Opt-in tests live under `src/test/l1_coherence/` gated by `CEP_L1_TESTS`.

## Q&A
- **Where do new L1 docs go?** Under `docs/L1_COHERENCE/`, following the intro → technical → Q&A pattern.
- **Do these docs replace L0 references?** No; keep using `docs/CEP.md`, `docs/CEP-Implementation-Reference.md`, and the orientation guide for kernel behavior.
- **How do I update the orientation guide?** Whenever you add/remove an L1 doc, update `docs/DOCS-ORIENTATION-GUIDE.md`.
