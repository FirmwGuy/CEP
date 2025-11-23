# Layer 1 Coherence Pack

## Introduction
Layer 1 is the coherence and pipeline graph pack. This directory now hosts every document related to the pack so contributors have a single place to land updates without scattering notes across the repo.

## Technical Details
- Scope: beings, bonds, contexts, facets, adjacency debts, pipeline DAG definitions, and the minimal runtime orchestration that emits pipeline metadata for Layer 2 flows.
- Ownership: treat this pack as optional; bootstrap and shutdown stay independent of the kernel. Keep docs here in step with the code under `src/l1_coherence/`.
- Structure: add feature-specific notes as separate files inside this directory. Use the nontechnical→technical→Q&A pattern for each new document so readers can skim quickly.

## Current Implementation Snapshot
- Pack bootstrap/shutdown helpers create `/data/coh/**` and `/data/flow/**` roots, register the closure enzyme placeholder, and publish pack readiness.
- Coherence helpers add beings/bonds/contexts/facets/debts with namepool-backed IDs; contexts accept role bindings and emit facet stubs while debts stay open when data is incomplete.
- Pipeline DAG scaffolding ensures pipeline/stage/edge dictionaries under `/data/flow/pipelines/**`, lets callers add edges, and links pipelines/stages back to coherence beings for provenance.
- Runtime scaffolding records runs, per-stage states, metrics, annotations, and can emit pipeline-aware impulses carrying L0 metadata.
- Opt-in smoke tests live under `src/test/l1_coherence/` gated by `CEP_L1_TESTS`.

## Backlog Snapshot
- Flesh out adjacency closure: real facet synthesis, debt history, CEI, and replay-safe cross-branch handling.
- Tighten coherence APIs: validate role vocab, lineage, and append-only debt lifecycle for beings/bonds/contexts/facets.
- Validate pipeline graphs: enforce stage/edge integrity, revisioning, and provenance links to coherence beings/provinces/owners.
- Build the runtime orchestrator: triggers, fan-in/out, per-stage state/metrics/annotations, and pipeline-aware impulses/episodes.
- Align hydration and federation paths: pipeline metadata on remote invokes, security preflight checks, and the planned L0 hydrate helper that carries budget/policy/Decision Cell handling.

## Q&A
- **Where do new L1 docs go?** Add them under `docs/L1_COHERENCE/` alongside this overview.
- **Do these docs replace L0 references?** No. Keep using `docs/CEP.md`, `docs/CEP-Implementation-Reference.md`, and the orientation guide for kernel behavior; this folder only tracks Layer 1 specifics.
- **How do I update the orientation guide?** Whenever you add/remove an L1 doc, update `docs/DOCS-ORIENTATION-GUIDE.md` so the index stays accurate.
