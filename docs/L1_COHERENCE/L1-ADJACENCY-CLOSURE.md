# Layer 1 Coherence — Adjacency Closure and Debts

## Introduction
Layer 1 keeps contexts, beings, bonds, and facets aligned. When required pieces are missing, it records debts and resolves them deterministically once data arrives. This note describes the closure contract and what to expect on replay.

## Technical Details
- **Inputs and scope**
  - Closure runs under `/data/coh/**`, listening for `coh:close` and the sweep op `op/coh_sweep`.
  - It inspects contexts, beings, bonds, and facets, applying rules from `/data/coh/schema/ctx_rules/<kind>/roles|facets`.
  - Context bindings are canonical (role + being, sorted) so IDs stay stable on replay even if callers change order.
- **Debt emission**
  - Missing required data emits debts under `/data/coh/debts/debt:<kind>:<ctx_id>:<requirement>`, each with `kind`, `ctx_id`, `target`, and append-only `history/ev0001..` entries recording `state` (`ist:open`/`ist:ok`) plus notes.
  - Resolution appends a new history entry instead of mutating existing state.
- **Closure actions**
  - Facets land in `/data/coh/facets/<facet_id>` with lineage to the source context; adjacency mirrors update `/data/coh/adj/by_ctx/**`, `/data/coh/adj/by_being/**`, and `/data/coh/adj/by_facet/**`.
  - When rules exist, they set facet kind/label/subject role; otherwise each binding gets a default facet using the role as both kind and label.
- **Replay and determinism**
  - IDs for contexts/facets/debts are built from canonical pieces to keep replays stable. Cross-branch hydration is avoided unless policy allows it; when enabled, Decision Cells and CEI guard it.
- **Backlog and remediation**
  - Closure is idempotent: reruns skip existing facets and refresh adjacency/debt state. `op/coh_sweep` reruns closure across everything.
- **Signals and follow-ups**
  - CEI: `coh.debt.new`, `coh.debt.resolved`, `coh.role.invalid`, `coh.closure.fail`, `coh.hydrate.fail`, `coh.cross_read`.
  - Extend roles/facets in `ctx_rules` as schemas grow; update `docs/CEP-TAG-LEXICON.md` when vocabularies expand.

## Q&A
- **Why track debts instead of failing the write?** Incomplete data still lands deterministically; debts give you a backlog to resolve when upstream data arrives.
- **How does this relate to pipelines?** Pipelines link to coherence beings/bonds; closure keeps those references consistent so runtime orchestration can trust the graph.
- **Do we validate pipeline edges here?** No; edge checks live in the pipeline helpers and use the same adjacency data.
