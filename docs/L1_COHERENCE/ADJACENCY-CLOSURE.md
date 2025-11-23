# Adjacency Closure and Debts (Layer 1 Coherence)

## Introduction
Layer 1 guarantees that contexts keep beings, bonds, and facets in sync. When a required facet is missing, the pack records a debt and later fills it deterministically. This note sketches the intended closure enzyme contract so future sessions can wire the logic without rediscovering the rules.

## Technical Details
- **Inputs and scope**
  - Closure runs under `/data/coh/**` and inspects contexts, beings, bonds, and facets created by Layer 1 clients.
  - The closure enzyme accepts a context target path and a payload listing participating beings and role tags; it may also run as a background sweep over `/data/coh/contexts/*`.
- **Debt emission**
  - When a required facet is absent, the enzyme appends an entry under `/data/coh/debts/` keyed by context ID. Each debt records `source` (context), `target` (missing facet path), `state` (e.g. `ist:open`/`ist:done`), and `note` describing why it was emitted.
  - Debts are append-only; resolution writes a new state entry rather than mutating the original.
- **Closure actions**
  - For each context, materialise derived facets (e.g. adjacency mirrors or role projections) under `/data/coh/facets/` using deterministic names (role + being identifiers). Use `cep_cell_hydrate_for_enzyme` to avoid cross-branch surprises once hooks are live.
  - Link facets back to their source context via `meta/parents` so replay and audits can trace lineage.
- **Replay and determinism**
  - Every debt entry must be reproducible: record the context DTs, role ordering, and the intended facet path so replays emit the same debt set.
  - When closure applies, emit Decision Cells for risky cross-branch reads once we allow cross-branch hydration; until then keep work scoped to `/data/coh`.
- **Backlog and remediation**
  - Keep the enzyme idempotent: reruns should detect existing facets/debts and avoid duplicate writes.
  - A later maintenance pass will scan `/data/coh/debts` for unresolved entries and either replay closure or escalate via CEI.
- **TODO hooks**
  - Implement the actual enzyme bindings and sweeps.
  - Define the precise facet families and role vocabulary, then extend `docs/CEP-TAG-LEXICON.md` accordingly.
  - Add CEI emissions for debt creation/resolution once the pack has a dedicated mailbox.

## Q&A
- **Why track debts instead of failing the write?** To keep ingestion deterministic and observable even when upstream data is incomplete; debts provide a durable backlog.
- **How will this integrate with pipeline DAGs?** Pipeline nodes will link to coherence beings/bonds; closure ensures those references stay consistent so runtime orchestration can trust the graph.
- **Do we validate edge consistency here?** Not yet. Edge validation will piggyback on the same adjacency data once the DAG helper is wired.
