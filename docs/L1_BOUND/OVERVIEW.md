# L1 Bonds & Coherence: Overview

## Introduction
Layer 1 is CEP's social sense: it keeps track of who and what are connected so the rest of the stack can reason safely. Think of it as a concierge that remembers every relationship, nudges implied facts into existence, and double-checks that nothing drifts out of sync while the kernel keeps beating.

## Technical Details
### Responsibilities and Scope
Layer 1 sits on top of the append-only kernel and specialises in four duties:
1. **Identity** – map deterministic `cepDT` names to long-lived beings, facets, and contexts under `/CEP/L1/*`.
2. **Relationships** – produce, mutate, and retire bond and context cells while preserving closure across all implied roles.
3. **Coherence** – schedule follow-up impulses when relationships drift, guaranteeing adjacency caches and derived facets stay consistent.
4. **Safety Rails** – guard writes with declared policies (read/write domains, role cardinality, facet completion) so higher layers inherit predictable invariants.

Layer 1 achieves this by extending the kernel API with a narrow C interface that orchestrates bonds, contexts, and adjacency caches without letting callers bypass the deterministic heartbeat model. Engine code lives next to the kernel, but all durable state is written as normal cells so existing tooling keeps working.

### Storage Shape
Durable records live beneath `/data/CEP/L1/`:
- `beings/` retains identity cards (`being` payloads and metadata links).
- `bonds/` stores pair relations with role-labelled links (`role_a`, `role_b`).
- `contexts/` materialise multi-party simplices where each role resolves to a link child.
- `facets/` contains derived records promised by contexts (closure obligations).

Transient helpers live beneath `/bonds/*` during the active beat:
- `adjacency/being/<id>` mirrors outgoing relations for quick lookups.
- `facet_queue/` holds contexts awaiting facet completion enzymes.
- `checkpoints/` records impulse cursors so retry logic can resume safely.

### Planned C API Surface
Layer 1 exposes handles that wrap kernel cells but remain replay-friendly:
- Implementation lives under `src/l1_bond/`, sharing the same `cep_` prefix used by the kernel families.
- `cep_init_l1(const cepConfig*, cepEnzymeRegistry*)` seeds namespaces, installs default enzymes, and primes caches.
- `cep_being_claim(cepCell* root, const cepDT* name, const cepBeingSpec*, cepBeingHandle*)` either returns an existing being or builds a fresh identity card.
- `cep_bond_upsert(cepCell* root, const cepBondSpec*, cepBondHandle*)` records pair bonds, stages adjacency deltas, and emits `sig_bond_*` impulses.
- `cep_context_upsert(cepCell* root, const cepContextSpec*, cepContextHandle*)` creates or updates a simplex, guaranteeing required facets are enqueued.
- `cep_facet_register(const cepFacetSpec*)` lets plugins describe closure rules so the scheduler can materialise derived facts when contexts appear.
- `cep_tick(cepHeartbeat*, cepRuntime*)` drives per-beat maintenance: replaying facet queues, pruning orphaned adjacency mirrors, and acking checkpoints after journal verification.

These calls follow the kernel's style: return `int` status codes, accept explicit handles, and never mutate caller memory outside documented handles. Layer 1 types (`cepBondHandle`, `cepContextSpec`, etc.) remain POD structs so they can be journaled directly.

### Execution Flow
1. **Impulse arrives** – a kernel enzyme records a raw fact and emits a signal (e.g., `sig_cell`).
2. **Layer 1 resolver** – registered L1 enzymes map the signal to a bond/context spec and call the appropriate `cep_*_upsert` helper.
3. **Adjacency staging** – the helper writes durable data under `/data/CEP/L1/*` and mirrors adjacency under `/bonds/adjacency` for intra-beat queries.
4. **Facet scheduling** – if a context implies additional records, the helper pushes a work item into `/bonds/facet_queue` and emits `sig_fct_pn`.
5. **Beat commit** – `cep_tick` runs before the kernel publishes N+1; it verifies that all staged facets either completed or remain queued with checkpoints for retry.

### Error Handling and Replay
All helpers must cope with partial retries. On failure they:
- leave durable records untouched (append-only semantics).
- emit detailed `CEP_ENZYME_FATAL` or `CEP_ENZYME_RETRY` codes.
- record checkpoints so a future beat resumes with the same spec.

Journal entries capture both the incoming spec and the resulting handles so higher layers can reconstruct decisions without bespoke logs.

## Q&A
- **Why add a new runtime instead of more enzymes?**  
  The kernel keeps facts consistent, but it doesn't understand relational closure. Layer 1 packages that logic so every app can rely on the same discipline.

- **Do I have to use the API directly?**  
  Most callers interact through enzymes or higher-layer helpers. Direct calls exist for tooling and migrations that need deterministic control.

- **What about garbage collection?**  
  Layer 1 marks orphaned bonds and contexts during `cep_tick`; the kernel still owns final deletion so history stays intact.

- **Can I extend the tag vocabulary?**  
  Yes. Add new entries to `docs/CEP-TAG-LEXICON.md` first so the shared domain stays coherent, then reference them in your facet specs.
