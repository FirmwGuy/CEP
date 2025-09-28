# L1 Bonds & Coherence: Bonds and Contexts

## Introduction
Bonds explain how beings relate; contexts capture multi-party situations in one breath. This guide walks through how Layer 1 represents those relationships, which tags it relies on, and how the upcoming C API keeps everything deterministic.

## Technical Details
### Core Records
Layer 1 introduces persistent records, all stored as regular dictionary cells beneath `/data/CEP/L1/`:
- **Being cards** (`being`): identity cells containing descriptive metadata, canonical tags, and optional schema links.
- **Bonds** (`bond_*`): pair relationships that always expose two role links (`role_a`, `role_b`).
- **Contexts** (`ctx_*`): higher-order simplices keyed by a context tag and populated with arbitrarily many role links (`role_<name>`).
- **Facets** (`facet_*`): closure artefacts promised by a context (e.g., type hierarchies, derived adjacency summaries).

All records keep their append-only history. When an update occurs, Layer 1 writes a new revision that points to the prior digest so replay can reproduce the same state graph.

### Tagging Discipline
Layer 1 extends the shared lexicon with predictable patterns:
- `being` – core tag for identity cards.
- `bond_*` – ops tags describing the relationship class (`bond_caned`, `bond_parent`, etc.).
- `ctx_*` – ops tags for contexts (`ctx_edit`, `ctx_member`).
- `facet_*` – ops tags naming closure obligations.
- `sig_bond_*`, `sig_ctx_*`, `sig_fct_*` – signal families emitted during processing.

Each pattern must be registered in the lexicon before use so tooling can validate domain/tag pairs at bootstrap.

### Specification Structures
The C API wraps kernel cells with POD specs so callers describe intent declaratively:
```c
typedef struct {
    const cepDT* tag;             /* bond: which relationship */
    const cepDT* role_a_tag;      /* default CEP:role_a */
    const cepCell* role_a;        /* resolved being cell */
    const cepDT* role_b_tag;      /* default CEP:role_b */
    const cepCell* role_b;        /* resolved being cell */
    const cepCell* metadata;      /* optional dictionary with annotations */
    cepOpCount     causal_op;     /* kernel op id for provenance tie-back */
} cepBondSpec;

typedef struct {
    const cepDT*   tag;           /* context identity */
    size_t         role_count;    /* number of occupied roles */
    const cepDT**  role_tags;     /* e.g., CEP:role_source */
    const cepCell**role_targets;  /* beings or nested contexts */
    const cepCell* metadata;      /* context-specific data cell */
    const cepDT**  facet_tags;    /* closure obligations */
    size_t         facet_count;   /* facets to schedule */
    cepOpCount     causal_op;     /* provenance */
} cepContextSpec;
```

Specs never contain mutable pointers owned by the API. Callers allocate arrays, populate them, and remain responsible for lifetime until the call returns. Results arrive via small handles (opaque structs containing cell pointers and revision ids) so subsequent writes can detect divergence.

### Lifecycle of a Bond
1. **Collect roles** – an enzyme or tool resolves the being cells that should appear on either side.
2. **Produce `cepBondSpec`** – the caller selects the bond tag (`CEP:bond_caned`) and optional metadata.
3. **Call `cep_bond_upsert`** – Layer 1 finds an existing bond with the same ordered tuple or creates a new dictionary cell with two link children.
4. **Mirror adjacency** – the helper updates `/bonds/adjacency/<being>` with forward/back references so reads remain O(1) during the beat.
5. **Emit signals** – the helper records journal entries and emits `sig_bond_wr` pointing at the new cell; higher layers may respond next beat.

Bonds are idempotent by design: the same spec results in the same durable cell revision. When metadata changes, a new revision is appended, but the canonical adjacency path remains stable.

### Lifecycle of a Context
Contexts follow the same outline but operate over N roles:
1. **Resolve participants** – each `role_tag` maps to a being or nested context.
2. **Validate schema** – the helper checks declared role cardinalities and facet requirements.
3. **Atomically update** – the API writes the context cell and ensures links carry canonical ordering so replay stays deterministic.
4. **Queue facets** – required facets enter `/bonds/facet_queue`; if one already exists, the queue entry upgrades a revision instead of duplicating work.
5. **Publish adjacency** – adjacency mirrors record the simplex ID for each participant so caches and queries stay in sync.

### Facet Completion
Facet rules are registered ahead of time:
```c
typedef struct {
    const cepDT* facet_tag;               /* e.g., CEP:facet_member */
    const cepDT* source_context_tag;      /* only contexts with this tag trigger */
    cepEnzyme    materialiser;            /* enzyme callback that materialises the facet */
    cepFacetPolicy policy;              /* retry / failure contract */
} cepFacetSpec;
```
Layer 1 uses these specs to know which enzymes to schedule when a context appears. Work items store the context handle, facet tag, and checkpoint metadata; completion clears the queue entry and writes the facet cell under `/data/CEP/L1/facets`.

### Concurrency and Ordering
Layer 1 never bypasses the kernel's heartbeat discipline. All helpers:
- operate within the calling beat and rely on the kernel to commit at N+1.
- write adjacency mirrors before emitting impulses so readers observe consistent state.
- respect dependency ordering by resolving L1 facet enzymes through the shared `cepEnzymeRegistry`.

## Q&A
- **How are bond identities generated?**  
  By hashing the ordered tuple of role DTs plus participant cell IDs. The hash becomes the dictionary key under `/data/CEP/L1/bonds`, guaranteeing idempotent upserts.

- **Can contexts reference other contexts?**  
  Yes, provided the target context already exists or is scheduled earlier in the beat. Layer 1 detects cycles and replaces them with explicit facet obligations so closure remains achievable.

- **What if a facet enzyme fails?**  
  The queue entry stays queued with a checkpoint; `cep_tick` retries on the next beat, and repeated failures escalate to governance layers through a dedicated signal family.

- **Do adjacency mirrors persist across restarts?**  
  No. They are rebuilt from durable bonds during bootstrap, ensuring warm start reliability without polluting the append-only history.

