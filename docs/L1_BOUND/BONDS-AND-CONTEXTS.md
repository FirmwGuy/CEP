# L1 Bonds & Coherence: Bonds and Contexts

## Introduction
Bonds explain how beings relate; contexts capture multi-party situations in one breath. This guide walks through how Layer 1 represents those relationships, which tags it relies on, and how the upcoming C API keeps everything deterministic.

## Technical Details
### Core Records
Layer 1 introduces persistent records, all stored as regular dictionary cells beneath `/data/CEP/L1/`:
- **Being cards** (`being`): identity cells containing descriptive metadata, canonical tags, and a `meta/` dictionary that clones any caller-provided annotations.
- **Bonds** (`bond_*`): pair relationships stored under `/bonds/<tag>/<key>` where `<key>` is a numeric name derived from hashing `<tag, role_a, being_a, role_b, being_b>`. Each record keeps `role_*` dictionaries that capture participant identifiers, short partner summaries, a `meta/` dictionary, and optional `bond_label`/`bond_note` values.
- **Contexts** (`ctx_*`): higher-order simplices keyed by the context tag and a hash over the supplied role tuple. Role dictionaries retain participant identifiers, new metadata lives under `meta/`, and the main record exposes `ctx_label` for diagnostics.
- **Facets** (`facet_*`): closure artefacts promised by a context. Entries live under `/facets/<facet-tag>/<context-key>` and record lifecycle state for the owning context.

All records keep their append-only history. When an update lands, the kernel timestamps the revised children so replay can reconstruct the previous shape without cloning entire trees.

### Tagging Discipline
Layer 1 extends the shared lexicon with predictable patterns:
- `being` – core tag for identity cards.
- `bond_*` – ops tags describing the relationship class (`bond_caned`, `bond_parent`, etc.).
- `ctx_*` – ops tags for contexts (`ctx_edit`, `ctx_member`).
- `facet_*` – ops tags naming closure obligations.
- `sig_bond_*`, `sig_ctx_*`, `sig_fct_*` – signal families emitted during processing.
- `meta` – core tag for metadata dictionaries cloned into beings, bonds, and contexts.

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

Layer 1 hashes the tuple encoded in each spec to derive the per-record numeric key. Changing metadata alone rewrites the `meta/` dictionary in place, while changing any role or tag produces a new hashed entry alongside the existing history.

### Lifecycle of a Bond
1. **Collect roles** – an enzyme or tool resolves the being cells that should appear on either side.
2. **Produce `cepBondSpec`** – the caller selects the bond tag (`CEP:bond_caned`) and optional metadata.
3. **Call `cep_bond_upsert`** – Layer 1 hashes the tuple, reuses the existing record if the hash matches, or creates a fresh dictionary under `/bonds/<tag>/<hash>` with role summaries and cloned metadata.
4. **Mirror adjacency** – the helper updates `/bonds/adjacency/<being>/<hash>` with a short summary so reads remain O(1) during the beat.
5. **Emit signals** – the helper records journal entries and emits `sig_bond_wr` pointing at the record; higher layers may respond next beat.

Bonds are idempotent by design: the same spec results in the same durable cell revision. When metadata changes, a new revision is appended, but the canonical adjacency path remains stable.

### Lifecycle of a Context
Contexts follow the same outline but operate over N roles:
1. **Resolve participants** – each `role_tag` maps to a being or nested context.
2. **Validate schema** – the helper checks declared role cardinalities and facet requirements.
3. **Atomically update** – the API hashes the role tuple to select `/contexts/<tag>/<hash>`, refreshes role summaries, and rewrites the `meta/` dictionary when metadata changes.
4. **Queue facets** – required facets enter `/bonds/facet_queue/<facet-tag>/<hash>` with the context label so retries can hop back to the owning context via a fresh lookup.
5. **Publish adjacency** – adjacency mirrors record the simplex hash for each participant with summaries like `<ctx_tag>:<ctx_label>`.

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
Layer 1 uses these specs to know which enzymes to schedule when a context appears. Work items store the context handle, facet tag, and checkpoint metadata; completion clears the queue entry under `/bonds/facet_queue/<facet-tag>/<context-hash>` and writes the facet cell under `/data/CEP/L1/facets/<facet-tag>/<context-hash>`.

### Concurrency and Ordering
Layer 1 never bypasses the kernel's heartbeat discipline. All helpers:
- operate within the calling beat and rely on the kernel to commit at N+1.
- write adjacency mirrors before emitting impulses so readers observe consistent state.
- respect dependency ordering by resolving L1 facet enzymes through the shared `cepEnzymeRegistry`.

## Q&A
- **How are bond identities generated?**  
  Layer 1 hashes the ordered tuple of role DTs plus participant cell IDs. The numeric hash becomes the child name under `/data/CEP/L1/bonds/<tag>/<hash>`, guaranteeing idempotent upserts.

- **Can contexts reference other contexts?**  
  Yes, provided the target context already exists or is scheduled earlier in the beat. Layer 1 detects cycles and replaces them with explicit facet obligations so closure remains achievable.

- **What if a facet enzyme fails?**  
  The queue entry stays queued with a checkpoint; `cep_tick` retries on the next beat, and repeated failures escalate to governance layers through a dedicated signal family.

- **Do adjacency mirrors persist across restarts?**  
  No. They are rebuilt from durable bonds during bootstrap, ensuring warm start reliability without polluting the append-only history.
