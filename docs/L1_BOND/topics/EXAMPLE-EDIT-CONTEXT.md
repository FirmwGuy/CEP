# L1 Topic: Example – Editing Context

## Introduction
To illustrate how Layer 1 will feel in practice, this walkthrough shows an enzyme responding to a document edit impulse. It claims the right beings, assembles a context describing the edit, and lets Layer 1 guarantee that all closure facets stay healthy.

## Technical Details
### Scenario
When `ceptron/doc/edit` emits an impulse, we want three things to line up:
1. The actor (user) and subject (document) remain bonded through `bond_caned`.
2. A context records the edit session (`ctx_editssn`) with roles for actor, subject, and the editor UI.
3. Facets ensure lightweight audit trails (`facet_edlog`) and notify collaboration watchers via `sig_fct_em`.

### Enzyme Sketch
```c
static int ceptron_on_edit(const cepPath* signal, const cepPath* target) {
    cepBeingHandle user = {0}, doc = {0}, ui = {0};
    cepContextHandle session = {0};

    /* Resolve beings */
    CEP_CALL(cep_being_claim(root, CEP_DTAW("CEP", "being"), &spec_user, &user));
    CEP_CALL(cep_being_claim(root, CEP_DTAW("CEP", "being"), &spec_doc, &doc));
    CEP_CALL(cep_being_claim(root, CEP_DTAW("CEP", "being"), &spec_ui, &ui));

    /* Ensure permission bond exists */
    const cepDT* roles[2] = { CEP_DTAW("CEP", "role_a"), CEP_DTAW("CEP", "role_b") };
    const cepCell* targets[2] = { user.cell, doc.cell };
    cepBondSpec perm_spec = {
        .tag         = CEP_DTAW("CEP", "bond_caned"),
        .role_a_tag  = roles[0],
        .role_a      = targets[0],
        .role_b_tag  = roles[1],
        .role_b      = targets[1],
        .metadata    = audit_dict,
        .causal_op   = cep_heartbeat_current_op(),
    };
    CEP_CALL(cep_bond_upsert(root, &perm_spec, NULL));

    /* Describe context */
    const cepDT* ctx_roles[] = {
        CEP_DTAW("CEP", "role_source"),
        CEP_DTAW("CEP", "role_subj"),
        CEP_DTAW("CEP", "role_entry"),
    };
    const cepCell* ctx_targets[] = { user.cell, doc.cell, ui.cell };
    const cepDT* ctx_facets[] = { CEP_DTAW("CEP", "facet_edlog"), CEP_DTAW("CEP", "facet_prsnc") };

    cepContextSpec ctx_spec = {
        .tag          = CEP_DTAW("CEP", "ctx_editssn"),
        .role_count   = cep_lengthof(ctx_roles),
        .role_tags    = ctx_roles,
        .role_targets = ctx_targets,
        .metadata     = session_dict,
        .facet_tags   = ctx_facets,
        .facet_count  = cep_lengthof(ctx_facets),
        .causal_op    = cep_heartbeat_current_op(),
        .label        = "edit session",
    };
    CEP_CALL(cep_context_upsert(root, &ctx_spec, &session));

    return CEP_ENZYME_SUCCESS;
}
```
`CEP_CALL` is the standard macro that converts non-zero returns into retry or fatal codes. The helper leaves adjacency mirrors staged, facet work queued, and journal entries ready for commit.

### Beat Outcomes
- `/data/CEP/L1/bonds/bond_caned/<hash>/` now contains the permission bond with two role dictionaries, a `meta/` clone, and a history entry referencing the prior revision.
- `/data/CEP/L1/contexts/ctx_editssn/<hash>/` records the edit session, the attached metadata payload, and link children for actor, subject, and UI.
- `/bonds/adjacency/being/<user>/<hash>/value` (and the matching document entry) carry compact summaries for fast local inspection.
- `/bonds/facet_queue/facet_edlog/<hash>/value` and `/bonds/facet_queue/facet_prsnc/<hash>/value` retain the context label and queue state until facet work materialises.
- The journal registers `sig_bond_wr` and `sig_ctx_wr` so higher layers can react deterministically at beat N+1.

### Closure Enforcement
When `cep_tick_l1` runs at the end of the beat it:
1. Feeds the facet queue through the registered facet enzymes (`facet_edlog`, `facet_prsnc`).
2. Confirms adjacency mirrors and facet outputs match the new context revision.
3. Writes checkpoints so a restart during processing can resume without double-creating facets.

If a facet enzyme returns `CEP_ENZYME_RETRY`, the queue entry remains with an exponential-backoff schedule stored alongside the checkpoint metadata, ensuring persistent but bounded retries while the queue state stays `pending`.

## Q&A
- **What if a role target is missing?**  
  `cep_context_upsert` validates that every declared role is populated; failure returns `CEP_ERR_ROLE_MISSING` and the enzyme reports `CEP_ENZYME_RETRY` after staging a diagnostic entry.

- **How do migrations update existing contexts?**  
  Provide the previous handle when calling `cep_context_upsert`. Layer 1 checks revision continuity so the migration can amend metadata without losing history.

- **Can we bypass `cep_being_claim` and pass raw cells?**  
  Only if you manage identity contracts yourself. Using the helper guarantees namespace reservations, schema links, and adjacency rebuild markers are applied correctly.

- **How are facet queues drained during bulk imports?**  
  Import tools run `cep_tick_l1` after each batch, letting the normal heartbeat maintenance clear queues before proceeding to the next chunk.
