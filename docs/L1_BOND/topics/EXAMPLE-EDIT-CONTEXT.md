# L1 Topic: Example – Editing Context

## Introduction
This walkthrough shows how an editing enzyme can use the bond layer today. It claims the relevant beings, records a permission bond, creates a context with required facets, and hands the facet queue off to a simple materialiser.

## Technical Details
### Scenario
When an edit impulse arrives we want to:
1. Ensure both the user and the document exist as beings with friendly metadata.
2. Record a `bond_caned` relationship so later audits can see who may edit the document.
3. Create a `ctx_editssn` context that ties the user and document together and queues facets for an edit log and presence tracker.

### Enzyme sketch
```c
static int on_edit(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* root = cep_root();

    /* Resolve beings */
    cepBeingHandle user = {0};
    cepBeingSpec user_spec = {
        .label = "Alex Solo",
        .kind = "human",
        .external_id = "user-001",
        .metadata = user_meta_dict,
    };
    if (cep_being_claim(root, CEP_DTAW("CEP", "being_alx"), &user_spec, &user) != CEP_L1_OK)
        return CEP_ENZYME_FATAL;

    cepBeingHandle doc = {0};
    cepBeingSpec doc_spec = {
        .label = "Feature Doc",
        .kind = "document",
        .external_id = "doc-2024A",
        .metadata = doc_meta_dict,
    };
    if (cep_being_claim(root, CEP_DTAW("CEP", "being_doc"), &doc_spec, &doc) != CEP_L1_OK)
        return CEP_ENZYME_FATAL;

    /* Upsert the permission bond */
    cepBondSpec bond_spec = {
        .tag = CEP_DTAW("CEP", "bond_caned"),
        .role_a_tag = CEP_DTAW("CEP", "role_a"),
        .role_a = user.cell,
        .role_b_tag = CEP_DTAW("CEP", "role_b"),
        .role_b = doc.cell,
        .metadata = bond_meta_dict,
        .label = "Primary Edit",
        .note = "shared workspace",
    };
    if (cep_bond_upsert(root, &bond_spec, NULL) != CEP_L1_OK)
        return CEP_ENZYME_FATAL;

    /* Describe the context and required facets */
    const cepDT* ctx_roles[] = {
        CEP_DTAW("CEP", "role_source"),
        CEP_DTAW("CEP", "role_subj"),
    };
    const cepCell* ctx_targets[] = { user.cell, doc.cell };
    const cepDT* facet_tags[] = {
        CEP_DTAW("CEP", "facet_edlog"),
        CEP_DTAW("CEP", "facet_prsnc"),
    };

    cepContextSpec ctx_spec = {
        .tag = CEP_DTAW("CEP", "ctx_editssn"),
        .role_count = 2,
        .role_tags = ctx_roles,
        .role_targets = ctx_targets,
        .metadata = context_meta_dict,
        .facet_tags = facet_tags,
        .facet_count = 2,
        .label = "First Draft",
    };
    if (cep_context_upsert(root, &ctx_spec, NULL) != CEP_L1_OK)
        return CEP_ENZYME_FATAL;

    return CEP_ENZYME_SUCCESS;
}
```
Any metadata dictionaries (`*_meta_dict`) are standard cells you create beforehand.

### Facet handler outline
```c
static int facet_apply_edit_log(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;

    cepCell* facet_record = cep_cell_find_by_path(cep_root(), target_path);
    if (!facet_record)
        return CEP_ENZYME_FATAL;

    /* Replace the summary text with an idempotent payload */
    cepDT value_tag = *CEP_DTAW("CEP", "value");
    cepCell* existing = cep_cell_find_by_name(facet_record, &value_tag);
    if (existing)
        cep_cell_remove_hard(existing, NULL);

    const char payload[] = "edit log ready";
    cepDT text_type = *CEP_DTAW("CEP", "text");
    if (!cep_cell_add_value(facet_record, &value_tag, 0, &text_type, payload, sizeof payload, sizeof payload))
        return CEP_ENZYME_FATAL;

    return CEP_ENZYME_SUCCESS;
}

static void register_facets(void) {
    cepFacetSpec spec = {
        .facet_tag = CEP_DTAW("CEP", "facet_edlog"),
        .source_context_tag = CEP_DTAW("CEP", "ctx_editssn"),
        .materialiser = facet_apply_edit_log,
        .policy = CEP_FACET_POLICY_DEFAULT,
    };
    (void)cep_facet_register(&spec);
    /* Register additional facets the same way */
}
```
`cep_tick_l1` calls the materialiser after the context enqueues the facet. Returning `CEP_ENZYME_SUCCESS` flips `facet_state` and `queue_state` to `complete` and removes the queue entry.

### Beat outcomes
After the enzyme runs you will see:
- `/data/CEP/CEP/L1/beings/being_alx` and `/being_doc` populated with label/kind/external metadata.
- `/data/CEP/CEP/L1/bonds/bond_caned/<hash>` storing role summaries plus optional label/note.
- `/data/CEP/CEP/L1/contexts/ctx_editssn/<hash>` capturing participants and the context label.
- `/bonds/adjacency/*/<hash>` summarising the bond and context for both beings.
- `/data/CEP/CEP/L1/facets/facet_edlog/<hash>` and `/facet_prsnc/<hash>` with `facet_state=pending` (until the facet handler completes them).
- `/bonds/facet_queue/facet_*` entries awaiting `cep_tick_l1`.

### Dispatching facets during the beat
Call `cep_tick_l1(runtime)` (usually near the end of your heartbeat step). It will:
1. Visit each queue entry, invoke the registered facet handler, and set queue/facet state based on the result.
2. Remove completed entries and drop empty queue families.
3. Prune adjacency buckets for beings that no longer exist.

Any entry left in `pending`, `fatal`, or `missing` remains visible in the queue for follow-up.

## Q&A
- **Do I have to call `cep_tick_l1` inside the same beat?** Run it before you advance to the next beat if you want facet records to materialise immediately. Skipping it leaves queue entries pending.
- **What if a facet handler is missing?** The queue entry flips to `missing` and stays put. Register the handler and rerun `cep_tick_l1` to retry.
- **Can I include additional metadata in the context?** Yes. Any children you add to the metadata dictionary you pass into `cep_context_upsert` are cloned onto the context record.
- **How do I handle retries?** Return `CEP_ENZYME_RETRY` from your facet handler. The queue entry remains `pending` and `cep_tick_l1` will try again on the next pass.
