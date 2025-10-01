# L1 Topic: Bonds and Contexts

## Introduction
Bonds capture pair relationships, contexts capture multi-party situations. Together they let Layer 1 express who is linked to whom and under which roles while still leaning on the kernel’s deterministic storage model.

## Technical Details
### Bonds (pair relationships)
- **Hashing**: `cep_bond_upsert` hashes `(tag, role_a_tag, role_a_name, role_b_tag, role_b_name)` to produce the child name under `/data/CEP/CEP/L1/bonds/<tag>/<hash>`.
- **Record layout**: each bond record is a dictionary with two role dictionaries (`role_a`, `role_b`), optional `bond_label` and `bond_note` text entries, and a `meta/` bucket cloned from the supplied metadata.
- **Adjacency**: after updating the record, the helper revisits both participants and writes summary strings into `/bonds/adjacency/<being>/<hash>`.
- **Idempotency**: calling `cep_bond_upsert` with the same spec reuses the existing record and only refreshes summaries or metadata when the input changed.

### Contexts (N-ary relationships)
- **Participants**: every role must point at a being cell; the current implementation rejects other target types.
- **Hashing**: the helper hashes `(tag, role_tags[], role_names[])` to find the child under `/data/CEP/CEP/L1/contexts/<tag>/<hash>`.
- **Record layout**: role dictionaries store participant identifiers as text, `ctx_label` holds a friendly name, and `meta/` receives a cloned metadata dictionary.
- **Facets**: for each required facet tag, the helper ensures a placeholder record at `/facets/<facet>/<hash>` (`facet_state=pending`) and enqueues a queue entry under `/bonds/facet_queue/<facet>/<hash>` with `queue_state=pending`.
- **Adjacency**: every participant receives a summary entry (`ctx_tag:ctx_label`) in `/bonds/adjacency`.

## Q&A
- **Can I bond or enrol something that isn’t a being?** Not with the current code. Make sure the cells you pass in come from `cep_being_claim`.
- **What happens if I change metadata only?** The helper clones the new metadata dictionary and updates the record in place. Hash keys remain stable because they derive from role tags and names, not metadata.
- **Do contexts emit signals automatically?** No. The current layer does not emit journal signals. If you need notifications, add them in your enzyme after the helper returns.
- **How do I clear facets that never completed?** Inspect `/bonds/facet_queue`. If entries sit in `missing`, register the appropriate facet handler or manually remove them after recording why they were skipped.
