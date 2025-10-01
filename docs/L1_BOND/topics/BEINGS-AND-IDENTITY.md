# L1 Topic: Being Cards and Identity Hygiene

## Introduction
Being cards give Layer 1 a stable identity record for each participant. They centralise friendly labels, classification hints, and external references so the rest of the system can point at a single cell when talking about a person, service, or asset.

## Technical Details
### Structure
- **Path**: `/data/CEP/CEP/L1/beings/<name>` where `<name>` is the exact `cepDT` you pass to `cep_being_claim` (no extra hashing or tagging happens automatically).
- **Fields**: three optional text children—`being_label`, `being_kind`, `being_ext`—plus a `meta/` dictionary cloned from any metadata you supply. Additional children are allowed but should obey the shared tag lexicon.
- **History**: every update advances the cell’s timestamp. Because helper functions rewrite the same child nodes, the revision history lives in the timestamp trail rather than separate append-only nodes.

### Claiming a being
1. Build a `cepBeingSpec` with whichever fields you want to populate (all are optional).
2. Call `cep_being_claim(root, name, &spec, &handle)` from inside an enzyme or controlled section. The helper validates `root` and either returns the existing card or creates a new dictionary tagged `CEP:being`.
3. Inspect `handle.revision` if you want to detect concurrent edits later.

### Keeping records clean
- **Consistency**: reuse the same `cepDT` names throughout your application. Namepool helpers in Layer 0 help turn external IDs into deterministic tags.
- **Metadata size**: large metadata trees are deep-cloned on every update. Store big documents elsewhere (e.g., `/cas`) and link them from the metadata dictionary if needed.
- **Retirement**: deleting a being marks it as deleted via the kernel API. Run `cep_tick_l1` afterward so adjacency mirrors referencing the being are pruned.

## Q&A
- **Can I merge two beings?** Not automatically. You need to retarget bonds/contexts manually and then remove the redundant being. Merge helpers are on the roadmap.
- **What stops duplicate external IDs?** Nothing yet. Add your own validation in the caller before invoking `cep_being_claim` if duplicates matter.
- **Do I have to provide label/kind/external values every time?** No. Pass `NULL` to leave the existing value untouched. Non-empty strings overwrite the previous value.
- **How do I attach arbitrary metadata?** Create a dictionary cell with the desired children and pass it via `spec.metadata`. The helper clones it under `meta/` so the being card has its own copy.
