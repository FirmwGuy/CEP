# L1 Bond Layer: Performance & Tuning Notes

## Introduction
The current Layer 1 implementation is small but already benefits from a few careful choices. These notes highlight the levers you can pull today to keep the bond layer responsive as data grows.

## Technical Details
### 1) Name and hash hygiene
- **What matters**: Bond and context keys are hashes over `cepDT` values. Reusing the same `cepDT` instances (or caching their words/acronyms) saves conversions and guarantees key stability.
- **Tuning tips**: Predeclare the tags you use most often (role tags, facet tags) as `static const cepDT` values. Avoid on-the-fly text-to-tag conversions in hot loops; if you must turn strings into `cepDT`, intern them via the namepool beforehand.

### 2) Metadata cloning
- **What happens**: `cep_being_claim`, `cep_bond_upsert`, and `cep_context_upsert` clone metadata dictionaries wholesale. Large, deeply nested metadata cells incur a deep copy on each update.
- **Tuning tips**: Keep metadata dictionaries compact and push heavyweight blobs into `/cas` or separate trees. When replaying imports, reuse the same metadata cell if it has not changed to avoid unnecessary cloning.

### 3) Adjacency mirrors
- **What happens**: Mirrors live in red-black dictionaries. Each update replaces the existing summary text if it differs.
- **Tuning tips**: Shorten summaries (for example `bond_caned:user-001` already fits) to keep allocations small. Schedule `cep_tick_l1` regularly so deleted beings drop their buckets promptly.

### 4) Facet queue health
- **What happens**: `/bonds/facet_queue` is a linked list sized to the number of pending facet jobs. Entries carry only the context label and current state.
- **Tuning tips**: Run `cep_tick_l1` every beat (or more often during bulk imports) to keep the queue bounded. If a facet enzyme performs long work, move heavy lifting into higher layers and leave the facet callback to publish a lightweight record.

### 5) Checkpoints
- **What happens**: The checkpoints dictionary exists but the current code only removes empty folders.
- **Tuning tips**: If you add retry metadata, namespace it predictably (for example `checkpoints/pending/<id>`). `cep_tick_l1` already cleans up empty families for you.

## Q&A
- **Do I need to choose between list or hash stores for adjacency?** Not right now; the helpers always provision red-black trees. If you need a different store, extend `cep_bond_ensure_dictionary_cell` so the choice remains centralised.
- **How can I measure queue pressure?** Count the children under `/bonds/facet_queue` after `cep_tick_l1`. A simple monitoring enzyme can emit those counts into a perspective or external metrics system.
- **Is cloning metadata safe for concurrent writers?** Yes, but it is still a full copy. Coordinate imports so you do not repeatedly rewrite the same large dictionaries in back-to-back beats.
- **Can I skip adjacency mirrors to save memory?** Not without modifying the code. Every bond/context update refreshes the mirror. If memory becomes a concern, compress the summary strings or strip optional labels until you introduce a smarter cache.
