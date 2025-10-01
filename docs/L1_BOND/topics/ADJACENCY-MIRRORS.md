# L1 Topic: Adjacency Mirrors and Summaries

## Introduction
Adjacency mirrors answer a simple question quickly: “who is this being connected to right now?” They live in the Layer 1 runtime workspace so reads stay cheap while the authoritative history remains in the bond and context ledgers.

## Technical Details
### Layout
- **Location**: `/bonds/adjacency/<being>/<hash>`.
- **Key**: `<being>` is the deterministic `cepDT` name of the being. `<hash>` matches the bond or context hash written under `/data/CEP/CEP/L1/(bonds|contexts)`.
- **Payload**: the entry stores a single `value` text cell such as `bond_caned:user-001` or `ctx_editssn:First Draft`. The helpers overwrite this value when the summary changes.

### Update flow
1. `cep_bond_upsert` or `cep_context_upsert` produces a summary string (`tag_text:partner_or_label`).
2. The helper calls `cep_bond_annotate_adjacency`, which ensures the bucket and entry exist (using red-black dictionaries) and writes the summary text.
3. No diffing or append-only history is kept inside the mirror. History lives in the timestamps on the entry itself and in the source bond/context record.

### Pruning
- `cep_tick_l1` walks every adjacency bucket each beat. Empty entries vanish; buckets disappear once they are empty or the owning being has been hard-finalised.
- You can trigger pruning manually by calling `cep_tick_l1` after deleting beings or tearing down large batches of bonds/contexts.

### Reading mirrors safely
- Reads are cheap dictionary lookups. If you need more than summary text, follow the hash back to the durable bond or context record.
- Treat mirrors as caches. Do not write to them directly; let the helper functions keep them aligned with the authoritative data.

## Q&A
- **Do mirrors survive restarts?** Yes. They are normal cells. The prune pass keeps them tidy after you replay work.
- **How do I tell whether a summary is stale?** Compare the entry’s timestamp to the bond/context record’s timestamp. If they differ, schedule a cleanup or rerun the helper.
- **Can I add richer metadata?** Not yet. The helper only writes the summary text. You can extend it to store additional child cells, but keep them compact to avoid degrading traversal speed.
- **What if I want a different storage engine?** Update `cep_bond_ensure_dictionary_cell` to pick the store you need (for example, hashed buckets) and the change will apply everywhere mirrors are created.
