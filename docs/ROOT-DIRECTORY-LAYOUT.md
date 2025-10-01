# CEP Root Directory Layout

## Introduction
Think of the CEP tree as the campus map for the runtime. Layer 0 keeps the utilities humming, Layer 1 adds social infrastructure, and higher layers reserve space for future learning and governance. This guide captures the directories that actually ship today so everyone files data, queues, and evidence in the same predictable places.

## Technical Details
### Always-on roots (created by `cep_heartbeat_bootstrap`)
- `/sys` – core counters, configuration toggles, and name tables the kernel reads each beat.
- `/rt` – heartbeat staging area. When `ensure_directories` is enabled (default) the runtime keeps `/rt/beat/<n>/inbox|agenda|stage` lists for inspection.
- `/journal` – append-only heartbeat evidence. The kernel writes intent/outcome records here; other layers can add ledgers alongside them.
- `/env` – handles and stream proxies bound to external resources. Enzymes dereference entries through the proxy helpers in `cep_cell`.
- `/cas` – content-addressable payload store. Large blobs land here so DATA cells can reference hashes instead of duplicating bytes.
- `/lib` – library snapshots for proxy-backed streams.
- `/data` – durable state, promoted from `/rt/.../stage` at the commit edge of a beat.
- `/tmp` – linked-list scratch pad for tooling; it is not part of the deterministic contract.
- `/enzymes` – registry manifest (`cep_enzyme_register`, `cep_enzyme_descriptor`) and their metadata.

### Layer 1 additions (created by `cep_init_l1`)
- `/data/CEP/CEP/L1` – namespace hub for beings, bonds, contexts, and facets. Each child is an ordinary dictionary so standard kernel helpers work.
  - `/beings` – identity cards keyed by deterministic `cepDT` names.
  - `/bonds` – pair ledgers grouped by bond tag then hashed relationship key.
  - `/contexts` – N-ary simplices keyed by context tag and role hash.
  - `/facets` – closure records keyed by facet tag and the owning context hash.
- `/bonds` – runtime workspace used by Layer 1 during a beat.
  - `/adjacency` – per-being summaries of active bonds and contexts.
  - `/facet_queue` – linked-list queue of pending facet jobs with the context label.
  - `/checkpoints` – reserved dictionary for future retry bookkeeping (currently empty unless callers populate it).

### Planned namespaces
`/stories` and `/law` appear in the conceptual model (see `docs/CEP.md`) but the kernel does not create them yet. Higher layers will mount those trees once their implementations land so the root stays stable for existing deployments.

## Q&A
- **When do the Layer 1 folders appear?** As soon as you call `cep_init_l1`. Skipping that step leaves `/bonds/*` and `/data/CEP/CEP/L1/*` undiscovered, which is why the tests invoke it before exercising the API.
- **Can I add my own root directories?** Yes, but keep them under `/data/CEP/<your-layer>` or another dedicated branch. The built-in bootstrap only manages the paths listed above.
- **Is `/tmp` durable?** No. Treat it as scratch space; nothing under `/tmp` participates in commit or replay.
- **Where should feature-level stories and laws go today?** Until the Layer 3–5 implementation arrives, record them under your own branch inside `/data` or `/stories` once that namespace is introduced. Avoid reusing `/rt` or `/bonds` for durable material.
