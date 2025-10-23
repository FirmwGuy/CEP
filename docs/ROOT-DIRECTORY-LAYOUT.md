# CEP Root Directory Layout

## Introduction
Think of the CEP tree as the campus map for the runtime. Layer 0 keeps the utilities humming, and today's shipping build only exposes that layer's neighbourhood. This guide captures the directories that actually come online so everyone files data, queues, and evidence in the same predictable places.

## Technical Details
### Always-on roots (created by `cep_heartbeat_bootstrap`)
- `/sys` – core counters, configuration toggles, and name tables the kernel reads each beat. The `/sys/state/<scope>` dictionary also records lifecycle readiness (`status`, `ready_beat`) and teardown metadata (`td_beat`) for kernel subsystems.
- `/rt` – heartbeat staging area. The runtime keeps beat journals here when directory capture is enabled and always maintains `/rt/ops` for live operations such as `op/boot` and `op/shdn`.
- `/journal` – append-only evidence for stream/library effects. Kernel helpers attach intent/outcome entries to stream cells here; packs can add their own ledgers alongside them when they need extra audit trails.
- `/env` – handles and stream proxies bound to external resources. Enzymes dereference entries through the proxy helpers in `cep_cell`.
- `/cas` – content-addressable payload store. Large blobs land here so data cells can reference hashes instead of duplicating bytes.
- `/lib` – library snapshots for proxy-backed streams.
- `/data` – durable state, promoted from `/rt/.../stage` at the commit edge of a beat. Optional upper-layer packs can pre-create their own namespaces here (for example, a coherence pack might reserve `/data/coh`).
- `/tmp` – linked-list scratch pad for tooling; it is not part of the deterministic contract.
- `/enzymes` – registry manifest (`cep_enzyme_register`, `cep_enzyme_descriptor`) and their metadata.

### Beat evidence (`cepHeartbeatPolicy.ensure_directories`)
- `/rt/beat/<n>` – numeric dictionary created when `ensure_directories` is true (the default).
  - `/inbox` – text log of impulses accepted for the beat.
  - `/agenda` – ordered ledger of resolved enzymes and dispatch results.
  - `/stage` – mutation log populated as enzymes commit changes.
    Transaction helpers add short `txn commit/abort: ...` notes here so you can match unveil decisions to beat numbers.
- `/rt/ops/<oid>` – operation dictionaries recording envelopes, state history, close status, and watcher metadata for lifecycle and pack-defined operations.

## Q&A
- **When do the beat folders appear?** As soon as `cepHeartbeatPolicy.ensure_directories` is left at its default `true`. Turning it off skips `/rt/beat/<n>` entirely so long-running captures do not grow without bound.
- **What lives under `/data` after bootstrap?** Only what subsystems ask for. The bare kernel leaves it empty; upper-layer packs are responsible for seeding their own ledgers (for example, `/data/flow` or `/data/coh`) when they bootstrap.
- **Can I add my own root directories?** Yes—create them under `/data` or `/env` as needed. The bootstrap only guarantees the paths listed in this document.
