# L1 Bond Layer: Roadmap

## Introduction
Layer 1 is growing from a focused bond manager into a full coherence service. This roadmap summarises what already ships, where the team is investing next, and which experiments are on the horizon so adopters can plan ahead.

## Technical Details
### Capability Snapshot
| Area | Status | In Place | Next Focus |
| --- | --- | --- | --- |
| Namespace bootstrap | ✅ Done | `cep_init_l1` seeds `/CEP/L1/*`, installs default enzymes, and migrates namepool seeds. | 📌 Auto-discover optional facets during bootstrap to cut manual setup. |
| Being lifecycle | ⚙️ Partial | `cep_being_claim` deduplicates identities and tracks external IDs with append-only history. | ⚙️ Add merge helpers for identity reconciliation workflows. |
| Bond ledger | ⚙️ Partial | `cep_bond_upsert` maintains pair records and adjacency mirrors across retries. | ⚙️ Harden conflict detection for concurrent impulses and expose diff-friendly summaries. |
| Context engine | ⚙️ Partial | `cep_context_upsert` records simplices and stages facet promises. | ⚙️ Support large role sets with streaming validation rather than in-memory arrays. |
| Facet orchestration | ⚙️ Partial | `cep_facet_dispatch` invokes registered plugins and retries with backoff. | 📌 Surface per-facet telemetry and deadline guards. |
| Checkpoint & retry | ⚙️ Partial | `cep_tick_l1` acks completed checkpoints and replays stuck impulses safely. | ⚙️ Add operator hooks to fast-forward or squash long-dead retries. |
| Telemetry & tooling | 🚧 Planned | Basic counters exist in `cep_metrics.c`. | 🚧 Export metrics through the same serializers used by Layer 0 for unified dashboards. |

### Current Foundations
- ✅ Deterministic hashing keeps bond and context keys stable across replays.
- ✅ Adjacency mirrors ride on kernel stores, so pruning and history reuse the same invariants as Layer 0.
- ✅ Unit tests (`test_bond_randomized.c`) exercise randomized permutations of beings, roles, and retries.
- ✅ The heartbeat loop shares infrastructure with the kernel, minimising scheduling drift.

### Active Focus Areas
- ⚙️ Build richer policy descriptors so enzymes can declare allowed role combinations without hand-written guards.
- ⚙️ Expand facet plugins to cover audit trails, notifications, and context rollups out of the box.
- ⚙️ Deliver migration helpers for renaming bond tags or remapping beings without rewriting history.

### Backlog Watchlist
- 📎 Cross-shard synchronisation for adjacency mirrors when deployments span multiple runtimes.
- 📎 Incremental diff stream for clients that need near-real-time bond updates without full snapshots.
- 📎 Garbage collection of orphaned metadata entries left behind after identity merges.

## Q&A
- **How often will this roadmap change?** Expect updates each release cycle; the table highlights progress so teams know when APIs stabilise.
- **Can I rely on bond hashes staying stable?** Yes. Hash formulas are versioned; future changes will flow through explicit migrations.
- **Is adjacency pruning safe in production?** The heartbeat only prunes mirrors after both participants are retired, preserving history while reclaiming transient cache slots.
- **Where should I report feature requests?** File them under the Layer 1 bond tracker so the roadmap can surface demand transparently.
