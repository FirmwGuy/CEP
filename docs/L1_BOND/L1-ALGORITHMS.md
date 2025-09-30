# L1 Bond Layer: Algorithms Report

## Introduction
Layer 1 wraps the kernel's append-only core with algorithms that guarantee social coherence. This report focuses on the routines that cut across naming, caching, heartbeat scheduling, and facet closure so you know where the moving parts live.

## Technical Details
### Identity resolution and deduplication
**Purpose.** Map external identifiers to canonical beings without duplicates while preserving history.

**How it works.**
- `cep_being_claim` hashes the caller's `cepDT` name and optional external IDs to look up or create the being card. When a fresh card is needed, it clones metadata into `meta/` and stamps timestamps for audit replay.
- Backfilling or replaying a journal reuses the same function, so deterministic hashes guarantee the same beings appear without collisions.

**Where to look.** Implementation resides in `src/l1_bond/cep_bond_being.c`; unit coverage lands in `src/test/l1_bond/test_bond_randomized.c`.

### Bond key synthesis and adjacency updates
**Purpose.** Keep pairwise relationships indexed for fast lookup and historical auditing.

**How it works.**
- `cep_bond_upsert` builds a stable hash from `(tag, role_a, being_a, role_b, being_b)`. The function updates or appends the bond record under `/data/CEP/L1/bonds/<tag>/<key>`.
- The same call stages adjacency mirrors by inserting summaries under `/bonds/adjacency/being/<id>/<key>`.
- A lightweight diff detects whether role payloads changed; only then do adjacency mirrors receive updates, keeping history tidy.

**Where to look.** Algorithms live in `src/l1_bond/cep_bond_pair.c`; adjacency helpers share utilities in `src/l1_bond/cep_bond_common.c`.

### Context closure and facet scheduling
**Purpose.** Guarantee that multi-party contexts always produce the derived records they promise.

**How it works.**
- `cep_context_upsert` normalises role arrays, hashes them to a context key, and updates the context record.
- Required facets are stored alongside the context. Each missing facet results in an enqueue operation in `/bonds/facet_queue` with the context label so diagnostics stay human-friendly.
- During the heartbeat, `cep_tick_l1` pops pending facet work, invokes registered plugins (`cep_facet_dispatch`), and requeues items with exponential backoff on failure.

**Where to look.** Core code sits in `src/l1_bond/cep_bond_context.c` and `src/l1_bond/cep_bond_facet.c`.

### Heartbeat maintenance loop
**Purpose.** Keep the transient caches in sync with durable state while respecting append-only semantics.

**How it works.**
- `cep_tick_l1` scans the adjacency mirrors for tombstoned bonds and prunes them once both participants are retired.
- The same loop sweeps checkpoints, acknowledging finished impulses and leaving history nodes in place for replay.
- Metrics emitted during the pass feed optional telemetry enzymes so operators can observe backlog depth and retry health.

**Where to look.** Heartbeat helpers live in `src/l1_bond/cep_bond_tick.c`; future telemetry shims will extend this file or land alongside it.

## Q&A
- **Why not store adjacency directly inside each bond?** Mirrors give O(1) lookups for clients that only need summaries. They also let you prune stale edges lazily without rewriting the authoritative history.
- **Can multiple contexts share the same facet queue entry?** No. Each context–facet pair enqueues its own cell so retries remain isolated and audit logs stay precise.
- **How do plugins stay deterministic?** Plugins receive only POD specs and operate inside the heartbeat. They must avoid global state and record any derived cells through the documented APIs so history is reproducible.
- **Where should I patch bugs first?** Start with the unit tests noted above. They exercise randomized permutations that catch ordering and dedup edge cases quickly.
