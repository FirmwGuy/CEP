# L1 Bond Layer: Performance & Tuning Notes

## Introduction
Layer 1 keeps every relationship coherent, so a few small choices make a big difference in responsiveness. These notes highlight the levers you can pull to keep bonds, contexts, and facets lean while still enjoying the kernel's audit trail.

## Technical Details
### 1) Identity and hashing discipline
**What to know**
- Bond and context keys are deterministic hashes over `(tag, roles, beings)`. The hash buffers live in packed queues so churned relationships recycle space efficiently.
- Role tags and being identifiers should already be interned DTs; converting fresh strings during hot paths will slow you down.

**Tuning tips**
- Cache common `cepDT` literals in static const tables so enzymes avoid recomputing them on every impulse.
- When importing data, group by bond tag before streaming into the heartbeat; batches with identical tags reuse cached hash state and reduce allocator churn.

### 2) Adjacency mirrors
**What to know**
- `/bonds/adjacency` mirrors are stored in array-backed stores sized to the number of active connections per being.
- Each append also updates a short summary payload used for UI and analytics reads.

**Tuning tips**
- For high-degree beings, prefer hash-backed child stores (`CEP_STORE_HASH`) so lookups stay O(1) even as thousands of links accumulate.
- Periodically call `cep_tick_l1` with a custom budget to prune mirrors for beings that have not changed in recent beats.

### 3) Facet queues and closure plugins
**What to know**
- Facet work lives in `/bonds/facet_queue`. Items are small cells with a context pointer, facet tag, and retry counter.
- Plugins register through `cep_facet_register` and execute under the heartbeat's ordering guarantees.

**Tuning tips**
- Keep facet payloads compact; if you need large computations, store only references and offload heavy work to a higher layer.
- Use the retry counter to backoff noisy facets. Combine it with a watchdog enzyme that parks unresponsive items into a diagnostic queue.

### 4) Journaling and checkpoints
**What to know**
- Pending impulse checkpoints live in `/bonds/checkpoints`. They prevent duplication when the runtime restarts mid-beat.
- Every successful `cep_tick_l1` pass acknowledges completed checkpoints while preserving the history chain.

**Tuning tips**
- On hot systems, flush checkpoint acknowledgements in bursts by running `cep_tick_l1` near the end of your beat agenda.
- Mirror checkpoint metrics into `/telemetry` or an external sink to confirm that retries are draining.

## Q&A
- **Does storing adjacency twice double memory?** Mirrors hold compact pointers and summaries; the authoritative relationship still lives under `/data/CEP/L1/*`, so total overhead stays modest even for dense graphs.
- **Can I skip facet queues if my application is synchronous?** No. Facets enforce closure promises; skipping the queue would leave derived records stale and violates the layer contract.
- **How can I reduce hash collisions for bond keys?** Keep role tags consistent and interned, and avoid cramming high-cardinality attributes into the tag itself. When in doubt, add a dedicated `meta/` value rather than baking data into the tag.
- **What helps during backfills?** Replay historical impulses in chronological order and run the heartbeat with a reduced agenda so facet queues drain gradually without starving live traffic.
