# L1 Bond Layer: Integration & Interop Guide

## Introduction
Layer 1 plugs social intelligence into the kernel. This guide explains how applications bind their own heartbeat work to the bond layer, how to feed it data from journals or services, and how to keep foreign systems in sync without breaking the deterministic rules that keep CEP tidy.

## Technical Details
### Layer bring-up checklist
1. **Seed namespaces.** Call `cep_init_l1` right after the kernel root is bootstrapped so the `/CEP/L1/*` tree exists before any heartbeat runs.
2. **Install enzymes.** Register the default bond and facet enzymes into the shared registry, then add your own `sig_bond_*`, `sig_ctx_*`, and `sig_fct_*` hooks for domain-specific reactions.
3. **Prime queues.** Ensure the heartbeat agenda includes `cep_tick_l1` (or your wrapper) so per-beat maintenance drains facet queues, prunes adjacency mirrors, and checkpoints retries.

### Working with beings, bonds, and contexts
- **Being handles.** Use `cep_being_claim` to look up or lazily create identity cards. Callers provide deterministic DT names or text keys that were interned through the namepool at a higher layer.
- **Bond upserts.** Run `cep_bond_upsert` inside your enzyme once both participants are known. The call computes the canonical hash for `(tag, roles, beings)`, emits adjacency deltas into `/bonds/adjacency`, and queues follow-up impulses when role summaries change.
- **Context orchestration.** Invoke `cep_context_upsert` with a `cepContextSpec` describing every role and its participant. Required closure facets are declared alongside the context so they can be enqueued automatically.

### Feeding external systems
- **Journal replay.** When importing historical relationships, stream the original impulses through the heartbeat so Layer 1 can rebuild caches incrementally. Avoid writing directly into `/data/CEP/L1/*`; you will bypass adjacency tracking.
- **Proxy bindings.** If a foreign service owns the canonical roster, wrap its API in a proxy that emits `sig_bond_sync` or `sig_ctx_sync` impulses. The kernel heartbeat will batch these into deterministic revisions while the proxy reports drift.
- **Serialization.** The bond layer rides on top of the kernel's serialization format. When you export or import a sub-tree, include `/data/CEP/L1/*` and the transient `/bonds/*` queues together so adjacency mirrors stay coherent.

### Guardrails and observability
- **Policy enforcement.** Guard your enzymes with explicit role and facet policies before calling into the bond APIs. Shared helpers under `src/l1_bond/policy` normalise the checks.
- **Monitoring.** Mirror heartbeat counters (`sig_bond_*` rate, facet backlog depth, adjacency churn) into analytics cells or telemetry sinks so you can spot stalled closures before they bite consumers.
- **Failure recovery.** If an enzyme aborts after staging adjacency deltas, the heartbeat will retry when the impulse is reissued. Keep retries idempotent by re-reading the target cells rather than carrying cached handles across beats.

## Q&A
- **Do I have to call Layer 1 APIs from inside a heartbeat?** Yes. Running them inside enzymes ensures adjacency mirrors, checkpoints, and facet queues move in lock-step with the kernel's op counts.
- **Can I mutate `/data/CEP/L1/*` directly for migrations?** Only through the documented APIs. Direct writes look fast but skip adjacency bookkeeping and will leave shards of stale state behind.
- **How do I sync identities with a directory service?** Wrap the upstream events into a proxy enzyme that emits `sig_being_sync` impulses, call `cep_being_claim` with the authoritative metadata, and let Layer 1 coalesce revisions before exposing them to the rest of the tree.
- **What if a facet plugin fails repeatedly?** The heartbeat keeps the work item parked in `/bonds/facet_queue`. Record failures into the context's `meta/` dictionary or escalate through telemetry so operators can remediate without dropping history.
