# CEP Contracts

## Introduction
CEP stays deterministic because a few simple contracts define who owns the runtime, which threads may touch Layer 0, and how optional packs join the party. This note collects those promises in one place so operators, pack authors, and tooling have a single checklist instead of scattered tribal knowledge.

## Technical Details

### Ownership and threading
The heartbeat owner is the only caller allowed to mutate Layer 0 directly. Read-only slices scheduled through the executor are the sole exception, and they run under `cep_executor_submit_ro()`/E3 with a managed `cepEpExecutionContext`. Ad-hoc threads must not call kernel APIs; route work through the heartbeat or an episode instead so determinism, budgets, and CEI guardrails stay intact.

### Runtime state boundaries
Runtime-scoped caches (namepool pages/buckets, organ registry tables, and the cell-op registry baseline) live inside the active `cepRuntime`. Shutdown clears them via `cep_namepool_shutdown()`, `cep_runtime_release_organ_registry()`, and `cep_cell_operations_registry_reset()` so teardown never resurrects fresh caches after callers already freed the previous copy.

### Execution policies
The default execution policy lives in `cepEpRuntimeState` and seeds new slices with a RO profile plus the configured CPU/IO budgets. Executor submissions inherit this runtime-owned default when policy fields are left zeroed; per-episode overrides still win when provided so tests and pack code can tune budgets deterministically.

### Bootstrap and optional packs
Upper layers behave like optional plugins: they use public L0 APIs, piggyback on the `op/boot`/`op/shdn` lifecycle, and must let the kernel start and stop cleanly without them. Bootstrap should be idempotent (re-runs verify existing descriptors instead of mutating blindly), publish readiness through the pack’s own operation or subtree once storage and enzymes are prepared, and rely on CEI instead of bespoke logging. Tests opt in explicitly; kernel boot must succeed with packs absent. Shutdown mirrors the same discipline: provide a `*_shutdown()` hook that releases pack-local resources and marks teardown, and never assume a pack ran just because the kernel did.

### Layer stacking discipline
Each layer only relies on those beneath it: L1 depends on L0, L2 on L1/L0, and so on. No layer should shortcut around lower-layer APIs or reach for higher-layer facilities; keep dependencies one-way so determinism, replay, and bootstrap expectations stay enforceable.

## Q&A
**Q: Can I call kernel APIs from my own thread?**  
No. Use the heartbeat thread for mutations and the executor/E3 for read-only slices. Any other thread risks violating determinism and will miss the TLS context/budget guardrails.

**Q: Where do default CPU/IO budgets come from now?**  
From the runtime. `cepEpRuntimeState` seeds the default policy to RO with the configured budgets, and executor submissions inherit it whenever a policy field is zero. Set `cepEpExecutionPolicy` per episode to override.

**Q: How do I keep teardown from leaking caches?**  
Let shutdown run its course: it resets the cell-op registry baseline, drops the organ registry, and tears down the namepool runtime state instead of reallocating during teardown. Avoid re-initialising those caches from cleanup code.

**Q: How do optional packs fit into the contract?**  
Treat them as plugins that lean on L0: probe prerequisites, publish readiness through your own `op/*` dossier, and keep bootstrap/shutdown idempotent so the kernel remains healthy whether packs are present or not.

**Q: How strict is layer stacking?**  
Treat it as one-way: L1 builds on L0, L2 on L1, etc. If a feature needs lower-layer support, add it there first instead of introducing backdoors from an upper layer.
