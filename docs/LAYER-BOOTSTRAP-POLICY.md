# Bootstrap Policy for Upper Layers

## Introduction
CEP’s kernel (Layer 0) must start, run, and shut down without assuming any higher-layer packs are present. This policy explains how optional packs should compose with the kernel so bootstrap sequences stay deterministic and tests remain modular.

## Technical Details
- **Kernel-first mindset**  
  - The kernel only guarantees `cep_l0_bootstrap`, heartbeat primitives, and shared services (namepool, journal, storage). All other components are optional.  
  - Kernel code and tests must succeed with zero upper-layer state; stubbing or mocking those packs is fine, but never require them for basic coverage.

- **Designing an upper-layer pack**  
  - Treat the pack as a plugin that calls into public L0 APIs. Its bootstrap should probe for prerequisites (for example, heartbeat readiness) and bail out cleanly if unavailable.  
  - Registration should be idempotent. Repeated calls must verify existing descriptors or state rather than mutating blindly.  
  - Readiness evidence belongs to the pack itself. Publish it through an operation timeline (for example, `op/pack_boot`) or a pack-owned subtree only after the pack has prepared its storage and registered enzymes.
  - Startup and shutdown operations progress one beat at a time; keep stepping the heartbeat until the expected `ist:*` or `sts:*` state is visible on `/rt/ops/<boot_oid>` before assuming the kernel is ready.

- **Testing packs**  
  - Provide explicit helpers (e.g., `bool mypack_bootstrap(void)`) so tests can opt-in.  
  - Keep pack-specific fixtures in dedicated suites or feature-gated blocks. Kernel CI should run with packs disabled unless a suite explicitly enables them.  
  - When packs depend on one another, document the ordering and require callers to perform each bootstrap in sequence.

- **Shutdown discipline**  
  - Offer a `*_shutdown()` routine that releases pack-local resources and marks its lifecycle scope as `teardown`.  
  - Kernel shutdown (`cep_heartbeat_emit_shutdown`) should succeed whether or not a pack ran; missing teardown hooks must not crash the heartbeat.

## Global Q&A
- **Can a pack preload kernel state for convenience?**  
  No. Import data through the pack’s public bootstrap or ingest helpers so dependency direction stays “kernel → pack”, never the reverse.

- **How do I detect whether a pack is available?**  
  Expose a feature flag or capability bit (for example, `cep_features_has("coherence")`) rather than probing for internal structures.

- **What about experimental packs under active development?**  
  Keep them disabled by default. Document setup steps in the pack’s README and add feature gates so production kernels run unchanged while experimentation continues.
