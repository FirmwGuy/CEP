# Layer Bootstrap Policy

## Introduction
Each CEP layer must be able to stand up, run, and shut down without depending on higher layers. This separation keeps the bootstrap choreography deterministic, reduces circular test fixtures, and makes it simpler to reason about which subsystems need to be present when you troubleshoot a failing heartbeat.

## Technical Details
- **Layer 0 (Kernel)**  
  - Bootstraps only itself (`cep_l0_bootstrap`, `cep_cell_system_ensure`, heartbeat primitives).  
  - Tests may stub or mock higher-layer behaviour, but must never load L1/L2 helpers.  
  - Any new L0 API or utility must run under the assumption that no mailroom, coherence, or flow state exists yet.
- **Layer 1 (Coherence)**  
  - Builds on L0 primitives, mailroom routing, and namepool services that L0 exposes.  
  - `cep_l1_coherence_bootstrap` must succeed without registering L2 descriptors.  
  - Unit tests should initialise the kernel + mailroom directly, enqueue intents, and verify ledgers without starting the flow VM.
- **Layer 2 (Flows & Rendezvous)**  
  - May rely on L0 + L1 having finished their bootstrap, but must not require higher experimental layers.  
  - Flow/Rendezvous tests should explicitly call the L1 bootstrap helpers they depend on; do not add hidden couplings back into the kernel.
- **Cross-layer tests**  
  - Integration suites can opt-in to multiple layers, but they must do so explicitly (for example through a feature flag such as `CEP_ENABLE_L2_TESTS`).  
  - Default CI runs should keep higher layers disabled unless a test proves their readiness signal can complete without affecting lower-layer determinism.

## Q&A
- **Q: Can a layer pre-load data from a higher layer for convenience?**  
  A: No. Import any state you need via the layer’s public bootstrap or ingest helpers so the dependency direction stays L0 → L1 → L2.
- **Q: How do I test optional packs that sit on top of L2?**  
  A: Create a dedicated test harness that turns those packs on after L2 initialises. Do not add those hooks to the default L0/L1 test paths.
- **Q: What about feature detection during bootstrap?**  
  A: Probe lower layers only. If a feature requires a higher layer, gate it behind an explicit config knob and document that dependency in the feature’s README.
