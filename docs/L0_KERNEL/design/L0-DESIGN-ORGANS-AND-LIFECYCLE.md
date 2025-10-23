# L0 Design: Organ Descriptors and Lifecycle

## Nontechnical Summary
Organs are Layer 0’s plug-in modules: each describes a subtree, optional constructor/destructor, and validator enzyme. During bootstrap the kernel reads these descriptors, invokes constructors to provision state, and later runs validators and destructors during shutdown. The design keeps organs declarative—descriptors are immutable, lifecycles are beat-aware, and tooling can inspect active organs by reading cells under `/sys/organs`.

## Decision Record
- Organ descriptors are immutable once registered; updates require a new descriptor to preserve replay fidelity.
- Constructors, validators, and destructors execute as enzymes, inheriting determinism and audit trails from the heartbeat.
- Organ registration is idempotent: repeated descriptors with the same identity reuse existing state instead of mutating blindly.
- Lifecycle scopes mark readiness and teardown progress so packs can coordinate dependence ordering.
- Validation failures surface as structured outcomes, allowing packs to quarantine organs without crashing the kernel.

## Subsystem Map
- Code
  - `src/l0_kernel/cep_organ.c`, `cep_organ.h` — descriptor definitions, registration, lifecycle helpers.
  - `src/l0_kernel/cep_enzyme_bindings.c` — binds lifecycle enzymes to organ cells.
  - `src/l0_kernel/cep_ops.c` (interaction) — lifecycle scopes emit OPS states for bootstrap/teardown.
- Tests
  - `src/test/l0_kernel/test_organ_dossiers.c` — descriptor parsing, field validation.
  - `src/test/l0_kernel/test_organ_validators.c` — validator execution ordering and failure handling.
  - `src/test/l0_kernel/test_enzyme.c` — ensures lifecycle enzymes respect binding inheritance and determinism.

## Operational Guidance
- Keep organ constructors idempotent; they may run during replay or recovery scenarios.
- Validators should produce actionable diagnostics and avoid side effects beyond reporting failures.
- Organ descriptors must declare storage/DT choices explicitly so audit tooling recognises owned branches.
- When adding packs, document dependency chains and ensure lifecycle scopes mark readiness before downstream organs start.
- Track lifecycle telemetry (ready/teardown beats, failure codes) for observability dashboards; these are critical for diagnosing boot issues.

## Change Playbook
1. Review this design doc plus `docs/L0_KERNEL/topics/ORGANS-AUTHORING.md`, `docs/L0_KERNEL/L0_ROADMAP.md`, and lifecycle sections in `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md`.
2. Extend `cep_organ.c/h` with new descriptor fields or lifecycle behaviour, keeping descriptors immutable post-registration.
3. Update or author tests in `test_organ_dossiers.c`, `test_organ_validators.c`, and related enzyme suites to cover the change.
4. Run `meson test -C build --suite organs` (and adjacent suites), then `python tools/check_docs_structure.py` and `meson compile -C build docs_html`.
5. Update documentation (topics, integration guide) describing organ expectations and lifecycle flags.
6. Plan migrations carefully—introduce new descriptors alongside old ones, migrate state, then retire legacy descriptors once replay coverage is secured.

## Global Q&A
- **How do organs differ from packs?** Organs are Layer 0 components defined by immutable descriptors; packs may bundle multiple organs plus higher-layer logic but still register through the same mechanism.
- **Can I mutate a descriptor after registration?** No. Descriptors live under `/sys/organs` append-only. Publish a new descriptor version instead.
- **What happens when a validator fails?** The heartbeat records the failure in the organ outcome cell, marks the lifecycle scope accordingly, and packs can react (e.g., disable the organ) without crashing the kernel.
- **Do destructors run during every shutdown?** Yes. Shutdown operations invoke destructors in dependency order so resources release deterministically.
- **How are organ dependencies expressed?** Use lifecycle scopes and documentation; organs should emit readiness signals before dependents start, and teardown should respect the reverse order to avoid dangling references.
