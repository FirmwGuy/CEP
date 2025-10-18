# CEP Documentation Orientation Guide

## Introduction
When you jump back into CEP, this cheat sheet points you straight to the docs that matter most so you can refresh key ideas without rereading the entire library every session.

## Technical Details
- **Core Architecture**
  - `docs/CEP.md` — Big-picture mission and vocabulary; skim first to align terminology.
  - `docs/L0_KERNEL/L0-OVERVIEW.md` — Layer‑0 capabilities, storage choices, and lifecycle behaviors that every kernel edit touches.
  - `docs/L0_KERNEL/L0-ALGORITHMS.md` — Cross-cutting invariants (history chains, shadow bookkeeping, traversal) to re-confirm before changing shared helpers.
  - `docs/L0_KERNEL/L0-INTEGRATION-GUIDE.md` — Enzyme dispatch, serialization flows, and proxy wiring that keep integrations deterministic.
  - `docs/L0_KERNEL/L0-TUNING-NOTES.md` — Performance levers, anti-patterns, and store selection guidance for hot-path work.

- **Deterministic Data & Storage**
  - `docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md` — How timelines, timestamps, and immutable seals must behave during mutations.
  - `docs/L0_KERNEL/topics/NATIVE-TYPES.md` — Payload tagging rules, hashing, and canonical byte expectations.
  - `docs/L0_KERNEL/topics/LOCKING.md` — Store/data lock propagation to respect when touching concurrency-sensitive code.
  - `docs/L0_KERNEL/topics/LINKS-AND-SHADOWING.md` — Link lifecycle and backlink invariants that moves/clones/deletes rely on.
  - `docs/CEP-TAG-LEXICON.md` — Canonical tag catalog; extend here before introducing new identifiers.

- **Runtime & Lifecycle**
  - `docs/LAYER-BOOTSTRAP-POLICY.md` — Kernel vs. pack responsibilities during bootstrap.
  - `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md` — Boot/shutdown operation timeline, states, and awaiter guidance.
  - `docs/L0_KERNEL/topics/HEARTBEAT-AND-ENZYMES.md` — Beat phases, agenda ordering, and signal staging contracts.
  - `docs/L0_KERNEL/topics/CELL-BOUND-ENZYME-BINDINGS.md` — Binding inheritance, wildcard routing, and tombstones.
  - `docs/L0_KERNEL/topics/CELL-OPERATIONS-ENZYMES.md` — Reference semantics for the standard `sig_cell/op_*` helpers.
  - `docs/L0_KERNEL/topics/ORGANS-AUTHORING.md` — Register organ descriptors, enforce validator bindings, and coordinate ctor/dtor/validation ops.

- **External Integrations**
  - `docs/L0_KERNEL/topics/SERIALIZATION-AND-STREAMS.md` — Chunk framing, manifest rules, and replay expectations.
  - `docs/L0_KERNEL/topics/IO-STREAMS-AND-FOREIGN-RESOURCES.md` — Effect logging, CAS, and preconditions around I/O.
  - `docs/L0_KERNEL/topics/EXTERNAL-LIBRARIES-INTERFACE.md` — Adapter vtable responsibilities, snapshot vs. handle rules.
  - `docs/L0_KERNEL/topics/PROXY-CELLS.md` — Proxy cell lifecycle and serialization hooks.
  - `docs/ROOT-DIRECTORY-LAYOUT.md` — Expected runtime directory tree created during bootstrap.

- **Tooling & Planning**
  - `docs/BUILD.md` — Meson/Ninja workflow, options, and sanitizer toggles before compiling or running tests.
  - `docs/TOOLS.md` — Repo scripts for fixtures, code maps, and Doxygen post-processing.
  - `docs/L0_KERNEL/L0_ROADMAP.md` — Active milestones, TODO markers, and planned helper work.
  - `docs/L0_KERNEL/topics/RAW-TRAVERSAL-HELPERS.md` — Upcoming `*_all` traversal APIs; recheck before touching traversal internals.

- **Contextual (Read Once, Revisit When Needed)**
  - `docs/LICENSING.md` — Licensing split across core, tests, and third-party components.
  - `docs/CEP-FOR-PL-SQL-DEVS.md` — Translation layer for database-centric contributors.
  - `docs/Doxyfile.in` — Doxygen template; helpful when altering documentation tooling.

## Q&A
- **What do I skim every time I start coding?** Revisit the Core Architecture block, then dip into Data & Storage or Runtime sections that match the subsystem you plan to touch.
- **When do I open the External Integrations docs?** Any time you touch serialization, streams, handles, or proxy cells—those docs spell out determinism rules the kernel must follow.
- **How do I add new terminology?** Update `docs/CEP-TAG-LEXICON.md` first, then reference the new tag in code or docs; this keeps tooling and reviewers aligned.
- **Where do I check pending work before drafting helpers?** Review `docs/L0_KERNEL/L0_ROADMAP.md` and `docs/L0_KERNEL/topics/RAW-TRAVERSAL-HELPERS.md` to confirm whether a feature already has an assigned plan or TODO marker.
- **Do I need to reread contextual docs each session?** No—use the Contextual section when your task involves licensing, onboarding translations, or documentation tooling. For daily kernel work, the earlier sections should be enough.
