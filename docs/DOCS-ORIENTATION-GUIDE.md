# CEP Documentation Orientation Guide

## Introduction
When you jump back into CEP, this cheat sheet points you straight to the docs that matter most so you can refresh key ideas without rereading the entire library every session. A full inventory lives at the end of this guide for quick status checks.

## Technical Details
- **Core Architecture**
  - `docs/CEP.md` — Big-picture mission and vocabulary; skim first to align terminology.
  - `docs/CEP-Implementation-Reference.md` — Deterministic contract digest covering cells, stores, transports, episodes, higher-layer invariants, and the shipping Enclave policy loader/enforcement workflow.
- **Layer 1 coherence + pipelines**
  - `docs/L1_COHERENCE/README.md` — Scope for beings/bonds/contexts/facets plus the flow runtime surface under `/data/flow/**` (pipelines, runtime runs, metrics, annotations).
- `docs/L0_KERNEL/design/L0-DESIGN-ENCLAVE.md` — Enclave architecture: policy loader, gateways/edges, pipeline approvals, diagnostics, and invariants behind `cep_enclave_policy`.
- `docs/L0_KERNEL/topics/ENCLAVE-OPERATIONS.md` — Operator workflow for policy edits, pipeline preflight, diagnostics, and the regression test matrix.
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
  - `docs/L0_KERNEL/design/L0-DESIGN-CPS.md` — CPS storage architecture, CAS caching, metrics, fixtures, and operational guidance.

- **Runtime & Lifecycle**
  - `docs/LAYER-BOOTSTRAP-POLICY.md` — Kernel vs. pack responsibilities during bootstrap.
  - `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md` — Boot/shutdown operation timeline, states, and awaiter guidance.
  - `docs/L0_KERNEL/topics/CEI.md` — Emission helper, diagnostics mailbox defaults, and severity rules for CEI facts.
  - `docs/L0_KERNEL/topics/HEARTBEAT-AND-ENZYMES.md` — Beat phases, agenda ordering, and signal staging contracts.
  - `docs/L0_KERNEL/topics/PIPELINES-AND-HYDRATION.md` — Friendly walkthrough of L0 pipeline metadata, cross-enclave approvals, and safe hydration for pipeline-aware enzymes.
  - `docs/L0_KERNEL/topics/CACHE-AND-CONTROLLERS.md` — Cache/branch controller overview: policies, history windows, flush triggers, telemetry, and CEI.
  - `docs/L0_KERNEL/topics/MAILBOX-LIFECYCLE.md` — Mailbox identity helpers, TTL precedence, and retention planning.
- `docs/L0_KERNEL/topics/MAILBOX-CEI-MAPPING.md` — Line-by-line severity map for mailbox helpers so CEI emits stay consistent.
- `docs/L0_KERNEL/topics/CELL-BOUND-ENZYME-BINDINGS.md` — Binding inheritance, wildcard routing, and tombstones.
- `docs/L0_KERNEL/topics/CELL-OPERATIONS-ENZYMES.md` — Reference semantics for the standard `sig_cell/op_*` helpers.
- `docs/L1_COHERENCE/README.md` — Landing spot for all Layer 1 coherence/pipeline docs and future pack notes.
- `docs/L1_COHERENCE/ADJACENCY-CLOSURE.md` — Sketch of the coherence closure/debt contract for contexts, facets, and adjacency sweeps.
- `docs/L0_KERNEL/topics/FEDERATION-TRANSPORT.md` — Transport manager duties, capability negotiation rules, the `/net` schema for peers/catalog/telemetry, and the discovery/health/link/mirror/invoke validators (now all flat-serializer by default).
- `docs/L0_KERNEL/topics/ORGANS-AUTHORING.md` — Register organ descriptors, enforce validator bindings, and coordinate ctor/dtor/validation ops.
  - `docs/L0_KERNEL/topics/E3-EPISODIC-ENGINE.md` — How the Episodic Enzyme Engine (E3) handles RO budgets, hybrid RO↔RW promotions/demotions, and cooperative cancellation.
  - `docs/L0_KERNEL/design/L0-DESIGN-E3-EPISODIC-ENGINE.md` — Episodic engine design rationale, executor backends, and queue invariants.
- **External Integrations**
- `docs/L0_KERNEL/topics/SERIALIZATION-AND-STREAMS.md` — Flat-frame record taxonomy, capability negotiation, AEAD/compression knobs, and replay expectations.
- Flat serializer wire-level specification — captures record layouts, env selectors (history, AEAD, compression), and reference frames for tooling/tests.
  - `docs/L0_KERNEL/topics/IO-STREAMS-AND-FOREIGN-RESOURCES.md` — Effect logging, CAS, and preconditions around I/O.
  - `docs/L0_KERNEL/topics/EXTERNAL-LIBRARIES-INTERFACE.md` — Adapter vtable responsibilities, snapshot vs. handle rules.
  - `docs/L0_KERNEL/topics/PROXY-CELLS.md` — Proxy cell lifecycle and serialization hooks.
  - `docs/ROOT-DIRECTORY-LAYOUT.md` — Expected runtime directory tree created during bootstrap.

- **Tooling & Planning**
- `docs/BUILD.md` — Meson/Ninja workflow, option reference (including the `zlib_provider` system-vs-bundled switch), and sanitizer toggles before compiling or running tests.
- `docs/L0_KERNEL/topics/DEBUG-MACROS.md` — Debug-only macro behavior, asserts inside control flow, and release-build caveats.
- `docs/TEST-WATCHDOG-GUIDE.md` — Harness watchdog expectations, tracing controls, and Organ Validation Harness (OVH) fixtures.
- `docs/TOOLS.md` — Repo scripts for fixtures, code maps, and Doxygen post-processing.
- `docs/L0_KERNEL/L0_ROADMAP.md` — Active milestones, TODO markers, and planned helper work.
- Dual-runtime harness — run `meson test runtime_dual_default` (or the generated Valgrind variant when available) to prove multi-instance isolation after touching runtime plumbing; the runtime context walkthrough lives in `docs/L0_KERNEL/L0-OVERVIEW.md`.
- `docs/L0_KERNEL/topics/RAW-TRAVERSAL-HELPERS.md` — Upcoming `*_all` traversal APIs; recheck before touching traversal internals.
- `docs/L0_KERNEL/design/DESIGN-INDEX.md` — Status board for Layer 0 design papers.
  - `docs/L0_KERNEL/design/L0-DESIGN-GUIDE.md` — Expectations for the new Design document tier that records architectural rationale.
- `docs/L0_KERNEL/design/L0-DESIGN-HEARTBEAT-AND-OPS.md` — Rationale behind beat ordering, enzyme dependencies, and OPS timelines.
- `docs/L0_KERNEL/design/L0-DESIGN-E3-EPISODIC-ENGINE.md` — Why the episodic engine replaces Rendezvous, how watcher/lease invariants fit, and what executor backends guarantee.
- `docs/L0_KERNEL/design/L0-DESIGN-FEDERATION.md` — Federation transport architecture, covering Beats 0–3, transport manager duties, and the link/mirror/invoke organ contracts plus diagnostics.
- `docs/L0_KERNEL/design/L0-DESIGN-PAUSE-AND-ROLLBACK.md` — Control-plane design for Pause/Rollback/Resume, backlog policy, and heartbeat gating.
- `docs/L0_KERNEL/design/L0-DESIGN-SERIALIZATION.md` — Design trade-offs for manifests, chunking, and replay safety.
- `docs/L0_KERNEL/design/L0-DESIGN-ASYNC-IO.md` — Async I/O fabric plan covering the reactor, serialization/federation integrations, CPS async commits, and telemetry expectations.
- `docs/L0_KERNEL/design/L0-DESIGN-CELL-AND-STORE.md` — Why cells stay append-only and how store backends uphold invariants.
- `docs/L0_KERNEL/design/L0-DESIGN-PROXY-AND-HANDLES.md` — Lifecycle rules for proxy payloads, adapters, and external handles.
- `docs/L0_KERNEL/design/L0-DESIGN-NAMEPOOL-AND-NAMING.md` — Domain/Tag rationale, glob semantics, and namepool lifecycle.
- `docs/L0_KERNEL/design/L0-DESIGN-ORGANS-AND-LIFECYCLE.md` — Organ descriptors, constructors/validators, and teardown guarantees.
- `docs/L0_KERNEL/design/L0-DESIGN-CEI.md` — Rationale for centralising CEI emission, diagnostics mailbox bootstrap, and severity-to-shutdown policies.
  - `docs/L0_KERNEL/design/L0-DESIGN-MAILBOX-LIFECYCLE.md` — Rationale behind mailbox identity precedence, TTL policy resolution, and retention buckets.
  - `docs/L0_KERNEL/design/L0-DESIGN-CPS.md` — Persistent storage layer design, CAS cache behaviour, metrics, ops verbs, and fixture workflow.

- **Contextual (Read Once, Revisit When Needed)**
  - `docs/LICENSING.md` — Licensing split across core, tests, and third-party components.
  - `docs/CEP-FOR-PL-SQL-DEVS.md` — Translation layer for database-centric contributors.
  - `docs/Doxyfile.in` — Doxygen template; helpful when altering documentation tooling.
  - `docs/GLOSSARY.md` — Acronyms and terminology cheat sheet for non-specialists.

## Global Q&A
- **What do I skim every time I start coding?** Revisit the Core Architecture block, then dip into Data & Storage or Runtime sections that match the subsystem you plan to touch.
- **When do I open the External Integrations docs?** Any time you touch serialization, streams, handles, or proxy cells—those docs spell out determinism rules the kernel must follow.
- **How do I add new terminology?** Update `docs/CEP-TAG-LEXICON.md` first, then reference the new tag in code or docs; this keeps tooling and reviewers aligned.
- **Where do I check pending work before drafting helpers?** Review `docs/L0_KERNEL/L0_ROADMAP.md` and `docs/L0_KERNEL/topics/RAW-TRAVERSAL-HELPERS.md` to confirm whether a feature already has an assigned plan or TODO marker.
- **Do I need to reread contextual docs each session?** No—use the Contextual section when your task involves licensing, onboarding translations, or documentation tooling. For daily kernel work, the earlier sections should be enough.

## Documentation Inventory
## Introduction
This index maps every document in `docs/` to the parts of CEP it describes so contributors can tell, at a glance, whether a guide reflects shipping code or forward-looking plans. Treat it as the hub you consult before editing a document or searching for design intent.

## Technical Details
The table below groups documents by their owning modules or features. The **Status** column distinguishes between live Layer 0 code, planned upper layers, and mixed coverage. **Notes** call out any pending rewrites or reminders uncovered during the October 2025 audit.

| Document | Primary Purpose | Owning Modules / Features | Status | Notes |
| --- | --- | --- | --- | --- |
| `docs/BUILD.md` | Build workflows, Meson/Ninja options, platform setup | Tooling: Meson/Ninja configs, test harness | Live | Matches current Meson options; keep fallback Makefile steps in sync with `unix/Makefile`. |
| `docs/CEP.md` | Conceptual overview of CEP across all layers | Layer 0 kernel (live), Layers 1–4 (planned) | Mixed | Layer 0 sections align with shipped code; higher-layer coverage remains aspirational and is labelled as such. |
| `docs/CEP-FOR-PL-SQL-DEVS.md` | Onboarding bridge for SQL-centric engineers | Layer 0 API surface, higher-layer concepts (planned) | Mixed | Keep terminology aligned with `docs/CEP-TAG-LEXICON.md`; note that policy/governance layers remain future work. |
| `docs/L1_COHERENCE/README.md` | Layer 1 coherence/pipeline doc home | Layer 1 pack (coherence + pipelines) | Live | Add future L1 docs under this directory; keep the index in sync. |
| `docs/L1_COHERENCE/ADJACENCY-CLOSURE.md` | Contract sketch for coherence adjacency closure and debts | Layer 1 pack (coherence closure) | Draft | TODO hooks for enzymes/CEI; use as design reference before implementation. |
| `docs/CEP-TAG-LEXICON.md` | Canonical tag catalogue and naming rules | Domain/tag encoding, namepool tooling | Live | Run `tools/check_unused_tags.py` after expanding the table. |
| `docs/L0_KERNEL/topics/DEBUG-MACROS.md` | Debug macro behaviour and usage patterns | `src/l0_kernel/cep_molecule.h`, debug flags | Live | No drift detected; ensure new debug wrappers get documented here. |
| `docs/DOCS-ORIENTATION-GUIDE.md` | Reading map for contributors returning to the repo | Documentation navigation | Live | Updated whenever new doc categories (e.g., Design docs) join the set. |
| `docs/LAYER-BOOTSTRAP-POLICY.md` | Policy for optional packs bootstrapping alongside the kernel | Lifecycle scopes, `op/boot` interplay | Live | Mirrors current startup/shutdown guarantees; cross-check with `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md`. |
| `docs/LICENSING.md` | Licensing breakdown for code and third-party assets | Legal notices | Live | No changes required; reference when adding dependencies. |
| `docs/ROOT-DIRECTORY-LAYOUT.md` | Expected runtime filesystem tree | Kernel lifecycle, storage layout | Live | Ensure new directories created during bootstrap are reflected. |
| `docs/TEST-WATCHDOG-GUIDE.md` | Watchdog and test harness expectations | Test harness utilities | Live | Keep in sync with `test/` harness parameters. |
| `docs/TOOLS.md` | Repository helper scripts | `tools/` utilities | Live | Update when adding new scripts or changing entry points. |
| `docs/L0_KERNEL/L0-OVERVIEW.md` | Layer 0 umbrella overview and topic summaries | Cells, stores, lifecycle, topics/ subtree | Live | Now includes paragraphs summarising each topic under `topics/`. |
| `docs/L0_KERNEL/L0-ALGORITHMS.md` | Cross-cutting algorithm explanations | Append-only history, links, traversal, serialization | Live | Add algorithm entries as new cross-cutting behaviours ship. |
| `docs/L0_KERNEL/L0-INTEGRATION-GUIDE.md` | Integration patterns (enzymes, serialization, proxies) | Heartbeat, registry, serialization stack | Live | Includes CEI helper usage alongside OPS and heartbeat integration patterns. |
| `docs/L0_KERNEL/L0-TUNING-NOTES.md` | Performance knobs and anti-patterns | Storage selection, history tuning, serialization parameters | Live | Verify recommendations whenever benchmarks change. |
| `docs/L0_KERNEL/design/DESIGN-INDEX.md` | Status tracker for design docs | Layer 0 subsystems | Live | Lists published and planned design papers. |
| `docs/L0_KERNEL/design/L0-DESIGN-GUIDE.md` | Structure for new Design documents | Design rationale workflow | Live | Use as the template when adding `L0-DESIGN-*.md` papers. |
| `docs/L0_KERNEL/design/L0-DESIGN-HEARTBEAT-AND-OPS.md` | Beat + OPS rationale | Heartbeat loop, OPS lifecycle | Live | Documents determinism guarantees and watcher mechanics. |
| `docs/L0_KERNEL/design/L0-DESIGN-PAUSE-AND-ROLLBACK.md` | Control-plane design | Pause/Rollback/Resume ops, backlog policy | Draft | Explains control dossiers, heartbeat gating, and mailbox-backed backlog behaviour. |
| `docs/L0_KERNEL/design/L0-DESIGN-SERIALIZATION.md` | Serialization rationale | Manifest, chunking, replay | Live | Records choices behind staging, hashing, and proxy snapshots. |
| `docs/L0_KERNEL/design/L0-DESIGN-CELL-AND-STORE.md` | Cell/store rationale | Append-only history, storage adapters | Live | Explains invariants that keep history and locks correct. |
| `docs/L0_KERNEL/design/L0-DESIGN-PROXY-AND-HANDLES.md` | Proxy/handle rationale | External resources, adapters | Live | Captures lifecycle, serialization, and error propagation rules. |
| `docs/L0_KERNEL/design/L0-DESIGN-NAMEPOOL-AND-NAMING.md` | Naming rationale | Domain/tag encoding, namepool lifecycle | Live | Explains glob semantics, reference IDs, and replay guarantees. |
| `docs/L0_KERNEL/design/L0-DESIGN-ORGANS-AND-LIFECYCLE.md` | Organ rationale | Descriptor lifecycle, validators/destructors | Live | Records boot/shutdown sequencing and validation rules. |
| Design Doc | Status | Scope | Notes |
| `docs/L0_KERNEL/design/L0-DESIGN-CEI.md` | CEI rationale | Diagnostics mailbox bootstrap, severity mapping, shutdown policy | Live | Explains why CEI centralises error facts and how severities drive OPS/shutdown actions. |
| `docs/L0_KERNEL/L0_ROADMAP.md` | Layer 0 milestones + readiness for upper layers | Kernel backlog | Live | Tracks finishing polish plus remaining tasks before L1/L2 integration ramps. |
| `docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md` | Append-only semantics and idempotent operations | Cell mutation paths | Live | Coordinate with `src/l0_kernel/cep_cell.c`. |
| `docs/L0_KERNEL/topics/CELL-BOUND-ENZYME-BINDINGS.md` | Binding enzymes to cells and inheritance rules | Enzyme registry, timeline storage | Live | Matches current binding propagation logic. |
| `docs/L0_KERNEL/topics/CELL-OPERATIONS-ENZYMES.md` | Enzyme helpers for cell operations | Standard enzyme suite | Live | Align with `src/l0_kernel/enzymes/`. |
| `docs/L0_KERNEL/topics/DEVELOPER-HANDBOOK.md` | Hands-on implementation guide for kernel contributors | `cep_cell.*`, storage backends, tests | Live | Restructured with nontechnical intro and final Q&A. |
| `docs/L0_KERNEL/topics/EXTERNAL-LIBRARIES-INTERFACE.md` | Adapters for foreign libraries and handles | Proxy/library ops | Live | Ensure adapter API changes are reflected. |
| `docs/L0_KERNEL/topics/CACHE-AND-CONTROLLERS.md` | Cache/branch controllers and policy knobs | CPS/branch controllers, telemetry, CEI | Live | One-stop overview of flush modes, history windows, CEI topics, and async flow. |
| `docs/L0_KERNEL/topics/GLOB-MATCHING.md` | Domain/tag glob semantics | Naming helpers | Live | Keep examples aligned with `cep_id_matches`. |
| `docs/L0_KERNEL/topics/HEARTBEAT-AND-ENZYMES.md` | Heartbeat phases and enzyme scheduling | Heartbeat engine, registry | Live | Sync with agenda ordering rules. |
| `docs/L0_KERNEL/topics/MAILBOX-LIFECYCLE.md` | Mailbox lifecycle | `cep_mailbox_*`, retention planners | Live | Documents diagnostics mailbox defaults and CEI TTL interplay. |
| `docs/L0_KERNEL/topics/CEI.md` | Common Error Interface helper and diagnostics mailbox usage | `cep_cei_emit`, `sig_cei/*`, OPS severity policies | Live | Pair with the CEI design note before changing error reporting. |
| `docs/L0_KERNEL/topics/IO-STREAMS-AND-FOREIGN-RESOURCES.md` | Streaming payloads and foreign resource lifecycles | Proxy streams, CAS, transaction helpers | Live | Mentions mailroom legacy only as historical context. |
| `docs/L0_KERNEL/topics/LINKS-AND-SHADOWING.md` | Link lifecycle and shadow bookkeeping | `cep_link_*`, `cep_shadow_*` | Live | Verify when link storage changes. |
| `docs/L0_KERNEL/topics/LOCKING.md` | Data/store locking rules | Lock hierarchy checks | Live | Matches `cep_cell_*_locked_hierarchy`. |
| `docs/L0_KERNEL/topics/NATIVE-TYPES.md` | Handling of VALUE/DATA/HANDLE/STREAM payloads | `cepData`, hashing, naming | Live | Examples rely on upper-layer agreements, not kernel features. |
| `docs/L0_KERNEL/topics/ORGANS-AUTHORING.md` | Authoring organ descriptors and lifecycle | Organ registration, validators | Live | Ensure organ descriptor enums stay updated. |
| `docs/L0_KERNEL/topics/PROXY-CELLS.md` | Proxy cell lifecycle and serialization | Proxy adapters | Live | Update when proxy ABI changes. |
| `docs/L0_KERNEL/topics/PIPELINES-AND-HYDRATION.md` | Friendly overview of pipeline metadata and safe hydration | Pipeline metadata, CEI tagging, cross-enclave approval cues | Live | Non-expert walkthrough of pipeline blocks, federation approvals, and `cep_cell_hydrate_for_enzyme()` usage. |
| `docs/L0_KERNEL/topics/RAW-TRAVERSAL-HELPERS.md` | Planned traversal helper APIs | Traversal roadmap | Planned | Pending implementation; reference before adding traversal helpers. |
| `docs/L0_KERNEL/topics/SERIALIZATION-AND-STREAMS.md` | Serialization format and reader/writer APIs | Serialization core | Live | Verify manifest and chunk descriptions against code. |
| `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md` | Boot/shutdown operation timelines | Lifecycle operations | Live | Should be reread before editing lifecycle helpers. |
| `docs/L0_KERNEL/topics/E3-EPISODIC-ENGINE.md` | Episodic Enzyme Engine overview (episodes, budgets, cancellation) | Heartbeat executor, OPS dossiers | Live | Describes queue semantics, RO guardrails, and CEI integration for the shipping executor. |
| `docs/L0_KERNEL/design/L0-DESIGN-E3-EPISODIC-ENGINE.md` | Episodic engine design (lifecycle, executor backends, migration) | Heartbeat executor, OPS dossiers | Live | Explains why E3 unifies long-running work, how budgets/leases interact, and what each backend guarantees. |

### Planned Document Type: Design Papers
Design documents live under `docs/L0_KERNEL/design/` and cover the architectural rationale behind concrete implementations. See `docs/L0_KERNEL/design/L0-DESIGN-GUIDE.md` for structure and expectations.

## Global Q&A
- **How do I tell if a document is still accurate?** Check the **Status** column above and cross-reference with the owning modules; live docs map directly to files under `src/`, while planned docs flag future work.
- **Where do I record discrepancies found during an audit?** Add a note in this index and open an issue or TODO linked to the owning module so the gap is tracked.
- **What if I introduce a new document type?** Update this index and `docs/DOCS-ORIENTATION-GUIDE.md` so the reading map and status table stay current.
- **How do Design documents fit in?** They provide the “why” for APIs—bridging between Overview context and Algorithms detail—without repeating how-to steps from Implementation Guides.
