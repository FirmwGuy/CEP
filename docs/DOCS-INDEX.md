# CEP Documentation Inventory

## Introduction
This index maps every document in `docs/` to the parts of CEP it describes so contributors can tell, at a glance, whether a guide reflects shipping code or forward-looking plans. Treat it as the hub you consult before editing a document or searching for design intent.

## Technical Details
The table below groups documents by their owning modules or features. The **Status** column distinguishes between live Layer 0 code, planned upper layers, and mixed coverage. **Notes** call out any pending rewrites or reminders uncovered during the October 2025 audit.

| Document | Primary Purpose | Owning Modules / Features | Status | Notes |
| --- | --- | --- | --- | --- |
| `docs/BUILD.md` | Build workflows, Meson/Ninja options, platform setup | Tooling: Meson/Ninja configs, test harness | Live | Matches current Meson options; keep fallback Makefile steps in sync with `unix/Makefile`. |
| `docs/CEP.md` | Conceptual overview of CEP across all layers | Layer 0 kernel (live), Layers 1–4 (planned) | Mixed | Layer 0 sections align with shipped code; higher-layer coverage remains aspirational and is labelled as such. |
| `docs/CEP-FOR-PL-SQL-DEVS.md` | Onboarding bridge for SQL-centric engineers | Layer 0 API surface, higher-layer concepts (planned) | Mixed | Keep terminology aligned with `docs/CEP-TAG-LEXICON.md`; note that policy/governance layers remain future work. |
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
| `docs/L0_KERNEL/design/L0-DESIGN-CEI.md` | CEI rationale | Diagnostics mailbox bootstrap, severity mapping, shutdown policy | Live | Explains why CEI centralises error facts and how severities drive OPS/shutdown actions. |
| `docs/L0_KERNEL/L0_ROADMAP.md` | Planned Layer 0 refactors and milestones | Kernel backlog | Planned | Outlines work-in-progress items; consult before large kernel edits. |
| `docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md` | Append-only semantics and idempotent operations | Cell mutation paths | Live | Coordinate with `src/l0_kernel/cep_cell.c`. |
| `docs/L0_KERNEL/topics/CELL-BOUND-ENZYME-BINDINGS.md` | Binding enzymes to cells and inheritance rules | Enzyme registry, timeline storage | Live | Matches current binding propagation logic. |
| `docs/L0_KERNEL/topics/CELL-OPERATIONS-ENZYMES.md` | Enzyme helpers for cell operations | Standard enzyme suite | Live | Align with `src/l0_kernel/enzymes/`. |
| `docs/L0_KERNEL/topics/DEVELOPER-HANDBOOK.md` | Hands-on implementation guide for kernel contributors | `cep_cell.*`, storage backends, tests | Live | Restructured with nontechnical intro and final Q&A. |
| `docs/L0_KERNEL/topics/EXTERNAL-LIBRARIES-INTERFACE.md` | Adapters for foreign libraries and handles | Proxy/library ops | Live | Ensure adapter API changes are reflected. |
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
| `docs/L0_KERNEL/topics/RAW-TRAVERSAL-HELPERS.md` | Planned traversal helper APIs | Traversal roadmap | Planned | Pending implementation; reference before adding traversal helpers. |
| `docs/L0_KERNEL/topics/SERIALIZATION-AND-STREAMS.md` | Serialization format and reader/writer APIs | Serialization core | Live | Verify manifest and chunk descriptions against code. |
| `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md` | Boot/shutdown operation timelines | Lifecycle operations | Live | Should be reread before editing lifecycle helpers. |
| `docs/L0_KERNEL/topics/E3-EPISODIC-ENGINE.md` | Episodic Enzyme Engine overview (episodes, budgets, cancellation) | Heartbeat executor, OPS dossiers | Live | Describes queue semantics, RO guardrails, and CEI integration now that E³ replaces Rendezvous. |
| `E3.md` | Episodic Enzyme Engine roadmap (executor queue, RO guard, budgets) | Heartbeat executor, CEI guardrails | Mixed | Executor skeleton and RO budgets implemented; cancellation/resume and OPS dossier wiring still underway. |
| `docs/FEDERATION-DESIGN-SPIKE.md` | Planning notes for the post-E³ federation spike | Federation architecture | Planned | Captures scope, deliverables, and follow-up actions before the formal design doc is written. |

### Planned Document Type: Design Papers
Design documents live under `docs/L0_KERNEL/design/` and cover the architectural rationale behind concrete implementations. See `docs/L0_KERNEL/design/L0-DESIGN-GUIDE.md` for structure and expectations.

## Global Q&A
- **How do I tell if a document is still accurate?** Check the **Status** column above and cross-reference with the owning modules; live docs map directly to files under `src/`, while planned docs flag future work.
- **Where do I record discrepancies found during an audit?** Add a note in this index and open an issue or TODO linked to the owning module so the gap is tracked.
- **What if I introduce a new document type?** Update this index and `docs/DOCS-ORIENTATION-GUIDE.md` so the reading map and status table stay current.
- **How do Design documents fit in?** They provide the “why” for APIs—bridging between Overview context and Algorithms detail—without repeating how-to steps from Implementation Guides.
