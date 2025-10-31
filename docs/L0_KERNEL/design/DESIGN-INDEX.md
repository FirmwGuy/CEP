# L0 Design: Document Index

## Introduction
This index tracks the planned and published design papers for Layer 0 so contributors know which subsystems already have rationale documented and which ones still need deep dives.

## Technical Details
| Design Doc | Status | Scope | Notes |
| --- | --- | --- | --- |
| `docs/L0_KERNEL/design/L0-DESIGN-HEARTBEAT-AND-OPS.md` | Published | Heartbeat loop, agenda build, OPS lifecycle | Captures determinism guarantees, awaiter mechanics, and shutdown sequencing. |
| `docs/L0_KERNEL/design/L0-DESIGN-SERIALIZATION.md` | Published | Serialization writer/reader, chunk protocol, replay safety | Documents manifest structure, transaction staging, and proxy participation. |
| `docs/L0_KERNEL/design/L0-DESIGN-CELL-AND-STORE.md` | Published | Cell lifecycle, store backends, append-only history | Explains invariants behind `cep_cell.*` and storage adapters. |
| `docs/L0_KERNEL/design/L0-DESIGN-PROXY-AND-HANDLES.md` | Published | Proxy cells, external handles, library adapters | Covers lifecycle guarantees for foreign resources and serialization hooks. |
| `docs/L0_KERNEL/design/L0-DESIGN-NAMEPOOL-AND-NAMING.md` | Published | Domain/tag encoding, namepool lifecycle | Document glob rules, intern semantics, and collision handling (future work). |
| `docs/L0_KERNEL/design/L0-DESIGN-ORGANS-AND-LIFECYCLE.md` | Published | Organ descriptors, ctor/dtor/validator lifecycle | Capture invariants for organ authoring, validation, and bootstrap/teardown sequencing. |
| `docs/L0_KERNEL/design/L0-DESIGN-CEI.md` | Published | Common Error Interface helper, diagnostics mailbox, severity policies | Records why CEI centralises error emission, how severity affects OPS/shutdown, and where diagnostics live. |
| `docs/L0_KERNEL/design/L0-DESIGN-E3-EPISODIC-ENGINE.md` | Published | Episodic engine, executor backends, Rendezvous migration | Details the deterministic episode lifecycle, TLS guardrails, and backend guarantees. |

## Global Q&A
- **How do I request a new design paper?** Add it to this index with status `Planned`, then follow the design guide to scope and author the document.
- **What happens when a design doc ships?** Update the status to `Published`, reference it from the orientation guide, and add it to `docs/DOCS-INDEX.md`.
- **Do design docs replace topic notes?** No. Topics explain “how”; design docs record “why” and the invariants that must stay true.
