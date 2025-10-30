# L0 Topic: Mailbox CEI Mapping

## Introduction
CEP ships with a default diagnostics mailbox so kernel code can deposit useful facts even when no packs are attached yet. This note explains, in plain terms, which kinds of situations map to which diagnostics severity and where those facts land. Treat it as a checklist when you need to raise an alert: pick the topic, read the matching severity, and make sure the message reaches the proper mailbox.

## Technical Details
- **Default destination** — The diagnostics mailbox lives at `/data/mailbox/diag`. Every CEI helper defaults to it unless a caller explicitly chooses a different mailbox. The bootstrap sequence guarantees the mailbox exists before regular runtime work begins.
- **Severity mapping**
  - `sev:usage` — User or pack misuse (for example, appending to an immutable branch or invoking a verb out of order). Facts stay actionable but non-fatal; the runtime continues operating normally.
  - `sev:warn` — Suspicious state the kernel can still tolerate (for example, slow IO during serialization). Warnings surface in diagnostics dashboards but do not trigger shutdown.
  - `sev:crit` — Kernel integrity risks (namepool exhaustion, control loop failures, serialization corruption). Critical entries trigger automatic shutdown via the control heartbeat helpers.
  - `sev:fatal` — Reserved for unrecoverable invariants. Emitting a fatal CEI fact immediately enters shutdown even if the heartbeat was mid-beat.
- **Topic conventions** — Topics are short, slash-delimited tokens that group related regulators. Examples added in this iteration:
  - `control/prr` — Control heartbeat failures (pause/resume/cutover stages).
  - `namepool.*` — Namepool allocation risks (`namepool.page.alloc`, `namepool.store.slot`, etc.).
  - `serialization.*` — Chunk emission or parsing anomalies.
- **Subject selection** — Helpers try to attach a canonical cell or operation dossier when available. Link pointers are resolved to their normal target so dashboards reflect the real actor.
- **Signal emission** — Critical and fatal facts set `emit_signal = true`; the heartbeat schedules a follow-up impulse so observers can react immediately. Usage and warning facts let callers choose whether to raise a signal.

## Q&A
- **Why map severities instead of letting callers choose arbitrarily?**  Consistent mapping keeps dashboards readable and ensures automation (such as shutdown triggers) reacts at the right level.
- **Can a pack override the diagnostics mailbox?**  Yes. Provide your own mailbox path in the CEI request; the helpers fall back to `/data/mailbox/diag` only when no subject-specific mailbox is given.
- **When should I emit `sev:fatal`?**  Almost never. Critical errors already force shutdown; reserve fatal for invariants that indicate memory corruption or other irrecoverable damage.
- **Do topics need to be pre-registered?**  No. Topics are plain text. Follow the documented conventions so downstream tooling can group related facts.
