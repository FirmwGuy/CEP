# L0 Topic: Common Error Interface (CEI)

## Introduction
CEI is Layer 0’s single voice for reporting faults. Instead of scattering ad-hoc log lines or bespoke signals, kernel code now emits one structured Error Fact that lands in a deterministic diagnostics mailbox, can page listeners through `sig_cei/*`, and—when required—updates an operation dossier or triggers shutdown. Think of it as a shared inbox and siren for problems: drop a fact in, the kernel records when and where it happened, and every interested consumer can react without guessing how the message was formed.

## Technical Details

### Diagnostics mailbox bootstrap
- Layer 0 creates `/data/mailbox/diag` during `cep_heartbeat_bootstrap()`. It is a dictionary mailbox with `meta/kind="diagnostic"`, ready-made `meta/runtime` buckets, and a `msgs/` store for entries.
- `cep_cei_diagnostics_mailbox()` exposes that mailbox so helpers and packs can inspect or override it. Callers may supply their own mailbox root in a request, but the diagnostics mailbox is always available as a fallback.
- TTL handling reuses the mailbox helpers. Requests can mark entries as forever, provide beat TTLs, or wall-clock windows; resolved deadlines are recorded under `meta/runtime/expiries*` so retention enzymes can sweep them.

### Error Fact layout
- Each emission creates a `msgs/<id>/err/` dictionary. Fields include:
  - `sev` → `sev:fatal|sev:crit|sev:usage|sev:warn|sev:debug`.
  - `note` (UTF‑8 message), `topic` (intern-friendly routing string), optional `code` and `payload_id`.
  - `origin/kind` and `origin/name` describe the module or enzyme that raised the fact.
  - `role_subj` is a link to the subject cell when the request names one.
  - `issued_beat` / `issued_unix` capture the deterministic timeline (beats and nanoseconds).
- Facts are sealed immutable before the transaction commits so replay observes the same evidence.

### Emission flow
- `cep_cei_emit(const cepCeiRequest*)` stages the Error Fact, selects a message identifier (preferring caller-provided mailboxes when present), writes TTL metadata, and commits through the usual mailbox transaction.
- Requests support optional signal emission. When `emit_signal=true`, the helper enqueues `sig_cei/<severity>` for `cep_heartbeat_next()` and records the impulse under `rt/beat/<n>/impulses`.
- Severity policies are enforced centrally:
  - `sev:crit` and `sev:usage` close attached operations with `sts:fail` when `attach_to_op=true`.
  - `sev:fatal` does the same and invokes `cep_heartbeat_emit_shutdown()` so the kernel begins the orderly teardown (`op/shdn`).
- Callers may pass a subject path and topic independently; the helper can derive a target path for impulses by calling `cep_cell_path` when only a cell pointer is available.

### Integration points
- Mailbox retention continues to run through `cep_mailbox_plan_retention()`. CEI facts honour the same expiry buckets, so existing retention enzymes transparently pick them up.
- OPS dossiers receive fail/summary updates through the regular APIs; no new storage structures were introduced.
- Observability tools can either read the diagnostics mailbox (`/data/mailbox/diag/msgs/<id>/err/…`) or watch the `sig_cei/*` namespace to escalate alerts.

## Global Q&A
- **Do I have to use the diagnostics mailbox?** No. Provide `mailbox_root` in the request to route the fact elsewhere; CEI falls back to the diagnostics mailbox only when none is supplied.
- **How do I add context beyond the note?** Use `payload_id` to reference a CAS entry or stream snapshot. Dashboards can resolve the identifier to fetch richer context.
- **Will CEI flood heartbeat agendas?** Each emission queues at most one impulse (`sig_cei/<severity>`) and rides the normal mailbox retention path. Severity policies gate the extra work (OPS updates, shutdown) so background warnings remain lightweight.
