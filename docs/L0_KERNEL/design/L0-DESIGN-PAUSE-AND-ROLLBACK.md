# L0 Design: Pause, Rollback, and Resume

## Introduction
Pause/Rollback/Resume (PRR) lets operators freeze work, roll back the visible beat horizon, and resume without breaking determinism. Think of Pause as closing the theater doors, Rollback as rewinding the visible scene, and Resume as reopening with the same script. This design explains the control verbs, the evidence they leave (OPS/CEI/mailboxes), and the guardrails that keep PRR replayable.

## Control surface (what you see)
- **OPS dossiers:** `op/pause`, `op/rollback`, `op/resume` all use `opm:states` so watchers can await `ist:*`.
  - Pause: `ist:plan → ist:quiesce → ist:paused → sts:ok`
  - Rollback: `ist:plan → ist:cutover → ist:ok → sts:ok`
  - Resume: `ist:plan → ist:run → ist:ok → sts:ok`
- **Published flags:** Pause sets `/sys/state/paused=true`; Rollback sets `/sys/state/view_hzn=<beat>`; Resume clears both (view horizon to `CEP_BEAT_INVALID`).
- **APIs:** `cep_runtime_pause()`, `cep_runtime_rollback(target_beat)`, `cep_runtime_resume()` enqueue the control ops, refuse conflicting requests, and capture the rollback target.

## How gating works
- **Allow list during gating:** only control signals (pause/resume/rollback/shutdown), `op/cont`, `op/tmo`, and CEI pass through. Everything else is parked.
- **Locks:** Pause grabs hierarchical read locks on `/data` (store + data locks) before gating; Resume releases them after draining the backlog.
- **Backlog mailbox:** Parked impulses go to `/data/mailbox/impulses` with full signal/target `cepDT` segments and QoS flags. IDs are deterministic (`cep_mailbox_select_message_id`) so replay order is stable.
- **QoS bits:** `CONTROL` (never parked), `RETAIN_ON_PAUSE` (default for kernel impulses), `DISCARD_ON_ROLLBACK` (drop before replaying backlog after rollback).
- **Draining:** Resume disables gating, drains messages in ID order, and re-enqueues them for the next beat—no surprises for enzyme ordering.

## Rollback specifics
- **View horizon:** published at `/sys/state/view_hzn`. Consumers can use it as “as-of beat” while paused.
- **Impulse cleanup:** messages marked `DISCARD_ON_ROLLBACK` are dropped before re-enqueue; others survive.
- **Namepool:** must be reactivated before Resume so descriptor interning works after horizon moves.

## Failure paths and evidence
- **State-machine guardrails:** transitions only advance on new beats. If a phase fails (locks, OPS write, backlog drain), the op closes with `sts:fail` and the wrapper returns false.
- **Diagnostics:** CEI continues to emit into `/data/mailbox/diag` even while gated. Failures ride both CEI and OPS history.
- **Heartbeat continues:** OPS expiry, CEI emission, and control watchers still advance; only non-allowed impulses are parked.

## Quick operator walkthrough
1. Call `cep_runtime_pause()`. Watch `/rt/ops/<oid>` for `ist:paused`; `/sys/state/paused` flips to true.
2. Optional: call `cep_runtime_rollback(target)` to set `/sys/state/view_hzn`. Impulses tagged discard-on-rollback are dropped.
3. Call `cep_runtime_resume()`. It drains the backlog in order, clears `/sys/state/paused` and `/sys/state/view_hzn`, and closes with `sts:ok`.

## Q&A
**What if Pause and Rollback race?**  
Control wrappers refuse conflicting ops; only one PRR op can be active. Use watchers to await `sts:ok` before issuing another.

**Does CEI stop during Pause?**  
No. CEI is on the allow list; diagnostics keep flowing to `/data/mailbox/diag`.

**Can I keep some impulses from replaying after rollback?**  
Yes—emit them with `DISCARD_ON_ROLLBACK`. Everything else is retained and re-enqueued.

**How do I know PRR stayed deterministic?**  
Check `/rt/ops/<oid>` history for each control op, `/data/mailbox/impulses` order/contents, and CEI topics emitted during gating. Replay consumes the same parked messages in the same order.
- IO/timer shims stay armed for control continuations; external effects remain staged until resume completes.

## Q&A
**Q: Why keep the heartbeat running during Pause instead of freezing beats entirely?**  
Because the OPS dossiers, CEI TTLs, and watcher expirations all depend on beat edges. By gating non-control impulses we preserve those guarantees without forfeiting observability or determinism.

**Q: What happens to impulses flagged `CEP_IMPULSE_QOS_DISCARD_ON_ROLLBACK`?**  
Rollback prunes them from `/data/mailbox/impulses` before publishing the new view horizon. Nothing re-enqueues them, so replay and audit runs never observe those impulses after the rollback.

**Q: Can I call `cep_runtime_resume()` if Pause is still processing transitions?**  
No. The wrapper verifies that the pause dossier finished (`pause.closed == true`) before starting Resume. If you need to force a resume while Pause is mid-flight, inspect `/rt/ops/<pause_oid>` to understand why it stalled.
