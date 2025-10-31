# L0 Design: Pause, Rollback, and Resume

## Introduction
CEP now ships first-class Pause, Rollback, and Resume controls so operators can freeze heartbeat work, rewind the visible beat window, and return to normal execution without violating determinism. This paper captures how the control verbs surface through OPS dossiers, which runtime flags they touch, and where durable evidence lives so tooling can always explain what the kernel did. Use it as the orientation map when reviewing PRR code paths or extending the control plane.

## Technical Details

The following subsections describe how the public control wrappers drive OPS dossiers, gating, backlog retention, and failure paths so that pause/rollback behaviour stays deterministic under replay.
### Control Surface and State Machines
- **OPS dossiers:** Each control verb opens an OPS record under `/rt/ops/*`. The verbs (`op/pause`, `op/rollback`, `op/resume`) share the `opm:states` mode so watchers can await `ist:*` transitions. The state ladders are:
  - Pause — `ist:plan → ist:quiesce → ist:paused → sts:ok`
  - Rollback — `ist:plan → ist:cutover → ist:ok → sts:ok`
  - Resume — `ist:plan → ist:run → ist:ok → sts:ok`
- **Runtime flags:** `cepHeartbeatRuntime` now records `paused` and `view_horizon`. Pause sets both the runtime flag and the published cell `/sys/state/paused = val/bool:true`; Resume clears the flag and resets `/sys/state/view_hzn` to `CEP_BEAT_INVALID`.
- **Wrappers:** The public entry points `cep_runtime_pause()`, `cep_runtime_resume()`, and `cep_runtime_rollback()` enqueue the control dossiers, guard against conflicting operations, and capture the target beat for rollback.

### Heartbeat Gating and Locks
- **Allow list:** While `gating_active` is true only control signals (pause/resume/rollback/shutdown, `op/cont`, `op/tmo`, and CEI signals) are allowed through. Everything else is diverted to the backlog.
- **Locks:** Pause acquires hierarchical locks on `/data` (`cep_store_lock` + `cep_data_lock`) before the agenda gate engages. Resume releases the locks once gating is lifted.
- **View horizon:** Rollback updates `CEP_RUNTIME.view_horizon` and publishes `/sys/state/view_hzn = val/u64:<beat>`. The value remains in place until Resume clears it, keeping “as-of” consumers aware of the rollback window.

### Backlog Mailbox and QoS
- **Mailbox organ:** Paused impulses land in `/data/mailbox/impulses`. Each message stores signal and target paths, QoS flags, and the beat that captured the impulse. Identifiers are assigned via `cep_mailbox_select_message_id()` so replay order matches dictionary order.
- **QoS flags:** `cepHeartbeatImpulseRecord` carries `cepImpulseQoS`. The new bits map to behaviours:
  - `CEP_IMPULSE_QOS_CONTROL` → always allowed (never parked).
  - `CEP_IMPULSE_QOS_RETAIN_ON_PAUSE` → default for kernel impulses; ensures they survive through Pause/Resume.
  - `CEP_IMPULSE_QOS_DISCARD_ON_ROLLBACK` → Rollback drops these messages before re-exposing the backlog.
- **Draining:** Resume disables gating, drains the backlog deterministically (by message ID order), and re-enqueues the stored impulses for the next beat.
- **Path fidelity:** When parking an impulse we persist the full `cepDT` domain/tag payload for every signal/target segment (not just `cep_id(...)`). `cep_control_path_read()` reconstructs segments directly from the stored `cepData`, so glob markers and naming bits survive Pause/Resume and enzymes continue matching the backlog replay exactly as when the impulse was captured.

### Failure Handling
- **State-machine guard rails:** Every phase records the most recent beat so transitions only happen on a new tick. If any step fails (lock acquisition, OPS update, backlog drain) the operation closes with `sts:fail` and control wrappers return `false`.
- **Diagnostics:** Failures bubble through the OPS dossier (`sts:fail`). The CEI surface inherits the existing diagnostics mailbox, so additional severity reporting can be layered without altering the control plane.

## Appendix A — Minimal L0 runtime contract during PRR
- Heartbeat core stays live to advance OPS dossiers, watcher expiries, CEI emissions, and backlog drains, even while non-essential impulses are gated.
- OPS dossiers for `op/pause`, `op/rollback`, and `op/resume` record `ist:*` transitions and close status so tooling can await or audit control flow beat-by-beat.
- Namepool revival is required before resume: `/rt/namepool/*` pages regain owners/writable flags so control code can intern descriptors post-rollback without hitting veiled stores.
- `/data/mailbox/impulses` remains writable and durable while paused; cefImpulseQoS flags (`retain_on_pause`, `discard_on_rollback`) drive backlog policy.
- CEI diagnostics continue to emit into `/data/mailbox/diag` with severity mapping even when general work is parked.
- IO/timer shims stay armed for control continuations; external effects remain staged until resume completes.

## Q&A
**Q: Why keep the heartbeat running during Pause instead of freezing beats entirely?**  
Because the OPS dossiers, CEI TTLs, and watcher expirations all depend on beat edges. By gating non-control impulses we preserve those guarantees without forfeiting observability or determinism.

**Q: What happens to impulses flagged `CEP_IMPULSE_QOS_DISCARD_ON_ROLLBACK`?**  
Rollback prunes them from `/data/mailbox/impulses` before publishing the new view horizon. Nothing re-enqueues them, so replay and audit runs never observe those impulses after the rollback.

**Q: Can I call `cep_runtime_resume()` if Pause is still processing transitions?**  
No. The wrapper verifies that the pause dossier finished (`pause.closed == true`) before starting Resume. If you need to force a resume while Pause is mid-flight, inspect `/rt/ops/<pause_oid>` to understand why it stalled.
