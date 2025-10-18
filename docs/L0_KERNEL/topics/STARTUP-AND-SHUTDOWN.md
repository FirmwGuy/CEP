# L0 Topic: Startup and Shutdown Sequence

## Introduction
Think of CEP's runtime as a pair of operations that bookend every session. `op/boot` raises the curtain with a deterministic checklist, `op/shdn` lowers it, and the kernel records each phase so tooling can observe progress without chasing ad‑hoc impulses. This chapter explains how those operations are created, which states they traverse, and where to look when you need to coordinate packs or await readiness. One-beat enzymes are still supported exactly as before—fire-and-forget callbacks run through the regular heartbeat resolver without interacting with OPS/STATES. The OPS/STATES machinery is reserved for multi-stage or stateful work that spans beats.

## Technical Details
### Phase 0 — Bootstrap prerequisites
- `cep_l0_bootstrap()` remains the public entry point. It calls `cep_cell_system_ensure()`, `cep_heartbeat_bootstrap()`, and `cep_namepool_bootstrap()` in order. Each helper marks its lifecycle scope ready, which now drives the `op/boot` timeline.
- `cep_cell_system_ensure()` initialises the root cell if needed. On shutdown `cep_cell_system_shutdown()` reverses the work so the next bootstrap starts cleanly.
- `cep_heartbeat_bootstrap()` creates the always-on directories (`/sys`, `/rt`, `/journal`, `/env`, `/cas`, `/lib`, `/data`, `/tmp`, `/enzymes`), ensures the enzyme registry exists, registers built-in cell operation enzymes, and starts the boot operation if the policy flag `boot_ops` is enabled (it is required for new builds). The helper refreshes lifecycle bookkeeping and leaves the kernel scope marked ready.
- `cep_namepool_bootstrap()` depends on the kernel scope. Once it succeeds, the boot operation records the final startup phase and closes with `sts:ok`.

### Phase 1 — Starting the heartbeat loop
- `cep_heartbeat_configure()` copies caller overrides and validates that `boot_ops` is true. Disabling the flag is no longer supported; the routine returns `false` rather than falling back to legacy signals.
- `cep_heartbeat_startup()` resets beat counters, clears the dispatch queues, opens the capture phase, and guarantees that the boot operation has been created (envelope sealed, history seeded).
- `cep_heartbeat_begin(start)` starts real execution. It does **not** emit `CEP:sig_sys/*` impulses anymore; instead it ensures the boot operation is live so observers can await states or statuses.

#### Boot operation timeline (`/rt/ops/<boot_oid>`)
1. **Envelope creation.** `cep_boot_ops_start_boot()` (called from bootstrap/startup paths) creates `/rt/ops/<boot_oid>/envelope/` with the verb (`op/boot`), target (`/sys/state`), mode (`opm:states`), issued beat, and optional payload. The branch is sealed immutable inside the veiled transaction.
2. **`ist:kernel`.** Immediately after creation the operation records `ist:kernel` and appends the first history entry.
3. **`ist:store`.** When the kernel scope is flagged ready (`cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_KERNEL)`), the scheduler records `ist:store` on the next beat and appends the second history entry.
4. **`ist:packs` → close.** Once the namepool scope becomes ready, the following beat records `ist:packs`. The beat after that closes with `sts:ok`, seals the `/close/` branch, and updates the final state to `ist:ok`.
5. **Publishing the OID.** The helper stores `boot_oid` as a `val/bytes` payload under `/sys/state/boot_oid`. Tools and packs resolve the boot snapshot by reading that cell.

Watchers can attach to any of these states (or `sts:ok`) via `cep_op_await()`. Ready watchers fire during `cep_heartbeat_stage_commit()` and enqueue follow-up impulses with whatever continuation signal you choose (`op/cont` by convention).

### Phase 2 — Coordinating packs and awaiters
- Awaiters call `cep_op_await(boot_oid, CEP_DTA("CEP","ist:packs"), ttl, CEP_DTA("CEP","op/cont"), payload, size)` to resume work once startup reaches a specific state. Watchers that are satisfied immediately are armed and will fire during the next stage commit.
- If you need a textual digest, call `cep_op_get(boot_oid, buffer, cap)`; it reports the current state, closed status, and watcher count.

### Phase 3 — Shutdown cascade
- `cep_heartbeat_emit_shutdown()` is the orderly teardown path. It ensures `op/shdn` exists, walks lifecycle scopes in teardown order, and lets the heartbeat advance the remaining states on subsequent beats. No legacy `CEP:sig_sys` pulses are emitted.
- `cep_heartbeat_shutdown()` wraps the orderly teardown, resets runtime scratch buffers, clears topology overrides, and calls `cep_cell_system_shutdown()` so the next bootstrap starts from a clean root.

#### Shutdown operation timeline (`/rt/ops/<shdn_oid>`)
1. **Envelope creation.** `cep_boot_ops_start_shutdown()` creates `/rt/ops/<shdn_oid>/envelope/` with verb `op/shdn`, target `/sys/state`, and mode `opm:states`, then records `ist:stop`. The OID is published at `/sys/state/shdn_oid`.
2. **`ist:flush`.** The first scope that enters teardown advances the operation to `ist:flush` on the next beat.
3. **`ist:halt` → close.** When the teardown list completes, the operation records `ist:halt` on the following beat and closes with `sts:ok` one beat later. The `/close/` branch is sealed and the terminal state becomes `ist:ok`.
4. **Awaiters and expiries.** Watchers targeting either states or statuses fire during stage commit. TTLs are counted in beats and expire via `cep_ops_expire_watchers()` if the awaited transition never surfaces.

### Observability quick reference
- `/sys/state/boot_oid` / `/sys/state/shdn_oid` – `val/bytes` payload storing the active OIDs.
- `/rt/ops/<oid>/state` – `val/dt` recording the current `ist:*`.
- `/rt/ops/<oid>/history/` – dictionary entries (`0001`, `0002`, …) each containing `state`, `beat`, optional `code`, optional `note`.
- `/rt/ops/<oid>/close/` – sealed dictionary with `status` (`sts:*`), `closed_beat`, and optional `summary_id`.
- `/rt/ops/<oid>/watchers/` – dictionary of live watcher entries. The branch is empty after watchers fire or expire.

## Q&A
**Q: What order should I follow when bringing CEP online?**  
Call `cep_l0_bootstrap()` first, then run any optional pack bootstrap that depends on the heartbeat, then invoke `cep_heartbeat_startup()` followed by `cep_heartbeat_begin()` (or drive beats manually with `cep_heartbeat_step()`). The boot operation appears during bootstrap; `ist:kernel` records immediately and the remaining milestones (`ist:store`, `ist:packs`, `ist:ok`) land on successive beats as you continue stepping.

**Q: How many beats does startup and shutdown consume?**  
With `start_at = 0`, expect the boot timeline at beats 0 (`ist:kernel`), 1 (`ist:store`), 2 (`ist:packs`), and 3 (`ist:ok`). Shutdown mirrors that cadence: triggering teardown records `ist:stop` on the current beat, `ist:flush` on the next, `ist:halt` one beat later, and the close (`ist:ok`/`sts:ok`) on the fourth beat.

**Q: How do I wait until the system is usable?**  
Read `/sys/state/boot_oid`, then await the desired state:  
`cep_op_await(boot_oid, CEP_DTA("CEP","ist:packs"), ttl, CEP_DTA("CEP","op/cont"), NULL, 0);`  
During the next stage commit the watcher queues your continuation signal for beat N+1.

**Q: What replaced the old `CEP:sig_sys/ready/*` and `CEP:sig_sys/shutdown` impulses?**  
They were removed entirely. Use the boot and shutdown operations (states, history, close status, or `cep_op_get`) to observe lifecycle progress. Packs that previously listened for the legacy signals should migrate to `cep_op_await`.

**Q: How do I perform a soft restart without losing topology?**  
Call `cep_heartbeat_restart()`. It clears runtime caches, reuses the configured topology, restarts the boot operation when needed, and leaves `/rt/ops/<boot_oid>` intact so diagnostics can inspect the prior run.

**Q: Where do I confirm lifecycle transitions at runtime?**  
Resolve the published OIDs and inspect the corresponding operation branches. History entries are append-only, `envelope/` and `close/` are sealed, and watchers disappear once fired—ideal for auditors and tooling dashboards.

**Q: What happens if the shutdown encounter fails?**  
`cep_boot_ops_close_shutdown()` closes the operation with `sts:fail` (and final `ist:fail`) if any state transition or watcher notification fails. Awaiters waiting on `sts:ok` will instead receive the failure status on the next beat.

## Layer-0 Operating Principles
- **Operation-first lifecycle.** Treat `op/boot` and `op/shdn` as the canonical lifecycle record. Align new packs or services with those operations instead of adding bespoke state trackers.
- **Append-only cells.** Stage replacements off-tree and graft them atomically. Direct edits of `/data` or `/rt/ops` break replay guarantees.
- **Phase discipline.** Capture → compute → commit is the only legal mutation flow. Use the `cep_beat_begin_*` helpers and keep shutdown transitions within the same rules.
- **Watcher hygiene.** Prefer `cep_op_await` over polling. Remember that watchers fire during stage commit and enqueue continuations for the next beat.
- **Path-based lookups.** Treat cached `cepCell*` pointers as ephemeral. Resolve by path across phase boundaries so store promotion or restart cannot strand stale handles.
- **Public-surface tests.** Layer‑0 suites step the heartbeat and call exported APIs. Avoid reaching around the public surface; that bypasses the very operations that keep lifecycle deterministic.
