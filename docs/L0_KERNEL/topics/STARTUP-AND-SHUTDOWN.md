# L0 Topic: Startup and Shutdown Sequence

## Introduction
Think of CEP's runtime like a stage crew preparing and striking a show. Before the lights go up, the crew lays out the scenery (cell system) and checks power and comms (heartbeat and namepool) so downstream packs step onto a stable stage. When the curtain falls they reverse the choreography so the next performance can start from a clean slate without loose props or missed cues.

> **Developer reminder:** Every new Layer‑0 facility should participate in this impulse choreography. When in doubt, bind your bootstrap to the existing `CEP:sig_sys/ready/*` and `CEP:sig_sys/init` pulses instead of open-coding bespoke startup checks—future you (or the next teammate) will thank you.

## Technical Details
### Phase 0 - Bootstrapping prerequisites
- `cep_l0_bootstrap()` is the public convenience entry point. It calls `cep_cell_system_ensure()`, `cep_heartbeat_bootstrap()`, and `cep_namepool_bootstrap()` in order, marking each lifecycle scope ready as it succeeds (`CEP_LIFECYCLE_SCOPE_KERNEL`, `NAMEPOOL`).
- `cep_cell_system_ensure()` initialises the root cell if it has not been created yet, resetting timestamps so subsequent stores start at beat zero. On shutdown `cep_cell_system_shutdown()` reverses that work, and `cep_namepool_reset()` prepares the namepool for the next boot.
- `cep_heartbeat_bootstrap()` provisions the always-on directories under `/sys`, `/rt`, `/journal`, `/env`, `/cas`, `/lib`, `/data`, `/tmp`, and `/enzymes`, creates the default enzyme registry when needed, registers the built-in cell operation enzymes, reloads lifecycle state from `/sys/state/*`, and marks the kernel scope ready.
- `cep_namepool_bootstrap()` depends on the kernel scope being ready. It makes sure `/sys/namepool` exists and registers the scope as ready so callers can safely intern identifiers during later boot stages.

### Phase 1 - Starting the heartbeat loop
- After configuration (optional `cep_heartbeat_configure()`), call `cep_heartbeat_startup()` to reset the beat counter, clear dispatch queues, and open the capture phase. This does not advance time yet; it only primes the runtime.
- `cep_heartbeat_begin(start_beat)` (or the convenience `cep_heartbeat_step()` loop) starts real execution. During the first begin call the runtime emits `CEP:sig_sys/init`, logs it under `/journal/sys_log`, and executes any init enzymes that were staged ahead of time.
- Every lifecycle scope marked ready before `cep_heartbeat_begin()` queues a deferred `CEP:sig_sys/ready/<scope>` impulse. `cep_lifecycle_flush_pending_signals()` sends them once the runtime is running so downstream enzymes can rely on deterministic readiness signals.
- Impulses emitted inside bootstrap and ready helpers temporarily disable the directory creation flag so system signals remain lightweight even before `/rt/beat/<n>` folders exist.

#### Impulse sequencing during bring-up
1. `cep_l0_bootstrap()` marks the scopes ready, but the runtime is not running yet, so no impulses fire.
2. `cep_heartbeat_startup()` sets `CEP_RUNTIME.running = true` and immediately emits the *ready* impulses in enum order:  
   `/CEP:sig_sys/CEP:ready/CEP:kernel`, `/CEP:sig_sys/CEP:ready/CEP:namepool`, and any additional scopes that earlier packs have already bootstrapped. These are immediate signals with a `NULL` target path and are handled entirely inside Layer 0.
3. `cep_heartbeat_begin()` enqueues `/CEP:sig_sys/CEP:init` for the next beat. That deferred signal is the only startup impulse user code or higher layers commonly bind to, and packs can register their own descriptors on the same path if they need to extend the init choreography.
4. When an upper-layer pack bootstraps after the heartbeat is live, its call to `cep_lifecycle_scope_mark_ready()` emits a deferred `/CEP:sig_sys/CEP:ready/CEP:<scope>` impulse. User code can hook those signals to observe when a pack becomes usable. User code can hook those signals to observe when a layer becomes usable.

At this stage only Layer 0 consumes the *ready* pulses; effective work (intent routing, ingest, user enzymes) starts after the deferred `/CEP:sig_sys/CEP:init` has executed.

### Phase 2 - Pack-owned ingest hooks
- With the mailroom retired, packs that still rely on lobby-style routing must register their own enzymes. Leave a `TODO` near any placeholder no-op so future work can supply the replacement dispatcher.

### Phase 3 - Shutdown cascade
- `cep_heartbeat_emit_shutdown()` is the orderly teardown path. It iterates through the teardown order (pack scopes, then `NAMEPOOL`, `KERNEL`), marking each scope as `teardown`, emitting `CEP:sig_sys/teardown/<scope>` immediately, and finally emitting `CEP:sig_sys/shutdown` for the runtime itself. All impulses are processed synchronously so downstream enzymes observe teardown in dependency order.
- `cep_heartbeat_shutdown()` wraps `cep_heartbeat_emit_shutdown()`, resets runtime scratch buffers, clears topology overrides, and calls `cep_cell_system_shutdown()` so the next bootstrap starts from a clean root.
- The journal (`/journal/sys_log`) records every lifecycle signal with the beat where it fired and whether it was immediate or deferred, providing an audit trail for both startup and shutdown transitions.

#### Impulse sequencing during teardown
1. `cep_heartbeat_emit_shutdown()` walks the teardown list `<pack scopes> → NAMEPOOL → KERNEL`, emitting `/CEP:sig_sys/CEP:teardown/CEP:<scope>` immediately for each scope. These pulses carry no target path; user enzymes can observe them by registering on the relevant signal if they need to mirror teardown work.
2. Once all scopes have emitted teardown, the runtime sends `/CEP:sig_sys/CEP:shutdown` (immediate) and processes the batch in the same beat, ensuring log ordering and deterministic cleanup.

## Q&A
**Q: What order should I call when bringing CEP online?**  
Call `cep_l0_bootstrap()` first, register any optional packs that depend on the heartbeat, then invoke `cep_heartbeat_startup()` followed by `cep_heartbeat_begin()` (or drive the beats manually with `cep_heartbeat_step()`).

**Q: What replaced the mailroom's unified inbox?**  
The kernel no longer mirrors `/data/inbox`; packs that ingest external work should register their own routing enzymes or append directly to their datasets. Leave a `TODO` beside any temporary no-op stubs so downstream refactors can wire the new ingress path.

**Q: How do I perform a soft restart without losing topology?**  
Use `cep_heartbeat_restart()`. It clears runtime caches, reuses the configured topology, and re-emits readiness signals without touching `/data`. For a hard reset call `cep_heartbeat_shutdown()` followed by a fresh bootstrap.

**Q: Where can I confirm lifecycle transitions?**  
Check `/sys/state/<scope>` for the recorded `status`, `ready_beat`, and `td_beat` fields, and `/journal/sys_log` for the textual impulses (`CEP:sig_sys/ready/<scope>`, `CEP:sig_sys/teardown/<scope>`, `CEP:sig_sys/shutdown`) emitted during startup and shutdown.

## Layer-0 Operating Principles
- **Append-only cells.** Stage replacements off-tree and graft them in one shot. Direct in-place edits of `/data` break replay guarantees.
- **Phase discipline.** Capture, compute, commit is the only legal mutation flow. Let the phase helpers (`cep_beat_begin_*`, capture/commit enzymes, etc.) drive writes.
- **Impulse bootstrap.** New services hook into the existing `CEP:sig_sys/ready/*` and `CEP:sig_sys/init` signals. Avoid bespoke readiness checks that bypass the heartbeat.
- **Link-safe helpers.** Always use `cep_cell_require_dictionary_store`, `cep_cell_clear_children`, `cep_cell_copy_children`, and related APIs so link promotion and store upgrades stay consistent.
- **Path-based lookups.** Treat `cepCell*` pointers as ephemeral; re-resolve by path whenever you cross a phase boundary so store promotion or replay cannot strand stale handles.
- **Public-surface tests.** Layer-0 test suites step the heartbeat and call exported APIs. Reaching around the surface hides lifecycle regressions that impulses would have exposed.
