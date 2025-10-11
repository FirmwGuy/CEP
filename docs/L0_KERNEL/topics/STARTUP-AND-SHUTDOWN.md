# L0 Topic: Startup and Shutdown Sequence

## Introduction
Think of CEP's runtime like a stage crew preparing and striking a show. Before the lights go up, the crew lays out the scenery (cell system), checks power and comms (heartbeat and namepool), and opens the lobby doors (mailroom). When the curtain falls they reverse the choreography so the next performance can start from a clean slate without loose props or missed cues.

## Technical Details
### Phase 0 - Bootstrapping prerequisites
- `cep_l0_bootstrap()` is the public convenience entry point. It calls `cep_cell_system_ensure()`, `cep_heartbeat_bootstrap()`, `cep_namepool_bootstrap()`, and `cep_mailroom_bootstrap()` in order, marking each lifecycle scope ready as it succeeds (`CEP_LIFECYCLE_SCOPE_KERNEL`, `NAMEPOOL`, `MAILROOM` respectively).
- `cep_cell_system_ensure()` initialises the root cell if it has not been created yet, resetting timestamps so subsequent stores start at beat zero. On shutdown `cep_cell_system_shutdown()` reverses that work and also invokes `cep_mailroom_shutdown()` and `cep_namepool_reset()`.
- `cep_heartbeat_bootstrap()` provisions the always-on directories under `/sys`, `/rt`, `/journal`, `/env`, `/cas`, `/lib`, `/data`, `/tmp`, and `/enzymes`, creates the default enzyme registry when needed, registers the built-in cell operation enzymes, reloads lifecycle state from `/sys/state/*`, and marks the kernel scope ready.
- `cep_namepool_bootstrap()` depends on the kernel scope being ready. It makes sure `/sys/namepool` exists and registers the scope as ready so callers can safely intern identifiers during later boot stages.
- `cep_mailroom_bootstrap()` expects both kernel and namepool scopes to be ready; if they are not, it marks them ready before proceeding. The helper ensures `/data/inbox` exists, seeds namespaces either from `/sys/err_cat/<scope>/mailroom/buckets/*` or from the built-in `{coh, flow}` defaults, mirrors any extra namespaces declared via `cep_mailroom_add_namespace()`, and records readiness for the mailroom lifecycle scope.

### Phase 1 - Starting the heartbeat loop
- After configuration (optional `cep_heartbeat_configure()`), call `cep_heartbeat_startup()` to reset the beat counter, clear dispatch queues, and open the capture phase. This does not advance time yet; it only primes the runtime.
- `cep_heartbeat_begin(start_beat)` (or the convenience `cep_heartbeat_step()` loop) starts real execution. During the first begin call the runtime emits `CEP:sig_sys/init`, logs it under `/journal/sys_log`, and immediately triggers the mailroom `mr_init` enzyme if it was registered.
- Every lifecycle scope marked ready before `cep_heartbeat_begin()` queues a deferred `CEP:sig_sys/ready/<scope>` impulse. `cep_lifecycle_flush_pending_signals()` sends them once the runtime is running so downstream enzymes can rely on deterministic readiness signals.
- Impulses emitted inside bootstrap and ready helpers temporarily disable the directory creation flag so system signals remain lightweight even before `/rt/beat/<n>` folders exist.

#### Impulse sequencing during bring-up
1. `cep_l0_bootstrap()` marks the scopes ready, but the runtime is not running yet, so no impulses fire.
2. `cep_heartbeat_startup()` sets `CEP_RUNTIME.running = true` and immediately emits the *ready* impulses in enum order:  
   `/CEP:sig_sys/CEP:ready/CEP:kernel`, `/CEP:sig_sys/CEP:ready/CEP:namepool`, `/CEP:sig_sys/CEP:ready/CEP:mailroom` (plus `/ERR`, `/L1`, `/L2` if they were already bootstrapped). These are immediate signals with a `NULL` target path and are handled entirely inside Layer 0.
3. `cep_heartbeat_begin()` enqueues `/CEP:sig_sys/CEP:init` for the next beat. That deferred signal is the only startup impulse user code or higher layers commonly bind to—mailroom’s `mr_init` enzyme is attached here, and packs can register their own descriptors on the same path if they need to extend the init choreography.
4. When L1/L2 bootstraps run after the heartbeat is live, their calls to `cep_lifecycle_scope_mark_ready()` emit deferred `/CEP:sig_sys/CEP:ready/CEP:l1` and `/CEP:sig_sys/CEP:ready/CEP:l2` impulses. User code can hook those signals to observe when a layer becomes usable.

At this stage only Layer 0 consumes the *ready* pulses; effective work (intent routing, ingest, user enzymes) starts after the deferred `/CEP:sig_sys/CEP:init` has executed and the mailroom has reseeded the layer inboxes.

### Phase 2 - Mailroom activation during startup
- `cep_mailroom_register(registry)` adds two descriptors to the given registry: `mr_init` bound to `CEP:sig_sys/init` (exact match) and `mr_route` bound to the `CEP:sig_cell/op_add` prefix. The router is flagged as idempotent and inserted before the ingest enzymes declared by Layer 1 (`coh_ing_*`) and Layer 2 (`fl_ing`, `ni_ing`, `inst_ing`); extra names queued through `cep_mailroom_add_router_before()` are appended before registration.
- When the registry activates on the first beat, `mr_init` replays `cep_mailroom_bootstrap()` so restarts and replays rebuild the lobby even if the process bootstrapped long before. The router also binds itself to `/data/inbox` the first time registration succeeds.
- `mr_route` clones intents from `/data/inbox/<ns>/<bucket>/<txn>` into `/data/<ns>/inbox/<bucket>/<txn>`, leaves an audit link at the source, guarantees `original/*`, `outcome`, and `meta/parents` exist, and short-circuits to `CEP_ENZYME_SUCCESS` if the destination inbox is missing (which keeps legacy tests that bypass layer bootstraps from failing hard).
- Adding namespaces after the first bootstrap is still supported: `cep_mailroom_add_namespace()` reseeds immediately when the mailroom is already alive.

### Phase 3 - Shutdown cascade
- `cep_heartbeat_emit_shutdown()` is the orderly teardown path. It iterates through the teardown order (`L2`, `L1`, `ERR`, `MAILROOM`, `NAMEPOOL`, `KERNEL`), marking each scope as `teardown`, emitting `CEP:sig_sys/teardown/<scope>` immediately, and finally emitting `CEP:sig_sys/shutdown` for the runtime itself. All impulses are processed synchronously so downstream enzymes observe teardown in dependency order.
- `cep_heartbeat_shutdown()` wraps `cep_heartbeat_emit_shutdown()`, resets runtime scratch buffers, clears topology overrides, and calls `cep_cell_system_shutdown()` so the next bootstrap starts from a clean root.
- `cep_mailroom_shutdown()` clears extra namespace and router caches, marks the mailroom scope as torn down, and lets the next bootstrap reseed the lobby. Because shutdown preserves the structural nodes, replaying a bootstrap reuses existing inbox trees without leaking prior requests.
- The journal (`/journal/sys_log`) records every lifecycle signal with the beat where it fired and whether it was immediate or deferred, providing an audit trail for both startup and shutdown transitions.

#### Impulse sequencing during teardown
1. `cep_heartbeat_emit_shutdown()` walks the teardown list `L2 → L1 → ERR → MAILROOM → NAMEPOOL → KERNEL`, emitting `/CEP:sig_sys/CEP:teardown/CEP:<scope>` immediately for each scope. These pulses carry no target path; user enzymes can observe them by registering on the relevant signal if they need to mirror teardown work.
2. Once all scopes have emitted teardown, the runtime sends `/CEP:sig_sys/CEP:shutdown` (immediate) and processes the batch in the same beat, ensuring log ordering and deterministic cleanup.

## Q&A
**Q: What order should I call when bringing CEP online?**  
Call `cep_l0_bootstrap()` first, then register your layer packs (they chain into `cep_mailroom_register()`), and finally invoke `cep_heartbeat_startup()` followed by `cep_heartbeat_begin()` or your own beat loop.

**Q: When is the mailroom safe to use?**  
As soon as `cep_mailroom_bootstrap()` returns or the `mr_init` enzyme runs on the first `CEP:sig_sys/init`. Both paths seed namespaces and mark `CEP_LIFECYCLE_SCOPE_MAILROOM` ready; the router only moves requests once it is registered in the active registry.

**Q: How do I inject a new namespace before traffic starts flowing?**  
Call `cep_mailroom_add_namespace()` before `cep_mailroom_bootstrap()` (or before you register the mailroom). If you add it later, the helper reseeds immediately, but doing it during bootstrap guarantees the buckets exist before any intents arrive.

**Q: How do I perform a soft restart without losing topology?**  
Use `cep_heartbeat_restart()`. It clears runtime caches, reuses the configured topology, re-emits readiness signals, and avoids tearing down `/data` or the mailroom tree. For a hard reset call `cep_heartbeat_shutdown()` followed by a fresh bootstrap.

**Q: Where can I confirm lifecycle transitions?**  
Check `/sys/state/<scope>` for the recorded `status`, `ready_beat`, and `td_beat` fields, and `/journal/sys_log` for the textual impulses (`mailroom.catalog ...`, `CEP:sig_sys/ready/<scope>`, `CEP:sig_sys/shutdown`, etc.) emitted during startup and shutdown.
