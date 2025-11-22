# L0 Design: Async I/O Fabric

## Introduction
Layer 0 increasingly needs to juggle persistence, federation, and serialization workloads that exceed what synchronous I/O can provide, yet the heartbeat must stay deterministic and replayable. The async I/O fabric described here shows how the kernel can adopt a non-blocking execution style without exposing nondeterminism to callers. It explains the moving parts, why they are required, and how operators benefit from improved throughput and observability.

## Technical Details

### Deterministic guardrails
- Beats still progress Capture → Compute → Commit, with visibility shifting at *N+1*. Async plumbing can never publish mid-beat state: CQ drains happen only where the heartbeat schedules them, and OPS dossiers store every state change.
- All control-plane data (OPS envelopes, watcher descriptors, reactor bookkeeping, async request metadata) must stay STREAM/HANDLE-free so bootstrap, replay, and pause/rollback do not depend on the async subsystem they are trying to reconstruct.
- Watcher TTLs, deadlines, and CPS commit gating continue to be expressed in beats. Wall-clock timers are advisory; beat counters decide progress.

### Fabric primitives
- `cep_io_reactor` wraps the platform’s non-blocking APIs (epoll/kqueue/IOCP) and falls back to a bounded worker-thread shim for blocking libraries. Reactors own channels and completion queues.
- `cep_io_channel` represents a handle to a file, pipe, socket, or KV entry configured for non-blocking access; creation parameters include beat budgets, TLS/AAD knobs, and telemetry hooks.
- `cep_io_req` is the unit of async work (read, write, send, recv, open, close, fsync, kv_get, kv_put). Submission returns immediately with a request id and initial `pending` status.
- `cep_io_cq` is the completion queue drained once per beat transition (Capture→Compute) and before pause/rollback. Each completion includes request id, byte counts, status, errno/diagnostics, and optionally telemetry deltas.
- `cep_io_timer` harmonizes beat and wall-clock deadlines and emits `op/tmo` CEI topics via watchers when a request exceeds its allowances.

Shipping builds currently run exclusively on the worker-thread shim so targets without epoll/kqueue/IOCP stay deterministic; the POSIX epoll backend is planned next so native async paths can bypass the shim entirely.
### Control-plane directories
- Every async-capable OPS dossier gains `/rt/ops/<oid>/io_req/<rid>/` with deterministic VALUE or CAS payloads:
  - `state` (`val/dt`): `pending`, `complete`, `cnl`, `fail`.
  - `channel` (`val/bytes`): channel id bound when the request was issued.
  - `opcode` (`val/bytes`): `read`, `write`, `send`, `recv`, `open`, `close`, `fsync`, `kv_get`, `kv_put`, `begin`, `finish`, `commit`.
  - `beats_budget` (`val/u32`), `deadline_beat` (`val/u64`), `deadline_unix_ns` (`val/u64`, optional).
  - `bytes_expected` / `bytes_done` (`val/u64`), `errno` (`val/i32`, optional), and `telemetry_id` (link into `/rt/analytics/async/...`).
- Channels live under `/rt/ops/<oid>/io_chan/<cid>/` with:
  - `target_path` (subject cell), `provider_id`, `reactor_id`, `caps`.
  - `shim` flag when a blocking fallback thread handles requests.
  - `watchers/` dictionary referencing awaiters interested in CTS/resume.
- Shared transports or CPS commits publish `/rt/io_reactors/<rid>/` so multiple dossiers can share a reactor; entries store `state`, `active_requests`, `shim_threads`, and `pause_token`.
- Quiesce metadata sits in `/rt/ops/<oid>/io_reactor/` with `draining`, `paused`, `shutting_down`, and `deadline_beats`. The heartbeat sets these flags before pause/rollback, and watchers emit CEI if deadlines are exceeded.
- Worker-thread fallbacks record usage under `/rt/analytics/async/shim/<provider>/<channel>` with counters `jobs_total`, `jobs_active`, `lat_p50`, `lat_p99`, `lat_max`, giving operators visibility into non-native providers.

### Reactor lifecycle & scheduling
- **Beat drain:** at the Capture→Compute transition the heartbeat runs:
  ```c
  while (cep_io_cq_next(reactor, &ev)) {
      cep_async_promote_completion(ev);
  }
  ```
  `cep_async_promote_completion` updates the owning OPS dossier, appends `op/cont` or `op/tmo`, bumps watcher TTL counters, and enqueues follow-on work for Compute. CQ drains never happen mid-beat unless replay is rewinding history inside the same deterministic order.
- **Episode awareness:** E3 episodes that owns async work receive borrow tokens so they can peek at completions during cooperative yields, but any mutation still posts back into OPS for beat-stage visibility.
- **Pause/rollback quiesce:** calling `cep_io_reactor_quiesce(deadline_beats)` sets `/io_reactor/draining=true`, drains CQs, issues cancels for outstanding requests, and blocks until worker shims stop. Requests exceeding the deadline receive `sts:cnl` plus CEI `persist.async.tmo` or transport-specific topics; only then does the heartbeat advance the pause/rollback beat.
- **Shutdown:** `cep_heartbeat_emit_shutdown()` triggers the same quiesce call with a short default budget so no background thread can observe torn shutdown state.
- **Metrics:** Reactors publish `/rt/analytics/async/reactor/<rid>/` entries (`cq_depth`, `pending_bytes`, `completions_per_beat`, `timeouts`) the heartbeat updates once per drain so dashboards see live progress.

### Serialization integration
- `cep_flat_frame_sink` vtable:
  - `cffs_begin_async(frame_meta, buffer_id)` allocates handles and records per-request IDs in `/io_req`.
  - `cffs_write_async(buffer_id, span_offset, span_len)` breaks large frames into spans (default 256 KiB) and emits chained requests so multiple writes can be in flight; completions update `bytes_done`.
  - `cffs_finish_async(buffer_id)` fsyncs and seals the frame handle.
- Capture assembles the frame into CAS-backed buffers; Compute schedules the async writes and records a watcher referencing the sink’s `finish_async` request. `ist:store` and CPS ingest do not advance until the watcher fires.
- Recoverable failures (`EAGAIN`, transient network loss) stay in OPS with `state=pending_retry` and beat-based backoff; fatal errors emit `persist.frame.io` + `sts:fail` and roll the beat back to Capture.
- Readers remain incremental: async sources feed CQ completions into the same parser used today, emitting events only at beat boundaries.

### Federation integration
- Capability bits:
  - `cap_send_async`, `cap_recv_async`, `cap_flush_async` advertised during `cep_fed_transport_register`.
  - Mount schema stores desired bits under `caps/required`. Providers missing a required bit are rejected; optional bits degrade via CEI `tp_async_unsp`.
- Request flow:
  1. Mount queues a send/recv; Control-plane records `io_req`.
  2. Reactor issues the provider’s async call (or shim thread for blocking provider). Providers receive a `cepFedTransportAsyncHandle*` and must call `cep_fed_transport_async_send_complete()` / `cep_fed_transport_async_receive_ready()` once the operation finishes; shim jobs call those helpers immediately after the blocking call returns so OPS timelines stay consistent.
  3. Completions transition OPS states; watcher TTLs drive `op/tmo`.
  4. Telemetry increments `ready_count`, `bp_count`, `fatal_count` plus async-specific counters `async_pending`, `async_shim_jobs`, and `async_native_jobs`. The same counts mirror into `/rt/analytics/async/(shim|native)/<provider>/<mount>/jobs_total` so dashboards can chart shim usage alongside provider completions.
- `upd_latest` semantics remain: the async path still deduplicates droppable payloads and respects provider backpressure callbacks. Detected drift (e.g., provider lacking `cap_unreliable` while mount enables `upd_latest`) emits `tp_policy_violation`.
- Replay ensures `/rt/ops/<oid>/io_req` plus `/net/mounts/.../telemetry` contain enough data to rehydrate outstanding sends without reading STREAM payloads.

### CPS async handshake
- FSM:
  1. `cps_begin_beat_async(branch, beat)` reserves log slots and issues a CQ request (`io_req/<rid_begin>`).
  2. `cps_put_record_async` streams serializer records; every chunk references the same `buffer_id`. Requests may run in parallel; ordering enforced via `seq` field stored with each `io_req`.
  3. `cps_finish_frame_async` seals the idx/dat staging areas and enqueues fsync requests; completions emit `persist.async` info CEI if queues exceed policy thresholds.
  4. `cps_commit_beat_async` swaps head pointers, publishes metrics, and marks `/rt/beat/<n>/ist:store`.
- Failure handling:
  - Recoverable IO errors keep the FSM in `pending_retry` with exponential backoff measured in beats.
  - Timeouts trigger `persist.async.tmo`, abort the beat (`cps_abort_beat_async`), emit CEI, and leave `/rt/beat/<n>/ist:fail`.
  - Replay enforces the same CEI order; decisions recorded in OPS/TODO cells ensure deterministic re-run.
- Metrics: `/data/persist/<branch>/metrics` gains `async_inflight`, `async_cq_latency`, `async_retries`, `async_shim_jobs`.

`cps_storage_commit_current_beat()` drives this FSM and then calls `cps_storage_async_wait_for_commit()` to poll the reactor (via `cep_async_runtime_on_phase`) until the `finish_async` request completes or the watchdog expires. Failures surface `persist.async` / `persist.async.tmo` CEI alongside the offending request id so tooling can correlate OPS state with telemetry.

### POC & regression testing
- **POC test upgrade**
  - Add async mode selectors so the POC suite runs the new reactor-backed path in parallel with its existing sync assertions (same inputs, deterministic outputs).
  - Tests never mix sync + async within the same invocation; a command-line flag (for example `--enable-async`) or environment toggle selects the mode.
  - Coverage: serialization sink (frame begin/write/finish), federation send/recv (including `upd_latest`), CPS async handshake, and OPS watcher visibility.
- **Regression plan**
  - Default build: run targeted suites (POC async, persistence, federation, runtime_dual_default) both with async disabled and enabled.
  - Sanitizer sweep: rebuild via `meson setup build-asan -Dasan=true`, rerun all async-touching suites (POC async, persistence async, federation async) under ASAN, confirm clean exit, then rerun the same selectors under Valgrind on the non-ASAN build.
  - Logging: capture CQ drain traces and CEI output for every failure; attach logs to TODO/bug reports per replication guardrail.
- Async I/O is now the default for serialization, federation, and CPS. Shim vs. native backends remain selectable (portable shim today, epoll backend forthcoming) so CI can force specific combinations; document any temporary override flags in `docs/L0_KERNEL/L0-TUNING-NOTES.md`.

## Q&A
**Q: How does this keep deterministic replay intact?**  
All observables (OPS histories, watcher transitions, CEI) remain beat-aligned. Async internals only influence when completions enter the CQ, and those completions are harvested at deterministic points.

**Q: What happens if a provider only supports blocking calls?**  
The reactor routes that request through a worker-thread shim. OPS still records the request, CQ completion, and `tp_async_unsp` telemetry so operators know the fallback was used.

**Q: Can pause/rollback safely interrupt in-flight async work?**  
Yes. The quiesce protocol drains CQs, cancels remaining requests with `sts:cnl`, and waits for worker shims to unwind before the heartbeat finalizes the control transition.

**Q: How do transports and persistence signal backpressure or timeouts?**  
They continue to emit existing CEI topics (`tp_backpressure`, `persist.frame.io`, etc.), plus the new `persist.async` informational events when async queues grow. Watchers convert beat overruns into `op/tmo`.

**Q: When is this design considered “fully rolled out”?**  
We are already routing serialization, federation, and CPS through reactors by default; the remaining milestone is shipping native epoll/kqueue/IOCP backends (so shim usage drops to zero on capable hosts) and proving the async-enabled regression suite (POC + PRR + federation) passes under both normal and sanitizer builds.
