# Episodic Enzyme Engine (E³)

## Introduction
Imagine taking a long-running job, slicing it into safe, deterministic beats, and letting the kernel keep score. The Episodic Enzyme Engine (E³) is Layer 0’s answer: a scheduler that lets enzymes span beats, run on read-only worker slices, and cancel cooperatively—without giving up the calm, replayable heartbeats that define CEP.

## Technical Details
- **Episodes & OPS dossiers.** Every episode is tracked as an `op/ep` operation under `/rt/ops/<eid>` so tooling can await state transitions (`ist:plan`, `ist:run`, `ist:yield`, `ist:await`, `ist:ok`, `ist:cxl`, `ist:fail`) and inspect watcher activity. The dossier outlives the worker slice, keeping cancellation and completion evidence append-only.
- **Executor queue.** `cep_executor_submit_ro()` pushes read-only slices onto a cooperative ready queue processed from `cep_heartbeat_stage_commit()`. The queue enforces determinism: only one slice runs per beat, activation order is FIFO, and submissions inherit a thread-local `cepEpExecutionContext`.
- **Thread-local contexts.** `cep_executor_context_get()` exposes the current execution context so guard helpers (`cep_ep_require_rw()`, `cep_ep_account_io()`, `cep_ep_check_cancel()`) have zero call-site state. Each context tracks slice budgets, ticket IDs (for cancellation), and CEI emission state.
- **Read-only guard.** Mutation helpers now early-out when invoked from a RO profile. They call `cep_ep_require_rw()` to emit a single `sev:usage` CEI fact (`topic=ep:profile/ro`) and skip journaling while returning `false`/`NULL`. This keeps “RO thread” episodes observational-only.
- **Budgets & CEI integration.** `cep_ep_account_io()` and the executor’s CPU timer maintain slice budgets. When an episode overruns its configured IO/CPU ceiling, the helpers emit `ep:budget/io` or `ep:budget/cpu` CEI facts and mark the context cancelled. Enzymes should call `cep_ep_check_cancel()` at yield points to respect the signal.
- **Cancellation APIs.** `cep_ep_cancel_ticket()` lets supervisors cancel queued or running episodes; `cep_ep_request_cancel()` gives the episode body a cooperative “bail out” lever. Both route through the TLS context so watchers see a deterministic `sts:cxl`.
- **Stream staging wrappers.** `cep_ep_stream_write()` and friends mirror the regular stream APIs but enforce the RO guard and budget accounting. Episodes can stage payloads safely, then rely on the heartbeat commit edge to publish deltas.
- **Build selection.** Meson’s `-Dexecutor_backend=` option selects the backend (`stub`, `threaded`). The stub backend ships today; it still surfaces budgets, CEI integration, and cancellation even without a thread pool. WebAssembly/emscripten builds automatically fall back to the stub path.

## Q&A
**Q: Why not keep Rendezvous?**  
Rendezvous relied on bespoke registries and opaque wait handles. E³ folds long-running work into the existing heartbeat + OPS machinery, so watchers, CEI, and replay all behave the same way—no forked control plane.

**Q: Can read-only episodes mutate state at the end?**  
They can queue intents (e.g., stage a transaction) for commit on the next beat, but mutation helpers stay guarded. Use a dedicated RW episode (with leases) for mutators; RO slices exist to analyse state, stream data, or schedule follow-on work.

**Q: How do I trigger cancellation from tooling?**  
Grab the episode’s OID (or the executor ticket) and call `cep_ep_cancel_ticket()`. The slice notices via `cep_ep_check_cancel()` and cleans up before returning; the OPS dossier records `ist:cxl`/`sts:cxl`.

**Q: What about cooperative yields?**  
Episodes should sprinkle `cep_ep_check_cancel()` in long loops, and future API layers will expose `cep_ep_yield()`/`cep_ep_await()` wrappers so enzymes can explicitly park until the next beat or a watched operation state. The dossier already records `ist:yield`/`ist:await`.

**Q: Do IO budgets count read traffic?**  
Only when the episode registers the bytes via `cep_ep_account_io()`. Stream helpers do this automatically for writes; read-heavy episodes should call the helper so cancellation policies remain consistent.

**Q: How do I debug stuck episodes?**  
Inspect `/rt/ops/<eid>/history/` for the latest `ist:*`. Check the diagnostics mailbox for `ep:profile/*` or `ep:budget/*` CEI facts, and enumerate watcher continuations under `/rt/ops/<eid>/watchers/` to see who’s waiting.

