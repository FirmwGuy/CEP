# L0 Design: Episodic Enzyme Engine (E3)

## Introduction
Think of an “episode” as a deterministic mini-story that plays out across several heartbeat beats. The Episodic Enzyme Engine (E3) lets enzymes pause, resume, and even borrow read-only worker threads without ever breaking the beat-by-beat determinism that Layer 0 guarantees. This design note explains why the engine exists, the invariants it must protect, and how executor backends keep wall-clock concurrency tamed.

## Technical Details
- **Deterministic lifecycle.** Every episode is represented by an `op/ep` dossier rooted at `/rt/ops/<eid>`. The envelope captures the signal, target, execution profile, and budgets; history entries log state changes (`ist:plan`, `ist:run`, `ist:yield`, `ist:await`, `ist:ok`, `ist:fail`, `ist:cxl`) with beats and optional diagnostic notes. Watchers reuse the existing OPS machinery so continuations (`CEP:ep/cont`) and timeouts (`CEP:op/tmo`) stay observable and replayable.
- **Slices & yields.** Slice bodies execute user callbacks until they voluntarily yield (`cep_ep_yield`) or await external work (`cep_ep_await`). Yield points append history, arm a watcher, and let the heartbeat pick work back up on the next beat. Awaiters bind to arbitrary `op/*` dossiers, allowing cross-operation dependencies without custom plumbing.
- **Execution profiles.** Two profiles exist today. `CEP_EP_PROFILE_RO` grants read-only access plus the ability to stage intents that commit on the next beat. `CEP_EP_PROFILE_RW` enables mutation but requires an explicit lease (`cep_ep_request_lease`) so store/data locks protect the subtree. The executor stores the active profile in thread-local context so helpers such as `cep_ep_require_rw`, `cep_ep_account_io`, and `cep_ep_check_cancel` can enforce permissions and budgets automatically.
- **Budgets & cancellation.** Execution policies define optional CPU (`cpu_budget_ns`) and IO (`io_budget_bytes`) ceilings. The executor timestamps each slice, and stream helpers account bytes to the TLS context. Overruns emit CEI usage facts (`ep:bud/cpu`, `ep:bud/io`) and flip the cancellation flag so the slice exits gracefully on its next `cep_ep_check_cancel()` call. Supervisors can cancel a queued or running slice via `cep_ep_cancel_ticket()` or by targeting the dossier with `cep_ep_cancel()`.
- **Executor backends.** Cooperative builds use a single-threaded queue (`CEP_EXECUTOR_BACKEND_STUB`) serviced during heartbeat commit. The threaded backend (`CEP_EXECUTOR_BACKEND_THREADED`) spins a worker pool sized to available CPUs, drives tasks in FIFO order, and mirrors the same TLS bookkeeping so guards behave identically. WebAssembly builds automatically fall back to the cooperative backend.
- **Continuation enzyme.** The `ep/cont` enzyme is the bridge between OPS watchers and episode resumption. When a watcher fires it requeues the owning episode (or cancels it on timeout) while preserving episode ordering. Tooling can also send `op/cont`/`op/tmo` impulses manually to orchestrate pipelines.
- **Lease tracking.** RW episodes maintain a linked list of lease records with precomputed paths and lock tokens. Closing an episode or cancelling it unwinds any outstanding leases. Violations are latched (`cep_ep_episode_record_violation`) so CEI emits a single `ep:lease/missing` fact per offending slice.
- **Coroutine coordination.** Cooperative schedulers call `cep_ep_suspend_rw()` before yielding a mutating coroutine; the helper clears TLS guardrails and, when requested, releases leases. `cep_ep_resume_rw()` rebinds the context, reacquires dropped leases deterministically, and cancels the episode if another owner grabbed the lock in the meantime.

### Why E3 matters
- **Single control plane.** Long-running work stays inside OPS so the existing await/watcher contracts, history, and CEI hooks apply automatically.
- **Replay safety.** Episodes respect the capture → compute → commit cadence. No slice publishes visible mutations mid-beat; RW episodes stage their work and rely on heartbeat commit to graft results.
- **Predictable concurrency.** Threaded slices run concurrently only when marked RO and only with explicit budgets. FIFO ordering and deterministic watcher wake-ups keep replays stable regardless of OS scheduling.

### Executor backend considerations
- POSIX builds use `pthread` primitives surfaced through `cep_sync.c`; Windows builds use `CreateThread` + condition variables via the same abstraction layer. Both variants share queue bookkeeping so tests (unit, POC, sanitizers) cover both code paths.
- Worker threads share zero mutable global state. Communication occurs exclusively through the queue protected by `cepMutex`/`cepCond`. Shutdown broadcasts wake sleepers, waits for threads to join, and clears TLS state.
- Cooperative builds still execute slices during heartbeat commit; this keeps deterministic behaviour on platforms without threads (wasm/emscripten) and doubles as a predictable test harness.

### Migration checklist
1. Call `cep_ep_start()` to register the episode. Capture the signal/target paths and specify the desired execution profile and budgets.
2. Fold any bespoke wait handles into OPS watchers by calling `cep_ep_await()` or directly wiring `cep_op_await()` to the foreign dossier/event.
3. Audit mutators: ensure RW code paths acquire leases before touching cells, release them when done, and honour the guard result from `cep_ep_require_rw()`.
4. Update observability: tooling should inspect `/rt/ops/<eid>` history, watchers, and `close/` data rather than bespoke rendezvous registries.

## Q&A
**Q: How do threaded episodes stay deterministic if wall-clock scheduling differs per run?**  
Episodes only observe their own TLS context and cannot publish mutations mid-slice. The heartbeat still controls commit ordering, and FIFO queueing keeps slice order deterministic even when wall-clock interleaving varies.

**Q: Can RW episodes run on the threaded backend?**  
RW slices still execute cooperatively on the heartbeat thread. The threaded executor is reserved for RO work until we add the remaining synchronization primitives for RW slices; cancellation and budgeting continue to flow through the shared TLS context, so enabling threaded RW support later remains straightforward.

**Q: Where should I hook debugging or observability?**  
Use the OPS dossier (`/rt/ops/<eid>/history`, `/watchers`) for lifecycle and watcher status, and the diagnostics mailbox for guard/budget violations. Avoid bespoke logging pipelines; they drift from replay semantics.

**Q: Do I need to update the orientation guide when adding new episode helpers?**  
Yes. Extend `docs/DOCS-ORIENTATION-GUIDE.md` so contributors rediscover the relevant topic/design docs quickly. Update `docs/CEP-TAG-LEXICON.md` if new tags become public.
