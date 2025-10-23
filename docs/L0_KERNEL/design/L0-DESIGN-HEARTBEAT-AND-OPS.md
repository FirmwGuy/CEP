# L0 Design: Heartbeat, Agenda, and OPS Lifecycle

## Nontechnical Summary
Layer 0 advances time in strict beats. Each beat captures inputs, computes work, and commits results so replay stays deterministic. The heartbeat also owns long-running operations (`op/boot`, `op/shdn`, pack-defined ops) through the OPS subsystem, letting tooling watch progress without depending on ad-hoc signals. This design keeps the system calm: new work waits for the next beat, deterministic ordering prevents surprises, and lifecycle operations show their state in plain cells so operators can see what is happening.

## Decision Record
- Beats are the only mutation boundary; any work triggered mid-beat is deferred to keep agendas stable.
- Enzyme descriptors declare dependencies (`before`/`after`) so the resolver can produce a topological order without implicit heuristics.
- OPS timelines replace broadcast signals for lifecycle coordination, ensuring auditors have an immutable history with per-state watchers.
- Pending enzyme registrations activate on the next beat, sacrificing immediacy for determinism.
- Awaiters ride the regular agenda by enqueuing continuations (`op/cont`, `op/tmo`) scheduled for the next beat, guaranteeing single execution.

## Subsystem Map
- Code
  - `src/l0_kernel/cep_heartbeat.c`, `cep_heartbeat.h` — beat phases, agenda resolution, enqueue/commit logic.
  - `src/l0_kernel/cep_heartbeat_queue.c` — impulse queue storage.
  - `src/l0_kernel/cep_enzyme.c`, `cep_enzyme_bindings.c` — descriptor registry, binding inheritance.
  - `src/l0_kernel/cep_ops.c`, `cep_ops.h` — operation envelopes, history, watcher management.
- Tests
  - `src/test/l0_kernel/test_heartbeat.c`, `test_scheduler_randomized.c` — agenda ordering, dependency resolution, beat stepping.
  - `src/test/l0_kernel/test_ops.c` — OPS state transitions, watcher expiry.
  - `src/test/l0_kernel/test_enzyme.c` — registration, dependency, and binding inheritance behaviour.

## Operational Guidance
- Expose heartbeat metrics (beats per second, backlog depth, retry counts) when embedding in packs; anomalies here often signal deadlocks.
- Keep watcher TTLs reasonable; expired watchers fire `op/tmo` and should be handled explicitly.
- Prefer static enzyme registration during bootstrap; mid-beat registration is supported but increases agenda churn at the next activation.
- When scheduling long-running work, model it as an OPS timeline rather than bespoke queues so you inherit watcher semantics for free.
- Budget retries carefully; repeated `CEP_ENZYME_RETRY` should escalate to diagnostics to avoid quiet livelock.

## Change Playbook
1. Re-read this design doc plus `docs/L0_KERNEL/topics/HEARTBEAT-AND-ENZYMES.md` and `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md`.
2. Update or add unit tests in `src/test/l0_kernel/test_heartbeat.c` / `test_ops.c` to cover the new behaviour.
3. Modify `cep_heartbeat.c` or `cep_ops.c`, keeping deferred activation rules and single-commit guarantees intact.
4. Run `meson test -C build --suite heartbeat` (or the relevant subset) and `python tools/check_docs_structure.py`.
5. Update documentation references (topics, integration guide) if semantics change, then re-run `meson compile -C build docs_html`.
6. Record any new configurables or metrics in `docs/L0_KERNEL/L0-TUNING-NOTES.md` or pack readmes as needed.

## Global Q&A
- **Why defer enzyme activation to the next beat?** It prevents agendas from mutating mid-flight, keeping diagnostics and replay aligned.
- **Can multiple OPS timelines run concurrently?** Yes. Each operation tracks its own state under `/rt/ops/<oid>` and the heartbeat services their watchers during commit.
- **What if an enzyme needs to emit immediate follow-up work?** Stage it for the current beat if it touches the same agenda, otherwise enqueue an impulse so the next beat handles it deterministically.
- **How do I add new lifecycle states?** Extend the OPS helper to recognise the new `ist:*` value, add documentation, and adjust watchers/tests to expect the additional steps.
- **What guards infinite retry loops?** Enzymes must track retry budgets; watchers time out; the design expects packs to record diagnostics when `CEP_ENZYME_RETRY` repeats without progress.
