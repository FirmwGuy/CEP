# L0 Topic: Heartbeat, Signals, and Enzymes

## Introduction

Think of CEP like a well-run workshop on a steady rhythm. Every few moments (a heartbeat), the team checks an inbox of small notes (signals) that say what needs doing and where. Skilled helpers (enzymes) pick the notes that match their job and do the work in a safe workbench. Results don’t appear instantly; they show up on the next beat. This rhythm keeps everything predictable, auditable, and calm.

What this means in simple terms:
- Signals are short requests dropped into an inbox.
- Enzymes are the workers (functions) that react to those requests.
- Work from beat N becomes visible at beat N+1, making the system easy to reason about and replay.

## Technical Design

### Scope and Naming
- Enzyme: a C function that performs work. Multiple enzymes can react to the same situation.
- Signal (Impulse): a request to act, expressed as a `cepPath`. Signals are queued for a specific beat.
- Target: the cell (also a `cepPath`) where the action applies.
- Registry: a dictionary of “query” paths → lists of enzyme functions. An enzyme becomes available for processing only after registration under a query path.

### Filesystem Layout (Runtime)
- `rt/beat/<N>/inbox` — when `cepHeartbeatPolicy.ensure_directories` is true (enabled by default), each appended signal is logged here as a text value (`signal=/… target=/…`).
- `rt/beat/<N>/agenda` — enzymes that executed during beat N, recorded with their name, return code, and the impulse that triggered them.
- `rt/beat/<N>/stage` — commit notes for beat N (for example, how many impulses were promoted to beat N+1).
- Other runtime folders (tokens, locks, budgets, metrics) integrate with scheduling but are optional to the core mechanism.

### Signal Structure
- Each queued item carries two paths:
  - `signal_path` — the “what” of the request (kind, intent, domain).
  - `target_path` — the “where” (cell to act upon).
- Example: `(signal=/signals/image/thumbnail, target=/env/fs/projects/p1/img123.jpg)`

### Registering Enzymes
- API sketch
  - `typedef int (*cepEnzyme)(const cepPath *signal, const cepPath *target);`
  - `int cep_enzyme_register(const cepPath *query, const cepEnzymeDescriptor *descriptor);`
  - `int cep_cell_bind_enzyme(cepCell *cell, const cepDT *name, bool propagate);`
  - `int cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath *signal, const cepPath *target);`
  - `bool cep_heartbeat_step(void);`
- Semantics
  - Registration publishes descriptor metadata (callback, name, before/after dependencies, match policy) under a query path.
  - Binding attaches the descriptor name to a cell. Bindings can propagate to descendants; tombstones cancel inherited bindings at or below a node.
  - Multiple descriptors can share the same query and a cell can bind several enzyme names; deterministic identifiers keep agenda ordering stable.

### Matching and Determinism
- Matching
  - If a `target_path` is present, gather bindings along the target’s ancestor chain (propagate flag extends bindings downward, tombstones cancel inherited entries). Only bound enzyme names are considered.
  - If a `signal_path` is also present, filter those bound enzymes to descriptors whose query matches the signal (exact or prefix, depending on the descriptor policy).
  - If no `target_path` is present, resolve candidates directly from the signal index (broadcast).
- Matching policy for descriptors remains deterministic: prefer higher specificity, then descriptor name, then registration order.
- Ordering
  - Inbox order is by insertion.
  - Resolved enzymes run through Kahn’s algorithm to honour `before`/`after` constraints. When several enzymes are simultaneously ready, the dispatcher keeps the priority tuple: dual-path matches (target + signal) ahead of single-path, higher combined specificity, descriptor name, then registration order.
  - Each descriptor runs at most once per `(signal_path, target_path, beat)` pair.

### Heartbeat Cycle
1) Begin beat N: create/ensure `rt/beat/<N>/*` structures.
2) Resolve agenda: for each inbox item, find all matching enzymes via the registry, order them deterministically, and enqueue them in `rt/beat/<N>/agenda`. The dispatcher memoises the resolved descriptor list for each unique `(signal_path, target_path)` pair during the beat so later duplicates reuse the cached ordering instead of repeating the registry scan.
3) Execute agenda: call each enzyme with `(signal_path, target_path)`.
4) Staging: enzymes write outputs and side effects to `rt/beat/<N>/stage` and may emit new signals destined for `rt/beat/<N+1>/inbox`.
5) Commit boundary (N → N+1): staged outputs become visible; newly emitted signals are now eligible for processing in the next beat.

### Emitting New Work
- Within an enzyme body, call `cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, signal, target)`; the runtime targets the next beat, records the textual entry under `rt/beat/<N+1>/inbox`, and queues the impulse in memory. Large payloads should be written to a content store (e.g., under `cas/…`) and referenced by hash in staged outputs or journals.

### Error Handling and Idempotency
- Return values: enzymes return a status code (e.g., 0 = success; negative for retryable or permanent failures).
- Retries: a retry policy can requeue failed work for `N+1` with backoff, provided determinism is preserved.
- Idempotency: design enzymes such that re-invoking with the same inputs either no-ops or reproduces the same staged outcome.

### Pseudocode (C-style Sketch)

```
typedef int (*cepEnzyme)(const cepPath *signal, const cepPath *target);

typedef struct {
  cepDT                name;
  const cepDT*         before;
  size_t               before_count;
  const cepDT*         after;
  size_t               after_count;
  cepEnzyme            callback;
  cepEnzymeMatchPolicy match;
  cepEnzymeFlags       flags;
} cepEnzymeDescriptor;

int  cep_enzyme_register(const cepPath *query, const cepEnzymeDescriptor *descriptor);
int  cep_cell_bind_enzyme(cepCell *cell, const cepDT *name, bool propagate);
int  cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath *signal, const cepPath *target);
bool cep_heartbeat_resolve_agenda(void);
bool cep_heartbeat_execute_agenda(void);
bool cep_heartbeat_stage_commit(void);

bool cep_heartbeat_step(void) {
  bool ok = cep_heartbeat_resolve_agenda();
  ok = ok && cep_heartbeat_execute_agenda();
  ok = ok && cep_heartbeat_stage_commit();
  return ok;
}
```

During setup, register descriptors first and then call `cep_cell_bind_enzyme` on the cells that should emit the work. Bindings are append-only at runtime; apply them before starting the heartbeat loop to keep the beat boundary deterministic.

### Example Flow
1) Beat 1, `cep_heartbeat_enqueue_signal` records `(signal=/signals/image/thumbnail, target=/env/fs/projects/p1/img123.jpg)` under `rt/beat/1/inbox` and queues it for the next beat.
2) Registry has descriptors:
   - `resize_image` registered under `/signals/image/thumbnail`.
   - `image_metadata` registered under `/env/fs/projects/*`.
   The `/env/fs/projects/` cell binds `image_metadata` with propagation enabled.
3) Bindings gathered along the target path yield `image_metadata`; the signal adds `resize_image`. Signal filtering keeps both; `resize_image` wins the first slot thanks to the dual match.
4) `resize_image` stages thumbnail bytes and calls `cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, /signals/db/write, /data/assets/img123/thumbnail)` to record the follow-up impulse.
5) Beat 2 repeats the process, using bindings under `/data/assets/` to drive follow-up work, while `rt/beat/2` accumulates the agenda and stage logs for auditing.

### Design Invariants
- Deterministic order at every step (inbox insertion, match ordering,
  dependency-aware enzyme ordering, name-based tie-breaks).
- Single-run per enzyme per pair in a beat.
- No visibility leaks: outputs from N only become visible at N+1.
- Pure path addressing: enzymes receive only paths, never raw internal pointers.

### Testing Notes
- Unit-test matching rules with fixed registries and synthetic inboxes.
- Simulate multiple beats to confirm N→N+1 visibility and idempotency.
- Verify that reordering registrations or inbox entries changes outcomes only as defined by the deterministic rules.

## OPS/STATES Operations

### Introduction
OPS/STATES gives every long-running operation a tidy logbook under `/rt/ops/<oid>`. A start helper seals the envelope (verb, target, mode, optional payload), subsequent state helpers append history entries, awaiters register continuations, and close seals the dossier. Instead of orchestrating these cells by hand, callers drive the lifecycle with a few purpose-built APIs while the heartbeat guarantees the same deterministic beat-to-beat cadence.

### Technical Details
- **Layout.** `cep_op_start()` fabricates a floating branch, seals `envelope/`, stamps `state=ist:run`, seeds an append-only `history/` list, and ensures a mutable `watchers/` dictionary is ready. Children are auto-named (`OPS/*` for ops, `OPH/*` for history, `OPW/*` for watchers) so lookups stay cheap.
- **State transitions.** `cep_op_state_set(oid, ist:*, code, note)` updates the live `state`, records the beat in `history/`, and fires watchers that asked for that state. Repeating the same state within the same beat is treated as idempotent (history is unchanged, but `code/note` can refresh).
- **Awaiters.** `cep_op_await(oid, want, ttl, cont, payload, len)` resolves immediately if `want` already matches the current state or the terminal status; otherwise it writes a watcher entry with `want`, `deadline` (current beat + ttl), `cont`, optional `payload_id`, and provenance info. On the beat where `deadline <= current`, `cep_ops_stage_commit()` enqueues an `op/tmo` impulse for N+1 and removes the watcher so timeouts stay deterministic.
- **Closure.** `cep_op_close(oid, sts, summary, len)` produces an immutable `close/` branch (`status`, `closed_beat`, optional `summary_id`), maps the status to `ist:ok|fail|cnl`, appends the last history entry, and blocks further mutations. A repeat close with the same status is a no-op; mismatched statuses are rejected.
- **Heartbeat integration.** The heartbeat calls `cep_ops_stage_commit()` during commit so awaiter continuations and timeouts ride the same promotion path as other impulses. Tests advance beats with `cep_heartbeat_step()` and drain the agenda with `cep_heartbeat_resolve_agenda()` to assert single-fire behaviour.
- **Inspection.** `cep_op_get(oid, buf, cap)` emits a compact textual summary (OID, state, status, watcher count) for tooling. For deeper audits, traverse `/rt/ops/<oid>` directly: envelope and close are immutable, while history and watchers remain append-only/mutable as expected.

### Q&A
- *When should I prefer `opm:direct` vs. `opm:states`?* Pick `opm:direct` for two-pulse work (start → close). Choose `opm:states` when intermediate checkpoints (`ist:skel`, `ist:unveil`, ...) need to be observable or awaitable.
- *How do I unit-test awaiters?* Register a test enzyme on `op/cont` (or `op/tmo`), call `cep_op_await()`, advance with `cep_heartbeat_step()`, then call `cep_heartbeat_resolve_agenda()`. The enzyme should run exactly once—if it triggers immediately, the state was already satisfied; if it never fires, the watcher was misconfigured.
- *What happens if I call `cep_op_state_set()` after `cep_op_close()`?* The helper returns `false`. Closing seals the managed branch, so subsequent writes must go through a new operation if additional work is needed.
- *Can I stash large artefacts alongside the close summary?* Yes. Store a CAS handle or library reference in the `summary` payload; the close branch keeps it immutable while leaving the heavy bytes in the content store.

## Q&A

- Why call functions “enzymes” and messages “signals/impulses”? 
  Enzymes are the actors that catalyze work; signals are the conditions that trigger them. This mirrors the biological metaphor and keeps terminology clear: functions do work; signals request work.

- Can multiple enzymes react to the same signal? 
  Yes. Any bound enzyme whose descriptor also passes the signal filter runs. Order remains deterministic: specificity, name, and registration order decide ties after dependencies are satisfied.

- How do enzymes coordinate when dynamic registration changes the available set during a beat?
  Enzymes declare a stable `cepDT` name plus optional `before` / `after` lists.
  At resolve time CEP builds a temporary dependency graph of the enzymes that
  match the impulse, performs a topological sort, and orders the agenda
  accordingly. Registration can occur at program start, shared-library load, or
  mid-run: the dependency metadata keeps execution deterministic in all cases.
  The heartbeat’s memoised cache is scoped to the current beat, so once pending
  registrations are activated they cause a fresh resolve and populate new cache
  entries automatically.

- What prevents infinite loops? 
  Budgets, match constraints, and idempotent checks. If an enzyme would emit the same signal repeatedly without changing state, it should detect and skip.

- Is execution parallel? 
  It can be, as long as determinism is preserved (e.g., fixed agenda order with isolated staging and a deterministic commit phase). The model does not require parallelism.

- How do failures get retried? 
  A retry policy may re-enqueue the pair for N+1 with counters/backoff. Enzymes must be idempotent so retries don’t corrupt state.

- Do enzymes need access to raw data? 
  Prefer handles/streams and content-addressed bytes with journaling, so work is replayable and auditable.

- How do I choose query paths? 
  Register by the most stable and meaningful discriminator you have: often the signal namespace (intent) and, secondarily, target domains.
