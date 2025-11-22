# L0 Topic: Heartbeat, Signals, and Enzymes

## Introduction

Think of CEP like a well-run workshop on a steady rhythm. Every few moments (a heartbeat), the team checks an impulse ledger—an inbox of small notes (signals) that say what needs doing and where. Skilled helpers (enzymes) pick the notes that match their job and do the work in a safe workbench. Results don’t appear instantly; they show up on the next beat. This rhythm keeps everything predictable, auditable, and calm.

What this means in simple terms:
- Signals are short requests dropped into the impulse ledger (`/rt/beat/<N>/impulses`).
- Enzymes are the workers (functions) that react to those requests.
- Work from beat N becomes visible at beat N+1, making the system easy to reason about and replay.

## Technical Design

The notes below translate the workshop metaphor into concrete data structures, file layout, and API contracts so you can inspect, debug, or extend the heartbeat without guessing at hidden state.

### Scope and Naming
- Enzyme: a C function that performs work. Multiple enzymes can react to the same situation.
- Signal (Impulse): a request to act, expressed as a `cepPath`. Signals are queued for a specific beat.
- Target: the cell (also a `cepPath`) where the action applies.
- Registry: a dictionary of “query” paths → lists of enzyme functions. An enzyme becomes available for processing only after registration under a query path.

### Filesystem Layout (Runtime)
- `rt/beat/<N>/impulses` — when `cepHeartbeatPolicy.ensure_directories` is true (enabled by default), each appended signal is logged here as a text value (`signal=/… target=/…`). A legacy link named `inbox` points to the same list for one release.
- `rt/beat/<N>/meta/unix_ts_ns` — persisted Unix timestamp (nanoseconds) for beat `N`, supplied by deterministic instrumentation.
- `rt/beat/<N>/agenda` — enzymes that executed during beat N, recorded with their name, return code, and the impulse that triggered them.
- `rt/beat/<N>/stage` — commit notes for beat N (for example, how many impulses were promoted to beat N+1).
- `rt/analytics/spacing` — sliding window (256 entries) of beat-to-beat intervals, pruned by the heartbeat until L1 regulators take over.
- Other runtime folders (tokens, locks, budgets, metrics) integrate with scheduling but are optional to the core mechanism.

### Signal Structure
- Each queued item carries two paths:
  - `signal_path` — the “what” of the request (kind, intent, domain).
  - `target_path` — the “where” (cell to act upon).
- Example: `(signal=/signals/image/thumbnail, target=/env/fs/projects/p1/img123.jpg)`
- CEI uses the reserved `sig_cei/<sev>` namespace so any component can subscribe to error severities. `cep_cei_emit()` enqueues those impulses for `cep_heartbeat_next()`, and they appear in the beat ledger (`rt/beat/<n>/impulses`) like any other signal.

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
- Impulse ledger order is by insertion.
  - Resolved enzymes run through Kahn’s algorithm to honour `before`/`after` constraints. When several enzymes are simultaneously ready, the dispatcher keeps the priority tuple: dual-path matches (target + signal) ahead of single-path, higher combined specificity, descriptor name, then registration order.
  - Each descriptor runs at most once per `(signal_path, target_path, beat)` pair.

### Canonical enzyme template
- Use the real prototype `int (*)(const cepPath *signal, const cepPath *target)`.
- Fetch context with `cep_enzyme_context_current()`, require RW via `cep_ep_require_rw()`, then resolve/mutate through the standard helpers so branch policy and enclave guards fire automatically.
- Return `CEP_ENZYME_SUCCESS` on success; `CEP_ENZYME_RETRY` to ask for re-run; `CEP_ENZYME_FATAL` to abort.

```c
static int ez_update(const cepPath *sig, const cepPath *tgt) {
    (void)sig;
    const cepEnzymeContext *ctx = cep_enzyme_context_current();
    if (!ctx || cep_ep_require_rw(ctx) != CEP_OK) return CEP_ENZYME_FATAL;

    cepCell *root = cep_root();
    if (!root || !tgt) return CEP_ENZYME_FATAL;

    cepCell *parent = cep_cell_find_by_path(root, tgt);
    if (!parent) return CEP_ENZYME_FATAL;

    cepDT name = /* build DT for child name */;
    cepCell *child = cep_cell_find_by_name(parent, &name);
    if (!child) {
        if (cep_cell_make_scratch_dt(&name, CEP_STORE_DICTIONARY, &child) != CEP_OK)
            return CEP_ENZYME_FATAL;
        if (cep_cell_add(parent, child) != CEP_OK) return CEP_ENZYME_FATAL;
    }

    cepData *d = cep_cell_data(child);
    if (cep_data_set_value(d, "new-bytes", strlen("new-bytes")) != CEP_OK)
        return CEP_ENZYME_FATAL;
    return CEP_ENZYME_SUCCESS;
}
```

### Heartbeat Cycle
1) Begin beat N: create/ensure `rt/beat/<N>/*` structures.
2) Resolve agenda: for each impulse ledger entry, find all matching enzymes via the registry, order them deterministically, and enqueue them in `rt/beat/<N>/agenda`. The dispatcher memoises the resolved descriptor list for each unique `(signal_path, target_path)` pair during the beat so later duplicates reuse the cached ordering instead of repeating the registry scan.
3) Execute agenda: call each enzyme with `(signal_path, target_path)`.
4) Staging: enzymes write outputs and side effects to `rt/beat/<N>/stage` and may emit new signals destined for `rt/beat/<N+1>/impulses`.
5) Commit boundary (N → N+1): staged outputs become visible; newly emitted signals are now eligible for processing in the next beat.

### Emitting New Work
- Within an enzyme body, call `cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, signal, target)`; the runtime targets the next beat, records the textual entry under `rt/beat/<N+1>/impulses`, and queues the impulse in memory. Large payloads should be written to a content store (e.g., under `cas/…`) and referenced by hash in staged outputs or journals.
- Enzymes may emit additional signals; the helper appends those to the next beat’s queue and logs the textual summary under `rt/beat/<N+1>/impulses` so replay has a durable ledger.

### Wallclock capture and spacing analytics
- Call `cep_heartbeat_publish_wallclock(beat, unix_ts_ns)` once per beat with a deterministically captured Unix timestamp (nanoseconds). The helper writes the value to `/rt/beat/<beat>/meta/unix_ts_ns`, rejects conflicting rewrites, and records the interval since the previous timestamp under `/rt/analytics/spacing/<beat>/interval_ns`.
- Retrieve stored timestamps via `cep_heartbeat_beat_to_unix()`. Until L1 predators/regulators supervise analytics retention, the spacing helper prunes the dictionary to the most recent 256 entries using hard deletes—`FIXME` notes in code document the future cleanup.
- Adjust the spacing retention window at runtime with `cep_heartbeat_set_spacing_window()` (and inspect it via `cep_heartbeat_get_spacing_window()`); the pruner trims analytics immediately when the window shrinks.
- Stage notes, OPS history entries, and stream journal/outcome records now embed the captured `unix_ts_ns` so textual logs and binary payloads share human-readable timestamps alongside beat counters.

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
1) Beat 1, `cep_heartbeat_enqueue_signal` records `(signal=/signals/image/thumbnail, target=/env/fs/projects/p1/img123.jpg)` under `rt/beat/1/impulses` and queues it for the next beat.
2) Registry has descriptors:
   - `resize_image` registered under `/signals/image/thumbnail`.
   - `image_metadata` registered under `/env/fs/projects/*`.
   The `/env/fs/projects/` cell binds `image_metadata` with propagation enabled.
3) Bindings gathered along the target path yield `image_metadata`; the signal adds `resize_image`. Signal filtering keeps both; `resize_image` wins the first slot thanks to the dual match.
4) `resize_image` stages thumbnail bytes and calls `cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, /signals/db/write, /data/assets/img123/thumbnail)` to record the follow-up impulse.
5) Beat 2 repeats the process, using bindings under `/data/assets/` to drive follow-up work, while `rt/beat/2` accumulates the agenda and stage logs for auditing.

### Mailbox TTL and retention helpers
- `cep_mailbox_select_message_id()` enforces the caller → digest → counter precedence for message identifiers and detects collisions by hashing sealed envelopes before beats advance.
- `cep_mailbox_resolve_ttl()` projects per-message TTLs against mailbox policy and topology defaults, capturing both beat deadlines and wallclock deadlines (or the `ttl_mode="forever"` sentinel for private inboxes). When a policy provides only wallclock TTLs, heuristics consult `/rt/analytics/spacing` so retention enzymes still receive a projected beat—toggle `cep_mailbox_disable_wallclock()` to freeze this behaviour while debugging.
- `cep_mailbox_record_expiry()` writes deterministic expiry buckets under `meta/runtime/expiries/<beat>/` and `meta/runtime/exp_wall/<unix_ns>/` so retention work queues persist inside the tree.
- `cep_mailbox_plan_retention()` scans those buckets each beat, returning two partitions (beat-first, wallclock-first) plus hints about future work so enzymes can purge deterministically and requeue themselves when necessary.

### Design Invariants
- Deterministic order at every step (impulse insertion, match ordering,
  dependency-aware enzyme ordering, name-based tie-breaks).
- Single-run per enzyme per pair in a beat.
- No visibility leaks: outputs from N only become visible at N+1.
- Pure path addressing: enzymes receive only paths, never raw internal pointers.

### Testing Notes
- Unit-test matching rules with fixed registries and synthetic impulse ledgers.
- Simulate multiple beats to confirm N→N+1 visibility and idempotency.
- Verify that reordering registrations or impulse ledger entries changes outcomes only as defined by the deterministic rules.
- Inject deterministic timestamps through `cep_heartbeat_publish_wallclock()`, assert the `/meta/unix_ts_ns` payloads, and check spacing analytics stay within the pruning window.
- Cover mailbox flows by exercising `cep_mailbox_resolve_ttl()` (beat + wallclock precedence), `cep_mailbox_record_expiry()` (bucket topology), and `cep_mailbox_plan_retention()` (partitioning) for both public boards and private inboxes.

## OPS/STATES Operations

OPS/STATES dossiers ride the same heartbeat as enzymes; this section explains how the helpers model long-running work, watchers, and close records so integrations can observe progress without touching raw cells.

### Overview
OPS/STATES gives every long-running operation a tidy logbook under `/rt/ops/<oid>`. A start helper seals the envelope (verb, target, mode, optional payload), subsequent state helpers append history entries, awaiters register continuations, and close seals the dossier. Instead of orchestrating these cells by hand, callers drive the lifecycle with a few purpose-built APIs while the heartbeat guarantees the same deterministic beat-to-beat cadence.

### Technical Details
- **Layout.** `cep_op_start()` fabricates a floating branch, seals `envelope/`, stamps `state=ist:run`, seeds an append-only `history/` list, and ensures a mutable `watchers/` dictionary is ready. Children are auto-named (`OPS/*` for ops, `OPH/*` for history, `OPW/*` for watchers) so lookups stay cheap.
- **State transitions.** `cep_op_state_set(oid, ist:*, code, note)` updates the live `state`, records the beat in `history/`, and fires watchers that asked for that state. Repeating the same state within the same beat is treated as idempotent (history is unchanged, but `code/note` can refresh).
- **Awaiters.** `cep_op_await(oid, want, ttl, cont, payload, len)` resolves immediately if `want` already matches the current state or the terminal status; otherwise it writes a watcher entry with `want`, `deadline` (current beat + ttl), `cont`, optional `payload_id`, provenance info, and an `armed` flag. Immediate matches simply flip `armed=true` so the continuation still rides the heartbeat boundary. On the beat where `armed=true` or `deadline <= current`, `cep_ops_stage_commit()` enqueues the appropriate impulse (`cont` vs. `op/tmo`) for N+1 and removes the watcher so continuations stay deterministic.
- **Closure.** `cep_op_close(oid, sts, summary, len)` produces an immutable `close/` branch (`status`, `closed_beat`, optional `summary_id`), maps the status to `ist:ok|fail|cnl`, appends the last history entry, and blocks further mutations. A repeat close with the same status is a no-op; mismatched statuses are rejected.
- **Heartbeat integration.** The heartbeat calls `cep_ops_stage_commit()` during commit so awaiter continuations and timeouts ride the same promotion path as other impulses. Tests advance beats with `cep_heartbeat_step()` and drain the agenda with `cep_heartbeat_resolve_agenda()` to assert single-fire behaviour.
- **Inspection.** `cep_op_get(oid, buf, cap)` emits a compact textual summary (OID, state, status, watcher count) for tooling. For deeper audits, traverse `/rt/ops/<oid>` directly: envelope and close are immutable, while history and watchers remain append-only/mutable as expected.

## Global Q&A
- **When should I prefer `opm:direct` vs. `opm:states`?** Use `opm:direct` for two-pulse work (start → close). Choose `opm:states` when intermediate checkpoints must be observable or awaitable.
- **How do I unit-test awaiters?** Register a test enzyme on `op/cont` (or `op/tmo`), call `cep_op_await()`, step the heartbeat once, then resolve the agenda. The enzyme should fire exactly once; if it never runs, revisit the watcher inputs.
- **What happens if I call `cep_op_state_set()` after `cep_op_close()`?** The helper returns `false`; closing seals the branch, so further work must run through a new operation.
- **Can I stash large artefacts alongside the close summary?** Yes. Put a CAS handle or library reference in the `summary` payload—close keeps it immutable while the bytes live in content storage.
- **Why call functions “enzymes” and messages “signals/impulses”?** Enzymes catalyse work while signals request it. The metaphor keeps roles clear: callbacks act; impulses ask.
- **Can multiple enzymes react to the same signal?** Yes. Any bound enzyme matching the filter runs. Deterministic ordering comes from specificity, name, and registration order after dependencies resolve.
- **How do enzymes coordinate when registrations change mid-beat?** Descriptors declare `before`/`after` lists. The resolver builds a dependency graph of matched enzymes each beat, topologically sorts it, and caches the result until pending registrations activate.
- **What prevents infinite loops?** Budgets, match constraints, and idempotent checks. An enzyme emitting the same signal without state change should detect and bail.
- **Is execution parallel?** It can be, provided agenda order and commit determinism hold. Parallel workers must respect staging and the final single commit.
- **How do failures get retried?** Retry policies re-enqueue the signal for beat N+1 with counters/backoff. Enzymes must remain idempotent so retries stay safe.
- **Do enzymes need direct access to payload bytes?** Prefer handles/streams plus journalled content IDs so work stays replayable and auditable.
- **How do I choose query paths?** Register using the most stable discriminator you have—often the signal namespace plus domain/tag filters that reflect intent.
