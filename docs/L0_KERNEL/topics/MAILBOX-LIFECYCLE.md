# L0 Topic: Mailbox Lifecycle

## Introduction
Mailboxes give packs a structured way to capture messages, enforce retention policies, and keep deterministic history without inventing new plumbing. This topic is the quick tour: it explains how the shared helper APIs pick message identifiers, honour beat and wallclock TTLs, and schedule expiry work so you can focus on higher-level workflows instead of reimplementing boilerplate.

## Technical Details

Use these notes when you need the exact storage layout or helper behaviour for mailbox identity, TTL resolution, and retention planning; they capture the invariants implied by the design rationale so code changes stay compatible.

### Message identity helpers
- `cep_mailbox_select_message_id()` settles the identifier for a message. It respects the precedence chain (caller-supplied → envelope digest → counter fallback), detects collisions by hashing the sealed envelope, and records which strategy won. Reusing a message ID with an identical sealed envelope returns a `CEP_MAILBOX_ID_REUSED` result so callers can short-circuit duplicate writes.
- The helper expects envelopes to be immutable (`cep_cell_set_immutable()` or `cep_branch_seal_immutable()`); otherwise the digest path is skipped and the counter fallback is used.
- Counter fallback state lives under `meta/runtime/next_msg_id` inside each mailbox root, keeping replay runs idempotent.

### TTL resolution and policy precedence
- `cep_mailbox_resolve_ttl()` merges TTL information from three scopes: the message envelope (`envelope/ttl/*`), mailbox policy (`meta/policy/*`), and topology defaults. It honours the first scope that specifies `ttl_mode="forever"` and records which scope provided beat or wallclock durations.
- Beat deadlines are computed relative to the issued beat (`ctx.issued_beat`), while wallclock deadlines use the captured timestamp (`ctx.issued_unix_ns`). When only wallclock TTLs exist, the helper can project a beat deadline using spacing analytics unless `cep_mailbox_disable_wallclock(true)` is in effect.
- `cep_mailbox_ttl_context_init()` samples the current heartbeat state so resolution routines share a consistent baseline. Callers can override the fields when envelopes publish explicit `issued_*` data.

### Retention buckets and planning
- `cep_mailbox_record_expiry()` writes deterministic expiry buckets under `meta/runtime/expiries/<beat>/<msg-id>` and `meta/runtime/exp_wall/<unix_ns>/<msg-id>`. Entries are stored as links to the message so retention enzymes stay append-only and replay-safe.
- `cep_mailbox_plan_retention()` scans those buckets each beat, splitting the workload into `beats` (due now) and `wallclock` (due now) partitions. It also signals whether future work remains so enzymes know when to reschedule themselves. A `FIXME` in the helper reminds us to hand over long-lived backlog management to L1 regulators.
- `cep_mailbox_set_expiry_windows()` tunes lookahead behaviour: the beat lookahead clamps projected deadlines derived from wallclock heuristics, while the spacing sample limit caps how many entries the heuristic consumes.

### Recommended workflow
1. Build or clone an immutable envelope for the message and call `cep_mailbox_select_message_id()`.
2. Resolve TTLs with `cep_mailbox_resolve_ttl()` (after initialising a context) and store the resolved metadata alongside the message so diagnostics stay traceable.
3. Write the message subtree under `msgs/<id>` and call `cep_mailbox_record_expiry()` once the message is visible.
4. In your retention enzyme, call `cep_mailbox_plan_retention()` at the start of the beat, process due partitions, and requeue yourself if `has_future_*` flags remain true.

### Diagnostics mailboxes and CEI
- Layer 0 seeds a diagnostics mailbox at `/data/mailbox/diag` during bootstrap. `cep_cei_emit()` falls back to that mailbox whenever callers do not supply `mailbox_root`, ensuring CEI facts always land somewhere deterministic.
- The diagnostics mailbox carries the same `meta/runtime/expiries*` structure as any other mailbox. CEI requests populate TTL hints (`ttl_beats`, `ttl_unix_ns`, `forever`) before the helper records deadlines through `cep_mailbox_record_expiry()`.
- Use the shared mailbox when you need a universal CEI feed; packs can still pass their own mailbox root to keep partitioned diagnostics but should reuse the same TTL planning helpers so retention enzymes behave consistently.

## Global Q&A
- **Why does the helper fall back to a counter instead of failing?** Mailboxes are often fed by external systems that cannot always deliver stable digests. The counter fallback keeps ingestion deterministic while still flagging collisions for manual diagnostics.
- **Do private inboxes need TTLs?** Private inbox policy defaults to `ttl_mode="forever"`, but per-message overrides still win. This lets packs honour “forever” semantics without relaxing the enforcement machinery.
- **Can I skip the analytics dependency?** Yes. Toggle `cep_mailbox_disable_wallclock(true)` when you are debugging without spacing data. The resolved structure records that heuristics were skipped so retention enzymes can adjust expectations.
