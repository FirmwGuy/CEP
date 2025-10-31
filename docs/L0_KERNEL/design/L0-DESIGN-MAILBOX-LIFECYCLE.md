# L0 Design: Mailbox Lifecycle Rationale

## Introduction
Mailboxes sit at the crossroads of Layer‑0 identity, policy, and retention. Their design balances determinism (so replays reproduce the same history) with pragmatism (so packs can drop in without bespoke scaffolding). This note captures the architectural reasoning behind the helper APIs, storage layout, and retention queue strategy so future refactors keep the same guarantees.

## Technical Details

This section documents the concrete mechanics behind identity selection, TTL resolution, and retention so implementation work can lean on the same guarantees captured in the design rationale.

### Identity precedence and collision handling
- **Problem:** Packs must support caller IDs, drive idempotent retries, and still ingest messages from sources that cannot provide stable names.
- **Decision:** Implement a fixed precedence order: caller-supplied ID → digest slug → counter fallback. Digest selection depends on envelopes being immutable so the hash remains reproducible. When a collision appears (same ID, different envelope), the helper refuses the pick and reports the collision so the caller can surface diagnostics instead of silently overwriting history.
- **Alternatives considered:** Always hashing the envelope would have broken existing packs that rely on human-friendly IDs. Conversely, relying solely on caller IDs pushes complexity into every caller. The mixed strategy keeps the fast-path simple while guarding against sloppy inputs.

### TTL resolution and heuristics
- **Problem:** Mailboxes need to respect per-message TTLs, mailbox defaults, and topology-wide policies, while still supporting beat-driven enforcement and wallclock analytics.
- **Decision:** Represent each scope as a `cepMailboxTTLSpec` and resolve them with a fixed precedence (message → mailbox → topology). Beat deadlines use the issued beat; wallclock deadlines use `issued_unix_ns`. When wallclock-only TTLs appear, the solver consults `/rt/analytics/spacing` to project a beat. The helper records which scope provided each value and whether heuristics were used so retention enzymes and observability tooling can reason about the result.
- **Alternatives considered:** Forcing callers to compute deadlines themselves would scatter policy logic and risk conflicting precedence orders. Expecting spacing analytics to always be present would punish offline or test builds. The current approach keeps heuristics optional and surfaces enough metadata to make downstream decisions explicit.

### Retention buckets and enzyme workload
- **Problem:** Retention must stay deterministic, replay-safe, and cheap to query. Enzymes should know what is due now and whether future work is recorded.
- **Decision:** Store expiry buckets inside `meta/runtime/` as dictionaries of links. Separate beat (`expiries/<beat>/`) and wallclock (`exp_wall/<unix_ns>/`) queues so enzymes can partition work and honour whichever policy triggered the expiry. `cep_mailbox_plan_retention()` returns copies of due IDs plus hints (`has_future_*`) so the enzyme can reschedule itself without re-traversing buckets mid-beat. A FIXME remains to hand off long-lived backlog management to L1 regulators when that infrastructure exists.
- **Alternatives considered:** Streaming buckets straight from `/rt/analytics` would couple policy to analytics retention and break replay. Deleting messages inline without staging would violate the append-only contract. The current queue design keeps retention work explicit, auditable, and safe to replay.

## Global Q&A
- **Why are expiry buckets links instead of copies?** Links let us preserve the append-only store, avoid duplicating payload state, and keep retention enzymes focused solely on scheduling. If a message moves or is recomputed, link resolution still hits the current canonical location.
- **What happens if spacing analytics are disabled?** The resolver records that heuristics were skipped. Retention enzymes still get wallclock deadlines, and tests can toggle `cep_mailbox_disable_wallclock(true)` to maintain predictable behaviour without analytics data.
- **Could we share buckets across mailboxes?** Not without sacrificing locality. Keeping buckets inside each mailbox root keeps per-mailbox policy changes isolated and lets packs manage retention without scanning global structures.
