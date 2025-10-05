# Layer 2 Algorithms

Think of Layer 2 as a conductor: it keeps the score of every flow, cues each section at the right beat, and records the performance so we can replay it perfectly later.

---

## Technical Details
- **Flow bootstrap** – `cep_l2_flows_bootstrap()` provisions `/data/flow/*` ledgers, inbox branches, and `/tmp/flow/adj`. `cep_l2_flows_register()` binds all L2 enzymes to `CEP:sig_cell/op_add`, wiring the agenda as `fl_ing → ni_ing → inst_ing → fl_wake → fl_step → fl_index → fl_adj` and binding descriptor DTs to `/data/flow`.
- **Ingest (`fl_ing`, `ni_ing`, `inst_ing`)** – Requests are copied into ledger entries with `original/*` mirrors. Canonicalisation stages verify identifiers via the namepool, link cross-ledger references (variant → program, niche → variant, decision → policy), and normalise step specs. Instance ingestion seeds `state=ready`, `pc=0`, `events/budget` dictionaries, and `original` snapshots.
- **Wake (`fl_wake`)** – Events resolve targeted instance IDs or broadcast across all instances. Subscriptions created by Wait steps match signals (exact/glob) and optional context signatures; matches enqueue structured event records (`events/<beat_index>` with payload, signal, origin, history log) and mark subscriptions `triggered`.
- **Stepper (`fl_step`)** – For each `ready` instance the loop honours per-instance clamp budgets. Guards exit or branch by setting `state`. Transforms stage emissions in `emits`. Waits create/update subscription entries and transition instances to `waiting`. Decide locks the Decision ledger bucket, reuses or writes a Decision Cell, stores validation/evidence, telemetry (`score`, `confidence`, `rng_*`, `latency`, `error_flag`), and applies retention. Clamp updates budgets, handles timeouts, and may pause the instance.
- **Index (`fl_index`)** – Before recomputing indexes, the enzyme enforces retention (prune/archive). It then rebuilds `inst_by_var`, `inst_by_st`, and `dec_by_pol` buckets, refreshing metadata counters and copying telemetry snippets onto policy summaries (`meta/lat_window`, `meta/err_window`, `meta/fingerprint`, etc.).
- **Adjacency (`fl_adj`)** – Clears `/tmp/flow/adj/by_inst/*`, writes per-instance snapshots (state, pc, counts, latest event link, `lat_window`, `err_window`, signal/context history), and provides live latency metrics derived from event history plus the current beat.
- **Budgets & deadlines** – Clamp steps call `cep_l2_budget_state_prepare()` to merge spec overrides with stored budgets. Deadlines are tracked inside `budget/` and Wait subscription entries via `deadline` tags; timeouts push instances back to `ready` while logging status transitions in event history.

## Q&A
- **Where do policy scores come from?**
  Policies may write `telemetry/*`; otherwise L2 seeds deterministic pseudo-random values derived from fingerprints, instance IDs, and beat numbers so replays stay identical.
- **How are retention TTLs computed?**
  The engine records `retain_ttl` and `retain_upto` on each Decision Cell. During `fl_index`, anything whose expiry beat is ≤ current beat moves to `dec_archive` (for `archive` mode) or is deleted (for `ttl`).
- **What keeps agenda ordering stable?**
  Enzyme descriptors use `after[]` chains and the resolver’s topological sort. Additional bindings on `/data/flow` bias resolver scoring so L2 handlers win over generic subscribers.
- **How do transforms publish work?**
  `fl_step` only stages results in `emits`. Publishing remains a TODO for downstream perspectives/integrations; today tests inspect staged output directly.
