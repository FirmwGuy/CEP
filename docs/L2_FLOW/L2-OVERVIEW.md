# Layer 2 Overview

Layer 2 teaches the runtime how to run playbooks: it wraps the raw facts from Layer 0 and the ledgers from Layer 1 in living flows, so product teams can tell the system “try this tactic, log every choice, and replay it whenever we need to explain ourselves.”

---

## Technical Details
- **Scope** – L2 adds a deterministic Flow VM with five programmable steps (Guard, Transform, Wait, Decide, Clamp). It anchors durable ledgers under `/data/flow/*` (`program`, `variant`, `policy`, `niche`, `guardian`, `instance`, `decision`, `index`) and transient caches under `/tmp/flow/*`.
- **Intents & enzymes** – Inboxes accept `fl_upsert`, `ni_upsert`, `inst_start`, `inst_event`, and `inst_ctrl` intents. Enzymes (`fl_ing`, `ni_ing`, `inst_ing`, `fl_wake`, `fl_step`, `fl_index`, `fl_adj`) are registered on the canonical agenda path `CEP:sig_cell/op_add` with strict before/after ordering so beats deterministically follow ingestion → wake → stepping → indexing → adjacency refresh.
- **Determinism** – Every policy branch writes a Decision Cell under `/data/flow/decision/{inst}/{site}` capturing choice, links to `policy` and `variant`, a fingerprint, validation/evidence payloads, telemetry metrics, and retention directives. Replay validates fingerprints and context signatures before reusing a stored decision.
- **Instance lifecycle** – Instances move through `ready → waiting → ready/done/error/paused` states. Wait steps materialise subscriptions in `subs`, latch events from `inst_event` intents, and compute deadlines/timeouts. Clamp steps enforce budgets using the `budget` dictionary (`step_limit`, `steps_used`, `deadline`).
- **Observability** – `fl_index` and `fl_adj` rebuild durable indexes (`inst_by_var`, `inst_by_st`, `dec_by_pol`) and adjacency summaries (`by_inst`). They now publish rolling `lat_window`/`err_window` samples plus decision telemetry (`score`, `confidence`, `rng_seed`, `rng_seq`, `latency`, `error_flag`).
- **Retention** – Policies can declare `retain_mode` (`permanent`, `ttl`, `archive`) and `retain_ttl`. `fl_index` pre-pass prunes or archives expired decisions into `/data/flow/dec_archive`, keeping ledgers compact without breaking replay.

## Q&A
- **Do I need Layer 1 before Layer 2?**
  Yes. L1 owns beings, bonds, contexts, and closure—flows rely on those ledgers for routing and provenance.
- **Can flows run arbitrary code?**
  Each step translates into enzyme-friendly operations: Guards inspect cells, Transforms emit staged cells, Waits subscribe to signals, Decide calls policies, Clamp manages budgets. Native code hooks live inside policies or helper libraries registered at L0.
- **How do I add telemetry?**
  Populate `policy/<id>/telemetry` or the per-step `spec/telemetry` fields; the engine merges them with deterministic defaults and stores the result under each Decision Cell.
- **What about parallel execution?**
  Heartbeats keep beats single-threaded per store. Future work explores multi-agency execution, but the semantics today guarantee serial determinism.
