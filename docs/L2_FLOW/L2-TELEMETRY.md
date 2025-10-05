# Layer 2 Telemetry, Retention, and Summaries

Layer 2 now reports how each flow decision was made, keeps a friendly eye on latency, and retires old choices when policies ask for it. Operators can glance at the new summaries to spot trouble before it compounds.

---

## Technical Details
- Decision entries carry a `telemetry` dictionary populated during `fl_step`. It records the evaluation `score`, reported `confidence`, and RNG provenance (`rng_seed`, `rng_seq`). The values live both under `decision/validation/*` for replay vetoes and under `decision/evidence/*` for downstream analytics.
- Policy retention directives expand to include `retain_mode`, `retain_ttl`, and `retain_upto`. Policies may declare `retain="ttl:360"` (or supply the same structure in their payload). The enforcement pass runs inside `fl_index`, archiving expired decisions under `/data/flow/dec_archive` when `retain_mode=archive`, or deleting them when `retain_mode=ttl`.
- Adjacency refresh (`fl_adj`) now emits a `lat_window` list plus an `err_window` list per instance. Each window holds up to eight recent samples sorted by beat (newest first). Policy summaries in `/data/flow/index/dec_by_pol/*/meta` expose matching windows derived from stored decision telemetry.
- New tags registered in the lexicon: `telemetry`, `score`, `confidence`, `rng_seed`, `rng_seq`, `lat_window`, `err_window`, `retain_mode`, `retain_ttl`, `retain_upto`, and `dec_archive`.
- Enzyme order remains `fl_ing → ni_ing → inst_ing → fl_wake → fl_step → fl_index → fl_adj`. Retention enforcement sits at the head of `fl_index`; telemetry capture executes inside the `fl_step` decision handler.

## Q&A
- **Why duplicate telemetry under `validation` and `evidence`?**
  Validation needs the numbers for replay cross-checks, while evidence keeps them handy for analytics without digging through replay guards.
- **What happens when a policy declares `retain="archive:720"`?**
  The decision lives for 720 beats, then moves into `/data/flow/dec_archive`. Replay still works because the archive preserves the full cell.
- **Do the latency windows include pending events?**
  Yes. Pending entries contribute a latency sample computed against the current heartbeat so you can see queues building before they unblock.
- **Is confidence required in the policy payload?**
  No. The system synthesizes one deterministically from the decision fingerprint when the policy omits it.
- **How large are the windows?**
  Eight samples per window by default. Adjust `CEP_L2_WINDOW_CAP` in `cep_l2_flows.c` if workloads demand a longer tail.
