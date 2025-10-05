# L2 Flow: Roadmap

Layer 2 is live but still growing muscles. The core VM runs, decisions are
recorded, and telemetry is flowing—we just need to tighten a few screws before
handing it to larger workloads.

---

## Technical Details
- **Status snapshot**
  - Flow ingestion, instance lifecycle, decision ledger, and retention: ✅
  - Telemetry (score/confidence/RNG, latency/error windows): ✅
  - Intent builders for definitions, niches, and instance start/event/control
    requests (`cep_l2_*_intent_*` helpers): ✅
  - Transform emission publication, guardian enforcement tooling, policy
    analytics dashboards: 🚧
- **Near term (Weeks)**
  - Promote `L2.md` from roadmap to reference, reflecting the current
    implementation.
  - Wire perspectives/consumers that ingest the new telemetry feeds.
  - Stress-test retention/archival performance with large decision ledgers and
    document the resulting operational metrics.
- **Mid term (Quarter)**
  - Surface guardian breach reporting and richer clamp/budget analytics.
  - Add transform publishers that can materialise staged `emits` into downstream
    stores (likely under Layer 3 perspectives).
  - Explore multi-agency execution slots while retaining beat determinism.
- **Long term**
  - Integrate policy experimentation loops (bandits, Bayesian updates) that feed
    new telemetry back into retention and governance layers.
  - Mirror adjacency summaries across shards for federated flow routing.

## Q&A
- **Why is transform publishing deferred?**
  We want perspectives (Layer 3) to own materialised views. Today L2 only stages
  data so the kernel remains deterministic and replay-friendly.
- **Will retention archiving impact replay?**
  No. Archive cells live under `/data/flow/dec_archive` and keep the full
  decision payload, so replays can pull from there when the live ledger prunes
  entries.
- **What happens if policies evolve faster than telemetry consumers?**
  Keep older telemetry fields; the engine always writes deterministic defaults.
  Consumers can key off `retain_mode` and fingerprint hashes to detect schema
  changes.
- **How will multi-agency execution be tested?**
  The roadmap calls for synthetic load harnesses that replay mixes of
  `inst_event` and `inst_ctrl` intents while verifying the exact same decision
  ledger is produced. Until that exists, single-threaded beats stay the safe
  default.
