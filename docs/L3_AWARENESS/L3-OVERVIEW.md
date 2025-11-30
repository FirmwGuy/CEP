# Layer 3 Awareness – Rat POC Aggregates

Layer 3 is about “what happened and how do we see it?” For the rat POCs, L3 stays tiny: it snapshots per-rat risk/reward traces, skill performance, and social signals into data that dashboards could read without changing the kernel or skills.

## Technical Details

- Roots: `/data/awareness/**`
  - `maze_risk_reward/<rat>`: shocks, food, steps, blocked, hunger, fatigue, plus a copy of the current Signal Field for that beat.
  - `skill_performance/<learner>/<focus_key>`: attempts, successes, imaginate hits, imaginate rate, and average cost rolled up over the focus key.
  - `social_comm/<rat>`: social trust, teach, and noise metrics mirrored from the social grounder.
- Producer: `cep_l3_awareness_run(eco_root, data_root)` (see `src/l3_awareness/cep_l3_runtime.c`) runs once per scheduler pump, reading L2 metrics/playbooks and writing deterministic aggregates.
- Data shape: all entries are dictionaries with numeric fields stored as `val/uint64` except for rates/costs kept as short text floats. Aggregates are append-only; re-running the beat overwrites within the same deterministic run.
- Dependencies: requires L2 metrics (`/data/eco/runtime/metrics/**`), signal_field/current, and playbooks. No extra organs or ops yet.

## Q&A

**Q: Does this enforce any policy?**  
No. It only records evidence for dashboards. Governance signals live separately under `/data/gov/**`.

**Q: How often are aggregates updated?**  
Once per scheduler pump (per beat) so the view stays in sync with the latest grounder metrics and playbook stats.

**Q: Can I extend these views?**  
Yes. Append more fields under the same subtrees or add new awareness branches; keep writes deterministic and append-only per beat.
