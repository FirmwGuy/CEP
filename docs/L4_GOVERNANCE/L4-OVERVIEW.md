# Layer 4 Governance – Rat POC Policies

Layer 4 records simple province policies and compliance signals for the rat POCs. It does not yet enforce anything; it just captures where the system exceeds risk caps or under-delivers exploration so operators can add rules later.

## Technical Details

- Root: `/data/gov/**`
  - `rat_provinces/<province>`: policy knobs (`risk_cap`, `imaginate_min`) seeded for `lab_train`, `lab_coop`, and `lab_compet`.
  - `state/<province>`: compliance snapshot with `risk_cap_hit`, `imaginate_low`, and a `compliance` sub-dictionary echoing the configured caps plus observed `imaginate_rate`.
- Producer: `cep_l4_governance_run(eco_root, data_root)` (see `src/l4_governance/cep_l4_runtime.c`) seeds defaults and records compliance each scheduler pump.
- Inputs: current Signal Field (`risk`) and aggregate imaginate rate derived from playbook stats across all learners/focus keys.
- Behavior: policies are evidence-only; no clamps or reforms are applied yet. Values are deterministic per beat.

## Q&A

**Q: What happens when a cap is hit?**  
Only the compliance flags flip to `1`. Enforcement or CEI can be added later on top of these signals.

**Q: How do I change policies?**  
Edit the `rat_provinces/<province>` cells (risk_cap/imaginate_min). The runtime will mirror the new values into `state/<province>/compliance` on the next pump.

**Q: Why keep L4 minimal?**  
To keep the POCs inspectable without full governance machinery. This is a scaffold for future laws (EXP/SOC/LEX) rather than a hard gate.*** End Patch
