# L0 Topic: Enclave Policy Operations

## Introduction
Enclaves are CEP’s trust bubbles. This guide walks through how to edit the policy map, approve pipelines, and read the evidence surfaces (`/sys/state/security`, `/rt/analytics/security`, and the `sec.*` CEI topics) without needing to be a security specialist. Use it whenever you change the security tree or diagnose cross-enclave issues so every beat stays replayable.

## Quick Refresher: What Lives Where
```
/sys/security/
  enclaves/    # enclave IDs + trust tiers
  edges/       # allowed from → to edges
  gateways/    # gateway enzymes per enclave
  branches/    # optional crown-jewel allow rules
  defaults/    # fallback budgets/TTLs/rates
  env/<name>/  # overlays (prod, staging, dev, test)
/data/<pack>/policy/security/pipelines/<id>/
  spec/        # stages = gateway + enclave per hop
  approval/    # stamped by sig_sec/pipeline_preflight
```
Merge order: defaults → global → env overlay → per-enclave overrides → pack policy cells. Deny beats allow; tightest budget wins when rules overlap.

## Step-by-Step Operator Workflow
1. **Edit the policy map.** Touch `/sys/security/**` (edges, gateways, branches, defaults, env overlays). If you need a breadcrumb trail of dirty sources, enable `CEP_ENABLE_DEBUG=1`; the loader logs each source with a stack trace.
2. **Watch readiness.** `/sys/state/security` moves to `state=loading` while parsing, then `state=ready pol_ver=<hash>` on success. Parse failures leave the old snapshot active and record `state=error fault=<reason>`.
3. **Freeze when you need stability.** Call `cep_enclave_policy_freeze_enter()` before multi-step edits or test retries to pin `pol_ver`; call `_leave()` even on failure paths.
4. **Re-run pipeline preflight.** Trigger `sig_sec/pipeline_preflight` so every `/data/<pack>/policy/security/pipelines/*` spec gets revalidated. Approvals record `state`, `note`, `pol_ver`, and the beat that wrote them.
5. **Check the evidence surfaces.**
   - `/rt/analytics/security/edges/<hash>` and `/rt/analytics/security/gateways/<hash>` show allow/deny counters plus labels; `/rt/analytics/security/beats/<beat>` shows per-beat digests (`allow`, `deny`, `limit_hit`).
   - CEI topics (`sec.edge.deny`, `sec.branch.deny`, `sec.limit.hit`, `sec.pipeline.reject`) land in the default mailbox unless a caller overrides it. `TEST_BRANCH_DEBUG=1` dumps the mailbox automatically in branch-guard tests.
   - `/journal/decisions/sec` records ledger entries for denials, including the matched rule and snapshot hash, so replays explain every block.
6. **Run the validation flow.** Follow `docs/BUILD.md` (“Enclave Validation Workflow”) for the exact test list: targeted unit suites, default + ASAN sweeps, lexicon check, and Valgrind batches (≤3 selectors per run).

## Reading the Evidence
- **Limit hits vs. denies.** `sec.limit.hit` means budgets were exceeded; `sec.edge.deny` means policy said “no” before budgets; `sec.pipeline.reject` means the pipeline approval was missing or stale; `sec.branch.deny` means a guarded branch lacked an allow rule.
- **Analytics counters.** The per-edge/gateway counters are hashed labels; use them to confirm that traffic is flowing on the expected edges and whether denies are rising.
- **Debug breadcrumbs.** With `CEP_ENABLE_DEBUG=1`, `cep_cell_svo_context_guard()` prints `[svo_guard]` lines with the resolved path, verb, and rule. Running `/CEP/fed_invoke/success` with debug on produces `build/logs/fed_invoke_policy_trace.log`, listing each dirty source that triggered a reload.
- **Cleaning diagnostics.** `test_branch_clear_diag_mailbox()` (see `test_branch_controller.c`) clears `/data/mailbox/diag/msgs`; handy between repeated runs of `/CEP/branch/security_guard`.

## Configuration examples
Use this skeleton to wire two enclaves (`alpha`, `beta`) and a guarded pipeline hop.

- **Policy map:** `/sys/security/enclaves/{alpha, beta}` (tiers optional), `/sys/security/gateways/beta/gw_ingest { }`, `/sys/security/edges/alpha/beta/` with `label="alpha_to_beta"`, `beats=128`, `io_bytes=1048576`, `rate_qps=500`, `ttl_bt=4`, and child `allow_gw/gw_ingest { }`. Add `/sys/security/branches/data/payments { allow=1 }` when a crown-jewel branch needs explicit allow rules. Overlays live under `/sys/security/env/staging/*` when staging budgets differ.
- **Pipeline approval:** `/data/paypack/policy/security/pipelines/pay_ingest/spec/` lists hops (`alpha→beta` via `gw_ingest`). After running `sig_sec/pipeline_preflight`, `/approval/{state=ready, pol_ver=<hash>, beat=<bt>}` proves the hop is allowed.
- **Runtime call:** A federation invoke from alpha to beta includes `pipeline_id=pay_ingest`, `stage_id=gw_ingest`, and consumes the negotiated edge budgets. CEI (`sec.limit.hit`, `sec.edge.deny`, `sec.pipeline.reject`) fires if budgets or approvals are missing.

## Q&A
**How do I spot which edit caused a reload?**  
Enable `CEP_ENABLE_DEBUG=1` and run a validator (for example `/CEP/fed_invoke/success`). The loader writes each dirty store/data source and stack trace into `build/logs/fed_invoke_policy_trace.log`.

**What if I see “approval out of date”?**  
Freeze the policy (`cep_enclave_policy_freeze_enter/leave`), rerun `sig_sec/pipeline_preflight`, and retry. During the freeze window, approvals stamped with the frozen `pol_ver` remain valid.

**How do I clear noisy diagnostics between iterations?**  
Use `test_branch_clear_diag_mailbox()` or delete children under `/data/mailbox/diag/msgs`. The helper already runs at the start of `/CEP/branch/security_guard`.

**Where do new tags belong?**  
Add them to `docs/CEP-TAG-LEXICON.md` and rerun `python3 tools/check_unused_tags.py`. Federation/security tags live next to the existing `sec.*` entries.

**How do I explain enclaves to a teammate in one line?**  
They’re named trust zones with explicit doors (gateways) between them, plus speed limits. Policy under `/sys/security` defines the doors and limits; telemetry and CEI facts show every allow, deny, and budget hit.

**How do I stage a new edge without disturbing production?**  
Add it under `/sys/security/env/staging/edges/...` with tighter budgets; run `sig_sec/pipeline_preflight` while the policy is frozen (`cep_enclave_policy_freeze_enter/leave`), then watch `/rt/analytics/security/beats/*` for staging-only allows/denies before promoting the edge into the global tree.
