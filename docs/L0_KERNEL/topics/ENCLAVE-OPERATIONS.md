# L0 Topic: Enclave Policy Operations

## Introduction
This field guide explains how to edit the Enclave policy tree, validate pipelines, and read the evidence surfaces (`/sys/state/security`, `/rt/analytics/security`, `sec.*` CEI topics). Use it whenever you touch the security tree or chase enclave regressions, so each beat stays replayable and tests stay deterministic.

## Policy Tree Layout
```
/sys/security/
  enclaves/            # trust tiers + enclave IDs
  edges/               # cross-enclave policies (from -> to)
  gateways/            # exported gateway enzymes per enclave
  branches/            # optional crown-jewel branch rules
  defaults/            # global budgets/TTL/rates
  env/<name>/          # environment overlays (prod, staging, dev, test)
/data/<pack>/policy/security/pipelines/<id>/
  spec/                # pipeline stages (enclave + enzyme IDs)
  approval/            # stamped by sig_sec/pipeline_preflight
```

### Merge Order
1. `defaults/`
2. global `/sys/security/*.yaml`
3. environment overlays (`env/<name>/`)
4. per-enclave overrides
5. per-pack policy cells

Conflicts resolve to *deny > allow* and *most specific wins*. Budgets, TTLs, and rates resolve to the most restrictive limits.

## Operator Workflow
1. **Edit policy.** Update `/sys/security/**` (edges, gateways, branches, defaults, env overlays). Watch `cep_enclave_policy_mark_dirty()` traces (enable `CEP_ENABLE_DEBUG=1`) if you need stack traces for dirty pulses.
2. **Wait for readiness.** `/sys/state/security` transitions to `state=loading` while the snapshot parses, then `state=ready pol_ver=<hash>` when successful. If parsing fails, the cell records `state=error fault=<reason>`.
3. **Freeze when necessary.** Tests and tooling can call `cep_enclave_policy_freeze_enter()` before mutating approvals to keep `pol_ver` stable; remember to call `_leave()` even on failures.
4. **Re-run pipeline preflight.** Execute `sig_sec/pipeline_preflight` (via tests or CLI). Approvals store `state`, `note`, `pol_ver`, and the beat that wrote them.
5. **Verify runtime evidence.**
   - `/rt/analytics/security/edges/<hash>` and `/rt/analytics/security/gateways/<hash>` show allow/deny counters plus the hashed labels.
   - `/rt/analytics/security/beats/<beat>` stores per-beat digests (`allow`, `deny`, `limit_hit`).
   - Diagnostics appear under the default mailbox; set `TEST_BRANCH_DEBUG=1` during tests to dump the latest entries when assertions fail.
6. **Exercise the suites.** Follow the Enclave validation workflow in `docs/BUILD.md` to rerun the targeted unit suites, full default/ASAN sweeps, lexicon checks, and Valgrind batches; this keeps `/sys/state/security`, `/rt/analytics/security`, and the CEI topics aligned with the latest snapshot.

## Diagnostics Cheatsheet
- **CEI topics.** `sec.edge.deny`, `sec.branch.deny`, `sec.limit.hit`, `sec.pipeline.reject`. Subscribers can filter by severity or topic. Diag mailboxes store `topic`, `note`, `origin`, and beat metadata.
- **Ledger entries.** `/journal/decisions/sec` records structured entries for denies (subjects, verbs, matched rule, snapshot hash).
- **Branch guard breadcrumbs.** With `CEP_ENABLE_DEBUG=1`, `cep_cell_svo_context_guard()` prints `[svo_guard]` entries that include the formatted branch path, verb, subject, and resolved topic.
- **Policy trace logs.** Set `CEP_ENABLE_DEBUG=1` and run `/CEP/fed_invoke/success` to generate `build/logs/fed_invoke_policy_trace.log`, which lists every dirty source (store/data) plus stack traces.

## Q&A
**How do I know which policy edit triggered a reload?**  
Set `CEP_ENABLE_DEBUG=1`. The loader logs each dirty source (store/data) with the owning cell path into `build/logs/fed_invoke_policy_trace.log`.

**What if a test hits `approval out of date`?**  
Wrap the test in a policy freeze (`cep_enclave_policy_freeze_enter/leave`) and rerun `sig_sec/pipeline_preflight`. The helper accepts approvals whose recorded `pol_ver` lags during the freeze window.

**How do I clear noisy diagnostics between runs?**  
Use `test_branch_clear_diag_mailbox()` (see `test_branch_controller.c`) or manually delete children under `/data/mailbox/diag/msgs`. The helper already runs at the start of `/CEP/branch/security_guard`.

**Where do new tags go?**  
Add them to `docs/CEP-TAG-LEXICON.md` and rerun `python3 tools/check_unused_tags.py`. Federation/security tags are grouped near the existing `sec.*` entries.
