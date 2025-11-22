# L0 Design: Enclave Enforcement

## Introduction
Enclaves are CEP’s “trust bubbles.” Each runtime—or even a fenced-off subtree—declares which bubble it lives in and what other bubbles it is willing to talk to. The Enclave design turns that idea into a single, replayable gatekeeper so cross-enclave calls, pipeline hops, and reads of crown-jewel branches all follow the same capture → compute → commit rhythm. Instead of scattered ACLs, policy sits under `/sys/security/**`, is replayed into a compact resolver (`cep_enclave_policy`), and every enforcement point listens to that resolver. This note explains the design in plain language so newcomers can see what an enclave is, how enforcement fits together, and where to look when something misbehaves.

## What an Enclave Is (and Is Not)
- An **enclave** is a named trust zone (often a runtime) plus a **trust tier**. Tier 0/1 enclaves run trusted CEP code; Tier 2+ enclaves sandbox partner or user modules.
- **Gateways** are the only doors into an enclave. Each gateway is a specific enzyme that other enclaves may call.
- **Edges** describe which enclaves may talk to which, through which gateways, and with what budgets (CPU, IO bytes, beats, rate).
- **Pipelines** can span multiple enclaves. A pipeline spec lists the stages (gateway + enclave) and optional ceilings the pack is requesting.
- **Crown-jewel branches** (for example `/data/payments/**`) can require explicit allow rules even inside the trusted enclave; everything else defaults to open unless policy says otherwise.

Think of the policy as a map: enclaves, the doors between them, the allowed trips, and the speed limits for each trip.

## Policy Map at a Glance
```
/sys/security/
  enclaves/    # who exists + trust tier
  edges/       # allowed from → to edges with budgets
  gateways/    # per-enclave gateway enzymes
  branches/    # optional branch allow-list for crown jewels
  defaults/    # fallback budgets/TTLs/rates
  env/*/       # overlays per environment (prod, staging, dev, …)
/data/<pack>/policy/security/pipelines/<id>/  # pack-owned pipeline specs
```
Merge order: defaults → global → env overlay → per-enclave overrides → pack policy. “Deny” and “tightest budget wins” when rules overlap.

## How a Cross-Enclave Call Flows
1. **Policy is loaded.** The loader snapshots `/sys/security/**`, hashes it (`pol_ver`), and publishes readiness under `/sys/state/security`.
2. **A caller sends work.** Federation validators resolve the source→dest edge, check the gateway is allowed, and ensure the call belongs to an approved pipeline stage if `pipeline_id`/`stage_id` are present.
3. **Budgets apply.** Per-edge ceilings (beats, CPU, IO bytes, rates) decrement for this hop. If a ceiling trips, the call is denied and a CEI fact (`sec.limit.hit`) is emitted.
4. **The destination runs the gateway enzyme.** Branch guards still protect sensitive `/sys/security` subtrees inside the enclave.
5. **Telemetry and ledger updates.** `/rt/analytics/security/**` counts allow/deny/limit hits; CEI facts record the why; ledger cells land in `/journal/decisions/sec` for replay.

## Policy Loader & Snapshots
- `cep_enclave_policy` captures `/sys/security/{enclaves,edges,gateways,branches,defaults,env/**}` during Capture, parses it in-memory, hashes it, and swaps it in atomically. Failed parses keep the old snapshot and publish `state=error fault=<reason>` in `/sys/state/security`.
- The loader writes readiness under `/sys/state/security` (`state`, `note`, `fault`, `pol_ver`, `beat`). Organ validators and bootstrap code watch this path instead of polling the tree.
- `cep_enclave_policy_freeze_enter/leave` pins the current `pol_ver` for test retries or multi-step approval edits. While frozen, approvals using the frozen hash remain valid.

## Enforcement Points
- **Federation transport manager (`cep_fed_transport_manager_send*`).** Each mount carries resolved `security_limits` (budgets, TTLs, per-edge QPS). On a trip, counters decrement; limit hits emit `sec.limit.hit` CEI facts and bump `/rt/analytics/security/edges|gateways`.
- **Gateway validators (link/mirror/invoke).** `cep_fed_invoke_validator()` resolves the source→dest edge, verifies the gateway, and refuses the call if the edge is denied or the pipeline approval is missing/stale. Diagnostics use CEP-domain severities via `cep_fed_transport_manager_emit_diag()`.
- **Pipeline preflight (`sig_sec/pipeline_preflight`).** Validates `/data/<pack>/policy/security/pipelines/*` DAGs, re-checks edges/ceilings, and stamps `approval/{state,note,pol_ver,beat}`. Cross-enclave calls carrying pipeline metadata are rejected when no approval exists (`sec.pipeline.reject`).
- **Branch guard (`cep_cell_svo_context_guard()`).** When touching `/sys/security/**` (or other security-flagged branches), the guard consults enclave policy. Denials emit `sec.branch.deny`, append to `/journal/decisions/sec`, and—with `CEP_ENABLE_DEBUG=1`—print `[svo_guard]` breadcrumbs (plus `TEST_BRANCH_DEBUG=1` mailbox dumps during tests).
- **Edge denies.** Policy mismatches on the edge itself emit `sec.edge.deny` before any work runs, keeping replays aligned with enforcement decisions.

## Beat Rhythm
- **Capture (Beat A):** Snapshot loads; `/sys/state/security` flips to `state=loading` then `state=ready` (or `state=error` with `fault`).
- **Compute (Beat B):** Validators apply budgets and approvals before mutations; branch guards run inline with cell operations.
- **Commit (Beat C):** `/rt/analytics/security` tallies allow/deny/limit-hit counts, CEI facts are sealed, and `/journal/decisions/sec` receives ledger entries for replay.

## Diagnostics & Telemetry
- `/sys/state/security` — live readiness + snapshot hash for bootstrap, OVH, and integration harnesses.
- `/rt/analytics/security/edges|gateways` — hashed allow/deny counters plus labels; `/rt/analytics/security/beats/<bt>` stores per-beat digests (`allow`, `deny`, `limit_hit`).
- **CEI topics:** `sec.edge.deny`, `sec.branch.deny`, `sec.limit.hit`, `sec.pipeline.reject`. Diagnostics land in the default mailbox unless callers provide another root.
- **Debug hooks:** `CEP_ENABLE_DEBUG=1` enables `[svo_guard]` breadcrumbs; `TEST_BRANCH_DEBUG=1` dumps the diagnostics mailbox when `/CEP/branch/security_guard` fails so you see the exact topic/note.

## Tests & Tooling
- **Unit suites:** `/CEP/fed_security/analytics_limit`, `/CEP/fed_security/pipeline_enforcement`, `/CEP/fed_invoke/decision_ledger`, `/CEP/branch/security_guard`.
- **Sweeps:** Run default + ASAN so gateway/branch diagnostics stay consistent under sanitizers; run Valgrind in ≤3-test batches and archive logs under `build/logs/valgrind_*.log`.
- **Lexicon:** `tools/check_unused_tags.py` keeps `docs/CEP-TAG-LEXICON.md` aligned with `sec.*` tags. See `docs/BUILD.md` (“Enclave Validation Workflow”) for the exact command list.

## Q&A
**What happens if the snapshot fails to parse?**  
The previous snapshot stays active; `/sys/state/security` records `state=error fault=<reason>`, and CEI facts explain the failure. Cross-enclave work remains blocked until the fault clears and readiness returns to `state=ready`.

**How do tests keep policy versions stable during retries?**  
Wrap the mutation with `cep_enclave_policy_freeze_enter()`/`_leave()`. While frozen, approvals stamped with the frozen `pol_ver` are accepted so replays do not trip on a moving hash.

**Where do budgets reset?**  
In `cep_fed_transport_manager_send*()` budgets decrement for the hop, then refresh each beat during the manager’s commit hook. Telemetry records both the counters and the beat that wrote them so replays match.

**How do I extend the policy schema safely?**  
Add new tags to `docs/CEP-TAG-LEXICON.md`, update the loader parser, and describe the field in `docs/L0_KERNEL/topics/ENCLAVE-OPERATIONS.md`. Ship CEI/telemetry evidence alongside the new field so operators can see it without code spelunking.

**What is the operator happy path?**  
Edit `/sys/security/**`, wait for `/sys/state/security state=ready pol_ver=<hash>`, rerun `sig_sec/pipeline_preflight` if pipelines changed, then watch `/rt/analytics/security` (and CEI topics) to verify edges, gateways, and budgets are behaving as expected. When staging risky edits, keep `CEP_ENABLE_DEBUG=1` on to capture breadcrumbs.
