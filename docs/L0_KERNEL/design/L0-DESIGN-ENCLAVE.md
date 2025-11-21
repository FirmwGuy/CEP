# L0 Design: Enclave Enforcement

## Introduction
Layer 0 now ships a deterministic Enclave gatekeeper so every cross‑enclave call, pipeline hop, and crown‑jewel branch read/write respects the same capture→compute→commit beat contract. Rather than sprinkling ACLs around the tree, we centralise policy inside `/sys/security/**`, replay it into a compact resolver (`cep_enclave_policy`), and wire the resolver into federation validators, branch guards, and the pipeline preflight enzyme. This note records the architecture so future edits can re-check the moving parts—policy snapshots, freeze guards, diagnostics, and tests—before touching code.

## Architecture Overview
- **Enclaves & trust tiers.** Each runtime (or isolated subtree) registers an enclave ID plus a trust tier. Higher tiers (T0–T1) run trusted enzymes, while T2+ enclaves sandbox partner or user code. The policy tree enumerates enclaves, trust tiers, and per-enclave overlays.
- **Gateways & edges.** Cross‑enclave work only enters a destination enclave through declared gateways. Edges (`from` → `to`) map allowed gateway IDs, verbs, and per-hop budgets (CPU, IO bytes, beats, rate).
- **Pipelines.** Pipelines stitch multiple stages across enclaves. Specs live under `/data/<pack>/policy/security/pipelines/*`. The `sig_sec/pipeline_preflight` enzyme validates the shape, stamps approvals, and binds resolved ceilings to pipeline IDs.
- **Internal branch rules.** Trusted enclaves may flag specific branches (e.g., `/data/payments/**`) for diet ACLs. The branch guard´s default fast path stays open, but `cep_cell_svo_context_guard()` consults Enclave rules when it detects a security branch.

## Policy Loader & Snapshots
- `cep_enclave_policy` captures `/sys/security/{enclaves,edges,gateways,branches,defaults,env/**}` during Beat A. It maintains watchers so later edits land in a pending state until the next capture window.
- Loads are atomic: the snapshot is parsed into in-memory structures, hashed, and swapped in when everything succeeds. Failures emit `state=error` in `/sys/state/security`.
- Reloads are tracked via `pol_ver` (hash of the snapshot). The `cep_enclave_policy_freeze_enter/leave` helpers let validators hold the version steady during retries (e.g., the fed invoke test harness).
- The loader records readiness under `/sys/state/security` with `state`, `note`, `fault`, `pol_ver`, and `beat`. Bootstrap and organ validators watch this path for deterministic liveness.

## Enforcement Points
1. **Federation transport manager (`cep_fed_transport_manager_send*`).**
   - Each mount carries resolved `security_limits` (budgets, TTL, per-edge QPS).
   - When limits trip, the manager emits `sec.limit.hit` CEI facts and increments `/rt/analytics/security/edges|gateways`.
2. **Federation validators (link/mirror/invoke).**
   - `cep_fed_invoke_validator()` resolves the source→dest edge, checks the recorded pipeline approval, and fails closed when the edge denies access or the approval is stale.
   - `cep_fed_transport_manager_emit_diag()` always uses CEP-domain severities so diag mailboxes record stable severities across builds.
3. **Pipeline preflight enzyme (`sig_sec/pipeline_preflight`).**
   - Parses DAG specs under `/data/<pack>/policy/security/pipelines/*`, re-validates edges and ceilings, and writes deterministic approvals (state, note, `pol_ver`, `beat`).
4. **Branch guard (`cep_cell_svo_context_guard()`).**
   - When the guarded branch lives under `/sys/security`, the helper formats the resolved path and runs it through `cep_enclave_policy_check_branch()`.
   - Denies emit `sec.branch.deny`, append ledger entries to `/journal/decisions/sec`, and, when CEP_ENABLE_DEBUG is set, print `[svo_guard]` breadcrumbs so CEP_DEBUG_LOG captures the exact branch note.

## Beat Integration
- **Capture (Beat A).** Policy snapshots load, watchers latch, `/sys/state/security` switches to `state=loading` then `state=ready` (or `state=error` with `fault` text).
- **Compute (Beat B).** Federation validators consult the snapshot, apply per-hop budgets, and record ledger entries before mutating runtime state. Branch guards run inline with cell ops.
- **Commit (Beat C).** `/rt/analytics/security` accumulates per-edge/per-gateway allow/deny counters and beat digests; CEI diagnostics are sealed; ledger cells in `/journal/decisions/sec` get appended for replay.

## Telemetry & Diagnostics
- `/sys/state/security` — live readiness/fault metadata for bootstrap, OVH (`/CEP/organ/sys_state`), and integration harnesses.
- `/rt/analytics/security/edges|gateways` — hashed allow/deny counters plus labels. `/rt/analytics/security/beats/<bt>` stores digests (allow, deny, limit hits) per beat.
- CEI topics — `sec.edge.deny`, `sec.branch.deny`, `sec.limit.hit`, `sec.pipeline.reject`. Diagnostics land in the default mailbox unless callers pass a custom root.
- Debug hooks — `CEP_ENABLE_DEBUG` enables `[svo_guard]` prints and the branch diag dumper (set `TEST_BRANCH_DEBUG=1` during tests to dump the diag mailbox when assertions fail).

## Tests & Tooling
- **Unit suites:** `/CEP/fed_security/analytics_limit`, `/CEP/fed_security/pipeline_enforcement`, `/CEP/fed_invoke/decision_ledger`, and `/CEP/branch/security_guard` prove the resolver, ledger, telemetry, and branch CEI paths.
- **Full sweeps:** run both the default and ASAN configurations so gateway/branch diagnostics remain consistent under sanitizers.
- **Valgrind batches:** execute the federation suites in groups of ≤3 selectors and archive logs under `build/logs/valgrind_*.log`; integration POC fixtures run separately because they hold locks longer.
- **Lexicon tool:** `tools/check_unused_tags.py` keeps `docs/CEP-TAG-LEXICON.md` aligned with the `sec.*` tags. See `docs/BUILD.md` (“Enclave Validation Workflow”) for the exact commands.

## Q&A
**What happens if the policy snapshot fails to parse?**  
`cep_enclave_policy` leaves the previous snapshot intact, publishes `state=error fault=<reason>` in `/sys/state/security`, and emits CEI diagnostics. Validators treat it as a fatal condition and block cross-enclave work until the fault clears.

**How do tests keep policy versions stable during retries?**  
The fed invoke fixtures call `cep_enclave_policy_freeze_enter()` before mutating approval cells, run the validator, and then call `_leave()` so watcher-driven reloads resume. The freeze guard also relaxes version matching (older `pol_ver` is accepted while frozen) to avoid unnecessary denials mid-test.

**Where do budgets reset?**  
Budgets decrement in `cep_fed_transport_manager_send*()` and refresh each beat during the manager’s commit hook. Telemetry shows both the current counter and the beat that wrote it, so replays can confirm the reset cadence.

**How do I extend the policy schema?**  
Add the new tags to `docs/CEP-TAG-LEXICON.md`, update the loader parser, and document the field in `docs/L0_KERNEL/topics/ENCLAVE-OPERATIONS.md`. Every addition should include CEI/telemetry evidence so operators can observe it without cracking binaries.

**What’s the recommended operator workflow?**  
Edit `/sys/security/**`, wait for `/sys/state/security state=ready pol_ver=<hash>`, rerun `sig_sec/pipeline_preflight`, and recheck `/rt/analytics/security` counters. When staging new features, set `CEP_ENABLE_DEBUG=1` to capture `[svo_guard]` breadcrumbs.
