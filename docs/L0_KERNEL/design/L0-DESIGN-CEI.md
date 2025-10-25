# L0 Design: Common Error Interface

## Nontechnical Summary
CEI gives the kernel one consistent way to talk about problems. Every module drops a structured Error Fact into a deterministic mailbox, may raise a `sig_cei/*` impulse, and—when the severity warrants it—updates the relevant operation or triggers shutdown. Operators get a single inbox and signal namespace to watch, packs can subscribe without bespoke plumbing, and replay sees the same facts the runtime observed.

## Decision Record
- Error reporting must remain append-only and replayable, so CEI reuses mailboxes (`/data/mailbox/diag`) and heartbeat impulses instead of inventing a logging subsystem.
- Severity is encoded as tags (`sev:*`) to keep matching trivial for enzymes and dashboards; fatal conditions must always funnel through `cep_heartbeat_emit_shutdown()` so teardown follows the documented timeline.
- Emission is a helper (`cep_cei_emit`) rather than free-form code: it standardises timestamps, TTL resolution, operation closure, and signal routing.
- Diagnostics need a kernel-owned sink to avoid circular dependencies, hence the default `/data/mailbox/diag` mailbox seeded during bootstrap.
- OPS integration stays opt-in via `attach_to_op` because not every error belongs to an operation dossier, but when present CEI enforces `sts:fail` semantics for critical severities.

## Subsystem Map
- Code
  - `src/l0_kernel/cep_cei.c`, `cep_cei.h` — diagnostics mailbox bootstrap, request handling, TTL recording, severity policies.
  - `src/l0_kernel/cep_heartbeat.c` — bootstrap hook ensuring the diagnostics mailbox exists.
  - `src/l0_kernel/cep_mailbox.c`, `cep_mailbox.h` — TTL helpers, expiry buckets consumed by CEI.
- Tests
  - `src/test/l0_kernel/test_cei.c` — mailbox emission, signal ledger coverage, OPS attachment, fatal shutdown trigger.
  - `src/test/l0_kernel/test_mailbox.c`, `test_ops.c` — supporting behaviour (ID precedence, OPS state transitions).

## Operational Guidance
- Treat `/data/mailbox/diag` as the default but not the only sink. Packs that want private channels can pass their workspace mailbox while still subscribing to `sig_cei/*`.
- Avoid emitting torrents of `sev:debug` during production; keep debug-level facts behind feature flags or pack-owned mailboxes.
- When attaching to an operation, include a `payload_id` referencing CAS or stream artefacts so operators can inspect full incident reports without browsing the mailbox tree manually.
- Fatal CEI emissions are the canonical way to trigger shutdown. Packs should not call `cep_heartbeat_emit_shutdown()` directly without also recording an Error Fact—otherwise observability loses the why.
- To fan out CEI facts, bind enzymes on `sig_cei/*` globs (`sig_cei/sev:*`) rather than bespoke signal namespaces; matching remains deterministic and mirrors the lexicon.

## Change Playbook
1. Re-read this design doc, `docs/L0_KERNEL/topics/CEI.md`, and `docs/L0_KERNEL/topics/MAILBOX-LIFECYCLE.md`.
2. Extend or adjust `cep_cei_request` semantics in `cep_cei.h` and keep the helper comment block aligned with the new behaviour.
3. Update `cep_cei_emit` (or supporting helpers) ensuring transactions stay atomic—commit after populating both `envelope/` and `err/`, abort on any partial failure.
4. Cover new behaviour in `src/test/l0_kernel/test_cei.c`; add fixtures for signals, OPS updates, or TTL edge cases as needed.
5. Run `meson test -C build --suite /cei` plus `tools/check_docs_structure.py`.
6. Refresh the topic and orientation docs so readers discover the new behaviour, then regenerate HTML docs via `meson compile -C build docs_html`.

## Global Q&A
- **Why not log text files instead?** Mailboxes preserve beat ordering, TTL enforcement, and structured payloads without leaving the append-only world. Logs would break determinism.
- **Can CEI emit multiple signals per fact?** The helper intentionally sends a single `sig_cei/<severity>` impulse to keep agendas tight. Downstream enzymes can fan out if necessary.
- **What about pack-specific severity ladders?** Packs can interpret `topic`, `origin`, or `payload_id` however they like, but the kernel’s severity taxonomy stays five tags so dashboards have a stable baseline.
- **Does CEI replace OPS history?** No. OPS records operation states; CEI enriches those dossiers with the facts that caused failures or shutdowns.
