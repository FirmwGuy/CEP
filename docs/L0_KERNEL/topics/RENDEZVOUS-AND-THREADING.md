# Rendezvous, Pipelines, and Threads

## Introduction
Rendezvous turn CEP’s tidy heartbeat rhythm into a safe meeting point for long-running or parallel work. Flows can hand jobs to background threads or external workers, resume deterministically once results arrive, and keep every choice explainable.

## Technical Details
- **Ledger schema**: Entries live under `/data/rv/{key}` and must expose the full contract: `prof`, `spawn_beat`, `due`, `epoch_k`, `input_fp`, `cas_hash`, `state` (`pending|ready|applied|late|timeout|killed|quarantine`), `on_miss`, `grace_delta`, `max_grace`, `deadline`, `kill_mode`, `kill_wait`, and `telemetry/*`. Default spawns now seed every field so replay tooling sees deterministic values (`epoch_k`, `input_fp`, `deadline`, `grace_delta`, `max_grace`, `kill_wait`, and `grace_used` default to `0`; `on_miss` defaults to `timeout`; `kill_mode` defaults to `none`; `cas_hash` defaults to an empty string; `telemetry` becomes an empty dictionary).
- **Helper APIs**: `cep_rv_prepare_spec()` merges defaults into a `cepRvSpec`, `cep_rv_spawn()` creates the ledger entry (TODO to double-check default state), `cep_rv_resched()` shifts `due`, `cep_rv_kill()` enforces kill policies, `cep_rv_report()` updates telemetry, and `cep_rv_capture_scan()`/`cep_rv_commit_apply()` bridge the heartbeat with the rendezvous queue. `cep_rv_signal_for_key()` generates the flow signal path `CEP:sig_rv/<key>`.
- **Pipeline integration**: Flow transform steps spawn rendezvous jobs; Wait steps subscribe to the rendezvous signal path. The rv→flow bridge enzyme emits `/data/inbox/flow/inst_event/*` when `state` becomes `applied`, `timeout`, or `killed`, so the instance resumes on the next beat with the recorded telemetry.
- **Threading profiles**: `rv-fixed` schedules a single due beat, `rv-epoch` repeats every *k* beats, `rv-cas` ingests `/cas` payloads, `observer` captures read-only telemetry, and `spec` explores speculative variants. Every profile stores its choice in the ledger so replays remain deterministic.
- **Mailroom updates**: `cep_mailroom_bootstrap()` now mirrors the namespaces described in `/sys/err_cat/**` instead of writing error codes itself. Flow and coherence bootstraps simply rely on the mailroom being ready.

## Q&A
- **How do I spawn a rendezvous?** Build a `cepRvSpec` (or call `cep_rv_prepare_spec()` with your transform dictionary) and then `cep_rv_spawn(spec, key)`. The helper adds `/data/rv/{key}` with the pending metadata and telemetry.
- **How do late jobs get supervised?** `cep_rv_capture_scan()`/`cep_rv_commit_apply()` evaluate `grace_delta`, `max_grace`, and `kill_mode`. States move through `pending → ready → applied` for on-time arrivals; otherwise they escalate to `late`, `timeout`, `killed`, or land in `quarantine`.
- **How do flows wake back up?** When `cep_rv_commit_apply()` marks `state=applied|timeout|killed`, the bridge enzyme writes an instance event under `/data/inbox/flow/inst_event`. Wait steps subscribed to `CEP:sig_rv/<key>` consume it next beat.
- **Do rendezvous expose telemetry?** Yes—include telemetry nodes in `cepRvSpec.telemetry` or call `cep_rv_report()` mid-flight. Telemetry fields duplicate into flow events so downstream transforms can inspect them.
- **What happens during restarts?** Rendezvous entries are ordinary cells. The rendezvous enzymes replay them deterministically as long as states and timestamps remain consistent. The TODO markers flag areas where we still need to audit state coverage.
