# L0 Design: Federation

## Introduction
Federation is how separate CEP runtimes share data and work without breaking determinism. Every byte rides the flat serializer; the transport manager chooses how to move those bytes; and three organs—link, mirror, invoke—turn them back into heartbeat work. This note explains the design in plain language, flagging what ships today and what is still forward-looking, so you can edit transports or organs with a clear mental model.

## Big picture
- **Transport-neutral:** Providers (sockets, pipes, mocks) plug into the transport manager. All traffic is flat frames; transports only move them.
- **Schema-first:** `/net/transports`, `/net/mounts`, `/net/telemetry`, and `/net/peers` record mounts, caps, and health so replay/debugging never depends on opaque provider state.
- **Organ trio:** link opens/control channels, mirror moves branch bundles, invoke runs remote enzymes. Discovery/health organs keep schemas clean and telemetry trustworthy.
- **Policy-aware:** Security checks (enclave edges, pipeline approvals, budgets) run on invoke; serializer caps and `upd_latest` are enforced centrally.

## Transport manager
- **Catalog:** Providers register caps (CRC32C, deflate, AEAD, comparator ceiling, unreliable for `upd_latest`); catalog is mirrored under `/net/transports/<id>/`.
- **Mounts:** `/net/mounts/<peer>/<mode>/<mount>/` holds `caps/{required,preferred,upd_latest}`, `transport/{provider,prov_caps,upd_latest}`, and negotiated `serializer/{crc32c_ok,deflate_ok,aead_ok,warn_down,cmp_max_ver}`.
- **Negotiation:** required caps must match; preferred caps break ties (lexicographic fallback). `upd_latest=true` restricts to unreliable providers. Missing serializer caps trigger `tp_flatneg` once unless `warn_down=false`.
- **Lifecycle:** configure → open channel immediately; close leaves schema so reconfigure is cheap. Telemetry is updated beat-by-beat for replay.

## Organs
- **Discovery (`org:net_discovery:vl`):** validates `/net/peers/<peer>/services/<service>/` (mode, mount, local_node, provider, `upd_latest`); prunes empty service branches on destroy.
- **Health (`org:net_health:vl`):** validates `/net/telemetry/<peer>/<mount>/` counters/flags/provider; prunes telemetry/CEI when mounts vanish.
- **Link:** turns request dictionaries into mounts with serializer policy. Records provider/state/error and CEI (`tp_schema`, `tp_flatneg`, `tp_fatal`). Destructor closes mounts.
- **Mirror:** stages beat bundles via the episodic engine. Handles `beat_window`, `max_infl`, resume tokens, episodic deadlines, inflight counters, and publishes telemetry (`bundle_seq`, `commit_beat`) plus CEI on conflicts/timeouts.
- **Invoke:** validates IDs (CEP word limits), requires reliable+ordered caps, schedules heartbeat-managed timeouts, and emits `tp_inv_timeout`/`tp_inv_reject`. Accepts `serializer/` policy like link/mirror and records negotiated policy on the mount.

## Serializer and caps
- Flat serializer is mandatory; caps cover CRC32C, deflate, AEAD, comparator ceilings, and history beats.
- Mount `serializer/` policy can opt out of features or set `cmp_max_ver`; downgrades are logged (`tp_flatneg`) unless `warn_down=false`.
- Future: broader algorithm menus once providers ship them.

## Security and pipeline metadata
- Invoke requests carry `pipeline/{pipeline_id,stage_id,dag_run_id,hop_index}`; `cep_fed_invoke_validator()` enforces enclave edges, approved security pipeline specs, and budgets (beats, CPU, IO bytes, hops, wallclock).
- Denials emit `sec.pipeline.reject`, `sec.edge.deny`, or `sec.limit.hit` with `origin/pipeline` populated. No pipeline metadata → cross-enclave invoke is rejected.

## Configuration examples
Here is a concrete wiring to make two peers talk deterministically without surprises.

- **Peer setup:** `/net/transports/tcp_main` registers `caps/required={crc32c=1}` and `caps/preferred={deflate=1,aead=1}`. Peer `saturn` exposes a single service `invoke/main`.
- **Mount + serializer policy:** `/net/mounts/saturn/invoke/main/` holds:
  - `caps/required={crc32c=1}` and `caps/preferred={deflate=1,aead=1,cmp_max_ver=0}`; `upd_latest=false` so only reliable transports qualify.
  - `serializer/{warn_down=true,cmp_max_ver=0}` to tolerate feature downgrades with CEI breadcrumbs.
  - `transport/{provider=tcp_main,prov_caps={crc32c=1,deflate=1,aead=1},upd_latest=false}` reflecting negotiation.
  - Optional `pipeline/{pipeline_id=demo/ingest,stage_id=StageA}` stamped by `sig_sec/pipeline_preflight` so cross-enclave invokes clear security checks.
- **Invoke request sketch:** `/net/peers/saturn/services/invoke/main/` carries `peer=saturn`, `mount=main`, `mode=invoke`, `local_node=node0`, `deadline_bt=+4`, `payload` (flat frame), and inherits the mount’s negotiated serializer caps. Validation emits CEI (`tp_inv_timeout`, `tp_inv_reject`) if the pipeline approval or caps are missing.

## Telemetry and evidence
- `/net/telemetry/<peer>/<mount>/`: `ready_count`, `bp_count`, `fatal_count`, `frame_count`, `last_mode`, `last_sample`, `last_event`, `bp_flag`.
- `/net/peers/<peer>/ceh/<topic>`: CEI health mirror (e.g., `tp_flatneg`, `tp_backpr`, `tp_fatal`, `tp_inv_timeout`).
- OPS dossiers for mirror/invoke (episodic or otherwise) capture envelopes, watcher states, and close status for replay and audits.

## Failure handling
- Provider loss/backpressure updates telemetry and CEI; link/mirror/invoke mark requests with error notes and close mounts when necessary.
- Timeouts are beat-based; invoke schedules `sig:fed_inv:timeout` and reports via CEI plus request state.
- Duplicate detection is per-runtime: request contexts stash `cepRuntime*` to avoid cross-runtime clashes in tests.

## Roadmap (forward-looking)
- Native async transports (epoll/kqueue) in more builds instead of shim-only paths.
- Richer serializer negotiation profiles beyond the current CRC32C/deflate/AEAD set.
- Better perspectives (pack-owned) to surface mount/provider mismatches automatically.

## Q&A
**How do runtimes agree on a transport?**  
The manager matches `caps/required`; if none satisfy, it emits `tp_noprov` and leaves the request in error. Preferred caps only break ties.

**Why did a mount downgrade features?**  
The provider lacked a requested serializer cap. The manager kept the mount, disabled the feature, and emitted `tp_flatneg` unless `warn_down=false`.

**What evidence do I get when something breaks?**  
Telemetry (`bp_flag`, counters, `last_event`) plus CEI under `/net/peers/<peer>/ceh/*` and the request’s state/error_note. Mirror/invoke OPS dossiers also record status transitions.

**How does this fit the heartbeat?**  
Organs run as normal enzymes: validate during capture, process callbacks during compute, publish telemetry/OPS updates at commit. No bypass of Capture → Compute → Commit.

**How do I reuse one transport for link, mirror, and invoke?**  
Register the provider once (for example `/net/transports/tcp_main`), then create three mounts under `/net/mounts/<peer>/{link,mirror,invoke}/<name>/` that share `transport/provider=tcp_main` but tailor `caps/required` (`invoke` insists on reliable/ordered, `mirror` may allow `upd_latest`). CEI will show individual mount downgrades if a feature is missing.***
