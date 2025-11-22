# L0 Topic: Federation Transport Manager

Federation moves CEP data and requests between peers. The transport manager is the traffic controller: it discovers providers, negotiates capabilities, seeds the `/net` schema, and enforces safety knobs like `upd_latest`. All federation traffic rides the flat serializer so frames stay beat-atomic and replayable.

## What the manager does
- Keeps a **catalog** of providers (sockets, pipes, mocks, etc.) under `/net/transports/**`.
- Builds **mounts** under `/net/mounts/<peer>/<mode>/<mount>/` with required/preferred caps, the chosen provider, and serializer policy.
- Registers **organs** for discovery and health so schemas and telemetry stay consistent.
- Handles **capability negotiation** and **downgrades** (CRC32C/deflate/AEAD/comparator ceilings).
- Implements **`upd_latest`** semantics for unreliable transports (drop older gauges, warn on reliable paths).

## Key flows
- **Provider registry.** `cep_fed_transport_register()` advertises caps; the manager mirrors them under `/net/transports/<id>/`.
- **Mount configure.** `cep_fed_transport_manager_configure_mount()`:
  - Ensures schema exists,
  - Applies required/preferred caps and `upd_latest` opt-in,
  - Selects a provider (lexicographic tie-break) and records it under `transport/`,
  - Opens the channel immediately.
- **Discovery & health organs.** `org:net_discovery:vl` validates peer service records; `org:net_health:vl` validates telemetry branches and prunes empty peers when mounts disappear.
- **Capability negotiation.** Required bits must be present; preferred bits are scored. If `upd_latest` is set, only providers advertising `CEP_FED_TRANSPORT_CAP_UNRELIABLE` are eligible. Serializer policy may request CRC32C/deflate/AEAD/comparator ceilings; missing caps trigger a `tp_flatneg` warning on first downgrade (suppressible via `serializer/warn_down=false`).
- **Telemetry.** `/net/telemetry/<peer>/<mount>/` tracks `ready_count`, `bp_count`, `fatal_count`, `frame_count`, `last_mode`, `last_sample`, `last_event`, and `bp_flag`. Types are enforced so tools can parse without guessing.
- **Channel lifecycle.** Close leaves schema intact so a mount can reconfigure without reseeding; reopen reuses catalogued providers.
- **`upd_latest`.** Unreliable transports cache a single droppable payload; backpressure replaces it, ready events flush it, and reliable transports emit CEI warnings if asked to drop.

## Quick recipes
- **Create a mount with a preferred provider:** set `caps/required` and `caps/preferred`; configure mount; the manager writes `transport/provider` and `prov_caps`.
- **Constrain serializer features:** add `serializer/{crc32c_ok,deflate_ok,aead_ok,cmp_max_ver,warn_down}` to a link/mirror/invoke request. The manager negotiates and mirrors results under the mount’s `serializer/`.
- **Use `upd_latest` for gauges:** set `caps/upd_latest=true` on unreliable transports to drop stale gauges instead of queuing them.
- **Inspect health:** check `/net/telemetry/<peer>/<mount>/` counters; `bp_flag=true` means backpressure.

## Q&A
- **What happens if no provider meets requirements?** The manager refuses the mount and emits CEI (`tp_noprov`/`tp_schema`); no channel opens.
- **Why do I see `tp_flatneg`?** A requested serializer feature (CRC32C/deflate/AEAD/comparator cap) isn’t supported by the chosen provider; the manager downgraded and warned.
- **Can I stop stale peer entries?** Discovery/health organs prune empty services/telemetry/CEI branches when mounts disappear; no manual cleanup needed.
- **CEI diagnostics.** Failure to find a provider, schema issues, send failures, backpressure, fatal events, and `upd_latest` misuse raise structured CEI facts with short-form topics (`tp_noprov`, `tp_schema`, `tp_catsync`, `tp_backpr`, `tp_sendfail`, `tp_fatal`, …). Flat negotiations add `tp_flatneg` so operators can see when the sender had to drop CRC32C/deflate/AEAD on a mount; the warning fires once per feature unless `serializer/warn_down=false`. Each peer’s `/net/peers/<peer>/ceh/<topic>/` branch records the last severity/note/beat so tools and tests can assert on the manager’s health signals without trawling logs.
- **Link organ (`/net/organs/link`).** Requests live under `/net/organs/link/requests/<id>/` and are plain dictionaries. Required fields are `peer`, `mount`, `mode`, and `local_node` (all `text`). Optional knobs include `pref_prov`, `allow_upd` (`bool`), `deadline` (`val/u64`), and a `caps/` sub-dictionary with `required/` and `preferred/` boolean flags matching `CEP_FED_TRANSPORT_CAP_*`. The validator writes `state` (`pending`, `active`, `error`, `removed`), clears or fills `error_note`, records the selected `provider`, and keeps those fields in the request cell so tools can watch the mount lifecycle without traversing `/net/mounts/…`. The destructor flips `state` to `removed`, clears `provider/error_note`, and asks the transport manager to close the mount with `reason="link-request-destroy"`.
- **Mirror organ (`/net/organs/mirror`).** Mirror requests also sit under `/net/organs/mirror/requests/<id>/` and extend the link layout with the information the episodic engine needs to stage bundles:
  - `peer` / `mount` / `mode` / `local_node` mirror the link contract and identify the local mirror mount to configure.
  - `src_peer` and `src_chan` (`text`) specify which remote peer and publish-side mount feed bundle data.
  - `bundle/` is a dictionary that captures staging limits:
    - `beat_window` (`val/u32`) – how many beats form a bundle.
    - `max_infl` (`val/u16`) – how many bundles may be outstanding before backpressure is asserted.
    - `resume_tok` (`text`, optional) – opaque token the episodic engine can hand back to resume an interrupted mirror.
    - `commit_mode` (`text`, optional) – `stream`, `batch`, or `manual` depending on whether commits happen every bundle, after a swarm of bundles, or under explicit operator control.
  - `caps/` and `pref_prov` follow the link schema so mirrors can favour providers (for example, low-latency LAN transports).
  - `serializer/` is an optional dictionary that constrains flat-frame features before emission:
    - `crc32c_ok`, `deflate_ok`, and `aead_ok` (`val/bool`, each defaulting to `true`) tell the transport manager whether it may enable CRC32C checksums, deflate frame compression, or AEAD payload encryption for this mount. When any flag is `false`, the manager forces the corresponding serializer knob off before calling `cep_fed_transport_manager_send_cell()`.
    - `warn_down` (`val/bool`, default `true`) silences the downgrade CEI (`tp_flatneg`) when operators intentionally disable a feature.
    - `cmp_max_ver` (`val/u32`, default unlimited) publishes the highest comparator version the reader understands. The transport manager exports this value through the `CEP_SERIALIZATION_FLAT_MAX_COMPARATOR_VERSION` override so the serializer can fail fast instead of emitting a frame the reader cannot apply.
  - The validator publishes the usual `state`, `provider`, and `error_note` plus mirror-specific status keys:
    - `bundle_seq` (`val/u64`) – highest bundle sequence the organ has committed.
    - `commit_beat` (`val/u64`) – beat of the most recent successful commit.
    - `pend_resum` (`text`, optional) – non-empty when the organ has paused and holds a new resume token for the caller.
  - On teardown the destructor closes the configured mount, clears the status fields, and deletes any `bundle/` progress nodes so subsequent requests start from a clean slate.
- **Invoke organ (`/net/organs/invoke`).** Invoke requests wire mounts that transport remote enzyme impulses:
  - `peer` / `mount` / `local_node` mirror the link contract; `pref_prov` (optional) and the `caps/` dictionary (`required` / `preferred`) reuse the capability schema so callers can steer transports and capability matching.
  - `deadline` (`val/u64`, optional) records the beat by which the request must become active. Validators flip the request to `state=error` with `error_note="deadline expired before activation"` if the supplied beat is in the past.
  - The validator publishes `state`, `provider`, and `error_note` inside the request. As invocation frames flow the module emits CEI on timeouts (`tp_inv_timeout`) or remote rejections (`tp_inv_reject`).
  - Successful submissions encode the signal and target paths into a transport frame, receive immediate acknowledgement frames, and schedule a timeout enzyme so late or missing responses surface deterministically.
- **Stub providers.** The repository ships three providers: `tcp` (reliable remote stream semantics), `pipe` (reliable local IPC) and `mock` (unreliable in-process test harness). The mock provider keeps queues visible to tests via helpers in `fed_transport_providers.h` so suites can drive backpressure, inbound frames, and verify coalescing without real sockets.

## Q&A
- **How do I add a new provider?** Implement a `cepFedTransportProvider` with the `open/send/request_receive/close` vtable, register it via `cep_fed_transport_register()`, and seed `/net/transports/<id>/` using `cep_fed_transport_schema_seed_provider()` if you want static metadata in tree. The manager takes care of negotiation and mount schema updates.
- **Where do I inspect capability choices at runtime?** Resolve `/net/mounts/<peer>/<mode>/<mount>/transport/`. The `provider` value records the ID, `prov_caps/` mirrors the provider’s capability bits, and `caps/` captures the mount’s required/preferred contract.
- **How do I simulate inbound frames in tests?** Use the mock provider helpers (`cep_fed_transport_mock_enqueue_inbound`, `cep_fed_transport_mock_signal_ready`, `cep_fed_transport_mock_pop_outbound`). They queue payloads, trigger READY events, and expose outbound buffers without reaching into provider internals.
- **What happens when negotiation fails?** The manager emits a `transport/no_provider` CEI fact and leaves the mount unchanged. The mount branch remains available so external tools can display the failure while the caller retries with different caps or providers.
