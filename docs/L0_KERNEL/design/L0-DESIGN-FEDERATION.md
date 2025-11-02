# Layer 0 Design: Federation Transport and Organs

## Introduction
Federation lets independent CEP runtimes exchange signals, mirror persistent state, and invoke enzymes across process boundaries without sacrificing the determinism guarantees Layer 0 already enforces. Think of it as a well-lit causeway between runtimes: each side publishes the services it can host, the transport manager negotiates how to move frames, and a trio of organs—link, mirror, and invoke—turn those frames into familiar heartbeat work. This note explains how the design fits together so you can reason about beats, telemetry, and CEI diagnostics before touching the code.

## Technical Details
### Beat Roadmap Overview
- **Beat 0 — Bootstrap & Pack Wiring.** `cep_fed_pack_bootstrap` seeds `/net` with catalog, telemetry, and organ scaffolding, then registers transport providers (tcp, pipe, mock). The transport manager resolves providers without opening channels yet; the heartbeat simply advances through bootstrap as usual.
- **Beat 1 — Manager Initialization.** The shared `cepFedTransportManager` binds to `/net/mounts`, `/net/peers`, and `/net/telemetry`. It exposes helpers for configuring mounts, refreshing telemetry, and recording CEI topics so every subsequent organ call shares the same store-and-diagnostics plumbing.
- **Beat 2 — Organs & Providers.** Validators under `/net/organs/link|mirror|invoke/requests/*` translate request dictionaries into transport mount configurations:
  - *Link* provisions long-lived channels for control traffic and telemetry. It enforces capability flags (`reliable`, `ordered`, `remote_net`, …), captures CEI topics like `tp_fatal`, and publishes state/provider fields back into the request.
  - *Mirror* stages beat bundles through the episodic engine. Requests supply `beat_window` (`val/u32`), `max_infl` (`val/u16`), and source peer/channel identifiers. The organ caches runtime-specific state, arms leases, and surfaces bundle commit evidence under the request.
  - *Invoke* routes remote enzyme submissions. Validators ensure peer/mount/local node identifiers respect CEP word limits, derive required transport caps, and register timeout handlers that enqueue `sig:fed_inv:timeout` if the remote side never responds.
- **Beat 3 — Validation & Documentation.** Dual-runtime harnesses exercise happy path (discovery → link → mirror → invoke) and failure modes (timeout, provider loss). Documentation—this design note plus updates to `FEDERATION-TRANSPORT.md` and the orientation guide—keeps the workflow discoverable.

### Transport Manager Responsibilities
- Maintains mount registry: `configure_mount`, `close`, `request_receive`, and telemetry refresh helpers.
- Emits CEI topics (`tp_noprov`, `tp_backpr`, `tp_fatal`, ...) and mirrors them under `/net/peers/<peer>/ceh/<topic>/`.
- Tracks per-mount counters so tests can assert readiness, backpressure, and fatal event evidence without poking providers directly.
- Provides callbacks to organs so they see consistent on_frame/on_event behaviour across real transports and mocks.

### Organ Behaviour and State
- **Link Organ**
  - Requests store fields: `peer`, `mount`, `mode`, `local_node`, optional `pref_prov`, `allow_upd`, `deadline`, and capability dictionaries.
  - Validator configures mounts via `cep_fed_link_mount_apply`, updates request `state/provider/error_note`, and records CEI when configuration fails.
  - Destructor closes mounts (reason `link-request-destroy`) and marks requests `removed`.
- **Mirror Organ**
  - Request contexts now record `cepRuntime*` so duplicate detection occurs per runtime. This prevents cross-runtime tests from tripping “mirror mount already active”.
  - Reads bundle settings (`beat_window` `val/u32`, `max_infl` `val/u16`, optional commit mode/resume tokens) and episodic deadlines (`val/u64`).
  - Manages episodic leases, tracks inflight bundle counts, updates telemetry (`bundle_seq`, `commit_beat`), and publishes CEI topics on schema conflicts or timeouts.
- **Invoke Organ**
  - Validates path segments and ensures textual IDs fit the 11-character CEP word constraint.
  - Configures mounts against required caps (reliable + ordered), schedules heartbeat-managed timeouts, and emits CEI topics `tp_inv_timeout` or `tp_inv_reject`.
  - Submission paths enqueue request frames with invocation IDs; responses remove pending entries and trigger completion callbacks.

### Federation Data Model
- All organ-visible data remains standard CEP dictionaries/values. Numeric knobs use canonical tags (`val/u32`, `val/u16`, `val/u64`), booleans use `val/bool`, and textual identifiers use `val/text`.
- Telemetry branches publish counts as `val/u64`, last-event text as `val/text`, and flags as `val/bool`.
- CEI topics adopt the short-form naming (`tp_*`) documented in the tag lexicon so observers can pattern-match across organs.

### Failure Handling & Diagnostics
- Transport manager surfaces provider failures through telemetry (`last_event`, `fatal_count`) and CEI topics.
- Mirror and invoke organs emit CEI on schema violations, timeouts, or provider rejections and reset request state when they tear down mounts.
- Dual-runtime harnesses rely on mock providers to simulate drop/reject conditions; unit tests assert that completion callbacks reflect success or failure and that request nodes carry the expected state transitions.

## Q&A
**Q: How do runtimes agree on which transports to use?**  
The transport manager inspects capability requirements (`caps/required`) and chooses a registered provider that satisfies them. If none match, it emits `tp_noprov` and leaves the request in `state=error`.

**Q: What keeps duplicate requests from conflicting across multiple runtimes?**  
Request contexts in each organ stash the current `cepRuntime*`; duplicate detection compares both runtime and peer/mount IDs. The dual-runtime harness now configures unique request names per runtime to make this explicit.

**Q: How are timeouts enforced for remote invokes?**  
Submissions capture the current beat, schedule `sig:fed_inv:timeout`, and enqueue the timeout handler at the deadline. When it fires, the handler emits `tp_inv_timeout`, marks the request error note, and fails the completion callback.

**Q: Where should new federation-native tags live?**  
Add them to `docs/CEP-TAG-LEXICON.md`, following the federation transport section. Numeric/scalar fields should use the canonical `val/*` tags described in `Native Types`.

**Q: What evidence do I get when a provider dies?**  
Telemetry marks `last_event` (e.g., `fatal` or `close`), counters increment, and `tp_fatal` (or similar) CEI entries update under `/net/peers/<peer>/ceh/`. Link/mirror/invoke validators propagate provider selection into the request so you can correlate CEI with the active provider.

**Q: How does this integrate with Layer 0 heartbeat?**  
Organs run as heartbeat enzymes. Link/mirror/invoke validators execute during the capture phase, transport callbacks fire during compute, and request state/telemetry updates land during commit. Federation never shortcuts the beat pipeline.

