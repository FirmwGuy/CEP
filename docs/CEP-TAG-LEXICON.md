# CEP Tag Lexicon

## Introduction
The CEP runtime speaks with a single voice: every domain/tag pair exposed by
different layers uses the `CEP` domain and a shared vocabulary of short tags. This
lexicon is the pocket dictionary for that vocabulary. It keeps engineers and
tools aligned, avoids improvised sigils or ad-hoc prefixes, and makes it obvious
when a new behavior needs a fresh word before it lands in code.

## Technical Details
- **Domain:** fixed to the uppercase acronym `CEP` for all kernel-provided data.
- **Tags:** lowercase words up to 11 characters using `[a-z0-9:_-.]`; `*` is reserved for glob patterns and `/` only appears in acronym IDs. Longer or
  composite concepts are shortened in this table; scripts should not invent
  alternatives.
- **CEP word vs. acronym:** A *word* ID encodes lowercase-first names (up to 11
  characters, must include at least one `a`-`z`, with optional `:-_./`). An
  *acronym* ID encodes uppercase or symbol-heavy names (up to 9 printable ASCII
  characters from space through underscore) and cannot be all digits. Both forms
  permit `*` when the identifier is used as a glob pattern; the runtime marks
  those tags with the `glob` hint automatically.
- **Reference tags:** `CEP_NAMING_REFERENCE` IDs come from the namepool; use
  `cep_namepool_intern_pattern*` when you want the stored string to behave as a
  glob. Plain interning leaves the text literal so existing names keep their
  current semantics.
- **Patterns:** Several entries describe a whole family of tags (e.g.
  `sig_*`). Only the patterns listed here are valid; collisions must be resolved
  by extending the table first.
- **Feature Area column:** uses acronyms to name the owning Layer 0 subsystem (see `docs/GLOSSARY.md` for definitions).

### Tag Catalogue

The tables below group CEP tags by the subsystem that consumes them so you can locate the canonical spelling, understand the owning feature area, and spot related patterns before minting new identifiers.

#### Core Runtime Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `/` | RT | root dictionary mounted during bootstrap. |
| `agenda` | RT | per-beat agenda log recorded under `/rt/beat/<n>/agenda`. |
| `beat` | RT | dictionary grouping heartbeat evidence for a specific beat. |
| `cas` | RT | content-addressable storage subtree. |
| `data` | RT | durable dataset root promoted at the end of a beat. |
| `coh` | L1 | Layer 1 coherence root under `/data/coh` (beings, bonds, contexts, facets, debts). |
| `beings` | L1 | Coherence beings dictionary under `/data/coh` storing durable identities. |
| `bonds` | L1 | Coherence bond records under `/data/coh` connecting beings with roles. |
| `contexts` | L1 | Context tuples linking beings under `/data/coh` with typed positions. |
| `facets` | L1 | Facet projections materialised for coherence closure under `/data/coh`. |
| `debts` | L1 | Adjacency debts recorded while required coherence facets are pending. |
| `flow` | L1 | Layer 1 flow root under `/data/flow` hosting pipeline definitions and runtime state. |
| `runs` | L1 | Runtime run records under `/data/flow/runtime/runs` capturing pipeline progress. |
| `annotations` | L1 | Human/runtime annotations attached to pipelines or runs under `/data/flow/annotations`. |
| `policy` | RT | pack-owned subtree under `/data/<pack>/policy` for publishing security pipeline specs or other pack policies. |
| `decisions` | RT | `/journal/decisions` ledger containing Decision Cell entries for risky cross-branch reads. |
| `persist` | RT | `/data/persist` subtree publishing CPS readiness evidence and per-branch stats. |
| `metrics` | RT | dictionary under `/data/persist/<branch>/metrics` containing per-branch counters. |
| `kv_eng` | RT | `val/text` field on `/data/persist/<branch>` identifying the active CPS backend (e.g. `flatfile`). |
| `frames` | RT | metric recording the number of committed frames under `/data/persist/<branch>/metrics`. |
| `beats` | RT | metric recording the number of beats persisted under `/data/persist/<branch>/metrics`. |
| `bytes_idx` | RT | metric tracking cumulative bytes written to `branch.idx` under `/data/persist/<branch>/metrics`. |
| `bytes_dat` | RT | metric tracking cumulative bytes written to `branch.dat` under `/data/persist/<branch>/metrics`. |
| `cas_hits` | RT | metric tracking how many CAS payload lookups were served from the branch cache (`/data/persist/<branch>/metrics`). |
| `cas_miss` | RT | metric counting CAS payload misses that required a runtime scan (`/data/persist/<branch>/metrics`). |
| `cas_lat_ns` | RT | metric reporting the average CAS lookup latency in nanoseconds for the active branch. |
| `persist_branch` | RT | fallback tag used when a branch name cannot be interned; hosts CPS metrics if needed. |
| `branch_stat` | RT | dictionary under `/data/persist/<branch>/branch_stat` exposing status fields for that branch’s persistence controller. |
| `config` | RT | dictionary under `/data/persist/<branch>/config` capturing the branch controller’s current persistence policy and scheduler knobs. |
| `last_bt` | RT | `branch_stat` field recording the last beat that reached CPS for the branch. |
| `pend_mut` | RT | `branch_stat` field counting pending mutations for the branch controller. |
| `dirty_ents` | RT | `branch_stat` field mirroring the controller’s dirty-entry count. |
| `dirty_bytes` | RT | `branch_stat` field estimating bytes currently pinned as dirty for the branch. |
| `pin_count` | RT | `branch_stat` field counting dirty payload/store pins that block eviction. |
| `frame_last` | RT | `branch_stat` field recording the most recent frame ID persisted for the branch. |
| `cause_last` | RT | `branch_stat` field indicating the last flush cause (`automatic`, `manual`, `scheduled`). |
| `flush_bytes` | RT | `branch_stat` field recording the byte estimate drained during the last flush. |
| `flush_pins` | RT | `branch_stat` field recording how many pins the last flush cleared. |
| `policy_mode` | RT | `config` field storing the active branch persistence policy label. |
| `flush_every` | RT | `config` field reporting the `flush_every_beats` policy value. |
| `flush_shdn` | RT | `config` field flagging whether the branch flushes when shutdown runs. |
| `allow_vol` | RT | `config` field signalling whether volatile reads are permitted for the branch. |
| `snapshot_ro` | RT | `config` field set to `1` when the branch runs under the read-only snapshot policy. |
| `schedule_bt` | RT | `config` field recording the beat the next scheduled flush should run (0 when unscheduled). |
| `bundle` | RT | envelope field used by `op/import` to specify the filesystem path to an exported CPS bundle. |
| `consumer` | RT | dictionary field storing the consumer branch DT inside `/journal/decisions/<entry>`. |
| `source` | RT | dictionary field storing the source branch DT inside `/journal/decisions/<entry>`. |
| `risk` | RT | text field recording the branch policy risk (`dirty` or `volatile`) for a recorded decision. |
| `persist.commit` | RT | CEI topic emitted when CPS finishes persisting a beat (`cps_storage_commit_current_beat`). |
| `persist.frame.io` | RT | CEI topic emitted when frame staging, fsync, or copy operations fail on the CPS backend. |
| `persist.checkpoint` | RT | CEI topic emitted when CPS writes checkpoint TOCs or reports errors during `op/checkpt`. |
| `persist.recover` | RT | CEI topic emitted when CPS detects branch corruption and runs crash-recovery sweeps. |
| `persist.bootstrap` | RT | CEI topic emitted when CPS bootstrap/engine activation surfaces warnings before `ist:store`. |
| `persist.flush.begin` | RT | CEI topic emitted when a branch flush request begins emitting a frame. |
| `persist.flush.done` | RT | CEI topic emitted when a branch flush request completes successfully. |
| `persist.flush.fail` | RT | CEI topic emitted when a branch flush request fails to serialize or apply. |
| `persist.evict` | RT | CEI topic emitted when CPCL trims branch cache history because RAM windows or quotas require eviction. |
| `persist.snapshot` | RT | CEI topic emitted when an operator enables the read-only snapshot policy for a branch. |
| `persist.defer` | RT | CEI topic emitted when a branch is placed into deferred/on-demand flush mode. |
| `chn:serial` | ASYNC | OPS/telemetry channel name reserved for the flat serializer sink. |
| `prov:serial` | ASYNC | Async provider identifier recorded alongside serializer sink requests. |
| `react:ser` | ASYNC | Reactor identifier mirrored into serializer async metadata. |
| `caps:sync` | ASYNC | Capability tag marking that the synchronous shim handled a request. |
| `reactor` | ASYNC | `/rt/analytics/async/reactor/<id>` branch storing per-reactor metrics. |
| `cq_depth` | ASYNC | metric counting the number of pending + active requests assigned to the reactor. |
| `pend_bytes` | ASYNC | metric tracking cumulative bytes staged across pending async jobs. |
| `comp_bt` | ASYNC | per-beat counter of completions drained from the reactor CQ. |
| `tp_async_unsp` | ASYNC | CEI topic emitted when a provider falls back to the async shim because native async paths are unavailable. |
| `persist.async` | ASYNC | CEI topic emitted when CPS async pipelines detect backlog or throttle events. |
| `persist.async.tmo` | ASYNC | CEI topic emitted when async persistence or serializer sinks exceed their beat/time budgets. |
| `enc_mode` | RT | Secdata metadata field describing the AEAD mode applied to the in-RAM payload. |
| `codec` | RT | Secdata metadata field describing the compression codec applied to the secured payload. |
| `key_id` | RT | Namepooled identifier recorded with secured payloads referencing the key selector used for sealing. |
| `payload_fp` | RT | Plaintext fingerprint stored alongside secured payload metadata for deterministic replay. |
| `ram_enc` | RT | Boolean flag indicating whether the in-memory payload bytes are sealed (encrypted) between beats. |
| `ram_cas` | RT | Boolean flag advertising whether the sealed payload has a matching CAS blob persisted on disk. |
| `rekey` | RT | OPS verb name reserved for secdata rekey operations. |
| `rcomp` | RT | OPS verb name reserved for secdata recompress operations. |
| `enc_fail` | RT | CEI topic emitted when secdata sealing fails (encryption/compression errors). |
| `dec_fail` | RT | CEI topic emitted when secdata unveiling fails (decryption errors). |
| `rekey_fail` | RT | CEI topic emitted when a secdata rekey attempt cannot complete. |
| `codec_mis` | RT | CEI topic emitted when secdata compression/decompression encounters an unsupported or corrupt codec stream. |
| `dictionary` | RT | canonical store tag for dictionary nodes. |
| `dtor` | RT | spec field storing the optional organ destructor enzyme name. |
| `ctor` | RT | spec field storing the optional organ constructor enzyme name. |
| `env` | RT | runtime environment subtree for external handles and the `security/env` overlay that stores environment-specific AEC policies. |
| `security` | RT | `/sys/security` subtree that collects Access & Execution Control policies. |
| `enclaves` | RT | dictionary under `/sys/security` describing enclave IDs and trust tiers. |
| `edges` | RT | dictionary under `/sys/security` storing cross-enclave edge policies. |
| `gateways` | RT | dictionary under `/sys/security` enumerating gateway enzymes surfaced to other enclaves. |
| `branches` | RT | dictionary under `/sys/security` specifying crown-jewel branch rules. |
| `defaults` | RT | dictionary under `/sys/security` capturing fallback budgets, TTLs, and rate ceilings. |
| `pipelines` | RT | `/data/<pack>/policy/security/pipelines` subtree containing pack-owned pipeline specs awaiting approval; reused under `/data/flow/pipelines` for Layer 1 DAG definitions. |
| `pipeline_id` | RT | `val/text` field storing the `<pack>/<name>` identifier for a pipeline spec. |
| `dag_run_id` | RT | `val/u64` field storing the DAG run identifier inside pipeline envelopes and CEI origin metadata. |
| `hop_index` | RT | `val/u64` field storing the hop ordinal inside pipeline envelopes and CEI origin metadata. |
| `stages` | RT | ordered dictionary listing the stages for a given pipeline spec. |
| `ceilings` | RT | optional dictionary inside a pipeline spec supplying requested aggregate ceilings. |
| `stage_id` | RT | per-stage identifier stored in each pipeline stage definition. |
| `stg_encl` | RT | `val/text` field assigning an enclave label to a pipeline stage. |
| `stg_enz` | RT | `val/text` field naming the gateway enzyme executed at a pipeline stage. |
| `approval` | RT | dictionary under each pipeline spec that records approval state, notes, and metadata. |
| `pol_ver` | RT | `val/u64` field inside a pipeline approval noting the security snapshot version used for validation. |
| `appr_bt` | RT | `val/u64` beat counter recorded when a pipeline spec was approved. |
| `tot_cpu_ns` | RT | pipeline ceiling field storing allowable cumulative CPU time per DAG. |
| `total_io_by` | RT | pipeline ceiling field storing allowable cumulative IO bytes per DAG. |
| `max_hops` | RT | pipeline ceiling field recording the maximum allowable edge count. |
| `max_wall_ms` | RT | pipeline ceiling field storing the maximum wall clock duration (milliseconds). |
| `max_beats` | RT | default budget field storing allowable beats per hop. |
| `mbox_max_bt` | RT | TTL default storing maximum heartbeat span for mailbox enforcement. |
| `ep_max_bt` | RT | TTL default storing maximum heartbeat span for episode-level enforcement. |
| `rsub_qps` | RT | rate ceiling field storing QPS caps per subject. |
| `renz_qps` | RT | rate ceiling field storing QPS caps per gateway enzyme. |
| `redge_qps` | RT | rate ceiling field storing QPS caps per edge (enclave→enclave). |
| `prod` | RT | leaf dictionary under `/sys/security/env` for production overlays. |
| `staging` | RT | leaf dictionary under `/sys/security/env` for staging overlays. |
| `dev` | RT | leaf dictionary under `/sys/security/env` for development overlays. |
| `sec.edge.deny` | RT | CEI topic emitted when an enclave edge policy denies a gateway invocation. |
| `sec.limit.hit` | RT | CEI topic emitted when a security budget or rate ceiling blocks a send. |
| `sig_sec/pipeline_preflight` | SIG | Signal routed to the pipeline preflight enzyme responsible for validating pipeline specs. |
| `sec_sends` | RT | telemetry counter tracking sends consumed under a security budget. |
| `sec_bytes` | RT | telemetry counter tracking bytes consumed under a security budget. |
| `sec_hits` | RT | telemetry counter tracking how many times a security limit fired. |
| `sec_rate` | RT | telemetry counter recording the current beat’s rate usage under a security ceiling. |
| `envelope` | RT | sealed message metadata dictionary under a mailbox message. |
| `err` | RT | root dictionary encapsulating a structured Common Error Interface fact. |
| `enzymes` | RT | registry dictionary exposing registered enzymes. |
| `impulses` | RT | beat impulse log recorded under `/rt/beat/<n>/impulses` (legacy `inbox` link retained for one release). |
| `analytics` | RT | runtime analytics root under `/rt/analytics`. |
| `spacing` | RT | beat-to-beat spacing metrics recorded by the heartbeat analytics helper. |
| `interval_ns` | RT | nanosecond interval payload inside spacing analytics entries. |
| `async` | RT | `/rt/analytics/async` root tracking shim/native async job summaries. |
| `shim` | RT | analytics branch storing shim-job counters under `/rt/analytics/async`. |
| `native` | RT | analytics branch storing provider-native async counters under `/rt/analytics/async`. |
| `jobs_total` | RT | counter stored under `/rt/analytics/async/(shim-or-native)/<provider>/<mount>/` reflecting total jobs per mount. |
| `issued_unix` | RT | unix timestamp captured alongside `issued_beat` inside a mailbox envelope. |
| `unix_ts_ns` | RT | per-beat Unix timestamp stored under `/rt/beat/<n>/meta/unix_ts_ns` and mirrored into stage notes, OPS history, and stream journals. |
| `paused` | PRR | `val/bool` flag under `/sys/state` indicating the heartbeat agenda is currently gated. |
| `view_hzn` | PRR | `val/u64` beat number recording the rollback visibility horizon. |
| `intent` | RT | journal entry describing requested work. |
| `journal` | RT | append-only heartbeat evidence ledger. |
| `kind` | RT | short organ slug persisted under `/sys/organs/<k>/spec/kind`. |
| `lib` | RT | library snapshot directory for proxied streams. |
| `list` | RT | store tag for linked-list containers. |
| `log` | RT | log entry tag attached to beat records. |
| `origin` | RT | dictionary describing the module, organ, or enzyme that emitted a CEI fact. |
| `label` | RT | optional human-readable organ description stored in the spec branch. |
| `meta` | RT | metadata dictionary attached to runtime cells. |
| `msgs` | RT | mailbox message dictionary keyed by local message ID. |
| `topic` | RT | short subject tag used by CEI facts for routing and filtering. |
| `organ/<k>` | RT | store tag pattern identifying typed organ root dictionaries. |
| `organs` | RT | system dictionary publishing immutable organ descriptors. |
| `txn` | RT | transaction metadata bucket (`meta/txn`) tracking veiled staging state. |
| `boot_oid` | RT | `val/bytes` cell under `/sys/state` publishing the boot operation OID. |
| `shdn_oid` | RT | `val/bytes` cell under `/sys/state` publishing the shutdown operation OID. |
| `op/l1_boot` | L1 | Operation verb used by the Layer 1 pack boot helper to publish readiness evidence. |
| `op/l1_shdn` | L1 | Operation verb used by the Layer 1 pack shutdown helper to mark teardown. |
| `namepool` | RT | identifier intern table. |
| `next_msg_id` | RT | deterministic counter stored under `meta/runtime/next_msg_id`. |
| `outcome` | RT | execution result record written after enzymes run. |
| `target` | RT | canonical link entry used by helper-built facet dictionaries. |
| `parent` | RT | provenance pointer stored inside `meta/parents`. |
| `parents` | RT | provenance list capturing the source lineage. |
| `rt` | RT | runtime staging root holding beat journals. |
| `runtime` | RT | per-mailbox runtime metadata bucket (ID counters, expiry buckets); reused under `/data/flow/runtime` for Layer 1 run state. |
| `rt_ctx` | RT | hidden root payload recording the owning runtime context for multi-instance isolation. |
| `expiries` | RT | beat-indexed expiry bucket dictionary under mailbox runtime metadata. |
| `exp_wall` | RT | unix timestamp expiry bucket dictionary under mailbox runtime metadata. |
| `stage` | RT | per-beat stage log recording committed mutations. |
| `spec` | RT | immutable organ descriptor snapshot stored under `/sys/organs/<k>/spec`. |
| `store` | RT | spec field recording the organ root store DT. |
| `stream-log` | RT | runtime log for stream adapters. |
| `sys` | RT | system namespace with counters and configuration. |
| `text` | RT | namepool payload store for textual data. |
| `tmp` | RT | scratch list reserved for tooling. |
| `ttl` | RT | TTL dictionary attached to envelopes or mailbox policy nodes. |
| `ttl_beats` | RT | relative TTL expressed in heartbeat counts. |
| `ttl_unix_ns` | RT | relative TTL expressed in wallclock nanoseconds. |
| `ttl_mode` | RT | TTL control flag (`"forever"` disables expiry at that scope). |
| `validator` | RT | spec field storing the required organ validator enzyme name. |
| `sev:*` (`sev:fatal`, `sev:crit`, `sev:usage`, `sev:warn`, `sev:debug`) | RT | severity vocabulary used by CEI to express runtime impact. |

#### Operational Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `arg_deep` / `arg_pos` / `arg_prepend` | OPS | parameters accepted by cell-operation enzymes. |
| `armed` | E3 | watcher flag indicating the continuation is queued for promotion at the next beat. |
| `close` | OPS | sealed dictionary containing terminal status metadata for an operation. |
| `code` | OPS | optional numeric code attached to a history entry or current state. |
| `cont` | E3 | watcher continuation signal stored under `/watchers/<id>/cont`. |
| `deadline` | OPS | watcher timeout beat stored under `/watchers/<id>/deadline`. |
| `envelope` | OPS | immutable dictionary describing an operation's verb, target, mode, and issued beat. |
| `enz_add` / `enz_cln` / `enz_del` / `enz_mov` / `enz_upd` | OPS | canonical enzyme descriptors registered at bootstrap. |
| `history` | OPS | dictionary logging state transitions (`0001/`, `0002/`, …). |
| `hist_next` | OPS | numeric field on `/rt/ops/<oid>` recording the next monotonic history auto-ID so resume/rollback loops never reuse prior names. |
| `issued_beat` | OPS | beat index recorded in an operation envelope. |
| `ist:cutover` | PRR | rollback operation state marking the live view pivot in progress. |
| `ist:flush` | PRR | shutdown operation state indicating buffered work is being flushed. |
| `ist:halt` | PRR | shutdown operation state indicating the runtime is halting. |
| `ist:kernel` | OPS | boot operation state marking kernel scaffolding completion. |
| `ist:ok` | OPS | terminal state recorded after `cep_op_close()` maps the final status. |
| `ist:paused` | PRR | pause operation state confirming agenda gating is active. |
| `ist:packs` | OPS | boot operation state marking pack readiness. |
| `ist:plan` | OPS | control operation planning state recorded when the dossier opens. |
| `ist:quiesce` | PRR | pause operation state marking non-essential work being parked. |
| `ist:run` | OPS | resume operation state confirming backlog drain has restarted the agenda. |
| `ist:exec` | OPS | intermediate state recorded while an OPS verb (checkpoint/compact/sync) is executing. |
| `ist:stop` | OPS | shutdown operation state marking teardown start. |
| `ist:store` | OPS | boot operation state marking persistent stores ready. |
| `note` | OPS | optional textual note attached to a history entry. |
| `op/boot` | OPS | bootstrapping operation verb emitted at startup. |
| `op/cont` | OPS | continuation signal emitted when an awaiter fires. |
| `op/ct` | OPS | constructor operation verb routed to organ roots. |
| `op/dt` | OPS | destructor operation verb routed to organ roots. |
| `op/checkpt` | OPS | persistence verb that asks CPS to write a checkpoint snapshot immediately. |
| `op/compact` | OPS | persistence verb requesting CPS compaction/retention maintenance. |
| `op/sync` | OPS | persistence verb signalling an explicit sync/export of CPS state. |
| `op/import` | OPS | persistence verb instructing CPS to verify + stage an exported bundle under the branch’s `imports/` directory. |
| `op/br_flush` | OPS | persistence verb that forces a specific branch to flush its dirty set on the next commit. |
| `op/br_sched` | OPS | persistence verb scheduling a branch to flush after a caller-provided beat offset. |
| `op/br_defer` | OPS | persistence verb that places a branch into on-demand/deferred flush mode. |
| `op/pause` | PRR | pause control operation verb that gates the heartbeat agenda. |
| `op/resume` | PRR | resume control operation verb that re-opens the agenda. |
| `op/rollback` | PRR | rollback control operation verb that re-points the view horizon. |
| `op/shdn` | OPS | shutdown operation verb emitted during teardown. |
| `op/tmo` | OPS | timeout signal emitted when an awaiter expires. |
| `op/vl` | OPS | validator operation verb that runs organ integrity checks. |
| `op_add` / `op_clone` / `op_delete` / `op_move` / `op_upd` | OPS | operation identifiers emitted by `sig_cell` payloads. |
| `opm:states` | OPS | operation mode indicating state-tracking semantics. |
| `org:<k>:*` | OPS | organ enzyme names (`org:<k>:vl`, `org:<k>:ct`, `org:<k>:dt`) bound at organ roots. |
| `payload_id` | OPS | optional `val/bytes` payload stored in envelopes and watcher entries. |
| `qos` | OPS | control-plane QoS flags stored alongside paused impulses. |
| `role_parnt` / `role_source` / `role_subj` / `role_templ` | OPS | role vocabulary consumed by mutation enzymes. |
| `sig_cell` | OPS | signal namespace for kernel cell operations. |
| `sig_cei/*` | OPS | error-channel signals dispatched by CEI helper emissions and consumed by bound enzymes. |
| `state` | OPS | current logical state (`ist:*`) stored on an operation root. |
| `status` | OPS | terminal status (`sts:*`) recorded under `/close/status`. |
| `sts:cnl` | OPS | cancellation status recorded when an operation is aborted. |
| `sts:fail` | OPS | failure status recorded when an operation terminates unsuccessfully. |
| `sts:ok` | OPS | success status recorded when an operation completes normally. |
| `summary_id` | OPS | optional summary payload identifier stored under `/close/summary_id`. |
| `ttl` | OPS | watcher expiry interval in beats. |
| `watchers` | OPS | dictionary tracking pending awaiters. |
| `want` | OPS | requested state or status captured for a watcher. |
| `closed_beat` | OPS | beat index recorded when the `/close/` branch was sealed. |

#### Episode Engine Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `op/ep` | E3 | operation verb assigned to episodic dossiers tracked under `/rt/ops/<eid>`. |
| `ep/cont` | E3 | continuation signal emitted when an episode should resume on the next beat. |
| `ist:yield` | E3 | state recorded when an episode voluntarily yields the current slice. |
| `ist:await` | E3 | state recorded while an episode is waiting on an external operation. |
| `ist:cxl` | E3 | intermediate cancellation state published before closing with `sts:cnl`. |
| `ep:pro/ro` | E3 | metadata marker indicating a read-only episode profile. |
| `ep:pro/rw` | E3 | metadata marker indicating a read-write episode profile. |
| `ep:bud/io` | E3 | CEI topic emitted when an episode exceeds its configured I/O budget. |
| `ep:bud/cpu` | E3 | CEI topic emitted when an episode exceeds its configured CPU budget. |
| `episode` | E3 | metadata dictionary under an `op/ep` branch capturing policy and paths. |
| `bud_cpu_ns` | E3 | metadata field storing the per-slice CPU budget in nanoseconds. |
| `bud_io_by` | E3 | metadata field storing the per-slice I/O budget in bytes. |
| `sig_path` | E3 | metadata field recording the signal path used to dispatch the episode. |
| `tgt_path` | E3 | metadata field recording the target path resumed by continuations. |
| `max_beats` | E3 | metadata field constraining how many slices an episode may execute. |

#### I/O Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `library` | SER | metadata tag describing proxied library payloads. |
| `stdio_res` / `stdio_str` | SER | stdio-backed stream resource and descriptor nodes. |
| `zip_entry` / `zip_stream` | SER | libzip-backed resource and stream adapters. |

#### Federation Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `net` | FED | root dictionary for federation metadata (peers, mounts, transports). |
| `mounts` | FED | groups mount declarations by peer and mode under `/net/mounts`. |
| `peers` | FED | peer registry keyed by peer identifier; hosts services and CEI health. |
| `catalog` | FED | per-mode mount catalog generated during bootstrap under `/net/catalog`. |
| `transports` | FED | registry of transport providers keyed by provider ID. |
| `transport` | FED | per-mount dictionary recording the chosen provider and capability summary. |
| `caps` | FED | nested dictionary capturing capability bitmaps (required, preferred, or provider-specific). |
| `cap_crc32c` | FED | provider capability flag indicating CRC32C checksum support. |
| `cap_deflate` | FED | provider capability flag indicating deflate frame compression support. |
| `cap_aead` | FED | provider capability flag indicating AEAD payload encryption support. |
| `cap_cmpver` | FED | provider capability flag signalling comparator-version awareness. |
| `prov_caps` | FED | mirrors the selected provider capability bitset for the active mount. |
| `provider` | FED | stores the provider identifier associated with a mount record. |
| `upd_latest` | FED | boolean flag indicating a mount opts into droppable gauge frames. |
| `src_peer` | FED | mirror organ request field naming the remote peer supplying bundles. |
| `src_chan` | FED | mirror organ request field naming the remote channel supplying bundles. |
| `max_infl` | FED | mirror organ bundle parameter limiting simultaneous in-flight bundles. |
| `resume_tok` | FED | mirror organ optional token handed to callers to resume paused mirrors. |
| `pend_resum` | FED | mirror organ status field publishing the pending resume token when manual commits pause work. |
| `serializer` | FED | optional mirror organ dictionary constraining flat serializer features. |
| `crc32c_ok` | FED | serializer policy flag that permits CRC32C emission on a mirror mount. |
| `deflate_ok` | FED | serializer policy flag that permits deflate compression on a mirror mount. |
| `aead_ok` | FED | serializer policy flag that permits AEAD encryption on a mirror mount. |
| `warn_down` | FED | serializer policy flag enabling/disabling CEI when downgrading features. |
| `cmp_max_ver` | FED | serializer policy field limiting comparator versions emitted for a mirror mount. |
| `bundle_seq` | FED | mirror organ status field recording the last committed bundle sequence. |
| `commit_beat` | FED | mirror organ status field recording the beat of the most recent commit. |
| `tp_inv_timeout` | FED | CEI topic emitted when a remote invocation exceeds its beat budget. |
| `tp_inv_reject` | FED | CEI topic emitted when the remote peer rejects an invocation request. |
| `services` | FED | peer-level dictionary listing advertised services/mounts. |
| `telemetry` | FED | heartbeat-sampled metrics root under `/net/telemetry`. |
| `ceh` | FED | consolidated CEI health facts per peer keyed by telemetry topic. |
| `net_discovery` | FED | discovery organ slug registered by the federation pack. |
| `net_health` | FED | health organ slug registered by the federation pack. |
| `bp_count` | FED | telemetry counter tracking total backpressure events for a mount. |
| `bp_flag` | FED | boolean flag indicating the mount is currently backpressured. |
| `last_mode` | FED | telemetry field recording the last transmitted frame mode. |
| `last_sample` | FED | telemetry field recording the first byte of the last transmitted frame. |
| `async_pnd` | FED | telemetry counter storing how many async requests are inflight for the mount. |
| `async_shm` | FED | telemetry counter tracking completions handled by shim worker threads. |
| `async_nat` | FED | telemetry counter tracking provider-native async completions. |
| `tp_backpr` | FED | CEI topic and health key for backpressure notifications. |
| `tp_catsync` | FED | CEI topic for catalog/telemetry publication failures. |
| `tp_fatal` | FED | CEI topic recording fatal transport channel events. |
| `tp_noprov` | FED | CEI topic recorded when no provider satisfies mount requirements. |
| `tp_async_unsp` | FED | CEI topic emitted when a mount falls back to the async shim because the provider lacks async hooks. |
| `tp_openfail` | FED | CEI topic emitted when provider channel negotiation fails. |
| `tp_provcell` | FED | CEI topic noting provider cell resolution failures. |
| `tp_provid` | FED | CEI topic emitted when provider identifiers cannot be encoded. |
| `tp_schema` | FED | CEI topic indicating the mount schema branch could not be ensured. |
| `tp_schemup` | FED | CEI topic signalling mount schema update failures. |
| `tp_sendfail` | FED | CEI topic emitted when a provider send operation fails. |
| `tp_upd_den` | FED | CEI topic capturing rejected `upd_latest` frames (mount opted out). |
| `tp_upd_mis` | FED | CEI topic capturing `upd_latest` frames sent to non-unreliable transports. |
| `tp_flatneg` | FED | CEI topic emitted when the sender downgrades CRC32C/deflate/AEAD for a mount. |
| `tp_mconf` | FED | CEI topic emitted when a mirror organ request conflicts with an existing mount. |
| `tp_mtimeout` | FED | CEI topic emitted when a mirror organ request exceeds its deadline. |

#### Test Harness Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `catalog` | TEST | storage fixture exercising catalog/indexed semantics. |
| `cmp_root` | TEST | comparison root used by traversal and enzyme tests. |
| `dict` | TEST | shorthand tag used by dynamic dictionary fixtures. |
| `domain` | TEST | domain/tag packing validation tag. |
| `hash` | TEST | storage fixture for hash-indexed tables. |
| `hyb_field` | TEST | hybrid integration POC field mutated during promote/demote coverage. |
| `hyb_fin` | TEST | hybrid episode test tag confirming RO guard after demotion. |
| `hyb_mut` | TEST | hybrid episode test tag recording the RW mutation slice. |
| `oct_root` / `oct_space` | TEST | octree storage fixtures in randomized tests. |
| `pq_buffer` / `pq_root` | TEST | packed-queue storage fixtures. |
| `poc` | TEST | integration POC root covering the end-to-end heartbeat timeline scenario. |
| `poc_catalog` | TEST | dictionary store standing in for the catalog branch during integration testing. |
| `poc_event` | TEST | log entry payload tag used by the integration log/history assertions. |
| `poc_item` | TEST | catalog value payload type exercised by the integration scenario. |
| `poc_link` | TEST | scratch dictionary used to validate link/backlink semantics in the integration test. |
| `poc_log` | TEST | list store tag backing the integration log branch. |
| `poc_stream_root` | TEST | stream/proxy dictionary hosting the journalled stdio adapter in the integration test. |
| `poc_replay` | TEST | replay root populated when verifying serialization round-trips. |
| `poc_txn` | TEST | veiled transaction branch staged during the integration heartbeat timeline. |
| `space` | TEST | octree dictionary mounted under `/data/poc` to exercise spatial store plumbing during integration. |
| `space_entry` | TEST | deterministic point payload inserted into the spatial store to validate octree comparisons. |
| `rand_entry_*` | TEST | seeded log entries appended during randomized mutation passes to ensure logging remains deterministic. |
| `prr_pause` | TEST | backlog dictionary that records retained impulses while pause/rollback is exercised. |
| `enz:poc_idx` / `enz:poc_agg` | TEST | ordered enzyme pair asserting catalog reindex sequencing. |
| `enz:poc_rand` | TEST | deterministic random enzyme descriptor feeding seeded impulse bursts. |
| `sig:poc/prr` | TEST | integration heartbeat signal that exercises pause/rollback sequencing. |
| `org:poc:*` | TEST | integration organ descriptor signals (`org:poc:val`, `org:poc:ctor`, `org:poc:dtor`). |
| `org:fixture:*` | TEST | OVH (Organ Validation Harness) fixture signals exercising constructor/destructor/validator dossiers. |
| `sig_apply` `sig_beta` `sig_broad` `sig_cycle` `sig_dedup` `sig_dup` `sig_empty` `sig_expect` `sig_gamma` `sig_hb` `sig_img` `sig_mask` `sig_match` `sig_nop` `sig_rand` `sig_root` `sig_rty` `sig_skip` `sig_thumb` `sig_tree` | TEST | assorted signal tags exercised by scheduler and heartbeat tests. |
| `sys_child` / `sys_root` | TEST | synthetic system fixtures in randomized tests. |
| `test_enz_*` (`test_enz_a`, `test_enz_b`, `test_enz_c`, `test_enz_d`, `test_enz_da`, `test_enz_e`, `test_enz_le`, `test_enz_ro`) | TEST | enzyme dependency graphs in unit tests. |
| `test_ez_*` (`test_ez_bc`, `test_ez_bd`, `test_ez_da`, `test_ez_du`, `test_ez_er`, `test_ez_ge`, `test_ez_la`, `test_ez_le`, `test_ez_li`, `test_ez_ma`, `test_ez_mi`, `test_ez_no`, `test_ez_p1`, `test_ez_p2`, `test_ez_p3`, `test_ez_pl`, `test_ez_ro`, `test_ez_si`, `test_ez_sig`, `test_ez_sp`, `test_ez_sr`, `test_ez_st`, `test_ez_wl`) | TEST | synthetic descriptor names used by dispatch tests. |
| `test_hb_*` (`test_hb_a`, `test_hb_b`, `test_hb_cn`, `test_hb_r`, `test_hb_rt`) | TEST | heartbeat test hooks. |
| `test_img_*` (`test_img_ch`, `test_img_vi`) | TEST | image stream fixtures in serialization tests. |
| `test_lck_*` (`test_lck_ch`, `test_lck_in`) | TEST | lock hierarchy fixtures. |
| `tst_enz*` (`tst_enza`, `tst_enzb`, `tst_enzc`, `tst_enzi`, `tst_enzj`, `tst_enzk`, `tst_enzl`, `tst_enzm`, `tst_enzo`, `tst_enzp`, `tst_enzq`, `tst_enzr`) | TEST | randomized enzyme descriptors used by registry fuzz tests. |
| `tst_*` (`tst_a`, `tst_b`, `tst_branch`, `tst_child`, `tst_chld`, `tst_clone`, `tst_data`, `tst_dedup`, `tst_drop`, `tst_empty`, `tst_far`, `tst_head`, `tst_keep_a`, `tst_keep_b`, `tst_leaf`, `tst_list`, `tst_mask`, `tst_mid`, `tst_nop`, `tst_path`, `tst_remove`, `tst_root`, `tst_sig`, `tst_stor`, `tst_tree`, `tst_update`, `tst_val`, `tst_value`) | TEST | generic test scaffolding tags. |
| `raw_all_sib` | TEST | veiled sibling fixture used by raw traversal helper tests. |
| `value` | TEST | generic payload tag for value-type fixtures. |
| `var_leaf` | TEST | variant selection fixture in unit tests. |

#### Reserved Upper-Layer Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| *reserved* | L1–L4 | Placeholder row; add upper-layer tag definitions here before minting them in code. |
### Usage Notes
- Tags marked *ops* should only appear in impulse payloads and descriptor
  declarations. Emitting them outside the heartbeat dispatcher is undefined.
- Tags marked *test* are reserved for the unit-test harness; production code
  must not emit them.
- When you need a new tag, update this lexicon first. Keep within the length and
  character constraints to preserve compatibility with the packed `cepDT`
  encoding.

## Global Q&A
- **Why force every domain to `CEP`?** It removes a whole axis of collisions and
  lets us reason about “what” without worrying about “where”. Tags now carry the
  meaning; the domain just declares “kernel-owned”.
- **What if a tag needs more than 11 characters?** Shorten it in a way that stays
  readable (`role_parnt`, `sig_expect`) and document the expansion here. If the
  abbreviation is unclear, add a note.
- **How do tests add fixtures?** Follow the existing patterns (`test_*`,
  `tst_*`, etc.) and document the new pattern on this table. This keeps the test
  namespace vast but contained.
- **Can application layers invent their own domains?** Yes—outside CEP the
  lexicon is advisory. The contract here only governs CEP's built-in runtime.
