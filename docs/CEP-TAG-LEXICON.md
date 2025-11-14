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
- **Feature Area column:** records the Layer 0 subsystem (PRR, E³, serialization,
  etc.) that owns the tag so reviewers can spot coupling at a glance; it
  replaces the old status flag.

### Tag Catalogue

The tables below group CEP tags by the subsystem that consumes them so you can locate the canonical spelling, understand the owning feature area, and spot related patterns before minting new identifiers.

#### Core Runtime Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `/` | Runtime platform | root dictionary mounted during bootstrap. |
| `agenda` | Runtime platform | per-beat agenda log recorded under `/rt/beat/<n>/agenda`. |
| `beat` | Runtime platform | dictionary grouping heartbeat evidence for a specific beat. |
| `cas` | Runtime platform | content-addressable storage subtree. |
| `data` | Runtime platform | durable dataset root promoted at the end of a beat. |
| `persist` | Runtime platform | `/data/persist` subtree publishing CPS readiness evidence and per-branch stats. |
| `metrics` | Runtime platform | dictionary under `/data/persist/<branch>/metrics` containing per-branch counters. |
| `kv_eng` | Runtime platform | `val/text` field on `/data/persist/<branch>` identifying the active CPS backend (e.g. `flatfile`). |
| `frames` | Runtime platform | metric recording the number of committed frames under `/data/persist/<branch>/metrics`. |
| `beats` | Runtime platform | metric recording the number of beats persisted under `/data/persist/<branch>/metrics`. |
| `bytes_idx` | Runtime platform | metric tracking cumulative bytes written to `branch.idx` under `/data/persist/<branch>/metrics`. |
| `bytes_dat` | Runtime platform | metric tracking cumulative bytes written to `branch.dat` under `/data/persist/<branch>/metrics`. |
| `cas_hits` | Runtime platform | metric tracking how many CAS payload lookups were served from the branch cache (`/data/persist/<branch>/metrics`). |
| `cas_miss` | Runtime platform | metric counting CAS payload misses that required a runtime scan (`/data/persist/<branch>/metrics`). |
| `cas_lat_ns` | Runtime platform | metric reporting the average CAS lookup latency in nanoseconds for the active branch. |
| `persist_branch` | Runtime platform | fallback tag used when a branch name cannot be interned; hosts CPS metrics if needed. |
| `bundle` | Runtime platform | envelope field used by `op/import` to specify the filesystem path to an exported CPS bundle. |
| `persist.commit` | Runtime platform | CEI topic emitted when CPS finishes persisting a beat (`cps_storage_commit_current_beat`). |
| `persist.frame.io` | Runtime platform | CEI topic emitted when frame staging, fsync, or copy operations fail on the CPS backend. |
| `persist.checkpoint` | Runtime platform | CEI topic emitted when CPS writes checkpoint TOCs or reports errors during `op/checkpt`. |
| `persist.recover` | Runtime platform | CEI topic emitted when CPS detects branch corruption and runs crash-recovery sweeps. |
| `persist.bootstrap` | Runtime platform | CEI topic emitted when CPS bootstrap/engine activation surfaces warnings before `ist:store`. |
| `enc_mode` | Runtime platform | Secdata metadata field describing the AEAD mode applied to the in-RAM payload. |
| `codec` | Runtime platform | Secdata metadata field describing the compression codec applied to the secured payload. |
| `key_id` | Runtime platform | Namepooled identifier recorded with secured payloads referencing the key selector used for sealing. |
| `payload_fp` | Runtime platform | Plaintext fingerprint stored alongside secured payload metadata for deterministic replay. |
| `ram_enc` | Runtime platform | Boolean flag indicating whether the in-memory payload bytes are sealed (encrypted) between beats. |
| `ram_cas` | Runtime platform | Boolean flag advertising whether the sealed payload has a matching CAS blob persisted on disk. |
| `rekey` | Runtime platform | OPS verb name reserved for secdata rekey operations. |
| `rcomp` | Runtime platform | OPS verb name reserved for secdata recompress operations. |
| `enc_fail` | Runtime platform | CEI topic emitted when secdata sealing fails (encryption/compression errors). |
| `dec_fail` | Runtime platform | CEI topic emitted when secdata unveiling fails (decryption errors). |
| `rekey_fail` | Runtime platform | CEI topic emitted when a secdata rekey attempt cannot complete. |
| `codec_mis` | Runtime platform | CEI topic emitted when secdata compression/decompression encounters an unsupported or corrupt codec stream. |
| `dictionary` | Runtime platform | canonical store tag for dictionary nodes. |
| `dtor` | Runtime platform | spec field storing the optional organ destructor enzyme name. |
| `ctor` | Runtime platform | spec field storing the optional organ constructor enzyme name. |
| `env` | Runtime platform | runtime environment subtree for external handles. |
| `envelope` | Runtime platform | sealed message metadata dictionary under a mailbox message. |
| `err` | Runtime platform | root dictionary encapsulating a structured Common Error Interface fact. |
| `enzymes` | Runtime platform | registry dictionary exposing registered enzymes. |
| `impulses` | Runtime platform | beat impulse log recorded under `/rt/beat/<n>/impulses` (legacy `inbox` link retained for one release). |
| `analytics` | Runtime platform | runtime analytics root under `/rt/analytics`. |
| `spacing` | Runtime platform | beat-to-beat spacing metrics recorded by the heartbeat analytics helper. |
| `interval_ns` | Runtime platform | nanosecond interval payload inside spacing analytics entries. |
| `issued_unix` | Runtime platform | unix timestamp captured alongside `issued_beat` inside a mailbox envelope. |
| `unix_ts_ns` | Runtime platform | per-beat Unix timestamp stored under `/rt/beat/<n>/meta/unix_ts_ns` and mirrored into stage notes, OPS history, and stream journals. |
| `paused` | Pause/Rollback/Resume | `val/bool` flag under `/sys/state` indicating the heartbeat agenda is currently gated. |
| `view_hzn` | Pause/Rollback/Resume | `val/u64` beat number recording the rollback visibility horizon. |
| `intent` | Runtime platform | journal entry describing requested work. |
| `journal` | Runtime platform | append-only heartbeat evidence ledger. |
| `kind` | Runtime platform | short organ slug persisted under `/sys/organs/<k>/spec/kind`. |
| `lib` | Runtime platform | library snapshot directory for proxied streams. |
| `list` | Runtime platform | store tag for linked-list containers. |
| `log` | Runtime platform | log entry tag attached to beat records. |
| `origin` | Runtime platform | dictionary describing the module, organ, or enzyme that emitted a CEI fact. |
| `label` | Runtime platform | optional human-readable organ description stored in the spec branch. |
| `meta` | Runtime platform | metadata dictionary attached to runtime cells. |
| `msgs` | Runtime platform | mailbox message dictionary keyed by local message ID. |
| `topic` | Runtime platform | short subject tag used by CEI facts for routing and filtering. |
| `organ/<k>` | Runtime platform | store tag pattern identifying typed organ root dictionaries. |
| `organs` | Runtime platform | system dictionary publishing immutable organ descriptors. |
| `txn` | Runtime platform | transaction metadata bucket (`meta/txn`) tracking veiled staging state. |
| `boot_oid` | Runtime platform | `val/bytes` cell under `/sys/state` publishing the boot operation OID. |
| `shdn_oid` | Runtime platform | `val/bytes` cell under `/sys/state` publishing the shutdown operation OID. |
| `namepool` | Runtime platform | identifier intern table. |
| `next_msg_id` | Runtime platform | deterministic counter stored under `meta/runtime/next_msg_id`. |
| `outcome` | Runtime platform | execution result record written after enzymes run. |
| `target` | Runtime platform | canonical link entry used by helper-built facet dictionaries. |
| `parent` | Runtime platform | provenance pointer stored inside `meta/parents`. |
| `parents` | Runtime platform | provenance list capturing the source lineage. |
| `rt` | Runtime platform | runtime staging root holding beat journals. |
| `runtime` | Runtime platform | per-mailbox runtime metadata bucket (ID counters, expiry buckets). |
| `rt_ctx` | Runtime platform | hidden root payload recording the owning runtime context for multi-instance isolation. |
| `expiries` | Runtime platform | beat-indexed expiry bucket dictionary under mailbox runtime metadata. |
| `exp_wall` | Runtime platform | unix timestamp expiry bucket dictionary under mailbox runtime metadata. |
| `stage` | Runtime platform | per-beat stage log recording committed mutations. |
| `spec` | Runtime platform | immutable organ descriptor snapshot stored under `/sys/organs/<k>/spec`. |
| `store` | Runtime platform | spec field recording the organ root store DT. |
| `stream-log` | Runtime platform | runtime log for stream adapters. |
| `sys` | Runtime platform | system namespace with counters and configuration. |
| `text` | Runtime platform | namepool payload store for textual data. |
| `tmp` | Runtime platform | scratch list reserved for tooling. |
| `ttl` | Runtime platform | TTL dictionary attached to envelopes or mailbox policy nodes. |
| `ttl_beats` | Runtime platform | relative TTL expressed in heartbeat counts. |
| `ttl_unix_ns` | Runtime platform | relative TTL expressed in wallclock nanoseconds. |
| `ttl_mode` | Runtime platform | TTL control flag (`"forever"` disables expiry at that scope). |
| `validator` | Runtime platform | spec field storing the required organ validator enzyme name. |
| `sev:*` (`sev:fatal`, `sev:crit`, `sev:usage`, `sev:warn`, `sev:debug`) | Runtime platform | severity vocabulary used by CEI to express runtime impact. |

#### Operational Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `arg_deep` / `arg_pos` / `arg_prepend` | OPS timeline | parameters accepted by cell-operation enzymes. |
| `armed` | E³ (Episodic Enzyme Engine) | watcher flag indicating the continuation is queued for promotion at the next beat. |
| `close` | OPS timeline | sealed dictionary containing terminal status metadata for an operation. |
| `code` | OPS timeline | optional numeric code attached to a history entry or current state. |
| `cont` | E³ (Episodic Enzyme Engine) | watcher continuation signal stored under `/watchers/<id>/cont`. |
| `deadline` | OPS timeline | watcher timeout beat stored under `/watchers/<id>/deadline`. |
| `envelope` | OPS timeline | immutable dictionary describing an operation's verb, target, mode, and issued beat. |
| `enz_add` / `enz_cln` / `enz_del` / `enz_mov` / `enz_upd` | OPS timeline | canonical enzyme descriptors registered at bootstrap. |
| `history` | OPS timeline | dictionary logging state transitions (`0001/`, `0002/`, …). |
| `hist_next` | OPS timeline | numeric field on `/rt/ops/<oid>` recording the next monotonic history auto-ID so resume/rollback loops never reuse prior names. |
| `issued_beat` | OPS timeline | beat index recorded in an operation envelope. |
| `ist:cutover` | Pause/Rollback/Resume | rollback operation state marking the live view pivot in progress. |
| `ist:flush` | Pause/Rollback/Resume | shutdown operation state indicating buffered work is being flushed. |
| `ist:halt` | Pause/Rollback/Resume | shutdown operation state indicating the runtime is halting. |
| `ist:kernel` | OPS timeline | boot operation state marking kernel scaffolding completion. |
| `ist:ok` | OPS timeline | terminal state recorded after `cep_op_close()` maps the final status. |
| `ist:paused` | Pause/Rollback/Resume | pause operation state confirming agenda gating is active. |
| `ist:packs` | OPS timeline | boot operation state marking pack readiness. |
| `ist:plan` | OPS timeline | control operation planning state recorded when the dossier opens. |
| `ist:quiesce` | Pause/Rollback/Resume | pause operation state marking non-essential work being parked. |
| `ist:run` | OPS timeline | resume operation state confirming backlog drain has restarted the agenda. |
| `ist:exec` | OPS timeline | intermediate state recorded while an OPS verb (checkpoint/compact/sync) is executing. |
| `ist:stop` | OPS timeline | shutdown operation state marking teardown start. |
| `ist:store` | OPS timeline | boot operation state marking persistent stores ready. |
| `note` | OPS timeline | optional textual note attached to a history entry. |
| `op/boot` | OPS timeline | bootstrapping operation verb emitted at startup. |
| `op/cont` | OPS timeline | continuation signal emitted when an awaiter fires. |
| `op/ct` | OPS timeline | constructor operation verb routed to organ roots. |
| `op/dt` | OPS timeline | destructor operation verb routed to organ roots. |
| `op/checkpt` | OPS timeline | persistence verb that asks CPS to write a checkpoint snapshot immediately. |
| `op/compact` | OPS timeline | persistence verb requesting CPS compaction/retention maintenance. |
| `op/sync` | OPS timeline | persistence verb signalling an explicit sync/export of CPS state. |
| `op/import` | OPS timeline | persistence verb instructing CPS to verify + stage an exported bundle under the branch’s `imports/` directory. |
| `op/pause` | Pause/Rollback/Resume | pause control operation verb that gates the heartbeat agenda. |
| `op/resume` | Pause/Rollback/Resume | resume control operation verb that re-opens the agenda. |
| `op/rollback` | Pause/Rollback/Resume | rollback control operation verb that re-points the view horizon. |
| `op/shdn` | OPS timeline | shutdown operation verb emitted during teardown. |
| `op/tmo` | OPS timeline | timeout signal emitted when an awaiter expires. |
| `op/vl` | OPS timeline | validator operation verb that runs organ integrity checks. |
| `op_add` / `op_clone` / `op_delete` / `op_move` / `op_upd` | OPS timeline | operation identifiers emitted by `sig_cell` payloads. |
| `opm:states` | OPS timeline | operation mode indicating state-tracking semantics. |
| `org:<k>:*` | OPS timeline | organ enzyme names (`org:<k>:vl`, `org:<k>:ct`, `org:<k>:dt`) bound at organ roots. |
| `payload_id` | OPS timeline | optional `val/bytes` payload stored in envelopes and watcher entries. |
| `qos` | OPS timeline | control-plane QoS flags stored alongside paused impulses. |
| `role_parnt` / `role_source` / `role_subj` / `role_templ` | OPS timeline | role vocabulary consumed by mutation enzymes. |
| `sig_cell` | OPS timeline | signal namespace for kernel cell operations. |
| `sig_cei/*` | OPS timeline | error-channel signals dispatched by CEI helper emissions and consumed by bound enzymes. |
| `state` | OPS timeline | current logical state (`ist:*`) stored on an operation root. |
| `status` | OPS timeline | terminal status (`sts:*`) recorded under `/close/status`. |
| `sts:cnl` | OPS timeline | cancellation status recorded when an operation is aborted. |
| `sts:fail` | OPS timeline | failure status recorded when an operation terminates unsuccessfully. |
| `sts:ok` | OPS timeline | success status recorded when an operation completes normally. |
| `summary_id` | OPS timeline | optional summary payload identifier stored under `/close/summary_id`. |
| `ttl` | OPS timeline | watcher expiry interval in beats. |
| `watchers` | OPS timeline | dictionary tracking pending awaiters. |
| `want` | OPS timeline | requested state or status captured for a watcher. |
| `closed_beat` | OPS timeline | beat index recorded when the `/close/` branch was sealed. |

#### Episode Engine Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `op/ep` | E³ (Episodic Enzyme Engine) | operation verb assigned to episodic dossiers tracked under `/rt/ops/<eid>`. |
| `ep/cont` | E³ (Episodic Enzyme Engine) | continuation signal emitted when an episode should resume on the next beat. |
| `ist:yield` | E³ (Episodic Enzyme Engine) | state recorded when an episode voluntarily yields the current slice. |
| `ist:await` | E³ (Episodic Enzyme Engine) | state recorded while an episode is waiting on an external operation. |
| `ist:cxl` | E³ (Episodic Enzyme Engine) | intermediate cancellation state published before closing with `sts:cnl`. |
| `ep:pro/ro` | E³ (Episodic Enzyme Engine) | metadata marker indicating a read-only episode profile. |
| `ep:pro/rw` | E³ (Episodic Enzyme Engine) | metadata marker indicating a read-write episode profile. |
| `ep:bud/io` | E³ (Episodic Enzyme Engine) | CEI topic emitted when an episode exceeds its configured I/O budget. |
| `ep:bud/cpu` | E³ (Episodic Enzyme Engine) | CEI topic emitted when an episode exceeds its configured CPU budget. |
| `episode` | E³ (Episodic Enzyme Engine) | metadata dictionary under an `op/ep` branch capturing policy and paths. |
| `bud_cpu_ns` | E³ (Episodic Enzyme Engine) | metadata field storing the per-slice CPU budget in nanoseconds. |
| `bud_io_by` | E³ (Episodic Enzyme Engine) | metadata field storing the per-slice I/O budget in bytes. |
| `sig_path` | E³ (Episodic Enzyme Engine) | metadata field recording the signal path used to dispatch the episode. |
| `tgt_path` | E³ (Episodic Enzyme Engine) | metadata field recording the target path resumed by continuations. |
| `max_beats` | E³ (Episodic Enzyme Engine) | metadata field constraining how many slices an episode may execute. |

#### I/O Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `library` | Serialization/IO | metadata tag describing proxied library payloads. |
| `stdio_res` / `stdio_str` | Serialization/IO | stdio-backed stream resource and descriptor nodes. |
| `zip_entry` / `zip_stream` | Serialization/IO | libzip-backed resource and stream adapters. |

#### Federation Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `net` | Federation transport | root dictionary for federation metadata (peers, mounts, transports). |
| `mounts` | Federation transport | groups mount declarations by peer and mode under `/net/mounts`. |
| `peers` | Federation transport | peer registry keyed by peer identifier; hosts services and CEI health. |
| `catalog` | Federation transport | per-mode mount catalog generated during bootstrap under `/net/catalog`. |
| `transports` | Federation transport | registry of transport providers keyed by provider ID. |
| `transport` | Federation transport | per-mount dictionary recording the chosen provider and capability summary. |
| `caps` | Federation transport | nested dictionary capturing capability bitmaps (required, preferred, or provider-specific). |
| `cap_crc32c` | Federation transport | provider capability flag indicating CRC32C checksum support. |
| `cap_deflate` | Federation transport | provider capability flag indicating deflate frame compression support. |
| `cap_aead` | Federation transport | provider capability flag indicating AEAD payload encryption support. |
| `cap_cmpver` | Federation transport | provider capability flag signalling comparator-version awareness. |
| `prov_caps` | Federation transport | mirrors the selected provider capability bitset for the active mount. |
| `provider` | Federation transport | stores the provider identifier associated with a mount record. |
| `upd_latest` | Federation transport | boolean flag indicating a mount opts into droppable gauge frames. |
| `src_peer` | Federation transport | mirror organ request field naming the remote peer supplying bundles. |
| `src_chan` | Federation transport | mirror organ request field naming the remote channel supplying bundles. |
| `max_infl` | Federation transport | mirror organ bundle parameter limiting simultaneous in-flight bundles. |
| `resume_tok` | Federation transport | mirror organ optional token handed to callers to resume paused mirrors. |
| `pend_resum` | Federation transport | mirror organ status field publishing the pending resume token when manual commits pause work. |
| `serializer` | Federation transport | optional mirror organ dictionary constraining flat serializer features. |
| `crc32c_ok` | Federation transport | serializer policy flag that permits CRC32C emission on a mirror mount. |
| `deflate_ok` | Federation transport | serializer policy flag that permits deflate compression on a mirror mount. |
| `aead_ok` | Federation transport | serializer policy flag that permits AEAD encryption on a mirror mount. |
| `warn_down` | Federation transport | serializer policy flag enabling/disabling CEI when downgrading features. |
| `cmp_max_ver` | Federation transport | serializer policy field limiting comparator versions emitted for a mirror mount. |
| `bundle_seq` | Federation transport | mirror organ status field recording the last committed bundle sequence. |
| `commit_beat` | Federation transport | mirror organ status field recording the beat of the most recent commit. |
| `tp_inv_timeout` | Federation transport | CEI topic emitted when a remote invocation exceeds its beat budget. |
| `tp_inv_reject` | Federation transport | CEI topic emitted when the remote peer rejects an invocation request. |
| `services` | Federation transport | peer-level dictionary listing advertised services/mounts. |
| `telemetry` | Federation transport | heartbeat-sampled metrics root under `/net/telemetry`. |
| `ceh` | Federation transport | consolidated CEI health facts per peer keyed by telemetry topic. |
| `net_discovery` | Federation transport | discovery organ slug registered by the federation pack. |
| `net_health` | Federation transport | health organ slug registered by the federation pack. |
| `bp_count` | Federation transport | telemetry counter tracking total backpressure events for a mount. |
| `bp_flag` | Federation transport | boolean flag indicating the mount is currently backpressured. |
| `last_mode` | Federation transport | telemetry field recording the last transmitted frame mode. |
| `last_sample` | Federation transport | telemetry field recording the first byte of the last transmitted frame. |
| `tp_backpr` | Federation transport | CEI topic and health key for backpressure notifications. |
| `tp_catsync` | Federation transport | CEI topic for catalog/telemetry publication failures. |
| `tp_fatal` | Federation transport | CEI topic recording fatal transport channel events. |
| `tp_noprov` | Federation transport | CEI topic recorded when no provider satisfies mount requirements. |
| `tp_openfail` | Federation transport | CEI topic emitted when provider channel negotiation fails. |
| `tp_provcell` | Federation transport | CEI topic noting provider cell resolution failures. |
| `tp_provid` | Federation transport | CEI topic emitted when provider identifiers cannot be encoded. |
| `tp_schema` | Federation transport | CEI topic indicating the mount schema branch could not be ensured. |
| `tp_schemup` | Federation transport | CEI topic signalling mount schema update failures. |
| `tp_sendfail` | Federation transport | CEI topic emitted when a provider send operation fails. |
| `tp_upd_den` | Federation transport | CEI topic capturing rejected `upd_latest` frames (mount opted out). |
| `tp_upd_mis` | Federation transport | CEI topic capturing `upd_latest` frames sent to non-unreliable transports. |
| `tp_flatneg` | Federation transport | CEI topic emitted when the sender downgrades CRC32C/deflate/AEAD for a mount. |
| `tp_mconf` | Federation transport | CEI topic emitted when a mirror organ request conflicts with an existing mount. |
| `tp_mtimeout` | Federation transport | CEI topic emitted when a mirror organ request exceeds its deadline. |

#### Test Harness Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
| `catalog` | Test harness | storage fixture exercising catalog/indexed semantics. |
| `cmp_root` | Test harness | comparison root used by traversal and enzyme tests. |
| `dict` | Test harness | shorthand tag used by dynamic dictionary fixtures. |
| `domain` | Test harness | domain/tag packing validation tag. |
| `hash` | Test harness | storage fixture for hash-indexed tables. |
| `hyb_field` | Test harness | hybrid integration POC field mutated during promote/demote coverage. |
| `hyb_fin` | Test harness | hybrid episode test tag confirming RO guard after demotion. |
| `hyb_mut` | Test harness | hybrid episode test tag recording the RW mutation slice. |
| `oct_root` / `oct_space` | Test harness | octree storage fixtures in randomized tests. |
| `pq_buffer` / `pq_root` | Test harness | packed-queue storage fixtures. |
| `poc` | Test harness | integration POC root covering the end-to-end heartbeat timeline scenario. |
| `poc_catalog` | Test harness | dictionary store standing in for the catalog branch during integration testing. |
| `poc_event` | Test harness | log entry payload tag used by the integration log/history assertions. |
| `poc_item` | Test harness | catalog value payload type exercised by the integration scenario. |
| `poc_link` | Test harness | scratch dictionary used to validate link/backlink semantics in the integration test. |
| `poc_log` | Test harness | list store tag backing the integration log branch. |
| `poc_stream_root` | Test harness | stream/proxy dictionary hosting the journalled stdio adapter in the integration test. |
| `poc_replay` | Test harness | replay root populated when verifying serialization round-trips. |
| `poc_txn` | Test harness | veiled transaction branch staged during the integration heartbeat timeline. |
| `space` | Test harness | octree dictionary mounted under `/data/poc` to exercise spatial store plumbing during integration. |
| `space_entry` | Test harness | deterministic point payload inserted into the spatial store to validate octree comparisons. |
| `rand_entry_*` | Test harness | seeded log entries appended during randomized mutation passes to ensure logging remains deterministic. |
| `prr_pause` | Test harness | backlog dictionary that records retained impulses while pause/rollback is exercised. |
| `enz:poc_idx` / `enz:poc_agg` | Test harness | ordered enzyme pair asserting catalog reindex sequencing. |
| `enz:poc_rand` | Test harness | deterministic random enzyme descriptor feeding seeded impulse bursts. |
| `sig:poc/prr` | Test harness | integration heartbeat signal that exercises pause/rollback sequencing. |
| `org:poc:*` | Test harness | integration organ descriptor signals (`org:poc:val`, `org:poc:ctor`, `org:poc:dtor`). |
| `org:fixture:*` | Test harness | OVH (Organ Validation Harness) fixture signals exercising constructor/destructor/validator dossiers. |
| `sig_apply` `sig_beta` `sig_broad` `sig_cycle` `sig_dedup` `sig_dup` `sig_empty` `sig_expect` `sig_gamma` `sig_hb` `sig_img` `sig_mask` `sig_match` `sig_nop` `sig_rand` `sig_root` `sig_rty` `sig_skip` `sig_thumb` `sig_tree` | Test harness | assorted signal tags exercised by scheduler and heartbeat tests. |
| `sys_child` / `sys_root` | Test harness | synthetic system fixtures in randomized tests. |
| `test_enz_*` (`test_enz_a`, `test_enz_b`, `test_enz_c`, `test_enz_d`, `test_enz_da`, `test_enz_e`, `test_enz_le`, `test_enz_ro`) | Test harness | enzyme dependency graphs in unit tests. |
| `test_ez_*` (`test_ez_bc`, `test_ez_bd`, `test_ez_da`, `test_ez_du`, `test_ez_er`, `test_ez_ge`, `test_ez_la`, `test_ez_le`, `test_ez_li`, `test_ez_ma`, `test_ez_mi`, `test_ez_no`, `test_ez_p1`, `test_ez_p2`, `test_ez_p3`, `test_ez_pl`, `test_ez_ro`, `test_ez_si`, `test_ez_sig`, `test_ez_sp`, `test_ez_sr`, `test_ez_st`, `test_ez_wl`) | Test harness | synthetic descriptor names used by dispatch tests. |
| `test_hb_*` (`test_hb_a`, `test_hb_b`, `test_hb_cn`, `test_hb_r`, `test_hb_rt`) | Test harness | heartbeat test hooks. |
| `test_img_*` (`test_img_ch`, `test_img_vi`) | Test harness | image stream fixtures in serialization tests. |
| `test_lck_*` (`test_lck_ch`, `test_lck_in`) | Test harness | lock hierarchy fixtures. |
| `tst_enz*` (`tst_enza`, `tst_enzb`, `tst_enzc`, `tst_enzi`, `tst_enzj`, `tst_enzk`, `tst_enzl`, `tst_enzm`, `tst_enzo`, `tst_enzp`, `tst_enzq`, `tst_enzr`) | Test harness | randomized enzyme descriptors used by registry fuzz tests. |
| `tst_*` (`tst_a`, `tst_b`, `tst_branch`, `tst_child`, `tst_chld`, `tst_clone`, `tst_data`, `tst_dedup`, `tst_drop`, `tst_empty`, `tst_far`, `tst_head`, `tst_keep_a`, `tst_keep_b`, `tst_leaf`, `tst_list`, `tst_mask`, `tst_mid`, `tst_nop`, `tst_path`, `tst_remove`, `tst_root`, `tst_sig`, `tst_stor`, `tst_tree`, `tst_update`, `tst_val`, `tst_value`) | Test harness | generic test scaffolding tags. |
| `raw_all_sib` | Test harness | veiled sibling fixture used by raw traversal helper tests. |
| `value` | Test harness | generic payload tag for value-type fixtures. |
| `var_leaf` | Test harness | variant selection fixture in unit tests. |

#### Reserved Upper-Layer Tags
| Tag / Pattern | Feature Area | Purpose |
| --- | --- | --- |
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
