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
| `dictionary` | Runtime platform | canonical store tag for dictionary nodes. |
| `dtor` | Runtime platform | spec field storing the optional organ destructor enzyme name. |
| `ctor` | Runtime platform | spec field storing the optional organ constructor enzyme name. |
| `env` | Runtime platform | runtime environment subtree for external handles. |
| `envelope` | Runtime platform | sealed message metadata dictionary under a mailbox message. |
| `err` | Runtime platform | root dictionary encapsulating a structured Common Error Interface fact. |
| `enzymes` | Runtime platform | registry dictionary exposing registered enzymes. |
| `impulses` | Runtime platform | beat impulse log recorded under `/rt/beat/<n>/impulses` (legacy `inbox` link retained for one release). |
| `analytics` | Runtime platform | runtime analytics root under `/rt/analytics`. |
| `runtime_isolation` | Runtime platform | harness marker ensuring per-runtime storage separation during tests. |
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
| `organ/sys_namepool` | Runtime platform | store tag assigned to the `/sys/namepool` dictionary (bootstrap service, not an organ). |
| `organ/rt_beat` | Runtime platform | store tag assigned to the `/rt/beat` organ root. |
| `organ/journal` | Runtime platform | store tag assigned to the `/journal` organ root. |
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
| `ist:stop` | OPS timeline | shutdown operation state marking teardown start. |
| `ist:store` | OPS timeline | boot operation state marking persistent stores ready. |
| `note` | OPS timeline | optional textual note attached to a history entry. |
| `op/boot` | OPS timeline | bootstrapping operation verb emitted at startup. |
| `op/cont` | OPS timeline | continuation signal emitted when an awaiter fires. |
| `op/ct` | OPS timeline | constructor operation verb routed to organ roots. |
| `op/dt` | OPS timeline | destructor operation verb routed to organ roots. |
| `op/pause` | Pause/Rollback/Resume | pause control operation verb that gates the heartbeat agenda. |
| `op/resume` | Pause/Rollback/Resume | resume control operation verb that re-opens the agenda. |
| `op/rollback` | Pause/Rollback/Resume | rollback control operation verb that re-points the view horizon. |
| `op/shdn` | OPS timeline | shutdown operation verb emitted during teardown. |
| `op/tmo` | OPS timeline | timeout signal emitted when an awaiter expires. |
| `op/vl` | OPS timeline | validator operation verb that runs organ integrity checks. |
| `op_add` / `op_clone` / `op_delete` / `op_move` / `op_upd` | OPS timeline | operation identifiers emitted by `sig_cell` payloads. |
| `opm:states` | OPS timeline | operation mode indicating state-tracking semantics. |
| `org:<k>:*` | OPS timeline | organ enzyme names (`org:<k>:vl`, `org:<k>:ct`, `org:<k>:dt`) bound at organ roots. |
| `org:sys_namepool:*` | OPS timeline | namepool organ validator/constructor/destructor signals. |
| `org:rt_beat:*` | OPS timeline | beat ledger organ validator/constructor/destructor signals. |
| `org:journal:*` | OPS timeline | journal organ validator/constructor/destructor signals. |
| `payload_id` | OPS timeline | optional `val/bytes` payload stored in envelopes and watcher entries. |
| `qos` | OPS timeline | control-plane QoS flags stored alongside paused impulses. |
| `role_parnt` / `role_source` / `role_subj` / `role_templ` | OPS timeline | role vocabulary consumed by mutation enzymes. |
| `sig_cell` | OPS timeline | signal namespace for kernel cell operations. |
| `sig_mail/arrive` | OPS timeline | mailbox arrival impulse emitted during beat capture. |
| `sig_mail/ack` | OPS timeline | mailbox acknowledgement impulse emitted when a subscriber reads or acknowledges a message. |
| `sig_mail/ttl` | OPS timeline | retention impulse emitted when a TTL deadline matures. |
| `sig_mail/route` | OPS timeline | optional routing impulse for fan-out or mirrors. |
| `sig_cei/*` | OPS timeline | error-channel signals dispatched by CEI helper emissions and consumed by bound enzymes. |
| `state` | OPS timeline | current logical state (`ist:*`) stored on an operation root. |
| `status` | OPS timeline | terminal status (`sts:*`) recorded under `/close/status`. |
| `sts:cnl` | OPS timeline | cancellation status recorded when an operation is aborted. |
| `sts:fail` | OPS timeline | failure status recorded when an operation terminates unsuccessfully. |
| `sts:ok` | OPS timeline | success status recorded when an operation completes normally. |
| `summary_id` | OPS timeline | optional summary payload identifier stored under `/close/summary_id`. |
| `ttl` | OPS timeline | watcher expiry interval in beats. |
| `enz_mail_dispatch` | OPS timeline | enzyme descriptor handling `sig_mail/arrive`. |
| `enz_mail_ack` | OPS timeline | enzyme descriptor handling `sig_mail/ack`. |
| `enz_mail_retention` | OPS timeline | enzyme descriptor handling `sig_mail/ttl`. |
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
| `lib_payld` | Test harness | payload marker for library-backed stream tests. |
| `oct_root` / `oct_space` | Test harness | octree storage fixtures in randomized tests. |
| `pq_buffer` / `pq_root` | Test harness | packed-queue storage fixtures. |
| `ser_child` / `ser_dict` / `ser_root` | Test harness | serialization fixtures validating tree walkers. |
| `poc` | Test harness | integration POC root covering the end-to-end heartbeat timeline scenario. |
| `poc_catalog` | Test harness | dictionary store standing in for the catalog branch during integration testing. |
| `poc_event` | Test harness | log entry payload tag used by the integration log/history assertions. |
| `poc_item` | Test harness | catalog value payload type exercised by the integration scenario. |
| `poc_link` | Test harness | scratch dictionary used to validate link/backlink semantics in the integration test. |
| `poc_log` | Test harness | list store tag backing the integration log branch. |
| `poc_stream_root` | Test harness | stream/proxy dictionary hosting the journalled stdio adapter in the integration test. |
| `poc_replay` | Test harness | replay root populated when verifying serialization round-trips. |
| `poc_replay_store` | Test harness | dictionary store tag assigned to the replay subtree. |
| `poc_txn` | Test harness | veiled transaction branch staged during the integration heartbeat timeline. |
| `space` | Test harness | octree dictionary mounted under `/data/poc` to exercise spatial store plumbing during integration. |
| `space_entry` | Test harness | deterministic point payload inserted into the spatial store to validate octree comparisons. |
| `item_[a-e]` | Test harness | catalog payload value tags that track deterministic append-only history mutations in the integration scenario. |
| `rand_entry_*` | Test harness | seeded log entries appended during randomized mutation passes to ensure logging remains deterministic. |
| `prr_pause` | Test harness | backlog dictionary that records retained impulses while pause/rollback is exercised. |
| `enz:poc_idx` / `enz:poc_agg` | Test harness | ordered enzyme pair asserting catalog reindex sequencing. |
| `enz:poc_rand` | Test harness | deterministic random enzyme descriptor feeding seeded impulse bursts. |
| `sig:poc/reindex` / `sig:poc/prr` / `sig:poc/rand/*` | Test harness | signal namespace driven by the integration heartbeat timeline. |
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
