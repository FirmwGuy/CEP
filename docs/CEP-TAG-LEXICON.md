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
- **Status column:** `core` tags ship in the runtime, `ops` feed signal/enzyme
  matching, `io` covers stream and library metadata, and `test` stays inside the
  unit-test harness.

### Tag Catalogue

#### Core Runtime Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `/` | core | root dictionary mounted during bootstrap. |
| `agenda` | core | per-beat agenda log recorded under `/rt/beat/<n>/agenda`. |
| `beat` | core | dictionary grouping heartbeat evidence for a specific beat. |
| `cas` | core | content-addressable storage subtree. |
| `data` | core | durable dataset root promoted at the end of a beat. |
| `dictionary` | core | canonical store tag for dictionary nodes. |
| `dtor` | core | spec field storing the optional organ destructor enzyme name. |
| `ctor` | core | spec field storing the optional organ constructor enzyme name. |
| `env` | core | runtime environment subtree for external handles. |
| `envelope` | core | sealed message metadata dictionary under a mailbox message. |
| `enzymes` | core | registry dictionary exposing registered enzymes. |
| `impulses` | core | beat impulse log recorded under `/rt/beat/<n>/impulses` (legacy `inbox` link retained for one release). |
| `analytics` | core | runtime analytics root under `/rt/analytics`. |
| `spacing` | core | beat-to-beat spacing metrics recorded by the heartbeat analytics helper. |
| `interval_ns` | core | nanosecond interval payload inside spacing analytics entries. |
| `issued_unix_ns` | core | unix timestamp captured alongside `issued_beat` inside a mailbox envelope. |
| `unix_ts_ns` | core | per-beat Unix timestamp stored under `/rt/beat/<n>/meta/unix_ts_ns` and mirrored into stage notes, OPS history, and stream journals. |
| `intent` | core | journal entry describing requested work. |
| `journal` | core | append-only heartbeat evidence ledger. |
| `kind` | core | short organ slug persisted under `/sys/organs/<k>/spec/kind`. |
| `lib` | core | library snapshot directory for proxied streams. |
| `list` | core | store tag for linked-list containers. |
| `log` | core | log entry tag attached to beat records. |
| `label` | core | optional human-readable organ description stored in the spec branch. |
| `meta` | core | metadata dictionary attached to runtime cells. |
| `msgs` | core | mailbox message dictionary keyed by local message ID. |
| `organ/<k>` | core | store tag pattern identifying typed organ root dictionaries. |
| `organ/sys_namepool` | core | store tag assigned to the `/sys/namepool` dictionary (bootstrap service, not an organ). |
| `organ/rt_beat` | core | store tag assigned to the `/rt/beat` organ root. |
| `organ/journal` | core | store tag assigned to the `/journal` organ root. |
| `organs` | core | system dictionary publishing immutable organ descriptors. |
| `txn` | core | transaction metadata bucket (`meta/txn`) tracking veiled staging state. |
| `boot_oid` | core | `val/bytes` cell under `/sys/state` publishing the boot operation OID. |
| `shdn_oid` | core | `val/bytes` cell under `/sys/state` publishing the shutdown operation OID. |
| `namepool` | core | identifier intern table. |
| `next_msg_id` | core | deterministic counter stored under `meta/runtime/next_msg_id`. |
| `outcome` | core | execution result record written after enzymes run. |
| `target` | core | canonical link entry used by helper-built facet dictionaries. |
| `parent` | core | provenance pointer stored inside `meta/parents`. |
| `parents` | core | provenance list capturing the source lineage. |
| `rt` | core | runtime staging root holding beat journals. |
| `runtime` | core | per-mailbox runtime metadata bucket (ID counters, expiry buckets). |
| `expiries` | core | beat-indexed expiry bucket dictionary under mailbox runtime metadata. |
| `exp_wall` | core | unix timestamp expiry bucket dictionary under mailbox runtime metadata. |
| `stage` | core | per-beat stage log recording committed mutations. |
| `spec` | core | immutable organ descriptor snapshot stored under `/sys/organs/<k>/spec`. |
| `store` | core | spec field recording the organ root store DT. |
| `stream-log` | core | runtime log for stream adapters. |
| `sys` | core | system namespace with counters and configuration. |
| `text` | core | namepool payload store for textual data. |
| `tmp` | core | scratch list reserved for tooling. |
| `ttl` | core | TTL dictionary attached to envelopes or mailbox policy nodes. |
| `ttl_beats` | core | relative TTL expressed in heartbeat counts. |
| `ttl_unix_ns` | core | relative TTL expressed in wallclock nanoseconds. |
| `ttl_mode` | core | TTL control flag (`"forever"` disables expiry at that scope). |
| `validator` | core | spec field storing the required organ validator enzyme name. |

#### Operational Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `arg_deep` / `arg_pos` / `arg_prepend` | ops | parameters accepted by cell-operation enzymes. |
| `armed` | ops | watcher flag indicating the continuation is queued for promotion at the next beat. |
| `close` | ops | sealed dictionary containing terminal status metadata for an operation. |
| `code` | ops | optional numeric code attached to a history entry or current state. |
| `cont` | ops | watcher continuation signal stored under `/watchers/<id>/cont`. |
| `deadline` | ops | watcher timeout beat stored under `/watchers/<id>/deadline`. |
| `envelope` | ops | immutable dictionary describing an operation's verb, target, mode, and issued beat. |
| `enz_add` / `enz_cln` / `enz_del` / `enz_mov` / `enz_upd` | ops | canonical enzyme descriptors registered at bootstrap. |
| `history` | ops | dictionary logging state transitions (`0001/`, `0002/`, …). |
| `issued_beat` | ops | beat index recorded in an operation envelope. |
| `ist:flush` | ops | shutdown operation state indicating buffered work is being flushed. |
| `ist:halt` | ops | shutdown operation state indicating the runtime is halting. |
| `ist:kernel` | ops | boot operation state marking kernel scaffolding completion. |
| `ist:ok` | ops | terminal state recorded after `cep_op_close()` maps the final status. |
| `ist:packs` | ops | boot operation state marking pack readiness. |
| `ist:stop` | ops | shutdown operation state marking teardown start. |
| `ist:store` | ops | boot operation state marking persistent stores ready. |
| `note` | ops | optional textual note attached to a history entry. |
| `op/boot` | ops | bootstrapping operation verb emitted at startup. |
| `op/cont` | ops | continuation signal emitted when an awaiter fires. |
| `op/ct` | ops | constructor operation verb routed to organ roots. |
| `op/dt` | ops | destructor operation verb routed to organ roots. |
| `op/shdn` | ops | shutdown operation verb emitted during teardown. |
| `op/tmo` | ops | timeout signal emitted when an awaiter expires. |
| `op/vl` | ops | validator operation verb that runs organ integrity checks. |
| `op_add` / `op_clone` / `op_delete` / `op_move` / `op_upd` | ops | operation identifiers emitted by `sig_cell` payloads. |
| `opm:states` | ops | operation mode indicating state-tracking semantics. |
| `org:<k>:*` | ops | organ enzyme names (`org:<k>:vl`, `org:<k>:ct`, `org:<k>:dt`) bound at organ roots. |
| `org:sys_namepool:*` | ops | namepool organ validator/constructor/destructor signals. |
| `org:rt_beat:*` | ops | beat ledger organ validator/constructor/destructor signals. |
| `org:journal:*` | ops | journal organ validator/constructor/destructor signals. |
| `payload_id` | ops | optional `val/bytes` payload stored in envelopes and watcher entries. |
| `role_parnt` / `role_source` / `role_subj` / `role_templ` | ops | role vocabulary consumed by mutation enzymes. |
| `sig_cell` | ops | signal namespace for kernel cell operations. |
| `sig_mail/arrive` | ops | mailbox arrival impulse emitted during beat capture. |
| `sig_mail/ack` | ops | mailbox acknowledgement impulse emitted when a subscriber reads or acknowledges a message. |
| `sig_mail/ttl` | ops | retention impulse emitted when a TTL deadline matures. |
| `sig_mail/route` | ops | optional routing impulse for fan-out or mirrors. |
| `state` | ops | current logical state (`ist:*`) stored on an operation root. |
| `status` | ops | terminal status (`sts:*`) recorded under `/close/status`. |
| `sts:cnl` | ops | cancellation status recorded when an operation is aborted. |
| `sts:fail` | ops | failure status recorded when an operation terminates unsuccessfully. |
| `sts:ok` | ops | success status recorded when an operation completes normally. |
| `summary_id` | ops | optional summary payload identifier stored under `/close/summary_id`. |
| `ttl` | ops | watcher expiry interval in beats. |
| `enz_mail_dispatch` | ops | enzyme descriptor handling `sig_mail/arrive`. |
| `enz_mail_ack` | ops | enzyme descriptor handling `sig_mail/ack`. |
| `enz_mail_retention` | ops | enzyme descriptor handling `sig_mail/ttl`. |
| `watchers` | ops | dictionary tracking pending awaiters. |
| `want` | ops | requested state or status captured for a watcher. |
| `closed_beat` | ops | beat index recorded when the `/close/` branch was sealed. |

#### I/O Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `library` | io | metadata tag describing proxied library payloads. |
| `stdio_res` / `stdio_str` | io | stdio-backed stream resource and descriptor nodes. |
| `zip_entry` / `zip_stream` | io | libzip-backed resource and stream adapters. |

#### Test Harness Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `catalog` | test | storage fixture exercising catalog/indexed semantics. |
| `cmp_root` | test | comparison root used by traversal and enzyme tests. |
| `dict` | test | shorthand tag used by dynamic dictionary fixtures. |
| `domain` | test | domain/tag packing validation tag. |
| `hash` | test | storage fixture for hash-indexed tables. |
| `lib_payld` | test | payload marker for library-backed stream tests. |
| `oct_root` / `oct_space` | test | octree storage fixtures in randomized tests. |
| `pq_buffer` / `pq_root` | test | packed-queue storage fixtures. |
| `ser_child` / `ser_dict` / `ser_root` | test | serialization fixtures validating tree walkers. |
| `org:fixture:*` | test | OVH (Organ Validation Harness) fixture signals exercising constructor/destructor/validator dossiers. |
| `sig_apply` `sig_beta` `sig_broad` `sig_cycle` `sig_dedup` `sig_dup` `sig_empty` `sig_expect` `sig_gamma` `sig_hb` `sig_img` `sig_mask` `sig_match` `sig_nop` `sig_rand` `sig_root` `sig_rty` `sig_skip` `sig_thumb` `sig_tree` | test | assorted signal tags exercised by scheduler and heartbeat tests. |
| `sys_child` / `sys_root` | test | synthetic system fixtures in randomized tests. |
| `test_enz_*` (`test_enz_a`, `test_enz_b`, `test_enz_c`, `test_enz_d`, `test_enz_da`, `test_enz_e`, `test_enz_le`, `test_enz_ro`) | test | enzyme dependency graphs in unit tests. |
| `test_ez_*` (`test_ez_bc`, `test_ez_bd`, `test_ez_da`, `test_ez_du`, `test_ez_er`, `test_ez_ge`, `test_ez_la`, `test_ez_le`, `test_ez_li`, `test_ez_ma`, `test_ez_mi`, `test_ez_no`, `test_ez_p1`, `test_ez_p2`, `test_ez_p3`, `test_ez_pl`, `test_ez_ro`, `test_ez_si`, `test_ez_sig`, `test_ez_sp`, `test_ez_sr`, `test_ez_st`, `test_ez_wl`) | test | synthetic descriptor names used by dispatch tests. |
| `test_hb_*` (`test_hb_a`, `test_hb_b`, `test_hb_cn`, `test_hb_r`, `test_hb_rt`) | test | heartbeat test hooks. |
| `test_img_*` (`test_img_ch`, `test_img_vi`) | test | image stream fixtures in serialization tests. |
| `test_lck_*` (`test_lck_ch`, `test_lck_in`) | test | lock hierarchy fixtures. |
| `tst_enz*` (`tst_enza`, `tst_enzb`, `tst_enzc`, `tst_enzi`, `tst_enzj`, `tst_enzk`, `tst_enzl`, `tst_enzm`, `tst_enzo`, `tst_enzp`, `tst_enzq`, `tst_enzr`) | test | randomized enzyme descriptors used by registry fuzz tests. |
| `tst_*` (`tst_a`, `tst_b`, `tst_branch`, `tst_child`, `tst_chld`, `tst_clone`, `tst_data`, `tst_dedup`, `tst_drop`, `tst_empty`, `tst_far`, `tst_head`, `tst_keep_a`, `tst_keep_b`, `tst_leaf`, `tst_list`, `tst_mask`, `tst_mid`, `tst_nop`, `tst_path`, `tst_remove`, `tst_root`, `tst_sig`, `tst_stor`, `tst_tree`, `tst_update`, `tst_val`, `tst_value`) | test | generic test scaffolding tags. |
| `raw_all_sib` | test | veiled sibling fixture used by raw traversal helper tests. |
| `value` | test | generic payload tag for value-type fixtures. |
| `var_leaf` | test | variant selection fixture in unit tests. |

#### Reserved Upper-Layer Tags
| Tag / Pattern | Status | Purpose |
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
