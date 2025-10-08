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
| `env` | core | runtime environment subtree for external handles. |
| `enzymes` | core | registry dictionary exposing registered enzymes. |
| `inbox` | core | captured impulses queued for the current beat. |
| `sig_sys` | core | System-level signal namespace emitted during lifecycle hooks. |
| `init` | core | System init signal tag that bootstraps higher layers. |
| `shutdown` | core | System shutdown signal tag emitted before teardown. |
| `mr_route` | ops | routing enzyme that moves unified inbox entries into layer inboxes. |
| `mr_init` | ops | Mailroom bootstrap enzyme bound to the system init signal. |
| `intent` | core | journal entry describing requested work. |
| `journal` | core | append-only heartbeat evidence ledger. |
| `lib` | core | library snapshot directory for proxied streams. |
| `list` | core | store tag for linked-list containers. |
| `log` | core | log entry tag attached to beat records. |
| `meta` | core | metadata dictionary attached to runtime cells. |
| `original` | core | dictionary storing pre-canonical text submitted alongside helper-built intents. |
| `namepool` | core | identifier intern table. |
| `outcome` | core | execution result record written after enzymes run. |
| `target` | core | canonical link entry used by helper-built facet dictionaries. |
| `parent` | core | provenance pointer stored inside `meta/parents`. |
| `parents` | core | provenance list capturing the source lineage. |
| `rt` | core | runtime staging root holding beat journals. |
| `stage` | core | per-beat stage log recording committed mutations. |
| `stream-log` | core | runtime log for stream adapters. |
| `sys_log` | core | journal list recording system init/shutdown signal emissions. |
| `sys` | core | system namespace with counters and configuration. |
| `err_cat` | core | dictionary of canonical error codes referenced by outcomes. |
| `text` | core | namepool payload store for textual data. |
| `tmp` | core | scratch list reserved for tooling. |

#### Layer 1 Coherence Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `coh` | core | L1 coherence root under `/data`. |
| `being` | core | ledger entry for beings. |
| `bond` | core | ledger entry for bonds. |
| `context` | core | ledger entry for contexts. |
| `facet` | core | global facet mirror keyed by `ctxId:facet`. |
| `attrs` | core | attribute dictionary reserved for beings or context extras. |
| `index` | core | dictionary of durable secondary indexes. |
| `debt` | core | placeholder bucket for closure debts. |
| `decision` | core | ledger of recorded tie-break decisions for replay. |
| `inbox` | core | intent inbox for coherence enzymes. |
| `be_kind` | core | index mapping kind -> beings. |
| `bo_pair` | core | index mapping `{src,dst,type,dir}` -> bond. |
| `ctx_type` | core | index mapping type -> contexts. |
| `fa_ctx` | core | index mapping context -> facet list. |
| `be_create` | ops | intent envelope for being creation. |
| `bo_upsert` | ops | intent envelope for bond upsert. |
| `ctx_upsert` | ops | intent envelope for context upsert. |
| `coh_ing_be` | ops | enzyme descriptor for being ingestion. |
| `coh_ing_bo` | ops | enzyme descriptor for bond ingestion. |
| `coh_ing_ctx` | ops | enzyme descriptor for context ingestion. |
| `coh_closure` | ops | enzyme descriptor for facet closure. |
| `coh_index` | ops | enzyme descriptor for coherence indexes. |
| `coh_adj` | ops | enzyme descriptor for adjacency refresh. |
| `coh_init` | ops | Coherence bootstrap enzyme triggered during init. |
| `out_bonds` | core | adjacency list of outgoing bonds per being. |
| `in_bonds` | core | adjacency list of inbound bonds per being. |
| `ctx_by_role` | core | adjacency bucket of contexts grouped by role. |

#### Operational Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `arg_deep` / `arg_pos` / `arg_prepend` | ops | parameters accepted by cell-operation enzymes. |
| `enz_add` / `enz_cln` / `enz_del` / `enz_mov` / `enz_upd` | ops | canonical enzyme descriptors registered at bootstrap. |
| `op_add` / `op_clone` / `op_delete` / `op_move` / `op_upd` | ops | operation identifiers emitted by `sig_cell` payloads. |
| `role_parnt` / `role_source` / `role_subj` / `role_templ` | ops | role vocabulary consumed by mutation enzymes. |
| `sig_cell` | ops | signal namespace for kernel cell operations. |

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
| `sig_apply` `sig_beta` `sig_broad` `sig_cycle` `sig_dedup` `sig_dup` `sig_empty` `sig_expect` `sig_gamma` `sig_hb` `sig_img` `sig_mask` `sig_match` `sig_nop` `sig_rand` `sig_root` `sig_rty` `sig_skip` `sig_thumb` `sig_tree` | test | assorted signal tags exercised by scheduler and heartbeat tests. |
| `sys_child` / `sys_root` | test | synthetic system fixtures in randomized tests. |
| `test_enz_*` (`test_enz_a`, `test_enz_b`, `test_enz_c`, `test_enz_d`, `test_enz_da`, `test_enz_e`, `test_enz_le`, `test_enz_ro`) | test | enzyme dependency graphs in unit tests. |
| `test_ez_*` (`test_ez_bc`, `test_ez_bd`, `test_ez_da`, `test_ez_du`, `test_ez_er`, `test_ez_ge`, `test_ez_la`, `test_ez_le`, `test_ez_li`, `test_ez_ma`, `test_ez_mi`, `test_ez_no`, `test_ez_p1`, `test_ez_p2`, `test_ez_p3`, `test_ez_pl`, `test_ez_ro`, `test_ez_si`, `test_ez_sig`, `test_ez_sp`, `test_ez_sr`, `test_ez_st`, `test_ez_wl`) | test | synthetic descriptor names used by dispatch tests. |
| `test_hb_*` (`test_hb_a`, `test_hb_b`, `test_hb_cn`, `test_hb_r`, `test_hb_rt`) | test | heartbeat test hooks. |
| `test_img_*` (`test_img_ch`, `test_img_vi`) | test | image stream fixtures in serialization tests. |
| `test_lck_*` (`test_lck_ch`, `test_lck_in`) | test | lock hierarchy fixtures. |
| `tst_enz*` (`tst_enza`, `tst_enzb`, `tst_enzc`, `tst_enzi`, `tst_enzj`, `tst_enzk`, `tst_enzl`, `tst_enzm`, `tst_enzo`, `tst_enzp`, `tst_enzq`, `tst_enzr`) | test | randomized enzyme descriptors used by registry fuzz tests. |
| `tst_*` (`tst_a`, `tst_b`, `tst_branch`, `tst_child`, `tst_chld`, `tst_clone`, `tst_data`, `tst_dedup`, `tst_drop`, `tst_empty`, `tst_far`, `tst_head`, `tst_keep_a`, `tst_keep_b`, `tst_leaf`, `tst_list`, `tst_mask`, `tst_mid`, `tst_nop`, `tst_path`, `tst_remove`, `tst_root`, `tst_sig`, `tst_stor`, `tst_tree`, `tst_update`, `tst_val`, `tst_value`) | test | generic test scaffolding tags. |
| `value` | test | generic payload tag for value-type fixtures. |
| `var_leaf` | test | variant selection fixture in unit tests. |

#### Layer 2 Flow VM Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `flow` | core | L2 flow root created under `/data`. |
| `program` | core | ledger storing compiled flow programs. |
| `policy` | core | ledger of decision policies used by flows. |
| `variant` | core | compiled flow variants linked to programs. |
| `niche` | core | routing maps that bind contexts to variants. |
| `guardian` | core | declarative invariant rules enforced by flows. |
| `instance` | core | runtime instances tracking VM state. |
| `decision` | core | immutable decision cells recorded for replay. |
| `dec_archive` | core | archival ledger for decisions retained past their TTL. |
| `index` | core | durable indexes mirroring flow lookups. |
| `inbox` | core | intent ingress namespace for L2. |
| `adj` | core | transient adjacency/cache namespace under `/tmp`. |
| `fl_upsert` | ops | intent envelope for program/policy/variant/guardian upserts. |
| `ni_upsert` | ops | intent envelope for niche updates. |
| `inst_start` | ops | intent envelope for starting flow instances. |
| `inst_event` | ops | intent envelope for external instance events. |
| `inst_ctrl` | ops | intent envelope for instance control actions. |
| `fl_ing` | ops | enzyme descriptor for ingesting flow definitions. |
| `ni_ing` | ops | enzyme descriptor for ingesting niche intents. |
| `inst_ing` | ops | enzyme descriptor for ingesting instance intents. |
| `fl_wake` | ops | enzyme descriptor for correlating events to waits. |
| `fl_step` | ops | enzyme descriptor for executing VM steps. |
| `fl_index` | ops | enzyme descriptor for rebuilding L2 indexes. |
| `fl_adj` | ops | enzyme descriptor for refreshing transient caches. |
| `fl_init` | ops | Flow bootstrap enzyme triggered during system init. |
| `fl_*` (`fl_ing`, `fl_wake`, `fl_step`, `fl_index`, `fl_adj`, `fl_upsert`) | ops | reserved prefix for flow enzymes/intents. |
| `inst_*` (`inst_ing`, `inst_start`, `inst_event`, `inst_ctrl`) | ops | reserved prefix for flow instance enzymes/intents. |
| `ni_*` (`ni_ing`, `ni_upsert`) | ops | reserved prefix for niche enzymes/intents. |
| `steps` | core | ordered list of program steps persisted under each flow definition. |
| `step` | core | container dictionary describing a single program step. |
| `spec` | core | nested dictionary carrying per-step parameters. |
| `state` | core | lifecycle flag recorded on flow instances. |
| `pc` | core | program counter stored with each instance. |
| `subs` | core | dictionary of active wait subscriptions per instance. |
| `events` | core | queued external events awaiting consumption by the VM. |
| `event` | core | link reference from wait entries to a captured event record. |
| `emits` | core | staged transform outputs stored per instance before commit. |
| `budget` | core | per-instance clamp state capturing execution ceilings. |
| `site` | core | identifier for a decision site inside a flow. |
| `action` | core | control action requested against an instance. |
| `inst_id` | core | identifier field referencing an existing instance. |
| `signal_path` | core | signal matcher stored on wait subscriptions and events. |
| `signal` | core | general-purpose signal identifier metadata. |
| `status` | core | lifecycle marker used by flow subscriptions and caches. |
| `payload` | core | dictionary carrying captured event payloads. |
| `evidence` | core | supporting facts recorded alongside a decision entry. |
| `validation` | core | replay guard metadata stored for decision verification. |
| `telemetry` | core | dictionary capturing per-decision evaluation metrics. |
| `fingerprint` | core | deterministic replay key stored under `validation`. |
| `retain` | core | retention directive for decision ledger entries. |
| `retain_mode` | core | canonical retention mode (`permanent`, `ttl`, `archive`). |
| `retain_ttl` | core | retention window expressed in beats. |
| `retain_upto` | core | beat when the decision expires under TTL enforcement. |
| `history` | core | append-only timeline recorded for event lifecycle tracking. |
| `choice` | core | decision choice recorded for replay. |
| `step_limit` | core | maximum steps permitted inside the current clamp window. |
| `steps_used` | core | running count of steps consumed during the active window. |
| `inst_by_var` | core | index bucket listing instances grouped by variant. |
| `inst_by_st` | core | index bucket listing instances grouped by state. |
| `dec_by_pol` | core | index bucket listing decisions grouped by policy. |
| `by_inst` | core | transient cache containing per-instance summaries. |
| `sub_count` | core | summary counter of active subscriptions. |
| `evt_count` | core | summary counter of queued events. |
| `emit_count` | core | summary counter of staged transform outputs. |
| `dec_count` | core | summary counter of decisions aggregated per policy. |
| `inst_count` | core | summary counter of instances grouped under a policy. |
| `site_count` | core | summary counter of decision sites keyed under a policy. |
| `latency` | core | heartbeat latency metric stored on adjacency summaries. |
| `lat_window` | core | rolling latency window maintained on adjacency summaries. |
| `err_window` | core | rolling error window maintained on policy and adjacency summaries. |
| `score` | core | recorded policy evaluation score for a decision. |
| `confidence` | core | recorded confidence level for a decision outcome. |
| `rng_seed` | core | deterministic seed used when sampling policy decisions. |
| `rng_seq` | core | deterministic sequence number associated with policy RNG state. |
| `error_flag` | core | boolean marker noting whether a decision ended in an error state. |
| `timeout` | core | wait specification field expressing timeout in beats. |
| `deadline` | core | recorded beat when a wait will time out. |
| `signal_glob` | core | glob pattern stored alongside wait subscriptions. |
| `beat` | core | heartbeat counter attached to events or waits. |
| `origin` | core | marker describing whether an event was targeted or broadcast. |

#### Rendezvous Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `rv` | core | Rendezvous ledger root stored under `/data`. |
| `rendezvous` | core | Transform spec dictionary describing rendezvous spawn parameters. |
| `prof` | core | Rendezvous profile identifier captured on ledger entries. |
| `spawn_beat` | core | Beat when a rendezvous job was created. |
| `due` | core | Beat when the rendezvous is due. |
| `due_off` | core | Relative due offset expressed in beats. |
| `deadline` | core | Hard beat deadline recorded on ledger entries. |
| `deadl_off` | core | Deadline offset applied relative to the due beat. |
| `ready_beat` | core | Beat when a rendezvous entered the ready state. |
| `applied_bt` | core | Beat when a rendezvous outcome was applied. |
| `epoch_k` | core | Rendezvous cadence interval for periodic jobs. |
| `input_fp` | core | Fingerprint of rendezvous inputs and code. |
| `cas_hash` | core | Content-addressed hash for rendezvous payloads staged in CAS. |
| `state` | core | Current rendezvous state (`pending`, `ready`, etc.). |
| `on_miss` | core | Policy captured for rendezvous misses. |
| `grace_delta` | core | Beat delta applied when extending a rendezvous via grace. |
| `grace_used` | core | Number of grace extensions already consumed. |
| `max_grace` | core | Maximum number of grace extensions allowed. |
| `kill_mode` | core | Kill policy recorded for rendezvous cancellation. |
| `kill_wait` | core | Beats to wait before enforcing a kill request. |
| `signal_path` | core | Rendezvous signal path used to wake waiting instances. |
| `telemetry` | core | Telemetry dictionary copied from rendezvous workers. |
| `defaults` | core | Profile-specific fallback parameters attached to rendezvous specs. |
| `rv_init` | ops | Rendezvous bootstrap enzyme triggered during system init. |

#### PoC Harness Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `poc` | core | PoC sandbox root nested under `/data`. |
| `io` | core | PoC I/O ledger namespace (`/data/poc/io`). |
| `hz` | core | Harness ledger namespace (`/data/poc/hz`). |
| `echo` | core | Echo ledger storing submitted text payloads. |
| `calc` | core | Calculator ledger storing expressions and results. |
| `kv` | core | Key/value ledger recording durable entries. |
| `ans` | core | Key/value answer ledger for read responses. |
| `scenario` | core | Stored harness scenario definitions. |
| `run` | core | Harness run ledger capturing execution evidence. |
| `bandit` | core | Bandit telemetry nested under a run entry. |
| `choices` | core | List of arm selections recorded per bandit run. |
| `inputs` | core | Snapshot of referenced scenario inputs stored on run entries. |
| `params` | core | Run-specific parameters supplied alongside scenarios. |
| `actual` | core | Observed value captured by harness assertions. |
| `diff` | core | Structured mismatch details recorded by harness assertions. |
| `keys` | core | Index bucket listing active key/value entries. |
| `count` | core | Numeric counter stored on index or adjacency nodes. |
| `tomb` | core | Tombstone flag marking soft-deleted key/value entries. |
| `enabled` | core | Toggle under `/sys/poc` gating PoC enzyme execution. |
| `parent` | core | Provenance link tag used for audit bindings. |
| `summary` | core | Aggregated metrics dictionary written by index and adjacency passes. |
| `recent` | core | Transient list of most recent operations surfaced via adjacency. |
| `calc_expr` | core | Calculator index grouping results by canonicalised expression. |
| `kv_prefix` | core | Key/value index grouping active keys by prefix. |
| `kv_hist` | core | Key/value index summarising per-key write history. |
| `ids` | core | List storing identifier collections copied into index buckets. |
| `total` | core | Summary field capturing total submissions for a bucket. |
| `active` | core | Summary field counting active entities within a bucket. |
| `ok` | core | Summary counter tracking successful outcomes. |
| `fail` | core | Summary counter tracking failed outcomes. |
| `wait` | core | Summary counter tracking pending or unprocessed items. |
| `kset` | core | Summary bucket covering `poc_kv_set` intents. |
| `kget` | core | Summary bucket covering `poc_kv_get` intents. |
| `kdel` | core | Summary bucket covering `poc_kv_del` intents. |

| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `poc_echo` | ops | Intent bucket for PoC echo submissions. |
| `poc_calc` | ops | Intent bucket for calculator requests. |
| `poc_kv_set` | ops | Intent bucket for key/value set operations. |
| `poc_kv_get` | ops | Intent bucket for key/value reads. |
| `poc_kv_del` | ops | Intent bucket for key/value deletion requests. |
| `poc_scenario` | ops | Intent bucket for scenario authoring. |
| `poc_run` | ops | Intent bucket for scenario executions. |
| `poc_assert` | ops | Intent bucket for harness assertions. |
| `poc_bandit` | ops | Intent bucket for bandit experiments. |
| `poc_io_ing_echo` | ops | Enzyme descriptor for echo ingestion. |
| `poc_io_ing_calc` | ops | Enzyme descriptor for calculator ingestion. |
| `poc_io_ing_kv` | ops | Enzyme descriptor for key/value ingestion. |
| `poc_io_index` | ops | Enzyme descriptor refreshing PoC I/O indexes. |
| `poc_io_adj` | ops | Enzyme descriptor publishing PoC I/O adjacency summaries. |
| `poc_hz_ing_scenario` | ops | Harness enzyme ingesting scenarios. |
| `poc_hz_ing_run` | ops | Harness enzyme ingesting runs. |
| `poc_hz_ing_assert` | ops | Harness enzyme validating assertions. |
| `poc_hz_ing_bandit` | ops | Harness enzyme coordinating bandit executions. |
| `poc_hz_index` | ops | Harness index refresh enzyme. |
| `poc_hz_adj` | ops | Harness adjacency refresh enzyme. |

### Usage Notes
- Tags marked *ops* should only appear in impulse payloads and descriptor
  declarations. Emitting them outside the heartbeat dispatcher is undefined.
- Tags marked *test* are reserved for the unit-test harness; production code
  must not emit them.
- When you need a new tag, update this lexicon first. Keep within the length and
  character constraints to preserve compatibility with the packed `cepDT`
  encoding.

## Q&A
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
