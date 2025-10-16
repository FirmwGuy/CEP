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
| `intent` | core | journal entry describing requested work. |
| `journal` | core | append-only heartbeat evidence ledger. |
| `lib` | core | library snapshot directory for proxied streams. |
| `list` | core | store tag for linked-list containers. |
| `log` | core | log entry tag attached to beat records. |
| `meta` | core | metadata dictionary attached to runtime cells. |
| `txn` | core | transaction metadata bucket (`meta/txn`) tracking veiled staging state. |
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
| `ready` | core | lifecycle readiness marker recorded under `/sys/state/<scope>`. |
| `teardown` | core | lifecycle teardown marker recorded under `/sys/state/<scope>`. |
| `ready_beat` | core | beat index captured when a scope emitted its ready signal. |
| `td_beat` | core | beat index captured when a scope entered teardown. |
| `text` | core | namepool payload store for textual data. |
| `tmp` | core | scratch list reserved for tooling. |
| `emit_kind` | core | CEI payload field identifying the emitter category. |
| `emit_label` | core | CEI payload field mirroring the descriptor label. |

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

#### Reserved Upper-Layer Tags
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `flow` | core | Reserved `/data/flow` root for future upper-layer packs that orchestrate long-running flows. The kernel keeps the tag so external tooling can prepare namespaces in advance. |
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
