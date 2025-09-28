# CEP Tag Lexicon

## Introduction
The CEP runtime now speaks with a single voice: every domain/tag pair exposed by
Layer 0 uses the `CEP` domain and a shared vocabulary of short tags. This
lexicon is the pocket dictionary for that vocabulary. It keeps engineers and
tools aligned, avoids improvised sigils or ad-hoc prefixes, and makes it obvious
when a new behaviour needs a fresh word before it lands in code.

## Technical Details
- **Domain:** fixed to the uppercase acronym `CEP` for all kernel-provided data.
- **Tags:** lowercase words up to 11 characters using `[a-z0-9:_-./]`. Longer or
  composite concepts are shortened in this table; scripts should not invent
  alternatives.
- **Patterns:** Several entries describe a whole family of tags (e.g.
  `sig_*`). Only the patterns listed here are valid; collisions must be resolved
  by extending the table first.
- **Status column:** `core` tags ship in the runtime, `ops` feed signal/enzyme
  matching, `io` covers stream and library metadata, and `test` stays inside the
  unit-test harness.

### Tag Catalogue
| Tag / Pattern | Status | Purpose |
| --- | --- | --- |
| `/` | core | root dictionary mounted during bootstrap. |
| `agenda` | core | heartbeat agenda ledger for resolved enzymes. |
| `beat` | core | heartbeat list storing per-beat runtime entries. |
| `cas` | core | content-addressable storage subtree. |
| `catalog` | core | cell stores using catalog/indexed semantics. |
| `cmp_root` | test | comparison fixtures in traversal/randomised tests. |
| `data` | core | durable dataset root under `/CEP/data`. |
| `dict` | core | shorthand tag used in dynamic dictionary construction tests. |
| `dictionary` | core | canonical store tag for dictionary nodes. |
| `domain` | test | validates domain/tag packing in namepool tests. |
| `env` | core | runtime environment subtree. |
| `enz_add` / `enz_cln` / `enz_del` / `enz_mov` / `enz_upd` | ops | descriptor identities for the cell operation enzymes. |
| `enzymes` | core | metadata dictionary exposing registered enzymes. |
| `hash` | core | hash-indexed store label. |
| `inbox` | core | heartbeat inbox log for queued impulses. |
| `intent` | core | journal entry describing signal intent. |
| `journal` | core | append-only journaling subtree. |
| `lib` | core | library mount point created during bootstrap. |
| `lib_payld` | io | payload marker for library-backed streams in tests. |
| `library` | core | library metadata tag for proxied payloads. |
| `list` | core | list-based store tag. |
| `log` | core | heartbeat log entry list. |
| `namepool` | core | backing catalog for identifier interning. |
| `oct_root` / `oct_space` | test | octree storage fixtures. |
| `op_add` / `op_clone` / `op_delete` / `op_move` / `op_upd` | ops | signal namespace for cell mutations. |
| `outcome` | core | heartbeat execution outcome records. |
| `pq_buffer` / `pq_root` | test | packed-queue testing fixtures. |
| `role_a` / `role_b` / `role_entry` / `role_parnt` / `role_source` / `role_subj` / `role_templ` | ops | shared vocabulary for multi-party roles in bonds/contexts. |
| `rt` | core | runtime staging subtree name. |
| `ser_child` / `ser_dict` / `ser_root` | io | serialization fixtures validating tree walkers. |
| `sig_cell` | ops | signal family for cell operations, previously `/sig/cell`. |
| `sig_apply` `sig_beta` `sig_broad` `sig_cycle` `sig_dedup` `sig_dup` `sig_empty` `sig_expect` `sig_gamma` `sig_hb` `sig_img` `sig_mask` `sig_match` `sig_nop` `sig_rand` `sig_root` `sig_rty` `sig_skip` `sig_thumb` `sig_tree` | ops | assorted signal tags used by scheduler and unit tests; see signal handling docs for behaviour. |
| `stage` | core | heartbeat stage ledger for committed work. |
| `stdio_res` / `stdio_str` | io | tags used by stdio-backed stream adapters. |
| `stream-log` | core | stream logging store under `/CEP/journal`. |
| `sys` | core | system namespace root. |
| `sys_child` / `sys_root` | test | system-level fixtures in randomized tests. |
| `temp` | core | temporary workspace directory under `/CEP/tmp`. |
| `text` | core | namepool textual payloads. |
| `tmp` | core | top-level temporary list root. |
| `value` | core | generic payload tag for value-type data nodes. |
| `var_leaf` | test | variant selection fixture in unit tests. |
| `zip_entry` / `zip_stream` | io | libzip-backed stream descriptors. |
| `bond_caned` | ops | canonical bond tag “CAN_EDIT” (borrowed by tests). |
| `arg_deep` / `arg_pos` / `arg_prepend` | ops | parameter dictionary tags for cell operation requests. |
| `test_enz_*` (`test_enz_a`, `test_enz_b`, `test_enz_c`, `test_enz_d`, `test_enz_da`, `test_enz_e`, `test_enz_le`, `test_enz_ro`) | test | enzyme dependency graphs in unit tests. |
| `test_ez_*` (`test_ez_bc`, `test_ez_bd`, … `test_ez_wl`) | test | synthetic descriptor names used by dispatch tests. |
| `test_hb_*` (`test_hb_a`, `test_hb_b`, `test_hb_cn`, `test_hb_r`, `test_hb_rt`) | test | heartbeat test hooks. |
| `test_img_*` (`test_img_ch`, `test_img_vi`) | test | image stream fixtures in serialization tests. |
| `test_lck_*` (`test_lck_ch`, `test_lck_in`) | test | lock hierarchy fixtures. |
| `tst_*` (`tst_branch`, `tst_child`, `tst_chld`, `tst_data`, `tst_dedup`, `tst_empty`, `tst_leaf`, `tst_mask`, `tst_nop`, `tst_root`, `tst_sig`, `tst_stor`, `tst_tree`, `tst_value`) | test | generic test scaffolding tags. |

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
- **Can application layers invent their own domains?** Yes—outside Layer 0 the
  lexicon is advisory. The contract here only governs CEP’s built-in runtime.
