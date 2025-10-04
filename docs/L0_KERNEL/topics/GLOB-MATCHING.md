# L0 Topic: Glob Matching in CEP

## Introduction
Globbing lets CEP reuse familiar "match anything" patterns when inspecting cell paths without turning every lookup into custom code. This guide explains how the `*` character behaves inside tag identifiers, what stays reserved for legacy domain wildcards, and how the runtime keeps those clues available for serialization, cloning, and replay.

## Technical Details
- Word and acronym tags may contain a literal `*` and still encode as `cepID` values; `cep_word_to_text` / `cep_text_to_word` and `cep_acronym_to_text` / `cep_text_to_acronym` translate the character using their packed alphabets (word tags rely on the dedicated `CEP_WORD_GLOB_SENTINEL`). Reference tags inherit glob awareness when you intern them through the pattern helpers provided by the namepool.
- When a word, acronym, or pattern-enabled reference includes `*`, helpers such as `cep_id_has_glob_char` flag the identifier as a glob. Builders produced via `cep_dt_make` or the `CEP_DTS` macros automatically set the `glob` bit inside `cepDT`, `cepMetacell`, `cepData`, and `cepStore` structures.
- Matching honours the glob bit on tag segments: `cep_id_matches` expands `*` as "match zero or more characters" for both word/acronym identifiers and reference patterns, and falls back to literal equality otherwise. Domain-level globs still rely on the `CEP_ID_GLOB_*` sentinels.
- Enzyme registries treat globbed tags as less specific than literal matches, ensuring deterministic priority when both candidate paths overlap.
- Serialization and replay preserve glob semantics. Each manifest segment and data descriptor carries a dedicated glob byte; readers restore the hint directly without recomputing from the identifier.
- Literal cell construction APIs reject globbed names; the wildcard syntax is reserved for query-time structures (enzyme patterns, lookups, traversal filters) rather than persistent node names.

## Q&A
- **Can I use `*` inside domains?** No. Domain segments still rely on the reserved sentinel IDs (`CEP_ID_GLOB_MULTI`, `CEP_ID_GLOB_STAR`, `CEP_ID_GLOB_QUESTION`) for wildcard behaviour.
- **Does `*` behave like UNIX globs or regex?** The implementation matches the classic single-segment glob: `*` consumes any number of characters within the tag; there is no implicit path separator handling or character classes.
- **Do I need to set the glob bit manually when building `cepDT` values?** No. Use `cep_dt_make` or the `CEP_DT*` convenience macros and the bit is derived from the tag automatically.
- **What happens if I try to name a cell with a globbed tag?** Cell constructors assert. Wildlife matching stays in query patterns so persisted timelines remain unambiguous.
- **How do I combine star patterns with historical traversal?** `cep_cell_path` records the glob bit alongside each segment, so downstream matchers such as `cep_cell_find_by_path_past` and enzyme registries can reuse that metadata during replay.
- **How do references become glob-aware?** Use `cep_namepool_intern_pattern*` to intern the string; the namepool records the hint so any `cepDT` carrying that reference automatically exposes the glob bit.
