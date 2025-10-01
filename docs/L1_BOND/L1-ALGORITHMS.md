# L1 Bond Layer: Algorithms Report

## Introduction
This report highlights the concrete routines that ship with Layer 1 today. Each section pinpoints the code, the problem it solves, and the behaviour you can rely on when wiring higher-level features.

## Technical Details
### Identity lookup (`cep_being_claim`)
**Goal** Keep being cards deterministic and append-only while letting callers refresh labels or metadata.

**How it works**
- Looks up `name` under `/data/CEP/CEP/L1/beings`. On a cache miss it creates a dictionary child tagged as `CEP:being`.
- Updates three well-known text fields when provided: `being_label`, `being_kind`, and `being_ext`.
- Replaces the existing `meta/` dictionary with a deep clone of the caller-supplied metadata cell so updates are atomic.

**Source** `src/l1_bond/cep_bond_being.c`

### Pair bond materialisation (`cep_bond_upsert`)
**Goal** Record pairwise relationships without duplicating entries and keep adjacency mirrors in sync.

**How it works**
- Validates that both role cells are direct children of the beings root.
- Hashes `(tag, role_a_tag, role_a_name, role_b_tag, role_b_name)` to produce the numeric key for `/bonds/<tag>/<hash>`.
- Ensures two role dictionaries exist, writes summary strings (`<tag_text>:<partner_identifier>`), and refreshes optional `bond_label`, `bond_note`, and metadata.
- Calls `cep_bond_annotate_adjacency` for each participant so `/bonds/adjacency/<being>/<hash>` mirrors the same summary value. Existing text is replaced in place when it changes.

**Source** `src/l1_bond/cep_bond_pair.c` (hashing helpers in `cep_bond_common.c`)

### Context + facet scheduling (`cep_context_upsert`)
**Goal** Capture N-ary relationships and guarantee that promised facets appear in the queue.

**How it works**
- Requires every role target to be a being. Hashes `(tag, role_tags[], role_names[])` to pick the context dictionary under `/contexts/<tag>/<hash>`.
- Writes one child per role with the participant identifier stored as a text payload, sets `ctx_label` when provided, and clones metadata.
- Mirrors adjacency summaries for every participant using the same `<tag_text>:<label>` format.
- For each facet tag, ensures a placeholder record exists at `/facets/<facet>/<hash>` with `facet_state=pending` and pushes an entry into `/bonds/facet_queue/<facet>/<hash>` with `value=<ctx_label>` and `queue_state=pending`.

**Source** `src/l1_bond/cep_bond_context.c`

### Facet dispatch (`cep_facet_register`, `cep_facet_dispatch`)
**Goal** Route queued facet work to deterministic callbacks.

**How it works**
- `cep_facet_register` stores `(facet_tag, source_context_tag, enzyme, policy)` in a growable array. Duplicate registrations return `CEP_L1_ERR_DUPLICATE`.
- `cep_facet_dispatch` finds the queue entry, resolves the context, looks up the registry entry, and calls the enzyme with synthetic paths that point at the queue node and facet record.
- The return code decides the outcome:
  - `CEP_ENZYME_SUCCESS` → facet record `facet_state=complete`, queue entry `queue_state=complete`, and the queue entry is removed on the next tick.
  - `CEP_ENZYME_RETRY` → both remain `pending` for the next pass.
  - `CEP_ENZYME_FATAL` or missing plugin → facet record gets `failed`, queue entry becomes `fatal` (`missing` when no plugin is registered).

**Source** `src/l1_bond/cep_bond_facet.c`

### Heartbeat maintenance (`cep_tick_l1`)
**Goal** Keep transient queues tidy and mirrors aligned with durable state at the end of each beat.

**How it works**
- Iterates every facet queue family, invokes `cep_facet_dispatch` per entry, removes entries whose `queue_state` toggled to `complete`, and drops empty facet families.
- Scans adjacency buckets, deleting empty entries or whole buckets whose owning being has been hard-finalised.
- Deletes empty folders under `/bonds/checkpoints` (no retry metadata is written yet, but the hook keeps the tree clean).

**Source** `src/l1_bond/cep_bond_tick.c`

## Q&A
- **Where are the exponential backoff and retry counters?** Not implemented yet. Queue entries only track the label and state string; higher layers can extend the structure once policies land.
- **Do facet policies influence dispatch?** The policy field is stored but unused. The callback’s return code is the only signal that affects queue state today.
- **How do I observe adjacency churn?** Mirrors are just dictionaries. Read them directly or layer a telemetry enzyme that inspects `/bonds/adjacency` after `cep_tick_l1` runs.
- **What keeps hashes stable?** Both bond and context helpers rely on `cep_hash_bytes` over deterministic `cepDT` values. As long as role tags and participant names stay the same, the key stays stable across runs.
