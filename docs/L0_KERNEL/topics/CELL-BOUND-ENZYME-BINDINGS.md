# L0 Topic: Cell-Bound Enzyme Bindings and Signal-Indexed Dispatch

## Introduction

Imagine putting a sticky note on a folder that says “run these helpers here.” Whenever anything in that folder changes, you look at the sticky notes on that folder (and its parent folders) to know which helpers should run. If the change also has a specific intent (a small tag like “thumbnail”), you only run the helpers that care about that intent. Helpers that use wildcards keep their own cabinet of sticky notes so they do not clutter every folder; when the system needs them, it looks inside that cabinet using the same rules people expect from filesystem globs.

## Technical Design

> The blueprint below captures the intended architecture. For the currently
> shipping behaviour, see the “Implementation Snapshot” section at the end of
> this note.

### Goal
- Trigger enzymes deterministically when facts (cells) change, while reducing per‑impulse dispatch cost and improving locality/auditability.

### Binding Semantics
- Literal paths: enzymes bound to concrete cell paths remain stored directly on the target cell and optionally inherit to descendants when marked propagate.
- Wildcard queries live in the registry: bindings themselves stay literal; glob semantics enter through signal queries (e.g., `CEP_ID_GLOB_MULTI`, word tags with `*`).
- Signal filters reuse the same glob-aware matching; the registry’s wildcard head list avoids having to enumerate every branch when the leading segment is a wildcard.
- Literal naming guidelines: bindings may contain `*`, so authors should use glob characters intentionally; history records the exact tag.
- Domains and tags: impulse cell paths resolve across both `cepData` and `cepStore` domains; bindings record the domain segment explicitly so literals attach to the correct list and wildcard nodes match the intended domain/tag combination.
- Append-only: binding and unbinding append records with the enzyme identity (`cepDT name`), flags, and registration stamp. Entries become visible on the next heartbeat; callers schedule bind/unbind work outside the active beat to preserve N→N+1 semantics.
- De-duplication: when the resolver gathers bindings it keeps the first occurrence of a name (most specific wins) and ignores duplicates.

### Signal Filter and Registry
- Registry continues to own descriptors (callback, before/after, match policy, flags).
- Signal indexing sorts descriptors by descriptor name and by the first concrete query segment; descriptors whose first segment is a wildcard sit in a wildcard head list scanned separately.
- Name lookup: maintain `name → [entries]` to materialize the best descriptor per enzyme name after literal/wildcard filtering.

### Matching Policy (Hybrid)
- Target present: an impulse gathers all literal bindings from the cell lineage. Future versions will union target wildcard matches once the trie lands. If a signal is also present, the dispatcher intersects against the signal matches.
- No target: signal-only/broadcast dispatch uses the signal index (literal buckets plus wildcard head list) to gather candidates.
- Policy roadmap: the dispatcher currently applies TARGET_THEN_SIGNAL; alternate combinations (OR, TARGET_ONLY, SIGNAL_ONLY, STRICT_BOTH) remain on the backlog.

### Data Structures
- Cell side (literal bindings):
  - Each `cepStore` / `cepData` holds an in-memory singly linked list of literal bindings.
  - Node layout: `name` (enzyme identity), `flags` (tombstone + propagate bits), `next` pointer, and `modified` heartbeat.
  - Precedence: when both store and data exist, the data enzyme list has precedence.
  - Resolve semantics: the target cell contributes all non-tombstoned entries; ancestors contribute only entries with the propagate flag set.
  - Runtime append-only trail: bind/unbind operations append nodes and stamp `modified` with `cep_cell_timestamp_next()`.
- Wildcard registry (signal side):
  - Literal descriptors are bucketed by the first concrete segment; descriptors whose head segment is a wildcard sit in a separate wildcard list.
  - `cepID` segments are canonicalised: literal children cache the namepool `cepID` for the exact segment, domain-wide globs still use the reserved `CEP_ID_GLOB_*` sentinels or the wildcard bit on word tags.
  - Traversal metadata precomputes segment matchers so resolve-time checks avoid repeated parsing.
- Inheritance masking:
  - A tombstone appended on a child masks inherited literal bindings with the same name, while remaining in the append-only chain for audit history. Wildcard tombstones in the registry mask earlier wildcard bindings along the matched path.
- Registry side metadata (current):
  - `signal_head_buckets[]`, wildcard head list, and `by_name` map for descriptor materialization and de-dup.
  - Planned: evolve the wildcard head list into the full trie described in the original blueprint when workloads demand richer wildcard storage.

### Resolve Algorithm
1) Gather literal target bindings: walk ancestors of the target cell; union enzyme names into `E_literal` (de-dup by name). If no target is provided, `E_literal` starts empty.
2) Gather wildcard target bindings (planned): traverse the target wildcard trie with the impulse path, collecting matches into `E_wildcard_target`.
3) Form target set: `E_cell = E_literal ∪ E_wildcard_target`, respecting specificity (literal beats wildcard, deeper path beats shallow, registration order as final tie-break). Today, `E_wildcard_target` is empty because bindings stay literal.
4) If a signal is present:
   - Gather literal signal bindings from the signal buckets.
   - Traverse the signal wildcard structures (head buckets plus wildcard list) with the signal path.
   - Intersect `E = E_cell ∩ (E_signal_literal ∪ E_signal_wildcard)`.
   If no signal is present, `E = E_cell`.
5) Materialize descriptors for names in `E` via the registry (`by_name`, pick the most specific entry when several exist for a name).
6) Build dependency graph within `E` (before/after), run Kahn’s algorithm with deterministic priority (dual-path ahead of single, combined specificity, descriptor name, registration order).
7) Execute in order; N→N+1 staging and visibility unchanged.

### Binding Read Path Details
- For each ancestor (including the target itself):
  - Determine the available lists for the cell (`cepData` if present, then `cepStore`). Always iterate the data list first, followed by the store list when both exist.
  - Iterate each list in that order; for each entry:
    - If the tombstone flag is set, add the name to a masked set (keeping the node for audit) and skip emission.
    - If this is the target cell and the name is not masked: accept the entry.
    - If this is a strict ancestor and the name is not masked: accept only if the propagate flag is set.
  - Merge accepted entries into `E_literal`, keeping the first occurrence of a name while respecting the masked set so ancestors cannot resurrect the entry.
- Traverse wildcard structures deterministically. Today the resolver scans the wildcard head list; the planned trie would follow literal children and wildcard drawers so multi-segment entries can append into `E_wildcard_target` if not already masked by a tombstone.
- This preserves low overhead (O(depth + matching wildcard nodes)) and respects data-over-store precedence.

### Determinism and Idempotency
- Deterministic order preserved (same tie‑breakers described in the resolve algorithm).
- Enzymes run at most once per `(signal, target, beat)` and per unique name.
- Bind/unbind are ordinary cell edits: become active at N+1, so mid‑beat agendas remain frozen.

### Migration and Compatibility
- Hybrid policy: TARGET_THEN_SIGNAL remains the default; alternate policies (OR, TARGET_ONLY, SIGNAL_ONLY, STRICT_BOTH) are planned but not yet configurable.
- Signal-only broadcasts continue to work (omit target).
- Enzyme renames: prefer stable `cepDT` identities; stale names in cells simply do not resolve (optionally provide aliases during transitions).

## Performance Analysis (Estimated)
These back-of-the-envelope numbers explain how the resolver scales with registry size, wildcard use, and ancestry depth so you can judge whether a proposed change might threaten beat budget.
### Scenario
- 10,000 impulses/heartbeat; average 3 enzymes triggered per impulse; 1,000 registry entries; 300 unique enzyme names.

### Reference Costs
- Target path: O(depth + |E_cell|) to gather literal bindings. Wildcard traversal becomes O(matching nodes) once the planned target trie lands.
- Signal path: O(|bucket_sig|) for literal head buckets, plus scanning the wildcard head list (proportional to wildcard descriptors).
- Dependency/topology: Kahn’s algorithm runs on the matched enzyme set; complexity scales with the number of enzymes after intersection.

### Expected Relative Throughput
- Resolve work is dominated by small sets: ancestors (depth), `|E_cell|` (often 3–8), signal buckets (often tens), and the subset of wildcard nodes that match the provided paths.
- Literal-only impulses pay identical cost to the literal design: gather along the target path, intersect with signal buckets, run dependency sort.
- Wildcard impulses add a wildcard scan whose cost scales with the number of matching wildcard descriptors rather than total registry size. Typical glob usage touches only a handful of entries, so throughput remains within a few percent of literal-only impulses.
- Resolve-buffer reuse (1.5–3×) combines with reduced registry scanning for an overall 3–10× improvement on resolve cost at the stated scale (10,000 impulses/heartbeat, 3 enzymes/impulse, 1,000 registry entries, 300 unique enzyme names).

### Verification
- Automated coverage: the heartbeat suite exercises each binding rule (tests in `src/test/test_heartbeat.c` such as `test_heartbeat_binding_propagation`, `_no_propagation`, `_union_chain`, `_duplicate_mask`, `_binding_signal_filter`, `_target_requires_binding`, and the wildcard traversal checks).
- Propagation scope: parent bindings marked propagate apply to descendants; bindings without propagate stay local.
- Tombstones mask inheritance: tombstoning a child binding hides the ancestor binding of the same name.
- Union and deduplication: the resolver unions ancestor and child bindings, running each unique enzyme at most once per impulse.
- Target + signal intersection: impulses with both target and signal fire only the leaf intersection—no fallback to signal-only when the target set is empty.
- Broadcast-only impulses remain supported by omitting a target; they still flow through the signal index.

### Notes and Safeguards
- Memory: per‑cell bindings add small overhead; inheritance and de‑dup keep it modest. Consider interning small fixed vectors to share common binding sets.
- Unbind/inheritance: support a tombstone to cancel a parent binding at a child when needed.
- Observability: expose counters (suppressed-by-signal, dual-path vs single, average `|E_cell|`, signal bucket sizes, matching wildcard nodes) and optional per-beat trace for a few impulses.


## Implementation Snapshot (Current Runtime)

- **Bindings stay literal.** Only concrete `cepDT` names are stored on cells. Wildcard behaviour is provided by signal queries whose segments carry either the glob bit (embedded `*`) or the `CEP_ID_GLOB_MULTI` sentinel.
- **Segment-scoped multi-glob.** The `CEP_ID_GLOB_MULTI` sentinel still matters: it lets an impulse cover any child under a structural branch or any payload descriptor at the leaf without enumerating every value.
- **Wildcard registry restored.** Alongside the sorted indexes, the dispatcher now maintains a wildcard head index so multi-segment `CEP_ID_GLOB_MULTI` queries trigger without enumerating every branch; literal paths still ride the original sorted arrays.
- **Policy backlog.** Only TARGET_THEN_SIGNAL dispatch ships; alternate combine modes (OR, TARGET_ONLY, SIGNAL_ONLY, STRICT_BOTH) stay queued in the dispatcher backlog (tracked in `src/l0_kernel/cep_enzyme.c`).
- **Veiled staging is silent.** Bindings that live under a veiled subtree (including the root created by `cep_txn_begin`) stay invisible to the resolver until the transaction commits and the veil lifts.

---

## Global Q&A

- Why bind on parents instead of every child?
  Parent bindings apply to the subtree, avoiding write amplification. Resolve unions ancestor lists to reconstruct the effective set for a leaf.

- Do bindings change determinism?
  No. Order is still governed by dependencies and deterministic tie‑breakers. Bind/unbind follow the heartbeat boundary (N→N+1) like any other fact.

- What if a cell lists an enzyme name that is no longer registered?
  It is ignored. Names are resolved against the active registry at beat time.

- How do signal‑only broadcasts work?
  Omit the target. The dispatcher uses the signal index to pick eligible enzymes, keeping broadcast behavior intact.

- Can we select OR behavior?
  Not yet. The dispatcher still applies TARGET_THEN_SIGNAL; alternate combine modes remain on the roadmap (see the backlog comment in `src/l0_kernel/cep_enzyme.c`).

- What about performance when many cells have many bindings?
  The gather step is proportional to depth plus the local binding sizes, which stay small in practice. For pathological cases, interning shared binding sets and caching per‑segment unions within a beat can keep it fast.

---
