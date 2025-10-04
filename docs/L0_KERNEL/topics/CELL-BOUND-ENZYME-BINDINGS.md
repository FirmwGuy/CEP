# L0 Topic: Cell-Bound Enzyme Bindings and Signal-Indexed Dispatch

## Introduction

Imagine putting a sticky note on a folder that says “run these helpers here.” Whenever anything in that folder changes, you look at the sticky notes on that folder (and its parent folders) to know which helpers should run. If the change also has a specific intent (a small tag like “thumbnail”), you only run the helpers that care about that intent. Helpers that use wildcards keep their own cabinet of sticky notes so they do not clutter every folder; when the system needs them, it looks inside that cabinet using the same rules people expect from filesystem globs.

## Technical Design

### Goal
- Trigger enzymes deterministically when facts (cells) change, while reducing per‑impulse dispatch cost and improving locality/auditability.

### Binding Semantics
- Literal paths: enzymes bound to concrete cell paths remain stored directly on the target cell and optionally inherit to descendants when marked propagate.
- Wildcard paths: any binding whose target path contains glob segments is captured in the registry-owned wildcard tree instead of the cell graph.
- Signal filters: signal paths behave the same way—literal entries live in the per-signal buckets, wildcard entries live in the wildcard tree for signals.
- Literal naming constraints: namepool rejects segments containing `*` or `?` so literal bindings stay unambiguous; multi-segment wildcards rely on the dedicated `CEP_ID_GLOB_MULTI` sentinel while `*` and `?` remain reserved for upcoming per-segment selectors.
- Domains and tags: impulse cell paths resolve across both `cepData` and `cepStore` domains; bindings record the domain segment explicitly so literals attach to the correct list and wildcard nodes match the intended domain/tag combination.
- Append-only: binding and unbinding append records with the enzyme identity (`cepDT name`), flags, and registration stamp. Entries become visible on the next heartbeat; callers schedule bind/unbind work outside the active beat to preserve N→N+1 semantics.
- De-duplication: when the resolver gathers bindings it keeps the first occurrence of a name (most specific wins) and ignores duplicates.

### Signal Filter and Registry
- Registry continues to own descriptors (callback, before/after, match policy, flags).
- Signal indexing splits literal and wildcard entries:
  - Literal head-segment buckets for prefix/exact queries.
  - Wildcard trie that mirrors filesystem-style glob semantics (single-segment `*`/`?` and multi-segment `**`).
- Name lookup: maintain `name → [entries]` to materialize the best descriptor per enzyme name after literal/wildcard filtering.

### Matching Policy (Hybrid)
- Target present: an impulse gathers all literal bindings from the cell lineage, then unions any wildcard matches reached through the wildcard tree. If a signal is also present, the intersection of target and signal matches produces the final enzyme set.
- No target: signal-only/broadcast dispatch uses the signal index (literal buckets plus wildcard tree) to gather candidates.
- Optional policy switch: deployments can select alternate policies (OR, TARGET_ONLY, SIGNAL_ONLY, STRICT_BOTH) when they need different gating rules. Default policy applies TARGET_THEN_SIGNAL semantics.

### Data Structures
- Cell side (literal bindings):
  - Each `cepStore` / `cepData` holds an in-memory singly linked list of literal bindings.
  - Node layout: `name` (enzyme identity), `flags` (tombstone + propagate bits), `next` pointer, and `modified` heartbeat.
  - Precedence: when both store and data exist, the data enzyme list has precedence.
  - Resolve semantics: the target cell contributes all non-tombstoned entries; ancestors contribute only entries with the propagate flag set.
  - Runtime append-only trail: bind/unbind operations append nodes and stamp `modified` with `cep_cell_timestamp_next()`.
- Wildcard registry (target and signal):
  - Per-domain trie keyed by path segments, with literal children and wildcard drawers stored separately.
  - Each node keeps vectors of binding records plus tombstones in registration order, carrying the same flags as literal nodes.
  - `cepID` segments are canonicalised: literal children cache the namepool `cepID` for the exact segment, domain-wide globs still use the reserved `CEP_ID_GLOB_*` sentinels, and tag-level globbing relies on the segment’s `glob` bit (set when the word includes `*`) so lookup stays O(1) and identifiers remain inspectable. Nodes retain the original pattern text for debugging, but the resolver relies on the precomputed glob kind.
  - Traversal metadata precomputes segment matchers so resolve-time checks avoid repeated parsing.
  - Domain/tag awareness is encoded in the segment keys so `cepData` vs `cepStore` bindings never collide.
- Inheritance masking:
  - A tombstone appended on a child masks inherited literal bindings with the same name, while remaining in the append-only chain for audit history. Wildcard tombstones in the registry mask earlier wildcard bindings along the matched path.
- Registry side metadata:
  - `signal_head_buckets[]`, wildcard trie nodes, and `by_name` map for descriptor materialization and de-dup.

### Resolve Algorithm
1) Gather literal target bindings: walk ancestors of the target cell; union enzyme names into `E_literal` (de-dup by name). If no target is provided, `E_literal` starts empty.
2) Gather wildcard target bindings: traverse the target wildcard trie with the impulse path, collecting matches into `E_wildcard_target`.
3) Form target set: `E_cell = E_literal ∪ E_wildcard_target`, respecting specificity (literal beats wildcard, deeper path beats shallow, registration order as final tie-break).
4) If a signal is present:
   - Gather literal signal bindings from the signal buckets.
   - Traverse the signal wildcard trie with the signal path.
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
- Traverse the wildcard trie by following literal children and wildcard drawers in deterministic order. A wildcard entry can match zero or more path segments; matches append into `E_wildcard_target` if not already masked by a tombstone.
- This preserves low overhead (O(depth + matching wildcard nodes)) and respects data-over-store precedence.

### Determinism and Idempotency
- Deterministic order preserved (same tie‑breakers described in the resolve algorithm).
- Enzymes run at most once per `(signal, target, beat)` and per unique name.
- Bind/unbind are ordinary cell edits: become active at N+1, so mid‑beat agendas remain frozen.

### Migration and Compatibility
- Hybrid policy: TARGET_THEN_SIGNAL remains the default; alternate policies (OR, TARGET_ONLY, SIGNAL_ONLY, STRICT_BOTH) stay available via configuration for specialised deployments.
- Signal-only broadcasts continue to work (omit target).
- Enzyme renames: prefer stable `cepDT` identities; stale names in cells simply do not resolve (optionally provide aliases during transitions).

## Performance Analysis (Estimated)

### Scenario
- 10,000 impulses/heartbeat; average 3 enzymes triggered per impulse; 1,000 registry entries; 300 unique enzyme names.

### Reference Costs
- Target path: O(depth + |E_cell|) to gather literal bindings, plus traversal of the target wildcard trie proportional to matching nodes.
- Signal path: O(|bucket_sig|) for literal head buckets, plus traversal of the signal wildcard trie proportional to matching nodes.
- Dependency/topology: Kahn’s algorithm runs on the matched enzyme set; complexity scales with the number of enzymes after intersection.

### Expected Relative Throughput
- Resolve work is dominated by small sets: ancestors (depth), `|E_cell|` (often 3–8), signal buckets (often tens), and the subset of wildcard nodes that match the provided paths.
- Literal-only impulses pay identical cost to the literal design: gather along the target path, intersect with signal buckets, run dependency sort.
- Wildcard impulses add a trie traversal whose cost scales with the number of matching wildcard entries, not total registry size. Typical glob usage touches a handful of trie nodes, so throughput remains within a few percent of literal-only impulses.
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

## Q&A

- Why bind on parents instead of every child?
  Parent bindings apply to the subtree, avoiding write amplification. Resolve unions ancestor lists to reconstruct the effective set for a leaf.

- Do bindings change determinism?
  No. Order is still governed by dependencies and deterministic tie‑breakers. Bind/unbind follow the heartbeat boundary (N→N+1) like any other fact.

- What if a cell lists an enzyme name that is no longer registered?
  It is ignored. Names are resolved against the active registry at beat time.

- How do signal‑only broadcasts work?
  Omit the target. The dispatcher uses the signal index to pick eligible enzymes, keeping broadcast behavior intact.

- Can we select OR behavior?
  Yes. A policy switch (global or per-enzyme) can request OR semantics when needed. Default remains Target-Then-Signal for safety.

- What about performance when many cells have many bindings?
  The gather step is proportional to depth plus the local binding sizes, which stay small in practice. For pathological cases, interning shared binding sets and caching per‑segment unions within a beat can keep it fast.
