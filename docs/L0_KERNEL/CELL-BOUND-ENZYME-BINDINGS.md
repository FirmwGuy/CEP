# L0 Kernel: Cell-Bound Enzyme Bindings and Signal-Indexed Dispatch

## Introduction

Imagine putting a sticky note on a folder that says “run these helpers here.” Whenever anything in that folder changes, you look at the sticky notes on that folder (and its parent folders) to know which helpers should run. If the change also has a specific intent (a small tag like “thumbnail”), you only run the helpers that care about that intent. This way, the helpers live next to the data they serve, and figuring out who should act stays quick and clear.

## Technical Design

### Goal
- Trigger enzymes deterministically when facts (cells) change, while reducing per‑impulse dispatch cost and improving locality/auditability.

### Binding Semantics
- Where to store: keep enzyme bindings as compact entries on the target cell and/or its ancestors (parent binding implies subtree). This avoids duplicating bindings on every child.
- What is stored: only the enzyme identity (`cepDT name`) and an optional scope flag (default is subtree; “node‑only” can opt out of inheritance).
- How it composes: at resolve time, union all bindings along the path root→…→target and de‑duplicate by enzyme name.
- Append‑only: bindings append new records (tombstone for removes). They currently become visible immediately; callers should schedule bind/unbind work outside the active beat to preserve N→N+1 semantics.

### Signal Filter and Registry
- Registry continues to own descriptors (callback, before/after, match policy, flags).
- Only index registry by signal:
  - Head‑segment buckets for prefix/exact signal queries.
  - Optional exact‑path map for fast equality matches.
- Name lookup: maintain `name → [entries]` to materialize the best descriptor (longest/specific) per enzyme name after signal filtering.

### Matching Policy (Hybrid)
- Target present: an enzyme must be bound on the target path (via ancestor union). If a signal is also present, it must additionally match the signal (intersection of sets).
- No target: signal‑only/broadcast dispatch using the signal index.
- Future compatibility: a policy switch could re-enable legacy modes (OR, TARGET_ONLY, SIGNAL_ONLY, STRICT_BOTH) if needed. The current implementation always applies TARGET_THEN_SIGNAL semantics.

### Data Structures
- Cell side (current implementation):
  - Each `cepStore` / `cepData` holds an in-memory singly linked list of bindings.
  - Node layout: `name` (enzyme identity), `flags` (tombstone + propagate bits), `next` pointer, and `modified` heartbeat.
  - Precedence: when both store and data exist, the store list is used; otherwise the data list is used.
  - Resolve semantics: the target cell contributes all non-tombstoned entries; ancestors contribute only entries with the propagate flag set.
  - Runtime append-only trail: bind/unbind operations append nodes and stamp `modified` with `cep_cell_timestamp_next()`. Persisting this chain into the historical journal is future work; today the list is kept in memory.
  - Future option: bindings could be materialised as a dedicated child (e.g., `CEP:enzymes`) so only that child’s `cepStoreNode` mutates. The current implementation avoids `store->past` snapshots by keeping the list alongside existing store/data structures.
- Inheritance masking:
  - A tombstone appended on a child masks inherited bindings with the same name. The resolver skips masked names downstream.
- Registry side:
  - `signal_head_buckets[]` and `signal_indices[]` for head‑segment lookup.
  - `by_name` map for descriptor materialization and de‑dup.

### Resolve Algorithm
1) Gather bindings: walk ancestors of target; union enzyme names into `E_cell` (de‑dup by name). If no target, skip to step 3.
2) If signal present: form `E_sig` from the signal index. Intersect `E = E_cell ∩ E_sig`. If no signal: `E = E_cell`.
3) Materialize descriptors for names in `E` via the registry (`by_name`, pick most specific entry when several exist for a name).
4) Build dependency graph within `E` (before/after), run Kahn’s algorithm with deterministic priority (dual‑path ahead of single, combined specificity, descriptor name, registration order).
5) Execute in order; N→N+1 staging and visibility unchanged.

### Binding Read Path Details
- For each ancestor (including the target itself):
  - Choose the binding list from `cepStore` if present; otherwise from `cepData`.
  - Iterate the linked list; for each entry:
    - If this is the target cell: accept non‑tombstoned entries unconditionally.
    - If this is a strict ancestor: accept only if the propagate flag is set.
  - Merge into `E_cell`, keeping first occurrence of a name and ignoring duplicates.
- This preserves low overhead (O(depth + total bindings seen)) and respects store‑over‑data precedence.

### Determinism and Idempotency
- Deterministic order preserved (same tie‑breakers as today).
- Enzymes run at most once per `(signal, target, beat)` and per unique name.
- Bind/unbind are ordinary cell edits: become active at N+1, so mid‑beat agendas remain frozen.

### Migration and Compatibility
- Keep the hybrid policy: TARGET_THEN_SIGNAL default; allow OR via global policy or per‑enzyme scope for legacy flows.
- Existing signal‑only broadcasts continue to work (omit target).
- Enzyme renames: prefer stable `cepDT` identities; stale names in cells simply do not resolve (optionally provide aliases during transitions).

## Performance Analysis (Estimated)

### Scenario
- 10,000 impulses/heartbeat; average 3 enzymes triggered per impulse; 1,000 registry entries; 300 unique enzyme names.

### Reference Costs
- Original (OR): registry scan O(R) per impulse; matches on target OR signal. Larger fan‑out; dependency/heap work on M matches.
- Current Target‑First: target gating, then optional signal. Smaller M; same O(R) scan.
- Hybrid: policy selectable; cost equals the active branch.
- Cell‑Bound + Signal Index (this proposal):
  - Target path: O(depth + |E_cell|) to gather bindings, plus O(|bucket_sig|) for signal prefilter, then small‑set intersection and topo sort.
  - No target: signal‑only path uses signal index (no registry full scan).

### Expected Relative Throughput
- Registry scan vs binding+index:
  - Today: ~10,000 × 1,000 = ~10M entry checks/beat dominate runtime.
  - Proposed: per‑impulse work dominated by tiny sets: ancestors (depth), `|E_cell|` (often 3–8), and a signal bucket (often tens). Intersection and topo sort are negligible at these sizes.
- Rough expectations (orders of magnitude, not measurements):
  - Original (OR): slowest of the three legacy policies; +5–15% vs Target‑First due to larger M.
  - Current Target‑First: baseline; 3–8% faster than OR (smaller M), still dominated by O(R) scan and per‑impulse allocations.
  - Hybrid (defaulting to Target‑First): ≈ Current.
  - Cell‑Bound + Signal Index: 2–5× faster resolve path than Current at the stated scale, especially when impulses cluster by subtree. Gains compound with resolve‑buffer reuse (1.5–3×) for an overall 3–10× improvement on resolve cost.

### Verification
- Automated coverage: the heartbeat suite exercises each binding rule (tests in `src/test/test_heartbeat.c` such as `test_heartbeat_binding_propagation`, `_no_propagation`, `_union_chain`, `_duplicate_mask`, `_binding_signal_filter`, and `_target_requires_binding`).
- Propagation scope: parent bindings marked propagate apply to descendants; bindings without propagate stay local.
- Tombstones mask inheritance: tombstoning a child binding hides the ancestor binding of the same name.
- Union and deduplication: the resolver unions ancestor and child bindings, running each unique enzyme at most once per impulse.
- Target + signal intersection: impulses with both target and signal fire only the leaf intersection—no fallback to signal-only when the target set is empty.
- Broadcast-only impulses remain supported by omitting a target; they still flow through the signal index.

### Notes and Safeguards
- Memory: per‑cell bindings add small overhead; inheritance and de‑dup keep it modest. Consider interning small fixed vectors to share common binding sets.
- Unbind/inheritance: support a tombstone to cancel a parent binding at a child when needed.
- Observability: expose counters (suppressed‑by‑signal, dual‑path vs single, average `|E_cell|`, signal bucket sizes) and optional per‑beat trace for a few impulses.

## Q&A

- Why bind on parents instead of every child?
  Parent bindings apply to the subtree, avoiding write amplification. Resolve unions ancestor lists to reconstruct the effective set for a leaf.

- Do bindings change determinism?
  No. Order is still governed by dependencies and deterministic tie‑breakers. Bind/unbind follow the heartbeat boundary (N→N+1) like any other fact.

- What if a cell lists an enzyme name that is no longer registered?
  It is ignored. Names are resolved against the active registry at beat time.

- How do signal‑only broadcasts work?
  Omit the target. The dispatcher uses the signal index to pick eligible enzymes, keeping broadcast behavior intact.

- Can we preserve legacy OR behavior?
  Yes. Keep a policy switch (global or per‑enzyme) to select OR. Default remains Target‑Then‑Signal for safety.

- What about performance when many cells have many bindings?
  The gather step is proportional to depth plus the local binding sizes, which stay small in practice. For pathological cases, interning shared binding sets and caching per‑segment unions within a beat can keep it fast.
