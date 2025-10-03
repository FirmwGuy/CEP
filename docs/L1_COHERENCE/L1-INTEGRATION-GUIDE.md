# L1 Coherence: Integration Guide

If you already speak the L0 kernel language, wiring up L1 is mostly about handing it a registry and writing intents to the right place. This guide walks through the few touchpoints you need so applications can create beings, bonds, and contexts without diving into enzyme internals.

In short: bootstrap once, register the enzymes, enqueue intents as cells, and let the heartbeat do the rest.

---

## Technical Details

### 1) Preparing the runtime
- **Bootstrap**: call `cep_l1_coherence_bootstrap()` after the kernel runtime and namepool are online. It is safe to call multiple times; subsequent calls simply verify the structure.
- **Register**: call `cep_l1_coherence_register(registry)` during your enzyme setup block. The helper creates six descriptors (three ingest, three maintenance) and binds them to `/data/coh` with prefix matching on `CEP:sig_cell/op_add`.
- **Verify**: after registration, inspect the registry size or list entries—L1 increases the descriptor count by six and marks their callbacks as idempotent.

### 2) Submitting intents
- **Paths**: write intents under `/data/coh/inbox/{be_create|bo_upsert|ctx_upsert}/{txn}`. The `{txn}` child can be any word ID; pick something stable so replays find the original cell.
- **Payload schema**:
  - `be_create`: `id`, `kind`, optional `attrs/*` values.
  - `bo_upsert`: `id`, `type`, `src` link, `dst` link, optional `directed` flag.
  - `ctx_upsert`: `id`, `type`, optional `roles/{role}` links, optional `facets/{facet}` link sets or requirements.
- **Word guard**: validate client input before enqueueing. L1 strictly enforces ≤ 11 character words via `cep_text_to_word` and will mark overlong inputs as invalid.
- **Provenance**: you do not need to add metadata links—the enzymes attach the intent as a parent on every ledger entry they touch.

### 3) Observing outcomes
- **Outcome code**: every intent receives an `outcome` value (`"ok"` or an error code). Poll the same node after the heartbeat to see whether your request succeeded.
- **Ledger writes**: beings land at `/data/coh/being/{id}`, bonds at `/data/coh/bond/{id}`, contexts at `/data/coh/context/{id}`. Facet mirrors and debts appear if the context described them.
- **Indexes and mirrors**: check `/data/coh/index/*` for durable lookup tables, or `/tmp/coh/adj` for fast adjacency buckets. Both refresh automatically after ingest.

### 4) Handling errors and retries
- **Validation errors** (`missing-id`, `invalid-kind`, etc.) leave the intent in place with no ledger mutation. Fix the payload and re-run the heartbeat.
- **Transient issues** (lock contention) trigger enzyme retries. The heartbeat queues the impulse for the next beat; no client action is required.
- **Cleanup**: when you no longer need an intent, you can soft-delete the intent node. The ledger keeps provenance history either way.

### 5) Working with decisions and debts
- **Debts** indicate unfinished closure work. They live under `/data/coh/debt/{ctx}/{facet}` and carry a `required` flag plus parent link back to the intent.
- **Decisions** under `/data/coh/decision` record tie-breaks. You generally do not write to this subtree; the closure enzyme maintains it so replays stay deterministic.
- **Monitoring**: treat both areas as metrics. A growing debt tree means contexts are missing required facets; a large decision ledger means business rules are branching frequently.

---

## Q&A

**Q: When should I call the bootstrap helper?**  
A: After the kernel has initialized stores but before you start sending intents—usually alongside other subsystem bootstraps during process startup.

**Q: Can multiple registries load L1 at the same time?**  
A: Yes. The register helper tracks previously-seen registries and only appends descriptors the first time each registry is encountered.

**Q: How do I link to beings from a context intent?**  
A: Create links inside `roles/{role}` that point to the target being cells. The ingest enzyme will clone those links into the context ledger entry.

**Q: What happens if my application replays the same intent cell?**  
A: The enzymes are idempotent. They will update the ledger with the same values, refresh indexes, and return `outcome="ok"` again without duplicating records.

