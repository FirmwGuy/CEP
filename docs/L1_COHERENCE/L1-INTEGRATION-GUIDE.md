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
- **Identifier guard**: any UTF-8 string can be supplied. L1 automatically runs it through the namepool, producing a compact word/acronym when possible and falling back to a reference otherwise. Empty strings still raise `invalid-*` outcomes.
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

### Example: Project onboarding with beings, bonds, and contexts
1. **Create beings** – enqueue two `be_create` intents (`/data/coh/inbox/be_create/tx-alice`, `tx-bot`) with `id`=`alice`, `bothelper` and `kind`=`human`, `agent`. After the heartbeat, ledger entries appear at `/data/coh/being/alice` and `/data/coh/being/bothelper` with `outcome="ok"` on each intent.
2. **Link them with a bond** – enqueue `/data/coh/inbox/bo_upsert/tx-alice-bot` containing `id`=`mentor`, `type`=`mentoring`, `src`→being `alice`, `dst`→being `bothelper`, `directed`=`1`. The bond ledger now records the relation and `coh_index` writes an entry under `/data/coh/index/bo_pair/{alice:bothelper:mentoring:1}`.
3. **Describe a shared context** – enqueue `/data/coh/inbox/ctx_upsert/tx-onboard` with `id`=`onboard1`, `type`=`project`, `roles/lead`→`alice`, `roles/assistant`→`bothelper`, and a `facets/review_plan` child containing a link to an existing plan (or a placeholder dictionary with `required` flag set). The ingest enzyme copies role links, the closure enzyme mirrors any resolved facet under `/data/coh/facet/onboard1:review_plan`, and records `/data/coh/debt/onboard1/review_plan` if the facet was required but absent.
4. **Observe caches** – after the beat, adjacency mirrors record the new relationships under `/tmp/coh/adj/by_being/alice/{out_bonds,ctx_by_role}` and `/tmp/coh/adj/by_being/bothelper/...`, giving neighborhood queries a ready-made cache.

The three intents illustrate the pattern: write to the inbox, let the enzyme pack populate ledgers, and rely on closure/index/adjacency passes to keep derived structures aligned with the source facts.

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

**Q: Do I need to shorten identifiers before enqueueing intents?**  
A: No. Pass the full string. L1 will compact it to a word or acronym when possible and otherwise record a namepool reference so the exact text survives replays.
