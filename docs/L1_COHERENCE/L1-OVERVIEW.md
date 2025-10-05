# L1 Coherence: Overview

Layer 1 exists so higher layers can talk about people, relationships, and shared context without worrying about how the kernel stores bytes. Think of it as the part of CEP that keeps a living notebook of beings, bonds, contexts, and the truths they imply. If you can think in terms of “who”, “how they connect”, and “what is true because of that”, you can work with L1.

L1’s goal is simple: keep the coherence story straight every heartbeat. It captures the real facts in ledgers, lets you ingest new intents safely, and fills in any missing connective tissue so the whole system stays replayable.

---

## Technical Details

### Durable ledgers and caches
- Authoritative data lives under `/data/coh` in five ledgers: `being`, `bond`, `context`, `facet`, and `debt`. Each ledger is append-only and records provenance links back to the intent that produced it.
- Secondary indexes under `/data/coh/index` mirror fast lookup patterns (beings by kind, bonds by endpoint tuple, contexts by type, facets by context). These are rebuilt deterministically after every ingest beat.
- Transient adjacency mirrors live under `/tmp/coh/adj`. They are drop-and-rebuild caches for “who is near this node?” queries and can be wiped between sessions without losing truth.

### How beings, bonds, contexts, and facets fit together
- **Beings** (`/data/coh/being/{id}`) hold long-lived identities and a free-form `attrs` dictionary. You link everything else to these anchors.
- **Bonds** (`/data/coh/bond/{id}`) connect exactly two beings with a `type`, `src`, `dst`, and optional `directed` flag. They model pairwise relations such as “owns” or “mentors”.
- **Contexts** (`/data/coh/context/{id}`) gather multiple beings under named `roles/{role}` links and carry scoped `facets/{facet}` children that either link to resolved facts or describe a required-but-missing piece.
- **Facets** materialize the implications of a context. When the closure enzyme finds a facet link it mirrors it into `/data/coh/facet/{ctx}:{facetType}` so global queries can scan a flat index instead of traversing every context. Canonical IDs (built via `cep_l1_compose_identifier()` or the `CEP_L1_COMPOSE` macro) keep `{ctx}` and `{facet}` consistent across callers.
- **Debts** (`/data/coh/debt/{ctx}/{facet}`) act as IOUs. When a required facet has no link yet, the closure enzyme records the debt and clears it once a matching fact appears, keeping the closure contract honest.

### Intent workflow
- Clients write intents to `/data/inbox/coh/{be_create|bo_upsert|ctx_upsert}/{txn}`. The mailroom moves them into `/data/coh/inbox/**` ahead of the ingest enzymes, leaving an audit link in the original bucket.
- Kernel heartbeats emit `CEP:sig_cell/op_add` when intents arrive. Registry bindings route those signals into the six coherence enzymes in a fixed order.
- Identifier fields now accept any text that can be interned by the namepool; short values compact to CEP words/acronyms, and longer phrases are stored as stable references without truncation.
- Helper builders (`cep_l1_being_intent_init()`, `cep_l1_bond_intent_init()`, `cep_l1_context_intent_init()` plus the role/facet adders) stitch these payloads together, mirror the submitted spelling under `original/*`, and keep callers away from low-level dictionary plumbing.
- Each ingest enzyme materializes ledgers, copies free-form attributes, and records `outcome` status back onto the intent cell.

### Closure and replay guarantees
- `coh_closure` mirrors resolved facets into `/data/coh/facet` and raises debts when a required facet has no target yet. Debts live under `/data/coh/debt/{ctxId}/{facet}` and clear automatically once satisfied.
- Decision facts under `/data/coh/decision` capture tie-breaks when more than one candidate could satisfy a facet. Replays consult the same decision so deterministic behavior never depends on iteration order.
- After closure, `coh_index` rebuilds durable indexes and `coh_adj` refreshes transient mirrors. Both steps respect locks so mid-beat readers see consistent snapshots.

### Bootstrap and registration
- Call `cep_l1_coherence_bootstrap()` once after the kernel is ready. It ensures `/data/coh` exists, creates every ledger/index/inbox branch, primes `/tmp/coh/adj`, and initializes the namepool.
- Call `cep_l1_coherence_register(registry)` to load the enzyme pack. Descriptors are idempotent: you can register multiple times, and bindings stay pointed at `/data/coh` with `propagate=true`.
- The default agenda order is `coh_ing_be → coh_ing_bo → coh_ing_ctx → coh_closure → coh_index → coh_adj`. Heartbeat fences guarantee the same ordering on replays.

---

## Q&A

**Q: Do I have to manage the adjacency mirrors manually?**  
A: No. They are scratch structures rebuilt by `coh_adj`. If they are missing or corrupted, the enzyme will recreate them on the next heartbeat.

**Q: What happens if an intent uses a word longer than 11 characters?**  
A: L1 interns the full string through the namepool (up to 256 bytes). If it cannot compact to a word/acronym it stores a `CEP_NAMING_REFERENCE`, so the intent succeeds without truncation.

**Q: How does L1 stay deterministic when multiple facets could link to the same context?**  
A: `coh_closure` writes a decision entry the first time it chooses a candidate. Later beats reuse the stored decision so replays take the same branch every time.

**Q: Can I extend the ledgers with custom fields?**  
A: Yes. Each being, bond, and context node exposes an `attrs` dictionary. Copy anything you like there—just keep tags within the lexicon rules.

**Q: Are identifiers still limited to 11 characters?**  
A: No. L1 routes every identifier through the namepool. Short names compact to CEP words/acronyms; longer phrases (up to 256 bytes) become stable references, so callers can use their own lexicon without truncation.

### Mailroom ingress guarantees

The mailroom removes guesswork from intent envelopes: every request that reaches L1 already carries the shared header and an audit trail back to its source bucket.

**Technical details**
- Mailroom routing runs before `coh_ing_*`, so intents arrive in `/data/coh/inbox/**` with no need for layer-specific shims.
- Each routed request includes an `original/*` mirror, a default `outcome` slot, and an empty `meta/parents` list that the ingest enzymes can extend.
- The mailroom leaves a link under `/data/inbox/coh/{bucket}/{txn}` pointing at the moved request, keeping provenance one hop away for tools and audits.
- Retention defaults live under `/sys/retention/coh` (`retain_mode`, `retain_ttl`, `retain_upto`). Update those cells—or set the same fields on individual intents—when you need decisions to expire or archive automatically.

**Q&A**
- *Should new tests write directly to the mailroom?* Yes. Staging a request under `/data/inbox/coh/**` exercises routing, shared headers, and audit links exactly like production, making regressions easier to spot.
- *What happens if routing fails?* The mailroom keeps the original request in place, returns a fatal code, and leaves `outcome` untouched so you can inspect the payload during debugging.
