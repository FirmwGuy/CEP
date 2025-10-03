# L1 Coherence Roadmap

Layer 1 keeps CEP’s shared story straight: beings carry identities, bonds explain relationships, contexts bind roles, and facets guarantee closure. The roadmap below explains where that layer already stands and what remains so application teams know when it is safe to build on top of it.

---

## Technical Details

### Delivered
- **Ledgers & bootstrap** – `/data/coh` hosts durable ledgers for beings, bonds, contexts, facets, debts, plus the inbox and secondary indexes. Helper `cep_l1_coherence_bootstrap()` is idempotent and already wired into the tests.
- **Enzyme pack** – `cep_l1_coherence_register()` stages six enzymes (`coh_ing_be`, `coh_ing_bo`, `coh_ing_ctx`, `coh_closure`, `coh_index`, `coh_adj`) with deterministic ordering and heartbeat fences.
- **Closure contracts** – Required facets record debts until satisfied; decision ledgers capture tie-breaks; facet mirrors clear stale entries every beat.
- **Index & adjacency hygiene** – Secondary indexes and `/tmp/coh/adj` buckets purge obsolete entries before relinking, so caches now mirror the authoritative ledgers exactly.

### In Flight
- **Debt analytics** – Surface metrics (counts, aging, per-context summaries) so operators can spot unfinished closure work without spelunking the tree.
- **Replay probes** – Add lightweight tools that compare ledger snapshots across beats to confirm deterministic replay in staging environments.
- **Lexicon expansion** – Reserve additional CEP tags for common domain facets (policy, geography, inventory) once production workloads request them.

### Next
- **Intent validation library** – Ship shared helpers so clients can build well-formed intents (word guards, link checks, truncation policy) without duplicating kernel code.
- **Adjacency subscriptions** – Expose change notifications or cached projections for consumers that want push-based updates instead of polling `/tmp`.
- **Upgrade playbooks** – Document rolling upgrade procedures for enzyme schema changes (e.g., new ledger buckets) to keep long-lived clusters safe.

---

## Q&A

**Q: Is L1 ready for production data today?**  
A: Yes for ledgers, closure, and indexes. The enzyme pack is idempotent, replayable, and covered by unit tests. What’s left is tooling around observability and rollout hygiene.

**Q: What should I build on top of L1 right now?**  
A: Any workload that needs durable identities, graph relationships, or deterministic closure. Plan for future upgrades by keeping your own domain tags within the CEP lexicon rules.

**Q: How will future changes roll out?**  
A: Upcoming features will ship alongside migration guides and compatibility notes. The roadmap above highlights which areas to watch so you can test against staging builds before opting in.

