# Layer 2 Integration Guide

Layer 2 is the bridge between business intent and the kernel. Treat it as the
place where product teams submit playbooks, policies, and experiments, while the
runtime guarantees deterministic execution and exhaustive evidence.

---

## Technical Details
- **Boot order** – Call `cep_l2_flows_bootstrap()` immediately after Layer 1
  coherence bootstraps. Follow with `cep_l2_flows_register(registry)` before
  heartbeat start so all seven enzymes resolve correctly.
- **Mailroom ingress** – Produce intents under `/data/inbox/flow/{fl_upsert|ni_upsert|inst_start|inst_event|inst_ctrl}/{txn}`. `cep_mailroom_bootstrap()`/`register()` run as part of bootstrap/registration, move the payload into `/data/flow/inbox/**`, and preserve an audit link in the mailroom bucket.
- **Required ledgers** – Ensure `/data/flow/{program,variant,policy,niche,
  guardian,instance,decision,index,inbox}` exist. The boot helper verifies this
  for you; only extend the list if you add new ledgers. The per-layer inbox is
  still used internally after the mailroom routes requests.
- **Namepool discipline** – Reuse CEP tags for every identifier shorter than
  12 chars. Longer identifiers must be interned through `cep_namepool_intern*`
  and referenced by DTs (flows, instances, policies, niches).
- **Intent format** – Payloads are plain dictionaries with `id` and `original`
  mirrors. Canonicalisers in `fl_ing`, `ni_ing`, and `inst_ing` expect text
  fields to be NUL-terminated UTF-8.
- **Policy hooks** – Policies live under `/data/flow/policy/<id>`. Populate
  optional `telemetry` keys (`score`, `confidence`, `rng_seed`, `rng_seq`) if
  the policy has deterministic values; otherwise the engine synthesizes them.
- **Instance integration** – Downstream systems fire waits by writing
  `inst_event` intents with `signal_path` (or `signal`) plus optional
  `payload/context`. Control flows operate through `inst_ctrl` with
  `action=pause|resume|cancel|budget`.
- **Observability** – Consume indexes under `/data/flow/index/*` and adjacency
  mirrors under `/tmp/flow/adj/by_inst/*` for real-time status, latency, and
  error windows. Decisions retain telemetry within
  `/data/flow/decision/<inst>/<site>/telemetry`.

## Q&A
- **Do I need to register custom enzymes?**
  Usually not. Bind additional descriptors only if you introduce new intent
  namespaces. Keep them after `fl_adj` to avoid breaking agenda order.
- **Where do transforms persist their outputs?**
  Today transforms stage cells under `instance/emits`. Commit/publish steps are
  deferred to Layer 3 perspectives and higher-level tooling.
- **How do I feed events from external brokers?**
  Bridge messages into `inst_event` intents. Use CEP-tagged DTs for signal
  routing; rely on `context` to scope the wake to a given being/context tuple.
- **Can policies call into native code?**
  Yes. Embed function pointers or hashed handles inside policy definitions and
  resolve them inside the Decide hook. Just record every non-deterministic
  result as part of the Decision Cell.
