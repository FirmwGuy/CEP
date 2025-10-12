# L0 Topic: Mailroom and Layer Mailboxes

## Introduction
The mailroom is CEP’s lobby. Every intent—whether it targets an upper-layer pack or a custom namespace—lands here first, is normalized, and then routes into the correct inbox ahead of the beat. Understanding the mailroom API makes it easy to stitch new namespaces, extend routing, or reason about why a request appears (or doesn’t) in `/data/<layer>/inbox`.

## Technical Details
- **Bootstrap** (`cep_mailroom_bootstrap()`): brings `/data/inbox/**` online, then reads `/sys/err_cat/<scope>/mailroom/buckets/*` to mirror namespaces and buckets defined by the error catalog. If the catalog is empty it can fall back to any defaults you seed (older deployments still list `{coh,flow}` for compatibility), but it never writes error codes itself.
- **Registration** (`cep_mailroom_register()`): installs the `mr_route` enzyme on `CEP:sig_cell/op_add` with `before` edges for every ingest enzyme (the ingest tags supplied via `cep_mailroom_add_router_before()` or by upper-layer packs), binds the router to `/data/inbox`, and keeps repeated registrations idempotent.
- **Routing contract**: when a request hits `/data/inbox/<ns>/<bucket>/<txn>`, the router clones it under `/data/<ns>/inbox/<bucket>/<txn>`, leaves an audit link at the original site, ensures the shared intent header (`original/*`, `outcome`, `meta/parents`) exists, and stops if the downstream inbox is missing (returning `CEP_ENZYME_FATAL`).
- **Namespaces** (`cep_mailroom_add_namespace()`): lets you register additional mailboxes. Call it before bootstrap (or rely on the automatic reseed after bootstrap) to mirror `/data/inbox/<namespace>/bucket` alongside `/data/<namespace>/inbox/bucket`.
- **Ordering hints** (`cep_mailroom_add_router_before()`): queue extra enzyme names to insert into the router’s `before` list before `cep_mailroom_register()` runs. Useful when a pack introduces its own ingest enzyme.
- **Lifecycle**: `cep_l0_bootstrap()` calls the mailroom bootstrap/registration for you. There’s no public `cep_mailroom_reset()` anymore; shutdown simply rebuilds the tree on the next bootstrap.
- **Error impulses**: CEI (`cep_error_emit`) writes to `/tmp/err/stage` and is processed by its own ingestion enzyme; error traffic does **not** transit the mailroom inbox hierarchy, so mailroom routing policies remain focused on application intents.

## Q&A
- **Where do I drop intents?** Use `/data/inbox/<namespace>/<bucket>/<txn>`. The mailroom takes care of the rest.
- **How do I add a namespace?** Call `cep_mailroom_add_namespace("my_ns", buckets, bucket_count)` during your pack’s bootstrap before you call `cep_mailroom_bootstrap()`. After bootstrap, the helper reseeds immediately.
- **Can I inspect routing results?** Yes—check `/data/inbox/<ns>/<bucket>/<txn>` for the audit link and `/data/<ns>/inbox/<bucket>/<txn>` for the routed request. Routing failures leave the original request untouched and return `CEP_ENZYME_FATAL`.
- **Do I need to reseed error catalogs?** No. The catalog lives under `/sys/err_cat/**` and the error layer owns its contents. The mailroom only mirrors the namespaces/buckets that catalog declares; it never rewrites the codes.
- **Where do rendezvous mailboxes fit?** Flows still publish rendezvous outcomes via `/data/inbox/flow/inst_event`. The rendezvous enzymes bridge ledger state to that mailbox—see `RENDEZVOUS-AND-THREADING.md` for the details.
