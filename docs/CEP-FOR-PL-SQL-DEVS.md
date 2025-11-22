# CEP for PL/SQL Developers

If you know how to keep database packages humming, you already understand most of CEP’s rhythm. Think of it as a runtime whose “database” is a tree of cells, whose “transactions” are heartbeats, and whose “stored procedures” are enzymes. Every mutation is journaled, every state is replayable, and you can safely swap out behavior without breaking determinism. This guide translates familiar PL/SQL instincts into CEP’s layer‑zero vocabulary so you can stay productive while the environment shifts from *tables and sessions* to *branches and beats*. 

---

## Technical Details

### Data model: tables vs. cells

* **Cells ≈ rows with history and children**
  A CEP cell is a fact: metadata, optional payload, and optional child store. Each change appends a new timeline entry; old versions remain addressable instead of being overwritten. History is append‑only per cell and per child store, so “UPDATE” semantics are modeled as “add a new version and keep the previous ones around.” 

* **Domain/Tag as your primary key**
  Instead of `(owner, table_name, pk_values)`, CEP uses a `(domain, tag)` pair plus the path in the tree. Layer 0 defaults to the `CEP` domain and short tags (≤11 chars, `[a-z0-9:_-.]`); longer or user‑facing identifiers are interned in the namepool. 

* **Stores ≈ index + physical layout**
  Child stores under a cell are like choosing an index or table organization: dictionary, list, hash, tree, octree, packed queue, etc., each with its own cost profile. You pick per workload, not per database. 

* **Roots ≈ schema and system tables**
  The kernel always mounts the same top‑level “schemas”: 

  * `/sys` – system state, counters, config, lifecycle info (including boot/shutdown OIDs).
  * `/rt` – runtime staging (`/rt/beat/<n>` with impulses/agenda/stage, plus `/rt/ops` for operations).
  * `/journal` – effect logs for I/O and external libraries.
  * `/env` – external handles and proxies.
  * `/cas` – content‑addressable blobs (large BLOBs by hash).
  * `/lib` – stream/library snapshots.
  * `/data` – durable application state (your “schema data”).
  * `/tmp` – scratch (non‑deterministic, not replayed).
  * `/enzymes` – registry of enzyme descriptors.

  If you squint: `/data/**` ≈ schema‑owned tables, `/rt/**` ≈ redo/undo buffer plus live ops, `/cas/**` ≈ secure BLOB tables, `/sys/**` ≈ `USER_TAB_COLUMNS` and `V$` views. 

---

### Transactions vs. beats

* **Beats ≈ commit cycles**
  In PL/SQL you batch work and `COMMIT`. In CEP, the heartbeat plays that role, with a strict three‑phase contract: Capture → Compute → Commit. Inputs for beat *N* are frozen in Capture, enzymes compute and stage changes during Compute, and those changes become visible at beat *N+1* during Commit. No observer can see half‑baked work. 

* **Isolation by construction**
  Because no one can “peek” into the current beat’s staging area, replay and replication stay deterministic: re‑running the same impulse stream yields the same sequence of states and CEI facts.

* **Driving the heartbeat**
  The `cep_heartbeat_*` helpers coordinate beats; bootstrap and shutdown show up as `op/boot` and `op/shdn` dossiers under `/rt/ops/<boot_oid>` and `/rt/ops/<shdn_oid>`. Those branches record state transitions (`ist:*`), final status (`sts:*`), and notes for each lifecycle step. 

---

### Stored procedures vs. enzymes

* **Enzymes ≈ deterministic stored procedures**
  An enzyme is a deterministic callback with metadata: which path it listens on, whether it’s idempotent, and what it depends on. Descriptors live under `/enzymes/**`, and bindings attach them to subtrees, similar to “execute this packaged procedure whenever rows under this table change.” 

* **Routing instead of explicit calls**
  You don’t normally call enzymes directly. Instead, you:

  1. Register an enzyme descriptor (`cep_enzyme_register`).
  2. Bind it to a subtree with `cep_cell_bind_enzyme` (exact or prefix match, propagate or not).
  3. Let the heartbeat resolve which enzymes should run when a signal or mutation touches that tree.

  The dispatcher resolves bindings along the ancestry, intersects them with signal matches (`sig_cell/op_add`, `CEP:sig_sys/init`, etc.), topologically sorts the enzyme graph (respecting dependencies), and records the agenda under `/rt/beat/<n>/agenda`. Circular dependencies surface at registration time instead of mid‑beat. 

* **Episodes for long‑running work**
  When a PL/SQL job would run for many seconds or minutes, CEP models it as an **episode** (`op/ep`) tracked in `/rt/ops/**`: each slice runs within a beat budget, can yield/await, and carries cancellation and usage limits. Think “DBMS_SCHEDULER job with explicit checkpoints,” but fully replayable. 
  
---

### Namepool vs. dictionary tables

* **Tags are short; names are interned**
  CEP tags stay intentionally short and regular; when you need longer or user‑defined identifiers, you store them in the **namepool**, which behaves like a dictionary table keyed by a compact reference (`CEP_NAMING_REFERENCE`). 

* **Think `NAME_ID` support tables**
  Conceptually, `cep_namepool_*` helpers are your `REF_NAME`, `PRIMARY_NAME`, or `DISPLAY_NAME` tables: you intern a string once, get an opaque ID, and use that ID everywhere. When tags need glob semantics, use `cep_namepool_intern_pattern*` so the runtime treats them as patterns (`CEP_ID_GLOB_MULTI`) instead of literals.  

---

### Error handling and CEI (Common Error Interface)

* **From `RAISE_APPLICATION_ERROR` to CEI facts**
  Layer 0 ships a Common Error Interface (CEI). Instead of raising exceptions inside the kernel, you call `cep_cei_emit()` to build a structured error fact and drop it into a mailbox (default `/data/mailbox/diag`). 

* **Structured diagnostics**
  A CEI fact captures:

  * severity (`sev:fatal|crit|usage|warn|debug`),
  * topic (`transport/*`, `persist.*`, `sec.edge.deny`, etc.),
  * note, origin, optional subject link,
  * beat and timestamps, and optional payload references.

  `sev:crit` and `sev:fatal` can also close OPS dossiers with `sts:fail` and trigger deterministic shutdown, similar to an unhandled exception terminating a PL/SQL session—but with explicit evidence attached. 

* **Signals for reactive error handling**
  You can ask CEI to also emit `sig_cei/<severity>` impulses. Packs that need custom pipelines for error handling can bind enzymes to those signals or to a pack‑owned mailbox instead.

---

### Replacing packages with packs and branches

* **Package state → `/data/<pack>` subtree**
  A PL/SQL package’s global variables, configuration tables, and caches become a branch under `/data/<pack>` with child stores for config, caches, derived facts, and indices. Each piece of state is an explicit cell, with history and provenance. 

* **Procedures → enzymes and helpers**

  * Package procedures that respond to events become enzymes bound on your branch.
  * Private helper functions become C helpers operating directly on cells and stores.
  * Long‑running procedures become episodes (`op/ep`) or pack‑defined ops tracked under `/rt/ops/**`. 

* **Bootstrap/shutdown discipline**
  Kernel bootstrap (`cep_l0_bootstrap`) and shutdown (`cep_heartbeat_emit_shutdown`) must succeed even if no packs are present. Your pack exposes explicit `*_bootstrap()` / `*_shutdown()` helpers, publishes readiness through its own OPS dossier or subtree, and treats registration as idempotent.  

---

### Schema migrations and data movement

* **Forward‑only migrations by design**
  Because cells and stores are append‑only, structural changes look like forward‑only schema migrations: introduce new shapes, backfill them via enzymes, and optionally garbage‑collect old branches once you’re sure nothing links to them. 

* **Recording reforms**
  You can model migrations as “reform stories” in branch‑specific subtrees (for example, `/data/<pack>/flow` or `/data/<pack>/migrations`) that record which beats applied which changes. This is the CEP analogue of keeping migration scripts in version control and a schema version table in the database.

* **Export/import instead of datapump**
  For moving state between environments, rely on CPS and the flat serializer instead of ad‑hoc dump scripts: 

  * Use `op/sync` to export a branch bundle (includes frames and CAS blobs) with integrity checks.
  * Use `op/import` to verify and stage that bundle on another node.
  * At finer granularity, `cep_serialization_emit_cell` and the flat reader/writer APIs let you stream individual subtrees through arbitrary transports.
Here is the missing piece you asked for — a concise, accurate addition explaining that **CPS can sit on top of SQL or KV engines**, grounded in the implementation reference.

You can drop this directly into the earlier document (for example under **“Schema migrations”**, **“Persistence,”** or **“Replacing packages”**), or I can reintegrate it into the full file for you.

---

## CPS Backends: SQL and Key–Value Engines

Although CEP ships a portable **flatfile CPS engine** by default, the **CPS contract does *not*** require a filesystem backend. The kernel talks to CPS through a capability-negotiated vtable (`cps_engine`), and any storage technology that implements that interface can serve as a durable branch engine.

Most importantly:

### **SQL databases and KV stores *can be used as CPS backends***

Nothing in CEP requires a byte-addressable flatfile. A CPS engine needs to support:

* **Beat-atomic commits** (`begin_beat`, `commit_beat`, `abort_beat`),
* **Record writes** (`put_record`),
* **Record lookup & prefix-scan**,
* **Checkpoint/compact/import/export hooks**,
* **Capability advertisement** (CRC32C, Merkle, AEAD, deflate, CAS dedup, namepool maps, history windows, remote backends).

A relational engine (e.g., Postgres, Oracle) or a KV engine (e.g., RocksDB, FoundationDB, LMDB, TiKV) can implement these easily:

### How SQL/KV backends map to CPS requirements

| CPS responsibility           | SQL/KV implementation notes                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------- |
| **Append beat frames**       | Table or KV prefix keyed by `(branch, frame_id)` storing flat frames or chunked pages. |
| **Atomic commit**            | Use DB transactions or KV atomic batches to commit each beat as a single unit.         |
| **Prefix scans**             | Map to index scans or ordered key ranges.                                              |
| **CAS blobs**                | Store large payloads in a dedicated BLOB/CAS table or KV namespace.                    |
| **Checkpoints / compaction** | SQL VACUUM / partitioning, or KV compaction APIs.                                      |
| **Capabilities**             | Expose supported checksum/compression/encryption features via engine metadata.         |

The implementation reference explicitly notes that engines may advertise **`remote backends`**, **AEAD**, **deflate**, **CAS dedup**, **history windows**, and more. Nothing constrains them to local filesystems.

### Why this matters for PL/SQL developers

If your organization already runs Oracle/Postgres/MySQL:

* You can **write a CPS engine** that persists each branch’s flat frames into your DB.
* SQL-side replicas, backups, PITR, and audits continue working as before.
* CEP still sees the engine as fully deterministic because the frame format and beat ordering remain unchanged.

If your infrastructure prefers KV stores:

* A KV engine can store frames in a log-structured fashion,
* and keep CAS blobs in a sibling namespace,
* while CPS retains beat-atomic semantics.

---

## Global Q&A

### Can I still rely on declarative constraints?

CEP layer 0 does **not** enforce SQL‑style declarative constraints (FKs, CHECKs, etc.). Invariants are modeled as enzymes and pack‑level policies that run each beat, plus higher‑layer packs (coherence, governance) when those arrive. Think of it as moving from:

```sql
ALTER TABLE ... ADD CONSTRAINT ...
```

to “register a deterministic hook that enforces this rule every beat.” 

---

### Where do I log?

* **Diagnostics**
  Use `cep_cei_emit()` for structured diagnostics; by default, CEI facts land in `/data/mailbox/diag`. Packs can route them into pack‑owned mailboxes if they need private channels or different retention policies. 

* **Operational audit trails**

  * `/journal/**` already captures effect logs for external I/O (reads/writes, hashes, offsets, etc.).
  * `/rt/ops/**` captures lifecycle and operation timelines (boot/shutdown, persistence, async IO, episodes, pack‑defined ops).

  If you need additional, domain‑specific logs, prefer branches under `/journal/<pack>` or pack‑specific mailboxes over new “log tables.” Most audit use cases can be satisfied with mailboxes + CEI + existing journals.  

---

### How do I run something at startup, like an `AFTER STARTUP` trigger?

Register an enzyme on the `CEP:sig_sys/init` signal and bind it to the subtree that needs initialization. The heartbeat emits that signal on the first beat, so your enzyme can: 

* seed namespaces under `/data/<pack>`,
* prime caches,
* register organs or secondary enzymes,
* and publish readiness under a pack‑owned OPS dossier once everything is in place. 

---

### What happens to long transactions or session state?

* **Long transactions → episodes or state machines**
  Instead of a multi‑second transaction holding locks, model the steps as:

  * state cells under `/data/<pack>/ops/**` or `/rt/ops/<oid>`, and
  * enzymes/episodes that advance the state one beat at a time.

  Long‑running external work is tracked as episodes with budgets and cancellation, showing up as `op/ep` dossiers with history. 

* **Session‑like state**

  * Transient scratch goes under `/rt/beat/<n>` or `/tmp/**`.
  * Anything you need to survive restarts belongs under `/data/**` with explicit lifecycle rules.

  Think “no hidden package globals”: if it matters, it’s a cell.

---

### Can I execute raw SQL or keep legacy PL/SQL around?

Layer 0 itself is C‑only and doesn’t ship a SQL engine, but it’s designed to coexist with one: 

* Treat existing PL/SQL components as **external services**.
* Capture inputs into cells (requests, parameters, preconditions).
* Call the legacy code via adapters or sidecar processes.
* Record intent and outcome in `/journal/**` and stage outputs back into `/data/**` through the heartbeat so replay remains deterministic.

This way, CEP owns the **evidence and orchestration**, while PL/SQL continues to own domain logic until you gradually migrate it into enzymes and packs.

---

If you think “tables → branches, rows → cells, packages → packs/enzymes, commits → beats,” you’re already most of the way to reading CEP’s tree like a schema and its heartbeats like a carefully controlled commit loop.
