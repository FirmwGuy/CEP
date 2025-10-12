# CEP for PL/SQL Developers

If you know how to keep Oracle packages humming, you already understand most of CEP’s rhythm. Think of it as a runtime that always journals its mutations, feeds messages through a persistent inbox, and lets you swap “stored procedures” without breaking determinism. This guide translates the familiar PL/SQL instincts into CEP’s layer-zero vocabulary so you can stay productive while the environment shifts from databases to beats.

## Technical Details
- **Data model: tables vs. cells**
  - CEP cells feel like rows whose primary key is a Domain/Tag pair. Child stores behave like embedded tables; you pick the storage engine (linked list, dictionary, hash, octree) in the same way you would choose an index or materialized view. Instead of `INSERT/UPDATE` statements, mutations append new timeline entries so every historical state remains queryable.
  - Collections under `/data/**` mirror schema-owned tables. `/sys/**` is roughly `USER_TAB_COLUMNS` plus control metadata, `/rt/**` is a redo buffer you can keep or disable, and `/cas/**` behaves like a secure BLOB store.

- **Transactions vs. beats**
  - PL/SQL commits group work; CEP beats do the same but in three explicit phases (Capture → Compute → Commit). Everything you stage in Compute becomes visible in the next beat. No one can “peek” at uncommitted work, which keeps replication and replay deterministic.
  - `cep_heartbeat_begin()` starts a cycle, `cep_heartbeat_step()` advances it, and lifecycle scopes emit the equivalent of trigger log entries under `/journal/sys_log`.

- **Stored procedures vs. enzymes**
  - An enzyme is a deterministic callback registered on a path (`CEP:sig_cell/op_add`, `CEP:sig_sys/init`, etc.) and bound to a subtree. Think of it as a packaged procedure with a declarative routing rule instead of an explicit call.
  - `cep_enzyme_register()` installs the descriptor (metadata + before/after dependencies) and `cep_cell_bind_enzyme()` is your synonym for “attach this procedure to that schema object.” Because the heartbeat resolves enzyme graphs ahead of execution, circular dependencies are surfaced as soon as you register.

- **Mailroom as message queue**
  - `/data/inbox/**` is the shared queue that replaces your polling tables. `mr_route` clones requests into per-namespace inboxes (`/data/flow/inbox/**`, `/data/coh/inbox/**`) and enriches them with standard headers (`original`, `outcome`, `meta/parents`). If you ever built an `INBOUND_REQUESTS` table with triggers to fan out work, the mailroom is the hardened version of that pattern.

- **Namepool vs. dictionary tables**
  - Instead of `USER_OBJECTS`, CEP tracks identifiers through `cep_namepool_*` helpers. Interpreting a `CEP_NAMING_REFERENCE` is similar to looking up a `NAME_ID` in a support table. Use the namepool when your identifiers exceed the 11-character word limit or when you need glob-aware patterns (`CEP_ID_GLOB_MULTI`).

- **Error handling and CEI**
  - CEI (CEP Error Impulses) will emit failures as structured cells under `/data/err/**` with a deterministic routing tag (`sig_err`). Replace your `raise_application_error` calls with `cep_error_emit()` once the CEI APIs land; the payload will contain `code`, `message`, and references to the offending parents.

- **Replacing packages**
  - Migrate package state by modelling it as a subtree under `/data/<package>` with child stores for configuration, caches, and derived facts. Package procedures map to enzymes and helper functions map to plain C utilities that operate on cells.
  - Declarative policies (timeouts, kill modes, grace periods) live alongside rendezvous entries. What used to be a `DBMS_SCHEDULER` job becomes a rendezvous entry with `due`, `deadline`, and `grace_*` fields.

- **Testing mind-set**
  - Unit tests ship with the repository (see `src/test/l0_kernel`) and rely on munit. Harness helpers such as `test_boot_cycle_prepare` mimic packages that rerun initialization blocks. When you need a PL/SQL-like fixture (set up schema, run procedure, assert tables), use the heartbeat boot helpers, mutate the tree, and inspect `/data/**` or `/journal/**`.

- **Schema migrations**
  - Because CEP is append-only, structural changes resemble forward-only migrations. Use enzymes to emit reform stories under `/data/flow/**` or `/data/err/**`; serialization snapshots (`cep_serialization_emit_cell`) replace your datapump exports when you need to move state between environments.

## Q&A
- **Can I still rely on declarative constraints?**  
  CEP layer zero does not enforce SQL constraints. You model invariants with enzymes, rendezvous policies, or upper-layer packs. Think of it as moving from `ALTER TABLE ... ADD CONSTRAINT` to deterministic hooks that run each beat.

- **Where do I log?**  
  Use `cep_mailroom_report_catalog_issue` or bespoke enzymes that append to `/journal/sys_log`. Since every mutation is already journaled, avoid extra tables for audit trails unless you need a different projection.

- **How do I run something at startup like an `AFTER STARTUP` trigger?**  
  Register an enzyme on `CEP:sig_sys/init`. The heartbeat queues the signal on the first beat and your enzyme can prime caches or seed mailroom namespaces before other work begins.

- **What happens to long transactions or session state?**  
  Break them into deterministic beats. Rendezvous entries encapsulate long-running external work and hold state between beats (deadline, telemetry, completion status). Session buffers can live under `/rt/beat/<n>` or `/tmp/**` depending on durability needs.

- **Can I execute raw SQL or keep legacy PL/SQL around?**  
  Layer zero is C-only, but nothing stops you from embedding a SQL engine above it. Treat PL/SQL components as external services: capture inputs into cells, call the legacy code, then stage outputs back through the heartbeat so replay and journaling stay intact.
