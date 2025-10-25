# CEP for PL/SQL Developers

If you know how to keep Oracle packages humming, you already understand most of CEP’s rhythm. Think of it as a runtime that always journals its mutations, feeds messages through a persistent impulse ledger, and lets you swap “stored procedures” without breaking determinism. This guide translates the familiar PL/SQL instincts into CEP’s layer-zero vocabulary so you can stay productive while the environment shifts from databases to beats.

## Technical Details
- **Data model: tables vs. cells**
  - CEP cells feel like rows whose primary key is a Domain/Tag pair. Child stores behave like embedded tables; you pick the storage engine (linked list, dictionary, hash, octree) in the same way you would choose an index or materialized view. Instead of `INSERT/UPDATE` statements, mutations append new timeline entries so every historical state remains queryable.
  - Collections under `/data/**` mirror schema-owned tables. `/sys/**` is roughly `USER_TAB_COLUMNS` plus control metadata, `/rt/**` is a redo buffer you can keep or disable, and `/cas/**` behaves like a secure BLOB store.

- **Transactions vs. beats**
  - PL/SQL commits group work; CEP beats do the same but in three explicit phases (Capture → Compute → Commit). Everything you stage in Compute becomes visible in the next beat. No one can “peek” at uncommitted work, which keeps replication and replay deterministic.
- `cep_heartbeat_begin()` starts a cycle, `cep_heartbeat_step()` advances it, and lifecycle scopes publish their state transitions through the `/rt/ops/<boot_oid>` and `/rt/ops/<shdn_oid>` operation branches.

- **Stored procedures vs. enzymes**
  - An enzyme is a deterministic callback registered on a path (`CEP:sig_cell/op_add`, `CEP:sig_sys/init`, etc.) and bound to a subtree. Think of it as a packaged procedure with a declarative routing rule instead of an explicit call.
  - `cep_enzyme_register()` installs the descriptor (metadata + before/after dependencies) and `cep_cell_bind_enzyme()` is your synonym for “attach this procedure to that schema object.” Because the heartbeat resolves enzyme graphs ahead of execution, circular dependencies are surfaced as soon as you register.

- **Mailroom as message queue**
  - The old `/data/inbox/**` lobby was removed. Packs that still need a fan-out queue must register their own routing enzymes (reuse `cep_txn_*` if you want the same veiled staging) and track any dispatcher follow-up in your pack’s backlog or roadmap instead of sprinkling placeholder TODO notes in code.

- **Namepool vs. dictionary tables**
  - Instead of `USER_OBJECTS`, CEP tracks identifiers through `cep_namepool_*` helpers. Interpreting a `CEP_NAMING_REFERENCE` is similar to looking up a `NAME_ID` in a support table. Use the namepool when your identifiers exceed the 11-character word limit or when you need glob-aware patterns (`CEP_ID_GLOB_MULTI`).

- **Error handling and CEI**
  - Layer 0 now ships the Common Error Interface. Call `cep_cei_emit` when you would have raised an exception: it builds a structured error fact, drops it into the diagnostics mailbox at `/data/mailbox/diag`, and can optionally emit `sig_cei/*` signals or close OPS dossiers. Packs that need private channels can still create their own mailboxes; just pass the root into `cep_cei_emit`.

- **Replacing packages**
  - Migrate package state by modelling it as a subtree under `/data/<package>` with child stores for configuration, caches, and derived facts. Package procedures map to enzymes and helper functions map to plain C utilities that operate on cells.
  - The rendezvous scheduler was removed. Model long-running jobs inside your own pack, coordinating beats through pack-owned state machines or backlog-tracked follow-up work.

- **Testing mind-set**
  - Unit tests ship with the repository (see `src/test/l0_kernel`) and rely on munit. Harness helpers such as `test_boot_cycle_prepare` mimic packages that rerun initialization blocks. When you need a PL/SQL-like fixture (set up schema, run procedure, assert tables), use the heartbeat boot helpers, mutate the tree, and inspect `/data/**` or `/journal/**`.

- **Schema migrations**
  - Because CEP is append-only, structural changes resemble forward-only migrations. Use enzymes to emit reform stories under `/data/flow/**` or `/data/err/**`; serialization snapshots (`cep_serialization_emit_cell`) replace your datapump exports when you need to move state between environments.

## Global Q&A
- **Can I still rely on declarative constraints?**  
  CEP layer zero does not enforce SQL constraints. You model invariants with enzymes or upper-layer packs. Think of it as moving from `ALTER TABLE ... ADD CONSTRAINT` to deterministic hooks that run each beat.

- **Where do I log?**  
  Emit diagnostics with bespoke enzymes under a pack-owned journal branch (for example, `/journal/<pack>`). Since every mutation is already journaled, avoid extra tables for audit trails unless you need a different projection.

- **How do I run something at startup like an `AFTER STARTUP` trigger?**  
  Register an enzyme on `CEP:sig_sys/init`. The heartbeat queues the signal on the first beat, giving you a clean hook to prime caches or seed pack-specific namespaces before other work begins.

- **What happens to long transactions or session state?**  
  Break them into deterministic beats. Since rendezvous helpers were retired, keep long-running external work inside pack-owned cells (beats, telemetry, completion state) and drive it with enzymes that revisit the branch each heartbeat. Session buffers can live under `/rt/beat/<n>` for transient data or `/tmp/**` when you need explicit teardown.

- **Can I execute raw SQL or keep legacy PL/SQL around?**  
  Layer zero is C-only, but nothing stops you from embedding a SQL engine above it. Treat PL/SQL components as external services: capture inputs into cells, call the legacy code, then stage outputs back through the heartbeat so replay and journaling stay intact.
