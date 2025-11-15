# L0 Kernel: A Quick Overview

Below is a practical, developer‑oriented overview of what this API enables, why it’s special, and how to put it to work.

---

## Executive summary

This L0 Kernel API gives you a **hierarchical, time‑aware data kernel** (“cells”) with:

* **Domain/Tag naming** that’s compact, glob‑friendly, and deterministic for routing and matching. 
* **Append‑only history** with snapshot querying (by “heartbeat” timestamps) instead of in‑place rewrites. 
* Multiple **child storage engines** (linked list, dynamic array, packed queue, red‑black tree, hash table, octree) you can swap per node. 
* **Links with backlink (shadow) tracking**, so references stay coherent through lifecycle events. 
* **Proxies and library bindings** to virtualize payloads and streams behind an adapter. 
* A **reactive “enzyme” layer** for deterministic, dependency‑aware work dispatch driven by paths and heartbeats.   
* A **beat-recorded Operations timeline** (`op/*`) with watcher support so long-running work, boot, and shutdown stay observable and awaitable.
* A **Common Error Interface (CEI)** that centralises diagnostics, routes structured Error Facts through mailboxes, and enforces severity-driven OPS/shutdown policy.
* A **pluggable federation transport manager** that negotiates capabilities, coalesces `upd_latest` gauges deterministically, and keeps `/net/mounts` plus `/net/transports` in sync with provider selections.
* A compact **flat-frame serialization** format with staged reading/commit and optional payload chunking for large blobs. 
* An optional **namepool** to intern strings when you need textual names bound to IDs. 
* **Pause / Rollback / Resume (PRR) controls** that gate non-essential work, rewind the visible beat horizon, and deterministically drain queued impulses from a mailbox-backed backlog.
* **Episodic Enzyme Engine (E³)** that runs long-lived workloads deterministically, with the ability to promote episodes from threaded RO slices to cooperative RW slices and demote them back without breaking replay or budget accounting.
* **Runtime contexts (`cepRuntime`)** so multiple CEP kernels can coexist in one process; activate an instance with `cep_runtime_set_active()` before calling the usual Layer 0 APIs.
* **CPS persistence with replay fixtures** so every beat is durably mirrored to `branch/` directories, CAS cache hits/misses get published under `/data/persist/<branch>/metrics`, and tests can regenerate deterministic flat frames and CAS blobs (`fixtures/cps/{frames,cas}`) whenever the serializer evolves. See `docs/L0_KERNEL/design/L0-DESIGN-CPS.md` for the full architecture and `docs/L0_KERNEL/L0-INTEGRATION-GUIDE.md` (§2.5) for the regeneration flow.


Together, these pieces let you build **local‑first trees, reactive dataflows, digital‑twin graphs, scene graphs with spatial indexing, and distributed state pipelines**—without giving up determinism, history, or zero‑copy performance where it matters.

---

## Topics Overview

Each linked topic digs into a specific subsystem of Layer 0. Use this map to decide which deep-dive to read before changing kernel code or wiring new integrations.

### Append-Only and Idempotency
This topic tracks how Layer 0 preserves deterministic history for both payloads and structure. It explains the twin timelines (`cepData` for bytes, `cepStore` for children), how timestamps reconstruct past states without cloning trees, and why duplicate updates short-circuit instead of forking history. Use it whenever you need to reason about replay, soft versus hard deletes, or store snapshot costs.

### Cell-Bound Enzyme Bindings
Layer 0 stores enzyme bindings on cell timelines so work dispatch honours ancestry and tombstones. The bindings topic walks through propagation flags, inheritance rules, and how tombstone entries mask older registrations. Read it before editing binding persistence or introducing new dispatch helpers.

### Cell-Operations Enzymes
Standard organ and cell operations surface as reusable enzymes. This chapter documents the supported verbs, required signal shapes, and the invariants the kernels expect callers to maintain. Lean on it when wiring automation packs or auditing which helper enzymes already exist.

### Developer Handbook
The handbook is the pragmatic orientation for contributors working inside `cep_cell.*` and its storage backends. It maps repository layout, highlights coding conventions, and lists the tests and fixtures that prove new work. Consult it whenever you are preparing a kernel patch or onboarding a teammate.

### Persistence & Replay Fixtures
Layer 0’s persistence service (CPS) now expects deterministic flat serializer frames and CAS blobs. The fixture workflow lives under `fixtures/cps/` and is exercised by `/CEP/serialization/flat_payload_ref_fixtures` plus `/CEP/cps/replay/*`. Regenerate fixtures by running those tests with `CEP_UPDATE_PAYLOAD_REF_FIXTURES=1`; commits must include both the refreshed frames and blobs so replay harnesses stay hermetic. Metrics such as `cas_hits`, `cas_miss`, and `cas_lat_ns` are republished after every lookup, ensuring `/data/persist/<branch>/metrics` reflects cache behaviour even on read-heavy beats. Refer to `docs/L0_KERNEL/design/L0-DESIGN-CPS.md` (Fixture & Replay Workflow) for the rationale and to `docs/L0_KERNEL/L0-INTEGRATION-GUIDE.md` (§2.5) for the exact regeneration steps.

Today every serializer emission runs through the async fabric. `cep_flat_stream_emit_cell_async()` buffers each frame during Capture, registers `begin`/`write`/`finish` requests with `cep_io_reactor`, and publishes completions back into CPS and federation via `/rt/ops/<oid>/io_req`. CPS will not advance `ist:store` until the reactor signals success, so beats remain deterministic even when persistence backs up; overruns emit `persist.async`/`persist.async.tmo` CEI. The default reactor uses a portable worker-thread shim so targets without epoll/kqueue/IOCP continue to work, while `/rt/analytics/async/(shim|native)` plus `tp_async_unsp` CEI facts expose when the shim handles requests.

### Debug Macros
Layer 0’s debug wrappers keep guardrails active in debug builds without polluting release binaries. The debug macros topic explains when `CEP_DEBUG`, `CEP_ASSERT`, and `CEP_NOT_ASSERT` execute, how they interact with control flow, and the logging helpers that stay behind the `CEP_ENABLE_DEBUG` flag.

### External Libraries Interface
Adapters keep external handles and libraries deterministic by routing them through proxy ops. This document describes the adapter vtables, retain/release contracts, and the serialization hooks that capture library state for replay. Use it when extending or auditing handle-bearing payloads.

### Glob Matching
Domain/tag identifiers support globbing for routing and discovery. The glob guide explains the numeric encodings, wildcard sentinels, and matching rules the runtime enforces. Review it before adjusting `cep_id_matches` or adding new wildcard patterns.

### Heartbeat and Enzymes
The heartbeat topic narrates the capture → compute → commit lifecycle, impulse queues, dependency sorting, and agenda replay rules. It anchors enzyme scheduling semantics so you can reason about deterministic work ordering and beat-level safety checks.

### Federation Transport Manager
Federation mounts lean on a dedicated manager to select transports, seed `/net/mounts` and `/net/transports`, and police `upd_latest` semantics. Read the topic when editing negotiation logic, adding providers, or wiring federation enzymes that publish capability preferences.

Async I/O brings new observability to this manager. Each mount now publishes `async_pnd`, `async_shm`, and `async_nat` counters under `/net/telemetry/<peer>/<mount>/` so operators can see how many requests are inflight, how many completions ran through shim threads, and how many were satisfied by provider-native async hooks. The same data lands in `/rt/analytics/async/(shim|native)/<provider>/<mount>/jobs_total`, letting tooling subscribe to a single runtime branch when correlating OPS dossiers or CEI facts with cluster health.

### Episodic Engine (E³)
The engine described in `docs/L0_KERNEL/topics/E3-EPISODIC-ENGINE.md` lets episodes span beats, yield, await other operations, and—when configured—promote from threaded RO slices to cooperative RW slices (and demote back again) without sacrificing determinism. Read it before wiring long-lived jobs that blend read-heavy analysis with targeted mutations.

### IO Streams and Foreign Resources
Streaming payloads bridge kernel cells with foreign resources. This topic covers the effect log, CAS guarantees, chunk management, and the guardrails for mapping external handles into CEP. It is required reading before changing stream ingestion or library-backed handles.

### Links and Shadowing
Links turn the tree into a safe graph via backlinks and shadow metadata. The document details attach/detach flows, target-dead propagation, and how clones or moves rebind shadows without breaking invariants. Consult it before touching link code or designing link-heavy features.

### Locking
Layer 0 enforces deterministic mutation using hierarchical locks. The locking topic explains store/data lock scopes, ancestor scans, and the failure modes to avoid when holding locks across beats. Use it when introducing new mutation helpers or debugging concurrency issues.

### Mailbox Lifecycle
Mailbox organs now ship with shared helpers that settle message identity, TTL precedence, and retention buckets. `docs/L0_KERNEL/topics/MAILBOX-LIFECYCLE.md` documents the layout under `meta/`, the `msgs/` store, and how `cep_mailbox_select_message_id()`, `cep_mailbox_resolve_ttl()`, and `cep_mailbox_plan_retention()` cooperate with the heartbeat. Revisit it before wiring board/news workflows, private inbox policies, or retention enzymes so behaviour stays deterministic across beats and replays.

### Pause, Rollback, and Resume
Control verbs (`op/pause`, `op/rollback`, `op/resume`) give Layer 0 a deterministic control plane: they park impulses, publish a rollback horizon, roll visibility back to a prior beat, and resume by draining the backlog in ID order. `docs/L0_KERNEL/design/L0-DESIGN-PAUSE-AND-ROLLBACK.md` documents the state ladders, backlog semantics (full `cepDT` path fidelity), and cleanup guarantees you need before evolving the control code or tooling against it.

### Common Error Interface (CEI)
Layer 0’s Common Error Interface (`docs/L0_KERNEL/topics/CEI.md`) centralises diagnostics. It seeds the default diagnostics mailbox at `/data/mailbox/diag`, assembles structured Error Facts via `cep_cei_emit`, can emit `sig_cei/*` impulses, and enforces severity policy (OPS closure, fatal shutdown). Pair it with the mailbox topic before altering diagnostics routing or severity handling.

### Operations Timeline and Watchers
Operations run as append-only dossiers under `/rt/ops/<oid>` with envelopes, history, close branches, and watcher ledgers. `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md` and `docs/L0_KERNEL/design/L0-DESIGN-HEARTBEAT-AND-OPS.md` explain how `cep_op_start`, `cep_op_close`, and `cep_op_await` coordinate with lifecycle scopes and the heartbeat so packs can observe boot/shutdown progress—or stitch their own long-running work—without polling.

### Mailbox Lifecycle and Retention
Mailboxes combine deterministic message identifiers, TTL resolution, and retention buckets so backlog/pause flows stay replayable. The topic `docs/L0_KERNEL/topics/MAILBOX-LIFECYCLE.md` explains how `cep_mailbox_select_message_id()`, `cep_mailbox_resolve_ttl()`, and `cep_mailbox_plan_retention()` work together; revisit it before wiring ingestion pipelines or backlog handling so new mail stays ordered and expiries behave the same across replays.

### Native Types
Native payloads are opaque bytes labelled by compact domain/tag identifiers. This document clarifies VALUE/DATA/HANDLE/STREAM semantics, hashing rules, and how upper layers layer meaning on top. Visit it before altering payload structures or introducing new tag conventions.

### Organs Authoring
Organ descriptors register constructors, destructors, and validators that bring packs to life. The organs guide steps through descriptor fields, lifecycle expectations, and validator binding discipline so optional packs remain deterministic. Check it prior to creating new organs or refactoring descriptors.

### Proxy Cells
Proxy cells virtualise resources via adapters that snapshot and restore state during serialization. The proxy topic captures adapter responsibilities, error reporting, and lifecycle transitions. Read it when extending proxy capabilities or auditing the replay pipeline.

### Raw Traversal Helpers
Traversal helpers are evolving to add `*_all` style APIs. This roadmap outlines the planned interfaces, invariants, and compatibility goals. Use it to coordinate traversal work and avoid diverging from the agreed successor APIs.

### Serialization and Streams
Serialization describes the manifest layout, chunk framing, hash strategy, and apply process that keep replicas faithful. It explains how staged transactions commit atomically and how proxies participate. Review it before extending the wire format or building ingestion tooling.

### Startup and Shutdown
Lifecycle operations (`op/boot` and `op/shdn`) replace ad-hoc signals. `docs/L0_KERNEL/topics/STARTUP-AND-SHUTDOWN.md` walks through the lifecycle scopes (`kernel`, `store`, `packs`), the bootstrap entry points (`cep_l0_bootstrap`, `cep_heartbeat_configure`, `cep_heartbeat_startup`, `cep_heartbeat_begin`), and the orderly teardown path so packs can synchronise safely. It also covers heartbeat wallclock capture and the watcher APIs that surface state changes without polling. Re-read it before modifying lifecycle helpers or writing tooling against the operation timelines.

---

## Core concepts

Layer 0 is built from a handful of durable ideas—cells, DT naming, stores, links, proxies, heartbeats, and episodic work. This section collects the “must-know” primitives you should internalise before modifying the kernel or building against it.

### 1) Cells: data + children (with time)

A **cell** is the unit of structure. A cell can hold:

* a **payload** (VALUE, DATA, HANDLE, or STREAM), and/or
* a **child store** (one of several storage engines).

Every cell carries **Domain/Tag (DT)** metadata and timestamps for *created/modified/deleted*, enabling history queries (“as of beat N”). The header makes these types and macros explicit (e.g., `cepCell`, `cepData`, `cepStore`, `cepDT`, `cepPath`, `CEP_WORD`, `CEP_ACRO`, `CEP_ID_GLOB_*`, etc.). 

The implementation emphasizes **append‑only** semantics: most observable history is encoded in **timestamps**; reindexing events snapshot structure only when the indexing scheme changes. That lets you replay or query previous states without destructive rewrites. 

You get a persistent, queryable history “for free,” plus clean semantics for deterministic iteration and auditing.

---

### 2) Naming that routes (Domain/Tag + globs)

The DT scheme packs two 58‑bit fields—`domain` and `tag`—and supports **word**, **acronym**, **reference**, and **numeric** encodings with compile‑time helpers (`CEP_WORD("users")`, `CEP_ACRO("SYS")`, etc.). Word tags may include a literal `*`; the runtime stamps a glob bit so helpers such as `cep_id_matches` expand the wildcard when comparing segments. For whole-domain/prefix globs the legacy sentinels (e.g., `CEP_ID_GLOB_MULTI`) still apply. 

To complement that, the **namepool** can intern text and map it to “reference” IDs when you need textual identity across the system (`cep_namepool_intern*`, `cep_namepool_lookup`). 

You can address and filter data and signals with compact, routable paths—perfect for enzyme dispatch, replication, and observability.

---

### 3) Child storage, indexing, and ordering

Each cell’s children live in a **store** you pick per node:

* Linked list, dynamic array, packed queue, red‑black tree, hash table, **octree**.
* Indexing policies: **insertion order**, **by name**, **by custom compare**, or **by hash + compare** (dictionary/sorted/hashed/spatial). 

The engine enforces the **append‑only contract**: e.g., normal mutations preserve sibling order and use timestamps to log history; **reindexing** (dictionary or comparator sort) snapshots the prior layout once for historical traversal. 

You tailor data structures per branch (queues, sorted catalogs, spatial indexes) and still keep consistent history semantics.

---

### 4) Links and shadowing (backlink bookkeeping)

Links are first‑class cells pointing to other cells. The runtime **tracks backlinks** (“shadows”), marks **linkers as ‘targetDead’** on deletion, and cleans/rebinds shadows on moves and clones (e.g., hard finalize vs. soft delete). This is handled internally (attach, detach, break all, rebind) so topology and lifecycle remain coherent. 

You can alias, fan‑out, and refactor trees without orphaning references or leaking invariants.

---

### 5) Proxies & libraries (virtual payloads and streams)

The proxy and library bindings let you **virtualize cell payloads** (handles/streams) behind adapters (`cepLibraryOps` and `cepProxyOps`). You can snapshot/restore proxy state for serialization, map stream windows, and retain/release handles through the library interface. 

Cells can represent **external resources** (files, GPU buffers, remote handles) with lifecycles managed by adapters—yet they remain first‑class in trees and serialization.

---

### 6) Heartbeats and enzymes (reactive, deterministic work)

The **heartbeat** provides a global beat number and impulse queue plumbing so the system can **stage signals** and **drive deterministic cycles**. 

Every beat now records a Unix timestamp (`/rt/beat/<N>/meta/unix_ts_ns`) via the mandatory wallclock capture pipeline. Callers publish the timestamp using `cep_heartbeat_publish_wallclock()`, read it back with `cep_heartbeat_beat_to_unix()`, and can resize the retention window for spacing analytics through `cep_heartbeat_set_spacing_window()`. Stage notes, OPS history entries, and stream journals automatically embed the captured `unix_ts_ns`, keeping textual diagnostics aligned with beat counters.

On top, **enzymes** are your **work units**: you register descriptors with a DT name, label, **before/after dependencies**, flags (idempotent/stateful/emit‑signals), and a **match policy** (exact or prefix). The registry **defers activation** of new registrations until the next beat (freezing the current agenda), and **resolves** work by intersecting target‑bound bindings with signal‑indexed candidates, ranking by **specificity**, and then doing a stable **topological sort** by dependencies.  

You get a **reactive dataflow kernel** that respects ordering constraints, reproducibility, and “nothing changes mid‑cycle” guarantees.

For multi-beat work, the **Episodic Enzyme Engine (E³)** builds on this loop. `cep_ep_start()` captures the signal/target metadata in an `op/ep` dossier, slices queue through the cooperative executor (`cep_executor_submit_ro()` today, threaded backends later), and `cep_ep_yield()` / `cep_ep_await()` use watchers to park until the continuation enzyme fires. `cep_ep_close()` and `cep_ep_cancel()` seal the dossier with `sts:ok` or `sts:cnl` while mutation helpers consult the TLS context (`cep_ep_require_rw`, `cep_ep_check_cancel`, `cep_ep_account_io`) so read-only slices stay safe and CEI records guard or budget violations. RW episodes claim mutation rights explicitly via `cep_ep_request_lease()` / `cep_ep_release_lease()`, which normalise cell paths, lock the relevant stores/data, and let the owning slice proceed while other contexts bail out cleanly. See `docs/L0_KERNEL/topics/E3-EPISODIC-ENGINE.md` for the lifecycle walkthrough and `docs/L0_KERNEL/design/L0-DESIGN-E3-EPISODIC-ENGINE.md` for design rationale and backend guarantees.

Mailbox retention hooks into the same cadence. Mailbox helpers resolve per-message TTLs against mailbox policy (message → mailbox → topology, with private inboxes pinning `ttl_mode="forever"`), stash beat and wallclock deadlines under `meta/runtime/expiries*`, and hand enzymes ready-to-run partitions each beat—all while honouring heartbeat spacing analytics when wallclock-only deadlines need a projected beat. Debug switches let you freeze the heuristics during instrumentation, but the defaults stay deterministic and replay-safe.

---

### 7) Serialization & streaming

The serializer emits a **record header** (magic, version, endianness, optional metadata), a **manifest** (path + flags), **data** (inline or chunked BLOBs), **library** snapshots for proxies, and a **frame trailer** that certifies integrity/capabilities. The reader **stages** records and only **commits** when the trailer arrives. It validates hashes and reconstructs cells (creating parents as needed) before applying payloads or proxy snapshots. 

You can **stream** parts of your tree over files/sockets, resume, validate, and apply atomically.

---

## What you can build (examples of potential)

* **Local‑first document/graph stores** with built‑in history and path addressing (dictionary or tree branches).  
* **Reactive pipelines** (“when `/signal/users/*` arrives, run indexer before aggregator, then commit”).  
* **Digital twins / scene graphs** leveraging the **octree** store for spatial indexing. 
* **Replicated state** across processes or machines via staged **flat serialization**. 
* **Resource graphs** where nodes are **proxies** to external handles and streams (files, sockets, GPU buffers) with snapshot/restore semantics. 
* **Audit‑friendly systems** where history is kept as timestamps and can be replayed or queried at a beat (“as of” semantics). 

---

## Quickstart recipes

> The code below is intentionally compact to illustrate the patterns. Names use `CEP_WORD/CEP_ACRO` helpers and DT macros from the public headers. 

### A) Build a typed dictionary and add data

```c
// 1) Init and get root
cep_cell_system_initiate();
cepCell* root = cep_root(); // Global root cell.  :contentReference[oaicite:31]{index=31}

// 2) Make a dictionary of "users"
cepDT usersName = *CEP_DTWW("app", "users");
cepDT usersType = *CEP_DTWW("app", "user");     // children type label
cepCell* users = cep_dict_add_dictionary(root, &usersName, &usersType, CEP_STORAGE_RED_BLACK_T); // sorted dict  :contentReference[oaicite:32]{index=32}

// 3) Insert a user with a value payload
cepDT userName = *CEP_DTWW("user", "alice");
char payload[] = "Alice Example";
cep_dict_add_value(users, &userName, CEP_DTWW("type","string"),
                   payload, sizeof(payload)-1, sizeof(payload)-1); // VALUE payload  :contentReference[oaicite:33]{index=33}
```

* The dictionary runs in a red‑black tree with **name indexing**, so lookups are O(log n). You could switch to **insertion order** or **hash + compare** by changing parameters. 
* Edits don’t rewrite history; they advance timestamps. Use `_past` APIs to read as‑of snapshots. 

---

### B) Snapshot queries (“as of” a heartbeat)

```c
// Fetch the first child 'as it was' at a given snapshot beat:
cepOpCount snapshot = /* some beat */ ;
cepCell* u = cep_cell_first_past(users, snapshot);        // snapshot-aware traversal  :contentReference[oaicite:36]{index=36}
void*    v = cep_cell_data(u);                            // live payload pointer      :contentReference[oaicite:37]{index=37}
```

Many find/next/traverse functions have `_past` variants that respect **created/deleted** and data/store **timeline** fields. 

---

### C) Reactive enzymes (deterministic dispatch)

Register a named enzyme that matches a **signal path prefix** and requires `indexer` to run before `aggregator`. Bind it to the `users` subtree so it’s considered when targets lie under that branch.

```c
// 1) Build a signal query path: signal/app/users/*
cepPath* q = cep_malloc(sizeof(cepPath) + 2*sizeof(cepPast));
q->length = 2;
q->past[0].dt = *CEP_DTWW("signal","users");
q->past[1].dt = (cepDT){ .domain = CEP_ID_GLOB_MULTI, .tag = CEP_ID_GLOB_MULTI }; // glob  :contentReference[oaicite:39]{index=39}

static int on_users_signal(const cepPath* sig, const cepPath* target) {
    // ... do work ...
    return CEP_ENZYME_SUCCESS;
}

cepDT NAME_INDEXER = *CEP_DTWA("E","indexer");
cepDT NAME_AGG     = *CEP_DTWA("E","aggregator");

// 'indexer' descriptor (idempotent) that should run before 'aggregator'
cepEnzymeDescriptor indexer = {
  .name = NAME_INDEXER, .label = "index users",
  .before = NULL, .before_count = 0,
  .after = NULL,  .after_count = 0,
  .callback = on_users_signal,
  .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
  .match = CEP_ENZYME_MATCH_PREFIX
};

// register now (activation happens either immediately or next beat, deterministically)
cepEnzymeRegistry* reg = cep_enzyme_registry_create();
cep_enzyme_register(reg, q, &indexer);                                         // registry API  :contentReference[oaicite:40]{index=40} :contentReference[oaicite:41]{index=41}

// bind by name on the target subtree so resolve can intersect bindings with signal matches
cep_cell_bind_enzyme(users, &NAME_INDEXER, /*propagate*/true);                  // binding API   :contentReference[oaicite:42]{index=42}
```

At resolve time, the runtime merges **bindings from target ancestry** (propagate vs. tombstone), finds signal matches by **prefix/exact**, chooses the **most specific** candidates, and performs a **stable topological sort** honoring `before/after`. New registrations made mid‑beat are queued and **activated next beat** so the agenda is frozen while executing. 

> Heartbeat plumbing (impulse queues and path cloning) underpins this cycle orchestration. 

---

### D) Streaming a cell over the wire (flat frames)

```c
// Writer callback used by the emitter
static bool write_chunk(void* ctx, const uint8_t* bytes, size_t n) {
    FILE* f = (FILE*)ctx;
    return fwrite(bytes, 1, n, f) == n;
}

// Emit one cell (with optional BLOB chunking)
cepSerializationHeader hdr = { .byte_order = CEP_SERIAL_ENDIAN_BIG };
FILE* out = fopen("cell.bin", "wb");
cep_flat_stream_emit_cell(users, &hdr, write_chunk, out, /*blob payload*/ 64*1024);  // emit chunks  :contentReference[oaicite:45]{index=45}
fclose(out);
```

On the receiving side, you **ingest** records (in any stepwise manner), and **commit** once the trailer is seen. The reader validates sizes/hashes, reconstructs the path (creating parents as needed), and restores either **inline data** or **proxy snapshots**. 

---

### E) Proxies and external resources

Wrap an external stream behind a library binding. Your `cepLibraryOps` implements `stream_read/write/map/unmap` and snapshot/restore for **handles/streams** (payload types). Cells then act as first‑class **proxies** to those resources, including **serialization** of proxy snapshots. 

---

## Design choices that unlock potential

* **Idempotency and append‑only history.** Most “writes” create a new point on a timeline; readers can ask “as of beat X” without branching logic. Reindexing captures a one‑time snapshot of layout to preserve historical traversal; normal operations rely solely on timestamps. 
* **Deterministic dispatch.** Enzyme activation is postponed until the next beat when registration happens mid‑cycle; resolution ranks by specificity and performs a topological sort on named dependencies. Reproducible agendas are a default. 
* **Local performance knobs.** Per‑branch storage engines let you optimize hot paths (e.g., append‑heavy queues vs. sorted catalogs vs. spatial indices). 
* **First‑class links and proxies.** References (with shadow tracking) and virtualized payloads keep graphs flexible while maintaining lifecycle invariants.  

---

## Veiled transactions & visibility masks

Veiled subtrees let you build a complex branch exactly where it belongs while keeping curious readers unaware that anything is happening. You can still peek behind the curtain when you need to, but the default view stays calm until you decide to unveil the work.

### Technical details
- Each cell now carries a `veiled` flag (previously the “hidden” bit). Default helpers such as `cep_cell_first`, `cep_cell_find_by_name`, and the shallow/deep traversal APIs consult this flag through `cepVisibilityMask`, so callers only see unveiled data unless they explicitly request otherwise.
- `cep_cell_visible_latest/past` expose the visibility mask so diagnostics and tooling can opt into veiled nodes without rewriting traversal code. `CEP_VIS_INCLUDE_VEILED` lifts the curtain; `CEP_VIS_INCLUDE_DEAD` replays tombstoned nodes alongside the usual history filters.
- The transaction helpers (`cep_txn_begin`, `cep_txn_mark_ready`, `cep_txn_commit`, `cep_txn_abort`) stage a new dictionary child directly under the final parent, mark the entire subtree veiled, and emit `meta/txn/state` breadcrumbs (`building → ready → committed/aborted`). Commit walks the subtree once, stamps missing timestamps, lifts the veil, and records a heartbeat stage note so observers can match the event to a beat.
- Link plumbing enforces the boundary: top-level veiled roots cannot be linked while veiled, and veiled descendants only accept links from inside the same veiled ancestor. Store insertion paths inherit the veil automatically so any child attached during the transaction stays hidden until commit.

## Operational notes & guardrails

* **Locking:** coarse flags exist for child stores and data payloads (`cep_store_lock/cep_data_lock`) and are checked up the ancestry to prevent unsafe mutations. These are **in‑tree logical locks**, not OS‑level primitives; coordinate your own threading policy. 
* **Soft vs. hard delete:** soft delete stamps timestamps and preserves history; “hard” variants drop memory (and can reorganize siblings) and are used for GC paths. Pick based on audit requirements. 
* **Cloning semantics:** VALUE/DATA clone by copy; HANDLE/STREAM clones appear as **links** to the original to keep external resources authoritative. 
* **Glob semantics:** enzyme path matching uses DT comparison with wildcard-aware word tags (single-segment `*`) and the reference sentinels (`CEP_ID_GLOB_*`) to match domains/tags flexibly.  
* **Namepool:** use it when you need text‑to‑ID indirection for `CEP_NAMING_REFERENCE` identifiers; remember to release IDs you no longer need. 
* **Lifecycle pulses:** each bootstrap flips `/sys/state/<scope>` to `"ready"`, emits `CEP:sig_sys/ready/<scope>`, and shutdown does the inverse via `CEP:sig_sys/teardown/<scope>` plus `status="teardown"`. Tools can poll the state tree even if impulses have already been consumed.

---

## Known limitations

- **Tag length caps:** Word IDs (lowercase) top out at 11 characters and acronym IDs (uppercase) at 9; use them for kernel-supplied tags. Longer caller-supplied names can be interned as namepool references (up to 256 bytes) and flow through any upper-layer packs without truncation. Core kernel routing still prefers compact word/acronym IDs, but dictionaries and ledgers accept reference IDs when the subsystem opts in.
- **Reference IDs:** Interned references compare by numeric ID; when you need glob behaviour, intern them with `cep_namepool_intern_pattern*` so matching behaves like word/acronym tags. Future work may introduce reference-aware routing indexes if heavier usage emerges.
- **HANDLE/STREAM support:** Stream/handle payload helpers now route through `cep_cell_stream_read|write|map`. VALUE/DATA use the inline/history helpers, while HANDLE/STREAM delegate to library adapters with intent/outcome journals and staged commits. Direct `cep_cell_data()` calls still return `NULL` for HANDLE/STREAM so integrations go through the stream APIs.

---

## Frequently useful APIs (mental map)

* **Cells & stores:** `cep_cell_initialize*`, `cep_cell_add*`, `cep_cell_append*`, `cep_cell_to_dictionary`, `cep_cell_sort`, traversal (`*_traverse*`, `*_find_*`). 
* **Data:** `cep_data_new`, `cep_cell_update(_hard)`, history via `_past` lookups; hashes are computed over dt+size+payload for integrity.  
* **Links/proxies:** `cep_link_*`, `cep_proxy_*`, `cep_library_*`.  
* **Enzymes & heartbeats:** `cep_enzyme_register/unregister/resolve`, registry lifecycle, bindings on cells. Heartbeat queues handle impulses.   
* **Serialization:** `cep_flat_stream_emit_cell`, reader `*_ingest/_commit`, header `*_write/_read`. 
* **Naming & namepool:** DT macros + `cep_namepool_*` for interned references.  

---

## Closing thought

This API is a compact **data+compute micro‑kernel**: trees with **deterministic history**, **pluggable storage**, **routable names**, **references with lifecycle**, **reactive work** with dependency ordering, and **streaming** across boundaries. That combination is rare—and it opens the door to building **auditable, reactive, distributed systems** while staying close to the metal.

---

## Global Q&A
- **Where should I start when untangling a kernel bug?** Skim this overview, then drop into the specific topic that matches the subsystem (e.g., append-only history, locking, or serialization). Each topic links directly to the code it describes.
- **How do I confirm a feature exists today versus being on the roadmap?** Check `docs/DOCS-INDEX.md`; planned entries (like Raw Traversal Helpers) are tagged so you do not assume finished behaviour.
- **What guarantees keep new mutations deterministic?** Append-only timelines, hierarchical locks, and beat-scoped agenda ordering. Changes that bypass those hooks need design review before landing.
- **Where do I record new architectural rationale?** Create an `L0-DESIGN-*.md` paper following `docs/L0_KERNEL/L0-DESIGN-GUIDE.md` whenever behaviour or invariants change materially.
- **How can I preview veiled or staged work without breaking invariants?** Use `cep_cell_visible_latest` or the `_past` variants with `CEP_VIS_INCLUDE_VEILED` so you inspect transactions without exposing them to other readers.
