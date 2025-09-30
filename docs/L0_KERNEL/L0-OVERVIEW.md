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
* A compact **chunked serialization** format with staged reading/commit and optional blob chunking for large payloads. 
* An optional **namepool** to intern strings when you need textual names bound to IDs. 

Together, these pieces let you build **local‑first trees, reactive dataflows, digital‑twin graphs, scene graphs with spatial indexing, and distributed state pipelines**—without giving up determinism, history, or zero‑copy performance where it matters.

---

## Core concepts

### 1) Cells: data + children (with time)

A **cell** is the unit of structure. A cell can hold:

* a **payload** (VALUE, DATA, HANDLE, or STREAM), and/or
* a **child store** (one of several storage engines).

Every cell carries **Domain/Tag (DT)** metadata and timestamps for *created/modified/deleted*, enabling history queries (“as of beat N”). The header makes these types and macros explicit (e.g., `cepCell`, `cepData`, `cepStore`, `cepDT`, `cepPath`, `CEP_WORD`, `CEP_ACRO`, `CEP_ID_GLOB_*`, etc.). 

The implementation emphasizes **append‑only** semantics: most observable history is encoded in **timestamps**; reindexing events snapshot structure only when the indexing scheme changes. That lets you replay or query previous states without destructive rewrites. 

You get a persistent, queryable history “for free,” plus clean semantics for deterministic iteration and auditing.

---

### 2) Naming that routes (Domain/Tag + globs)

The DT scheme packs two 58‑bit fields—`domain` and `tag`—and supports **word**, **acronym**, **reference**, and **numeric** encodings with compile‑time helpers (`CEP_WORD("users")`, `CEP_ACRO("SYS")`, etc.). There are **glob sentinels** (e.g., `CEP_ID_GLOB_MULTI`) that make **path matching** trivial and efficient. 

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

On top, **enzymes** are your **work units**: you register descriptors with a DT name, label, **before/after dependencies**, flags (idempotent/stateful/emit‑signals), and a **match policy** (exact or prefix). The registry **defers activation** of new registrations until the next beat (freezing the current agenda), and **resolves** work by intersecting target‑bound bindings with signal‑indexed candidates, ranking by **specificity**, and then doing a stable **topological sort** by dependencies.  

You get a **reactive dataflow kernel** that respects ordering constraints, reproducibility, and “nothing changes mid‑cycle” guarantees.

---

### 7) Serialization & streaming

The serializer emits a **control header** (magic, version, endianness, optional metadata), a **manifest** (path + flags), **data** (inline or chunked BLOBs), **library** snapshots for proxies, and an **end control** chunk. The reader **stages** chunks by transaction/sequence and only **commits** when a control marker tells it the set is complete. It validates hashes and reconstructs cells (creating parents as needed) before applying payloads or proxy snapshots. 

You can **stream** parts of your tree over files/sockets, resume, validate, and apply atomically.

---

## What you can build (examples of potential)

* **Local‑first document/graph stores** with built‑in history and path addressing (dictionary or tree branches).  
* **Reactive pipelines** (“when `/signal/users/*` arrives, run indexer before aggregator, then commit”).  
* **Digital twins / scene graphs** leveraging the **octree** store for spatial indexing. 
* **Replicated state** across processes or machines via staged **chunked serialization**. 
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

### D) Streaming a cell over the wire (chunked)

```c
// Writer callback used by the emitter
static bool write_chunk(void* ctx, const uint8_t* bytes, size_t n) {
    FILE* f = (FILE*)ctx;
    return fwrite(bytes, 1, n, f) == n;
}

// Emit one cell (with optional BLOB chunking)
cepSerializationHeader hdr = { .byte_order = CEP_SERIAL_ENDIAN_BIG };
FILE* out = fopen("cell.bin", "wb");
cep_serialization_emit_cell(users, &hdr, write_chunk, out, /*blob payload*/ 64*1024);  // emit chunks  :contentReference[oaicite:45]{index=45}
fclose(out);
```

On the receiving side, you **ingest** chunks (in any stepwise manner), and **commit** once a control marker is seen. The reader validates sizes/hashes, reconstructs the path (creating parents as needed), and restores either **inline data** or **proxy snapshots**. 

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

## Operational notes & guardrails

* **Locking:** coarse flags exist for child stores and data payloads (`cep_store_lock/cep_data_lock`) and are checked up the ancestry to prevent unsafe mutations. These are **in‑tree logical locks**, not OS‑level primitives; coordinate your own threading policy. 
* **Soft vs. hard delete:** soft delete stamps timestamps and preserves history; “hard” variants drop memory (and can reorganize siblings) and are used for GC paths. Pick based on audit requirements. 
* **Cloning semantics:** VALUE/DATA clone by copy; HANDLE/STREAM clones appear as **links** to the original to keep external resources authoritative. 
* **Glob semantics:** enzyme path matching uses DT comparison with **glob sentinels** (notably “multi”) to match domains/tags flexibly.  
* **Namepool:** use it when you need text‑to‑ID indirection for `CEP_NAMING_REFERENCE` identifiers; remember to release IDs you no longer need. 

---

## Frequently useful APIs (mental map)

* **Cells & stores:** `cep_cell_initialize*`, `cep_cell_add*`, `cep_cell_append*`, `cep_cell_to_dictionary`, `cep_cell_sort`, traversal (`*_traverse*`, `*_find_*`). 
* **Data:** `cep_data_new`, `cep_cell_update(_hard)`, history via `_past` lookups; hashes are computed over dt+size+payload for integrity.  
* **Links/proxies:** `cep_link_*`, `cep_proxy_*`, `cep_library_*`.  
* **Enzymes & heartbeats:** `cep_enzyme_register/unregister/resolve`, registry lifecycle, bindings on cells. Heartbeat queues handle impulses.   
* **Serialization:** `cep_serialization_emit_cell`, reader `*_ingest/_commit`, header `*_write/_read`. 
* **Naming & namepool:** DT macros + `cep_namepool_*` for interned references.  

---

## Closing thought

This API is a compact **data+compute micro‑kernel**: trees with **deterministic history**, **pluggable storage**, **routable names**, **references with lifecycle**, **reactive work** with dependency ordering, and **streaming** across boundaries. That combination is rare—and it opens the door to building **auditable, reactive, distributed systems** while staying close to the metal.
