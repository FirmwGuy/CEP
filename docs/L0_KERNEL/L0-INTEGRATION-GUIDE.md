# L0 Kernel: Integration & Interop Guide

*How to bind work to data, stream cells over the wire, and plug external resources into the kernel.*

**Audience:** engineers integrating CEP into applications, building adapters/libraries, or wiring data pipelines.
**Scope:** enzymes & heartbeat dispatch, wire serialization/ingest, proxy & library adapters, naming & namepool, locking & history, and practical recipes with small code sketches.

---

## 0) Reading map

* **Signals → Enzymes → Work**: register, bind, match, and order enzyme callbacks; how impulses get resolved and executed  .
* **Serialization & Streams**: emit/ingest chunked cell streams; transactions; manifest & payload; proxy snapshots .
* **Proxies & Libraries**: represent external resources/streams inside cells  .
* **Naming & Namepool**: compact Domain/Tag IDs, intern/lookup text names  .
* **Locking, History & “soft” vs “hard”**: data/store locks, append‑only timelines, snapshot traversals  .

---

## 1) Signals, enzymes, and the heartbeat

### 1.1 Enzyme descriptors and registration

An **enzyme** is a user callback that runs when an impulse matches a query. It is described by a `cepEnzymeDescriptor`:

```c
typedef int (*cepEnzyme)(const cepPath* signal_path, const cepPath* target_path);

typedef struct {
    cepDT        name;           // stable identity
    const char*  label;          // optional diagnostic label
    const cepDT* before; size_t before_count;  // ordering constraints
    const cepDT* after;  size_t after_count;
    cepEnzyme    callback;       // your function
    uint32_t     flags;          // e.g., CEP_ENZYME_FLAG_IDEMPOTENT
    cepEnzymeMatchPolicy match;  // EXACT or PREFIX
} cepEnzymeDescriptor;
```

Register via the **registry**; during a live heartbeat, registrations are staged and **activated on the next beat** to keep the current agenda frozen (see `cep_enzyme_register` and `cep_enzyme_registry_activate_pending`)  . Internally, mid‑beat calls are queued in a *pending* array and promoted later; out of beat, they go straight into the active table and indexes are rebuilt for fast lookup .

**Match policies & wildcards.** A descriptor’s `match` controls how its **query path** is compared: `EXACT` must match the entire `signal_path`, while `PREFIX` matches “starts with” semantics. Path segments can use **Domain/Tag** globbing in two ways: word tags may include `*` (handled by `cep_id_matches`), and the reserved sentinel IDs (`CEP_ID_GLOB_MULTI`, `CEP_ID_GLOB_STAR`, `CEP_ID_GLOB_QUESTION`) provide wildcard behaviour at the domain/tag level.

**Return codes.** Enzymes return `CEP_ENZYME_SUCCESS`, `CEP_ENZYME_RETRY`, or `CEP_ENZYME_FATAL` .

### 1.2 Binding enzymes at cells and collecting effective bindings

You can **bind** enzyme identities into the **data or store timeline** of a cell (e.g., “this subtree accepts X”), with flags to **propagate** to descendants or to **tombstone** (un‑bind) an earlier binding. Effective bindings are collected by walking upward and combining “active” with “masked” sets; only propagated entries flow past the target node, and tombstones remove prior matches. See the binding data structure (`cepEnzymeBinding`) and the collector used by resolve (`cep_enzyme_collect_bindings`)  .

### 1.3 From impulse to ordered agenda

Given an impulse:

```c
typedef struct {
    const cepPath* signal_path;
    const cepPath* target_path;
} cepImpulse;
```

the runtime resolves a **set of candidate enzymes** and returns them **in execution order** (`cep_enzyme_resolve`)  :

1. **Collect** target bindings (if any), intersect with signal matches, and **score** candidates by **match strength** (signal+target > single‑sided), **specificity** (non‑wildcard segments), **name ordering**, and **registration order** for tie‑breaks .
2. Build a **dependency graph** from `before[]`/`after[]`, dedupe edges, compute **indegrees** .
3. Perform a **stable topological sort** using a preference heap (stronger/more specific candidates surface earlier) and output the agenda .

**Heartbeat staging.** Impulses can be recorded and carried across beats. The queue/record helpers (`cep_heartbeat_impulse_queue_*`) clone `cepPath` entries and manage a compact, resettable buffer for recent signals/targets for diagnostics or deferred execution .

### 1.4 Beat phase helpers

Heartbeat loops now announce each phase so dashboards and tests can narrate the rhythm without reverse-engineering scheduler internals.

**Technical details**

- `cep_beat_begin_capture()`, `cep_beat_begin_compute()`, and `cep_beat_begin_commit()` mark the active phase; the default loop invokes them right before resolve/execute/commit.
- `cep_beat_index()` exposes the monotonic beat number (returns `0` until the scheduler advances), and `cep_beat_phase()` returns the current `cepBeatPhase` enum.
- `cep_beat_deferred_activation_count()` reports how many pending enzymes were promoted for the next beat, helping you assert that mid-beat registrations stay frozen.
- Phase helpers are read-only signals—no locks or timers—so you can safely call them from logging or lightweight assertions.

```c
if (cep_beat_phase() == CEP_BEAT_COMPUTE) {
    diag_log("beat %" PRIu64 ": %zu enzymes deferred",
             (unsigned long long)cep_beat_index(),
             cep_beat_deferred_activation_count());
}
```

### 1.5 L0 bootstrap helper

**In plain words.** `cep_l0_bootstrap()` is the one button that brings the heartbeat, namepool, and mailroom online so higher layers can assume the lobby is ready before they touch anything.

**Technical details**
- `cep_l0_bootstrap()` first ensures the cell system exists, then calls `cep_heartbeat_bootstrap()` to mint `/sys`, `/data`, `/rt`, `/journal`, `/tmp`, and the default enzyme registry.
- It follows up with `cep_namepool_bootstrap()` so reference identifiers can be interned immediately, and finally `cep_mailroom_bootstrap()` to seed `/data/inbox/{coh,flow}`, `/sys/err_cat`, and the layer error catalogs on `/sys/err_cat/{coh,flow}`.
- The helper caches its work; subsequent calls return `true` without mutating state unless the cell system has been torn down.

**Q&A**
- *Do I call heartbeat or mailroom bootstrap directly anymore?* Not when you have access to `cep_l0_bootstrap()`; call it once at process start (tests included) and higher-level bootstraps will sit atop a consistent base.
- *What if my embedder wants to customise the heartbeat topology?* Configure the heartbeat afterwards with `cep_heartbeat_configure()`—the bootstrap only creates missing roots, it doesn’t lock you out of overrides.

### 1.6 Unified mailroom router

Think of the mailroom as the lobby of the runtime: everyone drops their intents at the same desk and the kernel forwards them to the right layer before any work begins.

**Technical details**

- `cep_mailroom_bootstrap()` provisions `/data/inbox/{coh,flow}` alongside `/data/coh` and `/data/flow`, ensures `/sys/err_cat` exists, and now seeds both the coherence and flow error catalogs so higher layers no longer reseed the tables themselves.
- `cep_mailroom_register()` installs the `mr_route` enzyme on `CEP:sig_cell/op_add` with `before` edges targeting every ingest enzyme (`coh_ing_*`, `fl_ing`, etc.), so routing always happens ahead of layer-specific work.
- Routed intents keep an audit trail: the mailroom leaves a link behind in the source bucket and copies the staged cell into the downstream inbox. The router also guarantees the shared intent header by creating `original/*`, seeding `outcome` (if missing), and ensuring `meta/parents` exists.
- You can extend the router by adding new namespace buckets or compatibility shims (for a transition period, link legacy inbox paths into the mailroom so producers can keep using old entrypoints).

#### 1.6.1 Mailroom extension helpers

Sometimes you need the lobby to recognise brand new tenants. The two helper functions below let integrators register additional namespaces or slot custom enzymes ahead of the router without touching the built-in wiring.

**Technical details**
- `bool cep_mailroom_add_namespace(const char* namespace_tag, const char* const bucket_tags[], size_t bucket_count)`<br>
  Adds (or extends) a namespace under `/data/inbox/<namespace_tag>/` and mirrors the same buckets under `/data/<namespace_tag>/inbox/`. Call it before `cep_mailroom_bootstrap()` so the inbox hierarchy is created during bootstrap. Repeated calls are idempotent: duplicates are ignored and newly-added buckets are seeded immediately if the mailroom already bootstrapped. Passing `bucket_count==0` skips work; otherwise each entry in `bucket_tags` must be a valid lexicon tag.
- `bool cep_mailroom_add_router_before(const char* enzyme_tag)`<br>
  Queues a descriptor name to be inserted into the mailroom router's `before` list the next time `cep_mailroom_register()` runs. Use this when your pack needs routing to happen ahead of additional ingest enzymes (for example, PoC packs that introduce `poc_io_ing_*`). The helper validates uniqueness, so you can register the same tag repeatedly while building layered packs.

### 1.7 Identifier composer helper

**In plain words.** `cep_compose_identifier()` trims and normalises a handful of text fragments into the colon-delimited, lowercase identifier format the kernel expects, sparing you from writing the casing and validation boilerplate by hand.

**Technical details**
- Pass an array of C strings and the helper lowercases permitted characters (`[a-z0-9-_.\/]`), trims ASCII whitespace from each token, rejects embedded `:` characters, and glues the pieces with `:` into the supplied buffer.
- The output is limited to `CEP_IDENTIFIER_MAX` (256) bytes; the routine fails early if the combined length would overflow either `out_cap` or the global limit.
- If any token is `NULL`, reduces to empty after trimming, or contains a disallowed character, the helper returns `false` without touching the buffer.

**Q&A**
- *When should I prefer this over the layer-specific macros?* Use `cep_compose_identifier()` any time you need plain L0 naming (for example, mailroom buckets or diagnostics). Layer convenience macros such as `CEP_L1_COMPOSE` still make sense when you are operating entirely inside their schema.
- *Can I feed the result into the namepool?* Yes. Once composed, hand it to `cep_namepool_intern_cstr()` (or the layer helpers) to obtain a stable `cepID` if you need to reuse the identifier frequently.

---

## 2) Serialization & streams (wire format)

### 2.1 Chunk framing and the control header

Serialized streams are **chunked**. Each chunk carries a size and ID (class + transaction + sequence). The initial **control header** plants the **magic**, **format version**, **byte order**, and optional **metadata** (`cep_serialization_header_write/read`) . Helpers take care of **big‑endian on the wire** (inline BE conversions) and report exact buffer sizes so you can pre‑allocate (`*_chunk_size`) .

### 2.2 Manifest and payload

`cep_serialization_emit_cell` writes a **header** → **manifest** → **payload** → **end‑of‑transaction control**:

* **Manifest (STRUCTURE)**: captures the cell’s **type**, flags, and **path** segments (Domain/Tag pairs). The path is produced by `cep_cell_path` and stored as an array of `cepPast { cepDT dt; cepOpCount timestamp; }`, typically using timestamp 0 for “latest” at emit time  .
* **Payload (STRUCTURE + optional BLOBs)**:

  * Normal cells with `VALUE`/`DATA` payloads encode datatype, inlining small payloads and **chunking large blobs** with a caller‑configurable slice size (`blob_payload_bytes`). Each blob chunk carries an **offset + length**; the reader validates order and size before assembly .
  * **Proxy cells** emit a **LIBRARY** chunk that carries a *snapshot* (bytes and flags). The reader forwards the snapshot to the proxy via `cep_proxy_restore` to reconstruct external state without peeking into proxy internals  .

### 2.3 Reader, transactions, and safety

The **reader** (`cep_serialization_reader_*`) ingests chunks, validates ordering per **transaction/sequence**, stages per-cell **manifest/data/proxy** parts, and on `commit()` materializes changes into the tree:

* Transactions guard against **out-of-order** or mixed chunks; any violation flips the reader to **error** and clears staged state .
* For data payloads, the reader recomputes the **content hash** (over `{dt, size, payloadHash}`) using the same hash as the kernel (`cep_hash_bytes`) and rejects mismatches before applying the update  .
* **Structure synthesis:** if the target path doesn’t exist, the reader creates intermediate dictionaries/lists as needed, but will **not** fabricate a proxy where the type doesn’t match—types must line up with the manifest flags .

### 2.4 Journal metadata helpers

Control headers now carry a tiny record of “which beat emitted this?” so downstream systems can file serialized batches without guessing.

**Technical details**

- `cepSerializationHeader` gained `journal_metadata_present`, `journal_beat`, and `journal_decision_replay` fields. Set the boolean to `true` to request metadata; leave it `false` if you supply your own `metadata` buffer.
- `cep_serialization_emit_cell()` auto-populates `journal_beat` with `cep_beat_index()` when you pass `NULL` for the header (or leave the boolean unset), so ordinary emitters get beat stamps for free.
- Structure manifests encode an extra byte after every `domain/tag` pair that mirrors the segment’s `glob` flag (`0x01` when set). Data descriptors append the same byte after the payload tag so wildcard hints survive round-trips.
- During write, the header encodes a 16-byte metadata block: beat (big-endian `uint64_t`), a flag byte (`0x01` for decision replay), and padding. Readers parse it back and set the struct fields when `metadata_length` matches the pattern.
- You can still inject arbitrary metadata: provide `metadata_length`/`metadata` and leave `journal_metadata_present` `false`; the serializer simply copies your payload.

---

## 3) Proxies & libraries (external resources inside cells)

When your data lives outside the kernel (files, device handles, remote streams), wrap it in a **proxy**:

* A proxy cell is created via `cep_proxy_initialize` with a `cepProxyOps` vtable: `snapshot`, `release`, `restore`, and `finalize`—so the serializer can **snapshot**, carry, and **rebuild** the proxy’s state without kernel‑specific codepaths in your adapter  .
* The “Library” flavor (`cep_proxy_initialize_handle` / `cep_proxy_initialize_stream`) lazily routes to a `cepLibraryBinding` (your adapter): retain/release handles, map/unmap stream windows, read/write chunks, and snapshot/restore both handles and streams. CEP handles **back‑references** and ensures link/shadow invariants even when proxies are moved or cloned  .

> **Tip:** For **streams**, prefer `stream_map`/`unmap` for large sequential I/O and `stream_snapshot` for “publish and ship” payloads during serialization. The serializer will switch between inline payloads and BLOB slices based on the configured threshold  .

---

## 4) Naming & the namepool

**Domain/Tag** fields are compact `cepID`s with a **naming nibble** that encodes *word*, *acronym*, *reference*, or *numeric*. Helpers convert text ↔ IDs (`cep_text_to_word`, `cep_word_to_text`, `cep_text_to_acronym`, `cep_acronym_to_text`). Word **and acronym** IDs may contain `*`; the kernel records a glob bit so helpers such as `cep_id_matches` can expand the wildcard transparently, while the reference sentinels still cover whole-domain globs. Reference tags pick up the same glob awareness when you intern them through the pattern helpers (`cep_namepool_intern_pattern*`), leaving literal references untouched unless you opt in.

When you need to interoperate with human text reliably, enable the **namepool** and use:

```c
bool    cep_namepool_bootstrap(void);
cepID   cep_namepool_intern(const char* text, size_t length);
cepID   cep_namepool_intern_cstr(const char* text);
cepID   cep_namepool_intern_static(const char* text, size_t length); // no copy
cepID   cep_namepool_intern_pattern(const char* text, size_t length);
cepID   cep_namepool_intern_pattern_cstr(const char* text);
cepID   cep_namepool_intern_pattern_static(const char* text, size_t length);
const char* cep_namepool_lookup(cepID id, size_t* length);
bool    cep_namepool_release(cepID id);
```

This gives you **stable, interned references** for `CEP_NAMING_REFERENCE` names, with lookup and lifetime management centralized in one place .

`cep_namepool_intern_pattern*` mirrors the regular helpers but marks the resulting references as glob patterns. Literal references keep their original semantics even if the underlying text includes `*`; only the pattern helpers set the glob hint that propagates into every `cepDT`.

---

## 5) Locking, history, and deletion semantics

* **Locks.** You can lock a cell’s **store** (structure) or **data** to guard multi‑step edits (`cep_store_lock/cep_store_unlock`, `cep_data_lock/cep_data_unlock`). Lock predicates are **hierarchical**: if *any* ancestor holds a lock, mutation APIs refuse the operation to maintain consistency under composition  .
* **Append‑only timelines.** Payload updates push a snapshot node into the **data history chain**, and store re‑index operations capture snapshots of the **store layout**. “Normal” add/append operations keep sibling order stable and rely on **timestamps** as the audit trail (see `cep_data_history_push/clear`, store history helpers) .
* **Soft vs hard.** *Soft delete* marks `deleted` timestamps; snapshots and “past” APIs (`cep_cell_*_past`) remain valid. *Hard delete* physically removes nodes/children and frees memory immediately (e.g., `cep_store_delete_children_hard`, `cep_cell_remove_hard`)—intended for GC and aborted constructions .
* **Links & shadows.** Links maintain **back‑references** (“shadow lists”) on targets; CEP keeps those up‑to‑date when assigning links or deleting targets (see `cep_link_set`, shadow attach/detach, and `targetDead` propagation). Cloning a handle/stream turns into a **link** clone (shared resource) rather than attempting to duplicate opaque external state .

### 5.1 Provenance helpers

When you emit derived facts it helps to record “came from these parents” and a quick checksum, so auditors and replay tools have anchors with zero extra schema work.

**Technical details**

- `cep_cell_add_parents(derived, parents, count)` ensures there is a `meta/parents` list, clears previous entries, and appends link cells to every parent you pass. Null entries are skipped; errors surface as `-1`.
- `cep_cell_content_hash(cell)` recomputes the payload hash (using the kernel’s FNV‑1a) and stores it on the live `cepData` node, returning the 64-bit value for logs.
- `cep_cell_set_content_hash(cell, hash)` lets you stamp an externally computed checksum without touching the payload.
- Both helpers follow links to canonical cells and refuse to operate on proxies/handles where a value hash would be meaningless.

---

## 6) Recipes

### A) Register and bind an enzyme

```c
// 1) Create a registry once.
cepEnzymeRegistry* R = cep_enzyme_registry_create();

// 2) Describe your enzyme.
cepEnzymeDescriptor D = {
  .name  = *CEP_DTWA("sys", "ingest"),  // domain/tag
  .label = "Ingest CSV rows",
  .callback = &my_ingest,
  .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
  .match = CEP_ENZYME_MATCH_PREFIX,
};

// 3) Register for signals under /data/imports/...
cepPath* query = /* build or reuse a cepPath */;
cep_enzyme_register(R, query, &D);  // pending if a beat is live

// (Later, at safe points) Promote staged registrations:
cep_enzyme_registry_activate_pending(R);

// 4) Bind to a subtree to make it eligible by name.
cep_cell_bind_enzyme(someCell, &D.name, /*propagate=*/true);
```

The resolver will merge **bindings** with **signal‑indexed** candidates and topologically sort by `before`/`after`—preferring stronger/specific matches and respecting registration order ties  .

### B) Emit a cell to bytes and read it back

```c
// Writer callback
bool sink(void* ctx, const uint8_t* bytes, size_t n) {
  FILE* f = ctx; return fwrite(bytes,1,n,f) == n;
}

cepSerializationHeader hdr = {
  .byte_order = CEP_SERIAL_ENDIAN_BIG,  // wire choice
};
FILE* out = fopen("cell.bin","wb");
cep_serialization_emit_cell(cell, &hdr, sink, out, /*blob_payload_bytes*/ 64*1024);
fclose(out);

// Reader side
cepSerializationReader* rd = cep_serialization_reader_create(root);
FILE* in = fopen("cell.bin","rb");
for (;;) {
  uint64_t size, id;               // read chunk framing...
  // ...
  cep_serialization_reader_ingest(rd, chunk, chunk_len);
  if (cep_serialization_reader_pending(rd)) {
    cep_serialization_reader_commit(rd); // applies staged manifest/data
  }
}
```

The emitter outputs: **header → manifest → (data inline or BLOB chunks) → end control**. The reader validates **sequence**, reconstructs data, **verifies hashes**, and restores **proxy snapshots** when present .

### C) Wrap a file handle as a proxy

```c
// Implement a cepLibraryOps with retain/release + stream operations.
static const cepLibraryOps FILE_OPS = { /* ... */ };

// Build a 'library' cell once:
cepCell lib = {0};
cep_library_initialize(&lib, CEP_DTWA("io","fs"), &FILE_OPS, /*ctx*/NULL);

// Create a proxy-backed HANDLE cell referencing an OS handle:
cepCell fileCell = {0};
cep_proxy_initialize_handle(&fileCell, CEP_DTWA("io","file"), /*handle*/ resourceCell, &lib);

// Serializer will call snapshot/release; reader will call restore.
```

The **proxy** keeps your adapter logic isolated. CEP takes care of **shadowing** and **lifecycle** (retain/release around handle/stream pointers) and will serialize a **LIBRARY** chunk with your snapshot bytes for transport   .

---

## 7) API cheatsheet (selected)

* **Paths**: `cep_cell_path`, `cep_cell_find_by_path(_past)`, `cep_cell_find_next_by_path_past`  .
* **Traversal (latest or past)**: `cep_cell_traverse(_past)`, `cep_cell_deep_traverse(_past)` .
* **Mutation (append‑only semantics)**: `cep_cell_add`, `cep_cell_append`, `cep_cell_update`, `cep_cell_to_dictionary`, `cep_cell_sort` .
* **Deletion**: `cep_cell_delete[_hard]`, `cep_store_delete_children_hard`, child `take/pop` variants (soft/hard) .
* **Locks**: `cep_store_lock/unlock`, `cep_data_lock/unlock`  .
* **Enzymes**: registry lifecycle, register/unregister, resolve, and binding surface in the public header; see internals for ordering and specificity calculus  .
* **Serialization**: header read/write; emit cell; reader ingest/commit; BLOB slicing; proxy library chunks .
* **Namepool**: intern/lookup/release textual names when using reference‑style identifiers .

---

## 8) Integration guidance & gotchas

* **Don’t mutate mid‑beat registrations.** Register enzymes freely, but let CEP **activate** them between beats (`activate_pending`) to avoid agenda drift .
* **Prefer soft deletes** for observability; reserve hard deletes for GC or error recovery workflows. Past traversals depend on timestamps and history lists .
* **Respect locks**. Both **data** and **store** locks check the *entire ancestor chain*; if anything is locked above, mutations are denied to keep invariants intact  .
* **Proxy cloning.** Cloning cells whose payload is a handle/stream produces **links**, not resource copies—by design, to keep a single authoritative resource endpoint .
* **Hash checks are end‑to‑end.** The reader recomputes the same **content hash** the writer recorded; any mismatch aborts the apply phase before mutating the tree  .

---

## 9) Lifecycle signals in practice

Heartbeat init/shutdown pulses now mirror production beats, so tooling and tests can treat them as first-class events instead of ad-hoc bootstrap helpers.

### Technical details
- Call `cep_heartbeat_begin()` right after `cep_heartbeat_configure()` when you want the system-init cascade; follow it with `cep_heartbeat_step()` so `mr_init`, `coh_init`, `fl_init`, and `rv_init` actually execute.
- `cep_heartbeat_emit_shutdown()` enqueues the shutdown signal on the live agenda, runs the same commit path as a normal beat, and writes a short breadcrumb even when directory logging stays disabled.
- Each lifecycle emission appends a message under `/journal/sys_log`, giving you an easy way to assert that init/shutdown happened without rummaging through agenda dumps.

### Q&A
- *How do I check that init ran during a test?* Inspect `/journal/sys_log` or verify that `cep_heartbeat_sys_root()` picked up the expected namespaces after the first beat—both are populated by the init enzyme.
- *Can I replay init mid-run?* Yes. Call `cep_heartbeat_restart()`, then `cep_heartbeat_begin()` and a single `cep_heartbeat_step()`; the sys-log will capture each pulse so you can line them up with assertions.
- *Will emitting shutdown twice cause trouble?* No. The helper is idempotent; once `sys_shutdown_emitted` flips, subsequent calls simply return `true`.

---

## Q&A

- *Do I need to call the phase helpers manually?* No. They are wired into `cep_heartbeat_resolve_agenda()` and `cep_heartbeat_stage_commit()`. Manual calls are only for bespoke schedulers.
- *What happens to mid-beat registrations?* They are counted and deferred; the agenda for the current beat never mutates.
- *When should I call `cep_mailroom_add_namespace()` and `cep_mailroom_add_router_before()`?* During your pack’s bootstrap or registration sequence—before you invoke `cep_mailroom_bootstrap()`/`cep_mailroom_register()`—so the mailroom sees the extra namespaces and dependency edges on the first beat.
- *What happens if the mailroom already bootstrapped?* `cep_mailroom_add_namespace()` retrofits the new buckets immediately, while `cep_mailroom_add_router_before()` stores the dependency and applies it the next time the mailroom registers; you can safely call them on every initialisation pass.
- *Do I still call layer bootstraps?* Yes. The mailroom only handles ingress; `cep_l1_coherence_bootstrap()` and `cep_l2_flows_bootstrap()` still provision their ledgers and inboxes.
- *What happens if the downstream inbox is missing?* The router aborts the move, leaves the original intent under `/data/inbox`, and returns `CEP_ENZYME_FATAL` so tests catch the misconfiguration.
- *How do I disable the automatic beat stamp in serialization?* Supply your own `cepSerializationHeader` with `journal_metadata_present = false` (and your own metadata) or set the boolean to `false` before invoking `cep_serialization_emit_cell()`.
- *What toggles `journal_decision_replay`?* Higher layers set it when replaying stored decisions; the kernel preserves the advisory flag during round-trips.
- *Do parent links survive hard deletes?* They are regular links, so removing the parent turns them into shadow entries flagged via the existing link lifecycle—useful when diagnosing stale references.
- *Should I hash huge blobs with `cep_cell_content_hash()`?* Treat it as an integrity hint rather than a cryptographic guarantee. For large or high-assurance payloads, store your own checksum alongside the data and regard the built-in hash as advisory.
