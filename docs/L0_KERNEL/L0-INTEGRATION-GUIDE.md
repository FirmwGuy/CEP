# L0 Kernel: Integration & Interop Guide

*How to bind work to data, stream cells over the wire, and plug external resources into the kernel.*

**Audience:** engineers integrating CEP into applications, building adapters/libraries, or wiring data pipelines.
**Scope:** enzymes & heartbeat dispatch, wire serialization/ingest, proxy & library adapters, naming & namepool, locking & history, and practical recipes with small code sketches.

---

## 0) Reading map

* **Signals → Enzymes → Work**: register, bind, match, and order enzyme callbacks; how impulses get resolved and executed  .
* **Serialization & Streams**: emit/ingest chunked cell streams; transactions; manifest & payload; proxy snapshots .
* **Diagnostics / CEI**: the Common Error Interface (`cep_cei_emit`) publishes structured Error Facts into the diagnostics mailbox (`/data/mailbox/diag`) and can emit `sig_cei/*` impulses; re-read the CEI topic before customising severity handling or routing.
* **Proxies & Libraries**: represent external resources/streams inside cells  .
* **Naming & Namepool**: compact Domain/Tag IDs, intern/lookup text names  .
* **Locking, History & “soft” vs “hard”**: data/store locks, append‑only timelines, snapshot traversals  .
* **Episodic Enzyme Engine (E³)**: promote/demote episodic work between threaded RO and cooperative RW slices without breaking replay invariants.
* **Pause / Rollback / Resume (PRR)**: gate the heartbeat agenda, rewind the visible horizon, and drain postponed impulses deterministically.

---

## 1) Signals, enzymes, and the heartbeat

This chapter explains how work enters the kernel through signals, how enzyme registries resolve and order callbacks each beat, and how the heartbeat enforces the capture → compute → commit contract so integrations stay deterministic.

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

#### 1.1.1 Registry maintenance helpers

Registries live for the lifetime of a process, but tooling and tests often need to clean up descriptors, inspect bindings, or tear everything down between scenarios. These helpers keep that housekeeping predictable.

**Technical details**
- `size_t cep_enzyme_registry_size(const cepEnzymeRegistry* registry)` reports how many descriptors are currently active, so assertions can prove that bootstrap packs registered what they promised.
- `void cep_enzyme_registry_reset(cepEnzymeRegistry* registry)` clears both the active and pending tables while keeping the allocation in place; use it in test fixtures that reload descriptors repeatedly.
- `void cep_enzyme_registry_destroy(cepEnzymeRegistry* registry)` releases the registry and its backing allocations. Destroying a registry invalidates any pending activation, so call it after your heartbeat shuts down.
- `int cep_enzyme_unregister(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor)` removes a descriptor/query pair when you need to swap out callbacks without recreating the registry.
- `int cep_cell_unbind_enzyme(cepCell* cell, const cepDT* name)` appends a tombstone to the cell timeline so descendants stop inheriting that binding on the next beat.
- `const cepEnzymeBinding* cep_cell_enzyme_bindings(const cepCell* cell)` exposes the effective bindings stored on a node; useful for diagnostics or when you need to confirm propagation flags.

**Q&A**
- *Reset or destroy—when should I pick each?* Call `cep_enzyme_registry_reset()` when you want to reuse the same registry instance (for example, inside a test loop). Use `cep_enzyme_registry_destroy()` only when the registry’s lifetime ends and all descriptors should be dropped permanently.

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

**In plain words.** `cep_l0_bootstrap()` is the one button that brings the heartbeat and namepool online so higher layers land on a stable base before they touch anything.

**Technical details**
- `cep_l0_bootstrap()` first ensures the cell system exists, then calls `cep_heartbeat_bootstrap()` to mint `/sys`, `/data`, `/rt`, `/journal`, `/tmp`, and the default enzyme registry.
- It follows up with `cep_namepool_bootstrap()` so reference identifiers can be interned immediately.
- The helper caches its work; subsequent calls return `true` without mutating state unless the cell system has been torn down.
- `bool cep_cell_system_initialized(void)` tells you whether the low-level cell system is already online, and `void cep_cell_system_ensure(void)` performs the minimum bootstrap if it is not—useful when embedding CEP inside environments with custom startup order.

**Q&A**
- *Do I call heartbeat directly anymore?* Not when you have access to `cep_l0_bootstrap()`; call it once at process start (tests included) and higher-level bootstraps will sit atop a consistent base.
- *What if my embedder wants to customise the heartbeat topology?* Configure the heartbeat afterwards with `cep_heartbeat_configure()`—the bootstrap only creates missing roots, it doesn’t lock you out of overrides.

### 1.6 Ingest responsibilities after the mailroom

**In plain words.** Layer 0 no longer runs a shared lobby. Route intents inside your own pack bootstraps and keep transactional staging close to the data you own.

**Technical details**
- Register pack-specific routing enzymes ahead of ingest descriptors when you still need a lobby-style fan-out. Reuse the `cep_txn_*` helpers if you require veiled staging before grafting requests.
- When you remove legacy mailroom calls, document any temporary no-op stub in your pack backlog so downstream refactors can wire the new dispatcher explicitly.

**Q&A**
- *What replaced `cep_mailroom_stage_request()`?* Nothing in the kernel. Copy the staging pattern into your own pack (or wrap it as a helper) so the new ingress path remains explicit.
- *Can I keep `cep_mailroom_*` calls around for compatibility?* No—the APIs are gone. Replace them with pack-owned routers or direct writes into the correct inbox cells.

### 1.7 Identifier composer helper

**In plain words.** `cep_compose_identifier()` trims and normalises a handful of text fragments into the colon-delimited, lowercase identifier format the kernel expects, sparing you from writing the casing and validation boilerplate by hand.

**Technical details**
- Pass an array of C strings and the helper lowercases permitted characters (`[a-z0-9-_.\/]`), trims ASCII whitespace from each token, rejects embedded `:` characters, and glues the pieces with `:` into the supplied buffer.
- The output is limited to `CEP_IDENTIFIER_MAX` (256) bytes; the routine fails early if the combined length would overflow either `out_cap` or the global limit.
- If any token is `NULL`, reduces to empty after trimming, or contains a disallowed character, the helper returns `false` without touching the buffer.

**Q&A**
- *When should I prefer this over the layer-specific macros?* Use `cep_compose_identifier()` any time you need plain L0 naming (for example, error buckets or diagnostics). Pack-specific convenience macros (for example, a coherence helper) still make sense when you are operating entirely inside that schema.
- *Can I feed the result into the namepool?* Yes. Once composed, hand it to `cep_namepool_intern_cstr()` (or the layer helpers) to obtain a stable `cepID` if you need to reuse the identifier frequently.

### 1.8 Heartbeat runtime accessors

The heartbeat keeps a lot of book-keeping behind the curtain. These accessors expose that state so schedulers, diagnostics, and tests can peek without patching the core loop.

**Technical details**
- `bool cep_heartbeat_startup(void)` brings the runtime online after bootstrap, wiring the registry, deferred agenda buffers, and journal roots. This is the programmatic “power button” when you build your own loop.
- `void cep_heartbeat_shutdown(void)` flushes the agenda, releases scratch buffers, and clears lifecycle flags so a future `cep_heartbeat_startup()` call can rebuild the runtime cleanly.
- `void cep_beat_note_deferred_activation(size_t count)` lets subsystems tell the heartbeat how many descriptors were staged mid-beat; the number is then surfaced through `cep_beat_deferred_activation_count()`.
- `cepBeatNumber cep_heartbeat_current(void)` and `cepBeatNumber cep_heartbeat_next(void)` report the beat that is executing and the next scheduled beat when the loop is paused.
- `const cepHeartbeatPolicy* cep_heartbeat_policy(void)` and `const cepHeartbeatTopology* cep_heartbeat_topology(void)` expose the active policy knobs and tree roots so embedders can confirm configuration after a dynamic change.
- `cepEnzymeRegistry* cep_heartbeat_registry(void)` returns the live registry pointer, saving you from tracking the one `cep_heartbeat_bootstrap()` created.
- `int cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepImpulse* impulse)` queues a fully populated impulse (signal + target) for a specific beat. Use it when you already built a `cepImpulse` struct or when the signal/target paths live in reusable buffers.
- `bool cep_heartbeat_process_impulses(void)` drains the queued impulses into the live agenda; call it when you integrate a bespoke event loop and want to stage work without executing a full beat yet.
- `cepCell* cep_heartbeat_rt_root(void)`, `cep_heartbeat_journal_root(void)`, `cep_heartbeat_env_root(void)`, `cep_heartbeat_data_root(void)`, `cep_heartbeat_cas_root(void)`, `cep_heartbeat_tmp_root(void)`, and `cep_heartbeat_enzymes_root(void)` return the canonical cells for those runtime branches, making it easy to add assertions or inspection hooks without manually traversing from the global root.

**Q&A**
- *Is `cep_heartbeat_enqueue_impulse()` different from `cep_heartbeat_enqueue_signal()`?* Yes—`enqueue_signal` clones the paths for you from raw `cepPath` pointers, while `enqueue_impulse` lets you hand over a pre-built `cepImpulse` when you already manage its lifetime.

### 1.8.1 Raw traversal helpers *(kernel only)*

**In plain words.** These helpers are for the kernel’s own housekeeping (sealing, digests, debug). They walk veiled or deleted children intentionally, so keep user-facing code on the regular, visibility-respecting APIs.

**Technical details**
- `cep_cell_first_all` / `cep_cell_next_all` / `cep_cell_last_all` / `cep_cell_prev_all` mirror the regular sibling iterators but walk the store’s physical ordering, exposing veiled/deleted nodes for internal maintenance. Leave product code on the standard helpers.
- The helpers resolve the parent link once, then return the stored `cepCell*` pointer exactly as it lives in the backing store; links remain untouched unless you resolve them explicitly.
- `cep_cell_deep_traverse_all` shares the same “internal use only” contract; it recurses through hidden descendants so bootstrap and sealing routines can finish their work without violating transactional visibility.

**Q&A**
- *Can regular embeddings rely on `_all` variants?* No—stick to the standard helpers so your code respects veils and tombstones. `_all` is strictly for L0 internals.
- *Do I need extra locks first?* Follow the same locking discipline you would for visible traversals. The `_all` family never acquires additional locks on your behalf.

### 1.9 Building cell trees safely (floating → graft)

Layer 0 assumes that new structure is assembled off-tree first and only grafted under `/` once it is internally consistent. Mutating a node that is already anchored (for example, a dictionary under `/data`) risks tripping assertions in `cep_cell_add`/`cep_store_add_child` and can leave partially-built state visible if the process aborts mid-update.

**Recommended workflow**

```c
cepCell branch = {0};
cepDT   name   = *CEP_DTAW("CEP", "ledger:entry");
cepDT   dict   = *CEP_DTAW("CEP", "dictionary");

/* 1. Build the hierarchy as a floating (ungrounded) cell. */
cep_cell_initialize_dictionary(&branch, &name, &dict, CEP_STORAGE_RED_BLACK_T);
cep_dict_add_value(&branch, CEP_DTAW("CEP", "state"), CEP_DTAW("CEP", "text"),
                   "pending", sizeof("pending"), sizeof("pending"));

/* 2. Attach the finished branch in one step. */
cepCell* target = cep_heartbeat_data_root();
cep_cell_add(target, 0u, &branch);

/* 3. Drop the temporary shell now that the branch is grounded. */
cep_cell_finalize(&branch);
```

**Practical guidelines**

- Keep staging nodes floating (`cep_cell_is_floating`) until you graft them. Use `cep_cell_initialize_*` helpers to prepare dictionaries, lists, or value nodes without touching the live tree.
- Populate children with the dictionary/list APIs (`cep_dict_add_value`, `cep_dict_add_dictionary`, `cep_cell_copy_children`, …). If any step fails, call `cep_cell_finalize`/`cep_cell_finalize_hard` before returning; no visible state was changed yet.
- When the branch is ready, attach it with `cep_cell_add`, `cep_dict_add`, or the append helpers. Make sure the destination already exposes a writable store (`cep_cell_ensure_dictionary_child` is the usual guard) so append-only guarantees stay intact.
- Replacing or removing anchored nodes must go through the store helpers (`cep_cell_remove_hard`, `cep_store_replace_child`). Never keep raw child pointers across mutations—look them up again by path.
- References: the append-only rules live in `docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md`.

### 1.10 OPS/STATES dossiers

Long-running kernel work surfaces as OPS/STATES dossiers so integrations can track progress, await transitions, and publish structured close metadata without inventing bespoke timelines.

#### Introduction
OPS/STATES records each long-running task under `/rt/ops/<oid>` so callers can watch progress without hand-rolling cell mutations. Starting an operation freezes its envelope, state transitions append to a history list, awaiters register continuations, and a close helper seals the outcome. The heartbeat keeps beat-by-beat determinism, so work queued for N never leaks into the current cycle.

#### Technical Details
- `cep_op_start(verb, target, mode, payload, len, ttl)` stages a transaction beneath `/rt/ops`, populates the branch while veiled, seals `envelope/`, initialises `state=ist:run`, provisions `history/` (list) and `watchers/` (dictionary), and returns a `cepOID`. TTL beats (0 = none) set watcher deadlines—they do not auto-close the op.
- `cep_op_state_set(oid, ist:*, code, note)` updates the live `state`, persists optional `code/note`, appends a history entry stamped with the current beat, and triggers watchers that asked for that state. Repeating the same state in the same beat is treated as idempotent (history is unchanged, but metadata refreshes).
- `cep_op_await(oid, want, ttl, cont, payload, len)` resolves immediately when `want` already matches the current state or terminal status; otherwise it stores a watcher entry with `want`, `deadline` (= current beat + ttl), `cont`, optional `payload_id`, provenance (descriptor label when run inside an enzyme), and an `armed` flag. Immediate matches write the entry with `armed=true` so the heartbeat still promotes the continuation exactly once; pending awaiters keep `armed=false` until the requested state or status arrives.
- `cep_op_close(oid, sts:*, summary, len)` creates an immutable `close/` branch (`status`, `closed_beat`, optional `summary_id`), maps the status to the terminal `ist:*`, appends the final history entry, and blocks further mutations. Duplicate closes with the same status are harmless; mismatched statuses return `false`.
- `cep_ops_stage_commit()` runs at the end of every heartbeat commit so continuations and TTL expiries share the same promotion path as other impulses. Entries flagged `armed=true` fire their continuation; entries whose `deadline <= current` emit `op/tmo`. Tests typically call `cep_heartbeat_step()` followed by `cep_heartbeat_resolve_agenda()` to assert single-fire behaviour.
- `cep_op_get(oid, buf, cap)` generates a quick textual summary (OID components, state, status, watcher count). For deeper inspection, walk the dossier directly—`envelope/` and `close/` are sealed, `history/` is append-only, and `watchers/` stays mutable.

### 1.11 Mailbox lifecycle and retention

When ingesting messages or managing backlogs, use the shared helpers so CEP keeps identifiers, TTLs, and backlog drains deterministic:

- `cep_mailbox_select_message_id()` picks IDs (caller ID → digest → counter) and records which strategy won.
- `cep_mailbox_resolve_ttl()` merges message/mailbox/topology scopes and records both beat and wallclock deadlines.
- `cep_mailbox_plan_retention()` partitions due items each beat and tells your retention enzyme whether future work remains.

Mailbox organs and PRR rely on these APIs, so reusing them keeps routing/backlog behaviour consistent across packs and replay runs.


## 2) Serialization & streams (wire format)

When cells travel between processes or shards they move as chunked streams. This chapter explains how the wire format is framed, how manifests and payloads pair up during capture/commit, and which helpers keep ingestion deterministic while respecting append-only history.

### 2.1 Chunk framing and the control header

Serialized streams are **chunked**. Each chunk carries a size and ID (class + transaction + sequence). The initial **control header** plants the **magic**, **format version**, **byte order**, and optional **metadata** (`cep_serialization_header_write/read`) . Helpers take care of **big‑endian on the wire** (inline BE conversions) and report exact buffer sizes so you can pre‑allocate (`*_chunk_size`) .

#### 2.1.1 Chunk helper utilities

When you stitch bespoke emitters or parsers alongside the stock helpers, these primitives give you direct control over chunk identifiers and header sizes without duplicating bit-twiddling code.

**Technical details**
- `uint64_t cep_serialization_chunk_id(uint16_t chunk_class, uint32_t transaction, uint16_t sequence)` composes the 64-bit chunk identifier from its components. Pair it with `cep_serialization_chunk_class/id/sequence` when you need to inspect or construct IDs manually.
- `uint16_t cep_serialization_chunk_class(uint64_t chunk_id)`, `uint32_t cep_serialization_chunk_transaction(uint64_t chunk_id)`, and `uint16_t cep_serialization_chunk_sequence(uint64_t chunk_id)` unpack the class/transaction/sequence fields from any chunk ID you receive on the wire.
- `size_t cep_serialization_header_chunk_size(const cepSerializationHeader* header)` tells you exactly how many bytes the control header will consume once encoded, making it easy to reserve buffers ahead of time.
- `bool cep_serialization_header_read(const uint8_t* chunk, size_t chunk_size, cepSerializationHeader* header)` validates a control chunk and fills the struct back in, freeing you from reimplementing the endianness handling.

**Q&A**
- *Do I ever need to craft chunk IDs by hand?* Only when you build specialised emitters or run tests that validate error conditions. For ordinary streaming, stick to `cep_serialization_emit_cell()` and let it number chunks for you.

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

#### 2.3.1 Reader lifecycle helpers

Streaming readers often live inside tight loops. These helpers reset or retire them without leaking staged buffers.

**Technical details**
- `void cep_serialization_reader_reset(cepSerializationReader* reader)` clears staged transactions, error state, and hash caches so the same reader can ingest a fresh stream from the start.
- `void cep_serialization_reader_destroy(cepSerializationReader* reader)` releases allocations associated with staging buffers, manifests, and blob scratch space. Call it once you are done ingesting streams from that root.

**Q&A**
- *Why not create a new reader every time?* Reusing a reset reader avoids repeated allocations when you decode many short streams (for example, in tests or on embedded targets).

### 2.4 Journal metadata helpers

Control headers now carry a tiny record of “which beat emitted this?” so downstream systems can file serialized batches without guessing.

**Technical details**

- `cepSerializationHeader` gained `journal_metadata_present`, `journal_beat`, and `journal_decision_replay` fields. Set the boolean to `true` to request metadata; leave it `false` if you supply your own `metadata` buffer.
- `cep_serialization_emit_cell()` auto-populates `journal_beat` with `cep_beat_index()` when you pass `NULL` for the header (or leave the boolean unset), so ordinary emitters get beat stamps for free.
- Structure manifests encode an extra byte after every `domain/tag` pair that mirrors the segment’s `glob` flag (`0x01` when set). Data descriptors append the same byte after the payload tag so wildcard hints survive round-trips.
- During write, the header encodes a 16-byte metadata block: beat (big-endian `uint64_t`), a flag byte (`0x01` for decision replay), and padding. Readers parse it back and set the struct fields when `metadata_length` matches the pattern.
- You can still inject arbitrary metadata: provide `metadata_length`/`metadata` and leave `journal_metadata_present` `false`; the serializer simply copies your payload.
- `void cep_serialization_mark_decision_replay(void)` flips the global flag so the next serialized batch advertises that it originated from a replay, mirroring what higher layers use during forensic exports.

---

## 3) Proxies & libraries (external resources inside cells)

When your data lives outside the kernel (files, device handles, remote streams), wrap it in a **proxy**:

* A proxy cell is created via `cep_proxy_initialize` with a `cepProxyOps` vtable: `snapshot`, `release`, `restore`, and `finalize`—so the serializer can **snapshot**, carry, and **rebuild** the proxy’s state without kernel‑specific codepaths in your adapter  .
* The “Library” flavor (`cep_proxy_initialize_handle` / `cep_proxy_initialize_stream`) lazily routes to a `cepLibraryBinding` (your adapter): retain/release handles, map/unmap stream windows, read/write chunks, and snapshot/restore both handles and streams. CEP handles **back‑references** and ensures link/shadow invariants even when proxies are moved or cloned  .

> **Tip:** For **streams**, prefer `stream_map`/`unmap` for large sequential I/O and `stream_snapshot` for “publish and ship” payloads during serialization. The serializer will switch between inline payloads and BLOB slices based on the configured threshold  .

**Additional helpers**
- `void cep_proxy_set_context(cepProxy* proxy, void* context)` refreshes the adapter-side context pointer without tearing down the proxy, handy when a library handle migrates.
- `void cep_proxy_release_snapshot(cepProxy* proxy)` tells the adapter it can drop any staged snapshot buffers once you finished emitting them.
- `const cepProxyOps* cep_proxy_ops(const cepProxy* proxy)` gives you the vtable bound to a proxy so diagnostics can confirm which adapter is attached.
- `void cep_link_initialize(cepCell* link, const cepCell* target)` initialises a link cell in place, preserving backlink bookkeeping, and is the easiest path to turn freshly cloned proxies into references without re-running the high-level builders.
- `cepStreamBinding cep_stream_binding_prepare(const cepData* data)` is a convenience wrapper that normalises HANDLE/STREAM payloads into a `(binding, resource)` pair. Use it whenever you need to call the adapter vtable; it hides the retain/release checks and guarantees that `library->ops` exists before you dereference function pointers.

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

### 4.1 ID utility helpers

Occasionally you need to inspect or craft identifiers yourself—whether to debug a misbehaving tag or to reset the namepool between tests. These helpers expose the same conversions the kernel uses internally.

**Technical details**
- `cepID cep_id_to_word(cepID word)` and `cepID cep_id_to_acronym(cepID acronym)` pack a lowercase “word” or uppercase “acronym” into a `cepID` slot with the correct naming nibble. Use them when you already validated the raw value and want to skip the text helpers.
- `bool cep_id_is_glob_star(cepID id)` and `bool cep_id_is_glob_question(cepID id)` tell you whether a reference ID is one of the wildcard sentinels (`*` or `?`). Handy when tooling needs to warn about overly broad matches.
- `bool cep_word_glob_match_text(const char* pattern, size_t pattern_len, const char* text, size_t text_len)` evaluates a word-style glob (`*` and `?`) against arbitrary ASCII text, mirroring how the dispatcher compares identifiers.
- `bool cep_namepool_reference_is_glob(cepID id)` reports whether an interned reference was stored via the pattern helpers, so you can separate literal references from glob-capable ones.
- `void cep_namepool_reset(void)` clears every dynamic entry from the namepool. Reserve it for test harnesses or controlled shutdown paths—it drops all references, so live identifier handles become invalid.

**Q&A**
- *Should production systems ever call `cep_namepool_reset()`?* No. It is intended for test fixtures or full process teardown. In production, prefer `cep_namepool_release()` on specific IDs so long-lived references remain valid.

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

### 5.2 Cleanup and hard-delete helpers

When construction fails or you intentionally prune branches, these routines perform the irreversible variants of the usual store/data edits. They honour the append-only contract only insofar as you call them during controlled teardown.

**Technical details**
- `cepCell* cep_cell_child_pop_hard(cepCell* parent, cepCell* child)` removes a child from its store immediately and returns ownership to the caller—ideal for transactional builders that need to roll back a partially staged node.
- `void cep_cell_delete_children(cepCell* cell)` queues soft deletes for every child, while `void cep_cell_delete_children_hard(cepCell* cell)` removes them in-place and frees backing storage.
- `void cep_cell_delete_data_hard(cepCell* cell)` clears the payload history and releases buffers so the node becomes data-less without waiting for GC.
- `void cep_cell_delete_store(cepCell* cell)` marks the store timeline as deleted; `void cep_cell_delete_store_hard(cepCell* cell)` also frees the store engine immediately.
- `void cep_cell_dispose(cepCell* cell)` and `void cep_cell_dispose_hard(cepCell* cell)` shut down both data and store sides of a cell (soft vs hard), making it safe to recycle structs from object pools.
- `void cep_cell_initialize_clone(cepCell* clone, const cepCell* source)` copies the structural metadata from `source` into `clone` so you can duplicate nodes without re-running every individual `initialize` call.
- `void cep_cell_replace(cepCell* cell, cepCell* replacement)` swaps a live node out for a prepared replacement, preserving parent pointers.
- `int cep_cell_set_data(cepCell* cell, cepData* data)` and `int cep_cell_set_store(cepCell* cell, cepStore* store)` rebind payloads/stores that you constructed out-of-band.
- `void cep_cell_timestamp_reset(cepCell* cell)` rewinds the created/modified timestamps—useful in tests that need deterministic snapshots after rebuilding a branch.
- `void cep_data_history_clear(cepData* data)` and `void cep_data_del(cepData* data)` wipe the append-only history or delete the payload outright; call them only when you are certain no historical replay is required.

**Q&A**
- *Can I mix hard deletes with replayable history?* Avoid it. Hard deletes are for teardown paths (failed construction, controlled GC). Production mutations should stick to soft deletes so replays and audits remain consistent.

### 5.3 Traversal and ancestry utilities

When you need to walk or query the tree by hand, these helpers expose the same search and iteration primitives the kernel uses internally.

**Technical details**
- `cepCell* cep_cell_find_by_position_past(const cepCell* parent, size_t index, cepOpCount at)` looks up the child that occupied `index` at a given beat, bridging deterministic replay with positional lookups.
- `cepCell* cep_cell_prev_past(cepCell* cell, cepOpCount at)` and `cepCell* cep_cell_next(cepCell* cell)` step through siblings while honouring the append-only history.
- `cepCell* cep_cell_parent(cepCell* cell)` and `size_t cep_cell_siblings(const cepCell* cell)` report ancestry details, while `size_t cep_cell_children(const cepCell* cell)` returns the current child count (zero when no store exists).
- `cepCell* cep_cell_data_find_by_name(cepCell* cell, const cepDT* name)` and `cepCell* cep_cell_data_find_by_name_past(cepCell* cell, const cepDT* name, cepOpCount at)` locate payload entries by identifier, including historical snapshots.
- `bool cep_cell_traverse_internal(cepCell* cell, cepTraverse func, void* context, cepEntry* entry)` and `bool cep_cell_deep_traverse_internal(...)` expose the iterator core so specialised walkers can control recursion.
- `void cep_cell_relink_storage(cepCell* cell, cepStore* store)` swaps the underlying store engine while preserving child nodes—handy when promoting a temporary container to its durable form.

**Q&A**
- *Do these traversal helpers lock stores for me?* No. Acquire the necessary store/data locks before deep traversals if concurrent mutations are possible.

### 5.4 State and store inspectors

Diagnostics and guards often need quick answers about a node’s shape or payload. These inspectors read state without mutating anything.

**Technical details**
- `cepID cep_cell_get_autoid(cepCell* parent)` hands you the next numeric ID in a store, matching the auto-ID allocator.
- `bool cep_cell_has_store(const cepCell* cell)` tells you whether the node currently carries child storage, while the trio `cep_store_is_dictionary/store_is_insertable/store_is_sorted` reveal the storage policy bound to it.
- Predicates such as `cep_cell_is_deleted`, `cep_cell_is_dictionary`, `cep_cell_is_empty`, `cep_cell_is_f_sorted`, `cep_cell_is_floating`, `cep_cell_is_insertable`, `cep_cell_is_root`, `cep_cell_is_sorted`, and `cep_cell_is_unset` make assertions readable without spelunking internal flags.
- `cepOpCount cep_cell_latest_timestamp(const cepCell* cell)` returns the newest of created/modified/deleted timestamps; use it when you compare freshness across branches.
- `int cep_store_compare_cells(const cepCell* a, const cepCell* b)` evaluates the current store ordering function, which is useful when you need to maintain sorted inserts manually.
- `const void* cep_data_payload(const cepData* data, size_t* size)` and `bool cep_data_equals_bytes(const cepData* data, const void* bytes, size_t len)` examine payload contents without copying.
- Store predicates (`cep_store_is_dictionary`, `cep_store_is_empty`, `cep_store_is_f_sorted`, `cep_store_is_insertable`, `cep_store_is_sorted`) return `true` when the underlying storage engine matches the named characteristic.

**Q&A**
- *Why use these inspectors instead of peeking at struct fields?* They encode the exact invariants enforced by the kernel, so you stay compatible even if internal layouts change.

---

## 6) Recipes

Quick, copy‑pasteable snippets that show the happy-path sequence for common integration chores. Each recipe links the narrative guidance earlier in the guide to the concrete API calls you’ll make in production.

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

### D) Stage a veiled transaction in place

Sometimes you want a finished subtree to appear all at once even though it needs several steps to build. Veiled transactions let you assemble that branch under its final parent while keeping it invisible until you commit.

```c
cepTxn txn;
cepDT name = *CEP_DTAW("CEP", "report");
cepDT kind = *CEP_DTAW("CEP", "dictionary");
if (!cep_txn_begin(parent, &name, &kind, &txn)) {
    return CEP_ENZYME_RETRY; // parent missing or name collision
}

// Populate the veiled subtree.
cepDT title = *CEP_DTAW("CEP", "title");
cep_cell_put_text(txn.root, &title, "Q4 revenue snapshot");

if (!validate(txn.root)) {
    cep_txn_abort(&txn);
    return CEP_ENZYME_SUCCESS;  // no leak, nothing became visible
}

cep_txn_mark_ready(&txn);  // optional breadcrumb for observability
if (!cep_txn_commit(&txn)) {
    return CEP_ENZYME_RETRY;   // lock contention or heartbeat shutdown
}
```

- `cep_txn_begin` fails fast if the parent cannot host the new child (missing store, name collision, or out-of-memory). The helper marks the new subtree veiled and writes `meta/txn/state="building"` so tooling can spot it.
- While the transaction is veiled the usual readers and resolvers ignore it; use `cep_cell_visible_latest(txn.root, CEP_VIS_INCLUDE_VEILED)` if you need to inspect the staged work.
- `cep_txn_commit` locks the subtree briefly, stamps zeroed timestamps with the current beat, clears the veil, flips the metadata to `committed`, and records a heartbeat stage note. `cep_txn_abort` tears the branch down without leaking nodes or backlinks.

**Q&A**
- **What about links or enzymes inside the staged branch?** They are safe to register while veiled. Link targets cannot point outside the veiled ancestor, and enzyme bindings stay dormant until the branch is committed.
- **Can I reuse the same `cepTxn` after commit?** No. Each commit or abort clears the struct; start a fresh transaction for the next staging cycle.
- **How do I surface a partially built subtree for debugging?** Call the usual find/traverse helpers with `CEP_VIS_INCLUDE_VEILED`; everything else about the API is unchanged.

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

* **E³ episodes replace Rendezvous.** Retire any lingering Rendezvous hooks and model long-running work as episodes: queue slices with the executor, await `op/ep` dossiers, and use `cep_ep_cancel_ticket()` / `cep_ep_check_cancel()` for cooperative shutdown.
* **Don’t mutate mid‑beat registrations.** Register enzymes freely, but let CEP **activate** them between beats (`activate_pending`) to avoid agenda drift .
* **Prefer soft deletes** for observability; reserve hard deletes for GC or error recovery workflows. Past traversals depend on timestamps and history lists .
* **Respect locks**. Both **data** and **store** locks check the *entire ancestor chain*; if anything is locked above, mutations are denied to keep invariants intact  .
* **Proxy cloning.** Cloning cells whose payload is a handle/stream produces **links**, not resource copies—by design, to keep a single authoritative resource endpoint .
* **Hash checks are end‑to‑end.** The reader recomputes the same **content hash** the writer recorded; any mismatch aborts the apply phase before mutating the tree  .

---

## 9) Lifecycle signals in practice

Heartbeat init/shutdown operations now mirror production beats, so tooling and tests can treat them as first-class events instead of ad-hoc bootstrap helpers.

### Technical details
- Call `cep_heartbeat_begin()` right after `cep_heartbeat_configure()` when you want the system-init cascade; follow it with `cep_heartbeat_step()` so any pack-specific init descriptors you registered actually execute.
- `cep_heartbeat_emit_shutdown()` enqueues the shutdown operation on the live agenda and drives the same commit path as a normal beat.
- Each bootstrap helper now marks its subsystem as ready by writing to `/sys/state/<scope>` (`status=ready`, `ready_beat=<n>`). Shutdown walks the scopes in reverse dependency order, records `status=teardown` / `td_beat`, and closes the `op/shdn` timeline once all scopes report `ok`.
- The `/sys/state` dictionary and `/rt/ops/<oid>` branches are durable, so tooling can poll readiness/teardown even if the corresponding operations have already completed; readiness helpers return `false` if prerequisites have not finished booting.

## Global Q&A
- *How do I check that init ran during a test?* Inspect `/rt/ops/<boot_oid>` or verify that `cep_heartbeat_sys_root()` picked up the expected namespaces after the first beat—both advance as the boot operation progresses.
- *How do I know a subsystem is ready for work?* Read `/sys/state/<scope>/status` (expect "ready"), or call `cep_lifecycle_scope_is_ready(scope)`. Awaiters can also subscribe to the boot/shutdown operations via `cep_op_await`.
- *Can I replay init mid-run?* Yes. Call `cep_heartbeat_restart()`, then `cep_heartbeat_begin()` and a single `cep_heartbeat_step()`; the boot operation records the fresh states so you can line them up with assertions.
- *Will emitting shutdown twice cause trouble?* No. The helper is idempotent; once `sys_shutdown_emitted` flips, subsequent calls simply return `true`.
- *Do I need to call the phase helpers manually?* No. They are wired into `cep_heartbeat_resolve_agenda()` and `cep_heartbeat_stage_commit()`. Manual calls are only for bespoke schedulers.
- *What happens to mid-beat registrations?* They are counted and deferred; the agenda for the current beat never mutates.
- *What should I do with old `cep_mailroom_*` calls?* Delete them. Register pack-owned routing enzymes or write directly into your target inboxes, and track longer-term dispatcher work in your pack backlog.
- *How do I stage intents safely without the mailroom?* Wrap writes with `cep_txn_begin()`/`cep_txn_commit()` (or an equivalent helper) so veiled staging and audit links stay explicit.
- *Do I still call pack bootstraps?* Yes. Each optional pack must provision its own ledgers, inboxes, or indexes before handling impulses.
- *How do I disable the automatic beat stamp in serialization?* Supply your own `cepSerializationHeader` with `journal_metadata_present = false` (and custom metadata) or set the boolean to `false` before emitting cells.
- *What toggles `journal_decision_replay`?* Higher layers set it when replaying stored decisions; the kernel preserves the advisory flag during round-trips.
- *Do parent links survive hard deletes?* They remain as shadow entries flagged via the link lifecycle—useful when diagnosing stale references.
- *Should I hash huge blobs with `cep_cell_content_hash()`?* Treat it as an integrity hint. For high-assurance payloads, store your own checksum alongside the data and view the built-in hash as advisory.
- *When should I choose `opm:direct` over `opm:states`?* `opm:direct` fits two-impulse flows (start → close). `opm:states` is for multi-phase work where intermediate checkpoints must be observable or awaitable.
- *How do I test awaiters deterministically?* Register a test enzyme on `op/cont` (or `op/tmo`), call `cep_op_await()`, advance a beat with `cep_heartbeat_step()`, then resolve the agenda. The enzyme should fire exactly once—immediately if the state already matched, otherwise on the next beat.
- *Can I attach large artefacts to the close record?* Yes. Drop a CAS handle or library reference into the `summary` payload; the close branch keeps it immutable while heavy bytes live in content storage.
- ### 1.12 Episodic Enzyme Engine (E³) promotion and demotion

When you select the hybrid profile (`cepEpExecutionPolicy.profile = CEP_EP_PROFILE_HYBRID`), episodes start life on the threaded RO pool but can opt into mutations when needed:

- **Promote to RW.** Call `cep_ep_promote_to_rw()` from inside the active slice. Pass an optional array of `cepEpLeaseRequest` descriptors when you already know which subtrees need locks (supply both the path and, when convenient, the resolved `cepCell*` so the lease can reuse the pointer without another lookup). The helper queues those lease requests, flips the episode into `mode_next = RW`, and forces a yield so the heartbeat activates the cooperative slice on the next beat. When the new slice begins, `cep_ep_apply_pending_leases()` acquires the requested store/data locks before your callback resumes.
- **Mutate safely.** Once promoted, the slice behaves like a standard RW episode—`cep_ep_request_lease()` continues to work, `cep_ep_require_rw()` allows writes (but still enforces lease ownership), and CPU/IO budgets continue to accumulate on the shared `cepEpExecutionContext`.
- **Demote back to RO.** After releasing leases and finalising any transactional work (`cep_txn_commit`/`cep_txn_abort`), call `cep_ep_demote_to_ro()`. The helper records `mode_next = RO` and yields; the heartbeat rebuilds a threaded ticket so subsequent slices return to the worker pool. Attempting to demote while leases remain (or while the slice is suspended) fails fast so replay stays deterministic.

If you forget to promote before mutating, `cep_ep_require_rw()` emits a CEI advisory (`ep:pro/ro`) and returns false, making it obvious that an upgrade is required. Demotion requests are idempotent—calling them in an already-RO slice simply returns true.

### 1.13 Pause / Rollback / Resume (PRR)

The PRR helpers (`cep_runtime_pause()`, `cep_runtime_rollback()`, `cep_runtime_resume()`) let you gate work deterministically while maintenance or recovery tasks run:

- **Pause.** Acquires `/data` locks, enqueues an `op/pause` dossier (`ist:plan → ist:quiesce → ist:paused`), and routes new impulses into `/data/mailbox/impulses` until resume opens the gate.
- **Rollback.** Records the target beat, updates `/sys/state/view_hzn`, trims the backlog mailbox, and emits `op/rollback` history so downstream tooling knows which beat range is visible.
- **Resume.** Re-opens the agenda, drains the backlog mailbox in deterministic ID order, and closes the control dossier with `sts:ok` once normal scheduling resumes.

Tests: see `src/test/l0_kernel/test_prr.c` and the integration POC pause/rollback scenario. Design rationale lives in `docs/L0_KERNEL/design/L0-DESIGN-PAUSE-AND-ROLLBACK.md`.
