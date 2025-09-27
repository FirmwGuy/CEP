# L0 Kernel: Root Directory Layout

This document describes a practical, deterministic directory structure for CEP cells when introducing the heartbeat runtime and enzymes.


## 1) Introduction

Imagine a tidy workshop:
- A bench for the work that’s happening right now (runtime).
- Shelves for official records and history (data and journals).
- A toolbox with specialized helpers (enzymes and library adapters).
- A safe for big, heavy items (large files by hash in a content store).

Work in CEP happens in beats. What you prepare during beat N only becomes visible to everyone at beat N+1. This rhythm keeps the workshop calm, debuggable, and fair: nothing “jumps the line,” and you can always explain what happened and why.


## 2) Technical Layout

At the root, use a dictionary by name for stable lookups. Each top-level folder has a clear purpose and storage mode.

```
/
  sys/       — system settings & constants (dictionary)
  rt/        — live runtime per heartbeat (dictionary)
  enzymes/   — enzyme registry (durable definitions) (dictionary)
  env/       — handles to outside world (dictionary; HANDLE/STREAM)
  journal/   — intents, reads, outcomes by beat (append-only) (dictionary)
  cas/       — content-addressed store for large payloads (dictionary)
  lib/       — adapters for external libraries (dictionary)
  data/      — durable application data (dictionary)
  tmp/       — ephemeral scratch outside a beat (list)
```

#### Determinism Rules
- Root-level folders are dictionaries; iteration order is defined by name compare.
- Queues are lists by insertion order. No nondeterministic iteration.
- External reads/writes are journaled with hashes and preconditions.
- Outputs created in N become visible in N+1.
- See also: `docs/L0_KERNEL/APPEND-ONLY-AND-IDEMPOTENCY.md` for cell-level append-only history and idempotent updates.

We’ll use a running example: “resize_image” enzyme that makes a thumbnail for `/env/fs/projects/p1/img123.jpg` and writes the result to `/data/assets/img123/thumbnail`.

### 2.1 `sys/` — System Settings and Constants (dictionary)

#### Purpose
- House global kernel settings, heartbeat counters, and optional schema/type anchors.
- Rarely changes during a beat; read-only for most enzymes.

#### Typical Contents
- `sys/time`: current beat, epoch/time policy, tick duration.
- `sys/config`: budgets, logging levels, toggles.
- `sys/schema`: bootstrap type IDs (optional, for inspection tools).

#### Storage
- Dictionary by name; stable iteration. Small VALUE/DATA cells.

#### Example
1) Initialize beat counters:
   - `/sys/time/current = 1`
   - `/sys/time/tick_ms = 50`
2) Enzymes read `/sys/time/current` to label runtime nodes under `rt/beat/1/*`.

### 2.2 `rt/` — Runtime State Per Heartbeat (dictionary)

#### Purpose
- Everything live and transient while a beat is executing.
- Scopes effects and ensures visibility at the N→N+1 boundary.

#### Structure
```
rt/
  beat/<N>/
    inbox     — impulses/events queued for the beat (list)
    agenda    — runnable enzyme queue (list)
    tokens    — per-enzyme instances/tokens (dictionary → list)
    stage     — outputs staged for commit (list)
    locks     — resource reservations (dictionary)
    budgets   — time/memory/IO budgets (dictionary)
    metrics   — counters & gauges (dictionary)
  tmp         — ephemeral buffers (list)
```

#### Storage
- `rt/beat/<N>/*/inbox|agenda|stage`: list by insertion.
- `tokens|locks|budgets|metrics`: dictionaries (and sublists as needed).

#### Note
- Agenda resolution uses an in-memory enzyme function registry keyed by
  query paths. No function pointers are ever stored inside cells for
  security and portability.

#### Example
1) Beat 1 begins; create `rt/beat/1/*`.
2) An impulse arrives: “make thumbnail for img123.”
   - Append to `/rt/beat/1/inbox`: `{kind=make_thumbnail, target=/env/fs/.../img123.jpg}`
3) Scheduler moves it to `/rt/beat/1/agenda` and spawns a token:
   - `/rt/beat/1/tokens/resize_image/0001 = {state=ready, budget_ms=5}`
4) As the enzyme runs, it writes staged outputs (not yet visible):
   - Append to `/rt/beat/1/stage`: `(/data/assets/img123/thumbnail, bytes=..., hash=H1)`
5) Metrics update:
   - `/rt/beat/1/metrics/resize_image/processed += 1`

### 2.3 `enzymes/` — Registry of Enzyme Definitions (dictionary)

#### Purpose
- Durable, auditable declarations of enzyme capabilities.
- Versioned metadata and I/O contracts (domains touched, preconditions, budgets).
 - Security: this directory stores only metadata. It never persists function
   addresses or code pointers.

#### Structure
```
enzymes/
  <name>/
    io       — declared read/write domains (dictionary)
    policy   — budgets, concurrency, retry (dictionary)
    impl     — binding/adapter metadata (dictionary)
    version  — semantic version (value)
```

#### Storage
- Dictionary by name; small cells with VALUE/DATA.

#### Function Registry (Runtime, Non-Persistent)
- Residency: process memory only; built via `cep_enzyme_register(query, fn)`.
- Key: a “query” `cepPath` describing what the enzyme should react to.
- Value: ordered list of `cep_enzyme_fn` function pointers.
- Matching: eligible when the query matches either the inbox item’s
  `signal_path` or its `target_path`.
- Ordering: deterministic — sort by match specificity, then by registration
  order. Details in `docs/L0_KERNEL/HEARTBEAT-AND-ENZYMES.md`.
- Persistence: none. Only enzyme metadata under `enzymes/` is durable.

#### Example
1) Register `resize_image`:
   - `/enzymes/resize_image/version = 1.0.0`
   - `/enzymes/resize_image/io/reads = [env/fs]`
   - `/enzymes/resize_image/io/writes = [data/assets]`
   - `/enzymes/resize_image/policy/budget_ms = 5`
2) The scheduler validates that the token conforms to `io` and `policy`.

### 2.4 `env/` — Handles to the Outside World (dictionary)

#### Purpose
- Model external resources via HANDLE/STREAM without peeking internal fields.
- Gate all reads/writes through adapters and journal them for replay.

#### Structure
```
env/
  fs/   — files, directories (HANDLE/STREAM)
  net/  — sockets, HTTP endpoints (HANDLE/STREAM)
  db/   — database connections (HANDLE/STREAM)
  gpu/  — GPU buffers (HANDLE/STREAM)
```

#### Storage
- Dictionary of handles; content accessed via adapters in `lib/` and journaled.

#### Example
1) Create a file handle:
   - `/env/fs/projects/p1/img123.jpg = HANDLE{identity=F:... , version=Etag123}`
2) `resize_image` requests a STREAM window (read):
   - Adapter returns `{offset=0, length=64KiB, hash=H0}` scoped to beat 1.
3) The read is recorded under `/journal/beat/1/reads` (see next section).

### 2.5 `journal/` — Intents, Reads, Outcomes (append-only) (dictionary)

#### Purpose
- The auditable trace that enables simulation (no side effects) and re-apply (touch the world again if preconditions hold).

#### Structure
```
journal/
  beat/<N>/
    reads    — recorded STREAM reads with hashes (list)
    intents  — write intents with preconditions and idempotency (list)
    outcomes — commit results and divergences (list)
```

#### Storage
- Lists by insertion; items reference CAS entries for large payloads.

#### Example
1) Record read of `img123.jpg` header:
   - Append to `/journal/beat/1/reads`: `{target=/env/fs/.../img123.jpg, off=0, len=64KiB, hash=H0}`
2) Stage a write intent for thumbnail:
   - Append to `/journal/beat/1/intents`: `{target=/data/assets/img123/thumbnail, precond=none, body_hash=H1, idempotency=K1}`
3) On commit (N→N+1), outcome recorded:
   - Append to `/journal/beat/1/outcomes`: `{intent=K1, applied=true, final_hash=H1}`

### 2.6 `cas/` — Content-Addressed Store (dictionary)

#### Purpose
- Keep large payloads by hash to avoid duplication and support exact replay.

#### Structure
```
cas/
  <algo>/<prefix>/<hash>  — stored payload
  pins/                   — references preventing GC
```

#### Storage
- Dictionary by path; payloads as opaque bytes; small metadata cells for pins.

#### Example
1) Store thumbnail bytes:
   - `/cas/sha256/ab/cdef...` = stored payload (opaque bytes)
2) Reference from journal intent/outcome by `hash=H1` and pin if needed:
   - `/cas/pins/thumbnail/img123 = H1`

### 2.7 `lib/` — External Library Adapters (dictionary)

#### Purpose
- Define glue code contracts (vtables), lifetimes, and safe debug serializers.

#### Structure
```
lib/
  imageio/
    vtable   — handle/stream ops (dictionary)
    safety   — lifetime, zero-copy guarantees (dictionary)
    debug    — stable, human-readable serializer (dictionary)
```

#### Storage
- Dictionary of small VALUE/DATA cells and references to code modules.

#### Example
1) Register `imageio` adapter used by `env/fs` file handle:
   - `/lib/imageio/safety/zero_copy = false` (forces snapshot for decisions)
2) `resize_image` resolves the handle’s adapter through `lib/imageio`.

### 2.8 `data/` — Durable Application Data (dictionary)

#### Purpose
- The authoritative state produced by committed workflows. Visible at N+1.

#### Structure
```
data/
  assets/
    img123/
      original   — HANDLE or reference to env/fs (optional)
      thumbnail  — DATA (bytes) or HANDLE to env/fs copy
```

#### Storage
- Mostly dictionaries for stable lookup; lists for ordered collections.

#### Example
1) After commit of beat 1, the thumbnail becomes visible:
   - `/data/assets/img123/thumbnail = DATA{hash=H1, size=…}`
2) Any views or indices (e.g., by creation time) are updated deterministically.

### 2.9 `tmp/` — Ephemeral Workspace (list)

#### Purpose
- Scratch space outside a specific beat; cleared on startup or per policy.

#### Storage
- List by insertion; no durability guarantees; never drives decisions.

#### Example
1) During development, an enzyme may write debug dumps here:
   - `/tmp/resize_image/preview_0001.png` (not journaled, not durable)


## 3) Beat Lifecycle (N → N+1)

1) Input: enqueue impulses into `/rt/beat/N/inbox`.
2) Schedule: move items to `/rt/beat/N/agenda`, spawn/update `/rt/beat/N/tokens/*`.
3) Execute: enzymes read from `/env/*` and `/data/*` → record `/journal/beat/N/reads`.
4) Stage: enzymes prepare outputs in `/rt/beat/N/stage` and log `/journal/beat/N/intents`.
5) Commit edge: apply intents with preconditions; write durable results into `/data/*` (and possibly `/env/*`), record `/journal/beat/N/outcomes`.
6) Visibility: staged outputs from N become visible at `N+1`.
7) Rotate: initialize `rt/beat/N+1/*`, GC `rt/beat/N/*` per policy.

### Mini End-to-End Example (Recap)
- Beat 1: read `/env/fs/.../img123.jpg` header → `journal/beat/1/reads`.
- Beat 1: stage thumbnail bytes → `rt/beat/1/stage`; intent → `journal/beat/1/intents`.
- Commit: store payload in `cas/*`, write `/data/assets/img123/thumbnail`, record `journal/beat/1/outcomes`.
- Beat 2: `/data/.../thumbnail` is visible to other enzymes and users.


## 4) Implementation Notes & Checklists

#### Storage/Indexing
- Dictionaries: use name-based compare; RB-tree where ordered iteration matters.
- Queues: lists by insertion; avoid mixing sorted and insertion modes in a store.

Determinism
- All reads/writes go through `journal/beat/N/*`.
- No hidden side effects; enzyme outputs appear only at N+1.
- Use canonical bytes for VALUE/DATA per `NATIVE-TYPES.md`.

#### Ownership and Lifetimes
- `rt/*` and `tmp/` are ephemeral.
- `data/`, `enzymes/`, `lib/`, `env/` handles are durable.
- `cas/` is durable with GC via `pins/`.

#### Testing
- Seed a beat, enqueue impulses, run a dry simulation reading only from `journal`.
- Verify that re-apply respects preconditions and reproduces outcomes.


## 5) Q&A

Q: Why separate `rt/` from `journal/`?
A: Runtime is mutable and short-lived; the journal is append-only evidence used for simulation and re-apply. Separation keeps mutation fast and auditing clean.

Q: Do enzymes ever write directly to `data/`?
A: No. They stage outputs in `rt/beat/N/stage` and declare intents. The commit edge applies them to `data/` so visibility is deterministic (N+1).

Q: Can I skip `cas/` initially?
A: Yes. You can start by hashing payloads and only introduce a CAS when large data or deduplication matters. Journals can reference payload hashes even before CAS is present.

Q: How do I replay exactly?
A: Use `journal/beat/N/*` and `cas/*`. In simulate mode, serve reads/writes from the journal/CAS without touching the world. In re-apply mode, enforce preconditions (hash/ETag/version) and record divergences.

Q: What about concurrency?
A: Concurrency is coordinated through `rt/beat/N/agenda`, `tokens`, and `locks`. Determinism comes from explicit ordering in lists and from journaled choices; avoid nondeterministic iteration or hidden shared state.

Q: Where do adapter details live?
A: Under `lib/*`. Enzymes reference adapters via handles in `env/*`. Adapters define identity/versioning, zero-copy rules, and safe debug serializers.

Q: Are names or IDs special?
A: Use dictionaries for stable name-based lookup. Numeric IDs (e.g., beat numbers, token counters) can be used in child names where helpful. Follow `cepDT` rules for valid IDs.
