# L0 Topic: Accessing Foreign Library Structures

This document explains how the CEP kernel (Layer 0) safely uses internal data from external libraries (audio, video, 3D, networking, etc.).

## Intro

Imagine a workshop full of specialized machines owned by different teams. You don’t take those machines apart to use them; you either:
- Get a claim ticket to the machine (a handle) and ask the attendant to perform specific actions for you, or
- Take a photo or a measured copy of the result you need (a snapshot) and work with that copy elsewhere.

CEP treats foreign library internals the same way:
- Opaque handle: a safe claim ticket that lets CEP refer to “that thing over there” without peeking inside it.
- Snapshot: a precise copy (opaque bytes with a cepDT tag) that CEP can store, compare, hash, and replay on its own.

Why this approach?
- Determinism: you can replay exactly because snapshots are precise and handles carry stable identity and version.
- Safety: CEP doesn’t rely on hidden fields that may change without warning.
- Performance: where possible, CEP borrows read‑only views (zero‑copy) under strict rules; otherwise, it copies just what’s needed.

In short: use a handle when you mean “that external thing,” use a snapshot when you need stable bytes inside CEP. Never rummage around inside a library’s private drawers.

---

## Technical Model

### Core Principles

- Opaqueness at the boundary: CEP never dereferences foreign struct fields directly. It calls adapter functions owned by the library integration.
- Replay first: Decisions depend on bytes CEP can hash. If you read from a foreign structure, either provide a stable view (zero-copy) or take a snapshot into CEP data.
- Identity vs content: A handle identifies a resource; a snapshot represents its content. Equality of handles is identity; equality of snapshots is bytewise.
- Heartbeat discipline: Reads/writes stage within a beat and become visible at N+1. Borrowed views must not outlive their beat.
- Preconditions: Mutations against foreign resources require version checks (hash/ETag/sequence). Mismatch records a divergence instead of silently merging.
- Binding lifecycle: use `cep_library_initialize(...)` to register the adapter vtable and opaque context. L0 will invoke `handle_retain/release` around HANDLE/STREAM payload lifetime so adapters can refcount or pin resources.

### Representations at L0

- `cepData.VALUE` / `cepData.DATA` (snapshots)
  - Opaque bytes stored inside CEP. Deterministic bytewise hashing, comparison, and replay.
  - Use when decisions depend on content or when foreign memory cannot be safely borrowed.

- `cepData.HANDLE` (opaque handle)
  - Reference to a foreign resource managed by an adapter vtable. Carries identity and optional version.
  - Use when you need to refer to the thing itself, pass it around, schedule operations, or branch by identity.

- `cepData.STREAM` (windowed I/O)
  - An offset/length byte window onto a foreign stream or buffer. Operations are recorded with preconditions and idempotency keys (see I/O Streams doc).

### Adapter (Glue) Layer

Each integrated library provides an adapter with a small, explicit vtable. Typical responsibilities:

- Lifetime and ownership
  - Create/destroy handles; pin/unpin external memory; reference counting if available.
  - Guarantee that borrowed views remain valid at least for the current heartbeat.
  - Provide `handle_retain/release` hooks in the vtable so L0 can respect adapter ownership rules when HANDLE/STREAM cells are created or destroyed.

- Tagged accessors (by cepDT; no raw field peeking)
  - Read-only getters that return CEP snapshots (VALUE/DATA) or stream windows.
  - Enumerators that yield items as snapshots or handles with their own accessors.
  - Optional debug serializers that expose a safe, stable description for logs.

- Mutations with preconditions
  - Methods accept expected version/ETag/hash; adapter checks and applies, returning outcomes for journaling.
  - Expose idempotency keys where the foreign system supports them.
  - Implement `stream_read/write/map/unmap` callbacks so `cep_cell_stream_*` can journal I/O while the adapter enforces foreign invariants.

- Threading and scheduling
  - Document thread safety. If the library is not thread‑safe, serialize through the adapter.
  - Ensure external effects are staged and committed on heartbeat boundaries.

### Zero‑Copy Rules

Zero‑copy reads (borrowing a direct view into foreign memory) are allowed only if ALL conditions hold:

1) Read‑only guarantee for the view’s lifetime (no in‑place mutation by the library or other threads).
2) Lifetime ≥ one heartbeat, or the adapter renews the view seamlessly within the same beat.
3) Stable address or stable content hash; CEP ties decisions to a hash of the bytes it looked at.
4) Clear destructor/cleanup to unpin/unmap when the view is released.

If any condition is violated or uncertain, take a snapshot into `cepData.DATA` and proceed deterministically.

### Snapshots vs Handles: Choosing

- Choose a snapshot when:
  - You need to compare, hash, or persist the content.
  - The library can’t guarantee a safe, read‑only view.
  - You will branch logic on exact bytes (e.g., format headers, small structs).

- Choose a handle when:
  - You’re orchestrating the resource (play/pause a stream, render to a target).
  - You need to pass identity through flows and apply effects later.
  - Content is too large or too dynamic to snapshot, but you will access it via stream windows with preconditions.

### Identity, Versioning, Equality

- Handle identity: an adapter‑defined stable ID (pointer+generation, GUID, file inode+device, GPU buffer ID).
- Handle version: monotonic counter, ETag, or content hash checkpoint. Used as a precondition for mutations and to detect divergence.
- Equality semantics:
  - Handles: equal if identity matches; ordering is by identity bytes.
  - Snapshots: bytewise equality on canonical bytes; ordering per L0 type rules.

### Borrowing and Heartbeats

- All borrowed views (zero‑copy) are scoped to the current heartbeat unless explicitly extended by the adapter.
- At N→N+1, staged external effects commit; outcomes and journal entries become visible. Adapters must flush/fence DMA or GPU work before reporting success.

### Safety Checklist for Adapters

- Define identity and version; document how they are computed.
- Prove or enforce read‑only guarantees for any zero‑copy views.
- Provide a snapshot path for any data that influences decisions.
- Validate types and sizes; align with each tag’s canonicalization (endianness/encoding chosen by enzymes). L0 remains bytewise only.
- Enforce preconditions on mutations; record outcomes and divergences.
- Manage lifetimes: refcount/pin, and clean up exactly once.
- Be explicit about threading; serialize if needed.

### Examples

- Audio buffer
  - Handle: `AudioDevice` or `AudioStream` with identity and version.
  - Zero‑copy: expose read‑only frames for the current beat if the library guarantees immutability; otherwise snapshot frames used for decisions.
  - Stream writes: windowed writes with expected frame counter; commit at N+1.

- Video frame
  - Handle: `FrameSurface` (CPU or GPU). Identity is surface ID; version increments on each new frame.
  - Zero‑copy: CPU RAM frames may be borrowed; GPU textures require explicit staging or mapped ranges with fences.

- 3D mesh
  - Handle: `MeshBuffer` with vertex/index buffers.
  - Snapshots: small headers (counts/formats) as VALUE/DATA; large buffers via STREAM windows with periodic checkpoints.

- Network socket
  - Handle: `Socket` with connection identity.
  - Reads: STREAM segments (offset/length/hash) logged via the gateway.
  - Writes: intents with idempotency keys; outcomes recorded with status and response hashes.

---

## Q&A

Q: Can the kernel peek inside a C struct from a library?
A: No. CEP treats foreign structs as opaque. Access happens through adapter getters that return snapshots or controlled views.

Q: Can I wrap a raw pointer as a handle?
A: Yes, but include a generation counter or GUID to avoid ABA issues, and a destructor/refcount to prevent double‑free. Never expose the pointer for arithmetic in CEP.

Q: How do I avoid copying large buffers?
A: Use STREAM windows with preconditions and optional zero‑copy views under the Zero‑Copy Rules. Periodically record checkpoints (full hash or Merkle root) for verification.

Q: What about GPU textures or DMA buffers?
A: Represent them as handles with explicit fences/barriers. For content‑dependent decisions, stage to CPU memory and snapshot or compute a hash on the device and record it.

Q: How do I compare two handles?
A: By identity only. If you need content equality, take snapshots or compare recorded hashes/checkpoints.

Q: Is this just like Python/C FFI copying data back and forth?
A: The adapter concept is similar, but CEP adds determinism: every content‑dependent read is recorded (bytes or hashes), and every mutation is guarded by preconditions and journaled.

Q: Can I hold a borrowed view across multiple beats?
A: Only if the adapter can pin and prove immutability across beats; otherwise copy. Regardless, effects become visible at N+1.

Q: How do I debug foreign handles?
A: Provide a debug serializer in the adapter to produce a stable, human‑readable snapshot (names, sizes, versions) without exposing private fields.

Q: What if the library is not thread‑safe?
A: Serialize access inside the adapter and document it. CEP’s heartbeat scheduling helps isolate effect timing, but it does not fix underlying thread safety.
