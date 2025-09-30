# L0 Topic: I/O Streams and Foreign Resources

This note explains why CEP handles external I/O the way it does, and how we plan to implement it in Layer 0 (Kernel) so that systems remain deterministic, explainable, and replayable. The first part is language‑agnostic; the second part outlines the technical shape for implementors. See also: `EXTERNAL-LIBRARIES-INTERFACE.md` for handling foreign structures and opaque handles.

## Why This Matters (Rationale)

CEP aims to be both trustworthy (you can replay exactly what happened) and adaptive. External I/O – files, databases, network APIs – can easily break determinism: the world changes, data is huge, and endpoints aren’t always idempotent.

To keep replayability, CEP treats external I/O as explicit, auditable effects:

- Record first, then act: before touching the outside world, CEP records the intent (what we plan to do, with which inputs and preconditions). After acting, it records the outcome (what actually happened). This is like keeping both the recipe and the receipt.
- Heartbeat discipline: effects are staged during one step and applied at a commit boundary (the next heartbeat). This keeps the timeline clean: outputs from step N appear at step N+1.
- Content‑addressing for inputs: rather than depending on “whatever the resource is now,” CEP ties decisions to exact bytes (or their cryptographic hashes). This ensures you can reproduce decisions, even if the world has moved on.
- Preconditions instead of merges: when changing external resources, CEP checks the expected version (hash, ETag, row version). If it doesn’t match, CEP records a divergence. We don’t “auto‑merge” the outside world.
- Scales to large data: for big files/streams, CEP records windowed reads/writes (offset, length, hash) and optional checkpoints (full file hash or Merkle root). You don’t need to snapshot everything to be replayable.

What you get: exact replays (simulate without touching the world), safe re‑apply (touch the world only if preconditions still hold), and clear provenance (who/what/why for every byte that mattered).

## Model Overview

- Effect log: An append‑only record of intents and outcomes for external I/O. Reads are recorded too, not just writes.
- Preconditions: Expected version of a resource (e.g., hash, ETag, row count/version). If they don’t match during commit, the effect is not applied and a divergence is recorded.
- Idempotency key: A stable identifier attached to an effect so retries and replays do not duplicate the operation.
- Content‑addressed store (CAS): A place to keep large payloads by hash. The log can refer to bytes without duplicating them everywhere.
- Windowed I/O: Read/write by explicit offset and size. This makes operations deterministic and chunkable.
- Checkpoints: Optional periodic snapshots (full hash or Merkle root) to speed verification for very large data.

## Handling Different External Targets

- Files: Stage updates with preconditions (expected hash). Apply atomically (write temp + rename). Record final hash in the outcome. For large files, use windowed writes and periodic checkpoints.
- Databases: Record parameterized statements with preconditions (expected row counts or versions). Apply in a transaction. Record results (affected rows, returned rows or hashes). No “diffing” of DB files.
- Network APIs: Route calls through an auditable gateway/sidecar that logs method, URL, headers, body hash, and full response (status, headers, body hash). Use idempotency keys and If‑Match / ETag preconditions when possible.
- Unbounded streams: Treat as an ordered sequence of segments (offset, length, hash). Record both write intents and acks. Maintain a rolling hash or Merkle frontier so prefixes can be verified later.

## Replay Modes

- Simulate: Do not touch the world. Serve reads and provide outcomes from the effect log/CAS. Verify hashes.
- Re‑apply: Touch the world again using the same intents. Proceed only if preconditions match; record any divergence as a first‑class fact.

## Failure Handling

Every failure is recorded (code, message, partial counts). Replays reproduce the failure (simulate) or short‑circuit with the recorded outcome.

## Security and Privacy

Logs store references + hashes. Large or sensitive payloads live in the CAS with encryption‑at‑rest. Redaction policies can remove sensitive bodies while preserving replayability through hashes.

---

## Technical Design (Layer 0: Kernel)

Layer 0 already defines `cepData` with four representations:

- VALUE: small inline bytes.
- DATA: heap‑backed bytes (owned or view with a no‑op destructor).
- HANDLE: opaque reference to an external resource managed by a library cell.
- STREAM: a byte window onto a larger external stream managed by a library cell; payloads are opaque bytes tagged by cepDT.

Current code supports VALUE/DATA fully. HANDLE/STREAM are scaffolded and intentionally not exposed via `cep_cell_data()` yet (reads/updates are marked TODO). The design below completes HANDLE/STREAM without breaking determinism.

### Stream Abstraction

We treat streams as explicit, offset‑addressed operations. At L0, a “library” cell provides a vtable for HANDLE/STREAM operations; `cepData` points to that library via `data->library` and to the handle/stream via `data->handle` or `data->stream`.

Required operations (conceptual):

- read_at(off, buf, n) → bytes_read
- write_at(off, buf, n) → bytes_written
- map_at(off, n, mode) → ptr/token, unmap(token, commit)
- size() (optional), but callers should prefer explicit offsets to avoid hidden state

The L0 public API should expose helpers that route calls through the vtable:

- Read: `cep_cell_stream_read(cell, off, dst, n, out_read)`
- Write: `cep_cell_stream_write(cell, off, src, n, out_written)`
- Map/Unmap: `cep_cell_stream_map/unmap(...)` for zero‑copy where supported

For VALUE/DATA cells, these calls operate on the in‑memory buffer (bounds‑checked). For HANDLE/STREAM, they delegate to the library.

### Staging, Commit, and Journaling

- Staging: During heartbeat N, reads/writes are staged. Writes to HANDLE/STREAM are not visible immediately; VALUE/DATA mutations respect the same visibility rule.
- Commit: During the N→N+1 boundary, staged writes are applied in a deterministic order. Effects record preconditions (e.g., expected version/hash) and outcomes (bytes written, final hash).
- Journal facts: Each HANDLE/STREAM cell maintains child entries that log I/O:
  - `read`: {offset, requested, actual, hash}
  - `write`: {offset, length, hash, committed}
  - Optional payloads are stored in CAS and referenced by hash.

### Preconditions and Idempotency

- Each write includes an expected version (hash/ETag/row version) to avoid blind updates.
- Each effect carries an idempotency key to deduplicate retries and make replays safe.

### Large Data and Streams

- Windowed I/O: All operations specify offset + length; large data is chunked.
- Checkpoints: Periodically record a full resource hash or Merkle root so verification is fast without re‑reading everything.
- Memory streams: straightforward, fully deterministic (used in tests and examples).
- File streams: apply atomically (temp write + rename), record final hash in outcome; map for zero‑copy when available.

### Errors and Divergence

- Short reads/writes and errors are recorded, not hidden. Divergence occurs when preconditions fail at commit; CEP records it and does not auto‑merge.

## Developer Notes (Shape in Code)

This section sketches how the above maps onto existing headers without binding to a specific C style in the public narrative.

- `cep_cell_data(const cepCell*)`
  - VALUE/DATA: return byte pointer as today.
  - HANDLE/STREAM: return NULL. Callers must use the stream helpers.

- `cep_library_initialize(cepCell *library, cepDT *name, const cepLibraryOps *ops, void *ctx)`
  - Wrap a library cell with the adapter vtable and opaque context so HANDLE/STREAM payloads can delegate back into the integration.
  - `cep_library_binding/cep_library_context/cep_library_set_context` expose or update the binding without letting callers poke into internals.

- `cep_cell_update(...)`
  - VALUE/DATA only. For HANDLE/STREAM, return NULL or assert in debug; updates go through stream write APIs.

- Stream helpers (implemented):
  - `cep_cell_stream_read(cell, off, dst, n, out_read)` handles VALUE/DATA copies directly and calls the library adapter for HANDLE/STREAM resources. Every call appends a `CEP/stream-log` entry under `CEP/journal` recording requested/actual byte counts and an FNV-1a hash of the bytes read.
  - `cep_cell_stream_write(cell, off, src, n, out_written)` mirrors the read flow, updating VALUE/DATA hashes and timestamps while delegating to adapters for external resources. Successful commits journal a matching entry; failed writes log an error event without modifying state.
  - `cep_cell_stream_map(cell, off, n, access, view)` exposes an optional zero-copy window. VALUE/DATA mappings keep a copy-on-write snapshot so `cep_cell_stream_unmap(..., commit=false)` restores the original bytes. Committed writes refresh hashes, timestamps, and journal entries; adapters supply their own map/unmap handling for HANDLE/STREAM cells.

- Library vtable
  - The library cell referenced by `data->library` exports function pointers for HANDLE/STREAM ops. L0 routes calls to it.
  - Provide built-in adapters:
    - memory (for tests/examples)
    - file (POSIX/Win abstractions)
    - optional cas (read‑only, content‑addressed)

- Heartbeat integration
  - Stage write intents per stream with preconditions and idempotency key.
  - Apply in N→N+1; publish outcomes and journal entries at N+1.

- Hashing and CAS
  - Maintain `data->hash` for VALUE/DATA.
  - HANDLE/STREAM journal entries record hashes of the staged buffers (read/write). Adapters remain responsible for recording checkpoint hashes when windows are only partially committed.
  - Store large payloads in CAS and reference by hash in journals.

## Testing Strategy

- Memory stream: read/write/commit, verify journal, simulate replay.
- File stream: temp + rename atomicity, final hash check, windowed writes.
- Negative tests: precondition mismatch → divergence; short reads/writes recorded.
- Replay modes: simulate without touching FS; re‑apply with preconditions enforced.

## Migration Path (Current → Planned)

1) Keep VALUE/DATA behavior unchanged; ensure `cep_cell_data()` and `cep_cell_update()` are strict for HANDLE/STREAM.
2) Add stream helpers and minimal memory/file adapters.
3) Add journaling children for read/write events and wire them to the helpers.
4) Gate external effects on heartbeat commit and enforce preconditions.
5) Add tests as documentation of semantics.

This approach preserves CEP’s determinism and replay guarantees, while making external I/O practical for both tiny and massive resources.

## Q&A

- *Is this just a version control system for the outside world?*
  Not exactly. CEP uses an append‑only effect log with preconditions and content‑addressed inputs. You can add snapshots/checkpoints, but the source of truth is ordered intents and outcomes, not merged diffs.

- *Why not always store full copies of files or database dumps?*
  Cost and practicality. CEP records windowed I/O (offset/length/hash) and optional checkpoints (full hash or Merkle root). You can replay precisely without retaining every historical byte.

- *What happens if the external resource changed before we commit?*
  Preconditions fail (hash/ETag/version mismatch). CEP records a divergence outcome and does not auto‑merge. A separate policy can decide how to respond (retry, reform, or human review).

- *How are live network updates handled if we need to act immediately?*
  Effects are staged during the heartbeat and applied at the commit edge. Use idempotency keys and conditional requests (If‑Match/ETag). A gateway/sidecar logs request/response metadata and body hashes so replays are exact without requiring the remote system to cooperate.

- *Do I have to store payload bytes forever?*
  No. Keep payloads in a CAS with retention policies. Long‑term you can retain only hashes and metadata. Replay in “simulate” mode uses the recorded responses; “re‑apply” requires that preconditions still match.

- *Can I read without recording reads?*
  Avoid it. Unrecorded reads break determinism because later runs won’t know which bytes influenced decisions. CEP treats reads as first‑class facts with ranges and hashes.

- *Won’t staging and committing slow down I/O?*
  The boundary is about visibility and ordering, not necessarily latency. You can stage and send within the same beat if budgets allow; results become visible at N+1. For streams, CEP advances a committed frontier each beat.

- *How do we handle massive files efficiently?*
  Chunked windows, zero‑copy mapping where available, and periodic checkpoints. CEP never requires full materialization unless policy demands it.

- *Do I need a CAS to start?*
  It helps for large payloads, but you can begin by recording hashes and minimal payloads (e.g., memory streams for tests). Add a CAS when you need durable, deduplicated storage of big chunks.

- *What if an endpoint is non‑idempotent?*
  Wrap it with your own idempotent broker (idempotency keys, single‑flight per resource), or prefer replay‑simulate mode for that integration. CEP records the first outcome and prevents duplicate application.
