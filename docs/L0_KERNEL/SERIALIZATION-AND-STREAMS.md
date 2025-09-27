# CEP Serialization and Streams

CEP serialization packages cell state into travel-friendly pieces so snapshots and replays can hop between machines without special tooling. Think of it as a mail service: every envelope carries enough guidance for the receiver to rebuild what mattered, whether that is a tiny value or a multi-gigabyte blob. Streams show up here because they are our conveyor belt--the same chunk vocabulary powers on-disk archives, replication, and long-haul transfers.

This document explains the moving parts in plain language first, then dives into the binary framing, chunk taxonomy, and how stream adapters plug in. If you already know the stream APIs, treat this as the map that shows how their reads and writes become serialized artifacts (and vice versa).

## Technical Details

### Chunk framing

- Start each serialization stream with a dedicated header chunk (see `Serialization header`). It announces the magic number, format revision, and negotiated options so readers can refuse incompatible payloads or recover after corruption.
- Every subsequent chunk starts with a 64-bit size prefix (number of bytes that follow), then a 64-bit chunk ID, and finally the payload bytes. Sizes are expressed in the serialized byte order (big-endian by default); the payload may be zero length.
- Payloads remain opaque unless the chunk ID signals how to decode them. This mirrors `cepData`: the serializer does not reinterpret binary blobs, it records provenance around them.
- Large payloads are split into multiple chunks. Each part keeps the same semantic ID but carries ordering metadata (see "Chunk identity and ordering") so receivers can stitch the byte stream together.

### Chunk identity and ordering

- Chunk IDs are `uint64_t`. We reserve the top 16 bits for a **chunk class** (e.g., `0x0001` for structural metadata, `0x0002` for byte ranges, `0x0003` for library capsules). The next 32 bits hold a **transaction ID**, unique per serialization transaction so split payloads can be merged. The lowest 16 bits are a **sequence counter**, incremented per chunk within that transaction.
- When a payload spans multiple chunks, the sender emits them with monotonically increasing sequence counters. Receivers treat gaps as errors; duplicates trigger idempotent replays.
- Transactions reset when topology changes (e.g., moving from one cell subtree to another). Emit a zero-length "transaction delimiter" chunk (class `0x0000`) if you need an explicit barrier.

- Suggested chunk class names keep tooling aligned even before the values land in headers:

  - `CEP_CHUNK_CLASS_STRUCTURE` (0x0001) for manifests, keys, and child pointers.
  - `CEP_CHUNK_CLASS_BLOB` (0x0002) for binary segments.
  - `CEP_CHUNK_CLASS_LIBRARY` (0x0003) for library capsules and adapter-defined payloads.
  - `CEP_CHUNK_CLASS_CONTROL` (0x0000) reserved for the serialization header, delimiters, and future control frames.

### Chunk families

- **Serialization header (`class 0x0000`, sequence 0)**: the first chunk in every stream. Contains a fixed magic value, serialization version, byte order indicator, and optional TLV metadata (compression flags, feature bits). Recovery tools scan for this header to realign after a corruption event.
- **Cell manifest (`class 0x0001`)**: payload carries a serialized full cell path plus flags describing the cell type (normal, list head, library, etc.). When replayed, it creates or locates the target cell.
- **Key/value (`class 0x0001`)**: payload encodes a tag ID, key bytes, and value bytes. Use this for scalar `cepData` values and metadata.
- **Binary segment (`class 0x0002`)**: payload contains an offset and byte slice. Combine multiple segments (same transaction ID) to rebuild large buffers; inline descriptors also carry the data type hash/ID so the reconstructed `cepData` regains its original domain/tag.
- **Child list pointer (`class 0x0001`)**: describes nested stores so receivers can push/pop traversal state.
- **Library capsule (`class 0x0003`)**: wraps the result of invoking a library-specific serializer (see next section). If the library reports no payload, the chunk is still emitted to mark the dependency.
- Additional classes may be added; maintain forward compatibility by ignoring unknown classes after reading their payload bytes.

### Worked example

Consider serializing a root cell with two children:

- `settings`, a normal cell that stores the string `"ok"`.
- `blob`, a stream cell that exposes 12 bytes of binary data.

One valid emission order is:

1. `size=32 id=0x0000000000000000` (class 0x0000, sequence 0) -- serialization header with magic `CEP0`, format version `0x0001`, and `big-endian` flag.
2. `size=48 id=0x0001000000010001` (class 0x0001, transaction 0x00000001, sequence 0x0001) -- cell manifest for the root path.
3. `size=56 id=0x0001000000010002` -- child pointer describing `settings` and its metadata.
4. `size=40 id=0x0001000000010003` -- key/value chunk that carries the tag for `settings` plus the ASCII payload `"ok"`.
5. `size=56 id=0x0001000000020001` -- new transaction for `blob`; manifest spells out the stream cell path.
6. `size=64 id=0x0002000000020002` -- binary segment for offset 0..5 (first half of the stream) including the per-slice hash.
7. `size=64 id=0x0002000000020003` -- binary segment for offset 6..11 (second half).
8. `size=16 id=0x0000000000020004` -- control delimiter that marks the end of transaction 0x00000002.

Receivers rebuild the structure by applying the manifest and child pointer chunks as they arrive. They concatenate the binary segments that share the same transaction ID (`0x00000002`) and order them by the sequence counter (`0x0002`, `0x0003`). Missing sequence numbers or hashes that fail to match the journal trigger a serialization fault.

### Transaction boundaries and heartbeats

Each serialization pass piggybacks on the effect journal's heartbeat discipline. Emit a fresh transaction ID whenever you finish committing a heartbeat worth of writes (after `cep_stream_commit_pending` returns true) or when you switch to a new logical subtree. This mirrors replay semantics: replayers read chunks heartbeat by heartbeat, applying intents only when the preceding heartbeat has been fully acknowledged. Control chunks (class 0x0000) provide optional hard barriers if you need to pause between heartbeats or denote checkpoints; the reader waits for these markers before splicing staged cells back into the tree, so recovered state only appears on heartbeat boundaries.

### Streams and serialization

- Stream reads feed the serializer: `cep_cell_stream_read` yields deterministic byte windows whose hashes match what the effect journal recorded. Each window becomes one or more binary segment chunks.
- When deserializing, the stream adapter receives its chunks through `cep_stream_write` calls. The adapter reconstructs the pending write queue and applies `cep_stream_commit_pending` after all segments for a transaction arrive.
- Interleaving is expected. Emit structural chunks before the data chunks that rely on them (e.g., cell manifest before binary segments). Between multi-part payloads you may serialize additional cells, and receivers handle them by maintaining per-transaction buffers.

### Deserialization workflow

- Use `cep_serialization_reader_create`/`destroy` to manage a streaming reader bound to a root cell. The reader keeps transactions in a staging area until a control chunk (class `0x0000`) marks the end of a heartbeat.
- Feed each chunk to `cep_serialization_reader_ingest`. The reader verifies chunk IDs, enforces monotonically increasing sequences per transaction, and checks hashes on completed payloads.
- Nothing moves into the live tree until `cep_serialization_reader_commit` is invoked. Call it once per heartbeat; it materialises staged cells under the root while honouring manifest flags (hidden bits, data presence).
- `cep_serialization_reader_pending` reports whether a barrier was observed since the last commit, so ingest loops can avoid accidental double commits.

### Library participation

Adapters expose their serialization hooks through `cepLibraryOps` (see `src/l0_kernel/cep_cell.h`). The working proposal is to add optional callbacks such as `handle_serialize` and `handle_deserialize` alongside the existing stream vtable so adapters can pack their context before any dependent chunk is emitted. Until the API lands in headers, keep the names consistent with `EXTERNAL-LIBRARIES-INTERFACE.md` and document adapter expectations in the library capsule payload.

- Before serializing handles or streams backed by an external library, call the library's serializer hook (if registered). The hook returns its own chunk stream, which we wrap inside library capsule chunks.
- During deserialization, the library is asked to materialize its context before dependent chunks are replayed. If the library lacks a serializer, we fall back to recording an unresolved handle and mark the chunk as needing operator intervention.
- Library capsules follow the same transaction/sequencing rules. Their payload may contain further chunk lists defined by the adapter; those must remain self-contained so generic tooling can skip them when the adapter is absent.

### Suggested workflow

1. Traverse the cell tree depth-first, emitting a cell manifest chunk whenever you enter a node.
2. For each `cepData` payload, choose a key/value chunk (small data) or a series of binary segments (large data). Hash each slice to mirror the stream journal.
3. For child stores, emit child list pointer chunks before descending, and a delimiter chunk when unwinding the stack.
4. Any time a library-backed handle appears, delegate to the adapter serializer and wrap its output in library capsules with a fresh transaction ID.

### Error recovery

- Resynchronize by scanning for the serialization header's magic (`CEP0`) when a stream is damaged; resume parsing once the header and declared version match local expectations.
- Track the highest sequence counter observed per transaction ID. If the next chunk skips a number, keep the transaction open and request retransmission; do not apply partial state.
- Hash mismatches or short reads should raise a fatal error in the receiver and the exporter should consult the effect journal to determine which heartbeat introduced the divergence.
- Offline tooling that cannot request retransmission should log the gap, halt ingestion, and mark the archive as incomplete so operators can regenerate the missing heartbeat.
- Control chunks (class 0x0000) can carry retry hints or checkpoints; receivers may resume from the last confirmed control chunk after the gap is repaired.

## Q&A

- **Q: How do heartbeats relate to serialization transactions?**
  **A:** Emit a new transaction ID whenever you complete a heartbeat commit or switch to a new subtree. Replayers stay in lockstep by consuming all chunks with that ID before advancing the heartbeat, mirroring the order enforced by `cep_stream_commit_pending`.

- **Q: What should operators do after a broken transfer?**
  **A:** Stop ingesting at the gap, request the missing transaction from the producer (or regenerate the heartbeat from the effect journal), and resume from the last confirmed control chunk once hashes line up again.

- **Q: How strict is chunk ordering?**
  **A:** Structural chunks must appear before the data that depends on them, but different transactions may interleave freely. Receivers buffer by transaction ID and only finalize when all expected sequences arrive.

- **Q: What if a reader encounters an unknown chunk class?**
  **A:** Read and discard the payload bytes while logging a warning. Because chunk sizes are explicit, forward-compatible readers can skip data they do not understand without corrupting the stream.

- **Q: How do library serializers signal failure?**
  **A:** They return an error that we record as a zero-length library capsule chunk with an error flag in the payload header. Replay tools treat that as "library context missing" and ask operators to repair or resynchronize manually.

