# L0 Topic: Serialization and Streams

CEP serialization packages cell state into travel-friendly pieces so snapshots and replays can hop between machines without special tooling. Think of it as a mail service: every envelope carries enough guidance for the receiver to rebuild what mattered, whether that is a tiny value or a multi-gigabyte blob. Streams show up here because they are our conveyor belt--the same chunk vocabulary powers on-disk archives, replication, and long-haul transfers.

This document explains the moving parts in plain language first, then dives into the binary framing, chunk taxonomy, and how stream adapters plug in. If you already know the stream APIs, treat this as the map that shows how their reads and writes become serialized artifacts (and vice versa).

## Technical Details
Here is the nuts-and-bolts view of how chunks are framed, identified, and replayed, plus the way stream adapters plug into the pipeline.
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
- **Cell manifest (`class 0x0001`)**: payload carries the canonical cell path, type flags, and a child table that captures the live layout. Every child descriptor records the child domain/tag/glob, a flag byte (tombstone = `0x01`, veiled = `0x02`, payload fingerprint = `0x04`), the stable insertion position (for insertion-ordered stores), and—when the child owns deterministic bytes—a 64-bit payload fingerprint (hash of the child’s data domain/tag/size/payload tuple).
- **Manifest delta (`class 0x0001`, record type `0x02`)**: records a single structural change (add/delete/veil/unveil) for one child alongside the journal beat that produced it. The delta reuses the same child descriptor layout, propagates the child flag bits, and carries the optional payload fingerprint so the reader can verify lineage before applying the change. Deltas follow the base manifest and are gated by the `CAP_MANIFEST_DELTAS` capability bit so readers know to expect them.
- **Key/value (`class 0x0001`)**: payload encodes a tag ID, key bytes, and value bytes. Use this for scalar `cepData` values and metadata.
- **Binary segment (`class 0x0002`)**: payload contains an offset and byte slice. Combine multiple segments (same transaction ID) to rebuild large buffers; inline descriptors also carry the data type hash/ID so the reconstructed `cepData` regains its original domain/tag.
- **Child list pointer (`class 0x0001`)**: describes nested stores so receivers can push/pop traversal state.
- **Library capsule (`class 0x0003`)**: wraps the result of invoking a library-specific serializer (see next section). If the library reports no payload, the chunk is still emitted to mark the dependency.
- Additional classes may be added; maintain forward compatibility by ignoring unknown classes after reading their payload bytes.

### Split manifest chunks (metadata then descriptors)

**Plain-language intro.**  
Manifests now travel in two steps—first the store metadata, then the child descriptors—so the reader never has to guess how many children a parent expects. Think of it as sending the floor plan before the moving truck shows up; once the parent accepts the plan it can safely receive each child in order.

**Technical details.**
- The existing manifest chunk continues to announce organiser/storage hints, policy knobs, `child_count`, and other TLVs. When the payload stops before the child table it sets the new flag `CEP_SERIALIZATION_MANIFEST_FLAG_SPLIT_CHILDREN`, signalling that descriptors will follow in their own chunk.  
- When `child_count == 0`, the manifest base omits the split flag and no descriptor chunk is emitted. That keeps zero-child nodes wire-compatible with legacy readers while the staged stores still see the new organiser metadata first.  
- Descriptor chunks reuse `CEP_CHUNK_CLASS_STRUCTURE` with record type `CEP_MANIFEST_RECORD_CHILDREN`. The chunk header quotes the parent path reference plus `(descriptor_offset, descriptor_count)` so huge manifests can stream descriptors over multiple chunks. Each descriptor records `(domain, tag, cell_type, organiser_position, flags, fingerprint_hash, journal_beat, payload_size_hint)` exactly as before—only the location differs.  
    - Streams always advertise capability bit `CEP_SERIALIZATION_CAP_SPLIT_DESCRIPTORS (0x0040)` in the control header. Readers treat the bit as mandatory—if it is missing, the stream is rejected immediately because the single-chunk legacy format no longer exists.  
- Ingest order is strict: metadata must arrive before any descriptor chunk. Readers configure the parent store as soon as the metadata chunk lands, stash the expected descriptor range, then accept the descriptor chunk(s). Only after all descriptors are staged do they materialise placeholders or accept child manifests/data. Any chunk that references an unknown descriptor triggers a CEI fault.
- Tests enforce this contract: `test_serialization_manifest_history` inspects the header capability bit plus the manifest/descriptor sequence numbers, `test_serialization_manifest_split_child_capacity` emits/replays a manifest with six children to ensure the reader scales beyond legacy limits, and `/CEP/integration_poc/l0/integration_serialization_focus` replays the `/data/poc` tree while `integration_assert_manifest_chunk_order` records every metadata/descriptor pair it sees. Failures now point straight to the stage (`stage=emit`, `stage=replay`, or `stage=roundtrip`) instead of relying on indirect chunk-parity diffs.

**Q&A.**
- *Why bother splitting the chunk?* Because placeholder children created before store metadata arrives block the reader from reconfiguring `/space`-style stores. By splitting, we reconfigure the store first, then materialise children based on the authoritative descriptor list.  
- *What if a descriptor chunk never arrives?* The reader leaves the parent untouched and raises `descriptor_without_metadata`, aborting the transaction. No partial children remain because staging never progressed past the metadata step.  
- *What if metadata repeats or descriptors overshoot the advertised count?* Any duplicate metadata record triggers `metadata_duplicate`; extra descriptors (or offsets that skip positions) raise `descriptor_out_of_range`. Both facts cancel the transaction before new children appear in the live tree.  
- *How do we prove emit/replay streams obey the contract?* Set `CEP_SERIALIZATION_TRACE_DIR=/path/to/tmp` before running `./build/cep_tests --no-fork --single /CEP/integration_poc/l0/integration_focus` (or the full `/integration_poc/l0/integration`). The harness writes `integration_{before_ingest,original,replay,replay_roundtrip}.bin` plus manifest logs into the trace directory so you can diff emit vs. replay byte-for-byte.

When the serialization header omits the capability bitmap, the reader falls back to the legacy manifest format. Streams that present v2 manifest/delta records without advertising `CAP_HISTORY_MANIFEST`, `CAP_MANIFEST_DELTAS`, and `CAP_SPLIT_DESCRIPTORS` raise a capability fault immediately, preventing mixed-version replays from drifting silently.

### Worked example

Consider serializing a root cell with two children:

- `settings`, a normal cell that stores the string `"ok"`.
- `blob`, a stream cell that exposes 12 bytes of binary data.

In schema version 2 the base manifest carries the child descriptors directly; older traces may show separate child pointer chunks. The ordering below still illustrates how manifests, data, and control frames interleave even though the exact byte counts now differ.

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

## Global Q&A

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

## Namepool Translation Capability
### Nontechnical intro
Some deployments cannot assume every peer already interned the same set of domains/tags. The namepool translation capability gives us a small translator’s dictionary at the front of the stream so the receiver can hydrate any missing symbols before manifests reference them.

### Technical details
- Capability bit: `CEP_SERIALIZATION_CAP_NAMEPOOL_MAP`. When set, emitters may prepend one or more control chunks (`CEP_CHUNK_CLASS_CONTROL`, record `SERIAL_RECORD_NAMEPOOL_MAP` = `0x05`) after the header and before any manifest/data chunks.
- Payload layout (big-endian):
  - `u8 record` (`0x05`).
  - `u8 flags` where bit0 = `SERIAL_NAMEPOOL_FLAG_MORE` to signal continuation.
  - `u16 entry_count`.
  - Repeated entries: `u64 id`, `u16 text_len`, `u8 entry_flags` (bit0 mirrors `cep_namepool_reference_is_glob`), followed by `text_len` bytes of UTF-8.
- Emitters collect every `cepID` encountered during traversal that requires remote interning (domains, tags, glob references) and pack entries until the payload reaches `CEP_SERIALIZATION_NAMEPOOL_MAX_PAYLOAD` (4 KiB). Continue emitting chunks while toggling the continuation bit until the last entry.
- Readers that see the capability bit must consume the translation chunks immediately after the header, intern each entry (`cep_namepool_intern_*`), and only then proceed to manifest/data ingestion. Duplicate entries are cheap to skip; missing translation entries fall back to the existing `/sys/namepool/*` capture path and log a warning.
- Legacy peers that ignore the capability still replay successfully because `/sys/namepool` cells get captured during bootstrap. The capability simply shortens that warm-up for peers that opt in.

### Q&A
- **Q: What if a stream sets the capability but does not emit translation chunks?**  
  **A:** That is legal. The bit merely grants permission to emit translation chunks; readers should tolerate empty dictionaries and proceed with replay.
- **Q: Do numeric IDs need to be listed?**  
  **A:** No. If a symbol is globally stable and already reserved in the runtime, omit it to save payload space.
- **Q: How do we keep translation chunks from drifting away from the header?**  
  **A:** The reader expects them immediately after the control header, so emitters must serialize them before any manifest or data chunk. Use integration tests to enforce the ordering.

## Control Header and Chunk Schema v2
### Nontechnical intro
Schema version `0x0002` formalises the capability fields, manifest splits, proxy envelopes, and digest trailer so every bundle advertises its expectations up front. Treat it as the manifest that describes every other manifest.

### Technical details
- **Control header (`version 0x0002`).**
  - Fields: `u64 magic (0x4345503000000000)`, `u16 version`, `u8 byte_order`, `u8 flags` (bit0 = “has capabilities”), `u32 metadata_length + metadata`, `u64 journal_beat`, the existing journal flags, then (when bit0 is set) a `u16 capabilities` bitmap.
  - Capability bits: `0x0001` history manifests present, `0x0002` manifest deltas, `0x0004` payload fingerprints, `0x0008` proxy envelopes, `0x0010` digest trailer, `0x0020` split descriptors, `0x0040` namepool translation (`CEP_SERIALIZATION_CAP_NAMEPOOL_MAP`); remaining bits reserved and must raise CEI when unknown.
- **Chunk classes.**
  - Control (`0x0000`): header at `sequence==0`, optional digest trailer at `sequence==1` with `{u16 algo,u16 flags,u64 journal_beat,u64 checksum}` plus optional payload.
  - Structure (`0x0001`): transaction `0` carries base manifests (`record_type 0x01`) and deltas (`0x02`); other transaction IDs are reserved for multi-phase manifests.
  - Blob (`0x0002`) keeps the existing data-slice semantics.
  - Library (`0x0003`) hosts proxy envelopes (`version=1`, `kind`: handle/stream/adapter, flag bits for inline payloads and tickets).
- **Manifest payload layouts.**
  - Base manifest: record type `0x01`, organiser/storage hint bytes, `flags` (bit0 children, bit1 payload, bit2 veiled), `u8 cell_type`, `u16 path_length`, `u16 child_count`, path segments (`domain/tag/glob`), then `child_count` descriptors.
  - Descriptor fields: `u64 domain`, `u64 tag`, `u8 glob`, `u8 child_flags` (bit0 tombstone, bit1 veiled, bit2 fingerprint), `u16 position`, `u32 reserved`, optional fingerprint when flagged.
  - Delta manifest: record `0x02`, delta flags (add/delete/veil/unveil/update_order), organiser/storage hint, `u16 path_length`, `u8 cell_type`, `u64 journal_beat`, `u64 lineage_parent`, parent path segments, and a single `ChildDescriptor`.
- **Data chunk payload.**
  - Header: `u8 version`, `u8 kind` (`0=value`, `1=data`, `2=proxy-inline`), `u16 flags` (bit0 chunked, bit1 has hash, bit2 lineage), `u64 journal_beat`, optional `u64 payload_hash` (when flag set), `u16 datatype`, `u16 legacy_flags`, `u32 inline_size`, `u64 total_size`, DT identifiers (`domain/tag/glob` plus padding), followed by inline bytes when not chunked.
- **Proxy snapshot envelope.**
  - `{u8 version,u8 kind,u8 flags,u8 reserved,u32 ticket_len,u64 payload_len,...}` with optional ticket/payload bytes and metadata map; negotiated via capability `0x0008`.
- **Digest trailer.**
  - Optional control chunk at `sequence==1` when capability `0x0010` is set. The checksum covers every chunk after the header; readers should compare `journal_beat` and algorithm fields before trusting it.
- **Reader/writer guidance.**
  - Writers must set capability bits that match the features they emit and fall back to legacy framing when targeting peers that advertise older versions.
  - Readers reject bundles whose version exceeds their support level or whose capability bits they cannot honour, logging CEI `serialization.capability.missing`.

### Q&A
- **Q: Why bump the version if some peers still speak v1?**  
  **A:** Versioning protects mismatched peers from replaying partial histories. v1 readers continue to request v1 bundles; v2 bundles fail fast when the negotiation does not overlap.
- **Q: Can I emit split descriptors without the capability bit?**  
  **A:** No. The bit tells the reader to expect metadata + descriptor chunks. Without it, legacy readers would misinterpret the extra chunk and corrupt their store.
- **Q: Do digest trailers replace transport-level checksums?**  
  **A:** No. The trailer is an application-level checksum so operators can validate archives at rest. Still keep TLS, checksummed transports, or storage-level integrity in place.
