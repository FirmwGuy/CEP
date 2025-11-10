# L0 Topic: Serialization and Streams

Flat serialization is Layer 0’s default wire format. Every beat produces a **frame**: an unordered set of self-describing **records** (cells, payload chunks, manifest deltas, etc.) plus a trailer that certifies integrity, capabilities, and beat metadata. Streams, replication, archives, and federation all speak the same language, so updating the serializer automatically lifts every transport.

This guide explains the record taxonomy, the env knobs that tune emission and ingestion, and how streams plug in. The hierarchical chunk serializer is gone—there is no fallback path in the docs or the runtime.

## Record Schema (overview)

Each record has a canonical key (`type || path_key || subkey`), a body, and an IEEE CRC32 computed over the header+body. Payloads, manifests, and history windows re-use the same building blocks so tooling can reason uniformly.

| Record type | Purpose | Key notes |
| --- | --- | --- |
| `cell_desc (0x01)` | Declares a cell’s metadata (name path, type, beats, payload fingerprint, inline payload ≤64 B). | `type || path_key`. |
| `payload_chunk (0x02)` | Streams segments of non-inline payloads. Supports optional AEAD with deterministic nonces keyed by the record key + payload fingerprint. | `type || path_key || chunk_ordinal(varint)`. |
| `manifest_delta_pg (0x03)` | Paged description of a parent’s child set at the current beat (range min/max, organiser hints, child descriptors). | `type || parent_path_key || page_id(varint)`. |
| `order_delta_pg (0x04)` | Paged ordering/projection hints (by insertion order, hash, or custom projections). | `type || parent_path_key || projection_kind || page_id`. |
| `namepool_delta (0x05)` | Announces namepool reference IDs so readers can resolve interned tags before applying manifests. | `type || ref_id`. |
| `payload_history (0x06)` | Historical payload chunks keyed by `{cell path, revision}` with beat and AEAD metadata. Controlled by `CEP_SERIALIZATION_FLAT_PAYLOAD_HISTORY_BEATS`. | `type || path_key || revision_id || chunk_ordinal`. |
| `manifest_history_pg (0x07)` | Historical manifest pages keyed by `{parent path, page_id, revision}`. Controlled by `CEP_SERIALIZATION_FLAT_MANIFEST_HISTORY_BEATS`. | `type || parent_path_key || page_id || revision_id`. |
| `frame_trailer (0xFF)` | Closure certificate: beat number, record count, apply mode, hash/checksum IDs, Merkle root, optional mini-TOC, history selectors, and capability bitmap. | `0xFF`. |

The canonical specification (fields, varints, AEAD layout) lives in `FLAT_SERIALIZER.md`. This topic explains how the pieces are used inside the runtime.

## Frame lifecycle and invariants

### Apply modes & capabilities
- `apply_mode` in the trailer tells the reader whether it must insert-only, overwrite existing state, or enforce CAS semantics. Every record in the frame is validated before the apply-set becomes visible.
- Capability flags advertise optional features: split manifests, order projections, payload fingerprints, frame compression, namepool deltas, payload history, manifest history, etc. Readers that do not understand a bit must reject the frame *before* touching any state.

### Chunk ordering
- `payload_chunk` records must appear with strictly increasing ordinals per cell, and each chunk’s `chunk_offset` must equal the sum of the previous chunk sizes. The reader enforces this with chunk trackers and fails the frame if a chunk is duplicated, skipped, or sealed early.
- The trailer verification step also ensures every tracked payload sealed (offset == total) before the frame becomes visible.

### History selectors
- Set `CEP_SERIALIZATION_FLAT_PAYLOAD_HISTORY_BEATS=<beats>` or `CEP_SERIALIZATION_FLAT_MANIFEST_HISTORY_BEATS=<beats>` to bundle historical payload bytes or manifest pages. The trailer records the selectors so readers know the window is partial, and the writer only asserts `CEP_FLAT_CAP_{PAYLOAD,MANIFEST}_HISTORY` when history records were emitted.

### AEAD & compression
- Optional AEAD is controlled via `CEP_SERIALIZATION_FLAT_AEAD_MODE` (`none`, `chacha20`, `xchacha20`) and `CEP_SERIALIZATION_FLAT_AEAD_KEY` (32-byte hex). Nonces are deterministic (keyed BLAKE3 over record key + chunk metadata) so replays remain byte-identical while maintaining uniqueness per payload revision.
- Frame compression is negotiated via `CEP_SERIALIZATION_FLAT_COMPRESSION` (`none` or `deflate`). When enabled, the serializer wraps the flat buffer in a `CFLT` container, records the uncompressed/compressed sizes, and raises `CEP_FLAT_CAP_FRAME_COMPRESSION`.

### Namepool & CAS
- Every record key is expressed in DT-segment form. If a path references a namepool entry the reader may not have, the writer emits `namepool_delta` records and sets `CEP_FLAT_CAP_NAMEPOOL_MAP`. Readers ingest those deltas first, ensuring the rest of the frame resolves cleanly.
- Payload fingerprints surface the CAS ID for non-inline payloads; historical payload records reuse the same fingerprint so CAS consumers can prune duplicates efficiently.

## Streams & adapters

- `cep_serialization_emit_cell` (and the federation emitters layered on top) always build a flat frame. Feature toggles now enable/disable optional records within that frame rather than swapping whole serializers.
- Streams, CAS adapters, and federation transports simply forward the frame bytes. Replay paths call `cep_flat_reader_feed`/`commit` to validate and iterate records.
- Test helpers such as `serialization_capture_sink` or `flat_assert_chunk_records` in `src/test/l0_kernel/test_serialization.c` show how to capture a frame and inspect specific record types.

## Testing cues

- `test_serialization_flat_multi_chunk` exercises AEAD/no-AEAD payloads across multiple chunks.
- `test_serialization_flat_chunk_offset_violation` and `test_serialization_flat_chunk_order_violation` mutate captured frames (recomputing per-record CRCs) and ensure the reader now rejects out-of-order or overlapping chunks.
- Historical coverage lives in `test_serialization_manifest_history` and the new flat history tests—keep these updated whenever the schema changes.

By default, every Layer 0 node emits flat frames. Federation, replication, archives, and debug tooling all expect this format, so when you update the serializer or add a record type, update the docs (`FLAT_SERIALIZER.md` plus this topic) and the test cases listed above. No legacy chunk stream remains in the codebase or the documentation.
