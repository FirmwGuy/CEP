# L0 Design: Serialization and Replay

## Nontechnical Summary
Serialization is Layer 0’s shipping department. It turns a live tree into a stream of self-describing chunks so another process—or a later replay—can rebuild the exact same structure, payloads, and proxy states. The same machinery also ingests those chunks safely, staging them until every piece is present before touching the live tree. The goal: capture history faithfully, handle huge blobs without blocking, and keep proxies deterministic when they cross process boundaries.

## Decision Record
- Manifest + payload separation keeps structural metadata small and allows large data blobs to stream with configurable window sizes.
- Readers stage updates in veiled branches and commit only after control chunks confirm completeness, preventing partial application.
- Content hashes cover DT, size, and payload bytes; they are advisory for integrity but not used for encryption or auth.
- Proxy adapters snapshot/restore via library hooks so handles survive serialization without leaking process-local pointers.
- Transactions are beat-aware: serialized inputs re-enter the system through capture, preserving append-only semantics.

## Subsystem Map
- Code
  - `src/l0_kernel/cep_serialization.c`, `cep_serialization.h` — manifest writers, reader state machine, chunk orchestration.
  - `src/l0_kernel/stream/` (e.g., `cep_stream_stdio.c`, `cep_stream_zip.c`) — stream adapters participating in serialization.
  - `src/l0_kernel/cep_cell_stream.c` — proxy snapshot helpers used during serialize/restore.
- Tests
  - `src/test/l0_kernel/test_serialization.c`, `test_serialization_randomized.c` — writer/reader round-trips, edge cases, hash verification.
  - `src/test/l0_kernel/test_stream.c`, `test_streams_randomized.c`, `test_stream_zip.c` — adapter behaviour under serialization pressure.
  - `src/test/l0_kernel/test_cell_mutations.c` — ensures append-only histories remain correct after serialized replays.

## Operational Guidance
- Tune `blob_payload_bytes` to match transport capacity; defaults favour moderate buffers but high-throughput replication may need larger slices.
- Keep proxy adapters lightweight: snapshot methods should emit deterministic bytes and validate preconditions rigorously.
- Record manifest versions in monitoring dashboards; mismatches imply incompatible peers before failures escalate.
- Wrap ingestion in transactions when embedding into upper layers to guarantee the replay still honours beat boundaries.
- When enabling hashes for large blob streams, monitor CPU impact; consider supplemental checksums if external requirements demand cryptographic guarantees.

## Change Playbook
1. Revisit this design doc and `docs/L0_KERNEL/topics/SERIALIZATION-AND-STREAMS.md`.
2. Define new chunk types or manifest fields in `cep_serialization.h`, keeping backward compatibility in mind.
3. Extend unit tests (`test_serialization*.c`, stream tests) to exercise the new framing or adapter behaviour.
4. Update proxy adapters (`stream/` or `cep_cell_stream.c`) if payload semantics change.
5. Run `meson test -C build --suite serialization` followed by `python tools/check_docs_structure.py` and `meson compile -C build docs_html`.
6. Coordinate version negotiation with any upper-layer packs and document requirements in `docs/TOOLS.md` or integration guides.

## Global Q&A
- **How are partial streams handled?** Readers hold staged data veiled until a control chunk confirms completeness; unfinished transactions are discarded.
- **Can I skip hashes for performance?** Yes; hashes are advisory. Disable them when transport integrity is enforced elsewhere, but ensure monitoring still detects corruption.
- **How do proxy handles survive serialization?** Adapters emit deterministic snapshots (or references) and restore them through library APIs, leaving process-specific pointers behind.
- **What about schema evolution?** Use manifest versioning and route incompatible payloads through migration enzymes before committing them.
- **Can serialization span multiple beats?** Capture packages the state as of one beat. Long-running exports should snapshot at beat boundaries to preserve replay guarantees.
