# L0 Design: Serialization and Replay

## Nontechnical Summary
Serialization is Layer 0’s shipping department. It turns a live tree into a stream of self-describing **flat records** so another process—or a later replay—can rebuild the exact same structure, payloads, and proxy states. The same machinery also ingests those records safely, staging them until every piece is present before touching the live tree. The goal: capture history faithfully, handle huge blobs without blocking, and keep proxies deterministic when they cross process boundaries. Federation now consumes these flat frames end-to-end; the transport manager wraps every emit in `cep_fed_transport_manager_send_cell()` so link/mirror/invoke all run through the same serializer.

## Decision Record
- Manifest + payload separation keeps structural metadata small and allows large data blobs to stream with configurable window sizes.
- Manifest deltas (record type `0x03`) track child additions, deletions, and veil toggles per beat so replayed layouts recover historical state deterministically.
- Child descriptors record stable insertion positions and a 64-bit payload fingerprint so ingestion can prove the child’s lineage before applying structural or data changes.
- Capability negotiation is enforced: flat frames must advertise `CEP_FLAT_CAP_*` bits for every optional feature; readers reject mismatched headers before replay diverges.
- Readers stage updates in veiled branches and commit only after the frame trailer confirms completeness, preventing partial application.
- Content hashes cover DT, size, and payload bytes; they are advisory for integrity but not used for encryption or auth.
- Proxy adapters snapshot/restore via library hooks so handles survive serialization without leaking process-local pointers.
- Transactions are beat-aware: serialized inputs re-enter the system through capture, preserving append-only semantics.

## Subsystem Map
- Code
- `src/l0_kernel/cep_flat_stream.c`, `cep_flat_stream.h` — manifest writers, reader state machine, flat record orchestration.
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
- Surface fingerprint/capability faults as deployment blockers—those errors mean the stream was tampered with or produced by an incompatible peer.
- Wrap ingestion in transactions when embedding into upper layers to guarantee the replay still honours beat boundaries.
- When enabling hashes for large blob streams, monitor CPU impact; consider supplemental checksums if external requirements demand cryptographic guarantees. `CEP_CRC32C_MODE=castagnoli` opts the writer into hardware CRC32C (Castagnoli) when SSE4.2/ARM CRC32 instructions exist; emitters automatically fall back to IEEE CRC32 otherwise so the receiver never sees mixed algorithms without negotiation.

## Change Playbook
1. Revisit this design doc and `docs/L0_KERNEL/topics/SERIALIZATION-AND-STREAMS.md`.
2. Define new flat record fields in `cep_flat_stream.h`, keeping capability negotiation in mind.
3. Extend unit tests (`test_serialization*.c`, stream tests) to exercise the new framing or adapter behaviour.
4. Update proxy adapters (`stream/` or `cep_cell_stream.c`) if payload semantics change.
5. Run `meson test -C build --suite serialization` followed by `python tools/check_docs_structure.py` and `meson compile -C build docs_html`.
6. Coordinate version negotiation with any upper-layer packs and document requirements in `docs/TOOLS.md` or integration guides.

## S2 Upgrade Field Notes
### Nontechnical summary
S2 hardens serialization so manifests carry their own history, readers reject malformed ordering immediately, and leak hunting stays reproducible. Federation adoption is complete: every mount emits/ingests flat frames. Think of this section as the field guide: it lists the hot code paths, the gaps we still need to close, and the guardrails that keep replay deterministic.

### Technical details
- **Entry points worth bookmarking.**
  - Emit surface: `cep_flat_stream_header_write` (control chunk prep) and `cep_flat_stream_emit_cell` (graph traversal + sink writes).
  - Reader lifecycle: `cep_flat_stream_reader_create/destroy/reset`, `cep_flat_stream_reader_ingest`, `cep_flat_stream_reader_commit`, and `cep_flat_stream_reader_pending`.
  - Internal emit helpers: `cep_serialization_emit_manifest`, `cep_serialization_emit_data`, `cep_serialization_emit_library_proxy`.
  - Internal ingest helpers: `cep_serialization_stage_manifest`, `cep_serialization_stage_payload`, `cep_serialization_stage_commit`.
- **Gap snapshot (2025-11-03).**
  - Base manifests only record the active branch; we still need historical siblings/store layouts captured per beat.
  - Data emission streams the current payload without journal-beat lineage, so deterministic rewinds remain impossible.
  - Reader staging lacks hooks for reconstructing prior revisions or validating beat continuity.
- **Upgrade requirements.**
- Extend frame trailers with capability bits for history manifests, manifest deltas, payload fingerprints, proxy envelopes, digest trailers, split descriptors, and the namepool translation.
- Sequence historical payload segments (veiled siblings, tombstones) so replays can recover older revisions deterministically.
  - Stage history archives reader-side so shadow branches can be grafted before commit.
  - Reserve manifest bytes for organiser/storage hints (insertion-order, name, hash, spatial, function) and enforce them when rehydrating stores.
  - Pair payloads with journal-beat fingerprints so paged stores prove lineage before admitting bytes.
  - Wrap proxy snapshots in deterministic envelopes (version byte, inline/ticket flags, metadata TLVs) so adapters evolve without breaking compatibility.
- **Replay guardrails.**
- CEI triggers: descriptor record before metadata → `descriptor_without_metadata`; duplicate `(domain,tag,position)` within one parent → `duplicate_descriptor`; duplicate metadata record per parent → `metadata_duplicate`; exceeding advertised `child_count` → `parent_already_populated`. Drop staged descriptors/metadata for the affected parent whenever one of these fires.
- Placeholder policy: only materialize placeholders inside `cep_serialization_reader_materialize_child_additions` after metadata ingests; the organiser position comes from the descriptor table, and we fail fast if the parent already has children.
- **Instrumentation + regression hooks.**
- `/CEP/integration_poc/l0/integration_serialization_focus` and the full integration suite log manifest record orderings and `/data/poc/space` manifests via `integration_log_space_manifest_records`.
  - `CEP_SERIALIZATION_DEBUG` / `CEP_POC_SERIALIZATION_DEBUG` gate noisy tracing; `CEP_SERIALIZATION_TRACE_DIR` captures parity corpora for emit vs. replay diffs.
- **Sanitizer + Valgrind workflow.**
  - Maintain separate builds: run ASAN suites from `build-asan`, then run the same suites from a clean non-ASAN build under Valgrind (`build-valgrind`). Never layer Valgrind on top of ASAN; memcmp hooks differ and leak the allocator. Archive logs under `tmp/asan/` and `tmp/valgrind/`, and rerun integration harnesses both with and without `MALLOC_PERTURB_`.

### Q&A
- **Why repeat the entry points that already live in headers?**  
  **A:** This quick list eliminates spelunking when you return to the subsystem; you can jump straight to the helper that needs attention.
- **How strict are the guardrails?**  
  **A:** Treat them as fatal. Once staging sees out-of-order chunks or duplicate descriptors, raise CEI and dump the transaction rather than risk a half-applied manifest.
- **Do we really need two sanitizer builds?**  
  **A:** Yes. ASAN catches fast leaks, Valgrind catches allocator misuse, and keeping the builds separate avoids the missing memcmp hooks that tripped older runs.

## Global Q&A
- **How are partial streams handled?** Readers hold staged data veiled until a control chunk confirms completeness; unfinished transactions are discarded.
- **Can I skip hashes for performance?** Yes; hashes are advisory. Disable them when transport integrity is enforced elsewhere, but ensure monitoring still detects corruption.
- **How do proxy handles survive serialization?** Adapters emit deterministic snapshots (or references) and restore them through library APIs, leaving process-specific pointers behind.
- **What about schema evolution?** Use manifest versioning and route incompatible payloads through migration enzymes before committing them.
- **Can serialization span multiple beats?** Capture packages the state as of one beat. Long-running exports should snapshot at beat boundaries to preserve replay guarantees.
