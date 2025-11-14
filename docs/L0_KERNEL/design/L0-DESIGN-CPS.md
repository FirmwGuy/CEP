# L0 Design: CEP Persistent Storage (CPS)

## Introduction
CEP Persistent Storage (CPS) is the Layer 0 service that mirrors the in-memory tree to durable media without violating the heartbeat contract. CPS ingests the flat serializer’s beat-scoped frames, validates them, and appends the results to branch files so readers always observe complete beats at `N+1`. At a glance, CPS gives operators beat-atomic commits, CAS caching, observable maintenance verbs, and portable branch bundles that higher layers can ship or replay elsewhere.

## Decision Record

- **Beat-atomic persistence.** Every frame is ingested inside a transaction (`begin_beat` → `put_record` → `commit_beat`). CPS refuses to expose partial beats: commits publish only after Merkle verification, CRC32C checks, and fsync ordering succeed.
- **Flat serializer contract.** CPS is downstream of the flat serializer and therefore enforces the serializer’s capability bits (`payload_ref`, `frame_toc`, AEAD, deflate, etc.). Unsupported bits abort ingestion before any write touches disk.
- **KV abstraction.** CPS exposes a uniform KV interface (flatfile today, RocksDB/LMDB/object stores later). Each backend must implement the same vtable and advertise its capabilities so the runtime can negotiate features deterministically.
- **Runtime mirrors.** CPS mirrors `/data`, `/journal`, `/cas`, and `/rt/ops` into branch directories while respecting Layer 0’s boot/shutdown operations (`ist:store` readiness). Metrics and CEI topics keep operators informed without walking the filesystem.
- **CAS cache + runtime fallback.** Branches keep a hashed CAS cache plus `manifest.bin` for fast lookups. Misses fall back to the runtime `/cas` tree, republish metrics, and optionally persist the blob for future hits.
- **Deterministic fixtures.** Flat serializer fixtures (`fixtures/cps/{frames,cas}`) capture reference frames and blobs so CPS replay tests can assert CAS cache/runtime parity. Fixtures regenerate via `CEP_UPDATE_PAYLOAD_REF_FIXTURES=1`.

## Architecture Overview

### Stack Position

```
 Upper layers (L1–L4) ──────┐
                            │
                 L0 Kernel ─┴─ heartbeat, cells/stores, OPS, CEI
                            │ store service
                  CPS engine interface
                            │
                       CPS service ─── beat-atomic KV engine
                            │
                Pluggable KV engines (flatfile, RocksDB, LMDB, etc.)
```

- **Capture → Compute → Commit.** CPS aligns its transaction boundary with the heartbeat’s commit stage; ingestion happens after capture/compute finish so visibility still occurs at beat `N+1`.
- **Serializer ingestion.** Frames consist of `cell_desc`, `payload_chunk`, `manifest_delta_pg`, `order_delta_pg`, `namepool_delta`, and a trailer (capabilities, counts, CRC32C, Merkle root). CPS replays those records into the engine after verifying every checksum.
- **Branch layout.** Each branch stores `branch.idx` (structural timeline), `branch.dat` (payload bodies), checkpoint snapshots, `branch/cas/manifest.bin` plus hashed blob directories, and maintenance metadata.

### Data Flow

```
1. L0 capture/compute emits beat-scoped frame via cep_flat_serializer.
2. CPS receive_frame() validates CRC/Merkle and writes stage files.
3. commit_beat() appends idx/dat segments, fsyncs in order, and swaps head pointers.
4. Metrics publish under /data/persist/<branch>, CEI records success/failure.
```

## Storage Model & CAS

- **KV API.** `cps_engine` exposes `begin_beat`, `put_record`, `commit_beat`, `abort_beat`, `get_record`, `scan_prefix`, `checkpoint`, `compact`, and `stats`. Capabilities advertise AEAD, deflate, Merkle, namepool map, CAS dedup, etc.
- **File formats.** The flatfile backend appends idx/dat segments per beat, annotates them with frame IDs and Merkle hashes, and maintains sparse checkpoint snapshots so crash recovery can truncate torn writes deterministically.
- **CAS cache.** Every CAS payload gets a hashed directory entry plus a `manifest.bin`. `cps_flatfile_fetch_cas_blob_bytes` first consults the cache; if the blob is missing, `cps_flatfile_fetch_cas_blob_runtime` scans `/cas` for the BLAKE3 hash recorded inside `cell_desc.payload_ref`. Metrics (`cas_hits`, `cas_miss`, `cas_lat_ns`) update after every lookup via `cps_flatfile_publish_metrics`.
- **Runtime fallback hygiene.** CAS cache misses emit `persist.recover` CEI warnings if neither cache nor runtime hold the blob, keeping operators informed about incomplete branches.

## Operations & Observability

- **Metrics.** `/data/persist/<branch>` exposes `kv_eng`, `metrics/{frames,beats,bytes_idx,bytes_dat,cas_hits,cas_miss,cas_lat_ns}`. CPS publishes immediately during commits and CAS lookups so dashboards always see fresh counters.
- **OPS verbs.** `op/checkpt`, `op/compact`, and `op/sync` entries under `/rt/ops/*` let operators trigger checkpoints, log compaction, or export/import bundles. CEI topics (`persist.commit`, `persist.frame.io`, `persist.checkpoint`, `persist.recover`, `persist.bootstrap`) capture severity-tagged evidence.
- **CEI integration.** CPS emits diagnostic notes for frame verification failures, fsync errors, checkpoint rollbacks, import/export verification mismatches, and CAS runtime failures, tying each fact to the branch path.
- **Boot readiness.** Once CPS publishes metrics and marks `ist:store`, Layer 0’s boot operation (`op/boot`) can advance, ensuring storage readiness stays part of the deterministic startup timeline.

## Fixture & Replay Workflow

- **Fixtures.** `src/test/l0_kernel/test_flat_serializer_fixtures.c` generates deterministic inline and CAS frames plus blobs under `fixtures/cps/{frames,cas}`. The test fails fast if fixtures drift and logs “set `CEP_UPDATE_PAYLOAD_REF_FIXTURES=1`” instructions.
- **Replay harness.** `/CEP/cps/replay/inline`, `/CEP/cps/replay/cas_cache`, and `/CEP/cps/replay/cas_runtime` install fixtures into temporary branches and scoped runtimes, then assert CAS metrics and payload parity. Scoped runtimes guarantee `/data/persist` and `/cas` roots exist and serializer env vars never leak between suites.
- **Regeneration.** Run `CEP_UPDATE_PAYLOAD_REF_FIXTURES=1 build/cep_tests --no-fork --single /CEP/serialization/flat_payload_ref_fixtures`, commit the updated fixtures, then rerun `meson test -C build cep_unit_tests` to validate CPS replay with the new serializer output.

## Subsystem Map

| Area | Key files |
| --- | --- |
| Engine interface & vtable | `src/cps/cps_engine.h`, `src/cps/cps_flatfile.{h,c}` |
| Storage service & ops verbs | `src/cps/cps_storage_service.c` |
| Runtime wiring | `src/l0_kernel/cep_heartbeat.c` (storage hooks), `src/l0_kernel/cep_ops.c` |
| Tests & fixtures | `src/test/cps/test_cps_replay.c`, `src/test/l0_kernel/test_flat_serializer_fixtures.c`, `fixtures/cps/*` |
| Docs | Overview / Integration / Algorithms references plus this design doc |

## Operational Guidance

- **Environment switches.**
  - `CEP_SERIALIZATION_FLAT_AEAD_MODE`, `CEP_SERIALIZATION_FLAT_AEAD_KEY`, `CEP_SERIALIZATION_FLAT_COMPRESSION` control serializer policies; clean them up after tests.
  - `CEP_UPDATE_PAYLOAD_REF_FIXTURES=1` regenerates fixtures; keep it unset in CI.
- **Metrics consumption.** Dashboards should watch `/data/persist/<branch>/metrics/{frames,beats,bytes_*}` for branch health and `cas_*` for cache effectiveness. Latency is average nanoseconds per lookup (`cas_lat_ns`).
- **Import/export.** `op/sync` packages idx/dat/checkpoints + CAS blobs, signs them with a Merkle manifest, and stages bundles for import. Import verifies the bundle, merges CAS, swaps head files, and emits CEI evidence.
- **Recovery.** After crashes CPS scans trailing idx/dat segments, validates Merkle trailers, truncates torn beats, and replays the last good frame directory. Branches remain beat-consistent even after abrupt exits.

## Change Playbook

1. **Touching serializer compatibility.** Update `src/cps/cps_flatfile.c` capability checks, extend fixtures, rerun `/CEP/serialization/flat_payload_ref_fixtures` + `/CEP/cps/replay/*`, update docs (Integration + Algorithms).
2. **Adding engine backends.** Implement the `cps_engine` vtable, advertise capabilities, add Meson wiring, and extend `/data/persist/<branch>` to surface the engine name. Tests must cover `begin_beat` semantics and crash recovery.
3. **Tweaking CAS policy.** Keep manifest format backward compatible or add a version bump. Re-run the CAS replay harness and confirm metrics publish after lookups.
4. **Modifying ops verbs.** Document new CEI topics, add integration tests under `src/test/cps` or `src/test/poc`, and ensure `/rt/ops` state transitions still obey capture → compute → commit.
5. **Fixture updates.** Regenerate fixtures, commit artifacts, rerun serializer + CPS suites, and mention the fixtures in release notes if they change external tooling expectations.

## Global Q&A

- **Why a KV abstraction instead of direct file I/O?** To keep CPS pluggable: the flatfile backend proves determinism today, but RocksDB/LMDB/object-store engines can implement the same API for different deployments without rewriting Layer 0.
- **How does CPS avoid partial visibility?** Beats write to staging files, fsync parts in order, then atomically advance head pointers and metrics. Readers rely on `branch.meta` to locate the last sealed frame.
- **What happens if CAS is missing locally?** Metrics record a miss, CPS emits a `persist.recover` CEI warning, and the caller gets a deterministic error. Importing a bundle with CAS manifests is the recommended fix.
- **Do tests need a dedicated data root?** Yes. Scoped runtimes configure temporary directories so CPS can publish `/data/persist`, `/cas`, and `/tmp` without colliding with other suites.
- **How do I extend CPS docs?** Update this design doc plus the Overview/Integration references. Keep fixtures and replay instructions nearby so future contributors can replicate the workflow without hunting external files.
