# L0 Design: Content Persistence Service (CPS)

## Introduction
CPS (Content Persistence Service) is the Layer 0 service that mirrors the in-memory tree to durable media without violating the heartbeat contract. CPS ingests the flat serializer’s beat-scoped frames, validates them, and appends the results to branch files so readers always observe complete beats at `N+1`. At a glance, CPS gives operators beat-atomic commits, CAS caching, observable maintenance verbs, and portable branch bundles that higher layers can ship or replay elsewhere.

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

## Configuration examples
A concrete wiring helps spot whether CPS and the branch controller (CPCL) are configured as intended.

- **Durable branch with periodic flush:** `/data/persist/app/config/` holds `policy_mode="scheduled_save"`, `flush_every=10`, `flush_shdn=true`, `history_ram_beats=8`, `history_ram_versions=2`, `allow_vol=false`, and `ram_quota_bytes=134217728`. The controller flushes every 10 beats and on shutdown while keeping two versions and eight beats of history warm within a 128 MiB cap.
- **Volatile scratch branch:** `/data/persist/scratch/config/` uses `policy_mode="volatile"`, `allow_vol=true`, `flush_every=0`, `ram_quota_bytes=33554432`. Nothing hits disk; cross-branch reads require consumers to set `allow_volatile_reads` and will emit `cell.cross_read` decisions.
- **Engine selection:** `/data/persist/<branch>/kv_eng="flatfile"` reflects the active engine. Switching engines (e.g., to RocksDB) happens at bootstrap/meson configuration; metrics and CEI stay in the same schema for dashboards.
- **Ops triggers in practice:** `op/br_flush { branch=app }` forces an immediate flush; `op/checkpt { branch=app }` checkpoints; `op/sync { branch=app, dest=/tmp/app_export }` exports a bundle with CEI (`persist.checkpoint`/`persist.bootstrap`) capturing success/failure.

## Secured Payload Integration

### Introduction
Secured payloads let CEP keep VALUE/DATA bytes encrypted or compressed while they live in RAM. The serializer emits those ciphertext/deflated buffers as-is, so CPS simply persists what secdata sealed—there is no re-encoding step during commit.

### Technical Details
- **Secmeta snapshots.** Every cepData revision carries secmeta (fingerprint, raw/encrypted lengths, codec, AEAD mode, key identifier, nonce, and AAD hash). CPS does not interpret the struct; the serializer writes it alongside each cell_desc so replay tooling understands how to rehydrate the bytes.
- **Zero-transform handoff.** When cep_data_set_enc/cdef/cenc commit a payload, the stored buffer already matches the serializer’s payload_chunk body. CPS therefore ingests the same ciphertext/compressed data without decrypting or deflating it.
- **Plaintext hygiene.** cep_data_unveil_ro allocates a temporary plaintext view, marks sec_view_active, and cep_data_unveil_done zeros/frees it. CPS never needs to call unveil; persistence, serializer, and federation all stream the authoritative encrypted payload.
- **Runtime helpers.** Rekey/recompress calls (cep_data_rekey, cep_data_recompress) build a fresh secmeta snapshot and flip mode flags. CPS just persists the new ciphertext once the beat commits.
- **Failure isolation.** If secdata cannot decrypt/compress/encode, the caller emits CEI (enc_fail, codec_mis, rekey_fail) and CPS receives no frame for that beat, keeping the beat-atomic rollback semantics intact.

### Q&A
- **Where do policies see security metadata?** Call cep_data_secmeta during capture/compute. CPS already carries the metadata in the frame; no storage hook is needed.
- **Does CPS need new serializer bits?** No. The existing payload_ref/AED/codec capabilities already describe the chunk.
- **How are plaintext views protected?** Only the secdata unveil path touches plaintext, and the scratch buffer is zeroized immediately. CPS and the serializer never see unsealed payloads.
- **How do I keep a scheduled branch from starving durable data?** Cap its RAM window (`ram_quota_bytes`) and `flush_every` so the controller emits flushes regularly; if RAM pressure rises anyway, CEI `persist.evict` and CPS metrics (`dirty_bytes`, `pin_count`, `flush_bytes`) show whether the branch is overrunning its budget.***
