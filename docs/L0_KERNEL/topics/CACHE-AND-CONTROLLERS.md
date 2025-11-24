# L0 Topic: Cache and Branch Controllers

CEP’s cache story lives in the branch controllers (often dubbed “CPCL” for Cache/Persistence Controller Layer) and the CPS persistence layer. This note gives a single, readable place to understand how branch policies, in-RAM cache windows, and flushes fit together so you don’t have to hunt across design docs.

## What the cache does
- Tracks dirty cells/stores per branch and decides when to flush them to CPS (durable, scheduled, on-demand, volatile).
- Maintains in-RAM history windows (`history_ram_beats` / `history_ram_versions`) and optional RAM quota to keep hot data available.
- Applies policy knobs like `allow_volatile_reads`, `snapshot_ro`, and `flush_on_shutdown`.
- Emits telemetry under `/data/persist/<branch>/` and CEI topics when policy is exercised (`persist.flush.*`, `persist.defer`, `persist.snapshot`, `persist.evict`).

## Branch policies (quick map)
- **Modes:** `durable`, `scheduled_save`, `on_demand`, `volatile`, `ro_snapshot`.
- **Flush triggers:** `flush_every_beats`, explicit `op/br_flush`, scheduled beat via `op/br_sched`, defer via `op/br_defer`.
- **Reads:** `allow_volatile_reads` controls whether durable/scheduled consumers may read dirty/volatile branches; if allowed, Decision Cells and `cell.cross_read` CEI facts are recorded.
- **Shutdown:** `flush_on_shutdown` requests a flush when shutdown reaches `ist:flush`.
- **History windows:** `history_ram_beats`, `history_ram_versions`, optional `ram_quota_bytes` bound in-RAM history/cache.
- **Snapshot:** `op/br_snapshot` seals a branch read-only (`snapshot_ro=1`), emits `persist.snapshot`, and rejects mutations.

## Telemetry and evidence
- **Metrics:** `/data/persist/<branch>/metrics` publishes `frames`, `beats`, `dirty_bytes`, `pin_count`, `cas_hits/miss/lat_ns`, last flush bytes/pins.
- **Status:** `/data/persist/<branch>/branch_stat` shows `last_bt`, `frame_last`, `dirty_ents`, `dirty_bytes`, `pend_mut`, `cause_last`.
- **Config:** `/data/persist/<branch>/config` reflects active policy (`policy_mode`, `flush_every`, `flush_shdn`, `allow_vol`, `snapshot_ro`, `schedule_bt`).
- **CEI:** `persist.flush.begin/done/fail`, `persist.defer`, `persist.snapshot`, `persist.evict`, `persist.async`, `persist.async.tmo`, `persist.recover`.

## Flush and async flow (at a glance)
1. Controllers mark dirty entries during Compute.
2. Commit calls `cps_storage_commit_current_beat()`; controllers hand dirty roots to `cep_flat_stream_emit_branch_async()`.
3. Async serializer registers OPS `begin/write/finish` requests; CPS waits for completions (`op/io` dossiers) before advancing `ist:store`.
4. On success, metrics/config update; on failure/timeouts, CEI emits and the beat aborts.

## Cross-branch reads and determinism
- Before cloning/reading across branches, `cep_branch_policy_check_read()` enforces `allow_volatile_reads` and `snapshot_ro`.
- Risky cross-reads record Decision Cells (`cep_decision_cell_record_cross_branch`) and emit `cell.cross_read` CEI so replay consumes the same ledger. L1 enzymes should call `cep_l1_coh_hydrate_safe()` so cross-branch reads stay default-deny, log `coh.hydrate.fail` on policy errors, and carry pipeline metadata into CEI when present.

## Configuration examples
Here is a minimal mapping you can mirror in tests or staging to see CPCL and CPS working together.

- **Durable application branch:** `/data/persist/app/config/` sets `policy_mode="scheduled_save"`, `flush_every=8`, `flush_shdn=true`, `history_ram_beats=6`, `history_ram_versions=2`, and `ram_quota_bytes=134217728`. This keeps two versions and six beats warm within 128 MiB, flushes every eight beats and on shutdown, and rejects volatile reads by default.
- **Read-mostly catalog:** `/data/persist/catalog/config/` uses `policy_mode="durable"`, `history_ram_beats=2`, `ram_quota_bytes=67108864`, `allow_vol=false`, `snapshot_ro=0`. You can switch it to `ro_snapshot` with `op/br_snapshot { branch=catalog }` once imports finish.
- **Scratch/volatile branch:** `/data/persist/tmp/config/` uses `policy_mode="volatile"`, `allow_vol=true`, `ram_quota_bytes=33554432`. No flushes occur; consumers must opt into `allow_volatile_reads`, and any cross-branch read is logged with `cell.cross_read` CEI.
- **Ops examples:** `op/br_flush { branch=app }` forces an immediate flush; `op/br_sched { branch=app, beat=1234 }` schedules the next flush; `op/br_defer { branch=app }` defers until manually re-enabled; `op/compact { branch=app }` triggers backend compaction and CEI `persist.checkpoint`/`persist.flush.*` entries.

## Where to dive deeper
- Persistence design: `docs/L0_KERNEL/design/L0-DESIGN-CPS.md`
- Implementation digest: `docs/CEP-Implementation-Reference.md` (CPS, branch controllers, async flush)
- Tag catalog: `docs/CEP-TAG-LEXICON.md` (persist.* topics/fields)

## Q&A
- **How do I pick between `durable` and `scheduled_save`?** Use `scheduled_save` when you want predictable flush intervals; use `durable` when every dirty beat should flush unless deferred. Both modes keep history windows and telemetry identical.
- **How do I verify a branch is actually flushing?** Watch `/data/persist/<branch>/metrics/{flush_bytes,frames,beats}` and CEI `persist.flush.*`; a flat line on `frames` plus rising `dirty_bytes` means you likely deferred flushes or set `flush_every=0`.
- **When is `allow_volatile_reads` safe to enable?** Enable only for cache-style consumers that can tolerate replayed stale data; expect `cell.cross_read` CEI and Decision Cells to appear so replays remember that risk.***
