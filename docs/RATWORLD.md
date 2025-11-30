# Ratworld API

Ratworld is a deterministic, multi-floor roguelike environment meant for small learners. This document describes the standalone API surfaces (no CEP glue yet) that let callers configure worlds, drive ticks, and inspect observations/events for replayable rat runs.

## Technical Details

- **Service layout**
  - `ratworldService` owns capacity limits and creates per-run handles. `ratworldRun` is the runtime handle for a single seeded maze plus its rats and tick counter.
  - `ratworldServiceConfig` controls caps (runs, rats per run, max_floors default 10). `ratworldRunConfig` carries `run_id`, `seed`, floor specs, and a max-rat budget.
  - Action economy is configurable per run via an optional `ratworldActionEconomy` (hunger/stamina/trap constants); defaults match current roguelike-ish values if omitted.

- **World generation inputs**
  - Floors are defined by `ratworldFloorSpec` (`width`, `height`, food/trap/exit caps, cycle flag).
  - Tile base types: `FLOOR`, `WALL`, `STAIR_UP`, `STAIR_DOWN`, `FOOD`, `TRAP`, `HOME`, `EXIT`.
  - Tile tags (bitmask): `DARK`, `SMELL_MARK` plus `NONE` sentinel.
  - Runs remain reconstructible from `seed + floor specs`; callers own string/array lifetimes passed in configs.

- **Deterministic maze generation**
  - `ratworld_run_create` now allocates per-floor tile maps and carves mazes deterministically from the supplied `seed` using a SplitMix64 RNG.
  - Each floor is carved as walls with odd-coordinate corridors; cross-floor stair pairs are placed at shared walkable coordinates, with `STAIR_DOWN` on lower floors and matching `STAIR_UP` above.
  - `HOME` lands on floor `0`, `EXIT` on the last floor; per-floor food/trap caps are placed on walkable tiles without overwriting specials (stair/home/exit).
  - `ratworld_run_get_floor(run, z, &tiles, &w, &h)` provides read-only access to a floor’s tiles for renderers and UIs.
  - Floors default to classic terminal-friendly odd dimensions (79×23) when unspecified, keeping the visible maze within an 80×24 grid; a service-level `max_floors` cap defaults to 10 and rejects larger runs.
  - `ratworld_run_get_manifest` exposes `home`, `exit`, `exit_floor`, and `stair_pairs` metadata for challenge consumers.

- **Runtime data**
  - Actions: `ratworldActionKind` (`MOVE_*`, `MOVE_UP/DOWN`, `WAIT`) in `ratworldAction { rat_id, kind }`.
  - Events: `ratworldEventKind` (`MOVED`, `BUMPED`, `ATE_FOOD`, `TRIGGERED_TRAP`, `REACHED_EXIT`, `DIED`) packed into `ratworldEvent { rat_id, floor_z, x, y }`.
  - Observations: `ratworldObservation` bundles rat pose/state (`health`, `stamina`, `hunger`, presence flags) with a fixed 3×3 neighborhood (`neighborhood[9]` of `ratworldTileSample { dx, dy, type, tags }`).
  - Run state: `ratworldRunState { tick, alive_rats, dead_rats, exits_reached }` mirrors coarse status for UI/telemetry.
  - Control: `ratworldControl` toggles `mode` (`RUN`, `PAUSED`, `STEP`, `REPLAY`), optional `step_ticks`, and replay selectors (`replay_run_id`, `replay_tick`).

- **Snapshots and branching**
  - `ratworldSnapshot { seed, tick, opaque_state[*] }` includes a versioned header (`RATWORLD_SNAPSHOT_VERSION`) and checksum over the payload for validation.
  - `ratworld_run_snapshot` serializes RNG, tiles, rats, action economy, and manifest into an opaque blob; `ratworld_run_branch` rebuilds a run from that blob + matching config, restoring tiles/positions/health/economy/manifest.
  - `ratworld_snapshot_release` frees the allocated snapshot buffer when callers are done reading it.

- **API surface**
  - Creation/teardown: `ratworld_service_create/destroy`, `ratworld_run_create/destroy`.
  - World access: `ratworld_run_get_floor` exposes tiles and dimensions for a given floor index (pointer lifetime tied to run).
  - Challenge manifest: `ratworld_run_get_manifest` returns home/exit/stair metadata for the current layout.
  - Control paths: `ratworld_run_set_control`, `ratworld_run_stage_actions`, `ratworld_run_tick`.
  - Replay hooks: `ratworld_run_snapshot`, `ratworld_run_branch`.
  - Snapshot lifecycle: `ratworld_snapshot_release` frees snapshot buffers allocated by `ratworld_run_snapshot`.
  - Status helpers: `ratworld_status_string` covers `OK`, `INVALID_ARGUMENT`, `NOT_READY`, `NOT_FOUND`, `NO_MEMORY`, `NOT_IMPLEMENTED`, `FAILED`.
  - Tick loop processes staged actions for each rat, updates hunger/health/stamina, emits events, and fills observations; replay/branch are live for tiles/rats/RNG.

- **Textual interface for terminals**
  - `ratworldTextGlyphs` captures ASCII glyphs for tiles/tags/rats; `ratworld_text_default_glyphs` seeds classic roguelike glyphs `# . < > % ^ H >` plus `@/x` for alive/dead rats and fog (` `) and smell (`;`) markers.
  - `ratworldTextFloor { width, height, floor_z, tiles[] }` describes a renderable slice; callers overlay `ratworldRatState` entries for occupants.
  - `ratworld_text_render_floor(floor, glyphs, rats, rat_count, buffer, buffer_len)` writes a newline-terminated grid into a caller buffer; returns `INVALID_ARGUMENT` when inputs or buffer sizing are insufficient.
  - `ratworld_text_render_ui` adds a HUD line under the map: `Run:<id> Floor:<z> Tick:<n> Rat:<id> HP:<..> ST:<..> HG:<..> Exits:<count>`; callers pass `ratworldTextHud` with run/rat state.

## Q&A

**Q: Why expose run control before the tick loop exists?**  
To lock the ABI for pause/step/replay ahead of CEP glue; downstream UI or harness code can wire against the control shape while the tick driver is still under construction.

**Q: Who owns strings and floor arrays passed in configs?**  
Callers retain ownership. The current stub copies configs by value and borrows pointers; keep the provided strings/arrays alive for the run’s lifetime or extend the API later with owned copies.

**Q: How will replay/branching stay deterministic?**  
Seeds and tick counters sit in `ratworldSnapshot`, and the API keeps explicit action/event/observation types. Once state serialization lands, snapshots will include the opaque bytes so a new run can branch exactly from a prior tick.

**Q: How do I render a floor without CEP?**  
Fill a `ratworldTextFloor` with tile types/tags, pass any active `ratworldRatState` entries, and call `ratworld_text_render_floor` with either custom or default glyphs; the helper writes a single string (rows + newlines) suitable for terminal printing.

**Q: Can I inspect a generated maze without moving a rat?**  
Yes. After `ratworld_run_create`, call `ratworld_run_get_floor(run, z, &tiles, &w, &h)` and pipe that into `ratworld_text_render_floor` (with an empty rat list) to print the seeded maze; the same seed/config always regenerates the same layout.

**Q: What are the default spawn and tick rules?**  
`max_rats` controls how many rats spawn; each gets an id `rat<N>` and starts on floor 0 near `HOME` (or a random floor tile if `HOME` is absent). Each tick applies the staged action (default `WAIT`), bumps on walls/out-of-bounds, traverses stairs only from matching tiles, emits events, and updates `health/stamina/hunger` (traps hurt, food restores hunger and disappears, home restores a little stamina).

**Q: How do observations work without supplying buffers?**  
`ratworld_run_tick` fills a fixed 3×3 neighborhood inside each `ratworldObservation`; callers supply `ratworldObservationBuffer` with preallocated observation slots. If capacity is insufficient, the function returns `NOT_READY` while keeping run state deterministic.

**Q: Are mazes guaranteed solvable?**  
Yes. The generator retries with deterministic seeds until there is a path from `HOME` to `EXIT` across stairs (up to a fixed attempt cap); if it cannot find one, run creation fails.

**Q: What action economy and hunger/stamina rules are used?**  
Moves cost stamina and add hunger, wait recovers stamina, traps deal damage, hunger grows each tick and drains health when high, and home tiles restore a small amount of stamina and reduce hunger. The defaults live in `src/ratworld/ratworld.c` (`ratworld_default_economy`) and can be overridden per run via `ratworldRunConfig.economy`.

**Q: What buffers do I need to provide for ticks?**  
`ratworld_run_tick` requires observation capacity ≥ `rat_count` when an observation buffer is supplied and event capacity of at least `rat_count * 3` when an event buffer is supplied; otherwise it returns `NOT_READY` without advancing tick state.

**Q: How do I build or restore snapshots safely?**  
Snapshots carry a `RATWORLD_SNAPSHOT_VERSION` header and a checksum over the payload; `ratworld_run_branch` validates both before restoring. Future schema updates should bump the version and document compatibility.

**Q: How do I render a full roguelike frame (map + stats)?**  
Use `ratworld_text_render_ui` with a `ratworldTextHud` (run id, run state, rat state, floor) to emit the map followed by a HUD line containing tick, floor, rat id, HP/ST/HG, and exits reached.
