/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef RATWORLD_H
#define RATWORLD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  RATWORLD_STATUS_OK = 0,
  RATWORLD_STATUS_INVALID_ARGUMENT,
  RATWORLD_STATUS_NOT_READY,
  RATWORLD_STATUS_NOT_FOUND,
  RATWORLD_STATUS_NO_MEMORY,
  RATWORLD_STATUS_NOT_IMPLEMENTED,
  RATWORLD_STATUS_FAILED,
} ratworldStatus;

const char *ratworld_status_string(ratworldStatus status);

typedef enum {
  RATWORLD_TILE_FLOOR = 0,
  RATWORLD_TILE_WALL,
  RATWORLD_TILE_STAIR_UP,
  RATWORLD_TILE_STAIR_DOWN,
  RATWORLD_TILE_FOOD,
  RATWORLD_TILE_TRAP,
  RATWORLD_TILE_HOME,
  RATWORLD_TILE_EXIT,
} ratworldTileType;

typedef enum {
  RATWORLD_TILE_TAG_NONE = 0,
  RATWORLD_TILE_TAG_DARK = 1u << 0,
  RATWORLD_TILE_TAG_SMELL_MARK = 1u << 1,
} ratworldTileTag;

typedef struct {
  ratworldTileType type;
  uint32_t tags;
} ratworldTile;

typedef struct {
  uint32_t width;
  uint32_t height;
  uint32_t max_food_tiles;
  uint32_t max_trap_tiles;
  uint32_t max_exit_tiles;
  bool allow_cycles;
} ratworldFloorSpec;

typedef struct {
  double hunger_base_inc;
  double hunger_move_inc;
  double hunger_food_boost;
  double stamina_move_cost;
  double stamina_wait_recover;
  double stamina_home_recover;
  double hunger_home_recover;
  double trap_damage;
  double hunger_health_cost;
} ratworldActionEconomy;

typedef struct {
  uint32_t home_x;
  uint32_t home_y;
  uint32_t exit_x;
  uint32_t exit_y;
  uint32_t exit_floor;
  uint32_t stair_pairs;
} ratworldChallengeManifest;

typedef struct {
  const char *run_id;
  uint64_t seed;
  const ratworldFloorSpec *floors;
  size_t floor_count;
  size_t max_rats;
  const ratworldActionEconomy *economy;
} ratworldRunConfig;

typedef struct {
  const char *rat_id;
  uint32_t floor_z;
  int32_t x;
  int32_t y;
  bool alive;
  double health;
  double stamina;
  double hunger;
} ratworldRatState;

typedef struct {
  uint64_t tick;
  size_t alive_rats;
  size_t dead_rats;
  size_t exits_reached;
} ratworldRunState;

typedef enum {
  RATWORLD_ACTION_MOVE_N = 0,
  RATWORLD_ACTION_MOVE_S,
  RATWORLD_ACTION_MOVE_E,
  RATWORLD_ACTION_MOVE_W,
  RATWORLD_ACTION_MOVE_UP,
  RATWORLD_ACTION_MOVE_DOWN,
  RATWORLD_ACTION_WAIT,
} ratworldActionKind;

typedef struct {
  const char *rat_id;
  ratworldActionKind kind;
} ratworldAction;

typedef enum {
  RATWORLD_EVENT_MOVED = 0,
  RATWORLD_EVENT_BUMPED,
  RATWORLD_EVENT_ATE_FOOD,
  RATWORLD_EVENT_TRIGGERED_TRAP,
  RATWORLD_EVENT_REACHED_EXIT,
  RATWORLD_EVENT_DIED,
} ratworldEventKind;

typedef struct {
  ratworldEventKind kind;
  const char *rat_id;
  uint32_t floor_z;
  int32_t x;
  int32_t y;
} ratworldEvent;

typedef struct {
  int32_t dx;
  int32_t dy;
  ratworldTileType type;
  uint32_t tags;
} ratworldTileSample;

typedef struct {
  ratworldEvent *events;
  size_t event_count;
  size_t event_capacity;
} ratworldEventBuffer;

typedef struct {
  ratworldTileSample *tiles;
  size_t tile_count;
  size_t tile_capacity;
} ratworldTileSampleBuffer;

typedef struct {
  const char *rat_id;
  uint32_t floor_z;
  int32_t x;
  int32_t y;
  double health;
  double stamina;
  double hunger;
  bool on_food;
  bool on_trap;
  bool on_stair_up;
  bool on_stair_down;
  ratworldTileSample neighborhood[9];
  size_t neighborhood_count;
} ratworldObservation;

typedef struct {
  ratworldObservation *items;
  size_t observation_count;
  size_t observation_capacity;
} ratworldObservationBuffer;

typedef enum {
  RATWORLD_CONTROL_RUN = 0,
  RATWORLD_CONTROL_PAUSED,
  RATWORLD_CONTROL_STEP,
  RATWORLD_CONTROL_REPLAY,
} ratworldControlMode;

typedef struct {
  ratworldControlMode mode;
  uint64_t step_ticks;
  const char *replay_run_id;
  uint64_t replay_tick;
} ratworldControl;

typedef struct {
  uint64_t seed;
  uint64_t tick;
  const void *opaque_state;
  size_t opaque_state_len;
} ratworldSnapshot;

#define RATWORLD_SNAPSHOT_VERSION 1u

typedef struct ratworldService ratworldService;
typedef struct ratworldRun ratworldRun;

typedef struct {
  size_t max_runs;
  size_t max_rats_per_run;
  size_t max_floors;
} ratworldServiceConfig;

ratworldStatus ratworld_service_create(const ratworldServiceConfig *cfg, ratworldService **out_service);
void ratworld_service_destroy(ratworldService *service);

ratworldStatus ratworld_run_create(ratworldService *service,
                                   const ratworldRunConfig *config,
                                   ratworldRun **out_run);
void ratworld_run_destroy(ratworldRun *run);

ratworldStatus ratworld_run_set_control(ratworldRun *run, const ratworldControl *control);
ratworldStatus ratworld_run_stage_actions(ratworldRun *run,
                                          const ratworldAction *actions,
                                          size_t action_count);
ratworldStatus ratworld_run_tick(ratworldRun *run,
                                 ratworldEventBuffer *events_out,
                                 ratworldObservationBuffer *observations_out,
                                 ratworldRunState *state_out);

ratworldStatus ratworld_run_get_floor(const ratworldRun *run,
                                      uint32_t floor_z,
                                      const ratworldTile **tiles_out,
                                      uint32_t *width_out,
                                      uint32_t *height_out);
ratworldStatus ratworld_run_get_manifest(const ratworldRun *run, ratworldChallengeManifest *manifest_out);

ratworldStatus ratworld_run_snapshot(const ratworldRun *run, ratworldSnapshot *snapshot_out);
ratworldStatus ratworld_run_branch(ratworldService *service,
                                   const ratworldSnapshot *snapshot,
                                   const ratworldRunConfig *config,
                                   ratworldRun **out_run);
ratworldStatus ratworld_snapshot_release(ratworldSnapshot *snapshot);

#endif /* RATWORLD_H */
