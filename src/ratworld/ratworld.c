/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ratworld.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint32_t x;
  uint32_t y;
} ratworldCell;

typedef struct {
  int dx;
  int dy;
} ratworldDir;

typedef struct {
  uint32_t width;
  uint32_t height;
  ratworldTile *tiles;
} ratworldFloor;

static size_t ratworld_floor_index(const ratworldFloor *floor, uint32_t x, uint32_t y);

struct ratworldService {
  ratworldServiceConfig cfg;
};

struct ratworldRun {
  ratworldRunConfig config;
  ratworldRunState state;
  ratworldControl control;
  ratworldFloor *floors;
  size_t rat_count;
  ratworldRatState *rats;
  ratworldActionKind *staged_actions;
  size_t floor_count;
  uint64_t rng_state;
  ratworldActionEconomy economy;
  ratworldChallengeManifest manifest;
};

static ratworldServiceConfig ratworld_default_service_config(void)
{
  ratworldServiceConfig cfg;

  cfg.max_runs = 4;
  cfg.max_rats_per_run = 4;
  cfg.max_floors = 10;
  return cfg;
}

static ratworldControl ratworld_default_control(void)
{
  ratworldControl ctl;

  ctl.mode = RATWORLD_CONTROL_RUN;
  ctl.step_ticks = 1;
  ctl.replay_run_id = NULL;
  ctl.replay_tick = 0;
  return ctl;
}

static ratworldActionEconomy ratworld_default_economy(void)
{
  ratworldActionEconomy econ;

  econ.hunger_base_inc = 0.01;
  econ.hunger_move_inc = 0.01;
  econ.hunger_food_boost = 0.5;
  econ.stamina_move_cost = 0.05;
  econ.stamina_wait_recover = 0.02;
  econ.stamina_home_recover = 0.1;
  econ.hunger_home_recover = 0.1;
  econ.trap_damage = 0.3;
  econ.hunger_health_cost = 0.05;
  return econ;
}

static uint64_t ratworld_rng_next(uint64_t *state)
{
  uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);

  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  z = z ^ (z >> 31);
  return z;
}

static uint32_t ratworld_rng_range(uint64_t *state, uint32_t max_value)
{
  return (uint32_t)(ratworld_rng_next(state) % max_value);
}

static double ratworld_clamp(double v, double lo, double hi)
{
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

static uint32_t ratworld_checksum32(const uint8_t *data, size_t len)
{
  uint32_t hash = 2166136261u;
  size_t i;

  for (i = 0; i < len; ++i) {
    hash ^= data[i];
    hash *= 16777619u;
  }
  return hash;
}

static ratworldStatus ratworld_event_emit(ratworldEventBuffer *buf,
                                          ratworldEventKind kind,
                                          const ratworldRatState *rat)
{
  if (buf == NULL) {
    return RATWORLD_STATUS_OK;
  }
  if (buf->events == NULL || buf->event_capacity == 0) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (buf->event_count >= buf->event_capacity) {
    return RATWORLD_STATUS_NOT_READY;
  }
  buf->events[buf->event_count].kind = kind;
  buf->events[buf->event_count].rat_id = rat->rat_id;
  buf->events[buf->event_count].floor_z = rat->floor_z;
  buf->events[buf->event_count].x = rat->x;
  buf->events[buf->event_count].y = rat->y;
  buf->event_count += 1;
  return RATWORLD_STATUS_OK;
}

static ratworldStatus ratworld_observation_emit(const ratworldRun *run,
                                                const ratworldRatState *rat,
                                                ratworldObservationBuffer *buf)
{
  int radius = 1;
  int dx, dy;

  if (buf == NULL) {
    return RATWORLD_STATUS_OK;
  }
  if (buf->items == NULL || buf->observation_capacity == 0) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (buf->observation_count >= buf->observation_capacity) {
    return RATWORLD_STATUS_NOT_READY;
  }
  ratworldObservation *obs = &buf->items[buf->observation_count];
  const ratworldFloor *floor = &run->floors[rat->floor_z];
  size_t sample_idx = 0;

  obs->rat_id = rat->rat_id;
  obs->floor_z = rat->floor_z;
  obs->x = rat->x;
  obs->y = rat->y;
  obs->health = rat->health;
  obs->stamina = rat->stamina;
  obs->hunger = rat->hunger;
  obs->on_food = false;
  obs->on_trap = false;
  obs->on_stair_up = false;
  obs->on_stair_down = false;
  for (dy = -radius; dy <= radius; ++dy) {
    for (dx = -radius; dx <= radius; ++dx) {
      int32_t sx = rat->x + dx;
      int32_t sy = rat->y + dy;
      ratworldTileSample *samp = &obs->neighborhood[sample_idx++];

      samp->dx = dx;
      samp->dy = dy;
      if (sx < 0 || sy < 0 || sx >= (int32_t)floor->width || sy >= (int32_t)floor->height) {
        samp->type = RATWORLD_TILE_WALL;
        samp->tags = RATWORLD_TILE_TAG_NONE;
      } else {
        const ratworldTile *tile = &floor->tiles[ratworld_floor_index(floor, (uint32_t)sx, (uint32_t)sy)];
        samp->type = tile->type;
        samp->tags = tile->tags;
        if (dx == 0 && dy == 0) {
          obs->on_food = tile->type == RATWORLD_TILE_FOOD;
          obs->on_trap = tile->type == RATWORLD_TILE_TRAP;
          obs->on_stair_up = tile->type == RATWORLD_TILE_STAIR_UP;
          obs->on_stair_down = tile->type == RATWORLD_TILE_STAIR_DOWN;
        }
      }
    }
  }
  obs->neighborhood_count = sample_idx;
  buf->observation_count += 1;
  return RATWORLD_STATUS_OK;
}
static size_t ratworld_floor_index(const ratworldFloor *floor, uint32_t x, uint32_t y)
{
  return (size_t)y * floor->width + x;
}

static void ratworld_floor_fill(ratworldFloor *floor, ratworldTileType type)
{
  size_t i;
  size_t total = (size_t)floor->width * floor->height;

  for (i = 0; i < total; ++i) {
    floor->tiles[i].type = type;
    floor->tiles[i].tags = RATWORLD_TILE_TAG_NONE;
  }
}

static void ratworld_shuffle_dirs(uint64_t *state, ratworldDir dirs[4])
{
  size_t i;
  for (i = 3; i > 0; --i) {
    size_t j = ratworld_rng_range(state, (uint32_t)(i + 1));
    ratworldDir tmp = dirs[i];
    dirs[i] = dirs[j];
    dirs[j] = tmp;
  }
}

static void ratworld_carve_maze(ratworldFloor *floor, uint64_t *rng_state)
{
  ratworldCell *stack;
  size_t stack_size = 0;
  size_t stack_cap = (size_t)floor->width * floor->height;
  uint32_t start_x;
  uint32_t start_y;

  stack = malloc(stack_cap * sizeof(*stack));
  if (stack == NULL) {
    return;
  }
  ratworld_floor_fill(floor, RATWORLD_TILE_WALL);

  start_x = (ratworld_rng_range(rng_state, floor->width / 2) * 2u) | 1u;
  start_y = (ratworld_rng_range(rng_state, floor->height / 2) * 2u) | 1u;

  floor->tiles[ratworld_floor_index(floor, start_x, start_y)].type = RATWORLD_TILE_FLOOR;
  stack[stack_size++] = (ratworldCell){ start_x, start_y };

  while (stack_size > 0) {
    ratworldCell current = stack[stack_size - 1];
    ratworldDir dirs[4] = {
      { 0, 1 }, { 0, -1 }, { 1, 0 }, { -1, 0 }
    };
    size_t d;
    int carved = 0;

    ratworld_shuffle_dirs(rng_state, dirs);
    for (d = 0; d < 4; ++d) {
      int32_t nx = (int32_t)current.x + dirs[d].dx * 2;
      int32_t ny = (int32_t)current.y + dirs[d].dy * 2;
      uint32_t mid_x;
      uint32_t mid_y;

      if (nx <= 0 || ny <= 0 || nx >= (int32_t)floor->width - 1 || ny >= (int32_t)floor->height - 1) {
        continue;
      }
      if (floor->tiles[ratworld_floor_index(floor, (uint32_t)nx, (uint32_t)ny)].type != RATWORLD_TILE_WALL) {
        continue;
      }
      mid_x = (uint32_t)((int32_t)current.x + dirs[d].dx);
      mid_y = (uint32_t)((int32_t)current.y + dirs[d].dy);
      floor->tiles[ratworld_floor_index(floor, mid_x, mid_y)].type = RATWORLD_TILE_FLOOR;
      floor->tiles[ratworld_floor_index(floor, (uint32_t)nx, (uint32_t)ny)].type = RATWORLD_TILE_FLOOR;
      stack[stack_size++] = (ratworldCell){ (uint32_t)nx, (uint32_t)ny };
      carved = 1;
      break;
    }
    if (!carved) {
      --stack_size;
    }
  }
  free(stack);
}

static int ratworld_pick_random_tile(const ratworldFloor *floor, uint64_t *rng_state, ratworldTileType type)
{
  size_t attempts = 0;
  size_t total = (size_t)floor->width * floor->height;

  while (attempts < total * 2) {
    size_t idx = ratworld_rng_range(rng_state, (uint32_t)total);
    if (floor->tiles[idx].type == type) {
      return (int)idx;
    }
    ++attempts;
  }
  return -1;
}

static void ratworld_place_feature(ratworldFloor *floor,
                                   uint64_t *rng_state,
                                   ratworldTileType target,
                                   unsigned limit)
{
  unsigned placed = 0;
  while (placed < limit) {
    int idx = ratworld_pick_random_tile(floor, rng_state, RATWORLD_TILE_FLOOR);
    if (idx < 0) {
      break;
    }
    floor->tiles[idx].type = target;
    ++placed;
  }
}

static void ratworld_place_vertical_links(ratworldFloor *low,
                                          ratworldFloor *high,
                                          uint64_t *rng_state)
{
  uint32_t max_w = low->width < high->width ? low->width : high->width;
  uint32_t max_h = low->height < high->height ? low->height : high->height;
  size_t attempts = 0;
  size_t total = (size_t)max_w * max_h;

  while (attempts < total * 2) {
    uint32_t x = ratworld_rng_range(rng_state, max_w);
    uint32_t y = ratworld_rng_range(rng_state, max_h);
    size_t low_idx = ratworld_floor_index(low, x, y);
    size_t high_idx = ratworld_floor_index(high, x, y);

    if (low->tiles[low_idx].type == RATWORLD_TILE_FLOOR &&
        high->tiles[high_idx].type == RATWORLD_TILE_FLOOR) {
      low->tiles[low_idx].type = RATWORLD_TILE_STAIR_DOWN;
      high->tiles[high_idx].type = RATWORLD_TILE_STAIR_UP;
      return;
    }
    ++attempts;
  }
}

static void ratworld_place_home_exit(ratworldFloor *first,
                                     ratworldFloor *last,
                                     uint64_t *rng_state)
{
  int home_idx = ratworld_pick_random_tile(first, rng_state, RATWORLD_TILE_FLOOR);
  int exit_idx = ratworld_pick_random_tile(last, rng_state, RATWORLD_TILE_FLOOR);

  if (home_idx >= 0) {
    first->tiles[home_idx].type = RATWORLD_TILE_HOME;
    (void)home_idx; /* manifest filled later */
  }
  if (exit_idx >= 0) {
    last->tiles[exit_idx].type = RATWORLD_TILE_EXIT;
  }
}

static int ratworld_find_home_index(const ratworldFloor *floor)
{
  size_t total = (size_t)floor->width * floor->height;
  size_t i;

  for (i = 0; i < total; ++i) {
    if (floor->tiles[i].type == RATWORLD_TILE_HOME) {
      return (int)i;
    }
  }
  return -1;
}

static int ratworld_pick_spawn(const ratworldRun *run, uint32_t *floor_z, uint32_t *x, uint32_t *y)
{
  int idx = ratworld_find_home_index(&run->floors[0]);

  if (idx < 0) {
    return -1;
  }
  *floor_z = 0;
  *x = (uint32_t)(idx % run->floors[0].width);
  *y = (uint32_t)(idx / run->floors[0].width);
  return 0;
}

static int ratworld_world_is_solvable(const ratworldRun *run)
{
  size_t total_tiles = 0;
  size_t i;
  int start_idx;
  uint32_t start_x = 0, start_y = 0;
  typedef struct {
    uint32_t f;
    uint32_t x;
    uint32_t y;
  } node;
  node *queue;
  size_t q_head = 0, q_tail = 0, q_cap;
  uint8_t *visited;

  for (i = 0; i < run->floor_count; ++i) {
    total_tiles += (size_t)run->floors[i].width * run->floors[i].height;
  }
  if (total_tiles == 0) {
    return 0;
  }
  start_idx = ratworld_find_home_index(&run->floors[0]);
  if (start_idx < 0) {
    return 0;
  }
  start_x = (uint32_t)(start_idx % run->floors[0].width);
  start_y = (uint32_t)(start_idx / run->floors[0].width);
  q_cap = total_tiles;
  queue = malloc(q_cap * sizeof(*queue));
  visited = calloc(total_tiles, 1);
  if (queue == NULL || visited == NULL) {
    free(queue);
    free(visited);
    return 0;
  }
  queue[q_tail++] = (node){ 0, start_x, start_y };
  while (q_head < q_tail) {
    node cur = queue[q_head++];
    const ratworldFloor *floor = &run->floors[cur.f];
    size_t idx = ratworld_floor_index(floor, cur.x, cur.y);
    size_t global_idx = idx;
    for (i = 0; i < cur.f; ++i) {
      global_idx += (size_t)run->floors[i].width * run->floors[i].height;
    }
    if (visited[global_idx]) {
      continue;
    }
    visited[global_idx] = 1;
    if (floor->tiles[idx].type == RATWORLD_TILE_EXIT) {
      free(queue);
      free(visited);
      return 1;
    }
    const int dx[4] = { 1, -1, 0, 0 };
    const int dy[4] = { 0, 0, 1, -1 };
    for (int d = 0; d < 4; ++d) {
      int32_t nx = (int32_t)cur.x + dx[d];
      int32_t ny = (int32_t)cur.y + dy[d];
      if (nx < 0 || ny < 0 || nx >= (int32_t)floor->width || ny >= (int32_t)floor->height) {
        continue;
      }
      size_t nidx = ratworld_floor_index(floor, (uint32_t)nx, (uint32_t)ny);
      if (floor->tiles[nidx].type == RATWORLD_TILE_WALL) {
        continue;
      }
      if (q_tail < q_cap) {
        queue[q_tail++] = (node){ cur.f, (uint32_t)nx, (uint32_t)ny };
      }
    }
    if (floor->tiles[idx].type == RATWORLD_TILE_STAIR_UP && cur.f + 1 < run->floor_count) {
      const ratworldFloor *up = &run->floors[cur.f + 1];
      if (cur.x < up->width && cur.y < up->height) {
        size_t nidx = ratworld_floor_index(up, cur.x, cur.y);
        if (up->tiles[nidx].type != RATWORLD_TILE_WALL) {
          if (q_tail < q_cap) {
            queue[q_tail++] = (node){ cur.f + 1, cur.x, cur.y };
          }
        }
      }
    }
    if (floor->tiles[idx].type == RATWORLD_TILE_STAIR_DOWN && cur.f > 0) {
      const ratworldFloor *down = &run->floors[cur.f - 1];
      if (cur.x < down->width && cur.y < down->height) {
        size_t nidx = ratworld_floor_index(down, cur.x, cur.y);
        if (down->tiles[nidx].type != RATWORLD_TILE_WALL) {
          if (q_tail < q_cap) {
            queue[q_tail++] = (node){ cur.f - 1, cur.x, cur.y };
          }
        }
      }
    }
  }
  free(queue);
  free(visited);
  return 0;
}

static ratworldStatus ratworld_spawn_rats(ratworldRun *run)
{
  size_t i;
  size_t total_tiles;
  uint8_t *occupied;
  const ratworldFloor *spawn_floor;
  uint32_t spawn_floor_z = 0;
  uint32_t spawn_x = 0, spawn_y = 0;

  run->rat_count = run->config.max_rats;
  if (run->rat_count == 0) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  run->rats = calloc(run->rat_count, sizeof(*run->rats));
  run->staged_actions = calloc(run->rat_count, sizeof(*run->staged_actions));
  if (run->rats == NULL || run->staged_actions == NULL) {
    free(run->rats);
    free(run->staged_actions);
    return RATWORLD_STATUS_NO_MEMORY;
  }
  spawn_floor = &run->floors[0];
  total_tiles = (size_t)spawn_floor->width * spawn_floor->height;
  occupied = calloc(total_tiles, sizeof(*occupied));
  if (occupied == NULL) {
    return RATWORLD_STATUS_NO_MEMORY;
  }

  if (ratworld_pick_spawn(run, &spawn_floor_z, &spawn_x, &spawn_y) != 0) {
    free(occupied);
    return RATWORLD_STATUS_FAILED;
  }
  for (i = 0; i < run->rat_count; ++i) {
    ratworldRatState *rat = &run->rats[i];
    char namebuf[32];
    uint32_t fx = spawn_x;
    uint32_t fy = spawn_y;
    uint32_t fz = spawn_floor_z;
    int idx = -1;
    size_t attempts = 0;

    ratworld_pick_spawn(run, &fz, &fx, &fy);
    while (attempts < total_tiles * 2) {
      int candidate = ratworld_pick_random_tile(spawn_floor, &run->rng_state, RATWORLD_TILE_FLOOR);
      if (candidate < 0) {
        break;
      }
      if (!occupied[(size_t)candidate]) {
        idx = candidate;
        break;
      }
      ++attempts;
    }
    if (idx >= 0) {
      fx = (uint32_t)(idx % spawn_floor->width);
      fy = (uint32_t)(idx / spawn_floor->width);
      occupied[idx] = 1;
    }
    rat->rat_id = NULL;
    snprintf(namebuf, sizeof(namebuf), "rat%zu", i);
    rat->rat_id = strdup(namebuf);
    if (rat->rat_id == NULL) {
      size_t j;
      for (j = 0; j <= i; ++j) {
        free((char*)run->rats[j].rat_id);
      }
      free(run->rats);
      free(run->staged_actions);
      free(occupied);
      return RATWORLD_STATUS_NO_MEMORY;
    }
    rat->floor_z = fz;
    rat->x = (int32_t)fx;
    rat->y = (int32_t)fy;
    rat->alive = true;
    rat->health = 1.0;
    rat->stamina = 1.0;
    rat->hunger = 0.0;
    run->staged_actions[i] = RATWORLD_ACTION_WAIT;
    if (fz == 0) {
      size_t occ_idx = ratworld_floor_index(spawn_floor, (uint32_t)rat->x, (uint32_t)rat->y);
      if (occ_idx < total_tiles) {
        occupied[occ_idx] = 1;
      }
    }
  }
  run->state.alive_rats = run->rat_count;
  run->state.dead_rats = 0;
  free(occupied);
  return RATWORLD_STATUS_OK;
}

/* Returns a printable label for the given status code so callers can log stub
 * results without maintaining their own lookup table. */
const char *ratworld_status_string(ratworldStatus status)
{
  switch (status) {
    case RATWORLD_STATUS_OK: return "ok";
    case RATWORLD_STATUS_INVALID_ARGUMENT: return "invalid_argument";
    case RATWORLD_STATUS_NOT_READY: return "not_ready";
    case RATWORLD_STATUS_NOT_FOUND: return "not_found";
    case RATWORLD_STATUS_NO_MEMORY: return "no_memory";
    case RATWORLD_STATUS_NOT_IMPLEMENTED: return "not_implemented";
    case RATWORLD_STATUS_FAILED: return "failed";
    default: return "unknown_status";
  }
}

/* Allocate a Ratworld service handle so callers can register runs and drive
 * ticks independently of CEP glue. Uses a small default capacity when cfg is
 * NULL and records the requested limits for later validation. */
ratworldStatus ratworld_service_create(const ratworldServiceConfig *cfg, ratworldService **out_service)
{
  ratworldService *service;

  if (out_service == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  service = malloc(sizeof(*service));
  if (service == NULL) {
    return RATWORLD_STATUS_NO_MEMORY;
  }
  if (cfg == NULL) {
    service->cfg = ratworld_default_service_config();
  } else {
    service->cfg = *cfg;
  }
  *out_service = service;
  return RATWORLD_STATUS_OK;
}

/* Release a Ratworld service handle and any memory owned by it. */
void ratworld_service_destroy(ratworldService *service)
{
  free(service);
}

static ratworldStatus ratworld_run_alloc_floors(ratworldRun *run)
{
  size_t i;
  ratworldStatus st = RATWORLD_STATUS_OK;

  if (run->config.floors == NULL || run->config.floor_count == 0) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  run->floors = calloc(run->config.floor_count, sizeof(*run->floors));
  if (run->floors == NULL) {
    return RATWORLD_STATUS_NO_MEMORY;
  }
  for (i = 0; i < run->config.floor_count; ++i) {
    const ratworldFloorSpec *spec = &run->config.floors[i];
    ratworldFloor *floor = &run->floors[i];
    size_t tiles;
    uint32_t width = spec->width;
    uint32_t height = spec->height;

    if (width == 0) {
      width = 79; /* classic 80-column terminal minus border; keep odd for maze carving */
    }
    if (height == 0) {
      height = 23; /* classic 24-row terminal minus border; keep odd for maze carving */
    }
    if ((width & 1u) == 0) {
      width -= 1;
    }
    if ((height & 1u) == 0) {
      height -= 1;
    }

    if (width < 3 || height < 3) {
      st = RATWORLD_STATUS_INVALID_ARGUMENT;
      break;
    }
    floor->width = width;
    floor->height = height;
    tiles = (size_t)floor->width * floor->height;
    floor->tiles = calloc(tiles, sizeof(*floor->tiles));
    if (floor->tiles == NULL) {
      st = RATWORLD_STATUS_NO_MEMORY;
      break;
    }
  }
  if (st != RATWORLD_STATUS_OK) {
    size_t j;
    for (j = 0; j <= i; ++j) {
      free(run->floors[j].tiles);
    }
    free(run->floors);
    run->floors = NULL;
  }
  return st;
}

static void ratworld_run_free_floors(ratworldRun *run)
{
  size_t i;

  if (run->floors == NULL) {
    return;
  }
  for (i = 0; i < run->floor_count; ++i) {
    free(run->floors[i].tiles);
  }
  free(run->floors);
  run->floors = NULL;
}

static ratworldStatus ratworld_run_generate_world(ratworldRun *run)
{
  size_t i;
  uint64_t base_seed = run->config.seed;
  unsigned attempt;
  const unsigned k_max_attempts = 16;

  memset(&run->manifest, 0, sizeof(run->manifest));
  for (attempt = 0; attempt < k_max_attempts; ++attempt) {
    run->manifest.stair_pairs = 0;
    run->rng_state = base_seed + attempt;
    for (i = 0; i < run->floor_count; ++i) {
      ratworld_carve_maze(&run->floors[i], &run->rng_state);
    }
    for (i = 0; i + 1 < run->floor_count; ++i) {
      ratworld_place_vertical_links(&run->floors[i], &run->floors[i + 1], &run->rng_state);
      run->manifest.stair_pairs += 1;
    }
    ratworld_place_home_exit(&run->floors[0], &run->floors[run->floor_count - 1], &run->rng_state);
    for (i = 0; i < run->floor_count; ++i) {
      const ratworldFloorSpec *spec = &run->config.floors[i];

      ratworld_place_feature(&run->floors[i], &run->rng_state, RATWORLD_TILE_FOOD, spec->max_food_tiles);
      ratworld_place_feature(&run->floors[i], &run->rng_state, RATWORLD_TILE_TRAP, spec->max_trap_tiles);
      if (spec->max_exit_tiles > 0 && i == run->floor_count - 1) {
        ratworld_place_feature(&run->floors[i], &run->rng_state, RATWORLD_TILE_EXIT, spec->max_exit_tiles);
      }
    }
    int home_idx = ratworld_find_home_index(&run->floors[0]);
    if (home_idx >= 0) {
      run->manifest.home_x = (uint32_t)(home_idx % run->floors[0].width);
      run->manifest.home_y = (uint32_t)(home_idx / run->floors[0].width);
    }
    /* Record exit coordinates if present. */
    {
      const ratworldFloor *last = &run->floors[run->floor_count - 1];
      size_t total = (size_t)last->width * last->height;
      for (size_t t = 0; t < total; ++t) {
        if (last->tiles[t].type == RATWORLD_TILE_EXIT) {
          run->manifest.exit_floor = (uint32_t)(run->floor_count - 1);
          run->manifest.exit_x = (uint32_t)(t % last->width);
          run->manifest.exit_y = (uint32_t)(t / last->width);
          break;
        }
      }
    }
    if (ratworld_world_is_solvable(run)) {
      return RATWORLD_STATUS_OK;
    }
  }
  return RATWORLD_STATUS_FAILED;
}

/* Create a new run against the service using the provided configuration so
 * future ticks can generate maze layouts and process actions. The config is
 * copied by value; caller-owned strings remain borrowed. */
ratworldStatus ratworld_run_create(ratworldService *service,
                                   const ratworldRunConfig *config,
                                   ratworldRun **out_run)
{
  ratworldRun *run;
  ratworldStatus st;

  if (service == NULL || config == NULL || out_run == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (config->floors == NULL || config->floor_count == 0) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (config->floor_count > service->cfg.max_floors) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (config->max_rats == 0 || config->max_rats > service->cfg.max_rats_per_run) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  run = calloc(1, sizeof(*run));
  if (run == NULL) {
    return RATWORLD_STATUS_NO_MEMORY;
  }
  run->config = *config;
  run->state.tick = 0;
  run->state.exits_reached = 0;
  run->control = ratworld_default_control();
  run->economy = config->economy ? *config->economy : ratworld_default_economy();
  run->rng_state = config->seed;
  run->floor_count = config->floor_count;
  st = ratworld_run_alloc_floors(run);
  if (st != RATWORLD_STATUS_OK) {
    ratworld_run_free_floors(run);
    free(run);
    return st;
  }
  st = ratworld_run_generate_world(run);
  if (st != RATWORLD_STATUS_OK) {
    ratworld_run_free_floors(run);
    free(run);
    return st;
  }
  st = ratworld_spawn_rats(run);
  if (st != RATWORLD_STATUS_OK) {
    ratworld_run_free_floors(run);
    free(run->rats);
    free(run->staged_actions);
    free(run);
    return st;
  }
  *out_run = run;
  return RATWORLD_STATUS_OK;
}

/* Destroy a run handle previously created with ratworld_run_create. */
void ratworld_run_destroy(ratworldRun *run)
{
  if (run == NULL) {
    return;
  }
  ratworld_run_free_floors(run);
  if (run->rats != NULL) {
    size_t i;
    for (i = 0; i < run->rat_count; ++i) {
      free((char*)run->rats[i].rat_id);
    }
  }
  free(run->rats);
  free(run->staged_actions);
  free(run);
}

/* Update the control mode for a run so callers can pause, step, or enable
 * replay once tick execution is implemented. */
ratworldStatus ratworld_run_set_control(ratworldRun *run, const ratworldControl *control)
{
  if (run == NULL || control == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  run->control = *control;
  return RATWORLD_STATUS_OK;
}

/* Stub for staging actions that will feed the next tick. Clears output counts
 * so callers can safely inspect buffers even before the implementation lands. */
ratworldStatus ratworld_run_stage_actions(ratworldRun *run,
                                          const ratworldAction *actions,
                                          size_t action_count)
{
  if (run == NULL || (action_count > 0 && actions == NULL)) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (run->staged_actions == NULL || run->rat_count == 0) {
    return RATWORLD_STATUS_NOT_READY;
  }
  for (size_t r = 0; r < run->rat_count; ++r) {
    run->staged_actions[r] = RATWORLD_ACTION_WAIT;
  }
  if (actions == NULL) {
    return RATWORLD_STATUS_OK;
  }
  for (size_t i = 0; i < action_count; ++i) {
    for (size_t j = i + 1; j < action_count; ++j) {
      if (strcmp(actions[i].rat_id, actions[j].rat_id) == 0) {
        return RATWORLD_STATUS_INVALID_ARGUMENT;
      }
    }
  }
  for (size_t i = 0; i < action_count; ++i) {
    size_t r;
    int found = 0;
    for (r = 0; r < run->rat_count; ++r) {
      if (strcmp(run->rats[r].rat_id, actions[i].rat_id) == 0) {
        run->staged_actions[r] = actions[i].kind;
        found = 1;
        break;
      }
    }
    if (!found) {
      return RATWORLD_STATUS_NOT_FOUND;
    }
  }
  return RATWORLD_STATUS_OK;
}

/* Stub tick driver that leaves observations and events empty while reporting
 * the current run state. Intended to be replaced with deterministic maze
 * updates once the environment logic is wired in. */
ratworldStatus ratworld_run_tick(ratworldRun *run,
                                 ratworldEventBuffer *events_out,
                                 ratworldObservationBuffer *observations_out,
                                 ratworldRunState *state_out)
{
  ratworldStatus overall = RATWORLD_STATUS_OK;
  size_t r;

  if (events_out != NULL) {
    events_out->event_count = 0;
  }
  if (observations_out != NULL) {
    observations_out->observation_count = 0;
  }
  if (state_out != NULL) {
    if (run != NULL) {
      *state_out = run->state;
    } else {
      memset(state_out, 0, sizeof(*state_out));
    }
  }
  if (run == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (observations_out != NULL && observations_out->observation_capacity < run->rat_count) {
    return RATWORLD_STATUS_NOT_READY;
  }
  if (events_out != NULL && events_out->event_capacity < run->rat_count * 3) {
    return RATWORLD_STATUS_NOT_READY;
  }
  for (r = 0; r < run->rat_count; ++r) {
    ratworldRatState *rat = &run->rats[r];
    ratworldTileType current_type;
    ratworldFloor *floor;

    if (!rat->alive) {
      continue;
    }
    floor = &run->floors[rat->floor_z];
    current_type = floor->tiles[ratworld_floor_index(floor, (uint32_t)rat->x, (uint32_t)rat->y)].type;
    ratworldActionKind action = run->staged_actions != NULL ? run->staged_actions[r] : RATWORLD_ACTION_WAIT;
    int moved = 0;

    switch (action) {
      case RATWORLD_ACTION_MOVE_N:
      case RATWORLD_ACTION_MOVE_S:
      case RATWORLD_ACTION_MOVE_E:
      case RATWORLD_ACTION_MOVE_W: {
        int dx = 0;
        int dy = 0;

        if (action == RATWORLD_ACTION_MOVE_N) dy = -1;
        else if (action == RATWORLD_ACTION_MOVE_S) dy = 1;
        else if (action == RATWORLD_ACTION_MOVE_W) dx = -1;
        else if (action == RATWORLD_ACTION_MOVE_E) dx = 1;

        int32_t nx = rat->x + dx;
        int32_t ny = rat->y + dy;
        if (nx < 0 || ny < 0 || nx >= (int32_t)floor->width || ny >= (int32_t)floor->height) {
          (void)ratworld_event_emit(events_out, RATWORLD_EVENT_BUMPED, rat);
        } else {
          ratworldTileType target_type = floor->tiles[ratworld_floor_index(floor, (uint32_t)nx, (uint32_t)ny)].type;
          if (target_type == RATWORLD_TILE_WALL) {
            ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_BUMPED, rat);
            if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
              overall = st_ev;
            }
          } else {
            rat->x = nx;
            rat->y = ny;
            moved = 1;
            ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_MOVED, rat);
            if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
              overall = st_ev;
            }
            rat->stamina = ratworld_clamp(rat->stamina - run->economy.stamina_move_cost, 0.0, 1.0);
          }
        }
        break;
      }
      case RATWORLD_ACTION_MOVE_UP:
      case RATWORLD_ACTION_MOVE_DOWN: {
        if (action == RATWORLD_ACTION_MOVE_UP && current_type == RATWORLD_TILE_STAIR_UP && rat->floor_z + 1 < run->floor_count) {
          rat->floor_z += 1;
          floor = &run->floors[rat->floor_z];
          moved = 1;
          ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_MOVED, rat);
          if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
            overall = st_ev;
          }
        } else if (action == RATWORLD_ACTION_MOVE_DOWN && current_type == RATWORLD_TILE_STAIR_DOWN && rat->floor_z > 0) {
          rat->floor_z -= 1;
          floor = &run->floors[rat->floor_z];
          moved = 1;
          ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_MOVED, rat);
          if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
            overall = st_ev;
          }
        } else {
          ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_BUMPED, rat);
          if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
            overall = st_ev;
          }
        }
        break;
      }
      case RATWORLD_ACTION_WAIT:
      default:
        rat->stamina = ratworld_clamp(rat->stamina + run->economy.stamina_wait_recover, 0.0, 1.0);
        break;
    }

    rat->hunger = ratworld_clamp(rat->hunger + run->economy.hunger_base_inc + (moved ? run->economy.hunger_move_inc : 0.0), 0.0, 2.0);
    current_type = floor->tiles[ratworld_floor_index(floor, (uint32_t)rat->x, (uint32_t)rat->y)].type;
    if (current_type == RATWORLD_TILE_FOOD) {
      rat->hunger = ratworld_clamp(rat->hunger - run->economy.hunger_food_boost, 0.0, 2.0);
      floor->tiles[ratworld_floor_index(floor, (uint32_t)rat->x, (uint32_t)rat->y)].type = RATWORLD_TILE_FLOOR;
      ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_ATE_FOOD, rat);
      if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
        overall = st_ev;
      }
    } else if (current_type == RATWORLD_TILE_TRAP) {
      rat->health = ratworld_clamp(rat->health - run->economy.trap_damage, 0.0, 1.0);
      ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_TRIGGERED_TRAP, rat);
      if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
        overall = st_ev;
      }
    } else if (current_type == RATWORLD_TILE_HOME) {
      rat->stamina = ratworld_clamp(rat->stamina + run->economy.stamina_home_recover, 0.0, 1.0);
      rat->hunger = ratworld_clamp(rat->hunger - run->economy.hunger_home_recover, 0.0, 2.0);
    } else if (current_type == RATWORLD_TILE_EXIT) {
      ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_REACHED_EXIT, rat);
      if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
        overall = st_ev;
      }
      run->state.exits_reached += 1;
    }
    if (rat->hunger >= 1.0) {
      rat->health = ratworld_clamp(rat->health - run->economy.hunger_health_cost, 0.0, 1.0);
    }
    if (rat->health <= 0.0 && rat->alive) {
      rat->alive = false;
      if (run->state.alive_rats > 0) {
        run->state.alive_rats -= 1;
      }
      run->state.dead_rats += 1;
      ratworldStatus st_ev = ratworld_event_emit(events_out, RATWORLD_EVENT_DIED, rat);
      if (overall == RATWORLD_STATUS_OK && st_ev != RATWORLD_STATUS_OK) {
        overall = st_ev;
      }
    }
    ratworldStatus st_obs = ratworld_observation_emit(run, rat, observations_out);
    if (overall == RATWORLD_STATUS_OK && st_obs != RATWORLD_STATUS_OK) {
      overall = st_obs;
    }
  }
  run->state.tick += 1;
  if (state_out != NULL) {
    *state_out = run->state;
  }
  return overall;
}

/* Provide read-only access to a floor's tiles so renderers can operate
 * without owning the maze memory. The returned pointer remains valid for the
 * lifetime of the run. */
ratworldStatus ratworld_run_get_floor(const ratworldRun *run,
                                      uint32_t floor_z,
                                      const ratworldTile **tiles_out,
                                      uint32_t *width_out,
                                      uint32_t *height_out)
{
  if (run == NULL || tiles_out == NULL || width_out == NULL || height_out == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (run->floors == NULL) {
    return RATWORLD_STATUS_NOT_READY;
  }
  if (floor_z >= run->floor_count) {
    return RATWORLD_STATUS_NOT_FOUND;
  }
  *tiles_out = run->floors[floor_z].tiles;
  *width_out = run->floors[floor_z].width;
  *height_out = run->floors[floor_z].height;
  return RATWORLD_STATUS_OK;
}

ratworldStatus ratworld_run_get_manifest(const ratworldRun *run, ratworldChallengeManifest *manifest_out)
{
  if (run == NULL || manifest_out == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  *manifest_out = run->manifest;
  return RATWORLD_STATUS_OK;
}

/* Stub snapshot creator so callers can request branch/replay inputs without
 * depending on CEP; fills seed/tick and defers opaque bytes for later. */
ratworldStatus ratworld_run_snapshot(const ratworldRun *run, ratworldSnapshot *snapshot_out)
{
  uint8_t *buf;
  size_t total_size = 0;
  size_t i;

  if (run == NULL || snapshot_out == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  total_size += sizeof(uint64_t) * 2; /* seed, tick */
  total_size += sizeof(uint64_t); /* rng_state */
  total_size += sizeof(uint32_t) * 2; /* floor_count, rat_count */
  total_size += sizeof(ratworldActionEconomy);
  total_size += sizeof(ratworldChallengeManifest);
  for (i = 0; i < run->floor_count; ++i) {
    const ratworldFloor *floor = &run->floors[i];
    size_t tiles = (size_t)floor->width * floor->height;
    total_size += sizeof(uint32_t) * 2; /* w,h */
    total_size += tiles * (sizeof(uint8_t) + sizeof(uint32_t)); /* type + tags */
  }
  for (i = 0; i < run->rat_count; ++i) {
    size_t id_len = strlen(run->rats[i].rat_id);
    total_size += sizeof(uint16_t) + id_len; /* id */
    total_size += sizeof(uint32_t) * 3; /* floor_z,x,y */
    total_size += sizeof(uint8_t); /* alive */
    total_size += sizeof(double) * 3; /* health, stamina, hunger */
  }
  /* Header: version (u32), checksum (u32) followed by payload. */
  buf = malloc(total_size + sizeof(uint32_t) * 2);
  if (buf == NULL) {
    return RATWORLD_STATUS_NO_MEMORY;
  }
  size_t off = 0;
  uint8_t *payload = buf + sizeof(uint32_t) * 2;
#define RW_WRITE(src, sz) do { memcpy(payload + off, (src), (sz)); off += (sz); } while (0)
  RW_WRITE(&run->config.seed, sizeof(uint64_t));
  RW_WRITE(&run->state.tick, sizeof(uint64_t));
  RW_WRITE(&run->rng_state, sizeof(uint64_t));
  uint32_t fc = (uint32_t)run->floor_count;
  uint32_t rc = (uint32_t)run->rat_count;
  RW_WRITE(&fc, sizeof(uint32_t));
  RW_WRITE(&rc, sizeof(uint32_t));
  RW_WRITE(&run->economy, sizeof(run->economy));
  RW_WRITE(&run->manifest, sizeof(run->manifest));
  for (i = 0; i < run->floor_count; ++i) {
    const ratworldFloor *floor = &run->floors[i];
    RW_WRITE(&floor->width, sizeof(uint32_t));
    RW_WRITE(&floor->height, sizeof(uint32_t));
    size_t tiles = (size_t)floor->width * floor->height;
    for (size_t t = 0; t < tiles; ++t) {
      uint8_t type = (uint8_t)floor->tiles[t].type;
      RW_WRITE(&type, sizeof(uint8_t));
      RW_WRITE(&floor->tiles[t].tags, sizeof(uint32_t));
    }
  }
  for (i = 0; i < run->rat_count; ++i) {
    const ratworldRatState *rat = &run->rats[i];
    uint16_t id_len = (uint16_t)strlen(rat->rat_id);
    RW_WRITE(&id_len, sizeof(uint16_t));
    RW_WRITE(rat->rat_id, id_len);
    RW_WRITE(&rat->floor_z, sizeof(uint32_t));
    RW_WRITE(&rat->x, sizeof(uint32_t));
    RW_WRITE(&rat->y, sizeof(uint32_t));
    uint8_t alive = rat->alive ? 1u : 0u;
    RW_WRITE(&alive, sizeof(uint8_t));
    RW_WRITE(&rat->health, sizeof(double));
    RW_WRITE(&rat->stamina, sizeof(double));
    RW_WRITE(&rat->hunger, sizeof(double));
  }
#undef RW_WRITE
  uint32_t version = RATWORLD_SNAPSHOT_VERSION;
  uint32_t checksum = ratworld_checksum32(payload, total_size);
  memcpy(buf, &version, sizeof(uint32_t));
  memcpy(buf + sizeof(uint32_t), &checksum, sizeof(uint32_t));
  snapshot_out->seed = run->config.seed;
  snapshot_out->tick = run->state.tick;
  snapshot_out->opaque_state = buf;
  snapshot_out->opaque_state_len = total_size + sizeof(uint32_t) * 2;
  return RATWORLD_STATUS_OK;
}

/* Stub branch helper intended to spin up a new run from a snapshot once
 * persistence and state reconstruction land. */
ratworldStatus ratworld_run_branch(ratworldService *service,
                                   const ratworldSnapshot *snapshot,
                                   const ratworldRunConfig *config,
                                   ratworldRun **out_run)
{
  const uint8_t *buf;
  size_t off = 0;
  uint32_t floor_count;
  uint32_t rat_count;
  uint32_t version;
  uint32_t checksum_stored;
  ratworldRun *run;
  ratworldStatus st;
  size_t i;

  if (service == NULL || snapshot == NULL || config == NULL || out_run == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (config->floors == NULL || config->floor_count == 0) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (snapshot->opaque_state == NULL || snapshot->opaque_state_len == 0) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (snapshot->opaque_state_len < sizeof(uint32_t) * 2) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  buf = snapshot->opaque_state;
  run = calloc(1, sizeof(*run));
  if (run == NULL) {
    return RATWORLD_STATUS_NO_MEMORY;
  }
  run->config = *config;
  run->control = ratworld_default_control();
#define RW_READ(dst, sz) do { memcpy((dst), buf + off, (sz)); off += (sz); } while (0)
  off = 0;
  RW_READ(&version, sizeof(uint32_t));
  RW_READ(&checksum_stored, sizeof(uint32_t));
  if (version != RATWORLD_SNAPSHOT_VERSION) {
    free(run);
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (ratworld_checksum32(buf + sizeof(uint32_t) * 2, snapshot->opaque_state_len - sizeof(uint32_t) * 2) != checksum_stored) {
    free(run);
    return RATWORLD_STATUS_FAILED;
  }
  RW_READ(&run->config.seed, sizeof(uint64_t));
  RW_READ(&run->state.tick, sizeof(uint64_t));
  RW_READ(&run->rng_state, sizeof(uint64_t));
  RW_READ(&floor_count, sizeof(uint32_t));
  RW_READ(&rat_count, sizeof(uint32_t));
  RW_READ(&run->economy, sizeof(run->economy));
  RW_READ(&run->manifest, sizeof(run->manifest));
#undef RW_READ
  if (floor_count != config->floor_count) {
    free(run);
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (rat_count == 0 || rat_count > config->max_rats) {
    free(run);
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  run->floor_count = floor_count;
  st = ratworld_run_alloc_floors(run);
  if (st != RATWORLD_STATUS_OK) {
    free(run);
    return st;
  }
  for (i = 0; i < run->floor_count; ++i) {
    ratworldFloor *floor = &run->floors[i];
    uint32_t width, height;
    size_t tiles;
#define RW_READ(dst, sz) do { memcpy((dst), buf + off, (sz)); off += (sz); } while (0)
    RW_READ(&width, sizeof(uint32_t));
    RW_READ(&height, sizeof(uint32_t));
    if (width != floor->width || height != floor->height) {
      ratworld_run_free_floors(run);
      free(run);
      return RATWORLD_STATUS_INVALID_ARGUMENT;
    }
    tiles = (size_t)floor->width * floor->height;
    for (size_t t = 0; t < tiles; ++t) {
      uint8_t type;
      RW_READ(&type, sizeof(uint8_t));
      floor->tiles[t].type = (ratworldTileType)type;
      RW_READ(&floor->tiles[t].tags, sizeof(uint32_t));
    }
#undef RW_READ
  }
  run->rat_count = rat_count;
  run->rats = calloc(run->rat_count, sizeof(*run->rats));
  run->staged_actions = calloc(run->rat_count, sizeof(*run->staged_actions));
  if (run->rats == NULL || run->staged_actions == NULL) {
    ratworld_run_free_floors(run);
    free(run->rats);
    free(run->staged_actions);
    free(run);
    return RATWORLD_STATUS_NO_MEMORY;
  }
  for (i = 0; i < run->rat_count; ++i) {
    ratworldRatState *rat = &run->rats[i];
    uint16_t id_len;
    uint8_t alive;
#define RW_READ(dst, sz) do { memcpy((dst), buf + off, (sz)); off += (sz); } while (0)
    RW_READ(&id_len, sizeof(uint16_t));
    rat->rat_id = malloc(id_len + 1);
    if (rat->rat_id == NULL) {
      size_t j;
      for (j = 0; j < i; ++j) {
        free((char*)run->rats[j].rat_id);
      }
      ratworld_run_free_floors(run);
      free(run->rats);
      free(run->staged_actions);
      free(run);
      return RATWORLD_STATUS_NO_MEMORY;
    }
    memcpy((char*)rat->rat_id, buf + off, id_len);
    ((char*)rat->rat_id)[id_len] = '\0';
    off += id_len;
    RW_READ(&rat->floor_z, sizeof(uint32_t));
    RW_READ(&rat->x, sizeof(uint32_t));
    RW_READ(&rat->y, sizeof(uint32_t));
    RW_READ(&alive, sizeof(uint8_t));
    rat->alive = alive != 0;
    RW_READ(&rat->health, sizeof(double));
    RW_READ(&rat->stamina, sizeof(double));
    RW_READ(&rat->hunger, sizeof(double));
#undef RW_READ
    run->staged_actions[i] = RATWORLD_ACTION_WAIT;
  }
  run->state.alive_rats = 0;
  run->state.dead_rats = 0;
  for (i = 0; i < run->rat_count; ++i) {
    if (run->rats[i].alive) {
      run->state.alive_rats += 1;
    } else {
      run->state.dead_rats += 1;
    }
  }
  *out_run = run;
  return RATWORLD_STATUS_OK;
}

ratworldStatus ratworld_snapshot_release(ratworldSnapshot *snapshot)
{
  if (snapshot == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  free((void*)snapshot->opaque_state);
  snapshot->opaque_state = NULL;
  snapshot->opaque_state_len = 0;
  return RATWORLD_STATUS_OK;
}
