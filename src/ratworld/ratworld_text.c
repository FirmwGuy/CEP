/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ratworld_text.h"

#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>

static char ratworld_text_pick_tile(const ratworldTextGlyphs *glyphs,
                                    const ratworldTile *tile)
{
  char glyph;

  switch (tile->type) {
    case RATWORLD_TILE_WALL: glyph = glyphs->wall; break;
    case RATWORLD_TILE_STAIR_UP: glyph = glyphs->stair_up; break;
    case RATWORLD_TILE_STAIR_DOWN: glyph = glyphs->stair_down; break;
    case RATWORLD_TILE_FOOD: glyph = glyphs->food; break;
    case RATWORLD_TILE_TRAP: glyph = glyphs->trap; break;
    case RATWORLD_TILE_HOME: glyph = glyphs->home; break;
    case RATWORLD_TILE_EXIT: glyph = glyphs->exit; break;
    case RATWORLD_TILE_FLOOR: glyph = glyphs->floor; break;
    default: glyph = glyphs->unknown; break;
  }
  /* Tag overlays: DARK wins first (fog), smell mark is a light overlay if no
   * rat is present and tile is otherwise visible. */
  if ((tile->tags & RATWORLD_TILE_TAG_DARK) != 0) {
    glyph = glyphs->dark;
  } else if ((tile->tags & RATWORLD_TILE_TAG_SMELL_MARK) != 0) {
    glyph = glyphs->smell_mark;
  }
  return glyph;
}

void ratworld_text_default_glyphs(ratworldTextGlyphs *glyphs)
{
  if (glyphs == NULL) {
    return;
  }
  glyphs->wall = '#';
  glyphs->floor = '.';
  glyphs->stair_up = '<';
  glyphs->stair_down = '>';
  glyphs->food = '%';
  glyphs->trap = '^';
  glyphs->home = 'H';
  glyphs->exit = '>';
  glyphs->dark = ' ';
  glyphs->smell_mark = ';';
  glyphs->rat_alive = '@';
  glyphs->rat_dead = 'x';
  glyphs->unknown = '?';
}

ratworldStatus ratworld_text_render_floor(const ratworldTextFloor *floor,
                                          const ratworldTextGlyphs *glyphs,
                                          const ratworldRatState *rats,
                                          size_t rat_count,
                                          char *buffer,
                                          size_t buffer_len)
{
  ratworldTextGlyphs local_glyphs;
  size_t required;
  size_t idx = 0;
  uint32_t y;

  if (floor == NULL || floor->tiles == NULL || buffer == NULL) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  if (glyphs == NULL) {
    ratworld_text_default_glyphs(&local_glyphs);
    glyphs = &local_glyphs;
  }
  required = (size_t)(floor->width + 1) * (size_t)floor->height + 1;
  if (buffer_len < required) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  for (y = 0; y < floor->height; ++y) {
    uint32_t x;
    for (x = 0; x < floor->width; ++x) {
      const ratworldTile *tile = &floor->tiles[(size_t)y * floor->width + x];
      char glyph = ratworld_text_pick_tile(glyphs, tile);
      size_t r;
      for (r = 0; r < rat_count; ++r) {
        const ratworldRatState *rat = &rats[r];
        if (!rat->alive && glyphs->rat_dead == '\0') {
          continue;
        }
        if (rat->floor_z != floor->floor_z) {
          continue;
        }
        if ((uint32_t)rat->x == x && (uint32_t)rat->y == y) {
          glyph = rat->alive ? glyphs->rat_alive : glyphs->rat_dead;
          break;
        }
      }
      buffer[idx++] = glyph;
    }
    buffer[idx++] = '\n';
  }
  buffer[idx] = '\0';
  return RATWORLD_STATUS_OK;
}

ratworldStatus ratworld_text_render_ui(const ratworldTextFloor *floor,
                                       const ratworldTextGlyphs *glyphs,
                                       const ratworldRatState *rats,
                                       size_t rat_count,
                                       const ratworldTextHud *hud,
                                       char *buffer,
                                       size_t buffer_len)
{
  ratworldStatus st;
  size_t used;
  size_t remaining;
  int written;

  st = ratworld_text_render_floor(floor, glyphs, rats, rat_count, buffer, buffer_len);
  if (st != RATWORLD_STATUS_OK) {
    return st;
  }
  used = strlen(buffer);
  remaining = (used < buffer_len) ? buffer_len - used : 0;
  if (hud == NULL || remaining == 0) {
    return RATWORLD_STATUS_OK;
  }
  written = snprintf(buffer + used, remaining,
                     "Run:%s Floor:%u Tick:%" PRIu64 " Rat:%s HP:%.2f ST:%.2f HG:%.2f Exits:%zu\n",
                     hud->run_id ? hud->run_id : "-",
                     hud->floor_z,
                     hud->run_state ? (uint64_t)hud->run_state->tick : 0u,
                     hud->rat && hud->rat->rat_id ? hud->rat->rat_id : "-",
                     hud->rat ? hud->rat->health : 0.0,
                     hud->rat ? hud->rat->stamina : 0.0,
                     hud->rat ? hud->rat->hunger : 0.0,
                     hud->run_state ? hud->run_state->exits_reached : 0u);
  if (written < 0 || (size_t)written >= remaining) {
    return RATWORLD_STATUS_INVALID_ARGUMENT;
  }
  return RATWORLD_STATUS_OK;
}
