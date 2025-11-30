/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef RATWORLD_TEXT_H
#define RATWORLD_TEXT_H

#include "ratworld.h"

typedef struct {
  uint32_t width;
  uint32_t height;
  uint32_t floor_z;
  const ratworldTile *tiles;
} ratworldTextFloor;

typedef struct {
  char wall;
  char floor;
  char stair_up;
  char stair_down;
  char food;
  char trap;
  char home;
  char exit;
  char dark;
  char smell_mark;
  char rat_alive;
  char rat_dead;
  char unknown;
} ratworldTextGlyphs;

void ratworld_text_default_glyphs(ratworldTextGlyphs *glyphs);

ratworldStatus ratworld_text_render_floor(const ratworldTextFloor *floor,
                                          const ratworldTextGlyphs *glyphs,
                                          const ratworldRatState *rats,
                                          size_t rat_count,
                                          char *buffer,
                                          size_t buffer_len);

typedef struct {
  const char *run_id;
  const ratworldRatState *rat;
  const ratworldRunState *run_state;
  uint32_t floor_z;
} ratworldTextHud;

ratworldStatus ratworld_text_render_ui(const ratworldTextFloor *floor,
                                       const ratworldTextGlyphs *glyphs,
                                       const ratworldRatState *rats,
                                       size_t rat_count,
                                       const ratworldTextHud *hud,
                                       char *buffer,
                                       size_t buffer_len);

#endif /* RATWORLD_TEXT_H */
