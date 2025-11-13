/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_CPS_FLATFILE_H
#define CEP_CPS_FLATFILE_H

#include "cps_engine.h"

typedef struct {
  const char *root_dir;              /* absolute or repo-relative branch root */
  const char *branch_name;           /* branch identifier/path component */
  uint32_t checkpoint_interval;      /* beats between auto-checkpoints */
  uint32_t mini_toc_hint;            /* expected entries per beat */
  bool create_branch;                /* create directories if missing */
} cps_flatfile_opts;

int cps_flatfile_engine_open(const cps_flatfile_opts *opts, cps_engine **out);

#endif /* CEP_CPS_FLATFILE_H */
