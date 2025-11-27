/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_SEC_PIPELINE_H
#define CEP_SEC_PIPELINE_H

#include "../l0_kernel/cep_cell.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool cep_sec_pipeline_bootstrap(void);

int  cep_sec_pipeline_run_preflight(const cepPath* target_path);

bool cep_sec_pipeline_approved(const char* pipeline_id,
                               uint64_t* approved_policy_version,
                               char* note,
                               size_t note_capacity);

#endif /* CEP_SEC_PIPELINE_H */
