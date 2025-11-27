/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_SCHEMA_H
#define CEP_L2_SCHEMA_H

#include <stdbool.h>
#include "../l0_kernel/cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Ensures the pack-owned roots exist under `/data` and seeds baseline
 * dictionaries for schema/runtime/layout. Outputs the resolved eco/learn
 * roots when provided. */
bool cep_l2_schema_seed_roots(cepCell* data_root,
                              cepCell** eco_root_out,
                              cepCell** learn_root_out);

/* Ensures the meta/state cell under `/data/eco/meta/state` exists so callers
 * can record readiness. */
cepCell* cep_l2_schema_state_cell(cepCell* eco_root);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_SCHEMA_H */
