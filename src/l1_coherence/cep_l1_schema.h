/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_SCHEMA_H
#define CEP_L1_SCHEMA_H

#include "../l0_kernel/cep_cell.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    cepCell* data_root;
    cepCell* coh_root;
    cepCell* coh_beings;
    cepCell* coh_bonds;
    cepCell* coh_contexts;
    cepCell* coh_facets;
    cepCell* coh_debts;
    cepCell* flow_root;
    cepCell* flow_state;
    cepCell* flow_pipelines;
    cepCell* flow_runtime;
    cepCell* flow_runs;
    cepCell* flow_metrics;
    cepCell* flow_annotations;
} cepL1SchemaLayout;

bool cep_l1_schema_ensure(cepL1SchemaLayout* layout);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L1_SCHEMA_H */
