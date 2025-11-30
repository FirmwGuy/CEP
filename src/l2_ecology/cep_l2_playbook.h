/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_PLAYBOOK_H
#define CEP_L2_PLAYBOOK_H

#include <stdbool.h>
#include <stddef.h>
#include "../l0_kernel/cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    cepCell* eco_root;
    const char* learner_id;
    const char* skill_id;
    const char* focus_key;
    const char* const* actions; /* array of action IDs */
    size_t action_count;
    double exploration_bias;
    bool allow_imaginate;
    bool (*guardian_allow)(const char* action_id, void* user);
    void* guardian_user;
    const cepPipelineMetadata* pipeline;
    const cepDT* species_id;
    const cepDT* variant_id;
} cepL2DecisionRequest;

typedef struct {
    size_t chosen_index;
    bool imaginate_used;
    uint64_t seed;
    size_t sample_rank;
    const char* action_id;
    cepCell* playbook_row;
    cepCell* decision_cell;
} cepL2DecisionResult;

bool cep_l2_playbook_select(const cepL2DecisionRequest* req, cepL2DecisionResult* out);
bool cep_l2_playbook_update_stats(cepCell* eco_root,
                                  const char* learner_id,
                                  const char* focus_key,
                                  const char* action_id,
                                  bool success,
                                  double cost,
                                  bool imaginate_used,
                                  cepCell* decision_cell);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_PLAYBOOK_H */
