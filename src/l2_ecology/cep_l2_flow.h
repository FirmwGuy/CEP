/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_FLOW_H
#define CEP_L2_FLOW_H

#include <stdbool.h>
#include <stddef.h>
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CEP_L2_NODE_GUARD = 0,
    CEP_L2_NODE_TRANSFORM = 1,
    CEP_L2_NODE_WAIT = 2,
    CEP_L2_NODE_DECIDE = 3,
    CEP_L2_NODE_CLAMP = 4,
} cepL2NodeType;

typedef struct {
    cepL2NodeType type;
    cepDT         node_id;
    cepDT         successor;
    cepDT         alt_successor;
    cepCell*      node_cell;
    bool          yields;
} cepL2CompiledNode;

typedef enum {
    CEP_L2_ORG_RUNNING = 0,
    CEP_L2_ORG_WAITING = 1,
    CEP_L2_ORG_FINISHED = 2,
    CEP_L2_ORG_FAILED = 3,
} cepL2OrganismStatus;

typedef struct {
    cepCell*             eco_root;
    cepCell*             flow_root;
    cepCell*             learn_root;
    cepCell*             organism_root;
    cepCell*             organism;
    cepDT                organism_id;
    cepDT                flow_id;
    cepDT                species_id;
    cepDT                variant_id;
    cepDT                niche_id;
    cepDT                current_node;
    cepPipelineMetadata  pipeline;
    cepL2OrganismStatus  status;
    size_t               steps_executed;
    uint64_t             created_beat;
    uint64_t             last_beat;
    cepOID               episode_oid;
} cepL2OrganismContext;

/* Executes up to `step_budget` nodes for an organism context, compiling the
 * flow graph on demand, recording Decision Cells for non-deterministic choices,
 * and enforcing guardian/budget clamp rules. The helper updates organism state
 * (status/node pointer/timestamps) and emits CEI on violations so Flow VM
 * progress stays deterministic and observable. */
bool cep_l2_flow_step(cepL2OrganismContext* ctx, size_t step_budget);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_FLOW_H */
