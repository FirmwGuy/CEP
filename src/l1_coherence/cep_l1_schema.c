/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_schema.h"

#include "../l0_kernel/cep_heartbeat.h"

#include <string.h>

CEP_DEFINE_STATIC_DT(dt_coh_root_name, CEP_ACRO("CEP"), CEP_WORD("coh"));
CEP_DEFINE_STATIC_DT(dt_beings_name,    CEP_ACRO("CEP"), CEP_WORD("beings"));
CEP_DEFINE_STATIC_DT(dt_bonds_name,     CEP_ACRO("CEP"), CEP_WORD("bonds"));
CEP_DEFINE_STATIC_DT(dt_contexts_name,  CEP_ACRO("CEP"), CEP_WORD("contexts"));
CEP_DEFINE_STATIC_DT(dt_facets_name,    CEP_ACRO("CEP"), CEP_WORD("facets"));
CEP_DEFINE_STATIC_DT(dt_debts_name,     CEP_ACRO("CEP"), CEP_WORD("debts"));
CEP_DEFINE_STATIC_DT(dt_flow_root_name, CEP_ACRO("CEP"), CEP_WORD("flow"));
CEP_DEFINE_STATIC_DT(dt_state_root_name, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_pipelines_name, CEP_ACRO("CEP"), CEP_WORD("pipelines"));
CEP_DEFINE_STATIC_DT(dt_runtime_name,   CEP_ACRO("CEP"), CEP_WORD("runtime"));
CEP_DEFINE_STATIC_DT(dt_runs_name,      CEP_ACRO("CEP"), CEP_WORD("runs"));
CEP_DEFINE_STATIC_DT(dt_metrics_name,   CEP_ACRO("CEP"), CEP_WORD("metrics"));
CEP_DEFINE_STATIC_DT(dt_annotations_name, CEP_ACRO("CEP"), CEP_WORD("annotations"));

static bool cep_l1_schema_require_dict(cepCell* parent,
                                       const cepDT* name,
                                       cepCell** out) {
    if (!parent || !name) {
        return false;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return false;
    }
    if (out) {
        *out = child;
    }
    return true;
}

/* Ensure the Layer 1 storage layout exists and capture the resolved handles so
   pack helpers can populate coherence, pipeline, runtime, and awareness trees
   without repeating path traversal. The layout intentionally stays minimal for
   now; adjacency closure, pipeline validation, and runtime orchestration wire
   in TODO hooks where deeper logic will land. */
bool cep_l1_schema_ensure(cepL1SchemaLayout* layout) {
    if (!layout) {
        return false;
    }

    memset(layout, 0, sizeof *layout);

    cepCell* data_root = cep_heartbeat_data_root();
    data_root = data_root ? cep_cell_resolve(data_root) : NULL;
    if (!data_root || !cep_cell_require_dictionary_store(&data_root)) {
        return false;
    }

    cepCell* coh_root = NULL;
    if (!cep_l1_schema_require_dict(data_root, dt_coh_root_name(), &coh_root)) {
        return false;
    }

    cepCell* coh_beings = NULL;
    cepCell* coh_bonds = NULL;
    cepCell* coh_contexts = NULL;
    cepCell* coh_facets = NULL;
    cepCell* coh_debts = NULL;

    if (!cep_l1_schema_require_dict(coh_root, dt_beings_name(), &coh_beings)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(coh_root, dt_bonds_name(), &coh_bonds)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(coh_root, dt_contexts_name(), &coh_contexts)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(coh_root, dt_facets_name(), &coh_facets)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(coh_root, dt_debts_name(), &coh_debts)) {
        return false;
    }

    /* TODO: Attach adjacency closure + debt issuance enzymes once task 20.3 lands. */

    cepCell* flow_root = NULL;
    if (!cep_l1_schema_require_dict(data_root, dt_flow_root_name(), &flow_root)) {
        return false;
    }

    cepCell* flow_state = NULL;
    cepCell* flow_pipelines = NULL;
    cepCell* flow_runtime = NULL;
    cepCell* flow_runs = NULL;
    cepCell* flow_metrics = NULL;
    cepCell* flow_annotations = NULL;

    if (!cep_l1_schema_require_dict(flow_root, dt_state_root_name(), &flow_state)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(flow_root, dt_pipelines_name(), &flow_pipelines)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(flow_root, dt_runtime_name(), &flow_runtime)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(flow_runtime, dt_runs_name(), &flow_runs)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(flow_root, dt_metrics_name(), &flow_metrics)) {
        return false;
    }
    if (!cep_l1_schema_require_dict(flow_root, dt_annotations_name(), &flow_annotations)) {
        return false;
    }

    layout->data_root = data_root;
    layout->coh_root = coh_root;
    layout->coh_beings = coh_beings;
    layout->coh_bonds = coh_bonds;
    layout->coh_contexts = coh_contexts;
    layout->coh_facets = coh_facets;
    layout->coh_debts = coh_debts;
    layout->flow_root = flow_root;
    layout->flow_state = flow_state;
    layout->flow_pipelines = flow_pipelines;
    layout->flow_runtime = flow_runtime;
    layout->flow_runs = flow_runs;
    layout->flow_metrics = flow_metrics;
    layout->flow_annotations = flow_annotations;
    return true;
}
