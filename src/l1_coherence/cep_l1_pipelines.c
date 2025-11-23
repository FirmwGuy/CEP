/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_pipelines.h"
#include "cep_l1_coherence.h"

#include "../l0_kernel/cep_namepool.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_stages_name, CEP_ACRO("CEP"), CEP_WORD("stages"));
CEP_DEFINE_STATIC_DT(dt_edges_name,  CEP_ACRO("CEP"), CEP_WORD("edges"));
CEP_DEFINE_STATIC_DT(dt_stage_id,    CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_pipeline_id_field, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_source_field, CEP_ACRO("CEP"), CEP_WORD("source"));
CEP_DEFINE_STATIC_DT(dt_target_field, CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_note_field_flow, CEP_ACRO("CEP"), CEP_WORD("note"));

static bool cep_l1_pipeline_make_dt(const char* pipeline_id, cepDT* out) {
    if (!pipeline_id || !out) {
        return false;
    }
    size_t len = strlen(pipeline_id);
    if (len == 0u) {
        return false;
    }
    cepID tag = cep_namepool_intern(pipeline_id, len);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_pipeline_make_stage_dt(const char* stage_id, cepDT* out) {
    if (!stage_id || !out) {
        return false;
    }
    size_t len = strlen(stage_id);
    if (len == 0u) {
        return false;
    }
    cepID tag = cep_namepool_intern(stage_id, len);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_pipeline_make_edge_dt(const char* edge_id, cepDT* out) {
    if (!edge_id || !out) {
        return false;
    }
    size_t len = strlen(edge_id);
    if (len == 0u) {
        return false;
    }
    cepID tag = cep_namepool_intern(edge_id, len);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_pipeline_require_dict(cepCell* parent,
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

static bool cep_l1_pipeline_copy_text_field(cepCell* parent,
                                            const cepDT* field,
                                            char* buffer,
                                            size_t buffer_size) {
    if (!parent || !field || !buffer || buffer_size == 0u) {
        return false;
    }
    cepCell* field_cell = cep_cell_find_by_name(parent, field);
    field_cell = field_cell ? cep_cell_resolve(field_cell) : NULL;
    if (!field_cell) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&field_cell, &data) || !data || data->size == 0u) {
        return false;
    }
    size_t length = data->size;
    if (length >= buffer_size) {
        length = buffer_size - 1u;
    }
    memcpy(buffer, cep_data_payload(data), length);
    buffer[length] = '\0';
    return true;
}

/* Create or fetch a pipeline definition branch under `/data/flow/pipelines`,
   wiring the standard children (stages + edges) so callers can fill in DAGs.
   Validation is deliberately deferred; TODO hooks remain for edge/lineage
   checks once the adjacency/closure enzymes land. */
bool cep_l1_pipeline_ensure(cepCell* pipelines_root,
                            const char* pipeline_id,
                            cepL1PipelineLayout* layout) {
    if (!pipelines_root || !pipeline_id || !layout) {
        return false;
    }

    cepDT pipe_dt = {0};
    if (!cep_l1_pipeline_make_dt(pipeline_id, &pipe_dt)) {
        return false;
    }

    cepCell* pipeline = cep_cell_ensure_dictionary_child(pipelines_root, &pipe_dt, CEP_STORAGE_RED_BLACK_T);
    pipeline = pipeline ? cep_cell_resolve(pipeline) : NULL;
    if (!pipeline || !cep_cell_require_dictionary_store(&pipeline)) {
        return false;
    }
    if (!cep_cell_put_text(pipeline, dt_pipeline_id_field(), pipeline_id)) {
        return false;
    }

    cepCell* stages = NULL;
    cepCell* edges = NULL;

    if (!cep_l1_pipeline_require_dict(pipeline, dt_stages_name(), &stages)) {
        return false;
    }
    if (!cep_l1_pipeline_require_dict(pipeline, dt_edges_name(), &edges)) {
        return false;
    }

    /* TODO: record coherence provenance (beings/bonds/contexts) once available. */
    /* TODO: validate edges against stage set once adjacency closure lands. */

    layout->pipeline = pipeline;
    layout->stages = stages;
    layout->edges = edges;
    return true;
}

/* Ensure a stage stub exists so orchestration code has a deterministic home
   for stage metadata and state tracking. The stub records `stage_id` for quick
   lookup; later passes will attach budgets, enclaves, and validator links. */
bool cep_l1_pipeline_stage_stub(cepL1PipelineLayout* layout,
                                const char* stage_id,
                                cepCell** stage_out) {
    if (!layout || !layout->stages || !stage_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->stages)) {
        return false;
    }

    cepDT stage_dt = {0};
    if (!cep_l1_pipeline_make_stage_dt(stage_id, &stage_dt)) {
        return false;
    }

    cepCell* stage = cep_cell_ensure_dictionary_child(layout->stages, &stage_dt, CEP_STORAGE_RED_BLACK_T);
    stage = stage ? cep_cell_resolve(stage) : NULL;
    if (!stage || !cep_cell_require_dictionary_store(&stage)) {
        return false;
    }

    if (!cep_cell_put_text(stage, dt_stage_id(), stage_id)) {
        return false;
    }
    if (layout->pipeline) {
        cepCell* parents[] = {layout->pipeline};
        (void)cep_cell_add_parents(stage, parents, 1u);
    }

    if (stage_out) {
        *stage_out = stage;
    }
    return true;
}

/* Register a directed edge between two stage stubs. The helper ensures both
   endpoints exist, persists the edge metadata, and links the edge back to the
   pipeline container for provenance. */
bool cep_l1_pipeline_add_edge(cepL1PipelineLayout* layout,
                              const char* from_stage,
                              const char* to_stage,
                              const char* note) {
    if (!layout || !layout->edges || !layout->stages || !from_stage || !to_stage) {
        return false;
    }
    if (strcmp(from_stage, to_stage) == 0) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->edges)) {
        return false;
    }

    char edge_name[256];
    int written = snprintf(edge_name, sizeof edge_name, "%s_%s", from_stage, to_stage);
    if (written <= 0 || (size_t)written >= sizeof edge_name) {
        return false;
    }

    cepCell* from = NULL;
    if (!cep_l1_pipeline_stage_stub(layout, from_stage, &from)) {
        return false;
    }
    if (!cep_l1_pipeline_stage_stub(layout, to_stage, NULL)) {
        return false;
    }

    cepDT edge_dt = {0};
    if (!cep_l1_pipeline_make_edge_dt(edge_name, &edge_dt)) {
        return false;
    }
    cepCell* edge = cep_cell_ensure_dictionary_child(layout->edges, &edge_dt, CEP_STORAGE_RED_BLACK_T);
    edge = edge ? cep_cell_resolve(edge) : NULL;
    if (!edge || !cep_cell_require_dictionary_store(&edge)) {
        return false;
    }

    (void)cep_cell_put_text(edge, dt_source_field(), from_stage);
    (void)cep_cell_put_text(edge, dt_target_field(), to_stage);
    if (note && *note) {
        (void)cep_cell_put_text(edge, dt_note_field_flow(), note);
    }

    if (layout->pipeline) {
        char pipeline_buffer[128] = {0};
        if (cep_l1_pipeline_copy_text_field(layout->pipeline, dt_pipeline_id_field(), pipeline_buffer, sizeof pipeline_buffer) &&
            pipeline_buffer[0]) {
            (void)cep_cell_put_text(edge, dt_pipeline_id_field(), pipeline_buffer);
        }
        cepCell* parents[] = {layout->pipeline};
        (void)cep_cell_add_parents(edge, parents, 1u);
        if (from) {
            cepCell* endpoints[] = {from};
            (void)cep_cell_add_parents(edge, endpoints, 1u);
        }
    }

    return true;
}

/* Attach pipeline definitions to coherence beings so provenance survives beyond
   the DAG tree. A pipeline being is ensured, and all stages/edges inherit that
   parent so the closure engine can trace lineage deterministically. */
bool cep_l1_pipeline_bind_coherence(cepL1SchemaLayout* schema,
                                    cepL1PipelineLayout* pipeline) {
    if (!schema || !pipeline || !pipeline->pipeline || !schema->coh_beings) {
        return false;
    }
    char pipeline_buffer[128] = {0};
    if (!cep_l1_pipeline_copy_text_field(pipeline->pipeline, dt_pipeline_id_field(), pipeline_buffer, sizeof pipeline_buffer) ||
        !pipeline_buffer[0]) {
        return false;
    }

    cepCell* pipeline_being = NULL;
    if (!cep_l1_coh_add_being(schema, pipeline_buffer, &pipeline_being)) {
        return false;
    }

    cepCell* parents[] = {pipeline_being};
    (void)cep_cell_add_parents(pipeline->pipeline, parents, 1u);

    if (pipeline->stages && cep_cell_require_dictionary_store(&pipeline->stages)) {
        for (cepCell* stage = cep_cell_first(pipeline->stages); stage; stage = cep_cell_next(pipeline->stages, stage)) {
            stage = cep_cell_resolve(stage);
            if (!stage) {
                continue;
            }
            (void)cep_cell_add_parents(stage, parents, 1u);
        }
    }

    if (pipeline->edges && cep_cell_require_dictionary_store(&pipeline->edges)) {
        for (cepCell* edge = cep_cell_first(pipeline->edges); edge; edge = cep_cell_next(pipeline->edges, edge)) {
            edge = cep_cell_resolve(edge);
            if (!edge) {
                continue;
            }
            (void)cep_cell_add_parents(edge, parents, 1u);
        }
    }

    return true;
}
