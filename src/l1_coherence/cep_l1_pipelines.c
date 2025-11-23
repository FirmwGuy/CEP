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
CEP_DEFINE_STATIC_DT(dt_revision_field, CEP_ACRO("CEP"), CEP_WORD("rev"));
CEP_DEFINE_STATIC_DT(dt_version_field, CEP_ACRO("CEP"), CEP_WORD("ver"));
CEP_DEFINE_STATIC_DT(dt_owner_field_flow, CEP_ACRO("CEP"), CEP_WORD("owner"));
CEP_DEFINE_STATIC_DT(dt_province_field_flow, CEP_ACRO("CEP"), CEP_WORD("province"));
CEP_DEFINE_STATIC_DT(dt_max_hops_field_flow, CEP_ACRO("CEP"), CEP_WORD("max_hops"));

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

static bool cep_l1_pipeline_copy_uint64_field(cepCell* parent,
                                              const cepDT* field,
                                              uint64_t* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* field_cell = cep_cell_find_by_name(parent, field);
    field_cell = field_cell ? cep_cell_resolve(field_cell) : NULL;
    if (!field_cell) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&field_cell, &data) || !data || data->size < sizeof(uint64_t)) {
        return false;
    }
    uint64_t value = 0u;
    memcpy(&value, cep_data_payload(data), sizeof value);
    *out = value;
    return true;
}

static bool cep_l1_pipeline_stage_external_id(const char* pipeline_id,
                                               const char* stage_id,
                                               char* buffer,
                                               size_t buffer_size) {
    if (!pipeline_id || !stage_id || !buffer || buffer_size == 0u) {
        return false;
    }
    int written = snprintf(buffer, buffer_size, "%s/%s", pipeline_id, stage_id);
    return written > 0 && (size_t)written < buffer_size;
}

static bool cep_l1_pipeline_stage_exists(cepCell* stages, const char* stage_id) {
    if (!stages || !stage_id || !*stage_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&stages)) {
        return false;
    }
    cepDT stage_dt = {0};
    if (!cep_l1_pipeline_make_stage_dt(stage_id, &stage_dt)) {
        return false;
    }
    cepCell* stage = cep_cell_find_by_name(stages, &stage_dt);
    stage = stage ? cep_cell_resolve(stage) : NULL;
    return stage && cep_cell_require_dictionary_store(&stage);
}

/* Create or fetch a pipeline definition branch under `/data/flow/pipelines`,
   wiring the standard children (stages + edges) so callers can fill in DAGs.
   Validation is deliberately deferred; TODO hooks remain for edge/lineage
   checks once the adjacency/closure enzymes land. */
bool cep_l1_pipeline_ensure(cepCell* pipelines_root,
                            const char* pipeline_id,
                            const cepL1PipelineMeta* meta,
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

    cepCell* existing_rev = cep_cell_find_by_name(pipeline, dt_revision_field());
    existing_rev = existing_rev ? cep_cell_resolve(existing_rev) : NULL;
    if (meta) {
        if (meta->version && *meta->version) {
            (void)cep_cell_put_text(pipeline, dt_version_field(), meta->version);
        }
        if (meta->owner && *meta->owner) {
            (void)cep_cell_put_text(pipeline, dt_owner_field_flow(), meta->owner);
        }
        if (meta->province && *meta->province) {
            (void)cep_cell_put_text(pipeline, dt_province_field_flow(), meta->province);
        }
        if (meta->revision > 0u) {
            (void)cep_cell_put_uint64(pipeline, dt_revision_field(), meta->revision);
        } else if (!existing_rev) {
            (void)cep_cell_put_uint64(pipeline, dt_revision_field(), 1u);
        }
    } else if (!existing_rev) {
        (void)cep_cell_put_uint64(pipeline, dt_revision_field(), 1u);
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

    if (layout->pipeline) {
        uint64_t max_hops = 0u;
        if (cep_l1_pipeline_copy_uint64_field(layout->pipeline, dt_max_hops_field_flow(), &max_hops) && max_hops > 0u) {
            if (cep_cell_children(layout->edges) >= max_hops) {
                return false;
            }
        }
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
    cepCell* existing_edge = cep_cell_find_by_name(layout->edges, &edge_dt);
    existing_edge = existing_edge ? cep_cell_resolve(existing_edge) : NULL;
    if (existing_edge) {
        char existing_src[128] = {0};
        char existing_dst[128] = {0};
        (void)cep_l1_pipeline_copy_text_field(existing_edge, dt_source_field(), existing_src, sizeof existing_src);
        (void)cep_l1_pipeline_copy_text_field(existing_edge, dt_target_field(), existing_dst, sizeof existing_dst);
        if (strcmp(existing_src, from_stage) == 0 && strcmp(existing_dst, to_stage) == 0) {
            return true; /* Idempotent add */
        }
        return false; /* Conflicting edge definition */
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

static bool cep_l1_pipeline_validate(cepL1PipelineLayout* layout, const char* pipeline_id) {
    if (!layout || !layout->pipeline || !layout->stages || !layout->edges) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->stages) ||
        !cep_cell_require_dictionary_store(&layout->edges)) {
        return false;
    }

    bool ok = true;

    for (cepCell* stage = cep_cell_first(layout->stages); stage; stage = cep_cell_next(layout->stages, stage)) {
        stage = stage ? cep_cell_resolve(stage) : NULL;
        if (!stage || !cep_cell_require_dictionary_store(&stage)) {
            ok = false;
            continue;
        }
        char stage_buffer[128] = {0};
        if (!cep_l1_pipeline_copy_text_field(stage, dt_stage_id(), stage_buffer, sizeof stage_buffer)) {
            ok = false;
        }
    }

    for (cepCell* edge = cep_cell_first(layout->edges); edge; edge = cep_cell_next(layout->edges, edge)) {
        edge = edge ? cep_cell_resolve(edge) : NULL;
        if (!edge || !cep_cell_require_dictionary_store(&edge)) {
            ok = false;
            continue;
        }
        char source_buffer[128] = {0};
        char target_buffer[128] = {0};
        (void)cep_l1_pipeline_copy_text_field(edge, dt_source_field(), source_buffer, sizeof source_buffer);
        (void)cep_l1_pipeline_copy_text_field(edge, dt_target_field(), target_buffer, sizeof target_buffer);
        if (!source_buffer[0] || !target_buffer[0] || strcmp(source_buffer, target_buffer) == 0) {
            ok = false;
            continue;
        }
        if (!cep_l1_pipeline_stage_exists(layout->stages, source_buffer) ||
            !cep_l1_pipeline_stage_exists(layout->stages, target_buffer)) {
            ok = false;
        }
        if (pipeline_id && *pipeline_id) {
            char pipeline_buffer[128] = {0};
            if (cep_l1_pipeline_copy_text_field(edge, dt_pipeline_id_field(), pipeline_buffer, sizeof pipeline_buffer) &&
                pipeline_buffer[0] && strcmp(pipeline_buffer, pipeline_id) != 0) {
                ok = false;
            }
        }
    }

    if (layout->pipeline) {
        uint64_t max_hops = 0u;
        if (cep_l1_pipeline_copy_uint64_field(layout->pipeline, dt_max_hops_field_flow(), &max_hops) && max_hops > 0u) {
            size_t edge_count = cep_cell_children(layout->edges);
            if (edge_count > max_hops) {
                ok = false;
            }
        }
    }

    return ok;
}

/* Attach pipeline definitions to coherence beings so provenance survives beyond
   the DAG tree. A pipeline being is ensured, owner/province bonds are recorded,
   and all stages/edges inherit that parent so the closure engine can trace
   lineage deterministically. */
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
    if (!cep_l1_pipeline_validate(pipeline, pipeline_buffer)) {
        return false;
    }

    cepCell* pipeline_being = NULL;
    if (!cep_l1_coh_add_being(schema, "pipeline", pipeline_buffer, &pipeline_being)) {
        return false;
    }

    cepCell* parents[] = {pipeline_being};
    (void)cep_cell_add_parents(pipeline->pipeline, parents, 1u);

    char owner_buffer[128] = {0};
    if (cep_l1_pipeline_copy_text_field(pipeline->pipeline, dt_owner_field_flow(), owner_buffer, sizeof owner_buffer) &&
        owner_buffer[0]) {
        cepCell* owner_being = NULL;
        if (cep_l1_coh_add_being(schema, "owner", owner_buffer, &owner_being)) {
            (void)cep_l1_coh_add_bond(schema, "owned_by", "pipeline", pipeline_buffer, "owner", owner_buffer, NULL);
            cepCell* owner_parents[] = {owner_being};
            (void)cep_cell_add_parents(pipeline->pipeline, owner_parents, 1u);
        }
    }

    char province_buffer[128] = {0};
    if (cep_l1_pipeline_copy_text_field(pipeline->pipeline, dt_province_field_flow(), province_buffer, sizeof province_buffer) &&
        province_buffer[0]) {
        cepCell* province_being = NULL;
        if (cep_l1_coh_add_being(schema, "province", province_buffer, &province_being)) {
            (void)cep_l1_coh_add_bond(schema, "in_province", "pipeline", pipeline_buffer, "province", province_buffer, NULL);
            cepCell* province_parents[] = {province_being};
            (void)cep_cell_add_parents(pipeline->pipeline, province_parents, 1u);
        }
    }

    if (pipeline->stages && cep_cell_require_dictionary_store(&pipeline->stages)) {
        for (cepCell* stage = cep_cell_first(pipeline->stages); stage; stage = cep_cell_next(pipeline->stages, stage)) {
            stage = cep_cell_resolve(stage);
            if (!stage) {
                continue;
            }
            (void)cep_cell_add_parents(stage, parents, 1u);

            char stage_id_buffer[128] = {0};
            char stage_ext[256] = {0};
            if (cep_l1_pipeline_copy_text_field(stage, dt_stage_id(), stage_id_buffer, sizeof stage_id_buffer) &&
                stage_id_buffer[0] &&
                cep_l1_pipeline_stage_external_id(pipeline_buffer, stage_id_buffer, stage_ext, sizeof stage_ext)) {
                cepCell* stage_being = NULL;
                if (cep_l1_coh_add_being(schema, "stage", stage_ext, &stage_being)) {
                    (void)cep_l1_coh_add_bond(schema, "has_stage", "pipeline", pipeline_buffer, "stage", stage_ext, NULL);
                    cepCell* stage_parents[] = {stage_being};
                    (void)cep_cell_add_parents(stage, stage_parents, 1u);
                }
            }
        }
    }

    if (pipeline->edges && cep_cell_require_dictionary_store(&pipeline->edges)) {
        for (cepCell* edge = cep_cell_first(pipeline->edges); edge; edge = cep_cell_next(pipeline->edges, edge)) {
            edge = cep_cell_resolve(edge);
            if (!edge) {
                continue;
            }
            (void)cep_cell_add_parents(edge, parents, 1u);

            char source_buffer[128] = {0};
            char target_buffer[128] = {0};
            if (!cep_l1_pipeline_copy_text_field(edge, dt_source_field(), source_buffer, sizeof source_buffer) ||
                !cep_l1_pipeline_copy_text_field(edge, dt_target_field(), target_buffer, sizeof target_buffer)) {
                continue;
            }

            char from_ext[256] = {0};
            char to_ext[256] = {0};
            if (!cep_l1_pipeline_stage_external_id(pipeline_buffer, source_buffer, from_ext, sizeof from_ext) ||
                !cep_l1_pipeline_stage_external_id(pipeline_buffer, target_buffer, to_ext, sizeof to_ext)) {
                continue;
            }

            cepL1CohBinding edge_bindings[3] = {
                {.role = "pipeline", .being_kind = "pipeline", .being_external_id = pipeline_buffer, .bond_id = NULL},
                {.role = "from_stage", .being_kind = "stage", .being_external_id = from_ext, .bond_id = NULL},
                {.role = "to_stage", .being_kind = "stage", .being_external_id = to_ext, .bond_id = NULL},
            };

            char edge_note[160] = {0};
            snprintf(edge_note, sizeof edge_note, "edge %s -> %s", source_buffer, target_buffer);
            (void)cep_l1_coh_add_context(schema, "pipeline_edge", edge_note, edge_bindings, 3u, NULL);
        }
    }

    return true;
}
