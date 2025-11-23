/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_runtime.h"

#include "../l0_kernel/cep_cei.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_security_tags.h"
#include "../enzymes/sec_pipeline.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_state_field_l1,   CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_pipeline_id_field_l1, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_dag_run_id_field_l1,  CEP_ACRO("CEP"), CEP_WORD("dag_run_id"));
CEP_DEFINE_STATIC_DT(dt_stage_id_field_l1,    CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_hop_index_field_l1,   CEP_ACRO("CEP"), CEP_WORD("hop_index"));
CEP_DEFINE_STATIC_DT(dt_stages_name_l1,       CEP_ACRO("CEP"), CEP_WORD("stages"));
CEP_DEFINE_STATIC_DT(dt_annotations_name_l1,  CEP_ACRO("CEP"), CEP_WORD("annotations"));
CEP_DEFINE_STATIC_DT(dt_source_field_l1,      CEP_ACRO("CEP"), CEP_WORD("source"));
CEP_DEFINE_STATIC_DT(dt_target_field_l1,      CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_ready_field_l1,       CEP_ACRO("CEP"), CEP_WORD("ready"));
CEP_DEFINE_STATIC_DT(dt_triggers_name_l1,     CEP_ACRO("CEP"), CEP_WORD("triggers"));
CEP_DEFINE_STATIC_DT(dt_kind_field_l1,        CEP_ACRO("CEP"), CEP_WORD("kind"));
CEP_DEFINE_STATIC_DT(dt_beat_field_l1,        CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_sev_warn_l1,          CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_topic_pipeline_reject, CEP_ACRO("CEP"), cep_namepool_intern_cstr("sec.pipeline.reject"));
CEP_DEFINE_STATIC_DT(dt_fan_in_expected_l1,   CEP_ACRO("CEP"), CEP_WORD("fan_in"));
CEP_DEFINE_STATIC_DT(dt_fan_in_seen_l1,       CEP_ACRO("CEP"), CEP_WORD("fan_seen"));
CEP_DEFINE_STATIC_DT(dt_metrics_name_l1_stage, CEP_ACRO("CEP"), CEP_WORD("metrics"));
CEP_DEFINE_STATIC_DT(dt_edges_name_l1,        CEP_ACRO("CEP"), CEP_WORD("edges"));
CEP_DEFINE_STATIC_DT(dt_pipelines_root_l1,    CEP_ACRO("CEP"), CEP_WORD("pipelines"));
CEP_DEFINE_STATIC_DT(dt_paused_field_l1,      CEP_ACRO("CEP"), CEP_WORD("paused"));
CEP_DEFINE_STATIC_DT(dt_topic_dispatch_blocked, CEP_ACRO("CEP"), cep_namepool_intern_cstr("flow.dispatch.blocked"));
CEP_DEFINE_STATIC_DT(dt_topic_pipeline_missing, CEP_ACRO("CEP"), cep_namepool_intern_cstr("flow.pipeline.missing_metadata"));

static bool cep_l1_runtime_make_run_dt(uint64_t dag_run_id, cepDT* out) {
    if (!out) {
        return false;
    }
    char slug[16];
    int written = snprintf(slug, sizeof slug, "run.%llu", (unsigned long long)dag_run_id);
    if (written <= 0 || (size_t)written >= sizeof slug) {
        return false;
    }
    cepID tag = cep_namepool_intern(slug, (size_t)written);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_runtime_make_stage_dt(const char* stage_id, cepDT* out) {
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

static bool cep_l1_runtime_make_metric_dt(const char* metric_tag, cepDT* out) {
    if (!metric_tag || !out) {
        return false;
    }
    size_t len = strlen(metric_tag);
    if (len == 0u) {
        return false;
    }
    cepID tag = cep_namepool_intern(metric_tag, len);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_runtime_require_dict(cepCell* parent,
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

static bool cep_l1_runtime_copy_text_field(cepCell* parent,
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

static bool cep_l1_runtime_copy_uint64_field(cepCell* parent,
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

static void cep_l1_runtime_emit_run_cei(const cepDT* topic_dt,
                                        const char* note,
                                        cepCell* subject) {
    if (!topic_dt || !cep_dt_is_valid(topic_dt)) {
        return;
    }
    cepCeiRequest req = {
        .severity = *dt_sev_warn_l1(),
        .topic = cep_namepool_lookup(topic_dt->tag, NULL),
        .topic_len = 0u,
        .note = note,
        .subject = subject,
        .emit_signal = false,
    };
    (void)cep_cei_emit(&req);
}

static bool cep_l1_runtime_make_pipeline_dt(const char* pipeline_id, cepDT* out) {
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

static cepCell* cep_l1_runtime_find_pipelines_root(cepCell* runs_root) {
    for (cepCell* current = runs_root; current; current = cep_cell_parent(current)) {
        cepCell* pipelines = cep_cell_find_by_name(current, dt_pipelines_root_l1());
        pipelines = pipelines ? cep_cell_resolve(pipelines) : NULL;
        if (pipelines && cep_cell_require_dictionary_store(&pipelines)) {
            return pipelines;
        }
    }
    return NULL;
}

static bool cep_l1_runtime_resolve_stage(cepCell* run_root,
                                         const char* stage_id,
                                         cepCell** stage_out) {
    if (!run_root || !stage_id || !stage_out) {
        return false;
    }

    cepCell* stages = cep_cell_find_by_name(run_root, dt_stages_name_l1());
    stages = stages ? cep_cell_resolve(stages) : NULL;
    if (!stages || !cep_cell_require_dictionary_store(&stages)) {
        return false;
    }

    cepDT stage_dt = {0};
    if (!cep_l1_runtime_make_stage_dt(stage_id, &stage_dt)) {
        return false;
    }

    cepCell* stage = cep_cell_ensure_dictionary_child(stages, &stage_dt, CEP_STORAGE_RED_BLACK_T);
    stage = stage ? cep_cell_resolve(stage) : NULL;
    if (!stage || !cep_cell_require_dictionary_store(&stage)) {
        return false;
    }

    *stage_out = stage;
    return true;
}

static bool cep_l1_runtime_stage_ready(cepCell* stage, bool* out_ready) {
    if (!stage || !out_ready) {
        return false;
    }
    cepCell* ready = cep_cell_find_by_name(stage, dt_ready_field_l1());
    ready = ready ? cep_cell_resolve(ready) : NULL;
    if (!ready) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&ready, &data) || !data || data->size == 0u) {
        return false;
    }
    const unsigned char* bytes = (const unsigned char*)cep_data_payload(data);
    if (!bytes) {
        return false;
    }
    *out_ready = bytes[0] != 0u;
    return true;
}

static bool cep_l1_runtime_seed_fan_in_from_edges(cepCell* run_root) {
    if (!run_root) {
        return false;
    }
    cepCell* stages = cep_cell_find_by_name(run_root, dt_stages_name_l1());
    cepCell* edges = cep_cell_find_by_name(run_root, dt_edges_name_l1());
    stages = stages ? cep_cell_resolve(stages) : NULL;
    edges = edges ? cep_cell_resolve(edges) : NULL;
    if (!stages || !edges) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&stages) ||
        !cep_cell_require_dictionary_store(&edges)) {
        return false;
    }

    if (cep_cell_children(edges) == 0u) {
        for (cepCell* stage = cep_cell_first(stages); stage; stage = cep_cell_next(stages, stage)) {
            stage = stage ? cep_cell_resolve(stage) : NULL;
            if (!stage || !cep_cell_require_dictionary_store(&stage)) {
                continue;
            }
            (void)cep_cell_put_uint64(stage, dt_ready_field_l1(), 1u);
        }
        return true;
    }

    for (cepCell* stage = cep_cell_first(stages); stage; stage = cep_cell_next(stages, stage)) {
        stage = stage ? cep_cell_resolve(stage) : NULL;
        if (!stage || !cep_cell_require_dictionary_store(&stage)) {
            continue;
        }
        (void)cep_cell_put_uint64(stage, dt_fan_in_expected_l1(), 0u);
        (void)cep_cell_put_uint64(stage, dt_fan_in_seen_l1(), 0u);
        (void)cep_cell_put_uint64(stage, dt_ready_field_l1(), 0u);
    }

    for (cepCell* edge = cep_cell_first(edges); edge; edge = cep_cell_next(edges, edge)) {
        edge = edge ? cep_cell_resolve(edge) : NULL;
        if (!edge || !cep_cell_require_dictionary_store(&edge)) {
            continue;
        }
        char target_buffer[128] = {0};
        if (!cep_l1_runtime_copy_text_field(edge, dt_target_field_l1(), target_buffer, sizeof target_buffer) ||
            !target_buffer[0]) {
            continue;
        }
        cepCell* target_stage = NULL;
        if (!cep_l1_runtime_resolve_stage(run_root, target_buffer, &target_stage)) {
            continue;
        }
        uint64_t expected = 0u;
        (void)cep_l1_runtime_copy_uint64_field(target_stage, dt_fan_in_expected_l1(), &expected);
        ++expected;
        (void)cep_cell_put_uint64(target_stage, dt_fan_in_expected_l1(), expected);
        (void)cep_cell_put_uint64(target_stage, dt_ready_field_l1(), 0u);
    }

    for (cepCell* stage = cep_cell_first(stages); stage; stage = cep_cell_next(stages, stage)) {
        stage = stage ? cep_cell_resolve(stage) : NULL;
        if (!stage || !cep_cell_require_dictionary_store(&stage)) {
            continue;
        }
        uint64_t expected = 0u;
        (void)cep_l1_runtime_copy_uint64_field(stage, dt_fan_in_expected_l1(), &expected);
        if (expected == 0u) {
            (void)cep_cell_put_uint64(stage, dt_ready_field_l1(), 1u);
        }
    }

    return true;
}

static bool cep_l1_runtime_seed_pipeline_shape(cepCell* run_root,
                                               const char* pipeline_id) {
    if (!run_root || !pipeline_id || !*pipeline_id) {
        return true;
    }

    cepCell* edges = cep_cell_ensure_dictionary_child(run_root, dt_edges_name_l1(), CEP_STORAGE_RED_BLACK_T);
    edges = edges ? cep_cell_resolve(edges) : NULL;
    if (!edges || !cep_cell_require_dictionary_store(&edges)) {
        return false;
    }
    if (cep_cell_children(edges) > 0u) {
        return true; /* already mirrored; avoid clobbering runtime state */
    }

    cepCell* pipelines_root = cep_l1_runtime_find_pipelines_root(run_root);
    if (!pipelines_root) {
        return true;
    }

    cepDT pipeline_dt = {0};
    if (!cep_l1_runtime_make_pipeline_dt(pipeline_id, &pipeline_dt)) {
        return true;
    }

    cepCell* pipeline = cep_cell_find_by_name(pipelines_root, &pipeline_dt);
    pipeline = pipeline ? cep_cell_resolve(pipeline) : NULL;
    if (!pipeline || !cep_cell_require_dictionary_store(&pipeline)) {
        return true;
    }

    cepCell* stage_defs = cep_cell_find_by_name(pipeline, dt_stages_name_l1());
    stage_defs = stage_defs ? cep_cell_resolve(stage_defs) : NULL;
    if (stage_defs && cep_cell_require_dictionary_store(&stage_defs)) {
        for (cepCell* stage = cep_cell_first(stage_defs); stage; stage = cep_cell_next(stage_defs, stage)) {
            stage = stage ? cep_cell_resolve(stage) : NULL;
            if (!stage) {
                continue;
            }
            char stage_id_buffer[128] = {0};
            if (cep_l1_runtime_copy_text_field(stage, dt_stage_id_field_l1(), stage_id_buffer, sizeof stage_id_buffer) &&
                stage_id_buffer[0]) {
                (void)cep_l1_runtime_resolve_stage(run_root, stage_id_buffer, NULL);
            }
        }
    }

    cepCell* edge_defs = cep_cell_find_by_name(pipeline, dt_edges_name_l1());
    edge_defs = edge_defs ? cep_cell_resolve(edge_defs) : NULL;
    if (edge_defs && cep_cell_require_dictionary_store(&edge_defs)) {
        for (cepCell* edge = cep_cell_first(edge_defs); edge; edge = cep_cell_next(edge_defs, edge)) {
            edge = edge ? cep_cell_resolve(edge) : NULL;
            if (!edge || !cep_cell_require_dictionary_store(&edge)) {
                continue;
            }
            const cepDT* edge_name = cep_cell_get_name(edge);
            cepCell* run_edge = cep_cell_ensure_dictionary_child(edges, edge_name, CEP_STORAGE_RED_BLACK_T);
            run_edge = run_edge ? cep_cell_resolve(run_edge) : NULL;
            if (!run_edge || !cep_cell_require_dictionary_store(&run_edge)) {
                continue;
            }

            char source_buffer[128] = {0};
            char target_buffer[128] = {0};
            (void)cep_l1_runtime_copy_text_field(edge, dt_source_field_l1(), source_buffer, sizeof source_buffer);
            (void)cep_l1_runtime_copy_text_field(edge, dt_target_field_l1(), target_buffer, sizeof target_buffer);

            if (source_buffer[0]) {
                (void)cep_cell_put_text(run_edge, dt_source_field_l1(), source_buffer);
                (void)cep_l1_runtime_resolve_stage(run_root, source_buffer, NULL);
            }
            if (target_buffer[0]) {
                (void)cep_cell_put_text(run_edge, dt_target_field_l1(), target_buffer);
                (void)cep_l1_runtime_resolve_stage(run_root, target_buffer, NULL);
            }
        }
    }

    (void)cep_l1_runtime_seed_fan_in_from_edges(run_root);
    return true;
}

static void cep_l1_runtime_fan_out_edges(cepCell* run_root,
                                         const char* stage_id,
                                         const cepPipelineMetadata* meta) {
    if (!run_root || !stage_id || !meta) {
        return;
    }

    cepCell* edges = cep_cell_find_by_name(run_root, dt_edges_name_l1());
    edges = edges ? cep_cell_resolve(edges) : NULL;
    if (!edges || !cep_cell_require_dictionary_store(&edges)) {
        return;
    }

    uint64_t dispatch_beat = (uint64_t)cep_heartbeat_current();
    for (cepCell* edge = cep_cell_first(edges); edge; edge = cep_cell_next(edges, edge)) {
        edge = edge ? cep_cell_resolve(edge) : NULL;
        if (!edge || !cep_cell_require_dictionary_store(&edge)) {
            continue;
        }
        char source_buffer[128] = {0};
        char target_buffer[128] = {0};
        if (!cep_l1_runtime_copy_text_field(edge, dt_source_field_l1(), source_buffer, sizeof source_buffer) ||
            !source_buffer[0] ||
            strcmp(source_buffer, stage_id) != 0) {
            continue;
        }
        if (!cep_l1_runtime_copy_text_field(edge, dt_target_field_l1(), target_buffer, sizeof target_buffer) ||
            !target_buffer[0]) {
            continue;
        }

        cepCell* target_stage = NULL;
        if (!cep_l1_runtime_resolve_stage(run_root, target_buffer, &target_stage)) {
            continue;
        }

        if (meta->hop_index > 0u) {
            uint64_t next_hop = meta->hop_index + 1u;
            uint64_t existing_hop = 0u;
            (void)cep_l1_runtime_copy_uint64_field(target_stage, dt_hop_index_field_l1(), &existing_hop);
            if (existing_hop < next_hop) {
                (void)cep_cell_put_uint64(target_stage, dt_hop_index_field_l1(), next_hop);
            }
        }

        (void)cep_l1_runtime_record_trigger(run_root, target_buffer, "fan_out", NULL, dispatch_beat);
    }
}

/* Record or update a pipeline run entry under `/data/flow/runtime/runs`,
   capturing the pipeline ID, DAG run identifier, and current run state. This
   scaffolding only records metadata; orchestrator state machines will extend it
   with budgets, stage timelines, and CEI hooks in later tasks. */
bool cep_l1_runtime_record_run(cepCell* runs_root,
                               const char* pipeline_id,
                               uint64_t dag_run_id,
                               const char* state_tag,
                               const cepPipelineMetadata* metadata,
                               cepCell** run_out) {
    if (!runs_root || !pipeline_id || !state_tag) {
        return false;
    }

    cepDT run_dt = {0};
    if (!cep_l1_runtime_make_run_dt(dag_run_id, &run_dt)) {
        return false;
    }

    cepCell* run = cep_cell_ensure_dictionary_child(runs_root, &run_dt, CEP_STORAGE_RED_BLACK_T);
    run = run ? cep_cell_resolve(run) : NULL;
    if (!run || !cep_cell_require_dictionary_store(&run)) {
        return false;
    }

    if (metadata && metadata->pipeline_id) {
        cepDT pipeline_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = metadata->pipeline_id};
        if (!cep_cell_put_dt(run, dt_pipeline_id_field_l1(), &pipeline_dt)) {
            return false;
        }
        const char* pipeline_text = cep_namepool_lookup(metadata->pipeline_id, NULL);
        if (pipeline_text && *pipeline_text) {
            pipeline_id = pipeline_text;
        }
    } else {
        if (!cep_cell_put_text(run, dt_pipeline_id_field_l1(), pipeline_id)) {
            return false;
        }
    }
    if (!cep_cell_put_uint64(run, dt_dag_run_id_field_l1(), dag_run_id)) {
        return false;
    }

    cepDT state_dt = {0};
    if (!cep_l1_runtime_make_stage_dt(state_tag, &state_dt)) {
        return false;
    }
    if (!cep_cell_put_dt(run, dt_state_field_l1(), &state_dt)) {
        return false;
    }

    if (metadata) {
        if (metadata->stage_id) {
            cepDT stage_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = metadata->stage_id};
            (void)cep_cell_put_dt(run, dt_stage_id_field_l1(), &stage_dt);
        }
        (void)cep_cell_put_uint64(run, dt_hop_index_field_l1(), metadata->hop_index);
    }

    cepCell* stages = NULL;
    if (!cep_l1_runtime_require_dict(run, dt_stages_name_l1(), &stages)) {
        return false;
    }

    cepCell* edges = NULL;
    if (!cep_l1_runtime_require_dict(run, dt_edges_name_l1(), &edges)) {
        return false;
    }

    if (pipeline_id && *pipeline_id) {
        (void)cep_l1_runtime_seed_pipeline_shape(run, pipeline_id);
    }

    /* TODO: emit pipeline-aware impulses once orchestrator wiring lands. */
    /* TODO: attach metrics/annotations to the run as stage results accumulate. */

    if (run_out) {
        *run_out = run;
    }
    return true;
}

/* Record the latest state for a pipeline stage within a run so replay and
   metrics can surface per-stage outcomes. Validation against the declared DAG
   is deferred to the upcoming edge checker. */
bool cep_l1_runtime_record_stage_state(cepCell* run_root,
                                       const char* stage_id,
                                       const char* state_tag,
                                       uint64_t hop_index) {
    if (!run_root || !stage_id || !state_tag) {
        return false;
    }

    cepCell* stage = NULL;
    if (!cep_l1_runtime_resolve_stage(run_root, stage_id, &stage)) {
        return false;
    }

    cepDT state_dt = {0};
    if (!cep_l1_runtime_make_stage_dt(state_tag, &state_dt)) {
        return false;
    }
    if (!cep_cell_put_dt(stage, dt_state_field_l1(), &state_dt)) {
        return false;
    }
    (void)cep_cell_put_uint64(stage, dt_hop_index_field_l1(), hop_index);

    /* TODO: surface per-stage metrics + annotations as the orchestrator advances. */
    return true;
}

/* Mark a stage as ready for execution (fan-in resolved) so orchestrators can
   gate downstream dispatch. This is a light-weight flag; fan-out remains the
   caller's responsibility. */
bool cep_l1_runtime_mark_stage_ready(cepCell* run_root,
                                     const char* stage_id,
                                     bool ready) {
    if (!run_root || !stage_id) {
        return false;
    }

    cepCell* stage = NULL;
    if (!cep_l1_runtime_resolve_stage(run_root, stage_id, &stage)) {
        return false;
    }

    return cep_cell_put_uint64(stage, dt_ready_field_l1(), ready ? 1u : 0u);
}

/* Record a trigger (event/label/schedule) against a stage so downstream
   orchestrator logic can evaluate readiness/fan-in. Triggers are append-only
   list entries tagged with kind and beat. */
bool cep_l1_runtime_record_trigger(cepCell* run_root,
                                   const char* stage_id,
                                   const char* trigger_kind,
                                   const char* note,
                                   uint64_t beat) {
    if (!run_root || !stage_id || !trigger_kind) {
        return false;
    }

    cepCell* stage = NULL;
    if (!cep_l1_runtime_resolve_stage(run_root, stage_id, &stage)) {
        return false;
    }

    cepCell* triggers = cep_cell_ensure_dictionary_child(stage, dt_triggers_name_l1(), CEP_STORAGE_RED_BLACK_T);
    triggers = triggers ? cep_cell_resolve(triggers) : NULL;
    if (!triggers || !cep_cell_require_dictionary_store(&triggers)) {
        return false;
    }

    char trig_name[16] = {0};
    size_t seq = cep_cell_children(triggers);
    snprintf(trig_name, sizeof trig_name, "tr%04zu", seq + 1u);
    cepDT trig_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern(trig_name, strlen(trig_name))};

    cepCell* entry = cep_cell_ensure_dictionary_child(triggers, &trig_dt, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    (void)cep_cell_put_text(entry, dt_kind_field_l1(), trigger_kind);
    (void)cep_cell_put_uint64(entry, dt_beat_field_l1(), beat);
    if (note && *note) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "note"), note);
    }

    uint64_t expected = 0u;
    uint64_t seen = 0u;
    (void)cep_l1_runtime_copy_uint64_field(stage, dt_fan_in_expected_l1(), &expected);
    (void)cep_l1_runtime_copy_uint64_field(stage, dt_fan_in_seen_l1(), &seen);
    ++seen;
    (void)cep_cell_put_uint64(stage, dt_fan_in_seen_l1(), seen);
    if (expected == 0u || seen >= expected) {
        (void)cep_cell_put_uint64(stage, dt_ready_field_l1(), 1u);
    }

    return true;
}

/* Configure the expected fan-in for a stage and reset readiness counters so the
   orchestrator can gate downstream work deterministically. A zero expectation
   marks the stage ready immediately. */
bool cep_l1_runtime_configure_stage_fanin(cepCell* run_root,
                                          const char* stage_id,
                                          uint64_t expected) {
    cepCell* stage = NULL;
    if (!cep_l1_runtime_resolve_stage(run_root, stage_id, &stage)) {
        return false;
    }
    (void)cep_cell_put_uint64(stage, dt_fan_in_expected_l1(), expected);
    (void)cep_cell_put_uint64(stage, dt_fan_in_seen_l1(), 0u);
    (void)cep_cell_put_uint64(stage, dt_ready_field_l1(), expected == 0u ? 1u : 0u);
    return true;
}

/* Record a metric value under `/data/flow/metrics/<pipeline>/<metric_tag>`.
   This placeholder writes the latest value; accumulation will be added once
   the orchestrator defines counter semantics. */
bool cep_l1_runtime_record_metric(cepCell* metrics_root,
                                  const char* pipeline_id,
                                  const char* metric_tag,
                                  uint64_t value) {
    if (!metrics_root || !pipeline_id || !metric_tag) {
        return false;
    }

    cepDT pipeline_dt = {0};
    if (!cep_l1_runtime_make_stage_dt(pipeline_id, &pipeline_dt)) {
        return false;
    }

    cepCell* pipeline = cep_cell_ensure_dictionary_child(metrics_root, &pipeline_dt, CEP_STORAGE_RED_BLACK_T);
    pipeline = pipeline ? cep_cell_resolve(pipeline) : NULL;
    if (!pipeline || !cep_cell_require_dictionary_store(&pipeline)) {
        return false;
    }

    cepDT metric_dt = {0};
    if (!cep_l1_runtime_make_metric_dt(metric_tag, &metric_dt)) {
        return false;
    }

    uint64_t current = 0u;
    (void)cep_l1_runtime_copy_uint64_field(pipeline, &metric_dt, &current);
    uint64_t next = current + value;
    if (next < current) {
        next = UINT64_MAX;
    }
    return cep_cell_put_uint64(pipeline, &metric_dt, next);
}

/* Append a freeform annotation under `/data/flow/annotations/<pipeline>`.
   Stored as the latest note for now; later work can switch to append-only logs
   keyed by beat/author. */
bool cep_l1_runtime_add_annotation(cepCell* annotations_root,
                                   const char* pipeline_id,
                                   const char* note) {
    if (!annotations_root || !pipeline_id || !note) {
        return false;
    }

    cepDT pipeline_dt = {0};
    if (!cep_l1_runtime_make_stage_dt(pipeline_id, &pipeline_dt)) {
        return false;
    }

    cepCell* pipeline = cep_cell_ensure_dictionary_child(annotations_root, &pipeline_dt, CEP_STORAGE_RED_BLACK_T);
    pipeline = pipeline ? cep_cell_resolve(pipeline) : NULL;
    if (!pipeline || !cep_cell_require_dictionary_store(&pipeline)) {
        return false;
    }

    cepDT annotations_name = *dt_annotations_name_l1();
    cepCell* entries = cep_cell_ensure_list_child(pipeline, &annotations_name, CEP_STORAGE_LINKED_LIST);
    entries = entries ? cep_cell_resolve(entries) : NULL;
    if (!entries || !cep_cell_require_store(&entries, NULL)) {
        return false;
    }

    cepCell* entry = cep_cell_add_value(entries,
                                        &annotations_name,
                                        0,
                                        CEP_DTAW("CEP", "text"),
                                        (void*)note,
                                        strlen(note) + 1u,
                                        strlen(note) + 1u);
    return entry != NULL;
}

/* Attach a metric to a specific stage inside a run so per-stage health can be
   surfaced without scanning the whole pipeline metrics tree. */
bool cep_l1_runtime_record_stage_metric(cepCell* run_root,
                                        const char* stage_id,
                                        const char* metric_tag,
                                        uint64_t value) {
    if (!run_root || !stage_id || !metric_tag) {
        return false;
    }

    cepCell* stage = NULL;
    if (!cep_l1_runtime_resolve_stage(run_root, stage_id, &stage)) {
        return false;
    }

    cepCell* metrics = cep_cell_ensure_dictionary_child(stage, dt_metrics_name_l1_stage(), CEP_STORAGE_RED_BLACK_T);
    metrics = metrics ? cep_cell_resolve(metrics) : NULL;
    if (!metrics || !cep_cell_require_dictionary_store(&metrics)) {
        return false;
    }

    cepDT metric_dt = {0};
    if (!cep_l1_runtime_make_metric_dt(metric_tag, &metric_dt)) {
        return false;
    }

    uint64_t current = 0u;
    (void)cep_l1_runtime_copy_uint64_field(metrics, &metric_dt, &current);
    uint64_t next = current + value;
    if (next < current) {
        next = UINT64_MAX;
    }

    return cep_cell_put_uint64(metrics, &metric_dt, next);
}

/* Append an annotation directly to a stage entry so orchestrators can track
   fan-in/fan-out breadcrumbs alongside triggers. */
bool cep_l1_runtime_add_stage_annotation(cepCell* run_root,
                                         const char* stage_id,
                                         const char* note) {
    if (!run_root || !stage_id || !note) {
        return false;
    }

    cepCell* stage = NULL;
    if (!cep_l1_runtime_resolve_stage(run_root, stage_id, &stage)) {
        return false;
    }

    cepCell* annotations = cep_cell_ensure_list_child(stage, dt_annotations_name_l1(), CEP_STORAGE_LINKED_LIST);
    annotations = annotations ? cep_cell_resolve(annotations) : NULL;
    if (!annotations || !cep_cell_require_store(&annotations, NULL)) {
        return false;
    }

    cepDT annotations_name = *dt_annotations_name_l1();
    cepCell* entry = cep_cell_add_value(annotations,
                                        &annotations_name,
                                        0,
                                        CEP_DTAW("CEP", "text"),
                                        (void*)note,
                                        strlen(note) + 1u,
                                        strlen(note) + 1u);
    return entry != NULL;
}

/* Emit a pipeline-aware impulse for a ready stage, guarding against paused
   runtimes and filling metadata from the recorded run when callers do not
   supply a metadata block. Marks the stage as not ready once dispatched. */
bool cep_l1_runtime_dispatch_if_ready(cepCell* run_root,
                                      const char* stage_id,
                                      const cepPath* signal,
                                      const cepPath* target,
                                      const cepPipelineMetadata* metadata,
                                      cepImpulseQoS qos) {
    if (!run_root || !stage_id || !signal || !target) {
        return false;
    }

    cepCell* stage = NULL;
    if (!cep_l1_runtime_resolve_stage(run_root, stage_id, &stage)) {
        return false;
    }

    if (cep_runtime_is_paused()) {
        (void)cep_cell_put_uint64(run_root, dt_paused_field_l1(), 1u);
        cep_l1_runtime_emit_run_cei(dt_topic_dispatch_blocked(),
                                    "dispatch blocked: runtime paused or rollback gating active",
                                    stage);
        return false;
    }

    bool ready = false;
    if (!cep_l1_runtime_stage_ready(stage, &ready) || !ready) {
        return false;
    }

    char pipeline_buffer[128] = {0};
    (void)cep_l1_runtime_copy_text_field(run_root, dt_pipeline_id_field_l1(), pipeline_buffer, sizeof pipeline_buffer);

    cepPipelineMetadata meta = {0};
    if (metadata) {
        meta = *metadata;
    }
    if (!meta.pipeline_id && pipeline_buffer[0]) {
        meta.pipeline_id = cep_namepool_intern_cstr(pipeline_buffer);
    }
    if (!meta.stage_id) {
        meta.stage_id = cep_namepool_intern_cstr(stage_id);
    }
    if (meta.dag_run_id == 0u) {
        uint64_t dag_run_id = 0u;
        (void)cep_l1_runtime_copy_uint64_field(run_root, dt_dag_run_id_field_l1(), &dag_run_id);
        meta.dag_run_id = dag_run_id;
    }
    if (meta.hop_index == 0u) {
        uint64_t hop_index = 0u;
        (void)cep_l1_runtime_copy_uint64_field(stage, dt_hop_index_field_l1(), &hop_index);
        meta.hop_index = hop_index;
    }

    const char* pipeline_text = pipeline_buffer;
    if (!pipeline_text || !*pipeline_text) {
        pipeline_text = cep_namepool_lookup(meta.pipeline_id, NULL);
    }
    if (!pipeline_text || !*pipeline_text) {
        cep_l1_runtime_emit_run_cei(dt_topic_pipeline_missing(),
                                    "dispatch blocked: missing pipeline metadata",
                                    stage);
        return false;
    }

    bool dispatched = cep_l1_runtime_emit_impulse(signal,
                                                  target,
                                                  pipeline_text,
                                                  stage_id,
                                                  meta.dag_run_id,
                                                  meta.hop_index,
                                                  qos);
    if (dispatched) {
        (void)cep_cell_put_uint64(stage, dt_ready_field_l1(), 0u);
        cep_l1_runtime_fan_out_edges(run_root, stage_id, &meta);
    }
    return dispatched;
}

/* Emit a pipeline-aware impulse so orchestrators and validators can rely on the
   L0 metadata contract without rehydrating pipeline definitions. Callers supply
   signal/target paths; this helper only decorates the impulse with metadata. */
bool cep_l1_runtime_emit_impulse(const cepPath* signal,
                                 const cepPath* target,
                                 const char* pipeline_id,
                                 const char* stage_id,
                                 uint64_t dag_run_id,
                                 uint64_t hop_index,
                                 cepImpulseQoS qos) {
    if (!signal || !target || !pipeline_id) {
        return false;
    }

    cepPipelineMetadata meta = {0};
    meta.pipeline_id = cep_namepool_intern_cstr(pipeline_id);
    if (!meta.pipeline_id) {
        return false;
    }
    if (stage_id && *stage_id) {
        meta.stage_id = cep_namepool_intern_cstr(stage_id);
        if (!meta.stage_id) {
            return false;
        }
    }
    meta.dag_run_id = dag_run_id;
    meta.hop_index = hop_index;

    cepImpulse impulse = {
        .signal_path = signal,
        .target_path = target,
        .qos = qos,
        .has_pipeline = true,
        .pipeline = meta,
    };

    return cep_heartbeat_enqueue_impulse(cep_heartbeat_current(), &impulse) == CEP_ENZYME_SUCCESS;
}

static void cep_l1_runtime_emit_pipeline_reject_cei(const char* note) {
    cepCeiRequest cei = {
        .severity = *dt_sev_warn_l1(),
        .topic = cep_namepool_lookup(dt_topic_pipeline_reject()->tag, NULL),
        .topic_len = 0u,
        .note = note,
        .emit_signal = false,
    };
    (void)cep_cei_emit(&cei);
}

/* Prepare a federation invoke request cell with pipeline metadata so preflight
   can see the pipeline/stage/run context. */
bool cep_l1_fed_prepare_request(cepCell* request_cell,
                                const cepPipelineMetadata* metadata) {
    if (!request_cell || !metadata) {
        return false;
    }
    if (!metadata->pipeline_id) {
        cep_l1_runtime_emit_pipeline_reject_cei("missing pipeline metadata for invoke request");
        return false;
    }
    request_cell = cep_cell_resolve(request_cell);
    if (!request_cell || !cep_cell_require_dictionary_store(&request_cell)) {
        return false;
    }

    cepCell* pipeline = cep_cell_ensure_dictionary_child(request_cell, dt_pipeline_envelope_field(), CEP_STORAGE_RED_BLACK_T);
    pipeline = pipeline ? cep_cell_resolve(pipeline) : NULL;
    if (!pipeline || !cep_cell_require_dictionary_store(&pipeline)) {
        return false;
    }

    const char* pipeline_text = cep_namepool_lookup(metadata->pipeline_id, NULL);
    if (!pipeline_text || !*pipeline_text) {
        cep_l1_runtime_emit_pipeline_reject_cei("pipeline id could not be interned for invoke request");
        return false;
    }

    if (metadata->pipeline_id) {
        (void)cep_cell_put_text(pipeline, dt_sec_pipeline_id_field(), pipeline_text);
    }
    if (metadata->stage_id) {
        const char* text = cep_namepool_lookup(metadata->stage_id, NULL);
        if (!text || !*text) {
            cep_l1_runtime_emit_pipeline_reject_cei("stage id could not be interned for invoke request");
            return false;
        }
        (void)cep_cell_put_text(pipeline, dt_sec_stage_id_field(), text);
    }
    if (metadata->dag_run_id) {
        (void)cep_cell_put_uint64(pipeline, dt_pipeline_run_field(), metadata->dag_run_id);
    }
    if (metadata->hop_index) {
        (void)cep_cell_put_uint64(pipeline, dt_pipeline_hop_field(), metadata->hop_index);
    }
    return true;
}

/* Submit a federation invoke request while attaching pipeline metadata and
   emitting CEI on preflight or submission failures. */
bool cep_l1_fed_request_submit(const cepFedInvokeRequest* request,
                               cepCell* request_cell,
                               const cepPipelineMetadata* metadata,
                               const cepFedInvokeSubmission* submission) {
    if (!request || !submission) {
        return false;
    }

    if (!metadata || !metadata->pipeline_id) {
        cep_l1_runtime_emit_pipeline_reject_cei("missing pipeline metadata for invoke submit");
        return false;
    }

    if (request_cell && metadata) {
        if (!cep_l1_fed_prepare_request(request_cell, metadata)) {
            return false;
        }
    }

    if (submission->target_path) {
        int rc = cep_sec_pipeline_run_preflight(submission->target_path);
        if (rc != CEP_ENZYME_SUCCESS) {
            cep_l1_runtime_emit_pipeline_reject_cei("pipeline preflight rejected invoke");
            return false;
        }
    }

    if (!cep_fed_invoke_request_submit(request, submission)) {
        cep_l1_runtime_emit_pipeline_reject_cei("federation invoke submit failed");
        return false;
    }

    return true;
}

/* Attach pipeline metadata to a link or mirror mount so federation traffic
   carries context for security preflight and diagnostics. Emits CEI when
   metadata is missing or cannot be interned. */
bool cep_l1_fed_mount_attach_pipeline(cepFedTransportManagerMount* mount,
                                      const cepPipelineMetadata* metadata) {
    if (!mount || !metadata || !metadata->pipeline_id) {
        cep_l1_runtime_emit_pipeline_reject_cei("missing pipeline metadata for mount");
        return false;
    }

    const char* pipeline_text = cep_namepool_lookup(metadata->pipeline_id, NULL);
    const char* stage_text = metadata->stage_id ? cep_namepool_lookup(metadata->stage_id, NULL) : NULL;
    if (!pipeline_text || !*pipeline_text) {
        cep_l1_runtime_emit_pipeline_reject_cei("pipeline id could not be interned for mount");
        return false;
    }
    if (metadata->stage_id && (!stage_text || !*stage_text)) {
        cep_l1_runtime_emit_pipeline_reject_cei("stage id could not be interned for mount");
        return false;
    }

    cep_fed_transport_manager_mount_set_pipeline_metadata(mount,
                                                          pipeline_text,
                                                          stage_text,
                                                          metadata->dag_run_id,
                                                          metadata->hop_index);
    return true;
}
