/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_runtime.h"

#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_heartbeat.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_state_field_l1,   CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_pipeline_id_field_l1, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_dag_run_id_field_l1,  CEP_ACRO("CEP"), CEP_WORD("dag_run_id"));
CEP_DEFINE_STATIC_DT(dt_stage_id_field_l1,    CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_hop_index_field_l1,   CEP_ACRO("CEP"), CEP_WORD("hop_index"));
CEP_DEFINE_STATIC_DT(dt_stages_name_l1,       CEP_ACRO("CEP"), CEP_WORD("stages"));
CEP_DEFINE_STATIC_DT(dt_annotations_name_l1,  CEP_ACRO("CEP"), CEP_WORD("annotations"));

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

    /* TODO: switch to accumulators once orchestrator defines counter semantics. */
    return cep_cell_put_uint64(pipeline, &metric_dt, value);
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
