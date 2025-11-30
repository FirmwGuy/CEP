/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_runtime.h"

#include "../l0_kernel/cep_organ.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_branch_controller.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l1_coherence/cep_l1_runtime.h"
#include "../l1_coherence/cep_l1_coherence.h"
#include "cep_l2_flow.h"
#include "cep_l2_focus.h"
#include "cep_l2_playbook.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_org_eco_root_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root"));
CEP_DEFINE_STATIC_DT(dt_org_eco_root_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root:vl"));
CEP_DEFINE_STATIC_DT(dt_org_eco_root_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root:ct"));
CEP_DEFINE_STATIC_DT(dt_org_eco_root_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root:dt"));

CEP_DEFINE_STATIC_DT(dt_org_eco_flows_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows"));
CEP_DEFINE_STATIC_DT(dt_org_eco_flows_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows:vl"));
CEP_DEFINE_STATIC_DT(dt_org_eco_flows_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows:ct"));
CEP_DEFINE_STATIC_DT(dt_org_eco_flows_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows:dt"));

CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime"));
CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime:vl"));
CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime:ct"));
CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime:dt"));

CEP_DEFINE_STATIC_DT(dt_org_signal_field_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_signal_field"));
CEP_DEFINE_STATIC_DT(dt_org_signal_field_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_signal_field:vl"));
CEP_DEFINE_STATIC_DT(dt_org_signal_field_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_signal_field:ct"));
CEP_DEFINE_STATIC_DT(dt_org_signal_field_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_signal_field:dt"));

CEP_DEFINE_STATIC_DT(dt_org_playbooks_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_playbooks"));
CEP_DEFINE_STATIC_DT(dt_org_playbooks_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_playbooks:vl"));
CEP_DEFINE_STATIC_DT(dt_org_playbooks_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_playbooks:ct"));
CEP_DEFINE_STATIC_DT(dt_org_playbooks_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_playbooks:dt"));

CEP_DEFINE_STATIC_DT(dt_org_modes_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_modes"));
CEP_DEFINE_STATIC_DT(dt_org_modes_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_modes:vl"));
CEP_DEFINE_STATIC_DT(dt_org_modes_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_modes:ct"));
CEP_DEFINE_STATIC_DT(dt_org_modes_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_modes:dt"));

CEP_DEFINE_STATIC_DT(dt_org_learn_models_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models"));
CEP_DEFINE_STATIC_DT(dt_org_learn_models_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models:vl"));
CEP_DEFINE_STATIC_DT(dt_org_learn_models_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models:ct"));
CEP_DEFINE_STATIC_DT(dt_org_learn_models_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models:dt"));

CEP_DEFINE_STATIC_DT(dt_runtime_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_runtime_organisms, CEP_ACRO("CEP"), cep_namepool_intern_cstr("organisms"));
CEP_DEFINE_STATIC_DT(dt_runtime_metrics, CEP_ACRO("CEP"), cep_namepool_intern_cstr("metrics"));
CEP_DEFINE_STATIC_DT(dt_runtime_decisions, CEP_ACRO("CEP"), cep_namepool_intern_cstr("decisions"));
CEP_DEFINE_STATIC_DT(dt_runtime_sched, CEP_ACRO("CEP"), cep_namepool_intern_cstr("sched_queue"));
CEP_DEFINE_STATIC_DT(dt_runtime_history, CEP_ACRO("CEP"), cep_namepool_intern_cstr("history"));
CEP_DEFINE_STATIC_DT(dt_runtime_signal_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("signal_field"));
CEP_DEFINE_STATIC_DT(dt_runtime_playbooks, CEP_ACRO("CEP"), cep_namepool_intern_cstr("playbooks"));
CEP_DEFINE_STATIC_DT(dt_runtime_modes, CEP_ACRO("CEP"), cep_namepool_intern_cstr("modes"));
CEP_DEFINE_STATIC_DT(dt_signal_field_current, CEP_ACRO("CEP"), cep_namepool_intern_cstr("current"));
CEP_DEFINE_STATIC_DT(dt_signal_field_history, CEP_ACRO("CEP"), cep_namepool_intern_cstr("history"));
CEP_DEFINE_STATIC_DT(dt_signal_mode_field, CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_mode_id_field, CEP_ACRO("CEP"), CEP_WORD("mode_id"));
CEP_DEFINE_STATIC_DT(dt_mode_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_modes_definitions, CEP_ACRO("CEP"), cep_namepool_intern_cstr("definitions"));
CEP_DEFINE_STATIC_DT(dt_modes_evidence, CEP_ACRO("CEP"), cep_namepool_intern_cstr("evidence"));

CEP_DEFINE_STATIC_DT(dt_l1_flow_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("flow"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_pipelines, CEP_ACRO("CEP"), cep_namepool_intern_cstr("pipelines"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_runtime, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_runs, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runs"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_metrics, CEP_ACRO("CEP"), cep_namepool_intern_cstr("metrics"));

CEP_DEFINE_STATIC_DT(dt_decision_beat_field, CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_decision_risk_field, CEP_ACRO("CEP"), CEP_WORD("risk"));
CEP_DEFINE_STATIC_DT(dt_decision_consumer_field, CEP_ACRO("CEP"), CEP_WORD("consumer"));
CEP_DEFINE_STATIC_DT(dt_decision_source_field, CEP_ACRO("CEP"), CEP_WORD("source"));
CEP_DEFINE_STATIC_DT(dt_decision_pipeline_field, CEP_ACRO("CEP"), CEP_WORD("pipeline"));
CEP_DEFINE_STATIC_DT(dt_decision_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_pipeline_id_field, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_stage_id_field, CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_dag_run_id_field, CEP_ACRO("CEP"), CEP_WORD("dag_run_id"));
CEP_DEFINE_STATIC_DT(dt_hop_index_field, CEP_ACRO("CEP"), CEP_WORD("hop_index"));
CEP_DEFINE_STATIC_DT(dt_species_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("species"));
CEP_DEFINE_STATIC_DT(dt_variant_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("variant"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_species, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_species"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_variant, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_variant"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_niche, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_niche"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_global, CEP_ACRO("CEP"), cep_namepool_intern_cstr("global"));
CEP_DEFINE_STATIC_DT(dt_flow_field, CEP_ACRO("CEP"), CEP_WORD("flow"));
CEP_DEFINE_STATIC_DT(dt_niche_field, CEP_ACRO("CEP"), CEP_WORD("niche"));
CEP_DEFINE_STATIC_DT(dt_status_field, CEP_ACRO("CEP"), CEP_WORD("status"));
CEP_DEFINE_STATIC_DT(dt_node_ptr_field, CEP_ACRO("CEP"), CEP_WORD("node_ptr"));
CEP_DEFINE_STATIC_DT(dt_created_bt_field, CEP_ACRO("CEP"), CEP_WORD("created_bt"));
CEP_DEFINE_STATIC_DT(dt_updated_bt_field, CEP_ACRO("CEP"), CEP_WORD("updated_bt"));
CEP_DEFINE_STATIC_DT(dt_episode_field, CEP_ACRO("CEP"), CEP_WORD("episode"));
CEP_DEFINE_STATIC_DT(dt_learn_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("learn"));
CEP_DEFINE_STATIC_DT(dt_eco_flows_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("flows"));
CEP_DEFINE_STATIC_DT(dt_eco_variants_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("variants"));
CEP_DEFINE_STATIC_DT(dt_l2_op_mode_states, CEP_ACRO("CEP"), CEP_WORD("opm:states"));
CEP_DEFINE_STATIC_DT(dt_org_state_running, CEP_ACRO("CEP"), CEP_WORD("running"));
CEP_DEFINE_STATIC_DT(dt_org_state_waiting, CEP_ACRO("CEP"), CEP_WORD("waiting"));
CEP_DEFINE_STATIC_DT(dt_org_state_finished, CEP_ACRO("CEP"), CEP_WORD("finished"));
CEP_DEFINE_STATIC_DT(dt_org_state_failed, CEP_ACRO("CEP"), CEP_WORD("failed"));
CEP_DEFINE_STATIC_DT(dt_topic_evolution, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco.evolution.proposed"));
CEP_DEFINE_STATIC_DT(dt_sev_info, CEP_ACRO("CEP"), CEP_WORD("sev:info"));
CEP_DEFINE_STATIC_DT(dt_env_root, CEP_ACRO("CEP"), CEP_WORD("env"));
CEP_DEFINE_STATIC_DT(dt_env_maze, CEP_ACRO("CEP"), CEP_WORD("maze"));
CEP_DEFINE_STATIC_DT(dt_env_social, CEP_ACRO("CEP"), CEP_WORD("social"));
CEP_DEFINE_STATIC_DT(dt_env_rats, CEP_ACRO("CEP"), CEP_WORD("rat"));
CEP_DEFINE_STATIC_DT(dt_env_messages, CEP_ACRO("CEP"), CEP_WORD("messages"));
CEP_DEFINE_STATIC_DT(dt_env_shock, CEP_ACRO("CEP"), CEP_WORD("shock"));
CEP_DEFINE_STATIC_DT(dt_env_food, CEP_ACRO("CEP"), CEP_WORD("food"));
CEP_DEFINE_STATIC_DT(dt_env_steps, CEP_ACRO("CEP"), CEP_WORD("steps"));
CEP_DEFINE_STATIC_DT(dt_env_blocked, CEP_ACRO("CEP"), CEP_WORD("blocked"));
CEP_DEFINE_STATIC_DT(dt_env_hunger, CEP_ACRO("CEP"), CEP_WORD("hunger"));
CEP_DEFINE_STATIC_DT(dt_env_fatigue, CEP_ACRO("CEP"), CEP_WORD("fatigue"));
CEP_DEFINE_STATIC_DT(dt_env_trust, CEP_ACRO("CEP"), CEP_WORD("trust"));
CEP_DEFINE_STATIC_DT(dt_env_teach, CEP_ACRO("CEP"), CEP_WORD("teach"));
CEP_DEFINE_STATIC_DT(dt_env_noise, CEP_ACRO("CEP"), CEP_WORD("noise"));
CEP_DEFINE_STATIC_DT(dt_env_mode, CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_env_region, CEP_ACRO("CEP"), CEP_WORD("region"));
CEP_DEFINE_STATIC_DT(dt_env_province, CEP_ACRO("CEP"), CEP_WORD("province"));
CEP_DEFINE_STATIC_DT(dt_env_maze_id, CEP_ACRO("CEP"), CEP_WORD("maze_id"));

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak)) void cep_l3_awareness_run(cepCell* eco_root, cepCell* data_root);
__attribute__((weak)) void cep_l4_governance_run(cepCell* eco_root, cepCell* data_root);
#else
static void cep_l3_awareness_run(cepCell* eco_root, cepCell* data_root) {(void)eco_root; (void)data_root;}
static void cep_l4_governance_run(cepCell* eco_root, cepCell* data_root) {(void)eco_root; (void)data_root;}
#endif

static cepDT cep_l2_runtime_autoid(void) {
    cepDT name = {0};
    name.domain = CEP_ACRO("CEP");
    name.tag = CEP_AUTOID;
    return name;
}

static cepCell* cep_l2_runtime_resolve_child(cepCell* parent, const cepDT* name);
static bool cep_l2_runtime_put_pipeline_block(cepCell* parent, const cepPipelineMetadata* pipeline);

static bool cep_l2_runtime_read_text(cepCell* parent, const cepDT* field, char* buffer, size_t buffer_size) {
    if (!parent || !field || !buffer || buffer_size == 0u) {
        return false;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    const char* text = (const char*)cep_cell_data(child);
    if (!text) {
        return false;
    }
    size_t len = strlen(text);
    if (len >= buffer_size) {
        len = buffer_size - 1u;
    }
    memcpy(buffer, text, len);
    buffer[len] = '\0';
    return true;
}

static bool cep_l2_runtime_read_u64(cepCell* parent, const cepDT* field, uint64_t* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&child, &data) || !data || data->size < sizeof(uint64_t)) {
        return false;
    }
    uint64_t value = 0u;
    memcpy(&value, cep_data_payload(data), sizeof value);
    *out = value;
    return true;
}

static bool cep_l2_runtime_read_dt_field(cepCell* parent, const cepDT* field, cepDT* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* container = cep_cell_find_by_name(parent, field);
    container = container ? cep_cell_resolve(container) : NULL;
    if (!container || !cep_cell_require_dictionary_store(&container)) {
        return false;
    }
    uint64_t domain = 0u;
    uint64_t tag = 0u;
    if (!cep_l2_runtime_read_u64(container, CEP_DTAW("CEP", "domain"), &domain) ||
        !cep_l2_runtime_read_u64(container, CEP_DTAW("CEP", "tag"), &tag)) {
        return false;
    }
    out->domain = (cepID)domain;
    out->tag = (cepID)tag;
    out->glob = 0u;
    return cep_dt_is_valid(out);
}

static cepCell* cep_l2_runtime_metrics_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    if (!runtime_root) {
        return NULL;
    }
    cepCell* metrics_root = cep_l2_runtime_resolve_child(runtime_root, dt_runtime_metrics());
    if (!metrics_root || !cep_cell_require_dictionary_store(&metrics_root)) {
        return NULL;
    }
    return metrics_root;
}

static cepCell* cep_l2_runtime_metrics_bucket(cepCell* metrics_root, const cepDT* bucket_name, const cepDT* id) {
    if (!metrics_root || !bucket_name) {
        return NULL;
    }
    cepCell* bucket = cep_cell_ensure_dictionary_child(metrics_root, bucket_name, CEP_STORAGE_RED_BLACK_T);
    bucket = bucket ? cep_cell_resolve(bucket) : NULL;
    if (!bucket || !cep_cell_require_dictionary_store(&bucket)) {
        return NULL;
    }
    if (!id || !cep_dt_is_valid(id)) {
        return bucket;
    }
    cepCell* entry = cep_cell_ensure_dictionary_child(bucket, id, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return NULL;
    }
    return entry;
}

static void cep_l2_runtime_bump_metric(cepCell* eco_root,
                                       const cepDT* bucket_dt,
                                       const cepDT* id,
                                       const char* metric_tag,
                                       uint64_t delta) {
    if (!eco_root || !metric_tag) {
        return;
    }
    cepCell* metrics_root = cep_l2_runtime_metrics_root(eco_root);
    if (!metrics_root) {
        return;
    }
    cepCell* bucket = cep_l2_runtime_metrics_bucket(metrics_root, bucket_dt, id);
    if (!bucket) {
        return;
    }
    cepID tag = cep_namepool_intern(metric_tag, strlen(metric_tag));
    if (!tag) {
        return;
    }
    cepDT metric_dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = tag,
        .glob = 0u,
    };
    uint64_t current = 0u;
    (void)cep_l2_runtime_read_u64(bucket, &metric_dt, &current);
    (void)cep_cell_put_uint64(bucket, &metric_dt, current + delta);
}

static void cep_l2_runtime_bump_all_metrics(cepCell* eco_root,
                                            const cepDT* species,
                                            const cepDT* variant,
                                            const cepDT* niche,
                                            const char* metric_tag,
                                            uint64_t delta) {
    cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_global(), NULL, metric_tag, delta);
    if (species && cep_dt_is_valid(species)) {
        cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_per_species(), species, metric_tag, delta);
    }
    if (variant && cep_dt_is_valid(variant)) {
        cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_per_variant(), variant, metric_tag, delta);
    }
    if (niche && cep_dt_is_valid(niche)) {
        cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_per_niche(), niche, metric_tag, delta);
    }
}

static double cep_l2_runtime_clamp01(double value) {
    if (value < 0.0) {
        return 0.0;
    }
    if (value > 1.0) {
        return 1.0;
    }
    return value;
}

static bool cep_l2_runtime_put_signal(cepCell* current, const char* name, double value) {
    if (!current || !name || !*name) {
        return false;
    }
    cepID tag = cep_namepool_intern(name, strlen(name));
    if (!tag) {
        return false;
    }
    cepDT signal_dt = {.domain = CEP_ACRO("CEP"), .tag = tag, .glob = 0u};
    char buf[32];
    snprintf(buf, sizeof buf, "%.6f", cep_l2_runtime_clamp01(value));
    return cep_cell_put_text(current, &signal_dt, buf);
}

static uint64_t cep_l2_runtime_read_metric(cepCell* bucket, const cepDT* field) {
    uint64_t value = 0u;
    if (!bucket || !field) {
        return 0u;
    }
    (void)cep_l2_runtime_read_u64(bucket, field, &value);
    return value;
}

static cepCell* cep_l2_runtime_require_branch(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return NULL;
    }
    return child;
}

static bool cep_l2_runtime_seed_env_harness(cepCell* data_root) {
    if (!data_root) {
        return false;
    }
    cepCell* env_root = cep_l2_runtime_require_branch(data_root, dt_env_root());
    if (!env_root) {
        return false;
    }
    cepCell* maze_root = cep_l2_runtime_require_branch(env_root, dt_env_maze());
    cepCell* social_root = cep_l2_runtime_require_branch(env_root, dt_env_social());
    if (!maze_root || !social_root) {
        return false;
    }
    (void)cep_l2_runtime_require_branch(maze_root, dt_env_rats());
    (void)cep_l2_runtime_require_branch(social_root, dt_env_messages());
    return true;
}

static bool cep_l2_runtime_grounder_maze(cepCell* eco_root, cepCell* data_root) {
    if (!eco_root || !data_root) {
        return false;
    }
    cepCell* metrics_root = cep_l2_runtime_metrics_root(eco_root);
    if (!metrics_root) {
        return false;
    }
    cepCell* env_root = cep_cell_find_by_name(data_root, dt_env_root());
    env_root = env_root ? cep_cell_resolve(env_root) : NULL;
    cepCell* maze_root = env_root ? cep_cell_find_by_name(env_root, dt_env_maze()) : NULL;
    maze_root = maze_root ? cep_cell_resolve(maze_root) : NULL;
    cepCell* rats_root = maze_root ? cep_cell_find_by_name(maze_root, dt_env_rats()) : NULL;
    rats_root = rats_root ? cep_cell_resolve(rats_root) : NULL;
    if (!rats_root || !cep_cell_require_dictionary_store(&rats_root)) {
        return true; /* nothing to do, keep idempotent */
    }

    for (cepCell* rat = cep_cell_first(rats_root); rat; rat = cep_cell_next(rats_root, rat)) {
        cepCell* rat_entry = cep_cell_resolve(rat);
        if (!rat_entry || !cep_cell_require_dictionary_store(&rat_entry)) {
            continue;
        }
        const cepDT* rat_dt = cep_cell_get_name(rat_entry);
        if (!rat_dt || !cep_dt_is_valid(rat_dt)) {
            continue;
        }
        cepCell* bucket = cep_l2_runtime_metrics_bucket(metrics_root, dt_eco_metrics_per_variant(), rat_dt);
        if (!bucket) {
            continue;
        }
        uint64_t shocks = cep_l2_runtime_read_metric(rat_entry, dt_env_shock());
        uint64_t foods = cep_l2_runtime_read_metric(rat_entry, dt_env_food());
        uint64_t steps = cep_l2_runtime_read_metric(rat_entry, dt_env_steps());
        uint64_t blocked = cep_l2_runtime_read_metric(rat_entry, dt_env_blocked());
        uint64_t hunger = cep_l2_runtime_read_metric(rat_entry, dt_env_hunger());
        uint64_t fatigue = cep_l2_runtime_read_metric(rat_entry, dt_env_fatigue());
        (void)cep_cell_put_uint64(bucket, dt_env_shock(), shocks);
        (void)cep_cell_put_uint64(bucket, dt_env_food(), foods);
        (void)cep_cell_put_uint64(bucket, dt_env_steps(), steps);
        (void)cep_cell_put_uint64(bucket, dt_env_blocked(), blocked);
        (void)cep_cell_put_uint64(bucket, dt_env_hunger(), hunger);
        (void)cep_cell_put_uint64(bucket, dt_env_fatigue(), fatigue);
    }
    return true;
}

static bool cep_l2_runtime_grounder_social(cepCell* eco_root, cepCell* data_root) {
    if (!eco_root || !data_root) {
        return false;
    }
    cepCell* metrics_root = cep_l2_runtime_metrics_root(eco_root);
    if (!metrics_root) {
        return false;
    }
    cepCell* env_root = cep_cell_find_by_name(data_root, dt_env_root());
    env_root = env_root ? cep_cell_resolve(env_root) : NULL;
    cepCell* social_root = env_root ? cep_cell_find_by_name(env_root, dt_env_social()) : NULL;
    social_root = social_root ? cep_cell_resolve(social_root) : NULL;
    cepCell* messages_root = social_root ? cep_cell_find_by_name(social_root, dt_env_messages()) : NULL;
    messages_root = messages_root ? cep_cell_resolve(messages_root) : NULL;
    if (!messages_root || !cep_cell_require_dictionary_store(&messages_root)) {
        return true;
    }

    /* Aggregate simple trust/teach counters per sender rat. */
    for (cepCell* msg = cep_cell_first(messages_root); msg; msg = cep_cell_next(messages_root, msg)) {
        cepCell* entry = cep_cell_resolve(msg);
        if (!entry || !cep_cell_require_dictionary_store(&entry)) {
            continue;
        }
        const cepDT* sender_dt = cep_cell_get_name(entry);
        if (!sender_dt || !cep_dt_is_valid(sender_dt)) {
            continue;
        }
        cepCell* bucket = cep_l2_runtime_metrics_bucket(metrics_root, dt_eco_metrics_per_variant(), sender_dt);
        if (!bucket) {
            continue;
        }
        uint64_t trust = cep_l2_runtime_read_metric(entry, dt_env_trust());
        uint64_t teach = cep_l2_runtime_read_metric(entry, dt_env_teach());
        uint64_t noise = cep_l2_runtime_read_metric(entry, dt_env_noise());
        (void)cep_cell_put_uint64(bucket, dt_env_trust(), trust);
        (void)cep_cell_put_uint64(bucket, dt_env_teach(), teach);
        (void)cep_cell_put_uint64(bucket, dt_env_noise(), noise);
    }
    return true;
}

static bool cep_l2_runtime_update_modes(cepCell* modes_root,
                                        cepCell* signal_current,
                                        double risk,
                                        double hunger) {
    if (!modes_root || !signal_current) {
        return false;
    }
    cepCell* current = cep_l2_runtime_require_branch(modes_root, dt_signal_field_current());
    cepCell* evidence_root = cep_l2_runtime_require_branch(modes_root, dt_modes_evidence());
    if (!current || !evidence_root) {
        return false;
    }

    const char* mode_id = "steady";
    if (risk > 0.7) {
        mode_id = "high_risk";
    } else if (hunger > 0.6) {
        mode_id = "hungry";
    }

    if (!cep_cell_put_text(current, dt_mode_id_field(), mode_id)) {
        return false;
    }
    (void)cep_cell_put_text(signal_current, dt_signal_mode_field(), mode_id);

    cepDT entry_name = cep_l2_runtime_autoid();
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* entry = cep_cell_add_dictionary(evidence_root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }
    (void)cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
    (void)cep_cell_put_text(entry, dt_mode_id_field(), mode_id);
    char note_buf[64];
    snprintf(note_buf, sizeof note_buf, "risk=%.3f hunger=%.3f", risk, hunger);
    (void)cep_cell_put_text(entry, dt_mode_note_field(), note_buf);
    return true;
}

static bool cep_l2_runtime_update_signal_field(cepCell* eco_root) {
    if (!eco_root) {
        return false;
    }
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    cepCell* signal_root = runtime_root ? cep_l2_runtime_resolve_child(runtime_root, dt_runtime_signal_field()) : NULL;
    cepCell* modes_root = runtime_root ? cep_l2_runtime_resolve_child(runtime_root, dt_runtime_modes()) : NULL;
    if (!signal_root || !modes_root) {
        return false;
    }
    cepCell* current = cep_l2_runtime_require_branch(signal_root, dt_signal_field_current());
    if (!current) {
        return false;
    }

    /* Prefer per-variant metrics; fall back to global. */
    cepCell* metrics_root = cep_l2_runtime_metrics_root(eco_root);
    cepCell* bucket = NULL;
    if (metrics_root) {
        cepCell* per_variant = cep_l2_runtime_resolve_child(metrics_root, dt_eco_metrics_per_variant());
        per_variant = per_variant ? cep_cell_resolve(per_variant) : NULL;
        if (per_variant && cep_cell_require_dictionary_store(&per_variant)) {
            cepCell* first = cep_cell_first(per_variant);
            first = first ? cep_cell_resolve(first) : NULL;
            if (first && cep_cell_require_dictionary_store(&first)) {
                bucket = first;
            }
        }
        if (!bucket) {
            cepCell* global = cep_l2_runtime_resolve_child(metrics_root, dt_eco_metrics_global());
            bucket = (global && cep_cell_require_dictionary_store(&global)) ? global : NULL;
        }
    }

    uint64_t shocks = cep_l2_runtime_read_metric(bucket, dt_env_shock());
    uint64_t foods = cep_l2_runtime_read_metric(bucket, dt_env_food());
    uint64_t steps = cep_l2_runtime_read_metric(bucket, dt_env_steps());
    uint64_t blocked = cep_l2_runtime_read_metric(bucket, dt_env_blocked());
    uint64_t hunger = cep_l2_runtime_read_metric(bucket, dt_env_hunger());
    uint64_t fatigue = cep_l2_runtime_read_metric(bucket, dt_env_fatigue());
    uint64_t trust = cep_l2_runtime_read_metric(bucket, dt_env_trust());
    uint64_t teach = cep_l2_runtime_read_metric(bucket, dt_env_teach());
    uint64_t noise = cep_l2_runtime_read_metric(bucket, dt_env_noise());

    double total_events = (double)(shocks + foods + steps + blocked + 1u);
    double risk = (double)(shocks + blocked) / total_events;
    double curiosity = (double)(steps + foods) / total_events;
    double fast = (double)steps / total_events;
    double fatigue_n = fatigue > 100u ? 1.0 : ((double)fatigue / 100.0);
    double hunger_n = hunger > 100u ? 1.0 : ((double)hunger / 100.0);
    double social_trust = trust > 100u ? 1.0 : ((double)trust / 100.0);
    double teach_n = teach > 100u ? 1.0 : ((double)teach / 100.0);
    double noise_n = noise > 100u ? 1.0 : ((double)noise / 100.0);
    double low_noise = 1.0 - noise_n;

    bool ok = true;
    ok &= cep_l2_runtime_put_signal(current, "risk", risk);
    ok &= cep_l2_runtime_put_signal(current, "hunger", hunger_n);
    ok &= cep_l2_runtime_put_signal(current, "curiosity", curiosity);
    ok &= cep_l2_runtime_put_signal(current, "fast", fast);
    ok &= cep_l2_runtime_put_signal(current, "fatigue", fatigue_n);
    ok &= cep_l2_runtime_put_signal(current, "social_trust", social_trust);
    ok &= cep_l2_runtime_put_signal(current, "teach", teach_n);
    ok &= cep_l2_runtime_put_signal(current, "low_noise", cep_l2_runtime_clamp01(low_noise));

    if (ok && modes_root) {
        ok &= cep_l2_runtime_update_modes(modes_root, current, risk, hunger_n);
    }

    /* Optional beat-stamped history for debugging/awareness. */
    cepCell* history_root = cep_l2_runtime_require_branch(signal_root, dt_signal_field_history());
    if (history_root) {
        cepDT entry_name = cep_l2_runtime_autoid();
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepCell* entry = cep_cell_add_dictionary(history_root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
        entry = entry ? cep_cell_resolve(entry) : NULL;
        if (entry && cep_cell_require_dictionary_store(&entry)) {
            (void)cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
            (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "note"), "signal_field_snapshot");
            (void)cep_cell_copy_children(current, entry, false);
        }
    }

    return ok;
}

static const char* cep_l2_runtime_read_text_field(cepCell* parent, const cepDT* field, char* buf, size_t buf_sz) {
    if (!parent || !field || !buf || buf_sz == 0u) {
        return NULL;
    }
    buf[0] = '\0';
    cepCell* field_cell = cep_cell_find_by_name(parent, field);
    field_cell = field_cell ? cep_cell_resolve(field_cell) : NULL;
    if (!field_cell || !cep_cell_has_data(field_cell)) {
        return NULL;
    }
    const char* text = (const char*)cep_cell_data(field_cell);
    if (!text) {
        return NULL;
    }
    snprintf(buf, buf_sz, "%s", text);
    return buf;
}

static cepCell* cep_l2_runtime_signal_current(cepCell* eco_root) {
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    cepCell* signal_root = runtime_root ? cep_l2_runtime_resolve_child(runtime_root, dt_runtime_signal_field()) : NULL;
    cepCell* current = signal_root ? cep_l2_runtime_resolve_child(signal_root, dt_signal_field_current()) : NULL;
    current = current ? cep_cell_resolve(current) : NULL;
    return current;
}

static bool cep_l2_runtime_skill_decide(cepCell* eco_root,
                                        const cepL2FocusContext* ctx,
                                        const char* learner_id,
                                        const char* skill_id,
                                        const char* const* actions,
                                        size_t action_count,
                                        double exploration_bias) {
    if (!eco_root || !ctx || !learner_id || !skill_id || !actions || action_count == 0u) {
        return false;
    }

    char focus_key[96];
    bool focus_ok = false;
    if (strcmp(skill_id, "nav") == 0) {
        focus_ok = cep_l2_focus_build_nav(eco_root, ctx, focus_key, sizeof focus_key);
    } else if (strcmp(skill_id, "explore") == 0) {
        focus_ok = cep_l2_focus_build_exploration(eco_root, ctx, focus_key, sizeof focus_key);
    } else if (strcmp(skill_id, "memory") == 0) {
        focus_ok = cep_l2_focus_build_memory(eco_root, ctx, focus_key, sizeof focus_key);
    } else if (strcmp(skill_id, "social") == 0) {
        focus_ok = cep_l2_focus_build_social(eco_root, ctx, focus_key, sizeof focus_key);
    } else if (strcmp(skill_id, "warning") == 0) {
        focus_ok = cep_l2_focus_build_warning(eco_root, ctx, focus_key, sizeof focus_key);
    }
    if (!focus_ok) {
        return false;
    }

    cepL2DecisionRequest req = {
        .eco_root = eco_root,
        .learner_id = learner_id,
        .skill_id = skill_id,
        .focus_key = focus_key,
        .actions = actions,
        .action_count = action_count,
        .exploration_bias = exploration_bias,
        .allow_imaginate = exploration_bias > 0.0,
        .guardian_allow = NULL,
        .guardian_user = NULL,
        .pipeline = NULL,
        .species_id = NULL,
        .variant_id = NULL,
    };

    cepL2DecisionResult res = {0};
    if (!cep_l2_playbook_select(&req, &res)) {
        return false;
    }

    cepCell* signals = cep_l2_runtime_signal_current(eco_root);
    double risk = 0.0;
    (void)cep_l2_focus_read_signal(signals, "risk", &risk);
    bool success = risk < 0.6 || strcmp(res.action_id, "wait") == 0 || strcmp(res.action_id, "warn") == 0;
    double cost = risk;

    return cep_l2_playbook_update_stats(eco_root,
                                        learner_id,
                                        focus_key,
                                        res.action_id,
                                        success,
                                        cost,
                                        res.imaginate_used,
                                        res.decision_cell);
}

static void cep_l2_runtime_run_rat_skills(cepCell* eco_root, cepCell* data_root) {
    if (!eco_root || !data_root) {
        return;
    }
    cepCell* env_root = cep_cell_find_by_name(data_root, dt_env_root());
    env_root = env_root ? cep_cell_resolve(env_root) : NULL;
    cepCell* maze_root = env_root ? cep_cell_find_by_name(env_root, dt_env_maze()) : NULL;
    maze_root = maze_root ? cep_cell_resolve(maze_root) : NULL;
    cepCell* rats_root = maze_root ? cep_cell_find_by_name(maze_root, dt_env_rats()) : NULL;
    rats_root = rats_root ? cep_cell_resolve(rats_root) : NULL;
    if (!rats_root || !cep_cell_require_dictionary_store(&rats_root)) {
        return;
    }

    static const char* nav_actions[] = {"move_north", "move_south", "move_east", "move_west", "wait"};
    static const char* explore_actions[] = {"explore", "hold"};
    static const char* memory_actions[] = {"avoid", "retry"};
    static const char* social_actions[] = {"follow", "lead", "idle"};
    static const char* warning_actions[] = {"warn", "stay_quiet"};

    cepCell* signals = cep_l2_runtime_signal_current(eco_root);
    double curiosity = 0.0;
    double risk = 0.0;
    (void)cep_l2_focus_read_signal(signals, "curiosity", &curiosity);
    (void)cep_l2_focus_read_signal(signals, "risk", &risk);

    for (cepCell* rat = cep_cell_first(rats_root); rat; rat = cep_cell_next(rats_root, rat)) {
        cepCell* entry = cep_cell_resolve(rat);
        if (!entry || !cep_cell_require_dictionary_store(&entry)) {
            continue;
        }
        const cepDT* rat_dt = cep_cell_get_name(entry);
        const char* rat_id = (rat_dt && cep_dt_is_valid(rat_dt)) ? cep_namepool_lookup(rat_dt->tag, NULL) : NULL;
        char buf[64];
        cepL2FocusContext ctx = {
            .rat_id = rat_id ? rat_id : cep_l2_runtime_read_text_field(entry, dt_env_trust(), buf, sizeof buf),
            .maze_id = cep_l2_runtime_read_text_field(entry, dt_env_maze_id(), buf, sizeof buf),
            .region_id = cep_l2_runtime_read_text_field(entry, dt_env_region(), buf, sizeof buf),
            .province_id = cep_l2_runtime_read_text_field(entry, dt_env_province(), buf, sizeof buf),
            .mode_id = cep_l2_runtime_read_text_field(entry, dt_env_mode(), buf, sizeof buf),
        };

        double explore_bias = curiosity > 0.0 ? curiosity : 0.1;
        double warning_bias = risk;

        (void)cep_l2_runtime_skill_decide(eco_root, &ctx, "rat_nav", "nav", nav_actions, cep_lengthof(nav_actions), 0.0);
        (void)cep_l2_runtime_skill_decide(eco_root, &ctx, "rat_explore", "explore", explore_actions, cep_lengthof(explore_actions), explore_bias);
        (void)cep_l2_runtime_skill_decide(eco_root, &ctx, "rat_memory", "memory", memory_actions, cep_lengthof(memory_actions), 0.0);
        (void)cep_l2_runtime_skill_decide(eco_root, &ctx, "rat_social", "social", social_actions, cep_lengthof(social_actions), 0.2);
        (void)cep_l2_runtime_skill_decide(eco_root, &ctx, "rat_warning", "warning", warning_actions, cep_lengthof(warning_actions), warning_bias);
    }
}

static void cep_l2_runtime_emit_evolution(const cepPipelineMetadata* pipeline,
                                          const cepDT* species,
                                          const cepDT* variant) {
    char note[128] = {0};
    const char* species_text = (species && cep_dt_is_valid(species)) ? cep_namepool_lookup(species->tag, NULL) : NULL;
    const char* variant_text = (variant && cep_dt_is_valid(variant)) ? cep_namepool_lookup(variant->tag, NULL) : NULL;
    snprintf(note,
             sizeof note,
             "species=%s variant=%s",
             species_text ? species_text : "<unset>",
             variant_text ? variant_text : "<unset>");
    cepCeiRequest req = {
        .severity = *dt_sev_info(),
        .topic = cep_namepool_lookup(dt_topic_evolution()->tag, NULL),
        .topic_len = 0u,
        .note = note,
        .note_len = 0u,
        .emit_signal = true,
    };
    if (pipeline) {
        req.has_pipeline = true;
        req.pipeline = *pipeline;
    }
    (void)cep_cei_emit(&req);
}

static cepCell* cep_l2_runtime_resolve_child(cepCell* parent, const cepDT* name) {
    cepCell* child = cep_cell_find_by_name(parent, name);
    child = child ? cep_cell_resolve(child) : NULL;
    return child;
}

static cepID cep_l2_runtime_intern_id(const char* text) {
    if (!text || !*text) {
        return 0u;
    }
    return cep_namepool_intern(text, strlen(text));
}

static void cep_l2_runtime_pipeline_from_flow(cepCell* flow_root,
                                              const cepDT* flow_id,
                                              cepPipelineMetadata* pipeline) {
    if (!pipeline) {
        return;
    }
    pipeline->pipeline_id = 0u;
    pipeline->stage_id = 0u;
    pipeline->dag_run_id = 0u;
    pipeline->hop_index = 0u;
    if (flow_id && cep_dt_is_valid(flow_id)) {
        pipeline->pipeline_id = flow_id->tag;
    }
    if (flow_root) {
        char buf[64];
        if (cep_l2_runtime_read_text(flow_root, dt_pipeline_id_field(), buf, sizeof buf)) {
            pipeline->pipeline_id = cep_l2_runtime_intern_id(buf);
        }
        if (cep_l2_runtime_read_text(flow_root, dt_stage_id_field(), buf, sizeof buf)) {
            pipeline->stage_id = cep_l2_runtime_intern_id(buf);
        }
        uint64_t dag_id = 0u;
        if (cep_l2_runtime_read_u64(flow_root, dt_dag_run_id_field(), &dag_id)) {
            pipeline->dag_run_id = dag_id;
        }
        uint64_t hop = 0u;
        if (cep_l2_runtime_read_u64(flow_root, dt_hop_index_field(), &hop)) {
            pipeline->hop_index = hop;
        }
    }
}

static void cep_l2_runtime_pipeline_from_run(cepCell* run_root, cepPipelineMetadata* pipeline) {
    if (!pipeline) {
        return;
    }
    pipeline->pipeline_id = 0u;
    pipeline->stage_id = 0u;
    pipeline->dag_run_id = 0u;
    pipeline->hop_index = 0u;
    if (!run_root) {
        return;
    }
    char buf[64];
    if (cep_l2_runtime_read_text(run_root, dt_pipeline_id_field(), buf, sizeof buf)) {
        pipeline->pipeline_id = cep_l2_runtime_intern_id(buf);
    }
    if (cep_l2_runtime_read_text(run_root, dt_stage_id_field(), buf, sizeof buf)) {
        pipeline->stage_id = cep_l2_runtime_intern_id(buf);
    }
    uint64_t dag_id = 0u;
    if (cep_l2_runtime_read_u64(run_root, dt_dag_run_id_field(), &dag_id)) {
        pipeline->dag_run_id = dag_id;
    }
    uint64_t hop = 0u;
    if (cep_l2_runtime_read_u64(run_root, dt_hop_index_field(), &hop)) {
        pipeline->hop_index = hop;
    }
}

static cepDT cep_l2_runtime_choose_species(cepCell* flow_root, const cepDT* flow_id) {
    cepDT species = {0};
    char buf[64];
    if (flow_root && cep_l2_runtime_read_text(flow_root, dt_species_field(), buf, sizeof buf)) {
        cepID tag = cep_l2_runtime_intern_id(buf);
        if (tag) {
            species.domain = CEP_ACRO("CEP");
            species.tag = tag;
        }
    }
    if (!cep_dt_is_valid(&species) && flow_id && cep_dt_is_valid(flow_id)) {
        species = *flow_id;
    }
    return species;
}

static cepDT cep_l2_runtime_choose_variant(cepCell* eco_root, cepCell* flow_root) {
    cepDT variant = {0};
    char buf[64];
    if (flow_root && cep_l2_runtime_read_text(flow_root, dt_variant_field(), buf, sizeof buf)) {
        cepID tag = cep_l2_runtime_intern_id(buf);
        if (tag) {
            variant.domain = CEP_ACRO("CEP");
            variant.tag = tag;
        }
    }
    if (cep_dt_is_valid(&variant)) {
        return variant;
    }
    cepCell* variants_root = cep_l2_runtime_resolve_child(eco_root, dt_eco_variants_root());
    if (variants_root && cep_cell_require_dictionary_store(&variants_root)) {
        cepCell* first = cep_cell_first(variants_root);
        if (first) {
            variant = first->metacell.dt;
            variant.glob = 0u;
        }
    }
    return variant;
}

static cepOID cep_l2_runtime_start_episode(const cepPipelineMetadata* pipeline) {
    cepOID eid = cep_op_start(*CEP_DTAW("CEP", "op/ep"),
                              "/data/eco/runtime/organisms",
                              *dt_l2_op_mode_states(),
                              NULL,
                              0u,
                              0u);
    if (cep_oid_is_valid(eid) && pipeline) {
        (void)cep_op_set_pipeline_metadata(eid, pipeline);
    }
    return eid;
}

static void cep_l2_runtime_store_episode(cepCell* organism, cepOID oid) {
    if (!organism || !cep_oid_is_valid(oid)) {
        return;
    }
    cepCell* ep = cep_cell_ensure_dictionary_child(organism, dt_episode_field(), CEP_STORAGE_RED_BLACK_T);
    ep = ep ? cep_cell_resolve(ep) : NULL;
    if (!ep || !cep_cell_require_dictionary_store(&ep)) {
        return;
    }
    (void)cep_cell_put_uint64(ep, CEP_DTAW("CEP", "domain"), cep_id(oid.domain));
    (void)cep_cell_put_uint64(ep, CEP_DTAW("CEP", "tag"), cep_id(oid.tag));
}

static bool cep_l2_runtime_prepare_context(cepCell* eco_root,
                                           cepCell* learn_root,
                                           cepCell* organisms_root,
                                           cepCell* flow_root,
                                           const cepDT* flow_id,
                                           const cepPipelineMetadata* pipeline,
                                           cepL2OrganismContext* ctx_out,
                                           bool* out_new) {
    if (!eco_root || !organisms_root || !flow_root || !flow_id || !ctx_out) {
        return false;
    }
    cepDT organism_id = *flow_id;
    bool new_org = false;
    cepCell* existing = cep_cell_find_by_name(organisms_root, &organism_id);
    cepCell* organism = existing ? cep_cell_resolve(existing)
                                 : cep_cell_add_dictionary(organisms_root,
                                                            &organism_id,
                                                            0u,
                                                            CEP_DTAW("CEP", "dictionary"),
                                                            CEP_STORAGE_RED_BLACK_T);
    organism = organism ? cep_cell_resolve(organism) : NULL;
    if (!organism || !cep_cell_require_dictionary_store(&organism)) {
        return false;
    }
    if (!existing) {
        new_org = true;
        uint64_t beat = (uint64_t)cep_beat_index();
        (void)cep_cell_put_uint64(organism, dt_created_bt_field(), beat);
        (void)cep_cell_put_dt(organism, dt_status_field(), dt_org_state_running());
        (void)cep_cell_put_dt(organism, dt_flow_field(), flow_id);
        cepDT species = cep_l2_runtime_choose_species(flow_root, flow_id);
        if (cep_dt_is_valid(&species)) {
            (void)cep_cell_put_dt(organism, dt_species_field(), &species);
        }
        cepDT variant = cep_l2_runtime_choose_variant(eco_root, flow_root);
        if (cep_dt_is_valid(&variant)) {
            (void)cep_cell_put_dt(organism, dt_variant_field(), &variant);
        }
        char niche_buf[64];
        if (cep_l2_runtime_read_text(flow_root, dt_niche_field(), niche_buf, sizeof niche_buf)) {
            cepID niche_id = cep_l2_runtime_intern_id(niche_buf);
            if (niche_id) {
                cepDT niche = {.domain = CEP_ACRO("CEP"), .tag = niche_id, .glob = 0u};
                (void)cep_cell_put_dt(organism, dt_niche_field(), &niche);
            }
        }
        (void)cep_l2_runtime_put_pipeline_block(organism, pipeline);
        cepOID episode = cep_l2_runtime_start_episode(pipeline);
        if (cep_oid_is_valid(episode)) {
            cep_l2_runtime_store_episode(organism, episode);
        }
    }

    memset(ctx_out, 0, sizeof(*ctx_out));
    ctx_out->eco_root = eco_root;
    ctx_out->learn_root = learn_root;
    ctx_out->organism_root = organisms_root;
    ctx_out->organism = organism;
    ctx_out->organism_id = organism_id;
    ctx_out->flow_root = flow_root;
    ctx_out->flow_id = *flow_id;
    ctx_out->pipeline = pipeline ? *pipeline : (cepPipelineMetadata){0};
    cepDT species_id = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_species_field(), &species_id)) {
        ctx_out->species_id = species_id;
    }
    cepDT variant_id = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_variant_field(), &variant_id)) {
        ctx_out->variant_id = variant_id;
    }
    cepDT niche_id = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_niche_field(), &niche_id)) {
        ctx_out->niche_id = niche_id;
    }
    cepDT node_ptr = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_node_ptr_field(), &node_ptr)) {
        ctx_out->current_node = node_ptr;
    }
    cepDT ep_dt = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_episode_field(), &ep_dt)) {
        ctx_out->episode_oid.domain = ep_dt.domain;
        ctx_out->episode_oid.tag = ep_dt.tag;
    }
    uint64_t created_bt = 0u;
    if (cep_l2_runtime_read_u64(organism, dt_created_bt_field(), &created_bt)) {
        ctx_out->created_beat = created_bt;
    }
    if (out_new) {
        *out_new = new_org;
    }
    return true;
}

static bool cep_l2_runtime_step_flow(cepCell* eco_root,
                                     cepCell* learn_root,
                                     cepCell* organisms_root,
                                     cepCell* flow_root,
                                     const cepDT* flow_id,
                                     const cepPipelineMetadata* pipeline,
                                     size_t step_budget) {
    cepL2OrganismContext ctx = {0};
    bool new_org = false;
    if (!cep_l2_runtime_prepare_context(eco_root, learn_root, organisms_root, flow_root, flow_id, pipeline, &ctx, &new_org)) {
        return false;
    }
    if (new_org) {
        cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_started", 1u);
        cep_l2_runtime_emit_evolution(pipeline, &ctx.species_id, &ctx.variant_id);
    }

    bool progressed = cep_l2_flow_step(&ctx, step_budget);
    if (progressed) {
        cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "flow_steps", 1u);
    }

    switch (ctx.status) {
        case CEP_L2_ORG_FINISHED:
            cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_finished", 1u);
            break;
        case CEP_L2_ORG_FAILED:
            cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_failed", 1u);
            break;
        case CEP_L2_ORG_WAITING:
            cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_waiting", 1u);
            break;
        default:
            break;
    }
    return progressed;
}

static bool cep_l2_runtime_seed_metrics_branches(cepCell* metrics_root) {
    if (!metrics_root) {
        return false;
    }
    cepCell* per_species = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_per_species(), CEP_STORAGE_RED_BLACK_T);
    cepCell* per_variant = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_per_variant(), CEP_STORAGE_RED_BLACK_T);
    cepCell* per_niche = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_per_niche(), CEP_STORAGE_RED_BLACK_T);
    cepCell* global = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_global(), CEP_STORAGE_RED_BLACK_T);
    return per_species && per_variant && per_niche && global;
}

static bool cep_l2_runtime_put_pipeline_block(cepCell* parent, const cepPipelineMetadata* pipeline) {
    if (!parent || !pipeline) {
        return true;
    }
    cepCell* pipeline_root = cep_cell_ensure_dictionary_child(parent, dt_decision_pipeline_field(), CEP_STORAGE_RED_BLACK_T);
    pipeline_root = pipeline_root ? cep_cell_resolve(pipeline_root) : NULL;
    if (!pipeline_root) {
        return false;
    }
    bool ok = true;
    if (pipeline->pipeline_id) {
        const char* text = cep_namepool_lookup(pipeline->pipeline_id, NULL);
        if (text) {
            ok &= cep_cell_put_text(pipeline_root, dt_pipeline_id_field(), text);
        }
    }
    if (pipeline->stage_id) {
        const char* text = cep_namepool_lookup(pipeline->stage_id, NULL);
        if (text) {
            ok &= cep_cell_put_text(pipeline_root, dt_stage_id_field(), text);
        }
    }
    if (pipeline->dag_run_id) {
        ok &= cep_cell_put_uint64(pipeline_root, dt_dag_run_id_field(), pipeline->dag_run_id);
    }
    if (pipeline->hop_index) {
        ok &= cep_cell_put_uint64(pipeline_root, dt_hop_index_field(), pipeline->hop_index);
    }
    return ok;
}

static cepCell* cep_l2_runtime_history_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    if (runtime_root) {
        cepCell* history = cep_l2_runtime_resolve_child(runtime_root, dt_runtime_history());
        if (history) {
            return history;
        }
    }
    return NULL;
}

static cepCell* cep_l2_runtime_decisions_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    if (!runtime_root) {
        return NULL;
    }
    return cep_l2_runtime_resolve_child(runtime_root, dt_runtime_decisions());
}

static bool cep_l2_runtime_log_decision(cepCell* decisions_root,
                                        const cepPipelineMetadata* pipeline,
                                        const cepDT* species_id,
                                        const cepDT* variant_id,
                                        const char* risk_label,
                                        const cepBranchController* consumer,
                                        const cepBranchController* source,
                                        bool decision_recorded) {
    if (!decisions_root || !risk_label || !consumer || !source) {
        return false;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT entry_name = cep_l2_runtime_autoid();
    cepCell* entry = cep_cell_add_dictionary(decisions_root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    bool ok = true;
    ok &= cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
    ok &= cep_cell_put_text(entry, dt_decision_risk_field(), risk_label);
    ok &= cep_cell_put_dt(entry, dt_decision_consumer_field(), &consumer->branch_dt);
    ok &= cep_cell_put_dt(entry, dt_decision_source_field(), &source->branch_dt);
    ok &= cep_l2_runtime_put_pipeline_block(entry, pipeline);
    if (species_id && cep_dt_is_valid(species_id)) {
        ok &= cep_cell_put_dt(entry, dt_species_field(), species_id);
    }
    if (variant_id && cep_dt_is_valid(variant_id)) {
        ok &= cep_cell_put_dt(entry, dt_variant_field(), variant_id);
    }

    char note[64];
    snprintf(note,
             sizeof note,
             "decision_recorded=%s",
             decision_recorded ? "true" : "false");
    ok &= cep_cell_put_text(entry, dt_decision_note_field(), note);
    return ok;
}


/* Registers L2 organ descriptors so pack-owned roots can attach constructors
 * and validators; keeps registration idempotent to mirror other packs. */
bool cep_l2_runtime_register_organs(void) {
    cepOrganDescriptor organs[] = {
        {
            .kind = "eco_root",
            .label = "L2 ecology root organ",
            .store = *dt_org_eco_root_store(),
            .validator = *dt_org_eco_root_vl(),
            .constructor = *dt_org_eco_root_ct(),
            .destructor = *dt_org_eco_root_dt(),
        },
        {
            .kind = "eco_flows",
            .label = "L2 flows organ",
            .store = *dt_org_eco_flows_store(),
            .validator = *dt_org_eco_flows_vl(),
            .constructor = *dt_org_eco_flows_ct(),
            .destructor = *dt_org_eco_flows_dt(),
        },
        {
            .kind = "eco_runtime",
            .label = "L2 runtime organ",
            .store = *dt_org_eco_runtime_store(),
            .validator = *dt_org_eco_runtime_vl(),
            .constructor = *dt_org_eco_runtime_ct(),
            .destructor = *dt_org_eco_runtime_dt(),
        },
        {
            .kind = "eco_signal_field",
            .label = "L2 signal field organ",
            .store = *dt_org_signal_field_store(),
            .validator = *dt_org_signal_field_vl(),
            .constructor = *dt_org_signal_field_ct(),
            .destructor = *dt_org_signal_field_dt(),
        },
        {
            .kind = "eco_playbooks",
            .label = "L2 playbooks organ",
            .store = *dt_org_playbooks_store(),
            .validator = *dt_org_playbooks_vl(),
            .constructor = *dt_org_playbooks_ct(),
            .destructor = *dt_org_playbooks_dt(),
        },
        {
            .kind = "eco_modes",
            .label = "L2 modes organ",
            .store = *dt_org_modes_store(),
            .validator = *dt_org_modes_vl(),
            .constructor = *dt_org_modes_ct(),
            .destructor = *dt_org_modes_dt(),
        },
        {
            .kind = "learn_models",
            .label = "L2 learning organ",
            .store = *dt_org_learn_models_store(),
            .validator = *dt_org_learn_models_vl(),
            .constructor = *dt_org_learn_models_ct(),
            .destructor = *dt_org_learn_models_dt(),
        },
    };

    const size_t organ_count = sizeof organs / sizeof organs[0];
    for (size_t i = 0; i < organ_count; ++i) {
        if (!cep_organ_register(&organs[i])) {
            return false;
        }
    }

    return true;
}

/* Seeds runtime subtrees to host organisms, metrics, decisions, and queues so
 * scheduler and Flow VM wiring can attach without chasing missing nodes. */
bool cep_l2_runtime_seed_runtime(cepCell* eco_root) {
    if (!eco_root) {
        return false;
    }

    cepCell* runtime_root = cep_cell_ensure_dictionary_child(eco_root, dt_runtime_root(), CEP_STORAGE_RED_BLACK_T);
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    if (!runtime_root) {
        return false;
    }

    cepCell* organisms = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_organisms(), CEP_STORAGE_RED_BLACK_T);
    cepCell* metrics = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_metrics(), CEP_STORAGE_RED_BLACK_T);
    cepCell* decisions = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_decisions(), CEP_STORAGE_RED_BLACK_T);
    cepCell* sched = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_sched(), CEP_STORAGE_RED_BLACK_T);
    cepCell* history = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_history(), CEP_STORAGE_RED_BLACK_T);
    cepCell* signal_field = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_signal_field(), CEP_STORAGE_RED_BLACK_T);
    cepCell* playbooks = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_playbooks(), CEP_STORAGE_RED_BLACK_T);
    cepCell* modes = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_modes(), CEP_STORAGE_RED_BLACK_T);

    organisms = organisms ? cep_cell_resolve(organisms) : NULL;
    metrics = metrics ? cep_cell_resolve(metrics) : NULL;
    decisions = decisions ? cep_cell_resolve(decisions) : NULL;
    sched = sched ? cep_cell_resolve(sched) : NULL;
    history = history ? cep_cell_resolve(history) : NULL;
    signal_field = signal_field ? cep_cell_resolve(signal_field) : NULL;
    playbooks = playbooks ? cep_cell_resolve(playbooks) : NULL;
    modes = modes ? cep_cell_resolve(modes) : NULL;

    cepDT signal_field_store = cep_organ_store_dt("eco_signal_field");
    cepDT playbooks_store = cep_organ_store_dt("eco_playbooks");
    cepDT modes_store = cep_organ_store_dt("eco_modes");
    if (signal_field && signal_field->store && cep_dt_is_valid(&signal_field_store)) {
        cep_store_set_dt(signal_field->store, &signal_field_store);
    }
    if (playbooks && playbooks->store && cep_dt_is_valid(&playbooks_store)) {
        cep_store_set_dt(playbooks->store, &playbooks_store);
    }
    if (modes && modes->store && cep_dt_is_valid(&modes_store)) {
        cep_store_set_dt(modes->store, &modes_store);
    }

    cepCell* signal_current = signal_field ? cep_cell_ensure_dictionary_child(signal_field, dt_signal_field_current(), CEP_STORAGE_RED_BLACK_T) : NULL;
    signal_current = signal_current ? cep_cell_resolve(signal_current) : NULL;
    bool signal_ready = signal_current && cep_cell_require_dictionary_store(&signal_current);

    bool playbooks_ready = playbooks && cep_cell_require_dictionary_store(&playbooks);
    bool modes_ready = modes && cep_cell_require_dictionary_store(&modes);
    bool metrics_ready = cep_l2_runtime_seed_metrics_branches(metrics);

    return organisms && metrics && decisions && sched && history && signal_ready && playbooks_ready && modes_ready && metrics_ready;
}

/* TODO: replace stub with trigger scanning and organism creation once the Flow
 * VM and scheduler inputs are connected. */
bool cep_l2_runtime_scheduler_pump(cepCell* eco_root) {
    if (!eco_root) {
        return false;
    }

    cepCell* data_root = cep_cell_parent(eco_root);
    cepCell* learn_root = data_root ? cep_l2_runtime_resolve_child(data_root, dt_learn_root()) : NULL;
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    cepCell* organisms_root = runtime_root ? cep_l2_runtime_resolve_child(runtime_root, dt_runtime_organisms()) : NULL;
    cepCell* flows_root = cep_l2_runtime_resolve_child(eco_root, dt_eco_flows_root());

    cepCell* flow_root = data_root ? cep_l2_runtime_resolve_child(data_root, dt_l1_flow_root()) : NULL;
    cepCell* pipelines_root = flow_root ? cep_l2_runtime_resolve_child(flow_root, dt_l1_flow_pipelines()) : NULL;
    cepCell* flow_runtime = flow_root ? cep_l2_runtime_resolve_child(flow_root, dt_l1_flow_runtime()) : NULL;
    cepCell* runs_root = flow_runtime ? cep_l2_runtime_resolve_child(flow_runtime, dt_l1_flow_runs()) : NULL;
    cepCell* l1_metrics_root = flow_root ? cep_l2_runtime_resolve_child(flow_root, dt_l1_flow_metrics()) : NULL;

    if (!flows_root || !organisms_root || !flow_root || !pipelines_root || !runs_root || !l1_metrics_root) {
        return false;
    }

    (void)cep_l2_runtime_seed_env_harness(data_root);
    (void)cep_l2_runtime_grounder_maze(eco_root, data_root);
    (void)cep_l2_runtime_grounder_social(eco_root, data_root);
    (void)cep_l2_runtime_update_signal_field(eco_root);

    if (!cep_cell_require_dictionary_store(&flows_root) ||
        !cep_cell_require_dictionary_store(&organisms_root) ||
        !cep_cell_require_dictionary_store(&flow_root) ||
        !cep_cell_require_dictionary_store(&pipelines_root) ||
        !cep_cell_require_dictionary_store(&runs_root) ||
        !cep_cell_require_dictionary_store(&l1_metrics_root)) {
        return false;
    }

    (void)cep_l1_runtime_gc_runs(runs_root);
    (void)cep_l1_runtime_verify_edges(runs_root, pipelines_root);
    (void)cep_l1_runtime_rollup_metrics(runs_root, l1_metrics_root);

    bool ok = true;
    const size_t step_budget = 4u;
    cepCell* first_run = cep_cell_first(runs_root);
    for (cepCell* flow = cep_cell_first(flows_root); flow; flow = cep_cell_next(flows_root, flow)) {
        cepCell* resolved = cep_cell_resolve(flow);
        if (!resolved) {
            continue;
        }
        cepDT flow_id = flow->metacell.dt;
        flow_id.glob = 0u;
        cepPipelineMetadata pipeline = {0};
        cep_l2_runtime_pipeline_from_flow(resolved, &flow_id, &pipeline);
        if (first_run) {
            cep_l2_runtime_pipeline_from_run(first_run, &pipeline);
        }
        if (!cep_l2_runtime_step_flow(eco_root, learn_root, organisms_root, resolved, &flow_id, &pipeline, step_budget)) {
            ok = false;
        }
    }

    cep_l2_runtime_run_rat_skills(eco_root, data_root);
    if (cep_l3_awareness_run) {
        cep_l3_awareness_run(eco_root, data_root);
    }
    if (cep_l4_governance_run) {
        cep_l4_governance_run(eco_root, data_root);
    }

    return ok;
}

/* Appends a history entry under `/data/eco/runtime/history` capturing pipeline
 * metadata and ecological context so organism progress stays append-only and
 * replayable. The helper is best-effort: it returns false when the history
 * branch cannot be resolved but does not emit CEI. */
bool cep_l2_runtime_record_history(cepCell* eco_root,
                                   const cepPipelineMetadata* pipeline,
                                   const cepDT* species_id,
                                   const cepDT* variant_id,
                                   const char* note) {
    if (!eco_root) {
        return false;
    }
    cepCell* history_root = cep_l2_runtime_history_root(eco_root);
    if (!history_root) {
        return false;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT entry_name = cep_l2_runtime_autoid();
    cepCell* entry = cep_cell_add_dictionary(history_root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    bool ok = true;
    ok &= cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
    ok &= cep_l2_runtime_put_pipeline_block(entry, pipeline);
    if (species_id && cep_dt_is_valid(species_id)) {
        ok &= cep_cell_put_dt(entry, dt_species_field(), species_id);
    }
    if (variant_id && cep_dt_is_valid(variant_id)) {
        ok &= cep_cell_put_dt(entry, dt_variant_field(), variant_id);
    }
    if (note && note[0]) {
        ok &= cep_cell_put_text(entry, dt_decision_note_field(), note);
    }
    return ok;
}

/* Hydrates a cell for L2 flows with cross-branch policy enforcement and records
 * ecological context alongside Decision Cells when cross-branch reads occur.
 * The helper wraps the standard hydrate API but always enables cross-branch
 * allowance after running `cep_cell_svo_context_guard` so replay evidence is
 * preserved without double-recording decision entries. */
cepHydrateStatus cep_l2_runtime_hydrate_for_enzyme(cepCell* eco_root,
                                                   cep_cell_ref_t* ref,
                                                   const cepEnzymeContext* enz_ctx,
                                                   const cep_hydrate_opts_t* opts,
                                                   const cepPipelineMetadata* pipeline,
                                                   const cepDT* species_id,
                                                   const cepDT* variant_id) {
    if (!eco_root || !ref || !ref->cell) {
        return CEP_HYDRATE_STATUS_INVALID_ARGUMENT;
    }

    cepCellSvoContext guard_ctx;
    cep_cell_svo_context_init(&guard_ctx, "eco.hydrate");
    cep_cell_svo_context_set_consumer(&guard_ctx, eco_root);
    cep_cell_svo_context_set_source(&guard_ctx, ref->cell);

    if (!cep_cell_svo_context_guard(&guard_ctx, ref->cell, "cell.cross_read")) {
        return CEP_HYDRATE_STATUS_POLICY;
    }

    cep_hydrate_opts_t adjusted = {
        .view = CEP_HYDRATE_VIEW_LIVE,
        .allow_cross_branch = true,
        .require_decision_cell = false,
        .max_depth = 0u,
        .max_meta_bytes = 0u,
        .max_payload_bytes = 0u,
        .lock_ancestors_ro = false,
        .hydrate_children = false,
        .hydrate_payload = true,
    };
    if (opts) {
        adjusted = *opts;
        adjusted.allow_cross_branch = true;
        adjusted.require_decision_cell = false;
    }

    bool used_l1 = false;
    cepHydrateStatus status = CEP_HYDRATE_STATUS_OK;
    if (adjusted.allow_cross_branch || adjusted.view == CEP_HYDRATE_VIEW_SNAPSHOT_RO) {
        bool snapshot_only = (adjusted.view == CEP_HYDRATE_VIEW_SNAPSHOT_RO);
        if (cep_l1_coh_hydrate_safe(ref, enz_ctx, adjusted.allow_cross_branch, snapshot_only)) {
            used_l1 = true;
            status = CEP_HYDRATE_STATUS_OK;
        }
    }

    if (!used_l1) {
        cep_hydrate_result_t result = {0};
        status = cep_cell_hydrate_for_enzyme(ref, enz_ctx, &adjusted, &result);
        if (status != CEP_HYDRATE_STATUS_OK) {
            return status;
        }
    }

    const char* risk_label = cep_branch_policy_risk_label(guard_ctx.last_result.risk);
    if (!risk_label) {
        risk_label = "none";
    }
    cepCell* decisions_root = cep_l2_runtime_decisions_root(eco_root);
    if (decisions_root) {
        const cepBranchController* consumer = guard_ctx.consumer ? guard_ctx.consumer : guard_ctx.source;
        const cepBranchController* source = guard_ctx.source ? guard_ctx.source : guard_ctx.consumer;
        if (consumer && source) {
            (void)cep_l2_runtime_log_decision(decisions_root,
                                              pipeline,
                                              species_id,
                                              variant_id,
                                              risk_label,
                                              consumer,
                                              source,
                                              guard_ctx.decision_recorded);
        }
    }

    return status;
}
