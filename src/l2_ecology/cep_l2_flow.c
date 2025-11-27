/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_flow.h"
#include "cep_l2_runtime.h"

#include "../l0_kernel/cep_cei.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_molecule.h"
#include "../l0_kernel/cep_namepool.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    cepL2CompiledNode* nodes;
    size_t             count;
    int                entry_index;
} cepL2CompiledFlow;

CEP_DEFINE_STATIC_DT(dt_graph, CEP_ACRO("CEP"), CEP_WORD("graph"));
CEP_DEFINE_STATIC_DT(dt_nodes, CEP_ACRO("CEP"), CEP_WORD("nodes"));
CEP_DEFINE_STATIC_DT(dt_entry, CEP_ACRO("CEP"), CEP_WORD("entry"));
CEP_DEFINE_STATIC_DT(dt_node_type_field, CEP_ACRO("CEP"), CEP_WORD("node_type"));
CEP_DEFINE_STATIC_DT(dt_next_field, CEP_ACRO("CEP"), CEP_WORD("next"));
CEP_DEFINE_STATIC_DT(dt_alt_field, CEP_ACRO("CEP"), CEP_WORD("alt_next"));
CEP_DEFINE_STATIC_DT(dt_pred_field, CEP_ACRO("CEP"), CEP_WORD("pred"));
CEP_DEFINE_STATIC_DT(dt_actions_field, CEP_ACRO("CEP"), CEP_WORD("actions"));
CEP_DEFINE_STATIC_DT(dt_wait_kind_field, CEP_ACRO("CEP"), CEP_WORD("wait_kind"));
CEP_DEFINE_STATIC_DT(dt_resume_bt_field, CEP_ACRO("CEP"), CEP_WORD("resume_bt"));
CEP_DEFINE_STATIC_DT(dt_choices_field, CEP_ACRO("CEP"), CEP_WORD("choices"));
CEP_DEFINE_STATIC_DT(dt_choice_field, CEP_ACRO("CEP"), CEP_WORD("choice"));
CEP_DEFINE_STATIC_DT(dt_selected_field, CEP_ACRO("CEP"), CEP_WORD("selected"));
CEP_DEFINE_STATIC_DT(dt_guardian_field, CEP_ACRO("CEP"), CEP_WORD("guardian"));
CEP_DEFINE_STATIC_DT(dt_guardians_field, CEP_ACRO("CEP"), CEP_WORD("guardians"));
CEP_DEFINE_STATIC_DT(dt_budgets_field, CEP_ACRO("CEP"), CEP_WORD("budgets"));
CEP_DEFINE_STATIC_DT(dt_max_steps_field, CEP_ACRO("CEP"), CEP_WORD("max_steps"));
CEP_DEFINE_STATIC_DT(dt_max_beats_field, CEP_ACRO("CEP"), CEP_WORD("max_beats"));
CEP_DEFINE_STATIC_DT(dt_on_violation_field, CEP_ACRO("CEP"), CEP_WORD("on_violate"));
CEP_DEFINE_STATIC_DT(dt_metrics_field, CEP_ACRO("CEP"), CEP_WORD("metrics"));
CEP_DEFINE_STATIC_DT(dt_history_field, CEP_ACRO("CEP"), CEP_WORD("history"));
CEP_DEFINE_STATIC_DT(dt_status_field, CEP_ACRO("CEP"), CEP_WORD("status"));
CEP_DEFINE_STATIC_DT(dt_node_ptr_field, CEP_ACRO("CEP"), CEP_WORD("node_ptr"));
CEP_DEFINE_STATIC_DT(dt_created_bt_field, CEP_ACRO("CEP"), CEP_WORD("created_bt"));
CEP_DEFINE_STATIC_DT(dt_updated_bt_field, CEP_ACRO("CEP"), CEP_WORD("updated_bt"));
CEP_DEFINE_STATIC_DT(dt_flow_field, CEP_ACRO("CEP"), CEP_WORD("flow"));
CEP_DEFINE_STATIC_DT(dt_species_field, CEP_ACRO("CEP"), CEP_WORD("species"));
CEP_DEFINE_STATIC_DT(dt_variant_field, CEP_ACRO("CEP"), CEP_WORD("variant"));
CEP_DEFINE_STATIC_DT(dt_niche_field, CEP_ACRO("CEP"), CEP_WORD("niche"));
CEP_DEFINE_STATIC_DT(dt_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_model_update_field, CEP_ACRO("CEP"), CEP_WORD("model_upd"));
CEP_DEFINE_STATIC_DT(dt_payload_field, CEP_ACRO("CEP"), CEP_WORD("payload"));
CEP_DEFINE_STATIC_DT(dt_parents_field, CEP_ACRO("CEP"), CEP_WORD("parents"));
CEP_DEFINE_STATIC_DT(dt_rev_field, CEP_ACRO("CEP"), CEP_WORD("rev"));
CEP_DEFINE_STATIC_DT(dt_models_root, CEP_ACRO("CEP"), CEP_WORD("models"));
CEP_DEFINE_STATIC_DT(dt_revisions_root, CEP_ACRO("CEP"), CEP_WORD("revisions"));
CEP_DEFINE_STATIC_DT(dt_decision_root_name, CEP_ACRO("CEP"), CEP_WORD("decisions"));
CEP_DEFINE_STATIC_DT(dt_pipeline_field, CEP_ACRO("CEP"), CEP_WORD("pipeline"));
CEP_DEFINE_STATIC_DT(dt_decision_flow_field, CEP_ACRO("CEP"), CEP_WORD("flow"));
CEP_DEFINE_STATIC_DT(dt_decision_node_field, CEP_ACRO("CEP"), CEP_WORD("node"));
CEP_DEFINE_STATIC_DT(dt_decision_choice_field, CEP_ACRO("CEP"), CEP_WORD("choice"));
CEP_DEFINE_STATIC_DT(dt_decision_kind_field, CEP_ACRO("CEP"), CEP_WORD("kind"));
CEP_DEFINE_STATIC_DT(dt_decision_kind_policy, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco.policy"));
CEP_DEFINE_STATIC_DT(dt_runtime_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_runtime_organisms, CEP_ACRO("CEP"), cep_namepool_intern_cstr("organisms"));
CEP_DEFINE_STATIC_DT(dt_runtime_metrics, CEP_ACRO("CEP"), cep_namepool_intern_cstr("metrics"));
CEP_DEFINE_STATIC_DT(dt_runtime_history, CEP_ACRO("CEP"), cep_namepool_intern_cstr("history"));
CEP_DEFINE_STATIC_DT(dt_runtime_decisions, CEP_ACRO("CEP"), cep_namepool_intern_cstr("decisions"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_species, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_species"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_variant, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_variant"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_niche, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_niche"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_global, CEP_ACRO("CEP"), cep_namepool_intern_cstr("global"));
CEP_DEFINE_STATIC_DT(dt_pipeline_id_field, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_stage_id_field, CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_dag_run_id_field, CEP_ACRO("CEP"), CEP_WORD("dag_run_id"));
CEP_DEFINE_STATIC_DT(dt_hop_index_field, CEP_ACRO("CEP"), CEP_WORD("hop_index"));
CEP_DEFINE_STATIC_DT(dt_topic_guardian_violation, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco.guardian.violation"));
CEP_DEFINE_STATIC_DT(dt_topic_limit_hit, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco.limit.hit"));
CEP_DEFINE_STATIC_DT(dt_topic_flow_error, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco.flow.error"));
CEP_DEFINE_STATIC_DT(dt_topic_evolution, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco.evolution.proposed"));
CEP_DEFINE_STATIC_DT(dt_sev_info, CEP_ACRO("CEP"), CEP_WORD("sev:info"));
CEP_DEFINE_STATIC_DT(dt_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_sev_crit, CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_org_state_running, CEP_ACRO("CEP"), CEP_WORD("running"));
CEP_DEFINE_STATIC_DT(dt_org_state_waiting, CEP_ACRO("CEP"), CEP_WORD("waiting"));
CEP_DEFINE_STATIC_DT(dt_org_state_finished, CEP_ACRO("CEP"), CEP_WORD("finished"));
CEP_DEFINE_STATIC_DT(dt_org_state_failed, CEP_ACRO("CEP"), CEP_WORD("failed"));
static bool cep_l2_flow_node_id_matches(const cepDT* lhs, const cepDT* rhs);
static void cep_l2_flow_emit_cei(const cepL2OrganismContext* ctx,
                                 const cepDT* topic,
                                 const cepDT* severity,
                                 const char* note,
                                 cepOID op);
static cepCell* cep_l2_flow_metrics_root(cepCell* eco_root);
static void cep_l2_flow_bump_metric(cepCell* metrics_root,
                                    const cepDT* bucket_name,
                                    const cepDT* id,
                                    const char* metric_tag,
                                    uint64_t delta);
static void cep_l2_flow_record_history(cepL2OrganismContext* ctx, const char* note);
CEP_DEFINE_STATIC_DT(dt_app_root_name, CEP_ACRO("CEP"), CEP_WORD("app"));
CEP_DEFINE_STATIC_DT(dt_calc_root_name, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc"));
CEP_DEFINE_STATIC_DT(dt_calc_exprs_name, CEP_ACRO("CEP"), cep_namepool_intern_cstr("exprs"));
CEP_DEFINE_STATIC_DT(dt_calc_results_name, CEP_ACRO("CEP"), cep_namepool_intern_cstr("results"));
CEP_DEFINE_STATIC_DT(dt_calc_left_field, CEP_ACRO("CEP"), CEP_WORD("left"));
CEP_DEFINE_STATIC_DT(dt_calc_right_field, CEP_ACRO("CEP"), CEP_WORD("right"));
CEP_DEFINE_STATIC_DT(dt_calc_op_field, CEP_ACRO("CEP"), CEP_WORD("op"));
CEP_DEFINE_STATIC_DT(dt_calc_value_field, CEP_ACRO("CEP"), CEP_WORD("value"));
CEP_DEFINE_STATIC_DT(dt_calc_metric_eval, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_eval"));
CEP_DEFINE_STATIC_DT(dt_calc_variant_safe, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_safe"));
CEP_DEFINE_STATIC_DT(dt_calc_variant_fast, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_fast"));

static cepDT cep_l2_flow_auto_name(void) {
    cepDT name = {0};
    name.domain = CEP_ACRO("CEP");
    name.tag = CEP_AUTOID;
    return name;
}

static bool cep_l2_flow_require_dict(cepCell* parent, const cepDT* name, cepCell** out) {
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

static bool cep_l2_flow_read_u64(cepCell* parent, const cepDT* field, uint64_t* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&child, &data) || !data) {
        return false;
    }
    if (data->size >= sizeof(uint64_t)) {
        uint64_t value = 0u;
        memcpy(&value, cep_data_payload(data), sizeof value);
        *out = value;
        return true;
    }
    const char* text = (const char*)cep_data_payload(data);
    if (text) {
        char* endptr = NULL;
        unsigned long long parsed = strtoull(text, &endptr, 10);
        if (endptr && *endptr == '\0') {
            *out = (uint64_t)parsed;
            return true;
        }
    }
    return false;
}

static bool cep_l2_flow_read_text(cepCell* parent, const cepDT* field, const char** out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    *out = (const char*)cep_cell_data(child);
    return true;
}

static bool cep_l2_flow_eval_calc_expr(cepL2OrganismContext* ctx) {
    if (!ctx || !ctx->eco_root) {
        return false;
    }
    cepCell* data_root = cep_cell_parent(ctx->eco_root);
    cepCell* app_root = data_root ? cep_cell_find_by_name(data_root, dt_app_root_name()) : NULL;
    app_root = app_root ? cep_cell_resolve(app_root) : NULL;
    if (!app_root || !cep_cell_require_dictionary_store(&app_root)) {
        return false;
    }
    cepCell* calc_root = cep_cell_find_by_name(app_root, dt_calc_root_name());
    calc_root = calc_root ? cep_cell_resolve(calc_root) : NULL;
    if (!calc_root || !cep_cell_require_dictionary_store(&calc_root)) {
        return false;
    }

    cepCell* exprs = cep_cell_find_by_name(calc_root, dt_calc_exprs_name());
    cepCell* results = cep_cell_find_by_name(calc_root, dt_calc_results_name());
    exprs = exprs ? cep_cell_resolve(exprs) : NULL;
    results = results ? cep_cell_resolve(results) : NULL;
    if (!exprs || !results) {
        return false;
    }

    cepCell* expr = cep_cell_first(exprs);
    if (!expr) {
        return true;
    }

    cepCell* resolved = cep_cell_resolve(expr);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    const char* left_text = NULL;
    const char* right_text = NULL;
    const char* op_text = NULL;
    if (!cep_l2_flow_read_text(resolved, dt_calc_left_field(), &left_text) ||
        !cep_l2_flow_read_text(resolved, dt_calc_right_field(), &right_text) ||
        !cep_l2_flow_read_text(resolved, dt_calc_op_field(), &op_text) ||
        !left_text || !right_text || !op_text) {
        return false;
    }

    long long left = strtoll(left_text, NULL, 10);
    long long right = strtoll(right_text, NULL, 10);
    char op_char = op_text[0];
    bool fast_variant = cep_l2_flow_node_id_matches(&ctx->variant_id, dt_calc_variant_fast());
    bool safe_variant = cep_l2_flow_node_id_matches(&ctx->variant_id, dt_calc_variant_safe());
    if (!fast_variant && !safe_variant) {
        fast_variant = true;
    }

    bool valid = true;
    long long value = 0;
    switch (op_char) {
        case '+':
            value = left + right;
            break;
        case '-':
            value = left - right;
            break;
        case '*':
            value = left * right;
            break;
        case '/':
            if (right == 0) {
                if (safe_variant) {
                    cep_l2_flow_emit_cei(ctx, dt_topic_flow_error(), dt_sev_warn(), "calc_div_zero", ctx->episode_oid);
                    valid = false;
                } else {
                    value = 0;
                }
            } else {
                value = left / right;
            }
            break;
        default:
            valid = false;
            cep_l2_flow_emit_cei(ctx, dt_topic_flow_error(), dt_sev_warn(), "calc_unknown_op", ctx->episode_oid);
            break;
    }
    if (!valid) {
        return false;
    }

    cepDT result_name = expr->metacell.dt;
    result_name.glob = 0u;
    cepCell* result = cep_cell_add_dictionary(results, &result_name, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    result = result ? cep_cell_resolve(result) : NULL;
    if (!result || !cep_cell_require_dictionary_store(&result)) {
        return false;
    }
    (void)cep_cell_put_text(result, dt_calc_left_field(), left_text);
    (void)cep_cell_put_text(result, dt_calc_right_field(), right_text);
    (void)cep_cell_put_text(result, dt_calc_op_field(), op_text);
    char value_buf[64];
    snprintf(value_buf, sizeof value_buf, "%lld", value);
    (void)cep_cell_put_text(result, dt_calc_value_field(), value_buf);

    cep_cell_delete_hard(resolved);

    cepCell* metrics_root = cep_l2_flow_metrics_root(ctx->eco_root);
    const char* metric_tag = cep_namepool_lookup(dt_calc_metric_eval()->tag, NULL);
    if (!metric_tag) {
        metric_tag = "calc_eval";
    }
    fprintf(stderr,
            "[l2_flow] bump metric variant=%llu metric=%s\n",
            (unsigned long long)ctx->variant_id.tag,
            metric_tag);
    cep_l2_flow_bump_metric(metrics_root, dt_eco_metrics_global(), NULL, metric_tag, 1u);
    if (cep_dt_is_valid(&ctx->variant_id)) {
        cep_l2_flow_bump_metric(metrics_root, dt_eco_metrics_per_variant(), &ctx->variant_id, metric_tag, 1u);
    }
    cep_l2_flow_record_history(ctx, "calc_eval");
    return true;
}
static bool cep_l2_flow_put_pipeline_block(cepCell* parent, const cepPipelineMetadata* pipeline) {
    if (!parent || !pipeline) {
        return true;
    }
    cepCell* pipeline_root = NULL;
    if (!cep_l2_flow_require_dict(parent, dt_pipeline_field(), &pipeline_root)) {
        return false;
    }
    bool ok = true;
    fprintf(stderr,
            "[l2_flow] pipeline block pid=%llu sid=%llu\n",
            (unsigned long long)pipeline->pipeline_id,
            (unsigned long long)pipeline->stage_id);
    if (pipeline->pipeline_id) {
        const char* text = cep_namepool_lookup(pipeline->pipeline_id, NULL);
        if (text) {
            ok &= cep_cell_put_text(pipeline_root, dt_pipeline_id_field(), text);
        } else {
            ok &= cep_cell_put_uint64(pipeline_root, dt_pipeline_id_field(), (uint64_t)pipeline->pipeline_id);
        }
    }
    if (pipeline->stage_id) {
        const char* text = cep_namepool_lookup(pipeline->stage_id, NULL);
        if (text) {
            ok &= cep_cell_put_text(pipeline_root, dt_stage_id_field(), text);
        } else {
            ok &= cep_cell_put_uint64(pipeline_root, dt_stage_id_field(), (uint64_t)pipeline->stage_id);
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

static cepCell* cep_l2_flow_metrics_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    if (!runtime_root) {
        return NULL;
    }
    cepCell* metrics_root = cep_cell_find_by_name(runtime_root, dt_runtime_metrics());
    metrics_root = metrics_root ? cep_cell_resolve(metrics_root) : NULL;
    return metrics_root;
}

static cepCell* cep_l2_flow_metrics_bucket(cepCell* metrics_root, const cepDT* bucket_name, const cepDT* id) {
    if (!metrics_root || !bucket_name) {
        return NULL;
    }
    cepCell* bucket = cep_cell_find_by_name(metrics_root, bucket_name);
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

static void cep_l2_flow_bump_metric(cepCell* metrics_root,
                                    const cepDT* bucket_name,
                                    const cepDT* id,
                                    const char* metric_tag,
                                    uint64_t delta) {
    if (!metrics_root || !metric_tag) {
        return;
    }
    cepCell* bucket = cep_l2_flow_metrics_bucket(metrics_root, bucket_name, id);
    if (!bucket) {
        fprintf(stderr,
                "[l2_flow] missing metrics bucket bucket=%s id=%llu\n",
                bucket_name ? cep_namepool_lookup(bucket_name->tag, NULL) : "<null>",
                id ? (unsigned long long)id->tag : 0u);
        return;
    }
    cepDT metric_dt = {0};
    cepID tag = cep_namepool_intern(metric_tag, strlen(metric_tag));
    if (!tag) {
        return;
    }
    metric_dt.domain = CEP_ACRO("CEP");
    metric_dt.tag = tag;
    metric_dt.glob = 0u;

    uint64_t current = 0u;
    (void)cep_l2_flow_read_u64(bucket, &metric_dt, &current);
    (void)cep_cell_put_uint64(bucket, &metric_dt, current + delta);
}

static void cep_l2_flow_record_history(cepL2OrganismContext* ctx, const char* note) {
    if (!ctx) {
        return;
    }
    (void)cep_l2_runtime_record_history(ctx->eco_root, &ctx->pipeline, &ctx->species_id, &ctx->variant_id, note);
    cepCell* metrics_root = cep_l2_flow_metrics_root(ctx->eco_root);
    cep_l2_flow_bump_metric(metrics_root, dt_eco_metrics_global(), NULL, "history", 1u);
}

static void cep_l2_flow_update_status_cell(cepCell* organism_cell, const cepDT* status_dt) {
    if (!organism_cell || !status_dt) {
        return;
    }
    (void)cep_cell_put_dt(organism_cell, dt_status_field(), status_dt);
}

static void cep_l2_flow_sync_context_from_cell(cepL2OrganismContext* ctx) {
    if (!ctx || !ctx->organism) {
        return;
    }
    uint64_t created = 0u;
    if (cep_l2_flow_read_u64(ctx->organism, dt_created_bt_field(), &created)) {
        ctx->created_beat = created;
    } else {
        ctx->created_beat = (uint64_t)cep_beat_index();
    }
    uint64_t updated = 0u;
    if (cep_l2_flow_read_u64(ctx->organism, dt_updated_bt_field(), &updated)) {
        ctx->last_beat = updated;
    }
    cepDT node_ptr = {0};
    cepCell* node_cell = cep_cell_find_by_name(ctx->organism, dt_node_ptr_field());
    node_cell = node_cell ? cep_cell_resolve(node_cell) : NULL;
    if (node_cell && cep_cell_require_dictionary_store(&node_cell)) {
        cepCell* domain_cell = cep_cell_find_by_name(node_cell, CEP_DTAW("CEP", "domain"));
        cepCell* tag_cell = cep_cell_find_by_name(node_cell, CEP_DTAW("CEP", "tag"));
        if (domain_cell && tag_cell && cep_cell_has_data(domain_cell) && cep_cell_has_data(tag_cell)) {
            uint64_t domain = 0u;
            uint64_t tag = 0u;
            memcpy(&domain, cep_cell_data(domain_cell), sizeof domain);
            memcpy(&tag, cep_cell_data(tag_cell), sizeof tag);
            node_ptr.domain = (cepID)domain;
            node_ptr.tag = (cepID)tag;
            ctx->current_node = node_ptr;
        }
    }

    cepCell* status_cell = cep_cell_find_by_name(ctx->organism, dt_status_field());
    status_cell = status_cell ? cep_cell_resolve(status_cell) : NULL;
    ctx->status = CEP_L2_ORG_RUNNING;
    if (status_cell && cep_cell_require_dictionary_store(&status_cell)) {
        uint64_t domain = 0u;
        uint64_t tag = 0u;
        if (cep_l2_flow_read_u64(status_cell, CEP_DTAW("CEP", "domain"), &domain) &&
            cep_l2_flow_read_u64(status_cell, CEP_DTAW("CEP", "tag"), &tag)) {
            cepDT status_dt = {.domain = (cepID)domain, .tag = (cepID)tag, .glob = 0u};
            if (cep_l2_flow_node_id_matches(&status_dt, dt_org_state_waiting())) {
                ctx->status = CEP_L2_ORG_WAITING;
            } else if (cep_l2_flow_node_id_matches(&status_dt, dt_org_state_finished())) {
                ctx->status = CEP_L2_ORG_FINISHED;
            } else if (cep_l2_flow_node_id_matches(&status_dt, dt_org_state_failed())) {
                ctx->status = CEP_L2_ORG_FAILED;
            }
        }
    }
}

static void cep_l2_flow_store_progress(cepL2OrganismContext* ctx, const cepDT* next_node, const cepDT* status) {
    if (!ctx || !ctx->organism) {
        return;
    }
    uint64_t beat = (uint64_t)cep_beat_index();
    if (next_node && cep_dt_is_valid(next_node)) {
        (void)cep_cell_put_dt(ctx->organism, dt_node_ptr_field(), next_node);
        ctx->current_node = *next_node;
    } else {
        ctx->current_node = (cepDT){0};
    }
    (void)cep_cell_put_uint64(ctx->organism, dt_updated_bt_field(), beat);
    ctx->last_beat = beat;
    if (status) {
        cep_l2_flow_update_status_cell(ctx->organism, status);
    }
}

static bool cep_l2_flow_node_id_matches(const cepDT* lhs, const cepDT* rhs) {
    if (!lhs || !rhs) {
        return false;
    }
    return cep_dt_compare(lhs, rhs) == 0;
}

static int cep_l2_flow_find_node(const cepL2CompiledFlow* compiled, const cepDT* node_id) {
    if (!compiled || !node_id) {
        return -1;
    }
    for (size_t i = 0; i < compiled->count; ++i) {
        if (cep_l2_flow_node_id_matches(&compiled->nodes[i].node_id, node_id)) {
            return (int)i;
        }
    }
    return -1;
}

static bool cep_l2_flow_read_successor(cepCell* node_cell, const cepDT* field, cepDT* out) {
    if (!node_cell || !field || !out) {
        return false;
    }
    cepCell* child = cep_cell_find_by_name(node_cell, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child) {
        return false;
    }
    if (cep_cell_has_data(child)) {
        const char* text = (const char*)cep_cell_data(child);
        if (!text || !*text) {
            return false;
        }
        cepID tag = cep_namepool_intern(text, strlen(text));
        if (!tag) {
            return false;
        }
        out->domain = CEP_ACRO("CEP");
        out->tag = tag;
        out->glob = 0u;
        return true;
    }
    if (cep_cell_require_dictionary_store(&child)) {
        uint64_t domain = 0u;
        uint64_t tag = 0u;
        if (cep_l2_flow_read_u64(child, CEP_DTAW("CEP", "domain"), &domain) &&
            cep_l2_flow_read_u64(child, CEP_DTAW("CEP", "tag"), &tag)) {
            out->domain = (cepID)domain;
            out->tag = (cepID)tag;
            out->glob = 0u;
            return true;
        }
    }
    return false;
}

static bool cep_l2_flow_read_node_type(cepCell* node_cell, cepL2NodeType* out) {
    const char* text = NULL;
    if (!node_cell || !out || !cep_l2_flow_read_text(node_cell, dt_node_type_field(), &text)) {
        return false;
    }
    if (strcmp(text, "guard") == 0) {
        *out = CEP_L2_NODE_GUARD;
    } else if (strcmp(text, "transform") == 0) {
        *out = CEP_L2_NODE_TRANSFORM;
    } else if (strcmp(text, "wait") == 0) {
        *out = CEP_L2_NODE_WAIT;
    } else if (strcmp(text, "decide") == 0) {
        *out = CEP_L2_NODE_DECIDE;
    } else if (strcmp(text, "clamp") == 0) {
        *out = CEP_L2_NODE_CLAMP;
    } else {
        return false;
    }
    return true;
}

static bool cep_l2_flow_compile_nodes(cepCell* nodes_root, cepL2CompiledFlow* compiled) {
    if (!nodes_root || !compiled) {
        return false;
    }

    size_t count = 0u;
    for (cepCell* node = cep_cell_first(nodes_root); node; node = cep_cell_next(nodes_root, node)) {
        cepCell* resolved = cep_cell_resolve(node);
        cepL2NodeType type = CEP_L2_NODE_GUARD;
        if (!resolved || !cep_l2_flow_read_node_type(resolved, &type)) {
            continue;
        }
        ++count;
    }
    if (count == 0u) {
        return false;
    }
    cepL2CompiledNode* nodes = cep_malloc0(count * sizeof *nodes);
    size_t index = 0u;
    for (cepCell* node = cep_cell_first(nodes_root); node; node = cep_cell_next(nodes_root, node)) {
        cepCell* resolved = cep_cell_resolve(node);
        cepL2NodeType type = CEP_L2_NODE_GUARD;
        if (!resolved || !cep_l2_flow_read_node_type(resolved, &type)) {
            continue;
        }
        cepL2CompiledNode* slot = &nodes[index++];
        cepDT node_id = node->metacell.dt;
        node_id.glob = 0u;
        slot->node_id = node_id;
        slot->node_cell = resolved;
        slot->type = type;
        (void)cep_l2_flow_read_successor(resolved, dt_next_field(), &slot->successor);
        (void)cep_l2_flow_read_successor(resolved, dt_alt_field(), &slot->alt_successor);
        slot->yields = (slot->type == CEP_L2_NODE_WAIT || slot->type == CEP_L2_NODE_CLAMP);
    }
    compiled->nodes = nodes;
    compiled->count = index;

    cepDT entry_id = {0};
    if (!cep_l2_flow_read_successor(nodes_root, dt_entry(), &entry_id)) {
        compiled->entry_index = 0;
    } else {
        compiled->entry_index = cep_l2_flow_find_node(compiled, &entry_id);
    }
    if (compiled->entry_index < 0) {
        compiled->entry_index = 0;
    }
    return true;
}

static void cep_l2_flow_compiled_free(cepL2CompiledFlow* compiled) {
    if (!compiled) {
        return;
    }
    if (compiled->nodes) {
        cep_free(compiled->nodes);
    }
    compiled->nodes = NULL;
    compiled->count = 0u;
    compiled->entry_index = -1;
}

static void cep_l2_flow_emit_cei(const cepL2OrganismContext* ctx,
                                 const cepDT* topic,
                                 const cepDT* severity,
                                 const char* note,
                                 cepOID op) {
    if (!topic || !severity) {
        return;
    }
    cepCeiRequest req = {
        .severity = *severity,
        .topic = cep_namepool_lookup(topic->tag, NULL),
        .topic_len = 0u,
        .note = note,
        .note_len = 0u,
        .emit_signal = true,
        .attach_to_op = cep_oid_is_valid(op),
        .op = op,
    };
    if (ctx && ctx->pipeline.pipeline_id) {
        req.has_pipeline = true;
        req.pipeline = ctx->pipeline;
    }
    (void)cep_cei_emit(&req);
}

static bool cep_l2_flow_guard_passes(cepCell* node_cell) {
    uint64_t pred_val = 0u;
    if (cep_l2_flow_read_u64(node_cell, dt_pred_field(), &pred_val)) {
        return pred_val != 0u;
    }
    const char* pred_text = NULL;
    if (cep_l2_flow_read_text(node_cell, dt_pred_field(), &pred_text)) {
        return pred_text && (strcmp(pred_text, "true") == 0 || strcmp(pred_text, "pass") == 0);
    }
    return true;
}

static bool cep_l2_flow_transform(cepL2OrganismContext* ctx, cepCell* node_cell) {
    bool ok = true;
    const char* note = NULL;
    if (cep_l2_flow_read_text(node_cell, dt_note_field(), &note) && note) {
        cep_l2_flow_record_history(ctx, note);
    }
    cepCell* actions = cep_cell_find_by_name(node_cell, dt_actions_field());
    actions = actions ? cep_cell_resolve(actions) : NULL;
    if (actions && cep_cell_require_dictionary_store(&actions)) {
        for (cepCell* action = cep_cell_first(actions); action; action = cep_cell_next(actions, action)) {
            cepCell* resolved = cep_cell_resolve(action);
            if (!resolved) {
                continue;
            }
            const char* action_text = (const char*)cep_cell_data(resolved);
            if (action_text && strcmp(action_text, "history") == 0) {
                cep_l2_flow_record_history(ctx, "transform");
                continue;
            }
            if (action_text && strcmp(action_text, "calc_eval") == 0) {
                ok &= cep_l2_flow_eval_calc_expr(ctx);
                continue;
            }
            if (cep_cell_find_by_name(resolved, dt_model_update_field())) {
                // handled below
                continue;
            }
        }
    }
    cepCell* model_update = cep_cell_find_by_name(node_cell, dt_model_update_field());
    model_update = model_update ? cep_cell_resolve(model_update) : NULL;
    if (model_update && ctx && ctx->learn_root) {
        cepCell* models_root = cep_cell_find_by_name(ctx->learn_root, dt_models_root());
        models_root = models_root ? cep_cell_resolve(models_root) : NULL;
        cepCell* revisions_root = cep_cell_find_by_name(ctx->learn_root, dt_revisions_root());
        revisions_root = revisions_root ? cep_cell_resolve(revisions_root) : NULL;
        if (models_root && revisions_root) {
            cepDT model_name = ctx->species_id;
            if (!cep_dt_is_valid(&model_name)) {
                model_name = ctx->flow_id;
            }
            cepCell* model_root = cep_cell_ensure_dictionary_child(models_root, &model_name, CEP_STORAGE_RED_BLACK_T);
            model_root = model_root ? cep_cell_resolve(model_root) : NULL;
            if (model_root && cep_cell_require_dictionary_store(&model_root)) {
                cepDT revision_name = cep_l2_flow_auto_name();
                cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
                cepCell* rev = cep_cell_add_dictionary(model_root, &revision_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
                rev = rev ? cep_cell_resolve(rev) : NULL;
                if (rev && cep_cell_require_dictionary_store(&rev)) {
                    uint64_t beat = (uint64_t)cep_beat_index();
                    ok &= cep_cell_put_uint64(rev, dt_rev_field(), beat);
                    ok &= cep_cell_put_uint64(rev, dt_created_bt_field(), beat);
                    if (cep_dt_is_valid(&ctx->species_id)) {
                        ok &= cep_cell_put_dt(rev, dt_species_field(), &ctx->species_id);
                    }
                    if (cep_dt_is_valid(&ctx->variant_id)) {
                        ok &= cep_cell_put_dt(rev, dt_variant_field(), &ctx->variant_id);
                    }
                    ok &= cep_l2_flow_put_pipeline_block(rev, &ctx->pipeline);
                    const char* mu_note = NULL;
                    if (cep_l2_flow_read_text(model_update, dt_note_field(), &mu_note) && mu_note) {
                        ok &= cep_cell_put_text(rev, dt_note_field(), mu_note);
                    }
                    cepCell* parents = NULL;
                    if (cep_l2_flow_require_dict(rev, dt_parents_field(), &parents)) {
                        (void)cep_cell_put_uint64(parents, dt_rev_field(), beat - 1u);
                    }
                    cepCell* mirror = cep_cell_add_dictionary(revisions_root, &revision_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
                    mirror = mirror ? cep_cell_resolve(mirror) : NULL;
                    if (mirror && cep_cell_require_dictionary_store(&mirror)) {
                        if (cep_dt_is_valid(&ctx->species_id)) {
                            ok &= cep_cell_put_dt(mirror, dt_species_field(), &ctx->species_id);
                        }
                        if (cep_dt_is_valid(&ctx->variant_id)) {
                            ok &= cep_cell_put_dt(mirror, dt_variant_field(), &ctx->variant_id);
                        }
                        ok &= cep_cell_put_dt(mirror, CEP_DTAW("CEP", "target"), &revision_name);
                        ok &= cep_l2_flow_put_pipeline_block(mirror, &ctx->pipeline);
                    }
                } else {
                    ok = false;
                }
            } else {
                ok = false;
            }
        }
    }
    return ok;
}

static bool cep_l2_flow_wait_ready(cepL2OrganismContext* ctx, cepCell* node_cell) {
    if (!ctx || !node_cell) {
        return false;
    }
    uint64_t resume_bt = 0u;
    if (cep_l2_flow_read_u64(node_cell, dt_resume_bt_field(), &resume_bt)) {
        uint64_t now = (uint64_t)cep_beat_index();
        if (now < resume_bt) {
            ctx->status = CEP_L2_ORG_WAITING;
            return false;
        }
    }
    return true;
}

static cepCell* cep_l2_flow_decisions_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    if (!runtime_root) {
        return NULL;
    }
    cepCell* decisions = cep_cell_find_by_name(runtime_root, dt_runtime_decisions());
    decisions = decisions ? cep_cell_resolve(decisions) : NULL;
    if (!decisions || !cep_cell_require_dictionary_store(&decisions)) {
        return NULL;
    }
    return decisions;
}

static const char* cep_l2_flow_choice_from_decisions(cepL2OrganismContext* ctx,
                                                     const cepDT* node_id,
                                                     bool* out_record_needed) {
    if (out_record_needed) {
        *out_record_needed = false;
    }
    if (!ctx || !node_id) {
        return NULL;
    }
    cepCell* decisions = cep_l2_flow_decisions_root(ctx->eco_root);
    if (!decisions) {
        return NULL;
    }

    const char* pending_choice = NULL;
    bool pending_valid = false;
    for (cepCell* entry = cep_cell_first(decisions); entry; entry = cep_cell_next(decisions, entry)) {
        cepCell* resolved = cep_cell_resolve(entry);
        if (!resolved) {
            continue;
        }
        cepDT recorded_node = {0};
        if (!cep_l2_flow_read_successor(resolved, dt_decision_node_field(), &recorded_node)) {
            continue;
        }
        bool node_match = cep_l2_flow_node_id_matches(&recorded_node, node_id);
        const char* choice = NULL;
        if (!cep_l2_flow_read_text(resolved, dt_decision_choice_field(), &choice)) {
            continue;
        }
        /* Prefer previously recorded decisions that already carry pipeline metadata so
         * replay runs do not keep appending copies. */
        cepCell* pipeline_block = cep_cell_find_by_name(resolved, dt_pipeline_field());
        pipeline_block = pipeline_block ? cep_cell_resolve(pipeline_block) : NULL;
        if (pipeline_block && cep_cell_children(pipeline_block) > 0u) {
            return choice;
        }
        if (!node_match) {
            continue;
        }
        if (!pending_valid) {
            pending_choice = choice;
            pending_valid = true;
        }
    }
    if (pending_valid && out_record_needed) {
        *out_record_needed = true;
    }
    return pending_choice;
}

static void cep_l2_flow_record_decision(cepL2OrganismContext* ctx,
                                        const cepDT* node_id,
                                        const char* choice_text) {
    if (!ctx || !node_id || !choice_text) {
        return;
    }
    cepCell* journal = cep_heartbeat_journal_root();
    journal = journal ? cep_cell_resolve(journal) : NULL;
    if (journal && cep_cell_require_dictionary_store(&journal)) {
        cepCell* root = cep_cell_ensure_dictionary_child(journal, dt_decision_root_name(), CEP_STORAGE_RED_BLACK_T);
        root = root ? cep_cell_resolve(root) : NULL;
        if (root && cep_cell_require_dictionary_store(&root)) {
            cepPipelineMetadata pipeline = ctx ? ctx->pipeline : (cepPipelineMetadata){0};
            if (!pipeline.pipeline_id && ctx && cep_dt_is_valid(&ctx->flow_id)) {
                pipeline.pipeline_id = ctx->flow_id.tag;
            }
            cepDT entry_name = cep_l2_flow_auto_name();
            cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
            cepCell* entry = cep_cell_add_dictionary(root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
            entry = entry ? cep_cell_resolve(entry) : NULL;
            if (entry && cep_cell_require_dictionary_store(&entry)) {
                (void)cep_cell_put_uint64(entry, CEP_DTAW("CEP", "beat"), (uint64_t)cep_beat_index());
                (void)cep_cell_put_dt(entry, dt_decision_kind_field(), dt_decision_kind_policy());
                (void)cep_cell_put_dt(entry, dt_decision_flow_field(), &ctx->flow_id);
                (void)cep_cell_put_dt(entry, dt_decision_node_field(), node_id);
                (void)cep_cell_put_text(entry, dt_decision_choice_field(), choice_text);
                (void)cep_l2_flow_put_pipeline_block(entry, &pipeline);
                if (cep_dt_is_valid(&ctx->species_id)) {
                    (void)cep_cell_put_dt(entry, dt_species_field(), &ctx->species_id);
                }
                if (cep_dt_is_valid(&ctx->variant_id)) {
                    (void)cep_cell_put_dt(entry, dt_variant_field(), &ctx->variant_id);
                }
            }
        }
    }

    cepCell* decisions = cep_l2_flow_decisions_root(ctx->eco_root);
    if (decisions && cep_cell_require_dictionary_store(&decisions)) {
        cepDT entry_name = cep_l2_flow_auto_name();
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepCell* entry = cep_cell_add_dictionary(decisions, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
        entry = entry ? cep_cell_resolve(entry) : NULL;
        if (entry && cep_cell_require_dictionary_store(&entry)) {
            cepPipelineMetadata pipeline = ctx ? ctx->pipeline : (cepPipelineMetadata){0};
            if (!pipeline.pipeline_id && ctx && cep_dt_is_valid(&ctx->flow_id)) {
                pipeline.pipeline_id = ctx->flow_id.tag;
            }
            (void)cep_cell_put_dt(entry, dt_decision_flow_field(), &ctx->flow_id);
            (void)cep_cell_put_dt(entry, dt_decision_node_field(), node_id);
            (void)cep_cell_put_text(entry, dt_decision_choice_field(), choice_text);
            (void)cep_cell_put_uint64(entry, CEP_DTAW("CEP", "beat"), (uint64_t)cep_beat_index());
            (void)cep_l2_flow_put_pipeline_block(entry, &pipeline);
        }
    }
}

static const char* cep_l2_flow_choose_option(cepL2OrganismContext* ctx,
                                             cepCell* node_cell,
                                             const cepDT* node_id,
                                             cepDT* next_node) {
    if (!ctx || !node_cell || !node_id || !next_node) {
        return NULL;
    }
    bool record_missing = false;
    const char* recorded = cep_l2_flow_choice_from_decisions(ctx, node_id, &record_missing);
    if (recorded && *recorded) {
        if (record_missing) {
            cep_l2_flow_record_decision(ctx, node_id, recorded);
        }
        return recorded;
    }

    cepCell* choices = cep_cell_find_by_name(node_cell, dt_choices_field());
    choices = choices ? cep_cell_resolve(choices) : NULL;
    size_t choice_count = 0u;
    for (cepCell* c = choices ? cep_cell_first(choices) : NULL; c; c = cep_cell_next(choices, c)) {
        ++choice_count;
    }
    size_t pick_index = 0u;
    if (choice_count > 0u) {
        uint64_t hash = (uint64_t)cep_beat_index();
        hash ^= (uint64_t)cep_id(ctx->flow_id.tag) << 32u;
        hash ^= (uint64_t)cep_id(ctx->current_node.tag);
        pick_index = hash % choice_count;
    }

    size_t cursor = 0u;
    for (cepCell* choice = choices ? cep_cell_first(choices) : NULL; choice; choice = cep_cell_next(choices, choice)) {
        if (cursor == pick_index) {
            cepCell* resolved = cep_cell_resolve(choice);
            if (!resolved) {
                return NULL;
            }
            (void)cep_l2_flow_read_successor(resolved, dt_next_field(), next_node);
            const char* label = (const char*)cep_cell_data(resolved);
            if (label && *label) {
                cep_l2_flow_record_decision(ctx, &ctx->current_node, label);
                return label;
            }
        }
        ++cursor;
    }

    const char* fallback = "default";
    cep_l2_flow_record_decision(ctx, &ctx->current_node, fallback);
    return fallback;
}

static bool cep_l2_flow_guardian_allows(cepL2OrganismContext* ctx, cepCell* guardian_cell) {
    if (!guardian_cell) {
        return true;
    }
    const char* action = NULL;
    bool allowed = true;
    uint64_t allow_u64 = 0u;
    if (cep_l2_flow_read_u64(guardian_cell, CEP_DTAW("CEP", "allow"), &allow_u64)) {
        allowed = allow_u64 != 0u;
    }
    (void)cep_l2_flow_read_text(guardian_cell, dt_on_violation_field(), &action);
    if (!allowed && ctx) {
        cepOID invalid = cep_oid_invalid();
        const cepDT* severity = (action && strcmp(action, "hard") == 0) ? dt_sev_crit() : dt_sev_warn();
        cep_l2_flow_emit_cei(ctx, dt_topic_guardian_violation(), severity, "guardian_violation", invalid);
    }
    return allowed;
}

static bool cep_l2_flow_clamp(cepL2OrganismContext* ctx, cepCell* node_cell, size_t steps_taken) {
    if (!ctx || !node_cell) {
        return false;
    }
    bool ok = true;
    cepCell* budgets = cep_cell_find_by_name(node_cell, dt_budgets_field());
    budgets = budgets ? cep_cell_resolve(budgets) : NULL;
    if (budgets) {
        uint64_t max_steps = 0u;
        if (cep_l2_flow_read_u64(budgets, dt_max_steps_field(), &max_steps) && max_steps > 0u) {
            if (steps_taken >= max_steps) {
                cep_l2_flow_emit_cei(ctx, dt_topic_limit_hit(), dt_sev_warn(), "max_steps", ctx->episode_oid);
                ctx->status = CEP_L2_ORG_FAILED;
                ok = false;
            }
        }
        uint64_t max_beats = 0u;
        if (cep_l2_flow_read_u64(budgets, dt_max_beats_field(), &max_beats) && max_beats > 0u) {
            uint64_t elapsed = (uint64_t)cep_beat_index() - ctx->created_beat;
            if (elapsed > max_beats) {
                cep_l2_flow_emit_cei(ctx, dt_topic_limit_hit(), dt_sev_warn(), "max_beats", ctx->episode_oid);
                ctx->status = CEP_L2_ORG_FAILED;
                ok = false;
            }
        }
    }

    cepCell* guardian_ref = cep_cell_find_by_name(node_cell, dt_guardian_field());
    guardian_ref = guardian_ref ? cep_cell_resolve(guardian_ref) : NULL;
    if (guardian_ref && ok) {
        cepCell* guardian = NULL;
        if (ctx->eco_root) {
            cepCell* guardians_root = cep_cell_find_by_name(ctx->eco_root, dt_guardians_field());
            guardians_root = guardians_root ? cep_cell_resolve(guardians_root) : NULL;
            if (guardians_root && cep_cell_has_data(guardian_ref)) {
                const char* gid = (const char*)cep_cell_data(guardian_ref);
                if (gid) {
                    cepDT gid_dt = {0};
                    gid_dt.domain = CEP_ACRO("CEP");
                    gid_dt.tag = cep_namepool_intern(gid, strlen(gid));
                    guardian = cep_cell_find_by_name(guardians_root, &gid_dt);
                    guardian = guardian ? cep_cell_resolve(guardian) : NULL;
                }
            }
        }
        if (!cep_l2_flow_guardian_allows(ctx, guardian)) {
            ctx->status = CEP_L2_ORG_FAILED;
            ok = false;
        }
    }
    return ok;
}

/* Executes Flow VM nodes for the supplied organism context with a deterministic
 * budget. The helper compiles the flow graph on demand, consumes/records
 * Decision Cells when Decide nodes run, enforces clamp budgets/guardian rules,
 * and persists organism state (status/node pointer/timestamps) so replay stays
 * deterministic. */
bool cep_l2_flow_step(cepL2OrganismContext* ctx, size_t step_budget) {
    if (!ctx || !ctx->flow_root || step_budget == 0u) {
        fprintf(stderr, "[l2_flow] invalid ctx or step_budget\n");
        return false;
    }

    cep_l2_flow_sync_context_from_cell(ctx);
    cepCell* graph = cep_cell_find_by_name(ctx->flow_root, dt_graph());
    graph = graph ? cep_cell_resolve(graph) : NULL;
    if (!graph) {
        fprintf(stderr, "[l2_flow] missing graph\n");
        cep_l2_flow_emit_cei(ctx, dt_topic_flow_error(), dt_sev_warn(), "missing_graph", ctx->episode_oid);
        return false;
    }
    cepCell* nodes_root = cep_cell_find_by_name(graph, dt_nodes());
    nodes_root = nodes_root ? cep_cell_resolve(nodes_root) : NULL;
    if (!nodes_root || !cep_cell_require_dictionary_store(&nodes_root)) {
        fprintf(stderr, "[l2_flow] missing nodes\n");
        cep_l2_flow_emit_cei(ctx, dt_topic_flow_error(), dt_sev_warn(), "missing_nodes", ctx->episode_oid);
        return false;
    }

    cepL2CompiledFlow compiled = {0};
    if (!cep_l2_flow_compile_nodes(nodes_root, &compiled)) {
        fprintf(stderr, "[l2_flow] compile failed\n");
        cep_l2_flow_emit_cei(ctx, dt_topic_flow_error(), dt_sev_warn(), "compile_failed", ctx->episode_oid);
        return false;
    }

    int current_index = ctx->current_node.tag ? cep_l2_flow_find_node(&compiled, &ctx->current_node) : compiled.entry_index;
    if (current_index < 0 || (size_t)current_index >= compiled.count) {
        current_index = compiled.entry_index;
    }

    bool progress = false;
    size_t steps = 0u;
    for (; steps < step_budget && current_index >= 0 && (size_t)current_index < compiled.count; ++steps) {
        cepL2CompiledNode* node = &compiled.nodes[current_index];
        ctx->steps_executed++;
        progress = true;
        ctx->current_node = node->node_id;

        switch (node->type) {
            case CEP_L2_NODE_GUARD: {
                bool pass = cep_l2_flow_guard_passes(node->node_cell);
                cepDT next = pass ? node->successor : node->alt_successor;
                if (!cep_dt_is_valid(&next)) {
                    current_index = -1;
                } else {
                    current_index = cep_l2_flow_find_node(&compiled, &next);
                }
                break;
            }
            case CEP_L2_NODE_TRANSFORM: {
                (void)cep_l2_flow_transform(ctx, node->node_cell);
                cepDT next = node->successor;
                current_index = cep_dt_is_valid(&next) ? cep_l2_flow_find_node(&compiled, &next) : -1;
                break;
            }
            case CEP_L2_NODE_WAIT: {
                if (!cep_l2_flow_wait_ready(ctx, node->node_cell)) {
                    ctx->status = CEP_L2_ORG_WAITING;
                    cep_l2_flow_store_progress(ctx, &node->node_id, dt_org_state_waiting());
                    cep_l2_flow_compiled_free(&compiled);
                    return true;
                }
                cepDT next = node->successor;
                current_index = cep_dt_is_valid(&next) ? cep_l2_flow_find_node(&compiled, &next) : -1;
                break;
            }
            case CEP_L2_NODE_DECIDE: {
                cepDT next = {0};
                const char* choice = cep_l2_flow_choose_option(ctx, node->node_cell, &node->node_id, &next);
                if (choice && strncmp(choice, "variant:", 8) == 0) {
                    const char* variant_text = choice + 8;
                    cepID tag = cep_namepool_intern(variant_text, strlen(variant_text));
                    if (tag) {
                        ctx->variant_id.domain = CEP_ACRO("CEP");
                        ctx->variant_id.tag = tag;
                        ctx->variant_id.glob = 0u;
                    }
                }
                current_index = cep_dt_is_valid(&next) ? cep_l2_flow_find_node(&compiled, &next) : cep_l2_flow_find_node(&compiled, &node->successor);
                break;
            }
            case CEP_L2_NODE_CLAMP: {
                if (!cep_l2_flow_clamp(ctx, node->node_cell, steps)) {
                    cep_l2_flow_store_progress(ctx, &node->node_id, dt_org_state_failed());
                    cep_l2_flow_compiled_free(&compiled);
                    return true;
                }
                cepDT next = node->successor;
                current_index = cep_dt_is_valid(&next) ? cep_l2_flow_find_node(&compiled, &next) : -1;
                break;
            }
            default:
                current_index = -1;
                break;
        }
    }

    const cepDT* status_dt = NULL;
    if (current_index < 0) {
        ctx->status = CEP_L2_ORG_FINISHED;
        status_dt = dt_org_state_finished();
    } else if (ctx->status == CEP_L2_ORG_FAILED) {
        status_dt = dt_org_state_failed();
    } else if (ctx->status == CEP_L2_ORG_WAITING) {
        status_dt = dt_org_state_waiting();
    } else {
        ctx->status = CEP_L2_ORG_RUNNING;
        status_dt = dt_org_state_running();
    }

    cepDT next_node = {0};
    if (current_index >= 0 && (size_t)current_index < compiled.count) {
        next_node = compiled.nodes[current_index].node_id;
    }
    cep_l2_flow_store_progress(ctx, &next_node, status_dt);
    cep_l2_flow_record_history(ctx, "flow_step");

    cep_l2_flow_compiled_free(&compiled);
    return progress;
}
