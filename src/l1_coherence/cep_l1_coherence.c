/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_coherence.h"

#include "../l0_kernel/cep_cei.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_branch_controller.h"
#include "../l0_kernel/cep_runtime.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_being_id_field,   CEP_ACRO("CEP"), CEP_WORD("being_id"));
CEP_DEFINE_STATIC_DT(dt_bond_id_field,    CEP_ACRO("CEP"), CEP_WORD("bond_id"));
CEP_DEFINE_STATIC_DT(dt_context_id_field, CEP_ACRO("CEP"), CEP_WORD("ctx_id"));
CEP_DEFINE_STATIC_DT(dt_role_field,       CEP_ACRO("CEP"), CEP_WORD("role"));
CEP_DEFINE_STATIC_DT(dt_note_field_coh,   CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_state_field_coh,  CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_debt_state_open,  CEP_ACRO("CEP"), CEP_WORD("ist:open"));
CEP_DEFINE_STATIC_DT(dt_debt_state_done,  CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_closure_signal,   CEP_ACRO("CEP"), CEP_WORD("coh:close"));
CEP_DEFINE_STATIC_DT(dt_participants_name, CEP_ACRO("CEP"), CEP_WORD("beings"));
CEP_DEFINE_STATIC_DT(dt_target_field_coh, CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_kind_field_coh,   CEP_ACRO("CEP"), CEP_WORD("kind"));
CEP_DEFINE_STATIC_DT(dt_label_field_coh,  CEP_ACRO("CEP"), CEP_WORD("label"));
CEP_DEFINE_STATIC_DT(dt_history_field,    CEP_ACRO("CEP"), CEP_WORD("history"));
CEP_DEFINE_STATIC_DT(dt_contexts_bucket,  CEP_ACRO("CEP"), CEP_WORD("contexts"));
CEP_DEFINE_STATIC_DT(dt_facets_bucket,    CEP_ACRO("CEP"), CEP_WORD("facets"));
CEP_DEFINE_STATIC_DT(dt_bonds_bucket,     CEP_ACRO("CEP"), CEP_WORD("bonds"));
CEP_DEFINE_STATIC_DT(dt_sev_warn,         CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_topic_debt_new,   CEP_ACRO("CEP"), cep_namepool_intern_cstr("coh.debt.new"));
CEP_DEFINE_STATIC_DT(dt_topic_debt_done,  CEP_ACRO("CEP"), cep_namepool_intern_cstr("coh.debt.resolved"));
CEP_DEFINE_STATIC_DT(dt_topic_role_invalid, CEP_ACRO("CEP"), cep_namepool_intern_cstr("coh.role.invalid"));
CEP_DEFINE_STATIC_DT(dt_topic_closure_fail, CEP_ACRO("CEP"), cep_namepool_intern_cstr("coh.closure.fail"));
CEP_DEFINE_STATIC_DT(dt_topic_hydrate_fail, CEP_ACRO("CEP"), cep_namepool_intern_cstr("coh.hydrate.fail"));
CEP_DEFINE_STATIC_DT(dt_topic_cross_read,    CEP_ACRO("CEP"), cep_namepool_intern_cstr("coh.cross_read"));
CEP_DEFINE_STATIC_DT(dt_topic_rule_invalid,  CEP_ACRO("CEP"), cep_namepool_intern_cstr("coh.rule.invalid"));
CEP_DEFINE_STATIC_DT(dt_roles_bucket,     CEP_ACRO("CEP"), CEP_WORD("roles"));
CEP_DEFINE_STATIC_DT(dt_required_field_coh, CEP_ACRO("CEP"), CEP_WORD("required"));
CEP_DEFINE_STATIC_DT(dt_ctx_kind_field,   CEP_ACRO("CEP"), CEP_WORD("ctx_kind"));

typedef struct {
    const char* role;
    const char* being;
    const char* being_kind;
    const char* being_external;
    const char* bond;
    bool being_present;
} cepL1CohBindingView;

typedef struct {
    char* role;
    bool  required;
    bool  seen;
} cepL1CohRoleRule;

static bool cep_l1_coh_copy_dt_text(const cepDT* dt, char* buffer, size_t buffer_size);
static bool cep_l1_coh_copy_text_field(cepCell* parent, const cepDT* field, char* buffer, size_t buffer_size);

static int cep_l1_coh_binding_compare(const void* lhs, const void* rhs) {
    const cepL1CohBindingView* a = (const cepL1CohBindingView*)lhs;
    const cepL1CohBindingView* b = (const cepL1CohBindingView*)rhs;
    int cmp = strcmp(a->role, b->role);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(a->being, b->being);
    if (cmp != 0) {
        return cmp;
    }
    const char* bond_a = a->bond ? a->bond : "";
    const char* bond_b = b->bond ? b->bond : "";
    return strcmp(bond_a, bond_b);
}

static bool cep_l1_coh_append(char* buffer, size_t buffer_size, size_t* used, const char* text) {
    if (!buffer || !used || !text) {
        return false;
    }
    size_t remain = (buffer_size > *used) ? (buffer_size - *used) : 0u;
    if (remain == 0u) {
        return false;
    }
    int written = snprintf(buffer + *used, remain, "%s", text);
    if (written < 0 || (size_t)written >= remain) {
        return false;
    }
    *used += (size_t)written;
    return true;
}

static char* cep_l1_coh_dup_being_key(const char* kind, const char* external_id) {
    if (!kind || !*kind || !external_id || !*external_id) {
        return NULL;
    }
    size_t needed = strlen(kind) + strlen(external_id) + 2u; /* ':' + NUL */
    char* key = cep_malloc(needed);
    if (!cep_l1_coh_make_being_key(kind, external_id, key, needed)) {
        cep_free(key);
        return NULL;
    }
    return key;
}

static void cep_l1_coh_emit_cei(const cepDT* topic_dt,
                                const char* note,
                                cepCell* subject,
                                const cepPipelineMetadata* pipeline) {
    if (!topic_dt || !cep_dt_is_valid(topic_dt)) {
        return;
    }
    cepCeiRequest req = {
        .severity = *dt_sev_warn(),
        .note = note,
        .topic = cep_namepool_lookup(topic_dt->tag, NULL),
        .topic_len = 0u,
        .topic_intern = false,
        .subject = subject,
        .emit_signal = false,
    };
    if (pipeline && pipeline->pipeline_id) {
        req.has_pipeline = true;
        req.pipeline = *pipeline;
    }
    (void)cep_cei_emit(&req);
}

static bool cep_l1_coh_copy_bool_field(cepCell* parent, const cepDT* field, bool* out) {
    if (!parent || !field || !out) {
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
    const unsigned char* bytes = (const unsigned char*)cep_data_payload(data);
    if (!bytes) {
        return false;
    }
    *out = bytes[0] != 0u;
    return true;
}

bool cep_l1_coh_hydrate_safe(cep_cell_ref_t* ref,
                             const cepEnzymeContext* enz_ctx,
                             bool allow_cross_branch,
                             bool allow_snapshot_only) {
    if (!ref || !enz_ctx) {
        return false;
    }
    cepPipelineMetadata pipeline_meta = {0};
    if (enz_ctx->has_pipeline) {
        pipeline_meta = enz_ctx->pipeline;
    }

    cepRuntime* runtime = cep_runtime_default();
    cepBranchControllerRegistry* registry = runtime ? cep_runtime_branch_registry(runtime) : NULL;
    const cepBranchController* consumer_ctrl = NULL;
    const cepBranchController* source_ctrl = NULL;
    if (registry && cep_dt_is_valid(&enz_ctx->branch_dt)) {
        consumer_ctrl = cep_branch_registry_find_by_dt(registry, &enz_ctx->branch_dt);
    }
    if (ref->cell) {
        source_ctrl = cep_branch_controller_for_cell(ref->cell);
    }
    if (!source_ctrl && registry && cep_dt_is_valid(&ref->branch_dt)) {
        source_ctrl = cep_branch_registry_find_by_dt(registry, &ref->branch_dt);
    }

    bool dt_crossing = cep_dt_is_valid(&enz_ctx->branch_dt) &&
                       cep_dt_is_valid(&ref->branch_dt) &&
                       (cep_dt_compare(&enz_ctx->branch_dt, &ref->branch_dt) != 0);
    bool crossing = (consumer_ctrl && source_ctrl) ? (consumer_ctrl != source_ctrl) : dt_crossing;

    char consumer_label[64] = {0};
    char source_label[64] = {0};
    if (consumer_ctrl) {
        cep_branch_controller_format_label(consumer_ctrl, consumer_label, sizeof consumer_label);
    }
    if (source_ctrl) {
        cep_branch_controller_format_label(source_ctrl, source_label, sizeof source_label);
    }

    cepBranchPolicyResult policy = {
        .access = CEP_BRANCH_POLICY_ACCESS_ALLOW,
        .risk = CEP_BRANCH_POLICY_RISK_NONE,
    };
    if (crossing) {
        policy = cep_branch_policy_check_read(consumer_ctrl, source_ctrl);
    }

    if (crossing && !allow_cross_branch) {
        char note[160] = {0};
        snprintf(note,
                 sizeof note,
                 "cross-branch hydration denied (%.*s -> %.*s)",
                 48,
                 consumer_label[0] ? consumer_label : "consumer",
                 48,
                 source_label[0] ? source_label : "source");
        cep_l1_coh_emit_cei(dt_topic_hydrate_fail(),
                            note,
                            (cepCell*)ref->cell,
                            enz_ctx->has_pipeline ? &pipeline_meta : NULL);
        return false;
    }

    if (crossing && allow_cross_branch && policy.access == CEP_BRANCH_POLICY_ACCESS_DENY) {
        const char* risk_label = cep_branch_policy_risk_label(policy.risk);
        char note[160] = {0};
        snprintf(note,
                 sizeof note,
                 "cross-branch hydration denied (risk=%s %.*s -> %.*s)",
                 risk_label ? risk_label : "unknown",
                 48,
                 consumer_label[0] ? consumer_label : "consumer",
                 48,
                 source_label[0] ? source_label : "source");
        cep_l1_coh_emit_cei(dt_topic_hydrate_fail(),
                            note,
                            (cepCell*)ref->cell,
                            enz_ctx->has_pipeline ? &pipeline_meta : NULL);
        return false;
    }

    /* TODO: If L0 tightens hydrate policy (new budgets/Decision Cell rules),
       thread the updated opts here so L1 enzymes stay aligned with kernel
       expectations. */
    cep_hydrate_opts_t opts = {
        .view = CEP_HYDRATE_VIEW_LIVE,
        .allow_cross_branch = allow_cross_branch,
        .require_decision_cell = allow_cross_branch &&
                                 crossing &&
                                 policy.access == CEP_BRANCH_POLICY_ACCESS_DECISION, /* require Decision Cell when crossing branches */
        .max_depth = 0u,
        .max_meta_bytes = 0u,
        .max_payload_bytes = 0u,
        .lock_ancestors_ro = false,
        .hydrate_children = false,
        .hydrate_payload = true,
    };
    if (allow_snapshot_only) {
        opts.view = CEP_HYDRATE_VIEW_SNAPSHOT_RO;
    }
    cep_hydrate_result_t result = {0};
    cepHydrateStatus st = cep_cell_hydrate_for_enzyme(ref, enz_ctx, &opts, &result);
    if (st != CEP_HYDRATE_STATUS_OK) {
        const char* reason = (st == CEP_HYDRATE_STATUS_POLICY) ? "hydrate failed: policy denied" : "hydrate failed";
        cep_l1_coh_emit_cei(dt_topic_hydrate_fail(),
                            reason,
                            (cepCell*)ref->cell,
                            enz_ctx->has_pipeline ? &pipeline_meta : NULL);
        return false;
    }
    if (allow_cross_branch && crossing) {
        const char* risk_label = cep_branch_policy_risk_label(policy.risk);
        char note[160] = {0};
        snprintf(note,
                 sizeof note,
                 "cross-branch hydration performed%s%s",
                 (risk_label && policy.risk != CEP_BRANCH_POLICY_RISK_NONE) ? " risk=" : "",
                 (risk_label && policy.risk != CEP_BRANCH_POLICY_RISK_NONE) ? risk_label : "");
        cep_l1_coh_emit_cei(dt_topic_cross_read(),
                            note,
                            (cepCell*)ref->cell,
                            enz_ctx->has_pipeline ? &pipeline_meta : NULL);
    }
    return true;
}

static char* cep_l1_coh_dup_bond_key(const char* bond_kind,
                                     const char* from_being,
                                     const char* to_being) {
    if (!bond_kind || !*bond_kind || !from_being || !*from_being || !to_being || !*to_being) {
        return NULL;
    }
    size_t needed = strlen(bond_kind) + strlen(from_being) + strlen(to_being) + 8u; /* "bond:::" + NUL */
    char* key = cep_malloc(needed);
    if (!cep_l1_coh_make_bond_key(bond_kind, from_being, to_being, key, needed)) {
        cep_free(key);
        return NULL;
    }
    return key;
}

static char* cep_l1_coh_dup_facet_key(const char* facet_kind,
                                      const char* ctx_id,
                                      const char* subject_being,
                                      const char* label) {
    if (!facet_kind || !*facet_kind || !ctx_id || !*ctx_id || !subject_being || !*subject_being || !label || !*label) {
        return NULL;
    }
    size_t needed = strlen(facet_kind) + strlen(ctx_id) + strlen(subject_being) + strlen(label) + 8u; /* "facet::::" + NUL */
    char* key = cep_malloc(needed);
    if (!cep_l1_coh_make_facet_key(facet_kind, ctx_id, subject_being, label, key, needed)) {
        cep_free(key);
        return NULL;
    }
    return key;
}

static char* cep_l1_coh_dup_debt_key(const char* debt_kind,
                                     const char* ctx_or_bond_id,
                                     const char* requirement) {
    if (!debt_kind || !*debt_kind || !ctx_or_bond_id || !*ctx_or_bond_id || !requirement || !*requirement) {
        return NULL;
    }
    size_t needed = strlen(debt_kind) + strlen(ctx_or_bond_id) + strlen(requirement) + 7u; /* "debt:::\" + NUL */
    char* key = cep_malloc(needed);
    if (!cep_l1_coh_make_debt_key(debt_kind, ctx_or_bond_id, requirement, key, needed)) {
        cep_free(key);
        return NULL;
    }
    return key;
}

static bool cep_l1_coh_build_binding_views(const cepL1CohBinding* bindings,
                                           size_t binding_count,
                                           cepL1CohBindingView** out_views) {
    if (!bindings || binding_count == 0u || !out_views) {
        return false;
    }
    cepL1CohBindingView* views = cep_calloc(binding_count, sizeof(*views));
    for (size_t i = 0; i < binding_count; ++i) {
        const cepL1CohBinding* binding = &bindings[i];
        if (!binding->role || !*binding->role || !binding->being_kind || !*binding->being_kind ||
            !binding->being_external_id || !*binding->being_external_id) {
            cep_free(views);
            return false;
        }
        views[i].role = binding->role;
        views[i].being = cep_l1_coh_dup_being_key(binding->being_kind, binding->being_external_id);
        views[i].being_kind = binding->being_kind;
        views[i].being_external = binding->being_external_id;
        views[i].bond = binding->bond_id;
        views[i].being_present = true;
        if (!views[i].being) {
            cep_free(views);
            return false;
        }
    }
    *out_views = views;
    return true;
}

static void cep_l1_coh_free_binding_views(cepL1CohBindingView* views, size_t count) {
    if (!views) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        if (views[i].being) {
            cep_free((void*)views[i].being);
            views[i].being = NULL;
        }
    }
    cep_free(views);
}

static cepL1CohRoleRule* cep_l1_coh_find_role_rule(cepL1CohRoleRule* rules,
                                                   size_t count,
                                                   const char* role) {
    if (!rules || !role || !*role) {
        return NULL;
    }
    for (size_t i = 0; i < count; ++i) {
        if (rules[i].role && strcmp(rules[i].role, role) == 0) {
            return &rules[i];
        }
    }
    return NULL;
}

static void cep_l1_coh_free_role_rules(cepL1CohRoleRule* rules, size_t count) {
    if (!rules) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        if (rules[i].role) {
            cep_free(rules[i].role);
            rules[i].role = NULL;
        }
    }
    cep_free(rules);
}

static bool cep_l1_coh_collect_role_rules(cepCell* rule_root,
                                          cepCell* subject,
                                          cepL1CohRoleRule** out_rules,
                                          size_t* out_count) {
    if (!out_rules || !out_count) {
        return false;
    }
    *out_rules = NULL;
    *out_count = 0u;
    if (!rule_root) {
        return true;
    }
    rule_root = cep_cell_resolve(rule_root);
    if (!rule_root || !cep_cell_require_dictionary_store(&rule_root)) {
        return false;
    }
    size_t count = cep_cell_children(rule_root);
    if (count == 0u) {
        return true;
    }
    cepL1CohRoleRule* rules = cep_calloc(count, sizeof(*rules));
    size_t filled = 0u;
    for (cepCell* rule = cep_cell_first(rule_root); rule; rule = cep_cell_next(rule_root, rule)) {
        cepCell* resolved_rule = cep_cell_resolve(rule);
        if (!resolved_rule || !cep_cell_require_dictionary_store(&resolved_rule)) {
            continue;
        }
        char role_name[64] = {0};
        (void)cep_l1_coh_copy_text_field(resolved_rule, dt_role_field(), role_name, sizeof role_name);
        if (!role_name[0]) {
            (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(resolved_rule), role_name, sizeof role_name);
        }
        if (!role_name[0]) {
            cep_l1_coh_emit_cei(dt_topic_rule_invalid(), "role rule missing role id", subject, NULL);
            continue;
        }
        rules[filled].role = cep_malloc(strlen(role_name) + 1u);
        if (!rules[filled].role) {
            continue;
        }
        memcpy(rules[filled].role, role_name, strlen(role_name) + 1u);
        bool required = false;
        (void)cep_l1_coh_copy_bool_field(resolved_rule, dt_required_field_coh(), &required);
        rules[filled].required = required;
        rules[filled].seen = false;
        ++filled;
    }
    *out_rules = rules;
    *out_count = filled;
    return true;
}

static bool cep_l1_coh_role_allowed(cepCell* facet_rules, const char* role) {
    if (!facet_rules || !role || !*role) {
        return false;
    }
    for (cepCell* rule = cep_cell_first(facet_rules); rule; rule = cep_cell_next(facet_rules, rule)) {
        cepCell* resolved_rule = cep_cell_resolve(rule);
        if (!resolved_rule || !cep_cell_require_dictionary_store(&resolved_rule)) {
            continue;
        }
        char rule_role[64] = {0};
        (void)cep_l1_coh_copy_text_field(resolved_rule, dt_role_field(), rule_role, sizeof rule_role);
        if (!rule_role[0]) {
            (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(resolved_rule), rule_role, sizeof rule_role);
        }
        if (rule_role[0] && strcmp(rule_role, role) == 0) {
            return true;
        }
    }
    return false;
}

static bool cep_l1_coh_format_context_key(const char* ctx_kind,
                                          cepL1CohBindingView* views,
                                          size_t binding_count,
                                          char* buffer,
                                          size_t buffer_size) {
    if (!ctx_kind || !*ctx_kind || !views || binding_count == 0u || !buffer || buffer_size == 0u) {
        return false;
    }
    qsort(views, binding_count, sizeof(*views), cep_l1_coh_binding_compare);

    size_t used = 0u;
    buffer[0] = '\0';
    bool ok = cep_l1_coh_append(buffer, buffer_size, &used, "ctx:") &&
              cep_l1_coh_append(buffer, buffer_size, &used, ctx_kind);

    for (size_t i = 0; ok && i < binding_count; ++i) {
        ok = cep_l1_coh_append(buffer, buffer_size, &used, "|") &&
             cep_l1_coh_append(buffer, buffer_size, &used, views[i].role) &&
             cep_l1_coh_append(buffer, buffer_size, &used, "=") &&
             cep_l1_coh_append(buffer, buffer_size, &used, views[i].being);
        if (ok && views[i].bond && *views[i].bond) {
            ok = cep_l1_coh_append(buffer, buffer_size, &used, "@") &&
                 cep_l1_coh_append(buffer, buffer_size, &used, views[i].bond);
        }
    }
    return ok;
}

/* Build a canonical Being key of the form "<kind>:<external_id>" so callers do
   not re-invent ID strings. The caller supplies the output buffer; failure
   indicates validation or capacity issues. */
bool cep_l1_coh_make_being_key(const char* kind,
                               const char* external_id,
                               char* buffer,
                               size_t buffer_size) {
    if (!buffer || buffer_size == 0u || !kind || !*kind || !external_id || !*external_id) {
        return false;
    }
    size_t used = 0u;
    buffer[0] = '\0';
    return cep_l1_coh_append(buffer, buffer_size, &used, kind) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, external_id);
}

/* Build a canonical Bond key of the form "bond:<kind>:<from>:<to>" so bonds
   stay deterministic regardless of caller order. */
bool cep_l1_coh_make_bond_key(const char* bond_kind,
                              const char* from_being,
                              const char* to_being,
                              char* buffer,
                              size_t buffer_size) {
    if (!buffer || buffer_size == 0u || !bond_kind || !*bond_kind || !from_being || !*from_being ||
        !to_being || !*to_being) {
        return false;
    }
    size_t used = 0u;
    buffer[0] = '\0';
    return cep_l1_coh_append(buffer, buffer_size, &used, "bond:") &&
           cep_l1_coh_append(buffer, buffer_size, &used, bond_kind) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, from_being) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, to_being);
}

/* Build a canonical Context key "ctx:<kind>|role=being[@bond]|..." sorting
   bindings by role→being→bond to keep replays stable even when callers change
   order. */
bool cep_l1_coh_make_context_key(const char* ctx_kind,
                                 const cepL1CohBinding* bindings,
                                 size_t binding_count,
                                 char* buffer,
                                 size_t buffer_size) {
    if (!buffer || buffer_size == 0u || !ctx_kind || !*ctx_kind || !bindings || binding_count == 0u) {
        return false;
    }
    cepL1CohBindingView* views = NULL;
    if (!cep_l1_coh_build_binding_views(bindings, binding_count, &views)) {
        return false;
    }
    bool ok = cep_l1_coh_format_context_key(ctx_kind, views, binding_count, buffer, buffer_size);
    cep_l1_coh_free_binding_views(views, binding_count);
    return ok;
}

/* Build a canonical Facet key "facet:<kind>:<ctx>:<subject>:<label>" to keep
   derived truths traceable across replays. */
bool cep_l1_coh_make_facet_key(const char* facet_kind,
                               const char* ctx_id,
                               const char* subject_being,
                               const char* facet_label,
                               char* buffer,
                               size_t buffer_size) {
    if (!buffer || buffer_size == 0u || !facet_kind || !*facet_kind || !ctx_id || !*ctx_id ||
        !subject_being || !*subject_being || !facet_label || !*facet_label) {
        return false;
    }
    size_t used = 0u;
    buffer[0] = '\0';
    return cep_l1_coh_append(buffer, buffer_size, &used, "facet:") &&
           cep_l1_coh_append(buffer, buffer_size, &used, facet_kind) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, ctx_id) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, subject_being) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, facet_label);
}

/* Build a canonical Debt key "debt:<kind>:<ctx_or_bond>:<requirement>" to keep
   append-only debt history stable. */
bool cep_l1_coh_make_debt_key(const char* debt_kind,
                              const char* ctx_or_bond_id,
                              const char* requirement,
                              char* buffer,
                              size_t buffer_size) {
    if (!buffer || buffer_size == 0u || !debt_kind || !*debt_kind || !ctx_or_bond_id || !*ctx_or_bond_id ||
        !requirement || !*requirement) {
        return false;
    }
    size_t used = 0u;
    buffer[0] = '\0';
    return cep_l1_coh_append(buffer, buffer_size, &used, "debt:") &&
           cep_l1_coh_append(buffer, buffer_size, &used, debt_kind) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, ctx_or_bond_id) &&
           cep_l1_coh_append(buffer, buffer_size, &used, ":") &&
           cep_l1_coh_append(buffer, buffer_size, &used, requirement);
}

static bool cep_l1_coh_make_dt(const char* id, cepDT* out) {
    if (!id || !out) {
        return false;
    }
    size_t len = strlen(id);
    if (len == 0u) {
        return false;
    }
    cepID tag = cep_namepool_intern(id, len);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_coh_require_dict(cepCell* parent,
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

static bool cep_l1_coh_copy_dt_text(const cepDT* dt, char* buffer, size_t buffer_size) {
    if (!dt || !buffer || buffer_size == 0u) {
        return false;
    }
    size_t length = 0u;
    const char* text = cep_namepool_lookup(dt->tag, &length);
    if (!text || length == 0u) {
        return false;
    }
    if (length >= buffer_size) {
        length = buffer_size - 1u;
    }
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    return true;
}

static bool cep_l1_coh_copy_text_field(cepCell* parent,
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

static cepCell* cep_l1_coh_find_debt_cell(cepL1SchemaLayout* layout, const char* debt_id) {
    if (!layout || !layout->coh_debts || !debt_id) {
        return NULL;
    }
    cepDT debt_dt = {0};
    if (!cep_l1_coh_make_dt(debt_id, &debt_dt)) {
        return NULL;
    }
    cepCell* debt = cep_cell_find_by_name(layout->coh_debts, &debt_dt);
    debt = debt ? cep_cell_resolve(debt) : NULL;
    if (!debt || !cep_cell_require_dictionary_store(&debt)) {
        return NULL;
    }
    return debt;
}

static bool cep_l1_coh_append_debt_state(cepCell* debt, const cepDT* state, const char* note) {
    if (!debt || !state) {
        return false;
    }
    (void)cep_cell_put_dt(debt, dt_state_field_coh(), state);

    cepCell* history = cep_cell_ensure_dictionary_child(debt, dt_history_field(), CEP_STORAGE_RED_BLACK_T);
    history = history ? cep_cell_resolve(history) : NULL;
    if (!history || !cep_cell_require_dictionary_store(&history)) {
        return false;
    }

    char name[16] = {0};
    size_t seq = cep_cell_children(history);
    snprintf(name, sizeof name, "ev%04zu", seq + 1u);
    cepDT name_dt = {0};
    if (!cep_l1_coh_make_dt(name, &name_dt)) {
        return false;
    }

    cepCell* entry = cep_cell_ensure_dictionary_child(history, &name_dt, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }
    (void)cep_cell_put_dt(entry, dt_state_field_coh(), state);
    if (note && *note) {
        (void)cep_cell_put_text(entry, dt_note_field_coh(), note);
    }
    return true;
}

static void cep_l1_coh_mark_debt_state(cepL1SchemaLayout* layout,
                                       const char* debt_id,
                                       const cepDT* state,
                                       const char* note) {
    if (!layout || !state || !debt_id) {
        return;
    }
    cepCell* debt = cep_l1_coh_find_debt_cell(layout, debt_id);
    if (!debt) {
        return;
    }
    if (cep_l1_coh_append_debt_state(debt, state, note) && state == dt_debt_state_done()) {
        cep_l1_coh_emit_cei(dt_topic_debt_done(), note, debt, NULL);
    }
}

static void cep_l1_coh_resolve_debt(cepL1SchemaLayout* layout,
                                    const char* debt_kind,
                                    const char* context_id,
                                    const char* requirement,
                                    const char* note) {
    char* debt_key = cep_l1_coh_dup_debt_key(debt_kind, context_id, requirement);
    if (!debt_key) {
        return;
    }
    cep_l1_coh_mark_debt_state(layout, debt_key, dt_debt_state_done(), note ? note : "resolved");
    cep_free(debt_key);
}

static bool cep_l1_coh_materialize_facet(cepL1SchemaLayout* layout,
                                         cepCell* context_cell,
                                         const char* context_id,
                                         const char* facet_kind,
                                         const char* subject_being,
                                         const char* label) {
    if (!layout || !layout->coh_facets || !context_id || !facet_kind || !subject_being) {
        return false;
    }

    char* facet_id = cep_l1_coh_dup_facet_key(facet_kind, context_id, subject_being, label ? label : facet_kind);
    if (!facet_id) {
        return false;
    }
    cepDT facet_dt = {0};
    cepDT ctx_dt = {0};
    cepDT subject_dt = {0};
    bool ok = cep_l1_coh_make_dt(facet_id, &facet_dt) &&
              cep_l1_coh_make_dt(context_id, &ctx_dt) &&
              cep_l1_coh_make_dt(subject_being, &subject_dt);
    if (!ok) {
        cep_free(facet_id);
        return false;
    }

    cepCell* facet = cep_cell_ensure_dictionary_child(layout->coh_facets, &facet_dt, CEP_STORAGE_RED_BLACK_T);
    facet = facet ? cep_cell_resolve(facet) : NULL;
    if (!facet || !cep_cell_require_dictionary_store(&facet)) {
        cep_free(facet_id);
        return false;
    }

    (void)cep_cell_put_text(facet, dt_kind_field_coh(), facet_kind);
    (void)cep_cell_put_text(facet, dt_context_id_field(), context_id);
    (void)cep_cell_put_text(facet, dt_being_id_field(), subject_being);
    if (label && *label) {
        (void)cep_cell_put_text(facet, dt_label_field_coh(), label);
    }

    if (context_cell) {
        cepCell* parents[] = {context_cell};
        (void)cep_cell_add_parents(facet, parents, 1u);
    }

    /* Adjacency mirrors: by being, by facet kind, and by context. */
    cepDT facet_kind_dt = {0};
    if (layout->coh_adj_by_being && cep_l1_coh_make_dt(facet_kind, &facet_kind_dt)) {
        cepCell* by_being = NULL;
        if (cep_l1_coh_require_dict(layout->coh_adj_by_being, &subject_dt, &by_being)) {
            cepCell* by_being_facets = cep_cell_ensure_dictionary_child(by_being, dt_facets_bucket(), CEP_STORAGE_RED_BLACK_T);
            by_being_facets = by_being_facets ? cep_cell_resolve(by_being_facets) : NULL;
            if (by_being_facets && cep_cell_require_dictionary_store(&by_being_facets)) {
                cepCell* entry = cep_cell_ensure_dictionary_child(by_being_facets, &facet_dt, CEP_STORAGE_RED_BLACK_T);
                entry = entry ? cep_cell_resolve(entry) : NULL;
                if (entry && cep_cell_require_dictionary_store(&entry)) {
                    (void)cep_cell_put_text(entry, dt_context_id_field(), context_id);
                    (void)cep_cell_put_text(entry, dt_kind_field_coh(), facet_kind);
                }
            }
        }

        if (layout->coh_adj_by_facet_kind) {
            cepCell* by_facet = NULL;
            if (cep_l1_coh_require_dict(layout->coh_adj_by_facet_kind, &facet_kind_dt, &by_facet)) {
                cepCell* by_facet_entries = cep_cell_ensure_dictionary_child(by_facet, dt_facets_bucket(), CEP_STORAGE_RED_BLACK_T);
                by_facet_entries = by_facet_entries ? cep_cell_resolve(by_facet_entries) : NULL;
                if (by_facet_entries && cep_cell_require_dictionary_store(&by_facet_entries)) {
                    cepCell* entry = cep_cell_ensure_dictionary_child(by_facet_entries, &facet_dt, CEP_STORAGE_RED_BLACK_T);
                    entry = entry ? cep_cell_resolve(entry) : NULL;
                    if (entry && cep_cell_require_dictionary_store(&entry)) {
                        (void)cep_cell_put_text(entry, dt_being_id_field(), subject_being);
                        (void)cep_cell_put_text(entry, dt_context_id_field(), context_id);
                    }
                }
            }
        }
    }

    if (layout->coh_adj_by_context) {
        cepCell* by_ctx = NULL;
        if (cep_l1_coh_require_dict(layout->coh_adj_by_context, &ctx_dt, &by_ctx)) {
            cepCell* by_ctx_facets = cep_cell_ensure_dictionary_child(by_ctx, dt_facets_bucket(), CEP_STORAGE_RED_BLACK_T);
            by_ctx_facets = by_ctx_facets ? cep_cell_resolve(by_ctx_facets) : NULL;
            if (by_ctx_facets && cep_cell_require_dictionary_store(&by_ctx_facets)) {
                cepCell* entry = cep_cell_ensure_dictionary_child(by_ctx_facets, &facet_dt, CEP_STORAGE_RED_BLACK_T);
                entry = entry ? cep_cell_resolve(entry) : NULL;
                if (entry && cep_cell_require_dictionary_store(&entry)) {
                    (void)cep_cell_put_text(entry, dt_kind_field_coh(), facet_kind);
                    (void)cep_cell_put_text(entry, dt_being_id_field(), subject_being);
                }
            }
        }
    }

    cep_free(facet_id);
    return true;
}

bool cep_l1_coh_add_being(cepL1SchemaLayout* layout,
                          const char* being_kind,
                          const char* external_id,
                          cepCell** being_out) {
    /* Create or refresh a being entry under `/data/coh/beings`, keeping the
       dictionary store available and copying the provided identifier into a
        text field for quick inspection. */
    if (!layout || !layout->coh_beings || !being_kind || !external_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_beings)) {
        return false;
    }

    char* being_key = cep_l1_coh_dup_being_key(being_kind, external_id);
    if (!being_key) {
        return false;
    }
    cepDT being_dt = {0};
    if (!cep_l1_coh_make_dt(being_key, &being_dt)) {
        cep_free(being_key);
        return false;
    }
    cepCell* being = cep_cell_ensure_dictionary_child(layout->coh_beings, &being_dt, CEP_STORAGE_RED_BLACK_T);
    being = being ? cep_cell_resolve(being) : NULL;
    if (!being || !cep_cell_require_dictionary_store(&being)) {
        cep_free(being_key);
        return false;
    }
    (void)cep_cell_put_text(being, dt_being_id_field(), being_key);
    (void)cep_cell_put_text(being, dt_kind_field_coh(), being_kind);
    cep_free(being_key);
    if (being_out) {
        *being_out = being;
    }
    return true;
}

bool cep_l1_coh_add_bond(cepL1SchemaLayout* layout,
                         const char* bond_kind,
                         const char* from_being_kind,
                         const char* from_external_id,
                         const char* to_being_kind,
                         const char* to_external_id,
                         cepCell** bond_out) {
    /* Create or refresh a bond entry tying beings with a role label. This keeps
       the bonds dictionary populated and opportunistically ensures referenced
       beings exist so later closure passes can trust the identifiers. */
    if (!layout || !layout->coh_bonds || !bond_kind || !from_being_kind || !from_external_id ||
        !to_being_kind || !to_external_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_bonds)) {
        return false;
    }
    bool ok = true;
    char* from_key = cep_l1_coh_dup_being_key(from_being_kind, from_external_id);
    char* to_key = cep_l1_coh_dup_being_key(to_being_kind, to_external_id);
    if (!from_key || !to_key) {
        cep_free(from_key);
        cep_free(to_key);
        return false;
    }
    char* bond_key = cep_l1_coh_dup_bond_key(bond_kind, from_key, to_key);
    if (!bond_key) {
        cep_free(from_key);
        cep_free(to_key);
        return false;
    }

    ok = ok && cep_l1_coh_add_being(layout, from_being_kind, from_external_id, NULL);
    ok = ok && cep_l1_coh_add_being(layout, to_being_kind, to_external_id, NULL);

    cepDT bond_dt = {0};
    if (!cep_l1_coh_make_dt(bond_key, &bond_dt)) {
        ok = false;
    }
    cepCell* bond = NULL;
    if (ok) {
        bond = cep_cell_ensure_dictionary_child(layout->coh_bonds, &bond_dt, CEP_STORAGE_RED_BLACK_T);
        bond = bond ? cep_cell_resolve(bond) : NULL;
        ok = bond && cep_cell_require_dictionary_store(&bond);
    }
    if (ok) {
        (void)cep_cell_put_text(bond, dt_bond_id_field(), bond_key);
        (void)cep_cell_put_text(bond, dt_kind_field_coh(), bond_kind);
        (void)cep_cell_put_text(bond, CEP_DTAW("CEP", "source"), from_key);
        (void)cep_cell_put_text(bond, CEP_DTAW("CEP", "target"), to_key);

        if (layout->coh_adj_by_being) {
            cepDT from_dt = {0};
            cepDT to_dt = {0};
            if (cep_l1_coh_make_dt(from_key, &from_dt) && cep_l1_coh_make_dt(to_key, &to_dt)) {
                cepCell* from_adj = NULL;
                if (cep_l1_coh_require_dict(layout->coh_adj_by_being, &from_dt, &from_adj)) {
                    cepCell* bonds = cep_cell_ensure_dictionary_child(from_adj, dt_bonds_bucket(), CEP_STORAGE_RED_BLACK_T);
                    bonds = bonds ? cep_cell_resolve(bonds) : NULL;
                    if (bonds && cep_cell_require_dictionary_store(&bonds)) {
                        cepCell* entry = cep_cell_ensure_dictionary_child(bonds, &bond_dt, CEP_STORAGE_RED_BLACK_T);
                        entry = entry ? cep_cell_resolve(entry) : NULL;
                        if (entry && cep_cell_require_dictionary_store(&entry)) {
                            (void)cep_cell_put_text(entry, dt_target_field_coh(), to_key);
                            (void)cep_cell_put_text(entry, dt_kind_field_coh(), bond_kind);
                            (void)cep_cell_put_text(entry, dt_role_field(), "source");
                        }
                    }
                }

                cepCell* to_adj = NULL;
                if (cep_l1_coh_require_dict(layout->coh_adj_by_being, &to_dt, &to_adj)) {
                    cepCell* bonds = cep_cell_ensure_dictionary_child(to_adj, dt_bonds_bucket(), CEP_STORAGE_RED_BLACK_T);
                    bonds = bonds ? cep_cell_resolve(bonds) : NULL;
                    if (bonds && cep_cell_require_dictionary_store(&bonds)) {
                        cepCell* entry = cep_cell_ensure_dictionary_child(bonds, &bond_dt, CEP_STORAGE_RED_BLACK_T);
                        entry = entry ? cep_cell_resolve(entry) : NULL;
                        if (entry && cep_cell_require_dictionary_store(&entry)) {
                            (void)cep_cell_put_text(entry, dt_target_field_coh(), from_key);
                            (void)cep_cell_put_text(entry, dt_kind_field_coh(), bond_kind);
                            (void)cep_cell_put_text(entry, dt_role_field(), "target");
                        }
                    }
                }
            }
        }
    }

    if (bond_out) {
        *bond_out = ok ? bond : NULL;
    }

    cep_free(from_key);
    cep_free(to_key);
    cep_free(bond_key);
    return ok;
}

bool cep_l1_coh_add_context(cepL1SchemaLayout* layout,
                            const char* context_kind,
                            const char* note,
                            const cepL1CohBinding* bindings,
                            size_t binding_count,
                            cepCell** context_out) {
    /* Create or refresh a context entry, attach optional role→being bindings,
       and seed debts when required identifiers are missing so adjacency closure
       has a deterministic backlog to clear. */
    if (!layout || !layout->coh_contexts || !context_kind || !bindings || binding_count == 0u) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_contexts)) {
        return false;
    }
    cepL1CohBindingView* views = NULL;
    if (!cep_l1_coh_build_binding_views(bindings, binding_count, &views)) {
        return false;
    }

    size_t ctx_size = strlen(context_kind) + 5u; /* "ctx:" prefix + NUL */
    for (size_t i = 0; i < binding_count; ++i) {
        ctx_size += 1u + strlen(views[i].role) + 1u + strlen(views[i].being);
        if (views[i].bond) {
            ctx_size += 1u + strlen(views[i].bond);
        }
    }
    char* ctx_id = cep_malloc(ctx_size);
    bool ok = cep_l1_coh_format_context_key(context_kind, views, binding_count, ctx_id, ctx_size);

    cepDT ctx_dt = {0};
    cepCell* ctx = NULL;
    if (ok && cep_l1_coh_make_dt(ctx_id, &ctx_dt)) {
        ctx = cep_cell_ensure_dictionary_child(layout->coh_contexts, &ctx_dt, CEP_STORAGE_RED_BLACK_T);
        ctx = ctx ? cep_cell_resolve(ctx) : NULL;
        ok = ctx && cep_cell_require_dictionary_store(&ctx);
    } else {
        ok = false;
    }

    cepCell* ctx_participants = NULL;
    if (ok) {
        (void)cep_cell_put_text(ctx, dt_context_id_field(), ctx_id);
        (void)cep_cell_put_text(ctx, dt_kind_field_coh(), context_kind);
        if (note && *note) {
            (void)cep_cell_put_text(ctx, dt_note_field_coh(), note);
        }
        ctx_participants = cep_cell_ensure_dictionary_child(ctx, dt_participants_name(), CEP_STORAGE_RED_BLACK_T);
        ctx_participants = ctx_participants ? cep_cell_resolve(ctx_participants) : NULL;
        ok = ctx_participants && cep_cell_require_dictionary_store(&ctx_participants);
    }

    for (size_t i = 0; ok && i < binding_count; ++i) {
        const cepL1CohBindingView* view = &views[i];
        ok = ok && cep_l1_coh_add_being(layout, view->being_kind, view->being_external, NULL);

        cepDT role_dt = {0};
        ok = ok && cep_l1_coh_make_dt(view->role, &role_dt);
        cepCell* role_entry = ok ? cep_cell_ensure_dictionary_child(ctx_participants, &role_dt, CEP_STORAGE_RED_BLACK_T) : NULL;
        role_entry = role_entry ? cep_cell_resolve(role_entry) : NULL;
        ok = ok && role_entry && cep_cell_require_dictionary_store(&role_entry);
        if (!ok) {
            (void)cep_l1_coh_record_debt(layout, "missing_binding", ctx_id, view->role, "failed to attach role binding");
            continue;
        }

        (void)cep_cell_put_text(role_entry, dt_role_field(), view->role);
        (void)cep_cell_put_text(role_entry, dt_target_field_coh(), view->being);
        (void)cep_cell_put_text(role_entry, dt_being_id_field(), view->being);
        if (view->bond) {
            (void)cep_cell_put_text(role_entry, dt_bond_id_field(), view->bond);
        }

        if (layout->coh_adj_by_being) {
            cepDT being_dt = {0};
            if (cep_l1_coh_make_dt(view->being, &being_dt)) {
                cepCell* by_being = NULL;
                if (cep_l1_coh_require_dict(layout->coh_adj_by_being, &being_dt, &by_being)) {
                    cepCell* ctxs = cep_cell_ensure_dictionary_child(by_being, dt_contexts_bucket(), CEP_STORAGE_RED_BLACK_T);
                    ctxs = ctxs ? cep_cell_resolve(ctxs) : NULL;
                    if (ctxs && cep_cell_require_dictionary_store(&ctxs)) {
                        cepCell* entry = cep_cell_ensure_dictionary_child(ctxs, &ctx_dt, CEP_STORAGE_RED_BLACK_T);
                        entry = entry ? cep_cell_resolve(entry) : NULL;
                        if (entry && cep_cell_require_dictionary_store(&entry)) {
                            (void)cep_cell_put_text(entry, dt_role_field(), view->role);
                        }
                    }
                }
            }
        }
    }

    if (ok && layout->coh_adj_by_context) {
        cepCell* by_ctx = NULL;
        if (cep_l1_coh_require_dict(layout->coh_adj_by_context, &ctx_dt, &by_ctx)) {
            cepCell* participants = cep_cell_ensure_dictionary_child(by_ctx, dt_participants_name(), CEP_STORAGE_RED_BLACK_T);
            participants = participants ? cep_cell_resolve(participants) : NULL;
            if (participants && cep_cell_require_dictionary_store(&participants)) {
                for (size_t i = 0; i < binding_count; ++i) {
                    cepDT role_dt = {0};
                    if (!cep_l1_coh_make_dt(views[i].role, &role_dt)) {
                        continue;
                    }
                    cepCell* entry = cep_cell_ensure_dictionary_child(participants, &role_dt, CEP_STORAGE_RED_BLACK_T);
                    entry = entry ? cep_cell_resolve(entry) : NULL;
                    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
                        continue;
                    }
                    (void)cep_cell_put_text(entry, dt_being_id_field(), views[i].being);
                    (void)cep_cell_put_text(entry, dt_role_field(), views[i].role);
                    if (views[i].bond) {
                        (void)cep_cell_put_text(entry, dt_bond_id_field(), views[i].bond);
                    }
                }
            }
        }
    }

    if (ok) {
        /* Run a local closure pass immediately so facets appear alongside the
           context creation; debts remain open when bindings were incomplete. */
        ok = cep_l1_coh_run_closure(layout, ctx_id);
    }

    if (context_out) {
        *context_out = ok ? ctx : NULL;
    }
    cep_l1_coh_free_binding_views(views, binding_count);
    cep_free(ctx_id);
    return ok;
}

bool cep_l1_coh_record_debt(cepL1SchemaLayout* layout,
                            const char* debt_kind,
                            const char* context_id,
                            const char* requirement,
                            const char* note) {
    /* Track an outstanding adjacency debt for the provided context so later
       closure passes can retry facet materialisation deterministically. Debts
       append state history instead of mutating existing entries. */
    if (!layout || !layout->coh_debts || !debt_kind || !context_id || !requirement) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_debts)) {
        return false;
    }
    char* debt_key = cep_l1_coh_dup_debt_key(debt_kind, context_id, requirement);
    if (!debt_key) {
        return false;
    }
    cepDT debt_dt = {0};
    if (!cep_l1_coh_make_dt(debt_key, &debt_dt)) {
        cep_free(debt_key);
        return false;
    }
    cepCell* debt = cep_cell_ensure_dictionary_child(layout->coh_debts, &debt_dt, CEP_STORAGE_RED_BLACK_T);
    debt = debt ? cep_cell_resolve(debt) : NULL;
    if (!debt || !cep_cell_require_dictionary_store(&debt)) {
        cep_free(debt_key);
        return false;
    }
    char ctx_kind[128] = {0};
    if (strncmp(context_id, "ctx:", 4u) == 0u) {
        const char* kind_start = context_id + 4u;
        const char* kind_end = strchr(kind_start, '|');
        size_t len = kind_end ? (size_t)(kind_end - kind_start) : strlen(kind_start);
        if (len >= sizeof ctx_kind) {
            len = sizeof ctx_kind - 1u;
        }
        memcpy(ctx_kind, kind_start, len);
        ctx_kind[len] = '\0';
    }
    (void)cep_cell_put_text(debt, dt_kind_field_coh(), debt_kind);
    (void)cep_cell_put_text(debt, dt_context_id_field(), context_id);
    (void)cep_cell_put_text(debt, dt_target_field_coh(), requirement);
    if (ctx_kind[0]) {
        (void)cep_cell_put_text(debt, dt_ctx_kind_field(), ctx_kind);
    }
    (void)cep_l1_coh_append_debt_state(debt, dt_debt_state_open(), note ? note : requirement);
    cep_l1_coh_emit_cei(dt_topic_debt_new(), note ? note : requirement, debt, NULL);
    cep_free(debt_key);
    return true;
}

static bool cep_l1_coh_process_context(cepL1SchemaLayout* layout, cepCell* ctx, const char* ctx_id) {
    if (!layout || !ctx || !ctx_id) {
        return false;
    }

    char ctx_kind[128] = {0};
    if (!cep_l1_coh_copy_text_field(ctx, dt_kind_field_coh(), ctx_kind, sizeof ctx_kind)) {
        if (strncmp(ctx_id, "ctx:", 4u) == 0u) {
            const char* sep = strchr(ctx_id + 4u, '|');
            size_t len = sep ? (size_t)(sep - (ctx_id + 4u)) : strlen(ctx_id + 4u);
            if (len >= sizeof ctx_kind) {
                len = sizeof ctx_kind - 1u;
            }
            memcpy(ctx_kind, ctx_id + 4u, len);
            ctx_kind[len] = '\0';
        } else {
            strncpy(ctx_kind, "context", sizeof ctx_kind - 1u);
            ctx_kind[sizeof ctx_kind - 1u] = '\0';
        }
    }

    cepCell* participants = cep_cell_find_by_name(ctx, dt_participants_name());
    participants = participants ? cep_cell_resolve(participants) : NULL;
    if (!participants || !cep_cell_require_dictionary_store(&participants)) {
        (void)cep_l1_coh_record_debt(layout, "missing_participants", ctx_id, "participants", "context has no participants to close");
        cep_l1_coh_emit_cei(dt_topic_closure_fail(), "context missing participants", ctx, NULL);
        return true;
    }
    cep_l1_coh_resolve_debt(layout, "missing_participants", ctx_id, "participants", "participants recorded");

    size_t binding_cap = cep_cell_children(participants);
    if (binding_cap == 0u) {
        (void)cep_l1_coh_record_debt(layout, "missing_participants", ctx_id, "participants", "context has no participants");
        return true;
    }

    cepL1CohBindingView* views = cep_calloc(binding_cap, sizeof(*views));
    size_t view_count = 0u;
    bool missing = false;
    bool ok = true;

    cepDT ctx_dt = {0};
    ok = ok && cep_l1_coh_make_dt(ctx_id, &ctx_dt);

    /* Load facet/role rules for this context kind (if any) so role validation
       and facet synthesis share the same source. */
    cepDT ctx_kind_dt = {0};
    cepCell* facet_rules = NULL;
    cepCell* rule_root = NULL;
    cepCell* role_rules_root = NULL;
    cepL1CohRoleRule* role_rules = NULL;
    size_t role_rule_count = 0u;
    if (cep_l1_coh_make_dt(ctx_kind, &ctx_kind_dt) && layout->coh_context_rules) {
        rule_root = cep_cell_find_by_name(layout->coh_context_rules, &ctx_kind_dt);
        rule_root = rule_root ? cep_cell_resolve(rule_root) : NULL;
        if (rule_root && cep_cell_require_dictionary_store(&rule_root)) {
            facet_rules = cep_cell_find_by_name(rule_root, dt_facets_bucket());
            facet_rules = facet_rules ? cep_cell_resolve(facet_rules) : NULL;
            if (facet_rules && !cep_cell_require_dictionary_store(&facet_rules)) {
                facet_rules = NULL;
            }
            role_rules_root = cep_cell_find_by_name(rule_root, dt_roles_bucket());
            role_rules_root = role_rules_root ? cep_cell_resolve(role_rules_root) : NULL;
            if (role_rules_root && !cep_cell_require_dictionary_store(&role_rules_root)) {
                role_rules_root = NULL;
            }
        }
    }
    (void)cep_l1_coh_collect_role_rules(role_rules_root, ctx, &role_rules, &role_rule_count);
    bool enforce_roles = facet_rules != NULL || role_rule_count > 0u;

    for (cepCell* binding = ok ? cep_cell_first(participants) : NULL;
         binding;
         binding = cep_cell_next(participants, binding)) {
        binding = binding ? cep_cell_resolve(binding) : NULL;
        if (!binding || !cep_cell_require_dictionary_store(&binding)) {
            missing = true;
            continue;
        }
        char role_buffer[64] = {0};
        char being_buffer[160] = {0};
        char bond_buffer[160] = {0};
        (void)cep_l1_coh_copy_text_field(binding, dt_role_field(), role_buffer, sizeof role_buffer);
        if (!role_buffer[0]) {
            (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(binding), role_buffer, sizeof role_buffer);
        }
        (void)cep_l1_coh_copy_text_field(binding, dt_target_field_coh(), being_buffer, sizeof being_buffer);
        if (!being_buffer[0]) {
            (void)cep_l1_coh_copy_text_field(binding, dt_being_id_field(), being_buffer, sizeof being_buffer);
        }
        (void)cep_l1_coh_copy_text_field(binding, dt_bond_id_field(), bond_buffer, sizeof bond_buffer);

        if (!role_buffer[0] || !being_buffer[0]) {
            (void)cep_l1_coh_record_debt(layout, "missing_binding", ctx_id, role_buffer[0] ? role_buffer : "binding", "binding missing role or being");
            cep_l1_coh_emit_cei(dt_topic_role_invalid(), "binding missing role or being", ctx, NULL);
            missing = true;
            continue;
        }

        cepL1CohRoleRule* matched_rule = cep_l1_coh_find_role_rule(role_rules, role_rule_count, role_buffer);
        bool role_allowed = true;
        if (role_rule_count > 0u) {
            role_allowed = matched_rule != NULL;
        } else if (facet_rules) {
            role_allowed = cep_l1_coh_role_allowed(facet_rules, role_buffer);
        }
        if (enforce_roles && !role_allowed) {
            (void)cep_l1_coh_record_debt(layout, "invalid_role", ctx_id, role_buffer, "role not allowed by context rules");
            cep_l1_coh_emit_cei(dt_topic_role_invalid(), "role not allowed by context rules", ctx, NULL);
            missing = true;
            continue;
        }

        char* role_copy = cep_malloc(strlen(role_buffer) + 1u);
        memcpy(role_copy, role_buffer, strlen(role_buffer) + 1u);
        char* being_copy = cep_malloc(strlen(being_buffer) + 1u);
        memcpy(being_copy, being_buffer, strlen(being_buffer) + 1u);
        char* bond_copy = NULL;
        if (bond_buffer[0]) {
            bond_copy = cep_malloc(strlen(bond_buffer) + 1u);
            memcpy(bond_copy, bond_buffer, strlen(bond_buffer) + 1u);
        }

        views[view_count].role = role_copy;
        views[view_count].being = being_copy;
        views[view_count].being_kind = NULL;
        views[view_count].being_external = NULL;
        views[view_count].bond = bond_copy;
        views[view_count].being_present = true;

        cepDT being_dt = {0};
        cepCell* being_cell = NULL;
        if (!cep_l1_coh_make_dt(being_copy, &being_dt) ||
            !(being_cell = cep_cell_find_by_name(layout->coh_beings, &being_dt)) ||
            !(being_cell = cep_cell_resolve(being_cell))) {
            (void)cep_l1_coh_record_debt(layout, "missing_being", ctx_id, being_copy, "being missing for context");
            views[view_count].being_present = false;
            missing = true;
        } else {
            cep_l1_coh_resolve_debt(layout, "missing_being", ctx_id, being_copy, "being present");
        }

        if (matched_rule) {
            matched_rule->seen = true;
            if (matched_rule->required) {
                cep_l1_coh_resolve_debt(layout, "missing_role", ctx_id, role_buffer, "required role present");
            }
        }

        if (layout->coh_adj_by_being && views[view_count].being_present) {
            cepCell* by_being = NULL;
            if (cep_l1_coh_require_dict(layout->coh_adj_by_being, &being_dt, &by_being)) {
                cepCell* ctxs = cep_cell_ensure_dictionary_child(by_being, dt_contexts_bucket(), CEP_STORAGE_RED_BLACK_T);
                ctxs = ctxs ? cep_cell_resolve(ctxs) : NULL;
                if (ctxs && cep_cell_require_dictionary_store(&ctxs)) {
                    cepCell* entry = cep_cell_ensure_dictionary_child(ctxs, &ctx_dt, CEP_STORAGE_RED_BLACK_T);
                    entry = entry ? cep_cell_resolve(entry) : NULL;
                    if (entry && cep_cell_require_dictionary_store(&entry)) {
                        (void)cep_cell_put_text(entry, dt_role_field(), role_copy);
                    }
                }
            }
        }
        ++view_count;
    }

    if (view_count == 0u) {
        for (size_t i = 0; i < binding_cap; ++i) {
            cep_free((void*)views[i].role);
            cep_free((void*)views[i].being);
            if (views[i].bond) {
                cep_free((void*)views[i].bond);
            }
        }
        cep_free(views);
        cep_l1_coh_free_role_rules(role_rules, role_rule_count);
        return true;
    }

    if (layout->coh_adj_by_context && ok) {
        cepCell* by_ctx = NULL;
        if (cep_l1_coh_require_dict(layout->coh_adj_by_context, &ctx_dt, &by_ctx)) {
            cepCell* participants_idx = cep_cell_ensure_dictionary_child(by_ctx, dt_participants_name(), CEP_STORAGE_RED_BLACK_T);
            participants_idx = participants_idx ? cep_cell_resolve(participants_idx) : NULL;
            if (participants_idx && cep_cell_require_dictionary_store(&participants_idx)) {
                for (size_t i = 0; i < view_count; ++i) {
                    cepDT role_dt = {0};
                    if (!cep_l1_coh_make_dt(views[i].role, &role_dt)) {
                        continue;
                    }
                    cepCell* entry = cep_cell_ensure_dictionary_child(participants_idx, &role_dt, CEP_STORAGE_RED_BLACK_T);
                    entry = entry ? cep_cell_resolve(entry) : NULL;
                    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
                        continue;
                    }
                    (void)cep_cell_put_text(entry, dt_being_id_field(), views[i].being);
                    (void)cep_cell_put_text(entry, dt_role_field(), views[i].role);
                    if (views[i].bond) {
                        (void)cep_cell_put_text(entry, dt_bond_id_field(), views[i].bond);
                    }
                }
            }
        }
    }

    if (role_rule_count > 0u) {
        for (size_t i = 0; i < role_rule_count; ++i) {
            if (role_rules[i].required && !role_rules[i].seen) {
                (void)cep_l1_coh_record_debt(layout, "missing_role", ctx_id, role_rules[i].role, "required role missing");
                cep_l1_coh_emit_cei(dt_topic_role_invalid(), "required role missing", ctx, NULL);
                missing = true;
            }
        }
    }

    if (facet_rules) {
        for (cepCell* rule = cep_cell_first(facet_rules); rule; rule = cep_cell_next(facet_rules, rule)) {
            cepCell* resolved_rule = cep_cell_resolve(rule);
            if (!resolved_rule || !cep_cell_require_dictionary_store(&resolved_rule)) {
                ok = false;
                continue;
            }
            char facet_kind[128] = {0};
            char subject_role[64] = {0};
            char label[128] = {0};
            bool required_facet = false;
            (void)cep_l1_coh_copy_text_field(resolved_rule, dt_kind_field_coh(), facet_kind, sizeof facet_kind);
            if (!facet_kind[0]) {
                (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(resolved_rule), facet_kind, sizeof facet_kind);
            }
            (void)cep_l1_coh_copy_text_field(resolved_rule, dt_role_field(), subject_role, sizeof subject_role);
            if (!subject_role[0]) {
                (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(resolved_rule), subject_role, sizeof subject_role);
            }
            (void)cep_l1_coh_copy_text_field(resolved_rule, dt_label_field_coh(), label, sizeof label);
            (void)cep_l1_coh_copy_bool_field(resolved_rule, dt_required_field_coh(), &required_facet);
            if (!label[0] && subject_role[0]) {
                strncpy(label, subject_role, sizeof label - 1u);
                label[sizeof label - 1u] = '\0';
            }
            if (!facet_kind[0] || !subject_role[0]) {
                cep_l1_coh_emit_cei(dt_topic_rule_invalid(), "facet rule missing kind or role", ctx, NULL);
                continue;
            }
            cepL1CohBindingView* match = NULL;
            for (size_t i = 0; i < view_count; ++i) {
                if (strcmp(views[i].role, subject_role) == 0) {
                    match = &views[i];
                    break;
                }
            }
            if (!match || !match->being_present) {
                (void)cep_l1_coh_record_debt(layout, "missing_role", ctx_id, subject_role, required_facet ? "required facet role missing" : "context rule has no binding");
                cep_l1_coh_emit_cei(dt_topic_role_invalid(), required_facet ? "required facet role missing" : "context rule missing binding", ctx, NULL);
                if (required_facet) {
                    missing = true;
                }
                continue;
            }
            if (!cep_l1_coh_materialize_facet(layout, ctx, ctx_id, facet_kind, match->being, label)) {
                const char* debt_note = required_facet ? "required facet missing" : "failed to materialize facet from rule";
                (void)cep_l1_coh_record_debt(layout, "missing_facet", ctx_id, facet_kind, debt_note);
                cep_l1_coh_emit_cei(dt_topic_closure_fail(), debt_note, ctx, NULL);
                if (required_facet) {
                    missing = true;
                }
            } else {
                cep_l1_coh_resolve_debt(layout, "missing_facet", ctx_id, facet_kind, "facet materialized");
            }
        }
    } else {
        for (size_t i = 0; i < view_count; ++i) {
            if (!views[i].being_present) {
                continue;
            }
            if (!cep_l1_coh_materialize_facet(layout, ctx, ctx_id, views[i].role, views[i].being, views[i].role)) {
                (void)cep_l1_coh_record_debt(layout, "missing_facet", ctx_id, views[i].role, "failed to materialize default facet");
                cep_l1_coh_emit_cei(dt_topic_closure_fail(), "failed to materialize default facet", ctx, NULL);
                missing = true;
            } else {
                cep_l1_coh_resolve_debt(layout, "missing_facet", ctx_id, views[i].role, "facet materialized");
            }
        }
    }

    cep_l1_coh_free_role_rules(role_rules, role_rule_count);
    for (size_t i = 0; i < view_count; ++i) {
        cep_free((void*)views[i].role);
        cep_free((void*)views[i].being);
        if (views[i].bond) {
            cep_free((void*)views[i].bond);
        }
    }
    cep_free(views);
    return ok && !missing ? true : ok;
}

bool cep_l1_coh_run_closure(cepL1SchemaLayout* layout, const char* context_id) {
    if (!layout || !layout->coh_contexts || !layout->coh_beings || !layout->coh_facets || !layout->coh_debts) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_contexts) ||
        !cep_cell_require_dictionary_store(&layout->coh_beings) ||
        !cep_cell_require_dictionary_store(&layout->coh_facets) ||
        !cep_cell_require_dictionary_store(&layout->coh_debts)) {
        return false;
    }

    char ctx_id_buffer[192] = {0};
    bool ok = true;

    if (context_id && *context_id) {
        cepDT ctx_dt = {0};
        if (!cep_l1_coh_make_dt(context_id, &ctx_dt)) {
            return false;
        }
        cepCell* ctx = cep_cell_find_by_name(layout->coh_contexts, &ctx_dt);
        ctx = ctx ? cep_cell_resolve(ctx) : NULL;
        if (!ctx) {
            return false;
        }
        if (!cep_cell_require_dictionary_store(&ctx)) {
            return false;
        }
        strncpy(ctx_id_buffer, context_id, sizeof ctx_id_buffer - 1u);
        ctx_id_buffer[sizeof ctx_id_buffer - 1u] = '\0';
        return cep_l1_coh_process_context(layout, ctx, ctx_id_buffer);
    }

    for (cepCell* ctx = cep_cell_first(layout->coh_contexts); ctx; ctx = cep_cell_next(layout->coh_contexts, ctx)) {
        ctx = cep_cell_resolve(ctx);
        if (!ctx || !cep_cell_require_dictionary_store(&ctx)) {
            ok = false;
            continue;
        }

        memset(ctx_id_buffer, 0, sizeof ctx_id_buffer);
        if (!cep_l1_coh_copy_text_field(ctx, dt_context_id_field(), ctx_id_buffer, sizeof ctx_id_buffer)) {
            (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(ctx), ctx_id_buffer, sizeof ctx_id_buffer);
        }
        if (!ctx_id_buffer[0]) {
            strncpy(ctx_id_buffer, "ctx:unknown", sizeof ctx_id_buffer - 1u);
            ctx_id_buffer[sizeof ctx_id_buffer - 1u] = '\0';
        }

        if (!cep_l1_coh_process_context(layout, ctx, ctx_id_buffer)) {
            ok = false;
        }
    }

    return ok;
}
static int cep_l1_coh_closure_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    cepL1SchemaLayout layout = {0};
    if (!cep_l1_schema_ensure(&layout)) {
        return CEP_ENZYME_FATAL;
    }
    const char* ctx_id = NULL;
    char ctx_buffer[128] = {0};
    if (target && target->length > 0u) {
        const cepPast* tail = &target->past[target->length - 1u];
        if (cep_l1_coh_copy_dt_text(&tail->dt, ctx_buffer, sizeof ctx_buffer)) {
            ctx_id = ctx_buffer;
        }
    }

    if (!cep_l1_coh_run_closure(&layout, ctx_id)) {
        return CEP_ENZYME_FATAL;
    }
    return CEP_ENZYME_SUCCESS;
}

bool cep_l1_coh_register_closure_enzyme(void) {
    /* Register the adjacency-closure enzyme so pack bootstrap can rely on an
       opt-in signal (`coh:close`) to replay facet materialisation when new
       contexts or bindings arrive. */
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return false;
    }
    cepPath* path = cep_malloc(sizeof(cepPath) + sizeof(cepPast));
    if (!path) {
        return false;
    }
    path->length = 1u;
    path->capacity = 1u;
    path->past[0].dt = *dt_closure_signal();
    path->past[0].timestamp = 0u;

    cepEnzymeDescriptor descriptor = {
        .name = path->past[0].dt,
        .label = "coh.close",
        .callback = cep_l1_coh_closure_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    int rc = cep_enzyme_register(registry, (const cepPath*)path, &descriptor);
    cep_free(path);
    return rc == CEP_ENZYME_SUCCESS;
}
