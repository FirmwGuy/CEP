/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l3_runtime.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l2_ecology/cep_l2_playbook.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

CEP_DEFINE_STATIC_DT(dt_awareness_root, CEP_ACRO("CEP"), CEP_WORD("awareness"));
CEP_DEFINE_STATIC_DT(dt_awareness_maze, CEP_ACRO("CEP"), cep_namepool_intern_cstr("maze_risk_reward"));
CEP_DEFINE_STATIC_DT(dt_awareness_skill, CEP_ACRO("CEP"), cep_namepool_intern_cstr("skill_performance"));
CEP_DEFINE_STATIC_DT(dt_awareness_social, CEP_ACRO("CEP"), cep_namepool_intern_cstr("social_comm"));
CEP_DEFINE_STATIC_DT(dt_env_root, CEP_ACRO("CEP"), CEP_WORD("env"));
CEP_DEFINE_STATIC_DT(dt_env_maze, CEP_ACRO("CEP"), CEP_WORD("maze"));
CEP_DEFINE_STATIC_DT(dt_env_rats, CEP_ACRO("CEP"), CEP_WORD("rat"));
CEP_DEFINE_STATIC_DT(dt_env_shock, CEP_ACRO("CEP"), CEP_WORD("shock"));
CEP_DEFINE_STATIC_DT(dt_env_food, CEP_ACRO("CEP"), CEP_WORD("food"));
CEP_DEFINE_STATIC_DT(dt_env_steps, CEP_ACRO("CEP"), CEP_WORD("steps"));
CEP_DEFINE_STATIC_DT(dt_env_blocked, CEP_ACRO("CEP"), CEP_WORD("blocked"));
CEP_DEFINE_STATIC_DT(dt_env_hunger, CEP_ACRO("CEP"), CEP_WORD("hunger"));
CEP_DEFINE_STATIC_DT(dt_env_fatigue, CEP_ACRO("CEP"), CEP_WORD("fatigue"));
CEP_DEFINE_STATIC_DT(dt_env_trust, CEP_ACRO("CEP"), CEP_WORD("trust"));
CEP_DEFINE_STATIC_DT(dt_env_teach, CEP_ACRO("CEP"), CEP_WORD("teach"));
CEP_DEFINE_STATIC_DT(dt_env_noise, CEP_ACRO("CEP"), CEP_WORD("noise"));
CEP_DEFINE_STATIC_DT(dt_runtime_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_runtime_signal_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("signal_field"));
CEP_DEFINE_STATIC_DT(dt_signal_field_current, CEP_ACRO("CEP"), cep_namepool_intern_cstr("current"));
CEP_DEFINE_STATIC_DT(dt_runtime_metrics, CEP_ACRO("CEP"), cep_namepool_intern_cstr("metrics"));
CEP_DEFINE_STATIC_DT(dt_metrics_per_variant, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_variant"));
CEP_DEFINE_STATIC_DT(dt_runtime_playbooks, CEP_ACRO("CEP"), cep_namepool_intern_cstr("playbooks"));
CEP_DEFINE_STATIC_DT(dt_actions_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("actions"));
CEP_DEFINE_STATIC_DT(dt_attempts_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("attempts"));
CEP_DEFINE_STATIC_DT(dt_success_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("success"));
CEP_DEFINE_STATIC_DT(dt_imaginate_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_used"));
CEP_DEFINE_STATIC_DT(dt_avg_cost_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("avg_cost"));
CEP_DEFINE_STATIC_DT(dt_imaginate_rate_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_rate"));

static cepCell* cep_l3_require_dict(cepCell* parent, const cepDT* name) {
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

static cepCell* cep_l3_metrics_root(cepCell* eco_root) {
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    cepCell* metrics_root = runtime_root ? cep_cell_find_by_name(runtime_root, dt_runtime_metrics()) : NULL;
    metrics_root = metrics_root ? cep_cell_resolve(metrics_root) : NULL;
    return (metrics_root && cep_cell_require_dictionary_store(&metrics_root)) ? metrics_root : NULL;
}

static cepCell* cep_l3_signal_current(cepCell* eco_root) {
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    cepCell* signal_root = runtime_root ? cep_cell_find_by_name(runtime_root, dt_runtime_signal_field()) : NULL;
    signal_root = signal_root ? cep_cell_resolve(signal_root) : NULL;
    cepCell* current = signal_root ? cep_cell_find_by_name(signal_root, dt_signal_field_current()) : NULL;
    current = current ? cep_cell_resolve(current) : NULL;
    return (current && cep_cell_require_dictionary_store(&current)) ? current : NULL;
}

static uint64_t cep_l3_read_u64(cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return 0u;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child) {
        return 0u;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&child, &data) || !data || data->size < sizeof(uint64_t)) {
        return 0u;
    }
    uint64_t value = 0u;
    memcpy(&value, cep_data_payload(data), sizeof value);
    return value;
}

static double cep_l3_read_double(cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return 0.0;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_has_data(child)) {
        return 0.0;
    }
    const char* text = (const char*)cep_cell_data(child);
    if (!text) {
        return 0.0;
    }
    char* end = NULL;
    double parsed = strtod(text, &end);
    return (end && end != text) ? parsed : 0.0;
}

static uint64_t cep_l3_sum_u64(uint64_t a, uint64_t b) {
    uint64_t res = a + b;
    if (res < a) {
        res = UINT64_MAX;
    }
    return res;
}

static void cep_l3_awareness_maze(cepCell* awareness_root, cepCell* eco_root) {
    cepCell* maze_root = cep_l3_require_dict(awareness_root, dt_awareness_maze());
    cepCell* metrics_root = cep_l3_metrics_root(eco_root);
    cepCell* per_variant = metrics_root ? cep_cell_find_by_name(metrics_root, dt_metrics_per_variant()) : NULL;
    per_variant = per_variant ? cep_cell_resolve(per_variant) : NULL;
    if (!maze_root || !per_variant || !cep_cell_require_dictionary_store(&per_variant)) {
        return;
    }

    cepCell* signal_current = cep_l3_signal_current(eco_root);
    for (cepCell* bucket = cep_cell_first(per_variant); bucket; bucket = cep_cell_next(per_variant, bucket)) {
        cepCell* resolved = cep_cell_resolve(bucket);
        if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name || !cep_dt_is_valid(name)) {
            continue;
        }
        cepCell* entry = cep_l3_require_dict(maze_root, name);
        if (!entry) {
            continue;
        }
        (void)cep_cell_put_uint64(entry, dt_env_shock(), cep_l3_read_u64(resolved, dt_env_shock()));
        (void)cep_cell_put_uint64(entry, dt_env_food(), cep_l3_read_u64(resolved, dt_env_food()));
        (void)cep_cell_put_uint64(entry, dt_env_steps(), cep_l3_read_u64(resolved, dt_env_steps()));
        (void)cep_cell_put_uint64(entry, dt_env_blocked(), cep_l3_read_u64(resolved, dt_env_blocked()));
        (void)cep_cell_put_uint64(entry, dt_env_hunger(), cep_l3_read_u64(resolved, dt_env_hunger()));
        (void)cep_cell_put_uint64(entry, dt_env_fatigue(), cep_l3_read_u64(resolved, dt_env_fatigue()));
        if (signal_current) {
            (void)cep_cell_copy_children(signal_current, entry, false);
        }
    }
}

static void cep_l3_awareness_skill(cepCell* awareness_root, cepCell* eco_root) {
    cepCell* skill_root = cep_l3_require_dict(awareness_root, dt_awareness_skill());
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    cepCell* playbooks_root = runtime_root ? cep_cell_find_by_name(runtime_root, dt_runtime_playbooks()) : NULL;
    playbooks_root = playbooks_root ? cep_cell_resolve(playbooks_root) : NULL;
    if (!skill_root || !playbooks_root || !cep_cell_require_dictionary_store(&playbooks_root)) {
        return;
    }

    for (cepCell* learner = cep_cell_first(playbooks_root); learner; learner = cep_cell_next(playbooks_root, learner)) {
        cepCell* learner_cell = cep_cell_resolve(learner);
        if (!learner_cell || !cep_cell_require_dictionary_store(&learner_cell)) {
            continue;
        }
        const cepDT* learner_dt = cep_cell_get_name(learner_cell);
        if (!learner_dt || !cep_dt_is_valid(learner_dt)) {
            continue;
        }
        cepCell* learner_out = cep_l3_require_dict(skill_root, learner_dt);
        if (!learner_out) {
            continue;
        }
        for (cepCell* focus = cep_cell_first(learner_cell); focus; focus = cep_cell_next(learner_cell, focus)) {
            cepCell* focus_cell = cep_cell_resolve(focus);
            if (!focus_cell || !cep_cell_require_dictionary_store(&focus_cell)) {
                continue;
            }
            const cepDT* focus_dt = cep_cell_get_name(focus_cell);
            if (!focus_dt || !cep_dt_is_valid(focus_dt)) {
                continue;
            }
            cepCell* focus_out = cep_l3_require_dict(learner_out, focus_dt);
            if (!focus_out) {
                continue;
            }
            cepCell* actions = cep_cell_find_by_name(focus_cell, dt_actions_field());
            actions = actions ? cep_cell_resolve(actions) : NULL;
            if (!actions || !cep_cell_require_dictionary_store(&actions)) {
                continue;
            }
            uint64_t total_attempts = 0u;
            uint64_t total_success = 0u;
            uint64_t imaginate_hits = 0u;
            double total_cost = 0.0;
            uint64_t total_cost_samples = 0u;
            for (cepCell* action = cep_cell_first(actions); action; action = cep_cell_next(actions, action)) {
                cepCell* act_cell = cep_cell_resolve(action);
                if (!act_cell || !cep_cell_require_dictionary_store(&act_cell)) {
                    continue;
                }
                uint64_t attempts = cep_l3_read_u64(act_cell, dt_attempts_field());
                uint64_t success = cep_l3_read_u64(act_cell, dt_success_field());
                uint64_t imaginate = cep_l3_read_u64(act_cell, dt_imaginate_field());
                double avg_cost = cep_l3_read_double(act_cell, dt_avg_cost_field());
                total_attempts = cep_l3_sum_u64(total_attempts, attempts);
                total_success = cep_l3_sum_u64(total_success, success);
                imaginate_hits = cep_l3_sum_u64(imaginate_hits, imaginate);
                if (attempts > 0u) {
                    total_cost += avg_cost * (double)attempts;
                    total_cost_samples = cep_l3_sum_u64(total_cost_samples, attempts);
                }
            }
            double imaginate_rate = (total_attempts > 0u) ? ((double)imaginate_hits / (double)total_attempts) : 0.0;
            double avg_cost = (total_cost_samples > 0u) ? (total_cost / (double)total_cost_samples) : 0.0;
            char rate_buf[32];
            char cost_buf[32];
            snprintf(rate_buf, sizeof rate_buf, "%.6f", imaginate_rate);
            snprintf(cost_buf, sizeof cost_buf, "%.6f", avg_cost);
            (void)cep_cell_put_uint64(focus_out, dt_attempts_field(), total_attempts);
            (void)cep_cell_put_uint64(focus_out, dt_success_field(), total_success);
            (void)cep_cell_put_uint64(focus_out, dt_imaginate_field(), imaginate_hits);
            (void)cep_cell_put_text(focus_out, dt_imaginate_rate_field(), rate_buf);
            (void)cep_cell_put_text(focus_out, dt_avg_cost_field(), cost_buf);
        }
    }
}

static void cep_l3_awareness_social(cepCell* awareness_root, cepCell* eco_root) {
    cepCell* social_root = cep_l3_require_dict(awareness_root, dt_awareness_social());
    cepCell* metrics_root = cep_l3_metrics_root(eco_root);
    cepCell* per_variant = metrics_root ? cep_cell_find_by_name(metrics_root, dt_metrics_per_variant()) : NULL;
    per_variant = per_variant ? cep_cell_resolve(per_variant) : NULL;
    if (!social_root || !per_variant || !cep_cell_require_dictionary_store(&per_variant)) {
        return;
    }

    for (cepCell* bucket = cep_cell_first(per_variant); bucket; bucket = cep_cell_next(per_variant, bucket)) {
        cepCell* resolved = cep_cell_resolve(bucket);
        if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name || !cep_dt_is_valid(name)) {
            continue;
        }
        cepCell* entry = cep_l3_require_dict(social_root, name);
        if (!entry) {
            continue;
        }
        (void)cep_cell_put_uint64(entry, dt_env_trust(), cep_l3_read_u64(resolved, dt_env_trust()));
        (void)cep_cell_put_uint64(entry, dt_env_teach(), cep_l3_read_u64(resolved, dt_env_teach()));
        (void)cep_cell_put_uint64(entry, dt_env_noise(), cep_l3_read_u64(resolved, dt_env_noise()));
    }
}

void cep_l3_awareness_run(cepCell* eco_root, cepCell* data_root) {
    if (!eco_root || !data_root) {
        return;
    }
    cepCell* awareness_root = cep_l3_require_dict(data_root, dt_awareness_root());
    if (!awareness_root) {
        return;
    }
    cep_l3_awareness_maze(awareness_root, eco_root);
    cep_l3_awareness_skill(awareness_root, eco_root);
    cep_l3_awareness_social(awareness_root, eco_root);
}
