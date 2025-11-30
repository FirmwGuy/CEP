/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l4_runtime.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l2_ecology/cep_l2_focus.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

CEP_DEFINE_STATIC_DT(dt_gov_root, CEP_ACRO("CEP"), CEP_WORD("gov"));
CEP_DEFINE_STATIC_DT(dt_gov_provinces, CEP_ACRO("CEP"), cep_namepool_intern_cstr("rat_provinces"));
CEP_DEFINE_STATIC_DT(dt_gov_state, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_risk_cap_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("risk_cap"));
CEP_DEFINE_STATIC_DT(dt_imaginate_min_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_min"));
CEP_DEFINE_STATIC_DT(dt_compliance_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("compliance"));
CEP_DEFINE_STATIC_DT(dt_risk_cap_hit_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("risk_cap_hit"));
CEP_DEFINE_STATIC_DT(dt_imaginate_low_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_low"));
CEP_DEFINE_STATIC_DT(dt_imaginate_rate_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_rate"));
CEP_DEFINE_STATIC_DT(dt_runtime_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_runtime_signal_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("signal_field"));
CEP_DEFINE_STATIC_DT(dt_signal_field_current, CEP_ACRO("CEP"), cep_namepool_intern_cstr("current"));
CEP_DEFINE_STATIC_DT(dt_runtime_playbooks, CEP_ACRO("CEP"), cep_namepool_intern_cstr("playbooks"));
CEP_DEFINE_STATIC_DT(dt_actions_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("actions"));
CEP_DEFINE_STATIC_DT(dt_attempts_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("attempts"));
CEP_DEFINE_STATIC_DT(dt_imaginate_flag_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_used"));

static cepCell* cep_l4_require_dict(cepCell* parent, const cepDT* name) {
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

static cepCell* cep_l4_signal_current(cepCell* eco_root) {
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    cepCell* signal_root = runtime_root ? cep_cell_find_by_name(runtime_root, dt_runtime_signal_field()) : NULL;
    signal_root = signal_root ? cep_cell_resolve(signal_root) : NULL;
    cepCell* current = signal_root ? cep_cell_find_by_name(signal_root, dt_signal_field_current()) : NULL;
    current = current ? cep_cell_resolve(current) : NULL;
    return (current && cep_cell_require_dictionary_store(&current)) ? current : NULL;
}

static uint64_t cep_l4_read_u64(cepCell* parent, const cepDT* field) {
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

static uint64_t cep_l4_sum_u64(uint64_t a, uint64_t b) {
    uint64_t res = a + b;
    if (res < a) {
        res = UINT64_MAX;
    }
    return res;
}

static double cep_l4_imaginate_rate(cepCell* eco_root) {
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    cepCell* playbooks_root = runtime_root ? cep_cell_find_by_name(runtime_root, dt_runtime_playbooks()) : NULL;
    playbooks_root = playbooks_root ? cep_cell_resolve(playbooks_root) : NULL;
    if (!playbooks_root || !cep_cell_require_dictionary_store(&playbooks_root)) {
        return 0.0;
    }
    uint64_t attempts = 0u;
    uint64_t imaginate_hits = 0u;
    for (cepCell* learner = cep_cell_first(playbooks_root); learner; learner = cep_cell_next(playbooks_root, learner)) {
        cepCell* learner_cell = cep_cell_resolve(learner);
        if (!learner_cell || !cep_cell_require_dictionary_store(&learner_cell)) {
            continue;
        }
        for (cepCell* focus = cep_cell_first(learner_cell); focus; focus = cep_cell_next(learner_cell, focus)) {
            cepCell* focus_cell = cep_cell_resolve(focus);
            if (!focus_cell || !cep_cell_require_dictionary_store(&focus_cell)) {
                continue;
            }
            cepCell* actions = cep_cell_find_by_name(focus_cell, dt_actions_field());
            actions = actions ? cep_cell_resolve(actions) : NULL;
            if (!actions || !cep_cell_require_dictionary_store(&actions)) {
                continue;
            }
            for (cepCell* action = cep_cell_first(actions); action; action = cep_cell_next(actions, action)) {
                cepCell* act_cell = cep_cell_resolve(action);
                if (!act_cell || !cep_cell_require_dictionary_store(&act_cell)) {
                    continue;
                }
                attempts = cep_l4_sum_u64(attempts, cep_l4_read_u64(act_cell, dt_attempts_field()));
                imaginate_hits = cep_l4_sum_u64(imaginate_hits, cep_l4_read_u64(act_cell, dt_imaginate_flag_field()));
            }
        }
    }
    return (attempts > 0u) ? ((double)imaginate_hits / (double)attempts) : 0.0;
}

static const char* cep_l4_read_text(cepCell* parent, const cepDT* field, char* buf, size_t buf_sz) {
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

void cep_l4_governance_run(cepCell* eco_root, cepCell* data_root) {
    if (!eco_root || !data_root) {
        return;
    }
    cepCell* gov_root = cep_l4_require_dict(data_root, dt_gov_root());
    cepCell* provinces_root = gov_root ? cep_l4_require_dict(gov_root, dt_gov_provinces()) : NULL;
    cepCell* state_root = gov_root ? cep_l4_require_dict(gov_root, dt_gov_state()) : NULL;
    cepCell* signals = cep_l4_signal_current(eco_root);
    if (!gov_root || !provinces_root || !state_root || !signals) {
        return;
    }

    const char* seeds[] = {"lab_train", "lab_coop", "lab_compet"};
    for (size_t i = 0u; i < cep_lengthof(seeds); ++i) {
        cepDT id = {.domain = CEP_ACRO("CEP"), .tag = cep_namepool_intern_cstr(seeds[i]), .glob = 0u};
        cepCell* cfg = cep_cell_find_by_name(provinces_root, &id);
        cfg = cfg ? cep_cell_resolve(cfg) : cep_cell_ensure_dictionary_child(provinces_root, &id, CEP_STORAGE_RED_BLACK_T);
        if (cfg && cep_cell_require_dictionary_store(&cfg)) {
            if (!cep_cell_find_by_name(cfg, dt_risk_cap_field())) {
                (void)cep_cell_put_text(cfg, dt_risk_cap_field(), i == 0u ? "0.7" : "0.5");
            }
            if (!cep_cell_find_by_name(cfg, dt_imaginate_min_field())) {
                (void)cep_cell_put_text(cfg, dt_imaginate_min_field(), i == 0u ? "0.05" : "0.02");
            }
        }
    }

    double risk = 0.0;
    (void)cep_l2_focus_read_signal(signals, "risk", &risk);
    double imaginate_rate = cep_l4_imaginate_rate(eco_root);

    for (cepCell* province = cep_cell_first(provinces_root); province; province = cep_cell_next(provinces_root, province)) {
        cepCell* cfg = cep_cell_resolve(province);
        if (!cfg || !cep_cell_require_dictionary_store(&cfg)) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(cfg);
        if (!name || !cep_dt_is_valid(name)) {
            continue;
        }
        char buf[32];
        const char* risk_cap_txt = cep_l4_read_text(cfg, dt_risk_cap_field(), buf, sizeof buf);
        double risk_cap = risk_cap_txt ? strtod(risk_cap_txt, NULL) : 1.0;
        const char* imaginate_min_txt = cep_l4_read_text(cfg, dt_imaginate_min_field(), buf, sizeof buf);
        double imaginate_min = imaginate_min_txt ? strtod(imaginate_min_txt, NULL) : 0.0;

        cepCell* state_entry = cep_l4_require_dict(state_root, name);
        if (!state_entry) {
            continue;
        }
        bool risk_hit = risk_cap > 0.0 && risk > risk_cap;
        bool imaginate_low = imaginate_min > 0.0 && imaginate_rate < imaginate_min;
        (void)cep_cell_put_uint64(state_entry, dt_risk_cap_hit_field(), risk_hit ? 1u : 0u);
        (void)cep_cell_put_uint64(state_entry, dt_imaginate_low_field(), imaginate_low ? 1u : 0u);
        cepCell* comp = cep_l4_require_dict(state_entry, dt_compliance_field());
        if (comp) {
            (void)cep_cell_put_text(comp, dt_risk_cap_field(), risk_cap_txt ? risk_cap_txt : "unset");
            (void)cep_cell_put_text(comp, dt_imaginate_min_field(), imaginate_min_txt ? imaginate_min_txt : "unset");
            char rate_buf[32];
            snprintf(rate_buf, sizeof rate_buf, "%.6f", imaginate_rate);
            (void)cep_cell_put_text(comp, dt_imaginate_rate_field(), rate_buf);
        }
    }
}
