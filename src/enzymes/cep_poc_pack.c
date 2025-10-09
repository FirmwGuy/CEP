/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_poc_pack.h"

#include "cep_l2_flows.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_l0.h"
#include "../l0_kernel/cep_mailroom.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_identifier.h"

#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/*  Domain helpers                                                           */
/* ------------------------------------------------------------------------- */

static cepID cep_poc_domain(void) {
    return CEP_ACRO("CEP");
}

#define CEP_POC_DT_STATIC(fn_name, literal) \
    static const cepDT* fn_name(void) { \
        static cepDT dt = {0}; \
        if (!dt.tag) { \
            dt.domain = cep_poc_domain(); \
            dt.tag = cep_namepool_intern_static((literal), sizeof(literal) - 1u); \
        } \
        return &dt; \
    }

CEP_DEFINE_STATIC_DT(dt_dictionary, CEP_ACRO("CEP"), CEP_WORD("dictionary"))
CEP_DEFINE_STATIC_DT(dt_text, CEP_ACRO("CEP"), CEP_WORD("text"))
CEP_DEFINE_STATIC_DT(dt_data, CEP_ACRO("CEP"), CEP_WORD("data"))
CEP_DEFINE_STATIC_DT(dt_sys, CEP_ACRO("CEP"), CEP_WORD("sys"))
CEP_DEFINE_STATIC_DT(dt_tmp, CEP_ACRO("CEP"), CEP_WORD("tmp"))
CEP_DEFINE_STATIC_DT(dt_poc, CEP_ACRO("CEP"), CEP_WORD("poc"))
CEP_DEFINE_STATIC_DT(dt_io, CEP_ACRO("CEP"), CEP_WORD("io"))
CEP_DEFINE_STATIC_DT(dt_hz, CEP_ACRO("CEP"), CEP_WORD("hz"))
CEP_DEFINE_STATIC_DT(dt_index, CEP_ACRO("CEP"), CEP_WORD("index"))
CEP_DEFINE_STATIC_DT(dt_inbox, CEP_ACRO("CEP"), CEP_WORD("inbox"))
CEP_DEFINE_STATIC_DT(dt_adj, CEP_ACRO("CEP"), CEP_WORD("adj"))
CEP_DEFINE_STATIC_DT(dt_summary, CEP_ACRO("CEP"), CEP_WORD("summary"))
CEP_DEFINE_STATIC_DT(dt_recent, CEP_ACRO("CEP"), CEP_WORD("recent"))
CEP_DEFINE_STATIC_DT(dt_original, CEP_ACRO("CEP"), CEP_WORD("original"))
CEP_DEFINE_STATIC_DT(dt_outcome, CEP_ACRO("CEP"), CEP_WORD("outcome"))
CEP_DEFINE_STATIC_DT(dt_enabled, CEP_ACRO("CEP"), CEP_WORD("enabled"))
CEP_DEFINE_STATIC_DT(dt_retention, CEP_ACRO("CEP"), CEP_WORD("retention"))
CEP_DEFINE_STATIC_DT(dt_echo, CEP_ACRO("CEP"), CEP_WORD("echo"))
CEP_DEFINE_STATIC_DT(dt_calc, CEP_ACRO("CEP"), CEP_WORD("calc"))
CEP_DEFINE_STATIC_DT(dt_kv, CEP_ACRO("CEP"), CEP_WORD("kv"))
CEP_DEFINE_STATIC_DT(dt_ans, CEP_ACRO("CEP"), CEP_WORD("ans"))
CEP_DEFINE_STATIC_DT(dt_scenario, CEP_ACRO("CEP"), CEP_WORD("scenario"))
CEP_DEFINE_STATIC_DT(dt_run, CEP_ACRO("CEP"), CEP_WORD("run"))
CEP_DEFINE_STATIC_DT(dt_text_field, CEP_ACRO("CEP"), CEP_WORD("text"))
CEP_DEFINE_STATIC_DT(dt_expr, CEP_ACRO("CEP"), CEP_WORD("expr"))
CEP_DEFINE_STATIC_DT(dt_result, CEP_ACRO("CEP"), CEP_WORD("result"))
CEP_DEFINE_STATIC_DT(dt_inputs, CEP_ACRO("CEP"), CEP_WORD("inputs"))
CEP_DEFINE_STATIC_DT(dt_id, CEP_ACRO("CEP"), CEP_WORD("id"))
CEP_DEFINE_STATIC_DT(dt_key, CEP_ACRO("CEP"), CEP_WORD("key"))
CEP_DEFINE_STATIC_DT(dt_value, CEP_ACRO("CEP"), CEP_WORD("value"))
CEP_DEFINE_STATIC_DT(dt_kind, CEP_ACRO("CEP"), CEP_WORD("kind"))
CEP_DEFINE_STATIC_DT(dt_steps, CEP_ACRO("CEP"), CEP_WORD("steps"))
CEP_DEFINE_STATIC_DT(dt_asserts, CEP_ACRO("CEP"), CEP_WORD("asserts"))
CEP_DEFINE_STATIC_DT(dt_spawns, CEP_ACRO("CEP"), CEP_WORD("spawns"))
CEP_DEFINE_STATIC_DT(dt_expect, CEP_ACRO("CEP"), CEP_WORD("expect"))
CEP_DEFINE_STATIC_DT(dt_path, CEP_ACRO("CEP"), CEP_WORD("path"))
CEP_DEFINE_STATIC_DT(dt_parent, CEP_ACRO("CEP"), CEP_WORD("parent"))
CEP_DEFINE_STATIC_DT(dt_actual, CEP_ACRO("CEP"), CEP_WORD("actual"))
CEP_DEFINE_STATIC_DT(dt_diff, CEP_ACRO("CEP"), CEP_WORD("diff"))
CEP_DEFINE_STATIC_DT(dt_target, CEP_ACRO("CEP"), CEP_WORD("target"))
CEP_DEFINE_STATIC_DT(dt_beat, CEP_ACRO("CEP"), CEP_WORD("beat"))
CEP_DEFINE_STATIC_DT(dt_params, CEP_ACRO("CEP"), CEP_WORD("params"))
CEP_DEFINE_STATIC_DT(dt_flow, CEP_ACRO("CEP"), CEP_WORD("flow"))
CEP_DEFINE_STATIC_DT(dt_decision, CEP_ACRO("CEP"), CEP_WORD("decision"))
CEP_DEFINE_STATIC_DT(dt_validation, CEP_ACRO("CEP"), CEP_WORD("validation"))
CEP_DEFINE_STATIC_DT(dt_evidence, CEP_ACRO("CEP"), CEP_WORD("evidence"))
CEP_DEFINE_STATIC_DT(dt_telemetry, CEP_ACRO("CEP"), CEP_WORD("telemetry"))
CEP_DEFINE_STATIC_DT(dt_site_field, CEP_ACRO("CEP"), CEP_WORD("site"))
CEP_DEFINE_STATIC_DT(dt_meta, CEP_ACRO("CEP"), CEP_WORD("meta"))
CEP_DEFINE_STATIC_DT(dt_variant_field, CEP_ACRO("CEP"), CEP_WORD("variant"))
CEP_DEFINE_STATIC_DT(dt_inst_by_var, CEP_ACRO("CEP"), CEP_WORD("inst_by_var"))
CEP_DEFINE_STATIC_DT(dt_dec_by_pol, CEP_ACRO("CEP"), CEP_WORD("dec_by_pol"))
CEP_DEFINE_STATIC_DT(dt_choice_field, CEP_ACRO("CEP"), CEP_WORD("choice"))
CEP_DEFINE_STATIC_DT(dt_score, CEP_ACRO("CEP"), CEP_WORD("score"))
CEP_DEFINE_STATIC_DT(dt_confidence, CEP_ACRO("CEP"), CEP_WORD("confidence"))
CEP_DEFINE_STATIC_DT(dt_latency, CEP_ACRO("CEP"), CEP_WORD("latency"))
CEP_DEFINE_STATIC_DT(dt_error_flag, CEP_ACRO("CEP"), CEP_WORD("error_flag"))
CEP_DEFINE_STATIC_DT(dt_count_field, CEP_ACRO("CEP"), CEP_WORD("count"))
CEP_DEFINE_STATIC_DT(dt_lat_window, CEP_ACRO("CEP"), CEP_WORD("lat_window"))
CEP_DEFINE_STATIC_DT(dt_err_window, CEP_ACRO("CEP"), CEP_WORD("err_window"))
CEP_DEFINE_STATIC_DT(dt_keys, CEP_ACRO("CEP"), CEP_WORD("keys"))
CEP_DEFINE_STATIC_DT(dt_tomb, CEP_ACRO("CEP"), CEP_WORD("tomb"))
CEP_DEFINE_STATIC_DT(dt_parents, CEP_ACRO("CEP"), CEP_WORD("parents"))
CEP_DEFINE_STATIC_DT(dt_policy, CEP_ACRO("CEP"), CEP_WORD("policy"))
CEP_DEFINE_STATIC_DT(dt_arms, CEP_ACRO("CEP"), CEP_WORD("arms"))
CEP_DEFINE_STATIC_DT(dt_epsilon, CEP_ACRO("CEP"), CEP_WORD("epsilon"))
CEP_DEFINE_STATIC_DT(dt_rng_seed, CEP_ACRO("CEP"), CEP_WORD("rng_seed"))
CEP_DEFINE_STATIC_DT(dt_rng_seq, CEP_ACRO("CEP"), CEP_WORD("rng_seq"))
CEP_DEFINE_STATIC_DT(dt_bandit, CEP_ACRO("CEP"), CEP_WORD("bandit"))
CEP_DEFINE_STATIC_DT(dt_choices, CEP_ACRO("CEP"), CEP_WORD("choices"))
CEP_DEFINE_STATIC_DT(dt_calc_expr, CEP_ACRO("CEP"), CEP_WORD("calc_expr"))
CEP_DEFINE_STATIC_DT(dt_kv_prefix, CEP_ACRO("CEP"), CEP_WORD("kv_prefix"))
CEP_DEFINE_STATIC_DT(dt_kv_hist, CEP_ACRO("CEP"), CEP_WORD("kv_hist"))
CEP_DEFINE_STATIC_DT(dt_ids, CEP_ACRO("CEP"), CEP_WORD("ids"))
CEP_DEFINE_STATIC_DT(dt_retain_mode, CEP_ACRO("CEP"), CEP_WORD("retain_mode"))
CEP_DEFINE_STATIC_DT(dt_retain_ttl, CEP_ACRO("CEP"), CEP_WORD("retain_ttl"))
CEP_DEFINE_STATIC_DT(dt_retain_upto, CEP_ACRO("CEP"), CEP_WORD("retain_upto"))

CEP_DEFINE_STATIC_DT(dt_poc_echo_intent, CEP_ACRO("CEP"), CEP_WORD("poc_echo"))
CEP_DEFINE_STATIC_DT(dt_poc_calc_intent, CEP_ACRO("CEP"), CEP_WORD("poc_calc"))
CEP_DEFINE_STATIC_DT(dt_poc_kv_set_intent, CEP_ACRO("CEP"), CEP_WORD("poc_kv_set"))
CEP_DEFINE_STATIC_DT(dt_poc_kv_get_intent, CEP_ACRO("CEP"), CEP_WORD("poc_kv_get"))
CEP_DEFINE_STATIC_DT(dt_poc_kv_del_intent, CEP_ACRO("CEP"), CEP_WORD("poc_kv_del"))
CEP_POC_DT_STATIC(dt_poc_scenario_intent, "poc_scenario")
CEP_DEFINE_STATIC_DT(dt_poc_run_intent, CEP_ACRO("CEP"), CEP_WORD("poc_run"))
CEP_DEFINE_STATIC_DT(dt_poc_assert_intent, CEP_ACRO("CEP"), CEP_WORD("poc_assert"))
CEP_DEFINE_STATIC_DT(dt_poc_bandit_intent, CEP_ACRO("CEP"), CEP_WORD("poc_bandit"))

CEP_POC_DT_STATIC(dt_poc_io_ing_echo, "poc_io_ing_echo")
CEP_POC_DT_STATIC(dt_poc_io_ing_calc, "poc_io_ing_calc")
CEP_POC_DT_STATIC(dt_poc_io_ing_kv, "poc_io_ing_kv")
CEP_POC_DT_STATIC(dt_poc_io_index, "poc_io_index")
CEP_POC_DT_STATIC(dt_poc_io_adj, "poc_io_adj")
CEP_POC_DT_STATIC(dt_poc_hz_ing_scenario, "poc_hz_ing_scenario")
CEP_POC_DT_STATIC(dt_poc_hz_ing_run, "poc_hz_ing_run")
CEP_POC_DT_STATIC(dt_poc_hz_ing_assert, "poc_hz_ing_assert")
CEP_POC_DT_STATIC(dt_poc_hz_ing_bandit, "poc_hz_ing_bandit")
CEP_POC_DT_STATIC(dt_poc_hz_index, "poc_hz_index")
static const char* const cep_poc_mailroom_namespace = "poc";
static const char* const cep_poc_mailroom_buckets[] = {
    "poc_echo",
    "poc_calc",
    "poc_kv_set",
    "poc_kv_get",
    "poc_kv_del",
    "poc_scenario",
    "poc_run",
    "poc_assert",
    "poc_bandit",
};

static const char* const cep_poc_router_before[] = {
    "poc_io_ing_echo",
    "poc_io_ing_calc",
    "poc_io_ing_kv",
    "poc_hz_ing_scenario",
    "poc_hz_ing_run",
    "poc_hz_ing_assert",
    "poc_hz_ing_bandit",
};

CEP_POC_DT_STATIC(dt_poc_hz_adj, "poc_hz_adj")

/* ------------------------------------------------------------------------- */
/*  Forward declarations                                                     */
/* ------------------------------------------------------------------------- */

static int cep_poc_enzyme_io_echo(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_io_calc(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_io_kv(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_io_index(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_io_adj(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_hz_scenario(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_hz_run(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_hz_assert(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_hz_bandit(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_hz_index(const cepPath* signal, const cepPath* target);
static int cep_poc_enzyme_hz_adj(const cepPath* signal, const cepPath* target);

/* ------------------------------------------------------------------------- */
/*  Lock guards                                                              */
/* ------------------------------------------------------------------------- */

typedef struct {
    cepCell* cell;
    cepLockToken token;
    bool locked;
} cepPocStoreLock;

static void cep_poc_store_unlock(cepPocStoreLock* guard) {
    if (!guard || !guard->locked || !guard->cell) {
        return;
    }
    cep_store_unlock(guard->cell, &guard->token);
    guard->locked = false;
    guard->cell = NULL;
}

static bool cep_poc_store_lock(cepCell* cell, cepPocStoreLock* guard) {
    if (!guard) {
        return false;
    }

    guard->cell = NULL;
    guard->locked = false;

    if (!cell || !cep_cell_has_store(cell)) {
        return false;
    }

    if (!cep_store_lock(cell, &guard->token)) {
        return false;
    }

    guard->cell = cell;
    guard->locked = true;
    return true;
}

static cepCell* cep_poc_data_root(void) {
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    return cep_cell_find_by_name(root, dt_data());
}

static cepCell* cep_poc_sys_root(void) {
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    return cep_cell_find_by_name(root, dt_sys());
}

static cepCell* cep_poc_tmp_root(void) {
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    return cep_cell_find_by_name(root, dt_tmp());
}

static cepCell* cep_poc_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        return existing;
    }

    cepDT type = *dt_dictionary();
    cepDT name_copy = *name;
    return cep_dict_add_dictionary(parent, &name_copy, &type, storage);
}

static bool cep_poc_set_string_value(cepCell* parent, const cepDT* name, const char* text) {
    if (!parent || !name || !text) {
        return false;
    }

    size_t size = strlen(text) + 1u;
    cepCell* node = cep_cell_find_by_name(parent, name);
    if (node && cep_cell_has_data(node)) {
        const cepData* data = node->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size == size && memcmp(data->value, text, size) == 0) {
            return true;
        }
        cep_cell_remove_hard(parent, node);
    } else if (node) {
        cep_cell_remove_hard(parent, node);
    }

    cepDT type = *dt_text();
    cepDT name_copy = *name;
    cepCell* value = cep_dict_add_value(parent, &name_copy, &type, (void*)text, size, size);
    if (!value) {
        return false;
    }
    cep_cell_content_hash(value);
    return true;
}

static bool cep_poc_mark_outcome(cepCell* request, const char* status) {
    if (!request || !status) {
        return false;
    }
    return cep_poc_set_string_value(request, dt_outcome(), status);
}

static bool cep_poc_text_to_dt(const char* text, cepDT* out_dt) {
    if (!text || !out_dt) {
        return false;
    }

    cepID word = cep_text_to_word(text);
    if (word) {
        out_dt->domain = cep_poc_domain();
        out_dt->tag = word;
        return true;
    }

    cepID ref = cep_namepool_intern(text, strlen(text));
    if (!ref) {
        return false;
    }

    out_dt->domain = cep_poc_domain();
    out_dt->tag = ref;
    return true;
}

static cepCell* cep_poc_io_root(void) {
    cepCell* poc = NULL;
    cepCell* data = cep_poc_data_root();
    if (data) {
        poc = cep_cell_find_by_name(data, dt_poc());
    }
    if (!poc) {
        return NULL;
    }
    return cep_cell_find_by_name(poc, dt_io());
}

static cepCell* cep_poc_hz_root(void) {
    cepCell* poc = NULL;
    cepCell* data = cep_poc_data_root();
    if (data) {
        poc = cep_cell_find_by_name(data, dt_poc());
    }
    if (!poc) {
        return NULL;
    }
    return cep_cell_find_by_name(poc, dt_hz());
}

static cepCell* cep_poc_io_inbox(void) {
    cepCell* io_root = cep_poc_io_root();
    if (!io_root) {
        return NULL;
    }
    return cep_cell_find_by_name(io_root, dt_inbox());
}

static cepCell* cep_poc_hz_inbox(void) {
    cepCell* hz_root = cep_poc_hz_root();
    if (!hz_root) {
        return NULL;
    }
    return cep_cell_find_by_name(hz_root, dt_inbox());
}

static cepCell* cep_poc_inbox_bucket(cepCell* inbox, const cepDT* bucket_name) {
    if (!inbox || !bucket_name) {
        return NULL;
    }
    return cep_cell_find_by_name(inbox, bucket_name);
}

static bool cep_poc_intent_abort(cepPocIntent* intent) {
    if (!intent || !intent->request) {
        return false;
    }

    cepCell* bucket = cep_cell_parent(intent->request);
    cep_cell_remove_hard(intent->request, NULL);
    (void)bucket;
    intent->request = NULL;
    intent->original = NULL;
    return true;
}

static bool cep_poc_set_string_default(cepCell* parent, const cepDT* field, const char* text) {
    if (!parent || !field || !text) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(parent, field);
    if (existing) {
        return true;
    }

    return cep_poc_set_string_value(parent, field, text);
}

static bool cep_poc_configure_retention_slot(cepCell* retention_root,
                                             const cepDT* slot_name,
                                             const char* mode_text,
                                             const char* ttl_text,
                                             const char* upto_text) {
    if (!retention_root || !slot_name) {
        return false;
    }

    cepCell* slot = cep_poc_ensure_dictionary(retention_root, slot_name, CEP_STORAGE_RED_BLACK_T);
    if (!slot) {
        return false;
    }

    if (mode_text && !cep_poc_set_string_default(slot, dt_retain_mode(), mode_text)) {
        return false;
    }
    if (ttl_text && !cep_poc_set_string_default(slot, dt_retain_ttl(), ttl_text)) {
        return false;
    }
    if (upto_text && !cep_poc_set_string_default(slot, dt_retain_upto(), upto_text)) {
        return false;
    }

    return true;
}

/* Ensure the PoC directory tree and toggles exist before any registry wiring
 * so ingest enzymes can assume the ledgers and inbox buckets already exist. */
bool cep_poc_bootstrap(void) {
    if (!cep_l0_bootstrap()) {
        return false;
    }

    if (!cep_mailroom_add_namespace(cep_poc_mailroom_namespace,
                                    cep_poc_mailroom_buckets,
                                    cep_lengthof(cep_poc_mailroom_buckets))) {
        return false;
    }

    cepCell* data_root = cep_poc_data_root();
    cepCell* sys_root = cep_poc_sys_root();
    cepCell* tmp_root = cep_poc_tmp_root();
    if (!data_root || !sys_root || !tmp_root) {
        return false;
    }

    cepCell* poc_root = cep_poc_ensure_dictionary(data_root, dt_poc(), CEP_STORAGE_RED_BLACK_T);
    if (!poc_root) {
        return false;
    }

    cepCell* io_root = cep_poc_ensure_dictionary(poc_root, dt_io(), CEP_STORAGE_RED_BLACK_T);
    cepCell* hz_root = cep_poc_ensure_dictionary(poc_root, dt_hz(), CEP_STORAGE_RED_BLACK_T);
    if (!io_root || !hz_root) {
        return false;
    }

    cepCell* io_echo = cep_poc_ensure_dictionary(io_root, dt_echo(), CEP_STORAGE_RED_BLACK_T);
    cepCell* io_calc = cep_poc_ensure_dictionary(io_root, dt_calc(), CEP_STORAGE_RED_BLACK_T);
    cepCell* io_kv = cep_poc_ensure_dictionary(io_root, dt_kv(), CEP_STORAGE_RED_BLACK_T);
    cepCell* io_index = cep_poc_ensure_dictionary(io_root, dt_index(), CEP_STORAGE_RED_BLACK_T);
    cepCell* io_inbox = cep_poc_ensure_dictionary(io_root, dt_inbox(), CEP_STORAGE_RED_BLACK_T);
    if (!io_echo || !io_calc || !io_kv || !io_index || !io_inbox) {
        return false;
    }

    if (!cep_poc_ensure_dictionary(io_kv, dt_ans(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    if (!cep_poc_ensure_dictionary(io_inbox, dt_poc_echo_intent(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(io_inbox, dt_poc_calc_intent(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(io_inbox, dt_poc_kv_set_intent(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(io_inbox, dt_poc_kv_get_intent(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(io_inbox, dt_poc_kv_del_intent(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    cepCell* hz_scenario = cep_poc_ensure_dictionary(hz_root, dt_scenario(), CEP_STORAGE_RED_BLACK_T);
    cepCell* hz_run = cep_poc_ensure_dictionary(hz_root, dt_run(), CEP_STORAGE_RED_BLACK_T);
    cepCell* hz_index = cep_poc_ensure_dictionary(hz_root, dt_index(), CEP_STORAGE_RED_BLACK_T);
    cepCell* hz_inbox = cep_poc_ensure_dictionary(hz_root, dt_inbox(), CEP_STORAGE_RED_BLACK_T);
    if (!hz_scenario || !hz_run || !hz_index || !hz_inbox) {
        return false;
    }

    if (!cep_poc_ensure_dictionary(hz_inbox, dt_poc_scenario_intent(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(hz_inbox, dt_poc_run_intent(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(hz_inbox, dt_poc_assert_intent(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(hz_inbox, dt_poc_bandit_intent(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    cepCell* tmp_poc = cep_poc_ensure_dictionary(tmp_root, dt_poc(), CEP_STORAGE_RED_BLACK_T);
    if (!tmp_poc) {
        return false;
    }

    cepCell* tmp_io = cep_poc_ensure_dictionary(tmp_poc, dt_io(), CEP_STORAGE_RED_BLACK_T);
    cepCell* tmp_hz = cep_poc_ensure_dictionary(tmp_poc, dt_hz(), CEP_STORAGE_RED_BLACK_T);
    if (!tmp_io || !tmp_hz) {
        return false;
    }

    if (!cep_poc_ensure_dictionary(tmp_io, dt_adj(), CEP_STORAGE_RED_BLACK_T) ||
        !cep_poc_ensure_dictionary(tmp_hz, dt_adj(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    cepCell* sys_poc = cep_poc_ensure_dictionary(sys_root, dt_poc(), CEP_STORAGE_RED_BLACK_T);
    if (!sys_poc) {
        return false;
    }

    if (!cep_poc_set_string_value(sys_poc, dt_enabled(), "1")) {
        return false;
    }

    cepCell* retention_root = cep_poc_ensure_dictionary(sys_poc, dt_retention(), CEP_STORAGE_RED_BLACK_T);
    if (!retention_root) {
        return false;
    }

    if (!cep_poc_configure_retention_slot(retention_root, dt_io(), "permanent", "0", "0")) {
        return false;
    }
    if (!cep_poc_configure_retention_slot(retention_root, dt_hz(), "permanent", "0", "0")) {
        return false;
    }

    cepCell* retention_tmp = cep_poc_ensure_dictionary(retention_root, dt_tmp(), CEP_STORAGE_RED_BLACK_T);
    if (!retention_tmp) {
        return false;
    }

    if (!cep_poc_configure_retention_slot(retention_tmp, dt_io(), "ttl", "1", "0")) {
        return false;
    }
    if (!cep_poc_configure_retention_slot(retention_tmp, dt_hz(), "ttl", "1", "0")) {
        return false;
    }

    cep_namepool_bootstrap();
    return true;
}

static cepEnzymeRegistry* cep_poc_registered_registry = NULL;
static bool cep_poc_bindings_applied = false;

/* Wire the PoC ingest/index/adjacency enzymes to the registry so beats honour
 * the intended sequencing alongside the existing L0/L1/L2 packs. */
bool cep_poc_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (!cep_poc_bootstrap()) {
        return false;
    }

    for (size_t i = 0; i < cep_lengthof(cep_poc_router_before); ++i) {
        if (!cep_mailroom_add_router_before(cep_poc_router_before[i])) {
            return false;
        }
    }

    if (!cep_mailroom_register(registry)) {
        return false;
    }

    if (cep_poc_registered_registry == registry) {
        return true;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast past[2];
    } cepPathStatic2;

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *CEP_DTAW("CEP", "sig_cell"), .timestamp = 0u},
            {.dt = *CEP_DTAW("CEP", "op_add"), .timestamp = 0u},
        },
    };

    cepDT io_index_after[] = {
        *dt_poc_io_ing_echo(),
        *dt_poc_io_ing_calc(),
        *dt_poc_io_ing_kv(),
    };

    cepDT io_adj_after[] = {
        *dt_poc_io_index(),
    };

    cepDT hz_ing_after[] = {
        *dt_poc_io_adj(),
    };

    cepDT hz_index_after[] = {
        *dt_poc_hz_ing_scenario(),
        *dt_poc_hz_ing_run(),
        *dt_poc_hz_ing_assert(),
        *dt_poc_hz_ing_bandit(),
    };

    cepDT hz_adj_after[] = {
        *dt_poc_hz_index(),
    };

    cepEnzymeDescriptor descriptors[] = {
        {
            .name = *dt_poc_io_ing_echo(),
            .label = "poc.io.ing.echo",
            .callback = cep_poc_enzyme_io_echo,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_poc_io_ing_calc(),
            .label = "poc.io.ing.calc",
            .callback = cep_poc_enzyme_io_calc,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_poc_io_ing_kv(),
            .label = "poc.io.ing.kv",
            .callback = cep_poc_enzyme_io_kv,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_poc_io_index(),
            .label = "poc.io.index",
            .callback = cep_poc_enzyme_io_index,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = io_index_after,
            .after_count = cep_lengthof(io_index_after),
        },
        {
            .name = *dt_poc_io_adj(),
            .label = "poc.io.adj",
            .callback = cep_poc_enzyme_io_adj,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = io_adj_after,
            .after_count = cep_lengthof(io_adj_after),
        },
        {
            .name = *dt_poc_hz_ing_scenario(),
            .label = "poc.hz.ing.scenario",
            .callback = cep_poc_enzyme_hz_scenario,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = hz_ing_after,
            .after_count = cep_lengthof(hz_ing_after),
        },
        {
            .name = *dt_poc_hz_ing_run(),
            .label = "poc.hz.ing.run",
            .callback = cep_poc_enzyme_hz_run,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = hz_ing_after,
            .after_count = cep_lengthof(hz_ing_after),
        },
        {
            .name = *dt_poc_hz_ing_assert(),
            .label = "poc.hz.ing.assert",
            .callback = cep_poc_enzyme_hz_assert,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = hz_ing_after,
            .after_count = cep_lengthof(hz_ing_after),
        },
        {
            .name = *dt_poc_hz_ing_bandit(),
            .label = "poc.hz.ing.bandit",
            .callback = cep_poc_enzyme_hz_bandit,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = hz_ing_after,
            .after_count = cep_lengthof(hz_ing_after),
        },
        {
            .name = *dt_poc_hz_index(),
            .label = "poc.hz.index",
            .callback = cep_poc_enzyme_hz_index,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = hz_index_after,
            .after_count = cep_lengthof(hz_index_after),
        },
        {
            .name = *dt_poc_hz_adj(),
            .label = "poc.hz.adj",
            .callback = cep_poc_enzyme_hz_adj,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = hz_adj_after,
            .after_count = cep_lengthof(hz_adj_after),
        },
    };

    for (size_t i = 0; i < cep_lengthof(descriptors); ++i) {
        if (cep_enzyme_register(registry, (const cepPath*)&signal_path, &descriptors[i]) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    cep_poc_registered_registry = registry;

    if (!cep_poc_bindings_applied) {
        cepCell* io_root = cep_poc_io_root();
        cepCell* hz_root = cep_poc_hz_root();
        if (!io_root || !hz_root) {
            return false;
        }

        (void)cep_cell_bind_enzyme(io_root, dt_poc_io_ing_echo(), true);
        (void)cep_cell_bind_enzyme(io_root, dt_poc_io_ing_calc(), true);
        (void)cep_cell_bind_enzyme(io_root, dt_poc_io_ing_kv(), true);
        (void)cep_cell_bind_enzyme(io_root, dt_poc_io_index(), true);
        (void)cep_cell_bind_enzyme(io_root, dt_poc_io_adj(), true);

        (void)cep_cell_bind_enzyme(hz_root, dt_poc_hz_ing_scenario(), true);
        (void)cep_cell_bind_enzyme(hz_root, dt_poc_hz_ing_run(), true);
        (void)cep_cell_bind_enzyme(hz_root, dt_poc_hz_ing_assert(), true);
        (void)cep_cell_bind_enzyme(hz_root, dt_poc_hz_ing_bandit(), true);
        (void)cep_cell_bind_enzyme(hz_root, dt_poc_hz_index(), true);
        (void)cep_cell_bind_enzyme(hz_root, dt_poc_hz_adj(), true);

        cep_poc_bindings_applied = true;
    }

    return true;
}

static bool cep_poc_record_original_field(cepCell* original_root, const cepDT* field, const char* text) {
    if (!original_root || !field || !text) {
        return false;
    }
    return cep_poc_set_string_value(original_root, field, text);
}

static bool cep_poc_store_value(cepCell* parent, const cepDT* field, const char* text) {
    return cep_poc_set_string_value(parent, field, text);
}

static bool cep_poc_prepare_inbox_request(cepCell* bucket,
                                          const char* txn_word,
                                          cepCell** out_request,
                                          cepCell** out_original) {
    if (!bucket || !txn_word || !out_request || !out_original) {
        return false;
    }

    if (!cep_cell_has_store(bucket)) {
        return false;
    }

    cepDT txn_dt = {
        .domain = cep_poc_domain(),
        .tag = cep_text_to_word(txn_word),
    };

    if (!txn_dt.tag) {
        cepID ref = cep_namepool_intern(txn_word, strlen(txn_word));
        if (!ref) {
            return false;
        }
        txn_dt.tag = ref;
    }

    if (cep_cell_find_by_name(bucket, &txn_dt)) {
        return false;
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    cepCell* original = cep_poc_ensure_dictionary(request, dt_original(), CEP_STORAGE_RED_BLACK_T);
    if (!original) {
        cep_cell_remove_hard(request, NULL);
        return false;
    }

    *out_request = request;
    *out_original = original;
    return true;
}

/* Build a mailroom-ready `poc_echo` request that mirrors payload text under
 * `original subtree` so provenance tooling can replay the submission verbatim. */
bool cep_poc_echo_intent_init(cepPocIntent* intent,
                              const char* txn_word,
                              const char* id_text,
                              const char* text) {
    if (!intent || !txn_word || !id_text || !text) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_io_inbox(), dt_poc_echo_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), id_text) ||
        !cep_poc_store_value(intent->request, dt_text_field(), text) ||
        !cep_poc_record_original_field(intent->original, dt_id(), id_text) ||
        !cep_poc_record_original_field(intent->original, dt_text_field(), text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    return true;
}

/* Prepare a deterministic `poc_calc` intent capturing the expression both in
 * canonical form and under `original/expr` so ingest can evaluate it safely. */
bool cep_poc_calc_intent_init(cepPocIntent* intent,
                              const char* txn_word,
                              const char* id_text,
                              const char* expr_text) {
    if (!intent || !txn_word || !id_text || !expr_text) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_io_inbox(), dt_poc_calc_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), id_text) ||
        !cep_poc_store_value(intent->request, dt_expr(), expr_text) ||
        !cep_poc_record_original_field(intent->original, dt_id(), id_text) ||
        !cep_poc_record_original_field(intent->original, dt_expr(), expr_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    return true;
}

/* Assemble a `poc_kv_set` request that mirrors both key and value so replay
 * captures exactly what mutation was requested. */
bool cep_poc_kv_set_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* id_text,
                                const char* key_text,
                                const char* value_text) {
    if (!intent || !txn_word || !id_text || !key_text || !value_text) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_io_inbox(), dt_poc_kv_set_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), id_text) ||
        !cep_poc_store_value(intent->request, dt_key(), key_text) ||
        !cep_poc_store_value(intent->request, dt_value(), value_text) ||
        !cep_poc_record_original_field(intent->original, dt_id(), id_text) ||
        !cep_poc_record_original_field(intent->original, dt_key(), key_text) ||
        !cep_poc_record_original_field(intent->original, dt_value(), value_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    return true;
}

/* Stage a `poc_kv_get` request that asks for the latest value associated with
 * a key while preserving the submitted spelling for provenance. */
bool cep_poc_kv_get_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* id_text,
                                const char* key_text) {
    if (!intent || !txn_word || !id_text || !key_text) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_io_inbox(), dt_poc_kv_get_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), id_text) ||
        !cep_poc_store_value(intent->request, dt_key(), key_text) ||
        !cep_poc_record_original_field(intent->original, dt_id(), id_text) ||
        !cep_poc_record_original_field(intent->original, dt_key(), key_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    return true;
}

/* Stage a `poc_kv_del` request that records which key should be tombstoned in
 * the ledger and captures the spelling for replay diagnostics. */
bool cep_poc_kv_del_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* id_text,
                                const char* key_text) {
    if (!intent || !txn_word || !id_text || !key_text) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_io_inbox(), dt_poc_kv_del_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), id_text) ||
        !cep_poc_store_value(intent->request, dt_key(), key_text) ||
        !cep_poc_record_original_field(intent->original, dt_id(), id_text) ||
        !cep_poc_record_original_field(intent->original, dt_key(), key_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    return true;
}

/* Initialise a declarative `poc_scenario` request so callers can append steps
 * or inline assertions before it flows through the mailroom. */
bool cep_poc_scenario_intent_init(cepPocScenarioIntent* intent,
                                  const char* txn_word,
                                  const char* scenario_id) {
    if (!intent || !txn_word || !scenario_id) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;
    intent->steps = NULL;
    intent->asserts = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_hz_inbox(), dt_poc_scenario_intent());
    if (!bucket) {
        return false;
    }

    cepCell* request = NULL;
    cepCell* original = NULL;
    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &request, &original)) {
        return false;
    }

    if (!cep_poc_store_value(request, dt_id(), scenario_id) ||
        !cep_poc_record_original_field(original, dt_id(), scenario_id)) {
        cepPocIntent cleanup = {.request = request, .original = original};
        cep_poc_intent_abort(&cleanup);
        return false;
    }

    cepCell* steps = cep_poc_ensure_dictionary(request, dt_steps(), CEP_STORAGE_LINKED_LIST);
    cepCell* asserts = cep_poc_ensure_dictionary(request, dt_asserts(), CEP_STORAGE_RED_BLACK_T);
    cepCell* original_steps = cep_poc_ensure_dictionary(original, dt_steps(), CEP_STORAGE_LINKED_LIST);
    cepCell* original_asserts = cep_poc_ensure_dictionary(original, dt_asserts(), CEP_STORAGE_RED_BLACK_T);
    if (!steps || !asserts || !original_steps || !original_asserts) {
        cepPocIntent cleanup = {.request = request, .original = original};
        cep_poc_intent_abort(&cleanup);
        return false;
    }

    intent->request = request;
    intent->original = original;
    intent->steps = steps;
    intent->asserts = asserts;
    intent->original_steps = original_steps;
    intent->original_asserts = original_asserts;
    return true;
}

/* Add a scenario step with explicit kind/id fields and surface the dictionary
 * so callers can continue decorating the entry before submission. */
/* Add a scenario step with explicit kind/id fields and surface the dictionary
 * so callers can continue decorating the entry before submission. */
cepCell* cep_poc_scenario_intent_add_step(cepPocScenarioIntent* intent,
                                          const char* step_kind,
                                          const char* step_id) {
    if (!intent || !intent->steps || !intent->original_steps || !step_kind || !step_id) {
        return NULL;
    }

    cepDT dict_type = *dt_dictionary();
    cepDT auto_name = {
        .domain = cep_poc_domain(),
        .tag = CEP_AUTOID,
    };

    cepCell* step = cep_dict_add_dictionary(intent->steps, &auto_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!step) {
        return NULL;
    }

    const cepDT* step_name_dt = cep_cell_get_name(step);
    cepDT name_copy = step_name_dt ? *step_name_dt : auto_name;
    cepCell* original_step = cep_dict_add_dictionary(intent->original_steps, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!original_step) {
        cep_cell_remove_hard(step, NULL);
        return NULL;
    }

    if (!cep_poc_store_value(step, dt_id(), step_id) ||
        !cep_poc_store_value(step, dt_kind(), step_kind) ||
        !cep_poc_store_value(original_step, dt_id(), step_id) ||
        !cep_poc_store_value(original_step, dt_kind(), step_kind)) {
        cep_cell_remove_hard(step, NULL);
        cep_cell_remove_hard(original_step, NULL);
        return NULL;
    }

    return step;
}

/* Attach an inline assertion to the scenario for deterministic replay checks
 * when the scenario executes inside the harness. */
bool cep_poc_scenario_intent_add_assert(cepPocScenarioIntent* intent,
                                        const char* assert_id,
                                        const char* path,
                                        const char* expect_text) {
    if (!intent || !intent->asserts || !intent->original_asserts || !assert_id || !path || !expect_text) {
        return false;
    }

    cepDT assert_dt = {
        .domain = cep_poc_domain(),
        .tag = cep_text_to_word(assert_id),
    };
    if (!assert_dt.tag) {
        cepID ref = cep_namepool_intern(assert_id, strlen(assert_id));
        if (!ref) {
            return false;
        }
        assert_dt.tag = ref;
    }

    if (cep_cell_find_by_name(intent->asserts, &assert_dt)) {
        return false;
    }

    cepDT dict_type = *dt_dictionary();
    cepDT name_copy = assert_dt;
    cepCell* node = cep_dict_add_dictionary(intent->asserts, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!node) {
        return false;
    }

    cepCell* original_node = cep_dict_add_dictionary(intent->original_asserts, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!original_node) {
        cep_cell_remove_hard(node, NULL);
        return false;
    }

    if (!cep_poc_store_value(node, dt_path(), path) ||
        !cep_poc_store_value(node, dt_expect(), expect_text) ||
        !cep_poc_store_value(original_node, dt_path(), path) ||
        !cep_poc_store_value(original_node, dt_expect(), expect_text)) {
        cep_cell_remove_hard(node, NULL);
        cep_cell_remove_hard(original_node, NULL);
        return false;
    }

    return true;
}

/* Wire a `poc_run` intent that points at a scenario link so the harness ingest
 * enzyme can materialise a run node and spawn derived work. */
bool cep_poc_run_intent_init(cepPocIntent* intent,
                             const char* txn_word,
                             const char* run_id,
                             cepCell* scenario_link) {
    if (!intent || !txn_word || !run_id || !scenario_link) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_hz_inbox(), dt_poc_run_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), run_id) ||
        !cep_poc_store_value(intent->original, dt_id(), run_id)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    cepDT link_name = *dt_scenario();
    if (!cep_dict_add_link(intent->request, &link_name, scenario_link)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    return true;
}

/* Create a `poc_assert` intent that captures the lookup path and expected text
 * for harness-level validation runs. */
bool cep_poc_assert_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* assert_id,
                                const char* path_text,
                                const char* expect_text) {
    if (!intent || !txn_word || !assert_id || !path_text || !expect_text) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_hz_inbox(), dt_poc_assert_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), assert_id) ||
        !cep_poc_store_value(intent->request, dt_path(), path_text) ||
        !cep_poc_store_value(intent->request, dt_expect(), expect_text) ||
        !cep_poc_store_value(intent->original, dt_id(), assert_id) ||
        !cep_poc_store_value(intent->original, dt_path(), path_text) ||
        !cep_poc_store_value(intent->original, dt_expect(), expect_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    return true;
}

/* Assemble a `poc_bandit` intent capturing epsilon-greedy parameters and arm
 * catalogue so the harness ingest enzyme can coordinate with L2 flows. */
bool cep_poc_bandit_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* run_id,
                                const char* policy_text,
                                const char* const arms[], size_t arm_count,
                                const char* epsilon_text,
                                const char* rng_seed_text,
                                size_t pulls) {
    if (!intent || !txn_word || !run_id || !policy_text || !arms || !arm_count) {
        return false;
    }

    intent->request = NULL;
    intent->original = NULL;

    cepCell* bucket = cep_poc_inbox_bucket(cep_poc_hz_inbox(), dt_poc_bandit_intent());
    if (!bucket) {
        return false;
    }

    if (!cep_poc_prepare_inbox_request(bucket, txn_word, &intent->request, &intent->original)) {
        return false;
    }

    if (!cep_poc_store_value(intent->request, dt_id(), run_id) ||
        !cep_poc_store_value(intent->request, dt_policy(), policy_text) ||
        !cep_poc_store_value(intent->original, dt_id(), run_id) ||
        !cep_poc_store_value(intent->original, dt_policy(), policy_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    cepCell* arms_root = cep_poc_ensure_dictionary(intent->request, dt_arms(), CEP_STORAGE_LINKED_LIST);
    cepCell* arms_original = cep_poc_ensure_dictionary(intent->original, dt_arms(), CEP_STORAGE_LINKED_LIST);
    if (!arms_root || !arms_original) {
        cep_poc_intent_abort(intent);
        return false;
    }

    for (size_t i = 0; i < arm_count; ++i) {
        const char* arm = arms[i];
        if (!arm) {
            continue;
        }

        size_t len = strlen(arm) + 1u;
        cepDT auto_name = {
            .domain = cep_poc_domain(),
            .tag = CEP_AUTOID,
        };
        cepDT text_type = *dt_text();

        cepCell* node = cep_dict_add_value(arms_root, &auto_name, &text_type, (void*)arm, len, len);
        if (!node) {
            cep_poc_intent_abort(intent);
            return false;
        }
        cep_cell_content_hash(node);

        cepCell* mirror = cep_dict_add_value(arms_original, &auto_name, &text_type, (void*)arm, len, len);
        if (!mirror) {
            cep_poc_intent_abort(intent);
            return false;
        }
        cep_cell_content_hash(mirror);
    }

    if (epsilon_text && !cep_poc_store_value(intent->request, dt_epsilon(), epsilon_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }
    if (epsilon_text && !cep_poc_store_value(intent->original, dt_epsilon(), epsilon_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    if (rng_seed_text && !cep_poc_store_value(intent->request, dt_rng_seed(), rng_seed_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }
    if (rng_seed_text && !cep_poc_store_value(intent->original, dt_rng_seed(), rng_seed_text)) {
        cep_poc_intent_abort(intent);
        return false;
    }

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", pulls);
    (void)cep_poc_store_value(intent->request, dt_spawns(), buffer);
    (void)cep_poc_store_value(intent->original, dt_spawns(), buffer);

    return true;
}

static bool cep_poc_clear_children(cepCell* cell) {
    if (!cell || !cep_cell_has_store(cell)) {
        return false;
    }
    cep_cell_delete_children_hard(cell);
    return true;
}

static bool cep_poc_clone_child_into(cepCell* parent, const cepCell* child) {
    if (!parent || !child) {
        return false;
    }

    cepCell* clone = cep_cell_clone_deep(child);
    if (!clone) {
        return false;
    }

    cepCell* inserted = cep_cell_add(parent, 0, clone);
    if (!inserted) {
        cep_cell_finalize_hard(clone);
        cep_free(clone);
        return false;
    }

    cep_free(clone);
    return true;
}

static bool cep_poc_store_numeric_value(cepCell* parent, const char* key, size_t value) {
    if (!parent || !key) {
        return false;
    }

    cepDT key_dt = {0};
    if (!cep_poc_text_to_dt(key, &key_dt)) {
        return false;
    }

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", value);
    return cep_poc_store_value(parent, &key_dt, buffer);
}

static bool cep_poc_index_increment(cepCell* parent, const char* key, size_t delta) {
    if (!parent || !key) {
        return false;
    }

    cepDT key_dt = {0};
    if (!cep_poc_text_to_dt(key, &key_dt)) {
        return false;
    }

    size_t current = 0u;
    cepCell* existing = cep_cell_find_by_name(parent, &key_dt);
    if (existing && cep_cell_has_data(existing)) {
        const cepData* data = existing->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size > 1u) {
            current = (size_t)strtoull((const char*)data->value, NULL, 10);
        }
    }

    current += delta;

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", current);
    return cep_poc_store_value(parent, &key_dt, buffer);
}

static bool cep_poc_copy_payload(cepCell* request, cepCell* dst) {
    if (!request || !dst) {
        return false;
    }

    if (!cep_poc_clear_children(dst)) {
        return false;
    }

    for (cepCell* child = cep_cell_first(request); child; child = cep_cell_next(request, child)) {
        if (cep_cell_name_is(child, dt_outcome())) {
            continue;
        }
        if (!cep_poc_clone_child_into(dst, child)) {
            return false;
        }
    }

    return true;
}

static bool cep_poc_get_cstring(cepCell* parent, const cepDT* field, const char** out_text) {
    if (!parent || !field || !out_text) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node || !cep_cell_has_data(node)) {
        return false;
    }

    const cepData* data = node->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return false;
    }

    const char* text = (const char*)data->value;
    if (text[data->size - 1u] != '\0') {
        return false;
    }

    *out_text = text;
    return true;
}

static cepCell* cep_poc_resolve_request(const cepPath* target_path) {
    if (!target_path) {
        return NULL;
    }
    return cep_cell_find_by_path(cep_root(), target_path);
}

typedef struct {
    const char* text;
    size_t      length;
    size_t      pos;
} cepPocCalcParser;

static void cep_poc_calc_skip_ws(cepPocCalcParser* parser) {
    while (parser->pos < parser->length) {
        char ch = parser->text[parser->pos];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
            parser->pos++;
            continue;
        }
        break;
    }
}

static bool cep_poc_calc_parse_number(cepPocCalcParser* parser, double* out_value) {
    cep_poc_calc_skip_ws(parser);
    size_t start = parser->pos;
    bool seen_digit = false;

    while (parser->pos < parser->length) {
        char ch = parser->text[parser->pos];
        if ((ch >= '0' && ch <= '9') || ch == '.') {
            if (ch >= '0' && ch <= '9') {
                seen_digit = true;
            }
            parser->pos++;
            continue;
        }
        break;
    }

    if (!seen_digit) {
        return false;
    }

    char buffer[64];
    size_t span = parser->pos - start;
    if (span >= sizeof buffer) {
        return false;
    }
    memcpy(buffer, &parser->text[start], span);
    buffer[span] = '\0';
    *out_value = strtod(buffer, NULL);
    return true;
}

static bool cep_poc_calc_parse_factor(cepPocCalcParser* parser, double* out_value);

static bool cep_poc_calc_parse_unary(cepPocCalcParser* parser, double* out_value) {
    cep_poc_calc_skip_ws(parser);
    if (parser->pos >= parser->length) {
        return false;
    }

    char ch = parser->text[parser->pos];
    if (ch == '+') {
        parser->pos++;
        return cep_poc_calc_parse_unary(parser, out_value);
    }
    if (ch == '-') {
        parser->pos++;
        if (!cep_poc_calc_parse_unary(parser, out_value)) {
            return false;
        }
        *out_value = -*out_value;
        return true;
    }

    return cep_poc_calc_parse_factor(parser, out_value);
}

static bool cep_poc_calc_parse_factor(cepPocCalcParser* parser, double* out_value) {
    cep_poc_calc_skip_ws(parser);
    if (parser->pos >= parser->length) {
        return false;
    }

    char ch = parser->text[parser->pos];
    if (ch == '(') {
        parser->pos++;
        if (!cep_poc_calc_parse_unary(parser, out_value)) {
            return false;
        }
        cep_poc_calc_skip_ws(parser);
        if (parser->pos >= parser->length || parser->text[parser->pos] != ')') {
            return false;
        }
        parser->pos++;
        return true;
    }

    return cep_poc_calc_parse_number(parser, out_value);
}

static bool cep_poc_calc_parse_term(cepPocCalcParser* parser, double* out_value) {
    if (!cep_poc_calc_parse_unary(parser, out_value)) {
        return false;
    }

    while (true) {
        cep_poc_calc_skip_ws(parser);
        if (parser->pos >= parser->length) {
            return true;
        }

        char op = parser->text[parser->pos];
        if (op != '*' && op != '/') {
            return true;
        }
        parser->pos++;

        double rhs = 0.0;
        if (!cep_poc_calc_parse_unary(parser, &rhs)) {
            return false;
        }

        if (op == '*') {
            *out_value *= rhs;
        } else {
            if (rhs == 0.0) {
                return false;
            }
            *out_value /= rhs;
        }
    }
}

static bool cep_poc_calc_parse_expr(cepPocCalcParser* parser, double* out_value) {
    if (!cep_poc_calc_parse_term(parser, out_value)) {
        return false;
    }

    while (true) {
        cep_poc_calc_skip_ws(parser);
        if (parser->pos >= parser->length) {
            return true;
        }

        char op = parser->text[parser->pos];
        if (op != '+' && op != '-') {
            return true;
        }
        parser->pos++;

        double rhs = 0.0;
        if (!cep_poc_calc_parse_term(parser, &rhs)) {
            return false;
        }

        if (op == '+') {
            *out_value += rhs;
        } else {
            *out_value -= rhs;
        }
    }
}

static bool cep_poc_calc_evaluate(const char* expr, double* out_value) {
    if (!expr || !out_value) {
        return false;
    }

    cepPocCalcParser parser = {
        .text = expr,
        .length = strlen(expr),
        .pos = 0u,
    };

    if (!cep_poc_calc_parse_expr(&parser, out_value)) {
        return false;
    }

    cep_poc_calc_skip_ws(&parser);
    return parser.pos == parser.length;
}

static int cep_poc_enzyme_io_echo(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_poc_resolve_request(target);
    if (!request || !cep_cell_is_normal(request)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, dt_poc_echo_intent())) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* id_text = NULL;
    const char* echo_text = NULL;
    if (!cep_poc_get_cstring(request, dt_id(), &id_text) ||
        !cep_poc_get_cstring(request, dt_text_field(), &echo_text)) {
        cep_poc_mark_outcome(request, "invalid-payload");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_poc_text_to_dt(id_text, &id_dt)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* io_root = cep_poc_io_root();
    cepCell* echo_root = io_root ? cep_cell_find_by_name(io_root, dt_echo()) : NULL;
    if (!echo_root) {
        return CEP_ENZYME_FATAL;
    }

    cepPocStoreLock ledger_lock = {0};
    if (!cep_poc_store_lock(echo_root, &ledger_lock)) {
        cep_poc_mark_outcome(request, "ledger-lock");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* entry = cep_poc_ensure_dictionary(echo_root, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_poc_store_unlock(&ledger_lock);
    if (!entry) {
        cep_poc_mark_outcome(request, "create-failed");
        return CEP_ENZYME_SUCCESS;
    }

    if (!cep_poc_store_value(entry, dt_text_field(), echo_text)) {
        cep_poc_mark_outcome(request, "copy-failed");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT link_name = *dt_parent();
    cepCell* parent_link = cep_dict_add_link(entry, &link_name, request);
    if (parent_link) {
        cepCell* parents[] = { parent_link };
        (void)cep_cell_add_parents(entry, parents, cep_lengthof(parents));
    }

    cep_poc_mark_outcome(request, "ok");
    return CEP_ENZYME_SUCCESS;
}

static int cep_poc_enzyme_io_calc(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_poc_resolve_request(target);
    if (!request || !cep_cell_is_normal(request)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, dt_poc_calc_intent())) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* id_text = NULL;
    const char* expr_text = NULL;
    if (!cep_poc_get_cstring(request, dt_id(), &id_text) ||
        !cep_poc_get_cstring(request, dt_expr(), &expr_text)) {
        cep_poc_mark_outcome(request, "invalid-payload");
        return CEP_ENZYME_SUCCESS;
    }

    double value = 0.0;
    if (!cep_poc_calc_evaluate(expr_text, &value)) {
        cep_poc_mark_outcome(request, "invalid-expr");
        return CEP_ENZYME_SUCCESS;
    }

    char result_buffer[64];
    snprintf(result_buffer, sizeof result_buffer, "%.12g", value);

    cepDT id_dt = {0};
    if (!cep_poc_text_to_dt(id_text, &id_dt)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* io_root = cep_poc_io_root();
    cepCell* calc_root = io_root ? cep_cell_find_by_name(io_root, dt_calc()) : NULL;
    if (!calc_root) {
        return CEP_ENZYME_FATAL;
    }

    cepPocStoreLock ledger_lock = {0};
    if (!cep_poc_store_lock(calc_root, &ledger_lock)) {
        cep_poc_mark_outcome(request, "ledger-lock");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* entry = cep_poc_ensure_dictionary(calc_root, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_poc_store_unlock(&ledger_lock);
    if (!entry) {
        cep_poc_mark_outcome(request, "create-failed");
        return CEP_ENZYME_SUCCESS;
    }

    if (!cep_poc_store_value(entry, dt_expr(), expr_text) ||
        !cep_poc_store_value(entry, dt_result(), result_buffer)) {
        cep_poc_mark_outcome(request, "copy-failed");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT link_name = *dt_parent();
    cepCell* parent_link = cep_dict_add_link(entry, &link_name, request);
    if (parent_link) {
        cepCell* parents[] = { parent_link };
        (void)cep_cell_add_parents(entry, parents, cep_lengthof(parents));
    }

    cep_poc_mark_outcome(request, "ok");
    return CEP_ENZYME_SUCCESS;
}

static int cep_poc_enzyme_io_kv(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_poc_resolve_request(target);
    if (!request || !cep_cell_is_normal(request)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket) {
        return CEP_ENZYME_SUCCESS;
    }

    bool is_set = cep_cell_name_is(bucket, dt_poc_kv_set_intent());
    bool is_get = cep_cell_name_is(bucket, dt_poc_kv_get_intent());
    bool is_del = cep_cell_name_is(bucket, dt_poc_kv_del_intent());
    if (!is_set && !is_get && !is_del) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* id_text = NULL;
    const char* key_text = NULL;
    const char* value_text = NULL;

    if (!cep_poc_get_cstring(request, dt_id(), &id_text) ||
        !cep_poc_get_cstring(request, dt_key(), &key_text)) {
        cep_poc_mark_outcome(request, "invalid-payload");
        return CEP_ENZYME_SUCCESS;
    }

    if (is_set) {
        if (!cep_poc_get_cstring(request, dt_value(), &value_text)) {
            cep_poc_mark_outcome(request, "invalid-value");
            return CEP_ENZYME_SUCCESS;
        }
    }

    cepDT key_dt = {0};
    if (!cep_poc_text_to_dt(key_text, &key_dt)) {
        cep_poc_mark_outcome(request, "invalid-key");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_poc_text_to_dt(id_text, &id_dt)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* io_root = cep_poc_io_root();
    cepCell* kv_root = io_root ? cep_cell_find_by_name(io_root, dt_kv()) : NULL;
    if (!kv_root) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* ans_root = cep_cell_find_by_name(kv_root, dt_ans());
    if (!ans_root) {
        return CEP_ENZYME_FATAL;
    }

    if (is_set || is_del) {
        cepPocStoreLock kv_lock = {0};
        if (!cep_poc_store_lock(kv_root, &kv_lock)) {
            cep_poc_mark_outcome(request, "ledger-lock");
            return CEP_ENZYME_SUCCESS;
        }

        cepCell* entry = cep_poc_ensure_dictionary(kv_root, &key_dt, CEP_STORAGE_RED_BLACK_T);
        cep_poc_store_unlock(&kv_lock);
        if (!entry) {
            cep_poc_mark_outcome(request, "create-failed");
            return CEP_ENZYME_SUCCESS;
        }

        if (is_set) {
            if (!cep_poc_store_value(entry, dt_key(), key_text) ||
                !cep_poc_store_value(entry, dt_value(), value_text)) {
                cep_poc_mark_outcome(request, "copy-failed");
                return CEP_ENZYME_SUCCESS;
            }
            (void)cep_poc_store_value(entry, dt_tomb(), "0");
        } else {
            (void)cep_poc_store_value(entry, dt_tomb(), "1");
        }

        cepDT link_name = *dt_parent();
        cepCell* parent_link = cep_dict_add_link(entry, &link_name, request);
        if (parent_link) {
            cepCell* parents[] = { parent_link };
            (void)cep_cell_add_parents(entry, parents, cep_lengthof(parents));
        }

        cep_poc_mark_outcome(request, "ok");
        return CEP_ENZYME_SUCCESS;
    }

    /* Handle get */
    cepCell* entry = cep_cell_find_by_name(kv_root, &key_dt);
    if (!entry) {
        cep_poc_mark_outcome(request, "not-found");
        return CEP_ENZYME_SUCCESS;
    }

    const char* stored_value = NULL;
    bool tombstoned = false;
    (void)cep_poc_get_cstring(entry, dt_value(), &stored_value);
    const char* tomb_flag = NULL;
    if (cep_poc_get_cstring(entry, dt_tomb(), &tomb_flag) && tomb_flag && tomb_flag[0] == '1') {
        tombstoned = true;
    }

    if (!stored_value || tombstoned) {
        cep_poc_mark_outcome(request, "not-found");
        return CEP_ENZYME_SUCCESS;
    }

    cepPocStoreLock ans_lock = {0};
    if (!cep_poc_store_lock(ans_root, &ans_lock)) {
        cep_poc_mark_outcome(request, "ledger-lock");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* answer = cep_poc_ensure_dictionary(ans_root, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_poc_store_unlock(&ans_lock);
    if (!answer) {
        cep_poc_mark_outcome(request, "create-failed");
        return CEP_ENZYME_SUCCESS;
    }

    if (!cep_poc_store_value(answer, dt_key(), key_text) ||
        !cep_poc_store_value(answer, dt_value(), stored_value)) {
        cep_poc_mark_outcome(request, "copy-failed");
        return CEP_ENZYME_SUCCESS;
    }

    cep_poc_mark_outcome(request, "ok");
    return CEP_ENZYME_SUCCESS;
}

static size_t cep_poc_count_children(const cepCell* parent) {
    if (!parent || !cep_cell_has_store(parent)) {
        return 0u;
    }
    size_t count = 0u;
    for (cepCell* child = cep_cell_first(parent); child; child = cep_cell_next(parent, child)) {
        if (cep_cell_is_normal(child)) {
            ++count;
        }
    }
    return count;
}

static void cep_poc_extract_prefix(const char* key_text, char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0u) {
        return;
    }

    buffer[0] = '\0';

    if (!key_text || key_text[0] == '\0') {
        return;
    }

    size_t i = 0u;
    for (; key_text[i] && i + 1u < buffer_size; ++i) {
        char ch = key_text[i];
        if (ch == ':' || ch == '/' || ch == '.') {
            break;
        }
        buffer[i] = ch;
    }

    if (i == 0u || key_text[i] == '\0') {
        /* No detectable prefix separator: mirror the whole key until buffer ends. */
        for (; key_text[i] && i + 1u < buffer_size; ++i) {
            buffer[i] = key_text[i];
        }
    }

    buffer[i] = '\0';
    if (buffer[0] == '\0') {
        buffer[0] = '_';
        buffer[1] = '\0';
    }
}

typedef struct {
    cepCell* request;
    cepDT    name;
    const cepDT* bucket;
    cepOpCount modified;
} cepPocRecentEntry;

static void cep_poc_recent_insert(cepPocRecentEntry* entries,
                                  size_t* count,
                                  size_t limit,
                                  cepCell* request,
                                  const cepDT* bucket,
                                  cepOpCount modified) {
    if (!entries || !count || limit == 0u || !request || !bucket) {
        return;
    }

    cepDT name = {0};
    const cepDT* request_name = cep_cell_get_name(request);
    if (request_name) {
        name = *request_name;
    }

    size_t insert_at = 0u;
    for (; insert_at < *count; ++insert_at) {
        if (modified > entries[insert_at].modified) {
            break;
        }
        if (modified == entries[insert_at].modified) {
            int tie = cep_dt_compare(&name, &entries[insert_at].name);
            if (tie < 0) {
                break;
            }
            if (tie == 0) {
                entries[insert_at].request = request;
                entries[insert_at].name = name;
                entries[insert_at].bucket = bucket;
                entries[insert_at].modified = modified;
                return;
            }
        }
    }

    if (insert_at >= limit) {
        return;
    }

    if (*count < limit) {
        if (*count > insert_at) {
            memmove(&entries[insert_at + 1u],
                    &entries[insert_at],
                    (*count - insert_at) * sizeof(cepPocRecentEntry));
        }
        ++(*count);
    } else {
        memmove(&entries[insert_at + 1u],
                &entries[insert_at],
                (limit - insert_at - 1u) * sizeof(cepPocRecentEntry));
    }

    entries[insert_at].request = request;
    entries[insert_at].name = name;
    entries[insert_at].bucket = bucket;
    entries[insert_at].modified = modified;
}

static size_t cep_poc_count_active_kv(const cepCell* kv_root) {
    if (!kv_root || !cep_cell_has_store(kv_root)) {
        return 0u;
    }
    size_t count = 0u;
    for (cepCell* entry = cep_cell_first(kv_root); entry; entry = cep_cell_next(kv_root, entry)) {
        if (!cep_cell_is_normal(entry)) {
            continue;
        }
        const char* tomb = NULL;
        if (cep_poc_get_cstring(entry, dt_tomb(), &tomb) && tomb && tomb[0] == '1') {
            continue;
        }
        ++count;
    }
    return count;
}
static int cep_poc_enzyme_io_index(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* io_root = cep_poc_io_root();
    if (!io_root) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* echo_root = cep_cell_find_by_name(io_root, dt_echo());
    cepCell* calc_root = cep_cell_find_by_name(io_root, dt_calc());
    cepCell* kv_root = cep_cell_find_by_name(io_root, dt_kv());
    cepCell* index_root = cep_cell_find_by_name(io_root, dt_index());
    if (!echo_root || !calc_root || !kv_root || !index_root) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* ans_root = cep_cell_find_by_name(kv_root, dt_ans());

    size_t echo_total = cep_poc_count_children(echo_root);
    size_t calc_total = cep_poc_count_children(calc_root);
    size_t kv_total = cep_poc_count_children(kv_root);
    size_t kv_active = cep_poc_count_active_kv(kv_root);
    size_t ans_total = ans_root ? cep_poc_count_children(ans_root) : 0u;

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", echo_total);
    if (!cep_poc_store_value(index_root, dt_echo(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", calc_total);
    if (!cep_poc_store_value(index_root, dt_calc(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", kv_active);
    if (!cep_poc_store_value(index_root, dt_kv(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    if (ans_root) {
        snprintf(buffer, sizeof buffer, "%zu", ans_total);
        if (!cep_poc_store_value(index_root, dt_ans(), buffer)) {
            return CEP_ENZYME_FATAL;
        }
    }

    cepCell* summary_root = cep_poc_ensure_dictionary(index_root, dt_summary(), CEP_STORAGE_RED_BLACK_T);
    if (!summary_root || !cep_poc_clear_children(summary_root)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* summary_io = cep_poc_ensure_dictionary(summary_root, dt_io(), CEP_STORAGE_RED_BLACK_T);
    cepCell* summary_kv = cep_poc_ensure_dictionary(summary_root, dt_kv(), CEP_STORAGE_RED_BLACK_T);
    if (!summary_io || !summary_kv || !cep_poc_clear_children(summary_io) || !cep_poc_clear_children(summary_kv)) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_poc_store_numeric_value(summary_io, "echo", echo_total) ||
        !cep_poc_store_numeric_value(summary_io, "calc", calc_total) ||
        !cep_poc_store_numeric_value(summary_kv, "total", kv_total) ||
        !cep_poc_store_numeric_value(summary_kv, "active", kv_active) ||
        !cep_poc_store_numeric_value(summary_kv, "ans", ans_total)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* calc_expr_root = cep_poc_ensure_dictionary(index_root, dt_calc_expr(), CEP_STORAGE_RED_BLACK_T);
    if (!calc_expr_root || !cep_poc_clear_children(calc_expr_root)) {
        return CEP_ENZYME_FATAL;
    }

    for (cepCell* entry = cep_cell_first(calc_root); entry; entry = cep_cell_next(calc_root, entry)) {
        if (!cep_cell_is_normal(entry)) {
            continue;
        }

        const char* expr_text = NULL;
        const char* result_text = NULL;
        (void)cep_poc_get_cstring(entry, dt_expr(), &expr_text);
        (void)cep_poc_get_cstring(entry, dt_result(), &result_text);
        if (!expr_text || expr_text[0] == '\0') {
            continue;
        }

        cepDT expr_dt = {0};
        if (!cep_poc_text_to_dt(expr_text, &expr_dt)) {
            continue;
        }

        cepCell* bucket = cep_cell_find_by_name(calc_expr_root, &expr_dt);
        if (!bucket) {
            bucket = cep_poc_ensure_dictionary(calc_expr_root, &expr_dt, CEP_STORAGE_RED_BLACK_T);
            if (!bucket) {
                return CEP_ENZYME_FATAL;
            }
        }

        if (!cep_poc_index_increment(bucket, "count", 1u)) {
            return CEP_ENZYME_FATAL;
        }

        if (result_text && result_text[0]) {
            const char* existing = NULL;
            if (!cep_poc_get_cstring(bucket, dt_result(), &existing) || !existing || strcmp(existing, result_text) != 0) {
                if (!cep_poc_store_value(bucket, dt_result(), result_text)) {
                    return CEP_ENZYME_FATAL;
                }
            }
        }

        const char* id_text = NULL;
        (void)cep_poc_get_cstring(entry, dt_id(), &id_text);
        if (id_text && id_text[0]) {
            cepCell* ids_root = cep_poc_ensure_dictionary(bucket, dt_ids(), CEP_STORAGE_LINKED_LIST);
            if (!ids_root) {
                return CEP_ENZYME_FATAL;
            }

            size_t len = strlen(id_text) + 1u;
            cepDT auto_name = {
                .domain = cep_poc_domain(),
                .tag = CEP_AUTOID,
            };
            cepDT text_type = *dt_text();
            cepCell* node = cep_dict_add_value(ids_root, &auto_name, &text_type, (void*)id_text, len, len);
            if (!node) {
                return CEP_ENZYME_FATAL;
            }
            cep_cell_content_hash(node);
        }
    }

    cepCell* kv_prefix_root = cep_poc_ensure_dictionary(index_root, dt_kv_prefix(), CEP_STORAGE_RED_BLACK_T);
    cepCell* kv_hist_root = cep_poc_ensure_dictionary(index_root, dt_kv_hist(), CEP_STORAGE_RED_BLACK_T);
    if (!kv_prefix_root || !kv_hist_root ||
        !cep_poc_clear_children(kv_prefix_root) || !cep_poc_clear_children(kv_hist_root)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* kv_index = cep_poc_ensure_dictionary(index_root, dt_keys(), CEP_STORAGE_LINKED_LIST);
    if (!kv_index || !cep_poc_clear_children(kv_index)) {
        return CEP_ENZYME_FATAL;
    }

    for (cepCell* entry = cep_cell_first(kv_root); entry; entry = cep_cell_next(kv_root, entry)) {
        if (!cep_cell_is_normal(entry) || cep_cell_name_is(entry, dt_ans())) {
            continue;
        }

        const char* key_text = NULL;
        (void)cep_poc_get_cstring(entry, dt_key(), &key_text);
        if (!key_text || key_text[0] == '\0') {
            continue;
        }

        const char* value_text = NULL;
        (void)cep_poc_get_cstring(entry, dt_value(), &value_text);

        const char* tomb_flag = NULL;
        bool tombstoned = cep_poc_get_cstring(entry, dt_tomb(), &tomb_flag) && tomb_flag && tomb_flag[0] == '1';

        if (!tombstoned) {
            size_t len = strlen(key_text) + 1u;
            cepDT auto_name = {
                .domain = cep_poc_domain(),
                .tag = CEP_AUTOID,
            };
            cepDT text_type = *dt_text();
            cepCell* node = cep_dict_add_value(kv_index, &auto_name, &text_type, (void*)key_text, len, len);
            if (!node) {
                return CEP_ENZYME_FATAL;
            }
            cep_cell_content_hash(node);
        }

        char prefix_buffer[96];
        cep_poc_extract_prefix(key_text, prefix_buffer, sizeof prefix_buffer);

        cepDT prefix_dt = {0};
        if (prefix_buffer[0] && cep_poc_text_to_dt(prefix_buffer, &prefix_dt)) {
            cepCell* prefix_bucket = cep_cell_find_by_name(kv_prefix_root, &prefix_dt);
            if (!prefix_bucket) {
                prefix_bucket = cep_poc_ensure_dictionary(kv_prefix_root, &prefix_dt, CEP_STORAGE_RED_BLACK_T);
                if (!prefix_bucket) {
                    return CEP_ENZYME_FATAL;
                }
            }

            if (!cep_poc_index_increment(prefix_bucket, "total", 1u)) {
                return CEP_ENZYME_FATAL;
            }

            if (tombstoned) {
                if (!cep_poc_index_increment(prefix_bucket, "tomb", 1u)) {
                    return CEP_ENZYME_FATAL;
                }
            } else {
                if (!cep_poc_index_increment(prefix_bucket, "count", 1u)) {
                    return CEP_ENZYME_FATAL;
                }
                cepCell* keys_list = cep_poc_ensure_dictionary(prefix_bucket, dt_keys(), CEP_STORAGE_LINKED_LIST);
                if (!keys_list) {
                    return CEP_ENZYME_FATAL;
                }
                size_t len = strlen(key_text) + 1u;
                cepDT auto_name = {
                    .domain = cep_poc_domain(),
                    .tag = CEP_AUTOID,
                };
                cepDT text_type = *dt_text();
                cepCell* node = cep_dict_add_value(keys_list, &auto_name, &text_type, (void*)key_text, len, len);
                if (!node) {
                    return CEP_ENZYME_FATAL;
                }
                cep_cell_content_hash(node);
            }
        }

        cepDT key_dt = {0};
        if (!cep_poc_text_to_dt(key_text, &key_dt)) {
            continue;
        }

        cepCell* hist_bucket = cep_poc_ensure_dictionary(kv_hist_root, &key_dt, CEP_STORAGE_RED_BLACK_T);
        if (!hist_bucket || !cep_poc_clear_children(hist_bucket)) {
            return CEP_ENZYME_FATAL;
        }

        if (value_text && value_text[0]) {
            if (!cep_poc_store_value(hist_bucket, dt_value(), value_text)) {
                return CEP_ENZYME_FATAL;
            }
        }

        if (!cep_poc_store_value(hist_bucket, dt_tomb(), tombstoned ? "1" : "0")) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* meta = cep_cell_find_by_name(entry, dt_meta());
        cepCell* parents = meta ? cep_cell_find_by_name(meta, dt_parents()) : NULL;
        size_t write_count = parents ? cep_poc_count_children(parents) : 0u;
        if (!cep_poc_store_numeric_value(hist_bucket, "count", write_count)) {
            return CEP_ENZYME_FATAL;
        }
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_poc_enzyme_io_adj(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* tmp_root = cep_poc_tmp_root();
    cepCell* tmp_poc = tmp_root ? cep_cell_find_by_name(tmp_root, dt_poc()) : NULL;
    cepCell* tmp_io = tmp_poc ? cep_cell_find_by_name(tmp_poc, dt_io()) : NULL;
    cepCell* adj_root = tmp_io ? cep_cell_find_by_name(tmp_io, dt_adj()) : NULL;
    if (!adj_root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_poc_clear_children(adj_root)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* io_root = cep_poc_io_root();
    if (!io_root) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* echo_root = cep_cell_find_by_name(io_root, dt_echo());
    cepCell* calc_root = cep_cell_find_by_name(io_root, dt_calc());
    cepCell* kv_root = cep_cell_find_by_name(io_root, dt_kv());
    if (!echo_root || !calc_root || !kv_root) {
        return CEP_ENZYME_FATAL;
    }

    size_t echo_total = cep_poc_count_children(echo_root);
    size_t calc_total = cep_poc_count_children(calc_root);
    size_t kv_active = cep_poc_count_active_kv(kv_root);

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", echo_total);
    if (!cep_poc_store_value(adj_root, dt_echo(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", calc_total);
    if (!cep_poc_store_value(adj_root, dt_calc(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", kv_active);
    if (!cep_poc_store_value(adj_root, dt_kv(), buffer)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* inbox_root = cep_poc_io_inbox();
    if (!inbox_root) {
        return CEP_ENZYME_FATAL;
    }

    typedef struct {
        const cepDT* (*dt_fn)(void);
        const char* summary_key;
    } cepPocIoBucketSpec;

    static const cepPocIoBucketSpec CEP_POC_IO_BUCKETS[] = {
        {dt_poc_echo_intent, "echo"},
        {dt_poc_calc_intent, "calc"},
        {dt_poc_kv_set_intent, "kset"},
        {dt_poc_kv_get_intent, "kget"},
        {dt_poc_kv_del_intent, "kdel"},
    };

    enum { CEP_POC_IO_BUCKET_COUNT = (int)(sizeof CEP_POC_IO_BUCKETS / sizeof CEP_POC_IO_BUCKETS[0]) };
    enum { CEP_POC_IO_RECENT_LIMIT = 8 };

    typedef struct {
        size_t submitted;
        size_t ok;
        size_t fail;
        size_t wait;
    } cepPocIoStats;

    cepPocIoStats stats[CEP_POC_IO_BUCKET_COUNT];
    memset(stats, 0, sizeof stats);

    cepPocRecentEntry recent[CEP_POC_IO_RECENT_LIMIT];
    size_t recent_count = 0u;

    for (int i = 0; i < CEP_POC_IO_BUCKET_COUNT; ++i) {
        const cepDT* bucket_dt = CEP_POC_IO_BUCKETS[i].dt_fn();
        cepCell* bucket = cep_poc_inbox_bucket(inbox_root, bucket_dt);
        if (!bucket) {
            continue;
        }

        for (cepCell* request = cep_cell_first(bucket); request; request = cep_cell_next(bucket, request)) {
            if (!cep_cell_is_normal(request)) {
                continue;
            }

            stats[i].submitted++;

            const char* outcome_text = NULL;
            (void)cep_poc_get_cstring(request, dt_outcome(), &outcome_text);

            bool pending = (!outcome_text || outcome_text[0] == '\0' || strcmp(outcome_text, "pending") == 0);
            if (pending) {
                stats[i].wait++;
                continue;
            }

            if (strcmp(outcome_text, "ok") == 0) {
                stats[i].ok++;
            } else {
                stats[i].fail++;
            }

            cepCell* outcome_cell = cep_cell_find_by_name(request, dt_outcome());
            cepOpCount modified = 0u;
            if (outcome_cell && cep_cell_has_data(outcome_cell) && outcome_cell->data) {
                modified = outcome_cell->data->modified;
            }

            cep_poc_recent_insert(recent, &recent_count, CEP_POC_IO_RECENT_LIMIT, request, bucket_dt, modified);
        }
    }

    cepCell* summary_root = cep_poc_ensure_dictionary(adj_root, dt_summary(), CEP_STORAGE_RED_BLACK_T);
    if (!summary_root || !cep_poc_clear_children(summary_root)) {
        return CEP_ENZYME_FATAL;
    }

    for (int i = 0; i < CEP_POC_IO_BUCKET_COUNT; ++i) {
        cepDT name_dt = {0};
        if (!cep_poc_text_to_dt(CEP_POC_IO_BUCKETS[i].summary_key, &name_dt)) {
            continue;
        }

        cepCell* bucket_summary = cep_poc_ensure_dictionary(summary_root, &name_dt, CEP_STORAGE_RED_BLACK_T);
        if (!bucket_summary || !cep_poc_clear_children(bucket_summary)) {
            return CEP_ENZYME_FATAL;
        }

        if (!cep_poc_store_numeric_value(bucket_summary, "total", stats[i].submitted) ||
            !cep_poc_store_numeric_value(bucket_summary, "ok", stats[i].ok) ||
            !cep_poc_store_numeric_value(bucket_summary, "fail", stats[i].fail) ||
            !cep_poc_store_numeric_value(bucket_summary, "wait", stats[i].wait)) {
            return CEP_ENZYME_FATAL;
        }
    }

    cepCell* recent_root = cep_poc_ensure_dictionary(adj_root, dt_recent(), CEP_STORAGE_RED_BLACK_T);
    if (!recent_root || !cep_poc_clear_children(recent_root)) {
        return CEP_ENZYME_FATAL;
    }

    for (int i = 0; i < CEP_POC_IO_BUCKET_COUNT; ++i) {
        const cepDT* bucket_dt = CEP_POC_IO_BUCKETS[i].dt_fn();
        cepCell* bucket_list = cep_poc_ensure_dictionary(recent_root, bucket_dt, CEP_STORAGE_LINKED_LIST);
        if (!bucket_list || !cep_poc_clear_children(bucket_list)) {
            return CEP_ENZYME_FATAL;
        }

        for (size_t j = 0; j < recent_count; ++j) {
            if (recent[j].bucket != bucket_dt) {
                continue;
            }

            cepDT auto_name = {
                .domain = cep_poc_domain(),
                .tag = CEP_AUTOID,
            };
            cepDT dict_type = *dt_dictionary();
            cepCell* entry = cep_dict_add_dictionary(bucket_list, &auto_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
            if (!entry) {
                return CEP_ENZYME_FATAL;
            }

            const char* id_text = NULL;
            (void)cep_poc_get_cstring(recent[j].request, dt_id(), &id_text);
            if (id_text && id_text[0]) {
                (void)cep_poc_store_value(entry, dt_id(), id_text);
            }

            const char* outcome_text = NULL;
            (void)cep_poc_get_cstring(recent[j].request, dt_outcome(), &outcome_text);
            if (outcome_text && outcome_text[0]) {
                (void)cep_poc_store_value(entry, dt_outcome(), outcome_text);
            }

            if (bucket_dt == dt_poc_echo_intent()) {
                const char* text = NULL;
                (void)cep_poc_get_cstring(recent[j].request, dt_text_field(), &text);
                if (text && text[0]) {
                    (void)cep_poc_store_value(entry, dt_text_field(), text);
                }
            } else if (bucket_dt == dt_poc_calc_intent()) {
                const char* expr = NULL;
                (void)cep_poc_get_cstring(recent[j].request, dt_expr(), &expr);
                if (expr && expr[0]) {
                    (void)cep_poc_store_value(entry, dt_expr(), expr);
                }
            } else {
                const char* key_text = NULL;
                (void)cep_poc_get_cstring(recent[j].request, dt_key(), &key_text);
                if (key_text && key_text[0]) {
                    (void)cep_poc_store_value(entry, dt_key(), key_text);
                }

                if (bucket_dt == dt_poc_kv_set_intent()) {
                    const char* value_text = NULL;
                    (void)cep_poc_get_cstring(recent[j].request, dt_value(), &value_text);
                    if (value_text && value_text[0]) {
                        (void)cep_poc_store_value(entry, dt_value(), value_text);
                    }
                }
            }
        }
    }

    return CEP_ENZYME_SUCCESS;
}

static bool cep_poc_extract_identifier(cepCell* request, const cepDT* field, cepDT* out_dt) {
    const char* text = NULL;
    if (!cep_poc_get_cstring(request, field, &text)) {
        return false;
    }
    return cep_poc_text_to_dt(text, out_dt);
}

static void cep_poc_normalize_token(const char* text, char* buffer, size_t buffer_size, const char* fallback) {
    if (!buffer || buffer_size == 0u) {
        return;
    }

    const char* src = (text && text[0] != '\0') ? text : fallback;
    if (!src) {
        src = "poc";
    }

    size_t out = 0u;
    for (; src[out] && out + 1u < buffer_size; ++out) {
        unsigned char ch = (unsigned char)src[out];
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' || ch == '-' || ch == '.') {
            buffer[out] = (char)((ch >= 'A' && ch <= 'Z') ? (ch - 'A' + 'a') : ch);
        } else {
            buffer[out] = '_';
        }
    }

    if (out == 0u) {
        buffer[out++] = 'p';
    }

    buffer[out] = '\0';
}

static bool cep_poc_run_record_spawn(cepCell* spawns_root,
                                     const char* identifier,
                                     const char* kind_text,
                                     cepCell* request_node) {
    if (!spawns_root || !identifier) {
        return false;
    }

    cepDT id_dt = {0};
    if (!cep_poc_text_to_dt(identifier, &id_dt)) {
        return false;
    }

    cepCell* slot = cep_cell_find_by_name(spawns_root, &id_dt);
    bool newly_created = false;
    if (!slot) {
        cepDT dict_type = *dt_dictionary();
        cepDT id_copy = id_dt;
        slot = cep_dict_add_dictionary(spawns_root, &id_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!slot) {
            return false;
        }
        newly_created = true;
    }

    if (newly_created) {
        if (!cep_poc_store_value(slot, dt_id(), identifier)) {
            cep_cell_remove_hard(slot, NULL);
            return false;
        }
    }

    if (kind_text) {
        const char* existing_kind = NULL;
        if (!cep_poc_get_cstring(slot, dt_kind(), &existing_kind) || !existing_kind || existing_kind[0] == '\0') {
            if (!cep_poc_store_value(slot, dt_kind(), kind_text)) {
                if (newly_created) {
                    cep_cell_remove_hard(slot, NULL);
                }
                return false;
            }
        }
    }

    if (request_node) {
        cepCell* target_link = cep_cell_find_by_name(slot, dt_target());
        if (!target_link) {
            cepDT link_tag = *dt_target();
            if (!cep_dict_add_link(slot, &link_tag, request_node)) {
                if (newly_created) {
                    cep_cell_remove_hard(slot, NULL);
                }
                return false;
            }
        }
    }

    return true;
}

static bool cep_poc_run_spawn_step(const char* run_id,
                                   cepCell* step,
                                   cepCell* spawns_root,
                                   const char** error_code) {
    if (error_code) {
        *error_code = NULL;
    }

    if (!run_id || !step || !spawns_root) {
        if (error_code) {
            *error_code = "invalid-step";
        }
        return false;
    }

    const char* step_id = NULL;
    const char* kind_text = NULL;
    if (!cep_poc_get_cstring(step, dt_id(), &step_id) ||
        !cep_poc_get_cstring(step, dt_kind(), &kind_text)) {
        if (error_code) {
            *error_code = "step-metadata";
        }
        return false;
    }

    cepDT step_dt = {0};
    if (!cep_poc_text_to_dt(step_id, &step_dt)) {
        if (error_code) {
            *error_code = "step-invalid-id";
        }
        return false;
    }

    cepCell* existing_spawn = cep_cell_find_by_name(spawns_root, &step_dt);
    const char* existing_kind = NULL;
    if (existing_spawn) {
        (void)cep_poc_get_cstring(existing_spawn, dt_kind(), &existing_kind);
        if (existing_kind && kind_text && strcmp(existing_kind, kind_text) != 0) {
            if (error_code) {
                *error_code = "spawn-kind-mismatch";
            }
            return false;
        }
        return true;
    }

    char txn_buffer[96];
    snprintf(txn_buffer, sizeof txn_buffer, "run-%s-%s", run_id, step_id);

    cepPocIntent spawn = {0};
    bool success = false;

    if (strcmp(kind_text, "poc_echo") == 0) {
        const char* text = NULL;
        if (!cep_poc_get_cstring(step, dt_text_field(), &text)) {
            if (error_code) {
                *error_code = "step-missing-text";
            }
            return false;
        }
        success = cep_poc_echo_intent_init(&spawn, txn_buffer, step_id, text);
    } else if (strcmp(kind_text, "poc_calc") == 0) {
        const char* expr = NULL;
        if (!cep_poc_get_cstring(step, dt_expr(), &expr)) {
            if (error_code) {
                *error_code = "step-missing-expr";
            }
            return false;
        }
        success = cep_poc_calc_intent_init(&spawn, txn_buffer, step_id, expr);
    } else if (strcmp(kind_text, "poc_kv_set") == 0) {
        const char* key = NULL;
        const char* value = NULL;
        if (!cep_poc_get_cstring(step, dt_key(), &key) ||
            !cep_poc_get_cstring(step, dt_value(), &value)) {
            if (error_code) {
                *error_code = "step-missing-kv";
            }
            return false;
        }
        success = cep_poc_kv_set_intent_init(&spawn, txn_buffer, step_id, key, value);
    } else if (strcmp(kind_text, "poc_kv_get") == 0) {
        const char* key = NULL;
        if (!cep_poc_get_cstring(step, dt_key(), &key)) {
            if (error_code) {
                *error_code = "step-missing-key";
            }
            return false;
        }
        success = cep_poc_kv_get_intent_init(&spawn, txn_buffer, step_id, key);
    } else if (strcmp(kind_text, "poc_kv_del") == 0) {
        const char* key = NULL;
        if (!cep_poc_get_cstring(step, dt_key(), &key)) {
            if (error_code) {
                *error_code = "step-missing-key";
            }
            return false;
        }
        success = cep_poc_kv_del_intent_init(&spawn, txn_buffer, step_id, key);
    } else if (strcmp(kind_text, "poc_assert") == 0) {
        const char* path_text = NULL;
        const char* expect_text = NULL;
        if (!cep_poc_get_cstring(step, dt_path(), &path_text) ||
            !cep_poc_get_cstring(step, dt_expect(), &expect_text)) {
            if (error_code) {
                *error_code = "step-missing-assert";
            }
            return false;
        }
        success = cep_poc_assert_intent_init(&spawn, txn_buffer, step_id, path_text, expect_text);
    } else if (strcmp(kind_text, "poc_bandit") == 0) {
        const char* policy_text = NULL;
        if (!cep_poc_get_cstring(step, dt_policy(), &policy_text)) {
            if (error_code) {
                *error_code = "step-missing-policy";
            }
            return false;
        }

        cepCell* arms_node = cep_cell_find_by_name(step, dt_arms());
        size_t arm_count = 0u;
        for (cepCell* arm = arms_node ? cep_cell_first(arms_node) : NULL; arm; arm = cep_cell_next(arms_node, arm)) {
            if (cep_cell_has_data(arm)) {
                ++arm_count;
            }
        }
        if (arm_count == 0u) {
            if (error_code) {
                *error_code = "step-missing-arms";
            }
            return false;
        }

        const char** arms = cep_malloc(sizeof *arms * arm_count);
        if (!arms) {
            if (error_code) {
                *error_code = "spawn-alloc";
            }
            return false;
        }

        size_t index = 0u;
        for (cepCell* arm = arms_node ? cep_cell_first(arms_node) : NULL; arm; arm = cep_cell_next(arms_node, arm)) {
            if (!cep_cell_has_data(arm)) {
                continue;
            }
            const cepData* data = arm->data;
            if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
                arms[index++] = "";
                continue;
            }
            const char* text = (const char*)data->value;
            if (text[data->size - 1u] != '\0') {
                arms[index++] = "";
                continue;
            }
            arms[index++] = text;
        }

        const char* epsilon_text = NULL;
        (void)cep_poc_get_cstring(step, dt_epsilon(), &epsilon_text);
        const char* rng_seed_text = NULL;
        (void)cep_poc_get_cstring(step, dt_rng_seed(), &rng_seed_text);
        const char* pulls_text = NULL;
        (void)cep_poc_get_cstring(step, dt_spawns(), &pulls_text);

        size_t pulls = 0u;
        if (pulls_text) {
            pulls = (size_t)strtoull(pulls_text, NULL, 10);
        }

        success = cep_poc_bandit_intent_init(&spawn,
                                             txn_buffer,
                                             step_id,
                                             policy_text,
                                             arms,
                                             arm_count,
                                             epsilon_text,
                                             rng_seed_text,
                                             pulls);
        cep_free((void*)arms);
    } else {
        if (error_code) {
            *error_code = "step-unknown-kind";
        }
        return false;
    }

    if (!success) {
        if (error_code && !*error_code) {
            *error_code = "spawn-build";
        }
        return false;
    }

    if (!cep_poc_run_record_spawn(spawns_root, step_id, kind_text, spawn.request)) {
        cep_poc_intent_abort(&spawn);
        if (error_code) {
            *error_code = "spawn-record";
        }
        return false;
    }

    return true;
}

static bool cep_poc_run_spawn_assert(const char* run_id,
                                     cepCell* assert_entry,
                                     cepCell* spawns_root,
                                     const char** error_code) {
    if (error_code) {
        *error_code = NULL;
    }

    if (!run_id || !assert_entry || !spawns_root) {
        if (error_code) {
            *error_code = "assert-invalid";
        }
        return false;
    }

    const char* assert_id = NULL;
    const char* path_text = NULL;
    const char* expect_text = NULL;
    if (!cep_poc_get_cstring(assert_entry, dt_id(), &assert_id) ||
        !cep_poc_get_cstring(assert_entry, dt_path(), &path_text) ||
        !cep_poc_get_cstring(assert_entry, dt_expect(), &expect_text)) {
        if (error_code) {
            *error_code = "assert-metadata";
        }
        return false;
    }

    cepDT assert_dt = {0};
    if (!cep_poc_text_to_dt(assert_id, &assert_dt)) {
        if (error_code) {
            *error_code = "assert-invalid-id";
        }
        return false;
    }

    if (cep_cell_find_by_name(spawns_root, &assert_dt)) {
        return true;
    }

    char txn_buffer[96];
    snprintf(txn_buffer, sizeof txn_buffer, "run-%s-assert-%s", run_id, assert_id);

    cepPocIntent spawn = {0};
    if (!cep_poc_assert_intent_init(&spawn, txn_buffer, assert_id, path_text, expect_text)) {
        if (error_code) {
            *error_code = "spawn-build";
        }
        return false;
    }

    if (!cep_poc_run_record_spawn(spawns_root, assert_id, "poc_assert", spawn.request)) {
        cep_poc_intent_abort(&spawn);
        if (error_code) {
            *error_code = "spawn-record";
        }
        return false;
    }

    return true;
}

static cepCell* cep_poc_find_run_for_request(cepCell* request, cepCell** out_spawn) {
    if (out_spawn) {
        *out_spawn = NULL;
    }

    cepCell* hz_root = cep_poc_hz_root();
    cepCell* run_root = hz_root ? cep_cell_find_by_name(hz_root, dt_run()) : NULL;
    if (!run_root) {
        return NULL;
    }

    for (cepCell* run = cep_cell_first(run_root); run; run = cep_cell_next(run_root, run)) {
        if (!cep_cell_is_normal(run)) {
            continue;
        }

        cepCell* spawns_root = cep_cell_find_by_name(run, dt_spawns());
        if (!spawns_root) {
            continue;
        }

        for (cepCell* spawn = cep_cell_first(spawns_root); spawn; spawn = cep_cell_next(spawns_root, spawn)) {
            if (!cep_cell_is_normal(spawn)) {
                continue;
            }

            cepCell* target_link = cep_cell_find_by_name(spawn, dt_target());
            if (target_link && cep_cell_is_link(target_link) && target_link->link == request) {
                if (out_spawn) {
                    *out_spawn = spawn;
                }
                return run;
            }
        }
    }

    return NULL;
}

static cepPath* cep_poc_build_absolute_path(const char* path_text) {
    if (!path_text || path_text[0] != '/') {
        return NULL;
    }

    size_t len = strlen(path_text);
    size_t pos = 1u;
    unsigned segments = 0u;

    while (pos <= len) {
        size_t start = pos;
        while (pos < len && path_text[pos] != '/') {
            ++pos;
        }
        if (pos > start) {
            ++segments;
        }
        ++pos;
    }

    if (segments == 0u) {
        return NULL;
    }

    size_t bytes = sizeof(cepPath) + ((size_t)segments * sizeof(cepPast));
    cepPath* path = cep_malloc(bytes);
    if (!path) {
        return NULL;
    }

    path->length = segments;
    path->capacity = segments;

    pos = 1u;
    unsigned index = 0u;
    while (pos <= len && index < segments) {
        size_t start = pos;
        while (pos < len && path_text[pos] != '/') {
            ++pos;
        }

        size_t segment_len = pos - start;
        if (segment_len == 0u) {
            ++pos;
            continue;
        }

        if (segment_len > CEP_IDENTIFIER_MAX) {
            cep_free(path);
            return NULL;
        }

        char segment[CEP_IDENTIFIER_MAX + 1u];
        memcpy(segment, &path_text[start], segment_len);
        segment[segment_len] = '\0';

        cepDT segment_dt = {0};
        if (!cep_poc_text_to_dt(segment, &segment_dt)) {
            cep_free(path);
            return NULL;
        }

        path->past[index].dt = segment_dt;
        path->past[index].timestamp = 0u;
        ++index;
        ++pos;
    }

    if (index != segments) {
        cep_free(path);
        return NULL;
    }

    return path;
}

static cepCell* cep_poc_resolve_absolute_path(const char* path_text,
                                             cepOpCount snapshot,
                                             cepPath** out_path) {
    if (out_path) {
        *out_path = NULL;
    }

    cepPath* path = cep_poc_build_absolute_path(path_text);
    if (!path) {
        return NULL;
    }

    cepCell* node = cep_cell_find_by_path_past(cep_root(), path, snapshot);
    if (!node && snapshot != 0u) {
        node = cep_cell_find_by_path_past(cep_root(), path, 0u);
    }

    if (!node) {
        cep_free(path);
        return NULL;
    }

    if (out_path) {
        *out_path = path;
    } else {
        cep_free(path);
    }

    return node;
}

static const char* cep_poc_dt_to_text(const cepDT* dt, char buffer[], size_t size, const char* fallback) {
    if (!buffer || size == 0u) {
        return fallback;
    }
    if (!dt || !dt->tag) {
        if (fallback) {
            snprintf(buffer, size, "%s", fallback);
            return buffer;
        }
        buffer[0] = '\0';
        return buffer;
    }
    size_t written = cep_word_to_text(dt->tag, buffer);
    if (written == 0u || written >= size) {
        if (fallback) {
            snprintf(buffer, size, "%s", fallback);
            return buffer;
        }
        buffer[0] = '\0';
        return buffer;
    }
    buffer[written] = '\0';
    return buffer;
}

static bool cep_poc_bandit_collect_decisions(cepCell* bandit,
                                             cepCell* choices,
                                             const cepDT* run_dt,
                                             bool requested_flow) {
    if (!bandit || !choices || !run_dt) {
        return false;
    }

    cepCell* data_root = cep_poc_data_root();
    cepCell* flow_root = data_root ? cep_cell_find_by_name(data_root, dt_flow()) : NULL;
    cepCell* decision_root = flow_root ? cep_cell_find_by_name(flow_root, dt_decision()) : NULL;
    if (!decision_root) {
        (void)cep_poc_store_value(bandit, dt_flow(), requested_flow ? "queued" : "local");
        return false;
    }

    cepCell* inst_bucket = cep_cell_find_by_name(decision_root, run_dt);
    if (!inst_bucket) {
        (void)cep_poc_store_value(bandit, dt_flow(), requested_flow ? "queued" : "local");
        return false;
    }

    bool any_choice = false;
    for (cepCell* site_entry = cep_cell_first(inst_bucket); site_entry; site_entry = cep_cell_next(inst_bucket, site_entry)) {
        const char* choice_text = NULL;
        if (cep_poc_get_cstring(site_entry, dt_choice_field(), &choice_text) && choice_text && choice_text[0] != '\0') {
            any_choice = true;
            break;
        }
    }

    if (!any_choice) {
        (void)cep_poc_store_value(bandit, dt_flow(), "queued");
        return false;
    }

    (void)cep_poc_clear_children(choices);

    size_t inserted = 0u;
    cepDT dict_type = *dt_dictionary();

    for (cepCell* site_entry = cep_cell_first(inst_bucket); site_entry; site_entry = cep_cell_next(inst_bucket, site_entry)) {
        const char* choice_text = NULL;
        if (!cep_poc_get_cstring(site_entry, dt_choice_field(), &choice_text) || !choice_text || !choice_text[0]) {
            continue;
        }

        cepDT auto_name = {
            .domain = cep_poc_domain(),
            .tag = CEP_AUTOID,
        };
        cepCell* decision_entry = cep_dict_add_dictionary(choices, &auto_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!decision_entry) {
            continue;
        }

        char site_buffer[32];
        const char* site_text = cep_poc_dt_to_text(cep_cell_get_name(site_entry), site_buffer, sizeof site_buffer, "default");

        (void)cep_poc_store_value(decision_entry, dt_site_field(), site_text);
        (void)cep_poc_store_value(decision_entry, dt_choice_field(), choice_text);

        const char* score_text = NULL;
        const char* confidence_text = NULL;
        const char* latency_text = NULL;
        const char* err_text = NULL;
        const char* seed_text = NULL;
        const char* seq_text = NULL;

        cepCell* telemetry = NULL;
        cepCell* validation = cep_cell_find_by_name(site_entry, dt_validation());
        if (validation) {
            telemetry = cep_cell_find_by_name(validation, dt_telemetry());
        }
        if (!telemetry) {
            cepCell* evidence = cep_cell_find_by_name(site_entry, dt_evidence());
            if (evidence) {
                telemetry = cep_cell_find_by_name(evidence, dt_telemetry());
            }
        }

        if (telemetry) {
            (void)cep_poc_get_cstring(telemetry, dt_score(), &score_text);
            (void)cep_poc_get_cstring(telemetry, dt_confidence(), &confidence_text);
            (void)cep_poc_get_cstring(telemetry, dt_latency(), &latency_text);
            (void)cep_poc_get_cstring(telemetry, dt_error_flag(), &err_text);
            (void)cep_poc_get_cstring(telemetry, dt_rng_seed(), &seed_text);
            (void)cep_poc_get_cstring(telemetry, dt_rng_seq(), &seq_text);
        }

        if (score_text && score_text[0]) {
            (void)cep_poc_store_value(decision_entry, dt_score(), score_text);
        }
        if (confidence_text && confidence_text[0]) {
            (void)cep_poc_store_value(decision_entry, dt_confidence(), confidence_text);
        }
        if (latency_text && latency_text[0]) {
            (void)cep_poc_store_value(decision_entry, dt_latency(), latency_text);
        }
        if (err_text && err_text[0]) {
            (void)cep_poc_store_value(decision_entry, dt_error_flag(), err_text);
        }
        if (seed_text && seed_text[0]) {
            (void)cep_poc_store_value(decision_entry, dt_rng_seed(), seed_text);
        }
        if (seq_text && seq_text[0]) {
            (void)cep_poc_store_value(decision_entry, dt_rng_seq(), seq_text);
        }

        cepDT link_dt = *dt_target();
        (void)cep_dict_add_link(decision_entry, &link_dt, site_entry);

        ++inserted;
    }

    if (inserted == 0u) {
        (void)cep_poc_store_value(bandit, dt_flow(), "queued");
        return false;
    }

    char count_buffer[32];
    snprintf(count_buffer, sizeof count_buffer, "%zu", inserted);
    (void)cep_poc_store_value(bandit, dt_count_field(), count_buffer);
    (void)cep_poc_store_value(bandit, dt_flow(), "complete");
    return true;
}

static void cep_poc_bandit_capture_observability(cepCell* bandit,
                                                 const cepDT* run_dt,
                                                 const char* variant_token,
                                                 const char* policy_text,
                                                 bool requested_flow) {
    if (!bandit || !run_dt) {
        return;
    }

    cepCell* telemetry = cep_poc_ensure_dictionary(bandit, dt_telemetry(), CEP_STORAGE_RED_BLACK_T);
    if (!telemetry) {
        return;
    }
    (void)cep_poc_clear_children(telemetry);

    if (variant_token && variant_token[0]) {
        (void)cep_poc_store_value(telemetry, dt_variant_field(), variant_token);
    }
    if (policy_text && policy_text[0]) {
        (void)cep_poc_store_value(telemetry, dt_policy(), policy_text);
    }

    cepCell* data_root = cep_poc_data_root();
    cepCell* flow_root = data_root ? cep_cell_find_by_name(data_root, dt_flow()) : NULL;
    cepCell* index_root = flow_root ? cep_cell_find_by_name(flow_root, dt_index()) : NULL;

    cepDT variant_dt = {0};
    bool have_variant_dt = variant_token && cep_poc_text_to_dt(variant_token, &variant_dt);

    if (index_root && have_variant_dt) {
        cepCell* inst_by_var = cep_cell_find_by_name(index_root, dt_inst_by_var());
        if (inst_by_var) {
            cepCell* variant_bucket = cep_cell_find_by_name(inst_by_var, &variant_dt);
            if (variant_bucket) {
                cepCell* inst_copy_root = cep_poc_ensure_dictionary(telemetry, dt_inst_by_var(), CEP_STORAGE_RED_BLACK_T);
                if (inst_copy_root) {
                    cepCell* bucket_copy = cep_poc_ensure_dictionary(inst_copy_root, &variant_dt, CEP_STORAGE_RED_BLACK_T);
                    if (bucket_copy) {
                        (void)cep_poc_clear_children(bucket_copy);
                        size_t inst_count = 0u;
                        for (cepCell* inst_link = cep_cell_first(variant_bucket); inst_link; inst_link = cep_cell_next(variant_bucket, inst_link)) {
                            if (!cep_cell_is_link(inst_link) || !inst_link->link) {
                                continue;
                            }
                            const cepDT* inst_name = cep_cell_get_name(inst_link);
                            if (!inst_name) {
                                continue;
                            }
                            cepDT name_copy = *inst_name;
                            (void)cep_cell_add_link(bucket_copy, &name_copy, 0, inst_link->link);
                            ++inst_count;
                        }
                        char count_buffer[32];
                        snprintf(count_buffer, sizeof count_buffer, "%zu", inst_count);
                        (void)cep_poc_store_value(bucket_copy, dt_count_field(), count_buffer);
                    }
                }
            }
        }
    }

    cepDT policy_dt = {0};
    bool have_policy_dt = policy_text && policy_text[0] && cep_poc_text_to_dt(policy_text, &policy_dt);

    if (index_root && have_policy_dt) {
        cepCell* dec_by_pol = cep_cell_find_by_name(index_root, dt_dec_by_pol());
        if (dec_by_pol) {
            cepCell* policy_bucket = cep_cell_find_by_name(dec_by_pol, &policy_dt);
            if (policy_bucket) {
                cepCell* policy_copy_root = cep_poc_ensure_dictionary(telemetry, dt_dec_by_pol(), CEP_STORAGE_RED_BLACK_T);
                if (policy_copy_root) {
                    cepCell* bucket_copy = cep_poc_ensure_dictionary(policy_copy_root, &policy_dt, CEP_STORAGE_RED_BLACK_T);
                    if (bucket_copy) {
                        (void)cep_poc_clear_children(bucket_copy);

                        cepCell* meta_src = cep_cell_find_by_name(policy_bucket, dt_meta());
                        if (meta_src) {
                            cepCell* meta_copy = cep_poc_ensure_dictionary(bucket_copy, dt_meta(), CEP_STORAGE_RED_BLACK_T);
                            if (meta_copy) {
                                (void)cep_poc_clear_children(meta_copy);
                                for (cepCell* meta_child = cep_cell_first(meta_src); meta_child; meta_child = cep_cell_next(meta_src, meta_child)) {
                                    if (!cep_cell_is_normal(meta_child)) {
                                        continue;
                                    }
                                    (void)cep_poc_clone_child_into(meta_copy, meta_child);
                                }

                                cepCell* lat_src = cep_cell_find_by_name(meta_src, dt_lat_window());
                                if (lat_src) {
                                    (void)cep_poc_clone_child_into(telemetry, lat_src);
                                }
                                cepCell* err_src = cep_cell_find_by_name(meta_src, dt_err_window());
                                if (err_src) {
                                    (void)cep_poc_clone_child_into(telemetry, err_src);
                                }
                            }
                        }

                        for (cepCell* child = cep_cell_first(policy_bucket); child; child = cep_cell_next(policy_bucket, child)) {
                            if (!cep_cell_is_normal(child) || cep_cell_name_is(child, dt_meta())) {
                                continue;
                            }
                            (void)cep_poc_clone_child_into(bucket_copy, child);
                        }
                    }
                }
            }
        }
    }

    (void)cep_poc_store_value(telemetry, dt_flow(), requested_flow ? "queued" : "local");
}

/* Validate that a scenario step declares a unique identifier, references a
 * supported kind, and carries the payload required by that kind.
 */
static bool cep_poc_validate_scenario_step(cepCell* steps_root,
                                          cepCell* step,
                                          const char** error_code) {
    const char* step_id = NULL;
    if (!cep_poc_get_cstring(step, dt_id(), &step_id) || !step_id || step_id[0] == '\0') {
        if (error_code) {
            *error_code = "step-missing-id";
        }
        return false;
    }

    for (cepCell* other = cep_cell_first(steps_root); other && other != step; other = cep_cell_next(steps_root, other)) {
        const char* other_id = NULL;
        if (cep_poc_get_cstring(other, dt_id(), &other_id) && other_id && strcmp(other_id, step_id) == 0) {
            if (error_code) {
                *error_code = "step-dup-id";
            }
            return false;
        }
    }

    const char* kind_text = NULL;
    if (!cep_poc_get_cstring(step, dt_kind(), &kind_text) || !kind_text || kind_text[0] == '\0') {
        if (error_code) {
            *error_code = "step-missing-kind";
        }
        return false;
    }

    if (strcmp(kind_text, "poc_echo") == 0) {
        const char* text = NULL;
        if (!cep_poc_get_cstring(step, dt_text_field(), &text)) {
            if (error_code) {
                *error_code = "step-missing-text";
            }
            return false;
        }
    } else if (strcmp(kind_text, "poc_calc") == 0) {
        const char* expr = NULL;
        if (!cep_poc_get_cstring(step, dt_expr(), &expr)) {
            if (error_code) {
                *error_code = "step-missing-expr";
            }
            return false;
        }
    } else if (strcmp(kind_text, "poc_kv_set") == 0) {
        const char* key = NULL;
        const char* value = NULL;
        if (!cep_poc_get_cstring(step, dt_key(), &key) ||
            !cep_poc_get_cstring(step, dt_value(), &value)) {
            if (error_code) {
                *error_code = "step-missing-kv";
            }
            return false;
        }
    } else if (strcmp(kind_text, "poc_kv_get") == 0 || strcmp(kind_text, "poc_kv_del") == 0) {
        const char* key = NULL;
        if (!cep_poc_get_cstring(step, dt_key(), &key)) {
            if (error_code) {
                *error_code = "step-missing-key";
            }
            return false;
        }
    } else if (strcmp(kind_text, "poc_assert") == 0) {
        const char* path_text = NULL;
        const char* expect_text = NULL;
        if (!cep_poc_get_cstring(step, dt_path(), &path_text) ||
            !cep_poc_get_cstring(step, dt_expect(), &expect_text)) {
            if (error_code) {
                *error_code = "step-missing-assert";
            }
            return false;
        }
    } else if (strcmp(kind_text, "poc_bandit") == 0) {
        const char* policy_text = NULL;
        if (!cep_poc_get_cstring(step, dt_policy(), &policy_text)) {
            if (error_code) {
                *error_code = "step-missing-policy";
            }
            return false;
        }

        cepCell* arms_node = cep_cell_find_by_name(step, dt_arms());
        size_t arm_count = 0u;
        for (cepCell* arm = arms_node ? cep_cell_first(arms_node) : NULL; arm; arm = cep_cell_next(arms_node, arm)) {
            if (!cep_cell_has_data(arm)) {
                continue;
            }
            const cepData* data = arm->data;
            if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
                continue;
            }
            const char* text = (const char*)data->value;
            if (text[data->size - 1u] == '\0') {
                ++arm_count;
            }
        }
        if (arm_count == 0u) {
            if (error_code) {
                *error_code = "step-missing-arms";
            }
            return false;
        }
    } else {
        if (error_code) {
            *error_code = "step-unknown-kind";
        }
        return false;
    }

    return true;
}

/* Validate inline assertions declared on the scenario intent. */
static bool cep_poc_validate_scenario_assert(cepCell* asserts_root,
                                            cepCell* assert_entry,
                                            const char** error_code) {
    const char* assert_id = NULL;
    if (!cep_poc_get_cstring(assert_entry, dt_id(), &assert_id) || !assert_id || assert_id[0] == '\0') {
        if (error_code) {
            *error_code = "assert-missing-id";
        }
        return false;
    }

    cepDT id_dt = {0};
    if (!cep_poc_text_to_dt(assert_id, &id_dt) || !cep_cell_name_is(assert_entry, &id_dt)) {
        if (error_code) {
            *error_code = "assert-mismatch-id";
        }
        return false;
    }

    for (cepCell* other = cep_cell_first(asserts_root); other && other != assert_entry; other = cep_cell_next(asserts_root, other)) {
        const char* other_id = NULL;
        if (cep_poc_get_cstring(other, dt_id(), &other_id) && other_id && strcmp(other_id, assert_id) == 0) {
            if (error_code) {
                *error_code = "assert-dup-id";
            }
            return false;
        }
    }

    const char* path_text = NULL;
    const char* expect_text = NULL;
    if (!cep_poc_get_cstring(assert_entry, dt_path(), &path_text) ||
        !cep_poc_get_cstring(assert_entry, dt_expect(), &expect_text)) {
        if (error_code) {
            *error_code = "assert-missing-payload";
        }
        return false;
    }

    return true;
}

static bool cep_poc_validate_scenario_payload(cepCell* request, const char** error_code) {
    if (error_code) {
        *error_code = NULL;
    }

    cepCell* steps_root = cep_cell_find_by_name(request, dt_steps());
    for (cepCell* step = steps_root ? cep_cell_first(steps_root) : NULL;
         step;
         step = cep_cell_next(steps_root, step)) {
        if (!cep_poc_validate_scenario_step(steps_root, step, error_code)) {
            if (error_code && !*error_code) {
                *error_code = "step-invalid";
            }
            return false;
        }
    }

    cepCell* asserts_root = cep_cell_find_by_name(request, dt_asserts());
    for (cepCell* assert_entry = asserts_root ? cep_cell_first(asserts_root) : NULL;
         assert_entry;
         assert_entry = cep_cell_next(asserts_root, assert_entry)) {
        if (!cep_poc_validate_scenario_assert(asserts_root, assert_entry, error_code)) {
            if (error_code && !*error_code) {
                *error_code = "assert-invalid";
            }
            return false;
        }
    }

    return true;
}

static int cep_poc_enzyme_hz_scenario(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_poc_resolve_request(target);
    if (!request || !cep_cell_is_normal(request)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, dt_poc_scenario_intent())) {
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_poc_extract_identifier(request, dt_id(), &id_dt)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    const char* validation_error = NULL;
    if (!cep_poc_validate_scenario_payload(request, &validation_error)) {
        cep_poc_mark_outcome(request, validation_error ? validation_error : "invalid-scenario");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* hz_root = cep_poc_hz_root();
    cepCell* scenario_root = hz_root ? cep_cell_find_by_name(hz_root, dt_scenario()) : NULL;
    if (!scenario_root) {
        return CEP_ENZYME_FATAL;
    }

    cepPocStoreLock lock = {0};
    if (!cep_poc_store_lock(scenario_root, &lock)) {
        cep_poc_mark_outcome(request, "ledger-lock");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* entry = cep_poc_ensure_dictionary(scenario_root, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_poc_store_unlock(&lock);
    if (!entry) {
        cep_poc_mark_outcome(request, "create-failed");
        return CEP_ENZYME_SUCCESS;
    }

    if (!cep_poc_copy_payload(request, entry)) {
        cep_poc_mark_outcome(request, "copy-failed");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT link_name = *dt_parent();
    cepCell* parent_link = cep_dict_add_link(entry, &link_name, request);
    if (parent_link) {
        cepCell* parents[] = { parent_link };
        (void)cep_cell_add_parents(entry, parents, cep_lengthof(parents));
    }

    cep_poc_mark_outcome(request, "ok");
    return CEP_ENZYME_SUCCESS;
}

static int cep_poc_enzyme_hz_run(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_poc_resolve_request(target);
    if (!request || !cep_cell_is_normal(request)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, dt_poc_run_intent())) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* run_id_text = NULL;
    if (!cep_poc_get_cstring(request, dt_id(), &run_id_text)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_poc_text_to_dt(run_id_text, &id_dt)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* scenario_link = cep_cell_find_by_name(request, dt_scenario());
    if (!scenario_link || !cep_cell_is_link(scenario_link) || !scenario_link->link) {
        cep_poc_mark_outcome(request, "missing-scenario");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* hz_root = cep_poc_hz_root();
    cepCell* run_root = hz_root ? cep_cell_find_by_name(hz_root, dt_run()) : NULL;
    if (!run_root) {
        return CEP_ENZYME_FATAL;
    }

    cepPocStoreLock lock = {0};
    if (!cep_poc_store_lock(run_root, &lock)) {
        cep_poc_mark_outcome(request, "ledger-lock");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* entry = cep_poc_ensure_dictionary(run_root, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_poc_store_unlock(&lock);
    if (!entry) {
        cep_poc_mark_outcome(request, "create-failed");
        return CEP_ENZYME_SUCCESS;
    }

    if (!cep_poc_copy_payload(request, entry)) {
        cep_poc_mark_outcome(request, "copy-failed");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT link_name = *dt_parent();
    cepCell* parent_link = cep_dict_add_link(entry, &link_name, request);
    if (parent_link) {
        cepCell* parents[] = { parent_link };
        (void)cep_cell_add_parents(entry, parents, cep_lengthof(parents));
    }
    cep_poc_store_value(entry, dt_outcome(), "spawned");

    cepCell* scenario = scenario_link->link;
    if (!scenario) {
        cep_poc_mark_outcome(request, "scenario-link");
        (void)cep_poc_store_value(entry, dt_outcome(), "scenario-link");
        return CEP_ENZYME_SUCCESS;
    }
    cepCell* inputs = cep_poc_ensure_dictionary(entry, dt_inputs(), CEP_STORAGE_RED_BLACK_T);
    cepCell* inputs_steps = inputs ? cep_poc_ensure_dictionary(inputs, dt_steps(), CEP_STORAGE_LINKED_LIST) : NULL;
    cepCell* inputs_asserts = inputs ? cep_poc_ensure_dictionary(inputs, dt_asserts(), CEP_STORAGE_RED_BLACK_T) : NULL;
    cepCell* spawns = cep_poc_ensure_dictionary(entry, dt_spawns(), CEP_STORAGE_RED_BLACK_T);
    if (!inputs || !inputs_steps || !inputs_asserts || !spawns) {
        cep_poc_mark_outcome(request, "spawn-store");
        return CEP_ENZYME_SUCCESS;
    }

    (void)cep_poc_clear_children(inputs_steps);
    (void)cep_poc_clear_children(inputs_asserts);

    cepCell* existing_params = cep_cell_find_by_name(inputs, dt_params());
    if (existing_params) {
        cep_cell_remove_hard(inputs, existing_params);
    }
    cepCell* request_params = cep_cell_find_by_name(request, dt_params());
    if (request_params) {
        if (!cep_poc_clone_child_into(inputs, request_params)) {
            cep_poc_mark_outcome(request, "params-copy-failed");
            return CEP_ENZYME_SUCCESS;
        }
    }

    cepCell* existing_inputs_scenario = cep_cell_find_by_name(inputs, dt_scenario());
    if (existing_inputs_scenario) {
        cep_cell_remove_hard(inputs, existing_inputs_scenario);
    }
    cepDT inputs_scenario_tag = *dt_scenario();
    if (!cep_dict_add_link(inputs, &inputs_scenario_tag, scenario)) {
        cep_poc_mark_outcome(request, "inputs-scenario-link");
        return CEP_ENZYME_SUCCESS;
    }

    const char* error_code = NULL;

    cepCell* scenario_steps = scenario ? cep_cell_find_by_name(scenario, dt_steps()) : NULL;
    for (cepCell* step = scenario_steps ? cep_cell_first(scenario_steps) : NULL;
         step;
         step = cep_cell_next(scenario_steps, step)) {
        if (!cep_poc_clone_child_into(inputs_steps, step)) {
            error_code = "inputs-copy";
            break;
        }
        if (!cep_poc_run_spawn_step(run_id_text, step, spawns, &error_code)) {
            if (!error_code) {
                error_code = "spawn-failed";
            }
            break;
        }
    }

    if (!error_code) {
        cepCell* scenario_asserts = scenario ? cep_cell_find_by_name(scenario, dt_asserts()) : NULL;
        for (cepCell* assert_entry = scenario_asserts ? cep_cell_first(scenario_asserts) : NULL;
             assert_entry;
             assert_entry = cep_cell_next(scenario_asserts, assert_entry)) {
            if (!cep_poc_clone_child_into(inputs_asserts, assert_entry)) {
                error_code = "inputs-copy";
                break;
            }
            if (!cep_poc_run_spawn_assert(run_id_text, assert_entry, spawns, &error_code)) {
                if (!error_code) {
                    error_code = "spawn-failed";
                }
                break;
            }
        }
    }

    if (error_code) {
        cep_poc_store_value(entry, dt_outcome(), error_code);
        cep_poc_mark_outcome(request, error_code);
    } else {
        cep_poc_mark_outcome(request, "spawned");
    }

    return CEP_ENZYME_SUCCESS;
}
static bool cep_poc_read_cell_string(const cepCell* node, const char** out_text) {
    if (!node || !cep_cell_has_data(node) || !out_text) {
        return false;
    }
    const cepData* data = node->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return false;
    }
    const char* actual = (const char*)data->value;
    if (actual[data->size - 1u] != '\0') {
        return false;
    }
    *out_text = actual;
    return true;
}

static bool cep_poc_compare_expectation(const cepCell* node, const char* expect_text) {
    const char* actual = NULL;
    if (!expect_text || !cep_poc_read_cell_string(node, &actual)) {
        return false;
    }
    return strcmp(actual, expect_text) == 0;
}

static int cep_poc_enzyme_hz_assert(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_poc_resolve_request(target);
    if (!request || !cep_cell_is_normal(request)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, dt_poc_assert_intent())) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* path_text = NULL;
    const char* expect_text = NULL;
    if (!cep_poc_get_cstring(request, dt_path(), &path_text) ||
        !cep_poc_get_cstring(request, dt_expect(), &expect_text)) {
        cep_poc_mark_outcome(request, "invalid-payload");
        return CEP_ENZYME_SUCCESS;
    }

    cepOpCount snapshot = cep_cell_timestamp();
    if (snapshot > 0u) {
        snapshot -= 1u;
    }

    cepCell* target_cell = cep_poc_resolve_absolute_path(path_text, snapshot, NULL);

    const char* actual_text = NULL;
    const char* outcome = NULL;
    bool matched = false;

    if (!target_cell) {
        outcome = "not-found";
    } else if (!cep_poc_read_cell_string(target_cell, &actual_text)) {
        outcome = "unsupported-target";
    } else if (cep_poc_compare_expectation(target_cell, expect_text)) {
        outcome = "ok";
        matched = true;
    } else {
        outcome = "mismatch";
    }

    if (actual_text) {
        (void)cep_poc_store_value(request, dt_actual(), actual_text);
    } else {
        cepCell* existing_actual = cep_cell_find_by_name(request, dt_actual());
        if (existing_actual) {
            cep_cell_remove_hard(request, existing_actual);
        }
    }

    cepBeatNumber beat = cep_heartbeat_current();
    char beat_buffer[32];
    snprintf(beat_buffer, sizeof beat_buffer, "%llu", (unsigned long long)beat);
    (void)cep_poc_store_value(request, dt_beat(), beat_buffer);

    cepCell* diff_node = cep_cell_find_by_name(request, dt_diff());
    if (matched) {
        if (diff_node) {
            cep_cell_remove_hard(request, diff_node);
        }
    } else {
        cepCell* diff = diff_node ? diff_node : cep_poc_ensure_dictionary(request, dt_diff(), CEP_STORAGE_RED_BLACK_T);
        if (diff) {
            (void)cep_poc_set_string_value(diff, dt_expect(), expect_text);
            (void)cep_poc_set_string_value(diff, dt_path(), path_text);
            if (actual_text) {
                (void)cep_poc_set_string_value(diff, dt_actual(), actual_text);
            } else {
                cepCell* diff_actual = cep_cell_find_by_name(diff, dt_actual());
                if (diff_actual) {
                    cep_cell_remove_hard(diff, diff_actual);
                }
            }
        }
    }

    cepCell* spawn_entry = NULL;
    cepCell* run_entry = cep_poc_find_run_for_request(request, &spawn_entry);
    if (spawn_entry) {
        (void)cep_poc_store_value(spawn_entry, dt_outcome(), outcome);
    }

    if (run_entry) {
        cepCell* results_root = cep_poc_ensure_dictionary(run_entry, dt_asserts(), CEP_STORAGE_RED_BLACK_T);
        cepDT assert_dt = {0};
        const char* assert_id = NULL;
        (void)cep_poc_get_cstring(request, dt_id(), &assert_id);
        if (results_root && assert_id && cep_poc_text_to_dt(assert_id, &assert_dt)) {
            cepCell* result_entry = cep_poc_ensure_dictionary(results_root, &assert_dt, CEP_STORAGE_RED_BLACK_T);
            if (result_entry) {
                (void)cep_poc_clear_children(result_entry);
                (void)cep_poc_store_value(result_entry, dt_id(), assert_id);
                (void)cep_poc_store_value(result_entry, dt_path(), path_text);
                (void)cep_poc_store_value(result_entry, dt_outcome(), outcome);
                (void)cep_poc_store_value(result_entry, dt_beat(), beat_buffer);
                if (actual_text) {
                    (void)cep_poc_store_value(result_entry, dt_actual(), actual_text);
                }
                if (!matched && outcome && strcmp(outcome, "unsupported-target") != 0) {
                    cepCell* request_diff = cep_cell_find_by_name(request, dt_diff());
                    if (request_diff) {
                        (void)cep_poc_clone_child_into(result_entry, request_diff);
                    }
                }

                cepDT parent_dt = *dt_parent();
                cepCell* parent_link = cep_dict_add_link(result_entry, &parent_dt, request);
                if (parent_link) {
                    cepCell* parents[] = { parent_link };
                    (void)cep_cell_add_parents(result_entry, parents, cep_lengthof(parents));
                }
            }
        }
    }

    cep_poc_mark_outcome(request, outcome ? outcome : "error");
    return CEP_ENZYME_SUCCESS;
}
typedef struct {
    uint64_t state;
} cepPocRng;

static void cep_poc_rng_init(cepPocRng* rng, uint64_t seed) {
    if (!seed) {
        seed = 0x9E3779B97F4A7C15ull;
    }
    rng->state = seed;
}

static double cep_poc_rng_next(cepPocRng* rng) {
    rng->state = rng->state * 6364136223846793005ull + 1ull;
    uint64_t bits = rng->state >> 12u;
    return (bits & ((1ull << 52) - 1ull)) / (double)(1ull << 52);
}

static int cep_poc_enzyme_hz_bandit(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_poc_resolve_request(target);
    if (!request || !cep_cell_is_normal(request)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, dt_poc_bandit_intent())) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* run_id_text = NULL;
    if (!cep_poc_get_cstring(request, dt_id(), &run_id_text)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_poc_text_to_dt(run_id_text, &id_dt)) {
        cep_poc_mark_outcome(request, "invalid-id");
        return CEP_ENZYME_SUCCESS;
    }

    const char* policy_text = NULL;
    (void)cep_poc_get_cstring(request, dt_policy(), &policy_text);
    const char* epsilon_text = NULL;
    (void)cep_poc_get_cstring(request, dt_epsilon(), &epsilon_text);
    const char* rng_seed_text = NULL;
    (void)cep_poc_get_cstring(request, dt_rng_seed(), &rng_seed_text);
    const char* pulls_text = NULL;
    (void)cep_poc_get_cstring(request, dt_spawns(), &pulls_text);

    cepCell* arms_node = cep_cell_find_by_name(request, dt_arms());
    size_t arm_count = 0u;
    for (cepCell* arm = arms_node ? cep_cell_first(arms_node) : NULL; arm; arm = cep_cell_next(arms_node, arm)) {
        if (cep_cell_has_data(arm)) {
            ++arm_count;
        }
    }

    if (arm_count == 0u) {
        cep_poc_mark_outcome(request, "invalid-arms");
        return CEP_ENZYME_SUCCESS;
    }

    const char** arms = cep_malloc(sizeof(const char*) * arm_count);
    if (!arms) {
        return CEP_ENZYME_FATAL;
    }

    size_t index = 0u;
    for (cepCell* arm = arms_node ? cep_cell_first(arms_node) : NULL; arm; arm = cep_cell_next(arms_node, arm)) {
        if (!cep_cell_has_data(arm)) {
            continue;
        }
        const cepData* data = arm->data;
        if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
            continue;
        }
        const char* arm_text = (const char*)data->value;
        if (arm_text[data->size - 1u] != '\0') {
            continue;
        }
        arms[index++] = arm_text;
        if (index == arm_count) {
            break;
        }
    }
    arm_count = index;

    if (arm_count == 0u) {
        cep_free((void*)arms);
        cep_poc_mark_outcome(request, "invalid-arms");
        return CEP_ENZYME_SUCCESS;
    }

    double epsilon = epsilon_text ? strtod(epsilon_text, NULL) : 0.1;
    if (epsilon < 0.0) epsilon = 0.0;
    if (epsilon > 1.0) epsilon = 1.0;

    uint64_t seed = rng_seed_text ? strtoull(rng_seed_text, NULL, 10) : 0u;
    size_t pulls = pulls_text ? (size_t)strtoull(pulls_text, NULL, 10) : 0u;

    cepPocRng rng = {0};
    cep_poc_rng_init(&rng, seed);

    cepCell* hz_root = cep_poc_hz_root();
    cepCell* run_root = hz_root ? cep_cell_find_by_name(hz_root, dt_run()) : NULL;
    if (!run_root) {
        cep_free((void*)arms);
        return CEP_ENZYME_FATAL;
    }

    cepPocStoreLock lock = {0};
    if (!cep_poc_store_lock(run_root, &lock)) {
        cep_free((void*)arms);
        cep_poc_mark_outcome(request, "ledger-lock");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* entry = cep_poc_ensure_dictionary(run_root, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_poc_store_unlock(&lock);
    if (!entry) {
        cep_free((void*)arms);
        cep_poc_mark_outcome(request, "create-failed");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bandit = cep_poc_ensure_dictionary(entry, dt_bandit(), CEP_STORAGE_RED_BLACK_T);
    if (!bandit) {
        cep_free((void*)arms);
        cep_poc_mark_outcome(request, "bandit-store");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* choices = cep_poc_ensure_dictionary(bandit, dt_choices(), CEP_STORAGE_LINKED_LIST);
    if (!choices) {
        cep_free((void*)arms);
        cep_poc_mark_outcome(request, "bandit-store");
        return CEP_ENZYME_SUCCESS;
    }
    (void)cep_poc_clear_children(choices);

    char variant_token[32];
    cep_poc_normalize_token(policy_text, variant_token, sizeof variant_token, run_id_text);
    (void)cep_poc_store_value(bandit, dt_variant_field(), variant_token);

    cepCell* spawns_root = cep_cell_find_by_name(entry, dt_spawns());
    if (!spawns_root) {
        spawns_root = cep_poc_ensure_dictionary(entry, dt_spawns(), CEP_STORAGE_RED_BLACK_T);
    }
    if (!spawns_root) {
        cep_free((void*)arms);
        cep_poc_mark_outcome(request, "spawn-store");
        return CEP_ENZYME_SUCCESS;
    }

    const char* instance_tokens[] = { run_id_text };
    const char* variant_tokens[] = { variant_token };

    char start_txn[48];
    snprintf(start_txn, sizeof start_txn, "bn_%s_start", variant_token);

    bool l2_ready = false;
    cepCell* start_request = NULL;

    cepDT start_spawn_dt = {0};
    if (cep_poc_text_to_dt("bn_start", &start_spawn_dt)) {
        cepCell* existing_start = cep_cell_find_by_name(spawns_root, &start_spawn_dt);
        if (existing_start) {
            cepCell* link = cep_cell_find_by_name(existing_start, dt_target());
            if (link && cep_cell_is_link(link) && link->link) {
                start_request = link->link;
                l2_ready = true;
            }
        }
    }

    cepL2InstanceStartIntent start_intent = {0};
    if (!start_request && cep_l2_instance_start_intent_init(&start_intent,
                                                            start_txn,
                                                            instance_tokens, cep_lengthof(instance_tokens),
                                                            variant_tokens, cep_lengthof(variant_tokens))) {
        start_request = cep_l2_instance_start_intent_request(&start_intent);
        if (start_request) {
            if (policy_text && policy_text[0]) {
                (void)cep_l2_instance_start_intent_set_policy(&start_intent,
                                                              (const char*[]){ variant_token },
                                                              1u);
            }

            char text_buffer[32];
            snprintf(text_buffer, sizeof text_buffer, "%.6g", epsilon);
            (void)cep_l2_instance_start_intent_set_text(&start_intent, "epsilon", text_buffer);
            snprintf(text_buffer, sizeof text_buffer, "%llu", (unsigned long long)seed);
            (void)cep_l2_instance_start_intent_set_text(&start_intent, "rng_seed", text_buffer);
            snprintf(text_buffer, sizeof text_buffer, "%zu", pulls);
            (void)cep_l2_instance_start_intent_set_text(&start_intent, "pulls", text_buffer);

            if (cep_poc_run_record_spawn(spawns_root, "bn_start", "inst_start", start_request)) {
                l2_ready = true;
            }
        }
    }

    const char* signal_path = "CEP:poc/bandit/pull";
    cepDT dict_type = *dt_dictionary();

    for (size_t i = 0; i < pulls && arm_count > 0u; ++i) {
        const double explore_roll = cep_poc_rng_next(&rng);
        size_t pick = 0u;
        bool explore = (explore_roll < epsilon);

        if (explore) {
            double explore_choice = cep_poc_rng_next(&rng);
            pick = (size_t)(explore_choice * (double)arm_count);
        } else {
            pick = i % arm_count;
        }

        if (pick >= arm_count) {
            pick = arm_count - 1u;
        }

        cepCell* event_request = NULL;
        char spawn_id[12];
        snprintf(spawn_id, sizeof spawn_id, "bn%05zu", i % 100000u);

        cepDT spawn_dt = {0};
        if (cep_poc_text_to_dt(spawn_id, &spawn_dt)) {
            cepCell* existing_spawn = cep_cell_find_by_name(spawns_root, &spawn_dt);
            if (existing_spawn) {
                cepCell* link = cep_cell_find_by_name(existing_spawn, dt_target());
                if (link && cep_cell_is_link(link) && link->link) {
                    event_request = link->link;
                }
            }
        }

        if (!event_request && l2_ready) {
            char event_txn[64];
            snprintf(event_txn, sizeof event_txn, "bn_%s_p%02zu", variant_token, i);

            cepL2InstanceEventIntent event_intent = {0};
            if (cep_l2_instance_event_intent_init(&event_intent,
                                                  event_txn,
                                                  signal_path,
                                                  instance_tokens, cep_lengthof(instance_tokens))) {
                event_request = cep_l2_instance_event_intent_request(&event_intent);
                if (event_request) {
                    cepCell* payload = cep_l2_instance_event_intent_payload(&event_intent);
                    if (payload) {
                        (void)cep_poc_set_string_value(payload, dt_choice_field(), arms[pick]);
                        char payload_index[32];
                        snprintf(payload_index, sizeof payload_index, "%zu", pick);
                        (void)cep_poc_set_string_value(payload, dt_index(), payload_index);
                    }

                    if (!cep_poc_run_record_spawn(spawns_root, spawn_id, "inst_event", event_request)) {
                        event_request = NULL;
                    }
                }
            }

            if (!event_request) {
                l2_ready = false;
            }
        }

        if (!l2_ready) {
            cepDT auto_name = {
                .domain = cep_poc_domain(),
                .tag = CEP_AUTOID,
            };
            cepCell* decision_entry = cep_dict_add_dictionary(choices, &auto_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
            if (!decision_entry) {
                cep_free((void*)arms);
                cep_poc_mark_outcome(request, "choice-store");
                return CEP_ENZYME_SUCCESS;
            }

            (void)cep_poc_store_value(decision_entry, dt_choice_field(), arms[pick]);

            char metric_buffer[32];
            snprintf(metric_buffer, sizeof metric_buffer, "%zu", i);
            (void)cep_poc_store_value(decision_entry, dt_rng_seq(), metric_buffer);

            double score = explore ? epsilon : (1.0 - epsilon);
            snprintf(metric_buffer, sizeof metric_buffer, "%.6f", score);
            (void)cep_poc_store_value(decision_entry, dt_score(), metric_buffer);

            double confidence = 1.0 - (epsilon / (double)arm_count);
            snprintf(metric_buffer, sizeof metric_buffer, "%.6f", confidence);
            (void)cep_poc_store_value(decision_entry, dt_confidence(), metric_buffer);
        }
    }

    cep_free((void*)arms);

    char buffer[32];
    if (policy_text) {
        (void)cep_poc_store_value(bandit, dt_policy(), policy_text);
    }
    snprintf(buffer, sizeof buffer, "%.6g", epsilon);
    (void)cep_poc_store_value(bandit, dt_epsilon(), buffer);
    snprintf(buffer, sizeof buffer, "%llu", (unsigned long long)seed);
    (void)cep_poc_store_value(bandit, dt_rng_seed(), buffer);
    snprintf(buffer, sizeof buffer, "%zu", pulls);
    (void)cep_poc_store_value(bandit, dt_rng_seq(), buffer);

    bool decisions_ready = cep_poc_bandit_collect_decisions(bandit, choices, &id_dt, l2_ready);
    cep_poc_bandit_capture_observability(bandit, &id_dt, variant_token, policy_text, l2_ready);

    if (l2_ready) {
        if (decisions_ready) {
            cep_poc_mark_outcome(request, "ok");
        } else {
            (void)cep_poc_store_value(bandit, dt_flow(), "queued");
            cep_poc_mark_outcome(request, "queued");
        }
    } else {
        if (!decisions_ready) {
            (void)cep_poc_store_value(bandit, dt_flow(), "local");
        }
        cep_poc_mark_outcome(request, "ok");
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_poc_enzyme_hz_index(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* hz_root = cep_poc_hz_root();
    if (!hz_root) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* scenario_root = cep_cell_find_by_name(hz_root, dt_scenario());
    cepCell* run_root = cep_cell_find_by_name(hz_root, dt_run());
    cepCell* index_root = cep_cell_find_by_name(hz_root, dt_index());
    if (!scenario_root || !run_root || !index_root) {
        return CEP_ENZYME_FATAL;
    }

    size_t scenario_total = cep_poc_count_children(scenario_root);
    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", scenario_total);
    if (!cep_poc_store_value(index_root, dt_scenario(), buffer)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* run_index = cep_cell_find_by_name(index_root, dt_run());
    if (run_index && cep_cell_has_data(run_index)) {
        cep_cell_remove_hard(index_root, run_index);
        run_index = NULL;
    }
    run_index = cep_poc_ensure_dictionary(index_root, dt_run(), CEP_STORAGE_RED_BLACK_T);
    if (!run_index) {
        return CEP_ENZYME_FATAL;
    }
    (void)cep_poc_clear_children(run_index);

    cepCell* assert_index = cep_cell_find_by_name(index_root, dt_asserts());
    if (assert_index && cep_cell_has_data(assert_index)) {
        cep_cell_remove_hard(index_root, assert_index);
        assert_index = NULL;
    }
    assert_index = cep_poc_ensure_dictionary(index_root, dt_asserts(), CEP_STORAGE_RED_BLACK_T);
    if (!assert_index) {
        return CEP_ENZYME_FATAL;
    }
    (void)cep_poc_clear_children(assert_index);

    size_t run_total = 0u;
    size_t asserts_total = 0u;
    size_t asserts_passed = 0u;
    size_t asserts_expected = 0u;

    for (cepCell* run = cep_cell_first(run_root); run; run = cep_cell_next(run_root, run)) {
        if (!cep_cell_is_normal(run)) {
            continue;
        }

        ++run_total;

        const char* run_outcome = NULL;
        (void)cep_poc_get_cstring(run, dt_outcome(), &run_outcome);
        if (!cep_poc_index_increment(run_index, (run_outcome && run_outcome[0]) ? run_outcome : "pending", 1u)) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* inputs = cep_cell_find_by_name(run, dt_inputs());
        cepCell* inputs_asserts = inputs ? cep_cell_find_by_name(inputs, dt_asserts()) : NULL;
        if (inputs_asserts) {
            asserts_expected += cep_poc_count_children(inputs_asserts);
        }

        cepCell* results_asserts = cep_cell_find_by_name(run, dt_asserts());
        if (!results_asserts) {
            continue;
        }

        for (cepCell* assert_result = cep_cell_first(results_asserts);
             assert_result;
             assert_result = cep_cell_next(results_asserts, assert_result)) {
            if (!cep_cell_is_normal(assert_result)) {
                continue;
            }

            ++asserts_total;

            const char* assert_outcome = NULL;
            (void)cep_poc_get_cstring(assert_result, dt_outcome(), &assert_outcome);

            const char* bucket = NULL;
            if (assert_outcome && strcmp(assert_outcome, "ok") == 0) {
                bucket = "passed";
                ++asserts_passed;
            } else if (assert_outcome && strcmp(assert_outcome, "mismatch") == 0) {
                bucket = "failed";
            } else if (assert_outcome && strcmp(assert_outcome, "not-found") == 0) {
                bucket = "missing";
            } else if (assert_outcome && strcmp(assert_outcome, "unsupported-target") == 0) {
                bucket = "unsupported";
            } else if (assert_outcome && assert_outcome[0]) {
                bucket = assert_outcome;
            } else {
                bucket = "pending";
            }

            if (!cep_poc_index_increment(assert_index, bucket, 1u)) {
                return CEP_ENZYME_FATAL;
            }
        }
    }

    if (!cep_poc_store_numeric_value(run_index, "total", run_total)) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_poc_store_numeric_value(assert_index, "total", asserts_total)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_poc_store_numeric_value(assert_index, "passed", asserts_passed)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_poc_store_numeric_value(assert_index, "expected", asserts_expected)) {
        return CEP_ENZYME_FATAL;
    }

    double coverage = (asserts_expected > 0u)
                        ? (double)asserts_passed / (double)asserts_expected
                        : 0.0;
    char coverage_buffer[32];
    snprintf(coverage_buffer, sizeof coverage_buffer, "%.6f", coverage);
    cepDT coverage_dt = {0};
    if (cep_poc_text_to_dt("coverage", &coverage_dt)) {
        if (!cep_poc_store_value(assert_index, &coverage_dt, coverage_buffer)) {
            return CEP_ENZYME_FATAL;
        }
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_poc_enzyme_hz_adj(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* tmp_root = cep_poc_tmp_root();
    cepCell* tmp_poc = tmp_root ? cep_cell_find_by_name(tmp_root, dt_poc()) : NULL;
    cepCell* tmp_hz = tmp_poc ? cep_cell_find_by_name(tmp_poc, dt_hz()) : NULL;
    cepCell* adj_root = tmp_hz ? cep_cell_find_by_name(tmp_hz, dt_adj()) : NULL;
    if (!adj_root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_poc_clear_children(adj_root)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* hz_root = cep_poc_hz_root();
    if (!hz_root) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* scenario_root = cep_cell_find_by_name(hz_root, dt_scenario());
    cepCell* run_root = cep_cell_find_by_name(hz_root, dt_run());
    if (!scenario_root || !run_root) {
        return CEP_ENZYME_FATAL;
    }

    size_t scenario_total = cep_poc_count_children(scenario_root);
    size_t run_total = cep_poc_count_children(run_root);

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", scenario_total);
    if (!cep_poc_store_value(adj_root, dt_scenario(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", run_total);
    if (!cep_poc_store_value(adj_root, dt_run(), buffer)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* hz_index = cep_cell_find_by_name(hz_root, dt_index());
    cepCell* run_index = hz_index ? cep_cell_find_by_name(hz_index, dt_run()) : NULL;
    cepCell* assert_index = hz_index ? cep_cell_find_by_name(hz_index, dt_asserts()) : NULL;

    cepCell* summary_root = cep_poc_ensure_dictionary(adj_root, dt_summary(), CEP_STORAGE_RED_BLACK_T);
    if (!summary_root || !cep_poc_clear_children(summary_root)) {
        return CEP_ENZYME_FATAL;
    }

    if (run_index) {
        cepCell* summary_runs = cep_poc_ensure_dictionary(summary_root, dt_run(), CEP_STORAGE_RED_BLACK_T);
        if (!summary_runs || !cep_poc_clear_children(summary_runs)) {
            return CEP_ENZYME_FATAL;
        }
        for (cepCell* child = cep_cell_first(run_index); child; child = cep_cell_next(run_index, child)) {
            if (!cep_cell_is_normal(child)) {
                continue;
            }
            if (!cep_poc_clone_child_into(summary_runs, child)) {
                return CEP_ENZYME_FATAL;
            }
        }
    }

    if (assert_index) {
        cepCell* summary_asserts = cep_poc_ensure_dictionary(summary_root, dt_asserts(), CEP_STORAGE_RED_BLACK_T);
        if (!summary_asserts || !cep_poc_clear_children(summary_asserts)) {
            return CEP_ENZYME_FATAL;
        }
        for (cepCell* child = cep_cell_first(assert_index); child; child = cep_cell_next(assert_index, child)) {
            if (!cep_cell_is_normal(child)) {
                continue;
            }
            if (!cep_poc_clone_child_into(summary_asserts, child)) {
                return CEP_ENZYME_FATAL;
            }
        }
    }

    enum { CEP_POC_HZ_RECENT_LIMIT = 8 };
    cepPocRecentEntry recent_runs[CEP_POC_HZ_RECENT_LIMIT];
    cepPocRecentEntry recent_asserts[CEP_POC_HZ_RECENT_LIMIT];
    size_t run_recent_count = 0u;
    size_t assert_recent_count = 0u;

    for (cepCell* run = cep_cell_first(run_root); run; run = cep_cell_next(run_root, run)) {
        if (!cep_cell_is_normal(run)) {
            continue;
        }

        cepOpCount modified = 0u;
        if (run->store) {
            modified = run->store->modified;
        }
        cep_poc_recent_insert(recent_runs,
                              &run_recent_count,
                              CEP_POC_HZ_RECENT_LIMIT,
                              run,
                              dt_run(),
                              modified);

        cepCell* run_asserts = cep_cell_find_by_name(run, dt_asserts());
        for (cepCell* assert_entry = run_asserts ? cep_cell_first(run_asserts) : NULL;
             assert_entry;
             assert_entry = cep_cell_next(run_asserts, assert_entry)) {
            if (!cep_cell_is_normal(assert_entry)) {
                continue;
            }

            cepOpCount assert_modified = 0u;
            if (assert_entry->store) {
                assert_modified = assert_entry->store->modified;
            }
            cep_poc_recent_insert(recent_asserts,
                                  &assert_recent_count,
                                  CEP_POC_HZ_RECENT_LIMIT,
                                  assert_entry,
                                  dt_asserts(),
                                  assert_modified);
        }
    }

    cepCell* recent_root = cep_poc_ensure_dictionary(adj_root, dt_recent(), CEP_STORAGE_RED_BLACK_T);
    if (!recent_root || !cep_poc_clear_children(recent_root)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* recent_runs_root = cep_poc_ensure_dictionary(recent_root, dt_run(), CEP_STORAGE_LINKED_LIST);
    cepCell* recent_asserts_root = cep_poc_ensure_dictionary(recent_root, dt_asserts(), CEP_STORAGE_LINKED_LIST);
    if (!recent_runs_root || !recent_asserts_root ||
        !cep_poc_clear_children(recent_runs_root) ||
        !cep_poc_clear_children(recent_asserts_root)) {
        return CEP_ENZYME_FATAL;
    }

    for (size_t i = 0; i < run_recent_count; ++i) {
        cepDT auto_name = {
            .domain = cep_poc_domain(),
            .tag = CEP_AUTOID,
        };
        cepDT dict_type = *dt_dictionary();
        cepCell* entry = cep_dict_add_dictionary(recent_runs_root, &auto_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!entry) {
            return CEP_ENZYME_FATAL;
        }

        const char* run_id = NULL;
        (void)cep_poc_get_cstring(recent_runs[i].request, dt_id(), &run_id);
        if (run_id && run_id[0]) {
            (void)cep_poc_store_value(entry, dt_id(), run_id);
        }

        const char* outcome_text = NULL;
        (void)cep_poc_get_cstring(recent_runs[i].request, dt_outcome(), &outcome_text);
        if (outcome_text && outcome_text[0]) {
            (void)cep_poc_store_value(entry, dt_outcome(), outcome_text);
        }

        cepCell* params = cep_cell_find_by_name(recent_runs[i].request, dt_params());
        if (params) {
            cepCell* params_copy = cep_poc_ensure_dictionary(entry, dt_params(), CEP_STORAGE_RED_BLACK_T);
            if (params_copy) {
                (void)cep_poc_clear_children(params_copy);
                for (cepCell* child = cep_cell_first(params); child; child = cep_cell_next(params, child)) {
                    if (!cep_cell_is_normal(child)) {
                        continue;
                    }
                    (void)cep_poc_clone_child_into(params_copy, child);
                }
            }
        }
    }

    for (size_t i = 0; i < assert_recent_count; ++i) {
        cepDT auto_name = {
            .domain = cep_poc_domain(),
            .tag = CEP_AUTOID,
        };
        cepDT dict_type = *dt_dictionary();
        cepCell* entry = cep_dict_add_dictionary(recent_asserts_root, &auto_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!entry) {
            return CEP_ENZYME_FATAL;
        }

        const char* assert_id = NULL;
        (void)cep_poc_get_cstring(recent_asserts[i].request, dt_id(), &assert_id);
        if (assert_id && assert_id[0]) {
            (void)cep_poc_store_value(entry, dt_id(), assert_id);
        }

        const char* outcome_text = NULL;
        (void)cep_poc_get_cstring(recent_asserts[i].request, dt_outcome(), &outcome_text);
        if (outcome_text && outcome_text[0]) {
            (void)cep_poc_store_value(entry, dt_outcome(), outcome_text);
        }

        const char* path_text = NULL;
        (void)cep_poc_get_cstring(recent_asserts[i].request, dt_path(), &path_text);
        if (path_text && path_text[0]) {
            (void)cep_poc_store_value(entry, dt_path(), path_text);
        }

        const char* expect_text = NULL;
        (void)cep_poc_get_cstring(recent_asserts[i].request, dt_expect(), &expect_text);
        if (expect_text && expect_text[0]) {
            (void)cep_poc_store_value(entry, dt_expect(), expect_text);
        }

        const char* actual_text = NULL;
        (void)cep_poc_get_cstring(recent_asserts[i].request, dt_actual(), &actual_text);
        if (actual_text && actual_text[0]) {
            (void)cep_poc_store_value(entry, dt_actual(), actual_text);
        }

        const char* beat_text = NULL;
        (void)cep_poc_get_cstring(recent_asserts[i].request, dt_beat(), &beat_text);
        if (beat_text && beat_text[0]) {
            (void)cep_poc_store_value(entry, dt_beat(), beat_text);
        }
    }

    return CEP_ENZYME_SUCCESS;
}
