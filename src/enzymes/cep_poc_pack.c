/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_poc_pack.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
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

static const cepDT* dt_dictionary(void)  { return CEP_DTAW("CEP", "dictionary"); }
static const cepDT* dt_text(void)        { return CEP_DTAW("CEP", "text"); }
static const cepDT* dt_data(void)        { return CEP_DTAW("CEP", "data"); }
static const cepDT* dt_sys(void)         { return CEP_DTAW("CEP", "sys"); }
static const cepDT* dt_tmp(void)         { return CEP_DTAW("CEP", "tmp"); }
static const cepDT* dt_poc(void)         { return CEP_DTAW("CEP", "poc"); }
static const cepDT* dt_io(void)          { return CEP_DTAW("CEP", "io"); }
static const cepDT* dt_hz(void)          { return CEP_DTAW("CEP", "hz"); }
static const cepDT* dt_index(void)       { return CEP_DTAW("CEP", "index"); }
static const cepDT* dt_inbox(void)       { return CEP_DTAW("CEP", "inbox"); }
static const cepDT* dt_adj(void)         { return CEP_DTAW("CEP", "adj"); }
static const cepDT* dt_original(void)    { return CEP_DTAW("CEP", "original"); }
static const cepDT* dt_outcome(void)     { return CEP_DTAW("CEP", "outcome"); }
static const cepDT* dt_enabled(void)     { return CEP_DTAW("CEP", "enabled"); }
static const cepDT* dt_retention(void)   { return CEP_DTAW("CEP", "retention"); }
static const cepDT* dt_echo(void)        { return CEP_DTAW("CEP", "echo"); }
static const cepDT* dt_calc(void)        { return CEP_DTAW("CEP", "calc"); }
static const cepDT* dt_kv(void)          { return CEP_DTAW("CEP", "kv"); }
static const cepDT* dt_ans(void)         { return CEP_DTAW("CEP", "ans"); }
static const cepDT* dt_scenario(void)    { return CEP_DTAW("CEP", "scenario"); }
static const cepDT* dt_run(void)         { return CEP_DTAW("CEP", "run"); }
static const cepDT* dt_text_field(void)  { return CEP_DTAW("CEP", "text"); }
static const cepDT* dt_expr(void)        { return CEP_DTAW("CEP", "expr"); }
static const cepDT* dt_result(void)      { return CEP_DTAW("CEP", "result"); }
static const cepDT* dt_id(void)          { return CEP_DTAW("CEP", "id"); }
static const cepDT* dt_key(void)         { return CEP_DTAW("CEP", "key"); }
static const cepDT* dt_value(void)       { return CEP_DTAW("CEP", "value"); }
static const cepDT* dt_kind(void)        { return CEP_DTAW("CEP", "kind"); }
static const cepDT* dt_steps(void)       { return CEP_DTAW("CEP", "steps"); }
static const cepDT* dt_asserts(void)     { return CEP_DTAW("CEP", "asserts"); }
static const cepDT* dt_spawns(void)      { return CEP_DTAW("CEP", "spawns"); }
static const cepDT* dt_expect(void)      { return CEP_DTAW("CEP", "expect"); }
static const cepDT* dt_path(void)        { return CEP_DTAW("CEP", "path"); }
static const cepDT* dt_parent(void)      { return CEP_DTAW("CEP", "parent"); }
static const cepDT* dt_keys(void)        { return CEP_DTAW("CEP", "keys"); }
static const cepDT* dt_tomb(void)        { return CEP_DTAW("CEP", "tomb"); }
static const cepDT* dt_policy(void)      { return CEP_DTAW("CEP", "policy"); }
static const cepDT* dt_arms(void)        { return CEP_DTAW("CEP", "arms"); }
static const cepDT* dt_epsilon(void)     { return CEP_DTAW("CEP", "epsilon"); }
static const cepDT* dt_rng_seed(void)    { return CEP_DTAW("CEP", "rng_seed"); }
static const cepDT* dt_rng_seq(void)     { return CEP_DTAW("CEP", "rng_seq"); }
static const cepDT* dt_bandit(void)      { return CEP_DTAW("CEP", "bandit"); }
static const cepDT* dt_choices(void)     { return CEP_DTAW("CEP", "choices"); }

static const cepDT* dt_poc_echo_intent(void)    { return CEP_DTAW("CEP", "poc_echo"); }
static const cepDT* dt_poc_calc_intent(void)    { return CEP_DTAW("CEP", "poc_calc"); }
static const cepDT* dt_poc_kv_set_intent(void)  { return CEP_DTAW("CEP", "poc_kv_set"); }
static const cepDT* dt_poc_kv_get_intent(void)  { return CEP_DTAW("CEP", "poc_kv_get"); }
static const cepDT* dt_poc_kv_del_intent(void)  { return CEP_DTAW("CEP", "poc_kv_del"); }
CEP_POC_DT_STATIC(dt_poc_scenario_intent, "poc_scenario")
static const cepDT* dt_poc_run_intent(void)     { return CEP_DTAW("CEP", "poc_run"); }
static const cepDT* dt_poc_assert_intent(void)  { return CEP_DTAW("CEP", "poc_assert"); }
static const cepDT* dt_poc_bandit_intent(void)  { return CEP_DTAW("CEP", "poc_bandit"); }

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

/* Ensure the PoC directory tree and toggles exist before any registry wiring
 * so ingest enzymes can assume the ledgers and inbox buckets already exist. */
bool cep_poc_bootstrap(void) {
    if (!cep_cell_system_initialized()) {
        return false;
    }

    if (!cep_mailroom_add_namespace(cep_poc_mailroom_namespace,
                                    cep_poc_mailroom_buckets,
                                    cep_lengthof(cep_poc_mailroom_buckets))) {
        return false;
    }

    if (!cep_mailroom_bootstrap()) {
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

    if (!cep_poc_ensure_dictionary(sys_poc, dt_retention(), CEP_STORAGE_RED_BLACK_T)) {
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

    size_t echo_count = cep_poc_count_children(echo_root);
    size_t calc_count = cep_poc_count_children(calc_root);
    size_t kv_count = cep_poc_count_active_kv(kv_root);

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", echo_count);
    if (!cep_poc_store_value(index_root, dt_echo(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", calc_count);
    if (!cep_poc_store_value(index_root, dt_calc(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", kv_count);
    if (!cep_poc_store_value(index_root, dt_kv(), buffer)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* kv_index = cep_poc_ensure_dictionary(index_root, dt_keys(), CEP_STORAGE_LINKED_LIST);
    if (!kv_index) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_poc_clear_children(kv_index)) {
        return CEP_ENZYME_FATAL;
    }

    for (cepCell* entry = cep_cell_first(kv_root); entry; entry = cep_cell_next(kv_root, entry)) {
        if (!cep_cell_is_normal(entry)) {
            continue;
        }

        const char* tomb = NULL;
        if (cep_poc_get_cstring(entry, dt_tomb(), &tomb) && tomb && tomb[0] == '1') {
            continue;
        }

        const char* key_text = NULL;
        if (!cep_poc_get_cstring(entry, dt_key(), &key_text)) {
            continue;
        }

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

    size_t echo_count = cep_poc_count_children(echo_root);
    size_t calc_count = cep_poc_count_children(calc_root);
    size_t kv_count = cep_poc_count_active_kv(kv_root);

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", echo_count);
    if (!cep_poc_store_value(adj_root, dt_echo(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", calc_count);
    if (!cep_poc_store_value(adj_root, dt_calc(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", kv_count);
    if (!cep_poc_store_value(adj_root, dt_kv(), buffer)) {
        return CEP_ENZYME_FATAL;
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

    cepDT id_dt = {0};
    if (!cep_poc_extract_identifier(request, dt_id(), &id_dt)) {
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

    cep_poc_mark_outcome(request, "ok");
    return CEP_ENZYME_SUCCESS;
}
static cepCell* cep_poc_resolve_absolute_path(const char* path_text) {
    if (!path_text || path_text[0] != '/') {
        return NULL;
    }

    cepCell* node = cep_root();
    size_t len = strlen(path_text);
    size_t pos = 1u;

    while (pos <= len && node) {
        size_t start = pos;
        while (pos < len && path_text[pos] != '/') {
            ++pos;
        }

        size_t segment_len = pos - start;
        if (segment_len == 0u) {
            ++pos;
            continue;
        }

        char segment[CEP_IDENTIFIER_MAX + 1u];
        if (segment_len >= sizeof segment) {
            return NULL;
        }
        memcpy(segment, &path_text[start], segment_len);
        segment[segment_len] = '\0';

        cepDT segment_dt = {0};
        if (!cep_poc_text_to_dt(segment, &segment_dt)) {
            return NULL;
        }

        node = cep_cell_find_by_name(node, &segment_dt);
        ++pos;
    }

    return node;
}
static bool cep_poc_compare_expectation(const cepCell* node, const char* expect_text) {
    if (!node || !cep_cell_has_data(node) || !expect_text) {
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

    cepCell* target_cell = cep_poc_resolve_absolute_path(path_text);
    if (!target_cell) {
        cep_poc_mark_outcome(request, "not-found");
        return CEP_ENZYME_SUCCESS;
    }

    if (cep_poc_compare_expectation(target_cell, expect_text)) {
        cep_poc_mark_outcome(request, "ok");
    } else {
        cep_poc_mark_outcome(request, "mismatch");
    }

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

    cepDT id_dt = {0};
    if (!cep_poc_extract_identifier(request, dt_id(), &id_dt)) {
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

    for (size_t i = 0; i < pulls && arm_count > 0u; ++i) {
        double sample = cep_poc_rng_next(&rng);
        size_t pick = (size_t)(sample * (double)arm_count);
        if (pick >= arm_count) {
            pick = arm_count - 1u;
        }
        const char* arm_text = arms[pick];
        size_t len = strlen(arm_text) + 1u;
        cepDT auto_name = {
            .domain = cep_poc_domain(),
            .tag = CEP_AUTOID,
        };
        cepDT text_type = *dt_text();
        cepCell* node = cep_dict_add_value(choices, &auto_name, &text_type, (void*)arm_text, len, len);
        if (!node) {
            cep_free((void*)arms);
            cep_poc_mark_outcome(request, "choice-store");
            return CEP_ENZYME_SUCCESS;
        }
        cep_cell_content_hash(node);
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

    cep_poc_mark_outcome(request, "ok");
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

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", cep_poc_count_children(scenario_root));
    if (!cep_poc_store_value(index_root, dt_scenario(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", cep_poc_count_children(run_root));
    if (!cep_poc_store_value(index_root, dt_run(), buffer)) {
        return CEP_ENZYME_FATAL;
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

    char buffer[32];
    snprintf(buffer, sizeof buffer, "%zu", cep_poc_count_children(scenario_root));
    if (!cep_poc_store_value(adj_root, dt_scenario(), buffer)) {
        return CEP_ENZYME_FATAL;
    }
    snprintf(buffer, sizeof buffer, "%zu", cep_poc_count_children(run_root));
    if (!cep_poc_store_value(adj_root, dt_run(), buffer)) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}
