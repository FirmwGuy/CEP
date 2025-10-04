/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_flows.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

/* ------------------------------------------------------------------------- */
/*  Canonical tags                                                           */
/* ------------------------------------------------------------------------- */

/* These accessors keep tag lookups lazy so the compiler can fold the DT
 * constants while keeping call sites clean and consistent with the L1 module. */
static const cepDT* dt_data_root(void)   { return CEP_DTAW("CEP", "data"); }
static const cepDT* dt_tmp_root(void)    { return CEP_DTAW("CEP", "tmp"); }
static const cepDT* dt_dictionary(void)  { return CEP_DTAW("CEP", "dictionary"); }
static const cepDT* dt_flow(void)        { return CEP_DTAW("CEP", "flow"); }
static const cepDT* dt_program(void)     { return CEP_DTAW("CEP", "program"); }
static const cepDT* dt_policy(void)      { return CEP_DTAW("CEP", "policy"); }
static const cepDT* dt_variant(void)     { return CEP_DTAW("CEP", "variant"); }
static const cepDT* dt_niche(void)       { return CEP_DTAW("CEP", "niche"); }
static const cepDT* dt_guardian(void)    { return CEP_DTAW("CEP", "guardian"); }
static const cepDT* dt_instance(void)    { return CEP_DTAW("CEP", "instance"); }
static const cepDT* dt_decision(void)    { return CEP_DTAW("CEP", "decision"); }
static const cepDT* dt_index(void)       { return CEP_DTAW("CEP", "index"); }
static const cepDT* dt_inbox(void)       { return CEP_DTAW("CEP", "inbox"); }
static const cepDT* dt_adj(void)         { return CEP_DTAW("CEP", "adj"); }
static const cepDT* dt_signal_cell(void) { return CEP_DTAW("CEP", "sig_cell"); }
static const cepDT* dt_op_add(void)      { return CEP_DTAW("CEP", "op_add"); }
static const cepDT* dt_fl_upsert(void)   { return CEP_DTAW("CEP", "fl_upsert"); }
static const cepDT* dt_ni_upsert(void)   { return CEP_DTAW("CEP", "ni_upsert"); }
static const cepDT* dt_inst_start(void)  { return CEP_DTAW("CEP", "inst_start"); }
static const cepDT* dt_inst_event(void)  { return CEP_DTAW("CEP", "inst_event"); }
static const cepDT* dt_inst_ctrl(void)   { return CEP_DTAW("CEP", "inst_ctrl"); }
static const cepDT* dt_fl_ing(void)      { return CEP_DTAW("CEP", "fl_ing"); }
static const cepDT* dt_ni_ing(void)      { return CEP_DTAW("CEP", "ni_ing"); }
static const cepDT* dt_inst_ing(void)    { return CEP_DTAW("CEP", "inst_ing"); }
static const cepDT* dt_fl_wake(void)     { return CEP_DTAW("CEP", "fl_wake"); }
static const cepDT* dt_fl_step(void)     { return CEP_DTAW("CEP", "fl_step"); }
static const cepDT* dt_fl_index(void)    { return CEP_DTAW("CEP", "fl_index"); }
static const cepDT* dt_fl_adj(void)      { return CEP_DTAW("CEP", "fl_adj"); }
static const cepDT* dt_steps(void)       { return CEP_DTAW("CEP", "steps"); }
static const cepDT* dt_spec(void)        { return CEP_DTAW("CEP", "spec"); }
static const cepDT* dt_subs(void)        { return CEP_DTAW("CEP", "subs"); }
static const cepDT* dt_signal(void)      { return CEP_DTAW("CEP", "signal"); }
static const cepDT* dt_signal_path(void) { return CEP_DTAW("CEP", "signal_path"); }
static const cepDT* dt_status(void)      { return CEP_DTAW("CEP", "status"); }
static const cepDT* dt_payload(void)     { return CEP_DTAW("CEP", "payload"); }
static const cepDT* dt_choice(void)      { return CEP_DTAW("CEP", "choice"); }
static const cepDT* dt_text(void)        { return CEP_DTAW("CEP", "text"); }
static const cepDT* dt_outcome(void)     { return CEP_DTAW("CEP", "outcome"); }
static const cepDT* dt_original(void)    { return CEP_DTAW("CEP", "original"); }
static const cepDT* dt_id(void)          { return CEP_DTAW("CEP", "id"); }
static const cepDT* dt_kind(void)        { return CEP_DTAW("CEP", "kind"); }
static const cepDT* dt_state(void)       { return CEP_DTAW("CEP", "state"); }
static const cepDT* dt_pc(void)          { return CEP_DTAW("CEP", "pc"); }
static const cepDT* dt_events(void)      { return CEP_DTAW("CEP", "events"); }
static const cepDT* dt_action(void)      { return CEP_DTAW("CEP", "action"); }
static const cepDT* dt_inst_id(void)     { return CEP_DTAW("CEP", "inst_id"); }
static const cepDT* dt_site(void)        { return CEP_DTAW("CEP", "site"); }

/* Forward declarations for helpers used across the module. */
static cepCell* cep_l2_flow_root(void);
static cepCell* cep_l2_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage);
static bool     cep_l2_copy_request_payload(cepCell* request, cepCell* dst);
static cepCell* cep_l2_program_from_instance(cepCell* flow_root, cepCell* instance);
static cepCell* cep_l2_steps_container(cepCell* program);
static cepCell* cep_l2_step_at(cepCell* steps, size_t index);
static cepCell* cep_l2_step_spec(cepCell* step);
static cepCell* cep_l2_decision_ledger(cepCell* flow_root);
static cepCell* cep_l2_decision_node(cepCell* ledger, const cepDT* inst_name, const char* site, bool create);

/* ------------------------------------------------------------------------- */
/*  Local state                                                              */
/* ------------------------------------------------------------------------- */

static bool cep_l2_bindings_applied = false;

/* ------------------------------------------------------------------------- */
/*  Small helpers                                                            */
/* ------------------------------------------------------------------------- */

static cepID cep_l2_domain(void) {
    return CEP_ACRO("CEP");
}

typedef struct {
    cepCell*    cell;
    cepLockToken token;
    bool         locked;
} cepL2StoreLock;

typedef struct {
    cepCell*    cell;
    cepLockToken token;
    bool         locked;
} cepL2DataLock;

static void cep_l2_store_unlock(cepL2StoreLock* guard) {
    if (!guard || !guard->locked || !guard->cell) {
        return;
    }
    cep_store_unlock(guard->cell, &guard->token);
    guard->cell = NULL;
    guard->locked = false;
}

static bool cep_l2_store_lock(cepCell* cell, cepL2StoreLock* guard) {
    if (!cell || !guard || !cep_cell_has_store(cell)) {
        return false;
    }

    guard->cell = NULL;
    guard->locked = false;

    if (!cep_store_lock(cell, &guard->token)) {
        return false;
    }

    guard->cell = cell;
    guard->locked = true;
    return true;
}

static void cep_l2_data_unlock(cepL2DataLock* guard) {
    if (!guard || !guard->locked || !guard->cell) {
        return;
    }
    cep_data_unlock(guard->cell, &guard->token);
    guard->cell = NULL;
    guard->locked = false;
}

static bool cep_l2_data_lock(cepCell* cell, cepL2DataLock* guard) {
    if (!cell || !guard || !cep_cell_has_data(cell)) {
        return false;
    }

    guard->cell = NULL;
    guard->locked = false;

    if (!cep_data_lock(cell, &guard->token)) {
        return false;
    }

    guard->cell = cell;
    guard->locked = true;
    return true;
}

static void cep_l2_clear_children(cepCell* cell) {
    if (!cell || !cep_cell_has_store(cell)) {
        return;
    }

    bool writable = cell->store->writable;
    cell->store->writable = true;
    cep_store_delete_children_hard(cell->store);
    cell->store->writable = writable;
}

static bool cep_l2_clone_child_into(cepCell* parent, const cepCell* child) {
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

static bool cep_l2_copy_request_payload(cepCell* request, cepCell* dst) {
    if (!request || !dst || !cep_cell_has_store(request) || !cep_cell_has_store(dst)) {
        return false;
    }

    cep_l2_clear_children(dst);

    for (cepCell* child = cep_cell_first(request); child; child = cep_cell_next(request, child)) {
        if (cep_cell_name_is(child, dt_outcome())) {
            continue;
        }
        if (!cep_l2_clone_child_into(dst, child)) {
            return false;
        }
    }

    return true;
}

static bool cep_l2_get_cstring(cepCell* request, const cepDT* field, const char** out_text, size_t* out_len) {
    if (!request || !field || !out_text) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(request, field);
    if (!node || !cep_cell_has_data(node)) {
        return false;
    }

    const cepData* data = node->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE) {
        return false;
    }

    const char* text = (const char*)data->value;
    if (!text) {
        return false;
    }

    size_t length = data->size;
    if (!length || text[length - 1u] != '\0') {
        return false;
    }

    *out_text = text;
    if (out_len) {
        *out_len = length - 1u;
    }
    return true;
}

static bool cep_l2_text_to_dt_bytes(const char* text, size_t length, cepDT* out) {
    if (!text || !length || !out) {
        return false;
    }

    if (length > 256u) {
        return false;
    }

    cepID tag = cep_namepool_intern(text, length);
    if (!tag) {
        return false;
    }

    *out = cep_dt_make(cep_l2_domain(), tag);
    return true;
}

static bool cep_l2_set_value_bytes(cepCell* parent, const cepDT* name, const cepDT* type, const void* bytes, size_t size) {
    if (!parent || !name || !type || (!bytes && size)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing && cep_cell_has_data(existing)) {
        const cepData* data = existing->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size == size && (!size || memcmp(data->value, bytes, size) == 0)) {
            return true;
        }

        cepL2DataLock data_lock = {0};
        if (!cep_l2_data_lock(existing, &data_lock)) {
            return false;
        }

        cepCell* updated = cep_cell_update(existing, size, size, (void*)bytes, false);
        cep_l2_data_unlock(&data_lock);
        if (!updated) {
            return false;
        }

        cep_cell_content_hash(existing);
        return true;
    }

    cepDT name_copy = *name;
    cepDT type_copy = *type;
    cepCell* value = cep_dict_add_value(parent, &name_copy, &type_copy, (void*)bytes, size, size);
    if (!value) {
        return false;
    }
    cep_cell_content_hash(value);
    return true;
}

static bool cep_l2_set_string_value(cepCell* parent, const cepDT* name, const char* text) {
    if (!text) {
        text = "";
    }
    return cep_l2_set_value_bytes(parent, name, dt_text(), text, strlen(text) + 1u);
}

static void cep_l2_mark_outcome_error(cepCell* request, const char* code) {
    if (!request) {
        return;
    }
    if (!code) {
        code = "error";
    }
    (void)cep_l2_set_string_value(request, dt_outcome(), code);
}

static void cep_l2_mark_outcome_ok(cepCell* request) {
    (void)cep_l2_set_string_value(request, dt_outcome(), "ok");
}

static cepCell* cep_l2_resolve_request(const cepPath* target_path) {
    if (!target_path) {
        return NULL;
    }
    return cep_cell_find_by_path(cep_root(), target_path);
}

static bool cep_l2_request_guard(cepCell* request, const cepDT* bucket_name) {
    if (!request) {
        return false;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, bucket_name)) {
        return false;
    }

    cepCell* inbox = cep_cell_parent(bucket);
    if (!inbox || !cep_cell_name_is(inbox, dt_inbox())) {
        return false;
    }

    cepCell* flow_root = cep_cell_parent(inbox);
    if (!flow_root || !cep_cell_name_is(flow_root, dt_flow())) {
        return false;
    }

    return true;
}

static bool cep_l2_dt_to_text(const cepDT* dt, char* buffer, size_t cap) {
    if (!dt || !buffer || cap == 0u) {
        return false;
    }

    cepID tag = dt->tag;
    size_t written = 0u;

    if (cep_id_is_word(tag)) {
        written = cep_word_to_text(tag, buffer);
    } else if (cep_id_is_acronym(tag)) {
        written = cep_acronym_to_text(tag, buffer);
    } else if (cep_id_is_reference(tag)) {
        size_t len = 0u;
        const char* text = cep_namepool_lookup(tag, &len);
        if (!text || len + 1u > cap) {
            return false;
        }
        memcpy(buffer, text, len);
        buffer[len] = '\0';
        return true;
    } else {
        return false;
    }

    if (!written || written + 1u > cap) {
        return false;
    }
    buffer[written] = '\0';
    return true;
}

static bool cep_l2_parse_pc(cepCell* instance, size_t* out_pc) {
    if (!instance || !out_pc) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(instance, dt_pc());
    if (!node || !cep_cell_has_data(node)) {
        *out_pc = 0u;
        return true;
    }

    const char* text = (const char*)node->data->value;
    if (!text) {
        *out_pc = 0u;
        return true;
    }

    errno = 0;
    char* endptr = NULL;
    unsigned long long value = strtoull(text, &endptr, 10);
    if (errno != 0 || endptr == text) {
        *out_pc = 0u;
        return false;
    }

    *out_pc = (size_t)value;
    return true;
}

static bool cep_l2_store_pc(cepCell* instance, size_t pc) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%zu", pc);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return cep_l2_set_string_value(instance, dt_pc(), buffer);
}

static cepCell* cep_l2_ensure_subs(cepCell* instance) {
    if (!instance) {
        return NULL;
    }
    return cep_l2_ensure_dictionary(instance, dt_subs(), CEP_STORAGE_RED_BLACK_T);
}

static cepCell* cep_l2_sub_entry_for_pc(cepCell* instance, size_t pc, bool create) {
    cepCell* subs = cep_l2_ensure_subs(instance);
    if (!subs || !cep_cell_has_store(subs)) {
        return NULL;
    }

    char key_buf[32];
    int written = snprintf(key_buf, sizeof key_buf, "%zu", pc);
    if (written <= 0 || (size_t)written >= sizeof key_buf) {
        return NULL;
    }

    cepDT key_dt = {0};
    if (!cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
        return NULL;
    }

    if (!create) {
        return cep_cell_find_by_name(subs, &key_dt);
    }
    return cep_l2_ensure_dictionary(subs, &key_dt, CEP_STORAGE_RED_BLACK_T);
}

static bool cep_l2_sub_entry_set_string(cepCell* entry, const cepDT* field, const char* value) {
    if (!entry) {
        return false;
    }
    return cep_l2_set_string_value(entry, field, value ? value : "");
}

static const char* cep_l2_fetch_string(cepCell* container, const cepDT* field) {
    const char* text = NULL;
    if (!cep_l2_get_cstring(container, field, &text, NULL)) {
        return NULL;
    }
    return text;
}

static bool cep_l2_sub_entry_has_status(cepCell* entry, const char* status) {
    const char* current = cep_l2_fetch_string(entry, dt_status());
    if (!current || !status) {
        return false;
    }
    return strcmp(current, status) == 0;
}

static bool cep_l2_sub_entry_matches_signal(cepCell* entry, const char* signal) {
    if (!signal) {
        return true;
    }
    const char* current = cep_l2_fetch_string(entry, dt_signal_path());
    if (!current) {
        current = cep_l2_fetch_string(entry, dt_signal());
    }
    if (!current) {
        return false;
    }
    return strcmp(current, signal) == 0;
}

static bool cep_l2_fire_event_for_instance(cepCell* instance, const char* signal, cepCell* request) {
    if (!instance) {
        return false;
    }

    cepCell* subs = cep_cell_find_by_name(instance, dt_subs());
    if (!subs || !cep_cell_has_store(subs)) {
        return false;
    }

    bool matched = false;
    for (cepCell* entry = cep_cell_first(subs); entry; entry = cep_cell_next(subs, entry)) {
        if (!cep_l2_sub_entry_matches_signal(entry, signal)) {
            continue;
        }
        matched = true;
        cep_l2_sub_entry_set_string(entry, dt_status(), "triggered");
        if (request) {
            cepCell* payload = cep_l2_ensure_dictionary(entry, dt_payload(), CEP_STORAGE_RED_BLACK_T);
            if (payload) {
                cep_l2_copy_request_payload(request, payload);
            }
        }
    }

    if (matched) {
        cep_l2_set_string_value(instance, dt_state(), "ready");
    }
    return matched;
}

typedef enum {
    CEP_L2_STEP_ADVANCE = 0,
    CEP_L2_STEP_BLOCK,
    CEP_L2_STEP_ERROR
} cepL2StepResult;

static cepL2StepResult cep_l2_step_wait(cepCell* instance, cepCell* step, size_t pc) {
    cepCell* entry = cep_l2_sub_entry_for_pc(instance, pc, true);
    if (!entry) {
        return CEP_L2_STEP_ERROR;
    }

    if (cep_l2_sub_entry_has_status(entry, "triggered")) {
        cepCell* subs = cep_cell_parent(entry);
        if (subs) {
            cep_cell_remove_hard(subs, entry);
        }
        return CEP_L2_STEP_ADVANCE;
    }

    cepCell* spec = cep_l2_step_spec(step);
    const char* signal = spec ? cep_l2_fetch_string(spec, dt_signal_path()) : NULL;
    if (!signal) {
        signal = spec ? cep_l2_fetch_string(spec, dt_signal()) : NULL;
    }
    if (signal) {
        cep_l2_sub_entry_set_string(entry, dt_signal_path(), signal);
    }
    cep_l2_sub_entry_set_string(entry, dt_status(), "pending");
    cep_l2_set_string_value(instance, dt_state(), "waiting");
    return CEP_L2_STEP_BLOCK;
}

static cepL2StepResult cep_l2_step_decide(cepCell* flow_root, cepCell* instance, cepCell* step) {
    cepCell* spec = cep_l2_step_spec(step);
    const char* site = spec ? cep_l2_fetch_string(spec, dt_site()) : NULL;
    const char* choice = spec ? cep_l2_fetch_string(spec, dt_choice()) : NULL;

    cepCell* ledger = cep_l2_decision_ledger(flow_root);
    if (!ledger) {
        return CEP_L2_STEP_ERROR;
    }

    if (!choice || !*choice) {
        choice = "default";
    }

    const cepDT* inst_name = cep_cell_get_name(instance);
    cepCell* node = cep_l2_decision_node(ledger, inst_name, site, true);
    if (!node) {
        return CEP_L2_STEP_ERROR;
    }

    const char* recorded = cep_l2_fetch_string(node, dt_choice());
    if (!recorded) {
        cep_l2_set_string_value(node, dt_choice(), choice);
    }

    return CEP_L2_STEP_ADVANCE;
}

static cepL2StepResult cep_l2_step_clamp(cepCell* instance, cepCell* step) {
    cepCell* spec = cep_l2_step_spec(step);
    const char* new_state = spec ? cep_l2_fetch_string(spec, dt_state()) : NULL;
    if (new_state && *new_state) {
        cep_l2_set_string_value(instance, dt_state(), new_state);
    }
    return CEP_L2_STEP_ADVANCE;
}

static cepCell* cep_l2_program_from_instance(cepCell* flow_root, cepCell* instance) {
    if (!instance) {
        return NULL;
    }

    cepCell* program = cep_cell_find_by_name(instance, dt_program());
    if (program) {
        if (cep_cell_is_link(program)) {
            program = cep_link_pull(program);
        }
        return program;
    }

    cepCell* variant = cep_cell_find_by_name(instance, dt_variant());
    if (variant) {
        if (cep_cell_is_link(variant)) {
            variant = cep_link_pull(variant);
        }
        if (variant && cep_cell_has_store(variant)) {
            cepCell* link = cep_cell_find_by_name(variant, dt_program());
            if (link) {
                if (cep_cell_is_link(link)) {
                    link = cep_link_pull(link);
                }
                if (link) {
                    return link;
                }
            }
        }
    }

    if (!flow_root) {
        flow_root = cep_l2_flow_root();
    }
    if (!flow_root) {
        return NULL;
    }

    cepCell* program_ledger = cep_cell_find_by_name(flow_root, dt_program());
    if (!program_ledger || !cep_cell_has_store(program_ledger)) {
        return NULL;
    }

    const cepDT* instance_name = cep_cell_get_name(instance);
    if (!instance_name) {
        return NULL;
    }

    char name_buf[64];
    if (!cep_l2_dt_to_text(instance_name, name_buf, sizeof name_buf)) {
        return NULL;
    }

    cepCell* variant_ledger = cep_cell_find_by_name(flow_root, dt_variant());
    if (variant_ledger && cep_cell_has_store(variant_ledger)) {
        cepCell* variant_entry = cep_cell_find_by_name(variant_ledger, instance_name);
        if (variant_entry && cep_cell_has_store(variant_entry)) {
            cepCell* link = cep_cell_find_by_name(variant_entry, dt_program());
            if (link) {
                if (cep_cell_is_link(link)) {
                    link = cep_link_pull(link);
                }
                if (link) {
                    return link;
                }
            }
        }
    }

    return cep_cell_find_by_name(program_ledger, instance_name);
}

static cepCell* cep_l2_steps_container(cepCell* program) {
    if (!program) {
        return NULL;
    }
    cepCell* steps = cep_cell_find_by_name(program, dt_steps());
    if (steps && cep_cell_has_store(steps)) {
        return steps;
    }
    return NULL;
}

static cepCell* cep_l2_step_at(cepCell* steps, size_t index) {
    if (!steps || !cep_cell_has_store(steps)) {
        return NULL;
    }

    size_t position = 0u;
    for (cepCell* step = cep_cell_first(steps); step; step = cep_cell_next(steps, step)) {
        if (position == index) {
            return step;
        }
        ++position;
    }
    return NULL;
}

static const char* cep_l2_step_kind(cepCell* step) {
    if (!step) {
        return NULL;
    }
    return cep_l2_fetch_string(step, dt_kind());
}

static cepCell* cep_l2_step_spec(cepCell* step) {
    if (!step) {
        return NULL;
    }
    return cep_cell_find_by_name(step, dt_spec());
}

static cepCell* cep_l2_decision_ledger(cepCell* flow_root) {
    if (!flow_root) {
        flow_root = cep_l2_flow_root();
    }
    return flow_root ? cep_cell_find_by_name(flow_root, dt_decision()) : NULL;
}

static cepCell* cep_l2_decision_node(cepCell* ledger, const cepDT* inst_name, const char* site, bool create) {
    if (!ledger || !inst_name) {
        return NULL;
    }

    cepCell* inst_bucket = cep_cell_find_by_name(ledger, inst_name);
    if (!inst_bucket && create) {
        inst_bucket = cep_l2_ensure_dictionary(ledger, inst_name, CEP_STORAGE_RED_BLACK_T);
    }
    if (!inst_bucket) {
        return NULL;
    }

    char site_buf[64];
    if (!site || !*site) {
        site = "default";
    }
    size_t site_len = strlen(site);
    if (site_len >= sizeof site_buf) {
        site_len = sizeof site_buf - 1u;
    }
    memcpy(site_buf, site, site_len);
    site_buf[site_len] = '\0';

    cepDT site_dt = {0};
    if (!cep_l2_text_to_dt_bytes(site_buf, site_len, &site_dt)) {
        return NULL;
    }

    if (!create) {
        return cep_cell_find_by_name(inst_bucket, &site_dt);
    }

    return cep_l2_ensure_dictionary(inst_bucket, &site_dt, CEP_STORAGE_RED_BLACK_T);
}

/* This helper mirrors the L1 dictionary bootstrap behaviour by creating the
 * requested child when missing while staying idempotent when the node already
 * exists. It keeps bootstrap call sites compact and readable. */
static cepCell* cep_l2_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        return existing;
    }

    cepDT type = *dt_dictionary();
    cepDT copy = *name;
    return cep_dict_add_dictionary(parent, &copy, &type, storage);
}


static bool cep_l2_extract_identifier(cepCell* request, const cepDT* field, cepDT* out_dt, const char** out_text) {
    if (!request || !field || !out_dt) {
        return false;
    }

    const char* text = NULL;
    size_t length = 0u;
    if (!cep_l2_get_cstring(request, field, &text, &length)) {
        return false;
    }

    if (!cep_l2_text_to_dt_bytes(text, length, out_dt)) {
        return false;
    }

    if (out_text) {
        *out_text = text;
    }
    return true;
}

static cepCell* cep_l2_definition_ledger(const char* kind, cepCell* flow_root) {
    if (!kind || !flow_root) {
        return NULL;
    }

    if (strcmp(kind, "program") == 0) {
        return cep_cell_find_by_name(flow_root, dt_program());
    }
    if (strcmp(kind, "policy") == 0) {
        return cep_cell_find_by_name(flow_root, dt_policy());
    }
    if (strcmp(kind, "variant") == 0) {
        return cep_cell_find_by_name(flow_root, dt_variant());
    }
    if (strcmp(kind, "guardian") == 0) {
        return cep_cell_find_by_name(flow_root, dt_guardian());
    }

    return NULL;
}


/* ------------------------------------------------------------------------- */
/*  Bootstrap                                                                */
/* ------------------------------------------------------------------------- */

/* This helper materialises `/data` so subsequent bootstrap steps can create
 * the flow subtree regardless of the order in which higher layers initialise
 * the runtime. */
static cepCell* cep_l2_data_root(void) {
    cepCell* root = cep_root();
    cepCell* data = cep_cell_find_by_name(root, dt_data_root());
    if (!data) {
        data = cep_l2_ensure_dictionary(root, dt_data_root(), CEP_STORAGE_RED_BLACK_T);
    }
    return data;
}

/* This helper creates (or retrieves) `/data/flow`, serving as the anchor for
 * L2 ledgers. */
static cepCell* cep_l2_flow_root(void) {
    cepCell* data = cep_l2_data_root();
    if (!data) {
        return NULL;
    }
    return cep_l2_ensure_dictionary(data, dt_flow(), CEP_STORAGE_RED_BLACK_T);
}

/* This helper creates all durable ledgers that L2 relies on so that ingest and
 * stepper callbacks can assume the directories already exist. */
static bool cep_l2_bootstrap_ledgers(cepCell* flow_root) {
    if (!flow_root) {
        return false;
    }

    if (!cep_l2_ensure_dictionary(flow_root, dt_program(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_policy(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_variant(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_niche(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_guardian(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_instance(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_decision(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_index(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    cepCell* inbox = cep_l2_ensure_dictionary(flow_root, dt_inbox(), CEP_STORAGE_RED_BLACK_T);
    if (!inbox) {
        return false;
    }

    if (!cep_l2_ensure_dictionary(inbox, dt_fl_upsert(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_ni_upsert(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_inst_start(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_inst_event(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_inst_ctrl(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    return true;
}

/* This helper mirrors the L1 pattern for `/tmp`, allowing L2 to host transient
 * caches without polluting durable ledgers. */
static bool cep_l2_bootstrap_tmp(void) {
    cepCell* root = cep_root();
    if (!root) {
        return false;
    }

    cepCell* tmp_root = cep_l2_ensure_dictionary(root, dt_tmp_root(), CEP_STORAGE_RED_BLACK_T);
    if (!tmp_root) {
        return false;
    }

    cepCell* flow_tmp = cep_l2_ensure_dictionary(tmp_root, dt_flow(), CEP_STORAGE_RED_BLACK_T);
    if (!flow_tmp) {
        return false;
    }

    cepCell* adj_root = cep_l2_ensure_dictionary(flow_tmp, dt_adj(), CEP_STORAGE_RED_BLACK_T);
    if (!adj_root) {
        return false;
    }

    /* Additional adjacency buckets will be created on demand by the enzymes. */
    return true;
}

/* This helper coordinates the whole bootstrap sequence so callers can rely on
 * a single public function to prepare the flow layer. */
bool cep_l2_flows_bootstrap(void) {
    if (!cep_cell_system_initialized()) {
        return false;
    }

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return false;
    }

    if (!cep_l2_bootstrap_ledgers(flow_root)) {
        return false;
    }

    if (!cep_l2_bootstrap_tmp()) {
        return false;
    }

    cep_namepool_bootstrap();
    return true;
}

/* ------------------------------------------------------------------------- */
/*  Enzyme callbacks (skeletons)                                             */
/* ------------------------------------------------------------------------- */

/* The ingest enzyme will eventually canonicalise flow definitions. For now we
 * stage a placeholder so the agenda wiring compiles while leaving TODO markers
 * for the substantive work. */
static int cep_l2_enzyme_fl_ingest(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_l2_resolve_request(target);
    if (!cep_l2_request_guard(request, dt_fl_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* kind_text = NULL;
    if (!cep_l2_get_cstring(request, dt_kind(), &kind_text, NULL)) {
        cep_l2_mark_outcome_error(request, "missing-kind");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    cepCell* inbox = bucket ? cep_cell_parent(bucket) : NULL;
    cepCell* flow_root = inbox ? cep_cell_parent(inbox) : NULL;
    cepCell* ledger = cep_l2_definition_ledger(kind_text, flow_root);
    if (!ledger) {
        cep_l2_mark_outcome_error(request, "unknown-kind");
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_l2_extract_identifier(request, dt_id(), &id_dt, NULL)) {
        cep_l2_mark_outcome_error(request, "missing-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepL2StoreLock ledger_lock = (cepL2StoreLock){0};
    cepL2StoreLock entry_lock = (cepL2StoreLock){0};
    int result = CEP_ENZYME_FATAL;

    if (!cep_l2_store_lock(ledger, &ledger_lock)) {
        cep_l2_mark_outcome_error(request, "ledger-lock");
        goto done;
    }

    cepCell* entry = cep_l2_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_l2_store_unlock(&ledger_lock);
    ledger_lock.locked = false;
    if (!entry) {
        cep_l2_mark_outcome_error(request, "upsert-failed");
        goto done;
    }

    if (!cep_l2_store_lock(entry, &entry_lock)) {
        cep_l2_mark_outcome_error(request, "entry-lock");
        goto done;
    }

    if (!cep_l2_copy_request_payload(request, entry)) {
        cep_l2_mark_outcome_error(request, "copy-failed");
        goto done;
    }

    cep_l2_mark_outcome_ok(request);
    result = CEP_ENZYME_SUCCESS;

done:
    cep_l2_store_unlock(&entry_lock);
    cep_l2_store_unlock(&ledger_lock);
    return result;
}

static int cep_l2_enzyme_ni_ingest(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_l2_resolve_request(target);
    if (!cep_l2_request_guard(request, dt_ni_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_l2_extract_identifier(request, dt_id(), &id_dt, NULL)) {
        cep_l2_mark_outcome_error(request, "missing-id");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    cepCell* inbox = bucket ? cep_cell_parent(bucket) : NULL;
    cepCell* flow_root = inbox ? cep_cell_parent(inbox) : NULL;
    cepCell* ledger = flow_root ? cep_cell_find_by_name(flow_root, dt_niche()) : NULL;
    if (!ledger) {
        cep_l2_mark_outcome_error(request, "missing-ledger");
        return CEP_ENZYME_SUCCESS;
    }

    cepL2StoreLock ledger_lock = {0};
    cepL2StoreLock entry_lock = {0};
    int result = CEP_ENZYME_FATAL;

    if (!cep_l2_store_lock(ledger, &ledger_lock)) {
        cep_l2_mark_outcome_error(request, "ledger-lock");
        goto done;
    }

    cepCell* entry = cep_l2_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_l2_store_unlock(&ledger_lock);
    ledger_lock.locked = false;
    if (!entry) {
        cep_l2_mark_outcome_error(request, "upsert-failed");
        goto done;
    }

    if (!cep_l2_store_lock(entry, &entry_lock)) {
        cep_l2_mark_outcome_error(request, "entry-lock");
        goto done;
    }

    if (!cep_l2_copy_request_payload(request, entry)) {
        cep_l2_mark_outcome_error(request, "copy-failed");
        goto done;
    }

    cep_l2_mark_outcome_ok(request);
    result = CEP_ENZYME_SUCCESS;

done:
    cep_l2_store_unlock(&entry_lock);
    cep_l2_store_unlock(&ledger_lock);
    return result;
}

/* Instance ingestion will start and control state machines when the runtime is
 * fully wired; currently it only marks the future work. */
static int cep_l2_enzyme_inst_ingest(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_l2_resolve_request(target);
    if (!request) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket) {
        return CEP_ENZYME_SUCCESS;
    }

    bool is_start = cep_cell_name_is(bucket, dt_inst_start());
    bool is_ctrl = cep_cell_name_is(bucket, dt_inst_ctrl());
    if (!is_start && !is_ctrl) {
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (is_start) {
        if (!cep_l2_extract_identifier(request, dt_id(), &id_dt, NULL)) {
            cep_l2_mark_outcome_error(request, "missing-id");
            return CEP_ENZYME_SUCCESS;
        }
    } else {
        if (!cep_l2_extract_identifier(request, dt_inst_id(), &id_dt, NULL)
            && !cep_l2_extract_identifier(request, dt_id(), &id_dt, NULL)) {
            cep_l2_mark_outcome_error(request, "missing-id");
            return CEP_ENZYME_SUCCESS;
        }
    }

    cepCell* inbox = cep_cell_parent(bucket);
    cepCell* flow_root = inbox ? cep_cell_parent(inbox) : NULL;
    cepCell* ledger = flow_root ? cep_cell_find_by_name(flow_root, dt_instance()) : NULL;
    if (!ledger) {
        cep_l2_mark_outcome_error(request, "missing-ledger");
        return CEP_ENZYME_SUCCESS;
    }

    cepL2StoreLock ledger_lock = {0};
    cepL2StoreLock entry_lock = {0};
    int result = CEP_ENZYME_FATAL;

    if (!cep_l2_store_lock(ledger, &ledger_lock)) {
        cep_l2_mark_outcome_error(request, "ledger-lock");
        goto done;
    }

    cepCell* entry = cep_l2_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_l2_store_unlock(&ledger_lock);
    ledger_lock.locked = false;
    if (!entry) {
        cep_l2_mark_outcome_error(request, "upsert-failed");
        goto done;
    }

    if (!cep_l2_store_lock(entry, &entry_lock)) {
        cep_l2_mark_outcome_error(request, "entry-lock");
        goto done;
    }

    if (is_start) {
        if (!cep_l2_copy_request_payload(request, entry)) {
            cep_l2_mark_outcome_error(request, "copy-failed");
            goto done;
        }

        if (!cep_l2_set_string_value(entry, dt_state(), "ready")) {
            cep_l2_mark_outcome_error(request, "state");
            goto done;
        }

        char pc_buf[32];
        (void)snprintf(pc_buf, sizeof pc_buf, "%u", 0u);
        if (!cep_l2_set_string_value(entry, dt_pc(), pc_buf)) {
            cep_l2_mark_outcome_error(request, "pc");
            goto done;
        }

        cepCell* events = cep_cell_find_by_name(entry, dt_events());
        if (!events) {
            cepDT dict_type = *dt_dictionary();
            cepDT name_copy = *dt_events();
            events = cep_cell_add_dictionary(entry, &name_copy, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
            if (!events) {
                cep_l2_mark_outcome_error(request, "events");
                goto done;
            }
        }

        cep_l2_mark_outcome_ok(request);
        result = CEP_ENZYME_SUCCESS;
        goto done;
    }

    /* Control action */
    const char* action = NULL;
    if (!cep_l2_get_cstring(request, dt_action(), &action, NULL)) {
        cep_l2_mark_outcome_error(request, "missing-action");
        goto done;
    }

    if (strcmp(action, "pause") == 0) {
        if (!cep_l2_set_string_value(entry, dt_state(), "paused")) {
            cep_l2_mark_outcome_error(request, "state");
            goto done;
        }
    } else if (strcmp(action, "cancel") == 0) {
        if (!cep_l2_set_string_value(entry, dt_state(), "done")) {
            cep_l2_mark_outcome_error(request, "state");
            goto done;
        }
    } else if (strcmp(action, "resume") == 0) {
        if (!cep_l2_set_string_value(entry, dt_state(), "ready")) {
            cep_l2_mark_outcome_error(request, "state");
            goto done;
        }
    } else if (strcmp(action, "budget") == 0) {
        /* Record control intent under `original` for later reconciliation. */
        cepCell* original = cep_l2_ensure_dictionary(entry, dt_original(), CEP_STORAGE_RED_BLACK_T);
        cepL2StoreLock original_lock = {0};
        if (original && cep_l2_store_lock(original, &original_lock)) {
            (void)cep_l2_copy_request_payload(request, original);
        }
        cep_l2_store_unlock(&original_lock);
    } else {
        cep_l2_mark_outcome_error(request, "unknown-action");
        goto done;
    }

    cep_l2_mark_outcome_ok(request);
    result = CEP_ENZYME_SUCCESS;

done:
    cep_l2_store_unlock(&entry_lock);
    cep_l2_store_unlock(&ledger_lock);
    return result;
}

/* Event wakeups will later match subscriptions. */
static int cep_l2_enzyme_fl_wake(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_l2_resolve_request(target);
    if (!cep_l2_request_guard(request, dt_inst_event())) {
        return CEP_ENZYME_SUCCESS;
    }

    const char* signal_text = NULL;
    (void)cep_l2_get_cstring(request, dt_signal_path(), &signal_text, NULL);
    if (!signal_text) {
        (void)cep_l2_get_cstring(request, dt_signal(), &signal_text, NULL);
    }

    cepDT id_dt = {0};
    bool targeted = cep_l2_extract_identifier(request, dt_inst_id(), &id_dt, NULL)
                 || cep_l2_extract_identifier(request, dt_id(), &id_dt, NULL);

    cepCell* bucket = cep_cell_parent(request);
    cepCell* inbox = bucket ? cep_cell_parent(bucket) : NULL;
    cepCell* flow_root = inbox ? cep_cell_parent(inbox) : NULL;
    cepCell* ledger = flow_root ? cep_cell_find_by_name(flow_root, dt_instance()) : NULL;
    if (!ledger || !cep_cell_has_store(ledger)) {
        cep_l2_mark_outcome_error(request, "missing-ledger");
        return CEP_ENZYME_SUCCESS;
    }

    bool matched = false;

    if (targeted) {
        cepCell* entry = cep_cell_find_by_name(ledger, &id_dt);
        if (!entry) {
            cep_l2_mark_outcome_error(request, "unknown-instance");
            return CEP_ENZYME_SUCCESS;
        }
        matched = cep_l2_fire_event_for_instance(entry, signal_text, request);
    } else {
        for (cepCell* entry = cep_cell_first(ledger); entry; entry = cep_cell_next(ledger, entry)) {
            if (cep_l2_fire_event_for_instance(entry, signal_text, request)) {
                matched = true;
            }
        }
    }

    if (!matched) {
        cep_l2_mark_outcome_error(request, "no-match");
        return CEP_ENZYME_SUCCESS;
    }

    cep_l2_mark_outcome_ok(request);
    return CEP_ENZYME_SUCCESS;
}

static int cep_l2_enzyme_fl_step(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* ledger = cep_cell_find_by_name(flow_root, dt_instance());
    if (!ledger || !cep_cell_has_store(ledger)) {
        return CEP_ENZYME_SUCCESS;
    }

    for (cepCell* instance = cep_cell_first(ledger); instance; instance = cep_cell_next(ledger, instance)) {
        if (!cep_cell_is_normal(instance)) {
            continue;
        }

        cepL2StoreLock inst_lock = {0};
        if (!cep_l2_store_lock(instance, &inst_lock)) {
            continue;
        }

        const char* state = cep_l2_fetch_string(instance, dt_state());

        size_t pc = 0u;
        if (!cep_l2_parse_pc(instance, &pc)) {
            pc = 0u;
        }

        if (state && strcmp(state, "done") == 0) {
            cep_l2_store_unlock(&inst_lock);
            continue;
        }

        if (state && strcmp(state, "waiting") == 0) {
            cepCell* entry = cep_l2_sub_entry_for_pc(instance, pc, false);
            if (!entry || !cep_l2_sub_entry_has_status(entry, "triggered")) {
                cep_l2_store_unlock(&inst_lock);
                continue;
            }
            cep_l2_set_string_value(instance, dt_state(), "ready");
        } else if (state && strcmp(state, "paused") == 0) {
            cep_l2_store_unlock(&inst_lock);
            continue;
        } else if (state && strcmp(state, "error") == 0) {
            cep_l2_store_unlock(&inst_lock);
            continue;
        }

        size_t iterations = 0u;
        bool continue_run = true;
        while (continue_run && iterations++ < 64u) {
            cepCell* program = cep_l2_program_from_instance(flow_root, instance);
            if (!program) {
                program = instance;
            }
            cepCell* steps = cep_l2_steps_container(program);
            if (!steps) {
                cep_l2_set_string_value(instance, dt_state(), "done");
                break;
            }

            cepCell* step = cep_l2_step_at(steps, pc);
            if (!step) {
                cep_l2_set_string_value(instance, dt_state(), "done");
                break;
            }

            const char* kind = cep_l2_step_kind(step);
            cepL2StepResult outcome = CEP_L2_STEP_ADVANCE;

            if (kind && strcmp(kind, "wait") == 0) {
                outcome = cep_l2_step_wait(instance, step, pc);
            } else if (kind && strcmp(kind, "decide") == 0) {
                outcome = cep_l2_step_decide(flow_root, instance, step);
            } else if (kind && strcmp(kind, "clamp") == 0) {
                outcome = cep_l2_step_clamp(instance, step);
            } else {
                outcome = CEP_L2_STEP_ADVANCE;
            }

            if (outcome == CEP_L2_STEP_ERROR) {
                cep_l2_set_string_value(instance, dt_state(), "error");
                break;
            }

            if (outcome == CEP_L2_STEP_BLOCK) {
                continue_run = false;
                break;
            }

            ++pc;
        }

        cep_l2_store_pc(instance, pc);
        const char* final_state = cep_l2_fetch_string(instance, dt_state());
        if (!final_state) {
            cep_l2_set_string_value(instance, dt_state(), "ready");
        }

        cep_l2_store_unlock(&inst_lock);
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_l2_enzyme_fl_index(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement durable index maintenance for Layer 2.
    return CEP_ENZYME_SUCCESS;
}

/* Transient cache refresh mirrors the index pattern for `/tmp/flow/adj`. */
static int cep_l2_enzyme_fl_adj(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement cache refresh for transient adjacency structures.
    return CEP_ENZYME_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/*  Registration                                                             */
/* ------------------------------------------------------------------------- */

/* This helper binds all L2 enzyme identifiers onto the `/data/flow` subtree so
 * resolve scoring favours the intended handlers when multiple candidates
 * compete. */
static bool cep_l2_apply_bindings(void) {
    if (cep_l2_bindings_applied) {
        return true;
    }

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return false;
    }

    (void)cep_cell_bind_enzyme(flow_root, dt_fl_ing(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_ni_ing(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_inst_ing(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_wake(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_step(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_index(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_adj(), true);

    cep_l2_bindings_applied = true;
    return true;
}

/* This helper stages the seven descriptors on the registry, wiring before/after
 * dependencies to mirror the agenda detailed in L2.md. */
bool cep_l2_flows_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (!cep_l2_flows_bootstrap()) {
        return false;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepPathStatic2;

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_signal_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    cepDT after_ni[] = { *dt_fl_ing() };
    cepDT after_inst[] = { *dt_ni_ing() };
    cepDT after_wake[] = { *dt_inst_ing() };
    cepDT after_step[] = { *dt_fl_wake() };
    cepDT after_index[] = { *dt_fl_step() };
    cepDT after_adj[] = { *dt_fl_index() };

    cepEnzymeDescriptor descriptors[] = {
        {
            .name = *dt_fl_ing(),
            .label = "l2.fl.ingest",
            .callback = cep_l2_enzyme_fl_ingest,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_ni_ing(),
            .label = "l2.ni.ingest",
            .callback = cep_l2_enzyme_ni_ingest,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_ni,
            .after_count = sizeof after_ni / sizeof after_ni[0],
        },
        {
            .name = *dt_inst_ing(),
            .label = "l2.inst.ingest",
            .callback = cep_l2_enzyme_inst_ingest,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_inst,
            .after_count = sizeof after_inst / sizeof after_inst[0],
        },
        {
            .name = *dt_fl_wake(),
            .label = "l2.fl.wake",
            .callback = cep_l2_enzyme_fl_wake,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_wake,
            .after_count = sizeof after_wake / sizeof after_wake[0],
        },
        {
            .name = *dt_fl_step(),
            .label = "l2.fl.step",
            .callback = cep_l2_enzyme_fl_step,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_step,
            .after_count = sizeof after_step / sizeof after_step[0],
        },
        {
            .name = *dt_fl_index(),
            .label = "l2.fl.index",
            .callback = cep_l2_enzyme_fl_index,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_index,
            .after_count = sizeof after_index / sizeof after_index[0],
        },
        {
            .name = *dt_fl_adj(),
            .label = "l2.fl.adj",
            .callback = cep_l2_enzyme_fl_adj,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_adj,
            .after_count = sizeof after_adj / sizeof after_adj[0],
        },
    };

    for (size_t i = 0; i < sizeof descriptors / sizeof descriptors[0]; ++i) {
        if (cep_enzyme_register(registry, (const cepPath*)&signal_path, &descriptors[i]) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    if (!cep_l2_apply_bindings()) {
        return false;
    }

    return true;
}
