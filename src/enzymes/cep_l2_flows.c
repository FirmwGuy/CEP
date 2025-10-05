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
static const cepDT* dt_ctx_type(void)    { return CEP_DTAW("CEP", "ctx_type"); }
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
static const cepDT* dt_target(void)      { return CEP_DTAW("CEP", "target"); }
static const cepDT* dt_choice(void)      { return CEP_DTAW("CEP", "choice"); }
static const cepDT* dt_text(void)        { return CEP_DTAW("CEP", "text"); }
static const cepDT* dt_outcome(void)     { return CEP_DTAW("CEP", "outcome"); }
static const cepDT* dt_original(void)    { return CEP_DTAW("CEP", "original"); }
static const cepDT* dt_id(void)          { return CEP_DTAW("CEP", "id"); }
static const cepDT* dt_kind(void)        { return CEP_DTAW("CEP", "kind"); }
static const cepDT* dt_state(void)       { return CEP_DTAW("CEP", "state"); }
static const cepDT* dt_pc(void)          { return CEP_DTAW("CEP", "pc"); }
static const cepDT* dt_events(void)      { return CEP_DTAW("CEP", "events"); }
static const cepDT* dt_emits(void)       { return CEP_DTAW("CEP", "emits"); }
static const cepDT* dt_action(void)      { return CEP_DTAW("CEP", "action"); }
static const cepDT* dt_inst_id(void)     { return CEP_DTAW("CEP", "inst_id"); }
static const cepDT* dt_site(void)        { return CEP_DTAW("CEP", "site"); }
static const cepDT* dt_inst_by_var(void) { return CEP_DTAW("CEP", "inst_by_var"); }
static const cepDT* dt_inst_by_st(void)  { return CEP_DTAW("CEP", "inst_by_st"); }
static const cepDT* dt_dec_by_pol(void)  { return CEP_DTAW("CEP", "dec_by_pol"); }
static const cepDT* dt_by_inst(void)     { return CEP_DTAW("CEP", "by_inst"); }
static const cepDT* dt_sub_count(void)   { return CEP_DTAW("CEP", "sub_count"); }
static const cepDT* dt_evt_count(void)   { return CEP_DTAW("CEP", "evt_count"); }
static const cepDT* dt_emit_count(void)  { return CEP_DTAW("CEP", "emit_count"); }
static const cepDT* dt_timeout(void)     { return CEP_DTAW("CEP", "timeout"); }
static const cepDT* dt_deadline(void)    { return CEP_DTAW("CEP", "deadline"); }
static const cepDT* dt_signal_glob(void) { return CEP_DTAW("CEP", "signal_glob"); }
static const cepDT* dt_beat(void)        { return CEP_DTAW("CEP", "beat"); }
static const cepDT* dt_origin(void)      { return CEP_DTAW("CEP", "origin"); }
static const cepDT* dt_context(void)     { return CEP_DTAW("CEP", "context"); }
static const cepDT* dt_budget(void)      { return CEP_DTAW("CEP", "budget"); }
static const cepDT* dt_step_limit(void)  { return CEP_DTAW("CEP", "step_limit"); }
static const cepDT* dt_steps_used(void)  { return CEP_DTAW("CEP", "steps_used"); }

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
static bool     cep_l2_wait_entry_set_deadline(cepCell* entry, size_t timeout_beats);
static bool     cep_l2_wait_entry_timed_out(cepCell* entry);
static bool     cep_l2_dt_to_text(const cepDT* dt, char* buffer, size_t cap);
static bool     cep_l2_instance_variant_dt(cepCell* instance, cepDT* out_dt);
static bool     cep_l2_extract_cell_identifier(cepCell* container, const cepDT* field, cepDT* out_dt, const char** out_text);
static const char* cep_l2_fetch_string(cepCell* container, const cepDT* field);
static bool     cep_l2_extract_identifier(cepCell* request, const cepDT* field, cepDT* out_dt, const char** out_text);

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

static bool cep_l2_dt_equal(const cepDT* a, const cepDT* b) {
    if (!a || !b) {
        return false;
    }
    return a->domain == b->domain && a->tag == b->tag;
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

typedef struct {
    cepCell*      budget;
    size_t        limit;
    size_t        used_prior;
    cepBeatNumber beat;
    bool          initialized;
} cepL2BudgetState;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[2];
} cepPathStatic2;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[4];
} cepPathStatic4;

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

static bool cep_l2_store_dt_string(cepCell* parent, const cepDT* name, const cepDT* value) {
    if (!parent || !name || !value) {
        return false;
    }

    char buffer[128];
    if (!cep_l2_dt_to_text(value, buffer, sizeof buffer)) {
        return false;
    }

    return cep_l2_set_string_value(parent, name, buffer);
}

static bool cep_l2_parse_size_text(const char* text, size_t* out_value) {
    if (!text || !out_value) {
        return false;
    }

    errno = 0;
    char* endptr = NULL;
    unsigned long long value = strtoull(text, &endptr, 10);
    if (errno != 0 || endptr == text) {
        return false;
    }

    *out_value = (size_t)value;
    return true;
}

static void cep_l2_remove_field(cepCell* parent, const cepDT* field) {
    if (!parent || !field || !cep_cell_has_store(parent)) {
        return;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    if (child) {
        cep_cell_remove_hard(parent, child);
    }
}

static bool cep_l2_set_number_value(cepCell* parent, const cepDT* name, size_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%zu", value);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return cep_l2_set_value_bytes(parent, name, dt_text(), buffer, (size_t)written + 1u);
}

static bool cep_l2_enqueue_pipeline(void) {
    cepPathStatic2 signal_path = {0};
    signal_path.capacity = 2u;
    signal_path.length = 2u;
    signal_path.past[0].dt = *dt_signal_cell();
    signal_path.past[1].dt = *dt_op_add();

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return false;
    }

    cepPath* target_path = NULL;
    if (!cep_cell_path(flow_root, &target_path)) {
        return false;
    }

    int rc = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, (const cepPath*)&signal_path, target_path);
    cep_free(target_path);
    return rc != CEP_ENZYME_FATAL;
}

typedef enum {
    CEP_L2_DEF_UNKNOWN = 0,
    CEP_L2_DEF_PROGRAM,
    CEP_L2_DEF_POLICY,
    CEP_L2_DEF_VARIANT,
    CEP_L2_DEF_GUARDIAN,
} cepL2DefinitionKind;

typedef enum {
    CEP_L2_STEP_UNKNOWN = 0,
    CEP_L2_STEP_GUARD,
    CEP_L2_STEP_XFORM,
    CEP_L2_STEP_WAIT,
    CEP_L2_STEP_DECIDE,
    CEP_L2_STEP_CLAMP,
} cepL2StepKind;

static cepL2DefinitionKind cep_l2_definition_kind_from_text(const char* text) {
    if (!text) {
        return CEP_L2_DEF_UNKNOWN;
    }

    char lowered[16];
    size_t idx = 0u;
    for (; text[idx] && idx + 1u < sizeof lowered; ++idx) {
        lowered[idx] = (char)tolower((unsigned char)text[idx]);
    }
    if (text[idx] != '\0') {
        return CEP_L2_DEF_UNKNOWN;
    }
    lowered[idx] = '\0';

    if (strcmp(lowered, "program") == 0) {
        return CEP_L2_DEF_PROGRAM;
    }
    if (strcmp(lowered, "policy") == 0) {
        return CEP_L2_DEF_POLICY;
    }
    if (strcmp(lowered, "variant") == 0) {
        return CEP_L2_DEF_VARIANT;
    }
    if (strcmp(lowered, "guardian") == 0) {
        return CEP_L2_DEF_GUARDIAN;
    }

    return CEP_L2_DEF_UNKNOWN;
}

static const char* cep_l2_definition_kind_text(cepL2DefinitionKind kind) {
    switch (kind) {
    case CEP_L2_DEF_PROGRAM:  return "program";
    case CEP_L2_DEF_POLICY:   return "policy";
    case CEP_L2_DEF_VARIANT:  return "variant";
    case CEP_L2_DEF_GUARDIAN: return "guardian";
    default:                  return NULL;
    }
}

static cepL2StepKind cep_l2_step_kind_from_text(const char* text, const char** out_canonical) {
    if (out_canonical) {
        *out_canonical = NULL;
    }
    if (!text) {
        return CEP_L2_STEP_UNKNOWN;
    }

    char lowered[16];
    size_t idx = 0u;
    for (; text[idx] && idx + 1u < sizeof lowered; ++idx) {
        lowered[idx] = (char)tolower((unsigned char)text[idx]);
    }
    if (text[idx] != '\0') {
        return CEP_L2_STEP_UNKNOWN;
    }
    lowered[idx] = '\0';

    if (strcmp(lowered, "guard") == 0) {
        if (out_canonical) {
            *out_canonical = "guard";
        }
        return CEP_L2_STEP_GUARD;
    }
    if (strcmp(lowered, "xform") == 0 || strcmp(lowered, "transform") == 0) {
        if (out_canonical) {
            *out_canonical = "xform";
        }
        return CEP_L2_STEP_XFORM;
    }
    if (strcmp(lowered, "wait") == 0) {
        if (out_canonical) {
            *out_canonical = "wait";
        }
        return CEP_L2_STEP_WAIT;
    }
    if (strcmp(lowered, "decide") == 0) {
        if (out_canonical) {
            *out_canonical = "decide";
        }
        return CEP_L2_STEP_DECIDE;
    }
    if (strcmp(lowered, "clamp") == 0) {
        if (out_canonical) {
            *out_canonical = "clamp";
        }
        return CEP_L2_STEP_CLAMP;
    }

    return CEP_L2_STEP_UNKNOWN;
}

static bool cep_l2_copy_original_payload(cepCell* entry, cepCell* request) {
    if (!entry || !request) {
        return true;
    }

    cepCell* original = cep_l2_ensure_dictionary(entry, dt_original(), CEP_STORAGE_RED_BLACK_T);
    if (!original) {
        return false;
    }

    return cep_l2_copy_request_payload(request, original);
}

static bool cep_l2_store_identifier_text(cepCell* entry, const cepDT* field, const cepDT* value_dt) {
    if (!entry || !field || !value_dt) {
        return false;
    }
    return cep_l2_store_dt_string(entry, field, value_dt);
}

static bool cep_l2_replace_with_link_or_text(cepCell* container,
                                             const cepDT* field,
                                             cepCell* target,
                                             const cepDT* fallback_dt) {
    if (!container || !field) {
        return false;
    }

    cep_l2_remove_field(container, field);

    if (target) {
        cepDT name_copy = *field;
        if (!cep_cell_add_link(container, &name_copy, 0, target)) {
            return false;
        }
        return true;
    }

    if (!fallback_dt) {
        return false;
    }
    return cep_l2_store_identifier_text(container, field, fallback_dt);
}

static bool cep_l2_canonicalize_decide_spec(cepCell* flow_root, cepCell* spec, const char** error_code) {
    if (!spec) {
        if (error_code) {
            *error_code = "decide-spec";
        }
        return false;
    }

    cepDT policy_dt = {0};
    const char* policy_text = NULL;
    if (!cep_l2_extract_cell_identifier(spec, dt_policy(), &policy_dt, &policy_text)) {
        if (error_code) {
            *error_code = "decide-policy";
        }
        return false;
    }

    cepCell* policy_ledger = flow_root ? cep_cell_find_by_name(flow_root, dt_policy()) : NULL;
    cepCell* policy_entry = policy_ledger ? cep_cell_find_by_name(policy_ledger, &policy_dt) : NULL;

    if (!cep_l2_replace_with_link_or_text(spec, dt_policy(), policy_entry, &policy_dt)) {
        if (error_code) {
            *error_code = "decide-policy-link";
        }
        return false;
    }

    return true;
}

static bool cep_l2_canonicalize_step(cepCell* flow_root,
                                     cepCell* request_step,
                                     cepCell* dest_parent,
                                     size_t index,
                                     const char** error_code) {
    if (!request_step || !dest_parent) {
        if (error_code) {
            *error_code = "step-input";
        }
        return false;
    }

    if (!cep_cell_has_store(request_step)) {
        if (error_code) {
            *error_code = "step-schema";
        }
        return false;
    }

    char key_buf[16];
    int written = snprintf(key_buf, sizeof key_buf, "%04zu", index);
    if (written <= 0 || (size_t)written >= sizeof key_buf) {
        if (error_code) {
            *error_code = "step-key";
        }
        return false;
    }

    cepDT key_dt = {0};
    if (!cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
        if (error_code) {
            *error_code = "step-key";
        }
        return false;
    }

    cepDT dict_type = *dt_dictionary();
    cepCell* step_entry = cep_cell_add_dictionary(dest_parent, &key_dt, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!step_entry) {
        if (error_code) {
            *error_code = "step-entry";
        }
        return false;
    }

    const char* raw_kind = cep_l2_fetch_string(request_step, dt_kind());
    const char* canonical_kind = NULL;
    cepL2StepKind kind = cep_l2_step_kind_from_text(raw_kind, &canonical_kind);
    if (kind == CEP_L2_STEP_UNKNOWN || !canonical_kind) {
        if (error_code) {
            *error_code = "step-kind";
        }
        return false;
    }

    if (!cep_l2_set_string_value(step_entry, dt_kind(), canonical_kind)) {
        if (error_code) {
            *error_code = "step-kind";
        }
        return false;
    }

    cepCell* spec_entry = NULL;
    cepCell* raw_spec = cep_cell_find_by_name(request_step, dt_spec());
    cep_l2_remove_field(step_entry, dt_spec());

    cepDT spec_name = *dt_spec();
    spec_entry = cep_cell_add_dictionary(step_entry, &spec_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!spec_entry) {
        if (error_code) {
            *error_code = "step-spec";
        }
        return false;
    }

    if (raw_spec) {
        if (!cep_cell_has_store(raw_spec)) {
            if (error_code) {
                *error_code = "step-spec";
            }
            return false;
        }
        if (!cep_l2_copy_request_payload(raw_spec, spec_entry)) {
            if (error_code) {
                *error_code = "step-spec";
            }
            return false;
        }
    }

    for (cepCell* child = cep_cell_first(request_step); child; child = cep_cell_next(request_step, child)) {
        if (cep_cell_name_is(child, dt_kind()) || cep_cell_name_is(child, dt_spec())) {
            continue;
        }
        if (!cep_l2_clone_child_into(step_entry, child)) {
            if (error_code) {
                *error_code = "step-copy";
            }
            return false;
        }
    }

    if (kind == CEP_L2_STEP_DECIDE) {
        if (!cep_l2_canonicalize_decide_spec(flow_root, spec_entry, error_code)) {
            return false;
        }
    }

    (void)kind; /* Other kinds do not require canonicalisation yet. */
    return true;
}

static bool cep_l2_canonicalize_program(cepCell* flow_root,
                                        cepCell* entry,
                                        cepCell* request,
                                        const cepDT* id_dt,
                                        const char** error_code) {
    if (!entry || !id_dt) {
        if (error_code) {
            *error_code = "program-entry";
        }
        return false;
    }

    if (!cep_l2_store_identifier_text(entry, dt_id(), id_dt)) {
        if (error_code) {
            *error_code = "program-id";
        }
        return false;
    }

    cepCell* existing_steps = cep_cell_find_by_name(entry, dt_steps());
    if (existing_steps) {
        cep_cell_remove_hard(entry, existing_steps);
    }

    cepDT dict_type = *dt_dictionary();
    cepDT steps_name = *dt_steps();
    cepCell* dest_steps = cep_cell_add_dictionary(entry, &steps_name, 0, &dict_type, CEP_STORAGE_LINKED_LIST);
    if (!dest_steps) {
        if (error_code) {
            *error_code = "program-steps";
        }
        return false;
    }

    cepCell* source_steps = request ? cep_cell_find_by_name(request, dt_steps()) : NULL;
    size_t step_index = 0u;
    if (source_steps && cep_cell_has_store(source_steps)) {
        for (cepCell* raw_step = cep_cell_first(source_steps); raw_step; raw_step = cep_cell_next(source_steps, raw_step)) {
            if (!cep_l2_canonicalize_step(flow_root, raw_step, dest_steps, step_index, error_code)) {
                return false;
            }
            ++step_index;
        }
    }

    return true;
}

static bool cep_l2_canonicalize_policy(cepCell* entry, const cepDT* id_dt) {
    if (!entry || !id_dt) {
        return false;
    }
    return cep_l2_store_identifier_text(entry, dt_id(), id_dt);
}

static bool cep_l2_canonicalize_variant(cepCell* flow_root,
                                        cepCell* entry,
                                        cepCell* request,
                                        const cepDT* id_dt,
                                        const char** error_code) {
    if (!entry || !id_dt) {
        if (error_code) {
            *error_code = "variant-entry";
        }
        return false;
    }

    if (!cep_l2_store_identifier_text(entry, dt_id(), id_dt)) {
        if (error_code) {
            *error_code = "variant-id";
        }
        return false;
    }

    cepDT program_dt = {0};
    const char* program_text = NULL;
    bool have_program = cep_l2_extract_identifier(request, dt_program(), &program_dt, &program_text)
                     || cep_l2_extract_cell_identifier(entry, dt_program(), &program_dt, &program_text);
    if (!have_program) {
        if (error_code) {
            *error_code = "variant-program";
        }
        return false;
    }

    cepCell* program_ledger = flow_root ? cep_cell_find_by_name(flow_root, dt_program()) : NULL;
    cepCell* program_entry = program_ledger ? cep_cell_find_by_name(program_ledger, &program_dt) : NULL;

    if (!cep_l2_replace_with_link_or_text(entry, dt_program(), program_entry, &program_dt)) {
        if (error_code) {
            *error_code = "variant-program-link";
        }
        return false;
    }

    return true;
}

static bool cep_l2_canonicalize_guardian(cepCell* entry, const cepDT* id_dt) {
    if (!entry || !id_dt) {
        return false;
    }
    return cep_l2_store_identifier_text(entry, dt_id(), id_dt);
}

static bool cep_l2_canonicalize_niche(cepCell* flow_root,
                                      cepCell* entry,
                                      cepCell* request,
                                      const cepDT* id_dt,
                                      const char** error_code) {
    if (!entry || !id_dt) {
        if (error_code) {
            *error_code = "niche-entry";
        }
        return false;
    }

    if (!cep_l2_store_identifier_text(entry, dt_id(), id_dt)) {
        if (error_code) {
            *error_code = "niche-id";
        }
        return false;
    }

    cepDT ctx_dt = {0};
    if (!cep_l2_extract_identifier(request, dt_ctx_type(), &ctx_dt, NULL)) {
        if (error_code) {
            *error_code = "niche-context";
        }
        return false;
    }

    if (!cep_l2_store_identifier_text(entry, dt_ctx_type(), &ctx_dt)) {
        if (error_code) {
            *error_code = "niche-context";
        }
        return false;
    }

    cepDT variant_dt = {0};
    const char* variant_text = NULL;
    if (!cep_l2_extract_identifier(request, dt_variant(), &variant_dt, &variant_text)) {
        if (error_code) {
            *error_code = "niche-variant";
        }
        return false;
    }

    cepCell* variant_ledger = flow_root ? cep_cell_find_by_name(flow_root, dt_variant()) : NULL;
    cepCell* variant_entry = variant_ledger ? cep_cell_find_by_name(variant_ledger, &variant_dt) : NULL;

    if (!cep_l2_replace_with_link_or_text(entry, dt_variant(), variant_entry, &variant_dt)) {
        if (error_code) {
            *error_code = "niche-variant-link";
        }
        return false;
    }

    (void)variant_text;
    return true;
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

static bool cep_l2_context_node_signature(cepCell* node, char* buffer, size_t cap) {
    if (!node || !buffer || cap == 0u) {
        return false;
    }

    if (cep_cell_is_link(node)) {
        cepCell* target = cep_link_pull(node);
        const cepDT* name = target ? cep_cell_get_name(target) : NULL;
        if (!name) {
            return false;
        }
        return cep_l2_dt_to_text(name, buffer, cap);
    }

    if (cep_cell_has_data(node)) {
        const cepData* data = node->data;
        if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
            return false;
        }
        const char* text = (const char*)data->value;
        if (!text || text[data->size - 1u] != '\0' || data->size > cap) {
            return false;
        }
        memcpy(buffer, text, data->size);
        return true;
    }

    if (cep_cell_has_store(node)) {
        cepDT id_dt = {0};
        if (cep_l2_extract_identifier(node, dt_id(), &id_dt, NULL)) {
            return cep_l2_dt_to_text(&id_dt, buffer, cap);
        }
    }

    return false;
}

static bool cep_l2_extract_context_signature(cepCell* container, char* buffer, size_t cap) {
    if (!container) {
        return false;
    }
    cepCell* context = cep_cell_find_by_name(container, dt_context());
    if (!context) {
        return false;
    }
    return cep_l2_context_node_signature(context, buffer, cap);
}

static void cep_l2_store_wait_context(cepCell* entry, cepCell* instance) {
    if (!entry) {
        return;
    }

    char signature[128];
    if (cep_l2_extract_context_signature(instance, signature, sizeof signature)) {
        cep_l2_set_string_value(entry, dt_context(), signature);
    } else {
        cep_l2_remove_field(entry, dt_context());
    }
}

static bool cep_l2_budget_state_prepare(cepCell* instance, cepCell* spec, cepBeatNumber now, cepL2BudgetState* state) {
    if (!instance || !state) {
        return false;
    }

    cepCell* budget = cep_l2_ensure_dictionary(instance, dt_budget(), CEP_STORAGE_RED_BLACK_T);
    if (!budget) {
        return false;
    }

    size_t limit = 64u;
    bool limit_from_spec = false;

    if (spec) {
        const char* spec_limit = cep_l2_fetch_string(spec, dt_step_limit());
        size_t parsed = 0u;
        if (spec_limit && cep_l2_parse_size_text(spec_limit, &parsed) && parsed > 0u) {
            limit = parsed;
            limit_from_spec = true;
        }
    }

    if (!limit_from_spec) {
        const char* stored_limit = cep_l2_fetch_string(budget, dt_step_limit());
        size_t parsed = 0u;
        if (stored_limit && cep_l2_parse_size_text(stored_limit, &parsed) && parsed > 0u) {
            limit = parsed;
        }
    }

    if (limit == 0u) {
        limit = 1u;
    }

    const char* beat_text = cep_l2_fetch_string(budget, dt_beat());
    cepBeatNumber recorded = 0u;
    if (beat_text) {
        size_t parsed = 0u;
        if (cep_l2_parse_size_text(beat_text, &parsed)) {
            recorded = (cepBeatNumber)parsed;
        }
    }

    size_t used = 0u;
    if (recorded == now) {
        const char* used_text = cep_l2_fetch_string(budget, dt_steps_used());
        size_t parsed = 0u;
        if (used_text && cep_l2_parse_size_text(used_text, &parsed)) {
            used = parsed;
        }
    }

    if (recorded != now) {
        used = 0u;
        cep_l2_set_number_value(budget, dt_steps_used(), 0u);
        cep_l2_set_number_value(budget, dt_beat(), (size_t)now);
    }

    cep_l2_set_number_value(budget, dt_step_limit(), limit);

    state->budget = budget;
    state->limit = limit;
    state->used_prior = used;
    state->beat = now;
    state->initialized = true;
    return true;
}

static void cep_l2_budget_state_commit(cepL2BudgetState* state, size_t steps_added) {
    if (!state || !state->initialized || !state->budget) {
        return;
    }

    size_t total = state->used_prior + steps_added;
    if (total > state->limit) {
        total = state->limit;
    }

    cep_l2_set_number_value(state->budget, dt_steps_used(), total);
    cep_l2_set_number_value(state->budget, dt_step_limit(), state->limit);
    cep_l2_set_number_value(state->budget, dt_beat(), (size_t)state->beat);
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
    if (!entry) {
        return false;
    }

    const char* pattern = cep_l2_fetch_string(entry, dt_signal_path());
    if (!pattern) {
        pattern = cep_l2_fetch_string(entry, dt_signal());
    }

    if (!pattern) {
        return signal == NULL;
    }

    if (!signal) {
        return true;
    }

    for (const char* p = pattern; *p; ++p) {
        if (*p == '*' || *p == '?') {
            goto glob_match;
        }
    }
    return strcmp(pattern, signal) == 0;

glob_match:
    while (*pattern == '*') {
        ++pattern;
    }
    if (!*pattern) {
        return true;
    }

    const char* pat = pattern;
    const char* text = signal;
    const char* star = NULL;
    const char* backtrack = NULL;

    while (*text) {
        if (*pat == '*') {
            star = pat++;
            backtrack = text;
        } else if (*pat == '?' || *pat == *text) {
            ++pat;
            ++text;
        } else if (star) {
            pat = star + 1;
            text = ++backtrack;
        } else {
            return false;
        }
    }

    while (*pat == '*') {
        ++pat;
    }
    return *pat == '\0';
}

static bool cep_l2_fire_event_for_instance(cepCell* instance, const char* signal, cepCell* request, bool targeted) {
    if (!instance) {
        return false;
    }

    cepCell* subs = cep_cell_find_by_name(instance, dt_subs());
    if (!subs || !cep_cell_has_store(subs)) {
        return false;
    }

    bool matched = false;
    cepBeatNumber now = cep_heartbeat_current();

    char event_context[128];
    bool event_has_context = request ? cep_l2_extract_context_signature(request, event_context, sizeof event_context) : false;

    for (cepCell* entry = cep_cell_first(subs); entry; entry = cep_cell_next(subs, entry)) {
        if (!cep_l2_sub_entry_matches_signal(entry, signal)) {
            continue;
        }
        if (!targeted) {
            char wait_context[128];
            bool wait_has_context = cep_l2_extract_context_signature(entry, wait_context, sizeof wait_context);
            if (!wait_has_context) {
                wait_has_context = cep_l2_extract_context_signature(instance, wait_context, sizeof wait_context);
            }

            if (event_has_context) {
                if (!wait_has_context || strcmp(wait_context, event_context) != 0) {
                    continue;
                }
            } else if (wait_has_context) {
                continue;
            }
        }
        if (cep_l2_sub_entry_has_status(entry, "triggered")) {
            continue;
        }
        matched = true;
        cep_l2_sub_entry_set_string(entry, dt_status(), "triggered");
        cep_l2_remove_field(entry, dt_deadline());
        cep_l2_set_number_value(entry, dt_beat(), (size_t)now);
        cep_l2_set_string_value(entry, dt_origin(), targeted ? "target" : "broadcast");
        if (signal) {
            cep_l2_set_string_value(entry, dt_signal(), signal);
        }
        cep_l2_store_wait_context(entry, instance);
        if (request) {
            cepCell* payload = cep_l2_ensure_dictionary(entry, dt_payload(), CEP_STORAGE_RED_BLACK_T);
            if (payload) {
                cep_l2_copy_request_payload(request, payload);
            }
        }
    }

    if (matched) {
        cep_l2_set_string_value(instance, dt_state(), "ready");

        if (request) {
            cepCell* events = cep_cell_find_by_name(instance, dt_events());
            if (!events) {
                cepDT dict_type = *dt_dictionary();
                cepDT events_name = *dt_events();
                events = cep_cell_add_dictionary(instance, &events_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
            }
            if (events) {
                size_t suffix = cep_cell_children(events);
                char key_buf[32];
                int written = snprintf(key_buf, sizeof key_buf, "%llu_%zu", (unsigned long long)now, suffix);
                if (written > 0 && (size_t)written < sizeof key_buf) {
                    cepDT key_dt = {0};
                    if (cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
                        cepCell* slot = cep_l2_ensure_dictionary(events, &key_dt, CEP_STORAGE_RED_BLACK_T);
                        if (slot) {
                            cep_l2_copy_request_payload(request, slot);
                            if (signal) {
                                cep_l2_set_string_value(slot, dt_signal(), signal);
                                cep_l2_set_string_value(slot, dt_signal_path(), signal);
                            }
                            cep_l2_set_number_value(slot, dt_beat(), (size_t)now);
                            cep_l2_set_string_value(slot, dt_origin(), targeted ? "target" : "broadcast");
                            if (event_has_context) {
                                cep_l2_set_string_value(slot, dt_context(), event_context);
                            }
                        }
                    }
                }
            }
        }
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

    cepCell* subs = cep_cell_parent(entry);

    if (cep_l2_sub_entry_has_status(entry, "triggered")) {
        if (subs) {
            cep_cell_remove_hard(subs, entry);
        }
        return CEP_L2_STEP_ADVANCE;
    }

    if (cep_l2_wait_entry_timed_out(entry)) {
        cep_l2_sub_entry_set_string(entry, dt_status(), "timeout");
        if (subs) {
            cep_cell_remove_hard(subs, entry);
        }
        cep_l2_set_string_value(instance, dt_state(), "ready");
        return CEP_L2_STEP_ADVANCE;
    }

    cepCell* spec = cep_l2_step_spec(step);
    const char* signal = spec ? cep_l2_fetch_string(spec, dt_signal_path()) : NULL;
    if (!signal) {
        signal = spec ? cep_l2_fetch_string(spec, dt_signal()) : NULL;
    }
    if (signal) {
        cep_l2_sub_entry_set_string(entry, dt_signal_path(), signal);
        bool has_glob = false;
        for (const char* p = signal; *p; ++p) {
            if (*p == '*' || *p == '?') {
                has_glob = true;
                break;
            }
        }
        if (has_glob) {
            cep_l2_sub_entry_set_string(entry, dt_signal_glob(), signal);
        } else {
            cep_l2_remove_field(entry, dt_signal_glob());
            cep_l2_sub_entry_set_string(entry, dt_signal(), signal);
        }
    } else {
        cep_l2_remove_field(entry, dt_signal_path());
        cep_l2_remove_field(entry, dt_signal_glob());
        cep_l2_remove_field(entry, dt_signal());
    }
    cep_l2_sub_entry_set_string(entry, dt_status(), "pending");
    cep_l2_set_string_value(instance, dt_state(), "waiting");

    const char* timeout_text = spec ? cep_l2_fetch_string(spec, dt_timeout()) : NULL;
    if (timeout_text) {
        size_t timeout_beats = 0u;
        if (cep_l2_parse_size_text(timeout_text, &timeout_beats) && timeout_beats > 0u) {
            cep_l2_set_number_value(entry, dt_timeout(), timeout_beats);
            cep_l2_wait_entry_set_deadline(entry, timeout_beats);
        } else {
            cep_l2_remove_field(entry, dt_timeout());
            cep_l2_remove_field(entry, dt_deadline());
        }
    } else {
        cep_l2_remove_field(entry, dt_timeout());
        cep_l2_remove_field(entry, dt_deadline());
    }

    cep_l2_store_wait_context(entry, instance);

    return CEP_L2_STEP_BLOCK;
}

static cepL2StepResult cep_l2_step_decide(cepCell* flow_root, cepCell* instance, cepCell* step, size_t pc) {
    cepCell* spec = cep_l2_step_spec(step);
    const char* site = spec ? cep_l2_fetch_string(spec, dt_site()) : NULL;
    const char* choice = spec ? cep_l2_fetch_string(spec, dt_choice()) : NULL;

    if (!choice || !*choice) {
        choice = "default";
    }

    if (!site || !*site) {
        site = "default";
    }

    cepCell* ledger = cep_l2_decision_ledger(flow_root);
    if (!ledger) {
        return CEP_L2_STEP_ERROR;
    }

    const cepDT* inst_name = cep_cell_get_name(instance);
    if (!inst_name) {
        return CEP_L2_STEP_ERROR;
    }

    cepCell* node = cep_l2_decision_node(ledger, inst_name, site, true);
    if (!node) {
        return CEP_L2_STEP_ERROR;
    }

    cepL2StoreLock node_lock = {0};
    if (!cep_l2_store_lock(node, &node_lock)) {
        return CEP_L2_STEP_ERROR;
    }

    cepL2StepResult result = CEP_L2_STEP_ADVANCE;

    const char* recorded = cep_l2_fetch_string(node, dt_choice());
    if (recorded) {
        if (choice && strcmp(recorded, choice) != 0) {
            result = CEP_L2_STEP_ERROR;
            goto done;
        }
    } else if (!cep_l2_set_string_value(node, dt_choice(), choice)) {
        result = CEP_L2_STEP_ERROR;
        goto done;
    }

    if (!cep_cell_find_by_name(node, dt_site())) {
        (void)cep_l2_set_string_value(node, dt_site(), site);
    }

    if (!cep_cell_find_by_name(node, dt_inst_id())) {
        (void)cep_l2_store_dt_string(node, dt_inst_id(), inst_name);
    }

    if (!cep_cell_find_by_name(node, dt_pc())) {
        (void)cep_l2_set_number_value(node, dt_pc(), pc);
    }

    if (!cep_cell_find_by_name(node, dt_beat())) {
        (void)cep_l2_set_number_value(node, dt_beat(), (size_t)cep_heartbeat_current());
    }

    cepDT policy_dt = {0};
    const char* policy_text = NULL;
    bool has_policy = spec && cep_l2_extract_cell_identifier(spec, dt_policy(), &policy_dt, &policy_text);
    if (has_policy) {
        cepCell* existing_policy = cep_cell_find_by_name(node, dt_policy());
        if (existing_policy) {
            if (cep_cell_is_link(existing_policy)) {
                cepCell* target = cep_link_pull(existing_policy);
                const cepDT* existing_dt = target ? cep_cell_get_name(target) : NULL;
                if (!cep_l2_dt_equal(existing_dt, &policy_dt)) {
                    result = CEP_L2_STEP_ERROR;
                    goto done;
                }
            } else if (cep_cell_has_data(existing_policy)) {
                const char* recorded_policy = cep_l2_fetch_string(node, dt_policy());
                if (recorded_policy) {
                    if (policy_text && strcmp(recorded_policy, policy_text) != 0) {
                        result = CEP_L2_STEP_ERROR;
                        goto done;
                    }
                    if (!policy_text) {
                        char buffer[128];
                        if (cep_l2_dt_to_text(&policy_dt, buffer, sizeof buffer)
                            && strcmp(recorded_policy, buffer) != 0) {
                            result = CEP_L2_STEP_ERROR;
                            goto done;
                        }
                    }
                }
            }
        } else {
            cepCell* policy_ledger = cep_cell_find_by_name(flow_root, dt_policy());
            cepCell* policy_entry = policy_ledger ? cep_cell_find_by_name(policy_ledger, &policy_dt) : NULL;
            if (policy_entry) {
                cepDT name_copy = *dt_policy();
                (void)cep_cell_add_link(node, &name_copy, 0, policy_entry);
            } else if (!policy_text) {
                (void)cep_l2_store_dt_string(node, dt_policy(), &policy_dt);
            } else {
                (void)cep_l2_set_string_value(node, dt_policy(), policy_text);
            }
        }
    }

    cepDT variant_dt = {0};
    if (cep_l2_instance_variant_dt(instance, &variant_dt)) {
        cepCell* existing_variant = cep_cell_find_by_name(node, dt_variant());
        if (existing_variant) {
            if (cep_cell_is_link(existing_variant)) {
                cepCell* target = cep_link_pull(existing_variant);
                const cepDT* existing_dt = target ? cep_cell_get_name(target) : NULL;
                if (!cep_l2_dt_equal(existing_dt, &variant_dt)) {
                    result = CEP_L2_STEP_ERROR;
                    goto done;
                }
            } else if (cep_cell_has_data(existing_variant)) {
                const char* recorded_variant = cep_l2_fetch_string(node, dt_variant());
                char buffer[128];
                if (recorded_variant && cep_l2_dt_to_text(&variant_dt, buffer, sizeof buffer)
                    && strcmp(recorded_variant, buffer) != 0) {
                    result = CEP_L2_STEP_ERROR;
                    goto done;
                }
            }
        } else {
            cepCell* variant_ledger = cep_cell_find_by_name(flow_root, dt_variant());
            cepCell* variant_entry = variant_ledger ? cep_cell_find_by_name(variant_ledger, &variant_dt) : NULL;
            if (variant_entry) {
                cepDT name_copy = *dt_variant();
                (void)cep_cell_add_link(node, &name_copy, 0, variant_entry);
            } else {
                (void)cep_l2_store_dt_string(node, dt_variant(), &variant_dt);
            }
        }
    }

done:
    cep_l2_store_unlock(&node_lock);
    /* TODO(decision-ledger): capture policy evidence and replay validation metadata. */
    return result;
}

static cepL2StepResult cep_l2_step_clamp(cepCell* instance, cepCell* step, size_t pc, size_t projected_steps, cepBeatNumber now, cepL2BudgetState* budget_state) {
    cepCell* spec = cep_l2_step_spec(step);
    if (!spec) {
        return CEP_L2_STEP_ADVANCE;
    }

    if (budget_state) {
        if (!budget_state->initialized) {
            (void)cep_l2_budget_state_prepare(instance, spec, now, budget_state);
        }
        if (budget_state->initialized) {
            size_t total = budget_state->used_prior + projected_steps;
            if (total >= budget_state->limit) {
                const char* pause_state = cep_l2_fetch_string(spec, dt_state());
                cep_l2_set_string_value(instance, dt_state(), pause_state ? pause_state : "paused");
                return CEP_L2_STEP_BLOCK;
            }
        }
    }

    cepCell* budget_dict = (budget_state && budget_state->initialized) ? budget_state->budget : NULL;
    if (!budget_dict) {
        budget_dict = cep_cell_find_by_name(instance, dt_budget());
    }

    const char* timeout_text = cep_l2_fetch_string(spec, dt_timeout());
    if (timeout_text && budget_dict) {
        size_t timeout_beats = 0u;
        if (cep_l2_parse_size_text(timeout_text, &timeout_beats) && timeout_beats > 0u) {
            size_t deadline = (size_t)now + timeout_beats;
            cep_l2_set_number_value(budget_dict, dt_timeout(), timeout_beats);
            cep_l2_set_number_value(budget_dict, dt_deadline(), deadline);
        }
    }

    if (budget_dict) {
        const char* deadline_text = cep_l2_fetch_string(budget_dict, dt_deadline());
        size_t deadline_value = 0u;
        if (deadline_text && cep_l2_parse_size_text(deadline_text, &deadline_value) && (size_t)now >= deadline_value) {
            const char* pause_state = cep_l2_fetch_string(spec, dt_state());
            cep_l2_set_string_value(instance, dt_state(), pause_state ? pause_state : "paused");
            return CEP_L2_STEP_BLOCK;
        }
    }

    const char* limit_text = cep_l2_fetch_string(spec, dt_pc());
    if (limit_text) {
        size_t limit = 0u;
        if (cep_l2_parse_size_text(limit_text, &limit) && pc >= limit) {
            const char* pause_state = cep_l2_fetch_string(spec, dt_state());
            cep_l2_set_string_value(instance, dt_state(), pause_state ? pause_state : "paused");
            return CEP_L2_STEP_BLOCK;
        }
    }

    const char* annotate_state = cep_l2_fetch_string(spec, dt_state());
    if (annotate_state && (!limit_text)) {
        cep_l2_set_string_value(instance, dt_state(), annotate_state);
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

static cepL2StepResult cep_l2_step_guard(cepCell* instance, cepCell* step, size_t pc) {
    cepCell* spec = cep_l2_step_spec(step);
    if (!spec) {
        return CEP_L2_STEP_ADVANCE;
    }

    const char* required_state = cep_l2_fetch_string(spec, dt_state());
    if (required_state) {
        const char* current = cep_l2_fetch_string(instance, dt_state());
        if (!current || strcmp(current, required_state) != 0) {
            const char* action_state = cep_l2_fetch_string(spec, dt_action());
            cep_l2_set_string_value(instance, dt_state(), action_state ? action_state : "done");
            return CEP_L2_STEP_BLOCK;
        }
    }

    const char* pc_text = cep_l2_fetch_string(spec, dt_pc());
    if (pc_text) {
        size_t expected_pc = 0u;
        if (!cep_l2_parse_size_text(pc_text, &expected_pc) || pc != expected_pc) {
            const char* action_state = cep_l2_fetch_string(spec, dt_action());
            cep_l2_set_string_value(instance, dt_state(), action_state ? action_state : "done");
            return CEP_L2_STEP_BLOCK;
        }
    }

    return CEP_L2_STEP_ADVANCE;
}

static bool cep_l2_instance_variant_dt(cepCell* instance, cepDT* out_dt) {
    if (!instance || !out_dt) {
        return false;
    }

    cepCell* variant = cep_cell_find_by_name(instance, dt_variant());
    if (!variant) {
        return false;
    }

    if (cep_cell_is_link(variant)) {
        variant = cep_link_pull(variant);
        if (variant) {
            const cepDT* dt = cep_cell_get_name(variant);
            if (dt) {
                *out_dt = *dt;
                return true;
            }
        }
    }

    if (variant && cep_cell_has_data(variant)) {
        const cepData* data = variant->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size) {
            const char* text = (const char*)data->value;
            if (text && data->size >= 1u) {
                return cep_l2_text_to_dt_bytes(text, data->size - 1u, out_dt);
            }
        }
    }

    return false;
}

static bool cep_l2_wait_entry_set_deadline(cepCell* entry, size_t timeout_beats) {
    cepBeatNumber now = cep_heartbeat_current();
    size_t deadline = (size_t)now + timeout_beats;
    return cep_l2_set_number_value(entry, dt_deadline(), deadline);
}

static bool cep_l2_wait_entry_deadline(cepCell* entry, size_t* out_deadline) {
    if (!entry || !out_deadline) {
        return false;
    }

    const char* deadline_text = cep_l2_fetch_string(entry, dt_deadline());
    if (!deadline_text) {
        return false;
    }

    return cep_l2_parse_size_text(deadline_text, out_deadline);
}

static bool cep_l2_wait_entry_timed_out(cepCell* entry) {
    size_t deadline = 0u;
    if (!cep_l2_wait_entry_deadline(entry, &deadline)) {
        return false;
    }

    cepBeatNumber now = cep_heartbeat_current();
    return (size_t)now >= deadline;
}

static bool cep_l2_transform_build_signal_path(const char* text, cepPathStatic4* path) {
    if (!text || !*text || !path) {
        return false;
    }

    path->length = 0u;
    path->capacity = sizeof(path->past) / sizeof(path->past[0]);

    const char* cursor = text;
    while (*cursor) {
        if (path->length >= path->capacity) {
            return false;
        }

        const char* segment = cursor;
        while (*cursor && *cursor != '/' && *cursor != ':') {
            ++cursor;
        }

        size_t len = (size_t)(cursor - segment);
        if (len == 0u) {
            return false;
        }

        /* Ignore explicit domain prefixes (e.g., "CEP:"). */
        if (*cursor == ':' && path->length == 0u) {
            cursor++; /* Skip delimiter and restart next segment. */
            continue;
        }

        char buffer[64];
        if (len >= sizeof buffer) {
            return false;
        }
        memcpy(buffer, segment, len);
        buffer[len] = '\0';

        cepDT segment_dt = {0};
        if (!cep_l2_text_to_dt_bytes(buffer, len, &segment_dt)) {
            return false;
        }

        path->past[path->length].dt = segment_dt;
        path->past[path->length].timestamp = 0u;
        path->length += 1u;

        if (*cursor == '\0') {
            break;
        }
        cursor++; /* Skip delimiter */
    }

    return path->length > 0u;
}

static bool cep_l2_transform_stage_emit(cepCell* instance,
                                       cepCell* step,
                                       cepCell* emission,
                                       cepCell* emits_root,
                                       size_t pc,
                                       cepBeatNumber now,
                                       size_t index_offset,
                                       const char* default_signal) {
    if (!instance || !emits_root) {
        return false;
    }

    size_t suffix = cep_cell_children(emits_root) + index_offset;
    cepCell* slot = NULL;

    for (size_t attempt = 0u; attempt < 64u; ++attempt) {
        char key_buf[32];
        int written = snprintf(key_buf, sizeof key_buf, "%zu_%zu", pc, suffix + attempt);
        if (written <= 0 || (size_t)written >= sizeof key_buf) {
            return false;
        }

        cepDT key_dt = {0};
        if (!cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
            return false;
        }

        cepCell* existing = cep_cell_find_by_name(emits_root, &key_dt);
        if (existing) {
            continue;
        }

        slot = cep_l2_ensure_dictionary(emits_root, &key_dt, CEP_STORAGE_RED_BLACK_T);
        break;
    }

    if (!slot) {
        return false;
    }

    if (emission && cep_cell_has_store(emission)) {
        if (!cep_l2_copy_request_payload(emission, slot)) {
            return false;
        }
    } else if (emission && cep_cell_has_data(emission)) {
        cepCell* clone = cep_cell_clone_deep(emission);
        if (!clone) {
            return false;
        }
        cepCell* inserted = cep_cell_add(slot, 0, clone);
        if (!inserted) {
            cep_cell_finalize_hard(clone);
            cep_free(clone);
            return false;
        }
        cep_free(clone);
    }

    (void)cep_l2_set_number_value(slot, dt_pc(), pc);
    (void)cep_l2_set_number_value(slot, dt_beat(), (size_t)now);

    cepCell* parents[4];
    size_t parent_count = 0u;
    if (instance) {
        parents[parent_count++] = instance;
    }
    if (emission) {
        parents[parent_count++] = emission;
    }
    if (step) {
        parents[parent_count++] = step;
    }
    cepCell* target_field = cep_cell_find_by_name(slot, dt_target());
    if (!target_field && emission) {
        target_field = cep_cell_find_by_name(emission, dt_target());
    }
    if (target_field && cep_cell_is_link(target_field)) {
        cepCell* target_cell = cep_link_pull(target_field);
        if (target_cell && parent_count < sizeof(parents) / sizeof(parents[0])) {
            parents[parent_count++] = target_cell;
        }
    }
    if (parent_count > 0u) {
        (void)cep_cell_add_parents(slot, parents, parent_count);
    }

    cep_cell_content_hash(slot);

    const char* signal_text = cep_l2_fetch_string(slot, dt_signal_path());
    if (!signal_text || !*signal_text) {
        signal_text = cep_l2_fetch_string(slot, dt_signal());
    }
    if ((!signal_text || !*signal_text) && default_signal && *default_signal) {
        signal_text = default_signal;
    }

    if (signal_text && *signal_text) {
        cepPathStatic4 signal_path = {0};
        if (cep_l2_transform_build_signal_path(signal_text, &signal_path)) {
            cepPath* target_path = NULL;
            if (cep_cell_path(slot, &target_path)) {
                int rc = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, (const cepPath*)&signal_path, target_path);
                cep_free(target_path);
                if (rc == CEP_ENZYME_FATAL) {
                    return false;
                }
            }
        }
        if (!cep_cell_find_by_name(slot, dt_signal_path())) {
            (void)cep_l2_set_string_value(slot, dt_signal_path(), signal_text);
        }
        if (!cep_cell_find_by_name(slot, dt_signal())) {
            (void)cep_l2_set_string_value(slot, dt_signal(), signal_text);
        }
    }

    return true;
}

static bool cep_l2_transform_stage_outputs(cepCell* instance,
                                           cepCell* step,
                                           cepCell* spec,
                                           size_t pc,
                                           cepBeatNumber now,
                                           size_t* out_emits) {
    if (out_emits) {
        *out_emits = 0u;
    }

    if (!instance || !spec) {
        return true;
    }

    cepCell* payload = cep_cell_find_by_name(spec, dt_payload());
    if (!payload || !cep_cell_has_store(payload)) {
        return true;
    }

    cepCell* emits_root = cep_l2_ensure_dictionary(instance, dt_emits(), CEP_STORAGE_RED_BLACK_T);
    if (!emits_root) {
        return false;
    }

    const char* default_signal = cep_l2_fetch_string(spec, dt_signal_path());
    if (!default_signal) {
        default_signal = cep_l2_fetch_string(spec, dt_signal());
    }
    if (!default_signal || !*default_signal) {
        default_signal = "CEP:sig_cell/op_add";
    }

    size_t produced = 0u;
    size_t index_offset = 0u;
    for (cepCell* emission = cep_cell_first(payload); emission; emission = cep_cell_next(payload, emission)) {
        if (!cep_cell_is_normal(emission)) {
            continue;
        }
        if (!cep_l2_transform_stage_emit(instance, step, emission, emits_root, pc, now, index_offset, default_signal)) {
            return false;
        }
        ++produced;
        ++index_offset;
    }

    if (out_emits) {
        *out_emits = produced;
    }
    return true;
}

static bool cep_l2_canonicalize_inst_event(cepCell* request, const char** error_code) {
    if (error_code) {
        *error_code = NULL;
    }
    if (!request) {
        if (error_code) {
            *error_code = "no-request";
        }
        return false;
    }

    cepL2StoreLock request_lock = {0};
    if (!cep_l2_store_lock(request, &request_lock)) {
        if (error_code) {
            *error_code = "request-lock";
        }
        return false;
    }

    bool success = true;

    cepCell* original = cep_l2_ensure_dictionary(request, dt_original(), CEP_STORAGE_RED_BLACK_T);
    cepL2StoreLock original_lock = {0};
    if (original && cep_l2_store_lock(original, &original_lock)) {
        (void)cep_l2_copy_request_payload(request, original);
    }
    cep_l2_store_unlock(&original_lock);

    const char* signal_path = cep_l2_fetch_string(request, dt_signal_path());
    const char* signal_text = cep_l2_fetch_string(request, dt_signal());
    if (!signal_path && signal_text && *signal_text) {
        if (!cep_l2_set_string_value(request, dt_signal_path(), signal_text)) {
            if (error_code) {
                *error_code = "signal-store";
            }
            success = false;
        }
        signal_path = cep_l2_fetch_string(request, dt_signal_path());
    }

    if (success && (!signal_path || !*signal_path)) {
        if (error_code) {
            *error_code = "missing-signal";
        }
        success = false;
    }

    cepPathStatic4 signal_probe = {0};
    signal_probe.capacity = sizeof(signal_probe.past) / sizeof(signal_probe.past[0]);
    if (success && !cep_l2_transform_build_signal_path(signal_path, &signal_probe)) {
        if (error_code) {
            *error_code = "signal-format";
        }
        success = false;
    }

    if (success && (!signal_text || !*signal_text)) {
        if (!cep_l2_set_string_value(request, dt_signal(), signal_path)) {
            if (error_code) {
                *error_code = "signal-store";
            }
            success = false;
        }
    }

    cepCell* payload = success ? cep_cell_find_by_name(request, dt_payload()) : NULL;
    if (success && payload && !cep_cell_has_store(payload)) {
        if (error_code) {
            *error_code = "payload-type";
        }
        success = false;
    }
    if (success && !payload) {
        payload = cep_l2_ensure_dictionary(request, dt_payload(), CEP_STORAGE_RED_BLACK_T);
        if (!payload) {
            if (error_code) {
                *error_code = "payload-create";
            }
            success = false;
        }
    }

    if (success) {
        char context_signature[128];
        if (cep_l2_extract_context_signature(request, context_signature, sizeof context_signature)) {
            (void)cep_l2_set_string_value(request, dt_context(), context_signature);
        }
    }

    cep_l2_store_unlock(&request_lock);
    return success;
}

static cepL2StepResult cep_l2_step_transform(cepCell* instance, cepCell* step, size_t pc, cepBeatNumber now) {
    cepCell* spec = cep_l2_step_spec(step);
    if (!spec) {
        return CEP_L2_STEP_ADVANCE;
    }

    const char* new_state = cep_l2_fetch_string(spec, dt_state());
    if (new_state && *new_state) {
        cep_l2_set_string_value(instance, dt_state(), new_state);
    }

    size_t emitted = 0u;
    if (!cep_l2_transform_stage_outputs(instance, step, spec, pc, now, &emitted)) {
        return CEP_L2_STEP_ERROR;
    }
    (void)emitted;

    cepCell* payload = cep_cell_find_by_name(spec, dt_payload());
    if (payload && cep_cell_has_store(payload)) {
        cepCell* events = cep_cell_find_by_name(instance, dt_events());
        if (!events) {
            cepDT dict_type = *dt_dictionary();
            cepDT events_name = *dt_events();
            events = cep_cell_add_dictionary(instance, &events_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        }
        if (events) {
            char key_buf[32];
            int written = snprintf(key_buf, sizeof key_buf, "%zu", pc);
            if (written > 0 && (size_t)written < sizeof key_buf) {
                cepDT key_dt = {0};
                if (cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
                    cepCell* slot = cep_l2_ensure_dictionary(events, &key_dt, CEP_STORAGE_RED_BLACK_T);
                    if (slot) {
                        cep_l2_copy_request_payload(payload, slot);
                        cep_l2_set_number_value(slot, dt_beat(), (size_t)now);
                    }
                }
            }
        }
    }

    return CEP_L2_STEP_ADVANCE;
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

static bool cep_l2_extract_cell_identifier(cepCell* container, const cepDT* field, cepDT* out_dt, const char** out_text) {
    if (!container || !field || !out_dt) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(container, field);
    if (!node) {
        return false;
    }

    if (cep_cell_is_link(node)) {
        cepCell* target = cep_link_pull(node);
        if (!target) {
            return false;
        }
        const cepDT* name = cep_cell_get_name(target);
        if (!name) {
            return false;
        }
        *out_dt = *name;
        if (out_text) {
            *out_text = NULL;
        }
        return true;
    }

    const char* text = NULL;
    size_t length = 0u;
    if (!cep_l2_get_cstring(container, field, &text, &length)) {
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

/* Flow ingest normalises program/policy/variant/guardian definitions, capturing
 * the submitted payload under the `original` mirror while materialising the
 * canonical ledger schema used by the VM and downstream indexes. */
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

    cepL2DefinitionKind def_kind = cep_l2_definition_kind_from_text(kind_text);
    const char* canonical_kind = cep_l2_definition_kind_text(def_kind);
    if (def_kind == CEP_L2_DEF_UNKNOWN || !canonical_kind) {
        cep_l2_mark_outcome_error(request, "unknown-kind");
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* bucket = cep_cell_parent(request);
    cepCell* inbox = bucket ? cep_cell_parent(bucket) : NULL;
    cepCell* flow_root = inbox ? cep_cell_parent(inbox) : NULL;
    cepCell* ledger = cep_l2_definition_ledger(canonical_kind, flow_root);
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

    const char* canon_error = NULL;
    bool canon_ok = true;

    if (!cep_l2_copy_original_payload(entry, request)) {
        canon_ok = false;
        canon_error = "original-copy";
    }

    if (canon_ok && !cep_l2_set_string_value(entry, dt_kind(), canonical_kind)) {
        canon_ok = false;
        canon_error = "kind-store";
    }

    if (canon_ok) {
        switch (def_kind) {
        case CEP_L2_DEF_PROGRAM:
            canon_ok = cep_l2_canonicalize_program(flow_root, entry, request, &id_dt, &canon_error);
            break;
        case CEP_L2_DEF_POLICY:
            canon_ok = cep_l2_canonicalize_policy(entry, &id_dt);
            if (!canon_ok && !canon_error) {
                canon_error = "policy-canon";
            }
            break;
        case CEP_L2_DEF_VARIANT:
            canon_ok = cep_l2_canonicalize_variant(flow_root, entry, request, &id_dt, &canon_error);
            break;
        case CEP_L2_DEF_GUARDIAN:
            canon_ok = cep_l2_canonicalize_guardian(entry, &id_dt);
            if (!canon_ok && !canon_error) {
                canon_error = "guardian-canon";
            }
            break;
        case CEP_L2_DEF_UNKNOWN:
        default:
            canon_ok = false;
            if (!canon_error) {
                canon_error = "unknown-kind";
            }
            break;
        }
    }

    if (!canon_ok) {
        if (!canon_error) {
            canon_error = "canon-failed";
        }
        (void)cep_l2_copy_request_payload(request, entry);
        (void)cep_l2_copy_original_payload(entry, request);
        cep_l2_mark_outcome_error(request, canon_error);
        result = CEP_ENZYME_SUCCESS;
        goto done;
    }

    cep_l2_mark_outcome_ok(request);
    (void)cep_l2_enqueue_pipeline();
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

    const char* canon_error = NULL;
    bool canon_ok = true;

    if (!cep_l2_copy_original_payload(entry, request)) {
        canon_ok = false;
        canon_error = "original-copy";
    }

    if (canon_ok) {
        canon_ok = cep_l2_canonicalize_niche(flow_root, entry, request, &id_dt, &canon_error);
    }

    if (!canon_ok) {
        if (!canon_error) {
            canon_error = "canon-failed";
        }
        (void)cep_l2_copy_request_payload(request, entry);
        (void)cep_l2_copy_original_payload(entry, request);
        cep_l2_mark_outcome_error(request, canon_error);
        result = CEP_ENZYME_SUCCESS;
        goto done;
    }

    cep_l2_mark_outcome_ok(request);
    (void)cep_l2_enqueue_pipeline();
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

        cepCell* budget = cep_cell_find_by_name(entry, dt_budget());
        if (!budget) {
            cepDT dict_type = *dt_dictionary();
            cepDT name_copy = *dt_budget();
            budget = cep_cell_add_dictionary(entry, &name_copy, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
            if (!budget) {
                cep_l2_mark_outcome_error(request, "budget");
                goto done;
            }
        }

        cep_l2_mark_outcome_ok(request);
        (void)cep_l2_enqueue_pipeline();
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

        cepCell* updates = cep_cell_find_by_name(request, dt_budget());
        cepCell* budget = cep_l2_ensure_dictionary(entry, dt_budget(), CEP_STORAGE_RED_BLACK_T);
        if (budget) {
            const char* limit_text = NULL;
            if (updates && cep_cell_has_store(updates)) {
                limit_text = cep_l2_fetch_string(updates, dt_step_limit());
            }
            if (!limit_text) {
                limit_text = cep_l2_fetch_string(request, dt_step_limit());
            }
            size_t limit_value = 0u;
            if (limit_text && cep_l2_parse_size_text(limit_text, &limit_value) && limit_value > 0u) {
                cep_l2_set_number_value(budget, dt_step_limit(), limit_value);
                cep_l2_set_number_value(budget, dt_steps_used(), 0u);
                cep_l2_set_number_value(budget, dt_beat(), (size_t)cep_heartbeat_current());
            }
        }
    } else {
        cep_l2_mark_outcome_error(request, "unknown-action");
        goto done;
    }

    cep_l2_mark_outcome_ok(request);
    (void)cep_l2_enqueue_pipeline();
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

    const char* canon_error = NULL;
    if (!cep_l2_canonicalize_inst_event(request, &canon_error)) {
        cep_l2_mark_outcome_error(request, canon_error ? canon_error : "event-canon");
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
        matched = cep_l2_fire_event_for_instance(entry, signal_text, request, true);
    } else {
        for (cepCell* entry = cep_cell_first(ledger); entry; entry = cep_cell_next(ledger, entry)) {
            if (cep_l2_fire_event_for_instance(entry, signal_text, request, false)) {
                matched = true;
            }
        }
    }

    if (!matched) {
        cep_l2_mark_outcome_error(request, "no-match");
        return CEP_ENZYME_SUCCESS;
    }

    cep_l2_mark_outcome_ok(request);
    (void)cep_l2_enqueue_pipeline();
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

    bool pipeline_requested = false;

    for (cepCell* instance = cep_cell_first(ledger); instance; instance = cep_cell_next(ledger, instance)) {
        if (!cep_cell_is_normal(instance)) {
            continue;
        }

        cepL2StoreLock inst_lock = {0};
        if (!cep_l2_store_lock(instance, &inst_lock)) {
            continue;
        }

        bool instance_mutated = false;
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
            if (!entry) {
                cep_l2_set_string_value(instance, dt_state(), "ready");
                instance_mutated = true;
            } else if (cep_l2_sub_entry_has_status(entry, "triggered")) {
                cepCell* subs = cep_cell_parent(entry);
                if (subs) {
                    cep_cell_remove_hard(subs, entry);
                }
                cep_l2_set_string_value(instance, dt_state(), "ready");
                instance_mutated = true;
            } else if (cep_l2_wait_entry_timed_out(entry)) {
                cep_l2_sub_entry_set_string(entry, dt_status(), "timeout");
                cepCell* subs = cep_cell_parent(entry);
                if (subs) {
                    cep_cell_remove_hard(subs, entry);
                }
                cep_l2_set_string_value(instance, dt_state(), "ready");
                instance_mutated = true;
            } else {
                cep_l2_store_unlock(&inst_lock);
                continue;
            }
        } else if (state && strcmp(state, "paused") == 0) {
            cep_l2_store_unlock(&inst_lock);
            continue;
        } else if (state && strcmp(state, "error") == 0) {
            cep_l2_store_unlock(&inst_lock);
            continue;
        }

        cepBeatNumber now = cep_heartbeat_current();
        cepL2BudgetState budget_state = {0};
        size_t steps_this_run = 0u;
        bool continue_run = true;
        while (continue_run && steps_this_run < 64u) {
            cepCell* program = cep_l2_program_from_instance(flow_root, instance);
            if (!program) {
                program = instance;
            }
            cepCell* steps = cep_l2_steps_container(program);
            if (!steps) {
                cep_l2_set_string_value(instance, dt_state(), "done");
                instance_mutated = true;
                break;
            }

            cepCell* step = cep_l2_step_at(steps, pc);
            if (!step) {
                cep_l2_set_string_value(instance, dt_state(), "done");
                instance_mutated = true;
                break;
            }

            const char* kind = cep_l2_step_kind(step);
            cepL2StepResult outcome = CEP_L2_STEP_ADVANCE;

            if (kind && strcmp(kind, "guard") == 0) {
                outcome = cep_l2_step_guard(instance, step, pc);
            } else if (kind && strcmp(kind, "transform") == 0) {
                outcome = cep_l2_step_transform(instance, step, pc, now);
                if (outcome != CEP_L2_STEP_ADVANCE) {
                    instance_mutated = true;
                }
            } else if (kind && strcmp(kind, "wait") == 0) {
                outcome = cep_l2_step_wait(instance, step, pc);
            } else if (kind && strcmp(kind, "decide") == 0) {
                outcome = cep_l2_step_decide(flow_root, instance, step, pc);
            } else if (kind && strcmp(kind, "clamp") == 0) {
                size_t projected = steps_this_run + 1u;
                outcome = cep_l2_step_clamp(instance, step, pc, projected, now, &budget_state);
            }

            if (outcome == CEP_L2_STEP_ERROR) {
                cep_l2_set_string_value(instance, dt_state(), "error");
                instance_mutated = true;
                break;
            }

            if (outcome == CEP_L2_STEP_BLOCK) {
                continue_run = false;
                ++steps_this_run;
                instance_mutated = true;
                break;
            }

            ++steps_this_run;
            ++pc;
        }

        if (budget_state.initialized) {
            cep_l2_budget_state_commit(&budget_state, steps_this_run);
            if (steps_this_run > 0u) {
                instance_mutated = true;
            }
        }

        cep_l2_store_pc(instance, pc);
        if (steps_this_run > 0u) {
            instance_mutated = true;
        }
        const char* final_state = cep_l2_fetch_string(instance, dt_state());
        if (!final_state) {
            cep_l2_set_string_value(instance, dt_state(), "ready");
            instance_mutated = true;
        }

        if (instance_mutated) {
            pipeline_requested = true;
        }
        cep_l2_store_unlock(&inst_lock);
    }

    if (pipeline_requested) {
        (void)cep_l2_enqueue_pipeline();
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_l2_enzyme_fl_index(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* instances = cep_cell_find_by_name(flow_root, dt_instance());
    cepCell* index_root = cep_cell_find_by_name(flow_root, dt_index());
    if (!instances || !cep_cell_has_store(instances) || !index_root) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* by_variant = cep_l2_ensure_dictionary(index_root, dt_inst_by_var(), CEP_STORAGE_RED_BLACK_T);
    cepCell* by_state = cep_l2_ensure_dictionary(index_root, dt_inst_by_st(), CEP_STORAGE_RED_BLACK_T);
    cepCell* by_policy = cep_l2_ensure_dictionary(index_root, dt_dec_by_pol(), CEP_STORAGE_RED_BLACK_T);

    cep_l2_clear_children(by_variant);
    cep_l2_clear_children(by_state);
    cep_l2_clear_children(by_policy);

    for (cepCell* instance = cep_cell_first(instances); instance; instance = cep_cell_next(instances, instance)) {
        if (!cep_cell_is_normal(instance)) {
            continue;
        }

        const cepDT* inst_name = cep_cell_get_name(instance);
        if (!inst_name) {
            continue;
        }

        cepDT variant_dt = {0};
        if (cep_l2_instance_variant_dt(instance, &variant_dt)) {
            cepCell* bucket = cep_l2_ensure_dictionary(by_variant, &variant_dt, CEP_STORAGE_RED_BLACK_T);
            if (bucket) {
                cepDT name_copy = *inst_name;
                (void)cep_cell_add_link(bucket, &name_copy, 0, instance);
            }
        }

        const char* state = cep_l2_fetch_string(instance, dt_state());
        if (state && *state) {
            cepDT state_dt = {0};
            if (cep_l2_text_to_dt_bytes(state, strlen(state), &state_dt)) {
                cepCell* bucket = cep_l2_ensure_dictionary(by_state, &state_dt, CEP_STORAGE_RED_BLACK_T);
                if (bucket) {
                    cepDT name_copy = *inst_name;
                    (void)cep_cell_add_link(bucket, &name_copy, 0, instance);
                }
            }
        }
    }

    cepCell* decisions = cep_cell_find_by_name(flow_root, dt_decision());
    if (decisions && cep_cell_has_store(decisions)) {
        for (cepCell* inst_bucket = cep_cell_first(decisions); inst_bucket; inst_bucket = cep_cell_next(decisions, inst_bucket)) {
            if (!cep_cell_is_normal(inst_bucket) || !cep_cell_has_store(inst_bucket)) {
                continue;
            }

            const cepDT* inst_name = cep_cell_get_name(inst_bucket);
            if (!inst_name) {
                continue;
            }

            for (cepCell* decision = cep_cell_first(inst_bucket); decision; decision = cep_cell_next(inst_bucket, decision)) {
                if (!cep_cell_is_normal(decision)) {
                    continue;
                }

                cepCell* policy_field = cep_cell_find_by_name(decision, dt_policy());
                if (!policy_field) {
                    continue;
                }

                cepDT policy_dt = {0};
                bool have_policy = false;

                if (cep_cell_is_link(policy_field)) {
                    cepCell* target = cep_link_pull(policy_field);
                    const cepDT* name = target ? cep_cell_get_name(target) : NULL;
                    if (name) {
                        policy_dt = *name;
                        have_policy = true;
                    }
                } else if (cep_cell_has_data(policy_field)) {
                    const char* policy_text = cep_l2_fetch_string(decision, dt_policy());
                    if (policy_text) {
                        have_policy = cep_l2_text_to_dt_bytes(policy_text, strlen(policy_text), &policy_dt);
                    }
                }

                if (!have_policy) {
                    continue;
                }

                cepCell* policy_bucket = cep_l2_ensure_dictionary(by_policy, &policy_dt, CEP_STORAGE_RED_BLACK_T);
                if (!policy_bucket) {
                    continue;
                }

                cepCell* inst_index = cep_l2_ensure_dictionary(policy_bucket, inst_name, CEP_STORAGE_RED_BLACK_T);
                if (!inst_index) {
                    continue;
                }

                const cepDT* site_name = cep_cell_get_name(decision);
                if (!site_name) {
                    continue;
                }

                cepDT site_copy = *site_name;
                (void)cep_cell_add_link(inst_index, &site_copy, 0, decision);
            }
        }
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_l2_enzyme_fl_adj(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* instances = cep_cell_find_by_name(flow_root, dt_instance());
    if (!instances || !cep_cell_has_store(instances)) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* root = cep_root();
    cepCell* tmp_root = cep_cell_find_by_name(root, dt_tmp_root());
    if (!tmp_root) {
        return CEP_ENZYME_SUCCESS;
    }
    cepCell* flow_tmp = cep_cell_find_by_name(tmp_root, dt_flow());
    if (!flow_tmp) {
        return CEP_ENZYME_SUCCESS;
    }
    cepCell* adj_root = cep_cell_find_by_name(flow_tmp, dt_adj());
    if (!adj_root) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* by_inst = cep_l2_ensure_dictionary(adj_root, dt_by_inst(), CEP_STORAGE_RED_BLACK_T);
    if (!by_inst) {
        return CEP_ENZYME_SUCCESS;
    }

    cep_l2_clear_children(by_inst);

    for (cepCell* instance = cep_cell_first(instances); instance; instance = cep_cell_next(instances, instance)) {
        if (!cep_cell_is_normal(instance)) {
            continue;
        }

        const cepDT* inst_name = cep_cell_get_name(instance);
        if (!inst_name) {
            continue;
        }

        cepCell* summary = cep_l2_ensure_dictionary(by_inst, inst_name, CEP_STORAGE_RED_BLACK_T);
        if (!summary) {
            continue;
        }

        cep_l2_clear_children(summary);

        const char* state = cep_l2_fetch_string(instance, dt_state());
        if (state) {
            cep_l2_set_string_value(summary, dt_state(), state);
            cep_l2_set_string_value(summary, dt_status(), state);
        }

        size_t pc = 0u;
        (void)cep_l2_parse_pc(instance, &pc);
        cep_l2_set_number_value(summary, dt_pc(), pc);

        cepCell* subs = cep_cell_find_by_name(instance, dt_subs());
        size_t subs_count = subs && cep_cell_has_store(subs) ? cep_cell_children(subs) : 0u;
        cep_l2_set_number_value(summary, dt_sub_count(), subs_count);

        cepCell* events = cep_cell_find_by_name(instance, dt_events());
        size_t events_count = events && cep_cell_has_store(events) ? cep_cell_children(events) : 0u;
        cep_l2_set_number_value(summary, dt_evt_count(), events_count);

        cepCell* emits = cep_cell_find_by_name(instance, dt_emits());
        size_t emits_count = emits && cep_cell_has_store(emits) ? cep_cell_children(emits) : 0u;
        cep_l2_set_number_value(summary, dt_emit_count(), emits_count);

        cepCell* latest_event = NULL;
        size_t   latest_beat = 0u;
        if (events && cep_cell_has_store(events)) {
            for (cepCell* event = cep_cell_first(events); event; event = cep_cell_next(events, event)) {
                if (!cep_cell_is_normal(event)) {
                    continue;
                }

                size_t beat_value = 0u;
                const char* beat_text = cep_l2_fetch_string(event, dt_beat());
                if (beat_text && cep_l2_parse_size_text(beat_text, &beat_value)) {
                    if (!latest_event || beat_value >= latest_beat) {
                        latest_event = event;
                        latest_beat = beat_value;
                    }
                } else if (!latest_event) {
                    latest_event = event;
                }
            }
        }

        if (latest_event) {
            if (latest_beat) {
                cep_l2_set_number_value(summary, dt_beat(), latest_beat);
            }
            const char* origin = cep_l2_fetch_string(latest_event, dt_origin());
            if (origin) {
                cep_l2_set_string_value(summary, dt_origin(), origin);
            }
            const char* sig = cep_l2_fetch_string(latest_event, dt_signal());
            if (sig) {
                cep_l2_set_string_value(summary, dt_signal(), sig);
            }
            const char* sig_path = cep_l2_fetch_string(latest_event, dt_signal_path());
            if (sig_path) {
                cep_l2_set_string_value(summary, dt_signal_path(), sig_path);
            }
        }
    }

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
