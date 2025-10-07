/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_flows.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_l0.h"
#include "../l0_kernel/cep_mailroom.h"
#include "../l0_kernel/cep_serialization.h"
#include "../l0_kernel/cep_namepool.h"
#include "cep_rendezvous.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
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
static const cepDT* dt_dec_archive(void) { return CEP_DTAW("CEP", "dec_archive"); }
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
static const cepDT* dt_rendezvous(void)  { return CEP_DTAW("CEP", "rendezvous"); }
static const cepDT* dt_defaults(void)    { return CEP_DTAW("CEP", "defaults"); }
static const cepDT* dt_key_field(void)   { return CEP_DTAW("CEP", "key"); }
static const cepDT* dt_due_field(void)   { return CEP_DTAW("CEP", "due"); }
static const cepDT* dt_due_offset_field(void){ return CEP_DTAW("CEP", "due_off"); }
static const cepDT* dt_kill_mode_field(void){ return CEP_DTAW("CEP", "kill_mode"); }
static const cepDT* dt_kill_wait_field(void){ return CEP_DTAW("CEP", "kill_wait"); }
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
static const cepDT* dt_history(void)     { return CEP_DTAW("CEP", "history"); }
static const cepDT* dt_event_ref(void)   { return CEP_DTAW("CEP", "event"); }
static const cepDT* dt_evidence(void)    { return CEP_DTAW("CEP", "evidence"); }
static const cepDT* dt_validation(void)  { return CEP_DTAW("CEP", "validation"); }
static const cepDT* dt_telemetry(void)   { return CEP_DTAW("CEP", "telemetry"); }
static const cepDT* dt_retain(void)      { return CEP_DTAW("CEP", "retain"); }
static const cepDT* dt_retain_mode(void) { return CEP_DTAW("CEP", "retain_mode"); }
static const cepDT* dt_retain_ttl(void)  { return CEP_DTAW("CEP", "retain_ttl"); }
static const cepDT* dt_retain_upto(void){ return CEP_DTAW("CEP", "retain_upto"); }
static const cepDT* dt_fingerprint(void) { return CEP_DTAW("CEP", "fingerprint"); }
static const cepDT* dt_dec_count(void)   { return CEP_DTAW("CEP", "dec_count"); }
static const cepDT* dt_inst_count(void)  { return CEP_DTAW("CEP", "inst_count"); }
static const cepDT* dt_site_count(void)  { return CEP_DTAW("CEP", "site_count"); }
static const cepDT* dt_latency(void)     { return CEP_DTAW("CEP", "latency"); }
static const cepDT* dt_lat_window(void)  { return CEP_DTAW("CEP", "lat_window"); }
static const cepDT* dt_err_window(void)  { return CEP_DTAW("CEP", "err_window"); }
static const cepDT* dt_score(void)       { return CEP_DTAW("CEP", "score"); }
static const cepDT* dt_confidence(void)  { return CEP_DTAW("CEP", "confidence"); }
static const cepDT* dt_rng_seed(void)    { return CEP_DTAW("CEP", "rng_seed"); }
static const cepDT* dt_rng_seq(void)     { return CEP_DTAW("CEP", "rng_seq"); }
static const cepDT* dt_error_flag(void)  { return CEP_DTAW("CEP", "error_flag"); }
static const cepDT* dt_meta(void)        { return CEP_DTAW("CEP", "meta"); }
static const cepDT* dt_variant_field(void) { return CEP_DTAW("CEP", "variant"); }
static const cepDT* dt_program_field(void) { return CEP_DTAW("CEP", "program"); }
static const cepDT* dt_policy_field(void)  { return CEP_DTAW("CEP", "policy"); }

#define CEP_L2_WINDOW_CAP 8u

typedef struct {
    size_t beat;
    size_t value;
    size_t flag;
} cepL2WindowSample;

typedef enum {
    CEP_L2_RETAIN_UNSPECIFIED = 0,
    CEP_L2_RETAIN_PERMANENT,
    CEP_L2_RETAIN_TTL,
    CEP_L2_RETAIN_ARCHIVE,
} cepL2RetentionMode;

typedef struct {
    cepL2RetentionMode mode;
    size_t             ttl;
} cepL2RetentionPlan;

/* Forward declarations for helpers used across the module. */
static cepCell* cep_l2_flow_root(void);
static cepCell* cep_l2_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage);
static bool     cep_l2_copy_request_payload(cepCell* request, cepCell* dst);
static bool     cep_l2_set_decimal_value(cepCell* parent, const cepDT* name, double value);
static bool     cep_l2_set_u64_value(cepCell* parent, const cepDT* name, uint64_t value);
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
static bool     cep_l2_extract_context_signature(cepCell* container, char* buffer, size_t cap);
static bool     cep_l2_extract_cell_identifier(cepCell* container, const cepDT* field, cepDT* out_dt, const char** out_text);
static const char* cep_l2_fetch_string(cepCell* container, const cepDT* field);
static bool     cep_l2_extract_identifier(cepCell* request, const cepDT* field, cepDT* out_dt, const char** out_text);
static bool     cep_l2_canonicalize_inst_start(cepCell* flow_root, cepCell* entry, cepCell* request, const char** error_code);
static bool     cep_l2_canonicalize_inst_event(cepCell* request, const char** error_code);
static bool     cep_l2_process_emits(cepCell* flow_root);
static bool     cep_l2_transform_spawn_rendezvous(cepCell* instance, cepCell* spec, cepBeatNumber now);
static cepCell* cep_l2_events_root(cepCell* instance);
static cepCell* cep_l2_event_entry_new(cepCell* instance,
                                       cepCell* request,
                                       cepBeatNumber now,
                                       size_t index_hint,
                                       const char* signal_text,
                                       bool targeted);
static bool     cep_l2_event_record_status(cepCell* event_entry,
                                           const char* status,
                                           const char* action,
                                           cepBeatNumber beat);
static cepCell* cep_l2_wait_entry_event(cepCell* entry);
static bool     cep_l2_wait_entry_attach_event(cepCell* entry, cepCell* event_entry);
static void     cep_l2_wait_entry_detach_event(cepCell* entry);
static cepCell* cep_l2_instance_latest_event(cepCell* instance);
static size_t   cep_l2_collect_event_samples(cepCell* instance,
                                             cepBeatNumber now,
                                             cepL2WindowSample* samples);
static bool     cep_l2_decision_build_fingerprint(const cepDT* inst_dt,
                                                  const char* site,
                                                  const cepDT* policy_dt,
                                                  const cepDT* variant_dt,
                                                  size_t pc,
                                                  char* buffer,
                                                  size_t cap);
static bool     cep_l2_decision_store_validation(cepCell* node,
                                                 const char* fingerprint,
                                                 const char* context_signature);
static bool     cep_l2_decision_validate_replay(cepCell* node,
                                                const char* fingerprint,
                                                const char* context_signature);
static bool     cep_l2_decision_record_evidence(cepCell* node,
                                                cepCell* instance,
                                                const char* context_signature);
static bool     cep_l2_decision_record_telemetry(cepCell* node,
                                                 cepCell* instance,
                                                 cepCell* policy_entry,
                                                 const char* choice,
                                                 const char* fingerprint,
                                                 const char* context_signature,
                                                 cepBeatNumber decision_beat);
static bool     cep_l2_decision_apply_retention(cepCell* node,
                                                cepCell* policy_entry,
                                                cepCell* spec,
                                                cepBeatNumber decision_beat);
static bool     cep_l2_decision_extract_telemetry(cepCell* decision,
                                                  cepL2WindowSample* sample);
static bool     cep_l2_enforce_retention(cepCell* flow_root, cepBeatNumber now);
static void     cep_l2_window_insert(cepL2WindowSample* samples,
                                     size_t* count,
                                     size_t beat,
                                     size_t value,
                                     size_t flag);
static bool     cep_l2_window_write(cepCell* parent,
                                    const cepDT* window_name,
                                    const cepL2WindowSample* samples,
                                    size_t count,
                                    bool use_flag);
static cepCell* cep_l2_mailroom_bucket(const cepDT* bucket_name);
static bool     cep_l2_tokens_to_identifier(const char* const tokens[], size_t token_count, char* out_buffer, size_t out_cap);
static bool     cep_l2_set_identifier_value(cepCell* parent, const cepDT* field,
                                            const char* const tokens[], size_t token_count);
static bool     cep_l2_set_text_field(cepCell* parent, const char* field, const char* value);
static bool     cep_l2_set_number_field(cepCell* parent, const char* field, size_t value);
static cepCell* cep_l2_ensure_field_dictionary(cepCell* parent, const char* field, unsigned storage);

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

static bool cep_l2_parse_u64_text(const char* text, uint64_t* out_value) {
    if (!text || !out_value) {
        return false;
    }

    errno = 0;
    char* endptr = NULL;
    unsigned long long value = strtoull(text, &endptr, 10);
    if (errno != 0 || endptr == text) {
        return false;
    }

    *out_value = (uint64_t)value;
    return true;
}

static bool cep_l2_parse_double_text(const char* text, double* out_value) {
    if (!text || !out_value) {
        return false;
    }

    errno = 0;
    char* endptr = NULL;
    double value = strtod(text, &endptr);
    if (errno != 0 || endptr == text) {
        return false;
    }

    *out_value = value;
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

static bool cep_l2_set_decimal_value(cepCell* parent, const cepDT* name, double value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%.6f", value);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return cep_l2_set_value_bytes(parent, name, dt_text(), buffer, (size_t)written + 1u);
}

static bool cep_l2_set_u64_value(cepCell* parent, const cepDT* name, uint64_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%llu", (unsigned long long)value);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return cep_l2_set_value_bytes(parent, name, dt_text(), buffer, (size_t)written + 1u);
}

static cepCell* cep_l2_mailroom_bucket(const cepDT* bucket_name) {
    if (!bucket_name) {
        return NULL;
    }

    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }

    cepCell* data_root = cep_l2_ensure_dictionary(root, dt_data_root(), CEP_STORAGE_RED_BLACK_T);
    if (!data_root) {
        return NULL;
    }

    cepCell* inbox_root = cep_l2_ensure_dictionary(data_root, dt_inbox(), CEP_STORAGE_RED_BLACK_T);
    if (!inbox_root) {
        return NULL;
    }

    cepCell* flow_ns = cep_l2_ensure_dictionary(inbox_root, dt_flow(), CEP_STORAGE_RED_BLACK_T);
    if (!flow_ns) {
        return NULL;
    }

    cepCell* bucket = cep_cell_find_by_name(flow_ns, bucket_name);
    if (!bucket) {
        cepDT name_copy = *bucket_name;
        cepDT dict_type = *dt_dictionary();
        bucket = cep_dict_add_dictionary(flow_ns, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    return bucket;
}

static bool cep_l2_tokens_to_identifier(const char* const tokens[], size_t token_count, char* out_buffer, size_t out_cap) {
    if (!tokens || !token_count || !out_buffer || out_cap == 0u) {
        return false;
    }
    return cep_compose_identifier(tokens, token_count, out_buffer, out_cap);
}

static bool cep_l2_set_identifier_value(cepCell* parent, const cepDT* field,
                                        const char* const tokens[], size_t token_count) {
    if (!parent || !field || !tokens || !token_count) {
        return false;
    }

    char canonical[CEP_IDENTIFIER_MAX + 1u];
    if (!cep_l2_tokens_to_identifier(tokens, token_count, canonical, sizeof canonical)) {
        return false;
    }

    return cep_l2_set_string_value(parent, field, canonical);
}

static bool cep_l2_set_text_field(cepCell* parent, const char* field, const char* value) {
    if (!parent || !field || !value) {
        return false;
    }

    cepDT field_dt = {0};
    if (!cep_l2_text_to_dt_bytes(field, strlen(field), &field_dt)) {
        return false;
    }

    return cep_l2_set_string_value(parent, &field_dt, value);
}

static cepID cep_l2_text_to_id(const char* text) {
    if (!text || !*text) {
        return 0;
    }

    cepID id = cep_text_to_word(text);
    if (!id) {
        id = cep_text_to_acronym(text);
    }
    if (!id) {
        cepID ref = cep_namepool_intern(text, strlen(text));
        if (!ref) {
            return 0;
        }
        id = ref;
    }

    return id;
}

static bool cep_l2_set_number_field(cepCell* parent, const char* field, size_t number) {
    if (!parent || !field) {
        return false;
    }

    cepDT field_dt = {0};
    if (!cep_l2_text_to_dt_bytes(field, strlen(field), &field_dt)) {
        return false;
    }

    return cep_l2_set_number_value(parent, &field_dt, number);
}

static cepCell* cep_l2_ensure_field_dictionary(cepCell* parent, const char* field, unsigned storage) {
    if (!parent || !field) {
        return NULL;
    }

    cepDT field_dt = {0};
    if (!cep_l2_text_to_dt_bytes(field, strlen(field), &field_dt)) {
        return NULL;
    }

    return cep_l2_ensure_dictionary(parent, &field_dt, storage);
}

bool cep_l2_definition_intent_init(cepL2DefinitionIntent* intent,
                                   const char* txn_word,
                                   const char* kind,
                                   const char* const id_tokens[], size_t id_token_count) {
    if (!intent || !txn_word || !kind || !id_tokens || !id_token_count) {
        return false;
    }

    cepCell* bucket = cep_l2_mailroom_bucket(dt_fl_upsert());
    if (!bucket) {
        return false;
    }

    cepDT txn_dt = {0};
    if (!cep_l2_text_to_dt_bytes(txn_word, strlen(txn_word), &txn_dt)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(bucket, &txn_dt);
    if (existing) {
        cep_cell_remove_hard(bucket, existing);
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    char canonical[CEP_IDENTIFIER_MAX + 1u];
    if (!cep_l2_tokens_to_identifier(id_tokens, id_token_count, canonical, sizeof canonical)) {
        return false;
    }

    if (!cep_l2_set_string_value(request, dt_kind(), kind)) {
        return false;
    }

    if (!cep_l2_set_string_value(request, dt_id(), canonical)) {
        return false;
    }

    intent->request = request;
    intent->next_step_index = 0u;
    return true;
}

cepCell* cep_l2_definition_intent_request(const cepL2DefinitionIntent* intent) {
    return intent ? intent->request : NULL;
}

cepCell* cep_l2_definition_intent_add_step(cepL2DefinitionIntent* intent, const char* step_kind) {
    if (!intent || !intent->request || !step_kind) {
        return NULL;
    }

    cepCell* steps = cep_cell_find_by_name(intent->request, dt_steps());
    if (!steps) {
        steps = cep_l2_ensure_dictionary(intent->request, dt_steps(), CEP_STORAGE_RED_BLACK_T);
        if (!steps) {
            return NULL;
        }
    }

    char key_buffer[32];
    int written = snprintf(key_buffer, sizeof key_buffer, "%zu", intent->next_step_index++);
    if (written <= 0 || (size_t)written >= sizeof key_buffer) {
        return NULL;
    }

    cepDT key_dt = {0};
    if (!cep_l2_text_to_dt_bytes(key_buffer, (size_t)written, &key_dt)) {
        return NULL;
    }

    cepCell* existing = cep_cell_find_by_name(steps, &key_dt);
    if (existing) {
        cep_cell_remove_hard(steps, existing);
    }

    cepDT dict_type = *dt_dictionary();
    cepDT key_copy = key_dt;
    cepCell* step = cep_dict_add_dictionary(steps, &key_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!step) {
        return NULL;
    }

    if (!cep_l2_set_string_value(step, dt_kind(), step_kind)) {
        return NULL;
    }

    return step;
}

cepCell* cep_l2_definition_step_ensure_spec(cepCell* step) {
    if (!step) {
        return NULL;
    }

    cepCell* spec = cep_cell_find_by_name(step, dt_spec());
    if (!spec) {
        cepDT dict_type = *dt_dictionary();
        cepDT spec_name = *dt_spec();
        spec = cep_dict_add_dictionary(step, &spec_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    return spec;
}

bool cep_l2_definition_intent_set_program(cepL2DefinitionIntent* intent,
                                          const char* const program_tokens[], size_t program_token_count) {
    if (!intent || !intent->request || !program_tokens || !program_token_count) {
        return false;
    }
    return cep_l2_set_identifier_value(intent->request, dt_program_field(), program_tokens, program_token_count);
}

bool cep_l2_definition_intent_set_variant(cepL2DefinitionIntent* intent,
                                          const char* const variant_tokens[], size_t variant_token_count) {
    if (!intent || !intent->request || !variant_tokens || !variant_token_count) {
        return false;
    }
    return cep_l2_set_identifier_value(intent->request, dt_variant_field(), variant_tokens, variant_token_count);
}

bool cep_l2_definition_intent_set_text(cepL2DefinitionIntent* intent,
                                       const char* field,
                                       const char* value) {
    if (!intent || !intent->request) {
        return false;
    }
    return cep_l2_set_text_field(intent->request, field, value);
}

/* Ensure the rendezvous spec dictionary exists before mutating it so callers
 * can compose step definitions declaratively. */
cepCell* cep_l2_definition_step_ensure_rendezvous(cepCell* step) {
    if (!step) {
        return NULL;
    }

    cepCell* spec = cep_l2_definition_step_ensure_spec(step);
    if (!spec) {
        return NULL;
    }

    cepCell* rv = cep_cell_find_by_name(spec, dt_rendezvous());
    if (!rv) {
        rv = cep_l2_ensure_dictionary(spec, dt_rendezvous(), CEP_STORAGE_RED_BLACK_T);
    }
    return rv;
}

/* Store a rendezvous parameter as plain text so higher layers can express spawn
 * settings without digging into dictionary plumbing. */
bool cep_l2_definition_step_set_rendezvous_text(cepCell* step,
                                                const char* field,
                                                const char* value) {
    if (!step) {
        return false;
    }

    cepCell* rv = cep_l2_definition_step_ensure_rendezvous(step);
    if (!rv) {
        return false;
    }

    return cep_l2_set_text_field(rv, field, value);
}

/* Keep profile-aware defaults close to the flow definition by writing them
 * under `spec/rendezvous/defaults/<profile>` so runtime assembly can merge the
 * correct plan automatically. */
bool cep_l2_definition_step_set_rendezvous_default(cepCell* step,
                                                    const char* profile,
                                                    const char* field,
                                                    const char* value) {
    if (!step || !profile || !*profile || !field || !value) {
        return false;
    }

    cepCell* rv = cep_l2_definition_step_ensure_rendezvous(step);
    if (!rv) {
        return false;
    }

    cepCell* defaults_root = cep_l2_ensure_dictionary(rv, dt_defaults(), CEP_STORAGE_RED_BLACK_T);
    if (!defaults_root) {
        return false;
    }

    cepDT profile_dt = {0};
    if (!cep_l2_text_to_dt_bytes(profile, strlen(profile), &profile_dt)) {
        return false;
    }

    cepCell* profile_bucket = cep_cell_find_by_name(defaults_root, &profile_dt);
    if (!profile_bucket) {
        cepDT dict_type = *dt_dictionary();
        cepDT name_copy = profile_dt;
        profile_bucket = cep_dict_add_dictionary(defaults_root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!profile_bucket) {
            return false;
        }
    }

    return cep_l2_set_text_field(profile_bucket, field, value);
}

bool cep_l2_niche_intent_init(cepL2NicheIntent* intent,
                              const char* txn_word,
                              const char* const id_tokens[], size_t id_token_count,
                              const char* const ctx_tokens[], size_t ctx_token_count,
                              const char* const variant_tokens[], size_t variant_token_count) {
    if (!intent || !txn_word || !id_tokens || !id_token_count || !ctx_tokens || !ctx_token_count || !variant_tokens || !variant_token_count) {
        return false;
    }

    cepCell* bucket = cep_l2_mailroom_bucket(dt_ni_upsert());
    if (!bucket) {
        return false;
    }

    cepDT txn_dt = {0};
    if (!cep_l2_text_to_dt_bytes(txn_word, strlen(txn_word), &txn_dt)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(bucket, &txn_dt);
    if (existing) {
        cep_cell_remove_hard(bucket, existing);
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    if (!cep_l2_set_identifier_value(request, dt_id(), id_tokens, id_token_count)) {
        return false;
    }

    if (!cep_l2_set_identifier_value(request, dt_ctx_type(), ctx_tokens, ctx_token_count)) {
        return false;
    }

    if (!cep_l2_set_identifier_value(request, dt_variant_field(), variant_tokens, variant_token_count)) {
        return false;
    }

    intent->request = request;
    return true;
}

cepCell* cep_l2_niche_intent_request(const cepL2NicheIntent* intent) {
    return intent ? intent->request : NULL;
}

bool cep_l2_instance_start_intent_init(cepL2InstanceStartIntent* intent,
                                       const char* txn_word,
                                       const char* const id_tokens[], size_t id_token_count,
                                       const char* const variant_tokens[], size_t variant_token_count) {
    if (!intent || !txn_word || !id_tokens || !id_token_count || !variant_tokens || !variant_token_count) {
        return false;
    }

    cepCell* bucket = cep_l2_mailroom_bucket(dt_inst_start());
    if (!bucket) {
        return false;
    }

    cepDT txn_dt = {0};
    if (!cep_l2_text_to_dt_bytes(txn_word, strlen(txn_word), &txn_dt)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(bucket, &txn_dt);
    if (existing) {
        cep_cell_remove_hard(bucket, existing);
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    if (!cep_l2_set_identifier_value(request, dt_id(), id_tokens, id_token_count)) {
        return false;
    }

    if (!cep_l2_set_identifier_value(request, dt_variant_field(), variant_tokens, variant_token_count)) {
        return false;
    }

    intent->request = request;
    return true;
}

cepCell* cep_l2_instance_start_intent_request(const cepL2InstanceStartIntent* intent) {
    return intent ? intent->request : NULL;
}

bool cep_l2_instance_start_intent_set_policy(cepL2InstanceStartIntent* intent,
                                             const char* const policy_tokens[], size_t policy_token_count) {
    if (!intent || !intent->request || !policy_tokens || !policy_token_count) {
        return false;
    }
    return cep_l2_set_identifier_value(intent->request, dt_policy_field(), policy_tokens, policy_token_count);
}

bool cep_l2_instance_start_intent_set_text(cepL2InstanceStartIntent* intent,
                                           const char* field,
                                           const char* value) {
    if (!intent || !intent->request) {
        return false;
    }
    return cep_l2_set_text_field(intent->request, field, value);
}

bool cep_l2_instance_event_intent_init(cepL2InstanceEventIntent* intent,
                                       const char* txn_word,
                                       const char* signal_path,
                                       const char* const id_tokens[], size_t id_token_count) {
    if (!intent || !txn_word || !signal_path || !*signal_path) {
        return false;
    }

    cepCell* bucket = cep_l2_mailroom_bucket(dt_inst_event());
    if (!bucket) {
        return false;
    }

    cepDT txn_dt = {0};
    if (!cep_l2_text_to_dt_bytes(txn_word, strlen(txn_word), &txn_dt)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(bucket, &txn_dt);
    if (existing) {
        cep_cell_remove_hard(bucket, existing);
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    if (id_tokens && id_token_count) {
        if (!cep_l2_set_identifier_value(request, dt_inst_id(), id_tokens, id_token_count)) {
            return false;
        }
    }

    if (!cep_l2_set_string_value(request, dt_signal_path(), signal_path)) {
        return false;
    }

    if (!cep_l2_set_string_value(request, dt_signal(), signal_path)) {
        return false;
    }

    intent->request = request;
    return true;
}

cepCell* cep_l2_instance_event_intent_request(const cepL2InstanceEventIntent* intent) {
    return intent ? intent->request : NULL;
}

cepCell* cep_l2_instance_event_intent_payload(cepL2InstanceEventIntent* intent) {
    if (!intent || !intent->request) {
        return NULL;
    }
    return cep_l2_ensure_field_dictionary(intent->request, "payload", CEP_STORAGE_RED_BLACK_T);
}

bool cep_l2_instance_control_intent_init(cepL2InstanceControlIntent* intent,
                                         const char* txn_word,
                                         const char* action,
                                         const char* const id_tokens[], size_t id_token_count) {
    if (!intent || !txn_word || !action || !*action) {
        return false;
    }

    cepCell* bucket = cep_l2_mailroom_bucket(dt_inst_ctrl());
    if (!bucket) {
        return false;
    }

    cepDT txn_dt = {0};
    if (!cep_l2_text_to_dt_bytes(txn_word, strlen(txn_word), &txn_dt)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(bucket, &txn_dt);
    if (existing) {
        cep_cell_remove_hard(bucket, existing);
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    if (id_tokens && id_token_count) {
        if (!cep_l2_set_identifier_value(request, dt_inst_id(), id_tokens, id_token_count)) {
            return false;
        }
    }

    if (!cep_l2_set_string_value(request, dt_action(), action)) {
        return false;
    }

    intent->request = request;
    return true;
}

cepCell* cep_l2_instance_control_intent_request(const cepL2InstanceControlIntent* intent) {
    return intent ? intent->request : NULL;
}

bool cep_l2_instance_control_intent_set_step_limit(cepL2InstanceControlIntent* intent, size_t step_limit) {
    if (!intent || !intent->request) {
        return false;
    }

    cepCell* budget = cep_l2_ensure_field_dictionary(intent->request, "budget", CEP_STORAGE_RED_BLACK_T);
    if (!budget) {
        return false;
    }

    if (!cep_l2_set_number_value(budget, dt_step_limit(), step_limit)) {
        return false;
    }

    (void)cep_l2_set_number_value(budget, dt_steps_used(), 0u);
    (void)cep_l2_set_number_field(intent->request, "step_limit", step_limit);
    return true;
}

bool cep_l2_instance_control_intent_set_text(cepL2InstanceControlIntent* intent,
                                             const char* field,
                                             const char* value) {
    if (!intent || !intent->request) {
        return false;
    }
    return cep_l2_set_text_field(intent->request, field, value);
}

cepCell* cep_l2_instance_control_intent_ensure_rendezvous(cepL2InstanceControlIntent* intent) {
    if (!intent || !intent->request) {
        return NULL;
    }
    return cep_l2_ensure_dictionary(intent->request, dt_rendezvous(), CEP_STORAGE_RED_BLACK_T);
}

bool cep_l2_instance_control_intent_set_rendezvous_key(cepL2InstanceControlIntent* intent, const char* key_text) {
    if (!intent || !key_text || !*key_text) {
        return false;
    }
    cepCell* rv = cep_l2_instance_control_intent_ensure_rendezvous(intent);
    if (!rv) {
        return false;
    }
    return cep_l2_set_string_value(rv, dt_key_field(), key_text);
}

bool cep_l2_instance_control_intent_set_rendezvous_text(cepL2InstanceControlIntent* intent, const char* field, const char* value) {
    if (!intent || !field || !value) {
        return false;
    }
    cepCell* rv = cep_l2_instance_control_intent_ensure_rendezvous(intent);
    if (!rv) {
        return false;
    }
    return cep_l2_set_text_field(rv, field, value);
}

bool cep_l2_instance_control_intent_set_rendezvous_number(cepL2InstanceControlIntent* intent, const char* field, size_t value) {
    if (!intent || !field) {
        return false;
    }
    cepCell* rv = cep_l2_instance_control_intent_ensure_rendezvous(intent);
    if (!rv) {
        return false;
    }
    cepDT field_dt = {0};
    if (!cep_l2_text_to_dt_bytes(field, strlen(field), &field_dt)) {
        return false;
    }
    return cep_l2_set_number_value(rv, &field_dt, value);
}

bool cep_l2_instance_control_intent_copy_rendezvous_telemetry(cepL2InstanceControlIntent* intent, const cepCell* telemetry_source) {
    if (!intent || !intent->request) {
        return false;
    }
    cepCell* rv = cep_l2_instance_control_intent_ensure_rendezvous(intent);
    if (!rv) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(rv, dt_telemetry());
    if (existing) {
        cep_cell_remove_hard(rv, existing);
    }

    if (!telemetry_source || !cep_cell_has_store((cepCell*)telemetry_source)) {
        return true;
    }

    cepDT name_copy = *dt_telemetry();
    cepDT dict_type = *dt_dictionary();
    cepCell* dest = cep_dict_add_dictionary(rv, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!dest) {
        return false;
    }

    for (cepCell* child = cep_cell_first((cepCell*)telemetry_source); child; child = cep_cell_next((cepCell*)telemetry_source, child)) {
        cepCell* clone = cep_cell_clone_deep(child);
        if (!clone) {
            return false;
        }
        cepCell* inserted = cep_cell_add(dest, 0, clone);
        if (!inserted) {
            cep_cell_finalize_hard(clone);
            cep_free(clone);
            return false;
        }
        cep_free(clone);
    }

    return true;
}

static void cep_l2_retention_plan_init(cepL2RetentionPlan* plan) {
    if (!plan) {
        return;
    }
    plan->mode = CEP_L2_RETAIN_UNSPECIFIED;
    plan->ttl = 0u;
}

static bool cep_l2_retention_parse_text(const char* text, cepL2RetentionPlan* plan) {
    if (!text || !plan) {
        return false;
    }

    char lowered[64];
    size_t idx = 0u;
    for (; text[idx] && idx + 1u < sizeof lowered; ++idx) {
        char c = text[idx];
        if (c >= 'A' && c <= 'Z') {
            c = (char)tolower((unsigned char)c);
        }
        lowered[idx] = c;
    }
    lowered[idx] = '\0';

    if (strcmp(lowered, "permanent") == 0) {
        plan->mode = CEP_L2_RETAIN_PERMANENT;
        plan->ttl = 0u;
        return true;
    }

    const char* ttl_text = NULL;
    if (strncmp(lowered, "ttl:", 4) == 0) {
        plan->mode = CEP_L2_RETAIN_TTL;
        ttl_text = lowered + 4;
    } else if (strncmp(lowered, "archive:", 8) == 0) {
        plan->mode = CEP_L2_RETAIN_ARCHIVE;
        ttl_text = lowered + 8;
    } else if (strcmp(lowered, "archive") == 0) {
        plan->mode = CEP_L2_RETAIN_ARCHIVE;
        plan->ttl = 0u;
        return true;
    } else {
        return false;
    }

    if (ttl_text && *ttl_text) {
        size_t ttl_value = 0u;
        if (!cep_l2_parse_size_text(ttl_text, &ttl_value)) {
            return false;
        }
        plan->ttl = ttl_value;
    } else {
        plan->ttl = 0u;
    }
    return true;
}

static bool cep_l2_retention_extract_plan(cepCell* container, cepL2RetentionPlan* plan) {
    if (!plan) {
        return false;
    }
    cep_l2_retention_plan_init(plan);
    if (!container) {
        return false;
    }

    cepCell* retain_node = cep_cell_find_by_name(container, dt_retain());
    if (!retain_node) {
        return false;
    }

    if (cep_cell_has_data(retain_node)) {
        const char* text = cep_l2_fetch_string(container, dt_retain());
        if (!text) {
            return false;
        }
        return cep_l2_retention_parse_text(text, plan);
    }

    if (!cep_cell_has_store(retain_node)) {
        return false;
    }

    /* When `retain` is expressed as a dictionary, prefer the `mode` field and
     * fall back to explicit keys such as `ttl` or `archive`. Unrecognised
     * layouts leave the plan unspecified so callers can fall back to defaults. */
    const char* mode_text = cep_l2_fetch_string(retain_node, dt_retain_mode());
    if (mode_text && cep_l2_retention_parse_text(mode_text, plan)) {
        if (plan->mode == CEP_L2_RETAIN_TTL || plan->mode == CEP_L2_RETAIN_ARCHIVE) {
            const char* ttl_text = cep_l2_fetch_string(retain_node, dt_retain_ttl());
            if (ttl_text && cep_l2_parse_size_text(ttl_text, &plan->ttl)) {
                return true;
            }
        }
        return true;
    }

    const char* ttl_text = cep_l2_fetch_string(retain_node, dt_retain_ttl());
    if (ttl_text && cep_l2_parse_size_text(ttl_text, &plan->ttl)) {
        plan->mode = CEP_L2_RETAIN_TTL;
        return true;
    }

    return false;
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

static bool cep_l2_canonicalize_inst_start(cepCell* flow_root,
                                           cepCell* entry,
                                           cepCell* request,
                                           const char** error_code) {
    if (error_code) {
        *error_code = NULL;
    }
    if (!entry || !request) {
        if (error_code) {
            *error_code = "inst-start-input";
        }
        return false;
    }

    cepCell* original = cep_l2_ensure_dictionary(entry, dt_original(), CEP_STORAGE_RED_BLACK_T);
    cepL2StoreLock original_lock = {0};
    if (original && cep_l2_store_lock(original, &original_lock)) {
        (void)cep_l2_copy_request_payload(request, original);
    }
    cep_l2_store_unlock(&original_lock);

    cepDT variant_dt = {0};
    const char* variant_text = NULL;
    bool has_variant = cep_l2_extract_identifier(request, dt_variant(), &variant_dt, &variant_text)
                    || cep_l2_extract_cell_identifier(request, dt_variant(), &variant_dt, &variant_text);
    if (!has_variant) {
        if (error_code) {
            *error_code = "missing-variant";
        }
        return false;
    }

    cepCell* variant_ledger = flow_root ? cep_cell_find_by_name(flow_root, dt_variant()) : NULL;
    if (!variant_ledger) {
        if (error_code) {
            *error_code = "variant-ledger";
        }
        return false;
    }

    cepCell* variant_entry = cep_cell_find_by_name(variant_ledger, &variant_dt);
    if (!variant_entry) {
        if (error_code) {
            *error_code = "unknown-variant";
        }
        return false;
    }

    bool variant_matches = false;
    cepCell* existing_variant = cep_cell_find_by_name(entry, dt_variant());
    if (existing_variant) {
        if (cep_cell_is_link(existing_variant)) {
            cepCell* target = cep_link_pull(existing_variant);
            const cepDT* target_dt = target ? cep_cell_get_name(target) : NULL;
            if (cep_l2_dt_equal(target_dt, &variant_dt)) {
                variant_matches = true;
            }
        } else if (cep_cell_has_data(existing_variant)) {
            const char* recorded = cep_l2_fetch_string(entry, dt_variant());
            char buffer[128];
            if (recorded && cep_l2_dt_to_text(&variant_dt, buffer, sizeof buffer)
                && strcmp(recorded, buffer) == 0) {
                variant_matches = true;
            }
        }
    }

    if (!variant_matches) {
        cep_l2_remove_field(entry, dt_variant());
        cepDT variant_name = *dt_variant();
        if (!cep_cell_add_link(entry, &variant_name, 0, variant_entry)) {
            if (!cep_l2_store_dt_string(entry, dt_variant(), &variant_dt)) {
                if (error_code) {
                    *error_code = "variant-store";
                }
                return false;
            }
        }
    }

    cepCell* variant_program = cep_cell_find_by_name(variant_entry, dt_program());
    if (variant_program) {
        if (cep_cell_is_link(variant_program)) {
            variant_program = cep_link_pull(variant_program);
        }
        if (variant_program) {
            cepCell* existing_program = cep_cell_find_by_name(entry, dt_program());
            bool keep_program = false;
            if (existing_program && cep_cell_is_link(existing_program)) {
                cepCell* target = cep_link_pull(existing_program);
                keep_program = (target == variant_program);
            }
            if (!keep_program) {
                cep_l2_remove_field(entry, dt_program());
                cepDT program_name = *dt_program();
                if (!cep_cell_add_link(entry, &program_name, 0, variant_program)) {
                    const cepDT* program_dt = cep_cell_get_name(variant_program);
                    if (program_dt) {
                        (void)cep_l2_store_dt_string(entry, dt_program(), program_dt);
                    }
                }
            }
        }
    }

    cepCell* entry_context = cep_cell_find_by_name(entry, dt_context());
    bool entry_has_context_store = entry_context && (cep_cell_has_store(entry_context) || cep_cell_is_link(entry_context));
    if (!entry_has_context_store) {
        char signature[128];
        if (cep_l2_extract_context_signature(request, signature, sizeof signature)) {
            cep_l2_set_string_value(entry, dt_context(), signature);
        }
    }

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

static cepCell* cep_l2_events_root(cepCell* instance) {
    if (!instance) {
        return NULL;
    }
    return cep_l2_ensure_dictionary(instance, dt_events(), CEP_STORAGE_RED_BLACK_T);
}

static cepCell* cep_l2_event_entry_new(cepCell* instance,
                                       cepCell* request,
                                       cepBeatNumber now,
                                       size_t index_hint,
                                       const char* signal_text,
                                       bool targeted) {
    cepCell* events = cep_l2_events_root(instance);
    if (!events) {
        return NULL;
    }

    size_t attempt = index_hint;
    for (size_t tries = 0u; tries < 32u; ++tries, ++attempt) {
        unsigned long long beat_value = (unsigned long long)now;
        char key_buf[32];
        int written = snprintf(key_buf, sizeof key_buf, "%llu_%zu", beat_value, attempt);
        if (written <= 0 || (size_t)written >= sizeof key_buf) {
            return NULL;
        }

        cepDT key_dt = {0};
        if (!cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
            return NULL;
        }

        if (cep_cell_find_by_name(events, &key_dt)) {
            continue;
        }

        cepCell* entry = cep_l2_ensure_dictionary(events, &key_dt, CEP_STORAGE_RED_BLACK_T);
        if (!entry) {
            return NULL;
        }

        cep_l2_clear_children(entry);
        if (!cep_l2_copy_request_payload(request, entry)) {
            return NULL;
        }

        cep_l2_set_number_value(entry, dt_beat(), (size_t)now);
        if (signal_text && *signal_text) {
            cep_l2_set_string_value(entry, dt_signal(), signal_text);
            cep_l2_set_string_value(entry, dt_signal_path(), signal_text);
        }
        cep_l2_set_string_value(entry, dt_origin(), targeted ? "target" : "broadcast");
        return entry;
    }

    return NULL;
}

static bool cep_l2_event_record_status(cepCell* event_entry,
                                       const char* status,
                                       const char* action,
                                       cepBeatNumber beat) {
    if (!event_entry) {
        return false;
    }

    if (status && *status) {
        (void)cep_l2_set_string_value(event_entry, dt_status(), status);
    }
    if (action && *action) {
        (void)cep_l2_set_string_value(event_entry, dt_action(), action);
    }
    if (beat != CEP_BEAT_INVALID) {
        (void)cep_l2_set_number_value(event_entry, dt_beat(), (size_t)beat);
    }

    cepCell* history = cep_l2_ensure_dictionary(event_entry, dt_history(), CEP_STORAGE_RED_BLACK_T);
    if (!history) {
        return false;
    }

    size_t suffix = cep_cell_children(history);
    unsigned long long beat_value = (beat == CEP_BEAT_INVALID) ? 0ull : (unsigned long long)beat;
    char key_buf[32];
    int written = snprintf(key_buf, sizeof key_buf, "%llu_%zu", beat_value, suffix);
    if (written <= 0 || (size_t)written >= sizeof key_buf) {
        return false;
    }

    cepDT key_dt = {0};
    if (!cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
        return false;
    }

    cepCell* record = cep_l2_ensure_dictionary(history, &key_dt, CEP_STORAGE_RED_BLACK_T);
    if (!record) {
        return false;
    }

    cep_l2_clear_children(record);
    if (status && *status) {
        (void)cep_l2_set_string_value(record, dt_status(), status);
    }
    if (action && *action) {
        (void)cep_l2_set_string_value(record, dt_action(), action);
    }
    if (beat != CEP_BEAT_INVALID) {
        (void)cep_l2_set_number_value(record, dt_beat(), (size_t)beat);
    }

    return true;
}

static cepCell* cep_l2_wait_entry_event(cepCell* entry) {
    if (!entry) {
        return NULL;
    }

    cepCell* link = cep_cell_find_by_name(entry, dt_event_ref());
    if (!link || !cep_cell_is_link(link)) {
        return NULL;
    }
    return cep_link_pull(link);
}

static bool cep_l2_wait_entry_attach_event(cepCell* entry, cepCell* event_entry) {
    if (!entry || !event_entry) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(entry, dt_event_ref());
    if (existing) {
        cep_cell_remove_hard(entry, existing);
    }

    cepDT link_name = *dt_event_ref();
    return cep_cell_add_link(entry, &link_name, 0, event_entry) != NULL;
}

static void cep_l2_wait_entry_detach_event(cepCell* entry) {
    if (!entry) {
        return;
    }

    cepCell* existing = cep_cell_find_by_name(entry, dt_event_ref());
    if (existing) {
        cep_cell_remove_hard(entry, existing);
    }
}

static cepCell* cep_l2_instance_latest_event(cepCell* instance) {
    if (!instance) {
        return NULL;
    }

    cepCell* events = cep_cell_find_by_name(instance, dt_events());
    if (!events || !cep_cell_has_store(events)) {
        return NULL;
    }

    cepCell* latest = NULL;
    size_t latest_beat = 0u;
    bool   have_beat = false;

    for (cepCell* event = cep_cell_first(events); event; event = cep_cell_next(events, event)) {
        if (!cep_cell_is_normal(event)) {
            continue;
        }

        const char* beat_text = cep_l2_fetch_string(event, dt_beat());
        size_t beat_value = 0u;
        if (beat_text && cep_l2_parse_size_text(beat_text, &beat_value)) {
            if (!have_beat || beat_value > latest_beat) {
                latest = event;
                latest_beat = beat_value;
                have_beat = true;
            }
        } else if (!latest) {
            latest = event;
        }
    }

    return latest;
}

/* Builds a rolling latency/error sample set from the instance event ledger. */
static size_t cep_l2_collect_event_samples(cepCell* instance,
                                           cepBeatNumber now,
                                           cepL2WindowSample* samples) {
    if (!instance || !samples) {
        return 0u;
    }

    cepCell* events = cep_cell_find_by_name(instance, dt_events());
    if (!events || !cep_cell_has_store(events)) {
        return 0u;
    }

    size_t now_value = (size_t)now;
    if (now == CEP_BEAT_INVALID) {
        now_value = (size_t)cep_heartbeat_current();
    }

    size_t count = 0u;

    for (cepCell* event = cep_cell_first(events); event; event = cep_cell_next(events, event)) {
        if (!cep_cell_is_normal(event) || !cep_cell_has_store(event)) {
            continue;
        }

        size_t event_beat = 0u;
        const char* beat_text = cep_l2_fetch_string(event, dt_beat());
        if (beat_text) {
            (void)cep_l2_parse_size_text(beat_text, &event_beat);
        }

        size_t completion = event_beat;
        size_t error_flag = 0u;

        cepCell* history = cep_cell_find_by_name(event, dt_history());
        if (history && cep_cell_has_store(history)) {
            for (cepCell* record = cep_cell_first(history); record; record = cep_cell_next(history, record)) {
                const char* record_beat_text = cep_l2_fetch_string(record, dt_beat());
                size_t record_beat = 0u;
                if (record_beat_text && cep_l2_parse_size_text(record_beat_text, &record_beat)) {
                    if (record_beat > completion) {
                        completion = record_beat;
                    }
                }

                const char* status = cep_l2_fetch_string(record, dt_status());
                if (status && (strcmp(status, "error") == 0 || strcmp(status, "timeout") == 0 || strcmp(status, "cancelled") == 0)) {
                    error_flag = 1u;
                }
            }
        }

        size_t effective_complete = completion;
        if (effective_complete < now_value) {
            effective_complete = now_value;
        }

        size_t latency = 0u;
        if (effective_complete >= event_beat) {
            latency = effective_complete - event_beat;
        }

        cep_l2_window_insert(samples, &count, event_beat, latency, error_flag);
    }

    return count;
}

static bool cep_l2_decision_build_fingerprint(const cepDT* inst_dt,
                                              const char* site,
                                              const cepDT* policy_dt,
                                              const cepDT* variant_dt,
                                              size_t pc,
                                              char* buffer,
                                              size_t cap) {
    if (!buffer || cap == 0u) {
        return false;
    }

    char inst_buf[128] = "unknown";
    char policy_buf[128] = "none";
    char variant_buf[128] = "none";

    if (inst_dt) {
        (void)cep_l2_dt_to_text(inst_dt, inst_buf, sizeof inst_buf);
    }
    if (policy_dt && policy_dt->tag) {
        (void)cep_l2_dt_to_text(policy_dt, policy_buf, sizeof policy_buf);
    }
    if (variant_dt && variant_dt->tag) {
        (void)cep_l2_dt_to_text(variant_dt, variant_buf, sizeof variant_buf);
    }

    const char* site_text = (site && *site) ? site : "default";

    int written = snprintf(buffer, cap, "%s|%s|%s|%s|%zu",
                           inst_buf,
                           site_text,
                           policy_buf,
                           variant_buf,
                           pc);

    return written > 0 && (size_t)written < cap;
}

static bool cep_l2_decision_store_validation(cepCell* node,
                                             const char* fingerprint,
                                             const char* context_signature) {
    if (!node) {
        return false;
    }

    cepCell* validation = cep_l2_ensure_dictionary(node, dt_validation(), CEP_STORAGE_RED_BLACK_T);
    if (!validation) {
        return false;
    }

    if (fingerprint && *fingerprint) {
        if (!cep_l2_set_string_value(validation, dt_fingerprint(), fingerprint)) {
            return false;
        }
    }

    if (context_signature && *context_signature) {
        if (!cep_l2_set_string_value(validation, dt_context(), context_signature)) {
            return false;
        }
    }

    return true;
}

static bool cep_l2_decision_validate_replay(cepCell* node,
                                            const char* fingerprint,
                                            const char* context_signature) {
    if (!node) {
        return false;
    }

    cepCell* validation = cep_cell_find_by_name(node, dt_validation());
    if (validation) {
        const char* stored_fp = cep_l2_fetch_string(validation, dt_fingerprint());
        if (stored_fp && fingerprint && strcmp(stored_fp, fingerprint) != 0) {
            return false;
        }

        const char* stored_context = cep_l2_fetch_string(validation, dt_context());
        if (stored_context && context_signature && strcmp(stored_context, context_signature) != 0) {
            return false;
        }
    }

    if (context_signature && *context_signature) {
        cepCell* evidence = cep_cell_find_by_name(node, dt_evidence());
        const char* evidence_context = evidence ? cep_l2_fetch_string(evidence, dt_context()) : NULL;
        if (evidence_context && strcmp(evidence_context, context_signature) != 0) {
            return false;
        }
    }

    return true;
}

static bool cep_l2_decision_record_evidence(cepCell* node,
                                            cepCell* instance,
                                            const char* context_signature) {
    if (!node) {
        return false;
    }

    if (cep_cell_find_by_name(node, dt_evidence())) {
        return true;
    }

    cepCell* evidence = cep_l2_ensure_dictionary(node, dt_evidence(), CEP_STORAGE_RED_BLACK_T);
    if (!evidence) {
        return false;
    }

    if (context_signature && *context_signature) {
        (void)cep_l2_set_string_value(evidence, dt_context(), context_signature);
    }

    const char* state = instance ? cep_l2_fetch_string(instance, dt_state()) : NULL;
    if (state) {
        (void)cep_l2_set_string_value(evidence, dt_state(), state);
    }

    cepCell* event_entry = cep_l2_instance_latest_event(instance);
    if (event_entry) {
        cepCell* existing = cep_cell_find_by_name(evidence, dt_event_ref());
        if (existing) {
            cep_cell_remove_hard(evidence, existing);
        }
        cepDT event_name = *dt_event_ref();
        (void)cep_cell_add_link(evidence, &event_name, 0, event_entry);

        const char* event_signal = cep_l2_fetch_string(event_entry, dt_signal());
        if (!event_signal) {
            event_signal = cep_l2_fetch_string(event_entry, dt_signal_path());
        }
        if (event_signal) {
            (void)cep_l2_set_string_value(evidence, dt_signal(), event_signal);
        }

        const char* origin = cep_l2_fetch_string(event_entry, dt_origin());
        if (origin) {
            (void)cep_l2_set_string_value(evidence, dt_origin(), origin);
        }

        const char* beat_text = cep_l2_fetch_string(event_entry, dt_beat());
        if (beat_text) {
            (void)cep_l2_set_string_value(evidence, dt_beat(), beat_text);
        }

        cepCell* payload = cep_cell_find_by_name(event_entry, dt_payload());
        if (payload && cep_cell_has_store(payload)) {
            cepCell* evidence_payload = cep_l2_ensure_dictionary(evidence, dt_payload(), CEP_STORAGE_RED_BLACK_T);
            if (evidence_payload) {
                cep_l2_clear_children(evidence_payload);
                (void)cep_l2_copy_request_payload(payload, evidence_payload);
            }
        }
    }

    return true;
}

/* Captures deterministic policy telemetry for newly recorded decisions so
 * replays and analytics share the same evidence. */
static bool cep_l2_decision_record_telemetry(cepCell* node,
                                             cepCell* instance,
                                             cepCell* policy_entry,
                                             const char* choice,
                                             const char* fingerprint,
                                             const char* context_signature,
                                             cepBeatNumber decision_beat) {
    if (!node) {
        return false;
    }

    cepCell* validation = cep_cell_find_by_name(node, dt_validation());
    if (!validation) {
        validation = cep_l2_ensure_dictionary(node, dt_validation(), CEP_STORAGE_RED_BLACK_T);
        if (!validation) {
            return false;
        }
    }

    cepCell* evidence = cep_cell_find_by_name(node, dt_evidence());
    if (!evidence) {
        evidence = cep_l2_ensure_dictionary(node, dt_evidence(), CEP_STORAGE_RED_BLACK_T);
        if (!evidence) {
            return false;
        }
    }

    cepCell* validation_tel = cep_l2_ensure_dictionary(validation, dt_telemetry(), CEP_STORAGE_RED_BLACK_T);
    cepCell* evidence_tel = cep_l2_ensure_dictionary(evidence, dt_telemetry(), CEP_STORAGE_RED_BLACK_T);
    if (!validation_tel || !evidence_tel) {
        return false;
    }

    uint64_t seed = 0u;

    if (fingerprint && *fingerprint) {
        seed ^= cep_hash_bytes(fingerprint, strlen(fingerprint));
    }

    if (context_signature && *context_signature) {
        seed ^= cep_hash_bytes(context_signature, strlen(context_signature));
    }

    if (choice && *choice) {
        seed ^= cep_hash_bytes(choice, strlen(choice));
    }

    if (instance) {
        const cepDT* inst_name = cep_cell_get_name(instance);
        if (inst_name) {
            char buffer[128];
            if (cep_l2_dt_to_text(inst_name, buffer, sizeof buffer)) {
                seed ^= cep_hash_bytes(buffer, strlen(buffer));
            }
        }
    }

    uint64_t rng_seed = seed;
    uint64_t rng_seq = seed;

    double score = 0.5;
    double confidence = 0.5;

    if (policy_entry) {
        cepCell* policy_tel = cep_cell_find_by_name(policy_entry, dt_telemetry());
        if (policy_tel) {
            const char* seed_text = cep_l2_fetch_string(policy_tel, dt_rng_seed());
            uint64_t parsed_seed = 0u;
            if (seed_text && cep_l2_parse_u64_text(seed_text, &parsed_seed)) {
                rng_seed = parsed_seed;
            }

            const char* seq_text = cep_l2_fetch_string(policy_tel, dt_rng_seq());
            uint64_t parsed_seq = 0u;
            if (seq_text && cep_l2_parse_u64_text(seq_text, &parsed_seq)) {
                rng_seq = parsed_seq;
            }

            const char* score_text = cep_l2_fetch_string(policy_tel, dt_score());
            double parsed_score = 0.0;
            if (score_text && cep_l2_parse_double_text(score_text, &parsed_score)) {
                score = parsed_score;
            }

            const char* conf_text = cep_l2_fetch_string(policy_tel, dt_confidence());
            double parsed_conf = 0.0;
            if (conf_text && cep_l2_parse_double_text(conf_text, &parsed_conf)) {
                confidence = parsed_conf;
            }
        }
    }

    if (score == 0.5) {
        uint64_t slice = rng_seed ? (rng_seed & 0xFFFFFFull) : (seed & 0xFFFFFFull);
        if (slice == 0ull) {
            slice = 1ull;
        }
        score = (double)slice / (double)0xFFFFFFull;
    }

    if (confidence == 0.5) {
        uint64_t slice = ((rng_seed ^ seed) >> 24) & 0xFFFFFFull;
        if (slice == 0ull) {
            slice = 1ull;
        }
        confidence = (double)slice / (double)0xFFFFFFull;
    }

    rng_seq ^= ((uint64_t)decision_beat << 32);

    size_t decision_beat_value = (size_t)decision_beat;
    if (decision_beat == CEP_BEAT_INVALID) {
        const char* beat_text = cep_l2_fetch_string(node, dt_beat());
        size_t parsed = 0u;
        if (beat_text && cep_l2_parse_size_text(beat_text, &parsed)) {
            decision_beat_value = parsed;
        } else {
            decision_beat_value = 0u;
        }
    }

    size_t latency = 0u;
    size_t error_flag = 0u;

    cepCell* event_entry = instance ? cep_l2_instance_latest_event(instance) : NULL;
    if (event_entry) {
        const char* event_beat_text = cep_l2_fetch_string(event_entry, dt_beat());
        size_t event_beat_value = 0u;
        if (event_beat_text && cep_l2_parse_size_text(event_beat_text, &event_beat_value)) {
            if (decision_beat_value >= event_beat_value) {
                latency = decision_beat_value - event_beat_value;
            }
        }

        cepCell* history = cep_cell_find_by_name(event_entry, dt_history());
        if (history && cep_cell_has_store(history)) {
            for (cepCell* record = cep_cell_first(history); record; record = cep_cell_next(history, record)) {
                const char* status = cep_l2_fetch_string(record, dt_status());
                if (status && (strcmp(status, "error") == 0 || strcmp(status, "timeout") == 0 || strcmp(status, "cancelled") == 0)) {
                    error_flag = 1u;
                    break;
                }
            }
        }
    }

    if (instance) {
        const char* inst_state = cep_l2_fetch_string(instance, dt_state());
        if (inst_state && strcmp(inst_state, "error") == 0) {
            error_flag = 1u;
        }
    }

    if (!cep_l2_set_decimal_value(validation_tel, dt_score(), score)) {
        return false;
    }
    if (!cep_l2_set_decimal_value(evidence_tel, dt_score(), score)) {
        return false;
    }

    if (!cep_l2_set_decimal_value(validation_tel, dt_confidence(), confidence)) {
        return false;
    }
    if (!cep_l2_set_decimal_value(evidence_tel, dt_confidence(), confidence)) {
        return false;
    }

    if (!cep_l2_set_u64_value(validation_tel, dt_rng_seed(), rng_seed)) {
        return false;
    }
    if (!cep_l2_set_u64_value(evidence_tel, dt_rng_seed(), rng_seed)) {
        return false;
    }

    if (!cep_l2_set_u64_value(validation_tel, dt_rng_seq(), rng_seq)) {
        return false;
    }
    if (!cep_l2_set_u64_value(evidence_tel, dt_rng_seq(), rng_seq)) {
        return false;
    }

    if (!cep_l2_set_number_value(validation_tel, dt_latency(), latency)) {
        return false;
    }
    if (!cep_l2_set_number_value(evidence_tel, dt_latency(), latency)) {
        return false;
    }

    if (!cep_l2_set_number_value(validation_tel, dt_error_flag(), error_flag)) {
        return false;
    }
    if (!cep_l2_set_number_value(evidence_tel, dt_error_flag(), error_flag)) {
        return false;
    }

    return true;
}

static bool cep_l2_decision_extract_telemetry(cepCell* decision,
                                              cepL2WindowSample* sample) {
    if (!decision || !sample) {
        return false;
    }

    cepL2WindowSample local = {
        .beat = 0u,
        .value = 0u,
        .flag = 0u,
    };

    const char* beat_text = cep_l2_fetch_string(decision, dt_beat());
    size_t beat_value = 0u;
    if (beat_text && cep_l2_parse_size_text(beat_text, &beat_value)) {
        local.beat = beat_value;
    }

    cepCell* validation = cep_cell_find_by_name(decision, dt_validation());
    cepCell* telemetry = validation ? cep_cell_find_by_name(validation, dt_telemetry()) : NULL;
    if (!telemetry) {
        cepCell* evidence = cep_cell_find_by_name(decision, dt_evidence());
        telemetry = evidence ? cep_cell_find_by_name(evidence, dt_telemetry()) : NULL;
    }

    if (!telemetry) {
        return false;
    }

    const char* latency_text = cep_l2_fetch_string(telemetry, dt_latency());
    if (!latency_text || !cep_l2_parse_size_text(latency_text, &local.value)) {
        return false;
    }

    const char* err_text = cep_l2_fetch_string(telemetry, dt_error_flag());
    if (err_text) {
        size_t err_value = 0u;
        if (cep_l2_parse_size_text(err_text, &err_value)) {
            local.flag = err_value;
        }
    }

    *sample = local;
    return true;
}

/* Retention enforcement prunes or archives expired decision cells before the
 * indexer rebuilds policy mirrors, keeping ledgers aligned with policy TTLs. */
static bool cep_l2_enforce_retention(cepCell* flow_root, cepBeatNumber now) {
    if (!flow_root) {
        flow_root = cep_l2_flow_root();
        if (!flow_root) {
            return false;
        }
    }

    cepCell* decisions = cep_cell_find_by_name(flow_root, dt_decision());
    if (!decisions || !cep_cell_has_store(decisions)) {
        return true;
    }

    cepCell* archive_root = cep_l2_ensure_dictionary(flow_root, dt_dec_archive(), CEP_STORAGE_RED_BLACK_T);
    if (!archive_root) {
        return false;
    }

    size_t now_value = (size_t)now;
    if (now == CEP_BEAT_INVALID) {
        now_value = (size_t)cep_heartbeat_current();
    }

    for (cepCell* inst_bucket = cep_cell_first(decisions); inst_bucket; inst_bucket = cep_cell_next(decisions, inst_bucket)) {
        if (!cep_cell_is_normal(inst_bucket) || !cep_cell_has_store(inst_bucket)) {
            continue;
        }

        const cepDT* inst_name = cep_cell_get_name(inst_bucket);
        cepCell* archive_bucket = inst_name ? cep_l2_ensure_dictionary(archive_root, inst_name, CEP_STORAGE_RED_BLACK_T) : NULL;

        cepL2StoreLock bucket_lock = {0};
        if (!cep_l2_store_lock(inst_bucket, &bucket_lock)) {
            continue;
        }

        for (cepCell* decision = cep_cell_first(inst_bucket); decision; ) {
            cepCell* next = cep_cell_next(inst_bucket, decision);

            const char* retain_directive = cep_l2_fetch_string(decision, dt_retain());
            cepL2RetentionPlan plan;
            cep_l2_retention_plan_init(&plan);
            bool plan_known = retain_directive && cep_l2_retention_parse_text(retain_directive, &plan);

            if (!plan_known) {
                const char* mode_text = cep_l2_fetch_string(decision, dt_retain_mode());
                if (mode_text) {
                    plan_known = cep_l2_retention_parse_text(mode_text, &plan);
                }
            }

            if (!plan_known || plan.mode == CEP_L2_RETAIN_PERMANENT) {
                decision = next;
                continue;
            }

            if (plan.ttl == 0u) {
                const char* ttl_text = cep_l2_fetch_string(decision, dt_retain_ttl());
                if (ttl_text) {
                    (void)cep_l2_parse_size_text(ttl_text, &plan.ttl);
                }
            }

            size_t retain_until = 0u;
            const char* until_text = cep_l2_fetch_string(decision, dt_retain_upto());
            if (until_text) {
                (void)cep_l2_parse_size_text(until_text, &retain_until);
            }

            if (retain_until == 0u && plan.ttl > 0u) {
                const char* beat_text = cep_l2_fetch_string(decision, dt_beat());
                size_t beat_value = 0u;
                if (beat_text && cep_l2_parse_size_text(beat_text, &beat_value)) {
                    retain_until = beat_value + plan.ttl;
                }
            }

            if (retain_until == 0u || now_value < retain_until) {
                decision = next;
                continue;
            }

            bool archive_mode = (plan.mode == CEP_L2_RETAIN_ARCHIVE);

            if (archive_mode && archive_bucket) {
                (void)cep_l2_clone_child_into(archive_bucket, decision);
            }

            cep_cell_remove_hard(inst_bucket, decision);
            decision = next;
        }

        cep_l2_store_unlock(&bucket_lock);
    }

    return true;
}

static bool cep_l2_decision_apply_retention(cepCell* node,
                                            cepCell* policy_entry,
                                            cepCell* spec,
                                            cepBeatNumber decision_beat) {
    if (!node) {
        return false;
    }

    cepL2RetentionPlan plan;
    cep_l2_retention_plan_init(&plan);

    cepL2RetentionPlan spec_plan;
    if (cep_l2_retention_extract_plan(spec, &spec_plan) && spec_plan.mode != CEP_L2_RETAIN_UNSPECIFIED) {
        plan = spec_plan;
    } else {
        cepL2RetentionPlan policy_plan;
        if (cep_l2_retention_extract_plan(policy_entry, &policy_plan) && policy_plan.mode != CEP_L2_RETAIN_UNSPECIFIED) {
            plan = policy_plan;
        } else {
            plan.mode = CEP_L2_RETAIN_PERMANENT;
            plan.ttl = 0u;
        }
    }

    if ((plan.mode == CEP_L2_RETAIN_TTL || plan.mode == CEP_L2_RETAIN_ARCHIVE) && plan.ttl == 0u) {
        plan.mode = CEP_L2_RETAIN_PERMANENT;
    }

    char directive[64];
    const char* directive_text = "permanent";
    const char* mode_text = "permanent";

    if (plan.mode == CEP_L2_RETAIN_TTL) {
        int written = snprintf(directive, sizeof directive, "ttl:%zu", plan.ttl);
        if (written <= 0 || (size_t)written >= sizeof directive) {
            return false;
        }
        directive_text = directive;
        mode_text = "ttl";
    } else if (plan.mode == CEP_L2_RETAIN_ARCHIVE) {
        int written = snprintf(directive, sizeof directive, "archive:%zu", plan.ttl);
        if (written <= 0 || (size_t)written >= sizeof directive) {
            return false;
        }
        directive_text = directive;
        mode_text = "archive";
    }

    if (!cep_l2_set_string_value(node, dt_retain(), directive_text)) {
        return false;
    }

    if (!cep_l2_set_string_value(node, dt_retain_mode(), mode_text)) {
        return false;
    }

    if (plan.mode == CEP_L2_RETAIN_PERMANENT) {
        cep_l2_remove_field(node, dt_retain_ttl());
        cep_l2_remove_field(node, dt_retain_upto());
        return true;
    }

    if (!cep_l2_set_number_value(node, dt_retain_ttl(), plan.ttl)) {
        return false;
    }

    size_t base_beat = (size_t)decision_beat;
    if (decision_beat == CEP_BEAT_INVALID) {
        const char* beat_text = cep_l2_fetch_string(node, dt_beat());
        size_t parsed = 0u;
        if (beat_text && cep_l2_parse_size_text(beat_text, &parsed)) {
            base_beat = parsed;
        } else {
            base_beat = 0u;
        }
    }

    size_t expires = base_beat + plan.ttl;
    if (!cep_l2_set_number_value(node, dt_retain_upto(), expires)) {
        return false;
    }

    return true;
}

static void cep_l2_window_insert(cepL2WindowSample* samples,
                                 size_t* count,
                                 size_t beat,
                                 size_t value,
                                 size_t flag) {
    if (!samples || !count) {
        return;
    }

    cepL2WindowSample sample = {
        .beat = beat,
        .value = value,
        .flag = flag,
    };

    size_t n = *count;
    if (n < CEP_L2_WINDOW_CAP) {
        samples[n] = sample;
        ++n;
    } else if (beat > samples[n - 1u].beat) {
        samples[n - 1u] = sample;
    } else {
        return;
    }

    size_t limit = n < CEP_L2_WINDOW_CAP ? n : CEP_L2_WINDOW_CAP;
    if (limit == 0u) {
        *count = 0u;
        return;
    }

    size_t idx = (n < CEP_L2_WINDOW_CAP) ? (n - 1u) : (CEP_L2_WINDOW_CAP - 1u);
    while (idx > 0u && samples[idx].beat > samples[idx - 1u].beat) {
        cepL2WindowSample tmp = samples[idx - 1u];
        samples[idx - 1u] = samples[idx];
        samples[idx] = tmp;
        --idx;
    }

    if (n > CEP_L2_WINDOW_CAP) {
        n = CEP_L2_WINDOW_CAP;
    }
    *count = n;
}

static bool cep_l2_window_write(cepCell* parent,
                                const cepDT* window_name,
                                const cepL2WindowSample* samples,
                                size_t count,
                                bool use_flag) {
    if (!parent || !window_name) {
        return false;
    }

    cepCell* window = cep_l2_ensure_dictionary(parent, window_name, CEP_STORAGE_RED_BLACK_T);
    if (!window) {
        return false;
    }

    cep_l2_clear_children(window);

    for (size_t i = 0u; i < count && i < CEP_L2_WINDOW_CAP; ++i) {
        char key_buf[4];
        int written = snprintf(key_buf, sizeof key_buf, "%02zu", i);
        if (written <= 0 || (size_t)written >= sizeof key_buf) {
            return false;
        }

        cepDT key_dt = {0};
        if (!cep_l2_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
            return false;
        }

        size_t value = use_flag ? samples[i].flag : samples[i].value;
        if (!cep_l2_set_number_value(window, &key_dt, value)) {
            return false;
        }
    }

    return true;
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

    const char* action_text = request ? cep_l2_fetch_string(request, dt_action()) : NULL;
    const char* effective_action = (action_text && *action_text) ? action_text : "deliver";
    bool cancel_requested = strcmp(effective_action, "cancel") == 0 || strcmp(effective_action, "withdraw") == 0;

    cepBeatNumber now = cep_heartbeat_current();

    char event_context[128];
    bool event_has_context = request ? cep_l2_extract_context_signature(request, event_context, sizeof event_context) : false;

    bool matched = false;

    if (cancel_requested) {
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

            if (!cep_l2_sub_entry_has_status(entry, "triggered")) {
                continue;
            }

            cepCell* event_entry = cep_l2_wait_entry_event(entry);
            if (event_entry) {
                (void)cep_l2_event_record_status(event_entry, "cancelled", effective_action, now);
            }

            cep_l2_wait_entry_detach_event(entry);
            cep_l2_sub_entry_set_string(entry, dt_status(), "pending");
            cep_l2_remove_field(entry, dt_payload());
            cep_l2_remove_field(entry, dt_beat());
            cep_l2_remove_field(entry, dt_origin());
            cep_l2_store_wait_context(entry, instance);
            matched = true;
        }

        if (matched) {
            const char* current_state = cep_l2_fetch_string(instance, dt_state());
            if (!current_state || strcmp(current_state, "ready") == 0) {
                cep_l2_set_string_value(instance, dt_state(), "waiting");
            }
        }

        return matched;
    }

    cepCell* events_root = cep_l2_events_root(instance);
    size_t event_index = events_root ? cep_cell_children(events_root) : 0u;

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
            cepCell* event_entry = cep_l2_wait_entry_event(entry);
            if (event_entry) {
                (void)cep_l2_event_record_status(event_entry, "duplicate", effective_action, now);
            }
            continue;
        }

        cepCell* event_entry = cep_l2_event_entry_new(instance, request, now, event_index, signal, targeted);
        if (!event_entry) {
            continue;
        }
        ++event_index;

        (void)cep_l2_event_record_status(event_entry, "queued", effective_action, now);
        if (event_has_context) {
            (void)cep_l2_set_string_value(event_entry, dt_context(), event_context);
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
        (void)cep_l2_event_record_status(event_entry, "triggered", effective_action, now);
        (void)cep_l2_wait_entry_attach_event(entry, event_entry);
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

    cepCell* subs = cep_cell_parent(entry);

    if (cep_l2_sub_entry_has_status(entry, "triggered")) {
        cepCell* event_entry = cep_l2_wait_entry_event(entry);
        if (event_entry) {
            (void)cep_l2_event_record_status(event_entry, "consumed", "step", cep_heartbeat_current());
        }
        cep_l2_wait_entry_detach_event(entry);
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
    bool        is_replay = (recorded != NULL);

    cepBeatNumber decision_beat = cep_heartbeat_current();
    size_t decision_beat_value = (size_t)decision_beat;

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
        (void)cep_l2_set_number_value(node, dt_beat(), decision_beat_value);
    } else {
        const char* beat_text = cep_l2_fetch_string(node, dt_beat());
        size_t parsed = 0u;
        if (beat_text && cep_l2_parse_size_text(beat_text, &parsed)) {
            decision_beat_value = parsed;
            decision_beat = (cepBeatNumber)parsed;
        }
    }

    cepDT policy_dt = {0};
    const char* policy_text = NULL;
    cepCell* policy_entry = NULL;
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
                policy_entry = target;
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
            policy_entry = policy_ledger ? cep_cell_find_by_name(policy_ledger, &policy_dt) : NULL;
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

    if (!policy_entry && has_policy) {
        cepCell* policy_ledger = cep_cell_find_by_name(flow_root, dt_policy());
        if (policy_ledger) {
            policy_entry = cep_cell_find_by_name(policy_ledger, &policy_dt);
        }
    }

    cepDT variant_dt = {0};
    bool has_variant_dt = cep_l2_instance_variant_dt(instance, &variant_dt);
    if (has_variant_dt) {
        cepCell* existing_variant = cep_cell_find_by_name(node, dt_variant());
        if (existing_variant) {
            if (cep_cell_is_link(existing_variant)) {
                cepCell* target = cep_link_pull(existing_variant);
                const cepDT* existing_dt = target ? cep_cell_get_name(target) : NULL;
                if (!cep_l2_dt_equal(existing_dt, &variant_dt)) {
                    result = CEP_L2_STEP_ERROR;
                    goto done;
                }
                variant_dt = existing_dt ? *existing_dt : variant_dt;
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

    char context_signature[128];
    bool has_context_signature = cep_l2_extract_context_signature(instance, context_signature, sizeof context_signature);

    char fingerprint[256];
    const cepDT* variant_dt_ptr = has_variant_dt ? &variant_dt : NULL;
    bool have_fingerprint = cep_l2_decision_build_fingerprint(inst_name,
                                                             site,
                                                             has_policy ? &policy_dt : NULL,
                                                             variant_dt_ptr,
                                                             pc,
                                                             fingerprint,
                                                             sizeof fingerprint);

    if (is_replay) {
        if (have_fingerprint && !cep_l2_decision_validate_replay(node,
                                                                 fingerprint,
                                                                 has_context_signature ? context_signature : NULL)) {
            result = CEP_L2_STEP_ERROR;
            goto done;
        }
        cep_serialization_mark_decision_replay();
    } else {
        if (have_fingerprint && !cep_l2_decision_store_validation(node,
                                                                  fingerprint,
                                                                  has_context_signature ? context_signature : NULL)) {
            result = CEP_L2_STEP_ERROR;
            goto done;
        }
        if (!cep_l2_decision_record_evidence(node,
                                              instance,
                                              has_context_signature ? context_signature : NULL)) {
            result = CEP_L2_STEP_ERROR;
            goto done;
        }
        const char* fingerprint_text = have_fingerprint ? fingerprint : NULL;
        const char* context_text = has_context_signature ? context_signature : NULL;

        if (!cep_l2_decision_record_telemetry(node,
                                              instance,
                                              policy_entry,
                                              choice,
                                              fingerprint_text,
                                              context_text,
                                              decision_beat)) {
            result = CEP_L2_STEP_ERROR;
            goto done;
        }

        if (!cep_l2_decision_apply_retention(node, policy_entry, spec, decision_beat)) {
            result = CEP_L2_STEP_ERROR;
            goto done;
        }
    }

done:
    cep_l2_store_unlock(&node_lock);
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

    const char* action_state = cep_l2_fetch_string(spec, dt_action());
    const char* default_block_state = action_state ? action_state : "waiting";
    const char* default_done_state = action_state ? action_state : "done";

    const char* required_state = cep_l2_fetch_string(spec, dt_state());
    if (required_state) {
        const char* current = cep_l2_fetch_string(instance, dt_state());
        if (!current || strcmp(current, required_state) != 0) {
            cep_l2_set_string_value(instance, dt_state(), default_done_state);
            return CEP_L2_STEP_BLOCK;
        }
    }

    const char* pc_text = cep_l2_fetch_string(spec, dt_pc());
    if (pc_text) {
        size_t expected_pc = 0u;
        if (!cep_l2_parse_size_text(pc_text, &expected_pc) || pc != expected_pc) {
            cep_l2_set_string_value(instance, dt_state(), default_done_state);
            return CEP_L2_STEP_BLOCK;
        }
    }

    const char* required_context = cep_l2_fetch_string(spec, dt_context());
    if (required_context && *required_context) {
        char current_signature[128];
        if (!cep_l2_extract_context_signature(instance, current_signature, sizeof current_signature)
            || strcmp(current_signature, required_context) != 0) {
            cep_l2_set_string_value(instance, dt_state(), default_block_state);
            return CEP_L2_STEP_BLOCK;
        }
    }

    cepBeatNumber now = cep_heartbeat_current();

    const char* earliest_text = cep_l2_fetch_string(spec, dt_beat());
    if (earliest_text && *earliest_text) {
        size_t earliest = 0u;
        if (!cep_l2_parse_size_text(earliest_text, &earliest)) {
            cep_l2_set_string_value(instance, dt_state(), "error");
            return CEP_L2_STEP_ERROR;
        }
        if ((size_t)now < earliest) {
            cep_l2_set_string_value(instance, dt_state(), default_block_state);
            return CEP_L2_STEP_BLOCK;
        }
    }

    const char* deadline_text = cep_l2_fetch_string(spec, dt_deadline());
    if (deadline_text && *deadline_text) {
        size_t deadline = 0u;
        if (!cep_l2_parse_size_text(deadline_text, &deadline)) {
            cep_l2_set_string_value(instance, dt_state(), "error");
            return CEP_L2_STEP_ERROR;
        }
        if ((size_t)now > deadline) {
            cep_l2_set_string_value(instance, dt_state(), default_done_state);
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

static bool cep_l2_transform_spawn_rendezvous(cepCell* instance, cepCell* spec, cepBeatNumber now) {
    if (!instance || !spec) {
        return true;
    }

    cepCell* rv_spec = cep_cell_find_by_name(spec, dt_rendezvous());
    if (!rv_spec || !cep_cell_has_store(rv_spec)) {
        return true;
    }

    const cepDT* inst_name = cep_cell_get_name(instance);
    if (!inst_name) {
        return false;
    }

    cepRvSpec rv = {0};
    char signal_buffer[CEP_IDENTIFIER_MAX + 32u];
    if (!cep_rv_prepare_spec(&rv, rv_spec, inst_name, now, signal_buffer, sizeof signal_buffer)) {
        return false;
    }

    if (!rv.key_dt.tag) {
        return false;
    }

    if (!cep_rv_spawn(&rv, rv.key_dt.tag)) {
        return false;
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

static bool cep_l2_emit_clone_into(cepCell* target, const cepCell* source_child, cepCell* const* parents, size_t parent_count) {
    if (!target || !source_child) {
        return false;
    }

    cepCell* clone = cep_cell_clone_deep(source_child);
    if (!clone) {
        return false;
    }

    cepCell* inserted = cep_cell_add(target, 0, clone);
    if (!inserted) {
        cep_cell_finalize_hard(clone);
        cep_free(clone);
        return false;
    }

    if (parents && parent_count) {
        (void)cep_cell_add_parents(inserted, parents, parent_count);
    }
    cep_cell_content_hash(inserted);
    cep_free(clone);
    return true;
}

static bool cep_l2_emit_apply_slot(cepCell* instance, cepCell* slot, bool* out_remove) {
    if (out_remove) {
        *out_remove = false;
    }
    if (!instance || !slot) {
        return false;
    }

    cepCell* target_field = cep_cell_find_by_name(slot, dt_target());
    if (!target_field) {
        cepCell* payload = cep_cell_find_by_name(slot, dt_payload());
        if (payload) {
            target_field = cep_cell_find_by_name(payload, dt_target());
        }
    }

    if (!target_field || !cep_cell_is_link(target_field)) {
        (void)cep_l2_set_string_value(slot, dt_status(), "missing-target");
        (void)cep_l2_set_string_value(slot, dt_outcome(), "error");
        return false;
    }

    cepCell* target = cep_link_pull(target_field);
    if (!target) {
        (void)cep_l2_set_string_value(slot, dt_status(), "target-unresolved");
        (void)cep_l2_set_string_value(slot, dt_outcome(), "error");
        return false;
    }

    cepCell* payload = cep_cell_find_by_name(slot, dt_payload());
    cepCell* parents[2];
    size_t parent_count = 0u;
    if (instance) {
        parents[parent_count++] = instance;
    }
    parents[parent_count++] = slot;

    cepL2StoreLock target_lock = {0};
    if (!cep_l2_store_lock(target, &target_lock)) {
        (void)cep_l2_set_string_value(slot, dt_status(), "target-lock");
        (void)cep_l2_set_string_value(slot, dt_outcome(), "error");
        return false;
    }

    bool success = true;

    if (payload && cep_cell_has_store(payload)) {
        for (cepCell* child = cep_cell_first(payload); child && success; child = cep_cell_next(payload, child)) {
            if (cep_cell_name_is(child, dt_target())) {
                continue;
            }
            success = cep_l2_emit_clone_into(target, child, parents, parent_count);
        }
    } else {
        for (cepCell* child = cep_cell_first(slot); child && success; child = cep_cell_next(slot, child)) {
            if (cep_cell_name_is(child, dt_pc())
                || cep_cell_name_is(child, dt_beat())
                || cep_cell_name_is(child, dt_signal())
                || cep_cell_name_is(child, dt_signal_path())
                || cep_cell_name_is(child, dt_target())
                || cep_cell_name_is(child, dt_payload())
                || cep_cell_name_is(child, dt_status())
                || cep_cell_name_is(child, dt_outcome())) {
                continue;
            }
            success = cep_l2_emit_clone_into(target, child, parents, parent_count);
        }
    }

    cep_l2_store_unlock(&target_lock);

    if (!success) {
        (void)cep_l2_set_string_value(slot, dt_status(), "emit-copy-failed");
        (void)cep_l2_set_string_value(slot, dt_outcome(), "error");
        return false;
    }

    cep_l2_set_string_value(slot, dt_status(), "done");
    cep_l2_set_string_value(slot, dt_outcome(), "ok");
    if (out_remove) {
        *out_remove = true;
    }
    return true;
}

static bool cep_l2_process_emits(cepCell* flow_root) {
    if (!flow_root) {
        return false;
    }

    cepCell* instances = cep_cell_find_by_name(flow_root, dt_instance());
    if (!instances || !cep_cell_has_store(instances)) {
        return false;
    }

    bool mutated = false;

    for (cepCell* instance = cep_cell_first(instances); instance; instance = cep_cell_next(instances, instance)) {
        if (!cep_cell_is_normal(instance)) {
            continue;
        }

        cepL2StoreLock inst_lock = {0};
        if (!cep_l2_store_lock(instance, &inst_lock)) {
            continue;
        }

        cepCell* emits = cep_cell_find_by_name(instance, dt_emits());
        if (!emits || !cep_cell_has_store(emits)) {
            cep_l2_store_unlock(&inst_lock);
            continue;
        }

        for (cepCell* slot = cep_cell_first(emits); slot; ) {
            cepCell* next = cep_cell_next(emits, slot);
            bool remove_slot = false;
            if (cep_l2_emit_apply_slot(instance, slot, &remove_slot) && remove_slot) {
                cep_cell_remove_hard(emits, slot);
                mutated = true;
            }
            slot = next;
        }

        cep_l2_store_unlock(&inst_lock);
    }

    return mutated;
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
    if (!cep_l2_transform_spawn_rendezvous(instance, spec, now)) {
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
    if (!cep_l2_ensure_dictionary(flow_root, dt_dec_archive(), CEP_STORAGE_RED_BLACK_T)) {
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
    if (!cep_l0_bootstrap()) {
        return false;
    }

    if (!cep_mailroom_seed_flow_errors()) {
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

    (void)cep_namepool_bootstrap();
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

        const char* canon_error = NULL;
        if (!cep_l2_canonicalize_inst_start(flow_root, entry, request, &canon_error)) {
            cep_l2_mark_outcome_error(request, canon_error ? canon_error : "inst-start-canon");
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
    } else if (strcmp(action, "rv_resched") == 0) {
        cepCell* rv_node = cep_cell_find_by_name(request, dt_rendezvous());
        if (!rv_node) {
            cep_l2_mark_outcome_error(request, "rv-missing");
            goto done;
        }

        cepDT rv_key = {0};
        if (!cep_l2_extract_identifier(rv_node, dt_key_field(), &rv_key, NULL) || !rv_key.tag) {
            cep_l2_mark_outcome_error(request, "rv-key");
            goto done;
        }

        size_t parsed_value = 0u;
        uint32_t delta = 0u;
        const char* delta_text = cep_l2_fetch_string(rv_node, dt_due_offset_field());
        if (delta_text && cep_l2_parse_size_text(delta_text, &parsed_value) && parsed_value <= UINT32_MAX) {
            delta = (uint32_t)parsed_value;
        } else {
            const char* due_text = cep_l2_fetch_string(rv_node, dt_due_field());
            if (due_text && cep_l2_parse_size_text(due_text, &parsed_value)) {
                cepBeatNumber now = cep_heartbeat_current();
                if (parsed_value >= (size_t)now) {
                    size_t diff = parsed_value - (size_t)now;
                    delta = (diff > UINT32_MAX) ? UINT32_MAX : (uint32_t)diff;
                }
            }
        }

        if (!cep_rv_resched(rv_key.tag, delta)) {
            cep_l2_mark_outcome_error(request, "rv-resched");
            goto done;
        }

        (void)cep_l2_copy_original_payload(entry, request);
    } else if (strcmp(action, "rv_kill") == 0) {
        cepCell* rv_node = cep_cell_find_by_name(request, dt_rendezvous());
        if (!rv_node) {
            cep_l2_mark_outcome_error(request, "rv-missing");
            goto done;
        }

        cepDT rv_key = {0};
        if (!cep_l2_extract_identifier(rv_node, dt_key_field(), &rv_key, NULL) || !rv_key.tag) {
            cep_l2_mark_outcome_error(request, "rv-key");
            goto done;
        }

        cepID kill_mode = 0;
        const char* mode_text = cep_l2_fetch_string(rv_node, dt_kill_mode_field());
        if (mode_text && *mode_text) {
            kill_mode = cep_l2_text_to_id(mode_text);
            if (!kill_mode) {
                cep_l2_mark_outcome_error(request, "rv-mode");
                goto done;
            }
        }

        size_t parsed_value = 0u;
        uint32_t wait_beats = 0u;
        const char* wait_text = cep_l2_fetch_string(rv_node, dt_kill_wait_field());
        if (wait_text && cep_l2_parse_size_text(wait_text, &parsed_value)) {
            wait_beats = (parsed_value > UINT32_MAX) ? UINT32_MAX : (uint32_t)parsed_value;
        }

        if (!cep_rv_kill(rv_key.tag, kill_mode, wait_beats)) {
            cep_l2_mark_outcome_error(request, "rv-kill");
            goto done;
        }

        (void)cep_l2_copy_original_payload(entry, request);
    } else if (strcmp(action, "rv_report") == 0) {
        cepCell* rv_node = cep_cell_find_by_name(request, dt_rendezvous());
        if (!rv_node) {
            cep_l2_mark_outcome_error(request, "rv-missing");
            goto done;
        }

        cepDT rv_key = {0};
        if (!cep_l2_extract_identifier(rv_node, dt_key_field(), &rv_key, NULL) || !rv_key.tag) {
            cep_l2_mark_outcome_error(request, "rv-key");
            goto done;
        }

        cepCell* telemetry = cep_cell_find_by_name(rv_node, dt_telemetry());
        if (!cep_rv_report(rv_key.tag, telemetry)) {
            cep_l2_mark_outcome_error(request, "rv-report");
            goto done;
        }

        (void)cep_l2_copy_original_payload(entry, request);
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

    if (cep_l2_process_emits(flow_root)) {
        pipeline_requested = true;
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

    cepBeatNumber now = cep_heartbeat_current();
    if (!cep_l2_enforce_retention(flow_root, now)) {
        return CEP_ENZYME_FATAL;
    }

    (void)now;

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

                cepCell* meta = cep_l2_ensure_dictionary(policy_bucket, dt_meta(), CEP_STORAGE_RED_BLACK_T);

                cepCell* inst_index = cep_l2_ensure_dictionary(policy_bucket, inst_name, CEP_STORAGE_RED_BLACK_T);
                if (!inst_index) {
                    continue;
                }

                bool instance_bucket_was_empty = cep_cell_children(inst_index) == 0u;

                const cepDT* site_name = cep_cell_get_name(decision);
                if (!site_name) {
                    continue;
                }

                cepCell* existing_site = cep_cell_find_by_name(inst_index, site_name);
                bool site_was_present = existing_site != NULL;
                if (existing_site) {
                    cep_cell_remove_hard(inst_index, existing_site);
                }

                cepDT site_copy = *site_name;
                (void)cep_cell_add_link(inst_index, &site_copy, 0, decision);

                if (meta) {
                    size_t dec_count = 0u;
                    const char* dec_text = cep_l2_fetch_string(meta, dt_dec_count());
                    if (dec_text) {
                        (void)cep_l2_parse_size_text(dec_text, &dec_count);
                    }
                    cep_l2_set_number_value(meta, dt_dec_count(), dec_count + 1u);

                    if (instance_bucket_was_empty) {
                        size_t inst_total = 0u;
                        const char* inst_text = cep_l2_fetch_string(meta, dt_inst_count());
                        if (inst_text) {
                            (void)cep_l2_parse_size_text(inst_text, &inst_total);
                        }
                        cep_l2_set_number_value(meta, dt_inst_count(), inst_total + 1u);
                    }

                    if (!site_was_present) {
                        size_t site_total = 0u;
                        const char* site_text = cep_l2_fetch_string(meta, dt_site_count());
                        if (site_text) {
                            (void)cep_l2_parse_size_text(site_text, &site_total);
                        }
                        cep_l2_set_number_value(meta, dt_site_count(), site_total + 1u);
                    }

                    const char* decision_choice = cep_l2_fetch_string(decision, dt_choice());
                    if (decision_choice) {
                        (void)cep_l2_set_string_value(meta, dt_choice(), decision_choice);
                    }

                    const char* decision_beat = cep_l2_fetch_string(decision, dt_beat());
                    if (decision_beat) {
                        (void)cep_l2_set_string_value(meta, dt_beat(), decision_beat);
                    }

                    const char* retain_text = cep_l2_fetch_string(decision, dt_retain());
                    if (retain_text) {
                        (void)cep_l2_set_string_value(meta, dt_retain(), retain_text);
                    }

                    cepCell* validation = cep_cell_find_by_name(decision, dt_validation());
                    if (validation) {
                        const char* fingerprint = cep_l2_fetch_string(validation, dt_fingerprint());
                        if (fingerprint) {
                            (void)cep_l2_set_string_value(meta, dt_fingerprint(), fingerprint);
                        }
                        const char* validation_context = cep_l2_fetch_string(validation, dt_context());
                        if (validation_context) {
                            (void)cep_l2_set_string_value(meta, dt_context(), validation_context);
                        }
                    }

                    cepCell* evidence = cep_cell_find_by_name(decision, dt_evidence());
                    if (evidence) {
                        const char* ev_context = cep_l2_fetch_string(evidence, dt_context());
                        if (ev_context) {
                            (void)cep_l2_set_string_value(meta, dt_context(), ev_context);
                        }
                        const char* ev_signal = cep_l2_fetch_string(evidence, dt_signal());
                        if (!ev_signal) {
                            ev_signal = cep_l2_fetch_string(evidence, dt_signal_path());
                        }
                        if (ev_signal) {
                            (void)cep_l2_set_string_value(meta, dt_signal(), ev_signal);
                        }
                        cepCell* ev_event = cep_cell_find_by_name(evidence, dt_event_ref());
                        if (ev_event && cep_cell_is_link(ev_event)) {
                            cepCell* target = cep_link_pull(ev_event);
                            if (target) {
                                cepCell* existing_event = cep_cell_find_by_name(meta, dt_event_ref());
                                if (existing_event) {
                                    cep_cell_remove_hard(meta, existing_event);
                                }
                                cepDT event_name = *dt_event_ref();
                                (void)cep_cell_add_link(meta, &event_name, 0, target);
                            }
                        }
                        cepCell* ev_payload = cep_cell_find_by_name(evidence, dt_payload());
                        if (ev_payload && cep_cell_has_store(ev_payload)) {
                            cepCell* meta_payload = cep_l2_ensure_dictionary(meta, dt_payload(), CEP_STORAGE_RED_BLACK_T);
                            if (meta_payload) {
                                cep_l2_clear_children(meta_payload);
                                (void)cep_l2_copy_request_payload(ev_payload, meta_payload);
                            }
                        }
                    }
                }
            }
        }
    }

    if (by_policy && cep_cell_has_store(by_policy)) {
        for (cepCell* policy_bucket = cep_cell_first(by_policy); policy_bucket; policy_bucket = cep_cell_next(by_policy, policy_bucket)) {
            if (!cep_cell_is_normal(policy_bucket) || !cep_cell_has_store(policy_bucket)) {
                continue;
            }

            cepCell* meta = cep_cell_find_by_name(policy_bucket, dt_meta());
            if (!meta) {
                continue;
            }

            cepL2WindowSample samples[CEP_L2_WINDOW_CAP] = {0};
            size_t sample_count = 0u;

            for (cepCell* inst_index = cep_cell_first(policy_bucket); inst_index; inst_index = cep_cell_next(policy_bucket, inst_index)) {
                if (cep_cell_name_is(inst_index, dt_meta())) {
                    continue;
                }
                if (!cep_cell_is_normal(inst_index) || !cep_cell_has_store(inst_index)) {
                    continue;
                }

                for (cepCell* site_link = cep_cell_first(inst_index); site_link; site_link = cep_cell_next(inst_index, site_link)) {
                    if (!cep_cell_is_link(site_link)) {
                        continue;
                    }
                    cepCell* decision = cep_link_pull(site_link);
                    if (!decision) {
                        continue;
                    }

                    cepL2WindowSample sample = {0};
                    if (cep_l2_decision_extract_telemetry(decision, &sample)) {
                        cep_l2_window_insert(samples, &sample_count, sample.beat, sample.value, sample.flag);
                    }
                }
            }

            if (sample_count > 0u) {
                (void)cep_l2_window_write(meta, dt_lat_window(), samples, sample_count, false);
                (void)cep_l2_window_write(meta, dt_err_window(), samples, sample_count, true);
            } else {
                cep_l2_remove_field(meta, dt_lat_window());
                cep_l2_remove_field(meta, dt_err_window());
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

    cepBeatNumber now = cep_heartbeat_current();

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

        cepL2WindowSample samples[CEP_L2_WINDOW_CAP] = {0};
        size_t sample_count = cep_l2_collect_event_samples(instance, now, samples);
        if (sample_count > 0u) {
            (void)cep_l2_window_write(summary, dt_lat_window(), samples, sample_count, false);
            (void)cep_l2_window_write(summary, dt_err_window(), samples, sample_count, true);
        } else {
            cep_l2_remove_field(summary, dt_lat_window());
            cep_l2_remove_field(summary, dt_err_window());
        }

        cepCell* latest_event = cep_l2_instance_latest_event(instance);
        size_t   latest_beat = 0u;

        if (latest_event) {
            const char* beat_text = cep_l2_fetch_string(latest_event, dt_beat());
            if (beat_text) {
                (void)cep_l2_parse_size_text(beat_text, &latest_beat);
            }
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

            const char* context = cep_l2_fetch_string(latest_event, dt_context());
            if (context) {
                cep_l2_set_string_value(summary, dt_context(), context);
            }

            cepCell* payload = cep_cell_find_by_name(latest_event, dt_payload());
            if (payload && cep_cell_has_store(payload)) {
                cepCell* summary_payload = cep_l2_ensure_dictionary(summary, dt_payload(), CEP_STORAGE_RED_BLACK_T);
                if (summary_payload) {
                    cep_l2_clear_children(summary_payload);
                    (void)cep_l2_copy_request_payload(payload, summary_payload);
                }
            }

            cepCell* existing_event = cep_cell_find_by_name(summary, dt_event_ref());
            if (existing_event) {
                cep_cell_remove_hard(summary, existing_event);
            }
            cepDT event_link_name = *dt_event_ref();
            (void)cep_cell_add_link(summary, &event_link_name, 0, latest_event);

            if (latest_beat) {
                cepBeatNumber latest_beat_number = (cepBeatNumber)latest_beat;
                size_t latency = 0u;
                if (now >= latest_beat_number) {
                    latency = (size_t)(now - latest_beat_number);
                }
                cep_l2_set_number_value(summary, dt_latency(), latency);
            } else {
                cep_l2_set_number_value(summary, dt_latency(), 0u);
            }
        } else {
            cep_l2_remove_field(summary, dt_latency());
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

    if (!cep_mailroom_register(registry)) {
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
