/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_rendezvous.h"

#include "cep_l2_flows.h"

#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_identifier.h"
#include "../l0_kernel/cep_namepool.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool cep_rv_ready = false;
static bool cep_rv_registry_registered = false;
static int  cep_rv_enzyme_init(const cepPath* signal, const cepPath* target);
static cepRvSpawnStatus cep_rv_last_status = CEP_RV_SPAWN_STATUS_OK;

static bool cep_rv_data_root_ready(void) {
    cep_cell_system_ensure();
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root || !cep_cell_is_normal(data_root)) {
        return false;
    }

    cepStore* store = data_root->store;
    if (!store || !cep_dt_is_valid(&store->dt)) {
        return false;
    }

    return true;
}

static const cepDT* dt_flow_root(void)      { return CEP_DTAW("CEP", "flow"); }
static const cepDT* dt_dictionary(void)     { return CEP_DTAW("CEP", "dictionary"); }
static const cepDT* dt_text(void)           { return CEP_DTAW("CEP", "text"); }
static const cepDT* dt_rv_root(void)        { return CEP_DTAW("CEP", "rv"); }
static const cepDT* dt_sig_sys(void)        { return CEP_DTAW("CEP", "sig_sys"); }
static const cepDT* dt_sys_init(void)       { return CEP_DTAW("CEP", "init"); }
static const cepDT* dt_rv_init(void)        { return CEP_DTAW("CEP", "rv_init"); }
static const cepDT* dt_prof(void)           { return CEP_DTAW("CEP", "prof"); }
static const cepDT* dt_spawn_beat(void)     { return CEP_DTAW("CEP", "spawn_beat"); }
static const cepDT* dt_due(void)            { return CEP_DTAW("CEP", "due"); }
static const cepDT* dt_epoch_k(void)        { return CEP_DTAW("CEP", "epoch_k"); }
static const cepDT* dt_input_fp(void)       { return CEP_DTAW("CEP", "input_fp"); }
static const cepDT* dt_cas_hash(void)       { return CEP_DTAW("CEP", "cas_hash"); }
static const cepDT* dt_state(void)          { return CEP_DTAW("CEP", "state"); }
/* TODO: audit the rendezvous ledger so every entry can reach the full
 * pending|ready|applied|late|timeout|killed|quarantine lifecycle described by
 * the `/data/rv` schema. */
static const cepDT* dt_on_miss(void)        { return CEP_DTAW("CEP", "on_miss"); }
static const cepDT* dt_grace_delta(void)    { return CEP_DTAW("CEP", "grace_delta"); }
static const cepDT* dt_grace_used(void)     { return CEP_DTAW("CEP", "grace_used"); }
static const cepDT* dt_max_grace(void)      { return CEP_DTAW("CEP", "max_grace"); }
static const cepDT* dt_deadline(void)       { return CEP_DTAW("CEP", "deadline"); }
static const cepDT* dt_kill_mode(void)      { return CEP_DTAW("CEP", "kill_mode"); }
static const cepDT* dt_kill_wait(void)      { return CEP_DTAW("CEP", "kill_wait"); }
static const cepDT* dt_signal_path(void)    { return CEP_DTAW("CEP", "signal_path"); }
static const cepDT* dt_ready_beat(void)     { return CEP_DTAW("CEP", "ready_beat"); }
static const cepDT* dt_applied_beat(void)   { return CEP_DTAW("CEP", "applied_bt"); }
static const cepDT* dt_payload(void)        { return CEP_DTAW("CEP", "payload"); }
static const cepDT* dt_inst_id(void)        { return CEP_DTAW("CEP", "inst_id"); }
static const cepDT* dt_profile(void)        { return CEP_DTAW("CEP", "profile"); }
static const cepDT* dt_telemetry(void)      { return CEP_DTAW("CEP", "telemetry"); }

static const cepDT* dt_key(void)           { return CEP_DTAW("CEP", "key"); }
static const cepDT* dt_profile_field(void) { return CEP_DTAW("CEP", "profile"); }
static const cepDT* dt_defaults(void)      { return CEP_DTAW("CEP", "defaults"); }
static const cepDT* dt_signal(void)        { return CEP_DTAW("CEP", "signal"); }
static const cepDT* dt_result(void)        { return CEP_DTAW("CEP", "result"); }
static const cepDT* dt_due_offset(void)    { return CEP_DTAW("CEP", "due_off"); }
static const cepDT* dt_deadline_offset(void){ return CEP_DTAW("CEP", "deadl_off"); }

static cepID cep_rv_text_to_id(const char* text);
static bool cep_rv_text_to_dt(const char* text, cepDT* out_dt);

static bool cep_rv_id_to_text(cepID id, char* buffer, size_t capacity) {
    if (!buffer || capacity == 0u) {
        return false;
    }

    if (cep_id_is_reference(id)) {
        size_t len = 0u;
        const char* text = cep_namepool_lookup(id, &len);
        if (!text || len + 1u > capacity) {
            return false;
        }
        memcpy(buffer, text, len);
        buffer[len] = '\0';
        return true;
    }

    size_t written = 0u;
    if (cep_id_is_word(id)) {
        written = cep_word_to_text(id, buffer);
    } else if (cep_id_is_acronym(id)) {
        written = cep_acronym_to_text(id, buffer);
    } else if (cep_id_is_numeric(id)) {
        int rc = snprintf(buffer, capacity, "%" PRIu64, (unsigned long long)cep_id(id));
        if (rc <= 0) {
            return false;
        }
        written = (size_t)rc;
    } else {
        if (capacity < 2u) {
            return false;
        }
        buffer[0] = '?';
        buffer[1] = '\0';
        return true;
    }

    if (written + 1u > capacity) {
        return false;
    }
    buffer[written] = '\0';
    return true;
}

static bool cep_rv_dt_to_text(const cepDT* dt, char* buffer, size_t capacity) {
    if (!dt || !buffer || capacity == 0u) {
        return false;
    }

    char domain[64];
    char tag[128];

    if (!cep_rv_id_to_text(dt->domain, domain, sizeof domain)) {
        return false;
    }
    if (!cep_rv_id_to_text(dt->tag, tag, sizeof tag)) {
        return false;
    }

    size_t domain_len = strlen(domain);
    size_t tag_len = strlen(tag);
    size_t needed = domain_len + 1u + tag_len;
    if (needed + 1u > capacity) {
        return false;
    }

    memcpy(buffer, domain, domain_len);
    buffer[domain_len] = ':';
    memcpy(buffer + domain_len + 1u, tag, tag_len);
    buffer[needed] = '\0';
    return true;
}

static const char* cep_rv_fetch_cstring(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* node = cep_cell_find_by_name(parent, name);
    if (!node || !cep_cell_has_data(node)) {
        return NULL;
    }

    const cepData* data = node->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return NULL;
    }

    return (const char*)data->value;
}

static bool cep_rv_remove_field(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        cep_cell_remove_hard(parent, existing);
    }
    return true;
}

static bool cep_rv_set_string(cepCell* parent, const cepDT* name, const char* text) {
    if (!parent || !name) {
        return false;
    }

    if (!text || !*text) {
        return cep_rv_remove_field(parent, name);
    }

    size_t len = strlen(text) + 1u;
    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing && cep_cell_has_data(existing)) {
        const cepData* data = existing->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size == len && memcmp(data->value, text, len) == 0) {
            return true;
        }
        cep_cell_remove_hard(parent, existing);
    } else if (existing) {
        cep_cell_remove_hard(parent, existing);
    }

    cepDT name_copy = *name;
    cepDT text_dt = *dt_text();
    cepCell* node = cep_dict_add_value(parent, &name_copy, &text_dt, (void*)text, len, len);
    if (!node) {
        return false;
    }
    cep_cell_content_hash(node);
    return true;
}

static bool cep_rv_set_number(cepCell* parent, const cepDT* name, uint64_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%" PRIu64, (unsigned long long)value);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return cep_rv_set_string(parent, name, buffer);
}

static bool cep_rv_parse_u64(const char* text, uint64_t* out_value) {
    if (!text || !out_value) {
        return false;
    }

    char* end = NULL;
    uint64_t parsed = (uint64_t)strtoull(text, &end, 10);
    if (!end || *end != '\0') {
        return false;
    }

    *out_value = parsed;
    return true;
}

static bool cep_rv_parse_u32(const char* text, uint32_t* out_value) {
    uint64_t parsed = 0u;
    if (!cep_rv_parse_u64(text, &parsed)) {
        return false;
    }
    if (parsed > UINT32_MAX) {
        return false;
    }
    *out_value = (uint32_t)parsed;
    return true;
}

static const char* cep_rv_fetch_with_default(cepCell* primary, cepCell* fallback, const cepDT* field) {
    const char* value = cep_rv_fetch_cstring(primary, field);
    if (!value && fallback) {
        value = cep_rv_fetch_cstring(fallback, field);
    }
    return value;
}

static cepCell* cep_rv_profile_defaults(cepCell* defaults_root, const char* profile_text) {
    if (!defaults_root || !cep_cell_has_store(defaults_root)) {
        return NULL;
    }

    if (profile_text && *profile_text) {
        cepDT profile_dt = {0};
        if (cep_rv_text_to_dt(profile_text, &profile_dt)) {
            cepCell* specific = cep_cell_find_by_name(defaults_root, &profile_dt);
            if (specific && cep_cell_has_store(specific)) {
                return specific;
            }
        }
    }

    cepDT fallback_dt = {0};
    if (cep_rv_text_to_dt("default", &fallback_dt)) {
        cepCell* fallback = cep_cell_find_by_name(defaults_root, &fallback_dt);
        if (fallback && cep_cell_has_store(fallback)) {
            return fallback;
        }
    }

    return NULL;
}

bool cep_rv_prepare_spec(cepRvSpec* out_spec,
                         const cepCell* spec_node,
                         const cepDT* instance_dt,
                         cepBeatNumber now,
                         char* signal_buffer,
                         size_t signal_capacity) {
    if (!out_spec || !spec_node || !instance_dt) {
        return false;
    }

    memset(out_spec, 0, sizeof *out_spec);
    out_spec->instance_dt = *instance_dt;

    cepCell* spec = (cepCell*)spec_node;
    if (!cep_cell_has_store(spec)) {
        return false;
    }

    const char* key_text = cep_rv_fetch_cstring(spec, dt_key());
    if (!key_text || !*key_text) {
        return false;
    }

    cepDT key_dt = {0};
    if (!cep_rv_text_to_dt(key_text, &key_dt)) {
        cepID key_id = cep_rv_text_to_id(key_text);
        if (!key_id) {
            return false;
        }
        key_dt.domain = CEP_ACRO("CEP");
        key_dt.tag = key_id;
    }
    out_spec->key_dt = key_dt;

    const char* profile_text = cep_rv_fetch_cstring(spec, dt_profile_field());
    if (!profile_text || !*profile_text) {
        profile_text = "rv-fixed";
    }

    cepID profile_id = cep_rv_text_to_id(profile_text);
    if (profile_id) {
        out_spec->prof = profile_id;
    }

    cepCell* defaults_root = cep_cell_find_by_name(spec, dt_defaults());
    cepCell* profile_defaults = cep_rv_profile_defaults(defaults_root, profile_text);

    const char* on_miss_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_on_miss());
    if (on_miss_text && *on_miss_text) {
        out_spec->on_miss = cep_rv_text_to_id(on_miss_text);
    }

    const char* kill_mode_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_kill_mode());
    if (kill_mode_text && *kill_mode_text) {
        out_spec->kill_mode = cep_rv_text_to_id(kill_mode_text);
    }

    uint32_t number32 = 0u;
    const char* kill_wait_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_kill_wait());
    if (kill_wait_text && cep_rv_parse_u32(kill_wait_text, &number32)) {
        out_spec->kill_wait = number32;
    }

    const char* cas_hash = cep_rv_fetch_with_default(spec, profile_defaults, dt_cas_hash());
    if (cas_hash && *cas_hash) {
        out_spec->cas_hash = cas_hash;
    }

    uint64_t number64 = 0u;
    const char* input_fp_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_input_fp());
    if (input_fp_text && cep_rv_parse_u64(input_fp_text, &number64)) {
        out_spec->input_fp = number64;
    }

    uint64_t due_value = (uint64_t)now;
    const char* due_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_due());
    const char* due_off_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_due_offset());
    if (due_text && cep_rv_parse_u64(due_text, &number64)) {
        due_value = number64;
    } else if (due_off_text && cep_rv_parse_u64(due_off_text, &number64)) {
        due_value = (uint64_t)now + number64;
    }
    out_spec->due = due_value;

    const char* deadline_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_deadline());
    const char* deadline_off_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_deadline_offset());
    if (deadline_text && cep_rv_parse_u64(deadline_text, &number64)) {
        out_spec->deadline = number64;
    } else if (deadline_off_text && cep_rv_parse_u64(deadline_off_text, &number64)) {
        out_spec->deadline = due_value + number64;
    }

    const char* epoch_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_epoch_k());
    if (epoch_text && cep_rv_parse_u32(epoch_text, &number32)) {
        out_spec->epoch_k = number32;
    }

    const char* grace_delta_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_grace_delta());
    if (grace_delta_text && cep_rv_parse_u32(grace_delta_text, &number32)) {
        out_spec->grace_delta = number32;
    }

    const char* max_grace_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_max_grace());
    if (max_grace_text && cep_rv_parse_u32(max_grace_text, &number32)) {
        out_spec->max_grace = number32;
    }

    const char* signal_path = cep_rv_fetch_with_default(spec, profile_defaults, dt_signal_path());
    if (!signal_path || !*signal_path) {
        const char* signal_text = cep_rv_fetch_with_default(spec, profile_defaults, dt_signal());
        if (signal_text && *signal_text) {
            signal_path = signal_text;
        }
    }

    if (!signal_path || !*signal_path) {
        if (!signal_buffer || signal_capacity == 0u) {
            return false;
        }
        if (!cep_rv_signal_for_key(&out_spec->key_dt, signal_buffer, signal_capacity)) {
            return false;
        }
        out_spec->signal_path = signal_buffer;
    } else {
        out_spec->signal_path = signal_path;
    }

    cepCell* telemetry = cep_cell_find_by_name(spec, dt_telemetry());
    if (!telemetry || !cep_cell_has_store(telemetry)) {
        telemetry = profile_defaults ? cep_cell_find_by_name(profile_defaults, dt_telemetry()) : NULL;
        if (telemetry && !cep_cell_has_store(telemetry)) {
            telemetry = NULL;
        }
    }
    out_spec->telemetry = telemetry;

    return true;
}

static bool cep_rv_copy_telemetry(cepCell* entry, const cepCell* telemetry) {
    if (!entry) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(entry, dt_telemetry());
    if (existing) {
        cep_cell_remove_hard(entry, existing);
    }

    if (!telemetry || !cep_cell_has_store((cepCell*)telemetry)) {
        return true;
    }

    cepDT name_copy = *dt_telemetry();
    cepDT dict_type = *dt_dictionary();
    cepCell* dest = cep_dict_add_dictionary(entry, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!dest) {
        return false;
    }

    for (cepCell* child = cep_cell_first((cepCell*)telemetry); child; child = cep_cell_next((cepCell*)telemetry, child)) {
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

static cepID cep_rv_text_to_id(const char* text) {
    if (!text || !*text) {
        return 0;
    }

    cepID id = cep_text_to_word(text);
    if (!id) {
        id = cep_text_to_acronym(text);
    }
    if (!id) {
        size_t len = strlen(text);
        cepID ref = cep_namepool_intern(text, len);
        if (!ref) {
            return 0;
        }
        id = ref;
    }

    return id;
}

static bool cep_rv_text_to_dt(const char* text, cepDT* out_dt) {
    if (!text || !out_dt) {
        return false;
    }

    const char* colon = strchr(text, ':');
    if (!colon) {
        cepID tag = cep_rv_text_to_id(text);
        if (!tag) {
            return false;
        }
        out_dt->domain = CEP_ACRO("CEP");
        out_dt->tag = tag;
        return true;
    }

    size_t domain_len = (size_t)(colon - text);
    size_t tag_len = strlen(colon + 1u);
    if (domain_len == 0u || tag_len == 0u) {
        return false;
    }

    char domain_buf[64];
    char tag_buf[128];
    if (domain_len >= sizeof domain_buf || tag_len >= sizeof tag_buf) {
        return false;
    }

    memcpy(domain_buf, text, domain_len);
    domain_buf[domain_len] = 0;
    memcpy(tag_buf, colon + 1u, tag_len);
    tag_buf[tag_len] = 0;

    cepID domain_id = cep_rv_text_to_id(domain_buf);
    cepID tag_id = cep_rv_text_to_id(tag_buf);
    if (!domain_id || !tag_id) {
        return false;
    }

    out_dt->domain = domain_id;
    out_dt->tag = tag_id;
    return true;
}

static cepCell* cep_rv_flow_root(void) {
    cep_cell_system_ensure();
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return NULL;
    }

    if (!cep_cell_has_store(data_root) || !cep_dt_is_valid(&data_root->store->dt)) {
        return NULL;
    }

    cepDT flow_dt = *dt_flow_root();
    flow_dt.glob = 0u;
    cepCell* flow_root = cep_cell_find_by_name(data_root, &flow_dt);
    if (!flow_root) {
        cepDT dict_type = *dt_dictionary();
        cepDT flow_name = flow_dt;
        flow_root = cep_dict_add_dictionary(data_root, &flow_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    return flow_root;
}

static cepCell* cep_rv_ledger(void) {
    cep_cell_system_ensure();
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return NULL;
    }

    if (!cep_cell_has_store(data_root) || !cep_dt_is_valid(&data_root->store->dt)) {
        return NULL;
    }

    cepDT ledger_dt = *dt_rv_root();
    ledger_dt.glob = 0u;
    cepCell* ledger = cep_cell_find_by_name(data_root, &ledger_dt);
    if (!ledger) {
        cepDT dict_type = *dt_dictionary();
        cepDT name_copy = ledger_dt;
        ledger = cep_dict_add_dictionary(data_root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    return ledger;
}

static bool cep_rv_enqueue_pipeline(void) {
    cepCell* flow_root = cep_rv_flow_root();
    if (!flow_root) {
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
            { .dt = *CEP_DTAW("CEP", "sig_cell"), .timestamp = 0u },
            { .dt = *CEP_DTAW("CEP", "op_add"),  .timestamp = 0u },
        },
    };

    cepPath* target_path = NULL;
    if (!cep_cell_path(flow_root, &target_path)) {
        return false;
    }

    int rc = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, (const cepPath*)&signal_path, target_path);
    cep_free(target_path);
    return rc != CEP_ENZYME_FATAL;
}

static bool cep_rv_emit_signal_for_request(cepCell* request) {
    if (!request) {
        return false;
    }

    cepPath* target_path = NULL;
    if (!cep_cell_path(request, &target_path)) {
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
            { .dt = *CEP_DTAW("CEP", "sig_cell"), .timestamp = 0u },
            { .dt = *CEP_DTAW("CEP", "op_add"),  .timestamp = 0u },
        },
    };

    int rc = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, (const cepPath*)&signal_path, target_path);
    cep_free(target_path);
    return rc != CEP_ENZYME_FATAL;
}

static bool cep_rv_instance_tokens(const cepDT* instance_dt,
                                   const char* tokens[],
                                   size_t* token_count,
                                   char domain_buf[], size_t domain_cap,
                                   char tag_buf[], size_t tag_cap) {
    if (!instance_dt || !tokens || !token_count) {
        return false;
    }

    if (!cep_rv_id_to_text(instance_dt->domain, domain_buf, domain_cap)) {
        return false;
    }

    if (!cep_rv_id_to_text(instance_dt->tag, tag_buf, tag_cap)) {
        return false;
    }

    tokens[0] = domain_buf;
    tokens[1] = tag_buf;
    *token_count = 2u;
    return true;
}

static cepCell* cep_rv_prepare_payload(cepCell* request) {
    if (!request) {
        return NULL;
    }

    cepCell* payload = cep_cell_find_by_name(request, dt_payload());
    if (!payload) {
        cepDT name_copy = *dt_payload();
        cepDT dict_type = *dt_dictionary();
        payload = cep_dict_add_dictionary(request, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    return payload;
}

static bool cep_rv_prepare_event_payload(cepCell* request,
                                         cepCell* entry,
                                         const char* state,
                                         const char* profile,
                                         const char* cas_hash,
                                         const char* key_text,
                                         const char* signal_path,
                                         uint64_t input_fp,
                                         uint64_t spawn_beat,
                                         uint64_t due,
                                         uint64_t applied_beat) {
    cepCell* payload = cep_rv_prepare_payload(request);
    if (!payload) {
        return false;
    }

    cep_rv_set_string(payload, dt_state(), state ? state : "unknown");

    if (profile && *profile) {
        cep_rv_set_string(payload, dt_profile(), profile);
    } else {
        cep_rv_remove_field(payload, dt_profile());
    }

    if (cas_hash && *cas_hash) {
        cep_rv_set_string(payload, dt_cas_hash(), cas_hash);
        cep_rv_set_string(payload, dt_result(), cas_hash);
    } else {
        cep_rv_remove_field(payload, dt_cas_hash());
        cep_rv_remove_field(payload, dt_result());
    }

    if (key_text && *key_text) {
        cep_rv_set_string(payload, dt_key(), key_text);
    } else {
        cep_rv_remove_field(payload, dt_key());
    }

    if (signal_path && *signal_path) {
        cep_rv_set_string(payload, dt_signal(), signal_path);
    } else {
        cep_rv_remove_field(payload, dt_signal());
    }

    if (input_fp) {
        cep_rv_set_number(payload, dt_input_fp(), input_fp);
    } else {
        cep_rv_remove_field(payload, dt_input_fp());
    }

    if (spawn_beat) {
        cep_rv_set_number(payload, dt_spawn_beat(), spawn_beat);
    } else {
        cep_rv_remove_field(payload, dt_spawn_beat());
    }

    if (due) {
        cep_rv_set_number(payload, dt_due(), due);
    } else {
        cep_rv_remove_field(payload, dt_due());
    }

    if (applied_beat) {
        cep_rv_set_number(payload, dt_applied_beat(), applied_beat);
    } else {
        cep_rv_remove_field(payload, dt_applied_beat());
    }

    cepCell* telemetry_src = cep_cell_find_by_name(entry, dt_telemetry());
    if (telemetry_src && cep_cell_has_store(telemetry_src)) {
        (void)cep_rv_copy_telemetry(payload, telemetry_src);
    }

    return true;
}

static void cep_rv_transition_timeout(cepCell* entry, const char* policy) {
    if (!entry) {
        return;
    }

    if (policy && strcmp(policy, "ignore") == 0) {
        return;
    }

    if (policy && strcmp(policy, "kill") == 0) {
        cep_rv_set_string(entry, dt_state(), "killed");
    } else if (policy && strcmp(policy, "timeout") == 0) {
        cep_rv_set_string(entry, dt_state(), "timeout");
    } else {
        cep_rv_set_string(entry, dt_state(), "late");
    }
}

static bool cep_rv_emit_event_for_entry(cepCell* entry, const char* state) {
    if (!entry) {
        return false;
    }

    const char* signal_path = cep_rv_fetch_cstring(entry, dt_signal_path());
    const char* inst_text = cep_rv_fetch_cstring(entry, dt_inst_id());
    if (!signal_path || !*signal_path || !inst_text || !*inst_text) {
        return false;
    }

    cepDT inst_dt = {0};
    if (!cep_rv_text_to_dt(inst_text, &inst_dt)) {
        return false;
    }

    char domain_buf[64];
    char tag_buf[128];
    const char* tokens[2];
    size_t token_count = 0u;
    if (!cep_rv_instance_tokens(&inst_dt, tokens, &token_count, domain_buf, sizeof domain_buf, tag_buf, sizeof tag_buf)) {
        return false;
    }

    char txn_buf[128];
    const cepDT* entry_name = cep_cell_get_name(entry);
    if (!entry_name) {
        return false;
    }
    char key_text[128];
    if (!cep_rv_dt_to_text(entry_name, key_text, sizeof key_text)) {
        return false;
    }

    cepBeatNumber now = cep_heartbeat_current();
    int txn_written = snprintf(txn_buf, sizeof txn_buf, "rv-%s-%" PRIu64, key_text, (unsigned long long)now);
    if (txn_written <= 0 || (size_t)txn_written >= sizeof txn_buf) {
        return false;
    }

    cepL2InstanceEventIntent intent = {0};
    if (!cep_l2_instance_event_intent_init(&intent, txn_buf, signal_path, tokens, token_count)) {
        return false;
    }

    cepCell* request = cep_l2_instance_event_intent_request(&intent);
    if (!request) {
        return false;
    }

    uint64_t spawn_beat = 0u;
    uint64_t due_value = 0u;
    uint64_t applied_beat = (uint64_t)now;
    uint64_t input_fp = 0u;

    const char* spawn_text = cep_rv_fetch_cstring(entry, dt_spawn_beat());
    if (spawn_text) {
        cep_rv_parse_u64(spawn_text, &spawn_beat);
    }
    const char* due_text = cep_rv_fetch_cstring(entry, dt_due());
    if (due_text) {
        cep_rv_parse_u64(due_text, &due_value);
    }
    const char* fp_text = cep_rv_fetch_cstring(entry, dt_input_fp());
    if (fp_text) {
        cep_rv_parse_u64(fp_text, &input_fp);
    }

    const char* profile = cep_rv_fetch_cstring(entry, dt_prof());
    const char* cas_hash = cep_rv_fetch_cstring(entry, dt_cas_hash());

    cep_rv_prepare_event_payload(request,
                                 entry,
                                 state,
                                 profile,
                                 cas_hash,
                                 key_text,
                                 signal_path,
                                 input_fp,
                                 spawn_beat,
                                 due_value,
                                 applied_beat);

    cep_rv_emit_signal_for_request(request);
    cep_rv_enqueue_pipeline();

    return true;
}

bool cep_rv_bootstrap(void) {
    if (!cep_rv_data_root_ready()) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_DATA_ROOT;
        return false;
    }

    cepCell* ledger = cep_rv_ledger();
    if (ledger) {
        if (!cep_cell_has_store(ledger)) {
            cepDT dict_type = *dt_dictionary();
            dict_type.glob = 0u;
            cepStore* store = cep_store_new(&dict_type, CEP_STORAGE_RED_BLACK_T, CEP_INDEX_BY_NAME);
            if (!store) {
                cep_rv_last_status = CEP_RV_SPAWN_STATUS_ENTRY_ALLOC;
                return false;
            }
            cep_cell_set_store(ledger, store);
        } else if (ledger->store->indexing != CEP_INDEX_BY_NAME) {
            cep_cell_to_dictionary(ledger);
        }
        cep_rv_ready = true;
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_OK;
    }
    if (!ledger) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_LEDGER_MISSING;
    }
    return ledger != NULL;
}

static int cep_rv_enzyme_init(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    return cep_rv_bootstrap() ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static cepCell* cep_rv_find_entry(cepCell* ledger, cepID key) {
    if (!ledger) {
        return NULL;
    }

    for (cepCell* child = cep_cell_first(ledger); child; child = cep_cell_next(ledger, child)) {
        if (!cep_cell_is_normal(child)) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(child);
        if (name && name->tag == key) {
            return child;
        }
    }
    return NULL;
}

bool cep_rv_spawn(const cepRvSpec* spec, cepID key) {
    if (!spec) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_NO_SPEC;
        return false;
    }

    if (!cep_rv_bootstrap()) {
        return false;
    }

    cepCell* ledger = cep_rv_ledger();
    if (!ledger) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_LEDGER_MISSING;
        return false;
    }

    if (!cep_cell_has_store(ledger)) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_LEDGER_MISSING;
        return false;
    }

    if (cep_cell_store_locked_hierarchy(ledger)) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_LEDGER_LOCK;
        return false;
    }

    cepCell* entry = cep_rv_find_entry(ledger, key);
    if (!entry) {
        cepDT name_dt = spec->key_dt;
        if (!name_dt.domain) {
            name_dt.domain = CEP_ACRO("CEP");
        }
        if (!name_dt.tag) {
            name_dt.tag = key;
        }
        cepDT dict_type = *dt_dictionary();
        entry = cep_dict_add_dictionary(ledger, &name_dt, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    /* TODO: double-check rv_spawn writes the initial `state=pending` record plus
     * every default ledger field so replay tooling can rely on the schema
     * without defensive guards. */
    if (!entry) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_ENTRY_ALLOC;
        return false;
    }

    if (cep_cell_store_locked_hierarchy(entry)) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_ENTRY_LOCK;
        return false;
    }

    if (!cep_cell_has_store(entry) || !cep_store_valid(entry->store)) {
        cepDT dict_type = *dt_dictionary();
        cepStore* store = cep_store_new(&dict_type, CEP_STORAGE_RED_BLACK_T, CEP_INDEX_BY_NAME);
        if (!store) {
            cep_rv_last_status = CEP_RV_SPAWN_STATUS_ENTRY_ALLOC;
            return false;
        }
        cep_cell_set_store(entry, store);
    } else if (entry->store->indexing != CEP_INDEX_BY_NAME) {
        cep_cell_to_dictionary(entry);
    }

    cepLockToken entry_lock = {0};
    if (!cep_store_lock(entry, &entry_lock)) {
        cep_rv_last_status = CEP_RV_SPAWN_STATUS_ENTRY_LOCK;
        return false;
    }

    cepBeatNumber now = cep_heartbeat_current();

    cep_rv_set_number(entry, dt_spawn_beat(), (uint64_t)now);
    cep_rv_set_number(entry, dt_due(), spec->due);

    if (spec->epoch_k) {
        cep_rv_set_number(entry, dt_epoch_k(), spec->epoch_k);
    } else {
        cep_rv_remove_field(entry, dt_epoch_k());
    }

    if (spec->input_fp) {
        cep_rv_set_number(entry, dt_input_fp(), spec->input_fp);
    } else {
        cep_rv_remove_field(entry, dt_input_fp());
    }

    if (spec->deadline) {
        cep_rv_set_number(entry, dt_deadline(), spec->deadline);
    } else {
        cep_rv_remove_field(entry, dt_deadline());
    }

    if (spec->grace_delta) {
        cep_rv_set_number(entry, dt_grace_delta(), spec->grace_delta);
    } else {
        cep_rv_remove_field(entry, dt_grace_delta());
    }

    if (spec->max_grace) {
        cep_rv_set_number(entry, dt_max_grace(), spec->max_grace);
    } else {
        cep_rv_remove_field(entry, dt_max_grace());
    }

    if (spec->kill_wait) {
        cep_rv_set_number(entry, dt_kill_wait(), spec->kill_wait);
    } else {
        cep_rv_remove_field(entry, dt_kill_wait());
    }

    if (spec->prof) {
        char buffer[64];
        if (cep_rv_id_to_text(spec->prof, buffer, sizeof buffer)) {
            cep_rv_set_string(entry, dt_prof(), buffer);
        }
    } else {
        cep_rv_set_string(entry, dt_prof(), "rv-fixed");
    }

    if (spec->on_miss) {
        char buffer[64];
        if (cep_rv_id_to_text(spec->on_miss, buffer, sizeof buffer)) {
            cep_rv_set_string(entry, dt_on_miss(), buffer);
        }
    } else {
        cep_rv_remove_field(entry, dt_on_miss());
    }

    if (spec->kill_mode) {
        char buffer[64];
        if (cep_rv_id_to_text(spec->kill_mode, buffer, sizeof buffer)) {
            cep_rv_set_string(entry, dt_kill_mode(), buffer);
        }
    } else {
        cep_rv_remove_field(entry, dt_kill_mode());
    }

    if (spec->signal_path && *spec->signal_path) {
        cep_rv_set_string(entry, dt_signal_path(), spec->signal_path);
    } else {
        char signal_buf[CEP_IDENTIFIER_MAX + 32u];
        if (cep_rv_signal_for_key(&spec->key_dt, signal_buf, sizeof signal_buf)) {
            cep_rv_set_string(entry, dt_signal_path(), signal_buf);
        }
    }

    if (spec->cas_hash && *spec->cas_hash) {
        cep_rv_set_string(entry, dt_cas_hash(), spec->cas_hash);
    } else {
        cep_rv_remove_field(entry, dt_cas_hash());
    }

    if (spec->instance_dt.tag) {
        char inst_buf[CEP_IDENTIFIER_MAX + 1u];
        if (cep_rv_dt_to_text(&spec->instance_dt, inst_buf, sizeof inst_buf)) {
            cep_rv_set_string(entry, dt_inst_id(), inst_buf);
        }
    }

    if (spec->telemetry) {
        cep_rv_copy_telemetry(entry, spec->telemetry);
    } else {
        cep_rv_remove_field(entry, dt_telemetry());
    }

    cep_rv_set_string(entry, dt_state(), "pending");
    cep_rv_remove_field(entry, dt_ready_beat());
    cep_rv_remove_field(entry, dt_applied_beat());
    cep_rv_remove_field(entry, dt_grace_used());

    cep_store_unlock(entry, &entry_lock);

    cep_rv_last_status = CEP_RV_SPAWN_STATUS_OK;
    return true;
}

cepRvSpawnStatus cep_rv_last_spawn_status(void) {
    return cep_rv_last_status;
}

bool cep_rendezvous_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (cep_rv_registry_registered) {
        return true;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepStaticPath2;

    cepStaticPath2 init_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_init(), .timestamp = 0u},
        },
    };

    cepDT after_flow[] = { *CEP_DTAW("CEP", "fl_init") };

    cepEnzymeDescriptor descriptor = {
        .name = *dt_rv_init(),
        .label = "rv.init",
        .callback = cep_rv_enzyme_init,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
        .after = after_flow,
        .after_count = sizeof after_flow / sizeof after_flow[0],
    };

    if (cep_enzyme_register(registry, (const cepPath*)&init_path, &descriptor) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    cep_rv_registry_registered = true;
    return true;
}

bool cep_rv_resched(cepID key, uint32_t delta) {
    if (delta == 0u) {
        return true;
    }

    cepCell* ledger = cep_rv_ledger();
    if (!ledger) {
        return false;
    }

    cepCell* entry = cep_rv_find_entry(ledger, key);
    if (!entry) {
        return false;
    }

    const char* due_text = cep_rv_fetch_cstring(entry, dt_due());
    uint64_t due_value = 0u;
    if (!due_text || !cep_rv_parse_u64(due_text, &due_value)) {
        due_value = 0u;
    }

    due_value += delta;
    cep_rv_set_number(entry, dt_due(), due_value);
    return true;
}

bool cep_rv_kill(cepID key, cepID mode, uint32_t wait_beats) {
    cepCell* ledger = cep_rv_ledger();
    if (!ledger) {
        return false;
    }

    cepCell* entry = cep_rv_find_entry(ledger, key);
    if (!entry) {
        return false;
    }

    if (mode) {
        char buffer[64];
        if (cep_rv_id_to_text(mode, buffer, sizeof buffer)) {
            cep_rv_set_string(entry, dt_kill_mode(), buffer);
        }
    }

    if (wait_beats) {
        cep_rv_set_number(entry, dt_kill_wait(), wait_beats);
    }

    cep_rv_set_string(entry, dt_state(), "killed");
    return true;
}

bool cep_rv_report(cepID key, const cepCell* telemetry_node) {
    cepCell* ledger = cep_rv_ledger();
    if (!ledger) {
        return false;
    }

    cepCell* entry = cep_rv_find_entry(ledger, key);
    if (!entry) {
        return false;
    }
    return cep_rv_copy_telemetry(entry, telemetry_node);
}

bool cep_rv_capture_scan(void) {
    if (!cep_rv_ready) {
        return true;
    }

    cepCell* ledger = cep_rv_ledger();
    if (!ledger) {
        return true;
    }

    cepStore* ledger_store = ledger->store;
    if (!ledger_store || !cep_dt_is_valid(&ledger_store->dt)) {
        return true;
    }

    cepLockToken ledger_lock = {0};
    if (!cep_store_lock(ledger, &ledger_lock)) {
        return false;
    }

    cepBeatNumber current = cep_heartbeat_current();

    for (cepCell* entry = cep_cell_first(ledger); entry; entry = cep_cell_next(ledger, entry)) {
        if (!cep_cell_is_normal(entry)) {
            continue;
        }

        cepLockToken entry_lock = {0};
        if (!cep_store_lock(entry, &entry_lock)) {
            continue;
        }

        const char* state = cep_rv_fetch_cstring(entry, dt_state());
        if (!state) {
            state = "pending";
            cep_rv_set_string(entry, dt_state(), state);
        }

        const char* due_text = cep_rv_fetch_cstring(entry, dt_due());
        uint64_t due_value = 0u;
        if (!due_text || !cep_rv_parse_u64(due_text, &due_value)) {
            cep_store_unlock(entry, &entry_lock);
            continue;
        }

        const char* policy = cep_rv_fetch_cstring(entry, dt_on_miss());
        uint32_t grace_delta = 0u;
        uint32_t max_grace = 0u;
        uint32_t grace_used = 0u;

        const char* grace_text = cep_rv_fetch_cstring(entry, dt_grace_delta());
        if (grace_text) {
            (void)cep_rv_parse_u32(grace_text, &grace_delta);
        }
        const char* max_text = cep_rv_fetch_cstring(entry, dt_max_grace());
        if (max_text) {
            (void)cep_rv_parse_u32(max_text, &max_grace);
        }
        const char* used_text = cep_rv_fetch_cstring(entry, dt_grace_used());
        if (used_text) {
            (void)cep_rv_parse_u32(used_text, &grace_used);
        }

        bool became_ready = false;

        if (strcmp(state, "pending") == 0 || strcmp(state, "late") == 0) {
            if (current == due_value) {
                cep_rv_set_string(entry, dt_state(), "ready");
                cep_rv_set_number(entry, dt_ready_beat(), (uint64_t)current);
                became_ready = true;
            } else if (current > due_value) {
                if (policy && strcmp(policy, "grace") == 0 && grace_delta > 0u && grace_used < max_grace) {
                    due_value += grace_delta;
                    cep_rv_set_number(entry, dt_due(), due_value);
                    cep_rv_set_number(entry, dt_grace_used(), grace_used + 1u);
                } else {
                    cep_rv_transition_timeout(entry, policy);
                }
            }
        }

        if (!became_ready && strcmp(state, "pending") == 0) {
            const char* deadline_text = cep_rv_fetch_cstring(entry, dt_deadline());
            uint64_t deadline_value = 0u;
            if (deadline_text && cep_rv_parse_u64(deadline_text, &deadline_value)) {
                if (deadline_value > 0u && current >= deadline_value) {
                    cep_rv_transition_timeout(entry, policy ? policy : "timeout");
                }
            }
        }

        cep_store_unlock(entry, &entry_lock);
    }

    cep_store_unlock(ledger, &ledger_lock);
    return true;
}

bool cep_rv_commit_apply(void) {
    if (!cep_rv_ready) {
        return true;
    }

    cepCell* ledger = cep_rv_ledger();
    if (!ledger) {
        return true;
    }

    cepStore* ledger_store = ledger->store;
    if (!ledger_store || !cep_dt_is_valid(&ledger_store->dt)) {
        return true;
    }

    cepLockToken ledger_lock = {0};
    if (!cep_store_lock(ledger, &ledger_lock)) {
        return false;
    }

    cepBeatNumber current = cep_heartbeat_current();

    for (cepCell* entry = cep_cell_first(ledger); entry; entry = cep_cell_next(ledger, entry)) {
        if (!cep_cell_is_normal(entry)) {
            continue;
        }

        cepLockToken entry_lock = {0};
        if (!cep_store_lock(entry, &entry_lock)) {
            continue;
        }

        const char* state = cep_rv_fetch_cstring(entry, dt_state());
        if (!state) {
            cep_store_unlock(entry, &entry_lock);
            continue;
        }

        if (strcmp(state, "ready") == 0 || strcmp(state, "timeout") == 0 || strcmp(state, "killed") == 0) {
            if (cep_rv_emit_event_for_entry(entry, state)) {
                cep_rv_set_number(entry, dt_applied_beat(), (uint64_t)current);

                const char* epoch_text = cep_rv_fetch_cstring(entry, dt_epoch_k());
                uint32_t epoch = 0u;
                if (epoch_text && cep_rv_parse_u32(epoch_text, &epoch) && epoch > 0u) {
                    const char* due_text = cep_rv_fetch_cstring(entry, dt_due());
                    uint64_t due_value = 0u;
                    if (due_text && cep_rv_parse_u64(due_text, &due_value)) {
                        due_value = (uint64_t)current + epoch;
                        cep_rv_set_number(entry, dt_due(), due_value);
                    }
                    cep_rv_set_string(entry, dt_state(), "pending");
                    cep_rv_remove_field(entry, dt_ready_beat());
                } else {
                    cep_rv_set_string(entry, dt_state(), "applied");
                }
            }
        }

        cep_store_unlock(entry, &entry_lock);
    }

    cep_store_unlock(ledger, &ledger_lock);
    return true;
}

bool cep_rv_signal_for_key(const cepDT* key, char* buffer, size_t capacity) {
    if (!key || !buffer) {
        return false;
    }

    char key_text[128];
    if (!cep_rv_dt_to_text(key, key_text, sizeof key_text)) {
        return false;
    }

    int written = snprintf(buffer, capacity, "CEP:sig_rv/%s", key_text);
    if (written <= 0 || (size_t)written >= capacity) {
        return false;
    }
    return true;
}
