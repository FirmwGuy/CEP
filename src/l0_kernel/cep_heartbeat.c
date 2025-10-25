/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_heartbeat.h"
#include "cep_cei.h"
#include "cep_heartbeat_internal.h"
#include "cep_namepool.h"
#include "../enzymes/cep_cell_operations.h"
#include "../enzymes/cep_l0_organs.h"
#include "cep_ops.h"
#include "cep_organ.h"
#include "stream/cep_stream_internal.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>




static cepHeartbeatRuntime CEP_RUNTIME = {
    .current = CEP_BEAT_INVALID,
    .phase   = CEP_BEAT_CAPTURE,
    .deferred_activations = 0u,
    .sys_shutdown_emitted = false,
    .current_descriptor = NULL,
    .last_wallclock_beat = CEP_BEAT_INVALID,
    .last_wallclock_ns = 0u,
};

static cepHeartbeatTopology CEP_DEFAULT_TOPOLOGY;

CEP_DEFINE_STATIC_DT(dt_scope_kernel,   CEP_ACRO("CEP"), CEP_WORD("kernel"));
CEP_DEFINE_STATIC_DT(dt_scope_namepool, CEP_ACRO("CEP"), CEP_WORD("namepool"));
CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));
CEP_DEFINE_STATIC_DT(dt_list_type,      CEP_ACRO("CEP"), CEP_WORD("list"));
CEP_DEFINE_STATIC_DT(dt_log_payload,    CEP_ACRO("CEP"), CEP_WORD("log"));
CEP_DEFINE_STATIC_DT(dt_state_root,     CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_sys_root_name,  CEP_ACRO("CEP"), CEP_WORD("sys"));
CEP_DEFINE_STATIC_DT(dt_rt_root_name,   CEP_ACRO("CEP"), CEP_WORD("rt"));
CEP_DEFINE_STATIC_DT(dt_ops_rt_name,   CEP_ACRO("CEP"), CEP_WORD("ops"));
CEP_DEFINE_STATIC_DT(dt_journal_root_name, CEP_ACRO("CEP"), CEP_WORD("journal"));
CEP_DEFINE_STATIC_DT(dt_env_root_name,  CEP_ACRO("CEP"), CEP_WORD("env"));
CEP_DEFINE_STATIC_DT(dt_cas_root_name,  CEP_ACRO("CEP"), CEP_WORD("cas"));
CEP_DEFINE_STATIC_DT(dt_lib_root_name,  CEP_ACRO("CEP"), CEP_WORD("lib"));
CEP_DEFINE_STATIC_DT(dt_data_root_name, CEP_ACRO("CEP"), CEP_WORD("data"));
CEP_DEFINE_STATIC_DT(dt_tmp_root_name,  CEP_ACRO("CEP"), CEP_WORD("tmp"));
CEP_DEFINE_STATIC_DT(dt_enzymes_root_name, CEP_ACRO("CEP"), CEP_WORD("enzymes"));
CEP_DEFINE_STATIC_DT(dt_organs_root_name,  CEP_ACRO("CEP"), CEP_WORD("organs"));
CEP_DEFINE_STATIC_DT(dt_beat_root_name, CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_impulses_name,  CEP_ACRO("CEP"), CEP_WORD("impulses"));
CEP_DEFINE_STATIC_DT(dt_inbox_legacy_name, CEP_ACRO("CEP"), CEP_WORD("inbox"));
CEP_DEFINE_STATIC_DT(dt_agenda_name,    CEP_ACRO("CEP"), CEP_WORD("agenda"));
CEP_DEFINE_STATIC_DT(dt_stage_name,     CEP_ACRO("CEP"), CEP_WORD("stage"));
CEP_DEFINE_STATIC_DT(dt_boot_oid_field, CEP_ACRO("CEP"), CEP_WORD("boot_oid"));
CEP_DEFINE_STATIC_DT(dt_shdn_oid_field, CEP_ACRO("CEP"), CEP_WORD("shdn_oid"));
CEP_DEFINE_STATIC_DT(dt_ist_kernel,     CEP_ACRO("CEP"), CEP_WORD("ist:kernel"));
CEP_DEFINE_STATIC_DT(dt_ist_store,      CEP_ACRO("CEP"), CEP_WORD("ist:store"));
CEP_DEFINE_STATIC_DT(dt_meta_name,      CEP_ACRO("CEP"), CEP_WORD("meta"));
CEP_DEFINE_STATIC_DT(dt_unix_ts_name, CEP_ACRO("CEP"), CEP_WORD("unix_ts_ns"));
CEP_DEFINE_STATIC_DT(dt_analytics_root_name, CEP_ACRO("CEP"), CEP_WORD("analytics"));
CEP_DEFINE_STATIC_DT(dt_spacing_name,   CEP_ACRO("CEP"), CEP_WORD("spacing"));
CEP_DEFINE_STATIC_DT(dt_interval_ns_name, CEP_ACRO("CEP"), CEP_WORD("interval_ns"));

typedef struct {
    const char* kind;
    const char* label;
    bool        has_constructor;
    bool        has_destructor;
} cepHeartbeatOrganDescriptorInit;

#define CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT 256u

static cepCell* ensure_root_dictionary(cepCell* root, const cepDT* name, const cepDT* store_dt);
static cepCell* ensure_root_list(cepCell* root, const cepDT* name, const cepDT* store_dt);

static cepDT cep_heartbeat_make_signal_dt(const char* kind, const char* suffix) {
    if (!kind || !*kind || !suffix || !*suffix) {
        return (cepDT){0};
    }

    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "org:%s:%s", kind, suffix);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return (cepDT){0};
    }
    return cep_ops_make_dt(buffer);
}

static cepDT cep_heartbeat_make_validator_dt(const char* kind) {
    return cep_heartbeat_make_signal_dt(kind, "vl");
}

static bool cep_heartbeat_register_l0_organs(void) {
    static const cepHeartbeatOrganDescriptorInit descriptors[] = {
        { "sys_state",     "Kernel state organ",            false, false },
        { "sys_organs",    "Organ descriptor registry",     false, false },
        { "rt_ops",        "Runtime operations organ",      false, false },
        { "rt_beat",       "Heartbeat beat organ",          true,  true  },
        { "journal",       "Beat journal organ",            true,  true  },
        { "env",           "Environment organ",             false, false },
        { "cas",           "Content store organ",           false, false },
        { "lib",           "Library organ",                 false, false },
        { "tmp",           "Scratch queue organ",           false, false },
        { "enzymes",       "Enzyme manifest organ",         false, false },
    };

    size_t count = sizeof descriptors / sizeof descriptors[0];
    for (size_t index = 0; index < count; ++index) {
        const cepHeartbeatOrganDescriptorInit* init = &descriptors[index];
        cepDT store_dt = cep_organ_store_dt(init->kind);
        cepDT validator_dt = cep_heartbeat_make_validator_dt(init->kind);

        if (!cep_dt_is_valid(&store_dt) || !cep_dt_is_valid(&validator_dt)) {
            return false;
        }

        cepOrganDescriptor descriptor;
        memset(&descriptor, 0, sizeof descriptor);
        descriptor.kind = init->kind;
        descriptor.label = init->label;
        descriptor.store = store_dt;
        descriptor.validator = validator_dt;
        if (init->has_constructor) {
            descriptor.constructor = cep_heartbeat_make_signal_dt(init->kind, "ct");
        }
        if (init->has_destructor) {
            descriptor.destructor = cep_heartbeat_make_signal_dt(init->kind, "dt");
        }

        if (!cep_organ_register(&descriptor)) {
            return false;
        }
    }

    return true;
}
CEP_DEFINE_STATIC_DT(dt_ist_packs,      CEP_ACRO("CEP"), CEP_WORD("ist:packs"));
CEP_DEFINE_STATIC_DT(dt_ist_stop,       CEP_ACRO("CEP"), CEP_WORD("ist:stop"));
CEP_DEFINE_STATIC_DT(dt_ist_flush,      CEP_ACRO("CEP"), CEP_WORD("ist:flush"));
CEP_DEFINE_STATIC_DT(dt_ist_halt,       CEP_ACRO("CEP"), CEP_WORD("ist:halt"));
CEP_DEFINE_STATIC_DT(dt_sts_ok,         CEP_ACRO("CEP"), CEP_WORD("sts:ok"));
CEP_DEFINE_STATIC_DT(dt_sts_fail,       CEP_ACRO("CEP"), CEP_WORD("sts:fail"));

typedef struct {
    const char*             label;
    const cepDT*          (*scope_dt)(void);
    const cepLifecycleScope*dependencies;
    size_t                  dependency_count;
} cepLifecycleScopeInfo;

typedef struct {
    bool            ready;
    bool            teardown;
    cepBeatNumber   ready_beat;
    cepBeatNumber   td_beat;
} cepLifecycleScopeState;

typedef enum {
    CEP_BOOT_PHASE_NONE = 0,
    CEP_BOOT_PHASE_KERNEL,
    CEP_BOOT_PHASE_STORE,
    CEP_BOOT_PHASE_PACKS,
    CEP_BOOT_PHASE_CLOSED,
} cepBootPhase;

typedef enum {
    CEP_SHDN_PHASE_NONE = 0,
    CEP_SHDN_PHASE_STOP,
    CEP_SHDN_PHASE_FLUSH,
    CEP_SHDN_PHASE_HALT,
    CEP_SHDN_PHASE_CLOSED,
} cepShutdownPhase;

typedef struct {
    cepOID          boot_oid;
    cepOID          shdn_oid;
    bool            boot_started;
    bool            boot_closed;
    bool            shdn_started;
    bool            shdn_closed;
    bool            boot_failed;
    bool            shdn_failed;
    cepBootPhase    boot_phase;
    cepShutdownPhase shdn_phase;
    cepBeatNumber   boot_last_beat;
    cepBeatNumber   shdn_last_beat;
    bool            boot_kernel_ready;
    bool            boot_namepool_ready;
    size_t          shdn_scopes_marked;
} cepLifecycleOpsState;

static const cepLifecycleScope CEP_SCOPE_DEPS_NAMEPOOL[] = {
    CEP_LIFECYCLE_SCOPE_KERNEL,
};

static const cepLifecycleScopeInfo CEP_LIFECYCLE_SCOPE_INFO[CEP_LIFECYCLE_SCOPE_COUNT] = {
    [CEP_LIFECYCLE_SCOPE_KERNEL] = {
        .label = "kernel",
        .scope_dt = dt_scope_kernel,
        .dependencies = NULL,
        .dependency_count = 0u,
    },
    [CEP_LIFECYCLE_SCOPE_NAMEPOOL] = {
        .label = "namepool",
        .scope_dt = dt_scope_namepool,
        .dependencies = CEP_SCOPE_DEPS_NAMEPOOL,
        .dependency_count = cep_lengthof(CEP_SCOPE_DEPS_NAMEPOOL),
    },
};

static cepLifecycleScopeState CEP_LIFECYCLE_STATE[CEP_LIFECYCLE_SCOPE_COUNT];
static cepLifecycleOpsState CEP_LIFECYCLE_OPS_STATE;
static const cepLifecycleScope CEP_LIFECYCLE_TEARDOWN_ORDER[] = {
    CEP_LIFECYCLE_SCOPE_NAMEPOOL,
    CEP_LIFECYCLE_SCOPE_KERNEL,
};

static void cep_lifecycle_reset_state(void);
static bool cep_lifecycle_scope_dependencies_ready(cepLifecycleScope scope);
static cepCell* cep_lifecycle_get_dictionary(cepCell* parent, const cepDT* name, bool create);
static void cep_lifecycle_reload_state(void);
static void cep_boot_ops_reset(void);
static cepBeatNumber cep_boot_ops_effective_beat(void);
static bool cep_boot_ops_ready_for_next(cepBeatNumber last);
static bool cep_boot_ops_progress(void);
static bool cep_boot_ops_record_state(cepOID oid, const cepDT* state_dt, bool* failure_flag);
static bool cep_boot_ops_close_boot(bool success);
static bool cep_boot_ops_close_shutdown(bool success);

static cepCell* cep_heartbeat_ensure_list_child(cepCell* parent, const cepDT* name);
static bool cep_heartbeat_append_list_message(cepCell* list, const char* message);
static char* cep_heartbeat_path_to_string(const cepPath* path);


static int cep_heartbeat_path_compare(const cepPath* lhs, const cepPath* rhs) {
    if (lhs == rhs) {
        return 0;
    }
    if (!lhs) {
        return rhs ? -1 : 0;
    }
    if (!rhs) {
        return 1;
    }

    if (lhs->length < rhs->length) {
        return -1;
    }
    if (lhs->length > rhs->length) {
        return 1;
    }

    for (unsigned i = 0; i < lhs->length; ++i) {
        int cmp = cep_dt_compare(&lhs->past[i].dt, &rhs->past[i].dt);
        if (cmp != 0) {
            return cmp;
        }
    }

    return 0;
}


static uint64_t cep_heartbeat_hash_mix(uint64_t hash, uint64_t value) {
    hash ^= value + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    return hash;
}


static uint64_t cep_heartbeat_path_hash(const cepPath* path) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    if (!path) {
        return hash;
    }

    hash = cep_heartbeat_hash_mix(hash, path->length);
    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        hash = cep_heartbeat_hash_mix(hash, segment->dt.domain);
        hash = cep_heartbeat_hash_mix(hash, segment->dt.tag);
        hash = cep_heartbeat_hash_mix(hash, segment->timestamp);
    }

    return hash;
}


static uint64_t cep_heartbeat_impulse_hash(const cepHeartbeatImpulseRecord* record) {
    uint64_t hash = 0x84222325cbf29ce4ULL;
    if (!record) {
        return hash;
    }

    hash = cep_heartbeat_hash_mix(hash, cep_heartbeat_path_hash(record->signal_path));
    hash = cep_heartbeat_hash_mix(hash, cep_heartbeat_path_hash(record->target_path));
    return hash;
}


static bool cep_heartbeat_policy_use_dirs(void) {
    return CEP_RUNTIME.policy.ensure_directories;
}


static bool cep_heartbeat_id_to_string(cepID id, char* buffer, size_t capacity, size_t* out_len) {
    if (!buffer || capacity == 0u) {
        return false;
    }

    size_t len = 0u;

    if (cep_id_is_reference(id)) {
        size_t ref_len = 0u;
        const char* text = cep_namepool_lookup(id, &ref_len);
        if (!text) {
            return false;
        }
        if (ref_len + 1u > capacity) {
            return false;
        }
        memcpy(buffer, text, ref_len);
        buffer[ref_len] = '\0';
        if (out_len) {
            *out_len = ref_len;
        }
        return true;
    } else if (cep_id_is_word(id)) {
        len = cep_word_to_text(id, buffer);
    } else if (cep_id_is_acronym(id)) {
        len = cep_acronym_to_text(id, buffer);
    } else if (cep_id_is_numeric(id)) {
        uint64_t value = (uint64_t)cep_id(id);
        int written = snprintf(buffer, capacity, "%" PRIu64, (unsigned long long)value);
        if (written < 0) {
            return false;
        }
        len = (size_t)written;
    } else {
        if (capacity < 2u) {
            return false;
        }
        buffer[0] = '?';
        buffer[1] = '\0';
        len = 1u;
    }

    if (len + 1u > capacity) {
        return false;
    }

    if (out_len) {
        *out_len = len;
    }

    return true;
}


static bool cep_heartbeat_dt_to_string(const cepDT* dt, char* buffer, size_t capacity) {
    if (!dt) {
        return false;
    }

    char domain_buf[32];
    char tag_buf[32];
    size_t domain_len = 0u;
    size_t tag_len = 0u;

    if (!cep_heartbeat_id_to_string(dt->domain, domain_buf, sizeof(domain_buf), &domain_len)) {
        return false;
    }

    if (!cep_heartbeat_id_to_string(dt->tag, tag_buf, sizeof(tag_buf), &tag_len)) {
        return false;
    }

    size_t needed = domain_len + 1u + tag_len;
    if (needed + 1u > capacity) {
        return false;
    }

    memcpy(buffer, domain_buf, domain_len);
    buffer[domain_len] = ':';
    memcpy(buffer + domain_len + 1u, tag_buf, tag_len);
    buffer[needed] = '\0';
    return true;
}


static char* cep_heartbeat_path_to_string(const cepPath* path) {
    if (!path || path->length == 0u) {
        char* empty = cep_malloc(2u);
        if (!empty) {
            return NULL;
        }
        empty[0] = '-';
        empty[1] = '\0';
        return empty;
    }

    size_t capacity = (size_t)path->length * 80u + 2u;
    char* text = cep_malloc(capacity);
    if (!text) {
        return NULL;
    }

    size_t pos = 0u;
    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];

        if (pos + 1u >= capacity) {
            cep_free(text);
            return NULL;
        }
        text[pos++] = '/';

        char domain_buf[32];
        size_t domain_len = 0u;
        if (!cep_heartbeat_id_to_string(segment->dt.domain, domain_buf, sizeof(domain_buf), &domain_len)) {
            cep_free(text);
            return NULL;
        }
        if (pos + domain_len >= capacity) {
            cep_free(text);
            return NULL;
        }
        memcpy(text + pos, domain_buf, domain_len);
        pos += domain_len;

        if (pos + 1u >= capacity) {
            cep_free(text);
            return NULL;
        }
        text[pos++] = ':';

        char tag_buf[32];
        size_t tag_len = 0u;
        if (!cep_heartbeat_id_to_string(segment->dt.tag, tag_buf, sizeof(tag_buf), &tag_len)) {
            cep_free(text);
            return NULL;
        }
        if (pos + tag_len >= capacity) {
            cep_free(text);
            return NULL;
        }
        memcpy(text + pos, tag_buf, tag_len);
        pos += tag_len;

        if (segment->timestamp) {
            int written = snprintf(text + pos, capacity - pos, "@%" PRIu64, (unsigned long long)segment->timestamp);
            if (written < 0) {
                cep_free(text);
                return NULL;
            }
            size_t w = (size_t)written;
            if (pos + w >= capacity) {
                cep_free(text);
                return NULL;
            }
            pos += w;
        }
    }

    if (pos == 0u) {
        text[pos++] = '/';
    }

    if (pos >= capacity) {
        cep_free(text);
        return NULL;
    }

    text[pos] = '\0';
    return text;
}


static bool cep_heartbeat_append_list_message(cepCell* list, const char* message) {
    if (!list || !message) {
        return false;
    }

    size_t len = strlen(message);
    size_t size = len + 1u;
    char* buffer = cep_malloc(size);
    if (!buffer) {
        return false;
    }

    memcpy(buffer, message, len);
    buffer[len] = '\0';

    cepDT name = {
        .domain = CEP_ACRO("HB"),
        .tag    = CEP_AUTOID,
    };

    cepDT payload_type = *dt_log_payload();
    cepCell* entry = cep_cell_append_value(list, &name, &payload_type, buffer, size, size);
    cep_free(buffer);
    return entry != NULL;
}


static cepCell* cep_heartbeat_ensure_dictionary_child(cepCell* parent, const cepDT* name, bool* created) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child) {
        cepDT dict_type = *dt_dictionary_type();
        cepDT name_copy = cep_dt_clean(name);
        child = cep_cell_add_dictionary(parent, &name_copy, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (created) {
            *created = true;
        }
    } else if (created) {
        *created = false;
    }

    return child;
}


static cepCell* cep_heartbeat_ensure_list_child(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child) {
        cepDT list_type = *dt_list_type();
        cepDT name_copy = cep_dt_clean(name);
        child = cep_cell_add_list(parent, &name_copy, 0, &list_type, CEP_STORAGE_LINKED_LIST);
    }
    return child;
}

static cepCell* cep_heartbeat_ensure_meta_child(cepCell* beat_cell) {
    if (!beat_cell) {
        return NULL;
    }

    cepCell* meta = cep_cell_find_by_name(beat_cell, dt_meta_name());
    if (!meta) {
        cepDT meta_name = cep_dt_clean(dt_meta_name());
        cepDT dict_type = *dt_dictionary_type();
        meta = cep_cell_add_dictionary(beat_cell, &meta_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    } else {
        meta = cep_cell_resolve(meta);
    }

    if (!meta) {
        return NULL;
    }

    if (!cep_cell_require_dictionary_store(&meta)) {
        return NULL;
    }

    return meta;
}

static bool cep_heartbeat_ensure_legacy_inbox_alias(cepCell* beat_cell, cepCell* impulses_cell) {
    if (!beat_cell || !impulses_cell) {
        return false;
    }

    cepCell* legacy = cep_cell_find_by_name(beat_cell, dt_inbox_legacy_name());
    if (!legacy) {
        cepDT alias_name = cep_dt_clean(dt_inbox_legacy_name());
        cepCell* alias = cep_cell_add_link(beat_cell, &alias_name, 0, impulses_cell);
        if (!alias) {
            return false;
        }
        /* FIXME: Drop the legacy `inbox` alias once downstream tooling is updated.
         * The link survives for one release to keep older consumers alive. */
        cep_link_set(alias, impulses_cell);
        return true;
    }

    cepCell* resolved = cep_cell_resolve(legacy);
    if (resolved != impulses_cell) {
        if (cep_cell_is_link(legacy)) {
            cep_link_set(legacy, impulses_cell);
        } else {
            cepDT new_name = cep_dt_clean(dt_impulses_name());
            cep_cell_set_name(legacy, &new_name);
            return cep_heartbeat_ensure_legacy_inbox_alias(beat_cell, impulses_cell);
        }
    }

    return true;
}

static cepCell* cep_heartbeat_resolve_impulse_log(cepCell* beat_cell) {
    if (!beat_cell) {
        return NULL;
    }

    cepCell* impulses = cep_cell_find_by_name(beat_cell, dt_impulses_name());
    if (impulses && cep_cell_is_link(impulses)) {
        impulses = cep_cell_resolve(impulses);
    }

    if (!impulses) {
        cepCell* legacy = cep_cell_find_by_name(beat_cell, dt_inbox_legacy_name());
        if (legacy && !cep_cell_is_link(legacy)) {
            cepDT new_name = cep_dt_clean(dt_impulses_name());
            cep_cell_set_name(legacy, &new_name);
            impulses = legacy;
        }
    }

    if (!impulses) {
        impulses = cep_heartbeat_ensure_list_child(beat_cell, dt_impulses_name());
    }

    if (!impulses) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_legacy_inbox_alias(beat_cell, impulses)) {
        return NULL;
    }

    return impulses;
}


static bool cep_heartbeat_set_numeric_name(cepDT* name, cepBeatNumber beat) {
    if (!name || beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (beat >= CEP_AUTOID_MAX) {
        return false;
    }

    name->glob = 0u;
    name->domain = CEP_ACRO("HB");
    name->tag = cep_id_to_numeric((cepID)(beat + 1u));
    return true;
}


static cepCell* cep_heartbeat_ensure_beat_node(cepBeatNumber beat) {
    if (!cep_heartbeat_policy_use_dirs() || beat == CEP_BEAT_INVALID) {
        return NULL;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return NULL;
    }

    cepCell* beat_root = cep_heartbeat_ensure_dictionary_child(rt_root, dt_beat_root_name(), NULL);
    if (!beat_root) {
        return NULL;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return NULL;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_dictionary_child(beat_root, &beat_name, NULL);
    if (!beat_cell) {
        return NULL;
    }

    if (!cep_heartbeat_resolve_impulse_log(beat_cell)) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_list_child(beat_cell, dt_agenda_name())) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_list_child(beat_cell, dt_stage_name())) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_meta_child(beat_cell)) {
        return NULL;
    }

    return beat_cell;
}


static bool cep_heartbeat_record_impulse_entry(cepBeatNumber beat, const cepImpulse* impulse) {
    if (!cep_heartbeat_policy_use_dirs() || beat == CEP_BEAT_INVALID || !impulse) {
        return true;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    cepCell* impulses = cep_heartbeat_resolve_impulse_log(beat_cell);
    if (!impulses) {
        return false;
    }

    char* signal = cep_heartbeat_path_to_string(impulse->signal_path);
    char* target = cep_heartbeat_path_to_string(impulse->target_path);
    if (!signal || !target) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    int written = snprintf(NULL, 0, "signal=%s target=%s", signal, target);
    if (written < 0) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    size_t size = (size_t)written + 1u;
    char* message = cep_malloc(size);
    if (!message) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    snprintf(message, size, "signal=%s target=%s", signal, target);
    bool ok = cep_heartbeat_append_list_message(impulses, message);

    cep_free(message);
    cep_free(signal);
    cep_free(target);
    return ok;
}


static const char* cep_heartbeat_descriptor_label(const cepEnzymeDescriptor* descriptor, char* buffer, size_t capacity) {
    if (!descriptor) {
        return "no-match";
    }

    if (descriptor->label && descriptor->label[0]) {
        return descriptor->label;
    }

    if (cep_heartbeat_dt_to_string(&descriptor->name, buffer, capacity)) {
        return buffer;
    }

    return "(unnamed)";
}


static bool cep_heartbeat_record_agenda_entry(cepBeatNumber beat, const cepEnzymeDescriptor* descriptor, int rc, const cepImpulse* impulse) {
    if (!cep_heartbeat_policy_use_dirs()) {
        return true;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    cepCell* agenda = cep_cell_find_by_name(beat_cell, dt_agenda_name());
    if (!agenda) {
        agenda = cep_heartbeat_ensure_list_child(beat_cell, dt_agenda_name());
        if (!agenda) {
            return false;
        }
    }

    char* signal = cep_heartbeat_path_to_string(impulse ? impulse->signal_path : NULL);
    char* target = cep_heartbeat_path_to_string(impulse ? impulse->target_path : NULL);
    if (!signal || !target) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    char name_buf[64];
    const char* name = cep_heartbeat_descriptor_label(descriptor, name_buf, sizeof(name_buf));

    int written;
    if (descriptor) {
        written = snprintf(NULL, 0, "enzyme=%s rc=%d signal=%s target=%s", name, rc, signal, target);
    } else {
        written = snprintf(NULL, 0, "no-match signal=%s target=%s", signal, target);
    }

    if (written < 0) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    size_t size = (size_t)written + 1u;
    char* message = cep_malloc(size);
    if (!message) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    if (descriptor) {
        snprintf(message, size, "enzyme=%s rc=%d signal=%s target=%s", name, rc, signal, target);
    } else {
        snprintf(message, size, "no-match signal=%s target=%s", signal, target);
    }

    bool ok = cep_heartbeat_append_list_message(agenda, message);

    cep_free(message);
    cep_free(signal);
    cep_free(target);
    return ok;
}


static bool cep_heartbeat_record_stage_entry(cepBeatNumber beat, const char* message) {
    if (!cep_heartbeat_policy_use_dirs() || !message) {
        return true;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    cepCell* stage = cep_cell_find_by_name(beat_cell, dt_stage_name());
    if (!stage) {
        stage = cep_heartbeat_ensure_list_child(beat_cell, dt_stage_name());
        if (!stage) {
            return false;
        }
    }

    return cep_heartbeat_append_list_message(stage, message);
}

bool cep_heartbeat_stage_note(const char* message) {
    if (!message)
        return false;

    if (!cep_heartbeat_policy_use_dirs())
        return true;

    cepBeatNumber beat = (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : CEP_RUNTIME.current;
    const char* final_message = message;
    char* formatted = NULL;

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    uint64_t unix_ts = 0u;
    bool have_unix_ts = cep_heartbeat_beat_to_unix(beat, &unix_ts);
    if (!have_unix_ts) {
        cepCell* meta = cep_cell_find_by_name(beat_cell, dt_meta_name());
        if (meta) {
            meta = cep_cell_resolve(meta);
            if (meta) {
                cepCell* ts_cell = cep_cell_find_by_name(meta, dt_unix_ts_name());
                if (ts_cell) {
                    ts_cell = cep_cell_resolve(ts_cell);
                    if (ts_cell && cep_cell_has_data(ts_cell)) {
                        const char* stored_text = (const char*)cep_cell_data(ts_cell);
                        if (stored_text) {
                            char* endptr = NULL;
                            uint64_t parsed = (uint64_t)strtoull(stored_text, &endptr, 10);
                            if (endptr && *endptr == '\0') {
                                unix_ts = parsed;
                                have_unix_ts = true;
                            }
                        }
                    }
                }
            }
        }
    }

    if (have_unix_ts) {
        int written = snprintf(NULL, 0, "%s ts=%" PRIu64, message, unix_ts);
        if (written > 0) {
            formatted = cep_malloc((size_t)written + 1u);
            if (formatted) {
                snprintf(formatted, (size_t)written + 1u, "%s ts=%" PRIu64, message, unix_ts);
                final_message = formatted;
            }
        }
    }

    bool ok = cep_heartbeat_record_stage_entry(beat, final_message);
    cep_free(formatted);
    return ok;
}


static bool cep_heartbeat_scratch_ensure_ordered(cepHeartbeatScratch* scratch, size_t required) {
    if (!scratch) {
        return false;
    }
    if (required == 0u) {
        return true;
    }
    if (scratch->ordered_capacity >= required) {
        return true;
    }

    size_t bytes = required * sizeof(*scratch->ordered);
    const cepEnzymeDescriptor** buffer = scratch->ordered ? cep_realloc(scratch->ordered, bytes) : cep_malloc(bytes);
    if (!buffer) {
        return false;
    }

    scratch->ordered = buffer;
    scratch->ordered_capacity = required;
    return true;
}


static bool cep_heartbeat_dispatch_cache_reserve(cepHeartbeatScratch* scratch, size_t min_capacity) {
    if (!scratch || min_capacity == 0u) {
        return true;
    }

    if (scratch->entry_capacity >= min_capacity) {
        return true;
    }

    size_t capacity = scratch->entry_capacity ? scratch->entry_capacity : 8u;
    while (capacity < min_capacity && capacity < (SIZE_MAX >> 1)) {
        capacity <<= 1u;
    }
    if (capacity < min_capacity) {
        capacity = min_capacity;
    }

    size_t bytes = capacity * sizeof(*scratch->entries);
    cepHeartbeatDispatchCacheEntry* entries = scratch->entries ? cep_realloc(scratch->entries, bytes) : cep_malloc(bytes);
    if (!entries) {
        return false;
    }

    if (capacity > scratch->entry_capacity) {
        size_t old_capacity = scratch->entry_capacity;
        memset(entries + old_capacity, 0, (capacity - old_capacity) * sizeof(*entries));
    }

    scratch->entries = entries;
    scratch->entry_capacity = capacity;
    return true;
}


static void cep_heartbeat_dispatch_cache_destroy(cepHeartbeatScratch* scratch) {
    if (!scratch) {
        return;
    }

    if (scratch->entries) {
        for (size_t i = 0; i < scratch->entry_capacity; ++i) {
            CEP_FREE(scratch->entries[i].descriptors);
            scratch->entries[i].descriptors = NULL;
            scratch->entries[i].descriptor_capacity = 0u;
            scratch->entries[i].descriptor_count = 0u;
            scratch->entries[i].signal_path = NULL;
            scratch->entries[i].target_path = NULL;
            CEP_FREE(scratch->entries[i].memo);
            scratch->entries[i].memo = NULL;
            scratch->entries[i].memo_capacity = 0u;
            scratch->entries[i].memo_count = 0u;
            scratch->entries[i].used = 0u;
            scratch->entries[i].stamp = 0u;
            scratch->entries[i].hash = 0u;
        }
        CEP_FREE(scratch->entries);
    }

    CEP_FREE(scratch->ordered);

    memset(scratch, 0, sizeof(*scratch));
}


static void cep_heartbeat_scratch_next_generation(cepHeartbeatScratch* scratch) {
    if (!scratch) {
        return;
    }

    scratch->generation += 1u;
    if (scratch->generation == 0u) {
        scratch->generation = 1u;
        if (scratch->entries) {
            for (size_t i = 0; i < scratch->entry_capacity; ++i) {
                scratch->entries[i].stamp = 0u;
                scratch->entries[i].used = 0u;
                scratch->entries[i].hash = 0u;
                scratch->entries[i].signal_path = NULL;
                scratch->entries[i].target_path = NULL;
                scratch->entries[i].descriptor_count = 0u;
                scratch->entries[i].memo_count = 0u;
            }
        }
    }
}


/*
    Ensure dispatch cache entries keep memo buffers large enough to hold per
    descriptor execution state so duplicate impulses within a beat can be
    short-circuited safely. The allocator grows geometrically, zero-filling the
    newly added tail while preserving prior observations for descriptors that
    already ran this generation.
*/
static bool cep_heartbeat_dispatch_entry_reserve_memo(cepHeartbeatDispatchCacheEntry* entry, size_t required) {
    if (!entry) {
        return required == 0u;
    }

    if (required == 0u || entry->memo_capacity >= required) {
        return true;
    }

    size_t new_capacity = entry->memo_capacity ? entry->memo_capacity : 4u;
    while (new_capacity < required) {
        new_capacity <<= 1u;
    }

    size_t bytes = new_capacity * sizeof(*entry->memo);
    cepHeartbeatDescriptorMemo* memo = entry->memo ?
        cep_realloc(entry->memo, bytes) :
        cep_malloc(bytes);
    if (!memo) {
        return false;
    }

    if (new_capacity > entry->memo_capacity) {
        size_t old_bytes = entry->memo_capacity * sizeof(*entry->memo);
        memset(((uint8_t*)memo) + old_bytes, 0, bytes - old_bytes);
    }

    entry->memo = memo;
    entry->memo_capacity = new_capacity;
    return true;
}


static cepHeartbeatDispatchCacheEntry* cep_heartbeat_dispatch_cache_acquire(cepHeartbeatScratch* scratch, const cepHeartbeatImpulseRecord* record, uint64_t hash, bool* fresh) {
    if (!scratch || !scratch->entries || scratch->entry_capacity == 0u) {
        return NULL;
    }

    size_t mask = scratch->entry_capacity - 1u;
    size_t index = (size_t)hash & mask;

    for (size_t probe = 0; probe < scratch->entry_capacity; ++probe) {
        cepHeartbeatDispatchCacheEntry* entry = &scratch->entries[index];
        if (entry->stamp != scratch->generation || !entry->used) {
            entry->used = 1u;
            entry->stamp = scratch->generation;
            entry->hash = hash;
            entry->signal_path = record ? record->signal_path : NULL;
            entry->target_path = record ? record->target_path : NULL;
            entry->descriptor_count = 0u;
            entry->memo_count = 0u;
            if (fresh) {
                *fresh = true;
            }
            return entry;
        }

        if (entry->hash == hash &&
            cep_heartbeat_path_compare(entry->signal_path, record ? record->signal_path : NULL) == 0 &&
            cep_heartbeat_path_compare(entry->target_path, record ? record->target_path : NULL) == 0) {
            if (fresh) {
                *fresh = false;
            }
            return entry;
        }

        index = (index + 1u) & mask;
    }

    return NULL;
}


static void cep_heartbeat_dispatch_cache_cleanup_generation(cepHeartbeatScratch* scratch) {
    if (!scratch || !scratch->entries) {
        return;
    }

    for (size_t i = 0; i < scratch->entry_capacity; ++i) {
        cepHeartbeatDispatchCacheEntry* entry = &scratch->entries[i];
        if (entry->stamp == scratch->generation && entry->used) {
            entry->used = 0u;
            entry->hash = 0u;
            entry->signal_path = NULL;
            entry->target_path = NULL;
            entry->descriptor_count = 0u;
            entry->memo_count = 0u;
        }
    }
}


static bool cep_runtime_has_registry(void) {
    return CEP_RUNTIME.registry != NULL;
}


static void cep_runtime_reset_state(bool destroy_registry) {
    if (destroy_registry && cep_runtime_has_registry()) {
        cep_enzyme_registry_destroy(CEP_RUNTIME.registry);
        CEP_RUNTIME.registry = NULL;
    }

    cep_heartbeat_impulse_queue_destroy(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_destroy(&CEP_RUNTIME.impulses_next);
    cep_heartbeat_dispatch_cache_destroy(&CEP_RUNTIME.scratch);

    CEP_RUNTIME.current = CEP_BEAT_INVALID;
    CEP_RUNTIME.running = false;
    
    memset(&CEP_RUNTIME.topology, 0, sizeof(CEP_RUNTIME.topology));
    memset(&CEP_RUNTIME.policy, 0, sizeof(CEP_RUNTIME.policy));
    CEP_RUNTIME.policy.ensure_directories = true;
    CEP_RUNTIME.policy.boot_ops = true;
    CEP_RUNTIME.policy.spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    CEP_RUNTIME.deferred_activations = 0u;
    CEP_RUNTIME.sys_shutdown_emitted = false;
    CEP_RUNTIME.bootstrapping = false;
    CEP_RUNTIME.last_wallclock_beat = CEP_BEAT_INVALID;
    CEP_RUNTIME.last_wallclock_ns = 0u;
    CEP_RUNTIME.spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;

    cep_lifecycle_reset_state();
    cep_organ_runtime_reset();
}


static void cep_runtime_reset_defaults(void) {
    memset(&CEP_DEFAULT_TOPOLOGY, 0, sizeof(CEP_DEFAULT_TOPOLOGY));
}

void cep_heartbeat_detach_topology(void) {
    cep_runtime_reset_state(true);
    cep_runtime_reset_defaults();
}


static cepCell* ensure_root_dictionary(cepCell* root, const cepDT* name, const cepDT* store_dt) {
    cepCell* cell = cep_cell_find_by_name(root, name);
    if (!cell) {
        cepDT dict_type = store_dt ? cep_dt_clean(store_dt) : *dt_dictionary_type();
        cepDT name_copy = cep_dt_clean(name);
        cell = cep_cell_add_dictionary(root, &name_copy, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    } else {
        cepCell* resolved = cep_cell_resolve(cell);
        if (!resolved) {
            return NULL;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            return NULL;
        }
        if (store_dt && resolved->store) {
            cep_store_set_dt(resolved->store, store_dt);
        }
        cell = resolved;
    }
    return cell;
}


static cepCell* ensure_root_list(cepCell* root, const cepDT* name, const cepDT* store_dt) {
    cepCell* cell = cep_cell_find_by_name(root, name);
    if (!cell) {
        CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] missing name ptr=%p domain=%016llx tag=%016llx\n",
                                (void*)name,
                                name ? (unsigned long long)cep_id(name->domain) : 0ull,
                                name ? (unsigned long long)cep_id(name->tag) : 0ull);
        cepDT list_type = store_dt ? cep_dt_clean(store_dt) : *dt_list_type();
        cepDT name_copy = cep_dt_clean(name);
        cell = cep_cell_add_list(root, &name_copy, 0, &list_type, CEP_STORAGE_LINKED_LIST);
        if (!cell) {
            CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] add_list failed domain=%08x tag=%08x\n",
                                    (unsigned)name_copy.domain,
                                    (unsigned)name_copy.tag);
        }
    } else {
        cepCell* resolved = cep_cell_resolve(cell);
        if (!resolved) {
            CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] resolve failed domain=%08x tag=%08x\n",
                                    name ? (unsigned)name->domain : 0u,
                                    name ? (unsigned)name->tag : 0u);
            return NULL;
        }
        if (resolved->store && resolved->store->indexing != CEP_INDEX_BY_INSERTION) {
            CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] rebuilding list name=%016llx/%016llx indexing=%d\n",
                                    (unsigned long long)cep_id(name ? name->domain : (cepID)0),
                                    (unsigned long long)cep_id(name ? name->tag : (cepID)0),
                                    resolved->store->indexing);
            if (!cep_cell_is_root(resolved)) {
                cep_cell_remove_hard(resolved, NULL);
            }
            cepDT list_type = store_dt ? cep_dt_clean(store_dt) : *dt_list_type();
            cepDT name_copy = cep_dt_clean(name);
            cell = cep_cell_add_list(root, &name_copy, 0, &list_type, CEP_STORAGE_LINKED_LIST);
            if (!cell) {
                CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] rebuild add_list failed\n");
                return NULL;
            }
            resolved = cep_cell_resolve(cell);
            if (!resolved || !resolved->store || resolved->store->indexing != CEP_INDEX_BY_INSERTION) {
                CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] rebuild produced invalid list\n");
                return NULL;
            }
        }
        if (store_dt && resolved->store) {
            cep_store_set_dt(resolved->store, store_dt);
        }
        cell = resolved;
    }
    return cell;
}

static void cep_heartbeat_prune_spacing(cepCell* spacing) {
    if (!spacing) {
        return;
    }

    size_t target_window = CEP_RUNTIME.spacing_window ? CEP_RUNTIME.spacing_window : CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    if (target_window == 0u) {
        target_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    }

    size_t count = 0u;
    cepCell* oldest_entry = NULL;
    cepBeatNumber oldest_beat = CEP_BEAT_INVALID;
    for (cepCell* entry = cep_cell_first_all(spacing);
         entry;
         entry = cep_cell_next_all(spacing, entry)) {
        count += 1u;
        const cepDT* name = cep_cell_get_name(entry);
        if (!name || !cep_id_is_numeric(name->tag)) {
            continue;
        }
        cepBeatNumber beat = (cepBeatNumber)(cep_id(name->tag) - 1u);
        if (oldest_entry == NULL || beat < oldest_beat) {
            oldest_entry = entry;
            oldest_beat = beat;
        }
    }

    while (count > target_window && oldest_entry) {
        cep_cell_remove_hard(oldest_entry, NULL);
        count -= 1u;

        if (count <= target_window) {
            break;
        }

        oldest_entry = NULL;
        oldest_beat = CEP_BEAT_INVALID;
        for (cepCell* entry = cep_cell_first_all(spacing);
             entry;
             entry = cep_cell_next_all(spacing, entry)) {
            const cepDT* name = cep_cell_get_name(entry);
            if (!name || !cep_id_is_numeric(name->tag)) {
                continue;
            }
            cepBeatNumber beat = (cepBeatNumber)(cep_id(name->tag) - 1u);
            if (oldest_entry == NULL || beat < oldest_beat) {
                oldest_entry = entry;
                oldest_beat = beat;
            }
        }
    }
}

static bool cep_heartbeat_record_spacing(cepBeatNumber beat, uint64_t interval_ns) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return false;
    }

    cepCell* analytics_root = ensure_root_dictionary(rt_root, dt_analytics_root_name(), NULL);
    if (!analytics_root) {
        return false;
    }

    cepCell* spacing = ensure_root_dictionary(analytics_root, dt_spacing_name(), NULL);
    if (!spacing) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* entry = cep_heartbeat_ensure_dictionary_child(spacing, &beat_name, NULL);
    if (!entry) {
        return false;
    }

    if (!cep_cell_put_uint64(entry, dt_interval_ns_name(), interval_ns)) {
        return false;
    }

    /* FIXME: Replace hard-prune once L1 predators/regulators manage analytics retention. */
    cep_heartbeat_prune_spacing(spacing);
    return true;
}

static void cep_lifecycle_reset_state(void) {
    cep_boot_ops_reset();
    for (size_t i = 0; i < CEP_LIFECYCLE_SCOPE_COUNT; ++i) {
        CEP_LIFECYCLE_STATE[i].ready = false;
        CEP_LIFECYCLE_STATE[i].teardown = false;
        CEP_LIFECYCLE_STATE[i].ready_beat = 0u;
        CEP_LIFECYCLE_STATE[i].td_beat = 0u;
    }
}

static bool cep_lifecycle_scope_dependencies_ready(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }

    const cepLifecycleScopeInfo* info = &CEP_LIFECYCLE_SCOPE_INFO[scope];
    for (size_t i = 0; i < info->dependency_count; ++i) {
        cepLifecycleScope dep = info->dependencies[i];
        if (dep >= CEP_LIFECYCLE_SCOPE_COUNT) {
            return false;
        }
        if (!CEP_LIFECYCLE_STATE[dep].ready) {
            return false;
        }
    }
    return true;
}

static cepCell* cep_lifecycle_get_dictionary(cepCell* parent, const cepDT* name, bool create) {
    if (!parent || !name) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(name);
    lookup.glob = 0u;

    cepCell* existing = cep_cell_find_by_name(parent, &lookup);
    if (!create) {
        return existing;
    }

    cepDT state_name = *dt_state_root();
    bool is_state_root = (cep_dt_compare(&lookup, &state_name) == 0);
    cepDT organ_dt = is_state_root ? cep_organ_store_dt("sys_state") : *dt_dictionary_type();

    if (existing) {
        cepCell* resolved = cep_cell_resolve(existing);
        if (!resolved) {
            return NULL;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            return NULL;
        }
        if (is_state_root && resolved->store) {
            cep_store_set_dt(resolved->store, &organ_dt);
        }
        return resolved;
    }

    cepDT name_copy = lookup;
    return cep_cell_add_dictionary(parent, &name_copy, 0, &organ_dt, CEP_STORAGE_RED_BLACK_T);
}

static bool cep_boot_ops_enabled(void) {
    return CEP_RUNTIME.policy.boot_ops;
}

static void cep_boot_ops_reset(void) {
    CEP_LIFECYCLE_OPS_STATE.boot_oid = cep_oid_invalid();
    CEP_LIFECYCLE_OPS_STATE.shdn_oid = cep_oid_invalid();
    CEP_LIFECYCLE_OPS_STATE.boot_started = false;
    CEP_LIFECYCLE_OPS_STATE.boot_closed = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_started = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_closed = false;
    CEP_LIFECYCLE_OPS_STATE.boot_failed = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_failed = false;
    CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_NONE;
    CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_NONE;
    CEP_LIFECYCLE_OPS_STATE.boot_last_beat = CEP_BEAT_INVALID;
    CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = CEP_BEAT_INVALID;
    CEP_LIFECYCLE_OPS_STATE.boot_kernel_ready = false;
    CEP_LIFECYCLE_OPS_STATE.boot_namepool_ready = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked = 0u;
}

static cepBeatNumber cep_boot_ops_effective_beat(void) {
    cepBeatNumber beat = cep_beat_index();
    return (beat == CEP_BEAT_INVALID) ? 0u : beat;
}

static bool cep_boot_ops_ready_for_next(cepBeatNumber last) {
    if (last == CEP_BEAT_INVALID) {
        return true;
    }
    return cep_boot_ops_effective_beat() > last;
}

static bool cep_boot_ops_progress_boot(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.boot_started) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_failed &&
        !CEP_LIFECYCLE_OPS_STATE.boot_closed &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        if (!cep_boot_ops_close_boot(false)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_closed = true;
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_closed) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_phase == CEP_BOOT_PHASE_KERNEL &&
        CEP_LIFECYCLE_OPS_STATE.boot_kernel_ready &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.boot_oid,
                                       dt_ist_store(),
                                       &CEP_LIFECYCLE_OPS_STATE.boot_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_STORE;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_phase == CEP_BOOT_PHASE_STORE &&
        CEP_LIFECYCLE_OPS_STATE.boot_namepool_ready &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.boot_oid,
                                       dt_ist_packs(),
                                       &CEP_LIFECYCLE_OPS_STATE.boot_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_PACKS;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_phase == CEP_BOOT_PHASE_PACKS &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        bool success = !CEP_LIFECYCLE_OPS_STATE.boot_failed;
        if (!cep_boot_ops_close_boot(success)) {
            CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_closed = true;
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    return true;
}

static bool cep_boot_ops_progress_shutdown(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.shdn_started) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_failed &&
        !CEP_LIFECYCLE_OPS_STATE.shdn_closed &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        if (!cep_boot_ops_close_shutdown(false)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_closed = true;
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_closed) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_phase == CEP_SHDN_PHASE_STOP &&
        CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked > 0u &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.shdn_oid,
                                       dt_ist_flush(),
                                       &CEP_LIFECYCLE_OPS_STATE.shdn_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_FLUSH;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    size_t expected = cep_lengthof(CEP_LIFECYCLE_TEARDOWN_ORDER);
    if (CEP_LIFECYCLE_OPS_STATE.shdn_phase == CEP_SHDN_PHASE_FLUSH &&
        CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked >= expected &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.shdn_oid,
                                       dt_ist_halt(),
                                       &CEP_LIFECYCLE_OPS_STATE.shdn_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_HALT;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_phase == CEP_SHDN_PHASE_HALT &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        bool success = !CEP_LIFECYCLE_OPS_STATE.shdn_failed;
        if (!cep_boot_ops_close_shutdown(success)) {
            CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_closed = true;
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    return true;
}

static bool cep_boot_ops_progress(void) {
    bool ok = cep_boot_ops_progress_boot();
    ok = cep_boot_ops_progress_shutdown() && ok;
    return ok;
}

static bool cep_boot_ops_publish_oid(const cepDT* field_name, cepOID oid) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    if (!sys_root) {
        return false;
    }

    cepCell* state_root = cep_lifecycle_get_dictionary(sys_root, dt_state_root(), true);
    if (!state_root) {
        return false;
    }

    cepDT lookup = cep_dt_clean(field_name);
    lookup.glob = 0u;
    cepCell* existing = cep_cell_find_by_name(state_root, &lookup);
    if (existing) {
        cep_cell_remove_hard(existing, NULL);
    }

    cepDT name_copy = lookup;
    cepDT type = cep_ops_make_dt("val/bytes");
    cepCell* node = cep_dict_add_value(state_root,
                                       &name_copy,
                                       &type,
                                       &oid,
                                       sizeof oid,
                                       sizeof oid);
    if (!node) {
        return false;
    }
    cep_cell_content_hash(node);
    return true;
}

static bool cep_boot_ops_record_state(cepOID oid, const cepDT* state_dt, bool* failure_flag) {
    if (!cep_oid_is_valid(oid) || !state_dt) {
        if (failure_flag) {
            *failure_flag = true;
        }
        return false;
    }

    if (!cep_op_state_set(oid, *state_dt, 0, NULL)) {
        fprintf(stderr,
                "[boot_ops] state_set failed oid=%llu:%llu state=%llu:%llu\n",
                (unsigned long long)oid.domain,
                (unsigned long long)oid.tag,
                (unsigned long long)state_dt->domain,
                (unsigned long long)state_dt->tag);
        fflush(stderr);
        if (failure_flag) {
            *failure_flag = true;
        }
        return false;
    }

    return true;
}

static bool cep_boot_ops_start_boot(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.boot_started) {
        return true;
    }

    const char* target = "/sys/state";
    cepDT verb = cep_ops_make_dt("op/boot");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, target, mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(oid)) {
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
        return false;
    }

    if (!cep_boot_ops_publish_oid(dt_boot_oid_field(), oid)) {
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
        return false;
    }

    if (!cep_boot_ops_record_state(oid, dt_ist_kernel(), &CEP_LIFECYCLE_OPS_STATE.boot_failed)) {
        return false;
    }

    CEP_LIFECYCLE_OPS_STATE.boot_oid = oid;
    CEP_LIFECYCLE_OPS_STATE.boot_started = true;
    CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_KERNEL;
    CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
    return true;
}

static bool cep_boot_ops_start_shutdown(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.shdn_started) {
        return true;
    }

    const char* target = "/sys/state";
    cepDT verb = cep_ops_make_dt("op/shdn");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, target, mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(oid)) {
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
        return false;
    }

    if (!cep_boot_ops_publish_oid(dt_shdn_oid_field(), oid)) {
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
        return false;
    }

    if (!cep_boot_ops_record_state(oid, dt_ist_stop(), &CEP_LIFECYCLE_OPS_STATE.shdn_failed)) {
        return false;
    }

    CEP_LIFECYCLE_OPS_STATE.shdn_oid = oid;
    CEP_LIFECYCLE_OPS_STATE.shdn_started = true;
    CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_STOP;
    CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
    return true;
}

static bool cep_boot_ops_close_boot(bool success) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.boot_started) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.boot_closed) {
        return true;
    }

    bool ok = cep_op_close(CEP_LIFECYCLE_OPS_STATE.boot_oid,
                           success ? *dt_sts_ok() : *dt_sts_fail(),
                           NULL,
                           0u);
    if (!ok) {
        fprintf(stderr, "[boot_ops] op_close boot failed success=%d\n", success ? 1 : 0);
        fflush(stderr);
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
        return false;
    }
    CEP_LIFECYCLE_OPS_STATE.boot_closed = true;
    CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_CLOSED;
    CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
    if (!success) {
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
    }
    return true;
}

static bool cep_boot_ops_close_shutdown(bool success) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.shdn_started) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.shdn_closed) {
        return true;
    }

    bool ok = cep_op_close(CEP_LIFECYCLE_OPS_STATE.shdn_oid,
                           success ? *dt_sts_ok() : *dt_sts_fail(),
                           NULL,
                           0u);
    if (!ok) {
        fprintf(stderr, "[boot_ops] op_close shutdown failed success=%d\n", success ? 1 : 0);
        fflush(stderr);
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
        return false;
    }
    CEP_LIFECYCLE_OPS_STATE.shdn_closed = true;
    CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_CLOSED;
    CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
    if (!success) {
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
    }
    return true;
}


typedef struct {
    cepStore store;
    void*    head;
    void*    tail;
} cepListView;

static const cepDT* cep_cas_store_dt(void) {
    static cepDT cached = {0};
    if (!cep_dt_is_valid(&cached)) {
        cached = cep_organ_store_dt("cas");
    }
    return &cached;
}

static void cep_lifecycle_reload_state(void) {
    cep_lifecycle_reset_state();
}


static void cep_heartbeat_clear_store(cepCell* cell) {
    if (!cell) {
        return;
    }

    if (cell->store) {
        bool is_cas = false;
        const cepDT* cas_dt = cep_cas_store_dt();
        if (cas_dt && cep_dt_is_valid(&cell->store->dt) && cep_dt_compare(&cell->store->dt, cas_dt) == 0) {
            is_cas = true;
        } else if (cell == CEP_RUNTIME.topology.cas) {
            is_cas = true;
        }
        if (is_cas) {
            if (cell->store->storage == CEP_STORAGE_LINKED_LIST) {
                const cepListView* list = (const cepListView*)cell->store;
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_before] store=%p chd=%zu head=%p tail=%p\n",
                       (void*)cell->store,
                       cell->store->chdCount,
                       (void*)list->head,
                       (void*)list->tail);
            } else {
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_before] store=%p storage=%u chd=%zu\n",
                       (void*)cell->store,
                       cell->store->storage,
                       cell->store->chdCount);
            }
        }
        cep_store_delete_children_hard(cell->store);
        if (is_cas) {
            if (cell->store->storage == CEP_STORAGE_LINKED_LIST) {
                const cepListView* list = (const cepListView*)cell->store;
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_after] store=%p chd=%zu head=%p tail=%p\n",
                       (void*)cell->store,
                       cell->store->chdCount,
                       (void*)list->head,
                       (void*)list->tail);
            } else {
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_after] store=%p storage=%u chd=%zu\n",
                       (void*)cell->store,
                       cell->store->storage,
                       cell->store->chdCount);
            }
        }
    }
}


static void cep_heartbeat_reset_runtime_cells(void) {
    /* Keep the structural nodes but clear their contents. */
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.rt);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.journal);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.tmp);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.data);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.cas);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.env);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.lib);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.enzymes);
}


/* Establishes the heartbeat runtime by wiring up the root cells and lazy
 * allocating the enzyme registry so every public entry point works from a
 * consistent topology baseline.
 */
/** Create the runtime directories and initialise scratch buffers so future
    beats can rely on the topology without performing lazy checks. The routine
    is idempotent and safe to call before tests exercise the runtime. */
bool cep_heartbeat_bootstrap(void) {
#define CEP_BOOT_FAIL(reason)   do { fail_reason = (reason); goto fail; } while (0)
    if (CEP_RUNTIME.bootstrapping) {
        return true;
    }

    bool success = false;
    static const char* fail_reason = NULL;
    CEP_RUNTIME.bootstrapping = true;

    bool first_bootstrap = (CEP_RUNTIME.topology.root == NULL);

    cep_cell_system_ensure();

    cepCell* root = cep_root();
    if (!root) {
        CEP_BOOT_FAIL("root");
    }

    CEP_DEFAULT_TOPOLOGY.root = root;
    if (!CEP_RUNTIME.topology.root) {
        CEP_RUNTIME.topology.root = root;
    }

    const cepDT* sys_name = dt_sys_root_name();
    cepCell* sys = ensure_root_dictionary(root, sys_name, NULL);
    if (!sys) {
        CEP_BOOT_FAIL("sys dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.sys = sys;
    if (!CEP_RUNTIME.topology.sys) {
        CEP_RUNTIME.topology.sys = sys;
    }

    cepCell* state_root = cep_lifecycle_get_dictionary(sys, dt_state_root(), true);
    if (!state_root) {
        goto fail;
    }

    cepDT organs_store = cep_organ_store_dt("sys_organs");
    const cepDT* organs_name = dt_organs_root_name();
    cepCell* organs = ensure_root_dictionary(sys, organs_name, &organs_store);
    if (!organs) {
        CEP_BOOT_FAIL("organs dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.organs = organs;
    if (!CEP_RUNTIME.topology.organs) {
        CEP_RUNTIME.topology.organs = organs;
    }

    const cepDT* rt_name = dt_rt_root_name();
    cepCell* rt = ensure_root_dictionary(root, rt_name, NULL);
    if (!rt) {
        CEP_BOOT_FAIL("rt dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.rt = rt;
    if (!CEP_RUNTIME.topology.rt) {
        CEP_RUNTIME.topology.rt = rt;
    }

    cepDT beat_store = cep_organ_store_dt("rt_beat");
    const cepDT* beat_name = dt_beat_root_name();
    cepCell* beat_root = ensure_root_dictionary(rt, beat_name, &beat_store);
    if (!beat_root) {
        CEP_BOOT_FAIL("beat dictionary");
    }

    (void)cep_cell_ensure_dictionary_child(rt, dt_ops_rt_name(), CEP_STORAGE_RED_BLACK_T);

    cepDT journal_store = cep_organ_store_dt("journal");
    const cepDT* journal_name = dt_journal_root_name();
    cepCell* journal = ensure_root_dictionary(root, journal_name, &journal_store);
    if (!journal) {
        CEP_BOOT_FAIL("journal dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.journal = journal;
    if (!CEP_RUNTIME.topology.journal) {
        CEP_RUNTIME.topology.journal = journal;
    }

    cepDT env_store = cep_organ_store_dt("env");
    const cepDT* env_name = dt_env_root_name();
    cepCell* env = ensure_root_dictionary(root, env_name, &env_store);
    if (!env) {
        CEP_BOOT_FAIL("env dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.env = env;
    if (!CEP_RUNTIME.topology.env) {
        CEP_RUNTIME.topology.env = env;
    }

    cepDT cas_store = cep_organ_store_dt("cas");
    const cepDT* cas_name = dt_cas_root_name();
    cepCell* cas = ensure_root_dictionary(root, cas_name, &cas_store);
    if (!cas) {
        CEP_BOOT_FAIL("cas dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.cas = cas;
    if (!CEP_RUNTIME.topology.cas) {
        CEP_RUNTIME.topology.cas = cas;
    }

    cepDT lib_store = cep_organ_store_dt("lib");
    const cepDT* lib_name = dt_lib_root_name();
    cepCell* lib = ensure_root_dictionary(root, lib_name, &lib_store);
    if (!lib) {
        CEP_BOOT_FAIL("lib dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.lib = lib;
    if (!CEP_RUNTIME.topology.lib) {
        CEP_RUNTIME.topology.lib = lib;
    }

    const cepDT* data_name = dt_data_root_name();
    cepCell* data = ensure_root_dictionary(root, data_name, NULL);
    if (!data) {
        CEP_BOOT_FAIL("data dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.data = data;
    if (!CEP_RUNTIME.topology.data) {
        CEP_RUNTIME.topology.data = data;
    }
    if (!cep_cei_diagnostics_mailbox()) {
        CEP_BOOT_FAIL("cei diagnostics mailbox");
    }

    cepDT tmp_store = cep_organ_store_dt("tmp");
    const cepDT* tmp_name = dt_tmp_root_name();
    fprintf(stderr, "[bootstrap tmp] tmp_name=%p domain=%016llx tag=%016llx store=%016llx/%016llx\n",
            (void*)tmp_name,
            tmp_name ? (unsigned long long)cep_id(tmp_name->domain) : 0ull,
            tmp_name ? (unsigned long long)cep_id(tmp_name->tag) : 0ull,
            (unsigned long long)cep_id(tmp_store.domain),
            (unsigned long long)cep_id(tmp_store.tag));
    cepCell* tmp = ensure_root_list(root, tmp_name, &tmp_store);
    if (!tmp) {
        CEP_BOOT_FAIL("tmp list");
    }
    CEP_DEFAULT_TOPOLOGY.tmp = tmp;
    if (!CEP_RUNTIME.topology.tmp) {
        CEP_RUNTIME.topology.tmp = tmp;
    }

    cepDT enzymes_store = cep_organ_store_dt("enzymes");
    const cepDT* enzymes_name = dt_enzymes_root_name();
    cepCell* enzymes = ensure_root_dictionary(root, enzymes_name, &enzymes_store);
    if (!enzymes) {
        CEP_BOOT_FAIL("enzymes dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.enzymes = enzymes;
    if (!CEP_RUNTIME.topology.enzymes) {
        CEP_RUNTIME.topology.enzymes = enzymes;
    }

    if (first_bootstrap) {
        cep_lifecycle_reload_state();
    }

    if (!cep_runtime_has_registry()) {
        CEP_RUNTIME.registry = cep_enzyme_registry_create();
        if (!CEP_RUNTIME.registry) {
            CEP_BOOT_FAIL("registry create");
        }
    }

    if (!cep_cell_operations_register(CEP_RUNTIME.registry)) {
        CEP_BOOT_FAIL("ops register");
    }

    if (!cep_organ_runtime_bootstrap()) {
        CEP_BOOT_FAIL("organ runtime bootstrap");
    }

    if (!cep_heartbeat_register_l0_organs()) {
        CEP_BOOT_FAIL("register l0 organs");
    }

    if (!cep_l0_organs_register(CEP_RUNTIME.registry)) {
        CEP_BOOT_FAIL("organs register");
    }

    if (!cep_l0_organs_bind_roots()) {
        CEP_BOOT_FAIL("bind roots");
    }

    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_KERNEL);
    success = true;

fail:
    CEP_RUNTIME.bootstrapping = false;
    if (!success && fail_reason) {
        CEP_DEBUG_PRINTF_STDOUT("[bootstrap] fail: %s\n", fail_reason);
        fprintf(stderr, "[bootstrap] fail: %s\n", fail_reason);
        fflush(stderr);
        fail_reason = NULL;
    }
#undef CEP_BOOT_FAIL
    return success;
}


/* Merges caller supplied topology and policy values with the defaults so the
 * runtime can respect overrides without losing the safety of fully initialised
 * fallback structures.
 */
/** Configure the heartbeat runtime before any directories are created so the
    engine knows which roots to mount and which policy knobs to honour. The
    function copies the user-provided topology/policy and primes the registry
    pointer for later bootstrap work. */
bool cep_heartbeat_configure(const cepHeartbeatTopology* topology, const cepHeartbeatPolicy* policy) {
    if (!policy) {
        return false;
    }

    if (!policy->boot_ops) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepHeartbeatTopology merged = CEP_DEFAULT_TOPOLOGY;
    if (topology) {
        if (topology->root)     merged.root     = topology->root;
        if (topology->sys)      merged.sys      = topology->sys;
        if (topology->rt)       merged.rt       = topology->rt;
        if (topology->journal)  merged.journal  = topology->journal;
        if (topology->env)      merged.env      = topology->env;
        if (topology->cas)      merged.cas      = topology->cas;
        if (topology->lib)      merged.lib      = topology->lib;
        if (topology->data)     merged.data     = topology->data;
        if (topology->tmp)      merged.tmp      = topology->tmp;
        if (topology->enzymes)  merged.enzymes  = topology->enzymes;
        if (topology->organs)   merged.organs   = topology->organs;
    }

    CEP_RUNTIME.topology = merged;
    CEP_RUNTIME.policy   = *policy;
    CEP_RUNTIME.policy.boot_ops = policy->boot_ops;
    if (CEP_RUNTIME.policy.spacing_window == 0u) {
        CEP_RUNTIME.policy.spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    }
    CEP_RUNTIME.spacing_window = CEP_RUNTIME.policy.spacing_window;
    return true;
}


/* Starts the heartbeat loop at the configured entry point so the scheduler can
 * begin advancing beats using the state prepared during configuration.
 */
/** Start the heartbeat loop after configuration, wiring the registry and
    resetting state so the first beat observes a clean slate. */
bool cep_heartbeat_startup(void) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.current = CEP_RUNTIME.policy.start_at;
    CEP_RUNTIME.running = true;
    CEP_RUNTIME.spacing_window = (CEP_RUNTIME.policy.spacing_window != 0u)
        ? CEP_RUNTIME.policy.spacing_window
        : CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    if (cep_boot_ops_enabled()) {
        (void)cep_boot_ops_start_boot();
    }
    cep_beat_begin_capture();
    if (!cep_boot_ops_progress()) {
        return false;
    }
    return true;
}


/* Restarts execution by clearing per-run cells and resetting the beat counter
 * so a fresh cycle can reuse the existing topology without leaking data.
 */
/** Restart the heartbeat runtime without tearing down directories so callers
    can recover from transient failures while preserving topology. */
bool cep_heartbeat_restart(void) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cep_heartbeat_reset_runtime_cells();

    CEP_RUNTIME.current = CEP_RUNTIME.policy.start_at;
    CEP_RUNTIME.running = true;
    CEP_RUNTIME.spacing_window = (CEP_RUNTIME.policy.spacing_window != 0u)
        ? CEP_RUNTIME.policy.spacing_window
        : CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    if (cep_boot_ops_enabled()) {
        (void)cep_boot_ops_start_boot();
    }
    cep_beat_begin_capture();
    if (!cep_boot_ops_progress()) {
        return false;
    }
    return true;
}


/* Forces the runtime to begin at an explicit beat to support manual recovery or
 * replay scenarios where the caller chooses the next cadence.
 */
/** Prepare runtime bookkeeping for the selected beat number so resolve and
    execution have fresh impulse queues and caches. */
bool cep_heartbeat_begin(cepBeatNumber beat) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.current = beat;
    CEP_RUNTIME.running = true;
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    if (cep_boot_ops_enabled()) {
        (void)cep_boot_ops_start_boot();
    }
    cep_beat_begin_capture();
    if (!cep_boot_ops_progress()) {
        return false;
    }
    return true;
}


/* Resolves the agenda for the current beat by activating deferred enzyme
 * registrations and draining the impulse queue into deterministic execution order.
 */
/** Resolve the execution agenda for the current beat by draining the impulse queue,
    matching impulses, and building the ordered list of enzymes to run. */
bool cep_heartbeat_resolve_agenda(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    if (!cep_boot_ops_progress()) {
        return false;
    }

    cep_beat_begin_compute();

    if (CEP_RUNTIME.registry) {
        cep_enzyme_registry_activate_pending(CEP_RUNTIME.registry);
    }

    return cep_heartbeat_process_impulses();
}


/* Executes the resolved agenda; for now it simply mirrors the running flag so
 * callers can already chain the step flow before real executors arrive.
 */
/** Execute the enzymes scheduled for this beat, short-circuiting on fatal
    errors while allowing retries to propagate to the agenda statistics. */
bool cep_heartbeat_execute_agenda(void) {
    // Enzyme callbacks run during cep_heartbeat_process_impulses(); keep this
    // shim in sync if we refactor execution into its own phase.
    return CEP_RUNTIME.running;
}


/* Commits staged work by rotating the impulse queues so signals emitted during
 * beat N become visible to the dispatcher at beat N+1.
 */
/** Stage committed writes so they become visible at the next beat boundary,
    flushing staged caches and journaling the results. */
bool cep_heartbeat_stage_commit(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    cep_beat_begin_commit();

    if (!cep_stream_commit_pending()) {
        fprintf(stderr, "[stage_commit] stream commit failed\n");
        fflush(stderr);
        return false;
    }

    if (cep_heartbeat_policy_use_dirs()) {
        size_t promoted = CEP_RUNTIME.impulses_next.count;
        const char* plural = (promoted == 1u) ? "" : "s";
        cepBeatNumber current = (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : CEP_RUNTIME.current;
        cepBeatNumber next = (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : CEP_RUNTIME.current + 1u;
        int written = snprintf(NULL, 0, "commit: promoted %zu impulse%s -> beat %" PRIu64,
                                promoted, plural, (unsigned long long)next);
        if (written < 0) {
            fprintf(stderr, "[stage_commit] snprintf size failed\n");
            fflush(stderr);
            return false;
        }

        size_t size = (size_t)written + 1u;
        char* message = cep_malloc(size);
        if (!message) {
            fprintf(stderr, "[stage_commit] message alloc failed\n");
            fflush(stderr);
            return false;
        }

        snprintf(message, size, "commit: promoted %zu impulse%s -> beat %" PRIu64,
                 promoted, plural, (unsigned long long)next);

        bool recorded = cep_heartbeat_record_stage_entry(current, message);
        cep_free(message);
        if (!recorded) {
            fprintf(stderr, "[stage_commit] record stage entry failed\n");
            fflush(stderr);
            return false;
        }
    }

    if (!cep_ops_stage_commit()) {
        fprintf(stderr, "[stage_commit] ops stage commit failed err=%d\n", cep_ops_debug_last_error());
        fflush(stderr);
        return false;
    }

    cep_heartbeat_impulse_queue_swap(&CEP_RUNTIME.impulses_current, &CEP_RUNTIME.impulses_next);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    cep_beat_begin_capture();
    return true;
}


/** Publish the beat index without exposing the runtime structure so callers can
    tag journal entries or error messages with a stable counter. During
    bootstrap the heartbeat number is undefined, therefore the helper reports
    zero until the scheduler advances at least once. */
cepOpCount cep_beat_index(void) {
    return (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : (cepOpCount)CEP_RUNTIME.current;
}


/** Report which heartbeat phase is currently active so Layer 0 services can
    gate actions (for example, ingest vs. compute mutations) without tracking
    scheduler calls manually. The value reflects the most recent *_begin_* hook
    that ran. */
cepBeatPhase cep_beat_phase(void) {
    return CEP_RUNTIME.phase;
}


/** Surface how many enzyme registrations were deferred into this beat so tests
    and diagnostics can assert the agenda freeze contract stays intact during
    mid-cycle registrations. The value resets when the next Capture phase
    begins. */
size_t cep_beat_deferred_activation_count(void) {
    return CEP_RUNTIME.deferred_activations;
}


/** Accumulate the number of enzymes promoted out of the pending queue so the
    debug counter reflects mid-beat registrations that will only execute on the
    next cycle. Callers pass zero when nothing was promoted to avoid touching the
    counter unnecessarily. */
void cep_beat_note_deferred_activation(size_t count) {
    if (!count) {
        return;
    }

    CEP_RUNTIME.deferred_activations += count;
}


/** Mark the beginning of the capture phase so ingestion helpers can freeze
    inputs deterministically. The helper also clears the deferred activation
    counter because a fresh beat will tally its own promotions. */
void cep_beat_begin_capture(void) {
    CEP_RUNTIME.phase = CEP_BEAT_CAPTURE;
    CEP_RUNTIME.deferred_activations = 0u;
}


/** Switch the runtime into the compute phase so enzyme resolution and
    execution can proceed while asserts keep an eye on phase transitions. */
void cep_beat_begin_compute(void) {
    CEP_RUNTIME.phase = CEP_BEAT_COMPUTE;
}


/** Enter the commit phase so staging helpers can flush writes and diagnostics
    can confirm that agenda execution reached the last step for the beat. */
void cep_beat_begin_commit(void) {
    CEP_RUNTIME.phase = CEP_BEAT_COMMIT;
}


/* Drives a full beat by cascading resolve, execute, and commit stages and bumps
 * the counter when everything succeeds so the loop progresses deterministically.
 */
/** Convenience helper that performs resolve, execute, and stage for a single
    beat, returning false if any phase fails. */
bool cep_heartbeat_step(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    bool ok = cep_heartbeat_resolve_agenda();
    if (!ok) {
        fprintf(stderr, "[heartbeat_step] resolve agenda failed\n");
        fflush(stderr);
        return false;
    }

    ok = cep_heartbeat_execute_agenda();
    if (!ok) {
        fprintf(stderr, "[heartbeat_step] execute agenda failed\n");
        fflush(stderr);
        return false;
    }

    ok = cep_heartbeat_stage_commit();
    if (!ok) {
        fprintf(stderr, "[heartbeat_step] stage commit failed\n");
        fflush(stderr);
        return false;
    }

    if (ok && CEP_RUNTIME.current != CEP_BEAT_INVALID) {
        CEP_RUNTIME.current += 1u;
    }

    return ok;
}


bool cep_heartbeat_emit_shutdown(void) {
    if (CEP_RUNTIME.sys_shutdown_emitted) {
        return true;
    }

    if (!cep_runtime_has_registry()) {
        CEP_RUNTIME.sys_shutdown_emitted = true;
        return true;
    }

    if (!CEP_RUNTIME.running) {
        return false;
    }

    bool ok = cep_boot_ops_start_shutdown();

    for (size_t i = 0; i < cep_lengthof(CEP_LIFECYCLE_TEARDOWN_ORDER); ++i) {
        ok = cep_lifecycle_scope_mark_teardown(CEP_LIFECYCLE_TEARDOWN_ORDER[i]) && ok;
    }

    ok = cep_boot_ops_progress() && ok;
    ok = ok && !CEP_LIFECYCLE_OPS_STATE.shdn_failed;

    if (ok) {
        CEP_RUNTIME.sys_shutdown_emitted = true;
    }
    return ok;
}

/** Stop the heartbeat runtime and release scratch buffers so subsequent
    start-ups begin from a clean state. */
void cep_heartbeat_shutdown(void) {
    (void)cep_heartbeat_emit_shutdown();

    cep_runtime_reset_state(true);
    cep_runtime_reset_defaults();
    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
}


/** Drain the in-memory impulse queue and move entries into the agenda cache so
    resolve and execute phases operate on stable snapshots. */
bool cep_heartbeat_process_impulses(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    cepEnzymeRegistry* registry = CEP_RUNTIME.registry;
    size_t registry_size = registry ? cep_enzyme_registry_size(registry) : 0u;
    cepHeartbeatScratch* scratch = &CEP_RUNTIME.scratch;

    if (registry_size > 0u) {
        if (!cep_heartbeat_scratch_ensure_ordered(scratch, registry_size)) {
            fprintf(stderr, "[process_impulses] ensure ordered failed registry_size=%zu\n", registry_size);
            fflush(stderr);
            return false;
        }
    }

    cepHeartbeatImpulseQueue* queue = &CEP_RUNTIME.impulses_current;
    size_t impulse_count = queue->count;

    if (impulse_count == 0u) {
        cep_heartbeat_scratch_next_generation(scratch);
        cep_heartbeat_dispatch_cache_cleanup_generation(scratch);
        return true;
    }

    size_t desired_slots = impulse_count * 2u;
    if (desired_slots < 8u) {
        desired_slots = 8u;
    }
    size_t reserve = cep_next_pow_of_two(desired_slots);
    if (!cep_heartbeat_dispatch_cache_reserve(scratch, reserve)) {
        fprintf(stderr, "[process_impulses] dispatch reserve failed reserve=%zu\n", reserve);
        fflush(stderr);
        return false;
    }

    cep_heartbeat_scratch_next_generation(scratch);

    bool ok = true;

    for (size_t i = 0; i < impulse_count && ok; ++i) {
        cepHeartbeatImpulseRecord* record = &queue->records[i];
        cepImpulse impulse = {
            .signal_path = record->signal_path,
            .target_path = record->target_path,
        };

        bool fresh = false;
        uint64_t hash = cep_heartbeat_impulse_hash(record);
        cepHeartbeatDispatchCacheEntry* entry = cep_heartbeat_dispatch_cache_acquire(scratch, record, hash, &fresh);
        if (!entry) {
            fprintf(stderr, "[process_impulses] dispatch entry acquire failed\n");
            fflush(stderr);
            ok = false;
            break;
        }

        if (fresh) {
            size_t resolved = 0u;
            if (registry && registry_size > 0u) {
                resolved = cep_enzyme_resolve(registry, &impulse, scratch->ordered, scratch->ordered_capacity);
            }

            if (resolved > 0u) {
                if (entry->descriptor_capacity < resolved) {
                    size_t bytes = resolved * sizeof(*entry->descriptors);
                    const cepEnzymeDescriptor** buffer = entry->descriptors ?
                        cep_realloc(entry->descriptors, bytes) :
                        cep_malloc(bytes);
                    if (!buffer) {
                        ok = false;
                        break;
                    }
                    entry->descriptors = buffer;
                    entry->descriptor_capacity = resolved;
                }

                if (!cep_heartbeat_dispatch_entry_reserve_memo(entry, resolved)) {
                    fprintf(stderr, "[process_impulses] memo reserve failed resolved=%zu\n", resolved);
                    fflush(stderr);
                    ok = false;
                    break;
                }

                memcpy(entry->descriptors, scratch->ordered, resolved * sizeof(*scratch->ordered));
                memset(entry->memo, 0, resolved * sizeof(*entry->memo));
                entry->memo_count = resolved;
            } else {
                entry->memo_count = 0u;
            }
            entry->descriptor_count = resolved;
        } else if (entry->descriptor_count > entry->memo_count) {
            size_t previous = entry->memo_count;
            if (!cep_heartbeat_dispatch_entry_reserve_memo(entry, entry->descriptor_count)) {
                fprintf(stderr, "[process_impulses] memo reserve expansion failed count=%zu\n", entry->descriptor_count);
                fflush(stderr);
                ok = false;
                break;
            }
            memset(entry->memo + previous, 0, (entry->descriptor_count - previous) * sizeof(*entry->memo));
            entry->memo_count = entry->descriptor_count;
        }

        if (!ok) {
            break;
        }

        if (entry->descriptor_count == 0u && cep_heartbeat_policy_use_dirs()) {
            ok = cep_heartbeat_record_agenda_entry(CEP_RUNTIME.current, NULL, CEP_ENZYME_SUCCESS, &impulse);
            if (!ok) {
                fprintf(stderr, "[process_impulses] record agenda entry failed (no-match)\n");
                fflush(stderr);
            }
        }

        if (entry->descriptor_count > 0u && entry->descriptors) {
            cepHeartbeatDescriptorMemo* memo_array = entry->memo;
            for (size_t j = 0; j < entry->descriptor_count && ok; ++j) {
                const cepEnzymeDescriptor* descriptor = entry->descriptors[j];
                if (!descriptor || !descriptor->callback) {
                    continue;
                }

                cepHeartbeatDescriptorMemo* memo = (memo_array && j < entry->memo_count) ? &memo_array[j] : NULL;
                bool executed_before = memo && memo->executed;
                bool should_run = true;
                unsigned flags = descriptor->flags;

                if (executed_before && should_run) {
                    if (flags & CEP_ENZYME_FLAG_STATEFUL) {
                        should_run = false;
                    }
                    if (should_run && (flags & CEP_ENZYME_FLAG_EMIT_SIGNALS) && memo->emitted) {
                        should_run = false;
                    }
                    if (should_run && (flags & CEP_ENZYME_FLAG_IDEMPOTENT) && memo->last_rc == CEP_ENZYME_SUCCESS) {
                        should_run = false;
                    }
                }

                if (!should_run) {
                    if (cep_heartbeat_policy_use_dirs()) {
                        int rc_log = memo ? memo->last_rc : CEP_ENZYME_SUCCESS;
                    if (!cep_heartbeat_record_agenda_entry(CEP_RUNTIME.current, descriptor, rc_log, &impulse)) {
                        fprintf(stderr, "[process_impulses] record agenda entry failed (skip)\n");
                        fflush(stderr);
                        ok = false;
                        break;
                    }
                    }
                    continue;
                }

                CEP_RUNTIME.current_descriptor = descriptor;
                size_t before_signals = CEP_RUNTIME.impulses_next.count;
                int rc = descriptor->callback(impulse.signal_path, impulse.target_path);
                CEP_RUNTIME.current_descriptor = NULL;
                CEP_DEBUG_PRINTF("DEBUG heartbeat: descriptor %llu:%llu callback=%p rc=%d\n",
                        (unsigned long long)descriptor->name.domain,
                        (unsigned long long)descriptor->name.tag,
                        (void*)descriptor->callback,
                        rc);
                size_t after_signals = CEP_RUNTIME.impulses_next.count;
                bool emitted = after_signals > before_signals;

                if (memo) {
                    memo->executed = 1u;
                    memo->last_rc = rc;
                    if (emitted) {
                        memo->emitted = 1u;
                    }
                }

                if (cep_heartbeat_policy_use_dirs()) {
                    if (!cep_heartbeat_record_agenda_entry(CEP_RUNTIME.current, descriptor, rc, &impulse)) {
                        fprintf(stderr, "[process_impulses] record agenda entry failed rc=%d\n", rc);
                        fflush(stderr);
                        ok = false;
                        break;
                    }
                }
                if (rc == CEP_ENZYME_FATAL) {
                    char fatal_label[64];
                    const char* fatal_name = cep_heartbeat_descriptor_label(descriptor, fatal_label, sizeof fatal_label);
                    fprintf(stderr, "[process_impulses] descriptor fatal rc label=%s\n",
                            fatal_name ? fatal_name : "<null>");
                    fflush(stderr);
                    ok = false;
                    break;
                }

                if (rc == CEP_ENZYME_RETRY) {
                    if (!cep_heartbeat_impulse_queue_append(&CEP_RUNTIME.impulses_next, &impulse)) {
                        ok = false;
                        break;
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < impulse_count; ++i) {
        cep_heartbeat_impulse_record_clear(&queue->records[i]);
    }
    queue->count = 0u;

    cep_heartbeat_dispatch_cache_cleanup_generation(scratch);

    /* TODO: Feed this resolver cache with real-time stats—e.g. track miss ratios,
     * impulse uniqueness, and registry churn—to adapt cache sizes, fall back to
     * direct dispatch when reuse is low, or pre-populate hot pairs before the beat.
     * */
     
    return ok;
}


bool cep_heartbeat_publish_wallclock(cepBeatNumber beat, uint64_t unix_timestamp_ns) {
    if (beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return false;
    }

    cepCell* beat_root = ensure_root_dictionary(rt_root, dt_beat_root_name(), NULL);
    if (!beat_root) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_dictionary_child(beat_root, &beat_name, NULL);
    if (!beat_cell) {
        return false;
    }

    cepCell* meta = cep_heartbeat_ensure_meta_child(beat_cell);
    if (!meta) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(meta, dt_unix_ts_name());
    if (existing) {
        existing = cep_cell_resolve(existing);
    }
    if (existing && cep_cell_has_data(existing)) {
        const char* stored_text = (const char*)cep_cell_data(existing);
        if (stored_text) {
            char* endptr = NULL;
            uint64_t parsed = strtoull(stored_text, &endptr, 10);
            if (endptr && *endptr == '\0' && parsed == unix_timestamp_ns) {
                return true;
            }
        }
        return false;
    }

    if (!cep_cell_put_uint64(meta, dt_unix_ts_name(), unix_timestamp_ns)) {
        return false;
    }

    if (CEP_RUNTIME.last_wallclock_beat != CEP_BEAT_INVALID &&
        beat > CEP_RUNTIME.last_wallclock_beat) {
        uint64_t interval = (unix_timestamp_ns >= CEP_RUNTIME.last_wallclock_ns)
            ? (unix_timestamp_ns - CEP_RUNTIME.last_wallclock_ns)
            : 0u;
        if (!cep_heartbeat_record_spacing(beat, interval)) {
            return false;
        }
    }

    if (CEP_RUNTIME.last_wallclock_beat == CEP_BEAT_INVALID ||
        beat >= CEP_RUNTIME.last_wallclock_beat) {
        CEP_RUNTIME.last_wallclock_beat = beat;
        CEP_RUNTIME.last_wallclock_ns = unix_timestamp_ns;
    }

    return true;
}


bool cep_heartbeat_beat_to_unix(cepBeatNumber beat, uint64_t* unix_timestamp_ns) {
    if (!unix_timestamp_ns || beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (!cep_cell_system_initialized()) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root || cep_cell_is_void(rt_root)) {
        return false;
    }

    cepCell* beat_root = cep_cell_find_by_name(rt_root, dt_beat_root_name());
    if (!beat_root || cep_cell_is_void(beat_root)) {
        return false;
    }

    cepCell* resolved_root = cep_cell_resolve(beat_root);
    if (!resolved_root || cep_cell_is_void(resolved_root) || !resolved_root->store) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* beat_cell = cep_cell_find_by_name(resolved_root, &beat_name);
    if (!beat_cell || cep_cell_is_void(beat_cell)) {
        return false;
    }

    beat_cell = cep_cell_resolve(beat_cell);
    if (!beat_cell || cep_cell_is_void(beat_cell)) {
        return false;
    }

    cepCell* meta = cep_cell_find_by_name(beat_cell, dt_meta_name());
    if (!meta || cep_cell_is_void(meta)) {
        return false;
    }

    meta = cep_cell_resolve(meta);
    if (!meta || cep_cell_is_void(meta)) {
        return false;
    }

    cepCell* timestamp = cep_cell_find_by_name(meta, dt_unix_ts_name());
    if (!timestamp || cep_cell_is_void(timestamp)) {
        return false;
    }

    timestamp = cep_cell_resolve(timestamp);
    if (!timestamp || !cep_cell_has_data(timestamp)) {
        return false;
    }

    const char* stored_text = (const char*)cep_cell_data(timestamp);
    if (!stored_text) {
        return false;
    }

    char* endptr = NULL;
    uint64_t parsed = (uint64_t)strtoull(stored_text, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }

    *unix_timestamp_ns = parsed;
    return true;
}


size_t cep_heartbeat_get_spacing_window(void) {
    size_t window = CEP_RUNTIME.spacing_window;
    if (window == 0u) {
        window = CEP_RUNTIME.policy.spacing_window;
    }
    if (window == 0u) {
        window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    }
    return window;
}


bool cep_heartbeat_set_spacing_window(size_t window) {
    if (window == 0u) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.spacing_window = window;
    CEP_RUNTIME.policy.spacing_window = window;

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return true;
    }

    cepCell* analytics_root = cep_cell_find_by_name(rt_root, dt_analytics_root_name());
    if (!analytics_root) {
        return true;
    }
    analytics_root = cep_cell_resolve(analytics_root);
    if (!analytics_root) {
        return false;
    }

    cepCell* spacing = cep_cell_find_by_name(analytics_root, dt_spacing_name());
    if (!spacing) {
        return true;
    }
    spacing = cep_cell_resolve(spacing);
    if (!spacing) {
        return false;
    }

    cep_heartbeat_prune_spacing(spacing);
    return true;
}


/** Expose the currently active beat so observers can align their work with the
    scheduler state. */
cepBeatNumber cep_heartbeat_current(void) {
    return CEP_RUNTIME.current;
}


/** Compute the next beat index while guarding against the invalid sentinel so
    callers never advance past an uninitialised state. */
cepBeatNumber cep_heartbeat_next(void) {
    if (CEP_RUNTIME.current == CEP_BEAT_INVALID) {
        return CEP_BEAT_INVALID;
    }

    return CEP_RUNTIME.current + 1u;
}


/** Return a pointer to the current policy so readers can inspect timing rules
    without taking ownership of the underlying storage. */
const cepHeartbeatPolicy* cep_heartbeat_policy(void) {
    return &CEP_RUNTIME.policy;
}


/** Return the active topology structure so clients can access shared roots the
    runtime prepared during bootstrap. */
const cepHeartbeatTopology* cep_heartbeat_topology(void) {
    return &CEP_RUNTIME.topology;
}


/** Ensure the runtime is initialised and expose the shared enzyme registry so
    listeners can register dispatchers without duplicating bootstrap checks. */
cepEnzymeRegistry* cep_heartbeat_registry(void) {
    if (!cep_heartbeat_bootstrap()) {
        return NULL;
    }
    return CEP_RUNTIME.registry;
}


/** Queue a signal/target pair to be processed on the requested beat, cloning
    the paths so callers can reuse their buffers immediately. */
int cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath* signal_path, const cepPath* target_path) {
    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    return cep_heartbeat_enqueue_impulse(beat, &impulse);
}


/** Queue a fully materialised impulse that already contains cloned paths,
    keeping the internal impulse queue layout consistent with the signal helper. */
int cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepImpulse* impulse) {
    if (!cep_heartbeat_bootstrap()) {
        fprintf(stderr, "[enqueue_impulse] bootstrap failed\n");
        fflush(stderr);
        return CEP_ENZYME_FATAL;
    }

    if (!impulse || (!impulse->signal_path && !impulse->target_path)) {
        fprintf(stderr, "[enqueue_impulse] invalid impulse\n");
        fflush(stderr);
        return CEP_ENZYME_FATAL;
    }

    cepBeatNumber record_beat = beat;
    if (record_beat == CEP_BEAT_INVALID) {
        record_beat = cep_heartbeat_next();
        if (record_beat == CEP_BEAT_INVALID) {
            record_beat = 0u;
        }
    }

    if (cep_heartbeat_policy_use_dirs() && record_beat != CEP_BEAT_INVALID) {
        if (!cep_heartbeat_ensure_beat_node(record_beat)) {
            fprintf(stderr, "[enqueue_impulse] ensure beat node failed beat=%llu\n", (unsigned long long)record_beat);
            fflush(stderr);
            return CEP_ENZYME_FATAL;
        }
    }

    if (!cep_heartbeat_impulse_queue_append(&CEP_RUNTIME.impulses_next, impulse)) {
        fprintf(stderr, "[enqueue_impulse] queue append failed\n");
        fflush(stderr);
        return CEP_ENZYME_FATAL;
    }

    if (cep_heartbeat_policy_use_dirs() && record_beat != CEP_BEAT_INVALID) {
        if (!cep_heartbeat_record_impulse_entry(record_beat, impulse)) {
            fprintf(stderr, "[enqueue_impulse] record impulse entry failed\n");
            fflush(stderr);
            return CEP_ENZYME_FATAL;
        }
    }

    return CEP_ENZYME_SUCCESS;
}


/* Provides the root cell for the sys namespace so integrations can attach
 * system-level state without digging through runtime internals.
 */
/** Return the root cell of the system subtree defined in the configured
    topology. */
cepCell* cep_heartbeat_sys_root(void) {
    return CEP_RUNTIME.topology.sys;
}


/* Shares the runtime root cell to support modules that need direct access to
 * transient execution state.
 */
/** Return the runtime staging subtree root prepared during bootstrap. */
cepCell* cep_heartbeat_rt_root(void) {
    return CEP_RUNTIME.topology.rt;
}


/* Returns the journal root so persistence helpers can append entries in the
 * same tree the scheduler maintains.
 */
/** Return the journal subtree used to persist heartbeat logs. */
cepCell* cep_heartbeat_journal_root(void) {
    return CEP_RUNTIME.topology.journal;
}


/* Supplies the environment root cell so configuration loaders can coordinate on
 * a single namespace.
 */
/** Return the environment subtree that exposes external resources. */
cepCell* cep_heartbeat_env_root(void) {
    return CEP_RUNTIME.topology.env;
}


/* Exposes the data root so consumers can store long-lived datasets alongside
 * the runtime without guessing the internal layout.
 */
/** Return the durable data subtree that holds committed facts. */
cepCell* cep_heartbeat_data_root(void) {
    return CEP_RUNTIME.topology.data;
}


/* Returns the content-addressable storage root to let utilities share cached
 * assets with the engine-provided store.
 */
/** Return the CAS subtree storing opaque blobs by content hash. */
cepCell* cep_heartbeat_cas_root(void) {
    return CEP_RUNTIME.topology.cas;
}


/* Provides the temporary root so callers can manage short-lived buffers in the
 * same compartment the runtime clears between runs.
 */
/** Return the temporary workspace subtree used for scratch cells. */
cepCell* cep_heartbeat_tmp_root(void) {
    return CEP_RUNTIME.topology.tmp;
}


/* Shares the enzymes root dictionary so tooling can inspect or organise enzyme
 * metadata alongside the registry.
 */
/** Return the subtree that stores enzyme metadata visible to tooling. */
cepCell* cep_heartbeat_enzymes_root(void) {
    return CEP_RUNTIME.topology.enzymes;
}

const cepEnzymeDescriptor* cep_enzyme_current(void) {
    return CEP_RUNTIME.current_descriptor;
}

bool cep_lifecycle_scope_mark_ready(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }

    cepLifecycleScopeState* state = &CEP_LIFECYCLE_STATE[scope];
    const cepLifecycleScopeInfo* info = &CEP_LIFECYCLE_SCOPE_INFO[scope];

    if (state->ready) {
        return true;
    }

    if (!cep_lifecycle_scope_dependencies_ready(scope)) {
        for (size_t i = 0; i < info->dependency_count; ++i) {
            cepLifecycleScope dep = info->dependencies[i];
            if (dep < CEP_LIFECYCLE_SCOPE_COUNT) {
                (void)cep_lifecycle_scope_mark_ready(dep);
            }
        }
    }

    if (!cep_boot_ops_start_boot()) {
        return false;
    }

    cepBeatNumber beat = cep_beat_index();
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }

    state->ready = true;
    state->ready_beat = beat;
    state->teardown = false;
    if (scope == CEP_LIFECYCLE_SCOPE_KERNEL) {
        CEP_LIFECYCLE_OPS_STATE.boot_kernel_ready = true;
    } else if (scope == CEP_LIFECYCLE_SCOPE_NAMEPOOL) {
        CEP_LIFECYCLE_OPS_STATE.boot_namepool_ready = true;
    }

    return true;
}

bool cep_lifecycle_scope_mark_teardown(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }

    cepLifecycleScopeState* state = &CEP_LIFECYCLE_STATE[scope];

    if (state->teardown) {
        return true;
    }

    if (!cep_boot_ops_start_shutdown()) {
        return false;
    }

    cepBeatNumber beat = cep_beat_index();
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }

    state->ready = false;
    state->teardown = true;
    state->td_beat = beat;

    CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked += 1u;
    size_t expected = cep_lengthof(CEP_LIFECYCLE_TEARDOWN_ORDER);
    if (CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked > expected) {
        CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked = expected;
    }

    return true;
}

bool cep_lifecycle_scope_is_ready(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }
    return CEP_LIFECYCLE_STATE[scope].ready;
}


static void cep_heartbeat_auto_shutdown(void) CEP_AT_SHUTDOWN_(101);

static void cep_heartbeat_auto_shutdown(void) {
    cep_heartbeat_shutdown();
}
