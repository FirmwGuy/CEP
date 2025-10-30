/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_organ.h"

#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_ops.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    cepOrganDescriptor desc;
    char*              kind_storage;
    char*              label_storage;
} cepOrganEntry;

typedef struct {
    cepOrganEntry* entries;
    size_t         count;
    size_t         capacity;
    cepCell*       root;
    bool           bootstrapped;
    bool           dt_dirty;
} cepOrganRegistryState;

static cepOrganRegistryState CEP_ORGAN_REGISTRY = {0};

CEP_DEFINE_STATIC_DT(dt_organs_root_name, CEP_ACRO("CEP"), CEP_WORD("organs"));
CEP_DEFINE_STATIC_DT(dt_spec_name,        CEP_ACRO("CEP"), CEP_WORD("spec"));
CEP_DEFINE_STATIC_DT(dt_store_field,      CEP_ACRO("CEP"), CEP_WORD("store"));
CEP_DEFINE_STATIC_DT(dt_validator_field,  CEP_ACRO("CEP"), CEP_WORD("validator"));
CEP_DEFINE_STATIC_DT(dt_ctor_field,       CEP_ACRO("CEP"), CEP_WORD("ctor"));
CEP_DEFINE_STATIC_DT(dt_dtor_field,       CEP_ACRO("CEP"), CEP_WORD("dtor"));
CEP_DEFINE_STATIC_DT(dt_kind_field,       CEP_ACRO("CEP"), CEP_WORD("kind"));
CEP_DEFINE_STATIC_DT(dt_label_field,      CEP_ACRO("CEP"), CEP_WORD("label"));

static void cep_organ_registry_require_refresh(void);
static void prr_organ_log(const char* fmt, ...) {
    if (!fmt) {
        return;
    }
    char buffer[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof buffer, fmt, args);
    va_end(args);
    CEP_DEBUG_PRINTF_STDOUT("%s", buffer);
}

typedef struct {
    const char* kind;
    cepDT       dt;
} cepOrganStoreCacheEntry;

#define CEP_ORGAN_STORE_CACHE_CAP 32u
static cepOrganStoreCacheEntry CEP_ORGAN_STORE_CACHE[CEP_ORGAN_STORE_CACHE_CAP];
static size_t CEP_ORGAN_STORE_CACHE_COUNT = 0u;

static bool cep_organ_store_text_matches(const char* kind, cepID tag) {
    if (!kind || !*kind || !cep_id_is_reference(tag)) {
        return false;
    }
    size_t text_len = 0u;
    const char* text = cep_namepool_lookup(tag, &text_len);
    if (!text) {
        return false;
    }
    static const char prefix[] = "organ/";
    const size_t prefix_len = sizeof prefix - 1u;
    const size_t kind_len = strlen(kind);
    if (text_len != prefix_len + kind_len) {
        return false;
    }
    if (strncmp(text, prefix, prefix_len) != 0) {
        return false;
    }
    return strncmp(text + prefix_len, kind, kind_len) == 0;
}

static void cep_organ_store_cache_release(cepDT* dt) {
    if (!dt) {
        return;
    }
    if (cep_dt_is_valid(dt) && cep_id_is_reference(dt->tag)) {
        (void)cep_namepool_release(dt->tag);
    }
    dt->domain = 0u;
    dt->tag = 0u;
    dt->glob = 0u;
}

static cepDT cep_organ_store_cache_record(const char* kind, cepDT dt) {
    if (!kind || !*kind) {
        return dt;
    }
    for (size_t i = 0u; i < CEP_ORGAN_STORE_CACHE_COUNT; ++i) {
        cepOrganStoreCacheEntry* entry = &CEP_ORGAN_STORE_CACHE[i];
        if (entry->kind && strcmp(entry->kind, kind) == 0) {
            cep_organ_store_cache_release(&entry->dt);
            entry->dt = dt;
            return dt;
        }
    }
    if (CEP_ORGAN_STORE_CACHE_COUNT < CEP_ORGAN_STORE_CACHE_CAP) {
        CEP_ORGAN_STORE_CACHE[CEP_ORGAN_STORE_CACHE_COUNT].kind = kind;
        CEP_ORGAN_STORE_CACHE[CEP_ORGAN_STORE_CACHE_COUNT].dt = dt;
        CEP_ORGAN_STORE_CACHE_COUNT += 1u;
    } else {
        cep_organ_store_cache_release(&CEP_ORGAN_STORE_CACHE[CEP_ORGAN_STORE_CACHE_COUNT - 1u].dt);
        CEP_ORGAN_STORE_CACHE[CEP_ORGAN_STORE_CACHE_COUNT - 1u].kind = kind;
        CEP_ORGAN_STORE_CACHE[CEP_ORGAN_STORE_CACHE_COUNT - 1u].dt = dt;
    }
    return dt;
}

static bool cep_organ_store_cache_lookup(const char* kind, cepDT* out) {
    if (!kind || !*kind || !out) {
        return false;
    }
    for (size_t i = 0u; i < CEP_ORGAN_STORE_CACHE_COUNT; ++i) {
        const cepOrganStoreCacheEntry* entry = &CEP_ORGAN_STORE_CACHE[i];
        if (!entry->kind) {
            continue;
        }
        if (strcmp(entry->kind, kind) != 0) {
            continue;
        }
        if (!cep_dt_is_valid(&entry->dt)) {
            return false;
        }
        if (!cep_organ_store_text_matches(kind, entry->dt.tag)) {
            cep_organ_store_cache_release((cepDT*)&entry->dt);
            return false;
        }
        *out = entry->dt;
        return true;
    }
    return false;
}

void cep_organ_runtime_reset(void) {
    for (size_t i = 0; i < CEP_ORGAN_REGISTRY.count; ++i) {
        cepOrganEntry* entry = &CEP_ORGAN_REGISTRY.entries[i];
        if (entry->kind_storage) {
            cep_free(entry->kind_storage);
            entry->kind_storage = NULL;
        }
        if (entry->label_storage) {
            cep_free(entry->label_storage);
            entry->label_storage = NULL;
        }
        memset(&entry->desc, 0, sizeof(entry->desc));
    }
    CEP_ORGAN_REGISTRY.count = 0;
    CEP_ORGAN_REGISTRY.root = NULL;
    CEP_ORGAN_REGISTRY.bootstrapped = false;
    CEP_ORGAN_REGISTRY.dt_dirty = false;

    for (size_t i = 0u; i < CEP_ORGAN_STORE_CACHE_COUNT; ++i) {
        cep_organ_store_cache_release(&CEP_ORGAN_STORE_CACHE[i].dt);
        CEP_ORGAN_STORE_CACHE[i].kind = NULL;
    }
    CEP_ORGAN_STORE_CACHE_COUNT = 0u;
}

static void cep_organ_report_issue(const char* stage, const char* detail) {
    char note[160];
    if (!stage) {
        stage = "organ";
    }
    if (!detail) {
        detail = "";
    }
    int written = snprintf(note, sizeof note, "organ:%s detail=%s", stage, detail);
    if (written <= 0) {
        snprintf(note, sizeof note, "organ:%s", stage);
    }
    (void)cep_heartbeat_stage_note(note);
    CEP_DEBUG_PRINTF_STDOUT("[organ] %s\n", note);
}

static void cep_organ_mark_subtree_veiled(cepCell* cell) {
    if (!cell) {
        return;
    }

    cell->metacell.veiled = 1u;
    if (cep_cell_is_normal(cell)) {
        cell->created = 0;
        for (cepCell* child = cep_cell_first_all(cell);
             child;
             child = cep_cell_next_all(cell, child)) {
            cep_organ_mark_subtree_veiled(child);
        }
    }
}

static char* cep_organ_strdup(const char* text) {
    if (!text || !*text) {
        return NULL;
    }

    size_t len = strlen(text) + 1u;
    char* copy = cep_malloc(len);
    memcpy(copy, text, len);
    return copy;
}

static cepOrganEntry* cep_organ_registry_find_by_store(const cepDT* store) {
    if (!store || !cep_dt_is_valid(store) || CEP_ORGAN_REGISTRY.count == 0u) {
        return NULL;
    }

    cep_organ_registry_require_refresh();

    cepDT cleaned = cep_dt_clean(store);
    for (size_t i = 0; i < CEP_ORGAN_REGISTRY.count; ++i) {
        if (cep_dt_compare(&CEP_ORGAN_REGISTRY.entries[i].desc.store, &cleaned) == 0) {
            return &CEP_ORGAN_REGISTRY.entries[i];
        }
    }

    return NULL;
}

static bool cep_organ_registry_ensure_capacity(void) {
    if (CEP_ORGAN_REGISTRY.count < CEP_ORGAN_REGISTRY.capacity) {
        return true;
    }

    size_t new_capacity = CEP_ORGAN_REGISTRY.capacity ? (CEP_ORGAN_REGISTRY.capacity * 2u) : 4u;
    size_t old_bytes = CEP_ORGAN_REGISTRY.capacity * sizeof(*CEP_ORGAN_REGISTRY.entries);
    size_t new_bytes = new_capacity * sizeof(*CEP_ORGAN_REGISTRY.entries);

    cepOrganEntry* grown = CEP_ORGAN_REGISTRY.entries
                         ? cep_realloc(CEP_ORGAN_REGISTRY.entries, new_bytes)
                         : cep_malloc0(new_bytes);
    if (CEP_ORGAN_REGISTRY.entries) {
        memset(((uint8_t*)grown) + old_bytes, 0, new_bytes - old_bytes);
    }

    CEP_ORGAN_REGISTRY.entries = grown;
    CEP_ORGAN_REGISTRY.capacity = new_capacity;
    return true;
}

static bool cep_organ_spec_write_dt(cepCell* spec, const cepDT* field, const cepDT* value) {
    if (!spec || !field || !value || !cep_dt_is_valid(value)) {
        return false;
    }

    cepDT name = cep_dt_clean(field);
    cepDT payload_type = cep_ops_make_dt("val/dt");
    cepDT payload_value = cep_dt_clean(value);

    return cep_dict_add_value(spec,
                              &name,
                              &payload_type,
                              &payload_value,
                              sizeof payload_value,
                              sizeof payload_value) != NULL;
}

static bool cep_organ_spec_write_string(cepCell* spec, const cepDT* field, const char* value) {
    if (!spec || !field || !value) {
        return true;
    }

    size_t len = strlen(value) + 1u;
    if (len == 1u) {
        return true;
    }

    cepDT name = cep_dt_clean(field);
    cepDT payload_type = cep_ops_make_dt("val/str");

    return cep_dict_add_value(spec,
                              &name,
                              &payload_type,
                              (void*)value,
                              len,
                              len) != NULL;
}

static bool cep_organ_spec_matches_dt(const cepCell* spec, const cepDT* field, const cepDT* expected) {
    if (!spec || !field) {
        return false;
    }

    if (!expected || !cep_dt_is_valid(expected)) {
        cepDT lookup = cep_dt_clean(field);
        return cep_cell_find_by_name((cepCell*)spec, &lookup) == NULL;
    }

    cepDT lookup = cep_dt_clean(field);
    cepCell* node = cep_cell_find_by_name((cepCell*)spec, &lookup);
    if (!node || !cep_cell_has_data(node)) {
        return false;
    }

    const cepData* data = node->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size != sizeof(cepDT)) {
        return false;
    }

    cepDT stored;
    memcpy(&stored, data->value, sizeof stored);
    return cep_dt_compare(&stored, expected) == 0;
}

static bool cep_organ_spec_matches_string(const cepCell* spec, const cepDT* field, const char* expected) {
    if (!spec || !field) {
        return false;
    }

    cepDT lookup = cep_dt_clean(field);
    cepCell* node = cep_cell_find_by_name((cepCell*)spec, &lookup);
    if (!expected || !*expected) {
        return node == NULL;
    }

    if (!node || !cep_cell_has_data(node)) {
        return false;
    }

    const cepData* data = node->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return false;
    }

    const char* stored = (const char*)data->value;
    if (!stored || stored[data->size - 1u] != '\0') {
        return false;
    }

    bool match = strlen(stored) + 1u == data->size && strcmp(stored, expected) == 0;
    if (!match) {
        char detail[128];
        size_t field_tag_len = 0u;
        const char* field_tag = (field && cep_dt_is_valid(field))
                              ? cep_namepool_lookup(field->tag, &field_tag_len)
                              : NULL;
        if (!field_tag) {
            field_tag = "<unknown>";
            field_tag_len = strlen(field_tag);
        }
        snprintf(detail,
                 sizeof detail,
                 "field=%.*s stored=\"%s\"",
                 (int)field_tag_len,
                 field_tag,
                 stored ? stored : "<null>");
        cep_organ_report_issue("publish:spec-string", detail);
    }
    return match;
}

static bool cep_organ_spec_matches_entry(const cepOrganEntry* entry, cepCell* spec) {
    if (!entry || !spec || !cep_cell_is_immutable(spec)) {
        return false;
    }

    if (!cep_organ_spec_matches_dt(spec, dt_store_field(), &entry->desc.store)) {
        cep_organ_report_issue("publish:spec-store", entry->desc.kind);
        return false;
    }
    if (!cep_organ_spec_matches_dt(spec, dt_validator_field(), &entry->desc.validator)) {
        cep_organ_report_issue("publish:spec-validator", entry->desc.kind);
        return false;
    }
    if (!cep_organ_spec_matches_dt(spec, dt_ctor_field(), &entry->desc.constructor)) {
        cep_organ_report_issue("publish:spec-ctor", entry->desc.kind);
        return false;
    }
    if (!cep_organ_spec_matches_dt(spec, dt_dtor_field(), &entry->desc.destructor)) {
        cep_organ_report_issue("publish:spec-dtor", entry->desc.kind);
        return false;
    }
    if (!cep_organ_spec_matches_string(spec, dt_kind_field(), entry->desc.kind)) {
        cep_organ_report_issue("publish:spec-kind", entry->desc.kind);
        return false;
    }
    if (!cep_organ_spec_matches_string(spec, dt_label_field(), entry->desc.label)) {
        cep_organ_report_issue("publish:spec-label", entry->desc.kind);
        return false;
    }

    return true;
}

static bool cep_organ_publish_entry(const cepOrganEntry* entry) {
    if (!entry) {
        cep_organ_report_issue("publish:entry", "null");
        return false;
    }

    if (!cep_organ_runtime_bootstrap()) {
        cep_organ_report_issue("publish:bootstrap", entry->desc.kind);
        return false;
    }

    cepCell* organs_root = CEP_ORGAN_REGISTRY.root;
    if (!organs_root) {
        cep_organ_report_issue("publish:root", entry->desc.kind);
        return false;
    }

    cepDT kind_name = {0};
    kind_name.domain = cep_namepool_intern_cstr("CEP");
    kind_name.tag = cep_namepool_intern_cstr(entry->desc.kind ? entry->desc.kind : "");

    cepCell* writable_root = organs_root;
    cepStore* root_store = NULL;
    if (!cep_cell_require_store(&writable_root, &root_store)) {
        cep_organ_report_issue("publish:store", entry->desc.kind);
        return false;
    }

    unsigned root_writable_before = root_store->writable;
    if (!root_store->writable) {
        root_store->writable = 1u;
    }

    cepCell* kind_root = cep_cell_ensure_dictionary_child(writable_root, &kind_name, CEP_STORAGE_RED_BLACK_T);

    if (!root_writable_before) {
        root_store->writable = root_writable_before;
    }

    CEP_ORGAN_REGISTRY.root = writable_root;

    if (!kind_root) {
        cep_organ_report_issue("publish:kind-root", entry->desc.kind);
        return false;
    }

    cepDT spec_name = *dt_spec_name();
    cepCell* existing = cep_cell_find_by_name(kind_root, &spec_name);
    if (existing) {
        existing = cep_cell_resolve(existing);
        if (existing && cep_organ_spec_matches_entry(entry, existing)) {
            return true;
        }
        if (existing) {
            cep_cell_remove_hard(existing, NULL);
        }
    }

    if (cep_cell_is_immutable(kind_root)) {
        cep_organ_report_issue("publish:kind-immutable", entry->desc.kind);
        return false;
    }

    writable_root = kind_root;
    root_store = NULL;
    if (!cep_cell_require_store(&writable_root, &root_store) || !root_store) {
        cep_organ_report_issue("publish:kind-store", entry->desc.kind);
        return false;
    }

    unsigned writable_before = root_store->writable;
    if (!root_store->writable) {
        root_store->writable = 1u;
    }

    cepCell* spec = cep_cell_add_dictionary(writable_root,
                                            &spec_name,
                                            0,
                                            CEP_DTAW("CEP", "dictionary"),
                                            CEP_STORAGE_RED_BLACK_T);

    if (!writable_before) {
        root_store->writable = writable_before;
    }

    if (!spec) {
        cep_organ_report_issue("publish:spec-create", entry->desc.kind);
        return false;
    }

    if (!cep_cell_require_dictionary_store(&spec)) {
        cep_organ_report_issue("publish:spec-store", entry->desc.kind);
        cep_cell_remove_hard(spec, NULL);
        return false;
    }

    cep_organ_mark_subtree_veiled(spec);

    bool ok = true;
    ok = ok && cep_organ_spec_write_dt(spec, dt_store_field(), &entry->desc.store);
    ok = ok && cep_organ_spec_write_dt(spec, dt_validator_field(), &entry->desc.validator);
    if (cep_dt_is_valid(&entry->desc.constructor)) {
        ok = ok && cep_organ_spec_write_dt(spec, dt_ctor_field(), &entry->desc.constructor);
    }
    if (cep_dt_is_valid(&entry->desc.destructor)) {
        ok = ok && cep_organ_spec_write_dt(spec, dt_dtor_field(), &entry->desc.destructor);
    }
    ok = ok && cep_organ_spec_write_string(spec, dt_kind_field(), entry->desc.kind);
    ok = ok && cep_organ_spec_write_string(spec, dt_label_field(), entry->desc.label);

    if (!ok) {
        cep_organ_report_issue("publish:spec-write", entry->desc.kind);
        cep_cell_remove_hard(spec, NULL);
        return false;
    }

    cepSealOptions seal = { .recursive = true };
    if (!cep_branch_seal_immutable(spec, seal)) {
        cep_organ_report_issue("publish:seal", entry->desc.kind);
        cep_cell_remove_hard(spec, NULL);
        return false;
    }

    return true;
}

static bool cep_organ_validate_store_matches_kind(const cepDT* store, const char* kind) {
    if (!store || !cep_dt_is_valid(store) || !kind || !*kind) {
        prr_organ_log("[prr:organ_store_validate] invalid_inputs store=%p kind=%s\n",
                      (const void*)store,
                      kind ? kind : "<null>");
        return false;
    }

    size_t tag_len = 0u;
    const char* tag_text = cep_namepool_lookup(store->tag, &tag_len);
    if (!tag_text || tag_len == 0u) {
        prr_organ_log("[prr:organ_store_validate] lookup_fail tag_id=%016llx kind=%s\n",
                      (unsigned long long)cep_id(store->tag),
                      kind);
        return false;
    }

    const char prefix[] = "organ/";
    size_t prefix_len = sizeof prefix - 1u;
    size_t kind_len = strlen(kind);
    if (tag_len != prefix_len + kind_len) {
        prr_organ_log("[prr:organ_store_validate] len_mismatch tag='%.*s' tag_len=%zu kind=%s expected=%zu\n",
                      (int)tag_len,
                      tag_text,
                      tag_len,
                      kind,
                      prefix_len + kind_len);
        return false;
    }

    if (strncmp(tag_text, prefix, prefix_len) != 0) {
        prr_organ_log("[prr:organ_store_validate] prefix_mismatch tag='%.*s' kind=%s\n",
                      (int)tag_len,
                      tag_text,
                      kind);
        return false;
    }

    if (strncmp(tag_text + prefix_len, kind, kind_len) != 0) {
        prr_organ_log("[prr:organ_store_validate] suffix_mismatch tag='%.*s' kind=%s\n",
                      (int)tag_len,
                      tag_text,
                      kind);
        return false;
    }

    return true;
}

static const cepOrganDescriptor* cep_organ_descriptor_for_cell(const cepCell* cell) {
    if (!cell) {
        return NULL;
    }
    cepCell* resolved = cep_cell_resolve((cepCell*)cell);
    if (!resolved || !cep_cell_is_normal(resolved) || !resolved->store) {
        return NULL;
    }
    return cep_organ_descriptor(&resolved->store->dt);
}

static cepPath* cep_organ_make_signal_path(const cepDT* signal_dt) {
    if (!signal_dt) {
        return NULL;
    }
    size_t bytes = sizeof(cepPath) + sizeof(cepPast);
    cepPath* path = cep_malloc(bytes);
    path->length = 1u;
    path->capacity = 1u;
    path->past[0].dt = cep_dt_clean(signal_dt);
    path->past[0].timestamp = 0u;
    return path;
}

static cepPath* cep_organ_make_target_path(const cepCell* cell) {
    if (!cell) {
        return NULL;
    }

    unsigned depth = 0u;
    for (const cepCell* current = cell; current && cep_cell_parent(current); current = cep_cell_parent(current)) {
        ++depth;
    }
    if (depth == 0u) {
        return NULL;
    }

    size_t bytes = sizeof(cepPath) + ((size_t)depth * sizeof(cepPast));
    cepPath* path = cep_malloc(bytes);
    path->length = depth;
    path->capacity = depth;

    const cepCell* current = cell;
    for (int index = (int)depth - 1; index >= 0; --index) {
        cepPast* segment = &path->past[index];
        segment->dt = cep_dt_clean(&current->metacell.dt);
        segment->timestamp = 0u;
        current = cep_cell_parent(current);
    }

    return path;
}

static bool cep_organ_enqueue_signal(const cepDT* signal_dt, const cepCell* root) {
    if (!signal_dt || !root) {
        return false;
    }

    if (!cep_organ_runtime_bootstrap()) {
        return false;
    }

    cepCell* resolved = cep_cell_resolve((cepCell*)root);
    if (!resolved) {
        return false;
    }

    cepPath* signal_path = cep_organ_make_signal_path(signal_dt);
    if (!signal_path) {
        return false;
    }

    cepPath* target_path = cep_organ_make_target_path(resolved);
    if (!target_path) {
        cep_free(signal_path);
        return false;
    }

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
        .qos = CEP_IMPULSE_QOS_NONE,
    };

    int rc = cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &impulse);
    if (rc != CEP_ENZYME_SUCCESS) {
        char detail[80];
        snprintf(detail,
                 sizeof detail,
                 "enqueue_failed rc=%d signal=%s target=%s",
                 rc,
                 signal_dt ? cep_namepool_lookup(signal_dt->domain, NULL) : "<nil>",
                 signal_dt ? cep_namepool_lookup(signal_dt->tag, NULL) : "<nil>");
        cep_organ_report_issue("enqueue", detail);
    }
    cep_free(signal_path);
    cep_free(target_path);
    CEP_DEBUG_PRINTF_STDOUT("[organ enqueue] signal=%s:%s rc=%d\n",
                            signal_dt ? cep_namepool_lookup(signal_dt->domain, NULL) : "<nil>",
                            signal_dt ? cep_namepool_lookup(signal_dt->tag, NULL) : "<nil>",
                            rc);
    return rc == CEP_ENZYME_SUCCESS;
}

/* Bootstraps the organ registry by ensuring the `/sys/organs` dictionary
 * exists, wiring the cached root pointer, and leaving the registry ready for
 * descriptor publication; returns false if the heartbeat topology cannot be
 * initialised. */
bool cep_organ_runtime_bootstrap(void) {
    if (CEP_ORGAN_REGISTRY.bootstrapped && CEP_ORGAN_REGISTRY.root) {
        cepCell* resolved = cep_cell_resolve(CEP_ORGAN_REGISTRY.root);
        if (resolved && cep_cell_is_normal(resolved) && resolved->store) {
            CEP_ORGAN_REGISTRY.root = resolved;
            return true;
        }

        char detail[128];
        snprintf(detail,
                 sizeof detail,
                 "cached_root_invalid resolved=%p normal=%d store=%p",
                 (void*)resolved,
                 resolved ? (cep_cell_is_normal(resolved) ? 1 : 0) : 0,
                 resolved ? (void*)resolved->store : NULL);
        cep_organ_report_issue("runtime_bootstrap", detail);
        CEP_ORGAN_REGISTRY.root = NULL;
        CEP_ORGAN_REGISTRY.bootstrapped = false;
    }

    if (!cep_heartbeat_bootstrap()) {
        cep_organ_report_issue("runtime_bootstrap", "heartbeat_bootstrap_failed");
        return false;
    }

    const cepHeartbeatTopology* topology = cep_heartbeat_topology();
    cepCell* organs_root = NULL;
    if (topology) {
        organs_root = topology->organs;
    }

    if (!organs_root) {
        cepCell* sys_root = cep_heartbeat_sys_root();
        if (!sys_root) {
            cep_organ_report_issue("runtime_bootstrap", "sys_root_missing");
            return false;
        }
        cepDT organ_dt = cep_organ_store_dt("sys_organs");
        cepDT name_copy = *dt_organs_root_name();
        organs_root = cep_cell_add_dictionary(sys_root, &name_copy, 0, &organ_dt, CEP_STORAGE_RED_BLACK_T);
        if (!organs_root) {
            cep_organ_report_issue("runtime_bootstrap", "sys_organs_add_dictionary_failed");
            return false;
        }
    } else {
        cepCell* resolved = cep_cell_resolve(organs_root);
        if (!resolved) {
            cep_organ_report_issue("runtime_bootstrap", "topology_organs_resolve_failed");
            return false;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            cep_organ_report_issue("runtime_bootstrap", "topology_organs_not_dictionary");
            return false;
        }
        if (resolved->store) {
            cepDT organ_dt = cep_organ_store_dt("sys_organs");
            cep_store_set_dt(resolved->store, &organ_dt);
        }
        organs_root = resolved;
    }

    CEP_ORGAN_REGISTRY.root = organs_root;
    CEP_ORGAN_REGISTRY.bootstrapped = true;
    return true;
}

/* Registers a new organ descriptor, publishes its immutable spec under
 * `/sys/organs/<kind>/spec`, and caches the descriptor for lookup; returns
 * false when validation fails or publication cannot complete. */
bool cep_organ_register(const cepOrganDescriptor* descriptor) {
    if (!descriptor || !descriptor->kind || !*descriptor->kind) {
        cep_organ_report_issue("register:descriptor", "missing-kind");
        return false;
    }

    cepDT store = descriptor->store;
    cepDT validator = descriptor->validator;
    size_t store_len = 0u;
    const char* store_text = cep_namepool_lookup(store.tag, &store_len);
    prr_organ_log("[prr:organ_register] kind=%s store=%016llx/%016llx text='%.*s'\n",
                  descriptor->kind,
                  (unsigned long long)cep_id(store.domain),
                  (unsigned long long)cep_id(store.tag),
                  (int)store_len,
                  store_text ? store_text : "<null>");
    if (store_text && strncmp(store_text, "org:", 4) == 0) {
        cepDT corrected_store = cep_organ_store_dt(descriptor->kind);
        size_t corrected_len = 0u;
        const char* corrected_text = cep_namepool_lookup(corrected_store.tag, &corrected_len);
        prr_organ_log("[prr:organ_register] correcting_store kind=%s new_store=%016llx/%016llx text='%.*s'\n",
                      descriptor->kind,
                      (unsigned long long)cep_id(corrected_store.domain),
                      (unsigned long long)cep_id(corrected_store.tag),
                      (int)corrected_len,
                      corrected_text ? corrected_text : "<null>");
        store = corrected_store;
    }

    if (!cep_dt_is_valid(&store) || !cep_dt_is_valid(&validator)) {
        cep_organ_report_issue("register:descriptor", "invalid-dt");
        return false;
    }

    if (!cep_organ_runtime_bootstrap()) {
        cep_organ_report_issue("register:bootstrap", descriptor->kind);
        return false;
    }

    if (!cep_organ_validate_store_matches_kind(&store, descriptor->kind)) {
        cep_organ_report_issue("register:store-mismatch", descriptor->kind);
        return false;
    }

    cepOrganEntry* existing = cep_organ_registry_find_by_store(&store);
    if (existing) {
        if (cep_dt_compare(&existing->desc.validator, &validator) != 0) {
            cep_organ_report_issue("register:validator-mismatch", descriptor->kind);
            return false;
        }
        if (cep_dt_compare(&existing->desc.constructor, &descriptor->constructor) != 0) {
            cep_organ_report_issue("register:ctor-mismatch", descriptor->kind);
            return false;
        }
        if (cep_dt_compare(&existing->desc.destructor, &descriptor->destructor) != 0) {
            cep_organ_report_issue("register:dtor-mismatch", descriptor->kind);
            return false;
        }
        if ((existing->desc.label && descriptor->label && strcmp(existing->desc.label, descriptor->label) == 0) ||
            (!existing->desc.label && (!descriptor->label || !*descriptor->label))) {
            return true;
        }
        cep_organ_report_issue("register:label-mismatch", descriptor->kind);
        return false;
    }

    if (!cep_organ_registry_ensure_capacity()) {
        cep_organ_report_issue("register:capacity", descriptor->kind);
        return false;
    }

    cepOrganEntry entry = {0};
    entry.kind_storage = cep_organ_strdup(descriptor->kind);
    entry.label_storage = descriptor->label && *descriptor->label ? cep_organ_strdup(descriptor->label) : NULL;

    entry.desc.kind = entry.kind_storage;
    entry.desc.label = entry.label_storage;
    entry.desc.store = cep_dt_clean(&store);
    entry.desc.validator = cep_dt_clean(&validator);
    entry.desc.constructor = cep_dt_clean(&descriptor->constructor);
    entry.desc.destructor = cep_dt_clean(&descriptor->destructor);

    if (!cep_organ_publish_entry(&entry)) {
        cep_free(entry.kind_storage);
        cep_free(entry.label_storage);
        cep_organ_report_issue("register:publish", descriptor->kind);
        return false;
    }

    CEP_ORGAN_REGISTRY.entries[CEP_ORGAN_REGISTRY.count++] = entry;
    return true;
}

/* Looks up the cached descriptor for the provided store domain/tag so callers
 * can inspect organ metadata without touching the system tree. */
const cepOrganDescriptor* cep_organ_descriptor(const cepDT* store_kind) {
    cepOrganEntry* entry = cep_organ_registry_find_by_store(store_kind);
    return entry ? &entry->desc : NULL;
}

/* Walks the ancestry of the supplied cell to find the nearest organ root and
 * surfaces both the root cell and descriptor; returns false when the cell does
 * not reside within a registered organ. */
bool cep_organ_root_for_cell(const cepCell* cell, cepOrganRoot* out) {
    if (!cell || !out) {
        return false;
    }

    cepCell* current = cep_cell_resolve((cepCell*)cell);
    while (current) {
        if (cep_cell_is_normal(current) && current->store) {
            cepOrganEntry* entry = cep_organ_registry_find_by_store(&current->store->dt);
            if (entry) {
                out->descriptor = &entry->desc;
                out->root = current;
                return true;
            }
        }

        if (!current->parent) {
            break;
        }
        current = current->parent->owner;
    }

    return false;
}

/* Queues the optional organ constructor impulse so any registered
 * `org:<k>:ct` enzyme runs on the next beat; returns true when no constructor
 * is registered or when queuing succeeds. */
bool cep_organ_request_constructor(const cepCell* root) {
    const cepOrganDescriptor* descriptor = cep_organ_descriptor_for_cell(root);
    if (!descriptor || !cep_dt_is_valid(&descriptor->constructor)) {
        CEP_DEBUG_PRINTF_STDOUT("[organ req ctor] descriptor missing root=%p\n", (void*)root);
        return true;
    }

    cepDT signal = cep_dt_clean(&descriptor->constructor);
    return cep_organ_enqueue_signal(&signal, root);
}

/* Queues the optional organ destructor impulse so any registered
 * `org:<k>:dt` enzyme can tear down the branch before it is removed; returns
 * true when no destructor exists or when the impulse was enqueued. */
bool cep_organ_request_destructor(const cepCell* root) {
    const cepOrganDescriptor* descriptor = cep_organ_descriptor_for_cell(root);
    if (!descriptor || !cep_dt_is_valid(&descriptor->destructor)) {
        return true;
    }

    cepDT signal = cep_dt_clean(&descriptor->destructor);
    return cep_organ_enqueue_signal(&signal, root);
}

/* Detects the enclosing organ for the supplied cell and enqueues the
 * validation impulse so `org:<k>:vl` runs through the heartbeat; returns false
 * when the cell does not belong to any registered organ. */
bool cep_organ_request_validation(const cepCell* cell) {
    if (!cell) {
        return false;
    }

    cepOrganRoot info = {0};
    if (!cep_organ_root_for_cell(cell, &info) || !info.descriptor) {
        char detail[64];
        snprintf(detail, sizeof detail, "root_lookup_failed cell=%p", (void*)cell);
        cep_organ_report_issue("request_validation", detail);
        return false;
    }

    if (!cep_dt_is_valid(&info.descriptor->validator)) {
        char detail[64];
        snprintf(detail, sizeof detail, "invalid_descriptor descriptor=%p", (void*)info.descriptor);
        cep_organ_report_issue("request_validation", detail);
        return false;
    }

    cepDT signal = cep_dt_clean(&info.descriptor->validator);
    return cep_organ_enqueue_signal(&signal, info.root);
}

static const char* cep_organ_guess_kind(const cepCell* root) {
    if (!root) {
        return NULL;
    }

    const cepCell* resolved = cep_cell_resolve((cepCell*)root);
    if (!resolved || !cep_cell_is_normal(resolved)) {
        return NULL;
    }

    const cepDT* name = cep_cell_get_name(resolved);
    const cepCell* parent = cep_cell_parent(resolved);
    const cepDT* parent_name = parent ? cep_cell_get_name(parent) : NULL;

    if (name && cep_dt_compare(name, CEP_DTAW("CEP", "beat")) == 0) {
        if (parent_name && cep_dt_compare(parent_name, CEP_DTAW("CEP", "rt")) == 0) {
            return "rt_beat";
        }
    }
    if (name && cep_dt_compare(name, CEP_DTAW("CEP", "journal")) == 0) {
        return "journal";
    }

    return NULL;
}

/* Clears an organ root in place so follow-up constructors can rebuild the
 * branch. The helper resolves the supplied node to the concrete organ root,
 * ensures its store is writable long enough to hard-delete every child, keeps
 * the original store tag intact, and restores the writable flag afterwards so
 * existing lifecycle policy remains unchanged. */
bool cep_organ_clear_root(cepCell* root) {
    if (!root) {
        return false;
    }

    cepCell* resolved = cep_cell_resolve(root);
    if (!resolved || !cep_cell_is_normal(resolved)) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&resolved) || !resolved->store) {
        return false;
    }

    if (cep_cell_store_locked_hierarchy(resolved)) {
    CEP_DEBUG_PRINTF_STDOUT("[organ clear] root locked root=%p\n", (void*)resolved);
        return false;
    }

    cepStore* store = resolved->store;
    const char* kind = NULL;
    const cepOrganDescriptor* descriptor = cep_organ_descriptor_for_cell(resolved);
    if (descriptor && descriptor->kind) {
        kind = descriptor->kind;
    } else {
        kind = cep_organ_guess_kind(resolved);
        if (kind) {
            cepDT inferred = cep_organ_store_dt(kind);
            if (cep_dt_is_valid(&inferred)) {
                descriptor = cep_organ_descriptor(&inferred);
            }
        }
    }

    cepDT expected = {0};
    if (descriptor && descriptor->kind) {
        expected = cep_organ_store_dt(descriptor->kind);
    } else if (kind) {
        expected = cep_organ_store_dt(kind);
    } else {
        expected = store->dt;
    }

    unsigned writable_before = store->writable;
    if (!store->writable) {
        store->writable = 1u;
    }

    cep_store_delete_children_hard(store);

    if (cep_dt_is_valid(&expected)) {
        cep_store_set_dt(store, &expected);
    }

    store->writable = writable_before;

    return true;
}

/* Composes the canonical `organ/<kind>` store identifier used to mark organ
 * roots, interning the tag via the namepool so callers can build consistent
 * descriptors. */
cepDT cep_organ_store_dt(const char* kind) {
    cepDT invalid = {0};
    if (!kind || !*kind) {
        return invalid;
    }

    cepDT cached = {0};
    if (cep_organ_store_cache_lookup(kind, &cached)) {
        return cached;
    }

    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "organ/%s", kind);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return invalid;
    }

    cepDT dt = {0};
    dt.domain = cep_namepool_intern_cstr("CEP");
    if (!dt.domain) {
        char detail[96];
        snprintf(detail,
                 sizeof detail,
                 "store_dt_domain_failed kind=%s",
                 kind);
        cep_organ_report_issue("store_dt", detail);
        return invalid;
    }

    cepID tag = 0u;
    for (unsigned attempt = 0u; attempt < 3u && !tag; ++attempt) {
        cepID candidate = cep_namepool_intern_cstr(buffer);
        if (!candidate) {
            break;
        }
        if (cep_organ_store_text_matches(kind, candidate)) {
            tag = candidate;
            break;
        }
        (void)cep_namepool_release(candidate);
    }

    if (!tag) {
        char detail[160];
        snprintf(detail,
                 sizeof detail,
                 "store_dt_intern_failed kind=%s",
                 kind);
        cep_organ_report_issue("store_dt", detail);
        return invalid;
    }

    dt.tag = tag;
    dt.glob = 0u;
    return cep_organ_store_cache_record(kind, dt);
}

static cepDT cep_organ_make_signal_dt(const char* kind, const char* suffix) {
    cepDT invalid = {0};
    if (!kind || !*kind || !suffix || !*suffix) {
        return invalid;
    }

    char buffer[48];
    int written = snprintf(buffer, sizeof buffer, "org:%s:%s", kind, suffix);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return invalid;
    }
    return cep_ops_make_dt(buffer);
}

static bool cep_organ_registry_refresh(void) {
    if (!CEP_ORGAN_REGISTRY.dt_dirty) {
        return true;
    }

    bool bootstrapped = CEP_ORGAN_REGISTRY.bootstrapped && CEP_ORGAN_REGISTRY.root;
    if (!bootstrapped) {
        char note[128];
        snprintf(note,
                 sizeof note,
                 "bootstrap_required dirty=%d root=%p bootstrapped=%d",
                 CEP_ORGAN_REGISTRY.dt_dirty ? 1 : 0,
                 (void*)CEP_ORGAN_REGISTRY.root,
                 CEP_ORGAN_REGISTRY.bootstrapped ? 1 : 0);
        cep_organ_report_issue("registry_refresh", note);
        if (!cep_organ_runtime_bootstrap()) {
            return false;
        }
    } else {
        cepCell* resolved = cep_cell_resolve(CEP_ORGAN_REGISTRY.root);
        if (!resolved || !cep_cell_is_normal(resolved) || !cep_cell_require_dictionary_store(&resolved)) {
            char note[128];
            snprintf(note,
                     sizeof note,
                     "root_invalid resolved=%p has_store=%d is_normal=%d",
                     (void*)resolved,
                     resolved && resolved->store ? 1 : 0,
                     resolved ? (cep_cell_is_normal(resolved) ? 1 : 0) : 0);
            cep_organ_report_issue("registry_refresh", note);
            CEP_ORGAN_REGISTRY.bootstrapped = false;
            CEP_ORGAN_REGISTRY.root = NULL;
            if (!cep_organ_runtime_bootstrap()) {
                return false;
            }
        } else {
            CEP_ORGAN_REGISTRY.root = resolved;
        }
    }

    CEP_ORGAN_REGISTRY.dt_dirty = false;
    bool ok = true;

    for (size_t i = 0; i < CEP_ORGAN_REGISTRY.count; ++i) {
        cepOrganEntry* entry = &CEP_ORGAN_REGISTRY.entries[i];
        const char* kind = entry->desc.kind;
        if (!kind || !*kind) {
            continue;
        }

        cepDT updated_store = cep_organ_store_dt(kind);
        if (cep_dt_is_valid(&updated_store)) {
            entry->desc.store = updated_store;
        } else {
            ok = false;
        }

        if (cep_dt_is_valid(&entry->desc.validator)) {
            cepDT updated_validator = cep_organ_make_signal_dt(kind, "vl");
            if (cep_dt_is_valid(&updated_validator)) {
                entry->desc.validator = updated_validator;
            } else {
                ok = false;
            }
        }

        if (cep_dt_is_valid(&entry->desc.constructor)) {
            cepDT updated_ctor = cep_organ_make_signal_dt(kind, "ct");
            if (cep_dt_is_valid(&updated_ctor)) {
                entry->desc.constructor = updated_ctor;
            } else {
                ok = false;
            }
        }

        if (cep_dt_is_valid(&entry->desc.destructor)) {
            cepDT updated_dtor = cep_organ_make_signal_dt(kind, "dt");
            if (cep_dt_is_valid(&updated_dtor)) {
                entry->desc.destructor = updated_dtor;
            } else {
                ok = false;
            }
        }

        if (!cep_organ_publish_entry(entry)) {
            ok = false;
        }
    }

    if (!ok) {
        CEP_ORGAN_REGISTRY.dt_dirty = true;
    }
    return ok;
}

static void cep_organ_registry_require_refresh(void) {
    if (CEP_ORGAN_REGISTRY.dt_dirty) {
        (void)cep_organ_registry_refresh();
    }
}

void cep_organ_registry_mark_dirty(void) {
    CEP_ORGAN_REGISTRY.dt_dirty = true;
}

bool cep_organ_registry_refresh_descriptors(void) {
    return CEP_ORGAN_REGISTRY.dt_dirty ? cep_organ_registry_refresh() : true;
}
