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
#include <stdlib.h>
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

    return strlen(stored) + 1u == data->size && strcmp(stored, expected) == 0;
}

static bool cep_organ_spec_matches_entry(const cepOrganEntry* entry, cepCell* spec) {
    if (!entry || !spec || !cep_cell_is_immutable(spec)) {
        return false;
    }

    if (!cep_organ_spec_matches_dt(spec, dt_store_field(), &entry->desc.store)) {
        return false;
    }
    if (!cep_organ_spec_matches_dt(spec, dt_validator_field(), &entry->desc.validator)) {
        return false;
    }
    if (!cep_organ_spec_matches_dt(spec, dt_ctor_field(), &entry->desc.constructor)) {
        return false;
    }
    if (!cep_organ_spec_matches_dt(spec, dt_dtor_field(), &entry->desc.destructor)) {
        return false;
    }
    if (!cep_organ_spec_matches_string(spec, dt_kind_field(), entry->desc.kind)) {
        return false;
    }
    if (!cep_organ_spec_matches_string(spec, dt_label_field(), entry->desc.label)) {
        return false;
    }

    return true;
}

static bool cep_organ_publish_entry(const cepOrganEntry* entry) {
    if (!entry) {
        return false;
    }

    if (!cep_organ_runtime_bootstrap()) {
        return false;
    }

    cepCell* organs_root = CEP_ORGAN_REGISTRY.root;
    if (!organs_root) {
        return false;
    }

    cepDT kind_name = {0};
    kind_name.domain = cep_namepool_intern_cstr("CEP");
    kind_name.tag = cep_namepool_intern_cstr(entry->desc.kind ? entry->desc.kind : "");

    cepCell* kind_root = cep_cell_ensure_dictionary_child(organs_root, &kind_name, CEP_STORAGE_RED_BLACK_T);
    if (!kind_root) {
        return false;
    }

    cepDT spec_name = *dt_spec_name();
    cepCell* existing = cep_cell_find_by_name(kind_root, &spec_name);
    if (existing) {
        existing = cep_cell_resolve(existing);
        return cep_organ_spec_matches_entry(entry, existing);
    }

    cepTxn txn;
    if (!cep_txn_begin(kind_root, &spec_name, CEP_DTAW("CEP", "dictionary"), &txn)) {
        return false;
    }

    bool ok = true;

    ok = ok && cep_organ_spec_write_dt(txn.root, dt_store_field(), &entry->desc.store);
    ok = ok && cep_organ_spec_write_dt(txn.root, dt_validator_field(), &entry->desc.validator);
    if (cep_dt_is_valid(&entry->desc.constructor)) {
        ok = ok && cep_organ_spec_write_dt(txn.root, dt_ctor_field(), &entry->desc.constructor);
    }
    if (cep_dt_is_valid(&entry->desc.destructor)) {
        ok = ok && cep_organ_spec_write_dt(txn.root, dt_dtor_field(), &entry->desc.destructor);
    }
    ok = ok && cep_organ_spec_write_string(txn.root, dt_kind_field(), entry->desc.kind);
    ok = ok && cep_organ_spec_write_string(txn.root, dt_label_field(), entry->desc.label);

    if (ok) {
        cepSealOptions seal = { .recursive = true };
        ok = cep_branch_seal_immutable(txn.root, seal);
    }
    if (ok) {
        ok = cep_txn_mark_ready(&txn);
    }
    if (ok) {
        ok = cep_txn_commit(&txn);
    }

    if (!ok) {
        cep_txn_abort(&txn);
    }

    return ok;
}

static bool cep_organ_validate_store_matches_kind(const cepDT* store, const char* kind) {
    if (!store || !cep_dt_is_valid(store) || !kind || !*kind) {
        return false;
    }

    size_t tag_len = 0u;
    const char* tag_text = cep_namepool_lookup(store->tag, &tag_len);
    if (!tag_text || tag_len == 0u) {
        return false;
    }

    const char prefix[] = "organ/";
    size_t prefix_len = sizeof prefix - 1u;
    size_t kind_len = strlen(kind);
    if (tag_len != prefix_len + kind_len) {
        return false;
    }

    if (strncmp(tag_text, prefix, prefix_len) != 0) {
        return false;
    }

    return strncmp(tag_text + prefix_len, kind, kind_len) == 0;
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
    for (const cepCell* current = cell; current; current = cep_cell_parent(current)) {
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
    };

    int rc = cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &impulse);
    cep_free(signal_path);
    cep_free(target_path);
    return rc == CEP_ENZYME_SUCCESS;
}

/* Bootstraps the organ registry by ensuring the `/sys/organs` dictionary
 * exists, wiring the cached root pointer, and leaving the registry ready for
 * descriptor publication; returns false if the heartbeat topology cannot be
 * initialised. */
bool cep_organ_runtime_bootstrap(void) {
    if (CEP_ORGAN_REGISTRY.bootstrapped && CEP_ORGAN_REGISTRY.root) {
        return true;
    }

    if (!cep_heartbeat_bootstrap()) {
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
            return false;
        }
        organs_root = cep_cell_ensure_dictionary_child(sys_root, dt_organs_root_name(), CEP_STORAGE_RED_BLACK_T);
        if (!organs_root) {
            return false;
        }
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
        return false;
    }

    if (!cep_dt_is_valid(&descriptor->store) || !cep_dt_is_valid(&descriptor->validator)) {
        return false;
    }

    if (!cep_organ_runtime_bootstrap()) {
        return false;
    }

    if (!cep_organ_validate_store_matches_kind(&descriptor->store, descriptor->kind)) {
        return false;
    }

    cepOrganEntry* existing = cep_organ_registry_find_by_store(&descriptor->store);
    if (existing) {
        if (cep_dt_compare(&existing->desc.validator, &descriptor->validator) != 0) {
            return false;
        }
        if (cep_dt_compare(&existing->desc.constructor, &descriptor->constructor) != 0) {
            return false;
        }
        if (cep_dt_compare(&existing->desc.destructor, &descriptor->destructor) != 0) {
            return false;
        }
        if ((existing->desc.label && descriptor->label && strcmp(existing->desc.label, descriptor->label) == 0) ||
            (!existing->desc.label && (!descriptor->label || !*descriptor->label))) {
            return true;
        }
        return false;
    }

    if (!cep_organ_registry_ensure_capacity()) {
        return false;
    }

    cepOrganEntry entry = {0};
    entry.kind_storage = cep_organ_strdup(descriptor->kind);
    entry.label_storage = descriptor->label && *descriptor->label ? cep_organ_strdup(descriptor->label) : NULL;

    entry.desc.kind = entry.kind_storage;
    entry.desc.label = entry.label_storage;
    entry.desc.store = cep_dt_clean(&descriptor->store);
    entry.desc.validator = cep_dt_clean(&descriptor->validator);
    entry.desc.constructor = cep_dt_clean(&descriptor->constructor);
    entry.desc.destructor = cep_dt_clean(&descriptor->destructor);

    if (!cep_organ_publish_entry(&entry)) {
        cep_free(entry.kind_storage);
        cep_free(entry.label_storage);
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
        return true;
    }

    cepDT signal = cep_ops_make_dt("op/ct");
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

    cepDT signal = cep_ops_make_dt("op/dt");
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
        return false;
    }

    cepDT signal = cep_ops_make_dt("op/vl");
    return cep_organ_enqueue_signal(&signal, info.root);
}

/* Composes the canonical `organ/<kind>` store identifier used to mark organ
 * roots, interning the tag via the namepool so callers can build consistent
 * descriptors. */
cepDT cep_organ_store_dt(const char* kind) {
    cepDT invalid = {0};
    if (!kind || !*kind) {
        return invalid;
    }

    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "organ/%s", kind);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return invalid;
    }

    cepDT dt = {0};
    dt.domain = cep_namepool_intern_cstr("CEP");
    dt.tag = cep_namepool_intern_cstr(buffer);
    return dt;
}
