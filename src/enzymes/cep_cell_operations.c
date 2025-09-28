/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_cell_operations.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_heartbeat.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>


typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     past[2];
} cepPathConst2;

typedef struct {
    cepEnzymeRegistry* registry;
    size_t             baseline;
} cepCellOperationsRegistryRecord;

static cepCellOperationsRegistryRecord* cep_cell_operations_registry_records = NULL;
static size_t cep_cell_operations_registry_record_count = 0u;
static size_t cep_cell_operations_registry_record_capacity = 0u;
static cepEnzymeRegistry* cep_cell_operations_active_registry = NULL;

static cepCellOperationsRegistryRecord* cep_cell_operations_registry_record_find(cepEnzymeRegistry* registry) {
    if (!registry || !cep_cell_operations_registry_records) {
        return NULL;
    }

    for (size_t i = 0; i < cep_cell_operations_registry_record_count; ++i) {
        if (cep_cell_operations_registry_records[i].registry == registry) {
            return &cep_cell_operations_registry_records[i];
        }
    }

    return NULL;
}

static cepCellOperationsRegistryRecord* cep_cell_operations_registry_record_append(cepEnzymeRegistry* registry, size_t baseline) {
    if (!registry) {
        return NULL;
    }

    if (cep_cell_operations_registry_record_count == cep_cell_operations_registry_record_capacity) {
        size_t new_capacity = cep_cell_operations_registry_record_capacity ? (cep_cell_operations_registry_record_capacity * 2u) : 4u;
        size_t previous_bytes = cep_cell_operations_registry_record_capacity * sizeof(*cep_cell_operations_registry_records);
        size_t bytes = new_capacity * sizeof(*cep_cell_operations_registry_records);
        cepCellOperationsRegistryRecord* grown = cep_cell_operations_registry_records ? cep_realloc(cep_cell_operations_registry_records, bytes) : cep_malloc0(bytes);
        if (cep_cell_operations_registry_records) {
            memset(((uint8_t*)grown) + previous_bytes, 0, bytes - previous_bytes);
        }
        cep_cell_operations_registry_records = grown;
        cep_cell_operations_registry_record_capacity = new_capacity;
    }

    cepCellOperationsRegistryRecord* record = &cep_cell_operations_registry_records[cep_cell_operations_registry_record_count++];
    record->registry = registry;
    record->baseline = baseline;
    return record;
}


static const cepDT* dt_signal_cell(void) { return CEP_DTAW("CEP", "sig_cell"); }
static const cepDT* dt_op_add(void)      { return CEP_DTAW("CEP", "op_add"); }
static const cepDT* dt_op_update(void)   { return CEP_DTAW("CEP", "op_upd"); }
static const cepDT* dt_op_delete(void)   { return CEP_DTAW("CEP", "op_delete"); }
static const cepDT* dt_op_move(void)     { return CEP_DTAW("CEP", "op_move"); }
static const cepDT* dt_op_clone(void)    { return CEP_DTAW("CEP", "op_clone"); }

static const cepDT* dt_role_parent(void)   { return CEP_DTAW("CEP", "role_parnt"); }
static const cepDT* dt_role_subject(void)  { return CEP_DTAW("CEP", "role_subj"); }
static const cepDT* dt_role_source(void)   { return CEP_DTAW("CEP", "role_source"); }
static const cepDT* dt_role_template(void) { return CEP_DTAW("CEP", "role_templ"); }

static const cepDT* dt_arg_position(void) { return CEP_DTAW("CEP", "arg_pos"); }
static const cepDT* dt_arg_prepend(void)  { return CEP_DTAW("CEP", "arg_prepend"); }
static const cepDT* dt_arg_deep(void)     { return CEP_DTAW("CEP", "arg_deep"); }

static const cepDT* dt_enz_add(void)    { return CEP_DTAW("CEP", "enz_add"); }
static const cepDT* dt_enz_update(void) { return CEP_DTAW("CEP", "enz_upd"); }
static const cepDT* dt_enz_delete(void) { return CEP_DTAW("CEP", "enz_del"); }
static const cepDT* dt_enz_move(void)   { return CEP_DTAW("CEP", "enz_mov"); }
static const cepDT* dt_enz_clone(void)  { return CEP_DTAW("CEP", "enz_cln"); }


static cepCell* cep_cell_enzyme_resolve(const cepPath* path) {
    if (!path || !path->length) {
        return NULL;
    }
    return cep_cell_find_by_path_past(cep_root(), path, 0);
}

static cepCell* cep_cell_enzyme_resolve_link(cepCell* cell) {
    if (!cell) {
        return NULL;
    }
    return cep_link_pull(cell);
}

static cepCell* cep_cell_enzyme_request_link(cepCell* request, const cepDT* name) {
    if (!request || !name) {
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(request, name);
    if (!child) {
        return NULL;
    }
    return cep_cell_enzyme_resolve_link(child);
}

static bool cep_cell_enzyme_request_bool(cepCell* request, const cepDT* name, bool* out_value) {
    if (!request || !name || !out_value) {
        return false;
    }

    cepCell* entry = cep_cell_find_by_name(request, name);
    if (!entry) {
        return false;
    }

    entry = cep_cell_enzyme_resolve_link(entry);
    if (!entry || !cep_cell_has_data(entry)) {
        return false;
    }

    const cepData* data = entry->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size < 1u) {
        return false;
    }

    *out_value = data->value[0] != 0u;
    return true;
}

static bool cep_cell_enzyme_request_u64(cepCell* request, const cepDT* name, uint64_t* out_value) {
    if (!request || !name || !out_value) {
        return false;
    }

    cepCell* entry = cep_cell_find_by_name(request, name);
    if (!entry) {
        return false;
    }

    entry = cep_cell_enzyme_resolve_link(entry);
    if (!entry || !cep_cell_has_data(entry)) {
        return false;
    }

    const cepData* data = entry->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size != sizeof(uint64_t)) {
        return false;
    }

    uint64_t value;
    memcpy(&value, data->value, sizeof value);
    *out_value = value;
    return true;
}

static bool cep_cell_enzyme_prepare_clone(cepCell* source, bool deep, cepCell** out_clone) {
    if (!source || !out_clone) {
        return false;
    }

    cepCell* clone = deep ? cep_cell_clone_deep(source) : cep_cell_clone(source);
    if (!clone) {
        return false;
    }

    *out_clone = clone;
    return true;
}

static cepCell* cep_cell_enzyme_parent_store_owner(cepCell* node) {
    if (!node) {
        return NULL;
    }

    cepCell* resolved = cep_cell_enzyme_resolve_link(node);
    if (!resolved || !cep_cell_is_normal(resolved)) {
        return NULL;
    }

    if (!resolved->store) {
        return NULL;
    }

    return resolved;
}

static uintptr_t cep_cell_enzyme_compute_context(cepCell* parent, bool has_position, uint64_t position) {
    parent = cep_cell_enzyme_resolve_link(parent);
    if (!parent || !parent->store) {
        return 0u;
    }

    cepStore* store = parent->store;
    if (store->indexing != CEP_INDEX_BY_INSERTION) {
        return 0u;
    }

    if (!has_position) {
        return (uintptr_t)store->chdCount;
    }

    if (position > (uint64_t)store->chdCount) {
        return (uintptr_t)store->chdCount;
    }

    return (uintptr_t)position;
}

static void cep_cell_enzyme_free_clone(cepCell* clone) {
    if (!clone) {
        return;
    }

    if (!cep_cell_is_void(clone)) {
        cep_cell_finalize_hard(clone);
    }
    cep_free(clone);
}

static int cep_cell_enzyme_add(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_cell_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* parent = cep_cell_enzyme_request_link(request, dt_role_parent());
    if (!parent) {
        return CEP_ENZYME_FATAL;
    }

    parent = cep_cell_enzyme_parent_store_owner(parent);
    if (!parent) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* blueprint = cep_cell_enzyme_request_link(request, dt_role_template());
    if (!blueprint) {
        blueprint = cep_cell_enzyme_request_link(request, dt_role_source());
    }
    if (!blueprint) {
        return CEP_ENZYME_FATAL;
    }

    bool deep = false;
    (void)cep_cell_enzyme_request_bool(request, dt_arg_deep(), &deep);

    cepCell* clone = NULL;
    if (!cep_cell_enzyme_prepare_clone(blueprint, deep, &clone)) {
        return CEP_ENZYME_FATAL;
    }

    bool prepend = false;
    bool use_prepend = cep_cell_enzyme_request_bool(request, dt_arg_prepend(), &prepend);

    uint64_t position_raw = 0u;
    bool has_position = cep_cell_enzyme_request_u64(request, dt_arg_position(), &position_raw);
    uintptr_t context = cep_cell_enzyme_compute_context(parent, has_position, position_raw);

    cepCell* inserted = NULL;
    if (parent->store->indexing == CEP_INDEX_BY_INSERTION && !has_position && use_prepend && prepend) {
        inserted = cep_cell_append(parent, true, clone);
    } else if (parent->store->indexing == CEP_INDEX_BY_INSERTION && !has_position && use_prepend && !prepend) {
        inserted = cep_cell_append(parent, false, clone);
    } else {
        inserted = cep_cell_add(parent, context, clone);
    }

    if (!inserted) {
        cep_cell_enzyme_free_clone(clone);
        return CEP_ENZYME_FATAL;
    }

    cep_cell_enzyme_free_clone(clone);
    return CEP_ENZYME_SUCCESS;
}

static int cep_cell_enzyme_update(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_cell_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* subject = cep_cell_enzyme_request_link(request, dt_role_subject());
    cepCell* source  = cep_cell_enzyme_request_link(request, dt_role_source());
    if (!subject || !source) {
        return CEP_ENZYME_FATAL;
    }

    subject = cep_cell_enzyme_resolve_link(subject);
    source  = cep_cell_enzyme_resolve_link(source);

    if (!cep_cell_is_normal(subject) || !cep_cell_has_data(subject)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_cell_has_data(source)) {
        return CEP_ENZYME_FATAL;
    }

    cepData* subject_data = subject->data;
    cepData* source_data  = source->data;

    if (subject_data->datatype != source_data->datatype) {
        return CEP_ENZYME_FATAL;
    }

    size_t size = source_data->size;
    if (size == 0u) {
        return CEP_ENZYME_FATAL;
    }

    switch (subject_data->datatype) {
      case CEP_DATATYPE_VALUE: {
        if (size > subject_data->capacity) {
            return CEP_ENZYME_FATAL;
        }
        const void* payload = cep_data_payload(source_data);
        if (!payload) {
            return CEP_ENZYME_FATAL;
        }
        if (!cep_cell_update(subject, size, size, (void*)payload, false)) {
            return CEP_ENZYME_FATAL;
        }
        break;
      }

      case CEP_DATATYPE_DATA: {
        const void* payload = cep_data_payload(source_data);
        void* copy = cep_malloc(size);
        memcpy(copy, payload, size);
        if (!cep_cell_update_hard(subject, size, size, copy, true)) {
            cep_free(copy);
            return CEP_ENZYME_FATAL;
        }
        break;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM:
      default:
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_cell_enzyme_delete(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* cell = cep_cell_enzyme_resolve(target);
    if (!cell) {
        return CEP_ENZYME_FATAL;
    }

    cell = cep_cell_enzyme_resolve_link(cell);
    if (!cell || cep_cell_is_root(cell)) {
        return CEP_ENZYME_FATAL;
    }

    cep_cell_delete_hard(cell);
    return CEP_ENZYME_SUCCESS;
}

static cepCell* cep_cell_enzyme_insert_clone(cepCell* parent, cepCell* clone, bool use_prepend, bool prepend, bool has_position, uint64_t position_raw) {
    parent = cep_cell_enzyme_parent_store_owner(parent);
    if (!parent) {
        return NULL;
    }

    uintptr_t context = cep_cell_enzyme_compute_context(parent, has_position, position_raw);

    if (parent->store->indexing == CEP_INDEX_BY_INSERTION && !has_position && use_prepend) {
        return cep_cell_append(parent, prepend, clone);
    }

    return cep_cell_add(parent, context, clone);
}

static int cep_cell_enzyme_move(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_cell_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* subject = cep_cell_enzyme_request_link(request, dt_role_subject());
    cepCell* parent  = cep_cell_enzyme_request_link(request, dt_role_parent());
    if (!subject || !parent) {
        return CEP_ENZYME_FATAL;
    }

    subject = cep_cell_enzyme_resolve_link(subject);
    if (!subject || cep_cell_is_root(subject)) {
        return CEP_ENZYME_FATAL;
    }

    bool deep = true;
    (void)cep_cell_enzyme_request_bool(request, dt_arg_deep(), &deep);

    cepCell* clone = NULL;
    if (!cep_cell_enzyme_prepare_clone(subject, deep, &clone)) {
        return CEP_ENZYME_FATAL;
    }

    bool prepend = false;
    bool use_prepend = cep_cell_enzyme_request_bool(request, dt_arg_prepend(), &prepend);
    uint64_t position_raw = 0u;
    bool has_position = cep_cell_enzyme_request_u64(request, dt_arg_position(), &position_raw);

    cepCell* inserted = cep_cell_enzyme_insert_clone(parent, clone, use_prepend, prepend, has_position, position_raw);
    if (!inserted) {
        cep_cell_enzyme_free_clone(clone);
        return CEP_ENZYME_FATAL;
    }

    cep_cell_remove_hard(subject, NULL);
    cep_cell_enzyme_free_clone(clone);
    return CEP_ENZYME_SUCCESS;
}

static int cep_cell_enzyme_clone(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_cell_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* source = cep_cell_enzyme_request_link(request, dt_role_source());
    cepCell* parent = cep_cell_enzyme_request_link(request, dt_role_parent());
    if (!source || !parent) {
        return CEP_ENZYME_FATAL;
    }

    source = cep_cell_enzyme_resolve_link(source);
    if (!source) {
        return CEP_ENZYME_FATAL;
    }

    bool deep = false;
    (void)cep_cell_enzyme_request_bool(request, dt_arg_deep(), &deep);

    cepCell* clone = NULL;
    if (!cep_cell_enzyme_prepare_clone(source, deep, &clone)) {
        return CEP_ENZYME_FATAL;
    }

    bool prepend = false;
    bool use_prepend = cep_cell_enzyme_request_bool(request, dt_arg_prepend(), &prepend);
    uint64_t position_raw = 0u;
    bool has_position = cep_cell_enzyme_request_u64(request, dt_arg_position(), &position_raw);

    cepCell* inserted = cep_cell_enzyme_insert_clone(parent, clone, use_prepend, prepend, has_position, position_raw);
    if (!inserted) {
        cep_cell_enzyme_free_clone(clone);
        return CEP_ENZYME_FATAL;
    }

    cep_cell_enzyme_free_clone(clone);
    return CEP_ENZYME_SUCCESS;
}

static bool cep_cell_operations_populate(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    struct {
        cepPathConst2       path;
        cepEnzymeDescriptor descriptor;
    } entries[] = {
        {
            .path = {
                .length = 2u,
                .capacity = 2u,
                .past = {
                    { .dt = *dt_signal_cell(), .timestamp = 0u },
                    { .dt = *dt_op_add(),      .timestamp = 0u },
                },
            },
            .descriptor = {
                .name    = *dt_enz_add(),
                .label   = "cell.add",
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = cep_cell_enzyme_add,
                .flags    = CEP_ENZYME_FLAG_NONE,
                .match    = CEP_ENZYME_MATCH_EXACT,
            },
        },
        {
            .path = {
                .length = 2u,
                .capacity = 2u,
                .past = {
                    { .dt = *dt_signal_cell(), .timestamp = 0u },
                    { .dt = *dt_op_update(),   .timestamp = 0u },
                },
            },
            .descriptor = {
                .name    = *dt_enz_update(),
                .label   = "cell.update",
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = cep_cell_enzyme_update,
                .flags    = CEP_ENZYME_FLAG_NONE,
                .match    = CEP_ENZYME_MATCH_EXACT,
            },
        },
        {
            .path = {
                .length = 2u,
                .capacity = 2u,
                .past = {
                    { .dt = *dt_signal_cell(), .timestamp = 0u },
                    { .dt = *dt_op_delete(),   .timestamp = 0u },
                },
            },
            .descriptor = {
                .name    = *dt_enz_delete(),
                .label   = "cell.delete",
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = cep_cell_enzyme_delete,
                .flags    = CEP_ENZYME_FLAG_NONE,
                .match    = CEP_ENZYME_MATCH_EXACT,
            },
        },
        {
            .path = {
                .length = 2u,
                .capacity = 2u,
                .past = {
                    { .dt = *dt_signal_cell(), .timestamp = 0u },
                    { .dt = *dt_op_move(),     .timestamp = 0u },
                },
            },
            .descriptor = {
                .name    = *dt_enz_move(),
                .label   = "cell.move",
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = cep_cell_enzyme_move,
                .flags    = CEP_ENZYME_FLAG_NONE,
                .match    = CEP_ENZYME_MATCH_EXACT,
            },
        },
        {
            .path = {
                .length = 2u,
                .capacity = 2u,
                .past = {
                    { .dt = *dt_signal_cell(), .timestamp = 0u },
                    { .dt = *dt_op_clone(),    .timestamp = 0u },
                },
            },
            .descriptor = {
                .name    = *dt_enz_clone(),
                .label   = "cell.clone",
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = cep_cell_enzyme_clone,
                .flags    = CEP_ENZYME_FLAG_NONE,
                .match    = CEP_ENZYME_MATCH_EXACT,
            },
        },
    };

    for (size_t i = 0; i < cep_lengthof(entries); ++i) {
        const cepPath* path = (const cepPath*)&entries[i].path;
        if (cep_enzyme_register(registry, path, &entries[i].descriptor) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    return true;
}


bool cep_cell_operations_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    const size_t expected = 5u;
    cepCellOperationsRegistryRecord* record = cep_cell_operations_registry_record_find(registry);
    size_t current_size = cep_enzyme_registry_size(registry);

    if (record && current_size >= record->baseline) {
        return true;
    }

    if (!record && current_size >= expected) {
        (void)cep_cell_operations_registry_record_append(registry, current_size);
        return true;
    }

    if (cep_cell_operations_active_registry == registry) {
        return true;
    }

    cepEnzymeRegistry* previous_active = cep_cell_operations_active_registry;
    cep_cell_operations_active_registry = registry;

    size_t size_before = current_size;
    bool ok = cep_cell_operations_populate(registry);

    cep_cell_operations_active_registry = previous_active;

    if (!ok) {
        return false;
    }

    size_t size_after = cep_enzyme_registry_size(registry);
    size_t baseline = (size_after > size_before) ? size_after : (size_before + expected);

    if (record) {
        record->baseline = baseline;
    } else {
        (void)cep_cell_operations_registry_record_append(registry, baseline);
    }

    return true;
}

