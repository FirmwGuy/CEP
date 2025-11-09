/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "fed_transport.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_molecule.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_ops.h"

#include <stdint.h>
#include <string.h>

typedef struct {
    cepFedTransportProvider provider;
    void*                   ctx;
    char*                   provider_id_copy;
} cepFedTransportEntry;

static cepFedTransportEntry* cep_fed_transport_entries = NULL;
static size_t cep_fed_transport_entry_count = 0u;
static size_t cep_fed_transport_entry_capacity = 0u;

static const cepFedTransportProvider* cep_fed_transport_provider_at(size_t index, void** out_ctx) {
    if (index >= cep_fed_transport_entry_count) {
        return NULL;
    }
    if (out_ctx) {
        *out_ctx = cep_fed_transport_entries[index].ctx;
    }
    return &cep_fed_transport_entries[index].provider;
}

static ssize_t cep_fed_transport_find_index(const char* provider_id) {
    if (!provider_id || !cep_fed_transport_entries) {
        return -1;
    }
    for (size_t i = 0; i < cep_fed_transport_entry_count; ++i) {
        if (strcmp(cep_fed_transport_entries[i].provider.provider_id, provider_id) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

bool cep_fed_transport_register(const cepFedTransportProvider* provider,
                                void* provider_ctx) {
    if (!provider || !provider->provider_id || !provider->vtable) {
        return false;
    }

    size_t id_len = strlen(provider->provider_id);
    if (id_len == 0u || id_len > CEP_FED_TRANSPORT_PROVIDER_ID_MAX) {
        return false;
    }

    if (cep_fed_transport_find_index(provider->provider_id) >= 0) {
        return false;
    }

    if (cep_fed_transport_entry_count == cep_fed_transport_entry_capacity) {
        size_t new_capacity = cep_fed_transport_entry_capacity ? (cep_fed_transport_entry_capacity * 2u) : 4u;
        size_t bytes = new_capacity * sizeof(*cep_fed_transport_entries);
        cepFedTransportEntry* grown = cep_fed_transport_entries
            ? cep_realloc(cep_fed_transport_entries, bytes)
            : cep_malloc0(bytes);
        if (!grown) {
            return false;
        }
        if (grown != cep_fed_transport_entries) {
            size_t previous_bytes = cep_fed_transport_entry_capacity * sizeof(*cep_fed_transport_entries);
            if (previous_bytes < bytes) {
                memset(((uint8_t*)grown) + previous_bytes, 0, bytes - previous_bytes);
            }
        }
        cep_fed_transport_entries = grown;
        cep_fed_transport_entry_capacity = new_capacity;
    }

    char* id_copy = cep_malloc0(id_len + 1u);
    if (!id_copy) {
        return false;
    }
    memcpy(id_copy, provider->provider_id, id_len + 1u);

    cepFedTransportEntry* entry = &cep_fed_transport_entries[cep_fed_transport_entry_count++];
    memset(entry, 0, sizeof *entry);
    entry->provider = *provider;
    entry->provider.provider_id = id_copy;
    entry->provider_id_copy = id_copy;
    entry->ctx = provider_ctx;
    return true;
}

bool cep_fed_transport_unregister(const char* provider_id) {
    ssize_t index = cep_fed_transport_find_index(provider_id);
    if (index < 0) {
        return false;
    }

    cepFedTransportEntry* entry = &cep_fed_transport_entries[index];
    if (entry->provider_id_copy) {
        cep_free(entry->provider_id_copy);
        entry->provider_id_copy = NULL;
    }

    if ((size_t)index != (cep_fed_transport_entry_count - 1u)) {
        cep_fed_transport_entries[index] = cep_fed_transport_entries[cep_fed_transport_entry_count - 1u];
    }
    memset(&cep_fed_transport_entries[cep_fed_transport_entry_count - 1u], 0, sizeof *entry);
    --cep_fed_transport_entry_count;
    return true;
}

const cepFedTransportProvider* cep_fed_transport_provider_lookup(const char* provider_id,
                                                                 void** out_provider_ctx) {
    ssize_t index = cep_fed_transport_find_index(provider_id);
    if (index < 0) {
        if (out_provider_ctx) {
            *out_provider_ctx = NULL;
        }
        return NULL;
    }
    return cep_fed_transport_provider_at((size_t)index, out_provider_ctx);
}

size_t cep_fed_transport_provider_enumerate(const cepFedTransportProvider** out_array,
                                            size_t capacity,
                                            void** out_contexts) {
    if (!out_array || capacity == 0u) {
        return cep_fed_transport_entry_count;
    }

    size_t count = cep_fed_transport_entry_count < capacity
                   ? cep_fed_transport_entry_count
                   : capacity;
    for (size_t i = 0; i < count; ++i) {
        out_array[i] = cep_fed_transport_provider_at(i, out_contexts ? &out_contexts[i] : NULL);
    }
    return cep_fed_transport_entry_count;
}

CEP_DEFINE_STATIC_DT(dt_transports_name, CEP_ACRO("CEP"), CEP_WORD("transports"));
CEP_DEFINE_STATIC_DT(dt_caps_name, CEP_ACRO("CEP"), CEP_WORD("caps"));
CEP_DEFINE_STATIC_DT(dt_config_name, CEP_ACRO("CEP"), CEP_WORD("config"));
CEP_DEFINE_STATIC_DT(dt_health_name, CEP_ACRO("CEP"), CEP_WORD("health"));
CEP_DEFINE_STATIC_DT(dt_limits_name, CEP_ACRO("CEP"), CEP_WORD("limits"));
CEP_DEFINE_STATIC_DT(dt_max_payload_name, CEP_ACRO("CEP"), CEP_WORD("max_payload"));
CEP_DEFINE_STATIC_DT(dt_upd_latest_name, CEP_ACRO("CEP"), CEP_WORD("upd_latest"));

CEP_DEFINE_STATIC_DT(dt_cap_reliable_name, CEP_ACRO("CEP"), CEP_WORD("reliable"));
CEP_DEFINE_STATIC_DT(dt_cap_ordered_name, CEP_ACRO("CEP"), CEP_WORD("ordered"));
CEP_DEFINE_STATIC_DT(dt_cap_streaming_name, CEP_ACRO("CEP"), CEP_WORD("streaming"));
CEP_DEFINE_STATIC_DT(dt_cap_datagram_name, CEP_ACRO("CEP"), CEP_WORD("datagram"));
CEP_DEFINE_STATIC_DT(dt_cap_multicast_name, CEP_ACRO("CEP"), CEP_WORD("multicast"));
CEP_DEFINE_STATIC_DT(dt_cap_latency_name, CEP_ACRO("CEP"), CEP_WORD("low_latency"));
CEP_DEFINE_STATIC_DT(dt_cap_local_ipc_name, CEP_ACRO("CEP"), CEP_WORD("local_ipc"));
CEP_DEFINE_STATIC_DT(dt_cap_remote_net_name, CEP_ACRO("CEP"), CEP_WORD("remote_net"));
CEP_DEFINE_STATIC_DT(dt_cap_unreliable_name, CEP_ACRO("CEP"), CEP_WORD("unreliable"));

typedef const cepDT* (*cepFedTransportDtGetter)(void);

typedef struct {
    cepFedTransportCaps     flag;
    cepFedTransportDtGetter getter;
} cepFedTransportCapEntry;

#define CEP_FED_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static const cepFedTransportCapEntry cep_fed_transport_cap_entries[] = {
    { CEP_FED_TRANSPORT_CAP_RELIABLE,    dt_cap_reliable_name    },
    { CEP_FED_TRANSPORT_CAP_ORDERED,     dt_cap_ordered_name     },
    { CEP_FED_TRANSPORT_CAP_STREAMING,   dt_cap_streaming_name   },
    { CEP_FED_TRANSPORT_CAP_DATAGRAM,    dt_cap_datagram_name    },
    { CEP_FED_TRANSPORT_CAP_MULTICAST,   dt_cap_multicast_name   },
    { CEP_FED_TRANSPORT_CAP_LOW_LATENCY, dt_cap_latency_name     },
    { CEP_FED_TRANSPORT_CAP_LOCAL_IPC,   dt_cap_local_ipc_name   },
    { CEP_FED_TRANSPORT_CAP_REMOTE_NET,  dt_cap_remote_net_name  },
    { CEP_FED_TRANSPORT_CAP_UNRELIABLE,  dt_cap_unreliable_name  },
};

cepCell* cep_fed_transport_ensure_transports_root(cepCell* net_root) {
    if (!net_root) {
        return NULL;
    }

    cepCell* resolved = net_root;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return NULL;
    }

    return cep_cell_ensure_dictionary_child(resolved, dt_transports_name(), CEP_STORAGE_RED_BLACK_T);
}

static bool cep_fed_transport_write_bool(cepCell* parent,
                                         const cepDT* field,
                                         bool value) {
    if (!parent || !field) {
        return false;
    }

    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepDT name_copy = *field;
    cepDT type_dt = cep_ops_make_dt("val/bool");
    uint8_t bool_value = value ? 1u : 0u;
    cepCell* node = cep_dict_add_value(resolved, &name_copy, &type_dt, &bool_value, sizeof bool_value, sizeof bool_value);
    return node != NULL;
}

static bool cep_fed_transport_write_u64(cepCell* parent,
                                        const cepDT* field,
                                        uint64_t value) {
    if (!parent || !field) {
        return false;
    }

    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepDT name_copy = *field;
    cepDT type_dt = cep_ops_make_dt("val/u64");
    cepCell* node = cep_dict_add_value(resolved, &name_copy, &type_dt, &value, sizeof value, sizeof value);
    return node != NULL;
}

static cepCell* cep_fed_transport_prepare_caps(cepCell* provider_cell) {
    if (!provider_cell) {
        return NULL;
    }

    cepCell* caps_cell = cep_cell_ensure_dictionary_child(provider_cell, dt_caps_name(), CEP_STORAGE_RED_BLACK_T);
    if (!caps_cell) {
        return NULL;
    }
    caps_cell = cep_cell_resolve(caps_cell);
    if (!caps_cell || !cep_cell_require_dictionary_store(&caps_cell)) {
        return NULL;
    }
    if (caps_cell->store) {
        cep_store_delete_children_hard(caps_cell->store);
    }
    return caps_cell;
}

static cepCell* cep_fed_transport_prepare_limits(cepCell* provider_cell) {
    if (!provider_cell) {
        return NULL;
    }

    cepCell* limits_cell = cep_cell_ensure_dictionary_child(provider_cell, dt_limits_name(), CEP_STORAGE_RED_BLACK_T);
    if (!limits_cell) {
        return NULL;
    }
    limits_cell = cep_cell_resolve(limits_cell);
    if (!limits_cell || !cep_cell_require_dictionary_store(&limits_cell)) {
        return NULL;
    }
    if (limits_cell->store) {
        cep_store_delete_children_hard(limits_cell->store);
    }
    return limits_cell;
}

static bool cep_fed_transport_ensure_branch(cepCell* provider_cell) {
    if (!provider_cell) {
        return false;
    }

    if (!cep_cell_ensure_dictionary_child(provider_cell, dt_config_name(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_cell_ensure_dictionary_child(provider_cell, dt_health_name(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    return true;
}

static bool cep_fed_transport_write_caps(cepCell* caps_cell,
                                         cepFedTransportCaps caps) {
    if (!caps_cell) {
        return false;
    }

    bool ok = true;
    for (size_t i = 0; i < CEP_FED_ARRAY_LEN(cep_fed_transport_cap_entries); ++i) {
        const cepFedTransportCapEntry* entry = &cep_fed_transport_cap_entries[i];
        const cepDT* name = entry->getter ? entry->getter() : NULL;
        bool value = (caps & entry->flag) != 0u;
        ok = cep_fed_transport_write_bool(caps_cell, name, value) && ok;
    }
    return ok;
}

bool cep_fed_transport_schema_seed_provider(cepCell* transports_root,
                                            const char* provider_id,
                                            const cepFedTransportProvider* provider,
                                            bool supports_upd_latest) {
    if (!transports_root || !provider_id || !provider) {
        return false;
    }

    cepDT provider_name = {
        .domain = cep_namepool_intern_cstr("CEP"),
        .tag = cep_text_to_word(provider_id),
    };

    if (provider_name.tag == 0u) {
        return false;
    }

    cepCell* provider_cell = cep_cell_ensure_dictionary_child(transports_root, &provider_name, CEP_STORAGE_RED_BLACK_T);
    if (!provider_cell) {
        return false;
    }

    provider_cell = cep_cell_resolve(provider_cell);
    if (!provider_cell || !cep_cell_require_dictionary_store(&provider_cell)) {
        return false;
    }

    if (!cep_fed_transport_ensure_branch(provider_cell)) {
        return false;
    }

    cepCell* caps_cell = cep_fed_transport_prepare_caps(provider_cell);
    if (!caps_cell) {
        return false;
    }

    if (!cep_fed_transport_write_caps(caps_cell, provider->caps)) {
        return false;
    }

    if (supports_upd_latest) {
        if (!cep_fed_transport_write_bool(provider_cell, dt_upd_latest_name(), true)) {
            return false;
        }
    } else {
        cep_fed_transport_write_bool(provider_cell, dt_upd_latest_name(), false);
    }

    cepCell* limits_cell = cep_fed_transport_prepare_limits(provider_cell);
    if (!limits_cell) {
        return false;
    }

    if (provider->max_payload_bytes > 0u) {
        if (!cep_fed_transport_write_u64(limits_cell, dt_max_payload_name(), (uint64_t)provider->max_payload_bytes)) {
            return false;
        }
    } else {
        if (!cep_fed_transport_write_u64(limits_cell, dt_max_payload_name(), 0u)) {
            return false;
        }
    }

    (void)cep_cell_resolve(provider_cell);
    return true;
}
