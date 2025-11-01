#include "fed_transport_manager.h"

#include "fed_transport.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_molecule.h"
#include "../l0_kernel/cep_namepool.h"

#include <stdio.h>
#include <string.h>

struct cepFedTransportManagerMount {
    cepFedTransportManager*        manager;
    cepCell*                       mount_cell;
    char*                          peer_id;
    char*                          mount_id;
    char*                          mount_mode;
    char*                          local_node_id;
    char*                          provider_id;
    const cepFedTransportProvider* provider;
    void*                          provider_ctx;
    cepFedTransportChannel*        channel;
    cepFedTransportCaps            required_caps;
    cepFedTransportCaps            preferred_caps;
    bool                           allow_upd_latest;
    bool                           supports_upd_latest;
    bool                           channel_open;
    bool                           backpressured;
    uint8_t*                       pending_payload;
    size_t                         pending_len;
    cepFedTransportMountCallbacks  callbacks;
};

CEP_DEFINE_STATIC_DT(dt_mounts_name, CEP_ACRO("CEP"), CEP_WORD("mounts"));
CEP_DEFINE_STATIC_DT(dt_caps_name, CEP_ACRO("CEP"), CEP_WORD("caps"));
CEP_DEFINE_STATIC_DT(dt_required_name, CEP_ACRO("CEP"), CEP_WORD("required"));
CEP_DEFINE_STATIC_DT(dt_preferred_name, CEP_ACRO("CEP"), CEP_WORD("preferred"));
CEP_DEFINE_STATIC_DT(dt_transport_name, CEP_ACRO("CEP"), CEP_WORD("transport"));
CEP_DEFINE_STATIC_DT(dt_provider_name, CEP_ACRO("CEP"), CEP_WORD("provider"));
CEP_DEFINE_STATIC_DT(dt_selected_caps_name, CEP_ACRO("CEP"), CEP_WORD("prov_caps"));
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
CEP_DEFINE_STATIC_DT(dt_sev_error_name, CEP_ACRO("sev"), CEP_WORD("error"));
CEP_DEFINE_STATIC_DT(dt_sev_warn_name, CEP_ACRO("sev"), CEP_WORD("warn"));

typedef const cepDT* (*cepFedTransportDtGetter)(void);

typedef struct {
    cepFedTransportCaps     flag;
    cepFedTransportDtGetter getter;
} cepFedTransportCapEntry;

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

static inline unsigned cep_fed_transport_popcount(cepFedTransportCaps value) {
    unsigned count = 0u;
    while (value) {
        count += (value & 1u);
        value >>= 1u;
    }
    return count;
}

static void cep_fed_transport_manager_mount_reset_pending(cepFedTransportManagerMount* mount) {
    if (!mount) {
        return;
    }
    if (mount->pending_payload) {
        cep_free(mount->pending_payload);
        mount->pending_payload = NULL;
    }
    mount->pending_len = 0u;
}

static void cep_fed_transport_manager_emit_diag(cepFedTransportManager* manager,
                                                cepFedTransportManagerMount* mount,
                                                const cepDT* severity,
                                                const char* note,
                                                const char* topic) {
    if (!manager || !severity) {
        return;
    }
    cepCeiRequest req = {0};
    req.severity = *severity;
    req.note = note;
    req.topic = topic;
    req.topic_intern = (topic != NULL);
    req.subject = mount ? mount->mount_cell : NULL;
    req.mailbox_root = manager->diagnostics_mailbox;
    req.emit_signal = true;
    req.attach_to_op = false;
    req.ttl_forever = false;
    (void)cep_cei_emit(&req);
}

static cepCell* cep_fed_transport_manager_ensure_mount_cell(cepFedTransportManager* manager,
                                                            const char* peer_id,
                                                            const char* mode,
                                                            const char* mount_id) {
    if (!manager || !manager->mounts_root || !peer_id || !mode || !mount_id) {
        return NULL;
    }

    cepCell* resolved_root = cep_cell_resolve(manager->mounts_root);
    if (!resolved_root || !cep_cell_require_dictionary_store(&resolved_root)) {
        return NULL;
    }

    cepDT peer_dt = {
        .domain = cep_namepool_intern_cstr("CEP"),
        .tag = cep_text_to_word(peer_id),
    };
    cepDT mode_dt = {
        .domain = cep_namepool_intern_cstr("CEP"),
        .tag = cep_text_to_word(mode),
    };
    cepDT mount_dt = {
        .domain = cep_namepool_intern_cstr("CEP"),
        .tag = cep_text_to_word(mount_id),
    };

    if (peer_dt.tag == 0u || mode_dt.tag == 0u || mount_dt.tag == 0u) {
        return NULL;
    }

    cepCell* peer_cell = cep_cell_ensure_dictionary_child(resolved_root, &peer_dt, CEP_STORAGE_RED_BLACK_T);
    if (!peer_cell) {
        return NULL;
    }
    peer_cell = cep_cell_resolve(peer_cell);
    if (!peer_cell || !cep_cell_require_dictionary_store(&peer_cell)) {
        return NULL;
    }

    cepCell* mode_cell = cep_cell_ensure_dictionary_child(peer_cell, &mode_dt, CEP_STORAGE_RED_BLACK_T);
    if (!mode_cell) {
        return NULL;
    }
    mode_cell = cep_cell_resolve(mode_cell);
    if (!mode_cell || !cep_cell_require_dictionary_store(&mode_cell)) {
        return NULL;
    }

    cepCell* mount_cell = cep_cell_ensure_dictionary_child(mode_cell, &mount_dt, CEP_STORAGE_RED_BLACK_T);
    if (!mount_cell) {
        return NULL;
    }
    mount_cell = cep_cell_resolve(mount_cell);
    if (!mount_cell || !cep_cell_require_dictionary_store(&mount_cell)) {
        return NULL;
    }
    return mount_cell;
}

static bool cep_fed_transport_manager_write_bool(cepCell* parent,
                                                 const cepDT* field,
                                                 bool value) {
    if (!parent || !field) {
        return false;
    }
    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepDT field_copy = *field;
    cepDT type_dt = cep_ops_make_dt("val/bool");
    uint8_t bool_value = value ? 1u : 0u;
    return cep_dict_add_value(resolved, &field_copy, &type_dt, &bool_value, sizeof bool_value, sizeof bool_value) != NULL;
}

static bool cep_fed_transport_manager_write_text(cepCell* parent,
                                                 const cepDT* field,
                                                 const char* value) {
    if (!parent || !field || !value) {
        return false;
    }
    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepDT field_copy = *field;
    cepDT type_dt = cep_ops_make_dt("val/text");
    size_t len = strlen(value);
    return cep_dict_add_value(resolved, &field_copy, &type_dt, (void*)value, len, len) != NULL;
}

static bool cep_fed_transport_manager_write_caps_branch(cepCell* parent,
                                                        const cepDT* branch,
                                                        cepFedTransportCaps caps) {
    if (!parent || !branch) {
        return false;
    }

    cepCell* branch_cell = cep_cell_ensure_dictionary_child(parent, branch, CEP_STORAGE_RED_BLACK_T);
    if (!branch_cell) {
        return false;
    }
    branch_cell = cep_cell_resolve(branch_cell);
    if (!branch_cell || !cep_cell_require_dictionary_store(&branch_cell)) {
        return false;
    }
    cep_store_delete_children_hard(branch_cell->store);

    bool ok = true;
    for (size_t i = 0; i < cep_lengthof(cep_fed_transport_cap_entries); ++i) {
        const cepFedTransportCapEntry* entry = &cep_fed_transport_cap_entries[i];
        bool bit_on = (caps & entry->flag) != 0u;
        ok = cep_fed_transport_manager_write_bool(branch_cell, entry->getter ? entry->getter() : NULL, bit_on) && ok;
    }
    return ok;
}

static bool cep_fed_transport_manager_update_mount_schema(cepFedTransportManagerMount* mount) {
    if (!mount || !mount->manager || !mount->manager->mounts_root || !mount->mount_cell) {
        return false;
    }

    cepCell* caps_cell = cep_cell_ensure_dictionary_child(mount->mount_cell, dt_caps_name(), CEP_STORAGE_RED_BLACK_T);
    if (!caps_cell) {
        return false;
    }
    caps_cell = cep_cell_resolve(caps_cell);
    if (!caps_cell || !cep_cell_require_dictionary_store(&caps_cell)) {
        return false;
    }

    if (!cep_fed_transport_manager_write_caps_branch(caps_cell, dt_required_name(), mount->required_caps)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_caps_branch(caps_cell, dt_preferred_name(), mount->preferred_caps)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_bool(caps_cell, dt_upd_latest_name(), mount->allow_upd_latest)) {
        return false;
    }

    cepCell* transport_cell = cep_cell_ensure_dictionary_child(mount->mount_cell, dt_transport_name(), CEP_STORAGE_RED_BLACK_T);
    if (!transport_cell) {
        return false;
    }
    transport_cell = cep_cell_resolve(transport_cell);
    if (!transport_cell || !cep_cell_require_dictionary_store(&transport_cell)) {
        return false;
    }

    if (mount->provider_id) {
        if (!cep_fed_transport_manager_write_bool(transport_cell, dt_upd_latest_name(), mount->supports_upd_latest)) {
            return false;
        }
        if (!cep_fed_transport_manager_write_text(transport_cell, dt_provider_name(), mount->provider_id)) {
            return false;
        }
        if (!cep_fed_transport_manager_write_caps_branch(transport_cell, dt_selected_caps_name(), mount->provider ? mount->provider->caps : 0u)) {
            return false;
        }
    }

    (void)cep_cell_resolve(mount->mount_cell);
    return true;
}

static cepFedTransportManagerMount* cep_fed_transport_manager_find_mount(cepFedTransportManager* manager,
                                                                         const char* peer_id,
                                                                         const char* mount_mode,
                                                                         const char* mount_id) {
    if (!manager || !peer_id || !mount_mode || !mount_id) {
        return NULL;
    }
    for (size_t i = 0; i < manager->mount_count; ++i) {
        cepFedTransportManagerMount* mount = &manager->mounts[i];
        if (!mount->peer_id || !mount->mount_mode || !mount->mount_id) {
            continue;
        }
        if (strcmp(mount->peer_id, peer_id) == 0 &&
            strcmp(mount->mount_mode, mount_mode) == 0 &&
            strcmp(mount->mount_id, mount_id) == 0) {
            return mount;
        }
    }
    return NULL;
}

static bool cep_fed_transport_manager_grow_mounts(cepFedTransportManager* manager) {
    if (!manager) {
        return false;
    }
    if (manager->mount_count < manager->mount_capacity) {
        return true;
    }
    size_t new_capacity = manager->mount_capacity ? manager->mount_capacity * 2u : 4u;
    size_t bytes = new_capacity * sizeof *manager->mounts;
    cepFedTransportManagerMount* grown = manager->mounts
        ? cep_realloc(manager->mounts, bytes)
        : cep_malloc0(bytes);
    if (!grown) {
        return false;
    }
    manager->mounts = grown;
    manager->mount_capacity = new_capacity;
    return true;
}

static char* cep_fed_transport_manager_strdup(const char* text) {
    if (!text) {
        return NULL;
    }
    size_t len = strlen(text);
    char* copy = cep_malloc(len + 1u);
    memcpy(copy, text, len + 1u);
    return copy;
}

static void cep_fed_transport_manager_mount_detach(cepFedTransportManagerMount* mount) {
    if (!mount) {
        return;
    }
    if (mount->provider && mount->channel && mount->provider->vtable && mount->provider->vtable->close) {
        mount->provider->vtable->close(mount->provider_ctx, mount->channel, "manager-detach");
    }
    cep_fed_transport_manager_mount_reset_pending(mount);
    if (mount->peer_id) {
        cep_free(mount->peer_id);
        mount->peer_id = NULL;
    }
    if (mount->mount_id) {
        cep_free(mount->mount_id);
        mount->mount_id = NULL;
    }
    if (mount->mount_mode) {
        cep_free(mount->mount_mode);
        mount->mount_mode = NULL;
    }
    if (mount->local_node_id) {
        cep_free(mount->local_node_id);
        mount->local_node_id = NULL;
    }
    if (mount->provider_id) {
        cep_free(mount->provider_id);
        mount->provider_id = NULL;
    }
    mount->provider = NULL;
    mount->provider_ctx = NULL;
    mount->channel = NULL;
    mount->channel_open = false;
    mount->backpressured = false;
}

static bool cep_fed_transport_manager_flush_pending(cepFedTransportManagerMount* mount, uint64_t deadline_beat) {
    if (!mount || !mount->pending_payload || mount->pending_len == 0u || !mount->provider || !mount->provider->vtable) {
        return true;
    }
    if (!mount->channel) {
        return false;
    }
    bool sent = mount->provider->vtable->send(mount->provider_ctx,
                                              mount->channel,
                                              mount->pending_payload,
                                              mount->pending_len,
                                              CEP_FED_FRAME_MODE_UPD_LATEST,
                                              deadline_beat);
    if (sent) {
        cep_fed_transport_manager_mount_reset_pending(mount);
        mount->backpressured = false;
    }
    return sent;
}

static bool cep_fed_transport_manager_on_frame(void* manager_ctx,
                                               cepFedTransportChannel* channel,
                                               const uint8_t* payload,
                                               size_t payload_len,
                                               cepFedFrameMode mode) {
    cepFedTransportManagerMount* mount = (cepFedTransportManagerMount*)manager_ctx;
    if (!mount || channel != mount->channel) {
        return false;
    }
    if (mount->callbacks.on_frame) {
        return mount->callbacks.on_frame(mount->callbacks.user_ctx, mount, payload, payload_len, mode);
    }
    return true;
}

static void cep_fed_transport_manager_on_event(void* manager_ctx,
                                               cepFedTransportChannel* channel,
                                               cepFedTransportEventKind kind,
                                               const char* detail) {
    cepFedTransportManagerMount* mount = (cepFedTransportManagerMount*)manager_ctx;
    if (!mount || channel != mount->channel) {
        return;
    }

    switch (kind) {
    case CEP_FED_TRANSPORT_EVENT_BACKPRESSURE:
        mount->backpressured = true;
        break;
    case CEP_FED_TRANSPORT_EVENT_READY_RX:
    case CEP_FED_TRANSPORT_EVENT_RESET:
        mount->backpressured = false;
        (void)cep_fed_transport_manager_flush_pending(mount, 0u);
        break;
    case CEP_FED_TRANSPORT_EVENT_FATAL:
        mount->channel_open = false;
        break;
    default:
        break;
    }

    if (mount->callbacks.on_event) {
        mount->callbacks.on_event(mount->callbacks.user_ctx, mount, kind, detail);
    }
}

static bool cep_fed_transport_manager_select_provider(const cepFedTransportMountConfig* config,
                                                      const char** out_provider_id,
                                                      const cepFedTransportProvider** out_provider,
                                                      void** out_provider_ctx) {
    if (!config || !out_provider_id || !out_provider || !out_provider_ctx) {
        return false;
    }

    size_t provider_count = cep_fed_transport_provider_enumerate(NULL, 0u, NULL);
    if (provider_count == 0u) {
        return false;
    }

    const cepFedTransportProvider** providers = cep_malloc0(provider_count * sizeof(*providers));
    void** contexts = cep_malloc0(provider_count * sizeof(*contexts));
    size_t enumerated = cep_fed_transport_provider_enumerate(providers, provider_count, contexts);

    int best_index = -1;
    unsigned best_score = 0u;

    for (size_t i = 0; i < enumerated; ++i) {
        const cepFedTransportProvider* provider = providers[i];
        if (!provider) {
            continue;
        }
        if ((provider->caps & config->required_caps) != config->required_caps) {
            continue;
        }
        if (config->allow_upd_latest && (provider->caps & CEP_FED_TRANSPORT_CAP_UNRELIABLE) == 0u) {
            continue;
        }
        if (config->preferred_provider_id && strcmp(config->preferred_provider_id, provider->provider_id) == 0) {
            best_index = (int)i;
            break;
        }
        unsigned score = cep_fed_transport_popcount(provider->caps & config->preferred_caps);
        if (best_index < 0 || score > best_score) {
            best_index = (int)i;
            best_score = score;
        } else if (score == best_score && best_index >= 0) {
            if (strcmp(provider->provider_id, providers[best_index]->provider_id) < 0) {
                best_index = (int)i;
            }
        }
    }

    bool ok = false;
    if (best_index >= 0) {
        *out_provider_id = providers[best_index]->provider_id;
        *out_provider = providers[best_index];
        *out_provider_ctx = contexts[best_index];
        ok = true;
    }

    cep_free(providers);
    cep_free(contexts);
    return ok;
}

/* cep_fed_transport_manager_init ties the manager to the caller supplied /net root so
   subsequent mount orchestration can reuse the seeded transport registry and
   diagnostics mailbox without repeating resolution work on every call. */
bool cep_fed_transport_manager_init(cepFedTransportManager* manager,
                                    cepCell* net_root) {
    if (!manager || !net_root) {
        return false;
    }

    memset(manager, 0, sizeof *manager);
    manager->net_root = cep_cell_resolve(net_root);
    if (!manager->net_root || !cep_cell_require_dictionary_store(&manager->net_root)) {
        return false;
    }

    manager->transports_root = cep_fed_transport_ensure_transports_root(manager->net_root);
    if (!manager->transports_root) {
        return false;
    }

    manager->transports_root = cep_cell_resolve(manager->transports_root);
    if (!manager->transports_root || !cep_cell_require_dictionary_store(&manager->transports_root)) {
        return false;
    }

    manager->mounts_root = cep_cell_ensure_dictionary_child(manager->net_root, dt_mounts_name(), CEP_STORAGE_RED_BLACK_T);
    if (!manager->mounts_root) {
        return false;
    }
    manager->mounts_root = cep_cell_resolve(manager->mounts_root);
    if (!manager->mounts_root || !cep_cell_require_dictionary_store(&manager->mounts_root)) {
        return false;
    }

    manager->diagnostics_mailbox = cep_cei_diagnostics_mailbox();
    return manager->diagnostics_mailbox != NULL;
}

/* cep_fed_transport_manager_configure_mount selects a provider that satisfies the mount
   capability contract, updates the mount schema branch, and opens the provider channel
   so higher-level federation code only needs to supply callbacks for delivered frames. */
bool cep_fed_transport_manager_configure_mount(cepFedTransportManager* manager,
                                               const cepFedTransportMountConfig* config,
                                               const cepFedTransportMountCallbacks* callbacks,
                                               cepFedTransportManagerMount** out_mount) {
    if (!manager || !config || !config->peer_id || !config->mount_id || !config->local_node_id) {
        return false;
    }

    const char* mode = config->mount_mode ? config->mount_mode : "link";
    cepFedTransportManagerMount* mount = cep_fed_transport_manager_find_mount(manager,
                                                                              config->peer_id,
                                                                              mode,
                                                                              config->mount_id);

    if (!mount) {
        if (!cep_fed_transport_manager_grow_mounts(manager)) {
            return false;
        }
        mount = &manager->mounts[manager->mount_count++];
        memset(mount, 0, sizeof *mount);
        mount->manager = manager;
        mount->peer_id = cep_fed_transport_manager_strdup(config->peer_id);
        mount->mount_id = cep_fed_transport_manager_strdup(config->mount_id);
        mount->mount_mode = cep_fed_transport_manager_strdup(mode);
        mount->local_node_id = cep_fed_transport_manager_strdup(config->local_node_id);
        if (!mount->peer_id || !mount->mount_id || !mount->mount_mode || !mount->local_node_id) {
            cep_fed_transport_manager_mount_detach(mount);
            return false;
        }
    } else {
        if (mount->channel) {
            cep_fed_transport_manager_close(manager, mount, "reconfigure");
        }
    }

    mount->required_caps = config->required_caps;
    mount->preferred_caps = config->preferred_caps;
    mount->allow_upd_latest = config->allow_upd_latest;
    mount->callbacks = callbacks ? *callbacks : (cepFedTransportMountCallbacks){0};

    const char* provider_id = NULL;
    const cepFedTransportProvider* provider = NULL;
    void* provider_ctx = NULL;

    if (!cep_fed_transport_manager_select_provider(config, &provider_id, &provider, &provider_ctx)) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "No transport provider satisfies mount requirements",
                                            "transport/no_provider");
        return false;
    }

    if (mount->provider_id) {
        cep_free(mount->provider_id);
    }
    mount->provider_id = cep_fed_transport_manager_strdup(provider_id);
    mount->provider = provider;
    mount->provider_ctx = provider_ctx;
    mount->supports_upd_latest = (provider->caps & CEP_FED_TRANSPORT_CAP_UNRELIABLE) != 0u;

    mount->mount_cell = cep_fed_transport_manager_ensure_mount_cell(manager,
                                                                    mount->peer_id,
                                                                    mount->mount_mode,
                                                                    mount->mount_id);
    if (!mount->mount_cell) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Failed to ensure mount schema branch",
                                            "transport/schema");
        return false;
    }

    if (!cep_fed_transport_manager_update_mount_schema(mount)) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Failed to update mount schema with provider selection",
                                            "transport/schema_update");
        return false;
    }

    cepDT provider_dt = {
        .domain = cep_namepool_intern_cstr("CEP"),
        .tag = cep_text_to_word(provider_id),
    };
    if (provider_dt.tag == 0u) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Provider identifier could not be encoded",
                                            "transport/provider_id");
        return false;
    }

    cepCell* provider_cell = cep_cell_ensure_dictionary_child(manager->transports_root, &provider_dt, CEP_STORAGE_RED_BLACK_T);
    if (!provider_cell) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Provider cell missing in transport registry",
                                            "transport/provider_cell");
        return false;
    }

    provider_cell = cep_cell_resolve(provider_cell);
    if (!provider_cell || !cep_cell_require_dictionary_store(&provider_cell)) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Provider cell unavailable for open request",
                                            "transport/provider_cell");
        return false;
    }

    cepFedTransportOpenArgs open_args = {
        .provider_id = provider_id,
        .peer_id = config->peer_id,
        .mount_id = config->mount_id,
        .local_node_id = config->local_node_id,
        .provider_cell = provider_cell,
        .required_caps = config->required_caps,
        .preferred_caps = config->preferred_caps,
        .deadline_beat = config->deadline_beat,
    };

    cepFedTransportCallbacks provider_callbacks = {
        .on_frame = cep_fed_transport_manager_on_frame,
        .on_event = cep_fed_transport_manager_on_event,
    };

    cepFedTransportChannel* opened_channel = NULL;
    if (!provider->vtable || !provider->vtable->open || !provider->vtable->open(provider_ctx,
                                                                                &open_args,
                                                                                &provider_callbacks,
                                                                                mount,
                                                                                &opened_channel)) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Transport provider failed to open channel",
                                            "transport/open_failed");
        return false;
    }

    mount->channel = opened_channel;
    mount->channel_open = (opened_channel != NULL);
    mount->backpressured = false;

    if (out_mount) {
        *out_mount = mount;
    }
    return true;
}

/* cep_fed_transport_manager_send forwards frames through the selected provider while
   enforcing upd_latest policy and coalescing behaviour so transports that advertise
   unreliable delivery only see the freshest gauge payload. */
bool cep_fed_transport_manager_send(cepFedTransportManager* manager,
                                    cepFedTransportManagerMount* mount,
                                    const uint8_t* payload,
                                    size_t payload_len,
                                    cepFedFrameMode mode,
                                    uint64_t deadline_beat) {
    if (!manager || !mount || !mount->provider || !mount->channel || !mount->provider->vtable || !payload || payload_len == 0u) {
        return false;
    }

    if (mode == CEP_FED_FRAME_MODE_UPD_LATEST && !mount->allow_upd_latest) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_warn_name(),
                                            "upd_latest frame rejected because mount does not opt in",
                                            "transport/upd_latest_denied");
        return false;
    }

    if (mode == CEP_FED_FRAME_MODE_UPD_LATEST && !mount->supports_upd_latest) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_warn_name(),
                                            "upd_latest frame sent to provider without unreliable support",
                                            "transport/upd_latest_misuse");
    }

    bool sent = true;

    if (mode == CEP_FED_FRAME_MODE_UPD_LATEST && mount->supports_upd_latest) {
        if (mount->backpressured) {
            uint8_t* snapshot = cep_malloc(payload_len);
            memcpy(snapshot, payload, payload_len);
            if (mount->pending_payload) {
                cep_free(mount->pending_payload);
            }
            mount->pending_payload = snapshot;
            mount->pending_len = payload_len;
            return true;
        }
        sent = mount->provider->vtable->send(mount->provider_ctx,
                                             mount->channel,
                                             payload,
                                             payload_len,
                                             mode,
                                             deadline_beat);
        if (!sent) {
            uint8_t* snapshot = cep_malloc(payload_len);
            memcpy(snapshot, payload, payload_len);
            if (mount->pending_payload) {
                cep_free(mount->pending_payload);
            }
            mount->pending_payload = snapshot;
            mount->pending_len = payload_len;
            mount->backpressured = true;
            cep_fed_transport_manager_emit_diag(manager,
                                                mount,
                                                dt_sev_warn_name(),
                                                "Transport send backpressured; caching upd_latest frame",
                                                "transport/backpressure");
            sent = true;
        }
    } else {
        sent = mount->provider->vtable->send(mount->provider_ctx,
                                             mount->channel,
                                             payload,
                                             payload_len,
                                             mode,
                                             deadline_beat);
        if (!sent) {
            cep_fed_transport_manager_emit_diag(manager,
                                                mount,
                                                dt_sev_error_name(),
                                                "Transport provider failed to send frame",
                                                "transport/send_failed");
        }
    }

    return sent;
}

/* cep_fed_transport_manager_request_receive bridges the provider's receive hook so
   mounts can ask for more input frames without touching the provider vtable directly. */
bool cep_fed_transport_manager_request_receive(cepFedTransportManager* manager,
                                               cepFedTransportManagerMount* mount) {
    if (!manager || !mount || !mount->provider || !mount->channel || !mount->provider->vtable || !mount->provider->vtable->request_receive) {
        return false;
    }
    return mount->provider->vtable->request_receive(mount->provider_ctx, mount->channel);
}

/* cep_fed_transport_manager_close closes the active provider channel while keeping the
   mount registration intact, letting callers re-open after policy changes. */
bool cep_fed_transport_manager_close(cepFedTransportManager* manager,
                                     cepFedTransportManagerMount* mount,
                                     const char* reason) {
    (void)manager;
    if (!mount) {
        return false;
    }
    if (mount->provider && mount->channel && mount->provider->vtable && mount->provider->vtable->close) {
        mount->provider->vtable->close(mount->provider_ctx, mount->channel, reason);
    }
    mount->channel = NULL;
    mount->channel_open = false;
    mount->backpressured = false;
    cep_fed_transport_manager_mount_reset_pending(mount);
    return true;
}

/* cep_fed_transport_manager_teardown releases all mount state and closes providers so
   tests and shutdown paths can tear down the manager without leaking dynamic memory. */
void cep_fed_transport_manager_teardown(cepFedTransportManager* manager) {
    if (!manager) {
        return;
    }
    for (size_t i = 0; i < manager->mount_count; ++i) {
        cep_fed_transport_manager_mount_detach(&manager->mounts[i]);
    }
    if (manager->mounts) {
        cep_free(manager->mounts);
        manager->mounts = NULL;
    }
    manager->mount_count = 0u;
    manager->mount_capacity = 0u;
    manager->mounts_root = NULL;
    manager->transports_root = NULL;
    manager->diagnostics_mailbox = NULL;
    manager->net_root = NULL;
}

/* cep_fed_transport_manager_mount_provider_id exposes the selected provider so tests
   can assert capability negotiation outcomes without peeking into internal state. */
const char* cep_fed_transport_manager_mount_provider_id(const cepFedTransportManagerMount* mount) {
    if (!mount) {
        return NULL;
    }
    return mount->provider_id;
}
