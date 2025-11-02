#include "fed_link_organ.h"

#include "fed_pack.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_namepool.h"

#include <string.h>

typedef struct cepFedLinkRequestCtx {
    cepCell*                          request_cell;
    cepFedTransportManagerMount*      mount;
    struct cepFedLinkRequestCtx*      next;
} cepFedLinkRequestCtx;

static cepFedTransportManager* g_link_manager = NULL;
static cepCell* g_link_net_root = NULL;
static cepFedLinkRequestCtx* g_link_requests = NULL;

CEP_DEFINE_STATIC_DT(dt_organs_name,           CEP_ACRO("CEP"), CEP_WORD("organs"));
CEP_DEFINE_STATIC_DT(dt_link_name,             CEP_ACRO("CEP"), CEP_WORD("link"));
CEP_DEFINE_STATIC_DT(dt_spec_name,             CEP_ACRO("CEP"), CEP_WORD("spec"));
CEP_DEFINE_STATIC_DT(dt_requests_name,         CEP_ACRO("CEP"), CEP_WORD("requests"));
CEP_DEFINE_STATIC_DT(dt_usage_name,            CEP_ACRO("CEP"), CEP_WORD("usage"));
CEP_DEFINE_STATIC_DT(dt_status_name,           CEP_ACRO("CEP"), CEP_WORD("status"));
CEP_DEFINE_STATIC_DT(dt_state_name,            CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_error_name,            CEP_ACRO("CEP"), CEP_WORD("error_note"));
CEP_DEFINE_STATIC_DT(dt_peer_field_name,       CEP_ACRO("CEP"), CEP_WORD("peer"));
CEP_DEFINE_STATIC_DT(dt_mount_field_name,      CEP_ACRO("CEP"), CEP_WORD("mount"));
CEP_DEFINE_STATIC_DT(dt_mode_field_name,       CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_local_node_field_name, CEP_ACRO("CEP"), CEP_WORD("local_node"));
CEP_DEFINE_STATIC_DT(dt_pref_provider,         CEP_ACRO("CEP"), CEP_WORD("pref_prov"));
CEP_DEFINE_STATIC_DT(dt_allow_upd,             CEP_ACRO("CEP"), CEP_WORD("allow_upd"));
CEP_DEFINE_STATIC_DT(dt_deadline_name,         CEP_ACRO("CEP"), CEP_WORD("deadline"));
CEP_DEFINE_STATIC_DT(dt_caps_name,             CEP_ACRO("CEP"), CEP_WORD("caps"));
CEP_DEFINE_STATIC_DT(dt_required_name,         CEP_ACRO("CEP"), CEP_WORD("required"));
CEP_DEFINE_STATIC_DT(dt_preferred_name,        CEP_ACRO("CEP"), CEP_WORD("preferred"));
CEP_DEFINE_STATIC_DT(dt_provider_field_name,   CEP_ACRO("CEP"), CEP_WORD("provider"));

CEP_DEFINE_STATIC_DT(dt_cap_reliable_name,     CEP_ACRO("CEP"), CEP_WORD("reliable"));
CEP_DEFINE_STATIC_DT(dt_cap_ordered_name,      CEP_ACRO("CEP"), CEP_WORD("ordered"));
CEP_DEFINE_STATIC_DT(dt_cap_streaming_name,    CEP_ACRO("CEP"), CEP_WORD("streaming"));
CEP_DEFINE_STATIC_DT(dt_cap_datagram_name,     CEP_ACRO("CEP"), CEP_WORD("datagram"));
CEP_DEFINE_STATIC_DT(dt_cap_multicast_name,    CEP_ACRO("CEP"), CEP_WORD("multicast"));
CEP_DEFINE_STATIC_DT(dt_cap_latency_name,      CEP_ACRO("CEP"), CEP_WORD("low_latency"));
CEP_DEFINE_STATIC_DT(dt_cap_local_ipc_name,    CEP_ACRO("CEP"), CEP_WORD("local_ipc"));
CEP_DEFINE_STATIC_DT(dt_cap_remote_net_name,   CEP_ACRO("CEP"), CEP_WORD("remote_net"));
CEP_DEFINE_STATIC_DT(dt_cap_unreliable_name,   CEP_ACRO("CEP"), CEP_WORD("unreliable"));

static const struct {
    const cepDT* (*dt)(void);
    cepFedTransportCaps flag;
} cep_fed_link_cap_table[] = {
    { dt_cap_reliable_name,   CEP_FED_TRANSPORT_CAP_RELIABLE    },
    { dt_cap_ordered_name,    CEP_FED_TRANSPORT_CAP_ORDERED     },
    { dt_cap_streaming_name,  CEP_FED_TRANSPORT_CAP_STREAMING   },
    { dt_cap_datagram_name,   CEP_FED_TRANSPORT_CAP_DATAGRAM    },
    { dt_cap_multicast_name,  CEP_FED_TRANSPORT_CAP_MULTICAST   },
    { dt_cap_latency_name,    CEP_FED_TRANSPORT_CAP_LOW_LATENCY },
    { dt_cap_local_ipc_name,  CEP_FED_TRANSPORT_CAP_LOCAL_IPC   },
    { dt_cap_remote_net_name, CEP_FED_TRANSPORT_CAP_REMOTE_NET  },
    { dt_cap_unreliable_name, CEP_FED_TRANSPORT_CAP_UNRELIABLE  },
};

static cepFedLinkRequestCtx* cep_fed_link_find_ctx(cepCell* request_cell) {
    for (cepFedLinkRequestCtx* node = g_link_requests; node; node = node->next) {
        if (node->request_cell == request_cell) {
            return node;
        }
    }
    return NULL;
}

static void cep_fed_link_remove_ctx(cepCell* request_cell) {
    cepFedLinkRequestCtx** cursor = &g_link_requests;
    while (*cursor) {
        if ((*cursor)->request_cell == request_cell) {
            cepFedLinkRequestCtx* victim = *cursor;
            *cursor = victim->next;
            cep_free(victim);
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static cepCell* cep_fed_link_resolve_request(const cepPath* target_path) {
    if (!target_path) {
        return NULL;
    }
    cepCell* current = cep_root();
    current = current ? cep_cell_resolve(current) : NULL;
    if (!current) {
        return NULL;
    }

    unsigned start_index = 0u;
    if (target_path->length > 0u) {
        const cepDT* first = &target_path->past[0].dt;
        if (first && cep_dt_compare(first, &current->metacell.dt) == 0) {
            start_index = 1u;
        }
    }

    for (unsigned i = start_index; i < target_path->length; ++i) {
        const cepDT* segment = &target_path->past[i].dt;
        cepCell* child = cep_cell_find_by_name(current, segment);
        if (!child) {
            bool metadata_segment = false;
            if (cep_cell_is_normal(current)) {
                if (cep_cell_has_store(current) && current->store) {
                    if (cep_dt_compare(segment, &current->store->dt) == 0) {
                        metadata_segment = true;
                    }
                }
                if (!metadata_segment && cep_cell_has_data(current) && current->data) {
                    if (cep_dt_compare(segment, &current->data->dt) == 0) {
                        metadata_segment = true;
                    }
                }
            }
            if (metadata_segment) {
                continue;
            }
            return NULL;
        }
        child = cep_cell_resolve(child);
        if (!child) {
            return NULL;
        }
        current = child;
    }
    return current;
}

static bool cep_fed_link_read_text(cepCell* parent,
                                   const cepDT* field,
                                   bool required,
                                   char* buffer,
                                   size_t capacity) {
    if (!parent || !field || !buffer || capacity == 0u) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return !required;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&node, &data)) {
        return false;
    }
    cepDT expected = cep_ops_make_dt("val/text");
    if (cep_dt_compare(&data->dt, &expected) != 0) {
        const cepDT* alt_text = CEP_DTAW("CEP", "text");
        if (!alt_text || cep_dt_compare(&data->dt, alt_text) != 0) {
            return false;
        }
    }
    size_t length = data->size;
    if (length >= capacity) {
        length = capacity - 1u;
    }
    const void* payload = cep_data_payload(data);
    if (length > 0u && payload) {
        memcpy(buffer, payload, length);
    }
    buffer[length] = '\0';
    return true;
}

static bool cep_fed_link_read_bool(cepCell* parent,
                                   const cepDT* field,
                                   bool* out_value) {
    if (!parent || !field || !out_value) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&node, &data)) {
        return false;
    }
    cepDT expected = cep_ops_make_dt("val/bool");
    if (cep_dt_compare(&data->dt, &expected) != 0 || data->size != sizeof(uint8_t)) {
        return false;
    }
    const uint8_t* payload = (const uint8_t*)cep_data_payload(data);
    if (!payload) {
        return false;
    }
    *out_value = (*payload != 0u);
    return true;
}

static cepFedTransportCaps cep_fed_link_read_cap_flags(cepCell* caps_dict) {
    cepFedTransportCaps caps = 0u;
    if (!caps_dict) {
        return caps;
    }
    if (!cep_cell_require_dictionary_store(&caps_dict)) {
        return caps;
    }
    for (size_t i = 0; i < cep_lengthof(cep_fed_link_cap_table); ++i) {
        cepCell* node = cep_cell_find_by_name(caps_dict, cep_fed_link_cap_table[i].dt());
        if (!node) {
            continue;
        }
        node = cep_cell_resolve(node);
        if (!node || !node->data) {
            continue;
        }
        cepData* data = node->data;
        cepDT expected = cep_ops_make_dt("val/bool");
        if (cep_dt_compare(&data->dt, &expected) != 0 || data->size != sizeof(uint8_t)) {
            continue;
        }
        const uint8_t* payload = (const uint8_t*)cep_data_payload(data);
        bool enabled = payload && (*payload != 0u);
        if (enabled) {
            caps |= cep_fed_link_cap_table[i].flag;
        }
    }
    return caps;
}

static void cep_fed_link_publish_state(cepCell* request_cell,
                                       const char* state,
                                       const char* error_note,
                                       const char* provider) {
    if (!request_cell || !cep_cell_require_dictionary_store(&request_cell)) {
        return;
    }
    if (state) {
        (void)cep_cell_put_text(request_cell, dt_state_name(), state);
    }
    if (error_note) {
        (void)cep_cell_put_text(request_cell, dt_error_name(), error_note);
    } else {
        (void)cep_cell_put_text(request_cell, dt_error_name(), "");
    }
    if (provider) {
        (void)cep_cell_put_text(request_cell, dt_provider_field_name(), provider);
    }
}

static bool cep_fed_link_parse_caps(cepCell* request_cell,
                                    cepFedTransportCaps* required,
                                    cepFedTransportCaps* preferred) {
    *required = CEP_FED_TRANSPORT_CAP_RELIABLE | CEP_FED_TRANSPORT_CAP_ORDERED;
    *preferred = 0u;
    cepCell* caps = cep_cell_find_by_name(request_cell, dt_caps_name());
    if (!caps) {
        return true;
    }
    caps = cep_cell_resolve(caps);
    if (!caps || !cep_cell_require_dictionary_store(&caps)) {
        return false;
    }
    cepCell* required_caps = cep_cell_find_by_name(caps, dt_required_name());
    if (required_caps) {
        required_caps = cep_cell_resolve(required_caps);
        if (!required_caps || !cep_cell_require_dictionary_store(&required_caps)) {
            return false;
        }
        cepFedTransportCaps flags = cep_fed_link_read_cap_flags(required_caps);
        if (flags != 0u) {
            *required = flags;
        }
    }
    cepCell* preferred_caps = cep_cell_find_by_name(caps, dt_preferred_name());
    if (preferred_caps) {
        preferred_caps = cep_cell_resolve(preferred_caps);
        if (!preferred_caps || !cep_cell_require_dictionary_store(&preferred_caps)) {
            return false;
        }
        *preferred = cep_fed_link_read_cap_flags(preferred_caps);
    }
    return true;
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

bool cep_fed_link_organ_init(cepFedTransportManager* manager,
                             cepCell* net_root) {
    if (!manager || !net_root) {
        return false;
    }

    g_link_manager = manager;
    g_link_net_root = cep_cell_resolve(net_root);
    if (!g_link_net_root || !cep_cell_require_dictionary_store(&g_link_net_root)) {
        g_link_net_root = NULL;
        return false;
    }

    cepCell* organs = cep_cell_find_by_name(g_link_net_root, dt_organs_name());
    if (!organs) {
        organs = cep_cell_ensure_dictionary_child(g_link_net_root,
                                                  dt_organs_name(),
                                                  CEP_STORAGE_RED_BLACK_T);
    }
    organs = cep_cell_resolve(organs);
    if (!organs || !cep_cell_require_dictionary_store(&organs)) {
        return false;
    }

    cepCell* link_root = cep_cell_find_by_name(organs, dt_link_name());
    if (!link_root) {
        link_root = cep_cell_ensure_dictionary_child(organs,
                                                     dt_link_name(),
                                                     CEP_STORAGE_RED_BLACK_T);
    }
    link_root = cep_cell_resolve(link_root);
    if (!link_root || !cep_cell_require_dictionary_store(&link_root)) {
        return false;
    }

    cepCell* spec = cep_cell_find_by_name(link_root, dt_spec_name());
    if (!spec) {
        spec = cep_cell_ensure_dictionary_child(link_root,
                                                dt_spec_name(),
                                                CEP_STORAGE_RED_BLACK_T);
    }
    spec = cep_cell_resolve(spec);
    if (!spec || !cep_cell_require_dictionary_store(&spec)) {
        return false;
    }

    (void)cep_cell_put_text(spec, dt_usage_name(),
                             "Create requests under /net/organs/link/requests to "
                             "bind federation transport mounts.");
    (void)cep_cell_put_text(spec, dt_status_name(),
                             "Validator ensures request schema and invokes the "
                             "federation transport manager. State and provider fields "
                             "reflect the latest outcome.");

    cepCell* requests = cep_cell_find_by_name(link_root, dt_requests_name());
    if (!requests) {
        requests = cep_cell_ensure_dictionary_child(link_root,
                                                    dt_requests_name(),
                                                    CEP_STORAGE_RED_BLACK_T);
    }
    if (!requests) {
        return false;
    }
    requests = cep_cell_resolve(requests);
    if (!requests || !cep_cell_require_dictionary_store(&requests)) {
        return false;
    }

    return true;
}

bool cep_fed_link_mount_apply(const cepFedTransportMountConfig* config,
                              const cepFedTransportMountCallbacks* callbacks,
                              cepFedTransportManagerMount** out_mount) {
    if (!g_link_manager) {
        g_link_manager = cep_fed_pack_manager();
    }
    if (!g_link_manager || !config) {
        return false;
    }
    return cep_fed_transport_manager_configure_mount(g_link_manager,
                                                     config,
                                                     callbacks,
                                                     out_mount);
}

bool cep_fed_link_mount_release(cepFedTransportManagerMount* mount,
                                const char* reason) {
    if (!g_link_manager) {
        g_link_manager = cep_fed_pack_manager();
    }
    if (!g_link_manager || !mount) {
        return false;
    }
    return cep_fed_transport_manager_close(g_link_manager,
                                           mount,
                                           reason ? reason : "link-release");
}

/* ------------------------------------------------------------------------- */
/* Organ callbacks                                                           */
/* ------------------------------------------------------------------------- */

int cep_fed_link_validator(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request_cell = cep_fed_link_resolve_request(target_path);
    if (!request_cell) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_cell_require_dictionary_store(&request_cell)) {
        cep_fed_link_publish_state(request_cell, "error", "link request is not a dictionary", NULL);
        return CEP_ENZYME_FATAL;
    }

    char peer[64] = {0};
    char mount[64] = {0};
    char mode[32] = {0};
    char local_node[64] = {0};
    char preferred_provider[64] = {0};
    bool allow_upd_latest = false;
    uint64_t deadline = 0u;

    if (!cep_fed_link_read_text(request_cell, dt_peer_field_name(), true, peer, sizeof peer) ||
        !cep_fed_link_read_text(request_cell, dt_mount_field_name(), true, mount, sizeof mount) ||
        !cep_fed_link_read_text(request_cell, dt_mode_field_name(), true, mode, sizeof mode) ||
        !cep_fed_link_read_text(request_cell, dt_local_node_field_name(), true, local_node, sizeof local_node)) {
        cep_fed_link_publish_state(request_cell, "error", "missing required fields", NULL);
        return CEP_ENZYME_FATAL;
    }

    (void)cep_fed_link_read_text(request_cell, dt_pref_provider(), false, preferred_provider, sizeof preferred_provider);
    (void)cep_fed_link_read_bool(request_cell, dt_allow_upd(), &allow_upd_latest);

    cepCell* deadline_node = cep_cell_find_by_name(request_cell, dt_deadline_name());
    if (deadline_node) {
        deadline_node = cep_cell_resolve(deadline_node);
        if (deadline_node && deadline_node->data) {
            cepData* data = deadline_node->data;
            cepDT expected = cep_ops_make_dt("val/u64");
            if (cep_dt_compare(&data->dt, &expected) == 0 && data->size == sizeof(uint64_t)) {
                const uint64_t* payload = (const uint64_t*)cep_data_payload(data);
                if (payload) {
                    deadline = *payload;
                }
            }
        }
    }

    cepFedTransportCaps required_caps = 0u;
    cepFedTransportCaps preferred_caps = 0u;
    if (!cep_fed_link_parse_caps(request_cell, &required_caps, &preferred_caps)) {
        cep_fed_link_publish_state(request_cell, "error", "invalid capability dictionary", NULL);
        return CEP_ENZYME_FATAL;
    }

    cepFedTransportMountConfig cfg = {
        .peer_id = peer,
        .mount_id = mount,
        .mount_mode = mode,
        .local_node_id = local_node,
        .preferred_provider_id = preferred_provider[0] ? preferred_provider : NULL,
        .required_caps = required_caps,
        .preferred_caps = preferred_caps,
        .allow_upd_latest = allow_upd_latest,
        .deadline_beat = deadline,
    };

    cepFedLinkRequestCtx* ctx = cep_fed_link_find_ctx(request_cell);
    if (ctx && ctx->mount) {
        (void)cep_fed_link_mount_release(ctx->mount, "link-reconfigure");
        ctx->mount = NULL;
    }

    cepFedTransportManagerMount* new_mount = NULL;
    if (!cep_fed_link_mount_apply(&cfg, NULL, &new_mount)) {
        cep_fed_link_publish_state(request_cell, "error", "transport manager rejected configuration", NULL);
        return CEP_ENZYME_FATAL;
    }

    if (!ctx) {
        ctx = cep_malloc0(sizeof *ctx);
        ctx->request_cell = request_cell;
        ctx->next = g_link_requests;
        g_link_requests = ctx;
    }
    ctx->mount = new_mount;

    const char* provider_id = cep_fed_transport_manager_mount_provider_id(new_mount);
    cep_fed_link_publish_state(request_cell, "active", NULL, provider_id);
    return CEP_ENZYME_SUCCESS;
}

int cep_fed_link_destructor(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request_cell = cep_fed_link_resolve_request(target_path);
    if (!request_cell) {
        return CEP_ENZYME_SUCCESS;
    }

    cepFedLinkRequestCtx* ctx = cep_fed_link_find_ctx(request_cell);
    if (ctx && ctx->mount) {
        (void)cep_fed_link_mount_release(ctx->mount, "link-request-destroy");
        ctx->mount = NULL;
    }
    cep_fed_link_publish_state(request_cell, "removed", NULL, NULL);
    cep_fed_link_remove_ctx(request_cell);
    return CEP_ENZYME_SUCCESS;
}
