/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "fed_mirror_organ.h"

#include "fed_pack.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_cei.h"
#include "../l0_kernel/cep_ep.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_runtime.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    CEP_FED_MIRROR_COMMIT_STREAM = 0,
    CEP_FED_MIRROR_COMMIT_BATCH,
    CEP_FED_MIRROR_COMMIT_MANUAL,
} cepFedMirrorCommitMode;

typedef struct cepFedMirrorRequestCtx {
    cepCell*                         request_cell;
    cepFedTransportManagerMount*     mount;
    cepEID                           episode;
    cepPath*                         request_path;
    cepRuntime*                      runtime;
    char                             peer[64];
    char                             mount_id[64];
    char                             mode[32];
    char                             local_node[64];
    char                             source_peer[64];
    char                             source_channel[64];
    char                             provider_id[64];
    char                             resume_token[96];
    cepFedMirrorCommitMode           commit_mode;
    cepFedTransportCaps              required_caps;
    cepFedTransportCaps              preferred_caps;
    bool                             allow_upd_latest;
    uint32_t                         beat_window;
    uint16_t                         max_inflight;
    uint32_t                         beats_accum;
    uint16_t                         inflight;
    uint64_t                         bundle_seq;
    uint64_t                         last_commit_beat;
    uint64_t                         deadline;
    bool                             has_deadline;
    bool                             lease_armed;
    struct cepFedMirrorRequestCtx*   next;
} cepFedMirrorRequestCtx;

static cepFedTransportManager* g_mirror_manager = NULL;
static cepCell* g_mirror_net_root = NULL;
static cepFedMirrorRequestCtx* g_mirror_requests = NULL;

CEP_DEFINE_STATIC_DT(dt_organs_name,             CEP_ACRO("CEP"), CEP_WORD("organs"));
CEP_DEFINE_STATIC_DT(dt_mirror_name,             CEP_ACRO("CEP"), CEP_WORD("mirror"));
CEP_DEFINE_STATIC_DT(dt_spec_name,               CEP_ACRO("CEP"), CEP_WORD("spec"));
CEP_DEFINE_STATIC_DT(dt_usage_name,              CEP_ACRO("CEP"), CEP_WORD("usage"));
CEP_DEFINE_STATIC_DT(dt_status_name,             CEP_ACRO("CEP"), CEP_WORD("status"));
CEP_DEFINE_STATIC_DT(dt_requests_name,           CEP_ACRO("CEP"), CEP_WORD("requests"));
CEP_DEFINE_STATIC_DT(dt_state_name,              CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_error_name,              CEP_ACRO("CEP"), CEP_WORD("error_note"));
CEP_DEFINE_STATIC_DT(dt_provider_field_name,     CEP_ACRO("CEP"), CEP_WORD("provider"));
CEP_DEFINE_STATIC_DT(dt_peer_field_name,         CEP_ACRO("CEP"), CEP_WORD("peer"));
CEP_DEFINE_STATIC_DT(dt_mount_field_name,        CEP_ACRO("CEP"), CEP_WORD("mount"));
CEP_DEFINE_STATIC_DT(dt_mode_field_name,         CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_local_node_field_name,   CEP_ACRO("CEP"), CEP_WORD("local_node"));
CEP_DEFINE_STATIC_DT(dt_source_peer_field_name,  CEP_ACRO("CEP"), CEP_WORD("src_peer"));
CEP_DEFINE_STATIC_DT(dt_source_channel_field_name, CEP_ACRO("CEP"), CEP_WORD("src_chan"));
CEP_DEFINE_STATIC_DT(dt_pref_provider,           CEP_ACRO("CEP"), CEP_WORD("pref_prov"));
CEP_DEFINE_STATIC_DT(dt_allow_upd,               CEP_ACRO("CEP"), CEP_WORD("allow_upd"));
CEP_DEFINE_STATIC_DT(dt_deadline_name,           CEP_ACRO("CEP"), CEP_WORD("deadline"));
CEP_DEFINE_STATIC_DT(dt_caps_name,               CEP_ACRO("CEP"), CEP_WORD("caps"));
CEP_DEFINE_STATIC_DT(dt_required_name,           CEP_ACRO("CEP"), CEP_WORD("required"));
CEP_DEFINE_STATIC_DT(dt_preferred_name,          CEP_ACRO("CEP"), CEP_WORD("preferred"));
CEP_DEFINE_STATIC_DT(dt_bundle_name,             CEP_ACRO("CEP"), CEP_WORD("bundle"));
CEP_DEFINE_STATIC_DT(dt_beat_window_name,        CEP_ACRO("CEP"), CEP_WORD("beat_window"));
CEP_DEFINE_STATIC_DT(dt_max_inflight_name,       CEP_ACRO("CEP"), CEP_WORD("max_infl"));
CEP_DEFINE_STATIC_DT(dt_commit_mode_name,        CEP_ACRO("CEP"), CEP_WORD("commit_mode"));
CEP_DEFINE_STATIC_DT(dt_resume_token_name,       CEP_ACRO("CEP"), CEP_WORD("resume_tok"));
CEP_DEFINE_STATIC_DT(dt_bundle_hist_cap_name, CEP_ACRO("CEP"), CEP_WORD("hist_cap"));
CEP_DEFINE_STATIC_DT(dt_bundle_delta_cap_name, CEP_ACRO("CEP"), CEP_WORD("delta_cap"));
CEP_DEFINE_STATIC_DT(dt_pending_resume_name,     CEP_ACRO("CEP"), CEP_WORD("pend_resum"));
CEP_DEFINE_STATIC_DT(dt_last_bundle_seq_name,    CEP_ACRO("CEP"), CEP_WORD("bundle_seq"));
CEP_DEFINE_STATIC_DT(dt_last_commit_beat_name,   CEP_ACRO("CEP"), CEP_WORD("commit_beat"));
CEP_DEFINE_STATIC_DT(dt_sev_error_name,          CEP_ACRO("sev"), CEP_WORD("error"));

CEP_DEFINE_STATIC_DT(dt_cap_reliable_name,       CEP_ACRO("CEP"), CEP_WORD("reliable"));
CEP_DEFINE_STATIC_DT(dt_cap_ordered_name,        CEP_ACRO("CEP"), CEP_WORD("ordered"));
CEP_DEFINE_STATIC_DT(dt_cap_streaming_name,      CEP_ACRO("CEP"), CEP_WORD("streaming"));
CEP_DEFINE_STATIC_DT(dt_cap_datagram_name,       CEP_ACRO("CEP"), CEP_WORD("datagram"));
CEP_DEFINE_STATIC_DT(dt_cap_multicast_name,      CEP_ACRO("CEP"), CEP_WORD("multicast"));
CEP_DEFINE_STATIC_DT(dt_cap_latency_name,        CEP_ACRO("CEP"), CEP_WORD("low_latency"));
CEP_DEFINE_STATIC_DT(dt_cap_local_ipc_name,      CEP_ACRO("CEP"), CEP_WORD("local_ipc"));
CEP_DEFINE_STATIC_DT(dt_cap_remote_net_name,     CEP_ACRO("CEP"), CEP_WORD("remote_net"));
CEP_DEFINE_STATIC_DT(dt_cap_unreliable_name,     CEP_ACRO("CEP"), CEP_WORD("unreliable"));

static const struct {
    const cepDT* (*dt)(void);
    cepFedTransportCaps flag;
} cep_fed_mirror_cap_table[] = {
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

static const char* const CEP_FED_MIRROR_TOPIC_CONFLICT = "tp_mconf";
static const char* const CEP_FED_MIRROR_TOPIC_TIMEOUT  = "tp_mtimeout";
static const char* const CEP_FED_MIRROR_TOPIC_SCHEMA   = "tp_schema";

static cepFedMirrorRequestCtx* cep_fed_mirror_find_ctx(cepCell* request_cell) {
    for (cepFedMirrorRequestCtx* node = g_mirror_requests; node; node = node->next) {
        if (node->request_cell == request_cell) {
            return node;
        }
    }
    return NULL;
}

static void cep_fed_mirror_remove_ctx(cepCell* request_cell) {
    cepFedMirrorRequestCtx** cursor = &g_mirror_requests;
    while (*cursor) {
        if ((*cursor)->request_cell == request_cell) {
            cepFedMirrorRequestCtx* victim = *cursor;
            *cursor = victim->next;
            if (victim->request_path) {
                cep_free(victim->request_path);
            }
            cep_free(victim);
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static cepCell* cep_fed_mirror_resolve_request(const cepPath* target_path) {
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

static bool cep_fed_mirror_read_text(cepCell* parent,
                                     const cepDT* field,
                                     bool required,
                                     char* buffer,
                                     size_t capacity) {
    if (!parent || !field || !buffer || capacity == 0u) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        if (!required) {
            buffer[0] = '\0';
            return true;
        }
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

static bool cep_fed_mirror_read_bool(cepCell* parent,
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

static bool cep_fed_mirror_read_u32(cepCell* parent,
                                    const cepDT* field,
                                    bool required,
                                    uint32_t* out_value) {
    if (!parent || !field || !out_value) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        if (!required) {
            return true;
        }
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
    cepDT expected = cep_ops_make_dt("val/u32");
    if (cep_dt_compare(&data->dt, &expected) != 0 || data->size != sizeof(uint32_t)) {
        return false;
    }
    const uint32_t* payload = (const uint32_t*)cep_data_payload(data);
    if (!payload) {
        return false;
    }
    *out_value = *payload;
    return true;
}

static bool cep_fed_mirror_read_u16(cepCell* parent,
                                    const cepDT* field,
                                    bool required,
                                    uint16_t* out_value) {
    if (!parent || !field || !out_value) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        if (!required) {
            return true;
        }
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
    cepDT expected = cep_ops_make_dt("val/u16");
    if (cep_dt_compare(&data->dt, &expected) != 0 || data->size != sizeof(uint16_t)) {
        return false;
    }
    const uint16_t* payload = (const uint16_t*)cep_data_payload(data);
    if (!payload) {
        return false;
    }
    *out_value = *payload;
    return true;
}

static cepFedTransportCaps cep_fed_mirror_read_cap_flags(cepCell* caps_dict) {
    cepFedTransportCaps caps = 0u;
    if (!caps_dict) {
        return caps;
    }
    if (!cep_cell_require_dictionary_store(&caps_dict)) {
        return caps;
    }
    for (size_t i = 0; i < cep_lengthof(cep_fed_mirror_cap_table); ++i) {
        cepCell* node = cep_cell_find_by_name(caps_dict, cep_fed_mirror_cap_table[i].dt());
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
            caps |= cep_fed_mirror_cap_table[i].flag;
        }
    }
    return caps;
}

static bool cep_fed_mirror_parse_caps(cepCell* request_cell,
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
        cepFedTransportCaps flags = cep_fed_mirror_read_cap_flags(required_caps);
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
        *preferred = cep_fed_mirror_read_cap_flags(preferred_caps);
    }
    return true;
}

static void cep_fed_mirror_emit_issue(cepCell* request_cell,
                                      const char* topic,
                                      const char* note) {
    if (!topic || !note) {
        return;
    }
    cepCell* subject = request_cell ? cep_cell_resolve(request_cell) : NULL;
    cepCeiRequest req = {0};
    req.severity = *dt_sev_error_name();
    req.note = note;
    req.topic = topic;
    req.topic_intern = true;
    req.subject = subject;
    req.mailbox_root = cep_cei_diagnostics_mailbox();
    req.emit_signal = true;
    req.attach_to_op = false;
    req.ttl_forever = false;
    (void)cep_cei_emit(&req);
}

static void cep_fed_mirror_publish_state(cepCell* request_cell,
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

static bool cep_fed_mirror_write_u64(cepCell* parent,
                                     const cepDT* field,
                                     uint64_t value) {
    if (!parent || !field) {
        return false;
    }
    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(resolved, field);
    if (existing) {
        return cep_cell_update(existing, sizeof value, sizeof value, &value, false) != NULL;
    }

    cepDT field_copy = *field;
    cepDT type_dt = cep_ops_make_dt("val/u64");
    return cep_dict_add_value(resolved, &field_copy, &type_dt, &value, sizeof value, sizeof value) != NULL;
}

static uint64_t cep_fed_mirror_read_deadline(cepCell* request_cell) {
    if (!request_cell) {
        return 0u;
    }
    cepCell* resolved = cep_cell_resolve(request_cell);
    if (!resolved) {
        return 0u;
    }
    cepCell* deadline_node = cep_cell_find_by_name(resolved, dt_deadline_name());
    if (!deadline_node) {
        return 0u;
    }
    deadline_node = cep_cell_resolve(deadline_node);
    if (!deadline_node) {
        return 0u;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&deadline_node, &data)) {
        return 0u;
    }
    cepDT expected = cep_ops_make_dt("val/u64");
    if (cep_dt_compare(&data->dt, &expected) != 0 || data->size != sizeof(uint64_t)) {
        return 0u;
    }
    const uint64_t* payload = (const uint64_t*)cep_data_payload(data);
    return payload ? *payload : 0u;
}

static void cep_fed_mirror_publish_progress(cepFedMirrorRequestCtx* ctx) {
    if (!ctx || !ctx->request_cell) {
        return;
    }
    cepCell* request = cep_cell_resolve(ctx->request_cell);
    if (!request || !cep_cell_require_dictionary_store(&request)) {
        return;
    }
    (void)cep_fed_mirror_write_u64(request, dt_last_bundle_seq_name(), ctx->bundle_seq);
    (void)cep_fed_mirror_write_u64(request, dt_last_commit_beat_name(), ctx->last_commit_beat);
    if (ctx->commit_mode == CEP_FED_MIRROR_COMMIT_MANUAL) {
        (void)cep_cell_put_text(request,
                                dt_pending_resume_name(),
                                ctx->resume_token);
    } else {
        (void)cep_cell_put_text(request, dt_pending_resume_name(), "");
    }
}

static void cep_fed_mirror_cancel_episode(cepFedMirrorRequestCtx* ctx,
                                          const char* note) {
    if (!ctx) {
        return;
    }
    if (cep_oid_is_valid(ctx->episode)) {
        (void)cep_ep_cancel(ctx->episode, -3, note ? note : "mirror-stop");
        ctx->episode = cep_oid_invalid();
    }
    ctx->lease_armed = false;
}

static void cep_fed_mirror_release_mount(cepFedMirrorRequestCtx* ctx,
                                         const char* reason) {
    if (!ctx || !ctx->mount) {
        return;
    }
    if (!g_mirror_manager) {
        g_mirror_manager = cep_fed_pack_manager();
    }
    if (g_mirror_manager) {
        (void)cep_fed_transport_manager_close(g_mirror_manager,
                                              ctx->mount,
                                              reason ? reason : "mirror-release");
    }
    ctx->mount = NULL;
    ctx->provider_id[0] = '\0';
}

static bool cep_fed_mirror_make_signal_path(cepPath** out_path) {
    if (!out_path) {
        return false;
    }
    cepPath* path = cep_malloc(sizeof *path + sizeof(cepPast));
    if (!path) {
        return false;
    }
    memset(path, 0, sizeof *path + sizeof(cepPast));
    path->length = 1u;
    path->capacity = 1u;
    path->past[0].dt = cep_ops_make_dt("org:net_mirror:vl");
    path->past[0].timestamp = 0u;
    *out_path = path;
    return true;
}

static bool cep_fed_mirror_request_lease(cepFedMirrorRequestCtx* ctx, cepEID eid) {
    if (!ctx || !ctx->request_path) {
        return false;
    }
    if (cep_ep_request_lease(eid,
                             ctx->request_path,
                             false,
                             true,
                             true)) {
        return true;
    }

    cepCell* resolved = ctx->request_cell ? cep_cell_resolve(ctx->request_cell) : NULL;
    cepPath* regenerated = NULL;
    if (resolved && cep_cell_path(resolved, &regenerated)) {
        bool ok = cep_ep_request_lease(eid,
                                       regenerated,
                                       false,
                                       true,
                                       true);
        cep_free(regenerated);
        if (ok) {
            return true;
        }
    }

    ctx->lease_armed = true; /* best-effort: continue without explicit lease */
    return true;
}

static bool cep_fed_mirror_on_frame(void* user_ctx,
                                    cepFedTransportManagerMount* mount,
                                    const uint8_t* payload,
                                    size_t payload_len,
                                    cepFedFrameMode mode) {
    (void)mount;
    (void)payload;
    (void)payload_len;
    (void)mode;
    cepFedMirrorRequestCtx* ctx = user_ctx;
    if (!ctx) {
        return false;
    }
    if (ctx->inflight < ctx->max_inflight) {
        ++ctx->inflight;
    }
    return true;
}

static void cep_fed_mirror_on_event(void* user_ctx,
                                    cepFedTransportManagerMount* mount,
                                    cepFedTransportEventKind kind,
                                    const char* detail) {
    (void)mount;
    cepFedMirrorRequestCtx* ctx = user_ctx;
    if (!ctx || kind != CEP_FED_TRANSPORT_EVENT_FATAL) {
        return;
    }
    cep_fed_mirror_emit_issue(ctx->request_cell,
                              CEP_FED_MIRROR_TOPIC_SCHEMA,
                              detail ? detail : "mirror mount fatal event");
    cep_fed_mirror_publish_state(ctx->request_cell, "error", detail, NULL);
}

static void cep_fed_mirror_episode_slice(cepEID eid, void* user_ctx) {
    cepFedMirrorRequestCtx* ctx = user_ctx;
    if (!ctx || !ctx->request_cell) {
        cepDT fail = cep_ops_make_dt("sts:fail");
        (void)cep_ep_close(eid, fail, NULL, 0u);
    if (ctx) {
        cep_fed_mirror_release_mount(ctx, "mirror-episode-missing");
        ctx->episode = cep_oid_invalid();
    }
        return;
    }

    if (!ctx->lease_armed) {
        if (!cep_fed_mirror_request_lease(ctx, eid)) {
            cepDT fail = cep_ops_make_dt("sts:fail");
            (void)cep_ep_close(eid, fail, NULL, 0u);
            cep_fed_mirror_release_mount(ctx, "mirror-lease-failed");
            ctx->episode = cep_oid_invalid();
            return;
        }
        ctx->lease_armed = true;
    }

    cepCell* request = cep_cell_resolve(ctx->request_cell);
    if (!request || !cep_cell_require_dictionary_store(&request)) {
        cepDT fail = cep_ops_make_dt("sts:fail");
        (void)cep_ep_close(eid, fail, NULL, 0u);
        cep_fed_mirror_release_mount(ctx, "mirror-request-missing");
        ctx->episode = cep_oid_invalid();
        return;
    }

    cepBeatNumber beat = cep_heartbeat_current();
    uint64_t deadline_limit = ctx->has_deadline
        ? cep_fed_mirror_read_deadline(ctx->request_cell)
        : 0u;
    if (deadline_limit != 0u) {
        ctx->deadline = deadline_limit;
        ctx->has_deadline = true;
    }
    if (deadline_limit != 0u && beat > deadline_limit) {
        cep_fed_mirror_emit_issue(request,
                                  CEP_FED_MIRROR_TOPIC_TIMEOUT,
                                  "mirror request deadline expired");
        cep_fed_mirror_publish_state(request, "error", "deadline expired", NULL);
        cep_fed_mirror_release_mount(ctx, "mirror-deadline");
        cepDT fail = cep_ops_make_dt("sts:fail");
        (void)cep_ep_close(eid, fail, NULL, 0u);
        ctx->episode = cep_oid_invalid();
        return;
    }

    ctx->beats_accum += 1u;
    if (ctx->beats_accum >= ctx->beat_window) {
        ctx->beats_accum = 0u;
        ctx->bundle_seq += 1u;
        ctx->last_commit_beat = (uint64_t)beat;
        if (ctx->commit_mode == CEP_FED_MIRROR_COMMIT_MANUAL) {
            (void)snprintf(ctx->resume_token,
                           sizeof ctx->resume_token,
                           "resume-%" PRIu64,
                           ctx->bundle_seq);
        } else {
            ctx->resume_token[0] = '\0';
        }
        if (ctx->inflight > 0u) {
            --ctx->inflight;
        }
        cep_fed_mirror_publish_progress(ctx);
    }

    if (!cep_ep_yield(eid, "mirror-beat")) {
        cepDT fail = cep_ops_make_dt("sts:fail");
        (void)cep_ep_close(eid, fail, NULL, 0u);
        cep_fed_mirror_release_mount(ctx, "mirror-yield-failed");
        ctx->episode = cep_oid_invalid();
    } else {
        ctx->episode = eid;
    }
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

/* Initialise the mirror-mode organ roots so validators and episodic helpers
   can locate `/net/organs/mirror/requests` along with the spec metadata that
   describes the request contract. The routine caches the shared transport
   manager/net root pointers so subsequent validators can reuse them directly. */
bool cep_fed_mirror_organ_init(cepFedTransportManager* manager,
                               cepCell* net_root) {
    if (!manager || !net_root) {
        return false;
    }

    g_mirror_manager = manager;
    g_mirror_net_root = net_root;

    cepCell* resolved_root = cep_cell_resolve(net_root);
    if (!resolved_root || !cep_cell_require_dictionary_store(&resolved_root)) {
        return false;
    }

    cepCell* organs = cep_cell_find_by_name(resolved_root, dt_organs_name());
    if (!organs) {
        organs = cep_cell_ensure_dictionary_child(resolved_root,
                                                  dt_organs_name(),
                                                  CEP_STORAGE_RED_BLACK_T);
    }
    organs = cep_cell_resolve(organs);
    if (!organs || !cep_cell_require_dictionary_store(&organs)) {
        return false;
    }

    cepCell* mirror_root = cep_cell_find_by_name(organs, dt_mirror_name());
    if (!mirror_root) {
        mirror_root = cep_cell_ensure_dictionary_child(organs,
                                                       dt_mirror_name(),
                                                       CEP_STORAGE_RED_BLACK_T);
    }
    mirror_root = cep_cell_resolve(mirror_root);
    if (!mirror_root || !cep_cell_require_dictionary_store(&mirror_root)) {
        return false;
    }

    cepCell* spec = cep_cell_find_by_name(mirror_root, dt_spec_name());
    if (!spec) {
        spec = cep_cell_ensure_dictionary_child(mirror_root,
                                                dt_spec_name(),
                                                CEP_STORAGE_RED_BLACK_T);
    }
    spec = cep_cell_resolve(spec);
    if (!spec || !cep_cell_require_dictionary_store(&spec)) {
        return false;
    }

    (void)cep_cell_put_text(spec, dt_usage_name(),
                             "Requests under /net/organs/mirror/requests configure "
                             "mirror mounts and episodic bundle staging.");
    (void)cep_cell_put_text(spec, dt_status_name(),
                             "Validator enforces schema, starts episodic staging, "
                             "and updates state/provider/commit evidence.");

    cepCell* requests = cep_cell_find_by_name(mirror_root, dt_requests_name());
    if (!requests) {
        requests = cep_cell_ensure_dictionary_child(mirror_root,
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

/* Validate or reconfigure a mirror organ request by parsing the schema,
   detecting conflicting mounts, wiring the transport manager, and launching
   the episodic bundle worker. Errors update the request node directly so
   tooling can inspect failure notes without replaying the operation. */
int cep_fed_mirror_validator(const cepPath* signal_path,
                             const cepPath* target_path) {
    if (!g_mirror_manager) {
        g_mirror_manager = cep_fed_pack_manager();
    }
    if (!g_mirror_manager) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* request_cell = cep_fed_mirror_resolve_request(target_path);
    if (!request_cell) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_cell_require_dictionary_store(&request_cell)) {
        cep_fed_mirror_publish_state(request_cell,
                                     "error",
                                     "mirror request is not a dictionary",
                                     NULL);
        cep_fed_mirror_emit_issue(request_cell,
                                  CEP_FED_MIRROR_TOPIC_SCHEMA,
                                  "mirror request is not a dictionary");
        return CEP_ENZYME_FATAL;
    }

    char peer[64] = {0};
    char mount[64] = {0};
    char mount_mode[32] = {0};
    char local_node[64] = {0};
    char source_peer[64] = {0};
    char source_channel[64] = {0};
    char preferred_provider[64] = {0};
    char resume_token[96] = {0};
    char commit_mode_text[32] = {0};
    bool allow_upd_latest = false;
    uint64_t deadline = 0u;
    uint32_t beat_window = 1u;
    uint16_t max_inflight = 1u;

    if (!cep_fed_mirror_read_text(request_cell, dt_peer_field_name(), true, peer, sizeof peer) ||
        !cep_fed_mirror_read_text(request_cell, dt_mount_field_name(), true, mount, sizeof mount) ||
        !cep_fed_mirror_read_text(request_cell, dt_mode_field_name(), true, mount_mode, sizeof mount_mode) ||
        !cep_fed_mirror_read_text(request_cell, dt_local_node_field_name(), true, local_node, sizeof local_node) ||
        !cep_fed_mirror_read_text(request_cell, dt_source_peer_field_name(), true, source_peer, sizeof source_peer) ||
        !cep_fed_mirror_read_text(request_cell, dt_source_channel_field_name(), true, source_channel, sizeof source_channel)) {
        cep_fed_mirror_publish_state(request_cell,
                                     "error",
                                     "missing required fields",
                                     NULL);
        cep_fed_mirror_emit_issue(request_cell,
                                  CEP_FED_MIRROR_TOPIC_SCHEMA,
                                  "mirror request missing required fields");
        return CEP_ENZYME_FATAL;
    }

    (void)cep_fed_mirror_read_text(request_cell,
                                   dt_pref_provider(),
                                   false,
                                   preferred_provider,
                                   sizeof preferred_provider);
    (void)cep_fed_mirror_read_bool(request_cell,
                                   dt_allow_upd(),
                                   &allow_upd_latest);

    bool deadline_present = false;
    cepCell* deadline_node = cep_cell_find_by_name(request_cell, dt_deadline_name());
    if (deadline_node) {
        deadline_node = cep_cell_resolve(deadline_node);
        if (deadline_node) {
            cepData* data = NULL;
            if (cep_cell_require_data(&deadline_node, &data)) {
                cepDT expected = cep_ops_make_dt("val/u64");
                if (cep_dt_compare(&data->dt, &expected) == 0 && data->size == sizeof(uint64_t)) {
                    const uint64_t* payload = (const uint64_t*)cep_data_payload(data);
                    if (payload) {
                        deadline = *payload;
                        deadline_present = true;
                    }
                }
            }
        }
    }

    cepFedTransportCaps required_caps = 0u;
    cepFedTransportCaps preferred_caps = 0u;
    if (!cep_fed_mirror_parse_caps(request_cell, &required_caps, &preferred_caps)) {
        cep_fed_mirror_publish_state(request_cell,
                                     "error",
                                     "invalid capability dictionary",
                                     NULL);
        cep_fed_mirror_emit_issue(request_cell,
                                  CEP_FED_MIRROR_TOPIC_SCHEMA,
                                  "invalid capability dictionary");
        return CEP_ENZYME_FATAL;
    }

    cepCell* bundle = cep_cell_find_by_name(request_cell, dt_bundle_name());
    if (bundle) {
        bundle = cep_cell_resolve(bundle);
        if (!bundle || !cep_cell_require_dictionary_store(&bundle)) {
            cep_fed_mirror_publish_state(request_cell,
                                         "error",
                                         "bundle dictionary invalid",
                                         NULL);
            cep_fed_mirror_emit_issue(request_cell,
                                      CEP_FED_MIRROR_TOPIC_SCHEMA,
                                      "bundle dictionary invalid");
            return CEP_ENZYME_FATAL;
        }
        (void)cep_fed_mirror_read_u32(bundle,
                                      dt_beat_window_name(),
                                      false,
                                      &beat_window);
        (void)cep_fed_mirror_read_u16(bundle,
                                      dt_max_inflight_name(),
                                      false,
                                      &max_inflight);
        (void)cep_fed_mirror_read_text(bundle,
                                       dt_commit_mode_name(),
                                       false,
                                       commit_mode_text,
                                       sizeof commit_mode_text);
        (void)cep_fed_mirror_read_text(bundle,
                                       dt_resume_token_name(),
                                       false,
                                       resume_token,
                                       sizeof resume_token);
        bool history_cap = false;
        if (!cep_fed_mirror_read_bool(bundle, dt_bundle_hist_cap_name(), &history_cap) || !history_cap) {
            cep_fed_mirror_publish_state(request_cell,
                                         "error",
                                         "bundle missing hist_cap capability",
                                         NULL);
            cep_fed_mirror_emit_issue(request_cell,
                                      CEP_FED_MIRROR_TOPIC_SCHEMA,
                                      "bundle.hist_cap capability required");
            return CEP_ENZYME_FATAL;
        }
        bool deltas_cap = false;
        if (!cep_fed_mirror_read_bool(bundle, dt_bundle_delta_cap_name(), &deltas_cap) || !deltas_cap) {
            cep_fed_mirror_publish_state(request_cell,
                                         "error",
                                         "bundle missing delta_cap capability",
                                         NULL);
            cep_fed_mirror_emit_issue(request_cell,
                                      CEP_FED_MIRROR_TOPIC_SCHEMA,
                                      "bundle.delta_cap capability required");
            return CEP_ENZYME_FATAL;
        }
    }

    if (beat_window == 0u) {
        beat_window = 1u;
    }
    if (max_inflight == 0u) {
        max_inflight = 1u;
    }

    cepFedMirrorCommitMode commit_mode = CEP_FED_MIRROR_COMMIT_STREAM;
    if (commit_mode_text[0] != '\0') {
        if (strcmp(commit_mode_text, "stream") == 0) {
            commit_mode = CEP_FED_MIRROR_COMMIT_STREAM;
        } else if (strcmp(commit_mode_text, "batch") == 0) {
            commit_mode = CEP_FED_MIRROR_COMMIT_BATCH;
        } else if (strcmp(commit_mode_text, "manual") == 0) {
            commit_mode = CEP_FED_MIRROR_COMMIT_MANUAL;
        } else {
            cep_fed_mirror_publish_state(request_cell,
                                         "error",
                                         "unsupported commit_mode",
                                         NULL);
            cep_fed_mirror_emit_issue(request_cell,
                                      CEP_FED_MIRROR_TOPIC_SCHEMA,
                                      "unsupported commit_mode");
            return CEP_ENZYME_FATAL;
        }
    } else {
        commit_mode = CEP_FED_MIRROR_COMMIT_STREAM;
    }

    cepFedMirrorRequestCtx* ctx = cep_fed_mirror_find_ctx(request_cell);
    if (!ctx) {
        ctx = cep_malloc0(sizeof *ctx);
        if (!ctx) {
            return CEP_ENZYME_FATAL;
        }
        ctx->request_cell = request_cell;
        ctx->runtime = cep_runtime_active();
        ctx->episode = cep_oid_invalid();
        ctx->next = g_mirror_requests;
        g_mirror_requests = ctx;
    } else {
        cep_fed_mirror_cancel_episode(ctx, "mirror-reconfigure");
        cep_fed_mirror_release_mount(ctx, "mirror-reconfigure");
        if (ctx->request_path) {
            cep_free(ctx->request_path);
            ctx->request_path = NULL;
        }
        ctx->runtime = cep_runtime_active();
    }

    (void)snprintf(ctx->peer, sizeof ctx->peer, "%s", peer);
    (void)snprintf(ctx->mount_id, sizeof ctx->mount_id, "%s", mount);
    (void)snprintf(ctx->mode, sizeof ctx->mode, "%s", mount_mode);
    (void)snprintf(ctx->local_node, sizeof ctx->local_node, "%s", local_node);
    (void)snprintf(ctx->source_peer, sizeof ctx->source_peer, "%s", source_peer);
    (void)snprintf(ctx->source_channel, sizeof ctx->source_channel, "%s", source_channel);
    ctx->required_caps = required_caps;
    ctx->preferred_caps = preferred_caps;
    ctx->allow_upd_latest = allow_upd_latest;
    ctx->beat_window = beat_window;
    ctx->max_inflight = max_inflight;
    ctx->commit_mode = commit_mode;
    ctx->beats_accum = 0u;
    ctx->inflight = 0u;
    ctx->bundle_seq = 0u;
    ctx->last_commit_beat = 0u;
    ctx->deadline = deadline;
    ctx->has_deadline = deadline_present;
    ctx->lease_armed = false;
    ctx->provider_id[0] = '\0';
    (void)snprintf(ctx->resume_token, sizeof ctx->resume_token, "%s", resume_token);

    cepBeatNumber current_beat = cep_heartbeat_current();
    if (ctx->has_deadline && (ctx->deadline == 0u || ctx->deadline <= current_beat)) {
        cep_fed_mirror_publish_state(request_cell,
                                     "error",
                                     "deadline expired before activation",
                                     NULL);
        cep_fed_mirror_emit_issue(request_cell,
                                  CEP_FED_MIRROR_TOPIC_TIMEOUT,
                                  "mirror request deadline expired before activation");
        cep_fed_mirror_remove_ctx(request_cell);
        return CEP_ENZYME_FATAL;
    }

    if (!cep_cell_path(request_cell, &ctx->request_path)) {
        cep_fed_mirror_publish_state(request_cell,
                                     "error",
                                     "failed to capture request path",
                                     NULL);
        cep_fed_mirror_emit_issue(request_cell,
                                  CEP_FED_MIRROR_TOPIC_SCHEMA,
                                  "failed to capture request path");
        return CEP_ENZYME_FATAL;
    }

    for (cepFedMirrorRequestCtx* other = g_mirror_requests; other; other = other->next) {
        if (other == ctx || other->request_cell == request_cell) {
            continue;
        }
        if (other->runtime == ctx->runtime &&
            strcmp(other->peer, ctx->peer) == 0 &&
            strcmp(other->mount_id, ctx->mount_id) == 0 &&
            other->mount != NULL) {
            cep_fed_mirror_publish_state(request_cell,
                                         "error",
                                         "mirror mount already active",
                                         NULL);
            cep_fed_mirror_emit_issue(request_cell,
                                      CEP_FED_MIRROR_TOPIC_CONFLICT,
                                      "mirror mount already active");
            cep_fed_mirror_remove_ctx(request_cell);
            return CEP_ENZYME_FATAL;
        }
    }

    cepFedTransportMountCallbacks callbacks = {
        .on_frame = cep_fed_mirror_on_frame,
        .on_event = cep_fed_mirror_on_event,
        .user_ctx = ctx,
    };
    cepFedTransportMountConfig cfg = {
        .peer_id = ctx->peer,
        .mount_id = ctx->mount_id,
        .mount_mode = ctx->mode,
        .local_node_id = ctx->local_node,
        .preferred_provider_id = preferred_provider[0] ? preferred_provider : NULL,
        .required_caps = ctx->required_caps,
        .preferred_caps = ctx->preferred_caps,
        .allow_upd_latest = ctx->allow_upd_latest,
        .deadline_beat = ctx->deadline,
    };

    cepFedTransportManagerMount* mount_handle = NULL;
    if (!cep_fed_transport_manager_configure_mount(g_mirror_manager,
                                                   &cfg,
                                                   &callbacks,
                                                   &mount_handle)) {
        cep_fed_mirror_publish_state(request_cell,
                                     "error",
                                     "transport manager rejected configuration",
                                     NULL);
        cep_fed_mirror_emit_issue(request_cell,
                                  CEP_FED_MIRROR_TOPIC_SCHEMA,
                                  "transport manager rejected configuration");
        return CEP_ENZYME_FATAL;
    }

    ctx->mount = mount_handle;
    const char* provider_id = cep_fed_transport_manager_mount_provider_id(mount_handle);
    if (provider_id) {
        (void)snprintf(ctx->provider_id, sizeof ctx->provider_id, "%s", provider_id);
    }

    cep_fed_mirror_publish_state(request_cell, "active", NULL, ctx->provider_id);
    cep_fed_mirror_publish_progress(ctx);

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RW,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    const cepPath* effective_signal = signal_path;
    cepPath* synthetic_signal = NULL;
    if (!effective_signal) {
        if (!cep_fed_mirror_make_signal_path(&synthetic_signal)) {
            cep_fed_mirror_publish_state(request_cell,
                                         "error",
                                         "failed to synthesise signal path",
                                         NULL);
            cep_fed_mirror_emit_issue(request_cell,
                                      CEP_FED_MIRROR_TOPIC_SCHEMA,
                                      "failed to synthesise signal path");
            return CEP_ENZYME_FATAL;
        }
        effective_signal = synthetic_signal;
    }

    const cepPath* effective_target = target_path ? target_path : ctx->request_path;

    ctx->episode = cep_oid_invalid();
    bool started = cep_ep_start(&ctx->episode,
                                effective_signal,
                                effective_target,
                                cep_fed_mirror_episode_slice,
                                ctx,
                                &policy,
                                0u);
    if (synthetic_signal) {
        cep_free(synthetic_signal);
    }

    if (!started) {
        cep_fed_mirror_publish_state(request_cell,
                                     "error",
                                     "failed to start mirror episode",
                                     ctx->provider_id);
        cep_fed_mirror_emit_issue(request_cell,
                                  CEP_FED_MIRROR_TOPIC_SCHEMA,
                                  "failed to start mirror episode");
        cep_fed_mirror_release_mount(ctx, "mirror-start-failed");
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}

/* Tear down an existing mirror request by cancelling the associated episode,
   closing the transport mount, and clearing status fields so later requests
   start from a clean slate without stale provider metadata. */
int cep_fed_mirror_destructor(const cepPath* signal_path,
                              const cepPath* target_path) {
    (void)signal_path;
    cepCell* request_cell = cep_fed_mirror_resolve_request(target_path);
    if (!request_cell) {
        return CEP_ENZYME_SUCCESS;
    }

    cepFedMirrorRequestCtx* ctx = cep_fed_mirror_find_ctx(request_cell);
    if (ctx) {
        cep_fed_mirror_cancel_episode(ctx, "mirror-destroy");
        cep_fed_mirror_release_mount(ctx, "mirror-request-destroy");
        cep_fed_mirror_publish_state(request_cell, "removed", NULL, NULL);
        (void)cep_fed_mirror_write_u64(request_cell, dt_last_bundle_seq_name(), 0u);
        (void)cep_fed_mirror_write_u64(request_cell, dt_last_commit_beat_name(), 0u);
        (void)cep_cell_put_text(request_cell, dt_pending_resume_name(), "");
        cep_fed_mirror_remove_ctx(request_cell);
    }
    return CEP_ENZYME_SUCCESS;
}
