/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "fed_transport_manager.h"
#include "fed_schema_helpers.h"

#include "fed_pack.h"
#include "fed_transport.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_crc32c.h"
#include "../l0_kernel/cep_flat_stream.h"
#include "../l0_kernel/cep_molecule.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_enclave_policy.h"
#include "../l0_kernel/cep_security_tags.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_async.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#include <errno.h>

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
    uint64_t                       ready_events;
    uint64_t                       backpressure_events;
    uint64_t                       fatal_events;
    uint64_t                       frame_count;
    cepFedFrameMode                last_frame_mode;
    uint8_t                        last_frame_sample;
    uint8_t*                       pending_payload;
    size_t                         pending_len;
    cepFedTransportMountCallbacks  callbacks;
    uint32_t                       payload_history_beats;
    uint32_t                       manifest_history_beats;
    bool                           flat_allow_crc32c;
    bool                           flat_allow_deflate;
    bool                           flat_allow_aead;
    bool                           flat_warn_on_downgrade;
    bool                           flat_warn_crc32c_emitted;
    bool                           flat_warn_compression_emitted;
    bool                           flat_warn_aead_emitted;
    uint32_t                       flat_comparator_max_version;
    cepEnclavePolicyLimits         security_limits;
    cepDT                          async_channel_dt;
    bool                           async_channel_registered;
    uint64_t                       async_req_counter;
    char*                          async_target_path;
    bool                           async_pending_active;
    cepDT                          async_pending_request;
    size_t                         async_pending_bytes;
    cepFedTransportAsyncHandle*    async_pending_handle;
    bool                           async_receive_pending;
    cepDT                          async_receive_request;
    cepFedTransportAsyncHandle*    async_receive_handle;
    uint64_t                       async_pending_requests;
    uint64_t                       async_shim_jobs;
    uint64_t                       async_native_jobs;
    bool                           async_warn_emitted;
    bool                           security_limits_valid;
    uint64_t                       security_bytes_used;
    uint64_t                       security_send_count;
    uint64_t                       security_limit_hits;
    cepBeatNumber                  security_rate_beat;
    uint32_t                       security_rate_count;
    bool                           pipeline_metadata_known;
    char                           pipeline_label[128];
    char                           stage_label[128];
    uint64_t                       pipeline_run_id;
    uint64_t                       pipeline_hop_index;
};

struct cepFedTransportAsyncHandle {
    cepFedTransportManagerMount* mount;
    cepDT                        request_name;
    cepDT                        opcode;
    cepFedFrameMode              frame_mode;
    uint8_t                      frame_sample;
    size_t                       expected_bytes;
    bool                         shim;
    bool                         active;
};

typedef struct {
    uint8_t* data;
    size_t   size;
    size_t   capacity;
} cepFedFrameBuffer;

static void cep_fed_frame_buffer_reset(cepFedFrameBuffer* buffer) {
    if (!buffer) {
        return;
    }
    if (buffer->data) {
        cep_free(buffer->data);
        buffer->data = NULL;
    }
    buffer->size = 0u;
    buffer->capacity = 0u;
}

static bool cep_fed_frame_capture_sink(void* ctx, const uint8_t* chunk, size_t size) {
    if (!ctx || (!chunk && size)) {
        return false;
    }
    cepFedFrameBuffer* buffer = ctx;
    if (size == 0u) {
        return true;
    }
    size_t required = buffer->size + size;
    if (required > buffer->capacity) {
        size_t new_capacity = buffer->capacity ? buffer->capacity : 1024u;
        while (new_capacity < required) {
            new_capacity *= 2u;
        }
        uint8_t* grown = buffer->data
            ? cep_realloc(buffer->data, new_capacity)
            : cep_malloc(new_capacity);
        if (!grown) {
            return false;
        }
        buffer->data = grown;
        buffer->capacity = new_capacity;
    }
    memcpy(buffer->data + buffer->size, chunk, size);
    buffer->size += size;
    return true;
}

CEP_DEFINE_STATIC_DT(dt_mounts_name, CEP_ACRO("CEP"), CEP_WORD("mounts"));
CEP_DEFINE_STATIC_DT(dt_caps_name, CEP_ACRO("CEP"), CEP_WORD("caps"));
CEP_DEFINE_STATIC_DT(dt_required_name, CEP_ACRO("CEP"), CEP_WORD("required"));
CEP_DEFINE_STATIC_DT(dt_preferred_name, CEP_ACRO("CEP"), CEP_WORD("preferred"));
CEP_DEFINE_STATIC_DT(dt_transport_name, CEP_ACRO("CEP"), CEP_WORD("transport"));
CEP_DEFINE_STATIC_DT(dt_provider_name, CEP_ACRO("CEP"), CEP_WORD("provider"));
CEP_DEFINE_STATIC_DT(dt_selected_caps_name, CEP_ACRO("CEP"), CEP_WORD("prov_caps"));
CEP_DEFINE_STATIC_DT(dt_async_pending_field_name, CEP_ACRO("CEP"), CEP_WORD("async_pnd"));
CEP_DEFINE_STATIC_DT(dt_async_shim_field_name, CEP_ACRO("CEP"), CEP_WORD("async_shm"));
CEP_DEFINE_STATIC_DT(dt_async_native_field_name, CEP_ACRO("CEP"), CEP_WORD("async_nat"));
CEP_DEFINE_STATIC_DT(dt_rt_root_name_fed, CEP_ACRO("CEP"), CEP_WORD("rt"));
CEP_DEFINE_STATIC_DT(dt_analytics_root_name, CEP_ACRO("CEP"), CEP_WORD("analytics"));
CEP_DEFINE_STATIC_DT(dt_async_root_name, CEP_ACRO("CEP"), CEP_WORD("async"));
CEP_DEFINE_STATIC_DT(dt_shim_branch_name, CEP_ACRO("CEP"), CEP_WORD("shim"));
CEP_DEFINE_STATIC_DT(dt_native_branch_name, CEP_ACRO("CEP"), CEP_WORD("native"));
CEP_DEFINE_STATIC_DT(dt_sec_analytics_root_name_fed, CEP_ACRO("CEP"), CEP_WORD("security"));
CEP_DEFINE_STATIC_DT(dt_sec_analytics_beats_name_fed, CEP_ACRO("CEP"), CEP_WORD("beats"));
CEP_DEFINE_STATIC_DT(dt_sec_allow_field_fed, CEP_ACRO("CEP"), CEP_WORD("allow"));
CEP_DEFINE_STATIC_DT(dt_sec_deny_field_fed, CEP_ACRO("CEP"), CEP_WORD("deny"));
CEP_DEFINE_STATIC_DT(dt_sec_limits_field_fed, CEP_ACRO("CEP"), CEP_WORD("limits"));
CEP_DEFINE_STATIC_DT(dt_sec_label_field_fed, CEP_ACRO("CEP"), CEP_WORD("label"));

static cepCell*
cep_fed_transport_security_ensure_branch(cepCell* parent, const cepDT* name)
{
    if (!parent || !name) {
        return NULL;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    if (!child) {
        return NULL;
    }
    child = cep_cell_resolve(child);
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return NULL;
    }
    return child;
}

static cepCell*
cep_fed_transport_security_analytics_root(void)
{
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    cepCell* rt = cep_cell_ensure_dictionary_child(root, dt_rt_root_name_fed(), CEP_STORAGE_RED_BLACK_T);
    if (!rt) {
        return NULL;
    }
    rt = cep_cell_resolve(rt);
    if (!rt || !cep_cell_require_dictionary_store(&rt)) {
        return NULL;
    }
    cepCell* analytics = cep_cell_ensure_dictionary_child(rt,
                                                          dt_analytics_root_name(),
                                                          CEP_STORAGE_RED_BLACK_T);
    if (!analytics) {
        return NULL;
    }
    analytics = cep_cell_resolve(analytics);
    if (!analytics || !cep_cell_require_dictionary_store(&analytics)) {
        return NULL;
    }
    return cep_fed_transport_security_ensure_branch(analytics, dt_sec_analytics_root_name_fed());
}

static bool
cep_fed_transport_security_increment_counter(cepCell* parent, const cepDT* field, uint64_t delta)
{
    if (!parent || !field) {
        return false;
    }
    uint64_t next = delta;
    cepCell* existing = cep_cell_find_by_name(parent, field);
    if (existing) {
        existing = cep_cell_resolve(existing);
        if (existing && existing->data) {
            cepData* data = existing->data;
            if (data->size == sizeof(uint64_t)) {
                const uint64_t* payload = (const uint64_t*)cep_data_payload(data);
                if (payload) {
                    next += *payload;
                }
            }
        }
    }
    return cep_cell_put_uint64(parent, field, next);
}

static bool
cep_fed_transport_manager_read_text(cepCell* parent,
                                    const cepDT* field,
                                    char* buffer,
                                    size_t capacity)
{
    if (!parent || !field || !buffer || capacity == 0u) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node || !node->data) {
        return false;
    }
    const char* payload = (const char*)cep_data_payload(node->data);
    if (!payload || node->data->size == 0u) {
        return false;
    }
    size_t length = node->data->size;
    if (length >= capacity) {
        length = capacity - 1u;
    }
    memcpy(buffer, payload, length);
    buffer[length] = '\0';
    return true;
}

static cepDT
cep_fed_transport_security_hash_name(const char* name, uint32_t salt)
{
    cepDT dt = {0};
    if (!name) {
        return dt;
    }
    uint32_t hash = cep_crc32c((const uint8_t*)name, strlen(name), 0u);
    hash ^= salt * 0x9e3779b9u;
    cepID numeric = (cepID)((hash % CEP_NAME_MAXVAL) + 1u);
    dt.domain = CEP_ACRO("CEP");
    dt.tag = cep_id_to_numeric(numeric);
    dt.glob = 0u;
    return dt;
}

static cepCell*
cep_fed_transport_security_named_child(cepCell* parent, const char* name)
{
    if (!parent || !name || !*name) {
        return NULL;
    }
    for (uint32_t salt = 0u; salt < 1024u; ++salt) {
        cepDT dt = cep_fed_transport_security_hash_name(name, salt);
        cepCell* child = cep_cell_ensure_dictionary_child(parent, &dt, CEP_STORAGE_RED_BLACK_T);
        if (!child) {
            return NULL;
        }
        child = cep_cell_resolve(child);
        if (!child || !cep_cell_require_dictionary_store(&child)) {
            return NULL;
        }
        char existing[128] = {0};
        if (!cep_fed_transport_manager_read_text(child, dt_sec_label_field_fed(), existing, sizeof existing)) {
            (void)cep_cell_put_text(child, dt_sec_label_field_fed(), name);
            return child;
        }
        if (strcmp(existing, name) == 0) {
            return child;
        }
    }
    return NULL;
}

static bool
cep_fed_transport_security_make_beat_name(cepDT* out_name, cepBeatNumber beat)
{
    if (!out_name) {
        return false;
    }
    cepBeatNumber effective = (beat == CEP_BEAT_INVALID) ? 0u : beat;
    cepID numeric = (cepID)((effective % CEP_AUTOID_MAXVAL) + 1u);
    out_name->domain = CEP_ACRO("CEP");
    out_name->tag = cep_id_to_numeric(numeric);
    out_name->glob = 0u;
    return true;
}

static void
cep_fed_transport_security_record_beat(uint64_t allow_delta,
                                       uint64_t deny_delta,
                                       uint64_t limit_delta)
{
    if (allow_delta == 0u && deny_delta == 0u && limit_delta == 0u) {
        return;
    }
    cepCell* analytics = cep_fed_transport_security_analytics_root();
    if (!analytics) {
        return;
    }
    cepCell* beats = cep_fed_transport_security_ensure_branch(analytics,
                                                              dt_sec_analytics_beats_name_fed());
    if (!beats) {
        return;
    }
    cepBeatNumber beat = cep_beat_index();
    if (beat == CEP_BEAT_INVALID) {
        beat = cep_heartbeat_current();
    }
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }
    cepDT beat_name = {0};
    if (!cep_fed_transport_security_make_beat_name(&beat_name, beat)) {
        return;
    }
    cepCell* entry = cep_fed_transport_security_ensure_branch(beats, &beat_name);
    if (!entry) {
        return;
    }
    if (allow_delta) {
        (void)cep_fed_transport_security_increment_counter(entry,
                                                           dt_sec_allow_field_fed(),
                                                           allow_delta);
    }
    if (deny_delta) {
        (void)cep_fed_transport_security_increment_counter(entry,
                                                           dt_sec_deny_field_fed(),
                                                           deny_delta);
    }
    if (limit_delta) {
        (void)cep_fed_transport_security_increment_counter(entry,
                                                           dt_sec_limits_field_fed(),
                                                           limit_delta);
    }
}

static const char*
cep_fed_transport_label(const char* text, const char* fallback)
{
    return (text && *text) ? text : fallback;
}

static void
cep_fed_transport_security_record_edge_event(const cepFedTransportManagerMount* mount,
                                             bool allowed)
{
    if (!mount) {
        return;
    }
    cepCell* analytics = cep_fed_transport_security_analytics_root();
    if (!analytics) {
        return;
    }
    const char* from_label = cep_fed_transport_label(mount->peer_id, "enclave:<unknown>");
    const char* to_label = cep_fed_transport_label(mount->local_node_id, "enclave:<unknown>");
    const char* gateway_label = cep_fed_transport_label(mount->mount_id, "gateway:<unknown>");

    cepCell* edges = cep_fed_transport_security_ensure_branch(analytics, dt_sec_edges_name());
    if (edges) {
        cepCell* from_cell = cep_fed_transport_security_named_child(edges, from_label);
        if (from_cell) {
            cepCell* to_cell = cep_fed_transport_security_named_child(from_cell, to_label);
            if (to_cell) {
                (void)cep_fed_transport_security_increment_counter(to_cell,
                                                                   allowed ? dt_sec_allow_field_fed()
                                                                           : dt_sec_deny_field_fed(),
                                                                   1u);
            }
        }
    }

    cepCell* gateways = cep_fed_transport_security_ensure_branch(analytics, dt_sec_gateways_name());
    if (gateways) {
        cepCell* gateway_cell = cep_fed_transport_security_named_child(gateways, gateway_label);
        if (gateway_cell) {
            (void)cep_fed_transport_security_increment_counter(gateway_cell,
                                                               allowed ? dt_sec_allow_field_fed()
                                                                       : dt_sec_deny_field_fed(),
                                                               1u);
        }
    }

    cep_fed_transport_security_record_beat(allowed ? 1u : 0u,
                                           allowed ? 0u : 1u,
                                           0u);
}

static void
cep_fed_transport_security_record_limit_counter(const cepFedTransportManagerMount* mount)
{
    if (!mount) {
        return;
    }
    cepCell* analytics = cep_fed_transport_security_analytics_root();
    if (!analytics) {
        return;
    }
    const char* gateway_label = cep_fed_transport_label(mount->mount_id, "gateway:<unknown>");
    cepCell* gateways = cep_fed_transport_security_ensure_branch(analytics, dt_sec_gateways_name());
    if (gateways) {
        cepCell* gateway_cell = cep_fed_transport_security_named_child(gateways, gateway_label);
        if (gateway_cell) {
            (void)cep_fed_transport_security_increment_counter(gateway_cell,
                                                               dt_sec_limits_field_fed(),
                                                               1u);
        }
    }
    cep_fed_transport_security_record_beat(0u, 0u, 1u);
}

static void
cep_fed_transport_security_record_limit_hit(const cepFedTransportManagerMount* mount)
{
    cep_fed_transport_security_record_edge_event(mount, false);
    cep_fed_transport_security_record_limit_counter(mount);
}
CEP_DEFINE_STATIC_DT(dt_jobs_total_name, CEP_ACRO("CEP"), CEP_WORD("jobs_total"));
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
CEP_DEFINE_STATIC_DT(dt_fed_async_provider, CEP_ACRO("CEP"), CEP_WORD("prov:fed"));
CEP_DEFINE_STATIC_DT(dt_fed_async_reactor, CEP_ACRO("CEP"), CEP_WORD("react:fed"));
CEP_DEFINE_STATIC_DT(dt_fed_async_caps, CEP_ACRO("CEP"), CEP_WORD("caps:net"));
CEP_DEFINE_STATIC_DT(dt_fed_async_opcode_send, CEP_ACRO("CEP"), CEP_WORD("op:send"));
CEP_DEFINE_STATIC_DT(dt_fed_async_opcode_recv, CEP_ACRO("CEP"), CEP_WORD("op:recv"));
CEP_DEFINE_STATIC_DT(dt_fed_async_state_exec, CEP_ACRO("CEP"), CEP_WORD("ist:exec"));
CEP_DEFINE_STATIC_DT(dt_fed_async_state_ok, CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_fed_async_state_fail, CEP_ACRO("CEP"), CEP_WORD("ist:fail"));
#define CEP_DEFINE_DYNAMIC_DT(fn_name, literal)                                 \
    static const cepDT* fn_name(void) {                                         \
        static cepDT value = {0};                                               \
        static bool initialized = false;                                        \
        if (!initialized) {                                                     \
            value = cep_ops_make_dt(literal);                                   \
            initialized = true;                                                 \
        }                                                                       \
        return &value;                                                          \
    }

CEP_DEFINE_DYNAMIC_DT(dt_cap_crc32c_name, "cap_crc32c");
CEP_DEFINE_STATIC_DT(dt_cap_deflate_name, CEP_ACRO("CEP"), CEP_WORD("cap_deflate"));
CEP_DEFINE_STATIC_DT(dt_cap_aead_name, CEP_ACRO("CEP"), CEP_WORD("cap_aead"));
CEP_DEFINE_STATIC_DT(dt_cap_cmpver_name, CEP_ACRO("CEP"), CEP_WORD("cap_cmpver"));
CEP_DEFINE_STATIC_DT(dt_sev_error_name, CEP_ACRO("CEP"), CEP_WORD("sev:error"));
CEP_DEFINE_STATIC_DT(dt_sev_warn_name, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_services_name, CEP_ACRO("CEP"), CEP_WORD("services"));
CEP_DEFINE_STATIC_DT(dt_peer_field_name, CEP_ACRO("CEP"), CEP_WORD("peer"));
CEP_DEFINE_STATIC_DT(dt_mode_field_name, CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_local_node_field_name, CEP_ACRO("CEP"), CEP_WORD("local_node"));
CEP_DEFINE_STATIC_DT(dt_mount_path_name, CEP_ACRO("CEP"), CEP_WORD("mount_path"));
CEP_DEFINE_STATIC_DT(dt_last_event_name, CEP_ACRO("CEP"), CEP_WORD("last_event"));
CEP_DEFINE_STATIC_DT(dt_ready_count_name, CEP_ACRO("CEP"), CEP_WORD("ready_count"));
CEP_DEFINE_STATIC_DT(dt_backpressure_count_name, CEP_ACRO("CEP"), CEP_WORD("bp_count"));
CEP_DEFINE_STATIC_DT(dt_fatal_count_name, CEP_ACRO("CEP"), CEP_WORD("fatal_count"));
CEP_DEFINE_STATIC_DT(dt_frame_count_name, CEP_ACRO("CEP"), CEP_WORD("frame_count"));
CEP_DEFINE_STATIC_DT(dt_last_frame_mode_name, CEP_ACRO("CEP"), CEP_WORD("last_mode"));
CEP_DEFINE_STATIC_DT(dt_last_frame_sample_name, CEP_ACRO("CEP"), CEP_WORD("last_sample"));
CEP_DEFINE_STATIC_DT(dt_backpressured_flag_name, CEP_ACRO("CEP"), CEP_WORD("bp_flag"));
CEP_DEFINE_STATIC_DT(dt_ceh_name, CEP_ACRO("CEP"), CEP_WORD("ceh"));
CEP_DEFINE_STATIC_DT(dt_severity_field_name, CEP_ACRO("CEP"), CEP_WORD("severity"));
CEP_DEFINE_STATIC_DT(dt_note_field_name, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_beat_field_name, CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_serializer_name, CEP_ACRO("CEP"), CEP_WORD("serializer"));
CEP_DEFINE_DYNAMIC_DT(dt_ser_crc32c_ok_name, "crc32c_ok");
CEP_DEFINE_STATIC_DT(dt_ser_deflate_ok_name, CEP_ACRO("CEP"), CEP_WORD("deflate_ok"));
CEP_DEFINE_STATIC_DT(dt_ser_aead_ok_name, CEP_ACRO("CEP"), CEP_WORD("aead_ok"));
CEP_DEFINE_STATIC_DT(dt_ser_warn_down_name, CEP_ACRO("CEP"), CEP_WORD("warn_down"));
CEP_DEFINE_STATIC_DT(dt_ser_cmpmax_name, CEP_ACRO("CEP"), CEP_WORD("cmp_max_ver"));
CEP_DEFINE_STATIC_DT(dt_ser_pay_hist_name, CEP_ACRO("CEP"), CEP_WORD("pay_hist_bt"));
CEP_DEFINE_STATIC_DT(dt_ser_man_hist_name, CEP_ACRO("CEP"), CEP_WORD("man_hist_bt"));
CEP_DEFINE_STATIC_DT(dt_sec_send_count_name, CEP_ACRO("CEP"), CEP_WORD("sec_sends"));
CEP_DEFINE_STATIC_DT(dt_sec_bytes_name, CEP_ACRO("CEP"), CEP_WORD("sec_bytes"));
CEP_DEFINE_STATIC_DT(dt_sec_hits_name, CEP_ACRO("CEP"), CEP_WORD("sec_hits"));
CEP_DEFINE_STATIC_DT(dt_sec_rate_counter_name, CEP_ACRO("CEP"), CEP_WORD("sec_rate"));

typedef const cepDT* (*cepFedTransportDtGetter)(void);

typedef struct {
    cepFedTransportCaps     flag;
    cepFedTransportDtGetter getter;
    const char*             tag;
} cepFedTransportCapEntry;

static const cepFedTransportCapEntry cep_fed_transport_cap_entries[] = {
    { CEP_FED_TRANSPORT_CAP_RELIABLE,    dt_cap_reliable_name,    CEP_FED_TAG_CAP_RELIABLE    },
    { CEP_FED_TRANSPORT_CAP_ORDERED,     dt_cap_ordered_name,     CEP_FED_TAG_CAP_ORDERED     },
    { CEP_FED_TRANSPORT_CAP_STREAMING,   dt_cap_streaming_name,   CEP_FED_TAG_CAP_STREAMING   },
    { CEP_FED_TRANSPORT_CAP_DATAGRAM,    dt_cap_datagram_name,    CEP_FED_TAG_CAP_DATAGRAM    },
    { CEP_FED_TRANSPORT_CAP_MULTICAST,   dt_cap_multicast_name,   CEP_FED_TAG_CAP_MULTICAST   },
    { CEP_FED_TRANSPORT_CAP_LOW_LATENCY, dt_cap_latency_name,     CEP_FED_TAG_CAP_LOW_LATENCY },
    { CEP_FED_TRANSPORT_CAP_LOCAL_IPC,   dt_cap_local_ipc_name,   CEP_FED_TAG_CAP_LOCAL_IPC   },
    { CEP_FED_TRANSPORT_CAP_REMOTE_NET,  dt_cap_remote_net_name,  CEP_FED_TAG_CAP_REMOTE_NET  },
    { CEP_FED_TRANSPORT_CAP_UNRELIABLE,  dt_cap_unreliable_name,  CEP_FED_TAG_CAP_UNRELIABLE  },
    { CEP_FED_TRANSPORT_CAP_CHECKSUM_CRC32C,      dt_cap_crc32c_name,      "cap_crc32c"      },
    { CEP_FED_TRANSPORT_CAP_COMPRESSION_DEFLATE,  dt_cap_deflate_name,     "cap_deflate"     },
    { CEP_FED_TRANSPORT_CAP_ENCRYPTION_AEAD,      dt_cap_aead_name,        "cap_aead"        },
    { CEP_FED_TRANSPORT_CAP_COMPARATOR_VERSIONED, dt_cap_cmpver_name,      "cap_cmpver"      },
};

static const char* const CEP_FED_TOPIC_NO_PROVIDER      = "tp_noprov";
static const char* const CEP_FED_TOPIC_SCHEMA           = "tp_schema";
static const char* const CEP_FED_TOPIC_SCHEMA_UPDATE    = "tp_schemup";
static const char* const CEP_FED_TOPIC_PROVIDER_ID      = "tp_provid";
static const char* const CEP_FED_TOPIC_PROVIDER_CELL    = "tp_provcell";
static const char* const CEP_FED_TOPIC_OPEN_FAILED      = "tp_openfail";
static const char* const CEP_FED_TOPIC_CATALOG_SYNC     = "tp_catsync";
static const char* const CEP_FED_TOPIC_UPD_DENIED       = "tp_upd_den";
static const char* const CEP_FED_TOPIC_UPD_MISUSE       = "tp_upd_mis";
static const char* const CEP_FED_TOPIC_BACKPRESSURE     = "tp_backpr";
static const char* const CEP_FED_TOPIC_SEND_FAILED      = "tp_sendfail";
static const char* const CEP_FED_TOPIC_FATAL_EVENT      = "tp_fatal";
static const char* const CEP_FED_TOPIC_FLAT_NEGOTIATION = "tp_flatneg";
static const char* const CEP_FED_TOPIC_ASYNC_UNSUPPORTED = "tp_async_unsp";

static inline unsigned cep_fed_transport_popcount(cepFedTransportCaps value) {
    unsigned count = 0u;
    while (value) {
        count += (value & 1u);
        value >>= 1u;
    }
    return count;
}

static void cep_fed_transport_manager_update_health(cepFedTransportManager* manager,
                                                    cepFedTransportManagerMount* mount,
                                                    const cepDT* severity,
                                                    const char* note,
                                                    const char* topic);
static bool cep_fed_transport_manager_refresh_telemetry(cepFedTransportManager* manager,
                                                        cepFedTransportManagerMount* mount,
                                                        const char* last_event);

static void cep_fed_transport_manager_mount_reset_pending(cepFedTransportManagerMount* mount);
static bool cep_fed_env_push_override(const char* name, uint32_t value, char** previous_copy);
static bool cep_fed_env_push_text_override(const char* name, const char* value, char** previous_copy);
static void cep_fed_env_pop_override(const char* name, char* previous_copy);
static void cep_fed_transport_manager_warn_flat_downgrade(cepFedTransportManager* manager,
                                                          cepFedTransportManagerMount* mount,
                                                          bool* warned_flag,
                                                          const char* note);
static bool cep_fed_transport_mount_prepare_async_target(cepFedTransportManagerMount* mount);
static void cep_fed_transport_mount_async_ensure_channel(cepFedTransportManagerMount* mount);
static void cep_fed_transport_mount_async_cancel_pending(cepFedTransportManagerMount* mount, int error_code);
static void cep_fed_transport_mount_async_cancel_receive(cepFedTransportManagerMount* mount, int error_code);
static cepDT cep_fed_transport_mount_next_request_dt(cepFedTransportManagerMount* mount, const char prefix[3]);
static bool cep_fed_transport_mount_async_begin_request(cepFedTransportManagerMount* mount,
                                                        const char prefix[3],
                                                        const cepDT* opcode,
                                                        size_t expected_bytes,
                                                        cepDT* out_name);
static void cep_fed_transport_mount_async_complete_request(cepFedTransportManagerMount* mount,
                                                           const cepDT* request_name,
                                                           const cepDT* opcode,
                                                           bool success,
                                                           size_t bytes_done,
                                                           int error_code);
static bool cep_fed_transport_manager_security_allow(cepFedTransportManagerMount* mount,
                                                     size_t payload_len);
static void cep_fed_transport_manager_security_record_send(cepFedTransportManagerMount* mount,
                                                           size_t payload_len);
static void cep_fed_transport_manager_emit_limit_hit(cepFedTransportManagerMount* mount,
                                                     const char* limit_label,
                                                     const char* detail);

static void cep_fed_transport_manager_mount_reset_pending(cepFedTransportManagerMount* mount) {
    if (!mount) {
        return;
    }
    cep_fed_transport_mount_async_cancel_pending(mount, -ECANCELED);
    cep_fed_transport_mount_async_cancel_receive(mount, -ECANCELED);
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
    req.subject = NULL;
    req.mailbox_root = manager->diagnostics_mailbox;
    req.emit_signal = true;
    req.attach_to_op = false;
    req.ttl_forever = false;
    (void)cep_cei_emit(&req);
    if (mount && topic) {
        cep_fed_transport_manager_update_health(manager, mount, severity, note, topic);
    }
}

static void
cep_fed_transport_manager_emit_limit_hit(cepFedTransportManagerMount* mount,
                                         const char* limit_label,
                                         const char* detail)
{
    if (!mount) {
        return;
    }
    ++mount->security_limit_hits;

    const char* peer = mount->peer_id ? mount->peer_id : "<none>";
    const char* local = mount->local_node_id ? mount->local_node_id : "<none>";
    const char* mount_id = mount->mount_id ? mount->mount_id : "<none>";
    const char* limit = limit_label ? limit_label : "<unknown>";
    const char* info = detail ? detail : "";

    const char* pipeline = (mount->pipeline_label[0] != '\0') ? mount->pipeline_label : "<none>";
    const char* stage = (mount->stage_label[0] != '\0') ? mount->stage_label : "<none>";
    char note[256];
    if (mount->pipeline_metadata_known) {
        snprintf(note,
                 sizeof note,
                 "peer=%s node=%s mount=%s limit=%s detail=%s pipeline=%s stage=%s run=%" PRIu64 " hop=%" PRIu64,
                 peer,
                 local,
                 mount_id,
                 limit,
                 info,
                 pipeline,
                 stage,
                 mount->pipeline_run_id,
                 mount->pipeline_hop_index);
    } else {
        snprintf(note,
                 sizeof note,
                 "peer=%s node=%s mount=%s limit=%s detail=%s",
                 peer,
                 local,
                 mount_id,
                 limit,
                 info);
    }

    cepPipelineMetadata pipeline_meta = {0};
    bool has_pipeline = mount->pipeline_metadata_known;
    if (has_pipeline) {
        if (mount->pipeline_label[0]) {
            pipeline_meta.pipeline_id = cep_namepool_intern_cstr(mount->pipeline_label);
        }
        if (mount->stage_label[0]) {
            pipeline_meta.stage_id = cep_namepool_intern_cstr(mount->stage_label);
        }
        pipeline_meta.dag_run_id = mount->pipeline_run_id;
        pipeline_meta.hop_index = mount->pipeline_hop_index;
        has_pipeline = pipeline_meta.pipeline_id ||
                       pipeline_meta.stage_id ||
                       pipeline_meta.dag_run_id ||
                       pipeline_meta.hop_index;
    }

    cepCeiRequest req = {
        .severity = *dt_sev_warn_name(),
        .topic = "sec.limit.hit",
        .topic_intern = true,
        .note = note,
        .subject = NULL,
        .mailbox_root = mount->manager ? mount->manager->diagnostics_mailbox : NULL,
        .emit_signal = true,
        .attach_to_op = false,
        .ttl_forever = true,
    };
    req.has_pipeline = has_pipeline;
    if (has_pipeline) {
        req.pipeline = pipeline_meta;
    }
    (void)cep_cei_emit(&req);

    if (mount->manager) {
        (void)cep_fed_transport_manager_refresh_telemetry(mount->manager,
                                                          mount,
                                                          "sec.limit.hit");
    }
    cep_fed_transport_security_record_limit_hit(mount);
}

static bool
cep_fed_transport_manager_security_allow(cepFedTransportManagerMount* mount,
                                         size_t payload_len)
{
    if (!mount || !mount->security_limits_valid) {
        return true;
    }
    const cepEnclavePolicyLimits* limits = &mount->security_limits;
    cepBeatNumber beat = cep_heartbeat_current();
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }

    if (limits->max_beats && mount->security_send_count >= limits->max_beats) {
        char detail[64];
        snprintf(detail, sizeof detail, "limit=%u", limits->max_beats);
        cep_fed_transport_manager_emit_limit_hit(mount, "max_beats", detail);
        return false;
    }

    if (limits->bud_io_bytes &&
        mount->security_bytes_used + payload_len > limits->bud_io_bytes) {
        char detail[64];
        snprintf(detail, sizeof detail, "limit=%" PRIu64, limits->bud_io_bytes);
        cep_fed_transport_manager_emit_limit_hit(mount, "bud_io_by", detail);
        return false;
    }

    if (limits->rate_per_edge_qps) {
        if (mount->security_rate_beat == CEP_BEAT_INVALID ||
            mount->security_rate_beat != beat) {
            mount->security_rate_beat = beat;
            mount->security_rate_count = 0u;
        }
        if (mount->security_rate_count >= limits->rate_per_edge_qps) {
            char detail[64];
            snprintf(detail, sizeof detail, "limit=%u", limits->rate_per_edge_qps);
            cep_fed_transport_manager_emit_limit_hit(mount, "per_edge_qps", detail);
            return false;
        }
    }
    return true;
}

static void
cep_fed_transport_manager_security_record_send(cepFedTransportManagerMount* mount,
                                               size_t payload_len)
{
    if (!mount || !mount->security_limits_valid) {
        return;
    }
    mount->security_send_count += 1u;
    mount->security_bytes_used += payload_len;
    if (mount->security_limits.rate_per_edge_qps) {
        cepBeatNumber beat = cep_heartbeat_current();
        if (beat == CEP_BEAT_INVALID) {
            beat = 0u;
        }
        if (mount->security_rate_beat == CEP_BEAT_INVALID ||
            mount->security_rate_beat != beat) {
            mount->security_rate_beat = beat;
            mount->security_rate_count = 0u;
        }
        if (mount->security_rate_count < UINT32_MAX) {
            ++mount->security_rate_count;
        }
    }
    cep_fed_transport_security_record_edge_event(mount, true);
}

static bool cep_fed_transport_manager_make_mount_dt(const char* name, cepDT* out) {
    if (!name || !out) {
        return false;
    }
    cepDT dt = {0};
    dt.domain = cep_namepool_intern_cstr("CEP");
    if (!dt.domain) {
        return false;
    }
    cepID word = cep_text_to_word(name);
    if (word) {
        dt.tag = word;
    } else {
        dt.tag = cep_namepool_intern_cstr(name);
    }
    if (!dt.tag) {
        return false;
    }
    *out = dt;
    return true;
}

static cepCell* cep_fed_transport_manager_ensure_mount_cell(cepFedTransportManager* manager,
                                                            const char* peer_id,
                                                            const char* mode,
                                                            const char* mount_id) {
    if (!manager || !manager->mounts_root || !peer_id || !mode || !mount_id) {
        return NULL;
    }
    if (!cep_namepool_bootstrap()) {
        return NULL;
    }

    cepCell* resolved_root = cep_cell_resolve(manager->mounts_root);
    if (!resolved_root || !cep_cell_require_dictionary_store(&resolved_root)) {
        return NULL;
    }

    cepDT peer_dt = {0};
    cepDT mode_dt = {0};
    cepDT mount_dt = {0};
    if (!cep_fed_transport_manager_make_mount_dt(peer_id, &peer_dt) ||
        !cep_fed_transport_manager_make_mount_dt(mode, &mode_dt) ||
        !cep_fed_transport_manager_make_mount_dt(mount_id, &mount_dt)) {
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
                                                 const char* tag_text,
                                                 bool value) {
    if (!parent || !field) {
        return false;
    }
    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    uint8_t bool_value = value ? 1u : 0u;
    cepCell* existing = cep_fed_schema_find_field(resolved, field, tag_text);
    if (existing) {
        return cep_cell_update(existing, sizeof bool_value, sizeof bool_value, &bool_value, false) != NULL;
    }

    cepDT field_copy = *field;
    cepDT type_dt = cep_ops_make_dt("val/bool");
    return cep_dict_add_value(resolved, &field_copy, &type_dt, &bool_value, sizeof bool_value, sizeof bool_value) != NULL;
}

static bool cep_fed_transport_manager_write_text(cepCell* parent,
                                                 const cepDT* field,
                                                 const char* tag_text,
                                                 const char* value) {
    if (!parent || !field || !value) {
        return false;
    }
    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }
    (void)tag_text;
    return cep_cell_put_text(resolved, field, value);
}

static bool cep_fed_transport_manager_write_u64(cepCell* parent,
                                                const cepDT* field,
                                                const char* tag_text,
                                                uint64_t value) {
    if (!parent || !field) {
        return false;
    }
    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepCell* existing = cep_fed_schema_find_field(resolved, field, tag_text);
    if (existing) {
        return cep_cell_update(existing, sizeof value, sizeof value, &value, false) != NULL;
    }

    cepDT field_copy = *field;
    cepDT type_dt = cep_ops_make_dt("val/u64");
    return cep_dict_add_value(resolved, &field_copy, &type_dt, &value, sizeof value, sizeof value) != NULL;
}

static cepCell* cep_fed_transport_manager_ensure_word_child(cepCell* parent, const char* word) {
    if (!parent || !word || !*word) {
        return NULL;
    }
    cepDT name = {0};
    if (!cep_fed_transport_manager_make_mount_dt(word, &name)) {
        return NULL;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, &name, CEP_STORAGE_RED_BLACK_T);
    if (!child) {
        return NULL;
    }
    child = cep_cell_resolve(child);
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return NULL;
    }
    return child;
}

static void cep_fed_transport_manager_reset_dictionary(cepCell* cell) {
    if (cell && cell->store) {
        cep_store_delete_children_hard(cell->store);
    }
}

static void cep_fed_transport_manager_compose_mount_path(const cepFedTransportManagerMount* mount,
                                                         char buffer[256]) {
    if (!mount || !buffer) {
        return;
    }
    const char* mode = mount->mount_mode ? mount->mount_mode : "link";
    snprintf(buffer,
             256,
             "/net/mounts/%s/%s/%s",
             mount->peer_id ? mount->peer_id : "",
             mode,
             mount->mount_id ? mount->mount_id : "");
}

static const char* cep_fed_transport_event_kind_text(cepFedTransportEventKind kind) {
    switch (kind) {
    case CEP_FED_TRANSPORT_EVENT_READY_RX:
        return "ready_rx";
    case CEP_FED_TRANSPORT_EVENT_BACKPRESSURE:
        return "backpressure";
    case CEP_FED_TRANSPORT_EVENT_FATAL:
        return "fatal";
    case CEP_FED_TRANSPORT_EVENT_RESET:
        return "reset";
    default:
        return "event";
    }
}

static const char* cep_fed_transport_frame_mode_text(cepFedFrameMode mode) {
    switch (mode) {
    case CEP_FED_FRAME_MODE_DATA:
        return "data";
    case CEP_FED_FRAME_MODE_UPD_LATEST:
        return "upd_latest";
    default:
        return "unknown";
    }
}

static cepCell* cep_fed_transport_manager_ensure_async_root(cepFedTransportManager* manager);
static bool cep_fed_transport_manager_refresh_async_analytics(cepFedTransportManager* manager,
                                                              cepFedTransportManagerMount* mount);

static cepFedTransportAsyncHandle* cep_fed_transport_async_handle_create(cepFedTransportManagerMount* mount,
                                                                         const char prefix[3],
                                                                         const cepDT* opcode,
                                                                         size_t expected_bytes,
                                                                         cepFedFrameMode mode,
                                                                         uint8_t frame_sample,
                                                                         bool shim);
static void cep_fed_transport_async_handle_finish(cepFedTransportAsyncHandle* handle,
                                                  bool success,
                                                  size_t bytes_done,
                                                  int error_code);
static void cep_fed_transport_async_record_send_success(cepFedTransportAsyncHandle* handle);

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
        ok = cep_fed_transport_manager_write_bool(branch_cell,
                                                  entry->getter ? entry->getter() : NULL,
                                                  entry->tag,
                                                  bit_on) && ok;
    }
    return ok;
}

static cepCell*
cep_fed_transport_manager_ensure_async_root(cepFedTransportManager* manager)
{
    if (!manager) {
        return NULL;
    }
    if (manager->analytics_async_root && manager->analytics_root) {
        return manager->analytics_async_root;
    }
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    cepCell* rt = cep_cell_ensure_dictionary_child(root, dt_rt_root_name_fed(), CEP_STORAGE_RED_BLACK_T);
    if (!rt) {
        return NULL;
    }
    rt = cep_cell_resolve(rt);
    if (!rt || !cep_cell_require_dictionary_store(&rt)) {
        return NULL;
    }
    cepCell* analytics = cep_cell_ensure_dictionary_child(rt, dt_analytics_root_name(), CEP_STORAGE_RED_BLACK_T);
    if (!analytics) {
        return NULL;
    }
    analytics = cep_cell_resolve(analytics);
    if (!analytics || !cep_cell_require_dictionary_store(&analytics)) {
        return NULL;
    }
    cepCell* async_root = cep_cell_ensure_dictionary_child(analytics, dt_async_root_name(), CEP_STORAGE_RED_BLACK_T);
    if (!async_root) {
        return NULL;
    }
    async_root = cep_cell_resolve(async_root);
    if (!async_root || !cep_cell_require_dictionary_store(&async_root)) {
        return NULL;
    }
    manager->analytics_root = analytics;
    manager->analytics_async_root = async_root;
    return manager->analytics_async_root;
}

static bool
cep_fed_transport_manager_write_async_counter(cepCell* async_root,
                                              const cepDT* branch,
                                              const char* provider,
                                              const char* mount_id,
                                              uint64_t value)
{
    if (!async_root || !branch || !provider || !mount_id) {
        return false;
    }
    cepCell* branch_cell = cep_cell_ensure_dictionary_child(async_root, branch, CEP_STORAGE_RED_BLACK_T);
    if (!branch_cell) {
        return false;
    }
    branch_cell = cep_cell_resolve(branch_cell);
    if (!branch_cell || !cep_cell_require_dictionary_store(&branch_cell)) {
        return false;
    }
    cepCell* provider_cell = cep_fed_transport_manager_ensure_word_child(branch_cell, provider);
    if (!provider_cell) {
        return false;
    }
    cepCell* mount_cell = cep_fed_transport_manager_ensure_word_child(provider_cell, mount_id);
    if (!mount_cell) {
        return false;
    }
    cep_store_delete_children_hard(mount_cell->store);
    return cep_fed_transport_manager_write_u64(mount_cell,
                                               dt_jobs_total_name(),
                                               "jobs_total",
                                               value);
}

static bool
cep_fed_transport_manager_refresh_async_analytics(cepFedTransportManager* manager,
                                                  cepFedTransportManagerMount* mount)
{
    if (!manager || !mount) {
        return true;
    }
    if (!manager->analytics_async_root) {
        manager->analytics_async_root = cep_fed_transport_manager_ensure_async_root(manager);
    }
    if (!manager->analytics_async_root) {
        return false;
    }
    const char* provider = mount->provider_id ? mount->provider_id : "provider";
    const char* mount_id = mount->mount_id ? mount->mount_id : "mount";
    bool ok = true;
    ok = cep_fed_transport_manager_write_async_counter(manager->analytics_async_root,
                                                       dt_shim_branch_name(),
                                                       provider,
                                                       mount_id,
                                                       mount->async_shim_jobs) && ok;
    ok = cep_fed_transport_manager_write_async_counter(manager->analytics_async_root,
                                                       dt_native_branch_name(),
                                                       provider,
                                                       mount_id,
                                                       mount->async_native_jobs) && ok;
    return ok;
}

static cepFedTransportAsyncHandle*
cep_fed_transport_async_handle_create(cepFedTransportManagerMount* mount,
                                      const char prefix[3],
                                      const cepDT* opcode,
                                      size_t expected_bytes,
                                      cepFedFrameMode mode,
                                      uint8_t frame_sample,
                                      bool shim)
{
    if (!mount || !opcode) {
        return NULL;
    }
    cepDT request_name = {0};
    if (!cep_fed_transport_mount_async_begin_request(mount,
                                                     prefix,
                                                     opcode,
                                                     expected_bytes,
                                                     &request_name)) {
        return NULL;
    }
    cepFedTransportAsyncHandle* handle = cep_malloc(sizeof *handle);
    if (!handle) {
        cep_fed_transport_mount_async_complete_request(mount,
                                                       &request_name,
                                                       opcode,
                                                       false,
                                                       0u,
                                                       -ENOMEM);
        return NULL;
    }
    *handle = (cepFedTransportAsyncHandle){
        .mount = mount,
        .request_name = request_name,
        .opcode = *opcode,
        .frame_mode = mode,
        .frame_sample = frame_sample,
        .expected_bytes = expected_bytes,
        .shim = shim,
        .active = true,
    };
    mount->async_pending_requests += 1u;
    return handle;
}

static void
cep_fed_transport_async_record_send_success(cepFedTransportAsyncHandle* handle)
{
    if (!handle || !handle->mount) {
        return;
    }
    cepFedTransportManagerMount* mount = handle->mount;
    ++mount->frame_count;
    mount->last_frame_mode = handle->frame_mode;
    mount->last_frame_sample = handle->frame_sample;
    if (mount->manager) {
        (void)cep_fed_transport_manager_refresh_telemetry(mount->manager,
                                                          mount,
                                                          cep_fed_transport_frame_mode_text(handle->frame_mode));
    }
}

static void
cep_fed_transport_async_handle_finish(cepFedTransportAsyncHandle* handle,
                                      bool success,
                                      size_t bytes_done,
                                      int error_code)
{
    if (!handle || !handle->active) {
        return;
    }
    cepFedTransportManagerMount* mount = handle->mount;
    if (mount->async_pending_requests > 0u) {
        mount->async_pending_requests -= 1u;
    }
    if (handle->shim) {
        mount->async_shim_jobs += 1u;
    } else {
        mount->async_native_jobs += 1u;
    }
    if (handle == mount->async_pending_handle) {
        mount->async_pending_handle = NULL;
        mount->async_pending_active = false;
        mount->async_pending_request = (cepDT){0};
        mount->async_pending_bytes = 0u;
    }
    if (handle == mount->async_receive_handle) {
        mount->async_receive_handle = NULL;
        mount->async_receive_pending = false;
        mount->async_receive_request = (cepDT){0};
    }
    cep_fed_transport_mount_async_complete_request(mount,
                                                   &handle->request_name,
                                                   &handle->opcode,
                                                   success,
                                                   bytes_done,
                                                   error_code);
    handle->active = false;
    cep_free(handle);
}
static bool cep_fed_transport_manager_refresh_catalog(cepFedTransportManager* manager,
                                                      cepFedTransportManagerMount* mount) {
    if (!manager || !mount || !manager->catalog_root) {
        return true;
    }

    cepCell* mode_cell = cep_fed_transport_manager_ensure_word_child(manager->catalog_root, mount->mount_mode ? mount->mount_mode : "link");
    if (!mode_cell) {
        return false;
    }

    cepCell* mount_cell = cep_fed_transport_manager_ensure_word_child(mode_cell, mount->mount_id);
    if (!mount_cell) {
        return false;
    }

    cep_fed_transport_manager_reset_dictionary(mount_cell);

    bool ok = true;
    ok = cep_fed_transport_manager_write_text(mount_cell, dt_peer_field_name(), "peer", mount->peer_id) && ok;
    ok = cep_fed_transport_manager_write_text(mount_cell, dt_mode_field_name(), "mode", mount->mount_mode ? mount->mount_mode : "link") && ok;
    ok = cep_fed_transport_manager_write_text(mount_cell, dt_local_node_field_name(), "local_node", mount->local_node_id) && ok;
    if (mount->provider_id) {
        ok = cep_fed_transport_manager_write_text(mount_cell, dt_provider_name(), CEP_FED_TAG_PROVIDER, mount->provider_id) && ok;
    }
    ok = cep_fed_transport_manager_write_bool(mount_cell, dt_upd_latest_name(), CEP_FED_TAG_UPD_LATEST, mount->allow_upd_latest) && ok;
    return ok;
}

static bool cep_fed_transport_manager_refresh_peer_services(cepFedTransportManager* manager,
                                                            cepFedTransportManagerMount* mount) {
    if (!manager || !mount || !manager->peers_root) {
        return true;
    }

    cepCell* peer_cell = cep_fed_transport_manager_ensure_word_child(manager->peers_root, mount->peer_id);
    if (!peer_cell) {
        return false;
    }

    cepCell* services_cell = cep_cell_ensure_dictionary_child(peer_cell, dt_services_name(), CEP_STORAGE_RED_BLACK_T);
    if (!services_cell) {
        return false;
    }
    services_cell = cep_cell_resolve(services_cell);
    if (!services_cell || !cep_cell_require_dictionary_store(&services_cell)) {
        return false;
    }

    cepCell* service_cell = cep_fed_transport_manager_ensure_word_child(services_cell, mount->mount_id);
    if (!service_cell) {
        return false;
    }

    cep_fed_transport_manager_reset_dictionary(service_cell);

    char path_buffer[256];
    cep_fed_transport_manager_compose_mount_path(mount, path_buffer);

    bool ok = true;
    ok = cep_fed_transport_manager_write_text(service_cell, dt_mode_field_name(), "mode", mount->mount_mode ? mount->mount_mode : "link") && ok;
    ok = cep_fed_transport_manager_write_text(service_cell, dt_mount_path_name(), "mount_path", path_buffer) && ok;
    ok = cep_fed_transport_manager_write_text(service_cell, dt_local_node_field_name(), "local_node", mount->local_node_id) && ok;
    if (mount->provider_id) {
        ok = cep_fed_transport_manager_write_text(service_cell, dt_provider_name(), CEP_FED_TAG_PROVIDER, mount->provider_id) && ok;
    }
    ok = cep_fed_transport_manager_write_bool(service_cell, dt_upd_latest_name(), CEP_FED_TAG_UPD_LATEST, mount->allow_upd_latest) && ok;
    return ok;
}

static bool cep_fed_transport_manager_refresh_telemetry(cepFedTransportManager* manager,
                                                        cepFedTransportManagerMount* mount,
                                                        const char* last_event) {
    if (!manager || !mount || !manager->telemetry_root) {
        return true;
    }

    cepCell* peer_cell = cep_fed_transport_manager_ensure_word_child(manager->telemetry_root, mount->peer_id);
    if (!peer_cell) {
        return false;
    }

    cepCell* mount_cell = cep_fed_transport_manager_ensure_word_child(peer_cell, mount->mount_id);
    if (!mount_cell) {
        return false;
    }

    cep_fed_transport_manager_reset_dictionary(mount_cell);

    bool ok = true;
    ok = cep_fed_transport_manager_write_text(mount_cell, dt_mode_field_name(), "mode", mount->mount_mode ? mount->mount_mode : "link") && ok;
    ok = cep_fed_transport_manager_write_text(mount_cell, dt_local_node_field_name(), "local_node", mount->local_node_id) && ok;
    if (mount->provider_id) {
        ok = cep_fed_transport_manager_write_text(mount_cell, dt_provider_name(), CEP_FED_TAG_PROVIDER, mount->provider_id) && ok;
    }
    if (last_event) {
        ok = cep_fed_transport_manager_write_text(mount_cell, dt_last_event_name(), "last_event", last_event) && ok;
    }
    ok = cep_fed_transport_manager_write_bool(mount_cell, dt_backpressured_flag_name(), CEP_FED_TAG_BP_FLAG, mount->backpressured) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_ready_count_name(), "ready_count", mount->ready_events) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_backpressure_count_name(), "bp_count", mount->backpressure_events) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_fatal_count_name(), "fatal_count", mount->fatal_events) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_frame_count_name(), "frame_count", mount->frame_count) && ok;
    ok = cep_fed_transport_manager_write_text(mount_cell, dt_last_frame_mode_name(), "last_mode", cep_fed_transport_frame_mode_text(mount->last_frame_mode)) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_last_frame_sample_name(), "last_sample", (uint64_t)mount->last_frame_sample) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_async_pending_field_name(), "async_pending", mount->async_pending_requests) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_async_shim_field_name(), "async_shim", mount->async_shim_jobs) && ok;
    ok = cep_fed_transport_manager_write_u64(mount_cell, dt_async_native_field_name(), "async_native", mount->async_native_jobs) && ok;
    if (mount->security_limits_valid) {
        ok = cep_fed_transport_manager_write_u64(mount_cell, dt_sec_send_count_name(), "sec_sends", mount->security_send_count) && ok;
        ok = cep_fed_transport_manager_write_u64(mount_cell, dt_sec_bytes_name(), "sec_bytes", mount->security_bytes_used) && ok;
        ok = cep_fed_transport_manager_write_u64(mount_cell, dt_sec_hits_name(), "sec_hits", mount->security_limit_hits) && ok;
        ok = cep_fed_transport_manager_write_u64(mount_cell, dt_sec_rate_counter_name(), "sec_rate", mount->security_rate_count) && ok;
    }
    ok = cep_fed_transport_manager_refresh_async_analytics(manager, mount) && ok;
    return ok;
}

static void cep_fed_transport_manager_update_health(cepFedTransportManager* manager,
                                                    cepFedTransportManagerMount* mount,
                                                    const cepDT* severity,
                                                    const char* note,
                                                    const char* topic) {
    if (!manager || !manager->peers_root || !mount || !topic) {
        return;
    }

    cepCell* peer_cell = cep_fed_transport_manager_ensure_word_child(manager->peers_root, mount->peer_id);
    if (!peer_cell) {
        return;
    }

    cepCell* ceh_cell = cep_cell_ensure_dictionary_child(peer_cell, dt_ceh_name(), CEP_STORAGE_RED_BLACK_T);
    if (!ceh_cell) {
        return;
    }
    ceh_cell = cep_cell_resolve(ceh_cell);
    if (!ceh_cell || !cep_cell_require_dictionary_store(&ceh_cell)) {
        return;
    }

    cepCell* topic_cell = cep_fed_transport_manager_ensure_word_child(ceh_cell, topic);
    if (!topic_cell) {
        return;
    }

    cep_fed_transport_manager_reset_dictionary(topic_cell);

    char severity_text[32] = {0};
    size_t sev_len = 0u;
    if (severity && cep_id_is_word(cep_id(severity->tag))) {
        sev_len = cep_word_to_text(cep_id(severity->tag), severity_text);
    }

    if (sev_len > 0u) {
        (void)cep_fed_transport_manager_write_text(topic_cell, dt_severity_field_name(), "severity", severity_text);
    }
    if (note) {
        (void)cep_fed_transport_manager_write_text(topic_cell, dt_note_field_name(), "note", note);
    }

    cepBeatNumber beat = cep_heartbeat_current();
    if (beat == CEP_BEAT_INVALID) {
        beat = (cepBeatNumber)cep_beat_index();
    }
    (void)cep_fed_transport_manager_write_u64(topic_cell, dt_beat_field_name(), "beat", (uint64_t)beat);
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
    if (!cep_fed_transport_manager_write_bool(caps_cell, dt_upd_latest_name(), CEP_FED_TAG_UPD_LATEST, mount->allow_upd_latest)) {
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
        if (!cep_fed_transport_manager_write_bool(transport_cell, dt_upd_latest_name(), CEP_FED_TAG_UPD_LATEST, mount->supports_upd_latest)) {
            return false;
        }
        if (!cep_fed_transport_manager_write_text(transport_cell, dt_provider_name(), CEP_FED_TAG_PROVIDER, mount->provider_id)) {
            return false;
        }
        if (!cep_fed_transport_manager_write_caps_branch(transport_cell, dt_selected_caps_name(), mount->provider ? mount->provider->caps : 0u)) {
            return false;
        }
    }

    cepCell* serializer_cell = cep_cell_ensure_dictionary_child(mount->mount_cell, dt_serializer_name(), CEP_STORAGE_RED_BLACK_T);
    if (!serializer_cell) {
        return false;
    }
    serializer_cell = cep_cell_resolve(serializer_cell);
    if (!serializer_cell || !cep_cell_require_dictionary_store(&serializer_cell)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_bool(serializer_cell, dt_ser_crc32c_ok_name(), CEP_FED_TAG_SER_CRC32C_OK, mount->flat_allow_crc32c)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_bool(serializer_cell, dt_ser_deflate_ok_name(), CEP_FED_TAG_SER_DEFLATE_OK, mount->flat_allow_deflate)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_bool(serializer_cell, dt_ser_aead_ok_name(), CEP_FED_TAG_SER_AEAD_OK, mount->flat_allow_aead)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_bool(serializer_cell, dt_ser_warn_down_name(), CEP_FED_TAG_SER_WARN_DOWN, mount->flat_warn_on_downgrade)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_u64(serializer_cell, dt_ser_cmpmax_name(), CEP_FED_TAG_SER_CMP_MAX, (uint64_t)mount->flat_comparator_max_version)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_u64(serializer_cell, dt_ser_pay_hist_name(), CEP_FED_TAG_SER_PAY_HIST, mount->payload_history_beats)) {
        return false;
    }
    if (!cep_fed_transport_manager_write_u64(serializer_cell, dt_ser_man_hist_name(), CEP_FED_TAG_SER_MAN_HIST, mount->manifest_history_beats)) {
        return false;
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
    if (mount->async_target_path) {
        cep_free(mount->async_target_path);
        mount->async_target_path = NULL;
    }
    mount->async_channel_registered = false;
    mount->async_channel_dt = (cepDT){0};
    mount->async_req_counter = 0u;
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
    uint8_t sample = (mount->pending_len > 0u && mount->pending_payload) ? mount->pending_payload[0] : 0u;
    bool sent = mount->provider->vtable->send(mount->provider_ctx,
                                              mount->channel,
                                              mount->pending_payload,
                                              mount->pending_len,
                                              CEP_FED_FRAME_MODE_UPD_LATEST,
                                              deadline_beat);
    if (sent) {
        bool recorded = false;
        if (mount->async_pending_handle) {
            cep_fed_transport_async_record_send_success(mount->async_pending_handle);
            cep_fed_transport_async_handle_finish(mount->async_pending_handle,
                                                  true,
                                                  mount->pending_len,
                                                  0);
            mount->async_pending_handle = NULL;
            recorded = true;
        } else if (mount->async_pending_active) {
            cep_fed_transport_mount_async_complete_request(mount,
                                                           &mount->async_pending_request,
                                                           dt_fed_async_opcode_send(),
                                                           true,
                                                           mount->async_pending_bytes,
                                                           0);
            mount->async_pending_active = false;
            mount->async_pending_request = (cepDT){0};
            mount->async_pending_bytes = 0u;
        }
        if (mount->pending_payload) {
            cep_free(mount->pending_payload);
            mount->pending_payload = NULL;
        }
        mount->pending_len = 0u;
        mount->backpressured = false;
        if (!recorded) {
            ++mount->frame_count;
            mount->last_frame_mode = CEP_FED_FRAME_MODE_UPD_LATEST;
            mount->last_frame_sample = sample;
        }
        if (mount->manager) {
            (void)cep_fed_transport_manager_refresh_telemetry(mount->manager,
                                                              mount,
                                                              cep_fed_transport_frame_mode_text(CEP_FED_FRAME_MODE_UPD_LATEST));
        }
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
    bool handled = true;
    if (mount->callbacks.on_frame) {
        handled = mount->callbacks.on_frame(mount->callbacks.user_ctx, mount, payload, payload_len, mode);
    }
    if (mount->async_receive_pending) {
        if (mount->async_receive_handle) {
            cep_fed_transport_async_handle_finish(mount->async_receive_handle,
                                                  handled,
                                                  handled ? payload_len : 0u,
                                                  handled ? 0 : -EIO);
            mount->async_receive_handle = NULL;
        } else {
            if (handled) {
                cep_fed_transport_mount_async_complete_request(mount,
                                                               &mount->async_receive_request,
                                                               dt_fed_async_opcode_recv(),
                                                               true,
                                                               payload_len,
                                                               0);
            } else {
                cep_fed_transport_mount_async_complete_request(mount,
                                                               &mount->async_receive_request,
                                                               dt_fed_async_opcode_recv(),
                                                               false,
                                                               0u,
                                                               -EIO);
            }
        }
        mount->async_receive_pending = false;
        mount->async_receive_request = (cepDT){0};
    }
    return handled;
}

static void cep_fed_transport_manager_on_event(void* manager_ctx,
                                               cepFedTransportChannel* channel,
                                               cepFedTransportEventKind kind,
                                               const char* detail) {
    cepFedTransportManagerMount* mount = (cepFedTransportManagerMount*)manager_ctx;
    if (!mount || channel != mount->channel) {
        return;
    }

    cepFedTransportManager* manager = mount->manager;
    const char* event_text = cep_fed_transport_event_kind_text(kind);

    switch (kind) {
    case CEP_FED_TRANSPORT_EVENT_BACKPRESSURE:
        ++mount->backpressure_events;
        mount->backpressured = true;
        if (manager) {
            const char* note = detail ? detail : "Transport backpressure signalled";
            cep_fed_transport_manager_emit_diag(manager,
                                                mount,
                                                dt_sev_warn_name(),
                                                note,
                                                CEP_FED_TOPIC_BACKPRESSURE);
            (void)cep_fed_transport_manager_refresh_telemetry(manager, mount, event_text);
        }
        break;
    case CEP_FED_TRANSPORT_EVENT_READY_RX:
    case CEP_FED_TRANSPORT_EVENT_RESET:
        if (kind == CEP_FED_TRANSPORT_EVENT_READY_RX) {
            ++mount->ready_events;
        }
        mount->backpressured = false;
        (void)cep_fed_transport_manager_flush_pending(mount, 0u);
        if (manager) {
            (void)cep_fed_transport_manager_refresh_telemetry(manager, mount, event_text);
        }
        break;
    case CEP_FED_TRANSPORT_EVENT_FATAL:
        ++mount->fatal_events;
        mount->channel_open = false;
        if (manager) {
            const char* note = detail ? detail : "Transport channel fatal event";
            cep_fed_transport_manager_emit_diag(manager,
                                                mount,
                                                dt_sev_error_name(),
                                                note,
                                                CEP_FED_TOPIC_FATAL_EVENT);
            (void)cep_fed_transport_manager_refresh_telemetry(manager, mount, event_text);
        }
        break;
    default:
        if (manager) {
            (void)cep_fed_transport_manager_refresh_telemetry(manager, mount, event_text);
        }
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

    if (!cep_fed_pack_ensure_roots(manager->net_root,
                                   &manager->peers_root,
                                   &manager->catalog_root,
                                   &manager->telemetry_root,
                                   NULL)) {
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
    if (!manager->diagnostics_mailbox) {
        return false;
    }
    manager->analytics_root = NULL;
    manager->analytics_async_root = cep_fed_transport_manager_ensure_async_root(manager);
    return manager->analytics_async_root != NULL;
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
    mount->channel_open = false;
    mount->backpressured = false;
    mount->ready_events = 0u;
    mount->backpressure_events = 0u;
    mount->fatal_events = 0u;
    mount->frame_count = 0u;
    mount->last_frame_mode = CEP_FED_FRAME_MODE_DATA;
    mount->last_frame_sample = 0u;
    mount->async_pending_requests = 0u;
    mount->async_shim_jobs = 0u;
    mount->async_native_jobs = 0u;
    mount->async_warn_emitted = false;
    mount->async_pending_handle = NULL;
    mount->async_receive_handle = NULL;
    mount->payload_history_beats = 0u;
    mount->manifest_history_beats = 0u;
    mount->flat_allow_crc32c = true;
    mount->flat_allow_deflate = true;
    mount->flat_allow_aead = true;
    mount->flat_warn_on_downgrade = true;
    mount->flat_warn_crc32c_emitted = false;
    mount->flat_warn_compression_emitted = false;
    mount->flat_warn_aead_emitted = false;
    mount->flat_comparator_max_version = UINT32_MAX;
    cep_fed_transport_manager_mount_reset_pending(mount);
    if (mount->async_target_path) {
        cep_free(mount->async_target_path);
        mount->async_target_path = NULL;
    }
    mount->async_channel_registered = false;
    mount->async_channel_dt = (cepDT){0};
    mount->async_req_counter = 0u;
    mount->async_pending_active = false;
    mount->async_pending_request = (cepDT){0};
    mount->async_pending_bytes = 0u;
    mount->async_receive_pending = false;
    mount->async_receive_request = (cepDT){0};
    mount->security_limits_valid = config->security_limits_valid;
    if (config->security_limits_valid) {
        mount->security_limits = config->security_limits;
    } else {
        memset(&mount->security_limits, 0, sizeof mount->security_limits);
    }
    mount->security_bytes_used = 0u;
    mount->security_send_count = 0u;
    mount->security_limit_hits = 0u;
    mount->security_rate_beat = CEP_BEAT_INVALID;
    mount->security_rate_count = 0u;
    (void)cep_fed_transport_mount_prepare_async_target(mount);

    const char* provider_id = NULL;
    const cepFedTransportProvider* provider = NULL;
    void* provider_ctx = NULL;

    if (!cep_fed_transport_manager_select_provider(config, &provider_id, &provider, &provider_ctx)) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "No transport provider satisfies mount requirements",
                                            CEP_FED_TOPIC_NO_PROVIDER);
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
                                            CEP_FED_TOPIC_SCHEMA);
        return false;
    }

    if (!cep_fed_transport_manager_update_mount_schema(mount)) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Failed to update mount schema with provider selection",
                                            CEP_FED_TOPIC_SCHEMA_UPDATE);
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
                                            CEP_FED_TOPIC_PROVIDER_ID);
        return false;
    }

    cepCell* provider_cell = cep_cell_ensure_dictionary_child(manager->transports_root, &provider_dt, CEP_STORAGE_RED_BLACK_T);
    if (!provider_cell) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Provider cell missing in transport registry",
                                            CEP_FED_TOPIC_PROVIDER_CELL);
        return false;
    }

    provider_cell = cep_cell_resolve(provider_cell);
    if (!provider_cell || !cep_cell_require_dictionary_store(&provider_cell)) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Provider cell unavailable for open request",
                                            CEP_FED_TOPIC_PROVIDER_CELL);
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
                                            CEP_FED_TOPIC_OPEN_FAILED);
        return false;
    }

    mount->channel = opened_channel;
    mount->channel_open = (opened_channel != NULL);
    mount->backpressured = false;

    if (!cep_fed_transport_manager_refresh_catalog(manager, mount) ||
        !cep_fed_transport_manager_refresh_peer_services(manager, mount) ||
        !cep_fed_transport_manager_refresh_telemetry(manager, mount, "open")) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_error_name(),
                                            "Failed to publish federation catalog or telemetry branches",
                                            CEP_FED_TOPIC_CATALOG_SYNC);
        cep_fed_transport_manager_close(manager, mount, "catalog-sync-failed");
        return false;
    }

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

    if (!cep_fed_transport_manager_security_allow(mount, payload_len)) {
        return false;
    }

    bool security_recorded = false;

    if (mode == CEP_FED_FRAME_MODE_UPD_LATEST && !mount->allow_upd_latest) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_warn_name(),
                                            "upd_latest frame rejected because mount does not opt in",
                                            CEP_FED_TOPIC_UPD_DENIED);
        return false;
    }

    if (mode == CEP_FED_FRAME_MODE_UPD_LATEST && !mount->supports_upd_latest) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_warn_name(),
                                            "upd_latest frame sent to provider without unreliable support",
                                            CEP_FED_TOPIC_UPD_MISUSE);
    }

    cepFedTransportManager* owning_manager = mount->manager;
    bool provider_async = mount->provider && mount->provider->vtable && mount->provider->vtable->send_async;
    uint8_t frame_sample = payload_len > 0u ? payload[0] : 0u;
    cepFedTransportAsyncHandle* async_handle = NULL;
    if (mount->provider && mount->channel && mount->provider->vtable && payload_len > 0u) {
        async_handle = cep_fed_transport_async_handle_create(mount,
                                                             "fs",
                                                             dt_fed_async_opcode_send(),
                                                             payload_len,
                                                             mode,
                                                             frame_sample,
                                                             !provider_async);
    }

    if (provider_async && async_handle) {
        if (mount->provider->vtable->send_async(mount->provider_ctx,
                                                mount->channel,
                                                payload,
                                                payload_len,
                                                mode,
                                                deadline_beat,
                                                async_handle)) {
            if (!security_recorded) {
                cep_fed_transport_manager_security_record_send(mount, payload_len);
                security_recorded = true;
            }
            return true;
        }
        async_handle->shim = true;
    } else if (!provider_async && async_handle && !mount->async_warn_emitted) {
        cep_fed_transport_manager_emit_diag(manager,
                                            mount,
                                            dt_sev_warn_name(),
                                            "Transport lacks async send support; using shim",
                                            CEP_FED_TOPIC_ASYNC_UNSUPPORTED);
        mount->async_warn_emitted = true;
    }

    bool immediate_sent = false;

    if (mode == CEP_FED_FRAME_MODE_UPD_LATEST && mount->supports_upd_latest) {
        if (mount->backpressured) {
            uint8_t* snapshot = cep_malloc(payload_len);
            memcpy(snapshot, payload, payload_len);
            cep_fed_transport_mount_async_cancel_pending(mount, -ECANCELED);
            if (async_handle) {
                mount->async_pending_handle = async_handle;
                mount->async_pending_request = async_handle->request_name;
                mount->async_pending_active = true;
                mount->async_pending_bytes = payload_len;
                async_handle = NULL;
            }
            if (mount->pending_payload) {
                cep_free(mount->pending_payload);
            }
            mount->pending_payload = snapshot;
            mount->pending_len = payload_len;
            if (owning_manager) {
                (void)cep_fed_transport_manager_refresh_telemetry(owning_manager,
                                                                   mount,
                                                                   "backpressure");
            }
            if (!security_recorded) {
                cep_fed_transport_manager_security_record_send(mount, payload_len);
                security_recorded = true;
            }
            return true;
        }
        immediate_sent = mount->provider->vtable->send(mount->provider_ctx,
                                                       mount->channel,
                                                       payload,
                                                       payload_len,
                                                       mode,
                                                       deadline_beat);
        if (!immediate_sent) {
            uint8_t* snapshot = cep_malloc(payload_len);
            memcpy(snapshot, payload, payload_len);
            cep_fed_transport_mount_async_cancel_pending(mount, -ECANCELED);
            if (async_handle) {
                mount->async_pending_handle = async_handle;
                mount->async_pending_request = async_handle->request_name;
                mount->async_pending_active = true;
                mount->async_pending_bytes = payload_len;
                async_handle = NULL;
            }
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
                                                CEP_FED_TOPIC_BACKPRESSURE);
            if (owning_manager) {
                (void)cep_fed_transport_manager_refresh_telemetry(owning_manager,
                                                                   mount,
                                                                   "backpressure");
            }
            if (!security_recorded) {
                cep_fed_transport_manager_security_record_send(mount, payload_len);
                security_recorded = true;
            }
            return true;
        }
    } else {
        immediate_sent = mount->provider->vtable->send(mount->provider_ctx,
                                                       mount->channel,
                                                       payload,
                                                       payload_len,
                                                       mode,
                                                       deadline_beat);
        if (!immediate_sent) {
            if (async_handle) {
                cep_fed_transport_async_handle_finish(async_handle,
                                                      false,
                                                      0u,
                                                      -EIO);
                async_handle = NULL;
            }
            cep_fed_transport_manager_emit_diag(manager,
                                                mount,
                                                dt_sev_error_name(),
                                                "Transport provider failed to send frame",
                                                CEP_FED_TOPIC_SEND_FAILED);
            return false;
        }
    }

    if (immediate_sent) {
        if (async_handle) {
            cep_fed_transport_async_record_send_success(async_handle);
            cep_fed_transport_async_handle_finish(async_handle,
                                                  true,
                                                  payload_len,
                                                  0);
        } else {
            ++mount->frame_count;
            mount->last_frame_mode = mode;
            mount->last_frame_sample = frame_sample;
            if (owning_manager) {
                (void)cep_fed_transport_manager_refresh_telemetry(owning_manager,
                                                                   mount,
                                                                   cep_fed_transport_frame_mode_text(mode));
            }
        }
    }

    if (!security_recorded) {
        cep_fed_transport_manager_security_record_send(mount, payload_len);
        security_recorded = true;
    }
    return true;
}

/* cep_fed_transport_manager_request_receive bridges the provider's receive hook so
   mounts can ask for more input frames without touching the provider vtable directly. */
bool cep_fed_transport_manager_request_receive(cepFedTransportManager* manager,
                                               cepFedTransportManagerMount* mount) {
    if (!manager || !mount || !mount->provider || !mount->channel || !mount->provider->vtable || !mount->provider->vtable->request_receive) {
        return false;
    }
    bool provider_async = mount->provider->vtable->request_receive_async != NULL;
    cepFedTransportAsyncHandle* async_handle = cep_fed_transport_async_handle_create(mount,
                                                                                     "fr",
                                                                                     dt_fed_async_opcode_recv(),
                                                                                     0u,
                                                                                     CEP_FED_FRAME_MODE_DATA,
                                                                                     0u,
                                                                                     !provider_async);
    if (provider_async && async_handle) {
        if (mount->provider->vtable->request_receive_async(mount->provider_ctx,
                                                           mount->channel,
                                                           async_handle)) {
            if (mount->async_receive_pending) {
                cep_fed_transport_mount_async_cancel_receive(mount, -ECANCELED);
            }
            mount->async_receive_pending = true;
            mount->async_receive_request = async_handle->request_name;
            mount->async_receive_handle = async_handle;
            return true;
        }
        async_handle->shim = true;
    }

    bool requested = mount->provider->vtable->request_receive(mount->provider_ctx, mount->channel);
    if (!requested) {
        if (async_handle) {
            cep_fed_transport_async_handle_finish(async_handle,
                                                  false,
                                                  0u,
                                                  -EIO);
        }
        return false;
    }
    if (async_handle) {
        if (mount->async_receive_pending) {
            cep_fed_transport_mount_async_cancel_receive(mount, -ECANCELED);
        }
        mount->async_receive_pending = true;
        mount->async_receive_request = async_handle->request_name;
        mount->async_receive_handle = async_handle;
    }
    return true;
}

/* cep_fed_transport_manager_close closes the active provider channel while keeping the
   mount registration intact, letting callers re-open after policy changes. */
bool cep_fed_transport_manager_close(cepFedTransportManager* manager,
                                     cepFedTransportManagerMount* mount,
                                     const char* reason) {
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
    if (manager) {
        (void)cep_fed_transport_manager_refresh_telemetry(manager, mount, "close");
    }
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

void cep_fed_transport_async_send_complete(cepFedTransportAsyncHandle* handle,
                                           bool success,
                                           size_t bytes_done,
                                           int error_code)
{
    if (!handle) {
        return;
    }
    if (success) {
        cep_fed_transport_async_record_send_success(handle);
    }
    cep_fed_transport_async_handle_finish(handle, success, bytes_done, error_code);
}

void cep_fed_transport_async_receive_ready(cepFedTransportAsyncHandle* handle,
                                           bool success,
                                           size_t bytes_ready,
                                           int error_code)
{
    if (!handle) {
        return;
    }
    cep_fed_transport_async_handle_finish(handle, success, bytes_ready, error_code);
}

bool cep_fed_transport_manager_send_cell(cepFedTransportManager* manager,
                                         cepFedTransportManagerMount* mount,
                                         const cepCell* cell,
                                         const cepSerializationHeader* header,
                                         size_t blob_payload_bytes,
                                         cepFedFrameMode mode,
                                         uint64_t deadline_beat) {
    if (!manager || !mount || !cell) {
        return false;
    }

    cepFedTransportCaps provider_caps = (mount && mount->provider)
        ? mount->provider->caps
        : 0u;
    bool provider_crc32c = (provider_caps & CEP_FED_TRANSPORT_CAP_CHECKSUM_CRC32C) != 0u;
    bool provider_deflate = (provider_caps & CEP_FED_TRANSPORT_CAP_COMPRESSION_DEFLATE) != 0u;
    bool provider_aead = (provider_caps & CEP_FED_TRANSPORT_CAP_ENCRYPTION_AEAD) != 0u;

    const char* compression_env = getenv("CEP_SERIALIZATION_FLAT_COMPRESSION");
    bool compression_requested = compression_env && strcasecmp(compression_env, "deflate") == 0;
    const char* aead_env = getenv("CEP_SERIALIZATION_FLAT_AEAD_MODE");
    bool aead_requested = aead_env && *aead_env && strcasecmp(aead_env, "none") != 0;
    const char* crc_env = getenv("CEP_CRC32C_MODE");

    bool compression_allowed = mount->flat_allow_deflate && provider_deflate;
    bool aead_allowed = mount->flat_allow_aead && provider_aead;
    bool crc_allowed = mount->flat_allow_crc32c && provider_crc32c;

    char* prev_payload_hist = NULL;
    char* prev_manifest_hist = NULL;
    char* prev_compression = NULL;
    char* prev_aead_mode = NULL;
    char* prev_comparator_max = NULL;
    char* prev_checksum_mode = NULL;
    bool env_ok = true;
    bool downgraded_compression = false;
    bool downgraded_aead = false;
    bool downgraded_crc = false;
    if (mount->payload_history_beats > 0u) {
        env_ok = cep_fed_env_push_override("CEP_SERIALIZATION_FLAT_PAYLOAD_HISTORY_BEATS",
                                           mount->payload_history_beats,
                                           &prev_payload_hist);
    }
    if (env_ok && mount->manifest_history_beats > 0u) {
        env_ok = cep_fed_env_push_override("CEP_SERIALIZATION_FLAT_MANIFEST_HISTORY_BEATS",
                                           mount->manifest_history_beats,
                                           &prev_manifest_hist);
    }
    if (env_ok && mount->flat_comparator_max_version != UINT32_MAX) {
        env_ok = cep_fed_env_push_override("CEP_SERIALIZATION_FLAT_MAX_COMPARATOR_VERSION",
                                           mount->flat_comparator_max_version,
                                           &prev_comparator_max);
    }
    const char* downgraded_crc_note = NULL;
    const char* downgraded_compression_note = NULL;
    const char* downgraded_aead_note = NULL;

    if (env_ok && compression_requested && !compression_allowed) {
        env_ok = cep_fed_env_push_text_override("CEP_SERIALIZATION_FLAT_COMPRESSION",
                                                "none",
                                                &prev_compression);
        if (env_ok) {
            downgraded_compression = true;
            downgraded_compression_note = provider_deflate
                ? "Peer lacks deflate capability; disabling frame compression"
                : "Transport provider lacks deflate capability; disabling frame compression";
        }
    }
    if (env_ok && aead_requested && !aead_allowed) {
        env_ok = cep_fed_env_push_text_override("CEP_SERIALIZATION_FLAT_AEAD_MODE",
                                                "none",
                                                &prev_aead_mode);
        if (env_ok) {
            downgraded_aead = true;
            downgraded_aead_note = provider_aead
                ? "Peer rejected AEAD capability; sending plaintext payloads"
                : "Transport provider lacks AEAD capability; sending plaintext payloads";
        }
    }
    if (env_ok && !crc_allowed) {
        bool crc_env_cast = crc_env && *crc_env && strcasecmp(crc_env, "castagnoli") == 0;
        env_ok = cep_fed_env_push_text_override("CEP_SERIALIZATION_FLAT_CHECKSUM",
                                                "crc32",
                                                &prev_checksum_mode);
        if (env_ok && crc_env_cast) {
            downgraded_crc = true;
            if (!mount->flat_allow_crc32c) {
                downgraded_crc_note = "Peer cannot ingest CRC32C capability; forcing IEEE CRC32";
            } else if (!provider_crc32c) {
                downgraded_crc_note = "Transport provider lacks CRC32C capability; forcing IEEE CRC32";
            }
        }
    }
    if (!env_ok) {
        cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_PAYLOAD_HISTORY_BEATS", prev_payload_hist);
        cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_MANIFEST_HISTORY_BEATS", prev_manifest_hist);
        cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_MAX_COMPARATOR_VERSION", prev_comparator_max);
        cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_COMPRESSION", prev_compression);
        cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_AEAD_MODE", prev_aead_mode);
        cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_CHECKSUM", prev_checksum_mode);
        return false;
    }

    cepFedFrameBuffer buffer = {0};
    bool emitted = cep_flat_stream_emit_cell(cell,
                                             header,
                                             (cepFlatStreamWriteFn)cep_fed_frame_capture_sink,
                                             &buffer,
                                             blob_payload_bytes);
    cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_PAYLOAD_HISTORY_BEATS", prev_payload_hist);
    cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_MANIFEST_HISTORY_BEATS", prev_manifest_hist);
    cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_MAX_COMPARATOR_VERSION", prev_comparator_max);
    cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_COMPRESSION", prev_compression);
    cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_AEAD_MODE", prev_aead_mode);
    cep_fed_env_pop_override("CEP_SERIALIZATION_FLAT_CHECKSUM", prev_checksum_mode);
    if (!emitted || buffer.size == 0u) {
        cep_fed_frame_buffer_reset(&buffer);
        return false;
    }

    bool sent = cep_fed_transport_manager_send(manager,
                                               mount,
                                               buffer.data,
                                               buffer.size,
                                               mode,
                                               deadline_beat);
    cep_fed_frame_buffer_reset(&buffer);
    if (downgraded_crc) {
        const char* note = downgraded_crc_note
            ? downgraded_crc_note
            : "CRC32C capability disabled; forcing IEEE CRC32";
        cep_fed_transport_manager_warn_flat_downgrade(manager,
                                                      mount,
                                                      &mount->flat_warn_crc32c_emitted,
                                                      note);
    }
    if (downgraded_compression) {
        const char* note = downgraded_compression_note
            ? downgraded_compression_note
            : "Frame compression unavailable; disabling deflate";
        cep_fed_transport_manager_warn_flat_downgrade(manager,
                                                      mount,
                                                      &mount->flat_warn_compression_emitted,
                                                      note);
    }
    if (downgraded_aead) {
        const char* note = downgraded_aead_note
            ? downgraded_aead_note
            : "AEAD unavailable; sending plaintext payloads";
        cep_fed_transport_manager_warn_flat_downgrade(manager,
                                                      mount,
                                                      &mount->flat_warn_aead_emitted,
                                                      note);
    }
    return sent;
}

void cep_fed_transport_manager_mount_set_flat_history(cepFedTransportManagerMount* mount,
                                                      uint32_t payload_history_beats,
                                                      uint32_t manifest_history_beats) {
    if (!mount) {
        return;
    }
    mount->payload_history_beats = payload_history_beats;
    mount->manifest_history_beats = manifest_history_beats;
    if (mount->manager) {
        (void)cep_fed_transport_manager_update_mount_schema(mount);
    }
}

void cep_fed_transport_manager_mount_set_flat_policy(cepFedTransportManagerMount* mount,
                                                     const cepFedTransportFlatPolicy* policy) {
    if (!mount) {
        return;
    }
    if (!policy) {
        mount->flat_allow_crc32c = true;
        mount->flat_allow_deflate = true;
        mount->flat_allow_aead = true;
        mount->flat_warn_on_downgrade = true;
        mount->flat_comparator_max_version = UINT32_MAX;
    } else {
        mount->flat_allow_crc32c = policy->allow_crc32c;
        mount->flat_allow_deflate = policy->allow_deflate;
        mount->flat_allow_aead = policy->allow_aead;
        mount->flat_warn_on_downgrade = policy->warn_on_downgrade;
        mount->flat_comparator_max_version = policy->comparator_max_version;
    }
    mount->flat_warn_crc32c_emitted = false;
    mount->flat_warn_compression_emitted = false;
    mount->flat_warn_aead_emitted = false;
    if (mount->manager) {
        (void)cep_fed_transport_manager_update_mount_schema(mount);
    }
}

void
cep_fed_transport_manager_mount_set_pipeline_metadata(cepFedTransportManagerMount* mount,
                                                      const char* pipeline_id,
                                                      const char* stage_id,
                                                      uint64_t dag_run_id,
                                                      uint64_t hop_index)
{
    if (!mount) {
        return;
    }
    bool has_metadata = false;
    if (pipeline_id && *pipeline_id) {
        snprintf(mount->pipeline_label, sizeof mount->pipeline_label, "%s", pipeline_id);
        has_metadata = true;
    } else {
        mount->pipeline_label[0] = '\0';
    }
    if (stage_id && *stage_id) {
        snprintf(mount->stage_label, sizeof mount->stage_label, "%s", stage_id);
        has_metadata = true;
    } else {
        mount->stage_label[0] = '\0';
    }
    mount->pipeline_run_id = dag_run_id;
    mount->pipeline_hop_index = hop_index;
    if (dag_run_id || hop_index) {
        has_metadata = true;
    }
    mount->pipeline_metadata_known = has_metadata;
}
static bool cep_fed_env_push_override(const char* name,
                                      uint32_t value,
                                      char** previous_copy) {
    if (!name) {
        if (previous_copy)
            *previous_copy = NULL;
        return false;
    }
    const char* current = getenv(name);
    if (previous_copy) {
        *previous_copy = current ? strdup(current) : NULL;
    }
    char buf[32];
    int written = snprintf(buf, sizeof buf, "%u", value);
    if (written < 0 || (size_t)written >= sizeof buf) {
        return false;
    }
    return setenv(name, buf, 1) == 0;
}

static bool cep_fed_env_push_text_override(const char* name,
                                           const char* value,
                                           char** previous_copy) {
    if (!name || !value) {
        if (previous_copy) {
            *previous_copy = NULL;
        }
        return false;
    }
    const char* current = getenv(name);
    if (previous_copy) {
        *previous_copy = current ? strdup(current) : NULL;
    }
    return setenv(name, value, 1) == 0;
}

static void cep_fed_env_pop_override(const char* name, char* previous_copy) {
    if (!name)
        return;
    if (previous_copy) {
        setenv(name, previous_copy, 1);
        free(previous_copy);
    } else {
        unsetenv(name);
    }
}

static void cep_fed_transport_manager_warn_flat_downgrade(cepFedTransportManager* manager,
                                                          cepFedTransportManagerMount* mount,
                                                          bool* warned_flag,
                                                          const char* note) {
    if (!manager || !mount || !warned_flag || !note) {
        return;
    }
    if (!mount->flat_warn_on_downgrade || *warned_flag) {
        return;
    }
    cep_fed_transport_manager_emit_diag(manager,
                                        mount,
                                        dt_sev_warn_name(),
                                        note,
                                        CEP_FED_TOPIC_FLAT_NEGOTIATION);
    *warned_flag = true;
}

static bool cep_fed_transport_mount_prepare_async_target(cepFedTransportManagerMount* mount) {
    if (!mount) {
        return false;
    }
    if (mount->async_target_path) {
        return true;
    }
    if (!mount->peer_id || !mount->mount_mode || !mount->mount_id) {
        return false;
    }
    int needed = snprintf(NULL, 0, "/net/mounts/%s/%s/%s", mount->peer_id, mount->mount_mode, mount->mount_id);
    if (needed <= 0) {
        return false;
    }
    size_t size = (size_t)needed + 1u;
    char* path = cep_malloc(size);
    if (!path) {
        return false;
    }
    snprintf(path, size, "/net/mounts/%s/%s/%s", mount->peer_id, mount->mount_mode, mount->mount_id);
    mount->async_target_path = path;
    return true;
}

static cepDT cep_fed_transport_mount_next_request_dt(cepFedTransportManagerMount* mount,
                                                     const char prefix[3]) {
    char tag[12] = {0};
    uint32_t suffix = (uint32_t)(mount->async_req_counter++ % 1000000u);
    if (prefix && prefix[0] && prefix[1]) {
        snprintf(tag, sizeof tag, "%c%c%06u", prefix[0], prefix[1], suffix);
    } else {
        snprintf(tag, sizeof tag, "fx%06u", suffix);
    }
    return cep_ops_make_dt(tag);
}

static void cep_fed_transport_mount_async_complete_request(cepFedTransportManagerMount* mount,
                                                           const cepDT* request_name,
                                                           const cepDT* opcode,
                                                           bool success,
                                                           size_t bytes_done,
                                                           int error_code) {
    if (!mount || !request_name || !opcode || !cep_dt_is_valid(request_name)) {
        return;
    }
    cepOpsAsyncIoReqInfo info = {
        .state = success ? *dt_fed_async_state_ok() : *dt_fed_async_state_fail(),
        .channel = mount->async_channel_dt,
        .opcode = *opcode,
    };
    if (bytes_done > 0u) {
        info.has_bytes_done = true;
        info.bytes_done = bytes_done;
    }
    if (!success) {
        info.has_errno = true;
        info.errno_code = error_code;
    }
    (void)cep_async_post_completion(cep_async_ops_oid(), request_name, &info);
}

static void cep_fed_transport_mount_async_cancel_pending(cepFedTransportManagerMount* mount, int error_code) {
    if (!mount || !mount->async_pending_active) {
        return;
    }
    if (mount->async_pending_handle) {
        cep_fed_transport_async_handle_finish(mount->async_pending_handle,
                                              false,
                                              mount->async_pending_bytes,
                                              error_code);
        mount->async_pending_handle = NULL;
        mount->async_pending_active = false;
        mount->async_pending_request = (cepDT){0};
        mount->async_pending_bytes = 0u;
        return;
    }
    cep_fed_transport_mount_async_complete_request(mount,
                                                   &mount->async_pending_request,
                                                   dt_fed_async_opcode_send(),
                                                   false,
                                                   mount->async_pending_bytes,
                                                   error_code);
    mount->async_pending_active = false;
    mount->async_pending_request = (cepDT){0};
    mount->async_pending_bytes = 0u;
}

static void cep_fed_transport_mount_async_cancel_receive(cepFedTransportManagerMount* mount, int error_code) {
    if (!mount || !mount->async_receive_pending) {
        return;
    }
    if (mount->async_receive_handle) {
        cep_fed_transport_async_handle_finish(mount->async_receive_handle,
                                              false,
                                              0u,
                                              error_code);
        mount->async_receive_handle = NULL;
        mount->async_receive_pending = false;
        mount->async_receive_request = (cepDT){0};
        return;
    }
    cep_fed_transport_mount_async_complete_request(mount,
                                                   &mount->async_receive_request,
                                                   dt_fed_async_opcode_recv(),
                                                   false,
                                                   0u,
                                                   error_code);
    mount->async_receive_pending = false;
    mount->async_receive_request = (cepDT){0};
}

static void cep_fed_transport_mount_async_ensure_channel(cepFedTransportManagerMount* mount) {
    if (!mount || mount->async_channel_registered) {
        return;
    }
    if (!cep_dt_is_valid(&mount->async_channel_dt)) {
        uintptr_t ptr = (uintptr_t)mount;
        unsigned hash = (unsigned)((ptr >> 4) & 0xFFFFFFu);
        char tag[12];
        snprintf(tag, sizeof tag, "fc%06X", hash);
        mount->async_channel_dt = cep_ops_make_dt(tag);
    }
    if (!cep_fed_transport_mount_prepare_async_target(mount)) {
        return;
    }
    cepOpsAsyncChannelInfo info = {
        .target_path = mount->async_target_path,
        .has_target_path = (mount->async_target_path != NULL),
        .provider = *dt_fed_async_provider(),
        .has_provider = true,
        .reactor = *dt_fed_async_reactor(),
        .has_reactor = true,
        .caps = *dt_fed_async_caps(),
        .has_caps = true,
        .shim = true,
        .shim_known = true,
    };
    if (cep_async_register_channel(cep_async_ops_oid(), &mount->async_channel_dt, &info)) {
        mount->async_channel_registered = true;
    }
}

static bool cep_fed_transport_mount_async_begin_request(cepFedTransportManagerMount* mount,
                                                        const char prefix[3],
                                                        const cepDT* opcode,
                                                        size_t expected_bytes,
                                                        cepDT* out_name) {
    if (!mount || !opcode || !out_name) {
        return false;
    }
    cep_fed_transport_mount_async_ensure_channel(mount);
    if (!mount->async_channel_registered) {
        return false;
    }
    *out_name = cep_fed_transport_mount_next_request_dt(mount, prefix);
    cepOpsAsyncIoReqInfo info = {
        .state = *dt_fed_async_state_exec(),
        .channel = mount->async_channel_dt,
        .opcode = *opcode,
        .has_beats_budget = true,
        .beats_budget = 1u,
    };
    if (expected_bytes > 0u) {
        info.has_bytes_expected = true;
        info.bytes_expected = expected_bytes;
    }
    return cep_async_register_request(cep_async_ops_oid(), out_name, &info);
}
