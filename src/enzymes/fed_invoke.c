/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "fed_invoke.h"

#include "fed_transport.h"

#include "../l0_kernel/cep_cei.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_peer_field_name,       CEP_ACRO("CEP"), CEP_WORD("peer"));
CEP_DEFINE_STATIC_DT(dt_mount_field_name,      CEP_ACRO("CEP"), CEP_WORD("mount"));
CEP_DEFINE_STATIC_DT(dt_local_node_field_name, CEP_ACRO("CEP"), CEP_WORD("local_node"));
CEP_DEFINE_STATIC_DT(dt_pref_provider_name,    CEP_ACRO("CEP"), CEP_WORD("pref_prov"));
CEP_DEFINE_STATIC_DT(dt_state_field_name,      CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_error_field_name,      CEP_ACRO("CEP"), CEP_WORD("error_note"));
CEP_DEFINE_STATIC_DT(dt_provider_field_name,   CEP_ACRO("CEP"), CEP_WORD("provider"));
CEP_DEFINE_STATIC_DT(dt_caps_name,             CEP_ACRO("CEP"), CEP_WORD("caps"));
CEP_DEFINE_STATIC_DT(dt_required_caps_name,    CEP_ACRO("CEP"), CEP_WORD("required"));
CEP_DEFINE_STATIC_DT(dt_preferred_caps_name,   CEP_ACRO("CEP"), CEP_WORD("preferred"));
CEP_DEFINE_STATIC_DT(dt_deadline_field_name,   CEP_ACRO("CEP"), CEP_WORD("deadline"));
CEP_DEFINE_STATIC_DT(dt_serializer_name,       CEP_ACRO("CEP"), CEP_WORD("serializer"));
CEP_DEFINE_STATIC_DT(dt_ser_crc32c_ok_name,    CEP_ACRO("CEP"), CEP_WORD("crc32c_ok"));
CEP_DEFINE_STATIC_DT(dt_ser_deflate_ok_name,   CEP_ACRO("CEP"), CEP_WORD("deflate_ok"));
CEP_DEFINE_STATIC_DT(dt_ser_aead_ok_name,      CEP_ACRO("CEP"), CEP_WORD("aead_ok"));
CEP_DEFINE_STATIC_DT(dt_ser_warn_down_name,    CEP_ACRO("CEP"), CEP_WORD("warn_down"));
CEP_DEFINE_STATIC_DT(dt_ser_cmpmax_name,       CEP_ACRO("CEP"), CEP_WORD("cmp_max_ver"));
CEP_DEFINE_STATIC_DT(dt_ser_pay_hist_name,     CEP_ACRO("CEP"), CEP_WORD("pay_hist_bt"));
CEP_DEFINE_STATIC_DT(dt_ser_man_hist_name,     CEP_ACRO("CEP"), CEP_WORD("man_hist_bt"));

CEP_DEFINE_STATIC_DT(dt_cap_reliable_name,     CEP_ACRO("CEP"), CEP_WORD("reliable"));
CEP_DEFINE_STATIC_DT(dt_cap_ordered_name,      CEP_ACRO("CEP"), CEP_WORD("ordered"));
CEP_DEFINE_STATIC_DT(dt_cap_streaming_name,    CEP_ACRO("CEP"), CEP_WORD("streaming"));
CEP_DEFINE_STATIC_DT(dt_cap_datagram_name,     CEP_ACRO("CEP"), CEP_WORD("datagram"));
CEP_DEFINE_STATIC_DT(dt_cap_multicast_name,    CEP_ACRO("CEP"), CEP_WORD("multicast"));
CEP_DEFINE_STATIC_DT(dt_cap_latency_name,      CEP_ACRO("CEP"), CEP_WORD("low_latency"));
CEP_DEFINE_STATIC_DT(dt_cap_local_ipc_name,    CEP_ACRO("CEP"), CEP_WORD("local_ipc"));
CEP_DEFINE_STATIC_DT(dt_cap_remote_net_name,   CEP_ACRO("CEP"), CEP_WORD("remote_net"));
CEP_DEFINE_STATIC_DT(dt_cap_unreliable_name,   CEP_ACRO("CEP"), CEP_WORD("unreliable"));

typedef struct cepFedInvokeRequest {
    cepCell*                       request_cell;
    cepPath*                       request_path;
    cepFedTransportManagerMount*   mount;
    struct cepFedInvokeRequest*    next;
    char                           peer_id[64];
    char                           mount_id[64];
    char                           local_node[64];
    cepFedTransportCaps            required_caps;
    cepFedTransportCaps            preferred_caps;
    bool                           allow_upd_latest;
    bool                           has_deadline;
    uint64_t                       deadline;
    cepFedTransportFlatPolicy      flat_policy;
    uint32_t                       payload_history_beats;
    uint32_t                       manifest_history_beats;
} cepFedInvokeRequest;

typedef struct cepFedInvokePending {
    uint64_t                     id;
    const cepFedInvokeRequest*   request;
    cepBeatNumber                deadline;
    cepFedInvokeCompletion       on_complete;
    void*                        user_ctx;
    struct cepFedInvokePending*  next;
} cepFedInvokePending;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[1];
} cepFedInvokePathBuf;

typedef struct {
    uint16_t domain_length;
    uint16_t tag_length;
    uint8_t  domain_kind;
    uint8_t  tag_kind;
    uint16_t reserved;
    uint64_t timestamp;
} cepFedInvokeFrameSegmentHeader;

enum {
    CEP_FED_INVOKE_ID_KIND_INVALID   = 0u,
    CEP_FED_INVOKE_ID_KIND_REFERENCE = 1u,
    CEP_FED_INVOKE_ID_KIND_WORD      = 2u,
    CEP_FED_INVOKE_ID_KIND_ACRONYM   = 3u,
    CEP_FED_INVOKE_ID_KIND_NUMERIC   = 4u,
};

enum {
    CEP_FED_INVOKE_FRAME_REQUEST  = 0x01,
    CEP_FED_INVOKE_FRAME_RESPONSE = 0x02,
};

enum {
    CEP_FED_INVOKE_STATUS_OK     = 0x00,
    CEP_FED_INVOKE_STATUS_REJECT = 0x01,
};

static cepFedTransportManager* g_invoke_manager = NULL;
static cepCell*                g_invoke_net_root = NULL;
static cepFedInvokeRequest*    g_invoke_requests = NULL;
static cepFedInvokePending*    g_invoke_pending = NULL;
static uint64_t                g_invoke_next_id = 1u;

static const char* const CEP_FED_INVOKE_MODE            = "invoke";
static const char* const CEP_FED_INVOKE_TOPIC_TIMEOUT   = "tp_inv_timeout";
static const char* const CEP_FED_INVOKE_TOPIC_REJECT    = "tp_inv_reject";
static const char* const CEP_FED_INVOKE_TIMEOUT_NOTE    = "remote invocation timed out";
static const char* const CEP_FED_INVOKE_REJECT_NOTE     = "remote invocation rejected";
static const char* const CEP_FED_INVOKE_SCHEMA_NOTE     = "invoke request deadline expired before activation";
static const char* const CEP_FED_INVOKE_INVALID_PEER_NOTE = "invoke request peer identifier exceeds CEP word limits";
static const char* const CEP_FED_INVOKE_INVALID_MOUNT_NOTE = "invoke request mount identifier exceeds CEP word limits";
static const char* const CEP_FED_INVOKE_INVALID_NODE_NOTE = "invoke request local_node exceeds CEP word limits";
static const char* const CEP_FED_INVOKE_NOTE_SHORT_FRAME = "invoke frame shorter than header";
static const char* const CEP_FED_INVOKE_NOTE_MODE        = "invoke frame unsupported mode";

typedef struct {
    const cepDT* (*dt)(void);
    cepFedTransportCaps flag;
} cepFedInvokeCapEntry;

static const cepFedInvokeCapEntry cep_fed_invoke_cap_table[] = {
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

static cepFedInvokePathBuf g_invoke_timeout_signal_path = {
    .length = 1u,
    .capacity = 1u,
    .past = {
        {
            .dt = { .domain = 0u, .tag = 0u, .glob = false },
            .timestamp = 0u,
        },
    },
};

static cepFedInvokePathBuf g_invoke_timeout_target_path = {
    .length = 1u,
    .capacity = 1u,
    .past = {
        {
            .dt = { .domain = 0u, .tag = 0u, .glob = false },
            .timestamp = 0u,
        },
    },
};

static bool g_invoke_signal_paths_initialised = false;

static void
cep_fed_invoke_init_signal_paths(void)
{
    if (g_invoke_signal_paths_initialised) {
        return;
    }
    g_invoke_signal_paths_initialised = true;
    g_invoke_timeout_signal_path.past[0].dt = cep_ops_make_dt("sig:fed_inv:timeout");
    const cepDT* net_dt = CEP_DTAW("CEP", "net");
    if (net_dt) {
        g_invoke_timeout_target_path.past[0].dt = *net_dt;
    } else {
        g_invoke_timeout_target_path.past[0].dt = cep_ops_make_dt("CEP:net");
    }
}

static void
cep_fed_invoke_emit_issue(const cepFedInvokeRequest* request,
                          const char* topic,
                          const char* note)
{
    if (!topic || !note) {
        return;
    }

    cepCell* subject = request && request->request_cell
        ? cep_cell_resolve(request->request_cell)
        : NULL;

    cepCeiRequest req = {0};
    req.severity = cep_ops_make_dt("sev/error");
    req.topic = topic;
    req.topic_intern = true;
    req.note = note;
    req.subject = subject;
    req.mailbox_root = cep_cei_diagnostics_mailbox();
    req.emit_signal = true;
    req.attach_to_op = false;
    (void)cep_cei_emit(&req);
}

static cepCell*
cep_fed_invoke_resolve_request(const cepPath* target_path)
{
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

static void
cep_fed_invoke_publish_state(cepCell* request_cell,
                             const char* state,
                             const char* error_note,
                             const char* provider)
{
    if (!request_cell || !cep_cell_require_dictionary_store(&request_cell)) {
        return;
    }
    if (state) {
        (void)cep_cell_put_text(request_cell, dt_state_field_name(), state);
    }
    if (error_note) {
        (void)cep_cell_put_text(request_cell, dt_error_field_name(), error_note);
    } else {
        (void)cep_cell_put_text(request_cell, dt_error_field_name(), "");
    }
    if (provider) {
        (void)cep_cell_put_text(request_cell, dt_provider_field_name(), provider);
    }
}

static cepFedInvokeRequest*
cep_fed_invoke_find_ctx(const cepCell* request_cell)
{
    for (cepFedInvokeRequest* ctx = g_invoke_requests; ctx; ctx = ctx->next) {
        if (ctx->request_cell == request_cell) {
            return ctx;
        }
    }
    return NULL;
}

static cepFedInvokeRequest*
cep_fed_invoke_find_ctx_by_mount(const char* peer_id, const char* mount_id)
{
    for (cepFedInvokeRequest* ctx = g_invoke_requests; ctx; ctx = ctx->next) {
        if (strcmp(ctx->peer_id, peer_id) == 0 &&
            strcmp(ctx->mount_id, mount_id) == 0) {
            return ctx;
        }
    }
    return NULL;
}

static void
cep_fed_invoke_remove_ctx(cepFedInvokeRequest* victim)
{
    if (!victim) {
        return;
    }

    cepFedInvokeRequest** cursor = &g_invoke_requests;
    while (*cursor) {
        if (*cursor == victim) {
            *cursor = victim->next;
            break;
        }
        cursor = &(*cursor)->next;
    }

    if (victim->request_path) {
        cep_free(victim->request_path);
        victim->request_path = NULL;
    }

    cep_free(victim);
}

static uint8_t
cep_fed_invoke_id_kind(cepID id)
{
    if (cep_id_is_reference(id)) {
        return CEP_FED_INVOKE_ID_KIND_REFERENCE;
    }
    if (cep_id_is_word(id)) {
        return CEP_FED_INVOKE_ID_KIND_WORD;
    }
    if (cep_id_is_acronym(id)) {
        return CEP_FED_INVOKE_ID_KIND_ACRONYM;
    }
    if (cep_id_is_numeric(id)) {
        return CEP_FED_INVOKE_ID_KIND_NUMERIC;
    }
    return CEP_FED_INVOKE_ID_KIND_INVALID;
}

static bool
cep_fed_invoke_id_to_text(cepID id,
                          uint8_t kind,
                          char* buffer,
                          size_t capacity,
                          size_t* out_len)
{
    if (!buffer || capacity == 0u) {
        return false;
    }

    size_t length = 0u;

    switch (kind) {
    case CEP_FED_INVOKE_ID_KIND_REFERENCE: {
        size_t ref_len = 0u;
        const char* text = cep_namepool_lookup(id, &ref_len);
        if (!text || ref_len == 0u || ref_len >= capacity) {
            return false;
        }
        memcpy(buffer, text, ref_len);
        length = ref_len;
        break;
    }
    case CEP_FED_INVOKE_ID_KIND_WORD:
        length = cep_word_to_text(id, buffer);
        break;
    case CEP_FED_INVOKE_ID_KIND_ACRONYM:
        length = cep_acronym_to_text(id, buffer);
        break;
    case CEP_FED_INVOKE_ID_KIND_NUMERIC: {
        cepID value = cep_id(id);
        int written = snprintf(buffer, capacity, "%" PRIu64, (uint64_t)value);
        if (written < 0) {
            return false;
        }
        length = (size_t)written;
        break;
    }
    default:
        return false;
    }

    if (length == 0u || length >= capacity) {
        return false;
    }

    if (out_len) {
        *out_len = length;
    }
    return true;
}

static bool
cep_fed_invoke_text_to_id(const char* text,
                          size_t length,
                          uint8_t kind,
                          cepID* out_id)
{
    if (!text || length == 0u || !out_id) {
        return false;
    }

    switch (kind) {
    case CEP_FED_INVOKE_ID_KIND_REFERENCE: {
        cepID id = cep_namepool_intern(text, length);
        if (!id) {
            return false;
        }
        *out_id = id;
        return true;
    }
    case CEP_FED_INVOKE_ID_KIND_WORD: {
        if (length >= CEP_WORD_MAX_CHARS + 1u) {
            return false;
        }
        char buffer[CEP_WORD_MAX_CHARS + 1u];
        memcpy(buffer, text, length);
        buffer[length] = '\0';
        cepID id = cep_text_to_word(buffer);
        if (!id || !cep_id_is_word(id)) {
            return false;
        }
        *out_id = id;
        return true;
    }
    case CEP_FED_INVOKE_ID_KIND_ACRONYM: {
        if (length >= CEP_ACRON_MAX_CHARS + 1u) {
            return false;
        }
        char buffer[CEP_ACRON_MAX_CHARS + 1u];
        memcpy(buffer, text, length);
        buffer[length] = '\0';
        cepID id = cep_text_to_acronym(buffer);
        if (!id || !cep_id_is_acronym(id)) {
            return false;
        }
        *out_id = id;
        return true;
    }
    case CEP_FED_INVOKE_ID_KIND_NUMERIC: {
        if (length >= 32u) {
            return false;
        }
        char buffer[32];
        memcpy(buffer, text, length);
        buffer[length] = '\0';
        char* endptr = NULL;
        unsigned long long value = strtoull(buffer, &endptr, 10);
        if (!endptr || *endptr != '\0' || value == 0ull) {
            return false;
        }
        cepID id = cep_id_to_numeric((cepID)value);
        if (!id || !cep_id_is_numeric(id)) {
            return false;
        }
        *out_id = id;
        return true;
    }
    default:
        return false;
    }
}

static size_t
cep_fed_invoke_path_encoded_size(const cepPath* path)
{
    if (!path) {
        return 0u;
    }

    size_t total = 0u;
    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        uint8_t domain_kind = cep_fed_invoke_id_kind(segment->dt.domain);
        uint8_t tag_kind = cep_fed_invoke_id_kind(segment->dt.tag);
        if (domain_kind == CEP_FED_INVOKE_ID_KIND_INVALID ||
            tag_kind == CEP_FED_INVOKE_ID_KIND_INVALID) {
            return 0u;
        }

        char domain_buf[64];
        char tag_buf[64];
        size_t domain_len = 0u;
        size_t tag_len = 0u;
        if (!cep_fed_invoke_id_to_text(segment->dt.domain,
                                       domain_kind,
                                       domain_buf,
                                       sizeof domain_buf,
                                       &domain_len) ||
            !cep_fed_invoke_id_to_text(segment->dt.tag,
                                       tag_kind,
                                       tag_buf,
                                       sizeof tag_buf,
                                       &tag_len)) {
            return 0u;
        }

        if (domain_len > UINT16_MAX || tag_len > UINT16_MAX) {
            return 0u;
        }
        total += sizeof(cepFedInvokeFrameSegmentHeader) + domain_len + tag_len;
    }
    return total;
}

static bool
cep_fed_invoke_encode_path(const cepPath* path,
                           uint8_t** cursor)
{
    if (!path || !cursor || !*cursor) {
        return false;
    }

    uint8_t* out = *cursor;

    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        uint8_t domain_kind = cep_fed_invoke_id_kind(segment->dt.domain);
        uint8_t tag_kind = cep_fed_invoke_id_kind(segment->dt.tag);
        if (domain_kind == CEP_FED_INVOKE_ID_KIND_INVALID ||
            tag_kind == CEP_FED_INVOKE_ID_KIND_INVALID) {
            return false;
        }

        char domain_buf[64];
        char tag_buf[64];
        size_t domain_len = 0u;
        size_t tag_len = 0u;

        if (!cep_fed_invoke_id_to_text(segment->dt.domain,
                                       domain_kind,
                                       domain_buf,
                                       sizeof domain_buf,
                                       &domain_len) ||
            !cep_fed_invoke_id_to_text(segment->dt.tag,
                                       tag_kind,
                                       tag_buf,
                                       sizeof tag_buf,
                                       &tag_len)) {
            return false;
        }

        if (domain_len > UINT16_MAX || tag_len > UINT16_MAX) {
            return false;
        }

        cepFedInvokeFrameSegmentHeader header = {
            .domain_length = (uint16_t)domain_len,
            .tag_length = (uint16_t)tag_len,
            .domain_kind = domain_kind,
            .tag_kind = tag_kind,
            .reserved = 0u,
            .timestamp = (uint64_t)segment->timestamp,
        };

        memcpy(out, &header, sizeof header);
        out += sizeof header;

        memcpy(out, domain_buf, domain_len);
        out += domain_len;

        memcpy(out, tag_buf, tag_len);
        out += tag_len;
    }

    *cursor = out;
    return true;
}

static bool
cep_fed_invoke_decode_path(const uint8_t** cursor,
                           size_t* remaining,
                           uint16_t segment_count,
                           cepPath** out_path)
{
    if (!cursor || !*cursor || !remaining || !out_path) {
        return false;
    }
    *out_path = NULL;

    size_t bytes = sizeof(cepPath) + (size_t)segment_count * sizeof(cepPast);
    cepPath* path = cep_malloc0(bytes);
    if (!path) {
        return false;
    }
    path->length = segment_count;
    path->capacity = segment_count;

    for (uint16_t i = 0u; i < segment_count; ++i) {
        if (*remaining < sizeof(cepFedInvokeFrameSegmentHeader)) {
            cep_free(path);
            return false;
        }

        const cepFedInvokeFrameSegmentHeader* header =
            (const cepFedInvokeFrameSegmentHeader*)(void*)(*cursor);
        uint16_t domain_len = header->domain_length;
        uint16_t tag_len = header->tag_length;
        uint8_t domain_kind = header->domain_kind;
        uint8_t tag_kind = header->tag_kind;
        uint64_t timestamp = header->timestamp;

        *cursor += sizeof *header;
        *remaining -= sizeof *header;

        if (*remaining < (size_t)domain_len + (size_t)tag_len) {
            cep_free(path);
            return false;
        }

        const char* domain_bytes = (const char*)(*cursor);
        *cursor += domain_len;
        *remaining -= domain_len;

        const char* tag_bytes = (const char*)(*cursor);
        *cursor += tag_len;
        *remaining -= tag_len;

        if (domain_len == 0u || tag_len == 0u) {
            cep_free(path);
            return false;
        }

        cepID domain_id = 0u;
        cepID tag_id = 0u;
        if (!cep_fed_invoke_text_to_id(domain_bytes,
                                       domain_len,
                                       domain_kind,
                                       &domain_id) ||
            !cep_fed_invoke_text_to_id(tag_bytes,
                                       tag_len,
                                       tag_kind,
                                       &tag_id)) {
            cep_free(path);
            return false;
        }

        cepDT dt = cep_dt_make(domain_id, tag_id);
        path->past[i].dt = dt;
        path->past[i].timestamp = (cepOpCount)timestamp;
    }

    *out_path = path;
    return true;
}

static bool
cep_fed_invoke_encode_request_frame(const cepFedInvokeRequest* request,
                                    uint64_t invocation_id,
                                    const cepPath* signal_path,
                                    const cepPath* target_path,
                                    uint8_t** out_payload,
                                    size_t* out_len)
{
    if (!request || !signal_path || !target_path || !out_payload || !out_len) {
        return false;
    }

    size_t signal_bytes = cep_fed_invoke_path_encoded_size(signal_path);
    size_t target_bytes = cep_fed_invoke_path_encoded_size(target_path);
    if ((signal_path->length > 0u && signal_bytes == 0u) ||
        (target_path->length > 0u && target_bytes == 0u)) {
        return false;
    }

    size_t payload_len = sizeof(cepFedInvokeFrameHeader) +
                         signal_bytes +
                         target_bytes;

    uint8_t* payload = cep_malloc0(payload_len);
    if (!payload) {
        return false;
    }

    cepFedInvokeFrameHeader* header = (cepFedInvokeFrameHeader*)payload;
    header->kind = CEP_FED_INVOKE_FRAME_REQUEST;
    header->status = 0u;
    header->signal_segments = (uint16_t)signal_path->length;
    header->target_segments = (uint16_t)target_path->length;
    header->reserved = 0u;
    header->invocation_id = invocation_id;

    uint8_t* cursor = payload + sizeof *header;
    if (!cep_fed_invoke_encode_path(signal_path, &cursor) ||
        !cep_fed_invoke_encode_path(target_path, &cursor)) {
        cep_free(payload);
        return false;
    }

    *out_payload = payload;
    *out_len = payload_len;
    return true;
}

static bool
cep_fed_invoke_send_response(const cepFedInvokeRequest* request,
                             uint64_t invocation_id,
                             uint8_t status)
{
    if (!request || !request->mount || !g_invoke_manager) {
        return false;
    }

    cepFedInvokeFrameHeader header;
    memset(&header, 0, sizeof header);
    header.kind = CEP_FED_INVOKE_FRAME_RESPONSE;
    header.status = status;
    header.signal_segments = 0u;
    header.target_segments = 0u;
    header.invocation_id = invocation_id;

    uint8_t* payload = cep_malloc0(sizeof header);
    if (!payload) {
        return false;
    }
    memcpy(payload, &header, sizeof header);

    if (!cep_fed_transport_manager_send(g_invoke_manager,
                                        request->mount,
                                        payload,
                                        sizeof header,
                                        CEP_FED_FRAME_MODE_DATA,
                                        0u)) {
        cep_free(payload);
        return false;
    }
    return true;
}

static void
cep_fed_invoke_pending_remove(cepFedInvokePending* victim,
                              cepFedInvokePending* prev)
{
    if (!victim) {
        return;
    }

    if (prev) {
        prev->next = victim->next;
    } else {
        g_invoke_pending = victim->next;
    }
    cep_free(victim);
}

bool
cep_fed_invoke_validate_frame_contract(const uint8_t* payload,
                                       size_t payload_len,
                                       cepFedFrameMode mode,
                                       const char** failure_note)
{
    if (!payload || payload_len < sizeof(cepFedInvokeFrameHeader)) {
        if (failure_note)
            *failure_note = CEP_FED_INVOKE_NOTE_SHORT_FRAME;
        return false;
    }
    if (mode != CEP_FED_FRAME_MODE_DATA) {
        if (failure_note)
            *failure_note = CEP_FED_INVOKE_NOTE_MODE;
        return false;
    }
    return true;
}

static bool
cep_fed_invoke_on_frame(void* user_ctx,
                        cepFedTransportManagerMount* mount,
                        const uint8_t* payload,
                        size_t payload_len,
                        cepFedFrameMode mode)
{
    (void)mount;
    cepFedInvokeRequest* ctx = (cepFedInvokeRequest*)user_ctx;
    if (!ctx) {
        return false;
    }
    const char* failure_note = NULL;
    if (!cep_fed_invoke_validate_frame_contract(payload,
                                                payload_len,
                                                mode,
                                                &failure_note)) {
        cep_fed_invoke_emit_issue(ctx,
                                  CEP_FED_INVOKE_TOPIC_REJECT,
                                  failure_note ? failure_note : "invoke frame invalid");
        return false;
    }
    cep_fed_invoke_process_frame(ctx, payload, payload_len, mode);
    return true;
}

static void
cep_fed_invoke_on_event(void* user_ctx,
                        cepFedTransportManagerMount* mount,
                        cepFedTransportEventKind kind,
                        const char* detail)
{
    (void)user_ctx;
    (void)mount;
    (void)kind;
    (void)detail;
}

static bool
cep_fed_invoke_read_text(cepCell* request_cell,
                         const cepDT* field,
                         bool required,
                         char* buffer,
                         size_t capacity)
{
    if (!request_cell || !field || !buffer || capacity == 0u) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(request_cell, field);
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
    if (data->size == 0u) {
        return false;
    }
    size_t len = data->size < capacity - 1u ? data->size : capacity - 1u;
    memcpy(buffer, cep_data_payload(data), len);
    buffer[len] = '\0';
    return true;
}

static bool
cep_fed_invoke_read_bool(cepCell* parent,
                         const cepDT* field,
                         bool* out_value)
{
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

static bool
cep_fed_invoke_read_u32(cepCell* parent,
                        const cepDT* field,
                        bool required,
                        uint32_t* out_value)
{
    if (!parent || !field || !out_value) {
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

static void
cep_fed_invoke_read_serializer_caps(cepCell* request_cell,
                                    cepFedTransportFlatPolicy* policy,
                                    uint32_t* payload_history_beats,
                                    uint32_t* manifest_history_beats)
{
    if (!request_cell || !policy) {
        return;
    }
    cepCell* serializer = cep_cell_find_by_name(request_cell, dt_serializer_name());
    if (!serializer) {
        return;
    }
    serializer = cep_cell_resolve(serializer);
    if (!serializer || !cep_cell_require_dictionary_store(&serializer)) {
        return;
    }
    bool bool_value = false;
    if (cep_fed_invoke_read_bool(serializer, dt_ser_crc32c_ok_name(), &bool_value)) {
        policy->allow_crc32c = bool_value;
    }
    if (cep_fed_invoke_read_bool(serializer, dt_ser_deflate_ok_name(), &bool_value)) {
        policy->allow_deflate = bool_value;
    }
    if (cep_fed_invoke_read_bool(serializer, dt_ser_aead_ok_name(), &bool_value)) {
        policy->allow_aead = bool_value;
    }
    if (cep_fed_invoke_read_bool(serializer, dt_ser_warn_down_name(), &bool_value)) {
        policy->warn_on_downgrade = bool_value;
    }
    uint32_t cmp_max = policy->comparator_max_version;
    if (cep_fed_invoke_read_u32(serializer, dt_ser_cmpmax_name(), false, &cmp_max)) {
        policy->comparator_max_version = cmp_max;
    }
    if (payload_history_beats) {
        uint32_t beats = *payload_history_beats;
        if (cep_fed_invoke_read_u32(serializer, dt_ser_pay_hist_name(), false, &beats)) {
            *payload_history_beats = beats;
        }
    }
    if (manifest_history_beats) {
        uint32_t beats = *manifest_history_beats;
        if (cep_fed_invoke_read_u32(serializer, dt_ser_man_hist_name(), false, &beats)) {
            *manifest_history_beats = beats;
        }
    }
}

static bool
cep_fed_invoke_validate_word(const char* text)
{
    if (!text || !*text) {
        return false;
    }
    return cep_text_to_word(text) != 0u;
}

static bool
cep_fed_invoke_copy_request_path(cepFedInvokeRequest* ctx)
{
    if (!ctx || !ctx->request_cell) {
        return false;
    }
    cepPath* path = NULL;
    if (!cep_cell_path(ctx->request_cell, &path)) {
        return false;
    }
    if (ctx->request_path) {
        cep_free(ctx->request_path);
    }
    ctx->request_path = path;
    return true;
}

static void
cep_fed_invoke_cancel_pending_for(const cepFedInvokeRequest* ctx)
{
    if (!ctx) {
        return;
    }

    cepFedInvokePending* prev = NULL;
    cepFedInvokePending* node = g_invoke_pending;
    while (node) {
        if (node->request == ctx) {
            if (node->on_complete) {
                node->on_complete(node->user_ctx, false);
            }
            cepFedInvokePending* victim = node;
            node = node->next;
            cep_fed_invoke_pending_remove(victim, prev);
            continue;
        }
        prev = node;
        node = node->next;
    }
}

bool
cep_fed_invoke_organ_init(cepFedTransportManager* manager,
                          cepCell* net_root)
{
    if (!manager || !net_root) {
        return false;
    }

    g_invoke_manager = manager;
    g_invoke_net_root = net_root;

    cepCell* root = cep_cell_resolve(net_root);
    if (!root || !cep_cell_require_dictionary_store(&root)) {
        return false;
    }

    cepCell* organs = cep_cell_find_by_name(root, CEP_DTAW("CEP", "organs"));
    if (!organs) {
        organs = cep_cell_ensure_dictionary_child(root,
                                                  CEP_DTAW("CEP", "organs"),
                                                  CEP_STORAGE_RED_BLACK_T);
    }
    organs = cep_cell_resolve(organs);
    if (!organs || !cep_cell_require_dictionary_store(&organs)) {
        return false;
    }

    cepCell* invoke_root = cep_cell_find_by_name(organs, CEP_DTAW("CEP", "invoke"));
    if (!invoke_root) {
        invoke_root = cep_cell_ensure_dictionary_child(organs,
                                                       CEP_DTAW("CEP", "invoke"),
                                                       CEP_STORAGE_RED_BLACK_T);
    }
    invoke_root = cep_cell_resolve(invoke_root);
    if (!invoke_root || !cep_cell_require_dictionary_store(&invoke_root)) {
        return false;
    }

    cepCell* spec = cep_cell_find_by_name(invoke_root, CEP_DTAW("CEP", "spec"));
    if (!spec) {
        spec = cep_cell_ensure_dictionary_child(invoke_root,
                                                CEP_DTAW("CEP", "spec"),
                                                CEP_STORAGE_RED_BLACK_T);
    }
    spec = cep_cell_resolve(spec);
    if (!spec || !cep_cell_require_dictionary_store(&spec)) {
        return false;
    }

    (void)cep_cell_put_text(spec,
                            CEP_DTAW("CEP", "usage"),
                            "Create requests under /net/organs/invoke/requests "
                            "to route remote enzyme invocations across federation transports.");
    (void)cep_cell_put_text(spec,
                            CEP_DTAW("CEP", "status"),
                            "Validator provisions an invoke mount and records provider/error state.");

    cepCell* requests = cep_cell_find_by_name(invoke_root, CEP_DTAW("CEP", "requests"));
    if (!requests) {
        requests = cep_cell_ensure_dictionary_child(invoke_root,
                                                    CEP_DTAW("CEP", "requests"),
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

const cepFedInvokeRequest*
cep_fed_invoke_request_find(const char* peer_id,
                            const char* mount_id)
{
    if (!peer_id || !mount_id) {
        return NULL;
    }
    return cep_fed_invoke_find_ctx_by_mount(peer_id, mount_id);
}

static bool
cep_fed_invoke_setup_callbacks(cepFedInvokeRequest* ctx,
                               cepFedTransportMountCallbacks* callbacks)
{
    if (!ctx || !callbacks) {
        return false;
    }
    callbacks->on_frame = cep_fed_invoke_on_frame;
    callbacks->on_event = cep_fed_invoke_on_event;
    callbacks->user_ctx = ctx;
    return true;
}

int
cep_fed_invoke_validator(const cepPath* signal_path,
                         const cepPath* target_path)
{
    (void)signal_path;
    cepCell* request_cell = cep_fed_invoke_resolve_request(target_path);
    if (!request_cell) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_cell_require_dictionary_store(&request_cell)) {
        cep_fed_invoke_emit_issue(NULL,
                                  CEP_FED_INVOKE_TOPIC_REJECT,
                                  "invoke request is not a dictionary");
        return CEP_ENZYME_FATAL;
    }

    char peer[64] = {0};
    char mount[64] = {0};
    char local_node[64] = {0};
    char preferred_provider[64] = {0};
    cepFedTransportFlatPolicy flat_policy = {
        .allow_crc32c = true,
        .allow_deflate = true,
        .allow_aead = true,
        .warn_on_downgrade = true,
        .comparator_max_version = UINT32_MAX,
    };

    if (!cep_fed_invoke_read_text(request_cell, dt_peer_field_name(), true, peer, sizeof peer) ||
        !cep_fed_invoke_read_text(request_cell, dt_mount_field_name(), true, mount, sizeof mount) ||
        !cep_fed_invoke_read_text(request_cell, dt_local_node_field_name(), true, local_node, sizeof local_node)) {
        cep_fed_invoke_emit_issue(NULL,
                                  CEP_FED_INVOKE_TOPIC_REJECT,
                                  "invoke request missing required fields");
        cep_fed_invoke_publish_state(request_cell, "error", "missing required fields", NULL);
        return CEP_ENZYME_FATAL;
    }

    if (!cep_fed_invoke_validate_word(peer)) {
        cep_fed_invoke_emit_issue(NULL, CEP_FED_INVOKE_TOPIC_REJECT, CEP_FED_INVOKE_INVALID_PEER_NOTE);
        cep_fed_invoke_publish_state(request_cell, "error", "invalid peer identifier", NULL);
        return CEP_ENZYME_FATAL;
    }
    if (!cep_fed_invoke_validate_word(mount)) {
        cep_fed_invoke_emit_issue(NULL, CEP_FED_INVOKE_TOPIC_REJECT, CEP_FED_INVOKE_INVALID_MOUNT_NOTE);
        cep_fed_invoke_publish_state(request_cell, "error", "invalid mount identifier", NULL);
        return CEP_ENZYME_FATAL;
    }
    if (!cep_fed_invoke_validate_word(local_node)) {
        cep_fed_invoke_emit_issue(NULL, CEP_FED_INVOKE_TOPIC_REJECT, CEP_FED_INVOKE_INVALID_NODE_NOTE);
        cep_fed_invoke_publish_state(request_cell, "error", "invalid local_node identifier", NULL);
        return CEP_ENZYME_FATAL;
    }

    (void)cep_fed_invoke_read_text(request_cell,
                                   dt_pref_provider_name(),
                                   false,
                                   preferred_provider,
                                   sizeof preferred_provider);
    uint32_t payload_history_beats = 0u;
    uint32_t manifest_history_beats = 0u;
    cep_fed_invoke_read_serializer_caps(request_cell,
                                        &flat_policy,
                                        &payload_history_beats,
                                        &manifest_history_beats);

    cepFedTransportCaps required_caps = CEP_FED_TRANSPORT_CAP_RELIABLE |
                                        CEP_FED_TRANSPORT_CAP_ORDERED;
    cepFedTransportCaps preferred_caps = 0u;

    cepCell* caps = cep_cell_find_by_name(request_cell, dt_caps_name());
    if (caps) {
        caps = cep_cell_resolve(caps);
        if (!caps || !cep_cell_require_dictionary_store(&caps)) {
            cep_fed_invoke_publish_state(request_cell, "error", "invalid capability dictionary", NULL);
            return CEP_ENZYME_FATAL;
        }
        cepCell* required = cep_cell_find_by_name(caps, dt_required_caps_name());
        if (required) {
            required = cep_cell_resolve(required);
            if (!required || !cep_cell_require_dictionary_store(&required)) {
                cep_fed_invoke_publish_state(request_cell, "error", "invalid capability dictionary", NULL);
                return CEP_ENZYME_FATAL;
            }
            cepFedTransportCaps flags = 0u;
            for (size_t i = 0; i < cep_lengthof(cep_fed_invoke_cap_table); ++i) {
                cepCell* node = cep_cell_find_by_name(required, cep_fed_invoke_cap_table[i].dt());
                if (!node) {
                    continue;
                }
                node = cep_cell_resolve(node);
                if (!node || !node->data) {
                    continue;
                }
                cepData* data = node->data;
                cepDT expected = cep_ops_make_dt("val/bool");
                if (cep_dt_compare(&data->dt, &expected) != 0 ||
                    data->size != sizeof(uint8_t)) {
                    continue;
                }
                const uint8_t* payload = (const uint8_t*)cep_data_payload(data);
                if (payload && *payload) {
                    flags |= cep_fed_invoke_cap_table[i].flag;
                }
            }
            if (flags != 0u) {
                required_caps = flags;
            }
        }
        cepCell* preferred = cep_cell_find_by_name(caps, dt_preferred_caps_name());
        if (preferred) {
            preferred = cep_cell_resolve(preferred);
            if (!preferred || !cep_cell_require_dictionary_store(&preferred)) {
                cep_fed_invoke_publish_state(request_cell, "error", "invalid capability dictionary", NULL);
                return CEP_ENZYME_FATAL;
            }
            for (size_t i = 0; i < cep_lengthof(cep_fed_invoke_cap_table); ++i) {
                cepCell* node = cep_cell_find_by_name(preferred, cep_fed_invoke_cap_table[i].dt());
                if (!node) {
                    continue;
                }
                node = cep_cell_resolve(node);
                if (!node || !node->data) {
                    continue;
                }
                cepData* data = node->data;
                cepDT expected = cep_ops_make_dt("val/bool");
                if (cep_dt_compare(&data->dt, &expected) != 0 ||
                    data->size != sizeof(uint8_t)) {
                    continue;
                }
                const uint8_t* payload = (const uint8_t*)cep_data_payload(data);
                if (payload && *payload) {
                    preferred_caps |= cep_fed_invoke_cap_table[i].flag;
                }
            }
        }
    }

    cepCell* deadline_node = cep_cell_find_by_name(request_cell, dt_deadline_field_name());
    bool deadline_present = false;
    uint64_t deadline = 0u;
    if (deadline_node) {
        deadline_node = cep_cell_resolve(deadline_node);
        if (deadline_node) {
            cepData* data = NULL;
            if (cep_cell_require_data(&deadline_node, &data)) {
                cepDT expected = cep_ops_make_dt("val/u64");
                if (cep_dt_compare(&data->dt, &expected) == 0 &&
                    data->size == sizeof(uint64_t)) {
                    const uint64_t* payload = (const uint64_t*)cep_data_payload(data);
                    if (payload) {
                        deadline = *payload;
                        deadline_present = true;
                    }
                }
            }
        }
    }

    cepFedInvokeRequest* ctx = cep_fed_invoke_find_ctx(request_cell);
    if (ctx) {
        if (ctx->mount) {
            (void)cep_fed_transport_manager_close(g_invoke_manager,
                                                  ctx->mount,
                                                  "invoke-reconfigure");
            ctx->mount = NULL;
        }
        cep_fed_invoke_cancel_pending_for(ctx);
    } else {
        ctx = cep_malloc0(sizeof *ctx);
        if (!ctx) {
            return CEP_ENZYME_FATAL;
        }
        ctx->request_cell = request_cell;
        ctx->next = g_invoke_requests;
        g_invoke_requests = ctx;
    }

    snprintf(ctx->peer_id, sizeof ctx->peer_id, "%s", peer);
    snprintf(ctx->mount_id, sizeof ctx->mount_id, "%s", mount);
    snprintf(ctx->local_node, sizeof ctx->local_node, "%s", local_node);
    ctx->required_caps = required_caps;
    ctx->preferred_caps = preferred_caps;
    ctx->allow_upd_latest = false;
    ctx->deadline = deadline;
    ctx->has_deadline = deadline_present;
    ctx->flat_policy = flat_policy;
    ctx->payload_history_beats = payload_history_beats;
    ctx->manifest_history_beats = manifest_history_beats;

    if (!cep_fed_invoke_copy_request_path(ctx)) {
            cep_fed_invoke_emit_issue(ctx, CEP_FED_INVOKE_TOPIC_REJECT, "unable to capture invoke request path");
            cep_fed_invoke_remove_ctx(ctx);
            return CEP_ENZYME_FATAL;
        }

    if (ctx->has_deadline) {
        cepBeatNumber current = cep_heartbeat_current();
        if (ctx->deadline == 0u || ctx->deadline <= current) {
            cep_fed_invoke_emit_issue(ctx, CEP_FED_INVOKE_TOPIC_TIMEOUT, CEP_FED_INVOKE_SCHEMA_NOTE);
            cep_fed_invoke_remove_ctx(ctx);
            return CEP_ENZYME_FATAL;
        }
    }

    cepFedTransportMountConfig cfg = {
        .peer_id = ctx->peer_id,
        .mount_id = ctx->mount_id,
        .mount_mode = CEP_FED_INVOKE_MODE,
        .local_node_id = ctx->local_node,
        .preferred_provider_id = preferred_provider[0] ? preferred_provider : NULL,
        .required_caps = ctx->required_caps,
        .preferred_caps = ctx->preferred_caps,
        .allow_upd_latest = false,
        .deadline_beat = ctx->deadline,
    };

    cepFedTransportMountCallbacks callbacks = {0};
    cep_fed_invoke_setup_callbacks(ctx, &callbacks);

    cepFedTransportManagerMount* mount_ptr = NULL;
    if (!cep_fed_transport_manager_configure_mount(g_invoke_manager,
                                                   &cfg,
                                                   &callbacks,
                                                   &mount_ptr)) {
            cep_fed_invoke_emit_issue(ctx,
                                      CEP_FED_INVOKE_TOPIC_REJECT,
                                      "transport manager rejected invoke configuration");
            cep_fed_invoke_remove_ctx(ctx);
            return CEP_ENZYME_FATAL;
        }

    ctx->mount = mount_ptr;
    cep_fed_transport_manager_mount_set_flat_policy(mount_ptr, &flat_policy);
    cep_fed_transport_manager_mount_set_flat_history(mount_ptr,
                                                     ctx->payload_history_beats,
                                                     ctx->manifest_history_beats);
    cep_fed_invoke_publish_state(request_cell,
                                 "active",
                                 NULL,
                                 cep_fed_transport_manager_mount_provider_id(mount_ptr));
    return CEP_ENZYME_SUCCESS;
}

int
cep_fed_invoke_destructor(const cepPath* signal_path,
                          const cepPath* target_path)
{
    (void)signal_path;
    cepCell* request_cell = cep_fed_invoke_resolve_request(target_path);
    if (!request_cell) {
        return CEP_ENZYME_SUCCESS;
    }

    cepFedInvokeRequest* ctx = cep_fed_invoke_find_ctx(request_cell);
    if (!ctx) {
        return CEP_ENZYME_SUCCESS;
    }

    if (ctx->mount) {
        (void)cep_fed_transport_manager_close(g_invoke_manager,
                                              ctx->mount,
                                              "invoke-request-destroy");
        ctx->mount = NULL;
    }

    cepFedInvokePending* prev = NULL;
    cepFedInvokePending* node = g_invoke_pending;
    while (node) {
        if (node->request == ctx) {
            if (node->on_complete) {
                node->on_complete(node->user_ctx, false);
            }
            cepFedInvokePending* victim = node;
            node = node->next;
            cep_fed_invoke_pending_remove(victim, prev);
            continue;
        }
        prev = node;
        node = node->next;
    }

    cep_fed_invoke_publish_state(request_cell, "removed", NULL, NULL);
    cep_fed_invoke_remove_ctx(ctx);
    return CEP_ENZYME_SUCCESS;
}

bool
cep_fed_invoke_request_submit(const cepFedInvokeRequest* request,
                              const cepFedInvokeSubmission* submission)
{
    if (!request || !submission || !request->mount || !g_invoke_manager) {
        return false;
    }
    if (!submission->signal_path || !submission->target_path) {
        return false;
    }

    uint32_t timeout_beats = submission->timeout_beats ? submission->timeout_beats : 4u;
    cepBeatNumber current_beat = cep_heartbeat_current();
    cepBeatNumber deadline = (current_beat == CEP_BEAT_INVALID)
        ? (cepBeatNumber)timeout_beats
        : current_beat + timeout_beats;

    uint64_t invocation_id = g_invoke_next_id++;

    uint8_t* payload = NULL;
    size_t payload_len = 0u;
    if (!cep_fed_invoke_encode_request_frame(request,
                                             invocation_id,
                                             submission->signal_path,
                                             submission->target_path,
                                             &payload,
                                             &payload_len)) {
        return false;
    }

    if (!cep_fed_transport_manager_send(g_invoke_manager,
                                        request->mount,
                                        payload,
                                        payload_len,
                                        CEP_FED_FRAME_MODE_DATA,
                                        0u)) {
        cep_free(payload);
        cep_fed_invoke_emit_issue(request,
                                  CEP_FED_INVOKE_TOPIC_REJECT,
                                  "failed to stage remote invocation frame");
        return false;
    }
    cep_free(payload);

    cepFedInvokePending* pending = cep_malloc0(sizeof *pending);
    if (!pending) {
        return false;
    }
    pending->id = invocation_id;
    pending->request = request;
    pending->deadline = deadline;
    pending->on_complete = submission->on_complete;
    pending->user_ctx = submission->user_ctx;
    pending->next = g_invoke_pending;
    g_invoke_pending = pending;

    cep_fed_invoke_init_signal_paths();
    const cepPath* timeout_target = request->request_path
        ? request->request_path
        : (const cepPath*)&g_invoke_timeout_target_path;
    (void)cep_heartbeat_enqueue_signal(deadline,
                                       (const cepPath*)&g_invoke_timeout_signal_path,
                                       timeout_target);
    return true;
}

void
cep_fed_invoke_process_frame(cepFedInvokeRequest* request,
                             const uint8_t* payload,
                             size_t payload_len,
                             cepFedFrameMode mode)
{
    if (!request || !payload || payload_len < sizeof(cepFedInvokeFrameHeader)) {
        return;
    }
    if (mode != CEP_FED_FRAME_MODE_DATA) {
        return;
    }

    const cepFedInvokeFrameHeader* header = (const cepFedInvokeFrameHeader*)payload;
    const uint8_t* cursor = payload + sizeof *header;
    size_t remaining = payload_len - sizeof *header;

    if (header->kind == CEP_FED_INVOKE_FRAME_REQUEST) {
        cepPath* signal_path = NULL;
        cepPath* target_path = NULL;

        if (!cep_fed_invoke_decode_path(&cursor,
                                        &remaining,
                                        header->signal_segments,
                                        &signal_path)) {
            cep_fed_invoke_emit_issue(request,
                                      CEP_FED_INVOKE_TOPIC_REJECT,
                                      "failed to decode invocation signal path");
            return;
        }

        if (!cep_fed_invoke_decode_path(&cursor,
                                        &remaining,
                                        header->target_segments,
                                        &target_path)) {
            cep_free(signal_path);
            cep_fed_invoke_emit_issue(request,
                                      CEP_FED_INVOKE_TOPIC_REJECT,
                                      "failed to decode invocation target path");
            return;
        }

        int rc = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                              signal_path,
                                              target_path);
        cep_free(signal_path);
        cep_free(target_path);

        if (rc != CEP_ENZYME_SUCCESS) {
            (void)cep_fed_invoke_send_response(request,
                                               header->invocation_id,
                                               CEP_FED_INVOKE_STATUS_REJECT);
            cep_fed_invoke_emit_issue(request,
                                      CEP_FED_INVOKE_TOPIC_REJECT,
                                      "failed to enqueue remote invocation");
            return;
        }

        (void)cep_fed_invoke_send_response(request,
                                           header->invocation_id,
                                           CEP_FED_INVOKE_STATUS_OK);
        return;
    }

    if (header->kind == CEP_FED_INVOKE_FRAME_RESPONSE) {
        cepFedInvokePending* prev = NULL;
        cepFedInvokePending* node = g_invoke_pending;
        while (node) {
            if (node->id == header->invocation_id &&
                node->request == request) {
                bool ok = (header->status == CEP_FED_INVOKE_STATUS_OK);
                if (!ok) {
                    cep_fed_invoke_emit_issue(request,
                                              CEP_FED_INVOKE_TOPIC_REJECT,
                                              CEP_FED_INVOKE_REJECT_NOTE);
                }
                if (node->on_complete) {
                    node->on_complete(node->user_ctx, ok);
                }
                cep_fed_invoke_pending_remove(node, prev);
                return;
            }
            prev = node;
            node = node->next;
        }
    }
}

bool
cep_fed_invoke_emit_cell(const char* peer_id,
                         const char* mount_id,
                         const cepCell* cell,
                         const cepSerializationHeader* header,
                         size_t blob_payload_bytes,
                         cepFedFrameMode mode,
                         uint64_t deadline_beat)
{
    if (!peer_id || !mount_id || !cell) {
        return false;
    }
    if (!g_invoke_manager) {
        return false;
    }
    if (mode != CEP_FED_FRAME_MODE_DATA) {
        return false;
    }
    cepFedInvokeRequest* ctx = cep_fed_invoke_find_ctx_by_mount(peer_id, mount_id);
    if (!ctx || !ctx->mount) {
        return false;
    }
    return cep_fed_transport_manager_send_cell(g_invoke_manager,
                                               ctx->mount,
                                               cell,
                                               header,
                                               blob_payload_bytes,
                                               mode,
                                               deadline_beat);
}

int
cep_fed_invoke_timeout_enzyme(const cepPath* signal_path,
                              const cepPath* target_path)
{
    (void)signal_path;
    (void)target_path;

    cepBeatNumber current = cep_heartbeat_current();
    cepFedInvokePending* node = g_invoke_pending;
    cepFedInvokePending* prev = NULL;

    while (node) {
        bool expired = (node->deadline != CEP_BEAT_INVALID) &&
                       (current != CEP_BEAT_INVALID) &&
                       (current >= node->deadline);
        if (!expired) {
            prev = node;
            node = node->next;
            continue;
        }

        cep_fed_invoke_emit_issue(node->request,
                                  CEP_FED_INVOKE_TOPIC_TIMEOUT,
                                  CEP_FED_INVOKE_TIMEOUT_NOTE);
        if (node->on_complete) {
            node->on_complete(node->user_ctx, false);
        }
        cepFedInvokePending* victim = node;
        node = node->next;
        cep_fed_invoke_pending_remove(victim, prev);
    }

    return CEP_ENZYME_SUCCESS;
}
