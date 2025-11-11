/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_FED_TRANSPORT_H
#define CEP_FED_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct _cepCell;

typedef struct _cepCell cepCell;
typedef struct cepFedTransportChannel cepFedTransportChannel;

#define CEP_FED_TRANSPORT_PROVIDER_ID_MAX 11u

typedef uint32_t cepFedTransportCaps;

enum {
    CEP_FED_TRANSPORT_CAP_RELIABLE    = 1u << 0,
    CEP_FED_TRANSPORT_CAP_ORDERED     = 1u << 1,
    CEP_FED_TRANSPORT_CAP_STREAMING   = 1u << 2,
    CEP_FED_TRANSPORT_CAP_DATAGRAM    = 1u << 3,
    CEP_FED_TRANSPORT_CAP_MULTICAST   = 1u << 4,
    CEP_FED_TRANSPORT_CAP_LOW_LATENCY = 1u << 5,
    CEP_FED_TRANSPORT_CAP_LOCAL_IPC   = 1u << 6,
    CEP_FED_TRANSPORT_CAP_REMOTE_NET  = 1u << 7,
    CEP_FED_TRANSPORT_CAP_UNRELIABLE  = 1u << 8,
    CEP_FED_TRANSPORT_CAP_CHECKSUM_CRC32C      = 1u << 9,
    CEP_FED_TRANSPORT_CAP_COMPRESSION_DEFLATE  = 1u << 10,
    CEP_FED_TRANSPORT_CAP_ENCRYPTION_AEAD      = 1u << 11,
    CEP_FED_TRANSPORT_CAP_COMPARATOR_VERSIONED = 1u << 12,
};

typedef enum {
    CEP_FED_FRAME_MODE_DATA = 0,
    CEP_FED_FRAME_MODE_UPD_LATEST = 1,
} cepFedFrameMode;

typedef enum {
    CEP_FED_TRANSPORT_EVENT_READY_RX = 0,
    CEP_FED_TRANSPORT_EVENT_BACKPRESSURE,
    CEP_FED_TRANSPORT_EVENT_RESET,
    CEP_FED_TRANSPORT_EVENT_FATAL,
} cepFedTransportEventKind;

typedef struct {
    bool (*on_frame)(void* manager_ctx,
                     cepFedTransportChannel* channel,
                     const uint8_t* payload,
                     size_t payload_len,
                     cepFedFrameMode mode);
    void (*on_event)(void* manager_ctx,
                     cepFedTransportChannel* channel,
                     cepFedTransportEventKind kind,
                     const char* detail);
} cepFedTransportCallbacks;

typedef struct {
    const char* provider_id;
    const char* peer_id;
    const char* mount_id;
    const char* local_node_id;
    const cepCell* provider_cell;
    cepFedTransportCaps required_caps;
    cepFedTransportCaps preferred_caps;
    uint64_t deadline_beat;
} cepFedTransportOpenArgs;

typedef struct {
    bool (*open)(void* provider_ctx,
                 const cepFedTransportOpenArgs* args,
                 const cepFedTransportCallbacks* callbacks,
                 void* manager_ctx,
                 cepFedTransportChannel** out_channel);
    bool (*send)(void* provider_ctx,
                 cepFedTransportChannel* channel,
                 const uint8_t* payload,
                 size_t payload_len,
                 cepFedFrameMode mode,
                 uint64_t deadline_beat);
    bool (*request_receive)(void* provider_ctx,
                            cepFedTransportChannel* channel);
    bool (*close)(void* provider_ctx,
                  cepFedTransportChannel* channel,
                  const char* reason);
} cepFedTransportVTable;

typedef struct {
    const char* provider_id;
    cepFedTransportCaps caps;
    size_t max_payload_bytes;
    const cepFedTransportVTable* vtable;
} cepFedTransportProvider;

bool cep_fed_transport_register(const cepFedTransportProvider* provider,
                                void* provider_ctx);
bool cep_fed_transport_unregister(const char* provider_id);
const cepFedTransportProvider* cep_fed_transport_provider_lookup(const char* provider_id,
                                                                 void** out_provider_ctx);
size_t cep_fed_transport_provider_enumerate(const cepFedTransportProvider** out_array,
                                            size_t capacity,
                                            void** out_contexts);

cepCell* cep_fed_transport_ensure_transports_root(cepCell* net_root);
bool cep_fed_transport_schema_seed_provider(cepCell* transports_root,
                                            const char* provider_id,
                                            const cepFedTransportProvider* provider,
                                            bool supports_upd_latest);

#endif /* CEP_FED_TRANSPORT_H */
