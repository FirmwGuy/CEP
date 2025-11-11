/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_FED_TRANSPORT_MANAGER_H
#define CEP_FED_TRANSPORT_MANAGER_H

#include "fed_transport.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_cei.h"
#include "../l0_kernel/cep_serialization.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cepFedTransportManagerMount cepFedTransportManagerMount;

typedef struct {
    const char* peer_id;
    const char* mount_id;
    const char* mount_mode;
    const char* local_node_id;
    const char* preferred_provider_id;
    cepFedTransportCaps required_caps;
    cepFedTransportCaps preferred_caps;
    bool allow_upd_latest;
    uint64_t deadline_beat;
} cepFedTransportMountConfig;

typedef struct {
    bool (*on_frame)(void* user_ctx,
                     cepFedTransportManagerMount* mount,
                     const uint8_t* payload,
                     size_t payload_len,
                     cepFedFrameMode mode);
    void (*on_event)(void* user_ctx,
                     cepFedTransportManagerMount* mount,
                     cepFedTransportEventKind kind,
                     const char* detail);
    void* user_ctx;
} cepFedTransportMountCallbacks;

typedef struct {
    cepCell* net_root;
    cepCell* transports_root;
    cepCell* mounts_root;
    cepCell* peers_root;
    cepCell* catalog_root;
    cepCell* telemetry_root;
    cepCell* diagnostics_mailbox;
    cepFedTransportManagerMount* mounts;
    size_t mount_count;
    size_t mount_capacity;
} cepFedTransportManager;

typedef struct {
    bool allow_crc32c;
    bool allow_deflate;
    bool allow_aead;
    bool warn_on_downgrade;
    uint32_t comparator_max_version;
} cepFedTransportFlatPolicy;

bool cep_fed_transport_manager_init(cepFedTransportManager* manager,
                                    cepCell* net_root);

bool cep_fed_transport_manager_configure_mount(cepFedTransportManager* manager,
                                               const cepFedTransportMountConfig* config,
                                               const cepFedTransportMountCallbacks* callbacks,
                                               cepFedTransportManagerMount** out_mount);

bool cep_fed_transport_manager_send(cepFedTransportManager* manager,
                                    cepFedTransportManagerMount* mount,
                                    const uint8_t* payload,
                                    size_t payload_len,
                                    cepFedFrameMode mode,
                                    uint64_t deadline_beat);

bool cep_fed_transport_manager_send_cell(cepFedTransportManager* manager,
                                         cepFedTransportManagerMount* mount,
                                         const cepCell* cell,
                                         const cepSerializationHeader* header,
                                         size_t blob_payload_bytes,
                                         cepFedFrameMode mode,
                                         uint64_t deadline_beat);

void cep_fed_transport_manager_mount_set_flat_history(cepFedTransportManagerMount* mount,
                                                      uint32_t payload_history_beats,
                                                      uint32_t manifest_history_beats);
void cep_fed_transport_manager_mount_set_flat_policy(cepFedTransportManagerMount* mount,
                                                     const cepFedTransportFlatPolicy* policy);

bool cep_fed_transport_manager_request_receive(cepFedTransportManager* manager,
                                               cepFedTransportManagerMount* mount);

bool cep_fed_transport_manager_close(cepFedTransportManager* manager,
                                     cepFedTransportManagerMount* mount,
                                     const char* reason);

void cep_fed_transport_manager_teardown(cepFedTransportManager* manager);

const char* cep_fed_transport_manager_mount_provider_id(const cepFedTransportManagerMount* mount);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FED_TRANSPORT_MANAGER_H */
