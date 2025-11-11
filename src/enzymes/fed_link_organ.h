/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_FED_LINK_ORGAN_H
#define CEP_FED_LINK_ORGAN_H

#include "fed_transport_manager.h"
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_flat_serializer.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the link-mode federation organ scaffolding. */
bool cep_fed_link_organ_init(cepFedTransportManager* manager,
                             cepCell* net_root);

/* Apply a link-mode mount configuration via the shared transport manager. */
bool cep_fed_link_mount_apply(const cepFedTransportMountConfig* config,
                              const cepFedTransportMountCallbacks* callbacks,
                              cepFedTransportManagerMount** out_mount);

/* Release a link-mode mount using the shared transport manager. */
bool cep_fed_link_mount_release(cepFedTransportManagerMount* mount,
                                const char* reason);

/* Organ callback hooks registered via fed_pack. */
int cep_fed_link_validator(const cepPath* signal_path, const cepPath* target_path);
int cep_fed_link_destructor(const cepPath* signal_path, const cepPath* target_path);
bool cep_fed_link_emit_cell(const char* peer_id,
                            const char* mount_id,
                            const cepCell* cell,
                            const cepSerializationHeader* header,
                            size_t blob_payload_bytes,
                            cepFedFrameMode mode,
                            uint64_t deadline_beat);

/* Validates whether a flat frame matches the configured link serializer contract
   (history windows + permitted frame mode). Exposed for regression tests to
   exercise rejection paths without queuing transports. */
bool cep_fed_link_validate_frame_contract(uint32_t required_payload_history_beats,
                                          uint32_t required_manifest_history_beats,
                                          bool allow_upd_latest,
                                          cepFedFrameMode mode,
                                          const cepFlatFrameConfig* frame,
                                          const char** failure_note);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FED_LINK_ORGAN_H */
