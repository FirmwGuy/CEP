/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_FED_MIRROR_ORGAN_H
#define CEP_FED_MIRROR_ORGAN_H

#include "fed_transport_manager.h"
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_flat_serializer.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool cep_fed_mirror_organ_init(cepFedTransportManager* manager,
                               cepCell* net_root);

int cep_fed_mirror_validator(const cepPath* signal_path,
                             const cepPath* target_path);

int cep_fed_mirror_destructor(const cepPath* signal_path,
                              const cepPath* target_path);

bool cep_fed_mirror_emit_cell(const char* peer_id,
                              const char* mount_id,
                              const cepCell* cell,
                              const cepSerializationHeader* header,
                              size_t blob_payload_bytes,
                              cepFedFrameMode mode,
                              uint64_t deadline_beat);

/* Validates whether a flat frame satisfies the mirror contract (frame mode and
   advertised history windows). Exposed for regression tests so they can assert
   on rejection paths without plumbing full mounts. */
bool cep_fed_mirror_validate_frame_contract(uint32_t required_payload_history_beats,
                                            uint32_t required_manifest_history_beats,
                                            cepFedFrameMode mode,
                                            const cepFlatFrameConfig* frame,
                                            const char** failure_note);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FED_MIRROR_ORGAN_H */
