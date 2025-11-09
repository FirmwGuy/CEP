/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_FED_INVOKE_H
#define CEP_FED_INVOKE_H

#include "fed_transport_manager.h"

#include "../l0_kernel/cep_cell.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cepFedInvokeRequest cepFedInvokeRequest;

typedef void (*cepFedInvokeCompletion)(void* user_ctx, bool ok);

typedef struct {
    const cepPath*            signal_path;
    const cepPath*            target_path;
    uint32_t                  timeout_beats;
    cepFedInvokeCompletion    on_complete;
    void*                     user_ctx;
} cepFedInvokeSubmission;

bool cep_fed_invoke_organ_init(cepFedTransportManager* manager,
                               cepCell* net_root);

int cep_fed_invoke_validator(const cepPath* signal_path,
                             const cepPath* target_path);

int cep_fed_invoke_destructor(const cepPath* signal_path,
                              const cepPath* target_path);

const cepFedInvokeRequest* cep_fed_invoke_request_find(const char* peer_id,
                                                       const char* mount_id);

bool cep_fed_invoke_request_submit(const cepFedInvokeRequest* request,
                                   const cepFedInvokeSubmission* submission);

void cep_fed_invoke_process_frame(cepFedInvokeRequest* request,
                                  const uint8_t* payload,
                                  size_t payload_len,
                                  cepFedFrameMode mode);

int cep_fed_invoke_timeout_enzyme(const cepPath* signal_path,
                                  const cepPath* target_path);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FED_INVOKE_H */
