/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef CEP_ASYNC_H
#define CEP_ASYNC_H

#include "cep_ops.h"
#include "cep_heartbeat.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cepAsyncRuntimeState cepAsyncRuntimeState;

cepAsyncRuntimeState* cep_async_state_create(void);
void                  cep_async_state_destroy(cepAsyncRuntimeState* state);

bool cep_async_runtime_enqueue_completion(cepAsyncRuntimeState* state,
                                          cepOID oid,
                                          const cepDT* request_name,
                                          const cepOpsAsyncIoReqInfo* info);

void cep_async_runtime_on_phase(cepAsyncRuntimeState* state, cepBeatPhase phase);

cepOID cep_async_ops_oid(void);

bool cep_async_register_channel(cepOID oid,
                                const cepDT* channel_name,
                                const cepOpsAsyncChannelInfo* info);

bool cep_async_register_request(cepOID oid,
                                const cepDT* request_name,
                                const cepOpsAsyncIoReqInfo* info);

bool cep_async_post_completion(cepOID oid,
                               const cepDT* request_name,
                               const cepOpsAsyncIoReqInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* CEP_ASYNC_H */
