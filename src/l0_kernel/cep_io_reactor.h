/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef CEP_IO_REACTOR_H
#define CEP_IO_REACTOR_H

#include "cep_ops.h"
#include "cep_heartbeat.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CEP_IO_REACTOR_PAUSE_DEADLINE_BEATS 2u

typedef struct cepIoReactorJobContext cepIoReactorJobContext;

typedef struct {
    bool     success;
    uint64_t bytes_done;
    int      error_code;
} cepIoReactorResult;

typedef bool (*cepIoReactorJobFn)(void* context, cepIoReactorResult* out_result);
typedef void (*cepIoReactorJobDestroyFn)(void* context);
typedef void (*cepIoReactorCompletionFn)(void* context, const cepIoReactorResult* result);

typedef struct {
    cepOID                   owner;
    cepDT                    request_name;
    cepOpsAsyncIoReqInfo     success_info;
    cepOpsAsyncIoReqInfo     failure_info;
    uint32_t                 beats_budget;
    bool                     has_beats_budget;
    cepDT                    timeout_topic;
    bool                     has_timeout_topic;
    uint64_t                 bytes_expected;
    bool                     has_bytes_expected;
    bool                     shim_fallback;
    cepIoReactorJobFn        worker;
    void*                    worker_context;
    cepIoReactorJobDestroyFn destroy;
    cepIoReactorCompletionFn on_complete;
    void*                    on_complete_context;
} cepIoReactorWork;

typedef struct {
    cepOID               owner;
    cepDT                request_name;
    cepOpsAsyncIoReqInfo info;
    bool                 timed_out;
    bool                 shim_fallback;
    cepDT                timeout_topic;
    bool                 has_timeout_topic;
    uint64_t             bytes_done;
    bool                 has_bytes_done;
    cepIoReactorResult   result;
    bool                 has_result;
    cepIoReactorCompletionFn on_complete;
    void*                on_complete_context;
} cepIoReactorCompletion;

bool cep_io_reactor_submit(const cepIoReactorWork* work);
bool cep_io_reactor_next_completion(cepIoReactorCompletion* out_completion);
void cep_io_reactor_on_phase(cepBeatPhase phase);
bool cep_io_reactor_quiesce(uint32_t deadline_beats);
void cep_io_reactor_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_IO_REACTOR_H */
