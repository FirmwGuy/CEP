/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cep_async.h"

#include "cep_cell.h"
#include "cep_io_reactor.h"
#include "cep_runtime.h"

#include <string.h>

#define CEP_ASYNC_COMPLETION_CAP 64u

typedef struct {
    cepOID               owner;
    cepDT                request_name;
    cepOpsAsyncIoReqInfo info;
} cepAsyncCompletion;

typedef struct {
    cepAsyncCompletion entries[CEP_ASYNC_COMPLETION_CAP];
    size_t             head;
    size_t             tail;
    size_t             count;
} cepAsyncCompletionQueue;

struct cepAsyncRuntimeState {
    bool                     initialized;
    cepBeatPhase             last_phase;
    cepBeatNumber            last_compute_beat;
    cepAsyncCompletionQueue  queue;
};

static cepOID g_async_ops_oid = {0};

static cepOID
cep_async_lazy_ops_oid(void)
{
    if (cep_oid_is_valid(g_async_ops_oid)) {
        return g_async_ops_oid;
    }
    cepDT verb = cep_ops_make_dt("op/io");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb,
                              "/rt/async",
                              mode,
                              NULL,
                              0u,
                              0u);
    if (cep_oid_is_valid(oid)) {
        g_async_ops_oid = oid;
    }
    return g_async_ops_oid;
}

cepOID
cep_async_ops_oid(void)
{
    return cep_async_lazy_ops_oid();
}

static void
cep_async_queue_reset(cepAsyncCompletionQueue* queue)
{
    if (!queue) {
        return;
    }
    queue->head = 0u;
    queue->tail = 0u;
    queue->count = 0u;
    memset(queue->entries, 0, sizeof queue->entries);
}

static bool
cep_async_queue_push(cepAsyncCompletionQueue* queue,
                     const cepAsyncCompletion* entry)
{
    if (!queue || !entry) {
        return false;
    }
    if (queue->count >= CEP_ASYNC_COMPLETION_CAP) {
        return false;
    }
    queue->entries[queue->tail] = *entry;
    queue->tail = (queue->tail + 1u) % CEP_ASYNC_COMPLETION_CAP;
    queue->count += 1u;
    return true;
}

static bool
cep_async_queue_pop(cepAsyncCompletionQueue* queue,
                    cepAsyncCompletion* out)
{
    if (!queue || !queue->count) {
        return false;
    }
    if (out) {
        *out = queue->entries[queue->head];
    }
    queue->entries[queue->head] = (cepAsyncCompletion){0};
    queue->head = (queue->head + 1u) % CEP_ASYNC_COMPLETION_CAP;
    queue->count -= 1u;
    return true;
}

cepAsyncRuntimeState*
cep_async_state_create(void)
{
    cepAsyncRuntimeState* state = cep_malloc0(sizeof *state);
    if (!state) {
        return NULL;
    }
    cep_async_queue_reset(&state->queue);
    state->last_phase = CEP_BEAT_CAPTURE;
    state->last_compute_beat = CEP_BEAT_INVALID;
    state->initialized = true;
    return state;
}

void
cep_async_state_destroy(cepAsyncRuntimeState* state)
{
    if (!state) {
        return;
    }
    cep_async_queue_reset(&state->queue);
    cep_free(state);
}

bool
cep_async_runtime_enqueue_completion(cepAsyncRuntimeState* state,
                                     cepOID oid,
                                     const cepDT* request_name,
                                     const cepOpsAsyncIoReqInfo* info)
{
    if (!state || !request_name || !info || !cep_oid_is_valid(oid)) {
        return false;
    }
    if (!state->initialized) {
        state->initialized = true;
    }
    cepAsyncCompletion completion = {0};
    completion.owner = oid;
    completion.request_name = cep_dt_clean(request_name);
    completion.info = *info;
    if (!cep_async_queue_push(&state->queue, &completion)) {
        return false;
    }
    return true;
}

static void
cep_async_drain_completions(cepAsyncRuntimeState* state)
{
    if (!state || !state->queue.count) {
        return;
    }

    cepAsyncCompletion completion = {0};
    while (cep_async_queue_pop(&state->queue, &completion)) {
        if (!cep_op_async_record_request(completion.owner,
                                         &completion.request_name,
                                         &completion.info)) {
            CEP_DEBUG_PRINTF("[async] record_request failed err=%d\n", cep_ops_debug_last_error());
        }
        completion = (cepAsyncCompletion){0};
    }
}

static void
cep_async_ingest_reactor_completions(cepAsyncRuntimeState* state)
{
    if (!state) {
        return;
    }
    cepIoReactorCompletion completion = {0};
    while (cep_io_reactor_next_completion(&completion)) {
        cep_async_runtime_enqueue_completion(state,
                                             completion.owner,
                                             &completion.request_name,
                                             &completion.info);
        if (completion.on_complete) {
            const cepIoReactorResult* result_ptr = completion.has_result ? &completion.result : NULL;
            completion.on_complete(completion.on_complete_context, result_ptr);
        }
    }
}

void
cep_async_runtime_on_phase(cepAsyncRuntimeState* state, cepBeatPhase phase)
{
    if (!state) {
        return;
    }
    cep_io_reactor_on_phase(phase);
    state->last_phase = phase;
    if (!state->initialized) {
        state->initialized = true;
    }
    if (phase == CEP_BEAT_COMPUTE) {
        cep_async_ingest_reactor_completions(state);
        cep_async_drain_completions(state);
    }
}

static cepAsyncRuntimeState*
cep_async_default_state(void)
{
    return cep_runtime_async_state(cep_runtime_default());
}

bool
cep_async_register_channel(cepOID oid,
                           const cepDT* channel_name,
                           const cepOpsAsyncChannelInfo* info)
{
    return cep_op_async_record_channel(oid, channel_name, info);
}

bool
cep_async_register_request(cepOID oid,
                           const cepDT* request_name,
                           const cepOpsAsyncIoReqInfo* info)
{
    return cep_op_async_record_request(oid, request_name, info);
}

bool
cep_async_post_completion(cepOID oid,
                          const cepDT* request_name,
                          const cepOpsAsyncIoReqInfo* info)
{
    cepAsyncRuntimeState* state = cep_async_default_state();
    return cep_async_runtime_enqueue_completion(state, oid, request_name, info);
}

void
cep_async_reset_ops_oid(void)
{
    g_async_ops_oid = (cepOID){0};
}
