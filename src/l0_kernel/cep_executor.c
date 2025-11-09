/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_executor.h"
#include "cep_ep.h"
#include "cep_runtime.h"

#include "cep_cei.h"
#include "cep_heartbeat.h"
#include "cep_sync.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

typedef enum {
    CEP_EXECUTOR_SLOT_EMPTY = 0,
    CEP_EXECUTOR_SLOT_PENDING,
    CEP_EXECUTOR_SLOT_RUNNING,
    CEP_EXECUTOR_SLOT_CANCELLED,
} cepExecutorSlotState;

typedef struct {
    cepExecutorTicket      ticket;
    void                 (*fn)(void *ctx);
    void                  *ctx;
    cepEpExecutionContext  context;
    cepRuntime*            runtime;
    cepExecutorSlotState   state;
    uint64_t               submitted_beat;
} cepExecutorTask;

typedef struct {
    cepEpExecutionContext* ctx;
    cepRuntime*            runtime;
} cepExecutorTlsSlot;

static _Thread_local cepExecutorTlsSlot executor_tls = {0};

static inline cepRuntime*
cep_executor_active_runtime(void)
{
    if (executor_tls.runtime) {
        return executor_tls.runtime;
    }
    return cep_runtime_default();
}

#if defined(CEP_EXECUTOR_BACKEND_THREADED)

typedef struct {
    cepExecutorTask slots[CEP_EXECUTOR_QUEUE_CAPACITY];
    size_t          head;
    size_t          tail;
    size_t          count;
    cepExecutorTicket next_ticket;
    bool            initialised;
    bool            shutting_down;
    cepMutex        mutex;
    cepCond         cond;
    cepThread*      workers;
    size_t          worker_count;
} cepExecutorRuntimeState;

static cepExecutorRuntimeState*
cep_executor_state_ptr(void)
{
    return cep_runtime_executor_state(cep_executor_active_runtime());
}

#define executor_state (*cep_executor_state_ptr())

static inline uint64_t
cep_executor_now_ns(void)
{
#if defined(CLOCK_MONOTONIC)
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        }
    }
#endif
#if defined(TIME_UTC)
    {
        struct timespec ts;
        if (timespec_get(&ts, TIME_UTC) == TIME_UTC) {
            return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        }
    }
#endif
    return 0u;
}

static void
cep_executor_reset_task(cepExecutorTask *task)
{
    if (!task) {
        return;
    }
    memset(task, 0, sizeof *task);
    task->state = CEP_EXECUTOR_SLOT_EMPTY;
}

static void
cep_executor_emit_budget_overrun(const cepEpExecutionContext *ctx)
{
    char note[160];
    snprintf(note,
             sizeof note,
             "cpu budget exceeded: consumed=%" PRIu64 "ns budget=%" PRIu64 "ns",
             (uint64_t)ctx->cpu_consumed_ns,
             (uint64_t)ctx->cpu_budget_ns);

    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:usage"),
        .topic = "ep:budget/cpu",
        .topic_intern = true,
        .note = note,
        .emit_signal = false,
        .ttl_forever = true,
    };
    cep_cei_emit(&req);
}

static void*
cep_executor_worker(void* arg)
{
    (void)arg;
    for (;;) {
        cepExecutorTask* slot = NULL;

        cep_mutex_lock(&executor_state.mutex);
        while (!executor_state.shutting_down && executor_state.count == 0u) {
            cep_cond_wait(&executor_state.cond, &executor_state.mutex);
        }
        if (executor_state.shutting_down) {
            cep_mutex_unlock(&executor_state.mutex);
            break;
        }

        slot = &executor_state.slots[executor_state.head];
        executor_state.head = (executor_state.head + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
        executor_state.count--;

        if (slot->state == CEP_EXECUTOR_SLOT_CANCELLED) {
            cep_executor_reset_task(slot);
            cep_mutex_unlock(&executor_state.mutex);
            continue;
        }

        slot->state = CEP_EXECUTOR_SLOT_RUNNING;
        cep_mutex_unlock(&executor_state.mutex);

        executor_tls.ctx = &slot->context;
        executor_tls.runtime = slot->runtime;
        cepRuntime* previous_runtime_scope = cep_runtime_set_active(slot->runtime);

        uint64_t start_ns = cep_executor_now_ns();
        slot->fn(slot->ctx);
        uint64_t end_ns = cep_executor_now_ns();

        if (end_ns >= start_ns) {
            uint64_t delta = end_ns - start_ns;
            if (UINT64_MAX - slot->context.cpu_consumed_ns < delta) {
                slot->context.cpu_consumed_ns = UINT64_MAX;
            } else {
                slot->context.cpu_consumed_ns += delta;
            }
        }

        executor_tls.ctx = NULL;
        executor_tls.runtime = NULL;
        cep_runtime_restore_active(previous_runtime_scope);

        bool cpu_over_budget = slot->context.cpu_budget_ns &&
                               slot->context.cpu_consumed_ns > slot->context.cpu_budget_ns;
        if (cpu_over_budget) {
            atomic_store(&slot->context.cancel_requested, true);
            cep_executor_emit_budget_overrun(&slot->context);
        }

        cep_mutex_lock(&executor_state.mutex);
        cep_executor_reset_task(slot);
        cep_mutex_unlock(&executor_state.mutex);
    }
    return NULL;
}

static cepExecutorTicket
cep_executor_next_ticket(void)
{
    cepExecutorTicket ticket = executor_state.next_ticket++;
    if (executor_state.next_ticket == 0u) {
        executor_state.next_ticket = 1u;
    }
    return ticket;
}

bool
cep_executor_init(void)
{
    memset(&executor_state, 0, sizeof executor_state);
    executor_state.initialised = true;
    executor_state.next_ticket = 1u;
    executor_tls.ctx = NULL;
    executor_tls.runtime = NULL;

    if (!cep_mutex_init(&executor_state.mutex)) {
        executor_state.initialised = false;
        return false;
    }
    if (!cep_cond_init(&executor_state.cond)) {
        cep_mutex_destroy(&executor_state.mutex);
        executor_state.initialised = false;
        return false;
    }

    unsigned cpu = cep_cpu_count();
    if (cpu == 0u) {
        cpu = 1u;
    }
    if (cpu > CEP_EXECUTOR_QUEUE_CAPACITY) {
        cpu = CEP_EXECUTOR_QUEUE_CAPACITY;
    }

    executor_state.worker_count = cpu;
    executor_state.workers = (cepThread*)calloc(cpu, sizeof *executor_state.workers);
    if (!executor_state.workers) {
        cep_cond_destroy(&executor_state.cond);
        cep_mutex_destroy(&executor_state.mutex);
        executor_state.initialised = false;
        return false;
    }

    for (size_t i = 0; i < executor_state.worker_count; ++i) {
        if (!cep_thread_start(&executor_state.workers[i], cep_executor_worker, NULL)) {
            executor_state.shutting_down = true;
            for (size_t j = 0; j < i; ++j) {
                cep_thread_detach(&executor_state.workers[j]);
            }
            free(executor_state.workers);
            executor_state.workers = NULL;
            executor_state.worker_count = 0u;
            cep_cond_destroy(&executor_state.cond);
            cep_mutex_destroy(&executor_state.mutex);
            executor_state.initialised = false;
            return false;
        }
    }

    for (size_t i = 0; i < CEP_EXECUTOR_QUEUE_CAPACITY; ++i) {
        executor_state.slots[i].state = CEP_EXECUTOR_SLOT_EMPTY;
    }

    return true;
}

void
cep_executor_shutdown(void)
{
    if (!executor_state.initialised) {
        return;
    }

    cep_mutex_lock(&executor_state.mutex);
    executor_state.shutting_down = true;
    cep_cond_broadcast(&executor_state.cond);
    cep_mutex_unlock(&executor_state.mutex);

    for (size_t i = 0; i < executor_state.worker_count; ++i) {
        cep_thread_join(&executor_state.workers[i]);
    }

    free(executor_state.workers);
    executor_state.workers = NULL;
    executor_state.worker_count = 0u;

    cep_cond_destroy(&executor_state.cond);
    cep_mutex_destroy(&executor_state.mutex);

    memset(&executor_state, 0, sizeof executor_state);
    executor_tls.ctx = NULL;
    executor_tls.runtime = NULL;
}

size_t
cep_executor_pending(void)
{
    size_t pending = 0u;
    cep_mutex_lock(&executor_state.mutex);
    pending = executor_state.count;
    cep_mutex_unlock(&executor_state.mutex);
    return pending;
}

bool
cep_executor_submit_ro(void (*task)(void *ctx),
                       void *ctx,
                       const cepEpExecutionPolicy *policy,
                       cepExecutorTicket *out_ticket)
{
    if (!executor_state.initialised || !task) {
        return false;
    }

    cep_mutex_lock(&executor_state.mutex);

    if (executor_state.shutting_down || executor_state.count >= CEP_EXECUTOR_QUEUE_CAPACITY) {
        cep_mutex_unlock(&executor_state.mutex);
        return false;
    }

    cepExecutorTask *slot = &executor_state.slots[executor_state.tail];
    cep_executor_reset_task(slot);

    slot->ticket = cep_executor_next_ticket();
    slot->fn = task;
    slot->ctx = ctx;
    slot->runtime = cep_executor_active_runtime();
    slot->state = CEP_EXECUTOR_SLOT_PENDING;

    cepEpExecutionContext *ctx_out = &slot->context;
    ctx_out->profile = CEP_EP_PROFILE_RO;
    ctx_out->cpu_budget_ns = (policy && policy->cpu_budget_ns)
        ? policy->cpu_budget_ns
        : CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS;
    ctx_out->io_budget_bytes = (policy && policy->io_budget_bytes)
        ? policy->io_budget_bytes
        : CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES;
    ctx_out->user_data = ctx;
    ctx_out->cpu_consumed_ns = 0u;
    ctx_out->io_consumed_bytes = 0u;
    atomic_store(&ctx_out->cancel_requested, false);
    ctx_out->ticket = slot->ticket;
    ctx_out->runtime = slot->runtime;

    slot->submitted_beat = cep_beat_index();

    executor_state.tail = (executor_state.tail + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
    executor_state.count++;

    if (out_ticket) {
        *out_ticket = slot->ticket;
    }

    cep_cond_signal(&executor_state.cond);
    cep_mutex_unlock(&executor_state.mutex);

    return true;
}

bool
cep_executor_cancel(cepExecutorTicket ticket)
{
    if (!executor_state.initialised || ticket == 0u) {
        return false;
    }

    bool result = false;

    cep_mutex_lock(&executor_state.mutex);
    for (size_t i = 0; i < CEP_EXECUTOR_QUEUE_CAPACITY; ++i) {
        cepExecutorTask *slot = &executor_state.slots[i];
        if (slot->ticket != ticket) {
            continue;
        }
        atomic_store(&slot->context.cancel_requested, true);
        if (slot->state == CEP_EXECUTOR_SLOT_PENDING) {
            slot->state = CEP_EXECUTOR_SLOT_CANCELLED;
        }
        result = true;
        break;
    }
    cep_mutex_unlock(&executor_state.mutex);

    return result;
}

void
cep_executor_service(void)
{
    (void)0;
}

void
cep_executor_context_set(cepEpExecutionContext *context)
{
    executor_tls.ctx = context;
    executor_tls.runtime = context ? context->runtime : NULL;
}

cepEpExecutionContext *
cep_executor_context_get(void)
{
    return executor_tls.ctx;
}

void
cep_executor_context_clear(void)
{
    executor_tls.ctx = NULL;
    executor_tls.runtime = NULL;
}

struct cepExecutorRuntimeState*
cep_executor_state_create(void)
{
    return cep_malloc0(sizeof(cepExecutorRuntimeState));
}

void
cep_executor_state_destroy(struct cepExecutorRuntimeState* state)
{
    if (!state) {
        return;
    }
    if (state->workers) {
        cep_free(state->workers);
        state->workers = NULL;
    }
    cep_free(state);
}

#else /* CEP_EXECUTOR_BACKEND_STUB */

typedef struct cepExecutorRuntimeState {
    cepExecutorTask slots[CEP_EXECUTOR_QUEUE_CAPACITY];
    size_t          head;
    size_t          tail;
    size_t          count;
    cepExecutorTicket next_ticket;
    bool            initialised;
} cepExecutorRuntimeState;

static cepExecutorRuntimeState*
cep_executor_state_ptr(void)
{
    return cep_runtime_executor_state(cep_executor_active_runtime());
}

#define executor_state (*cep_executor_state_ptr())

static inline uint64_t
cep_executor_now_ns(void)
{
#if defined(CLOCK_MONOTONIC)
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        }
    }
#endif
#if defined(TIME_UTC)
    {
        struct timespec ts;
        if (timespec_get(&ts, TIME_UTC) == TIME_UTC) {
            return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        }
    }
#endif
    return 0u;
}

static void
cep_executor_reset_task(cepExecutorTask *task)
{
    if (!task) {
        return;
    }
    memset(task, 0, sizeof *task);
    task->state = CEP_EXECUTOR_SLOT_EMPTY;
}

static void
cep_executor_emit_budget_overrun(const cepEpExecutionContext *ctx)
{
    char note[160];
    snprintf(note,
             sizeof note,
             "cpu budget exceeded: consumed=%" PRIu64 "ns budget=%" PRIu64 "ns",
             (uint64_t)ctx->cpu_consumed_ns,
             (uint64_t)ctx->cpu_budget_ns);

    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:usage"),
        .topic = "ep:budget/cpu",
        .topic_intern = true,
        .note = note,
        .emit_signal = false,
        .ttl_forever = true,
    };
    cep_cei_emit(&req);
}

bool
cep_executor_init(void)
{
    memset(&executor_state, 0, sizeof executor_state);
    executor_state.initialised = true;
    executor_state.next_ticket = 1u;
    executor_tls.ctx = NULL;
    executor_tls.runtime = NULL;
    for (size_t i = 0; i < CEP_EXECUTOR_QUEUE_CAPACITY; ++i) {
        executor_state.slots[i].state = CEP_EXECUTOR_SLOT_EMPTY;
    }
    return true;
}

void
cep_executor_shutdown(void)
{
    memset(&executor_state, 0, sizeof executor_state);
    executor_tls.ctx = NULL;
    executor_tls.runtime = NULL;
}

size_t
cep_executor_pending(void)
{
    return executor_state.count;
}

static cepExecutorTicket
cep_executor_next_ticket(void)
{
    cepExecutorTicket ticket = executor_state.next_ticket++;
    if (executor_state.next_ticket == 0u) {
        executor_state.next_ticket = 1u;
    }
    return ticket;
}

bool
cep_executor_submit_ro(void (*task)(void *ctx),
                       void *ctx,
                       const cepEpExecutionPolicy *policy,
                       cepExecutorTicket *out_ticket)
{
    if (!executor_state.initialised || !task) {
        return false;
    }

    if (executor_state.count >= CEP_EXECUTOR_QUEUE_CAPACITY) {
        return false;
    }

    cepExecutorTask *slot = &executor_state.slots[executor_state.tail];
    cep_executor_reset_task(slot);

    slot->ticket = cep_executor_next_ticket();
    slot->fn = task;
    slot->ctx = ctx;
    slot->runtime = cep_executor_active_runtime();
    slot->state = CEP_EXECUTOR_SLOT_PENDING;

    cepEpExecutionContext *ctx_out = &slot->context;
    ctx_out->profile = CEP_EP_PROFILE_RO;
    ctx_out->cpu_budget_ns = (policy && policy->cpu_budget_ns)
        ? policy->cpu_budget_ns
        : CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS;
    ctx_out->io_budget_bytes = (policy && policy->io_budget_bytes)
        ? policy->io_budget_bytes
        : CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES;
    ctx_out->user_data = ctx;
    ctx_out->cpu_consumed_ns = 0u;
    ctx_out->io_consumed_bytes = 0u;
    atomic_store(&ctx_out->cancel_requested, false);
    ctx_out->ticket = slot->ticket;
    ctx_out->runtime = slot->runtime;

    slot->submitted_beat = cep_beat_index();

    executor_state.tail = (executor_state.tail + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
    executor_state.count++;

    if (out_ticket) {
        *out_ticket = slot->ticket;
    }

    return true;
}

bool
cep_executor_cancel(cepExecutorTicket ticket)
{
    if (!executor_state.initialised || ticket == 0u || executor_state.count == 0u) {
        return false;
    }

    size_t index = executor_state.head;
    for (size_t i = 0; i < executor_state.count; ++i) {
        cepExecutorTask *slot = &executor_state.slots[index];
        if (slot->ticket == ticket && slot->state != CEP_EXECUTOR_SLOT_EMPTY) {
            atomic_store(&slot->context.cancel_requested, true);
            if (slot->state == CEP_EXECUTOR_SLOT_PENDING) {
                slot->state = CEP_EXECUTOR_SLOT_CANCELLED;
            }
            return true;
        }
        index = (index + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
    }

    return false;
}

void
cep_executor_service(void)
{
    if (!executor_state.initialised || executor_state.count == 0u) {
        return;
    }

    cepExecutorTask *slot = &executor_state.slots[executor_state.head];

    if (slot->state == CEP_EXECUTOR_SLOT_EMPTY) {
        executor_state.head = (executor_state.head + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
        executor_state.count--;
        return;
    }

    bool cancel_requested = atomic_load(&slot->context.cancel_requested);
    if (slot->state == CEP_EXECUTOR_SLOT_CANCELLED || cancel_requested) {
        cep_executor_reset_task(slot);
        executor_state.head = (executor_state.head + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
        executor_state.count--;
        return;
    }

    slot->state = CEP_EXECUTOR_SLOT_RUNNING;
    executor_tls.ctx = &slot->context;
    executor_tls.runtime = slot->runtime;
    cepRuntime* previous_runtime_scope = cep_runtime_set_active(slot->runtime);

    uint64_t start_ns = cep_executor_now_ns();
    slot->fn(slot->ctx);
    uint64_t end_ns = cep_executor_now_ns();

    if (end_ns >= start_ns) {
        uint64_t delta = end_ns - start_ns;
        if (UINT64_MAX - slot->context.cpu_consumed_ns < delta) {
            slot->context.cpu_consumed_ns = UINT64_MAX;
        } else {
            slot->context.cpu_consumed_ns += delta;
        }
    }

    executor_tls.ctx = NULL;
    executor_tls.runtime = NULL;
    cep_runtime_restore_active(previous_runtime_scope);

    bool cpu_over_budget = slot->context.cpu_budget_ns &&
                           slot->context.cpu_consumed_ns > slot->context.cpu_budget_ns;
    if (cpu_over_budget) {
        atomic_store(&slot->context.cancel_requested, true);
        cep_executor_emit_budget_overrun(&slot->context);
    }

    cep_executor_reset_task(slot);
    executor_state.head = (executor_state.head + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
    executor_state.count--;
}

void
cep_executor_context_set(cepEpExecutionContext *context)
{
    executor_tls.ctx = context;
    executor_tls.runtime = context ? context->runtime : NULL;
}

cepEpExecutionContext *
cep_executor_context_get(void)
{
    return executor_tls.ctx;
}

void
cep_executor_context_clear(void)
{
    executor_tls.ctx = NULL;
    executor_tls.runtime = NULL;
}

struct cepExecutorRuntimeState*
cep_executor_state_create(void)
{
    return cep_malloc0(sizeof(cepExecutorRuntimeState));
}

void
cep_executor_state_destroy(struct cepExecutorRuntimeState* state)
{
    if (!state) {
        return;
    }
    cep_free(state);
}

#endif /* CEP_EXECUTOR_BACKEND_THREADED */

bool
cep_ep_require_rw(void)
{
    cepEpExecutionContext *ctx = executor_tls.ctx;
    if (!ctx) {
        return true;
    }
    if (ctx->profile == CEP_EP_PROFILE_RO || ctx->profile == CEP_EP_PROFILE_HYBRID) {
        CEP_DEBUG_PRINTF("[cep_ep_require_rw] profile=RO ctx=%p\n", (void*)ctx);
        cepCeiRequest req = {
            .severity = *CEP_DTAW("CEP", "sev:usage"),
            .topic = "ep:pro/ro",
            .topic_len = 0,
            .note = "mutation attempted from read-only episode",
            .note_len = 0,
            .emit_signal = false,
            .attach_to_op = false,
            .ttl_forever = true,
        };
        cepEpExecutionContext *saved = executor_tls.ctx;
        executor_tls.ctx = NULL;
        cep_cei_emit(&req);
        executor_tls.ctx = saved;
        return false;
    }
    if (ctx->profile == CEP_EP_PROFILE_RW) {
        void* episode = ctx->user_data;
        bool has_lease = cep_ep_episode_has_active_lease(episode);
        CEP_DEBUG_PRINTF("[cep_ep_require_rw] profile=RW ctx=%p allow_without_lease=%d has_lease=%d\n",
                         (void*)ctx,
                         ctx->allow_without_lease ? 1 : 0,
                         has_lease ? 1 : 0);
        if (!ctx->allow_without_lease && !has_lease) {
            if (cep_ep_episode_record_violation(episode)) {
                cepCeiRequest req = {
                    .severity = *CEP_DTAW("CEP", "sev:usage"),
                    .topic = "ep:lease/missing",
                    .topic_len = 0,
                    .note = "mutation attempted without active lease",
                    .note_len = 0,
                    .emit_signal = false,
                    .attach_to_op = false,
                    .ttl_forever = true,
                };
                cepEpExecutionContext *saved = executor_tls.ctx;
                executor_tls.ctx = NULL;
                cep_cei_emit(&req);
                executor_tls.ctx = saved;
            }
            return false;
        }
        cep_ep_episode_clear_violation(episode);
    }
    return true;
}
