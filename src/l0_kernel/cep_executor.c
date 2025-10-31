#include "cep_executor.h"

#include "cep_cei.h"
#include "cep_heartbeat.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
    cepExecutorSlotState   state;
    uint64_t               submitted_beat;
} cepExecutorTask;

typedef struct {
    cepExecutorTask slots[CEP_EXECUTOR_QUEUE_CAPACITY];
    size_t          head;
    size_t          tail;
    size_t          count;
    cepExecutorTicket next_ticket;
    bool            initialised;
} cepExecutorState;

static cepExecutorState executor_state;
static _Thread_local cepEpExecutionContext *tls_context;

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

bool
cep_executor_init(void)
{
    memset(&executor_state, 0, sizeof executor_state);
    executor_state.initialised = true;
    executor_state.next_ticket = 1u;
    tls_context = NULL;
    for (size_t i = 0; i < CEP_EXECUTOR_QUEUE_CAPACITY; ++i) {
        executor_state.slots[i].state = CEP_EXECUTOR_SLOT_EMPTY;
    }
    return true;
}

void
cep_executor_shutdown(void)
{
    memset(&executor_state, 0, sizeof executor_state);
    tls_context = NULL;
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
    slot->state = CEP_EXECUTOR_SLOT_PENDING;

    cepEpExecutionContext *ctx_out = &slot->context;
    ctx_out->profile = CEP_EP_PROFILE_RO;
    ctx_out->cpu_budget_ns = (policy && policy->cpu_budget_ns)
        ? policy->cpu_budget_ns
        : CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS;
    ctx_out->io_budget_bytes = (policy && policy->io_budget_bytes)
        ? policy->io_budget_bytes
        : CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES;
    ctx_out->user_data = NULL;
    ctx_out->cpu_consumed_ns = 0u;
    ctx_out->io_consumed_bytes = 0u;
    atomic_store(&ctx_out->cancel_requested, false);
    ctx_out->ticket = slot->ticket;

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

void
cep_executor_service(void)
{
    if (!executor_state.initialised || executor_state.count == 0u) {
        return;
    }

    cepExecutorTask *slot = &executor_state.slots[executor_state.head];

    uint64_t current_beat = cep_beat_index();
    if (current_beat && slot->submitted_beat == current_beat) {
        return;
    }

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

    if (!slot->fn) {
        cep_executor_reset_task(slot);
        executor_state.head = (executor_state.head + 1u) % CEP_EXECUTOR_QUEUE_CAPACITY;
        executor_state.count--;
        return;
    }

    slot->state = CEP_EXECUTOR_SLOT_RUNNING;
    tls_context = &slot->context;

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

    tls_context = NULL;

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
    tls_context = context;
}

cepEpExecutionContext *
cep_executor_context_get(void)
{
    return tls_context;
}

void
cep_executor_context_clear(void)
{
    tls_context = NULL;
}

bool
cep_ep_require_rw(void)
{
    cepEpExecutionContext *ctx = tls_context;
    if (!ctx) {
        return true;
    }
    if (ctx->profile == CEP_EP_PROFILE_RO) {
        cepCeiRequest req = {
            .severity = *CEP_DTAW("CEP", "sev:usage"),
            .topic = "ep:profile/ro",
            .topic_len = 0,
            .note = "mutation attempted from read-only episode",
            .note_len = 0,
            .emit_signal = false,
            .attach_to_op = false,
            .ttl_forever = true,
        };
        cepEpExecutionContext *saved = tls_context;
        tls_context = NULL;
        cep_cei_emit(&req);
        tls_context = saved;
        return false;
    }
    return true;
}
