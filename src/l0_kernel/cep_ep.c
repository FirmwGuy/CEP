#include "cep_ep.h"

#include "cep_cei.h"
#include "cep_executor.h"
#include "stream/cep_stream_internal.h"

#include <stdio.h>

bool
cep_ep_stream_write(cepCell* cell, uint64_t offset, const void* src, size_t size, size_t* out_written)
{
    return cep_cell_stream_write(cell, offset, src, size, out_written);
}

bool
cep_ep_stream_commit_pending(void)
{
    return cep_stream_commit_pending();
}

void
cep_ep_stream_clear_pending(void)
{
    cep_stream_clear_pending();
}

size_t
cep_ep_stream_pending_count(void)
{
    return cep_stream_pending_count();
}

bool
cep_ep_cancel_ticket(cepExecutorTicket ticket)
{
    if (!ticket) {
        return false;
    }
    return cep_executor_cancel(ticket);
}

void
cep_ep_request_cancel(void)
{
    cepEpExecutionContext *ctx = cep_executor_context_get();
    if (!ctx) {
        return;
    }
    if (ctx->ticket) {
        (void)cep_executor_cancel(ctx->ticket);
    } else {
        atomic_store(&ctx->cancel_requested, true);
    }
}

static void
cep_ep_emit_io_overrun(const cepEpExecutionContext *ctx)
{
    if (!ctx) {
        return;
    }

    char note[160];
    snprintf(note,
             sizeof note,
             "io budget exceeded: consumed=%zu bytes budget=%zu bytes",
             ctx->io_consumed_bytes,
             ctx->io_budget_bytes);

    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:usage"),
        .topic = "ep:budget/io",
        .topic_intern = true,
        .note = note,
        .emit_signal = false,
        .ttl_forever = true,
    };
    cep_cei_emit(&req);
}

bool
cep_ep_check_cancel(void)
{
    cepEpExecutionContext *ctx = cep_executor_context_get();
    if (!ctx) {
        return false;
    }
    return atomic_load(&ctx->cancel_requested);
}

void
cep_ep_account_io(size_t bytes)
{
    if (!bytes) {
        return;
    }

    cepEpExecutionContext *ctx = cep_executor_context_get();
    if (!ctx) {
        return;
    }

    if (SIZE_MAX - ctx->io_consumed_bytes < bytes) {
        ctx->io_consumed_bytes = SIZE_MAX;
    } else {
        ctx->io_consumed_bytes += bytes;
    }

    if (ctx->io_budget_bytes && ctx->io_consumed_bytes > ctx->io_budget_bytes) {
        bool already = atomic_load(&ctx->cancel_requested);
        atomic_store(&ctx->cancel_requested, true);
        if (!already) {
            cep_ep_emit_io_overrun(ctx);
        }
    }
}
