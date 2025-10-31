#ifndef CEP_EXECUTOR_H
#define CEP_EXECUTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/*
 * Episodic execution support (read-only worker pools + cooperative context).
 * This skeleton keeps the API stable while the underlying implementation is
 * developed. Mutating work remains cooperative; threaded execution is reserved
 * for read-only slices.
 */

typedef enum cepEpProfile {
    CEP_EP_PROFILE_RO = 0,
    CEP_EP_PROFILE_RW = 1,
} cepEpProfile;

typedef uint64_t cepExecutorTicket;

typedef struct cepEpExecutionPolicy {
    cepEpProfile profile;
    uint64_t     cpu_budget_ns;
    size_t       io_budget_bytes;
} cepEpExecutionPolicy;

typedef struct cepEpExecutionContext {
    cepEpProfile profile;
    uint64_t     cpu_budget_ns;
    size_t       io_budget_bytes;
    void        *user_data;
    uint64_t     cpu_consumed_ns;
    size_t       io_consumed_bytes;
    bool         allow_without_lease;
    atomic_bool  cancel_requested;
    cepExecutorTicket ticket;
} cepEpExecutionContext;

#define CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS   (5ULL * 1000ULL * 1000ULL)  /* 5ms per slice */
#define CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES (1ULL << 20)                /* 1 MiB per slice */
#define CEP_EXECUTOR_QUEUE_CAPACITY          64u

/* Initialise / shutdown the executor back-end (no-op in the stub). */
bool cep_executor_init(void);
void cep_executor_shutdown(void);

/* Submit a read-only task to the worker pool (stubbed to synchronous call). */
bool cep_executor_submit_ro(void (*task)(void *ctx),
                            void *ctx,
                            const cepEpExecutionPolicy *policy,
                            cepExecutorTicket *out_ticket);

/* Request cooperative cancellation of a pending task. */
bool cep_executor_cancel(cepExecutorTicket ticket);

/* Service queued tasks (cooperative, heartbeat-driven). */
void cep_executor_service(void);

/* Inspect queue depth for diagnostics/tests. */
size_t cep_executor_pending(void);

/* Thread-local context helpers (used by mutation guards). */
void cep_executor_context_set(cepEpExecutionContext *context);
cepEpExecutionContext *cep_executor_context_get(void);
void cep_executor_context_clear(void);

/* Helper for mutation guards; returns true only when profile permits writes. */
bool cep_ep_require_rw(void);

#endif /* CEP_EXECUTOR_H */
