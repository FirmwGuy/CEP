/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Tests for the episodic executor skeleton (queueing, cancellation, budgets). */




#include "test.h"

#include "cep_ep.h"
#include "cep_executor.h"

typedef struct ExecutorProbe {
    bool executed;
    bool guard_probe;
    size_t account_bytes;
    bool guard_result;
    bool cancel_before;
    bool cancel_after;
    bool self_cancel;
    bool cancel_requested_inside;
} ExecutorProbe;

static void
executor_probe_task(void *ctx)
{
    ExecutorProbe *probe = ctx;
    probe->executed = true;

    if (probe->guard_probe) {
        probe->guard_result = cep_ep_require_rw();
    }

    probe->cancel_before = cep_ep_check_cancel();

    if (probe->self_cancel) {
        cep_ep_request_cancel();
        probe->cancel_requested_inside = true;
    }

    if (probe->account_bytes) {
        cep_ep_account_io(probe->account_bytes);
    }

    probe->cancel_after = cep_ep_check_cancel();
}

static void
executor_reset(void)
{
    cep_executor_shutdown();
}

MunitResult
test_executor_runs_task(const MunitParameter params[], void *user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(cep_executor_init());

    ExecutorProbe probe = {
        .guard_probe = true,
        .account_bytes = 0u,
    };

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepExecutorTicket ticket = 0u;
    munit_assert_true(cep_executor_submit_ro(executor_probe_task, &probe, &policy, &ticket));
    munit_assert_uint64(ticket, !=, 0u);

    munit_assert_true(test_executor_wait_until_empty(128));

    munit_assert_true(probe.executed);
    munit_assert_false(probe.guard_result);
    munit_assert_false(probe.cancel_before);
    munit_assert_false(probe.cancel_after);

    executor_reset();
    return MUNIT_OK;
}

MunitResult
test_executor_cancel_pending(const MunitParameter params[], void *user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(cep_executor_init());

    ExecutorProbe probe = {
        .guard_probe = false,
        .account_bytes = 0u,
    };

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepExecutorTicket ticket = 0u;
    munit_assert_true(cep_executor_submit_ro(executor_probe_task, &probe, &policy, &ticket));
    munit_assert_true(cep_ep_cancel_ticket(ticket));

    munit_assert_true(test_executor_wait_until_empty(128));
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    if (probe.executed) {
        munit_assert_true(probe.cancel_before);
        munit_assert_true(probe.cancel_after);
    } else {
        munit_assert_size(cep_executor_pending(), ==, 0u);
    }
#else
    munit_assert_false(probe.executed);
    munit_assert_size(cep_executor_pending(), ==, 0u);
#endif

    executor_reset();
    return MUNIT_OK;
}

MunitResult
test_executor_io_budget_cancel(const MunitParameter params[], void *user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(cep_executor_init());

    ExecutorProbe probe = {
        .guard_probe = false,
        .account_bytes = 1024u,
    };

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = 512u,
    };

    cepExecutorTicket ticket = 0u;
    munit_assert_true(cep_executor_submit_ro(executor_probe_task, &probe, &policy, &ticket));

    munit_assert_true(test_executor_wait_until_empty(128));

    munit_assert_true(probe.executed);
    munit_assert_false(probe.cancel_before);
    munit_assert_true(probe.cancel_after);

    executor_reset();
    return MUNIT_OK;
}

MunitResult
test_executor_self_cancel(const MunitParameter params[], void *user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(cep_executor_init());

    ExecutorProbe probe = {
        .guard_probe = false,
        .account_bytes = 0u,
        .self_cancel = true,
    };

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepExecutorTicket ticket = 0u;
    munit_assert_true(cep_executor_submit_ro(executor_probe_task, &probe, &policy, &ticket));

    munit_assert_true(test_executor_wait_until_empty(128));

    munit_assert_true(probe.executed);
    munit_assert_false(probe.cancel_before);
    munit_assert_true(probe.cancel_after);
    munit_assert_true(probe.cancel_requested_inside);

    executor_reset();
    return MUNIT_OK;
}
