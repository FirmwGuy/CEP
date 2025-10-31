/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Test harness entry points for CEP core suites. */



#include "test.h"
#include "cep_ops.h"
#include "cep_executor.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

extern MunitSuite integration_poc_suite;

static bool ovh_trace_initialized;
static bool ovh_trace_enabled_flag;

bool test_ovh_trace_enabled(void) {
    if (!ovh_trace_initialized) {
        const char* env = getenv("TEST_WATCHDOG_TRACE");
        ovh_trace_enabled_flag = (env && env[0] && env[0] != '0');
        ovh_trace_initialized = true;
    }
    return ovh_trace_enabled_flag;
}

void test_ovh_tracef(const char* fmt, ...) {
    if (!test_ovh_trace_enabled())
        return;
    va_list args;
    va_start(args, fmt);
    fputs("[ovh] ", stderr);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(args);
}

bool test_ovh_heartbeat_step(const char* label) {
    cepBeatNumber before = cep_heartbeat_current();
    test_ovh_tracef("%s before beat=%" PRIu64, label, (uint64_t)before);
    bool ok = cep_heartbeat_step();
    cepBeatNumber after = cep_heartbeat_current();
    test_ovh_tracef("%s after beat=%" PRIu64 " ok=%d", label, (uint64_t)after, ok ? 1 : 0);
    if (!ok && test_ovh_trace_enabled()) {
        test_ovh_tracef("%s heartbeat_step failed ops_error=%d", label, cep_ops_debug_last_error());
    }
    return ok;
}

void test_executor_relax(void)
{
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1 * 1000 * 1000,
    };
    nanosleep(&ts, NULL);
#else
    cep_executor_service();
#endif
}

bool test_executor_wait_until_empty(unsigned spins)
{
    for (unsigned i = 0; i < spins; ++i) {
        if (cep_executor_pending() == 0u) {
            return true;
        }
        test_executor_relax();
    }
    return cep_executor_pending() == 0u;
}

bool test_executor_wait_for_calls(atomic_uint* counter, unsigned target, unsigned spins)
{
    if (!counter) {
        return false;
    }
    for (unsigned i = 0; i < spins; ++i) {
        if (atomic_load(counter) >= target) {
            return true;
        }
        test_executor_relax();
    }
    return atomic_load(counter) >= target;
}



static char* boot_cycle_values[] = {
    TEST_BOOT_CYCLE_FRESH,
    TEST_BOOT_CYCLE_AFTER,
    NULL
};

static MunitParameterEnum boot_cycle_params[] = {
    {"boot_cycle", boot_cycle_values},
    {NULL, NULL}
};

static MunitParameterEnum boot_cycle_timeout_params[] = {
    {"boot_cycle", boot_cycle_values},
    {"timeout", NULL},
    {NULL, NULL}
};

static MunitParameterEnum boot_cycle_text_params[] = {
    {"boot_cycle", boot_cycle_values},
    {"text", NULL},
    {NULL, NULL}
};


MunitTest tests[] = {
    {
        "/cell",
        test_cell,
        test_cell_setup,
        test_cell_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params  // Parameters.
    },
    {
        "/cell/immutable",
        test_cell_immutable,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/traverse",
        test_traverse,
        test_traverse_setup,
        test_traverse_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params  // Parameters.
    },
    {
        "/traverse/all",
        test_traverse_all,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/domain_tag_naming",
        test_domain_tag_naming,
        NULL,                     // Setup
        NULL,                     // Tear_down
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_text_params
    },
    {
        "/identifier",
        test_identifier,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/mailbox/public",
        test_mailbox_board,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/mailbox/private",
        test_mailbox_private,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/cei/mailbox",
        test_cei_mailbox,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/cei/cell_append_guard",
        test_cell_append_guard_cei,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/cei/signal_ledger",
        test_cei_signal_ledger,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/cei/op_failure",
        test_cei_op_failure,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/cei/fatal_shutdown",
        test_cei_fatal_shutdown,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/pause_resume_backlog",
        test_prr_pause_resume_backlog,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/pause_rollback_backlog_guard",
        test_prr_pause_rollback_backlog_guard,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/soft_delete_lookup",
        test_prr_soft_delete_lookup,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/view_horizon_snapshot",
        test_prr_view_horizon_snapshot,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/soft_deleted_dictionary_revives",
        test_prr_soft_deleted_dictionary_revives,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/history_autoid_monotonic",
        test_prr_history_autoid_monotonic,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/minimal_rollback",
        test_prr_minimal_rollback,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/control_failure_cei",
        test_prr_control_failure_cei,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/prr/watcher_timeout_cei",
        test_prr_watcher_timeout_cei,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/ops",
        test_ops,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/heartbeat/single",
        test_heartbeat_single,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params
    },
    {
        "/heartbeat/bootstrap",
        test_heartbeat_bootstrap,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/sys_state",
        test_organ_sys_state_validator,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/rt_ops",
        test_organ_rt_ops_validator,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/bootstrap/constructors",
        test_organ_constructor_bootstrap,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/destructors/cycles",
        test_organ_constructor_destructor_cycles,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/constructors",
        test_organ_constructor_dossier,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/destructors",
        test_organ_destructor_dossier,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/dossiers",
        test_organ_dossier_sequence,
        test_ovh_watchdog_setup,
        test_ovh_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/serialization/cell",
        test_serialization,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/serialization/proxy",
        test_serialization_proxy,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/stream/episode_guard",
        test_ep_stream_access,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/stream/stdio",
        test_stream_stdio,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
#ifdef CEP_HAS_LIBZIP
    {
        "/stream/zip",
        test_stream_zip,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
#endif
    {
        "/executor/queue",
        test_executor_runs_task,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/executor/cancel",
        test_executor_cancel_pending,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/executor/io_budget",
        test_executor_io_budget_cancel,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/executor/self_cancel",
        test_executor_self_cancel,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/episode/yield_resume",
        test_episode_yield_resume,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/episode/await_resume",
        test_episode_await_resume,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/episode/await_timeout",
        test_episode_await_timeout,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/episode/lease_enforcement",
        test_episode_lease_enforcement,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/episode/rw_suspend_resume",
        test_episode_rw_suspend_resume,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },

    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}  // EOL
};


int main(int argC, char* argV[MUNIT_ARRAY_PARAM(argC + 1)]) {
    MunitSuite sub_suites[3];
    size_t suite_index = 0u;

    for (size_t i = 0u; lock_suites[i].tests != NULL && suite_index < cep_lengthof(sub_suites) - 1u; ++i) {
        sub_suites[suite_index++] = lock_suites[i];
    }
    sub_suites[suite_index++] = integration_poc_suite;
    sub_suites[suite_index] = (MunitSuite){0};

    MunitSuite root = {
        "/CEP",
        tests,
        sub_suites,
        1,
        MUNIT_SUITE_OPTION_NONE
    };

    return munit_suite_main(&root, NULL, argC, argV);
}
