/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Test harness entry points for CEP core suites. */



#include "test.h"
#include "cep_ops.h"
#include "cep_executor.h"
#include "../cps/cps_runtime.h"
#include "../l1_coherence/cep_l1_pack.h"
#include "l1_coherence/test_l1_smoke.h"
#include "l2_ecology/test_l2_scaffold.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

extern MunitSuite integration_poc_suite;

static bool ovh_trace_initialized;
static bool ovh_trace_enabled_flag;
static unsigned test_mock_cps_depth;

void test_runtime_enable_mock_cps(void) {
    if (test_mock_cps_depth++ == 0u) {
        cps_runtime_force_mock_mode(true);
    }
}

void test_runtime_disable_mock_cps(void) {
    if (test_mock_cps_depth == 0u) {
        return;
    }
    test_mock_cps_depth--;
    if (test_mock_cps_depth == 0u) {
        cps_runtime_force_mock_mode(false);
    }
}

bool test_runtime_mock_cps_enabled(void) {
    return test_mock_cps_depth > 0u;
}

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
    if (!ok) {
        fprintf(stderr,
                "[instrument][test] heartbeat_step failure label=%s before=%" PRIu64 " after=%" PRIu64 " ops_error=%d\\n",
                label ? label : "(null)",
                (uint64_t)before,
                (uint64_t)after,
                cep_ops_debug_last_error());
        fflush(stderr);
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
        "/cps/replay/inline",
        test_cps_replay_inline,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/cps/replay/cas_cache",
        test_cps_replay_cas_cache,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/cps/replay/cas_runtime",
        test_cps_replay_cas_runtime,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/cps/export/windowed_external",
        test_cps_export_windowed_external,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/cps/stage/external_bundle",
        test_cps_stage_external_bundle,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
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
        "/branch/dirty_tracking",
        test_branch_controller_dirty_tracking,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/branch/policy_flush",
        test_branch_controller_flush_policy,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/branch/history_eviction",
        test_branch_controller_history_eviction,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/branch/snapshot_policy",
        test_branch_controller_snapshot_policy,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/branch/security_guard",
        test_branch_controller_security_guard,
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
        "/serialization/flat_multi_chunk",
        test_serialization_flat_multi_chunk,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/serialization/flat_payload_ref_fixtures",
        test_flat_serializer_payload_ref_fixtures,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/serialization/flat_round_trip",
        test_flat_serializer_round_trip,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/serialization/flat_chunk_offset_violation",
        test_serialization_flat_chunk_offset_violation,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/serialization/flat_chunk_order_violation",
        test_serialization_flat_chunk_order_violation,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/serialization/flat_randomized_corruption",
        test_serialization_flat_randomized_corruption,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
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
    {
        "/episode/hybrid_promote_demote",
        test_episode_hybrid_promote_demote,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
#if !CEP_DISABLE_FEDERATION_TESTS
    {
        "/fed_transport/negotiation",
        test_fed_transport_negotiation,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_transport/upd_latest",
        test_fed_transport_upd_latest,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_transport/send_cell_flat",
        test_fed_transport_send_cell_flat,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_transport/send_cell_provider_caps",
        test_fed_transport_send_cell_provider_caps,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_mirror/frame_contract",
        test_fed_mirror_frame_contract,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/frame_contract",
        test_fed_invoke_frame_contract,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/decision_ledger",
        test_fed_invoke_decision_ledger,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_transport/inbound",
        test_fed_transport_inbound,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_transport/close_events",
        test_fed_transport_close_events,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_security/analytics_limit",
        test_fed_security_analytics_limit,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_security/pipeline_enforcement",
        test_fed_security_pipeline_enforcement,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_link/validator_success",
        test_fed_link_validator_success,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_link/validator_duplicate_request",
        test_fed_link_validator_duplicate_request,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_link/validator_missing_peer",
        test_fed_link_validator_missing_peer,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_link/emit_cell",
        test_fed_link_emit_cell,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_link/frame_contract",
        test_fed_link_frame_contract,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_mirror/validator_success",
        test_fed_mirror_validator_success,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_mirror/validator_conflict",
        test_fed_mirror_validator_conflict,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_mirror/validator_deadline",
        test_fed_mirror_validator_deadline,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_mirror/emit_cell",
        test_fed_mirror_emit_cell,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/validator_long_name",
        test_fed_invoke_validator_rejects_long_names,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/pipeline_metadata",
        test_fed_invoke_pipeline_metadata_roundtrip,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/success",
        test_fed_invoke_success,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/reconfigure_cancel",
        test_fed_invoke_reconfigure_cancels_pending,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/dual_runtime_happy",
        test_fed_invoke_dual_runtime_happy_path,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/dual_runtime_timeout",
        test_fed_invoke_dual_runtime_timeout,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_link/dual_runtime_provider_fatal",
        test_fed_link_dual_runtime_provider_fatal,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/timeout",
        test_fed_invoke_timeout,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/reject",
        test_fed_invoke_reject,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/fed_invoke/emit_cell",
        test_fed_invoke_emit_cell,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
#endif /* !CEP_DISABLE_FEDERATION_TESTS */
    {
        "/ratworld/determinism",
        test_ratworld_determinism,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/ratworld/solvable",
        test_ratworld_solvable,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/ratworld/renderer",
        test_ratworld_renderer,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/ratworld/tick_mechanics",
        test_ratworld_tick_mechanics,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/runtime/dual_isolation",
        test_runtime_dual_isolation,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },

    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}  // EOL
};


int main(int argC, char* argV[MUNIT_ARRAY_PARAM(argC + 1)]) {
    const char* seed_env = getenv("MUNIT_SEED");
    unsigned long override_seed = 0u;
    if (seed_env && *seed_env) {
        override_seed = strtoul(seed_env, NULL, 0);
    }
    MunitSuite sub_suites[5];
    size_t suite_index = 0u;

    for (size_t i = 0u; lock_suites[i].tests != NULL && suite_index < cep_lengthof(sub_suites) - 1u; ++i) {
        sub_suites[suite_index++] = lock_suites[i];
    }
    MunitSuite* l1_suite = test_suite_l1();
    if (l1_suite && suite_index < cep_lengthof(sub_suites) - 1u) {
        sub_suites[suite_index++] = *l1_suite;
    }
    MunitSuite* l2_suite = test_suite_l2();
    if (l2_suite && suite_index < cep_lengthof(sub_suites) - 1u) {
        sub_suites[suite_index++] = *l2_suite;
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

    if (override_seed) {
        static char seed_buf[32];
        snprintf(seed_buf, sizeof seed_buf, "0x%lx", override_seed);
        char* argv_with_seed[argC + 3];
        memcpy(argv_with_seed, argV, sizeof(char*) * argC);
        argv_with_seed[argC] = "--seed";
        argv_with_seed[argC + 1] = seed_buf;
        argv_with_seed[argC + 2] = NULL;
        return munit_suite_main(&root, NULL, argC + 2, argv_with_seed);
    }
    return munit_suite_main(&root, NULL, argC, argV);
}
