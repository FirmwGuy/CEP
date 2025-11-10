/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/*  This test program uses Munit, which is MIT licensed. Please see munit.h file
 *  for a complete license information.
 */
#define MUNIT_ENABLE_ASSERT_ALIASES
#include "munit.h"

#include <string.h>
#include <stdatomic.h>

#include "cep_cell.h"
#include "cep_heartbeat.h"
#include "cep_runtime.h"
#include "cep_l0.h"
#include "stream/cep_stream_internal.h"
#include "watchdog.h"

enum {
    CEP_NAME_ENUMERATION = cep_id_to_numeric(100),
    CEP_NAME_TEMP,
    CEP_NAME_Z_COUNT
};


MunitResult test_cell(const MunitParameter params[], void* user_data_or_fixture);
void*       test_cell_setup(const MunitParameter params[], void* user_data);
void        test_cell_tear_down(void* fixture);
MunitResult test_cell_mutations(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_cell_immutable(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_traverse(const MunitParameter params[], void* user_data_or_fixture);
void*       test_traverse_setup(const MunitParameter params[], void* user_data);
void        test_traverse_tear_down(void* fixture);
MunitResult test_traverse_all(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_domain_tag_naming(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_identifier(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_ops(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_enzyme(const MunitParameter params[], void* user_data_or_fixture);
void*       test_enzyme_setup(const MunitParameter params[], void* user_data);
void        test_enzyme_tear_down(void* fixture);
MunitResult test_cell_operations_enzymes(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_enzyme_randomized(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_heartbeat_single(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_heartbeat_bootstrap(const MunitParameter params[], void* user_data_or_fixture);
bool        test_ovh_trace_enabled(void);
void        test_ovh_tracef(const char* fmt, ...);
bool        test_ovh_heartbeat_step(const char* label);
void*       test_ovh_watchdog_setup(const MunitParameter params[], void* user_data);
void        test_ovh_watchdog_tear_down(void* fixture);
MunitResult test_serialization(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_proxy(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_proxy_release_single(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_manifest_history(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_manifest_split_child_capacity(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_manifest_positional_add(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_manifest_fingerprint_corruption(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_manifest_delta_fingerprint_corruption(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_header_capability_mismatch(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_flat_multi_chunk(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_flat_serializer_round_trip(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_stream_stdio(const MunitParameter params[], void* user_data_or_fixture);
#ifdef CEP_HAS_LIBZIP
MunitResult test_stream_zip(const MunitParameter params[], void* user_data_or_fixture);
#endif
MunitResult test_ep_stream_access(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_mailbox_board(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_mailbox_private(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_organ_sys_state_validator(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_organ_rt_ops_validator(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_organ_constructor_dossier(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_organ_destructor_dossier(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_organ_dossier_sequence(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_organ_constructor_bootstrap(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_organ_constructor_destructor_cycles(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_cei_mailbox(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_cei_signal_ledger(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_cell_append_guard_cei(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_cei_op_failure(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_cei_fatal_shutdown(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_pause_resume_backlog(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_pause_rollback_backlog_guard(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_soft_delete_lookup(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_view_horizon_snapshot(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_soft_deleted_dictionary_revives(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_history_autoid_monotonic(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_minimal_rollback(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_control_failure_cei(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_prr_watcher_timeout_cei(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_executor_runs_task(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_executor_cancel_pending(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_executor_io_budget_cancel(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_executor_self_cancel(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_episode_yield_resume(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_episode_await_resume(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_episode_await_timeout(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_episode_lease_enforcement(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_episode_rw_suspend_resume(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_episode_hybrid_promote_demote(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_runtime_dual_isolation(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_fed_transport_negotiation(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_transport_upd_latest(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_transport_inbound(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_transport_close_events(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_link_validator_success(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_link_validator_duplicate_request(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_link_validator_missing_peer(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_mirror_validator_success(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_mirror_validator_conflict(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_mirror_validator_deadline(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_invoke_validator_rejects_long_names(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_invoke_success(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_invoke_reconfigure_cancels_pending(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_invoke_dual_runtime_happy_path(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_invoke_dual_runtime_timeout(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_invoke_timeout(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_invoke_reject(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_fed_link_dual_runtime_provider_fatal(const MunitParameter params[], void* user_data_or_fixture);

extern MunitSuite lock_suites[];
extern MunitSuite integration_poc_suite;

bool        test_executor_wait_until_empty(unsigned spins);
bool        test_executor_wait_for_calls(atomic_uint* counter, unsigned target, unsigned spins);
void        test_executor_relax(void);

static inline void test_runtime_shutdown(void) {
    cep_stream_clear_pending();
    cepRuntime* runtime = cep_runtime_active();
    (void)cep_runtime_shutdown(runtime);
    if (runtime == cep_runtime_default()) {
        /* FIXME: Legacy suites still depend on the global default runtime; migrate
           those fixtures to scoped runtimes so this branch can disappear. */
        cep_cell_system_shutdown();
        cep_l0_bootstrap_reset();
    }
}

static inline cepRuntime* test_runtime_legacy_default_context(void) {
    /* FIXME: Temporary shim for the handful of suites that still execute against
       the custom default runtime context; replace with fixture-owned runtimes so
       comparator registries and serialization state stay per-instance. */
    cep_comparator_registry_reset_default();
    return cep_runtime_default();
}

#define TEST_BOOT_CYCLE_FRESH       "fresh"
#define TEST_BOOT_CYCLE_AFTER       "after_reboot"

static inline bool test_boot_cycle_is_after(const MunitParameter params[]) {
    const char* cycle = params ? munit_parameters_get(params, "boot_cycle") : NULL;
    return cycle && (strcmp(cycle, TEST_BOOT_CYCLE_AFTER) == 0);
}

static inline void test_boot_cycle_prepare(const MunitParameter params[]) {
    if (!test_boot_cycle_is_after(params)) {
        return;
    }

    test_runtime_shutdown();
    cep_cell_system_initiate();
}
