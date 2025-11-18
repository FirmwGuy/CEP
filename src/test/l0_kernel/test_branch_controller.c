/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/.
 */

#include "test.h"

#include "cps_storage_service.h"
#include "cep_branch_controller.h"
#include "cep_cell.h"
#include "cep_heartbeat.h"
#include "cep_l0.h"
#include "cep_ops.h"

static void
test_branch_cleanup(cepCell* branch)
{
    if (!branch) {
        return;
    }
    branch = cep_cell_resolve(branch);
    if (branch) {
        cep_cell_remove_hard(branch, NULL);
    }
}

MunitResult
test_branch_controller_dirty_tracking(const MunitParameter params[],
                                      void* user_data_or_fixture)
{
    (void)user_data_or_fixture;
    test_runtime_enable_mock_cps();
    test_boot_cycle_prepare(params);
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_heartbeat_bootstrap());

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepDT branch_name = cep_ops_make_dt("test_branch_dirty");
    cepCell* existing = cep_cell_find_by_name(data_root, &branch_name);
    if (existing) {
        test_branch_cleanup(existing);
    }

    cepCell* branch = cep_cell_ensure_dictionary_child(data_root,
                                                       &branch_name,
                                                       CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(branch);
    branch = cep_cell_resolve(branch);
    munit_assert_not_null(branch);
    munit_assert_not_null(branch->store);

    cepBranchControllerRegistry* registry = cep_runtime_branch_registry(NULL);
    munit_assert_not_null(registry);
    cepBranchController* controller =
        cep_branch_registry_find_by_dt(registry, &branch->metacell.dt);
    munit_assert_not_null(controller);
    munit_assert_not_null(controller);

    cepDT field_dt = cep_ops_make_dt("dirty_field");
    munit_assert_true(cep_cell_put_text(branch, &field_dt, "value"));

    cepCell* field_cell = cep_cell_find_by_name(branch, &field_dt);
    munit_assert_not_null(field_cell);
    field_cell = cep_cell_resolve(field_cell);
    munit_assert_not_null(field_cell);
    munit_assert_not_null(field_cell->data);
    munit_assert_true(field_cell->data->dirty != 0u);
    munit_assert_true(branch->store->dirty != 0u);

    bool dirty_entry_found = false;
    for (size_t i = 0; i < controller->dirty_index.count; ++i) {
        const cepBranchDirtyEntry* entry = &controller->dirty_index.entries[i];
        if (entry->cell == field_cell &&
            (entry->flags & CEP_BRANCH_DIRTY_FLAG_DATA)) {
            dirty_entry_found = true;
            break;
        }
    }
    munit_assert_true(dirty_entry_found);

    test_branch_cleanup(branch);
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

static void
test_branch_controller_simulate_flush(cepBranchController* controller,
                                      cepBranchFlushCause cause)
{
    if (!controller) {
        return;
    }
    controller->dirty_entry_count = 0u;
    controller->force_flush = false;
    controller->last_flush_cause = cause;
    if (cause == CEP_BRANCH_FLUSH_CAUSE_SCHEDULED) {
        controller->flush_scheduled_bt = CEP_BEAT_INVALID;
    }
}

MunitResult
test_branch_controller_flush_policy(const MunitParameter params[],
                                    void* user_data_or_fixture)
{
    (void)user_data_or_fixture;
    test_runtime_enable_mock_cps();
    test_boot_cycle_prepare(params);
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepDT branch_name = cep_ops_make_dt("test_branch_policy");
    cepCell* existing = cep_cell_find_by_name(data_root, &branch_name);
    if (existing) {
        test_branch_cleanup(existing);
    }

    cepCell* branch = cep_cell_ensure_dictionary_child(data_root,
                                                       &branch_name,
                                                       CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(branch);
    branch = cep_cell_resolve(branch);
    munit_assert_not_null(branch);

    cepBranchControllerRegistry* registry = cep_runtime_branch_registry(NULL);
    munit_assert_not_null(registry);
    cepBranchController* controller =
        cep_branch_registry_find_by_dt(registry, &branch->metacell.dt);
    munit_assert_not_null(controller);

    cepDT field_dt = cep_ops_make_dt("policy_field");
    munit_assert_true(cep_cell_put_text(branch, &field_dt, "initial"));

    controller->policy.mode = CEP_BRANCH_PERSIST_ON_DEMAND;
    controller->force_flush = false;
    controller->flush_scheduled_bt = CEP_BEAT_INVALID;
    munit_assert_true(controller->dirty_entry_count > 0u);

    munit_assert_true(cps_storage_commit_current_beat());
    munit_assert_true(controller->dirty_entry_count > 0u);
    munit_assert_false(controller->force_flush);

    controller->force_flush = true;
    munit_assert_true(cps_storage_commit_current_beat());
    if (test_runtime_mock_cps_enabled()) {
        test_branch_controller_simulate_flush(controller, CEP_BRANCH_FLUSH_CAUSE_MANUAL);
    }
    munit_assert_true(controller->dirty_entry_count == 0u);
    munit_assert_false(controller->force_flush);
    munit_assert_true(controller->last_flush_cause == CEP_BRANCH_FLUSH_CAUSE_MANUAL);

    munit_assert_true(cep_cell_put_text(branch, &field_dt, "scheduled"));
    controller->policy.mode = CEP_BRANCH_PERSIST_SCHEDULED_SAVE;
    controller->flush_scheduled_bt = cep_beat_index();
    controller->force_flush = false;

    munit_assert_true(cps_storage_commit_current_beat());
    if (test_runtime_mock_cps_enabled()) {
        test_branch_controller_simulate_flush(controller, CEP_BRANCH_FLUSH_CAUSE_SCHEDULED);
    }
    munit_assert_true(controller->dirty_entry_count == 0u);
    munit_assert_true(controller->flush_scheduled_bt == CEP_BEAT_INVALID);
    munit_assert_true(controller->last_flush_cause == CEP_BRANCH_FLUSH_CAUSE_SCHEDULED);

    test_branch_cleanup(branch);
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

MunitResult
test_branch_controller_history_eviction(const MunitParameter params[],
                                        void* user_data_or_fixture)
{
    (void)user_data_or_fixture;
    test_runtime_enable_mock_cps();
    test_boot_cycle_prepare(params);
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepDT branch_name = cep_ops_make_dt("test_branch_eviction");
    cepCell* existing = cep_cell_find_by_name(data_root, &branch_name);
    if (existing) {
        test_branch_cleanup(existing);
    }

    cepCell* branch = cep_cell_ensure_dictionary_child(data_root,
                                                       &branch_name,
                                                       CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(branch);
    branch = cep_cell_resolve(branch);
    munit_assert_not_null(branch);

    cepBranchControllerRegistry* registry = cep_runtime_branch_registry(NULL);
    munit_assert_not_null(registry);
    cepBranchController* controller =
        cep_branch_registry_find_by_dt(registry, &branch->metacell.dt);
    munit_assert_not_null(controller);

    cepDT field_dt = cep_ops_make_dt("evict_field");
    munit_assert_true(cep_cell_put_text(branch, &field_dt, "v0"));
    munit_assert_true(cep_cell_put_text(branch, &field_dt, "v1"));
    munit_assert_true(cep_cell_put_text(branch, &field_dt, "v2"));

    cepCell* field_cell = cep_cell_find_by_name(branch, &field_dt);
    munit_assert_not_null(field_cell);
    field_cell = cep_cell_resolve(field_cell);
    munit_assert_not_null(field_cell);
    munit_assert_not_null(field_cell->data);
    munit_assert_not_null(field_cell->data->past);
    munit_assert_not_null(field_cell->data->past->past);

    controller->policy.mode = CEP_BRANCH_PERSIST_DURABLE;
    controller->policy.history_ram_versions = 1u;
    controller->policy.history_ram_beats = 0u;
    controller->policy.ram_quota_bytes = 0u;

    cep_branch_controller_apply_eviction(controller);

    munit_assert_true(controller->cached_history_versions <= 1u);
    cepDataNode* retained = field_cell->data->past;
    munit_assert_not_null(retained);
    munit_assert_null(retained->past);

    test_branch_cleanup(branch);
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

MunitResult
test_branch_controller_snapshot_policy(const MunitParameter params[],
                                       void* user_data_or_fixture)
{
    (void)user_data_or_fixture;
    test_runtime_enable_mock_cps();
    test_boot_cycle_prepare(params);
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepDT branch_name = cep_ops_make_dt("test_branch_snapshot");
    cepCell* existing = cep_cell_find_by_name(data_root, &branch_name);
    if (existing) {
        test_branch_cleanup(existing);
    }

    cepCell* branch = cep_cell_ensure_dictionary_child(data_root,
                                                       &branch_name,
                                                       CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(branch);
    branch = cep_cell_resolve(branch);
    munit_assert_not_null(branch);

    cepBranchControllerRegistry* registry = cep_runtime_branch_registry(NULL);
    munit_assert_not_null(registry);
    cepBranchController* controller =
        cep_branch_registry_find_by_dt(registry, &branch->metacell.dt);
    munit_assert_not_null(controller);

    cepDT field_dt = cep_ops_make_dt("snapshot_field");
    munit_assert_true(cep_cell_put_text(branch, &field_dt, "initial"));

    munit_assert_true(cep_branch_controller_enable_snapshot_mode(controller));
    munit_assert_true(controller->policy.mode == CEP_BRANCH_PERSIST_RO_SNAPSHOT);

    bool write_ok = cep_cell_put_text(branch, &field_dt, "mutated");
    munit_assert_false(write_ok);

    test_branch_cleanup(branch);
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}
