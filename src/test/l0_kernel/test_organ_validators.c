/* Validator adoption tests: ensure Stage E organ validators execute via
 * OPS/STATES and close dossiers cleanly for representative subsystems. The
 * checks drive a lightweight heartbeat cycle so we can observe the emitted
 * dossiers without rebuilding the entire runtime fixture. */

#include "test.h"
#include "cep_l0.h"
#include "cep_ops.h"
#include "cep_organ.h"

static void organ_prepare_runtime(void) {
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_heartbeat_startup());

    /* Advance a few beats so the boot dossier reaches ist:ok before we queue
     * organ validators. */
    for (int i = 0; i < 6; ++i) {
        munit_assert_true(cep_heartbeat_step());
    }
}

static cepCell* organ_ops_root(void) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops);
    return cep_cell_resolve(ops);
}

static cepCell* organ_find_cell(cepCell* parent, const cepDT* name) {
    cepCell* node = cep_cell_find_by_name(parent, name);
    munit_assert_not_null(node);
    node = cep_cell_resolve(node);
    munit_assert_not_null(node);
    return node;
}

static void organ_process_beat(void) {
    /* The validator impulse lands on the next beat, so run two cycles to cover
     * resolve+execute as well as any continuations staged during commit. */
    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_step());
}

static void organ_assert_latest_success(const char* expected_target) {
    cepCell* ops_root = organ_ops_root();
    cepCell* newest = cep_cell_last_all(ops_root);
    munit_assert_not_null(newest);

    cepCell* envelope = organ_find_cell(newest, CEP_DTAW("CEP", "envelope"));

    cepCell* verb_node = organ_find_cell(envelope, CEP_DTAW("CEP", "verb"));
    const cepData* verb_data = verb_node->data;
    munit_assert_not_null(verb_data);
    munit_assert_int(verb_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(verb_data->size, ==, sizeof(cepDT));
    cepDT verb_dt = {0};
    memcpy(&verb_dt, verb_data->value, sizeof verb_dt);
    cepDT verb_expected = cep_ops_make_dt("op/vl");
    munit_assert_int(cep_dt_compare(&verb_dt, &verb_expected), ==, 0);

    cepCell* target_node = organ_find_cell(envelope, CEP_DTAW("CEP", "target"));
    const cepData* target_data = target_node->data;
    munit_assert_not_null(target_data);
    munit_assert_int(target_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_true(target_data->size > 0u);
    const char* target_path = (const char*)target_data->value;
    munit_assert_not_null(target_path);
    munit_assert_string_equal(target_path, expected_target);

    cepCell* state_node = organ_find_cell(newest, CEP_DTAW("CEP", "state"));
    const cepData* state_data = state_node->data;
    munit_assert_int(state_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(state_data->size, ==, sizeof(cepDT));
    cepDT state_dt = {0};
    memcpy(&state_dt, state_data->value, sizeof state_dt);
    cepDT state_expected = cep_ops_make_dt("ist:ok");
    munit_assert_int(cep_dt_compare(&state_dt, &state_expected), ==, 0);

    cepCell* close_branch = organ_find_cell(newest, CEP_DTAW("CEP", "close"));
    munit_assert_true(cep_cell_is_immutable(close_branch));
    cepCell* status_node = organ_find_cell(close_branch, CEP_DTAW("CEP", "status"));
    const cepData* status_data = status_node->data;
    munit_assert_int(status_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(status_data->size, ==, sizeof(cepDT));
    cepDT status_dt = {0};
    memcpy(&status_dt, status_data->value, sizeof status_dt);
    cepDT status_expected = cep_ops_make_dt("sts:ok");
    munit_assert_int(cep_dt_compare(&status_dt, &status_expected), ==, 0);
}

MunitResult test_organ_sys_state_validator(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    organ_prepare_runtime();

    cepCell* sys_root = cep_heartbeat_sys_root();
    munit_assert_not_null(sys_root);
    cepCell* state_root = organ_find_cell(sys_root, CEP_DTAW("CEP", "state"));

    cepCell* ops_root = organ_ops_root();
    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_validation(state_root));
    organ_process_beat();

    size_t after_count = cep_cell_children(ops_root);
    munit_assert_size(after_count, ==, before_count + 1u);

    organ_assert_latest_success("/sys/state");
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_organ_rt_ops_validator(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    organ_prepare_runtime();

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "ops"));

    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_validation(ops_root));
    organ_process_beat();

    size_t after_count = cep_cell_children(ops_root);
    munit_assert_size(after_count, ==, before_count + 1u);

    organ_assert_latest_success("/rt/ops");
    test_runtime_shutdown();
    return MUNIT_OK;
}
