#include "test.h"

#include "cep_l0.h"
#include "cep_ops.h"
#include "cep_runtime.h"

MunitResult
test_runtime_dual_isolation(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    cepRuntime* runtime_a = cep_runtime_default();
    cepRuntime* initial_scope = cep_runtime_active();

    cepRuntime* previous_scope = cep_runtime_set_active(runtime_a);
    munit_assert_true(cep_l0_bootstrap());
    cep_runtime_restore_active(previous_scope);

    cepRuntime* runtime_b = cep_runtime_create();
    munit_assert_not_null(runtime_b);

    previous_scope = cep_runtime_set_active(runtime_b);
    cep_l0_bootstrap_reset();
    munit_assert_true(cep_l0_bootstrap());

    munit_assert_true(cep_runtime_attach_metadata(runtime_b));

    cepCell* root_b = cep_root();
    munit_assert_not_null(root_b);
    munit_assert_ptr_equal(root_b, cep_runtime_root(runtime_b));
    munit_assert_ptr_not_equal(root_b, cep_runtime_root(runtime_a));
    munit_assert_ptr_equal(cep_runtime_from_root(root_b), runtime_b);

    cepCell* data_root_b = cep_heartbeat_data_root();
    munit_assert_not_null(data_root_b);

    cepDT marker_name = cep_ops_make_dt("val/runtime_isolation");
    munit_assert_true(cep_cell_put_text(data_root_b, &marker_name, "runtime-b"));
    cepCell* marker_b = cep_cell_find_by_name(data_root_b, &marker_name);
    munit_assert_not_null(marker_b);

    cep_runtime_restore_active(previous_scope);
    previous_scope = cep_runtime_set_active(runtime_a);

    cepCell* data_root_a = cep_heartbeat_data_root();
    munit_assert_not_null(data_root_a);
    cepCell* marker_a = cep_cell_find_by_name(data_root_a, &marker_name);
    munit_assert_null(marker_a);

    cep_runtime_restore_active(previous_scope);
    previous_scope = cep_runtime_set_active(runtime_b);
    cep_runtime_shutdown(runtime_b);
    cep_runtime_restore_active(previous_scope);
    cep_runtime_destroy(runtime_b);

    previous_scope = cep_runtime_set_active(runtime_a);
    cep_l0_bootstrap_reset();
    munit_assert_true(cep_l0_bootstrap());
    cep_runtime_restore_active(previous_scope);

    cep_runtime_restore_active(initial_scope);
    test_runtime_shutdown();

    return MUNIT_OK;
}
