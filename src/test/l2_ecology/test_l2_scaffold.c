#include "munit.h"

#include "../../l2_ecology/cep_l2_pack.h"
#include "../../l2_ecology/cep_l2_runtime.h"
#include "../../l0_kernel/cep_runtime.h"
#include "../../l0_kernel/cep_namepool.h"
#include "../test.h"

#include <stdlib.h>

static MunitResult test_l2_bootstrap_history(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    if (!cep_l2_bootstrap()) {
        return MUNIT_SKIP;
    }

    cepRuntime* runtime = cep_runtime_active();
    cepHeartbeatTopology* topo = runtime ? cep_runtime_default_topology(runtime) : NULL;
    munit_assert_not_null(topo);
    munit_assert_not_null(topo->data);

    cepCell* eco_root = cep_cell_find_by_name(topo->data, CEP_DTAW("CEP", "eco"));
    eco_root = eco_root ? cep_cell_resolve(eco_root) : NULL;
    munit_assert_not_null(eco_root);

    cepCell* runtime_root = cep_cell_find_by_name(eco_root, CEP_DTAW("CEP", "runtime"));
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    munit_assert_not_null(runtime_root);
    munit_assert_not_null(cep_cell_find_by_name(runtime_root, CEP_DTAW("CEP", "history")));

    munit_assert_true(cep_l2_runtime_record_history(eco_root, NULL, NULL, NULL, "scaffold"));
    return MUNIT_OK;
}

static MunitTest l2_tests[] = {
    {(char*)"/l2/scaffold/history", test_l2_bootstrap_history, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL}
};

static const MunitSuite l2_suite = {
    (char*)"/CEP/l2",
    l2_tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE
};

MunitSuite* test_suite_l2(void) {
    const char* enable = getenv("CEP_L2_TESTS");
    if (!enable || !*enable || *enable == '0') {
        return NULL;
    }
    return (MunitSuite*)&l2_suite;
}
