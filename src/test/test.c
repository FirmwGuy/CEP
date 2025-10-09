/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Test harness entry points for CEP core suites. */



#include "test.h"


static MunitParameterEnum timeout_params[] = {
    {"timeout", NULL},
    {NULL, NULL}
};

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

static MunitParameterEnum boot_cycle_stdio_params[] = {
    {"boot_cycle", boot_cycle_values},
    {"stdio", NULL},
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
        "/traverse",
        test_traverse,
        test_traverse_setup,
        test_traverse_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params  // Parameters.
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
        "/mailroom",
        test_mailroom,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params
    },
    {
        "/enzyme",
        test_enzyme,
        test_enzyme_setup,
        test_enzyme_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_stdio_params
    },
    {
        "/enzyme/randomized",
        test_enzyme_randomized,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params
    },
    {
        "/heartbeat",
        test_heartbeat,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params
    },
    {
        "/rendezvous/bootstrap_cycles",
        test_rendezvous_bootstrap_cycles,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
    {
        "/rendezvous/pipeline",
        test_rendezvous_pipeline,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
    {
        "/rendezvous/parallel",
        test_rendezvous_parallel,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
#if defined(CEP_HAS_L2_TESTS)
    {
        "/flows/basic",
        test_l2_ingest_and_decision,
        l2_setup,
        l2_teardown,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params
    },
    {
        "/flows/wait_event",
        test_l2_wait_event_resume,
        l2_setup,
        l2_teardown,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params
    },
    {
        "/flows/retention",
        test_l2_retention_archive,
        l2_setup,
        l2_teardown,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_timeout_params
    },
#endif
    {
        "/serialization/cell",
        test_serialization,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
#ifdef CEP_HAS_POC
    {
        "/poc/bootstrap",
        test_poc_bootstrap,
        test_poc_setup,
        test_poc_teardown,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
    {
        "/poc/io_pipeline",
        test_poc_io_pipeline,
        test_poc_setup,
        test_poc_teardown,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
    {
        "/poc/scenario_pipeline",
        test_poc_scenario_pipeline,
        test_poc_setup,
        test_poc_teardown,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
    {
        "/poc/assert_builder",
        test_poc_assert_builder,
        test_poc_setup,
        test_poc_teardown,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
#endif
    {
        "/serialization/proxy",
        test_serialization_proxy,
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

    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}  // EOL
};


const MunitSuite testSuite = {
    "/CEP",
    tests,
    lock_suites,
    1,                        // Iterations.
    MUNIT_SUITE_OPTION_NONE
};


int main(int argC, char* argV[MUNIT_ARRAY_PARAM(argC + 1)]) {
    return munit_suite_main(&testSuite, NULL, argC, argV);
}
