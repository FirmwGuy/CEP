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




MunitTest tests[] = {
    {
        "/cell",
        test_cell,
        test_cell_setup,
        test_cell_tear_down,
        MUNIT_TEST_OPTION_NONE,
        timeout_params             // Parameters.
    },
    {
        "/traverse",
        test_traverse,
        test_traverse_setup,
        test_traverse_tear_down,
        MUNIT_TEST_OPTION_NONE,
        timeout_params             // Parameters.
    },
    {
        "/domain_tag_naming",
        test_domain_tag_naming,
        NULL,                     // Setup
        NULL,                     // Tear_down
        MUNIT_TEST_OPTION_NONE,
        (MunitParameterEnum[]) {
            {"text", NULL},       // Text to convert to ID value.
            {NULL, NULL}
        }
    },
    {
        "/enzyme",
        test_enzyme,
        test_enzyme_setup,
        test_enzyme_tear_down,
        MUNIT_TEST_OPTION_NONE,
        (MunitParameterEnum[]) {
            {"stdio", NULL},      // Text to convert to ID value.
            {NULL, NULL}
        }
    },
    {
        "/heartbeat",
        test_heartbeat,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        timeout_params
    },
    {
        "/serialization/cell",
        test_serialization,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/serialization/proxy",
        test_serialization_proxy,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
    {
        "/stream/stdio",
        test_stream_stdio,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
    },
#ifdef CEP_HAS_LIBZIP
    {
        "/stream/zip",
        test_stream_zip,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL
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
