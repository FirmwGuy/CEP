/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Test harness entry points for CEP core suites. */



#include "test.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

static bool stagee_trace_initialized;
static bool stagee_trace_enabled_flag;

bool test_stagee_trace_enabled(void) {
    if (!stagee_trace_initialized) {
        const char* env = getenv("TEST_WATCHDOG_TRACE");
        stagee_trace_enabled_flag = (env && env[0] && env[0] != '0');
        stagee_trace_initialized = true;
    }
    return stagee_trace_enabled_flag;
}

void test_stagee_tracef(const char* fmt, ...) {
    if (!test_stagee_trace_enabled())
        return;
    va_list args;
    va_start(args, fmt);
    fputs("[stagee] ", stderr);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(args);
}

bool test_stagee_heartbeat_step(const char* label) {
    cepBeatNumber before = cep_heartbeat_current();
    test_stagee_tracef("%s before beat=%" PRIu64, label, (uint64_t)before);
    bool ok = cep_heartbeat_step();
    cepBeatNumber after = cep_heartbeat_current();
    test_stagee_tracef("%s after beat=%" PRIu64 " ok=%d", label, (uint64_t)after, ok ? 1 : 0);
    return ok;
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
        test_stagee_watchdog_setup,
        test_stagee_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/sys_state",
        test_organ_sys_state_validator,
        test_stagee_watchdog_setup,
        test_stagee_watchdog_tear_down,
        MUNIT_TEST_OPTION_NONE,
        boot_cycle_params
    },
    {
        "/organ/rt_ops",
        test_organ_rt_ops_validator,
        test_stagee_watchdog_setup,
        test_stagee_watchdog_tear_down,
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
