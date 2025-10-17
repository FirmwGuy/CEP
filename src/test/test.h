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

#include "cep_cell.h"
#include "cep_heartbeat.h"
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

MunitResult test_heartbeat(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization_proxy(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_stream_stdio(const MunitParameter params[], void* user_data_or_fixture);
#ifdef CEP_HAS_LIBZIP
MunitResult test_stream_zip(const MunitParameter params[], void* user_data_or_fixture);
#endif

extern MunitSuite lock_suites[];

static inline void test_runtime_shutdown(void) {
    cep_stream_clear_pending();
    (void)cep_heartbeat_emit_shutdown();
    cep_heartbeat_shutdown();
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
