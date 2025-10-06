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

#ifndef CEP_HAS_L2_TESTS
/* Meson builds run the full flow suite; the fallback unix/Makefile may define
 * this to 0 when it omits the L2 intent fixtures. */
#define CEP_HAS_L2_TESTS 1
#endif

#include "cep_cell.h"
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

MunitResult test_traverse(const MunitParameter params[], void* user_data_or_fixture);
void*       test_traverse_setup(const MunitParameter params[], void* user_data);
void        test_traverse_tear_down(void* fixture);

MunitResult test_domain_tag_naming(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_identifier(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_mailroom(const MunitParameter params[], void* user_data_or_fixture);

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
MunitResult test_stream_stdio(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_l2_ingest_and_decision(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_l2_retention_archive(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_l2_wait_event_resume(const MunitParameter params[], void* user_data_or_fixture);
void*       l2_setup(const MunitParameter params[], void* user_data);
void        l2_teardown(void* fixture);

MunitResult test_poc_bootstrap(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_poc_io_pipeline(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_poc_scenario_pipeline(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_poc_assert_builder(const MunitParameter params[], void* user_data_or_fixture);
void*       test_poc_setup(const MunitParameter params[], void* user_data);
void        test_poc_teardown(void* fixture);

extern MunitSuite lock_suites[];
