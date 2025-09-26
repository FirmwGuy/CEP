/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Verifies lock primitives prevent unsafe mutations under contention. */

#include "test.h"

#include "cep_cell.h"

static MunitResult test_lock_store_blocks_append(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    cepCell parent;
    CEP_0(&parent);
    cep_cell_initialize_dictionary(&parent,
                                   CEP_DTS(CEP_ACRO("TST"), CEP_WORD("parent")),
                                   CEP_DTAW("TST", "child"),
                                   CEP_STORAGE_LINKED_LIST);

    cepCell child;
    CEP_0(&child);
    cep_cell_initialize_value(&child,
                              CEP_DTS(CEP_ACRO("TST"), CEP_WORD("child")),
                              CEP_DTAW("TST", "value"),
                              "x",
                              (size_t)1,
                              (size_t)1);

    cepLockToken token;
    munit_assert_true(cep_store_lock(&parent, &token));

    cepCell* inserted = cep_store_add_child(parent.store, 0, &child);
    munit_assert_null(inserted);

    cep_store_unlock(&parent, &token);

    cep_cell_finalize_hard(&child);
    CEP_0(&child);

    cep_cell_initialize_value(&child,
                              CEP_DTS(CEP_ACRO("TST"), CEP_WORD("child")),
                              CEP_DTAW("TST", "value"),
                              "x",
                              (size_t)1,
                              (size_t)1);

    inserted = cep_store_add_child(parent.store, 0, &child);
    munit_assert_not_null(inserted);
    munit_assert_ptr_equal(inserted->parent, parent.store);
    cep_cell_finalize_hard(&parent);
    return MUNIT_OK;
}

static MunitResult test_lock_data_blocks_update(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    cepCell cell;
    CEP_0(&cell);
    cep_cell_initialize_value(&cell,
                              CEP_DTS(CEP_ACRO("TST"), CEP_WORD("value")),
                              CEP_DTAW("TST", "value"),
                              "a",
                              (size_t)1,
                              (size_t)1);

    cepLockToken token;
    munit_assert_true(cep_data_lock(&cell, &token));

    munit_assert_null(cep_cell_update(&cell, (size_t)1, (size_t)1, "b", false));

    cep_data_unlock(&cell, &token);
    munit_assert_not_null(cep_cell_update(&cell, (size_t)1, (size_t)1, "b", false));

    cep_cell_finalize_hard(&cell);
    return MUNIT_OK;
}

static MunitTest lock_tests[] = {
    {
        "/lock_store_blocks_append",
        test_lock_store_blocks_append,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/lock_data_blocks_update",
        test_lock_data_blocks_update,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

MunitSuite lock_suites[] = {
    {
        "/locking",
        lock_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE,
    },
    {NULL, NULL, NULL, 0, 0}
};
