/*
 *  Locking tests randomly orchestrate read/write acquisitions to validate the
 *  layered mutex discipline that guards cell and store mutations.
 */

#include "test.h"
#include "watchdog.h"

#include "cep_cell.h"

#define TEST_TIMEOUT_SECONDS 60u

typedef struct {
    TestWatchdog* watchdog;
} LockingFixture;

void* test_locking_randomized_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    LockingFixture* fix = munit_malloc(sizeof *fix);
    unsigned timeout = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    fix->watchdog = test_watchdog_create(timeout ? timeout : TEST_TIMEOUT_SECONDS);
    return fix;
}

void test_locking_randomized_tear_down(void* fixture) {
    LockingFixture* fix = fixture;
    if (!fix)
        return;
    test_watchdog_destroy(fix->watchdog);
    free(fix);
}

MunitResult test_locking_randomized(const MunitParameter params[], void* fixture) {
    (void)params;
    LockingFixture* fix = fixture;
    munit_assert_not_null(fix);

    cepCell parent;
    CEP_0(&parent);
    cep_cell_initialize_dictionary(&parent,
                                   CEP_DTS(CEP_ACRO("LCK"), CEP_WORD("parent")),
                                   CEP_DTAW("LCK", "child"),
                                   CEP_STORAGE_LINKED_LIST);

    for (unsigned round = 0; round < 8; ++round) {
        cepCell child;
        CEP_0(&child);
        cep_cell_initialize_value(&child,
                                  CEP_DTS(CEP_ACRO("LCK"), CEP_WORD("child")),
                                  CEP_DTAW("LCK", "value"),
                                  "x",
                                  (size_t)1,
                                  (size_t)1);

        cepLockToken token;
        munit_assert_true(cep_store_lock(&parent, &token));
        munit_assert_null(cep_store_add_child(parent.store, 0, &child));
        cep_store_unlock(&parent, &token);

        cepCell* inserted = cep_store_add_child(parent.store, 0, &child);
        munit_assert_not_null(inserted);

        if (munit_rand_uint32() & 1u) {
            cepLockToken value_token;
            munit_assert_true(cep_data_lock(inserted, &value_token));
            munit_assert_null(cep_cell_update(inserted, (size_t)1, (size_t)1, "y", false));
            cep_data_unlock(inserted, &value_token);
            munit_assert_not_null(cep_cell_update(inserted, (size_t)1, (size_t)1, "y", false));
        }

        cep_cell_delete_hard(inserted);
        test_watchdog_signal(fix->watchdog);
    }

    cep_cell_finalize_hard(&parent);
    return MUNIT_OK;
}
