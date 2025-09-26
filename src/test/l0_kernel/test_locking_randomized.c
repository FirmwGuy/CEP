/*
 *  Locking fuzz tests orchestrate nested store and payload locks to confirm
 *  write helpers refuse to mutate while a subtree is frozen, then resume
 *  without leaking state once the locks drop.
 */
/* Exercises locking under randomized schedules and nested scopes. */


#include "test.h"
#include "watchdog.h"

#include "cep_cell.h"

#define TEST_TIMEOUT_SECONDS 60u
#define LOCK_ITERATIONS      64u

typedef struct {
    TestWatchdog* watchdog;
    cepCell       parent;
    cepID         next_numeric;
} LockingFixture;

static cepDT random_child_name(LockingFixture* fix) {
    if (!fix->next_numeric || fix->next_numeric > CEP_AUTOID_MAX)
        fix->next_numeric = CEP_ID(1);

    cepDT dt = {0};
    dt.domain = (munit_rand_uint32() & 1u) ? CEP_WORD("lock") : CEP_ACRO("LCK");
    dt.tag = cep_id_to_numeric(fix->next_numeric++);
    return dt;
}

static cepCell* ensure_child(LockingFixture* fix) {
    if (!cep_cell_children(&fix->parent)) {
        uint32_t seed = munit_rand_uint32();
        cepDT name = *CEP_DTAA("LCK", "INIT");
        cepCell* added = cep_cell_add_value(&fix->parent,
                                            &name,
                                            0,
                                            CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("LOCK")),
                                            &seed,
                                            sizeof seed,
                                            sizeof seed);
        munit_assert_not_null(added);
    }

    size_t count = cep_cell_children(&fix->parent);
    size_t index = (size_t)munit_rand_int_range(0, (int)count);
    if (index >= count)
        index = count - 1u;
    cepCell* child = cep_cell_find_by_position(&fix->parent, index);
    munit_assert_not_null(child);
    return child;
}

static void exercise_store_lock_sequence(LockingFixture* fix) {
    cepLockToken token;
    cepDT name = random_child_name(fix);
    uint32_t payload = munit_rand_uint32();

    size_t before = cep_cell_children(&fix->parent);
    munit_assert_true(cep_store_lock(&fix->parent, &token));
    cepCell* inserted = cep_cell_add_value(&fix->parent,
                                           &name,
                                           0,
                                           CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("LOCK")),
                                           &payload,
                                           sizeof payload,
                                           sizeof payload);
    munit_assert_null(inserted);
    munit_assert_size(cep_cell_children(&fix->parent), ==, before);

    if (before) {
        cepCell* victim = cep_cell_first(&fix->parent);
        cepDT victim_name = *cep_cell_get_name(victim);
        cep_cell_delete_hard(victim);
        munit_assert_not_null(cep_cell_find_by_name(&fix->parent, &victim_name));
    }

    cep_store_unlock(&fix->parent, &token);

    inserted = cep_cell_add_value(&fix->parent,
                                  &name,
                                  0,
                                  CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("LOCK")),
                                  &payload,
                                  sizeof payload,
                                  sizeof payload);
    munit_assert_not_null(inserted);
    munit_assert_size(cep_cell_children(&fix->parent), ==, before + 1u);

    cep_cell_delete_hard(inserted);
    munit_assert_size(cep_cell_children(&fix->parent), ==, before);
}

static void exercise_data_lock_sequence(LockingFixture* fix) {
    cepCell* child = ensure_child(fix);

    cepLockToken token;
    munit_assert_true(cep_data_lock(child, &token));

    uint32_t replacement = munit_rand_uint32();
    void* updated = cep_cell_update(child,
                                    sizeof replacement,
                                    sizeof replacement,
                                    &replacement,
                                    false);
    munit_assert_null(updated);

    cep_cell_delete_hard(child);
    munit_assert_true(cep_cell_children(&fix->parent) > 0);

    cep_data_unlock(child, &token);

    updated = cep_cell_update(child,
                              sizeof replacement,
                              sizeof replacement,
                              &replacement,
                              false);
    munit_assert_not_null(updated);
    munit_assert_uint(*(uint32_t*)updated, ==, replacement);
}

static void random_unlock_cleanup(LockingFixture* fix) {
    if (cep_cell_children(&fix->parent) <= 4u)
        return;

    size_t count = cep_cell_children(&fix->parent);
    size_t index = (size_t)munit_rand_int_range(0, (int)count);
    if (index >= count)
        index = count - 1u;

    cepCell* child = cep_cell_find_by_position(&fix->parent, index);
    if (child)
        cep_cell_delete_hard(child);
}

void* test_locking_randomized_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    LockingFixture* fix = munit_malloc(sizeof *fix);
    unsigned timeout = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    fix->watchdog = test_watchdog_create(timeout ? timeout : TEST_TIMEOUT_SECONDS);

    cep_cell_system_initiate();
    CEP_0(&fix->parent);
    cep_cell_initialize_dictionary(&fix->parent,
                                   CEP_DTS(CEP_ACRO("LCK"), CEP_WORD("parent")),
                                   CEP_DTAW("LCK", "children"),
                                   CEP_STORAGE_LINKED_LIST);
    fix->next_numeric = CEP_ID(1);

    for (unsigned i = 0; i < 3; ++i)
        ensure_child(fix);

    return fix;
}

void test_locking_randomized_tear_down(void* fixture) {
    LockingFixture* fix = fixture;
    if (!fix)
        return;

    while (cep_cell_children(&fix->parent)) {
        cepCell* child = cep_cell_first(&fix->parent);
        cep_cell_delete_hard(child);
    }

    cep_cell_finalize_hard(&fix->parent);
    cep_cell_system_shutdown();

    test_watchdog_destroy(fix->watchdog);
    free(fix);
}

MunitResult test_locking_randomized(const MunitParameter params[], void* fixture) {
    (void)params;
    LockingFixture* fix = fixture;
    munit_assert_not_null(fix);

    for (unsigned iter = 0; iter < LOCK_ITERATIONS; ++iter) {
        if (munit_rand_uint32() & 1u)
            exercise_store_lock_sequence(fix);
        else
            exercise_data_lock_sequence(fix);

        random_unlock_cleanup(fix);
        test_watchdog_signal(fix->watchdog);
    }

    return MUNIT_OK;
}
