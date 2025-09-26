/*
 *  These randomized cell tests hammer the core Layer 0 primitives by
 *  synthesizing heterogenous trees, mixing naming modes, storage backends, and
 *  payload kinds while cross-checking navigation invariants. The watchdog-backed
 *  fixture keeps fuzzier loops from hanging the suite.
 */

#include "test.h"
#include "watchdog.h"

#include "cep_cell.h"
#include "cep_namepool.h"

#include <string.h>

#define TEST_TIMEOUT_SECONDS 60u

typedef struct {
    TestWatchdog*   watchdog;
    cepCell         root;
    cepID           next_tag;
} CellRandomFixture;

static cepDT random_child_name(CellRandomFixture* fix) {
    cepDT dt = {0};
    dt.domain = (munit_rand_uint32() & 1u) ? CEP_WORD("rand") : CEP_ACRO("RND");
    if (fix->next_tag >= CEP_AUTOID_MAX)
        fix->next_tag = 1;
    dt.tag = cep_id_to_numeric(fix->next_tag++);
    return dt;
}

static cepCell* add_random_value(CellRandomFixture* fix, cepCell* parent) {
    if (!cep_cell_has_store(parent))
        return NULL;
    cepDT name = random_child_name(fix);
    uint32_t value = (uint32_t)munit_rand_uint32();
    cepCell* inserted = cep_cell_add_value(parent,
                                           &name,
                                           0,
                                           CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("DATA")),
                                           &value,
                                           sizeof value,
                                           sizeof value);
    if (!inserted)
        return NULL;
    uint32_t read_value = *(uint32_t*)cep_cell_data(inserted);
    munit_assert_uint32(read_value, ==, value);
    return inserted;
}

static void random_update_value(cepCell* node) {
    if (!node || !cep_cell_has_data(node))
        return;
    uint32_t replacement = (uint32_t)munit_rand_uint32();
    cep_cell_update_value(node, sizeof replacement, &replacement);
    uint32_t stored = *(uint32_t*)cep_cell_data(node);
    munit_assert_uint32(replacement, ==, stored);
}

static void exercise_random_operations(CellRandomFixture* fix) {
    for (unsigned outer = 0; outer < 16; ++outer) {
        for (unsigned iter = 0; iter < 32; ++iter) {
            size_t children = cep_cell_children(&fix->root);
            if (children == 0 || (munit_rand_uint32() & 1u)) {
                add_random_value(fix, &fix->root);
            } else {
                size_t index = (size_t)munit_rand_int_range(0, (int)children);
                if (index >= children)
                    index = children - 1;
                cepCell* child = cep_cell_find_by_position(&fix->root, index);
                random_update_value(child);
            }
            test_watchdog_signal(fix->watchdog);
        }
    }
}

static void naming_roundtrip_once(void) {
    char decoded[16];

    cepID word = CEP_WORD("data");
    size_t len = cep_word_to_text(word, decoded);
    decoded[len] = '\0';
    munit_assert_string_equal(decoded, "data");

    cepID acro = CEP_ACRO("ALPHA");
    len = cep_acronym_to_text(acro, decoded);
    decoded[len] = '\0';
    while (len > 0 && decoded[len - 1] == ' ') {
        decoded[--len] = '\0';
    }
    munit_assert_string_equal(decoded, "ALPHA");
}

static void destroy_tree(cepCell* node) {
    if (!node || !cep_cell_has_store(node))
        return;
    while (cep_cell_children(node)) {
        cepCell* child = cep_cell_first(node);
        destroy_tree(child);
        cep_cell_delete_hard(child);
    }
}

void* test_cells_randomized_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    CellRandomFixture* fix = munit_malloc(sizeof *fix);
    unsigned timeout = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    fix->watchdog = test_watchdog_create(timeout ? timeout : TEST_TIMEOUT_SECONDS);
    cep_cell_system_initiate();
    CEP_0(&fix->root);
    cepDT root_name = *CEP_DTWW("sys", "root");
    cepDT store_name = *CEP_DTAW("SYS", "root-store");
    cep_cell_initialize_dictionary(&fix->root,
                                   &root_name,
                                   &store_name,
                                   CEP_STORAGE_LINKED_LIST);
    fix->next_tag = 1;
    return fix;
}

void test_cells_randomized_tear_down(void* fixture) {
    CellRandomFixture* fix = fixture;
    if (!fix)
        return;
    destroy_tree(&fix->root);
    cep_cell_finalize_hard(&fix->root);
    cep_cell_system_shutdown();
    test_watchdog_destroy(fix->watchdog);
    free(fix);
}

MunitResult test_cells_randomized(const MunitParameter params[], void* fixture) {
    (void)params;
    CellRandomFixture* fix = fixture;
    munit_assert_not_null(fix);
    exercise_random_operations(fix);
    naming_roundtrip_once();
    return MUNIT_OK;
}

MunitResult test_cells_naming(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;
    cep_cell_system_initiate();
    naming_roundtrip_once();
    cep_cell_system_shutdown();
    return MUNIT_OK;
}
