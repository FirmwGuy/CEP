/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Walk through the cell mutation APIs the enzyme layer depends on so clone,
   insert, update, and removal helpers keep their documented guarantees. */



#include "test.h"
#include "cep_cell.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>


static void exercise_clone_variants(void) {
    cepCell* parent = cep_cell_add_dictionary(cep_root(),
                                              CEP_DTAW("CEP", "tst_clone"),
                                              0,
                                              CEP_DTAW("CEP", "dictionary"),
                                              CEP_STORAGE_LINKED_LIST);
    munit_assert_not_null(parent);

    uint32_t rootValue = 41u;
    cepCell* head = cep_cell_add_value(parent,
                                       CEP_DTAW("CEP", "tst_head"),
                                       0,
                                       CEP_DTAW("CEP", "value"),
                                       &rootValue,
                                       sizeof rootValue,
                                       sizeof rootValue);
    munit_assert_not_null(head);

    cepCell* branch = cep_cell_add_dictionary(parent,
                                              CEP_DTAW("CEP", "tst_branch"),
                                              0,
                                              CEP_DTAW("CEP", "dictionary"),
                                              CEP_STORAGE_LINKED_LIST);
    munit_assert_not_null(branch);

    uint32_t leafValue = 1337u;
    cepCell* leaf = cep_cell_add_value(branch,
                                       CEP_DTAW("CEP", "tst_leaf"),
                                       0,
                                       CEP_DTAW("CEP", "value"),
                                       &leafValue,
                                       sizeof leafValue,
                                       sizeof leafValue);
    munit_assert_not_null(leaf);

    cepCell* shallow = cep_cell_clone(parent);
    munit_assert_not_null(shallow);
    munit_assert_false(cep_cell_children(shallow));
    munit_assert_null(cep_cell_find_by_name(shallow, CEP_DTAW("CEP", "tst_branch")));

    cepCell* deep = cep_cell_clone_deep(parent);
    munit_assert_not_null(deep);
    munit_assert_true(cep_cell_children(deep));
    cepCell* deepBranch = cep_cell_find_by_name(deep, CEP_DTAW("CEP", "tst_branch"));
    munit_assert_not_null(deepBranch);
    cepCell* deepLeaf = cep_cell_find_by_name(deepBranch, CEP_DTAW("CEP", "tst_leaf"));
    munit_assert_not_null(deepLeaf);
    munit_assert_true(cep_cell_has_data(deepLeaf));
    uint32_t deepLeafValue = *(uint32_t*)cep_cell_data(deepLeaf);
    munit_assert_uint32(deepLeafValue, ==, leafValue);

    uint32_t mutatedLeaf = leafValue + 1u;
    munit_assert_not_null(cep_cell_update(leaf,
                                          sizeof mutatedLeaf,
                                          sizeof mutatedLeaf,
                                          &mutatedLeaf,
                                          false));
    deepLeafValue = *(uint32_t*)cep_cell_data(deepLeaf);
    munit_assert_uint32(deepLeafValue, ==, leafValue);

    cepCell* shallowValue = cep_cell_clone(head);
    munit_assert_not_null(shallowValue);
    uint32_t mutatedHead = rootValue + 3u;
    munit_assert_not_null(cep_cell_update(head,
                                          sizeof mutatedHead,
                                          sizeof mutatedHead,
                                          &mutatedHead,
                                          false));
    uint32_t clonedHeadValue = *(uint32_t*)cep_cell_data(shallowValue);
    munit_assert_uint32(clonedHeadValue, ==, rootValue);

    cep_cell_finalize_hard(shallowValue);
    cep_free(shallowValue);
    cep_cell_finalize_hard(deep);
    cep_free(deep);
    cep_cell_finalize_hard(shallow);
    cep_free(shallow);

    cep_cell_delete_hard(parent);
}


static void collect_child_tags(const cepCell* parent, cepID tags[], size_t* out_count) {
    size_t count = 0u;
    for (cepCell* child = cep_cell_first((cepCell*)parent);
         child;
         child = cep_cell_next((cepCell*)parent, child)) {
        tags[count++] = cep_cell_get_name(child)->tag;
    }
    *out_count = count;
}


static void exercise_append_and_add_positions(void) {
    cepCell* list = cep_cell_add_list(cep_root(),
                                      CEP_DTAW("CEP", "tst_list"),
                                      0,
                                      CEP_DTAW("CEP", "list"),
                                      CEP_STORAGE_LINKED_LIST,
                                      8);
    munit_assert_not_null(list);

    uint32_t valueA = 1u;
    cepCell* tailA = cep_cell_append_value(list,
                                           CEP_DTAW("CEP", "tst_a"),
                                           CEP_DTAW("CEP", "value"),
                                           &valueA,
                                           sizeof valueA,
                                           sizeof valueA);
    munit_assert_not_null(tailA);

    uint32_t valueB = 2u;
    cepCell* tailB = cep_cell_append_value(list,
                                           CEP_DTAW("CEP", "tst_b"),
                                           CEP_DTAW("CEP", "value"),
                                           &valueB,
                                           sizeof valueB,
                                           sizeof valueB);
    munit_assert_not_null(tailB);

    uint32_t headValue = 0u;
    cepCell* head = cep_cell_prepend_value(list,
                                           CEP_DTAW("CEP", "tst_head"),
                                           CEP_DTAW("CEP", "value"),
                                           &headValue,
                                           sizeof headValue,
                                           sizeof headValue);
    munit_assert_not_null(head);
    munit_assert_ptr_equal(cep_cell_first(list), head);

    uint32_t midValue = 99u;
    cepCell* inserted = cep_cell_add_value(list,
                                           CEP_DTAW("CEP", "tst_mid"),
                                           1,
                                           CEP_DTAW("CEP", "value"),
                                           &midValue,
                                           sizeof midValue,
                                           sizeof midValue);
    munit_assert_not_null(inserted);

    uint32_t farTailValue = 5u;
    cepCell* farTail = cep_cell_add_value(list,
                                          CEP_DTAW("CEP", "tst_far"),
                                          4,
                                          CEP_DTAW("CEP", "value"),
                                          &farTailValue,
                                          sizeof farTailValue,
                                          sizeof farTailValue);
    munit_assert_not_null(farTail);

    cepID observed[8] = {0};
    size_t count = 0u;
    collect_child_tags(list, observed, &count);
    munit_assert_size(count, ==, 5u);

    cepID expected[5] = {
        CEP_DTAW("CEP", "tst_head")->tag,
        CEP_DTAW("CEP", "tst_mid")->tag,
        CEP_DTAW("CEP", "tst_a")->tag,
        CEP_DTAW("CEP", "tst_b")->tag,
        CEP_DTAW("CEP", "tst_far")->tag,
    };

    for (size_t i = 0; i < count; ++i) {
        munit_assert_uint64(observed[i], ==, expected[i]);
    }

    munit_assert_ptr_equal(cep_cell_last(list), farTail);

    cep_cell_delete_hard(list);
}


static void exercise_update_variants(void) {
    cepCell* list = cep_cell_add_list(cep_root(),
                                      CEP_DTAW("CEP", "tst_update"),
                                      0,
                                      CEP_DTAW("CEP", "list"),
                                      CEP_STORAGE_LINKED_LIST,
                                      4);
    munit_assert_not_null(list);

    uint32_t initial = 17u;
    cepCell* valueCell = cep_cell_add_value(list,
                                            CEP_DTAW("CEP", "tst_val"),
                                            0,
                                            CEP_DTAW("CEP", "value"),
                                            &initial,
                                            sizeof initial,
                                            sizeof initial);
    munit_assert_not_null(valueCell);

    uint32_t updated = 23u;
    void* valueResult = cep_cell_update(valueCell,
                                        sizeof updated,
                                        sizeof updated,
                                        &updated,
                                        false);
    munit_assert_not_null(valueResult);
    munit_assert_uint32(*(uint32_t*)cep_cell_data(valueCell), ==, updated);

    uint8_t* payload = cep_malloc(4u);
    payload[0] = 1u;
    payload[1] = 2u;
    payload[2] = 3u;
    payload[3] = 4u;

    cepCell* dataCell = cep_cell_add_data(list,
                                          CEP_DTAW("CEP", "tst_data"),
                                          0,
                                          CEP_DTAW("CEP", "value"),
                                          payload,
                                          4u,
                                          4u,
                                          free);
    munit_assert_not_null(dataCell);
    munit_assert_ptr_equal(dataCell->data->data, payload);

    uint8_t* swapped = cep_malloc(4u);
    memset(swapped, 0xEE, 4u);
    void* dataResult = cep_cell_update_hard(dataCell,
                                            4u,
                                            4u,
                                            swapped,
                                            true);
    munit_assert_not_null(dataResult);
    munit_assert_ptr_equal(dataCell->data->data, swapped);
    for (size_t i = 0; i < 4u; ++i) {
        munit_assert_uint8(((uint8_t*)cep_cell_data(dataCell))[i], ==, 0xEEu);
    }

    cep_cell_delete_hard(list);
}


static void exercise_remove_and_finalize(void) {
    cepCell* list = cep_cell_add_list(cep_root(),
                                      CEP_DTAW("CEP", "tst_remove"),
                                      0,
                                      CEP_DTAW("CEP", "list"),
                                      CEP_STORAGE_LINKED_LIST,
                                      4);
    munit_assert_not_null(list);

    uint32_t headValue = 7u;
    cepCell* head = cep_cell_add_value(list,
                                       CEP_DTAW("CEP", "tst_keep_a"),
                                       0,
                                       CEP_DTAW("CEP", "value"),
                                       &headValue,
                                       sizeof headValue,
                                       sizeof headValue);
    munit_assert_not_null(head);

    uint32_t removeValue = 9u;
    cepCell* doomed = cep_cell_add_value(list,
                                         CEP_DTAW("CEP", "tst_drop"),
                                         0,
                                         CEP_DTAW("CEP", "value"),
                                         &removeValue,
                                         sizeof removeValue,
                                         sizeof removeValue);
    munit_assert_not_null(doomed);

    uint32_t tailValue = 11u;
    cepCell* tail = cep_cell_add_value(list,
                                       CEP_DTAW("CEP", "tst_keep_b"),
                                       0,
                                       CEP_DTAW("CEP", "value"),
                                       &tailValue,
                                       sizeof tailValue,
                                       sizeof tailValue);
    munit_assert_not_null(tail);

    cep_cell_remove_hard(doomed, NULL);

    cepID observed[4] = {0};
    size_t count = 0u;
    collect_child_tags(list, observed, &count);
    munit_assert_size(count, ==, 2u);
    bool seenA = false;
    bool seenB = false;
    const cepID tagA = CEP_DTAW("CEP", "tst_keep_a")->tag;
    const cepID tagB = CEP_DTAW("CEP", "tst_keep_b")->tag;
    for (size_t i = 0u; i < count; ++i) {
        if (observed[i] == tagA)
            seenA = true;
        else if (observed[i] == tagB)
            seenB = true;
    }
    munit_assert_true(seenA);
    munit_assert_true(seenB);

    cep_cell_delete_hard(list);
}


static void exercise_find_by_path_past(void) {
    cepCell* rootDict = cep_cell_add_dictionary(cep_root(),
                                                CEP_DTAW("CEP", "tst_path"),
                                                0,
                                                CEP_DTAW("CEP", "dictionary"),
                                                CEP_STORAGE_LINKED_LIST);
    munit_assert_not_null(rootDict);

    uint32_t payload = 55u;
    cepCell* value = cep_cell_add_value(rootDict,
                                        CEP_DTAW("CEP", "tst_leaf"),
                                        0,
                                        CEP_DTAW("CEP", "value"),
                                        &payload,
                                        sizeof payload,
                                        sizeof payload);
    munit_assert_not_null(value);

    cepPath* path = cep_alloca(sizeof(cepPath) + (3u * sizeof(cepPast)));
    path->length = 3u;
    path->capacity = 3u;

    path->past[0].dt = *cep_cell_get_name(rootDict);
    path->past[0].timestamp = 0u;
    path->past[1].dt = *cep_cell_get_name(value);
    path->past[1].timestamp = value->created;
    path->past[2].dt = value->data->dt;
    path->past[2].timestamp = value->data->created;

    cepCell* resolved = cep_cell_find_by_path_past(cep_root(), path, 0u);
    munit_assert_not_null(resolved);
    munit_assert_ptr_equal(resolved, value);

    cep_cell_delete_hard(rootDict);
}


MunitResult test_cell_mutations(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;

    TestWatchdog* watchdog = user_data_or_fixture;
    (void)watchdog;

    cep_cell_system_initiate();

    exercise_clone_variants();
    exercise_append_and_add_positions();
    exercise_update_variants();
    exercise_remove_and_finalize();
    exercise_find_by_path_past();

    if (watchdog)
        test_watchdog_signal(watchdog);

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
