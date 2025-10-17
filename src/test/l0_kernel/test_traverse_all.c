/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Verifies cep_cell_deep_traverse_all() sees veiled and deleted nodes
   so sealing/digest helpers can rely on it when walking staged subtrees. */



#include "test.h"
#include "cep_cell.h"

static bool capture_all_nodes(cepEntry* entry, void* ctx) {
    (void)entry;
    unsigned* counter = ctx;
    (*counter)++;
    return true;
}

static void build_two_level_tree(cepCell* root, bool mark_deleted) {
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT list_type = *CEP_DTAW("CEP", "list");

    cepCell* bucket = cep_cell_add_dictionary(root,
                                              CEP_DTAW("CEP", "bucket"),
                                              0,
                                              &dict_type,
                                              CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(bucket);

    for (unsigned i = 0; i < 3; ++i) {
        cepDT leaf_name = cep_dt_make(CEP_ACRO("CEP"), cep_id_to_numeric(100u + i));

        cepCell* leaf = cep_cell_add_list(bucket,
                                          &leaf_name,
                                          0,
                                          &list_type,
                                          CEP_STORAGE_LINKED_LIST,
                                          4);
        munit_assert_not_null(leaf);

        cepDT value_name = *CEP_DTAW("CEP", "value");
        uint32_t payload = i;
        munit_assert_not_null(cep_cell_add_value(leaf,
                                                &value_name,
                                                0,
                                                CEP_DTAW("CEP", "value"),
                                                &payload,
                                                sizeof payload,
                                                sizeof payload));

        if (mark_deleted && (i == 1)) {
            cep_cell_delete(leaf);
        }
    }
}

static void test_deep_traverse_all_covers_veiled_children(void) {
    cepCell* parent = cep_cell_add_dictionary(cep_root(),
                                             CEP_DTAW("CEP", "raw_root_a"),
                                             0,
                                             CEP_DTAW("CEP", "dictionary"),
                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepTxn txn;
    cepDT staged_name = *CEP_DTAW("CEP", "raw_all_txn");
    munit_assert_true(cep_txn_begin(parent, &staged_name, CEP_DTAW("CEP", "dictionary"), &txn));
    munit_assert_true(cep_cell_is_veiled(txn.root));

    build_two_level_tree(txn.root, false);

    unsigned visit_count = 0;
    munit_assert_true(cep_cell_deep_traverse_all(txn.root,
                                                capture_all_nodes,
                                                NULL,
                                                &visit_count,
                                                NULL));

    /* Expect: 3 leaves + 3 child values = 6 nodes (root is not counted). */
    munit_assert_uint(visit_count, ==, 6u);

    cep_txn_abort(&txn);
    cep_cell_delete_hard(parent);
}

static void test_deep_traverse_all_covers_deleted_children(void) {
    cepCell* parent = cep_cell_add_dictionary(cep_root(),
                                             CEP_DTAW("CEP", "raw_root_b"),
                                             0,
                                             CEP_DTAW("CEP", "dictionary"),
                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    build_two_level_tree(parent, true);

    unsigned visit_count = 0;
    munit_assert_true(cep_cell_deep_traverse_all(parent,
                                                capture_all_nodes,
                                                NULL,
                                                &visit_count,
                                                NULL));

    /* All three leaves should be visited even though one is deleted. */
    munit_assert_uint(visit_count, ==, 6u);

    cep_cell_delete_hard(parent);
}

MunitResult test_traverse_all(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    cep_cell_system_initiate();

    test_deep_traverse_all_covers_veiled_children();
    test_deep_traverse_all_covers_deleted_children();

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
