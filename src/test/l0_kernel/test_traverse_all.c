/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Verifies cep_cell_deep_traverse_all() sees veiled and deleted nodes
   so sealing/digest helpers can rely on it when walking staged subtrees. */



#include "test.h"
#include "cep_cell.h"

typedef struct {
    bool      leaf_seen[3];
    unsigned  leaf_count;
    unsigned  value_count;
} TraverseAllStats;

typedef struct {
    cepCell* bucket;
    cepCell* first_leaf;
} BuildTreeResult;

static bool capture_all_nodes(cepEntry* entry, void* ctx) {
    TraverseAllStats* stats = ctx;
    if (!entry || !entry->cell)
        return true;

    const cepDT* name = cep_cell_get_name(entry->cell);
    if (!name)
        return true;

    cepID tag = name->tag;
    for (unsigned i = 0; i < 3; ++i) {
        if (tag == cep_id_to_numeric(100u + i) && !stats->leaf_seen[i]) {
            stats->leaf_seen[i] = true;
            stats->leaf_count++;
        }
    }

    if (cep_dt_compare(name, CEP_DTAW("CEP", "value")) == 0)
        stats->value_count++;

    return true;
}

static BuildTreeResult build_two_level_tree(cepCell* root, bool mark_deleted) {
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT list_type = *CEP_DTAW("CEP", "list");

    cepCell* bucket = cep_cell_add_dictionary(root,
                                              CEP_DTAW("CEP", "bucket"),
                                              0,
                                              &dict_type,
                                              CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(bucket);

    BuildTreeResult result = {
        .bucket = bucket,
        .first_leaf = NULL,
    };

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

        if (!result.first_leaf)
            result.first_leaf = leaf;
    }

    return result;
}

static void test_deep_traverse_all_covers_veiled_children(void) {
    cepDT root_name = cep_dt_make(CEP_ACRO("CEP"), cep_id_to_numeric(500u));
    cepCell* parent = cep_cell_add_dictionary(cep_root(),
                                             &root_name,
                                             0,
                                             CEP_DTAW("CEP", "dictionary"),
                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepTxn txn;
    cepDT staged_name = *CEP_DTAW("CEP", "raw_all_txn");
    munit_assert_true(cep_txn_begin(parent, &staged_name, CEP_DTAW("CEP", "dictionary"), &txn));
    munit_assert_true(cep_cell_is_veiled(txn.root));

    BuildTreeResult tree = build_two_level_tree(txn.root, false);

    TraverseAllStats stats = {0};
    munit_assert_true(cep_cell_deep_traverse_all(txn.root,
                                                capture_all_nodes,
                                                NULL,
                                                &stats,
                                                NULL));
    munit_assert_uint(stats.leaf_count, ==, 3u);
    munit_assert_uint(stats.value_count, ==, 3u);

    munit_assert_not_null(tree.bucket);
    munit_assert_not_null(tree.first_leaf);
    munit_assert_true(cep_cell_is_veiled(tree.bucket));
    munit_assert_true(cep_cell_is_veiled(tree.first_leaf));

    cep_txn_abort(&txn);
    cep_cell_delete_hard(parent);
}

static void test_deep_traverse_all_covers_deleted_children(void) {
    cepDT root_name = cep_dt_make(CEP_ACRO("CEP"), cep_id_to_numeric(600u));
    cepCell* parent = cep_cell_add_dictionary(cep_root(),
                                             &root_name,
                                             0,
                                             CEP_DTAW("CEP", "dictionary"),
                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    BuildTreeResult tree = build_two_level_tree(parent, true);

    TraverseAllStats stats = {0};
    munit_assert_true(cep_cell_deep_traverse_all(parent,
                                                capture_all_nodes,
                                                NULL,
                                                &stats,
                                                NULL));
    munit_assert_uint(stats.leaf_count, ==, 3u);
    munit_assert_uint(stats.value_count, ==, 3u);

    munit_assert_not_null(tree.bucket);

    cep_cell_delete_hard(parent);
}

static void test_sibling_helpers_cover_veiled_children(void) {
    cepDT parent_name = cep_dt_make(CEP_ACRO("CEP"), cep_id_to_numeric(610u));
    cepCell* parent = cep_cell_add_dictionary(cep_root(),
                                              &parent_name,
                                              0,
                                              CEP_DTAW("CEP", "dictionary"),
                                              CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepTxn txn;
    cepDT staged_name = *CEP_DTAW("CEP", "raw_all_sib");
    munit_assert_true(cep_txn_begin(parent, &staged_name, CEP_DTAW("CEP", "dictionary"), &txn));
    munit_assert_true(cep_cell_is_veiled(txn.root));

    BuildTreeResult tree = build_two_level_tree(txn.root, false);
    munit_assert_not_null(tree.first_leaf);
    munit_assert_true(cep_cell_is_veiled(tree.first_leaf));

    munit_assert_null(cep_cell_first(txn.root));

    cepCell* raw_bucket = cep_cell_first_all(txn.root);
    munit_assert_not_null(raw_bucket);
    munit_assert_true(cep_cell_is_veiled(raw_bucket));

    unsigned count = 0;
    for (cepCell* child = cep_cell_first_all(tree.bucket);
         child;
         child = cep_cell_next_all(tree.bucket, child)) {
        munit_assert_true(cep_cell_is_veiled(child));
        count++;
    }
    munit_assert_uint(count, ==, 3u);

    cep_txn_abort(&txn);
    cep_cell_delete_hard(parent);
}

static void test_sibling_helpers_include_deleted_children(void) {
    cepDT parent_name = cep_dt_make(CEP_ACRO("CEP"), cep_id_to_numeric(620u));
    cepCell* parent = cep_cell_add_dictionary(cep_root(),
                                              &parent_name,
                                              0,
                                              CEP_DTAW("CEP", "dictionary"),
                                              CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    BuildTreeResult tree = build_two_level_tree(parent, true);
    munit_assert_not_null(tree.bucket);

    unsigned deleted_seen = 0;
    unsigned total = 0;
    for (cepCell* child = cep_cell_first_all(tree.bucket);
         child;
         child = cep_cell_next_all(tree.bucket, child)) {
        if (cep_cell_is_deleted(child))
            deleted_seen++;
        total++;
    }
    munit_assert_uint(total, ==, 3u);
    munit_assert_uint(deleted_seen, ==, 1u);

    cep_cell_delete_hard(parent);
}

MunitResult test_traverse_all(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    cep_cell_system_initiate();

    test_deep_traverse_all_covers_veiled_children();
    test_deep_traverse_all_covers_deleted_children();
    test_sibling_helpers_cover_veiled_children();
    test_sibling_helpers_include_deleted_children();

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
