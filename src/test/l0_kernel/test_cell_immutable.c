/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Exercises the immutable sealing helpers and canonical SHA-256 digest support
   so transactions can freeze subtrees inside a veil and tooling can fingerprint
   the resulting topology without mutating the runtime. */



#include "test.h"
#include "cep_cell.h"

#include <string.h>

static void test_seal_leaf_blocks_mutations(void) {
    cepDT parent_name = *CEP_DTAW("CEP", "imm_prnt_lf");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* parent = cep_cell_add_dictionary(cep_root(), &parent_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepTxn txn;
    cepDT branch_name = *CEP_DTAW("CEP", "imm_lf_brn");
    munit_assert_true(cep_txn_begin(parent, &branch_name, &dict_type, &txn));
    munit_assert_not_null(txn.root);
    munit_assert_true(cep_cell_is_veiled(txn.root));

    cepDT value_name = *CEP_DTAW("CEP", "imm_field");
    char initial[] = "sealed";
    cepCell* value = cep_cell_add_value(txn.root,
                                        &value_name,
                                        0,
                                        CEP_DTAW("CEP", "text"),
                                        initial,
                                        sizeof initial,
                                        sizeof initial);
    munit_assert_not_null(value);

    munit_assert_true(cep_cell_set_immutable(value));
    munit_assert_true(cep_cell_is_immutable(value));

    munit_assert_true(cep_txn_mark_ready(&txn));
    munit_assert_true(cep_txn_commit(&txn));

    cepCell* sealed_branch = cep_cell_find_by_name(parent, &branch_name);
    munit_assert_not_null(sealed_branch);
    cepCell* sealed_value = cep_cell_find_by_name(sealed_branch, &value_name);
    munit_assert_not_null(sealed_value);
    munit_assert_true(cep_cell_is_immutable(sealed_value));

    const char mutated[] = "mutated";
    munit_assert_null(cep_cell_update(sealed_value,
                                      sizeof mutated,
                                      sizeof mutated,
                                      (void*)mutated,
                                      false));

    cepDT renamed = *CEP_DTAW("CEP", "imm_renamed");
    cep_cell_set_name(sealed_value, &renamed);
    const cepDT* current_name = cep_cell_get_name(sealed_value);
    munit_assert_true(cep_dt_compare(current_name, &value_name) == 0);

    bool deleted_before = cep_cell_is_deleted(sealed_value);
    cep_cell_delete(sealed_value);
    munit_assert_true(cep_cell_is_deleted(sealed_value) == deleted_before);

    cep_cell_delete_hard(parent);
}

static void test_recursive_seal_blocks_children(void) {
    cepDT parent_name = *CEP_DTAW("CEP", "imm_prn_brn");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* parent = cep_cell_add_dictionary(cep_root(), &parent_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepTxn txn;
    cepDT branch_name = *CEP_DTAW("CEP", "imm_branch");
    munit_assert_true(cep_txn_begin(parent, &branch_name, &dict_type, &txn));
    munit_assert_not_null(txn.root);

    cepDT child_one_name = *CEP_DTAW("CEP", "imm_child_a");
    uint32_t child_value = 42u;
    cepCell* child_one = cep_cell_add_value(txn.root,
                                            &child_one_name,
                                            0,
                                            CEP_DTAW("CEP", "value"),
                                            &child_value,
                                            sizeof child_value,
                                            sizeof child_value);
    munit_assert_not_null(child_one);

    cepDT child_two_name = *CEP_DTAW("CEP", "imm_child_b");
    cepCell* child_two = cep_cell_add_dictionary(txn.root,
                                                 &child_two_name,
                                                 0,
                                                 &dict_type,
                                                 CEP_STORAGE_LINKED_LIST);
    munit_assert_not_null(child_two);

    munit_assert_true(cep_txn_mark_ready(&txn));

    cepSealOptions opt = {.recursive = true};
    munit_assert_true(cep_branch_seal_immutable(txn.root, opt));
    munit_assert_true(cep_cell_is_immutable(txn.root));
    munit_assert_true(cep_txn_commit(&txn));

    cepCell* sealed_branch = cep_cell_find_by_name(parent, &branch_name);
    munit_assert_not_null(sealed_branch);
    munit_assert_true(cep_cell_is_immutable(sealed_branch));

    cepCell* sealed_child_a = cep_cell_find_by_name(sealed_branch, &child_one_name);
    cepCell* sealed_child_b = cep_cell_find_by_name(sealed_branch, &child_two_name);
    munit_assert_not_null(sealed_child_a);
    munit_assert_not_null(sealed_child_b);

    cepCell temp_child = {0};
    cepDT attempt_name = *CEP_DTAW("CEP", "imm_fail");
    const char denied[] = "denied";
    cep_cell_initialize_value(&temp_child,
                              &attempt_name,
                              CEP_DTAW("CEP", "text"),
                              (void*)denied,
                              sizeof denied,
                              sizeof denied);
    cepCell* inserted = cep_cell_add(sealed_branch, 0, &temp_child);
    munit_assert_null(inserted);
    cep_cell_finalize_hard(&temp_child);

    cep_cell_remove_hard(sealed_child_a, NULL);
    cepCell* still_child = cep_cell_find_by_name(sealed_branch, &child_one_name);
    munit_assert_not_null(still_child);

    cep_cell_delete_hard(parent);
}

static void compute_branch_digest(const cepDT* branch_name, const char* payload, uint8_t out[32]) {
    cepCell branch = {0};
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT name_copy = *branch_name;
    cep_cell_initialize_dictionary(&branch, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);

    branch.metacell.veiled = 1u;

    cepDT value_name = *CEP_DTAW("CEP", "imm_val");
    size_t len = strlen(payload) + 1u;
    cepCell* value = cep_cell_add_value(&branch,
                                        &value_name,
                                        0,
                                        CEP_DTAW("CEP", "text"),
                                        (void*)payload,
                                        len,
                                        len);
    munit_assert_not_null(value);
    munit_assert_true(cep_dt_is_valid(cep_cell_get_name(value)));
    munit_assert_true(cep_cell_is_veiled(value));
    munit_assert_uint(value->data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_uint(value->metacell.type, ==, CEP_TYPE_NORMAL);
    munit_assert_not_null(value->parent);

    cepSealOptions opt = {.recursive = true};
    munit_assert_true(cep_branch_seal_immutable(&branch, opt));
    munit_assert_true(cep_cell_is_immutable(&branch));
    for (cepCell* child = cep_cell_first(&branch); child; child = cep_cell_next(&branch, child)) {
        munit_assert_true(cep_cell_set_immutable(child));
        munit_assert_true(cep_cell_is_immutable(child));
    }
    value = cep_cell_first(&branch);
    uint8_t leaf_digest[32];
    if (!cep_cell_digest(value, CEP_DIGEST_SHA256, leaf_digest)) {
        munit_errorf("leaf digest failed: imm=%u type=%u size=%zu data=%p", (unsigned)cep_cell_is_immutable(value), (unsigned)value->metacell.type, value->data ? value->data->size : 0u, (void*)(value->data ? value->data->value : NULL));
    }
    if (!cep_cell_digest(&branch, CEP_DIGEST_SHA256, out)) {
        munit_errorf("digest failed: root imm=%u type=%u child imm=%u size=%zu", (unsigned)cep_cell_is_immutable(&branch), (unsigned)branch.metacell.type, (unsigned)cep_cell_is_immutable(value), value->data ? value->data->size : 0u);
    }

    cep_cell_finalize_hard(&branch);
}

static void test_digest_consistency(void) {
    uint8_t digest_a[32];
    uint8_t digest_b[32];
    uint8_t digest_c[32];

    compute_branch_digest(CEP_DTAW("CEP", "imm_diga"), "alpha", digest_a);
    compute_branch_digest(CEP_DTAW("CEP", "imm_digb"), "alpha", digest_b);
    compute_branch_digest(CEP_DTAW("CEP", "imm_digc"), "beta", digest_c);

    munit_assert_memory_equal(sizeof digest_a, digest_a, digest_b);
    munit_assert_memory_not_equal(sizeof digest_a, digest_a, digest_c);
}

static void test_sealed_visibility_survives_unveil(void) {
    cepDT parent_name = *CEP_DTAW("CEP", "imm_prnt_vl");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* parent = cep_cell_add_dictionary(cep_root(), &parent_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepTxn txn;
    cepDT branch_name = *CEP_DTAW("CEP", "imm_vl_brn");
    munit_assert_true(cep_txn_begin(parent, &branch_name, &dict_type, &txn));
    munit_assert_not_null(txn.root);

    munit_assert_true(cep_txn_mark_ready(&txn));

    cepSealOptions opt = {.recursive = true};
    munit_assert_true(cep_branch_seal_immutable(txn.root, opt));
    munit_assert_true(cep_cell_is_immutable(txn.root));
    munit_assert_true(cep_cell_is_veiled(txn.root));
    munit_assert_true(cep_txn_commit(&txn));

    cepCell* sealed_branch = cep_cell_find_by_name(parent, &branch_name);
    munit_assert_not_null(sealed_branch);
    munit_assert_true(cep_cell_is_immutable(sealed_branch));

    cepCell temp_child = {0};
    cep_cell_initialize_empty(&temp_child, CEP_DTAW("CEP", "imm_ignore"));
    munit_assert_null(cep_cell_add(sealed_branch, 0, &temp_child));
    cep_cell_finalize_hard(&temp_child);

    cep_cell_delete_hard(parent);
}

MunitResult test_cell_immutable(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    test_seal_leaf_blocks_mutations();
    test_recursive_seal_blocks_children();
    test_digest_consistency();
    test_sealed_visibility_survives_unveil();

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
