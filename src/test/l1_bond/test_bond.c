/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Layer 1 bond bootstrap & topology smoke tests. */

#include "test.h"

#include "cep_bond.h"
#include "cep_cell.h"


/* expect_dictionary fetches a named child and asserts the backing store is a dictionary. */
static cepCell* expect_dictionary(cepCell* parent, const cepDT* name) {
    assert_not_null(parent);
    assert_not_null(name);

    cepCell* child = cep_cell_find_by_name(parent, name);
    assert_not_null(child);
    assert_true(cep_cell_is_normal(child));
    assert_true(cep_cell_is_dictionary(child));
    return child;
}

/* expect_list fetches a named child and asserts it is a linked-list store. */
static cepCell* expect_list(cepCell* parent, const cepDT* name) {
    assert_not_null(parent);
    assert_not_null(name);

    cepCell* child = cep_cell_find_by_name(parent, name);
    assert_not_null(child);
    assert_true(cep_cell_is_normal(child));
    assert_not_null(child->store);
    assert_int(child->store->storage, ==, CEP_STORAGE_LINKED_LIST);
    return child;
}

/* Bind two beings through a bond, mirror adjacency, schedule a facet, and ensure teardown respects ensure_directories. */
MunitResult test_bond(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    cepL1Result rc = cep_init_l1(NULL, NULL);
    assert_int(rc, ==, CEP_L1_OK);

    cepCell* root = cep_root();
    cepCell* data = expect_dictionary(root, CEP_DTAW("CEP", "data"));
    cepCell* namespace_root = expect_dictionary(data, CEP_DTAA("CEP", "CEP"));
    cepCell* l1_root = expect_dictionary(namespace_root, CEP_DTAA("CEP", "L1"));

    cepCell* beings_root = expect_dictionary(l1_root, CEP_DTAW("CEP", "beings"));
    cepCell* bonds_root = expect_dictionary(l1_root, CEP_DTAW("CEP", "bonds"));
    cepCell* contexts_root = expect_dictionary(l1_root, CEP_DTAW("CEP", "contexts"));
    cepCell* facets_root = expect_dictionary(l1_root, CEP_DTAW("CEP", "facets"));

    cepCell* runtime_bonds_root = expect_dictionary(root, CEP_DTAW("CEP", "bonds"));
    cepCell* adjacency_root = expect_dictionary(runtime_bonds_root, CEP_DTAW("CEP", "adjacency"));
    cepCell* facet_queue = expect_list(runtime_bonds_root, CEP_DTAW("CEP", "facet_queue"));
    cepCell* checkpoints_root = expect_dictionary(runtime_bonds_root, CEP_DTAW("CEP", "checkpoints"));
    (void)checkpoints_root;

    /* Seed two beings with lightweight metadata. */
    cepDT being_a_name = *CEP_DTAW("CEP", "being_a");
    cepCell* being_a = cep_cell_add_dictionary(beings_root, &being_a_name, 0, CEP_DTAW("CEP", "being"), CEP_STORAGE_RED_BLACK_T);
    assert_not_null(being_a);

    cepDT being_b_name = *CEP_DTAW("CEP", "being_b");
    cepCell* being_b = cep_cell_add_dictionary(beings_root, &being_b_name, 0, CEP_DTAW("CEP", "being"), CEP_STORAGE_RED_BLACK_T);
    assert_not_null(being_b);

    /* Describe the bond and attach role links. */
    cepDT bond_name = *CEP_DTAW("CEP", "bond_pair");
    cepCell* bond = cep_cell_add_dictionary(bonds_root, &bond_name, 0, CEP_DTAW("CEP", "bond_caned"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(bond);

    cepDT role_a_tag = *CEP_DTAW("CEP", "role_a");
    cepCell* bond_role_a = cep_cell_add_dictionary(bond, &role_a_tag, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(bond_role_a);
    static const char role_a_ref[] = "being_a";
    cepDT value_tag = *CEP_DTAW("CEP", "value");
    assert_not_null(cep_cell_add_value(bond_role_a, &value_tag, 0, CEP_DTAW("CEP", "text"), CEP_P(role_a_ref), sizeof role_a_ref, sizeof role_a_ref));

    cepDT role_b_tag = *CEP_DTAW("CEP", "role_b");
    cepCell* bond_role_b = cep_cell_add_dictionary(bond, &role_b_tag, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(bond_role_b);
    static const char role_b_ref[] = "being_b";
    assert_not_null(cep_cell_add_value(bond_role_b, &value_tag, 0, CEP_DTAW("CEP", "text"), CEP_P(role_b_ref), sizeof role_b_ref, sizeof role_b_ref));

    /* Instantiate a context referencing both beings and capturing facet obligations. */
    cepDT context_name = *CEP_DTAW("CEP", "ctx_edit");
    cepCell* context = cep_cell_add_dictionary(contexts_root, &context_name, 0, CEP_DTAW("CEP", "ctx_editssn"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(context);

    cepDT role_source_tag = *CEP_DTAW("CEP", "role_source");
    cepCell* ctx_role_source = cep_cell_add_dictionary(context, &role_source_tag, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(ctx_role_source);
    static const char ctx_source_ref[] = "being_a";
    assert_not_null(cep_cell_add_value(ctx_role_source, &value_tag, 0, CEP_DTAW("CEP", "text"), CEP_P(ctx_source_ref), sizeof ctx_source_ref, sizeof ctx_source_ref));

    cepDT role_subj_tag = *CEP_DTAW("CEP", "role_subj");
    cepCell* ctx_role_subject = cep_cell_add_dictionary(context, &role_subj_tag, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(ctx_role_subject);
    static const char ctx_subject_ref[] = "being_b";
    assert_not_null(cep_cell_add_value(ctx_role_subject, &value_tag, 0, CEP_DTAW("CEP", "text"), CEP_P(ctx_subject_ref), sizeof ctx_subject_ref, sizeof ctx_subject_ref));

    cepDT facet_need_tag = *CEP_DTAW("CEP", "facet_edlog");
    cepCell* facet_obligation = cep_cell_add_dictionary(context, &facet_need_tag, 0, &facet_need_tag, CEP_STORAGE_LINKED_LIST);
    assert_not_null(facet_obligation);

    /* Materialise the facet output branch. */
    cepCell* facet_record = cep_cell_add_dictionary(facets_root, &facet_need_tag, 0, &facet_need_tag, CEP_STORAGE_LINKED_LIST);
    assert_not_null(facet_record);
    assert_ptr_equal(cep_cell_parent(facet_record), facets_root);

    /* Publish adjacency mirrors for both beings. */
    cepCell* adjacency_a = cep_cell_add_list(adjacency_root, &being_a_name, 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(adjacency_a);
    static const char adjacency_ctx_ref[] = "ctx_edit";
    assert_not_null(cep_cell_add_value(adjacency_a, &value_tag, 0, CEP_DTAW("CEP", "text"), CEP_P(adjacency_ctx_ref), sizeof adjacency_ctx_ref, sizeof adjacency_ctx_ref));

    cepCell* adjacency_b = cep_cell_add_list(adjacency_root, &being_b_name, 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(adjacency_b);
    assert_not_null(cep_cell_add_value(adjacency_b, &value_tag, 0, CEP_DTAW("CEP", "text"), CEP_P(adjacency_ctx_ref), sizeof adjacency_ctx_ref, sizeof adjacency_ctx_ref));

    /* Enqueue facet work in the runtime queue. */
    cepCell* queue_entry = cep_cell_add_dictionary(facet_queue, &facet_need_tag, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_LINKED_LIST);
    assert_not_null(queue_entry);
    assert_not_null(cep_cell_add_value(queue_entry, &value_tag, 0, CEP_DTAW("CEP", "text"), CEP_P(adjacency_ctx_ref), sizeof adjacency_ctx_ref, sizeof adjacency_ctx_ref));

    /* Ensure disable-auto-create configuration refuses to backfill topology. */
    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    cepConfig without_create = {
        .root = NULL,
        .data_root = NULL,
        .bonds_root = NULL,
        .l1_root = NULL,
        .ensure_directories = false,
    };

    rc = cep_init_l1(&without_create, NULL);
    assert_int(rc, ==, CEP_L1_ERR_STATE);
    root = cep_root();
    assert_null(cep_cell_find_by_name(root, CEP_DTAW("CEP", "data")));

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
    return MUNIT_OK;
}
