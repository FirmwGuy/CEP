/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Layer 1 bond bootstrap & behaviour tests using the public API. */

#include "test.h"

#include "cep_bond.h"
#include "cep_cell.h"

#include <string.h>

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

/* Extract the text payload stored under the requested name on a parent dictionary. */
static const char* expect_value(cepCell* parent, const cepDT* name) {
    cepCell* cell = cep_cell_find_by_name(parent, name);
    assert_not_null(cell);
    assert_true(cep_cell_is_normal(cell));
    assert_true(cep_cell_has_data(cell));
    const char* text = (const char*)cep_cell_data(cell);
    assert_not_null(text);
    return text;
}

/* Bind two beings through a bond, mirror adjacency, schedule facets, and verify topology. */
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

    /* Claim beings using the public API. */
    cepBeingHandle user = {0};
    cepBeingSpec user_spec = {
        .label = "Alex Solo",
        .kind = "human",
        .external_id = "user-001",
        .metadata = NULL,
    };
    rc = cep_being_claim(root, CEP_DTAW("CEP", "being_alx"), &user_spec, &user);
    assert_int(rc, ==, CEP_L1_OK);
    assert_not_null(user.cell);

    cepBeingHandle document = {0};
    cepBeingSpec doc_spec = {
        .label = "Feature Doc",
        .kind = "document",
        .external_id = "doc-2024A",
        .metadata = NULL,
    };
    rc = cep_being_claim(root, CEP_DTAW("CEP", "being_doc"), &doc_spec, &document);
    assert_int(rc, ==, CEP_L1_OK);
    assert_not_null(document.cell);

    /* Record a bond between the two beings. */
    cepBondHandle bond_handle = {0};
    cepBondSpec bond_spec = {
        .tag = CEP_DTAW("CEP", "bond_caned"),
        .role_a_tag = CEP_DTAW("CEP", "role_a"),
        .role_a = user.cell,
        .role_b_tag = CEP_DTAW("CEP", "role_b"),
        .role_b = document.cell,
        .metadata = NULL,
        .causal_op = 0,
        .label = "Primary Edit",
        .note = "shared workspace",
    };
    rc = cep_bond_upsert(root, &bond_spec, &bond_handle);
    assert_int(rc, ==, CEP_L1_OK);
    assert_not_null(bond_handle.cell);

    /* Describe an editing context requiring two facets. */
    const cepDT* ctx_role_tags[] = {
        CEP_DTAW("CEP", "role_source"),
        CEP_DTAW("CEP", "role_subj"),
    };
    const cepCell* ctx_role_targets[] = { user.cell, document.cell };
    const cepDT* facet_tags[] = {
        CEP_DTAW("CEP", "facet_edlog"),
        CEP_DTAW("CEP", "facet_prsnc"),
    };
    cepContextHandle context_handle = {0};
    cepContextSpec context_spec = {
        .tag = CEP_DTAW("CEP", "ctx_edit"),
        .role_count = 2,
        .role_tags = ctx_role_tags,
        .role_targets = ctx_role_targets,
        .metadata = NULL,
        .facet_tags = facet_tags,
        .facet_count = 2,
        .causal_op = 0,
        .label = "First Draft",
    };
    rc = cep_context_upsert(root, &context_spec, &context_handle);
    assert_int(rc, ==, CEP_L1_OK);
    assert_not_null(context_handle.cell);

    /* Validate beings carry the advertised metadata. */
    cepCell* being_alx = cep_cell_find_by_name(beings_root, CEP_DTAW("CEP", "being_alx"));
    assert_not_null(being_alx);
    assert_string_equal(expect_value(being_alx, CEP_DTAW("CEP", "being_label")), "Alex Solo");
    assert_string_equal(expect_value(being_alx, CEP_DTAW("CEP", "being_kind")), "human");
    assert_string_equal(expect_value(being_alx, CEP_DTAW("CEP", "being_ext")), "user-001");

    cepCell* being_doc = cep_cell_find_by_name(beings_root, CEP_DTAW("CEP", "being_doc"));
    assert_not_null(being_doc);
    const char* doc_label = expect_value(being_doc, CEP_DTAW("CEP", "being_label"));
    assert_string_equal(doc_label, "Feature Doc");
    assert_string_equal(expect_value(being_doc, CEP_DTAW("CEP", "being_kind")), "document");
    assert_string_equal(expect_value(being_doc, CEP_DTAW("CEP", "being_ext")), "doc-2024A");

    /* Bond record captures role summaries and annotations. */
    cepCell* bond_node = cep_cell_find_by_name(bonds_root, CEP_DTAW("CEP", "bond_caned"));
    assert_not_null(bond_node);
    assert_string_equal(expect_value(bond_node, CEP_DTAW("CEP", "bond_label")), "Primary Edit");
    assert_string_equal(expect_value(bond_node, CEP_DTAW("CEP", "bond_note")), "shared workspace");
    cepCell* bond_role_a = expect_dictionary(bond_node, CEP_DTAW("CEP", "role_a"));
    assert_string_equal(expect_value(bond_role_a, CEP_DTAW("CEP", "value")), "being_doc");
    cepCell* bond_role_b = expect_dictionary(bond_node, CEP_DTAW("CEP", "role_b"));
    assert_string_equal(expect_value(bond_role_b, CEP_DTAW("CEP", "value")), "being_alx");

    /* Context node tracks participants and label. */
    cepCell* context_node = cep_cell_find_by_name(contexts_root, CEP_DTAW("CEP", "ctx_edit"));
    assert_not_null(context_node);
    assert_string_equal(expect_value(context_node, CEP_DTAW("CEP", "ctx_label")), "First Draft");
    assert_string_equal(expect_value(cep_cell_find_by_name(context_node, CEP_DTAW("CEP", "role_source")), CEP_DTAW("CEP", "value")), "being_alx");
    assert_string_equal(expect_value(cep_cell_find_by_name(context_node, CEP_DTAW("CEP", "role_subj")), CEP_DTAW("CEP", "value")), "being_doc");

    /* Facet records mark pending state and the queue references the context. */
    cepCell* facet_edlog = cep_cell_find_by_name(facets_root, CEP_DTAW("CEP", "facet_edlog"));
    assert_not_null(facet_edlog);
    assert_string_equal(expect_value(facet_edlog, CEP_DTAW("CEP", "facet_state")), "pending");
    cepCell* facet_prsnc = cep_cell_find_by_name(facets_root, CEP_DTAW("CEP", "facet_prsnc"));
    assert_not_null(facet_prsnc);
    assert_string_equal(expect_value(facet_prsnc, CEP_DTAW("CEP", "facet_state")), "pending");

    cepCell* queue_edlog = cep_cell_find_by_name(facet_queue, CEP_DTAW("CEP", "facet_edlog"));
    assert_not_null(queue_edlog);
    assert_string_equal(expect_value(queue_edlog, CEP_DTAW("CEP", "value")), "First Draft");
    assert_string_equal(expect_value(queue_edlog, CEP_DTAW("CEP", "queue_state")), "pending");

    cepCell* queue_prsnc = cep_cell_find_by_name(facet_queue, CEP_DTAW("CEP", "facet_prsnc"));
    assert_not_null(queue_prsnc);
    assert_string_equal(expect_value(queue_prsnc, CEP_DTAW("CEP", "value")), "First Draft");
    assert_string_equal(expect_value(queue_prsnc, CEP_DTAW("CEP", "queue_state")), "pending");

    // Adjacency mirrors capture both the bond and the active context for each being.
    cepCell* adjacency_alx = expect_dictionary(adjacency_root, CEP_DTAW("CEP", "being_alx"));
    const char* adjacency_alx_bond = expect_value(adjacency_alx, CEP_DTAW("CEP", "bond_caned"));
    assert_string_equal(adjacency_alx_bond, "bond_caned:doc-2024A");
    assert_string_equal(expect_value(adjacency_alx, CEP_DTAW("CEP", "ctx_edit")), "ctx_edit:First Draft");

    cepCell* adjacency_doc = expect_dictionary(adjacency_root, CEP_DTAW("CEP", "being_doc"));
    const char* adjacency_doc_bond = expect_value(adjacency_doc, CEP_DTAW("CEP", "bond_caned"));
    assert_string_equal(adjacency_doc_bond, "bond_caned:user-001");
    assert_string_equal(expect_value(adjacency_doc, CEP_DTAW("CEP", "ctx_edit")), "ctx_edit:First Draft");

    // Counts remain stable after repeat upserts (idempotent behaviour).
    rc = cep_bond_upsert(root, &bond_spec, &bond_handle);
    assert_int(rc, ==, CEP_L1_OK);
    rc = cep_context_upsert(root, &context_spec, &context_handle);
    assert_int(rc, ==, CEP_L1_OK);
    assert_size(cep_cell_children(beings_root), ==, 2);
    assert_size(cep_cell_children(bonds_root), ==, 1);
    assert_size(cep_cell_children(contexts_root), ==, 1);
    assert_size(cep_cell_children(facets_root), ==, 2);
    assert_size(cep_cell_children(adjacency_alx), ==, 2);
    assert_size(cep_cell_children(adjacency_doc), ==, 2);
    assert_size(cep_cell_children(facet_queue), ==, 2);

    // Ensure disable-auto-create configuration refuses to backfill topology.
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
