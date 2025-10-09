/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Checks enzyme registry behaviour and runtime matching rules. */



#include "test.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"




typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[1];
} CepPathBuf;

typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[4];
} CepPathBufDyn;


static const cepPath* make_single_segment_path(CepPathBuf* buf, const cepDT* segment) {
    buf->length = 1u;
    buf->capacity = 1u;
    buf->segments[0].dt = *segment;
    buf->segments[0].timestamp = 0u;
    return (const cepPath*)buf;
}


static const cepPath* make_path_from_segments(CepPathBufDyn* buf, const cepDT* segments, unsigned count) {
    munit_assert_uint(count, <=, cep_lengthof(buf->segments));
    buf->length = count;
    buf->capacity = cep_lengthof(buf->segments);
    for (unsigned i = 0; i < count; ++i) {
        buf->segments[i].dt = segments[i];
        buf->segments[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}


static void enzyme_runtime_start(void) {
    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
}


static const cepPath* ensure_dictionary_path(const cepDT* segments,
                                             unsigned count,
                                             CepPathBufDyn* buf,
                                             const cepDT* type_dt,
                                             cepCell** out_leaf) {
    cepCell* parent = cep_root();
    for (unsigned i = 0; i < count; ++i) {
        cepCell* child = cep_cell_find_by_name(parent, &segments[i]);
        if (!child) {
            child = cep_cell_add_dictionary(parent,
                                            (cepDT*)&segments[i],
                                            0,
                                            (cepDT*)type_dt,
                                            CEP_STORAGE_RED_BLACK_T);
        }
        munit_assert_not_null(child);
        parent = child;
    }

    if (out_leaf) {
        *out_leaf = parent;
    }

    return make_path_from_segments(buf, segments, count);
}


static int dummy_enzyme_success(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    return CEP_ENZYME_SUCCESS;
}


static MunitResult test_enzyme_tombstone_masks_ancestor(void) {
    enzyme_runtime_start();

    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    const cepDT seg_root = *CEP_DTAW("CEP", "test_enz_ro");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "test_enz_le");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepPathBufDyn target_buf = {0};
    cepCell* leaf = NULL;
    const cepPath* target_path = ensure_dictionary_path(path_segments,
                                                       cep_lengthof(path_segments),
                                                       &target_buf,
                                                       CEP_DTAW("CEP", "dictionary"),
                                                       &leaf);
    munit_assert_not_null(target_path);
    munit_assert_not_null(leaf);

    cepCell* parent = cep_cell_parent(leaf);
    munit_assert_not_null(parent);

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_ma");

    munit_assert_int(cep_cell_bind_enzyme(parent, &enzyme_name, true), ==, CEP_ENZYME_SUCCESS);

    CepPathBuf signal_buf;
    const cepPath* signal_path = make_single_segment_path(&signal_buf, &seg_root);

    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "tombstone-mask",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepImpulse impulse = {
        .signal_path = NULL,
        .target_path = target_path,
    };

    const cepEnzymeDescriptor* ordered[2] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 1);
    munit_assert_not_null(ordered[0]);
    munit_assert_int(cep_dt_compare(&ordered[0]->name, &enzyme_name), ==, 0);

    munit_assert_int(cep_cell_unbind_enzyme(leaf, &enzyme_name), ==, CEP_ENZYME_SUCCESS);

    resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 0);

    cep_enzyme_registry_destroy(registry);
    test_runtime_shutdown();
    return MUNIT_OK;
}


static MunitResult test_enzyme_dependencies(void) {
    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    cepDT query_dt = *CEP_DTAW("CEP", "sig_img");
    CepPathBuf query_buf;
    const cepPath* query_path = make_single_segment_path(&query_buf, &query_dt);

    cepDT name_a = *CEP_DTAW("CEP", "test_enz_a");
    cepDT name_b = *CEP_DTAW("CEP", "test_enz_b");
    cepDT name_c = *CEP_DTAW("CEP", "test_enz_c");

    cepEnzymeDescriptor desc_a = {
        .name   = name_a,
        .label  = "A",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepDT after_b_list[] = { name_a };
    cepEnzymeDescriptor desc_b = {
        .name   = name_b,
        .label  = "B",
        .before = NULL,
        .before_count = 0,
        .after = after_b_list,
        .after_count = cep_lengthof(after_b_list),
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepDT before_c_list[] = { name_b };
    cepDT after_c_list[]  = { name_a };
    cepEnzymeDescriptor desc_c = {
        .name   = name_c,
        .label  = "C",
        .before = before_c_list,
        .before_count = cep_lengthof(before_c_list),
        .after = after_c_list,
        .after_count = cep_lengthof(after_c_list),
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    munit_assert_int(cep_enzyme_register(registry, query_path, &desc_a), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, query_path, &desc_b), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, query_path, &desc_c), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = query_path,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 3);
    munit_assert_not_null(ordered[0]);
    munit_assert_not_null(ordered[1]);
    munit_assert_not_null(ordered[2]);

    munit_assert_int(cep_dt_compare(&ordered[0]->name, &name_a), ==, 0);
    munit_assert_int(cep_dt_compare(&ordered[1]->name, &name_c), ==, 0);
    munit_assert_int(cep_dt_compare(&ordered[2]->name, &name_b), ==, 0);

    cep_enzyme_registry_destroy(registry);
    return MUNIT_OK;
}


static MunitResult test_enzyme_dependency_cycle(void) {
    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    cepDT query_dt = *CEP_DTAW("CEP", "sig_cycle");
    CepPathBuf query_buf;
    const cepPath* query_path = make_single_segment_path(&query_buf, &query_dt);

    cepDT name_d = *CEP_DTAW("CEP", "test_enz_d");
    cepDT name_e = *CEP_DTAW("CEP", "test_enz_e");

    cepDT after_d_list[] = { name_e };
    cepEnzymeDescriptor desc_d = {
        .name   = name_d,
        .label  = "D",
        .before = NULL,
        .before_count = 0,
        .after = after_d_list,
        .after_count = cep_lengthof(after_d_list),
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepDT after_e_list[] = { name_d };
    cepEnzymeDescriptor desc_e = {
        .name   = name_e,
        .label  = "E",
        .before = NULL,
        .before_count = 0,
        .after = after_e_list,
        .after_count = cep_lengthof(after_e_list),
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    munit_assert_int(cep_enzyme_register(registry, query_path, &desc_d), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, query_path, &desc_e), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = query_path,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 0);

    cep_enzyme_registry_destroy(registry);
    return MUNIT_OK;
}


static MunitResult test_enzyme_name_tiebreak(void) {
    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    const cepDT seg_root = *CEP_DTAW("CEP", "cmp_root");
    const cepDT seg_signal = *CEP_DTAW("CEP", "sig_gamma");

    CepPathBufDyn path_buf = {0};
    const cepDT signal_segments[] = { seg_root, seg_signal };
    const cepPath* signal_path = make_path_from_segments(&path_buf, signal_segments, cep_lengthof(signal_segments));

    cepDT name_late = *CEP_DTAW("CEP", "test_ez_la");
    cepEnzymeDescriptor desc_late = {
        .name   = name_late,
        .label  = "late",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepDT name_early = *CEP_DTAW("CEP", "test_ez_er");
    cepEnzymeDescriptor desc_early = {
        .name   = name_early,
        .label  = "early",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    munit_assert_int(cep_enzyme_register(registry, signal_path, &desc_late), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, signal_path, &desc_early), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 2);

    munit_assert_int(cep_dt_compare(&ordered[0]->name, &name_early), ==, 0);
    munit_assert_int(cep_dt_compare(&ordered[1]->name, &name_late), ==, 0);

    cep_enzyme_registry_destroy(registry);
    return MUNIT_OK;
}


static MunitResult test_enzyme_specificity_priority(void) {
    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    const cepDT seg_root = *CEP_DTAW("CEP", "cmp_root");
    const cepDT seg_detail = *CEP_DTAW("CEP", "sig_beta");

    CepPathBufDyn signal_buf = {0};
    const cepDT signal_segments[] = { seg_root, seg_detail };
    const cepPath* signal_path = make_path_from_segments(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    CepPathBufDyn prefix_buf = {0};
    const cepDT prefix_segments[] = { seg_root };
    const cepPath* prefix_path = make_path_from_segments(&prefix_buf, prefix_segments, cep_lengthof(prefix_segments));

    CepPathBufDyn exact_buf = {0};
    const cepPath* exact_path = make_path_from_segments(&exact_buf, signal_segments, cep_lengthof(signal_segments));

    cepDT name_specific = *CEP_DTAW("CEP", "test_ez_sp");
    cepEnzymeDescriptor desc_specific = {
        .name   = name_specific,
        .label  = "specific",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    cepDT name_general = *CEP_DTAW("CEP", "test_ez_ge");
    cepEnzymeDescriptor desc_general = {
        .name   = name_general,
        .label  = "general",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    munit_assert_int(cep_enzyme_register(registry, prefix_path, &desc_general), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, exact_path, &desc_specific), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 2);

    munit_assert_int(cep_dt_compare(&ordered[0]->name, &name_specific), ==, 0);
    munit_assert_int(cep_dt_compare(&ordered[1]->name, &name_general), ==, 0);

    cep_enzyme_registry_destroy(registry);
    return MUNIT_OK;
}


static MunitResult test_enzyme_data_binding_resolves(void) {
    enzyme_runtime_start();

    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    const cepDT seg_root = *CEP_DTAW("CEP", "test_enz_da");
    const cepDT path_segments[] = { seg_root };

    CepPathBufDyn target_buf = {0};
    cepCell* target = NULL;
    const cepPath* target_path = ensure_dictionary_path(path_segments,
                                                       cep_lengthof(path_segments),
                                                       &target_buf,
                                                       CEP_DTAW("CEP", "dictionary"),
                                                       &target);
    munit_assert_not_null(target);

    uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    cepData* data = cep_data_new_value(CEP_DTAW("CEP", "test_ez_pl"), payload, sizeof payload);
    munit_assert_not_null(data);
    cep_cell_set_data(target, data);
    munit_assert_not_null(target->data);
    munit_assert_not_null(target->store);

    const cepDT enzyme_data_name = *CEP_DTAW("CEP", "test_ez_da");
    const cepDT enzyme_store_name = *CEP_DTAW("CEP", "test_ez_sr");

    cepEnzymeBinding* data_binding = cep_malloc0(sizeof *data_binding);
    data_binding->name = enzyme_data_name;
    data_binding->flags = 0u;
    data_binding->modified = cep_cell_timestamp_next();
    data_binding->next = target->data->bindings;
    target->data->bindings = data_binding;

    munit_assert_int(cep_cell_bind_enzyme(target, &enzyme_store_name, false), ==, CEP_ENZYME_SUCCESS);

    CepPathBuf signal_buf;
    const cepPath* signal_path = make_single_segment_path(&signal_buf, &seg_root);

    cepEnzymeDescriptor desc_data = {
        .name   = enzyme_data_name,
        .label  = "data-binding",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    cepEnzymeDescriptor desc_store = {
        .name   = enzyme_store_name,
        .label  = "store-binding",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    munit_assert_int(cep_enzyme_register(registry, signal_path, &desc_data), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, signal_path, &desc_store), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepImpulse impulse = {
        .signal_path = NULL,
        .target_path = target_path,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 2);

    bool seen_data = false;
    bool seen_store = false;
    for (size_t i = 0; i < resolved; ++i) {
        const cepEnzymeDescriptor* desc = ordered[i];
        munit_assert_not_null(desc);
        if (cep_dt_compare(&desc->name, &enzyme_data_name) == 0) {
            seen_data = true;
        }
        if (cep_dt_compare(&desc->name, &enzyme_store_name) == 0) {
            seen_store = true;
        }
    }
    munit_assert_true(seen_data);
    munit_assert_true(seen_store);

    cep_enzyme_registry_destroy(registry);
    test_runtime_shutdown();
    return MUNIT_OK;
}


static MunitResult test_enzyme_signal_wildcard_priority(void) {
    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    cepDT seg_head = *CEP_DTAW("CEP", "sig_root");
    cepDT seg_tail = *CEP_DTAW("CEP", "test_img_vi");
    cepDT literal_segments[] = { seg_head, seg_tail };

    CepPathBufDyn signal_buf = {0};
    const cepPath* signal_path = make_path_from_segments(&signal_buf, literal_segments, cep_lengthof(literal_segments));

    CepPathBufDyn literal_buf = {0};
    const cepPath* literal_path = make_path_from_segments(&literal_buf, literal_segments, cep_lengthof(literal_segments));

    cepDT wildcard_tag_segments[] = { seg_head, seg_tail };
    wildcard_tag_segments[1].tag = CEP_ID_GLOB_MULTI;
    CepPathBufDyn wildcard_tag_buf = {0};
    const cepPath* wildcard_tag_path = make_path_from_segments(&wildcard_tag_buf, wildcard_tag_segments, cep_lengthof(wildcard_tag_segments));

    cepEnzymeDescriptor desc_literal = {
        .name   = *CEP_DTAW("CEP", "test_ez_li"),
        .label  = "literal",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepEnzymeDescriptor desc_wild_tag = {
        .name   = *CEP_DTAW("CEP", "test_ez_wl"),
        .label  = "wild-tag",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    munit_assert_int(cep_enzyme_register(registry, literal_path, &desc_literal), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, wildcard_tag_path, &desc_wild_tag), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 2);

    munit_assert_int(cep_dt_compare(&ordered[0]->name, &desc_literal.name), ==, 0);
    munit_assert_int(cep_dt_compare(&ordered[1]->name, &desc_wild_tag.name), ==, 0);

    cep_enzyme_registry_destroy(registry);
    return MUNIT_OK;
}


static MunitResult test_enzyme_signal_prefix_wildcard(void) {
    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    cepDT seg_head = *CEP_DTAW("CEP", "sig_root");
    cepDT seg_mid  = *CEP_DTAW("CEP", "test_img_ch");
    cepDT seg_tail = *CEP_DTAW("CEP", "var_leaf");
    cepDT signal_segments[] = { seg_head, seg_mid, seg_tail };

    CepPathBufDyn signal_buf = {0};
    const cepPath* signal_path = make_path_from_segments(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    cepDT prefix_specific_segments[] = { seg_head, seg_mid };
    CepPathBufDyn prefix_specific_buf = {0};
    const cepPath* prefix_specific_path = make_path_from_segments(&prefix_specific_buf, prefix_specific_segments, cep_lengthof(prefix_specific_segments));

    cepDT prefix_head_literal_segments[] = { seg_head };
    CepPathBufDyn prefix_head_literal_buf = {0};
    const cepPath* prefix_head_literal_path = make_path_from_segments(&prefix_head_literal_buf, prefix_head_literal_segments, cep_lengthof(prefix_head_literal_segments));

    cepDT prefix_mid_any_segments[] = { seg_head, seg_mid };
    prefix_mid_any_segments[1].tag = CEP_ID_GLOB_MULTI;
    CepPathBufDyn prefix_mid_any_buf = {0};
    const cepPath* prefix_mid_any_path = make_path_from_segments(&prefix_mid_any_buf, prefix_mid_any_segments, cep_lengthof(prefix_mid_any_segments));

    cepEnzymeDescriptor desc_specific = {
        .name   = *CEP_DTAW("CEP", "test_ez_p1"),
        .label  = "prefix-specific",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    cepEnzymeDescriptor desc_head_literal = {
        .name   = *CEP_DTAW("CEP", "test_ez_p2"),
        .label  = "prefix-head-literal",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    cepEnzymeDescriptor desc_mid_any = {
        .name   = *CEP_DTAW("CEP", "test_ez_p3"),
        .label  = "prefix-mid-any",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = dummy_enzyme_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    munit_assert_int(cep_enzyme_register(registry, prefix_specific_path, &desc_specific), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, prefix_head_literal_path, &desc_head_literal), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, prefix_mid_any_path, &desc_mid_any), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, ==, 3);

    munit_assert_int(cep_dt_compare(&ordered[0]->name, &desc_specific.name), ==, 0);
    munit_assert_int(cep_dt_compare(&ordered[1]->name, &desc_mid_any.name), ==, 0);
    munit_assert_int(cep_dt_compare(&ordered[2]->name, &desc_head_literal.name), ==, 0);

    cep_enzyme_registry_destroy(registry);
    return MUNIT_OK;
}


void* test_enzyme_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    return NULL;
}


void test_enzyme_tear_down(void* fixture) {
    (void)fixture;
}


MunitResult test_enzyme(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    MunitResult result;

    result = test_enzyme_dependencies();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_enzyme_dependency_cycle();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_enzyme_name_tiebreak();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_enzyme_tombstone_masks_ancestor();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_enzyme_data_binding_resolves();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_enzyme_signal_wildcard_priority();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_enzyme_signal_prefix_wildcard();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_enzyme_specificity_priority();
    if (result != MUNIT_OK) {
        return result;
    }

    return MUNIT_OK;
}
