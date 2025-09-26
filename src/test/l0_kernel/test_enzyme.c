/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Checks enzyme registry behaviour and runtime matching rules. */



#include "test.h"
#include "cep_enzyme.h"




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


static int dummy_enzyme_success(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    return CEP_ENZYME_SUCCESS;
}


static MunitResult test_enzyme_dependencies(void) {
    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    cepDT query_dt = *CEP_DTWW("SIG", "IMG");
    CepPathBuf query_buf;
    const cepPath* query_path = make_single_segment_path(&query_buf, &query_dt);

    cepDT name_a = *CEP_DTAA("ENZ", "A");
    cepDT name_b = *CEP_DTAA("ENZ", "B");
    cepDT name_c = *CEP_DTAA("ENZ", "C");

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

    cepDT query_dt = *CEP_DTWW("SIG", "CYCLE");
    CepPathBuf query_buf;
    const cepPath* query_path = make_single_segment_path(&query_buf, &query_dt);

    cepDT name_d = *CEP_DTAA("ENZ", "D");
    cepDT name_e = *CEP_DTAA("ENZ", "E");

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

    const cepDT seg_root = *CEP_DTWW("CMP", "ROOT");
    const cepDT seg_signal = *CEP_DTWW("SIG", "GAMMA");

    CepPathBufDyn path_buf = {0};
    const cepDT signal_segments[] = { seg_root, seg_signal };
    const cepPath* signal_path = make_path_from_segments(&path_buf, signal_segments, cep_lengthof(signal_segments));

    cepDT name_late = *CEP_DTAA("EZ", "LATE");
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

    cepDT name_early = *CEP_DTAA("EZ", "EARL");
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

    const cepDT seg_root = *CEP_DTWW("CMP", "ROOT");
    const cepDT seg_detail = *CEP_DTWW("SIG", "BETA");

    CepPathBufDyn signal_buf = {0};
    const cepDT signal_segments[] = { seg_root, seg_detail };
    const cepPath* signal_path = make_path_from_segments(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    CepPathBufDyn prefix_buf = {0};
    const cepDT prefix_segments[] = { seg_root };
    const cepPath* prefix_path = make_path_from_segments(&prefix_buf, prefix_segments, cep_lengthof(prefix_segments));

    CepPathBufDyn exact_buf = {0};
    const cepPath* exact_path = make_path_from_segments(&exact_buf, signal_segments, cep_lengthof(signal_segments));

    cepDT name_specific = *CEP_DTAA("EZ", "SP");
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

    cepDT name_general = *CEP_DTAA("EZ", "GE");
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


void* test_enzyme_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    return NULL;
}


void test_enzyme_tear_down(void* fixture) {
    (void)fixture;
}


MunitResult test_enzyme(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
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

    result = test_enzyme_specificity_priority();
    if (result != MUNIT_OK) {
        return result;
    }

    return MUNIT_OK;
}
