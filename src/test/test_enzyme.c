/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */


#include "test.h"
#include "cep_enzyme.h"




typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[1];
} CepPathBuf;


static const cepPath* make_single_segment_path(CepPathBuf* buf, const cepDT* segment) {
    buf->length = 1u;
    buf->capacity = 1u;
    buf->segments[0].dt = *segment;
    buf->segments[0].timestamp = 0u;
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

    return MUNIT_OK;
}
