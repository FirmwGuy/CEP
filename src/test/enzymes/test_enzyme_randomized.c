/* Randomized enzyme registry tests ensure dependency ordering remains stable no matter what combination of descriptors a fuzzed run produces. We rely on the munit PRNG so each iteration shakes the registry with different dependency graphs while still running deterministically under the harness seed. */

#include "test.h"

#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"

#include <stdio.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RANDOM_ENZYMES 12
#define RANDOM_ITERATIONS 24

typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[1];
} CepPathBuf;

/* make_single_segment_path builds a minimal path buffer so randomized tests can target a single descriptor. */
static const cepPath* make_single_segment_path(CepPathBuf* buf, const cepDT* segment) {
    buf->length = 1u;
    buf->capacity = 1u;
    buf->segments[0].dt = *segment;
    buf->segments[0].timestamp = 0u;
    return (const cepPath*)buf;
}

/* Dummy enzyme callback used by randomized descriptors to satisfy the registry contract. */
static int dummy_enzyme_success(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    return CEP_ENZYME_SUCCESS;
}

/* make_enzyme_dt crafts a unique test dt using the lexicon test_ez_r* sandbox. */
static cepDT make_enzyme_dt(size_t index) {
    munit_assert_size(index, <, MAX_RANDOM_ENZYMES);
    switch (index) {
    case 0:  return *CEP_DTAW("CEP", "tst_enza");
    case 1:  return *CEP_DTAW("CEP", "tst_enzb");
    case 2:  return *CEP_DTAW("CEP", "tst_enzc");
    case 3:  return *CEP_DTAW("CEP", "tst_enzi");
    case 4:  return *CEP_DTAW("CEP", "tst_enzj");
    case 5:  return *CEP_DTAW("CEP", "tst_enzk");
    case 6:  return *CEP_DTAW("CEP", "tst_enzl");
    case 7:  return *CEP_DTAW("CEP", "tst_enzm");
    case 8:  return *CEP_DTAW("CEP", "tst_enzo");
    case 9:  return *CEP_DTAW("CEP", "tst_enzp");
    case 10: return *CEP_DTAW("CEP", "tst_enzq");
    case 11: return *CEP_DTAW("CEP", "tst_enzr");
    default: break;
    }
    munit_error("unexpected enzyme index");
    return (cepDT){0};
}

/* resolve_positions builds a lookup table mapping descriptor indexes to their resolved order. */
static void resolve_positions(const cepEnzymeDescriptor* const resolved[], size_t resolved_count,
                              const cepDT names[], size_t* out_positions, size_t descriptor_count) {
    for (size_t i = 0; i < descriptor_count; ++i) {
        out_positions[i] = SIZE_MAX;
    }

    for (size_t order = 0; order < resolved_count; ++order) {
        const cepEnzymeDescriptor* descriptor = resolved[order];
        munit_assert_not_null(descriptor);
        bool mapped = false;
        for (size_t idx = 0; idx < descriptor_count; ++idx) {
            if (cep_dt_compare(&descriptor->name, &names[idx]) == 0) {
                out_positions[idx] = order;
                mapped = true;
                break;
            }
        }
        munit_assert_true(mapped);
    }
}

/* verify_dependency_order checks that every dependency resolved prior to its consumer. */
static void verify_dependency_order(const cepDT names[], const size_t dependency_counts[],
                                    cepDT dependencies[][MAX_RANDOM_ENZYMES], const size_t positions[],
                                    size_t descriptor_count) {
    for (size_t idx = 0; idx < descriptor_count; ++idx) {
        size_t current_position = positions[idx];
        munit_assert_size(current_position, <, descriptor_count);
        for (size_t dep = 0; dep < dependency_counts[idx]; ++dep) {
            const cepDT* dependency_name = &dependencies[idx][dep];
            bool found = false;
            for (size_t lookup = 0; lookup < descriptor_count; ++lookup) {
                if (cep_dt_compare(dependency_name, &names[lookup]) == 0) {
                    size_t dependency_position = positions[lookup];
                    munit_assert_size(dependency_position, <, current_position);
                    found = true;
                    break;
                }
            }
            munit_assert_true(found);
        }
    }
}

MunitResult test_enzyme_randomized(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    cepDT signal_dt = *CEP_DTAW("CEP", "sig_rand");
    for (size_t iteration = 0; iteration < RANDOM_ITERATIONS; ++iteration) {
        munit_assert_true(cep_heartbeat_bootstrap());
        CepPathBuf signal_buf;
        const cepPath* signal_path = make_single_segment_path(&signal_buf, &signal_dt);
        munit_assert_not_null(signal_path);
        cepEnzymeRegistry* registry = cep_enzyme_registry_create();
        munit_assert_not_null(registry);

        size_t descriptor_count = (size_t)munit_rand_int_range(3, MAX_RANDOM_ENZYMES);
        cepDT names[MAX_RANDOM_ENZYMES] = {0};
        cepEnzymeDescriptor descriptors[MAX_RANDOM_ENZYMES] = {0};
        cepDT after_lists[MAX_RANDOM_ENZYMES][MAX_RANDOM_ENZYMES] = {0};
        size_t after_counts[MAX_RANDOM_ENZYMES] = {0};

        for (size_t idx = 0; idx < descriptor_count; ++idx) {
            names[idx] = make_enzyme_dt(idx);

            size_t dependency_pool = idx;
            size_t desired_dependencies = (dependency_pool == 0)
                ? 0
                : (size_t)munit_rand_int_range(0, (int)cep_min(dependency_pool, (size_t)3));

            size_t chosen = 0;
            bool used[MAX_RANDOM_ENZYMES] = {0};
            while (chosen < desired_dependencies) {
                size_t candidate = (size_t)munit_rand_int_range(0, (int)dependency_pool);
                if (candidate == dependency_pool) {
                    continue;
                }
                if (used[candidate]) {
                    continue;
                }
                used[candidate] = true;
                after_lists[idx][chosen] = names[candidate];
                ++chosen;
            }
            after_counts[idx] = chosen;

            descriptors[idx] = (cepEnzymeDescriptor){
                .name = names[idx],
                .label = "random-enzyme",
                .before = NULL,
                .before_count = 0,
                .after = after_lists[idx],
                .after_count = after_counts[idx],
                .callback = dummy_enzyme_success,
                .flags = CEP_ENZYME_FLAG_NONE,
                .match = CEP_ENZYME_MATCH_EXACT,
            };

            munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptors[idx]), ==, CEP_ENZYME_SUCCESS);
        }

        cep_enzyme_registry_activate_pending(registry);
        munit_assert_size(cep_enzyme_registry_size(registry), ==, descriptor_count);

        const cepEnzymeDescriptor* resolved[MAX_RANDOM_ENZYMES] = {0};
        cepImpulse impulse = {
            .signal_path = signal_path,
            .target_path = NULL,
        };
        size_t resolved_count = cep_enzyme_resolve(registry, &impulse, resolved, MAX_RANDOM_ENZYMES);
        munit_assert_size(resolved_count, ==, descriptor_count);

        size_t positions[MAX_RANDOM_ENZYMES] = {0};
        resolve_positions(resolved, resolved_count, names, positions, descriptor_count);
        verify_dependency_order(names, after_counts, after_lists, positions, descriptor_count);

        cep_enzyme_registry_destroy(registry);
        test_runtime_shutdown();
    }

    return MUNIT_OK;
}
