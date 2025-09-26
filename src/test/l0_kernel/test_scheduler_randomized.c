/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/*
 *  Scheduler fuzzing weaves randomized dependency graphs and heartbeat queues
 *  to ensure topological resolution and retry semantics remain stable while
 *  enzymes load and requeue under pressure.
 */
/* Randomized scheduler tests for agenda ordering and fairness. */


#include "test.h"
#include "watchdog.h"

#include "cep_enzyme.h"
#include "cep_heartbeat.h"

#include <string.h>

#define TEST_TIMEOUT_SECONDS 60u
#define MAX_RANDOM_ENZYMES   16u

typedef struct {
    TestWatchdog* watchdog;
} SchedulerFixture;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast   segments[4];
} PathBuffer;

static const cepPath* make_path(PathBuffer* buf, const cepDT* segments, unsigned count) {
    munit_assert_uint(count, <=, cep_lengthof(buf->segments));
    buf->length = count;
    buf->capacity = cep_lengthof(buf->segments);
    for (unsigned i = 0; i < count; ++i) {
        buf->segments[i].dt = segments[i];
        buf->segments[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}

typedef struct {
    cepEnzymeDescriptor descriptor;
    cepDT               before[MAX_RANDOM_ENZYMES];
    cepDT               after[MAX_RANDOM_ENZYMES];
} FuzzEnzyme;

static void shuffle_indices(size_t* indices, size_t count) {
    for (size_t i = count; i > 1; --i) {
        size_t j = (size_t)munit_rand_int_range(0, (int)i);
        if (j == i - 1)
            continue;
        size_t tmp = indices[i - 1];
        indices[i - 1] = indices[j];
        indices[j] = tmp;
    }
}

static void seed_enzyme_descriptor(FuzzEnzyme* enzyme, cepID base_tag, size_t index) {
    memset(enzyme, 0, sizeof *enzyme);
    enzyme->descriptor.name.domain = CEP_ACRO("ENZ");
    enzyme->descriptor.name.tag = cep_id_to_numeric(base_tag + (cepID)index);
    enzyme->descriptor.label = "random-enzyme";
    enzyme->descriptor.before = enzyme->before;
    enzyme->descriptor.after = enzyme->after;
    enzyme->descriptor.before_count = 0u;
    enzyme->descriptor.after_count = 0u;
    enzyme->descriptor.callback = NULL;
    enzyme->descriptor.flags = CEP_ENZYME_FLAG_NONE;
    enzyme->descriptor.match = CEP_ENZYME_MATCH_EXACT;
}

static void link_dependency(FuzzEnzyme* head, FuzzEnzyme* tail) {
    munit_assert_size(head->descriptor.after_count, <, MAX_RANDOM_ENZYMES);
    munit_assert_size(tail->descriptor.before_count, <, MAX_RANDOM_ENZYMES);

    head->after[head->descriptor.after_count++] = tail->descriptor.name;
    tail->before[tail->descriptor.before_count++] = head->descriptor.name;
}

static bool build_random_dag(FuzzEnzyme* enzymes,
                             size_t* topo_order,
                             size_t count,
                             cepEnzymeRegistry* registry,
                             const cepPath* signal_path) {
    cepID base_tag = CEP_NAME_TEMP + 2000u;
    for (size_t i = 0; i < count; ++i) {
        seed_enzyme_descriptor(&enzymes[i], base_tag, i);
        topo_order[i] = i;
    }

    shuffle_indices(topo_order, count);

    bool adjacency[MAX_RANDOM_ENZYMES][MAX_RANDOM_ENZYMES] = {{false}};
    for (size_t pos = 0; pos < count; ++pos) {
        size_t head = topo_order[pos];
        for (size_t next = pos + 1; next < count; ++next) {
            size_t tail = topo_order[next];
            if (munit_rand_uint32() & 1u) {
                adjacency[head][tail] = true;
            }
        }
    }

    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < count; ++j) {
            if (!adjacency[i][j])
                continue;
            link_dependency(&enzymes[i], &enzymes[j]);
        }
    }

    size_t registration[MAX_RANDOM_ENZYMES];
    for (size_t i = 0; i < count; ++i)
        registration[i] = i;
    shuffle_indices(registration, count);

    for (size_t i = 0; i < count; ++i) {
        FuzzEnzyme* current = &enzymes[registration[i]];
        if (cep_enzyme_register(registry, signal_path, &current->descriptor) != CEP_ENZYME_SUCCESS)
            return false;
    }

    cep_enzyme_registry_activate_pending(registry);
    return true;
}

static void verify_topological_resolution(const FuzzEnzyme* enzymes,
                                          const size_t* topo_order,
                                          size_t count,
                                          const cepEnzymeDescriptor* const* resolved,
                                          size_t resolved_count) {
    munit_assert_size(resolved_count, ==, count);
    for (size_t i = 0; i < count; ++i) {
        size_t expected_index = topo_order[i];
        const cepEnzymeDescriptor* actual = resolved[i];
        munit_assert_not_null(actual);
        munit_assert_int(cep_dt_compare(&enzymes[expected_index].descriptor.name, &actual->name), ==, 0);
    }
}

static void exercise_random_registry(SchedulerFixture* fix) {
    size_t enzyme_count = (size_t)munit_rand_int_range(4, (int)MAX_RANDOM_ENZYMES);
    FuzzEnzyme enzymes[MAX_RANDOM_ENZYMES];
    size_t topo_order[MAX_RANDOM_ENZYMES];

    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    PathBuffer path_buf;
    const cepDT signal_segments[] = { *CEP_DTAA("SIG", "RAND") };
    const cepPath* query = make_path(&path_buf, signal_segments, 1u);

    if (build_random_dag(enzymes, topo_order, enzyme_count, registry, query)) {
        cepImpulse impulse = {
            .signal_path = query,
            .target_path = NULL,
        };

        const cepEnzymeDescriptor* resolved[MAX_RANDOM_ENZYMES] = {0};
        size_t resolved_count = cep_enzyme_resolve(registry,
                                                   &impulse,
                                                   resolved,
                                                   cep_lengthof(resolved));
        verify_topological_resolution(enzymes, topo_order, enzyme_count, resolved, resolved_count);
    }

    cep_enzyme_registry_destroy(registry);
    test_watchdog_signal(fix->watchdog);
}

static unsigned g_success_calls;
static unsigned g_retry_calls;
static bool     g_force_retry;

static int heartbeat_success(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    ++g_success_calls;
    return CEP_ENZYME_SUCCESS;
}

static int heartbeat_retry(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    ++g_retry_calls;
    if (g_force_retry)
        return CEP_ENZYME_RETRY;
    return CEP_ENZYME_SUCCESS;
}

static void exercise_heartbeat_sequence(SchedulerFixture* fix) {
    cep_heartbeat_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    PathBuffer path_buf;
    const cepDT path_segments[] = { *CEP_DTAA("SIG", "HB") };
    const cepPath* path = make_path(&path_buf, path_segments, 1u);

    cepEnzymeDescriptor success_a = {
        .name   = *CEP_DTAA("HB", "A"),
        .label  = "heartbeat-success-a",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_success,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepEnzymeDescriptor success_b = success_a;
    success_b.name = *CEP_DTAA("HB", "B");
    success_b.label = "heartbeat-success-b";

    cepEnzymeDescriptor retrying = success_a;
    retrying.name = *CEP_DTAA("HB", "R");
    retrying.label = "heartbeat-retry";
    retrying.callback = heartbeat_retry;

    munit_assert_int(cep_enzyme_register(registry, path, &success_a), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, path, &success_b), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, path, &retrying), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    size_t pulses = (size_t)munit_rand_int_range(1, 5);
    g_success_calls = 0u;
    g_retry_calls = 0u;
    g_force_retry = true;

    for (size_t i = 0; i < pulses; ++i) {
        munit_assert_int(cep_heartbeat_enqueue_signal(0u, path, NULL), ==, CEP_ENZYME_SUCCESS);
    }

    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());

    munit_assert_uint(g_success_calls, ==, pulses * 2u);
    munit_assert_uint(g_retry_calls, ==, pulses);

    g_force_retry = false;
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());

    munit_assert_uint(g_success_calls, ==, pulses * 4u);
    munit_assert_uint(g_retry_calls, ==, pulses * 2u);

    cep_heartbeat_shutdown();
    test_watchdog_signal(fix->watchdog);
}

void* test_scheduler_randomized_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    SchedulerFixture* fix = munit_malloc(sizeof *fix);
    unsigned timeout = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    fix->watchdog = test_watchdog_create(timeout ? timeout : TEST_TIMEOUT_SECONDS);
    return fix;
}

void test_scheduler_randomized_tear_down(void* fixture) {
    SchedulerFixture* fix = fixture;
    if (!fix)
        return;
    test_watchdog_destroy(fix->watchdog);
    free(fix);
}

MunitResult test_scheduler_randomized(const MunitParameter params[], void* fixture) {
    (void)params;
    SchedulerFixture* fix = fixture;
    munit_assert_not_null(fix);

    for (unsigned round = 0; round < 8; ++round)
        exercise_random_registry(fix);

    exercise_heartbeat_sequence(fix);
    return MUNIT_OK;
}

