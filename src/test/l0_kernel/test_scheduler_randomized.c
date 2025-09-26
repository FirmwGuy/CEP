/*
 *  Scheduler stress tests weave together heartbeat pulses and enzyme DAGs using
 *  randomized dependency graphs and requeue patterns to ensure the orchestrator
 *  preserves ordering guarantees under load.
 */

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
} RandomEnzyme;

static void shuffle_indices(size_t* items, size_t count) {
    for (size_t i = count; i > 1; --i) {
        size_t j = (size_t)munit_rand_int_range(0, (int)i);
        if (i - 1 != j) {
            size_t tmp = items[i - 1];
            items[i - 1] = items[j];
            items[j] = tmp;
        }
    }
}

static bool build_random_registry(RandomEnzyme* enzymes,
                                  size_t* topo_order,
                                  size_t count,
                                  cepEnzymeRegistry* registry,
                                  const cepPath* query) {
    cepID base_tag = CEP_NAME_TEMP + 5000;
    for (size_t i = 0; i < count; ++i) {
        RandomEnzyme* current = &enzymes[i];
        memset(current, 0, sizeof *current);
        current->descriptor.name.domain = CEP_ACRO("ENZ");
        current->descriptor.name.tag = cep_id_to_numeric(base_tag + (cepID)i);
        current->descriptor.label = "random-enzyme";
        current->descriptor.before = current->before;
        current->descriptor.after = current->after;
        current->descriptor.before_count = 0u;
        current->descriptor.after_count = 0u;
        current->descriptor.callback = NULL;
        current->descriptor.flags = CEP_ENZYME_FLAG_NONE;
        current->descriptor.match = CEP_ENZYME_MATCH_EXACT;
        topo_order[i] = i;
    }

    shuffle_indices(topo_order, count);

    bool adjacency[MAX_RANDOM_ENZYMES][MAX_RANDOM_ENZYMES] = {{false}};
    for (size_t ahead = 0; ahead < count; ++ahead) {
        size_t head_index = topo_order[ahead];
        for (size_t behind = ahead + 1; behind < count; ++behind) {
            size_t tail_index = topo_order[behind];
            if (munit_rand_uint32() & 1u) {
                adjacency[head_index][tail_index] = true;
            }
        }
    }

    for (size_t src = 0; src < count; ++src) {
        for (size_t dst = 0; dst < count; ++dst) {
            if (!adjacency[src][dst])
                continue;
            RandomEnzyme* from = &enzymes[src];
            RandomEnzyme* to   = &enzymes[dst];
            to->after[to->descriptor.after_count++] = from->descriptor.name;
            from->before[from->descriptor.before_count++] = to->descriptor.name;
        }
    }

    size_t registration_order[MAX_RANDOM_ENZYMES];
    for (size_t i = 0; i < count; ++i)
        registration_order[i] = i;
    shuffle_indices(registration_order, count);

    for (size_t i = 0; i < count; ++i) {
        RandomEnzyme* current = &enzymes[registration_order[i]];
        if (cep_enzyme_register(registry, query, &current->descriptor) != CEP_ENZYME_SUCCESS)
            return false;
    }
    cep_enzyme_registry_activate_pending(registry);
    return true;
}

static void verify_resolved_order(const RandomEnzyme* enzymes,
                                  const size_t* topo_order,
                                  size_t count,
                                  const cepEnzymeDescriptor* const* resolved,
                                  size_t resolved_count) {
    munit_assert_size(resolved_count, ==, count);
    for (size_t i = 0; i < count; ++i) {
        size_t expected_index = topo_order[i];
        const cepDT* expected = &enzymes[expected_index].descriptor.name;
        const cepEnzymeDescriptor* actual = resolved[i];
        munit_assert_not_null(actual);
        munit_assert_int(cep_dt_compare(expected, &actual->name), ==, 0);
    }
}

static void exercise_random_resolution(TestWatchdog* watchdog) {
    size_t enzyme_count = (size_t)munit_rand_int_range(4, (int)MAX_RANDOM_ENZYMES);
    RandomEnzyme enzymes[MAX_RANDOM_ENZYMES];
    size_t topo[MAX_RANDOM_ENZYMES];

    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    PathBuffer path_buf;
    const cepDT signal_segments[] = { *CEP_DTAA("SIG", "RAND") };
    const cepPath* query = make_path(&path_buf, signal_segments, 1u);

    if (!build_random_registry(enzymes, topo, enzyme_count, registry, query)) {
        cep_enzyme_registry_destroy(registry);
        test_watchdog_signal(watchdog);
        return;
    }

    cepImpulse impulse = {
        .signal_path = query,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* resolved[MAX_RANDOM_ENZYMES] = {0};
    size_t resolved_count = cep_enzyme_resolve(registry, &impulse, resolved, cep_lengthof(resolved));
    verify_resolved_order(enzymes, topo, enzyme_count, resolved, resolved_count);

    cep_enzyme_registry_destroy(registry);
    test_watchdog_signal(watchdog);
}

static unsigned g_success_calls;
static unsigned g_retry_calls;
static bool     g_force_retry;

static int heartbeat_success_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    ++g_success_calls;
    return CEP_ENZYME_SUCCESS;
}

static int heartbeat_retry_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    ++g_retry_calls;
    if (g_force_retry) {
        return CEP_ENZYME_RETRY;
    }
    return CEP_ENZYME_SUCCESS;
}

static void exercise_heartbeat_random(TestWatchdog* watchdog) {
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
    const cepDT signal_segments[] = { *CEP_DTAA("SIG", "BEAT") };
    const cepPath* path = make_path(&path_buf, signal_segments, 1u);

    cepEnzymeDescriptor success_a = {
        .name   = *CEP_DTAA("HB", "A"),
        .label  = "success-a",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_success_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepEnzymeDescriptor success_b = success_a;
    success_b.name = *CEP_DTAA("HB", "B");
    success_b.label = "success-b";

    cepEnzymeDescriptor retrying = success_a;
    retrying.name = *CEP_DTAA("HB", "R");
    retrying.label = "retry";
    retrying.callback = heartbeat_retry_enzyme;

    munit_assert_int(cep_enzyme_register(registry, path, &success_a), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, path, &success_b), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, path, &retrying), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    size_t impulses = (size_t)munit_rand_int_range(1, 5);
    g_success_calls = 0u;
    g_retry_calls = 0u;
    g_force_retry = true;

    for (size_t i = 0; i < impulses; ++i) {
        munit_assert_int(cep_heartbeat_enqueue_signal(0u, path, NULL), ==, CEP_ENZYME_SUCCESS);
    }

    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());

    munit_assert_uint(g_success_calls, ==, impulses * 2u);
    munit_assert_uint(g_retry_calls, ==, impulses);

    g_force_retry = false;
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());

    munit_assert_uint(g_success_calls, ==, impulses * 4u);
    munit_assert_uint(g_retry_calls, ==, impulses * 2u);

    cep_heartbeat_shutdown();
    test_watchdog_signal(watchdog);
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
    for (unsigned round = 0; round < 8; ++round) {
        exercise_random_resolution(fix->watchdog);
    }
    exercise_heartbeat_random(fix->watchdog);
    return MUNIT_OK;
}
