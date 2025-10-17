/* Exercises the OPS/STATES API surface so operations can start, advance
   through state transitions, trigger continuations, honour TTL expiries, and
   reject post-close mutations. */

#include "test.h"

#include "cep_ops.h"
#include "cep_enzyme.h"

#include <string.h>

typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[4];
} OpsPathBuf;

static const cepPath* ops_make_path(OpsPathBuf* buf, const cepDT* segments, unsigned count) {
    munit_assert_uint(count, <=, cep_lengthof(buf->segments));
    buf->length = count;
    buf->capacity = cep_lengthof(buf->segments);
    for (unsigned i = 0; i < count; ++i) {
        buf->segments[i].dt = segments[i];
        buf->segments[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}

static void ops_runtime_start(bool ensure_dirs) {
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = ensure_dirs,
        .enforce_visibility = false,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_logf(MUNIT_LOG_INFO, "ops_runtime_start: rt_root=%p", (void*)rt_root);
}

static cepCell* ops_lookup_cell(cepOID oid) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);

    cepDT ops_name = cep_ops_make_dt("ops");
    cepCell* ops_root = cep_cell_find_by_name(rt_root, &ops_name);
    munit_assert_not_null(ops_root);

    cepDT lookup = {0};
    lookup.domain = oid.domain;
    lookup.tag = oid.tag;

    return cep_cell_find_by_name(ops_root, &lookup);
}

static void test_ops_direct_close_case(void) {
    ops_runtime_start(false);

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepDT ops_name = cep_ops_make_dt("ops");
    munit_assert_not_null(cep_cell_ensure_dictionary_child(rt_root, &ops_name, CEP_STORAGE_RED_BLACK_T));

    cepDT verb = cep_ops_make_dt("op/ct");
    cepDT mode = cep_ops_make_dt("opm:direct");
    munit_logf(MUNIT_LOG_INFO,
               "verb domain=%llu tag=%llu mode domain=%llu tag=%llu",
               (unsigned long long)verb.domain,
               (unsigned long long)verb.tag,
               (unsigned long long)mode.domain,
               (unsigned long long)mode.tag);
    cepOID oid = cep_op_start(verb, "/tmp/direct", mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(oid)) {
        cepCell* rt_root = cep_heartbeat_rt_root();
        cepDT ops_lookup = cep_ops_make_dt("ops");
        cepCell* ops_root = rt_root ? cep_cell_find_by_name(rt_root, &ops_lookup) : NULL;
        bool ops_root_immutable = ops_root ? cep_cell_is_immutable(ops_root) : false;
        cepCell* first = ops_root ? cep_cell_first_all(ops_root) : NULL;
        cepDT first_dt = {0};
        if (first) {
            first_dt = cep_dt_clean(&first->metacell.dt);
        }
        munit_logf(MUNIT_LOG_INFO, "ops_root=%p", (void*)ops_root);
        munit_logf(MUNIT_LOG_INFO, "ops_root immutable=%d", ops_root_immutable ? 1 : 0);
        munit_logf(MUNIT_LOG_INFO, "ops debug err=%d", cep_ops_debug_last_error());
        if (rt_root) {
            size_t idx = 0u;
            for (cepCell* child = cep_cell_first_all(rt_root); child; child = cep_cell_next_all(rt_root, child)) {
                cepDT dt = cep_dt_clean(&child->metacell.dt);
                int cmp = cep_dt_compare(&dt, &ops_lookup);
                munit_logf(MUNIT_LOG_INFO,
                           "rt child[%zu] domain=%llu tag=%llu cmp=%d",
                           idx++,
                           (unsigned long long)dt.domain,
                           (unsigned long long)dt.tag,
                           cmp);
            }
        }
        munit_logf(MUNIT_LOG_ERROR,
                   "invalid oid domain=%llu tag=%llu first=%p first_domain=%llu first_tag=%llu",
                   (unsigned long long)oid.domain,
                   (unsigned long long)oid.tag,
                   (void*)first,
                   (unsigned long long)first_dt.domain,
                   (unsigned long long)first_dt.tag);
    }
    munit_assert_true(cep_oid_is_valid(oid));

    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    bool closed = cep_op_close(oid, sts_ok, NULL, 0u);
    if (!closed) {
        munit_logf(MUNIT_LOG_ERROR, "close failed err=%d", cep_ops_debug_last_error());
    }
    munit_assert_true(closed);

    cepCell* op_cell = ops_lookup_cell(oid);
    munit_assert_not_null(op_cell);

    cepDT state_name = cep_ops_make_dt("state");
    cepCell* state_cell = cep_cell_find_by_name(op_cell, &state_name);
    munit_assert_not_null(state_cell);
    const cepDT* state_value = cep_cell_data(state_cell);
    munit_assert_not_null(state_value);
    cepDT ist_ok = cep_ops_make_dt("ist:ok");
    munit_assert_int(cep_dt_compare(state_value, &ist_ok), ==, 0);

    test_runtime_shutdown();
}

static void test_ops_stateful_history_case(void) {
    ops_runtime_start(false);

    cepDT verb = cep_ops_make_dt("op/vl");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb,
                              "/tmp/history",
                              mode,
                              NULL,
                              0u,
                              0u);
    munit_assert_true(cep_oid_is_valid(oid));

    munit_assert_true(cep_op_state_set(oid, cep_ops_make_dt("ist:skel"), 0, NULL));
    /* Duplicate should be suppressed this beat. */
    munit_assert_true(cep_op_state_set(oid, cep_ops_make_dt("ist:skel"), 0, NULL));
    munit_assert_true(cep_op_state_set(oid, cep_ops_make_dt("ist:unveil"), 0, NULL));
    munit_assert_true(cep_op_close(oid, cep_ops_make_dt("sts:ok"), NULL, 0u));

    cepCell* op_cell = ops_lookup_cell(oid);
    munit_assert_not_null(op_cell);

    cepDT history_name = cep_ops_make_dt("history");
    cepCell* history = cep_cell_find_by_name(op_cell, &history_name);
    munit_assert_not_null(history);

    cepDT expected[] = {
        cep_ops_make_dt("ist:run"),
        cep_ops_make_dt("ist:skel"),
        cep_ops_make_dt("ist:unveil"),
        cep_ops_make_dt("ist:ok"),
    };
    size_t index = 0u;

    for (cepCell* entry = cep_cell_first(history);
         entry && index < cep_lengthof(expected);
         entry = cep_cell_next(history, entry), ++index) {
        cepDT state_field = cep_ops_make_dt("state");
        cepCell* state_cell = cep_cell_find_by_name(entry, &state_field);
        munit_assert_not_null(state_cell);
        const cepDT* recorded = cep_cell_data(state_cell);
        munit_assert_not_null(recorded);
        munit_assert_int(cep_dt_compare(recorded, &expected[index]), ==, 0);
    }

    munit_assert_size(index, ==, cep_lengthof(expected));

    test_runtime_shutdown();
}

static int ops_continuation_calls;
static int ops_timeout_calls;

static int ops_cont_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    ops_continuation_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int ops_timeout_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    ops_timeout_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static void register_enzyme(const cepDT* signal_dt, cepEnzyme callback) {
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    OpsPathBuf buf = {0};
    const cepPath* query = ops_make_path(&buf, signal_dt, 1u);

    cepEnzymeDescriptor descriptor = {
        .name   = *signal_dt,
        .label  = "ops-enzyme",
        .before = NULL,
        .before_count = 0u,
        .after  = NULL,
        .after_count  = 0u,
        .callback = callback,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    munit_assert_int(cep_enzyme_register(registry, query, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
}

static void test_ops_await_continuation_case(void) {
    ops_runtime_start(false);
    cepDT cont_signal = cep_ops_make_dt("op/cont");
    register_enzyme(&cont_signal, ops_cont_enzyme);
    ops_continuation_calls = 0;

    cepDT boot = cep_ops_make_dt("op/boot");
    cepDT mode_states = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(boot,
                              "/ops/await",
                              mode_states,
                              NULL,
                              0u,
                              0u);
    munit_assert_true(cep_oid_is_valid(oid));

    munit_assert_true(cep_op_await(oid,
                                   cep_ops_make_dt("ist:unveil"),
                                   0u,
                                   cep_ops_make_dt("op/cont"),
                                   NULL,
                                   0u));
    munit_assert_true(cep_op_state_set(oid, cep_ops_make_dt("ist:unveil"), 0, NULL));
    munit_assert_int(ops_continuation_calls, ==, 0);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_int(ops_continuation_calls, ==, 1);

    test_runtime_shutdown();
}

static void test_ops_ttl_timeout_case(void) {
    ops_runtime_start(false);
    cepDT tmo_signal = cep_ops_make_dt("op/tmo");
    register_enzyme(&tmo_signal, ops_timeout_enzyme);
    ops_timeout_calls = 0;

    cepDT shdn = cep_ops_make_dt("op/shdn");
    cepDT mode_states = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(shdn,
                              "/ops/ttl",
                              mode_states,
                              NULL,
                              0u,
                              0u);
    munit_assert_true(cep_oid_is_valid(oid));

    munit_assert_true(cep_op_await(oid,
                                   cep_ops_make_dt("ist:ok"),
                                   1u,
                                   cep_ops_make_dt("op/cont"),
                                   NULL,
                                   0u));

    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_int(ops_timeout_calls, ==, 1);

    test_runtime_shutdown();
}

static void test_ops_terminal_guard_case(void) {
    ops_runtime_start(false);

    cepDT move = cep_ops_make_dt("op/move");
    cepDT mode_states = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(move,
                              "/ops/close",
                              mode_states,
                              NULL,
                              0u,
                              0u);
    munit_assert_true(cep_oid_is_valid(oid));
    munit_assert_true(cep_op_close(oid, cep_ops_make_dt("sts:ok"), NULL, 0u));
    munit_assert_false(cep_op_state_set(oid, cep_ops_make_dt("ist:run"), 0, NULL));

    test_runtime_shutdown();
}

MunitResult test_ops(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    test_ops_direct_close_case();
    test_ops_stateful_history_case();
    test_ops_await_continuation_case();
    test_ops_ttl_timeout_case();
    test_ops_terminal_guard_case();

    return MUNIT_OK;
}
