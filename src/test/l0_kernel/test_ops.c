/* Exercises the OPS/STATES API surface so operations can start, advance
   through state transitions, trigger continuations, honour TTL expiries, and
   reject post-close mutations. */

#include "test.h"

#include "cep_ops.h"
#include "cep_enzyme.h"
#include "cep_namepool.h"

#include <string.h>
#include <stdio.h>

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

typedef struct {
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} OpsRuntimeScope;

static OpsRuntimeScope ops_runtime_start(bool ensure_dirs) {
    OpsRuntimeScope scope = {
        .runtime = cep_runtime_create(),
        .previous_runtime = NULL,
    };
    munit_assert_not_null(scope.runtime);
    scope.previous_runtime = cep_runtime_set_active(scope.runtime);
    cep_cell_system_initiate();
    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_namepool_bootstrap());
    munit_assert_true(cep_runtime_attach_metadata(scope.runtime));

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = ensure_dirs,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());

    (void)cep_heartbeat_rt_root();
    printf("[instrument][test] ops_runtime_start runtime=%p previous=%p ensure_dirs=%d\n",
           (void*)scope.runtime,
           (void*)scope.previous_runtime,
           ensure_dirs ? 1 : 0);
    fflush(stdout);
    return scope;
}

static void ops_runtime_cleanup(OpsRuntimeScope* scope) {
    if (!scope || !scope->runtime) {
        return;
    }
    printf("[instrument][test] ops_runtime_cleanup runtime=%p previous=%p\n",
           (void*)scope->runtime,
           (void*)scope->previous_runtime);
    fflush(stdout);
    cep_runtime_set_active(scope->runtime);
    cep_stream_clear_pending();
    cep_runtime_shutdown(scope->runtime);
    cep_runtime_restore_active(scope->previous_runtime);
    cep_runtime_destroy(scope->runtime);
    scope->runtime = NULL;
    scope->previous_runtime = NULL;
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

static bool ops_child_bool(cepCell* parent, const char* field) {
    cepDT name = cep_ops_make_dt(field);
    cepCell* leaf = cep_cell_find_by_name(parent, &name);
    munit_assert_not_null(leaf);
    const bool* payload = cep_cell_data(leaf);
    munit_assert_not_null(payload);
    return *payload;
}

static uint64_t ops_child_u64(cepCell* parent, const char* field) {
    cepDT name = cep_ops_make_dt(field);
    cepCell* leaf = cep_cell_find_by_name(parent, &name);
    munit_assert_not_null(leaf);
    const uint64_t* payload = cep_cell_data(leaf);
    munit_assert_not_null(payload);
    return *payload;
}

static void test_ops_direct_close_case(void) {
    OpsRuntimeScope scope = ops_runtime_start(false);

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepDT ops_name = cep_ops_make_dt("ops");
    munit_assert_not_null(cep_cell_ensure_dictionary_child(rt_root, &ops_name, CEP_STORAGE_RED_BLACK_T));

    cepDT verb = cep_ops_make_dt("op/ct");
    cepDT mode = cep_ops_make_dt("opm:direct");
    cepOID oid = cep_op_start(verb, "/tmp/direct", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(oid));

    cepCell* op_cell = ops_lookup_cell(oid);
    munit_assert_not_null(op_cell);

    cepDT envelope_name = cep_ops_make_dt("envelope");
    cepCell* envelope = cep_cell_find_by_name(op_cell, &envelope_name);
    munit_assert_not_null(envelope);
    munit_assert_true(cep_cell_is_immutable(envelope));

    cepDT history_name = cep_ops_make_dt("history");
    cepCell* history = cep_cell_find_by_name(op_cell, &history_name);
    munit_assert_not_null(history);

    cepDT watchers_name = cep_ops_make_dt("watchers");
    cepCell* watchers = cep_cell_find_by_name(op_cell, &watchers_name);
    munit_assert_not_null(watchers);
    size_t watcher_count = (watchers->store) ? watchers->store->chdCount : 0u;
    munit_assert_size(watcher_count, ==, 0u);

    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    bool closed = cep_op_close(oid, sts_ok, NULL, 0u);
    if (!closed) {
        munit_logf(MUNIT_LOG_ERROR, "close failed err=%d", cep_ops_debug_last_error());
    }
    munit_assert_true(closed);

    cepDT state_name = cep_ops_make_dt("state");
    cepCell* state_cell = cep_cell_find_by_name(op_cell, &state_name);
    munit_assert_not_null(state_cell);
    const cepDT* state_value = cep_cell_data(state_cell);
    munit_assert_not_null(state_value);
    cepDT ist_ok = cep_ops_make_dt("ist:ok");
    munit_assert_int(cep_dt_compare(state_value, &ist_ok), ==, 0);

    cepDT close_name = cep_ops_make_dt("close");
    cepCell* close_branch = cep_cell_find_by_name(op_cell, &close_name);
    munit_assert_not_null(close_branch);
    munit_assert_true(cep_cell_is_immutable(close_branch));

    ops_runtime_cleanup(&scope);
}

static void test_ops_stateful_history_case(void) {
    OpsRuntimeScope scope = ops_runtime_start(false);

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

    ops_runtime_cleanup(&scope);
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
    munit_assert_size(cep_enzyme_registry_size(registry), >=, 1u);

}

static void unregister_enzyme(const cepDT* signal_dt, cepEnzyme callback) {
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

    munit_assert_int(cep_enzyme_unregister(registry, query, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
}

static void test_ops_await_continuation_case(void) {
    OpsRuntimeScope scope = ops_runtime_start(false);
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

    cepCell* op_cell = ops_lookup_cell(oid);
    munit_assert_not_null(op_cell);
    munit_assert_int(cep_cell_bind_enzyme(op_cell, &cont_signal, false), ==, CEP_ENZYME_SUCCESS);
    cepDT watchers_name = cep_ops_make_dt("watchers");
    cepCell* watchers = cep_cell_find_by_name(op_cell, &watchers_name);
    munit_assert_not_null(watchers);
    cepCell* watcher_entry = cep_cell_first_all(watchers);
    munit_assert_not_null(watcher_entry);
    munit_assert_false(ops_child_bool(watcher_entry, "armed"));

    munit_assert_true(cep_op_state_set(oid, cep_ops_make_dt("ist:unveil"), 0, NULL));
    watcher_entry = cep_cell_first_all(watchers);
    munit_assert_not_null(watcher_entry);
    munit_assert_true(ops_child_bool(watcher_entry, "armed"));
    munit_assert_int(ops_continuation_calls, ==, 0);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_int(ops_continuation_calls, ==, 1);
    munit_assert_null(cep_cell_first_all(watchers));

    munit_assert_int(cep_cell_unbind_enzyme(op_cell, &cont_signal), ==, CEP_ENZYME_SUCCESS);
    unregister_enzyme(&cont_signal, ops_cont_enzyme);

    ops_runtime_cleanup(&scope);
}

static void test_ops_ttl_timeout_case(void) {
    OpsRuntimeScope scope = ops_runtime_start(false);
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

    cepCell* op_cell = ops_lookup_cell(oid);
    munit_assert_not_null(op_cell);
    cepDT watchers_name = cep_ops_make_dt("watchers");
    cepCell* watchers = cep_cell_find_by_name(op_cell, &watchers_name);
    munit_assert_not_null(watchers);
    munit_assert_int(cep_cell_bind_enzyme(op_cell, &tmo_signal, false), ==, CEP_ENZYME_SUCCESS);
    cepCell* watcher_entry = cep_cell_first_all(watchers);
    munit_assert_not_null(watcher_entry);
    munit_assert_false(ops_child_bool(watcher_entry, "armed"));
    uint64_t deadline = ops_child_u64(watcher_entry, "deadline");
    munit_assert_uint(deadline, ==, 1u);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_int(ops_timeout_calls, ==, 1);
    munit_assert_null(cep_cell_first_all(watchers));

    munit_assert_int(cep_cell_unbind_enzyme(op_cell, &tmo_signal), ==, CEP_ENZYME_SUCCESS);
    unregister_enzyme(&tmo_signal, ops_timeout_enzyme);

    ops_runtime_cleanup(&scope);
}

static void test_ops_terminal_guard_case(void) {
    OpsRuntimeScope scope = ops_runtime_start(false);

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

    ops_runtime_cleanup(&scope);
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
