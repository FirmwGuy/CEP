/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Episodic engine tests covering dossier creation, yields, awaits, and timeouts. */

#include "test.h"

#include "cep_ep.h"
#include "cep_ops.h"
#include "cep_namepool.h"
#include "cep_l0.h"
#include "cep_executor.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[4];
} EpisodePathBuf;

typedef struct {
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} EpisodeRuntimeScope;

static const cepPath*
episode_make_path(EpisodePathBuf* buf, const char* tag)
{
    buf->length = 1u;
    buf->capacity = cep_lengthof(buf->segments);
    buf->segments[0].dt = cep_ops_make_dt(tag);
    buf->segments[0].timestamp = 0u;
    return (const cepPath*)buf;
}

static EpisodeRuntimeScope
episode_runtime_start(void)
{
    test_runtime_shutdown();

    EpisodeRuntimeScope scope = {
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
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
    (void)cep_heartbeat_rt_root();

    cepOID bootstrap = cep_op_start(cep_ops_make_dt("op/probe"),
                                    "/episode/runtime/probe",
                                    cep_ops_make_dt("opm:states"),
                                    NULL,
                                    0u,
                                    0u);
    munit_assert_true(cep_oid_is_valid(bootstrap));
    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    munit_assert_true(cep_op_close(bootstrap, sts_ok, NULL, 0u));
    return scope;
}

static void
episode_runtime_cleanup(EpisodeRuntimeScope* scope)
{
    if (!scope || !scope->runtime) {
        return;
    }
    cep_runtime_set_active(scope->runtime);
    cep_stream_clear_pending();
    cep_runtime_shutdown(scope->runtime);
    cep_runtime_restore_active(scope->previous_runtime);
    cep_runtime_destroy(scope->runtime);
    scope->runtime = NULL;
    scope->previous_runtime = NULL;
}

static cepCell*
episode_lookup_cell(cepOID eid)
{
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);

    cepDT ops_name = cep_ops_make_dt("ops");
    cepCell* ops_root = cep_cell_find_by_name(rt_root, &ops_name);
    munit_assert_not_null(ops_root);

    cepDT lookup = {
        .domain = eid.domain,
        .tag = eid.tag,
    };
    return cep_cell_find_by_name(ops_root, &lookup);
}

static const cepDT*
episode_state(cepOID eid)
{
    cepCell* op_cell = episode_lookup_cell(eid);
    munit_assert_not_null(op_cell);

    cepDT state_name = cep_ops_make_dt("state");
    cepCell* state_cell = cep_cell_find_by_name(op_cell, &state_name);
    munit_assert_not_null(state_cell);
    return cep_cell_data(state_cell);
}

static const cepDT*
episode_close_status(cepOID eid)
{
    cepCell* op_cell = episode_lookup_cell(eid);
    munit_assert_not_null(op_cell);

    cepDT close_name = cep_ops_make_dt("close");
    cepCell* close_cell = cep_cell_find_by_name(op_cell, &close_name);
    if (!close_cell) {
        return NULL;
    }

    cepDT status_name = cep_ops_make_dt("status");
    cepCell* status_cell = cep_cell_find_by_name(close_cell, &status_name);
    if (!status_cell) {
        return NULL;
    }
    return cep_cell_data(status_cell);
}

static cepCell*
episode_metadata_root(cepOID eid)
{
    cepCell* op_cell = episode_lookup_cell(eid);
    munit_assert_not_null(op_cell);

    cepCell* episode = cep_cell_find_by_name(op_cell, CEP_DTAW("CEP", "episode"));
    munit_assert_not_null(episode);
    episode = cep_cell_resolve(episode);
    munit_assert_not_null(episode);
    return episode;
}

static const char*
episode_metadata_text(cepOID eid, const char* field_tag)
{
    cepCell* episode = episode_metadata_root(eid);
    cepDT field = cep_ops_make_dt(field_tag);
    cepCell* node = cep_cell_find_by_name(episode, &field);
    if (!node) {
        return NULL;
    }
    return (const char*)cep_cell_data(node);
}

static uint64_t
episode_metadata_u64(cepOID eid, const char* field_tag)
{
    cepCell* episode = episode_metadata_root(eid);
    cepDT field = cep_ops_make_dt(field_tag);
    cepCell* node = cep_cell_find_by_name(episode, &field);
    if (!node) {
        return 0u;
    }
    const char* value_text = (const char*)cep_cell_data(node);
    if (!value_text) {
        return 0u;
    }
    return (uint64_t)strtoull(value_text, NULL, 10);
}

static size_t
episode_watcher_count(cepOID eid)
{
    cepCell* op_cell = episode_lookup_cell(eid);
    munit_assert_not_null(op_cell);

    cepDT watchers_name = cep_ops_make_dt("watchers");
    cepCell* watchers = cep_cell_find_by_name(op_cell, &watchers_name);
    if (!watchers) {
        return 0u;
    }
    watchers = cep_cell_resolve(watchers);
    if (!watchers) {
        return 0u;
    }

    size_t count = 0u;
    for (cepCell* entry = cep_cell_first_all(watchers); entry; entry = cep_cell_next_all(watchers, entry)) {
        count += 1u;
    }
    return count;
}

static void
episode_wait_for_calls(atomic_uint* counter, unsigned target)
{
    munit_assert_true(test_executor_wait_for_calls(counter, target, 1024));
}

static bool
episode_wait_for_state(cepEID eid, cepDT desired, unsigned spins)
{
    for (unsigned i = 0; i < spins; ++i) {
        const cepDT* current = episode_state(eid);
        if (current && current->tag == desired.tag) {
            return true;
        }
        test_executor_relax();
    }
    const cepDT* current = episode_state(eid);
    return current && current->tag == desired.tag;
}

typedef struct {
    atomic_uint calls;
} EpisodeYieldProbe;

static void
episode_yield_slice(cepEID eid, void* ctx)
{
    EpisodeYieldProbe* probe = ctx;
    unsigned count = atomic_fetch_add_explicit(&probe->calls, 1u, memory_order_relaxed) + 1u;
    if (count == 1u) {
        munit_assert_true(cep_ep_yield(eid, "yield-phase-one"));
        return;
    }

    cepDT ok = cep_ops_make_dt("sts:ok");
    munit_assert_true(cep_ep_close(eid, ok, NULL, 0u));
}

MunitResult
test_episode_yield_resume(const MunitParameter params[], void* user_data_or_fixture)
{
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    (void)params;
    (void)user_data_or_fixture;
    return MUNIT_SKIP;
#endif
    (void)params;
    (void)user_data_or_fixture;

    EpisodeRuntimeScope scope = episode_runtime_start();

    EpisodePathBuf signal_buf = {0};
    EpisodePathBuf target_buf = {0};
    const cepPath* signal_path = episode_make_path(&signal_buf, "sig:episode");
    const cepPath* target_path = episode_make_path(&target_buf, "rt:episode");

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    EpisodeYieldProbe probe = {0};
    atomic_init(&probe.calls, 0u);
    cepEID eid = cep_oid_invalid();
    bool started = cep_ep_start(&eid,
                                signal_path,
                                target_path,
                                episode_yield_slice,
                                &probe,
                                &policy,
                                0u);
    if (!started) {
        munit_logf(MUNIT_LOG_ERROR,
                   "cep_ep_start failed err=%d",
                   cep_ops_debug_last_error());
    }
    munit_assert_true(started);
    munit_assert_true(cep_oid_is_valid(eid));

    const char* profile_text = episode_metadata_text(eid, "profile");
    munit_assert_not_null(profile_text);
    munit_assert_string_equal(profile_text, "ep:pro/ro");

    munit_assert_uint64(episode_metadata_u64(eid, "bud_cpu_ns"),
                        ==,
                        CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS);
    munit_assert_uint64(episode_metadata_u64(eid, "bud_io_by"),
                        ==,
                        CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES);

    const char* recorded_signal = episode_metadata_text(eid, "sig_path");
    munit_assert_not_null(recorded_signal);
    munit_assert_string_equal(recorded_signal, "/CEP:sig:episode");

    const char* recorded_target = episode_metadata_text(eid, "tgt_path");
   munit_assert_not_null(recorded_target);
   munit_assert_string_equal(recorded_target, "/CEP:rt:episode");

    munit_assert_true(cep_heartbeat_step());
    episode_wait_for_calls(&probe.calls, 1u);
    unsigned first_calls = atomic_load_explicit(&probe.calls, memory_order_relaxed);
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    munit_assert_true(first_calls >= 1u);
#else
    munit_assert_uint(first_calls, ==, 1u);
    munit_assert_size(episode_watcher_count(eid), ==, 0u);

    const cepDT* yielded_state = episode_state(eid);
    munit_assert_not_null(yielded_state);
    cepDT ist_yield = cep_ops_make_dt("ist:yield");
    munit_assert_uint(yielded_state->tag, ==, ist_yield.tag);
#endif

    munit_assert_true(cep_heartbeat_step());
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    munit_assert_true(test_executor_wait_until_empty(128));
#else
    episode_wait_for_calls(&probe.calls, 2u);
    munit_assert_true(test_executor_wait_until_empty(128));
    munit_assert_uint(atomic_load_explicit(&probe.calls, memory_order_relaxed), ==, 2u);
    munit_assert_size(episode_watcher_count(eid), ==, 0u);
#endif

    cepDT ist_ok = cep_ops_make_dt("ist:ok");
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    munit_assert_true(episode_wait_for_state(eid, ist_ok, 2048));
#endif
    const cepDT* state = episode_state(eid);
    munit_assert_not_null(state);
    munit_assert_uint(state->tag, ==, ist_ok.tag);

    const cepDT* status = episode_close_status(eid);
    munit_assert_not_null(status);
    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    munit_assert_uint(status->tag, ==, sts_ok.tag);

    episode_runtime_cleanup(&scope);
    return MUNIT_OK;
}

typedef struct {
    cepOID      awaited;
    atomic_uint calls;
} EpisodeAwaitProbe;

static void
episode_await_slice(cepEID eid, void* ctx)
{
    EpisodeAwaitProbe* probe = ctx;
    unsigned count = atomic_fetch_add_explicit(&probe->calls, 1u, memory_order_relaxed) + 1u;
    if (count == 1u) {
        cepDT want = cep_ops_make_dt("ist:ok");
        munit_assert_true(cep_ep_await(eid, probe->awaited, want, 0u, "await-signal"));
        return;
    }

    cepDT ok = cep_ops_make_dt("sts:ok");
    munit_assert_true(cep_ep_close(eid, ok, NULL, 0u));
}

MunitResult
test_episode_await_resume(const MunitParameter params[], void* user_data_or_fixture)
{
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    (void)params;
    (void)user_data_or_fixture;
    return MUNIT_SKIP;
#endif
    (void)params;
    (void)user_data_or_fixture;

    EpisodeRuntimeScope scope = episode_runtime_start();

    cepDT verb = cep_ops_make_dt("op/test");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID awaited = cep_op_start(verb, "/episode/await", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(awaited));

    EpisodeAwaitProbe probe = {
        .awaited = awaited,
    };
    atomic_init(&probe.calls, 0u);

    EpisodePathBuf signal_buf = {0};
    EpisodePathBuf target_buf = {0};
    const cepPath* signal_path = episode_make_path(&signal_buf, "sig:episode/wait");
    const cepPath* target_path = episode_make_path(&target_buf, "rt:episode/wait");

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepEID eid = cep_oid_invalid();
    bool started = cep_ep_start(&eid,
                                signal_path,
                                target_path,
                                episode_await_slice,
                                &probe,
                                &policy,
                                0u);
    if (!started) {
        munit_logf(MUNIT_LOG_ERROR,
                   "cep_ep_start failed err=%d",
                   cep_ops_debug_last_error());
    }
    munit_assert_true(started);

    munit_assert_true(cep_heartbeat_step());
    episode_wait_for_calls(&probe.calls, 1u);
    unsigned await_calls = atomic_load_explicit(&probe.calls, memory_order_relaxed);
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    munit_assert_true(await_calls >= 1u);
#else
    munit_assert_uint(await_calls, ==, 1u);
    const cepDT* awaiting_state = episode_state(eid);
    munit_assert_not_null(awaiting_state);
    cepDT ist_await = cep_ops_make_dt("ist:await");
    munit_assert_uint(awaiting_state->tag, ==, ist_await.tag);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_uint(atomic_load_explicit(&probe.calls, memory_order_relaxed), ==, 1u);

    awaiting_state = episode_state(eid);
    munit_assert_not_null(awaiting_state);
    munit_assert_uint(awaiting_state->tag, ==, ist_await.tag);
#endif

    cepDT want = cep_ops_make_dt("ist:ok");
    munit_assert_true(cep_op_state_set(awaited, want, 0, NULL));

    for (unsigned step = 0; step < 3 && atomic_load_explicit(&probe.calls, memory_order_relaxed) < 2u; ++step) {
        munit_assert_true(cep_heartbeat_step());
        test_executor_relax();
    }
    munit_assert_uint(atomic_load_explicit(&probe.calls, memory_order_relaxed), ==, 2u);
    munit_assert_true(test_executor_wait_until_empty(128));

    const cepDT* status = episode_close_status(eid);
    munit_assert_not_null(status);
    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    munit_assert_uint(status->tag, ==, sts_ok.tag);

    episode_runtime_cleanup(&scope);
    return MUNIT_OK;
}

typedef struct {
    cepOID      awaited;
    atomic_uint calls;
} EpisodeTimeoutProbe;

typedef struct {
    cepCell*     target;
    cepPath*     lease_path;
    atomic_bool  first_mutation_denied;
    atomic_bool  second_mutation_allowed;
    atomic_bool  third_mutation_denied;
} EpisodeLeaseProbe;

typedef struct {
    cepCell*    target;
    cepPath*    lease_path;
    atomic_bool initial_write_ok;
    atomic_bool resume_ok;
    atomic_bool resumed_write_ok;
    atomic_bool post_release_denied;
} EpisodeSuspendProbe;

typedef struct {
    cepCell*    target;
    cepPath*    lease_path;
    atomic_uint slice_index;
    atomic_bool saw_ro_entry;
    atomic_bool saw_rw_slice;
    atomic_bool saw_final_ro;
} EpisodeHybridProbe;

static void
episode_timeout_slice(cepEID eid, void* ctx)
{
    EpisodeTimeoutProbe* probe = ctx;
    unsigned count = atomic_fetch_add_explicit(&probe->calls, 1u, memory_order_relaxed) + 1u;
    if (count == 1u) {
        cepDT want = cep_ops_make_dt("ist:ok");
        munit_assert_true(cep_ep_await(eid, probe->awaited, want, 1u, "await-timeout"));
    }
}

static void
episode_lease_slice(cepEID eid, void* ctx)
{
    EpisodeLeaseProbe* probe = ctx;
    cepDT field = cep_ops_make_dt("lease-field");

    bool ok = cep_cell_put_text(probe->target, &field, "no-lease");
    atomic_store_explicit(&probe->first_mutation_denied, !ok, memory_order_relaxed);

    munit_assert_true(cep_ep_request_lease(eid, probe->lease_path, true, false, true));

    ok = cep_cell_put_text(probe->target, &field, "with-lease");
    atomic_store_explicit(&probe->second_mutation_allowed, ok, memory_order_relaxed);

    munit_assert_true(cep_ep_release_lease(eid, probe->lease_path));

    ok = cep_cell_put_text(probe->target, &field, "post-release");
    atomic_store_explicit(&probe->third_mutation_denied, !ok, memory_order_relaxed);

cepDT status = cep_ops_make_dt("sts:ok");
munit_assert_true(cep_ep_close(eid, status, NULL, 0u));
}

static void
episode_hybrid_slice(cepEID eid, void* ctx)
{
    EpisodeHybridProbe* probe = ctx;
    unsigned slice = atomic_fetch_add_explicit(&probe->slice_index, 1u, memory_order_relaxed);

    if (slice == 0u) {
        cepEpLeaseRequest request = {
            .path = probe->lease_path,
            .cell = probe->target,
            .lock_store = true,
            .lock_data = false,
            .include_descendants = false,
        };
        munit_assert_true(cep_ep_promote_to_rw(eid, &request, 1u, CEP_EP_PROMOTE_FLAG_NONE));
        atomic_store_explicit(&probe->saw_ro_entry, true, memory_order_relaxed);
        return;
    }

    if (slice == 1u) {
        atomic_store_explicit(&probe->saw_rw_slice, true, memory_order_relaxed);

        const cepDT* field = CEP_DTAW("CEP", "hyb_mut");
        munit_assert_true(cep_cell_put_text(probe->target, field, "mutated"));

        munit_assert_true(cep_ep_release_lease(eid, probe->lease_path));
        munit_assert_true(cep_ep_demote_to_ro(eid, CEP_EP_DEMOTE_FLAG_NONE));
        return;
    }

    if (slice == 2u) {
        atomic_store_explicit(&probe->saw_final_ro, true, memory_order_relaxed);

        const cepDT* field = CEP_DTAW("CEP", "hyb_fin");
        munit_assert_false(cep_cell_put_text(probe->target, field, "should-fail"));

        cepDT status = cep_ops_make_dt("sts:ok");
        munit_assert_true(cep_ep_close(eid, status, NULL, 0u));
        return;
    }
}

static void
episode_suspend_slice(cepEID eid, void* ctx)
{
    EpisodeSuspendProbe* probe = ctx;

    munit_assert_true(cep_ep_request_lease(eid, probe->lease_path, true, false, true));

    cepDT field = cep_ops_make_dt("lease-field");
    bool ok = cep_cell_put_text(probe->target, &field, "initial");
    atomic_store_explicit(&probe->initial_write_ok, ok, memory_order_relaxed);

    munit_assert_true(cep_ep_suspend_rw(eid, CEP_EP_SUSPEND_DROP_LEASES));

    ok = cep_ep_resume_rw(eid);
    atomic_store_explicit(&probe->resume_ok, ok, memory_order_relaxed);
    if (!ok) {
        return;
    }

    ok = cep_cell_put_text(probe->target, &field, "resumed");
    atomic_store_explicit(&probe->resumed_write_ok, ok, memory_order_relaxed);

    munit_assert_true(cep_ep_release_lease(eid, probe->lease_path));

    ok = cep_cell_put_text(probe->target, &field, "after-release");
    atomic_store_explicit(&probe->post_release_denied, !ok, memory_order_relaxed);

    cepDT status = cep_ops_make_dt("sts:ok");
    munit_assert_true(cep_ep_close(eid, status, NULL, 0u));
}

MunitResult
test_episode_await_timeout(const MunitParameter params[], void* user_data_or_fixture)
{
#if defined(CEP_EXECUTOR_BACKEND_THREADED)
    (void)params;
    (void)user_data_or_fixture;
    return MUNIT_SKIP;
#endif
    (void)params;
    (void)user_data_or_fixture;

    EpisodeRuntimeScope scope = episode_runtime_start();

    cepDT verb = cep_ops_make_dt("op/slow");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID awaited = cep_op_start(verb, "/episode/timeout", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(awaited));

    EpisodeTimeoutProbe probe = {
        .awaited = awaited,
    };
    atomic_init(&probe.calls, 0u);

    EpisodePathBuf signal_buf = {0};
    EpisodePathBuf target_buf = {0};
    const cepPath* signal_path = episode_make_path(&signal_buf, "sig:episode/timeout");
    const cepPath* target_path = episode_make_path(&target_buf, "rt:episode/timeout");

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepEID eid = cep_oid_invalid();
    bool started = cep_ep_start(&eid,
                                signal_path,
                                target_path,
                                episode_timeout_slice,
                                &probe,
                                &policy,
                                0u);
    if (!started) {
        munit_logf(MUNIT_LOG_ERROR,
                   "cep_ep_start failed err=%d",
                   cep_ops_debug_last_error());
    }
    munit_assert_true(started);

    episode_wait_for_calls(&probe.calls, 1u);
    munit_assert_true(test_executor_wait_until_empty(128));

    munit_assert_true(cep_heartbeat_step());
    munit_assert_uint(atomic_load_explicit(&probe.calls, memory_order_relaxed), ==, 1u);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_uint(atomic_load_explicit(&probe.calls, memory_order_relaxed), ==, 1u);

    const cepDT* awaiting_state = episode_state(eid);
    munit_assert_not_null(awaiting_state);
    cepDT ist_await = cep_ops_make_dt("ist:await");
    munit_assert_uint(awaiting_state->tag, ==, ist_await.tag);

    const cepDT* status = NULL;
    for (unsigned step = 0; step < 3 && !status; ++step) {
        munit_assert_true(cep_heartbeat_step());
        test_executor_relax();
        status = episode_close_status(eid);
    }
    munit_assert_not_null(status);
    cepDT sts_cnl = cep_ops_make_dt("sts:cnl");
    munit_assert_uint(status->tag, ==, sts_cnl.tag);

    const cepDT* final_state = episode_state(eid);
    munit_assert_not_null(final_state);
    cepDT ist_cxl = cep_ops_make_dt("ist:cxl");
    munit_assert_int(cep_dt_compare(final_state, &ist_cxl), ==, 0);

    episode_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult
test_episode_lease_enforcement(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    EpisodeRuntimeScope scope = episode_runtime_start();

    cepCell* data_root = cep_cell_ensure_dictionary_child(cep_root(),
                                                          CEP_DTAW("CEP", "data"),
                                                          CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(data_root);
    data_root = cep_cell_resolve(data_root);
    munit_assert_not_null(data_root);

    cepCell* lease_target = cep_cell_ensure_dictionary_child(data_root,
                                                             CEP_DTAW("CEP", "ep_lease"),
                                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(lease_target);
    lease_target = cep_cell_resolve(lease_target);
    munit_assert_not_null(lease_target);

    cepPath* lease_path = NULL;
    munit_assert_true(cep_cell_path(lease_target, &lease_path));
    munit_assert_not_null(lease_path);

    EpisodeLeaseProbe probe = {
        .target = lease_target,
        .lease_path = lease_path,
    };
    atomic_init(&probe.first_mutation_denied, false);
    atomic_init(&probe.second_mutation_allowed, false);
    atomic_init(&probe.third_mutation_denied, false);

    EpisodePathBuf signal_buf = {0};
    EpisodePathBuf target_buf = {0};
    const cepPath* signal_path = episode_make_path(&signal_buf, "sig:episode/lease");
    const cepPath* target_path = episode_make_path(&target_buf, "rt:episode/lease");

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RW,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepEID eid = cep_oid_invalid();
    bool started = cep_ep_start(&eid,
                                signal_path,
                                target_path,
                                episode_lease_slice,
                                &probe,
                                &policy,
                                0u);
    munit_assert_true(started);
    munit_assert_true(cep_oid_is_valid(eid));

    munit_assert_true(test_executor_wait_until_empty(128));
    munit_assert_true(atomic_load_explicit(&probe.first_mutation_denied, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.second_mutation_allowed, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.third_mutation_denied, memory_order_relaxed));

    cep_free(lease_path);
    episode_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult
test_episode_rw_suspend_resume(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    EpisodeRuntimeScope scope = episode_runtime_start();

    cepCell* data_root = cep_cell_ensure_dictionary_child(cep_root(),
                                                          CEP_DTAW("CEP", "data"),
                                                          CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(data_root);
    data_root = cep_cell_resolve(data_root);
    munit_assert_not_null(data_root);

    cepCell* target = cep_cell_ensure_dictionary_child(data_root,
                                                       CEP_DTAW("CEP", "ep_suspend"),
                                                       CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(target);
    target = cep_cell_resolve(target);
    munit_assert_not_null(target);

    cepPath* lease_path = NULL;
    munit_assert_true(cep_cell_path(target, &lease_path));
    munit_assert_not_null(lease_path);

    EpisodeSuspendProbe probe = {
        .target = target,
        .lease_path = lease_path,
    };
    atomic_init(&probe.initial_write_ok, false);
    atomic_init(&probe.resume_ok, false);
    atomic_init(&probe.resumed_write_ok, false);
    atomic_init(&probe.post_release_denied, false);

    EpisodePathBuf signal_buf = {0};
    EpisodePathBuf target_buf = {0};
    const cepPath* signal_path = episode_make_path(&signal_buf, "sig:episode/suspend");
    const cepPath* target_path = episode_make_path(&target_buf, "rt:episode/suspend");

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RW,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepEID eid = cep_oid_invalid();
    bool started = cep_ep_start(&eid,
                                signal_path,
                                target_path,
                                episode_suspend_slice,
                                &probe,
                                &policy,
                                0u);
    munit_assert_true(started);
    munit_assert_true(cep_oid_is_valid(eid));

    munit_assert_true(test_executor_wait_until_empty(128));

    munit_assert_true(atomic_load_explicit(&probe.initial_write_ok, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.resume_ok, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.resumed_write_ok, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.post_release_denied, memory_order_relaxed));

    cep_free(lease_path);
    episode_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult
test_episode_hybrid_promote_demote(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    EpisodeRuntimeScope scope = episode_runtime_start();

    cepCell* data_root = cep_cell_ensure_dictionary_child(cep_root(),
                                                          CEP_DTAW("CEP", "data"),
                                                          CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(data_root);
    data_root = cep_cell_resolve(data_root);
    munit_assert_not_null(data_root);

    cepCell* target = cep_cell_ensure_dictionary_child(data_root,
                                                       CEP_DTAW("CEP", "ep_hybrid"),
                                                       CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(target);
    target = cep_cell_resolve(target);
    munit_assert_not_null(target);

    cepPath* lease_path = NULL;
    munit_assert_true(cep_cell_path(target, &lease_path));
    munit_assert_not_null(lease_path);

    EpisodeHybridProbe probe = {
        .target = target,
        .lease_path = lease_path,
    };
    atomic_init(&probe.slice_index, 0u);
    atomic_init(&probe.saw_ro_entry, false);
    atomic_init(&probe.saw_rw_slice, false);
    atomic_init(&probe.saw_final_ro, false);

    EpisodePathBuf signal_buf = {0};
    EpisodePathBuf target_buf = {0};
    const cepPath* signal_path = episode_make_path(&signal_buf, "sig:episode/hybrid");
    const cepPath* target_path = episode_make_path(&target_buf, "rt:episode/hybrid");

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_HYBRID,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepEID eid = cep_oid_invalid();
    bool started = cep_ep_start(&eid,
                                signal_path,
                                target_path,
                                episode_hybrid_slice,
                                &probe,
                                &policy,
                                0u);
    if (!started) {
        munit_logf(MUNIT_LOG_ERROR,
                   "cep_ep_start failed err=%d",
                   cep_ops_debug_last_error());
    }
    munit_assert_true(started);
    munit_assert_true(cep_oid_is_valid(eid));

    munit_assert_true(test_executor_wait_until_empty(128));
    unsigned observed = atomic_load_explicit(&probe.slice_index, memory_order_relaxed);
    munit_assert_uint(observed, >=, 1u);
    munit_assert_true(atomic_load_explicit(&probe.saw_ro_entry, memory_order_relaxed));

    for (unsigned attempt = 0; attempt < 16 && observed < 2u; ++attempt) {
        munit_assert_true(cep_heartbeat_stage_commit());
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        munit_assert_true(test_executor_wait_until_empty(128));
        observed = atomic_load_explicit(&probe.slice_index, memory_order_relaxed);
    }
    munit_assert_uint(observed, >=, 2u);
    munit_assert_true(atomic_load_explicit(&probe.saw_rw_slice, memory_order_relaxed));

    for (unsigned attempt = 0; attempt < 16 && observed < 3u; ++attempt) {
        munit_assert_true(cep_heartbeat_stage_commit());
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        munit_assert_true(test_executor_wait_until_empty(128));
        observed = atomic_load_explicit(&probe.slice_index, memory_order_relaxed);
    }
    munit_assert_uint(observed, >=, 3u);
    munit_assert_true(atomic_load_explicit(&probe.saw_final_ro, memory_order_relaxed));

    const cepDT* status = NULL;
    for (unsigned step = 0; step < 4 && !status; ++step) {
        munit_assert_true(cep_heartbeat_step());
        test_executor_relax();
        status = episode_close_status(eid);
    }
    munit_assert_not_null(status);
    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    munit_assert_uint(status->tag, ==, sts_ok.tag);

    cep_free(lease_path);
    episode_runtime_cleanup(&scope);
    return MUNIT_OK;
}
