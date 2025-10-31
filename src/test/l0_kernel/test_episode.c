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

static const cepPath*
episode_make_path(EpisodePathBuf* buf, const char* tag)
{
    buf->length = 1u;
    buf->capacity = cep_lengthof(buf->segments);
    buf->segments[0].dt = cep_ops_make_dt(tag);
    buf->segments[0].timestamp = 0u;
    return (const cepPath*)buf;
}

static void
episode_runtime_start(void)
{
    test_runtime_shutdown();

    munit_assert_true(cep_l0_bootstrap());

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
    (void)cep_heartbeat_rt_root();
    munit_assert_true(cep_namepool_bootstrap());

    cepOID bootstrap = cep_op_start(cep_ops_make_dt("op/probe"),
                                    "/episode/runtime/probe",
                                    cep_ops_make_dt("opm:states"),
                                    NULL,
                                    0u,
                                    0u);
    munit_assert_true(cep_oid_is_valid(bootstrap));
    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    munit_assert_true(cep_op_close(bootstrap, sts_ok, NULL, 0u));
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

typedef struct {
    unsigned calls;
} EpisodeYieldProbe;

static void
episode_yield_slice(cepEID eid, void* ctx)
{
    EpisodeYieldProbe* probe = ctx;
    probe->calls += 1u;
    if (probe->calls == 1u) {
        munit_assert_true(cep_ep_yield(eid, "yield-phase-one"));
        return;
    }

    cepDT ok = cep_ops_make_dt("sts:ok");
    munit_assert_true(cep_ep_close(eid, ok, NULL, 0u));
}

MunitResult
test_episode_yield_resume(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    episode_runtime_start();

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
    munit_assert_uint(probe.calls, ==, 1u);
    munit_assert_size(cep_executor_pending(), ==, 0u);
    munit_assert_size(episode_watcher_count(eid), ==, 0u);

    const cepDT* yielded_state = episode_state(eid);
    munit_assert_not_null(yielded_state);
    cepDT ist_yield = cep_ops_make_dt("ist:yield");
    munit_assert_uint(yielded_state->tag, ==, ist_yield.tag);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_uint(probe.calls, ==, 2u);
    munit_assert_size(cep_executor_pending(), ==, 0u);
    munit_assert_size(episode_watcher_count(eid), ==, 0u);

    const cepDT* state = episode_state(eid);
    munit_assert_not_null(state);
    cepDT ist_ok = cep_ops_make_dt("ist:ok");
    munit_assert_uint(state->tag, ==, ist_ok.tag);

    const cepDT* status = episode_close_status(eid);
    munit_assert_not_null(status);
    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    munit_assert_uint(status->tag, ==, sts_ok.tag);

    test_runtime_shutdown();
    return MUNIT_OK;
}

typedef struct {
    cepOID awaited;
    unsigned calls;
} EpisodeAwaitProbe;

static void
episode_await_slice(cepEID eid, void* ctx)
{
    EpisodeAwaitProbe* probe = ctx;
    probe->calls += 1u;
    if (probe->calls == 1u) {
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
    (void)params;
    (void)user_data_or_fixture;

    episode_runtime_start();

    cepDT verb = cep_ops_make_dt("op/test");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID awaited = cep_op_start(verb, "/episode/await", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(awaited));

    EpisodeAwaitProbe probe = {
        .awaited = awaited,
        .calls = 0u,
    };

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
    munit_assert_uint(probe.calls, ==, 1u);

    const cepDT* awaiting_state = episode_state(eid);
    munit_assert_not_null(awaiting_state);
    cepDT ist_await = cep_ops_make_dt("ist:await");
    munit_assert_uint(awaiting_state->tag, ==, ist_await.tag);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_uint(probe.calls, ==, 1u);

    awaiting_state = episode_state(eid);
    munit_assert_not_null(awaiting_state);
    munit_assert_uint(awaiting_state->tag, ==, ist_await.tag);

    cepDT want = cep_ops_make_dt("ist:ok");
    munit_assert_true(cep_op_state_set(awaited, want, 0, NULL));

    for (unsigned step = 0; step < 3 && probe.calls < 2u; ++step) {
        munit_assert_true(cep_heartbeat_step());
    }
    munit_assert_uint(probe.calls, ==, 2u);

    const cepDT* status = episode_close_status(eid);
    munit_assert_not_null(status);
    cepDT sts_ok = cep_ops_make_dt("sts:ok");
    munit_assert_uint(status->tag, ==, sts_ok.tag);

    test_runtime_shutdown();
    return MUNIT_OK;
}

typedef struct {
    cepOID awaited;
    unsigned calls;
} EpisodeTimeoutProbe;

static void
episode_timeout_slice(cepEID eid, void* ctx)
{
    EpisodeTimeoutProbe* probe = ctx;
    probe->calls += 1u;
    if (probe->calls == 1u) {
        cepDT want = cep_ops_make_dt("ist:ok");
        munit_assert_true(cep_ep_await(eid, probe->awaited, want, 1u, "await-timeout"));
    }
}

MunitResult
test_episode_await_timeout(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    episode_runtime_start();

    cepDT verb = cep_ops_make_dt("op/slow");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID awaited = cep_op_start(verb, "/episode/timeout", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(awaited));

    EpisodeTimeoutProbe probe = {
        .awaited = awaited,
        .calls = 0u,
    };

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

    munit_assert_true(cep_heartbeat_step());
    munit_assert_uint(probe.calls, ==, 1u);

    munit_assert_true(cep_heartbeat_step());
    munit_assert_uint(probe.calls, ==, 1u);

    const cepDT* awaiting_state = episode_state(eid);
    munit_assert_not_null(awaiting_state);
    cepDT ist_await = cep_ops_make_dt("ist:await");
    munit_assert_uint(awaiting_state->tag, ==, ist_await.tag);

    const cepDT* status = NULL;
    for (unsigned step = 0; step < 3 && !status; ++step) {
        munit_assert_true(cep_heartbeat_step());
        status = episode_close_status(eid);
    }
    munit_assert_not_null(status);
    cepDT sts_cnl = cep_ops_make_dt("sts:cnl");
    munit_assert_uint(status->tag, ==, sts_cnl.tag);

    const cepDT* final_state = episode_state(eid);
    munit_assert_not_null(final_state);
    cepDT ist_cxl = cep_ops_make_dt("ist:cxl");
    munit_assert_int(cep_dt_compare(final_state, &ist_cxl), ==, 0);

    test_runtime_shutdown();
    return MUNIT_OK;
}
