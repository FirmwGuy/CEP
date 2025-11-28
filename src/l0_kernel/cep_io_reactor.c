/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cep_io_reactor.h"

#include "cep_runtime.h"
#include "cep_cell.h"
#include "cep_ops.h"
#include "cep_cei.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>

#if defined(CEP_IO_REACTOR_HAS_EPOLL)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif

#define CEP_IO_REACTOR_WORKER_COUNT        2u
#define CEP_IO_REACTOR_COMPLETION_CAPACITY 256u
#define CEP_IO_REACTOR_BACKEND_ENV         "CEP_IO_REACTOR_BACKEND"

#if defined(CEP_IO_REACTOR_HAS_EPOLL)
#define CEP_IO_REACTOR_EPOLL_MAX_EVENTS 32
#endif

typedef struct cepIoReactorJob {
    cepIoReactorWork       work;
    cepBeatNumber          enqueue_beat;
    cepBeatNumber          deadline_beat;
    bool                   has_deadline;
    bool                   timed_out;
    uint64_t               bytes_expected;
    bool                   has_bytes_expected;
    struct cepIoReactorJob* next_pending;
    struct cepIoReactorJob* next_active;
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    bool                   native_registered;
#endif
} cepIoReactorJob;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    cepIoReactorJob* pending_head;
    cepIoReactorJob* pending_tail;
    cepIoReactorJob* active_head;
    cepIoReactorCompletion completions[CEP_IO_REACTOR_COMPLETION_CAPACITY];
    size_t          completion_head;
    size_t          completion_tail;
    size_t          completion_count;
    pthread_t       workers[CEP_IO_REACTOR_WORKER_COUNT];
    bool            workers_started;
    bool            shutting_down;
    bool            draining;
    cepBeatNumber   current_beat;
    size_t          pending_count;
    size_t          active_count;
    uint64_t        pending_bytes;
    uint64_t        jobs_queued;
    uint64_t        jobs_completed;
    uint64_t        jobs_timed_out;
    uint64_t        completions_this_beat;
    cepCell*        analytics_root;
    cepIoReactorBackendKind backend_kind;
    bool            backend_initialized;
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    int             epoll_fd;
    int             epoll_wake_fd;
    pthread_t       epoll_thread;
    bool            epoll_thread_started;
#endif
} cepIoReactorState;

static cepIoReactorState* g_io_reactor = NULL;
static bool g_io_reactor_trace_cache = false;
static bool g_io_reactor_trace_enabled = false;

static void cep_io_reactor_decrement_pending_bytes(cepIoReactorState* state, uint64_t amount);
static bool cep_io_reactor_completion_enqueue_locked(cepIoReactorState* state,
                                                     const cepIoReactorCompletion* completion);
static bool cep_io_reactor_remove_active_locked(cepIoReactorState* state, cepIoReactorJob* target);
static void cep_io_reactor_timeout_job_locked(cepIoReactorState* state, cepIoReactorJob* job);

#if defined(CEP_IO_REACTOR_HAS_EPOLL)
static bool cep_io_reactor_epoll_setup(cepIoReactorState* state);
static void cep_io_reactor_epoll_teardown(cepIoReactorState* state);
static void* cep_io_reactor_epoll_thread(void* arg);
static bool cep_io_reactor_register_native_locked(cepIoReactorState* state, cepIoReactorJob* job);
static void cep_io_reactor_deregister_native_locked(cepIoReactorState* state, cepIoReactorJob* job);
static void cep_io_reactor_epoll_wake(cepIoReactorState* state);
#endif

static bool
cep_io_reactor_trace(void)
{
    if (!g_io_reactor_trace_cache) {
        const char* env = getenv("CEP_IO_REACTOR_TRACE");
        g_io_reactor_trace_enabled = env && *env && env[0] != '0';
        g_io_reactor_trace_cache = true;
    }
    return g_io_reactor_trace_enabled;
}

static bool
cep_io_reactor_epoll_supported(void)
{
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    return true;
#else
    return false;
#endif
}

static bool
cep_io_reactor_streq_icase(const char* lhs, const char* rhs)
{
    if (!lhs || !rhs) {
        return false;
    }
    while (*lhs && *rhs) {
        if (tolower((unsigned char)*lhs) != tolower((unsigned char)*rhs)) {
            return false;
        }
        lhs += 1;
        rhs += 1;
    }
    return *lhs == '\0' && *rhs == '\0';
}

static cepIoReactorBackendKind
cep_io_reactor_backend_default_kind(void)
{
#if defined(CEP_IO_REACTOR_BACKEND_DEFAULT_EPOLL)
    return CEP_IO_REACTOR_BACKEND_EPOLL;
#else
    return CEP_IO_REACTOR_BACKEND_PORTABLE;
#endif
}

static cepIoReactorBackendKind
cep_io_reactor_backend_preference(void)
{
    static bool cached = false;
    static cepIoReactorBackendKind cached_kind = CEP_IO_REACTOR_BACKEND_PORTABLE;
    if (cached) {
        return cached_kind;
    }
    cached_kind = cep_io_reactor_backend_default_kind();
    const char* env = getenv(CEP_IO_REACTOR_BACKEND_ENV);
    if (env && *env) {
        if (cep_io_reactor_streq_icase(env, "portable") ||
            cep_io_reactor_streq_icase(env, "shim") ||
            cep_io_reactor_streq_icase(env, "threaded")) {
            cached_kind = CEP_IO_REACTOR_BACKEND_PORTABLE;
        } else if (cep_io_reactor_streq_icase(env, "epoll") ||
                   cep_io_reactor_streq_icase(env, "native")) {
            cached_kind = CEP_IO_REACTOR_BACKEND_EPOLL;
        } else if (cep_io_reactor_streq_icase(env, "auto")) {
            cached_kind = cep_io_reactor_backend_default_kind();
        }
    }
    if (cached_kind == CEP_IO_REACTOR_BACKEND_EPOLL && !cep_io_reactor_epoll_supported()) {
        cached_kind = CEP_IO_REACTOR_BACKEND_PORTABLE;
    }
    cached = true;
    return cached_kind;
}

static bool
cep_io_reactor_job_used_shim(const cepIoReactorState* state, const cepIoReactorJob* job)
{
    if (!state || !job) {
        return true;
    }
    if (job->work.kind == CEP_IO_REACTOR_WORK_KIND_NATIVE_FD) {
        return false;
    }
    if (job->work.shim_fallback) {
        return true;
    }
    return state->backend_kind == CEP_IO_REACTOR_BACKEND_PORTABLE;
}

static bool
cep_io_reactor_state_init_backend(cepIoReactorState* state)
{
    if (!state) {
        return false;
    }
    if (state->backend_initialized) {
        return true;
    }
    state->backend_kind = cep_io_reactor_backend_preference();
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    if (state->backend_kind == CEP_IO_REACTOR_BACKEND_EPOLL) {
        if (!cep_io_reactor_epoll_supported() || !cep_io_reactor_epoll_setup(state)) {
            state->backend_kind = CEP_IO_REACTOR_BACKEND_PORTABLE;
        }
    }
#else
    state->backend_kind = CEP_IO_REACTOR_BACKEND_PORTABLE;
#endif
    state->backend_initialized = true;
    return true;
}

static void
cep_io_reactor_finalize_completion_locked(cepIoReactorState* state,
                                          cepIoReactorJob* job,
                                          bool job_ok,
                                          const cepIoReactorResult* result)
{
    if (!state || !job || job->timed_out) {
        return;
    }
    uint64_t bytes_done = result ? result->bytes_done : 0u;
    bool has_bytes_done = result ? result->bytes_done > 0u : false;
    if (!has_bytes_done && job->has_bytes_expected) {
        bytes_done = job->bytes_expected;
        has_bytes_done = job->has_bytes_expected;
    }
    if (has_bytes_done) {
        cep_io_reactor_decrement_pending_bytes(state, bytes_done);
        job->has_bytes_expected = false;
    }
    int completion_error = job_ok ? 0 : ((result && result->error_code) ? result->error_code : -EIO);
    cepIoReactorCompletion completion = {
        .owner = job->work.owner,
        .request_name = job->work.request_name,
        .info = job_ok ? job->work.success_info : job->work.failure_info,
        .timed_out = false,
        .shim_fallback = cep_io_reactor_job_used_shim(state, job),
        .timeout_topic = job->work.timeout_topic,
        .has_timeout_topic = job->work.has_timeout_topic,
        .on_complete = job->work.on_complete,
        .on_complete_context = job->work.on_complete_context,
        .bytes_done = bytes_done,
        .has_bytes_done = has_bytes_done,
        .has_result = true,
        .result = {
            .success = job_ok,
            .bytes_done = job_ok ? bytes_done : 0u,
            .error_code = job_ok ? 0 : completion_error,
        },
    };
    if (has_bytes_done) {
        completion.info.has_bytes_done = true;
        completion.info.bytes_done = bytes_done;
    }
    if (!job_ok) {
        completion.info.has_errno = true;
        completion.info.errno_code = completion_error;
    }
    if (!cep_io_reactor_completion_enqueue_locked(state, &completion)) {
        CEP_DEBUG_PRINTF("[io_reactor] completion queue full\n");
    } else {
        state->jobs_completed += 1u;
    }
}

#if defined(CEP_IO_REACTOR_HAS_EPOLL)
static bool
cep_io_reactor_epoll_setup(cepIoReactorState* state)
{
    if (!state) {
        return false;
    }
    if (state->epoll_fd >= 0 && state->epoll_wake_fd >= 0) {
        return true;
    }
    state->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (state->epoll_fd < 0) {
        return false;
    }
    state->epoll_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (state->epoll_wake_fd < 0) {
        close(state->epoll_fd);
        state->epoll_fd = -1;
        return false;
    }
    struct epoll_event wake_event = {
        .events = EPOLLIN,
        .data.ptr = NULL,
    };
    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->epoll_wake_fd, &wake_event) != 0) {
        close(state->epoll_wake_fd);
        close(state->epoll_fd);
        state->epoll_wake_fd = -1;
        state->epoll_fd = -1;
        return false;
    }
    return true;
}

static void
cep_io_reactor_epoll_teardown(cepIoReactorState* state)
{
    if (!state) {
        return;
    }
    if (state->epoll_fd >= 0) {
        close(state->epoll_fd);
        state->epoll_fd = -1;
    }
    if (state->epoll_wake_fd >= 0) {
        close(state->epoll_wake_fd);
        state->epoll_wake_fd = -1;
    }
}

static void
cep_io_reactor_epoll_wake(cepIoReactorState* state)
{
    if (!state || state->epoll_wake_fd < 0) {
        return;
    }
    uint64_t one = 1u;
    ssize_t wrote = write(state->epoll_wake_fd, &one, sizeof one);
    (void)wrote;
}

static void
cep_io_reactor_deregister_native_locked(cepIoReactorState* state, cepIoReactorJob* job)
{
    if (!state || !job || !job->native_registered) {
        return;
    }
    if (state->epoll_fd >= 0 && job->work.native_fd.fd >= 0) {
        (void)epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, job->work.native_fd.fd, NULL);
    }
    job->native_registered = false;
}

static bool
cep_io_reactor_register_native_locked(cepIoReactorState* state, cepIoReactorJob* job)
{
    if (!state || !job) {
        return false;
    }
    if (state->backend_kind != CEP_IO_REACTOR_BACKEND_EPOLL) {
        return false;
    }
    if (job->work.native_fd.fd < 0 || !job->work.native_fd.handler) {
        return false;
    }
    if (state->epoll_fd < 0 || state->epoll_wake_fd < 0) {
        if (!cep_io_reactor_epoll_setup(state)) {
            return false;
        }
    }
    if (!state->epoll_thread_started) {
        if (pthread_create(&state->epoll_thread, NULL, cep_io_reactor_epoll_thread, state) == 0) {
            state->epoll_thread_started = true;
        } else {
            return false;
        }
    }
    job->next_active = state->active_head;
    state->active_head = job;
    state->active_count += 1u;
    struct epoll_event ev = {
        .events = job->work.native_fd.events ? job->work.native_fd.events : (uint32_t)EPOLLOUT,
        .data.ptr = job,
    };
    if (job->work.native_fd.oneshot || !job->work.native_fd.events) {
        ev.events |= EPOLLONESHOT;
    }
    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, job->work.native_fd.fd, &ev) != 0) {
        cep_io_reactor_remove_active_locked(state, job);
        return false;
    }
    job->native_registered = true;
    if (job->has_bytes_expected) {
        state->pending_bytes += job->bytes_expected;
    }
    state->jobs_queued += 1u;
    return true;
}

static void*
cep_io_reactor_epoll_thread(void* arg)
{
    cepIoReactorState* state = (cepIoReactorState*)arg;
    if (!state) {
        return NULL;
    }
    struct epoll_event events[CEP_IO_REACTOR_EPOLL_MAX_EVENTS];
    while (true) {
        int ready = epoll_wait(state->epoll_fd,
                               events,
                               CEP_IO_REACTOR_EPOLL_MAX_EVENTS,
                               50);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            if (state->shutting_down) {
                break;
            }
            continue;
        }
        for (int i = 0; i < ready; ++i) {
            if (!events[i].data.ptr) {
                uint64_t drained = 0u;
                (void)read(state->epoll_wake_fd, &drained, sizeof drained);
                continue;
            }
            cepIoReactorJob* job = (cepIoReactorJob*)events[i].data.ptr;
            if (!job) {
                continue;
            }
            cepIoReactorResult result = {0};
            bool job_ok = false;
            if (job->work.native_fd.handler) {
                job_ok = job->work.native_fd.handler(job->work.native_fd.fd,
                                                     events[i].events,
                                                     job->work.native_fd.handler_context,
                                                     &result);
            }
            pthread_mutex_lock(&state->lock);
            cep_io_reactor_deregister_native_locked(state, job);
            bool timed_out = job->timed_out;
            cep_io_reactor_remove_active_locked(state, job);
            if (!timed_out) {
                cep_io_reactor_finalize_completion_locked(state, job, job_ok, &result);
            }
            pthread_mutex_unlock(&state->lock);

            if (job->work.native_fd.close_fd && job->work.native_fd.fd >= 0) {
                close(job->work.native_fd.fd);
            }
            if (job->work.destroy) {
                job->work.destroy(job->work.worker_context);
            }
            cep_free(job);
        }
        if (state->shutting_down) {
            break;
        }
    }
    pthread_mutex_lock(&state->lock);
    state->epoll_thread_started = false;
    pthread_mutex_unlock(&state->lock);
    return NULL;
}
#endif

CEP_DEFINE_STATIC_DT(dt_reactor_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_rt_root_name_io, CEP_ACRO("CEP"), CEP_WORD("rt"));
CEP_DEFINE_STATIC_DT(dt_analytics_root_name_io, CEP_ACRO("CEP"), CEP_WORD("analytics"));
CEP_DEFINE_STATIC_DT(dt_async_root_name_io, CEP_ACRO("CEP"), CEP_WORD("async"));
CEP_DEFINE_STATIC_DT(dt_reactor_branch_name, CEP_ACRO("CEP"), CEP_WORD("reactor"));
CEP_DEFINE_STATIC_DT(dt_cq_depth_name, CEP_ACRO("CEP"), CEP_WORD("cq_depth"));
CEP_DEFINE_STATIC_DT(dt_pend_bytes_name, CEP_ACRO("CEP"), CEP_WORD("pend_bytes"));
CEP_DEFINE_STATIC_DT(dt_comp_per_bt_name, CEP_ACRO("CEP"), CEP_WORD("comp_bt"));
CEP_DEFINE_STATIC_DT(dt_timeouts_name, CEP_ACRO("CEP"), CEP_WORD("timeouts"));
CEP_DEFINE_STATIC_DT(dt_jobs_total_name_io, CEP_ACRO("CEP"), CEP_WORD("jobs_total"));
CEP_DEFINE_STATIC_DT(dt_reactor_default_id, CEP_ACRO("CEP"), CEP_WORD("react:io"));

static const cepDT*
cep_io_reactor_default_topic(void)
{
    static cepDT topic = {0};
    if (!cep_dt_is_valid(&topic)) {
        topic = cep_ops_make_dt("persist.async.tmo");
    }
    return &topic;
}

static void
cep_io_reactor_emit_topic(const cepDT* topic, const char* detail)
{
    if (!topic) {
        return;
    }
    cepCeiRequest req = {
        .severity = *dt_reactor_sev_warn(),
        .topic = topic->tag ? (const char*)topic : NULL,
        .topic_len = 0u,
        .topic_intern = true,
        .note = detail,
        .note_len = detail ? 0u : 0u,
        .origin_kind = "cep_io_reactor",
        .emit_signal = false,
        .attach_to_op = false,
        .ttl_forever = true,
    };
    (void)cep_cei_emit(&req);
}

static const cepDT*
cep_io_reactor_tp_async_unsp_topic(void)
{
    static cepDT topic = {0};
    if (!cep_dt_is_valid(&topic)) {
        topic = cep_ops_make_dt("tp_async_unsp");
    }
    return &topic;
}

static cepCell*
cep_io_reactor_ensure_metrics_root(cepIoReactorState* state)
{
    if (!state) {
        return NULL;
    }
    if (state->analytics_root) {
        return state->analytics_root;
    }
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    cepCell* rt = cep_cell_ensure_dictionary_child(root, dt_rt_root_name_io(), CEP_STORAGE_RED_BLACK_T);
    if (!rt) {
        return NULL;
    }
    rt = cep_cell_resolve(rt);
    if (!rt || !cep_cell_require_dictionary_store(&rt)) {
        return NULL;
    }
    cepCell* analytics = cep_cell_ensure_dictionary_child(rt, dt_analytics_root_name_io(), CEP_STORAGE_RED_BLACK_T);
    if (!analytics) {
        return NULL;
    }
    analytics = cep_cell_resolve(analytics);
    if (!analytics || !cep_cell_require_dictionary_store(&analytics)) {
        return NULL;
    }
    cepCell* async_root = cep_cell_ensure_dictionary_child(analytics, dt_async_root_name_io(), CEP_STORAGE_RED_BLACK_T);
    if (!async_root) {
        return NULL;
    }
    async_root = cep_cell_resolve(async_root);
    if (!async_root || !cep_cell_require_dictionary_store(&async_root)) {
        return NULL;
    }
    cepCell* reactor_branch = cep_cell_ensure_dictionary_child(async_root, dt_reactor_branch_name(), CEP_STORAGE_RED_BLACK_T);
    if (!reactor_branch) {
        return NULL;
    }
    reactor_branch = cep_cell_resolve(reactor_branch);
    if (!reactor_branch || !cep_cell_require_dictionary_store(&reactor_branch)) {
        return NULL;
    }
    cepCell* entry = cep_cell_ensure_dictionary_child(reactor_branch, dt_reactor_default_id(), CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        return NULL;
    }
    entry = cep_cell_resolve(entry);
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return NULL;
    }
    state->analytics_root = entry;
    return state->analytics_root;
}

static void
cep_io_reactor_publish_metrics_locked(cepIoReactorState* state)
{
    if (!state) {
        return;
    }
    cepCell* metrics_root = cep_io_reactor_ensure_metrics_root(state);
    if (!metrics_root) {
        return;
    }
    uint64_t depth = (uint64_t)(state->pending_count + state->active_count);
    (void)cep_cell_put_uint64(metrics_root, dt_cq_depth_name(), depth);
    (void)cep_cell_put_uint64(metrics_root, dt_pend_bytes_name(), state->pending_bytes);
    (void)cep_cell_put_uint64(metrics_root, dt_comp_per_bt_name(), state->completions_this_beat);
    (void)cep_cell_put_uint64(metrics_root, dt_timeouts_name(), state->jobs_timed_out);
    (void)cep_cell_put_uint64(metrics_root, dt_jobs_total_name_io(), state->jobs_completed);
}

static void
cep_io_reactor_decrement_pending_bytes(cepIoReactorState* state, uint64_t amount)
{
    if (!state || amount == 0u) {
        return;
    }
    if (state->pending_bytes > amount) {
        state->pending_bytes -= amount;
    } else {
        state->pending_bytes = 0u;
    }
}

static void
cep_io_reactor_emit_timeout_cei(const cepIoReactorCompletion* completion)
{
    if (!completion) {
        return;
    }
    const cepDT* topic = completion->has_timeout_topic ? &completion->timeout_topic
                                                       : cep_io_reactor_default_topic();
    cep_io_reactor_emit_topic(topic, "async request timed out");
    if (completion->shim_fallback) {
        cep_io_reactor_emit_topic(cep_io_reactor_tp_async_unsp_topic(), "shim fallback timed out");
    }
}

static bool
cep_io_reactor_completion_enqueue_locked(cepIoReactorState* state,
                                         const cepIoReactorCompletion* completion)
{
    if (!state || !completion) {
        return false;
    }
    if (state->completion_count >= CEP_IO_REACTOR_COMPLETION_CAPACITY) {
        return false;
    }
    state->completions[state->completion_tail] = *completion;
    state->completion_tail =
        (state->completion_tail + 1u) % CEP_IO_REACTOR_COMPLETION_CAPACITY;
    state->completion_count += 1u;
    state->completions_this_beat += 1u;
    pthread_cond_broadcast(&state->cond);
    if (completion->shim_fallback && !completion->timed_out) {
        cep_io_reactor_emit_topic(cep_io_reactor_tp_async_unsp_topic(), "shim fallback used");
    }
    return true;
}

static bool
cep_io_reactor_remove_active_locked(cepIoReactorState* state, cepIoReactorJob* target)
{
    if (!state || !target) {
        return false;
    }
    cepIoReactorJob* prev = NULL;
    for (cepIoReactorJob* job = state->active_head; job; job = job->next_active) {
        if (job == target) {
            if (prev) {
                prev->next_active = job->next_active;
            } else {
                state->active_head = job->next_active;
            }
            job->next_active = NULL;
            if (state->active_count > 0u) {
                state->active_count -= 1u;
            }
            return true;
        }
        prev = job;
    }
    return false;
}

static cepIoReactorJob*
cep_io_reactor_pop_pending_locked(cepIoReactorState* state)
{
    if (!state || !state->pending_head) {
        return NULL;
    }
    cepIoReactorJob* job = state->pending_head;
    state->pending_head = job->next_pending;
    if (!state->pending_head) {
        state->pending_tail = NULL;
    }
    job->next_pending = NULL;
    if (state->pending_count > 0u) {
        state->pending_count -= 1u;
    }
    return job;
}

static void
cep_io_reactor_timeout_job_locked(cepIoReactorState* state, cepIoReactorJob* job)
{
    if (!state || !job || job->timed_out) {
        return;
    }
    job->timed_out = true;
    bool is_native = (job->work.kind == CEP_IO_REACTOR_WORK_KIND_NATIVE_FD);
    if (is_native) {
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
        cep_io_reactor_deregister_native_locked(state, job);
#endif
        cep_io_reactor_remove_active_locked(state, job);
    }
    cepIoReactorCompletion completion = {
        .owner = job->work.owner,
        .request_name = job->work.request_name,
        .info = job->work.failure_info,
        .timed_out = true,
        .shim_fallback = cep_io_reactor_job_used_shim(state, job),
        .timeout_topic = job->work.timeout_topic,
        .has_timeout_topic = job->work.has_timeout_topic,
        .has_bytes_done = false,
        .bytes_done = 0u,
        .on_complete = job->work.on_complete,
        .on_complete_context = job->work.on_complete_context,
    };
    completion.info.has_errno = true;
    completion.info.errno_code = -ETIMEDOUT;
    if (job->has_bytes_expected) {
        cep_io_reactor_decrement_pending_bytes(state, job->bytes_expected);
        job->has_bytes_expected = false;
    }
    completion.has_result = true;
    completion.result = (cepIoReactorResult){
        .success = false,
        .bytes_done = 0u,
        .error_code = -ETIMEDOUT,
    };
    if (!cep_io_reactor_completion_enqueue_locked(state, &completion)) {
        CEP_DEBUG_PRINTF("[io_reactor] timeout completion queue full\n");
    } else {
        state->jobs_timed_out += 1u;
    }
    pthread_cond_broadcast(&state->cond);
    if (is_native) {
        if (job->work.native_fd.close_fd && job->work.native_fd.fd >= 0) {
            close(job->work.native_fd.fd);
        }
        if (job->work.destroy) {
            job->work.destroy(job->work.worker_context);
        }
        cep_free(job);
    }
}

static void*
cep_io_reactor_worker_main(void* arg)
{
    cepIoReactorState* state = (cepIoReactorState*)arg;
    if (!state) {
        return NULL;
    }
    for (;;) {
        pthread_mutex_lock(&state->lock);
        while (!state->shutting_down && !state->pending_head) {
            pthread_cond_wait(&state->cond, &state->lock);
        }
        if (state->shutting_down && !state->pending_head) {
            pthread_mutex_unlock(&state->lock);
            break;
        }
        cepIoReactorJob* job = cep_io_reactor_pop_pending_locked(state);
        if (!job) {
            pthread_mutex_unlock(&state->lock);
            continue;
        }
        job->next_active = state->active_head;
        state->active_head = job;
        state->active_count += 1u;
        pthread_mutex_unlock(&state->lock);

        cepIoReactorResult result = {0};
        bool job_ok = false;
        if (job->work.worker) {
            job_ok = job->work.worker(job->work.worker_context, &result);
        }

        pthread_mutex_lock(&state->lock);
        cep_io_reactor_remove_active_locked(state, job);
        bool timed_out = job->timed_out;
        if (!timed_out) {
            cep_io_reactor_finalize_completion_locked(state, job, job_ok, &result);
        }
        pthread_mutex_unlock(&state->lock);

        if (job->work.destroy) {
            job->work.destroy(job->work.worker_context);
        }
        cep_free(job);
    }
    return NULL;
}

static cepIoReactorState*
cep_io_reactor_state(void)
{
    if (g_io_reactor) {
        return g_io_reactor;
    }
    cepIoReactorState* state = cep_malloc0(sizeof *state);
    if (!state) {
        return NULL;
    }
    pthread_mutex_init(&state->lock, NULL);
    pthread_cond_init(&state->cond, NULL);
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    state->epoll_fd = -1;
    state->epoll_wake_fd = -1;
#endif
    cep_io_reactor_state_init_backend(state);
    g_io_reactor = state;
    return g_io_reactor;
}

static void
cep_io_reactor_start_workers(cepIoReactorState* state)
{
    if (!state || state->workers_started) {
        return;
    }
    for (size_t i = 0; i < CEP_IO_REACTOR_WORKER_COUNT; ++i) {
        (void)pthread_create(&state->workers[i], NULL, cep_io_reactor_worker_main, state);
    }
    state->workers_started = true;
}

static bool
cep_io_reactor_schedule_job(cepIoReactorState* state, cepIoReactorJob* job)
{
    if (!state || !job) {
        return false;
    }

    job->next_pending = NULL;
    if (!state->pending_head) {
        state->pending_head = job;
        state->pending_tail = job;
    } else {
        state->pending_tail->next_pending = job;
        state->pending_tail = job;
    }
    state->pending_count += 1u;
    if (job->has_bytes_expected) {
        state->pending_bytes += job->bytes_expected;
    }
    state->jobs_queued += 1u;
    pthread_cond_broadcast(&state->cond);
    return true;
}

bool
cep_io_reactor_submit(const cepIoReactorWork* work)
{
    if (!work || !cep_oid_is_valid(work->owner)) {
        return false;
    }
    cepIoReactorState* state = cep_io_reactor_state();
    if (!state) {
        if (cep_io_reactor_trace()) {
            fprintf(stderr, "[io_reactor] submit failed: no state\n");
        }
        return false;
    }
    if (!cep_io_reactor_state_init_backend(state)) {
        if (cep_io_reactor_trace()) {
            fprintf(stderr, "[io_reactor] submit failed: backend init error\n");
        }
        return false;
    }
    cepIoReactorJob* job = cep_malloc0(sizeof *job);
    if (!job) {
        return false;
    }
    job->work = *work;
    if (job->work.kind != CEP_IO_REACTOR_WORK_KIND_NATIVE_FD) {
        job->work.kind = CEP_IO_REACTOR_WORK_KIND_SHIM;
    }
    job->bytes_expected = work->has_bytes_expected ? work->bytes_expected : 0u;
    job->has_bytes_expected = work->has_bytes_expected;
    job->enqueue_beat = cep_beat_index();
    if (work->has_beats_budget && work->beats_budget > 0u) {
        cepBeatNumber current = cep_beat_index();
        cepBeatNumber base = (current == CEP_BEAT_INVALID) ? 0 : current;
        job->deadline_beat = base + (cepBeatNumber)work->beats_budget;
        job->has_deadline = true;
    }
    bool is_native = (job->work.kind == CEP_IO_REACTOR_WORK_KIND_NATIVE_FD);
    if (is_native && state->backend_kind != CEP_IO_REACTOR_BACKEND_EPOLL) {
        if (cep_io_reactor_trace()) {
            fprintf(stderr, "[io_reactor] submit failed: native job without epoll backend\n");
        }
        if (work->destroy) {
            work->destroy(work->worker_context);
        }
        cep_free(job);
        return false;
    }
    pthread_mutex_lock(&state->lock);
    bool queued = false;
    if (is_native) {
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
        queued = cep_io_reactor_register_native_locked(state, job);
#else
        queued = false;
#endif
    } else {
        cep_io_reactor_start_workers(state);
        queued = cep_io_reactor_schedule_job(state, job);
    }
    pthread_mutex_unlock(&state->lock);
    if (!queued) {
        if (cep_io_reactor_trace()) {
            fprintf(stderr,
                    "[io_reactor] submit failed: queue miss native=%d backend=%d pending=%zu active=%zu\n",
                    is_native ? 1 : 0,
                    (int)state->backend_kind,
                    state->pending_count,
                    state->active_count);
        }
        if (work->destroy) {
            work->destroy(work->worker_context);
        }
        cep_free(job);
    }
    return queued;
}

static void
cep_io_reactor_check_timeouts_locked(cepIoReactorState* state)
{
    if (!state || !state->active_head) {
        return;
    }
    cepBeatNumber current = state->current_beat;
    if (current == CEP_BEAT_INVALID) {
        return;
    }
    for (cepIoReactorJob* job = state->active_head; job;) {
        cepIoReactorJob* next = job->next_active;
        if (!job->has_deadline || job->timed_out) {
            job = next;
            continue;
        }
        if (current < job->deadline_beat) {
            job = next;
            continue;
        }
        cep_io_reactor_timeout_job_locked(state, job);
        job = next;
    }
}

bool
cep_io_reactor_next_completion(cepIoReactorCompletion* out_completion)
{
    if (!out_completion) {
        return false;
    }
    cepIoReactorState* state = g_io_reactor;
    if (!state) {
        return false;
    }
    pthread_mutex_lock(&state->lock);
    if (!state->completion_count) {
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    *out_completion = state->completions[state->completion_head];
    state->completion_head =
        (state->completion_head + 1u) % CEP_IO_REACTOR_COMPLETION_CAPACITY;
    state->completion_count -= 1u;
    pthread_mutex_unlock(&state->lock);
    if (out_completion->timed_out) {
        cep_io_reactor_emit_timeout_cei(out_completion);
    }
    return true;
}

void
cep_io_reactor_on_phase(cepBeatPhase phase)
{
    cepIoReactorState* state = g_io_reactor;
    if (!state) {
        return;
    }
    pthread_mutex_lock(&state->lock);
    if (phase == CEP_BEAT_CAPTURE) {
        state->current_beat = cep_beat_index();
        state->completions_this_beat = 0u;
    }
    if (phase == CEP_BEAT_COMPUTE) {
        cep_io_reactor_check_timeouts_locked(state);
        cep_io_reactor_publish_metrics_locked(state);
    }
    if (phase == CEP_BEAT_COMMIT) {
        cep_io_reactor_publish_metrics_locked(state);
    }
    pthread_mutex_unlock(&state->lock);
}

bool
cep_io_reactor_quiesce(uint32_t deadline_beats)
{
    cepIoReactorState* state = g_io_reactor;
    if (!state) {
        return true;
    }
    pthread_mutex_lock(&state->lock);
    state->draining = true;
    cepBeatNumber start = state->current_beat;
    bool timed_out = false;
    while (!state->shutting_down) {
        /* Completions that have already been produced but not yet ingested by
           the async runtime should not block quiesce: they will be processed
           once the heartbeat resumes, so only pending/active work keeps the
           reactor busy here. */
        bool has_inflight = state->pending_head || state->active_head;
        if (!has_inflight) {
            break;
        }
        if (deadline_beats > 0u && start != CEP_BEAT_INVALID) {
            cepBeatNumber now = state->current_beat;
            if (now != CEP_BEAT_INVALID &&
                (uint32_t)(now - start) >= deadline_beats) {
                timed_out = true;
                break;
            }
        }
        if (cep_io_reactor_trace()) {
            fprintf(stderr,
                    "[io_reactor] quiesce wait pending=%zu active=%zu completions=%zu beat=%" PRIi64 "\n",
                    state->pending_count,
                    state->active_count,
                    state->completion_count,
                    (int64_t)state->current_beat);
            fflush(stderr);
        }
        pthread_cond_wait(&state->cond, &state->lock);
    }
    if (timed_out) {
        while (state->pending_head) {
            cepIoReactorJob* job = state->pending_head;
            state->pending_head = job->next_pending;
            if (state->pending_count > 0u) {
                state->pending_count -= 1u;
            }
            job->next_pending = NULL;
            cep_io_reactor_timeout_job_locked(state, job);
            if (job->work.destroy) {
                job->work.destroy(job->work.worker_context);
            }
            cep_free(job);
        }
        state->pending_tail = NULL;
        for (cepIoReactorJob* job = state->active_head; job; job = job->next_active) {
            cep_io_reactor_timeout_job_locked(state, job);
        }
    }
    state->draining = false;
    pthread_mutex_unlock(&state->lock);
    return !timed_out;
}

void
cep_io_reactor_shutdown(void)
{
    cepIoReactorState* state = g_io_reactor;
    if (!state) {
        return;
    }
    pthread_mutex_lock(&state->lock);
    state->shutting_down = true;
    pthread_cond_broadcast(&state->cond);
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    cep_io_reactor_epoll_wake(state);
#endif
    pthread_mutex_unlock(&state->lock);
    if (state->workers_started) {
        for (size_t i = 0; i < CEP_IO_REACTOR_WORKER_COUNT; ++i) {
            if (state->workers[i]) {
                (void)pthread_join(state->workers[i], NULL);
            }
        }
    }
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    if (state->epoll_thread_started) {
        (void)pthread_join(state->epoll_thread, NULL);
        state->epoll_thread_started = false;
    }
#endif
    pthread_mutex_destroy(&state->lock);
    pthread_cond_destroy(&state->cond);
    while (state->pending_head) {
        cepIoReactorJob* job = state->pending_head;
        state->pending_head = job->next_pending;
        cep_io_reactor_timeout_job_locked(state, job);
        if (job->work.destroy) {
            job->work.destroy(job->work.worker_context);
        }
        cep_free(job);
    }
    while (state->active_head) {
        cepIoReactorJob* job = state->active_head;
        state->active_head = job->next_active;
        cep_io_reactor_timeout_job_locked(state, job);
        if (job->work.destroy) {
            job->work.destroy(job->work.worker_context);
        }
        cep_free(job);
    }
#if defined(CEP_IO_REACTOR_HAS_EPOLL)
    cep_io_reactor_epoll_teardown(state);
#endif
    g_io_reactor = NULL;
    cep_free(state);
}

cepIoReactorBackendKind
cep_io_reactor_active_backend(void)
{
    cepIoReactorState* state = g_io_reactor;
    if (state && state->backend_initialized) {
        return state->backend_kind;
    }
    return cep_io_reactor_backend_preference();
}
