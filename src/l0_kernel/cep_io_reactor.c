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

#include <errno.h>
#include <pthread.h>
#include <string.h>

#define CEP_IO_REACTOR_WORKER_COUNT        2u
#define CEP_IO_REACTOR_COMPLETION_CAPACITY 256u

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
} cepIoReactorState;

static cepIoReactorState* g_io_reactor = NULL;

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
    cepIoReactorCompletion completion = {
        .owner = job->work.owner,
        .request_name = job->work.request_name,
        .info = job->work.failure_info,
        .timed_out = true,
        .shim_fallback = job->work.shim_fallback,
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
            uint64_t bytes_done = result.bytes_done;
            bool has_bytes_done = (bytes_done > 0u);
            if (!has_bytes_done && job->has_bytes_expected) {
                bytes_done = job->bytes_expected;
                has_bytes_done = job->has_bytes_expected;
            }
            if (has_bytes_done) {
                cep_io_reactor_decrement_pending_bytes(state, bytes_done);
                job->has_bytes_expected = false;
            }
            int completion_error = job_ok ? 0 : (result.error_code ? result.error_code : -EIO);
            cepIoReactorCompletion completion = {
                .owner = job->work.owner,
                .request_name = job->work.request_name,
                .info = job_ok ? job->work.success_info : job->work.failure_info,
                .timed_out = false,
                .shim_fallback = job->work.shim_fallback,
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
        return false;
    }
    cepIoReactorJob* job = cep_malloc0(sizeof *job);
    if (!job) {
        return false;
    }
    job->work = *work;
    job->bytes_expected = work->has_bytes_expected ? work->bytes_expected : 0u;
    job->has_bytes_expected = work->has_bytes_expected;
    job->enqueue_beat = cep_beat_index();
    if (work->has_beats_budget && work->beats_budget > 0u) {
        cepBeatNumber current = cep_beat_index();
        cepBeatNumber base = (current == CEP_BEAT_INVALID) ? 0 : current;
        job->deadline_beat = base + (cepBeatNumber)work->beats_budget;
        job->has_deadline = true;
    }
    pthread_mutex_lock(&state->lock);
    cep_io_reactor_start_workers(state);
    bool queued = cep_io_reactor_schedule_job(state, job);
    pthread_mutex_unlock(&state->lock);
    if (!queued) {
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
    for (cepIoReactorJob* job = state->active_head; job; job = job->next_active) {
        if (!job->has_deadline || job->timed_out) {
            continue;
        }
        if (current < job->deadline_beat) {
            continue;
        }
        cep_io_reactor_timeout_job_locked(state, job);
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
    while ((state->pending_head || state->active_head || state->completion_count) &&
           !state->shutting_down) {
        if (deadline_beats > 0u && start != CEP_BEAT_INVALID) {
            cepBeatNumber now = state->current_beat;
            if (now != CEP_BEAT_INVALID &&
                (uint32_t)(now - start) >= deadline_beats) {
                timed_out = true;
                break;
            }
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
    pthread_mutex_unlock(&state->lock);
    if (state->workers_started) {
        for (size_t i = 0; i < CEP_IO_REACTOR_WORKER_COUNT; ++i) {
            if (state->workers[i]) {
                (void)pthread_join(state->workers[i], NULL);
            }
        }
    }
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
    g_io_reactor = NULL;
    cep_free(state);
}
