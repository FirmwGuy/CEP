/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_ep.h"

#include "cep_cei.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_ops.h"
#include "cep_runtime.h"
#include "cep_molecule.h"
#include "stream/cep_stream_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>


typedef enum {
    CEP_EP_PENDING_RUNNING = 0,
    CEP_EP_PENDING_YIELD,
    CEP_EP_PENDING_AWAIT,
    CEP_EP_PENDING_COMPLETED,
    CEP_EP_PENDING_CANCELLED,
} cepEpPendingState;

typedef struct cepEpEpisode {
    cepEID                  eid;
    cepEpCallback           callback;
    void*                   user_ctx;
    cepRuntime*             runtime;
    cepEpExecutionPolicy    policy;
    cepEpProfile            mode_current;
    cepEpProfile            mode_next;
    cepEpExecutionContext   context;
    cepRuntime*             previous_runtime_scope;
    uint64_t                max_beats;
    uint64_t                beats_used;
    cepExecutorTicket       ticket;
    cepEpPendingState       pending_state;
    bool                    in_slice;
    bool                    closed;
    bool                    remove_after_slice;
    cepOID                  awaited_oid;
    bool                    pending_note_set;
    char                    pending_note[128];
    struct cepEpLease*      leases;
    bool                    lease_violation_reported;
    bool                    context_initialized;
    bool                    context_tls_bound;
    bool                    context_suspended;
    struct cepEpLeaseRequestNode* pending_lease_requests;
    struct cepEpEpisode*    next;
} cepEpEpisode;

typedef struct cepEpLease {
    cepCell*             cell;
    cepPath*             path;
    bool                 lock_store;
    bool                 lock_data;
    bool                 include_descendants;
    cepLockToken         store_token;
    cepLockToken         data_token;
    bool                 needs_store_reacquire;
    bool                 needs_data_reacquire;
    bool                 reacquired_store;
    bool                 reacquired_data;
    struct cepEpLease*   next;
} cepEpLease;

typedef struct cepEpAwaitBinding {
    cepOID                      awaited_oid;
    cepEpEpisode*               episode;
    struct cepEpAwaitBinding*   next;
} cepEpAwaitBinding;

typedef struct cepEpLeaseRequestNode {
    cepPath*                    path;
    cepCell*                    cell;
    bool                        lock_store;
    bool                        lock_data;
    bool                        include_descendants;
    struct cepEpLeaseRequestNode* next;
} cepEpLeaseRequestNode;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast past[1];
} cepEpPathBuf;

static cepRuntime*
cep_ep_runtime_current(void)
{
    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (ctx && ctx->runtime) {
        return ctx->runtime;
    }
    return cep_runtime_default();
}

static cepEpRuntimeState*
cep_ep_state_for_runtime(cepRuntime* runtime)
{
    return cep_runtime_ep_state(runtime ? runtime : cep_runtime_default());
}

static cepEpRuntimeState*
cep_ep_state_current(void)
{
    return cep_ep_state_for_runtime(cep_ep_runtime_current());
}

static cepEpEpisode* cep_ep_episode_lookup(cepRuntime* runtime, cepEID eid);
static void          cep_ep_episode_append(cepEpRuntimeState* state, cepEpEpisode* episode);
static void          cep_ep_episode_remove(cepEpRuntimeState* state, cepEpEpisode* episode);
static cepEpAwaitBinding* cep_ep_binding_lookup(cepEpRuntimeState* state, cepOID awaited_oid);
static void          cep_ep_binding_add(cepEpRuntimeState* state, cepOID awaited_oid, cepEpEpisode* episode);
static void          cep_ep_binding_remove(cepEpRuntimeState* state, cepOID awaited_oid, cepEpEpisode* episode);
static void          cep_ep_binding_remove_episode(cepEpRuntimeState* state, cepEpEpisode* episode);
static bool          cep_ep_runtime_init(cepRuntime* runtime, cepEpRuntimeState* state);
static bool          cep_ep_register_enzyme(const char* signal_tag,
                                            cepEnzyme callback,
                                            cepDT* out_name);
static bool          cep_ep_bind_operation(cepRuntime* runtime, cepEpRuntimeState* state, cepOID oid);
static char*         cep_ep_path_to_string(const cepPath* path);
static bool          cep_ep_path_clone(const cepPath* path, cepPath** out_clone);
static bool          cep_ep_paths_equal(const cepPath* lhs, const cepPath* rhs);
static cepCell*      cep_ep_find_op_cell(cepOID oid);
static bool          cep_ep_write_metadata(cepOID oid,
                                           const cepEpExecutionPolicy* policy,
                                           uint64_t max_beats,
                                           const cepPath* signal_path,
                                           const cepPath* target_path);
static cepEpLease*   cep_ep_lease_lookup(cepEpEpisode* episode, const cepPath* path);
static void          cep_ep_release_all_leases(cepEpEpisode* episode);
static void          cep_ep_pending_leases_clear(cepEpEpisode* episode);
static bool          cep_ep_apply_pending_leases(cepEpEpisode* episode);
static bool          cep_ep_schedule_run(cepEpEpisode* episode, const char* note);
static void          cep_ep_run_slice_impl(cepEpEpisode* episode);
static void          cep_ep_run_slice_task(void* ctx);
static void          cep_ep_finalize_slice(cepEpEpisode* episode);
static void          cep_ep_execute_cooperative(cepEpEpisode* episode);
static cepOID        cep_ep_oid_from_path(const cepPath* path);
static bool          cep_ep_mark_state(cepEID eid, const char* state_tag, int code, const char* note);
static bool          cep_ep_arm_continuation(cepEID eid, const char* state_tag);
static cepEpExecutionPolicy cep_ep_effective_policy(const cepEpExecutionPolicy* policy);
static int           cep_ep_continuation_enzyme(const cepPath* signal_path, const cepPath* target_path);

typedef struct {
    cepEpExecutionContext* ctx;
    cepEpProfile           previous_profile;
    bool                   previous_allow_without_lease;
    bool                   active;
} cepEpRwScope;

static cepEpRwScope
cep_ep_rw_scope_begin(void)
{
    cepEpRwScope scope = {0};
    scope.ctx = cep_executor_context_get();
    if (scope.ctx) {
        scope.previous_profile = scope.ctx->profile;
        scope.previous_allow_without_lease = scope.ctx->allow_without_lease;
        scope.ctx->profile = CEP_EP_PROFILE_RW;
        scope.ctx->allow_without_lease = true;
        scope.active = true;
    }
    return scope;
}

static void
cep_ep_rw_scope_end(cepEpRwScope* scope)
{
    if (!scope || !scope->active || !scope->ctx) {
        return;
    }
    scope->ctx->profile = scope->previous_profile;
    scope->ctx->allow_without_lease = scope->previous_allow_without_lease;
}

static bool
cep_ep_lease_covers_cell(const cepEpLease* lease, const cepCell* cell)
{
    if (!lease || !cell || !lease->cell) {
        return false;
    }
    if (lease->cell == cell) {
        return true;
    }
    if (!lease->include_descendants) {
        return false;
    }
    const cepCell* current = cell;
    while (current) {
        if (current == lease->cell) {
            return true;
        }
        current = cep_cell_parent(current);
    }
    return false;
}

bool
cep_ep_store_lock_allows(const cepCell* owner, const cepCell* lock_owner)
{
    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->profile != CEP_EP_PROFILE_RW) {
        return false;
    }
    cepEpEpisode* episode = (cepEpEpisode*)ctx->user_data;
    if (!episode) {
        return false;
    }
    for (const cepEpLease* lease = episode->leases; lease; lease = lease->next) {
        if (!lease->lock_store) {
            continue;
        }
        if (lock_owner && lease->cell != lock_owner) {
            continue;
        }
        if (cep_ep_lease_covers_cell(lease, owner)) {
            return true;
        }
    }
    return false;
}

bool
cep_ep_data_lock_allows(const cepCell* owner, const cepCell* lock_owner)
{
    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->profile != CEP_EP_PROFILE_RW) {
        return false;
    }
    cepEpEpisode* episode = (cepEpEpisode*)ctx->user_data;
    if (!episode) {
        return false;
    }
    for (const cepEpLease* lease = episode->leases; lease; lease = lease->next) {
        if (!lease->lock_data) {
            continue;
        }
        if (lock_owner && lease->cell != lock_owner) {
            continue;
        }
        if (cep_ep_lease_covers_cell(lease, owner)) {
            return true;
        }
    }
    return false;
}

static const cepPath*
cep_ep_make_path(cepEpPathBuf* buf, const cepDT* segment)
{
    buf->length = 1u;
    buf->capacity = 1u;
    buf->past[0].dt = *segment;
    buf->past[0].timestamp = 0u;
    return (const cepPath*)buf;
}

static bool
cep_ep_register_enzyme(const char* signal_tag, cepEnzyme callback, cepDT* out_name)
{
    cepDT raw_dt = cep_ops_make_dt(signal_tag);
    if (!cep_dt_is_valid(&raw_dt)) {
        return false;
    }

    cepDT signal_dt = cep_dt_clean(&raw_dt);

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return false;
    }

    cepEpPathBuf path_buf = {0};
    const cepPath* path = cep_ep_make_path(&path_buf, &signal_dt);

    cepEnzymeDescriptor descriptor = {
        .name   = signal_dt,
        .label  = signal_tag,
        .before = NULL,
        .before_count = 0u,
        .after  = NULL,
        .after_count = 0u,
        .callback = callback,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    int rc = cep_enzyme_register(registry, path, &descriptor);
    if (rc != CEP_ENZYME_SUCCESS) {
        return false;
    }

    cep_enzyme_registry_activate_pending(registry);
    if (out_name) {
        *out_name = signal_dt;
    }
    return true;
}

static bool
cep_ep_runtime_init(cepRuntime* runtime, cepEpRuntimeState* state)
{
    if (!state) {
        return false;
    }

    if (state->runtime_ready) {
        return true;
    }

    cepEpExecutionContext* previous_ctx = cep_executor_context_get();
    cepRuntime* target_runtime = runtime ? runtime : cep_runtime_default();
    cepEpExecutionContext shim_ctx = {0};
    shim_ctx.runtime = target_runtime;

    cepRuntime* previous_runtime_scope = cep_runtime_set_active(target_runtime);
    cep_executor_context_set(&shim_ctx);

    if (!state->executor_ready) {
        if (!cep_executor_init()) {
            if (previous_ctx) {
                cep_executor_context_set(previous_ctx);
            } else {
                cep_executor_context_clear();
            }
            cep_runtime_restore_active(previous_runtime_scope);
            return false;
        }
        state->executor_ready = true;
    }

    if (previous_ctx) {
        cep_executor_context_set(previous_ctx);
    } else {
        cep_executor_context_clear();
    }
    cep_runtime_restore_active(previous_runtime_scope);

    if (!state->enzyme_registered) {
        cepDT ep_cont = (cepDT){0};
        if (!cep_ep_register_enzyme("ep/cont", cep_ep_continuation_enzyme, &ep_cont)) {
            return false;
        }
        state->signal_ep_cont = ep_cont;

        cepDT op_tmo = (cepDT){0};
        if (!cep_ep_register_enzyme("op/tmo", cep_ep_continuation_enzyme, &op_tmo)) {
            return false;
        }
        state->signal_op_tmo = op_tmo;

        state->enzyme_registered = true;
    }

    state->runtime_ready = true;
    return true;
}

static bool
cep_ep_bind_operation(cepRuntime* runtime, cepEpRuntimeState* state, cepOID oid)
{
    cepEpRwScope scope = cep_ep_rw_scope_begin();
    bool ok = false;

    if (!state) {
        state = cep_ep_state_for_runtime(runtime);
    }

    cepCell* op_cell = cep_ep_find_op_cell(oid);
    if (!op_cell) {
        goto out;
    }

    cepCell* resolved = cep_cell_resolve(op_cell);
    if (resolved) {
        op_cell = resolved;
    }

    cepDT cont_name = (state && cep_dt_is_valid(&state->signal_ep_cont))
        ? cep_dt_clean(&state->signal_ep_cont)
        : cep_ops_make_dt("ep/cont");
    if (cep_cell_bind_enzyme(op_cell, &cont_name, false) != CEP_ENZYME_SUCCESS) {
        goto out;
    }

    cepDT tmo_name = (state && cep_dt_is_valid(&state->signal_op_tmo))
        ? cep_dt_clean(&state->signal_op_tmo)
        : cep_ops_make_dt("op/tmo");
    if (cep_cell_bind_enzyme(op_cell, &tmo_name, false) != CEP_ENZYME_SUCCESS) {
        goto out;
    }

    ok = true;

out:
    cep_ep_rw_scope_end(&scope);
    return ok;
}

static void
cep_ep_release_all_leases(cepEpEpisode* episode)
{
    if (!episode) {
        return;
    }
    cepEpLease* lease = episode->leases;
    while (lease) {
        cepEpLease* next = lease->next;
        if (lease->lock_store) {
            cep_store_unlock(lease->cell, &lease->store_token);
            memset(&lease->store_token, 0, sizeof lease->store_token);
            lease->lock_store = false;
        }
        if (lease->lock_data) {
            cep_data_unlock(lease->cell, &lease->data_token);
            memset(&lease->data_token, 0, sizeof lease->data_token);
            lease->lock_data = false;
        }
        lease->needs_store_reacquire = false;
        lease->needs_data_reacquire = false;
        lease->reacquired_store = false;
        lease->reacquired_data = false;
        if (lease->path) {
            cep_free(lease->path);
        }
        cep_free(lease);
        lease = next;
    }
    episode->leases = NULL;
    episode->lease_violation_reported = false;
}

static void
cep_ep_pending_leases_clear(cepEpEpisode* episode)
{
    if (!episode) {
        return;
    }
    cepEpLeaseRequestNode* node = episode->pending_lease_requests;
    while (node) {
        cepEpLeaseRequestNode* next = node->next;
        if (node->path) {
            cep_free(node->path);
        }
        cep_free(node);
        node = next;
    }
    episode->pending_lease_requests = NULL;
}

static bool
cep_ep_apply_pending_leases(cepEpEpisode* episode)
{
    if (!episode) {
        return false;
    }

    cepEpLeaseRequestNode* node = episode->pending_lease_requests;
    episode->pending_lease_requests = NULL;

    cepEpRuntimeState* state = cep_ep_state_for_runtime(episode->runtime);

    while (node) {
        cepEpLeaseRequestNode* next = node->next;
        if (state) {
            atomic_store_explicit(&state->last_lease_fail_reason,
                                  NULL,
                                  memory_order_relaxed);
        }
        bool ok = cep_ep_request_lease(episode->eid,
                                       node->path,
                                       node->lock_store,
                                       node->lock_data,
                                       node->include_descendants);
        if (!ok && node->cell) {
            cepPath* regenerated = NULL;
            if (cep_cell_path(node->cell, &regenerated)) {
                ok = cep_ep_request_lease(episode->eid,
                                           regenerated,
                                           node->lock_store,
                                           node->lock_data,
                                           node->include_descendants);
                cep_free(regenerated);
            }
        }
        if (node->path) {
            cep_free(node->path);
        }
        cep_free(node);
        if (!ok) {
            while (next) {
                cepEpLeaseRequestNode* cleanup = next;
                next = next->next;
                if (cleanup->path) {
                    cep_free(cleanup->path);
                }
                cep_free(cleanup);
            }
            return false;
        }
        node = next;
    }

    return true;
}

static cepEpEpisode*
cep_ep_episode_lookup(cepRuntime* runtime, cepEID eid)
{
    cepEpRuntimeState* state = runtime
        ? cep_ep_state_for_runtime(runtime)
        : cep_ep_state_current();
    for (cepEpEpisode* node = state->episodes; node; node = node->next) {
        if (node->eid.domain == eid.domain && node->eid.tag == eid.tag) {
            return node;
        }
    }
    return NULL;
}

static void
cep_ep_episode_append(cepEpRuntimeState* state, cepEpEpisode* episode)
{
    if (!state || !episode) {
        return;
    }
    episode->next = state->episodes;
    state->episodes = episode;
}

static void
cep_ep_episode_remove(cepEpRuntimeState* state, cepEpEpisode* episode)
{
    if (!state || !episode) {
        return;
    }

    if (episode->ticket) {
        (void)cep_executor_cancel(episode->ticket);
        episode->ticket = 0u;
    }

    cep_ep_binding_remove_episode(state, episode);

    cepEpEpisode** head = &state->episodes;
    while (*head) {
        if (*head == episode) {
            *head = episode->next;
            break;
        }
        head = &(*head)->next;
    }

    cep_ep_release_all_leases(episode);
    cep_ep_pending_leases_clear(episode);
    cep_free(episode);
}

static cepEpAwaitBinding*
cep_ep_binding_lookup(cepEpRuntimeState* state, cepOID awaited_oid)
{
    if (!state) {
        return NULL;
    }
    for (cepEpAwaitBinding* node = state->await_bindings; node; node = node->next) {
        if (node->awaited_oid.domain == awaited_oid.domain &&
            node->awaited_oid.tag == awaited_oid.tag) {
            return node;
        }
    }
    return NULL;
}

static void
cep_ep_binding_add(cepEpRuntimeState* state, cepOID awaited_oid, cepEpEpisode* episode)
{
    if (!state || !episode) {
        return;
    }
    cepEpAwaitBinding* binding = cep_malloc(sizeof *binding);
    binding->awaited_oid = awaited_oid;
    binding->episode = episode;
    binding->next = state->await_bindings;
    state->await_bindings = binding;
}

static void
cep_ep_binding_remove(cepEpRuntimeState* state, cepOID awaited_oid, cepEpEpisode* episode)
{
    if (!state) {
        return;
    }
    cepEpAwaitBinding** head = &state->await_bindings;
    while (*head) {
        if ((*head)->awaited_oid.domain == awaited_oid.domain &&
            (*head)->awaited_oid.tag == awaited_oid.tag &&
            (*head)->episode == episode) {
            cepEpAwaitBinding* doomed = *head;
            *head = doomed->next;
            cep_free(doomed);
            return;
        }
        head = &(*head)->next;
    }
}

static void
cep_ep_binding_remove_episode(cepEpRuntimeState* state, cepEpEpisode* episode)
{
    if (!state) {
        return;
    }
    cepEpAwaitBinding** head = &state->await_bindings;
    while (*head) {
        if ((*head)->episode == episode) {
            cepEpAwaitBinding* doomed = *head;
            *head = doomed->next;
            cep_free(doomed);
        } else {
            head = &(*head)->next;
        }
    }
}

static cepEpLease*
cep_ep_lease_lookup(cepEpEpisode* episode, const cepPath* path)
{
    if (!episode || !path) {
        return NULL;
    }
    for (cepEpLease* lease = episode->leases; lease; lease = lease->next) {
        if (lease->path && cep_ep_paths_equal(lease->path, path)) {
            return lease;
        }
    }
    return NULL;
}

static cepCell*
cep_ep_find_op_cell(cepOID oid)
{
    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return NULL;
    }

    cepDT ops_name = cep_ops_make_dt("ops");
    cepCell* ops_root = cep_cell_find_by_name(rt_root, &ops_name);
    if (!ops_root) {
        return NULL;
    }

    cepDT lookup = {
        .domain = oid.domain,
        .tag = oid.tag,
        .glob = 0,
    };
    return cep_cell_find_by_name(ops_root, &lookup);
}

static bool
cep_ep_write_metadata(cepOID oid,
                      const cepEpExecutionPolicy* policy,
                      uint64_t max_beats,
                      const cepPath* signal_path,
                      const cepPath* target_path)
{
    cepEpRwScope scope = cep_ep_rw_scope_begin();
    bool ok = false;
    char* signal_text = NULL;
    char* target_text = NULL;

    cepCell* op_cell = cep_ep_find_op_cell(oid);
    if (!op_cell) {
        goto out;
    }

    cepDT episode_name = cep_ops_make_dt("episode");
    cepCell* episode = cep_cell_ensure_dictionary_child(op_cell,
                                                        &episode_name,
                                                        CEP_STORAGE_RED_BLACK_T);
    if (!episode) {
        goto out;
    }

    const char* profile_text = (policy->profile == CEP_EP_PROFILE_RW)
        ? "ep:pro/rw"
        : "ep:pro/ro";
    cepDT profile_field = cep_ops_make_dt("profile");
    if (!cep_cell_put_text(episode, &profile_field, profile_text)) {
        goto out;
    }

    cepDT cpu_field = cep_ops_make_dt("bud_cpu_ns");
    if (!cep_cell_put_uint64(episode, &cpu_field, policy->cpu_budget_ns)) {
        goto out;
    }

    cepDT io_field = cep_ops_make_dt("bud_io_by");
    if (!cep_cell_put_uint64(episode, &io_field, policy->io_budget_bytes)) {
        goto out;
    }

    signal_text = cep_ep_path_to_string(signal_path);
    target_text = cep_ep_path_to_string(target_path);
    if (!signal_text || !target_text) {
        goto out;
    }

    cepDT signal_field = cep_ops_make_dt("sig_path");
    if (!cep_cell_put_text(episode, &signal_field, signal_text)) {
        goto out;
    }

    cepDT target_field = cep_ops_make_dt("tgt_path");
    if (!cep_cell_put_text(episode, &target_field, target_text)) {
        goto out;
    }

    if (max_beats) {
        cepDT max_field = cep_ops_make_dt("max_beats");
        if (!cep_cell_put_uint64(episode, &max_field, max_beats)) {
            goto out;
        }
    }

    ok = true;

out:
    if (signal_text) {
        cep_free(signal_text);
    }
    if (target_text) {
        cep_free(target_text);
    }
    cep_ep_rw_scope_end(&scope);
    return ok;
}

static char*
cep_ep_path_to_string(const cepPath* path)
{
    if (!path || path->length == 0u) {
        char* text = cep_malloc(2u);
        if (!text) {
            return NULL;
        }
        text[0] = '/';
        text[1] = '\0';
        return text;
    }

    size_t capacity = (size_t)path->length * 96u + 2u;
    char* text = cep_malloc(capacity);
    if (!text) {
        return NULL;
    }

    size_t pos = 0u;
    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];

        if (pos + 1u >= capacity) {
            cep_free(text);
            return NULL;
        }
        text[pos++] = '/';

        char domain_buffer[CEP_WORD_MAX_CHARS + 1u];
        const char* domain = cep_namepool_lookup(segment->dt.domain, NULL);
        size_t domain_len = domain ? strlen(domain) : 0u;
        if (!domain) {
            if (cep_id_is_acronym(segment->dt.domain)) {
                domain_len = cep_acronym_to_text(cep_id(segment->dt.domain), domain_buffer);
                domain_buffer[domain_len] = '\0';
                domain = domain_buffer;
            } else if (cep_id_is_word(segment->dt.domain)) {
                domain_len = cep_word_to_text(cep_id(segment->dt.domain), domain_buffer);
                domain_buffer[domain_len] = '\0';
                domain = domain_buffer;
            } else {
                domain = "-";
                domain_len = 1u;
            }
        }
        if (pos + domain_len >= capacity) {
            cep_free(text);
            return NULL;
        }
        memcpy(text + pos, domain, domain_len);
        pos += domain_len;

        if (pos + 1u >= capacity) {
            cep_free(text);
            return NULL;
        }
        text[pos++] = ':';

        char tag_buffer[CEP_WORD_MAX_CHARS + 1u];
        const char* tag = cep_namepool_lookup(segment->dt.tag, NULL);
        size_t tag_len = tag ? strlen(tag) : 0u;
        if (!tag) {
            if (cep_id_is_word(segment->dt.tag)) {
                tag_len = cep_word_to_text(cep_id(segment->dt.tag), tag_buffer);
                tag_buffer[tag_len] = '\0';
                tag = tag_buffer;
            } else if (cep_id_is_acronym(segment->dt.tag)) {
                tag_len = cep_acronym_to_text(cep_id(segment->dt.tag), tag_buffer);
                tag_buffer[tag_len] = '\0';
                tag = tag_buffer;
            } else {
                tag = "-";
                tag_len = 1u;
            }
        }
        if (pos + tag_len >= capacity) {
            cep_free(text);
            return NULL;
        }
        memcpy(text + pos, tag, tag_len);
        pos += tag_len;

        if (segment->timestamp) {
            int written = snprintf(text + pos,
                                   capacity - pos,
                                   "@%" PRIu64,
                                   (uint64_t)segment->timestamp);
            if (written < 0) {
                cep_free(text);
                return NULL;
            }
            size_t w = (size_t)written;
            if (pos + w >= capacity) {
                cep_free(text);
                return NULL;
            }
            pos += w;
        }
    }

    if (pos >= capacity) {
        cep_free(text);
        return NULL;
    }

    text[pos] = '\0';
    return text;
}

static bool
cep_ep_path_clone(const cepPath* path, cepPath** out_clone)
{
    if (!path || !out_clone) {
        return false;
    }
    size_t bytes = sizeof(cepPath) + (size_t)path->length * sizeof(cepPast);
    cepPath* clone = cep_malloc(bytes);
    if (!clone) {
        return false;
    }
    clone->length = path->length;
    clone->capacity = path->length;
    memcpy(clone->past, path->past, (size_t)path->length * sizeof(cepPast));
    *out_clone = clone;
    return true;
}

static bool
cep_ep_paths_equal(const cepPath* lhs, const cepPath* rhs)
{
    if (lhs == rhs) {
        return true;
    }
    if (!lhs || !rhs || lhs->length != rhs->length) {
        return false;
    }
    for (unsigned i = 0; i < lhs->length; ++i) {
        const cepPast* lp = &lhs->past[i];
        const cepPast* rp = &rhs->past[i];
        if (lp->timestamp != rp->timestamp) {
            return false;
        }
        if (cep_dt_compare(&lp->dt, &rp->dt) != 0) {
            return false;
        }
    }
    return true;
}

static cepEpExecutionPolicy
cep_ep_effective_policy(const cepEpExecutionPolicy* policy)
{
    cepEpExecutionPolicy effective = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    if (policy) {
        if (policy->profile == CEP_EP_PROFILE_RO ||
            policy->profile == CEP_EP_PROFILE_RW ||
            policy->profile == CEP_EP_PROFILE_HYBRID) {
            effective.profile = policy->profile;
        }
        if (policy->cpu_budget_ns) {
            effective.cpu_budget_ns = policy->cpu_budget_ns;
        }
        if (policy->io_budget_bytes) {
            effective.io_budget_bytes = policy->io_budget_bytes;
        }
    }

    return effective;
}

static bool
cep_ep_mark_state(cepEID eid, const char* state_tag, int code, const char* note)
{
    cepEpRwScope scope = cep_ep_rw_scope_begin();
    bool ok = false;

    cepDT raw_state = cep_ops_make_dt(state_tag);
    if (!cep_dt_is_valid(&raw_state)) {
        goto out;
    }

    cepDT cleaned_state = cep_dt_clean(&raw_state);
    ok = cep_op_state_set(eid, cleaned_state, code, note);

out:
    cep_ep_rw_scope_end(&scope);
    return ok;
}

static bool
cep_ep_arm_continuation(cepEID eid, const char* state_tag)
{
    cepEpRwScope scope = cep_ep_rw_scope_begin();
    bool ok = false;

    cepDT want_raw = cep_ops_make_dt(state_tag);
    if (!cep_dt_is_valid(&want_raw)) {
        goto out;
    }

    cepDT want_clean = cep_dt_clean(&want_raw);
    cepEpRuntimeState* state = cep_ep_state_current();
    cepDT cont = (state && cep_dt_is_valid(&state->signal_ep_cont))
        ? cep_dt_clean(&state->signal_ep_cont)
        : cep_dt_clean(CEP_DTAW("CEP", "ep/cont"));

    ok = cep_op_await(eid,
                      want_clean,
                      0u,
                      cont,
                      &eid,
                      sizeof eid);

out:
    cep_ep_rw_scope_end(&scope);
    return ok;
}

static bool
cep_ep_schedule_run(cepEpEpisode* episode, const char* note)
{
    if (!episode || episode->closed) {
        return false;
    }

    if (!cep_ep_mark_state(episode->eid, "ist:run", 0, note)) {
        return false;
    }

    if (episode->max_beats && episode->beats_used >= episode->max_beats) {
        (void)cep_ep_cancel_for_runtime(episode->runtime, episode->eid, -1, "max beats exceeded");
        return false;
    }

    episode->pending_state = CEP_EP_PENDING_RUNNING;
    episode->beats_used += 1u;

    episode->mode_current = episode->mode_next;

    if (episode->mode_current == CEP_EP_PROFILE_RO) {
        if (episode->ticket) {
            return true;
        }
        cepEpExecutionPolicy ro_policy = episode->policy;
        ro_policy.profile = CEP_EP_PROFILE_RO;
        episode->context.runtime = episode->runtime;
        cepEpExecutionContext* previous_ctx = cep_executor_context_get();
        cep_executor_context_set(&episode->context);

        bool submitted = cep_executor_submit_ro(cep_ep_run_slice_task,
                                                episode,
                                                &ro_policy,
                                                &episode->ticket);

        if (previous_ctx) {
            cep_executor_context_set(previous_ctx);
        } else {
            cep_executor_context_clear();
        }

        if (!submitted) {
            (void)cep_ep_cancel_for_runtime(episode->runtime, episode->eid, -2, "executor queue full");
            return false;
        }
        return true;
    }

    if (episode->in_slice) {
        return true;
    }

    cep_ep_execute_cooperative(episode);
    return true;
}

static void
cep_ep_bind_tls_context(cepEpEpisode* episode, bool fresh_slice)
{
    if (!episode) {
        return;
    }

    cepEpExecutionContext* ctx = &episode->context;
    if (fresh_slice || !episode->context_initialized) {
        ctx->cpu_budget_ns = episode->policy.cpu_budget_ns;
        ctx->io_budget_bytes = episode->policy.io_budget_bytes;
        ctx->user_data = episode;
        ctx->cpu_consumed_ns = 0u;
        ctx->io_consumed_bytes = 0u;
        atomic_store(&ctx->cancel_requested, false);
    }
    ctx->profile = episode->mode_current;
    ctx->allow_without_lease = false;
    ctx->ticket = episode->ticket;
    ctx->runtime = episode->runtime;
    cep_executor_context_set(ctx);
    if (!episode->context_tls_bound) {
        episode->previous_runtime_scope = cep_runtime_set_active(episode->runtime);
    }
    episode->context_initialized = true;
    episode->context_tls_bound = true;
    episode->context_suspended = false;
}

static void
cep_ep_unbind_tls_context(cepEpEpisode* episode)
{
    if (!episode || !episode->context_tls_bound) {
        return;
    }
    cep_executor_context_clear();
    episode->context_tls_bound = false;
    cep_runtime_restore_active(episode->previous_runtime_scope);
    episode->previous_runtime_scope = NULL;
}

static void
cep_ep_execute_cooperative(cepEpEpisode* episode)
{
    cep_ep_bind_tls_context(episode, true);
    cep_ep_run_slice_impl(episode);
}

static void
cep_ep_run_slice_task(void* ctx)
{
    cepEpEpisode* episode = (cepEpEpisode*)ctx;
    if (!episode) {
        return;
    }
    cep_ep_run_slice_impl(episode);
}

static void
cep_ep_run_slice_impl(cepEpEpisode* episode)
{
    if (!episode || episode->closed) {
        return;
    }

    episode->in_slice = true;
    episode->pending_state = CEP_EP_PENDING_RUNNING;

    cepEpRuntimeState* state = cep_ep_state_for_runtime(episode->runtime);

    bool leases_ok = cep_ep_apply_pending_leases(episode);
    if (leases_ok) {
        episode->callback(episode->eid, episode->user_ctx);
    } else {
        const char* reason = state
            ? atomic_exchange_explicit(&state->last_lease_fail_reason,
                                       NULL,
                                       memory_order_relaxed)
            : NULL;
        if (reason && reason[0]) {
            char note[128];
            snprintf(note, sizeof note, "lease apply failed (%s)", reason);
            (void)cep_ep_cancel_for_runtime(episode->runtime, episode->eid, -4, note);
        } else {
            (void)cep_ep_cancel_for_runtime(episode->runtime, episode->eid, -4, "lease apply failed");
        }
    }

    if (episode->mode_current == CEP_EP_PROFILE_RO) {
        episode->ticket = 0u;
    }

    cep_ep_unbind_tls_context(episode);
    cep_ep_finalize_slice(episode);
}

static void
cep_ep_finalize_slice(cepEpEpisode* episode)
{
    if (!episode) {
        return;
    }

    episode->in_slice = false;
    episode->context_suspended = false;

    cepEpRuntimeState* state = cep_ep_state_for_runtime(episode->runtime);

    switch (episode->pending_state) {
    case CEP_EP_PENDING_RUNNING:
        if (!episode->closed) {
            cepDT ok = cep_ops_make_dt("sts:ok");
            (void)cep_ep_close(episode->eid, ok, NULL, 0u);
        }
        break;
    case CEP_EP_PENDING_YIELD:
        (void)cep_ep_mark_state(episode->eid,
                                "ist:yield",
                                0,
                                episode->pending_note_set ? episode->pending_note : NULL);
        (void)cep_ep_arm_continuation(episode->eid, "ist:yield");
        episode->pending_note_set = false;
        break;
    case CEP_EP_PENDING_AWAIT:
        (void)cep_ep_mark_state(episode->eid,
                                "ist:await",
                                0,
                                episode->pending_note_set ? episode->pending_note : NULL);
        episode->pending_note_set = false;
        break;
    case CEP_EP_PENDING_CANCELLED:
    case CEP_EP_PENDING_COMPLETED:
        break;
    default:
        break;
    }

    if (episode->closed || episode->remove_after_slice) {
        cep_ep_episode_remove(state, episode);
    }
}

static cepOID
cep_ep_oid_from_path(const cepPath* path)
{
    cepOID oid = cep_oid_invalid();
    if (!path || path->length == 0u) {
        return oid;
    }

    const cepPast* segment = &path->past[path->length - 1u];
    oid.domain = segment->dt.domain;
    oid.tag = segment->dt.tag;
    return oid;
}

static int
cep_ep_continuation_enzyme(const cepPath* signal_path, const cepPath* target_path)
{
    if (!signal_path || signal_path->length == 0u) {
        return CEP_ENZYME_SUCCESS;
    }

    cepOID target_oid = cep_ep_oid_from_path(target_path);
    if (!cep_oid_is_valid(target_oid)) {
        return CEP_ENZYME_SUCCESS;
    }

    const cepPast* tail = &signal_path->past[signal_path->length - 1u];
    if (!cep_dt_is_valid(&tail->dt)) {
        return CEP_ENZYME_SUCCESS;
    }

    (void)cep_ep_handle_continuation(&tail->dt, target_oid);

    return CEP_ENZYME_SUCCESS;
}

/* Bridge OPS watcher continuations back into episodes by inspecting the
   continuation signal and resuming or cancelling any episodes waiting on the
   affected operation. The helper recognises the `CEP:ep/cont` signal emitted
   for resumptions and `CEP:op/tmo` for timeouts, matching the design notes so
   continuation routing stays deterministic. */
bool
cep_ep_handle_continuation(const cepDT* continuation, cepOID target_oid)
{
    if (!continuation || !cep_dt_is_valid(continuation) || !cep_oid_is_valid(target_oid)) {
        return false;
    }

    cepDT signal = cep_dt_clean(continuation);
    cepEpRuntimeState* state = cep_ep_state_current();
    const bool have_ep_cont = state && cep_dt_is_valid(&state->signal_ep_cont);
    const bool have_op_tmo = state && cep_dt_is_valid(&state->signal_op_tmo);

    cepDT ep_cont_dt = have_ep_cont
        ? cep_dt_clean(&state->signal_ep_cont)
        : cep_dt_clean(CEP_DTAW("CEP", "ep/cont"));
    if (cep_dt_compare(&signal, &ep_cont_dt) == 0) {
        cepEpEpisode* episode = cep_ep_episode_lookup(NULL, target_oid);
        if (episode) {
            return cep_ep_schedule_run(episode, NULL);
        }

        bool routed = false;
        while (true) {
            cepEpAwaitBinding* binding = cep_ep_binding_lookup(state, target_oid);
            if (!binding) {
                break;
            }
            cepEpEpisode* waiting = binding->episode;
            cep_ep_binding_remove(state, target_oid, waiting);
            waiting->awaited_oid = cep_oid_invalid();
            waiting->pending_state = CEP_EP_PENDING_RUNNING;
            if (cep_ep_schedule_run(waiting, NULL)) {
                routed = true;
            }
        }
        return routed;
    }

    cepDT op_tmo_dt = have_op_tmo
        ? cep_dt_clean(&state->signal_op_tmo)
        : cep_dt_clean(CEP_DTAW("CEP", "op/tmo"));
    if (cep_dt_compare(&signal, &op_tmo_dt) == 0) {
        bool cancelled = false;

        while (true) {
            cepEpAwaitBinding* binding = cep_ep_binding_lookup(state, target_oid);
            if (!binding) {
                break;
            }
            cepEpEpisode* waiting = binding->episode;
            cep_ep_binding_remove(state, target_oid, waiting);
            waiting->awaited_oid = cep_oid_invalid();
            waiting->pending_state = CEP_EP_PENDING_CANCELLED;
            if (cep_ep_cancel_for_runtime(waiting->runtime, waiting->eid, -3, "await timeout")) {
                cancelled = true;
            }
        }
        return cancelled;
    }

    return false;
}

/* Initialise an episodic dossier, capture execution policy, and queue the
   first slice so the heartbeat can run multi-beat work deterministically. The
   routine stores human-readable metadata alongside the OPS branch and
   self-registers the continuation enzyme on demand. */
bool
cep_ep_start(cepEID* out_eid,
             const cepPath* signal_path,
             const cepPath* target_path,
             cepEpCallback callback,
             void* user_context,
             const cepEpExecutionPolicy* policy,
             uint64_t max_beats)
{
    if (!out_eid || !signal_path || !target_path || !callback) {
        return false;
    }

    cepRuntime* runtime = cep_ep_runtime_current();
    cepEpRuntimeState* state = cep_ep_state_for_runtime(runtime);

    if (!cep_ep_runtime_init(runtime, state)) {
        return false;
    }

    if (!cep_namepool_bootstrap()) {
        return false;
    }

    cepEpExecutionPolicy effective = cep_ep_effective_policy(policy);
    cepDT fail_status = cep_ops_make_dt("sts:fail");

    char* target_text = cep_ep_path_to_string(target_path);
    if (!target_text) {
        return false;
    }

    cepDT verb_dt = cep_ops_make_dt("op/ep");
    cepDT mode_dt = cep_ops_make_dt("opm:states");
    if (!cep_dt_is_valid(&verb_dt) || !cep_dt_is_valid(&mode_dt)) {
        return false;
    }

    cepOID eid = cep_op_start(verb_dt,
                              target_text,
                              mode_dt,
                              NULL,
                              0u,
                              0u);

    cep_free(target_text);

    if (!cep_oid_is_valid(eid)) {
        return false;
    }

    if (!cep_ep_mark_state(eid, "ist:plan", 0, NULL)) {
        CEP_DEBUG_PRINTF("[cep_ep_start] mark_state plan failed\n");
        (void)cep_op_close(eid, fail_status, NULL, 0u);
        return false;
    }

    if (!cep_ep_write_metadata(eid, &effective, max_beats, signal_path, target_path)) {
        CEP_DEBUG_PRINTF("[cep_ep_start] metadata write failed\n");
        (void)cep_op_close(eid, fail_status, NULL, 0u);
        return false;
    }

    if (!cep_ep_bind_operation(runtime, state, eid)) {
        CEP_DEBUG_PRINTF("[cep_ep_start] ensure bindings failed\n");
        (void)cep_op_close(eid, fail_status, NULL, 0u);
        return false;
    }

    cepEpEpisode* episode = cep_malloc(sizeof *episode);
    if (!episode) {
        (void)cep_op_close(eid, fail_status, NULL, 0u);
        return false;
    }

    memset(episode, 0, sizeof *episode);
    episode->eid = eid;
    episode->callback = callback;
    episode->user_ctx = user_context;
    episode->runtime = runtime;
    episode->policy = effective;
    episode->max_beats = max_beats;
    episode->pending_state = CEP_EP_PENDING_RUNNING;
    episode->awaited_oid = cep_oid_invalid();

    if (effective.profile == CEP_EP_PROFILE_HYBRID) {
        episode->mode_current = CEP_EP_PROFILE_RO;
    } else {
        episode->mode_current = effective.profile;
    }
    episode->mode_next = episode->mode_current;

    cep_ep_episode_append(state, episode);
    *out_eid = eid;

    if (!cep_ep_schedule_run(episode, "start")) {
        cepEpEpisode* retained = cep_ep_episode_lookup(runtime, eid);
        if (retained == episode) {
            CEP_DEBUG_PRINTF("[cep_ep_start] schedule failed retained episode\n");
            (void)cep_op_close(eid, fail_status, NULL, 0u);
            cep_ep_episode_remove(state, episode);
        } else {
            CEP_DEBUG_PRINTF("[cep_ep_start] schedule failed episode already cancelled\n");
        }
        return false;
    }

    return true;
}

/* Cooperatively yield the current episode so the heartbeat queues a
   continuation for the next beat. The helper records `ist:yield`, arms an
   awaiter on that state, and leaves the slice expecting to return to the caller
   immediately. */
bool
cep_ep_yield(cepEID eid, const char* note)
{
    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode || episode->closed) {
        return false;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->user_data != episode) {
        CEP_DEBUG_PRINTF("[cep_ep_yield] ctx mismatch episode=%p ctx=%p ctx_user=%p\n",
                         (void*)episode,
                         (void*)ctx,
                         ctx ? ctx->user_data : NULL);
        return false;
    }

    episode->pending_state = CEP_EP_PENDING_YIELD;
    episode->pending_note_set = false;
    if (note && note[0]) {
        size_t len = strlen(note);
        size_t cap = sizeof episode->pending_note;
        if (len >= cap) {
            len = cap - 1u;
        }
        memcpy(episode->pending_note, note, len);
        episode->pending_note[len] = '\0';
        episode->pending_note_set = true;
    }
    return true;
}

/* Park an episode until another operation reaches `want_state`. The helper
   records `ist:await`, registers a continuation watcher on the awaited
   operation, and hands control back to the caller. */
bool
cep_ep_await(cepEID eid,
             cepOID awaited_oid,
             cepDT want_state,
             uint32_t ttl_beats,
             const char* note)
{
    if (!cep_oid_is_valid(eid) || !cep_oid_is_valid(awaited_oid) || !cep_dt_is_valid(&want_state)) {
        return false;
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode || episode->closed) {
        return false;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->user_data != episode) {
        return false;
    }

    cepEpRuntimeState* state = cep_ep_state_for_runtime(episode->runtime);

    if (!cep_ep_binding_lookup(state, awaited_oid)) {
        if (!cep_ep_bind_operation(episode->runtime, state, awaited_oid)) {
            return false;
        }
    }

    cepDT want_clean = cep_dt_clean(&want_state);
    cepDT cont = (state && cep_dt_is_valid(&state->signal_ep_cont))
        ? cep_dt_clean(&state->signal_ep_cont)
        : cep_dt_clean(CEP_DTAW("CEP", "ep/cont"));

    cepEpRwScope scope = cep_ep_rw_scope_begin();
    bool awaited = cep_op_await(awaited_oid,
                                want_clean,
                                ttl_beats,
                                cont,
                                &eid,
                                sizeof eid);
    cep_ep_rw_scope_end(&scope);
    if (!awaited) {
        return false;
    }

    episode->pending_state = CEP_EP_PENDING_AWAIT;
    episode->awaited_oid = awaited_oid;
    episode->pending_note_set = false;
    if (note && note[0]) {
        size_t len = strlen(note);
        size_t cap = sizeof episode->pending_note;
        if (len >= cap) {
            len = cap - 1u;
        }
        memcpy(episode->pending_note, note, len);
        episode->pending_note[len] = '\0';
        episode->pending_note_set = true;
    }
    cep_ep_binding_add(state, awaited_oid, episode);
    return true;
}

bool
cep_ep_request_lease(cepEID eid,
                     const cepPath* root,
                     bool lock_store,
                     bool lock_data,
                     bool include_descendants)
{
    cepEpRuntimeState* fail_state = cep_ep_state_for_runtime(cep_ep_runtime_current());

#define CEP_EP_LEASE_FAIL(code)                                            \
    do {                                                                   \
        CEP_DEBUG_PRINTF("[cep_ep_request_lease] %s\n", code);             \
        if (fail_state) {                                                  \
            atomic_store_explicit(&fail_state->last_lease_fail_reason,      \
                                  (code),                                  \
                                  memory_order_relaxed);                   \
        }                                                                  \
        return false;                                                      \
    } while (0)

    if (!cep_oid_is_valid(eid) || !root || root->length == 0u) {
        CEP_EP_LEASE_FAIL("invalid-input");
    }
    if (!lock_store && !lock_data) {
        CEP_EP_LEASE_FAIL("no-locks");
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode || episode->closed) {
        CEP_EP_LEASE_FAIL("episode-state");
    }

    fail_state = cep_ep_state_for_runtime(episode->runtime);

    bool can_lock = (episode->policy.profile == CEP_EP_PROFILE_RW) ||
                    (episode->policy.profile == CEP_EP_PROFILE_HYBRID &&
                     episode->mode_current == CEP_EP_PROFILE_RW);
    if (!can_lock) {
        CEP_EP_LEASE_FAIL("episode-state");
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->user_data != episode) {
        CEP_EP_LEASE_FAIL("ctx-mismatch");
    }

    cepEpLease* existing = cep_ep_lease_lookup(episode, root);
    if (existing) {
        bool need_store = lock_store && !existing->lock_store;
        bool need_data = lock_data && !existing->lock_data;

        if (need_store) {
            if (!cep_store_lock(existing->cell, &existing->store_token)) {
                CEP_EP_LEASE_FAIL("upgrade-store");
            }
            existing->lock_store = true;
        }

        if (need_data) {
            if (!cep_data_lock(existing->cell, &existing->data_token)) {
                if (need_store) {
                    cep_store_unlock(existing->cell, &existing->store_token);
                    existing->lock_store = false;
                }
                CEP_EP_LEASE_FAIL("upgrade-data");
            }
            existing->lock_data = true;
        }

        if (include_descendants && !existing->include_descendants) {
            existing->include_descendants = true;
        }

        episode->lease_violation_reported = false;
        return true;
    }

    cepPath* cloned = NULL;
    if (!cep_ep_path_clone(root, &cloned)) {
        CEP_EP_LEASE_FAIL("clone-path");
    }

    const cepPath* lookup_path = root;
    bool consumed_root_segment = false;
    cepPath* trimmed_path = NULL;
    const cepCell* system_root = cep_root();
    const cepDT* system_root_name = system_root ? cep_cell_get_name(system_root) : NULL;
    if (lookup_path && lookup_path->length && system_root_name) {
        if (cep_dt_compare(system_root_name, &lookup_path->past[0].dt) == 0) {
            consumed_root_segment = true;
            if (lookup_path->length > 1u) {
                unsigned trimmed_len = lookup_path->length - 1u;
                size_t bytes = sizeof(cepPath) + ((size_t)trimmed_len * sizeof(cepPast));
                trimmed_path = cep_alloca(bytes);
                trimmed_path->length = trimmed_len;
                trimmed_path->capacity = trimmed_len;
                memcpy(trimmed_path->past, &lookup_path->past[1], trimmed_len * sizeof(cepPast));
                lookup_path = trimmed_path;
            } else {
                lookup_path = NULL;
            }
        }
    }

    cepCell* target = NULL;
    if (lookup_path && lookup_path->length) {
        target = cep_cell_find_by_path(cep_root(), lookup_path);
    } else if (consumed_root_segment) {
        target = (cepCell*)system_root;
    }
    if (!target) {
        cepCell* current = cep_root();
        if (current) {
            for (unsigned i = 0; i < root->length; ++i) {
                const cepPast* segment = &root->past[i];
                if (segment->dt.domain == current->metacell.domain &&
                    segment->dt.tag == current->metacell.tag &&
                    segment->dt.glob == current->metacell.glob) {
                    continue;
                }
                cepCell* next = cep_cell_find_by_name(current, &segment->dt);
                if (!next) {
                    current = NULL;
                    break;
                }
                current = next;
            }
        }
        target = current;
    }
    if (!target) {
        char* debug_path = cep_ep_path_to_string(root);
        CEP_DEBUG_PRINTF("[cep_ep_request_lease] resolve failed path=%s\n",
                         debug_path ? debug_path : "<null>");
        if (debug_path) {
            cep_free(debug_path);
        }
        cep_free(cloned);
        return false;
    }
    target = cep_cell_resolve(target);
    if (!target) {
        cep_free(cloned);
        CEP_EP_LEASE_FAIL("resolve-target");
    }

    cepEpLease* lease = cep_malloc0(sizeof *lease);
    lease->cell = target;
    lease->path = cloned;
    lease->include_descendants = include_descendants;

    if (lock_store) {
        if (!cep_store_lock(target, &lease->store_token)) {
            cep_free(cloned);
            cep_free(lease);
            CEP_EP_LEASE_FAIL("lock-store");
        }
        lease->lock_store = true;
    }

    if (lock_data) {
        if (!cep_data_lock(target, &lease->data_token)) {
            if (lease->lock_store) {
                cep_store_unlock(target, &lease->store_token);
            }
            cep_free(cloned);
            cep_free(lease);
            CEP_EP_LEASE_FAIL("lock-data");
        }
        lease->lock_data = true;
    }

    lease->next = episode->leases;
    episode->leases = lease;
    episode->lease_violation_reported = false;

#undef CEP_EP_LEASE_FAIL
    return true;
}

bool
cep_ep_release_lease(cepEID eid, const cepPath* root)
{
    if (!cep_oid_is_valid(eid) || !root) {
        return false;
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode) {
        return false;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->user_data != episode) {
        return false;
    }

    cepEpLease* prev = NULL;
    cepEpLease* lease = episode->leases;
    while (lease) {
        if (lease->path && cep_ep_paths_equal(lease->path, root)) {
            if (lease->lock_store) {
                cep_store_unlock(lease->cell, &lease->store_token);
            }
            if (lease->lock_data) {
                cep_data_unlock(lease->cell, &lease->data_token);
            }
            if (prev) {
                prev->next = lease->next;
            } else {
                episode->leases = lease->next;
            }
            if (lease->path) {
                cep_free(lease->path);
            }
            cep_free(lease);
            episode->lease_violation_reported = false;
            return true;
        }
        prev = lease;
        lease = lease->next;
    }

    return false;
}

/* Suspend an active RW slice so cooperative coroutine schedulers can yield
   without leaving the thread in a privileged state. The helper clears the TLS
   execution context and optionally releases outstanding leases when the caller
   provides `CEP_EP_SUSPEND_DROP_LEASES`. */
bool
cep_ep_suspend_rw(cepEID eid, uint32_t flags)
{
    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode || episode->closed || episode->policy.profile != CEP_EP_PROFILE_RW) {
        return false;
    }
    if (flags & ~CEP_EP_SUSPEND_DROP_LEASES) {
        return false;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx != &episode->context) {
        return false;
    }
    if (episode->context_suspended) {
        return false;
    }

    cep_ep_unbind_tls_context(episode);
    episode->context_suspended = true;

    if (flags & CEP_EP_SUSPEND_DROP_LEASES) {
        for (cepEpLease* lease = episode->leases; lease; lease = lease->next) {
            if (lease->lock_store) {
                cep_store_unlock(lease->cell, &lease->store_token);
                memset(&lease->store_token, 0, sizeof lease->store_token);
                lease->lock_store = false;
                lease->needs_store_reacquire = true;
            }
            if (lease->lock_data) {
                cep_data_unlock(lease->cell, &lease->data_token);
                memset(&lease->data_token, 0, sizeof lease->data_token);
                lease->lock_data = false;
                lease->needs_data_reacquire = true;
            }
            lease->reacquired_store = false;
            lease->reacquired_data = false;
        }
    }

    return true;
}

/* Resume a coroutine-friendly RW slice by rebinding TLS state and reacquiring
   any leases that were dropped during suspension. Failures trigger an
   immediate cancellation with `sts:cnl` so callers cannot continue with stale
   guard state. */
bool
cep_ep_resume_rw(cepEID eid)
{
    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode || episode->closed || episode->policy.profile != CEP_EP_PROFILE_RW) {
        return false;
    }
    if (!episode->context_suspended || episode->context_tls_bound) {
        return false;
    }

    cep_ep_bind_tls_context(episode, false);

    for (cepEpLease* lease = episode->leases; lease; lease = lease->next) {
        if (lease->needs_store_reacquire) {
            if (!cep_store_lock(lease->cell, &lease->store_token)) {
                goto reacquire_fail;
            }
            lease->lock_store = true;
            lease->needs_store_reacquire = false;
            lease->reacquired_store = true;
        }
        if (lease->needs_data_reacquire) {
            if (!cep_data_lock(lease->cell, &lease->data_token)) {
                goto reacquire_fail;
            }
            lease->lock_data = true;
            lease->needs_data_reacquire = false;
            lease->reacquired_data = true;
        }
    }

    for (cepEpLease* lease = episode->leases; lease; lease = lease->next) {
        lease->reacquired_store = false;
        lease->reacquired_data = false;
    }

    episode->context_suspended = false;
    return true;

reacquire_fail:
    for (cepEpLease* lease = episode->leases; lease; lease = lease->next) {
        if (lease->reacquired_store) {
            cep_store_unlock(lease->cell, &lease->store_token);
            memset(&lease->store_token, 0, sizeof lease->store_token);
            lease->lock_store = false;
            lease->needs_store_reacquire = true;
            lease->reacquired_store = false;
        }
        if (lease->reacquired_data) {
            cep_data_unlock(lease->cell, &lease->data_token);
            memset(&lease->data_token, 0, sizeof lease->data_token);
            lease->lock_data = false;
            lease->needs_data_reacquire = true;
            lease->reacquired_data = false;
        }
    }

    cep_ep_unbind_tls_context(episode);
    episode->context_suspended = true;
    (void)cep_ep_cancel_for_runtime(episode->runtime, eid, -3, "lease reacquire failed");
    return false;
}

/* Close an episode with the provided terminal status. The helper defers actual
   teardown until the currently running slice unwinds so invariants around
   context cleanup remain intact. */
bool
cep_ep_close(cepEID eid, cepDT status, const void* summary, size_t summary_len)
{
    cepEpRwScope scope = cep_ep_rw_scope_begin();
   bool ok = false;

    if (!cep_dt_is_valid(&status)) {
        CEP_DEBUG_PRINTF("[cep_ep_close] invalid status\n");
        goto out;
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode) {
        CEP_DEBUG_PRINTF("[cep_ep_close] episode missing\n");
        goto out;
    }

    cepDT clean_status = cep_dt_clean(&status);
    if (!cep_op_close(eid, clean_status, summary, summary_len)) {
        CEP_DEBUG_PRINTF("[cep_ep_close] op_close failed err=%d\n", cep_ops_debug_last_error());
        goto out;
    }

    episode->closed = true;
    episode->pending_state = CEP_EP_PENDING_COMPLETED;
    if (!episode->in_slice) {
        cep_ep_episode_remove(cep_ep_state_for_runtime(episode->runtime), episode);
    } else {
        episode->remove_after_slice = true;
    }
    ok = true;

out:
    cep_ep_rw_scope_end(&scope);
    return ok;
}

/* Cancel an episode in-flight, propagating a cooperative cancellation request
   and closing the dossier with `sts:cnl`. */
bool
cep_ep_cancel_for_runtime(cepRuntime* runtime, cepEID eid, int code, const char* note)
{
    if (!runtime) {
        runtime = cep_ep_runtime_current();
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(runtime, eid);
    if (!episode || episode->closed) {
        return false;
    }

    if (episode->ticket) {
        (void)cep_executor_cancel(episode->ticket);
        episode->ticket = 0u;
    }

    (void)cep_ep_mark_state(eid, "ist:cxl", code, note);
    episode->pending_state = CEP_EP_PENDING_CANCELLED;
    cepDT cancel_status = cep_ops_make_dt("sts:cnl");
    (void)cep_ep_close(eid, cancel_status, NULL, 0u);
    return true;
}

bool
cep_ep_cancel(cepEID eid, int code, const char* note)
{
    return cep_ep_cancel_for_runtime(cep_ep_runtime_current(), eid, code, note);
}

/* Request cancellation from inside a running slice so the executor can stop
   scheduling additional work for the same ticket. */
void
cep_ep_request_cancel(void)
{
    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx) {
        return;
    }
    if (ctx->ticket) {
        (void)cep_executor_cancel(ctx->ticket);
    } else {
        atomic_store(&ctx->cancel_requested, true);
    }
}

/* Schedule an asynchronous ticket cancellation for a queued slice. */
bool
cep_ep_cancel_ticket(cepExecutorTicket ticket)
{
    if (!ticket) {
        return false;
    }
    return cep_executor_cancel(ticket);
}

/* Report whether the current slice observes a cancellation request so long-
   running loops can bail out cooperatively. */
bool
cep_ep_check_cancel(void)
{
    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx) {
        return false;
    }
    return atomic_load(&ctx->cancel_requested);
}

void
cep_ep_runtime_reset(void)
{
    cepRuntime* runtime = cep_ep_runtime_current();
    cepEpRuntimeState* state = cep_ep_state_for_runtime(runtime);
    if (!state) {
        return;
    }

    while (state->episodes) {
        cepEpEpisode* episode = state->episodes;
        cep_ep_episode_remove(state, episode);
    }

    while (state->await_bindings) {
        cepEpAwaitBinding* binding = state->await_bindings;
        state->await_bindings = binding->next;
        cep_free(binding);
    }

    state->runtime_ready = false;
    state->executor_ready = false;
    state->enzyme_registered = false;
    memset(&state->signal_ep_cont, 0, sizeof state->signal_ep_cont);
    memset(&state->signal_op_tmo, 0, sizeof state->signal_op_tmo);
    atomic_store_explicit(&state->last_lease_fail_reason, NULL, memory_order_relaxed);

    cepEpExecutionContext* previous_ctx = cep_executor_context_get();
    cepRuntime* target_runtime = runtime ? runtime : cep_runtime_default();
    cepEpExecutionContext shim_ctx = {0};
    shim_ctx.runtime = target_runtime;
    cepRuntime* previous_runtime_scope = cep_runtime_set_active(target_runtime);
    cep_executor_context_set(&shim_ctx);
    cep_executor_shutdown();
    if (previous_ctx) {
        cep_executor_context_set(previous_ctx);
    } else {
        cep_executor_context_clear();
    }
    cep_runtime_restore_active(previous_runtime_scope);
}

bool
cep_ep_episode_has_active_lease(const void* episode_ptr)
{
    const cepEpEpisode* episode = (const cepEpEpisode*)episode_ptr;
    if (!episode) {
        return true;
    }
    return episode->leases != NULL;
}

bool
cep_ep_episode_record_violation(void* episode_ptr)
{
    cepEpEpisode* episode = (cepEpEpisode*)episode_ptr;
    if (!episode) {
        return false;
    }
    if (episode->lease_violation_reported) {
        return false;
    }
    episode->lease_violation_reported = true;
    return true;
}

void
cep_ep_episode_clear_violation(void* episode_ptr)
{
    cepEpEpisode* episode = (cepEpEpisode*)episode_ptr;
    if (!episode) {
        return;
    }
    episode->lease_violation_reported = false;
}

static void
cep_ep_emit_io_overrun(const cepEpExecutionContext* ctx)
{
    if (!ctx) {
        return;
    }

    char note[160];
    snprintf(note,
             sizeof note,
             "io budget exceeded: consumed=%zu bytes budget=%zu bytes",
             ctx->io_consumed_bytes,
             ctx->io_budget_bytes);

    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:usage"),
        .topic = "ep:budget/io",
        .topic_intern = true,
        .note = note,
        .emit_signal = false,
        .ttl_forever = true,
    };
    cep_cei_emit(&req);
}

/* Track staged I/O volume for the current slice and trip the cancellation
   flag once the configured budget is exceeded. */
void
cep_ep_account_io(size_t bytes)
{
    if (!bytes) {
        return;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx) {
        return;
    }

    if (SIZE_MAX - ctx->io_consumed_bytes < bytes) {
        ctx->io_consumed_bytes = SIZE_MAX;
    } else {
        ctx->io_consumed_bytes += bytes;
    }

    if (ctx->io_budget_bytes && ctx->io_consumed_bytes > ctx->io_budget_bytes) {
        bool already = atomic_load(&ctx->cancel_requested);
        atomic_store(&ctx->cancel_requested, true);
        if (!already) {
            cep_ep_emit_io_overrun(ctx);
        }
    }
}

bool
cep_ep_promote_to_rw(cepEID eid,
                     const cepEpLeaseRequest* requests,
                     size_t request_count,
                     uint32_t flags)
{
    if (flags != CEP_EP_PROMOTE_FLAG_NONE) {
        return false;
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode || episode->closed) {
        return false;
    }
    if (episode->policy.profile != CEP_EP_PROFILE_HYBRID) {
        return false;
    }

    if (request_count && !requests) {
        return false;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->user_data != episode) {
        return false;
    }

    if (episode->mode_current == CEP_EP_PROFILE_RW) {
        for (size_t i = 0; i < request_count; ++i) {
            if (!requests[i].path) {
                return false;
            }
            if (!cep_ep_request_lease(eid,
                                      requests[i].path,
                                      requests[i].lock_store,
                                      requests[i].lock_data,
                                      requests[i].include_descendants)) {
                return false;
            }
        }
        return true;
    }

    if (episode->mode_current != CEP_EP_PROFILE_RO) {
        return false;
    }

    cepEpLeaseRequestNode* new_head = NULL;
    cepEpLeaseRequestNode* new_tail = NULL;
    for (size_t i = 0; i < request_count; ++i) {
        const cepPath* request_path = requests[i].path;
        cepCell* request_cell = NULL;
        if (requests[i].cell) {
            request_cell = cep_cell_resolve((cepCell*)requests[i].cell);
        }
        if (!request_path && !request_cell) {
            while (new_head) {
                cepEpLeaseRequestNode* next = new_head->next;
                if (new_head->path) {
                    cep_free(new_head->path);
                }
                cep_free(new_head);
                new_head = next;
            }
            return false;
        }

        cepPath* cloned = NULL;
        if (request_path) {
            if (!cep_ep_path_clone(request_path, &cloned)) {
                while (new_head) {
                    cepEpLeaseRequestNode* next = new_head->next;
                    if (new_head->path) {
                        cep_free(new_head->path);
                    }
                    cep_free(new_head);
                    new_head = next;
                }
                return false;
            }
        } else {
            if (!cep_cell_path(request_cell, &cloned)) {
                while (new_head) {
                    cepEpLeaseRequestNode* next = new_head->next;
                    if (new_head->path) {
                        cep_free(new_head->path);
                    }
                    cep_free(new_head);
                    new_head = next;
                }
                return false;
            }
            request_path = cloned;
        }

        cepEpLeaseRequestNode* node = cep_malloc(sizeof *node);
        if (!node) {
            cep_free(cloned);
            while (new_head) {
                cepEpLeaseRequestNode* next = new_head->next;
                if (new_head->path) {
                    cep_free(new_head->path);
                }
                cep_free(new_head);
                new_head = next;
            }
            return false;
        }

        node->path = cloned;
        node->cell = request_cell;
        node->lock_store = requests[i].lock_store;
        node->lock_data = requests[i].lock_data;
        node->include_descendants = requests[i].include_descendants;
        node->next = NULL;

        if (!new_head) {
            new_head = node;
        } else {
            new_tail->next = node;
        }
        new_tail = node;
    }

    if (new_tail) {
        if (!episode->pending_lease_requests) {
            episode->pending_lease_requests = new_head;
        } else {
            cepEpLeaseRequestNode* tail = episode->pending_lease_requests;
            while (tail->next) {
                tail = tail->next;
            }
            tail->next = new_head;
        }
    }

    if (episode->mode_next == CEP_EP_PROFILE_RW) {
        return true;
    }

    episode->mode_next = CEP_EP_PROFILE_RW;
    if (!cep_ep_yield(eid, NULL)) {
        episode->mode_next = episode->mode_current;
        cep_ep_pending_leases_clear(episode);
        return false;
    }

    return true;
}

bool
cep_ep_demote_to_ro(cepEID eid, uint32_t flags)
{
    if (flags != CEP_EP_DEMOTE_FLAG_NONE) {
        return false;
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(NULL, eid);
    if (!episode || episode->closed) {
        return false;
    }
    if (episode->policy.profile != CEP_EP_PROFILE_HYBRID) {
        return false;
    }

    if (episode->mode_current == CEP_EP_PROFILE_RO) {
        return true;
    }
    if (episode->mode_current != CEP_EP_PROFILE_RW) {
        return false;
    }

    if (episode->leases) {
        return false;
    }
    if (episode->pending_lease_requests) {
        return false;
    }
    if (episode->context_suspended) {
        return false;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->user_data != episode) {
        return false;
    }

    if (episode->mode_next == CEP_EP_PROFILE_RO) {
        return true;
    }

    episode->mode_next = CEP_EP_PROFILE_RO;
    if (!cep_ep_yield(eid, NULL)) {
        episode->mode_next = episode->mode_current;
        return false;
    }
    return true;
}

/* Write through to the staging stream helper while enforcing the active
   episode's read/write profile. */
bool
cep_ep_stream_write(cepCell* cell,
                    uint64_t offset,
                    const void* src,
                    size_t size,
                    size_t* out_written)
{
    return cep_cell_stream_write(cell, offset, src, size, out_written);
}

/* Flush all staged stream writes so they become visible at the next commit
   boundary. */
bool
cep_ep_stream_commit_pending(void)
{
    return cep_stream_commit_pending();
}

/* Drop any buffered staged stream writes accumulated during the current slice. */
void
cep_ep_stream_clear_pending(void)
{
    cep_stream_clear_pending();
}

/* Report how many stream staging buffers are currently outstanding for the
   calling slice. */
size_t
cep_ep_stream_pending_count(void)
{
    return cep_stream_pending_count();
}
