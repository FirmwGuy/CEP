#include "cep_ep.h"

#include "cep_cei.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_ops.h"
#include "cep_molecule.h"
#include "stream/cep_stream_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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
    cepEpExecutionPolicy    policy;
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
    struct cepEpLease*   next;
} cepEpLease;

typedef struct cepEpAwaitBinding {
    cepOID                      awaited_oid;
    cepEpEpisode*               episode;
    struct cepEpAwaitBinding*   next;
} cepEpAwaitBinding;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast past[1];
} cepEpPathBuf;

static cepEpEpisode*      cep_ep_episodes;
static cepEpAwaitBinding* cep_ep_await_bindings;
static bool               cep_ep_runtime_ready;
static bool               cep_ep_executor_ready;
static bool               cep_ep_enzyme_registered;
static cepDT              cep_ep_signal_ep_cont;
static cepDT              cep_ep_signal_op_tmo;

static cepEpEpisode* cep_ep_episode_lookup(cepEID eid);
static void          cep_ep_episode_append(cepEpEpisode* episode);
static void          cep_ep_episode_remove(cepEpEpisode* episode);
static cepEpAwaitBinding* cep_ep_binding_lookup(cepOID awaited_oid);
static void          cep_ep_binding_add(cepOID awaited_oid, cepEpEpisode* episode);
static void          cep_ep_binding_remove(cepOID awaited_oid, cepEpEpisode* episode);
static void          cep_ep_binding_remove_episode(cepEpEpisode* episode);
static bool          cep_ep_runtime_init(void);
static bool          cep_ep_register_enzyme(const char* signal_tag,
                                            cepEnzyme callback,
                                            cepDT* out_name);
static bool          cep_ep_bind_operation(cepOID oid);
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
cep_ep_runtime_init(void)
{
    if (cep_ep_runtime_ready) {
        return true;
    }

    if (!cep_ep_executor_ready) {
        if (!cep_executor_init()) {
            return false;
        }
        cep_ep_executor_ready = true;
    }

    if (!cep_ep_enzyme_registered) {
        cepDT ep_cont = {0};
        if (!cep_ep_register_enzyme("ep/cont", cep_ep_continuation_enzyme, &ep_cont)) {
            return false;
        }
        cep_ep_signal_ep_cont = ep_cont;

        cepDT op_tmo = {0};
        if (!cep_ep_register_enzyme("op/tmo", cep_ep_continuation_enzyme, &op_tmo)) {
            return false;
        }
        cep_ep_signal_op_tmo = op_tmo;

        cep_ep_enzyme_registered = true;
    }

    cep_ep_runtime_ready = true;
    return true;
}

static bool
cep_ep_bind_operation(cepOID oid)
{
    cepEpRwScope scope = cep_ep_rw_scope_begin();
    bool ok = false;

    cepCell* op_cell = cep_ep_find_op_cell(oid);
    if (!op_cell) {
        goto out;
    }

    cepCell* resolved = cep_cell_resolve(op_cell);
    if (resolved) {
        op_cell = resolved;
    }

    cepDT cont_name = cep_dt_is_valid(&cep_ep_signal_ep_cont)
        ? cep_dt_clean(&cep_ep_signal_ep_cont)
        : cep_ops_make_dt("ep/cont");
    if (cep_cell_bind_enzyme(op_cell, &cont_name, false) != CEP_ENZYME_SUCCESS) {
        goto out;
    }

    cepDT tmo_name = cep_dt_is_valid(&cep_ep_signal_op_tmo)
        ? cep_dt_clean(&cep_ep_signal_op_tmo)
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
        }
        if (lease->lock_data) {
            cep_data_unlock(lease->cell, &lease->data_token);
        }
        if (lease->path) {
            cep_free(lease->path);
        }
        cep_free(lease);
        lease = next;
    }
    episode->leases = NULL;
    episode->lease_violation_reported = false;
}

static cepEpEpisode*
cep_ep_episode_lookup(cepEID eid)
{
    for (cepEpEpisode* node = cep_ep_episodes; node; node = node->next) {
        if (node->eid.domain == eid.domain && node->eid.tag == eid.tag) {
            return node;
        }
    }
    return NULL;
}

static void
cep_ep_episode_append(cepEpEpisode* episode)
{
    episode->next = cep_ep_episodes;
    cep_ep_episodes = episode;
}

static void
cep_ep_episode_remove(cepEpEpisode* episode)
{
    if (!episode) {
        return;
    }

    if (episode->ticket) {
        (void)cep_executor_cancel(episode->ticket);
        episode->ticket = 0u;
    }

    cep_ep_binding_remove_episode(episode);

    cepEpEpisode** head = &cep_ep_episodes;
    while (*head) {
        if (*head == episode) {
            *head = episode->next;
            break;
        }
        head = &(*head)->next;
    }

    cep_ep_release_all_leases(episode);
    cep_free(episode);
}

static cepEpAwaitBinding*
cep_ep_binding_lookup(cepOID awaited_oid)
{
    for (cepEpAwaitBinding* node = cep_ep_await_bindings; node; node = node->next) {
        if (node->awaited_oid.domain == awaited_oid.domain &&
            node->awaited_oid.tag == awaited_oid.tag) {
            return node;
        }
    }
    return NULL;
}

static void
cep_ep_binding_add(cepOID awaited_oid, cepEpEpisode* episode)
{
    cepEpAwaitBinding* binding = cep_malloc(sizeof *binding);
    binding->awaited_oid = awaited_oid;
    binding->episode = episode;
    binding->next = cep_ep_await_bindings;
    cep_ep_await_bindings = binding;
}

static void
cep_ep_binding_remove(cepOID awaited_oid, cepEpEpisode* episode)
{
    cepEpAwaitBinding** head = &cep_ep_await_bindings;
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
cep_ep_binding_remove_episode(cepEpEpisode* episode)
{
    cepEpAwaitBinding** head = &cep_ep_await_bindings;
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
        if (policy->profile == CEP_EP_PROFILE_RO || policy->profile == CEP_EP_PROFILE_RW) {
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
    cepDT cont = cep_dt_is_valid(&cep_ep_signal_ep_cont)
        ? cep_dt_clean(&cep_ep_signal_ep_cont)
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
        (void)cep_ep_cancel(episode->eid, -1, "max beats exceeded");
        return false;
    }

    episode->pending_state = CEP_EP_PENDING_RUNNING;
    episode->beats_used += 1u;

    if (episode->policy.profile == CEP_EP_PROFILE_RO) {
        if (episode->ticket) {
            return true;
        }
        if (!cep_executor_submit_ro(cep_ep_run_slice_task, episode, &episode->policy, &episode->ticket)) {
            (void)cep_ep_cancel(episode->eid, -2, "executor queue full");
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
cep_ep_set_tls_context(cepEpEpisode* episode, cepEpExecutionContext* context)
{
    context->profile = episode->policy.profile;
    context->cpu_budget_ns = episode->policy.cpu_budget_ns;
    context->io_budget_bytes = episode->policy.io_budget_bytes;
    context->user_data = episode;
    context->cpu_consumed_ns = 0u;
    context->io_consumed_bytes = 0u;
    context->allow_without_lease = false;
    atomic_store(&context->cancel_requested, false);
    context->ticket = episode->ticket;
    cep_executor_context_set(context);
}

static void
cep_ep_clear_tls_context(void)
{
    cep_executor_context_clear();
}

static void
cep_ep_execute_cooperative(cepEpEpisode* episode)
{
    cepEpExecutionContext context = {0};
    cep_ep_set_tls_context(episode, &context);
    cep_ep_run_slice_impl(episode);
    cep_ep_clear_tls_context();
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

    episode->callback(episode->eid, episode->user_ctx);

    if (episode->policy.profile == CEP_EP_PROFILE_RO) {
        episode->ticket = 0u;
    }

    cep_ep_finalize_slice(episode);
}

static void
cep_ep_finalize_slice(cepEpEpisode* episode)
{
    if (!episode) {
        return;
    }

    episode->in_slice = false;

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
        cep_ep_episode_remove(episode);
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
    const bool have_ep_cont = cep_dt_is_valid(&cep_ep_signal_ep_cont);
    const bool have_op_tmo = cep_dt_is_valid(&cep_ep_signal_op_tmo);

    cepDT ep_cont_dt = have_ep_cont
        ? cep_dt_clean(&cep_ep_signal_ep_cont)
        : cep_dt_clean(CEP_DTAW("CEP", "ep/cont"));
    if (cep_dt_compare(&signal, &ep_cont_dt) == 0) {
        cepEpEpisode* episode = cep_ep_episode_lookup(target_oid);
        if (episode) {
            return cep_ep_schedule_run(episode, NULL);
        }

        bool routed = false;
        while (true) {
            cepEpAwaitBinding* binding = cep_ep_binding_lookup(target_oid);
            if (!binding) {
                break;
            }
            cepEpEpisode* waiting = binding->episode;
            cep_ep_binding_remove(target_oid, waiting);
            waiting->awaited_oid = cep_oid_invalid();
            waiting->pending_state = CEP_EP_PENDING_RUNNING;
            if (cep_ep_schedule_run(waiting, NULL)) {
                routed = true;
            }
        }
        return routed;
    }

    cepDT op_tmo_dt = have_op_tmo
        ? cep_dt_clean(&cep_ep_signal_op_tmo)
        : cep_dt_clean(CEP_DTAW("CEP", "op/tmo"));
    if (cep_dt_compare(&signal, &op_tmo_dt) == 0) {
        bool cancelled = false;

        while (true) {
            cepEpAwaitBinding* binding = cep_ep_binding_lookup(target_oid);
            if (!binding) {
                break;
            }
            cepEpEpisode* waiting = binding->episode;
            cep_ep_binding_remove(target_oid, waiting);
            waiting->awaited_oid = cep_oid_invalid();
            waiting->pending_state = CEP_EP_PENDING_CANCELLED;
            if (cep_ep_cancel(waiting->eid, -3, "await timeout")) {
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

    if (!cep_ep_runtime_init()) {
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

    if (!cep_ep_bind_operation(eid)) {
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
    episode->policy = effective;
    episode->max_beats = max_beats;
    episode->pending_state = CEP_EP_PENDING_RUNNING;
    episode->awaited_oid = cep_oid_invalid();

    cep_ep_episode_append(episode);
    *out_eid = eid;

    if (!cep_ep_schedule_run(episode, "start")) {
        cepEpEpisode* retained = cep_ep_episode_lookup(eid);
        if (retained == episode) {
            CEP_DEBUG_PRINTF("[cep_ep_start] schedule failed retained episode\n");
            (void)cep_op_close(eid, fail_status, NULL, 0u);
            cep_ep_episode_remove(episode);
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
    cepEpEpisode* episode = cep_ep_episode_lookup(eid);
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

    cepEpEpisode* episode = cep_ep_episode_lookup(eid);
    if (!episode || episode->closed) {
        return false;
    }

    cepEpExecutionContext* ctx = cep_executor_context_get();
    if (!ctx || ctx->user_data != episode) {
        return false;
    }

    if (!cep_ep_binding_lookup(awaited_oid)) {
        if (!cep_ep_bind_operation(awaited_oid)) {
            return false;
        }
    }

    cepDT want_clean = cep_dt_clean(&want_state);
    cepDT cont = cep_dt_is_valid(&cep_ep_signal_ep_cont)
        ? cep_dt_clean(&cep_ep_signal_ep_cont)
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
    cep_ep_binding_add(awaited_oid, episode);
    return true;
}

bool
cep_ep_request_lease(cepEID eid,
                     const cepPath* root,
                     bool lock_store,
                     bool lock_data,
                     bool include_descendants)
{
#define CEP_EP_LEASE_FAIL(code)                                    \
    do {                                                           \
        CEP_DEBUG_PRINTF("[cep_ep_request_lease] %s\n", code);     \
        return false;                                              \
    } while (0)

    if (!cep_oid_is_valid(eid) || !root || root->length == 0u) {
        CEP_EP_LEASE_FAIL("invalid-input");
    }
    if (!lock_store && !lock_data) {
        CEP_EP_LEASE_FAIL("no-locks");
    }

    cepEpEpisode* episode = cep_ep_episode_lookup(eid);
    if (!episode || episode->closed || episode->policy.profile != CEP_EP_PROFILE_RW) {
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

    cepCell* target = NULL;
    if (lookup_path && lookup_path->length) {
        target = cep_cell_find_by_path(cep_root(), lookup_path);
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

    cepEpEpisode* episode = cep_ep_episode_lookup(eid);
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

    cepEpEpisode* episode = cep_ep_episode_lookup(eid);
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
        cep_ep_episode_remove(episode);
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
cep_ep_cancel(cepEID eid, int code, const char* note)
{
    cepEpEpisode* episode = cep_ep_episode_lookup(eid);
    if (!episode || episode->closed) {
        return false;
    }

    if (episode->ticket) {
        (void)cep_executor_cancel(episode->ticket);
        episode->ticket = 0u;
    }

    (void)cep_ep_mark_state(eid, "ist:cxl", code, note);
    cepDT cancel_status = cep_ops_make_dt("sts:cnl");
    (void)cep_ep_close(eid, cancel_status, NULL, 0u);
    episode->pending_state = CEP_EP_PENDING_CANCELLED;
    return true;
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
    while (cep_ep_episodes) {
        cepEpEpisode* episode = cep_ep_episodes;
        cep_ep_episode_remove(episode);
    }

    while (cep_ep_await_bindings) {
        cepEpAwaitBinding* binding = cep_ep_await_bindings;
        cep_ep_await_bindings = binding->next;
        cep_free(binding);
    }

    cep_ep_runtime_ready = false;
    cep_ep_executor_ready = false;
    cep_ep_enzyme_registered = false;
    memset(&cep_ep_signal_ep_cont, 0, sizeof cep_ep_signal_ep_cont);
    memset(&cep_ep_signal_op_tmo, 0, sizeof cep_ep_signal_op_tmo);

    cep_executor_shutdown();
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
