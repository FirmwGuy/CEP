/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_runtime.h"

#include "cep_cell.h"
#include "cep_branch_controller.h"
#include "cep_ep.h"
#include "cep_heartbeat.h"
#include "cep_heartbeat_internal.h"
#include "cep_async.h"
#include "cep_io_reactor.h"
#include "../enzymes/cep_l0_organs.h"
#include "cep_namepool.h"
#include "cep_namepool_runtime.h"
#include "cep_organ.h"
#include "cep_organ.h"
#include "../cps/cps_runtime.h"

#include <stdint.h>
#include <string.h>

struct cepExecutorRuntimeState* cep_executor_state_create(void);
void cep_executor_state_destroy(struct cepExecutorRuntimeState* state);

typedef struct cepFederationRuntimeState {
    void* transport_registry;
    void* mock_provider_queue;
} cepFederationRuntimeState;

CEP_DEFINE_STATIC_DT(dt_runtime_meta_type, CEP_ACRO("CEP"), CEP_WORD("rt_ctx"));

typedef struct {
    uint64_t  magic;
    uintptr_t runtime_ptr;
    uintptr_t root_ptr;
} cepRuntimeMetadata;

static const uint64_t CEP_RUNTIME_METADATA_MAGIC = UINT64_C(0x435052544D455441);

static cepFederationRuntimeState*
cep_federation_state_create(void)
{
    return cep_malloc0(sizeof(cepFederationRuntimeState));
}

static void
cep_federation_state_destroy(cepFederationRuntimeState* state)
{
    if (!state) {
        return;
    }
    cep_free(state);
}

struct cepRuntime {
    cepCell                     root;
    cepOpCount                  op_count;
    cepHeartbeatRuntime         heartbeat;
    cepControlRuntimeState      control_state;
    cepHeartbeatTopology        default_topology;
    struct cepNamePoolRuntimeState* namepool_state;
    struct cepOrganRegistryState*   organ_registry;
    struct cepExecutorRuntimeState* executor_state;
    struct cepFederationRuntimeState* federation_state;
    struct cepAsyncRuntimeState* async_state;
    cepBranchControllerRegistry* branch_registry;
    cepMailboxRuntimeSettings   mailbox_settings;
    cepSerializationRuntimeState serialization_state;
    cepEpRuntimeState           ep_state;
    bool                        heartbeat_initialised;
    bool                        l0_bootstrap_done;
};

static cepRuntime CEP_RUNTIME_DEFAULT = {0};
static _Thread_local cepRuntime* CEP_RUNTIME_ACTIVE = NULL;

static const cepCell*
cep_runtime_canonical_root(const cepCell* cell)
{
    if (!cell) {
        return NULL;
    }

    const cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical) {
        return NULL;
    }

    for (const cepCell* parent = cep_cell_parent(canonical);
         parent;
         parent = cep_cell_parent(parent)) {
        canonical = parent;
    }

    return canonical;
}

static const cepRuntimeMetadata*
cep_runtime_metadata_payload(const cepCell* canonical_root)
{
    if (!canonical_root) {
        return NULL;
    }

    const cepData* data = canonical_root->data;
    if (!data || data->datatype != CEP_DATATYPE_DATA) {
        return NULL;
    }

    const cepRuntimeMetadata* payload =
        (const cepRuntimeMetadata*)cep_data_payload(data);
    if (!payload) {
        return NULL;
    }

    if (payload->magic != CEP_RUNTIME_METADATA_MAGIC) {
        return NULL;
    }

    if ((const cepCell*)(uintptr_t)payload->root_ptr != canonical_root) {
        return NULL;
    }

    return payload;
}

cepRuntime*
cep_runtime_default(void)
{
    return CEP_RUNTIME_ACTIVE ? CEP_RUNTIME_ACTIVE : &CEP_RUNTIME_DEFAULT;
}

cepRuntime*
cep_runtime_create(void)
{
    cepRuntime* runtime = cep_malloc0(sizeof *runtime);
    return runtime;
}

void
cep_runtime_destroy(cepRuntime* runtime)
{
    if (!runtime) {
        return;
    }
    cep_runtime_shutdown(runtime);
    if (CEP_RUNTIME_ACTIVE == runtime) {
        CEP_RUNTIME_ACTIVE = NULL;
    }
    if (runtime != &CEP_RUNTIME_DEFAULT) {
        cep_free(runtime);
    }
}

cepRuntime*
cep_runtime_set_active(cepRuntime* runtime)
{
    cepRuntime* previous = CEP_RUNTIME_ACTIVE;
    CEP_RUNTIME_ACTIVE = runtime;
    return previous;
}

void
cep_runtime_restore_active(cepRuntime* runtime)
{
    CEP_RUNTIME_ACTIVE = runtime;
}

cepRuntime*
cep_runtime_active(void)
{
    return CEP_RUNTIME_ACTIVE ? CEP_RUNTIME_ACTIVE : &CEP_RUNTIME_DEFAULT;
}

cepCell*
cep_runtime_root(cepRuntime* runtime)
{
    return runtime ? &runtime->root : NULL;
}

cepOpCount*
cep_runtime_op_counter(cepRuntime* runtime)
{
    return runtime ? &runtime->op_count : NULL;
}

cepHeartbeatRuntime*
cep_runtime_heartbeat(cepRuntime* runtime)
{
    if (!runtime) {
        return NULL;
    }

    cepHeartbeatRuntime* heartbeat = &runtime->heartbeat;
    if (!runtime->heartbeat_initialised) {
        memset(heartbeat, 0, sizeof *heartbeat);
        heartbeat->current = CEP_BEAT_INVALID;
        heartbeat->phase = CEP_BEAT_CAPTURE;
        heartbeat->last_wallclock_beat = CEP_BEAT_INVALID;
        heartbeat->view_horizon = CEP_BEAT_INVALID;
        heartbeat->policy.ensure_directories = true;
        heartbeat->policy.boot_ops = true;
        heartbeat->policy.spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
        heartbeat->spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
        runtime->heartbeat_initialised = true;
    }
    return heartbeat;
}

struct cepControlRuntimeState*
cep_runtime_control_state(cepRuntime* runtime)
{
    return runtime ? &runtime->control_state : NULL;
}

cepHeartbeatTopology*
cep_runtime_default_topology(cepRuntime* runtime)
{
    return runtime ? &runtime->default_topology : NULL;
}

struct cepNamePoolRuntimeState*
cep_runtime_namepool_state(cepRuntime* runtime)
{
    if (!runtime) {
        return NULL;
    }
    if (!runtime->namepool_state) {
        runtime->namepool_state = cep_namepool_state_create();
    }
    return runtime->namepool_state;
}

cepMailboxRuntimeSettings*
cep_runtime_mailbox_settings(cepRuntime* runtime)
{
    if (!runtime) {
        return NULL;
    }
    cepMailboxRuntimeSettings* settings = &runtime->mailbox_settings;
    if (!settings->initialised) {
        settings->wallclock_disabled = false;
        settings->beat_lookahead = 32u;
        settings->spacing_samples = 8u;
        settings->cei_debug_last_error = 0;
        settings->initialised = true;
    }
    return settings;
}

cepSerializationRuntimeState*
cep_runtime_serialization_state(cepRuntime* runtime)
{
    if (!runtime) {
        return NULL;
    }
    return &runtime->serialization_state;
}

cepEpRuntimeState*
cep_runtime_ep_state(cepRuntime* runtime)
{
    if (!runtime) {
        return NULL;
    }
    return &runtime->ep_state;
}

struct cepOrganRegistryState*
cep_runtime_organ_registry(cepRuntime* runtime)
{
    if (!runtime) {
        return NULL;
    }
    if (!runtime->organ_registry) {
        runtime->organ_registry = cep_organ_registry_create();
    }
    return runtime->organ_registry;
}

struct cepExecutorRuntimeState*
cep_runtime_executor_state(cepRuntime* runtime)
{
    if (!runtime) {
        return NULL;
    }
    if (!runtime->executor_state) {
        runtime->executor_state = cep_executor_state_create();
    }
    return runtime->executor_state;
}

bool
cep_runtime_has_executor_state(const cepRuntime* runtime)
{
    const cepRuntime* target = runtime ? runtime : cep_runtime_default();
    return target && target->executor_state != NULL;
}

struct cepFederationRuntimeState*
cep_runtime_federation_state(cepRuntime* runtime)
{
    cepRuntime* target = runtime ? runtime : cep_runtime_default();
    if (!target->federation_state) {
        target->federation_state = cep_federation_state_create();
    }
    return target->federation_state;
}

struct cepAsyncRuntimeState*
cep_runtime_async_state(cepRuntime* runtime)
{
    cepRuntime* target = runtime ? runtime : cep_runtime_default();
    if (!target->async_state) {
        target->async_state = cep_async_state_create();
    }
    return target->async_state;
}

cepBranchControllerRegistry*
cep_runtime_branch_registry(cepRuntime* runtime)
{
    cepRuntime* target = runtime ? runtime : cep_runtime_default();
    if (!target) {
        return NULL;
    }
    if (!target->branch_registry) {
        target->branch_registry = cep_branch_registry_create();
    }
    return target->branch_registry;
}

cepBranchController*
cep_runtime_track_data_branch(cepCell* branch_root)
{
    if (!branch_root) {
        return NULL;
    }
    cepRuntime* runtime = cep_runtime_default();
    cepBranchControllerRegistry* registry = cep_runtime_branch_registry(runtime);
    if (!registry) {
        return NULL;
    }
    const cepDT* branch_name =
        cep_dt_is_valid(&branch_root->metacell.dt) ? &branch_root->metacell.dt : NULL;
    cepBranchController* controller =
        cep_branch_registry_register(registry, branch_root, branch_name);
    if (!controller) {
        return NULL;
    }
    if (cep_branch_lazy_boot_claim(&controller->branch_dt)) {
        controller->policy.mode = CEP_BRANCH_PERSIST_LAZY_LOAD;
        controller->policy.lazy_load_at_boot = true;
    }
    if (cep_branch_snapshot_policy_requested(&controller->branch_dt)) {
        (void)cep_branch_controller_enable_snapshot_mode(controller);
    }
    return controller;
}

bool
cep_runtime_bootstrap_is_done(cepRuntime* runtime)
{
    cepRuntime* target = runtime ? runtime : cep_runtime_default();
    return target->l0_bootstrap_done;
}

void
cep_runtime_bootstrap_mark_done(cepRuntime* runtime, bool done)
{
    cepRuntime* target = runtime ? runtime : cep_runtime_default();
    target->l0_bootstrap_done = done;
}

/* Ensure the canonical root cell carries a runtime metadata payload so any
   caller can rediscover the owning runtime without relying on process-wide
   singletons. The helper refreshes the payload if it is missing or stale while
   keeping the data hidden behind the existing root-payload guard. */
bool
cep_runtime_attach_metadata(cepRuntime* runtime)
{
    if (!runtime) {
        return false;
    }

    cepCell* root = cep_runtime_root(runtime);
    const cepCell* canonical_root = cep_runtime_canonical_root(root);
    if (!canonical_root || cep_cell_is_void(canonical_root)) {
        return false;
    }

    const cepRuntimeMetadata* existing =
        cep_runtime_metadata_payload(canonical_root);
    if (existing) {
        cepRuntime* recorded =
            (cepRuntime*)(uintptr_t)existing->runtime_ptr;
        if (recorded == runtime) {
            return true;
        }

        cepData* stale = canonical_root->data;
        if (stale) {
            cep_data_del(stale);
        }
        ((cepCell*)canonical_root)->data = NULL;
    }

    const cepRuntimeMetadata metadata = {
        .magic       = CEP_RUNTIME_METADATA_MAGIC,
        .runtime_ptr = (uintptr_t)runtime,
        .root_ptr    = (uintptr_t)canonical_root,
    };

    cepDT meta_type = *dt_runtime_meta_type();
    cepData* stored = cep_data_new(&meta_type,
                                   CEP_DATATYPE_DATA,
                                   false,
                                   NULL,
                                   (void*)&metadata,
                                   sizeof metadata,
                                   sizeof metadata,
                                   NULL);
    if (!stored) {
        return false;
    }

    ((cepCell*)canonical_root)->data = stored;
    return true;
}

static void
cep_runtime_detach_metadata(cepRuntime* runtime)
{
    if (!runtime) {
        return;
    }

    cepCell* root = cep_runtime_root(runtime);
    const cepCell* canonical_root = cep_runtime_canonical_root(root);
    if (!canonical_root || cep_cell_is_void(canonical_root)) {
        return;
    }

    const cepData* payload = canonical_root->data;
    if (!payload) {
        return;
    }

    cep_data_del((cepData*)payload);
    ((cepCell*)canonical_root)->data = NULL;
}

cepRuntime*
cep_runtime_from_root(const cepCell* root)
{
    const cepCell* canonical = cep_runtime_canonical_root(root);
    if (!canonical) {
        return NULL;
    }

    const cepRuntimeMetadata* payload =
        cep_runtime_metadata_payload(canonical);
    if (payload) {
        cepRuntime* runtime =
            (cepRuntime*)(uintptr_t)payload->runtime_ptr;
        if (runtime) {
            return runtime;
        }
    }

    cepRuntime* default_runtime = cep_runtime_default();
    if (canonical == &default_runtime->root) {
        if (cep_runtime_attach_metadata(default_runtime)) {
            const cepRuntimeMetadata* refreshed =
                cep_runtime_metadata_payload(canonical);
            if (refreshed) {
                return (cepRuntime*)(uintptr_t)refreshed->runtime_ptr;
            }
        }
        return default_runtime;
    }

    return NULL;
}

cepRuntime*
cep_runtime_from_cell(const cepCell* cell)
{
    if (!cell) {
        return NULL;
    }

    const cepCell* canonical = cep_runtime_canonical_root(cell);
    return cep_runtime_from_root(canonical);
}

void
cep_runtime_shutdown(cepRuntime* runtime)
{
    if (!runtime) {
        runtime = cep_runtime_default();
    }

    CEP_DEBUG_PRINTF_STDOUT("[instrument][runtime_shutdown] enter runtime=%p default=%p active=%p organ_state=%p namepool_state=%p\n",
           (void*)runtime,
           (void*)cep_runtime_default(),
           (void*)cep_runtime_active(),
           (void*)runtime->organ_registry,
           (void*)runtime->namepool_state);
    bool is_default_runtime = (runtime == &CEP_RUNTIME_DEFAULT);

    cepEpExecutionContext* previous_ctx = cep_executor_context_get();
    cepEpExecutionContext shim_ctx = {0};
    shim_ctx.runtime = runtime;
    shim_ctx.profile = CEP_EP_PROFILE_RW;
    shim_ctx.allow_without_lease = true;
    cepRuntime* previous_runtime_scope = cep_runtime_set_active(runtime);
    cep_executor_context_set(&shim_ctx);

    cep_runtime_detach_metadata(runtime);
    (void)cep_io_reactor_quiesce(0u);
    cep_ep_runtime_reset();
    cep_organ_runtime_reset();
    cep_l0_organs_unbind_roots();
    cepHeartbeatRuntime* heartbeat_state = cep_runtime_heartbeat(runtime);
    cep_heartbeat_release_signal_dts(heartbeat_state);
    cepCell* rt_root = cep_heartbeat_rt_root();
    if (rt_root && cep_cell_is_normal(rt_root) && rt_root->store) {
        cep_store_delete_children_hard(rt_root->store);
    }
    cep_heartbeat_release_runtime(heartbeat_state);
    if (!is_default_runtime) {
        cepCell* root_cell = cep_runtime_root(runtime);
        if (root_cell && !cep_cell_is_void(root_cell)) {
            cep_cell_finalize_hard(root_cell);
            CEP_0(root_cell);
        }
    }

    if (previous_ctx) {
        cep_executor_context_set(previous_ctx);
    } else {
        cep_executor_context_clear();
    }

    cep_runtime_restore_active(previous_runtime_scope);

    cps_runtime_shutdown();

    if (runtime->executor_state) {
        cep_executor_state_destroy(runtime->executor_state);
        runtime->executor_state = NULL;
    }

    if (runtime->organ_registry) {
        cep_organ_registry_destroy(runtime->organ_registry);
        runtime->organ_registry = NULL;
        CEP_DEBUG_PRINTF_STDOUT("[instrument][runtime_shutdown] organ_registry_destroyed runtime=%p\n", (void*)runtime);
    }

    if (runtime->namepool_state) {
        cep_namepool_state_destroy(runtime->namepool_state);
        runtime->namepool_state = NULL;
    }

    if (runtime->federation_state) {
        cep_federation_state_destroy(runtime->federation_state);
        runtime->federation_state = NULL;
    }
    cep_io_reactor_shutdown();

    if (runtime->async_state) {
        cep_async_state_destroy(runtime->async_state);
        runtime->async_state = NULL;
    }
    cep_async_reset_ops_oid();

    if (runtime->branch_registry) {
        cep_branch_registry_destroy(runtime->branch_registry);
        runtime->branch_registry = NULL;
    }

    if (runtime->serialization_state.comparator_registry.entries) {
        cep_free(runtime->serialization_state.comparator_registry.entries);
        runtime->serialization_state.comparator_registry.entries = NULL;
    }
    runtime->serialization_state.comparator_registry.count = 0;
    runtime->serialization_state.comparator_registry.capacity = 0;
    runtime->serialization_state.comparators_initialized = false;

    runtime->heartbeat_initialised = false;
    runtime->l0_bootstrap_done = false;
    memset(&runtime->heartbeat, 0, sizeof runtime->heartbeat);
    memset(&runtime->control_state, 0, sizeof runtime->control_state);
    memset(&runtime->default_topology, 0, sizeof runtime->default_topology);
    memset(&runtime->mailbox_settings, 0, sizeof runtime->mailbox_settings);
    memset(&runtime->serialization_state, 0, sizeof runtime->serialization_state);
    memset(&runtime->ep_state, 0, sizeof runtime->ep_state);
    CEP_DEBUG_PRINTF_STDOUT("[instrument][runtime_shutdown] exit runtime=%p\n", (void*)runtime);
}
