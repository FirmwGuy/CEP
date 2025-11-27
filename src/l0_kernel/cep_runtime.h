/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_RUNTIME_H
#define CEP_RUNTIME_H

#include "cep_ops.h"
#include "cep_heartbeat.h"
#include "cep_executor.h"
#include <stdatomic.h>
#include <stdint.h>

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cepRuntime cepRuntime;

struct _cepCell;
struct cepControlRuntimeState;
struct cepNamePoolRuntimeState;
struct cepEpEpisode;
struct cepEpAwaitBinding;
struct cepOrganRegistryState;
struct cepExecutorRuntimeState;
struct cepFederationRuntimeState;
struct cepAsyncRuntimeState;
typedef struct cepBranchController cepBranchController;
typedef struct cepBranchControllerRegistry cepBranchControllerRegistry;
typedef struct {
    bool      wallclock_disabled;
    uint32_t  beat_lookahead;
    uint32_t  spacing_samples;
    int       cei_debug_last_error;
    bool      initialised;
} cepMailboxRuntimeSettings;

typedef struct {
    cepCompareInfo info;
    cepCompare     comparator;
} cepComparatorRegistryEntry;

typedef struct {
    cepComparatorRegistryEntry* entries;
    size_t                      count;
    size_t                      capacity;
} cepComparatorRegistry;

typedef struct {
    cepBeatNumber          marked_decision_beat;
    cepComparatorRegistry  comparator_registry;
    bool                   comparators_initialized;
    _Atomic uint32_t       emit_active;
    _Atomic uint32_t       replay_active;
} cepSerializationRuntimeState;

typedef struct {
    struct cepEpEpisode*      episodes;
    struct cepEpAwaitBinding* await_bindings;
    bool                      runtime_ready;
    bool                      executor_ready;
    bool                      enzyme_registered;
    cepDT                     signal_ep_cont;
    cepDT                     signal_op_tmo;
    cepEpExecutionPolicy      default_policy;
    bool                      default_policy_initialized;
    _Atomic(const char*)      last_lease_fail_reason;
} cepEpRuntimeState;

cepRuntime*    cep_runtime_default(void);
cepRuntime*    cep_runtime_create(void);
void           cep_runtime_destroy(cepRuntime* runtime);
cepRuntime*    cep_runtime_set_active(cepRuntime* runtime);
void           cep_runtime_restore_active(cepRuntime* runtime);
cepRuntime*    cep_runtime_active(void);

struct _cepCell* cep_runtime_root(cepRuntime* runtime);
cepOpCount*      cep_runtime_op_counter(cepRuntime* runtime);
bool             cep_runtime_attach_metadata(cepRuntime* runtime);
cepHeartbeatRuntime*    cep_runtime_heartbeat(cepRuntime* runtime);
struct cepControlRuntimeState* cep_runtime_control_state(cepRuntime* runtime);
cepHeartbeatTopology*   cep_runtime_default_topology(cepRuntime* runtime);
struct cepNamePoolRuntimeState* cep_runtime_namepool_state_existing(cepRuntime* runtime);
struct cepNamePoolRuntimeState* cep_runtime_namepool_state(cepRuntime* runtime);
bool             cep_runtime_has_namepool_state(const cepRuntime* runtime);
void             cep_runtime_release_namepool_state(cepRuntime* runtime);
cepMailboxRuntimeSettings* cep_runtime_mailbox_settings(cepRuntime* runtime);
cepSerializationRuntimeState* cep_runtime_serialization_state(cepRuntime* runtime);
cepEpRuntimeState* cep_runtime_ep_state(cepRuntime* runtime);
struct cepOrganRegistryState* cep_runtime_organ_registry_existing(cepRuntime* runtime);
struct cepOrganRegistryState* cep_runtime_organ_registry(cepRuntime* runtime);
bool             cep_runtime_has_organ_registry(const cepRuntime* runtime);
void             cep_runtime_release_organ_registry(cepRuntime* runtime);
struct cepExecutorRuntimeState* cep_runtime_executor_state(cepRuntime* runtime);
bool                    cep_runtime_has_executor_state(const cepRuntime* runtime);
struct cepFederationRuntimeState* cep_runtime_federation_state(cepRuntime* runtime);
struct cepAsyncRuntimeState* cep_runtime_async_state(cepRuntime* runtime);
cepBranchControllerRegistry* cep_runtime_branch_registry(cepRuntime* runtime);
cepBranchController* cep_runtime_track_data_branch(cepCell* branch_root);
bool           cep_runtime_bootstrap_is_done(cepRuntime* runtime);
void           cep_runtime_bootstrap_mark_done(cepRuntime* runtime, bool done);
cepRuntime*      cep_runtime_from_root(const struct _cepCell* root);
cepRuntime*      cep_runtime_from_cell(const struct _cepCell* cell);
void             cep_runtime_shutdown(cepRuntime* runtime);

#ifdef __cplusplus
}
#endif

#endif /* CEP_RUNTIME_H */
