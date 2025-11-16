/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef CEP_BRANCH_CONTROLLER_H
#define CEP_BRANCH_CONTROLLER_H

#include "cep_heartbeat.h"
#include "cep_cell.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief Per-branch persistence controller scaffolding.
 */

typedef enum {
    CEP_BRANCH_PERSIST_DURABLE = 0,
    CEP_BRANCH_PERSIST_VOLATILE,
    CEP_BRANCH_PERSIST_COMMIT_ONCE,
    CEP_BRANCH_PERSIST_LAZY_LOAD,
    CEP_BRANCH_PERSIST_LAZY_SAVE,
    CEP_BRANCH_PERSIST_SCHEDULED_SAVE,
    CEP_BRANCH_PERSIST_ON_DEMAND,
    CEP_BRANCH_PERSIST_MODE_COUNT,
} cepBranchPersistMode;

typedef struct {
    cepBranchPersistMode mode;
    uint32_t             flush_every_beats;
    bool                 flush_on_shutdown;
    bool                 lazy_load_at_boot;
    bool                 allow_volatile_reads;
} cepBranchPersistPolicy;

typedef enum {
    CEP_BRANCH_FLUSH_CAUSE_UNKNOWN = 0,
    CEP_BRANCH_FLUSH_CAUSE_AUTOMATIC,
    CEP_BRANCH_FLUSH_CAUSE_MANUAL,
    CEP_BRANCH_FLUSH_CAUSE_SCHEDULED,
    CEP_BRANCH_FLUSH_CAUSE_COUNT,
} cepBranchFlushCause;

typedef struct {
    cepCell*    cell;
    uint32_t    flags;
    cepOpCount  stamp;
} cepBranchDirtyEntry;

typedef struct {
    cepBranchDirtyEntry* entries;
    size_t               count;
    size_t               capacity;
} cepBranchDirtyIndex;

typedef struct cepBranchController {
    cepDT                  branch_dt;
    cepCell*               branch_root;
    cepBranchPersistPolicy policy;
    cepBranchDirtyIndex    dirty_index;
    cepBeatNumber          last_persisted_bt;
    cepBeatNumber          flush_scheduled_bt;
    uint64_t               dirty_entry_count;
    uint64_t               dirty_bytes;
    uint64_t               pending_mutations;
    uint64_t               pins;
    uint64_t               version;
    cepOpCount             last_frame_id;
    cepBranchFlushCause    last_flush_cause;
    bool                   registered;
    bool                   pinned;
    bool                   force_flush;
} cepBranchController;

typedef struct cepBranchControllerRegistry cepBranchControllerRegistry;

#define CEP_BRANCH_DIRTY_FLAG_DATA  UINT32_C(0x01)
#define CEP_BRANCH_DIRTY_FLAG_STORE UINT32_C(0x02)

cepBranchControllerRegistry* cep_branch_registry_create(void);
void                          cep_branch_registry_destroy(cepBranchControllerRegistry* registry);
void                          cep_branch_registry_reset(cepBranchControllerRegistry* registry);
size_t                        cep_branch_registry_count(const cepBranchControllerRegistry* registry);

cepBranchController* cep_branch_registry_register(cepBranchControllerRegistry* registry,
                                                   cepCell* branch_root,
                                                   const cepDT* branch_name);
cepBranchController* cep_branch_registry_find_by_root(const cepBranchControllerRegistry* registry,
                                                      const cepCell* branch_root);
cepBranchController* cep_branch_registry_find_by_dt(const cepBranchControllerRegistry* registry,
                                                    const cepDT* branch_dt);

bool cep_branch_registry_bind_existing_children(cepBranchControllerRegistry* registry,
                                                cepCell* data_root);

const cepBranchPersistPolicy* cep_branch_controller_policy(const cepBranchController* controller);
void                          cep_branch_controller_set_policy(cepBranchController* controller,
                                                               const cepBranchPersistPolicy* policy);
bool cep_branch_controller_mark_dirty(cepBranchController* controller,
                                      cepCell* cell,
                                      uint32_t flags);
cepBranchController* cep_branch_registry_controller(const cepBranchControllerRegistry* registry,
                                                    size_t index);
const cepBranchDirtyEntry* cep_branch_controller_dirty_entries(const cepBranchController* controller,
                                                               size_t* count);
void cep_branch_controller_clear_dirty(cepBranchController* controller);

#ifdef __cplusplus
}
#endif

#endif /* CEP_BRANCH_CONTROLLER_H */
