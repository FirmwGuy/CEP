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
    CEP_BRANCH_PERSIST_RO_SNAPSHOT,
    CEP_BRANCH_PERSIST_MODE_COUNT,
} cepBranchPersistMode;

typedef struct {
    cepBranchPersistMode mode;
    uint32_t             flush_every_beats;
    bool                 flush_on_shutdown;
    bool                 lazy_load_at_boot;
    bool                 allow_volatile_reads;
    uint32_t             history_ram_beats;
    uint32_t             history_ram_versions;
    uint64_t             ram_quota_bytes;
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
    cepBeatNumber          periodic_anchor_bt;
    cepBeatNumber          last_eviction_bt;
    uint64_t               dirty_entry_count;
    uint64_t               dirty_bytes;
    uint64_t               pending_mutations;
    uint64_t               pins;
    uint64_t               last_flush_bytes;
    uint64_t               last_flush_pins;
    uint64_t               version;
    cepOpCount             last_frame_id;
    cepBranchFlushCause    last_flush_cause;
    bool                   registered;
    bool                   pinned;
    bool                   force_flush;
    uint32_t               cached_history_beats;
    uint32_t               cached_history_versions;
    uint64_t               cached_history_bytes;
} cepBranchController;

typedef struct cepBranchControllerRegistry cepBranchControllerRegistry;

#define CEP_BRANCH_DIRTY_FLAG_DATA  UINT32_C(0x01)
#define CEP_BRANCH_DIRTY_FLAG_STORE UINT32_C(0x02)

typedef enum {
    CEP_BRANCH_POLICY_ACCESS_ALLOW = 0,
    CEP_BRANCH_POLICY_ACCESS_DECISION,
    CEP_BRANCH_POLICY_ACCESS_DENY,
} cepBranchPolicyAccess;

typedef enum {
    CEP_BRANCH_POLICY_RISK_NONE = 0,
    CEP_BRANCH_POLICY_RISK_DIRTY,
    CEP_BRANCH_POLICY_RISK_VOLATILE,
} cepBranchPolicyRisk;

typedef struct {
    cepBranchPolicyAccess access;
    cepBranchPolicyRisk   risk;
} cepBranchPolicyResult;

#define CEP_CELL_SVO_SUBJECT_MAX 96u

/**
 * Tracks context for source/verb operations so branch policy guards can attach
 * Decision Cell evidence to risky cross-branch reads before allowing them to
 * proceed.
 */
typedef struct {
    const cepBranchController* consumer;
    const cepBranchController* source;
    const char*                verb;
    cepBranchPolicyResult      last_result;
    bool                       decision_required;
    bool                       decision_recorded;
    const cepDT*               security_branch;
    const char*                subject_id;
    char                       subject_label[CEP_CELL_SVO_SUBJECT_MAX];
} cepCellSvoContext;

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
bool cep_branch_snapshot_policy_requested(const cepDT* branch_dt);

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
bool cep_branch_controller_enable_snapshot_mode(cepBranchController* controller);
void cep_branch_controller_apply_eviction(cepBranchController* controller);
cepBranchController* cep_branch_controller_for_cell(const cepCell* cell);
bool cep_cell_is_under_security_branch(const cepCell* cell);
cepBranchController* cep_branch_controller_for_security_cell(const cepCell* cell);
cepBranchPolicyResult cep_branch_policy_check_read(const cepBranchController* consumer,
                                                   const cepBranchController* source);
const char* cep_branch_policy_risk_label(cepBranchPolicyRisk risk);
void cep_branch_controller_format_label(const cepBranchController* controller,
                                        char* buffer,
                                        size_t capacity);
void cep_cell_svo_context_init(cepCellSvoContext* ctx, const char* verb);
void cep_cell_svo_context_set_consumer(cepCellSvoContext* ctx, const cepCell* consumer_cell);
void cep_cell_svo_context_set_source(cepCellSvoContext* ctx, const cepCell* source_cell);
bool cep_cell_svo_context_guard(cepCellSvoContext* ctx,
                                const cepCell* fallback_source,
                                const char* topic);
bool cep_decision_cell_record_cross_branch(const cepBranchController* consumer,
                                           const cepBranchController* source,
                                           const char* verb,
                                           cepBranchPolicyRisk risk);
bool cep_decision_cell_replay_begin(void);
void cep_decision_cell_replay_end(void);
bool cep_branch_lazy_boot_register(const cepDT* branch_dt);
bool cep_branch_lazy_boot_claim(const cepDT* branch_dt);
void cep_branch_lazy_boot_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_BRANCH_CONTROLLER_H */
