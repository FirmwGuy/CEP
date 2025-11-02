/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_HEARTBEAT_INTERNAL_H
#define CEP_HEARTBEAT_INTERNAL_H

#include "cep_heartbeat.h"
#include "cep_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT 256u

typedef enum {
    CEP_CTRL_PHASE_IDLE = 0,
    CEP_CTRL_PHASE_PLAN,
    CEP_CTRL_PHASE_APPLY,
    CEP_CTRL_PHASE_STEADY,
    CEP_CTRL_PHASE_CLOSING,
} cepControlPhase;

typedef enum {
    CEP_ROLLBACK_STAGE_IDLE = 0,
    CEP_ROLLBACK_STAGE_EXAMINE,
    CEP_ROLLBACK_STAGE_PRUNE,
    CEP_ROLLBACK_STAGE_CUTOVER,
    CEP_ROLLBACK_STAGE_STEADY,
    CEP_ROLLBACK_STAGE_FAILED,
} cepRollbackStage;

typedef struct cepControlOpState {
    cepOID          oid;
    bool            started;
    bool            closed;
    bool            failed;
    cepControlPhase phase;
    cepBeatNumber   last_beat;
    cepDT           verb_dt;
    bool            diag_emitted;
} cepControlOpState;

typedef struct cepControlRuntimeState {
    cepControlOpState pause;
    cepControlOpState resume;
    cepControlOpState rollback;
    bool              gating_active;
    bool              paused_published;
    bool              locks_acquired;
    bool              drain_requested;
    bool              backlog_dirty;
    bool              agenda_noted;
    bool              cleanup_pending;
    bool              backlog_cleanup_pending;
    bool              data_cleanup_pending;
    bool              gc_pending;
    cepLockToken      store_lock;
    cepLockToken      data_lock;
    cepBeatNumber     rollback_target;
    cepRollbackStage  rollback_stage;
} cepControlRuntimeState;

void                cep_heartbeat_impulse_record_clear(cepHeartbeatImpulseRecord* record);
void                cep_heartbeat_impulse_queue_reset(cepHeartbeatImpulseQueue* queue);
void                cep_heartbeat_impulse_queue_destroy(cepHeartbeatImpulseQueue* queue);
bool                cep_heartbeat_impulse_queue_append(cepHeartbeatImpulseQueue* queue, const cepImpulse* impulse);
void                cep_heartbeat_impulse_queue_swap(cepHeartbeatImpulseQueue* a, cepHeartbeatImpulseQueue* b);

#ifdef __cplusplus
}
#endif

#endif
