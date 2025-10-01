/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_HEARTBEAT_H
#define CEP_HEARTBEAT_H


#include "cep_cell.h"
#include "cep_enzyme.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief Heartbeat runtime configuration and scheduling APIs.
 */


/**
 * @brief Sequential identifier for a heartbeat cycle.
 */
typedef uint64_t cepBeatNumber;

#define CEP_BEAT_INVALID  ((cepBeatNumber)UINT64_MAX)


/**
 * @brief Enumerates the three-phase heartbeat contract (Capture -> Compute -> Commit).
 */
typedef enum {
    CEP_BEAT_CAPTURE = 0,
    CEP_BEAT_COMPUTE = 1,
    CEP_BEAT_COMMIT  = 2,
} cepBeatPhase;


/**
 * @struct cepHeartbeatTopology
 * @brief Logical directories that compose the CEP runtime tree.
 */
typedef struct {
    cepCell* root;
    cepCell* sys;
    cepCell* rt;
    cepCell* journal;
    cepCell* env;
    cepCell* cas;
    cepCell* lib;
    cepCell* data;
    cepCell* tmp;
    cepCell* enzymes;
} cepHeartbeatTopology;


/**
 * @struct cepHeartbeatPolicy
 * @brief Behavioural knobs that influence heartbeat execution.
 */
typedef struct {
    cepBeatNumber       start_at;
    bool                ensure_directories;
    bool                enforce_visibility;
} cepHeartbeatPolicy;

/**
 * @struct cepHeartbeatImpulseRecord
 * @brief Lightweight storage for a queued signal/target pair.
 */
typedef struct {
    cepPath* signal_path;
    cepPath* target_path;
} cepHeartbeatImpulseRecord;


/**
 * @struct cepHeartbeatImpulseQueue
 * @brief Expandable buffer that backs heartbeat inboxes.
 */
typedef struct {
    cepHeartbeatImpulseRecord* records;
    size_t                     count;
    size_t                     capacity;
} cepHeartbeatImpulseQueue;


/**
 * @struct cepHeartbeatDescriptorMemo
 * @brief Memoisation for descriptor execution state within a beat.
 */
typedef struct {
    uint8_t executed;   /* Memoises whether the descriptor already ran this beat. */
    uint8_t emitted;    /* Tracks if the descriptor emitted follow-up signals. */
    int     last_rc;    /* Stores the most recent return code for duplicate detections. */
} cepHeartbeatDescriptorMemo;


/**
 * @struct cepHeartbeatDispatchCacheEntry
 * @brief Cache entry that accelerates agenda resolution for repeated impulses.
 */
typedef struct {
    uint8_t                      used;
    size_t                       stamp;
    uint64_t                     hash;
    cepPath*                     signal_path;
    cepPath*                     target_path;
    const cepEnzymeDescriptor**  descriptors;
    size_t                       descriptor_count;
    size_t                       descriptor_capacity;
    cepHeartbeatDescriptorMemo*  memo;
    size_t                       memo_count;
    size_t                       memo_capacity;
} cepHeartbeatDispatchCacheEntry;


/**
 * @struct cepHeartbeatScratch
 * @brief Scratch buffers reused across agenda resolution phases.
 */
typedef struct {
    cepHeartbeatDispatchCacheEntry*  entries;
    size_t                           entry_capacity;
    size_t                           generation;
    const cepEnzymeDescriptor**      ordered;
    size_t                           ordered_capacity;
} cepHeartbeatScratch;


/**
 * @struct cepHeartbeatRuntime
 * @brief Aggregate structure representing the live heartbeat runtime.
 */
typedef struct {
    cepBeatNumber             current;
    cepBeatPhase              phase;
    cepHeartbeatTopology      topology;
    cepHeartbeatPolicy        policy;
    cepEnzymeRegistry*        registry;
    cepHeartbeatImpulseQueue  inbox_current;
    cepHeartbeatImpulseQueue  inbox_next;
    cepHeartbeatScratch       scratch;
    bool                      running;
    size_t                    deferred_activations;
} cepHeartbeatRuntime;


bool  cep_heartbeat_configure(const cepHeartbeatTopology* topology, const cepHeartbeatPolicy* policy);
bool  cep_heartbeat_bootstrap(void);
bool  cep_heartbeat_startup(void);
bool  cep_heartbeat_restart(void);
bool  cep_heartbeat_begin(cepBeatNumber beat);
bool  cep_heartbeat_resolve_agenda(void);
bool  cep_heartbeat_execute_agenda(void);
bool  cep_heartbeat_stage_commit(void);
bool  cep_heartbeat_step(void);
void  cep_heartbeat_shutdown(void);


cepOpCount   cep_beat_index(void);
cepBeatPhase cep_beat_phase(void);
size_t       cep_beat_deferred_activation_count(void);
void         cep_beat_note_deferred_activation(size_t count);
void         cep_beat_begin_capture(void);
void         cep_beat_begin_compute(void);
void         cep_beat_begin_commit(void);


cepBeatNumber               cep_heartbeat_current(void);
cepBeatNumber               cep_heartbeat_next(void);
const cepHeartbeatPolicy*   cep_heartbeat_policy(void);
const cepHeartbeatTopology* cep_heartbeat_topology(void);
cepEnzymeRegistry*          cep_heartbeat_registry(void);


int   cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath* signal_path, const cepPath* target_path);
int   cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepImpulse* impulse);
bool  cep_heartbeat_process_impulses(void);


cepCell*  cep_heartbeat_sys_root(void);
cepCell*  cep_heartbeat_rt_root(void);
cepCell*  cep_heartbeat_journal_root(void);
cepCell*  cep_heartbeat_env_root(void);
cepCell*  cep_heartbeat_data_root(void);
cepCell*  cep_heartbeat_cas_root(void);
cepCell*  cep_heartbeat_tmp_root(void);
cepCell*  cep_heartbeat_enzymes_root(void);


#ifdef __cplusplus
}
#endif


#endif
