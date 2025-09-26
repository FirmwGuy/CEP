/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */

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
    cepHeartbeatTopology      topology;
    cepHeartbeatPolicy        policy;
    cepEnzymeRegistry*        registry;
    cepHeartbeatImpulseQueue  inbox_current;
    cepHeartbeatImpulseQueue  inbox_next;
    cepHeartbeatScratch       scratch;
    bool                      running;
} cepHeartbeatRuntime;


/**
 * @brief Configure the heartbeat runtime prior to bootstrapping.
 */
bool  cep_heartbeat_configure(const cepHeartbeatTopology* topology, const cepHeartbeatPolicy* policy);
/**
 * @brief Create required directories and seed runtime state under the policy.
 */
bool  cep_heartbeat_bootstrap(void);
/**
 * @brief Start the heartbeat loop using the supplied topology and policy.
 */
bool  cep_heartbeat_startup(void);
/**
 * @brief Restart the heartbeat loop without destroying runtime scaffolding.
 */
bool  cep_heartbeat_restart(void);
/**
 * @brief Prepare runtime state to process the supplied beat number.
 */
bool  cep_heartbeat_begin(cepBeatNumber beat);
/**
 * @brief Resolve the execution agenda for the current beat.
 */
bool  cep_heartbeat_resolve_agenda(void);
/**
 * @brief Execute the enzymes scheduled during agenda resolution.
 */
bool  cep_heartbeat_execute_agenda(void);
/**
 * @brief Stage committed changes so they become visible in the next beat.
 */
bool  cep_heartbeat_stage_commit(void);
/**
 * @brief Convenience helper that runs resolve, execute and stage for one beat.
 */
bool  cep_heartbeat_step(void);
/**
 * @brief Stop the heartbeat runtime and release temporary allocations.
 */
void  cep_heartbeat_shutdown(void);


cepBeatNumber               cep_heartbeat_current(void);
cepBeatNumber               cep_heartbeat_next(void);
const cepHeartbeatPolicy*   cep_heartbeat_policy(void);
const cepHeartbeatTopology* cep_heartbeat_topology(void);
cepEnzymeRegistry*          cep_heartbeat_registry(void);


/**
 * @brief Queue a signal/target pair for processing on the selected beat.
 */
int   cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath* signal_path, const cepPath* target_path);
/**
 * @brief Queue a fully materialised impulse for future processing.
 */
int   cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepImpulse* impulse);
/**
 * @brief Drain the current inbox, resolving newly enqueued impulses.
 */
bool  cep_heartbeat_process_impulses(void);


/**
 * @brief Convenience accessors for well-known subtrees within the topology.
 */
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
