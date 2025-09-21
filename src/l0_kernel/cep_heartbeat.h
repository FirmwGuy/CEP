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


typedef uint64_t cepBeatNumber;

#define CEP_BEAT_INVALID  ((cepBeatNumber)UINT64_MAX)


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


typedef struct {
    cepBeatNumber       start_at;
    bool                ensure_directories;
    bool                enforce_visibility;
} cepHeartbeatPolicy;

typedef struct {
    cepPath* signal_path;
    cepPath* target_path;
} cepHeartbeatImpulseRecord;


typedef struct {
    cepHeartbeatImpulseRecord* records;
    size_t                     count;
    size_t                     capacity;
} cepHeartbeatImpulseQueue;


typedef struct {
    cepBeatNumber             current;
    cepHeartbeatTopology      topology;
    cepHeartbeatPolicy        policy;
    cepEnzymeRegistry*        registry;
    cepHeartbeatImpulseQueue  inbox_current;
    cepHeartbeatImpulseQueue  inbox_next;
    bool                      running;
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
