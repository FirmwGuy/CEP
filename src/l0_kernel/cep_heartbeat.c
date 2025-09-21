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


#include "cep_heartbeat.h"




static cepHeartbeatRuntime CEP_RUNTIME = {
    .current = CEP_BEAT_INVALID,
};




static bool cep_runtime_has_registry(void) {
    return CEP_RUNTIME.registry != NULL;
}


static void cep_runtime_reset_state(void) {
    if (cep_runtime_has_registry()) {
        cep_enzyme_registry_destroy(CEP_RUNTIME.registry);
    }

    CEP_RUNTIME.registry = NULL;
    CEP_RUNTIME.current = CEP_BEAT_INVALID;
    CEP_RUNTIME.running = false;
    memset(&CEP_RUNTIME.topology, 0, sizeof(CEP_RUNTIME.topology));
    memset(&CEP_RUNTIME.policy, 0, sizeof(CEP_RUNTIME.policy));
}


bool cep_heartbeat_configure(const cepHeartbeatTopology* topology, const cepHeartbeatPolicy* policy) {
    if (!topology || !policy) {
        return false;
    }

    CEP_RUNTIME.topology = *topology;
    CEP_RUNTIME.policy = *policy;
    return true;
}


bool cep_heartbeat_startup(void) {
    if (!cep_runtime_has_registry()) {
        CEP_RUNTIME.registry = cep_enzyme_registry_create();
        if (!CEP_RUNTIME.registry) {
            return false;
        }
    }

    CEP_RUNTIME.current = CEP_RUNTIME.policy.start_at;
    CEP_RUNTIME.running = true;
    return true;
}


bool cep_heartbeat_begin(cepBeatNumber beat) {
    if (!cep_runtime_has_registry()) {
        return false;
    }

    CEP_RUNTIME.current = beat;
    CEP_RUNTIME.running = true;
    return true;
}


bool cep_heartbeat_resolve_agenda(void) {
    return CEP_RUNTIME.running;
}


bool cep_heartbeat_execute_agenda(void) {
    return CEP_RUNTIME.running;
}


bool cep_heartbeat_stage_commit(void) {
    return CEP_RUNTIME.running;
}


bool cep_heartbeat_step(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    bool ok = cep_heartbeat_resolve_agenda();
    ok = ok && cep_heartbeat_execute_agenda();
    ok = ok && cep_heartbeat_stage_commit();

    if (ok && CEP_RUNTIME.current != CEP_BEAT_INVALID) {
        CEP_RUNTIME.current += 1u;
    }

    return ok;
}


void cep_heartbeat_shutdown(void) {
    cep_runtime_reset_state();
}


cepBeatNumber cep_heartbeat_current(void) {
    return CEP_RUNTIME.current;
}


cepBeatNumber cep_heartbeat_next(void) {
    if (CEP_RUNTIME.current == CEP_BEAT_INVALID) {
        return CEP_BEAT_INVALID;
    }

    return CEP_RUNTIME.current + 1u;
}


const cepHeartbeatPolicy* cep_heartbeat_policy(void) {
    return &CEP_RUNTIME.policy;
}


const cepHeartbeatTopology* cep_heartbeat_topology(void) {
    return &CEP_RUNTIME.topology;
}


cepEnzymeRegistry* cep_heartbeat_registry(void) {
    return CEP_RUNTIME.registry;
}


int cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath* signal_path, const cepPath* target_path) {
    (void)beat;
    (void)signal_path;
    (void)target_path;
    return CEP_ENZYME_FATAL;
}


int cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepEnzymeImpulse* impulse) {
    (void)beat;
    (void)impulse;
    return CEP_ENZYME_FATAL;
}


cepCell* cep_heartbeat_sys_root(void) {
    return CEP_RUNTIME.topology.sys;
}


cepCell* cep_heartbeat_rt_root(void) {
    return CEP_RUNTIME.topology.rt;
}


cepCell* cep_heartbeat_journal_root(void) {
    return CEP_RUNTIME.topology.journal;
}


cepCell* cep_heartbeat_env_root(void) {
    return CEP_RUNTIME.topology.env;
}


cepCell* cep_heartbeat_data_root(void) {
    return CEP_RUNTIME.topology.data;
}


cepCell* cep_heartbeat_cas_root(void) {
    return CEP_RUNTIME.topology.cas;
}


cepCell* cep_heartbeat_tmp_root(void) {
    return CEP_RUNTIME.topology.tmp;
}


cepCell* cep_heartbeat_enzymes_root(void) {
    return CEP_RUNTIME.topology.enzymes;
}

