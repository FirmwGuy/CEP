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

static cepHeartbeatTopology CEP_DEFAULT_TOPOLOGY;


static bool cep_runtime_has_registry(void) {
    return CEP_RUNTIME.registry != NULL;
}


static void cep_runtime_reset_state(bool destroy_registry) {
    if (destroy_registry && cep_runtime_has_registry()) {
        cep_enzyme_registry_destroy(CEP_RUNTIME.registry);
        CEP_RUNTIME.registry = NULL;
    }

    CEP_RUNTIME.current = CEP_BEAT_INVALID;
    CEP_RUNTIME.running = false;

    memset(&CEP_RUNTIME.topology, 0, sizeof(CEP_RUNTIME.topology));
    memset(&CEP_RUNTIME.policy, 0, sizeof(CEP_RUNTIME.policy));
}


static void cep_runtime_reset_defaults(void) {
    memset(&CEP_DEFAULT_TOPOLOGY, 0, sizeof(CEP_DEFAULT_TOPOLOGY));
}


static cepCell* ensure_root_dictionary(cepCell* root, const cepDT* name) {
    cepCell* cell = cep_cell_find_by_name(root, name);
    if (!cell) {
        cell = cep_cell_add_dictionary(root, (cepDT*)name, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    }
    return cell;
}


static cepCell* ensure_root_list(cepCell* root, const cepDT* name) {
    cepCell* cell = cep_cell_find_by_name(root, name);
    if (!cell) {
        cell = cep_cell_add_list(root, (cepDT*)name, 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_LINKED_LIST);
    }
    return cell;
}


static void cep_heartbeat_clear_store(cepCell* cell) {
    if (!cell) {
        return;
    }

    if (cell->store) {
        cep_store_delete_children_hard(cell->store);
    }
}


static void cep_heartbeat_reset_runtime_cells(void) {
    /* Keep the structural nodes but clear their contents. */
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.rt);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.journal);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.tmp);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.data);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.cas);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.env);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.lib);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.enzymes);
}


/* Establishes the heartbeat runtime by wiring up the root cells and lazy
 * allocating the enzyme registry so every public entry point works from a
 * consistent topology baseline.
 */
bool cep_heartbeat_bootstrap(void) {
    cep_cell_system_ensure();

    cepCell* root = cep_root();
    CEP_DEFAULT_TOPOLOGY.root = root;
    if (!CEP_RUNTIME.topology.root) {
        CEP_RUNTIME.topology.root = root;
    }

    const cepDT* sys_name = CEP_DTAW("CEP", "sys");
    cepCell* sys = ensure_root_dictionary(root, sys_name);
    CEP_DEFAULT_TOPOLOGY.sys = sys;
    if (!CEP_RUNTIME.topology.sys) {
        CEP_RUNTIME.topology.sys = sys;
    }

    const cepDT* rt_name = CEP_DTAW("CEP", "rt");
    cepCell* rt = ensure_root_dictionary(root, rt_name);
    CEP_DEFAULT_TOPOLOGY.rt = rt;
    if (!CEP_RUNTIME.topology.rt) {
        CEP_RUNTIME.topology.rt = rt;
    }

    const cepDT* journal_name = CEP_DTAW("CEP", "journal");
    cepCell* journal = ensure_root_dictionary(root, journal_name);
    CEP_DEFAULT_TOPOLOGY.journal = journal;
    if (!CEP_RUNTIME.topology.journal) {
        CEP_RUNTIME.topology.journal = journal;
    }

    const cepDT* env_name = CEP_DTAW("CEP", "env");
    cepCell* env = ensure_root_dictionary(root, env_name);
    CEP_DEFAULT_TOPOLOGY.env = env;
    if (!CEP_RUNTIME.topology.env) {
        CEP_RUNTIME.topology.env = env;
    }

    const cepDT* cas_name = CEP_DTAW("CEP", "cas");
    cepCell* cas = ensure_root_dictionary(root, cas_name);
    CEP_DEFAULT_TOPOLOGY.cas = cas;
    if (!CEP_RUNTIME.topology.cas) {
        CEP_RUNTIME.topology.cas = cas;
    }

    const cepDT* lib_name = CEP_DTAW("CEP", "lib");
    cepCell* lib = ensure_root_dictionary(root, lib_name);
    CEP_DEFAULT_TOPOLOGY.lib = lib;
    if (!CEP_RUNTIME.topology.lib) {
        CEP_RUNTIME.topology.lib = lib;
    }

    const cepDT* data_name = CEP_DTAW("CEP", "data");
    cepCell* data = ensure_root_dictionary(root, data_name);
    CEP_DEFAULT_TOPOLOGY.data = data;
    if (!CEP_RUNTIME.topology.data) {
        CEP_RUNTIME.topology.data = data;
    }

    const cepDT* tmp_name = CEP_DTAW("CEP", "tmp");
    cepCell* tmp = ensure_root_list(root, tmp_name);
    CEP_DEFAULT_TOPOLOGY.tmp = tmp;
    if (!CEP_RUNTIME.topology.tmp) {
        CEP_RUNTIME.topology.tmp = tmp;
    }

    const cepDT* enzymes_name = CEP_DTAW("CEP", "enzymes");
    cepCell* enzymes = ensure_root_dictionary(root, enzymes_name);
    CEP_DEFAULT_TOPOLOGY.enzymes = enzymes;
    if (!CEP_RUNTIME.topology.enzymes) {
        CEP_RUNTIME.topology.enzymes = enzymes;
    }

    if (!cep_runtime_has_registry()) {
        CEP_RUNTIME.registry = cep_enzyme_registry_create();
        if (!CEP_RUNTIME.registry) {
            return false;
        }
    }

    return true;
}


/* Merges caller supplied topology and policy values with the defaults so the
 * runtime can respect overrides without losing the safety of fully initialised
 * fallback structures.
 */
bool cep_heartbeat_configure(const cepHeartbeatTopology* topology, const cepHeartbeatPolicy* policy) {
    if (!policy) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepHeartbeatTopology merged = CEP_DEFAULT_TOPOLOGY;
    if (topology) {
        if (topology->root)     merged.root     = topology->root;
        if (topology->sys)      merged.sys      = topology->sys;
        if (topology->rt)       merged.rt       = topology->rt;
        if (topology->journal)  merged.journal  = topology->journal;
        if (topology->env)      merged.env      = topology->env;
        if (topology->cas)      merged.cas      = topology->cas;
        if (topology->lib)      merged.lib      = topology->lib;
        if (topology->data)     merged.data     = topology->data;
        if (topology->tmp)      merged.tmp      = topology->tmp;
        if (topology->enzymes)  merged.enzymes  = topology->enzymes;
    }

    CEP_RUNTIME.topology = merged;
    CEP_RUNTIME.policy   = *policy;
    return true;
}


/* Starts the heartbeat loop at the configured entry point so the scheduler can
 * begin advancing beats using the state prepared during configuration.
 */
bool cep_heartbeat_startup(void) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.current = CEP_RUNTIME.policy.start_at;
    CEP_RUNTIME.running = true;
    return true;
}


/* Restarts execution by clearing per-run cells and resetting the beat counter
 * so a fresh cycle can reuse the existing topology without leaking data.
 */
bool cep_heartbeat_restart(void) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cep_heartbeat_reset_runtime_cells();

    CEP_RUNTIME.current = CEP_RUNTIME.policy.start_at;
    CEP_RUNTIME.running = true;
    return true;
}


/* Forces the runtime to begin at an explicit beat to support manual recovery or
 * replay scenarios where the caller chooses the next cadence.
 */
bool cep_heartbeat_begin(cepBeatNumber beat) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.current = beat;
    CEP_RUNTIME.running = true;
    return true;
}


/* Resolves the agenda for the current beat; presently that means reporting
 * whether the engine is running, keeping the control flow plumbed for future work. 
 */
bool cep_heartbeat_resolve_agenda(void) {
    return CEP_RUNTIME.running;
}


/* Executes the resolved agenda; for now it simply mirrors the running flag so
 * callers can already chain the step flow before real executors arrive.
 */
bool cep_heartbeat_execute_agenda(void) {
    return CEP_RUNTIME.running;
}


/* Commits staged work at the end of a beat; currently it just keeps the step
 * pipeline shape intact by reflecting whether the loop is active.
 */
bool cep_heartbeat_stage_commit(void) {
    return CEP_RUNTIME.running;
}


/* Drives a full beat by cascading resolve, execute, and commit stages and bumps
 * the counter when everything succeeds so the loop progresses deterministically.
 */
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


/* Shuts the heartbeat down by releasing runtime state and the cell system so a
 * subsequent bootstrap starts from a completely clean environment.
 */
void cep_heartbeat_shutdown(void) {
    cep_runtime_reset_state(true);
    cep_runtime_reset_defaults();
    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
}


/* Exposes the currently active beat so observers can align their work with the
 * scheduler state.
 */
cepBeatNumber cep_heartbeat_current(void) {
    return CEP_RUNTIME.current;
}


/* Computes the next beat index while guarding against the invalid sentinel so
 * callers never advance past an uninitialised state.
 */
cepBeatNumber cep_heartbeat_next(void) {
    if (CEP_RUNTIME.current == CEP_BEAT_INVALID) {
        return CEP_BEAT_INVALID;
    }

    return CEP_RUNTIME.current + 1u;
}


/* Returns a pointer to the current policy so readers can inspect timing rules
 * without taking ownership of the underlying storage.
 */
const cepHeartbeatPolicy* cep_heartbeat_policy(void) {
    return &CEP_RUNTIME.policy;
}


/* Returns the active topology structure so clients can access shared roots the
 * runtime prepared during bootstrap.
 */
const cepHeartbeatTopology* cep_heartbeat_topology(void) {
    return &CEP_RUNTIME.topology;
}


/* Ensures the runtime is initialised and exposes the shared enzyme registry so
 * listeners can register dispatchers without duplicating bootstrap checks.
 */
cepEnzymeRegistry* cep_heartbeat_registry(void) {
    if (!cep_heartbeat_bootstrap()) {
        return NULL;
    }
    return CEP_RUNTIME.registry;
}


/* Placeholder for signal enqueuing that keeps the public API stable while the
 * actual queueing mechanics are still under construction.
 */
int cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath* signal_path, const cepPath* target_path) {
    (void)beat;
    (void)signal_path;
    (void)target_path;
    return CEP_ENZYME_FATAL;
}


/* Placeholder for impulse enqueuing that already captures the intended inputs
 * so future implementations can focus on storage without changing signatures.
 */
int cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepImpulse* impulse) {
    (void)beat;
    (void)impulse;
    return CEP_ENZYME_FATAL;
}


/* Provides the root cell for the sys namespace so integrations can attach
 * system-level state without digging through runtime internals.
 */
cepCell* cep_heartbeat_sys_root(void) {
    return CEP_RUNTIME.topology.sys;
}


/* Shares the runtime root cell to support modules that need direct access to
 * transient execution state.
 */
cepCell* cep_heartbeat_rt_root(void) {
    return CEP_RUNTIME.topology.rt;
}


/* Returns the journal root so persistence helpers can append entries in the
 * same tree the scheduler maintains.
 */
cepCell* cep_heartbeat_journal_root(void) {
    return CEP_RUNTIME.topology.journal;
}


/* Supplies the environment root cell so configuration loaders can coordinate on
 * a single namespace.
 */
cepCell* cep_heartbeat_env_root(void) {
    return CEP_RUNTIME.topology.env;
}


/* Exposes the data root so consumers can store long-lived datasets alongside
 * the runtime without guessing the internal layout.
 */
cepCell* cep_heartbeat_data_root(void) {
    return CEP_RUNTIME.topology.data;
}


/* Returns the content-addressable storage root to let utilities share cached
 * assets with the engine-provided store.
 */
cepCell* cep_heartbeat_cas_root(void) {
    return CEP_RUNTIME.topology.cas;
}


/* Provides the temporary root so callers can manage short-lived buffers in the
 * same compartment the runtime clears between runs.
 */
cepCell* cep_heartbeat_tmp_root(void) {
    return CEP_RUNTIME.topology.tmp;
}


/* Shares the enzymes root dictionary so tooling can inspect or organise enzyme
 * metadata alongside the registry.
 */
cepCell* cep_heartbeat_enzymes_root(void) {
    return CEP_RUNTIME.topology.enzymes;
}


static void cep_heartbeat_auto_shutdown(void) CEP_AT_SHUTDOWN_(101);

static void cep_heartbeat_auto_shutdown(void) {
    cep_heartbeat_shutdown();
}
