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
#include "cep_heartbeat_internal.h"
#include "stream/cep_stream_internal.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>




static cepHeartbeatRuntime CEP_RUNTIME = {
    .current = CEP_BEAT_INVALID,
};

static cepHeartbeatTopology CEP_DEFAULT_TOPOLOGY;


static int cep_heartbeat_path_compare(const cepPath* lhs, const cepPath* rhs) {
    if (lhs == rhs) {
        return 0;
    }
    if (!lhs) {
        return rhs ? -1 : 0;
    }
    if (!rhs) {
        return 1;
    }

    if (lhs->length < rhs->length) {
        return -1;
    }
    if (lhs->length > rhs->length) {
        return 1;
    }

    for (unsigned i = 0; i < lhs->length; ++i) {
        int cmp = cep_dt_compare(&lhs->past[i].dt, &rhs->past[i].dt);
        if (cmp != 0) {
            return cmp;
        }
    }

    return 0;
}


static uint64_t cep_heartbeat_hash_mix(uint64_t hash, uint64_t value) {
    hash ^= value + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    return hash;
}


static uint64_t cep_heartbeat_path_hash(const cepPath* path) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    if (!path) {
        return hash;
    }

    hash = cep_heartbeat_hash_mix(hash, path->length);
    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        hash = cep_heartbeat_hash_mix(hash, segment->dt.domain);
        hash = cep_heartbeat_hash_mix(hash, segment->dt.tag);
        hash = cep_heartbeat_hash_mix(hash, segment->timestamp);
    }

    return hash;
}


static uint64_t cep_heartbeat_impulse_hash(const cepHeartbeatImpulseRecord* record) {
    uint64_t hash = 0x84222325cbf29ce4ULL;
    if (!record) {
        return hash;
    }

    hash = cep_heartbeat_hash_mix(hash, cep_heartbeat_path_hash(record->signal_path));
    hash = cep_heartbeat_hash_mix(hash, cep_heartbeat_path_hash(record->target_path));
    return hash;
}


static bool cep_heartbeat_scratch_ensure_ordered(cepHeartbeatScratch* scratch, size_t required) {
    if (!scratch) {
        return false;
    }
    if (required == 0u) {
        return true;
    }
    if (scratch->ordered_capacity >= required) {
        return true;
    }

    size_t bytes = required * sizeof(*scratch->ordered);
    const cepEnzymeDescriptor** buffer = scratch->ordered ? cep_realloc(scratch->ordered, bytes) : cep_malloc(bytes);
    if (!buffer) {
        return false;
    }

    scratch->ordered = buffer;
    scratch->ordered_capacity = required;
    return true;
}


static bool cep_heartbeat_dispatch_cache_reserve(cepHeartbeatScratch* scratch, size_t min_capacity) {
    if (!scratch || min_capacity == 0u) {
        return true;
    }

    if (scratch->entry_capacity >= min_capacity) {
        return true;
    }

    size_t capacity = scratch->entry_capacity ? scratch->entry_capacity : 8u;
    while (capacity < min_capacity && capacity < (SIZE_MAX >> 1)) {
        capacity <<= 1u;
    }
    if (capacity < min_capacity) {
        capacity = min_capacity;
    }

    size_t bytes = capacity * sizeof(*scratch->entries);
    cepHeartbeatDispatchCacheEntry* entries = scratch->entries ? cep_realloc(scratch->entries, bytes) : cep_malloc(bytes);
    if (!entries) {
        return false;
    }

    if (capacity > scratch->entry_capacity) {
        size_t old_capacity = scratch->entry_capacity;
        memset(entries + old_capacity, 0, (capacity - old_capacity) * sizeof(*entries));
    }

    scratch->entries = entries;
    scratch->entry_capacity = capacity;
    return true;
}


static void cep_heartbeat_dispatch_cache_destroy(cepHeartbeatScratch* scratch) {
    if (!scratch) {
        return;
    }

    if (scratch->entries) {
        for (size_t i = 0; i < scratch->entry_capacity; ++i) {
            CEP_FREE(scratch->entries[i].descriptors);
            scratch->entries[i].descriptors = NULL;
            scratch->entries[i].descriptor_capacity = 0u;
            scratch->entries[i].descriptor_count = 0u;
            scratch->entries[i].signal_path = NULL;
            scratch->entries[i].target_path = NULL;
            scratch->entries[i].used = 0u;
            scratch->entries[i].stamp = 0u;
            scratch->entries[i].hash = 0u;
        }
        CEP_FREE(scratch->entries);
    }

    CEP_FREE(scratch->ordered);

    memset(scratch, 0, sizeof(*scratch));
}


static void cep_heartbeat_scratch_next_generation(cepHeartbeatScratch* scratch) {
    if (!scratch) {
        return;
    }

    scratch->generation += 1u;
    if (scratch->generation == 0u) {
        scratch->generation = 1u;
        if (scratch->entries) {
            for (size_t i = 0; i < scratch->entry_capacity; ++i) {
                scratch->entries[i].stamp = 0u;
                scratch->entries[i].used = 0u;
                scratch->entries[i].hash = 0u;
                scratch->entries[i].signal_path = NULL;
                scratch->entries[i].target_path = NULL;
                scratch->entries[i].descriptor_count = 0u;
            }
        }
    }
}


static cepHeartbeatDispatchCacheEntry* cep_heartbeat_dispatch_cache_acquire(cepHeartbeatScratch* scratch, const cepHeartbeatImpulseRecord* record, uint64_t hash, bool* fresh) {
    if (!scratch || !scratch->entries || scratch->entry_capacity == 0u) {
        return NULL;
    }

    size_t mask = scratch->entry_capacity - 1u;
    size_t index = (size_t)hash & mask;

    for (size_t probe = 0; probe < scratch->entry_capacity; ++probe) {
        cepHeartbeatDispatchCacheEntry* entry = &scratch->entries[index];
        if (entry->stamp != scratch->generation || !entry->used) {
            entry->used = 1u;
            entry->stamp = scratch->generation;
            entry->hash = hash;
            entry->signal_path = record ? record->signal_path : NULL;
            entry->target_path = record ? record->target_path : NULL;
            entry->descriptor_count = 0u;
            if (fresh) {
                *fresh = true;
            }
            return entry;
        }

        if (entry->hash == hash &&
            cep_heartbeat_path_compare(entry->signal_path, record ? record->signal_path : NULL) == 0 &&
            cep_heartbeat_path_compare(entry->target_path, record ? record->target_path : NULL) == 0) {
            if (fresh) {
                *fresh = false;
            }
            return entry;
        }

        index = (index + 1u) & mask;
    }

    return NULL;
}


static void cep_heartbeat_dispatch_cache_cleanup_generation(cepHeartbeatScratch* scratch) {
    if (!scratch || !scratch->entries) {
        return;
    }

    for (size_t i = 0; i < scratch->entry_capacity; ++i) {
        cepHeartbeatDispatchCacheEntry* entry = &scratch->entries[i];
        if (entry->stamp == scratch->generation && entry->used) {
            entry->used = 0u;
            entry->hash = 0u;
            entry->signal_path = NULL;
            entry->target_path = NULL;
            entry->descriptor_count = 0u;
        }
    }
}


static bool cep_runtime_has_registry(void) {
    return CEP_RUNTIME.registry != NULL;
}


static void cep_runtime_reset_state(bool destroy_registry) {
    if (destroy_registry && cep_runtime_has_registry()) {
        cep_enzyme_registry_destroy(CEP_RUNTIME.registry);
        CEP_RUNTIME.registry = NULL;
    }

    cep_heartbeat_impulse_queue_destroy(&CEP_RUNTIME.inbox_current);
    cep_heartbeat_impulse_queue_destroy(&CEP_RUNTIME.inbox_next);
    cep_heartbeat_dispatch_cache_destroy(&CEP_RUNTIME.scratch);

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
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.inbox_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.inbox_next);
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
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.inbox_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.inbox_next);
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
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.inbox_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.inbox_next);
    return true;
}


/* Resolves the agenda for the current beat by activating deferred enzyme
 * registrations and draining the impulse inbox into deterministic execution order.
 */
bool cep_heartbeat_resolve_agenda(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    if (CEP_RUNTIME.registry) {
        cep_enzyme_registry_activate_pending(CEP_RUNTIME.registry);
    }

    return cep_heartbeat_process_impulses();
}


/* Executes the resolved agenda; for now it simply mirrors the running flag so
 * callers can already chain the step flow before real executors arrive.
 */
bool cep_heartbeat_execute_agenda(void) {
    return CEP_RUNTIME.running;
}


/* Commits staged work by rotating the impulse queues so signals emitted during
 * beat N become visible to the dispatcher at beat N+1.
 */
bool cep_heartbeat_stage_commit(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    if (!cep_stream_commit_pending())
        return false;

    cep_heartbeat_impulse_queue_swap(&CEP_RUNTIME.inbox_current, &CEP_RUNTIME.inbox_next);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.inbox_next);

    return true;
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


/* By looking at the complete inbox the dispatcher groups identical impulses,
 * reuses their dependency resolution, and still walks the agenda in enqueue
 * order so repeated graph work disappears without losing determinism.
 */
bool cep_heartbeat_process_impulses(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    cepEnzymeRegistry* registry = CEP_RUNTIME.registry;
    size_t registry_size = registry ? cep_enzyme_registry_size(registry) : 0u;
    cepHeartbeatScratch* scratch = &CEP_RUNTIME.scratch;

    if (registry_size > 0u) {
        if (!cep_heartbeat_scratch_ensure_ordered(scratch, registry_size)) {
            return false;
        }
    }

    cepHeartbeatImpulseQueue* inbox = &CEP_RUNTIME.inbox_current;
    size_t impulse_count = inbox->count;

    if (impulse_count == 0u) {
        cep_heartbeat_scratch_next_generation(scratch);
        cep_heartbeat_dispatch_cache_cleanup_generation(scratch);
        return true;
    }

    size_t desired_slots = impulse_count * 2u;
    if (desired_slots < 8u) {
        desired_slots = 8u;
    }
    size_t reserve = cep_next_pow_of_two(desired_slots);
    if (!cep_heartbeat_dispatch_cache_reserve(scratch, reserve)) {
        return false;
    }

    cep_heartbeat_scratch_next_generation(scratch);

    bool ok = true;

    for (size_t i = 0; i < impulse_count && ok; ++i) {
        cepHeartbeatImpulseRecord* record = &inbox->records[i];
        cepImpulse impulse = {
            .signal_path = record->signal_path,
            .target_path = record->target_path,
        };

        bool fresh = false;
        uint64_t hash = cep_heartbeat_impulse_hash(record);
        cepHeartbeatDispatchCacheEntry* entry = cep_heartbeat_dispatch_cache_acquire(scratch, record, hash, &fresh);
        if (!entry) {
            ok = false;
            break;
        }

        if (fresh) {
            size_t resolved = 0u;
            if (registry && registry_size > 0u) {
                resolved = cep_enzyme_resolve(registry, &impulse, scratch->ordered, scratch->ordered_capacity);
            }

            if (resolved > 0u) {
                if (entry->descriptor_capacity < resolved) {
                    size_t bytes = resolved * sizeof(*entry->descriptors);
                    const cepEnzymeDescriptor** buffer = entry->descriptors ?
                        cep_realloc(entry->descriptors, bytes) :
                        cep_malloc(bytes);
                    if (!buffer) {
                        ok = false;
                        break;
                    }
                    entry->descriptors = buffer;
                    entry->descriptor_capacity = resolved;
                }
                memcpy(entry->descriptors, scratch->ordered, resolved * sizeof(*scratch->ordered));
            }
            entry->descriptor_count = resolved;
        }

        if (entry->descriptor_count > 0u && entry->descriptors) {
            for (size_t j = 0; j < entry->descriptor_count && ok; ++j) {
                const cepEnzymeDescriptor* descriptor = entry->descriptors[j];
                if (!descriptor || !descriptor->callback) {
                    continue;
                }

                int rc = descriptor->callback(impulse.signal_path, impulse.target_path);
                if (rc == CEP_ENZYME_FATAL) {
                    ok = false;
                    break;
                }

                if (rc == CEP_ENZYME_RETRY) {
                    if (!cep_heartbeat_impulse_queue_append(&CEP_RUNTIME.inbox_next, &impulse)) {
                        ok = false;
                        break;
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < impulse_count; ++i) {
        cep_heartbeat_impulse_record_clear(&inbox->records[i]);
    }
    inbox->count = 0u;

    cep_heartbeat_dispatch_cache_cleanup_generation(scratch);

    /* TODO: Feed this resolver cache with real-time stats—e.g. track miss ratios,
     * impulse uniqueness, and registry churn—to adapt cache sizes, fall back to
     * direct dispatch when reuse is low, or pre-populate hot pairs before the beat.
     * */
     
    return ok;
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
    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    return cep_heartbeat_enqueue_impulse(beat, &impulse);
}


/* Records an impulse for processing at the next beat boundary, cloning the
 * supplied paths so callers can release their buffers immediately.
 */
int cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepImpulse* impulse) {
    if (!cep_heartbeat_bootstrap()) {
        return CEP_ENZYME_FATAL;
    }

    (void)beat;

    if (!impulse || (!impulse->signal_path && !impulse->target_path)) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_heartbeat_impulse_queue_append(&CEP_RUNTIME.inbox_next, impulse)) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
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
