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

#include <stdlib.h>

#include "cep_heartbeat.h"




#define CEP_ENZYME_REGISTRY_DEFAULT_CAPACITY    16u
#define CEP_ENZYME_REGISTRY_MAX_HINT            65536u


typedef struct {
    cepPath*            query;
    cepEnzymeDescriptor descriptor;
    size_t              registration_order;
} cepEnzymeEntry;


struct _cepEnzymeRegistry {
    cepEnzymeEntry*     entries;
    size_t              entry_count;
    size_t              entry_capacity;
    size_t              next_registration_order;
    cepEnzymeEntry*     pending_entries;
    size_t              pending_count;
    size_t              pending_capacity;
};




static size_t cep_enzyme_registry_hint_capacity(void) {
    static size_t cached_hint;
    static bool   hint_initialised;

    if (hint_initialised) {
        return cached_hint;
    }

    size_t fallback = CEP_ENZYME_REGISTRY_DEFAULT_CAPACITY;
    const char* hint = getenv("CEP_ENZYME_CAPACITY_HINT");
    if (!hint || !*hint) {
        cached_hint = fallback;
        hint_initialised = true;
        return cached_hint;
    }

    char* endptr = NULL;
    unsigned long long parsed = strtoull(hint, &endptr, 10);
    if (endptr && *endptr == '\0' && parsed > 0u) {
        const size_t max_hint = CEP_ENZYME_REGISTRY_MAX_HINT;
        if (parsed > max_hint) {
            parsed = max_hint;
        }
        cached_hint = (size_t)parsed;
    } else {
        cached_hint = fallback;
    }

    hint_initialised = true;
    return cached_hint;
}


static void cep_enzyme_entry_clear(cepEnzymeEntry* entry) {
    if (!entry) {
        return;
    }

    CEP_FREE(entry->query);
    CEP_0(entry);
}


static void cep_enzyme_registry_free_all(cepEnzymeRegistry* registry) {
    if (!registry) {
        return;
    }

    if (registry->entries) {
        for (size_t i = 0; i < registry->entry_count; ++i) {
            cep_enzyme_entry_clear(&registry->entries[i]);
        }
        CEP_FREE(registry->entries);
    }

    if (registry->pending_entries) {
        for (size_t i = 0; i < registry->pending_count; ++i) {
            cep_enzyme_entry_clear(&registry->pending_entries[i]);
        }
        CEP_FREE(registry->pending_entries);
    }

    registry->entries                 = NULL;
    registry->entry_count             = 0;
    registry->entry_capacity          = 0;
    registry->pending_entries         = NULL;
    registry->pending_count           = 0;
    registry->pending_capacity        = 0;
    registry->next_registration_order = 0;
}


static cepPath* cep_enzyme_path_clone(const cepPath* path) {
    if (!path) {
        return NULL;
    }

    size_t   bytes = sizeof(cepPath) + (size_t)path->length * sizeof(cepPast);
    cepPath* clone = cep_malloc(bytes);

    clone->length   = path->length;
    clone->capacity = path->length;
    memcpy(clone->past, path->past, (size_t)path->length * sizeof(cepPast));

    return clone;
}


static bool cep_enzyme_paths_equal(const cepPath* a, const cepPath* b) {
    if (a == b) {
        return true;
    }
    if (!a || !b) {
        return false;
    }
    if (a->length != b->length) {
        return false;
    }

    for (unsigned i = 0; i < a->length; ++i) {
        if (cep_dt_compare(&a->past[i].dt, &b->past[i].dt) != 0) {
            return false;
        }
    }

    return true;
}


static bool cep_enzyme_path_is_prefix(const cepPath* prefix, const cepPath* path) {
    if (!prefix || !path) {
        return false;
    }
    if (prefix->length > path->length) {
        return false;
    }

    for (unsigned i = 0; i < prefix->length; ++i) {
        if (cep_dt_compare(&prefix->past[i].dt, &path->past[i].dt) != 0) {
            return false;
        }
    }

    return true;
}


static bool cep_enzyme_descriptor_equal(const cepEnzymeDescriptor* a, const cepEnzymeDescriptor* b) {
    if (a == b) {
        return true;
    }
    if (!a || !b) {
        return false;
    }

    if (a->callback != b->callback) {
        return false;
    }
    if (a->flags != b->flags) {
        return false;
    }
    if (a->match != b->match) {
        return false;
    }

    return cep_dt_compare(&a->name, &b->name) == 0;
}


/* Creates a registry instance so enzymes can be registered and does an upfront
 * capacity reservation based on environment hints to reduce later reallocations.
 */
cepEnzymeRegistry* cep_enzyme_registry_create(void) {
    CEP_NEW(cepEnzymeRegistry, registry);
    if (!registry) {
        return NULL;
    }

    CEP_0(registry);
    size_t hint = cep_enzyme_registry_hint_capacity();
    if (hint) {
        registry->entries = cep_malloc0(hint * sizeof(*registry->entries));
        registry->entry_capacity = hint;
        registry->pending_entries = cep_malloc0(hint * sizeof(*registry->pending_entries));
        registry->pending_capacity = hint;
    }
    return registry;
}


/* Tears down a registry by releasing all tracked entries so callers can avoid
 * leaking per-enzyme allocations when a runtime shuts down.
 */
void cep_enzyme_registry_destroy(cepEnzymeRegistry* registry) {
    if (!registry) {
        return;
    }

    cep_enzyme_registry_free_all(registry);
    CEP_FREE(registry);
}


/* Clears the registry contents while keeping the buffer alive so repeated test
 * runs can start from a clean slate without paying the allocation cost again.
 */
void cep_enzyme_registry_reset(cepEnzymeRegistry* registry) {
    if (!registry) {
        return;
    }

    if (!registry->entries && !registry->pending_entries) {
        registry->entry_count             = 0;
        registry->entry_capacity          = 0;
        registry->pending_count           = 0;
        registry->pending_capacity        = 0;
        registry->next_registration_order = 0;
        return;
    }

    if (registry->entries) {
        for (size_t i = 0; i < registry->entry_count; ++i) {
            cep_enzyme_entry_clear(&registry->entries[i]);
        }
    }

    if (registry->pending_entries) {
        for (size_t i = 0; i < registry->pending_count; ++i) {
            cep_enzyme_entry_clear(&registry->pending_entries[i]);
        }
    }

    registry->entry_count             = 0;
    registry->pending_count           = 0;
    registry->next_registration_order = 0;
}


/* Reports how many enzymes are currently tracked so higher layers can decide
 * whether new registrations are needed or whether iteration should even start.
 */
size_t cep_enzyme_registry_size(const cepEnzymeRegistry* registry) {
    return registry ? registry->entry_count : 0u;
}


/* Promotes pending enzyme registrations into the active registry so
 * the next beat observes them in deterministic order without mutating the
 * frozen agenda mid-cycle.
 */
void cep_enzyme_registry_activate_pending(cepEnzymeRegistry* registry) {
    if (!registry || registry->pending_count == 0u) {
        return;
    }

    for (size_t i = 0; i < registry->pending_count; ++i) {
        cepEnzymeEntry* pending = &registry->pending_entries[i];
        if (!pending->query || !pending->descriptor.callback) {
            CEP_0(pending);
            continue;
        }

        if (!cep_enzyme_registry_ensure_capacity(registry)) {
            break;
        }

        cepEnzymeEntry* entry = &registry->entries[registry->entry_count++];
        *entry = *pending;
        entry->registration_order = registry->next_registration_order++;
        CEP_0(pending);
    }

    registry->pending_count = 0u;
}


static bool cep_enzyme_registry_ensure_capacity(cepEnzymeRegistry* registry) {
    if (registry->entry_count < registry->entry_capacity) {
        return true;
    }

    size_t new_capacity = registry->entry_capacity ? (registry->entry_capacity * 2u) : cep_enzyme_registry_hint_capacity();
    if (!new_capacity) {
        new_capacity = CEP_ENZYME_REGISTRY_DEFAULT_CAPACITY;
    }
    cepEnzymeEntry* new_entries = cep_realloc(registry->entries, new_capacity * sizeof(*new_entries));
    if (!new_entries) {
        return false;
    }

    if (new_capacity > registry->entry_capacity) {
        size_t previous_bytes = registry->entry_capacity * sizeof(*new_entries);
        size_t total_bytes = new_capacity * sizeof(*new_entries);
        memset(((uint8_t*)new_entries) + previous_bytes, 0, total_bytes - previous_bytes);
    }

    registry->entries        = new_entries;
    registry->entry_capacity = new_capacity;
    return true;
}


static bool cep_enzyme_registry_pending_ensure_capacity(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (registry->pending_count < registry->pending_capacity) {
        return true;
    }

    size_t new_capacity = registry->pending_capacity ? (registry->pending_capacity * 2u) : cep_enzyme_registry_hint_capacity();
    if (!new_capacity) {
        new_capacity = CEP_ENZYME_REGISTRY_DEFAULT_CAPACITY;
    }

    size_t bytes = new_capacity * sizeof(*registry->pending_entries);
    cepEnzymeEntry* entries = registry->pending_entries ? cep_realloc(registry->pending_entries, bytes) : cep_malloc0(bytes);
    if (!entries) {
        return false;
    }

    if (new_capacity > registry->pending_capacity) {
        size_t previous_bytes = registry->pending_capacity * sizeof(*registry->pending_entries);
        memset(((uint8_t*)entries) + previous_bytes, 0, bytes - previous_bytes);
    }

    registry->pending_entries  = entries;
    registry->pending_capacity = new_capacity;
    return true;
}


static int cep_enzyme_registry_pending_add(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor) {
    if (!cep_enzyme_registry_pending_ensure_capacity(registry)) {
        return CEP_ENZYME_FATAL;
    }

    cepPath* copy = cep_enzyme_path_clone(query);
    if (!copy) {
        return CEP_ENZYME_FATAL;
    }

    cepEnzymeEntry* entry = &registry->pending_entries[registry->pending_count++];
    entry->query              = copy;
    entry->descriptor         = *descriptor;
    entry->registration_order = 0u;

    return CEP_ENZYME_SUCCESS;
}


/* Registers a new enzyme by cloning the query path and storing the descriptor
 * for deterministic dispatch, deferring activation to the next beat when the
 * heartbeat is live so mid-beat registrations never perturb the frozen agenda.
 */
int cep_enzyme_register(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor) {
    if (!cep_heartbeat_bootstrap()) {
        return CEP_ENZYME_FATAL;
    }

    if (!registry || !query || !descriptor || !descriptor->callback) {
        return CEP_ENZYME_FATAL;
    }

    cepBeatNumber current = cep_heartbeat_current();
    if (current != CEP_BEAT_INVALID) {
        return cep_enzyme_registry_pending_add(registry, query, descriptor);
    }

    if (!cep_enzyme_registry_ensure_capacity(registry)) {
        return CEP_ENZYME_FATAL;
    }

    cepPath* copy = cep_enzyme_path_clone(query);
    if (!copy) {
        return CEP_ENZYME_FATAL;
    }

    cepEnzymeEntry* entry = &registry->entries[registry->entry_count++];
    entry->query              = copy;
    entry->descriptor         = *descriptor;
    entry->registration_order = registry->next_registration_order++;

    return CEP_ENZYME_SUCCESS;
}


/* Removes a previously registered enzyme entry to keep dispatch decisions in
 * sync with caller intent, compacting the table so subsequent lookups stay fast.
 */
int cep_enzyme_unregister(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor) {
    if (!cep_heartbeat_bootstrap()) {
        return CEP_ENZYME_FATAL;
    }

    if (!registry || !query || !descriptor || registry->entry_count == 0u) {
        return CEP_ENZYME_FATAL;
    }

    for (size_t i = 0; i < registry->entry_count; ++i) {
        cepEnzymeEntry* entry = &registry->entries[i];
        if (!cep_enzyme_paths_equal(entry->query, query)) {
            continue;
        }
        if (!cep_enzyme_descriptor_equal(&entry->descriptor, descriptor)) {
            continue;
        }

        cep_enzyme_entry_clear(entry);

        if (i + 1u < registry->entry_count) {
            memmove(&registry->entries[i], &registry->entries[i + 1u], (registry->entry_count - (i + 1u)) * sizeof(*registry->entries));
        }

        registry->entry_count--;
        return CEP_ENZYME_SUCCESS;
    }

    for (size_t i = 0; i < registry->pending_count; ++i) {
        cepEnzymeEntry* entry = &registry->pending_entries[i];
        if (!cep_enzyme_paths_equal(entry->query, query)) {
            continue;
        }
        if (!cep_enzyme_descriptor_equal(&entry->descriptor, descriptor)) {
            continue;
        }

        cep_enzyme_entry_clear(entry);

        if (i + 1u < registry->pending_count) {
            memmove(&registry->pending_entries[i], &registry->pending_entries[i + 1u], (registry->pending_count - (i + 1u)) * sizeof(*registry->pending_entries));
        }

        registry->pending_count--;
        return CEP_ENZYME_SUCCESS;
    }

    return CEP_ENZYME_FATAL;
}


typedef struct {
    const cepEnzymeDescriptor* descriptor;
    size_t                     specificity_signal;
    size_t                     specificity_target;
    size_t                     specificity_total;
    size_t                     registration_order;
    uint8_t                    match_type;
} cepEnzymeMatch;


typedef struct {
    const cepDT* name;
    size_t       index;
} cepEnzymeMatchLookup;


enum {
    CEP_ENZYME_MATCH_FLAG_SIGNAL = 1u << 0,
    CEP_ENZYME_MATCH_FLAG_TARGET = 1u << 1,
};


static int cep_enzyme_match_lookup_sort(const void* lhs, const void* rhs) {
    const cepEnzymeMatchLookup* a = lhs;
    const cepEnzymeMatchLookup* b = rhs;

    int cmp = cep_dt_compare(a->name, b->name);
    if (cmp != 0) {
        return cmp;
    }

    if (a->index < b->index) {
        return -1;
    }
    if (a->index > b->index) {
        return 1;
    }

    return 0;
}


static int cep_enzyme_match_lookup_compare_name(const void* needle, const void* haystack) {
    const cepDT*                 name  = needle;
    const cepEnzymeMatchLookup*  entry = haystack;

    return cep_dt_compare(name, entry->name);
}


static size_t cep_enzyme_match_index_by_name(const cepEnzymeMatchLookup* lookup, size_t count, const cepDT* name) {
    if (!lookup || !name || count == 0u) {
        return SIZE_MAX;
    }

    const cepEnzymeMatchLookup* found = bsearch(name,
                                                lookup,
                                                count,
                                                sizeof(*lookup),
                                                cep_enzyme_match_lookup_compare_name);
    if (!found) {
        return SIZE_MAX;
    }

    size_t position = (size_t)(found - lookup);
    while (position > 0u && cep_dt_compare(lookup[position - 1u].name, name) == 0) {
        position--;
    }

    return lookup[position].index;
}


static uint8_t cep_enzyme_match_strength(uint8_t flags) {
    return (flags == (CEP_ENZYME_MATCH_FLAG_SIGNAL | CEP_ENZYME_MATCH_FLAG_TARGET)) ? 2u : 1u;
}


static bool cep_enzyme_match_prefer(const cepEnzymeMatch* lhs, const cepEnzymeMatch* rhs) {
    uint8_t lhs_strength = cep_enzyme_match_strength(lhs->match_type);
    uint8_t rhs_strength = cep_enzyme_match_strength(rhs->match_type);
    if (lhs_strength != rhs_strength) {
        return lhs_strength > rhs_strength;
    }

    if (lhs->specificity_total != rhs->specificity_total) {
        return lhs->specificity_total > rhs->specificity_total;
    }

    int name_cmp = cep_dt_compare(&lhs->descriptor->name, &rhs->descriptor->name);
    if (name_cmp != 0) {
        return name_cmp < 0;
    }

    return lhs->registration_order < rhs->registration_order;
}


static void cep_enzyme_ready_push(size_t* heap, size_t* heap_size, size_t value, const cepEnzymeMatch* matches) {
    size_t child = (*heap_size)++;
    heap[child] = value;

    while (child > 0u) {
        size_t parent = (child - 1u) / 2u;
        if (!cep_enzyme_match_prefer(&matches[heap[child]], &matches[heap[parent]])) {
            break;
        }
        size_t tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;
        child = parent;
    }
}


static size_t cep_enzyme_ready_pop(size_t* heap, size_t* heap_size, const cepEnzymeMatch* matches) {
    size_t result = heap[0u];
    size_t last = --(*heap_size);
    heap[0u] = heap[last];

    size_t parent = 0u;
    while (true) {
        size_t left = parent * 2u + 1u;
        if (left >= *heap_size) {
            break;
        }
        size_t right = left + 1u;
        size_t best_child = left;
        if (right < *heap_size && cep_enzyme_match_prefer(&matches[heap[right]], &matches[heap[left]])) {
            best_child = right;
        }

        if (!cep_enzyme_match_prefer(&matches[heap[best_child]], &matches[heap[parent]])) {
            break;
        }

        size_t tmp = heap[parent];
        heap[parent] = heap[best_child];
        heap[best_child] = tmp;
        parent = best_child;
    }

    return result;
}


static uint8_t cep_enzyme_match_flags(const cepEnzymeEntry* entry, const cepImpulse* impulse, size_t* signal_specificity, size_t* target_specificity) {
    if (signal_specificity) {
        *signal_specificity = 0u;
    }
    if (target_specificity) {
        *target_specificity = 0u;
    }
    if (!entry || !impulse) {
        return 0u;
    }

    const cepPath* query = entry->query;
    if (!query || query->length == 0u) {
        return 0u;
    }

    const cepPath* signal = impulse->signal_path;
    const cepPath* target = impulse->target_path;

    const size_t specificity = query->length;
    uint8_t flags = 0u;

    switch (entry->descriptor.match) {
      case CEP_ENZYME_MATCH_EXACT:
        if (signal && cep_enzyme_paths_equal(query, signal)) {
            flags |= CEP_ENZYME_MATCH_FLAG_SIGNAL;
            if (signal_specificity) {
                *signal_specificity = specificity;
            }
        }
        if (target && cep_enzyme_paths_equal(query, target)) {
            flags |= CEP_ENZYME_MATCH_FLAG_TARGET;
            if (target_specificity) {
                *target_specificity = specificity;
            }
        }
        break;

      case CEP_ENZYME_MATCH_PREFIX:
        if (signal && cep_enzyme_path_is_prefix(query, signal)) {
            flags |= CEP_ENZYME_MATCH_FLAG_SIGNAL;
            if (signal_specificity) {
                *signal_specificity = specificity;
            }
        }
        if (target && cep_enzyme_path_is_prefix(query, target)) {
            flags |= CEP_ENZYME_MATCH_FLAG_TARGET;
            if (target_specificity) {
                *target_specificity = specificity;
            }
        }
        break;

      default:
        break;
    }

    return flags;
}


/*
 * Impulse agenda construction follows a fixed pipeline to keep dispatch deterministic
 * and to avoid quadratic hot paths when many enzymes collide on the same impulse.
 * 
 *   1. Scan the registry once, capturing every enzyme whose query path matches either
 *      the impulse signal or target. For each match we record whether the hit came
 *      from the signal, the target, or both, and we cache the per-path specificity
 *      (currently the query length) so dual-path hits naturally outrank single-side
 *      matches. The scan stays linear in the registry size, so idle enzymes cost only
 *      a cheap mismatch check.
 *   2. Build a name-indexed adjacency table on the fly from the collected matches,
 *      translating descriptor before/after constraints into edges inside the active
 *      set. Duplicate edges are skipped, and dependencies on enzymes that did not
 *      match the impulse are ignored. Because the graph is scoped to the active set,
 *      edge wiring grows with the square of the match count at worst, not the entire
 *      registry, while each individual lookup is logarithmic thanks to the sorted
 *      name cache built earlier.
 *   3. Run Kahn's algorithm with a small binary heap rather than a linear scan for
 *      zero-indegree nodes. The heap uses a deterministic priority tuple:
 *         - match strength (both-path matches ahead of single-path ones)
 *         - combined specificity (longer query beats shorter)
 *         - descriptor name (lexicographic order)
 *         - registration order (first registered wins)
 *      This guarantees replayable agendas while keeping the ready-set selection at
 *      O(log M) per placement instead of repeatedly scanning all matches.
 *   4. Emit descriptors in the order they are popped. If a cycle is detected the
 *      agenda is abandoned and the caller observes an empty resolution. The total
 *      per-impulse cost is roughly O(M log M + E) (matches M, dependency edges E),
 *      which scales cleanly even as the registry grows.
 */
size_t cep_enzyme_resolve(const cepEnzymeRegistry* registry, const cepImpulse* impulse, const cepEnzymeDescriptor** ordered, size_t capacity) {
    if (!registry || !impulse || registry->entry_count == 0u) {
        return 0u;
    }

    cepEnzymeMatch* matches = cep_malloc(registry->entry_count * sizeof(*matches));
    size_t match_count = 0u;

    for (size_t i = 0; i < registry->entry_count; ++i) {
        const cepEnzymeEntry* entry = &registry->entries[i];
        size_t signal_specificity = 0u;
        size_t target_specificity = 0u;
        uint8_t flags = cep_enzyme_match_flags(entry, impulse, &signal_specificity, &target_specificity);
        if (!flags) {
            continue;
        }

        matches[match_count].descriptor          = &entry->descriptor;
        matches[match_count].match_type          = flags;
        matches[match_count].specificity_signal  = signal_specificity;
        matches[match_count].specificity_target  = target_specificity;
        matches[match_count].specificity_total   = signal_specificity + target_specificity;
        if (matches[match_count].specificity_total == 0u) {
            matches[match_count].specificity_total = signal_specificity ? signal_specificity : target_specificity;
        }
        matches[match_count].registration_order  = entry->registration_order;
        match_count++;
    }

    if (match_count == 0u) {
        CEP_FREE(matches);
        return 0u;
    }

    size_t n = match_count;

    cepEnzymeMatchLookup* lookup = cep_malloc(n * sizeof(*lookup));
    for (size_t i = 0; i < n; ++i) {
        lookup[i].name  = &matches[i].descriptor->name;
        lookup[i].index = i;
    }
    qsort(lookup, n, sizeof(*lookup), cep_enzyme_match_lookup_sort);

    size_t* indegree = cep_calloc(n, sizeof(*indegree));
    size_t* adjacency_head = cep_malloc(n * sizeof(*adjacency_head));
    for (size_t i = 0; i < n; ++i) {
        adjacency_head[i] = SIZE_MAX;
    }

    size_t edge_capacity = 0u;
    for (size_t i = 0; i < n; ++i) {
        const cepEnzymeDescriptor* desc = matches[i].descriptor;
        if (desc->before) {
            edge_capacity += desc->before_count;
        }
        if (desc->after) {
            edge_capacity += desc->after_count;
        }
    }

    size_t* edge_to = NULL;
    size_t* edge_next = NULL;
    bool graph_ok = true;
    if (edge_capacity > 0u) {
        edge_to = cep_malloc(edge_capacity * sizeof(*edge_to));
        edge_next = cep_malloc(edge_capacity * sizeof(*edge_next));
        if (!edge_to || !edge_next) {
            graph_ok = false;
        }
    }
    size_t edge_count = 0u;

    for (size_t i = 0; graph_ok && i < n; ++i) {
        const cepEnzymeDescriptor* desc = matches[i].descriptor;

        for (size_t b = 0; graph_ok && desc->before && b < desc->before_count; ++b) {
            size_t j = cep_enzyme_match_index_by_name(lookup, n, &desc->before[b]);
            if (j == SIZE_MAX) {
                continue;
            }

            size_t head = adjacency_head[i];
            bool duplicate = false;
            for (size_t edge = head; edge != SIZE_MAX; edge = edge_next[edge]) {
                if (edge_to[edge] == j) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                continue;
            }

            if (edge_count >= edge_capacity) {
                graph_ok = false;
                break;
            }

            size_t slot = edge_count++;
            edge_to[slot] = j;
            edge_next[slot] = adjacency_head[i];
            adjacency_head[i] = slot;
            indegree[j]++;
        }

        for (size_t a = 0; graph_ok && desc->after && a < desc->after_count; ++a) {
            size_t j = cep_enzyme_match_index_by_name(lookup, n, &desc->after[a]);
            if (j == SIZE_MAX) {
                continue;
            }

            size_t head = adjacency_head[j];
            bool duplicate = false;
            for (size_t edge = head; edge != SIZE_MAX; edge = edge_next[edge]) {
                if (edge_to[edge] == i) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                continue;
            }

            if (edge_count >= edge_capacity) {
                graph_ok = false;
                break;
            }

            size_t slot = edge_count++;
            edge_to[slot] = i;
            edge_next[slot] = adjacency_head[j];
            adjacency_head[j] = slot;
            indegree[i]++;
        }
    }

    size_t resolved = 0u;

    if (graph_ok) {
        size_t* ready_heap = cep_malloc(n * sizeof(*ready_heap));
        size_t ready_size = 0u;

        for (size_t i = 0; i < n; ++i) {
            if (indegree[i] == 0u) {
                cep_enzyme_ready_push(ready_heap, &ready_size, i, matches);
            }
        }

        size_t* order = cep_malloc(n * sizeof(*order));
        size_t order_count = 0u;

        while (ready_size > 0u) {
            size_t best = cep_enzyme_ready_pop(ready_heap, &ready_size, matches);
            order[order_count++] = best;

            for (size_t edge = adjacency_head[best]; edge != SIZE_MAX; edge = edge_next[edge]) {
                size_t to = edge_to[edge];
                if (indegree[to] > 0u) {
                    indegree[to]--;
                    if (indegree[to] == 0u) {
                        cep_enzyme_ready_push(ready_heap, &ready_size, to, matches);
                    }
                }
            }
        }

        if (order_count == n) {
            resolved = n;
            if (ordered && capacity > 0u) {
                size_t limit = (resolved < capacity) ? resolved : capacity;
                for (size_t i = 0; i < limit; ++i) {
                    ordered[i] = matches[order[i]].descriptor;
                }
            }
        }

        CEP_FREE(order);
        CEP_FREE(ready_heap);
    }

    CEP_FREE(edge_next);
    CEP_FREE(edge_to);
    CEP_FREE(adjacency_head);
    CEP_FREE(indegree);
    CEP_FREE(lookup);
    CEP_FREE(matches);

    return resolved;
}
