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
    if (!registry || !registry->entries) {
        return;
    }

    for (size_t i = 0; i < registry->entry_count; ++i) {
        cep_enzyme_entry_clear(&registry->entries[i]);
    }

    CEP_FREE(registry->entries);
    registry->entries                 = NULL;
    registry->entry_count             = 0;
    registry->entry_capacity          = 0;
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

    if (!registry->entries) {
        registry->entry_count             = 0;
        registry->entry_capacity          = 0;
        registry->next_registration_order = 0;
        return;
    }

    for (size_t i = 0; i < registry->entry_count; ++i) {
        cep_enzyme_entry_clear(&registry->entries[i]);
    }

    registry->entry_count             = 0;
    registry->next_registration_order = 0;
}


/* Reports how many enzymes are currently tracked so higher layers can decide
 * whether new registrations are needed or whether iteration should even start.
 */
size_t cep_enzyme_registry_size(const cepEnzymeRegistry* registry) {
    return registry ? registry->entry_count : 0u;
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


/* Registers a new enzyme by cloning the query path and storing the descriptor
 * so dispatch can later use the captured data without relying on caller memory.
 */
int cep_enzyme_register(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor) {
    if (!cep_heartbeat_bootstrap()) {
        return CEP_ENZYME_FATAL;
    }

    if (!registry || !query || !descriptor || !descriptor->callback) {
        return CEP_ENZYME_FATAL;
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

    return CEP_ENZYME_FATAL;
}


typedef struct {
    const cepEnzymeDescriptor* descriptor;
    size_t                     specificity;
    size_t                     registration_order;
} cepEnzymeMatch;


typedef struct {
    const cepDT* name;
    size_t       index;
} cepEnzymeMatchLookup;


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


static bool cep_enzyme_match_entry(const cepEnzymeEntry* entry, const cepImpulse* impulse) {
    if (!entry || !impulse) {
        return false;
    }

    const cepPath* query = entry->query;
    if (!query || query->length == 0u) {
        return false;
    }

    const cepPath* signal = impulse->signal_path;
    const cepPath* target = impulse->target_path;

    bool matches = false;

    switch (entry->descriptor.match) {
      case CEP_ENZYME_MATCH_EXACT:
        matches = (signal && cep_enzyme_paths_equal(query, signal)) ||
                  (target && cep_enzyme_paths_equal(query, target));
        break;

      case CEP_ENZYME_MATCH_PREFIX:
        matches = (signal && cep_enzyme_path_is_prefix(query, signal)) ||
                  (target && cep_enzyme_path_is_prefix(query, target));
        break;

      default:
        matches = false;
        break;
    }

    return matches;
}


/* Collects and sorts matching enzymes for a given impulse so execution can walk
 * descriptors by dependency-aware order, falling back to specificity and registration
 * when no additional constraints exist. 
 */
size_t cep_enzyme_resolve(const cepEnzymeRegistry* registry, const cepImpulse* impulse, const cepEnzymeDescriptor** ordered, size_t capacity) {
    if (!registry || !impulse || registry->entry_count == 0u) {
        return 0u;
    }

    cepEnzymeMatch* matches = cep_malloc(registry->entry_count * sizeof(*matches));
    size_t match_count = 0u;

    for (size_t i = 0; i < registry->entry_count; ++i) {
        const cepEnzymeEntry* entry = &registry->entries[i];
        if (!cep_enzyme_match_entry(entry, impulse)) {
            continue;
        }

        matches[match_count].descriptor         = &entry->descriptor;
        matches[match_count].specificity        = entry->query ? entry->query->length : 0u;
        matches[match_count].registration_order = entry->registration_order;
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
    uint8_t* edges = cep_calloc(n * n, sizeof(*edges));

    for (size_t i = 0; i < n; ++i) {
        const cepEnzymeDescriptor* desc = matches[i].descriptor;

        for (size_t b = 0; desc->before && b < desc->before_count; ++b) {
            size_t j = cep_enzyme_match_index_by_name(lookup, n, &desc->before[b]);
            if (j == SIZE_MAX) {
                continue;
            }
            size_t idx = i * n + j;
            if (!edges[idx]) {
                edges[idx] = 1u;
                indegree[j]++;
            }
        }

        for (size_t a = 0; desc->after && a < desc->after_count; ++a) {
            size_t j = cep_enzyme_match_index_by_name(lookup, n, &desc->after[a]);
            if (j == SIZE_MAX) {
                continue;
            }
            size_t idx = j * n + i;
            if (!edges[idx]) {
                edges[idx] = 1u;
                indegree[i]++;
            }
        }
    }

    bool* placed = cep_calloc(n, sizeof(*placed));
    size_t* order = cep_malloc(n * sizeof(*order));
    size_t order_count = 0u;

    for (size_t processed = 0; processed < n; ++processed) {
        size_t best = SIZE_MAX;
        for (size_t i = 0; i < n; ++i) {
            if (placed[i] || indegree[i] != 0u) {
                continue;
            }

            if (best == SIZE_MAX) {
                best = i;
                continue;
            }

            bool more_specific    = matches[i].specificity        > matches[best].specificity;
            bool equally_specific = matches[i].specificity       == matches[best].specificity;
            bool earlier          = matches[i].registration_order < matches[best].registration_order;

            if (more_specific || (equally_specific && earlier)) {
                best = i;
            }
        }

        if (best == SIZE_MAX) {
            order_count = 0u;
            break;
        }

        placed[best] = true;
        order[order_count++] = best;

        for (size_t j = 0; j < n; ++j) {
            size_t idx = best * n + j;
            if (edges[idx] && indegree[j] > 0u) {
                indegree[j]--;
            }
        }
    }

    size_t resolved = (order_count == n) ? n : 0u;

    if (resolved && ordered && capacity > 0u) {
        size_t limit = (resolved < capacity) ? resolved : capacity;
        for (size_t i = 0; i < limit; ++i) {
            ordered[i] = matches[order[i]].descriptor;
        }
    }

    CEP_FREE(order);
    CEP_FREE(placed);
    CEP_FREE(edges);
    CEP_FREE(indegree);
    CEP_FREE(lookup);
    CEP_FREE(matches);

    return resolved;
}
