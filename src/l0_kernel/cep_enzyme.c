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

    if (a->name == b->name) {
        return true;
    }
    if (!a->name || !b->name) {
        return false;
    }

    return strcmp(a->name, b->name) == 0;
}


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


void cep_enzyme_registry_destroy(cepEnzymeRegistry* registry) {
    if (!registry) {
        return;
    }

    cep_enzyme_registry_free_all(registry);
    CEP_FREE(registry);
}


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

    for (size_t i = 0; i + 1u < match_count; ++i) {
        size_t best = i;
        for (size_t j = i + 1u; j < match_count; ++j) {
            bool more_specific    = matches[j].specificity        > matches[best].specificity;
            bool equally_specific = matches[j].specificity       == matches[best].specificity;
            bool earlier          = matches[j].registration_order < matches[best].registration_order;

            if (more_specific || (equally_specific && earlier)) {
                best = j;
            }
        }
        if (best != i) {
            cepEnzymeMatch temp = matches[i];
            matches[i]    = matches[best];
            matches[best] = temp;
        }
    }

    if (ordered && capacity > 0u) {
        size_t limit = (match_count < capacity) ? match_count : capacity;
        for (size_t i = 0; i < limit; ++i) {
            ordered[i] = matches[i].descriptor;
        }
    }

    CEP_FREE(matches);
    return match_count;
}
