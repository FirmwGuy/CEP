/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include <stdlib.h>

#include "cep_heartbeat.h"




#define CEP_ENZYME_REGISTRY_DEFAULT_CAPACITY    16u
#define CEP_ENZYME_REGISTRY_MAX_HINT            65536u


static const cepEnzymeRegistry* CEP_ENZYME_SORT_REGISTRY;

typedef struct {
    cepPath*            query;
    cepEnzymeDescriptor descriptor;
    size_t              registration_order;
} cepEnzymeEntry;

typedef struct {
    cepDT   key;
    size_t  offset;
    size_t  count;
} cepEnzymeIndexBucket;

typedef struct {
    cepDT name;
} cepEffectiveBinding;

typedef struct cepEnzymeMatch cepEnzymeMatch;


struct _cepEnzymeRegistry {
    cepEnzymeEntry*     entries;
    size_t              entry_count;
    size_t              entry_capacity;
    size_t              next_registration_order;
    cepEnzymeEntry*     pending_entries;
    size_t              pending_count;
    size_t              pending_capacity;
    size_t*             index_by_name;
    size_t              index_by_name_count;
    cepEnzymeIndexBucket* name_buckets;
    size_t              name_bucket_count;
    size_t*             index_by_signal;
    size_t              index_by_signal_count;
    cepEnzymeIndexBucket* signal_buckets;
    size_t              signal_bucket_count;
};




static bool cep_enzyme_registry_ensure_capacity(cepEnzymeRegistry* registry);
static bool cep_enzyme_registry_pending_ensure_capacity(cepEnzymeRegistry* registry);
static int  cep_enzyme_registry_pending_add(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor);
static bool cep_enzyme_registry_rebuild_indexes(cepEnzymeRegistry* registry);
static cepDT cep_enzyme_query_head(const cepPath* path);
static int cep_enzyme_compare_name_index(const void* lhs, const void* rhs);
static int cep_enzyme_compare_signal_index(const void* lhs, const void* rhs);
static bool cep_enzyme_match_prefer(const cepEnzymeMatch* lhs, const cepEnzymeMatch* rhs);
static const cepEnzymeIndexBucket* cep_enzyme_find_bucket(const cepEnzymeIndexBucket* buckets, size_t bucket_count, const cepDT* key);
static bool cep_enzyme_binding_name_equals(const cepDT* a, const cepDT* b);
static bool cep_enzyme_binding_contains(const cepEffectiveBinding* list, size_t count, const cepDT* name, size_t* index_out);
static cepEffectiveBinding* cep_enzyme_collect_bindings(const cepCell* target, size_t* out_count);
static bool cep_enzyme_matches_signal(const cepEnzymeEntry* entry, const cepPath* signal, size_t* specificity_out);
static void cep_enzyme_match_merge(cepEnzymeMatch* matches, size_t* match_count, const cepEnzymeMatch* candidate);
static size_t cep_enzyme_path_specificity(const cepPath* pattern);
static bool cep_enzyme_dt_matches(const cepDT* pattern, const cepDT* observed);
static bool cep_enzyme_paths_equal(const cepPath* pattern, const cepPath* candidate);
static bool cep_enzyme_path_is_prefix(const cepPath* prefix, const cepPath* path);

static cepDT cep_enzyme_query_head(const cepPath* path) {
    if (!path || path->length == 0u) {
        return (cepDT){ .domain = 0, .tag = 0 };
    }

    return path->past[0].dt;
}

static int cep_enzyme_compare_name_index(const void* lhs, const void* rhs) {
    const cepEnzymeRegistry* registry = CEP_ENZYME_SORT_REGISTRY;
    const size_t ia = *(const size_t*)lhs;
    const size_t ib = *(const size_t*)rhs;
    const cepEnzymeEntry* ea = &registry->entries[ia];
    const cepEnzymeEntry* eb = &registry->entries[ib];

    int cmp = cep_dt_compare(&ea->descriptor.name, &eb->descriptor.name);
    if (cmp != 0) {
        return cmp;
    }

    if (ea->registration_order < eb->registration_order) {
        return -1;
    }
    if (ea->registration_order > eb->registration_order) {
        return 1;
    }

    return 0;
}

static int cep_enzyme_compare_signal_index(const void* lhs, const void* rhs) {
    const cepEnzymeRegistry* registry = CEP_ENZYME_SORT_REGISTRY;
    const size_t ia = *(const size_t*)lhs;
    const size_t ib = *(const size_t*)rhs;
    const cepEnzymeEntry* ea = &registry->entries[ia];
    const cepEnzymeEntry* eb = &registry->entries[ib];

    cepDT head_a = cep_enzyme_query_head(ea->query);
    cepDT head_b = cep_enzyme_query_head(eb->query);

    int cmp = cep_dt_compare(&head_a, &head_b);
    if (cmp != 0) {
        return cmp;
    }

    if (ea->registration_order < eb->registration_order) {
        return -1;
    }
    if (ea->registration_order > eb->registration_order) {
        return 1;
    }

    return 0;
}

static const cepEnzymeIndexBucket* cep_enzyme_find_bucket(const cepEnzymeIndexBucket* buckets, size_t bucket_count, const cepDT* key) {
    size_t lo = 0u;
    size_t hi = bucket_count;

    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1u);
        int cmp = cep_dt_compare(&buckets[mid].key, key);
        if (cmp < 0) {
            lo = mid + 1u;
        } else if (cmp > 0) {
            hi = mid;
        } else {
            return &buckets[mid];
        }
    }

    return NULL;
}

static bool cep_enzyme_binding_name_equals(const cepDT* a, const cepDT* b) {
    return a && b && a->domain == b->domain && a->tag == b->tag;
}

static bool cep_enzyme_binding_contains(const cepEffectiveBinding* list, size_t count, const cepDT* name, size_t* index_out) {
    if (!list || !name) {
        return false;
    }

    for (size_t i = 0; i < count; ++i) {
        if (cep_enzyme_binding_name_equals(&list[i].name, name)) {
            if (index_out) {
                *index_out = i;
            }
            return true;
        }
    }

    return false;
}

static bool cep_enzyme_registry_rebuild_indexes(cepEnzymeRegistry* registry) {
    CEP_FREE(registry->index_by_name);
    CEP_FREE(registry->name_buckets);
    CEP_FREE(registry->index_by_signal);
    CEP_FREE(registry->signal_buckets);

    registry->index_by_name = NULL;
    registry->index_by_name_count = 0;
    registry->name_buckets = NULL;
    registry->name_bucket_count = 0;
    registry->index_by_signal = NULL;
    registry->index_by_signal_count = 0;
    registry->signal_buckets = NULL;
    registry->signal_bucket_count = 0;

    size_t n = registry->entry_count;
    if (n == 0u) {
        return true;
    }

    size_t* by_name = cep_malloc(n * sizeof(*by_name));
    size_t* by_signal = cep_malloc(n * sizeof(*by_signal));
    if (!by_name || !by_signal) {
        CEP_FREE(by_name);
        CEP_FREE(by_signal);
        return false;
    }

    for (size_t i = 0; i < n; ++i) {
        by_name[i] = i;
        by_signal[i] = i;
    }

    CEP_ENZYME_SORT_REGISTRY = registry;
    qsort(by_name, n, sizeof(*by_name), cep_enzyme_compare_name_index);
    qsort(by_signal, n, sizeof(*by_signal), cep_enzyme_compare_signal_index);
    CEP_ENZYME_SORT_REGISTRY = NULL;

    cepEnzymeIndexBucket* name_buckets = cep_malloc(n * sizeof(*name_buckets));
    cepEnzymeIndexBucket* signal_buckets = cep_malloc(n * sizeof(*signal_buckets));
    if ((!name_buckets && n > 0u) || (!signal_buckets && n > 0u)) {
        CEP_FREE(by_name);
        CEP_FREE(by_signal);
        CEP_FREE(name_buckets);
        CEP_FREE(signal_buckets);
        return false;
    }

    size_t name_bucket_count = 0u;
    for (size_t i = 0; i < n; ) {
        size_t start = i;
        const cepEnzymeEntry* entry = &registry->entries[by_name[i]];
        cepDT key = entry->descriptor.name;
        ++i;
        while (i < n) {
            const cepEnzymeEntry* next_entry = &registry->entries[by_name[i]];
            if (cep_dt_compare(&key, &next_entry->descriptor.name) != 0) {
                break;
            }
            ++i;
        }

        name_buckets[name_bucket_count++] = (cepEnzymeIndexBucket) {
            .key    = key,
            .offset = start,
            .count  = i - start,
        };
    }

    size_t signal_bucket_count = 0u;
    for (size_t i = 0; i < n; ) {
        size_t start = i;
        const cepEnzymeEntry* entry = &registry->entries[by_signal[i]];
        cepDT key = cep_enzyme_query_head(entry->query);
        ++i;
        while (i < n) {
            const cepEnzymeEntry* next_entry = &registry->entries[by_signal[i]];
            cepDT next_key = cep_enzyme_query_head(next_entry->query);
            if (cep_dt_compare(&key, &next_key) != 0) {
                break;
            }
            ++i;
        }

        signal_buckets[signal_bucket_count++] = (cepEnzymeIndexBucket) {
            .key    = key,
            .offset = start,
            .count  = i - start,
        };
    }

    registry->index_by_name = by_name;
    registry->index_by_name_count = n;
    registry->name_buckets = name_buckets;
    registry->name_bucket_count = name_bucket_count;
    registry->index_by_signal = by_signal;
    registry->index_by_signal_count = n;
    registry->signal_buckets = signal_buckets;
    registry->signal_bucket_count = signal_bucket_count;

    return true;
}

static cepEffectiveBinding* cep_enzyme_collect_bindings(const cepCell* target, size_t* out_count) {
    if (out_count) {
        *out_count = 0u;
    }
    if (!target) {
        return NULL;
    }

    cepEffectiveBinding* active = NULL;
    size_t active_count = 0u;
    size_t active_capacity = 0u;

    cepEffectiveBinding* blocked = NULL;
    size_t blocked_count = 0u;
    size_t blocked_capacity = 0u;

    for (const cepCell* cell = target; cell; cell = cep_cell_parent(cell)) {
        bool is_target = (cell == target);
        const cepEnzymeBinding* binding = cep_cell_enzyme_bindings(cell);
        if (!binding) {
            continue;
        }

        cepEffectiveBinding* local_seen = NULL;
        size_t local_count = 0u;
        size_t local_capacity = 0u;

        for (const cepEnzymeBinding* node = binding; node; node = node->next) {
            if (cep_enzyme_binding_contains(local_seen, local_count, &node->name, NULL)) {
                continue;
            }

            if (local_count == local_capacity) {
                size_t new_capacity = local_capacity ? (local_capacity << 1u) : 4u;
                cepEffectiveBinding* resized = cep_realloc(local_seen, new_capacity * sizeof(*resized));
                if (!resized) {
                    CEP_FREE(local_seen);
                    CEP_FREE(blocked);
                    CEP_FREE(active);
                    if (out_count) {
                        *out_count = SIZE_MAX;
                    }
                    return NULL;
                }
                local_seen = resized;
                local_capacity = new_capacity;
            }
            local_seen[local_count++].name = node->name;

            if (node->flags & CEP_ENZYME_BIND_TOMBSTONE) {
                size_t idx;
                if (cep_enzyme_binding_contains(active, active_count, &node->name, &idx)) {
                    if (idx + 1u < active_count) {
                        memmove(&active[idx], &active[idx + 1u], (active_count - (idx + 1u)) * sizeof(*active));
                    }
                    active_count--;
                }
                if (!cep_enzyme_binding_contains(blocked, blocked_count, &node->name, NULL)) {
                    if (blocked_count == blocked_capacity) {
                        size_t new_capacity = blocked_capacity ? (blocked_capacity << 1u) : 8u;
                        cepEffectiveBinding* resized = cep_realloc(blocked, new_capacity * sizeof(*resized));
                        if (!resized) {
                            CEP_FREE(local_seen);
                        CEP_FREE(blocked);
                        CEP_FREE(active);
                        if (out_count) {
                            *out_count = SIZE_MAX;
                        }
                        return NULL;
                    }
                    blocked = resized;
                    blocked_capacity = new_capacity;
                }
                    blocked[blocked_count++].name = node->name;
                }
                continue;
            }

            if (!is_target && !(node->flags & CEP_ENZYME_BIND_PROPAGATE)) {
                continue;
            }

            if (cep_enzyme_binding_contains(blocked, blocked_count, &node->name, NULL)) {
                continue;
            }

            if (!cep_enzyme_binding_contains(active, active_count, &node->name, NULL)) {
                if (active_count == active_capacity) {
                    size_t new_capacity = active_capacity ? (active_capacity << 1u) : 8u;
                    cepEffectiveBinding* resized = cep_realloc(active, new_capacity * sizeof(*resized));
                    if (!resized) {
                        CEP_FREE(local_seen);
                        CEP_FREE(blocked);
                        CEP_FREE(active);
                        if (out_count) {
                            *out_count = SIZE_MAX;
                        }
                        return NULL;
                    }
                    active = resized;
                    active_capacity = new_capacity;
                }
                active[active_count++].name = node->name;
            }
        }

        CEP_FREE(local_seen);
    }

    CEP_FREE(blocked);

    if (out_count) {
        *out_count = active_count;
    }
    return active;
}

static bool cep_enzyme_matches_signal(const cepEnzymeEntry* entry, const cepPath* signal, size_t* specificity_out) {
    if (specificity_out) {
        *specificity_out = 0u;
    }

    if (!entry || !signal) {
        return false;
    }

    if (!entry->query || entry->query->length == 0u) {
        if (specificity_out) {
            *specificity_out = 0u;
        }
        return true;
    }

    size_t specificity = cep_enzyme_path_specificity(entry->query);

    switch (entry->descriptor.match) {
      case CEP_ENZYME_MATCH_EXACT:
        if (entry->query->length == signal->length && cep_enzyme_paths_equal(entry->query, signal)) {
            if (specificity_out) {
                *specificity_out = specificity;
            }
            return true;
        }
        return false;

      case CEP_ENZYME_MATCH_PREFIX:
        if (cep_enzyme_path_is_prefix(entry->query, signal)) {
            if (specificity_out) {
                *specificity_out = specificity;
            }
            return true;
        }
        return false;

      default:
        break;
    }

    return false;
}

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

    CEP_FREE(registry->index_by_name);
    CEP_FREE(registry->name_buckets);
    CEP_FREE(registry->index_by_signal);
    CEP_FREE(registry->signal_buckets);

    registry->entries                 = NULL;
    registry->entry_count             = 0;
    registry->entry_capacity          = 0;
    registry->pending_entries         = NULL;
    registry->pending_count           = 0;
    registry->pending_capacity        = 0;
    registry->next_registration_order = 0;
    registry->index_by_name           = NULL;
    registry->index_by_name_count     = 0;
    registry->name_buckets            = NULL;
    registry->name_bucket_count       = 0;
    registry->index_by_signal         = NULL;
    registry->index_by_signal_count   = 0;
    registry->signal_buckets          = NULL;
    registry->signal_bucket_count     = 0;
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


static size_t cep_enzyme_path_specificity(const cepPath* pattern) {
    if (!pattern || pattern->length == 0u) {
        return 0u;
    }

    size_t specificity = 0u;
    for (unsigned i = 0; i < pattern->length; ++i) {
        const cepDT* dt = &pattern->past[i].dt;
        if (!cep_id_is_match_any(dt->domain)) {
            specificity++;
        }
        if (!cep_id_is_match_any(dt->tag)) {
            specificity++;
        }
    }

    return specificity;
}


static bool cep_enzyme_dt_matches(const cepDT* pattern, const cepDT* observed) {
    if (!pattern || !observed) {
        return false;
    }

    return cep_id_matches(pattern->domain, observed->domain) &&
           cep_id_matches(pattern->tag, observed->tag);
}


static bool cep_enzyme_paths_equal(const cepPath* pattern, const cepPath* candidate) {
    if (pattern == candidate) {
        return true;
    }
    if (!pattern || !candidate) {
        return false;
    }
    if (pattern->length != candidate->length) {
        return false;
    }

    for (unsigned i = 0; i < pattern->length; ++i) {
        if (!cep_enzyme_dt_matches(&pattern->past[i].dt, &candidate->past[i].dt)) {
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
        if (!cep_enzyme_dt_matches(&prefix->past[i].dt, &path->past[i].dt)) {
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


/** Create a registry instance so enzymes can be registered and perform an
    upfront capacity reservation based on environment hints to reduce later
    reallocations. */
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


/** Tear down a registry by releasing all tracked entries so callers avoid
    leaking per-enzyme allocations when the runtime shuts down. */
void cep_enzyme_registry_destroy(cepEnzymeRegistry* registry) {
    if (!registry) {
        return;
    }

    cep_enzyme_registry_free_all(registry);
    CEP_FREE(registry);
}


/** Clear the registry contents while keeping the buffer alive so repeated test
    runs can start from a clean slate without paying the allocation cost again. */
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
        CEP_FREE(registry->index_by_name);
        CEP_FREE(registry->name_buckets);
        CEP_FREE(registry->index_by_signal);
        CEP_FREE(registry->signal_buckets);
        registry->index_by_name         = NULL;
        registry->index_by_name_count   = 0;
        registry->name_buckets          = NULL;
        registry->name_bucket_count     = 0;
        registry->index_by_signal       = NULL;
        registry->index_by_signal_count = 0;
        registry->signal_buckets        = NULL;
        registry->signal_bucket_count   = 0;
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
    CEP_FREE(registry->index_by_name);
    registry->index_by_name = NULL;
    registry->index_by_name_count = 0;
    CEP_FREE(registry->name_buckets);
    registry->name_buckets = NULL;
    registry->name_bucket_count = 0;
    CEP_FREE(registry->index_by_signal);
    registry->index_by_signal = NULL;
    registry->index_by_signal_count = 0;
    CEP_FREE(registry->signal_buckets);
    registry->signal_buckets = NULL;
    registry->signal_bucket_count = 0;
}


/** Report how many enzymes are currently tracked so higher layers can decide
    whether new registrations are needed or whether iteration should even
    start. */
size_t cep_enzyme_registry_size(const cepEnzymeRegistry* registry) {
    return registry ? registry->entry_count : 0u;
}


/** Promote pending enzyme registrations into the active registry so the next
    beat observes them in deterministic order without mutating the frozen agenda
    mid-cycle. */
void cep_enzyme_registry_activate_pending(cepEnzymeRegistry* registry) {
    if (!registry || registry->pending_count == 0u) {
        return;
    }

    size_t required = registry->entry_count + registry->pending_count;
    while (registry->entry_capacity < required) {
        if (!cep_enzyme_registry_ensure_capacity(registry)) {
            return;
        }
    }

    for (size_t i = 0; i < registry->pending_count; ++i) {
        cepEnzymeEntry* pending = &registry->pending_entries[i];
        if (!pending->query || !pending->descriptor.callback) {
            cep_enzyme_entry_clear(pending);
            continue;
        }

        cepEnzymeEntry* entry = &registry->entries[registry->entry_count++];
        *entry = *pending;
        entry->registration_order = registry->next_registration_order++;
        CEP_0(pending);
    }

    registry->pending_count = 0u;

    (void)cep_enzyme_registry_rebuild_indexes(registry);
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
    CEP_0(entry);
    entry->query              = copy;
    entry->descriptor         = *descriptor;
    entry->registration_order = 0u;

    return CEP_ENZYME_SUCCESS;
}


/** Register a new enzyme by cloning the query path and storing the descriptor
    for deterministic dispatch, deferring activation to the next beat when the
    heartbeat is live so mid-beat registrations never perturb the frozen
    agenda. */
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

    (void)cep_enzyme_registry_rebuild_indexes(registry);

    return CEP_ENZYME_SUCCESS;
}


/** Remove a previously registered enzyme entry to keep dispatch decisions in
    sync with caller intent, compacting the table so subsequent lookups stay
    fast. */
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
        (void)cep_enzyme_registry_rebuild_indexes(registry);
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
        (void)cep_enzyme_registry_rebuild_indexes(registry);
        return CEP_ENZYME_SUCCESS;
    }

    return CEP_ENZYME_FATAL;
}


struct cepEnzymeMatch {
    const cepEnzymeDescriptor* descriptor;
    size_t                     specificity_signal;
    size_t                     specificity_target;
    size_t                     specificity_total;
    size_t                     registration_order;
    uint8_t                    match_type;
};


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

static void cep_enzyme_match_merge(cepEnzymeMatch* matches, size_t* match_count, const cepEnzymeMatch* candidate) {
    if (!matches || !match_count || !candidate || !candidate->descriptor) {
        return;
    }

    for (size_t i = 0; i < *match_count; ++i) {
        if (matches[i].descriptor == candidate->descriptor) {
            if (cep_enzyme_match_prefer(candidate, &matches[i])) {
                matches[i] = *candidate;
            }
            return;
        }
    }

    matches[(*match_count)++] = *candidate;
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


/** Resolve an impulse by merging cell-bound bindings with signal-indexed
    filters, then building a deterministic execution order that honours
    dependencies and specificity. The routine gathers bindings along the target
    path, intersects them with signal matches, and performs a stable
    topological sort before materialising the agenda into @p ordered. */
size_t cep_enzyme_resolve(const cepEnzymeRegistry* registry, const cepImpulse* impulse, const cepEnzymeDescriptor** ordered, size_t capacity) {
    if (!registry || !impulse || registry->entry_count == 0u) {
        return 0u;
    }

    size_t registry_count = registry->entry_count;
    cepEnzymeMatch* matches = cep_malloc(registry_count * sizeof(*matches));
    if (!matches) {
        return 0u;
    }
    size_t match_count = 0u;

    if (registry_count > 0u &&
        (!registry->index_by_name || !registry->name_buckets ||
         !registry->index_by_signal || !registry->signal_buckets)) {
        (void)cep_enzyme_registry_rebuild_indexes((cepEnzymeRegistry*)registry);
    }

    const cepPath* signal = impulse->signal_path;
    const cepPath* target_path = impulse->target_path;

    cepEffectiveBinding* bindings = NULL;
    size_t binding_count = 0u;

    if (target_path) {
        const cepHeartbeatTopology* topology = cep_heartbeat_topology();
        const cepCell* root = topology ? topology->root : NULL;
        cepCell* target_cell = root ? cep_cell_find_by_path(root, target_path) : NULL;
        if (target_cell) {
            bindings = cep_enzyme_collect_bindings(target_cell, &binding_count);
            if (binding_count == SIZE_MAX) {
                CEP_FREE(matches);
                return 0u;
            }
        }
    }


    if (binding_count > 0u) {
        for (size_t i = 0; i < binding_count; ++i) {
            const cepEnzymeIndexBucket* bucket = cep_enzyme_find_bucket(registry->name_buckets, registry->name_bucket_count, &bindings[i].name);
            if (!bucket) {
                continue;
            }

            cepEnzymeMatch best = {0};
            bool best_valid = false;

            for (size_t offset = 0; offset < bucket->count; ++offset) {
                size_t entry_index = registry->index_by_name[bucket->offset + offset];
                if (entry_index >= registry_count) {
                    continue;
                }

                const cepEnzymeEntry* entry = &registry->entries[entry_index];

                size_t target_specificity = cep_enzyme_path_specificity(entry->query);

                cepEnzymeMatch candidate = {
                    .descriptor = &entry->descriptor,
                    .specificity_signal = 0u,
                    .specificity_target = target_specificity,
                    .specificity_total = target_specificity,
                    .registration_order = entry->registration_order,
                    .match_type = CEP_ENZYME_MATCH_FLAG_TARGET,
                };

                if (signal) {
                    size_t signal_specificity = 0u;
                    if (!cep_enzyme_matches_signal(entry, signal, &signal_specificity)) {
                        continue;
                    }
                    candidate.match_type |= CEP_ENZYME_MATCH_FLAG_SIGNAL;
                    candidate.specificity_signal = signal_specificity;
                    candidate.specificity_total += signal_specificity;
                }

                if (candidate.specificity_total == 0u) {
                    candidate.specificity_total = candidate.specificity_target ? candidate.specificity_target : candidate.specificity_signal;
                }

                if (!best_valid || cep_enzyme_match_prefer(&candidate, &best)) {
                    best = candidate;
                    best_valid = true;
                }
            }

            if (best_valid) {
                cep_enzyme_match_merge(matches, &match_count, &best);
            }
        }
    }

    if (!target_path && signal) {
        cepDT head = cep_enzyme_query_head(signal);
        size_t begin = 0u;
        size_t end = registry_count;

        if (registry->signal_bucket_count > 0u) {
            const cepEnzymeIndexBucket* bucket = cep_enzyme_find_bucket(registry->signal_buckets, registry->signal_bucket_count, &head);
            if (bucket) {
                begin = bucket->offset;
                end = bucket->offset + bucket->count;
            }
        }

        for (size_t offset = begin; offset < end; ++offset) {
            size_t entry_index = registry->index_by_signal ? registry->index_by_signal[offset] : offset;
            if (entry_index >= registry_count) {
                continue;
            }

            const cepEnzymeEntry* entry = &registry->entries[entry_index];
            size_t signal_specificity = 0u;
            if (!cep_enzyme_matches_signal(entry, signal, &signal_specificity)) {
                continue;
            }

            cepEnzymeMatch candidate = {
                .descriptor = &entry->descriptor,
                .specificity_signal = signal_specificity,
                .specificity_target = 0u,
                .specificity_total = signal_specificity ? signal_specificity : cep_enzyme_path_specificity(entry->query),
                .registration_order = entry->registration_order,
                .match_type = CEP_ENZYME_MATCH_FLAG_SIGNAL,
            };

            cep_enzyme_match_merge(matches, &match_count, &candidate);
        }
    }

    CEP_FREE(bindings);

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
