/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_internal.h"

#include <string.h>

static bool cep_bond_facet_policy_valid(cepFacetPolicy policy);
static cepFacetRegistryEntry* cep_bond_registry_find_mutable(const cepDT* facet_tag, const cepDT* context_tag);

cepFacetRegistry CEP_FACET_REGISTRY;

static bool cep_bond_facet_policy_valid(cepFacetPolicy policy) {
    switch (policy) {
        case CEP_FACET_POLICY_DEFAULT:
        case CEP_FACET_POLICY_RETRY:
        case CEP_FACET_POLICY_ABORT:
            return true;
        default:
            break;
    }
    return false;
}

static bool cep_bond_dt_equals(const cepDT* a, const cepDT* b) {
    if (!a || !b) {
        return a == b;
    }
    return cep_dt_compare(a, b) == 0;
}

static cepFacetRegistryEntry* cep_bond_registry_find_mutable(const cepDT* facet_tag, const cepDT* context_tag) {
    if (!facet_tag || !context_tag) {
        return NULL;
    }

    for (size_t i = 0; i < CEP_FACET_REGISTRY.count; ++i) {
        cepFacetRegistryEntry* entry = &CEP_FACET_REGISTRY.entries[i];
        if (cep_bond_dt_equals(entry->facet_tag, facet_tag) && cep_bond_dt_equals(entry->context_tag, context_tag)) {
            return entry;
        }
    }

    return NULL;
}

const cepFacetRegistryEntry* cep_bond_lookup_facet(const cepDT* facet_tag, const cepDT* context_tag) {
    return cep_bond_registry_find_mutable(facet_tag, context_tag);
}

/* Register a facet materialiser so future contexts know which enzyme handles
   closure and which retry policy it follows, rejecting duplicates to keep
   dispatch deterministic. */
cepL1Result cep_facet_register(const cepFacetSpec* spec) {
    cepL1Result ready = cep_bond_require_ready();
    if (ready != CEP_L1_OK) {
        return ready;
    }

    if (!spec || !spec->facet_tag || !spec->source_context_tag || !spec->materialiser) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!cep_bond_facet_policy_valid(spec->policy)) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (cep_bond_registry_find_mutable(spec->facet_tag, spec->source_context_tag)) {
        return CEP_L1_ERR_DUPLICATE;
    }

    if (CEP_FACET_REGISTRY.count == CEP_FACET_REGISTRY.capacity) {
        size_t new_capacity = CEP_FACET_REGISTRY.capacity ? CEP_FACET_REGISTRY.capacity * 2u : 4u;
        size_t bytes = new_capacity * sizeof *CEP_FACET_REGISTRY.entries;
        cepFacetRegistryEntry* grown = CEP_FACET_REGISTRY.entries
            ? cep_realloc(CEP_FACET_REGISTRY.entries, bytes)
            : cep_malloc(bytes);
        CEP_FACET_REGISTRY.entries = grown;
        CEP_FACET_REGISTRY.capacity = new_capacity;
    }

    cepFacetRegistryEntry* entry = &CEP_FACET_REGISTRY.entries[CEP_FACET_REGISTRY.count++];
    entry->facet_tag = spec->facet_tag;
    entry->context_tag = spec->source_context_tag;
    entry->materialiser = spec->materialiser;
    entry->policy = spec->policy;

    return CEP_L1_OK;
}

static const char* cep_bond_cell_text(const cepCell* cell) {
    if (!cell || !cep_cell_has_data(cell)) {
        return NULL;
    }
    return (const char*)cep_cell_data(cell);
}

static cepCell* cep_bond_find_context_cell(const cepDT* context_name, const cepDT** context_tag_out) {
    cepCell* contexts_root = CEP_BOND_TOPOLOGY.contexts_root;
    if (!contexts_root || !context_name) {
        return NULL;
    }

    size_t families = cep_cell_children(contexts_root);
    for (size_t i = 0; i < families; ++i) {
        cepCell* family = cep_cell_find_by_position(contexts_root, i);
        if (!family) {
            continue;
        }

        cepCell* candidate = cep_cell_find_by_name(family, context_name);
        if (candidate) {
            if (context_tag_out) {
                *context_tag_out = cep_cell_get_name(family);
            }
            return candidate;
        }
    }

    return NULL;
}

typedef struct {
    cepPath path;
    cepPast segments[6];
} cepBondPath6;

static void cep_bond_path_fill(cepBondPath6* holder, size_t count, const cepDT* const* tags) {
    CEP_0(holder);
    holder->path.capacity = (unsigned)(sizeof holder->segments / sizeof holder->segments[0]);
    holder->path.length = (unsigned)count;
    for (size_t i = 0; i < count && i < holder->path.capacity; ++i) {
        holder->segments[i].dt = *tags[i];
        holder->segments[i].timestamp = 0;
    }
}

static const cepDT* dt_namespace(void)     { return CEP_DTAA("CEP", "CEP"); }
static const cepDT* dt_l1_root(void)       { return CEP_DTAA("CEP", "L1"); }
static const cepDT* dt_data_root(void)     { return CEP_DTAW("CEP", "data"); }
static const cepDT* dt_facets_root(void)   { return CEP_DTAW("CEP", "facets"); }
static const cepDT* dt_facet_queue_root(void) { return CEP_DTAW("CEP", "facet_queue"); }

cepL1Result cep_facet_dispatch(cepCell* root, const cepDT* facet_tag, const cepDT* context_name) {
    cepL1Result ready = cep_bond_require_ready();
    if (ready != CEP_L1_OK) {
        return ready;
    }

    if (!facet_tag || !context_name) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!cep_bond_match_root(root)) {
        return CEP_L1_ERR_ARGUMENT;
    }

    cepCell* facet_queue_root = CEP_BOND_TOPOLOGY.facet_queue_root;
    cepCell* facets_root = CEP_BOND_TOPOLOGY.facets_root;
    if (!facet_queue_root || !facets_root) {
        return CEP_L1_ERR_STATE;
    }

    cepCell* queue_family = cep_cell_find_by_name(facet_queue_root, facet_tag);
    if (!queue_family) {
        return CEP_L1_ERR_STATE;
    }

    cepCell* queue_entry = cep_cell_find_by_name(queue_family, context_name);
    if (!queue_entry) {
        return CEP_L1_ERR_STATE;
    }

    cepDT queue_state_tag = *CEP_DTAW("CEP", "queue_state");
    const char* queue_state = cep_bond_cell_text(cep_cell_find_by_name(queue_entry, &queue_state_tag));
    if (queue_state && strcmp(queue_state, "complete") == 0) {
        return CEP_L1_OK;
    }

    const cepDT* context_tag = NULL;
    cepCell* context = cep_bond_find_context_cell(context_name, &context_tag);
    if (!context || !context_tag) {
        return CEP_L1_ERR_STATE;
    }

    const cepFacetRegistryEntry* entry = cep_bond_lookup_facet(facet_tag, context_tag);
    if (!entry || !entry->materialiser) {
        (void)cep_bond_set_text(queue_entry, &queue_state_tag, "missing");
        return CEP_L1_ERR_STATE;
    }

    cepCell* facet_family = cep_cell_find_by_name(facets_root, facet_tag);
    if (!facet_family) {
        return CEP_L1_ERR_STATE;
    }

    cepCell* facet_record = cep_cell_find_by_name(facet_family, context_name);
    if (!facet_record) {
        return CEP_L1_ERR_STATE;
    }

    const cepDT context_key = *context_name;

    const cepDT* signal_segments[] = {
        dt_facet_queue_root(),
        facet_tag,
        &context_key,
    };

    const cepDT* target_segments[] = {
        dt_data_root(),
        dt_namespace(),
        dt_l1_root(),
        dt_facets_root(),
        facet_tag,
        &context_key,
    };

    cepBondPath6 signal_path;
    cepBondPath6 target_path;
    cep_bond_path_fill(&signal_path, sizeof signal_segments / sizeof signal_segments[0], signal_segments);
    cep_bond_path_fill(&target_path, sizeof target_segments / sizeof target_segments[0], target_segments);

    int enzyme_rc = entry->materialiser(&signal_path.path, &target_path.path);

    cepDT value_tag = *CEP_DTAW("CEP", "value");
    const char* label = cep_bond_cell_text(cep_cell_find_by_name(queue_entry, &value_tag));
    if (label) {
        (void)cep_bond_set_text(facet_record, &value_tag, label);
    }

    const char* facet_state_value = NULL;
    const char* queue_state_value = NULL;

    switch (enzyme_rc) {
        case CEP_ENZYME_SUCCESS:
            facet_state_value = "complete";
            queue_state_value = "complete";
            break;
        case CEP_ENZYME_RETRY:
            facet_state_value = "pending";
            queue_state_value = "pending";
            break;
        case CEP_ENZYME_FATAL:
        default:
            facet_state_value = "failed";
            queue_state_value = "fatal";
            break;
    }

    cepDT facet_state_tag = *CEP_DTAW("CEP", "facet_state");
    (void)cep_bond_set_text(facet_record, &facet_state_tag, facet_state_value);
    (void)cep_bond_set_text(queue_entry, &queue_state_tag, queue_state_value);

    return (enzyme_rc == CEP_ENZYME_FATAL) ? CEP_L1_ERR_STATE : CEP_L1_OK;
}
