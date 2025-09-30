/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_internal.h"

#include <string.h>

typedef struct {
    size_t  facets_attempted;
    size_t  facets_completed;
    size_t  facets_pending;
    size_t  facets_failed;
    size_t  adjacency_pruned;
    size_t  checkpoints_pruned;
} cepBondTickStats;

static const char* cep_bond_cell_text_opt(const cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }
    const cepCell* node = cep_cell_find_by_name(parent, name);
    if (!node || !cep_cell_has_data(node)) {
        return NULL;
    }
    return (const char*)cep_cell_data(node);
}

static void cep_bond_tick_handle_queue_family(cepCell* root, cepCell* queue_family, cepBondTickStats* stats) {
    if (!queue_family || !stats) {
        return;
    }

    const cepDT* facet_tag = cep_cell_get_name(queue_family);
    if (!facet_tag) {
        return;
    }

    size_t count = cep_cell_children(queue_family);
    cepDT queue_state_tag = *CEP_DTAW("CEP", "queue_state");

    for (size_t index = 0; index < count; ++index) {
        cepCell* queue_entry = cep_cell_find_by_position(queue_family, index);
        if (!queue_entry) {
            continue;
        }

        const cepDT* context_name = cep_cell_get_name(queue_entry);
        if (!context_name) {
            continue;
        }

        const char* queue_state = cep_bond_cell_text_opt(queue_entry, &queue_state_tag);
        if (queue_state && strcmp(queue_state, "complete") == 0) {
            cep_cell_remove_hard(queue_entry, NULL);
            ++stats->facets_completed;
            --index;
            --count;
            continue;
        }

        ++stats->facets_attempted;
        cepL1Result rc = cep_facet_dispatch(root, facet_tag, context_name);
        if (rc != CEP_L1_OK) {
            ++stats->facets_failed;
            continue;
        }

        queue_state = cep_bond_cell_text_opt(queue_entry, &queue_state_tag);
        if (!queue_state) {
            ++stats->facets_failed;
            continue;
        }

        if (strcmp(queue_state, "complete") == 0) {
            ++stats->facets_completed;
            cep_cell_remove_hard(queue_entry, NULL);
            --index;
            --count;
        } else if (strcmp(queue_state, "pending") == 0) {
            ++stats->facets_pending;
        } else {
            ++stats->facets_failed;
        }
    }
}

static void cep_bond_tick_prune_facets(cepCell* root, cepBondTickStats* stats) {
    cepCell* facet_queue_root = CEP_BOND_TOPOLOGY.facet_queue_root;
    if (!facet_queue_root || !stats) {
        return;
    }

    size_t families = cep_cell_children(facet_queue_root);
    for (size_t i = 0; i < families; ++i) {
        cepCell* queue_family = cep_cell_find_by_position(facet_queue_root, i);
        if (!queue_family) {
            continue;
        }

        cep_bond_tick_handle_queue_family(root, queue_family, stats);

        if (!cep_cell_children(queue_family)) {
            cep_cell_remove_hard(queue_family, NULL);
            --i;
            --families;
        }
    }
}

static bool cep_bond_should_prune_adjacency_bucket(const cepCell* bucket) {
    if (!bucket) {
        return false;
    }

    const cepDT* being_name = cep_cell_get_name(bucket);
    if (!being_name) {
        return false;
    }

    cepCell* beings_root = CEP_BOND_TOPOLOGY.beings_root;
    if (!beings_root) {
        return false;
    }

    cepCell* being = cep_cell_find_by_name(beings_root, being_name);
    if (!being) {
        return true;
    }

    return cep_cell_is_deleted(being);
}

static void cep_bond_tick_prune_adjacency(cepBondTickStats* stats) {
    cepCell* adjacency_root = CEP_BOND_TOPOLOGY.adjacency_root;
    if (!adjacency_root || !stats) {
        return;
    }

    size_t bucket_count = cep_cell_children(adjacency_root);
    for (size_t i = 0; i < bucket_count; ++i) {
        cepCell* bucket = cep_cell_find_by_position(adjacency_root, i);
        if (!bucket) {
            continue;
        }

        size_t entry_count = cep_cell_children(bucket);
        for (size_t j = 0; j < entry_count; ++j) {
            cepCell* entry = cep_cell_find_by_position(bucket, j);
            if (!entry) {
                continue;
            }

            const char* summary = cep_bond_cell_text_opt(entry, CEP_DTAW("CEP", "value"));
            if (!summary || !*summary) {
                cep_cell_remove_hard(entry, NULL);
                --j;
                --entry_count;
                continue;
            }
        }

        if (!cep_cell_children(bucket) || cep_bond_should_prune_adjacency_bucket(bucket)) {
            cep_cell_remove_hard(bucket, NULL);
            ++stats->adjacency_pruned;
            --i;
            --bucket_count;
        }
    }
}

static void cep_bond_tick_prune_checkpoints(cepBondTickStats* stats) {
    cepCell* checkpoints_root = CEP_BOND_TOPOLOGY.checkpoints_root;
    if (!checkpoints_root || !stats) {
        return;
    }

    size_t families = cep_cell_children(checkpoints_root);
    for (size_t i = 0; i < families; ++i) {
        cepCell* family = cep_cell_find_by_position(checkpoints_root, i);
        if (!family) {
            continue;
        }

        if (cep_cell_children(family) == 0u) {
            cep_cell_remove_hard(family, NULL);
            ++stats->checkpoints_pruned;
            --i;
            --families;
        }
    }
}

/* Drain facet queues, prune adjacency mirrors, and clean idle checkpoint folders
   during the heartbeat tail so Layer 1 keeps derived state tidy. */
cepL1Result cep_tick_l1(cepHeartbeatRuntime* runtime) {
    cepL1Result ready = cep_bond_require_ready();
    if (ready != CEP_L1_OK) {
        return ready;
    }

    cepBondTickStats stats = {0};

    cepCell* root = CEP_BOND_TOPOLOGY.root;
    if (!root && runtime) {
        root = runtime->topology.root;
    }

    cep_bond_tick_prune_facets(root, &stats);
    cep_bond_tick_prune_adjacency(&stats);
    cep_bond_tick_prune_checkpoints(&stats);

    return CEP_L1_OK;
}
