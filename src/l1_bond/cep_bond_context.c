/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_internal.h"

#include <stdio.h>

/* Materialise a multi-party context as a keyed simplex, linking every role
   back to its being, mirroring adjacency summaries, and queueing the required
   facets so orchestration stays consistent across beats. */
cepL1Result cep_context_upsert(cepCell* root, const cepContextSpec* spec, cepContextHandle* handle) {
    cepL1Result ready = cep_bond_require_ready();
    if (ready != CEP_L1_OK) {
        return ready;
    }

    if (!spec || !spec->tag || spec->role_count == 0 || !spec->role_tags || !spec->role_targets) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!cep_bond_match_root(root)) {
        return CEP_L1_ERR_ARGUMENT;
    }

    cepCell* beings_root = CEP_BOND_TOPOLOGY.beings_root;
    cepCell* contexts_root = CEP_BOND_TOPOLOGY.contexts_root;
    cepCell* facets_root = CEP_BOND_TOPOLOGY.facets_root;
    cepCell* facet_queue_root = CEP_BOND_TOPOLOGY.facet_queue_root;
    if (!beings_root || !contexts_root || !facets_root || !facet_queue_root) {
        return CEP_L1_ERR_STATE;
    }

    for (size_t i = 0; i < spec->role_count; ++i) {
        if (!spec->role_targets[i] || cep_cell_parent(spec->role_targets[i]) != beings_root) {
            return CEP_L1_ERR_ARGUMENT;
        }
    }

    cepCell* family = cep_cell_find_by_name(contexts_root, spec->tag);
    if (!family) {
        cepDT family_name = *spec->tag;
        cepDT family_type = *spec->tag;
        family = cep_cell_add_dictionary(contexts_root, &family_name, 0, &family_type, CEP_STORAGE_RED_BLACK_T);
        if (!family) {
            return CEP_L1_ERR_MEMORY;
        }
    }

    uint64_t context_key = cep_context_compute_key(spec);
    if (!context_key) {
        return CEP_L1_ERR_STATE;
    }

    cepDT context_name = cep_bond_numeric_name(context_key);
    cepCell* context = cep_cell_find_by_name(family, &context_name);
    if (!context) {
        cepDT context_type = *spec->tag;
        context = cep_cell_add_dictionary(family, &context_name, 0, &context_type, CEP_STORAGE_RED_BLACK_T);
        if (!context) {
            return CEP_L1_ERR_MEMORY;
        }
    }

    if (spec->metadata) {
        cepL1Result meta_rc = cep_bond_apply_metadata(context, spec->metadata);
        if (meta_rc != CEP_L1_OK) {
            return meta_rc;
        }
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT value_tag = *CEP_DTAW("CEP", "value");
    for (size_t i = 0; i < spec->role_count; ++i) {
        cepCell* role_entry = cep_bond_ensure_dictionary_cell(context, spec->role_tags[i], &dict_type, CEP_STORAGE_LINKED_LIST);
        if (!role_entry) {
            return CEP_L1_ERR_MEMORY;
        }
        char being_identifier[32] = {0};
        cep_bond_being_identifier_text(spec->role_targets[i], being_identifier);
        cepL1Result rc_local = cep_bond_set_text(role_entry, &value_tag, being_identifier);
        if (rc_local != CEP_L1_OK) {
            return rc_local;
        }
    }

    cepDT ctx_label_tag = *CEP_DTAW("CEP", "ctx_label");
    cepL1Result rc = cep_bond_set_text(context, &ctx_label_tag, spec->label);
    if (rc != CEP_L1_OK) {
        return rc;
    }

    char ctx_tag_text[12] = {0};
    cep_bond_tag_text(spec->tag, ctx_tag_text);
    const char* ctx_label = spec->label ? spec->label : ctx_tag_text;

    char summary[96] = {0};
    for (size_t i = 0; i < spec->role_count; ++i) {
        snprintf(summary, sizeof summary, "%s:%s", ctx_tag_text, ctx_label);
        rc = cep_bond_annotate_adjacency(spec->role_targets[i], &context_name, summary);
        if (rc != CEP_L1_OK) {
            return rc;
        }
    }

    const char* pending = "pending";
    cepDT facet_state_tag = *CEP_DTAW("CEP", "facet_state");
    cepDT queue_state_tag = *CEP_DTAW("CEP", "queue_state");
    for (size_t i = 0; i < spec->facet_count; ++i) {
        const cepDT* facet_tag = spec->facet_tags[i];
        if (!facet_tag) {
            continue;
        }

        cepCell* facet_family = cep_bond_ensure_dictionary_cell(facets_root, facet_tag, facet_tag, CEP_STORAGE_RED_BLACK_T);
        if (!facet_family) {
            return CEP_L1_ERR_MEMORY;
        }

        cepCell* facet_record = cep_bond_ensure_dictionary_cell(facet_family, &context_name, &dict_type, CEP_STORAGE_LINKED_LIST);
        if (!facet_record) {
            return CEP_L1_ERR_MEMORY;
        }
        rc = cep_bond_set_text(facet_record, &facet_state_tag, pending);
        if (rc != CEP_L1_OK) {
            return rc;
        }
        rc = cep_bond_set_text(facet_record, &value_tag, ctx_label);
        if (rc != CEP_L1_OK) {
            return rc;
        }

        cepCell* queue_family = cep_bond_ensure_dictionary_cell(facet_queue_root, facet_tag, &dict_type, CEP_STORAGE_LINKED_LIST);
        if (!queue_family) {
            return CEP_L1_ERR_MEMORY;
        }
        cepCell* queue_entry = cep_bond_ensure_dictionary_cell(queue_family, &context_name, &dict_type, CEP_STORAGE_LINKED_LIST);
        if (!queue_entry) {
            return CEP_L1_ERR_MEMORY;
        }
        rc = cep_bond_set_text(queue_entry, &value_tag, ctx_label);
        if (rc != CEP_L1_OK) {
            return rc;
        }
        rc = cep_bond_set_text(queue_entry, &queue_state_tag, pending);
        if (rc != CEP_L1_OK) {
            return rc;
        }
    }

    if (handle) {
        handle->cell = context;
        handle->revision = cep_cell_latest_timestamp(context);
    }

    return CEP_L1_OK;
}
