/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_internal.h"

#include <stdio.h>

/* Record or refresh a pairwise bond by hashing the ordered role tuple into a
   stable cell name, wiring role links, labels, and adjacency mirrors so future
   beats can reason about the relationship deterministically. */
cepL1Result cep_bond_upsert(cepCell* root, const cepBondSpec* spec, cepBondHandle* handle) {
    cepL1Result ready = cep_bond_require_ready();
    if (ready != CEP_L1_OK) {
        return ready;
    }

    if (!spec || !spec->tag || !spec->role_a_tag || !spec->role_b_tag || !spec->role_a || !spec->role_b) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!cep_bond_match_root(root)) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (spec->role_a == spec->role_b) {
        return CEP_L1_ERR_ARGUMENT;
    }

    cepCell* beings_root = CEP_BOND_TOPOLOGY.beings_root;
    cepCell* bonds_root = CEP_BOND_TOPOLOGY.bonds_root;
    if (!beings_root || !bonds_root) {
        return CEP_L1_ERR_STATE;
    }

    if (cep_cell_parent(spec->role_a) != beings_root || cep_cell_parent(spec->role_b) != beings_root) {
        return CEP_L1_ERR_ARGUMENT;
    }

    cepCell* family = cep_cell_find_by_name(bonds_root, spec->tag);
    if (!family) {
        cepDT family_name = *spec->tag;
        cepDT family_type = *spec->tag;
        family = cep_cell_add_dictionary(bonds_root, &family_name, 0, &family_type, CEP_STORAGE_RED_BLACK_T);
        if (!family) {
            return CEP_L1_ERR_MEMORY;
        }
    }

    uint64_t pair_key = cep_bond_compute_pair_key(spec);
    if (!pair_key) {
        return CEP_L1_ERR_STATE;
    }

    cepDT record_name = cep_bond_numeric_name(pair_key);
    cepCell* record = cep_cell_find_by_name(family, &record_name);
    if (!record) {
        cepDT record_type = *spec->tag;
        record = cep_cell_add_dictionary(family, &record_name, 0, &record_type, CEP_STORAGE_RED_BLACK_T);
        if (!record) {
            return CEP_L1_ERR_MEMORY;
        }
    }

    if (spec->metadata) {
        cepL1Result meta_rc = cep_bond_apply_metadata(record, spec->metadata);
        if (meta_rc != CEP_L1_OK) {
            return meta_rc;
        }
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT value_tag = *CEP_DTAW("CEP", "value");
    char partner_identifier[32] = {0};
    char tag_text[12] = {0};
    cep_bond_tag_text(spec->tag, tag_text);
    char summary[96] = {0};

    cepCell* role_entry_a = cep_bond_ensure_dictionary_cell(record, spec->role_a_tag, &dict_type, CEP_STORAGE_LINKED_LIST);
    if (!role_entry_a) {
        return CEP_L1_ERR_MEMORY;
    }
    cep_bond_being_identifier_text(spec->role_b, partner_identifier);
    snprintf(summary, sizeof summary, "%s:%s", tag_text, partner_identifier);
    cepL1Result rc_status = cep_bond_set_text(role_entry_a, &value_tag, summary);
    if (rc_status != CEP_L1_OK) {
        return rc_status;
    }

    cepCell* role_entry_b = cep_bond_ensure_dictionary_cell(record, spec->role_b_tag, &dict_type, CEP_STORAGE_LINKED_LIST);
    if (!role_entry_b) {
        return CEP_L1_ERR_MEMORY;
    }
    cep_bond_being_identifier_text(spec->role_a, partner_identifier);
    snprintf(summary, sizeof summary, "%s:%s", tag_text, partner_identifier);
    rc_status = cep_bond_set_text(role_entry_b, &value_tag, summary);
    if (rc_status != CEP_L1_OK) {
        return rc_status;
    }

    cepDT bond_label_tag = *CEP_DTAW("CEP", "bond_label");
    cepDT bond_note_tag = *CEP_DTAW("CEP", "bond_note");
    rc_status = cep_bond_set_text(record, &bond_label_tag, spec->label);
    if (rc_status != CEP_L1_OK) {
        return rc_status;
    }
    rc_status = cep_bond_set_text(record, &bond_note_tag, spec->note);
    if (rc_status != CEP_L1_OK) {
        return rc_status;
    }

    cep_bond_being_identifier_text(spec->role_b, partner_identifier);
    snprintf(summary, sizeof summary, "%s:%s", tag_text, partner_identifier);
    rc_status = cep_bond_annotate_adjacency(spec->role_a, &record_name, summary);
    if (rc_status != CEP_L1_OK) {
        return rc_status;
    }

    cep_bond_being_identifier_text(spec->role_a, partner_identifier);
    snprintf(summary, sizeof summary, "%s:%s", tag_text, partner_identifier);
    rc_status = cep_bond_annotate_adjacency(spec->role_b, &record_name, summary);
    if (rc_status != CEP_L1_OK) {
        return rc_status;
    }

    if (handle) {
        handle->cell = record;
        handle->revision = cep_cell_latest_timestamp(record);
    }

    return CEP_L1_OK;
}
