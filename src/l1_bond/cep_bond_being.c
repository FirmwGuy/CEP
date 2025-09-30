/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_internal.h"

/* Claim or create a Layer 1 being so callers always land on the same identity
   card, updating friendly labels and metadata while keeping the record rooted in
   the CEP:L1/beings dictionary for append-only history. */
cepL1Result cep_being_claim(cepCell* root, const cepDT* name, const cepBeingSpec* spec, cepBeingHandle* handle) {
    cepL1Result ready = cep_bond_require_ready();
    if (ready != CEP_L1_OK) {
        return ready;
    }

    if (!name || !handle) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!cep_bond_match_root(root)) {
        return CEP_L1_ERR_ARGUMENT;
    }

    cepCell* beings_root = CEP_BOND_TOPOLOGY.beings_root;
    if (!beings_root) {
        return CEP_L1_ERR_STATE;
    }

    cepCell* being = cep_cell_find_by_name(beings_root, name);
    if (!being) {
        cepDT name_copy = *name;
        cepDT being_type = *CEP_DTAW("CEP", "being");
        being = cep_cell_add_dictionary(beings_root, &name_copy, 0, &being_type, CEP_STORAGE_RED_BLACK_T);
        if (!being) {
            return CEP_L1_ERR_MEMORY;
        }
    }

    if (spec) {
        cepDT label_tag = *CEP_DTAW("CEP", "being_label");
        cepDT kind_tag = *CEP_DTAW("CEP", "being_kind");
        cepDT ext_tag = *CEP_DTAW("CEP", "being_ext");

        cepL1Result rc;
        rc = cep_bond_set_text(being, &label_tag, spec->label);
        if (rc != CEP_L1_OK) {
            return rc;
        }
        rc = cep_bond_set_text(being, &kind_tag, spec->kind);
        if (rc != CEP_L1_OK) {
            return rc;
        }
        rc = cep_bond_set_text(being, &ext_tag, spec->external_id);
        if (rc != CEP_L1_OK) {
            return rc;
        }

        if (spec->metadata) {
            cepL1Result meta_rc = cep_bond_apply_metadata(being, spec->metadata);
            if (meta_rc != CEP_L1_OK) {
                return meta_rc;
            }
        }
    }

    handle->cell = being;
    handle->revision = cep_cell_latest_timestamp(being);
    return CEP_L1_OK;
}
