/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_internal.h"

#include <assert.h>
#include <string.h>

cepCell* cep_bond_ensure_dictionary_cell(cepCell* parent, const cepDT* name, const cepDT* type_dt, unsigned storage) {
    if (!parent || !name || !type_dt) {
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child) {
        cepDT name_copy = *name;
        cepDT type_copy = *type_dt;
        child = cep_cell_add_dictionary(parent, &name_copy, 0, &type_copy, storage);
    }

    if (!child || !cep_cell_is_normal(child) || !child->store) {
        return NULL;
    }

    if (!cep_cell_is_dictionary(child) || child->store->storage != storage) {
        return NULL;
    }

    return child;
}

cepL1Result cep_bond_set_text(cepCell* parent, const cepDT* name, const char* text) {
    if (!parent || !name) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!text || !*text) {
        return CEP_L1_OK;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing && cep_cell_is_normal(existing) && cep_cell_has_data(existing)) {
        cep_cell_remove_hard(existing, NULL);
    }

    size_t len = strlen(text) + 1u;
    cepDT name_copy = *name;
    cepDT text_type = *CEP_DTAW("CEP", "text");
    const size_t inline_cap = sizeof(void*) * 2u;

    if (len <= inline_cap) {
        if (!cep_cell_add_value(parent, &name_copy, 0, &text_type, CEP_P(text), len, len)) {
            return CEP_L1_ERR_MEMORY;
        }
    } else {
        char* copy = cep_malloc(len);
        if (!copy) {
            return CEP_L1_ERR_MEMORY;
        }
        memcpy(copy, text, len);
        if (!cep_cell_add_data(parent, &name_copy, 0, &text_type, copy, len, len, cep_free)) {
            cep_free(copy);
            return CEP_L1_ERR_MEMORY;
        }
    }

    return CEP_L1_OK;
}

cepL1Result cep_bond_apply_metadata(cepCell* target, const cepCell* source) {
    if (!target || !source) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!cep_cell_is_normal(source) || !cep_cell_children(source)) {
        return CEP_L1_OK;
    }

    cepDT meta_tag = *CEP_DTAW("CEP", "meta");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* bucket = cep_bond_ensure_dictionary_cell(target, &meta_tag, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        return CEP_L1_ERR_MEMORY;
    }

    if (bucket->store) {
        bool writable = bucket->store->writable;
        bucket->store->writable = true;
        cep_store_delete_children_hard(bucket->store);
        bucket->store->writable = writable;
    }

    size_t count = cep_cell_children(source);
    for (size_t i = 0; i < count; ++i) {
        const cepCell* child = cep_cell_find_by_position(source, i);
        if (!child) {
            continue;
        }

        cepCell* clone = cep_cell_clone_deep(child);
        if (!clone) {
            return CEP_L1_ERR_MEMORY;
        }

        cepCell* inserted = cep_cell_add(bucket, 0, clone);
        if (!inserted) {
            cep_free(clone);
            return CEP_L1_ERR_MEMORY;
        }

        cep_free(clone);
    }

    return CEP_L1_OK;
}

cepDT cep_bond_numeric_name(uint64_t key) {
    cepDT dt = {0};
    dt.domain = CEP_ACRO("CEP");
    dt.tag = cep_id_to_numeric((cepID)(key & CEP_NAME_MAXVAL));
    return dt;
}

uint64_t cep_bond_compute_pair_key(const cepBondSpec* spec) {
    assert(spec);

    const cepDT* role_a_name = cep_cell_get_name(spec->role_a);
    const cepDT* role_b_name = cep_cell_get_name(spec->role_b);
    if (!role_a_name || !role_b_name) {
        return 0u;
    }

    const cepDT digest[] = {
        *spec->tag,
        *spec->role_a_tag,
        *role_a_name,
        *spec->role_b_tag,
        *role_b_name,
    };

    return cep_hash_bytes(digest, sizeof digest);
}

uint64_t cep_context_compute_key(const cepContextSpec* spec) {
    assert(spec);

    size_t digest_len = 1u + (spec->role_count * 2u);
    cepDT* digest = cep_malloc(digest_len * sizeof *digest);
    if (!digest) {
        return 0u;
    }

    size_t index = 0u;
    digest[index++] = *spec->tag;

    for (size_t i = 0; i < spec->role_count; ++i) {
        const cepDT* role_tag = spec->role_tags[i];
        const cepDT* role_name = cep_cell_get_name(spec->role_targets[i]);
        if (!role_tag || !role_name) {
            cep_free(digest);
            return 0u;
        }
        digest[index++] = *role_tag;
        digest[index++] = *role_name;
    }

    uint64_t hash = cep_hash_bytes(digest, digest_len * sizeof *digest);
    cep_free(digest);
    return hash;
}

void cep_bond_tag_text(const cepDT* tag, char buffer[12]) {
    if (!buffer) {
        return;
    }

    buffer[0] = '\0';
    if (!tag) {
        return;
    }

    size_t len = cep_word_to_text(tag->tag, buffer);
    if (len >= 12u) {
        len = 11u;
    }
    buffer[len] = '\0';
}

static void cep_bond_being_name(const cepCell* being, char buffer[12]) {
    if (!buffer) {
        return;
    }

    buffer[0] = '\0';
    if (!being) {
        return;
    }

    const cepDT* name = cep_cell_get_name(being);
    if (!name) {
        return;
    }

    cep_bond_tag_text(name, buffer);
}

void cep_bond_being_identifier_text(const cepCell* being, char buffer[32]) {
    if (!buffer) {
        return;
    }

    buffer[0] = '\0';
    if (!being) {
        return;
    }

    cepCell* external_cell = cep_cell_find_by_name(being, CEP_DTAW("CEP", "being_ext"));
    if (external_cell && cep_cell_has_data(external_cell)) {
        const char* text = (const char*)cep_cell_data(external_cell);
        if (text) {
            strncpy(buffer, text, 31u);
            buffer[31u] = '\0';
            return;
        }
    }

    cepCell* label_cell = cep_cell_find_by_name(being, CEP_DTAW("CEP", "being_label"));
    if (label_cell && cep_cell_has_data(label_cell)) {
        const char* text = (const char*)cep_cell_data(label_cell);
        if (text) {
            strncpy(buffer, text, 31u);
            buffer[31u] = '\0';
            return;
        }
    }

    char fallback[12] = {0};
    cep_bond_being_name(being, fallback);
    strncpy(buffer, fallback, 31u);
    buffer[31u] = '\0';
}

cepL1Result cep_bond_annotate_adjacency(const cepCell* being, const cepDT* entry_name, const char* summary) {
    if (!being || !entry_name) {
        return CEP_L1_ERR_ARGUMENT;
    }

    cepCell* adjacency_root = CEP_BOND_TOPOLOGY.adjacency_root;
    if (!adjacency_root) {
        return CEP_L1_ERR_STATE;
    }

    const cepDT* being_dt = cep_cell_get_name(being);
    if (!being_dt) {
        return CEP_L1_ERR_ARGUMENT;
    }

    cepDT bucket_name = *being_dt;
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* bucket = cep_bond_ensure_dictionary_cell(adjacency_root, &bucket_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        return CEP_L1_ERR_MEMORY;
    }

    cepCell* entry = cep_bond_ensure_dictionary_cell(bucket, entry_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        return CEP_L1_ERR_MEMORY;
    }

    if (summary && *summary) {
        cepDT value_tag = *CEP_DTAW("CEP", "value");
        cepL1Result rc = cep_bond_set_text(entry, &value_tag, summary);
        if (rc != CEP_L1_OK) {
            return rc;
        }
    }

    return CEP_L1_OK;
}
