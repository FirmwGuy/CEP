/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_bond.h"

#include "cep_cell.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>


typedef struct {
    cepCell*    root;
    cepCell*    data_root;
    cepCell*    namespace_root;
    cepCell*    l1_root;
    cepCell*    beings_root;
    cepCell*    bonds_root;
    cepCell*    contexts_root;
    cepCell*    facets_root;
    cepCell*    bonds_runtime_root;
    cepCell*    adjacency_root;
    cepCell*    facet_queue_root;
    cepCell*    checkpoints_root;
} cepBondTopologyCache;


static cepBondTopologyCache    CEP_BOND_TOPOLOGY;
static bool                    CEP_BOND_READY;
static cepEnzymeRegistry*      CEP_BOND_REGISTRY;


static cepCell* cep_bond_prepare_dictionary(cepCell* parent, const cepDT* name, bool ensure, cepL1Result* status);
static cepCell* cep_bond_prepare_list(cepCell* parent, const cepDT* name, bool ensure, cepL1Result* status);
static bool     cep_bond_register_default_enzymes(cepEnzymeRegistry* registry);
static cepL1Result cep_bond_require_ready(void);
static bool     cep_bond_match_root(cepCell* root);
static cepCell* cep_bond_ensure_dictionary_cell(cepCell* parent, const cepDT* name, const cepDT* type_dt, unsigned storage);
static cepL1Result cep_bond_set_text(cepCell* parent, const cepDT* name, const char* text);
static cepL1Result cep_bond_clone_children(cepCell* target, const cepCell* source);
static void     cep_bond_tag_text(const cepDT* tag, char buffer[12]);
static void     cep_bond_being_name(const cepCell* being, char buffer[12]);
static cepL1Result cep_bond_annotate_adjacency(const cepCell* being, const cepDT* entry_name, const char* summary);
static void     cep_bond_being_identifier_text(const cepCell* being, char buffer[32]);


/** Prime Layer 1 by wiring the expected directory layout under `/data` and
    `/bonds`, creating any missing nodes when allowed so later helpers can
    assume the topology exists. Callers may override the main anchors through
    the configuration structure; passing `NULL` falls back to the kernel roots.
    The function also records the registry pointer for default enzyme
    registration and future lookups. */
cepL1Result cep_init_l1(const cepConfig* config, cepEnzymeRegistry* registry) {
    const bool ensure = config ? config->ensure_directories : true;

    cep_cell_system_ensure();

    cepCell* root = config && config->root ? config->root : cep_root();
    if (!root || cep_cell_is_void(root) || !cep_cell_is_normal(root)) {
        return CEP_L1_ERR_STATE;
    }

    cepL1Result status = CEP_L1_OK;

    cepCell* data_root = config && config->data_root
        ? config->data_root
        : cep_bond_prepare_dictionary(root, CEP_DTAW("CEP", "data"), ensure, &status);
    if (!data_root) {
        return status;
    }

    cepCell* namespace_root = cep_bond_prepare_dictionary(data_root, CEP_DTAA("CEP", "CEP"), ensure, &status);
    if (!namespace_root) {
        return status;
    }

    cepCell* l1_root = config && config->l1_root
        ? config->l1_root
        : cep_bond_prepare_dictionary(namespace_root, CEP_DTAA("CEP", "L1"), ensure, &status);
    if (!l1_root) {
        return status;
    }

    cepCell* beings_root = cep_bond_prepare_dictionary(l1_root, CEP_DTAW("CEP", "beings"), ensure, &status);
    if (!beings_root) {
        return status;
    }

    cepCell* bonds_root = cep_bond_prepare_dictionary(l1_root, CEP_DTAW("CEP", "bonds"), ensure, &status);
    if (!bonds_root) {
        return status;
    }

    cepCell* contexts_root = cep_bond_prepare_dictionary(l1_root, CEP_DTAW("CEP", "contexts"), ensure, &status);
    if (!contexts_root) {
        return status;
    }

    cepCell* facets_root = cep_bond_prepare_dictionary(l1_root, CEP_DTAW("CEP", "facets"), ensure, &status);
    if (!facets_root) {
        return status;
    }

    cepCell* bonds_runtime_root = config && config->bonds_root
        ? config->bonds_root
        : cep_bond_prepare_dictionary(root, CEP_DTAW("CEP", "bonds"), ensure, &status);
    if (!bonds_runtime_root) {
        return status;
    }

    cepCell* adjacency_root = cep_bond_prepare_dictionary(bonds_runtime_root, CEP_DTAW("CEP", "adjacency"), ensure, &status);
    if (!adjacency_root) {
        return status;
    }

    cepCell* facet_queue_root = cep_bond_prepare_list(bonds_runtime_root, CEP_DTAW("CEP", "facet_queue"), ensure, &status);
    if (!facet_queue_root) {
        return status;
    }

    cepCell* checkpoints_root = cep_bond_prepare_dictionary(bonds_runtime_root, CEP_DTAW("CEP", "checkpoints"), ensure, &status);
    if (!checkpoints_root) {
        return status;
    }

    if (!cep_bond_register_default_enzymes(registry)) {
        return CEP_L1_ERR_STATE;
    }

    CEP_0(&CEP_BOND_TOPOLOGY);
    CEP_BOND_TOPOLOGY.root = root;
    CEP_BOND_TOPOLOGY.data_root = data_root;
    CEP_BOND_TOPOLOGY.namespace_root = namespace_root;
    CEP_BOND_TOPOLOGY.l1_root = l1_root;
    CEP_BOND_TOPOLOGY.beings_root = beings_root;
    CEP_BOND_TOPOLOGY.bonds_root = bonds_root;
    CEP_BOND_TOPOLOGY.contexts_root = contexts_root;
    CEP_BOND_TOPOLOGY.facets_root = facets_root;
    CEP_BOND_TOPOLOGY.bonds_runtime_root = bonds_runtime_root;
    CEP_BOND_TOPOLOGY.adjacency_root = adjacency_root;
    CEP_BOND_TOPOLOGY.facet_queue_root = facet_queue_root;
    CEP_BOND_TOPOLOGY.checkpoints_root = checkpoints_root;

    CEP_BOND_REGISTRY = registry;
    CEP_BOND_READY = true;
    return CEP_L1_OK;
}


static cepCell* cep_bond_prepare_dictionary(cepCell* parent, const cepDT* name, bool ensure, cepL1Result* status) {
    if (!parent || !name) {
        if (status) {
            *status = CEP_L1_ERR_ARGUMENT;
        }
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child && ensure) {
        child = cep_cell_add_dictionary(parent, (cepDT*)name, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
        if (!child && status) {
            *status = CEP_L1_ERR_MEMORY;
        }
    }

    if (!child) {
        if (status && *status == CEP_L1_OK) {
            *status = CEP_L1_ERR_STATE;
        }
        return NULL;
    }

    if (!cep_cell_is_normal(child) || !child->store || !cep_cell_is_dictionary(child)) {
        if (status && *status == CEP_L1_OK) {
            *status = CEP_L1_ERR_STATE;
        }
        return NULL;
    }

    return child;
}


static cepCell* cep_bond_prepare_list(cepCell* parent, const cepDT* name, bool ensure, cepL1Result* status) {
    if (!parent || !name) {
        if (status) {
            *status = CEP_L1_ERR_ARGUMENT;
        }
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child && ensure) {
        child = cep_cell_add_list(parent, (cepDT*)name, 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_LINKED_LIST);
        if (!child && status) {
            *status = CEP_L1_ERR_MEMORY;
        }
    }

    if (!child) {
        if (status && *status == CEP_L1_OK) {
            *status = CEP_L1_ERR_STATE;
        }
        return NULL;
    }

    if (!cep_cell_is_normal(child) || !child->store || child->store->storage != CEP_STORAGE_LINKED_LIST) {
        if (status && *status == CEP_L1_OK) {
            *status = CEP_L1_ERR_STATE;
        }
        return NULL;
    }

    return child;
}


static bool cep_bond_register_default_enzymes(cepEnzymeRegistry* registry) {
    (void)registry;
    return true;
}


static cepL1Result cep_bond_require_ready(void) {
    return CEP_BOND_READY ? CEP_L1_OK : CEP_L1_ERR_STATE;
}


static bool cep_bond_match_root(cepCell* root) {
    return !root
        || root == CEP_BOND_TOPOLOGY.root
        || root == CEP_BOND_TOPOLOGY.data_root
        || root == CEP_BOND_TOPOLOGY.l1_root;
}


static cepCell* cep_bond_ensure_dictionary_cell(cepCell* parent, const cepDT* name, const cepDT* type_dt, unsigned storage) {
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


static cepL1Result cep_bond_set_text(cepCell* parent, const cepDT* name, const char* text) {
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


static cepL1Result cep_bond_clone_children(cepCell* target, const cepCell* source) {
    if (!target || !source) {
        return CEP_L1_ERR_ARGUMENT;
    }

    if (!cep_cell_is_normal(source) || !cep_cell_children(source)) {
        return CEP_L1_OK;
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

        cepCell* inserted = cep_cell_add(target, 0, clone);
        if (!inserted) {
            cep_free(clone);
            return CEP_L1_ERR_MEMORY;
        }

        cep_free(clone);
    }

    return CEP_L1_OK;
}


static void cep_bond_tag_text(const cepDT* tag, char buffer[12]) {
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


static void cep_bond_being_identifier_text(const cepCell* being, char buffer[32]) {
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


static cepL1Result cep_bond_annotate_adjacency(const cepCell* being, const cepDT* entry_name, const char* summary) {
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

    return cep_bond_set_text(bucket, entry_name, summary);
}


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
    bool created = false;
    if (!being) {
        cepDT name_copy = *name;
        cepDT being_type = *CEP_DTAW("CEP", "being");
        being = cep_cell_add_dictionary(beings_root, &name_copy, 0, &being_type, CEP_STORAGE_RED_BLACK_T);
        if (!being) {
            return CEP_L1_ERR_MEMORY;
        }
        created = true;

        if (spec && spec->metadata) {
            cepL1Result meta_rc = cep_bond_clone_children(being, spec->metadata);
            if (meta_rc != CEP_L1_OK) {
                return meta_rc;
            }
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

        if (!created && spec->metadata) {
            /* Preserve existing structure; metadata cloning only happens on new records. */
        }
    }

    handle->cell = being;
    handle->revision = cep_cell_latest_timestamp(being);
    return CEP_L1_OK;
}


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

    cepCell* bond = cep_cell_find_by_name(bonds_root, spec->tag);
    if (!bond) {
        cepDT bond_name = *spec->tag;
        cepDT bond_type = *spec->tag;
        bond = cep_cell_add_dictionary(bonds_root, &bond_name, 0, &bond_type, CEP_STORAGE_LINKED_LIST);
        if (!bond) {
            return CEP_L1_ERR_MEMORY;
        }

        if (spec->metadata) {
            cepL1Result meta_rc = cep_bond_clone_children(bond, spec->metadata);
            if (meta_rc != CEP_L1_OK) {
                return meta_rc;
            }
        }
    }

    cepDT role_a_tag = *spec->role_a_tag;
    cepDT role_b_tag = *spec->role_b_tag;
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");

    cepCell* role_a_entry = cep_bond_ensure_dictionary_cell(bond, &role_a_tag, &dict_type, CEP_STORAGE_LINKED_LIST);
    cepCell* role_b_entry = cep_bond_ensure_dictionary_cell(bond, &role_b_tag, &dict_type, CEP_STORAGE_LINKED_LIST);
    if (!role_a_entry || !role_b_entry) {
        return CEP_L1_ERR_MEMORY;
    }

    char partner_text[12] = {0};
    cep_bond_being_name(spec->role_b, partner_text);
    cepL1Result rc = cep_bond_set_text(role_a_entry, CEP_DTAW("CEP", "value"), partner_text);
    if (rc != CEP_L1_OK) {
        return rc;
    }

    cep_bond_being_name(spec->role_a, partner_text);
    rc = cep_bond_set_text(role_b_entry, CEP_DTAW("CEP", "value"), partner_text);
    if (rc != CEP_L1_OK) {
        return rc;
    }

    cepDT bond_label_tag = *CEP_DTAW("CEP", "bond_label");
    cepDT bond_note_tag = *CEP_DTAW("CEP", "bond_note");
    rc = cep_bond_set_text(bond, &bond_label_tag, spec->label);
    if (rc != CEP_L1_OK) {
        return rc;
    }
    rc = cep_bond_set_text(bond, &bond_note_tag, spec->note);
    if (rc != CEP_L1_OK) {
        return rc;
    }

    char tag_text[12] = {0};
    char summary[96] = {0};
    cep_bond_tag_text(spec->tag, tag_text);

    char partner_identifier[32] = {0};
    cep_bond_being_identifier_text(spec->role_b, partner_identifier);
    snprintf(summary, sizeof summary, "%s:%s", tag_text, partner_identifier);
    rc = cep_bond_annotate_adjacency(spec->role_a, spec->tag, summary);
    if (rc != CEP_L1_OK) {
        return rc;
    }

    cep_bond_being_identifier_text(spec->role_a, partner_identifier);
    snprintf(summary, sizeof summary, "%s:%s", tag_text, partner_identifier);
    rc = cep_bond_annotate_adjacency(spec->role_b, spec->tag, summary);
    if (rc != CEP_L1_OK) {
        return rc;
    }

    if (handle) {
        handle->cell = bond;
        handle->revision = cep_cell_latest_timestamp(bond);
    }

    return CEP_L1_OK;
}


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

    cepCell* context = cep_cell_find_by_name(contexts_root, spec->tag);
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    if (!context) {
        cepDT name_copy = *spec->tag;
        cepDT type_copy = *spec->tag;
        context = cep_cell_add_dictionary(contexts_root, &name_copy, 0, &type_copy, CEP_STORAGE_LINKED_LIST);
        if (!context) {
            return CEP_L1_ERR_MEMORY;
        }
    }

    if (!context->store) {
        return CEP_L1_ERR_STATE;
    }

    cep_store_delete_children_hard(context->store);

    if (spec->metadata) {
        cepL1Result meta_rc = cep_bond_clone_children(context, spec->metadata);
        if (meta_rc != CEP_L1_OK) {
            return meta_rc;
        }
    }

    cepDT value_tag = *CEP_DTAW("CEP", "value");
    for (size_t i = 0; i < spec->role_count; ++i) {
        cepDT role_tag = *spec->role_tags[i];
        cepCell* role_entry = cep_bond_ensure_dictionary_cell(context, &role_tag, &dict_type, CEP_STORAGE_LINKED_LIST);
        if (!role_entry) {
            return CEP_L1_ERR_MEMORY;
        }
        char being_name[12] = {0};
        cep_bond_being_name(spec->role_targets[i], being_name);
        cepL1Result rc = cep_bond_set_text(role_entry, &value_tag, being_name);
        if (rc != CEP_L1_OK) {
            return rc;
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

    /* Update adjacency mirrors. */
    char summary[64] = {0};
    for (size_t i = 0; i < spec->role_count; ++i) {
        snprintf(summary, sizeof summary, "%s:%s", ctx_tag_text, ctx_label);
        rc = cep_bond_annotate_adjacency(spec->role_targets[i], spec->tag, summary);
        if (rc != CEP_L1_OK) {
            return rc;
        }
    }

    /* Ensure facets exist and mark them pending. */
    const char* pending = "pending";
    cepDT facet_state_tag = *CEP_DTAW("CEP", "facet_state");
    cepDT queue_state_tag = *CEP_DTAW("CEP", "queue_state");
    for (size_t i = 0; i < spec->facet_count; ++i) {
        const cepDT* facet_tag = spec->facet_tags[i];
        if (!facet_tag) {
            continue;
        }

        cepDT facet_name = *facet_tag;
        cepCell* facet_record = cep_bond_ensure_dictionary_cell(facets_root, &facet_name, &facet_name, CEP_STORAGE_LINKED_LIST);
        if (!facet_record) {
            return CEP_L1_ERR_MEMORY;
        }
        rc = cep_bond_set_text(facet_record, &facet_state_tag, pending);
        if (rc != CEP_L1_OK) {
            return rc;
        }

        cepCell* queue_entry = cep_bond_ensure_dictionary_cell(facet_queue_root, &facet_name, &dict_type, CEP_STORAGE_LINKED_LIST);
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
