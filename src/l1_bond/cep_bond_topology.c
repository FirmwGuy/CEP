/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_internal.h"
#include "../enzymes/cep_bond_operations.h"

static cepCell*    cep_bond_prepare_dictionary(cepCell* parent, const cepDT* name, bool ensure, cepL1Result* status);
static cepCell*    cep_bond_prepare_list(cepCell* parent, const cepDT* name, bool ensure, cepL1Result* status);
static bool        cep_bond_register_default_enzymes(cepEnzymeRegistry* registry);

cepBondTopologyCache   CEP_BOND_TOPOLOGY;
bool                   CEP_BOND_READY;
cepEnzymeRegistry*     CEP_BOND_REGISTRY;

cepL1Result cep_bond_require_ready(void) {
    return CEP_BOND_READY ? CEP_L1_OK : CEP_L1_ERR_STATE;
}

bool cep_bond_match_root(cepCell* root) {
    return !root
        || root == CEP_BOND_TOPOLOGY.root
        || root == CEP_BOND_TOPOLOGY.data_root
        || root == CEP_BOND_TOPOLOGY.l1_root;
}

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

    if (CEP_FACET_REGISTRY.entries) {
        cep_free(CEP_FACET_REGISTRY.entries);
    }
    CEP_0(&CEP_FACET_REGISTRY);

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
    if (!registry) {
        return true;
    }
    return cep_bond_operations_register(registry);
}
