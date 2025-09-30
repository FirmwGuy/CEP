/* Copyright (c) 2024–2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_BOND_INTERNAL_H
#define CEP_BOND_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "cep_bond.h"
#include "cep_cell.h"

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

extern cepBondTopologyCache   CEP_BOND_TOPOLOGY;
extern bool                   CEP_BOND_READY;
extern cepEnzymeRegistry*     CEP_BOND_REGISTRY;

typedef struct {
    const cepDT*       facet_tag;
    const cepDT*       context_tag;
    cepEnzyme          materialiser;
    cepFacetPolicy     policy;
} cepFacetRegistryEntry;

typedef struct {
    cepFacetRegistryEntry* entries;
    size_t                 count;
    size_t                 capacity;
} cepFacetRegistry;

extern cepFacetRegistry CEP_FACET_REGISTRY;

cepL1Result cep_bond_require_ready(void);
bool        cep_bond_match_root(cepCell* root);

cepCell*    cep_bond_ensure_dictionary_cell(cepCell* parent, const cepDT* name, const cepDT* type_dt, unsigned storage);
cepL1Result cep_bond_set_text(cepCell* parent, const cepDT* name, const char* text);
cepL1Result cep_bond_apply_metadata(cepCell* target, const cepCell* source);
cepDT       cep_bond_numeric_name(uint64_t key);
uint64_t    cep_bond_compute_pair_key(const cepBondSpec* spec);
uint64_t    cep_context_compute_key(const cepContextSpec* spec);
void        cep_bond_tag_text(const cepDT* tag, char buffer[12]);
void        cep_bond_being_identifier_text(const cepCell* being, char buffer[32]);
cepL1Result cep_bond_annotate_adjacency(const cepCell* being, const cepDT* entry_name, const char* summary);
const cepFacetRegistryEntry* cep_bond_lookup_facet(const cepDT* facet_tag, const cepDT* context_tag);
cepL1Result                 cep_facet_dispatch(cepCell* root, const cepDT* facet_tag, const cepDT* context_name);

#endif
