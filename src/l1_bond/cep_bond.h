/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_BOND_H
#define CEP_BOND_H


#include <stdbool.h>
#include <stddef.h>

#include "cep_enzyme.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief Layer 1 configuration, specs, and entry points.
 */


typedef enum {
    CEP_L1_OK                = 0,
    CEP_L1_ERR_ARGUMENT      = -1,
    CEP_L1_ERR_STATE         = -2,
    CEP_L1_ERR_MEMORY        = -3,
    CEP_L1_ERR_DUPLICATE     = -4,
    CEP_L1_ERR_ROLE_MISSING  = -10,
    CEP_L1_ERR_UNIMPLEMENTED = -127,
} cepL1Result;


typedef enum {
    CEP_FACET_POLICY_DEFAULT = 0,
    CEP_FACET_POLICY_RETRY,
    CEP_FACET_POLICY_ABORT,
} cepFacetPolicy;


typedef struct {
    cepCell*    cell;
    cepOpCount  revision;
} cepBeingHandle;


typedef struct {
    cepCell*    cell;
    cepOpCount  revision;
} cepBondHandle;


typedef struct {
    cepCell*    cell;
    cepOpCount  revision;
} cepContextHandle;


typedef struct {
    const cepDT*        tag;
    const cepDT*        role_a_tag;
    const cepCell*      role_a;
    const cepDT*        role_b_tag;
    const cepCell*      role_b;
    const cepCell*      metadata;
    cepOpCount          causal_op;
} cepBondSpec;


typedef struct {
    const cepDT*            tag;
    size_t                  role_count;
    const cepDT* const*     role_tags;
    const cepCell* const*   role_targets;
    const cepCell*          metadata;
    const cepDT* const*     facet_tags;
    size_t                  facet_count;
    cepOpCount              causal_op;
} cepContextSpec;


typedef struct {
    const cepDT*        facet_tag;
    const cepDT*        source_context_tag;
    cepEnzyme           materialiser;
    cepFacetPolicy      policy;
} cepFacetSpec;


typedef struct {
    cepCell*    root;               /**< Optional override for the global root dictionary. */
    cepCell*    data_root;          /**< Optional override for the durable `/CEP/data` dictionary. */
    cepCell*    bonds_root;         /**< Optional override for the transient `/CEP/bonds` dictionary. */
    cepCell*    l1_root;            /**< Optional override for the `/CEP/data/CEP/L1` dictionary. */
    bool        ensure_directories; /**< Allow creation of missing directories when true. */
} cepConfig;


cepL1Result cep_init_l1(const cepConfig* config, cepEnzymeRegistry* registry);


#ifdef __cplusplus
}
#endif


#endif
