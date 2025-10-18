/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_ORGAN_H
#define CEP_ORGAN_H

#include "cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* kind;
    const char* label;
    cepDT       store;
    cepDT       validator;
    cepDT       constructor;
    cepDT       destructor;
} cepOrganDescriptor;

typedef struct {
    const cepOrganDescriptor* descriptor;
    cepCell*                  root;
} cepOrganRoot;

bool    cep_organ_runtime_bootstrap(void);
bool    cep_organ_register(const cepOrganDescriptor* descriptor);
const cepOrganDescriptor* cep_organ_descriptor(const cepDT* store_kind);
bool    cep_organ_root_for_cell(const cepCell* cell, cepOrganRoot* out);
bool    cep_organ_request_constructor(const cepCell* root);
bool    cep_organ_request_destructor(const cepCell* root);
bool    cep_organ_request_validation(const cepCell* cell);
cepDT   cep_organ_store_dt(const char* kind);

#ifdef __cplusplus
}
#endif

#endif /* CEP_ORGAN_H */
