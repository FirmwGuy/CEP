/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_COHERENCE_H
#define CEP_L1_COHERENCE_H

#include "cep_l1_schema.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* role;
    const char* being_id;
    const char* bond_id;
} cepL1CohBinding;

bool cep_l1_coh_add_being(cepL1SchemaLayout* layout,
                          const char* being_id,
                          cepCell** being_out);

bool cep_l1_coh_add_bond(cepL1SchemaLayout* layout,
                         const char* bond_id,
                         const char* role,
                         const char* from_being,
                         const char* to_being,
                         cepCell** bond_out);

bool cep_l1_coh_add_context(cepL1SchemaLayout* layout,
                            const char* context_id,
                            const char* note,
                            const cepL1CohBinding* bindings,
                            size_t binding_count,
                            cepCell** context_out);

bool cep_l1_coh_record_debt(cepL1SchemaLayout* layout,
                            const char* context_id,
                            const char* note);

bool cep_l1_coh_run_closure(cepL1SchemaLayout* layout, const char* context_id);
bool cep_l1_coh_register_closure_enzyme(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L1_COHERENCE_H */
