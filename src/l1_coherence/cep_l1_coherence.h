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
    const char* being_kind;
    const char* being_external_id;
    const char* bond_id;
} cepL1CohBinding;

bool cep_l1_coh_make_being_key(const char* kind,
                               const char* external_id,
                               char* buffer,
                               size_t buffer_size);

bool cep_l1_coh_make_bond_key(const char* bond_kind,
                              const char* from_being,
                              const char* to_being,
                              char* buffer,
                              size_t buffer_size);

bool cep_l1_coh_make_context_key(const char* ctx_kind,
                                 const cepL1CohBinding* bindings,
                                 size_t binding_count,
                                 char* buffer,
                                 size_t buffer_size);

bool cep_l1_coh_make_facet_key(const char* facet_kind,
                               const char* ctx_id,
                               const char* subject_being,
                               const char* facet_label,
                               char* buffer,
                               size_t buffer_size);

bool cep_l1_coh_make_debt_key(const char* debt_kind,
                              const char* ctx_or_bond_id,
                              const char* requirement,
                              char* buffer,
                              size_t buffer_size);

bool cep_l1_coh_add_being(cepL1SchemaLayout* layout,
                          const char* being_kind,
                          const char* external_id,
                          cepCell** being_out);

bool cep_l1_coh_add_bond(cepL1SchemaLayout* layout,
                         const char* bond_kind,
                         const char* from_being_kind,
                         const char* from_external_id,
                         const char* to_being_kind,
                         const char* to_external_id,
                         cepCell** bond_out);

bool cep_l1_coh_add_context(cepL1SchemaLayout* layout,
                            const char* context_kind,
                            const char* note,
                            const cepL1CohBinding* bindings,
                            size_t binding_count,
                            cepCell** context_out);

bool cep_l1_coh_hydrate_safe(cep_cell_ref_t* ref,
                             const cepEnzymeContext* enz_ctx,
                             bool allow_cross_branch,
                             bool allow_snapshot_only);

bool cep_l1_coh_record_debt(cepL1SchemaLayout* layout,
                            const char* debt_kind,
                            const char* context_id,
                            const char* requirement,
                            const char* note);

bool cep_l1_coh_run_closure(cepL1SchemaLayout* layout, const char* context_id);
bool cep_l1_coh_register_closure_enzyme(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L1_COHERENCE_H */
