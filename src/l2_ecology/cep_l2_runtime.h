/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_RUNTIME_H
#define CEP_L2_RUNTIME_H

#include <stdbool.h>
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Registers organ descriptors owned by the L2 pack (roots, flows, runtime,
 * learn/models) so constructors/validators can be attached deterministically. */
bool cep_l2_runtime_register_organs(void);

/* Ensures runtime subtrees exist (runtime/organisms/metrics/decisions) so the
 * scheduler and flow VM have stable homes. */
bool cep_l2_runtime_seed_runtime(cepCell* eco_root);

/* Scheduler stub that will later scan L1 runtime triggers and app events to
 * start organisms. Today it only exists to preserve the call flow and should
 * be extended once triggers and Flow VM hooks are in place. */
bool cep_l2_runtime_scheduler_pump(cepCell* eco_root);

/* Appends an append-only history entry under `/data/eco/runtime/history`,
 * recording pipeline metadata, ecological identifiers, and an optional note so
 * organism progress can be replayed or audited beat-by-beat. */
bool cep_l2_runtime_record_history(cepCell* eco_root,
                                   const cepPipelineMetadata* pipeline,
                                   const cepDT* species_id,
                                   const cepDT* variant_id,
                                   const char* note);

/* Hydrates cells on behalf of L2 flows with explicit cross-branch policy
 * enforcement and Decision Cell logging so replay covers risky reads. The
 * helper wraps `cep_cell_hydrate_for_enzyme`, forcing cross-branch allowance
 * only after the branch policy guard records evidence, and mirrors pipeline +
 * ecology context into `/data/eco/runtime/decisions`. */
cepHydrateStatus cep_l2_runtime_hydrate_for_enzyme(cepCell* eco_root,
                                                   cep_cell_ref_t* ref,
                                                   const cepEnzymeContext* enz_ctx,
                                                   const cep_hydrate_opts_t* opts,
                                                   const cepPipelineMetadata* pipeline,
                                                   const cepDT* species_id,
                                                   const cepDT* variant_id);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_RUNTIME_H */
