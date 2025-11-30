/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L4_RUNTIME_H
#define CEP_L4_RUNTIME_H

#include "../l0_kernel/cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Records governance policy/compliance for rat POCs under `/data/gov/**`,
   seeding provinces and tracking risk/imaginate thresholds. No enforcement
   yet—only evidence for dashboards. */
void cep_l4_governance_run(cepCell* eco_root, cepCell* data_root);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L4_RUNTIME_H */
