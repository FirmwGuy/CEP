/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L3_RUNTIME_H
#define CEP_L3_RUNTIME_H

#include "../l0_kernel/cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Aggregates awareness evidence for rat POCs into `/data/awareness/**`:
   - maze_risk_reward per rat (shocks/foods/steps/etc + signal snapshot)
   - skill_performance per learner/focus (attempts/success/imaginate rate/cost)
   - social_comm per rat (trust/teach/noise)
   Intended for lightweight L3 dashboards; runs once per scheduler pump. */
void cep_l3_awareness_run(cepCell* eco_root, cepCell* data_root);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L3_RUNTIME_H */
