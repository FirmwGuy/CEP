/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_BOND_OPERATIONS_H
#define CEP_BOND_OPERATIONS_H

#include <stdbool.h>

#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register the impulse-accessible Layer 1 bond enzymes on the supplied
 * registry so beats can drive `cep_being_claim`, `cep_bond_upsert`,
 * `cep_context_upsert`, facet helpers, and `cep_tick_l1` without calling the
 * C API directly.
 */
bool cep_bond_operations_register(cepEnzymeRegistry* registry);

#ifdef __cplusplus
}
#endif

#endif
