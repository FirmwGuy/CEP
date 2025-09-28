/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_CELL_OPERATIONS_H
#define CEP_CELL_OPERATIONS_H

#include <stdbool.h>

#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register the built-in cell manipulation enzymes on the supplied registry so
 * heartbeat impulses can perform add/update/delete/move/clone operations via
 * the cadence instead of direct API calls.
 */
bool cep_cell_operations_register(cepEnzymeRegistry* registry);

#ifdef __cplusplus
}
#endif

#endif
