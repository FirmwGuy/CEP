/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_COHERENCE_H
#define CEP_L1_COHERENCE_H

#include <stdbool.h>

#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Prepare the `/data/coh` subtree and all supporting ledgers/indexes so the
 * Layer 1 coherence enzymes have a deterministic place to write their facts.
 * Call this once after bootstrapping the kernel; the helper is idempotent and
 * safe to invoke before or after registry wiring.
 */
bool cep_l1_coherence_bootstrap(void);

/**
 * Register the Layer 1 coherence enzyme pack on the given registry and bind it
 * to the `/data/coh` subtree. Descriptors are staged (respecting heartbeat
 * fences) and may be registered multiple times without duplication.
 */
bool cep_l1_coherence_register(cepEnzymeRegistry* registry);

#ifdef __cplusplus
}
#endif

#endif
