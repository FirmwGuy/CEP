/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_FLOWS_H
#define CEP_L2_FLOWS_H

#include <stdbool.h>

#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flow orchestration for CEP Layer 2 mirrors the pattern provided by coherence: a
 * bootstrap helper wires the `/data/flow` subtree and an accompanying registration
 * routine loads the enzyme pack that drives intent ingestion, wakeups, stepping,
 * and cache refresh. Callers should invoke both helpers during startup, after the
 * kernel has been initialised.
 */
bool cep_l2_flows_bootstrap(void);

/**
 * Register the Layer 2 enzyme pack on the supplied registry, binding each
 * descriptor to the `/data/flow` subtree so signal matching observes the intended
 * specificity. The helper is idempotent and safe to call multiple times.
 */
bool cep_l2_flows_register(cepEnzymeRegistry* registry);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_FLOWS_H */
