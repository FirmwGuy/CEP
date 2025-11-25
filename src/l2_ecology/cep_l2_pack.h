/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_PACK_H
#define CEP_L2_PACK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bootstraps the optional Layer 2 Ecology pack on top of the active runtime,
 * seeding pack-owned branches, registering organs/enzymes, and publishing an
 * `op/l2_boot` dossier. It is safe to call multiple times; later calls become
 * no-ops when bootstrap already succeeded. */
bool cep_l2_bootstrap(void);

/* Performs a best-effort shutdown of the Layer 2 Ecology pack, closing the
 * `op/l2_shdn` dossier and marking pack readiness as torn down without
 * blocking kernel shutdown. */
bool cep_l2_shutdown(void);

/* Returns true when bootstrap detected L1 helpers (coherence + pipeline pack)
 * so L2 integrations can decide whether to call L1 hooks. */
bool cep_l2_l1_present(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_PACK_H */
