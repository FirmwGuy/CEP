/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_PACK_H
#define CEP_L1_PACK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool cep_l1_pack_bootstrap(void);
bool cep_l1_pack_shutdown(void);
bool cep_l1_pack_coh_sweep(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L1_PACK_H */
