/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L0_H
#define CEP_L0_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool cep_l0_bootstrap(void);
void cep_l0_bootstrap_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L0_H */
