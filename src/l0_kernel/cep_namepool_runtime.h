/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_NAMEPOOL_RUNTIME_H
#define CEP_NAMEPOOL_RUNTIME_H

#ifdef __cplusplus
extern "C" {
#endif

struct cepNamePoolRuntimeState;

struct cepNamePoolRuntimeState* cep_namepool_state_create(void);
void cep_namepool_state_destroy(struct cepNamePoolRuntimeState* state);

#ifdef __cplusplus
}
#endif

#endif /* CEP_NAMEPOOL_RUNTIME_H */
