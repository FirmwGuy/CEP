/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_IDENTIFIER_H
#define CEP_IDENTIFIER_H

#include <stdbool.h>
#include <stddef.h>

#include "cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CEP_IDENTIFIER_MAX 256u

bool cep_compose_identifier(const char* const tokens[],
                            size_t token_count,
                            char* out_buffer,
                            size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* CEP_IDENTIFIER_H */
