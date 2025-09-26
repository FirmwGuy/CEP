/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_STREAM_STDIO_H
#define CEP_STREAM_STDIO_H

#include "cep_cell.h"

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void cep_stdio_library_init(cepCell* library, cepDT* name);
void cep_stdio_resource_init(cepCell* resource, cepDT* name, FILE* file, bool close_on_release);
void cep_stdio_stream_init(cepCell* stream, cepDT* name, cepCell* library, cepCell* resource);

#ifdef __cplusplus
}
#endif

#endif /* CEP_STREAM_STDIO_H */
