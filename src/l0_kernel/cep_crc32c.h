/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_CRC32C_H
#define CEP_CRC32C_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CEP_CRC32C_OVERRIDE_AUTO = -1,
    CEP_CRC32C_OVERRIDE_FORCE_IEEE = 0,
    CEP_CRC32C_OVERRIDE_FORCE_CASTAGNOLI = 1,
} cepCrc32cOverride;

uint32_t cep_crc32c(const void* data, size_t size, uint32_t seed);
uint32_t cep_crc32c_compute_explicit(const void* data,
                                     size_t size,
                                     uint32_t seed,
                                     bool castagnoli);
bool cep_crc32c_castagnoli_enabled(void);
cepCrc32cOverride cep_crc32c_set_castagnoli_override(cepCrc32cOverride override_mode);

#endif /* CEP_CRC32C_H */
