/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_CRC32C_H
#define CEP_CRC32C_H

#include <stddef.h>
#include <stdint.h>

uint32_t cep_crc32c(const void* data, size_t size, uint32_t seed);

#endif /* CEP_CRC32C_H */
