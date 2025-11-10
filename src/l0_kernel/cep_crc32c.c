/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/* NOTE: despite the helper name, this currently computes the standard zlib
 * (IEEE) CRC-32 polynomial. When we add a true CRC32C (Castagnoli) backend,
 * update this notice and the serializer docs accordingly. */

#include "cep_crc32c.h"

#if defined(CEP_ZLIB_SYSTEM)
#include <zlib.h>
#elif defined(CEP_ZLIB_BUNDLED)
#include "zlib.h"
#else
#error "No zlib provider selected for CRC32 computation."
#endif

uint32_t cep_crc32c(const void* data, size_t size, uint32_t seed) {
    if (!data || size == 0u) {
        return seed;
    }

    const unsigned char* bytes = (const unsigned char*)data;
    unsigned long crc = crc32_z((unsigned long)seed, bytes, (z_size_t)size);
    return (uint32_t)crc;
}
