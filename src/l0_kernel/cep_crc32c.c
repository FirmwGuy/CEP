/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/* By default this helper computes the standard zlib (IEEE) CRC-32 polynomial.
 * When CEP_CRC32C_MODE=castagnoli is set (and the CPU exposes SSE4.2/ARM CRC32
 * instructions) we switch to the hardware CRC32C backend automatically.
 * Callers that set the env without hardware support transparently fall back
 * to the IEEE path so emitted frames remain compatible. */

#include "cep_crc32c.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#if defined(CEP_ZLIB_SYSTEM)
#include <zlib.h>
#elif defined(CEP_ZLIB_BUNDLED)
#include "zlib.h"
#else
#error "No zlib provider selected for CRC32 computation."
#endif

#if defined(__x86_64__) || defined(__i386__)
#define CEP_CRC32C_HAS_X86 1
#include <cpuid.h>
#include <nmmintrin.h>
#else
#define CEP_CRC32C_HAS_X86 0
#endif

#if defined(__aarch64__) && defined(__linux__)
#define CEP_CRC32C_HAS_ARM 1
#include <sys/auxv.h>
#include <asm/hwcap.h>
#include <arm_acle.h>
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1UL << 7)
#endif
#else
#define CEP_CRC32C_HAS_ARM 0
#endif

static cepCrc32cOverride g_crc32c_override = CEP_CRC32C_OVERRIDE_AUTO;

static bool cep_crc32c_castagnoli_mode(void) {
    static int cached = -1;
    if (g_crc32c_override == CEP_CRC32C_OVERRIDE_FORCE_CASTAGNOLI) {
        return true;
    }
    if (g_crc32c_override == CEP_CRC32C_OVERRIDE_FORCE_IEEE) {
        return false;
    }
    if (cached < 0) {
        const char* mode = getenv("CEP_CRC32C_MODE");
        cached = (mode && strcasecmp(mode, "castagnoli") == 0) ? 1 : 0;
    }
    return cached == 1;
}

cepCrc32cOverride cep_crc32c_set_castagnoli_override(cepCrc32cOverride override_mode) {
    cepCrc32cOverride previous = g_crc32c_override;
    g_crc32c_override = override_mode;
    return previous;
}

static bool cep_crc32c_hw_process(const void* data, size_t size, uint32_t seed, uint32_t* out);

static uint32_t cep_crc32c_compute_impl(const void* data, size_t size, uint32_t seed, bool castagnoli) {
    if (!data || size == 0u) {
        return seed;
    }

    if (castagnoli) {
        uint32_t castagnoli_value = seed;
        if (cep_crc32c_hw_process(data, size, seed, &castagnoli_value)) {
            return castagnoli_value;
        }
    }

    const unsigned char* bytes = (const unsigned char*)data;
    unsigned long crc = crc32_z((unsigned long)seed, bytes, (z_size_t)size);
    return (uint32_t)crc;
}

uint32_t cep_crc32c(const void* data, size_t size, uint32_t seed) {
    return cep_crc32c_compute_impl(data, size, seed, cep_crc32c_castagnoli_mode());
}

uint32_t cep_crc32c_compute_explicit(const void* data,
                                     size_t size,
                                     uint32_t seed,
                                     bool castagnoli) {
    return cep_crc32c_compute_impl(data, size, seed, castagnoli);
}

bool cep_crc32c_castagnoli_enabled(void) {
    return cep_crc32c_castagnoli_mode();
}

#if CEP_CRC32C_HAS_X86
static bool cep_crc32c_hw_available_x86(void) {
    static int state = -1;
    if (state < 0) {
        unsigned int eax = 0u, ebx = 0u, ecx = 0u, edx = 0u;
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & bit_SSE4_2)) {
            state = 1;
        } else {
            state = 0;
        }
    }
    return state == 1;
}

#if defined(__SSE4_2__)
static uint32_t cep_crc32c_hw_crc_x86(const uint8_t* cursor, size_t size, uint32_t seed) {
#else
__attribute__((target("sse4.2")))
static uint32_t cep_crc32c_hw_crc_x86(const uint8_t* cursor, size_t size, uint32_t seed) {
#endif
#if defined(__x86_64__)
    while (size >= sizeof(uint64_t)) {
        uint64_t chunk;
        memcpy(&chunk, cursor, sizeof chunk);
        seed = (uint32_t)_mm_crc32_u64(seed, chunk);
        cursor += sizeof chunk;
        size -= sizeof chunk;
    }
#endif
    while (size >= sizeof(uint32_t)) {
        uint32_t chunk;
        memcpy(&chunk, cursor, sizeof chunk);
        seed = _mm_crc32_u32(seed, chunk);
        cursor += sizeof chunk;
        size -= sizeof chunk;
    }
    while (size > 0u) {
        seed = _mm_crc32_u8(seed, *cursor++);
        --size;
    }
    return seed;
}

static bool cep_crc32c_hw_process_x86(const void* data, size_t size, uint32_t seed, uint32_t* out) {
    if (!cep_crc32c_hw_available_x86())
        return false;
    const uint8_t* cursor = (const uint8_t*)data;
    *out = cep_crc32c_hw_crc_x86(cursor, size, seed);
    return true;
}
#endif /* CEP_CRC32C_HAS_X86 */

#if CEP_CRC32C_HAS_ARM
static bool cep_crc32c_hw_available_arm(void) {
    static int state = -1;
    if (state < 0) {
#if defined(AT_HWCAP)
        unsigned long caps = getauxval(AT_HWCAP);
        state = (caps & HWCAP_CRC32) ? 1 : 0;
#else
        state = 0;
#endif
    }
    return state == 1;
}

static bool cep_crc32c_hw_process_arm(const void* data, size_t size, uint32_t seed, uint32_t* out) {
    if (!cep_crc32c_hw_available_arm())
        return false;

    const uint8_t* cursor = (const uint8_t*)data;
    while (size >= sizeof(uint64_t)) {
        uint64_t chunk;
        memcpy(&chunk, cursor, sizeof chunk);
        seed = __crc32cd(seed, chunk);
        cursor += sizeof chunk;
        size -= sizeof chunk;
    }
    while (size >= sizeof(uint32_t)) {
        uint32_t chunk;
        memcpy(&chunk, cursor, sizeof chunk);
        seed = __crc32cw(seed, chunk);
        cursor += sizeof chunk;
        size -= sizeof chunk;
    }
    while (size > 0u) {
        seed = __crc32cb(seed, *cursor++);
        --size;
    }
    *out = seed;
    return true;
}
#endif /* CEP_CRC32C_HAS_ARM */

static bool cep_crc32c_hw_process(const void* data, size_t size, uint32_t seed, uint32_t* out) {
#if CEP_CRC32C_HAS_X86
    if (cep_crc32c_hw_process_x86(data, size, seed, out)) {
        return true;
    }
#endif
#if CEP_CRC32C_HAS_ARM
    if (cep_crc32c_hw_process_arm(data, size, seed, out)) {
        return true;
    }
#endif
    (void)data;
    (void)size;
    (void)seed;
    (void)out;
    return false;
}
