/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_COHERENCE_H
#define CEP_L1_COHERENCE_H

#include <stdbool.h>
#include <stddef.h>

#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Prepare the `/data/coh` subtree and all supporting ledgers/indexes so the
 * Layer 1 coherence enzymes have a deterministic place to write their facts.
 * Call this once after bootstrapping the kernel; the helper is idempotent and
 * safe to invoke before or after registry wiring.
 */
bool cep_l1_coherence_bootstrap(void);

/**
 * Register the Layer 1 coherence enzyme pack on the given registry and bind it
 * to the `/data/coh` subtree. Descriptors are staged (respecting heartbeat
 * fences) and may be registered multiple times without duplication.
 */
bool cep_l1_coherence_register(cepEnzymeRegistry* registry);

/**
 * Canonicalize user-provided identifier tokens by lowercasing and joining them
 * with ':' so collaborating callers converge on the same ledger keys. The
 * helper rejects empty tokens, embedded separators, or unsupported characters
 * and writes the canonical text into the provided buffer.
 */
bool cep_l1_compose_identifier(const char* const tokens[],
                               size_t token_count,
                               char* out_buffer,
                               size_t out_cap);

/**
 * Convert canonical tokens into a `cepDT` that can be used as an identifier in
 * intents or ledgers. Short results return a packed word ID, while longer ones
 * are interned through the namepool so the final `cepID` stays consistent.
 */
bool cep_l1_tokens_to_dt(const char* const tokens[], size_t token_count, cepDT* out_dt);

/* Convenience wrappers for call sites that already have string literals or
   temporaries; the compound literal keeps everything in a single expression. */
#define CEP_L1_TOKENS_TO_DT(out_dt, ...)                                         \
    cep_l1_tokens_to_dt((const char*[]){ __VA_ARGS__ },                          \
                        sizeof((const char*[]){ __VA_ARGS__ }) / sizeof(const char*), \
                        (out_dt))

#define CEP_L1_COMPOSE(buffer, cap, ...)                                        \
    cep_l1_compose_identifier((const char*[]){ __VA_ARGS__ },                   \
                              sizeof((const char*[]){ __VA_ARGS__ }) / sizeof(const char*), \
                              (buffer),                                         \
                              (cap))

#ifdef __cplusplus
}
#endif

#endif
#define CEP_L1_IDENTIFIER_MAX 256u
