/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_COHERENCE_H
#define CEP_L1_COHERENCE_H

#include <stdbool.h>
#include <stddef.h>

#include "../l0_kernel/cep_enzyme.h"

#define CEP_L1_IDENTIFIER_MAX 256u

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    cepCell* request;   /**< Inbox dictionary that carries the intent payload. */
    cepCell* attrs;     /**< Attached `attrs` dictionary for caller extensions. */
    cepCell* original;  /**< `original` dictionary capturing pre-canonical tokens. */
    cepDT    id_dt;     /**< Canonical identifier resolved through the namepool. */
    cepDT    kind_dt;   /**< Canonical kind token resolved through the namepool. */
} cepL1BeingIntent;

typedef struct {
    cepCell* request;   /**< Inbox dictionary staged under `bo_upsert`. */
    cepCell* original;  /**< `original` dictionary for audit trails. */
    cepDT    id_dt;     /**< Canonical bond identifier. */
    cepDT    type_dt;   /**< Canonical bond type identifier. */
    bool     directed;  /**< Directed flag staged on the request. */
} cepL1BondIntent;

typedef struct {
    cepCell* request;   /**< Inbox dictionary staged under `ctx_upsert`. */
    cepCell* roles;     /**< Convenience handle for the `roles` dictionary. */
    cepCell* facets;    /**< Convenience handle for the `facets` dictionary. */
    cepCell* original;  /**< `original` dictionary for audit trails. */
    cepDT    id_dt;     /**< Canonical context identifier. */
    cepDT    type_dt;   /**< Canonical context type identifier. */
} cepL1ContextIntent;

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

/* Build a `be_create` intent with canonical identifiers and ready-to-extend
   attribute space. The helper writes both canonical and original spellings. */
bool cep_l1_being_intent_init(cepL1BeingIntent* intent,
                              const char* txn_word,
                              const char* const id_tokens[], size_t id_token_count,
                              const char* const kind_tokens[], size_t kind_token_count);

/* Assemble a `bo_upsert` intent, wiring canonical identifiers and endpoints so
   callers only provide tokens and link targets. The `directed` flag is staged
   as provided and mirrored on the returned intent descriptor. */
bool cep_l1_bond_intent_init(cepL1BondIntent* intent,
                             const char* txn_word,
                             const char* const id_tokens[], size_t id_token_count,
                             const char* const type_tokens[], size_t type_token_count,
                             cepCell* src,
                             cepCell* dst,
                             bool directed);

/* Stage a `ctx_upsert` intent with canonical identifiers and empty role/facet
   containers so callers can extend the payload using the provided builders. */
bool cep_l1_context_intent_init(cepL1ContextIntent* intent,
                                const char* txn_word,
                                const char* const id_tokens[], size_t id_token_count,
                                const char* const type_tokens[], size_t type_token_count);

/* Attach a role link to the prepared context intent while recording the
   user-supplied spelling under `original/roles`. */
bool cep_l1_context_intent_add_role(cepL1ContextIntent* intent,
                                    const char* const role_tokens[], size_t role_token_count,
                                    cepCell* target,
                                    cepCell** out_role_link);

/* Append or update a facet entry, optionally wiring a target link and toggling
   the `required` flag. The helper preserves the submitted spelling under
   `original/facets` and returns the facet dictionary for further decoration. */
bool cep_l1_context_intent_add_facet(cepL1ContextIntent* intent,
                                     const char* const facet_tokens[], size_t facet_token_count,
                                     cepCell* target,
                                     bool required,
                                     cepCell** out_facet_cell);

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

#endif /* CEP_L1_COHERENCE_H */
