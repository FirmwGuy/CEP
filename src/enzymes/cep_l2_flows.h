/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_FLOWS_H
#define CEP_L2_FLOWS_H

#include <stdbool.h>

#include <stddef.h>
#include <stdbool.h>

#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_identifier.h"
#include "../l0_kernel/cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flow orchestration for CEP Layer 2 mirrors the pattern provided by coherence: a
 * bootstrap helper wires the `/data/flow` subtree and an accompanying registration
 * routine loads the enzyme pack that drives intent ingestion, wakeups, stepping,
 * and cache refresh. Callers should invoke both helpers during startup, after the
 * kernel has been initialised.
 */
bool cep_l2_flows_bootstrap(void);

/**
 * Register the Layer 2 enzyme pack on the supplied registry, binding each
 * descriptor to the `/data/flow` subtree so signal matching observes the intended
 * specificity. The helper is idempotent and safe to call multiple times.
 */
bool cep_l2_flows_register(cepEnzymeRegistry* registry);

typedef struct {
    cepCell* request;
    size_t   next_step_index;
} cepL2DefinitionIntent;

typedef struct {
    cepCell* request;
} cepL2NicheIntent;

typedef struct {
    cepCell* request;
} cepL2InstanceStartIntent;

typedef struct {
    cepCell* request;
} cepL2InstanceEventIntent;

typedef struct {
    cepCell* request;
} cepL2InstanceControlIntent;

bool cep_l2_definition_intent_init(cepL2DefinitionIntent* intent,
                                   const char* txn_word,
                                   const char* kind,
                                   const char* const id_tokens[], size_t id_token_count);
cepCell* cep_l2_definition_intent_request(const cepL2DefinitionIntent* intent);
cepCell* cep_l2_definition_intent_add_step(cepL2DefinitionIntent* intent, const char* step_kind);
cepCell* cep_l2_definition_step_ensure_spec(cepCell* step);
bool cep_l2_definition_intent_set_program(cepL2DefinitionIntent* intent,
                                          const char* const program_tokens[], size_t program_token_count);
bool cep_l2_definition_intent_set_variant(cepL2DefinitionIntent* intent,
                                          const char* const variant_tokens[], size_t variant_token_count);
bool cep_l2_definition_intent_set_text(cepL2DefinitionIntent* intent,
                                       const char* field,
                                       const char* value);

/**
 * Ensure the rendezvous dictionary for a step exists so callers can populate
 * spawn parameters without poking at lower-level helpers.
 */
cepCell* cep_l2_definition_step_ensure_rendezvous(cepCell* step);

/**
 * Store a rendezvous parameter on the step's spec dictionary using the
 * provided textual field name.
 */
bool cep_l2_definition_step_set_rendezvous_text(cepCell* step,
                                                const char* field,
                                                const char* value);

/**
 * Record a profile-specific rendezvous default under
 * `spec/rendezvous/defaults/<profile>` so runtime assembly can merge the
 * fallback values before spawning.
 */
bool cep_l2_definition_step_set_rendezvous_default(cepCell* step,
                                                    const char* profile,
                                                    const char* field,
                                                    const char* value);

bool cep_l2_niche_intent_init(cepL2NicheIntent* intent,
                              const char* txn_word,
                              const char* const id_tokens[], size_t id_token_count,
                              const char* const ctx_tokens[], size_t ctx_token_count,
                              const char* const variant_tokens[], size_t variant_token_count);
cepCell* cep_l2_niche_intent_request(const cepL2NicheIntent* intent);

bool cep_l2_instance_start_intent_init(cepL2InstanceStartIntent* intent,
                                       const char* txn_word,
                                       const char* const id_tokens[], size_t id_token_count,
                                       const char* const variant_tokens[], size_t variant_token_count);
cepCell* cep_l2_instance_start_intent_request(const cepL2InstanceStartIntent* intent);
bool cep_l2_instance_start_intent_set_policy(cepL2InstanceStartIntent* intent,
                                             const char* const policy_tokens[], size_t policy_token_count);
bool cep_l2_instance_start_intent_set_text(cepL2InstanceStartIntent* intent,
                                           const char* field,
                                           const char* value);

bool cep_l2_instance_event_intent_init(cepL2InstanceEventIntent* intent,
                                       const char* txn_word,
                                       const char* signal_path,
                                       const char* const id_tokens[], size_t id_token_count);
cepCell* cep_l2_instance_event_intent_request(const cepL2InstanceEventIntent* intent);
cepCell* cep_l2_instance_event_intent_payload(cepL2InstanceEventIntent* intent);

bool cep_l2_instance_control_intent_init(cepL2InstanceControlIntent* intent,
                                         const char* txn_word,
                                         const char* action,
                                         const char* const id_tokens[], size_t id_token_count);
cepCell* cep_l2_instance_control_intent_request(const cepL2InstanceControlIntent* intent);
bool cep_l2_instance_control_intent_set_step_limit(cepL2InstanceControlIntent* intent, size_t step_limit);
bool cep_l2_instance_control_intent_set_text(cepL2InstanceControlIntent* intent,
                                             const char* field,
                                             const char* value);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_FLOWS_H */
