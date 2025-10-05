/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_POC_PACK_H
#define CEP_POC_PACK_H

#include <stdbool.h>
#include <stddef.h>

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Lightweight descriptor shared by the PoC intent builders so callers can keep
 * access to the staged inbox dictionary and its `original subtree` mirror when they
 * need to enrich the payload before handing it to the mailroom.
 */
typedef struct {
    cepCell* request;   /**< Mailroom bucket entry staged under `/data/inbox/poc`. */
    cepCell* original;  /**< Canonical mirror under `original subtree` for audit trails. */
} cepPocIntent;

/**
 * Scenario builder descriptor that tracks the nested collections used to add
 * steps or inline assertions while the request is still mutable in user space.
 */
typedef struct {
    cepCell* request;           /**< Inbox dictionary staged for the scenario intent. */
    cepCell* original;          /**< Original spelling mirror for identifiers. */
    cepCell* steps;             /**< Ordered container that stores `steps[]` entries. */
    cepCell* asserts;           /**< Container of inline assertions authored with the scenario. */
    cepCell* original_steps;    /**< Mirror dictionary for step spellings. */
    cepCell* original_asserts;  /**< Mirror dictionary for assertion spellings. */
} cepPocScenarioIntent;

/**
 * Prepare the `/data/poc` hierarchy, inbox buckets, tmp adjacency roots, and
 * default `/sys/poc/ toggles` toggles so the PoC enzymes can operate deterministically
 * without callers hand-wiring dictionaries before boot completes.
 */
bool cep_poc_bootstrap(void);

/**
 * Register the PoC enzyme pack (I/O ingest, harness ingest, indexers, and
 * adjacency refreshers) on the supplied registry while binding descriptors to
 * the proper roots so routing and beat scheduling follow the contract.
 */
bool cep_poc_register(cepEnzymeRegistry* registry);

/**
 * Create a `poc_echo` intent ready for mailroom routing, mirroring the supplied
 * identifier and payload under `original subtree` so provenance is preserved.
 */
bool cep_poc_echo_intent_init(cepPocIntent* intent,
                              const char* txn_word,
                              const char* id_text,
                              const char* text);

/**
 * Assemble a `poc_calc` intent with the expression recorded both canonically
 * and under `original/expr`, keeping the request ready for additional tokens if
 * the caller decides to augment the prepared dictionary.
 */
bool cep_poc_calc_intent_init(cepPocIntent* intent,
                              const char* txn_word,
                              const char* id_text,
                              const char* expr_text);

/**
 * Prepare a `poc_kv_set` intent with canonical identifier, key, and value while
 * copying the submitted text under `original subtree` for replay auditing.
 */
bool cep_poc_kv_set_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* id_text,
                                const char* key_text,
                                const char* value_text);

/**
 * Prepare a `poc_kv_get` intent that records the requested key and optional id
 * mirrors so the ingest enzyme can produce deterministic read responses.
 */
bool cep_poc_kv_get_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* id_text,
                                const char* key_text);

/**
 * Prepare a `poc_kv_del` intent that instructs the key/value ingest enzyme to
 * mark the latest value as tombstoned while mirroring the submitted key.
 */
bool cep_poc_kv_del_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* id_text,
                                const char* key_text);

/**
 * Initialise a declarative `poc_scenario` intent, returning handles for the
 * nested collections so callers can append steps or inline assertions.
 */
bool cep_poc_scenario_intent_init(cepPocScenarioIntent* intent,
                                  const char* txn_word,
                                  const char* scenario_id);

/**
 * Append a scenario step to the prepared scenario intent, returning the newly
 * created dictionary so callers can decorate its payload directly.
 */
cepCell* cep_poc_scenario_intent_add_step(cepPocScenarioIntent* intent,
                                          const char* step_kind,
                                          const char* step_id);

/**
 * Attach an inline assertion to the scenario intent so replay tooling can run
 * the expectation automatically after the scenario executes.
 */
bool cep_poc_scenario_intent_add_assert(cepPocScenarioIntent* intent,
                                        const char* assert_id,
                                        const char* path,
                                        const char* expect_text);

/**
 * Build a `poc_run` intent pointing at a stored scenario, optionally allowing
 * callers to decorate the request further before it reaches the mailroom.
 */
bool cep_poc_run_intent_init(cepPocIntent* intent,
                             const char* txn_word,
                             const char* run_id,
                             cepCell* scenario_link);

/**
 * Construct a `poc_assert` intent to validate an as-of beat path, staging both
 * the lookup path and expected value for deterministic replay.
 */
bool cep_poc_assert_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* assert_id,
                                const char* path_text,
                                const char* expect_text);

/**
 * Produce a `poc_bandit` intent capturing the lightweight epsilon-greedy
 * configuration so the harness ingest enzyme can delegate exploration to L2 and
 * record deterministic decision telemetry.
 */
bool cep_poc_bandit_intent_init(cepPocIntent* intent,
                                const char* txn_word,
                                const char* run_id,
                                const char* policy_text,
                                const char* const arms[], size_t arm_count,
                                const char* epsilon_text,
                                const char* rng_seed_text,
                                size_t pulls);

#ifdef __cplusplus
}
#endif

#endif /* CEP_POC_PACK_H */
