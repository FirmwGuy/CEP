/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_ENZYME_H
#define CEP_ENZYME_H


#include <stddef.h>

#include "cep_cell.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @typedef cepEnzyme
 * @brief Signature for user-provided enzyme callbacks.
 *
 * Enzymes receive the signal path that triggered execution and the concrete
 * target path addressed by the impulse. Implementations return
 * #CEP_ENZYME_SUCCESS when work was staged successfully or one of the negative
 * values to request a retry or abort.
 */
typedef int (*cepEnzyme)(const cepPath* signal_path, const cepPath* target_path);


/**
 * @brief Canonical return codes for enzyme callbacks.
 */
enum {
    CEP_ENZYME_SUCCESS = 0,
    CEP_ENZYME_RETRY   = -1,
    CEP_ENZYME_FATAL   = -2,
};


typedef uint32_t cepEnzymeFlags;

/**
 * @brief Behaviour modifiers advertised by an enzyme descriptor.
 */
enum {
    CEP_ENZYME_FLAG_NONE         = 0u,
    CEP_ENZYME_FLAG_IDEMPOTENT   = 1u << 0,
    CEP_ENZYME_FLAG_STATEFUL     = 1u << 1,
    CEP_ENZYME_FLAG_EMIT_SIGNALS = 1u << 2,
};


/**
 * @brief Policies that describe how an enzyme matches signal paths.
 */
typedef enum {
    CEP_ENZYME_MATCH_EXACT = 0,   /**< Match only the exact query path. */
    CEP_ENZYME_MATCH_PREFIX,      /**< Match any impulse whose signal begins with the query path. */
} cepEnzymeMatchPolicy;


/**
 * @struct cepEnzymeDescriptor
 * @brief Metadata describing an enzyme registered with the dispatcher.
 */
typedef struct {
    cepDT                   name;           /**< Deterministic identity for reproducibility. */
    const char*             label;          /**< Optional human readable tag for diagnostics. */
    const cepDT*            before;         /**< Names that must execute prior to this enzyme. */
    size_t                  before_count;   /**< Number of entries in @ref before. */
    const cepDT*            after;          /**< Names that must execute after this enzyme. */
    size_t                  after_count;    /**< Number of entries in @ref after. */
    cepEnzyme               callback;       /**< Function pointer that performs the work. */
    cepEnzymeFlags          flags;          /**< Behaviour hints exposed to the runtime. */
    cepEnzymeMatchPolicy    match;          /**< Signal matching mode used during resolve. */
} cepEnzymeDescriptor;


/**
 * @struct cepImpulse
 * @brief Small helper describing the signal and target that triggered work.
 */
typedef struct {
    const cepPath*          signal_path;    /**< Path that identifies the impulse kind. */
    const cepPath*          target_path;    /**< Path that receives the enzyme output. */
} cepImpulse;


typedef struct _cepEnzymeRegistry  cepEnzymeRegistry;


cepEnzymeRegistry*  cep_enzyme_registry_create(void);
void                cep_enzyme_registry_destroy(cepEnzymeRegistry* registry);
void                cep_enzyme_registry_reset(cepEnzymeRegistry* registry);
size_t              cep_enzyme_registry_size(const cepEnzymeRegistry* registry);
void                cep_enzyme_registry_activate_pending(cepEnzymeRegistry* registry);
int                 cep_enzyme_register(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor);
int                 cep_enzyme_unregister(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor);
size_t              cep_enzyme_resolve(const cepEnzymeRegistry* registry, const cepImpulse* impulse, const cepEnzymeDescriptor** ordered, size_t capacity);
int                 cep_cell_bind_enzyme(cepCell* cell, const cepDT* name, bool propagate);
int                 cep_cell_unbind_enzyme(cepCell* cell, const cepDT* name);
const cepEnzymeBinding* cep_cell_enzyme_bindings(const cepCell* cell);


#ifdef __cplusplus
}
#endif


#endif
