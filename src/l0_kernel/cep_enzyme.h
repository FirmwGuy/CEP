/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */

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


/**
 * @brief Allocate a fresh enzyme registry.
 */
cepEnzymeRegistry*  cep_enzyme_registry_create(void);

/**
 * @brief Destroy a registry, freeing all owned resources.
 */
void                cep_enzyme_registry_destroy(cepEnzymeRegistry* registry);

/**
 * @brief Drop every registered descriptor and cached agenda state.
 */
void                cep_enzyme_registry_reset(cepEnzymeRegistry* registry);

/**
 * @brief Obtain the number of activation-ready descriptors stored in @p registry.
 */
size_t              cep_enzyme_registry_size(const cepEnzymeRegistry* registry);

/**
 * @brief Promote descriptors staged for activation into the live registry.
 */
void                cep_enzyme_registry_activate_pending(cepEnzymeRegistry* registry);

/**
 * @brief Register an enzyme descriptor under the provided query path.
 *
 * @param registry Registry that receives the descriptor.
 * @param query    Signal path used when matching impulses.
 * @param descriptor Detailed metadata describing the enzyme.
 * @return 0 on success; a negative errno-style value otherwise.
 */
int                 cep_enzyme_register(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor);

/**
 * @brief Remove a descriptor previously registered for a query path.
 */
int                 cep_enzyme_unregister(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor);

/**
 * @brief Produce an ordered execution list for the supplied impulse.
 *
 * @param registry Source registry.
 * @param impulse  Signal/target pair to match against.
 * @param ordered  Output array receiving pointers to descriptors.
 * @param capacity Maximum number of elements that can be written to @p ordered.
 * @return Number of descriptors produced (may exceed @p capacity, in which case the result is truncated).
 */
size_t              cep_enzyme_resolve(const cepEnzymeRegistry* registry, const cepImpulse* impulse, const cepEnzymeDescriptor** ordered, size_t capacity);

/**
 * @brief Append a binding for @p name on @p cell, optionally inheriting to descendants.
 */
int                 cep_cell_bind_enzyme(cepCell* cell, const cepDT* name, bool propagate);

/**
 * @brief Tombstone a previously bound enzyme name on @p cell.
 */
int                 cep_cell_unbind_enzyme(cepCell* cell, const cepDT* name);

/**
 * @brief Retrieve the head of the binding list associated with @p cell.
 */
const cepEnzymeBinding* cep_cell_enzyme_bindings(const cepCell* cell);


#ifdef __cplusplus
}
#endif


#endif
