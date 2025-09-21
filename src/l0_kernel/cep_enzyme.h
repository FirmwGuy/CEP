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


typedef int (*cepEnzyme)(const cepPath* signal_path, const cepPath* target_path);


enum {
    CEP_ENZYME_SUCCESS = 0,
    CEP_ENZYME_RETRY   = -1,
    CEP_ENZYME_FATAL   = -2,
};


typedef uint32_t cepEnzymeFlags;

enum {
    CEP_ENZYME_FLAG_NONE         = 0u,
    CEP_ENZYME_FLAG_IDEMPOTENT   = 1u << 0,
    CEP_ENZYME_FLAG_STATEFUL     = 1u << 1,
    CEP_ENZYME_FLAG_EMIT_SIGNALS = 1u << 2,
};


typedef enum {
    CEP_ENZYME_MATCH_EXACT = 0,
    CEP_ENZYME_MATCH_PREFIX,
} cepEnzymeMatchPolicy;


typedef struct {
    cepDT                   name;           /* Deterministic identity */
    const char*             label;          /* Optional human readable label */
    const cepDT*            before;         /* Names that must run after this enzyme */
    size_t                  before_count;
    const cepDT*            after;          /* Names that must run before this enzyme */
    size_t                  after_count;
    cepEnzyme               callback;
    cepEnzymeFlags          flags;
    cepEnzymeMatchPolicy    match;
} cepEnzymeDescriptor;


typedef struct {
    const cepPath*          signal_path;
    const cepPath*          target_path;
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


#ifdef __cplusplus
}
#endif


#endif
