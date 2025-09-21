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


#include "cep_enzyme.h"




struct cepEnzymeRegistry {
    size_t entry_count;
};




cepEnzymeRegistry* cep_enzyme_registry_create(void) {
    return cep_new(cepEnzymeRegistry);
}


void cep_enzyme_registry_destroy(cepEnzymeRegistry* registry) {
    if (!registry) {
        return;
    }

    CEP_FREE(registry);
}


void cep_enzyme_registry_reset(cepEnzymeRegistry* registry) {
    if (!registry) {
        return;
    }

    registry->entry_count = 0;
}


size_t cep_enzyme_registry_size(const cepEnzymeRegistry* registry) {
    return registry ? registry->entry_count : 0u;
}


int cep_enzyme_register(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor) {
    if (!registry || !query || !descriptor || !descriptor->callback) {
        return CEP_ENZYME_FATAL;
    }

    registry->entry_count++;
    return CEP_ENZYME_SUCCESS;
}


int cep_enzyme_unregister(cepEnzymeRegistry* registry, const cepPath* query, const cepEnzymeDescriptor* descriptor) {
    if (!registry || !query || !descriptor || registry->entry_count == 0u) {
        return CEP_ENZYME_FATAL;
    }

    registry->entry_count--;
    return CEP_ENZYME_SUCCESS;
}


size_t cep_enzyme_resolve(const cepEnzymeRegistry* registry, const cepEnzymeImpulse* impulse, const cepEnzymeDescriptor** ordered, size_t capacity) {
    (void)registry;
    (void)impulse;
    (void)ordered;
    (void)capacity;

    return 0u;
}
