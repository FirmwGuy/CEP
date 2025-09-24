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
 */

#include <stdlib.h>

#include "cep_cell.h"
#include "cep_enzyme.h"

static cepEnzymeBinding** cep_cell_binding_slot(cepCell* cell, cepOpCount** modified_out) {
    if (modified_out) {
        *modified_out = NULL;
    }

    if (!cell || !cep_cell_is_normal(cell)) {
        return NULL;
    }

    if (cell->store) {
        if (modified_out) {
            *modified_out = &cell->store->modified;
        }
        return &cell->store->bindings;
    }

    if (cell->data) {
        if (modified_out) {
            *modified_out = &cell->data->modified;
        }
        return &cell->data->bindings;
    }

    return NULL;
}

static int cep_cell_append_binding(cepCell* cell, const cepDT* name, uint32_t flags) {
    if (!cell || !cep_cell_is_normal(cell) || !name || !cep_dt_valid(name)) {
        return CEP_ENZYME_FATAL;
    }

    cepOpCount* modified_slot = NULL;
    cepEnzymeBinding** head = cep_cell_binding_slot(cell, &modified_slot);
    if (!head) {
        return CEP_ENZYME_FATAL;
    }

    cepEnzymeBinding* binding = cep_malloc(sizeof *binding);
    if (!binding) {
        return CEP_ENZYME_FATAL;
    }

    cepOpCount timestamp = cep_cell_timestamp_next();
    binding->next = *head;
    binding->name = *name;
    binding->flags = flags;
    binding->modified = timestamp;

    *head = binding;

    if (modified_slot) {
        *modified_slot = timestamp;
    }

    return CEP_ENZYME_SUCCESS;
}

int cep_cell_bind_enzyme(cepCell* cell, const cepDT* name, bool propagate) {
    uint32_t flags = propagate ? CEP_ENZYME_BIND_PROPAGATE : 0u;
    return cep_cell_append_binding(cell, name, flags);
}

int cep_cell_unbind_enzyme(cepCell* cell, const cepDT* name) {
    return cep_cell_append_binding(cell, name, CEP_ENZYME_BIND_TOMBSTONE);
}

const cepEnzymeBinding* cep_cell_enzyme_bindings(const cepCell* cell) {
    if (!cell || !cep_cell_is_normal(cell)) {
        return NULL;
    }

    if (cell->store && cell->store->bindings) {
        return cell->store->bindings;
    }

    if (cell->data) {
        return cell->data->bindings;
    }

    return NULL;
}

