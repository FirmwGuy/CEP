/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


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
    if (!cell || !cep_cell_is_normal(cell) || !name || !cep_dt_is_valid(name)) {
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

/** Append a binding for @p name onto @p cell so future impulses can trigger the
    enzyme directly from the tree. The helper records the heartbeat in the
    binding and optionally marks it for propagation down the subtree. */
int cep_cell_bind_enzyme(cepCell* cell, const cepDT* name, bool propagate) {
    uint32_t flags = propagate ? CEP_ENZYME_BIND_PROPAGATE : 0u;
    return cep_cell_append_binding(cell, name, flags);
}

/** Append a tombstone for @p name, hiding the enzyme from subsequent resolves
    without destroying historical bindings. */
int cep_cell_unbind_enzyme(cepCell* cell, const cepDT* name) {
    return cep_cell_append_binding(cell, name, CEP_ENZYME_BIND_TOMBSTONE);
}

/** Surface the binding list associated with @p cell so diagnostics and tooling
    can inspect it without walking internal structures. */
const cepEnzymeBinding* cep_cell_enzyme_bindings(const cepCell* cell) {
    if (!cell || !cep_cell_is_normal(cell)) {
        return NULL;
    }

    if (cell->data && cell->data->bindings) {
        return cell->data->bindings;
    }

    if (cell->store && cell->store->bindings) {
        return cell->store->bindings;
    }

    if (cell->data) {
        return cell->data->bindings;
    }

    if (cell->store) {
        return cell->store->bindings;
    }

    return NULL;
}
