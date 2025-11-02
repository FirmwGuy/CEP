/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include <stdlib.h>

#include "cep_cell.h"
#include "cep_enzyme.h"
#include "cep_organ.h"

static bool cep_cell_binding_has_active(const cepEnzymeBinding* head, const cepDT* name) {
    if (!head || !name || !cep_dt_is_valid(name)) {
        return false;
    }

    cepDT lookup = cep_dt_clean(name);
    for (const cepEnzymeBinding* node = head; node; node = node->next) {
        if (node->flags & CEP_ENZYME_BIND_TOMBSTONE) {
            continue;
        }
        if (cep_dt_compare(&node->name, &lookup) == 0) {
            return true;
        }
    }

    return false;
}

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

static void
cep_enzyme_binding_list_destroy(cepEnzymeBinding* bindings)
{
    while (bindings) {
        cepEnzymeBinding* next = bindings->next;
        cep_free(bindings);
        bindings = next;
    }
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
    cepDT binding_name = cep_dt_clean(name);

    const cepOrganDescriptor* descriptor = NULL;
    if (cell && cep_cell_is_normal(cell) && cell->store) {
        descriptor = cep_organ_descriptor(&cell->store->dt);
    }

    if (descriptor) {
        if (!propagate) {
            return CEP_ENZYME_FATAL;
        }

        bool is_validator = cep_dt_compare(&binding_name, &descriptor->validator) == 0;
        bool is_constructor = cep_dt_is_valid(&descriptor->constructor) &&
                              cep_dt_compare(&binding_name, &descriptor->constructor) == 0;
        bool is_destructor = cep_dt_is_valid(&descriptor->destructor) &&
                             cep_dt_compare(&binding_name, &descriptor->destructor) == 0;

        if (!is_validator && !is_constructor && !is_destructor) {
            return CEP_ENZYME_FATAL;
        }

        if (!is_validator) {
            const cepEnzymeBinding* existing = cep_cell_enzyme_bindings(cell);
            if (!cep_cell_binding_has_active(existing, &descriptor->validator)) {
                return CEP_ENZYME_FATAL;
            }
        }
    }

    uint32_t flags = propagate ? CEP_ENZYME_BIND_PROPAGATE : 0u;
    return cep_cell_append_binding(cell, &binding_name, flags);
}

/** Append a tombstone for @p name, hiding the enzyme from subsequent resolves
    without destroying historical bindings. */
int cep_cell_unbind_enzyme(cepCell* cell, const cepDT* name) {
    cepDT binding_name = cep_dt_clean(name);

    const cepOrganDescriptor* descriptor = NULL;
    if (cell && cep_cell_is_normal(cell) && cell->store) {
        descriptor = cep_organ_descriptor(&cell->store->dt);
    }

    if (descriptor) {
        if (cep_dt_compare(&binding_name, &descriptor->validator) == 0) {
            return CEP_ENZYME_FATAL;
        }
    }

    return cep_cell_append_binding(cell, &binding_name, CEP_ENZYME_BIND_TOMBSTONE);
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

void
cep_cell_clear_bindings(cepCell* cell)
{
    if (!cell || !cep_cell_is_normal(cell)) {
        return;
    }

    cepOpCount* modified_slot = NULL;
    cepEnzymeBinding** head = cep_cell_binding_slot(cell, &modified_slot);
    if (!head || !*head) {
        return;
    }

    cep_enzyme_binding_list_destroy(*head);
    *head = NULL;

    if (modified_slot) {
        *modified_slot = cep_cell_timestamp_next();
    }
}
