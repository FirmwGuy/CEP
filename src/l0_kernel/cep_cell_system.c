/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_cell.h"
#include "cep_l0.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_runtime.h"

#include <assert.h>

CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));

cepOpCount cep_cell_timestamp_next(void) {
    cepRuntime* runtime = cep_runtime_default();
    cepOpCount* counter = cep_runtime_op_counter(runtime);
    if (!counter) {
        return 0;
    }
    cepOpCount next = ++(*counter);
    if (!next) {
        next = ++(*counter);
    }
    return next;
}

static bool g_cell_system_shutting_down = false;

bool
cep_cell_system_shutting_down(void)
{
    return g_cell_system_shutting_down;
}

void cep_cell_timestamp_reset(void) {
    cepOpCount* counter = cep_runtime_op_counter(cep_runtime_default());
    if (counter) {
        *counter = 0;
    }
}

void cep_cell_system_initiate(void) {
    cepRuntime* runtime = cep_runtime_default();
    cepCell* root = cep_runtime_root(runtime);

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    cep_cell_timestamp_reset();

    cepDT dictionary_type = *dt_dictionary_type();
    cep_cell_initialize_dictionary(root,
                                   CEP_DTAA("CEP", "/"),
                                   &dictionary_type,
                                   CEP_STORAGE_RED_BLACK_T );

    assert(cep_runtime_attach_metadata(runtime));

    cep_l0_bootstrap_reset();
}

void cep_cell_system_shutdown(void) {
    cepRuntime* runtime = cep_runtime_default();
    cepCell* root = cep_runtime_root(runtime);

    if (!cep_cell_system_initialized()) {
        return;
    }

    g_cell_system_shutting_down = true;
    cep_heartbeat_detach_topology();

    cep_cell_finalize_hard(root);
    CEP_0(root);
    cep_namepool_shutdown();
    cep_runtime_release_organ_registry(cep_runtime_default());
    g_cell_system_shutting_down = false;
}

bool cep_cell_system_initialized(void) {
    cepRuntime* runtime = cep_runtime_default();
    cepCell* root = cep_runtime_root(runtime);
    return root && !cep_cell_is_void(root);
}

void cep_cell_system_ensure(void) {
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
}

cepCell* cep_root(void) {
    cepRuntime* runtime = cep_runtime_default();
    cep_cell_system_ensure();
    cepCell* root = cep_runtime_root(runtime);
    assert(root);
    assert(!cep_cell_is_void(root));
    return root;
}

cepOpCount cep_cell_timestamp(void) {
    cepOpCount* counter = cep_runtime_op_counter(cep_runtime_default());
    return counter ? *counter : 0;
}
