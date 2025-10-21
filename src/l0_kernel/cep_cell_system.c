/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_cell.h"
#include "cep_l0.h"
#include "cep_namepool.h"
#include "cep_organ.h"

cepOpCount CEP_OP_COUNT;

CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));

cepOpCount cep_cell_timestamp_next(void) {
    cepOpCount next = ++CEP_OP_COUNT;
    if (!next)
        next = ++CEP_OP_COUNT;
    return next;
}

void cep_cell_timestamp_reset(void) {
    CEP_OP_COUNT = 0;
}

cepCell CEP_ROOT;   // The root cell.

void cep_cell_system_initiate(void) {
    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    cep_cell_timestamp_reset();

    cepDT dictionary_type = *dt_dictionary_type();
    cep_cell_initialize_dictionary(   &CEP_ROOT,
                                      CEP_DTAA("CEP", "/"),
                                      &dictionary_type,
                                      CEP_STORAGE_RED_BLACK_T );

    cep_l0_bootstrap_reset();
}

void cep_cell_system_shutdown(void) {
    if (!cep_cell_system_initialized()) {
        return;
    }

    cep_cell_finalize_hard(&CEP_ROOT);
    CEP_0(&CEP_ROOT);
    cep_namepool_reset();
    cep_organ_runtime_reset();
}

bool cep_cell_system_initialized(void) {
    return !cep_cell_is_void(&CEP_ROOT);
}

void cep_cell_system_ensure(void) {
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
}
