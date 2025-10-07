/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_cell.h"
#include "cep_mailroom.h"

cepOpCount CEP_OP_COUNT;

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
    cep_cell_timestamp_reset();

    cep_cell_initialize_dictionary(   &CEP_ROOT,
                                      CEP_DTAA("CEP", "/"),
                                      CEP_DTAW("CEP", "dictionary"),
                                      CEP_STORAGE_RED_BLACK_T );
}

void cep_cell_system_shutdown(void) {
    cep_cell_finalize_hard(&CEP_ROOT);
    CEP_0(&CEP_ROOT);
}

bool cep_cell_system_initialized(void) {
    return !cep_cell_is_void(&CEP_ROOT);
}

void cep_cell_system_ensure(void) {
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
}
