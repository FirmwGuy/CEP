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

#include "cep_cell.h"

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
