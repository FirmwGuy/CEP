/**
 * @file
 * @brief Interned string support backing CEP_NAMING_REFERENCE identifiers.
 */

#ifndef CEP_NAMEPOOL_H
#define CEP_NAMEPOOL_H

#include <stddef.h>
#include <stdbool.h>
#include "cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

bool    cep_namepool_bootstrap(void);
cepID   cep_namepool_intern(const char* text, size_t length);
cepID   cep_namepool_intern_cstr(const char* text);
cepID   cep_namepool_intern_static(const char* text, size_t length);
const char* cep_namepool_lookup(cepID id, size_t* length);
bool    cep_namepool_release(cepID id);

#ifdef __cplusplus
}
#endif

#endif
