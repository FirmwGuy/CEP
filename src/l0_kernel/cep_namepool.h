/*
 *  CEP Name Pool - Interned string support for CEP_NAMING_REFERENCE.
 */

#ifndef CEP_NAMEPOOL_H
#define CEP_NAMEPOOL_H

#include <stddef.h>
#include "cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

bool    cep_namepool_bootstrap(void);
cepID   cep_namepool_intern(const char* text, size_t length);
cepID   cep_namepool_intern_cstr(const char* text);
const char* cep_namepool_lookup(cepID id, size_t* length);

#ifdef __cplusplus
}
#endif

#endif
