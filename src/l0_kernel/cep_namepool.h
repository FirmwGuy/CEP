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

/**
 * @brief Ensure the name pool infrastructure exists before use.
 */
bool    cep_namepool_bootstrap(void);
/**
 * @brief Intern a UTF-8 buffer and return a CEP_NAMING_REFERENCE ID.
 */
cepID   cep_namepool_intern(const char* text, size_t length);
/**
 * @brief Convenience wrapper around cep_namepool_intern for C strings.
 */
cepID   cep_namepool_intern_cstr(const char* text);
/**
 * @brief Register a static (caller-owned) string without copying.
 */
cepID   cep_namepool_intern_static(const char* text, size_t length);
/**
 * @brief Resolve a reference ID back into the stored bytes.
 */
const char* cep_namepool_lookup(cepID id, size_t* length);
/**
 * @brief Release a dynamic interned name, reducing its reference count.
 */
bool    cep_namepool_release(cepID id);

#ifdef __cplusplus
}
#endif

#endif
