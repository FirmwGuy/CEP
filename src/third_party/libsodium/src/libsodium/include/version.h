/* Minimal version header to satisfy bundled libsodium shims on Windows builds. */

#ifndef sodium_version_H
#define sodium_version_H

#include "sodium/export.h"

#define SODIUM_VERSION_STRING "1.0.21"

#define SODIUM_LIBRARY_VERSION_MAJOR 28
#define SODIUM_LIBRARY_VERSION_MINOR 0

#ifdef __cplusplus
extern "C" {
#endif

const char *sodium_version_string(void);
int         sodium_library_version_major(void);
int         sodium_library_version_minor(void);
int         sodium_library_minimal(void);

#ifdef __cplusplus
}
#endif

#endif
