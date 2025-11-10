/* Thin shims so we can link against the bundled libsodium sources without
 * modifying upstream files. */

#include <stdlib.h>

#include "core.h"
#include "runtime.h"
#include "utils.h"
#include "version.h"

static void (*sodium_misuse_handler)(void);

int
sodium_init(void)
{
    return 0;
}

int
sodium_set_misuse_handler(void (*handler)(void))
{
    sodium_misuse_handler = handler;
    return 0;
}

void
sodium_misuse(void)
{
    void (*handler)(void) = sodium_misuse_handler;
    if (handler != NULL) {
        handler();
    }
    abort();
}

void
sodium_memzero(void *const pnt, const size_t len)
{
    if (pnt == NULL) {
        return;
    }
    volatile unsigned char *volatile buf = (volatile unsigned char *volatile)pnt;
    for (size_t i = 0; i < len; i++) {
        buf[i] = 0u;
    }
}

const char *
sodium_version_string(void)
{
    return SODIUM_VERSION_STRING;
}

int
sodium_library_version_major(void)
{
    return SODIUM_LIBRARY_VERSION_MAJOR;
}

int
sodium_library_version_minor(void)
{
    return SODIUM_LIBRARY_VERSION_MINOR;
}

int
sodium_library_minimal(void)
{
    return 0;
}
