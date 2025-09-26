/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/*
 *  CEP Layer 0 Watchdog helpers
 *
 *  These helpers spin a background thread that terminates the process when a
 *  test takes too long. They are shared by multiple suites so we keep them in a
 *  dedicated compilation unit. Callers can request a watchdog for a given timeout
 *  and must dispose it once finished; a manual signal is also exposed so tests
 *  can stop the watchdog early when they know they are done.
 */

#ifndef CEP_WATCHDOG_H
#define CEP_WATCHDOG_H

#include <stdatomic.h>

#include "munit.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TestWatchdog TestWatchdog;

TestWatchdog*   test_watchdog_create(unsigned seconds);
void            test_watchdog_destroy(TestWatchdog* wd);
void            test_watchdog_signal(TestWatchdog* wd);
unsigned        test_watchdog_resolve_timeout(const MunitParameter params[], unsigned fallback);

#ifdef __cplusplus
}
#endif

#endif /* CEP_WATCHDOG_H */
