/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/*
 *  The watchdog module keeps long-running randomized tests honest by arming a
 *  background thread that aborts the process if a test exceeds its negotiated
 *  timeout; this lets us keep aggressive fuzz-like loops without risking hangs.
 *  Callers create a watchdog per test, poke it once they are done, and destroy
 *  it alongside their fixtures.
 */
/* Watchdog helpers that abort tests when progress stalls. */


#include "watchdog.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>

#if defined(_WIN32)
#   include <windows.h>
#   include <process.h>
#else
#   include <pthread.h>
#   include <unistd.h>
#endif

enum {
    WATCHDOG_MAX_TIMEOUT_SECONDS = 300u,
    WATCHDOG_MIN_TIMEOUT_SECONDS = 1u,
};

struct TestWatchdog {
    atomic_bool done;
    unsigned    timeoutSeconds;
    bool        trace;
    time_t      armedAt;
#if defined(_WIN32)
    HANDLE      thread;
#else
    pthread_t   thread;
#endif
};

static bool watchdog_should_trace(void) {
    const char* value = getenv("TEST_WATCHDOG_TRACE");
    return value && value[0] && value[0] != '0';
}

static void watchdog_trace(const TestWatchdog* wd, const char* event) {
    if (!wd || !wd->trace)
        return;
    time_t now = time(NULL);
    unsigned elapsed = 0u;
    if (now != (time_t)-1 && wd->armedAt != (time_t)-1 && now >= wd->armedAt) {
        elapsed = (unsigned) difftime(now, wd->armedAt);
    }
    fprintf(stderr,
            "[watchdog] %s elapsed=%us timeout=%us\n",
            event,
            elapsed,
            wd->timeoutSeconds);
    fflush(stderr);
}

#if defined(_WIN32)
static unsigned __stdcall watchdog_thread(void* param) {
    TestWatchdog* wd = param;
    for (unsigned elapsed = 0; elapsed < wd->timeoutSeconds; ++elapsed) {
        Sleep(1000);
        if (atomic_load_explicit(&wd->done, memory_order_acquire))
            return 0;
    }
    watchdog_trace(wd, "expired");
    fputs("test timed out after watchdog limit\n", stderr);
    fflush(stderr);
    _Exit(EXIT_FAILURE);
}
#else
static void* watchdog_thread(void* param) {
    TestWatchdog* wd = param;
    for (unsigned elapsed = 0; elapsed < wd->timeoutSeconds; ++elapsed) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        if (atomic_load_explicit(&wd->done, memory_order_acquire))
            return NULL;
    }
    watchdog_trace(wd, "expired");
    fputs("test timed out after watchdog limit\n", stderr);
    fflush(stderr);
    _Exit(EXIT_FAILURE);
    return NULL;
}
#endif

static unsigned watchdog_clamp_timeout(unsigned seconds) {
    if (seconds < WATCHDOG_MIN_TIMEOUT_SECONDS) {
        return WATCHDOG_MIN_TIMEOUT_SECONDS;
    }
    if (seconds > WATCHDOG_MAX_TIMEOUT_SECONDS) {
        return WATCHDOG_MAX_TIMEOUT_SECONDS;
    }
    return seconds;
}

static void watchdog_start(TestWatchdog* wd, unsigned seconds) {
    atomic_init(&wd->done, false);
    wd->timeoutSeconds = watchdog_clamp_timeout(seconds);
    wd->armedAt = time(NULL);
    wd->trace = watchdog_should_trace();
    watchdog_trace(wd, "armed");
#if defined(_WIN32)
    uintptr_t handle = _beginthreadex(NULL, 0, watchdog_thread, wd, 0, NULL);
    munit_assert(handle != 0);
    wd->thread = (HANDLE)handle;
#else
    int rc = pthread_create(&wd->thread, NULL, watchdog_thread, wd);
    munit_assert_int(rc, ==, 0);
#endif
}

/* test_watchdog_create allocates a watchdog and arms its worker so slow tests abort instead of hanging the suite. */
TestWatchdog* test_watchdog_create(unsigned seconds) {
    TestWatchdog* wd = munit_malloc(sizeof *wd);
    watchdog_start(wd, seconds);
    return wd;
}

/* test_watchdog_signal lets tests mark the watchdog as satisfied so the watchdog thread exits without killing the process. */
void test_watchdog_signal(TestWatchdog* wd) {
    if (!wd)
        return;
    atomic_store_explicit(&wd->done, true, memory_order_release);
    watchdog_trace(wd, "cleared");
}

static void watchdog_stop(TestWatchdog* wd) {
    if (!wd)
        return;
    test_watchdog_signal(wd);
#if defined(_WIN32)
    WaitForSingleObject(wd->thread, INFINITE);
    CloseHandle(wd->thread);
#else
    pthread_join(wd->thread, NULL);
#endif
}

/* test_watchdog_destroy stops the watchdog thread and disposes the watchdog instance to avoid dangling background workers between tests. */
void test_watchdog_destroy(TestWatchdog* wd) {
    if (!wd)
        return;
    watchdog_stop(wd);
    free(wd);
}

/* test_watchdog_resolve_timeout extracts and validates the timeout parameter so suites can honor overrides without crashing. */
unsigned test_watchdog_resolve_timeout(const MunitParameter params[], unsigned fallback) {
    if (!params)
        return watchdog_clamp_timeout(fallback);
    const char* value = munit_parameters_get(params, "timeout");
    if (!value || !value[0])
        return watchdog_clamp_timeout(fallback);
    char* endptr = NULL;
    unsigned long parsed = strtoul(value, &endptr, 10);
    if (endptr == value || (endptr && *endptr))
        return watchdog_clamp_timeout(fallback);
    if (parsed == 0 || parsed > UINT_MAX)
        return watchdog_clamp_timeout(fallback);
    return watchdog_clamp_timeout((unsigned)parsed);
}
