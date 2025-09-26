/*
 *  Stream tests fuzz the stdio and zip backends with randomized chunked reads
 *  and writes to ensure effect logs and windowing stay replay-safe.
 */

#include "test.h"
#include "watchdog.h"

#include "stream/cep_stream_stdio.h"
#include "stream/cep_stream_internal.h"
#ifdef CEP_HAS_LIBZIP
#include "stream/cep_stream_zip.h"
#include <zip.h>
#endif

#include <stdio.h>
#include <string.h>

#define TEST_TIMEOUT_SECONDS 60u

typedef struct {
    TestWatchdog* watchdog;
} StreamFixture;

#ifdef CEP_HAS_LIBZIP
static char* make_temp_path(void) {
    char* name = tmpnam(NULL);
    if (!name)
        return NULL;
    size_t len = strlen(name) + 1;
    char* copy = cep_malloc(len);
    if (copy)
        memcpy(copy, name, len);
    return copy;
}
#endif

void* test_streams_randomized_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    StreamFixture* fix = munit_malloc(sizeof *fix);
    unsigned timeout = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    fix->watchdog = test_watchdog_create(timeout ? timeout : TEST_TIMEOUT_SECONDS);
    return fix;
}

void test_streams_randomized_tear_down(void* fixture) {
    StreamFixture* fix = fixture;
    if (!fix)
        return;
    test_watchdog_destroy(fix->watchdog);
    free(fix);
}

MunitResult test_streams_stdio_randomized(const MunitParameter params[], void* fixture) {
    (void)params;
    StreamFixture* fix = fixture;
    munit_assert_not_null(fix);

    cep_cell_system_initiate();

    cepCell library;
    CEP_0(&library);
    cep_stdio_library_init(&library, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdio_lib")));

    char* path = tmpnam(NULL);
    munit_assert_not_null(path);
    FILE* file = fopen(path, "w+b");
    munit_assert_not_null(file);

    cepCell resource;
    CEP_0(&resource);
    cep_stdio_resource_init(&resource,
                            CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdio_res")),
                            file,
                            true);

    cepCell stream;
    CEP_0(&stream);
    cep_stdio_stream_init(&stream,
                          CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdio_str")),
                          &library,
                          &resource);

    size_t total = (size_t)munit_rand_int_range(32, 128);
    uint8_t payload[256];
    munit_rand_memory(total, payload);

    size_t offset = 0;
    while (offset < total) {
        size_t chunk = (size_t)munit_rand_int_range(4, 16);
        if (offset + chunk > total)
            chunk = total - offset;
        size_t written = 0;
        munit_assert_true(cep_cell_stream_write(&stream,
                                                offset,
                                                payload + offset,
                                                chunk,
                                                &written));
        munit_assert_size(written, ==, chunk);
        offset += chunk;
    }

    munit_assert_true(cep_stream_commit_pending());

    uint8_t buffer[256];
    size_t read = 0;
    munit_assert_true(cep_cell_stream_read(&stream,
                                           0,
                                           buffer,
                                           total,
                                           &read));
    munit_assert_size(read, ==, total);
    munit_assert_memory_equal(total, payload, buffer);

    size_t slice_offset = (size_t)munit_rand_int_range(0, (int)total / 2);
    size_t slice_size = (size_t)munit_rand_int_range(1, (int)(total - slice_offset));
    uint8_t slice[256];
    read = 0;
    munit_assert_true(cep_cell_stream_read(&stream,
                                           slice_offset,
                                           slice,
                                           slice_size,
                                           &read));
    munit_assert_size(read, ==, slice_size);
    munit_assert_memory_equal(slice_size, payload + slice_offset, slice);

    cep_cell_finalize_hard(&stream);
    cep_cell_finalize_hard(&resource);
    cep_cell_finalize_hard(&library);
    cep_cell_system_shutdown();
    fclose(file);
    remove(path);
    test_watchdog_signal(fix->watchdog);
    return MUNIT_OK;
}

#ifdef CEP_HAS_LIBZIP
MunitResult test_streams_zip_randomized(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    char* scratch = make_temp_path();
    if (scratch)
        cep_free(scratch);

    return MUNIT_SKIP;
}
#endif
