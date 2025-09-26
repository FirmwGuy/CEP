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
        test_watchdog_signal(fix->watchdog);
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
    StreamFixture* fix = fixture;
    munit_assert_not_null(fix);

    char* archive_path = make_temp_path();
    munit_assert_not_null(archive_path);

    cep_cell_system_initiate();

    cepCell library;
    CEP_0(&library);
    munit_assert_true(cep_zip_library_open(&library,
                                           CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_lib")),
                                           archive_path,
                                           ZIP_CREATE | ZIP_TRUNCATE));

    enum { MAX_ENTRIES = 5, MAX_ENTRY_SIZE = 256 };
    size_t entry_count = (size_t)munit_rand_int_range(1, MAX_ENTRIES + 1);
    uint8_t payloads[MAX_ENTRIES][MAX_ENTRY_SIZE];
    size_t lengths[MAX_ENTRIES];

    for (size_t i = 0; i < entry_count; ++i) {
        lengths[i] = (size_t)munit_rand_int_range(32, MAX_ENTRY_SIZE);
        munit_rand_memory(lengths[i], payloads[i]);

        char name[32];
        snprintf(name, sizeof name, "entry-%zu.bin", i);

        cepCell entry;
        CEP_0(&entry);
        munit_assert_true(cep_zip_entry_init(&entry,
                                             CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_entry")),
                                             &library,
                                             name,
                                             true));

        cepCell stream;
        CEP_0(&stream);
        cep_zip_stream_init(&stream,
                            CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_stream")),
                            &library,
                            &entry);

        size_t offset = 0;
        while (offset < lengths[i]) {
            size_t chunk = (size_t)munit_rand_int_range(8, 48);
            if (offset + chunk > lengths[i])
                chunk = lengths[i] - offset;
            size_t written = 0;
            munit_assert_true(cep_cell_stream_write(&stream,
                                                    offset,
                                                    payloads[i] + offset,
                                                    chunk,
                                                    &written));
            munit_assert_size(written, ==, chunk);
            offset += chunk;
            test_watchdog_signal(fix->watchdog);
        }

        munit_assert_true(cep_stream_commit_pending());
        cep_cell_finalize_hard(&stream);
        cep_cell_finalize_hard(&entry);
    }

    for (size_t i = 0; i < entry_count; ++i) {
        char name[32];
        snprintf(name, sizeof name, "entry-%zu.bin", i);

        cepCell resource;
        CEP_0(&resource);
        munit_assert_true(cep_zip_entry_init(&resource,
                                             CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_vfy")),
                                             &library,
                                             name,
                                             false));

        cepCell stream;
        CEP_0(&stream);
        cep_zip_stream_init(&stream,
                            CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_vfys")),
                            &library,
                            &resource);

        uint8_t buffer[MAX_ENTRY_SIZE];
        size_t read = 0;
        munit_assert_true(cep_cell_stream_read(&stream,
                                               0,
                                               buffer,
                                               lengths[i],
                                               &read));
        munit_assert_size(read, ==, lengths[i]);
        munit_assert_memory_equal(lengths[i], payloads[i], buffer);

        cep_cell_finalize_hard(&stream);
        cep_cell_finalize_hard(&resource);
        test_watchdog_signal(fix->watchdog);
    }

    cep_zip_library_close(&library);
    cep_cell_finalize_hard(&library);
    cep_cell_system_shutdown();

    remove(archive_path);
    cep_free(archive_path);
    test_watchdog_signal(fix->watchdog);
    return MUNIT_OK;
}
#endif
