#include "test.h"

#ifdef CEP_HAS_LIBZIP

#include "stream/cep_stream_zip.h"
#include "stream/cep_stream_internal.h"

#include <zip.h>

#include <stdio.h>
#include <string.h>

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

MunitResult test_stream_zip(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    char* archive_path = make_temp_path();
    munit_assert_not_null(archive_path);

    cep_cell_system_initiate();

    cepCell library;
    CEP_0(&library);
    munit_assert_true(cep_zip_library_open(&library,
                                           CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_lib")),
                                           archive_path,
                                           ZIP_CREATE | ZIP_TRUNCATE));

    cepCell entry;
    CEP_0(&entry);
    munit_assert_true(cep_zip_entry_init(&entry,
                                         CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_entry")),
                                         &library,
                                         "greeting.txt",
                                         true));

    cepCell stream;
    CEP_0(&stream);
    cep_zip_stream_init(&stream,
                        CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_stream")),
                        &library,
                        &entry);

    const char* payload = "hello world";
    size_t written = 0;
    munit_assert_true(cep_cell_stream_write(&stream, 0, payload, strlen(payload), &written));
    munit_assert_size(written, ==, strlen(payload));

    munit_assert_true(cep_stream_commit_pending());

    cepCell verify_resource;
    CEP_0(&verify_resource);
    munit_assert_true(cep_zip_entry_init(&verify_resource,
                                         CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_verify")),
                                         &library,
                                         "greeting.txt",
                                         false));

    cepCell verify_stream;
    CEP_0(&verify_stream);
    cep_zip_stream_init(&verify_stream,
                        CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("zip_ver_str")),
                        &library,
                        &verify_resource);

    char buffer[32] = {0};
    size_t read = 0;
    munit_assert_true(cep_cell_stream_read(&verify_stream, 0, buffer, strlen(payload), &read));
    buffer[read] = '\0';
    munit_assert_string_equal(buffer, payload);

    cep_cell_finalize(&verify_stream);
    cep_cell_finalize(&verify_resource);
    cep_cell_finalize(&stream);
    cep_cell_finalize(&entry);

    cep_zip_library_close(&library);
    cep_cell_finalize(&library);
    cep_cell_system_shutdown();

    remove(archive_path);
    cep_free(archive_path);

    return MUNIT_OK;
}

#endif /* CEP_HAS_LIBZIP */
