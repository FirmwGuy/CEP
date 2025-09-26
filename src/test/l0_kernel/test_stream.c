/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/*
 *  Standard C stream adapter smoke tests. Verifies CEP stream helpers can
 *  drive stdio-backed files through the new library vtable while journaling
 *  reads and writes.
 */
/* STREAM adapter unit tests for basic read/write contract. */


#include "test.h"
#include "stream/cep_stream_stdio.h"
#include "stream/cep_stream_internal.h"

#include <stdio.h>

MunitResult test_stream_stdio(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepCell library;
    CEP_0(&library);
    cep_stdio_library_init(&library, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdio_lib")));

    FILE* file = tmpfile();
    assert_not_null(file);

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

    const char* greeting = "hello ";
    size_t written = 0;
    assert_true(cep_cell_stream_write(&stream, 0, greeting, strlen(greeting), &written));
    assert_size(written, ==, strlen(greeting));

    const char* noun = "world";
    written = 0;
    assert_true(cep_cell_stream_write(&stream, strlen(greeting), noun, strlen(noun), &written));
    assert_size(written, ==, strlen(noun));

    assert_true(cep_stream_commit_pending());

    char buffer[32] = {0};
    size_t read = 0;
    assert_true(cep_cell_stream_read(&stream, 0, buffer, strlen(greeting) + strlen(noun), &read));
    buffer[read] = '\0';
    assert_string_equal(buffer, "hello world");

    char tail[6] = {0};
    read = 0;
    assert_true(cep_cell_stream_read(&stream, strlen(greeting), tail, strlen(noun), &read));
    tail[read] = '\0';
    assert_string_equal(tail, "world");

    cep_cell_finalize_hard(&stream);
    cep_cell_finalize_hard(&resource);
    cep_cell_finalize_hard(&library);
    cep_cell_system_shutdown();

    return MUNIT_OK;
}
