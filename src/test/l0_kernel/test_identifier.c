/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Validate cep_compose_identifier canonicalizes token slices into a single
 * ledger-friendly identifier and rejects malformed inputs so downstream layers
 * keep deterministic naming across call sites. */

#include "test.h"
#include "cep_identifier.h"

#include <string.h>

/* Exercise happy path and rejection rules for cep_compose_identifier so callers
 * see consistent trimming, casing, and validation behaviour. */
MunitResult test_identifier(const MunitParameter params[], void* fixture) {
    test_boot_cycle_prepare(params);
    (void)fixture;

    char buffer[CEP_IDENTIFIER_MAX + 2u];

    const char* basic_tokens[] = { " Team ", "Alpha" };
    munit_assert_true(cep_compose_identifier(basic_tokens, cep_lengthof(basic_tokens), buffer, sizeof buffer));
    munit_assert_string_equal(buffer, "team:alpha");

    const char* symbol_tokens[] = { "Project-42", "Phase_1/2" };
    munit_assert_true(cep_compose_identifier(symbol_tokens, cep_lengthof(symbol_tokens), buffer, sizeof buffer));
    munit_assert_string_equal(buffer, "project-42:phase_1/2");

    const char* long_token[] = { NULL };
    char long_source[CEP_IDENTIFIER_MAX + 2u];
    memset(long_source, 'a', CEP_IDENTIFIER_MAX);
    long_source[CEP_IDENTIFIER_MAX] = '\0';
    long_token[0] = long_source;
    munit_assert_true(cep_compose_identifier(long_token, cep_lengthof(long_token), buffer, sizeof buffer));
    munit_assert_size(strlen(buffer), ==, CEP_IDENTIFIER_MAX);

    long_source[CEP_IDENTIFIER_MAX] = 'q';
    long_source[CEP_IDENTIFIER_MAX + 1u] = '\0';
    munit_assert_false(cep_compose_identifier(long_token, cep_lengthof(long_token), buffer, sizeof buffer));

    const char* bad_colon[] = { "alpha:beta" };
    munit_assert_false(cep_compose_identifier(bad_colon, cep_lengthof(bad_colon), buffer, sizeof buffer));

    const char* bad_char[] = { "beta@" };
    munit_assert_false(cep_compose_identifier(bad_char, cep_lengthof(bad_char), buffer, sizeof buffer));

    const char* empty_token[] = { " \t" };
    munit_assert_false(cep_compose_identifier(empty_token, cep_lengthof(empty_token), buffer, sizeof buffer));

    const char* null_token[] = { NULL };
    munit_assert_false(cep_compose_identifier(null_token, cep_lengthof(null_token), buffer, sizeof buffer));

    const char* short_tokens[] = { "One", "Two" };
    munit_assert_false(cep_compose_identifier(short_tokens, cep_lengthof(short_tokens), buffer, 5u));

    munit_assert_false(cep_compose_identifier(short_tokens, 0u, buffer, sizeof buffer));

    return MUNIT_OK;
}
