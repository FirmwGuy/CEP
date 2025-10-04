/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Validates domain/tag naming conversions and reference handling. */



#include "test.h"
#include "cep_cell.h"
#include "cep_namepool.h"

#include <stdio.h>      // printf()
#include <ctype.h>      // islower()
#include <string.h>


static int test_domain_tag_naming_text(const char* text) {
    cepID word  = cep_text_to_word(text);
    cepID acron = cep_text_to_acronym(text);

    if (!word && !acron)
        return MUNIT_ERROR;

    char decoded[12];

    if (word) {
        size_t decoded_length = cep_word_to_text(word, decoded);
        assert_size(decoded_length, ==, strlen(text));
        assert_string_equal(text, decoded);

        printf("WORD  (%zu): \"%s\" = 0x%016"PRIX64"\n", decoded_length, text, word);
    } else {
        size_t decoded_length = cep_acronym_to_text(acron, decoded);
        assert_size(decoded_length, ==, strlen(text));
        assert_string_equal(text, decoded);

        printf("ACRON (%zu): \"%s\" = 0x%016"PRIX64"\n", decoded_length, text, acron);
    }

    return MUNIT_OK;
}


static inline size_t get_trimmed_length(const char* s) {
    while (*s == ' ')   s++;
    size_t len = strlen(s);
    while (len > 0  &&  s[len - 1] == ' ') {
        len--;
    }
    return len;
}

#define CODABLE_MIN     2
#define PRINTABLE_MIN   5

static void test_domain_tag_naming_coding(void) {
    const char* acronym_tests[] = {
        " ",
        "TOOLONGNAMEEXCEEDS",

        // Codable min:
        " TEST",
        "SPACE X   ",
        "TRIMMED   ",
    
        // Printable min:
        "HELLO",
        "WORLD!",
        "?",
        "ACRONYS()",
        "LONGNAME+"
    };
    const char* word_tests[] = {
        " ",
        "toolongtoencodeproperly",

        // Codable min:
        " with space",
        "trailing     ",
        "    trimthis   ",

        // Printable min:
        "hello",
        "world.",
        "a",
        "valid_word",
        "punctu-ated"
    };

    char   decoded[12];
    cepID  encoded;
    size_t decoded_length;

    for (size_t i = 0;  i < cep_lengthof(acronym_tests);  i++) {
        encoded = cep_text_to_acronym(acronym_tests[i]);
        if (encoded) {
            decoded_length = cep_acronym_to_text(encoded, decoded);

            assert_size(decoded_length, ==, get_trimmed_length(acronym_tests[i]));
            if (i < PRINTABLE_MIN)
                assert_string_not_equal(decoded, acronym_tests[i]);
            else
                assert_string_equal(decoded, acronym_tests[i]);
        } else {
            assert_size(i, <=, CODABLE_MIN);
        }
    }

    for (size_t i = 0;  i < cep_lengthof(word_tests);  i++) {
        encoded = cep_text_to_word(word_tests[i]);
        if (encoded) {
            decoded_length = cep_word_to_text(encoded, decoded);

            assert_size(decoded_length, ==, get_trimmed_length(word_tests[i]));
            if (i < PRINTABLE_MIN)
                assert_string_not_equal(decoded, word_tests[i]);
            else
                assert_string_equal(decoded, word_tests[i]);
        } else {
            assert_size(i, <=, CODABLE_MIN);
        }
    }
}

static void test_reference_interning(void) {
    assert_true(cep_namepool_bootstrap());

    static const char dynamic_text[] = "dynamic-namepool-entry";
    size_t dynamic_len = strlen(dynamic_text);
    cepID dynamic_id1 = cep_namepool_intern(dynamic_text, dynamic_len);
    assert_true(cep_id_is_reference(dynamic_id1));
    assert_true(cep_id_text_valid(dynamic_id1));

    size_t lookup_len = 0u;
    const char* lookup_bytes = cep_namepool_lookup(dynamic_id1, &lookup_len);
    assert_not_null(lookup_bytes);
    assert_size(lookup_len, ==, dynamic_len);
    assert_memory_equal(dynamic_len, dynamic_text, lookup_bytes);

    cepID dynamic_id2 = cep_namepool_intern(dynamic_text, dynamic_len);
    assert_true(dynamic_id1 == dynamic_id2);

    assert_true(cep_namepool_release(dynamic_id1));
    assert_true(cep_namepool_release(dynamic_id2));
    assert_null(cep_namepool_lookup(dynamic_id1, NULL));

    cepID dynamic_id3 = cep_namepool_intern(dynamic_text, dynamic_len);
    assert_uint64(dynamic_id3, !=, 0u);
    assert_true(cep_namepool_release(dynamic_id3));

    static const char static_text[] = "static-namepool-entry";
    cepID static_id = cep_namepool_intern_static(static_text, strlen(static_text));
    assert_true(cep_id_is_reference(static_id));
    assert_true(cep_id_text_valid(static_id));

    lookup_bytes = cep_namepool_lookup(static_id, &lookup_len);
    assert_not_null(lookup_bytes);
    assert_size(lookup_len, ==, strlen(static_text));
    assert_ptr_equal(lookup_bytes, static_text);

    cepDT dt = {
        .domain = static_id,
        .tag = CEP_DTAW("CEP", "domain")->tag,
    };
    assert_true(cep_dt_is_valid(&dt));

    assert_true(cep_namepool_release(static_id));
    assert_not_null(cep_namepool_lookup(static_id, NULL));

    static const char word_text[] = "lowercase";
    cepID word_id = cep_namepool_intern(word_text, strlen(word_text));
    assert_true(cep_id_is_word(word_id));
    assert_uint64(word_id, ==, cep_text_to_word(word_text));
    assert_true(cep_namepool_release(word_id));

    static const char acro_text[] = "UPPER";
    cepID acro_id = cep_namepool_intern(acro_text, strlen(acro_text));
    assert_true(cep_id_is_acronym(acro_id));
    assert_uint64(acro_id, ==, cep_text_to_acronym(acro_text));
    assert_true(cep_namepool_release(acro_id));

    static const char numeric_text[] = "123456";
    cepID numeric_id = cep_namepool_intern(numeric_text, strlen(numeric_text));
    assert_true(cep_id_is_numeric(numeric_id));
    assert_uint64(numeric_id, ==, cep_id_to_numeric((cepID)123456));
    assert_true(cep_namepool_release(numeric_id));
}

static void test_glob_interning(void) {
    assert_true(cep_namepool_bootstrap());

    /* Reference glob via pattern interning. */
    const char* pattern_text = "inventory/*/restock";
    cepID ref_glob_a = cep_namepool_intern_pattern_cstr(pattern_text);
    cepID ref_glob_b = cep_namepool_intern_pattern_cstr(pattern_text);
    assert_true(cep_id_is_reference(ref_glob_a));
    assert_true(cep_namepool_reference_is_glob(ref_glob_a));
    assert_true(cep_id_has_glob_char(ref_glob_a));
    size_t len = 0u;
    const char* lookup = cep_namepool_lookup(ref_glob_a, &len);
    assert_not_null(lookup);
    assert_size(len, ==, strlen(pattern_text));
    assert_memory_equal(len, pattern_text, lookup);

    /* Word-level glob bit. */
    cepID word_glob = cep_text_to_word("order*");
    cepID word_target = cep_text_to_word("order");
    cepID word_other = cep_text_to_word("invoice");
    assert_uint64(word_glob, !=, 0u);
    assert_uint64(word_target, !=, 0u);
    assert_uint64(word_other, !=, 0u);
    assert_true(cep_id_has_glob_char(word_glob));
    assert_true(cep_id_matches(word_glob, word_target));
    assert_false(cep_id_matches(word_glob, word_other));

    /* Reference glob matching. */
    const char* ref_pattern_text = "customer:*:active";
    cepID ref_pattern = cep_namepool_intern_pattern_cstr(ref_pattern_text);
    assert_true(cep_namepool_reference_is_glob(ref_pattern));
    cepID ref_value = cep_namepool_intern_cstr("customer:emea:active");
    cepID ref_other = cep_namepool_intern_cstr("customer:emea:inactive");
    assert_true(cep_id_matches(ref_pattern, ref_value));
    assert_false(cep_id_matches(ref_pattern, ref_other));

    /* Cleanup releases (mirroring the number of interning calls). */
    assert_true(cep_namepool_release(ref_glob_b));
    assert_true(cep_namepool_release(ref_glob_a));
    assert_true(cep_namepool_release(ref_pattern));
    assert_true(cep_namepool_release(ref_value));
    assert_true(cep_namepool_release(ref_other));
}


MunitResult test_domain_tag_naming(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;

    const char* param_value = munit_parameters_get(params, "text");
    if (param_value) {
        return test_domain_tag_naming_text(param_value);
    } else {
        test_domain_tag_naming_coding();
        test_reference_interning();
        test_glob_interning();
    }

    return MUNIT_OK;
}
