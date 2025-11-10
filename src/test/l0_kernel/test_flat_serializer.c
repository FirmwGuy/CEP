/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "test.h"
#include "cep_flat_serializer.h"

#include <string.h>

MunitResult test_flat_serializer_round_trip(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    cepFlatSerializer* serializer = cep_flat_serializer_create();
    munit_assert_not_null(serializer);

    cepFlatFrameConfig config = {
        .beat_number = 42u,
        .apply_mode = CEP_FLAT_APPLY_INSERT_ONLY,
        .capability_flags = CEP_FLAT_CAP_SPLIT_DESC | CEP_FLAT_CAP_PAGED_CHILDSET,
        .hash_algorithm = CEP_FLAT_HASH_BLAKE3_256,
    };
    munit_assert_true(cep_flat_serializer_begin(serializer, &config));

    static const uint8_t key_a[] = {0x01u, 0x00u, 0xA5u, 0x5Au};
    static const uint8_t body_a[] = {0x10u, 0x20u, 0x30u};
    cepFlatRecordSpec record_a = {
        .type = CEP_FLAT_RECORD_CELL_DESC,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0x0001u,
        .key = {
            .data = key_a,
            .size = sizeof key_a,
        },
        .body = {
            .data = body_a,
            .size = sizeof body_a,
        },
    };
    munit_assert_true(cep_flat_serializer_emit(serializer, &record_a));

    static const uint8_t key_b[] = {0x02u, 0xFFu};
    static const uint8_t body_b[] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    cepFlatRecordSpec record_b = {
        .type = CEP_FLAT_RECORD_MANIFEST_DELTA,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0x0002u,
        .key = {
            .data = key_b,
            .size = sizeof key_b,
        },
        .body = {
            .data = body_b,
            .size = sizeof body_b,
        },
    };
    munit_assert_true(cep_flat_serializer_emit(serializer, &record_b));

    munit_assert_true(cep_flat_serializer_finish(serializer, NULL, NULL));

    const uint8_t* frame_bytes = NULL;
    size_t frame_size = 0u;
    munit_assert_true(cep_flat_serializer_frame_bytes(serializer, &frame_bytes, &frame_size));
    munit_assert_not_null(frame_bytes);
    munit_assert_size(frame_size, >, 0u);

    cepFlatReader* reader = cep_flat_reader_create();
    munit_assert_not_null(reader);
    munit_assert_true(cep_flat_reader_feed(reader, frame_bytes, frame_size));
    munit_assert_true(cep_flat_reader_commit(reader));
    munit_assert_true(cep_flat_reader_ready(reader));

    const cepFlatFrameConfig* parsed_config = cep_flat_reader_frame(reader);
    munit_assert_not_null(parsed_config);
    munit_assert_uint64(parsed_config->beat_number, ==, config.beat_number);
    munit_assert_uint(parsed_config->capability_flags, ==, config.capability_flags);
    munit_assert_uint(parsed_config->apply_mode, ==, config.apply_mode);

    const uint8_t* merkle = cep_flat_reader_merkle_root(reader);
    munit_assert_not_null(merkle);

    size_t parsed_count = 0u;
    const cepFlatRecordView* parsed = cep_flat_reader_records(reader, &parsed_count);
    munit_assert_not_null(parsed);
    munit_assert_size(parsed_count, ==, 2u);

    munit_assert_uint(parsed[0].type, ==, record_a.type);
    munit_assert_size(parsed[0].key.size, ==, sizeof key_a);
    munit_assert_memory_equal(sizeof key_a, parsed[0].key.data, key_a);
    munit_assert_size(parsed[0].body.size, ==, sizeof body_a);
    munit_assert_memory_equal(sizeof body_a, parsed[0].body.data, body_a);

    munit_assert_uint(parsed[1].type, ==, record_b.type);
    munit_assert_size(parsed[1].key.size, ==, sizeof key_b);
    munit_assert_memory_equal(sizeof key_b, parsed[1].key.data, key_b);
    munit_assert_size(parsed[1].body.size, ==, sizeof body_b);
    munit_assert_memory_equal(sizeof body_b, parsed[1].body.data, body_b);

    cep_flat_reader_destroy(reader);
    cep_flat_serializer_destroy(serializer);
    return MUNIT_OK;
}
