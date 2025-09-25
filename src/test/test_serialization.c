#include "test.h"

#include "cep_serialization.h"
#include "cep_cell.h"

#include <string.h>


typedef struct {
    uint8_t* data;
    size_t   size;
} SerializationChunk;

typedef struct {
    SerializationChunk chunks[8];
    size_t             count;
} SerializationCapture;

static bool serialization_capture_sink(void* ctx, const uint8_t* chunk, size_t size) {
    SerializationCapture* capture = ctx;
    if (!capture || !chunk || !size)
        return false;
    if (capture->count >= sizeof capture->chunks / sizeof capture->chunks[0])
        return false;

    uint8_t* copy = cep_malloc(size);
    memcpy(copy, chunk, size);

    capture->chunks[capture->count].data = copy;
    capture->chunks[capture->count].size = size;
    capture->count++;

    return true;
}

static uint16_t read_be16(const uint8_t* buffer) {
    return (uint16_t)((buffer[0] << 8) | buffer[1]);
}

static uint32_t read_be32(const uint8_t* buffer) {
    return ((uint32_t)buffer[0] << 24) |
           ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8)  |
           ((uint32_t)buffer[3]);
}

static uint64_t read_be64(const uint8_t* buffer) {
    uint64_t hi = read_be32(buffer);
    uint64_t lo = read_be32(buffer + 4);
    return (hi << 32) | lo;
}

/* Validate that a single normal cell turns into the expected trio of chunks:
   the control/header frame with the CEP magic, the structural manifest with the
   cell path, and the inline data descriptor that carries both metadata and the
   payload bytes. */
MunitResult test_serialization(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    uint8_t payload[] = "serialize-me";
    cepData* data = cep_data_new_value(CEP_DTAW("CEP", "value"), payload, sizeof payload - 1u);

    cepCell cell;
    CEP_0(&cell);
    cep_cell_initialize(&cell,
                        CEP_TYPE_NORMAL,
                        CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("ser_cell")),
                        data,
                        NULL);

    cepID expected_domain = cell.metacell.domain;
    cepID expected_tag = cell.metacell.tag;

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(&cell,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));

    munit_assert_size(capture.count, ==, 3);

    const SerializationChunk* header_chunk = &capture.chunks[0];
    cepSerializationHeader parsed = {0};
    munit_assert_true(cep_serialization_header_read(header_chunk->data,
                                                    header_chunk->size,
                                                    &parsed));
    munit_assert_uint64(parsed.magic, ==, CEP_SERIALIZATION_MAGIC);
    munit_assert_uint16(parsed.version, ==, CEP_SERIALIZATION_VERSION);
    munit_assert_uint8(parsed.byte_order, ==, CEP_SERIAL_ENDIAN_BIG);

    const SerializationChunk* manifest_chunk = &capture.chunks[1];
    uint64_t manifest_payload = read_be64(manifest_chunk->data);
    munit_assert_size(manifest_chunk->size, ==, manifest_payload + CEP_SERIALIZATION_CHUNK_OVERHEAD);
    uint64_t manifest_id = read_be64(manifest_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(manifest_id), ==, CEP_CHUNK_CLASS_STRUCTURE);
    munit_assert_uint32(cep_serialization_chunk_transaction(manifest_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(manifest_id), ==, 1);

    const uint8_t* manifest_payload_bytes = manifest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint16_t segment_count = read_be16(manifest_payload_bytes);
    munit_assert_uint16(segment_count, ==, 1);
    uint8_t cell_type = manifest_payload_bytes[2];
    uint8_t manifest_flags = manifest_payload_bytes[3];
    munit_assert_uint8(cell_type, ==, CEP_TYPE_NORMAL);
    munit_assert_true((manifest_flags & 0x08u) != 0);

    const uint8_t* path_bytes = manifest_payload_bytes + 6;
    uint64_t domain = read_be64(path_bytes);
    uint64_t tag = read_be64(path_bytes + 8);
    munit_assert_uint64(domain, ==, expected_domain);
    munit_assert_uint64(tag, ==, expected_tag);

    const SerializationChunk* data_chunk = &capture.chunks[2];
    uint64_t data_payload = read_be64(data_chunk->data);
    munit_assert_size(data_chunk->size, ==, data_payload + CEP_SERIALIZATION_CHUNK_OVERHEAD);
    uint64_t data_id = read_be64(data_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(data_id), ==, CEP_CHUNK_CLASS_STRUCTURE);
    munit_assert_uint32(cep_serialization_chunk_transaction(data_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(data_id), ==, 2);

    const uint8_t* descriptor = data_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint16_t datatype = read_be16(descriptor);
    uint16_t flags = read_be16(descriptor + 2);
    uint32_t inline_len = read_be32(descriptor + 4);
    uint64_t total_len = read_be64(descriptor + 8);
    uint64_t hash = read_be64(descriptor + 16);
    const uint8_t* inline_data = descriptor + 24;

    munit_assert_uint16(datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_uint16(flags, ==, 0);
    munit_assert_uint32(inline_len, ==, sizeof payload - 1u);
    munit_assert_uint64(total_len, ==, sizeof payload - 1u);
    munit_assert_uint64(hash, ==, cep_hash_bytes(payload, sizeof payload - 1u));
    munit_assert_int(memcmp(inline_data, payload, sizeof payload - 1u), ==, 0);

    for (size_t i = 0; i < capture.count; ++i)
        cep_free(capture.chunks[i].data);
    cep_cell_finalize(&cell);

    return MUNIT_OK;
}

