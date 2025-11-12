/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "test.h"

#include "cep_flat_stream.h"
#include "cep_flat_serializer.h"
#include "cep_crc32c.h"
#include "blake3.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char kFlatAeadKeyHex[] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

typedef struct {
    uint8_t* data;
    size_t   size;
} FlatFrameCapture;

static bool flat_capture_sink(void* ctx, const uint8_t* chunk, size_t size) {
    FlatFrameCapture* capture = ctx;
    if (!capture || !chunk || !size)
        return false;
    uint8_t* grown = capture->data
        ? cep_realloc(capture->data, capture->size + size)
        : cep_malloc(size);
    if (!grown)
        return false;
    memcpy(grown + capture->size, chunk, size);
    capture->data = grown;
    capture->size += size;
    return true;
}

static void flat_capture_clear(FlatFrameCapture* capture) {
    if (!capture)
        return;
    cep_free(capture->data);
    capture->data = NULL;
    capture->size = 0u;
}

static bool flat_hex_decode(const char* hex, uint8_t* out, size_t expected_len) {
    if (!hex || !out)
        return false;
    size_t len = strlen(hex);
    if (len != expected_len * 2u)
        return false;
    for (size_t i = 0; i < expected_len; ++i) {
        unsigned hi = (unsigned)hex[i * 2u + 0u];
        unsigned lo = (unsigned)hex[i * 2u + 1u];
        if (hi >= '0' && hi <= '9')
            hi -= '0';
        else if (hi >= 'a' && hi <= 'f')
            hi = 10u + (hi - 'a');
        else if (hi >= 'A' && hi <= 'F')
            hi = 10u + (hi - 'A');
        else
            return false;
        if (lo >= '0' && lo <= '9')
            lo -= '0';
        else if (lo >= 'a' && lo <= 'f')
            lo = 10u + (lo - 'a');
        else if (lo >= 'A' && lo <= 'F')
            lo = 10u + (lo - 'A');
        else
            return false;
        out[i] = (uint8_t)((hi << 4u) | lo);
    }
    return true;
}

static bool flat_read_varint(const uint8_t* data, size_t size, size_t* offset, uint64_t* out_value) {
    if (!data || !offset || !out_value || *offset >= size)
        return false;
    uint64_t value = 0u;
    unsigned shift = 0u;
    while (*offset < size) {
        uint8_t byte = data[(*offset)++];
        value |= (uint64_t)(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0u)
            break;
        shift += 7u;
        if (shift >= 64u)
            return false;
    }
    *out_value = value;
    return true;
}

static size_t flat_varint_length_u64(uint64_t value) {
    size_t len = 1u;
    while (value >= 0x80u) {
        value >>= 7u;
        len++;
    }
    return len;
}

static bool flat_write_varint_fixed(uint8_t* dst, size_t len, uint64_t value) {
    if (!dst)
        return false;
    size_t needed = flat_varint_length_u64(value);
    if (needed != len)
        return false;
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = (uint8_t)(value & 0x7Fu);
        value >>= 7u;
        if (value)
            byte |= 0x80u;
        dst[i] = byte;
    }
    return true;
}

static uint32_t flat_recompute_crc(const uint8_t* payload, size_t payload_size) {
    return cep_crc32c(payload, payload_size, 0u);
}

static void flat_compute_aad_hash(const uint8_t* key_ptr,
                                  size_t key_len,
                                  uint8_t out_hash[CEP_FLAT_HASH_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (key_ptr && key_len)
        blake3_hasher_update(&hasher, key_ptr, key_len);
    blake3_hasher_finalize(&hasher, out_hash, CEP_FLAT_HASH_SIZE);
}

static void flat_assert_chunk_records(const uint8_t* frame,
                                      size_t frame_size,
                                      const uint8_t* expected_payload,
                                      size_t expected_payload_size,
                                      bool expect_encrypted,
                                      const uint8_t* aead_key,
                                      size_t aead_key_len) {
    size_t offset = 0u;
    unsigned chunk_records = 0u;
    uint64_t expected_chunk_offset = 0u;
    uint8_t nonce_buf[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0};

    while (offset < frame_size) {
        if (frame_size - offset < 4u)
            break;
        uint8_t type = frame[offset++];
        uint8_t version = frame[offset++];
        uint16_t flags = (uint16_t)(frame[offset] | (frame[offset + 1u] << 8));
        offset += 2u;
        (void)flags;

        uint64_t key_len_u64 = 0u;
        uint64_t body_len_u64 = 0u;
        munit_assert_true(flat_read_varint(frame, frame_size, &offset, &key_len_u64));
        munit_assert_true(flat_read_varint(frame, frame_size, &offset, &body_len_u64));
        munit_assert_uint64(key_len_u64, <=, SIZE_MAX);
        munit_assert_uint64(body_len_u64, <=, SIZE_MAX);
        size_t key_len = (size_t)key_len_u64;
        size_t body_len = (size_t)body_len_u64;
        munit_assert_size(offset + key_len + body_len + sizeof(uint32_t), <=, frame_size);
        const uint8_t* key_ptr = frame + offset;
        offset += key_len;

        const uint8_t* body_ptr = frame + offset;
        offset += body_len;
        offset += sizeof(uint32_t);

        if (type == CEP_FLAT_RECORD_PAYLOAD_CHUNK &&
            version == CEP_FLAT_SERIALIZER_VERSION) {
            size_t body_off = 0u;
            munit_assert_size(body_len, >, 0u);
            munit_assert_uint8(body_ptr[body_off++], ==, CEP_DATATYPE_VALUE);

            uint64_t total_size = 0u;
            munit_assert_true(flat_read_varint(body_ptr, body_len, &body_off, &total_size));
            munit_assert_uint64(total_size, ==, expected_payload_size);

            uint64_t chunk_offset = 0u;
            uint64_t chunk_size = 0u;
            munit_assert_true(flat_read_varint(body_ptr, body_len, &body_off, &chunk_offset));
            munit_assert_true(flat_read_varint(body_ptr, body_len, &body_off, &chunk_size));
            munit_assert_uint64(chunk_offset, ==, expected_chunk_offset);
            expected_chunk_offset += chunk_size;

            uint64_t fp_len = 0u;
            munit_assert_true(flat_read_varint(body_ptr, body_len, &body_off, &fp_len));
            munit_assert_size(body_off + fp_len, <=, body_len);
            body_off += (size_t)fp_len;
            munit_assert_size(body_off, <, body_len);

            uint8_t aead_mode = body_ptr[body_off++];
            if (expect_encrypted)
                munit_assert_uint8(aead_mode, ==, CEP_FLAT_AEAD_XCHACHA20_POLY1305);
            else
                munit_assert_uint8(aead_mode, ==, CEP_FLAT_AEAD_NONE);

            uint64_t nonce_len_u64 = 0u;
            munit_assert_true(flat_read_varint(body_ptr, body_len, &body_off, &nonce_len_u64));
            munit_assert_uint64(nonce_len_u64, <=, sizeof nonce_buf);
            size_t nonce_len = (size_t)nonce_len_u64;
            munit_assert_size(body_off + nonce_len, <=, body_len);
            memcpy(nonce_buf, body_ptr + body_off, nonce_len);
            body_off += nonce_len;

            uint8_t stored_aad[CEP_FLAT_HASH_SIZE];
            munit_assert_size(body_off + sizeof stored_aad, <=, body_len);
            memcpy(stored_aad, body_ptr + body_off, sizeof stored_aad);
            body_off += sizeof stored_aad;

            uint8_t expected_aad[CEP_FLAT_HASH_SIZE];
            flat_compute_aad_hash(key_ptr, key_len, expected_aad);
            munit_assert_memory_equal(sizeof stored_aad, stored_aad, expected_aad);

            size_t remaining = body_len - body_off;
            const uint8_t* chunk_payload = expected_payload + chunk_offset;
            if (!expect_encrypted) {
                munit_assert_size(nonce_len, ==, 0u);
                munit_assert_size(remaining, ==, (size_t)chunk_size);
                munit_assert_memory_equal((size_t)chunk_size, body_ptr + body_off, chunk_payload);
            } else {
                munit_assert_size(nonce_len, ==, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
                size_t expected_cipher = (size_t)chunk_size + crypto_aead_xchacha20poly1305_ietf_ABYTES;
                munit_assert_size(remaining, ==, expected_cipher);
                munit_assert_not_null(aead_key);
                munit_assert_size(aead_key_len, ==, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
                uint8_t* decrypted = malloc((size_t)chunk_size);
                munit_assert_not_null(decrypted);
                unsigned long long plain_len = 0u;
                int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted,
                                                                    &plain_len,
                                                                    NULL,
                                                                    body_ptr + body_off,
                                                                    remaining,
                                                                    key_ptr,
                                                                    key_len,
                                                                    nonce_buf,
                                                                    aead_key);
                munit_assert_int(rc, ==, 0);
                munit_assert_uint64(plain_len, ==, chunk_size);
                munit_assert_memory_equal((size_t)chunk_size, decrypted, chunk_payload);
                sodium_memzero(decrypted, (size_t)plain_len);
                free(decrypted);
            }

            chunk_records++;
        }
    }

    munit_assert_uint(chunk_records, >=, 2u);
    munit_assert_uint64(expected_chunk_offset, ==, expected_payload_size);
}

typedef struct {
    uint8_t* record_ptr;
    size_t   payload_size;
    uint8_t* body_ptr;
    size_t   body_size;
} FlatChunkRecord;

static bool flat_locate_chunk_record(uint8_t* frame,
                                     size_t frame_size,
                                     unsigned target_chunk,
                                     FlatChunkRecord* out) {
    size_t offset = 0u;
    unsigned chunk_index = 0u;
    while (offset < frame_size) {
        if (frame_size - offset < 4u)
            return false;
        size_t record_start = offset;
        uint8_t type = frame[offset++];
        offset++; /* version */
        offset += sizeof(uint16_t); /* flags */

        uint64_t key_len = 0u;
        if (!flat_read_varint(frame, frame_size, &offset, &key_len))
            return false;
        uint64_t body_len = 0u;
        if (!flat_read_varint(frame, frame_size, &offset, &body_len))
            return false;
        if (frame_size - offset < key_len + body_len + sizeof(uint32_t))
            return false;

        uint8_t* key_ptr = frame + offset;
        (void)key_ptr;
        offset += (size_t)key_len;
        uint8_t* body_ptr = frame + offset;
        offset += (size_t)body_len;
        size_t payload_size = offset - record_start;
        uint8_t* record_ptr = frame + record_start;

        offset += sizeof(uint32_t); /* CRC */
        if (offset > frame_size)
            return false;

        if (type == CEP_FLAT_RECORD_PAYLOAD_CHUNK) {
            if (chunk_index == target_chunk) {
                if (out) {
                    out->record_ptr = record_ptr;
                    out->payload_size = payload_size;
                    out->body_ptr = body_ptr;
                    out->body_size = (size_t)body_len;
                }
                return true;
            }
            chunk_index++;
        }
    }
    return false;
}

static bool flat_mutate_chunk_offset(uint8_t* frame,
                                     size_t frame_size,
                                     unsigned target_chunk,
                                     uint64_t new_offset) {
    FlatChunkRecord record = {0};
    if (!flat_locate_chunk_record(frame, frame_size, target_chunk, &record))
        return false;
    size_t cursor = 0u;
    if (record.body_size == 0u)
        return false;
    cursor++; /* payload kind */
    if (!flat_read_varint(record.body_ptr, record.body_size, &cursor, &(uint64_t){0}))
        return false;
    size_t chunk_offset_pos = cursor;
    uint64_t chunk_offset = 0u;
    if (!flat_read_varint(record.body_ptr, record.body_size, &cursor, &chunk_offset))
        return false;
    size_t chunk_offset_len = cursor - chunk_offset_pos;
    if (flat_varint_length_u64(new_offset) != chunk_offset_len)
        return false;
    if (!flat_write_varint_fixed(record.body_ptr + chunk_offset_pos,
                                 chunk_offset_len,
                                 new_offset))
        return false;

    uint32_t crc = flat_recompute_crc(record.record_ptr, record.payload_size);
    memcpy(record.record_ptr + record.payload_size, &crc, sizeof crc);
    return true;
}

static bool flat_swap_chunk_records(uint8_t* frame,
                                    size_t frame_size,
                                    unsigned chunk_a,
                                    unsigned chunk_b) {
    if (chunk_a == chunk_b)
        return true;
    const size_t max_records = 128u;
    size_t record_starts[128];
    size_t record_sizes[128];
    unsigned chunk_map[64];
    size_t record_count = 0u;
    unsigned chunk_count = 0u;

    size_t offset = 0u;
    while (offset < frame_size && record_count < max_records) {
        record_starts[record_count] = offset;
        if (frame_size - offset < 4u)
            return false;
        uint8_t type = frame[offset++];
        offset++; /* version */
        offset += sizeof(uint16_t);
        uint64_t key_len = 0u;
        if (!flat_read_varint(frame, frame_size, &offset, &key_len))
            return false;
        uint64_t body_len = 0u;
        if (!flat_read_varint(frame, frame_size, &offset, &body_len))
            return false;
        if (frame_size - offset < key_len + body_len + sizeof(uint32_t))
            return false;
        offset += (size_t)key_len + (size_t)body_len + sizeof(uint32_t);
        if (offset > frame_size)
            return false;

        record_sizes[record_count] = offset - record_starts[record_count];
        if (type == CEP_FLAT_RECORD_PAYLOAD_CHUNK && chunk_count < cep_lengthof(chunk_map))
            chunk_map[chunk_count++] = record_count;
        record_count++;
    }

    if (chunk_a >= chunk_count || chunk_b >= chunk_count)
        return false;
    unsigned record_idx_a = chunk_map[chunk_a];
    unsigned record_idx_b = chunk_map[chunk_b];

    uint8_t* temp = cep_malloc(frame_size);
    if (!temp)
        return false;

    size_t out = 0u;
    for (size_t i = 0; i < record_count; ++i) {
        size_t source_index = i;
        if (i == record_idx_a)
            source_index = record_idx_b;
        else if (i == record_idx_b)
            source_index = record_idx_a;
        memcpy(temp + out,
               frame + record_starts[source_index],
               record_sizes[source_index]);
        out += record_sizes[source_index];
    }
    bool ok = (out == frame_size);
    if (ok)
        memcpy(frame, temp, frame_size);
    cep_free(temp);
    return ok;
}

static bool flat_reader_expect_failure(uint8_t* frame, size_t frame_size) {
    cepFlatReader* reader = cep_flat_reader_create();
    if (!reader)
        return false;
    bool feed_ok = cep_flat_reader_feed(reader, frame, frame_size);
    bool commit_ok = feed_ok && cep_flat_reader_commit(reader);
    cep_flat_reader_destroy(reader);
    return !feed_ok || !commit_ok;
}

static void flat_restore_env(const char* key, char* snapshot) {
    if (snapshot) {
        setenv(key, snapshot, 1);
        free(snapshot);
    } else {
        unsetenv(key);
    }
}

static void flat_prng_payload(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        buf[i] = (uint8_t)(i & 0xFFu);
}

static bool flat_random_mutate_frame(uint8_t* frame, size_t original_size, size_t* mutated_size) {
    if (!frame || !mutated_size || original_size <= 4u)
        return false;
    for (unsigned attempt = 0; attempt < 4u; ++attempt) {
        unsigned mode = (unsigned)munit_rand_int_range(0, 4);
        switch (mode) {
        case 0: {
            size_t max_drop = original_size > 4u ? original_size - 4u : 1u;
            if (max_drop == 0u)
                break;
            size_t drop = (size_t)munit_rand_int_range(1, (int)(max_drop + 1u));
            if (drop >= original_size)
                drop = original_size - 1u;
            *mutated_size = original_size - drop;
            return true;
        }
        case 1: {
            if (original_size <= sizeof(uint32_t))
                break;
            uint8_t* crc_ptr = frame + original_size - sizeof(uint32_t);
            uint32_t crc = 0u;
            memcpy(&crc, crc_ptr, sizeof crc);
            uint32_t poison = (munit_rand_uint32() | 1u);
            crc ^= poison;
            memcpy(crc_ptr, &crc, sizeof crc);
            *mutated_size = original_size;
            return true;
        }
        case 2: {
            if (original_size <= 12u)
                break;
            size_t cut_start = (size_t)munit_rand_int_range(4, (int)(original_size - 4u));
            size_t max_cut = original_size - cut_start - 1u;
            if (max_cut == 0u)
                break;
            size_t cut_len = (size_t)munit_rand_int_range(1, (int)(max_cut + 1u));
            memmove(frame + cut_start,
                    frame + cut_start + cut_len,
                    original_size - (cut_start + cut_len));
            *mutated_size = original_size - cut_len;
            return true;
        }
        case 3: {
            if (original_size <= 5u)
                break;
            frame[4u] = 0xFFu;
            if (original_size > 5u)
                frame[5u] |= 0x80u;
            *mutated_size = original_size;
            return true;
        }
        default:
            break;
        }
    }
    if (original_size > 1u) {
        *mutated_size = original_size - 1u;
        return true;
    }
    return false;
}

MunitResult test_serialization_flat_multi_chunk(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    const char* prev_comp = getenv("CEP_SERIALIZATION_FLAT_COMPRESSION");
    char* prev_comp_copy = prev_comp ? strdup(prev_comp) : NULL;
    const char* prev_aead_mode = getenv("CEP_SERIALIZATION_FLAT_AEAD_MODE");
    char* prev_aead_mode_copy = prev_aead_mode ? strdup(prev_aead_mode) : NULL;
    const char* prev_aead_key = getenv("CEP_SERIALIZATION_FLAT_AEAD_KEY");
    char* prev_aead_key_copy = prev_aead_key ? strdup(prev_aead_key) : NULL;
    munit_assert_int(unsetenv("CEP_SERIALIZATION_FLAT_AEAD_MODE"), ==, 0);
    munit_assert_int(unsetenv("CEP_SERIALIZATION_FLAT_AEAD_KEY"), ==, 0);
    munit_assert_int(sodium_init(), >=, 0);

    uint8_t payload[96];
    flat_prng_payload(payload, sizeof payload);
    cepData* data = cep_data_new_value(CEP_DTAW("CEP", "flat_multi"),
                                      payload,
                                      sizeof payload);
    munit_assert_not_null(data);
    const uint8_t* expected_payload = (const uint8_t*)cep_data_payload(data);
    if (!expected_payload)
        expected_payload = payload;

    cepCell cell;
    CEP_0(&cell);
    cep_cell_initialize(&cell,
                        CEP_TYPE_NORMAL,
                        CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("flat_test")),
                        data,
                        NULL);

    FlatFrameCapture capture = {0};
    const size_t chunk_limit = 32u;
    munit_assert_true(cep_flat_stream_emit_cell(&cell,
                                                NULL,
                                                (cepFlatStreamWriteFn)flat_capture_sink,
                                                &capture,
                                                chunk_limit));
    munit_assert_size(capture.size, >, 0u);
    flat_assert_chunk_records(capture.data,
                              capture.size,
                              expected_payload,
                              sizeof payload,
                              false,
                              NULL,
                              0u);
    flat_capture_clear(&capture);

    uint8_t aead_key_bytes[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    munit_assert_true(flat_hex_decode(kFlatAeadKeyHex, aead_key_bytes, sizeof aead_key_bytes));
    munit_assert_int(setenv("CEP_SERIALIZATION_FLAT_AEAD_MODE", "xchacha20", 1), ==, 0);
    munit_assert_int(setenv("CEP_SERIALIZATION_FLAT_AEAD_KEY", kFlatAeadKeyHex, 1), ==, 0);
    munit_assert_true(cep_flat_stream_emit_cell(&cell,
                                                NULL,
                                                (cepFlatStreamWriteFn)flat_capture_sink,
                                                &capture,
                                                chunk_limit));
    flat_assert_chunk_records(capture.data,
                              capture.size,
                              expected_payload,
                              sizeof payload,
                              true,
                              aead_key_bytes,
                              sizeof aead_key_bytes);
    flat_capture_clear(&capture);

    munit_assert_int(setenv("CEP_SERIALIZATION_FLAT_COMPRESSION", "deflate", 1), ==, 0);
    munit_assert_true(cep_flat_stream_emit_cell(&cell,
                                                NULL,
                                                (cepFlatStreamWriteFn)flat_capture_sink,
                                                &capture,
                                                chunk_limit));
    munit_assert_size(capture.size, >, 0u);
    cepFlatReader* reader = cep_flat_reader_create();
    munit_assert_not_null(reader);
    munit_assert_true(cep_flat_reader_feed(reader, capture.data, capture.size));
    munit_assert_true(cep_flat_reader_commit(reader));
    const cepFlatFrameConfig* frame_cfg = cep_flat_reader_frame(reader);
    munit_assert_uint(frame_cfg->compression_algorithm, ==, CEP_FLAT_COMPRESSION_DEFLATE);
    munit_assert_uint(frame_cfg->checksum_algorithm, ==, CEP_FLAT_CHECKSUM_CRC32);
    cep_flat_reader_destroy(reader);
    flat_capture_clear(&capture);

    flat_restore_env("CEP_SERIALIZATION_FLAT_COMPRESSION", prev_comp_copy);
    flat_restore_env("CEP_SERIALIZATION_FLAT_AEAD_MODE", prev_aead_mode_copy);
    flat_restore_env("CEP_SERIALIZATION_FLAT_AEAD_KEY", prev_aead_key_copy);
    cep_cell_finalize_hard(&cell);
    return MUNIT_OK;
}

static MunitResult flat_chunk_violation_helper(const cepDT* data_type,
                                               const cepDT* cell_type,
                                               bool (*mutator)(uint8_t*, size_t),
                                               bool expect_success_after_mutation) {
    uint8_t payload[96];
    flat_prng_payload(payload, sizeof payload);

    cepData* data = cep_data_new_value((cepDT*)data_type,
                                      payload,
                                      sizeof payload);
    munit_assert_not_null(data);

    cepCell cell;
    CEP_0(&cell);
    cep_cell_initialize(&cell,
                        CEP_TYPE_NORMAL,
                        (cepDT*)cell_type,
                        data,
                        NULL);

    FlatFrameCapture capture = {0};
    munit_assert_true(cep_flat_stream_emit_cell(&cell,
                                                NULL,
                                                (cepFlatStreamWriteFn)flat_capture_sink,
                                                &capture,
                                                32u));
    munit_assert_size(capture.size, >, 0u);

    uint8_t* mutated = malloc(capture.size);
    munit_assert_not_null(mutated);
    memcpy(mutated, capture.data, capture.size);
    bool mutated_ok = mutator(mutated, capture.size);
    munit_assert_true(mutated_ok);
    bool reader_failed = flat_reader_expect_failure(mutated, capture.size);
    munit_assert_int(reader_failed ? 1 : 0, ==, expect_success_after_mutation ? 0 : 1);
    free(mutated);

    flat_capture_clear(&capture);
    cep_cell_finalize_hard(&cell);
    return MUNIT_OK;
}

static bool flat_mutate_offset_wrapper(uint8_t* frame, size_t frame_size) {
    return flat_mutate_chunk_offset(frame, frame_size, 1u, 0u);
}

static bool flat_swap_chunks_wrapper(uint8_t* frame, size_t frame_size) {
    return flat_swap_chunk_records(frame, frame_size, 0u, 1u);
}

MunitResult test_serialization_flat_chunk_offset_violation(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;
    return flat_chunk_violation_helper(CEP_DTAW("CEP", "chunk_off"),
                                       CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("chunk_off")),
                                       flat_mutate_offset_wrapper,
                                       false);
}

MunitResult test_serialization_flat_chunk_order_violation(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;
    return flat_chunk_violation_helper(CEP_DTAW("CEP", "chunk_ord"),
                                       CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("chunk_ord")),
                                       flat_swap_chunks_wrapper,
                                       false);
}

MunitResult test_serialization_flat_randomized_corruption(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    const char* prev_comp = getenv("CEP_SERIALIZATION_FLAT_COMPRESSION");
    char* prev_comp_copy = prev_comp ? strdup(prev_comp) : NULL;
    const char* prev_aead_mode = getenv("CEP_SERIALIZATION_FLAT_AEAD_MODE");
    char* prev_aead_mode_copy = prev_aead_mode ? strdup(prev_aead_mode) : NULL;
    const char* prev_aead_key = getenv("CEP_SERIALIZATION_FLAT_AEAD_KEY");
    char* prev_aead_key_copy = prev_aead_key ? strdup(prev_aead_key) : NULL;
    munit_assert_int(sodium_init(), >=, 0);

    uint8_t aead_key_bytes[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    munit_assert_true(flat_hex_decode(kFlatAeadKeyHex, aead_key_bytes, sizeof aead_key_bytes));

    for (unsigned iteration = 0; iteration < 32u; ++iteration) {
        bool use_compression = (munit_rand_uint32() & 1u) != 0u;
        bool use_aead = (munit_rand_uint32() & 1u) != 0u;
        if (use_compression)
            munit_assert_int(setenv("CEP_SERIALIZATION_FLAT_COMPRESSION", "deflate", 1), ==, 0);
        else
            munit_assert_int(unsetenv("CEP_SERIALIZATION_FLAT_COMPRESSION"), ==, 0);

        if (use_aead) {
            munit_assert_int(setenv("CEP_SERIALIZATION_FLAT_AEAD_MODE", "xchacha20", 1), ==, 0);
            munit_assert_int(setenv("CEP_SERIALIZATION_FLAT_AEAD_KEY", kFlatAeadKeyHex, 1), ==, 0);
        } else {
            munit_assert_int(unsetenv("CEP_SERIALIZATION_FLAT_AEAD_MODE"), ==, 0);
            munit_assert_int(unsetenv("CEP_SERIALIZATION_FLAT_AEAD_KEY"), ==, 0);
        }

        size_t payload_size = (size_t)munit_rand_int_range(64, 2049);
        uint8_t* payload = malloc(payload_size);
        munit_assert_not_null(payload);
        munit_rand_memory(payload_size, payload);

        cepData* data = cep_data_new_value(CEP_DTAW("CEP", "flat_multi"),
                                          payload,
                                          payload_size);
        munit_assert_not_null(data);

        cepCell cell;
        CEP_0(&cell);
        cep_cell_initialize(&cell,
                            CEP_TYPE_NORMAL,
                            CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("flat_test")),
                            data,
                            NULL);

        FlatFrameCapture capture = {0};
        size_t chunk_limit = (size_t)munit_rand_int_range(16, 257);
        munit_assert_true(cep_flat_stream_emit_cell(&cell,
                                                    NULL,
                                                    (cepFlatStreamWriteFn)flat_capture_sink,
                                                    &capture,
                                                    chunk_limit));
        munit_assert_size(capture.size, >, 0u);

        cepFlatReader* reader = cep_flat_reader_create();
        munit_assert_not_null(reader);
        munit_assert_true(cep_flat_reader_feed(reader, capture.data, capture.size));
        munit_assert_true(cep_flat_reader_commit(reader));
        cep_flat_reader_destroy(reader);

        uint8_t* mutated = malloc(capture.size);
        munit_assert_not_null(mutated);
        memcpy(mutated, capture.data, capture.size);
        size_t mutated_size = capture.size;
        bool mutated_ok = flat_random_mutate_frame(mutated, capture.size, &mutated_size);
        munit_assert_true(mutated_ok);
        munit_assert_true(mutated_size > 0u);
        munit_assert_true(flat_reader_expect_failure(mutated, mutated_size));
        free(mutated);

        flat_capture_clear(&capture);
        cep_cell_finalize_hard(&cell);
        free(payload);
    }

    flat_restore_env("CEP_SERIALIZATION_FLAT_COMPRESSION", prev_comp_copy);
    flat_restore_env("CEP_SERIALIZATION_FLAT_AEAD_MODE", prev_aead_mode_copy);
    flat_restore_env("CEP_SERIALIZATION_FLAT_AEAD_KEY", prev_aead_key_copy);
    return MUNIT_OK;
}
