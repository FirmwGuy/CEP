/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_flat_serializer.h"
#include "cep_molecule.h"
#include "cep_crc32c.h"
#include "blake3.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <sodium.h>

#define CEP_FLAT_MAGIC UINT32_C(0x43455046)
#define CEP_FLAT_BRANCH_METADATA_BYTES (1u + sizeof(uint64_t) * 3u)

typedef struct {
    uint8_t* data;
    size_t   size;
    size_t   capacity;
} cepFlatBuffer;

typedef struct {
    size_t key_offset;
    size_t key_size;
    size_t record_offset;
    size_t record_size;
    uint32_t checksum;
    uint8_t hash[CEP_FLAT_HASH_SIZE];
    uint8_t record_type;
} cepFlatDigestEntry;

typedef struct {
    const uint8_t* key;
    size_t         key_size;
    uint8_t        hash[CEP_FLAT_HASH_SIZE];
} cepFlatDigestLeaf;

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  compression;
    uint8_t  checksum;
    uint8_t  reserved;
    uint64_t uncompressed_size;
    uint64_t compressed_size;
} cepFlatContainerHeader;

typedef struct {
    uint8_t* key;
    size_t   key_size;
    uint64_t expected_offset;
    uint64_t expected_ordinal;
    uint64_t total_size;
    bool     total_set;
    bool     sealed;
} cepFlatChunkTracker;

struct cepFlatSerializer {
    cepFlatFrameConfig config;
    cepFlatBuffer      frame;
    cepFlatDigestEntry* digests;
    size_t              digest_count;
    size_t              digest_capacity;
    uint32_t            record_count;
    bool                frame_open;
};

struct cepFlatReader {
    cepFlatFrameConfig  frame;
    cepFlatBuffer       buffer;
    cepFlatRecordView*  records;
    size_t              record_count;
    size_t              record_capacity;
    cepFlatDigestEntry* digests;
    size_t              digest_count;
    size_t              digest_capacity;
    cepFlatChunkTracker* chunk_trackers;
    size_t chunk_tracker_count;
    size_t chunk_tracker_capacity;
    bool                committed;
    bool                trailer_verified;
    uint8_t             trailer_merkle[CEP_FLAT_HASH_SIZE];
    uint32_t            trailer_record_count;
    size_t              trailer_record_offset;
    size_t              trailer_record_size;
    uint32_t            trailer_checksum;
    cepFlatMiniTocEntry* mini_toc;
    size_t              mini_toc_count;
    size_t              mini_toc_capacity;
};

static bool cep_flat_append_record(cepFlatSerializer* serializer,
                                   const cepFlatRecordSpec* spec,
                                   bool track_digest);
static bool cep_flat_emit_trailer(cepFlatSerializer* serializer,
                                  const uint8_t merkle_root[CEP_FLAT_HASH_SIZE]);
static void cep_flat_compute_merkle(const cepFlatSerializer* serializer,
                                    uint8_t merkle_root[CEP_FLAT_HASH_SIZE]);
static bool cep_flat_reader_parse(cepFlatReader* reader);
static bool cep_flat_reader_parse_trailer(cepFlatReader* reader,
                                          const uint8_t* body,
                                          size_t body_size);
static bool cep_flat_serializer_apply_compression(cepFlatSerializer* serializer);
static bool cep_flat_reader_prepare_buffer(cepFlatReader* reader);
static bool cep_flat_reader_decode_chunk_key(const uint8_t* key,
                                             size_t key_size,
                                             size_t* base_size,
                                             uint64_t* ordinal);
static bool cep_flat_reader_validate_chunk(cepFlatReader* reader,
                                           const uint8_t* key,
                                           size_t key_size,
                                           const uint8_t* body,
                                           size_t body_size);
static bool cep_flat_reader_finalize_chunks(cepFlatReader* reader);
static void cep_flat_reader_clear_chunks(cepFlatReader* reader);
static bool cep_flat_reader_mini_toc_reserve(cepFlatReader* reader, size_t count);
static void cep_flat_reader_clear_mini_toc(cepFlatReader* reader);
static bool cep_flat_reader_validate_chunk(cepFlatReader* reader,
                                           const uint8_t* key,
                                           size_t key_size,
                                           const uint8_t* body,
                                           size_t body_size);
static bool cep_flat_reader_finalize_chunks(cepFlatReader* reader);
static void cep_flat_reader_clear_chunks(cepFlatReader* reader);

static size_t cep_flat_varint_length(uint64_t value);
static uint8_t* cep_flat_write_varint(uint64_t value, uint8_t* dst);
static bool cep_flat_read_varint(const uint8_t* data, size_t size, size_t* offset, uint64_t* out_value);
static uint32_t cep_flat_record_checksum(const uint8_t* data,
                                         size_t size,
                                         cepFlatChecksumAlgorithm algorithm);
static bool cep_flat_reader_verify_checksums(cepFlatReader* reader);

static bool cep_flat_reader_decode_chunk_key(const uint8_t* key,
                                             size_t key_size,
                                             size_t* base_size,
                                             uint64_t* ordinal) {
    if (!key || !key_size)
        return false;
    size_t idx = key_size;
    uint64_t value = 0u;
    unsigned shift = 0u;
    while (idx > 0u) {
        uint8_t byte = key[--idx];
        value |= ((uint64_t)(byte & 0x7Fu)) << shift;
        if ((byte & 0x80u) == 0u) {
            if (base_size)
                *base_size = idx;
            if (ordinal)
                *ordinal = value;
            return true;
        }
        shift += 7u;
        if (shift >= 64u)
            return false;
    }
    return false;
}

static void cep_flat_reader_clear_chunks(cepFlatReader* reader) {
    if (!reader)
        return;
    if (reader->chunk_trackers) {
        for (size_t i = 0; i < reader->chunk_tracker_count; ++i)
            cep_free(reader->chunk_trackers[i].key);
        cep_free(reader->chunk_trackers);
    }
    reader->chunk_trackers = NULL;
    reader->chunk_tracker_count = 0u;
    reader->chunk_tracker_capacity = 0u;
}

static void cep_flat_reader_clear_mini_toc(cepFlatReader* reader) {
    if (!reader)
        return;
    if (reader->mini_toc) {
        cep_free(reader->mini_toc);
    }
    reader->mini_toc = NULL;
    reader->mini_toc_capacity = 0u;
    reader->mini_toc_count = 0u;
}

static bool cep_flat_reader_mini_toc_reserve(cepFlatReader* reader, size_t count) {
    if (!reader)
        return false;
    if (count == 0u) {
        reader->mini_toc_count = 0u;
        return true;
    }
    if (reader->mini_toc_capacity < count) {
        cepFlatMiniTocEntry* grown = cep_realloc(reader->mini_toc, count * sizeof *grown);
        if (!grown)
            return false;
        reader->mini_toc = grown;
        reader->mini_toc_capacity = count;
    }
    reader->mini_toc_count = 0u;
    return true;
}

static cepFlatChunkTracker* cep_flat_reader_chunk_tracker_get(cepFlatReader* reader,
                                                              const uint8_t* base_key,
                                                              size_t base_key_size) {
    if (!reader || !base_key || !base_key_size)
        return NULL;
    for (size_t i = 0; i < reader->chunk_tracker_count; ++i) {
        cepFlatChunkTracker* tracker = &reader->chunk_trackers[i];
        if (tracker->key_size == base_key_size &&
            memcmp(tracker->key, base_key, base_key_size) == 0)
            return tracker;
    }
    if (reader->chunk_tracker_count == reader->chunk_tracker_capacity) {
        size_t new_cap = reader->chunk_tracker_capacity ? reader->chunk_tracker_capacity << 1u : 8u;
        cepFlatChunkTracker* grown = cep_realloc(reader->chunk_trackers, new_cap * sizeof *grown);
        if (!grown)
            return NULL;
        reader->chunk_trackers = grown;
        reader->chunk_tracker_capacity = new_cap;
    }
    cepFlatChunkTracker* tracker = &reader->chunk_trackers[reader->chunk_tracker_count++];
    memset(tracker, 0, sizeof *tracker);
    tracker->key = cep_malloc(base_key_size);
    if (!tracker->key) {
        reader->chunk_tracker_count--;
        return NULL;
    }
    memcpy(tracker->key, base_key, base_key_size);
    tracker->key_size = base_key_size;
    tracker->expected_offset = 0u;
    tracker->expected_ordinal = 0u;
    tracker->total_set = false;
    tracker->sealed = false;
    return tracker;
}

static bool cep_flat_reader_validate_chunk(cepFlatReader* reader,
                                           const uint8_t* key,
                                           size_t key_size,
                                           const uint8_t* body,
                                           size_t body_size) {
    if (!reader || !key || !body)
        return false;

    size_t base_size = 0u;
    uint64_t ordinal = 0u;
    if (!cep_flat_reader_decode_chunk_key(key, key_size, &base_size, &ordinal))
        return false;
    if (base_size == 0u)
        return false;

    cepFlatChunkTracker* tracker = cep_flat_reader_chunk_tracker_get(reader, key, base_size);
    if (!tracker)
        return false;
    if (tracker->sealed)
        return false;

    size_t offset = 0u;
    if (body_size < 1u)
        return false;
    uint8_t payload_kind = body[offset++];
    (void)payload_kind;

    uint64_t total_size = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &total_size))
        return false;
    uint64_t chunk_offset = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &chunk_offset))
        return false;
    uint64_t chunk_size = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &chunk_size))
        return false;
    if (chunk_size == 0u)
        return false;
    if (chunk_offset > total_size)
        return false;
    if (chunk_offset + chunk_size > total_size)
        return false;

    uint64_t fp_len = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &fp_len))
        return false;
    if (body_size - offset < fp_len)
        return false;
    offset += (size_t)fp_len;

    if (body_size - offset < 1u)
        return false;
    uint8_t aead_mode = body[offset++];
    if (aead_mode > CEP_FLAT_AEAD_XCHACHA20_POLY1305)
        return false;

    uint64_t nonce_len = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &nonce_len))
        return false;
    if (aead_mode == CEP_FLAT_AEAD_NONE) {
        if (nonce_len != 0u)
            return false;
    } else if (aead_mode == CEP_FLAT_AEAD_CHACHA20_POLY1305) {
        if (nonce_len != crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
            return false;
    } else if (aead_mode == CEP_FLAT_AEAD_XCHACHA20_POLY1305) {
        if (nonce_len != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
            return false;
    }
    if (body_size - offset < nonce_len + CEP_FLAT_HASH_SIZE)
        return false;
    offset += (size_t)nonce_len;
    offset += CEP_FLAT_HASH_SIZE;
    if (body_size - offset == 0u)
        return false;
    size_t remaining = body_size - offset;
    size_t expected_payload = (size_t)chunk_size;
    if (aead_mode == CEP_FLAT_AEAD_NONE) {
        if (remaining != expected_payload)
            return false;
    } else {
        size_t overhead = (aead_mode == CEP_FLAT_AEAD_CHACHA20_POLY1305)
                              ? crypto_aead_chacha20poly1305_ietf_ABYTES
                              : crypto_aead_xchacha20poly1305_ietf_ABYTES;
        if (remaining != expected_payload + overhead)
            return false;
    }

    if (!tracker->total_set) {
        tracker->total_size = total_size;
        tracker->total_set = true;
    } else if (tracker->total_size != total_size) {
        return false;
    }

    if (ordinal != tracker->expected_ordinal)
        return false;
    if (chunk_offset != tracker->expected_offset)
        return false;

    tracker->expected_ordinal += 1u;
    tracker->expected_offset += chunk_size;
    if (tracker->expected_offset > tracker->total_size)
        return false;
    if (tracker->expected_offset == tracker->total_size)
        tracker->sealed = true;

    return true;
}

static bool cep_flat_reader_finalize_chunks(cepFlatReader* reader) {
    if (!reader)
        return false;
    for (size_t i = 0; i < reader->chunk_tracker_count; ++i) {
        const cepFlatChunkTracker* tracker = &reader->chunk_trackers[i];
        if (!tracker->total_set)
            continue;
        if (!tracker->sealed)
            return false;
    }
    return true;
}

cepFlatSerializer* cep_flat_serializer_create(void) {
    cepFlatSerializer* serializer = cep_malloc0(sizeof *serializer);
    return serializer;
}

static uint32_t cep_flat_record_checksum(const uint8_t* data,
                                         size_t size,
                                         cepFlatChecksumAlgorithm algorithm) {
    bool castagnoli = (algorithm == CEP_FLAT_CHECKSUM_CRC32C);
    return cep_crc32c_compute_explicit(data, size, 0u, castagnoli);
}


/* Destroy a serializer instance, releasing any buffers and bookkeeping so the
   runtime does not leak memory when flat serialization is toggled on/off. */
void cep_flat_serializer_destroy(cepFlatSerializer* serializer) {
    if (!serializer)
        return;
    cep_free(serializer->frame.data);
    cep_free(serializer->digests);
    cep_free(serializer);
}

/* Reset the serializer so the next begin() call starts from a clean slate and
   the previous frame bytes (if any) can be reclaimed deterministically. */
void cep_flat_serializer_reset(cepFlatSerializer* serializer) {
    if (!serializer)
        return;
    serializer->frame.size = 0u;
    serializer->record_count = 0u;
    serializer->digest_count = 0u;
    serializer->frame_open = false;
}

/* Begin a new frame with the supplied configuration so subsequent record
   emissions follow the requested merge semantics and capability flags. */
bool cep_flat_serializer_begin(cepFlatSerializer* serializer, const cepFlatFrameConfig* config) {
    if (!serializer || serializer->frame_open)
        return false;

    cep_flat_serializer_reset(serializer);

    serializer->frame_open = true;
    serializer->config.apply_mode = config ? config->apply_mode : CEP_FLAT_APPLY_INSERT_ONLY;
    serializer->config.beat_number = config ? config->beat_number : 0u;
    serializer->config.capability_flags = config ? config->capability_flags : 0u;
    serializer->config.hash_algorithm = config ? config->hash_algorithm : CEP_FLAT_HASH_BLAKE3_256;
    serializer->config.compression_algorithm = config ? config->compression_algorithm : CEP_FLAT_COMPRESSION_NONE;
    serializer->config.checksum_algorithm = config ? config->checksum_algorithm : CEP_FLAT_CHECKSUM_CRC32;
    serializer->config.payload_history_beats = config ? config->payload_history_beats : 0u;
    serializer->config.manifest_history_beats = config ? config->manifest_history_beats : 0u;
    serializer->config.branch_info_present = config ? config->branch_info_present : false;
    serializer->config.branch_glob = config ? config->branch_glob : 0u;
    serializer->config.branch_domain = config ? config->branch_domain : 0u;
    serializer->config.branch_tag = config ? config->branch_tag : 0u;
    serializer->config.branch_frame_id = config ? config->branch_frame_id : 0u;

    if (serializer->config.hash_algorithm != CEP_FLAT_HASH_BLAKE3_256)
        return false;
    if (serializer->config.checksum_algorithm != CEP_FLAT_CHECKSUM_CRC32 &&
        serializer->config.checksum_algorithm != CEP_FLAT_CHECKSUM_CRC32C)
        return false;
    if (serializer->config.compression_algorithm != CEP_FLAT_COMPRESSION_NONE &&
        serializer->config.compression_algorithm != CEP_FLAT_COMPRESSION_DEFLATE)
        return false;

    return true;
}

/* Append a single record to the frame, copying the caller-supplied key/body
   slices and tracking the digest so the frame trailer can certify integrity. */
bool cep_flat_serializer_emit(cepFlatSerializer* serializer, const cepFlatRecordSpec* record) {
    if (!serializer || !serializer->frame_open || !record)
        return false;
    return cep_flat_append_record(serializer, record, true);
}

/* Finalize the frame by emitting the trailer record, optionally streaming the
   contiguous byte buffer to the provided sink, and keeping the bytes available
   for callers that want to reuse the in-memory frame. */
bool cep_flat_serializer_finish(cepFlatSerializer* serializer,
                                cepSerializationWriteFn sink,
                                void* context) {
    if (!serializer || !serializer->frame_open)
        return false;

    if (serializer->config.compression_algorithm != CEP_FLAT_COMPRESSION_NONE)
        serializer->config.capability_flags |= CEP_FLAT_CAP_FRAME_COMPRESSION;

    uint8_t merkle_root[CEP_FLAT_HASH_SIZE];
    cep_flat_compute_merkle(serializer, merkle_root);

    if (!cep_flat_emit_trailer(serializer, merkle_root))
        return false;

    if (!cep_flat_serializer_apply_compression(serializer))
        return false;

    serializer->frame_open = false;

    if (sink) {
        if (!sink(context, serializer->frame.data, serializer->frame.size))
            return false;
    }
    return true;
}

/* Report the current serialized frame size so tooling can size buffers without
   touching internal structures. */
size_t cep_flat_serializer_frame_size(const cepFlatSerializer* serializer) {
    if (!serializer)
        return 0u;
    return serializer->frame.size;
}

/* Return a pointer to the in-memory frame so callers can transmit or persist it
   without invoking the sink path. */
bool cep_flat_serializer_frame_bytes(const cepFlatSerializer* serializer,
                                     const uint8_t** data,
                                     size_t* size) {
    if (!serializer || !data || !size)
        return false;
    *data = serializer->frame.data;
    *size = serializer->frame.size;
    return true;
}

void cep_flat_serializer_add_caps(cepFlatSerializer* serializer, uint32_t caps) {
    if (!serializer)
        return;
    serializer->config.capability_flags |= caps;
}

static size_t cep_flat_varint_length(uint64_t value) {
    size_t length = 1u;
    while (value >= 0x80u) {
        value >>= 7u;
        length++;
    }
    return length;
}

static uint8_t* cep_flat_write_varint(uint64_t value, uint8_t* dst) {
    do {
        uint8_t byte = (uint8_t)(value & 0x7Fu);
        value >>= 7u;
        if (value)
            byte |= 0x80u;
        *dst++ = byte;
    } while (value);
    return dst;
}

static bool cep_flat_read_varint(const uint8_t* data, size_t size, size_t* offset, uint64_t* out_value) {
    if (!data || !offset || !out_value)
        return false;
    uint64_t value = 0u;
    unsigned shift = 0u;
    size_t cursor = *offset;
    while (cursor < size) {
        uint8_t byte = data[cursor++];
        value |= ((uint64_t)(byte & 0x7Fu)) << shift;
        if (!(byte & 0x80u))
            break;
        shift += 7u;
        if (shift >= 64u)
            return false;
    }
    if (cursor > size)
        return false;
    *offset = cursor;
    *out_value = value;
    return true;
}

static void cep_flat_hash_bytes(const uint8_t* bytes, size_t size, uint8_t out[CEP_FLAT_HASH_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (bytes && size)
        blake3_hasher_update(&hasher, bytes, size);
    blake3_hasher_finalize(&hasher, out, CEP_FLAT_HASH_SIZE);
}

static void cep_flat_hash_pair(const uint8_t* lhs, const uint8_t* rhs, uint8_t out[CEP_FLAT_HASH_SIZE]) {
    uint8_t buffer[CEP_FLAT_HASH_SIZE * 2u];
    memcpy(buffer, lhs, CEP_FLAT_HASH_SIZE);
    memcpy(buffer + CEP_FLAT_HASH_SIZE, rhs, CEP_FLAT_HASH_SIZE);
    cep_flat_hash_bytes(buffer, sizeof buffer, out);
}

static bool cep_flat_reader_verify_checksums(cepFlatReader* reader) {
    if (!reader)
        return false;
    cepFlatChecksumAlgorithm algorithm = reader->frame.checksum_algorithm;
    if (algorithm != CEP_FLAT_CHECKSUM_CRC32 && algorithm != CEP_FLAT_CHECKSUM_CRC32C)
        return false;
    for (size_t i = 0; i < reader->digest_count; ++i) {
        const cepFlatDigestEntry* entry = &reader->digests[i];
        const uint8_t* record = reader->buffer.data + entry->record_offset;
        uint32_t actual = cep_flat_record_checksum(record, entry->record_size, algorithm);
        if (actual != entry->checksum)
            return false;
    }
    if (reader->trailer_record_size) {
        const uint8_t* trailer = reader->buffer.data + reader->trailer_record_offset;
        uint32_t trailer_actual = cep_flat_record_checksum(trailer,
                                                           reader->trailer_record_size,
                                                           algorithm);
        if (trailer_actual != reader->trailer_checksum)
            return false;
    }
    return true;
}

static bool cep_flat_buffer_reserve(cepFlatBuffer* buffer, size_t extra) {
    if (!buffer)
        return false;
    size_t required = buffer->size + extra;
    if (required <= buffer->capacity)
        return true;
    size_t new_capacity = buffer->capacity ? buffer->capacity : 1024u;
    while (new_capacity < required) {
        new_capacity *= 2u;
    }
    buffer->data = cep_realloc(buffer->data, new_capacity);
    buffer->capacity = new_capacity;
    return true;
}

static bool cep_flat_digest_reserve(cepFlatSerializer* serializer) {
    if (!serializer)
        return false;
    if (serializer->digest_count < serializer->digest_capacity)
        return true;
    size_t new_capacity = serializer->digest_capacity ? serializer->digest_capacity * 2u : 16u;
    serializer->digests = cep_realloc(serializer->digests, new_capacity * sizeof *serializer->digests);
    serializer->digest_capacity = new_capacity;
    return true;
}

static bool cep_flat_reader_digest_reserve(cepFlatReader* reader) {
    if (!reader)
        return false;
    if (reader->digest_count < reader->digest_capacity)
        return true;
    size_t new_capacity = reader->digest_capacity ? reader->digest_capacity * 2u : 16u;
    reader->digests = cep_realloc(reader->digests, new_capacity * sizeof *reader->digests);
    reader->digest_capacity = new_capacity;
    return true;
}

static bool cep_flat_reader_record_reserve(cepFlatReader* reader) {
    if (!reader)
        return false;
    if (reader->record_count < reader->record_capacity)
        return true;
    size_t new_capacity = reader->record_capacity ? reader->record_capacity * 2u : 32u;
    reader->records = cep_realloc(reader->records, new_capacity * sizeof *reader->records);
    reader->record_capacity = new_capacity;
    return true;
}

static size_t cep_flat_container_header_size(void) {
    return sizeof(uint32_t) + 4u + sizeof(uint64_t) * 2u;
}

static void cep_flat_container_write_header(uint8_t* dst,
                                            cepFlatCompressionAlgorithm compression,
                                            cepFlatChecksumAlgorithm checksum,
                                            uint64_t raw_size,
                                            uint64_t compressed_size) {
    uint32_t magic = CEP_FLAT_CONTAINER_MAGIC;
    memcpy(dst, &magic, sizeof magic);
    dst += sizeof magic;
    *dst++ = CEP_FLAT_CONTAINER_VERSION;
    *dst++ = (uint8_t)compression;
    *dst++ = (uint8_t)checksum;
    *dst++ = 0u;
    memcpy(dst, &raw_size, sizeof raw_size);
    dst += sizeof raw_size;
    memcpy(dst, &compressed_size, sizeof compressed_size);
}

static bool cep_flat_serializer_apply_deflate(cepFlatSerializer* serializer) {
    size_t raw_size = serializer->frame.size;
    size_t header_size = cep_flat_container_header_size();
    cepFlatBuffer container = {0};

    if (!cep_flat_buffer_reserve(&container, header_size))
        return false;
    container.size = header_size;

    uLongf max_size = compressBound((uLong)raw_size);
    if (!cep_flat_buffer_reserve(&container, max_size))
        goto fail;

    uLongf compressed_len = max_size;
    int rc = compress2(container.data + header_size,
                       &compressed_len,
                       serializer->frame.data,
                       (uLong)raw_size,
                       Z_BEST_SPEED);
    if (rc != Z_OK)
        goto fail;

    container.size = header_size + (size_t)compressed_len;
    cep_flat_container_write_header(container.data,
                                    serializer->config.compression_algorithm,
                                    serializer->config.checksum_algorithm,
                                    (uint64_t)raw_size,
                                    (uint64_t)compressed_len);

    cep_free(serializer->frame.data);
    serializer->frame = container;
    return true;

fail:
    cep_free(container.data);
    return false;
}

static bool cep_flat_serializer_apply_compression(cepFlatSerializer* serializer) {
    if (!serializer)
        return false;
    switch (serializer->config.compression_algorithm) {
      case CEP_FLAT_COMPRESSION_NONE:
        return true;
      case CEP_FLAT_COMPRESSION_DEFLATE:
        return cep_flat_serializer_apply_deflate(serializer);
      default:
        return false;
    }
}

static bool cep_flat_reader_prepare_buffer(cepFlatReader* reader) {
    if (!reader)
        return false;

    size_t header_size = cep_flat_container_header_size();
    if (reader->buffer.size < header_size)
        return true;

    const uint8_t* base = reader->buffer.data;
    uint32_t magic = 0u;
    memcpy(&magic, base, sizeof magic);
    if (magic != CEP_FLAT_CONTAINER_MAGIC)
        return true;

    const uint8_t* cursor = base + sizeof magic;
    uint8_t version = *cursor++;
    uint8_t compression = *cursor++;
    uint8_t checksum = *cursor++;
    cursor++; /* reserved */

    uint64_t raw_size = 0u;
    uint64_t compressed_size = 0u;
    memcpy(&raw_size, cursor, sizeof raw_size);
    cursor += sizeof raw_size;
    memcpy(&compressed_size, cursor, sizeof compressed_size);

    if (version != CEP_FLAT_CONTAINER_VERSION)
        return false;
    if (compression != CEP_FLAT_COMPRESSION_DEFLATE)
        return false;
    if (checksum != CEP_FLAT_CHECKSUM_CRC32 && checksum != CEP_FLAT_CHECKSUM_CRC32C)
        return false;
    if (raw_size > SIZE_MAX || compressed_size > SIZE_MAX)
        return false;

    size_t total_needed = header_size + (size_t)compressed_size;
    if (reader->buffer.size < total_needed)
        return false;

    cepFlatBuffer decompressed = {0};
    if (!cep_flat_buffer_reserve(&decompressed, (size_t)raw_size)) {
        cep_free(decompressed.data);
        return false;
    }
    decompressed.size = (size_t)raw_size;

    uLongf dest_len = (uLongf)raw_size;
    int rc = uncompress(decompressed.data,
                        &dest_len,
                        base + header_size,
                        (uLongf)compressed_size);
    if (rc != Z_OK || dest_len != raw_size) {
        cep_free(decompressed.data);
        return false;
    }

    cep_free(reader->buffer.data);
    reader->buffer = decompressed;
    reader->frame.compression_algorithm = (cepFlatCompressionAlgorithm)compression;
    reader->frame.checksum_algorithm = (cepFlatChecksumAlgorithm)checksum;
    return true;
}

static bool cep_flat_append_record(cepFlatSerializer* serializer,
                                   const cepFlatRecordSpec* spec,
                                   bool track_digest) {
    if (!serializer || !spec)
        return false;

    size_t key_len = spec->key.size;
    size_t body_len = spec->body.size;
    size_t header_size = 1u + 1u + 2u +
                         cep_flat_varint_length(key_len) +
                         cep_flat_varint_length(body_len);

    size_t payload_size = header_size + key_len + body_len;
    size_t total_size = payload_size + sizeof(uint32_t);

    if (!cep_flat_buffer_reserve(&serializer->frame, total_size))
        return false;

    uint8_t* dst = serializer->frame.data + serializer->frame.size;
    size_t record_offset = serializer->frame.size;

    uint8_t* cursor = dst;
    *cursor++ = spec->type;
    *cursor++ = spec->version ? spec->version : CEP_FLAT_SERIALIZER_VERSION;

    uint16_t flags = spec->flags;
    memcpy(cursor, &flags, sizeof flags);
    cursor += sizeof flags;

    cursor = cep_flat_write_varint(key_len, cursor);
    cursor = cep_flat_write_varint(body_len, cursor);

    uint8_t* key_ptr = cursor;
    if (key_len && spec->key.data) {
        memcpy(cursor, spec->key.data, key_len);
    } else if (key_len) {
        memset(cursor, 0, key_len);
    }
    cursor += key_len;

    if (body_len && spec->body.data) {
        memcpy(cursor, spec->body.data, body_len);
    } else if (body_len) {
        memset(cursor, 0, body_len);
    }
    cursor += body_len;

    uint32_t checksum = cep_flat_record_checksum(dst, payload_size, serializer->config.checksum_algorithm);
    memcpy(cursor, &checksum, sizeof checksum);

    serializer->frame.size += total_size;

    if (track_digest) {
        if (!cep_flat_digest_reserve(serializer))
            return false;
        cepFlatDigestEntry* entry = &serializer->digests[serializer->digest_count++];
        entry->key_offset = (size_t)(key_ptr - serializer->frame.data);
        entry->key_size = key_len;
        entry->record_offset = record_offset;
        entry->record_size = payload_size;
        entry->checksum = checksum;
        cep_flat_hash_bytes(dst, payload_size, entry->hash);
        entry->record_type = spec->type;
        serializer->record_count++;
    }

    return true;
}

static bool cep_flat_emit_trailer(cepFlatSerializer* serializer,
                                  const uint8_t merkle_root[CEP_FLAT_HASH_SIZE]) {
    if (!serializer)
        return false;

    cepFlatBuffer body = {0};

#define APPEND_BYTES(ptr, len)                                                        \
    do {                                                                              \
        size_t __len = (size_t)(len);                                                 \
        if (!cep_flat_buffer_reserve(&body, __len))                                   \
            goto fail;                                                                \
        memcpy(body.data + body.size, (ptr), __len);                                  \
        body.size += __len;                                                           \
    } while (0)

#define APPEND_U8(value)                                                              \
    do {                                                                              \
        if (!cep_flat_buffer_reserve(&body, 1u))                                      \
            goto fail;                                                                \
        body.data[body.size++] = (uint8_t)(value);                                    \
    } while (0)

#define APPEND_VARINT(value)                                                          \
    do {                                                                              \
        size_t __len = cep_flat_varint_length((uint64_t)(value));                     \
        if (!cep_flat_buffer_reserve(&body, __len))                                   \
            goto fail;                                                                \
        cep_flat_write_varint((uint64_t)(value), body.data + body.size);              \
        body.size += __len;                                                           \
    } while (0)

    uint32_t magic = CEP_FLAT_MAGIC;
    APPEND_BYTES(&magic, sizeof magic);
    APPEND_U8(CEP_FLAT_SERIALIZER_VERSION);
    APPEND_VARINT(serializer->config.beat_number);
    APPEND_VARINT(serializer->record_count);
    APPEND_U8((uint8_t)serializer->config.apply_mode);
    APPEND_U8((uint8_t)serializer->config.hash_algorithm);
    APPEND_U8((uint8_t)serializer->config.compression_algorithm);
    APPEND_U8((uint8_t)serializer->config.checksum_algorithm);
    APPEND_VARINT(CEP_FLAT_HASH_SIZE);
    APPEND_BYTES(merkle_root, CEP_FLAT_HASH_SIZE);

    size_t mini_toc_count = serializer->digest_count;
    if (mini_toc_count)
        cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_FRAME_TOC);
    APPEND_VARINT(mini_toc_count);
    for (size_t i = 0; i < mini_toc_count; ++i) {
        const cepFlatDigestEntry* entry = &serializer->digests[i];
        const uint8_t* key = serializer->frame.data + entry->key_offset;
        APPEND_U8(entry->record_type);
        APPEND_VARINT(entry->key_size);
        APPEND_BYTES(key, entry->key_size);
        APPEND_VARINT(entry->record_offset);
    }

    APPEND_VARINT(serializer->config.payload_history_beats);
    APPEND_VARINT(serializer->config.manifest_history_beats);

    uint32_t caps = serializer->config.capability_flags;
    if (serializer->config.branch_info_present)
        caps |= CEP_FLAT_CAP_BRANCH_METADATA;
    APPEND_BYTES(&caps, sizeof caps);
    if (serializer->config.branch_info_present) {
        uint8_t branch_payload[CEP_FLAT_BRANCH_METADATA_BYTES];
        uint8_t* branch_cursor = branch_payload;
        *branch_cursor++ = serializer->config.branch_glob ? 1u : 0u;
        memcpy(branch_cursor, &serializer->config.branch_domain, sizeof serializer->config.branch_domain);
        branch_cursor += sizeof serializer->config.branch_domain;
        memcpy(branch_cursor, &serializer->config.branch_tag, sizeof serializer->config.branch_tag);
        branch_cursor += sizeof serializer->config.branch_tag;
        memcpy(branch_cursor, &serializer->config.branch_frame_id, sizeof serializer->config.branch_frame_id);
        branch_cursor += sizeof serializer->config.branch_frame_id;
        size_t branch_len = (size_t)(branch_cursor - branch_payload);
        APPEND_VARINT(branch_len);
        APPEND_BYTES(branch_payload, branch_len);
    }

#undef APPEND_BYTES
#undef APPEND_U8
#undef APPEND_VARINT

    cepFlatRecordSpec trailer = {
        .type = CEP_FLAT_RECORD_FRAME_TRAILER,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0u,
        .key = {.data = NULL, .size = 0u},
        .body = {.data = body.data, .size = body.size},
    };

    if (!cep_flat_append_record(serializer, &trailer, false))
        goto fail;
    cep_free(body.data);
    return true;

fail:
    cep_free(body.data);
    return false;
}

static int cep_flat_digest_leaf_cmp(const void* lhs, const void* rhs) {
    const cepFlatDigestLeaf* a = lhs;
    const cepFlatDigestLeaf* b = rhs;
    size_t min_len = a->key_size < b->key_size ? a->key_size : b->key_size;
    int cmp = memcmp(a->key, b->key, min_len);
    if (cmp)
        return cmp;
    if (a->key_size < b->key_size)
        return -1;
    if (a->key_size > b->key_size)
        return 1;
    return 0;
}

static void cep_flat_build_merkle(const uint8_t* base,
                                  const cepFlatDigestEntry* digests,
                                  size_t digest_count,
                                  uint8_t merkle_root[CEP_FLAT_HASH_SIZE]) {
    if (!merkle_root) {
        return;
    }

    if (!base || !digests || digest_count == 0u) {
        memset(merkle_root, 0, CEP_FLAT_HASH_SIZE);
        return;
    }

    size_t leaf_count = digest_count;
    cepFlatDigestLeaf* leaves = cep_malloc0(sizeof *leaves * leaf_count);
    for (size_t i = 0; i < leaf_count; ++i) {
        const cepFlatDigestEntry* entry = &digests[i];
        leaves[i].key = base + entry->key_offset;
        leaves[i].key_size = entry->key_size;
        memcpy(leaves[i].hash, entry->hash, CEP_FLAT_HASH_SIZE);
    }

    qsort(leaves, leaf_count, sizeof *leaves, cep_flat_digest_leaf_cmp);

    uint8_t* current = cep_malloc(leaf_count * CEP_FLAT_HASH_SIZE);
    uint8_t* next = cep_malloc(leaf_count * CEP_FLAT_HASH_SIZE);
    for (size_t i = 0; i < leaf_count; ++i) {
        memcpy(current + i * CEP_FLAT_HASH_SIZE, leaves[i].hash, CEP_FLAT_HASH_SIZE);
    }

    size_t level_count = leaf_count;
    while (level_count > 1u) {
        size_t next_count = (level_count + 1u) / 2u;
        for (size_t i = 0; i < next_count; ++i) {
            const uint8_t* left = current + (i * 2u) * CEP_FLAT_HASH_SIZE;
            const uint8_t* right = (i * 2u + 1u < level_count)
                                       ? left + CEP_FLAT_HASH_SIZE
                                       : left;
            cep_flat_hash_pair(left, right, next + i * CEP_FLAT_HASH_SIZE);
        }
        uint8_t* tmp = current;
        current = next;
        next = tmp;
        level_count = next_count;
    }

    memcpy(merkle_root, current, CEP_FLAT_HASH_SIZE);

    cep_free(leaves);
    cep_free(current);
    cep_free(next);
}

static void cep_flat_compute_merkle(const cepFlatSerializer* serializer,
                                    uint8_t merkle_root[CEP_FLAT_HASH_SIZE]) {
    if (!serializer) {
        if (merkle_root)
            memset(merkle_root, 0, CEP_FLAT_HASH_SIZE);
        return;
    }
    cep_flat_build_merkle(serializer->frame.data,
                          serializer->digests,
                          serializer->digest_count,
                          merkle_root);
}

/* -- Reader implementation ------------------------------------------------- */

cepFlatReader* cep_flat_reader_create(void) {
    return cep_malloc0(sizeof(cepFlatReader));
}

void cep_flat_reader_destroy(cepFlatReader* reader) {
    if (!reader)
        return;
    cep_free(reader->buffer.data);
    cep_free(reader->records);
    cep_free(reader->digests);
    cep_flat_reader_clear_chunks(reader);
    cep_flat_reader_clear_mini_toc(reader);
    cep_free(reader);
}

void cep_flat_reader_reset(cepFlatReader* reader) {
    if (!reader)
        return;
    reader->buffer.size = 0u;
    reader->record_count = 0u;
    reader->digest_count = 0u;
    cep_flat_reader_clear_chunks(reader);
    cep_flat_reader_clear_mini_toc(reader);
    reader->committed = false;
    reader->trailer_verified = false;
    reader->trailer_record_count = 0u;
    reader->trailer_record_offset = 0u;
    reader->trailer_record_size = 0u;
    reader->trailer_checksum = 0u;
    memset(reader->trailer_merkle, 0, sizeof reader->trailer_merkle);
    reader->frame.beat_number = 0u;
    reader->frame.apply_mode = CEP_FLAT_APPLY_INSERT_ONLY;
    reader->frame.capability_flags = 0u;
    reader->frame.hash_algorithm = CEP_FLAT_HASH_BLAKE3_256;
    reader->frame.compression_algorithm = CEP_FLAT_COMPRESSION_NONE;
    reader->frame.checksum_algorithm = CEP_FLAT_CHECKSUM_CRC32;
    reader->frame.payload_history_beats = 0u;
    reader->frame.manifest_history_beats = 0u;
}

bool cep_flat_reader_feed(cepFlatReader* reader, const uint8_t* chunk, size_t size) {
    if (!reader || !chunk || !size || reader->committed)
        return false;
    if (!cep_flat_buffer_reserve(&reader->buffer, size))
        return false;
    memcpy(reader->buffer.data + reader->buffer.size, chunk, size);
    reader->buffer.size += size;
    return true;
}

bool cep_flat_reader_commit(cepFlatReader* reader) {
    if (!reader || reader->committed)
        return false;
    if (!cep_flat_reader_parse(reader))
        return false;
    reader->committed = true;
    return true;
}

bool cep_flat_reader_ready(const cepFlatReader* reader) {
    return reader && reader->committed;
}

const cepFlatRecordView* cep_flat_reader_records(const cepFlatReader* reader, size_t* count) {
    if (!reader || !reader->committed) {
        if (count)
            *count = 0u;
        return NULL;
    }
    if (count)
        *count = reader->record_count;
    return reader->records;
}

const cepFlatFrameConfig* cep_flat_reader_frame(const cepFlatReader* reader) {
    if (!reader || !reader->committed)
        return NULL;
    return &reader->frame;
}

const uint8_t* cep_flat_reader_merkle_root(const cepFlatReader* reader) {
    if (!reader || !reader->committed)
        return NULL;
    return reader->trailer_merkle;
}

const cepFlatMiniTocEntry* cep_flat_reader_mini_toc(const cepFlatReader* reader, size_t* count) {
    if (!reader || !reader->committed) {
        if (count)
            *count = 0u;
        return NULL;
    }
    if (count)
        *count = reader->mini_toc_count;
    return reader->mini_toc;
}

static bool cep_flat_reader_parse(cepFlatReader* reader) {
    if (!reader)
        return false;

    if (!cep_flat_reader_prepare_buffer(reader))
        return false;

    size_t offset = 0u;
    reader->record_count = 0u;
    reader->digest_count = 0u;
    reader->trailer_verified = false;
    reader->trailer_record_count = 0u;
    reader->trailer_record_offset = 0u;
    reader->trailer_record_size = 0u;
    reader->trailer_checksum = 0u;

    bool trailer_seen = false;

    while (offset < reader->buffer.size) {
        if (reader->buffer.size - offset < 4u)
            return false;

        size_t record_start = offset;
        const uint8_t* data = reader->buffer.data;

        uint8_t type = data[offset++];
        uint8_t version = data[offset++];

        uint16_t flags = 0u;
        memcpy(&flags, data + offset, sizeof flags);
        offset += sizeof flags;

        uint64_t key_len_u64 = 0u;
        if (!cep_flat_read_varint(data, reader->buffer.size, &offset, &key_len_u64))
            return false;
        if (key_len_u64 > SIZE_MAX)
            return false;
        size_t key_length = (size_t)key_len_u64;

        uint64_t body_len_u64 = 0u;
        if (!cep_flat_read_varint(data, reader->buffer.size, &offset, &body_len_u64))
            return false;
        if (body_len_u64 > SIZE_MAX)
            return false;
        size_t body_length = (size_t)body_len_u64;

        size_t payload_offset = offset;
        size_t needed = key_length + body_length + sizeof(uint32_t);
        if (reader->buffer.size - payload_offset < needed)
            return false;

        const uint8_t* key_ptr = data + offset;
        offset += key_length;

        const uint8_t* body_ptr = data + offset;
        offset += body_length;

        size_t payload_size = offset - record_start;

        uint32_t crc_expected = 0u;
        memcpy(&crc_expected, data + offset, sizeof crc_expected);
        offset += sizeof crc_expected;

        if (type == CEP_FLAT_RECORD_FRAME_TRAILER) {
            if (trailer_seen)
                return false;
            trailer_seen = true;
            reader->trailer_record_offset = record_start;
            reader->trailer_record_size = payload_size;
            reader->trailer_checksum = crc_expected;
            if (!cep_flat_reader_parse_trailer(reader, body_ptr, body_length))
                return false;
            if (offset != reader->buffer.size)
                return false;
            break;
        }

        if (type == CEP_FLAT_RECORD_PAYLOAD_CHUNK) {
            if (!cep_flat_reader_validate_chunk(reader, key_ptr, key_length, body_ptr, body_length))
                return false;
        }

        if (!cep_flat_reader_record_reserve(reader))
            return false;
        if (!cep_flat_reader_digest_reserve(reader))
            return false;

        cepFlatRecordView* view = &reader->records[reader->record_count++];
        view->type = type;
        view->version = version;
        view->flags = flags;
        view->key.data = key_ptr;
        view->key.size = key_length;
        view->body.data = body_ptr;
        view->body.size = body_length;

        cepFlatDigestEntry* entry = &reader->digests[reader->digest_count++];
        entry->key_offset = (size_t)(key_ptr - reader->buffer.data);
        entry->key_size = key_length;
        entry->record_offset = record_start;
        entry->record_size = payload_size;
        entry->checksum = crc_expected;
        cep_flat_hash_bytes(data + record_start, payload_size, entry->hash);
    }

    if (!trailer_seen)
        return false;

    if (!reader->trailer_verified)
        return false;

    if (!cep_flat_reader_verify_checksums(reader))
        return false;

    if (reader->digest_count != reader->trailer_record_count)
        return false;
    if (!cep_flat_reader_finalize_chunks(reader))
        return false;

    uint8_t merkle[CEP_FLAT_HASH_SIZE];
    cep_flat_build_merkle(reader->buffer.data,
                          reader->digests,
                          reader->digest_count,
                          merkle);
    if (memcmp(merkle, reader->trailer_merkle, CEP_FLAT_HASH_SIZE) != 0)
        return false;

    return true;
}

static bool cep_flat_reader_parse_trailer(cepFlatReader* reader, const uint8_t* body, size_t body_size) {
    if (!reader || !body)
        return false;

    size_t offset = 0u;
    if (body_size - offset < sizeof(uint32_t))
        return false;

    uint32_t magic = 0u;
    memcpy(&magic, body + offset, sizeof magic);
    offset += sizeof magic;
    if (magic != CEP_FLAT_MAGIC)
        return false;

    if (body_size - offset < 1u)
        return false;
    uint8_t version = body[offset++];
    if (version != CEP_FLAT_SERIALIZER_VERSION)
        return false;

    uint64_t beat_number = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &beat_number))
        return false;

    uint64_t record_count = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &record_count))
        return false;
    if (record_count > UINT32_MAX)
        return false;

    if (body_size - offset < 1u)
        return false;
    uint8_t apply_mode = body[offset++];
    if (apply_mode > CEP_FLAT_APPLY_UPSERT_WITH_CAS)
        return false;

    if (body_size - offset < 1u)
        return false;
    uint8_t hash_alg = body[offset++];
    if (hash_alg != CEP_FLAT_HASH_BLAKE3_256)
        return false;
    if (body_size - offset < 1u)
        return false;
    uint8_t compression = body[offset++];
    if (compression > CEP_FLAT_COMPRESSION_DEFLATE)
        return false;
    if (reader->frame.compression_algorithm != CEP_FLAT_COMPRESSION_NONE &&
        reader->frame.compression_algorithm != compression)
        return false;
    reader->frame.compression_algorithm = (cepFlatCompressionAlgorithm)compression;
    if (body_size - offset < 1u)
        return false;
    uint8_t checksum = body[offset++];
    if (checksum != CEP_FLAT_CHECKSUM_CRC32 && checksum != CEP_FLAT_CHECKSUM_CRC32C)
        return false;
    reader->frame.checksum_algorithm = (cepFlatChecksumAlgorithm)checksum;

    uint64_t root_len = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &root_len))
        return false;
    if (root_len != CEP_FLAT_HASH_SIZE)
        return false;
    if (body_size - offset < root_len)
        return false;
    memcpy(reader->trailer_merkle, body + offset, (size_t)root_len);
    offset += (size_t)root_len;

    uint64_t mini_toc = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &mini_toc))
        return false;
    if (mini_toc > SIZE_MAX)
        return false;
    if (!cep_flat_reader_mini_toc_reserve(reader, (size_t)mini_toc))
        return false;
    for (uint64_t i = 0; i < mini_toc; ++i) {
        if (body_size - offset < 1u)
            return false;
        uint8_t entry_type = body[offset++];
        uint64_t prefix_len = 0u;
        if (!cep_flat_read_varint(body, body_size, &offset, &prefix_len))
            return false;
        if (body_size - offset < prefix_len)
            return false;
        size_t prefix_size = (size_t)prefix_len;
        const uint8_t* prefix_ptr = body + offset;
        offset += prefix_size;
        uint64_t first_offset = 0u;
        if (!cep_flat_read_varint(body, body_size, &offset, &first_offset))
            return false;
        cepFlatMiniTocEntry* entry = &reader->mini_toc[reader->mini_toc_count++];
        entry->record_type = entry_type;
        entry->key_prefix.data = prefix_ptr;
        entry->key_prefix.size = prefix_size;
        entry->record_offset = first_offset;
    }

    uint64_t payload_history = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &payload_history))
        return false;
    if (payload_history > UINT32_MAX)
        return false;
    reader->frame.payload_history_beats = (uint32_t)payload_history;

    uint64_t manifest_history = 0u;
    if (!cep_flat_read_varint(body, body_size, &offset, &manifest_history))
        return false;
    if (manifest_history > UINT32_MAX)
        return false;
    reader->frame.manifest_history_beats = (uint32_t)manifest_history;

    if (body_size - offset < sizeof(uint32_t))
        return false;
    uint32_t caps = 0u;
    memcpy(&caps, body + offset, sizeof caps);
    offset += sizeof caps;

    reader->frame.branch_info_present = false;
    reader->frame.branch_domain = 0u;
    reader->frame.branch_tag = 0u;
    reader->frame.branch_glob = 0u;
    reader->frame.branch_frame_id = 0u;
    if ((caps & CEP_FLAT_CAP_BRANCH_METADATA) != 0u) {
        uint64_t branch_len = 0u;
        if (!cep_flat_read_varint(body, body_size, &offset, &branch_len))
            return false;
        if (branch_len != CEP_FLAT_BRANCH_METADATA_BYTES)
            return false;
        if (body_size - offset < branch_len)
            return false;
        const uint8_t* branch_ptr = body + offset;
        offset += (size_t)branch_len;
        reader->frame.branch_info_present = true;
        reader->frame.branch_glob = branch_ptr[0];
        branch_ptr += 1u;
        memcpy(&reader->frame.branch_domain, branch_ptr, sizeof reader->frame.branch_domain);
        branch_ptr += sizeof reader->frame.branch_domain;
        memcpy(&reader->frame.branch_tag, branch_ptr, sizeof reader->frame.branch_tag);
        branch_ptr += sizeof reader->frame.branch_tag;
        memcpy(&reader->frame.branch_frame_id, branch_ptr, sizeof reader->frame.branch_frame_id);
    }

    if (offset != body_size)
        return false;

    reader->frame.beat_number = beat_number;
    reader->frame.apply_mode = (cepFlatApplyMode)apply_mode;
    reader->frame.hash_algorithm = (cepFlatHashAlgorithm)hash_alg;
    reader->frame.capability_flags = caps;
    reader->trailer_record_count = (uint32_t)record_count;
    reader->trailer_verified = true;
    return true;
}
