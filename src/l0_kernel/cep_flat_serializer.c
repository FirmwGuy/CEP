/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_flat_serializer.h"
#include "cep_molecule.h"
#include "cep_crc32c.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define CEP_FLAT_MAGIC UINT32_C(0x43455046)
#define CEP_FLAT_CONTAINER_MAGIC  UINT32_C(0x43464C54) /* 'CFLT' */
#define CEP_FLAT_CONTAINER_VERSION 1u

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
    uint8_t hash[CEP_FLAT_HASH_SIZE];
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
    bool                committed;
    bool                trailer_verified;
    uint8_t             trailer_merkle[CEP_FLAT_HASH_SIZE];
    uint32_t            trailer_record_count;
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


static size_t cep_flat_varint_length(uint64_t value);
static uint8_t* cep_flat_write_varint(uint64_t value, uint8_t* dst);
static bool cep_flat_read_varint(const uint8_t* data, size_t size, size_t* offset, uint64_t* out_value);

cepFlatSerializer* cep_flat_serializer_create(void) {
    cepFlatSerializer* serializer = cep_malloc0(sizeof *serializer);
    return serializer;
}

static uint32_t cep_flat_record_crc(const uint8_t* data, size_t size) {
    return cep_crc32c(data, size, 0u);
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

    if (serializer->config.hash_algorithm != CEP_FLAT_HASH_BLAKE3_256)
        return false;
    if (serializer->config.checksum_algorithm != CEP_FLAT_CHECKSUM_CRC32)
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

/* TODO: replace this FNV-derived hash with a true BLAKE3 implementation once
   the dependency lands; the placeholder keeps record hashing deterministic so
   Merkle scaffolding can evolve in parallel. */
static void cep_flat_hash_bytes(const uint8_t* bytes, size_t size, uint8_t out[CEP_FLAT_HASH_SIZE]) {
    uint64_t acc = UINT64_C(0x6D5A56DA1F4F3D9B);
    for (size_t i = 0; i < size; ++i) {
        acc ^= bytes[i];
        acc *= UINT64_C(0x100000001B3);
    }

    for (size_t lane = 0; lane < CEP_FLAT_HASH_SIZE / sizeof(uint64_t); ++lane) {
        uint64_t word = acc + lane * UINT64_C(0x9E3779B185EBCA87);
        memcpy(out + lane * sizeof(uint64_t), &word, sizeof word);
        acc ^= word;
        acc *= UINT64_C(0x100000001B3);
    }
}

static void cep_flat_hash_pair(const uint8_t* lhs, const uint8_t* rhs, uint8_t out[CEP_FLAT_HASH_SIZE]) {
    uint8_t buffer[CEP_FLAT_HASH_SIZE * 2u];
    memcpy(buffer, lhs, CEP_FLAT_HASH_SIZE);
    memcpy(buffer + CEP_FLAT_HASH_SIZE, rhs, CEP_FLAT_HASH_SIZE);
    cep_flat_hash_bytes(buffer, sizeof buffer, out);
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
    if (checksum != CEP_FLAT_CHECKSUM_CRC32)
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

    uint32_t crc = cep_flat_record_crc(dst, payload_size);
    memcpy(cursor, &crc, sizeof crc);

    serializer->frame.size += total_size;

    if (track_digest) {
        if (!cep_flat_digest_reserve(serializer))
            return false;
        cepFlatDigestEntry* entry = &serializer->digests[serializer->digest_count++];
        entry->key_offset = (size_t)(key_ptr - serializer->frame.data);
        entry->key_size = key_len;
        entry->record_offset = record_offset;
        entry->record_size = payload_size;
        cep_flat_hash_bytes(dst, payload_size, entry->hash);
        serializer->record_count++;
    }

    return true;
}

static bool cep_flat_emit_trailer(cepFlatSerializer* serializer,
                                  const uint8_t merkle_root[CEP_FLAT_HASH_SIZE]) {
    uint8_t body[256];
    uint8_t* cursor = body;

    uint32_t magic = CEP_FLAT_MAGIC;
    memcpy(cursor, &magic, sizeof magic);
    cursor += sizeof magic;

    *cursor++ = CEP_FLAT_SERIALIZER_VERSION;
    cursor = cep_flat_write_varint(serializer->config.beat_number, cursor);
    cursor = cep_flat_write_varint(serializer->record_count, cursor);
    *cursor++ = (uint8_t)serializer->config.apply_mode;
    *cursor++ = (uint8_t)serializer->config.hash_algorithm;
    *cursor++ = (uint8_t)serializer->config.compression_algorithm;
    *cursor++ = (uint8_t)serializer->config.checksum_algorithm;
    cursor = cep_flat_write_varint(CEP_FLAT_HASH_SIZE, cursor);
    memcpy(cursor, merkle_root, CEP_FLAT_HASH_SIZE);
    cursor += CEP_FLAT_HASH_SIZE;
    cursor = cep_flat_write_varint(0u, cursor); /* mini_toc_count */

    uint32_t caps = serializer->config.capability_flags;
    memcpy(cursor, &caps, sizeof caps);
    cursor += sizeof caps;

    cepFlatRecordSpec trailer = {
        .type = CEP_FLAT_RECORD_FRAME_TRAILER,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0u,
        .key = {
            .data = NULL,
            .size = 0u,
        },
        .body = {
            .data = body,
            .size = (size_t)(cursor - body),
        },
    };

    return cep_flat_append_record(serializer, &trailer, false);
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
    cep_free(reader);
}

void cep_flat_reader_reset(cepFlatReader* reader) {
    if (!reader)
        return;
    reader->buffer.size = 0u;
    reader->record_count = 0u;
    reader->digest_count = 0u;
    reader->committed = false;
    reader->trailer_verified = false;
    reader->trailer_record_count = 0u;
    memset(reader->trailer_merkle, 0, sizeof reader->trailer_merkle);
    reader->frame.beat_number = 0u;
    reader->frame.apply_mode = CEP_FLAT_APPLY_INSERT_ONLY;
    reader->frame.capability_flags = 0u;
    reader->frame.hash_algorithm = CEP_FLAT_HASH_BLAKE3_256;
    reader->frame.compression_algorithm = CEP_FLAT_COMPRESSION_NONE;
    reader->frame.checksum_algorithm = CEP_FLAT_CHECKSUM_CRC32;
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

        uint32_t crc_actual = cep_flat_record_crc(data + record_start, payload_size);
        if (crc_actual != crc_expected)
            return false;

        if (type == CEP_FLAT_RECORD_FRAME_TRAILER) {
            if (trailer_seen)
                return false;
            trailer_seen = true;
            if (!cep_flat_reader_parse_trailer(reader, body_ptr, body_length))
                return false;
            if (offset != reader->buffer.size)
                return false;
            break;
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
        cep_flat_hash_bytes(data + record_start, payload_size, entry->hash);
    }

    if (!trailer_seen)
        return false;

    if (!reader->trailer_verified)
        return false;

    if (reader->digest_count != reader->trailer_record_count)
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
    if (checksum != CEP_FLAT_CHECKSUM_CRC32)
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
    for (uint64_t i = 0; i < mini_toc; ++i) {
        if (body_size - offset < 1u)
            return false;
        offset++; /* type */
        uint64_t prefix_len = 0u;
        if (!cep_flat_read_varint(body, body_size, &offset, &prefix_len))
            return false;
        if (body_size - offset < prefix_len)
            return false;
        offset += (size_t)prefix_len;
        uint64_t first_offset = 0u;
        if (!cep_flat_read_varint(body, body_size, &offset, &first_offset))
            return false;
        (void)first_offset;
    }

    if (body_size - offset < sizeof(uint32_t))
        return false;
    uint32_t caps = 0u;
    memcpy(&caps, body + offset, sizeof caps);
    offset += sizeof caps;

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
