/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_SERIALIZATION_H
#define CEP_SERIALIZATION_H

/**
 * @file
 * @brief Binary serialization helpers for CEP cell graphs.
 */

#include "cep_molecule.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cepSerializationReader cepSerializationReader;
typedef cepSerializationReader cepFlatStreamReader;

typedef struct _cepCell cepCell;

typedef void (*cepFlatStreamAsyncCompletionFn)(bool success,
                                               uint64_t bytes,
                                               int error_code,
                                               void* context);

typedef struct {
    bool                               async_mode;
    bool                               fallback_used;
    bool                               require_sync_copy;
    cepFlatStreamAsyncCompletionFn     completion_cb;
    void*                              completion_ctx;
} cepFlatStreamAsyncStats;

typedef struct {
    uint64_t branch_domain;
    uint64_t branch_tag;
    uint8_t  branch_glob;
    uint64_t frame_id;
} cepFlatBranchFrameInfo;

#define CEP_SERIALIZATION_MAGIC   UINT64_C(0x4345503000000000)
#define CEP_SERIALIZATION_VERSION UINT16_C(0x0002)

#define CEP_SERIALIZATION_CHUNK_OVERHEAD 16u
#define CEP_SERIALIZATION_HEADER_BASE    16u

typedef bool (*cepSerializationWriteFn)(void* context, const uint8_t* chunk, size_t size);
typedef cepSerializationWriteFn cepFlatStreamWriteFn;

#define CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD 4096u
#define CEP_FLAT_STREAM_DEFAULT_BLOB_PAYLOAD CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD

/**
 * @brief Logical chunk classes used by the CEP serialization envelope.
 */
enum {
    CEP_CHUNK_CLASS_CONTROL   = 0x0000u,
    CEP_CHUNK_CLASS_STRUCTURE = 0x0001u,
    CEP_CHUNK_CLASS_BLOB      = 0x0002u,
    CEP_CHUNK_CLASS_LIBRARY   = 0x0003u,
};

typedef enum {
    CEP_SERIAL_ENDIAN_BIG    = 0,
    CEP_SERIAL_ENDIAN_LITTLE = 1,
} cepSerializationByteOrder;

/**
 * @struct cepSerializationHeader
 * @brief Metadata that precedes a stream of CEP serialization chunks.
 */
typedef struct {
    uint64_t     magic;
    uint16_t     version;
    uint8_t      byte_order;
    uint8_t      flags;
    uint32_t     metadata_length;
    const uint8_t* metadata;
    uint64_t     journal_beat;
    bool         journal_metadata_present;
    bool         journal_decision_replay;
    uint16_t     capabilities;
    bool         capabilities_present;
} cepSerializationHeader;

#define CEP_SERIALIZATION_FLAG_CAPABILITIES 0x01u

enum {
    CEP_SERIALIZATION_CAP_HISTORY_MANIFEST = 0x0001u,
    CEP_SERIALIZATION_CAP_MANIFEST_DELTAS  = 0x0002u,
    CEP_SERIALIZATION_CAP_PAYLOAD_HASH     = 0x0004u,
    CEP_SERIALIZATION_CAP_PROXY_ENVELOPE   = 0x0008u,
    CEP_SERIALIZATION_CAP_DIGEST_TRAILER   = 0x0010u,
    CEP_SERIALIZATION_CAP_NAMEPOOL_MAP     = 0x0020u,
    CEP_SERIALIZATION_CAP_SPLIT_DESCRIPTORS = 0x0040u,
};

static inline uint64_t cep_serialization_chunk_id(uint16_t chunk_class, uint32_t transaction, uint16_t sequence) {
    return ((uint64_t)chunk_class << 48) | ((uint64_t)transaction << 16) | sequence;
}

static inline uint16_t cep_serialization_chunk_class(uint64_t chunk_id) {
    return (uint16_t)(chunk_id >> 48);
}

static inline uint32_t cep_serialization_chunk_transaction(uint64_t chunk_id) {
    return (uint32_t)((chunk_id >> 16) & UINT64_C(0xFFFFFFFF));
}

static inline uint16_t cep_serialization_chunk_sequence(uint64_t chunk_id) {
    return (uint16_t)(chunk_id & UINT64_C(0xFFFF));
}

size_t cep_serialization_header_chunk_size(const cepSerializationHeader* header);
bool cep_serialization_header_write(const cepSerializationHeader* header,
                                    uint8_t* dst,
                                    size_t capacity,
                                    size_t* out_size);
bool cep_serialization_header_read(const uint8_t* chunk,
                                   size_t chunk_size,
                                   cepSerializationHeader* header);
bool cep_serialization_emit_cell(const cepCell* cell,
                                 const cepSerializationHeader* header,
                                 cepSerializationWriteFn write,
                                 void* context,
                                 size_t blob_payload_bytes);

bool cep_flat_stream_emit_cell_async(const cepCell* cell,
                                     const cepSerializationHeader* header,
                                     cepSerializationWriteFn write,
                                     void* context,
                                     size_t blob_payload_bytes,
                                     cepFlatStreamAsyncStats* stats);
bool cep_flat_stream_emit_branch_async(const cepCell* cell,
                                       const cepFlatBranchFrameInfo* branch_info,
                                       const cepSerializationHeader* header,
                                       cepSerializationWriteFn write,
                                       void* context,
                                       size_t blob_payload_bytes,
                                       cepFlatStreamAsyncStats* stats);

void cep_serialization_mark_decision_replay(void);
cepSerializationReader* cep_serialization_reader_create(cepCell* root);
void cep_serialization_reader_destroy(cepSerializationReader* reader);
void cep_serialization_reader_reset(cepSerializationReader* reader);
bool cep_serialization_reader_ingest(cepSerializationReader* reader, const uint8_t* chunk, size_t size);
bool cep_serialization_reader_commit(cepSerializationReader* reader);
bool cep_serialization_reader_pending(const cepSerializationReader* reader);
bool cep_serialization_is_busy(void);

#define cep_flat_stream_header_chunk_size cep_serialization_header_chunk_size
#define cep_flat_stream_header_write cep_serialization_header_write
#define cep_flat_stream_header_read cep_serialization_header_read
#define cep_flat_stream_emit_cell cep_serialization_emit_cell
#define cep_flat_stream_mark_decision_replay cep_serialization_mark_decision_replay
#define cep_flat_stream_reader_create cep_serialization_reader_create
#define cep_flat_stream_reader_destroy cep_serialization_reader_destroy
#define cep_flat_stream_reader_reset cep_serialization_reader_reset
#define cep_flat_stream_reader_ingest cep_serialization_reader_ingest
#define cep_flat_stream_reader_commit cep_serialization_reader_commit
#define cep_flat_stream_reader_pending cep_serialization_reader_pending
#define cep_flat_stream_is_busy cep_serialization_is_busy

#ifdef __cplusplus
}
#endif

#endif /* CEP_SERIALIZATION_H */
