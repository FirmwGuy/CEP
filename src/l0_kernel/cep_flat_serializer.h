/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_FLAT_SERIALIZER_H
#define CEP_FLAT_SERIALIZER_H

#include "cep_flat_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CEP_FLAT_SERIALIZER_VERSION 1u
#define CEP_FLAT_HASH_SIZE          32u
#define CEP_FLAT_CONTAINER_MAGIC    UINT32_C(0x43464C54)
#define CEP_FLAT_CONTAINER_VERSION  1u

typedef enum {
    CEP_FLAT_RECORD_CELL_DESC       = 0x01u,
    CEP_FLAT_RECORD_PAYLOAD_CHUNK   = 0x02u,
    CEP_FLAT_RECORD_MANIFEST_DELTA  = 0x03u,
    CEP_FLAT_RECORD_ORDER_DELTA     = 0x04u,
    CEP_FLAT_RECORD_NAMEPOOL_DELTA  = 0x05u,
    CEP_FLAT_RECORD_PAYLOAD_HISTORY = 0x06u,
    CEP_FLAT_RECORD_MANIFEST_HISTORY = 0x07u,
    CEP_FLAT_RECORD_FRAME_TRAILER   = 0xFFu,
} cepFlatRecordType;

typedef enum {
    CEP_FLAT_AEAD_NONE                    = 0u,
    CEP_FLAT_AEAD_AES_GCM                 = 1u,
    CEP_FLAT_AEAD_CHACHA20_POLY1305       = 2u,
    CEP_FLAT_AEAD_XCHACHA20_POLY1305      = 3u,
} cepFlatAeadMode;

typedef enum {
    CEP_FLAT_HASH_BLAKE3_256 = 1u,
} cepFlatHashAlgorithm;

typedef enum {
    CEP_FLAT_COMPRESSION_NONE    = 0u,
    CEP_FLAT_COMPRESSION_DEFLATE = 1u,
} cepFlatCompressionAlgorithm;

typedef enum {
    CEP_FLAT_CHECKSUM_CRC32  = 0u,
    CEP_FLAT_CHECKSUM_CRC32C = 1u,
} cepFlatChecksumAlgorithm;

typedef enum {
    CEP_FLAT_CAP_SPLIT_DESC        = 0x00000001u,
    CEP_FLAT_CAP_NAMEPOOL_MAP      = 0x00000002u,
    CEP_FLAT_CAP_PAYLOAD_FP        = 0x00000004u,
    CEP_FLAT_CAP_PAGED_CHILDSET    = 0x00000008u,
    CEP_FLAT_CAP_PAGED_ORDER       = 0x00000010u,
    CEP_FLAT_CAP_FRAME_COMPRESSION = 0x00000020u,
    CEP_FLAT_CAP_PAYLOAD_HISTORY   = 0x00000040u,
    CEP_FLAT_CAP_MANIFEST_HISTORY  = 0x00000080u,
    CEP_FLAT_CAP_PAYLOAD_REF       = 0x00000100u,
    CEP_FLAT_CAP_FRAME_TOC         = 0x00000200u,
    CEP_FLAT_CAP_BRANCH_METADATA   = 0x00000400u,
} cepFlatCapabilityFlag;

typedef enum {
    CEP_FLAT_APPLY_INSERT_ONLY   = 0u,
    CEP_FLAT_APPLY_OVERWRITE_ALL = 1u,
    CEP_FLAT_APPLY_UPSERT_WITH_CAS = 2u,
} cepFlatApplyMode;

typedef struct {
    const uint8_t* data;
    size_t         size;
} cepFlatSlice;

typedef struct {
    uint8_t     type;
    uint8_t     version;
    uint16_t    flags;
    cepFlatSlice key;
    cepFlatSlice body;
} cepFlatRecordSpec;

typedef struct {
    uint8_t     type;
    uint8_t     version;
    uint16_t    flags;
    cepFlatSlice key;
    cepFlatSlice body;
} cepFlatRecordView;

typedef struct {
    uint64_t                   beat_number;
    cepFlatApplyMode           apply_mode;
    uint32_t                   capability_flags;
    cepFlatHashAlgorithm       hash_algorithm;
    cepFlatCompressionAlgorithm compression_algorithm;
    cepFlatChecksumAlgorithm    checksum_algorithm;
    uint32_t                   payload_history_beats;
    uint32_t                   manifest_history_beats;
    bool                       branch_info_present;
    uint8_t                    branch_glob;
    uint64_t                   branch_domain;
    uint64_t                   branch_tag;
    uint64_t                   branch_frame_id;
} cepFlatFrameConfig;

typedef struct cepFlatSerializer cepFlatSerializer;
typedef struct cepFlatReader cepFlatReader;

typedef enum {
    CEP_FLAT_PAYLOAD_REF_INLINE = 0u,
    CEP_FLAT_PAYLOAD_REF_CAS    = 1u,
} cepFlatPayloadRefKind;

typedef struct {
    uint8_t     record_type;
    cepFlatSlice key_prefix;
    uint64_t    record_offset;
} cepFlatMiniTocEntry;

cepFlatSerializer* cep_flat_serializer_create(void);
void                cep_flat_serializer_destroy(cepFlatSerializer* serializer);
void                cep_flat_serializer_reset(cepFlatSerializer* serializer);
bool                cep_flat_serializer_begin(cepFlatSerializer* serializer,
                                              const cepFlatFrameConfig* config);
bool                cep_flat_serializer_emit(cepFlatSerializer* serializer,
                                             const cepFlatRecordSpec* record);
bool                cep_flat_serializer_finish(cepFlatSerializer* serializer,
                                               cepSerializationWriteFn sink,
                                               void* context);
size_t              cep_flat_serializer_frame_size(const cepFlatSerializer* serializer);
bool                cep_flat_serializer_frame_bytes(const cepFlatSerializer* serializer,
                                                    const uint8_t** data,
                                                    size_t* size);
void                cep_flat_serializer_add_caps(cepFlatSerializer* serializer, uint32_t caps);

cepFlatReader*      cep_flat_reader_create(void);
void                cep_flat_reader_destroy(cepFlatReader* reader);
void                cep_flat_reader_reset(cepFlatReader* reader);
bool                cep_flat_reader_feed(cepFlatReader* reader, const uint8_t* chunk, size_t size);
bool                cep_flat_reader_commit(cepFlatReader* reader);
bool                cep_flat_reader_ready(const cepFlatReader* reader);
const cepFlatRecordView* cep_flat_reader_records(const cepFlatReader* reader, size_t* count);
const cepFlatFrameConfig* cep_flat_reader_frame(const cepFlatReader* reader);
const uint8_t*      cep_flat_reader_merkle_root(const cepFlatReader* reader);
const cepFlatMiniTocEntry* cep_flat_reader_mini_toc(const cepFlatReader* reader, size_t* count);

bool cep_flat_stream_aead_ready(void);
cepFlatAeadMode cep_flat_stream_active_aead_mode(void);
bool cep_flat_stream_aead_encrypt_chunk(const uint8_t* chunk_key,
                                        size_t chunk_key_size,
                                        uint64_t payload_fp,
                                        size_t chunk_offset,
                                        size_t chunk_size,
                                        size_t total_size,
                                        const uint8_t* plaintext,
                                        uint8_t** out_ciphertext,
                                        size_t* out_ciphertext_size,
                                        uint8_t* nonce_out,
                                        size_t* nonce_len_out,
                                        uint8_t aad_hash[CEP_FLAT_HASH_SIZE]);
void cep_flat_stream_compute_chunk_aad_hash(const uint8_t* chunk_key,
                                            size_t chunk_key_size,
                                            uint8_t aad_hash[CEP_FLAT_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FLAT_SERIALIZER_H */
