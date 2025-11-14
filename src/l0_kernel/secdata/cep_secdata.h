/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_SECDATA_H
#define CEP_SECDATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _cepCell;
struct _cepData;
struct _cepDataNode;

typedef uint64_t cepKeyId;

#define CEP_SECDATA_NONCE_MAX   24u
#define CEP_SECDATA_AAD_BYTES   32u

enum {
    CEP_SECDATA_FLAG_SECURED         = 1u << 0,
    CEP_SECDATA_FLAG_ENCRYPTED       = 1u << 1,
    CEP_SECDATA_FLAG_COMPRESSED      = 1u << 2,
    CEP_SECDATA_FLAG_INLINE_FORBIDDEN = 1u << 3,
};

typedef enum {
    CEP_SECDATA_AEAD_NONE = 0,
    CEP_SECDATA_AEAD_CHACHA20,
    CEP_SECDATA_AEAD_XCHACHA20,
} cepAeadMode;

typedef enum {
    CEP_SECDATA_CODEC_NONE = 0,
    CEP_SECDATA_CODEC_DEFLATE = 1,
} cepCodec;

typedef enum {
    CEP_SECDATA_MODE_PLAIN = 0,
    CEP_SECDATA_MODE_ENC,
    CEP_SECDATA_MODE_CENC,
    CEP_SECDATA_MODE_CDEF,
} cepSecdataMode;

typedef struct {
    uint8_t   enc_mode;
    uint8_t   codec;
    uint16_t  reserved;
    cepKeyId  key_id;
    uint64_t  payload_fp;
    uint64_t  raw_len;
    uint64_t  enc_len;
} cepSecmeta;

bool        cep_data_set_plain(struct _cepCell* cell, const void* payload, size_t size);
bool        cep_data_set_enc(struct _cepCell* cell,
                             const void* payload,
                             size_t size,
                             cepKeyId key_id,
                             cepAeadMode mode);
bool        cep_data_set_cenc(struct _cepCell* cell,
                              const void* payload,
                              size_t size,
                              cepKeyId key_id,
                              cepAeadMode mode,
                              cepCodec codec);
bool        cep_data_set_cdef(struct _cepCell* cell,
                              const void* payload,
                              size_t size,
                              cepCodec codec);

bool        cep_data_unveil_ro(struct _cepCell* cell, const void** out_payload, size_t* out_size);
void        cep_data_unveil_done(struct _cepCell* cell, const void* payload);
bool        cep_data_rekey(struct _cepCell* cell, cepKeyId new_key);
bool        cep_data_recompress(struct _cepCell* cell, cepCodec codec);
void        cep_secdata_runtime_scrub(struct _cepData* data);

cepSecdataMode    cep_data_mode(const struct _cepCell* cell);
const cepSecmeta* cep_data_secmeta(const struct _cepDataNode* node);

#ifdef __cplusplus
}
#endif

#endif /* CEP_SECDATA_H */
