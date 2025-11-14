/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "secdata/cep_secdata.h"

#include "cep_cell.h"
#include "cep_cei.h"

#include <sodium.h>
#include <string.h>
#include <zlib.h>

typedef struct {
    uint8_t* bytes;
    size_t   size;
} cepSecdataBuf;

CEP_DEFINE_STATIC_DT(dt_secdata_sev_crit, CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_secdata_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));

static bool     cep_secdata_ensure_sodium(void);
static bool     cep_secdata_prepare(cepCell** cell_ref, cepData** out_data);
static void     cep_secdata_clear_mode(cepData* data);
static uint64_t cep_secdata_payload_fp(const void* payload, size_t size);
static bool     cep_secdata_commit_payload(cepCell* cell, cepData* data, const uint8_t* bytes, size_t size);
static bool     cep_secdata_deflate(const uint8_t* plaintext, size_t size, cepSecdataBuf* out);
static bool     cep_secdata_inflate(const uint8_t* sealed, size_t sealed_len, size_t expected_len, cepSecdataBuf* out);
static bool     cep_secdata_hash_path(const cepCell* cell, blake3_hasher* hasher);
static bool     cep_secdata_compute_ad(const cepCell* cell, uint64_t payload_fp, uint8_t out[CEP_SECDATA_AAD_BYTES]);
static bool     cep_secdata_pin_plaintext(const cepData* data,
                                          const uint8_t* payload,
                                          size_t size,
                                          cepSecdataBuf* clone,
                                          const uint8_t** out_payload);
static void     cep_secdata_release_clone(cepSecdataBuf* clone);
static void     cep_secdata_memzero(void* ptr, size_t len);
static bool     cep_secdata_encrypt(const cepCell* cell,
                                    const uint8_t* plaintext,
                                    size_t plaintext_len,
                                    uint64_t payload_fp,
                                    cepKeyId key_id,
                                    cepAeadMode mode,
                                    cepSecdataBuf* out_cipher,
                                    uint8_t nonce_out[CEP_SECDATA_NONCE_MAX],
                                    size_t* nonce_len_out,
                                    uint8_t aad_hash[CEP_SECDATA_AAD_BYTES]);
static bool     cep_secdata_decrypt(const cepCell* cell, const cepData* data, cepSecdataBuf* out);
static bool     cep_secdata_emit_plain(cepCell* cell, cepData* data, const uint8_t* payload, size_t size);
static void     cep_secdata_mode_set(cepData* data, bool encrypted, bool compressed, bool forbid_inline);
static void     cep_secdata_emit_cei(cepCell* cell, const char* topic, const char* note, bool critical);

static bool cep_secdata_validate_inputs(const void* payload, size_t size) {
    return payload || size == 0u;
}

static bool cep_secdata_ensure_sodium(void) {
    static bool ready = false;
    static bool attempted = false;
    if (attempted)
        return ready;
    attempted = true;
    ready = sodium_init() >= 0;
    return ready;
}

static bool cep_secdata_prepare(cepCell** cell_ref, cepData** out_data) {
    if (!cell_ref || !*cell_ref || !out_data)
        return false;

    cepCell* canonical = cep_link_pull(*cell_ref);
    if (!canonical || !cep_cell_is_normal(canonical))
        return false;

    cepData* data = canonical->data;
    if (!data || !cep_data_valid(data))
        return false;
    if (!data->writable)
        return false;
    if (data->datatype != CEP_DATATYPE_VALUE && data->datatype != CEP_DATATYPE_DATA)
        return false;

    *cell_ref = canonical;
    *out_data = data;
    return true;
}

void cep_secdata_runtime_scrub(cepData* data) {
    if (!data)
        return;
    if (data->sec_plaintext) {
        cep_secdata_memzero(data->sec_plaintext, data->sec_plaintext_size);
        cep_free(data->sec_plaintext);
    }
    data->sec_plaintext = NULL;
    data->sec_plaintext_size = 0u;
    data->sec_view_active = 0u;
}

static void cep_secdata_clear_mode(cepData* data) {
    if (!data)
        return;
    data->mode_flags = 0u;
    memset(&data->secmeta, 0, sizeof data->secmeta);
    memset(data->sec_nonce, 0, sizeof data->sec_nonce);
    data->sec_nonce_len = 0u;
    memset(data->sec_aad_hash, 0, sizeof data->sec_aad_hash);
}

static uint64_t cep_secdata_payload_fp(const void* payload, size_t size) {
    if (!payload || !size)
        return 0u;
    return cep_hash_bytes(payload, size);
}

static bool cep_secdata_commit_payload(cepCell* cell, cepData* data, const uint8_t* bytes, size_t size) {
    if (!cell || !data || !bytes || !size)
        return false;

    if (data->datatype == CEP_DATATYPE_VALUE) {
        if (size > data->capacity)
            return false;
        return cep_cell_update(cell, size, data->capacity, (void*)bytes, false) != NULL;
    }

    if (data->capacity >= size) {
        return cep_cell_update(cell, size, data->capacity, (void*)bytes, false) != NULL;
    }

    uint8_t* heap = cep_malloc(size);
    if (!heap)
        return false;
    memcpy(heap, bytes, size);

    void* stored = cep_cell_update(cell, size, size, heap, true);
    if (!stored) {
        cep_free(heap);
        return false;
    }
    return true;
}

static bool cep_secdata_deflate(const uint8_t* plaintext, size_t size, cepSecdataBuf* out) {
    if (!plaintext || !size || !out)
        return false;

    uLongf max_len = compressBound((uLong)size);
    uint8_t* buffer = cep_malloc(max_len);
    if (!buffer)
        return false;

    uLongf written = max_len;
    int rc = compress2(buffer, &written, plaintext, (uLong)size, Z_BEST_SPEED);
    if (rc != Z_OK) {
        cep_free(buffer);
        return false;
    }

    out->bytes = buffer;
    out->size = (size_t)written;
    return true;
}

static bool cep_secdata_inflate(const uint8_t* sealed, size_t sealed_len, size_t expected_len, cepSecdataBuf* out) {
    if (!sealed || !sealed_len || !expected_len || !out)
        return false;

    uint8_t* buffer = cep_malloc(expected_len);
    if (!buffer)
        return false;

    uLongf written = (uLongf)expected_len;
    int rc = uncompress(buffer, &written, sealed, (uLongf)sealed_len);
    if (rc != Z_OK || written != expected_len) {
        cep_free(buffer);
        return false;
    }

    out->bytes = buffer;
    out->size = expected_len;
    return true;
}

static bool cep_secdata_hash_path(const cepCell* cell, blake3_hasher* hasher) {
    if (!cell || !hasher)
        return false;

    cepPath* path = NULL;
    if (!cep_cell_path(cell, &path))
        return false;

    for (unsigned i = 0; path && i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        cepDT cleaned = cep_dt_clean(&segment->dt);
        uint64_t dom = cleaned.domain;
        uint64_t tag = cleaned.tag;
        uint8_t glob = cleaned.glob ? 1u : 0u;
        blake3_hasher_update(hasher, &dom, sizeof dom);
        blake3_hasher_update(hasher, &tag, sizeof tag);
        blake3_hasher_update(hasher, &glob, sizeof glob);
    }

    if (path)
        cep_free(path);
    return true;
}

static bool cep_secdata_compute_ad(const cepCell* cell, uint64_t payload_fp, uint8_t out[CEP_SECDATA_AAD_BYTES]) {
    if (!out)
        return false;

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (!cep_secdata_hash_path(cell, &hasher))
        return false;
    blake3_hasher_update(&hasher, &payload_fp, sizeof payload_fp);
    blake3_hasher_finalize(&hasher, out, CEP_SECDATA_AAD_BYTES);
    return true;
}

static void cep_secdata_mode_set(cepData* data, bool encrypted, bool compressed, bool forbid_inline) {
    if (!data)
        return;
    uint8_t flags = 0u;
    if (encrypted || compressed)
        flags |= CEP_SECDATA_FLAG_SECURED;
    if (encrypted)
        flags |= CEP_SECDATA_FLAG_ENCRYPTED;
    if (compressed)
        flags |= CEP_SECDATA_FLAG_COMPRESSED;
    if (forbid_inline)
        flags |= CEP_SECDATA_FLAG_INLINE_FORBIDDEN;
    data->mode_flags = flags;
}

static void cep_secdata_emit_cei(cepCell* cell, const char* topic, const char* note, bool critical) {
    if (!topic)
        return;
    cepCell* canonical = cell ? cep_link_pull(cell) : NULL;
    cepCeiRequest req = {
        .severity = critical ? *dt_secdata_sev_crit() : *dt_secdata_sev_warn(),
        .note = note,
        .topic = topic,
        .topic_intern = true,
        .subject = canonical,
        .emit_signal = true,
        .ttl_forever = true,
    };
    (void)cep_cei_emit(&req);
}

static bool cep_secdata_pin_plaintext(const cepData* data,
                                      const uint8_t* payload,
                                      size_t size,
                                      cepSecdataBuf* clone,
                                      const uint8_t** out_payload) {
    if (!clone || !out_payload) {
        return false;
    }
    clone->bytes = NULL;
    clone->size = 0u;
    *out_payload = payload;
    if (!data || !payload || !size) {
        return true;
    }
    if (payload != data->sec_plaintext || data->sec_plaintext_size != size) {
        return true;
    }
    uint8_t* copy = cep_malloc(size);
    if (!copy) {
        return false;
    }
    memcpy(copy, payload, size);
    clone->bytes = copy;
    clone->size = size;
    *out_payload = copy;
    return true;
}

static void cep_secdata_release_clone(cepSecdataBuf* clone) {
    if (!clone || !clone->bytes || !clone->size) {
        return;
    }
    cep_secdata_memzero(clone->bytes, clone->size);
    cep_free(clone->bytes);
    clone->bytes = NULL;
    clone->size = 0u;
}

static void cep_secdata_memzero(void* ptr, size_t len) {
    if (!ptr || !len) {
        return;
    }
    volatile unsigned char* bytes = (volatile unsigned char*)ptr;
    while (len--) {
        *bytes++ = 0u;
    }
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

static bool cep_secdata_encrypt(const cepCell* cell,
                                const uint8_t* plaintext,
                                size_t plaintext_len,
                                uint64_t payload_fp,
                                cepKeyId key_id,
                                cepAeadMode mode,
                                cepSecdataBuf* out_cipher,
                                uint8_t nonce_out[CEP_SECDATA_NONCE_MAX],
                                size_t* nonce_len_out,
                                uint8_t aad_hash[CEP_SECDATA_AAD_BYTES]) {
    if (!cell || !plaintext || !plaintext_len || !out_cipher || !nonce_out || !nonce_len_out || !aad_hash)
        return false;
    if (mode == CEP_SECDATA_AEAD_NONE)
        return false;
    if (!key_id)
        return false;
    if (!cep_secdata_ensure_sodium())
        return false;

    if (!cep_secdata_compute_ad(cell, payload_fp, aad_hash))
        return false;

    uint8_t derived_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        const char salt[] = "cep-secdata-key";
        blake3_hasher_update(&hasher, salt, sizeof salt - 1u);
        blake3_hasher_update(&hasher, &key_id, sizeof key_id);
        blake3_hasher_finalize(&hasher, derived_key, sizeof derived_key);
    }

    size_t nonce_len = (mode == CEP_SECDATA_AEAD_CHACHA20)
                           ? crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                           : crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    blake3_hasher nonce_hasher;
    blake3_hasher_init_keyed(&nonce_hasher, derived_key);
    if (!cep_secdata_hash_path(cell, &nonce_hasher)) {
        cep_secdata_memzero(derived_key, sizeof derived_key);
        return false;
    }
    blake3_hasher_update(&nonce_hasher, &payload_fp, sizeof payload_fp);
    blake3_hasher_finalize(&nonce_hasher, nonce_out, CEP_SECDATA_NONCE_MAX);

    size_t tag_len = (mode == CEP_SECDATA_AEAD_CHACHA20)
                         ? crypto_aead_chacha20poly1305_ietf_ABYTES
                         : crypto_aead_xchacha20poly1305_ietf_ABYTES;
    size_t cipher_len = plaintext_len + tag_len;
    uint8_t* buffer = cep_malloc(cipher_len);
    if (!buffer) {
        cep_secdata_memzero(derived_key, sizeof derived_key);
        return false;
    }

    unsigned long long written = 0u;
    int rc = 0;
    if (mode == CEP_SECDATA_AEAD_CHACHA20) {
        rc = crypto_aead_chacha20poly1305_ietf_encrypt(buffer,
                                                       &written,
                                                       plaintext,
                                                       (unsigned long long)plaintext_len,
                                                       aad_hash,
                                                       CEP_SECDATA_AAD_BYTES,
                                                       NULL,
                                                       nonce_out,
                                                       derived_key);
    } else {
        rc = crypto_aead_xchacha20poly1305_ietf_encrypt(buffer,
                                                        &written,
                                                        plaintext,
                                                        (unsigned long long)plaintext_len,
                                                        aad_hash,
                                                        CEP_SECDATA_AAD_BYTES,
                                                        NULL,
                                                        nonce_out,
                                                        derived_key);
    }

    cep_secdata_memzero(derived_key, sizeof derived_key);

    if (rc != 0) {
        cep_secdata_memzero(buffer, cipher_len);
        cep_free(buffer);
        return false;
    }

    *nonce_len_out = nonce_len;
    out_cipher->bytes = buffer;
    out_cipher->size = (size_t)written;
    return true;
}

static bool cep_secdata_decrypt(const cepCell* cell, const cepData* data, cepSecdataBuf* out) {
    if (!cell || !data || !out)
        return false;
    if (!(data->mode_flags & CEP_SECDATA_FLAG_ENCRYPTED))
        return false;

    if (!cep_secdata_ensure_sodium())
        return false;

    uint8_t expected_ad[CEP_SECDATA_AAD_BYTES];
    if (!cep_secdata_compute_ad(cell, data->secmeta.payload_fp, expected_ad))
        return false;
    if (memcmp(expected_ad, data->sec_aad_hash, CEP_SECDATA_AAD_BYTES) != 0)
        return false;

    uint8_t derived_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        const char salt[] = "cep-secdata-key";
        blake3_hasher_update(&hasher, salt, sizeof salt - 1u);
        blake3_hasher_update(&hasher, &data->secmeta.key_id, sizeof data->secmeta.key_id);
        blake3_hasher_finalize(&hasher, derived_key, sizeof derived_key);
    }

    const uint8_t* sealed = (const uint8_t*)cep_data_payload(data);
    size_t sealed_len = data->size;
    if (!sealed || !sealed_len) {
        cep_secdata_memzero(derived_key, sizeof derived_key);
        return false;
    }

    size_t alloc_len = data->secmeta.enc_len ? data->secmeta.enc_len : sealed_len;
    if (data->secmeta.raw_len && data->secmeta.raw_len > alloc_len)
        alloc_len = data->secmeta.raw_len;
    uint8_t* plaintext = cep_malloc(alloc_len);
    if (!plaintext) {
        cep_secdata_memzero(derived_key, sizeof derived_key);
        return false;
    }

    unsigned long long plain_written = 0u;
    int rc = 0;
    if (data->secmeta.enc_mode == CEP_SECDATA_AEAD_CHACHA20) {
        rc = crypto_aead_chacha20poly1305_ietf_decrypt(plaintext,
                                                       &plain_written,
                                                       NULL,
                                                       sealed,
                                                       (unsigned long long)sealed_len,
                                                       expected_ad,
                                                       CEP_SECDATA_AAD_BYTES,
                                                       data->sec_nonce,
                                                       derived_key);
    } else {
        rc = crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext,
                                                        &plain_written,
                                                        NULL,
                                                        sealed,
                                                        (unsigned long long)sealed_len,
                                                        expected_ad,
                                                        CEP_SECDATA_AAD_BYTES,
                                                        data->sec_nonce,
                                                        derived_key);
    }

    cep_secdata_memzero(derived_key, sizeof derived_key);

    if (rc != 0) {
        cep_secdata_memzero(plaintext, data->secmeta.raw_len ? data->secmeta.raw_len : sealed_len);
        cep_free(plaintext);
        return false;
    }

    out->bytes = plaintext;
    out->size = (size_t)plain_written;
    return true;
}

bool cep_data_set_plain(cepCell* cell, const void* payload, size_t size) {
    if (!cep_secdata_validate_inputs(payload, size) || !size)
        return false;
    if (!cep_ep_require_rw())
        return false;

    cepData* data = NULL;
    if (!cep_secdata_prepare(&cell, &data))
        return false;

    const uint8_t* working_payload = (const uint8_t*)payload;
    cepSecdataBuf clone = {0};
    if (!cep_secdata_pin_plaintext(data,
                                   working_payload,
                                   size,
                                   &clone,
                                   &working_payload)) {
        return false;
    }

    cep_secdata_runtime_scrub(data);
    cep_secdata_clear_mode(data);

    bool ok = cep_secdata_emit_plain(cell, data, working_payload, size);
    cep_secdata_release_clone(&clone);
    if (!ok)
        return false;

    return true;
}

static bool cep_secdata_emit_plain(cepCell* cell, cepData* data, const uint8_t* payload, size_t size) {
    if (!cep_secdata_commit_payload(cell, data, payload, size))
        return false;
    cep_secdata_clear_mode(data);
    return true;
}

bool cep_data_set_cdef(cepCell* cell, const void* payload, size_t size, cepCodec codec) {
    if (!cep_secdata_validate_inputs(payload, size) || !size)
        return false;
    if (codec != CEP_SECDATA_CODEC_DEFLATE) {
        cep_secdata_emit_cei(cell, "codec_mis", "secdata codec unsupported", false);
        return false;
    }
    if (!cep_ep_require_rw())
        return false;

    cepData* data = NULL;
    if (!cep_secdata_prepare(&cell, &data))
        return false;

    const uint8_t* working_payload = (const uint8_t*)payload;
    cepSecdataBuf clone = {0};
    if (!cep_secdata_pin_plaintext(data,
                                   working_payload,
                                   size,
                                   &clone,
                                   &working_payload)) {
        return false;
    }

    cep_secdata_runtime_scrub(data);

    cepSecdataBuf compressed = {0};
    if (!cep_secdata_deflate(working_payload, size, &compressed)) {
        cep_secdata_release_clone(&clone);
        cep_secdata_emit_cei(cell, "enc_fail", "secdata compression failed", true);
        return false;
    }

    uint64_t payload_fp = cep_secdata_payload_fp(working_payload, size);

    bool stored = cep_secdata_commit_payload(cell, data, compressed.bytes, compressed.size);
    cep_secdata_memzero(compressed.bytes, compressed.size);
    cep_free(compressed.bytes);
    if (!stored) {
        cep_secdata_release_clone(&clone);
        cep_secdata_emit_cei(cell, "enc_fail", "secdata compression commit failed", true);
        return false;
    }

    cep_secdata_clear_mode(data);
    data->secmeta.payload_fp = payload_fp;
    data->secmeta.raw_len = size;
    data->secmeta.enc_len = compressed.size;
    data->secmeta.codec = codec;
    data->secmeta.enc_mode = CEP_SECDATA_AEAD_NONE;
    cep_secdata_mode_set(data, false, true, data->datatype == CEP_DATATYPE_VALUE);
    cep_secdata_release_clone(&clone);
    return true;
}

bool cep_data_set_enc(cepCell* cell,
                      const void* payload,
                      size_t size,
                      cepKeyId key_id,
                      cepAeadMode mode) {
    if (!cep_secdata_validate_inputs(payload, size) || !size)
        return false;
    if (!key_id || mode == CEP_SECDATA_AEAD_NONE) {
        cep_secdata_emit_cei(cell, "enc_fail", "secdata encryption params invalid", true);
        return false;
    }
    if (!cep_ep_require_rw())
        return false;

    cepData* data = NULL;
    if (!cep_secdata_prepare(&cell, &data))
        return false;

    const uint8_t* working_payload = (const uint8_t*)payload;
    cepSecdataBuf clone = {0};
    if (!cep_secdata_pin_plaintext(data,
                                   working_payload,
                                   size,
                                   &clone,
                                   &working_payload)) {
        return false;
    }

    cep_secdata_runtime_scrub(data);

    cepSecdataBuf cipher = {0};
    uint8_t nonce[CEP_SECDATA_NONCE_MAX] = {0};
    size_t nonce_len = 0u;
    uint8_t aad_hash[CEP_SECDATA_AAD_BYTES];
    uint64_t payload_fp = cep_secdata_payload_fp(working_payload, size);

    if (!cep_secdata_encrypt(cell,
                             working_payload,
                             size,
                             payload_fp,
                             key_id,
                             mode,
                             &cipher,
                             nonce,
                             &nonce_len,
                             aad_hash)) {
        cep_secdata_emit_cei(cell, "enc_fail", "secdata encryption failed", true);
        cep_secdata_release_clone(&clone);
        return false;
    }

    bool stored = cep_secdata_commit_payload(cell, data, cipher.bytes, cipher.size);
    cep_secdata_memzero(cipher.bytes, cipher.size);
    cep_free(cipher.bytes);
    if (!stored) {
        cep_secdata_release_clone(&clone);
        cep_secdata_emit_cei(cell, "enc_fail", "secdata encryption commit failed", true);
        return false;
    }

    cep_secdata_clear_mode(data);
    data->secmeta.payload_fp = payload_fp;
    data->secmeta.raw_len = size;
    data->secmeta.enc_len = cipher.size;
    data->secmeta.key_id = key_id;
    data->secmeta.enc_mode = mode;
    data->secmeta.codec = CEP_SECDATA_CODEC_NONE;
    memcpy(data->sec_nonce, nonce, nonce_len);
    data->sec_nonce_len = (uint8_t)nonce_len;
    memcpy(data->sec_aad_hash, aad_hash, sizeof aad_hash);
    cep_secdata_mode_set(data, true, false, true);
    cep_secdata_release_clone(&clone);
    return true;
}

bool cep_data_set_cenc(cepCell* cell,
                       const void* payload,
                       size_t size,
                       cepKeyId key_id,
                       cepAeadMode mode,
                       cepCodec codec) {
    if (!cep_secdata_validate_inputs(payload, size) || !size)
        return false;
    if (!key_id || mode == CEP_SECDATA_AEAD_NONE) {
        cep_secdata_emit_cei(cell, "enc_fail", "secdata encryption params invalid", true);
        return false;
    }
    if (codec != CEP_SECDATA_CODEC_DEFLATE && codec != CEP_SECDATA_CODEC_NONE) {
        cep_secdata_emit_cei(cell, "codec_mis", "secdata codec unsupported", false);
        return false;
    }
    if (!cep_ep_require_rw())
        return false;

    cepData* data = NULL;
    if (!cep_secdata_prepare(&cell, &data))
        return false;

    const uint8_t* working_payload = (const uint8_t*)payload;
    cepSecdataBuf clone = {0};
    if (!cep_secdata_pin_plaintext(data,
                                   working_payload,
                                   size,
                                   &clone,
                                   &working_payload)) {
        return false;
    }

    cep_secdata_runtime_scrub(data);

    cepSecdataBuf working = {0};
    bool has_working = false;
    if (codec == CEP_SECDATA_CODEC_DEFLATE) {
        if (!cep_secdata_deflate(working_payload, size, &working)) {
            cep_secdata_release_clone(&clone);
            cep_secdata_emit_cei(cell, "enc_fail", "secdata compression failed", true);
            return false;
        }
        has_working = true;
    }

    const uint8_t* stage = has_working ? working.bytes : working_payload;
    size_t stage_len = has_working ? working.size : size;

    cepSecdataBuf cipher = {0};
    uint8_t nonce[CEP_SECDATA_NONCE_MAX] = {0};
    size_t nonce_len = 0u;
    uint8_t aad_hash[CEP_SECDATA_AAD_BYTES];
    uint64_t payload_fp = cep_secdata_payload_fp(working_payload, size);

    bool encrypted = cep_secdata_encrypt(cell,
                                         stage,
                                         stage_len,
                                         payload_fp,
                                         key_id,
                                         mode,
                                         &cipher,
                                         nonce,
                                         &nonce_len,
                                         aad_hash);

    if (has_working) {
        cep_secdata_memzero(working.bytes, working.size);
        cep_free(working.bytes);
    }

    if (!encrypted) {
        cep_secdata_release_clone(&clone);
        cep_secdata_emit_cei(cell, "enc_fail", "secdata encryption failed", true);
        return false;
    }

    bool stored = cep_secdata_commit_payload(cell, data, cipher.bytes, cipher.size);
    cep_secdata_memzero(cipher.bytes, cipher.size);
    cep_free(cipher.bytes);
    if (!stored) {
        cep_secdata_emit_cei(cell, "enc_fail", "secdata encryption commit failed", true);
        return false;
    }

    cep_secdata_clear_mode(data);
    data->secmeta.payload_fp = payload_fp;
    data->secmeta.raw_len = size;
    data->secmeta.enc_len = cipher.size;
    data->secmeta.key_id = key_id;
    data->secmeta.enc_mode = mode;
    data->secmeta.codec = codec;
    memcpy(data->sec_nonce, nonce, nonce_len);
    data->sec_nonce_len = (uint8_t)nonce_len;
    memcpy(data->sec_aad_hash, aad_hash, sizeof aad_hash);
    cep_secdata_mode_set(data, true, codec == CEP_SECDATA_CODEC_DEFLATE, true);
    cep_secdata_release_clone(&clone);
    return true;
}

bool cep_data_unveil_ro(cepCell* cell, const void** out_payload, size_t* out_size) {
    if (!cell || !out_payload || !out_size)
        return false;

    cepCell* canonical = cep_link_pull(cell);
    if (!canonical || !cep_cell_is_normal(canonical))
        return false;
    cepData* data = canonical->data;
    if (!data || !cep_data_valid(data))
        return false;

    if (!(data->mode_flags & CEP_SECDATA_FLAG_SECURED)) {
        *out_payload = cep_data_payload(data);
        *out_size = data->size;
        data->sec_view_active = 0u;
        return true;
    }

    if (data->sec_view_active)
        return false;

    cepSecdataBuf stage = {0};
    if (data->mode_flags & CEP_SECDATA_FLAG_ENCRYPTED) {
        if (!cep_secdata_decrypt(canonical, data, &stage)) {
            cep_secdata_emit_cei(cell, "dec_fail", "secdata decrypt failed", true);
            return false;
        }
    } else {
        const uint8_t* sealed = cep_data_payload(data);
        if (!sealed || !data->size)
            return false;
        stage.bytes = cep_malloc(data->size);
        if (!stage.bytes)
            return false;
        memcpy(stage.bytes, sealed, data->size);
        stage.size = data->size;
    }

    if (data->mode_flags & CEP_SECDATA_FLAG_COMPRESSED) {
        cepSecdataBuf inflated = {0};
        if (!cep_secdata_inflate(stage.bytes, stage.size, data->secmeta.raw_len, &inflated)) {
            cep_free(stage.bytes);
            cep_secdata_emit_cei(cell, "codec_mis", "secdata inflate mismatch", false);
            return false;
        }
        cep_free(stage.bytes);
        stage = inflated;
    }

    data->sec_plaintext = stage.bytes;
    data->sec_plaintext_size = stage.size;
    data->sec_view_active = 1u;
    *out_payload = stage.bytes;
    *out_size = stage.size;
    return true;
}

void cep_data_unveil_done(cepCell* cell, const void* payload) {
    if (!cell || !payload)
        return;

    cepCell* canonical = cep_link_pull(cell);
    if (!canonical || !cep_cell_is_normal(canonical))
        return;
    cepData* data = canonical->data;
    if (!data || !cep_data_valid(data))
        return;

    if (!data->sec_plaintext || payload != data->sec_plaintext)
        return;

    if (data->sec_plaintext_size)
        cep_secdata_memzero(data->sec_plaintext, data->sec_plaintext_size);
    cep_free(data->sec_plaintext);
    data->sec_plaintext = NULL;
    data->sec_plaintext_size = 0u;
    data->sec_view_active = 0u;
}

bool cep_data_rekey(cepCell* cell, cepKeyId new_key) {
    if (!cell || !new_key)
        return false;

    const void* plaintext = NULL;
    size_t plain_len = 0u;
    if (!cep_data_unveil_ro(cell, &plaintext, &plain_len))
        return false;

    cepCell* canonical = cep_link_pull(cell);
    if (!canonical || !cep_cell_is_normal(canonical)) {
        cep_data_unveil_done(cell, plaintext);
        return false;
    }
    cepData* data = canonical->data;
    if (!data) {
        cep_data_unveil_done(cell, plaintext);
        return false;
    }

    bool ok = false;
    if (data->mode_flags & CEP_SECDATA_FLAG_ENCRYPTED) {
        cepAeadMode mode = (cepAeadMode)data->secmeta.enc_mode;
        cepCodec codec = (cepCodec)data->secmeta.codec;
        if (codec == CEP_SECDATA_CODEC_DEFLATE) {
            ok = cep_data_set_cenc(canonical, plaintext, plain_len, new_key, mode, codec);
        } else {
            ok = cep_data_set_enc(canonical, plaintext, plain_len, new_key, mode);
        }
    }
    cep_data_unveil_done(cell, plaintext);
    if (!ok)
        cep_secdata_emit_cei(cell, "rekey_fail", "secdata rekey failed", false);
    return ok;
}

bool cep_data_recompress(cepCell* cell, cepCodec codec) {
    if (!cell)
        return false;

    const void* plaintext = NULL;
    size_t plain_len = 0u;
    if (!cep_data_unveil_ro(cell, &plaintext, &plain_len))
        return false;

    cepCell* canonical = cep_link_pull(cell);
    if (!canonical || !cep_cell_is_normal(canonical)) {
        cep_data_unveil_done(cell, plaintext);
        return false;
    }
    cepData* data = canonical->data;
    if (!data) {
        cep_data_unveil_done(cell, plaintext);
        return false;
    }

    bool ok = false;
    if (data->mode_flags & CEP_SECDATA_FLAG_ENCRYPTED) {
        cepAeadMode mode = (cepAeadMode)data->secmeta.enc_mode;
        ok = cep_data_set_cenc(canonical, plaintext, plain_len, data->secmeta.key_id, mode, codec);
    } else if (data->mode_flags & CEP_SECDATA_FLAG_COMPRESSED) {
        ok = cep_data_set_cdef(canonical, plaintext, plain_len, codec);
    }

    cep_data_unveil_done(cell, plaintext);
    if (!ok)
        cep_secdata_emit_cei(cell, "codec_mis", "secdata recompress failed", false);
    return ok;
}

const cepSecmeta* cep_data_secmeta(const cepDataNode* node) {
    if (!node || !(node->mode_flags & CEP_SECDATA_FLAG_SECURED))
        return NULL;
    return &node->secmeta;
}

cepSecdataMode cep_data_mode(const cepCell* cell) {
    if (!cell || !cell->data)
        return CEP_SECDATA_MODE_PLAIN;

    const cepData* data = cell->data;
    bool encrypted = (data->mode_flags & CEP_SECDATA_FLAG_ENCRYPTED) != 0;
    bool compressed = (data->mode_flags & CEP_SECDATA_FLAG_COMPRESSED) != 0;

    if (encrypted && compressed)
        return CEP_SECDATA_MODE_CENC;
    if (encrypted)
        return CEP_SECDATA_MODE_ENC;
    if (compressed)
        return CEP_SECDATA_MODE_CDEF;
    return CEP_SECDATA_MODE_PLAIN;
}
