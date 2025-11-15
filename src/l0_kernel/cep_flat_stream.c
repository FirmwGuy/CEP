/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_flat_stream.h"
#include "cep_cell.h"
#include "cep_flat_serializer.h"
#include "cep_flat_helpers.h"
#include "cep_cei.h"
#include "cep_heartbeat.h"
#include "cep_async.h"
#include "cep_io_reactor.h"
#include "cep_ops.h"
#include "cep_namepool.h"
#include "cep_crc32c.h"
#include "cep_runtime.h"
#include "blake3.h"
#include "storage/cep_octree.h"
#include "stream/cep_stream_internal.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <ctype.h>
#include <sodium.h>

/* Storage backends expose inline helpers that depend on internal Layer 0
   symbols such as `cep_shadow_rebind_links` and `cell_compare_by_name`. This
   translation unit only needs the struct layouts, so provide conservative
   stubs that should never run; if they ever do, crash loudly. */
static inline void cep_serialization_unreachable_stub(void) {
#ifdef CEP_ENABLE_DEBUG
    CEP_ASSERT(!"storage shim invoked from cep_serialization.c");
#else
    abort();
#endif
}

static void cep_shadow_rebind_links(cepCell* target) {
    (void)target;
    cep_serialization_unreachable_stub();
}

static int cell_compare_by_name(const cepCell* restrict key,
                                const cepCell* restrict rec,
                                void* unused,
                                cepCompareInfo* info) {
    (void)key;
    (void)rec;
    (void)unused;
    (void)info;
    cep_serialization_unreachable_stub();
    return 0;
}

#include "storage/cep_dynamic_array.h"
#include "storage/cep_hash_table.h"
#include "storage/cep_packed_queue.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <limits.h>

#define CEP_ASYNC_SYNC_COPY_ENV "CEP_ASYNC_SYNC_COPY"

typedef enum {
    CEP_FLAT_STREAM_SYNC_COPY_AUTO = 0,
    CEP_FLAT_STREAM_SYNC_COPY_FORCE,
    CEP_FLAT_STREAM_SYNC_COPY_DISABLE,
} cepFlatStreamSyncCopyOverride;

static bool
cep_flat_stream_env_equals(const char* value, const char* token)
{
    if (!value || !token) {
        return false;
    }
    while (*value && *token) {
        if (tolower((unsigned char)*value) != tolower((unsigned char)*token)) {
            return false;
        }
        value += 1;
        token += 1;
    }
    return *value == '\0' && *token == '\0';
}

static cepFlatStreamSyncCopyOverride
cep_flat_stream_sync_copy_override(void)
{
    static bool cached = false;
    static cepFlatStreamSyncCopyOverride override_mode = CEP_FLAT_STREAM_SYNC_COPY_AUTO;
    if (cached) {
        return override_mode;
    }
    const char* env = getenv(CEP_ASYNC_SYNC_COPY_ENV);
    if (env && *env) {
        if (cep_flat_stream_env_equals(env, "force") ||
            cep_flat_stream_env_equals(env, "required")) {
            override_mode = CEP_FLAT_STREAM_SYNC_COPY_FORCE;
        } else if (cep_flat_stream_env_equals(env, "disable") ||
                   cep_flat_stream_env_equals(env, "off") ||
                   cep_flat_stream_env_equals(env, "false")) {
            override_mode = CEP_FLAT_STREAM_SYNC_COPY_DISABLE;
        }
    }
    cached = true;
    return override_mode;
}

static bool
cep_flat_stream_should_require_sync_copy(bool requested)
{
    cepFlatStreamSyncCopyOverride mode = cep_flat_stream_sync_copy_override();
    if (mode == CEP_FLAT_STREAM_SYNC_COPY_FORCE) {
        return true;
    }
    if (mode == CEP_FLAT_STREAM_SYNC_COPY_DISABLE) {
        return false;
    }
    if (cep_io_reactor_active_backend() == CEP_IO_REACTOR_BACKEND_EPOLL && !requested) {
        return false;
    }
    return requested;
}

CEP_DEFINE_STATIC_DT(dt_flat_async_channel, CEP_ACRO("CEP"), CEP_WORD("chn:serial"));
CEP_DEFINE_STATIC_DT(dt_flat_async_provider, CEP_ACRO("CEP"), CEP_WORD("prov:serial"));
CEP_DEFINE_STATIC_DT(dt_flat_async_reactor, CEP_ACRO("CEP"), CEP_WORD("react:ser"));
CEP_DEFINE_STATIC_DT(dt_flat_async_caps, CEP_ACRO("CEP"), CEP_WORD("caps:sync"));
CEP_DEFINE_STATIC_DT(dt_flat_async_opcode_begin, CEP_ACRO("CEP"), CEP_WORD("op:begin"));
CEP_DEFINE_STATIC_DT(dt_flat_async_opcode_write, CEP_ACRO("CEP"), CEP_WORD("op:write"));
CEP_DEFINE_STATIC_DT(dt_flat_async_opcode_finish, CEP_ACRO("CEP"), CEP_WORD("op:finish"));
CEP_DEFINE_STATIC_DT(dt_flat_async_state_exec, CEP_ACRO("CEP"), CEP_WORD("ist:exec"));
CEP_DEFINE_STATIC_DT(dt_flat_async_state_ok, CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_flat_async_state_fail, CEP_ACRO("CEP"), CEP_WORD("ist:fail"));

#define CEP_FLAT_CELL_META_TOMBSTONE 0x0001u
#define CEP_FLAT_CELL_META_VEILED    0x0002u
#define CEP_FLAT_ORGANISER_HASH      0x04u
#define CEP_SERIALIZATION_HISTORY_PAGE_LIMIT 64u

typedef enum {
    CEP_SERIALIZATION_AEAD_MODE_NONE = CEP_FLAT_AEAD_NONE,
    CEP_SERIALIZATION_AEAD_MODE_AES_GCM = CEP_FLAT_AEAD_AES_GCM,
    CEP_SERIALIZATION_AEAD_MODE_CHACHA20 = CEP_FLAT_AEAD_CHACHA20_POLY1305,
    CEP_SERIALIZATION_AEAD_MODE_XCHACHA20 = CEP_FLAT_AEAD_XCHACHA20_POLY1305,
} cepSerializationAeadMode;

typedef struct {
    bool                     parsed;
    bool                     enabled;
    cepSerializationAeadMode mode;
    size_t                   key_len;
    size_t                   nonce_len;
    size_t                   tag_len;
    uint8_t                  key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    char                     mode_token[32];
    uint8_t                  key_fingerprint[CEP_FLAT_HASH_SIZE];
} cepSerializationAeadConfig;

static cepSerializationAeadConfig cep_serialization_aead_config;

static bool cep_serialization_build_payload_chunk_body(const cepData* data,
                                                       const cepDataNode* snapshot,
                                                       uint64_t payload_fp,
                                                       const void* payload_bytes,
                                                       size_t total_size,
                                                       size_t chunk_offset,
                                                       size_t chunk_size,
                                                       const uint8_t* chunk_key,
                                                       size_t chunk_key_size,
                                                       cepFlatNamepoolCollector* names,
                                                       uint8_t** out_body,
                                                       size_t* out_body_size);
static bool cep_serialization_collect_children_snapshot(const cepCell* parent,
                                                        cepOpCount snapshot,
                                                        cepFlatChildDescriptor** out_children,
                                                        size_t* out_count,
                                                        uint8_t* organiser);
static bool cep_serialization_hash_payload_blake3(const void* payload,
                                                  size_t size,
                                                  uint8_t out[CEP_FLAT_HASH_SIZE]);
static bool cep_serialization_emit_manifest_history(const cepCell* cell,
                                                    cepFlatSerializer* serializer,
                                                    cepFlatNamepoolCollector* names,
                                                    uint32_t history_window,
                                                    cepOpCount frame_beat);
static bool cep_serialization_emit_manifest_history_page(cepFlatSerializer* serializer,
                                                         const cepCell* parent,
                                                         cepOpCount snapshot,
                                                         const cepFlatChildDescriptor* children,
                                                         size_t child_count,
                                                         const cepFlatChildDescriptor* next_child,
                                                         uint8_t organiser,
                                                         cepFlatNamepoolCollector* names,
                                                         uint64_t page_id);
static void cep_serialization_history_revision(const cepCell* cell,
                                               cepOpCount snapshot,
                                               uint64_t page_id,
                                               uint8_t out[16]);
static bool cep_serialization_key_append_bytes(uint8_t** key,
                                               size_t* key_size,
                                               const void* bytes,
                                               size_t len);
static bool cep_serialization_key_append_varint(uint8_t** key,
                                                size_t* key_size,
                                                uint64_t value);

static cepSerializationAeadMode cep_serialization_aead_mode(void);
static void cep_serialization_aead_refresh(void);
static bool cep_serialization_aead_ready(void);
static bool cep_serialization_aead_encrypt_chunk(const uint8_t* chunk_key,
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
static void cep_serialization_compute_aad_hash(const uint8_t* chunk_key,
                                               size_t chunk_key_size,
                                               uint8_t aad_hash[CEP_FLAT_HASH_SIZE]);
static bool cep_serialization_hex_decode(const char* hex, uint8_t* out, size_t expected_len);
static int cep_serialization_hex_nibble(char c);
static void cep_serialization_hash_string(const char* value, uint8_t out[CEP_FLAT_HASH_SIZE]);
static cepSerializationAeadMode cep_serialization_aead_parse_mode(const char* value);
static size_t cep_serialization_aead_expected_keybytes(cepSerializationAeadMode mode);

static bool cep_serialization_emit_cell_flat(const cepCell* cell,
                                             const cepSerializationHeader* header,
                                             cepSerializationWriteFn write,
                                             void* context,
                                             size_t blob_payload_bytes);
static bool cep_serialization_build_cell_desc_body(const cepCell* cell,
                                                   const cepData* data,
                                                   uint64_t payload_fp,
                                                   const void* inline_payload,
                                                   size_t inline_length,
                                                   size_t payload_size,
                                                   const uint8_t* payload_hash,
                                                   cepFlatNamepoolCollector* names,
                                                   uint8_t** out_body,
                                                   size_t* out_body_size);
static bool cep_serialization_build_payload_chunk_key(const cepCell* cell,
                                                      uint64_t chunk_ordinal,
                                                      cepFlatNamepoolCollector* names,
                                                      uint8_t** out_key,
                                                      size_t* out_key_size);
static uint8_t cep_serialization_flat_aead_from_secdata(uint8_t enc_mode);
static bool cep_serialization_emit_payload_history(const cepCell* cell,
                                                   cepFlatSerializer* serializer,
                                                   cepFlatNamepoolCollector* names,
                                                   size_t chunk_limit,
                                                   uint32_t history_window);
static size_t cep_serialization_varint_length(uint64_t value);
static uint8_t* cep_serialization_write_varint(uint64_t value, uint8_t* dst);
static bool cep_serialization_body_reserve(uint8_t** buffer,
                                           size_t* capacity,
                                           size_t needed);
static uint16_t cep_serial_read_be16_buf(const uint8_t* src);
static uint32_t cep_serial_read_be32_buf(const uint8_t* src);
static uint64_t cep_serial_read_be64_buf(const uint8_t* src);
static void cep_serialization_register_builtin_comparators(void);

static const char* cep_serialization_id_desc(cepID id, char* buf, size_t cap) {
    if (!buf || !cap) {
        return "<buf>";
    }
    if (!id) {
        snprintf(buf, cap, "0");
        return buf;
    }
    if (cep_id_is_reference(id)) {
        const char* text = cep_namepool_lookup(id, NULL);
        if (text) {
            snprintf(buf, cap, "%s", text);
            return buf;
        }
    } else if (cep_id_is_word(id)) {
        size_t len = cep_word_to_text(id, buf);
        if (len >= cap)
            len = cap - 1u;
        buf[len] = '\0';
        return buf;
    } else if (cep_id_is_acronym(id)) {
        size_t len = cep_acronym_to_text(id, buf);
        if (len >= cap)
            len = cap - 1u;
        buf[len] = '\0';
        while (len && buf[len - 1] == ' ')
            buf[--len] = '\0';
        return buf;
    } else if (cep_id_is_numeric(id)) {
        snprintf(buf, cap, "#%llu", (unsigned long long)cep_id_to_numeric(id));
        return buf;
    }
    snprintf(buf, cap, "0x%016" PRIx64, (uint64_t)id);
    return buf;
}

static void cep_serialization_debug_log(const char* fmt, ...);
static void cep_serialization_emit_failure(const char* topic,
                                           const cepCell* subject,
                                           const char* detail_fmt,
                                           ...);

static bool cep_serialization_debug_logging_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* dbg = getenv("CEP_SERIALIZATION_DEBUG");
        const char* poc = getenv("CEP_POC_SERIALIZATION_DEBUG");
        bool enabled = (dbg && *dbg && strcmp(dbg, "0") != 0 && strcasecmp(dbg, "false") != 0) ||
                       (poc && *poc && strcmp(poc, "0") != 0 && strcasecmp(poc, "false") != 0);
        cached = enabled ? 1 : 0;
    }
    return cached == 1;
}

static bool cep_serialization_flat_mode_enabled(void) {
    return true;
}

static cepFlatCompressionAlgorithm cep_serialization_flat_compression_mode(void) {
    const char* value = getenv("CEP_SERIALIZATION_FLAT_COMPRESSION");
    if (!value || !*value)
        return CEP_FLAT_COMPRESSION_NONE;
    if (strcasecmp(value, "deflate") == 0)
        return CEP_FLAT_COMPRESSION_DEFLATE;
    return CEP_FLAT_COMPRESSION_NONE;
}

static uint32_t cep_serialization_env_history_beats(const char* name) {
    const char* value = getenv(name);
    if (!value || !*value)
        return 0u;
    errno = 0;
    char* end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || (end && *end)) {
        cep_serialization_debug_log("[serialization][flat] ignoring %s=%s (invalid integer)\n",
                                    name,
                                    value);
        return 0u;
    }
    if (parsed > UINT32_MAX)
        parsed = UINT32_MAX;
    return (uint32_t)parsed;
}

static uint32_t cep_serialization_flat_payload_history_beats(void) {
    return cep_serialization_env_history_beats("CEP_SERIALIZATION_FLAT_PAYLOAD_HISTORY_BEATS");
}

static uint32_t cep_serialization_flat_manifest_history_beats(void) {
    return cep_serialization_env_history_beats("CEP_SERIALIZATION_FLAT_MANIFEST_HISTORY_BEATS");
}

static uint32_t cep_serialization_flat_comparator_max_version(void) {
    const char* value = getenv("CEP_SERIALIZATION_FLAT_MAX_COMPARATOR_VERSION");
    if (!value || !*value)
        return UINT32_MAX;
    errno = 0;
    char* end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || (end && *end)) {
        cep_serialization_debug_log("[serialization][flat] ignoring CEP_SERIALIZATION_FLAT_MAX_COMPARATOR_VERSION=%s (invalid integer)\n",
                                    value);
        return UINT32_MAX;
    }
    if (parsed > UINT32_MAX)
        parsed = UINT32_MAX;
    return (uint32_t)parsed;
}

static cepFlatChecksumAlgorithm cep_serialization_flat_checksum_algorithm(void) {
    const char* override = getenv("CEP_SERIALIZATION_FLAT_CHECKSUM");
    if (override && *override) {
        if (strcasecmp(override, "crc32c") == 0)
            return CEP_FLAT_CHECKSUM_CRC32C;
        if (strcasecmp(override, "crc32") == 0)
            return CEP_FLAT_CHECKSUM_CRC32;
    }
    return cep_crc32c_castagnoli_enabled() ? CEP_FLAT_CHECKSUM_CRC32C : CEP_FLAT_CHECKSUM_CRC32;
}

static void cep_serialization_debug_log(const char* fmt, ...) {
    if (!cep_serialization_debug_logging_enabled())
        return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
}

static void cep_serialization_hash_string(const char* value, uint8_t out[CEP_FLAT_HASH_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (value && *value) {
        size_t len = strlen(value);
        blake3_hasher_update(&hasher, value, len);
    }
    blake3_hasher_finalize(&hasher, out, CEP_FLAT_HASH_SIZE);
}

static int cep_serialization_hex_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static bool cep_serialization_hex_decode(const char* hex, uint8_t* out, size_t expected_len) {
    if (!hex || !out)
        return false;
    size_t len = strlen(hex);
    if (len != expected_len * 2u)
        return false;
    for (size_t i = 0; i < expected_len; ++i) {
        int hi = cep_serialization_hex_nibble(hex[i * 2u]);
        int lo = cep_serialization_hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4u) | lo);
    }
    return true;
}

static size_t cep_serialization_aead_expected_keybytes(cepSerializationAeadMode mode) {
    switch (mode) {
        case CEP_SERIALIZATION_AEAD_MODE_CHACHA20:
            return crypto_aead_chacha20poly1305_ietf_KEYBYTES;
        case CEP_SERIALIZATION_AEAD_MODE_XCHACHA20:
            return crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
        case CEP_SERIALIZATION_AEAD_MODE_AES_GCM:
            return 32u;
        default:
            return 0u;
    }
}

static cepSerializationAeadMode cep_serialization_aead_parse_mode(const char* value) {
    if (!value || !*value)
        return CEP_SERIALIZATION_AEAD_MODE_NONE;
    if (strcasecmp(value, "none") == 0 || strcmp(value, "0") == 0)
        return CEP_SERIALIZATION_AEAD_MODE_NONE;
    if (strcasecmp(value, "aes-gcm") == 0 || strcasecmp(value, "aesgcm") == 0)
        return CEP_SERIALIZATION_AEAD_MODE_AES_GCM;
    if (strcasecmp(value, "chacha20") == 0 || strcasecmp(value, "chacha20-poly1305") == 0)
        return CEP_SERIALIZATION_AEAD_MODE_CHACHA20;
    if (strcasecmp(value, "xchacha20") == 0 || strcasecmp(value, "xchacha20-poly1305") == 0)
        return CEP_SERIALIZATION_AEAD_MODE_XCHACHA20;
    return CEP_SERIALIZATION_AEAD_MODE_NONE;
}

static void cep_serialization_aead_refresh(void) {
    const char* mode_env = getenv("CEP_SERIALIZATION_FLAT_AEAD_MODE");
    const char* key_env = getenv("CEP_SERIALIZATION_FLAT_AEAD_KEY");

    char mode_value[sizeof cep_serialization_aead_config.mode_token];
    if (mode_env && *mode_env) {
        size_t len = strlen(mode_env);
        if (len >= sizeof mode_value)
            len = sizeof mode_value - 1u;
        memcpy(mode_value, mode_env, len);
        mode_value[len] = '\0';
    } else {
        mode_value[0] = '\0';
    }

    uint8_t key_fingerprint[CEP_FLAT_HASH_SIZE];
    cep_serialization_hash_string(key_env ? key_env : "", key_fingerprint);

    bool needs_parse = !cep_serialization_aead_config.parsed ||
                       strcmp(cep_serialization_aead_config.mode_token, mode_value) != 0 ||
                       memcmp(cep_serialization_aead_config.key_fingerprint,
                              key_fingerprint,
                              CEP_FLAT_HASH_SIZE) != 0;
    if (!needs_parse)
        return;

    cep_serialization_aead_config.parsed = true;
    cep_serialization_aead_config.enabled = false;
    cep_serialization_aead_config.mode = CEP_SERIALIZATION_AEAD_MODE_NONE;
    cep_serialization_aead_config.key_len = 0u;
    cep_serialization_aead_config.nonce_len = 0u;
    cep_serialization_aead_config.tag_len = 0u;
    memset(cep_serialization_aead_config.key, 0, sizeof cep_serialization_aead_config.key);
    memcpy(cep_serialization_aead_config.mode_token, mode_value, sizeof mode_value);
    memcpy(cep_serialization_aead_config.key_fingerprint, key_fingerprint, CEP_FLAT_HASH_SIZE);

    cepSerializationAeadMode mode = cep_serialization_aead_parse_mode(mode_env);
    if (mode == CEP_SERIALIZATION_AEAD_MODE_NONE)
        return;
    if (mode == CEP_SERIALIZATION_AEAD_MODE_AES_GCM) {
        cep_serialization_debug_log("[serialization][flat] AES-GCM mode is not implemented; disabling AEAD\n");
        return;
    }

    size_t expected_key = cep_serialization_aead_expected_keybytes(mode);
    if (!key_env || !*key_env) {
        cep_serialization_debug_log("[serialization][flat] AEAD mode requires CEP_SERIALIZATION_FLAT_AEAD_KEY\n");
        return;
    }
    size_t key_hex_len = strlen(key_env);
    if (key_hex_len != expected_key * 2u) {
        cep_serialization_debug_log("[serialization][flat] AEAD key length mismatch (wanted %zu hex chars, saw %zu)\n",
                                    expected_key * 2u,
                                    key_hex_len);
        return;
    }
    if (!cep_serialization_hex_decode(key_env, cep_serialization_aead_config.key, expected_key)) {
        cep_serialization_debug_log("[serialization][flat] AEAD key contains invalid hex characters\n");
        return;
    }
    if (sodium_init() < 0) {
        cep_serialization_debug_log("[serialization][flat] sodium_init failed; disabling AEAD\n");
        sodium_memzero(cep_serialization_aead_config.key, sizeof cep_serialization_aead_config.key);
        return;
    }

    cep_serialization_aead_config.enabled = true;
    cep_serialization_aead_config.mode = mode;
    cep_serialization_aead_config.key_len = expected_key;
    cep_serialization_aead_config.nonce_len = (mode == CEP_SERIALIZATION_AEAD_MODE_CHACHA20)
                                                  ? crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                                                  : crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    cep_serialization_aead_config.tag_len = (mode == CEP_SERIALIZATION_AEAD_MODE_CHACHA20)
                                                ? crypto_aead_chacha20poly1305_ietf_ABYTES
                                                : crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

static cepSerializationAeadMode cep_serialization_aead_mode(void) {
    cep_serialization_aead_refresh();
    return cep_serialization_aead_config.mode;
}

static bool cep_serialization_aead_ready(void) {
    cep_serialization_aead_refresh();
    return cep_serialization_aead_config.enabled;
}

static void cep_serialization_compute_aad_hash(const uint8_t* chunk_key,
                                               size_t chunk_key_size,
                                               uint8_t aad_hash[CEP_FLAT_HASH_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (chunk_key && chunk_key_size)
        blake3_hasher_update(&hasher, chunk_key, chunk_key_size);
    blake3_hasher_finalize(&hasher, aad_hash, CEP_FLAT_HASH_SIZE);
}

bool cep_flat_stream_aead_ready(void) {
    return cep_serialization_aead_ready();
}

cepFlatAeadMode cep_flat_stream_active_aead_mode(void) {
    return (cepFlatAeadMode)cep_serialization_aead_mode();
}

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
                                        uint8_t aad_hash[CEP_FLAT_HASH_SIZE]) {
    return cep_serialization_aead_encrypt_chunk(chunk_key,
                                                chunk_key_size,
                                                payload_fp,
                                                chunk_offset,
                                                chunk_size,
                                                total_size,
                                                plaintext,
                                                out_ciphertext,
                                                out_ciphertext_size,
                                                nonce_out,
                                                nonce_len_out,
                                                aad_hash);
}

void cep_flat_stream_compute_chunk_aad_hash(const uint8_t* chunk_key,
                                            size_t chunk_key_size,
                                            uint8_t aad_hash[CEP_FLAT_HASH_SIZE]) {
    cep_serialization_compute_aad_hash(chunk_key, chunk_key_size, aad_hash);
}

static bool cep_serialization_hash_payload_blake3(const void* payload,
                                                  size_t size,
                                                  uint8_t out[CEP_FLAT_HASH_SIZE]) {
    if (!payload || !size || !out)
        return false;
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, payload, size);
    blake3_hasher_finalize(&hasher, out, CEP_FLAT_HASH_SIZE);
    return true;
}

static bool cep_serialization_aead_encrypt_chunk(const uint8_t* chunk_key,
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
                                                 uint8_t aad_hash[CEP_FLAT_HASH_SIZE]) {
    if (!chunk_key || !chunk_key_size || !plaintext || !chunk_size ||
        !out_ciphertext || !out_ciphertext_size || !nonce_out || !nonce_len_out || !aad_hash)
        return false;
    if (!cep_serialization_aead_ready())
        return false;

    cepSerializationAeadMode mode = cep_serialization_aead_mode();
    if (mode == CEP_SERIALIZATION_AEAD_MODE_NONE)
        return false;

    cep_serialization_compute_aad_hash(chunk_key, chunk_key_size, aad_hash);

    uint8_t nonce_buf[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0};
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, cep_serialization_aead_config.key);
    blake3_hasher_update(&hasher, chunk_key, chunk_key_size);
    struct {
        uint64_t payload_fp;
        uint64_t chunk_offset;
        uint64_t chunk_size;
        uint64_t total_size;
    } nonce_material = {
        .payload_fp = payload_fp,
        .chunk_offset = chunk_offset,
        .chunk_size = chunk_size,
        .total_size = total_size,
    };
    blake3_hasher_update(&hasher, &nonce_material, sizeof nonce_material);
    blake3_hasher_finalize(&hasher, nonce_buf, sizeof nonce_buf);
    size_t nonce_len = cep_serialization_aead_config.nonce_len;

    size_t cipher_len = chunk_size + cep_serialization_aead_config.tag_len;
    uint8_t* cipher = cep_malloc(cipher_len);
    if (!cipher)
        return false;

    unsigned long long written = 0u;
    int rc = 0;
    if (mode == CEP_SERIALIZATION_AEAD_MODE_CHACHA20) {
        rc = crypto_aead_chacha20poly1305_ietf_encrypt(cipher,
                                                       &written,
                                                       plaintext,
                                                       (unsigned long long)chunk_size,
                                                       chunk_key,
                                                       (unsigned long long)chunk_key_size,
                                                       NULL,
                                                       nonce_buf,
                                                       cep_serialization_aead_config.key);
    } else {
        rc = crypto_aead_xchacha20poly1305_ietf_encrypt(cipher,
                                                        &written,
                                                        plaintext,
                                                        (unsigned long long)chunk_size,
                                                        chunk_key,
                                                        (unsigned long long)chunk_key_size,
                                                        NULL,
                                                        nonce_buf,
                                                        cep_serialization_aead_config.key);
    }
    if (rc != 0) {
        sodium_memzero(cipher, cipher_len);
        cep_free(cipher);
        return false;
    }

    memcpy(nonce_out, nonce_buf, nonce_len);
    *nonce_len_out = nonce_len;
    *out_ciphertext = cipher;
    *out_ciphertext_size = (size_t)written;
    return true;
}

static bool cep_serialization_emit_cell_flat(const cepCell* cell,
                                             const cepSerializationHeader* header,
                                             cepSerializationWriteFn write,
                                             void* context,
                                             size_t blob_payload_bytes) {
    (void)header;
    (void)blob_payload_bytes;
    if (!cell || !write)
        return false;

    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical)
        return false;

    cepFlatSerializer* serializer = cep_flat_serializer_create();
    if (!serializer)
        return false;

    bool ok = false;
    uint32_t payload_history_window = cep_serialization_flat_payload_history_beats();
    uint32_t manifest_history_window = cep_serialization_flat_manifest_history_beats();
    cepOpCount frame_beat = cep_cell_latest_timestamp(canonical);
    if (!frame_beat)
        frame_beat = cep_beat_index();

    cepFlatFrameConfig config = {
        .beat_number = frame_beat,
        .apply_mode = CEP_FLAT_APPLY_INSERT_ONLY,
        .capability_flags = 0u,
        .hash_algorithm = CEP_FLAT_HASH_BLAKE3_256,
        .compression_algorithm = cep_serialization_flat_compression_mode(),
        .checksum_algorithm = cep_serialization_flat_checksum_algorithm(),
        .payload_history_beats = payload_history_window,
        .manifest_history_beats = manifest_history_window,
    };

    if (!cep_flat_serializer_begin(serializer, &config))
        goto exit;

    cepFlatNamepoolCollector names = {0};

    const cepData* data = canonical->data;
    const void* payload_bytes = (data && (data->datatype == CEP_DATATYPE_VALUE || data->datatype == CEP_DATATYPE_DATA))
                                    ? cep_data_payload(data)
                                    : NULL;
    size_t payload_size = (data && payload_bytes) ? data->size : 0u;
    bool inline_allowed = data && data->datatype == CEP_DATATYPE_VALUE && payload_size && payload_size <= 64u;
    if (data && (data->mode_flags & CEP_SECDATA_FLAG_INLINE_FORBIDDEN))
        inline_allowed = false;
    size_t inline_len = inline_allowed ? payload_size : 0u;
    bool data_secured = data && (data->mode_flags & CEP_SECDATA_FLAG_SECURED);
    uint64_t payload_fp = 0u;
    if (data) {
        if (data_secured && data->secmeta.payload_fp)
            payload_fp = data->secmeta.payload_fp;
        else
            payload_fp = cep_data_compute_hash(data);
    }
    uint8_t payload_hash[CEP_FLAT_HASH_SIZE];
    bool has_payload_hash = false;
    if (payload_bytes && payload_size)
        has_payload_hash = cep_serialization_hash_payload_blake3(payload_bytes, payload_size, payload_hash);
    size_t chunk_limit = blob_payload_bytes ? blob_payload_bytes : CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD;
    if (!chunk_limit)
        chunk_limit = CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD;
    if (data_secured && payload_size)
        chunk_limit = payload_size;

    uint8_t* key_bytes = NULL;
    size_t key_size = 0u;
    if (!cep_flat_build_key(canonical, CEP_FLAT_RECORD_CELL_DESC, &names, &key_bytes, &key_size))
        goto exit;

    uint8_t* body_bytes = NULL;
    size_t body_size = 0u;
    if (!cep_serialization_build_cell_desc_body(canonical,
                                                data,
                                                payload_fp,
                                                inline_len ? payload_bytes : NULL,
                                                inline_len,
                                                payload_size,
                                                has_payload_hash ? payload_hash : NULL,
                                                &names,
                                                &body_bytes,
                                                &body_size))
        goto exit;

    if (payload_fp)
        cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_PAYLOAD_FP);
    if (has_payload_hash && payload_size)
        cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_PAYLOAD_REF);

    /* TODO(2025-11-09T22:31Z): populate the body payload with the actual cell
       metadata (store hints, beats, payload fingerprints). */
    cepFlatRecordSpec root_record = {
        .type = CEP_FLAT_RECORD_CELL_DESC,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0u,
        .key = {
            .data = key_bytes,
            .size = key_size,
        },
        .body = {
            .data = body_bytes,
            .size = body_size,
        },
    };

    if (!cep_flat_serializer_emit(serializer, &root_record))
        goto exit;

    cep_free(key_bytes);
    key_bytes = NULL;
    cep_free(body_bytes);
    body_bytes = NULL;

    cepFlatChildDescriptor* children = NULL;
    size_t child_count = 0u;
    uint8_t organiser = 0u;
    if (!cep_flat_collect_children(canonical, &children, &child_count, &organiser))
        goto exit;

    if (child_count) {
        if (!cep_flat_emit_manifest_delta(serializer,
                                          canonical,
                                          children,
                                          child_count,
                                          organiser,
                                          &names))
            goto exit;
        if (!cep_flat_emit_order_delta(serializer,
                                       canonical,
                                       children,
                                       child_count,
                                       organiser,
                                       &names))
            goto exit;
    }

    if (payload_size > inline_len && payload_bytes) {
        uint8_t* chunk_key = NULL;
        uint8_t* chunk_body = NULL;
        size_t chunk_key_size = 0u;
        size_t chunk_body_size = 0u;
        size_t chunk_offset = 0u;
        uint64_t chunk_ordinal = 0u;
        size_t expected_chunk_offset = 0u;
        uint64_t expected_chunk_ordinal = 0u;
        const cepDataNode* live_snapshot = data ? (const cepDataNode*)&data->modified : NULL;

        while (chunk_offset < payload_size) {
            if (chunk_offset != expected_chunk_offset || chunk_ordinal != expected_chunk_ordinal) {
                cep_serialization_debug_log("[serialization][flat] chunk ordering violated (%zu!=%zu or %" PRIu64 "!=%" PRIu64 ")\n",
                                            chunk_offset,
                                            expected_chunk_offset,
                                            chunk_ordinal,
                                            expected_chunk_ordinal);
                goto exit;
            }

            size_t remaining = payload_size - chunk_offset;
            size_t chunk_size = remaining < chunk_limit ? remaining : chunk_limit;

            if (!cep_serialization_build_payload_chunk_key(canonical, chunk_ordinal, &names, &chunk_key, &chunk_key_size))
                goto exit;
            if (!cep_serialization_build_payload_chunk_body(data,
                                                            live_snapshot,
                                                            payload_fp,
                                                            payload_bytes,
                                                            payload_size,
                                                            chunk_offset,
                                                            chunk_size,
                                                            chunk_key,
                                                            chunk_key_size,
                                                            &names,
                                                            &chunk_body,
                                                            &chunk_body_size)) {
                cep_free(chunk_key);
                goto exit;
            }

            cepFlatRecordSpec chunk_record = {
                .type = CEP_FLAT_RECORD_PAYLOAD_CHUNK,
                .version = CEP_FLAT_SERIALIZER_VERSION,
                .flags = 0u,
                .key = {
                    .data = chunk_key,
                    .size = chunk_key_size,
                },
                .body = {
                    .data = chunk_body,
                    .size = chunk_body_size,
                },
            };

            if (!cep_flat_serializer_emit(serializer, &chunk_record)) {
                cep_free(chunk_key);
                cep_free(chunk_body);
                goto exit;
            }

            cep_free(chunk_key);
            cep_free(chunk_body);
            chunk_key = NULL;
            chunk_body = NULL;

            chunk_offset += chunk_size;
            chunk_ordinal++;
            expected_chunk_offset += chunk_size;
            expected_chunk_ordinal++;
        }

        if (expected_chunk_offset != payload_size || chunk_offset != payload_size) {
            cep_serialization_debug_log("[serialization][flat] chunk ordering completion mismatch (%zu/%zu vs %zu)\n",
                                        expected_chunk_offset,
                                        payload_size,
                                        chunk_offset);
            goto exit;
        }
    }

    if (manifest_history_window &&
        !cep_serialization_emit_manifest_history(canonical,
                                                 serializer,
                                                 &names,
                                                 manifest_history_window,
                                                 config.beat_number)) {
        goto exit;
    }

    if (!cep_serialization_emit_payload_history(canonical,
                                                serializer,
                                                &names,
                                                chunk_limit,
                                                payload_history_window))
        goto exit;

    if (!cep_flat_namepool_emit(&names, serializer))
        goto exit;

    if (!cep_flat_serializer_finish(serializer, write, context))
        goto exit;

    ok = true;

exit:
    if (key_bytes)
        cep_free(key_bytes);
    if (body_bytes)
        cep_free(body_bytes);
    if (children)
        cep_free(children);
    cep_flat_namepool_clear(&names);
    cep_flat_serializer_destroy(serializer);
    return ok;
}

static size_t cep_serialization_varint_length(uint64_t value) {
    size_t length = 1u;
    while (value >= 0x80u) {
        value >>= 7u;
        length++;
    }
    return length;
}

static uint8_t* cep_serialization_write_varint(uint64_t value, uint8_t* dst) {
    do {
        uint8_t byte = (uint8_t)(value & 0x7Fu);
        value >>= 7u;
        if (value)
            byte |= 0x80u;
        *dst++ = byte;
    } while (value);
    return dst;
}

static bool cep_serialization_body_reserve(uint8_t** buffer,
                                           size_t* capacity,
                                           size_t needed_total) {
    if (!buffer || !capacity)
        return false;
    if (*capacity >= needed_total)
        return true;

    size_t new_capacity = *capacity ? *capacity : 64u;
    while (new_capacity < needed_total) {
        size_t doubled = new_capacity << 1u;
        if (doubled <= new_capacity) {
            new_capacity = needed_total;
            break;
        }
        new_capacity = doubled;
    }

    uint8_t* grown = *buffer ? cep_realloc(*buffer, new_capacity) : cep_malloc(new_capacity);
    if (!grown)
        return false;

    *buffer = grown;
    *capacity = new_capacity;
    return true;
}


static bool cep_serialization_build_cell_desc_body(const cepCell* cell,
                                                   const cepData* data,
                                                   uint64_t payload_fp,
                                                   const void* inline_payload,
                                                   size_t inline_length,
                                                   size_t payload_size,
                                                   const uint8_t* payload_hash,
                                                   cepFlatNamepoolCollector* names,
                                                   uint8_t** out_body,
                                                   size_t* out_body_size) {
    if (!cell || !out_body || !out_body_size)
        return false;

    uint8_t* body = NULL;
    size_t capacity = 0u;
    size_t size = 0u;
    bool ok = false;

#define BODY_RESERVE(extra)                                                             \
    do {                                                                                \
        if (!cep_serialization_body_reserve(&body, &capacity, size + (extra)))          \
            goto exit;                                                                  \
    } while (0)

#define BODY_APPEND_U8(value)                                                           \
    do {                                                                                \
        BODY_RESERVE(1u);                                                               \
        body[size++] = (uint8_t)(value);                                                \
    } while (0)

#define BODY_APPEND_U16(value)                                                          \
    do {                                                                                \
        uint16_t v__ = (uint16_t)(value);                                               \
        BODY_RESERVE(sizeof v__);                                                       \
        memcpy(body + size, &v__, sizeof v__);                                          \
        size += sizeof v__;                                                             \
    } while (0)

#define BODY_APPEND_VARINT(value)                                                       \
    do {                                                                                \
        size_t len__ = cep_serialization_varint_length((uint64_t)(value));              \
        BODY_RESERVE(len__);                                                            \
        cep_serialization_write_varint((uint64_t)(value), body + size);                 \
        size += len__;                                                                  \
    } while (0)

#define BODY_APPEND_BYTES(ptr, len)                                                     \
    do {                                                                                \
        size_t len__ = (size_t)(len);                                                   \
        if (len__) {                                                                    \
            BODY_RESERVE(len__);                                                        \
            memcpy(body + size, (ptr), len__);                                          \
            size += len__;                                                              \
        }                                                                               \
    } while (0)

    BODY_APPEND_U8(cell->metacell.type & 0xFFu);
    if (names) {
        const cepDT* cell_name = cep_cell_get_name(cell);
        if (cell_name) {
            if (!cep_flat_namepool_register_id(names, cell_name->domain) ||
                !cep_flat_namepool_register_id(names, cell_name->tag)) {
                goto exit;
            }
        }
    }

    uint16_t store_descriptor = cep_flat_store_descriptor(cell);
    BODY_APPEND_U16(store_descriptor);

    BODY_APPEND_VARINT(cell->created);

    cepOpCount latest = cep_cell_latest_timestamp(cell);
    BODY_APPEND_VARINT(latest);

    uint16_t meta_mask = 0u;
    if (cep_cell_is_deleted(cell))
        meta_mask |= CEP_FLAT_CELL_META_TOMBSTONE;
    if (cep_cell_is_veiled(cell))
        meta_mask |= CEP_FLAT_CELL_META_VEILED;

    uint8_t revision[16] = {0};
    cep_flat_compute_revision_id(cell,
                                 data,
                                 store_descriptor,
                                 meta_mask,
                                 payload_fp,
                                 inline_payload,
                                 inline_length,
                                 revision);
    BODY_APPEND_BYTES(revision, sizeof revision);

    uint8_t payload_kind = data ? (uint8_t)data->datatype : 0u;
    BODY_APPEND_U8(payload_kind);
    if (names && data) {
        if (!cep_flat_namepool_register_id(names, data->dt.domain) ||
            !cep_flat_namepool_register_id(names, data->dt.tag)) {
            goto exit;
        }
    }

    if (payload_fp) {
        BODY_APPEND_VARINT(sizeof payload_fp);
        BODY_APPEND_BYTES(&payload_fp, sizeof payload_fp);
    } else {
        BODY_APPEND_VARINT(0u);
    }

    BODY_APPEND_VARINT(inline_length);
    if (inline_length)
        BODY_APPEND_BYTES(inline_payload, inline_length);

    if (payload_hash && payload_size) {
        uint8_t payload_ref_buf[4u + (2u * 10u) + CEP_FLAT_HASH_SIZE];
        size_t payload_ref_len = 0u;
        payload_ref_buf[payload_ref_len++] = (uint8_t)CEP_FLAT_PAYLOAD_REF_INLINE;
        payload_ref_buf[payload_ref_len++] = (uint8_t)CEP_FLAT_HASH_BLAKE3_256;
        payload_ref_buf[payload_ref_len++] = (uint8_t)CEP_FLAT_COMPRESSION_NONE;
        payload_ref_buf[payload_ref_len++] = (uint8_t)cep_serialization_aead_mode();

        size_t size_len = cep_serialization_varint_length(payload_size);
        if (payload_ref_len + size_len > sizeof payload_ref_buf)
            goto exit;
        cep_serialization_write_varint(payload_size, payload_ref_buf + payload_ref_len);
        payload_ref_len += size_len;

        size_t hash_len = CEP_FLAT_HASH_SIZE;
        size_t hash_len_var = cep_serialization_varint_length(hash_len);
        if (payload_ref_len + hash_len_var + hash_len > sizeof payload_ref_buf)
            goto exit;
        cep_serialization_write_varint(hash_len, payload_ref_buf + payload_ref_len);
        payload_ref_len += hash_len_var;
        memcpy(payload_ref_buf + payload_ref_len, payload_hash, hash_len);
        payload_ref_len += hash_len;

        BODY_APPEND_VARINT(payload_ref_len);
        BODY_APPEND_BYTES(payload_ref_buf, payload_ref_len);
    } else {
        BODY_APPEND_VARINT(0u);
    }

    BODY_APPEND_VARINT(0u); /* namepool_map_ref placeholder */

    BODY_APPEND_U16(meta_mask);

    *out_body = body;
    *out_body_size = size;
    ok = true;

exit:
    if (!ok && body)
        cep_free(body);

#undef BODY_RESERVE
#undef BODY_APPEND_U8
#undef BODY_APPEND_U16
#undef BODY_APPEND_VARINT
#undef BODY_APPEND_BYTES

    return ok;
}

static bool cep_serialization_build_payload_chunk_key(const cepCell* cell,
                                                      uint64_t chunk_ordinal,
                                                      cepFlatNamepoolCollector* names,
                                                      uint8_t** out_key,
                                                      size_t* out_key_size) {
    if (!cell || !out_key || !out_key_size)
        return false;

    uint8_t* base = NULL;
    size_t base_size = 0u;
    if (!cep_flat_build_key(cell, CEP_FLAT_RECORD_PAYLOAD_CHUNK, names, &base, &base_size))
        return false;

    size_t ordinal_len = cep_serialization_varint_length(chunk_ordinal);
    uint8_t* key = cep_malloc(base_size + ordinal_len);
    memcpy(key, base, base_size);
    cep_serialization_write_varint(chunk_ordinal, key + base_size);

    *out_key = key;
    *out_key_size = base_size + ordinal_len;
    cep_free(base);
    return true;
}

static uint8_t cep_serialization_flat_aead_from_secdata(uint8_t enc_mode) {
    switch ((cepAeadMode)enc_mode) {
      case CEP_SECDATA_AEAD_CHACHA20:
        return CEP_FLAT_AEAD_CHACHA20_POLY1305;
      case CEP_SECDATA_AEAD_XCHACHA20:
        return CEP_FLAT_AEAD_XCHACHA20_POLY1305;
      default:
        return CEP_FLAT_AEAD_NONE;
    }
}

static bool cep_serialization_build_payload_chunk_body(const cepData* data,
                                                       const cepDataNode* snapshot,
                                                       uint64_t payload_fp,
                                                       const void* payload_bytes,
                                                       size_t total_size,
                                                       size_t chunk_offset,
                                                       size_t chunk_size,
                                                       const uint8_t* chunk_key,
                                                       size_t chunk_key_size,
                                                       cepFlatNamepoolCollector* names,
                                                       uint8_t** out_body,
                                                       size_t* out_body_size) {
    if (!data || !payload_bytes || !out_body || !out_body_size)
        return false;
    if (chunk_size == 0u || chunk_offset > total_size || chunk_offset + chunk_size > total_size)
        return false;

    uint8_t* body = NULL;
    size_t capacity = 0u;
    size_t size = 0u;
    bool ok = false;

#define BODY_RESERVE(extra)                                                             \
    do {                                                                                \
        if (!cep_serialization_body_reserve(&body, &capacity, size + (extra)))          \
            goto exit;                                                                  \
    } while (0)

#define BODY_APPEND_U8(value)                                                           \
    do {                                                                                \
        BODY_RESERVE(1u);                                                               \
        body[size++] = (uint8_t)(value);                                                \
    } while (0)

#define BODY_APPEND_VARINT(value)                                                       \
    do {                                                                                \
        size_t len__ = cep_serialization_varint_length((uint64_t)(value));              \
        BODY_RESERVE(len__);                                                            \
        cep_serialization_write_varint((uint64_t)(value), body + size);                 \
        size += len__;                                                                  \
    } while (0)

#define BODY_APPEND_BYTES(ptr, len)                                                     \
    do {                                                                                \
        size_t len__ = (size_t)(len);                                                   \
        if (len__) {                                                                    \
            BODY_RESERVE(len__);                                                        \
            memcpy(body + size, (ptr), len__);                                          \
            size += len__;                                                              \
        }                                                                               \
    } while (0)

    BODY_APPEND_U8((uint8_t)data->datatype);
    if (names) {
        if (!cep_flat_namepool_register_id(names, data->dt.domain) ||
            !cep_flat_namepool_register_id(names, data->dt.tag)) {
            goto exit;
        }
    }
    BODY_APPEND_VARINT(total_size);
    BODY_APPEND_VARINT(chunk_offset);
    BODY_APPEND_VARINT(chunk_size);

    if (payload_fp) {
        BODY_APPEND_VARINT(sizeof payload_fp);
        BODY_APPEND_BYTES(&payload_fp, sizeof payload_fp);
    } else {
        BODY_APPEND_VARINT(0u);
    }

    uint8_t aad_hash[CEP_FLAT_HASH_SIZE];
    uint8_t nonce_buf[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0};
    size_t nonce_len = 0u;
    uint8_t aead_mode = (uint8_t)CEP_FLAT_AEAD_NONE;
    uint8_t* encrypted = NULL;
    size_t encrypted_len = 0u;

    bool snapshot_secured = snapshot && (snapshot->mode_flags & CEP_SECDATA_FLAG_SECURED);
    bool snapshot_encrypted = snapshot_secured && (snapshot->mode_flags & CEP_SECDATA_FLAG_ENCRYPTED);
    if (snapshot_encrypted && (chunk_offset != 0u || chunk_size != total_size)) {
        cep_serialization_debug_log("[serialization][flat] secured payload chunking violated (offset=%zu size=%zu total=%zu)\n",
                                    chunk_offset,
                                    chunk_size,
                                    total_size);
        goto exit;
    }

    const uint8_t* chunk_ptr = (const uint8_t*)payload_bytes + chunk_offset;
    bool encrypt = !snapshot_encrypted &&
                   chunk_key && chunk_key_size &&
                   cep_serialization_aead_ready() &&
                   cep_serialization_aead_mode() != CEP_SERIALIZATION_AEAD_MODE_NONE;

    if (snapshot_encrypted) {
        aead_mode = cep_serialization_flat_aead_from_secdata(snapshot->secmeta.enc_mode);
        nonce_len = snapshot->sec_nonce_len;
        if (nonce_len > sizeof nonce_buf || nonce_len == 0u)
            goto exit;
        if (nonce_len)
            memcpy(nonce_buf, snapshot->sec_nonce, nonce_len);
        size_t copy_len = sizeof aad_hash;
        if (copy_len > CEP_SECDATA_AAD_BYTES)
            copy_len = CEP_SECDATA_AAD_BYTES;
        memcpy(aad_hash, snapshot->sec_aad_hash, copy_len);
        if (copy_len < sizeof aad_hash)
            memset(aad_hash + copy_len, 0, sizeof aad_hash - copy_len);
    } else if (encrypt) {
        if (!cep_serialization_aead_encrypt_chunk(chunk_key,
                                                  chunk_key_size,
                                                  payload_fp,
                                                  chunk_offset,
                                                  chunk_size,
                                                  total_size,
                                                  chunk_ptr,
                                                  &encrypted,
                                                  &encrypted_len,
                                                  nonce_buf,
                                                  &nonce_len,
                                                  aad_hash)) {
            goto exit;
        }
        aead_mode = (uint8_t)cep_serialization_aead_mode();
    } else {
        cep_serialization_compute_aad_hash(chunk_key, chunk_key_size, aad_hash);
    }

    BODY_APPEND_U8(aead_mode);
    BODY_APPEND_VARINT(nonce_len);
    if (nonce_len)
        BODY_APPEND_BYTES(nonce_buf, nonce_len);
    BODY_APPEND_BYTES(aad_hash, sizeof aad_hash);

    if (encrypted) {
        BODY_APPEND_BYTES(encrypted, encrypted_len);
        sodium_memzero(encrypted, encrypted_len);
        cep_free(encrypted);
        encrypted = NULL;
    } else {
        BODY_APPEND_BYTES(chunk_ptr, chunk_size);
    }

    *out_body = body;
    *out_body_size = size;
    ok = true;

exit:
    if (!ok && body)
        cep_free(body);
    if (encrypted) {
        sodium_memzero(encrypted, encrypted_len);
        cep_free(encrypted);
    }

#undef BODY_RESERVE
#undef BODY_APPEND_U8
#undef BODY_APPEND_VARINT
#undef BODY_APPEND_BYTES

    return ok;
}

static bool cep_serialization_key_append_bytes(uint8_t** key,
                                               size_t* key_size,
                                               const void* bytes,
                                               size_t len) {
    if (!key || !key_size || !bytes || !len)
        return true;
    uint8_t* grown = cep_realloc(*key, *key_size + len);
    if (!grown)
        return false;
    memcpy(grown + *key_size, bytes, len);
    *key = grown;
    *key_size += len;
    return true;
}

static bool cep_serialization_key_append_varint(uint8_t** key,
                                                size_t* key_size,
                                                uint64_t value) {
    if (!key || !key_size)
        return false;
    size_t len = cep_serialization_varint_length(value);
    uint8_t* grown = cep_realloc(*key, *key_size + len);
    if (!grown)
        return false;
    cep_serialization_write_varint(value, grown + *key_size);
    *key = grown;
    *key_size += len;
    return true;
}

static void cep_serialization_history_revision(const cepCell* cell,
                                               cepOpCount snapshot,
                                               uint64_t page_id,
                                               uint8_t out[16]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (cell) {
        const cepDT* name = cep_cell_get_name(cell);
        if (name)
            blake3_hasher_update(&hasher, name, sizeof *name);
    }
    blake3_hasher_update(&hasher, &snapshot, sizeof snapshot);
    blake3_hasher_update(&hasher, &page_id, sizeof page_id);
    blake3_hasher_finalize(&hasher, out, 16);
}

static void cep_serialization_write_name_bytes(uint8_t* dst, const cepDT* name) {
    if (!dst)
        return;
    cepDT clean = name ? cep_dt_clean(name) : (cepDT){0};
    uint64_t domain = clean.domain;
    uint64_t tag = clean.tag;
    memcpy(dst, &domain, sizeof domain);
    memcpy(dst + sizeof domain, &tag, sizeof tag);
    dst[16] = clean.glob ? 1u : 0u;
}

static uint8_t cep_serialization_range_kind(uint8_t organiser) {
    return organiser == CEP_FLAT_ORGANISER_HASH ? 1u : 0u;
}

static bool cep_serialization_collect_children_snapshot(const cepCell* parent,
                                                        cepOpCount snapshot,
                                                        cepFlatChildDescriptor** out_children,
                                                        size_t* out_count,
                                                        uint8_t* organiser) {
    if (!out_children || !out_count)
        return false;
    *out_children = NULL;
    *out_count = 0u;
    if (organiser)
        *organiser = 0u;

    if (!parent)
        return true;

    cepCell* canonical = cep_link_pull((cepCell*)parent);
    if (!canonical || !canonical->store)
        return true;

    size_t capacity = canonical->store->chdCount ? canonical->store->chdCount : 4u;
    cepFlatChildDescriptor* children = NULL;
    size_t count = 0u;

    for (cepCell* child = cep_cell_first_past(canonical, snapshot);
         child;
         child = cep_cell_next_past(canonical, child, snapshot)) {
        cepCell* resolved = cep_link_pull(child);
        if (!resolved)
            continue;
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name)
            continue;
        if (!children) {
            children = cep_malloc(capacity * sizeof *children);
            if (!children)
                return false;
        } else if (count == capacity) {
            size_t new_cap = capacity ? capacity << 1u : 8u;
            cepFlatChildDescriptor* grown = cep_realloc(children, new_cap * sizeof *children);
            if (!grown) {
                cep_free(children);
                return false;
            }
            children = grown;
            capacity = new_cap;
        }

        cepFlatChildDescriptor desc = {
            .name = *name,
            .flags = 0u,
            .position = (uint16_t)((count > UINT16_MAX) ? UINT16_MAX : count),
            .has_fingerprint = false,
            .fingerprint = 0u,
            .cell_type = (uint8_t)resolved->metacell.type,
            .delta_flags = 0u,
        };
        children[count++] = desc;
    }

    if (!count) {
        if (children)
            cep_free(children);
        return true;
    }

    *out_children = children;
    *out_count = count;
    if (organiser)
        *organiser = (uint8_t)(cep_flat_store_descriptor(canonical) >> 8);
    return true;
}

static bool cep_serialization_emit_manifest_history_page(cepFlatSerializer* serializer,
                                                         const cepCell* parent,
                                                         cepOpCount snapshot,
                                                         const cepFlatChildDescriptor* children,
                                                         size_t child_count,
                                                         const cepFlatChildDescriptor* next_child,
                                                         uint8_t organiser,
                                                         cepFlatNamepoolCollector* names,
                                                         uint64_t page_id) {
    if (!serializer || !parent || !children || !child_count)
        return false;

    uint8_t* key = NULL;
    size_t key_size = 0u;
    if (!cep_flat_build_key(parent, CEP_FLAT_RECORD_MANIFEST_HISTORY, names, &key, &key_size))
        return false;
    if (!cep_serialization_key_append_varint(&key, &key_size, page_id)) {
        cep_free(key);
        return false;
    }

    uint8_t revision[16];
    cep_serialization_history_revision(parent, snapshot, page_id, revision);
    if (!cep_serialization_key_append_bytes(&key, &key_size, revision, sizeof revision)) {
        cep_free(key);
        return false;
    }

    uint8_t* body = NULL;
    size_t capacity = 0u;
    size_t size = 0u;
    bool ok = false;

#define MAN_BODY_RESERVE(extra) \
    do { \
        if (!cep_serialization_body_reserve(&body, &capacity, size + (extra))) \
            goto manifest_history_cleanup; \
    } while (0)
#define MAN_BODY_APPEND_U8(value) \
    do { MAN_BODY_RESERVE(1u); body[size++] = (uint8_t)(value); } while (0)
#define MAN_BODY_APPEND_U16(value) \
    do { uint16_t v__ = (uint16_t)(value); MAN_BODY_RESERVE(sizeof v__); memcpy(body + size, &v__, sizeof v__); size += sizeof v__; } while (0)
#define MAN_BODY_APPEND_VARINT(value) \
    do { size_t len__ = cep_serialization_varint_length((uint64_t)(value)); MAN_BODY_RESERVE(len__); cep_serialization_write_varint((uint64_t)(value), body + size); size += len__; } while (0)
#define MAN_BODY_APPEND_BYTES(ptr, len) \
    do { size_t len__ = (size_t)(len); if (len__) { MAN_BODY_RESERVE(len__); memcpy(body + size, (ptr), len__); size += len__; } } while (0)

    MAN_BODY_APPEND_VARINT(snapshot);
    MAN_BODY_APPEND_U8(cep_serialization_range_kind(organiser));

    uint8_t range_min[17] = {0};
    size_t range_min_len = 0u;
    if (child_count) {
        cep_serialization_write_name_bytes(range_min, &children[0].name);
        range_min_len = sizeof range_min;
        if (names) {
            (void)cep_flat_namepool_register_id(names, children[0].name.domain);
            (void)cep_flat_namepool_register_id(names, children[0].name.tag);
        }
    }
    MAN_BODY_APPEND_VARINT(range_min_len);
    MAN_BODY_APPEND_BYTES(range_min, range_min_len);

    uint8_t range_max[17] = {0};
    size_t range_max_len = 0u;
    if (next_child) {
        cep_serialization_write_name_bytes(range_max, &next_child->name);
        range_max_len = sizeof range_max;
        if (names) {
            (void)cep_flat_namepool_register_id(names, next_child->name.domain);
            (void)cep_flat_namepool_register_id(names, next_child->name.tag);
        }
    }
    MAN_BODY_APPEND_VARINT(range_max_len);
    MAN_BODY_APPEND_BYTES(range_max, range_max_len);

    MAN_BODY_APPEND_VARINT(child_count);

    for (size_t i = 0; i < child_count; ++i) {
        const cepFlatChildDescriptor* child = &children[i];
        if (names) {
            (void)cep_flat_namepool_register_id(names, child->name.domain);
            (void)cep_flat_namepool_register_id(names, child->name.tag);
        }
        MAN_BODY_APPEND_U8(1u); /* snapshot uses ADD opcode */
        uint8_t name_bytes[17];
        cep_serialization_write_name_bytes(name_bytes, &child->name);
        MAN_BODY_APPEND_BYTES(name_bytes, sizeof name_bytes);
        MAN_BODY_APPEND_U16(0u);
        uint8_t child_revision[16] = {0};
        if (child->has_fingerprint)
            memcpy(child_revision, &child->fingerprint, sizeof child->fingerprint);
        MAN_BODY_APPEND_BYTES(child_revision, sizeof child_revision);
    }

    {
        cepFlatRecordSpec record = {
            .type = CEP_FLAT_RECORD_MANIFEST_HISTORY,
            .version = CEP_FLAT_SERIALIZER_VERSION,
            .flags = 0u,
            .key = {.data = key, .size = key_size},
            .body = {.data = body, .size = size},
        };
        ok = cep_flat_serializer_emit(serializer, &record);
    }

manifest_history_cleanup:
    if (!ok && body)
        cep_free(body);
    if (key)
        cep_free(key);

#undef MAN_BODY_RESERVE
#undef MAN_BODY_APPEND_U8
#undef MAN_BODY_APPEND_U16
#undef MAN_BODY_APPEND_VARINT
#undef MAN_BODY_APPEND_BYTES

    return ok;
}

static bool cep_serialization_emit_manifest_history(const cepCell* cell,
                                                    cepFlatSerializer* serializer,
                                                    cepFlatNamepoolCollector* names,
                                                    uint32_t history_window,
                                                    cepOpCount frame_beat) {
    if (!cell || !serializer || !history_window)
        return true;

    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical || !canonical->store || !canonical->store->chdCount)
        return true;

    cepOpCount current = frame_beat ? frame_beat : cep_beat_index();
    bool emitted = false;

    for (uint32_t offset = 1u; offset <= history_window; ++offset) {
        if (current < offset)
            break;
        cepOpCount snapshot = current - offset;

        cepFlatChildDescriptor* snapshot_children = NULL;
        size_t child_count = 0u;
        uint8_t organiser = 0u;
        if (!cep_serialization_collect_children_snapshot(canonical,
                                                         snapshot,
                                                         &snapshot_children,
                                                         &child_count,
                                                         &organiser)) {
            return false;
        }
        if (!child_count) {
            if (snapshot_children)
                cep_free(snapshot_children);
            continue;
        }

        size_t page_limit = CEP_SERIALIZATION_HISTORY_PAGE_LIMIT
                                ? CEP_SERIALIZATION_HISTORY_PAGE_LIMIT
                                : child_count;
        size_t idx = 0u;
        uint64_t page_id = 0u;
        while (idx < child_count) {
            size_t page_count = child_count - idx;
            if (page_count > page_limit)
                page_count = page_limit;
            const cepFlatChildDescriptor* next_child = (idx + page_count < child_count)
                                                           ? &snapshot_children[idx + page_count]
                                                           : NULL;
            if (!cep_serialization_emit_manifest_history_page(serializer,
                                                              canonical,
                                                              snapshot,
                                                              snapshot_children + idx,
                                                              page_count,
                                                              next_child,
                                                              organiser,
                                                              names,
                                                              page_id)) {
                cep_free(snapshot_children);
                return false;
            }
            idx += page_count;
            page_id++;
        }

        cep_free(snapshot_children);
        emitted = true;
    }

    if (emitted)
        cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_MANIFEST_HISTORY);
    return true;
}

static bool cep_serialization_emit_payload_history(const cepCell* cell,
                                                   cepFlatSerializer* serializer,
                                                   cepFlatNamepoolCollector* names,
                                                   size_t chunk_limit,
                                                   uint32_t history_window) {
    if (!cell || !serializer || !history_window)
        return true;
    cell = cep_link_pull((cepCell*)cell);
    if (!cell || !cell->data)
        return true;

    const cepData* data = cell->data;
    const cepDataNode* node = data->past;
    if (!node)
        return true;

    if (!chunk_limit)
        chunk_limit = CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD;

    cepOpCount beat_now = cep_beat_index();
    cepOpCount cutoff = (history_window >= beat_now) ? 0u : (beat_now - history_window);

    uint16_t store_descriptor = cep_flat_store_descriptor(cell);
    uint16_t meta_mask = 0u;
    if (cep_cell_is_deleted(cell))
        meta_mask |= CEP_FLAT_CELL_META_TOMBSTONE;
    if (cep_cell_is_veiled(cell))
        meta_mask |= CEP_FLAT_CELL_META_VEILED;

    bool emitted = false;

    for (const cepDataNode* cursor = node; cursor; cursor = cursor->past) {
        cepOpCount modified = cursor->modified;
        if (modified < cutoff)
            break;
        if (!cursor->size)
            continue;
        if (data->datatype != CEP_DATATYPE_VALUE && data->datatype != CEP_DATATYPE_DATA)
            continue;

        const uint8_t* payload_bytes = NULL;
        if (data->datatype == CEP_DATATYPE_VALUE)
            payload_bytes = cursor->value;
        else if (data->datatype == CEP_DATATYPE_DATA)
            payload_bytes = cursor->data ? (const uint8_t*)cursor->data : NULL;
        if (!payload_bytes && cursor->size)
            continue;

        const void* inline_payload = NULL;
        size_t inline_length = 0u;
        if (data->datatype == CEP_DATATYPE_VALUE && cursor->size && cursor->size <= 64u) {
            inline_payload = cursor->value;
            inline_length = cursor->size;
        }
        if (inline_payload && (cursor->mode_flags & CEP_SECDATA_FLAG_INLINE_FORBIDDEN)) {
            inline_payload = NULL;
            inline_length = 0u;
        }

        uint8_t revision[16] = {0};
        uint64_t revision_fp = (cursor->mode_flags & CEP_SECDATA_FLAG_SECURED && cursor->secmeta.payload_fp)
                                   ? cursor->secmeta.payload_fp
                                   : cursor->hash;
        cep_flat_compute_revision_id(cell,
                                     data,
                                     store_descriptor,
                                     meta_mask,
                                     revision_fp,
                                     inline_payload,
                                     inline_length,
                                     revision);

        uint8_t* base_key = NULL;
        size_t base_key_size = 0u;
        if (!cep_flat_build_key(cell, CEP_FLAT_RECORD_PAYLOAD_HISTORY, names, &base_key, &base_key_size))
            return false;

        size_t revision_key_size = base_key_size + sizeof revision;
        uint8_t* revision_key = cep_malloc(revision_key_size);
        if (!revision_key) {
            cep_free(base_key);
            return false;
        }
        memcpy(revision_key, base_key, base_key_size);
        memcpy(revision_key + base_key_size, revision, sizeof revision);
        cep_free(base_key);

        uint64_t node_payload_fp = (cursor->mode_flags & CEP_SECDATA_FLAG_SECURED && cursor->secmeta.payload_fp)
                                       ? cursor->secmeta.payload_fp
                                       : cursor->hash;
        size_t chunk_offset = 0u;
        uint64_t chunk_ordinal = 0u;
        while (chunk_offset < cursor->size) {
            size_t chunk_size = cursor->size - chunk_offset;
            size_t node_chunk_limit = (cursor->mode_flags & CEP_SECDATA_FLAG_SECURED) ? cursor->size : chunk_limit;
            if (chunk_size > node_chunk_limit)
                chunk_size = node_chunk_limit;

            size_t ordinal_len = cep_serialization_varint_length(chunk_ordinal);
            size_t chunk_key_size = revision_key_size + ordinal_len;
            uint8_t* chunk_key = cep_malloc(chunk_key_size);
            if (!chunk_key) {
                cep_free(revision_key);
                return false;
            }
            memcpy(chunk_key, revision_key, revision_key_size);
            cep_serialization_write_varint(chunk_ordinal, chunk_key + revision_key_size);

            uint8_t* chunk_body = NULL;
            size_t chunk_body_size = 0u;
            if (!cep_serialization_build_payload_chunk_body(data,
                                                            cursor,
                                                            node_payload_fp,
                                                            payload_bytes,
                                                            cursor->size,
                                                            chunk_offset,
                                                            chunk_size,
                                                            chunk_key,
                                                            chunk_key_size,
                                                            names,
                                                            &chunk_body,
                                                            &chunk_body_size)) {
                cep_free(chunk_key);
                cep_free(revision_key);
                return false;
            }

            size_t beat_len = cep_serialization_varint_length(modified);
            uint8_t* history_body = cep_malloc(beat_len + chunk_body_size);
            if (!history_body) {
                cep_free(chunk_body);
                cep_free(chunk_key);
                cep_free(revision_key);
                return false;
            }
            uint8_t* cursor_ptr = history_body;
            cursor_ptr = cep_serialization_write_varint(modified, cursor_ptr);
            memcpy(cursor_ptr, chunk_body, chunk_body_size);

            cep_free(chunk_body);

            cepFlatRecordSpec record = {
                .type = CEP_FLAT_RECORD_PAYLOAD_HISTORY,
                .version = CEP_FLAT_SERIALIZER_VERSION,
                .flags = 0u,
                .key = {
                    .data = chunk_key,
                    .size = chunk_key_size,
                },
                .body = {
                    .data = history_body,
                    .size = beat_len + chunk_body_size,
                },
            };

            if (!cep_flat_serializer_emit(serializer, &record)) {
                cep_free(chunk_key);
                cep_free(history_body);
                cep_free(revision_key);
                return false;
            }

            cep_free(chunk_key);
            cep_free(history_body);

            chunk_offset += chunk_size;
            chunk_ordinal++;
        }

        cep_free(revision_key);
        emitted = true;
    }

    if (emitted)
        cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_PAYLOAD_HISTORY);

    return true;
}


#ifdef CEP_ENABLE_DEBUG
#define CEP_SERIALIZATION_DEBUG_PRINTF(...)                                            \
    do {                                                                              \
        if (cep_serialization_debug_logging_enabled()) {                              \
            CEP_DEBUG_PRINTF(__VA_ARGS__);                                            \
        }                                                                             \
    } while (0)
#else
#define CEP_SERIALIZATION_DEBUG_PRINTF(...) do { } while (0)
#endif

CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));
CEP_DEFINE_STATIC_DT(dt_list_type_default, CEP_ACRO("CEP"), CEP_WORD("list"));
CEP_DEFINE_STATIC_DT(dt_stream_outcome, CEP_ACRO("CEP"), CEP_WORD("outcome"));

#define SERIAL_RECORD_MANIFEST_BASE    0x01u
#define SERIAL_RECORD_MANIFEST_DELTA   0x02u
#define SERIAL_RECORD_MANIFEST_CHILDREN 0x03u

#define SERIAL_RECORD_NAMEPOOL_MAP     0x05u

#define SERIAL_CHILD_FLAG_TOMBSTONE    0x01u
#define SERIAL_CHILD_FLAG_VEILED       0x02u
#define SERIAL_CHILD_FLAG_FINGERPRINT  0x04u

#define SERIAL_NAMEPOOL_FLAG_MORE      0x01u
#define SERIAL_NAMEPOOL_FLAG_GLOB      0x01u

#define CEP_SERIALIZATION_NAMEPOOL_MAX_PAYLOAD 4096u

#define SERIAL_BASE_FLAG_CHILDREN      0x01u
#define SERIAL_BASE_FLAG_PAYLOAD       0x02u
#define SERIAL_BASE_FLAG_VEILED        0x04u
#define SERIAL_BASE_FLAG_CHILDREN_SPLIT 0x08u

#define SERIAL_ORGANISER_INSERTION         0x01u
#define SERIAL_ORGANISER_NAME              0x02u
#define SERIAL_ORGANISER_FUNCTION          0x03u
#define SERIAL_ORGANISER_HASH              0x04u
#define SERIAL_ORGANISER_FUNCTION_OCTREE   0x05u

#define SERIAL_STORAGE_FLAG_METADATA   0x80u

#define SERIAL_OCTREE_METADATA_SIZE    (sizeof(float) * 5u + sizeof(uint16_t) * 2u)
#define SERIAL_STORE_META_TLV_HEADER_SIZE 4u
#define SERIAL_COMPARATOR_METADATA_PAYLOAD_SIZE (sizeof(uint64_t) * 2u + 1u + 3u + sizeof(uint32_t) * 2u)
#define SERIAL_COMPARATOR_METADATA_SIZE (SERIAL_STORE_META_TLV_HEADER_SIZE + SERIAL_COMPARATOR_METADATA_PAYLOAD_SIZE)
#define SERIAL_STORE_META_TYPE_PAYLOAD_SIZE (sizeof(uint64_t) * 2u + 1u + 3u)
#define SERIAL_STORE_META_TYPE_SIZE (SERIAL_STORE_META_TLV_HEADER_SIZE + SERIAL_STORE_META_TYPE_PAYLOAD_SIZE)
#define SERIAL_STORE_META_TLV_COMPARATOR 0x01u
#define SERIAL_STORE_META_TLV_OCTREE     0x02u
#define SERIAL_STORE_META_TLV_LAYOUT     0x03u
#define SERIAL_STORE_META_TLV_TYPE       0x04u
#define SERIAL_STORE_META_LAYOUT_PAYLOAD_SIZE (sizeof(uint32_t) + sizeof(uint64_t))
#define SERIAL_STORE_METADATA_CAPACITY (SERIAL_STORE_META_TYPE_SIZE + SERIAL_COMPARATOR_METADATA_SIZE + SERIAL_STORE_META_TLV_HEADER_SIZE + SERIAL_OCTREE_METADATA_SIZE + SERIAL_STORE_META_TLV_HEADER_SIZE + SERIAL_STORE_META_LAYOUT_PAYLOAD_SIZE)

#define SERIAL_DELTA_FLAG_ADD          0x01u
#define SERIAL_DELTA_FLAG_DELETE       0x02u
#define SERIAL_DELTA_FLAG_VEIL         0x04u
#define SERIAL_DELTA_FLAG_UNVEIL       0x08u
#define SERIAL_DELTA_FLAG_REORDER      0x10u

#define SERIAL_PROXY_KIND_HANDLE       0x00u
#define SERIAL_PROXY_KIND_STREAM       0x01u

#define SERIAL_PATH_FLAG_POSITION      0x01u

static uint16_t cep_serial_read_be16_buf(const uint8_t* src);
static uint32_t cep_serial_read_be32_buf(const uint8_t* src);
static uint64_t cep_serial_read_be64_buf(const uint8_t* src);
static void cep_serialization_register_builtin_comparators(void);

static cepSerializationRuntimeState*
cep_serialization_state(void)
{
    cepRuntime* runtime = cep_runtime_active();
    if (!runtime)
        runtime = cep_runtime_default();
    cepSerializationRuntimeState* state = cep_runtime_serialization_state(runtime);
    if (state && !state->comparators_initialized) {
        state->comparators_initialized = true;
        cep_serialization_register_builtin_comparators();
    }
    return state;
}

static bool
cep_serialization_emit_scope_enter(void)
{
    cepSerializationRuntimeState* state = cep_serialization_state();
    if (!state)
        return false;
    atomic_fetch_add_explicit(&state->emit_active, 1u, memory_order_acq_rel);
    return true;
}

static void
cep_serialization_emit_scope_exit(bool entered)
{
    if (!entered)
        return;
    cepSerializationRuntimeState* state = cep_serialization_state();
    if (!state)
        return;
    atomic_fetch_sub_explicit(&state->emit_active, 1u, memory_order_acq_rel);
}

static bool
cep_serialization_replay_scope_enter(void)
{
    cepSerializationRuntimeState* state = cep_serialization_state();
    if (!state)
        return false;
    atomic_fetch_add_explicit(&state->replay_active, 1u, memory_order_acq_rel);
    return true;
}

static void
cep_serialization_replay_scope_exit(bool entered)
{
    if (!entered)
        return;
    cepSerializationRuntimeState* state = cep_serialization_state();
    if (!state)
        return;
    atomic_fetch_sub_explicit(&state->replay_active, 1u, memory_order_acq_rel);
}

bool
cep_serialization_is_busy(void)
{
    cepSerializationRuntimeState* state = cep_serialization_state();
    if (!state)
        return false;
    uint32_t emit = atomic_load_explicit(&state->emit_active, memory_order_acquire);
    uint32_t replay = atomic_load_explicit(&state->replay_active, memory_order_acquire);
    return (emit != 0u) || (replay != 0u);
}

void cep_serialization_mark_decision_replay(void) {
    cepSerializationRuntimeState* state = cep_serialization_state();
    if (!state) {
        return;
    }
    state->marked_decision_beat = cep_heartbeat_current();
}

static inline uint16_t cep_serial_to_be16(uint16_t value) {
    return __builtin_bswap16(value);
}

static inline uint32_t cep_serial_to_be32(uint32_t value) {
    return __builtin_bswap32(value);
}

static inline uint64_t cep_serial_to_be64(uint64_t value) {
    return __builtin_bswap64(value);
}

static inline uint16_t cep_serial_from_be16(uint16_t value) {
    return __builtin_bswap16(value);
}

static inline uint32_t cep_serial_from_be32(uint32_t value) {
    return __builtin_bswap32(value);
}

static inline uint64_t cep_serial_from_be64(uint64_t value) {
    return __builtin_bswap64(value);
}

static inline void cep_serialization_write_float(uint8_t** cursor, float value) {
    uint32_t bits = 0u;
    memcpy(&bits, &value, sizeof bits);
    uint32_t be = cep_serial_to_be32(bits);
    memcpy(*cursor, &be, sizeof be);
    *cursor += sizeof be;
}

static inline float cep_serialization_read_float(const uint8_t** cursor) {
    uint32_t be = 0u;
    memcpy(&be, *cursor, sizeof be);
    *cursor += sizeof be;
    uint32_t host = cep_serial_from_be32(be);
    float value = 0.0f;
    memcpy(&value, &host, sizeof value);
    return value;
}

static size_t cep_serialization_store_metadata_octree(const cepCell* cell,
                                                      uint8_t* buffer,
                                                      size_t capacity) {
    if (!cell || !cell->store || cell->store->storage != CEP_STORAGE_OCTREE)
        return 0u;
    if (!buffer || capacity < SERIAL_OCTREE_METADATA_SIZE)
        return 0u;

    const cepOctree* octree = (const cepOctree*)cell->store;
    uint8_t* cursor = buffer;
    const float* center = octree->root.bound.center;
    for (size_t i = 0; i < 3; ++i)
        cep_serialization_write_float(&cursor, center[i]);
    cep_serialization_write_float(&cursor, octree->root.bound.subwide);

    uint16_t max_depth_be = cep_serial_to_be16((uint16_t)octree->maxDepth);
    memcpy(cursor, &max_depth_be, sizeof max_depth_be);
    cursor += sizeof max_depth_be;

    uint16_t max_per_node_be = cep_serial_to_be16((uint16_t)octree->maxPerNode);
    memcpy(cursor, &max_per_node_be, sizeof max_per_node_be);
    cursor += sizeof max_per_node_be;

    cep_serialization_write_float(&cursor, octree->minSubwide);
    return (size_t)(cursor - buffer);
}

static bool cep_serialization_parse_octree_metadata(const uint8_t* buffer,
                                                    size_t size,
                                                    float center[3],
                                                    float* subwide,
                                                    uint16_t* max_depth,
                                                    uint16_t* max_per_node,
                                                    float* min_subwide) {
    if (!buffer || size < SERIAL_OCTREE_METADATA_SIZE || !center || !subwide ||
        !max_depth || !max_per_node || !min_subwide) {
        return false;
    }
    const uint8_t* cursor = buffer;
    for (size_t i = 0; i < 3; ++i)
        center[i] = cep_serialization_read_float(&cursor);
    *subwide = cep_serialization_read_float(&cursor);
    uint16_t max_depth_be = 0u;
    memcpy(&max_depth_be, cursor, sizeof max_depth_be);
    cursor += sizeof max_depth_be;
    *max_depth = cep_serial_from_be16(max_depth_be);

    uint16_t max_per_node_be = 0u;
    memcpy(&max_per_node_be, cursor, sizeof max_per_node_be);
    cursor += sizeof max_per_node_be;
    *max_per_node = cep_serial_from_be16(max_per_node_be);

    *min_subwide = cep_serialization_read_float(&cursor);
    return true;
}

static bool cep_serialization_store_meta_write_layout(const cepCell* cell,
                                                      uint8_t* buffer,
                                                      size_t capacity,
                                                      size_t* out_size) {
    if (!out_size) {
        return false;
    }
    *out_size = 0u;
    if (!cell || !cell->store || !buffer || !capacity)
        return true;

    const cepStore* store = cell->store;
    uint64_t layout_capacity = 0u;
    bool needs_layout = false;

    switch (store->storage) {
      case CEP_STORAGE_ARRAY: {
        const cepArray* array = (const cepArray*)store;
        layout_capacity = array ? (uint64_t)array->capacity : 0u;
        needs_layout = true;
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        const cepPackedQ* queue = (const cepPackedQ*)store;
        layout_capacity = queue ? (uint64_t)queue->nodeCapacity : 0u;
        needs_layout = true;
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        const cepHashTable* table = (const cepHashTable*)store;
        layout_capacity = table ? (uint64_t)table->bucketCount : 0u;
        needs_layout = true;
        break;
      }
      default:
        break;
    }

    if (!needs_layout)
        return true;

    size_t required = SERIAL_STORE_META_TLV_HEADER_SIZE + SERIAL_STORE_META_LAYOUT_PAYLOAD_SIZE;
    if (required > capacity)
        return false;

    buffer[0] = SERIAL_STORE_META_TLV_LAYOUT;
    buffer[1] = 0u;
    uint16_t payload_len_be = cep_serial_to_be16((uint16_t)SERIAL_STORE_META_LAYOUT_PAYLOAD_SIZE);
    memcpy(buffer + 2u, &payload_len_be, sizeof payload_len_be);

    uint8_t* cursor = buffer + SERIAL_STORE_META_TLV_HEADER_SIZE;
    cursor[0] = (uint8_t)store->storage;
    cursor[1] = 0u;
    cursor[2] = 0u;
    cursor[3] = 0u;
    uint64_t capacity_be = cep_serial_to_be64(layout_capacity);
    memcpy(cursor + 4u, &capacity_be, sizeof capacity_be);

    *out_size = required;
    return true;
}

static bool cep_serialization_store_meta_write_comparator(const cepStore* store,
                                                          uint8_t* buffer,
                                                          size_t capacity,
                                                          size_t* written) {
    if (!buffer || !written)
        return false;
    *written = 0u;
    if (!store || !store->compare)
        return true;

    cepCompareInfo info = {0};
    if (!cep_compare_identity(store->compare, &info))
        return false;

    uint32_t max_version = cep_serialization_flat_comparator_max_version();
    if (info.version > max_version) {
        cep_serialization_emit_failure("serialization.store.comparator_version",
                                       NULL,
                                       "comparator version %u exceeds negotiated max %u (domain=%016" PRIx64 " tag=%016" PRIx64 ")",
                                       info.version,
                                       max_version,
                                       (uint64_t)info.identifier.domain,
                                       (uint64_t)info.identifier.tag);
        return false;
    }

    if (capacity < SERIAL_COMPARATOR_METADATA_SIZE)
        return false;

    uint8_t* cursor = buffer;
    cursor[0] = SERIAL_STORE_META_TLV_COMPARATOR;
    cursor[1] = 0u;
    uint16_t payload_len = (uint16_t)SERIAL_COMPARATOR_METADATA_PAYLOAD_SIZE;
    uint16_t payload_be = cep_serial_to_be16(payload_len);
    memcpy(cursor + 2u, &payload_be, sizeof payload_be);
    cursor += SERIAL_STORE_META_TLV_HEADER_SIZE;

    uint64_t domain_be = cep_serial_to_be64(info.identifier.domain);
    memcpy(cursor, &domain_be, sizeof domain_be);
    cursor += sizeof domain_be;

    uint64_t tag_be = cep_serial_to_be64(info.identifier.tag);
    memcpy(cursor, &tag_be, sizeof tag_be);
    cursor += sizeof tag_be;

    *cursor++ = info.identifier.glob ? 1u : 0u;
    *cursor++ = 0u;
    *cursor++ = 0u;
    *cursor++ = 0u;

    uint32_t version_be = cep_serial_to_be32(info.version);
    memcpy(cursor, &version_be, sizeof version_be);
    cursor += sizeof version_be;

    uint32_t flags_be = cep_serial_to_be32(info.flags);
    memcpy(cursor, &flags_be, sizeof flags_be);
    cursor += sizeof flags_be;

    *written = (size_t)(cursor - buffer);
    return true;
}

static bool cep_serialization_store_meta_write_type(const cepStore* store,
                                                    uint8_t* buffer,
                                                    size_t capacity,
                                                    size_t* written) {
    if (!buffer || !written)
        return false;
    *written = 0u;
    if (!store)
        return true;

    const cepDT* dt = &store->dt;
    if (!cep_dt_is_valid(dt))
        return true;

    if (capacity < SERIAL_STORE_META_TYPE_SIZE)
        return false;

    uint8_t* cursor = buffer;
    cursor[0] = SERIAL_STORE_META_TLV_TYPE;
    cursor[1] = 0u;
    uint16_t payload_len = (uint16_t)SERIAL_STORE_META_TYPE_PAYLOAD_SIZE;
    uint16_t payload_be = cep_serial_to_be16(payload_len);
    memcpy(cursor + 2u, &payload_be, sizeof payload_be);
    cursor += SERIAL_STORE_META_TLV_HEADER_SIZE;

    uint64_t domain_be = cep_serial_to_be64(dt->domain);
    memcpy(cursor, &domain_be, sizeof domain_be);
    cursor += sizeof domain_be;

    uint64_t tag_be = cep_serial_to_be64(dt->tag);
    memcpy(cursor, &tag_be, sizeof tag_be);
    cursor += sizeof tag_be;

    *cursor++ = dt->glob ? 1u : 0u;
    *cursor++ = 0u;
    *cursor++ = 0u;
    *cursor++ = 0u;

    *written = (size_t)(cursor - buffer);
    return true;
}

static bool cep_serialization_store_meta_write_octree(const cepCell* cell,
                                                      uint8_t* buffer,
                                                      size_t capacity,
                                                      size_t* written) {
    if (!buffer || !written)
        return false;
    *written = 0u;

    uint8_t payload[SERIAL_OCTREE_METADATA_SIZE] = {0};
    size_t payload_len = cep_serialization_store_metadata_octree(cell, payload, sizeof payload);
    if (!payload_len)
        return true;

    size_t required = SERIAL_STORE_META_TLV_HEADER_SIZE + payload_len;
    if (capacity < required)
        return false;

    buffer[0] = SERIAL_STORE_META_TLV_OCTREE;
    buffer[1] = 0u;
    uint16_t len_be = cep_serial_to_be16((uint16_t)payload_len);
    memcpy(buffer + 2u, &len_be, sizeof len_be);
    memcpy(buffer + 4u, payload, payload_len);
    *written = required;
    return true;
}

static bool cep_serialization_build_store_metadata(const cepCell* cell,
                                                   uint8_t* buffer,
                                                   size_t capacity,
                                                   size_t* out_size) {
    if (!out_size) {
        return false;
    }
    *out_size = 0u;
    if (!cell || !cell->store || !buffer || !capacity)
        return true;

    size_t used = 0u;
    size_t chunk = 0u;
    if (!cep_serialization_store_meta_write_type(cell->store, buffer + used, capacity - used, &chunk))
        return false;
    used += chunk;

    if (!cep_serialization_store_meta_write_comparator(cell->store, buffer + used, capacity - used, &chunk))
        return false;
    used += chunk;

    if (!cep_serialization_store_meta_write_octree(cell, buffer + used, capacity - used, &chunk))
        return false;
    used += chunk;

    if (!cep_serialization_store_meta_write_layout(cell, buffer + used, capacity - used, &chunk))
        return false;
    used += chunk;

    *out_size = used;
    return true;
}

typedef struct {
    bool            has_comparator;
    cepCompareInfo  comparator;
    bool            has_octree;
    const uint8_t*  octree_payload;
    uint16_t        octree_payload_size;
    bool            has_layout;
    uint8_t         layout_storage;
    uint64_t        layout_capacity;
    bool            has_type;
    cepDT           type;
} cepSerializationStoreMeta;

static bool cep_serialization_parse_store_metadata(const uint8_t* buffer,
                                                   size_t size,
                                                   cepSerializationStoreMeta* meta) {
    if (!meta) {
        return false;
    }
    memset(meta, 0, sizeof *meta);
    if (!buffer || !size)
        return true;

    const uint8_t* cursor = buffer;
    size_t remaining = size;
    while (remaining >= SERIAL_STORE_META_TLV_HEADER_SIZE) {
        uint8_t kind = cursor[0];
        uint16_t payload_len = cep_serial_from_be16(*(const uint16_t*)(cursor + 2u));
        cursor += SERIAL_STORE_META_TLV_HEADER_SIZE;
        remaining -= SERIAL_STORE_META_TLV_HEADER_SIZE;
        if (payload_len > remaining)
            return false;

        switch (kind) {
          case SERIAL_STORE_META_TLV_COMPARATOR: {
            if (payload_len < SERIAL_COMPARATOR_METADATA_PAYLOAD_SIZE)
                return false;
            const uint8_t* cmp_cursor = cursor;
            const uint8_t* cmp_end = cursor + payload_len;
            cepCompareInfo info = {0};
            info.identifier.domain = cep_serial_read_be64_buf(cmp_cursor);
            cmp_cursor += sizeof(uint64_t);
            info.identifier.tag = cep_serial_read_be64_buf(cmp_cursor);
            cmp_cursor += sizeof(uint64_t);
            info.identifier.glob = (*cmp_cursor++) ? 1u : 0u;
            cmp_cursor += 3u; /* padding */
            uint32_t version_be = 0u;
            memcpy(&version_be, cmp_cursor, sizeof version_be);
            info.version = cep_serial_from_be32(version_be);
            cmp_cursor += sizeof version_be;
            uint32_t flags_be = 0u;
            memcpy(&flags_be, cmp_cursor, sizeof flags_be);
            info.flags = cep_serial_from_be32(flags_be);
            cmp_cursor += sizeof flags_be;
            meta->comparator = info;
            meta->has_comparator = true;
            cursor = cmp_end;
            break;
          }
          case SERIAL_STORE_META_TLV_OCTREE: {
            meta->octree_payload = cursor;
            meta->octree_payload_size = payload_len;
            meta->has_octree = true;
            cursor += payload_len;
            break;
          }
          case SERIAL_STORE_META_TLV_LAYOUT: {
            if (payload_len < SERIAL_STORE_META_LAYOUT_PAYLOAD_SIZE)
                return false;
            meta->layout_storage = cursor[0];
            uint64_t capacity_be = 0u;
            memcpy(&capacity_be, cursor + 4u, sizeof capacity_be);
            meta->layout_capacity = cep_serial_from_be64(capacity_be);
            meta->has_layout = true;
            cursor += payload_len;
            break;
          }
          case SERIAL_STORE_META_TLV_TYPE: {
            if (payload_len < SERIAL_STORE_META_TYPE_PAYLOAD_SIZE)
                return false;
            uint64_t domain_be = 0u;
            memcpy(&domain_be, cursor, sizeof domain_be);
            cursor += sizeof domain_be;
            uint64_t tag_be = 0u;
            memcpy(&tag_be, cursor, sizeof tag_be);
            cursor += sizeof tag_be;
            cepDT type = {0};
            type.domain = cep_serial_from_be64(domain_be);
            type.tag = cep_serial_from_be64(tag_be);
            type.glob = (*cursor++) ? 1u : 0u;
            cursor += 3u; /* padding */
            meta->type = type;
            meta->has_type = cep_dt_is_valid(&type);
            break;
          }
          default:
            cursor += payload_len;
            break;
        }
        remaining -= payload_len;
    }

    return remaining == 0u;
}

static int cep_serialization_default_compare(const cepCell* lhs,
                                             const cepCell* rhs,
                                             void* context,
                                             cepCompareInfo* info) {
    (void)context;
    if (CEP_RARELY_PTR(info)) {
        cep_compare_info_set(info, CEP_DTAW("CEP", "cmp:order"), 1u, 0u);
        return 0;
    }
    return cep_cell_order_compare(lhs, rhs);
}

static int cep_serialization_octree_compare_stub(const cepCell* lhs,
                                                 const cepCell* rhs,
                                                 void* context,
                                                 cepCompareInfo* info) {
    (void)context;
    if (CEP_RARELY_PTR(info)) {
        cep_compare_info_set(info, CEP_DTAW("CEP", "cmp:o_stub"), 1u, 0u);
        return 0;
    }
    if (lhs == rhs)
        return 0;
    return lhs < rhs ? -1 : 1;
}

static void cep_serialization_register_builtin_comparators(void) {
    (void)cep_comparator_registry_record(cep_serialization_default_compare);
    (void)cep_comparator_registry_record(cep_serialization_octree_compare_stub);
}

static void cep_serialization_reset_registry_for_runtime(cepRuntime* runtime) {
    if (!runtime)
        return;
    cepSerializationRuntimeState* state = cep_runtime_serialization_state(runtime);
    if (!state)
        return;
    if (state->comparator_registry.entries) {
        cep_free(state->comparator_registry.entries);
        state->comparator_registry.entries = NULL;
    }
    state->comparator_registry.count = 0;
    state->comparator_registry.capacity = 0;
    state->comparators_initialized = false;
}

static void cep_serialization_cleanup_default_registry(void) {
    cep_serialization_reset_registry_for_runtime(cep_runtime_default());
}

static void CEP_AT_STARTUP_(202) cep_serialization_register_cleanup_startup(void) {
    (void)atexit(cep_serialization_cleanup_default_registry);
}

void cep_comparator_registry_reset_active(void) {
    cep_serialization_reset_registry_for_runtime(cep_runtime_active());
}

void cep_comparator_registry_reset_default(void) {
    cep_serialization_cleanup_default_registry();
}

CEP_DEFINE_STATIC_DT(dt_sev_crit, CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));

/* Serialization failures should not emit CEI until the diagnostics mailbox is
   available. This guard keeps early bootstrap from tripping fatal reports. */
static bool cep_serialization_can_emit_cei(void) {
    return cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL);
}

/* Format and emit a CEI fact describing a serialization failure. The helper
   resolves a canonical subject when possible so dashboards can inspect the
   offending cell without wading through transient link wrappers. */
static void cep_serialization_emit_failure(const char* topic,
                                           const cepCell* subject,
                                           const char* detail_fmt,
                                           ...) {
    if (!topic || !detail_fmt) {
        return;
    }
    if (!cep_serialization_can_emit_cei()) {
        return;
    }

    char note[256];
    va_list args;
    va_start(args, detail_fmt);
    vsnprintf(note, sizeof note, detail_fmt, args);
    va_end(args);

    cep_serialization_debug_log("[serialization][fail] topic=%s detail=%s\n", topic, note);

    cepCell* canonical = NULL;
    if (subject) {
        canonical = cep_link_pull((cepCell*)subject);
        if (!canonical) {
            canonical = (cepCell*)subject;
        }
        if (canonical && !cep_cell_is_normal(canonical)) {
            canonical = NULL;
        }
        if (canonical && !cep_cell_parent(canonical)) {
            canonical = NULL;
        }
        if (canonical && cep_cell_is_root(canonical)) {
            canonical = NULL;
        }
    }

    cepCeiRequest req = {
        .severity = *dt_sev_crit(),
        .note = note,
        .topic = topic,
        .topic_intern = true,
        .subject = canonical,
        .emit_signal = true,
        .ttl_forever = true,
    };

    (void)cep_cei_emit(&req);
}

static bool cep_compare_info_equal(const cepCompareInfo* lhs, const cepCompareInfo* rhs) {
    if (!lhs || !rhs)
        return false;
    return lhs->identifier.domain == rhs->identifier.domain &&
           lhs->identifier.tag == rhs->identifier.tag &&
           lhs->identifier.glob == rhs->identifier.glob &&
           lhs->version == rhs->version &&
           lhs->flags == rhs->flags;
}

static cepComparatorRegistry* cep_serialization_comparator_registry(void) {
    cepSerializationRuntimeState* state = cep_serialization_state();
    if (!state)
        return NULL;
    return &state->comparator_registry;
}

static bool cep_comparator_registry_reserve(cepComparatorRegistry* registry, size_t min_capacity) {
    if (!registry)
        return false;
    if (registry->capacity >= min_capacity)
        return true;
    size_t new_capacity = registry->capacity ? registry->capacity * 2u : 8u;
    while (new_capacity < min_capacity)
        new_capacity *= 2u;
    cepComparatorRegistryEntry* grown = cep_realloc(registry->entries, new_capacity * sizeof(*grown));
    if (!grown)
        return false;
    registry->entries = grown;
    registry->capacity = new_capacity;
    return true;
}

bool cep_comparator_registry_record(cepCompare comparator) {
    if (!comparator)
        return false;
    cepComparatorRegistry* registry = cep_serialization_comparator_registry();
    if (!registry)
        return false;
    cepCompareInfo info = {0};
    if (!cep_compare_identity(comparator, &info))
        return false;

    for (size_t i = 0; i < registry->count; ++i) {
        if (cep_compare_info_equal(&registry->entries[i].info, &info)) {
            registry->entries[i].comparator = comparator;
            return true;
        }
    }

    if (!cep_comparator_registry_reserve(registry, registry->count + 1u))
        return false;

    registry->entries[registry->count].info = info;
    registry->entries[registry->count].comparator = comparator;
    registry->count += 1u;
    return true;
}

cepCompare cep_comparator_registry_lookup(const cepCompareInfo* info) {
    if (!info)
        return NULL;
    cepComparatorRegistry* registry = cep_serialization_comparator_registry();
    if (!registry || !registry->entries)
        return NULL;
    for (size_t i = 0; i < registry->count; ++i) {
        if (cep_compare_info_equal(&registry->entries[i].info, info))
            return registry->entries[i].comparator;
    }
    return NULL;
}

typedef struct {
    uint64_t beat;
    uint8_t  flags;
    uint8_t  reserved[7];
} cepSerializationJournalMetadata;

enum {
    CEP_SERIALIZATION_JOURNAL_FLAG_DECISION = 0x01u,
    CEP_SERIALIZATION_JOURNAL_METADATA_BYTES = 16u,
};

static size_t cep_serialization_effective_metadata_length(const cepSerializationHeader* header) {
    if (!header) {
        return 0u;
    }

    if (header->metadata_length) {
        return header->metadata_length;
    }

    return header->journal_metadata_present ? CEP_SERIALIZATION_JOURNAL_METADATA_BYTES : 0u;
}

static size_t cep_serialization_header_payload_size(const cepSerializationHeader* header) {
    assert(header);
    size_t payload = CEP_SERIALIZATION_HEADER_BASE + cep_serialization_effective_metadata_length(header);
    if ((header->flags & CEP_SERIALIZATION_FLAG_CAPABILITIES) != 0u || header->capabilities_present)
        payload += sizeof(uint16_t);
    return payload;
}

/** Compute the number of bytes required to serialise @p header into a chunk so
    callers can reserve output buffers accurately. */
size_t cep_serialization_header_chunk_size(const cepSerializationHeader* header) {
    /* Report the total number of bytes required for the control header chunk so callers can size buffers before attempting to encode it. */
    if (!header)
        return 0;

    size_t payload = cep_serialization_header_payload_size(header);
    if (payload > SIZE_MAX - CEP_SERIALIZATION_CHUNK_OVERHEAD)
        return 0;

    return payload + CEP_SERIALIZATION_CHUNK_OVERHEAD;
}

/** Serialise @p header into @p dst, updating @p out_size with the number of
    bytes written when successful. */
bool cep_serialization_header_write(const cepSerializationHeader* header,
                                    uint8_t* dst,
                                    size_t capacity,
                                    size_t* out_size) {
    /* Emit a self-identifying control chunk that plants the CEP magic, format version, and negotiated options at the start of a stream so readers can validate or resynchronize before processing the rest of the payload. */
    if (!header || !dst)
        return false;

    if (header->metadata_length && !header->metadata)
        return false;

    uint16_t version = header->version ? header->version : CEP_SERIALIZATION_VERSION;
    uint8_t order = header->byte_order;
    if (order != CEP_SERIAL_ENDIAN_BIG && order != CEP_SERIAL_ENDIAN_LITTLE)
        return false;

    if (header->metadata_length && !header->metadata)
        return false;

    size_t metadata_len = cep_serialization_effective_metadata_length(header);
    bool include_capabilities = ((header->flags & CEP_SERIALIZATION_FLAG_CAPABILITIES) != 0u) ||
                                header->capabilities_present;
    size_t payload = CEP_SERIALIZATION_HEADER_BASE + metadata_len;
    if (include_capabilities)
        payload += sizeof(uint16_t);
    size_t required = payload + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    if (capacity < required)
        return false;

    uint64_t chunk_id = cep_serialization_chunk_id(CEP_CHUNK_CLASS_CONTROL, 0u, 0u);

    uint8_t* p = dst;
    uint64_t size_be = cep_serial_to_be64((uint64_t) payload);
    memcpy(p, &size_be, sizeof size_be);
    p += sizeof size_be;

    uint64_t id_be = cep_serial_to_be64(chunk_id);
    memcpy(p, &id_be, sizeof id_be);
    p += sizeof id_be;

    uint64_t magic = header->magic ? header->magic : CEP_SERIALIZATION_MAGIC;
    uint64_t magic_be = cep_serial_to_be64(magic);
    memcpy(p, &magic_be, sizeof magic_be);
    p += sizeof magic_be;

    uint16_t version_be = cep_serial_to_be16(version);
    memcpy(p, &version_be, sizeof version_be);
    p += sizeof version_be;

    uint8_t write_flags = header->flags;
    if (include_capabilities)
        write_flags |= CEP_SERIALIZATION_FLAG_CAPABILITIES;

    *p++ = order;
    *p++ = write_flags;

    uint32_t metadata_len_be = cep_serial_to_be32((uint32_t)metadata_len);
    memcpy(p, &metadata_len_be, sizeof metadata_len_be);
    p += sizeof metadata_len_be;

    if (metadata_len) {
        if (header->metadata_length) {
            memcpy(p, header->metadata, metadata_len);
            p += metadata_len;
        } else if (header->journal_metadata_present) {
            cepSerializationJournalMetadata meta = {
                .beat = header->journal_beat,
                .flags = header->journal_decision_replay ? CEP_SERIALIZATION_JOURNAL_FLAG_DECISION : 0u,
                .reserved = {0},
            };

            uint64_t beat_be = cep_serial_to_be64(meta.beat);
            memcpy(p, &beat_be, sizeof beat_be);
            p += sizeof beat_be;

            *p++ = meta.flags;
            memset(p, 0, sizeof meta.reserved);
            p += sizeof meta.reserved;
        }
    }

    if (include_capabilities) {
        uint16_t caps_be = cep_serial_to_be16(header->capabilities);
        memcpy(p, &caps_be, sizeof caps_be);
        p += sizeof caps_be;
    }

    if (out_size)
        *out_size = required;

    return true;
}

/** Parse @p chunk back into a structured header, validating magic, version,
    and metadata length. */
bool cep_serialization_header_read(const uint8_t* chunk,
                                   size_t chunk_size,
                                   cepSerializationHeader* header) {
    /* Parse the control chunk at the head of a stream so tools can confirm the magic, inspect the format version, and pull option metadata without guessing the layout. */
    if (!chunk || !header)
        return false;

    if (chunk_size < CEP_SERIALIZATION_CHUNK_OVERHEAD + CEP_SERIALIZATION_HEADER_BASE)
        return false;

    const uint8_t* p = chunk;
    uint64_t payload_be = 0;
    memcpy(&payload_be, p, sizeof payload_be);
    p += sizeof payload_be;
    size_t payload = (size_t) cep_serial_from_be64(payload_be);

    if (payload + CEP_SERIALIZATION_CHUNK_OVERHEAD != chunk_size)
        return false;

    uint64_t id_be = 0;
    memcpy(&id_be, p, sizeof id_be);
    p += sizeof id_be;
    uint64_t chunk_id = cep_serial_from_be64(id_be);

    if (cep_serialization_chunk_class(chunk_id) != CEP_CHUNK_CLASS_CONTROL ||
        cep_serialization_chunk_transaction(chunk_id) != 0u ||
        cep_serialization_chunk_sequence(chunk_id) != 0u)
        return false;

    uint64_t magic_be = 0;
    memcpy(&magic_be, p, sizeof magic_be);
    p += sizeof magic_be;
    uint64_t magic = cep_serial_from_be64(magic_be);
    if (magic != CEP_SERIALIZATION_MAGIC)
        return false;

    uint16_t version_be = 0;
    memcpy(&version_be, p, sizeof version_be);
    p += sizeof version_be;
    uint16_t version = cep_serial_from_be16(version_be);

    uint8_t byte_order = *p++;
    uint8_t flags = *p++;

    if (byte_order != CEP_SERIAL_ENDIAN_BIG && byte_order != CEP_SERIAL_ENDIAN_LITTLE)
        return false;

    uint32_t metadata_len_be = 0;
    memcpy(&metadata_len_be, p, sizeof metadata_len_be);
    p += sizeof metadata_len_be;
    uint32_t metadata_len = cep_serial_from_be32(metadata_len_be);

    if ((size_t)metadata_len > payload - CEP_SERIALIZATION_HEADER_BASE)
        return false;
    if ((size_t)metadata_len > chunk_size - (size_t)(p - chunk))
        return false;

    const uint8_t* metadata = metadata_len ? p : NULL;
    const uint8_t* after_metadata = p + metadata_len;
    size_t remaining_after_metadata = payload - (CEP_SERIALIZATION_HEADER_BASE + metadata_len);

    header->magic = magic;
    header->version = version;
    header->byte_order = byte_order;
    header->flags = flags;
    header->metadata_length = metadata_len;
    header->metadata = metadata;
    header->journal_metadata_present = false;
    header->journal_decision_replay = false;
    header->journal_beat = 0u;
    header->capabilities = 0u;
    header->capabilities_present = false;

    if (metadata && metadata_len == CEP_SERIALIZATION_JOURNAL_METADATA_BYTES) {
        uint64_t beat_be = 0u;
        memcpy(&beat_be, metadata, sizeof beat_be);
        const uint8_t* cursor = metadata + sizeof beat_be;

        header->journal_beat = cep_serial_from_be64(beat_be);
        header->journal_decision_replay = ((*cursor) & CEP_SERIALIZATION_JOURNAL_FLAG_DECISION) != 0;
        header->journal_metadata_present = true;
    }

    if ((flags & CEP_SERIALIZATION_FLAG_CAPABILITIES) != 0u) {
        if (remaining_after_metadata < sizeof(uint16_t))
            return false;
        uint16_t caps_be = 0u;
        memcpy(&caps_be, after_metadata, sizeof caps_be);
        header->capabilities = cep_serial_from_be16(caps_be);
        header->capabilities_present = true;
    }

    return true;
}

typedef struct {
    cepSerializationWriteFn write;
    void*                  context;
    uint32_t               transaction;
    uint16_t               sequence;
    size_t                 blob_limit;
    uint64_t               digest;
    uint64_t               journal_beat;
    const cepCell*         root;
    struct {
        cepID      id;
        uint16_t   length;
        char*      text;
        uint8_t    flags;
    } *namepool_entries;
    size_t                 namepool_count;
    size_t                 namepool_capacity;
    size_t                 namepool_emit_index;
} cepSerializationEmitter;

static bool cep_serialization_emitter_emit(cepSerializationEmitter* emitter,
                                           uint16_t chunk_class,
                                           const uint8_t* payload,
                                           size_t payload_size);

static inline uint64_t cep_serialization_hash_payload(const uint8_t* payload, size_t payload_size) {
    return (payload && payload_size) ? cep_hash_bytes_fnv1a(payload, payload_size) : UINT64_C(0);
}

static uint64_t cep_serialization_digest_mix(uint64_t seed,
                                             uint64_t chunk_id,
                                             const uint8_t* payload,
                                             size_t payload_size) {
    struct {
        uint64_t seed;
        uint64_t id;
        uint64_t payload;
    } block = {
        .seed = seed,
        .id = chunk_id,
        .payload = cep_serialization_hash_payload(payload, payload_size),
    };
    return cep_hash_bytes_fnv1a(&block, sizeof block);
}

static uint8_t cep_serialization_store_organiser(const cepCell* cell) {
    if (!cell || !cep_cell_is_normal(cell) || !cell->store)
        return 0u;

    switch (cell->store->indexing) {
      case CEP_INDEX_BY_INSERTION:
        return 0x01u;
      case CEP_INDEX_BY_NAME:
        return 0x02u;
      case CEP_INDEX_BY_FUNCTION:
        return (cell->store->storage == CEP_STORAGE_OCTREE) ? 0x05u : 0x03u;
      case CEP_INDEX_BY_HASH:
        return 0x04u;
      default:
        break;
    }
    return 0u;
}

static uint8_t cep_serialization_store_hint(const cepCell* cell) {
    if (!cell || !cep_cell_is_normal(cell) || !cell->store)
        return 0u;

    switch (cell->store->storage) {
      case CEP_STORAGE_LINKED_LIST:
        return 0x01u;
      case CEP_STORAGE_RED_BLACK_T:
        return 0x02u;
      case CEP_STORAGE_ARRAY:
        return 0x03u;
      case CEP_STORAGE_PACKED_QUEUE:
        return 0x04u;
      case CEP_STORAGE_HASH_TABLE:
        return 0x05u;
      case CEP_STORAGE_OCTREE:
        return 0x06u;
      default:
        break;
    }
    return 0u;
}

static bool cep_serialization_compute_cell_fingerprint(const cepCell* cell, uint64_t* out_fingerprint) {
    if (!cell || !out_fingerprint)
        return false;
    if (!cep_cell_is_normal(cell))
        return false;
    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical)
        return false;
    cepData* data = canonical->data;
    if (!data)
        return false;
    if (data->datatype != CEP_DATATYPE_VALUE && data->datatype != CEP_DATATYPE_DATA)
        return false;

    size_t size = data->size;
    const void* bytes = cep_data_payload(data);
    uint64_t payload_hash = size ? cep_hash_bytes_fnv1a(bytes, size) : UINT64_C(0);
    struct {
        uint64_t domain;
        uint64_t tag;
        uint64_t size;
        uint64_t payload;
    } fingerprint = {
        .domain = data->dt.domain,
        .tag = data->dt.tag,
        .size = size,
        .payload = payload_hash,
    };
    *out_fingerprint = cep_hash_bytes_fnv1a(&fingerprint, sizeof fingerprint);
    return true;
}

typedef struct {
    cepDT    name;
    uint8_t  flags;
    uint16_t position;
    bool     has_fingerprint;
    uint64_t fingerprint;
    uint8_t  cell_type;
    uint8_t  delta_flags;
} cepSerializationManifestChild;

typedef struct {
    cepCell* library;
    cepCell* resource;
    bool     isStream;
} cepSerializationProxyLibraryCtx;

static int cep_serialization_manifest_child_cmp_name(const void* lhs_ptr,
                                                     const void* rhs_ptr);

static void cep_serialization_normalize_stream_outcome(cepData* payload) {
    if (!payload)
        return;
    if (payload->datatype != CEP_DATATYPE_DATA &&
        payload->datatype != CEP_DATATYPE_VALUE)
        return;
    if (!cep_dt_is_valid(&payload->dt))
        return;
    const cepDT* outcome_dt = dt_stream_outcome();
    if (payload->dt.domain != outcome_dt->domain ||
        payload->dt.tag != outcome_dt->tag)
        return;
    cepStreamOutcomeEntry* entry = (cepStreamOutcomeEntry*)cep_data_payload(payload);
    if (!entry)
        return;
    if (entry->payload_hash && entry->resulting_hash == 0u) {
        uint64_t hash_copy = entry->payload_hash;
        CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][normalize_outcome] restoring resulting_hash payload=0x%016" PRIx64 "\n",
                                       hash_copy);
        entry->resulting_hash = hash_copy;
    }
}

static bool cep_serialization_collect_children(const cepCell* cell,
                                               uint8_t organiser,
                                               cepSerializationManifestChild** out_children,
                                               size_t* out_count) {
    if (!out_children || !out_count)
        return false;
    *out_children = NULL;
    *out_count = 0;

    if (!cell || !cep_cell_is_normal(cell) || !cell->store || !cell->store->chdCount)
        return true;

    size_t capacity = cell->store->chdCount;
    cepSerializationManifestChild* items = cep_malloc(capacity * sizeof(*items));
    if (!items)
        return false;

    size_t index = 0;
    uint32_t next_position = 0u;
    bool positional = (organiser == SERIAL_ORGANISER_INSERTION);
    for (cepCell* child = cep_cell_first_all(cell); child; child = cep_cell_next_all(cell, child)) {
        cepCell* resolved = cep_link_pull(child);
        if (!resolved)
            continue;
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name)
            continue;

        uint32_t assigned_position = next_position;
        if (positional) {
            size_t ordinal = 0u;
            if (cep_cell_indexof((cepCell*)cell, resolved, &ordinal)) {
                assigned_position = ordinal > (size_t)UINT32_MAX ? UINT32_MAX : (uint32_t)ordinal;
            }
        }

        cepSerializationManifestChild info = {
            .name = *name,
            .cell_type = (uint8_t)resolved->metacell.type,
            .flags = 0u,
            .position = (uint16_t)((assigned_position > UINT16_MAX) ? UINT16_MAX : assigned_position),
            .has_fingerprint = false,
            .fingerprint = 0u,
            .delta_flags = SERIAL_DELTA_FLAG_ADD,
        };

        if (next_position < UINT32_MAX)
            next_position++;

        if (resolved->metacell.veiled)
            info.flags |= SERIAL_CHILD_FLAG_VEILED;

        bool tombstone = cep_cell_is_deleted(resolved);
        if (tombstone) {
            info.flags |= SERIAL_CHILD_FLAG_TOMBSTONE;
            info.delta_flags = SERIAL_DELTA_FLAG_DELETE;
        }

        uint64_t fingerprint = 0u;
        if (!tombstone && cep_serialization_compute_cell_fingerprint(resolved, &fingerprint)) {
            info.has_fingerprint = true;
            info.fingerprint = fingerprint;
            info.flags |= SERIAL_CHILD_FLAG_FINGERPRINT;
        }

        items[index++] = info;
    }

    if (!index) {
        cep_free(items);
        items = NULL;
    } else if (index > 1u) {
        bool sort_by_name =
            organiser == SERIAL_ORGANISER_NAME ||
            organiser == SERIAL_ORGANISER_FUNCTION ||
            organiser == SERIAL_ORGANISER_HASH;
        if (sort_by_name) {
            qsort(items, index, sizeof(*items), cep_serialization_manifest_child_cmp_name);
            for (size_t i = 0; i < index; ++i) {
                uint32_t ordinal = (uint32_t)i;
                items[i].position = (uint16_t)((ordinal > UINT16_MAX) ? UINT16_MAX : ordinal);
            }
        }
    }

    *out_children = items;
    *out_count = index;
    return true;
}

static bool cep_serialization_collect_name_segments(const cepCell* cell,
                                                    cepDT** out_segments,
                                                    size_t* out_count) {
    if (!cell || !out_segments || !out_count)
        return false;

    size_t count = 0u;
    const cepCell* current = cell;
    while (current && !cep_cell_is_root((cepCell*)current)) {
        const cepDT* name = cep_cell_get_name(current);
        if (!name || !cep_dt_is_valid(name))
            return false;
        count++;
        current = cep_cell_parent(current);
    }

    if (count == 0u) {
        *out_segments = NULL;
        *out_count = 0u;
        return false;
    }

    cepDT* segments = cep_malloc(count * sizeof(*segments));
    if (!segments)
        return false;

    current = cell;
    for (size_t i = count; i-- > 0;) {
        const cepDT* name = cep_cell_get_name(current);
        if (!name || !cep_dt_is_valid(name)) {
            cep_free(segments);
            return false;
        }
        segments[i] = *name;
        current = cep_cell_parent(current);
    }

    *out_segments = segments;
    *out_count = count;
    return true;
}

/* Stamp each path segment with its ordinal when the parent store is indexed by
   insertion order. The timestamp field carries (position + 1) so zero remains
   reserved for “no positional metadata”. */
static void cep_serialization_stamp_path_positions(const cepCell* leaf, cepPath* path) {
    if (!leaf || !path || !path->length)
        return;

    unsigned structural = 0u;
    for (const cepCell* cursor = leaf; cursor; cursor = cep_cell_parent(cursor))
        structural++;
    if (!structural)
        return;

    const cepCell* current = leaf;
    for (unsigned idx = structural; idx-- > 0u && current; ) {
        cepOpCount stamp = 0u;
        const cepCell* parent = cep_cell_parent(current);
        if (parent) {
            size_t ordinal = 0u;
            if (cep_cell_indexof(parent, current, &ordinal)) {
                size_t bounded = ordinal > (size_t)UINT16_MAX ? (size_t)UINT16_MAX : ordinal;
                stamp = (cepOpCount)(bounded + 1u);
            }
        }
        path->past[idx].timestamp = stamp;
        current = parent;
    }

    for (unsigned idx = structural; idx < path->length; ++idx)
        path->past[idx].timestamp = 0u;
}

static void cep_serialization_trim_duplicate_root(cepPath* path) {
    if (!path || path->length < 2u)
        return;
    const cepDT* root = &path->past[0].dt;
    for (unsigned idx = 1u; idx < path->length; ++idx) {
        const cepDT* segment = &path->past[idx].dt;
        if (segment->domain == root->domain &&
            segment->tag == root->tag &&
            segment->glob == root->glob) {
            unsigned remaining = path->length - idx;
            memmove(path->past, path->past + idx, remaining * sizeof(path->past[0]));
            path->length = remaining;
            return;
        }
    }
}

static size_t cep_serialization_reference_path_size(size_t segment_count) {
    return sizeof(uint16_t) + segment_count * ((sizeof(uint64_t) * 2u) + 4u);
}

static uint8_t* cep_serialization_reference_path_encode(uint8_t* cursor,
                                                        const cepDT* segments,
                                                        size_t segment_count) {
    uint16_t count_be = cep_serial_to_be16((uint16_t)segment_count);
    memcpy(cursor, &count_be, sizeof count_be);
    cursor += sizeof count_be;
    for (size_t i = 0; i < segment_count; ++i) {
        uint64_t domain_be = cep_serial_to_be64(segments[i].domain);
        memcpy(cursor, &domain_be, sizeof domain_be);
        cursor += sizeof domain_be;

        uint64_t tag_be = cep_serial_to_be64(segments[i].tag);
        memcpy(cursor, &tag_be, sizeof tag_be);
        cursor += sizeof tag_be;

        *cursor++ = (uint8_t)(segments[i].glob ? 1u : 0u);
        *cursor++ = 0u;
        uint16_t reserved = 0u;
        memcpy(cursor, &reserved, sizeof reserved);
        cursor += sizeof reserved;
    }
    return cursor;
}

static bool cep_serialization_reference_path_decode(const uint8_t** cursor_ptr,
                                                    size_t* remaining,
                                                    cepDT** out_segments,
                                                    size_t* out_count) {
    if (!cursor_ptr || !*cursor_ptr || !remaining || !out_segments || !out_count)
        return false;
    if (*remaining < sizeof(uint16_t))
        return false;

    const uint8_t* cursor = *cursor_ptr;
    uint16_t segment_count = cep_serial_read_be16_buf(cursor);
    cursor += sizeof(uint16_t);
    *remaining -= sizeof(uint16_t);

    size_t expected = (size_t)segment_count * ((sizeof(uint64_t) * 2u) + 4u);
    if (*remaining < expected)
        return false;

    cepDT* segments = NULL;
    if (segment_count) {
        segments = cep_malloc((size_t)segment_count * sizeof(*segments));
        if (!segments)
            return false;
    }

    for (uint16_t i = 0; i < segment_count; ++i) {
        uint64_t domain = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        uint64_t tag = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        uint8_t glob = *cursor++;
        uint8_t meta = *cursor++;
        (void)meta;
        cursor += sizeof(uint16_t);

        segments[i].domain = domain;
        segments[i].tag = tag;
        segments[i].glob = (glob != 0u);
    }

    *cursor_ptr = cursor;
    *remaining -= expected;
    *out_segments = segments;
    *out_count = segment_count;
    return true;
}

static void cep_serialization_root_ids(cepID* out_domain, cepID* out_tag) {
    static cepID cached_domain = 0u;
    static cepID cached_tag = 0u;
    static bool initialized = false;
    if (!initialized) {
        cep_namepool_bootstrap();
        cached_domain = cep_namepool_intern_cstr("CEP");
        cached_tag = cep_namepool_intern_cstr("/");
        initialized = true;
    }
    if (out_domain)
        *out_domain = cached_domain;
    if (out_tag)
        *out_tag = cached_tag;
}

static bool cep_serialization_emitter_register_id(cepSerializationEmitter* emitter, cepID id) {
    if (!emitter || !cep_id_is_reference(id))
        return true;

    for (size_t i = 0; i < emitter->namepool_count; ++i) {
        if (emitter->namepool_entries[i].id == id)
            return true;
    }

    size_t length = 0u;
    const char* text = cep_namepool_lookup(id, &length);
    if (!text) {
        cep_serialization_emit_failure("serialization.namepool.lookup",
                                       NULL,
                                       "reference id=%016" PRIx64 " missing from namepool",
                                       (uint64_t)id);
        return false;
    }
    if (length > UINT16_MAX) {
        cep_serialization_emit_failure("serialization.namepool.length",
                                       NULL,
                                       "reference id=%016" PRIx64 " exceeds map limits (len=%zu)",
                                       (uint64_t)id,
                                       length);
        return false;
    }

    if (emitter->namepool_count == emitter->namepool_capacity) {
        size_t new_cap = emitter->namepool_capacity ? emitter->namepool_capacity << 1u : 16u;
        void* resized = cep_realloc(emitter->namepool_entries, new_cap * sizeof *emitter->namepool_entries);
        if (!resized)
            return false;
        emitter->namepool_entries = resized;
        emitter->namepool_capacity = new_cap;
    }

    char* copy = NULL;
    if (length) {
        copy = cep_malloc(length);
        if (!copy)
            return false;
        memcpy(copy, text, length);
    }

    emitter->namepool_entries[emitter->namepool_count].id = id;
    emitter->namepool_entries[emitter->namepool_count].length = (uint16_t)length;
    emitter->namepool_entries[emitter->namepool_count].text = copy;
    emitter->namepool_entries[emitter->namepool_count].flags =
        cep_namepool_reference_is_glob(id) ? SERIAL_NAMEPOOL_FLAG_GLOB : 0u;
    emitter->namepool_count += 1u;
    return true;
}

static bool cep_serialization_emitter_register_dt(cepSerializationEmitter* emitter, const cepDT* dt) {
    if (!dt)
        return true;
    if (!cep_serialization_emitter_register_id(emitter, dt->domain))
        return false;
    if (!cep_serialization_emitter_register_id(emitter, dt->tag))
        return false;
    return true;
}

static bool cep_serialization_emitter_flush_namepool_map(cepSerializationEmitter* emitter) {
    if (!emitter)
        return false;

    while (emitter->namepool_emit_index < emitter->namepool_count) {
        size_t start = emitter->namepool_emit_index;
        size_t payload_size = 4u; /* record + flags + count */
        size_t emit_count = 0u;

        while (emitter->namepool_emit_index < emitter->namepool_count) {
            const typeof(*emitter->namepool_entries)* entry = &emitter->namepool_entries[emitter->namepool_emit_index];
            size_t entry_size = sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint8_t) + entry->length;
            if (emit_count && payload_size + entry_size > CEP_SERIALIZATION_NAMEPOOL_MAX_PAYLOAD)
                break;
            payload_size += entry_size;
            emitter->namepool_emit_index += 1u;
            emit_count += 1u;
        }

        uint8_t flags = 0u;
        if (emitter->namepool_emit_index < emitter->namepool_count)
            flags |= SERIAL_NAMEPOOL_FLAG_MORE;

        uint8_t* payload = cep_malloc(payload_size);
        if (!payload)
            return false;

        uint8_t* cursor = payload;
        *cursor++ = SERIAL_RECORD_NAMEPOOL_MAP;
        *cursor++ = flags;
        uint16_t count_be = cep_serial_to_be16((uint16_t)emit_count);
        memcpy(cursor, &count_be, sizeof count_be);
        cursor += sizeof count_be;

        for (size_t i = 0; i < emit_count; ++i) {
            const typeof(*emitter->namepool_entries)* entry = &emitter->namepool_entries[start + i];
            uint64_t id_be = cep_serial_to_be64((uint64_t)entry->id);
            memcpy(cursor, &id_be, sizeof id_be);
            cursor += sizeof id_be;

            uint16_t len_be = cep_serial_to_be16(entry->length);
            memcpy(cursor, &len_be, sizeof len_be);
            cursor += sizeof len_be;

            *cursor++ = entry->flags;
            if (entry->length) {
                memcpy(cursor, entry->text, entry->length);
                cursor += entry->length;
            }
        }

        bool ok = cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_CONTROL, payload, payload_size);
        cep_free(payload);
        if (!ok)
            return false;
    }

    return true;
}

static void cep_serialization_emitter_clear_namepool(cepSerializationEmitter* emitter) {
    if (!emitter)
        return;
    if (emitter->namepool_entries) {
        for (size_t i = 0; i < emitter->namepool_count; ++i) {
            if (emitter->namepool_entries[i].text)
                cep_free(emitter->namepool_entries[i].text);
        }
        cep_free(emitter->namepool_entries);
    }
    emitter->namepool_entries = NULL;
    emitter->namepool_count = 0u;
    emitter->namepool_capacity = 0u;
    emitter->namepool_emit_index = 0u;
}

static bool cep_serialization_collect_namepool_entries(cepSerializationEmitter* emitter,
                                                       const cepCell* cell) {
    if (!emitter || !cell)
        return false;

    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical)
        return false;

    cepPath* path = NULL;
    if (!cep_cell_path(canonical, &path))
        return false;

    for (unsigned i = 0; i < path->length; ++i) {
        if (!cep_serialization_emitter_register_dt(emitter, &path->past[i].dt)) {
            if (path)
                cep_free(path);
            return false;
        }
    }
    if (path)
        cep_free(path);

    if (cep_cell_is_normal(canonical) && canonical->data) {
        cepData* data = canonical->data;
        if (data && cep_dt_is_valid(&data->dt)) {
            if (!cep_serialization_emitter_register_dt(emitter, &data->dt))
                return false;

            bool is_handle = (data->datatype == CEP_DATATYPE_HANDLE);
            bool is_stream = (data->datatype == CEP_DATATYPE_STREAM);
            if (is_handle || is_stream) {
                cepCell* library_cell = data->library;
                cepCell* resource_cell = is_handle ? data->handle : data->stream;
                if (library_cell && resource_cell) {
                    cepDT* segments = NULL;
                    size_t count = 0u;
                    if (cep_serialization_collect_name_segments(library_cell, &segments, &count)) {
                        for (size_t i = 0; i < count; ++i)
                            (void)cep_serialization_emitter_register_dt(emitter, &segments[i]);
                        if (segments)
                            cep_free(segments);
                    }
                    segments = NULL;
                    count = 0u;
                    if (cep_serialization_collect_name_segments(resource_cell, &segments, &count)) {
                        for (size_t i = 0; i < count; ++i)
                            (void)cep_serialization_emitter_register_dt(emitter, &segments[i]);
                        if (segments)
                            cep_free(segments);
                    }
                }
            }
        }
    }

    for (cepCell* child = cep_cell_first_all(canonical); child; child = cep_cell_next_all(canonical, child)) {
        cepCell* resolved = cep_link_pull(child);
        if (!resolved)
            continue;
        if (cep_cell_is_deleted(resolved))
            continue;
        const cepDT* name = cep_cell_get_name(resolved);
        if (name && cep_dt_is_valid(name))
            (void)cep_serialization_emitter_register_dt(emitter, name);
        if (!cep_serialization_collect_namepool_entries(emitter, resolved))
            return false;
    }

    return true;
}

static cepCell* cep_serialization_resolve_segments(cepCell* root,
                                                   const cepDT* segments,
                                                   size_t segment_count) {
    if (!root)
        return NULL;
    cepCell* current = root;
    for (size_t i = 0; i < segment_count; ++i) {
        cepDT name = segments[i];
        if (!cep_dt_is_valid(&name))
            return NULL;
        cepCell* child = cep_cell_find_by_name(current, &name);
        if (!child)
            goto fallback;
        current = cep_link_pull(child);
        if (!current)
            return NULL;
    }
    return current;

fallback:
    {
        cepID root_domain = 0u;
        cepID root_tag = 0u;
        cep_serialization_root_ids(&root_domain, &root_tag);

        cepCell* absolute = cep_link_pull(cep_root());
        if (!absolute)
            return NULL;

        size_t start = 0u;
        if (segment_count && root_domain && root_tag &&
            segments[0].domain == root_domain &&
            segments[0].tag == root_tag) {
            start = 1u;
        }

        current = absolute;
        for (size_t i = start; i < segment_count; ++i) {
            cepDT name = segments[i];
            if (!cep_dt_is_valid(&name))
                return NULL;
            cepCell* child = cep_cell_find_by_name(current, &name);
            if (!child) {
                char dom_buf[64];
                char tag_buf[64];
                cep_serialization_debug_log("[serialization][resolve] missing segment=%zu domain=%s tag=%s\n",
                                            i,
                                            cep_serialization_id_desc(name.domain, dom_buf, sizeof dom_buf),
                                            cep_serialization_id_desc(name.tag, tag_buf, sizeof tag_buf));
                return NULL;
            }
            current = cep_link_pull(child);
            if (!current)
                return NULL;
        }
    }
    return current;
}

static inline void cep_serialization_emitter_reset(cepSerializationEmitter* emitter, uint32_t transaction) {
    assert(emitter);
    emitter->transaction = transaction;
    emitter->sequence = 0;
    emitter->digest = 0u;
}

static inline bool cep_serialization_emitter_emit(cepSerializationEmitter* emitter,
                                                  uint16_t chunk_class,
                                                  const uint8_t* payload,
                                                  size_t payload_size) {
    assert(emitter && emitter->write);
    if (payload_size && !payload)
        return false;

    if (payload_size > UINT64_MAX - CEP_SERIALIZATION_CHUNK_OVERHEAD) {
        cep_serialization_emit_failure("serialization.chunk.frame",
                                       NULL,
                                       "payload size overflow (class=%u size=%zu)",
                                       (unsigned)chunk_class,
                                       payload_size);
        return false;
    }

    if (emitter->sequence == UINT16_MAX) {
        emitter->transaction++;
        emitter->sequence = 0;
    }

    emitter->sequence++;

    size_t total = payload_size + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint8_t* buffer = cep_malloc(total);

    uint64_t size_be = cep_serial_to_be64((uint64_t)payload_size);
    memcpy(buffer, &size_be, sizeof size_be);

    uint64_t chunk_id = cep_serialization_chunk_id(chunk_class, emitter->transaction, emitter->sequence);
    uint64_t id_be = cep_serial_to_be64(chunk_id);
    memcpy(buffer + sizeof size_be, &id_be, sizeof id_be);

    if (payload_size)
        memcpy(buffer + CEP_SERIALIZATION_CHUNK_OVERHEAD, payload, payload_size);

    bool ok = emitter->write(emitter->context, buffer, total);
    if (ok && chunk_class != CEP_CHUNK_CLASS_CONTROL) {
        emitter->digest = cep_serialization_digest_mix(emitter->digest,
                                                       chunk_id,
                                                       payload,
                                                       payload_size);
    }
    cep_free(buffer);
    if (!ok) {
        cep_serialization_debug_log("[serialization][debug] emitter_write_failed class=0x%04x tx=%u seq=%u payload_size=%zu\n",
                                    chunk_class,
                                    emitter->transaction,
                                    emitter->sequence,
                                    payload_size);
        cep_serialization_emit_failure("serialization.chunk.write",
                                       NULL,
                                       "writer callback failed (class=%u tx=%u seq=%u)",
                                       (unsigned)chunk_class,
                                       emitter->transaction,
                                       emitter->sequence);
    }
    return ok;
}

static size_t cep_serialization_manifest_child_descriptor_size(const cepSerializationManifestChild* child) {
    if (!child)
        return 0u;
    size_t size = (sizeof(uint64_t) * 2u) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    if (child->has_fingerprint)
        size += sizeof(uint64_t);
    return size;
}

static uint8_t* cep_serialization_manifest_write_child(uint8_t* cursor,
                                                       const cepSerializationManifestChild* child) {
    uint64_t domain_be = cep_serial_to_be64(child->name.domain);
    memcpy(cursor, &domain_be, sizeof domain_be);
    cursor += sizeof domain_be;

    uint64_t tag_be = cep_serial_to_be64(child->name.tag);
    memcpy(cursor, &tag_be, sizeof tag_be);
    cursor += sizeof tag_be;

    *cursor++ = (uint8_t)(child->name.glob ? 1u : 0u);
    *cursor++ = child->flags;

    uint16_t position_be = cep_serial_to_be16(child->position);
    memcpy(cursor, &position_be, sizeof position_be);
    cursor += sizeof position_be;

    uint32_t reserved = 0u;
    memcpy(cursor, &reserved, sizeof reserved);
    cursor += sizeof reserved;

    if (child->has_fingerprint) {
        uint64_t fingerprint_be = cep_serial_to_be64(child->fingerprint);
        memcpy(cursor, &fingerprint_be, sizeof fingerprint_be);
        cursor += sizeof fingerprint_be;
    }

    return cursor;
}

static bool cep_serialization_emit_manifest_base(cepSerializationEmitter* emitter,
                                                 const cepCell* cell,
                                                 const cepPath* path,
                                                 uint8_t organiser,
                                                 uint8_t storage_hint,
                                                 uint8_t base_flags,
                                                 const cepSerializationManifestChild* children,
                                                 size_t child_count,
                                                 bool split_children,
                                                 uint16_t descriptor_spans,
                                                 uint8_t cell_type,
                                                 const uint8_t* store_meta,
                                                 size_t store_meta_size) {
    assert(emitter && cell && path);

    if (path->length > UINT16_MAX) {
        cep_serialization_emit_failure("serialization.manifest.bounds",
                                       cell,
                                       "path length %u exceeds manifest limits",
                                       (unsigned)path->length);
        return false;
    }

    if (split_children && descriptor_spans == 0u) {
        cep_serialization_emit_failure("serialization.manifest.descriptor_spans",
                                       cell,
                                       "split manifest missing descriptor spans");
        return false;
    }

#ifdef CEP_ENABLE_DEBUG
    if (cep_serialization_debug_logging_enabled()) {
        char cell_dom_buf[64];
        char cell_tag_buf[64];
        const cepDT* cell_name = cep_cell_get_name(cell);
        const char* cell_dom = cell_name
            ? cep_serialization_id_desc(cell_name->domain, cell_dom_buf, sizeof cell_dom_buf)
            : "<anon>";
        const char* cell_tag = cell_name
            ? cep_serialization_id_desc(cell_name->tag, cell_tag_buf, sizeof cell_tag_buf)
            : "<anon>";
        CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][manifest_base] cell=%s/%s segments=%u children=%zu split=%u spans=%u base_flags=0x%02x store_meta=%zu\n",
                                       cell_dom,
                                       cell_tag,
                                       path ? (unsigned)path->length : 0u,
                                       child_count,
                                       split_children ? 1u : 0u,
                                       (unsigned)descriptor_spans,
                                       base_flags,
                                       store_meta_size);
        if (path && path->length) {
            for (uint16_t idx = 0; idx < path->length; ++idx) {
                const cepPast* segment = &path->past[idx];
                char seg_dom_buf[64];
                char seg_tag_buf[64];
                CEP_SERIALIZATION_DEBUG_PRINTF("  [serialization][manifest_base_path] idx=%u dom=%s tag=%s glob=%u stamp=%" PRIu64 "\n",
                                               (unsigned)idx,
                                               cep_serialization_id_desc(segment->dt.domain, seg_dom_buf, sizeof seg_dom_buf),
                                               cep_serialization_id_desc(segment->dt.tag, seg_tag_buf, sizeof seg_tag_buf),
                                               segment->dt.glob ? 1u : 0u,
                                               (uint64_t)segment->timestamp);
            }
        }
    }
#endif

    uint16_t segment_count = (uint16_t)path->length;
    bool include_children_inline = child_count && !split_children;
    uint16_t descriptor_span_count = split_children ? descriptor_spans : 0u;
    size_t payload_size = 11u + ((size_t)segment_count * ((sizeof(uint64_t) * 2u) + 4u));
    if (include_children_inline) {
        for (size_t i = 0; i < child_count; ++i)
            payload_size += cep_serialization_manifest_child_descriptor_size(&children[i]);
    }
    size_t meta_section = (store_meta && store_meta_size) ? (sizeof(uint16_t) + store_meta_size) : 0u;
    payload_size += meta_section;

    uint8_t* payload = cep_malloc(payload_size);
    if (!payload)
        return false;

    uint8_t* cursor = payload;
    *cursor++ = SERIAL_RECORD_MANIFEST_BASE;
    *cursor++ = organiser;
    *cursor++ = storage_hint;
    *cursor++ = base_flags;
    *cursor++ = cell_type;

    uint16_t segments_be = cep_serial_to_be16(segment_count);
    memcpy(cursor, &segments_be, sizeof segments_be);
    cursor += sizeof segments_be;

    uint16_t children_be = cep_serial_to_be16((uint16_t)child_count);
    memcpy(cursor, &children_be, sizeof children_be);
    cursor += sizeof children_be;

    uint16_t spans_be = cep_serial_to_be16(descriptor_span_count);
    memcpy(cursor, &spans_be, sizeof spans_be);
    cursor += sizeof spans_be;

    for (uint16_t i = 0; i < segment_count; ++i) {
        const cepPast* segment = &path->past[i];
        uint64_t domain_be = cep_serial_to_be64(segment->dt.domain);
        memcpy(cursor, &domain_be, sizeof domain_be);
        cursor += sizeof domain_be;

        uint64_t tag_be = cep_serial_to_be64(segment->dt.tag);
        memcpy(cursor, &tag_be, sizeof tag_be);
        cursor += sizeof tag_be;

        uint8_t glob_flag = (uint8_t)(segment->dt.glob ? 1u : 0u);
        *cursor++ = glob_flag;
        uint8_t meta_flags = 0u;
        uint16_t position = 0u;
        if (segment->timestamp) {
            cepOpCount stamp = segment->timestamp;
            uint64_t ordinal = stamp > 0u ? (uint64_t)(stamp - 1u) : 0u;
            if (ordinal > UINT16_MAX)
                ordinal = UINT16_MAX;
            position = (uint16_t)ordinal;
            meta_flags |= SERIAL_PATH_FLAG_POSITION;
        }
#ifdef CEP_ENABLE_DEBUG
        if (cep_serialization_debug_logging_enabled()) {
            char dom_buf[64];
            char tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][manifest_base_segment] idx=%u dom=%s tag=%s glob=%u meta_flags=0x%02x position=%u\n",
                                           (unsigned)i,
                                           cep_serialization_id_desc(segment->dt.domain, dom_buf, sizeof dom_buf),
                                           cep_serialization_id_desc(segment->dt.tag, tag_buf, sizeof tag_buf),
                                           (unsigned)glob_flag,
                                           (unsigned)meta_flags,
                                           (unsigned)position);
        }
#endif
        *cursor++ = meta_flags;
        uint16_t position_be = cep_serial_to_be16(position);
        memcpy(cursor, &position_be, sizeof position_be);
        cursor += sizeof position_be;
    }

    if (include_children_inline) {
        for (size_t i = 0; i < child_count; ++i)
            cursor = cep_serialization_manifest_write_child(cursor, &children[i]);
    }

    if (meta_section) {
        uint16_t meta_be = cep_serial_to_be16((uint16_t)store_meta_size);
        memcpy(cursor, &meta_be, sizeof meta_be);
        cursor += sizeof meta_be;
        memcpy(cursor, store_meta, store_meta_size);
        cursor += store_meta_size;
    }

    bool ok = cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_STRUCTURE, payload, payload_size);
    if (!ok) {
        cep_serialization_emit_failure("serialization.manifest.emit",
                                       cell,
                                       "failed to emit manifest chunk");
    }
    cep_free(payload);
    return ok;
}

static bool cep_serialization_emit_manifest_children(cepSerializationEmitter* emitter,
                                                     const cepCell* cell,
                                                     const cepPath* path,
                                                     const cepSerializationManifestChild* children,
                                                     size_t child_count,
                                                     uint16_t descriptor_offset,
                                                     uint16_t descriptor_count,
                                                     uint16_t span_index) {
    if (!emitter || !cell || !path || !children)
        return false;
    if (!descriptor_count)
        return true;
    if ((size_t)descriptor_offset + descriptor_count > child_count)
        return false;
    if (path->length == 0u || path->length > UINT16_MAX)
        return false;

    uint16_t segment_count = (uint16_t)path->length;
    size_t segments_bytes = (size_t)segment_count * ((sizeof(uint64_t) * 2u) + 4u);
    size_t descriptor_bytes = 0u;
    for (uint16_t i = 0; i < descriptor_count; ++i) {
        const cepSerializationManifestChild* child = &children[descriptor_offset + i];
        descriptor_bytes += cep_serialization_manifest_child_descriptor_size(child);
    }

    size_t payload_size = 10u + segments_bytes + descriptor_bytes;
    uint8_t* payload = cep_malloc(payload_size);
    if (!payload)
        return false;

    uint8_t* cursor = payload;
    *cursor++ = SERIAL_RECORD_MANIFEST_CHILDREN;
    *cursor++ = 0u;

    uint16_t span_be = cep_serial_to_be16(span_index);
    memcpy(cursor, &span_be, sizeof span_be);
    cursor += sizeof span_be;

    uint16_t offset_be = cep_serial_to_be16(descriptor_offset);
    memcpy(cursor, &offset_be, sizeof offset_be);
    cursor += sizeof offset_be;

    uint16_t count_be = cep_serial_to_be16(descriptor_count);
    memcpy(cursor, &count_be, sizeof count_be);
    cursor += sizeof count_be;

    uint16_t segments_be = cep_serial_to_be16(segment_count);
    memcpy(cursor, &segments_be, sizeof segments_be);
    cursor += sizeof segments_be;

    for (uint16_t i = 0; i < segment_count; ++i) {
        const cepPast* segment = &path->past[i];
        uint64_t domain_be = cep_serial_to_be64(segment->dt.domain);
        memcpy(cursor, &domain_be, sizeof domain_be);
        cursor += sizeof domain_be;

        uint64_t tag_be = cep_serial_to_be64(segment->dt.tag);
        memcpy(cursor, &tag_be, sizeof tag_be);
        cursor += sizeof tag_be;

        *cursor++ = (uint8_t)(segment->dt.glob ? 1u : 0u);
        uint8_t meta_flags = 0u;
        uint16_t position = 0u;
        if (segment->timestamp) {
            cepOpCount stamp = segment->timestamp;
            uint64_t ordinal = stamp > 0u ? (uint64_t)(stamp - 1u) : 0u;
            if (ordinal > UINT16_MAX)
                ordinal = UINT16_MAX;
            position = (uint16_t)ordinal;
            meta_flags |= SERIAL_PATH_FLAG_POSITION;
        }
        *cursor++ = meta_flags;
        uint16_t position_be = cep_serial_to_be16(position);
        memcpy(cursor, &position_be, sizeof position_be);
        cursor += sizeof position_be;
    }

    for (uint16_t i = 0; i < descriptor_count; ++i) {
        const cepSerializationManifestChild* child = &children[descriptor_offset + i];
        cursor = cep_serialization_manifest_write_child(cursor, child);
    }

    bool ok = cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_STRUCTURE, payload, payload_size);
    cep_free(payload);
    if (!ok) {
        cep_serialization_emit_failure("serialization.manifest.children_emit",
                                       cell,
                                       "failed to emit manifest children chunk");
    }
    return ok;
}

static bool cep_serialization_emit_manifest_delta(cepSerializationEmitter* emitter,
                                                  const cepCell* cell,
                                                  const cepPath* path,
                                                  uint8_t organiser,
                                                  uint8_t storage_hint,
                                                  uint64_t journal_beat,
                                                  const cepSerializationManifestChild* child) {
    assert(emitter && cell && path && child);

    if (path->length > UINT16_MAX) {
        cep_serialization_emit_failure("serialization.manifest.delta_bounds",
                                       cell,
                                       "path length %u exceeds manifest limits",
                                       (unsigned)path->length);
        return false;
    }

    uint16_t segment_count = (uint16_t)path->length;
    size_t child_size = cep_serialization_manifest_child_descriptor_size(child);
    size_t payload_size = 8u + (sizeof(uint64_t) * 2u) + ((size_t)segment_count * ((sizeof(uint64_t) * 2u) + 4u)) + child_size;

    uint8_t* payload = cep_malloc(payload_size);
    if (!payload)
        return false;

    uint8_t* cursor = payload;
    *cursor++ = SERIAL_RECORD_MANIFEST_DELTA;
    *cursor++ = child->delta_flags;
    *cursor++ = organiser;
    *cursor++ = storage_hint;

    uint16_t segments_be = cep_serial_to_be16(segment_count);
    memcpy(cursor, &segments_be, sizeof segments_be);
    cursor += sizeof segments_be;

    *cursor++ = child->cell_type;
    *cursor++ = 0u; /* reserved */

    uint64_t beat_be = cep_serial_to_be64(journal_beat);
    memcpy(cursor, &beat_be, sizeof beat_be);
    cursor += sizeof beat_be;

    uint64_t lineage_parent = 0u;
    uint64_t lineage_be = cep_serial_to_be64(lineage_parent);
    memcpy(cursor, &lineage_be, sizeof lineage_be);
    cursor += sizeof lineage_be;

    for (uint16_t i = 0; i < segment_count; ++i) {
        const cepPast* segment = &path->past[i];
        uint64_t domain_be = cep_serial_to_be64(segment->dt.domain);
        memcpy(cursor, &domain_be, sizeof domain_be);
        cursor += sizeof domain_be;

        uint64_t tag_be = cep_serial_to_be64(segment->dt.tag);
        memcpy(cursor, &tag_be, sizeof tag_be);
        cursor += sizeof tag_be;

        *cursor++ = (uint8_t)(segment->dt.glob ? 1u : 0u);
        memset(cursor, 0, 3u);
        cursor += 3u;
    }

    cursor = cep_serialization_manifest_write_child(cursor, child);

    bool ok = cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_STRUCTURE, payload, payload_size);
    if (!ok) {
        cep_serialization_emit_failure("serialization.manifest.delta_emit",
                                       cell,
                                       "failed to emit manifest delta chunk");
    }
    cep_free(payload);
    return ok;
}

static bool cep_serialization_emit_data(cepSerializationEmitter* emitter,
                                        const cepCell* cell) {
    assert(emitter && cell);

    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical) {
        cep_serialization_emit_failure("serialization.data.resolve",
                                       cell,
                                       "failed to resolve canonical cell for data chunk");
        return false;
    }

    if (cep_cell_is_proxy(canonical)) {
        cepProxySnapshot snapshot;
        if (!cep_proxy_snapshot(canonical, &snapshot)) {
            cep_serialization_emit_failure("serialization.data.proxy_snapshot",
                                           canonical,
                                           "proxy snapshot capture failed");
            return false;
        }

        const cepSerializationProxyLibraryCtx* ctx =
            (const cepSerializationProxyLibraryCtx*)cep_proxy_context(canonical);
        uint8_t proxy_kind = (ctx && ctx->isStream) ? SERIAL_PROXY_KIND_STREAM : SERIAL_PROXY_KIND_HANDLE;

        bool inline_payload = snapshot.payload && snapshot.size;
        uint8_t envelope_flags = inline_payload ? 0x01u : 0u;

        if (inline_payload && snapshot.size > SIZE_MAX - (sizeof(uint8_t) * 4u + sizeof(uint32_t) + sizeof(uint64_t))) {
            cep_serialization_emit_failure("serialization.data.proxy_payload",
                                           canonical,
                                           "proxy payload size overflow (size=%zu)",
                                           snapshot.size);
            cep_proxy_release_snapshot(canonical, &snapshot);
            return false;
        }

        size_t payload_size = sizeof(uint8_t) * 4u + sizeof(uint32_t) + sizeof(uint64_t) + (inline_payload ? snapshot.size : 0u);
        uint8_t* payload = cep_malloc(payload_size);
        if (!payload) {
            cep_proxy_release_snapshot(canonical, &snapshot);
            return false;
        }

        uint8_t* cursor = payload;
        *cursor++ = 0x01u; /* version */
        *cursor++ = proxy_kind;
        *cursor++ = envelope_flags;
        *cursor++ = 0u; /* reserved */

        uint32_t ticket_len_be = cep_serial_to_be32(0u);
        memcpy(cursor, &ticket_len_be, sizeof ticket_len_be);
        cursor += sizeof ticket_len_be;

        uint64_t payload_len = inline_payload ? (uint64_t)snapshot.size : 0u;
        uint64_t payload_len_be = cep_serial_to_be64(payload_len);
        memcpy(cursor, &payload_len_be, sizeof payload_len_be);
        cursor += sizeof payload_len_be;

        if (inline_payload) {
            memcpy(cursor, snapshot.payload, snapshot.size);
            cursor += snapshot.size;
        }

        bool ok = cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_LIBRARY, payload, payload_size);
        cep_free(payload);
        cep_proxy_release_snapshot(canonical, &snapshot);
        if (!ok) {
            cep_serialization_debug_log("[serialization][data] emit_proxy_failure payload_size=%zu kind=%u flags=0x%x\n",
                                        payload_size,
                                        (unsigned)proxy_kind,
                                        (unsigned)envelope_flags);
            cep_serialization_emit_failure("serialization.data.proxy_emit",
                                           canonical,
                                           "failed to emit proxy chunk");
        }
        return ok;
    }

    if (!cep_cell_is_normal(canonical)) {
        cep_serialization_emit_failure("serialization.data.type",
                                       canonical,
                                       "non-normal cell cannot emit data");
        return false;
    }

    cepData* data = canonical->data;
    if (!data)
        return true;

    bool is_value = (data->datatype == CEP_DATATYPE_VALUE);
    bool is_data_type = (data->datatype == CEP_DATATYPE_DATA);
    bool is_handle = (data->datatype == CEP_DATATYPE_HANDLE);
    bool is_stream = (data->datatype == CEP_DATATYPE_STREAM);

    if (!is_value && !is_data_type && !is_handle && !is_stream) {
        cep_serialization_emit_failure("serialization.data.type",
                                       canonical,
                                       "unsupported datatype=%u for serialization",
                                       (unsigned)data->datatype);
        return false;
    }

    size_t blob_limit = emitter->blob_limit ? emitter->blob_limit : CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD;
    if (blob_limit < 16u)
        blob_limit = 16u;

    size_t total_size = (is_value || is_data_type) ? data->size : 0u;
    const uint8_t* bytes = (is_value || is_data_type) ? (const uint8_t*)cep_data_payload(data) : NULL;
    if ((is_value || is_data_type) && total_size && !bytes) {
        cep_serialization_emit_failure("serialization.data.buffer",
                                       canonical,
                                       "payload bytes missing for size=%zu",
                                       total_size);
        return false;
    }

    bool chunked = (is_value || is_data_type) && (total_size > blob_limit);

    cepDT* library_segments = NULL;
    size_t library_count = 0u;
    cepDT* resource_segments = NULL;
    size_t resource_count = 0u;
    uint8_t* metadata = NULL;
    size_t metadata_size = 0u;
    uint8_t* payload = NULL;
    bool ok = false;

    uint64_t payload_hash = 0u;
    uint64_t journal_beat = emitter->journal_beat;

    if (is_handle || is_stream) {
        cepCell* library_cell = data->library;
        cepCell* resource_cell = is_handle ? data->handle : data->stream;
        if (!library_cell || !resource_cell) {
            cep_serialization_emit_failure("serialization.data.reference",
                                           canonical,
                                           "library/resource missing for handle/stream serialization");
            goto data_cleanup;
        }
        if (!cep_serialization_collect_name_segments(library_cell, &library_segments, &library_count)) {
            cep_serialization_emit_failure("serialization.data.reference",
                                           canonical,
                                           "failed to capture library reference path");
            goto data_cleanup;
        }
        if (!cep_serialization_collect_name_segments(resource_cell, &resource_segments, &resource_count)) {
            cep_serialization_emit_failure("serialization.data.reference",
                                           canonical,
                                           "failed to capture resource reference path");
            goto data_cleanup;
        }

        metadata_size = sizeof(uint8_t) * 2u + sizeof(uint16_t)
                      + cep_serialization_reference_path_size(library_count)
                      + cep_serialization_reference_path_size(resource_count);
        if (metadata_size) {
            metadata = cep_malloc(metadata_size);
            if (!metadata)
                goto data_cleanup;
            uint8_t* meta_cursor = metadata;
            *meta_cursor++ = 0x01u;
            uint8_t meta_flags = 0u;
            if (library_count)
                meta_flags |= 0x01u;
            if (resource_count)
                meta_flags |= 0x02u;
            *meta_cursor++ = meta_flags;
            uint16_t reserved_be = cep_serial_to_be16(0u);
            memcpy(meta_cursor, &reserved_be, sizeof reserved_be);
            meta_cursor += sizeof reserved_be;
            if (library_count)
                meta_cursor = cep_serialization_reference_path_encode(meta_cursor, library_segments, library_count);
            if (resource_count)
                meta_cursor = cep_serialization_reference_path_encode(meta_cursor, resource_segments, resource_count);
        }
        payload_hash = metadata_size ? cep_hash_bytes_fnv1a(metadata, metadata_size) : 0u;
    } else {
        payload_hash = cep_data_compute_hash(data);
    }

    size_t inline_size = chunked ? 0u : (is_handle || is_stream ? metadata_size : total_size);
    if (is_handle || is_stream) {
        char dt_dom_buf[64];
        char dt_tag_buf[64];
        cep_serialization_debug_log("[serialization][debug] emit_handle meta_size=%zu library_count=%zu resource_count=%zu inline_size=%zu dt=%s/%s\n",
                                    metadata_size,
                                    library_count,
                                    resource_count,
                                    inline_size,
                                    cep_serialization_id_desc(data->dt.domain, dt_dom_buf, sizeof dt_dom_buf),
                                    cep_serialization_id_desc(data->dt.tag, dt_tag_buf, sizeof dt_tag_buf));
    }
    size_t header_payload = 60u + inline_size;
    if (header_payload > SIZE_MAX - CEP_SERIALIZATION_CHUNK_OVERHEAD) {
        cep_serialization_emit_failure("serialization.data.header",
                                       canonical,
                                       "header payload overflow (size=%zu)",
                                       header_payload);
        goto data_cleanup;
    }

    payload = cep_malloc(header_payload);
    if (!payload)
        goto data_cleanup;

    uint8_t* cursor = payload;
    *cursor++ = 0x01u; /* version */
    uint8_t kind = 0x00u;
    if (is_data_type)
        kind = 0x01u;
    else if (is_handle)
        kind = 0x02u;
    else if (is_stream)
        kind = 0x03u;
    *cursor++ = kind;

    uint16_t data_flags = chunked ? UINT16_C(0x0001) : UINT16_C(0x0000);
    data_flags |= UINT16_C(0x0002); /* has hash */
    uint16_t data_flags_be = cep_serial_to_be16(data_flags);
    memcpy(cursor, &data_flags_be, sizeof data_flags_be);
    cursor += sizeof data_flags_be;

    uint64_t journal_be = cep_serial_to_be64(journal_beat);
    memcpy(cursor, &journal_be, sizeof journal_be);
    cursor += sizeof journal_be;

    uint64_t hash_be = cep_serial_to_be64(payload_hash);
    memcpy(cursor, &hash_be, sizeof hash_be);
    cursor += sizeof hash_be;

    uint16_t datatype_be = cep_serial_to_be16((uint16_t)data->datatype);
    memcpy(cursor, &datatype_be, sizeof datatype_be);
    cursor += sizeof datatype_be;

    uint16_t legacy_flags = chunked ? UINT16_C(0x0001) : UINT16_C(0x0000);
    uint16_t legacy_flags_be = cep_serial_to_be16(legacy_flags);
    memcpy(cursor, &legacy_flags_be, sizeof legacy_flags_be);
    cursor += sizeof legacy_flags_be;

    uint32_t inline_be = cep_serial_to_be32((uint32_t)(inline_size & UINT32_C(0xFFFFFFFF)));
    memcpy(cursor, &inline_be, sizeof inline_be);
    cursor += sizeof inline_be;

    uint64_t total_be = cep_serial_to_be64((uint64_t)total_size);
    memcpy(cursor, &total_be, sizeof total_be);
    cursor += sizeof total_be;

    uint64_t dt_domain_be = cep_serial_to_be64(data->dt.domain);
    memcpy(cursor, &dt_domain_be, sizeof dt_domain_be);
    cursor += sizeof dt_domain_be;

    uint64_t dt_tag_be = cep_serial_to_be64(data->dt.tag);
    memcpy(cursor, &dt_tag_be, sizeof dt_tag_be);
    cursor += sizeof dt_tag_be;

    *cursor++ = (uint8_t)(data->dt.glob ? 1u : 0u);
    memset(cursor, 0, 7u);
    cursor += 7u;

    if (!chunked && inline_size) {
        if (is_handle || is_stream) {
            memcpy(cursor, metadata, metadata_size);
        } else {
            memcpy(cursor, bytes, inline_size);
        }
        cursor += inline_size;
    }

    if (metadata) {
        cep_free(metadata);
        metadata = NULL;
    }
    if (library_segments) {
        cep_free(library_segments);
        library_segments = NULL;
    }
    if (resource_segments) {
        cep_free(resource_segments);
        resource_segments = NULL;
    }

    if (!cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_STRUCTURE, payload, header_payload)) {
        cep_serialization_emit_failure("serialization.data.header_emit",
                                       canonical,
                                       "failed to emit data header chunk");
        goto data_cleanup;
    }
    cep_free(payload);
    payload = NULL;

    if (!chunked || !total_size) {
        ok = true;
        goto data_cleanup;
    }

    if (!chunked || !total_size)
        return true;

    uint64_t offset = 0;
    size_t remaining = total_size;
    while (remaining) {
        size_t slice = remaining < blob_limit ? remaining : blob_limit;
        size_t blob_payload = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + slice;
        uint8_t* blob = cep_malloc(blob_payload);
        uint8_t* bp = blob;

        uint64_t offset_be = cep_serial_to_be64(offset);
        memcpy(bp, &offset_be, sizeof offset_be);
        bp += sizeof offset_be;

        uint32_t length_be = cep_serial_to_be32((uint32_t)(slice & UINT32_C(0xFFFFFFFF)));
        memcpy(bp, &length_be, sizeof length_be);
        bp += sizeof length_be;

        uint32_t reserved = 0;
        memcpy(bp, &reserved, sizeof reserved);
        bp += sizeof reserved;

        memcpy(bp, bytes + offset, slice);

        if (!cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_BLOB, blob, blob_payload)) {
            cep_serialization_emit_failure("serialization.data.blob_emit",
                                           canonical,
                                           "blob chunk emit failed at offset=%" PRIu64,
                                           offset);
            cep_free(blob);
            goto data_cleanup;
        }

        cep_free(blob);
        offset += (uint64_t)slice;
        remaining -= slice;
    }

    ok = true;

data_cleanup:
    if (payload)
        cep_free(payload);
    if (metadata)
        cep_free(metadata);
    if (library_segments)
        cep_free(library_segments);
    if (resource_segments)
        cep_free(resource_segments);
    return ok;
}

static bool cep_serialization_emit_cell_recursive(cepSerializationEmitter* emitter,
                                                  const cepCell* cell) {
    if (!emitter || !cell)
        return false;

    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical) {
        cep_serialization_emit_failure("serialization.manifest.resolve",
                                       cell,
                                       "failed to resolve canonical cell");
        return false;
    }

    cepPath* path = NULL;
    if (!cep_cell_path(canonical, &path)) {
        cep_serialization_emit_failure("serialization.path.resolve",
                                       canonical,
                                       "failed to build cell path for serialization");
        return false;
    }
    cep_serialization_stamp_path_positions(canonical, path);
    cep_serialization_trim_duplicate_root(path);

    if (cep_serialization_debug_logging_enabled() && path && path->length) {
        cep_serialization_debug_log("[serialization][emit_cell] path_len=%u",
                                    (unsigned)path->length);
        for (unsigned idx = 0; idx < path->length; ++idx) {
            char dom_buf[64];
            char tag_buf[64];
            cepDT cleaned = cep_dt_clean(&path->past[idx].dt);
            cep_serialization_debug_log("  [%u]=%s/%s%s",
                                        idx,
                                        cep_serialization_id_desc(cleaned.domain, dom_buf, sizeof dom_buf),
                                        cep_serialization_id_desc(cleaned.tag, tag_buf, sizeof tag_buf),
                                        cleaned.glob ? "*" : "");
        }
    }

    uint8_t organiser = cep_serialization_store_organiser(canonical);
    uint8_t storage_hint = cep_serialization_store_hint(canonical);
    uint8_t store_meta_buf[SERIAL_STORE_METADATA_CAPACITY] = {0};
    const uint8_t* store_meta = NULL;
    size_t store_meta_size = 0u;
    if (!cep_serialization_build_store_metadata(canonical,
                                                store_meta_buf,
                                                sizeof store_meta_buf,
                                                &store_meta_size)) {
        uint64_t dt_domain = (canonical->store && cep_dt_is_valid(&canonical->store->dt))
            ? canonical->store->dt.domain
            : 0u;
        uint64_t dt_tag = (canonical->store && cep_dt_is_valid(&canonical->store->dt))
            ? canonical->store->dt.tag
            : 0u;
        cep_serialization_emit_failure("serialization.store.comparator",
                                       canonical,
                                       "missing comparator identity for store dt=%016" PRIx64 "/%016" PRIx64,
                                       dt_domain,
                                       dt_tag);
        if (path)
            cep_free(path);
        return false;
    }
    if (store_meta_size) {
        storage_hint |= SERIAL_STORAGE_FLAG_METADATA;
        store_meta = store_meta_buf;
    }

    cepSerializationManifestChild* children = NULL;
    size_t child_count = 0u;
    if (!cep_serialization_collect_children(canonical, organiser, &children, &child_count)) {
        if (path)
            cep_free(path);
        return false;
    }

    uint8_t base_flags = 0u;
    bool split_children = child_count > 0u;
    if (child_count)
        base_flags |= SERIAL_BASE_FLAG_CHILDREN;
    if (split_children)
        base_flags |= SERIAL_BASE_FLAG_CHILDREN_SPLIT;
    if (canonical->metacell.veiled)
        base_flags |= SERIAL_BASE_FLAG_VEILED;

    bool wants_payload = false;
    if (cep_cell_is_proxy(canonical))
        wants_payload = true;
    else if (cep_cell_is_normal(canonical) && canonical->data)
        wants_payload = true;

    if (wants_payload)
        base_flags |= SERIAL_BASE_FLAG_PAYLOAD;

    uint16_t descriptor_spans = split_children ? 1u : 0u;

    unsigned original_path_len = path ? path->length : 0u;
    unsigned manifest_path_len = original_path_len;
    const cepStore* canonical_store = canonical->store;
    bool trimmed_store_segment = false;
    if (path &&
        manifest_path_len &&
        canonical_store &&
        canonical_store->chdCount &&
        cep_dt_is_valid(&canonical_store->dt)) {
        const cepDT* tail = &path->past[manifest_path_len - 1u].dt;
        if (tail->domain == canonical_store->dt.domain &&
            tail->tag == canonical_store->dt.tag &&
            tail->glob == canonical_store->dt.glob) {
            manifest_path_len--;
            trimmed_store_segment = true;
        }
    }
    if (path && manifest_path_len != path->length) {
#ifdef CEP_ENABLE_DEBUG
        if (cep_serialization_debug_logging_enabled()) {
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][manifest_path_trim] trimmed_store=%u original_len=%u new_len=%u\n",
                                           trimmed_store_segment ? 1u : 0u,
                                           path->length,
                                           manifest_path_len);
        }
#endif
        path->length = manifest_path_len;
    }

    bool ok = cep_serialization_emit_manifest_base(emitter,
                                                   canonical,
                                                   path,
                                                   organiser,
                                                   storage_hint,
                                                   base_flags,
                                                   children,
                                                   child_count,
                                                   split_children,
                                                   descriptor_spans,
                                                   (uint8_t)canonical->metacell.type,
                                                   store_meta,
                                                   store_meta_size);
    if (!ok)
        goto cleanup;

    if (split_children) {
        uint16_t descriptor_count = (uint16_t)child_count;
        if (!cep_serialization_emit_manifest_children(emitter,
                                                      canonical,
                                                      path,
                                                      children,
                                                      child_count,
                                                      0u,
                                                      descriptor_count,
                                                      0u)) {
            ok = false;
            goto cleanup;
        }
    }

    for (size_t i = 0; i < child_count; ++i) {
        if (!cep_serialization_emit_manifest_delta(emitter,
                                                   canonical,
                                                   path,
                                                   organiser,
                                                   storage_hint,
                                                   emitter->journal_beat,
                                                   &children[i])) {
            ok = false;
            goto cleanup;
        }
    }

    if (!cep_serialization_emit_data(emitter, canonical)) {
        ok = false;
        goto cleanup;
    }

    const cepDT* parent_name = cep_cell_get_name(canonical);
    bool use_descriptor_order = (children && child_count && organiser != SERIAL_ORGANISER_INSERTION);
    bool children_emitted = false;
#ifdef CEP_ENABLE_DEBUG
    if (cep_serialization_debug_logging_enabled()) {
        char parent_dom_buf[64];
        char parent_tag_buf[64];
        const char* parent_dom = parent_name ? cep_serialization_id_desc(parent_name->domain, parent_dom_buf, sizeof parent_dom_buf) : "<anon>";
        const char* parent_tag = parent_name ? cep_serialization_id_desc(parent_name->tag, parent_tag_buf, sizeof parent_tag_buf) : "<anon>";
        CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][emit_children_order] parent=%s/%s descriptors=%zu available=%d organiser=0x%02x\n",
                                       parent_dom,
                                       parent_tag,
                                       child_count,
                                       use_descriptor_order ? 1 : 0,
                                       (unsigned)organiser);
    }
#endif
    if (use_descriptor_order) {
        children_emitted = true;
        for (size_t i = 0; i < child_count; ++i) {
            const cepSerializationManifestChild* descriptor = &children[i];
            if (!descriptor)
                continue;
            if ((descriptor->flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u)
                continue;
            if ((descriptor->delta_flags & SERIAL_DELTA_FLAG_DELETE) != 0u)
                continue;
            cepCell* child = cep_cell_find_by_name_all(canonical, &descriptor->name);
            if (!child)
                continue;
            cepCell* resolved = cep_link_pull(child);
            if (!resolved || cep_cell_is_deleted(resolved))
                continue;
#ifdef CEP_ENABLE_DEBUG
            if (cep_serialization_debug_logging_enabled()) {
                const cepDT* child_name = cep_cell_get_name(resolved);
                if (child_name) {
                    char child_dom_buf[64];
                    char child_tag_buf[64];
                    char parent_dom_buf[64];
                    char parent_tag_buf[64];
                    const char* parent_dom = parent_name ? cep_serialization_id_desc(parent_name->domain, parent_dom_buf, sizeof parent_dom_buf) : "<anon>";
                    const char* parent_tag = parent_name ? cep_serialization_id_desc(parent_name->tag, parent_tag_buf, sizeof parent_tag_buf) : "<anon>";
                    cep_serialization_debug_log("[serialization][emit_child] parent=%s/%s child=%s/%s\n",
                                                parent_dom,
                                                parent_tag,
                                                cep_serialization_id_desc(child_name->domain, child_dom_buf, sizeof child_dom_buf),
                                                cep_serialization_id_desc(child_name->tag, child_tag_buf, sizeof child_tag_buf));
                }
            }
#endif
            if (!cep_serialization_emit_cell_recursive(emitter, resolved)) {
                ok = false;
                break;
            }
        }
    }
    if (!children_emitted && ok) {
        for (cepCell* child = cep_cell_first_all(canonical); child; child = cep_cell_next_all(canonical, child)) {
            cepCell* resolved = cep_link_pull(child);
            if (!resolved)
                continue;
            if (cep_cell_is_deleted(resolved))
                continue;
#ifdef CEP_ENABLE_DEBUG
            if (cep_serialization_debug_logging_enabled()) {
                const cepDT* child_name = cep_cell_get_name(resolved);
                if (child_name) {
                    char child_dom_buf[64];
                    char child_tag_buf[64];
                    char parent_dom_buf[64];
                    char parent_tag_buf[64];
                    const char* parent_dom = parent_name ? cep_serialization_id_desc(parent_name->domain, parent_dom_buf, sizeof parent_dom_buf) : "<anon>";
                    const char* parent_tag = parent_name ? cep_serialization_id_desc(parent_name->tag, parent_tag_buf, sizeof parent_tag_buf) : "<anon>";
                    cep_serialization_debug_log("[serialization][emit_child] parent=%s/%s child=%s/%s\n",
                                                parent_dom,
                                                parent_tag,
                                                cep_serialization_id_desc(child_name->domain, child_dom_buf, sizeof child_dom_buf),
                                                cep_serialization_id_desc(child_name->tag, child_tag_buf, sizeof child_tag_buf));
                }
            }
#endif
            if (!cep_serialization_emit_cell_recursive(emitter, resolved)) {
                ok = false;
                break;
            }
        }
    }

cleanup:
    if (path)
        path->length = original_path_len;
    if (children)
        cep_free(children);
    if (path)
        cep_free(path);
    return ok;
}

/* Serialise a single cell into the chunked wire format described in
   SERIALIZATION-AND-STREAMS.md. The function emits the mandatory header chunk,
   a manifest that captures the cell's path and metadata, and either an inline or
   chunked data descriptor depending on payload size. Callers supply a sink that
   receives fully framed chunks, letting them forward bytes to files, sockets, or
   higher-level transports without exposing the traversal mechanics. */
/** Emit a sequence of chunks that describes @p cell and, optionally, its blob
    payloads. The writer callback receives each chunk and can stream it to disk
    or over the network. */
bool cep_serialization_emit_cell(const cepCell* cell,
                                 const cepSerializationHeader* header,
                                 cepSerializationWriteFn write,
                                 void* context,
                                 size_t blob_payload_bytes) {
    if (cep_serialization_flat_mode_enabled()) {
        if (cep_serialization_emit_cell_flat(cell, header, write, context, blob_payload_bytes)) {
            return true;
        }
        cep_serialization_debug_log("[serialization][legacy] flat serializer requested but falling back to chunk stream");
    }

    bool emit_scope_entered = cep_serialization_emit_scope_enter();
    bool success = false;
    cepSerializationEmitter emitter = {0};
    bool emitter_ready = false;

    if (!cell || !write)
        goto exit;

    cepCell* canonical_root = cep_link_pull((cepCell*)cell);
    if (!canonical_root) {
        cep_serialization_emit_failure("serialization.root.resolve",
                                       cell,
                                       "failed to resolve canonical root for serialization");
        goto exit;
    }

    cepSerializationHeader local = header ? *header : (cepSerializationHeader){0};
    cepSerializationRuntimeState* state = cep_serialization_state();

    cepBeatNumber current_beat = cep_beat_index();
    if (state->marked_decision_beat != CEP_BEAT_INVALID &&
        state->marked_decision_beat != current_beat) {
        state->marked_decision_beat = CEP_BEAT_INVALID;
    }
    if (state->marked_decision_beat == current_beat) {
        local.journal_decision_replay = true;
    }

    if (!local.metadata_length && !local.journal_metadata_present) {
        local.journal_metadata_present = true;
        local.journal_beat = current_beat;
    } else if (!local.journal_beat) {
        local.journal_beat = current_beat;
    }
    if (!local.magic)
        local.magic = CEP_SERIALIZATION_MAGIC;
    if (!local.version)
        local.version = CEP_SERIALIZATION_VERSION;
    if (!local.byte_order)
        local.byte_order = CEP_SERIAL_ENDIAN_BIG;

    uint16_t required_caps = CEP_SERIALIZATION_CAP_HISTORY_MANIFEST |
                             CEP_SERIALIZATION_CAP_MANIFEST_DELTAS  |
                             CEP_SERIALIZATION_CAP_PAYLOAD_HASH     |
                             CEP_SERIALIZATION_CAP_PROXY_ENVELOPE   |
                             CEP_SERIALIZATION_CAP_DIGEST_TRAILER   |
                             CEP_SERIALIZATION_CAP_SPLIT_DESCRIPTORS;
    local.flags |= CEP_SERIALIZATION_FLAG_CAPABILITIES;
    local.capabilities_present = true;
    local.capabilities |= required_caps;
    local.capabilities |= CEP_SERIALIZATION_CAP_NAMEPOOL_MAP;

    size_t header_size = cep_serialization_header_chunk_size(&local);
    if (!header_size) {
        cep_serialization_emit_failure("serialization.header.size",
                                       cell,
                                       "header chunk size calculation failed");
        goto exit;
    }

    uint8_t* header_chunk = cep_malloc(header_size);
    size_t written = 0;
    if (!cep_serialization_header_write(&local, header_chunk, header_size, &written)) {
        cep_free(header_chunk);
        cep_serialization_emit_failure("serialization.header.write",
                                       cell,
                                       "failed to encode header chunk");
        goto exit;
    }

    bool ok = write(context, header_chunk, written);
    cep_free(header_chunk);
    if (!ok) {
        cep_serialization_emit_failure("serialization.header.flush",
                                       cell,
                                       "writer rejected header chunk");
        goto exit;
    }

    emitter = (cepSerializationEmitter){
        .write = write,
        .context = context,
        .blob_limit = blob_payload_bytes ? blob_payload_bytes : CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD,
        .journal_beat = local.journal_beat,
        .root = canonical_root,
    };
    emitter_ready = true;

    if (!cep_serialization_collect_namepool_entries(&emitter, canonical_root)) {
        goto exit;
    }

    if (!cep_serialization_emitter_flush_namepool_map(&emitter)) {
        goto exit;
    }

    cep_serialization_emitter_reset(&emitter, 1u);

    if (!cep_serialization_emit_cell_recursive(&emitter, cell)) {
        goto exit;
    }

    if (!cep_serialization_emitter_emit(&emitter, CEP_CHUNK_CLASS_CONTROL, NULL, 0u)) {
        cep_serialization_emit_failure("serialization.control.emit",
                                       cell,
                                       "failed to emit control terminator chunk");
        goto exit;
    }

    uint8_t digest_payload[sizeof(uint16_t) * 2u + sizeof(uint64_t) * 2u];
    uint8_t* cursor = digest_payload;
    uint16_t digest_algo = cep_serial_to_be16(UINT16_C(0x0001));
    memcpy(cursor, &digest_algo, sizeof digest_algo);
    cursor += sizeof digest_algo;

    uint16_t digest_flags = cep_serial_to_be16(UINT16_C(0x0000));
    memcpy(cursor, &digest_flags, sizeof digest_flags);
    cursor += sizeof digest_flags;

    uint64_t digest_beat_be = cep_serial_to_be64(local.journal_beat);
    memcpy(cursor, &digest_beat_be, sizeof digest_beat_be);
    cursor += sizeof digest_beat_be;

    uint64_t digest_value_be = cep_serial_to_be64(emitter.digest);
    memcpy(cursor, &digest_value_be, sizeof digest_value_be);

    if (!cep_serialization_emitter_emit(&emitter,
                                        CEP_CHUNK_CLASS_CONTROL,
                                        digest_payload,
                                        sizeof digest_payload)) {
        cep_serialization_emit_failure("serialization.control.digest",
                                       cell,
                                       "failed to emit digest trailer chunk");
        goto exit;
    }

    success = true;

exit:
    if (emitter_ready)
        cep_serialization_emitter_clear_namepool(&emitter);
    cep_serialization_emit_scope_exit(emit_scope_entered);
    return success;
}

typedef struct {
    cepFlatStreamWriteFn write;
    void*                context;
    size_t               bytes_written;
    cepOID               ops_oid;
    bool                 channel_ready;
    bool                 begin_registered;
    bool                 write_registered;
    bool                 finish_registered;
    cepDT                begin_req;
    cepDT                write_req;
    cepDT                finish_req;
} cepFlatFrameSinkContext;

static atomic_uint_fast64_t g_flat_frame_sink_req_counter = 0u;
static cepOID               g_flat_frame_sink_channel_oid = {0};

typedef struct {
    uint8_t* data;
    size_t   size;
    size_t   capacity;
} cepFlatFrameBuffer;

typedef struct {
    cepFlatFrameSinkContext          sink;
    uint8_t*                         buffer;
    size_t                           buffer_size;
    cepSerializationWriteFn          target_write;
    void*                            target_context;
    bool                             perform_write;
    cepFlatStreamAsyncCompletionFn   completion_cb;
    void*                            completion_ctx;
} cepFlatFrameAsyncJob;

static void
cep_flat_frame_buffer_reset(cepFlatFrameBuffer* buffer)
{
    if (!buffer) {
        return;
    }
    if (buffer->data) {
        cep_free(buffer->data);
    }
    *buffer = (cepFlatFrameBuffer){0};
}

static bool
cep_flat_frame_buffer_reserve(cepFlatFrameBuffer* buffer, size_t additional)
{
    if (!buffer) {
        return false;
    }
    size_t required = buffer->size + additional;
    if (required <= buffer->capacity) {
        return true;
    }
    size_t new_capacity = buffer->capacity ? buffer->capacity : 4096u;
    while (new_capacity < required) {
        new_capacity *= 2u;
    }
    uint8_t* grown = buffer->data ? cep_realloc(buffer->data, new_capacity)
                                  : cep_malloc(new_capacity);
    if (!grown) {
        return false;
    }
    buffer->data = grown;
    buffer->capacity = new_capacity;
    return true;
}

static bool
cep_flat_frame_buffer_write(void* context, const uint8_t* chunk, size_t size)
{
    cepFlatFrameBuffer* buffer = (cepFlatFrameBuffer*)context;
    if (!buffer) {
        return false;
    }
    if (size == 0u) {
        return true;
    }
    if (!chunk) {
        return false;
    }
    if (!cep_flat_frame_buffer_reserve(buffer, size)) {
        return false;
    }
    memcpy(buffer->data + buffer->size, chunk, size);
    buffer->size += size;
    return true;
}

static bool
cep_flat_frame_sink_write_proxy(void* context, const uint8_t* chunk, size_t size)
{
    cepFlatFrameSinkContext* sink = (cepFlatFrameSinkContext*)context;
    if (!sink || !sink->write) {
        return false;
    }
    if (size == 0u) {
        return true;
    }
    if (!chunk) {
        return false;
    }
    if (!sink->write(sink->context, chunk, size)) {
        return false;
    }
    sink->bytes_written += size;
    return true;
}

static cepDT
cep_flat_frame_sink_make_request_name(const char prefix[3])
{
    uint64_t id = atomic_fetch_add_explicit(&g_flat_frame_sink_req_counter, 1u, memory_order_relaxed);
    uint64_t suffix = id % 100000000ULL;
    char tag[12];
    char first = (prefix && prefix[0]) ? prefix[0] : 's';
    char second = (prefix && prefix[1]) ? prefix[1] : 'x';
    snprintf(tag, sizeof tag, "%c%c%08" PRIu64, first, second, suffix);
    return cep_ops_make_dt(tag);
}

static bool
cep_flat_frame_sink_register_channel(cepFlatFrameSinkContext* sink)
{
    if (!sink) {
        return false;
    }
    if (sink->channel_ready) {
        return true;
    }
    if (sink->channel_ready &&
        cep_oid_is_valid(g_flat_frame_sink_channel_oid) &&
        sink->ops_oid.domain == g_flat_frame_sink_channel_oid.domain &&
        sink->ops_oid.tag == g_flat_frame_sink_channel_oid.tag) {
        return true;
    }
    cepOpsAsyncChannelInfo info = {
        .target_path = "/data/persist",
        .has_target_path = true,
        .provider = *dt_flat_async_provider(),
        .has_provider = true,
        .reactor = *dt_flat_async_reactor(),
        .has_reactor = true,
        .caps = *dt_flat_async_caps(),
        .has_caps = true,
        .shim = true,
        .shim_known = true,
    };
    if (!cep_async_register_channel(sink->ops_oid, dt_flat_async_channel(), &info)) {
        return false;
    }
    sink->channel_ready = true;
    g_flat_frame_sink_channel_oid = sink->ops_oid;
    return true;
}

static bool
cep_flat_frame_sink_register_request(cepFlatFrameSinkContext* sink,
                                     const char prefix[3],
                                     const cepDT* opcode,
                                     cepDT* out_name)
{
    if (!sink || !opcode || !out_name || !cep_oid_is_valid(sink->ops_oid)) {
        return false;
    }
    *out_name = cep_flat_frame_sink_make_request_name(prefix);
    cepOpsAsyncIoReqInfo info = {
        .state = *dt_flat_async_state_exec(),
        .channel = *dt_flat_async_channel(),
        .opcode = *opcode,
        .has_beats_budget = true,
        .beats_budget = 1u,
    };
    return cep_async_register_request(sink->ops_oid, out_name, &info);
}

static void
cep_flat_frame_sink_post_completion(cepFlatFrameSinkContext* sink,
                                    const cepDT* request_name,
                                    const cepDT* opcode,
                                    bool success,
                                    uint64_t bytes_done,
                                    int error_code)
{
    if (!sink || !request_name || !opcode) {
        return;
    }
    if (!cep_oid_is_valid(sink->ops_oid) || !cep_dt_is_valid(request_name)) {
        return;
    }
    cepOpsAsyncIoReqInfo info = {
        .state = success ? *dt_flat_async_state_ok() : *dt_flat_async_state_fail(),
        .channel = *dt_flat_async_channel(),
        .opcode = *opcode,
    };
    if (bytes_done > 0u) {
        info.has_bytes_done = true;
        info.bytes_done = bytes_done;
    }
    if (!success) {
        info.has_errno = true;
        info.errno_code = error_code;
    }
    (void)cep_async_post_completion(sink->ops_oid, request_name, &info);
}

static void
cep_flat_frame_sink_finalize(cepFlatFrameSinkContext* sink,
                             bool success,
                             int error_code,
                             bool include_finish)
{
    if (!sink) {
        return;
    }
    if (sink->begin_registered) {
        cep_flat_frame_sink_post_completion(sink,
                                            &sink->begin_req,
                                            dt_flat_async_opcode_begin(),
                                            success,
                                            0u,
                                            error_code);
        sink->begin_registered = false;
    }
    if (sink->write_registered) {
        cep_flat_frame_sink_post_completion(sink,
                                            &sink->write_req,
                                            dt_flat_async_opcode_write(),
                                            success,
                                            (uint64_t)sink->bytes_written,
                                            error_code);
        sink->write_registered = false;
    }
    if (include_finish && sink->finish_registered) {
        cep_flat_frame_sink_post_completion(sink,
                                            &sink->finish_req,
                                            dt_flat_async_opcode_finish(),
                                            success,
                                            0u,
                                            error_code);
        sink->finish_registered = false;
    }
}

static bool
cep_flat_frame_sink_prepare(cepFlatFrameSinkContext* sink)
{
    if (!sink || !sink->write) {
        return false;
    }
    sink->ops_oid = cep_async_ops_oid();
    if (!cep_oid_is_valid(sink->ops_oid)) {
        return false;
    }
    if (!cep_flat_frame_sink_register_channel(sink)) {
        return false;
    }
    if (!cep_flat_frame_sink_register_request(sink,
                                              "sb",
                                              dt_flat_async_opcode_begin(),
                                              &sink->begin_req)) {
        return false;
    }
    sink->begin_registered = true;
    if (!cep_flat_frame_sink_register_request(sink,
                                              "sw",
                                              dt_flat_async_opcode_write(),
                                              &sink->write_req)) {
        cep_flat_frame_sink_finalize(sink, false, -EIO, true);
        return false;
    }
    sink->write_registered = true;
    if (!cep_flat_frame_sink_register_request(sink,
                                              "sf",
                                              dt_flat_async_opcode_finish(),
                                              &sink->finish_req)) {
        cep_flat_frame_sink_finalize(sink, false, -EIO, true);
        return false;
    }
    sink->finish_registered = true;
    return true;
}

static bool
cep_flat_frame_async_worker(void* context, cepIoReactorResult* out_result)
{
    cepFlatFrameAsyncJob* job = (cepFlatFrameAsyncJob*)context;
    if (!job) {
        if (out_result) {
            *out_result = (cepIoReactorResult){ .success = false, .bytes_done = 0u, .error_code = -EIO };
        }
        return false;
    }
    bool success = true;
    int error_code = 0;
    if (job->perform_write && job->buffer && job->buffer_size > 0u) {
        if (!job->target_write(job->target_context, job->buffer, job->buffer_size)) {
            success = false;
            error_code = -EIO;
        }
    }
    if (out_result) {
        out_result->success = success;
        out_result->bytes_done = success ? job->sink.bytes_written : 0u;
        out_result->error_code = success ? 0 : error_code;
    }
    return success;
}

static void
cep_flat_frame_async_on_complete(void* context, const cepIoReactorResult* result)
{
    cepFlatFrameAsyncJob* job = (cepFlatFrameAsyncJob*)context;
    if (!job) {
        return;
    }
    bool success = result ? result->success : false;
    int error_code = result ? result->error_code : -EIO;
    cep_flat_frame_sink_finalize(&job->sink, success, error_code, false);
    if (job->completion_cb) {
        job->completion_cb(success, job->sink.bytes_written, error_code, job->completion_ctx);
    }
    if (job->buffer) {
        cep_free(job->buffer);
    }
    cep_free(job);
}

bool
cep_flat_stream_emit_cell_async(const cepCell* cell,
                                const cepSerializationHeader* header,
                                cepSerializationWriteFn write,
                                void* context,
                                size_t blob_payload_bytes,
                                cepFlatStreamAsyncStats* stats)
{
    if (!cell || !write) {
        return false;
    }

    cepFlatStreamAsyncStats local_stats = {0};
    cepFlatStreamAsyncStats* out_stats = stats ? stats : &local_stats;
    bool require_sync_copy = cep_flat_stream_should_require_sync_copy(out_stats->require_sync_copy);
    out_stats->require_sync_copy = require_sync_copy;

    cepFlatFrameSinkContext sink = {
        .write = cep_flat_frame_buffer_write,
        .context = NULL,
        .bytes_written = 0u,
        .ops_oid = cep_oid_invalid(),
        .channel_ready = false,
        .begin_registered = false,
        .write_registered = false,
        .finish_registered = false,
    };
    cepFlatFrameBuffer buffer = {0};
    sink.context = &buffer;

    if (!cep_flat_frame_sink_prepare(&sink)) {
        out_stats->async_mode = false;
        out_stats->fallback_used = false;
        cep_flat_frame_buffer_reset(&buffer);
        return false;
    }

    bool emitted = cep_serialization_emit_cell(cell,
                                               header,
                                               cep_flat_frame_sink_write_proxy,
                                               &sink,
                                               blob_payload_bytes);
    if (!emitted) {
        cep_flat_frame_sink_finalize(&sink, false, -EIO, true);
        out_stats->async_mode = false;
        out_stats->fallback_used = true;
        cep_flat_frame_buffer_reset(&buffer);
        return false;
    }

    if (require_sync_copy) {
        if (!write(context, buffer.data, buffer.size)) {
            cep_flat_frame_sink_finalize(&sink, false, -EIO, true);
            out_stats->async_mode = false;
            out_stats->fallback_used = true;
            cep_flat_frame_buffer_reset(&buffer);
            return false;
        }
    }

    cepFlatFrameAsyncJob* job = cep_malloc0(sizeof *job);
    if (!job) {
        cep_flat_frame_sink_finalize(&sink, false, -ENOMEM, true);
        out_stats->async_mode = false;
        out_stats->fallback_used = true;
        cep_flat_frame_buffer_reset(&buffer);
        return false;
    }

    job->sink = sink;
    job->target_write = write;
    job->target_context = context;
    job->perform_write = !require_sync_copy;
    job->completion_cb = out_stats->completion_cb;
    job->completion_ctx = out_stats->completion_ctx;
    if (job->perform_write) {
        job->buffer = buffer.data;
        job->buffer_size = buffer.size;
    } else {
        cep_flat_frame_buffer_reset(&buffer);
    }

    cepOpsAsyncIoReqInfo success_info = {
        .state = *dt_flat_async_state_ok(),
        .channel = *dt_flat_async_channel(),
        .opcode = *dt_flat_async_opcode_finish(),
        .has_bytes_done = true,
        .bytes_done = (uint64_t)sink.bytes_written,
    };
    cepOpsAsyncIoReqInfo failure_info = {
        .state = *dt_flat_async_state_fail(),
        .channel = *dt_flat_async_channel(),
        .opcode = *dt_flat_async_opcode_finish(),
    };

    cepIoReactorWork work = {
        .owner = sink.ops_oid,
        .request_name = sink.finish_req,
        .success_info = success_info,
        .failure_info = failure_info,
        .beats_budget = 1u,
        .has_beats_budget = true,
        .bytes_expected = (uint64_t)sink.bytes_written,
        .has_bytes_expected = true,
        .shim_fallback = (cep_io_reactor_active_backend() != CEP_IO_REACTOR_BACKEND_EPOLL),
        .worker = cep_flat_frame_async_worker,
        .worker_context = job,
        .destroy = NULL,
        .on_complete = cep_flat_frame_async_on_complete,
        .on_complete_context = job,
    };
    if (!job->perform_write) {
        work.bytes_expected = 0u;
        work.has_bytes_expected = false;
    }

    if (!cep_io_reactor_submit(&work)) {
        cep_flat_frame_sink_finalize(&sink, false, -EIO, true);
        out_stats->async_mode = false;
        out_stats->fallback_used = true;
        if (!require_sync_copy && job->buffer) {
            (void)write(context, job->buffer, job->buffer_size);
        }
        if (job->buffer) {
            cep_free(job->buffer);
        }
        cep_free(job);
        return false;
    }

    out_stats->async_mode = true;
    out_stats->fallback_used = false;
    return true;
}


typedef struct {
    bool        needed;
    bool        header_received;
    bool        chunked;
    bool        complete;
    uint8_t     kind;
    uint16_t    datatype;
    uint16_t    flags;
    cepDT       dt;
    uint64_t    total_size;
    uint64_t    hash;
    uint8_t*    buffer;
    size_t      size;
    uint64_t    next_offset;
    uint64_t    journal_beat;
    uint16_t    legacy_flags;
    cepDT*      library_segments;
    size_t      library_segment_count;
    cepDT*      resource_segments;
    size_t      resource_segment_count;
} cepSerializationStageData;

typedef struct {
    bool        needed;
    bool        complete;
    uint32_t    flags;
    uint8_t     kind;
    uint8_t*    buffer;
    size_t      size;
} cepSerializationStageProxy;

typedef struct {
    cepDT       name;
    uint8_t     flags;
    uint16_t    position;
    bool        has_fingerprint;
    bool        matched;
    bool        descriptor_ready;
    bool        freshly_materialized;
    uint64_t    fingerprint;
    uint8_t     delta_flags;
    uint8_t     cell_type;
} cepSerializationStageChild;

typedef struct {
    cepPath*                     path;
    uint8_t                      cell_type;
    uint8_t                      organiser;
    uint8_t                      storage_hint;
    uint8_t                      base_flags;
    uint8_t*                     store_metadata;
    size_t                       store_metadata_size;
    uint32_t                     transaction;
    cepSerializationStageData    data;
    cepSerializationStageProxy   proxy;
    cepSerializationStageChild*  children;
    size_t                       child_count;
    size_t                       child_capacity;
    size_t                       child_target;
    size_t                       descriptor_spans_expected;
    size_t                       descriptor_spans_seen;
    size_t                       delta_expected;
    size_t                       delta_seen;
} cepSerializationStage;

static void cep_serialization_debug_dump_stage(const cepSerializationStage* stage, const char* label) {
    if (!stage)
        return;

    unsigned path_len = stage->path ? stage->path->length : 0u;
    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][stage] label=%s tx=%u organiser=0x%02x storage_hint=0x%02x base_flags=0x%02x cell_type=%u children=%zu path_len=%u delta=%zu/%zu\n",
                     label ? label : "(null)",
                     (unsigned)stage->transaction,
                     (unsigned)stage->organiser,
                     (unsigned)stage->storage_hint,
                     (unsigned)stage->base_flags,
                     (unsigned)stage->cell_type,
                     stage->child_count,
                     path_len,
                     stage->delta_seen,
                     stage->delta_expected);
    if (stage->path) {
        for (unsigned idx = 0; idx < path_len; ++idx) {
            const cepPast* segment = &stage->path->past[idx];
            char dom_buf[64];
            char tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][stage]   path[%u]=%s/%s%s\n",
                             idx,
                             cep_serialization_id_desc(segment->dt.domain, dom_buf, sizeof dom_buf),
                             cep_serialization_id_desc(segment->dt.tag, tag_buf, sizeof tag_buf),
                             segment->dt.glob ? "*" : "");
        }
    }
    if (stage->children) {
        for (size_t i = 0; i < stage->child_count; ++i) {
            const cepSerializationStageChild* child = &stage->children[i];
            char dom_buf[64];
            char tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][stage]   child[%zu] name=%s/%s%s pos=%u flags=0x%02x delta=0x%02x type=%u fp=%s\n",
                             i,
                             cep_serialization_id_desc(child->name.domain, dom_buf, sizeof dom_buf),
                             cep_serialization_id_desc(child->name.tag, tag_buf, sizeof tag_buf),
                             child->name.glob ? "*" : "",
                             (unsigned)child->position,
                             (unsigned)child->flags,
                             (unsigned)child->delta_flags,
                             (unsigned)child->cell_type,
                             child->has_fingerprint ? "yes" : "no");
        }
    }
}

#ifdef CEP_ENABLE_DEBUG
static inline void cep_serialization_debug_dump_stage(const cepSerializationStage* stage, const char* label) {
    (void)stage;
    (void)label;
}
#endif

static bool cep_serialization_stage_ensure_child_capacity(cepSerializationStage* stage, size_t required) {
    if (!stage)
        return false;
    if (required == 0u)
        return true;
    if (required <= stage->child_capacity && stage->children)
        return true;

    size_t new_capacity = stage->child_capacity ? stage->child_capacity : 4u;
    while (new_capacity < required) {
        size_t doubled = new_capacity << 1u;
        if (doubled <= new_capacity) { /* overflow */
            new_capacity = required;
            break;
        }
        new_capacity = doubled;
    }

    size_t bytes = new_capacity * sizeof(*stage->children);
    cepSerializationStageChild* grown = stage->children
        ? cep_realloc(stage->children, bytes)
        : cep_malloc(bytes);
    if (!grown)
        return false;

    if (new_capacity > stage->child_capacity) {
        size_t delta = new_capacity - stage->child_capacity;
        memset(grown + stage->child_capacity, 0, delta * sizeof(*stage->children));
    }

    stage->children = grown;
    stage->child_capacity = new_capacity;
    return true;
}

static cepSerializationStageChild* cep_serialization_stage_find_child(cepSerializationStage* stage,
                                                                      const cepDT* name,
                                                                      bool require_position,
                                                                      uint16_t position) {
    if (!stage || !name || !stage->children)
        return NULL;

    bool positional = require_position && stage->organiser == SERIAL_ORGANISER_INSERTION;

    for (size_t i = 0; i < stage->child_count; ++i) {
        cepSerializationStageChild* child = &stage->children[i];
        if (!child->descriptor_ready)
            continue;
        if (child->name.domain != name->domain ||
            child->name.tag != name->tag ||
            child->name.glob != name->glob) {
            continue;
        }
        if (positional && child->position != position)
            continue;
        return child;
    }
    return NULL;
}



typedef struct {
    uint32_t                 id;
    uint16_t                 last_sequence;
    bool                     active;
    cepSerializationStage*   pending_stage;
} cepSerializationTxState;

struct cepSerializationReader {
    cepCell*                    root;
    bool                        header_seen;
    bool                        pending_commit;
    bool                        error;
    cepSerializationHeader      header;

    cepSerializationTxState*    transactions;
    size_t                      transaction_count;
    size_t                      transaction_capacity;

    cepSerializationStage*      stages;
    size_t                      stage_count;
    size_t                      stage_capacity;
};

static uint16_t cep_serial_read_be16_buf(const uint8_t* src) {
    uint16_t temp;
    memcpy(&temp, src, sizeof temp);
    return cep_serial_from_be16(temp);
}

static uint32_t cep_serial_read_be32_buf(const uint8_t* src) {
    uint32_t temp;
    memcpy(&temp, src, sizeof temp);
    return cep_serial_from_be32(temp);
}

static uint64_t cep_serial_read_be64_buf(const uint8_t* src) {
    uint64_t temp;
    memcpy(&temp, src, sizeof temp);
    return cep_serial_from_be64(temp);
}

static void cep_serialization_stage_data_dispose(cepSerializationStageData* data) {
    if (!data)
        return;

    if (data->buffer) {
        cep_free(data->buffer);
        data->buffer = NULL;
    }

    if (data->library_segments) {
        cep_free(data->library_segments);
        data->library_segments = NULL;
    }
    data->library_segment_count = 0u;

    if (data->resource_segments) {
        cep_free(data->resource_segments);
        data->resource_segments = NULL;
    }
    data->resource_segment_count = 0u;

    memset(data, 0, sizeof(*data));
}

static void cep_serialization_stage_proxy_dispose(cepSerializationStageProxy* proxy) {
    if (!proxy)
        return;

    if (proxy->buffer) {
        cep_free(proxy->buffer);
        proxy->buffer = NULL;
    }

    memset(proxy, 0, sizeof(*proxy));
}

static void cep_serialization_stage_dispose(cepSerializationStage* stage) {
    if (!stage)
        return;

    if (stage->path) {
        cep_free(stage->path);
        stage->path = NULL;
    }

    cep_serialization_stage_data_dispose(&stage->data);
    cep_serialization_stage_proxy_dispose(&stage->proxy);
    if (stage->store_metadata) {
        cep_free(stage->store_metadata);
        stage->store_metadata = NULL;
    }
    if (stage->children) {
        cep_free(stage->children);
        stage->children = NULL;
    }
    memset(stage, 0, sizeof(*stage));
}

static void cep_serialization_reader_clear_transactions(cepSerializationReader* reader) {
    if (!reader)
        return;

    if (reader->transactions) {
        memset(reader->transactions, 0, reader->transaction_capacity * sizeof(*reader->transactions));
    }
    reader->transaction_count = 0;
}

static void cep_serialization_reader_clear_stages(cepSerializationReader* reader) {
    if (!reader)
        return;

    if (reader->stages) {
        for (size_t i = 0; i < reader->stage_count; ++i)
            cep_serialization_stage_dispose(&reader->stages[i]);
    }
    reader->stage_count = 0;
}

static void cep_serialization_reader_init(cepSerializationReader* reader, cepCell* root) {
    assert(reader);
    memset(reader, 0, sizeof(*reader));
    reader->root = root ? cep_link_pull(root) : NULL;
}

/** Allocate a reader that reconstructs cells under @p root as chunks arrive. */
cepSerializationReader* cep_serialization_reader_create(cepCell* root) {
    cepSerializationReader* reader = cep_malloc0(sizeof *reader);
    if (!reader)
        return NULL;
    cep_namepool_bootstrap();
    cep_serialization_reader_init(reader, root);
    return reader;
}

/** Destroy a reader, releasing staged chunks and transaction caches. */
void cep_serialization_reader_destroy(cepSerializationReader* reader) {
    if (!reader)
        return;

    cep_serialization_reader_reset(reader);

    if (reader->transactions) {
        cep_free(reader->transactions);
        reader->transactions = NULL;
        reader->transaction_capacity = 0;
    }

    if (reader->stages) {
        cep_free(reader->stages);
        reader->stages = NULL;
        reader->stage_capacity = 0;
    }

    cep_free(reader);
}


/** Reset a reader to its initial state while keeping allocations for reuse. */
void cep_serialization_reader_reset(cepSerializationReader* reader) {
    if (!reader)
        return;

    cep_serialization_reader_clear_stages(reader);
    cep_serialization_reader_clear_transactions(reader);

    reader->header_seen = false;
    reader->pending_commit = false;
    reader->error = false;
    memset(&reader->header, 0, sizeof(reader->header));
}

static bool cep_serialization_reader_ensure_stage_capacity(cepSerializationReader* reader, size_t needed) {
    if (reader->stage_capacity >= needed)
        return true;

    size_t capacity = reader->stage_capacity ? reader->stage_capacity : 4u;
    while (capacity < needed && capacity < (SIZE_MAX >> 1))
        capacity <<= 1u;
    if (capacity < needed)
        capacity = needed;

    size_t bytes = capacity * sizeof(*reader->stages);
    cepSerializationStage* stages = reader->stages ? cep_realloc(reader->stages, bytes) : cep_malloc(bytes);
    if (!stages)
        return false;

    if (capacity > reader->stage_capacity) {
        size_t old_bytes = reader->stage_capacity * sizeof(*reader->stages);
        memset((uint8_t*)stages + old_bytes, 0, bytes - old_bytes);
    }

    reader->stages = stages;
    reader->stage_capacity = capacity;
    return true;
}

static bool cep_serialization_reader_ensure_tx_capacity(cepSerializationReader* reader, size_t needed) {
    if (reader->transaction_capacity >= needed)
        return true;

    size_t capacity = reader->transaction_capacity ? reader->transaction_capacity : 4u;
    while (capacity < needed && capacity < (SIZE_MAX >> 1))
        capacity <<= 1u;
    if (capacity < needed)
        capacity = needed;

    size_t bytes = capacity * sizeof(*reader->transactions);
    cepSerializationTxState* txs = reader->transactions ? cep_realloc(reader->transactions, bytes) : cep_malloc(bytes);
    if (!txs)
        return false;

    if (capacity > reader->transaction_capacity) {
        size_t old_bytes = reader->transaction_capacity * sizeof(*reader->transactions);
        memset((uint8_t*)txs + old_bytes, 0, bytes - old_bytes);
    }

    reader->transactions = txs;
    reader->transaction_capacity = capacity;
    return true;
}

static cepSerializationTxState* cep_serialization_reader_find_tx(cepSerializationReader* reader, uint32_t id) {
    for (size_t i = 0; i < reader->transaction_count; ++i) {
        if (reader->transactions[i].id == id)
            return &reader->transactions[i];
    }
    return NULL;
}

static cepSerializationTxState* cep_serialization_reader_get_tx(cepSerializationReader* reader, uint32_t id) {
    cepSerializationTxState* state = cep_serialization_reader_find_tx(reader, id);
    if (state)
        return state;

    if (!cep_serialization_reader_ensure_tx_capacity(reader, reader->transaction_count + 1u))
        return NULL;

    state = &reader->transactions[reader->transaction_count++];
    memset(state, 0, sizeof(*state));
    state->id = id;
    state->active = true;
    state->last_sequence = 0;
    state->pending_stage = NULL;
    return state;
}

static bool cep_serialization_reader_record_manifest_base(cepSerializationReader* reader,
                                                          cepSerializationTxState* tx,
                                                          uint32_t transaction,
                                                          const uint8_t* payload,
                                                          size_t payload_size);

static bool cep_serialization_reader_record_manifest_children(cepSerializationReader* reader,
                                                              cepSerializationTxState* tx,
                                                              const uint8_t* payload,
                                                              size_t payload_size);

static bool cep_serialization_reader_record_manifest_delta(cepSerializationReader* reader,
                                                           cepSerializationTxState* tx,
                                                           const uint8_t* payload,
                                                           size_t payload_size);

static bool cep_serialization_reader_record_manifest(cepSerializationReader* reader,
                                                     cepSerializationTxState* tx,
                                                     uint32_t transaction,
                                                     const uint8_t* payload,
                                                     size_t payload_size) {
    if (!payload || !payload_size)
        return false;

    uint8_t record_type = payload[0];
    switch (record_type) {
      case SERIAL_RECORD_MANIFEST_BASE:
        return cep_serialization_reader_record_manifest_base(reader,
                                                             tx,
                                                             transaction,
                                                             payload,
                                                             payload_size);
      case SERIAL_RECORD_MANIFEST_CHILDREN:
        return cep_serialization_reader_record_manifest_children(reader,
                                                                 tx,
                                                                 payload,
                                                                 payload_size);
      case SERIAL_RECORD_MANIFEST_DELTA:
        return cep_serialization_reader_record_manifest_delta(reader,
                                                              tx,
                                                              payload,
                                                              payload_size);
      default:
        break;
    }
    return false;
}

static bool cep_serialization_stage_allocate_buffer(cepSerializationStageData* data, size_t size) {
    if (!data)
        return false;

    if (data->buffer) {
        cep_free(data->buffer);
        data->buffer = NULL;
    }

    if (!size) {
        data->size = 0;
        data->next_offset = 0;
        return true;
    }

    data->buffer = cep_malloc(size);
    if (!data->buffer)
        return false;

    data->size = 0;
    data->next_offset = 0;
    return true;
}

static bool cep_serialization_reader_record_data_header(cepSerializationStageData* data,
                                                        const uint8_t* payload,
                                                        size_t payload_size,
                                                        const uint8_t* inline_bytes,
                                                        size_t inline_size) {
    if (!data || !payload)
        return false;

    if (payload_size < 60u) {
        cep_serialization_debug_log("[serialization][debug] reader_data_header short payload payload_size=%zu chunked_flag=%u\n",
                                    payload_size,
                                    data->flags);
        return false;
    }

    data->kind = payload[1u];
    data->flags = cep_serial_read_be16_buf(payload + 2u);
    data->chunked = (data->flags & UINT16_C(0x0001)) != 0u;
    data->journal_beat = cep_serial_read_be64_buf(payload + 4u);
    data->hash = cep_serial_read_be64_buf(payload + 12u);
    data->datatype = cep_serial_read_be16_buf(payload + 20u);
    data->legacy_flags = cep_serial_read_be16_buf(payload + 22u);
    uint32_t inline_len = cep_serial_read_be32_buf(payload + 24u);
    data->total_size = cep_serial_read_be64_buf(payload + 28u);
    data->dt.domain = cep_serial_read_be64_buf(payload + 36u);
    data->dt.tag = cep_serial_read_be64_buf(payload + 44u);
    data->dt.glob = payload[52u] != 0u;

    size_t header_bytes = 60u;
    size_t expected_inline = payload_size - header_bytes;

    char dt_dom_buf[64];
    char dt_tag_buf[64];
    cep_serialization_debug_log("[serialization][debug] reader_data_header payload_size=%zu inline_len=%u inline_size=%zu expected_inline=%zu chunked=%d total_size=%" PRIu64 " datatype=%u journal=%" PRIu64 " hash=%" PRIu64 " dt=%s/%s\n",
                                payload_size,
                                (unsigned)inline_len,
                                inline_size,
                                expected_inline,
                                data->chunked ? 1 : 0,
                                (uint64_t)data->total_size,
                                (unsigned)data->datatype,
                                (uint64_t)data->journal_beat,
                                (uint64_t)data->hash,
                                cep_serialization_id_desc(data->dt.domain, dt_dom_buf, sizeof dt_dom_buf),
                                cep_serialization_id_desc(data->dt.tag, dt_tag_buf, sizeof dt_tag_buf));

    if (data->datatype == CEP_DATATYPE_HANDLE || data->datatype == CEP_DATATYPE_STREAM) {
        if (data->chunked)
            return false;
        if ((size_t)inline_len != inline_size || inline_size != expected_inline)
            return false;
        if (!inline_bytes || inline_size < 4u)
            return false;
        const uint8_t* cursor = inline_bytes;
        size_t remaining = inline_size;
        uint8_t meta_version = cursor[0];
        uint8_t meta_flags = cursor[1];
        cursor += 2u;
        remaining -= 2u;
        uint16_t reserved = cep_serial_read_be16_buf(cursor);
        (void)reserved;
        cursor += 2u;
        remaining -= 2u;
        if (meta_version != 0x01u)
            return false;
        if ((meta_flags & 0x01u) != 0u) {
            if (!cep_serialization_reference_path_decode(&cursor,
                                                         &remaining,
                                                         &data->library_segments,
                                                         &data->library_segment_count)) {
                return false;
            }
        }
        if ((meta_flags & 0x02u) != 0u) {
            if (!cep_serialization_reference_path_decode(&cursor,
                                                         &remaining,
                                                         &data->resource_segments,
                                                         &data->resource_segment_count)) {
                return false;
            }
        }
        if (remaining != 0u)
            return false;
        data->buffer = NULL;
        data->size = 0u;
        data->total_size = 0u;
        data->complete = true;
    } else if (!data->chunked) {
        if ((size_t)inline_len != inline_size || inline_size != expected_inline)
            return false;
        if ((uint64_t)inline_size != data->total_size)
            return false;
        if (!cep_serialization_stage_allocate_buffer(data, inline_size ? inline_size : 1u))
            return false;
        if (inline_size && inline_bytes)
            memcpy(data->buffer, inline_bytes, inline_size);
        data->size = inline_size;
        data->complete = true;
    } else {
        if (inline_len != 0u || expected_inline != 0u)
            return false;
        if (!cep_serialization_stage_allocate_buffer(data, (size_t)data->total_size))
            return false;
        data->complete = (data->total_size == 0u);
    }

    data->header_received = true;
    data->next_offset = 0;
    return true;
}

static bool cep_serialization_reader_record_data_chunk(cepSerializationStageData* data,
                                                       const uint8_t* payload,
                                                       size_t payload_size) {
    if (!data || !payload)
        return false;
    if (!data->header_received || !data->chunked)
        return false;

    if (payload_size < sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t))
        return false;

    uint64_t offset = cep_serial_read_be64_buf(payload);
    uint32_t length = cep_serial_read_be32_buf(payload + sizeof(uint64_t));
    (void)cep_serial_read_be32_buf(payload + sizeof(uint64_t) + sizeof(uint32_t));

    size_t slice = (size_t)length;
    size_t expected = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + slice;
    if (expected != payload_size)
        return false;

    if (offset != data->next_offset)
        return false;

    if (slice && data->buffer)
        memcpy(data->buffer + data->next_offset, payload + expected - slice, slice);

    data->next_offset += slice;
    data->size += slice;

    if (data->next_offset == data->total_size)
        data->complete = true;

    return true;
}

static bool cep_serialization_reader_check_hash(const cepSerializationStageData* data) {
    if (!data)
        return false;
    if (data->datatype == CEP_DATATYPE_HANDLE || data->datatype == CEP_DATATYPE_STREAM)
        return true;
    if (!data->hash)
        return true;
    if (data->total_size && !data->buffer)
        return false;

    uint64_t payload_hash = cep_hash_bytes_fnv1a(data->buffer, (size_t)data->total_size);
    struct {
        uint64_t domain;
        uint64_t tag;
        uint64_t size;
        uint64_t payload;
    } fingerprint = {
        .domain  = data->dt.domain,
        .tag     = data->dt.tag,
        .size    = data->total_size,
        .payload = payload_hash,
    };

    uint64_t computed = cep_hash_bytes_fnv1a(&fingerprint, sizeof fingerprint);
    return computed == data->hash;
}

typedef struct {
    cepSerializationStageChild* child;
    size_t                      index;
} cepSerializationChildOrder;

static int cep_serialization_child_order_cmp(const void* lhs_ptr, const void* rhs_ptr) {
    const cepSerializationChildOrder* lhs = (const cepSerializationChildOrder*)lhs_ptr;
    const cepSerializationChildOrder* rhs = (const cepSerializationChildOrder*)rhs_ptr;
    uint16_t lhs_position = lhs->child ? lhs->child->position : 0u;
    uint16_t rhs_position = rhs->child ? rhs->child->position : 0u;
    if (lhs_position < rhs_position)
        return -1;
    if (lhs_position > rhs_position)
        return 1;
    if (lhs->index < rhs->index)
        return -1;
    if (lhs->index > rhs->index)
        return 1;
    return 0;
}

static int cep_serialization_manifest_child_cmp_name(const void* lhs_ptr,
                                                     const void* rhs_ptr) {
    const cepSerializationManifestChild* lhs =
        (const cepSerializationManifestChild*)lhs_ptr;
    const cepSerializationManifestChild* rhs =
        (const cepSerializationManifestChild*)rhs_ptr;
    if (lhs->name.domain < rhs->name.domain)
        return -1;
    if (lhs->name.domain > rhs->name.domain)
        return 1;
    if (lhs->name.tag < rhs->name.tag)
        return -1;
    if (lhs->name.tag > rhs->name.tag)
        return 1;
    if (lhs->name.glob != rhs->name.glob)
        return lhs->name.glob ? 1 : -1;
    if (lhs->position < rhs->position)
        return -1;
    if (lhs->position > rhs->position)
        return 1;
    return 0;
}

static bool cep_serialization_child_needs_materialization(const cepSerializationStageChild* child) {
    if (!child)
        return false;
    if ((child->delta_flags & SERIAL_DELTA_FLAG_ADD) == 0u)
        return false;
    if ((child->flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u)
        return false;
    uint8_t cell_type = child->cell_type ? child->cell_type : CEP_TYPE_NORMAL;
    if (cell_type != CEP_TYPE_NORMAL)
        return false;
    return true;
}

static bool cep_serialization_child_resolve_descriptor(cepCell* parent,
                                                       const cepSerializationStageChild* descriptor,
                                                       bool positional,
                                                       cepCell** out_child) {
    if (!parent || !descriptor || !out_child)
        return false;

    *out_child = NULL;

    if (!cep_cell_is_normal(parent) || !cep_cell_has_store(parent))
        return true;

    if (positional) {
        size_t position = (size_t)descriptor->position;
        size_t child_count = cep_cell_children(parent);
        if (position >= child_count)
            return true;
        cepCell* slot = cep_cell_find_by_position(parent, position);
        if (!slot)
            return true;
        cepCell* resolved = cep_link_pull(slot);
        if (!resolved)
            return true;
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name)
            return true;
        if (name->domain != descriptor->name.domain ||
            name->tag != descriptor->name.tag ||
            name->glob != descriptor->name.glob)
            return true;
        *out_child = resolved;
        return true;
    }

    cepDT lookup = cep_dt_make(descriptor->name.domain, descriptor->name.tag);
    cepCell* counterpart = cep_cell_find_by_name_all(parent, &lookup);
    if (!counterpart)
        return true;
    cepCell* resolved = cep_link_pull(counterpart);
    if (!resolved)
        return true;
    const cepDT* name = cep_cell_get_name(resolved);
    if (!name)
        return true;
    if (name->domain != descriptor->name.domain ||
        name->tag != descriptor->name.tag ||
        name->glob != descriptor->name.glob)
        return true;
    *out_child = resolved;
    return true;
}

static cepCell* cep_serialization_child_add(cepCell* parent,
                                            cepSerializationStageChild* descriptor,
                                            size_t insert_at) {
    if (!parent || !descriptor)
        return NULL;
    if (!cep_cell_is_normal(parent) || !cep_cell_has_store(parent))
        return NULL;
    cepDT name = descriptor->name;
    uint8_t cell_type = descriptor->cell_type ? descriptor->cell_type : CEP_TYPE_NORMAL;
    cepCell* inserted = NULL;

    switch (cell_type) {
      case CEP_TYPE_NORMAL:
        inserted = cep_cell_add_empty(parent, &name, insert_at);
        break;
      default:
        return NULL;
    }

    if (!inserted)
        return NULL;

    inserted->metacell.veiled = (descriptor->flags & SERIAL_CHILD_FLAG_VEILED) ? 1u : 0u;
#ifdef CEP_ENABLE_DEBUG
    cepDT cleaned = cep_dt_clean(&descriptor->name);
    char dom_buf[64];
    char tag_buf[64];
    const char* parent_dom = "<anon>";
    const char* parent_tag = "<anon>";
    if (parent) {
        char parent_dom_buf[64];
        char parent_tag_buf[64];
        const cepDT* parent_name = cep_cell_get_name(parent);
        if (parent_name) {
            parent_dom = cep_serialization_id_desc(parent_name->domain, parent_dom_buf, sizeof parent_dom_buf);
            parent_tag = cep_serialization_id_desc(parent_name->tag, parent_tag_buf, sizeof parent_tag_buf);
        }
    }
    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][child_add] parent=%p (%s/%s) inserted=%p name=%s/%s type=%u insert_at=%zu\n",
                     (void*)parent,
                     parent_dom,
                     parent_tag,
                     (void*)inserted,
                     cep_serialization_id_desc(cleaned.domain, dom_buf, sizeof dom_buf),
                     cep_serialization_id_desc(cleaned.tag, tag_buf, sizeof tag_buf),
                     (unsigned)cell_type,
                     insert_at);
#endif
    return inserted;
}

static bool cep_serialization_reader_materialize_child_additions(cepSerializationStage* stage,
                                                                 cepCell* current) {
    if (!stage || !current || !stage->child_count || !stage->children)
        return true;

    bool positional = (stage->organiser == SERIAL_ORGANISER_INSERTION);
    bool name_ordered = (stage->organiser == SERIAL_ORGANISER_NAME);

    if (!cep_cell_is_normal(current) || !cep_cell_has_store(current))
        return true;

    cepSerializationChildOrder* order = NULL;
    if (stage->child_count) {
        order = cep_malloc(stage->child_count * sizeof(*order));
        if (!order)
            return false;
        for (size_t i = 0; i < stage->child_count; ++i) {
            order[i].child = &stage->children[i];
            order[i].index = i;
        }
        qsort(order, stage->child_count, sizeof(*order), cep_serialization_child_order_cmp);
    }

    cepDT debug_link_tgt = *CEP_DTAW("CEP", "link_tgt");
#ifdef CEP_ENABLE_DEBUG
    char parent_dom_buf[64];
    char parent_tag_buf[64];
    const char* parent_dom = "<anon>";
    const char* parent_tag = "<anon>";
    const cepDT* parent_name = cep_cell_get_name(current);
    if (parent_name) {
        parent_dom = cep_serialization_id_desc(parent_name->domain, parent_dom_buf, sizeof parent_dom_buf);
        parent_tag = cep_serialization_id_desc(parent_name->tag, parent_tag_buf, sizeof parent_tag_buf);
    }
#endif

    for (size_t i = 0; i < stage->child_count; ++i) {
        cepSerializationStageChild* descriptor = order ? order[i].child : &stage->children[i];
        if (descriptor && descriptor->cell_type == 0u)
            descriptor->cell_type = CEP_TYPE_NORMAL;
        bool needs_creation = cep_serialization_child_needs_materialization(descriptor);
        bool descriptor_tombstone = (descriptor->flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u;
        bool descriptor_delete = (descriptor->delta_flags & SERIAL_DELTA_FLAG_DELETE) != 0u;
        bool needs_tombstone = descriptor_tombstone || (name_ordered && descriptor_delete);
#ifdef CEP_ENABLE_DEBUG
        cepDT descriptor_name_clean = cep_dt_clean(&descriptor->name);
        if (descriptor_name_clean.domain == debug_link_tgt.domain &&
            descriptor_name_clean.tag == debug_link_tgt.tag) {
            char child_dom_buf[64];
            char child_tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][materialize][link_tgt] name=%s/%s needs_creation=%d needs_tombstone=%d flags=0x%02x delta=0x%02x\n",
                             cep_serialization_id_desc(descriptor_name_clean.domain, child_dom_buf, sizeof child_dom_buf),
                             cep_serialization_id_desc(descriptor_name_clean.tag, child_tag_buf, sizeof child_tag_buf),
                             needs_creation ? 1 : 0,
                             needs_tombstone ? 1 : 0,
                             (unsigned)descriptor->flags,
                             (unsigned)descriptor->delta_flags);
        }
#endif
        if (!needs_creation && !needs_tombstone)
            continue;

        cepCell* existing = NULL;
        if (!cep_serialization_child_resolve_descriptor(current, descriptor, positional, &existing)) {
            if (order)
                cep_free(order);
            return false;
        }
        bool exists = existing != NULL;
#ifdef CEP_ENABLE_DEBUG
        if (needs_tombstone) {
            char child_dom_buf[64];
            char child_tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][materialize] tombstone descriptor parent=%s/%s name=%s/%s exists=%d pos=%u delta=0x%02x\n",
                             parent_dom,
                             parent_tag,
                             cep_serialization_id_desc(descriptor->name.domain, child_dom_buf, sizeof child_dom_buf),
                             cep_serialization_id_desc(descriptor->name.tag, child_tag_buf, sizeof child_tag_buf),
                             exists ? 1 : 0,
                             (unsigned)descriptor->position,
                             (unsigned)descriptor->delta_flags);
        }
#endif
        if (needs_tombstone) {
            if (exists) {
                cepCell* resolved_existing = cep_link_pull(existing);
                if (resolved_existing && !cep_cell_is_deleted(resolved_existing)) {
                    cep_cell_delete(resolved_existing);
#ifdef CEP_ENABLE_DEBUG
                    cepDT cleaned = cep_dt_clean(&descriptor->name);
                    char dom_buf[64];
                    char tag_buf[64];
                    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][materialize] tombstone applied to existing child parent=%p (%s/%s) child=%p name=%s/%s\n",
                                     (void*)current,
                                     parent_dom,
                                     parent_tag,
                                     (void*)resolved_existing,
                                     cep_serialization_id_desc(cleaned.domain, dom_buf, sizeof dom_buf),
                                     cep_serialization_id_desc(cleaned.tag, tag_buf, sizeof tag_buf));
#endif
                }
                continue;
            }

            size_t insert_at = positional ? (size_t)descriptor->position : cep_cell_children(current);
            if (positional) {
                size_t child_count = cep_cell_children(current);
                if (insert_at > child_count)
                    insert_at = child_count;
            }

            cepCell* inserted = cep_serialization_child_add(current, descriptor, insert_at);
            if (!inserted)
                continue;

            descriptor->freshly_materialized = true;
            cep_cell_delete(inserted);
#ifdef CEP_ENABLE_DEBUG
            cepDT cleaned = cep_dt_clean(&descriptor->name);
            char dom_buf[64];
            char tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][materialize] tombstone node created parent=%p (%s/%s) child=%p pos=%zu name=%s/%s\n",
                             (void*)current,
                             parent_dom,
                             parent_tag,
                             (void*)inserted,
                             insert_at,
                             cep_serialization_id_desc(cleaned.domain, dom_buf, sizeof dom_buf),
                             cep_serialization_id_desc(cleaned.tag, tag_buf, sizeof tag_buf));
#endif
            continue;
        }

        if (!needs_creation)
            continue;

        if (exists)
            continue;

        size_t insert_at = positional ? (size_t)descriptor->position : cep_cell_children(current);
        if (positional) {
            size_t child_count = cep_cell_children(current);
            if (insert_at > child_count)
                insert_at = child_count;
        }

        cepCell* inserted = cep_serialization_child_add(current, descriptor, insert_at);
        if (!inserted)
            continue;
        descriptor->freshly_materialized = true;
#ifdef CEP_ENABLE_DEBUG
        cepDT cleaned = cep_dt_clean(&descriptor->name);
        char dom_buf[64];
        char tag_buf[64];
        CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][materialize] child retained parent=%p (%s/%s) child=%p pos=%zu name=%s/%s\n",
                         (void*)current,
                         parent_dom,
                         parent_tag,
                         (void*)inserted,
                         insert_at,
                         cep_serialization_id_desc(cleaned.domain, dom_buf, sizeof dom_buf),
                         cep_serialization_id_desc(cleaned.tag, tag_buf, sizeof tag_buf));
#endif
    }

    if (order)
        cep_free(order);
    return true;
}


static bool cep_serialization_reader_validate_manifest_children(const cepSerializationReader* reader,
                                                                cepSerializationStage* stage,
                                                                cepCell* current) {
    (void)reader;
    if (!stage || !current)
        return false;

    bool positional = (stage->organiser == SERIAL_ORGANISER_INSERTION);
#ifdef CEP_ENABLE_DEBUG
    char parent_dom_buf[64];
    char parent_tag_buf[64];
    const char* parent_dom = "<anon>";
    const char* parent_tag = "<anon>";
    const cepDT* parent_name = cep_cell_get_name(current);
    if (parent_name) {
        parent_dom = cep_serialization_id_desc(parent_name->domain, parent_dom_buf, sizeof parent_dom_buf);
        parent_tag = cep_serialization_id_desc(parent_name->tag, parent_tag_buf, sizeof parent_tag_buf);
    }
#endif

    typedef struct {
        cepCell*        cell;
        const cepDT*    name;
        size_t          position;
        bool            matched;
        bool            deleted;
        bool            veiled;
        uint8_t         type;
        bool            fingerprint_valid;
        uint64_t        fingerprint;
    } ValidationChild;

    ValidationChild* actual_children = NULL;
    size_t actual_len = 0u;
    size_t actual_capacity = 0u;

    for (size_t i = 0; i < stage->child_count; ++i)
        stage->children[i].matched = false;

    if (positional) {
        actual_capacity = stage->child_count ? stage->child_count : 4u;
        if (actual_capacity)
            actual_children = cep_malloc(sizeof(*actual_children) * actual_capacity);
        if (actual_capacity && !actual_children)
            return false;

        size_t position_index = 0u;
        for (cepCell* child = cep_cell_first_all(current); child; child = cep_cell_next_all(current, child)) {
            cepCell* resolved = cep_link_pull(child);
            if (!resolved || !cep_cell_is_normal(resolved))
                continue;
            const cepDT* name = cep_cell_get_name(resolved);
            if (!name)
                continue;

            if (actual_len >= actual_capacity) {
                size_t new_capacity = actual_capacity ? actual_capacity * 2u : 4u;
                ValidationChild* grown = cep_realloc(actual_children, sizeof(*actual_children) * new_capacity);
                if (!grown) {
                    if (actual_children)
                        cep_free(actual_children);
                    return false;
                }
                actual_children = grown;
                actual_capacity = new_capacity;
            }

            actual_children[actual_len++] = (ValidationChild){
                .cell = resolved,
                .name = name,
                .position = position_index,
                .matched = false,
                .deleted = cep_cell_is_deleted(resolved),
                .veiled = resolved->metacell.veiled != 0u,
                .type = (uint8_t)resolved->metacell.type,
                .fingerprint_valid = false,
                .fingerprint = 0u,
            };
            position_index++;
        }
    }

    if (positional) {
        for (size_t i = 0; i < stage->child_count; ++i) {
            cepSerializationStageChild* descriptor = &stage->children[i];
            bool expect_tombstone = (descriptor->flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u;

            if (expect_tombstone) {
                ValidationChild* entry = NULL;
                for (size_t j = 0; j < actual_len; ++j) {
                    ValidationChild* candidate = &actual_children[j];
                    if (candidate->matched)
                        continue;
                    if (candidate->position != (size_t)descriptor->position)
                        continue;
                    entry = candidate;
                    break;
                }
            if (entry && !entry->deleted) {
#ifdef CEP_ENABLE_DEBUG
                    char desc_dom_buf[64];
                    char desc_tag_buf[64];
                    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=tombstone_not_deleted pos=%u name=%s/%s\n",
                                     parent_dom,
                                     parent_tag,
                                     (unsigned)descriptor->position,
                                     cep_serialization_id_desc(descriptor->name.domain, desc_dom_buf, sizeof desc_dom_buf),
                                     cep_serialization_id_desc(descriptor->name.tag, desc_tag_buf, sizeof desc_tag_buf));
#endif
                if (actual_children)
                    cep_free(actual_children);
                return false;
            }
                if (entry)
                    entry->matched = true;
                descriptor->matched = true;
                continue;
            }

            ValidationChild* candidate = NULL;
            for (size_t j = 0; j < actual_len; ++j) {
                ValidationChild* entry = &actual_children[j];
                if (entry->matched)
                    continue;
                if (entry->position != (size_t)descriptor->position)
                    continue;
                candidate = entry;
                break;
            }

            if ((descriptor->delta_flags & SERIAL_DELTA_FLAG_ADD) != 0u) {
                if (candidate)
                    candidate->matched = true;
                descriptor->matched = true;
                continue;
            }

            if (!candidate || candidate->deleted) {
#ifdef CEP_ENABLE_DEBUG
                char desc_dom_buf[64];
                char desc_tag_buf[64];
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=missing_candidate pos=%u deleted=%d name=%s/%s\n",
                                 parent_dom,
                                 parent_tag,
                                 (unsigned)descriptor->position,
                                 candidate ? candidate->deleted : -1,
                                 cep_serialization_id_desc(descriptor->name.domain, desc_dom_buf, sizeof desc_dom_buf),
                                 cep_serialization_id_desc(descriptor->name.tag, desc_tag_buf, sizeof desc_tag_buf));
#endif
                if (actual_children)
                    cep_free(actual_children);
                return false;
            }

            if (candidate->name->domain != descriptor->name.domain ||
                candidate->name->tag != descriptor->name.tag ||
                candidate->name->glob != descriptor->name.glob) {
#ifdef CEP_ENABLE_DEBUG
                char desc_dom_buf[64];
                char desc_tag_buf[64];
                char cand_dom_buf[64];
                char cand_tag_buf[64];
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=name pos=%u expected=%s/%s actual=%s/%s\n",
                                 parent_dom,
                                 parent_tag,
                                 (unsigned)descriptor->position,
                                 cep_serialization_id_desc(descriptor->name.domain, desc_dom_buf, sizeof desc_dom_buf),
                                 cep_serialization_id_desc(descriptor->name.tag, desc_tag_buf, sizeof desc_tag_buf),
                                 cep_serialization_id_desc(candidate->name->domain, cand_dom_buf, sizeof cand_dom_buf),
                                 cep_serialization_id_desc(candidate->name->tag, cand_tag_buf, sizeof cand_tag_buf));
#endif
                if (actual_children)
                    cep_free(actual_children);
                return false;
            }

            if (descriptor->cell_type && candidate->type != descriptor->cell_type) {
#ifdef CEP_ENABLE_DEBUG
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=type pos=%u expected=%u actual=%u\n",
                                 parent_dom,
                                 parent_tag,
                                 (unsigned)descriptor->position,
                                 (unsigned)descriptor->cell_type,
                                 (unsigned)candidate->type);
#endif
                if (actual_children)
                    cep_free(actual_children);
                return false;
            }

            bool expected_veiled = (descriptor->flags & SERIAL_CHILD_FLAG_VEILED) != 0u;
            if (candidate->veiled != expected_veiled) {
#ifdef CEP_ENABLE_DEBUG
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=veiled pos=%u expected=%d actual=%d\n",
                                 parent_dom,
                                 parent_tag,
                                 (unsigned)descriptor->position,
                                 expected_veiled ? 1 : 0,
                                 candidate->veiled ? 1 : 0);
#endif
                if (actual_children)
                    cep_free(actual_children);
                return false;
            }

            if (descriptor->has_fingerprint && !descriptor->freshly_materialized) {
                if (!candidate->fingerprint_valid) {
                    if (!cep_serialization_compute_cell_fingerprint(candidate->cell, &candidate->fingerprint)) {
                        if (actual_children)
                            cep_free(actual_children);
                        return false;
                    }
                    candidate->fingerprint_valid = true;
                }
                if (candidate->fingerprint != descriptor->fingerprint) {
#ifdef CEP_ENABLE_DEBUG
                    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=fingerprint pos=%u expected=0x%016" PRIx64 " actual=0x%016" PRIx64 "\n",
                                     parent_dom,
                                     parent_tag,
                                     (unsigned)descriptor->position,
                                     descriptor->fingerprint,
                                     candidate->fingerprint);
#endif
                    if (actual_children)
                        cep_free(actual_children);
                    return false;
                }
            }

            candidate->matched = true;
            descriptor->matched = true;
        }

        for (size_t j = 0; j < actual_len; ++j) {
            ValidationChild* entry = &actual_children[j];
            if (!entry->matched && !entry->deleted) {
#ifdef CEP_ENABLE_DEBUG
                char cand_dom_buf[64];
                char cand_tag_buf[64];
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=extra_child pos=%zu name=%s/%s\n",
                                 parent_dom,
                                 parent_tag,
                                 entry->position,
                                 entry->name ? cep_serialization_id_desc(entry->name->domain, cand_dom_buf, sizeof cand_dom_buf) : "<unknown>",
                                 entry->name ? cep_serialization_id_desc(entry->name->tag, cand_tag_buf, sizeof cand_tag_buf) : "<unknown>");
#endif
                if (actual_children)
                    cep_free(actual_children);
                return false;
            }
        }

        if (actual_children)
            cep_free(actual_children);
        return true;
    }

    for (size_t i = 0; i < stage->child_count; ++i) {
        cepSerializationStageChild* descriptor = &stage->children[i];
        cepDT name = cep_dt_make(descriptor->name.domain, descriptor->name.tag);
        cepCell* counterpart = cep_cell_find_by_name_all(current, &name);

        if ((descriptor->flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u) {
            if (counterpart) {
                cepCell* resolved = cep_link_pull(counterpart);
                if (resolved && !cep_cell_is_deleted(resolved)) {
#ifdef CEP_ENABLE_DEBUG
                    char desc_dom_buf[64];
                    char desc_tag_buf[64];
                    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=name_tombstone_not_deleted name=%s/%s\n",
                                     parent_dom,
                                     parent_tag,
                                     cep_serialization_id_desc(descriptor->name.domain, desc_dom_buf, sizeof desc_dom_buf),
                                     cep_serialization_id_desc(descriptor->name.tag, desc_tag_buf, sizeof desc_tag_buf));
#endif
                    return false;
                }
            }
            descriptor->matched = true;
            continue;
        }

        if (!counterpart) {
            if ((descriptor->delta_flags & SERIAL_DELTA_FLAG_ADD) != 0u) {
                descriptor->matched = true;
                continue;
            }
#ifdef CEP_ENABLE_DEBUG
            char desc_dom_buf[64];
            char desc_tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=missing_counterpart name=%s/%s\n",
                             parent_dom,
                             parent_tag,
                             cep_serialization_id_desc(descriptor->name.domain, desc_dom_buf, sizeof desc_dom_buf),
                             cep_serialization_id_desc(descriptor->name.tag, desc_tag_buf, sizeof desc_tag_buf));
#endif
            return false;
        }

        cepCell* resolved = cep_link_pull(counterpart);
        if (!resolved) {
#ifdef CEP_ENABLE_DEBUG
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=counterpart_resolve\n",
                             parent_dom,
                             parent_tag);
#endif
            return false;
        }

        const cepDT* resolved_name = cep_cell_get_name(resolved);
        if (!resolved_name) {
#ifdef CEP_ENABLE_DEBUG
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=counterpart_name\n",
                             parent_dom,
                             parent_tag);
#endif
            return false;
        }
        if (resolved_name->domain != descriptor->name.domain ||
            resolved_name->tag != descriptor->name.tag ||
            resolved_name->glob != descriptor->name.glob) {
#ifdef CEP_ENABLE_DEBUG
            char desc_dom_buf[64];
            char desc_tag_buf[64];
            char cand_dom_buf[64];
            char cand_tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=name expected=%s/%s actual=%s/%s\n",
                             parent_dom,
                             parent_tag,
                             cep_serialization_id_desc(descriptor->name.domain, desc_dom_buf, sizeof desc_dom_buf),
                             cep_serialization_id_desc(descriptor->name.tag, desc_tag_buf, sizeof desc_tag_buf),
                             cep_serialization_id_desc(resolved_name->domain, cand_dom_buf, sizeof cand_dom_buf),
                             cep_serialization_id_desc(resolved_name->tag, cand_tag_buf, sizeof cand_tag_buf));
#endif
            return false;
        }

        if (descriptor->cell_type && (uint8_t)resolved->metacell.type != descriptor->cell_type) {
#ifdef CEP_ENABLE_DEBUG
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=type expected=%u actual=%u\n",
                             parent_dom,
                             parent_tag,
                             (unsigned)descriptor->cell_type,
                             (unsigned)resolved->metacell.type);
#endif
            return false;
        }

        bool expected_veiled = (descriptor->flags & SERIAL_CHILD_FLAG_VEILED) != 0u;
        if ((resolved->metacell.veiled != 0u) != expected_veiled) {
#ifdef CEP_ENABLE_DEBUG
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=veiled expected=%d actual=%d\n",
                             parent_dom,
                             parent_tag,
                             expected_veiled ? 1 : 0,
                             resolved->metacell.veiled ? 1 : 0);
#endif
            return false;
        }

        if (descriptor->has_fingerprint && !descriptor->freshly_materialized) {
            uint64_t fingerprint = 0u;
            if (!cep_serialization_compute_cell_fingerprint(resolved, &fingerprint)) {
#ifdef CEP_ENABLE_DEBUG
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=fingerprint_compute\n",
                                 parent_dom,
                                 parent_tag);
#endif
                return false;
            }
            if (fingerprint != descriptor->fingerprint) {
#ifdef CEP_ENABLE_DEBUG
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=fingerprint expected=0x%016" PRIx64 " actual=0x%016" PRIx64 "\n",
                                 parent_dom,
                                 parent_tag,
                                 descriptor->fingerprint,
                                 fingerprint);
#endif
                return false;
            }
        }

        if (cep_cell_is_deleted(resolved)) {
#ifdef CEP_ENABLE_DEBUG
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=unexpected_deletion name=%s/%s\n",
                             parent_dom,
                             parent_tag,
                             parent_dom,
                             parent_tag);
#endif
            return false;
        }

        descriptor->matched = true;
    }

    for (cepCell* child = cep_cell_first_all(current); child; child = cep_cell_next_all(current, child)) {
        cepCell* resolved = cep_link_pull(child);
        if (!resolved || !cep_cell_is_normal(resolved))
            continue;
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name)
            continue;

        const cepSerializationStageChild* descriptor = cep_serialization_stage_find_child(stage,
                                                                                         name,
                                                                                         false,
                                                                                         0u);
        if (!descriptor) {
#ifdef CEP_ENABLE_DEBUG
            char child_dom_buf[64];
            char child_tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=unexpected_child name=%s/%s\n",
                             parent_dom,
                             parent_tag,
                             cep_serialization_id_desc(name->domain, child_dom_buf, sizeof child_dom_buf),
                             cep_serialization_id_desc(name->tag, child_tag_buf, sizeof child_tag_buf));
#endif
            return false;
        }

        if ((descriptor->flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u) {
            if (!cep_cell_is_deleted(resolved)) {
#ifdef CEP_ENABLE_DEBUG
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=tombstone_unexpected_live name=%s/%s\n",
                                 parent_dom,
                                 parent_tag,
                                 parent_dom,
                                 parent_tag);
#endif
                return false;
            }
            continue;
        }

        if (cep_cell_is_deleted(resolved)) {
#ifdef CEP_ENABLE_DEBUG
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][validate] parent=%s/%s mismatch=child_deleted name=%s/%s\n",
                             parent_dom,
                             parent_tag,
                             parent_dom,
                             parent_tag);
#endif
            return false;
        }
    }

    return true;
}


static unsigned cep_serialization_index_from_organiser(uint8_t organiser) {
    switch (organiser) {
      case SERIAL_ORGANISER_INSERTION:
        return CEP_INDEX_BY_INSERTION;
      case SERIAL_ORGANISER_NAME:
        return CEP_INDEX_BY_NAME;
      case SERIAL_ORGANISER_HASH:
        return CEP_INDEX_BY_HASH;
      case SERIAL_ORGANISER_FUNCTION:
      case SERIAL_ORGANISER_FUNCTION_OCTREE:
        return CEP_INDEX_BY_FUNCTION;
      default:
        return CEP_INDEX_BY_NAME;
    }
}

static unsigned cep_serialization_storage_from_hint(uint8_t hint, unsigned index) {
    uint8_t code = hint & (uint8_t)~SERIAL_STORAGE_FLAG_METADATA;
    switch (code) {
      case 0x01u:
        return CEP_STORAGE_LINKED_LIST;
      case 0x02u:
        return CEP_STORAGE_RED_BLACK_T;
      case 0x03u:
        return CEP_STORAGE_ARRAY;
      case 0x04u:
        return CEP_STORAGE_PACKED_QUEUE;
      case 0x05u:
        return CEP_STORAGE_HASH_TABLE;
      case 0x06u:
        return CEP_STORAGE_OCTREE;
      default:
        break;
    }
    switch (index) {
      case CEP_INDEX_BY_INSERTION:
        return CEP_STORAGE_LINKED_LIST;
      case CEP_INDEX_BY_FUNCTION:
        return CEP_STORAGE_RED_BLACK_T;
      case CEP_INDEX_BY_HASH:
        return CEP_STORAGE_HASH_TABLE;
      case CEP_INDEX_BY_NAME:
      default:
        return CEP_STORAGE_RED_BLACK_T;
    }
}

static bool cep_serialization_reader_configure_store(cepCell* current,
                                                     uint8_t organiser,
                                                     uint8_t storage_hint,
                                                     const cepDT* store_dt,
                                                     const uint8_t* store_meta,
                                                     size_t store_meta_size) {
    if (!current || !cep_cell_is_normal(current))
        return false;

    unsigned desired_index = cep_serialization_index_from_organiser(organiser);
    unsigned desired_storage = cep_serialization_storage_from_hint(storage_hint, desired_index);

    cepStore* existing = current->store;
    cepSerializationStoreMeta meta = {0};
    if (store_meta && store_meta_size) {
        if (!cep_serialization_parse_store_metadata(store_meta, store_meta_size, &meta))
            return false;
    }
    size_t layout_capacity = 0u;
    if (meta.has_layout && meta.layout_storage == desired_storage)
        layout_capacity = (size_t)meta.layout_capacity;
    cepDT configured = {0};
    if (meta.has_type)
        configured = cep_dt_clean(&meta.type);
    else if (store_dt && cep_dt_is_valid(store_dt))
        configured = cep_dt_clean(store_dt);

#ifdef CEP_ENABLE_DEBUG
    cepDT configured_snapshot = configured;
    const cepDT* existing_dt = (existing && cep_dt_is_valid(&existing->dt)) ? &existing->dt : NULL;
    char configured_dom_buf[64];
    char configured_tag_buf[64];
    char existing_dom_buf[64];
    char existing_tag_buf[64];
    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][store_config] node=%p organiser=0x%02x storage_hint=0x%02x desired_index=%u desired_storage=%u has_store=%d current_index=%u current_storage=%u manageable=%d configured_dt=%s/%s existing_dt=%s/%s\n",
                     (void*)current,
                     (unsigned)organiser,
                     (unsigned)storage_hint,
                     desired_index,
                     desired_storage,
                     existing ? 1 : 0,
                     existing ? existing->indexing : 0u,
                     existing ? existing->storage : 0u,
                     (desired_index == CEP_INDEX_BY_INSERTION || desired_index == CEP_INDEX_BY_NAME) ? 1 : 0,
                     cep_serialization_id_desc(configured_snapshot.domain, configured_dom_buf, sizeof configured_dom_buf),
                     cep_serialization_id_desc(configured_snapshot.tag, configured_tag_buf, sizeof configured_tag_buf),
                     existing_dt ? cep_serialization_id_desc(existing_dt->domain, existing_dom_buf, sizeof existing_dom_buf) : "<none>",
                     existing_dt ? cep_serialization_id_desc(existing_dt->tag, existing_tag_buf, sizeof existing_tag_buf) : "<none>");
#endif

    size_t existing_children = existing ? cep_cell_children(current) : 0u;
    bool requires_replacement = true;
    if (existing &&
        existing->indexing == desired_index &&
        existing->storage == desired_storage) {
        requires_replacement = false;
        if (meta.has_comparator) {
            cepCompareInfo current_info = {0};
            if (!existing->compare) {
                cepCompare comparator = cep_comparator_registry_lookup(&meta.comparator);
                if (!comparator)
                    return false;
                existing->compare = comparator;
            } else if (!cep_compare_identity(existing->compare, &current_info) ||
                       !cep_compare_info_equal(&current_info, &meta.comparator)) {
                return false;
            }
        }
        if (cep_dt_is_valid(&configured))
            existing->dt = configured;
        if (existing->storage == CEP_STORAGE_ARRAY || existing->storage == CEP_STORAGE_PACKED_QUEUE ||
            existing->storage == CEP_STORAGE_HASH_TABLE) {
            existing->writable = 1u;
        }
    }

    if (existing && requires_replacement && existing_children > 0u &&
        existing->indexing == CEP_INDEX_BY_INSERTION) {
#ifdef CEP_ENABLE_DEBUG
        cepDT name_snapshot = {0};
        const cepDT* name = cep_cell_get_name(current);
        if (name)
            name_snapshot = *name;
        char dom_buf[64];
        char tag_buf[64];
        CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][store_config][preserve] node=%p name=%s/%s"
                         " existing_index=%u existing_storage=%u desired_index=%u desired_storage=%u children=%zu\n",
                         (void*)current,
                         cep_serialization_id_desc(name_snapshot.domain, dom_buf, sizeof dom_buf),
                         cep_serialization_id_desc(name_snapshot.tag, tag_buf, sizeof tag_buf),
                         (unsigned)existing->indexing,
                         (unsigned)existing->storage,
                         desired_index,
                         desired_storage,
                         existing_children);
#endif
        requires_replacement = false;
    }

    if (!requires_replacement)
        return true;

    if (!cep_dt_is_valid(&configured)) {
        if (existing && cep_dt_is_valid(&existing->dt)) {
            configured = cep_dt_clean(&existing->dt);
        } else if (desired_index == CEP_INDEX_BY_INSERTION) {
            configured = *dt_list_type_default();
        } else {
            configured = *dt_dictionary_type();
        }
    }

    cepStore* replacement = NULL;
    bool needs_compare = (desired_index == CEP_INDEX_BY_FUNCTION || desired_index == CEP_INDEX_BY_HASH);
    cepCompare comparator = NULL;
    if (needs_compare) {
        if (meta.has_comparator) {
            comparator = cep_comparator_registry_lookup(&meta.comparator);
            if (!comparator) {
                cep_serialization_emit_failure("serialization.store.comparator_unknown",
                                               current,
                                               "missing comparator entry domain=%016" PRIx64 " tag=%016" PRIx64 " version=%u flags=0x%08x",
                                               (uint64_t)meta.comparator.identifier.domain,
                                               (uint64_t)meta.comparator.identifier.tag,
                                               meta.comparator.version,
                                               meta.comparator.flags);
                return false;
            }
        } else if (desired_storage == CEP_STORAGE_OCTREE) {
            comparator = cep_serialization_octree_compare_stub;
        } else {
            comparator = cep_serialization_default_compare;
        }
    }

    if (desired_storage == CEP_STORAGE_OCTREE) {
        float center[3] = {0};
        float subwide = 0.0f;
        uint16_t max_depth = 0u;
        uint16_t max_per_node = 0u;
        float min_subwide = 0.0f;
        if (!meta.has_octree ||
            !cep_serialization_parse_octree_metadata(meta.octree_payload,
                                                     meta.octree_payload_size,
                                                     center,
                                                     &subwide,
                                                     &max_depth,
                                                     &max_per_node,
                                                     &min_subwide)) {
            return false;
        }
        double bound = (double)subwide;
        if (bound <= 0.0)
            bound = 1.0;
        cepCompare octree_compare = comparator ? comparator : cep_serialization_octree_compare_stub;
        replacement = cep_store_new(&configured,
                                    desired_storage,
                                    desired_index,
                                    center,
                                    bound,
                                    octree_compare);
        if (!replacement)
            return false;
        cepOctree* octree = (cepOctree*)replacement;
        octree_set_policy(octree, max_depth, max_per_node, min_subwide);
    } else if (desired_storage == CEP_STORAGE_ARRAY) {
        size_t capacity_hint = layout_capacity ? layout_capacity : 8u;
        replacement = cep_store_new(&configured, desired_storage, desired_index, capacity_hint);
    } else if (desired_storage == CEP_STORAGE_PACKED_QUEUE) {
        size_t capacity_hint = layout_capacity ? layout_capacity : 8u;
        replacement = cep_store_new(&configured, desired_storage, desired_index, capacity_hint);
    } else if (desired_storage == CEP_STORAGE_HASH_TABLE) {
        size_t capacity_hint = layout_capacity ? layout_capacity : 16u;
        cepCompare selected = comparator ? comparator : cep_serialization_default_compare;
        replacement = cep_store_new(&configured, desired_storage, desired_index, capacity_hint, selected);
    } else if (needs_compare) {
        cepCompare selected = comparator ? comparator : cep_serialization_default_compare;
        replacement = cep_store_new(&configured, desired_storage, desired_index, selected);
    } else {
        replacement = cep_store_new(&configured, desired_storage, desired_index);
    }
    if (!replacement)
        return false;
    replacement->owner = current;
    replacement->writable = 1u;

    if (existing) {
        cep_store_delete_children_hard(existing);
        cep_store_del(existing);
    }

    current->store = replacement;
    return true;
}


static bool cep_serialization_reader_apply_stage(const cepSerializationReader* reader,
                                                 cepSerializationStage* stage) {
    const char* fail_reason = NULL;
    unsigned path_length = 0u;
    unsigned limit = 0u;
    if (!reader || !stage || !reader->root) {
        fail_reason = "invalid_args";
        goto fail;
    }

    path_length = stage->path ? stage->path->length : 0u;
    if (!path_length) {
        fail_reason = "empty_path";
        goto fail;
    }

    limit = path_length;

    bool child_flag = (stage->base_flags & SERIAL_BASE_FLAG_CHILDREN) != 0u;
    bool store_meta_present = stage->store_metadata && stage->store_metadata_size;
    bool has_storage_hint = stage->storage_hint != 0u;
    bool configure_store = child_flag || store_meta_present || has_storage_hint;
    if ((stage->base_flags & SERIAL_BASE_FLAG_CHILDREN_SPLIT) != 0u) {
        if (!stage->descriptor_spans_expected ||
            stage->descriptor_spans_seen < stage->descriptor_spans_expected ||
            (stage->child_target && stage->child_count < stage->child_target)) {
            fail_reason = "descriptor_pending";
            goto fail;
        }
    }

    if (child_flag && limit == 0u) {
        fail_reason = "limit_children_zero";
        goto fail;
    }

    if (stage->data.needed) {
        if (limit == 0u) {
            fail_reason = "limit_data_zero";
            goto fail;
        }
        const cepPast* data_segment = &stage->path->past[limit - 1u];
        bool dt_valid = stage->data.dt.domain || stage->data.dt.tag || stage->data.dt.glob;
        bool payload_segment = false;
        if (dt_valid) {
            payload_segment = (stage->data.dt.domain == data_segment->dt.domain) &&
                              (stage->data.dt.tag == data_segment->dt.tag) &&
                              ((stage->data.dt.glob != 0u) == (data_segment->dt.glob != 0u));
        }
        if (payload_segment) {
            limit--;
        } else if (dt_valid) {
#ifdef CEP_ENABLE_DEBUG
            char data_dom_buf[64];
            char data_tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][apply_stage] payload path sentinel missing; treating full path as structural "
                             "path_len=%u data_dt=%s/%s\n",
                             (unsigned)path_length,
                             cep_serialization_id_desc(stage->data.dt.domain, data_dom_buf, sizeof data_dom_buf),
                             cep_serialization_id_desc(stage->data.dt.tag, data_tag_buf, sizeof data_tag_buf));
#endif
        }
    }

    if (limit == 0u) {
        fail_reason = "limit_zero";
        goto fail;
    }
#ifdef CEP_ENABLE_DEBUG
    CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][apply_stage] path_len=%u limit=%u base_flags=0x%02x children=%zu organiser=0x%02x storage_hint=0x%02x child_target=%zu\n",
                     (unsigned)path_length,
                     (unsigned)limit,
                     (unsigned)stage->base_flags,
                     (size_t)stage->child_count,
                     (unsigned)stage->organiser,
                     (unsigned)stage->storage_hint,
                     stage->child_target);
    if (stage->path && stage->path->length <= 5u) {
        CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][apply_stage] path segments:");
        for (unsigned idx = 0; idx < stage->path->length; ++idx) {
            cepDT cleaned = cep_dt_clean(&stage->path->past[idx].dt);
            char dom_buf[64];
            char tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("  [%u]=%s/%s%s",
                             idx,
                             cep_serialization_id_desc(cleaned.domain, dom_buf, sizeof dom_buf),
                             cep_serialization_id_desc(cleaned.tag, tag_buf, sizeof tag_buf),
                             cleaned.glob ? "*" : "");
        }
    }
#endif

#ifdef CEP_ENABLE_DEBUG
    cepDT debug_link_tgt = *CEP_DTAW("CEP", "link_tgt");
    cepDT debug_poc = *CEP_DTAW("CEP", "poc");
    if (stage->path && path_length) {
        bool contains_link_tgt = false;
        bool contains_poc = false;
        for (unsigned idx = 0; idx < path_length; ++idx) {
            cepDT cleaned = cep_dt_clean(&stage->path->past[idx].dt);
            if (cleaned.domain == debug_link_tgt.domain &&
                cleaned.tag == debug_link_tgt.tag) {
                contains_link_tgt = true;
            }
            if (cleaned.domain == debug_poc.domain &&
                cleaned.tag == debug_poc.tag) {
                contains_poc = true;
            }
        }
        if (contains_link_tgt) {
        CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][apply_stage][link_tgt] children=%zu base_flags=0x%02x organiser=0x%02x storage_hint=0x%02x\n",
                         (size_t)stage->child_count,
                         (unsigned)stage->base_flags,
                         (unsigned)stage->organiser,
                         (unsigned)stage->storage_hint);
        for (size_t idx = 0; idx < stage->child_count; ++idx) {
            const cepSerializationStageChild* child = &stage->children[idx];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][link_tgt_child] idx=%zu flags=0x%02x delta=0x%02x pos=%u type=%u fingerprint=%s\n",
                             idx,
                             (unsigned)child->flags,
                             (unsigned)child->delta_flags,
                             (unsigned)child->position,
                             (unsigned)child->cell_type,
                             child->has_fingerprint ? "yes" : "no");
        }
        }
        if (contains_poc) {
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][apply_stage][poc] children=%zu base_flags=0x%02x organiser=0x%02x storage_hint=0x%02x\n",
                             (size_t)stage->child_count,
                             (unsigned)stage->base_flags,
                             (unsigned)stage->organiser,
                             (unsigned)stage->storage_hint);
            for (size_t idx = 0; idx < stage->child_count; ++idx) {
                const cepSerializationStageChild* child = &stage->children[idx];
                char dom_buf[64];
                char tag_buf[64];
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][poc_child] idx=%zu name=%s/%s%s flags=0x%02x delta=0x%02x pos=%u\n",
                                 idx,
                                 cep_serialization_id_desc(child->name.domain, dom_buf, sizeof dom_buf),
                                 cep_serialization_id_desc(child->name.tag, tag_buf, sizeof tag_buf),
                                 child->name.glob ? "*" : "",
                                 (unsigned)child->flags,
                                 (unsigned)child->delta_flags,
                                 (unsigned)child->position);
            }
        }
    }
#endif

    const cepDT* store_dt = NULL;
    if (configure_store && path_length) {
        store_dt = &stage->path->past[path_length - 1u].dt;
    }

    cepCell* current = reader->root;
    for (unsigned idx = 0; idx < limit; ++idx) {
        const cepPast* segment = &stage->path->past[idx];
        cepDT name = cep_dt_make(segment->dt.domain, segment->dt.tag);
        bool positional_segment = segment->timestamp != 0u;
        bool allow_name_fallback = !positional_segment;
        size_t positional_index = positional_segment && segment->timestamp > 0u
                                      ? (size_t)(segment->timestamp - 1u)
                                      : 0u;
        cepCell* child = NULL;
        if (positional_segment) {
            child = cep_cell_find_by_position(current, positional_index);
            if (child) {
                cepCell* resolved_child = cep_link_pull(child);
                if (!resolved_child) {
                    child = NULL;
                } else {
                    const cepDT* resolved_name = cep_cell_get_name(resolved_child);
                    if (!resolved_name ||
                        resolved_name->domain != name.domain ||
                        resolved_name->tag != name.tag) {
                        child = NULL;
                    }
                }
            }
#ifdef CEP_ENABLE_DEBUG
            char dom_buf[64];
            char tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][apply_path_meta] idx=%u position=%zu dom=%s tag=%s found=%p\n",
                             idx,
                             positional_index,
                             cep_serialization_id_desc(name.domain, dom_buf, sizeof dom_buf),
                             cep_serialization_id_desc(name.tag, tag_buf, sizeof tag_buf),
                             (void*)child);
#endif
        }
        if (!child && allow_name_fallback)
            child = cep_cell_find_by_name(current, &name);
        if (!child) {
            bool final_segment = (idx + 1u == limit);
            if (final_segment && stage->cell_type == CEP_TYPE_PROXY) {
                fail_reason = "proxy_missing";
                goto fail;
            }

            if (!final_segment) {
                cepDT dict_type = *dt_dictionary_type();
                child = cep_cell_add_dictionary(current,
                                                &name,
                                                0,
                                                &dict_type,
                                                CEP_STORAGE_RED_BLACK_T);
            } else {
                size_t insert_at = 0u;
                if (positional_segment && cep_cell_has_store(current)) {
                    size_t child_count = cep_cell_children(current);
                    insert_at = positional_index <= child_count ? positional_index : child_count;
                }
                child = cep_cell_add_empty(current, &name, insert_at);
#ifdef CEP_ENABLE_DEBUG
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][insert_child] idx=%u insert_at=%zu parent_children=%zu parent=%p child=%p\n",
                                 idx,
                                 insert_at,
                                 cep_cell_children(current),
                                 (void*)current,
                                 (void*)child);
#endif
            }
        }
        if (!child) {
            fail_reason = "child_create";
            goto fail;
        }
        current = cep_link_pull(child);
    }

    if (!current) {
        fail_reason = "current_null";
        goto fail;
    }

    if ((uint8_t)current->metacell.type != stage->cell_type) {
        fail_reason = "type_mismatch";
        goto fail;
    }

    current->metacell.veiled = (stage->base_flags & SERIAL_BASE_FLAG_VEILED) ? 1u : 0u;

    cepData* pending_payload = NULL;
    cepData* previous_payload = NULL;

    if (stage->data.needed) {
        if (!stage->data.complete) {
            fail_reason = "data_incomplete";
            goto fail;
        }
        if (!cep_serialization_reader_check_hash(&stage->data)) {
            fail_reason = "hash_mismatch";
            goto fail;
        }

        previous_payload = current->data;
        cepData* payload = NULL;
        if (stage->data.datatype == CEP_DATATYPE_VALUE) {
            size_t size = (size_t)stage->data.total_size;
            size_t capacity = size ? size : 1u;
            payload = cep_data_new(&stage->data.dt,
                                   CEP_DATATYPE_VALUE,
                                   true,
                                   NULL,
                                   stage->data.buffer,
                                   size,
                                   capacity);
            if (!payload) {
                fail_reason = "payload_value_alloc";
                goto fail;
            }
            if (stage->data.buffer) {
                cep_free(stage->data.buffer);
                stage->data.buffer = NULL;
            }
            cep_serialization_normalize_stream_outcome(payload);
        } else if (stage->data.datatype == CEP_DATATYPE_DATA) {
            size_t size = (size_t)stage->data.total_size;
            size_t capacity = size ? size : 1u;
            uint8_t* owned = NULL;
            uint8_t* staged_buffer = stage->data.buffer;
            if (size) {
                owned = cep_malloc(size);
                if (!owned) {
                    fail_reason = "payload_data_alloc";
                    goto fail;
                }
                memcpy(owned, staged_buffer, size);
            }
            if (staged_buffer) {
                cep_free(staged_buffer);
                stage->data.buffer = NULL;
            }
            payload = cep_data_new(&stage->data.dt,
                                   CEP_DATATYPE_DATA,
                                   true,
                                   NULL,
                                   owned,
                                   size,
                                   capacity,
                                   size ? cep_free : NULL);
            if (!payload) {
                if (owned)
                    cep_free(owned);
                fail_reason = "payload_data_new";
                goto fail;
            }
            cep_serialization_normalize_stream_outcome(payload);
        } else if (stage->data.datatype == CEP_DATATYPE_HANDLE || stage->data.datatype == CEP_DATATYPE_STREAM) {
            if (!stage->data.library_segment_count || !stage->data.resource_segment_count) {
                fail_reason = "handle_segments_missing";
                goto fail;
            }
            cepCell* library = cep_serialization_resolve_segments(reader->root,
                                                                  stage->data.library_segments,
                                                                  stage->data.library_segment_count);
            cepCell* resource = cep_serialization_resolve_segments(reader->root,
                                                                   stage->data.resource_segments,
                                                                   stage->data.resource_segment_count);
            if (!library || !resource) {
                fail_reason = "handle_resolve";
                goto fail;
            }
            payload = cep_data_new(&stage->data.dt,
                                   stage->data.datatype,
                                   true,
                                   NULL,
                                   NULL,
                                   resource,
                                   library);
            if (!payload) {
                fail_reason = "handle_payload_new";
                goto fail;
            }
        } else {
            fail_reason = "datatype_unknown";
            goto fail;
        }

        pending_payload = payload;
    }

    if (stage->proxy.needed) {
        if (!stage->proxy.complete) {
            if (pending_payload) {
                cep_data_del(pending_payload);
                pending_payload = NULL;
            }
            fail_reason = "proxy_incomplete";
            goto fail;
        }
        if (!cep_cell_is_proxy(current)) {
            if (pending_payload) {
                cep_data_del(pending_payload);
                pending_payload = NULL;
            }
            fail_reason = "proxy_expected";
            goto fail;
        }

        cepProxySnapshot snapshot = {
            .payload = stage->proxy.buffer,
            .size = stage->proxy.size,
            .flags = stage->proxy.flags,
            .ticket = NULL,
        };

        if (!cep_proxy_restore(current, &snapshot)) {
            fail_reason = "proxy_restore";
            goto fail;
        }
    }

    if (configure_store) {
        if (!cep_serialization_reader_configure_store(current,
                                                      stage->organiser,
                                                      stage->storage_hint,
                                                      store_dt,
                                                      stage->store_metadata,
                                                      stage->store_metadata_size)) {
            fail_reason = "store_config";
            goto fail;
        }
    }

    if (!cep_serialization_reader_materialize_child_additions(stage, current)) {
        fail_reason = "child_materialize";
        goto fail;
    }

    if (!cep_serialization_reader_validate_manifest_children(reader, stage, current)) {
        fail_reason = "child_validation";
        
        goto fail;
    }

    if (pending_payload) {
        if (previous_payload)
            cep_data_del(previous_payload);
        current->data = pending_payload;
        pending_payload = NULL;
    }

    return true;

fail:
    (void)pending_payload;
    if (fail_reason && strcmp(fail_reason, "child_validation") == 0) {
        cep_serialization_debug_dump_stage(stage, "child_validation");
        if (current) {
            const cepDT* current_name = cep_cell_get_name(current);
            if (current_name) {
                char dom_buf[64];
                char tag_buf[64];
                CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][child_validation] current=%s/%s%s\n",
                                 cep_serialization_id_desc(current_name->domain, dom_buf, sizeof dom_buf),
                                 cep_serialization_id_desc(current_name->tag, tag_buf, sizeof tag_buf),
                                 current_name->glob ? "*" : "");
            }
        }
    }
    if (cep_serialization_debug_logging_enabled()) {
        cep_serialization_debug_log("[serialization][apply] fail reason=%s path_len=%u limit=%u data_needed=%u data_complete=%u delta=%zu/%zu cell_type=%u tx=%u\n",
                                    fail_reason ? fail_reason : "unknown",
                                    (unsigned)path_length,
                                    (unsigned)limit,
                                    stage ? (unsigned)(stage->data.needed ? 1u : 0u) : 0u,
                                    stage ? (unsigned)(stage->data.complete ? 1u : 0u) : 0u,
                                    stage ? stage->delta_seen : 0u,
                                    stage ? stage->delta_expected : 0u,
                                    stage ? (unsigned)stage->cell_type : 0u,
                                    stage ? stage->transaction : 0u);
        if (stage && stage->path) {
            cep_serialization_debug_log("[serialization][apply] path:");
            for (unsigned i = 0; i < stage->path->length; ++i) {
                const cepPast* segment = &stage->path->past[i];
                char dom_buf[64];
                char tag_buf[64];
                cep_serialization_debug_log(" [%u]=%s/%s%s",
                                            i,
                                            cep_serialization_id_desc(segment->dt.domain, dom_buf, sizeof dom_buf),
                                            cep_serialization_id_desc(segment->dt.tag, tag_buf, sizeof tag_buf),
                                            segment->dt.glob ? "*" : "");
            }
            cep_serialization_debug_log("\n");
        }
    }
    fflush(stderr);
    return false;
}

typedef struct {
    cepSerializationStage* stage;
    size_t                 index;
} cepSerializationStageOrder;

static int cep_serialization_stage_order_cmp(const void* lhs_ptr, const void* rhs_ptr) {
    const cepSerializationStageOrder* lhs = (const cepSerializationStageOrder*)lhs_ptr;
    const cepSerializationStageOrder* rhs = (const cepSerializationStageOrder*)rhs_ptr;
    size_t lhs_len = (lhs->stage && lhs->stage->path) ? lhs->stage->path->length : 0u;
    size_t rhs_len = (rhs->stage && rhs->stage->path) ? rhs->stage->path->length : 0u;
    if (lhs_len < rhs_len)
        return -1;
    if (lhs_len > rhs_len)
        return 1;
    if (lhs->index < rhs->index)
        return -1;
    if (lhs->index > rhs->index)
        return 1;
    return 0;
}

static void cep_serialization_reader_fail(cepSerializationReader* reader) {
    if (!reader)
        return;

    reader->error = true;
    reader->pending_commit = false;
    cep_serialization_reader_clear_stages(reader);
    cep_serialization_reader_clear_transactions(reader);
}

static bool cep_serialization_reader_fail_with_note(cepSerializationReader* reader,
                                                    const char* topic,
                                                    const char* detail_fmt,
                                                    ...) {
    if (topic && detail_fmt) {
        char note[256];
        va_list args;
        va_start(args, detail_fmt);
        vsnprintf(note, sizeof note, detail_fmt, args);
        va_end(args);
        cep_serialization_emit_failure(topic,
                                       reader ? reader->root : NULL,
                                       "%s",
                                       note);
    }
    cep_serialization_reader_fail(reader);
    return false;
}

static bool cep_serialization_reader_consume_namepool_map(cepSerializationReader* reader,
                                                          const uint8_t* payload,
                                                          size_t payload_size) {
    if (!reader || !payload)
        return false;

    if (payload_size < 4u) {
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.namepool",
                                                       "namepool map chunk too small (size=%zu)",
                                                       payload_size);
    }

    uint8_t record = payload[0u];
    if (record != SERIAL_RECORD_NAMEPOOL_MAP) {
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.namepool",
                                                       "unexpected namepool record type=%u",
                                                       (unsigned)record);
    }

    uint8_t flags = payload[1u];
    if ((flags & ~SERIAL_NAMEPOOL_FLAG_MORE) != 0u) {
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.namepool",
                                                       "unsupported namepool flags=0x%02x",
                                                       (unsigned)flags);
    }

    uint16_t count = cep_serial_read_be16_buf(payload + 2u);
    size_t offset = 4u;

    for (uint16_t i = 0; i < count; ++i) {
        size_t remaining = (offset <= payload_size) ? (payload_size - offset) : 0u;
        size_t header_bytes = sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint8_t);
        if (remaining < header_bytes) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.namepool",
                                                           "namepool entry truncated (idx=%u remaining=%zu)",
                                                           (unsigned)i,
                                                           remaining);
        }

        uint64_t id_raw = cep_serial_read_be64_buf(payload + offset);
        cepID entry_id = (cepID)id_raw;
        offset += sizeof(uint64_t);

        uint16_t text_len = cep_serial_read_be16_buf(payload + offset);
        offset += sizeof(uint16_t);

        uint8_t entry_flags = payload[offset];
        if ((entry_flags & ~SERIAL_NAMEPOOL_FLAG_GLOB) != 0u) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.namepool",
                                                           "unsupported namepool entry flags=0x%02x",
                                                           (unsigned)entry_flags);
        }
        offset += sizeof(uint8_t);

        remaining = (offset <= payload_size) ? (payload_size - offset) : 0u;
        if (remaining < text_len) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.namepool",
                                                           "namepool text truncated (idx=%u need=%u have=%zu)",
                                                           (unsigned)i,
                                                           (unsigned)text_len,
                                                           remaining);
        }

        if (text_len == 0u) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.namepool",
                                                           "empty namepool text not supported (id=%016" PRIx64 ")",
                                                           id_raw);
        }

        const char* text = (const char*)(payload + offset);
        size_t text_size = (size_t)text_len;
        size_t existing_len = 0u;
        const char* existing = cep_namepool_lookup(entry_id, &existing_len);
        if (existing) {
            if (text_size != existing_len ||
                memcmp(existing, text, text_size) != 0) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.namepool",
                                                               "conflicting namepool text for id=%016" PRIx64,
                                                               id_raw);
            }
        } else {
            cepID interned = 0;
            if ((entry_flags & SERIAL_NAMEPOOL_FLAG_GLOB) != 0u) {
                interned = cep_namepool_intern_pattern(text, text_size);
            } else {
                interned = cep_namepool_intern(text, text_size);
            }
            if (!interned) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.namepool",
                                                               "failed to intern namepool entry id=%016" PRIx64,
                                                               id_raw);
            }
            if (interned != entry_id) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.namepool",
                                                               "interned id mismatch expected=%016" PRIx64 " got=%016" PRIx64,
                                                               id_raw,
                                                               (uint64_t)interned);
            }
        }

        offset += text_size;
    }

    if (offset != payload_size) {
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.namepool",
                                                       "namepool payload trailing bytes=%zu",
                                                       payload_size - offset);
    }

    return true;
}

/** Feed a serialisation chunk into the reader state machine, staging work until
    commit is requested. */
bool cep_serialization_reader_ingest(cepSerializationReader* reader, const uint8_t* chunk, size_t chunk_size) {
    if (!reader || !chunk || chunk_size < CEP_SERIALIZATION_CHUNK_OVERHEAD)
        return false;

    uint64_t payload_be = 0;
    memcpy(&payload_be, chunk, sizeof payload_be);
    size_t payload_size = (size_t)cep_serial_from_be64(payload_be);
    if (payload_size + CEP_SERIALIZATION_CHUNK_OVERHEAD != chunk_size)
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.chunk",
                                                       "chunk size mismatch (payload=%zu chunk=%zu)",
                                                       payload_size,
                                                       chunk_size);

    uint64_t id_be = 0;
    memcpy(&id_be, chunk + sizeof(uint64_t), sizeof(uint64_t));
    uint64_t chunk_id = cep_serial_from_be64(id_be);
    uint16_t chunk_class = cep_serialization_chunk_class(chunk_id);
    uint32_t transaction = cep_serialization_chunk_transaction(chunk_id);
    uint16_t sequence = cep_serialization_chunk_sequence(chunk_id);

    const uint8_t* payload = chunk + CEP_SERIALIZATION_CHUNK_OVERHEAD;

    if (chunk_class == CEP_CHUNK_CLASS_CONTROL && transaction == 0u && sequence == 0u) {
        if (!cep_serialization_header_read(chunk, chunk_size, &reader->header))
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.header",
                                                           "failed to parse control header");
        uint16_t required_caps = CEP_SERIALIZATION_CAP_HISTORY_MANIFEST |
                                 CEP_SERIALIZATION_CAP_MANIFEST_DELTAS  |
                                 CEP_SERIALIZATION_CAP_PAYLOAD_HASH     |
                                 CEP_SERIALIZATION_CAP_PROXY_ENVELOPE   |
                                 CEP_SERIALIZATION_CAP_DIGEST_TRAILER;
        if (!reader->header.capabilities_present ||
            (reader->header.capabilities & required_caps) != required_caps) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.capability",
                                                           "required serialization capabilities missing (caps=0x%04x)",
                                                           reader->header.capabilities);
        }
        cep_serialization_reader_clear_stages(reader);
        cep_serialization_reader_clear_transactions(reader);
        reader->header_seen = true;
        reader->pending_commit = false;
        reader->error = false;
        return true;
    }

    if (reader->error)
        return false;

    if (!reader->header_seen)
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.order",
                                                       "received data chunk before header");

    if (!sequence) {
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.sequence",
                                                       "chunk sequence zero (class=%u tx=%u)",
                                                       (unsigned)chunk_class,
                                                       transaction);
    }

    cepSerializationTxState* tx = cep_serialization_reader_get_tx(reader, transaction);
    if (!tx)
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.transaction",
                                                       "failed to allocate state for tx=%u",
                                                       transaction);

    if ((uint16_t)(tx->last_sequence + 1u) != sequence) {
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.sequence",
                                                       "out-of-order chunk (last=%u seq=%u tx=%u)",
                                                       tx->last_sequence,
                                                       sequence,
                                                       transaction);
    }
    tx->last_sequence = sequence;

    switch (chunk_class) {
      case CEP_CHUNK_CLASS_STRUCTURE: {
        cepSerializationStage* pending_stage = tx->pending_stage;
        bool expecting_data_header = pending_stage &&
                                     pending_stage->data.needed &&
                                     !pending_stage->data.header_received &&
                                     (pending_stage->delta_seen >= pending_stage->delta_expected);

        if (expecting_data_header) {
            size_t header_bytes = 60u;
            if (payload_size < header_bytes) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.data_header",
                                                               "inline data header too small (payload=%zu)",
                                                               payload_size);
            }

            size_t inline_size = payload_size > header_bytes ? payload_size - header_bytes : 0u;
            const uint8_t* inline_bytes = inline_size ? payload + header_bytes : NULL;
            if (!cep_serialization_reader_record_data_header(&pending_stage->data,
                                                             payload,
                                                             payload_size,
                                                             inline_bytes,
                                                             inline_size)) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.data_header",
                                                               "failed to record data header (tx=%u seq=%u)",
                                                               transaction,
                                                               sequence);
            }

            if (!pending_stage->data.chunked && !pending_stage->proxy.needed)
                tx->pending_stage = NULL;
            else
                tx->pending_stage = pending_stage;
        } else {
            if (!cep_serialization_reader_record_manifest(reader, tx, transaction, payload, payload_size)) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.manifest",
                                                               "manifest parse failed (tx=%u seq=%u)",
                                                               transaction,
                                                               sequence);
            }
        }
        break;
      }
      case CEP_CHUNK_CLASS_BLOB: {
        if (!tx->pending_stage || !tx->pending_stage->data.header_received) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.data_blob",
                                                           "blob arrived without header (tx=%u seq=%u)",
                                                           transaction,
                                                           sequence);
        }
        if (!cep_serialization_reader_record_data_chunk(&tx->pending_stage->data, payload, payload_size)) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.data_blob",
                                                           "failed to record blob chunk (tx=%u seq=%u)",
                                                           transaction,
                                                           sequence);
        }
        if (tx->pending_stage->data.complete)
            tx->pending_stage = NULL;
        break;
      }
      case CEP_CHUNK_CLASS_CONTROL: {
        if (payload_size && payload[0u] == SERIAL_RECORD_NAMEPOOL_MAP) {
            if (!cep_serialization_reader_consume_namepool_map(reader, payload, payload_size))
                return false;
            break;
        }
        reader->pending_commit = true;
        break;
      }
      case CEP_CHUNK_CLASS_LIBRARY: {
        if (!tx->pending_stage || !tx->pending_stage->proxy.needed || tx->pending_stage->proxy.complete) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.proxy",
                                                           "unexpected proxy chunk (tx=%u seq=%u)",
                                                           transaction,
                                                           sequence);
        }
        if (tx->pending_stage->data.needed && !tx->pending_stage->data.complete) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.proxy",
                                                           "proxy chunk arrived before data complete (tx=%u seq=%u)",
                                                           transaction,
                                                           sequence);
        }

        if (payload_size < 16u) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.proxy",
                                                           "proxy header smaller than minimum (payload=%zu)",
                                                           payload_size);
        }

        uint8_t version = payload[0u];
        (void)version;
        uint8_t kind = payload[1u];
        uint8_t envelope_flags = payload[2u];
        uint32_t ticket_len = cep_serial_read_be32_buf(payload + 4u);
        uint64_t payload_len = cep_serial_read_be64_buf(payload + 8u);

        if (ticket_len != 0u) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.proxy",
                                                           "ticket-based proxy snapshots unsupported (len=%u)",
                                                           ticket_len);
        }

        size_t inline_size = payload_size - 16u;
        bool has_inline = (envelope_flags & 0x01u) != 0u;
        if (payload_len > SIZE_MAX) {
            return cep_serialization_reader_fail_with_note(reader,
                                                           "serialization.replay.proxy",
                                                           "proxy payload overflow (size=%" PRIu64 ")",
                                                           payload_len);
        }
        if (has_inline) {
            if ((uint64_t)inline_size != payload_len) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.proxy",
                                                               "proxy payload mismatch (expected=%" PRIu64 " got=%zu)",
                                                               payload_len,
                                                               inline_size);
            }
        } else {
            if (payload_len != 0u || inline_size != 0u) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.proxy",
                                                               "proxy payload expected empty inline section");
            }
        }

        cepSerializationStage* stage = tx->pending_stage;
        if (stage->proxy.buffer) {
            cep_free(stage->proxy.buffer);
            stage->proxy.buffer = NULL;
        }

        stage->proxy.flags = envelope_flags;
        stage->proxy.kind = kind;
        stage->proxy.size = (size_t)payload_len;

        if (has_inline && stage->proxy.size) {
            stage->proxy.buffer = cep_malloc(stage->proxy.size);
            if (!stage->proxy.buffer) {
                return cep_serialization_reader_fail_with_note(reader,
                                                               "serialization.replay.proxy",
                                                               "proxy buffer allocation failed (size=%zu)",
                                                               stage->proxy.size);
            }
            memcpy(stage->proxy.buffer, payload + 16u, stage->proxy.size);
        }

        stage->proxy.complete = true;
        stage->proxy.needed = true;
        tx->pending_stage = NULL;
        break;
      }
      default:
        return cep_serialization_reader_fail_with_note(reader,
                                                       "serialization.replay.chunk",
                                                       "unknown chunk class=%u tx=%u seq=%u",
                                                       (unsigned)chunk_class,
                                                       transaction,
                                                       sequence);
    }

    return true;
}

/** Apply staged chunks to the target tree, materialising payloads and proxy
    state. */
bool cep_serialization_reader_commit(cepSerializationReader* reader) {
    bool replay_scope_entered = cep_serialization_replay_scope_enter();
    bool result = false;
    cepSerializationStageOrder* order = NULL;

    if (!reader || reader->error || !reader->pending_commit)
        goto exit;

    if (reader->stage_count) {
        order = cep_malloc(reader->stage_count * sizeof(*order));
        if (!order) {
            cep_serialization_reader_fail_with_note(reader,
                                                    "serialization.replay.commit",
                                                    "failed to allocate stage ordering buffer");
            goto exit;
        }
        for (size_t i = 0; i < reader->stage_count; ++i) {
            order[i].stage = &reader->stages[i];
            order[i].index = i;
        }
        qsort(order, reader->stage_count, sizeof(*order), cep_serialization_stage_order_cmp);
    }

    for (size_t i = 0; i < reader->stage_count; ++i) {
        cepSerializationStage* stage = order ? order[i].stage : &reader->stages[i];
        if (!cep_serialization_reader_apply_stage(reader, stage)) {
            cep_serialization_reader_fail_with_note(reader,
                                                    "serialization.replay.commit",
                                                    "apply stage failed (index=%zu tx=%u)",
                                                    i,
                                                    stage->transaction);
            goto exit;
        }
        cep_serialization_stage_dispose(stage);
    }

    reader->stage_count = 0;
    reader->pending_commit = false;
    reader->transaction_count = 0;
    if (reader->transactions)
        memset(reader->transactions, 0, reader->transaction_capacity * sizeof(*reader->transactions));
    result = true;

exit:
    if (order)
        cep_free(order);
    cep_serialization_replay_scope_exit(replay_scope_entered);
    return result;
}

/** Return true when the reader has staged work that still needs committing. */
bool cep_serialization_reader_pending(const cepSerializationReader* reader) {
    if (!reader)
        return false;
    return reader->pending_commit;
}
static bool cep_serialization_reader_record_manifest_base(cepSerializationReader* reader,
                                                          cepSerializationTxState* tx,
                                                          uint32_t transaction,
                                                          const uint8_t* payload,
                                                          size_t payload_size) {
    if (!reader || !tx || !payload || payload_size < 9u)
        return false;

    uint8_t organiser = payload[1];
    uint8_t storage_hint = payload[2];
    bool store_meta_present = (storage_hint & SERIAL_STORAGE_FLAG_METADATA) != 0u;
    if (store_meta_present)
        storage_hint &= (uint8_t)~SERIAL_STORAGE_FLAG_METADATA;
    uint8_t base_flags = payload[3];
    uint8_t cell_type = payload[4];
    uint16_t segment_count = cep_serial_read_be16_buf(payload + 5u);
    uint16_t child_count = cep_serial_read_be16_buf(payload + 7u);
    uint16_t descriptor_spans = cep_serial_read_be16_buf(payload + 9u);

    size_t segments_bytes = (size_t)segment_count * ((sizeof(uint64_t) * 2u) + 4u);
    size_t header_bytes = 11u + segments_bytes;
    if (segment_count == 0u || payload_size < header_bytes)
        return false;

    if (!cep_serialization_reader_ensure_stage_capacity(reader, reader->stage_count + 1u))
        return false;

    cepSerializationStage* stage = &reader->stages[reader->stage_count];
    memset(stage, 0, sizeof(*stage));
    stage->transaction = transaction;
    stage->cell_type = cell_type;
    stage->organiser = organiser;
    stage->storage_hint = storage_hint;
    stage->base_flags = base_flags;

    size_t path_bytes = sizeof(cepPath) + (size_t)segment_count * sizeof(cepPast);
    cepPath* path = cep_malloc(path_bytes);
    if (!path)
        goto fail;
    path->length = segment_count;
    path->capacity = segment_count;
    stage->path = path;

    cep_serialization_debug_log("[serialization][debug] manifest_base path_len=%u children=%u flags=0x%02x tx=%u\n",
                                (unsigned)segment_count,
                                (unsigned)child_count,
                                (unsigned)base_flags,
                                transaction);

    const uint8_t* cursor = payload + 11u;
    for (uint16_t i = 0; i < segment_count; ++i) {
        cepPast* segment = &path->past[i];
        segment->dt.domain = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        segment->dt.tag = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        uint8_t glob = cursor[0];
        uint8_t meta = cursor[1];
        uint16_t position = cep_serial_read_be16_buf(cursor + 2u);
        cursor += sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);
        segment->dt.glob = glob != 0u;
        segment->timestamp = 0u;
        if ((meta & SERIAL_PATH_FLAG_POSITION) != 0u) {
            segment->timestamp = (cepOpCount)position + 1u;
#ifdef CEP_ENABLE_DEBUG
            char dom_buf[64];
            char tag_buf[64];
            CEP_SERIALIZATION_DEBUG_PRINTF("[serialization][decode_path_meta] idx=%u position=%u dom=%s tag=%s\n",
                             (unsigned)i,
                             (unsigned)position,
                             cep_serialization_id_desc(segment->dt.domain, dom_buf, sizeof dom_buf),
                             cep_serialization_id_desc(segment->dt.tag, tag_buf, sizeof tag_buf));
#endif
        }
    }

#ifdef CEP_ENABLE_DEBUG
    if (segment_count && cep_serialization_debug_logging_enabled()) {
        cep_serialization_debug_log("[serialization][debug] manifest_path tx=%u", transaction);
        for (uint16_t idx = 0; idx < segment_count; ++idx) {
            const cepPast* segment = &path->past[idx];
            char dom_buf[64];
            char tag_buf[64];
            cep_serialization_debug_log(" [%u]=%s/%s%s",
                                        idx,
                                        cep_serialization_id_desc(segment->dt.domain, dom_buf, sizeof dom_buf),
                                        cep_serialization_id_desc(segment->dt.tag, tag_buf, sizeof tag_buf),
                                        segment->dt.glob ? "*" : "");
        }
        cep_serialization_debug_log("\n");
    }
#endif

    size_t remaining = payload_size - (cursor - payload);
    bool split_children = (base_flags & SERIAL_BASE_FLAG_CHILDREN_SPLIT) != 0u;
    if (child_count) {
        if (split_children && descriptor_spans == 0u)
            goto fail;
        if (!cep_serialization_stage_ensure_child_capacity(stage, child_count))
            goto fail;
    }
    stage->child_target = child_count;
    stage->child_count = split_children ? 0u : child_count;
    stage->descriptor_spans_expected = split_children ? descriptor_spans : 0u;
    stage->descriptor_spans_seen = split_children ? 0u : descriptor_spans;
    stage->delta_expected = child_count;
    stage->delta_seen = 0u;

    if (child_count && !split_children) {
        for (uint16_t i = 0; i < child_count; ++i) {
            size_t descriptor_base = (sizeof(uint64_t) * 2u) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
            if (remaining < descriptor_base)
                goto fail;

            cepSerializationStageChild* child = &stage->children[i];
            child->name.domain = cep_serial_read_be64_buf(cursor);
            cursor += sizeof(uint64_t);
            child->name.tag = cep_serial_read_be64_buf(cursor);
            cursor += sizeof(uint64_t);
            child->name.glob = cursor[0] != 0u;
            uint8_t child_flags = cursor[1];
            uint16_t position = cep_serial_read_be16_buf(cursor + 2u);
            cursor += sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);
            cursor += sizeof(uint32_t); /* reserved */
            remaining -= descriptor_base;

            child->flags = child_flags;
            child->position = position;
            child->delta_flags = SERIAL_DELTA_FLAG_ADD;
            child->cell_type = 0u;
            child->has_fingerprint = false;
            child->fingerprint = 0u;
            child->descriptor_ready = true;
            child->freshly_materialized = false;

            if ((child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u) {
                if (remaining < sizeof(uint64_t))
                    goto fail;
                child->fingerprint = cep_serial_read_be64_buf(cursor);
                cursor += sizeof(uint64_t);
                remaining -= sizeof(uint64_t);
                child->has_fingerprint = true;
            }
        }
    }

    if (store_meta_present) {
        if (remaining < sizeof(uint16_t))
            goto fail;
        uint16_t meta_size = cep_serial_read_be16_buf(cursor);
        cursor += sizeof(uint16_t);
        remaining -= sizeof(uint16_t);
        if (meta_size) {
            if (remaining < meta_size)
                goto fail;
            uint8_t* meta = cep_malloc(meta_size);
            if (!meta)
                goto fail;
            memcpy(meta, cursor, meta_size);
            cursor += meta_size;
            remaining -= meta_size;
            stage->store_metadata = meta;
            stage->store_metadata_size = meta_size;
        }
    }

    bool wants_proxy = (cell_type == CEP_TYPE_PROXY);
    bool wants_data = ((base_flags & SERIAL_BASE_FLAG_PAYLOAD) != 0u) && !wants_proxy;

    stage->proxy.needed = wants_proxy;
    stage->proxy.complete = !wants_proxy;
    stage->proxy.flags = 0;
    stage->proxy.buffer = NULL;
    stage->proxy.size = 0;

    stage->data.needed = wants_data;
    stage->data.header_received = false;
    stage->data.chunked = false;
    stage->data.complete = !wants_data;
    stage->data.buffer = NULL;
    stage->data.size = 0;
    stage->data.next_offset = 0;
    stage->data.total_size = 0;
    stage->data.hash = 0;
    stage->data.kind = wants_data ? 0u : 0u;
    stage->data.journal_beat = 0u;
    stage->data.legacy_flags = 0u;

    tx->pending_stage = stage;
    reader->stage_count++;
    return true;

fail:
    if (stage->children) {
        cep_free(stage->children);
        stage->children = NULL;
    }
    if (stage->path) {
        cep_free(stage->path);
        stage->path = NULL;
    }
    stage->child_count = 0u;
    stage->child_capacity = 0u;
    stage->child_target = 0u;
    memset(stage, 0, sizeof(*stage));
    return false;
}

static bool cep_serialization_reader_record_manifest_children(cepSerializationReader* reader,
                                                              cepSerializationTxState* tx,
                                                              const uint8_t* payload,
                                                              size_t payload_size) {
    if (!reader || !tx || !payload || payload_size < 10u)
        return false;

    cepSerializationStage* stage = tx->pending_stage;
    if (!stage && reader->stage_count)
        stage = &reader->stages[reader->stage_count - 1u];
    if (!stage || stage->transaction != tx->id)
        return false;

    if ((stage->base_flags & SERIAL_BASE_FLAG_CHILDREN_SPLIT) == 0u)
        return false;
    if (!stage->children || !stage->child_capacity)
        return false;

    uint16_t span_index = cep_serial_read_be16_buf(payload + 2u);
    uint16_t descriptor_offset = cep_serial_read_be16_buf(payload + 4u);
    uint16_t descriptor_count = cep_serial_read_be16_buf(payload + 6u);
    uint16_t segment_count = cep_serial_read_be16_buf(payload + 8u);

    if (!descriptor_count || !segment_count)
        return false;
    size_t target_end = (size_t)descriptor_offset + descriptor_count;
    if (stage->child_target && target_end > stage->child_target)
        return false;
    if (!cep_serialization_stage_ensure_child_capacity(stage, target_end))
        return false;
    if (stage->descriptor_spans_expected &&
        stage->descriptor_spans_seen >= stage->descriptor_spans_expected)
        return false;
    if (stage->descriptor_spans_expected &&
        span_index != stage->descriptor_spans_seen)
        return false;

    size_t segments_bytes = (size_t)segment_count * ((sizeof(uint64_t) * 2u) + 4u);
    size_t header_bytes = 10u + segments_bytes;
    if (payload_size < header_bytes)
        return false;

    const uint8_t* cursor = payload + 10u;
    for (uint16_t i = 0; i < segment_count; ++i) {
        uint64_t domain = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        uint64_t tag = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        bool glob = cursor[0] != 0u;
        uint8_t meta = cursor[1];
        (void)meta;
        cursor += sizeof(uint8_t);
        cursor += sizeof(uint8_t) + sizeof(uint16_t);
        if (!stage->path || i >= stage->path->length)
            return false;
        const cepPast* segment = &stage->path->past[i];
        if (segment->dt.domain != domain ||
            segment->dt.tag != tag ||
            (segment->dt.glob != 0u) != glob) {
            return false;
        }
    }

    size_t remaining = payload_size - (cursor - payload);
    for (uint16_t i = 0; i < descriptor_count; ++i) {
        size_t descriptor_base = (sizeof(uint64_t) * 2u) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
        if (remaining < descriptor_base)
            return false;

        size_t target_index = (size_t)descriptor_offset + i;
        cepSerializationStageChild* child = &stage->children[target_index];
        if (child->descriptor_ready)
            return false;

        child->name.domain = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        child->name.tag = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        child->name.glob = cursor[0] != 0u;
        uint8_t child_flags = cursor[1];
        uint16_t position = cep_serial_read_be16_buf(cursor + 2u);
        cursor += sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);
        cursor += sizeof(uint32_t);
        remaining -= descriptor_base;

        child->flags = child_flags;
        child->position = position;
        child->delta_flags = SERIAL_DELTA_FLAG_ADD;
        child->cell_type = 0u;
        child->has_fingerprint = false;
        child->fingerprint = 0u;
        child->descriptor_ready = true;
        child->freshly_materialized = false;

        if ((child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u) {
            if (remaining < sizeof(uint64_t))
                return false;
            child->fingerprint = cep_serial_read_be64_buf(cursor);
            cursor += sizeof(uint64_t);
            remaining -= sizeof(uint64_t);
            child->has_fingerprint = true;
        }
    }

    size_t new_count = (size_t)descriptor_offset + descriptor_count;
    if (stage->child_count < new_count)
        stage->child_count = new_count;

    stage->descriptor_spans_seen += 1u;
    return true;
}

static bool cep_serialization_reader_record_manifest_delta(cepSerializationReader* reader,
                                                           cepSerializationTxState* tx,
                                                           const uint8_t* payload,
                                                           size_t payload_size) {
    if (!reader || !tx || !payload || payload_size < 8u + (sizeof(uint64_t) * 2u))
        return false;

    cepSerializationStage* stage = tx->pending_stage;
    if (!stage && reader->stage_count)
        stage = &reader->stages[reader->stage_count - 1u];
    if (!stage || stage->transaction != tx->id)
        return false;

    uint8_t delta_flags = payload[1];
    uint16_t segment_count = cep_serial_read_be16_buf(payload + 4u);
    uint8_t child_type = payload[6u];

    size_t segments_bytes = (size_t)segment_count * ((sizeof(uint64_t) * 2u) + 4u);
    size_t header_bytes = 24u + segments_bytes;
    if (payload_size < header_bytes)
        return false;

    const uint8_t* cursor = payload + 24u;
    for (uint16_t i = 0; i < segment_count; ++i) {
        uint64_t domain = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        uint64_t tag = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        bool glob = cursor[0] != 0u;
        cursor += sizeof(uint8_t);
        cursor += 3u;
        if (!stage->path || i >= stage->path->length)
            continue;
        const cepPast* segment = &stage->path->past[i];
        if (segment->dt.domain != domain ||
            segment->dt.tag != tag ||
            (segment->dt.glob != 0u) != glob) {
            return false;
        }
    }

    size_t remaining = payload_size - (cursor - payload);
    size_t descriptor_base = (sizeof(uint64_t) * 2u) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    if (remaining < descriptor_base)
        return false;

    cepDT child_name = {
        .domain = cep_serial_read_be64_buf(cursor),
        .tag = cep_serial_read_be64_buf(cursor + sizeof(uint64_t)),
        .glob = ((cursor[sizeof(uint64_t) * 2u]) != 0u),
    };
    uint8_t child_flags = cursor[sizeof(uint64_t) * 2u + 1u];
    uint16_t position = cep_serial_read_be16_buf(cursor + sizeof(uint64_t) * 2u + 2u);
    cursor += descriptor_base;
    remaining -= descriptor_base;

    bool require_position = (stage->organiser == SERIAL_ORGANISER_INSERTION);
    cepSerializationStageChild* child = cep_serialization_stage_find_child(stage,
                                                                           &child_name,
                                                                           require_position,
                                                                           position);
    if (!child)
        return false;

    child->flags = child_flags;
    child->position = position;
    child->delta_flags = delta_flags;
    child->cell_type = child_type;

    if ((child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u) {
        if (remaining < sizeof(uint64_t))
            return false;
        child->fingerprint = cep_serial_read_be64_buf(cursor);
        child->has_fingerprint = true;
        cursor += sizeof(uint64_t);
        remaining -= sizeof(uint64_t);
    }

    if (!stage->data.needed && !stage->proxy.needed)
        tx->pending_stage = NULL;
    else
        tx->pending_stage = stage;

    if (stage->delta_seen < stage->delta_expected)
        stage->delta_seen += 1u;

    return true;
}
