#include "test.h"
#include "cps/cps_fixture_defs.h"

#include "blake3.h"
#include "cep_cell.h"
#include "cep_flat_serializer.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
} fixture_buf;

static void fixture_buf_init(fixture_buf* buf) {
    buf->data = NULL;
    buf->len = 0u;
    buf->cap = 0u;
}

static void fixture_buf_reset(fixture_buf* buf) {
    if (!buf) {
        return;
    }
    free(buf->data);
    buf->data = NULL;
    buf->len = 0u;
    buf->cap = 0u;
}

static bool fixture_buf_reserve(fixture_buf* buf, size_t extra) {
    if (!buf) {
        return false;
    }
    size_t needed = buf->len + extra;
    if (needed <= buf->cap) {
        return true;
    }
    size_t new_cap = buf->cap ? buf->cap : 64u;
    while (new_cap < needed) {
        size_t grown = new_cap << 1u;
        if (grown <= new_cap) {
            new_cap = needed;
            break;
        }
        new_cap = grown;
    }
    uint8_t* grown = (uint8_t*)realloc(buf->data, new_cap);
    if (!grown) {
        return false;
    }
    buf->data = grown;
    buf->cap = new_cap;
    return true;
}

static bool fixture_buf_append(fixture_buf* buf, const void* data, size_t len) {
    if (!buf || (!data && len)) {
        return false;
    }
    if (!len) {
        return true;
    }
    if (!fixture_buf_reserve(buf, len)) {
        return false;
    }
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return true;
}

static bool fixture_buf_append_u8(fixture_buf* buf, uint8_t value) {
    return fixture_buf_append(buf, &value, sizeof value);
}

static bool fixture_buf_append_u16_le(fixture_buf* buf, uint16_t value) {
    uint8_t le[2] = {
        (uint8_t)(value & 0xFFu),
        (uint8_t)((value >> 8u) & 0xFFu),
    };
    return fixture_buf_append(buf, le, sizeof le);
}

static bool fixture_buf_append_varint(fixture_buf* buf, uint64_t value) {
    do {
        uint8_t byte = (uint8_t)(value & 0x7Fu);
        value >>= 7u;
        if (value) {
            byte |= 0x80u;
        }
        if (!fixture_buf_append_u8(buf, byte)) {
            return false;
        }
    } while (value);
    return true;
}

static void fixture_compute_hash(const uint8_t* data, size_t len, uint8_t out[CEP_FLAT_HASH_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (data && len) {
        blake3_hasher_update(&hasher, data, len);
    }
    blake3_hasher_finalize(&hasher, out, CEP_FLAT_HASH_SIZE);
}

static bool fixture_build_cell_desc_body(const uint8_t* payload,
                                         size_t payload_len,
                                         const uint8_t* inline_bytes,
                                         size_t inline_len,
                                         uint8_t payload_kind,
                                         uint8_t payload_ref_kind,
                                         uint8_t codec,
                                         uint8_t aead_mode,
                                         fixture_buf* out) {
    if (!payload || !payload_len || !out) {
        return false;
    }
    fixture_buf_init(out);

    uint8_t revision[16];
    uint8_t revision_hash[CEP_FLAT_HASH_SIZE];
    fixture_compute_hash(payload, payload_len, revision_hash);
    memcpy(revision, revision_hash, sizeof revision);

    uint8_t payload_hash[CEP_FLAT_HASH_SIZE];
    fixture_compute_hash(payload, payload_len, payload_hash);

    if (!fixture_buf_append_u8(out, payload_kind)) {
        goto fail;
    }

    if (!fixture_buf_append_u16_le(out, 0u)) { /* store descriptor */
        goto fail;
    }

    if (!fixture_buf_append_varint(out, 0u) || !fixture_buf_append_varint(out, 0u)) { /* created + latest */
        goto fail;
    }

    if (!fixture_buf_append(out, revision, sizeof revision)) {
        goto fail;
    }

    if (!fixture_buf_append_u8(out, payload_kind)) {
        goto fail;
    }

    /* fingerprint length */
    if (!fixture_buf_append_varint(out, 0u)) {
        goto fail;
    }

    if (!fixture_buf_append_varint(out, inline_len)) {
        goto fail;
    }
    if (inline_len && !fixture_buf_append(out, inline_bytes, inline_len)) {
        goto fail;
    }

    fixture_buf ref = {0};
    if (!fixture_buf_append_u8(&ref, payload_ref_kind) ||
        !fixture_buf_append_u8(&ref, CEP_FLAT_HASH_BLAKE3_256) ||
        !fixture_buf_append_u8(&ref, codec) ||
        !fixture_buf_append_u8(&ref, aead_mode) ||
        !fixture_buf_append_varint(&ref, payload_len) ||
        !fixture_buf_append_varint(&ref, CEP_FLAT_HASH_SIZE) ||
        !fixture_buf_append(&ref, payload_hash, CEP_FLAT_HASH_SIZE)) {
        fixture_buf_reset(&ref);
        goto fail;
    }

    if (!fixture_buf_append_varint(out, ref.len) ||
        !fixture_buf_append(out, ref.data, ref.len)) {
        fixture_buf_reset(&ref);
        goto fail;
    }
    fixture_buf_reset(&ref);

    if (!fixture_buf_append_varint(out, 0u)) { /* namepool map ref */
        goto fail;
    }
    if (!fixture_buf_append_u16_le(out, 0u)) { /* meta mask */
        goto fail;
    }
    return true;

fail:
    fixture_buf_reset(out);
    return false;
}

static bool fixture_capture_frame(const cepFlatRecordSpec* record, fixture_buf* out) {
    if (!record || !out) {
        return false;
    }
    bool ok = false;
    cepFlatSerializer* serializer = cep_flat_serializer_create();
    if (!serializer) {
        return false;
    }

    cepFlatFrameConfig config = {
        .beat_number = 1u,
        .apply_mode = CEP_FLAT_APPLY_INSERT_ONLY,
        .capability_flags = CEP_FLAT_CAP_FRAME_TOC | CEP_FLAT_CAP_PAYLOAD_REF,
        .hash_algorithm = CEP_FLAT_HASH_BLAKE3_256,
    };

    if (!cep_flat_serializer_begin(serializer, &config)) {
        goto cleanup;
    }
    if (!cep_flat_serializer_emit(serializer, record)) {
        goto cleanup;
    }
    if (!cep_flat_serializer_finish(serializer, NULL, NULL)) {
        goto cleanup;
    }

    const uint8_t* frame_bytes = NULL;
    size_t frame_size = 0u;
    if (!cep_flat_serializer_frame_bytes(serializer, &frame_bytes, &frame_size) ||
        !frame_bytes || !frame_size) {
        goto cleanup;
    }
    if (!fixture_buf_append(out, frame_bytes, frame_size)) {
        fixture_buf_reset(out);
        goto cleanup;
    }
    ok = true;

cleanup:
    cep_flat_serializer_destroy(serializer);
    return ok;
}

static bool fixture_compress_payload(const uint8_t* input, size_t input_len, fixture_buf* out) {
    if (!input || !input_len || !out) {
        return false;
    }
    fixture_buf_init(out);
    uLongf bound = compressBound((uLong)input_len);
    if (!fixture_buf_reserve(out, (size_t)bound)) {
        fixture_buf_reset(out);
        return false;
    }
    uLongf dest_len = bound;
    int rc = compress2(out->data, &dest_len, input, (uLong)input_len, Z_BEST_COMPRESSION);
    if (rc != Z_OK) {
        fixture_buf_reset(out);
        return false;
    }
    out->len = (size_t)dest_len;
    return true;
}

static const char* fixture_source_root(void) {
    const char* root = getenv("MESON_SOURCE_ROOT");
    if (root && *root) {
        return root;
    }
    return CEP_SOURCE_ROOT;
}

static bool fixture_make_path(const char* rel, char* buffer, size_t cap) {
    if (!rel || !buffer || !cap) {
        return false;
    }
    int need = snprintf(buffer, cap, "%s/%s", fixture_source_root(), rel);
    return need >= 0 && (size_t)need < cap;
}

static bool fixture_ensure_parent_dirs(char* path) {
    if (!path) {
        return false;
    }
    size_t len = strlen(path);
    if (!len) {
        return false;
    }
    for (size_t i = 1u; i < len; ++i) {
        if (path[i] == '/') {
            char saved = path[i];
            path[i] = '\0';
            if (mkdir(path, 0755) != 0 && errno != EEXIST) {
                path[i] = saved;
                return false;
            }
            path[i] = saved;
        }
    }
    return true;
}

static bool fixture_write_or_compare(const char* rel_path, const uint8_t* data, size_t len, bool update) {
    char path[PATH_MAX];
    if (!fixture_make_path(rel_path, path, sizeof path)) {
        return false;
    }
    if (update) {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof tmp, "%s", path);
        if (!fixture_ensure_parent_dirs(tmp)) {
            return false;
        }
        FILE* fp = fopen(path, "wb");
        if (!fp) {
            return false;
        }
        size_t written = fwrite(data, 1u, len, fp);
        fclose(fp);
        return written == len;
    }
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        munit_logf(MUNIT_LOG_ERROR,
                   "payload_ref fixture missing: %s (set CEP_UPDATE_PAYLOAD_REF_FIXTURES=1 to regenerate)",
                   path);
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize < 0) {
        fclose(fp);
        return false;
    }
    fseek(fp, 0, SEEK_SET);
    if ((size_t)fsize != len) {
        munit_logf(MUNIT_LOG_ERROR,
                   "payload_ref fixture size mismatch: %s expected=%zu actual=%ld (set CEP_UPDATE_PAYLOAD_REF_FIXTURES=1)",
                   path,
                   len,
                   fsize);
        fclose(fp);
        return false;
    }
    uint8_t* buffer = (uint8_t*)malloc((size_t)fsize);
    if (!buffer) {
        fclose(fp);
        return false;
    }
    size_t rd = fread(buffer, 1u, (size_t)fsize, fp);
    fclose(fp);
    bool equal = rd == (size_t)fsize && memcmp(buffer, data, len) == 0;
    if (!equal) {
        munit_logf(MUNIT_LOG_ERROR,
                   "payload_ref fixture drift detected: %s (set CEP_UPDATE_PAYLOAD_REF_FIXTURES=1)",
                   path);
    }
    free(buffer);
    return equal;
}

static bool fixture_generate_inline(bool update) {
    fixture_buf body;
    if (!fixture_build_cell_desc_body(k_cps_fixture_inline_payload,
                                      k_cps_fixture_inline_payload_len,
                                      k_cps_fixture_inline_payload,
                                      k_cps_fixture_inline_payload_len,
                                      CEP_DATATYPE_VALUE,
                                      CEP_FLAT_PAYLOAD_REF_INLINE,
                                      CEP_FLAT_COMPRESSION_NONE,
                                      CEP_FLAT_AEAD_NONE,
                                      &body)) {
        return false;
    }

    cepFlatRecordSpec record = {
        .type = CEP_FLAT_RECORD_CELL_DESC,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0u,
        .key = {
            .data = k_cps_fixture_inline_cell_key,
            .size = k_cps_fixture_inline_cell_key_len,
        },
        .body = {
            .data = body.data,
            .size = body.len,
        },
    };

    fixture_buf frame;
    fixture_buf_init(&frame);
    bool ok = fixture_capture_frame(&record, &frame) &&
              fixture_write_or_compare(CPS_FIXTURE_INLINE_FRAME_PATH, frame.data, frame.len, update);

    fixture_buf_reset(&frame);
    fixture_buf_reset(&body);
    return ok;
}

static bool fixture_generate_cas_plain(bool update) {
    fixture_buf body;
    if (!fixture_build_cell_desc_body(k_cps_fixture_cas_plain_payload,
                                      k_cps_fixture_cas_plain_payload_len,
                                      NULL,
                                      0u,
                                      CEP_DATATYPE_VALUE,
                                      CEP_FLAT_PAYLOAD_REF_CAS,
                                      CEP_FLAT_COMPRESSION_NONE,
                                      CEP_FLAT_AEAD_XCHACHA20_POLY1305,
                                      &body)) {
        return false;
    }

    cepFlatRecordSpec record = {
        .type = CEP_FLAT_RECORD_CELL_DESC,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0u,
        .key = {
            .data = k_cps_fixture_cas_plain_cell_key,
            .size = k_cps_fixture_cas_plain_cell_key_len,
        },
        .body = {
            .data = body.data,
            .size = body.len,
        },
    };

    fixture_buf frame;
    fixture_buf_init(&frame);
    bool ok = fixture_capture_frame(&record, &frame) &&
              fixture_write_or_compare(CPS_FIXTURE_CAS_PLAIN_FRAME_PATH, frame.data, frame.len, update) &&
              fixture_write_or_compare(CPS_FIXTURE_CAS_PLAIN_BLOB_PATH,
                                       k_cps_fixture_cas_plain_payload,
                                       k_cps_fixture_cas_plain_payload_len,
                                       update);

    fixture_buf_reset(&frame);
    fixture_buf_reset(&body);
    return ok;
}

static bool fixture_generate_cas_deflate(bool update) {
    fixture_buf body;
    if (!fixture_build_cell_desc_body(k_cps_fixture_cas_deflate_payload,
                                      k_cps_fixture_cas_deflate_payload_len,
                                      NULL,
                                      0u,
                                      CEP_DATATYPE_VALUE,
                                      CEP_FLAT_PAYLOAD_REF_CAS,
                                      CEP_FLAT_COMPRESSION_DEFLATE,
                                      CEP_FLAT_AEAD_XCHACHA20_POLY1305,
                                      &body)) {
        return false;
    }

    cepFlatRecordSpec record = {
        .type = CEP_FLAT_RECORD_CELL_DESC,
        .version = CEP_FLAT_SERIALIZER_VERSION,
        .flags = 0u,
        .key = {
            .data = k_cps_fixture_cas_deflate_cell_key,
            .size = k_cps_fixture_cas_deflate_cell_key_len,
        },
        .body = {
            .data = body.data,
            .size = body.len,
        },
    };

    fixture_buf frame;
    fixture_buf_init(&frame);
    fixture_buf compressed;
    fixture_buf_init(&compressed);

    bool ok = fixture_capture_frame(&record, &frame) &&
              fixture_compress_payload(k_cps_fixture_cas_deflate_payload,
                                       k_cps_fixture_cas_deflate_payload_len,
                                       &compressed) &&
              fixture_write_or_compare(CPS_FIXTURE_CAS_DEFLATE_FRAME_PATH, frame.data, frame.len, update) &&
              fixture_write_or_compare(CPS_FIXTURE_CAS_DEFLATE_BLOB_PATH, compressed.data, compressed.len, update);

    fixture_buf_reset(&compressed);
    fixture_buf_reset(&frame);
    fixture_buf_reset(&body);
    return ok;
}

MunitResult test_flat_serializer_payload_ref_fixtures(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    const bool update = getenv("CEP_UPDATE_PAYLOAD_REF_FIXTURES") && getenv("CEP_UPDATE_PAYLOAD_REF_FIXTURES")[0];

    munit_assert_true(fixture_generate_inline(update));
    munit_assert_true(fixture_generate_cas_plain(update));
    munit_assert_true(fixture_generate_cas_deflate(update));
    return MUNIT_OK;
}
