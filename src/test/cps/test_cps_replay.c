/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "test.h"
#include "cps/cps_fixture_defs.h"

#include "blake3.h"
#include "cps_flatfile.h"
#include "cps_storage_service.h"
#include "cep_flat_serializer.h"
#include "cep_cell.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_ops.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
static int test_replay_mkdir(const char* path, mode_t mode) {
    (void)mode;
    return _mkdir(path);
}
static char* test_replay_mkdtemp(char* tmpl) {
    if (_mktemp_s(tmpl, strlen(tmpl) + 1) != 0) {
        return NULL;
    }
    return (_mkdir(tmpl) == 0) ? tmpl : NULL;
}
static bool test_replay_setenv(const char* name, const char* value) {
    return _putenv_s(name, value ? value : "") == 0;
}
static bool test_replay_unsetenv(const char* name) {
    return _putenv_s(name, "") == 0;
}
#define lstat(path, buf) stat(path, buf)
#else
static int test_replay_mkdir(const char* path, mode_t mode) {
    return mkdir(path, mode);
}
static char* test_replay_mkdtemp(char* tmpl) {
    return mkdtemp(tmpl);
}
static bool test_replay_setenv(const char* name, const char* value) {
    return setenv(name, value, 1) == 0;
}
static bool test_replay_unsetenv(const char* name) {
    return unsetenv(name) == 0;
}
#endif

#define setenv(name, value, overwrite) test_replay_setenv(name, value)
#define unsetenv(name) test_replay_unsetenv(name)

#define CPS_CAS_MANIFEST_MAGIC   0x4341534Du
#define CPS_CAS_MANIFEST_VERSION 1u

typedef struct {
    uint8_t* data;
    size_t   len;
} fixture_blob;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint64_t entry_count;
} cas_manifest_header_disk;

typedef struct __attribute__((packed)) {
    uint8_t  hash[CEP_FLAT_HASH_SIZE];
    uint64_t payload_size;
    uint8_t  codec;
    uint8_t  aead_mode;
    uint8_t  reserved[6];
} cas_manifest_entry_disk;

typedef struct {
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} CpsRuntimeScope;

static bool fixture_make_temp_root(char* buffer, size_t cap);

static CpsRuntimeScope cps_runtime_start(void) {
    CpsRuntimeScope scope = {
        .runtime = cep_runtime_create(),
        .previous_runtime = NULL,
    };
    munit_assert_not_null(scope.runtime);
    scope.previous_runtime = cep_runtime_set_active(scope.runtime);

    cep_cell_system_initiate();
    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_namepool_bootstrap());
    munit_assert_true(cep_runtime_attach_metadata(scope.runtime));

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
    munit_assert_not_null(cep_heartbeat_data_root());
    munit_assert_not_null(cep_heartbeat_cas_root());
    return scope;
}

static void cps_runtime_cleanup(CpsRuntimeScope* scope) {
    if (!scope || !scope->runtime) {
        return;
    }
    cep_runtime_set_active(scope->runtime);
    cep_stream_clear_pending();
    (void)cep_runtime_shutdown(scope->runtime);
    cep_runtime_restore_active(scope->previous_runtime);
    cep_runtime_destroy(scope->runtime);
    scope->runtime = NULL;
    scope->previous_runtime = NULL;
}

static const char* fixture_source_root(void) {
    const char* root = getenv("MESON_SOURCE_ROOT");
    if (root && *root) {
        return root;
    }
    return CEP_SOURCE_ROOT;
}

static const char* fixture_build_root(void) {
    const char* root = getenv("MESON_BUILD_ROOT");
    return (root && *root) ? root : "build";
}

static bool fixture_make_abs_path(const char* rel, char* buffer, size_t cap) {
    if (!rel || !buffer || !cap) {
        return false;
    }
    int need = snprintf(buffer, cap, "%s/%s", fixture_source_root(), rel);
    return need >= 0 && (size_t)need < cap;
}

static bool fixture_read_varint(const uint8_t* data, size_t size, size_t* offset, uint64_t* out) {
    if (!data || !offset || !out) {
        return false;
    }
    uint64_t value = 0u;
    unsigned shift = 0u;
    size_t cursor = *offset;
    while (cursor < size) {
        uint8_t byte = data[cursor++];
        value |= ((uint64_t)(byte & 0x7Fu)) << shift;
        if ((byte & 0x80u) == 0u) {
            *offset = cursor;
            *out = value;
            return true;
        }
        shift += 7u;
        if (shift >= 64u) {
            return false;
        }
    }
    return false;
}

static bool fixture_read_file(const char* rel_path, fixture_blob* out) {
    if (!rel_path || !out) {
        return false;
    }
    char path[PATH_MAX];
    if (!fixture_make_abs_path(rel_path, path, sizeof path)) {
        return false;
    }
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return false;
    }
    fseek(fp, 0, SEEK_SET);
    uint8_t* data = (uint8_t*)malloc((size_t)size);
    if (!data) {
        fclose(fp);
        return false;
    }
    size_t rd = fread(data, 1u, (size_t)size, fp);
    fclose(fp);
    if (rd != (size_t)size) {
        free(data);
        return false;
    }
    out->data = data;
    out->len = (size_t)size;
    return true;
}

static void fixture_blob_reset(fixture_blob* blob) {
    if (!blob) {
        return;
    }
    free(blob->data);
    blob->data = NULL;
    blob->len = 0u;
}

static bool fixture_ensure_dirs(char* path) {
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
            if (test_replay_mkdir(path, 0755) != 0 && errno != EEXIST) {
                path[i] = saved;
                return false;
            }
            path[i] = saved;
        }
    }
    return true;
}

static bool fixture_write_file(const char* path, const uint8_t* data, size_t len) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    if (!fixture_ensure_dirs(tmp)) {
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

static bool fixture_make_temp_root(char* buffer, size_t cap) {
    if (!buffer || !cap) {
        return false;
    }
    char tmpl[PATH_MAX];
    int need = snprintf(tmpl, sizeof tmpl, "%s/cps_fixture.XXXXXX", fixture_build_root());
    if (need < 0 || (size_t)need >= sizeof tmpl) {
        return false;
    }
    if (!fixture_ensure_dirs(tmpl)) {
        return false;
    }
    char* dir = test_replay_mkdtemp(tmpl);
    if (!dir) {
        return false;
    }
    snprintf(buffer, cap, "%s", dir);
    return true;
}

static void fixture_hash(const uint8_t* data, size_t len, uint8_t out[CEP_FLAT_HASH_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (data && len) {
        blake3_hasher_update(&hasher, data, len);
    }
    blake3_hasher_finalize(&hasher, out, CEP_FLAT_HASH_SIZE);
}

static void fixture_hash_hex(const uint8_t hash[CEP_FLAT_HASH_SIZE], char hex[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < CEP_FLAT_HASH_SIZE; ++i) {
        hex[i * 2u] = digits[(hash[i] >> 4u) & 0x0Fu];
        hex[i * 2u + 1u] = digits[hash[i] & 0x0Fu];
    }
    hex[64] = '\0';
}

static bool fixture_cache_blob_path(const char* branch_dir,
                                    const uint8_t hash[CEP_FLAT_HASH_SIZE],
                                    char* buffer,
                                    size_t cap) {
    if (!branch_dir || !buffer || !cap) {
        return false;
    }
    char hex[65];
    fixture_hash_hex(hash, hex);
    int need = snprintf(buffer,
                        cap,
                        "%s/cas/%c%c/%s.blob",
                        branch_dir,
                        hex[0],
                        hex[1],
                        hex);
    return need >= 0 && (size_t)need < cap;
}

static bool fixture_install_manifest(const char* branch_dir,
                                     const uint8_t hash[CEP_FLAT_HASH_SIZE],
                                     uint64_t payload_size,
                                     uint8_t codec,
                                     uint8_t aead_mode) {
    cas_manifest_header_disk header = {
        .magic = CPS_CAS_MANIFEST_MAGIC,
        .version = CPS_CAS_MANIFEST_VERSION,
        .reserved = 0u,
        .entry_count = 1u,
    };
    cas_manifest_entry_disk entry = {
        .payload_size = payload_size,
        .codec = codec,
        .aead_mode = aead_mode,
        .reserved = {0},
    };
    memcpy(entry.hash, hash, CEP_FLAT_HASH_SIZE);

    char path[PATH_MAX];
    int need = snprintf(path, sizeof path, "%s/cas/manifest.bin", branch_dir);
    if (need < 0 || (size_t)need >= sizeof path) {
        return false;
    }
    if (!fixture_write_file(path, (const uint8_t*)&header, sizeof header)) {
        return false;
    }
    FILE* fp = fopen(path, "ab");
    if (!fp) {
        return false;
    }
    size_t written = fwrite(&entry, 1u, sizeof entry, fp);
    fclose(fp);
    return written == sizeof entry;
}

static bool fixture_setup_branch_dirs(const char* root_dir, char* branch_dir, size_t cap) {
    if (!root_dir || !branch_dir || !cap) {
        return false;
    }
    int need = snprintf(branch_dir, cap, "%s/%s", root_dir, CPS_FIXTURE_BRANCH_NAME);
    if (need < 0 || (size_t)need >= cap) {
        return false;
    }
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s/cas/", branch_dir);
    return fixture_ensure_dirs(tmp);
}

static bool fixture_open_engine(const char* root_dir, cps_engine** out_engine) {
    if (!root_dir || !out_engine) {
        return false;
    }
    cps_flatfile_opts opts = {
        .root_dir = root_dir,
        .branch_name = CPS_FIXTURE_BRANCH_NAME,
        .checkpoint_interval = 8u,
        .mini_toc_hint = 8u,
        .create_branch = true,
    };
    return cps_flatfile_engine_open(&opts, out_engine) == CPS_OK;
}

static bool fixture_ingest_frame(cps_engine* engine, const fixture_blob* frame, uint64_t beat) {
    if (!engine || !frame) {
        return false;
    }
    cepFlatReader* reader = cep_flat_reader_create();
    if (!reader) {
        return false;
    }
    bool ok = false;
    if (!cep_flat_reader_feed(reader, frame->data, frame->len) ||
        !cep_flat_reader_commit(reader)) {
        goto cleanup;
    }
    size_t record_count = 0u;
    const cepFlatRecordView* records = cep_flat_reader_records(reader, &record_count);
    if (!records || !record_count) {
        goto cleanup;
    }
    cps_txn* txn = NULL;
    if (engine->ops->begin_beat(engine, beat, &txn) != CPS_OK || !txn) {
        goto cleanup;
    }
    for (size_t i = 0; i < record_count; ++i) {
        cps_slice key = {
            .data = records[i].key.data,
            .len = records[i].key.size,
        };
        cps_slice value = {
            .data = records[i].body.data,
            .len = records[i].body.size,
        };
        if (engine->ops->put_record(txn, key, value, records[i].type) != CPS_OK) {
            engine->ops->abort_beat(txn);
            goto cleanup;
        }
    }
    if (engine->ops->commit_beat(txn, NULL) != CPS_OK) {
        goto cleanup;
    }
    ok = true;

cleanup:
    cep_flat_reader_destroy(reader);
    return ok;
}

static cepCell* fixture_find_child(cepCell* parent, const char* name) {
    if (!parent || !name) {
        return NULL;
    }
    cepCell* resolved = cep_cell_resolve(parent);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return NULL;
    }
    cepDT dt = cep_ops_make_dt(name);
    for (cepCell* child = cep_cell_first_all(resolved);
         child;
         child = cep_cell_next_all(resolved, child)) {
        const cepDT* cname = cep_cell_get_name(child);
        if (cname && cname->domain == dt.domain && cname->tag == dt.tag) {
            return child;
        }
    }
    return NULL;
}

static uint64_t fixture_read_metric(cepCell* metrics, const char* field) {
    cepCell* node = fixture_find_child(metrics, field);
    munit_assert_not_null(node);
    cepCell* resolved = cep_cell_resolve(node);
    munit_assert_not_null(resolved);
    const cepData* data = resolved->data;
    munit_assert_not_null(data);
    munit_assert_size(data->size, >, 0u);
    const char* text = (const char*)cep_data_payload(data);
    char buffer[64];
    size_t copy = data->size < sizeof buffer - 1u ? data->size : sizeof buffer - 1u;
    memcpy(buffer, text, copy);
    buffer[copy] = '\0';
    return (uint64_t)strtoull(buffer, NULL, 10);
}

static uint64_t fixture_metric_value(const char* field) {
    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);
    cepCell* persist = fixture_find_child(data_root, "persist");
    munit_assert_not_null(persist);
    cepCell* branch = fixture_find_child(persist, CPS_FIXTURE_BRANCH_NAME);
    munit_assert_not_null(branch);
    cepCell* metrics = fixture_find_child(branch, "metrics");
    munit_assert_not_null(metrics);
    return fixture_read_metric(metrics, field);
}

static bool fixture_install_runtime_blob(const char* entry_name,
                                         const uint8_t* payload,
                                         size_t payload_len,
                                         cepCell** out_entry) {
    cepCell* cas_root = cep_heartbeat_cas_root();
    munit_assert_not_null(cas_root);
    cepCell* resolved = cep_cell_resolve(cas_root);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }
    cepDT bucket_dt = cep_ops_make_dt("fixtures");
    cepCell* bucket = cep_cell_ensure_dictionary_child(resolved, &bucket_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        return false;
    }
    cepDT entry_dt = cep_ops_make_dt(entry_name);
    cepCell* entry = cep_cell_add_value(bucket,
                                        &entry_dt,
                                        0,
                                        CEP_DTAW("CEP", "blob"),
                                        (void*)payload,
                                        payload_len,
                                        payload_len);
    if (!entry) {
        return false;
    }
    if (out_entry) {
        *out_entry = entry;
    }
    return true;
}

static bool fixture_request_record(cps_engine* engine,
                                   const uint8_t* key_bytes,
                                   size_t key_len,
                                   fixture_blob* out_value) {
    cps_slice key = {
        .data = key_bytes,
        .len = key_len,
    };
    cps_buf value = {0};
    int rc = engine->ops->get_record(engine, key, &value);
    if (rc != CPS_OK) {
        fprintf(stderr,
                "[fixture_request_record] get_record failed rc=%d key_len=%zu\n",
                rc,
                key_len);
        return false;
    }
    out_value->data = value.data;
    out_value->len = value.len;
    return true;
}

static bool fixture_parse_chunk(const fixture_blob* chunk,
                                uint8_t* payload_kind,
                                uint64_t* total_size) {
    if (!chunk || !chunk->data || chunk->len == 0u) {
        return false;
    }
    const uint8_t* body = chunk->data;
    size_t size = chunk->len;
    size_t offset = 0u;

    uint8_t kind = body[offset++];
    if (payload_kind) {
        *payload_kind = kind;
    }
    uint64_t tmp = 0u;
    if (!fixture_read_varint(body, size, &offset, &tmp)) {
        return false;
    }
    if (total_size) {
        *total_size = tmp;
    }
    return true;
}

MunitResult test_cps_replay_inline(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    CpsRuntimeScope runtime = cps_runtime_start();
    char root_dir[PATH_MAX];
    munit_assert_true(fixture_make_temp_root(root_dir, sizeof root_dir));
    char branch_dir[PATH_MAX];
    munit_assert_true(fixture_setup_branch_dirs(root_dir, branch_dir, sizeof branch_dir));

    cps_engine* engine = NULL;
    munit_assert_true(fixture_open_engine(root_dir, &engine));

    fixture_blob frame = {0};
    munit_assert_true(fixture_read_file(CPS_FIXTURE_INLINE_FRAME_PATH, &frame));
    munit_assert_true(fixture_ingest_frame(engine, &frame, 1));
    fixture_blob_reset(&frame);

    fixture_blob chunk = {0};
    munit_assert_true(fixture_request_record(engine,
                                             k_cps_fixture_inline_cell_key,
                                             k_cps_fixture_inline_cell_key_len,
                                             &chunk));
    fixture_blob_reset(&chunk);

    engine->ops->close(engine);
    test_replay_unsetenv("CEP_SERIALIZATION_FLAT_AEAD_MODE");
    test_replay_unsetenv("CEP_SERIALIZATION_FLAT_AEAD_KEY");
    cps_runtime_cleanup(&runtime);
    return MUNIT_OK;
}

MunitResult test_cps_replay_cas_cache(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    CpsRuntimeScope runtime = cps_runtime_start();
    char root_dir[PATH_MAX];
    munit_assert_true(fixture_make_temp_root(root_dir, sizeof root_dir));
    char branch_dir[PATH_MAX];
    munit_assert_true(fixture_setup_branch_dirs(root_dir, branch_dir, sizeof branch_dir));

    fixture_blob compressed = {0};
    munit_assert_true(fixture_read_file(CPS_FIXTURE_CAS_DEFLATE_BLOB_PATH, &compressed));

    uint8_t hash[CEP_FLAT_HASH_SIZE];
    fixture_hash(k_cps_fixture_cas_deflate_payload,
                 k_cps_fixture_cas_deflate_payload_len,
                 hash);

    char blob_path[PATH_MAX];
    munit_assert_true(fixture_cache_blob_path(branch_dir, hash, blob_path, sizeof blob_path));
    munit_assert_true(fixture_write_file(blob_path, compressed.data, compressed.len));
    fixture_blob_reset(&compressed);
    munit_assert_true(fixture_install_manifest(branch_dir,
                                               hash,
                                               k_cps_fixture_cas_deflate_payload_len,
                                               CEP_FLAT_COMPRESSION_DEFLATE,
                                               CEP_FLAT_AEAD_XCHACHA20_POLY1305));

    cps_engine* engine = NULL;
    munit_assert_true(fixture_open_engine(root_dir, &engine));

    fixture_blob frame = {0};
    munit_assert_true(fixture_read_file(CPS_FIXTURE_CAS_DEFLATE_FRAME_PATH, &frame));
    munit_assert_true(fixture_ingest_frame(engine, &frame, 1));
    fixture_blob_reset(&frame);

    test_replay_setenv("CEP_SERIALIZATION_FLAT_AEAD_MODE", CPS_FIXTURE_AEAD_MODE);
    test_replay_setenv("CEP_SERIALIZATION_FLAT_AEAD_KEY", CPS_FIXTURE_AEAD_KEY_HEX);

    fixture_blob chunk = {0};
    munit_assert_true(fixture_request_record(engine,
                                             k_cps_fixture_cas_deflate_chunk_key,
                                             k_cps_fixture_cas_deflate_chunk_key_len,
                                             &chunk));
    uint8_t payload_kind = 0u;
    uint64_t total_size = 0u;
    munit_assert_true(fixture_parse_chunk(&chunk, &payload_kind, &total_size));
    munit_assert_uint64(total_size, ==, k_cps_fixture_cas_deflate_payload_len);
    fixture_blob_reset(&chunk);

    munit_assert_uint64(fixture_metric_value("cas_hits"), ==, 1u);
    munit_assert_uint64(fixture_metric_value("cas_miss"), ==, 0u);

    engine->ops->close(engine);
    unsetenv("CEP_SERIALIZATION_FLAT_AEAD_MODE");
    unsetenv("CEP_SERIALIZATION_FLAT_AEAD_KEY");
    cps_runtime_cleanup(&runtime);
    return MUNIT_OK;
}

MunitResult test_cps_replay_cas_runtime(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    CpsRuntimeScope runtime = cps_runtime_start();
    char root_dir[PATH_MAX];
    munit_assert_true(fixture_make_temp_root(root_dir, sizeof root_dir));
    char branch_dir[PATH_MAX];
    munit_assert_true(fixture_setup_branch_dirs(root_dir, branch_dir, sizeof branch_dir));

    cps_engine* engine = NULL;
    munit_assert_true(fixture_open_engine(root_dir, &engine));

    fixture_blob frame = {0};
    munit_assert_true(fixture_read_file(CPS_FIXTURE_CAS_PLAIN_FRAME_PATH, &frame));
    munit_assert_true(fixture_ingest_frame(engine, &frame, 1));
    fixture_blob_reset(&frame);

    fixture_blob runtime_blob = {0};
    munit_assert_true(fixture_read_file(CPS_FIXTURE_CAS_PLAIN_BLOB_PATH, &runtime_blob));

    cepCell* runtime_entry = NULL;
    munit_assert_true(fixture_install_runtime_blob("cas_plain_blob",
                                                   runtime_blob.data,
                                                   runtime_blob.len,
                                                   &runtime_entry));
    cepCell* resolved_entry = cep_cell_resolve(runtime_entry);
    munit_assert_not_null(resolved_entry);
    cepData* entry_data = resolved_entry->data;
    munit_assert_not_null(entry_data);
    munit_assert_size(entry_data->size, ==, runtime_blob.len);
    memcpy((void*)cep_data_payload(entry_data), runtime_blob.data, runtime_blob.len);
    setenv("CEP_SERIALIZATION_FLAT_AEAD_MODE", CPS_FIXTURE_AEAD_MODE, 1);
    setenv("CEP_SERIALIZATION_FLAT_AEAD_KEY", CPS_FIXTURE_AEAD_KEY_HEX, 1);

    fixture_blob chunk = {0};
    munit_assert_true(fixture_request_record(engine,
                                             k_cps_fixture_cas_plain_chunk_key,
                                             k_cps_fixture_cas_plain_chunk_key_len,
                                             &chunk));
    uint64_t total_size = 0u;
    munit_assert_true(fixture_parse_chunk(&chunk, NULL, &total_size));
    munit_assert_uint64(total_size, ==, k_cps_fixture_cas_plain_payload_len);
    fixture_blob_reset(&chunk);

    munit_assert_uint64(fixture_metric_value("cas_hits"), ==, 0u);
    munit_assert_uint64(fixture_metric_value("cas_miss"), ==, 1u);

    cep_cell_delete_hard(runtime_entry);
    fixture_blob_reset(&runtime_blob);
    engine->ops->close(engine);
    unsetenv("CEP_SERIALIZATION_FLAT_AEAD_MODE");
    unsetenv("CEP_SERIALIZATION_FLAT_AEAD_KEY");
    cps_runtime_cleanup(&runtime);
    return MUNIT_OK;
}

MunitResult test_cps_export_windowed_external(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    char root_dir[PATH_MAX];
    munit_assert_true(fixture_make_temp_root(root_dir, sizeof root_dir));
    setenv("CEP_CPS_ROOT", root_dir, 1);
    setenv("CEP_CPS_BRANCH", "bundle_test", 1);

    CpsRuntimeScope runtime = cps_runtime_start();

    char target_dir[PATH_MAX];
    int need = snprintf(target_dir, sizeof target_dir, "%s/external_bundle", root_dir);
    munit_assert_true(need > 0 && (size_t)need < sizeof target_dir);

    cpsStorageSaveOptions opts = {
        .target_path = target_dir,
        .history_window_beats = 1u,
    };
    char bundle_path[PATH_MAX];
    uint64_t copied_bytes = 0u;
    uint64_t cas_bytes = 0u;
    uint64_t cas_blobs = 0u;
    int rc = cps_storage_export_active_branch(&opts,
                                              bundle_path,
                                              sizeof bundle_path,
                                              &copied_bytes,
                                              &cas_bytes,
                                              &cas_blobs);
    munit_assert_int(rc, ==, CPS_OK);
    munit_assert_string_equal(bundle_path, target_dir);

    char manifest_path[PATH_MAX];
    need = snprintf(manifest_path, sizeof manifest_path, "%s/manifest.txt", bundle_path);
    munit_assert_true(need > 0 && (size_t)need < sizeof manifest_path);
    struct stat st = {0};
    munit_assert_int(stat(manifest_path, &st), ==, 0);
    munit_assert_true(cps_storage_verify_bundle_dir(bundle_path));

    cps_runtime_cleanup(&runtime);
    unsetenv("CEP_CPS_ROOT");
    unsetenv("CEP_CPS_BRANCH");
    return MUNIT_OK;
}

MunitResult test_cps_stage_external_bundle(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    char root_dir[PATH_MAX];
    munit_assert_true(fixture_make_temp_root(root_dir, sizeof root_dir));
    setenv("CEP_CPS_ROOT", root_dir, 1);
    setenv("CEP_CPS_BRANCH", "bundle_stage", 1);

    CpsRuntimeScope runtime = cps_runtime_start();

    char target_dir[PATH_MAX];
    int need = snprintf(target_dir, sizeof target_dir, "%s/external_stage_bundle", root_dir);
    munit_assert_true(need > 0 && (size_t)need < sizeof target_dir);

    cpsStorageSaveOptions opts = {
        .target_path = target_dir,
        .history_window_beats = 0u,
    };
    char bundle_path[PATH_MAX];
    int rc = cps_storage_export_active_branch(&opts, bundle_path, sizeof bundle_path, NULL, NULL, NULL);
    munit_assert_int(rc, ==, CPS_OK);

    char staged_path[PATH_MAX];
    munit_assert_true(cps_storage_stage_bundle_dir(bundle_path, staged_path, sizeof staged_path));
    struct stat st = {0};
    munit_assert_int(stat(staged_path, &st), ==, 0);
    munit_assert_true(S_ISDIR(st.st_mode));

    cps_runtime_cleanup(&runtime);
    unsetenv("CEP_CPS_ROOT");
    unsetenv("CEP_CPS_BRANCH");
    return MUNIT_OK;
}
