/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "test.h"

#include "cep_serialization.h"
#include "cep_cell.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>


typedef struct {
    uint8_t* data;
    size_t   size;
} SerializationChunk;

typedef struct {
    SerializationChunk chunks[64];
    size_t             count;
} SerializationCapture;

static cepCell* serialization_find_cell_recursive(cepCell* node, const cepDT* target) {
    if (!node || !target)
        return NULL;

    cepCell* resolved = cep_cell_resolve(node);
    if (resolved) {
        const cepDT* name = cep_cell_get_name(resolved);
        if (name &&
            name->domain == target->domain &&
            name->tag == target->tag &&
            name->glob == target->glob) {
            return resolved;
        }
    }

    if (!resolved || !cep_cell_has_store(resolved))
        return NULL;

    for (cepCell* child = cep_cell_first_all(resolved); child; child = cep_cell_next_all(resolved, child)) {
        cepCell* match = serialization_find_cell_recursive(child, target);
        if (match)
            return match;
    }

    return NULL;
}

static void serialization_dump_trace(const SerializationCapture* capture, const char* suffix) {
    const char* base = getenv("CEP_SERIALIZATION_TRACE_DIR");
    if (!base || !capture || !suffix)
        return;

    if (mkdir(base, 0775) != 0 && errno != EEXIST)
        return;

    char path[1024];
    if (snprintf(path, sizeof path, "%s/%s", base, suffix) < 0 || strlen(path) >= sizeof path)
        return;

    FILE* fp = fopen(path, "wb");
    if (!fp)
        return;

    for (size_t i = 0; i < capture->count; ++i) {
        const SerializationChunk* chunk = &capture->chunks[i];
        if (!chunk->data || !chunk->size)
            continue;
        fwrite(chunk->data, 1u, chunk->size, fp);
    }

    fclose(fp);
}

static void serialization_dump_payload_blob(const uint8_t* payload, size_t size, const char* suffix) {
    const char* base = getenv("CEP_SERIALIZATION_TRACE_DIR");
    if (!base || !payload || !size || !suffix)
        return;

    if (mkdir(base, 0775) != 0 && errno != EEXIST)
        return;

    char path[1024];
    if (snprintf(path, sizeof path, "%s/%s", base, suffix) < 0 || strlen(path) >= sizeof path)
        return;

    FILE* fp = fopen(path, "wb");
    if (!fp)
        return;

    fwrite(payload, 1u, size, fp);
    fclose(fp);
}

static uint64_t serialization_digest_mix(uint64_t seed, uint64_t chunk_id, const uint8_t* payload, size_t payload_size) {
    uint64_t payload_hash = payload_size ? cep_hash_bytes(payload, payload_size) : UINT64_C(0);
    struct {
        uint64_t seed;
        uint64_t id;
        uint64_t payload;
    } block = {
        .seed = seed,
        .id = chunk_id,
        .payload = payload_hash,
    };
    return cep_hash_bytes(&block, sizeof block);
}

#define SERIAL_CHILD_FLAG_TOMBSTONE    0x01u
#define SERIAL_CHILD_FLAG_VEILED       0x02u
#define SERIAL_CHILD_FLAG_FINGERPRINT  0x04u
#define SERIAL_RECORD_MANIFEST_BASE    0x01u
#define SERIAL_RECORD_MANIFEST_DELTA   0x02u
#define SERIAL_RECORD_MANIFEST_CHILDREN 0x03u
#define SERIAL_BASE_FLAG_CHILDREN_SPLIT 0x08u

static bool serialization_capture_sink(void* ctx, const uint8_t* chunk, size_t size) {
    SerializationCapture* capture = ctx;
    if (!capture || !chunk || !size)
        return false;
    if (capture->count >= sizeof capture->chunks / sizeof capture->chunks[0])
        return false;

    uint8_t* copy = cep_malloc(size);
    memcpy(copy, chunk, size);

    uint64_t chunk_id = 0;
    if (size >= CEP_SERIALIZATION_CHUNK_OVERHEAD)
        memcpy(&chunk_id, chunk + sizeof(uint64_t), sizeof(uint64_t));
    fprintf(stderr, "[capture] idx=%zu class=%u size=%zu\n",
            capture->count,
            (unsigned)cep_serialization_chunk_class(chunk_id),
            size);

    capture->chunks[capture->count].data = copy;
    capture->chunks[capture->count].size = size;
    capture->count++;

    return true;
}

static uint16_t read_be16(const uint8_t* buffer) {
    return (uint16_t)((buffer[0] << 8) | buffer[1]);
}

static uint32_t read_be32(const uint8_t* buffer) {
    return ((uint32_t)buffer[0] << 24) |
           ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8)  |
           ((uint32_t)buffer[3]);
}

static uint64_t read_be64(const uint8_t* buffer) {
    uint64_t hi = read_be32(buffer);
    uint64_t lo = read_be32(buffer + 4);
    return (hi << 32) | lo;
}

static void write_be64(uint8_t* buffer, uint64_t value) {
    buffer[0] = (uint8_t)((value >> 56) & 0xFFu);
    buffer[1] = (uint8_t)((value >> 48) & 0xFFu);
    buffer[2] = (uint8_t)((value >> 40) & 0xFFu);
    buffer[3] = (uint8_t)((value >> 32) & 0xFFu);
    buffer[4] = (uint8_t)((value >> 24) & 0xFFu);
    buffer[5] = (uint8_t)((value >> 16) & 0xFFu);
    buffer[6] = (uint8_t)((value >> 8) & 0xFFu);
    buffer[7] = (uint8_t)(value & 0xFFu);
}

static uint64_t serialization_recompute_digest(const SerializationCapture* capture) {
    if (!capture || capture->count < 2u)
        return 0u;

    uint64_t digest = 0u;
    for (size_t i = 1; i + 1 < capture->count; ++i) {
        const SerializationChunk* chunk = &capture->chunks[i];
        if (!chunk->data || chunk->size < CEP_SERIALIZATION_CHUNK_OVERHEAD)
            continue;
        uint64_t payload_size = read_be64(chunk->data);
        uint64_t chunk_id = read_be64(chunk->data + sizeof(uint64_t));
        uint16_t chunk_class = cep_serialization_chunk_class(chunk_id);
        if (chunk_class == CEP_CHUNK_CLASS_CONTROL)
            continue;
        const uint8_t* payload = chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
        digest = serialization_digest_mix(digest, chunk_id, payload, (size_t)payload_size);
    }
    return digest;
}

static uint8_t* serialization_manifest_child(uint8_t* payload, uint16_t child_index) {
    if (!payload)
        return NULL;

    const size_t descriptor_base = sizeof(uint64_t) * 2u + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint8_t record_type = payload[0];
    if (record_type == SERIAL_RECORD_MANIFEST_CHILDREN) {
        uint16_t descriptor_offset = read_be16(payload + 4u);
        uint16_t descriptor_count = read_be16(payload + 6u);
        uint16_t segment_count = read_be16(payload + 8u);
        if (child_index < descriptor_offset || child_index >= descriptor_offset + descriptor_count)
            return NULL;
        uint8_t* cursor = payload + 10u;
        const size_t segment_stride = sizeof(uint64_t) * 2u + 4u;
        cursor += (size_t)segment_count * segment_stride;
        uint16_t relative = (uint16_t)(child_index - descriptor_offset);
        for (uint16_t i = 0; i < descriptor_count; ++i) {
            uint8_t* descriptor = cursor;
            cursor += descriptor_base;
            if ((descriptor[sizeof(uint64_t) * 2u + 1u] & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u)
                cursor += sizeof(uint64_t);
            if (i == relative)
                return descriptor;
        }
        return NULL;
    }

    if (record_type != SERIAL_RECORD_MANIFEST_BASE)
        return NULL;

    uint8_t base_flags = payload[3];
    if ((base_flags & SERIAL_BASE_FLAG_CHILDREN_SPLIT) != 0u)
        return NULL;

    uint16_t path_segments = read_be16(payload + 5u);
    uint16_t child_count = read_be16(payload + 7u);
    if (child_index >= child_count)
        return NULL;

    uint8_t* cursor = payload + 11u;
    const size_t segment_stride = sizeof(uint64_t) * 2u + 4u;
    cursor += (size_t)path_segments * segment_stride;

    for (uint16_t i = 0; i < child_count; ++i) {
        uint8_t* descriptor = cursor;
        cursor += descriptor_base;
        if ((descriptor[sizeof(uint64_t) * 2u + 1u] & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u)
            cursor += sizeof(uint64_t);
        if (i == child_index)
            return descriptor;
    }
    return NULL;
}

static const SerializationChunk* serialization_find_chunk(const SerializationCapture* capture,
                                                          uint8_t record_type) {
    if (!capture)
        return NULL;
    for (size_t i = 0; i < capture->count; ++i) {
        const SerializationChunk* chunk = &capture->chunks[i];
        if (!chunk->data || chunk->size < CEP_SERIALIZATION_CHUNK_OVERHEAD + 1u)
            continue;
        uint64_t chunk_id = read_be64(chunk->data + sizeof(uint64_t));
        if (cep_serialization_chunk_class(chunk_id) != CEP_CHUNK_CLASS_STRUCTURE)
            continue;
        const uint8_t* payload = chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
        if (payload[0] == record_type)
            return chunk;
    }
    return NULL;
}

static uint8_t* serialization_delta_child(uint8_t* payload) {
    if (!payload)
        return NULL;
    uint16_t path_segments = read_be16(payload + 4u);
    uint8_t* cursor = payload + 8u + sizeof(uint64_t) * 2u + (size_t)path_segments * (sizeof(uint64_t) * 2u + 4u);
    return cursor;
}

static bool serialization_dt_equal(const cepDT* a, const cepDT* b) {
    if (!a || !b)
        return false;
    return a->domain == b->domain && a->tag == b->tag && a->glob == b->glob;
}

static cepCell* serialization_find_descendant(cepCell* start, const cepDT* target) {
    if (!start || !target)
        return NULL;

    cepCell* node = cep_link_pull(start);
    if (!node)
        return NULL;

    const cepDT* name = cep_cell_get_name(node);
    if (serialization_dt_equal(name, target))
        return node;

    for (cepCell* child = cep_cell_first_all(node); child; child = cep_cell_next_all(node, child)) {
        cepCell* next = cep_cell_is_link(child) ? cep_link_pull(child) : child;
        if (!next)
            continue;
        cepCell* found = serialization_find_descendant(next, target);
        if (found)
            return found;
    }
    return NULL;
}

static void serialization_capture_clear(SerializationCapture* capture) {
    if (!capture)
        return;

    for (size_t i = 0; i < capture->count; ++i) {
        cep_free(capture->chunks[i].data);
        capture->chunks[i].data = NULL;
        capture->chunks[i].size = 0;
    }
    capture->count = 0;
}

typedef struct {
    unsigned    handle_retains;
    unsigned    handle_releases;
    unsigned    stream_retains;
    unsigned    stream_releases;
    cepCell*    last_restored_handle;
    cepCell*    last_restored_stream;
} ProxyTestLibraryContext;

static cepCell* proxy_test_make_resource(const uint8_t* bytes, size_t size) {
    cepCell* cell = cep_malloc0(sizeof *cell);
    CEP_0(cell);
    cep_cell_initialize_value(cell,
                              CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("resource")),
                              CEP_DTAW("CEP", "lib_payld"),
                              (void*)bytes,
                              size,
                              size? size: 1u);
    return cell;
}

static bool proxy_test_snapshot_common(cepCell* resource, cepProxySnapshot* snapshot) {
    resource = cep_link_pull(resource);
    if (!resource || !cep_cell_is_normal(resource) || !resource->data)
        return false;

    size_t size = resource->data->size;
    uint8_t* copy = NULL;
    if (size) {
        copy = cep_malloc(size);
        memcpy(copy, resource->data->value, size);
    }

    snapshot->payload = copy;
    snapshot->size = size;
    snapshot->flags = copy? CEP_PROXY_SNAPSHOT_INLINE: 0u;
    snapshot->ticket = NULL;
    return true;
}

static bool proxy_test_handle_snapshot(const cepLibraryBinding* binding, cepCell* handle, cepProxySnapshot* snapshot) {
    (void)binding;
    return proxy_test_snapshot_common(handle, snapshot);
}

static bool proxy_test_stream_snapshot(const cepLibraryBinding* binding, cepCell* stream, cepProxySnapshot* snapshot) {
    (void)binding;
    return proxy_test_snapshot_common(stream, snapshot);
}

static bool proxy_test_restore_common(const cepProxySnapshot* snapshot,
                                      cepCell** out_cell,
                                      ProxyTestLibraryContext* ctx,
                                      bool is_stream) {
    if (!out_cell)
        return false;

    cepCell* cell = cep_malloc0(sizeof *cell);
    CEP_0(cell);
    cep_cell_initialize_value(cell,
                              is_stream? CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("stream"))
                                        : CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")),
                              CEP_DTAW("CEP", "lib_payld"),
                              (void*)snapshot->payload,
                              snapshot->size,
                              snapshot->size? snapshot->size: 1u);

    if (ctx) {
        if (is_stream)
            ctx->last_restored_stream = cell;
        else
            ctx->last_restored_handle = cell;
    }

    *out_cell = cell;
    return true;
}

static bool proxy_test_handle_restore(const cepLibraryBinding* binding,
                                      const cepProxySnapshot* snapshot,
                                      cepCell** out_handle) {
    ProxyTestLibraryContext* ctx = binding? (ProxyTestLibraryContext*)binding->ctx: NULL;
    return proxy_test_restore_common(snapshot, out_handle, ctx, false);
}

static bool proxy_test_stream_restore(const cepLibraryBinding* binding,
                                      const cepProxySnapshot* snapshot,
                                      cepCell** out_stream) {
    ProxyTestLibraryContext* ctx = binding? (ProxyTestLibraryContext*)binding->ctx: NULL;
    return proxy_test_restore_common(snapshot, out_stream, ctx, true);
}

static bool proxy_test_handle_retain(const cepLibraryBinding* binding, cepCell* handle) {
    (void)handle;
    ProxyTestLibraryContext* ctx = binding? (ProxyTestLibraryContext*)binding->ctx: NULL;
    if (ctx)
        ctx->handle_retains++;
    return true;
}

static void proxy_test_handle_release(const cepLibraryBinding* binding, cepCell* handle) {
    ProxyTestLibraryContext* ctx = binding? (ProxyTestLibraryContext*)binding->ctx: NULL;
    if (ctx)
        ctx->handle_releases++;

    if (handle) {
        cep_cell_finalize_hard(handle);
        cep_free(handle);
    }
}

static const cepLibraryOps proxy_test_library_ops = {
    .handle_retain      = proxy_test_handle_retain,
    .handle_release     = proxy_test_handle_release,
    .stream_read        = NULL,
    .stream_write       = NULL,
    .stream_expected_hash = NULL,
    .stream_map         = NULL,
    .stream_unmap       = NULL,
    .handle_snapshot    = proxy_test_handle_snapshot,
    .handle_restore     = proxy_test_handle_restore,
    .stream_snapshot    = proxy_test_stream_snapshot,
    .stream_restore     = proxy_test_stream_restore,
};

typedef struct {
    unsigned handle_releases;
    bool     count_releases;
    cepCell* next_restore;
} ReleaseCounterLibraryCtx;

static bool release_counter_handle_retain(const cepLibraryBinding* binding, cepCell* handle) {
    (void)binding;
    (void)handle;
    return true;
}

static void release_counter_handle_release(const cepLibraryBinding* binding, cepCell* handle) {
    ReleaseCounterLibraryCtx* ctx = binding ? (ReleaseCounterLibraryCtx*)binding->ctx : NULL;
    if (ctx && ctx->count_releases)
        ctx->handle_releases++;
    (void)handle;
}

static bool release_counter_handle_restore(const cepLibraryBinding* binding,
                                           const cepProxySnapshot* snapshot,
                                           cepCell** out_handle) {
    (void)snapshot;
    ReleaseCounterLibraryCtx* ctx = binding ? (ReleaseCounterLibraryCtx*)binding->ctx : NULL;
    if (!ctx || !out_handle || !ctx->next_restore)
        return false;
    *out_handle = ctx->next_restore;
    ctx->next_restore = NULL;
    return true;
}

static const cepLibraryOps release_counter_library_ops = {
    .handle_retain      = release_counter_handle_retain,
    .handle_release     = release_counter_handle_release,
    .stream_read        = NULL,
    .stream_write       = NULL,
    .stream_expected_hash = NULL,
    .stream_map         = NULL,
    .stream_unmap       = NULL,
    .handle_snapshot    = proxy_test_handle_snapshot,
    .handle_restore     = release_counter_handle_restore,
    .stream_snapshot    = NULL,
    .stream_restore     = NULL,
};

/* Validate that a single normal cell turns into the expected trio of chunks:
   the control/header frame with the CEP magic, the structural manifest with the
   cell path, and the inline data descriptor that carries both metadata and the
   payload bytes. */
/* Covers serialization framing and payload replay semantics. */

MunitResult test_serialization(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;
    bool boot_cycle_after = test_boot_cycle_is_after(params);

    uint8_t payload[] = "serialize-me";
    cepData* data = cep_data_new_value(CEP_DTAW("CEP", "value"), payload, sizeof payload - 1u);

    cepCell cell;
    CEP_0(&cell);
    cep_cell_initialize(&cell,
                        CEP_TYPE_NORMAL,
                        CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("ser_cell")),
                        data,
                        NULL);

    cepID expected_domain = cell.metacell.domain;
    cepID expected_tag = cell.metacell.tag;
    uint64_t expected_hash = cep_data_compute_hash(data);

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(&cell,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));


    const SerializationChunk* header_chunk = &capture.chunks[0];
    cepSerializationHeader parsed = {0};
    munit_assert_true(cep_serialization_header_read(header_chunk->data,
                                                    header_chunk->size,
                                                    &parsed));
    munit_assert_uint64(parsed.magic, ==, CEP_SERIALIZATION_MAGIC);
    munit_assert_uint16(parsed.version, ==, CEP_SERIALIZATION_VERSION);
    munit_assert_uint8(parsed.byte_order, ==, CEP_SERIAL_ENDIAN_BIG);
    munit_assert_true((parsed.flags & CEP_SERIALIZATION_FLAG_CAPABILITIES) != 0u);
    munit_assert_true(parsed.capabilities_present);
    munit_assert_true((parsed.capabilities & CEP_SERIALIZATION_CAP_HISTORY_MANIFEST) != 0u);
    munit_assert_true((parsed.capabilities & CEP_SERIALIZATION_CAP_MANIFEST_DELTAS) != 0u);
    munit_assert_true((parsed.capabilities & CEP_SERIALIZATION_CAP_PAYLOAD_HASH) != 0u);
    munit_assert_true((parsed.capabilities & CEP_SERIALIZATION_CAP_PROXY_ENVELOPE) != 0u);
    munit_assert_true((parsed.capabilities & CEP_SERIALIZATION_CAP_SPLIT_DESCRIPTORS) != 0u);

    const SerializationChunk* manifest_chunk = &capture.chunks[1];
    uint64_t manifest_payload = read_be64(manifest_chunk->data);
    munit_assert_size(manifest_chunk->size, ==, manifest_payload + CEP_SERIALIZATION_CHUNK_OVERHEAD);
    uint64_t manifest_id = read_be64(manifest_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(manifest_id), ==, CEP_CHUNK_CLASS_STRUCTURE);
    munit_assert_uint32(cep_serialization_chunk_transaction(manifest_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(manifest_id), ==, 1);

    const uint8_t* manifest_payload_bytes = manifest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(manifest_payload_bytes[0], ==, 0x01u);
    munit_assert_uint8(manifest_payload_bytes[1], ==, 0u); /* organiser */
    munit_assert_uint8(manifest_payload_bytes[2], ==, 0u); /* storage hint */
    uint8_t base_flags = manifest_payload_bytes[3];
    uint8_t cell_type = manifest_payload_bytes[4];
    uint16_t segment_count = read_be16(manifest_payload_bytes + 5);
    uint16_t child_count = read_be16(manifest_payload_bytes + 7);
    bool payload_present = (base_flags & 0x02u) != 0u;

    const size_t path_stride = sizeof(uint64_t) * 2u + 4u;
    const uint8_t* path_bytes = manifest_payload_bytes + 11;
    if (!boot_cycle_after) {
        fprintf(stderr,
                "[instrument][serialization_cell] boot_cycle=fresh segment_count=%u child_count=%u base_flags=0x%02x payload_present=%u\n",
                (unsigned)segment_count,
                (unsigned)child_count,
                base_flags,
                payload_present ? 1u : 0u);
        const uint8_t* cursor = path_bytes;
        for (uint16_t idx = 0; idx < segment_count; ++idx) {
            uint64_t seg_domain = read_be64(cursor);
            uint64_t seg_tag = read_be64(cursor + 8);
            uint8_t seg_glob = cursor[16];
            fprintf(stderr,
                    "[instrument][serialization_cell] boot_cycle=fresh path[%u]=%016" PRIx64 ":%016" PRIx64 " glob=%u\n",
                    (unsigned)idx,
                    (uint64_t)seg_domain,
                    (uint64_t)seg_tag,
                    seg_glob);
            cursor += path_stride;
        }
        serialization_dump_payload_blob(manifest_payload_bytes,
                                        manifest_chunk->size - CEP_SERIALIZATION_CHUNK_OVERHEAD,
                                        "unit_serialization_cell_manifest_fresh.bin");
    }

    munit_assert_uint8(cell_type, ==, CEP_TYPE_NORMAL);
    munit_assert_uint16(segment_count, ==, 2);
    munit_assert_uint16(child_count, ==, 0);
    munit_assert_true(payload_present); /* payload present */

    uint64_t domain = read_be64(path_bytes);
    uint64_t tag = read_be64(path_bytes + 8);
    uint8_t glob_flag = path_bytes[16];
    munit_assert_uint64(domain, ==, expected_domain);
    munit_assert_uint64(tag, ==, expected_tag);
    munit_assert_uint8(glob_flag, ==, 0);

    const uint8_t* data_bytes = path_bytes + path_stride;
    uint64_t data_domain = read_be64(data_bytes);
    uint64_t data_tag = read_be64(data_bytes + 8);
    uint8_t data_glob = data_bytes[16];
    munit_assert_uint64(data_domain, ==, data->dt.domain);
    munit_assert_uint64(data_tag, ==, data->dt.tag);
    munit_assert_uint8(data_glob, ==, 0);

    const SerializationChunk* data_chunk = &capture.chunks[2];
    const SerializationChunk* control_chunk = &capture.chunks[3];
    const SerializationChunk* digest_chunk = &capture.chunks[4];
    uint64_t data_payload = read_be64(data_chunk->data);
    munit_assert_size(data_chunk->size, ==, data_payload + CEP_SERIALIZATION_CHUNK_OVERHEAD);
    uint64_t data_id = read_be64(data_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(data_id), ==, CEP_CHUNK_CLASS_STRUCTURE);
    munit_assert_uint32(cep_serialization_chunk_transaction(data_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(data_id), ==, 2);

    uint64_t control_payload = read_be64(control_chunk->data);
    munit_assert_size(control_chunk->size, ==, control_payload + CEP_SERIALIZATION_CHUNK_OVERHEAD);
    uint64_t control_id = read_be64(control_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(control_id), ==, CEP_CHUNK_CLASS_CONTROL);
    munit_assert_uint32(cep_serialization_chunk_transaction(control_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(control_id), ==, 3);

    const uint8_t* descriptor = data_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint8_t data_version = descriptor[0];
    uint8_t data_kind = descriptor[1];
    uint16_t chunk_flags = read_be16(descriptor + 2);
    uint64_t journal_beat = read_be64(descriptor + 4);
    uint64_t payload_hash = read_be64(descriptor + 12);
    uint16_t datatype = read_be16(descriptor + 20);
    uint16_t legacy_flags = read_be16(descriptor + 22);
    uint32_t inline_len = read_be32(descriptor + 24);
    uint64_t total_len = read_be64(descriptor + 28);
    uint64_t dt_domain = read_be64(descriptor + 36);
    uint64_t dt_tag = read_be64(descriptor + 44);
    uint8_t dt_glob = descriptor[52];
    const uint8_t* inline_data = descriptor + 60;

    (void)journal_beat;
    munit_assert_uint8(data_version, ==, 0x01u);
    munit_assert_uint8(data_kind, ==, 0x00u);
    munit_assert_true((chunk_flags & 0x0002u) != 0u);
    munit_assert_uint16((uint16_t)(chunk_flags & 0x0001u), ==, 0u);
    munit_assert_uint16((uint16_t)(chunk_flags & 0x0004u), ==, 0u);
    munit_assert_uint16(datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_uint16(legacy_flags, ==, 0u);
    munit_assert_uint32(inline_len, ==, sizeof payload - 1u);
    munit_assert_uint64(total_len, ==, sizeof payload - 1u);
    munit_assert_uint64(payload_hash, ==, expected_hash);
    munit_assert_uint64(dt_domain, ==, CEP_DTAW("CEP", "value")->domain);
    munit_assert_uint64(dt_tag, ==, CEP_DTAW("CEP", "value")->tag);
    munit_assert_uint8(dt_glob, ==, 0);
    munit_assert_int(memcmp(inline_data, payload, sizeof payload - 1u), ==, 0);

    munit_assert_size(digest_chunk->size, ==, CEP_SERIALIZATION_CHUNK_OVERHEAD + (sizeof(uint16_t) * 2u) + (sizeof(uint64_t) * 2u));
    uint64_t digest_payload = read_be64(digest_chunk->data);
    munit_assert_size(digest_payload, ==, digest_chunk->size - CEP_SERIALIZATION_CHUNK_OVERHEAD);
    uint64_t digest_id = read_be64(digest_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(digest_id), ==, CEP_CHUNK_CLASS_CONTROL);
    munit_assert_uint16(cep_serialization_chunk_transaction(digest_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(digest_id), ==, 4);

    const uint8_t* digest_bytes = digest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint16_t digest_algo = read_be16(digest_bytes);
    uint16_t digest_flags = read_be16(digest_bytes + sizeof(uint16_t));
    uint64_t digest_beat = read_be64(digest_bytes + sizeof(uint16_t) * 2u);
    uint64_t digest_value = read_be64(digest_bytes + sizeof(uint16_t) * 2u + sizeof(uint64_t));
    (void)digest_beat;
    munit_assert_uint16(digest_algo, ==, 0x0001u);
    munit_assert_uint16(digest_flags, ==, 0u);

    uint64_t expected_digest = 0u;
    for (size_t idx = 1; idx < 4; ++idx) {
        const SerializationChunk* chunk = &capture.chunks[idx];
        uint64_t chunk_id = read_be64(chunk->data + sizeof(uint64_t));
        uint16_t chunk_class = cep_serialization_chunk_class(chunk_id);
        if (chunk_class == CEP_CHUNK_CLASS_CONTROL)
            continue;
        const uint8_t* chunk_payload = chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
        size_t chunk_payload_size = chunk->size - CEP_SERIALIZATION_CHUNK_OVERHEAD;
        expected_digest = serialization_digest_mix(expected_digest, chunk_id, chunk_payload, chunk_payload_size);
    }
    munit_assert_uint64(digest_value, ==, expected_digest);

    cep_cell_system_initiate();

    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);

    munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[0].data, capture.chunks[0].size));
    munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[1].data, capture.chunks[1].size));
    munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[2].data, capture.chunks[2].size));
    munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[3].data, capture.chunks[3].size));

    cepDT expected_name = cep_dt_make(expected_domain, expected_tag);
    munit_assert_null(cep_cell_find_by_name(cep_root(), &expected_name));
    munit_assert_true(cep_serialization_reader_pending(reader));
    munit_assert_true(cep_serialization_reader_commit(reader));

    cepCell* recovered = cep_cell_find_by_name(cep_root(), &expected_name);
    munit_assert_not_null(recovered);
    cepData* recovered_data = recovered->data;
    munit_assert_not_null(recovered_data);
    munit_assert_uint64(recovered_data->dt.domain, ==, CEP_DTAW("CEP", "value")->domain);
    munit_assert_uint64(recovered_data->dt.tag, ==, CEP_DTAW("CEP", "value")->tag);
    munit_assert_uint64(recovered_data->size, ==, sizeof payload - 1u);
    munit_assert_int(memcmp(recovered_data->value, payload, sizeof payload - 1u), ==, 0);

    cep_serialization_reader_reset(reader);
    munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[0].data, capture.chunks[0].size));
    munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[1].data, capture.chunks[1].size));
    munit_assert_false(cep_serialization_reader_ingest(reader, capture.chunks[1].data, capture.chunks[1].size));
    munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[0].data, capture.chunks[0].size));
    for (size_t i = 1; i < capture.count; ++i)
        munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[i].data, capture.chunks[i].size));
    munit_assert_true(cep_serialization_reader_commit(reader));

    cep_serialization_reader_reset(reader);
    cep_serialization_reader_destroy(reader);
    cep_cell_system_shutdown();

    serialization_dump_trace(&capture, "unit_serialization_cell.bin");
    for (size_t i = 0; i < capture.count; ++i)
        cep_free(capture.chunks[i].data);
    cep_cell_finalize_hard(&cell);

    return MUNIT_OK;
}


MunitResult test_serialization_proxy(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    cepDT handle_name = *CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("proxy_hdl"));
    cepDT stream_name = *CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("proxy_str"));

    /* Handle proxy emit */
    ProxyTestLibraryContext handle_emit_ctx = {0};
    cepCell handle_library;
    CEP_0(&handle_library);
    cep_library_initialize(&handle_library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_test_library_ops,
                           &handle_emit_ctx);

    static const uint8_t handle_bytes[] = {0xBA, 0xAD, 0xF0, 0x0D};
    cepCell* handle_resource = proxy_test_make_resource(handle_bytes, sizeof handle_bytes);

    cepCell proxy_handle;
    CEP_0(&proxy_handle);
    cep_proxy_initialize_handle(&proxy_handle, &handle_name, handle_resource, &handle_library);

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(&proxy_handle,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >=, 5u);

    const SerializationChunk* manifest_chunk = &capture.chunks[1];
    const uint8_t* manifest_payload = manifest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(manifest_payload[0], ==, 0x01u);
    munit_assert_uint8(manifest_payload[4], ==, CEP_TYPE_PROXY);

    /* Successful ingest with matching adapter */
    cep_cell_system_initiate();
    ProxyTestLibraryContext handle_import_ctx = {0};
    cepCell handle_import_library;
    CEP_0(&handle_import_library);
    cep_library_initialize(&handle_import_library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_test_library_ops,
                           &handle_import_ctx);

    cepCell placeholder_handle;
    CEP_0(&placeholder_handle);
    cep_proxy_initialize_handle(&placeholder_handle, &handle_name, NULL, &handle_import_library);
    munit_assert_not_null(cep_cell_add(cep_root(), 0, &placeholder_handle));

    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        if (!cep_serialization_reader_ingest(reader, capture.chunks[i].data, capture.chunks[i].size)) {
            munit_errorf("manifest fingerprint ingest failed at chunk=%zu size=%zu", i, capture.chunks[i].size);
        }
    }
    munit_assert_true(cep_serialization_reader_commit(reader));

    cepCell* recovered_handle = cep_cell_find_by_name(cep_root(), &handle_name);
    munit_assert_not_null(recovered_handle);
    munit_assert_true(cep_cell_is_proxy(recovered_handle));
    munit_assert_not_null(handle_import_ctx.last_restored_handle);
    munit_assert_size(handle_import_ctx.handle_retains, ==, 1);
    munit_assert_size(handle_import_ctx.handle_releases, ==, 0);

    cepCell* restored_handle = cep_link_pull(handle_import_ctx.last_restored_handle);
    munit_assert_not_null(restored_handle);
    munit_assert_true(cep_cell_is_normal(restored_handle));
    munit_assert_not_null(restored_handle->data);
    munit_assert_size(restored_handle->data->size, ==, sizeof handle_bytes);
    munit_assert_memory_equal(sizeof handle_bytes, restored_handle->data->value, handle_bytes);

    cep_serialization_reader_destroy(reader);
    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&handle_import_library);

    /* Fails when proxy placeholder is missing */
    cep_cell_system_initiate();
    ProxyTestLibraryContext handle_fail_ctx = {0};
    cepCell handle_fail_library;
    CEP_0(&handle_fail_library);
    cep_library_initialize(&handle_fail_library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_test_library_ops,
                           &handle_fail_ctx);

    cepSerializationReader* reader_fail = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader_fail);
    for (size_t i = 0; i < capture.count; ++i)
        munit_assert_true(cep_serialization_reader_ingest(reader_fail, capture.chunks[i].data, capture.chunks[i].size));
    munit_assert_true(cep_serialization_reader_pending(reader_fail));
    munit_assert_false(cep_serialization_reader_commit(reader_fail));
    cep_serialization_reader_destroy(reader_fail);
    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&handle_fail_library);

    serialization_capture_clear(&capture);
    cep_cell_finalize_hard(&proxy_handle);
    cep_cell_finalize_hard(&handle_library);

    /* Stream proxy emit */
    ProxyTestLibraryContext stream_emit_ctx = {0};
    cepCell stream_library;
    CEP_0(&stream_library);
    cep_library_initialize(&stream_library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_test_library_ops,
                           &stream_emit_ctx);

    static const uint8_t stream_bytes[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    cepCell* stream_resource = proxy_test_make_resource(stream_bytes, sizeof stream_bytes);

    cepCell proxy_stream;
    CEP_0(&proxy_stream);
    cep_proxy_initialize_stream(&proxy_stream, &stream_name, stream_resource, &stream_library);

    SerializationCapture stream_capture = {0};
    munit_assert_true(cep_serialization_emit_cell(&proxy_stream,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &stream_capture,
                                                  0));
    munit_assert_size(stream_capture.count, >=, 5u);

    const uint8_t* stream_manifest = stream_capture.chunks[1].data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(stream_manifest[0], ==, 0x01u);
    munit_assert_uint8(stream_manifest[4], ==, CEP_TYPE_PROXY);

    /* Successful ingest for stream proxy */
    cep_cell_system_initiate();
    ProxyTestLibraryContext stream_import_ctx = {0};
    cepCell stream_import_library;
    CEP_0(&stream_import_library);
    cep_library_initialize(&stream_import_library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_test_library_ops,
                           &stream_import_ctx);

    cepCell placeholder_stream;
    CEP_0(&placeholder_stream);
    cep_proxy_initialize_stream(&placeholder_stream, &stream_name, NULL, &stream_import_library);
    munit_assert_not_null(cep_cell_add(cep_root(), 0, &placeholder_stream));

    cepSerializationReader* stream_reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(stream_reader);
    for (size_t i = 0; i < stream_capture.count; ++i)
        munit_assert_true(cep_serialization_reader_ingest(stream_reader, stream_capture.chunks[i].data, stream_capture.chunks[i].size));
    munit_assert_true(cep_serialization_reader_commit(stream_reader));

    cepCell* recovered_stream = cep_cell_find_by_name(cep_root(), &stream_name);
    munit_assert_not_null(recovered_stream);
    munit_assert_true(cep_cell_is_proxy(recovered_stream));
    munit_assert_not_null(stream_import_ctx.last_restored_stream);

    cepCell* restored_stream = cep_link_pull(stream_import_ctx.last_restored_stream);
    munit_assert_not_null(restored_stream);
    munit_assert_true(cep_cell_is_normal(restored_stream));
    munit_assert_not_null(restored_stream->data);
    munit_assert_size(restored_stream->data->size, ==, sizeof stream_bytes);
    munit_assert_memory_equal(sizeof stream_bytes, restored_stream->data->value, stream_bytes);

    cep_serialization_reader_destroy(stream_reader);
    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&stream_import_library);

    /* Failure path for stream proxies without placeholders */
    cep_cell_system_initiate();
    ProxyTestLibraryContext stream_fail_ctx = {0};
    cepCell stream_fail_library;
    CEP_0(&stream_fail_library);
    cep_library_initialize(&stream_fail_library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_test_library_ops,
                           &stream_fail_ctx);

    cepSerializationReader* stream_fail_reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(stream_fail_reader);
    for (size_t i = 0; i < stream_capture.count; ++i)
        munit_assert_true(cep_serialization_reader_ingest(stream_fail_reader, stream_capture.chunks[i].data, stream_capture.chunks[i].size));
    munit_assert_true(cep_serialization_reader_pending(stream_fail_reader));
    munit_assert_false(cep_serialization_reader_commit(stream_fail_reader));
    cep_serialization_reader_destroy(stream_fail_reader);
    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&stream_fail_library);

    serialization_capture_clear(&stream_capture);
    cep_cell_finalize_hard(&proxy_stream);
    cep_cell_finalize_hard(&stream_library);

    return MUNIT_OK;
}

MunitResult test_serialization_proxy_release_single(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    ReleaseCounterLibraryCtx ctx = {
        .handle_releases = 0u,
        .count_releases = true,
        .next_restore = NULL,
    };

    cepCell library = {0};
    CEP_0(&library);
    cep_library_initialize(&library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("rel_probe")),
                           &release_counter_library_ops,
                           &ctx);

    cepDT handle_name = *CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("rel_target"));
    cepCell proxy_handle = {0};
    CEP_0(&proxy_handle);
    cep_proxy_initialize_handle(&proxy_handle, &handle_name, NULL, &library);

    cepProxySnapshot snapshot = {0};
    cepCell* resource_initial = proxy_test_make_resource((const uint8_t*)"old", 3u);
    cepCell* resource_replacement = proxy_test_make_resource((const uint8_t*)"new", 3u);

    ctx.next_restore = resource_initial;
    munit_assert_true(cep_proxy_restore(&proxy_handle, &snapshot));
    munit_assert_size(ctx.handle_releases, ==, 0u);

    munit_assert_not_null(resource_initial->data);
    cep_data_del(resource_initial->data);
    resource_initial->data = NULL;
    munit_assert_size(ctx.handle_releases, ==, 0u);

    ctx.next_restore = resource_replacement;
    munit_assert_true(cep_proxy_restore(&proxy_handle, &snapshot));
    munit_assert_size(ctx.handle_releases, ==, 1u);

    ctx.count_releases = false;

    if (resource_replacement->data) {
        cep_data_del(resource_replacement->data);
        resource_replacement->data = NULL;
    }

    cep_cell_finalize_hard(&proxy_handle);
    cep_cell_finalize_hard(&library);

    if (resource_initial) {
        cep_cell_finalize_hard(resource_initial);
        cep_free(resource_initial);
    }
    if (resource_replacement) {
        cep_cell_finalize_hard(resource_replacement);
        cep_free(resource_replacement);
    }

    return MUNIT_OK;
}

MunitResult test_serialization_manifest_history(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepDT parent_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("hist_parent"));
    cepDT child_type = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("hist_kind"));
    cepCell* parent = cep_dict_add_dictionary(cep_root(), &parent_name, &child_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepDT child_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("hist_child"));
    cepCell* child = cep_dict_add_empty(parent, &child_name);
    munit_assert_not_null(child);

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(parent,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >=, 7);

    const SerializationChunk* header_chunk = &capture.chunks[0];
    cepSerializationHeader parsed = {0};
    munit_assert_true(cep_serialization_header_read(header_chunk->data,
                                                    header_chunk->size,
                                                    &parsed));
    munit_assert_true((parsed.capabilities & CEP_SERIALIZATION_CAP_MANIFEST_DELTAS) != 0u);
    munit_assert_true((parsed.capabilities & CEP_SERIALIZATION_CAP_SPLIT_DESCRIPTORS) != 0u);

    const SerializationChunk* manifest_chunk = &capture.chunks[1];
    const uint8_t* manifest_payload = manifest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(manifest_payload[0], ==, 0x01u);
    uint8_t manifest_base_flags = manifest_payload[3];
    munit_assert_true((manifest_base_flags & SERIAL_BASE_FLAG_CHILDREN_SPLIT) != 0u);
    uint16_t manifest_children = read_be16(manifest_payload + 7u);
    munit_assert_uint16(manifest_children, ==, 1u);
    const SerializationChunk* descriptor_chunk = serialization_find_chunk(&capture, SERIAL_RECORD_MANIFEST_CHILDREN);
    munit_assert_not_null(descriptor_chunk);
    uint64_t descriptor_id = read_be64(descriptor_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(descriptor_id), ==, CEP_CHUNK_CLASS_STRUCTURE);
    munit_assert_uint32(cep_serialization_chunk_transaction(descriptor_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(descriptor_id), ==, 2);
    const uint8_t* descriptor_payload = descriptor_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint8_t* manifest_child = serialization_manifest_child((uint8_t*)descriptor_payload, 0u);
    munit_assert_not_null(manifest_child);
    uint64_t manifest_child_domain = read_be64(manifest_child);
    uint64_t manifest_child_tag = read_be64(manifest_child + sizeof(uint64_t));
    uint8_t manifest_child_glob = manifest_child[sizeof(uint64_t) * 2u];
    uint8_t manifest_child_flags = manifest_child[sizeof(uint64_t) * 2u + 1u];
    uint16_t manifest_child_position = read_be16(manifest_child + sizeof(uint64_t) * 2u + 2u);
    munit_assert_uint64(manifest_child_domain, ==, child_name.domain);
    munit_assert_uint64(manifest_child_tag, ==, child_name.tag);
    munit_assert_uint8(manifest_child_glob, ==, child_name.glob ? 1u : 0u);
    munit_assert_uint16(manifest_child_position, ==, 0u);
    munit_assert_false((manifest_child_flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u);
    munit_assert_false((manifest_child_flags & SERIAL_CHILD_FLAG_VEILED) != 0u);
    munit_assert_false((manifest_child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u);

    const SerializationChunk* delta_chunk = serialization_find_chunk(&capture, SERIAL_RECORD_MANIFEST_DELTA);
    munit_assert_not_null(delta_chunk);
    uint64_t delta_id = read_be64(delta_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(delta_id), ==, CEP_CHUNK_CLASS_STRUCTURE);
    munit_assert_uint32(cep_serialization_chunk_transaction(delta_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(delta_id), ==, 3);

    const uint8_t* delta_payload = delta_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(delta_payload[0], ==, 0x02u);
    uint8_t delta_flags = delta_payload[1];
    munit_assert_true((delta_flags & 0x01u) != 0u);

    uint8_t* child_descriptor = serialization_delta_child((uint8_t*)delta_payload);
    munit_assert_not_null(child_descriptor);
    uint64_t child_domain = read_be64(child_descriptor);
    uint64_t child_tag = read_be64(child_descriptor + sizeof(uint64_t));
    uint8_t child_glob = child_descriptor[sizeof(uint64_t) * 2u];
    uint8_t child_flags = child_descriptor[sizeof(uint64_t) * 2u + 1u];
    munit_assert_uint64(child_domain, ==, child_name.domain);
    munit_assert_uint64(child_tag, ==, child_name.tag);
    munit_assert_uint8(child_glob, ==, child_name.glob ? 1u : 0u);
    munit_assert_false((child_flags & SERIAL_CHILD_FLAG_TOMBSTONE) != 0u);
    munit_assert_false((child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u);

    cep_cell_system_shutdown();

    cep_cell_system_initiate();
    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        if (!cep_serialization_reader_ingest(reader, capture.chunks[i].data, capture.chunks[i].size)) {
            munit_errorf("manifest delta fingerprint ingest failed at chunk=%zu size=%zu", i, capture.chunks[i].size);
        }
    }
    munit_assert_true(cep_serialization_reader_commit(reader));

    (void)parent_name;
    (void)child_name;

    cep_serialization_reader_destroy(reader);
    cep_cell_system_shutdown();

    serialization_capture_clear(&capture);

    return MUNIT_OK;
}

MunitResult test_serialization_manifest_split_child_capacity(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepDT parent_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("spl_parent"));
    cepDT child_type = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("spl_child"));
    cepCell* parent = cep_dict_add_dictionary(cep_root(), &parent_name, &child_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepDT child_names[6];
    child_names[0] = *CEP_DTS(CEP_ACRO("APP"), CEP_ACRO("SPLCA"));
    child_names[1] = *CEP_DTS(CEP_ACRO("APP"), CEP_ACRO("SPLCB"));
    child_names[2] = *CEP_DTS(CEP_ACRO("APP"), CEP_ACRO("SPLCC"));
    child_names[3] = *CEP_DTS(CEP_ACRO("APP"), CEP_ACRO("SPLCD"));
    child_names[4] = *CEP_DTS(CEP_ACRO("APP"), CEP_ACRO("SPLCE"));
    child_names[5] = *CEP_DTS(CEP_ACRO("APP"), CEP_ACRO("SPLCF"));

    for (size_t i = 0; i < cep_lengthof(child_names); ++i) {
        cepCell* node = cep_dict_add_dictionary(parent, &child_names[i], &child_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(node);
        (void)node;
    }

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(parent,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >, 2u);

    bool base_seen = false;
    bool descriptor_seen = false;
    bool descriptor_before_base = false;
    size_t base_chunk_index = 0u;
    uint16_t descriptor_total = 0u;
    for (size_t i = 0; i < capture.count; ++i) {
        SerializationChunk* chunk = &capture.chunks[i];
        if (!chunk->data || chunk->size < CEP_SERIALIZATION_CHUNK_OVERHEAD + 1u)
            continue;
        uint64_t payload_sz = read_be64(chunk->data);
        if (payload_sz == 0u || chunk->size < CEP_SERIALIZATION_CHUNK_OVERHEAD + payload_sz)
            continue;
        uint64_t chunk_id = read_be64(chunk->data + sizeof(uint64_t));
        if (cep_serialization_chunk_class(chunk_id) != CEP_CHUNK_CLASS_STRUCTURE)
            continue;
        uint8_t* payload = chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
        uint8_t record_type = payload[0];
        if (record_type == SERIAL_RECORD_MANIFEST_BASE) {
            uint8_t base_flags = payload[3];
            uint16_t child_count = read_be16(payload + 7u);
            uint16_t span_count = read_be16(payload + 9u);
            if (child_count != cep_lengthof(child_names))
                continue;
            base_seen = true;
            base_chunk_index = i;
            munit_assert_size(child_count, ==, cep_lengthof(child_names));
            munit_assert_true((base_flags & SERIAL_BASE_FLAG_CHILDREN_SPLIT) != 0u);
            munit_assert_size((size_t)span_count, >, 0u);
        } else if (record_type == SERIAL_RECORD_MANIFEST_CHILDREN) {
            uint16_t descriptor_offset = read_be16(payload + 4u);
            uint16_t descriptor_count = read_be16(payload + 6u);
            if (!descriptor_count)
                continue;
            if (descriptor_offset >= cep_lengthof(child_names))
                continue;
            if (!base_seen)
                descriptor_before_base = true;
            descriptor_seen = true;
            munit_assert_true(base_seen);
            munit_assert_size(i, >, base_chunk_index);
            munit_assert_size(descriptor_offset + descriptor_count, <=, cep_lengthof(child_names));
            descriptor_total = (uint16_t)(descriptor_total + descriptor_count);
        }
    }
    munit_assert_true(base_seen);
    munit_assert_true(descriptor_seen);
    munit_assert_false(descriptor_before_base);
    munit_assert_size(descriptor_total, ==, cep_lengthof(child_names));

    cep_cell_system_shutdown();

    cep_cell_system_initiate();
    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }
    munit_assert_true(cep_serialization_reader_commit(reader));

    cepCell* replay_parent = cep_cell_find_by_name_all(cep_root(), &parent_name);
    if (!replay_parent)
        replay_parent = serialization_find_cell_recursive(cep_root(), &parent_name);
    munit_assert_not_null(replay_parent);
    replay_parent = cep_cell_resolve(replay_parent);
    munit_assert_not_null(replay_parent);
    munit_assert_size(cep_cell_children(replay_parent), ==, cep_lengthof(child_names));

    cep_serialization_reader_destroy(reader);
    cep_cell_system_shutdown();
    serialization_capture_clear(&capture);

    return MUNIT_OK;
}

MunitResult test_serialization_manifest_positional_add(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepDT parent_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("pos_parent"));
    cepDT list_type = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("pos_kind"));
    cepCell* parent = cep_dict_add_list(cep_root(),
                                       &parent_name,
                                       &list_type,
                                       CEP_STORAGE_LINKED_LIST);
    munit_assert_not_null(parent);

    cepDT child_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("pos_entry"));
    for (uint16_t idx = 0; idx < 3u; ++idx) {
        cepCell* child = cep_cell_add_empty(parent, &child_name, cep_cell_children(parent));
        munit_assert_not_null(child);
    }

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(parent,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >=, 5u);

    cep_cell_system_shutdown();
    cep_cell_system_initiate();

    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }
    munit_assert_true(cep_serialization_reader_commit(reader));

    cepCell* replay_parent = serialization_find_descendant(cep_root(), &parent_name);
    munit_assert_not_null(replay_parent);
    replay_parent = cep_cell_resolve(replay_parent);
    munit_assert_not_null(replay_parent);
    munit_assert_size(cep_cell_children(replay_parent), ==, 3u);
    for (size_t pos = 0; pos < 3u; ++pos) {
        cepCell* node = cep_cell_find_by_position(replay_parent, pos);
        munit_assert_not_null(node);
        node = cep_link_pull(node);
        munit_assert_not_null(node);
        const cepDT* restored = cep_cell_get_name(node);
        munit_assert_not_null(restored);
        munit_assert_uint64(restored->domain, ==, child_name.domain);
        munit_assert_uint64(restored->tag, ==, child_name.tag);
        munit_assert_uint8(restored->glob, ==, child_name.glob);
    }

    cep_serialization_reader_destroy(reader);
    cep_cell_system_shutdown();
    serialization_capture_clear(&capture);
    return MUNIT_OK;
}

MunitResult test_serialization_manifest_fingerprint_corruption(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepDT parent_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("fp_parent"));
    cepDT child_type = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("fp_kind"));
    cepCell* parent = cep_dict_add_dictionary(cep_root(), &parent_name, &child_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);
    cepDT child_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("fp_child"));
    const char payload[] = "fingerprint-data";
    cepCell* child = cep_dict_add_value(parent,
                                        &child_name,
                                        CEP_DTAW("APP", "val"),
                                        (void*)payload,
                                        sizeof(payload) - 1u,
                                        sizeof(payload) - 1u);
    munit_assert_not_null(child);

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(parent,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >=, 5u);

    SerializationChunk* digest_chunk = &capture.chunks[capture.count - 1u];
    uint8_t* digest_payload = digest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint64_t existing_digest = read_be64(digest_payload + sizeof(uint16_t) * 2u + sizeof(uint64_t));
    uint64_t baseline_digest = serialization_recompute_digest(&capture);
    uint64_t debug_digest = 0u;
    for (size_t i = 1; i + 1 < capture.count; ++i) {
        SerializationChunk* chunk = &capture.chunks[i];
        uint64_t payload_sz = read_be64(chunk->data);
        uint64_t chunk_id = read_be64(chunk->data + sizeof(uint64_t));
        uint16_t chunk_class = cep_serialization_chunk_class(chunk_id);
        if (chunk_class == CEP_CHUNK_CLASS_CONTROL)
            continue;
        const uint8_t* payload = chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
        debug_digest = serialization_digest_mix(debug_digest, chunk_id, payload, (size_t)payload_sz);
    }
    munit_assert_uint64(baseline_digest, ==, existing_digest);

    SerializationChunk* descriptor_chunk = (SerializationChunk*)serialization_find_chunk(&capture, SERIAL_RECORD_MANIFEST_CHILDREN);
    munit_assert_not_null(descriptor_chunk);
    uint8_t* descriptor_payload = descriptor_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint8_t* manifest_child = serialization_manifest_child(descriptor_payload, 0u);
    munit_assert_not_null(manifest_child);
    uint8_t manifest_child_flags = manifest_child[sizeof(uint64_t) * 2u + 1u];
    munit_assert_true((manifest_child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u);
    uint8_t* manifest_fingerprint = manifest_child + sizeof(uint64_t) * 2u + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint64_t original_fp = read_be64(manifest_fingerprint);
    write_be64(manifest_fingerprint, original_fp ^ UINT64_C(0x1));

    const SerializationChunk* delta_chunk = serialization_find_chunk(&capture, SERIAL_RECORD_MANIFEST_DELTA);
    munit_assert_not_null(delta_chunk);
    uint8_t* delta_payload = (uint8_t*)delta_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint8_t* delta_child = serialization_delta_child(delta_payload);
    munit_assert_not_null(delta_child);
    uint8_t delta_child_flags = delta_child[sizeof(uint64_t) * 2u + 1u];
    if ((delta_child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u) {
        uint8_t* delta_fp_ptr = delta_child + sizeof(uint64_t) * 2u + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
        uint64_t delta_fp = read_be64(delta_fp_ptr);
        write_be64(delta_fp_ptr, delta_fp ^ UINT64_C(0x5));
    }

    uint64_t updated_digest = serialization_recompute_digest(&capture);
    write_be64(digest_payload + sizeof(uint16_t) * 2u + sizeof(uint64_t), updated_digest);

    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        if (!cep_serialization_reader_ingest(reader, capture.chunks[i].data, capture.chunks[i].size)) {
            munit_errorf("manifest fingerprint ingest failed at chunk=%zu size=%zu", i, capture.chunks[i].size);
        }
    }
    munit_assert_true(cep_serialization_reader_pending(reader));
    bool commit_ok = cep_serialization_reader_commit(reader);
    munit_assert_false(commit_ok);
    cep_serialization_reader_destroy(reader);

    cep_cell_system_shutdown();

    serialization_dump_trace(&capture, "manifest_fingerprint_corrupt.bin");
    serialization_capture_clear(&capture);
    return MUNIT_OK;
}

MunitResult test_serialization_manifest_delta_fingerprint_corruption(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepDT parent_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("del_parent"));
    cepDT child_type = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("del_kind"));
    cepCell* parent = cep_dict_add_dictionary(cep_root(), &parent_name, &child_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(parent);

    cepDT child_name = *CEP_DTS(CEP_ACRO("APP"), CEP_WORD("del_child"));
    const char payload[] = "delta-fingerprint";
    cepCell* child = cep_dict_add_value(parent,
                                        &child_name,
                                        CEP_DTAW("APP", "val"),
                                        (void*)payload,
                                        sizeof(payload) - 1u,
                                        sizeof(payload) - 1u);
    munit_assert_not_null(child);

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(parent,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >=, 5u);

    SerializationChunk* delta_chunk = (SerializationChunk*)serialization_find_chunk(&capture, SERIAL_RECORD_MANIFEST_DELTA);
    munit_assert_not_null(delta_chunk);
    uint8_t* delta_payload = delta_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(delta_payload[0], ==, 0x02u);
    uint8_t* delta_child = serialization_delta_child(delta_payload);
    munit_assert_not_null(delta_child);
    uint8_t delta_child_flags = delta_child[sizeof(uint64_t) * 2u + 1u];
    munit_assert_true((delta_child_flags & SERIAL_CHILD_FLAG_FINGERPRINT) != 0u);
    uint8_t* delta_fp_ptr = delta_child + sizeof(uint64_t) * 2u + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint64_t original_fp = read_be64(delta_fp_ptr);
    write_be64(delta_fp_ptr, original_fp ^ UINT64_C(0x2));

    uint64_t updated_digest = serialization_recompute_digest(&capture);
    SerializationChunk* digest_chunk = &capture.chunks[capture.count - 1u];
    uint8_t* digest_payload = digest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    write_be64(digest_payload + sizeof(uint16_t) * 2u + sizeof(uint64_t), updated_digest);

    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i)
        munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[i].data, capture.chunks[i].size));
    munit_assert_true(cep_serialization_reader_pending(reader));
    munit_assert_false(cep_serialization_reader_commit(reader));
    cep_serialization_reader_destroy(reader);

    cep_cell_system_shutdown();
    serialization_dump_trace(&capture, "manifest_delta_fingerprint_corrupt.bin");
    serialization_capture_clear(&capture);
    return MUNIT_OK;
}

MunitResult test_serialization_header_capability_mismatch(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepCell cell = {0};
    CEP_0(&cell);
    static const char cap_payload[] = "cap-test";
    const size_t cap_payload_size = sizeof cap_payload - 1u;
    cep_cell_initialize_value(&cell,
                              CEP_DTS(CEP_ACRO("APP"), CEP_WORD("cap_cell")),
                              CEP_DTAW("APP", "payload"),
                              (void*)cap_payload,
                              cap_payload_size,
                              cap_payload_size);

    SerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(&cell,
                                                  NULL,
                                                  serialization_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >=, 5u);

    SerializationChunk* header_chunk = &capture.chunks[0];
    cepSerializationHeader parsed = {0};
    munit_assert_true(cep_serialization_header_read(header_chunk->data,
                                                    header_chunk->size,
                                                    &parsed));
    parsed.flags &= (uint8_t)~CEP_SERIALIZATION_FLAG_CAPABILITIES;
    parsed.capabilities_present = false;
    parsed.capabilities = 0u;

    size_t mutated_size = cep_serialization_header_chunk_size(&parsed);
    uint8_t* mutated_header = cep_malloc(mutated_size);
    size_t mutated_written = 0u;
    munit_assert_true(cep_serialization_header_write(&parsed, mutated_header, mutated_size, &mutated_written));
    cep_free(header_chunk->data);
    header_chunk->data = mutated_header;
    header_chunk->size = mutated_written;

    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    bool ingest_failed = false;
    for (size_t i = 0; i < capture.count; ++i) {
        if (!cep_serialization_reader_ingest(reader, capture.chunks[i].data, capture.chunks[i].size)) {
            ingest_failed = true;
            break;
        }
    }
    if (!ingest_failed && cep_serialization_reader_pending(reader))
        munit_assert_false(cep_serialization_reader_commit(reader));
    else
        munit_assert_true(ingest_failed);
    cep_serialization_reader_destroy(reader);

    serialization_dump_trace(&capture, "header_capability_mismatch.bin");
    serialization_capture_clear(&capture);
    cep_cell_finalize_hard(&cell);
    cep_cell_system_shutdown();
    return MUNIT_OK;
}
