/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "test.h"

#include "cep_serialization.h"
#include "cep_cell.h"

#include <string.h>


typedef struct {
    uint8_t* data;
    size_t   size;
} SerializationChunk;

typedef struct {
    SerializationChunk chunks[8];
    size_t             count;
} SerializationCapture;

static bool serialization_capture_sink(void* ctx, const uint8_t* chunk, size_t size) {
    SerializationCapture* capture = ctx;
    if (!capture || !chunk || !size)
        return false;
    if (capture->count >= sizeof capture->chunks / sizeof capture->chunks[0])
        return false;

    uint8_t* copy = cep_malloc(size);
    memcpy(copy, chunk, size);

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

/* Validate that a single normal cell turns into the expected trio of chunks:
   the control/header frame with the CEP magic, the structural manifest with the
   cell path, and the inline data descriptor that carries both metadata and the
   payload bytes. */
/* Covers serialization framing and payload replay semantics. */

MunitResult test_serialization(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

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

    munit_assert_size(capture.count, ==, 4);

    const SerializationChunk* header_chunk = &capture.chunks[0];
    cepSerializationHeader parsed = {0};
    munit_assert_true(cep_serialization_header_read(header_chunk->data,
                                                    header_chunk->size,
                                                    &parsed));
    munit_assert_uint64(parsed.magic, ==, CEP_SERIALIZATION_MAGIC);
    munit_assert_uint16(parsed.version, ==, CEP_SERIALIZATION_VERSION);
    munit_assert_uint8(parsed.byte_order, ==, CEP_SERIAL_ENDIAN_BIG);

    const SerializationChunk* manifest_chunk = &capture.chunks[1];
    uint64_t manifest_payload = read_be64(manifest_chunk->data);
    munit_assert_size(manifest_chunk->size, ==, manifest_payload + CEP_SERIALIZATION_CHUNK_OVERHEAD);
    uint64_t manifest_id = read_be64(manifest_chunk->data + sizeof(uint64_t));
    munit_assert_uint16(cep_serialization_chunk_class(manifest_id), ==, CEP_CHUNK_CLASS_STRUCTURE);
    munit_assert_uint32(cep_serialization_chunk_transaction(manifest_id), ==, 1);
    munit_assert_uint16(cep_serialization_chunk_sequence(manifest_id), ==, 1);

    const uint8_t* manifest_payload_bytes = manifest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint16_t segment_count = read_be16(manifest_payload_bytes);
    munit_assert_uint16(segment_count, ==, 2);
    uint8_t cell_type = manifest_payload_bytes[2];
    uint8_t manifest_flags = manifest_payload_bytes[3];
    munit_assert_uint8(cell_type, ==, CEP_TYPE_NORMAL);
    munit_assert_true((manifest_flags & 0x08u) != 0);

    const uint8_t* path_bytes = manifest_payload_bytes + 6;
    uint64_t domain = read_be64(path_bytes);
    uint64_t tag = read_be64(path_bytes + 8);
    uint8_t glob_flag = path_bytes[16];
    munit_assert_uint64(domain, ==, expected_domain);
    munit_assert_uint64(tag, ==, expected_tag);
    munit_assert_uint8(glob_flag, ==, 0);

    const uint8_t* data_bytes = path_bytes + 17;
    uint64_t data_domain = read_be64(data_bytes);
    uint64_t data_tag = read_be64(data_bytes + 8);
    uint8_t data_glob = data_bytes[16];
    munit_assert_uint64(data_domain, ==, data->dt.domain);
    munit_assert_uint64(data_tag, ==, data->dt.tag);
    munit_assert_uint8(data_glob, ==, 0);

    const SerializationChunk* data_chunk = &capture.chunks[2];
    const SerializationChunk* control_chunk = &capture.chunks[3];
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
    uint16_t datatype = read_be16(descriptor);
    uint16_t flags = read_be16(descriptor + 2);
    uint32_t inline_len = read_be32(descriptor + 4);
    uint64_t total_len = read_be64(descriptor + 8);
    uint64_t hash = read_be64(descriptor + 16);
    uint64_t dt_domain = read_be64(descriptor + 24);
    uint64_t dt_tag = read_be64(descriptor + 32);
    uint8_t dt_glob = descriptor[40];
    const uint8_t* inline_data = descriptor + 41;

    munit_assert_uint16(datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_uint16(flags, ==, 0);
    munit_assert_uint32(inline_len, ==, sizeof payload - 1u);
    munit_assert_uint64(total_len, ==, sizeof payload - 1u);
    munit_assert_uint64(hash, ==, expected_hash);
    munit_assert_uint64(dt_domain, ==, CEP_DTAW("CEP", "value")->domain);
    munit_assert_uint64(dt_tag, ==, CEP_DTAW("CEP", "value")->tag);
    munit_assert_uint8(dt_glob, ==, 0);
    munit_assert_int(memcmp(inline_data, payload, sizeof payload - 1u), ==, 0);

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
    munit_assert_size(capture.count, ==, 4);

    const SerializationChunk* manifest_chunk = &capture.chunks[1];
    const uint8_t* manifest_payload = manifest_chunk->data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(manifest_payload[2], ==, CEP_TYPE_PROXY);
    munit_assert_true((manifest_payload[3] & 0x20u) != 0);

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
    for (size_t i = 0; i < capture.count; ++i)
        munit_assert_true(cep_serialization_reader_ingest(reader, capture.chunks[i].data, capture.chunks[i].size));
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
    munit_assert_size(stream_capture.count, ==, 4);

    const uint8_t* stream_manifest = stream_capture.chunks[1].data + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    munit_assert_uint8(stream_manifest[2], ==, CEP_TYPE_PROXY);
    munit_assert_true((stream_manifest[3] & 0x20u) != 0);

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
