/*
 *  Serialization fuzzing rebuilds random forests of cells, streams them through
 *  the Layer 0 serializer, and rehydrates the snapshots to prove structure and
 *  payload fidelity survive arbitrary layout and proxy mixes.
 */
/* Randomized serialization fuzz that stresses chunk assembly. */


#include "test.h"
#include "watchdog.h"

#include "cep_serialization.h"
#include "cep_cell.h"

#include <string.h>

#define TEST_TIMEOUT_SECONDS 60u
#define MAX_CAPTURE_CHUNKS   128u

typedef struct {
    TestWatchdog* watchdog;
    cepID         next_tag;
} SerializationFixture;

typedef struct {
    uint8_t* data;
    size_t   size;
} CaptureChunk;

typedef struct {
    CaptureChunk chunks[MAX_CAPTURE_CHUNKS];
    size_t       count;
} CaptureBuffer;

static void capture_reset(CaptureBuffer* capture) {
    for (size_t i = 0; i < capture->count; ++i) {
        cep_free(capture->chunks[i].data);
        capture->chunks[i].data = NULL;
        capture->chunks[i].size = 0u;
    }
    capture->count = 0u;
}

static bool capture_sink(void* context, const uint8_t* chunk, size_t size) {
    CaptureBuffer* capture = context;
    if (!capture || !chunk || !size)
        return false;
    if (capture->count >= MAX_CAPTURE_CHUNKS)
        return false;

    uint8_t* copy = cep_malloc(size);
    memcpy(copy, chunk, size);

    capture->chunks[capture->count].data = copy;
    capture->chunks[capture->count].size = size;
    capture->count++;
    return true;
}

typedef struct {
    unsigned handle_retains;
    unsigned handle_releases;
    cepCell* last_handle;
    cepCell* last_stream;
} ProxyContext;

static cepCell* proxy_make_handle_resource(const uint8_t* bytes, size_t size) {
    cepCell* cell = cep_malloc0(sizeof *cell);
    CEP_0(cell);
    cep_cell_initialize_value(cell,
                              CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")),
                              CEP_DTAW("LIB", "payload"),
                              (void*)bytes,
                              size,
                              size ? size : 1u);
    return cell;
}

static cepCell* proxy_make_stream_resource(const uint8_t* bytes, size_t size) {
    cepCell* cell = cep_malloc0(sizeof *cell);
    CEP_0(cell);
    cep_cell_initialize_value(cell,
                              CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("stream")),
                              CEP_DTAW("LIB", "payload"),
                              (void*)bytes,
                              size,
                              size ? size : 1u);
    return cell;
}

static bool proxy_snapshot_common(cepCell* resource, cepProxySnapshot* snapshot) {
    resource = cep_link_pull(resource);
    if (!resource || !cep_cell_has_data(resource))
        return false;

    const void* payload = cep_cell_data(resource);
    size_t size = resource->data ? resource->data->size : 0u;
    uint8_t* copy = NULL;
    if (payload && size) {
        copy = cep_malloc(size);
        memcpy(copy, payload, size);
    }

    snapshot->payload = copy;
    snapshot->size = size;
    snapshot->flags = copy ? CEP_PROXY_SNAPSHOT_INLINE : 0u;
    snapshot->ticket = NULL;
    return true;
}

static bool proxy_handle_snapshot(const cepLibraryBinding* binding, cepCell* handle, cepProxySnapshot* snapshot) {
    (void)binding;
    return proxy_snapshot_common(handle, snapshot);
}

static bool proxy_stream_snapshot(const cepLibraryBinding* binding, cepCell* stream, cepProxySnapshot* snapshot) {
    (void)binding;
    return proxy_snapshot_common(stream, snapshot);
}

static bool proxy_restore_common(const cepProxySnapshot* snapshot,
                                 cepCell** out_cell,
                                 ProxyContext* ctx,
                                 bool is_stream) {
    if (!snapshot || !out_cell)
        return false;

    cepCell* cell = cep_malloc0(sizeof *cell);
    CEP_0(cell);
    cep_cell_initialize_value(cell,
                              is_stream ? CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("stream"))
                                        : CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")),
                              CEP_DTAW("LIB", "payload"),
                              (void*)snapshot->payload,
                              snapshot->size,
                              snapshot->size ? snapshot->size : 1u);

    if (ctx) {
        if (is_stream)
            ctx->last_stream = cell;
        else
            ctx->last_handle = cell;
    }

    *out_cell = cell;
    return true;
}

static bool proxy_handle_restore(const cepLibraryBinding* binding,
                                 const cepProxySnapshot* snapshot,
                                 cepCell** out_handle) {
    ProxyContext* ctx = binding ? (ProxyContext*)binding->ctx : NULL;
    return proxy_restore_common(snapshot, out_handle, ctx, false);
}

static bool proxy_stream_restore(const cepLibraryBinding* binding,
                                 const cepProxySnapshot* snapshot,
                                 cepCell** out_stream) {
    ProxyContext* ctx = binding ? (ProxyContext*)binding->ctx : NULL;
    return proxy_restore_common(snapshot, out_stream, ctx, true);
}

static bool proxy_handle_retain(const cepLibraryBinding* binding, cepCell* handle) {
    (void)handle;
    ProxyContext* ctx = binding ? (ProxyContext*)binding->ctx : NULL;
    if (ctx)
        ctx->handle_retains++;
    return true;
}

static void proxy_handle_release(const cepLibraryBinding* binding, cepCell* handle) {
    (void)handle;
    ProxyContext* ctx = binding ? (ProxyContext*)binding->ctx : NULL;
    if (ctx)
        ctx->handle_releases++;
}

static const cepLibraryOps proxy_library_ops = {
    .handle_retain   = proxy_handle_retain,
    .handle_release  = proxy_handle_release,
    .handle_snapshot = proxy_handle_snapshot,
    .handle_restore  = proxy_handle_restore,
    .stream_read     = NULL,
    .stream_write    = NULL,
    .stream_expected_hash = NULL,
    .stream_map      = NULL,
    .stream_unmap    = NULL,
    .stream_snapshot = proxy_stream_snapshot,
    .stream_restore  = proxy_stream_restore,
};

/*
 *  Failure stubs let the serializer exercise emit/ingest error propagation
 *  without crafting bespoke external bindings in the test body.
 */
static bool proxy_handle_snapshot_fail(const cepLibraryBinding* binding,
                                       cepCell* handle,
                                       cepProxySnapshot* snapshot) {
    (void)binding;
    (void)handle;
    (void)snapshot;
    return false;
}

static bool proxy_handle_restore_fail(const cepLibraryBinding* binding,
                                      const cepProxySnapshot* snapshot,
                                      cepCell** out_handle) {
    (void)binding;
    (void)snapshot;
    (void)out_handle;
    return false;
}
static cepDT random_child_name(SerializationFixture* fix) {
    if (!fix->next_tag || fix->next_tag > CEP_AUTOID_MAX)
        fix->next_tag = CEP_ID(1);

    cepDT dt = {0};
    dt.domain = (munit_rand_uint32() & 1u) ? CEP_WORD("ser") : CEP_ACRO("SER");
    dt.tag = cep_id_to_numeric(fix->next_tag++);
    return dt;
}

static cepCell* add_random_value_cell(SerializationFixture* fix, cepCell* parent) {
    if (!cep_cell_has_store(parent))
        return NULL;

    cepDT name = random_child_name(fix);
    uint8_t payload[48];
    size_t size = (size_t)munit_rand_int_range(1, 24);
    munit_rand_memory(size, payload);

    cepCell* value = cep_cell_add_value(parent,
                                        &name,
                                        0,
                                        CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("RND")),
                                        payload,
                                        size,
                                        sizeof payload);
    munit_assert_not_null(value);
    munit_assert_not_null(cep_cell_data(value));
    munit_assert_memory_equal(size, payload, cep_cell_data(value));
    return value;
}

static cepCell* add_random_container(SerializationFixture* fix, cepCell* parent, unsigned depth) {
    if (!cep_cell_has_store(parent) || depth == 0u)
        return NULL;

    cepDT name = random_child_name(fix);
    unsigned storage_pick = (unsigned)munit_rand_int_range(0, 3);
    cepCell* container = NULL;
    switch (storage_pick) {
    case 0:
        container = cep_cell_add_dictionary(parent,
                                            &name,
                                            0,
                                            CEP_DTAW("SER", "dict"),
                                            CEP_STORAGE_LINKED_LIST);
        break;
    case 1: {
        size_t capacity = (size_t)munit_rand_int_range(4, 12);
        container = cep_cell_add_dictionary(parent,
                                            &name,
                                            0,
                                            CEP_DTAW("SER", "dict"),
                                            CEP_STORAGE_ARRAY,
                                            capacity);
        break;
    }
    default:
        container = cep_cell_add_dictionary(parent,
                                            &name,
                                            0,
                                            CEP_DTAW("SER", "dict"),
                                            CEP_STORAGE_RED_BLACK_T);
        break;
    }

    munit_assert_not_null(container);

    unsigned branches = (unsigned)munit_rand_int_range(1, depth + 1u);
    for (unsigned i = 0; i < branches; ++i) {
        if (depth > 1u && (munit_rand_uint32() & 1u))
            add_random_container(fix, container, depth - 1u);
        else
            add_random_value_cell(fix, container);
    }
    return container;
}

static void destroy_tree(cepCell* node) {
    if (!node || !cep_cell_has_store(node))
        return;

    while (cep_cell_children(node)) {
        cepCell* child = cep_cell_first(node);
        destroy_tree(child);
        cep_cell_delete_hard(child);
    }
}

static void assert_cells_equal(const cepCell* expected, const cepCell* actual) {
    const cepDT* expected_name = cep_cell_get_name(expected);
    const cepDT* actual_name = cep_cell_get_name(actual);
    munit_assert_int(cep_dt_compare(expected_name, actual_name), ==, 0);

    if (cep_cell_has_data(expected)) {
        munit_assert_true(cep_cell_has_data(actual));
        const cepData* expected_data = expected->data;
        const cepData* actual_data = actual->data;
        munit_assert_size(expected_data->size, ==, actual_data->size);
        const void* expected_bytes = cep_cell_data(expected);
        const void* actual_bytes = cep_cell_data(actual);
        if (expected_bytes && actual_bytes)
            munit_assert_memory_equal(expected_data->size, expected_bytes, actual_bytes);
    } else {
        munit_assert_false(cep_cell_has_data(actual));
    }

    size_t expected_children = cep_cell_children(expected);
    size_t actual_children = cep_cell_children(actual);
    munit_assert_size(actual_children, >=, expected_children);

    cepCell* expected_child = cep_cell_first((cepCell*)expected);
    cepCell* actual_child = cep_cell_first((cepCell*)actual);
    while (expected_child && actual_child) {
        assert_cells_equal(expected_child, actual_child);
        expected_child = cep_cell_next((cepCell*)expected, expected_child);
        actual_child = cep_cell_next((cepCell*)actual, actual_child);
    }
    munit_assert_true(expected_child == NULL);
}

static void run_roundtrip_once(SerializationFixture* fix) {
    cepCell source;
    CEP_0(&source);
    cepCell restored;
    CEP_0(&restored);

    cepDT name = *CEP_DTWW("ser", "root");
    cepDT store = *CEP_DTAW("SER", "children");
    cep_cell_initialize_dictionary(&source, &name, &store, CEP_STORAGE_LINKED_LIST);
    cep_cell_initialize_dictionary(&restored, &name, &store, CEP_STORAGE_LINKED_LIST);

    unsigned depth = (unsigned)munit_rand_int_range(1, 4);
    unsigned branches = (unsigned)munit_rand_int_range(2, 5);
    for (unsigned i = 0; i < branches; ++i) {
        if (munit_rand_uint32() & 1u)
            add_random_container(fix, &source, depth);
        else
            add_random_value_cell(fix, &source);
    }

    CaptureBuffer capture = {0};
    uint8_t metadata[32];
    size_t meta_size = (size_t)munit_rand_int_range(0, 16);
    if (meta_size)
        munit_rand_memory(meta_size, metadata);

    cepSerializationHeader header = {
        .magic = CEP_SERIALIZATION_MAGIC,
        .version = CEP_SERIALIZATION_VERSION,
        .byte_order = CEP_SERIAL_ENDIAN_LITTLE,
        .flags = 0u,
        .metadata_length = (uint32_t)meta_size,
        .metadata = meta_size ? metadata : NULL,
    };

    munit_assert_true(cep_serialization_emit_cell(&source,
                                                  &header,
                                                  capture_sink,
                                                  &capture,
                                                  CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD));

    cepSerializationReader* reader = cep_serialization_reader_create(&restored);
    munit_assert_not_null(reader);

    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }

    munit_assert_true(cep_serialization_reader_commit(reader));
    munit_assert_false(cep_serialization_reader_pending(reader));
    cep_serialization_reader_destroy(reader);

    assert_cells_equal(&source, &restored);

    destroy_tree(&source);
    destroy_tree(&restored);
    cep_cell_finalize_hard(&source);
    cep_cell_finalize_hard(&restored);
    capture_reset(&capture);
    test_watchdog_signal(fix->watchdog);
}

static void exercise_proxy_roundtrip(SerializationFixture* fix) {
    CaptureBuffer capture = {0};
    uint8_t payload[64];
    size_t payload_size = (size_t)munit_rand_int_range(8, 32);
    munit_rand_memory(payload_size, payload);

    ProxyContext emit_ctx = {0};
    cepCell library;
    CEP_0(&library);
    cep_library_initialize(&library,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_library_ops,
                           &emit_ctx);

    cepCell* handle_resource = proxy_make_handle_resource(payload, payload_size);
    cepCell proxy_handle;
    CEP_0(&proxy_handle);
    cep_proxy_initialize_handle(&proxy_handle,
                                CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")),
                                handle_resource,
                                &library);

    munit_assert_true(cep_serialization_emit_cell(&proxy_handle,
                                                  NULL,
                                                  capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >, 0u);

    cep_cell_finalize_hard(&proxy_handle);
    cep_cell_finalize_hard(handle_resource);
    cep_free(handle_resource);
    cep_cell_finalize_hard(&library);

    cep_cell_system_initiate();
    ProxyContext import_ctx = {0};
    cepCell import_lib;
    CEP_0(&import_lib);
    cep_library_initialize(&import_lib,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_library_ops,
                           &import_ctx);

    cepCell placeholder;
    CEP_0(&placeholder);
    cep_proxy_initialize_handle(&placeholder,
                                CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")),
                                NULL,
                                &import_lib);
    munit_assert_not_null(cep_cell_add(cep_root(), 0, &placeholder));

    cepSerializationReader* reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);

    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }
    munit_assert_true(cep_serialization_reader_commit(reader));
    cep_serialization_reader_destroy(reader);

    cepCell* restored = cep_cell_find_by_name(cep_root(), CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")));
    munit_assert_not_null(restored);
    munit_assert_true(cep_cell_is_proxy(restored));
    munit_assert_not_null(import_ctx.last_handle);
    munit_assert_size(import_ctx.handle_retains, ==, 1u);
    munit_assert_size(import_ctx.handle_releases, ==, 0u);

    cep_cell_delete_hard(restored);
    munit_assert_size(import_ctx.handle_releases, ==, 1u);

    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&import_lib);

    cep_cell_system_initiate();
    ProxyContext missing_ctx = {0};
    cepCell missing_lib;
    CEP_0(&missing_lib);
    cep_library_initialize(&missing_lib,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_library_ops,
                           &missing_ctx);

    reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }
    munit_assert_false(cep_serialization_reader_commit(reader));
    cep_serialization_reader_destroy(reader);
    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&missing_lib);

    cep_cell_system_initiate();
    ProxyContext restore_fail_ctx = {0};
    cepCell restore_fail_lib;
    CEP_0(&restore_fail_lib);
    const cepLibraryOps restore_fail_ops = {
        .handle_retain   = proxy_handle_retain,
        .handle_release  = proxy_handle_release,
        .handle_snapshot = proxy_handle_snapshot,
        .handle_restore  = proxy_handle_restore_fail,
        .stream_read     = NULL,
        .stream_write    = NULL,
        .stream_expected_hash = NULL,
        .stream_map      = NULL,
        .stream_unmap    = NULL,
        .stream_snapshot = proxy_stream_snapshot,
        .stream_restore  = proxy_stream_restore,
    };
    cep_library_initialize(&restore_fail_lib,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &restore_fail_ops,
                           &restore_fail_ctx);

    cepCell restore_placeholder;
    CEP_0(&restore_placeholder);
    cep_proxy_initialize_handle(&restore_placeholder,
                                CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")),
                                NULL,
                                &restore_fail_lib);
    munit_assert_not_null(cep_cell_add(cep_root(), 0, &restore_placeholder));

    reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }
    munit_assert_false(cep_serialization_reader_commit(reader));
    cep_serialization_reader_destroy(reader);
    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&restore_fail_lib);

    capture_reset(&capture);

    ProxyContext snapshot_fail_ctx = {0};
    cepCell snapshot_fail_lib;
    CEP_0(&snapshot_fail_lib);
    const cepLibraryOps snapshot_fail_ops = {
        .handle_retain   = proxy_handle_retain,
        .handle_release  = proxy_handle_release,
        .handle_snapshot = proxy_handle_snapshot_fail,
        .handle_restore  = proxy_handle_restore,
        .stream_read     = NULL,
        .stream_write    = NULL,
        .stream_expected_hash = NULL,
        .stream_map      = NULL,
        .stream_unmap    = NULL,
        .stream_snapshot = proxy_stream_snapshot,
        .stream_restore  = proxy_stream_restore,
    };
    cep_library_initialize(&snapshot_fail_lib,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &snapshot_fail_ops,
                           &snapshot_fail_ctx);

    cepCell* snapshot_resource = proxy_make_handle_resource(payload, payload_size);
    cepCell snapshot_handle;
    CEP_0(&snapshot_handle);
    cep_proxy_initialize_handle(&snapshot_handle,
                                CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("handle")),
                                snapshot_resource,
                                &snapshot_fail_lib);

    munit_assert_false(cep_serialization_emit_cell(&snapshot_handle,
                                                   NULL,
                                                   capture_sink,
                                                   &capture,
                                                   0));

    cep_cell_finalize_hard(&snapshot_handle);
    cep_cell_finalize_hard(snapshot_resource);
    cep_free(snapshot_resource);
    cep_cell_finalize_hard(&snapshot_fail_lib);

    capture_reset(&capture);

    /* Stream proxies */
    size_t stream_size = (size_t)munit_rand_int_range(12, 48);
    munit_rand_memory(stream_size, payload);

    ProxyContext stream_emit_ctx = {0};
    cepCell stream_lib;
    CEP_0(&stream_lib);
    cep_library_initialize(&stream_lib,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_library_ops,
                           &stream_emit_ctx);

    cepCell* stream_resource = proxy_make_stream_resource(payload, stream_size);
    cepCell proxy_stream;
    CEP_0(&proxy_stream);
    cep_proxy_initialize_stream(&proxy_stream,
                                CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("stream")),
                                stream_resource,
                                &stream_lib);

    munit_assert_true(cep_serialization_emit_cell(&proxy_stream,
                                                  NULL,
                                                  capture_sink,
                                                  &capture,
                                                  0));

    cep_cell_finalize_hard(&proxy_stream);
    cep_cell_finalize_hard(stream_resource);
    cep_free(stream_resource);
    cep_cell_finalize_hard(&stream_lib);

    cep_cell_system_initiate();
    ProxyContext stream_import_ctx = {0};
    cepCell stream_import_lib;
    CEP_0(&stream_import_lib);
    cep_library_initialize(&stream_import_lib,
                           CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("library")),
                           &proxy_library_ops,
                           &stream_import_ctx);

    cepCell stream_placeholder;
    CEP_0(&stream_placeholder);
    cep_proxy_initialize_stream(&stream_placeholder,
                                CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("stream")),
                                NULL,
                                &stream_import_lib);
    munit_assert_not_null(cep_cell_add(cep_root(), 0, &stream_placeholder));

    reader = cep_serialization_reader_create(cep_root());
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }
    munit_assert_true(cep_serialization_reader_commit(reader));
    cep_serialization_reader_destroy(reader);

    cepCell* restored_stream = cep_cell_find_by_name(cep_root(), CEP_DTS(CEP_ACRO("LIB"), CEP_WORD("stream")));
    munit_assert_not_null(restored_stream);
    munit_assert_true(cep_cell_is_proxy(restored_stream));
    munit_assert_not_null(stream_import_ctx.last_stream);

    cep_cell_system_shutdown();
    cep_cell_finalize_hard(&stream_import_lib);
    capture_reset(&capture);

    test_watchdog_signal(fix->watchdog);
}

void* test_serialization_randomized_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    SerializationFixture* fix = munit_malloc(sizeof *fix);
    unsigned timeout = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    fix->watchdog = test_watchdog_create(timeout ? timeout : TEST_TIMEOUT_SECONDS);
    fix->next_tag = CEP_ID(1);
    return fix;
}

void test_serialization_randomized_tear_down(void* fixture) {
    SerializationFixture* fix = fixture;
    if (!fix)
        return;
    test_watchdog_destroy(fix->watchdog);
    free(fix);
}

MunitResult test_serialization_roundtrip(const MunitParameter params[], void* fixture) {
    (void)params;
    SerializationFixture* fix = fixture;
    munit_assert_not_null(fix);

    cep_cell_system_initiate();
    for (unsigned round = 0; round < 6; ++round) {
        run_roundtrip_once(fix);
    }
    cep_cell_system_shutdown();
    return MUNIT_OK;
}

MunitResult test_serialization_proxies(const MunitParameter params[], void* fixture) {
    (void)params;
    SerializationFixture* fix = fixture;
    munit_assert_not_null(fix);

    exercise_proxy_roundtrip(fix);
    return MUNIT_OK;
}
