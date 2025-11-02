/* Federation transport manager exercises: these tests drive the stub transport providers
   to ensure capability negotiation, upd_latest coalescing, and inbound delivery work
   without relying on real network I/O. */

#include "test.h"

#include "cep_cell.h"
#include "cep_namepool.h"
#include "cep_ops.h"
#include "cep_heartbeat.h"
#include "cep_enzyme.h"
#include "cep_runtime.h"
#include "cep_organ.h"
#include "fed_transport_manager.h"
#include "fed_transport_providers.h"
#include "fed_link_organ.h"
#include "fed_mirror_organ.h"
#include "fed_invoke.h"
#include "fed_pack.h"

#include <string.h>

typedef struct {
    unsigned ready_events;
    unsigned backpressure_events;
    unsigned fatal_events;
    unsigned frames;
    uint8_t  last_frame;
    cepFedFrameMode last_mode;
} FedTransportHooks;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[4];
} FedInvokePathBuf;

typedef struct {
    bool completed;
    bool success;
} FedInvokeCompletion;

typedef struct {
    const char* label;
    cepRuntime* runtime;
    cepCell*    net_root;
    cepFedTransportManager manager;
} FedDualRuntimeCtx;

typedef struct {
    cepCell* link_request;
    cepCell* mirror_request;
    cepCell* invoke_request;
    cepPath* link_path;
    cepPath* mirror_path;
    cepPath* invoke_path;
    const cepFedInvokeRequest* invoke_ctx;
} FedDualMountState;

typedef struct {
    cepRuntime* initial_scope;
    cepRuntime* runtime_a;
    cepRuntime* runtime_b;
} FedDualRuntimePair;

static const char* const FED_DUAL_PEER_A = "runtime-a";
static const char* const FED_DUAL_PEER_B = "runtime-b";
static const char* const FED_DUAL_NODE_A = "node-a";
static const char* const FED_DUAL_NODE_B = "node-b";
static const char* const FED_DUAL_LINK_MOUNT = "link-ab";
static const char* const FED_DUAL_MIRROR_MOUNT = "mir-ab";
static const char* const FED_DUAL_INVOKE_MOUNT = "inv-ab";
static const char* const FED_DUAL_CHANNEL_AB = "channel-ab";
static const char* const FED_DUAL_CHANNEL_BA = "channel-ba";
static const char* const FED_DUAL_LINK_REQ_A = "link_ab";
static const char* const FED_DUAL_LINK_REQ_B = "link_ba";
static const char* const FED_DUAL_MIRROR_REQ_A = "mir_ab";
static const char* const FED_DUAL_MIRROR_REQ_B = "mir_ba";
static const char* const FED_DUAL_INVOKE_REQ_A = "inv_req_a";
static const char* const FED_DUAL_INVOKE_REQ_B = "inv_req_b";

#define FED_INVOKE_FRAME_RESPONSE 0x02u
#define FED_INVOKE_STATUS_REJECT  0x01u
#define FED_INVOKE_TOPIC_TIMEOUT  "tp_inv_timeout"
#define FED_INVOKE_TOPIC_REJECT   "tp_inv_reject"
#define FED_INVOKE_TIMEOUT_NOTE   "remote invocation timed out"
#define FED_INVOKE_REJECT_NOTE    "remote invocation rejected"

typedef struct {
    uint8_t  kind;
    uint8_t  status;
    uint16_t signal_segments;
    uint16_t target_segments;
    uint16_t reserved;
    uint64_t invocation_id;
} FedInvokeFrameHeader;

static int g_fed_invoke_handler_calls = 0;
static cepRuntime* g_fed_invoke_handler_runtimes[4];
static size_t g_fed_invoke_handler_runtime_count = 0u;
static cepRuntime* g_fed_invoke_timeout_runtimes[4];
static size_t g_fed_invoke_timeout_runtime_count = 0u;

static const cepPath* fed_test_build_path(FedInvokePathBuf* buf,
                                          const char* const* segments,
                                          size_t count);
static void fed_test_write_bool(cepCell* parent, const char* tag, bool value);
static void fed_test_write_u32(cepCell* parent, const char* tag, uint32_t value);
static void fed_test_write_u16(cepCell* parent, const char* tag, uint16_t value);

static void
fed_test_runtime_forget(cepRuntime* runtime,
                        cepRuntime** list,
                        size_t* count)
{
    if (!runtime || !list || !count || *count == 0u) {
        return;
    }
    for (size_t i = 0; i < *count; ++i) {
        if (list[i] == runtime) {
            for (size_t j = i + 1; j < *count; ++j) {
                list[j - 1] = list[j];
            }
            list[*count - 1] = NULL;
            *count -= 1u;
            break;
        }
    }
}

static int
fed_test_invoke_handler(const cepPath* signal, const cepPath* target)
{
    (void)signal;
    (void)target;
    g_fed_invoke_handler_calls++;
    return CEP_ENZYME_SUCCESS;
}

static void
fed_test_invoke_completion(void* ctx, bool ok)
{
    FedInvokeCompletion* completion = ctx;
    if (!completion) {
        return;
    }
    completion->completed = true;
    completion->success = ok;
}

static void
fed_test_ensure_invoke_handler(void)
{
    cepRuntime* runtime = cep_runtime_active();
    for (size_t i = 0; i < g_fed_invoke_handler_runtime_count; ++i) {
        if (g_fed_invoke_handler_runtimes[i] == runtime) {
            return;
        }
    }

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[1];
    } FedInvokeSignalBuf;

    FedInvokeSignalBuf buf = {
        .length = 1u,
        .capacity = 1u,
        .past = {
            {
                .dt = cep_ops_make_dt("sig:test_invoke"),
                .timestamp = 0u,
            },
        },
    };

    cepEnzymeDescriptor descriptor = {
        .name = buf.past[0].dt,
        .label = "test.invoke.handler",
        .callback = fed_test_invoke_handler,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    if (cep_enzyme_register(registry,
                            (const cepPath*)&buf,
                            &descriptor) != CEP_ENZYME_SUCCESS) {
        munit_error("failed to register invoke test handler");
    }

    munit_assert_size(g_fed_invoke_handler_runtime_count, <, cep_lengthof(g_fed_invoke_handler_runtimes));
    g_fed_invoke_handler_runtimes[g_fed_invoke_handler_runtime_count++] = runtime;
}

static void
fed_test_register_invoke_timeout(void)
{
    cepRuntime* runtime = cep_runtime_active();
    for (size_t i = 0; i < g_fed_invoke_timeout_runtime_count; ++i) {
        if (g_fed_invoke_timeout_runtimes[i] == runtime) {
            return;
        }
    }

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[1];
    } FedTimeoutSignalBuf;

    FedTimeoutSignalBuf buf = {
        .length = 1u,
        .capacity = 1u,
        .past = {
            {
                .dt = cep_ops_make_dt("sig:fed_inv:timeout"),
                .timestamp = 0u,
            },
        },
    };

    cepEnzymeDescriptor descriptor = {
        .name = buf.past[0].dt,
        .label = "fed.invoke.timeout",
        .callback = cep_fed_invoke_timeout_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    if (cep_enzyme_register(registry,
                            (const cepPath*)&buf,
                            &descriptor) != CEP_ENZYME_SUCCESS) {
        munit_error("failed to register invoke timeout handler");
    }

    munit_assert_size(g_fed_invoke_timeout_runtime_count, <, cep_lengthof(g_fed_invoke_timeout_runtimes));
    g_fed_invoke_timeout_runtimes[g_fed_invoke_timeout_runtime_count++] = runtime;
}

static const cepPath*
fed_test_build_path(FedInvokePathBuf* buf,
                    const char* const* segments,
                    size_t count)
{
    munit_assert_not_null(buf);
    munit_assert_not_null(segments);
    munit_assert_size(count, <=, cep_lengthof(buf->past));

    buf->length = count;
    buf->capacity = cep_lengthof(buf->past);

    for (size_t i = 0; i < count; ++i) {
        buf->past[i].dt = cep_ops_make_dt(segments[i]);
        buf->past[i].timestamp = 0u;
    }

    return (const cepPath*)buf;
}

static cepDT fed_test_make_dt(const char* tag) {
    cepID domain = cep_namepool_intern_cstr("CEP");
    cepID word = cep_text_to_word(tag);
    munit_assert_uint64(word, !=, 0u);
    return cep_dt_make(domain, word);
}

static cepCell* fed_test_lookup_child(cepCell* parent, const char* tag) {
    if (!parent || !tag) {
        return NULL;
    }
    cepDT dt = fed_test_make_dt(tag);
    cepCell* child = cep_cell_find_by_name(parent, &dt);
    if (!child) {
        return NULL;
    }
    return cep_cell_resolve(child);
}

static cepCell* fed_test_require_dictionary(cepCell* cell) {
    munit_assert_not_null(cell);
    munit_assert_true(cep_cell_require_dictionary_store(&cell));
    return cell;
}

static const char* fed_test_read_text_field(cepCell* parent,
                                            const char* tag,
                                            char* buffer,
                                            size_t capacity) {
    cepCell* node = fed_test_lookup_child(parent, tag);
    munit_assert_not_null(node);
    cepData* data = NULL;
    munit_assert_true(cep_cell_require_data(&node, &data));
    munit_assert_size(data->size, <, capacity);
    const void* payload = cep_data_payload(data);
    munit_assert_not_null(payload);
    memcpy(buffer, payload, data->size);
    buffer[data->size] = '\0';
    return buffer;
}

static bool fed_test_try_read_text_field(cepCell* parent,
                                         const char* tag,
                                         char* buffer,
                                         size_t capacity) {
    if (!parent || !tag || !buffer || capacity == 0u) {
        return false;
    }
    cepCell* node = fed_test_lookup_child(parent, tag);
    if (!node) {
        buffer[0] = '\0';
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&node, &data)) {
        buffer[0] = '\0';
        return false;
    }
    cepDT type = cep_ops_make_dt("val/text");
    if (cep_dt_compare(&data->dt, &type) != 0) {
        if (cep_dt_compare(&data->dt, CEP_DTAW("CEP", "text")) != 0) {
            buffer[0] = '\0';
            return false;
        }
    }
    if (data->size >= capacity) {
        buffer[0] = '\0';
        return false;
    }
    const void* payload = cep_data_payload(data);
    if (!payload) {
        buffer[0] = '\0';
        return false;
    }
    memcpy(buffer, payload, data->size);
    buffer[data->size] = '\0';
    return true;
}

static bool fed_test_read_bool_field(cepCell* parent, const char* tag) {
    cepCell* node = fed_test_lookup_child(parent, tag);
    munit_assert_not_null(node);
    cepData* data = NULL;
    munit_assert_true(cep_cell_require_data(&node, &data));
    cepDT type = cep_ops_make_dt("val/bool");
    munit_assert_int(cep_dt_compare(&data->dt, &type), ==, 0);
    munit_assert_size(data->size, ==, sizeof(uint8_t));
    const uint8_t* payload = (const uint8_t*)cep_data_payload(data);
    munit_assert_not_null(payload);
    return *payload != 0u;
}

static uint64_t fed_test_read_u64_field(cepCell* parent, const char* tag) {
    cepCell* node = fed_test_lookup_child(parent, tag);
    munit_assert_not_null(node);
    cepData* data = NULL;
    munit_assert_true(cep_cell_require_data(&node, &data));
    cepDT type = cep_ops_make_dt("val/u64");
    munit_assert_int(cep_dt_compare(&data->dt, &type), ==, 0);
    munit_assert_size(data->size, ==, sizeof(uint64_t));
    const uint64_t* payload = (const uint64_t*)cep_data_payload(data);
    munit_assert_not_null(payload);
    return *payload;
}

static cepCell* fed_test_catalog_entry(cepCell* net_root,
                                       const char* mode,
                                       const char* mount) {
    cepCell* catalog = fed_test_lookup_child(net_root, "catalog");
    if (!catalog) {
        return NULL;
    }
    catalog = fed_test_require_dictionary(catalog);
    cepCell* mode_cell = fed_test_lookup_child(catalog, mode);
    if (!mode_cell) {
        return NULL;
    }
    mode_cell = fed_test_require_dictionary(mode_cell);
    cepCell* mount_cell = fed_test_lookup_child(mode_cell, mount);
    if (!mount_cell) {
        return NULL;
    }
    return fed_test_require_dictionary(mount_cell);
}

static cepCell* fed_test_telemetry_entry(cepCell* net_root,
                                         const char* peer,
                                         const char* mount) {
    cepCell* telemetry = fed_test_lookup_child(net_root, "telemetry");
    if (!telemetry) {
        return NULL;
    }
    telemetry = fed_test_require_dictionary(telemetry);
    cepCell* peer_cell = fed_test_lookup_child(telemetry, peer);
    if (!peer_cell) {
        return NULL;
    }
    peer_cell = fed_test_require_dictionary(peer_cell);
    cepCell* mount_cell = fed_test_lookup_child(peer_cell, mount);
    if (!mount_cell) {
        return NULL;
    }
    return fed_test_require_dictionary(mount_cell);
}

static cepCell* fed_test_ceh_entry(cepCell* net_root,
                                   const char* peer,
                                   const char* topic) {
    cepCell* peers = fed_test_lookup_child(net_root, "peers");
    if (!peers) {
        return NULL;
    }
    peers = fed_test_require_dictionary(peers);
    cepCell* peer_cell = fed_test_lookup_child(peers, peer);
    if (!peer_cell) {
        return NULL;
    }
    peer_cell = fed_test_require_dictionary(peer_cell);
    cepCell* ceh_cell = fed_test_lookup_child(peer_cell, "ceh");
    if (!ceh_cell) {
        return NULL;
    }
    ceh_cell = fed_test_require_dictionary(ceh_cell);
    cepCell* topic_cell = fed_test_lookup_child(ceh_cell, topic);
    if (!topic_cell) {
        return NULL;
    }
    return fed_test_require_dictionary(topic_cell);
}

static void fed_test_bootstrap_runtime(void) {
    fed_test_runtime_forget(cep_runtime_active(), g_fed_invoke_timeout_runtimes, &g_fed_invoke_timeout_runtime_count);
    fed_test_runtime_forget(cep_runtime_active(), g_fed_invoke_handler_runtimes, &g_fed_invoke_handler_runtime_count);

    test_runtime_shutdown();

    cep_cell_system_initiate();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
        .spacing_window = 8u,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
}

static cepCell* fed_test_net_root(void) {
    cepCell* root = cep_root();
    cepCell* net_root = cep_cell_ensure_dictionary_child(root, CEP_DTAW("CEP", "net"), CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(net_root);
    net_root = cep_cell_resolve(net_root);
    munit_assert_not_null(net_root);
    munit_assert_true(cep_cell_require_dictionary_store(&net_root));
    if (net_root->store) {
        cep_store_delete_children_hard(net_root->store);
    }
    return net_root;
}

static void fed_test_prepare_providers(void) {
    fed_test_bootstrap_runtime();
    munit_assert_true(cep_fed_transport_register_tcp_provider());
    munit_assert_true(cep_fed_transport_register_pipe_provider());
    munit_assert_true(cep_fed_transport_register_mock_provider());
    cep_fed_transport_mock_reset();
}

static void fed_test_pop_and_process_invoke_response(const cepFedInvokeRequest* ctx) {
    uint8_t resp_buffer[256];
    size_t resp_len = 0u;
    cepFedFrameMode resp_mode = CEP_FED_FRAME_MODE_DATA;

    if (!cep_fed_transport_mock_pop_outbound("peer-invoke",
                                             "inv-mnt",
                                             resp_buffer,
                                             sizeof resp_buffer,
                                             &resp_len,
                                             &resp_mode)) {
        return;
    }
    cep_fed_invoke_process_frame((cepFedInvokeRequest*)ctx,
                                 resp_buffer,
                                 resp_len,
                                 resp_mode);
}

static void fed_dual_runtime_bootstrap(FedDualRuntimeCtx* ctx) {
    munit_assert_not_null(ctx);
    munit_assert_not_null(ctx->runtime);

    fed_test_runtime_forget(ctx->runtime, g_fed_invoke_timeout_runtimes, &g_fed_invoke_timeout_runtime_count);
    fed_test_runtime_forget(ctx->runtime, g_fed_invoke_handler_runtimes, &g_fed_invoke_handler_runtime_count);

    cepRuntime* previous = cep_runtime_set_active(ctx->runtime);
    cep_l0_bootstrap_reset();
    munit_assert_true(cep_l0_bootstrap());

    munit_assert_true(cep_fed_pack_bootstrap());

    ctx->net_root = fed_test_net_root();
    fed_test_register_invoke_timeout();

    munit_assert_true(cep_fed_transport_manager_init(&ctx->manager, ctx->net_root));
    munit_assert_true(cep_fed_link_organ_init(&ctx->manager, ctx->net_root));
    munit_assert_true(cep_fed_mirror_organ_init(&ctx->manager, ctx->net_root));
    munit_assert_true(cep_fed_invoke_organ_init(&ctx->manager, ctx->net_root));

    cep_runtime_restore_active(previous);
}

static void fed_dual_runtime_teardown(FedDualRuntimeCtx* ctx) {
    if (!ctx || !ctx->runtime) {
        return;
    }
    cepRuntime* previous = cep_runtime_set_active(ctx->runtime);
    cep_fed_transport_manager_teardown(&ctx->manager);
    cep_runtime_restore_active(previous);
}

static cepCell* fed_dual_require_requests_root(cepCell* net_root, const char* organ_tag) {
    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* organ_root = fed_test_require_dictionary(fed_test_lookup_child(organs, organ_tag));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(organ_root, "requests"));
    return requests;
}

static void fed_dual_runtime_seed_service(FedDualRuntimeCtx* ctx,
                                          const char* remote_peer,
                                          const char* service_name,
                                          const char* mode,
                                          const char* mount_path,
                                          const char* local_node,
                                          const char* provider,
                                          bool upd_latest) {
    munit_assert_not_null(ctx);
    munit_assert_not_null(remote_peer);
    munit_assert_not_null(service_name);
    munit_assert_not_null(mode);
    munit_assert_not_null(mount_path);
    munit_assert_not_null(local_node);

    cepRuntime* previous = cep_runtime_set_active(ctx->runtime);

    cepCell* peers = fed_test_require_dictionary(fed_test_lookup_child(ctx->net_root, "peers"));
    cepDT peer_dt = fed_test_make_dt(remote_peer);
    cepCell* peer_cell = cep_cell_ensure_dictionary_child(peers, &peer_dt, CEP_STORAGE_RED_BLACK_T);
    peer_cell = fed_test_require_dictionary(peer_cell);

    cepCell* services = cep_cell_ensure_dictionary_child(peer_cell, CEP_DTAW("CEP", "services"), CEP_STORAGE_RED_BLACK_T);
    services = fed_test_require_dictionary(services);

    cepDT service_dt = fed_test_make_dt(service_name);
    cepCell* service_cell = cep_cell_ensure_dictionary_child(services, &service_dt, CEP_STORAGE_RED_BLACK_T);
    service_cell = fed_test_require_dictionary(service_cell);

    (void)cep_cell_put_text(service_cell, CEP_DTAW("CEP", "mode"), mode);
    (void)cep_cell_put_text(service_cell, CEP_DTAW("CEP", "mount_path"), mount_path);
    (void)cep_cell_put_text(service_cell, CEP_DTAW("CEP", "local_node"), local_node);
    if (provider && provider[0] != '\0') {
        (void)cep_cell_put_text(service_cell, CEP_DTAW("CEP", "provider"), provider);
    }
    fed_test_write_bool(service_cell, "upd_latest", upd_latest);

    cepCell* catalog = fed_test_require_dictionary(fed_test_lookup_child(ctx->net_root, "catalog"));
    cepDT mode_dt = fed_test_make_dt(mode);
    cepCell* mode_root = cep_cell_ensure_dictionary_child(catalog, &mode_dt, CEP_STORAGE_RED_BLACK_T);
    mode_root = fed_test_require_dictionary(mode_root);
    cepDT mount_dt = fed_test_make_dt(service_name);
    cepCell* mount_cell = cep_cell_ensure_dictionary_child(mode_root, &mount_dt, CEP_STORAGE_RED_BLACK_T);
    mount_cell = fed_test_require_dictionary(mount_cell);
    (void)cep_cell_put_text(mount_cell, CEP_DTAW("CEP", "peer"), remote_peer);
    (void)cep_cell_put_text(mount_cell, CEP_DTAW("CEP", "mode"), mode);
    (void)cep_cell_put_text(mount_cell, CEP_DTAW("CEP", "local_node"), local_node);
    if (provider && provider[0] != '\0') {
        (void)cep_cell_put_text(mount_cell, CEP_DTAW("CEP", "provider"), provider);
    }
    fed_test_write_bool(mount_cell, "upd_latest", upd_latest);

    cep_runtime_restore_active(previous);
}

/* fed_dual_runtime_configure_requests seeds the link, mirror, and invoke request
   cells for the provided runtime, runs the validators, and snapshots the resulting
   request handles so dual-runtime tests can drive scenarios without repeating the
   boilerplate request setup. */
static void fed_dual_runtime_configure_requests(FedDualRuntimeCtx* ctx,
                                                const char* remote_peer,
                                                const char* local_node,
                                                const char* link_mount,
                                                const char* link_request_name,
                                                const char* mirror_mount,
                                                const char* mirror_request_name,
                                                const char* invoke_mount,
                                                const char* invoke_request_name,
                                                const char* mirror_src_channel,
                                                FedDualMountState* out_state) {
    munit_assert_not_null(ctx);
    munit_assert_not_null(remote_peer);
    munit_assert_not_null(local_node);
    munit_assert_not_null(link_mount);
    munit_assert_not_null(mirror_mount);
    munit_assert_not_null(invoke_mount);
    munit_assert_not_null(mirror_src_channel);
    munit_assert_not_null(out_state);

    memset(out_state, 0, sizeof *out_state);

    cepRuntime* previous = cep_runtime_set_active(ctx->runtime);

    munit_assert_true(cep_fed_link_organ_init(&ctx->manager, ctx->net_root));
    munit_assert_true(cep_fed_mirror_organ_init(&ctx->manager, ctx->net_root));
    munit_assert_true(cep_fed_invoke_organ_init(&ctx->manager, ctx->net_root));

    cepCell* link_requests = fed_dual_require_requests_root(ctx->net_root, "link");
    cepDT link_dt = fed_test_make_dt(link_request_name);
    cepCell* link_request = cep_cell_ensure_dictionary_child(link_requests, &link_dt, CEP_STORAGE_RED_BLACK_T);
    link_request = fed_test_require_dictionary(link_request);
    (void)cep_cell_put_text(link_request, CEP_DTAW("CEP","peer"), remote_peer);
    (void)cep_cell_put_text(link_request, CEP_DTAW("CEP","mount"), link_mount);
    (void)cep_cell_put_text(link_request, CEP_DTAW("CEP","mode"), "link");
    (void)cep_cell_put_text(link_request, CEP_DTAW("CEP","local_node"), local_node);
    cepCell* link_caps = cep_cell_ensure_dictionary_child(link_request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    link_caps = fed_test_require_dictionary(link_caps);
    cepCell* link_required = cep_cell_ensure_dictionary_child(link_caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    link_required = fed_test_require_dictionary(link_required);
    fed_test_write_bool(link_required, "reliable", true);
    fed_test_write_bool(link_required, "ordered", true);
    fed_test_write_bool(link_required, "remote_net", true);
    cepPath* link_path = NULL;
    munit_assert_true(cep_cell_path(link_request, &link_path));
    munit_assert_int(cep_fed_link_validator(NULL, link_path), ==, CEP_ENZYME_SUCCESS);

    cepCell* mirror_requests = fed_dual_require_requests_root(ctx->net_root, "mirror");
    cepDT mirror_dt = fed_test_make_dt(mirror_request_name);
    cepCell* mirror_request = cep_cell_ensure_dictionary_child(mirror_requests, &mirror_dt, CEP_STORAGE_RED_BLACK_T);
    mirror_request = fed_test_require_dictionary(mirror_request);
    (void)cep_cell_put_text(mirror_request, CEP_DTAW("CEP","peer"), remote_peer);
    (void)cep_cell_put_text(mirror_request, CEP_DTAW("CEP","mount"), mirror_mount);
    (void)cep_cell_put_text(mirror_request, CEP_DTAW("CEP","mode"), "mirror");
    (void)cep_cell_put_text(mirror_request, CEP_DTAW("CEP","local_node"), local_node);
    (void)cep_cell_put_text(mirror_request, CEP_DTAW("CEP","src_peer"), remote_peer);
    (void)cep_cell_put_text(mirror_request, CEP_DTAW("CEP","src_chan"), mirror_src_channel);
    cepCell* mirror_caps = cep_cell_ensure_dictionary_child(mirror_request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    mirror_caps = fed_test_require_dictionary(mirror_caps);
    cepCell* mirror_required = cep_cell_ensure_dictionary_child(mirror_caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    mirror_required = fed_test_require_dictionary(mirror_required);
    fed_test_write_bool(mirror_required, "reliable", true);
    cepCell* mirror_bundle = cep_cell_ensure_dictionary_child(mirror_request, CEP_DTAW("CEP","bundle"), CEP_STORAGE_RED_BLACK_T);
    mirror_bundle = fed_test_require_dictionary(mirror_bundle);
    fed_test_write_u32(mirror_bundle, "beat_window", 1u);
    fed_test_write_u16(mirror_bundle, "max_infl", 1u);
    cepPath* mirror_path = NULL;
    munit_assert_true(cep_cell_path(mirror_request, &mirror_path));
    int mirror_rc = cep_fed_mirror_validator(NULL, mirror_path);
    if (mirror_rc != CEP_ENZYME_SUCCESS) {
        char note[128] = {0};
        fed_test_try_read_text_field(mirror_request, "error_note", note, sizeof note);
        munit_errorf("mirror validator failed (%d): %s", mirror_rc, note);
    }

    cepCell* invoke_requests = fed_dual_require_requests_root(ctx->net_root, "invoke");
    cepDT invoke_dt = fed_test_make_dt(invoke_request_name);
    cepCell* invoke_request = cep_cell_ensure_dictionary_child(invoke_requests, &invoke_dt, CEP_STORAGE_RED_BLACK_T);
    invoke_request = fed_test_require_dictionary(invoke_request);
    (void)cep_cell_put_text(invoke_request, CEP_DTAW("CEP","peer"), remote_peer);
    (void)cep_cell_put_text(invoke_request, CEP_DTAW("CEP","mount"), invoke_mount);
    (void)cep_cell_put_text(invoke_request, CEP_DTAW("CEP","local_node"), local_node);
    cepCell* invoke_caps = cep_cell_ensure_dictionary_child(invoke_request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    invoke_caps = fed_test_require_dictionary(invoke_caps);
    cepCell* invoke_required = cep_cell_ensure_dictionary_child(invoke_caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    invoke_required = fed_test_require_dictionary(invoke_required);
    fed_test_write_bool(invoke_required, "ordered", true);
    cepPath* invoke_path = NULL;
    munit_assert_true(cep_cell_path(invoke_request, &invoke_path));
    munit_assert_int(cep_fed_invoke_validator(NULL, invoke_path), ==, CEP_ENZYME_SUCCESS);

    const cepFedInvokeRequest* invoke_ctx = cep_fed_invoke_request_find(remote_peer, invoke_mount);
    munit_assert_not_null(invoke_ctx);

    cep_runtime_restore_active(previous);

    out_state->link_request = link_request;
    out_state->mirror_request = mirror_request;
    out_state->invoke_request = invoke_request;
    out_state->link_path = link_path;
    out_state->mirror_path = mirror_path;
    out_state->invoke_path = invoke_path;
    out_state->invoke_ctx = invoke_ctx;
}

/* fed_dual_runtime_release_mounts frees any path buffers captured during request
   configuration so dual-runtime fixtures can clean up without duplicating checks. */
static void fed_dual_runtime_release_mounts(FedDualMountState* state) {
    if (!state) {
        return;
    }
    if (state->link_path) {
        cep_free(state->link_path);
    }
    if (state->mirror_path) {
        cep_free(state->mirror_path);
    }
    if (state->invoke_path) {
        cep_free(state->invoke_path);
    }
    memset(state, 0, sizeof *state);
}

/* fed_dual_runtime_prepare_pair boots two runtimes, registers the mock transport
   providers, seeds link/mirror/invoke services, and captures the configured mount
   state so dual-runtime tests can focus on behavioural coverage. */
static void fed_dual_runtime_prepare_pair(FedDualRuntimePair* pair,
                                          FedDualRuntimeCtx* ctx_a,
                                          FedDualRuntimeCtx* ctx_b,
                                          FedDualMountState* mounts_a,
                                          FedDualMountState* mounts_b) {
    munit_assert_not_null(pair);
    munit_assert_not_null(ctx_a);
    munit_assert_not_null(ctx_b);
    munit_assert_not_null(mounts_a);
    munit_assert_not_null(mounts_b);

    fed_test_bootstrap_runtime();

    pair->initial_scope = cep_runtime_active();
    pair->runtime_a = cep_runtime_default();
    pair->runtime_b = cep_runtime_create();
    munit_assert_not_null(pair->runtime_b);

    ctx_a->label = FED_DUAL_PEER_A;
    ctx_a->runtime = pair->runtime_a;
    ctx_b->label = FED_DUAL_PEER_B;
    ctx_b->runtime = pair->runtime_b;

    cepRuntime* previous = cep_runtime_set_active(pair->runtime_a);
    munit_assert_true(cep_fed_transport_register_tcp_provider());
    munit_assert_true(cep_fed_transport_register_pipe_provider());
    munit_assert_true(cep_fed_transport_register_mock_provider());
    cep_fed_transport_mock_reset();
    cep_runtime_restore_active(previous);

    previous = cep_runtime_set_active(pair->runtime_b);
    munit_assert_true(cep_fed_transport_register_tcp_provider());
    munit_assert_true(cep_fed_transport_register_pipe_provider());
    munit_assert_true(cep_fed_transport_register_mock_provider());
    cep_fed_transport_mock_reset();
    cep_runtime_restore_active(previous);

    fed_dual_runtime_bootstrap(ctx_a);
    fed_dual_runtime_bootstrap(ctx_b);

    fed_dual_runtime_seed_service(ctx_a,
                                  FED_DUAL_PEER_B,
                                  FED_DUAL_LINK_MOUNT,
                                  "link",
                                  FED_DUAL_LINK_MOUNT,
                                  FED_DUAL_NODE_A,
                                  "mock",
                                  true);
    fed_dual_runtime_seed_service(ctx_a,
                                  FED_DUAL_PEER_B,
                                  FED_DUAL_MIRROR_MOUNT,
                                  "mirror",
                                  FED_DUAL_MIRROR_MOUNT,
                                  FED_DUAL_NODE_A,
                                  "mock",
                                  true);
    fed_dual_runtime_seed_service(ctx_a,
                                  FED_DUAL_PEER_B,
                                  FED_DUAL_INVOKE_MOUNT,
                                  "invoke",
                                  FED_DUAL_INVOKE_MOUNT,
                                  FED_DUAL_NODE_A,
                                  "mock",
                                  true);

    fed_dual_runtime_seed_service(ctx_b,
                                  FED_DUAL_PEER_A,
                                  FED_DUAL_LINK_MOUNT,
                                  "link",
                                  FED_DUAL_LINK_MOUNT,
                                  FED_DUAL_NODE_B,
                                  "mock",
                                  true);
    fed_dual_runtime_seed_service(ctx_b,
                                  FED_DUAL_PEER_A,
                                  FED_DUAL_MIRROR_MOUNT,
                                  "mirror",
                                  FED_DUAL_MIRROR_MOUNT,
                                  FED_DUAL_NODE_B,
                                  "mock",
                                  true);
    fed_dual_runtime_seed_service(ctx_b,
                                  FED_DUAL_PEER_A,
                                  FED_DUAL_INVOKE_MOUNT,
                                  "invoke",
                                  FED_DUAL_INVOKE_MOUNT,
                                  FED_DUAL_NODE_B,
                                  "mock",
                                  true);

    previous = cep_runtime_set_active(ctx_a->runtime);
    fed_test_ensure_invoke_handler();
    cep_runtime_restore_active(previous);
    fed_dual_runtime_configure_requests(ctx_a,
                                        FED_DUAL_PEER_B,
                                        FED_DUAL_NODE_A,
                                        FED_DUAL_LINK_MOUNT,
                                        FED_DUAL_LINK_REQ_A,
                                        FED_DUAL_MIRROR_MOUNT,
                                        FED_DUAL_MIRROR_REQ_A,
                                        FED_DUAL_INVOKE_MOUNT,
                                        FED_DUAL_INVOKE_REQ_A,
                                        FED_DUAL_CHANNEL_AB,
                                        mounts_a);

    previous = cep_runtime_set_active(ctx_b->runtime);
    fed_test_ensure_invoke_handler();
    cep_runtime_restore_active(previous);
    fed_dual_runtime_configure_requests(ctx_b,
                                        FED_DUAL_PEER_A,
                                        FED_DUAL_NODE_B,
                                        FED_DUAL_LINK_MOUNT,
                                        FED_DUAL_LINK_REQ_B,
                                        FED_DUAL_MIRROR_MOUNT,
                                        FED_DUAL_MIRROR_REQ_B,
                                        FED_DUAL_INVOKE_MOUNT,
                                        FED_DUAL_INVOKE_REQ_B,
                                        FED_DUAL_CHANNEL_BA,
                                        mounts_b);
}

/* fed_dual_runtime_cleanup_pair unwinds the runtimes created by prepare_pair,
   ensuring transports reset, runtimes tear down cleanly, and path buffers are
   freed between tests. */
static void fed_dual_runtime_cleanup_pair(FedDualRuntimePair* pair,
                                          FedDualRuntimeCtx* ctx_a,
                                          FedDualRuntimeCtx* ctx_b,
                                          FedDualMountState* mounts_a,
                                          FedDualMountState* mounts_b) {
    if (!pair || !ctx_a || !ctx_b) {
        return;
    }

    fed_dual_runtime_teardown(ctx_a);
    fed_dual_runtime_teardown(ctx_b);

    cepRuntime* previous = cep_runtime_set_active(pair->runtime_b);
    if (mounts_b && mounts_b->link_path) {
        (void)cep_fed_link_destructor(NULL, mounts_b->link_path);
    }
    if (mounts_b && mounts_b->mirror_path) {
        (void)cep_fed_mirror_destructor(NULL, mounts_b->mirror_path);
    }
    if (mounts_b && mounts_b->invoke_path) {
        (void)cep_fed_invoke_destructor(NULL, mounts_b->invoke_path);
    }
    cep_runtime_shutdown(pair->runtime_b);
    cep_runtime_restore_active(previous);
    cep_runtime_destroy(pair->runtime_b);

    previous = cep_runtime_set_active(pair->runtime_a);
    if (mounts_a && mounts_a->link_path) {
        (void)cep_fed_link_destructor(NULL, mounts_a->link_path);
    }
    if (mounts_a && mounts_a->mirror_path) {
        (void)cep_fed_mirror_destructor(NULL, mounts_a->mirror_path);
    }
    if (mounts_a && mounts_a->invoke_path) {
        (void)cep_fed_invoke_destructor(NULL, mounts_a->invoke_path);
    }
    cep_l0_bootstrap_reset();
    munit_assert_true(cep_l0_bootstrap());
    cep_runtime_restore_active(previous);

    cep_runtime_restore_active(pair->initial_scope);
    test_runtime_shutdown();
    cep_fed_transport_mock_reset();
    fed_dual_runtime_release_mounts(mounts_a);
    fed_dual_runtime_release_mounts(mounts_b);
    pair->runtime_a = NULL;
    pair->runtime_b = NULL;
    pair->initial_scope = NULL;
}

static void fed_test_setup_invoke_request(cepCell* net_root,
                                          cepFedTransportManager* manager,
                                          const char* request_name_text,
                                          cepCell** out_request,
                                          cepPath** out_request_path) {
    (void)manager;

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* invoke_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "invoke"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(invoke_root, "requests"));

    cepDT request_name = fed_test_make_dt(request_name_text);
    cepCell* request = cep_cell_ensure_dictionary_child(requests, &request_name, CEP_STORAGE_RED_BLACK_T);
    request = fed_test_require_dictionary(request);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","peer"), "peer-invoke");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mount"), "inv-mnt");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","local_node"), "node-local");

    cepCell* caps = cep_cell_ensure_dictionary_child(request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    caps = fed_test_require_dictionary(caps);
    cepCell* required_caps = cep_cell_ensure_dictionary_child(caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    required_caps = fed_test_require_dictionary(required_caps);
    fed_test_write_bool(required_caps, "ordered", true);

    cepPath* request_path = NULL;
    munit_assert_true(cep_cell_path(request, &request_path));

    munit_assert_int(cep_fed_invoke_validator(NULL, request_path), ==, CEP_ENZYME_SUCCESS);

    if (out_request) {
        *out_request = request;
    }
    if (out_request_path) {
        *out_request_path = request_path;
    } else {
        cep_free(request_path);
    }
}
static bool fed_test_on_frame(void* ctx,
                              cepFedTransportManagerMount* mount,
                              const uint8_t* payload,
                              size_t payload_len,
                              cepFedFrameMode mode) {
    (void)mount;
    FedTransportHooks* hooks = ctx;
    ++hooks->frames;
    hooks->last_mode = mode;
    hooks->last_frame = payload_len > 0u && payload ? payload[0] : 0u;
    return true;
}

static void fed_test_on_event(void* ctx,
                              cepFedTransportManagerMount* mount,
                              cepFedTransportEventKind kind,
                              const char* detail) {
    (void)mount;
    (void)detail;
    FedTransportHooks* hooks = ctx;
    switch (kind) {
    case CEP_FED_TRANSPORT_EVENT_READY_RX:
        ++hooks->ready_events;
        break;
    case CEP_FED_TRANSPORT_EVENT_BACKPRESSURE:
        ++hooks->backpressure_events;
        break;
    case CEP_FED_TRANSPORT_EVENT_FATAL:
        ++hooks->fatal_events;
        break;
    default:
        break;
    }
}

MunitResult test_fed_transport_negotiation(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));

    cepFedTransportMountCallbacks callbacks = {0};
    cepFedTransportManagerMount* mount = NULL;
    char text[64] = {0};

    cepFedTransportMountConfig tcp_cfg = {
        .peer_id = "peer-alpha",
        .mount_id = "link-main",
        .mount_mode = "link",
        .local_node_id = "node-local",
        .preferred_provider_id = NULL,
        .required_caps = CEP_FED_TRANSPORT_CAP_RELIABLE |
                         CEP_FED_TRANSPORT_CAP_ORDERED |
                         CEP_FED_TRANSPORT_CAP_REMOTE_NET,
        .preferred_caps = CEP_FED_TRANSPORT_CAP_STREAMING,
        .allow_upd_latest = false,
        .deadline_beat = 0u,
    };
    munit_assert_true(cep_fed_transport_manager_configure_mount(&manager, &tcp_cfg, &callbacks, &mount));
    munit_assert_not_null(mount);
    munit_assert_string_equal(cep_fed_transport_manager_mount_provider_id(mount), "tcp");
    cepCell* catalog_entry = fed_test_catalog_entry(net_root, "link", "link-main");
    munit_assert_not_null(catalog_entry);
    fed_test_read_text_field(catalog_entry, "peer", text, sizeof text);
    munit_assert_string_equal(text, "peer-alpha");
    fed_test_read_text_field(catalog_entry, "mode", text, sizeof text);
    munit_assert_string_equal(text, "link");
    fed_test_read_text_field(catalog_entry, "provider", text, sizeof text);
    munit_assert_string_equal(text, "tcp");
    munit_assert_false(fed_test_read_bool_field(catalog_entry, "upd_latest"));

    cepFedTransportMountConfig pipe_cfg = {
        .peer_id = "peer-beta",
        .mount_id = "mirror-alt",
        .mount_mode = "mirror",
        .local_node_id = "node-local",
        .preferred_provider_id = NULL,
        .required_caps = CEP_FED_TRANSPORT_CAP_RELIABLE |
                         CEP_FED_TRANSPORT_CAP_ORDERED |
                         CEP_FED_TRANSPORT_CAP_LOCAL_IPC,
        .preferred_caps = 0,
        .allow_upd_latest = false,
        .deadline_beat = 0u,
    };
    mount = NULL;
    munit_assert_true(cep_fed_transport_manager_configure_mount(&manager, &pipe_cfg, &callbacks, &mount));
   munit_assert_not_null(mount);
    munit_assert_string_equal(cep_fed_transport_manager_mount_provider_id(mount), "pipe");
    catalog_entry = fed_test_catalog_entry(net_root, "mirror", "mirror-alt");
    munit_assert_not_null(catalog_entry);
    fed_test_read_text_field(catalog_entry, "peer", text, sizeof text);
    munit_assert_string_equal(text, "peer-beta");
    fed_test_read_text_field(catalog_entry, "mode", text, sizeof text);
    munit_assert_string_equal(text, "mirror");
    fed_test_read_text_field(catalog_entry, "provider", text, sizeof text);
    munit_assert_string_equal(text, "pipe");
    munit_assert_false(fed_test_read_bool_field(catalog_entry, "upd_latest"));

    FedTransportHooks hooks = {0};
    cepFedTransportMountCallbacks mock_callbacks = {
        .on_frame = fed_test_on_frame,
        .on_event = fed_test_on_event,
        .user_ctx = &hooks,
    };
    cepFedTransportMountConfig mock_cfg = {
        .peer_id = "peer-gamma",
        .mount_id = "gauge",
        .mount_mode = "mirror",
        .local_node_id = "node-local",
        .preferred_provider_id = NULL,
        .required_caps = CEP_FED_TRANSPORT_CAP_ORDERED |
                         CEP_FED_TRANSPORT_CAP_LOCAL_IPC,
        .preferred_caps = 0,
        .allow_upd_latest = true,
        .deadline_beat = 0u,
    };
    mount = NULL;
    munit_assert_true(cep_fed_transport_manager_configure_mount(&manager, &mock_cfg, &mock_callbacks, &mount));
    munit_assert_not_null(mount);
    munit_assert_string_equal(cep_fed_transport_manager_mount_provider_id(mount), "mock");
    catalog_entry = fed_test_catalog_entry(net_root, "mirror", "gauge");
    munit_assert_not_null(catalog_entry);
    fed_test_read_text_field(catalog_entry, "peer", text, sizeof text);
    munit_assert_string_equal(text, "peer-gamma");
    fed_test_read_text_field(catalog_entry, "mode", text, sizeof text);
    munit_assert_string_equal(text, "mirror");
    fed_test_read_text_field(catalog_entry, "provider", text, sizeof text);
    munit_assert_string_equal(text, "mock");
    munit_assert_true(fed_test_read_bool_field(catalog_entry, "upd_latest"));

    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_transport_upd_latest(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));

    FedTransportHooks hooks = {0};
    cepFedTransportMountCallbacks callbacks = {
        .on_frame = fed_test_on_frame,
        .on_event = fed_test_on_event,
        .user_ctx = &hooks,
    };
    char text[64] = {0};
    cepFedTransportMountConfig cfg = {
        .peer_id = "peer-del",
        .mount_id = "gauge-upd",
        .mount_mode = "mirror",
        .local_node_id = "node-local",
        .preferred_provider_id = NULL,
        .required_caps = CEP_FED_TRANSPORT_CAP_ORDERED |
                         CEP_FED_TRANSPORT_CAP_LOCAL_IPC,
        .preferred_caps = CEP_FED_TRANSPORT_CAP_UNRELIABLE,
        .allow_upd_latest = true,
        .deadline_beat = 0u,
    };

    cepFedTransportManagerMount* mount = NULL;
    munit_assert_true(cep_fed_transport_manager_configure_mount(&manager, &cfg, &callbacks, &mount));
    munit_assert_not_null(mount);
    munit_assert_string_equal(cep_fed_transport_manager_mount_provider_id(mount), "mock");

    uint8_t frame1 = 1u;
    uint8_t frame2 = 2u;
    uint8_t frame3 = 3u;
    uint8_t frame4 = 4u;

    munit_assert_true(cep_fed_transport_manager_send(&manager, mount, &frame1, sizeof frame1, CEP_FED_FRAME_MODE_UPD_LATEST, 0u));
    munit_assert_true(cep_fed_transport_manager_send(&manager, mount, &frame2, sizeof frame2, CEP_FED_FRAME_MODE_UPD_LATEST, 0u));
    munit_assert_true(cep_fed_transport_manager_send(&manager, mount, &frame3, sizeof frame3, CEP_FED_FRAME_MODE_UPD_LATEST, 0u));
    munit_assert_true(cep_fed_transport_manager_send(&manager, mount, &frame4, sizeof frame4, CEP_FED_FRAME_MODE_UPD_LATEST, 0u));

    munit_assert_uint(cep_fed_transport_mock_outbound_count("peer-del", "gauge-upd"), ==, 2u);
    size_t len = 0u;
    cepFedFrameMode mode = CEP_FED_FRAME_MODE_DATA;
    uint8_t buffer = 0u;

    munit_assert_true(cep_fed_transport_mock_pop_outbound("peer-del", "gauge-upd", &buffer, sizeof buffer, &len, &mode));
    munit_assert_uint(buffer, ==, 1u);
    munit_assert_uint(len, ==, sizeof buffer);
    munit_assert_uint(mode, ==, CEP_FED_FRAME_MODE_UPD_LATEST);

    munit_assert_true(cep_fed_transport_mock_pop_outbound("peer-del", "gauge-upd", &buffer, sizeof buffer, &len, &mode));
    munit_assert_uint(buffer, ==, 2u);

    munit_assert_true(cep_fed_transport_mock_pop_outbound("peer-del", "gauge-upd", &buffer, sizeof buffer, &len, &mode));
    munit_assert_uint(buffer, ==, 4u);

    munit_assert_uint(cep_fed_transport_mock_outbound_count("peer-del", "gauge-upd"), ==, 0u);
    munit_assert_uint(hooks.backpressure_events, >=, 1u);
    cepCell* telemetry_entry = fed_test_telemetry_entry(net_root, "peer-del", "gauge-upd");
    munit_assert_not_null(telemetry_entry);
    fed_test_read_text_field(telemetry_entry, "mode", &text[0], sizeof text);
    munit_assert_string_equal(text, "mirror");
    fed_test_read_text_field(telemetry_entry, "provider", &text[0], sizeof text);
    munit_assert_string_equal(text, "mock");
    fed_test_read_text_field(telemetry_entry, "last_event", &text[0], sizeof text);
    munit_assert_size(strlen(text), >, (size_t)0);
    munit_assert_false(fed_test_read_bool_field(telemetry_entry, "bp_flag"));
    munit_assert_uint64(fed_test_read_u64_field(telemetry_entry, "ready_count"), >=, 1u);
    munit_assert_uint64(fed_test_read_u64_field(telemetry_entry, "bp_count"), >=, 1u);
    munit_assert_uint64(fed_test_read_u64_field(telemetry_entry, "fatal_count"), ==, 0u);
    munit_assert_uint64(fed_test_read_u64_field(telemetry_entry, "frame_count"), ==, 3u);
    fed_test_read_text_field(telemetry_entry, "last_mode", &text[0], sizeof text);
    munit_assert_string_equal(text, "upd_latest");
    munit_assert_uint64(fed_test_read_u64_field(telemetry_entry, "last_sample"), ==, 4u);

    cepCell* ceh_entry = fed_test_ceh_entry(net_root, "peer-del", "tp_backpr");
    munit_assert_not_null(ceh_entry);
    fed_test_read_text_field(ceh_entry, "severity", &text[0], sizeof text);
    munit_assert_string_equal(text, "warn");
    fed_test_read_text_field(ceh_entry, "note", &text[0], sizeof text);
    munit_assert_size(strlen(text), >, (size_t)0);
    munit_assert_uint64(fed_test_read_u64_field(ceh_entry, "beat"), !=, CEP_BEAT_INVALID);

    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_transport_inbound(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));

    FedTransportHooks hooks = {0};
    cepFedTransportMountCallbacks callbacks = {
        .on_frame = fed_test_on_frame,
        .on_event = fed_test_on_event,
        .user_ctx = &hooks,
    };
    cepFedTransportMountConfig cfg = {
        .peer_id = "peer-inb",
        .mount_id = "rx",
        .mount_mode = "mirror",
        .local_node_id = "node-local",
        .preferred_provider_id = NULL,
        .required_caps = CEP_FED_TRANSPORT_CAP_ORDERED |
                         CEP_FED_TRANSPORT_CAP_LOCAL_IPC,
        .preferred_caps = CEP_FED_TRANSPORT_CAP_UNRELIABLE,
        .allow_upd_latest = true,
        .deadline_beat = 0u,
    };

    cepFedTransportManagerMount* mount = NULL;
    munit_assert_true(cep_fed_transport_manager_configure_mount(&manager, &cfg, &callbacks, &mount));
    munit_assert_not_null(mount);

    uint8_t inbound_payload = 42u;
    munit_assert_true(cep_fed_transport_mock_enqueue_inbound("peer-inb", "rx", &inbound_payload, sizeof inbound_payload, CEP_FED_FRAME_MODE_DATA));
    munit_assert_true(cep_fed_transport_manager_request_receive(&manager, mount));
    munit_assert_uint(hooks.frames, ==, 1u);
    munit_assert_uint(hooks.last_frame, ==, 42u);
    munit_assert_uint(hooks.ready_events, >=, 1u);

    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_transport_close_events(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));

    cepFedTransportMountCallbacks callbacks = {0};
    cepFedTransportManagerMount* mount = NULL;
    cepFedTransportMountConfig cfg = {
        .peer_id = "peer-fatal",
        .mount_id = "link-fatal",
        .mount_mode = "link",
        .local_node_id = "node-local",
        .preferred_provider_id = NULL,
        .required_caps = CEP_FED_TRANSPORT_CAP_RELIABLE |
                         CEP_FED_TRANSPORT_CAP_ORDERED |
                         CEP_FED_TRANSPORT_CAP_REMOTE_NET,
        .preferred_caps = 0,
        .allow_upd_latest = false,
        .deadline_beat = 0u,
    };
    munit_assert_true(cep_fed_transport_manager_configure_mount(&manager, &cfg, &callbacks, &mount));
    munit_assert_not_null(mount);

    munit_assert_true(cep_fed_transport_manager_close(&manager, mount, "unit-test-fatal"));

    char text[64] = {0};
    cepCell* telemetry_entry = fed_test_telemetry_entry(net_root, "peer-fatal", "link-fatal");
    munit_assert_not_null(telemetry_entry);
    munit_assert_uint64(fed_test_read_u64_field(telemetry_entry, "fatal_count"), >=, 1u);
    fed_test_read_text_field(telemetry_entry, "last_event", text, sizeof text);
    munit_assert_string_equal(text, "close");

    cepCell* ceh_entry = fed_test_ceh_entry(net_root, "peer-fatal", "tp_fatal");
    munit_assert_not_null(ceh_entry);
    fed_test_read_text_field(ceh_entry, "severity", text, sizeof text);
    munit_assert_string_equal(text, "error");
    fed_test_read_text_field(ceh_entry, "note", text, sizeof text);
    munit_assert_string_equal(text, "unit-test-fatal");
    munit_assert_uint64(fed_test_read_u64_field(ceh_entry, "beat"), !=, CEP_BEAT_INVALID);

    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

static void fed_test_write_bool(cepCell* parent, const char* tag, bool value) {
    cepCell* resolved = parent;
    munit_assert_true(cep_cell_require_dictionary_store(&resolved));
    cepDT field = fed_test_make_dt(tag);
    cepDT bool_type = cep_ops_make_dt("val/bool");
    uint8_t payload = value ? 1u : 0u;
    cepDT field_copy = field;
    munit_assert_not_null(cep_dict_add_value(resolved,
                                             &field_copy,
                                             &bool_type,
                                             &payload,
                                             sizeof payload,
                                             sizeof payload));
}

static void fed_test_write_u32(cepCell* parent, const char* tag, uint32_t value) {
    cepCell* resolved = parent;
    munit_assert_true(cep_cell_require_dictionary_store(&resolved));
    cepDT field = fed_test_make_dt(tag);
    cepDT num_type = cep_ops_make_dt("val/u32");
    uint32_t payload = value;
    cepDT field_copy = field;
    munit_assert_not_null(cep_dict_add_value(resolved,
                                             &field_copy,
                                             &num_type,
                                             &payload,
                                             sizeof payload,
                                             sizeof payload));
}

static void fed_test_write_u16(cepCell* parent, const char* tag, uint16_t value) {
    cepCell* resolved = parent;
    munit_assert_true(cep_cell_require_dictionary_store(&resolved));
    cepDT field = fed_test_make_dt(tag);
    cepDT num_type = cep_ops_make_dt("val/u16");
    uint16_t payload = value;
    cepDT field_copy = field;
    munit_assert_not_null(cep_dict_add_value(resolved,
                                             &field_copy,
                                             &num_type,
                                             &payload,
                                             sizeof payload,
                                             sizeof payload));
}

static void fed_test_write_u64(cepCell* parent, const char* tag, uint64_t value) {
    cepCell* resolved = parent;
    munit_assert_true(cep_cell_require_dictionary_store(&resolved));
    cepDT field = fed_test_make_dt(tag);
    cepDT num_type = cep_ops_make_dt("val/u64");
    uint64_t payload = value;
    cepDT field_copy = field;
    munit_assert_not_null(cep_dict_add_value(resolved,
                                             &field_copy,
                                             &num_type,
                                             &payload,
                                             sizeof payload,
                                             sizeof payload));
}

MunitResult test_fed_link_validator_success(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_link_organ_init(&manager, net_root));

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* link_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "link"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(link_root, "requests"));

    cepDT request_name = fed_test_make_dt("link_req");
    munit_assert_true(cep_dt_is_valid(&request_name));
    cepCell* request = cep_cell_ensure_dictionary_child(requests, &request_name, CEP_STORAGE_RED_BLACK_T);
    request = fed_test_require_dictionary(request);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","peer"), "peer-link");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mount"), "mount-link");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mode"), "link");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","local_node"), "node-local");

    cepCell* caps = cep_cell_ensure_dictionary_child(request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    caps = fed_test_require_dictionary(caps);
    cepCell* required_caps = cep_cell_ensure_dictionary_child(caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    required_caps = fed_test_require_dictionary(required_caps);
    fed_test_write_bool(required_caps, "reliable", true);
    fed_test_write_bool(required_caps, "ordered", true);
    fed_test_write_bool(required_caps, "remote_net", true);

    cepPath* request_path = NULL;
    munit_assert_true(cep_cell_path(request, &request_path));

    int rc = cep_fed_link_validator(NULL, request_path);
    char state_text[64] = {0};
    char error_text[64] = {0};
    fed_test_try_read_text_field(request, "state", state_text, sizeof state_text);
    fed_test_try_read_text_field(request, "error_note", error_text, sizeof error_text);
    munit_assert_int(rc, ==, CEP_ENZYME_SUCCESS);

    char text[64] = {0};
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");
    fed_test_read_text_field(request, "provider", text, sizeof text);
    munit_assert_size(strlen(text), >, (size_t)0);

    rc = cep_fed_link_destructor(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_SUCCESS);
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "removed");

    cepCell* telemetry_root = fed_test_lookup_child(net_root, "telemetry");
    if (telemetry_root) {
        telemetry_root = fed_test_require_dictionary(telemetry_root);
        cepCell* telemetry_peer = fed_test_lookup_child(telemetry_root, "peer-dup");
        if (telemetry_peer) {
            telemetry_peer = fed_test_require_dictionary(telemetry_peer);
            cepCell* telemetry_entry = fed_test_lookup_child(telemetry_peer, "mount-dup");
            if (telemetry_entry) {
                telemetry_entry = fed_test_require_dictionary(telemetry_entry);
                fed_test_read_text_field(telemetry_entry, "last_event", text, sizeof text);
                munit_assert_string_equal(text, "close");
                fed_test_read_text_field(telemetry_entry, "provider", text, sizeof text);
                munit_assert_string_equal(text, "pipe");
                munit_assert_false(fed_test_read_bool_field(telemetry_entry, "bp_flag"));
            } else {
                munit_assert_null(telemetry_entry);
            }
        }
    }

    cepCell* peers_root = fed_test_lookup_child(net_root, "peers");
    if (peers_root) {
        peers_root = fed_test_require_dictionary(peers_root);
        cepCell* peer_entry = fed_test_lookup_child(peers_root, "peer-dup");
        if (peer_entry) {
            peer_entry = fed_test_require_dictionary(peer_entry);
            cepCell* ceh_root = fed_test_lookup_child(peer_entry, "ceh");
            if (ceh_root) {
                ceh_root = fed_test_require_dictionary(ceh_root);
                munit_assert_null(fed_test_lookup_child(ceh_root, "tp_fatal"));
                munit_assert_null(fed_test_lookup_child(ceh_root, "tp_backpr"));
            }
        }
    }

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_invoke_validator_rejects_long_names(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();

    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_invoke_organ_init(&manager, net_root));

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* invoke_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "invoke"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(invoke_root, "requests"));

    cepDT request_name = fed_test_make_dt("inv_long");
    cepCell* request = cep_cell_ensure_dictionary_child(requests, &request_name, CEP_STORAGE_RED_BLACK_T);
    request = fed_test_require_dictionary(request);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","peer"), "peer-invoke-xx");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mount"), "inv-mnt");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","local_node"), "node-local");

    cepPath* request_path = NULL;
    munit_assert_true(cep_cell_path(request, &request_path));

    int rc = cep_fed_invoke_validator(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_FATAL);

    char text[64] = {0};
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "error");
    fed_test_read_text_field(request, "error_note", text, sizeof text);
    munit_assert_string_equal(text, "invalid peer identifier");

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_invoke_success(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    fed_test_ensure_invoke_handler();
    g_fed_invoke_handler_calls = 0;

    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_invoke_organ_init(&manager, net_root));

    cepCell* request = NULL;
    cepPath* request_path = NULL;
    fed_test_setup_invoke_request(net_root, &manager, "inv_req", &request, &request_path);

    const cepFedInvokeRequest* ctx = cep_fed_invoke_request_find("peer-invoke", "inv-mnt");
    munit_assert_not_null(ctx);

    FedInvokePathBuf signal_buf = {0};
    FedInvokePathBuf target_buf = {0};
    const char* signal_segments[] = { "sig:test_invoke" };
    const char* target_segments[] = { "rt:test_invoke" };
    const cepPath* signal_path = fed_test_build_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));
    const cepPath* target_path = fed_test_build_path(&target_buf, target_segments, cep_lengthof(target_segments));

    FedInvokeCompletion completion = {0};
    cepFedInvokeSubmission submission = {
        .signal_path = signal_path,
        .target_path = target_path,
        .timeout_beats = 4u,
        .on_complete = fed_test_invoke_completion,
        .user_ctx = &completion,
    };

    munit_assert_true(cep_fed_invoke_request_submit(ctx, &submission));

    uint8_t request_buffer[256];
    size_t request_len = 0u;
    cepFedFrameMode request_mode = CEP_FED_FRAME_MODE_DATA;
    munit_assert_true(cep_fed_transport_mock_pop_outbound("peer-invoke",
                                                          "inv-mnt",
                                                          request_buffer,
                                                          sizeof request_buffer,
                                                          &request_len,
                                                          &request_mode));

    cep_fed_invoke_process_frame((cepFedInvokeRequest*)ctx,
                                 request_buffer,
                                 request_len,
                                 request_mode);

    fed_test_pop_and_process_invoke_response(ctx);

    (void)cep_heartbeat_step();
    (void)cep_heartbeat_step();

    munit_assert_int(g_fed_invoke_handler_calls, ==, 1);
    munit_assert_true(completion.completed);
    munit_assert_true(completion.success);

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_invoke_reconfigure_cancels_pending(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    fed_test_ensure_invoke_handler();
    g_fed_invoke_handler_calls = 0;

    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_invoke_organ_init(&manager, net_root));

    cepCell* request = NULL;
    cepPath* request_path = NULL;
    fed_test_setup_invoke_request(net_root, &manager, "inv_reconf", &request, &request_path);

    const cepFedInvokeRequest* ctx = cep_fed_invoke_request_find("peer-invoke", "inv-mnt");
    munit_assert_not_null(ctx);

    FedInvokePathBuf signal_buf = {0};
    FedInvokePathBuf target_buf = {0};
    const char* signal_segments[] = { "sig:test_invoke" };
    const char* target_segments[] = { "rt:test_invoke" };
    const cepPath* signal_path = fed_test_build_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));
    const cepPath* target_path = fed_test_build_path(&target_buf, target_segments, cep_lengthof(target_segments));

    FedInvokeCompletion completion = {0};
    cepFedInvokeSubmission submission = {
        .signal_path = signal_path,
        .target_path = target_path,
        .timeout_beats = 6u,
        .on_complete = fed_test_invoke_completion,
        .user_ctx = &completion,
    };

    munit_assert_true(cep_fed_invoke_request_submit(ctx, &submission));
    munit_assert_false(completion.completed);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","pref_prov"), "tcp");
    munit_assert_int(cep_fed_invoke_validator(NULL, request_path), ==, CEP_ENZYME_SUCCESS);

    munit_assert_true(completion.completed);
    munit_assert_false(completion.success);

    char text[64] = {0};
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");
    fed_test_read_text_field(request, "provider", text, sizeof text);
    munit_assert_string_equal(text, "tcp");

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_invoke_dual_runtime_happy_path(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    g_fed_invoke_handler_calls = 0;

    FedDualRuntimeCtx ctx_a = {0};
    FedDualRuntimeCtx ctx_b = {0};
    FedDualMountState mounts_a = {0};
    FedDualMountState mounts_b = {0};
    FedDualRuntimePair pair = {0};

    fed_dual_runtime_prepare_pair(&pair, &ctx_a, &ctx_b, &mounts_a, &mounts_b);

    cepRuntime* previous = cep_runtime_set_active(ctx_a.runtime);
    FedInvokePathBuf signal_buf = {0};
    FedInvokePathBuf target_buf = {0};
    const char* signal_segments[] = { "sig:test_invoke" };
    const char* target_segments[] = { "rt:test_invoke" };
    const cepPath* signal_path = fed_test_build_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));
    const cepPath* target_path = fed_test_build_path(&target_buf, target_segments, cep_lengthof(target_segments));

    FedInvokeCompletion completion = {0};
    cepFedInvokeSubmission submission = {
        .signal_path = signal_path,
        .target_path = target_path,
        .timeout_beats = 6u,
        .on_complete = fed_test_invoke_completion,
        .user_ctx = &completion,
    };

    munit_assert_true(cep_fed_invoke_request_submit(mounts_a.invoke_ctx, &submission));

    uint8_t request_buffer[256];
    size_t request_len = 0u;
    cepFedFrameMode request_mode = CEP_FED_FRAME_MODE_DATA;
    munit_assert_true(cep_fed_transport_mock_pop_outbound(FED_DUAL_PEER_B,
                                                          FED_DUAL_INVOKE_MOUNT,
                                                          request_buffer,
                                                          sizeof request_buffer,
                                                          &request_len,
                                                          &request_mode));
    cep_runtime_restore_active(previous);

    previous = cep_runtime_set_active(ctx_b.runtime);
    munit_assert_true(cep_fed_invoke_organ_init(&ctx_b.manager, ctx_b.net_root));
    cep_fed_invoke_process_frame((cepFedInvokeRequest*)mounts_b.invoke_ctx,
                                 request_buffer,
                                 request_len,
                                 request_mode);

    uint8_t response_buffer[256];
    size_t response_len = 0u;
    cepFedFrameMode response_mode = CEP_FED_FRAME_MODE_DATA;
    munit_assert_true(cep_fed_transport_mock_pop_outbound(FED_DUAL_PEER_A,
                                                          FED_DUAL_INVOKE_MOUNT,
                                                          response_buffer,
                                                          sizeof response_buffer,
                                                          &response_len,
                                                          &response_mode));
    (void)cep_heartbeat_step();
    cep_runtime_restore_active(previous);

    previous = cep_runtime_set_active(ctx_a.runtime);
    munit_assert_true(cep_fed_invoke_organ_init(&ctx_a.manager, ctx_a.net_root));
    cep_fed_invoke_process_frame((cepFedInvokeRequest*)mounts_a.invoke_ctx,
                                 response_buffer,
                                 response_len,
                                 response_mode);
    (void)cep_heartbeat_step();
    (void)cep_heartbeat_step();
    cep_runtime_restore_active(previous);

    munit_assert_true(completion.completed);
    munit_assert_true(completion.success);

    previous = cep_runtime_set_active(ctx_a.runtime);
    char text[64] = {0};
    fed_test_read_text_field(mounts_a.invoke_request, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");
    fed_test_read_text_field(mounts_a.invoke_request, "provider", text, sizeof text);
    munit_assert_string_equal(text, "mock");
    cep_runtime_restore_active(previous);

    previous = cep_runtime_set_active(ctx_b.runtime);
    fed_test_read_text_field(mounts_b.invoke_request, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");
    fed_test_read_text_field(mounts_b.invoke_request, "provider", text, sizeof text);
    munit_assert_string_equal(text, "mock");
    cep_runtime_restore_active(previous);

    fed_dual_runtime_cleanup_pair(&pair, &ctx_a, &ctx_b, &mounts_a, &mounts_b);
    return MUNIT_OK;
}

/* test_fed_link_dual_runtime_provider_fatal closes a runtime-A mount with a fatal
   reason and verifies CEI telemetry/diagnostics reflect the event for peer B. */
MunitResult test_fed_link_dual_runtime_provider_fatal(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    FedDualRuntimeCtx ctx_a = {0};
    FedDualRuntimeCtx ctx_b = {0};
    FedDualMountState mounts_a = {0};
    FedDualMountState mounts_b = {0};
    FedDualRuntimePair pair = {0};

    fed_dual_runtime_prepare_pair(&pair, &ctx_a, &ctx_b, &mounts_a, &mounts_b);

    cepRuntime* previous = cep_runtime_set_active(ctx_a.runtime);
    cepFedTransportMountConfig cfg = {
        .peer_id = FED_DUAL_PEER_B,
        .mount_id = "fatal-link",
        .mount_mode = "link",
        .local_node_id = FED_DUAL_NODE_A,
        .preferred_provider_id = NULL,
        .required_caps = CEP_FED_TRANSPORT_CAP_RELIABLE |
                         CEP_FED_TRANSPORT_CAP_ORDERED |
                         CEP_FED_TRANSPORT_CAP_REMOTE_NET,
        .preferred_caps = 0u,
        .allow_upd_latest = false,
        .deadline_beat = 0u,
    };
    cepFedTransportManagerMount* fatal_mount = NULL;
    munit_assert_true(cep_fed_transport_manager_configure_mount(&ctx_a.manager,
                                                                &cfg,
                                                                NULL,
                                                                &fatal_mount));
    munit_assert_not_null(fatal_mount);
    const char* fatal_reason = "provider-fatal-test";
    munit_assert_true(cep_fed_transport_manager_close(&ctx_a.manager,
                                                      fatal_mount,
                                                      fatal_reason));
    (void)cep_heartbeat_step();
    cepCell* ceh_entry = fed_test_ceh_entry(ctx_a.net_root, FED_DUAL_PEER_B, "tp_fatal");
    munit_assert_not_null(ceh_entry);
    char text[64] = {0};
    fed_test_read_text_field(ceh_entry, "severity", text, sizeof text);
    munit_assert_string_equal(text, "error");
    fed_test_read_text_field(ceh_entry, "note", text, sizeof text);
    munit_assert_size(strlen(text), >, (size_t)0);
    munit_assert_int(strncmp(text, fatal_reason, strlen(text)), ==, 0);
    cep_runtime_restore_active(previous);

    fed_dual_runtime_cleanup_pair(&pair, &ctx_a, &ctx_b, &mounts_a, &mounts_b);
    return MUNIT_OK;
}

/* test_fed_invoke_dual_runtime_timeout verifies that cross-runtime invocation
   requests honour their beat deadlines by having runtime B drop the frame and
   confirming runtime A emits the timeout CEI topic and marks the submission
   as failed. */
MunitResult test_fed_invoke_dual_runtime_timeout(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    g_fed_invoke_handler_calls = 0;

    FedDualRuntimeCtx ctx_a = {0};
    FedDualRuntimeCtx ctx_b = {0};
    FedDualMountState mounts_a = {0};
    FedDualMountState mounts_b = {0};
    FedDualRuntimePair pair = {0};

    fed_dual_runtime_prepare_pair(&pair, &ctx_a, &ctx_b, &mounts_a, &mounts_b);

    cepRuntime* previous = cep_runtime_set_active(ctx_a.runtime);
    FedInvokePathBuf signal_buf = {0};
    FedInvokePathBuf target_buf = {0};
    const char* signal_segments[] = { "sig:test_invoke" };
    const char* target_segments[] = { "rt:test_invoke" };
    const cepPath* signal_path = fed_test_build_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));
    const cepPath* target_path = fed_test_build_path(&target_buf, target_segments, cep_lengthof(target_segments));

    FedInvokeCompletion completion = {0};
    cepFedInvokeSubmission submission = {
        .signal_path = signal_path,
        .target_path = target_path,
        .timeout_beats = 3u,
        .on_complete = fed_test_invoke_completion,
        .user_ctx = &completion,
    };

    munit_assert_true(cep_fed_invoke_request_submit(mounts_a.invoke_ctx, &submission));

    uint8_t request_buffer[256];
    size_t request_len = 0u;
    cepFedFrameMode request_mode = CEP_FED_FRAME_MODE_DATA;
    munit_assert_true(cep_fed_transport_mock_pop_outbound(FED_DUAL_PEER_B,
                                                          FED_DUAL_INVOKE_MOUNT,
                                                          request_buffer,
                                                          sizeof request_buffer,
                                                          &request_len,
                                                          &request_mode));
    cep_runtime_restore_active(previous);

    previous = cep_runtime_set_active(ctx_a.runtime);
    for (unsigned i = 0u; i < 12u; ++i) {
        (void)cep_heartbeat_step();
    }
    (void)cep_fed_invoke_timeout_enzyme(NULL, NULL);
    cep_runtime_restore_active(previous);

    munit_assert_true(completion.completed);
    munit_assert_false(completion.success);
    munit_assert_int(g_fed_invoke_handler_calls, ==, 0);

    cep_runtime_restore_active(previous);

    fed_dual_runtime_cleanup_pair(&pair, &ctx_a, &ctx_b, &mounts_a, &mounts_b);
    return MUNIT_OK;
}

MunitResult test_fed_invoke_timeout(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    fed_test_ensure_invoke_handler();
    g_fed_invoke_handler_calls = 0;

    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_invoke_organ_init(&manager, net_root));

    cepCell* request = NULL;
    cepPath* request_path = NULL;
    fed_test_setup_invoke_request(net_root, &manager, "inv_to", &request, &request_path);

    const cepFedInvokeRequest* ctx = cep_fed_invoke_request_find("peer-invoke", "inv-mnt");
    munit_assert_not_null(ctx);

    FedInvokePathBuf signal_buf = {0};
    FedInvokePathBuf target_buf = {0};
    const char* signal_segments[] = { "sig:test_invoke" };
    const char* target_segments[] = { "rt:test_invoke" };
    const cepPath* signal_path = fed_test_build_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));
    const cepPath* target_path = fed_test_build_path(&target_buf, target_segments, cep_lengthof(target_segments));

    FedInvokeCompletion completion = {0};
    cepFedInvokeSubmission submission = {
        .signal_path = signal_path,
        .target_path = target_path,
        .timeout_beats = 2u,
        .on_complete = fed_test_invoke_completion,
        .user_ctx = &completion,
    };

    munit_assert_true(cep_fed_invoke_request_submit(ctx, &submission));

    uint8_t request_buffer[256];
    size_t request_len = 0u;
    cepFedFrameMode request_mode = CEP_FED_FRAME_MODE_DATA;
    munit_assert_true(cep_fed_transport_mock_pop_outbound("peer-invoke",
                                                          "inv-mnt",
                                                          request_buffer,
                                                          sizeof request_buffer,
                                                          &request_len,
                                                          &request_mode));

    /* Drop the request without responding to trigger timeout. */

    for (unsigned i = 0; i < 4u; ++i) {
        (void)cep_heartbeat_step();
    }

    (void)cep_fed_invoke_timeout_enzyme(NULL, NULL);

    munit_assert_int(g_fed_invoke_handler_calls, ==, 0);
    munit_assert_true(completion.completed);
    munit_assert_false(completion.success);

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_invoke_reject(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    fed_test_ensure_invoke_handler();
    g_fed_invoke_handler_calls = 0;

    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_invoke_organ_init(&manager, net_root));

    cepCell* request = NULL;
    cepPath* request_path = NULL;
    fed_test_setup_invoke_request(net_root, &manager, "inv_rej", &request, &request_path);

    const cepFedInvokeRequest* ctx = cep_fed_invoke_request_find("peer-invoke", "inv-mnt");
    munit_assert_not_null(ctx);

    FedInvokePathBuf signal_buf = {0};
    FedInvokePathBuf target_buf = {0};
    const char* signal_segments[] = { "sig:test_invoke" };
    const char* target_segments[] = { "rt:test_invoke" };
    const cepPath* signal_path = fed_test_build_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));
    const cepPath* target_path = fed_test_build_path(&target_buf, target_segments, cep_lengthof(target_segments));

    FedInvokeCompletion completion = {0};
    cepFedInvokeSubmission submission = {
        .signal_path = signal_path,
        .target_path = target_path,
        .timeout_beats = 4u,
        .on_complete = fed_test_invoke_completion,
        .user_ctx = &completion,
    };

    munit_assert_true(cep_fed_invoke_request_submit(ctx, &submission));

    uint8_t request_buffer[256];
    size_t request_len = 0u;
    cepFedFrameMode request_mode = CEP_FED_FRAME_MODE_DATA;
    munit_assert_true(cep_fed_transport_mock_pop_outbound("peer-invoke",
                                                          "inv-mnt",
                                                          request_buffer,
                                                          sizeof request_buffer,
                                                          &request_len,
                                                          &request_mode));

    /* Simulate provider rejection by sending a response with reject status. */
    FedInvokeFrameHeader header = {
        .kind = FED_INVOKE_FRAME_RESPONSE,
        .status = FED_INVOKE_STATUS_REJECT,
        .signal_segments = 0u,
        .target_segments = 0u,
        .invocation_id = ((const FedInvokeFrameHeader*)request_buffer)->invocation_id,
    };

    cep_fed_invoke_process_frame((cepFedInvokeRequest*)ctx,
                                 (const uint8_t*)&header,
                                 sizeof header,
                                 CEP_FED_FRAME_MODE_DATA);

    munit_assert_true(completion.completed);
    munit_assert_false(completion.success);
    munit_assert_int(g_fed_invoke_handler_calls, ==, 0);

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_link_validator_duplicate_request(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_link_organ_init(&manager, net_root));

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* link_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "link"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(link_root, "requests"));

    cepDT request_name = fed_test_make_dt("link_dup");
    munit_assert_true(cep_dt_is_valid(&request_name));
    cepCell* request = cep_cell_ensure_dictionary_child(requests, &request_name, CEP_STORAGE_RED_BLACK_T);
    request = fed_test_require_dictionary(request);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","peer"), "peer-dup");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mount"), "mount-dup");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mode"), "link");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","local_node"), "node-local");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","pref_prov"), "tcp");

    cepCell* caps = cep_cell_ensure_dictionary_child(request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    caps = fed_test_require_dictionary(caps);
    cepCell* required_caps = cep_cell_ensure_dictionary_child(caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    required_caps = fed_test_require_dictionary(required_caps);
    fed_test_write_bool(required_caps, "reliable", true);
    fed_test_write_bool(required_caps, "ordered", true);

    cepPath* request_path = NULL;
    munit_assert_true(cep_cell_path(request, &request_path));

    int rc = cep_fed_link_validator(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_SUCCESS);

    char text[64] = {0};
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");
    fed_test_read_text_field(request, "provider", text, sizeof text);
    munit_assert_string_equal(text, "tcp");

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","pref_prov"), "pipe");

    rc = cep_fed_link_validator(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_SUCCESS);
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");
    fed_test_read_text_field(request, "provider", text, sizeof text);
    munit_assert_string_equal(text, "pipe");

    rc = cep_fed_link_destructor(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_SUCCESS);
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "removed");

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_link_validator_missing_peer(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_link_organ_init(&manager, net_root));

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* link_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "link"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(link_root, "requests"));

    cepDT request_name = fed_test_make_dt("bad_link");
    munit_assert_true(cep_dt_is_valid(&request_name));
    cepCell* request = cep_cell_ensure_dictionary_child(requests, &request_name, CEP_STORAGE_RED_BLACK_T);
    request = fed_test_require_dictionary(request);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mount"), "mount-bad");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mode"), "link");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","local_node"), "node-local");

    cepPath* request_path = NULL;
    munit_assert_true(cep_cell_path(request, &request_path));

    int rc = cep_fed_link_validator(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_FATAL);

    char text[64] = {0};
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "error");
    fed_test_read_text_field(request, "error_note", text, sizeof text);
    munit_assert_string_equal(text, "missing required fields");
    char provider_text[32] = {0};
    munit_assert_false(fed_test_try_read_text_field(request, "provider", provider_text, sizeof provider_text));

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_mirror_validator_success(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_mirror_organ_init(&manager, net_root));

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* mirror_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "mirror"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(mirror_root, "requests"));

    cepDT request_name = fed_test_make_dt("mirror_ok");
    cepCell* request = cep_cell_ensure_dictionary_child(requests, &request_name, CEP_STORAGE_RED_BLACK_T);
    request = fed_test_require_dictionary(request);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","peer"), "peer_mir");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mount"), "mount_mir");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mode"), "mirror");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","local_node"), "node-local");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","src_peer"), "peer-source");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","src_chan"), "channel-alpha");

    cepCell* caps = cep_cell_ensure_dictionary_child(request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    caps = fed_test_require_dictionary(caps);
    cepCell* required_caps = cep_cell_ensure_dictionary_child(caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    required_caps = fed_test_require_dictionary(required_caps);
    fed_test_write_bool(required_caps, "reliable", true);
    fed_test_write_bool(required_caps, "ordered", true);
    fed_test_write_bool(required_caps, "remote_net", true);

    cepCell* bundle = cep_cell_ensure_dictionary_child(request, CEP_DTAW("CEP","bundle"), CEP_STORAGE_RED_BLACK_T);
    bundle = fed_test_require_dictionary(bundle);
    fed_test_write_u32(bundle, "beat_window", 2u);
    fed_test_write_u16(bundle, "max_infl", 2u);
    (void)cep_cell_put_text(bundle, CEP_DTAW("CEP","commit_mode"), "stream");

    cepPath* request_path = NULL;
    munit_assert_true(cep_cell_path(request, &request_path));

    int rc = cep_fed_mirror_validator(NULL, request_path);
    if (rc != CEP_ENZYME_SUCCESS) {
        char note[96] = {0};
        fed_test_try_read_text_field(request, "error_note", note, sizeof note);
        munit_errorf("mirror validator failed: %s", note);
    }

    char text[64] = {0};
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");
    fed_test_read_text_field(request, "provider", text, sizeof text);
    munit_assert_size(strlen(text), >, (size_t)0);

    for (unsigned i = 0; i < 8u; ++i) {
        munit_assert_true(cep_heartbeat_step());
    }

    uint64_t last_seq = fed_test_read_u64_field(request, "bundle_seq");
    munit_assert_uint64(last_seq, >=, 1u);
    uint64_t last_beat = fed_test_read_u64_field(request, "commit_beat");
    munit_assert_uint64(last_beat, !=, 0u);
    char resume_text[64] = {0};
    fed_test_try_read_text_field(request, "pend_resum", resume_text, sizeof resume_text);
    munit_assert_string_equal(resume_text, "");

    rc = cep_fed_mirror_destructor(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_SUCCESS);
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "removed");

    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_mirror_validator_conflict(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_mirror_organ_init(&manager, net_root));

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* mirror_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "mirror"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(mirror_root, "requests"));

    cepDT first_name = fed_test_make_dt("mir_conf_a");
    cepCell* first = cep_cell_ensure_dictionary_child(requests, &first_name, CEP_STORAGE_RED_BLACK_T);
    first = fed_test_require_dictionary(first);
    (void)cep_cell_put_text(first, CEP_DTAW("CEP","peer"), "peer_conf");
    (void)cep_cell_put_text(first, CEP_DTAW("CEP","mount"), "mount_conf");
    (void)cep_cell_put_text(first, CEP_DTAW("CEP","mode"), "mirror");
    (void)cep_cell_put_text(first, CEP_DTAW("CEP","local_node"), "node-local");
    (void)cep_cell_put_text(first, CEP_DTAW("CEP","src_peer"), "peer-source");
    (void)cep_cell_put_text(first, CEP_DTAW("CEP","src_chan"), "channel-alpha");

    cepCell* first_caps = cep_cell_ensure_dictionary_child(first, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    first_caps = fed_test_require_dictionary(first_caps);
    cepCell* first_required = cep_cell_ensure_dictionary_child(first_caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    first_required = fed_test_require_dictionary(first_required);
    fed_test_write_bool(first_required, "reliable", true);
    fed_test_write_bool(first_required, "ordered", true);

    cepCell* first_bundle = cep_cell_ensure_dictionary_child(first, CEP_DTAW("CEP","bundle"), CEP_STORAGE_RED_BLACK_T);
    first_bundle = fed_test_require_dictionary(first_bundle);
    fed_test_write_u32(first_bundle, "beat_window", 1u);
    fed_test_write_u16(first_bundle, "max_infl", 1u);
    (void)cep_cell_put_text(first_bundle, CEP_DTAW("CEP","commit_mode"), "batch");

    cepPath* first_path = NULL;
    munit_assert_true(cep_cell_path(first, &first_path));
    int rc = cep_fed_mirror_validator(NULL, first_path);
    munit_assert_int(rc, ==, CEP_ENZYME_SUCCESS);

    cepDT second_name = fed_test_make_dt("mir_conf_b");
    cepCell* second = cep_cell_ensure_dictionary_child(requests, &second_name, CEP_STORAGE_RED_BLACK_T);
    second = fed_test_require_dictionary(second);
    (void)cep_cell_put_text(second, CEP_DTAW("CEP","peer"), "peer_conf");
    (void)cep_cell_put_text(second, CEP_DTAW("CEP","mount"), "mount_conf");
    (void)cep_cell_put_text(second, CEP_DTAW("CEP","mode"), "mirror");
    (void)cep_cell_put_text(second, CEP_DTAW("CEP","local_node"), "node-local");
    (void)cep_cell_put_text(second, CEP_DTAW("CEP","src_peer"), "peer-source");
    (void)cep_cell_put_text(second, CEP_DTAW("CEP","src_chan"), "channel-beta");

    cepCell* second_bundle = cep_cell_ensure_dictionary_child(second, CEP_DTAW("CEP","bundle"), CEP_STORAGE_RED_BLACK_T);
    second_bundle = fed_test_require_dictionary(second_bundle);
    fed_test_write_u32(second_bundle, "beat_window", 1u);
    fed_test_write_u16(second_bundle, "max_infl", 1u);

    cepPath* second_path = NULL;
    munit_assert_true(cep_cell_path(second, &second_path));
    rc = cep_fed_mirror_validator(NULL, second_path);
    munit_assert_int(rc, ==, CEP_ENZYME_FATAL);

    char text[64] = {0};
    fed_test_read_text_field(second, "state", text, sizeof text);
    munit_assert_string_equal(text, "error");
    fed_test_read_text_field(second, "error_note", text, sizeof text);
    munit_assert_string_equal(text, "mirror mount already active");

    fed_test_read_text_field(first, "state", text, sizeof text);
    munit_assert_string_equal(text, "active");

    (void)cep_fed_mirror_destructor(NULL, second_path);
    cep_free(second_path);
    (void)cep_fed_mirror_destructor(NULL, first_path);
    cep_free(first_path);

    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_fed_mirror_validator_deadline(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    fed_test_prepare_providers();
    cepCell* net_root = fed_test_net_root();
    cepFedTransportManager manager;
    munit_assert_true(cep_fed_transport_manager_init(&manager, net_root));
    munit_assert_true(cep_fed_mirror_organ_init(&manager, net_root));

    cepCell* organs = fed_test_require_dictionary(fed_test_lookup_child(net_root, "organs"));
    cepCell* mirror_root = fed_test_require_dictionary(fed_test_lookup_child(organs, "mirror"));
    cepCell* requests = fed_test_require_dictionary(fed_test_lookup_child(mirror_root, "requests"));

    cepDT request_name = fed_test_make_dt("mir_dead");
    cepCell* request = cep_cell_ensure_dictionary_child(requests, &request_name, CEP_STORAGE_RED_BLACK_T);
    request = fed_test_require_dictionary(request);

    (void)cep_cell_put_text(request, CEP_DTAW("CEP","peer"), "peer_dead");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mount"), "mount_dead");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","mode"), "mirror");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","local_node"), "node-local");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","src_peer"), "peer-source");
    (void)cep_cell_put_text(request, CEP_DTAW("CEP","src_chan"), "channel-deadline");

    cepCell* caps = cep_cell_ensure_dictionary_child(request, CEP_DTAW("CEP","caps"), CEP_STORAGE_RED_BLACK_T);
    caps = fed_test_require_dictionary(caps);
    cepCell* required_caps = cep_cell_ensure_dictionary_child(caps, CEP_DTAW("CEP","required"), CEP_STORAGE_RED_BLACK_T);
    required_caps = fed_test_require_dictionary(required_caps);
    fed_test_write_bool(required_caps, "reliable", true);

    cepCell* bundle = cep_cell_ensure_dictionary_child(request, CEP_DTAW("CEP","bundle"), CEP_STORAGE_RED_BLACK_T);
    bundle = fed_test_require_dictionary(bundle);
    fed_test_write_u32(bundle, "beat_window", 1u);
    fed_test_write_u16(bundle, "max_infl", 1u);
    (void)cep_cell_put_text(bundle, CEP_DTAW("CEP","commit_mode"), "manual");

    (void)cep_heartbeat_current();
    fed_test_write_u64(request, "deadline", 0u);

    cepPath* request_path = NULL;
    munit_assert_true(cep_cell_path(request, &request_path));

    int rc = cep_fed_mirror_validator(NULL, request_path);
    munit_assert_int(rc, ==, CEP_ENZYME_FATAL);

    char text[64] = {0};
    fed_test_read_text_field(request, "state", text, sizeof text);
    munit_assert_string_equal(text, "error");
    fed_test_read_text_field(request, "error_note", text, sizeof text);
    munit_assert_string_equal(text, "deadline expired before activation");

    (void)cep_fed_mirror_destructor(NULL, request_path);
    cep_free(request_path);
    cep_fed_transport_manager_teardown(&manager);
    test_runtime_shutdown();
    return MUNIT_OK;
}
