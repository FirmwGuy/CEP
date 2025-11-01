/* Federation transport manager exercises: these tests drive the stub transport providers
   to ensure capability negotiation, upd_latest coalescing, and inbound delivery work
   without relying on real network I/O. */

#include "test.h"

#include "cep_cell.h"
#include "cep_namepool.h"
#include "fed_transport_manager.h"
#include "fed_transport_providers.h"

typedef struct {
    unsigned ready_events;
    unsigned backpressure_events;
    unsigned fatal_events;
    unsigned frames;
    uint8_t  last_frame;
    cepFedFrameMode last_mode;
} FedTransportHooks;

static void fed_test_bootstrap_runtime(void) {
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
