/* Federation transport manager exercises: these tests drive the stub transport providers
   to ensure capability negotiation, upd_latest coalescing, and inbound delivery work
   without relying on real network I/O. */

#include "test.h"

#include "cep_cell.h"
#include "cep_namepool.h"
#include "cep_ops.h"
#include "cep_heartbeat.h"
#include "fed_transport_manager.h"
#include "fed_transport_providers.h"
#include "fed_link_organ.h"

#include <string.h>

typedef struct {
    unsigned ready_events;
    unsigned backpressure_events;
    unsigned fatal_events;
    unsigned frames;
    uint8_t  last_frame;
    cepFedFrameMode last_mode;
} FedTransportHooks;

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
    cepDT type = cep_ops_make_dt("val/text");
    if (cep_dt_compare(&data->dt, &type) != 0) {
        munit_assert_int(cep_dt_compare(&data->dt, CEP_DTAW("CEP", "text")), ==, 0);
    }
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
