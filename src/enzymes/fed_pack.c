#include "fed_pack.h"

#include "fed_transport_manager.h"
#include "fed_link_organ.h"
#include "fed_mirror_organ.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_cei.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_organ.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_net_name,         CEP_ACRO("CEP"), CEP_WORD("net"));
CEP_DEFINE_STATIC_DT(dt_peers_name,       CEP_ACRO("CEP"), CEP_WORD("peers"));
CEP_DEFINE_STATIC_DT(dt_catalog_name,     CEP_ACRO("CEP"), CEP_WORD("catalog"));
CEP_DEFINE_STATIC_DT(dt_telemetry_name,   CEP_ACRO("CEP"), CEP_WORD("telemetry"));
CEP_DEFINE_STATIC_DT(dt_organs_name,      CEP_ACRO("CEP"), CEP_WORD("organs"));
CEP_DEFINE_STATIC_DT(dt_discovery_name,   CEP_ACRO("CEP"), CEP_WORD("discovery"));
CEP_DEFINE_STATIC_DT(dt_health_name,      CEP_ACRO("CEP"), CEP_WORD("health"));
CEP_DEFINE_STATIC_DT(dt_link_name,        CEP_ACRO("CEP"), CEP_WORD("link"));
CEP_DEFINE_STATIC_DT(dt_mirror_name,      CEP_ACRO("CEP"), CEP_WORD("mirror"));
CEP_DEFINE_STATIC_DT(dt_spec_name,        CEP_ACRO("CEP"), CEP_WORD("spec"));
CEP_DEFINE_STATIC_DT(dt_kind_field_name,  CEP_ACRO("CEP"), CEP_WORD("kind"));
CEP_DEFINE_STATIC_DT(dt_label_field_name, CEP_ACRO("CEP"), CEP_WORD("label"));
CEP_DEFINE_STATIC_DT(dt_store_field_name, CEP_ACRO("CEP"), CEP_WORD("store"));
CEP_DEFINE_STATIC_DT(dt_validator_field_name, CEP_ACRO("CEP"), CEP_WORD("validator"));
CEP_DEFINE_STATIC_DT(dt_destructor_field_name, CEP_ACRO("CEP"), CEP_WORD("destructor"));
CEP_DEFINE_STATIC_DT(dt_services_name,    CEP_ACRO("CEP"), CEP_WORD("services"));
CEP_DEFINE_STATIC_DT(dt_ceh_name,         CEP_ACRO("CEP"), CEP_WORD("ceh"));
CEP_DEFINE_STATIC_DT(dt_peer_field_name,  CEP_ACRO("CEP"), CEP_WORD("peer"));
CEP_DEFINE_STATIC_DT(dt_mode_field_name,  CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_local_node_field_name, CEP_ACRO("CEP"), CEP_WORD("local_node"));
CEP_DEFINE_STATIC_DT(dt_provider_name,    CEP_ACRO("CEP"), CEP_WORD("provider"));
CEP_DEFINE_STATIC_DT(dt_mount_path_name,  CEP_ACRO("CEP"), CEP_WORD("mount_path"));
CEP_DEFINE_STATIC_DT(dt_upd_latest_name,  CEP_ACRO("CEP"), CEP_WORD("upd_latest"));
CEP_DEFINE_STATIC_DT(dt_ready_count_name, CEP_ACRO("CEP"), CEP_WORD("ready_count"));
CEP_DEFINE_STATIC_DT(dt_backpressure_count_name, CEP_ACRO("CEP"), CEP_WORD("bp_count"));
CEP_DEFINE_STATIC_DT(dt_fatal_count_name, CEP_ACRO("CEP"), CEP_WORD("fatal_count"));
CEP_DEFINE_STATIC_DT(dt_frame_count_name, CEP_ACRO("CEP"), CEP_WORD("frame_count"));
CEP_DEFINE_STATIC_DT(dt_last_frame_mode_name, CEP_ACRO("CEP"), CEP_WORD("last_mode"));
CEP_DEFINE_STATIC_DT(dt_last_frame_sample_name, CEP_ACRO("CEP"), CEP_WORD("last_sample"));
CEP_DEFINE_STATIC_DT(dt_backpressured_flag_name, CEP_ACRO("CEP"), CEP_WORD("bp_flag"));
CEP_DEFINE_STATIC_DT(dt_last_event_name,  CEP_ACRO("CEP"), CEP_WORD("last_event"));
CEP_DEFINE_STATIC_DT(dt_severity_field_name, CEP_ACRO("CEP"), CEP_WORD("severity"));
CEP_DEFINE_STATIC_DT(dt_note_field_name,  CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_beat_field_name,  CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_val_text,         CEP_ACRO("CEP"), CEP_WORD("val/text"));
CEP_DEFINE_STATIC_DT(dt_val_bool,         CEP_ACRO("CEP"), CEP_WORD("val/bool"));
CEP_DEFINE_STATIC_DT(dt_val_u64,          CEP_ACRO("CEP"), CEP_WORD("val/u64"));
CEP_DEFINE_STATIC_DT(dt_sev_error_name,   CEP_ACRO("sev"), CEP_WORD("error"));

static const char* const CEP_FED_TOPIC_SCHEMA         = "tp_schema";

static const char* const CEP_FED_DISCOVERY_KIND = "net_discovery";
static const char* const CEP_FED_DISCOVERY_LABEL = "organ.net_discovery.vl";
static const char* const CEP_FED_DISCOVERY_STORE = "organ/net_discovery";
static const char* const CEP_FED_DISCOVERY_VALIDATOR_SIGNAL = "org:net_discovery:vl";
static const char* const CEP_FED_DISCOVERY_DESTRUCTOR_SIGNAL = "org:net_discovery:dt";

static const char* const CEP_FED_HEALTH_KIND = "net_health";
static const char* const CEP_FED_HEALTH_LABEL = "organ.net_health.vl";
static const char* const CEP_FED_HEALTH_STORE = "organ/net_health";
static const char* const CEP_FED_HEALTH_VALIDATOR_SIGNAL = "org:net_health:vl";
static const char* const CEP_FED_HEALTH_DESTRUCTOR_SIGNAL = "org:net_health:dt";

static const char* const CEP_FED_LINK_KIND = "net_link";
static const char* const CEP_FED_LINK_LABEL = "organ.net_link.vl";
static const char* const CEP_FED_LINK_STORE = "organ/net_link";
static const char* const CEP_FED_LINK_VALIDATOR_SIGNAL = "org:net_link:vl";
static const char* const CEP_FED_LINK_DESTRUCTOR_SIGNAL = "org:net_link:dt";

static const char* const CEP_FED_MIRROR_KIND = "net_mirror";
static const char* const CEP_FED_MIRROR_LABEL = "organ.net_mirror.vl";
static const char* const CEP_FED_MIRROR_STORE = "organ/net_mirror";
static const char* const CEP_FED_MIRROR_VALIDATOR_SIGNAL = "org:net_mirror:vl";
static const char* const CEP_FED_MIRROR_DESTRUCTOR_SIGNAL = "org:net_mirror:dt";

static cepFedTransportManager g_fed_transport_manager;
static bool g_fed_transport_manager_ready = false;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[1];
} cepFedPackPath;

enum {
    CEP_FED_NAME_MAX = 64,
};

static void cep_fed_pack_emit_issue(const char* topic,
                                    const char* note,
                                    cepCell* subject) {
    if (!topic || !note) {
        return;
    }
    cepCeiRequest req = {0};
    req.severity = *dt_sev_error_name();
    req.note = note;
    req.topic = topic;
    req.topic_intern = true;
    req.subject = subject ? cep_cell_resolve(subject) : NULL;
    req.mailbox_root = cep_cei_diagnostics_mailbox();
    req.emit_signal = false;
    req.attach_to_op = false;
    req.ttl_forever = false;
    (void)cep_cei_emit(&req);
}

static void cep_fed_pack_render_name(const cepDT* dt,
                                     char* buffer,
                                     size_t capacity) {
    if (!buffer || capacity == 0u) {
        return;
    }
    buffer[0] = '\0';
    if (!dt) {
        return;
    }
    size_t len = 0u;
    const char* text = cep_namepool_lookup(dt->tag, &len);
    if (!text || len == 0u) {
        return;
    }
    if (len >= capacity) {
        len = capacity - 1u;
    }
    memcpy(buffer, text, len);
    buffer[len] = '\0';
}

static const char* cep_fed_pack_cell_name(const cepCell* cell,
                                          char* buffer,
                                          size_t capacity) {
    if (!cell) {
        if (buffer && capacity) {
            buffer[0] = '\0';
        }
        return "";
    }
    const cepDT* name = cep_cell_get_name(cell);
    cep_fed_pack_render_name(name, buffer, capacity);
    return buffer;
}

static bool cep_fed_pack_expect_dictionary(cepCell** cell_ptr,
                                           const char* context,
                                           const char* topic) {
    if (!cell_ptr || !*cell_ptr) {
        char note[128];
        snprintf(note, sizeof note, "%s missing or unresolved dictionary", context ? context : "dictionary");
        cep_fed_pack_emit_issue(topic, note, NULL);
        return false;
    }
    cepCell* resolved = cep_cell_resolve(*cell_ptr);
    if (!resolved) {
        char note[128];
        snprintf(note, sizeof note, "%s unresolved dictionary", context ? context : "dictionary");
        cep_fed_pack_emit_issue(topic, note, *cell_ptr);
        return false;
    }
    if (!cep_cell_require_dictionary_store(&resolved)) {
        char note[128];
        snprintf(note, sizeof note, "%s not a dictionary store", context ? context : "dictionary");
        cep_fed_pack_emit_issue(topic, note, resolved);
        return false;
    }
    *cell_ptr = resolved;
    return true;
}

static bool cep_fed_pack_expect_data_type(cepCell* node,
                                          const cepDT* expected_type,
                                          size_t expected_size,
                                          const char* context,
                                          const char* field_label,
                                          const char* topic) {
    cepData* data = NULL;
    if (!cep_cell_require_data(&node, &data)) {
        char note[160];
        snprintf(note, sizeof note, "%s field '%s' missing data payload", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, node);
        return false;
    }
    if (!expected_type || cep_dt_compare(&data->dt, expected_type) != 0) {
        char note[160];
        snprintf(note, sizeof note, "%s field '%s' has unexpected type", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, node);
        return false;
    }
    if (expected_size != 0u && data->size != expected_size) {
        char note[160];
        snprintf(note, sizeof note, "%s field '%s' size mismatch (expected %zu, saw %zu)",
                 context ? context : "node",
                 field_label,
                 expected_size,
                 data->size);
        cep_fed_pack_emit_issue(topic, note, node);
        return false;
    }
    return true;
}

static bool cep_fed_pack_expect_text_field(cepCell* parent,
                                           const cepDT* field,
                                           const char* context,
                                           const char* field_label,
                                           bool required,
                                           const char* topic) {
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        if (!required) {
            return true;
        }
        char note[160];
        snprintf(note, sizeof note, "%s missing required field '%s'", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, parent);
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        char note[160];
        snprintf(note, sizeof note, "%s field '%s' unresolved", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, parent);
        return false;
    }
    if (!cep_fed_pack_expect_data_type(node, dt_val_text(), 0u, context, field_label, topic)) {
        return false;
    }
    const cepData* data = node->data;
    if (!data || data->size == 0u) {
        char note[160];
        snprintf(note, sizeof note, "%s field '%s' must not be empty", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, node);
        return false;
    }
    return true;
}

static bool cep_fed_pack_expect_bool_field(cepCell* parent,
                                           const cepDT* field,
                                           const char* context,
                                           const char* field_label,
                                           bool required,
                                           const char* topic) {
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        if (!required) {
            return true;
        }
        char note[160];
        snprintf(note, sizeof note, "%s missing required field '%s'", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, parent);
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        char note[160];
        snprintf(note, sizeof note, "%s field '%s' unresolved", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, parent);
        return false;
    }
    if (!cep_fed_pack_expect_data_type(node, dt_val_bool(), sizeof(uint8_t), context, field_label, topic)) {
        return false;
    }
    return true;
}

static bool cep_fed_pack_expect_u64_field(cepCell* parent,
                                          const cepDT* field,
                                          const char* context,
                                          const char* field_label,
                                          bool required,
                                          const char* topic) {
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        if (!required) {
            return true;
        }
        char note[160];
        snprintf(note, sizeof note, "%s missing required field '%s'", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, parent);
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        char note[160];
        snprintf(note, sizeof note, "%s field '%s' unresolved", context ? context : "node", field_label);
        cep_fed_pack_emit_issue(topic, note, parent);
        return false;
    }
    if (!cep_fed_pack_expect_data_type(node, dt_val_u64(), sizeof(uint64_t), context, field_label, topic)) {
        return false;
    }
    return true;
}

static void cep_fed_pack_prune_empty_children(cepCell* dictionary) {
    if (!dictionary) {
        return;
    }
    cepCell* resolved = dictionary;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return;
    }
    for (cepCell* child = cep_cell_first_all(resolved); child; ) {
        cepCell* next = cep_cell_next_all(resolved, child);
        cepCell* resolved_child = cep_cell_resolve(child);
        if (!resolved_child) {
            cep_cell_delete_hard(child);
            child = next;
            continue;
        }
        if (!cep_cell_is_deleted(resolved_child) &&
            cep_cell_require_dictionary_store(&resolved_child)) {
            if (resolved_child->store && resolved_child->store->chdCount == 0u) {
                cep_cell_delete_hard(resolved_child);
            }
        }
        child = next;
    }
}

static bool cep_fed_pack_validate_ceh_entry(cepCell* entry,
                                            const char* peer_name,
                                            const char* topic_name) {
    if (!entry) {
        return true;
    }
    cepCell* resolved = entry;
    char context[160];
    snprintf(context, sizeof context, "peer '%s' ceh '%s'",
             peer_name ? peer_name : "<anon>",
             topic_name ? topic_name : "<anon>");
    if (!cep_fed_pack_expect_dictionary(&resolved, context, CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_severity_field_name(),
                                         context,
                                         "severity",
                                         false,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_note_field_name(),
                                         context,
                                         "note",
                                         false,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_u64_field(resolved,
                                        dt_beat_field_name(),
                                        context,
                                        "beat",
                                        true,
                                        CEP_FED_TOPIC_SCHEMA);
    return ok;
}

static bool cep_fed_pack_validate_service_entry(cepCell* entry,
                                                const char* peer_name) {
    if (!entry) {
        return true;
    }
    cepCell* resolved = entry;
    char service_name[CEP_FED_NAME_MAX] = {0};
    cep_fed_pack_cell_name(entry, service_name, sizeof service_name);
    char context[160];
    snprintf(context, sizeof context, "peer '%s' service '%s'",
             peer_name ? peer_name : "<anon>",
             service_name[0] ? service_name : "<anon>");
    if (!cep_fed_pack_expect_dictionary(&resolved, context, CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_mode_field_name(),
                                         context,
                                         "mode",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_mount_path_name(),
                                         context,
                                         "mount_path",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_local_node_field_name(),
                                         context,
                                         "local_node",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_provider_name(),
                                         context,
                                         "provider",
                                         false,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_bool_field(resolved,
                                         dt_upd_latest_name(),
                                         context,
                                         "upd_latest",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    return ok;
}

static bool cep_fed_pack_validate_peer_entry(cepCell* entry) {
    if (!entry) {
        return true;
    }
    cepCell* resolved = entry;
    char peer_name[CEP_FED_NAME_MAX] = {0};
    cep_fed_pack_cell_name(entry, peer_name, sizeof peer_name);
    char context[96];
    snprintf(context, sizeof context, "peer '%s'", peer_name[0] ? peer_name : "<anon>");
    if (!cep_fed_pack_expect_dictionary(&resolved, context, CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    cepCell* services = cep_cell_find_by_name(resolved, dt_services_name());
    if (!services) {
        char note[160];
        snprintf(note, sizeof note, "%s missing services dictionary", context);
        cep_fed_pack_emit_issue(CEP_FED_TOPIC_SCHEMA, note, resolved);
        ok = false;
    } else {
        if (cep_fed_pack_expect_dictionary(&services, context, CEP_FED_TOPIC_SCHEMA)) {
            for (cepCell* service = cep_cell_first_all(services); service; service = cep_cell_next_all(services, service)) {
                if (!service) {
                    continue;
                }
                cepCell* resolved_service = cep_cell_resolve(service);
                if (!resolved_service || cep_cell_is_deleted(resolved_service)) {
                    continue;
                }
                ok &= cep_fed_pack_validate_service_entry(resolved_service, peer_name);
            }
        } else {
            ok = false;
        }
    }

    cepCell* ceh = cep_cell_find_by_name(resolved, dt_ceh_name());
    if (ceh && cep_fed_pack_expect_dictionary(&ceh, context, CEP_FED_TOPIC_SCHEMA)) {
        for (cepCell* topic = cep_cell_first_all(ceh); topic; topic = cep_cell_next_all(ceh, topic)) {
            if (!topic) {
                continue;
            }
            cepCell* resolved_topic = cep_cell_resolve(topic);
            if (!resolved_topic || cep_cell_is_deleted(resolved_topic)) {
                continue;
            }
            char topic_name[CEP_FED_NAME_MAX] = {0};
            cep_fed_pack_cell_name(resolved_topic, topic_name, sizeof topic_name);
            ok &= cep_fed_pack_validate_ceh_entry(resolved_topic, peer_name, topic_name);
        }
    }
    return ok;
}

static bool cep_fed_pack_validate_peers(cepCell* peers_root) {
    if (!peers_root) {
        return true;
    }
    cepCell* resolved = peers_root;
    if (!cep_fed_pack_expect_dictionary(&resolved, "peers root", CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    for (cepCell* peer = cep_cell_first_all(resolved); peer; peer = cep_cell_next_all(resolved, peer)) {
        if (!peer) {
            continue;
        }
        cepCell* resolved_peer = cep_cell_resolve(peer);
        if (!resolved_peer || cep_cell_is_deleted(resolved_peer)) {
            continue;
        }
        ok &= cep_fed_pack_validate_peer_entry(resolved_peer);
    }
    return ok;
}

static bool cep_fed_pack_validate_catalog_entry(cepCell* entry,
                                                const char* mode_name) {
    if (!entry) {
        return true;
    }
    cepCell* resolved = entry;
    char mount_name[CEP_FED_NAME_MAX] = {0};
    cep_fed_pack_cell_name(entry, mount_name, sizeof mount_name);
    char context[160];
    snprintf(context, sizeof context, "catalog '%s/%s'",
             mode_name ? mode_name : "<mode>",
             mount_name[0] ? mount_name : "<mount>");
    if (!cep_fed_pack_expect_dictionary(&resolved, context, CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_peer_field_name(),
                                         context,
                                         "peer",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_mode_field_name(),
                                         context,
                                         "mode",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_local_node_field_name(),
                                         context,
                                         "local_node",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_provider_name(),
                                         context,
                                         "provider",
                                         false,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_bool_field(resolved,
                                         dt_upd_latest_name(),
                                         context,
                                         "upd_latest",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    return ok;
}

static bool cep_fed_pack_validate_catalog(cepCell* catalog_root) {
    if (!catalog_root) {
        return true;
    }
    cepCell* resolved = catalog_root;
    if (!cep_fed_pack_expect_dictionary(&resolved, "catalog root", CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    for (cepCell* mode = cep_cell_first_all(resolved); mode; mode = cep_cell_next_all(resolved, mode)) {
        if (!mode) {
            continue;
        }
        cepCell* resolved_mode = cep_cell_resolve(mode);
        if (!resolved_mode || cep_cell_is_deleted(resolved_mode)) {
            continue;
        }
        char mode_name[CEP_FED_NAME_MAX] = {0};
        cep_fed_pack_cell_name(resolved_mode, mode_name, sizeof mode_name);
        if (!cep_fed_pack_expect_dictionary(&resolved_mode, mode_name, CEP_FED_TOPIC_SCHEMA)) {
            ok = false;
            continue;
        }
        for (cepCell* mount = cep_cell_first_all(resolved_mode); mount; mount = cep_cell_next_all(resolved_mode, mount)) {
            if (!mount) {
                continue;
            }
            cepCell* resolved_mount = cep_cell_resolve(mount);
            if (!resolved_mount || cep_cell_is_deleted(resolved_mount)) {
                continue;
            }
            ok &= cep_fed_pack_validate_catalog_entry(resolved_mount, mode_name);
        }
    }
    return ok;
}

static bool cep_fed_pack_validate_telemetry_entry(cepCell* entry,
                                                  const char* peer_name) {
    if (!entry) {
        return true;
    }
    cepCell* resolved = entry;
    char mount_name[CEP_FED_NAME_MAX] = {0};
    cep_fed_pack_cell_name(entry, mount_name, sizeof mount_name);
    char context[160];
    snprintf(context, sizeof context, "telemetry '%s/%s'",
             peer_name ? peer_name : "<peer>",
             mount_name[0] ? mount_name : "<mount>");
    if (!cep_fed_pack_expect_dictionary(&resolved, context, CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_mode_field_name(),
                                         context,
                                         "mode",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_local_node_field_name(),
                                         context,
                                         "local_node",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_provider_name(),
                                         context,
                                         "provider",
                                         false,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_last_event_name(),
                                         context,
                                         "last_event",
                                         false,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_bool_field(resolved,
                                         dt_backpressured_flag_name(),
                                         context,
                                         "bp_flag",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_u64_field(resolved,
                                        dt_ready_count_name(),
                                        context,
                                        "ready_count",
                                        true,
                                        CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_u64_field(resolved,
                                        dt_backpressure_count_name(),
                                        context,
                                        "bp_count",
                                        true,
                                        CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_u64_field(resolved,
                                        dt_fatal_count_name(),
                                        context,
                                        "fatal_count",
                                        true,
                                        CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_u64_field(resolved,
                                        dt_frame_count_name(),
                                        context,
                                        "frame_count",
                                        true,
                                        CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_text_field(resolved,
                                         dt_last_frame_mode_name(),
                                         context,
                                         "last_mode",
                                         true,
                                         CEP_FED_TOPIC_SCHEMA);
    ok &= cep_fed_pack_expect_u64_field(resolved,
                                        dt_last_frame_sample_name(),
                                        context,
                                        "last_sample",
                                        true,
                                        CEP_FED_TOPIC_SCHEMA);
    return ok;
}

static bool cep_fed_pack_validate_telemetry(cepCell* telemetry_root) {
    if (!telemetry_root) {
        return true;
    }
    cepCell* resolved = telemetry_root;
    if (!cep_fed_pack_expect_dictionary(&resolved, "telemetry root", CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    bool ok = true;
    for (cepCell* peer = cep_cell_first_all(resolved); peer; peer = cep_cell_next_all(resolved, peer)) {
        if (!peer) {
            continue;
        }
        cepCell* resolved_peer = cep_cell_resolve(peer);
        if (!resolved_peer || cep_cell_is_deleted(resolved_peer)) {
            continue;
        }
        char peer_name[CEP_FED_NAME_MAX] = {0};
        cep_fed_pack_cell_name(resolved_peer, peer_name, sizeof peer_name);
        if (!cep_fed_pack_expect_dictionary(&resolved_peer, peer_name, CEP_FED_TOPIC_SCHEMA)) {
            ok = false;
            continue;
        }
        for (cepCell* entry = cep_cell_first_all(resolved_peer); entry; entry = cep_cell_next_all(resolved_peer, entry)) {
            if (!entry) {
                continue;
            }
            cepCell* resolved_entry = cep_cell_resolve(entry);
            if (!resolved_entry || cep_cell_is_deleted(resolved_entry)) {
                continue;
            }
            ok &= cep_fed_pack_validate_telemetry_entry(resolved_entry, peer_name);
        }
    }
    return ok;
}

static bool cep_fed_pack_validate_net_root(cepCell* net_root) {
    if (!net_root) {
        return true;
    }
    cepCell* resolved = net_root;
    if (!cep_fed_pack_expect_dictionary(&resolved, "net root", CEP_FED_TOPIC_SCHEMA)) {
        return false;
    }
    cepCell* peers = cep_cell_find_by_name(resolved, dt_peers_name());
    cepCell* catalog = cep_cell_find_by_name(resolved, dt_catalog_name());
    cepCell* telemetry = cep_cell_find_by_name(resolved, dt_telemetry_name());

    bool ok = true;
    if (!peers) {
        cep_fed_pack_emit_issue(CEP_FED_TOPIC_SCHEMA, "net root missing peers dictionary", resolved);
        ok = false;
    }
    if (!catalog) {
        cep_fed_pack_emit_issue(CEP_FED_TOPIC_SCHEMA, "net root missing catalog dictionary", resolved);
        ok = false;
    }
    if (!telemetry) {
        cep_fed_pack_emit_issue(CEP_FED_TOPIC_SCHEMA, "net root missing telemetry dictionary", resolved);
        ok = false;
    }
    if (peers) {
        ok &= cep_fed_pack_validate_peers(peers);
    }
    if (catalog) {
        ok &= cep_fed_pack_validate_catalog(catalog);
    }
    if (telemetry) {
        ok &= cep_fed_pack_validate_telemetry(telemetry);
    }
    return ok;
}

static void cep_fed_pack_prune_peer_services(cepCell* peers_root) {
    if (!peers_root) {
        return;
    }
    cepCell* resolved = peers_root;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return;
    }
    for (cepCell* peer = cep_cell_first_all(resolved); peer; ) {
        cepCell* next_peer = cep_cell_next_all(resolved, peer);
        cepCell* resolved_peer = cep_cell_resolve(peer);
        if (!resolved_peer) {
            cep_cell_delete_hard(peer);
            peer = next_peer;
            continue;
        }
        if (!cep_cell_require_dictionary_store(&resolved_peer)) {
            cep_cell_delete_hard(resolved_peer);
            peer = next_peer;
            continue;
        }
        cepCell* services = cep_cell_find_by_name(resolved_peer, dt_services_name());
        if (services && cep_cell_require_dictionary_store(&services)) {
            for (cepCell* service = cep_cell_first_all(services); service; ) {
                cepCell* next_service = cep_cell_next_all(services, service);
                cepCell* resolved_service = cep_cell_resolve(service);
                if (!resolved_service ||
                    !cep_cell_require_dictionary_store(&resolved_service) ||
                    (resolved_service->store && resolved_service->store->chdCount == 0u)) {
                    if (resolved_service) {
                        cep_cell_delete_hard(resolved_service);
                    } else {
                        cep_cell_delete_hard(service);
                    }
                }
                service = next_service;
            }
        }
        cepCell* ceh = cep_cell_find_by_name(resolved_peer, dt_ceh_name());
        if (ceh && cep_cell_require_dictionary_store(&ceh)) {
            cep_fed_pack_prune_empty_children(ceh);
        }
        bool services_empty = false;
        if (services && services->store && services->store->chdCount == 0u) {
            services_empty = true;
        } else if (!services) {
            services_empty = true;
        }
        bool ceh_empty = true;
        if (ceh && ceh->store) {
            ceh_empty = (ceh->store->chdCount == 0u);
        }
        if (services_empty && ceh_empty) {
            cep_cell_delete_hard(resolved_peer);
        }
        peer = next_peer;
    }
}

static void cep_fed_pack_prune_telemetry(cepCell* telemetry_root) {
    if (!telemetry_root) {
        return;
    }
    cepCell* resolved = telemetry_root;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return;
    }
    for (cepCell* peer = cep_cell_first_all(resolved); peer; ) {
        cepCell* next_peer = cep_cell_next_all(resolved, peer);
        cepCell* resolved_peer = cep_cell_resolve(peer);
        if (!resolved_peer) {
            cep_cell_delete_hard(peer);
            peer = next_peer;
            continue;
        }
        if (!cep_cell_require_dictionary_store(&resolved_peer)) {
            cep_cell_delete_hard(resolved_peer);
            peer = next_peer;
            continue;
        }
        for (cepCell* entry = cep_cell_first_all(resolved_peer); entry; ) {
            cepCell* next_entry = cep_cell_next_all(resolved_peer, entry);
            cepCell* resolved_entry = cep_cell_resolve(entry);
            if (!resolved_entry ||
                !cep_cell_require_dictionary_store(&resolved_entry) ||
                (resolved_entry->store && resolved_entry->store->chdCount == 0u)) {
                if (resolved_entry) {
                    cep_cell_delete_hard(resolved_entry);
                } else {
                    cep_cell_delete_hard(entry);
                }
            }
            entry = next_entry;
        }
        if (resolved_peer->store && resolved_peer->store->chdCount == 0u) {
            cep_cell_delete_hard(resolved_peer);
        }
        peer = next_peer;
    }
}

static bool cep_fed_pack_register_organs(void);

static cepCell* cep_fed_pack_ensure_dict_child(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    if (!child) {
        return NULL;
    }
    child = cep_cell_resolve(child);
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return NULL;
    }
    return child;
}

static bool cep_fed_pack_write_text(cepCell* parent, const cepDT* name, const char* value) {
    if (!parent || !name || !value) {
        return false;
    }
    cepCell* resolved = parent;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }
    size_t len = strlen(value);
    cepDT key = *name;
    cepDT type = cep_ops_make_dt("val/text");
    return cep_dict_add_value(resolved, &key, &type, (void*)value, len, len) != NULL;
}

static bool cep_fed_pack_publish_organ_spec(cepCell* organ_cell,
                                            const char* kind,
                                            const char* label,
                                            const char* store_value,
                                            const char* validator_signal,
                                            const char* destructor_signal) {
    if (!organ_cell || !kind || !label || !store_value || !validator_signal) {
        return false;
    }

    cepCell* spec_cell = cep_fed_pack_ensure_dict_child(organ_cell, dt_spec_name());
    if (!spec_cell) {
        return false;
    }

    if (spec_cell->store) {
        cep_store_delete_children_hard(spec_cell->store);
    }

    bool ok = true;
    ok = cep_fed_pack_write_text(spec_cell, dt_kind_field_name(), kind) && ok;
    ok = cep_fed_pack_write_text(spec_cell, dt_label_field_name(), label) && ok;
    ok = cep_fed_pack_write_text(spec_cell, dt_store_field_name(), store_value) && ok;
    ok = cep_fed_pack_write_text(spec_cell, dt_validator_field_name(), validator_signal) && ok;
    if (destructor_signal && *destructor_signal) {
        ok = cep_fed_pack_write_text(spec_cell, dt_destructor_field_name(), destructor_signal) && ok;
    }
    return ok;
}

/* cep_fed_pack_ensure_roots resolves the caller supplied `/net` branch, creates the
   deterministic child dictionaries (peers/catalog/telemetry/organs), and returns the
   resolved handles so later bootstrap steps can seed mounts or telemetry without
   racing other bootstrap helpers. */
bool cep_fed_pack_ensure_roots(cepCell* net_root,
                               cepCell** peers_root,
                               cepCell** catalog_root,
                               cepCell** telemetry_root,
                               cepCell** organs_root) {
    if (!net_root) {
        return false;
    }

    cepCell* resolved = cep_cell_resolve(net_root);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepCell* peers = cep_fed_pack_ensure_dict_child(resolved, dt_peers_name());
    cepCell* catalog = cep_fed_pack_ensure_dict_child(resolved, dt_catalog_name());
    cepCell* telemetry = cep_fed_pack_ensure_dict_child(resolved, dt_telemetry_name());
    cepCell* organs = cep_fed_pack_ensure_dict_child(resolved, dt_organs_name());

    if (!peers || !catalog || !telemetry || !organs) {
        return false;
    }

    if (!cep_fed_pack_ensure_dict_child(organs, dt_discovery_name())) {
        return false;
    }
    if (!cep_fed_pack_ensure_dict_child(organs, dt_health_name())) {
        return false;
    }

    if (peers_root) {
        *peers_root = peers;
    }
    if (catalog_root) {
        *catalog_root = catalog;
    }
    if (telemetry_root) {
        *telemetry_root = telemetry;
    }
    if (organs_root) {
        *organs_root = organs;
    }

    return true;
}

/* cep_fed_pack_bootstrap is invoked during Layer 0 bootstrap to ensure the `/net`
   hierarchy exists and to register the discovery/health organ descriptors so the
   federation transport manager can publish catalog and telemetry data deterministically. */
bool cep_fed_pack_bootstrap(void) {
    cepCell* root = cep_root();
    if (!root) {
        return false;
    }

    cepCell* net_root = cep_cell_ensure_dictionary_child(root, dt_net_name(), CEP_STORAGE_RED_BLACK_T);
    if (!net_root) {
        return false;
    }
    net_root = cep_cell_resolve(net_root);
    if (!net_root || !cep_cell_require_dictionary_store(&net_root)) {
        return false;
    }

    cepCell* peers = NULL;
    cepCell* catalog = NULL;
    cepCell* telemetry = NULL;
    cepCell* organs = NULL;

    if (!cep_fed_pack_ensure_roots(net_root, &peers, &catalog, &telemetry, &organs)) {
        return false;
    }

    (void)peers;
    (void)catalog;
    (void)telemetry;
    (void)organs;

    cepCell* discovery = cep_fed_pack_ensure_dict_child(organs, dt_discovery_name());
    cepCell* health = cep_fed_pack_ensure_dict_child(organs, dt_health_name());
    cepCell* link = cep_fed_pack_ensure_dict_child(organs, dt_link_name());
    cepCell* mirror = cep_fed_pack_ensure_dict_child(organs, dt_mirror_name());
    if (!discovery || !health || !link || !mirror) {
        return false;
    }

    if (!cep_fed_pack_publish_organ_spec(discovery,
                                         CEP_FED_DISCOVERY_KIND,
                                         CEP_FED_DISCOVERY_LABEL,
                                         CEP_FED_DISCOVERY_STORE,
                                         CEP_FED_DISCOVERY_VALIDATOR_SIGNAL,
                                         CEP_FED_DISCOVERY_DESTRUCTOR_SIGNAL)) {
        return false;
    }

    if (!cep_fed_pack_publish_organ_spec(health,
                                         CEP_FED_HEALTH_KIND,
                                         CEP_FED_HEALTH_LABEL,
                                         CEP_FED_HEALTH_STORE,
                                         CEP_FED_HEALTH_VALIDATOR_SIGNAL,
                                         CEP_FED_HEALTH_DESTRUCTOR_SIGNAL)) {
        return false;
    }

    if (!cep_fed_pack_publish_organ_spec(link,
                                         CEP_FED_LINK_KIND,
                                         CEP_FED_LINK_LABEL,
                                         CEP_FED_LINK_STORE,
                                         CEP_FED_LINK_VALIDATOR_SIGNAL,
                                         CEP_FED_LINK_DESTRUCTOR_SIGNAL)) {
        return false;
    }

    if (!cep_fed_pack_publish_organ_spec(mirror,
                                         CEP_FED_MIRROR_KIND,
                                         CEP_FED_MIRROR_LABEL,
                                         CEP_FED_MIRROR_STORE,
                                         CEP_FED_MIRROR_VALIDATOR_SIGNAL,
                                         CEP_FED_MIRROR_DESTRUCTOR_SIGNAL)) {
        return false;
    }

    if (!g_fed_transport_manager_ready) {
        if (!cep_fed_transport_manager_init(&g_fed_transport_manager, net_root)) {
            return false;
        }
        g_fed_transport_manager_ready = true;
    }

    if (!cep_fed_link_organ_init(&g_fed_transport_manager, net_root)) {
        return false;
    }

    if (!cep_fed_mirror_organ_init(&g_fed_transport_manager, net_root)) {
        return false;
    }

    return cep_fed_pack_register_organs();
}

cepFedTransportManager* cep_fed_pack_manager(void) {
    return g_fed_transport_manager_ready ? &g_fed_transport_manager : NULL;
}

static cepFedPackPath cep_fed_pack_make_signal_path(const char* signal) {
    cepFedPackPath path = {
        .length = 1u,
        .capacity = 1u,
        .past = {
            {
                .dt = cep_ops_make_dt(signal),
                .timestamp = 0u,
            },
        },
    };
    return path;
}

static cepCell* cep_fed_pack_net_root(void) {
    cepCell* root = cep_root();
    root = root ? cep_cell_resolve(root) : NULL;
    if (!root) {
        return NULL;
    }
    cepCell* net = cep_cell_find_by_name(root, dt_net_name());
    if (!net) {
        return NULL;
    }
    return cep_cell_resolve(net);
}

static int cep_fed_pack_discovery_validator(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    (void)target_path;
    cepCell* net_root = cep_fed_pack_net_root();
    if (!net_root) {
        return CEP_ENZYME_SUCCESS;
    }
    bool ok = cep_fed_pack_validate_net_root(net_root);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_fed_pack_discovery_destructor(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    (void)target_path;
    cepCell* net_root = cep_fed_pack_net_root();
    if (!net_root) {
        return CEP_ENZYME_SUCCESS;
    }
    if (!cep_cell_require_dictionary_store(&net_root)) {
        return CEP_ENZYME_SUCCESS;
    }
    cepCell* peers = cep_cell_find_by_name(net_root, dt_peers_name());
    if (peers) {
        cep_fed_pack_prune_peer_services(peers);
    }
    cepCell* catalog = cep_cell_find_by_name(net_root, dt_catalog_name());
    if (catalog) {
        cep_fed_pack_prune_empty_children(catalog);
    }
    return CEP_ENZYME_SUCCESS;
}

static int cep_fed_pack_health_validator(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    (void)target_path;
    cepCell* net_root = cep_fed_pack_net_root();
    if (!net_root) {
        return CEP_ENZYME_SUCCESS;
    }
    bool ok = cep_fed_pack_validate_net_root(net_root);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_fed_pack_health_destructor(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    (void)target_path;
    cepCell* net_root = cep_fed_pack_net_root();
    if (!net_root) {
        return CEP_ENZYME_SUCCESS;
    }
    if (!cep_cell_require_dictionary_store(&net_root)) {
        return CEP_ENZYME_SUCCESS;
    }
    cepCell* telemetry = cep_cell_find_by_name(net_root, dt_telemetry_name());
    if (telemetry) {
        cep_fed_pack_prune_telemetry(telemetry);
    }
    cepCell* peers = cep_cell_find_by_name(net_root, dt_peers_name());
    if (peers) {
        cep_fed_pack_prune_peer_services(peers);
    }
    return CEP_ENZYME_SUCCESS;
}

static bool cep_fed_pack_register_organs(void) {
    static bool registered = false;
    if (registered) {
        return true;
    }

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return false;
    }

    cepOrganDescriptor discovery = {0};
    discovery.kind = CEP_FED_DISCOVERY_KIND;
    discovery.label = CEP_FED_DISCOVERY_LABEL;
    discovery.store = cep_organ_store_dt("net_discovery");
    discovery.validator = cep_ops_make_dt(CEP_FED_DISCOVERY_VALIDATOR_SIGNAL);
    discovery.constructor = (cepDT){0};
    discovery.destructor = cep_ops_make_dt(CEP_FED_DISCOVERY_DESTRUCTOR_SIGNAL);

    cepOrganDescriptor health = {0};
    health.kind = CEP_FED_HEALTH_KIND;
    health.label = CEP_FED_HEALTH_LABEL;
    health.store = cep_organ_store_dt("net_health");
    health.validator = cep_ops_make_dt(CEP_FED_HEALTH_VALIDATOR_SIGNAL);
    health.destructor = cep_ops_make_dt(CEP_FED_HEALTH_DESTRUCTOR_SIGNAL);

    cepOrganDescriptor link = {0};
   link.kind = CEP_FED_LINK_KIND;
   link.label = CEP_FED_LINK_LABEL;
   link.store = cep_organ_store_dt("net_link");
   link.validator = cep_ops_make_dt(CEP_FED_LINK_VALIDATOR_SIGNAL);
   link.destructor = cep_ops_make_dt(CEP_FED_LINK_DESTRUCTOR_SIGNAL);

    cepOrganDescriptor mirror = {0};
    mirror.kind = CEP_FED_MIRROR_KIND;
    mirror.label = CEP_FED_MIRROR_LABEL;
    mirror.store = cep_organ_store_dt("net_mirror");
    mirror.validator = cep_ops_make_dt(CEP_FED_MIRROR_VALIDATOR_SIGNAL);
    mirror.destructor = cep_ops_make_dt(CEP_FED_MIRROR_DESTRUCTOR_SIGNAL);

    if (!cep_organ_register(&discovery)) {
        return false;
    }
    if (!cep_organ_register(&health)) {
        return false;
    }
    if (!cep_organ_register(&link)) {
        return false;
    }
    if (!cep_organ_register(&mirror)) {
        return false;
    }

    cepFedPackPath discovery_validator_path = cep_fed_pack_make_signal_path("org:net_discovery:vl");
    cepEnzymeDescriptor discovery_validator = {
        .name = discovery_validator_path.past[0].dt,
        .label = "organ.net_discovery.vl",
        .callback = cep_fed_pack_discovery_validator,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    if (cep_enzyme_register(registry, (const cepPath*)&discovery_validator_path, &discovery_validator) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    if (cep_dt_is_valid(&discovery.destructor)) {
        cepFedPackPath discovery_destructor_path = cep_fed_pack_make_signal_path("org:net_discovery:dt");
        cepEnzymeDescriptor discovery_destructor = {
            .name = discovery_destructor_path.past[0].dt,
            .label = "organ.net_discovery.dt",
            .callback = cep_fed_pack_discovery_destructor,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_EXACT,
        };
        if (cep_enzyme_register(registry, (const cepPath*)&discovery_destructor_path, &discovery_destructor) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    cepFedPackPath health_validator_path = cep_fed_pack_make_signal_path("org:net_health:vl");
    cepEnzymeDescriptor health_validator = {
        .name = health_validator_path.past[0].dt,
        .label = "organ.net_health.vl",
        .callback = cep_fed_pack_health_validator,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    if (cep_enzyme_register(registry, (const cepPath*)&health_validator_path, &health_validator) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    if (cep_dt_is_valid(&health.destructor)) {
        cepFedPackPath health_destructor_path = cep_fed_pack_make_signal_path("org:net_health:dt");
        cepEnzymeDescriptor health_destructor = {
            .name = health_destructor_path.past[0].dt,
            .label = "organ.net_health.dt",
            .callback = cep_fed_pack_health_destructor,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_EXACT,
        };
        if (cep_enzyme_register(registry, (const cepPath*)&health_destructor_path, &health_destructor) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    cepFedPackPath link_validator_path = cep_fed_pack_make_signal_path("org:net_link:vl");
    cepEnzymeDescriptor link_validator = {
        .name = link_validator_path.past[0].dt,
        .label = "organ.net_link.vl",
        .callback = cep_fed_link_validator,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    if (cep_enzyme_register(registry, (const cepPath*)&link_validator_path, &link_validator) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    if (cep_dt_is_valid(&link.destructor)) {
        cepFedPackPath link_destructor_path = cep_fed_pack_make_signal_path("org:net_link:dt");
        cepEnzymeDescriptor link_destructor = {
            .name = link_destructor_path.past[0].dt,
            .label = "organ.net_link.dt",
            .callback = cep_fed_link_destructor,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_EXACT,
        };
        if (cep_enzyme_register(registry, (const cepPath*)&link_destructor_path, &link_destructor) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    cepFedPackPath mirror_validator_path = cep_fed_pack_make_signal_path("org:net_mirror:vl");
    cepEnzymeDescriptor mirror_validator = {
        .name = mirror_validator_path.past[0].dt,
        .label = "organ.net_mirror.vl",
        .callback = cep_fed_mirror_validator,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    if (cep_enzyme_register(registry, (const cepPath*)&mirror_validator_path, &mirror_validator) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    if (cep_dt_is_valid(&mirror.destructor)) {
        cepFedPackPath mirror_destructor_path = cep_fed_pack_make_signal_path("org:net_mirror:dt");
        cepEnzymeDescriptor mirror_destructor = {
            .name = mirror_destructor_path.past[0].dt,
            .label = "organ.net_mirror.dt",
            .callback = cep_fed_mirror_destructor,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_EXACT,
        };
        if (cep_enzyme_register(registry, (const cepPath*)&mirror_destructor_path, &mirror_destructor) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    registered = true;
    return true;
}
