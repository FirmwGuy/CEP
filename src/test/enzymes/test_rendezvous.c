/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Rendezvous lifecycle and policy tests. */

#include "test.h"

#include "cep_rendezvous.h"
#include "cep_l2_flows.h"
#include "cep_mailroom.h"
#include "cep_identifier.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static void rc_reset_runtime(void) {
    cep_heartbeat_shutdown();
}

static void rc_bootstrap_runtime(void) {
    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
    munit_assert_true(cep_l2_flows_bootstrap());

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (registry) {
        munit_assert_true(cep_l2_flows_register(registry));
    }

    munit_assert_true(cep_heartbeat_begin(cep_heartbeat_current()));
}

static cepCell* rc_rv_ledger(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);
    cepCell* ledger = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "rv"));
    munit_assert_not_null(ledger);
    return ledger;
}

static cepCell* rc_rv_entry(const cepDT* key_dt) {
    cepCell* entry = cep_cell_find_by_name(rc_rv_ledger(), key_dt);
    munit_assert_not_null(entry);
    return entry;
}

static cepID rc_text_to_id(const char* text) {
    if (!text || !*text) {
        return 0;
    }
    cepID id = cep_text_to_word(text);
    if (!id) {
        id = cep_text_to_acronym(text);
    }
    if (!id) {
        id = cep_namepool_intern(text, strlen(text));
    }
    return id;
}

static cepDT rc_make_dt(const char* tag) {
    cepID id = rc_text_to_id(tag);
    munit_assert_uint64(id, !=, 0u);
    return cep_dt_make(CEP_ACRO("CEP"), id);
}

static const char* rc_get_text(cepCell* parent, const char* tag) {
    cepDT field = rc_make_dt(tag);
    cepCell* node = cep_cell_find_by_name(parent, &field);
    if (!node || !cep_cell_has_data(node)) {
        return NULL;
    }
    return (const char*)node->data->value;
}

static uint64_t rc_get_u64(cepCell* parent, const char* tag) {
    const char* text = rc_get_text(parent, tag);
    munit_assert_not_null(text);
    return (uint64_t)strtoull(text, NULL, 10);
}

static void rc_dispatch_request(cepCell* request) {
    cepPath* target_path = NULL;
    munit_assert_true(cep_cell_path(request, &target_path));

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } CepStaticSignal;

    CepStaticSignal signal = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            { .dt = *CEP_DTAW("CEP", "sig_cell"), .timestamp = 0u },
            { .dt = *CEP_DTAW("CEP", "op_add"),  .timestamp = 0u },
        },
    };

    munit_assert_int(cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, (const cepPath*)&signal, target_path), ==, CEP_ENZYME_SUCCESS);
    cep_free(target_path);

    munit_assert_true(cep_heartbeat_process_impulses());
}

static void rc_set_string(cepCell* parent, const char* tag, const char* value) {
    cepDT name = rc_make_dt(tag);
    cepDT text_dt = *CEP_DTAW("CEP", "text");
    cepCell* existing = cep_cell_find_by_name(parent, &name);
    if (existing) {
        cep_cell_remove_hard(parent, existing);
    }
    cep_dict_add_value(parent, &name, &text_dt, (void*)value, strlen(value) + 1u, strlen(value) + 1u);
}

static void rc_ensure_instance_entry(const char* instance_id) {
    cepCell* data_root = cep_heartbeat_data_root();
    cepCell* flow_root = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "flow"));
    munit_assert_not_null(flow_root);
    cepCell* ledger = cep_cell_find_by_name(flow_root, CEP_DTAW("CEP", "instance"));
    munit_assert_not_null(ledger);

    cepDT inst_dt = rc_make_dt(instance_id);
    cepCell* entry = cep_cell_find_by_name(ledger, &inst_dt);
    if (!entry) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        entry = cep_dict_add_dictionary(ledger, &inst_dt, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(entry);
    }
    rc_set_string(entry, "state", "ready");
}

static void rc_assert_outcome(cepCell* request, const char* expected) {
    const char* outcome = rc_get_text(request, "outcome");
    munit_assert_not_null(outcome);
    munit_assert_string_equal(outcome, expected);
}

MunitResult test_rendezvous_capture_commit(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    rc_reset_runtime();
    rc_bootstrap_runtime();

    cepRvSpec spec = {0};
    spec.key_dt = rc_make_dt("rv.capture");
    spec.instance_dt = rc_make_dt("inst.capture");
    spec.due = (uint64_t)cep_heartbeat_current();

    munit_assert_true(cep_rv_spawn(&spec, spec.key_dt.tag));

    cepCell* entry = rc_rv_entry(&spec.key_dt);
    munit_assert_string_equal(rc_get_text(entry, "state"), "pending");

    munit_assert_true(cep_rv_capture_scan());
    munit_assert_string_equal(rc_get_text(entry, "state"), "ready");

    munit_assert_true(cep_rv_commit_apply());
    munit_assert_string_equal(rc_get_text(entry, "state"), "applied");

    uint64_t applied = rc_get_u64(entry, "applied_bt");
    munit_assert_uint64(applied, ==, (uint64_t)cep_heartbeat_current());

    cepCell* data_root = cep_heartbeat_data_root();
    cepCell* flow_root = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "flow"));
    munit_assert_not_null(flow_root);
    cepCell* inbox = cep_cell_find_by_name(flow_root, CEP_DTAW("CEP", "inbox"));
    munit_assert_not_null(inbox);
    cepCell* inst_event = cep_cell_find_by_name(inbox, CEP_DTAW("CEP", "inst_event"));
    munit_assert_not_null(inst_event);
    munit_assert_size(cep_cell_children(inst_event), >, 0u);

    cepCell* emitted = cep_cell_first(inst_event);
    munit_assert_not_null(emitted);
    const char* payload_state = NULL;
    cepCell* payload = cep_cell_find_by_name(emitted, CEP_DTAW("CEP", "payload"));
    if (payload) {
        payload_state = rc_get_text(payload, "state");
    }
    munit_assert_string_equal(payload_state, "ready");

    rc_reset_runtime();
    return MUNIT_OK;
}

MunitResult test_rendezvous_policies(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    rc_reset_runtime();
    rc_bootstrap_runtime();

    cepRvSpec spec = {0};
    spec.key_dt = rc_make_dt("rv.grace");
    spec.instance_dt = rc_make_dt("inst.grace");
    spec.due = (uint64_t)cep_heartbeat_current();
    spec.on_miss = rc_text_to_id("grace");
    spec.grace_delta = 2u;
    spec.max_grace = 1u;

    munit_assert_true(cep_rv_spawn(&spec, spec.key_dt.tag));
    cepCell* entry = rc_rv_entry(&spec.key_dt);

    munit_assert_true(cep_heartbeat_begin(cep_heartbeat_current() + 1u));
    munit_assert_true(cep_rv_capture_scan());

    munit_assert_string_equal(rc_get_text(entry, "state"), "pending");
    uint64_t due_after_grace = rc_get_u64(entry, "due");
    munit_assert_uint64(due_after_grace, ==, (uint64_t)cep_heartbeat_current() + spec.grace_delta);
    munit_assert_string_equal(rc_get_text(entry, "grace_used"), "1");

    munit_assert_true(cep_heartbeat_begin(cep_heartbeat_current() + (cepBeatNumber)spec.grace_delta + 1u));
    munit_assert_true(cep_rv_capture_scan());
    munit_assert_string_equal(rc_get_text(entry, "state"), "late");

    cepRvSpec timeout_spec = {0};
    timeout_spec.key_dt = rc_make_dt("rv.timeout");
    timeout_spec.instance_dt = rc_make_dt("inst.timeout");
    timeout_spec.due = (uint64_t)cep_heartbeat_current();
    timeout_spec.on_miss = rc_text_to_id("timeout");

    munit_assert_true(cep_rv_spawn(&timeout_spec, timeout_spec.key_dt.tag));
    cepCell* timeout_entry = rc_rv_entry(&timeout_spec.key_dt);

    munit_assert_true(cep_heartbeat_begin(cep_heartbeat_current() + 1u));
    munit_assert_true(cep_rv_capture_scan());
    munit_assert_string_equal(rc_get_text(timeout_entry, "state"), "timeout");

    rc_reset_runtime();
    return MUNIT_OK;
}

MunitResult test_rendezvous_controls(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    rc_reset_runtime();
    rc_bootstrap_runtime();

    const char* instance_id = "instance.control";
    const char* key_text = "rv.control";

    cepRvSpec spec = {0};
    spec.key_dt = rc_make_dt(key_text);
    spec.instance_dt = rc_make_dt(instance_id);
    spec.due = (uint64_t)cep_heartbeat_current() + 5u;

    munit_assert_true(cep_rv_spawn(&spec, spec.key_dt.tag));
    cepCell* entry = rc_rv_entry(&spec.key_dt);
    uint64_t initial_due = rc_get_u64(entry, "due");

    rc_ensure_instance_entry(instance_id);

    const char* id_tokens[] = { "instance", "control" };

    cepL2InstanceControlIntent resched_intent = {0};
    munit_assert_true(cep_l2_instance_control_intent_init(&resched_intent,
                                                          "ctrl_resched",
                                                          "rv_resched",
                                                          id_tokens,
                                                          cep_lengthof(id_tokens)));
    munit_assert_true(cep_l2_instance_control_intent_set_rendezvous_key(&resched_intent, key_text));
    munit_assert_true(cep_l2_instance_control_intent_set_rendezvous_number(&resched_intent, "due_off", 3u));

    cepCell* resched_request = cep_l2_instance_control_intent_request(&resched_intent);
    rc_dispatch_request(resched_request);

    rc_assert_outcome(resched_request, "ok");
    uint64_t rescheduled_due = rc_get_u64(entry, "due");
    munit_assert_uint64(rescheduled_due, ==, initial_due + 3u);

    cepL2InstanceControlIntent kill_intent = {0};
    munit_assert_true(cep_l2_instance_control_intent_init(&kill_intent,
                                                          "ctrl_kill",
                                                          "rv_kill",
                                                          id_tokens,
                                                          cep_lengthof(id_tokens)));
    munit_assert_true(cep_l2_instance_control_intent_set_rendezvous_key(&kill_intent, key_text));
    munit_assert_true(cep_l2_instance_control_intent_set_rendezvous_text(&kill_intent, "kill_mode", "kill"));
    munit_assert_true(cep_l2_instance_control_intent_set_rendezvous_number(&kill_intent, "kill_wait", 2u));

    cepCell* kill_request = cep_l2_instance_control_intent_request(&kill_intent);
    rc_dispatch_request(kill_request);

    rc_assert_outcome(kill_request, "ok");
    munit_assert_string_equal(rc_get_text(entry, "state"), "killed");

    cepL2InstanceControlIntent report_intent = {0};
    munit_assert_true(cep_l2_instance_control_intent_init(&report_intent,
                                                          "ctrl_report",
                                                          "rv_report",
                                                          id_tokens,
                                                          cep_lengthof(id_tokens)));
    munit_assert_true(cep_l2_instance_control_intent_set_rendezvous_key(&report_intent, key_text));

    cepCell* report_rv = cep_l2_instance_control_intent_ensure_rendezvous(&report_intent);
    munit_assert_not_null(report_rv);
    cepDT telemetry_dt = *CEP_DTAW("CEP", "telemetry");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* telemetry = cep_dict_add_dictionary(report_rv, &telemetry_dt, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(telemetry);
    rc_set_string(telemetry, "score", "42");

    cepCell* report_request = cep_l2_instance_control_intent_request(&report_intent);
    rc_dispatch_request(report_request);

    rc_assert_outcome(report_request, "ok");
    cepCell* telemetry_node = cep_cell_find_by_name(entry, CEP_DTAW("CEP", "telemetry"));
    munit_assert_not_null(telemetry_node);
    munit_assert_string_equal(rc_get_text(telemetry_node, "score"), "42");

    rc_reset_runtime();
    return MUNIT_OK;
}

