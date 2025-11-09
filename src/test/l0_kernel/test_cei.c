/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* CEI helper coverage: verify diagnostics mailbox emission, signal ledger
   entries, OPS attachment semantics, and fatal shutdown triggers. */

#include "test.h"

#include "cep_cei.h"
#include "cep_cell.h"
#include "cep_ops.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} CeiRuntimeScope;

static CeiRuntimeScope cei_runtime_start(bool ensure_dirs) {
    test_runtime_shutdown();

    CeiRuntimeScope scope = {
        .runtime = cep_runtime_create(),
        .previous_runtime = NULL,
    };
    munit_assert_not_null(scope.runtime);
    scope.previous_runtime = cep_runtime_set_active(scope.runtime);
    cep_cell_system_initiate();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = ensure_dirs,
        .enforce_visibility = false,
        .boot_ops = true,
        .spacing_window = 32u,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_namepool_bootstrap());
    munit_assert_true(cep_runtime_attach_metadata(scope.runtime));
    munit_assert_true(cep_heartbeat_startup());
    return scope;
}

static void cei_runtime_cleanup(CeiRuntimeScope* scope) {
    if (!scope || !scope->runtime) {
        return;
    }
    cep_runtime_set_active(scope->runtime);
    cep_stream_clear_pending();
    cep_runtime_shutdown(scope->runtime);
    cep_runtime_restore_active(scope->previous_runtime);
    cep_runtime_destroy(scope->runtime);
    scope->runtime = NULL;
    scope->previous_runtime = NULL;
}

static cepCell* cei_msgs_root(void) {
    cepCell* mailbox = cep_cei_diagnostics_mailbox();
    munit_assert_not_null(mailbox);

    cepCell* msgs = cep_cell_find_by_name(mailbox, CEP_DTAW("CEP", "msgs"));
    munit_assert_not_null(msgs);
    msgs = cep_cell_resolve(msgs);
    munit_assert_not_null(msgs);
    return msgs;
}

static cepCell* cei_latest_message(void) {
    cepCell* msgs = cei_msgs_root();
    cepCell* message = cep_cell_last_all(msgs);
    munit_assert_not_null(message);
    message = cep_cell_resolve(message);
    munit_assert_not_null(message);
    return message;
}

static const char* cei_leaf_text(cepCell* node) {
    munit_assert_not_null(node);
    node = cep_cell_resolve(node);
    munit_assert_not_null(node);
    munit_assert_true(cep_cell_has_data(node));
    const char* text = cep_cell_data(node);
    munit_assert_not_null(text);
    return text;
}

static cepDT cei_read_dt_cell(cepCell* container) {
    munit_assert_not_null(container);
    container = cep_cell_resolve(container);
    munit_assert_not_null(container);

    if (cep_cell_has_data(container)) {
        const cepDT* stored = cep_cell_data(container);
        munit_assert_not_null(stored);
        return cep_dt_clean(stored);
    }

    cepCell* domain_cell = cep_cell_find_by_name(container, CEP_DTAW("CEP", "domain"));
    cepCell* tag_cell = cep_cell_find_by_name(container, CEP_DTAW("CEP", "tag"));
    munit_assert_not_null(domain_cell);
    munit_assert_not_null(tag_cell);

    const char* domain_text = cei_leaf_text(domain_cell);
    const char* tag_text = cei_leaf_text(tag_cell);

    cepDT value = {0};
    value.domain = (cepID)strtoull(domain_text, NULL, 10);
    value.tag = (cepID)strtoull(tag_text, NULL, 10);
    value.glob = 0u;
    return value;
}

static void cei_assert_dt_matches(const cepDT* actual, const cepDT* expected) {
    munit_assert_not_null(actual);
    munit_assert_not_null(expected);
    cepID actual_domain = cep_id(actual->domain);
    cepID expected_domain = cep_id(expected->domain);
    munit_assert_uint64(actual_domain, ==, expected_domain);
    cepID actual_tag = cep_id(actual->tag);
    cepID expected_tag = cep_id(expected->tag);
    munit_assert_uint64(actual_tag, ==, expected_tag);
}

static cepCell* cei_subject_cell(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepCell* subject_root = cep_cell_ensure_dictionary_child(data_root,
                                                             CEP_DTAW("CEP", "subject"),
                                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(subject_root);
    return subject_root;
}

static cepCell* cei_lookup_op_cell(cepOID oid) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);

    cepDT ops_name = cep_ops_make_dt("ops");
    cepCell* ops_root = cep_cell_find_by_name(rt_root, &ops_name);
    munit_assert_not_null(ops_root);

    cepDT lookup = {.domain = oid.domain, .tag = oid.tag, .glob = 0u};
    cepCell* op = cep_cell_find_by_name(ops_root, &lookup);
    return op ? cep_cell_resolve(op) : NULL;
}

static cepOID cei_read_oid_field(const char* field_name) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    munit_assert_not_null(sys_root);

    cepCell* state_root = cep_cell_find_by_name(sys_root, CEP_DTAW("CEP", "state"));
    if (!state_root) {
        state_root = cep_cell_ensure_dictionary_child(sys_root, CEP_DTAW("CEP", "state"), CEP_STORAGE_RED_BLACK_T);
    }
    munit_assert_not_null(state_root);

    cepDT field_dt = cep_ops_make_dt(field_name);
    cepCell* entry = cep_cell_find_by_name(state_root, &field_dt);
    if (entry && cep_cell_has_data(entry)) {
        const cepOID* stored = cep_cell_data(entry);
        if (stored) {
            return *stored;
        }
    }
    return cep_oid_invalid();
}

MunitResult test_cei_mailbox(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    test_boot_cycle_prepare(params);
    CeiRuntimeScope scope = cei_runtime_start(true);

    cepCell* subject = cei_subject_cell();
    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:warn"),
        .note = "diagnostics mailbox emission",
        .topic = "mailbox.ttl",
        .topic_intern = true,
        .origin_name = CEP_DTAW("CEP", "mailbox"),
        .origin_kind = "kernel",
        .subject = subject,
        .has_code = true,
        .code = 42u,
        .payload_id = "CAS:deadbeef",
        .emit_signal = false,
        .attach_to_op = false,
    };

    bool emitted = cep_cei_emit(&req);
    if (!emitted) {
        munit_logf(MUNIT_LOG_ERROR, "cep_cei_emit failed: %d", cep_cei_debug_last_error());
        cepCell* diag = cep_cei_diagnostics_mailbox();
        munit_logf(MUNIT_LOG_ERROR, "diag mailbox=%p", (void*)diag);
        if (diag) {
            cepCell* meta = cep_cell_find_by_name(diag, CEP_DTAW("CEP", "meta"));
            cepCell* runtime = meta ? cep_cell_find_by_name(meta, CEP_DTAW("CEP", "runtime")) : NULL;
            munit_logf(MUNIT_LOG_ERROR, "meta=%p runtime=%p", (void*)meta, (void*)runtime);
        }
    }
    munit_assert_true(emitted);

    cepCell* message = cei_latest_message();
    cepCell* err = cep_cell_find_by_name(message, CEP_DTAW("CEP", "err"));
    munit_assert_not_null(err);
    err = cep_cell_resolve(err);
    munit_assert_true(cep_cell_is_immutable(err));

    cepCell* sev_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "sev"));
    munit_assert_not_null(sev_cell);
    cepDT sev_value = cei_read_dt_cell(sev_cell);
    cei_assert_dt_matches(&sev_value, CEP_DTAW("CEP", "sev:warn"));

    cepCell* note_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "note"));
    munit_assert_not_null(note_cell);
    munit_assert_string_equal(cei_leaf_text(note_cell), "diagnostics mailbox emission");

    cepCell* topic_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "topic"));
    munit_assert_not_null(topic_cell);
    munit_assert_string_equal(cei_leaf_text(topic_cell), "mailbox.ttl");

    cepCell* code_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "code"));
    munit_assert_not_null(code_cell);
    munit_assert_string_equal(cei_leaf_text(code_cell), "42");

    cepCell* payload_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "payload_id"));
    munit_assert_not_null(payload_cell);
    munit_assert_string_equal(cei_leaf_text(payload_cell), "CAS:deadbeef");

    cepCell* issued_beat = cep_cell_find_by_name(err, CEP_DTAW("CEP", "issued_beat"));
    munit_assert_not_null(issued_beat);
    uint64_t beat_value = strtoull(cei_leaf_text(issued_beat), NULL, 10);
    munit_assert_uint64(beat_value, ==, (uint64_t)cep_heartbeat_current());

    cepCell* origin = cep_cell_find_by_name(err, CEP_DTAW("CEP", "origin"));
    munit_assert_not_null(origin);
    cepCell* origin_name = cep_cell_find_by_name(origin, CEP_DTAW("CEP", "name"));
    munit_assert_not_null(origin_name);
    cepDT origin_value = cei_read_dt_cell(origin_name);
    cei_assert_dt_matches(&origin_value, CEP_DTAW("CEP", "mailbox"));
    cepCell* origin_kind = cep_cell_find_by_name(origin, CEP_DTAW("CEP", "kind"));
    munit_assert_not_null(origin_kind);
    munit_assert_string_equal(cei_leaf_text(origin_kind), "kernel");

    cepCell* subject_link = cep_cell_find_by_name(err, CEP_DTAW("CEP", "role_subj"));
    munit_assert_not_null(subject_link);
    munit_assert_true(cep_cell_is_link(subject_link));
    cepCell* resolved_subject = cep_link_pull(subject_link);
    munit_assert_ptr_equal(resolved_subject, subject);

    cei_runtime_cleanup(&scope);
    return MUNIT_OK;
}

/* Guard that append-only violations on immutable parents emit sev:usage CEI
   facts that link to the owning OPS dossier and close the operation with
   sts:fail. */
MunitResult test_cell_append_guard_cei(const MunitParameter params[], void* fixture) {
    (void)fixture;
    test_boot_cycle_prepare(params);
    CeiRuntimeScope scope = cei_runtime_start(true);

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops_root = cep_cell_ensure_dictionary_child(rt_root,
                                                         CEP_DTAW("CEP", "ops"),
                                                         CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(ops_root);

    cepDT verb = cep_ops_make_dt("op/cei");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, "/tmp/cei-append", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(oid));

    cepCell* op_cell = cei_lookup_op_cell(oid);
    munit_assert_not_null(op_cell);
    op_cell = cep_cell_resolve(op_cell);
    munit_assert_not_null(op_cell);
    bool op_store_writable = true;
    if (op_cell->store) {
        op_store_writable = op_cell->store->writable != 0u;
        op_cell->store->writable = 0u;
    }

    cepCell* msgs = cei_msgs_root();
    munit_assert_not_null(msgs);
    munit_assert_not_null(msgs->store);
    size_t before_msgs = msgs->store->chdCount;

    uint32_t payload = 7u;
    cepCell* inserted = cep_cell_add_value(op_cell,
                                           CEP_DTAW("CEP", "cei_violate"),
                                           0,
                                           CEP_DTAW("CEP", "value"),
                                           &payload,
                                           sizeof payload,
                                           sizeof payload);
    munit_assert_null(inserted);

    size_t after_msgs = msgs->store->chdCount;
    munit_assert_size(after_msgs, ==, before_msgs + 1u);

    cepCell* message = cei_latest_message();
    cepCell* err = cep_cell_find_by_name(message, CEP_DTAW("CEP", "err"));
    munit_assert_not_null(err);
    err = cep_cell_resolve(err);
    munit_assert_not_null(err);

    cepCell* sev_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "sev"));
    munit_assert_not_null(sev_cell);
    cepDT sev_value = cei_read_dt_cell(sev_cell);
    cei_assert_dt_matches(&sev_value, CEP_DTAW("CEP", "sev:usage"));

    cepCell* topic_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "topic"));
    munit_assert_not_null(topic_cell);
    munit_assert_string_equal(cei_leaf_text(topic_cell), "cell.store.readonly");

    cepCell* role_cell = cep_cell_find_by_name(err, CEP_DTAW("CEP", "role_subj"));
    munit_assert_not_null(role_cell);
    cepCell* linked = cep_link_pull(role_cell);
    munit_assert_ptr_equal(linked, op_cell);

    cepCell* close_branch = cep_cell_find_by_name(op_cell, CEP_DTAW("CEP", "close"));
    munit_assert_not_null(close_branch);
    close_branch = cep_cell_resolve(close_branch);
    munit_assert_not_null(close_branch);
    cepCell* status_cell = cep_cell_find_by_name(close_branch, CEP_DTAW("CEP", "status"));
    munit_assert_not_null(status_cell);
    cepDT status_value = cei_read_dt_cell(status_cell);
    cei_assert_dt_matches(&status_value, CEP_DTAW("CEP", "sts:fail"));

    if (op_cell->store) {
        op_cell->store->writable = op_store_writable ? 1u : 0u;
    }

    cei_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_cei_signal_ledger(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    test_boot_cycle_prepare(params);
    CeiRuntimeScope scope = cei_runtime_start(true);

    cepBeatNumber due = cep_heartbeat_next();
    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:crit"),
        .note = "signal path test",
        .emit_signal = true,
    };
    bool emitted = cep_cei_emit(&req);
    if (!emitted) {
        munit_logf(MUNIT_LOG_ERROR, "cep_cei_emit failed: %d", cep_cei_debug_last_error());
    }
    munit_assert_true(emitted);

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* beat_root = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "beat"));
    munit_assert_not_null(beat_root);
    beat_root = cep_cell_resolve(beat_root);

    cepDT beat_name = {.domain = CEP_ACRO("HB"),
                       .tag = cep_id_to_numeric((cepID)(due + 1u)),
                       .glob = 0u};
    cepCell* beat_cell = cep_cell_find_by_name(beat_root, &beat_name);
    munit_assert_not_null(beat_cell);
    beat_cell = cep_cell_resolve(beat_cell);

    cepCell* impulses = cep_cell_find_by_name(beat_cell, CEP_DTAW("CEP", "impulses"));
    munit_assert_not_null(impulses);
    impulses = cep_cell_resolve(impulses);

    cepCell* ledger_entry = cep_cell_last_all(impulses);
    munit_assert_not_null(ledger_entry);
    ledger_entry = cep_cell_resolve(ledger_entry);
    const char* text = cei_leaf_text(ledger_entry);
    munit_assert_not_null(text);
    size_t text_len = strlen(text);
    munit_assert_size(text_len, >=, strlen("signal=/CEP:sig_"));
    munit_assert_int(strncmp(text, "signal=/CEP:sig_", strlen("signal=/CEP:sig_")), ==, 0);

    cei_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_cei_op_failure(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    test_boot_cycle_prepare(params);
    CeiRuntimeScope scope = cei_runtime_start(false);

    cepDT verb = cep_ops_make_dt("op/cei");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, "/cei/op", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(oid));

    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:crit"),
        .note = "attach to operation",
        .attach_to_op = true,
        .op = oid,
    };
    bool emitted = cep_cei_emit(&req);
    if (!emitted) {
        munit_logf(MUNIT_LOG_ERROR, "cep_cei_emit failed: %d", cep_cei_debug_last_error());
    }
    munit_assert_true(emitted);

    cepCell* op_cell = cei_lookup_op_cell(oid);
    munit_assert_not_null(op_cell);

    cepCell* close_branch = cep_cell_find_by_name(op_cell, CEP_DTAW("CEP", "close"));
    munit_assert_not_null(close_branch);
    close_branch = cep_cell_resolve(close_branch);
    munit_assert_true(cep_cell_is_immutable(close_branch));

    cepCell* status_cell = cep_cell_find_by_name(close_branch, CEP_DTAW("CEP", "status"));
    munit_assert_not_null(status_cell);
    cepDT status = cei_read_dt_cell(status_cell);
    cei_assert_dt_matches(&status, CEP_DTAW("CEP", "sts:fail"));

    cei_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_cei_fatal_shutdown(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    test_boot_cycle_prepare(params);
    CeiRuntimeScope scope = cei_runtime_start(true);

    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:fatal"),
        .note = "fatal condition",
        .emit_signal = false,
    };
    bool emitted = cep_cei_emit(&req);
    if (!emitted) {
        munit_logf(MUNIT_LOG_ERROR, "cep_cei_emit failed: %d", cep_cei_debug_last_error());
    }
    munit_assert_true(emitted);

    cepOID shdn_oid = cei_read_oid_field("shdn_oid");
    munit_assert_true(cep_oid_is_valid(shdn_oid));

    cei_runtime_cleanup(&scope);
    return MUNIT_OK;
}
