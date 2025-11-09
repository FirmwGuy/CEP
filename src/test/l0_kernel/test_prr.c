/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Public domain (CC0 1.0). See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "test.h"

#include "cep_cei.h"
#include "cep_cell.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_runtime.h"
#include "cep_ops.h"
#include "cep_namepool.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[4];
} CepPrrPathBuf;

typedef struct {
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} PrrRuntimeScope;

static PrrRuntimeScope prr_runtime_start(void) {
    PrrRuntimeScope scope = {
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
        .ensure_directories = false,
        .enforce_visibility = false,
        .boot_ops = true,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
    return scope;
}

static void prr_runtime_cleanup(PrrRuntimeScope* scope) {
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

static size_t prr_diag_message_count(void);
static const char* prr_last_diag_note(void);

static void prr_step(unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        if (!cep_heartbeat_step()) {
            munit_logf(MUNIT_LOG_ERROR, "heartbeat_step failed ops_err=%d", cep_ops_debug_last_error());
            size_t diag_count = prr_diag_message_count();
            const char* note = diag_count ? prr_last_diag_note() : "<none>";
            munit_logf(MUNIT_LOG_ERROR, "diag_count=%zu note=%s", diag_count, note);
            munit_error("heartbeat step failed");
        }
    }
}

static void prr_step_checked(unsigned count, const char* label) {
    for (unsigned i = 0; i < count; ++i) {
        if (!cep_heartbeat_step()) {
            size_t diag_count = prr_diag_message_count();
            const char* note = diag_count ? prr_last_diag_note() : "<none>";
            munit_logf(MUNIT_LOG_ERROR,
                       "%s heartbeat_step failed note=%s",
                       label ? label : "prr_step_checked",
                       note);
            munit_error("heartbeat step failed");
        }
    }
}

static bool prr_rollbacks_enabled(void) {
    const char* env = getenv("CEP_TEST_ENABLE_PRR_ROLLBACK");
    if (!env || !env[0]) {
        return true;
    }
    return env[0] != '0';
}

static const cepPath* prr_make_path(CepPrrPathBuf* buf, const cepDT* segments, unsigned count) {
    munit_assert_uint(count, <=, cep_lengthof(buf->segments));
    buf->length = count;
    buf->capacity = cep_lengthof(buf->segments);
    for (unsigned i = 0; i < count; ++i) {
        buf->segments[i].dt = segments[i];
        buf->segments[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}

static cepCell* prr_diag_msgs(void) {
    cepCell* mailbox = cep_cei_diagnostics_mailbox();
    munit_assert_not_null(mailbox);
    mailbox = cep_cell_resolve(mailbox);
    cepCell* msgs = cep_cell_find_by_name(mailbox, CEP_DTAW("CEP", "msgs"));
    munit_assert_not_null(msgs);
    return cep_cell_resolve(msgs);
}

static size_t prr_impulse_backlog_count(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);
    cepCell* data = cep_cell_resolve(data_root);
    munit_assert_not_null(data);

    cepCell* mailbox = cep_cell_find_by_name(data, CEP_DTAW("CEP", "mailbox"));
    if (!mailbox) {
        mailbox = cep_cell_find_by_name_all(data, CEP_DTAW("CEP", "mailbox"));
        if (!mailbox) {
            return 0u;
        }
    }
    cepCell* resolved_mailbox = cep_cell_resolve(mailbox);
    if (!resolved_mailbox) {
        resolved_mailbox = cep_cell_find_by_name_all(data, CEP_DTAW("CEP", "mailbox"));
        if (!resolved_mailbox) {
            return 0u;
        }
    }

    cepCell* impulses = cep_cell_find_by_name(resolved_mailbox, CEP_DTAW("CEP", "impulses"));
    if (!impulses) {
        impulses = cep_cell_find_by_name_all(resolved_mailbox, CEP_DTAW("CEP", "impulses"));
        if (!impulses) {
            return 0u;
        }
    }
    cepCell* resolved_impulses = cep_cell_resolve(impulses);
    if (!resolved_impulses) {
        resolved_impulses = cep_cell_find_by_name_all(resolved_mailbox, CEP_DTAW("CEP", "impulses"));
        if (!resolved_impulses) {
            return 0u;
        }
    }

    cepCell* msgs = cep_cell_find_by_name(resolved_impulses, CEP_DTAW("CEP", "msgs"));
    if (!msgs) {
        msgs = cep_cell_find_by_name_all(resolved_impulses, CEP_DTAW("CEP", "msgs"));
        if (!msgs) {
            return 0u;
        }
    }
    cepCell* resolved_msgs = cep_cell_resolve(msgs);
    if (!resolved_msgs) {
        resolved_msgs = cep_cell_find_by_name_all(resolved_impulses, CEP_DTAW("CEP", "msgs"));
        if (!resolved_msgs) {
            return 0u;
        }
    }

    cepCell* iter_base = resolved_msgs ? resolved_msgs : msgs;
    size_t count = 0u;
    for (cepCell* node = cep_cell_first_all(iter_base); node; node = cep_cell_next_all(iter_base, node)) {
        ++count;
    }
    return count;
}

static size_t prr_diag_message_count(void) {
    cepCell* msgs = prr_diag_msgs();
    if (!msgs->store) {
        return 0u;
    }
    return msgs->store->chdCount;
}

static const char* prr_last_diag_note(void) {
    static const char* const fallback = "<none>";
    cepCell* msgs = prr_diag_msgs();
    cepCell* last = cep_cell_last_all(msgs);
    if (!last) {
        return fallback;
    }
    last = cep_cell_resolve(last);
    if (!last) {
        return fallback;
    }

    const cepDT* note_name = CEP_DTAW("CEP", "note");
    cepCell* err = cep_cell_find_by_name(last, CEP_DTAW("CEP", "err"));
    if (err) {
        err = cep_cell_resolve(err);
        if (err) {
            cepCell* note = cep_cell_find_by_name(err, note_name);
            if (note) {
                note = cep_cell_resolve(note);
                if (note && cep_cell_has_data(note)) {
                    return (const char*)cep_cell_data(note);
                }
            }
        }
    }

    for (cepCell* child = cep_cell_first_all(last); child; child = cep_cell_next_all(last, child)) {
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(resolved);
        if (name && cep_dt_compare(name, note_name) == 0 && cep_cell_has_data(resolved)) {
            return (const char*)cep_cell_data(resolved);
        }
        cepCell* nested = cep_cell_find_by_name(resolved, note_name);
        if (nested) {
            nested = cep_cell_resolve(nested);
            if (nested && cep_cell_has_data(nested)) {
                return (const char*)cep_cell_data(nested);
            }
        }
    }

    return fallback;
}

static int prr_enzyme_calls;

static int prr_enzyme_counter(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    prr_enzyme_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

MunitResult test_prr_pause_resume_backlog(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    if (!prr_rollbacks_enabled()) {
        return MUNIT_SKIP;
    }
    if (test_boot_cycle_is_after(params)) {
        return MUNIT_SKIP;
    }
    test_boot_cycle_prepare(params);
    PrrRuntimeScope scope = prr_runtime_start();

    prr_enzyme_calls = 0;
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    cepDT signal_segments[] = {
        *CEP_DTAW("CEP", "sig_prr"),
        *CEP_DTAW("CEP", "echo"),
    };
    CepPrrPathBuf signal_buf;
    const cepPath* signal_path = prr_make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    cepDT enzyme_name = *CEP_DTAW("CEP", "test_prr_ez");
    cepEnzymeDescriptor descriptor = {
        .name = enzyme_name,
        .label = "prr-enzyme",
        .callback = prr_enzyme_counter,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    /* Begin pause sequence */
    if (!cep_runtime_pause()) {
        size_t after = prr_diag_message_count();
        const char* note = after ? prr_last_diag_note() : "<none>";
        munit_logf(MUNIT_LOG_ERROR, "pause failed note=%s", note);
        munit_error("pause failed");
    }
    for (unsigned i = 0; i < 4u; ++i) {
        if (!cep_heartbeat_step()) {
            break;
        }
    }
    munit_assert_true(cep_runtime_is_paused());

    /* Enqueue non-control impulse; it should park while paused. */
    munit_assert_int(cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, signal_path, NULL), ==, CEP_ENZYME_SUCCESS);
    prr_step(2u);
    munit_assert_int(prr_enzyme_calls, ==, 0);

    /* Resume and ensure backlog drains deterministically. */
    munit_assert_true(cep_runtime_resume());
    unsigned attempts = 0u;
    while (prr_enzyme_calls == 0 && attempts < 100u) {
#if defined(CEP_ENABLE_DEBUG)
        munit_logf(MUNIT_LOG_INFO,
                   "pause_resume_backlog attempts=%u enzyme_calls=%d",
                   attempts,
                   prr_enzyme_calls);
#endif
        if (!cep_heartbeat_step()) {
            size_t diag_count = prr_diag_message_count();
            const char* diag_note = diag_count ? prr_last_diag_note() : "<none>";
            munit_logf(MUNIT_LOG_ERROR, "resume-step failed note=%s", diag_note);
            munit_error("heartbeat step failed during resume drain");
        }
        attempts += 1u;
    }
    munit_assert_int(prr_enzyme_calls, ==, 1);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_prr_pause_rollback_backlog_guard(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    if (!prr_rollbacks_enabled()) {
        return MUNIT_SKIP;
    }
    if (test_boot_cycle_is_after(params)) {
        return MUNIT_SKIP;
    }

    test_boot_cycle_prepare(params);

    test_runtime_shutdown();
    PrrRuntimeScope scope = prr_runtime_start();

    prr_enzyme_calls = 0;

    cepDT signal_segments[] = {
        *CEP_DTAW("CEP", "sig_prr"),
        *CEP_DTAW("CEP", "echo"),
    };
    CepPrrPathBuf signal_buf;
    const cepPath* signal_path = prr_make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    cepDT enzyme_name = *CEP_DTAW("CEP", "prr_guard");
    cepEnzymeDescriptor descriptor = {
        .name = enzyme_name,
        .label = "prr-guard-enzyme",
        .callback = prr_enzyme_counter,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepBeatNumber target_beat = cep_heartbeat_current();
    munit_assert_true(cep_runtime_pause());
    prr_step_checked(4u, "pause");
    munit_assert_true(cep_runtime_is_paused());

    munit_assert_int(cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID, signal_path, NULL), ==, CEP_ENZYME_SUCCESS);
    prr_step_checked(2u, "enqueue");
    munit_assert_int(prr_enzyme_calls, ==, 0);
    size_t backlog_initial = prr_impulse_backlog_count();
    munit_logf(MUNIT_LOG_INFO, "backlog before guard prep=%zu", backlog_initial);
    munit_assert_size(backlog_initial, ==, 1u);

    size_t diag_before = prr_diag_message_count();
    munit_assert_true(cep_runtime_rollback(target_beat));
    prr_step_checked(4u, "rollback-cutover");
    munit_assert_true(cep_runtime_is_paused());
    munit_assert_false(cep_runtime_rollback(target_beat));
    size_t diag_after = prr_diag_message_count();
    munit_assert_size(diag_after, ==, diag_before + 1u);

    munit_assert_int(prr_enzyme_calls, ==, 0);
    size_t backlog_after_guard = prr_impulse_backlog_count();
    munit_logf(MUNIT_LOG_INFO, "backlog after guard=%zu", backlog_after_guard);
    munit_assert_size(backlog_after_guard, ==, 1u);
    munit_assert_true(cep_runtime_resume());
    unsigned attempts = 0u;
    while (prr_enzyme_calls == 0 && attempts < 100u) {
#if defined(CEP_ENABLE_DEBUG)
        munit_logf(MUNIT_LOG_INFO,
                   "pause_rollback_backlog_guard attempts=%u enzyme_calls=%d",
                   attempts,
                   prr_enzyme_calls);
#endif
        if (!cep_heartbeat_step()) {
            size_t diag_count = prr_diag_message_count();
            const char* diag_note = diag_count ? prr_last_diag_note() : "<none>";
            munit_logf(MUNIT_LOG_ERROR, "resume-step failed note=%s", diag_note);
            munit_error("heartbeat step failed during resume drain");
        }
        attempts += 1u;
    }

    munit_assert_int(prr_enzyme_calls, ==, 1);
    munit_assert_size(prr_impulse_backlog_count(), ==, 0u);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_prr_soft_delete_lookup(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    if (!prr_rollbacks_enabled()) {
        return MUNIT_SKIP;
    }
    if (test_boot_cycle_is_after(params)) {
        return MUNIT_SKIP;
    }

    test_boot_cycle_prepare(params);

    test_runtime_shutdown();
    PrrRuntimeScope scope = prr_runtime_start();

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);
    munit_assert_true(cep_cell_has_data(data_root));

    cepDT dict_name = *CEP_DTAW("CEP", "prr_soft");
    cepDT value_name = *CEP_DTAW("CEP", "marker");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT value_type = *CEP_DTAW("CEP", "value");
    munit_assert_true(cep_dt_is_valid(&value_type));

    cepCell* dict = cep_cell_add_dictionary(data_root, &dict_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(dict);
    prr_step_checked(2u, "dict-create");

    uint32_t payload = 0x1234u;
    cepCell* value_cell = cep_cell_add_value(dict, &value_name, 0, &value_type, &payload, sizeof payload, sizeof payload);
    munit_assert_not_null(value_cell);
    prr_step_checked(2u, "value-create");
    cepBeatNumber creation_beat = cep_heartbeat_current();

    cep_cell_delete(value_cell);
    prr_step_checked(2u, "value-delete");

    munit_assert_true(cep_runtime_pause());
    prr_step_checked(3u, "soft-pause");
    munit_assert_true(cep_runtime_is_paused());
    munit_assert_true(cep_runtime_rollback(creation_beat));
    prr_step_checked(4u, "soft-rollback");

    cepOpCount horizon_stamp = cep_runtime_view_horizon_stamp();
    munit_assert_uint64(horizon_stamp, !=, 0u);

    const cepCell* root = cep_heartbeat_topology()->root;
    munit_assert_not_null(root);

    CepPrrPathBuf dict_path_buf;
    const cepDT dict_segments[] = {
        *CEP_DTAW("CEP", "data"),
        dict_name,
    };
    const cepPath* dict_path = prr_make_path(&dict_path_buf, dict_segments, cep_lengthof(dict_segments));

    cepCell* dict_live = cep_cell_find_by_path(root, dict_path);
    munit_assert_not_null(dict_live);
    dict_live = cep_cell_resolve(dict_live);
    munit_assert_not_null(dict_live);
    munit_assert_true(cep_cell_is_deleted(dict_live));

    cepCell* dict_past = cep_cell_find_by_path_past(root, dict_path, horizon_stamp);
    munit_assert_not_null(dict_past);
    dict_past = cep_cell_resolve(dict_past);
    munit_assert_not_null(dict_past->store);
    munit_assert_ptr_equal(dict_past->store->owner, dict_past);
    munit_assert_true(dict_past->deleted == 0u || dict_past->deleted > horizon_stamp);

    CepPrrPathBuf value_path_buf;
    const cepDT value_segments[] = {
        *CEP_DTAW("CEP", "data"),
        dict_name,
        value_name,
    };
    const cepPath* value_path = prr_make_path(&value_path_buf, value_segments, cep_lengthof(value_segments));

    cepCell* value_live = cep_cell_find_by_path(root, value_path);
    munit_assert_not_null(value_live);
    value_live = cep_cell_resolve(value_live);
    munit_assert_true(cep_cell_is_deleted(value_live));

    cepCell* value_past = cep_cell_find_by_path_past(root, value_path, horizon_stamp);
    munit_assert_not_null(value_past);
    value_past = cep_cell_resolve(value_past);
    munit_assert_true(value_past->deleted == 0u || value_past->deleted > horizon_stamp);
    munit_assert_true(cep_cell_has_data(value_past));
    const uint32_t* past_payload = (const uint32_t*)cep_cell_data(value_past);
    munit_assert_not_null(past_payload);
    munit_assert_uint32(*past_payload, ==, payload);

    munit_assert_true(cep_runtime_resume());
    prr_step(6u);

    root = cep_heartbeat_topology()->root;
    munit_assert_not_null(root);
    dict_live = cep_cell_find_by_path(root, dict_path);
    munit_assert_not_null(dict_live);
    dict_live = cep_cell_resolve(dict_live);
    munit_assert_false(cep_cell_is_deleted(dict_live));
    munit_assert_not_null(dict_live->store);
    munit_assert_ptr_equal(dict_live->store->owner, dict_live);

    value_live = cep_cell_find_by_path(root, value_path);
    munit_assert_not_null(value_live);
    value_live = cep_cell_resolve(value_live);
    munit_assert_false(cep_cell_is_deleted(value_live));
    munit_assert_true(cep_cell_has_data(value_live));
    const uint32_t* restored = (const uint32_t*)cep_cell_data(value_live);
    munit_assert_not_null(restored);
    munit_assert_uint32(*restored, ==, payload);

    value_past = cep_cell_find_by_path_past(root, value_path, horizon_stamp);
    munit_assert_not_null(value_past);
    value_past = cep_cell_resolve(value_past);
    munit_assert_ptr_equal(value_live, value_past);
    munit_assert_true(cep_cell_has_data(value_past));

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_prr_view_horizon_snapshot(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;
    if (!prr_rollbacks_enabled()) {
        return MUNIT_SKIP;
    }
    test_boot_cycle_prepare(params);
    test_runtime_shutdown();
    PrrRuntimeScope scope = prr_runtime_start();

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);
    munit_assert_true(cep_cell_has_data(data_root));

    cepDT dict_name = *CEP_DTAW("CEP", "prr_view");
    cepDT value_name = *CEP_DTAW("CEP", "target");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");

    cepCell* dict = cep_cell_add_dictionary(data_root, &dict_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(dict);
    prr_step(2u);

    uint32_t value = 0xA5A5u;
    cepDT value_type = *CEP_DTAW("CEP", "value");
    munit_assert_true(cep_dt_is_valid(&value_type));
    cepCell* value_cell = cep_cell_add_value(dict, &value_name, 0, &value_type, &value, sizeof value, sizeof value);
    munit_assert_not_null(value_cell);
    prr_step(2u);
    cepBeatNumber creation_beat = cep_heartbeat_current();

    /* Remove the value and commit the deletion (soft-delete to mirror runtime semantics). */
    cep_cell_delete(value_cell);
    prr_step(2u);

    CepPrrPathBuf path_buf;
    cepDT path_segments[] = {
        *CEP_DTAW("CEP", "data"),
        dict_name,
        value_name,
    };
    const cepPath* target_path = prr_make_path(&path_buf, path_segments, cep_lengthof(path_segments));
    const cepCell* root = cep_heartbeat_topology()->root;
    munit_assert_not_null(root);
    cepCell* removed = cep_cell_find_by_path(root, target_path);
    munit_assert_not_null(removed);
    removed = cep_cell_resolve(removed);
    munit_assert_not_null(removed);
    munit_assert_true(cep_cell_is_deleted(removed));

    /* Roll back visibility to the creation beat. */
    munit_assert_true(cep_runtime_pause());
    prr_step(3u);
    munit_assert_true(cep_runtime_is_paused());
    munit_assert_true(cep_runtime_rollback(creation_beat));
    prr_step(6u);
    munit_assert_true(cep_runtime_resume());
    prr_step(4u);

    munit_assert_uint64(cep_runtime_view_horizon(), ==, creation_beat);
    cepDT dict_path_segments[] = {
        *CEP_DTAW("CEP", "data"),
        dict_name,
    };
    CepPrrPathBuf dict_path_buf;
    const cepPath* dict_path = prr_make_path(&dict_path_buf, dict_path_segments, cep_lengthof(dict_path_segments));
    cepCell* dict_live = cep_cell_find_by_path(root, dict_path);
    munit_assert_not_null(dict_live);
    dict_live = cep_cell_resolve(dict_live);
    munit_assert_not_null(dict_live);
    munit_assert_not_null(dict_live->store);
    munit_assert_ptr_equal(dict_live->store->owner, dict_live);
    cepOpCount horizon_stamp = cep_runtime_view_horizon_stamp();
    cepCell* debug_live = cep_cell_find_by_path_past(root, target_path, horizon_stamp);
    munit_assert_not_null(debug_live);

    cepCell* live = cep_cell_find_by_path(root, target_path);
    munit_assert_not_null(live);
    live = cep_cell_resolve(live);
    munit_assert_not_null(live);
    munit_assert_true(cep_cell_has_data(live));
    const uint32_t* restored = (const uint32_t*)cep_cell_data(live);
    munit_assert_not_null(restored);
    munit_assert_uint32(*restored, ==, value);
    munit_assert_ptr_equal((const void*)debug_live, (const void*)live);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

/* Validates that a soft-deleted dictionary (and nested entries) revives after
   pause→rollback→resume and that live lookups converge with `_past`. */
MunitResult test_prr_soft_deleted_dictionary_revives(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    if (!prr_rollbacks_enabled()) {
        return MUNIT_SKIP;
    }

    if (test_boot_cycle_is_after(params)) {
        return MUNIT_SKIP;
    }

    test_boot_cycle_prepare(params);
    test_runtime_shutdown();
    PrrRuntimeScope scope = prr_runtime_start();

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);
    munit_assert_true(cep_cell_has_data(data_root));

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT value_type = *CEP_DTAW("CEP", "value");
    munit_assert_true(cep_dt_is_valid(&value_type));

    cepDT dict_name = *CEP_DTAW("CEP", "prr_revive");
    cepDT inner_name = *CEP_DTAW("CEP", "branch");
    cepDT value_name = *CEP_DTAW("CEP", "payload");

    cepCell* dict = cep_cell_add_dictionary(data_root, &dict_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(dict);
    prr_step_checked(2u, "dict-create");

    cepCell* inner = cep_cell_add_dictionary(dict, &inner_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(inner);
    prr_step_checked(2u, "inner-create");

    uint32_t payload = 0xCAF3u;
    cepCell* value_cell = cep_cell_add_value(inner, &value_name, 0, &value_type, &payload, sizeof payload, sizeof payload);
    munit_assert_not_null(value_cell);
    prr_step_checked(2u, "value-create");

    cepBeatNumber creation_beat = cep_heartbeat_current();
    munit_assert_uint64(creation_beat, !=, CEP_BEAT_INVALID);

    cep_cell_delete(dict);
    prr_step_checked(2u, "dict-soft-delete");

    const cepCell* root = cep_heartbeat_topology()->root;
    munit_assert_not_null(root);

    CepPrrPathBuf dict_path_buf;
    const cepDT dict_segments[] = {
        *CEP_DTAW("CEP", "data"),
        dict_name,
    };
    const cepPath* dict_path = prr_make_path(&dict_path_buf, dict_segments, cep_lengthof(dict_segments));

    CepPrrPathBuf inner_path_buf;
    const cepDT inner_segments[] = {
        *CEP_DTAW("CEP", "data"),
        dict_name,
        inner_name,
    };
    const cepPath* inner_path = prr_make_path(&inner_path_buf, inner_segments, cep_lengthof(inner_segments));

    CepPrrPathBuf value_path_buf;
    const cepDT value_segments[] = {
        *CEP_DTAW("CEP", "data"),
        dict_name,
        inner_name,
        value_name,
    };
    const cepPath* value_path = prr_make_path(&value_path_buf, value_segments, cep_lengthof(value_segments));

    cepCell* dict_live = cep_cell_find_by_path(root, dict_path);
    munit_assert_not_null(dict_live);
    dict_live = cep_cell_resolve(dict_live);
    munit_assert_true(cep_cell_is_deleted(dict_live));

    cepCell* inner_live = cep_cell_find_by_path(root, inner_path);
    munit_assert_not_null(inner_live);
    inner_live = cep_cell_resolve(inner_live);
    munit_assert_true(cep_cell_is_deleted(inner_live));

    cepCell* value_live = cep_cell_find_by_path(root, value_path);
    munit_assert_not_null(value_live);
    value_live = cep_cell_resolve(value_live);
    munit_assert_true(cep_cell_is_deleted(value_live));

    munit_assert_true(cep_runtime_pause());
    prr_step_checked(3u, "dict-pause");
    munit_assert_true(cep_runtime_is_paused());

    munit_assert_true(cep_runtime_rollback(creation_beat));
    prr_step_checked(6u, "dict-rollback");

    cepOpCount horizon_stamp = cep_runtime_view_horizon_stamp();
    munit_assert_uint64(horizon_stamp, !=, 0u);

    munit_assert_true(cep_runtime_resume());
    prr_step_checked(6u, "dict-resume");

    root = cep_heartbeat_topology()->root;
    munit_assert_not_null(root);

    dict_live = cep_cell_find_by_path(root, dict_path);
    munit_assert_not_null(dict_live);
    dict_live = cep_cell_resolve(dict_live);
    munit_assert_false(cep_cell_is_deleted(dict_live));
    munit_assert_not_null(dict_live->store);
    munit_assert_ptr_equal(dict_live->store->owner, dict_live);

    inner_live = cep_cell_find_by_path(root, inner_path);
    munit_assert_not_null(inner_live);
    inner_live = cep_cell_resolve(inner_live);
    munit_assert_false(cep_cell_is_deleted(inner_live));

    value_live = cep_cell_find_by_path(root, value_path);
    munit_assert_not_null(value_live);
    value_live = cep_cell_resolve(value_live);
    munit_assert_false(cep_cell_is_deleted(value_live));
    munit_assert_true(cep_cell_has_data(value_live));
    const uint32_t* revived = (const uint32_t*)cep_cell_data(value_live);
    munit_assert_not_null(revived);
    munit_assert_uint32(*revived, ==, payload);

    cepCell* dict_past = cep_cell_find_by_path_past(root, dict_path, horizon_stamp);
    munit_assert_not_null(dict_past);
    dict_past = cep_cell_resolve(dict_past);
    munit_assert_ptr_equal(dict_past, dict_live);

    cepCell* value_past = cep_cell_find_by_path_past(root, value_path, horizon_stamp);
    munit_assert_not_null(value_past);
    value_past = cep_cell_resolve(value_past);
    munit_assert_ptr_equal(value_past, value_live);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

static cepCell* prr_ops_root(void) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops);
    cepCell* resolved = cep_cell_resolve(ops);
    munit_assert_not_null(resolved);
    munit_assert_true(cep_cell_require_dictionary_store(&resolved));
    return resolved;
}

static cepCell* prr_find_latest_op(const char* verb_tag) {
    munit_assert_not_null(verb_tag);
    cepCell* ops_root = prr_ops_root();
    cepDT envelope_name = cep_ops_make_dt("envelope");
    cepDT verb_field = cep_ops_make_dt("verb");
    cepDT verb_dt = cep_ops_make_dt(verb_tag);

    for (cepCell* node = cep_cell_last_all(ops_root); node; node = cep_cell_prev_all(ops_root, node)) {
        cepCell* op = cep_cell_resolve(node);
        if (!op) {
            continue;
        }
        cepCell* envelope = cep_cell_find_by_name(op, &envelope_name);
        if (!envelope) {
            continue;
        }
        envelope = cep_cell_resolve(envelope);
        if (!envelope) {
            continue;
        }
        cepCell* verb_cell = cep_cell_find_by_name(envelope, &verb_field);
        if (!verb_cell || !cep_cell_has_data(verb_cell)) {
            continue;
        }
        const cepDT* recorded = (const cepDT*)cep_cell_data(verb_cell);
        if (recorded && cep_dt_compare(recorded, &verb_dt) == 0) {
            return op;
        }
    }
    return NULL;
}

static void prr_assert_history_autoid_monotonic(cepCell* op) {
    munit_assert_not_null(op);
    cepCell* close_branch = cep_cell_find_by_name(op, CEP_DTAW("CEP", "close"));
    munit_assert_not_null(close_branch);
    close_branch = cep_cell_resolve(close_branch);
    munit_assert_not_null(close_branch);
    munit_assert_null(cep_cell_find_by_name(close_branch, CEP_DTAW("CEP", "meta")));

    cepCell* history = cep_cell_find_by_name(op, CEP_DTAW("CEP", "history"));
    munit_assert_not_null(history);
    history = cep_cell_resolve(history);
    munit_assert_not_null(history);
    munit_assert_not_null(history->store);

    cepID previous = 0u;
    size_t entries = 0u;

    for (cepCell* node = cep_cell_first_all(history); node; node = cep_cell_next_all(history, node)) {
        cepCell* entry = cep_cell_resolve(node);
        munit_assert_not_null(entry);
        const cepDT* name = cep_cell_get_name(entry);
        munit_assert_not_null(name);
        munit_assert_true(cep_id_is_numeric(name->tag));
        cepID numeric = cep_id(name->tag);
        munit_assert_uint64(numeric, >, previous);
        previous = numeric;
        entries += 1u;
    }

    munit_assert_size(entries, >=, 2u);
    munit_assert_uint64(history->store->autoid, >, previous);
}

MunitResult test_prr_history_autoid_monotonic(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;
    if (!prr_rollbacks_enabled()) {
        return MUNIT_SKIP;
    }

    test_boot_cycle_prepare(params);

    test_runtime_shutdown();
    PrrRuntimeScope scope = prr_runtime_start();

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepDT dict_name = *CEP_DTAW("CEP", "prr_autoid");
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* dict = cep_cell_add_dictionary(data_root, &dict_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(dict);
    prr_step(2u);

    cepDT value_name = *CEP_DTAW("CEP", "target");
    cepDT value_type = *CEP_DTAW("CEP", "value");
    uint32_t value = 0x1234u;
    munit_assert_true(cep_dt_is_valid(&value_type));
    cepCell* value_cell = cep_cell_add_value(dict, &value_name, 0, &value_type, &value, sizeof value, sizeof value);
    munit_assert_not_null(value_cell);
    prr_step(2u);
    cepBeatNumber creation_beat = cep_heartbeat_current();

    cep_cell_remove_hard(value_cell, NULL);
    prr_step(2u);

    munit_assert_true(cep_runtime_pause());
    prr_step(3u);
    munit_assert_true(cep_runtime_is_paused());
    munit_assert_true(cep_runtime_rollback(creation_beat));
    prr_step(6u);
    munit_assert_true(cep_runtime_resume());
    prr_step(6u);

    cepCell* resume_op = prr_find_latest_op("op/resume");
    munit_assert_not_null(resume_op);
    prr_assert_history_autoid_monotonic(resume_op);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_prr_minimal_rollback(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;
    if (!prr_rollbacks_enabled()) {
        return MUNIT_SKIP;
    }

    test_boot_cycle_prepare(params);

    test_runtime_shutdown();
    PrrRuntimeScope scope = prr_runtime_start();

    prr_step(2u);
    munit_assert_true(cep_runtime_pause());
    prr_step(3u);
    munit_assert_true(cep_runtime_is_paused());

    cepBeatNumber target = cep_heartbeat_current();
    munit_assert_uint64(target, !=, CEP_BEAT_INVALID);

    munit_assert_true(cep_runtime_rollback(target));
    prr_step(6u);
    munit_assert_true(cep_runtime_resume());
    prr_step(4u);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_prr_control_failure_cei(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;
    test_runtime_shutdown();
    test_boot_cycle_prepare(params);
    PrrRuntimeScope scope = prr_runtime_start();

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    munit_assert_true(cep_cell_has_data(data_root));

    cepLockToken store_token = {0};
    cepLockToken data_token = {0};
    munit_assert_true(cep_store_lock(data_root, &store_token));
    munit_assert_true(cep_data_lock(data_root, &data_token));

    size_t before = prr_diag_message_count();
    (void)cep_runtime_pause();
    for (unsigned i = 0; i < 4u; ++i) {
        if (!cep_heartbeat_step()) {
            break;
        }
    }

    cep_data_unlock(data_root, &data_token);
    cep_store_unlock(data_root, &store_token);

    size_t after = prr_diag_message_count();
    munit_assert_size(after, ==, before + 1u);
    const char* note = prr_last_diag_note();
    munit_assert_not_null(note);
    munit_assert_ptr_not_equal(strstr(note, "pause failure"), NULL);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}

MunitResult test_prr_watcher_timeout_cei(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;
    test_runtime_shutdown();
    test_boot_cycle_prepare(params);
    PrrRuntimeScope scope = prr_runtime_start();

    cepDT verb = cep_ops_make_dt("op/prr_test");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, "/prr/test", mode, NULL, 0u, 0u);
    munit_assert_true(cep_oid_is_valid(oid));

    cepDT want = cep_ops_make_dt("ist:paused");
    cepDT cont = cep_ops_make_dt("op/cont");
    munit_assert_true(cep_op_await(oid, want, 1u, cont, NULL, 0u));

    size_t before = prr_diag_message_count();
    prr_step(4u);
    size_t after = prr_diag_message_count();
    munit_assert_size(after, ==, before + 1u);
    const char* note = prr_last_diag_note();
    munit_assert_not_null(note);
    munit_assert_ptr_not_equal(strstr(note, "watcher timeout"), NULL);

    prr_runtime_cleanup(&scope);
    return MUNIT_OK;
}
