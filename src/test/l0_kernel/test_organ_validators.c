/* Validator adoption tests: ensure Stage E organ validators execute via
 * OPS/STATES and close dossiers cleanly for representative subsystems. The
 * checks drive a lightweight heartbeat cycle so we can observe the emitted
 * dossiers without rebuilding the entire runtime fixture. */

#include "test.h"
#include "cep_l0.h"
#include "cep_ops.h"
#include "cep_organ.h"

#include <stdio.h>
#include <string.h>

static void organ_prepare_runtime(void) {
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_heartbeat_startup());

    /* Advance a few beats so the boot dossier reaches ist:ok before we queue
     * organ validators. */
    for (int i = 0; i < 6; ++i) {
        test_stagee_tracef("organ_prepare_runtime iteration=%d", i);
        munit_assert_true(test_stagee_heartbeat_step("organ_prepare_runtime"));
    }
}

static cepCell* organ_ops_root(void) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops);
    return cep_cell_resolve(ops);
}

static cepCell* organ_find_cell(cepCell* parent, const cepDT* name) {
    cepCell* node = cep_cell_find_by_name(parent, name);
    munit_assert_not_null(node);
    node = cep_cell_resolve(node);
    munit_assert_not_null(node);
    return node;
}

static void organ_trace_ops_size(const char* label, cepCell* ops_root) {
    if (!test_stagee_trace_enabled() || !ops_root)
        return;
    test_stagee_tracef("%s ops_children=%zu", label, cep_cell_children(ops_root));
}

static bool organ_ops_has_entry(const char* target_path);

static void organ_wait_for_validator(const char* label,
                                     cepCell* ops_root,
                                     size_t before_count) {
    for (int beat = 0; beat < 32; ++beat) {
        munit_assert_true(test_stagee_heartbeat_step(label));
        organ_trace_ops_size(label, ops_root);
        if (cep_cell_children(ops_root) > before_count) {
            return;
        }
    }
    munit_error("validator did not emit dossier within heartbeat allowance");
}

static void organ_step_beats(const char* label, unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        munit_assert_true(test_stagee_heartbeat_step(label));
    }
}

static cepCell* organ_resolve_meta_node(cepCell* root) {
    cepCell* meta = cep_cell_find_by_name(root, CEP_DTAW("CEP", "meta"));
    if (!meta) {
        cepCell* resolved_root = root;
        if (!cep_cell_require_dictionary_store(&resolved_root)) {
            return NULL;
        }
        for (cepCell* child = cep_cell_first_all(resolved_root);
             child;
             child = cep_cell_next_all(resolved_root, child)) {
            const cepDT* name = cep_cell_get_name(child);
            if (name && cep_dt_compare(name, CEP_DTAW("CEP", "meta")) == 0) {
                meta = child;
                break;
            }
        }
        if (!meta) {
            return NULL;
        }
    }
    return cep_cell_resolve(meta);
}

static void organ_assert_schema_present(cepCell* root) {
    cepCell* meta = organ_resolve_meta_node(root);
    if (!meta && test_stagee_trace_enabled()) {
        cepCell* resolved_root = root;
        if (cep_cell_require_dictionary_store(&resolved_root)) {
            test_stagee_tracef("organ schema debug: immutable=%d children=%zu",
                               cep_cell_is_immutable(resolved_root) ? 1 : 0,
                               cep_cell_children(resolved_root));
            cepCell* meta_lookup = cep_cell_find_by_name(resolved_root, CEP_DTAW("CEP", "meta"));
            test_stagee_tracef("organ schema debug: meta_lookup=%p", (void*)meta_lookup);
            for (cepCell* child = cep_cell_first_all(resolved_root);
                 child;
                 child = cep_cell_next_all(resolved_root, child)) {
                const cepDT* name = cep_cell_get_name(child);
                char domain_buf[16];
                char tag_buf[32];
                const char* domain_text = "<none>";
                const char* tag_text = "<none>";
                if (name) {
                    if (cep_id_is_acronym(name->domain)) {
                        size_t len = cep_acronym_to_text(name->domain, domain_buf);
                        if (len >= sizeof domain_buf) {
                            len = sizeof domain_buf - 1u;
                        }
                        domain_buf[len] = '\0';
                        domain_text = domain_buf;
                    } else if (name->domain) {
                        snprintf(domain_buf, sizeof domain_buf, "0x%08x", (unsigned)name->domain);
                        domain_text = domain_buf;
                    }
                    if (cep_id_is_word(name->tag) || cep_id_is_reference(name->tag)) {
                        size_t len = cep_word_to_text(name->tag, tag_buf);
                        if (len >= sizeof tag_buf) {
                            len = sizeof tag_buf - 1u;
                        }
                        tag_buf[len] = '\0';
                        tag_text = tag_buf;
                    } else if (name->tag) {
                        snprintf(tag_buf, sizeof tag_buf, "0x%08x", (unsigned)name->tag);
                        tag_text = tag_buf;
                    }
                }
                test_stagee_tracef("organ schema missing meta child dom=%s tag=%s",
                                   domain_text,
                                   tag_text);
            }
        }
    }
    munit_assert_not_null(meta);

    cepCell* schema = cep_cell_find_by_name(meta, CEP_DTAW("CEP", "schema"));
    munit_assert_not_null(schema);
    schema = cep_cell_resolve(schema);
    munit_assert_not_null(schema);

    cepCell* summary = cep_cell_find_by_name(schema, CEP_DTAW("CEP", "summary"));
    munit_assert_not_null(summary);
    summary = cep_cell_resolve(summary);
    munit_assert_not_null(summary);
    munit_assert_true(cep_cell_has_data(summary));

    cepCell* layout = cep_cell_find_by_name(schema, CEP_DTAW("CEP", "layout"));
    munit_assert_not_null(layout);
    layout = cep_cell_resolve(layout);
    munit_assert_not_null(layout);
    munit_assert_true(cep_cell_has_data(layout));
}

static bool organ_ops_has_entry(const char* target_path) {
    cepCell* ops_root = organ_ops_root();
    munit_assert_not_null(ops_root);

    for (cepCell* op = cep_cell_last_all(ops_root);
         op;
         op = cep_cell_prev_all(ops_root, op)) {
        cepCell* envelope = organ_find_cell(op, CEP_DTAW("CEP", "envelope"));
        cepCell* target_node = organ_find_cell(envelope, CEP_DTAW("CEP", "target"));

        const cepData* target_data = target_node->data;
        if (!target_data || target_data->datatype != CEP_DATATYPE_VALUE || target_data->size == 0u) {
            continue;
        }
        const char* stored_target = (const char*)target_data->value;
        if (!stored_target || strcmp(stored_target, target_path) != 0) {
            continue;
        }

        cepCell* state_node = organ_find_cell(op, CEP_DTAW("CEP", "state"));
        const cepData* state_data = state_node->data;
        if (!state_data || state_data->datatype != CEP_DATATYPE_VALUE || state_data->size != sizeof(cepDT)) {
            continue;
        }
        cepDT state_dt = {0};
        memcpy(&state_dt, state_data->value, sizeof state_dt);
        if (cep_dt_compare(&state_dt, CEP_DTAW("CEP", "ist:ok")) != 0) {
            continue;
        }

        cepCell* close_branch = organ_find_cell(op, CEP_DTAW("CEP", "close"));
        cepCell* status_node = organ_find_cell(close_branch, CEP_DTAW("CEP", "status"));
        const cepData* status_data = status_node->data;
        if (!status_data || status_data->datatype != CEP_DATATYPE_VALUE || status_data->size != sizeof(cepDT)) {
            continue;
        }
        cepDT status_dt = {0};
        memcpy(&status_dt, status_data->value, sizeof status_dt);
        if (cep_dt_compare(&status_dt, CEP_DTAW("CEP", "sts:ok")) != 0) {
            continue;
        }

        return true;
    }

    return false;
}

static void organ_assert_latest_success(const char* expected_target) {
    cepCell* ops_root = organ_ops_root();
    cepCell* newest = NULL;
    for (cepCell* op = cep_cell_last_all(ops_root);
         op;
         op = cep_cell_prev_all(ops_root, op)) {
        cepCell* envelope = organ_find_cell(op, CEP_DTAW("CEP", "envelope"));
        cepCell* target_node = organ_find_cell(envelope, CEP_DTAW("CEP", "target"));
        if (!target_node || !target_node->data || target_node->data->datatype != CEP_DATATYPE_VALUE) {
            continue;
        }
        const char* target_path = (const char*)target_node->data->value;
        if (!target_path || strcmp(target_path, expected_target) != 0) {
            continue;
        }

        cepCell* verb_node = organ_find_cell(envelope, CEP_DTAW("CEP", "verb"));
        if (!verb_node || !verb_node->data || verb_node->data->datatype != CEP_DATATYPE_VALUE || verb_node->data->size != sizeof(cepDT)) {
            continue;
        }
        cepDT verb_dt = {0};
        memcpy(&verb_dt, verb_node->data->value, sizeof verb_dt);
        cepDT verb_expected = cep_ops_make_dt("op/vl");
        if (cep_dt_compare(&verb_dt, &verb_expected) != 0) {
            continue;
        }

        newest = op;
        break;
    }
    munit_assert_not_null(newest);

    cepCell* envelope = organ_find_cell(newest, CEP_DTAW("CEP", "envelope"));

    cepCell* verb_node = organ_find_cell(envelope, CEP_DTAW("CEP", "verb"));
    const cepData* verb_data = verb_node->data;
    munit_assert_not_null(verb_data);
    munit_assert_int(verb_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(verb_data->size, ==, sizeof(cepDT));
    cepDT verb_dt = {0};
    memcpy(&verb_dt, verb_data->value, sizeof verb_dt);
    cepDT verb_expected = cep_ops_make_dt("op/vl");
    munit_assert_int(cep_dt_compare(&verb_dt, &verb_expected), ==, 0);

    cepCell* target_node = organ_find_cell(envelope, CEP_DTAW("CEP", "target"));
    const cepData* target_data = target_node->data;
    munit_assert_not_null(target_data);
    munit_assert_int(target_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_true(target_data->size > 0u);
    const char* target_path = (const char*)target_data->value;
    munit_assert_not_null(target_path);
    munit_assert_string_equal(target_path, expected_target);

    cepCell* state_node = organ_find_cell(newest, CEP_DTAW("CEP", "state"));
    const cepData* state_data = state_node->data;
    munit_assert_int(state_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(state_data->size, ==, sizeof(cepDT));
    cepDT state_dt = {0};
    memcpy(&state_dt, state_data->value, sizeof state_dt);
    cepDT state_expected = cep_ops_make_dt("ist:ok");
    munit_assert_int(cep_dt_compare(&state_dt, &state_expected), ==, 0);

    cepCell* close_branch = organ_find_cell(newest, CEP_DTAW("CEP", "close"));
    munit_assert_true(cep_cell_is_immutable(close_branch));
    cepCell* status_node = organ_find_cell(close_branch, CEP_DTAW("CEP", "status"));
    const cepData* status_data = status_node->data;
    munit_assert_int(status_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(status_data->size, ==, sizeof(cepDT));
    cepDT status_dt = {0};
    memcpy(&status_dt, status_data->value, sizeof status_dt);
    cepDT status_expected = cep_ops_make_dt("sts:ok");
    munit_assert_int(cep_dt_compare(&status_dt, &status_expected), ==, 0);
}

MunitResult test_organ_sys_state_validator(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);

    organ_prepare_runtime();

    cepCell* sys_root = cep_heartbeat_sys_root();
    munit_assert_not_null(sys_root);
    cepCell* state_root = organ_find_cell(sys_root, CEP_DTAW("CEP", "state"));

    cepCell* ops_root = organ_ops_root();
    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_validation(state_root));
    organ_trace_ops_size("organ_sys_state queued", ops_root);

    organ_wait_for_validator("organ_sys_state run", ops_root, before_count);

    organ_assert_latest_success("/sys/state");
    test_watchdog_signal(watchdog);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_organ_rt_ops_validator(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);

    organ_prepare_runtime();

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "ops"));

    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_validation(ops_root));
    organ_trace_ops_size("organ_rt_ops queued", ops_root);

    organ_wait_for_validator("organ_rt_ops run", ops_root, before_count);

    organ_assert_latest_success("/rt/ops");
    test_watchdog_signal(watchdog);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_organ_constructor_bootstrap(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);

    organ_prepare_runtime();

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* beat_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "beat"));

    cepCell* journal_root = cep_heartbeat_journal_root();
    munit_assert_not_null(journal_root);

    munit_assert_true(cep_organ_request_constructor(beat_root));
    munit_assert_true(cep_organ_request_constructor(journal_root));
    organ_step_beats("organ_constructor_bootstrap:ctor_prime", 4);

    beat_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "beat"));
    journal_root = cep_heartbeat_journal_root();
    munit_assert_not_null(journal_root);

    organ_assert_schema_present(beat_root);
    organ_assert_schema_present(journal_root);

    cepCell* ops_root = organ_ops_root();
    size_t before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(beat_root));
    organ_wait_for_validator("organ_constructor_bootstrap:vl_rt_beat", ops_root, before);
    organ_assert_latest_success("/rt/beat");

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(journal_root));
    organ_wait_for_validator("organ_constructor_bootstrap:vl_journal", ops_root, before);
    organ_assert_latest_success("/journal");

    test_watchdog_signal(watchdog);
    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_organ_constructor_destructor_cycles(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);

    organ_prepare_runtime();

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* beat_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "beat"));

    cepCell* journal_root = cep_heartbeat_journal_root();
    munit_assert_not_null(journal_root);

    if (test_stagee_trace_enabled()) {
        cepDT expected_beat = cep_organ_store_dt("rt_beat");
        cepDT expected_journal = cep_organ_store_dt("journal");
        test_stagee_tracef("expected store dt: beat=%08x/%08x journal=%08x/%08x",
                           (unsigned)expected_beat.domain,
                           (unsigned)expected_beat.tag,
                           (unsigned)expected_journal.domain,
                           (unsigned)expected_journal.tag);
    }

    munit_assert_true(cep_organ_request_constructor(beat_root));
    munit_assert_true(cep_organ_request_constructor(journal_root));
    organ_step_beats("organ_destructor_cycles:ctor_prime", 4);

    beat_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "beat"));
    journal_root = cep_heartbeat_journal_root();
    munit_assert_not_null(journal_root);

    organ_assert_schema_present(beat_root);
    organ_assert_schema_present(journal_root);

    cepCell* ops_root = organ_ops_root();
    size_t before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(beat_root));
    organ_wait_for_validator("organ_destructor_cycles:vl_rt_beat_before", ops_root, before);
    organ_assert_latest_success("/rt/beat");

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(journal_root));
    organ_wait_for_validator("organ_destructor_cycles:vl_journal_before", ops_root, before);
    organ_assert_latest_success("/journal");

    if (test_stagee_trace_enabled()) {
        const cepStore* beat_store = beat_root ? beat_root->store : NULL;
        const cepStore* journal_store = journal_root ? journal_root->store : NULL;
        test_stagee_tracef("pre-dtor store dt: beat=%08x/%08x journal=%08x/%08x",
                           beat_store ? (unsigned)beat_store->dt.domain : 0u,
                           beat_store ? (unsigned)beat_store->dt.tag : 0u,
                           journal_store ? (unsigned)journal_store->dt.domain : 0u,
                           journal_store ? (unsigned)journal_store->dt.tag : 0u);
    }

    munit_assert_true(cep_organ_request_destructor(beat_root));
    munit_assert_true(cep_organ_request_destructor(journal_root));
    organ_step_beats("organ_destructor_cycles:cycle", 4);

    munit_assert_true(organ_ops_has_entry("/rt/beat"));
    munit_assert_true(organ_ops_has_entry("/journal"));

    beat_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "beat"));
    journal_root = cep_heartbeat_journal_root();
    munit_assert_not_null(journal_root);
    organ_assert_schema_present(beat_root);
    organ_assert_schema_present(journal_root);

    if (test_stagee_trace_enabled()) {
        const cepStore* beat_store = beat_root ? beat_root->store : NULL;
        const cepStore* journal_store = journal_root ? journal_root->store : NULL;
        test_stagee_tracef("post-dtor store dt: beat=%08x/%08x journal=%08x/%08x",
                           beat_store ? (unsigned)beat_store->dt.domain : 0u,
                           beat_store ? (unsigned)beat_store->dt.tag : 0u,
                           journal_store ? (unsigned)journal_store->dt.domain : 0u,
                           journal_store ? (unsigned)journal_store->dt.tag : 0u);
    }

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(beat_root));
    organ_wait_for_validator("organ_destructor_cycles:vl_rt_beat_after", ops_root, before);
    organ_assert_latest_success("/rt/beat");

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(journal_root));
    organ_wait_for_validator("organ_destructor_cycles:vl_journal_after", ops_root, before);
    organ_assert_latest_success("/journal");

    test_watchdog_signal(watchdog);
    test_runtime_shutdown();
    return MUNIT_OK;
}
