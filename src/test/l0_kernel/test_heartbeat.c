/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Ensures heartbeat sequencing, agenda resolve and commit staging. */

#include "test.h"
#include "cep_heartbeat.h"
#include "cep_enzyme.h"
#include "cep_ops.h"
#include "cep_l0.h"
#include "stream/cep_stream_internal.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OVH_WATCHDOG_DEFAULT_SECONDS 240u

/* OVH suites arm a watchdog so hang regressions end quickly; this setup resolves
   the requested timeout (allowing per-test overrides) and returns the armed fixture. */
void* test_ovh_watchdog_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    unsigned seconds = test_watchdog_resolve_timeout(params, OVH_WATCHDOG_DEFAULT_SECONDS);
    const char* raw = getenv("TEST_WATCHDOG_TRACE");
    printf("[debug] trace flag=%d raw_env=%s\n",
           test_ovh_trace_enabled()? 1:0,
           raw ? raw : "(null)");
    fflush(stdout);
    if (test_ovh_trace_enabled()) {
        test_ovh_tracef("watchdog setup seconds=%u", seconds);
    }
    return test_watchdog_create(seconds);
}

/* OVH watchdog tear-down stops the background watchdog thread to avoid leaking
   workers between suites once the test has either completed or timed out. */
void test_ovh_watchdog_tear_down(void* fixture) {
    if (test_ovh_trace_enabled()) {
        test_ovh_tracef("watchdog teardown");
    }
    test_watchdog_destroy((TestWatchdog*)fixture);
}

typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     segments[4];
} CepHeartbeatPathBuf;


static const cepPath* make_path(CepHeartbeatPathBuf* buf, const cepDT* segments, unsigned count) {
    munit_assert_uint(count, <=, cep_lengthof(buf->segments));
    buf->length = count;
    buf->capacity = cep_lengthof(buf->segments);
    for (unsigned i = 0; i < count; ++i) {
        buf->segments[i].dt = segments[i];
        buf->segments[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}

static cepCell* heartbeat_ops_root(void) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops_root = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops_root);
    return ops_root;
}

static cepDT heartbeat_read_dt_field(cepCell* parent, const char* field_name);

static cepCell* heartbeat_find_op_cell(cepOID oid) {
    cepCell* ops_root = heartbeat_ops_root();
    munit_assert_not_null(ops_root);

    cepDT lookup = {
        .domain = oid.domain,
        .tag = oid.tag,
        .glob = 0u,
    };

    cepCell* op = cep_cell_find_by_name(ops_root, &lookup);
    munit_assert_not_null(op);
    return op;
}

static uint64_t heartbeat_read_u64_field(cepCell* parent, const char* field_name) {
    cepDT lookup = cep_ops_make_dt(field_name);
    lookup.glob = 0u;
    cepCell* node = cep_cell_find_by_name(parent, &lookup);
    munit_assert_not_null(node);
    munit_assert_true(cep_cell_has_data(node));
    const uint64_t* value = (const uint64_t*)cep_cell_data(node);
    munit_assert_not_null(value);
    return *value;
}

static size_t heartbeat_watchers_count(cepCell* op) {
    cepCell* watchers = cep_cell_find_by_name(op, CEP_DTAW("CEP", "watchers"));
    if (!watchers || !watchers->store) {
        return 0u;
    }
    return watchers->store->chdCount;
}

static void heartbeat_trace_op_state(const char* label, cepCell* op) {
    if (!test_ovh_trace_enabled() || !op)
        return;
    cepDT state = heartbeat_read_dt_field(op, "state");
    size_t watchers = heartbeat_watchers_count(op);
    test_ovh_tracef("%s state=0x%llx:0x%llx watchers=%zu",
                       label,
                       (unsigned long long)state.domain,
                       (unsigned long long)state.tag,
                       watchers);
}

static cepDT heartbeat_expected_dt(const char* tag) {
    if (strcmp(tag, "ist:kernel") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:kernel"));
    }
    if (strcmp(tag, "ist:run") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:run"));
    }
    if (strcmp(tag, "ist:store") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:store"));
    }
    if (strcmp(tag, "ist:packs") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:packs"));
    }
    if (strcmp(tag, "ist:ok") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:ok"));
    }
    if (strcmp(tag, "ist:stop") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:stop"));
    }
    if (strcmp(tag, "ist:flush") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:flush"));
    }
    if (strcmp(tag, "ist:halt") == 0) {
        return cep_dt_clean(CEP_DTAW("CEP", "ist:halt"));
    }
    munit_error("unexpected state tag");
    return (cepDT){0};
}

static void heartbeat_assert_history_timeline(cepOID oid,
                                              const char* const* expected_states,
                                              size_t count) {
    cepCell* op = heartbeat_find_op_cell(oid);
    cepCell* history = cep_cell_find_by_name(op, CEP_DTAW("CEP", "history"));
    munit_assert_not_null(history);

    size_t index = 0u;
    uint64_t previous_beat = 0;
    bool have_previous = false;

    for (cepCell* entry = cep_cell_first_all(history);
         entry && index < count;
         entry = cep_cell_next_all(history, entry)) {
        cepDT state = heartbeat_read_dt_field(entry, "state");
        cepDT expected = heartbeat_expected_dt(expected_states[index]);
        if (cep_dt_compare(&state, &expected) != 0) {
            continue;
        }

        uint64_t beat = heartbeat_read_u64_field(entry, "beat");
        if (have_previous) {
            munit_assert_uint64(beat, >=, previous_beat);
        }
        previous_beat = beat;
        have_previous = true;
        index += 1u;
    }

    munit_assert_size(index, ==, count);
}

static void heartbeat_assert_state(cepOID oid, const char* expected_tag) {
    cepDT expected = heartbeat_expected_dt(expected_tag);
    cepCell* op = heartbeat_find_op_cell(oid);
    cepDT state = heartbeat_read_dt_field(op, "state");
    int cmp = cep_dt_compare(&state, &expected);
    if (cmp != 0) {
        const char* actual = "?";
        if (cep_dt_compare(&state, CEP_DTAW("CEP", "ist:kernel")) == 0) {
            actual = "ist:kernel";
        } else if (cep_dt_compare(&state, CEP_DTAW("CEP", "ist:store")) == 0) {
            actual = "ist:store";
        } else if (cep_dt_compare(&state, CEP_DTAW("CEP", "ist:packs")) == 0) {
            actual = "ist:packs";
        } else if (cep_dt_compare(&state, CEP_DTAW("CEP", "ist:ok")) == 0) {
            actual = "ist:ok";
        } else if (cep_dt_compare(&state, CEP_DTAW("CEP", "ist:stop")) == 0) {
            actual = "ist:stop";
        } else if (cep_dt_compare(&state, CEP_DTAW("CEP", "ist:flush")) == 0) {
            actual = "ist:flush";
        } else if (cep_dt_compare(&state, CEP_DTAW("CEP", "ist:halt")) == 0) {
            actual = "ist:halt";
        }
        munit_logf(MUNIT_LOG_ERROR,
                   "state mismatch actual=%s expected=%s (domain=0x%llx tag=0x%llx) expected_domain=0x%llx expected_tag=0x%llx",
                   actual,
                   expected_tag,
                   (unsigned long long)state.domain,
                   (unsigned long long)state.tag,
                   (unsigned long long)expected.domain,
                   (unsigned long long)expected.tag);
    }
    munit_assert_int(cmp, ==, 0);
}


static cepOID heartbeat_read_oid(const char* field_name) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    munit_assert_not_null(sys_root);

    cepCell* state_root = cep_cell_find_by_name(sys_root, CEP_DTAW("CEP", "state"));
    if (!state_root) {
        state_root = cep_cell_ensure_dictionary_child(sys_root, CEP_DTAW("CEP", "state"), CEP_STORAGE_RED_BLACK_T);
    }
    munit_assert_not_null(state_root);
    munit_assert_true(cep_cell_has_store(state_root));

    cepDT lookup = cep_ops_make_dt(field_name);
    lookup.glob = 0u;
    cepCell* entry = cep_cell_find_by_name(state_root, &lookup);
    if (entry && cep_cell_has_data(entry)) {
        const cepOID* stored = (const cepOID*)cep_cell_data(entry);
        if (stored && cep_oid_is_valid(*stored)) {
            return *stored;
        }
    }

    const cepDT* expected_verb = NULL;
    if (strcmp(field_name, "boot_oid") == 0) {
        expected_verb = CEP_DTAW("CEP", "op/boot");
    } else if (strcmp(field_name, "shdn_oid") == 0) {
        expected_verb = CEP_DTAW("CEP", "op/shdn");
    }
    if (!expected_verb) {
        return cep_oid_invalid();
    }

    cepCell* ops_root = heartbeat_ops_root();
    for (cepCell* op = cep_cell_first_all(ops_root); op; op = cep_cell_next_all(ops_root, op)) {
        cepCell* envelope = cep_cell_find_by_name(op, CEP_DTAW("CEP", "envelope"));
        if (!envelope) {
            continue;
        }
        cepDT verb = heartbeat_read_dt_field(envelope, "verb");
        if (cep_dt_compare(&verb, expected_verb) != 0) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(op);
        munit_assert_not_null(name);
        cepDT cleaned = cep_dt_clean(name);
        cepOID oid = {
            .domain = cleaned.domain,
            .tag = cleaned.tag,
        };
        if (cep_oid_is_valid(oid)) {
            return oid;
        }
    }

    return cep_oid_invalid();
}


static cepDT heartbeat_read_dt_field(cepCell* parent, const char* field_name) {
    cepDT lookup = cep_ops_make_dt(field_name);
    lookup.glob = 0u;
    cepCell* node = cep_cell_find_by_name(parent, &lookup);
    munit_assert_not_null(node);
    munit_assert_true(cep_cell_has_data(node));
    const cepDT* payload = (const cepDT*)cep_cell_data(node);
    munit_assert_not_null(payload);
    return cep_dt_clean(payload);
}

static void heartbeat_runtime_start(void) {
    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
        .boot_ops = true,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
}


static int heartbeat_success_calls;
static int heartbeat_retry_calls;
static int heartbeat_binding_calls;
static int heartbeat_secondary_calls;
static int heartbeat_cont_calls;


static int heartbeat_success_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    heartbeat_success_calls += 1;
    return CEP_ENZYME_SUCCESS;
}


static int heartbeat_retry_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    heartbeat_retry_calls += 1;
    if (heartbeat_retry_calls == 1) {
        return CEP_ENZYME_RETRY;
    }
    return CEP_ENZYME_SUCCESS;
}

static int heartbeat_binding_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    heartbeat_binding_calls += 1;
    return CEP_ENZYME_SUCCESS;
}


static int heartbeat_secondary_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    heartbeat_secondary_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int heartbeat_cont_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    heartbeat_cont_calls += 1;
    return CEP_ENZYME_SUCCESS;
}


static MunitResult test_heartbeat_duplicate_impulses(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT seg_signal = *CEP_DTAW("CEP", "sig_dup");
    CepHeartbeatPathBuf path_buf = {0};
    const cepPath* path = make_path(&path_buf, &seg_signal, 1u);

    cepEnzymeDescriptor descriptor = {
        .name   = *CEP_DTAW("CEP", "test_hb_cn"),
        .label  = "heartbeat-count",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_success_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    heartbeat_success_calls = 0;
    munit_assert_int(cep_enzyme_register(registry, path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    for (unsigned i = 0; i < 3; ++i) {
        munit_assert_int(cep_heartbeat_enqueue_signal(0u, path, NULL), ==, CEP_ENZYME_SUCCESS);
    }

    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_success_calls, ==, 3);

    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_success_calls, ==, 3);

    test_runtime_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_retry_requeues(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT seg_signal = *CEP_DTAW("CEP", "sig_rty");
    CepHeartbeatPathBuf path_buf = {0};
    const cepPath* path = make_path(&path_buf, &seg_signal, 1u);

    cepEnzymeDescriptor descriptor = {
        .name   = *CEP_DTAW("CEP", "test_hb_rt"),
        .label  = "heartbeat-retry",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_retry_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    heartbeat_retry_calls = 0;
    munit_assert_int(cep_enzyme_register(registry, path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    munit_assert_int(cep_heartbeat_enqueue_signal(0u, path, NULL), ==, CEP_ENZYME_SUCCESS);

    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_retry_calls, ==, 1);

    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_retry_calls, ==, 2);

    test_runtime_shutdown();
    return MUNIT_OK;
}


/* Binding propagation coverage verifies that single-trigger enzymes still
   reach bound targets after the OPS/STATES migration tightened watcher flows. */
static const cepPath* create_binding_path(const cepDT* segments, size_t count, CepHeartbeatPathBuf* buf, const cepDT* type_dt, cepCell** out_cell) {
    cepCell* parent = cep_root();
    for (size_t i = 0; i < count; ++i) {
        cepDT name = segments[i];
        cepCell* child = cep_cell_find_by_name(parent, &name);
        if (!child) {
            child = cep_cell_add_dictionary(parent, &name, 0, (cepDT*)type_dt, CEP_STORAGE_RED_BLACK_T);
        }
        parent = child;
    }
    if (out_cell) {
        *out_cell = parent;
    }
    return make_path(buf, segments, count);
}


static MunitResult test_heartbeat_binding_propagation(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_root");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);
    munit_assert_true(cep_cell_has_store(leaf_cell));

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_bd");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-propagation",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_img");
    const cepDT seg_sig_leaf = *CEP_DTAW("CEP", "sig_thumb");
    const cepDT signal_segments[] = { seg_sig_root, seg_sig_leaf };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    heartbeat_binding_calls = 0;

    cepCell* root_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(root_cell);

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    munit_assert_int(cep_cell_bind_enzyme(root_cell, &enzyme_name, true), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 1);

    test_runtime_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_binding_tombstone(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_mask");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);
    munit_assert_true(cep_cell_has_store(leaf_cell));

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_ma");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-mask",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_mask");
    const cepDT seg_sig_leaf = *CEP_DTAW("CEP", "sig_apply");
    const cepDT signal_segments[] = { seg_sig_root, seg_sig_leaf };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    heartbeat_binding_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepCell* root_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(root_cell);
    munit_assert_int(cep_cell_bind_enzyme(leaf_cell, &enzyme_name, false), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 1);

    heartbeat_binding_calls = 0;
    munit_assert_int(cep_cell_unbind_enzyme(leaf_cell, &enzyme_name), ==, CEP_ENZYME_SUCCESS);

    const cepEnzymeBinding* cursor = cep_cell_enzyme_bindings(leaf_cell);
    bool found_tombstone = false;
    for ( ; cursor; cursor = cursor->next) {
        if (cep_dt_compare(&cursor->name, &enzyme_name) == 0 &&
            (cursor->flags & CEP_ENZYME_BIND_TOMBSTONE)) {
            found_tombstone = true;
            break;
        }
    }
    munit_assert_true(found_tombstone);

    test_runtime_shutdown();
    return MUNIT_OK;
}


#if 0  /* TODO: Re-calibrate binding filtering tests for the post-OPS watcher pipeline. */
static MunitResult test_heartbeat_binding_no_propagation(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_nop");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_no");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-no-propagate",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_nop");
    const cepDT signal_segments[] = { seg_sig_root };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    heartbeat_binding_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepCell* root_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(root_cell);
    munit_assert_int(cep_cell_bind_enzyme(root_cell, &enzyme_name, false), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 1);

    test_runtime_shutdown();
    return MUNIT_OK;
}

#endif /* TODO: Re-calibrate binding filtering tests for the post-OPS watcher pipeline. */

static MunitResult test_heartbeat_binding_union_chain(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_tree");
    const cepDT seg_mid  = *CEP_DTAW("CEP", "tst_branch");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_mid, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    cepCell* mid_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(mid_cell);
    cepCell* root_cell = cep_cell_parent(mid_cell);
    munit_assert_not_null(root_cell);

    const cepDT enzyme_root = *CEP_DTAW("CEP", "test_ez_ro");
    const cepDT enzyme_mid  = *CEP_DTAW("CEP", "test_ez_mi");
    const cepDT enzyme_leaf = *CEP_DTAW("CEP", "test_ez_le");

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_tree");
    const cepDT signal_segments[] = { seg_sig_root };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    heartbeat_binding_calls = 0;

    cepEnzymeDescriptor desc_root = {
        .name   = enzyme_root,
        .label  = "binding-union-root",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };
    cepEnzymeDescriptor desc_mid = desc_root;
    desc_mid.name = enzyme_mid;
    desc_mid.label = "binding-union-mid";
    cepEnzymeDescriptor desc_leaf = desc_root;
    desc_leaf.name = enzyme_leaf;
    desc_leaf.label = "binding-union-leaf";

    munit_assert_int(cep_enzyme_register(registry, signal_path, &desc_root), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, signal_path, &desc_mid), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, signal_path, &desc_leaf), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    munit_assert_int(cep_cell_bind_enzyme(root_cell, &enzyme_root, true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(mid_cell,  &enzyme_mid,  true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(leaf_cell, &enzyme_leaf, false), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 3);

    test_runtime_shutdown();
    return MUNIT_OK;
}
static void heartbeat_drive_boot_completion(cepOID boot_oid) {
    (void)boot_oid;
    for (int i = 0; i < 6; ++i) {
        test_ovh_tracef("boot_completion iteration=%d", i);
        munit_assert_true(test_ovh_heartbeat_step("boot_completion"));
    }
}

static MunitResult test_heartbeat_boot_timeline(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    test_runtime_shutdown();
    test_ovh_tracef("boot_timeline: after runtime shutdown");

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    test_ovh_tracef("boot_timeline: configuring heartbeat");
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    test_ovh_tracef("boot_timeline: bootstrap");
    munit_assert_true(cep_l0_bootstrap());
    test_ovh_tracef("boot_timeline: startup");
    munit_assert_true(cep_heartbeat_startup());

    cepOID boot_oid = heartbeat_read_oid("boot_oid");
    munit_assert_true(cep_oid_is_valid(boot_oid));
    heartbeat_drive_boot_completion(boot_oid);
    test_ovh_tracef("boot_timeline completed boot sequence beat=%" PRIu64, (uint64_t)cep_heartbeat_current());

    const char* expected_states[] = {
        "ist:run",
        "ist:kernel",
        "ist:store",
        "ist:packs",
        "ist:ok",
    };
    heartbeat_assert_history_timeline(boot_oid,
                                      expected_states,
                                      sizeof(expected_states) / sizeof(expected_states[0]));

    cepCell* boot_op = heartbeat_find_op_cell(boot_oid);
    cepCell* close_branch = cep_cell_find_by_name(boot_op, CEP_DTAW("CEP", "close"));
    munit_assert_not_null(close_branch);
    cepDT status = heartbeat_read_dt_field(close_branch, "status");
    munit_assert_int(cep_dt_compare(&status, CEP_DTAW("CEP", "sts:ok")), ==, 0);

    test_runtime_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_shutdown_timeline(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    test_runtime_shutdown();
    test_ovh_tracef("shutdown_timeline: after runtime shutdown");

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    test_ovh_tracef("shutdown_timeline: configuring heartbeat");
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    test_ovh_tracef("shutdown_timeline: bootstrap");
    munit_assert_true(cep_l0_bootstrap());
    test_ovh_tracef("shutdown_timeline: startup");
    munit_assert_true(cep_heartbeat_startup());

    cepOID boot_oid = heartbeat_read_oid("boot_oid");
    munit_assert_true(cep_oid_is_valid(boot_oid));
    heartbeat_drive_boot_completion(boot_oid);
    test_ovh_tracef("shutdown_timeline boot ready beat=%" PRIu64, (uint64_t)cep_heartbeat_current());

    munit_assert_true(cep_heartbeat_emit_shutdown());

    cepOID shdn_oid = heartbeat_read_oid("shdn_oid");
    munit_assert_true(cep_oid_is_valid(shdn_oid));

    for (int i = 0; i < 6; ++i) {
        test_ovh_tracef("shutdown_timeline iteration=%d", i);
        munit_assert_true(test_ovh_heartbeat_step("shutdown_timeline"));
    }

    const char* expected_states[] = {
        "ist:run",
        "ist:stop",
        "ist:flush",
        "ist:halt",
        "ist:ok",
    };
    heartbeat_assert_history_timeline(shdn_oid,
                                      expected_states,
                                      sizeof(expected_states) / sizeof(expected_states[0]));

    cepCell* shdn_op = heartbeat_find_op_cell(shdn_oid);
    cepCell* close_branch = cep_cell_find_by_name(shdn_op, CEP_DTAW("CEP", "close"));
    munit_assert_not_null(close_branch);
    cepDT status = heartbeat_read_dt_field(close_branch, "status");
    munit_assert_int(cep_dt_compare(&status, CEP_DTAW("CEP", "sts:ok")), ==, 0);

    test_runtime_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_boot_awaiters(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    test_runtime_shutdown();
    test_ovh_tracef("boot_awaiters: after runtime shutdown");

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    test_ovh_tracef("boot_awaiters: configuring heartbeat");
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    test_ovh_tracef("boot_awaiters: bootstrap");
    munit_assert_true(cep_l0_bootstrap());
    test_ovh_tracef("boot_awaiters: startup");
    munit_assert_true(cep_heartbeat_startup());

    cepOID boot_oid = heartbeat_read_oid("boot_oid");
    munit_assert_true(cep_oid_is_valid(boot_oid));
    cepCell* boot_op = heartbeat_find_op_cell(boot_oid);

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    heartbeat_cont_calls = 0;
    const cepDT seg_cont = cep_ops_make_dt("op/cont");
    CepHeartbeatPathBuf cont_path_buf = {0};
    const cepPath* cont_path = make_path(&cont_path_buf, &seg_cont, 1u);
    cepEnzymeDescriptor cont_desc = {
        .name   = *CEP_DTAW("CEP", "boot_cont"),
        .label  = "boot-await-cont",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_cont_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    munit_assert_int(cep_enzyme_register(registry, cont_path, &cont_desc), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    munit_assert_int(cep_cell_bind_enzyme(boot_op, &cont_desc.name, false), ==, CEP_ENZYME_SUCCESS);

    cepDT want_dt = cep_ops_make_dt("ist:packs");

    cepDT cont_dt = cep_ops_make_dt("op/cont");

    bool await_ok = cep_op_await(boot_oid,
                                 want_dt,
                                 10u,
                                 cont_dt,
                                 NULL,
                                  0);
    munit_assert_true(await_ok);
    munit_assert_size(heartbeat_watchers_count(boot_op), ==, 1u);

    munit_assert_true(test_ovh_heartbeat_step("boot_awaiters step1"));
    boot_op = heartbeat_find_op_cell(boot_oid);
    heartbeat_trace_op_state("boot_awaiters step1", boot_op);
    munit_assert_true(test_ovh_heartbeat_step("boot_awaiters step2"));
    boot_op = heartbeat_find_op_cell(boot_oid);
    heartbeat_trace_op_state("boot_awaiters step2", boot_op);

    munit_assert_true(test_ovh_heartbeat_step("boot_awaiters step3"));
    boot_op = heartbeat_find_op_cell(boot_oid);
    heartbeat_trace_op_state("boot_awaiters step3", boot_op);
    munit_assert_size(heartbeat_watchers_count(boot_op), ==, 0u);

    munit_assert_true(test_ovh_heartbeat_step("boot_awaiters step4"));
    boot_op = heartbeat_find_op_cell(boot_oid);
    heartbeat_trace_op_state("boot_awaiters step4", boot_op);
    munit_assert_int(heartbeat_cont_calls, ==, 1);
    heartbeat_assert_state(boot_oid, "ist:ok");

    test_runtime_shutdown();
    return MUNIT_OK;
}

#if 0  /* TODO: Revisit advanced binding propagation semantics under OPS/STATES. */
static MunitResult test_heartbeat_binding_duplicate_mask(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_dedup");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_du");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-duplicate",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_dedup");
    const cepDT signal_segments[] = { seg_sig_root };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    heartbeat_binding_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepCell* root_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(root_cell);
    munit_assert_int(cep_cell_bind_enzyme(root_cell, &enzyme_name, true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(leaf_cell, &enzyme_name, false), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 1);

    test_runtime_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_target_requires_binding(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_empty");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_si");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-silent",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_empty");
    const cepDT signal_segments[] = { seg_sig_root };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    heartbeat_binding_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 0);

    test_runtime_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_binding_signal_filter(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_sig");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);
    munit_assert_true(cep_cell_has_store(leaf_cell));

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_sig");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-signal",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_expect");
    const cepDT seg_sig_leaf = *CEP_DTAW("CEP", "sig_match");
    const cepDT signal_segments[] = { seg_sig_root, seg_sig_leaf };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    const cepDT seg_wrong = *CEP_DTAW("CEP", "sig_skip");
    const cepDT wrong_segments[] = { seg_wrong };
    CepHeartbeatPathBuf wrong_buf = {0};
    const cepPath* wrong_signal = make_path(&wrong_buf, wrong_segments, cep_lengthof(wrong_segments));

    heartbeat_binding_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepCell* root_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(root_cell);
    munit_assert_int(cep_cell_bind_enzyme(root_cell, &enzyme_name, true), ==, CEP_ENZYME_SUCCESS);

    cepImpulse impulse = {
        .signal_path = wrong_signal,
        .target_path = target_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 0);

    test_runtime_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_binding_matches_data_suffix(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_data");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    (void)create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    uint8_t payload[] = { 0xCA, 0xFE };
    cepData* data = cep_data_new_value(CEP_DTAW("CEP", "test_ez_pl"), payload, sizeof payload);
    munit_assert_not_null(data);
    cep_cell_set_data(leaf_cell, data);

    cepPath* dynamic_path = NULL;
    munit_assert_true(cep_cell_path(leaf_cell, &dynamic_path));
    munit_assert_not_null(dynamic_path);

    size_t path_len = dynamic_path->length;
    munit_assert_size(path_len, >, 1u);

    cepDT wildcard = {0};
    wildcard.domain = CEP_ID_GLOB_MULTI;
    wildcard.tag = CEP_ID_GLOB_MULTI;

    size_t data_index = SIZE_MAX;
    for (size_t i = 0; i < path_len; ++i) {
        const cepDT* segment = &dynamic_path->past[i].dt;
        if (segment->domain == leaf_cell->data->dt.domain &&
            segment->tag == leaf_cell->data->dt.tag) {
            data_index = i;
            break;
        }
    }
    munit_assert_size(data_index, !=, SIZE_MAX);

    size_t trim_len = path_len - 1u;
    size_t data_index_trim = data_index - 1u;
    munit_assert_size(data_index_trim, <, trim_len);

    CepHeartbeatPathBuf target_runtime = {0};
    munit_assert_size(trim_len, <=, cep_lengthof(target_runtime.segments));
    target_runtime.length = (unsigned)trim_len;
    target_runtime.capacity = cep_lengthof(target_runtime.segments);
    for (size_t i = 0; i < trim_len; ++i) {
        target_runtime.segments[i].dt = dynamic_path->past[i + 1u].dt;
        target_runtime.segments[i].timestamp = 0u;
    }
    const cepPath* trimmed_path = (const cepPath*)&target_runtime;

    CepHeartbeatPathBuf query_buf = {0};
    query_buf.length = (unsigned)trim_len;
    query_buf.capacity = cep_lengthof(query_buf.segments);
    for (size_t i = 0; i < trim_len; ++i) {
        cepDT dt = wildcard;
        if (i == data_index_trim) {
            dt = target_runtime.segments[i].dt;
        }
        query_buf.segments[i].dt = dt;
        query_buf.segments[i].timestamp = 0u;
    }
    const cepPath* query_path = (const cepPath*)&query_buf;

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_da");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-data-suffix",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    heartbeat_binding_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, query_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    munit_assert_int(cep_cell_bind_enzyme(leaf_cell, &enzyme_name, false), ==, CEP_ENZYME_SUCCESS);

    const cepEnzymeBinding* leaf_bindings = cep_cell_enzyme_bindings(leaf_cell);
    munit_assert_not_null(leaf_bindings);
    munit_assert_int(cep_dt_compare(&leaf_bindings->name, &enzyme_name), ==, 0);

    cepCell* resolved = cep_cell_find_by_path(cep_root(), trimmed_path);
    munit_assert_ptr_equal(resolved, leaf_cell);

    cepImpulse impulse = {
        .signal_path = NULL,
        .target_path = trimmed_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 1);

    cep_free(dynamic_path);
    test_runtime_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_binding_matches_store_suffix(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAW("CEP", "tst_stor");
    const cepDT seg_leaf = *CEP_DTAW("CEP", "tst_leaf");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    (void)create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);
    munit_assert_true(cep_cell_has_store(leaf_cell));

    cepDT child_name = *CEP_DTAW("CEP", "tst_chld");
    cepCell* child = cep_cell_add_dictionary(leaf_cell, &child_name, 0, &type_dictionary, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(child);

    cepPath* dynamic_path = NULL;
    munit_assert_true(cep_cell_path(leaf_cell, &dynamic_path));
    munit_assert_not_null(dynamic_path);

    size_t path_len = dynamic_path->length;
    munit_assert_size(path_len, >, 1u);

    cepDT wildcard = {0};
    wildcard.domain = CEP_ID_GLOB_MULTI;
    wildcard.tag = CEP_ID_GLOB_MULTI;

    size_t store_index = path_len - 1u;
    const cepDT store_dt = dynamic_path->past[store_index].dt;

    size_t trim_len = path_len - 1u;
    size_t store_index_trim = store_index - 1u;

    CepHeartbeatPathBuf target_runtime = {0};
    munit_assert_size(trim_len, <=, cep_lengthof(target_runtime.segments));
    target_runtime.length = (unsigned)trim_len;
    target_runtime.capacity = cep_lengthof(target_runtime.segments);
    for (size_t i = 0; i < trim_len; ++i) {
        target_runtime.segments[i].dt = dynamic_path->past[i + 1u].dt;
        target_runtime.segments[i].timestamp = 0u;
    }
    const cepPath* trimmed_path = (const cepPath*)&target_runtime;

    CepHeartbeatPathBuf query_buf = {0};
    query_buf.length = (unsigned)trim_len;
    query_buf.capacity = cep_lengthof(query_buf.segments);
    for (size_t i = 0; i < trim_len; ++i) {
        cepDT dt = wildcard;
        if (i == store_index_trim) {
            dt = store_dt;
        }
        query_buf.segments[i].dt = dt;
        query_buf.segments[i].timestamp = 0u;
    }
    const cepPath* query_path = (const cepPath*)&query_buf;

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_st");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "binding-store-suffix",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_binding_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    heartbeat_binding_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, query_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    munit_assert_int(cep_cell_bind_enzyme(leaf_cell, &enzyme_name, false), ==, CEP_ENZYME_SUCCESS);

    const cepEnzymeBinding* leaf_bindings = cep_cell_enzyme_bindings(leaf_cell);
    munit_assert_not_null(leaf_bindings);
    munit_assert_int(cep_dt_compare(&leaf_bindings->name, &enzyme_name), ==, 0);

    cepCell* resolved = cep_cell_find_by_path(cep_root(), trimmed_path);
    munit_assert_ptr_equal(resolved, leaf_cell);

    cepImpulse impulse = {
        .signal_path = NULL,
        .target_path = trimmed_path,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_binding_calls, ==, 1);

    cep_free(dynamic_path);
    test_runtime_shutdown();
    return MUNIT_OK;
}


#endif /* TODO: Revisit advanced binding propagation semantics under OPS/STATES. */


static MunitResult test_heartbeat_signal_broadcast(void) {
    test_runtime_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT enzyme_name = *CEP_DTAW("CEP", "test_ez_bc");
    cepEnzymeDescriptor descriptor = {
        .name   = enzyme_name,
        .label  = "signal-broadcast",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = heartbeat_secondary_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    const cepDT seg_sig_root = *CEP_DTAW("CEP", "sig_broad");
    const cepDT signal_segments[] = { seg_sig_root };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    heartbeat_secondary_calls = 0;

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = NULL,
    };

    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_int(heartbeat_secondary_calls, ==, 1);

    test_runtime_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_wallclock_capture(void) {
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
        .spacing_window = 0u,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());

    size_t default_spacing_window = cep_heartbeat_get_spacing_window();
    munit_assert_size(default_spacing_window, >, 0u);

    const uint64_t ts_beat0 = 1000000ull;
    const uint64_t ts_beat1 = 1005000ull;

    munit_assert_true(cep_heartbeat_publish_wallclock(0u, ts_beat0));

    uint64_t retrieved = 0u;
    munit_assert_true(cep_heartbeat_beat_to_unix(0u, &retrieved));
    munit_assert_uint64(retrieved, ==, ts_beat0);

    munit_assert_true(cep_heartbeat_publish_wallclock(1u, ts_beat1));
    munit_assert_true(cep_heartbeat_beat_to_unix(1u, &retrieved));
    munit_assert_uint64(retrieved, ==, ts_beat1);

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);

    cepCell* beat_root = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "beat"));
    munit_assert_not_null(beat_root);
    beat_root = cep_cell_resolve(beat_root);
    munit_assert_not_null(beat_root);

    cepDT beat0_name = cep_dt_make(CEP_ACRO("HB"), cep_id_to_numeric((cepID)(0u + 1u)));
    beat0_name.glob = 0u;
    cepCell* beat0_cell = cep_cell_find_by_name(beat_root, &beat0_name);
    munit_assert_not_null(beat0_cell);
    beat0_cell = cep_cell_resolve(beat0_cell);
    munit_assert_not_null(beat0_cell);

    cepCell* meta0 = cep_cell_find_by_name(beat0_cell, CEP_DTAW("CEP", "meta"));
    munit_assert_not_null(meta0);
    meta0 = cep_cell_resolve(meta0);
    munit_assert_not_null(meta0);

    cepCell* ts0_node = cep_cell_find_by_name(meta0, CEP_DTAW("CEP", "unix_ts_ns"));
    munit_assert_not_null(ts0_node);
    ts0_node = cep_cell_resolve(ts0_node);
    munit_assert_not_null(ts0_node);
    munit_assert_true(cep_cell_has_data(ts0_node));
    const char* ts0_payload = (const char*)cep_cell_data(ts0_node);
    munit_assert_not_null(ts0_payload);
    char* ts0_end = NULL;
    uint64_t parsed_ts0 = strtoull(ts0_payload, &ts0_end, 10);
    munit_assert_not_null(ts0_end);
    munit_assert_char(*ts0_end, ==, '\0');
    munit_assert_uint64(parsed_ts0, ==, ts_beat0);

    cepCell* analytics_root = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "analytics"));
    munit_assert_not_null(analytics_root);
    analytics_root = cep_cell_resolve(analytics_root);
    munit_assert_not_null(analytics_root);

    cepCell* spacing = cep_cell_find_by_name(analytics_root, CEP_DTAW("CEP", "spacing"));
    munit_assert_not_null(spacing);
    spacing = cep_cell_resolve(spacing);
    munit_assert_not_null(spacing);

    cepDT beat1_name = cep_dt_make(CEP_ACRO("HB"), cep_id_to_numeric((cepID)(1u + 1u)));
    beat1_name.glob = 0u;
    cepCell* beat1_entry = cep_cell_find_by_name(spacing, &beat1_name);
    munit_assert_not_null(beat1_entry);
    beat1_entry = cep_cell_resolve(beat1_entry);
    munit_assert_not_null(beat1_entry);

    cepCell* interval_node = cep_cell_find_by_name(beat1_entry, CEP_DTAW("CEP", "interval_ns"));
    munit_assert_not_null(interval_node);
    interval_node = cep_cell_resolve(interval_node);
    munit_assert_not_null(interval_node);
    munit_assert_true(cep_cell_has_data(interval_node));
    const char* interval_text = (const char*)cep_cell_data(interval_node);
    munit_assert_not_null(interval_text);
    char* interval_end = NULL;
    uint64_t interval_value = strtoull(interval_text, &interval_end, 10);
    munit_assert_not_null(interval_end);
    munit_assert_char(*interval_end, ==, '\0');
    munit_assert_uint64(interval_value, ==, ts_beat1 - ts_beat0);

    cepBeatNumber last_spacing_beat = 1u;
    uint64_t rolling_ts = ts_beat1;
    for (cepBeatNumber beat = 2u; beat < default_spacing_window + 3u; ++beat) {
        rolling_ts += 1000ull;
        munit_assert_true(cep_heartbeat_publish_wallclock(beat, rolling_ts));
        last_spacing_beat = beat;
    }
    munit_assert_not_null(spacing->store);
    munit_assert_size(spacing->store->chdCount, <=, default_spacing_window);

    cepBeatNumber earliest_beat = CEP_BEAT_INVALID;
    cepBeatNumber max_beat = 0u;
    for (cepCell* entry = cep_cell_first_all(spacing);
         entry;
         entry = cep_cell_next_all(spacing, entry)) {
        const cepDT* name = cep_cell_get_name(entry);
        munit_assert_not_null(name);
        uint64_t numeric = cep_id(name->tag);
        munit_assert_uint64(numeric, >, 0u);
        cepBeatNumber beat = (cepBeatNumber)(numeric - 1u);
        if (earliest_beat == CEP_BEAT_INVALID || beat < earliest_beat) {
            earliest_beat = beat;
        }
        if (beat > max_beat) {
            max_beat = beat;
        }
    }

    cepBeatNumber expected_min = (last_spacing_beat > default_spacing_window)
        ? (last_spacing_beat - default_spacing_window + 1u)
        : 1u;
    munit_assert_uint64(earliest_beat, >=, expected_min);
    munit_assert_uint64(max_beat, ==, last_spacing_beat);

    size_t new_window = 32u;
    munit_assert_true(cep_heartbeat_set_spacing_window(new_window));
    munit_assert_size(cep_heartbeat_get_spacing_window(), ==, new_window);

    spacing = cep_cell_find_by_name(analytics_root, CEP_DTAW("CEP", "spacing"));
    munit_assert_not_null(spacing);
    spacing = cep_cell_resolve(spacing);
    munit_assert_not_null(spacing);

    earliest_beat = CEP_BEAT_INVALID;
    max_beat = 0u;
    size_t entry_count = 0u;
    for (cepCell* entry = cep_cell_first_all(spacing);
         entry;
         entry = cep_cell_next_all(spacing, entry)) {
        const cepDT* name = cep_cell_get_name(entry);
        munit_assert_not_null(name);
        if (!cep_id_is_numeric(name->tag)) {
            continue;
        }
        uint64_t numeric = cep_id(name->tag);
        cepBeatNumber beat = (cepBeatNumber)(numeric - 1u);
        if (earliest_beat == CEP_BEAT_INVALID || beat < earliest_beat) {
            earliest_beat = beat;
        }
        if (beat > max_beat) {
            max_beat = beat;
        }
        entry_count += 1u;
    }
    munit_assert_size(entry_count, <=, new_window);
    expected_min = (last_spacing_beat > new_window)
        ? (last_spacing_beat - new_window + 1u)
        : 1u;
    munit_assert_uint64(earliest_beat, >=, expected_min);
    munit_assert_uint64(max_beat, ==, last_spacing_beat);

    munit_assert_true(cep_heartbeat_publish_wallclock(0u, ts_beat0));
    munit_assert_true(cep_heartbeat_stage_note("txn commit: sample"));

    bool stage_note_found = false;
    for (cepCell* beat_entry = cep_cell_first_all(beat_root);
         beat_entry && !stage_note_found;
         beat_entry = cep_cell_next_all(beat_root, beat_entry)) {
        if (!beat_entry) {
            continue;
        }
        cepCell* resolved_entry = cep_cell_resolve(beat_entry);
        if (!resolved_entry) {
            continue;
        }
        const cepDT* beat_name = cep_cell_get_name(beat_entry);
        if (!beat_name || !cep_id_is_numeric(beat_name->tag)) {
            continue;
        }
        uint64_t numeric = cep_id(beat_name->tag);
        if (numeric == 0u) {
            continue;
        }
        cepBeatNumber beat_number = (cepBeatNumber)(numeric - 1u);
        cepCell* stage = cep_cell_find_by_name(resolved_entry, CEP_DTAW("CEP", "stage"));
        if (!stage) {
            continue;
        }
        stage = cep_cell_resolve(stage);
        if (!stage) {
            continue;
        }

        for (cepCell* note_entry = cep_cell_first_all(stage);
             note_entry;
             note_entry = cep_cell_next_all(stage, note_entry)) {
            cepCell* resolved_note = cep_cell_resolve(note_entry);
            if (!resolved_note || !cep_cell_has_data(resolved_note)) {
                continue;
            }
            const char* message = (const char*)cep_cell_data(resolved_note);
            if (!message) {
                continue;
            }
            static const char* stage_prefix = "txn commit: samp";
            if (strncmp(message, stage_prefix, strlen(stage_prefix)) != 0) {
                continue;
            }

            uint64_t expected_note_ts = 0u;
            munit_assert_true(cep_heartbeat_beat_to_unix(beat_number, &expected_note_ts));
            stage_note_found = true;
            break;
        }
    }
    munit_assert_true(stage_note_found);

    cepDT verb = cep_ops_make_dt("op/vl");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb,
                              "/tmp/history",
                              mode,
                              NULL,
                              0u,
                              0u);
    munit_assert_true(cep_oid_is_valid(oid));
    munit_assert_true(cep_op_state_set(oid, cep_ops_make_dt("ist:skel"), 0, NULL));
    munit_assert_true(cep_op_state_set(oid, cep_ops_make_dt("ist:unveil"), 0, NULL));
    munit_assert_true(cep_op_close(oid, cep_ops_make_dt("sts:ok"), NULL, 0u));

    cepCell* op_cell = heartbeat_find_op_cell(oid);
    munit_assert_not_null(op_cell);
    cepDT history_name = cep_ops_make_dt("history");
    cepCell* history = cep_cell_find_by_name(op_cell, &history_name);
    munit_assert_not_null(history);
    cepCell* first_history = cep_cell_first(history);
    munit_assert_not_null(first_history);
    cepDT ts_field = cep_ops_make_dt("unix_ts_ns");
    cepCell* ts_cell = cep_cell_find_by_name(first_history, &ts_field);
    munit_assert_not_null(ts_cell);
    const uint64_t* recorded_ts = (const uint64_t*)cep_cell_data(ts_cell);
    munit_assert_not_null(recorded_ts);
    munit_assert_uint64(*recorded_ts, ==, ts_beat0);

    typedef struct {
        uint64_t offset;
        uint64_t requested;
        uint64_t actual;
        uint64_t hash;
        uint32_t flags;
        uint32_t reserved;
        uint64_t unix_ts_ns;
    } TestStreamJournalEntry;

    cepDT stream_name = cep_dt_make(CEP_ACRO("CEP"), cep_id_to_numeric((cepID)1234));
    stream_name.glob = 0u;
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* stream_cell = cep_cell_add_dictionary(rt_root,
                                                  &stream_name,
                                                  0,
                                                  &dict_type,
                                                  CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(stream_cell);

    cep_stream_journal(stream_cell, 0u, 0u, 0u, 0u, 0u);
    cepCell* journal = cep_cell_find_by_name(stream_cell, CEP_DTAW("CEP", "journal"));
    munit_assert_not_null(journal);
    journal = cep_cell_resolve(journal);
    munit_assert_not_null(journal);
    cepCell* journal_entry = cep_cell_last_all(journal);
    munit_assert_not_null(journal_entry);
    const TestStreamJournalEntry* journal_data = (const TestStreamJournalEntry*)cep_cell_data(journal_entry);
    munit_assert_not_null(journal_data);
    munit_assert_uint64(journal_data->unix_ts_ns, ==, ts_beat0);

    test_runtime_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_boot_ops_required(void) {
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
        .boot_ops = false,
    };

    munit_assert_false(cep_heartbeat_configure(NULL, &policy));
    return MUNIT_OK;
}


MunitResult test_heartbeat_single(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    (void)user_data_or_fixture;

    MunitResult result;

    result = test_heartbeat_duplicate_impulses();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_retry_requeues();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_propagation();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_tombstone();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_union_chain();
    if (result != MUNIT_OK) {
        return result;
    }
    result = test_heartbeat_signal_broadcast();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_wallclock_capture();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_boot_ops_required();
    if (result != MUNIT_OK) {
        return result;
    }

    return MUNIT_OK;
}

MunitResult test_heartbeat_bootstrap(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);
    test_ovh_tracef("heartbeat_bootstrap: begin boot_timeline");
    MunitResult result = test_heartbeat_boot_timeline(params, NULL);
    if (result != MUNIT_OK) {
        test_watchdog_signal(watchdog);
        return result;
    }

    test_ovh_tracef("heartbeat_bootstrap: begin shutdown_timeline");
    result = test_heartbeat_shutdown_timeline(params, NULL);
    if (result != MUNIT_OK) {
        test_watchdog_signal(watchdog);
        return result;
    }

    test_ovh_tracef("heartbeat_bootstrap: begin boot_awaiters");
    result = test_heartbeat_boot_awaiters(params, NULL);
    test_watchdog_signal(watchdog);
    return result;
}
