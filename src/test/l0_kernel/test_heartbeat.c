/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Ensures heartbeat sequencing, agenda resolve and commit staging. */

#include "test.h"
#include "cep_heartbeat.h"
#include "cep_enzyme.h"
#include "cep_l0.h"
#include <stddef.h>
#include <string.h>

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

static const char* lifecycle_status_for(const cepDT* scope_dt) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    if (!sys_root) {
        return NULL;
    }

    cepCell* state_root = cep_cell_find_by_name(sys_root, CEP_DTAW("CEP", "state"));
    if (!state_root) {
        return NULL;
    }
    if (!cep_cell_has_store(state_root)) {
        return NULL;
    }

    cepDT lookup = *scope_dt;
    lookup.glob = 0u;
    cepCell* bucket = cep_cell_find_by_name(state_root, &lookup);
    if (!bucket) {
        return NULL;
    }
    if (!cep_cell_has_store(bucket)) {
        return NULL;
    }

    cepCell* status = cep_cell_find_by_name(bucket, CEP_DTAW("CEP", "status"));
    if (!status || !cep_cell_has_data(status)) {
        return NULL;
    }

    return (const char*)cep_cell_data(status);
}

static void heartbeat_runtime_start(void) {
    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());
}


static int heartbeat_success_calls;
static int heartbeat_retry_calls;
static int heartbeat_binding_calls;
static int heartbeat_secondary_calls;


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

    munit_assert_int(cep_enzyme_register(registry, signal_path, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepCell* root_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(root_cell);
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
    munit_assert_int(cep_cell_bind_enzyme(root_cell, &enzyme_name, true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_unbind_enzyme(leaf_cell, &enzyme_name), ==, CEP_ENZYME_SUCCESS);

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
    munit_assert_int(heartbeat_binding_calls, ==, 0);

    test_runtime_shutdown();
    return MUNIT_OK;
}

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

static void assert_scope_ready(cepLifecycleScope scope, const cepDT* scope_dt) {
    const char* status = lifecycle_status_for(scope_dt);
    if (status) {
        munit_assert_string_equal(status, "ready");
    } else {
        (void)scope;
    }
}

static void assert_scope_teardown(cepLifecycleScope scope, const cepDT* scope_dt) {
    const char* status = lifecycle_status_for(scope_dt);
    if (status) {
        munit_assert_string_equal(status, "teardown");
    } else {
        (void)scope;
    }
}

static MunitResult test_heartbeat_lifecycle_signals(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());

    munit_assert_true(cep_heartbeat_startup());
    munit_assert_true(cep_heartbeat_begin(policy.start_at));
    munit_assert_true(cep_heartbeat_step());

    assert_scope_ready(CEP_LIFECYCLE_SCOPE_KERNEL, CEP_DTAW("CEP", "kernel"));
    assert_scope_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL, CEP_DTAW("CEP", "namepool"));

    munit_assert_true(cep_heartbeat_emit_shutdown());

    assert_scope_teardown(CEP_LIFECYCLE_SCOPE_KERNEL, CEP_DTAW("CEP", "kernel"));
    assert_scope_teardown(CEP_LIFECYCLE_SCOPE_NAMEPOOL, CEP_DTAW("CEP", "namepool"));

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}

static void heartbeat_check_shutdown_case(bool load_layers) {
    (void)load_layers;
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());

    munit_assert_true(cep_heartbeat_startup());
    munit_assert_true(cep_heartbeat_begin(policy.start_at));
    munit_assert_true(cep_heartbeat_step());

    munit_assert_true(cep_heartbeat_emit_shutdown());

    assert_scope_teardown(CEP_LIFECYCLE_SCOPE_KERNEL, CEP_DTAW("CEP", "kernel"));
    assert_scope_teardown(CEP_LIFECYCLE_SCOPE_NAMEPOOL, CEP_DTAW("CEP", "namepool"));

    cep_heartbeat_shutdown();
}

static MunitResult test_heartbeat_shutdown_sequences(void) {
    heartbeat_check_shutdown_case(false);
    heartbeat_check_shutdown_case(true);
    return MUNIT_OK;
}

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


MunitResult test_heartbeat(const MunitParameter params[], void* user_data_or_fixture) {
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

    result = test_heartbeat_binding_no_propagation();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_union_chain();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_duplicate_mask();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_target_requires_binding();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_signal_filter();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_matches_data_suffix();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_binding_matches_store_suffix();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_lifecycle_signals(params, NULL);
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_shutdown_sequences();
    if (result != MUNIT_OK) {
        return result;
    }

    result = test_heartbeat_signal_broadcast();
    if (result != MUNIT_OK) {
        return result;
    }

    return MUNIT_OK;
}
