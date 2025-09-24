/*
 *  Copyright (c) 2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */


#include "test.h"
#include "cep_heartbeat.h"
#include "cep_enzyme.h"


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
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT seg_signal = *CEP_DTAA("SIG", "DUP");
    CepHeartbeatPathBuf path_buf = {0};
    const cepPath* path = make_path(&path_buf, &seg_signal, 1u);

    cepEnzymeDescriptor descriptor = {
        .name   = *CEP_DTAA("HB", "CNT"),
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_retry_requeues(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT seg_signal = *CEP_DTAA("SIG", "RTY");
    CepHeartbeatPathBuf path_buf = {0};
    const cepPath* path = make_path(&path_buf, &seg_signal, 1u);

    cepEnzymeDescriptor descriptor = {
        .name   = *CEP_DTAA("HB", "RTY"),
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

    cep_heartbeat_shutdown();
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
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAA("TST", "ROOT");
    const cepDT seg_leaf = *CEP_DTAA("TST", "LEAF");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);
    munit_assert_true(cep_cell_has_store(leaf_cell));

    const cepDT enzyme_name = *CEP_DTAA("EZ", "BIND");
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

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "IMG");
    const cepDT seg_sig_leaf = *CEP_DTAA("SIG", "THUMB");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_binding_tombstone(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAA("TST", "MASK");
    const cepDT seg_leaf = *CEP_DTAA("TST", "LEAF");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);
    munit_assert_true(cep_cell_has_store(leaf_cell));

    const cepDT enzyme_name = *CEP_DTAA("EZ", "MASK");
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

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "MASK");
    const cepDT seg_sig_leaf = *CEP_DTAA("SIG", "APPLY");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_binding_no_propagation(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAA("TST", "NOP");
    const cepDT seg_leaf = *CEP_DTAA("TST", "LEAF");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    const cepDT enzyme_name = *CEP_DTAA("EZ", "NOP");
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

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "NOP");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_binding_union_chain(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAA("TST", "TREE");
    const cepDT seg_mid  = *CEP_DTAA("TST", "BRANCH");
    const cepDT seg_leaf = *CEP_DTAA("TST", "LEAF");
    const cepDT path_segments[] = { seg_root, seg_mid, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    cepCell* mid_cell = cep_cell_parent(leaf_cell);
    munit_assert_not_null(mid_cell);
    cepCell* root_cell = cep_cell_parent(mid_cell);
    munit_assert_not_null(root_cell);

    const cepDT enzyme_root = *CEP_DTAA("EZ", "ROOT");
    const cepDT enzyme_mid  = *CEP_DTAA("EZ", "MID");
    const cepDT enzyme_leaf = *CEP_DTAA("EZ", "LEAF");

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "TREE");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_binding_duplicate_mask(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAA("TST", "DEDUP");
    const cepDT seg_leaf = *CEP_DTAA("TST", "LEAF");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    const cepDT enzyme_name = *CEP_DTAA("EZ", "DUPE");
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

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "DEDUP");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_target_requires_binding(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAA("TST", "EMPTY");
    const cepDT seg_leaf = *CEP_DTAA("TST", "LEAF");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);

    const cepDT enzyme_name = *CEP_DTAA("EZ", "SILENT");
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

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "EMPTY");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}

static MunitResult test_heartbeat_binding_signal_filter(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT type_dictionary = *CEP_DTAW("CEP", "dictionary");
    const cepDT seg_root = *CEP_DTAA("TST", "SIG");
    const cepDT seg_leaf = *CEP_DTAA("TST", "LEAF");
    const cepDT path_segments[] = { seg_root, seg_leaf };

    CepHeartbeatPathBuf target_buf = {0};
    cepCell* leaf_cell = NULL;
    const cepPath* target_path = create_binding_path(path_segments, cep_lengthof(path_segments), &target_buf, &type_dictionary, &leaf_cell);
    munit_assert_not_null(leaf_cell);
    munit_assert_true(cep_cell_has_store(leaf_cell));

    const cepDT enzyme_name = *CEP_DTAA("EZ", "SIG");
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

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "EXPECTED");
    const cepDT seg_sig_leaf = *CEP_DTAA("SIG", "MATCH");
    const cepDT signal_segments[] = { seg_sig_root, seg_sig_leaf };
    CepHeartbeatPathBuf signal_buf = {0};
    const cepPath* signal_path = make_path(&signal_buf, signal_segments, cep_lengthof(signal_segments));

    const cepDT seg_wrong = *CEP_DTAA("SIG", "SKIP");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}


static MunitResult test_heartbeat_signal_broadcast(void) {
    cep_heartbeat_shutdown();
    heartbeat_runtime_start();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    const cepDT enzyme_name = *CEP_DTAA("EZ", "BCAST");
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

    const cepDT seg_sig_root = *CEP_DTAA("SIG", "BROAD");
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

    cep_heartbeat_shutdown();
    return MUNIT_OK;
}


MunitResult test_heartbeat(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
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

    result = test_heartbeat_signal_broadcast();
    if (result != MUNIT_OK) {
        return result;
    }

    return MUNIT_OK;
}
