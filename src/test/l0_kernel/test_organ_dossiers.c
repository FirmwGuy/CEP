/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Organ Validation Harness (OVH) dossier tests confirm constructors and destructors emit their
 * heartbeat operations, reusing a fixture organ so we can observe `op/ct` and
 * `op/dt` timelines alongside validator dossiers. Each test bootstraps the
 * runtime, registers the fixture enzymes, drives the heartbeat, and inspects
 * `/rt/ops` to make sure the expected dossiers appear. */

#include "test.h"

#include "cep_cell.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_l0.h"
#include "cep_namepool.h"
#include "cep_ops.h"
#include "cep_organ.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} OrganDossierRuntimeScope;

static OrganDossierRuntimeScope organ_dossier_prepare_runtime(void) {
    OrganDossierRuntimeScope scope = {
        .runtime = cep_runtime_create(),
        .previous_runtime = NULL,
    };
    munit_assert_not_null(scope.runtime);
    scope.previous_runtime = cep_runtime_set_active(scope.runtime);
    cep_cell_system_initiate();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_namepool_bootstrap());
    (void)cep_namepool_intern_static("op/vl", strlen("op/vl"));
    (void)cep_namepool_intern_static("op/ct", strlen("op/ct"));
    (void)cep_namepool_intern_static("op/dt", strlen("op/dt"));
    (void)cep_namepool_intern_static("opm:states", strlen("opm:states"));
    munit_assert_true(cep_runtime_attach_metadata(scope.runtime));
    munit_assert_true(cep_heartbeat_startup());

    for (int i = 0; i < 6; ++i) {
        test_ovh_tracef("organ_dossier_prepare_runtime iteration=%d", i);
        munit_assert_true(test_ovh_heartbeat_step("organ_dossier_prepare_runtime"));
    }

    return scope;
}

static void organ_dossier_cleanup_runtime(OrganDossierRuntimeScope* scope) {
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

static cepCell* organ_dossier_ops_root(void) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops);
    return cep_cell_resolve(ops);
}

static cepCell* organ_dossier_find_cell(cepCell* parent, const cepDT* name) {
    cepCell* node = cep_cell_find_by_name(parent, name);
    munit_assert_not_null(node);
    node = cep_cell_resolve(node);
    munit_assert_not_null(node);
    return node;
}

static const char* organ_dossier_dt_desc(const cepDT* dt, char* buffer, size_t capacity) {
    if (!dt || !buffer || capacity == 0u) {
        return "<invalid>";
    }
    const char* domain = cep_namepool_lookup(dt->domain, NULL);
    const char* tag = cep_namepool_lookup(dt->tag, NULL);
    if (!domain) {
        domain = "?";
    }
    if (!tag) {
        tag = "?";
    }
    snprintf(buffer, capacity, "%s:%s", domain, tag);
    return buffer;
}


static void organ_dossier_trace_ops_size(const char* label, cepCell* ops_root) {
    if (!test_ovh_trace_enabled() || !ops_root)
        return;
    test_ovh_tracef("%s ops_children=%zu", label, cep_cell_children(ops_root));
}

static void organ_dossier_trace_recent_ops(const char* label, cepCell* ops_root, unsigned limit) {
    if (!test_ovh_trace_enabled() || !ops_root || limit == 0u)
        return;
    unsigned emitted = 0u;
    for (cepCell* entry = cep_cell_last_all(ops_root);
         entry && emitted < limit;
         entry = cep_cell_prev_all(ops_root, entry)) {
        const char* target_desc = "<missing>";
        const char* verb_desc = "<missing>";
        const char* state_desc = "<missing>";
        char verb_buf[64];
        char state_buf[64];
        cepCell* envelope = cep_cell_find_by_name(entry, CEP_DTAW("CEP", "envelope"));
        if (envelope) {
            envelope = cep_cell_resolve(envelope);
        }
        if (envelope) {
            cepCell* target_node = cep_cell_find_by_name(envelope, CEP_DTAW("CEP", "target"));
            target_node = target_node ? cep_cell_resolve(target_node) : NULL;
            cepCell* verb_node = cep_cell_find_by_name(envelope, CEP_DTAW("CEP", "verb"));
            verb_node = verb_node ? cep_cell_resolve(verb_node) : NULL;
            if (target_node && target_node->data && target_node->data->datatype == CEP_DATATYPE_VALUE) {
                target_desc = (const char*)target_node->data->value;
            }
            if (verb_node && verb_node->data && verb_node->data->datatype == CEP_DATATYPE_VALUE &&
                verb_node->data->size == sizeof(cepDT)) {
                cepDT verb_dt = {0};
                memcpy(&verb_dt, verb_node->data->value, sizeof verb_dt);
                verb_desc = organ_dossier_dt_desc(&verb_dt, verb_buf, sizeof verb_buf);
            }
        }
        cepCell* state_node = cep_cell_find_by_name(entry, CEP_DTAW("CEP", "state"));
        state_node = state_node ? cep_cell_resolve(state_node) : NULL;
        if (state_node && state_node->data && state_node->data->datatype == CEP_DATATYPE_VALUE &&
            state_node->data->size == sizeof(cepDT)) {
            cepDT state_dt = {0};
            memcpy(&state_dt, state_node->data->value, sizeof state_dt);
            state_desc = organ_dossier_dt_desc(&state_dt, state_buf, sizeof state_buf);
        }
        test_ovh_tracef("%s recent[%u] target=%s verb=%s state=%s",
                        label ? label : "ops_recent",
                        emitted,
                        target_desc ? target_desc : "<null>",
                        verb_desc ? verb_desc : "<null>",
                        state_desc ? state_desc : "<null>");
        ++emitted;
    }
}

static cepCell* organ_dossier_find_matching(cepCell* ops_root,
                                            const char* expected_target,
                                            const char* expected_verb);

static void organ_dossier_wait_for_operation(const char* label,
                                             cepCell* ops_root,
                                             size_t before_count,
                                             const char* expected_target,
                                             const char* expected_verb) {
    const int max_beats = expected_target ? 48 : 12;
    for (int beat = 0; beat < max_beats; ++beat) {
        munit_assert_true(test_ovh_heartbeat_step(label));
        organ_dossier_trace_ops_size(label, ops_root);
        if (expected_target && expected_verb) {
            cepCell* hit = organ_dossier_find_matching(ops_root, expected_target, expected_verb);
            if (hit) {
                return;
            }
        } else if (cep_cell_children(ops_root) > before_count) {
            return;
        }
    }
    if (expected_target && expected_verb) {
        munit_errorf("organ dossier did not surface: target=%s verb=%s", expected_target, expected_verb);
    }
    munit_error("organ dossier did not increase ops count within heartbeat allowance");
}

static cepCell* organ_dossier_find_matching(cepCell* ops_root,
                                            const char* expected_target,
                                            const char* expected_verb) {
    cepDT verb_expected = cep_ops_make_dt(expected_verb);
    for (cepCell* entry = cep_cell_last_all(ops_root); entry; entry = cep_cell_prev_all(ops_root, entry)) {
        cepCell* envelope = organ_dossier_find_cell(entry, CEP_DTAW("CEP", "envelope"));

        cepCell* verb_node = organ_dossier_find_cell(envelope, CEP_DTAW("CEP", "verb"));
        const cepData* verb_data = verb_node->data;
        if (!verb_data || verb_data->datatype != CEP_DATATYPE_VALUE || verb_data->size != sizeof(cepDT)) {
            continue;
        }
        cepDT verb_dt = {0};
        memcpy(&verb_dt, verb_data->value, sizeof verb_dt);
        cepCell* target_node = organ_dossier_find_cell(envelope, CEP_DTAW("CEP", "target"));
        if (cep_dt_compare(&verb_dt, &verb_expected) != 0) {
            continue;
        }
        const cepData* target_data = target_node->data;
        if (!target_data || target_data->datatype != CEP_DATATYPE_VALUE || target_data->size == 0u) {
            continue;
        }
        const char* target_path = (const char*)target_data->value;
        if (!target_path || strcmp(target_path, expected_target) != 0) {
            continue;
        }

        return entry;
    }

    return NULL;
}

static void organ_dossier_assert_latest(const char* expected_target,
                                        const char* expected_verb) {
    cepCell* ops_root = organ_dossier_ops_root();
    cepCell* newest = organ_dossier_find_matching(ops_root, expected_target, expected_verb);
    if (!newest) {
        organ_dossier_trace_recent_ops("organ_dossier_assert_latest", ops_root, 5u);
        munit_error("matching organ dossier not found");
    }

    cepCell* envelope = organ_dossier_find_cell(newest, CEP_DTAW("CEP", "envelope"));

    cepCell* verb_node = organ_dossier_find_cell(envelope, CEP_DTAW("CEP", "verb"));
    const cepData* verb_data = verb_node->data;
    munit_assert_not_null(verb_data);
    munit_assert_int(verb_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(verb_data->size, ==, sizeof(cepDT));
    cepDT verb_dt = {0};
    memcpy(&verb_dt, verb_data->value, sizeof verb_dt);
    cepDT verb_expected = cep_ops_make_dt(expected_verb);
    munit_assert_int(cep_dt_compare(&verb_dt, &verb_expected), ==, 0);

    cepCell* target_node = organ_dossier_find_cell(envelope, CEP_DTAW("CEP", "target"));
    const cepData* target_data = target_node->data;
    munit_assert_not_null(target_data);
    munit_assert_int(target_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_true(target_data->size > 0u);
    const char* target_path = (const char*)target_data->value;
    munit_assert_not_null(target_path);
    munit_assert_string_equal(target_path, expected_target);

    cepCell* state_node = organ_dossier_find_cell(newest, CEP_DTAW("CEP", "state"));
    const cepData* state_data = state_node->data;
    munit_assert_int(state_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(state_data->size, ==, sizeof(cepDT));
    cepDT state_dt = {0};
    memcpy(&state_dt, state_data->value, sizeof state_dt);
    cepDT state_expected = cep_ops_make_dt("ist:ok");
    munit_assert_int(cep_dt_compare(&state_dt, &state_expected), ==, 0);

    cepCell* close_branch = organ_dossier_find_cell(newest, CEP_DTAW("CEP", "close"));
    munit_assert_true(cep_cell_is_immutable(close_branch));
    cepCell* status_node = organ_dossier_find_cell(close_branch, CEP_DTAW("CEP", "status"));
    const cepData* status_data = status_node->data;
    munit_assert_int(status_data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(status_data->size, ==, sizeof(cepDT));
    cepDT status_dt = {0};
    memcpy(&status_dt, status_data->value, sizeof status_dt);
    cepDT status_expected = cep_ops_make_dt("sts:ok");
    munit_assert_int(cep_dt_compare(&status_dt, &status_expected), ==, 0);
}

static cepDT ORGAN_FIXTURE_STORE_DT;
static cepDT ORGAN_FIXTURE_VALIDATOR_DT;
static cepDT ORGAN_FIXTURE_CONSTRUCTOR_DT;
static cepDT ORGAN_FIXTURE_DESTRUCTOR_DT;
static const char* ORGAN_FIXTURE_TARGET = "/tmp/fixture";

static bool organ_fixture_id_to_text(cepID id, char* buffer, size_t capacity, size_t* out_len) {
    if (!buffer || capacity == 0u) {
        return false;
    }

    size_t len = 0u;

    if (cep_id_is_reference(id)) {
        size_t ref_len = 0u;
        const char* text = cep_namepool_lookup(id, &ref_len);
        if (!text) {
            return false;
        }
        if (ref_len + 1u > capacity) {
            return false;
        }
        memcpy(buffer, text, ref_len);
        buffer[ref_len] = '\0';
        len = ref_len;
    } else if (cep_id_is_word(id)) {
        len = cep_word_to_text(id, buffer);
    } else if (cep_id_is_acronym(id)) {
        len = cep_acronym_to_text(id, buffer);
    } else if (cep_id_is_numeric(id)) {
        uint64_t value = (uint64_t)cep_id(id);
        int written = snprintf(buffer, capacity, "%" PRIu64, value);
        if (written < 0) {
            return false;
        }
        len = (size_t)written;
    } else {
        if (capacity < 2u) {
            return false;
        }
        buffer[0] = '?';
        buffer[1] = '\0';
        len = 1u;
    }

    if (len + 1u > capacity) {
        return false;
    }

    if (out_len) {
        *out_len = len;
    }
    return true;
}

static void organ_fixture_init_dts(void) {
    ORGAN_FIXTURE_STORE_DT = cep_organ_store_dt("fixture");
    ORGAN_FIXTURE_VALIDATOR_DT = cep_ops_make_dt("org:fixture:vl");
    ORGAN_FIXTURE_CONSTRUCTOR_DT = cep_ops_make_dt("org:fixture:ct");
    ORGAN_FIXTURE_DESTRUCTOR_DT = cep_ops_make_dt("org:fixture:dt");
}

static bool organ_fixture_path_text(const cepPath* target_path, char* buffer, size_t capacity) {
    if (!target_path || !buffer || capacity == 0u) {
        return false;
    }
    size_t offset = 0u;
    for (unsigned i = 0; i < target_path->length; ++i) {
        const cepPast* segment = &target_path->past[i];
        if (offset + 1u >= capacity) {
            return false;
        }
        buffer[offset++] = '/';

        char tag_buf[32];
        size_t tag_len = 0u;
        if (!organ_fixture_id_to_text(segment->dt.tag, tag_buf, sizeof tag_buf, &tag_len)) {
            return false;
        }
        if (offset + tag_len >= capacity) {
            return false;
        }
        memcpy(buffer + offset, tag_buf, tag_len);
        offset += tag_len;
    }
    if (offset == 0u && capacity > 1u) {
        buffer[offset++] = '/';
    }
    buffer[offset] = '\0';
    return true;
}

static bool organ_fixture_emit_dossier(const cepPath* target, const char* verb_tag, const char* log_label) {
    char path_buffer[128];
    if (!organ_fixture_path_text(target, path_buffer, sizeof path_buffer)) {
        if (test_ovh_trace_enabled()) {
            test_ovh_tracef("%s path decode failed", log_label ? log_label : "fixture_emit");
        }
        return false;
    }
    if (test_ovh_trace_enabled() && log_label) {
        test_ovh_tracef("%s begin target=%s", log_label, path_buffer);
    }
    munit_assert_true(cep_namepool_bootstrap());
    cepDT verb = cep_ops_make_dt(verb_tag);
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, path_buffer, mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(oid)) {
        if (test_ovh_trace_enabled()) {
            test_ovh_tracef("%s op_start failed err=%d", log_label ? log_label : "fixture_emit", cep_ops_debug_last_error());
        }
        return false;
    }
    if (!cep_op_state_set(oid, cep_ops_make_dt("ist:ok"), 0u, NULL)) {
        if (test_ovh_trace_enabled()) {
            test_ovh_tracef("%s state_set failed err=%d", log_label ? log_label : "fixture_emit", cep_ops_debug_last_error());
        }
        return false;
    }
    if (!cep_op_close(oid, cep_ops_make_dt("sts:ok"), NULL, 0u)) {
        if (test_ovh_trace_enabled()) {
            test_ovh_tracef("%s close failed err=%d", log_label ? log_label : "fixture_emit", cep_ops_debug_last_error());
        }
        return false;
    }
    if (test_ovh_trace_enabled() && log_label) {
        test_ovh_tracef("%s success oid=%" PRIu64 ":%" PRIu64,
                           log_label,
                           (unsigned long long)oid.domain,
                           (unsigned long long)oid.tag);
    }
    return true;
}

static int organ_fixture_validator_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    if (test_ovh_trace_enabled()) {
        char path_buffer[128];
        if (organ_fixture_path_text(target, path_buffer, sizeof path_buffer)) {
            test_ovh_tracef("fixture_validator signal=%p target=%s", (const void*)signal, path_buffer);
        } else {
            test_ovh_tracef("fixture_validator signal=%p target=<decode-failed>", (const void*)signal);
        }
    }
    if (!organ_fixture_emit_dossier(target, "op/vl", "fixture_vl")) {
        return CEP_ENZYME_FATAL;
    }
    return CEP_ENZYME_SUCCESS;
}

static int organ_fixture_dtor_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    if (test_ovh_trace_enabled()) {
        char path_buffer[128];
        if (organ_fixture_path_text(target, path_buffer, sizeof path_buffer)) {
            test_ovh_tracef("fixture_dtor signal=%p target=%s", (const void*)signal, path_buffer);
        } else {
            test_ovh_tracef("fixture_dtor signal=%p target=<decode-failed>", (const void*)signal);
        }
    }
    if (!organ_fixture_emit_dossier(target, "op/dt", "fixture_dtor")) {
        return CEP_ENZYME_FATAL;
    }
    return CEP_ENZYME_SUCCESS;
}

static int organ_fixture_ctor_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    if (test_ovh_trace_enabled()) {
        char path_buffer[128];
        if (organ_fixture_path_text(target, path_buffer, sizeof path_buffer)) {
            test_ovh_tracef("fixture_ctor signal=%p target=%s", (const void*)signal, path_buffer);
        } else {
            test_ovh_tracef("fixture_ctor signal=%p target=<decode-failed>", (const void*)signal);
        }
    }
    if (!organ_fixture_emit_dossier(target, "op/ct", "fixture_ctor")) {
        return CEP_ENZYME_FATAL;
    }
    return CEP_ENZYME_SUCCESS;
}

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  segments[1];
} OrganPathBuf;

static const cepPath* organ_make_single_path(OrganPathBuf* buf, const cepDT* dt) {
    buf->length = 1u;
    buf->capacity = 1u;
    buf->segments[0].dt = *dt;
    buf->segments[0].timestamp = 0u;
    return (const cepPath*)buf;
}

static void organ_fixture_register_descriptor(void) {
    organ_fixture_init_dts();
    cepOrganDescriptor descriptor = {
        .kind = "fixture",
        .label = "organ.fixture.test",
        .store = ORGAN_FIXTURE_STORE_DT,
        .validator = ORGAN_FIXTURE_VALIDATOR_DT,
        .constructor = ORGAN_FIXTURE_CONSTRUCTOR_DT,
        .destructor = ORGAN_FIXTURE_DESTRUCTOR_DT,
    };
    munit_assert_true(cep_organ_register(&descriptor));
}

static void organ_fixture_assert_descriptor_registered(void) {
    organ_fixture_init_dts();
    const cepOrganDescriptor* descriptor = cep_organ_descriptor(&ORGAN_FIXTURE_STORE_DT);
    munit_assert_not_null(descriptor);
}

static void organ_fixture_register_enzymes(void) {
    static cepEnzymeRegistry* registered_registry = NULL;

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    if (registry == registered_registry) {
        return;
    }

    OrganPathBuf validator_path = {0};
    OrganPathBuf ctor_path = {0};
    OrganPathBuf dtor_path = {0};

    cepEnzymeDescriptor validator_desc = {
        .name = ORGAN_FIXTURE_VALIDATOR_DT,
        .label = "organ.fixture.vl",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = organ_fixture_validator_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    munit_assert_int(cep_enzyme_register(registry,
                                         organ_make_single_path(&validator_path, &ORGAN_FIXTURE_VALIDATOR_DT),
                                         &validator_desc),
                     ==,
                     CEP_ENZYME_SUCCESS);

    cepEnzymeDescriptor ctor_desc = {
        .name = ORGAN_FIXTURE_CONSTRUCTOR_DT,
        .label = "organ.fixture.ct",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = organ_fixture_ctor_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    munit_assert_int(cep_enzyme_register(registry,
                                         organ_make_single_path(&ctor_path, &ORGAN_FIXTURE_CONSTRUCTOR_DT),
                                         &ctor_desc),
                     ==,
                     CEP_ENZYME_SUCCESS);

    cepEnzymeDescriptor dtor_desc = {
        .name = ORGAN_FIXTURE_DESTRUCTOR_DT,
        .label = "organ.fixture.dt",
        .before = NULL,
        .before_count = 0,
        .after = NULL,
        .after_count = 0,
        .callback = organ_fixture_dtor_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    munit_assert_int(cep_enzyme_register(registry,
                                         organ_make_single_path(&dtor_path, &ORGAN_FIXTURE_DESTRUCTOR_DT),
                                         &dtor_desc),
                     ==,
                     CEP_ENZYME_SUCCESS);

    cep_enzyme_registry_activate_pending(registry);
    registered_registry = registry;
}

static cepCell* organ_fixture_root(void) {
    organ_fixture_init_dts();
    cepCell* tmp_root = cep_heartbeat_tmp_root();
    munit_assert_not_null(tmp_root);
    cepCell* resolved_tmp = cep_cell_resolve(tmp_root);
    munit_assert_not_null(resolved_tmp);

    cepDT name = *CEP_DTAW("CEP", "fixture");
    cepCell* existing = cep_cell_find_by_name(resolved_tmp, &name);
    if (existing) {
        cepCell* resolved_existing = cep_cell_resolve(existing);
        munit_assert_not_null(resolved_existing);
        return resolved_existing;
    }

    cepCell* created = cep_cell_add_dictionary(resolved_tmp,
                                               &name,
                                               0,
                                               &ORGAN_FIXTURE_STORE_DT,
                                               CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(created);
    return created;
}

static void organ_fixture_bindings(cepCell* root) {
    munit_assert_int(cep_cell_bind_enzyme(root, &ORGAN_FIXTURE_VALIDATOR_DT, true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(root, &ORGAN_FIXTURE_CONSTRUCTOR_DT, true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(root, &ORGAN_FIXTURE_DESTRUCTOR_DT, true), ==, CEP_ENZYME_SUCCESS);
}

MunitResult test_organ_constructor_dossier(const MunitParameter params[], void* fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)fixture;
    munit_assert_not_null(watchdog);

    OrganDossierRuntimeScope scope = organ_dossier_prepare_runtime();
    organ_fixture_register_descriptor();
    organ_fixture_register_enzymes();
    organ_fixture_assert_descriptor_registered();
    cepCell* fixture_root = organ_fixture_root();
    organ_fixture_bindings(fixture_root);
    cepOrganRoot info = {0};
    munit_assert_true(cep_organ_root_for_cell(fixture_root, &info));
    munit_assert_not_null(info.descriptor);

    cepCell* ops_root = organ_dossier_ops_root();
    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_constructor(fixture_root));
    organ_dossier_trace_ops_size("organ_ctor queued", ops_root);
    organ_dossier_wait_for_operation("organ_ctor run", ops_root, before_count, ORGAN_FIXTURE_TARGET, "op/ct");
    organ_dossier_assert_latest(ORGAN_FIXTURE_TARGET, "op/ct");

    test_watchdog_signal(watchdog);
    organ_dossier_cleanup_runtime(&scope);
    return MUNIT_OK;
}

MunitResult test_organ_destructor_dossier(const MunitParameter params[], void* fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)fixture;
    munit_assert_not_null(watchdog);

    OrganDossierRuntimeScope scope = organ_dossier_prepare_runtime();
    organ_fixture_register_descriptor();
    organ_fixture_register_enzymes();
    cepCell* fixture_root = organ_fixture_root();
    organ_fixture_bindings(fixture_root);

    cepCell* ops_root = organ_dossier_ops_root();
    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_destructor(fixture_root));
    organ_dossier_trace_ops_size("organ_dtor queued", ops_root);
    organ_dossier_wait_for_operation("organ_dtor run", ops_root, before_count, ORGAN_FIXTURE_TARGET, "op/dt");
    organ_dossier_assert_latest(ORGAN_FIXTURE_TARGET, "op/dt");

    test_watchdog_signal(watchdog);
    organ_dossier_cleanup_runtime(&scope);
    return MUNIT_OK;
}

static void organ_dossier_assert_count_grew(cepCell* ops_root, size_t before_count, const char* target, const char* verb) {
    organ_dossier_wait_for_operation("organ_dossier sequence", ops_root, before_count, target, verb);
    organ_dossier_assert_latest(target, verb);
}

MunitResult test_organ_dossier_sequence(const MunitParameter params[], void* fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)fixture;
    munit_assert_not_null(watchdog);

    OrganDossierRuntimeScope scope = organ_dossier_prepare_runtime();
    organ_fixture_register_descriptor();
    organ_fixture_register_enzymes();
    cepCell* fixture_root = organ_fixture_root();
    organ_fixture_bindings(fixture_root);

    cepCell* ops_root = organ_dossier_ops_root();

    size_t before_validation = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(fixture_root));
    organ_dossier_trace_ops_size("organ_seq validation queued", ops_root);
    organ_dossier_assert_count_grew(ops_root, before_validation, ORGAN_FIXTURE_TARGET, "op/vl");

    size_t before_constructor = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_constructor(fixture_root));
    organ_dossier_trace_ops_size("organ_seq constructor queued", ops_root);
    organ_dossier_assert_count_grew(ops_root, before_constructor, ORGAN_FIXTURE_TARGET, "op/ct");

    size_t before_destructor = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_destructor(fixture_root));
    organ_dossier_trace_ops_size("organ_seq destructor queued", ops_root);
    organ_dossier_assert_count_grew(ops_root, before_destructor, ORGAN_FIXTURE_TARGET, "op/dt");

    test_watchdog_signal(watchdog);
    organ_dossier_cleanup_runtime(&scope);
    return MUNIT_OK;
}
