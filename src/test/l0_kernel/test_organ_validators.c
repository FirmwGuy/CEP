/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Validator adoption tests: ensure the Organ Validation Harness (OVH) validators execute via
 * OPS/STATES and close dossiers cleanly for representative subsystems. The
 * checks drive a lightweight heartbeat cycle so we can observe the emitted
 * dossiers without rebuilding the entire runtime fixture. */

#include "test.h"
#include "cep_l0.h"
#include "cep_ops.h"
#include "cep_organ.h"
#include "cep_enzyme.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} OrganRuntimeScope;

static cepCell* organ_find_cell(cepCell* parent, const cepDT* name);
static const char* organ_ops_entry_target_strict(cepCell* op);

static OrganRuntimeScope organ_prepare_runtime(void) {
    OrganRuntimeScope scope = {
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

    /* Advance a few beats so the boot dossier reaches ist:ok before we queue
     * organ validators. */
    for (int i = 0; i < 6; ++i) {
        test_ovh_tracef("organ_prepare_runtime iteration=%d", i);
        munit_assert_true(test_ovh_heartbeat_step("organ_prepare_runtime"));
    }

    printf("[instrument][test] organ_prepare_runtime runtime=%p previous=%p\n",
           (void*)scope.runtime,
           (void*)scope.previous_runtime);
    fflush(stdout);

    return scope;
}

static void organ_cleanup_runtime(OrganRuntimeScope* scope) {
    if (!scope || !scope->runtime) {
        return;
    }

    printf("[instrument][test] organ_cleanup_runtime runtime=%p previous=%p\n",
           (void*)scope->runtime,
           (void*)scope->previous_runtime);
    fflush(stdout);

    cep_runtime_set_active(scope->runtime);
    cep_stream_clear_pending();
    cep_runtime_shutdown(scope->runtime);
    cep_runtime_restore_active(scope->previous_runtime);
    cep_runtime_destroy(scope->runtime);
    scope->runtime = NULL;
    scope->previous_runtime = NULL;
}

static cepCell* organ_ops_root(void) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops);
    return cep_cell_resolve(ops);
}

static const char*
organ_ops_entry_target_strict(cepCell* op)
{
    if (!op) {
        return NULL;
    }
    cepCell* envelope = organ_find_cell(op, CEP_DTAW("CEP", "envelope"));
    cepCell* target_node = organ_find_cell(envelope, CEP_DTAW("CEP", "target"));
    const cepData* target_data = target_node->data;
    if (!target_data || target_data->datatype != CEP_DATATYPE_VALUE || target_data->size == 0u) {
        return NULL;
    }
    const char* stored_target = (const char*)target_data->value;
    return (stored_target && stored_target[0]) ? stored_target : NULL;
}

static cepCell* organ_find_cell(cepCell* parent, const cepDT* name) {
    cepCell* node = cep_cell_find_by_name(parent, name);
    munit_assert_not_null(node);
    node = cep_cell_resolve(node);
    munit_assert_not_null(node);
    return node;
}

static void organ_trace_ops_size(const char* label, cepCell* ops_root) {
    if (!test_ovh_trace_enabled() || !ops_root)
        return;
    test_ovh_tracef("%s ops_children=%zu", label, cep_cell_children(ops_root));
}

static void organ_trace_bindings(const char* label, cepCell* root) {
    if (!test_ovh_trace_enabled() || !root) {
        return;
    }
    const cepEnzymeBinding* binding = cep_cell_enzyme_bindings(root);
    size_t count = 0u;
    for (const cepEnzymeBinding* node = binding; node; node = node->next) {
        if (node->flags & CEP_ENZYME_BIND_TOMBSTONE) {
            continue;
        }
        char tag_buf[64];
        const char* tag_text = tag_buf;
        if (cep_id_is_reference(node->name.tag)) {
            size_t tag_len = 0u;
            const char* looked = cep_namepool_lookup(node->name.tag, &tag_len);
            if (!looked || tag_len + 1u > sizeof tag_buf) {
                tag_text = "<ref>";
            } else {
                memcpy(tag_buf, looked, tag_len);
                tag_buf[tag_len] = '\0';
            }
        } else {
            size_t len = cep_word_to_text(node->name.tag, tag_buf);
            if (len >= sizeof tag_buf) {
                len = sizeof tag_buf - 1u;
            }
            tag_buf[len] = '\0';
        }
        test_ovh_tracef("%s binding[%zu] domain=%08x tag=%s flags=0x%x",
                        label ? label : "bindings",
                        count++,
                        (unsigned)cep_id(node->name.domain),
                        tag_text,
                        node->flags);
    }
    if (count == 0u) {
        test_ovh_tracef("%s binding[none]", label ? label : "bindings");
    }
}

typedef struct {
    cepPath path;
    cepPast past[1];
} OrganSinglePath;

typedef struct {
    cepPath path;
    cepPast past[4];
} OrganTargetPath;

static const cepPath* organ_build_target_path(OrganTargetPath* buf, cepCell* cell) {
    if (!buf || !cell) {
        return NULL;
    }
    unsigned depth = 0u;
    for (cepCell* current = cell; current && current->parent; current = current->parent->owner) {
        if (depth >= buf->path.capacity) {
            break;
        }
        depth++;
    }
    if (depth == 0u || depth > buf->path.capacity) {
        return NULL;
    }
    buf->path.length = depth;
    buf->path.capacity = depth;
    cepCell* current = cell;
    for (int index = (int)depth - 1; index >= 0 && current && current->parent; --index) {
        cepCell* parent = current->parent->owner;
        const cepDT* name = cep_cell_get_name(current);
        if (!name) {
            return NULL;
        }
        buf->past[index].dt = *name;
        buf->past[index].timestamp = 0u;
        current = parent;
    }
    return &buf->path;
}

static void organ_debug_resolve_signal(const char* label, const char* signal_text) {
    if (!test_ovh_trace_enabled() || !signal_text) {
        return;
    }
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return;
    }
    OrganSinglePath sig = {
        .path = {
            .length = 1u,
            .capacity = 1u,
        },
        .past = {
            {
                .dt = cep_ops_make_dt(signal_text),
                .timestamp = 0u,
            },
        },
    };
    const cepEnzymeDescriptor* ordered[16];
    cepImpulse impulse = {
        .signal_path = &sig.path,
        .target_path = NULL,
        .qos = 0u,
    };
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    test_ovh_tracef("%s resolve signal=%s count=%zu",
                    label ? label : "organ_resolve",
                    signal_text,
                    resolved);
}

static void organ_debug_resolve_signal_target(const char* label, const char* signal_text, cepCell* target) {
    if (!test_ovh_trace_enabled() || !signal_text || !target) {
        return;
    }
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return;
    }
    OrganTargetPath target_buf = {
        .path = {
            .length = 0u,
            .capacity = cep_lengthof(target_buf.past),
        },
    };
    const cepPath* target_path = organ_build_target_path(&target_buf, target);
    if (!target_path) {
        test_ovh_tracef("%s resolve signal=%s target=<invalid>", label ? label : "organ_resolve", signal_text);
        return;
    }
    OrganSinglePath sig = {
        .path = {
            .length = 1u,
            .capacity = 1u,
        },
        .past = {{
            .dt = cep_ops_make_dt(signal_text),
            .timestamp = 0u,
        }},
    };
    const cepEnzymeDescriptor* ordered[16];
    cepImpulse impulse = {
        .signal_path = &sig.path,
        .target_path = target_path,
        .qos = 0u,
    };
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    test_ovh_tracef("%s resolve signal=%s count=%zu target_segments=%u",
                    label ? label : "organ_resolve",
                    signal_text,
                    resolved,
                    target_path->length);
}

static bool organ_ops_has_entry(const char* target_path);
static bool organ_ops_has_entry_since(const char* target_path, cepID min_tag);

static void organ_wait_for_validator(const char* label,
                                     cepCell* ops_root,
                                     size_t before_count,
                                     const char* expected_target) {
    const int max_beats = expected_target ? 256 : 32;
    cepID baseline_tag = 0u;
    if (expected_target) {
        cepCell* tail = cep_cell_last_all(ops_root);
        if (tail) {
            const cepDT* name = cep_cell_get_name(tail);
            baseline_tag = name ? cep_id(name->tag) : 0u;
        }
    }
    for (int beat = 0; beat < max_beats; ++beat) {
        munit_assert_true(test_ovh_heartbeat_step(label));
        organ_trace_ops_size(label, ops_root);
        if (expected_target && organ_ops_has_entry_since(expected_target, baseline_tag)) {
            return;
        }
        size_t child_count = cep_cell_children(ops_root);
        if (child_count > before_count) {
            if (!expected_target) {
                return;
            }
            before_count = child_count;
        }
    }
    if (expected_target) {
        munit_errorf("validator %s did not emit target %s within heartbeat allowance",
                     label ? label : "<validator>",
                     expected_target);
    } else {
        munit_error("validator did not emit dossier within heartbeat allowance");
    }
}

static void organ_step_beats(const char* label, unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        munit_assert_true(test_ovh_heartbeat_step(label));
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
    if (!meta && test_ovh_trace_enabled()) {
        cepCell* resolved_root = root;
        if (cep_cell_require_dictionary_store(&resolved_root)) {
            test_ovh_tracef("organ schema debug: immutable=%d children=%zu",
                               cep_cell_is_immutable(resolved_root) ? 1 : 0,
                               cep_cell_children(resolved_root));
            cepCell* meta_lookup = cep_cell_find_by_name(resolved_root, CEP_DTAW("CEP", "meta"));
            test_ovh_tracef("organ schema debug: meta_lookup=%p", (void*)meta_lookup);
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
                test_ovh_tracef("organ schema missing meta child dom=%s tag=%s",
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
    return organ_ops_has_entry_since(target_path, 0u);
}

static bool organ_ops_has_entry_since(const char* target_path, cepID min_tag) {
    cepCell* ops_root = organ_ops_root();
    munit_assert_not_null(ops_root);

    for (cepCell* op = cep_cell_first_all(ops_root);
         op;
         op = cep_cell_next_all(ops_root, op)) {
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
        const cepDT* name = cep_cell_get_name(op);
        cepID tag_numeric = name ? cep_id(name->tag) : 0u;
        if (min_tag && tag_numeric && tag_numeric <= min_tag) {
            continue;
        }
        cepCell* state_node = organ_find_cell(op, CEP_DTAW("CEP", "state"));
        const cepData* state_data = state_node->data;
        if (!state_data || state_data->datatype != CEP_DATATYPE_VALUE || state_data->size != sizeof(cepDT)) {
            if (test_ovh_trace_enabled()) {
                test_ovh_tracef("organ_ops_has_entry pending target=%s state_data_missing=%d",
                                   target_path,
                                   state_data ? 0 : 1);
            }
            continue;
        }
        cepDT state_dt = {0};
        memcpy(&state_dt, state_data->value, sizeof state_dt);
        if (cep_dt_compare(&state_dt, CEP_DTAW("CEP", "ist:ok")) != 0) {
            if (test_ovh_trace_enabled()) {
                char state_buf[32];
                size_t len = cep_word_to_text(state_dt.tag, state_buf);
                if (len >= sizeof state_buf) {
                    len = sizeof state_buf - 1u;
                }
                state_buf[len] = '\0';
                test_ovh_tracef("organ_ops_has_entry target=%s unexpected_state=%s",
                                   target_path,
                                   state_buf);
            }
            continue;
        }

        cepCell* close_branch = organ_find_cell(op, CEP_DTAW("CEP", "close"));
        cepCell* status_node = organ_find_cell(close_branch, CEP_DTAW("CEP", "status"));
        const cepData* status_data = status_node->data;
        if (!status_data || status_data->datatype != CEP_DATATYPE_VALUE || status_data->size != sizeof(cepDT)) {
            if (test_ovh_trace_enabled()) {
                test_ovh_tracef("organ_ops_has_entry target=%s status_missing=%d",
                                   target_path,
                                   status_data ? 0 : 1);
            }
            continue;
        }
        cepDT status_dt = {0};
        memcpy(&status_dt, status_data->value, sizeof status_dt);
        if (cep_dt_compare(&status_dt, CEP_DTAW("CEP", "sts:ok")) != 0) {
            if (test_ovh_trace_enabled()) {
                char status_buf[32];
                size_t len = cep_word_to_text(status_dt.tag, status_buf);
                if (len >= sizeof status_buf) {
                    len = sizeof status_buf - 1u;
                }
                status_buf[len] = '\0';
                test_ovh_tracef("organ_ops_has_entry target=%s unexpected_status=%s",
                                   target_path,
                                   status_buf);
            }
            continue;
        }

        return true;
    }

    return false;
}

static void organ_assert_latest_success(const char* expected_target) {
    cepCell* ops_root = organ_ops_root();
    cepCell* newest = NULL;
    cepID newest_tag = 0u;
    for (cepCell* op = cep_cell_first_all(ops_root);
         op;
         op = cep_cell_next_all(ops_root, op)) {
        const char* target_path = organ_ops_entry_target_strict(op);
        if (!target_path || strcmp(target_path, expected_target) != 0) {
            continue;
        }

        cepCell* envelope = organ_find_cell(op, CEP_DTAW("CEP", "envelope"));
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

        const cepDT* name = cep_cell_get_name(op);
        cepID tag_numeric = name ? cep_id(name->tag) : 0u;
        if (!newest || tag_numeric > newest_tag) {
            newest = op;
            newest_tag = tag_numeric;
        }
    }
    if (!newest) {
        char summary[256];
        size_t offset = 0u;
        size_t inspected = 0u;
        for (cepCell* op = cep_cell_last_all(ops_root);
             op && inspected < 5u;
             op = cep_cell_prev_all(ops_root, op)) {
            const char* target_desc = "<missing>";
            cepCell* envelope = cep_cell_find_by_name(op, CEP_DTAW("CEP", "envelope"));
            if (envelope) {
                envelope = cep_cell_resolve(envelope);
                if (envelope) {
                    cepCell* target_node = cep_cell_find_by_name(envelope, CEP_DTAW("CEP", "target"));
                    if (target_node) {
                        target_node = cep_cell_resolve(target_node);
                        if (target_node && target_node->data && target_node->data->datatype == CEP_DATATYPE_VALUE) {
                            target_desc = (const char*)target_node->data->value;
                        } else {
                            target_desc = "<target-invalid>";
                        }
                    }
                }
            }
            int wrote = snprintf(summary + offset,
                                 sizeof(summary) - offset,
                                 "%s%s",
                                 (inspected++ ? "; " : ""),
                                 target_desc ? target_desc : "<null>");
            if (wrote < 0 || (size_t)wrote >= sizeof(summary) - offset) {
                offset = sizeof(summary) - 1u;
                summary[offset] = '\0';
                break;
            }
            offset += (size_t)wrote;
        }
        if (offset == 0u) {
            summary[0] = '\0';
        }
        munit_logf(MUNIT_LOG_ERROR,
                   "organ_ops missing expected target %s; recent targets: %s",
                   expected_target,
                   offset ? summary : "<none>");
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

    const char* target_path = organ_ops_entry_target_strict(newest);
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

    OrganRuntimeScope scope = organ_prepare_runtime();

    cepCell* sys_root = cep_heartbeat_sys_root();
    munit_assert_not_null(sys_root);
    cepCell* state_root = organ_find_cell(sys_root, CEP_DTAW("CEP", "state"));

    cepCell* ops_root = organ_ops_root();
    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_validation(state_root));
    organ_trace_ops_size("organ_sys_state queued", ops_root);

    organ_wait_for_validator("organ_sys_state run", ops_root, before_count, "/sys/state");

    munit_assert_true(organ_ops_has_entry("/sys/state"));
    test_watchdog_signal(watchdog);
    organ_cleanup_runtime(&scope);
    return MUNIT_OK;
}

MunitResult test_organ_rt_ops_validator(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);

    OrganRuntimeScope scope = organ_prepare_runtime();

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* ops_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "ops"));

    size_t before_count = cep_cell_children(ops_root);

    munit_assert_true(cep_organ_request_validation(ops_root));
    organ_trace_ops_size("organ_rt_ops queued", ops_root);

    organ_wait_for_validator("organ_rt_ops run", ops_root, before_count, "/rt/ops");

    organ_assert_latest_success("/rt/ops");
    test_watchdog_signal(watchdog);
    organ_cleanup_runtime(&scope);
    return MUNIT_OK;
}

MunitResult test_organ_constructor_bootstrap(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);

    OrganRuntimeScope scope = organ_prepare_runtime();

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* beat_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "beat"));

    cepCell* journal_root = cep_heartbeat_journal_root();
    munit_assert_not_null(journal_root);

    organ_trace_bindings("rt_beat bindings (cycles)", beat_root);
    organ_trace_bindings("journal bindings (cycles)", journal_root);
    organ_debug_resolve_signal("rt_beat resolve (cycles)", "org:rt_beat:vl");
    organ_debug_resolve_signal("journal resolve (cycles)", "org:journal:vl");
    organ_debug_resolve_signal_target("rt_beat resolve target (cycles)", "org:rt_beat:vl", beat_root);
    organ_debug_resolve_signal_target("journal resolve target (cycles)", "org:journal:vl", journal_root);

    organ_trace_bindings("rt_beat bindings (bootstrap)", beat_root);
    organ_trace_bindings("journal bindings (bootstrap)", journal_root);
    organ_debug_resolve_signal("rt_beat resolve (bootstrap)", "org:rt_beat:vl");
    organ_debug_resolve_signal("journal resolve (bootstrap)", "org:journal:vl");
    organ_debug_resolve_signal_target("rt_beat resolve target (bootstrap)", "org:rt_beat:vl", beat_root);
    organ_debug_resolve_signal_target("journal resolve target (bootstrap)", "org:journal:vl", journal_root);

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
    organ_wait_for_validator("organ_constructor_bootstrap:vl_rt_beat", ops_root, before, "/rt/beat");
    organ_assert_latest_success("/rt/beat");

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(journal_root));
    organ_wait_for_validator("organ_constructor_bootstrap:vl_journal", ops_root, before, "/journal");
    organ_assert_latest_success("/journal");

    test_watchdog_signal(watchdog);
    organ_cleanup_runtime(&scope);
    return MUNIT_OK;
}

MunitResult test_organ_constructor_destructor_cycles(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    TestWatchdog* watchdog = (TestWatchdog*)user_data_or_fixture;
    munit_assert_not_null(watchdog);

    OrganRuntimeScope scope = organ_prepare_runtime();

    cepCell* rt_root = cep_heartbeat_rt_root();
    munit_assert_not_null(rt_root);
    cepCell* beat_root = organ_find_cell(rt_root, CEP_DTAW("CEP", "beat"));

    cepCell* journal_root = cep_heartbeat_journal_root();
    munit_assert_not_null(journal_root);

    if (test_ovh_trace_enabled()) {
        cepDT expected_beat = cep_organ_store_dt("rt_beat");
        cepDT expected_journal = cep_organ_store_dt("journal");
        test_ovh_tracef("expected store dt: beat=%08x/%08x journal=%08x/%08x",
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
    organ_wait_for_validator("organ_destructor_cycles:vl_rt_beat_before", ops_root, before, "/rt/beat");
    organ_assert_latest_success("/rt/beat");

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(journal_root));
    organ_wait_for_validator("organ_destructor_cycles:vl_journal_before", ops_root, before, "/journal");
    organ_assert_latest_success("/journal");

    if (test_ovh_trace_enabled()) {
        const cepStore* beat_store = beat_root ? beat_root->store : NULL;
        const cepStore* journal_store = journal_root ? journal_root->store : NULL;
        test_ovh_tracef("pre-dtor store dt: beat=%08x/%08x journal=%08x/%08x",
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

    if (test_ovh_trace_enabled()) {
        const cepStore* beat_store = beat_root ? beat_root->store : NULL;
        const cepStore* journal_store = journal_root ? journal_root->store : NULL;
        test_ovh_tracef("post-dtor store dt: beat=%08x/%08x journal=%08x/%08x",
                           beat_store ? (unsigned)beat_store->dt.domain : 0u,
                           beat_store ? (unsigned)beat_store->dt.tag : 0u,
                           journal_store ? (unsigned)journal_store->dt.domain : 0u,
                           journal_store ? (unsigned)journal_store->dt.tag : 0u);
    }

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(beat_root));
    organ_wait_for_validator("organ_destructor_cycles:vl_rt_beat_after", ops_root, before, "/rt/beat");
    organ_assert_latest_success("/rt/beat");

    before = cep_cell_children(ops_root);
    munit_assert_true(cep_organ_request_validation(journal_root));
    organ_wait_for_validator("organ_destructor_cycles:vl_journal_after", ops_root, before, "/journal");
    organ_assert_latest_success("/journal");

    test_watchdog_signal(watchdog);
    organ_cleanup_runtime(&scope);
    return MUNIT_OK;
}
