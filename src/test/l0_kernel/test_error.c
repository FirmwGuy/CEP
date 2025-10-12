#include "test.h"

#include "cep_error.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_identifier.h"
#include "cep_l0.h"
#include "cep_molecule.h"
#include "cep_namepool.h"

#include <string.h>

static cepCell* error_stage_root(void) {
    cepCell* tmp_root = cep_heartbeat_tmp_root();
    munit_assert_not_null(tmp_root);

    cepCell* err_root = cep_cell_find_by_name(tmp_root, CEP_DTAW("CEP", "err"));
    if (!err_root) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT name = *CEP_DTAW("CEP", "err");
        err_root = cep_cell_add_dictionary(tmp_root, &name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(err_root);
    }

    cepCell* stage = cep_cell_find_by_name(err_root, CEP_DTAW("CEP", "stage"));
    if (!stage) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT name = *CEP_DTAW("CEP", "stage");
        stage = cep_cell_add_dictionary(err_root, &name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(stage);
    }

    return stage;
}

static cepID ensure_word(const char* text) {
    cepID id = cep_text_to_word(text);
    if (!id) {
        id = cep_namepool_intern_cstr(text);
    }
    munit_assert_true(id != 0);
    return id;
}

static void ensure_err_code(const char* scope_text, const char* code_text, const char* message) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    munit_assert_not_null(sys_root);

    cepCell* err_cat = cep_cell_find_by_name(sys_root, CEP_DTAW("CEP", "err_cat"));
    if (!err_cat) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT name = *CEP_DTAW("CEP", "err_cat");
        err_cat = cep_cell_add_dictionary(sys_root, &name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(err_cat);
    }

    cepDT scope_dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = ensure_word(scope_text),
        .glob = 0u,
    };
    cepCell* scope_node = cep_cell_find_by_name(err_cat, &scope_dt);
    if (!scope_node) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepCell* created = cep_cell_add_dictionary(err_cat, &scope_dt, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(created);
        scope_node = created;
    }

    cepDT code_dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = ensure_word(code_text),
        .glob = 0u,
    };
    cepCell* code_node = cep_cell_find_by_name(scope_node, &code_dt);
    if (!code_node) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepCell* created = cep_cell_add_dictionary(scope_node, &code_dt, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(created);
        cepDT msg_name = *CEP_DTAW("CEP", "message");
        cepDT text_type = *CEP_DTAW("CEP", "text");
        size_t len = strlen(message) + 1u;
        munit_assert_not_null(cep_dict_add_value(created, &msg_name, &text_type, message, len, len));
    }
}

static const char* error_field_text(const cepCell* event, const char* tag_text) {
    cepDT lookup = {
        .domain = CEP_ACRO("CEP"),
        .tag = ensure_word(tag_text),
        .glob = 0u,
    };
    return (const char*)cep_cell_data_find_by_name(event, &lookup);
}

MunitResult test_error_emit_kernel(const MunitParameter params[], void* fixture) {
    (void)fixture;
    test_boot_cycle_prepare(params);

    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_heartbeat_begin(0));

    ensure_err_code("kernel", "E001", "kernel default");

    cepCell* stage = error_stage_root();
    size_t before = cep_cell_children(stage);

    cepErrorSpec spec = {
        .code = *CEP_DTAW("CEP", "E001"),
        .message = "Kernel warning",
        .target = NULL,
        .parents = NULL,
        .parent_count = 0u,
        .detail = NULL,
        .scope = *CEP_DTAW("CEP", "kernel"),
    };

    munit_assert_true(cep_error_emit(CEP_ERR_WARN, &spec));

    cepCell* refreshed_stage = error_stage_root();
    size_t after = cep_cell_children(refreshed_stage);
    munit_assert_size(after, ==, before + 1u);

    cepCell* event = cep_cell_find_by_position(refreshed_stage, after - 1u);
    munit_assert_not_null(event);

    const char* level_text = error_field_text(event, "level");
    munit_assert_not_null(level_text);
    munit_assert_string_equal(level_text, "warn");

    const char* msg_text = error_field_text(event, "message");
    munit_assert_not_null(msg_text);
    munit_assert_string_equal(msg_text, "CEP-L0: Kernel warning");

    const char* emit_kind = error_field_text(event, "emit_kind");
    munit_assert_not_null(emit_kind);
    munit_assert_string_equal(emit_kind, "kernel");

    const char* emitter = error_field_text(event, "emitter");
    munit_assert_not_null(emitter);
    munit_assert_string_equal(emitter, "CEP:kernel");

    const char* scope_text = error_field_text(event, "scope");
    munit_assert_not_null(scope_text);
    munit_assert_string_equal(scope_text, "CEP:kernel");

    test_runtime_shutdown();
    return MUNIT_OK;
}

static int test_error_emitter_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepErrorSpec spec = {
        .code = *CEP_DTAW("CEP", "MR001"),
        .message = "Mailroom fault",
        .target = NULL,
        .parents = NULL,
        .parent_count = 0u,
        .detail = NULL,
        .scope = *CEP_DTAW("CEP", "mailroom"),
    };

    munit_assert_true(cep_error_emit(CEP_ERR_USAGE, &spec));
    return CEP_ENZYME_SUCCESS;
}

MunitResult test_error_emit_enzyme(const MunitParameter params[], void* fixture) {
    (void)fixture;
    test_boot_cycle_prepare(params);

    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_heartbeat_begin(0));

    ensure_err_code("mailroom", "MR001", "mailroom default");

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    cepDT enzyme_name = *CEP_DTAW("CEP", "err_emit");
    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepStaticPath2;
    cepStaticPath2 signal_buf = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            { .dt = *CEP_DTAW("CEP", "sig_errtest"), .timestamp = 0u },
            { .dt = *CEP_DTAW("CEP", "emit"),        .timestamp = 0u },
        },
    };

    cepEnzymeDescriptor descriptor = {
        .name = enzyme_name,
        .label = "test.error.emitter",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = test_error_emitter_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    munit_assert_int(cep_enzyme_register(registry, (const cepPath*)&signal_buf, &descriptor), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    munit_assert_int(cep_cell_bind_enzyme(cep_root(), &enzyme_name, true), ==, CEP_ENZYME_SUCCESS);

    cepCell* stage = error_stage_root();
    size_t before = cep_cell_children(stage);

    cepPath* target_path = NULL;
    munit_assert_true(cep_cell_path(cep_root(), &target_path));

    cepImpulse impulse = {
        .signal_path = (const cepPath*)&signal_buf,
        .target_path = target_path,
    };
    munit_assert_int(cep_heartbeat_enqueue_impulse(0u, &impulse), ==, CEP_ENZYME_SUCCESS);
    CEP_FREE(target_path);

    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_execute_agenda());
    munit_assert_true(cep_heartbeat_stage_commit());

    cepCell* refreshed_stage = error_stage_root();
    size_t after = cep_cell_children(refreshed_stage);
    munit_assert_size(after, ==, before + 1u);

    cepCell* event = cep_cell_find_by_position(refreshed_stage, after - 1u);
    munit_assert_not_null(event);

    const char* emit_kind = error_field_text(event, "emit_kind");
    munit_assert_not_null(emit_kind);
    munit_assert_string_equal(emit_kind, "enzyme");

    const char* emitter = error_field_text(event, "emitter");
    munit_assert_not_null(emitter);
    munit_assert_string_equal(emitter, "CEP:err_emit");

    const char* label = error_field_text(event, "emit_label");
    munit_assert_not_null(label);
    munit_assert_string_equal(label, "test.error.emitter");

    const char* message = error_field_text(event, "message");
    munit_assert_not_null(message);
    munit_assert_string_equal(message, "Mailroom fault");

    test_runtime_shutdown();
    return MUNIT_OK;
}
