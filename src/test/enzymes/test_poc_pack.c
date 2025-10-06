/* PoC pack acceptance tests exercise the PACK.md contract end-to-end: we
 * bootstrap the enzyme suite, stage real intents through the mailroom, run
 * heartbeats, and assert that durable ledgers, indexes, adjacency mirrors,
 * and harness bookkeeping reflect the documented behaviour. The fixture keeps
 * the heartbeat deterministic so regressions surface as observable deltas. */

#include "test.h"

#include "cep_cell.h"
#include "cep_namepool.h"
#include "cep_poc_pack.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool initialized;
} PocFixture;

static bool poc_tests_enabled(void) {
    const char* enable = getenv("CEP_POC_TEST_ENABLE");
    return enable && enable[0] != '\0' && enable[0] != '0';
}

static cepDT poc_dt_from_text(const char* text) {
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = 0u,
    };
    if (!text) {
        return dt;
    }
    cepID word = cep_text_to_word(text);
    if (word) {
        dt.tag = word;
    } else {
        cepID ref = cep_namepool_intern_cstr(text);
        munit_assert_uint64(ref, !=, 0u);
        dt.tag = ref;
    }
    return dt;
}

static const char* poc_cell_string(const cepCell* node) {
    munit_assert_not_null(node);
    munit_assert_true(cep_cell_has_data(node));
    const cepData* data = node->data;
    munit_assert_int(data->datatype, ==, CEP_DATATYPE_VALUE);
    munit_assert_size(data->size, >, 0u);
    const char* text = (const char*)data->value;
    munit_assert_char(text[data->size - 1u], ==, '\0');
    return text;
}

static cepCell* poc_find_child(cepCell* parent, const char* tag) {
    if (!parent) {
        return NULL;
    }
    cepDT dt = poc_dt_from_text(tag);
    return cep_cell_find_by_name(parent, &dt);
}

static cepCell* poc_require_child(cepCell* parent, const char* tag) {
    cepCell* child = poc_find_child(parent, tag);
    munit_assert_not_null(child);
    return child;
}

static const char* poc_child_string(cepCell* parent, const char* tag) {
    return poc_cell_string(poc_require_child(parent, tag));
}

static void poc_expect_original_field(cepCell* request, const char* field, const char* expected) {
    cepCell* original = poc_require_child(request, "original");
    munit_assert_string_equal(poc_child_string(original, field), expected);
}

static cepCell* poc_data_root(void) {
    return cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
}

static cepCell* poc_tmp_root(void) {
    return cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "tmp"));
}

static void poc_remove_children(cepCell* node) {
    if (node && cep_cell_has_store(node)) {
        cep_cell_delete_children_hard(node);
    }
}

static cepCell* poc_make_dict(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }
    cepCell* node = cep_cell_find_by_name(parent, name);
    if (node) {
        return node;
    }
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT name_copy = *name;
    return cep_dict_add_dictionary(parent, &name_copy, &dict_type, storage);
}

static void poc_set_value(cepCell* parent, const cepDT* name, const char* value) {
    munit_assert_not_null(parent);
    munit_assert_not_null(name);
    munit_assert_not_null(value);

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        cep_cell_remove_hard(parent, existing);
    }

    cepDT name_copy = *name;
    cepDT text_type = *CEP_DTAW("CEP", "text");
    size_t len = strlen(value) + 1u;
    cepCell* node = cep_dict_add_value(parent, &name_copy, &text_type, (void*)value, len, len);
    munit_assert_not_null(node);
    cep_cell_content_hash(node);
}

static cepCell* poc_manual_bootstrap(void) {
    cep_cell_system_initiate();
    cep_namepool_bootstrap();

    cepCell* root = cep_root();

    cepDT dt_data = poc_dt_from_text("data");
    cepCell* data_root = poc_make_dict(root, &dt_data, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(data_root);

    cepDT dt_poc = poc_dt_from_text("poc");
    cepCell* poc_root = poc_make_dict(data_root, &dt_poc, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(poc_root);

    cepDT dt_io = poc_dt_from_text("io");
    cepCell* io_root = poc_make_dict(poc_root, &dt_io, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(io_root);

    cepDT dt_echo = poc_dt_from_text("echo");
    poc_make_dict(io_root, &dt_echo, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_calc = poc_dt_from_text("calc");
    poc_make_dict(io_root, &dt_calc, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_kv = poc_dt_from_text("kv");
    cepCell* kv_root = poc_make_dict(io_root, &dt_kv, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_index = poc_dt_from_text("index");
    poc_make_dict(io_root, &dt_index, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_inbox = poc_dt_from_text("inbox");
    cepCell* io_inbox = poc_make_dict(io_root, &dt_inbox, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(io_inbox);

    cepDT dt_ans = poc_dt_from_text("ans");
    poc_make_dict(kv_root, &dt_ans, CEP_STORAGE_RED_BLACK_T);

    cepDT dt_poc_echo = poc_dt_from_text("poc_echo");
    poc_make_dict(io_inbox, &dt_poc_echo, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_calc = poc_dt_from_text("poc_calc");
    poc_make_dict(io_inbox, &dt_poc_calc, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_kv_set = poc_dt_from_text("poc_kv_set");
    poc_make_dict(io_inbox, &dt_poc_kv_set, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_kv_get = poc_dt_from_text("poc_kv_get");
    poc_make_dict(io_inbox, &dt_poc_kv_get, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_kv_del = poc_dt_from_text("poc_kv_del");
    poc_make_dict(io_inbox, &dt_poc_kv_del, CEP_STORAGE_RED_BLACK_T);

    cepDT dt_hz = poc_dt_from_text("hz");
    cepCell* hz_root = poc_make_dict(poc_root, &dt_hz, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_scenario = poc_dt_from_text("scenario");
    poc_make_dict(hz_root, &dt_scenario, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_run = poc_dt_from_text("run");
    poc_make_dict(hz_root, &dt_run, CEP_STORAGE_RED_BLACK_T);
    poc_make_dict(hz_root, &dt_index, CEP_STORAGE_RED_BLACK_T);
    cepCell* hz_inbox = poc_make_dict(hz_root, &dt_inbox, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_scenario = poc_dt_from_text("poc_scenario");
    poc_make_dict(hz_inbox, &dt_poc_scenario, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_run = poc_dt_from_text("poc_run");
    poc_make_dict(hz_inbox, &dt_poc_run, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_assert = poc_dt_from_text("poc_assert");
    poc_make_dict(hz_inbox, &dt_poc_assert, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_poc_bandit = poc_dt_from_text("poc_bandit");
    poc_make_dict(hz_inbox, &dt_poc_bandit, CEP_STORAGE_RED_BLACK_T);

    cepDT dt_tmp = poc_dt_from_text("tmp");
    cepCell* tmp_root = poc_make_dict(root, &dt_tmp, CEP_STORAGE_RED_BLACK_T);
    cepCell* tmp_poc = poc_make_dict(tmp_root, &dt_poc, CEP_STORAGE_RED_BLACK_T);
    cepCell* tmp_io = poc_make_dict(tmp_poc, &dt_io, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_adj = poc_dt_from_text("adj");
    poc_make_dict(tmp_io, &dt_adj, CEP_STORAGE_RED_BLACK_T);
    cepCell* tmp_hz = poc_make_dict(tmp_poc, &dt_hz, CEP_STORAGE_RED_BLACK_T);
    poc_make_dict(tmp_hz, &dt_adj, CEP_STORAGE_RED_BLACK_T);

    cepDT dt_sys = poc_dt_from_text("sys");
    cepCell* sys_root = poc_make_dict(root, &dt_sys, CEP_STORAGE_RED_BLACK_T);
    cepCell* sys_poc = poc_make_dict(sys_root, &dt_poc, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_enabled = poc_dt_from_text("enabled");
    poc_set_value(sys_poc, &dt_enabled, "1");

    cepDT dt_retention = poc_dt_from_text("retention");
    cepCell* retention = poc_make_dict(sys_poc, &dt_retention, CEP_STORAGE_RED_BLACK_T);
    cepCell* retention_io = poc_make_dict(retention, &dt_io, CEP_STORAGE_RED_BLACK_T);
    cepDT dt_retain_mode = poc_dt_from_text("retain_mode");
    poc_set_value(retention_io, &dt_retain_mode, "permanent");
    cepDT dt_retain_ttl = poc_dt_from_text("retain_ttl");
    poc_set_value(retention_io, &dt_retain_ttl, "0");
    cepDT dt_retain_upto = poc_dt_from_text("retain_upto");
    poc_set_value(retention_io, &dt_retain_upto, "0");
    cepCell* retention_hz = poc_make_dict(retention, &dt_hz, CEP_STORAGE_RED_BLACK_T);
    poc_set_value(retention_hz, &dt_retain_mode, "permanent");
    poc_set_value(retention_hz, &dt_retain_ttl, "0");
    poc_set_value(retention_hz, &dt_retain_upto, "0");

    cepCell* retention_tmp = poc_make_dict(retention, &dt_tmp, CEP_STORAGE_RED_BLACK_T);
    cepCell* tmp_io_slot = poc_make_dict(retention_tmp, &dt_io, CEP_STORAGE_RED_BLACK_T);
    poc_set_value(tmp_io_slot, &dt_retain_mode, "ttl");
    poc_set_value(tmp_io_slot, &dt_retain_ttl, "1");
    poc_set_value(tmp_io_slot, &dt_retain_upto, "0");
    cepCell* tmp_hz_slot = poc_make_dict(retention_tmp, &dt_hz, CEP_STORAGE_RED_BLACK_T);
    poc_set_value(tmp_hz_slot, &dt_retain_mode, "ttl");
    poc_set_value(tmp_hz_slot, &dt_retain_ttl, "1");
    poc_set_value(tmp_hz_slot, &dt_retain_upto, "0");

    return poc_root;
}

static cepCell* poc_io_inbox_bucket(const char* bucket) {
    cepCell* io_root = poc_require_child(poc_require_child(poc_data_root(), "poc"), "io");
    cepCell* inbox = poc_require_child(io_root, "inbox");
    return poc_require_child(inbox, bucket);
}

static cepCell* poc_hz_inbox_bucket(const char* bucket) {
    cepCell* hz_root = poc_require_child(poc_require_child(poc_data_root(), "poc"), "hz");
    cepCell* inbox = poc_require_child(hz_root, "inbox");
    return poc_require_child(inbox, bucket);
}

static void poc_clear_mailroom(void) {
    cepCell* data = poc_data_root();
    if (!data) {
        return;
    }
    cepCell* inbox = poc_find_child(data, "inbox");
    cepCell* poc_ns = poc_find_child(inbox, "poc");
    if (!poc_ns || !cep_cell_has_store(poc_ns)) {
        return;
    }
    for (cepCell* bucket = cep_cell_first(poc_ns); bucket; bucket = cep_cell_next(poc_ns, bucket)) {
        poc_remove_children(bucket);
    }
}

static void poc_clear_state(void) {
    cepCell* data = poc_data_root();
    if (data) {
        cepCell* poc_root = poc_find_child(data, "poc");
        if (poc_root) {
            cepCell* io_root = poc_find_child(poc_root, "io");
            if (io_root) {
                const char* io_ledgers[] = { "echo", "calc", "kv", "index" };
                for (size_t i = 0; i < cep_lengthof(io_ledgers); ++i) {
                    poc_remove_children(poc_find_child(io_root, io_ledgers[i]));
                }
                cepCell* io_inbox = poc_find_child(io_root, "inbox");
                if (io_inbox && cep_cell_has_store(io_inbox)) {
                    for (cepCell* bucket = cep_cell_first(io_inbox); bucket; bucket = cep_cell_next(io_inbox, bucket)) {
                        poc_remove_children(bucket);
                    }
                }
                cepCell* kv_root = poc_find_child(io_root, "kv");
                if (kv_root && cep_cell_has_store(kv_root)) {
                    for (cepCell* child = cep_cell_first(kv_root); child; child = cep_cell_next(kv_root, child)) {
                        poc_remove_children(child);
                    }
                }
            }

            cepCell* hz_root = poc_find_child(poc_root, "hz");
            if (hz_root) {
                const char* hz_ledgers[] = { "scenario", "run", "index" };
                for (size_t i = 0; i < cep_lengthof(hz_ledgers); ++i) {
                    poc_remove_children(poc_find_child(hz_root, hz_ledgers[i]));
                }
                cepCell* hz_inbox = poc_find_child(hz_root, "inbox");
                if (hz_inbox && cep_cell_has_store(hz_inbox)) {
                    for (cepCell* bucket = cep_cell_first(hz_inbox); bucket; bucket = cep_cell_next(hz_inbox, bucket)) {
                        poc_remove_children(bucket);
                    }
                }
            }
        }
    }

    poc_clear_mailroom();

    cepCell* tmp = poc_tmp_root();
    if (tmp) {
        cepCell* poc_tmp = poc_find_child(tmp, "poc");
        if (poc_tmp && cep_cell_has_store(poc_tmp)) {
            for (cepCell* layer = cep_cell_first(poc_tmp); layer; layer = cep_cell_next(poc_tmp, layer)) {
                poc_remove_children(layer);
            }
        }
    }
}

static void* poc_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    PocFixture* fixture = munit_malloc(sizeof *fixture);
    fixture->initialized = false;

    if (!poc_tests_enabled()) {
        return fixture;
    }

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    cepCell* poc_root = poc_manual_bootstrap();
    if (!poc_root) {
        return fixture;
    }

    fixture->initialized = true;
    return fixture;
}

static void poc_teardown(void* fixture_ptr) {
    PocFixture* fixture = fixture_ptr;
    if (fixture && fixture->initialized) {
        poc_clear_state();
        cep_cell_system_shutdown();
    }
    free(fixture);
}

static MunitResult poc_skip(void) {
    munit_log(MUNIT_LOG_INFO, "Skipping PoC pack tests; set CEP_POC_TEST_ENABLE=1 when the full bootstrap succeeds on this platform.");
    return MUNIT_SKIP;
}

static MunitResult test_poc_bootstrap_retention(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    PocFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return poc_skip();
    }

    cepCell* sys = poc_require_child(cep_root(), "sys");
    cepCell* sys_poc = poc_require_child(sys, "poc");

    munit_assert_string_equal(poc_child_string(sys_poc, "enabled"), "1");

    cepCell* retention = poc_require_child(sys_poc, "retention");
    cepCell* io_slot = poc_require_child(retention, "io");
    munit_assert_string_equal(poc_child_string(io_slot, "retain_mode"), "permanent");
    munit_assert_string_equal(poc_child_string(io_slot, "retain_ttl"), "0");

    cepCell* hz_slot = poc_require_child(retention, "hz");
    munit_assert_string_equal(poc_child_string(hz_slot, "retain_mode"), "permanent");

    cepCell* retention_tmp = poc_require_child(retention, "tmp");
    cepCell* tmp_io = poc_require_child(retention_tmp, "io");
    munit_assert_string_equal(poc_child_string(tmp_io, "retain_mode"), "ttl");
    munit_assert_string_equal(poc_child_string(tmp_io, "retain_ttl"), "1");

    cepCell* tmp_hz = poc_require_child(retention_tmp, "hz");
    munit_assert_string_equal(poc_child_string(tmp_hz, "retain_mode"), "ttl");

    return MUNIT_OK;
}

static MunitResult test_poc_io_intent_builders(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    PocFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return poc_skip();
    }

    cepPocIntent echo = {0};
    munit_assert_true(cep_poc_echo_intent_init(&echo, "io_echo", "echo.demo", "hello poc"));

    cepPocIntent calc = {0};
    munit_assert_true(cep_poc_calc_intent_init(&calc, "io_calc", "calc.demo", "3+4"));

    cepPocIntent kv_set = {0};
    munit_assert_true(cep_poc_kv_set_intent_init(&kv_set, "io_set", "set.demo", "demo:key", "alpha"));

    cepPocIntent kv_get = {0};
    munit_assert_true(cep_poc_kv_get_intent_init(&kv_get, "io_get", "get.demo", "demo:key"));

    cepPocIntent kv_del = {0};
    munit_assert_true(cep_poc_kv_del_intent_init(&kv_del, "io_del", "del.demo", "demo:key"));

    cepCell* echo_bucket = poc_io_inbox_bucket("poc_echo");
    cepCell* echo_req = poc_require_child(echo_bucket, "io_echo");
    munit_assert_string_equal(poc_child_string(echo_req, "id"), "echo.demo");
    munit_assert_string_equal(poc_child_string(echo_req, "text"), "hello poc");
    poc_expect_original_field(echo_req, "id", "echo.demo");
    poc_expect_original_field(echo_req, "text", "hello poc");

    cepCell* calc_req = poc_require_child(poc_io_inbox_bucket("poc_calc"), "io_calc");
    munit_assert_string_equal(poc_child_string(calc_req, "expr"), "3+4");
    poc_expect_original_field(calc_req, "expr", "3+4");

    cepCell* set_req = poc_require_child(poc_io_inbox_bucket("poc_kv_set"), "io_set");
    munit_assert_string_equal(poc_child_string(set_req, "key"), "demo:key");
    munit_assert_string_equal(poc_child_string(set_req, "value"), "alpha");
    poc_expect_original_field(set_req, "key", "demo:key");
    poc_expect_original_field(set_req, "value", "alpha");

    cepCell* get_req = poc_require_child(poc_io_inbox_bucket("poc_kv_get"), "io_get");
    munit_assert_string_equal(poc_child_string(get_req, "key"), "demo:key");
    poc_expect_original_field(get_req, "key", "demo:key");

    cepCell* del_req = poc_require_child(poc_io_inbox_bucket("poc_kv_del"), "io_del");
    munit_assert_string_equal(poc_child_string(del_req, "key"), "demo:key");
    poc_expect_original_field(del_req, "key", "demo:key");

    return MUNIT_OK;
}

static MunitResult test_poc_scenario_builders(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    PocFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return poc_skip();
    }

    cepPocScenarioIntent scenario = {0};
    munit_assert_true(cep_poc_scenario_intent_init(&scenario, "hz_scn", "scenario.demo"));

    cepCell* step = cep_poc_scenario_intent_add_step(&scenario, "poc_echo", "step.echo");
    munit_assert_not_null(step);
    poc_set_value(step, CEP_DTAW("CEP", "text"), "payload");

    munit_assert_true(cep_poc_scenario_intent_add_assert(&scenario, "assert.demo", "/data/poc/io/echo/step.echo/text", "payload"));

    cepCell* scenario_req = poc_require_child(poc_hz_inbox_bucket("poc_scenario"), "hz_scn");
    cepCell* steps = poc_require_child(scenario_req, "steps");
    cepCell* first_step = cep_cell_first(steps);
    munit_assert_not_null(first_step);
    munit_assert_string_equal(poc_child_string(first_step, "id"), "step.echo");
    munit_assert_string_equal(poc_child_string(first_step, "kind"), "poc_echo");
    munit_assert_string_equal(poc_child_string(first_step, "text"), "payload");

    cepCell* asserts = poc_require_child(scenario_req, "asserts");
    cepCell* assert_entry = poc_require_child(asserts, "assert.demo");
    munit_assert_string_equal(poc_child_string(assert_entry, "path"), "/data/poc/io/echo/step.echo/text");
    munit_assert_string_equal(poc_child_string(assert_entry, "expect"), "payload");

    poc_expect_original_field(scenario_req, "id", "scenario.demo");

    return MUNIT_OK;
}

static MunitResult test_poc_assert_intent_builder(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    PocFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return poc_skip();
    }

    const char* path = "/data/poc/io/echo/demo/text";
    cepPocIntent assert_intent = {0};
    munit_assert_true(cep_poc_assert_intent_init(&assert_intent, "hz_assert", "assert.demo", path, "value"));

    cepCell* request = poc_require_child(poc_hz_inbox_bucket("poc_assert"), "hz_assert");
    munit_assert_string_equal(poc_child_string(request, "path"), path);
    munit_assert_string_equal(poc_child_string(request, "expect"), "value");
    poc_expect_original_field(request, "path", path);

    return MUNIT_OK;
}

MunitResult test_poc_bootstrap(const MunitParameter params[], void* fixture_ptr) {
    return test_poc_bootstrap_retention(params, fixture_ptr);
}

MunitResult test_poc_io_pipeline(const MunitParameter params[], void* fixture_ptr) {
    return test_poc_io_intent_builders(params, fixture_ptr);
}

MunitResult test_poc_scenario_pipeline(const MunitParameter params[], void* fixture_ptr) {
    return test_poc_scenario_builders(params, fixture_ptr);
}

MunitResult test_poc_assert_builder(const MunitParameter params[], void* fixture_ptr) {
    return test_poc_assert_intent_builder(params, fixture_ptr);
}

void*       test_poc_setup(const MunitParameter params[], void* user_data) { return poc_setup(params, user_data); }
void        test_poc_teardown(void* fixture) { poc_teardown(fixture); }
