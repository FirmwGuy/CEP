/* Rendezvous integration tests exercise the heartbeat-driven bootstrap,
 * ledger lifecycle, and control helpers so the suite can verify that
 * init/shutdown signals wire the subsystem the same way production beats do.
 */

#include "test.h"

#include "cep_namepool.h"
#include "cep_rendezvous.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    bool initialized;
} RendezvousFixture;

static cepDT rv_make_dt(const char* tag_text) {
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = cep_namepool_intern_cstr(tag_text),
    };
    return dt;
}

static void rv_force_root_directories(void) {
    cepCell* root = cep_root();
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");

    const cepDT* required[] = {
        CEP_DTAW("CEP", "sys"),
        CEP_DTAW("CEP", "rt"),
        CEP_DTAW("CEP", "journal"),
        CEP_DTAW("CEP", "env"),
        CEP_DTAW("CEP", "cas"),
        CEP_DTAW("CEP", "lib"),
        CEP_DTAW("CEP", "data"),
        CEP_DTAW("CEP", "enzymes"),
    };

    for (size_t i = 0; i < sizeof required / sizeof required[0]; ++i) {
        cepDT name_copy = *required[i];
        if (!cep_cell_find_by_name(root, &name_copy)) {
            cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        }
    }

    cepDT tmp_name = *CEP_DTAW("CEP", "tmp");
    if (!cep_cell_find_by_name(root, &tmp_name)) {
        cepDT list_type = *CEP_DTAW("CEP", "list");
        cepDT name_copy = tmp_name;
        cep_dict_add_list(root, &name_copy, &list_type, CEP_STORAGE_LINKED_LIST);
    }

    cepCell* sys = cep_cell_find_by_name(root, CEP_DTAW("CEP", "sys"));
    if (sys) {
        cepDT err_name = *CEP_DTAW("CEP", "err_cat");
        if (!cep_cell_find_by_name(sys, &err_name)) {
            cepDT name_copy = err_name;
            cep_dict_add_dictionary(sys, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        }
    }
}

static cepCell* rv_ledger(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return NULL;
    }
    return cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "rv"));
}

static void rv_clear_entries(void) {
    cepCell* ledger = rv_ledger();
    if (!ledger || !cep_cell_has_store(ledger)) {
        return;
    }

    for (cepCell* entry = cep_cell_first(ledger); entry;) {
        cepCell* next = cep_cell_next(ledger, entry);
        cep_cell_remove_hard(ledger, entry);
        entry = next;
    }
}

static const char* rv_field_string(cepCell* entry, const cepDT* name) {
    cepCell* node = cep_cell_find_by_name(entry, name);
    if (!node || !cep_cell_has_data(node)) {
        return NULL;
    }
    const cepData* data = node->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return NULL;
    }
    return (const char*)data->value;
}

static uint64_t rv_field_u64(cepCell* entry, const cepDT* name) {
    const char* text = rv_field_string(entry, name);
    return text ? (uint64_t)strtoull(text, NULL, 10) : 0u;
}

static cepCell* rv_entry(const cepDT* key_dt) {
    cepCell* ledger = rv_ledger();
    if (!ledger) {
        return NULL;
    }
    return cep_cell_find_by_name(ledger, key_dt);
}

void* rendezvous_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    if (cep_cell_system_initialized()) {
        cep_heartbeat_shutdown();
        cep_cell_system_shutdown();
    }

    cep_cell_system_initiate();
    rv_force_root_directories();
    munit_assert_true(cep_namepool_bootstrap());

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_begin(policy.start_at));
    munit_assert_true(cep_rv_bootstrap());
    munit_assert_true(cep_heartbeat_step());

    rv_clear_entries();

    RendezvousFixture* fixture = munit_malloc(sizeof *fixture);
    fixture->initialized = true;
    return fixture;
}

void rendezvous_teardown(void* fixture_ptr) {
    RendezvousFixture* fixture = fixture_ptr;
    if (fixture && fixture->initialized) {
        rv_clear_entries();
        test_runtime_shutdown();
        cep_cell_system_shutdown();
    }
    free(fixture);
}

MunitResult test_rendezvous_capture_commit(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    RendezvousFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return MUNIT_SKIP;
    }

    rv_clear_entries();

    cepRvSpec spec = {0};
    spec.key_dt = rv_make_dt("rv.cap");
    spec.instance_dt = rv_make_dt("inst.cap");
    spec.signal_path = "CEP:sig_rv/cap";
    spec.due = (uint64_t)(cep_heartbeat_current() + 1u);

    cepID key = spec.key_dt.tag;
    munit_assert_true(cep_rv_spawn(&spec, key));
    munit_assert_int(cep_rv_last_spawn_status(), ==, CEP_RV_SPAWN_STATUS_OK);

    uint64_t start = cep_heartbeat_current();
    munit_assert_true(cep_heartbeat_step());

    cepCell* entry = rv_entry(&spec.key_dt);
    munit_assert_not_null(entry);
    const char* state = rv_field_string(entry, CEP_DTAW("CEP", "state"));
    munit_assert_not_null(state);
    munit_assert_string_equal(state, "pending");

    uint64_t expected_ready = start + 1u;
    munit_assert_true(cep_heartbeat_step());

    entry = rv_entry(&spec.key_dt);
    munit_assert_not_null(entry);
    state = rv_field_string(entry, CEP_DTAW("CEP", "state"));
    munit_assert_not_null(state);
    munit_assert_string_equal(state, "ready");
    munit_assert_uint64(rv_field_u64(entry, CEP_DTAW("CEP", "ready_beat")), ==, expected_ready);

    return MUNIT_OK;
}

MunitResult test_rendezvous_policies(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    RendezvousFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return MUNIT_SKIP;
    }

    rv_clear_entries();

    uint64_t start = cep_heartbeat_current();

    cepRvSpec spec = {0};
    spec.key_dt = rv_make_dt("rv.pol");
    spec.instance_dt = rv_make_dt("inst.pol");
    spec.signal_path = "CEP:sig_rv/policy";
    spec.due = (start > 0u) ? (start - 1u) : 0u;
    spec.on_miss = CEP_WORD("grace");
    spec.grace_delta = 2u;
    spec.max_grace = 2u;

    munit_assert_true(cep_rv_spawn(&spec, spec.key_dt.tag));

    munit_assert_true(cep_heartbeat_step());

    cepCell* entry = rv_entry(&spec.key_dt);
    munit_assert_not_null(entry);
    const char* state = rv_field_string(entry, CEP_DTAW("CEP", "state"));
    munit_assert_not_null(state);
    munit_assert_string_equal(state, "pending");

    uint64_t due = rv_field_u64(entry, CEP_DTAW("CEP", "due"));
    munit_assert_uint64(due, ==, spec.due + spec.grace_delta);
    munit_assert_uint64(rv_field_u64(entry, CEP_DTAW("CEP", "grace_used")), ==, 1u);

    uint64_t expected_ready = due;
    munit_assert_true(cep_heartbeat_step());

    entry = rv_entry(&spec.key_dt);
    munit_assert_not_null(entry);
    state = rv_field_string(entry, CEP_DTAW("CEP", "state"));
    munit_assert_not_null(state);
    munit_assert_string_equal(state, "ready");
    munit_assert_uint64(rv_field_u64(entry, CEP_DTAW("CEP", "ready_beat")), ==, expected_ready);

    return MUNIT_OK;
}

MunitResult test_rendezvous_controls(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    RendezvousFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return MUNIT_SKIP;
    }

    rv_clear_entries();

    cepRvSpec spec = {0};
    spec.key_dt = rv_make_dt("rv.control");
    spec.instance_dt = rv_make_dt("inst.control");
    spec.signal_path = "CEP:sig_rv/control";
    spec.due = (uint64_t)(cep_heartbeat_current() + 1u);

    cepID key = spec.key_dt.tag;
    munit_assert_true(cep_rv_spawn(&spec, key));

    munit_assert_true(cep_rv_resched(key, 3u));
    cepCell* entry = rv_entry(&spec.key_dt);
    munit_assert_not_null(entry);
    munit_assert_uint64(rv_field_u64(entry, CEP_DTAW("CEP", "due")), ==, spec.due + 3u);

    munit_assert_true(cep_rv_kill(key, CEP_WORD("kill"), 2u));
    entry = rv_entry(&spec.key_dt);
    munit_assert_not_null(entry);
    const char* state = rv_field_string(entry, CEP_DTAW("CEP", "state"));
    munit_assert_not_null(state);
    munit_assert_string_equal(state, "killed");
    munit_assert_string_equal(rv_field_string(entry, CEP_DTAW("CEP", "kill_mode")), "kill");
    munit_assert_uint64(rv_field_u64(entry, CEP_DTAW("CEP", "kill_wait")), ==, 2u);

    munit_assert_true(cep_heartbeat_step());

    entry = rv_entry(&spec.key_dt);
    munit_assert_not_null(entry);
    state = rv_field_string(entry, CEP_DTAW("CEP", "state"));
    munit_assert_not_null(state);
    munit_assert_string_equal(state, "killed");

    return MUNIT_OK;
}

static MunitTest rendezvous_tests[] = {
    {
        "/rendezvous/capture_commit",
        test_rendezvous_capture_commit,
        rendezvous_setup,
        rendezvous_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/rendezvous/policies",
        test_rendezvous_policies,
        rendezvous_setup,
        rendezvous_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/rendezvous/controls",
        test_rendezvous_controls,
        rendezvous_setup,
        rendezvous_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    { NULL, NULL, NULL, NULL, 0, NULL },
};

const MunitSuite rendezvous_suite = {
    .prefix = "/CEP",
    .tests = rendezvous_tests,
    .suites = NULL,
    .iterations = 1,
    .options = MUNIT_SUITE_OPTION_NONE,
};
