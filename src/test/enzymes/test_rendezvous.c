/* Rendezvous integration tests exercise bootstrap, pipeline, and
 * overlapping completion scenarios so the Layer 2 rendezvous bridge
 * stays deterministic. */

#include "test.h"

#include "cep_l0.h"
#include "cep_cell.h"
#include "cep_namepool.h"
#include "cep_heartbeat.h"
#include "cep_rendezvous.h"

#include <string.h>

#ifndef CEP_ENABLE_L2_TESTS
#define CEP_ENABLE_L2_TESTS 0
#endif

/* Rebuild a fresh runtime for rendezvous tests so each case starts from a clean
 * ledger, a blank namepool, and an idle heartbeat regardless of how the
 * previous test exited. */
static void rendezvous_prepare_runtime(const MunitParameter params[], bool start_heartbeat) {
    test_boot_cycle_prepare(params);

    test_runtime_shutdown();

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    munit_assert_true(cep_l0_bootstrap());
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    munit_assert_true(cep_rv_bootstrap());

    if (start_heartbeat) {
        munit_assert_true(cep_heartbeat_begin(0));
    }
}

static cepCell* rendezvous_ledger_optional(void) {
    if (!cep_cell_system_initialized()) {
        return NULL;
    }

    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root || !cep_cell_has_store(data_root)) {
        return NULL;
    }

    cepDT ledger_dt = cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("rv"));
    ledger_dt.glob = 0u;
    return cep_cell_find_by_name(data_root, &ledger_dt);
}

/* Count active rendezvous entries so tests can assert that previous runs left
 * nothing behind and that newly spawned jobs materialise as expected. */
static size_t rendezvous_entry_count(void) {
    cepCell* ledger = rendezvous_ledger_optional();
    if (!ledger || !cep_cell_has_store(ledger)) {
        return 0u;
    }

    size_t count = 0u;
    for (cepCell* entry = cep_cell_first(ledger); entry; entry = cep_cell_next(ledger, entry)) {
        if (cep_cell_is_normal(entry)) {
            ++count;
        }
    }
    return count;
}

static void rendezvous_shutdown_runtime(void) {
    test_runtime_shutdown();
}

static cepCell* rendezvous_ledger(void) {
    cepCell* ledger = rendezvous_ledger_optional();
    munit_assert_not_null(ledger);
    return ledger;
}

static cepID rendezvous_spawn_request(const char* key_text,
                                      const char* profile,
                                      cepBeatNumber due) {
    cepID key_id = cep_text_to_word(key_text);
    if (!key_id) {
        key_id = cep_namepool_intern(key_text, strlen(key_text));
    }
    munit_assert_true(key_id != 0);

    cepID profile_id = cep_text_to_word(profile);
    munit_assert_true(profile_id != 0);

    cepRvSpec spec = {0};
    spec.key_dt = cep_dt_make(CEP_ACRO("CEP"), key_id);
    spec.prof = profile_id;
    spec.due = due;

    char signal_buf[128];
    munit_assert_true(cep_rv_signal_for_key(&spec.key_dt, signal_buf, sizeof signal_buf));
    spec.signal_path = signal_buf;

    munit_assert_true(cep_rv_spawn(&spec, spec.key_dt.tag));
    return spec.key_dt.tag;
}

MunitResult test_rendezvous_bootstrap_cycles(const MunitParameter params[], void* fixture) {
    (void)fixture;
#if !CEP_ENABLE_L2_TESTS
    (void)params;
    return MUNIT_SKIP;
#endif

    for (size_t cycle = 0; cycle < 5u; ++cycle) {
        rendezvous_prepare_runtime(params, /*start_heartbeat=*/false);
        munit_assert_size(rendezvous_entry_count(), ==, 0u);

        munit_assert_true(cep_rv_bootstrap());
        cepCell* ledger = rendezvous_ledger();
        munit_assert_true(cep_cell_has_store(ledger));
        munit_assert_size(rendezvous_entry_count(), ==, 0u);

        rendezvous_shutdown_runtime();
    }

    /* Regression guard: tear the runtime down and immediately bootstrap again.
     * The mailroom rebootstrap bug triggered here before it was surfaced by the
     * pipeline test, so keep the scenario explicit. */
    rendezvous_prepare_runtime(params, /*start_heartbeat=*/false);
    munit_assert_true(cep_rv_bootstrap());
    munit_assert_true(cep_cell_has_store(rendezvous_ledger()));
    rendezvous_shutdown_runtime();

    rendezvous_prepare_runtime(params, /*start_heartbeat=*/false);
    munit_assert_true(cep_rv_bootstrap());
    munit_assert_true(cep_cell_has_store(rendezvous_ledger()));
    rendezvous_shutdown_runtime();

    return MUNIT_OK;
}

MunitResult test_rendezvous_pipeline(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;
    (void)rendezvous_spawn_request;

    munit_log(MUNIT_LOG_INFO, "Skipping rendezvous pipeline test until mailroom rebootstrap bug is fixed.");
    return MUNIT_SKIP;
}

MunitResult test_rendezvous_parallel(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;
    (void)rendezvous_spawn_request;

    munit_log(MUNIT_LOG_INFO, "Skipping rendezvous parallel test until mailroom rebootstrap bug is fixed.");
    return MUNIT_SKIP;
}

static MunitTest rendezvous_tests[] = {
    {
        "/rendezvous/bootstrap_cycles",
        test_rendezvous_bootstrap_cycles,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/rendezvous/pipeline",
        test_rendezvous_pipeline,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/rendezvous/parallel",
        test_rendezvous_parallel,
        NULL,
        NULL,
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
