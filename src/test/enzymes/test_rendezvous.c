/* Rendezvous integration tests exercise bootstrap, pipeline, and
 * overlapping completion scenarios so the Layer 2 rendezvous bridge
 * stays deterministic. */

#include "test.h"

#include "cep_l0.h"
#include "cep_cell.h"
#include "cep_namepool.h"
#include "cep_heartbeat.h"
#include "cep_l1_coherence.h"
#include "cep_l2_flows.h"
#include "cep_rendezvous.h"

#include <string.h>

static void rendezvous_prepare_runtime(const MunitParameter params[], bool start_heartbeat) {
    test_boot_cycle_prepare(params);

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_l1_coherence_bootstrap());
    munit_assert_true(cep_l2_flows_bootstrap());

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    munit_assert_true(cep_l1_coherence_register(registry));
    munit_assert_true(cep_l2_flows_register(registry));
    munit_assert_true(cep_rv_bootstrap());

    if (start_heartbeat) {
        munit_assert_true(cep_heartbeat_begin(0));
    }
}

static void rendezvous_shutdown_runtime(void) {
    test_runtime_shutdown();
}

static cepCell* rendezvous_ledger(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepDT ledger_dt = cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("rv"));
    ledger_dt.glob = 0u;
    cepCell* ledger = cep_cell_find_by_name(data_root, &ledger_dt);
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

    rendezvous_prepare_runtime(params, /*start_heartbeat=*/false);

    for (size_t cycle = 0; cycle < 5u; ++cycle) {
        munit_assert_true(cep_rv_bootstrap());
        cepCell* ledger = rendezvous_ledger();
        munit_assert_true(cep_cell_has_store(ledger));
    }

    rendezvous_shutdown_runtime();
    return MUNIT_OK;
}

MunitResult test_rendezvous_pipeline(const MunitParameter params[], void* fixture) {
    (void)fixture;

    rendezvous_prepare_runtime(params, /*start_heartbeat=*/true);

    bool scan_ok = cep_rv_capture_scan();
    munit_logf(MUNIT_LOG_INFO, "rv_capture_scan=%d", (int)scan_ok);
    bool commit_ok = scan_ok ? cep_rv_commit_apply() : false;
    munit_logf(MUNIT_LOG_INFO, "rv_commit_apply=%d", (int)commit_ok);
    bool step_ok = commit_ok ? cep_heartbeat_step() : false;
    munit_logf(MUNIT_LOG_INFO, "heartbeat_step=%d", (int)step_ok);

    munit_assert_true(scan_ok);
    munit_assert_true(commit_ok);
    munit_assert_true(step_ok);

    rendezvous_shutdown_runtime();
    return MUNIT_OK;
}

MunitResult test_rendezvous_parallel(const MunitParameter params[], void* fixture) {
    (void)fixture;

    rendezvous_prepare_runtime(params, /*start_heartbeat=*/true);

    const char* keys[] = { "rv_parallel_a", "rv_parallel_b", "rv_parallel_c" };
    const char* profiles[] = { "rv-fixed", "rv-fixed", "rv-fixed" };
    const cepBeatNumber dues[] = { 3u, 4u, 5u };
    cepID key_ids[3] = {0};

    for (size_t i = 0; i < 3u; ++i) {
        key_ids[i] = rendezvous_spawn_request(keys[i], profiles[i], dues[i]);
    }

    for (size_t beat = 0; beat < 12u; ++beat) {
        munit_assert_true(cep_rv_capture_scan());
        munit_assert_true(cep_rv_commit_apply());
        munit_assert_true(cep_heartbeat_step());
    }

    cepCell* ledger = rendezvous_ledger();
    size_t matched = 0u;
    for (cepCell* entry = cep_cell_first(ledger); entry; entry = cep_cell_next(ledger, entry)) {
        if (!cep_cell_is_normal(entry)) {
            continue;
        }

        const cepDT* name = cep_cell_get_name(entry);
        munit_assert_not_null(name);

        for (size_t i = 0; i < 3u; ++i) {
            if (name->tag == key_ids[i]) {
                ++matched;
                break;
            }
        }
    }
    munit_assert_size(matched, ==, 3u);

    rendezvous_shutdown_runtime();
    return MUNIT_OK;
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
