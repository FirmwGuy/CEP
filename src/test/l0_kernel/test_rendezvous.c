/* Rendezvous integration tests validate ledger defaults, heartbeat staging,
 * and completion routing into the flow inbox. */

#include "test.h"

#include "cep_l0.h"
#include "cep_rendezvous.h"
#include "cep_enzyme.h"
#include "cep_namepool.h"

#include <stdio.h>

#include <inttypes.h>
#include <string.h>

static cepDT rv_dt_from_text(const char* tag) {
    cepID id = cep_text_to_word(tag);
    if (!id) {
        id = cep_namepool_intern(tag, strlen(tag));
    }
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = id,
    };
    return dt;
}

static cepCell* rv_ledger(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);
    cepDT ledger_dt = rv_dt_from_text("rv");
    cepCell* ledger = cep_cell_find_by_name(data_root, &ledger_dt);
    munit_assert_not_null(ledger);
    return ledger;
}

static const char* rv_entry_text(cepCell* entry, const char* tag_text) {
    cepDT field = rv_dt_from_text(tag_text);
    cepCell* node = cep_cell_find_by_name(entry, &field);
    if (!node) {
        return NULL;
    }
    munit_assert_true(cep_cell_has_data(node));
    return (const char*)cep_cell_data(node);
}

static cepCell* rv_flow_event(const cepDT* key_dt) {
    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepCell* inbox = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "inbox"));
    if (!inbox) {
        return NULL;
    }
    cepCell* flow = cep_cell_find_by_name(inbox, CEP_DTAW("CEP", "flow"));
    if (!flow) {
        return NULL;
    }
    cepCell* inst = cep_cell_find_by_name(flow, CEP_DTAW("CEP", "inst_event"));
    if (!inst) {
        return NULL;
    }
    return cep_cell_find_by_name(inst, key_dt);
}

static void rv_configure_runtime(void) {
    if (cep_cell_system_initialized()) {
        test_runtime_shutdown();
    }
    printf("rv_configure_runtime: begin\n"); fflush(stdout);
    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_true(cep_rendezvous_register(registry));
    munit_assert_true(cep_heartbeat_begin(policy.start_at));
    cepID debug_prof = cep_namepool_intern("rv-fixed", strlen("rv-fixed"));
    printf("bootstrap intern rv-fixed -> %llu\n", (unsigned long long)debug_prof); fflush(stdout);
    printf("rv_configure_runtime: done\n"); fflush(stdout);
}

static void rv_spawn_basic(const char* key_text, uint64_t due) {
    printf("rv_spawn_basic: key=%s due=%llu\n", key_text, (unsigned long long)due); fflush(stdout);
    cepRvSpec spec = {0};
    spec.key_dt = rv_dt_from_text(key_text);
    printf("key tag value=%llu\n", (unsigned long long)spec.key_dt.tag); fflush(stdout);
    spec.prof = rv_dt_from_text("rv-fixed").tag;
    printf("prof tag value=%llu\n", (unsigned long long)spec.prof); fflush(stdout);
    spec.due = due;
    munit_assert_true(cep_rv_spawn(&spec, spec.key_dt.tag));
    printf("rv_spawn_basic: spawn complete\n"); fflush(stdout);
}

MunitResult test_rendezvous_defaults(const MunitParameter params[], void* fixture) {
    (void)fixture;
    test_boot_cycle_prepare(params);

    rv_configure_runtime();
    munit_assert_not_null(cep_heartbeat_data_root());
    rv_spawn_basic("defaults", 5u);

    cepDT defaults_key = rv_dt_from_text("defaults");
    if (!cep_id(defaults_key.domain)) {
        defaults_key.domain = CEP_ACRO("CEP");
    }
    cepCell* entry = cep_cell_find_by_name(rv_ledger(), &defaults_key);
    munit_assert_not_null(entry);

    munit_assert_string_equal(rv_entry_text(entry, "state"), "pending");
    munit_assert_string_equal(rv_entry_text(entry, "prof"), "rv-fixed");
    munit_assert_string_equal(rv_entry_text(entry, "on_miss"), "timeout");
    munit_assert_string_equal(rv_entry_text(entry, "kill_mode"), "none");
    munit_assert_string_equal(rv_entry_text(entry, "cas_hash"), "");
    munit_assert_string_equal(rv_entry_text(entry, "grace_used"), "0");

    test_runtime_shutdown();
    return MUNIT_OK;
}

static void rv_step_beats(unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        munit_assert_true(cep_heartbeat_step());
    }
}

MunitResult test_rendezvous_heartbeat_pipeline(const MunitParameter params[], void* fixture) {
    (void)fixture;
    test_boot_cycle_prepare(params);

    rv_configure_runtime();
    rv_spawn_basic("pipeline", 0u);

    rv_step_beats(1u);

    cepDT key_dt = rv_dt_from_text("pipeline");
    if (!cep_id(key_dt.domain)) {
        key_dt.domain = CEP_ACRO("CEP");
    }
    cepCell* entry = cep_cell_find_by_name(rv_ledger(), &key_dt);
    munit_assert_not_null(entry);
    munit_assert_string_equal(rv_entry_text(entry, "state"), "pending");

    rv_step_beats(1u);
    munit_assert_string_equal(rv_entry_text(entry, "state"), "ready");

    cepDT telemetry_name = rv_dt_from_text("telemetry");
    cepDT telemetry_type = *CEP_DTAW("CEP", "dictionary");
    cepCell telemetry = {0};
    cep_cell_initialize_dictionary(&telemetry, &telemetry_name, &telemetry_type, CEP_STORAGE_RED_BLACK_T);

    cepDT sample_name = rv_dt_from_text("ticks");
    uint64_t value = 7u;
    cepCell* sample = cep_dict_add_value(&telemetry, &sample_name, CEP_DTAW("CEP", "value"), &value, sizeof value, sizeof value);
    munit_assert_not_null(sample);

    munit_assert_true(cep_rv_report(key_dt.tag, &telemetry));
    cep_cell_finalize(&telemetry);

    rv_step_beats(1u);

    cepCell* flow_event = rv_flow_event(&key_dt);
    munit_assert_not_null(flow_event);
    munit_assert_string_equal(rv_entry_text(flow_event, "outcome"), "applied");

    cepCell* flow_telemetry = cep_cell_find_by_name(flow_event, CEP_DTAW("CEP", "telemetry"));
    munit_assert_not_null(flow_telemetry);
    cepCell* copied = cep_cell_find_by_name(flow_telemetry, &sample_name);
    munit_assert_not_null(copied);
    munit_assert_true(cep_cell_has_data(copied));
    munit_assert_uint64(*(const uint64_t*)cep_cell_data(copied), ==, value);

    test_runtime_shutdown();
    return MUNIT_OK;
}

MunitResult test_rendezvous_kill_and_timeout(const MunitParameter params[], void* fixture) {
    (void)fixture;
    test_boot_cycle_prepare(params);

    rv_configure_runtime();
    rv_spawn_basic("miss", 0u);

    cepDT key_dt = rv_dt_from_text("miss");
    if (!cep_id(key_dt.domain)) {
        key_dt.domain = CEP_ACRO("CEP");
    }

    /* Trigger an immediate kill event. */
    munit_assert_true(cep_rv_kill(key_dt.tag, CEP_WORD("kill"), 0u));
    rv_step_beats(1u);

    cepCell* entry = cep_cell_find_by_name(rv_ledger(), &key_dt);
    munit_assert_not_null(entry);
    munit_assert_string_equal(rv_entry_text(entry, "state"), "killed");

    cepCell* kill_event = rv_flow_event(&key_dt);
    munit_assert_not_null(kill_event);
    munit_assert_string_equal(rv_entry_text(kill_event, "outcome"), "killed");

    /* Spawn again with a grace window and let it time out. */
    cepRvSpec spec = {0};
    spec.key_dt = key_dt;
    spec.prof = rv_dt_from_text("rv-fixed").tag;
    printf("prof tag value=%llu\n", (unsigned long long)spec.prof); fflush(stdout);
    spec.due = 0u;
    spec.grace_delta = 1u;
    spec.max_grace = 1u;
    spec.on_miss = CEP_WORD("timeout");
    munit_assert_true(cep_rv_spawn(&spec, spec.key_dt.tag));

    rv_step_beats(2u);

    entry = cep_cell_find_by_name(rv_ledger(), &key_dt);
    munit_assert_not_null(entry);
    munit_assert_string_equal(rv_entry_text(entry, "state"), "timeout");

    cepCell* timeout_event = rv_flow_event(&key_dt);
    munit_assert_not_null(timeout_event);
    munit_assert_string_equal(rv_entry_text(timeout_event, "outcome"), "timeout");

    test_runtime_shutdown();
    return MUNIT_OK;
}
