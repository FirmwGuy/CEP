/* Layer 2 flow acceptance tests exercise the bootstrap helpers, ingest
 * canonicalisation, VM stepping, telemetry capture, and retention/archival
 * paths. The suite spins a real heartbeat so we observe agenda ordering and
 * ledger mutations exactly as production would see them. */

#include "test.h"

#include "cep_cell.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_l2_flows.h"
#include "cep_namepool.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    bool initialized;
} L2Fixture;

static cepDT l2_name_dt(const char* tag) {
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = 0u,
    };
    cepID word = cep_text_to_word(tag);
    if (word) {
        dt.tag = word;
    } else {
        cepID ref = cep_namepool_intern_cstr(tag);
        munit_assert_uint64(ref, !=, 0u);
        dt.tag = ref;
    }
    return dt;
}

static cepCell* l2_flow_root(void) {
    cepCell* data = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    munit_assert_not_null(data);
    cepCell* flow = cep_cell_find_by_name(data, CEP_DTAW("CEP", "flow"));
    munit_assert_not_null(flow);
    return flow;
}

static cepCell* l2_ledger(const char* name) {
    cepCell* flow = l2_flow_root();
    cepDT name_dt = l2_name_dt(name);
    cepCell* ledger = cep_cell_find_by_name(flow, &name_dt);
    munit_assert_not_null(ledger);
    return ledger;
}

static cepCell* l2_inbox_bucket(const char* bucket_name) {
    cepCell* flow = l2_flow_root();
    cepCell* inbox = cep_cell_find_by_name(flow, CEP_DTAW("CEP", "inbox"));
    munit_assert_not_null(inbox);
    cepDT dt = l2_name_dt(bucket_name);
    cepCell* bucket = cep_cell_find_by_name(inbox, &dt);
    munit_assert_not_null(bucket);
    return bucket;
}

static cepCell* l2_tmp_adj(void) {
    cepCell* tmp = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "tmp"));
    munit_assert_not_null(tmp);
    cepCell* flow_tmp = cep_cell_find_by_name(tmp, CEP_DTAW("CEP", "flow"));
    munit_assert_not_null(flow_tmp);
    cepCell* adj = cep_cell_find_by_name(flow_tmp, CEP_DTAW("CEP", "adj"));
    munit_assert_not_null(adj);
    return adj;
}

static void l2_remove_children(cepCell* node) {
    if (node && cep_cell_has_store(node)) {
        cep_cell_delete_children_hard(node);
    }
}

static void l2_clear_state(void) {
    cepCell* flow = l2_flow_root();
    const char* ledgers[] = {
        "program", "policy", "variant", "guardian",
        "niche", "instance", "decision", "dec_archive",
        "index"
    };
    for (size_t i = 0; i < cep_lengthof(ledgers); ++i) {
        cepDT ledger_dt = l2_name_dt(ledgers[i]);
        cepCell* ledger = cep_cell_find_by_name(flow, &ledger_dt);
        l2_remove_children(ledger);
    }

    cepCell* inbox = cep_cell_find_by_name(flow, CEP_DTAW("CEP", "inbox"));
    if (inbox && cep_cell_has_store(inbox)) {
        for (cepCell* bucket = cep_cell_first(inbox); bucket; bucket = cep_cell_next(inbox, bucket)) {
            l2_remove_children(bucket);
        }
    }

    cepCell* data = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    if (data) {
        cepCell* mailroom = cep_cell_find_by_name(data, CEP_DTAW("CEP", "inbox"));
        if (mailroom && cep_cell_has_store(mailroom)) {
            cepCell* flow_ns = cep_cell_find_by_name(mailroom, CEP_DTAW("CEP", "flow"));
            if (flow_ns && cep_cell_has_store(flow_ns)) {
                for (cepCell* bucket = cep_cell_first(flow_ns); bucket; bucket = cep_cell_next(flow_ns, bucket)) {
                    l2_remove_children(bucket);
                }
            }
        }
    }

    cepCell* adj_root = l2_tmp_adj();
    if (adj_root && cep_cell_has_store(adj_root)) {
        for (cepCell* bucket = cep_cell_first(adj_root); bucket; bucket = cep_cell_next(adj_root, bucket)) {
            l2_remove_children(bucket);
        }
    }
}

static void l2_run_single_beat(void) {
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_true(cep_heartbeat_process_impulses());
}

static void l2_run_beats(unsigned count) {
    for (unsigned i = 0u; i < count; ++i) {
        l2_run_single_beat();
    }
}

static void l2_set_string(cepCell* parent, const char* field, const char* value) {
    cepDT name_dt = l2_name_dt(field);
    cepCell* existing = cep_cell_find_by_name(parent, &name_dt);
    if (existing) {
        cep_cell_remove_hard(parent, existing);
    }
    cepDT text_dt = *CEP_DTAW("CEP", "text");
    size_t len = strlen(value) + 1u;
    cepDT name_copy = name_dt;
    cepDT text_copy = text_dt;
    cepCell* node = cep_dict_add_value(parent, &name_copy, &text_copy, (void*)value, len, len);
    munit_assert_not_null(node);
}

static void l2_set_number(cepCell* parent, const char* field, size_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%zu", value);
    munit_assert_true(written > 0 && (size_t)written < sizeof buffer);
    l2_set_string(parent, field, buffer);
}

static cepCell* l2_expect_entry(cepCell* ledger, const char* identifier) {
    cepDT id_dt = l2_name_dt(identifier);
    cepCell* entry = cep_cell_find_by_name(ledger, &id_dt);
    munit_assert_not_null(entry);
    return entry;
}

static const char* l2_get_text(cepCell* parent, const char* field) {
    cepDT name_dt = l2_name_dt(field);
    cepCell* node = cep_cell_find_by_name(parent, &name_dt);
    if (!node || !cep_cell_has_data(node)) {
        return NULL;
    }
    return (const char*)node->data->value;
}

static void l2_build_policy(const char* policy_id, const char* retain_directive) {
    cepL2DefinitionIntent intent = {0};
    munit_assert_true(cep_l2_definition_intent_init(&intent,
                                                    "req_policy",
                                                    "policy",
                                                    (const char*[]){ policy_id },
                                                    1u));
    if (retain_directive) {
        munit_assert_true(cep_l2_definition_intent_set_text(&intent, "retain", retain_directive));
    }
    l2_run_beats(2u);
    cepCell* policy = l2_expect_entry(l2_ledger("policy"), policy_id);
    munit_assert_not_null(policy);
}

static void l2_build_program(const char* program_id, const char* policy_id, const char* site_name) {
    cepL2DefinitionIntent intent = {0};
    munit_assert_true(cep_l2_definition_intent_init(&intent,
                                                    "req_program",
                                                    "program",
                                                    (const char*[]){ program_id },
                                                    1u));

    cepCell* step0 = cep_l2_definition_intent_add_step(&intent, "decide");
    cepCell* spec = cep_l2_definition_step_ensure_spec(step0);
    l2_set_string(spec, "policy", policy_id);
    l2_set_string(spec, "site", site_name);
    l2_set_string(spec, "choice", "variant_a");
    l2_run_beats(2u);
    cepCell* program = l2_expect_entry(l2_ledger("program"), program_id);
    munit_assert_not_null(program);
}

static void l2_build_wait_program(const char* program_id,
                                  const char* wait_signal) {
    cepL2DefinitionIntent intent = {0};
    munit_assert_true(cep_l2_definition_intent_init(&intent,
                                                    "req_program_wait",
                                                    "program",
                                                    (const char*[]){ program_id },
                                                    1u));

    cepCell* wait_step = cep_l2_definition_intent_add_step(&intent, "wait");
    cepCell* wait_spec = cep_l2_definition_step_ensure_spec(wait_step);
    l2_set_string(wait_spec, "signal_path", wait_signal);
    l2_set_number(wait_spec, "timeout", 5u);

    cepCell* transform_step = cep_l2_definition_intent_add_step(&intent, "transform");
    cepCell* transform_spec = cep_l2_definition_step_ensure_spec(transform_step);
    l2_set_string(transform_spec, "state", "done");

    l2_run_beats(2u);
    cepCell* program = l2_expect_entry(l2_ledger("program"), program_id);
    munit_assert_not_null(program);
}

static void l2_build_variant(const char* variant_id, const char* program_id) {
    cepL2DefinitionIntent intent = {0};
    munit_assert_true(cep_l2_definition_intent_init(&intent,
                                                    "req_variant",
                                                    "variant",
                                                    (const char*[]){ variant_id },
                                                    1u));
    munit_assert_true(cep_l2_definition_intent_set_program(&intent,
                                                           (const char*[]){ program_id },
                                                           1u));
    l2_run_beats(2u);
    cepCell* variant = l2_expect_entry(l2_ledger("variant"), variant_id);
    munit_assert_not_null(variant);
}

static cepCell* l2_start_instance(const char* instance_id, const char* variant_id) {
    cepL2InstanceStartIntent intent = {0};
    munit_assert_true(cep_l2_instance_start_intent_init(&intent,
                                                        "req_inst_start",
                                                        (const char*[]){ instance_id },
                                                        1u,
                                                        (const char*[]){ variant_id },
                                                        1u));
    l2_run_beats(3u);
    return l2_expect_entry(l2_ledger("instance"), instance_id);
}

static cepCell* l2_decision_entry(const char* instance_id, const char* site) {
    cepCell* decisions = l2_ledger("decision");
    cepCell* inst_bucket = l2_expect_entry(decisions, instance_id);
    cepDT site_dt = l2_name_dt(site);
    cepCell* site_entry = cep_cell_find_by_name(inst_bucket, &site_dt);
    munit_assert_not_null(site_entry);
    return site_entry;
}

static void l2_post_event(const char* request_id,
                          const char* instance_id,
                          const char* signal_path,
                          const char* payload_key,
                          const char* payload_value) {
    cepL2InstanceEventIntent intent = {0};
    munit_assert_true(cep_l2_instance_event_intent_init(&intent,
                                                       request_id,
                                                       signal_path,
                                                       instance_id ? (const char*[]){ instance_id } : NULL,
                                                       instance_id ? 1u : 0u));
    if (payload_key && payload_value) {
        cepCell* payload = cep_l2_instance_event_intent_payload(&intent);
        munit_assert_not_null(payload);
        l2_set_string(payload, payload_key, payload_value);
    }
    l2_run_beats(2u);
}

static size_t l2_count_children(cepCell* node) {
    if (!node || !cep_cell_has_store(node)) {
        return 0u;
    }
    size_t count = 0u;
    for (cepCell* child = cep_cell_first(node); child; child = cep_cell_next(node, child)) {
        ++count;
    }
    return count;
}

static void l2_force_root_directories(void) {
    cepCell* root = cep_root();
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");

    cepDT sys_name = *CEP_DTAW("CEP", "sys");
    if (!cep_cell_find_by_name(root, &sys_name)) {
        cepDT name_copy = sys_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    cepDT rt_name = *CEP_DTAW("CEP", "rt");
    if (!cep_cell_find_by_name(root, &rt_name)) {
        cepDT name_copy = rt_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    cepDT journal_name = *CEP_DTAW("CEP", "journal");
    if (!cep_cell_find_by_name(root, &journal_name)) {
        cepDT name_copy = journal_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    cepDT env_name = *CEP_DTAW("CEP", "env");
    if (!cep_cell_find_by_name(root, &env_name)) {
        cepDT name_copy = env_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    cepDT cas_name = *CEP_DTAW("CEP", "cas");
    if (!cep_cell_find_by_name(root, &cas_name)) {
        cepDT name_copy = cas_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    cepDT lib_name = *CEP_DTAW("CEP", "lib");
    if (!cep_cell_find_by_name(root, &lib_name)) {
        cepDT name_copy = lib_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    cepDT data_name = *CEP_DTAW("CEP", "data");
    if (!cep_cell_find_by_name(root, &data_name)) {
        cepDT name_copy = data_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }

    cepDT tmp_name = *CEP_DTAW("CEP", "tmp");
    if (!cep_cell_find_by_name(root, &tmp_name)) {
        cepDT list_type = *CEP_DTAW("CEP", "list");
        cepDT name_copy = tmp_name;
        cep_dict_add_list(root, &name_copy, &list_type, CEP_STORAGE_LINKED_LIST);
    }

    cepDT enzymes_name = *CEP_DTAW("CEP", "enzymes");
    if (!cep_cell_find_by_name(root, &enzymes_name)) {
        cepDT name_copy = enzymes_name;
        cep_dict_add_dictionary(root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
}

void* l2_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    const char* enable = getenv("CEP_L2_TEST_ENABLE");
    if (!enable || enable[0] == '\0' || enable[0] == '0') {
        L2Fixture* fixture = munit_malloc(sizeof *fixture);
        fixture->initialized = false;
        return fixture;
    }

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
    cep_cell_system_initiate();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_bootstrap());
    l2_force_root_directories();
    munit_assert_true(cep_heartbeat_startup());

    munit_assert_true(cep_l2_flows_bootstrap());
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_true(cep_l2_flows_register(registry));
    cep_enzyme_registry_activate_pending(registry);

    l2_clear_state();

    L2Fixture* fixture = munit_malloc(sizeof *fixture);
    fixture->initialized = true;
    return fixture;
}

void l2_teardown(void* fixture_ptr) {
    L2Fixture* fixture = fixture_ptr;
    if (fixture && fixture->initialized) {
        l2_clear_state();
        test_runtime_shutdown();
        cep_cell_system_shutdown();
    }
    free(fixture);
}

MunitResult test_l2_ingest_and_decision(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    L2Fixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        munit_log(MUNIT_LOG_INFO, "Skipping Layer 2 flow tests; set CEP_L2_TEST_ENABLE=1 to run when bootstrap succeeds on this platform.");
        return MUNIT_SKIP;
    }

    const char* policy_id = "policy.alpha";
    const char* program_id = "program.alpha";
    const char* variant_id = "variant.alpha";
    const char* instance_id = "instance.alpha";

    l2_build_policy(policy_id, "archive:2");
    l2_build_program(program_id, policy_id, "main");
    l2_build_variant(variant_id, program_id);

    cepCell* instance = l2_start_instance(instance_id, variant_id);
    munit_assert_not_null(instance);

    /* Allow the VM to process the initial decision and indexing passes. */
    l2_run_beats(4u);

    const char* state = l2_get_text(instance, "state");
    munit_assert_string_equal(state, "done");
    const char* pc_text = l2_get_text(instance, "pc");
    munit_assert_string_equal(pc_text, "1");

    cepCell* decision = l2_decision_entry(instance_id, "main");
    const char* choice = l2_get_text(decision, "choice");
    munit_assert_string_equal(choice, "variant_a");
    const char* retain = l2_get_text(decision, "retain");
    munit_assert_string_equal(retain, "archive:2");

    cepCell* validation = cep_cell_find_by_name(decision, CEP_DTAW("CEP", "validation"));
    munit_assert_not_null(validation);
    cepCell* telemetry = cep_cell_find_by_name(validation, CEP_DTAW("CEP", "telemetry"));
    munit_assert_not_null(telemetry);
    munit_assert_not_null(l2_get_text(telemetry, "score"));
    munit_assert_not_null(l2_get_text(telemetry, "confidence"));
    munit_assert_not_null(l2_get_text(telemetry, "rng_seed"));
    munit_assert_not_null(l2_get_text(telemetry, "rng_seq"));
    munit_assert_not_null(l2_get_text(telemetry, "latency"));

    cepCell* evidence = cep_cell_find_by_name(decision, CEP_DTAW("CEP", "evidence"));
    munit_assert_not_null(evidence);
    cepCell* evidence_tel = cep_cell_find_by_name(evidence, CEP_DTAW("CEP", "telemetry"));
    munit_assert_not_null(evidence_tel);

    cepCell* index_root = l2_ledger("index");
    cepDT by_policy_dt = l2_name_dt("dec_by_pol");
    cepCell* by_policy = cep_cell_find_by_name(index_root, &by_policy_dt);
    munit_assert_not_null(by_policy);
    cepCell* policy_bucket = l2_expect_entry(by_policy, policy_id);
    cepCell* meta = cep_cell_find_by_name(policy_bucket, CEP_DTAW("CEP", "meta"));
    munit_assert_not_null(meta);
    munit_assert_not_null(cep_cell_find_by_name(meta, CEP_DTAW("CEP", "lat_window")));
    munit_assert_not_null(cep_cell_find_by_name(meta, CEP_DTAW("CEP", "err_window")));

    cepCell* adj_root = l2_tmp_adj();
    cepCell* by_inst = cep_cell_find_by_name(adj_root, CEP_DTAW("CEP", "by_inst"));
    munit_assert_not_null(by_inst);
    cepCell* inst_bucket = l2_expect_entry(by_inst, instance_id);
    munit_assert_not_null(cep_cell_find_by_name(inst_bucket, CEP_DTAW("CEP", "lat_window")));
    munit_assert_not_null(cep_cell_find_by_name(inst_bucket, CEP_DTAW("CEP", "err_window")));

    return MUNIT_OK;
}

MunitResult test_l2_retention_archive(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    L2Fixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        munit_log(MUNIT_LOG_INFO, "Skipping Layer 2 retention test; set CEP_L2_TEST_ENABLE=1 to run when bootstrap succeeds on this platform.");
        return MUNIT_SKIP;
    }

    const char* policy_id = "policy.retain";
    const char* program_id = "program.retain";
    const char* variant_id = "variant.retain";
    const char* instance_id = "instance.retain";

    l2_build_policy(policy_id, "archive:1");
    l2_build_program(program_id, policy_id, "decision-site");
    l2_build_variant(variant_id, program_id);

    cepCell* instance = l2_start_instance(instance_id, variant_id);
    munit_assert_not_null(instance);
    l2_run_beats(4u);

    cepCell* decision = l2_decision_entry(instance_id, "decision-site");
    munit_assert_not_null(decision);
    const char* retain_upto = l2_get_text(decision, "retain_upto");
    munit_assert_not_null(retain_upto);

    /* Advance beats beyond the expiry window. */
    l2_run_beats(3u);

    /* Submit a no-op control to trigger the pipeline and retention pass. */
    cepL2InstanceControlIntent ctrl_intent = {0};
    munit_assert_true(cep_l2_instance_control_intent_init(&ctrl_intent,
                                                          "req_ctrl_resume",
                                                          "resume",
                                                          (const char*[]){ instance_id },
                                                          1u));
    l2_run_beats(4u);

    cepCell* decisions = l2_ledger("decision");
    cepDT inst_dt = l2_name_dt(instance_id);
    cepCell* inst_bucket = cep_cell_find_by_name(decisions, &inst_dt);
    if (inst_bucket) {
        cepDT site_dt = l2_name_dt("decision-site");
        cepCell* site_entry = cep_cell_find_by_name(inst_bucket, &site_dt);
        munit_assert_null(site_entry);
    }

    cepCell* archive_root = l2_ledger("dec_archive");
    cepCell* archive_bucket = l2_expect_entry(archive_root, instance_id);
    cepDT site_dt = l2_name_dt("decision-site");
    cepCell* archived = cep_cell_find_by_name(archive_bucket, &site_dt);
    munit_assert_not_null(archived);
    munit_assert_string_equal(l2_get_text(archived, "retain"), "archive:1");

    return MUNIT_OK;
}

MunitResult test_l2_wait_event_resume(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    L2Fixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        munit_log(MUNIT_LOG_INFO, "Skipping Layer 2 wait/event test; set CEP_L2_TEST_ENABLE=1 to run when bootstrap succeeds on this platform.");
        return MUNIT_SKIP;
    }

    const char* program_id = "program.wait";
    const char* variant_id = "variant.wait";
    const char* instance_id = "instance.wait";
    const char* wait_signal = "CEP:flow/event";

    l2_build_wait_program(program_id, wait_signal);
    l2_build_variant(variant_id, program_id);

    cepCell* instance = l2_start_instance(instance_id, variant_id);
    munit_assert_not_null(instance);

    l2_run_beats(1u);
    const char* state = l2_get_text(instance, "state");
    munit_assert_string_equal(state, "waiting");

    cepCell* subs = cep_cell_find_by_name(instance, CEP_DTAW("CEP", "subs"));
    munit_assert_not_null(subs);
    munit_assert_true(l2_count_children(subs) > 0u);

    l2_post_event("req_event_wait", instance_id, wait_signal, "payload_kind", "wake");

    cepCell* event_bucket = l2_inbox_bucket("inst_event");
    cepDT event_req_dt = l2_name_dt("req_event_wait");
    cepCell* event_request = cep_cell_find_by_name(event_bucket, &event_req_dt);
    munit_assert_not_null(event_request);
    munit_assert_string_equal(l2_get_text(event_request, "outcome"), "ok");

    l2_run_beats(4u);

    const char* final_state = l2_get_text(instance, "state");
    munit_assert_string_equal(final_state, "done");
    const char* pc_text = l2_get_text(instance, "pc");
    munit_assert_string_equal(pc_text, "2");

    subs = cep_cell_find_by_name(instance, CEP_DTAW("CEP", "subs"));
    if (subs) {
        munit_assert_size(l2_count_children(subs), ==, 0u);
    }

    cepCell* events = cep_cell_find_by_name(instance, CEP_DTAW("CEP", "events"));
    munit_assert_not_null(events);
    munit_assert_true(l2_count_children(events) > 0u);
    cepCell* event_entry = cep_cell_first(events);
    munit_assert_not_null(event_entry);
    munit_assert_not_null(l2_get_text(event_entry, "status"));
    const char* origin = l2_get_text(event_entry, "origin");
    munit_assert_string_equal(origin, "target");

    cepCell* history = cep_cell_find_by_name(event_entry, CEP_DTAW("CEP", "history"));
    munit_assert_not_null(history);
    munit_assert_true(l2_count_children(history) >= 2u);

    return MUNIT_OK;
}
