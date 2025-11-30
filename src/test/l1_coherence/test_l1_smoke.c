/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "munit.h"

#include "../../l1_coherence/cep_l1_pack.h"
#include "../../l1_coherence/cep_l1_schema.h"
#include "../../l1_coherence/cep_l1_pipelines.h"
#include "../../l1_coherence/cep_l1_runtime.h"
#include "../../l1_coherence/cep_l1_coherence.h"
#include "../../l0_kernel/cep_runtime.h"
#include "../../l0_kernel/cep_heartbeat.h"
#include "../../l0_kernel/cep_namepool.h"
#include "../../l0_kernel/cep_ops.h"
#include "../../l0_kernel/cep_enzyme.h"
#include "../../l0_kernel/cep_organ.h"
#include "../../l0_kernel/cep_cei.h"
#include "../../l0_kernel/cep_branch_controller.h"
#include "../../enzymes/fed_invoke.h"
#include "../test.h"

#include <string.h>
#include <stdio.h>

static bool read_bool_field(cepCell* parent, const cepDT* field, bool* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* cell = cep_cell_find_by_name(parent, field);
    cell = cell ? cep_cell_resolve(cell) : NULL;
    if (!cell) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&cell, &data) || !data || data->size == 0u) {
        return false;
    }
    const unsigned char* bytes = (const unsigned char*)cep_data_payload(data);
    if (!bytes) {
        return false;
    }
    *out = bytes[0] != 0u;
    return true;
}

static uint64_t read_u64_field(cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return 0u;
    }
    cepCell* cell = cep_cell_find_by_name(parent, field);
    cell = cell ? cep_cell_resolve(cell) : NULL;
    if (!cell) {
        return 0u;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&cell, &data) || !data || data->size < sizeof(uint64_t)) {
        return 0u;
    }
    uint64_t value = 0u;
    memcpy(&value, cep_data_payload(data), sizeof value);
    return value;
}

static void clear_diag_mailbox(void) {
    cepCell* mailbox = cep_cei_diagnostics_mailbox();
    if (!mailbox) {
        return;
    }
    cepCell* msgs = cep_cell_find_by_name(mailbox, CEP_DTAW("CEP", "msgs"));
    msgs = msgs ? cep_cell_resolve(msgs) : NULL;
    if (!msgs || !msgs->store) {
        return;
    }
    cep_store_delete_children_hard(msgs->store);
}

static bool find_diag_topic(const char* expected_topic, char* buffer, size_t capacity) {
    if (!expected_topic) {
        return false;
    }
    if (buffer && capacity > 0u) {
        buffer[0] = '\0';
    }
    cepCell* mailbox = cep_cei_diagnostics_mailbox();
    if (!mailbox) {
        return false;
    }
    cepCell* msgs = cep_cell_find_by_name(mailbox, CEP_DTAW("CEP", "msgs"));
    msgs = msgs ? cep_cell_resolve(msgs) : NULL;
    if (!msgs || !cep_cell_require_dictionary_store(&msgs)) {
        return false;
    }
    for (cepCell* entry = cep_cell_last_all(msgs); entry; entry = cep_cell_prev_all(msgs, entry)) {
        cepCell* err_root = cep_cell_find_by_name(entry, CEP_DTAW("CEP", "err"));
        err_root = err_root ? cep_cell_resolve(err_root) : NULL;
        if (!err_root) {
            continue;
        }
        cepCell* topic_cell = cep_cell_find_by_name(err_root, CEP_DTAW("CEP", "topic"));
        topic_cell = topic_cell ? cep_cell_resolve(topic_cell) : NULL;
        if (!topic_cell || !cep_cell_has_data(topic_cell)) {
            continue;
        }
        const char* topic_text = cep_cell_data(topic_cell);
        if (topic_text && strcmp(topic_text, expected_topic) == 0) {
            if (buffer && capacity > 0u) {
                snprintf(buffer, capacity, "%s", topic_text);
            }
            return true;
        }
    }
    return false;
}

typedef struct {
    cepPath path;
    cepPast past[2];
} L1PathBuf;

static const cepPath* make_single_path(L1PathBuf* buf, const char* text) {
    if (!buf || !text) {
        return NULL;
    }
    buf->path.length = 1u;
    buf->path.capacity = sizeof(buf->past) / sizeof(buf->past[0]);
    buf->past[0].dt = cep_ops_make_dt(text);
    buf->past[0].timestamp = 0u;
    return &buf->path;
}

static int run_organ_enzyme(const char* signal_text, const char* target_text) {
    L1PathBuf signal_buf = {0};
    L1PathBuf target_buf = {0};
    const cepPath* signal_path = make_single_path(&signal_buf, signal_text);
    const cepPath* target_path = target_text ? make_single_path(&target_buf, target_text) : make_single_path(&target_buf, "tgt:l1");
    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
        .qos = CEP_IMPULSE_QOS_NONE,
        .has_pipeline = false,
    };
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    cep_enzyme_registry_activate_pending(registry);

    const cepEnzymeDescriptor* ordered[2] = {0};
    size_t found = cep_enzyme_resolve(registry, &impulse, ordered, 2u);
    munit_assert_size(found, >=, 1u);
    munit_assert_not_null(ordered[0]);
    return ordered[0]->callback(signal_path, target_path);
}

static MunitResult test_l1_bootstrap_schema(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    if (!cep_l1_pack_bootstrap()) {
        return MUNIT_SKIP;
    }

    cepL1SchemaLayout layout = {0};
    if (!cep_l1_schema_ensure(&layout)) {
        return MUNIT_SKIP;
    }
    munit_assert_not_null(layout.coh_root);
    munit_assert_not_null(layout.flow_root);
    munit_assert_not_null(layout.flow_pipelines);
    munit_assert_not_null(layout.flow_runtime);
    return MUNIT_OK;
}

static MunitResult test_l1_pipeline_and_run(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    cepL1SchemaLayout layout = {0};
    if (!cep_l1_schema_ensure(&layout)) {
        return MUNIT_SKIP;
    }

    cepL1PipelineMeta meta_info = {.owner = "ops", .province = "prod", .version = "v1", .kind = "application", .revision = 2u};
    cepL1PipelineLayout pl = {0};
    munit_assert_true(cep_l1_pipeline_ensure(layout.flow_pipelines, "demo/pipeline", &meta_info, &pl));
    munit_assert_not_null(pl.stages);
    cepCell* stage = NULL;
    munit_assert_true(cep_l1_pipeline_stage_stub(&pl, "stageA", &stage));
    munit_assert_true(cep_l1_pipeline_stage_set_role(&pl, "stageA", "prepare_features"));
    munit_assert_true(cep_l1_pipeline_stage_set_role(&pl, "stageB", "call_learner"));
    munit_assert_true(cep_l1_pipeline_add_edge(&pl, "stageA", "stageB", "edge note"));
    munit_assert_true(cep_l1_pipeline_bind_coherence(&layout, &pl));
    munit_assert_not_null(stage);

    /* Pipeline provenance */
    munit_assert_uint64(read_u64_field(pl.pipeline, CEP_DTAW("CEP", "rev")), ==, 2u);
    char pipeline_being_key[128] = {0};
    munit_assert_true(cep_l1_coh_make_being_key("pipeline", "demo/pipeline", pipeline_being_key, sizeof pipeline_being_key));
    char owner_being_key[64] = {0};
    munit_assert_true(cep_l1_coh_make_being_key("owner", "ops", owner_being_key, sizeof owner_being_key));
    char province_being_key[64] = {0};
    munit_assert_true(cep_l1_coh_make_being_key("province", "prod", province_being_key, sizeof province_being_key));
    char owner_bond_key[256] = {0};
    munit_assert_true(cep_l1_coh_make_bond_key("owned_by", pipeline_being_key, owner_being_key, owner_bond_key, sizeof owner_bond_key));
    char province_bond_key[256] = {0};
    munit_assert_true(cep_l1_coh_make_bond_key("in_province", pipeline_being_key, province_being_key, province_bond_key, sizeof province_bond_key));
    cepDT owner_bond_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(owner_bond_key)};
    cepDT province_bond_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(province_bond_key)};
    munit_assert_not_null(cep_cell_find_by_name(layout.coh_bonds, &owner_bond_dt));
    munit_assert_not_null(cep_cell_find_by_name(layout.coh_bonds, &province_bond_dt));

    /* Context rules with required roles/facets */
    cepDT ctx_kind_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("schema_ctx")};
    cepCell* ctx_rules = cep_cell_ensure_dictionary_child(layout.coh_context_rules, &ctx_kind_dt, CEP_STORAGE_RED_BLACK_T);
    ctx_rules = ctx_rules ? cep_cell_resolve(ctx_rules) : NULL;
    munit_assert_not_null(ctx_rules);
    cepCell* roles = cep_cell_ensure_dictionary_child(ctx_rules, CEP_DTAW("CEP", "roles"), CEP_STORAGE_RED_BLACK_T);
    roles = roles ? cep_cell_resolve(roles) : NULL;
    munit_assert_not_null(roles);
    cepCell* role_entry = cep_cell_ensure_dictionary_child(roles, CEP_DTAW("CEP", "actor"), CEP_STORAGE_RED_BLACK_T);
    role_entry = role_entry ? cep_cell_resolve(role_entry) : NULL;
    munit_assert_not_null(role_entry);
    munit_assert_true(cep_cell_put_uint64(role_entry, CEP_DTAW("CEP", "required"), 1u));

    cepCell* facets = cep_cell_ensure_dictionary_child(ctx_rules, CEP_DTAW("CEP", "facets"), CEP_STORAGE_RED_BLACK_T);
    facets = facets ? cep_cell_resolve(facets) : NULL;
    munit_assert_not_null(facets);
    cepCell* facet_entry = cep_cell_ensure_dictionary_child(facets, CEP_DTAW("CEP", "actor"), CEP_STORAGE_RED_BLACK_T);
    facet_entry = facet_entry ? cep_cell_resolve(facet_entry) : NULL;
    munit_assert_not_null(facet_entry);
    munit_assert_true(cep_cell_put_text(facet_entry, CEP_DTAW("CEP", "role"), "actor"));
    munit_assert_true(cep_cell_put_uint64(facet_entry, CEP_DTAW("CEP", "required"), 1u));

    /* Missing required role should record a debt with ctx_kind lineage. */
    cepL1CohBinding viewer_binding = {.role = "viewer", .being_kind = "being", .being_external_id = "alice", .bond_id = NULL};
    cepCell* viewer_being = NULL;
    munit_assert_true(cep_l1_coh_add_being(&layout, "being", "alice", &viewer_being));
    char viewer_ctx_id[256] = {0};
    munit_assert_true(cep_l1_coh_make_context_key("schema_ctx", &viewer_binding, 1u, viewer_ctx_id, sizeof viewer_ctx_id));
    munit_assert_true(cep_l1_coh_add_context(&layout, "schema_ctx", "viewer ctx", &viewer_binding, 1u, NULL));
    char debt_id[320] = {0};
    munit_assert_true(cep_l1_coh_make_debt_key("missing_role", viewer_ctx_id, "actor", debt_id, sizeof debt_id));
    cepDT debt_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(debt_id)};
    cepCell* debt = cep_cell_find_by_name(layout.coh_debts, &debt_dt);
    debt = debt ? cep_cell_resolve(debt) : NULL;
    munit_assert_not_null(debt);
    cepCell* ctx_kind_cell = cep_cell_find_by_name(debt, CEP_DTAW("CEP", "ctx_kind"));
    munit_assert_not_null(ctx_kind_cell);

    /* Closure with required role present should materialize facets. */
    cepL1CohBinding actor_binding = {.role = "actor", .being_kind = "being", .being_external_id = "alice", .bond_id = NULL};
    char actor_ctx_id[256] = {0};
    munit_assert_true(cep_l1_coh_make_context_key("schema_ctx", &actor_binding, 1u, actor_ctx_id, sizeof actor_ctx_id));
    munit_assert_true(cep_l1_coh_add_context(&layout, "schema_ctx", "actor ctx", &actor_binding, 1u, NULL));
    char actor_facet_id[256] = {0};
    munit_assert_true(cep_l1_coh_make_facet_key("actor", actor_ctx_id, "being:alice", "actor", actor_facet_id, sizeof actor_facet_id));
    cepDT actor_facet_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(actor_facet_id)};
    cepCell* actor_facet = cep_cell_find_by_name(layout.coh_facets, &actor_facet_dt);
    munit_assert_not_null(actor_facet);

    /* Runtime orchestrator fan-in and stage metadata. */
    cepCell* run = NULL;
    cepPipelineMetadata run_meta = {0};
    run_meta.pipeline_id = cep_namepool_intern_cstr("demo/pipeline");
    run_meta.stage_id = cep_namepool_intern_cstr("stageA");
    run_meta.dag_run_id = 1u;
    run_meta.hop_index = 1;
    munit_assert_true(cep_l1_runtime_record_run(layout.flow_runs, "demo/pipeline", 1u, "ist:run", &run_meta, &run));
    munit_assert_not_null(run);
    munit_assert_true(cep_l1_runtime_configure_stage_fanin(run, "stageA", 2u));
    munit_assert_true(cep_l1_runtime_record_trigger(run, "stageA", "event", "first trigger", 10u));
    munit_assert_true(cep_l1_runtime_record_trigger(run, "stageA", "label", "second trigger", 11u));
    cepCell* stage_entry = cep_cell_find_by_name(run, CEP_DTAW("CEP", "stages"));
    stage_entry = stage_entry ? cep_cell_resolve(stage_entry) : NULL;
    munit_assert_not_null(stage_entry);
    cepCell* stageA = cep_cell_find_by_name(stage_entry, CEP_DTAW("CEP", "stageA"));
    stageA = stageA ? cep_cell_resolve(stageA) : NULL;
    munit_assert_not_null(stageA);
    cepCell* stageB = cep_cell_find_by_name(stage_entry, CEP_DTAW("CEP", "stageB"));
    stageB = stageB ? cep_cell_resolve(stageB) : NULL;
    munit_assert_not_null(stageB);
    bool ready = false;
    munit_assert_true(read_bool_field(stageA, CEP_DTAW("CEP", "ready"), &ready));
    munit_assert_true(ready);
    munit_assert_uint64(read_u64_field(stageA, CEP_DTAW("CEP", "fan_seen")), ==, 2u);
    bool stageB_ready = true;
    munit_assert_true(read_bool_field(stageB, CEP_DTAW("CEP", "ready"), &stageB_ready));
    munit_assert_false(stageB_ready);
    munit_assert_uint64(read_u64_field(stageB, CEP_DTAW("CEP", "fan_in")), ==, 1u);
    munit_assert_uint64(read_u64_field(stageB, CEP_DTAW("CEP", "fan_seen")), ==, 0u);

    L1PathBuf signal_buf = {0};
    L1PathBuf target_buf = {0};
    const cepPath* signal_path = make_single_path(&signal_buf, "sig:l1/fanout");
    const cepPath* target_path = make_single_path(&target_buf, "tgt:l1/fanout");
    munit_assert_not_null(signal_path);
    munit_assert_not_null(target_path);

    munit_assert_true(cep_runtime_pause());
    munit_assert_false(cep_l1_runtime_dispatch_if_ready(run, "stageA", signal_path, target_path, &run_meta, CEP_IMPULSE_QOS_NONE));
    bool paused_flag = false;
    munit_assert_true(read_bool_field(run, CEP_DTAW("CEP", "paused"), &paused_flag));
    munit_assert_true(paused_flag);
    munit_assert_true(cep_runtime_resume());

    munit_assert_true(cep_l1_runtime_dispatch_if_ready(run, "stageA", signal_path, target_path, &run_meta, CEP_IMPULSE_QOS_NONE));

    ready = true;
    munit_assert_true(read_bool_field(stageA, CEP_DTAW("CEP", "ready"), &ready));
    munit_assert_false(ready);

    stageB_ready = false;
    munit_assert_true(read_bool_field(stageB, CEP_DTAW("CEP", "ready"), &stageB_ready));
    munit_assert_true(stageB_ready);
    munit_assert_uint64(read_u64_field(stageB, CEP_DTAW("CEP", "fan_seen")), ==, 1u);
    munit_assert_uint64(read_u64_field(stageB, CEP_DTAW("CEP", "hop_index")), ==, 2u);

    cepCell* stageB_triggers = cep_cell_find_by_name(stageB, CEP_DTAW("CEP", "triggers"));
    stageB_triggers = stageB_triggers ? cep_cell_resolve(stageB_triggers) : NULL;
    munit_assert_not_null(stageB_triggers);
    cepCell* fan_out_entry = cep_cell_first(stageB_triggers);
    fan_out_entry = fan_out_entry ? cep_cell_resolve(fan_out_entry) : NULL;
    munit_assert_not_null(fan_out_entry);
    cepCell* fan_kind = cep_cell_find_by_name(fan_out_entry, CEP_DTAW("CEP", "kind"));
    fan_kind = fan_kind ? cep_cell_resolve(fan_kind) : NULL;
    munit_assert_not_null(fan_kind);
    cepData* fan_kind_data = NULL;
    munit_assert_true(cep_cell_require_data(&fan_kind, &fan_kind_data));
    munit_assert_string_equal((const char*)cep_data_payload(fan_kind_data), "fan_out");

    munit_assert_true(cep_l1_runtime_record_stage_metric(run, "stageA", "metric/local", 7u));
    munit_assert_true(cep_l1_runtime_record_stage_metric(run, "stageA", "metric/local", 3u));
    cepCell* stage_metrics = cep_cell_find_by_name(stageA, CEP_DTAW("CEP", "metrics"));
    stage_metrics = stage_metrics ? cep_cell_resolve(stage_metrics) : NULL;
    munit_assert_not_null(stage_metrics);
    cepDT metric_local_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("metric/local")};
    munit_assert_uint64(read_u64_field(stage_metrics, &metric_local_dt), ==, 10u);
    munit_assert_true(cep_l1_runtime_add_stage_annotation(run, "stageA", "stage note"));
    munit_assert_not_null(cep_cell_find_by_name(stageA, CEP_DTAW("CEP", "annotations")));

    munit_assert_true(cep_l1_runtime_record_metric(layout.flow_metrics, "demo/pipeline", "metric/global", 5u));
    munit_assert_true(cep_l1_runtime_record_metric(layout.flow_metrics, "demo/pipeline", "metric/global", 7u));
    cepDT pipeline_metrics_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("demo/pipeline")};
    cepCell* pipeline_metrics = cep_cell_find_by_name(layout.flow_metrics, &pipeline_metrics_dt);
    pipeline_metrics = pipeline_metrics ? cep_cell_resolve(pipeline_metrics) : NULL;
    munit_assert_not_null(pipeline_metrics);
    cepDT metric_global_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("metric/global")};
    munit_assert_uint64(read_u64_field(pipeline_metrics, &metric_global_dt), ==, 12u);

    cepCell* req = cep_cell_ensure_dictionary_child(layout.flow_root, CEP_DTAW("CEP", "req"), CEP_STORAGE_RED_BLACK_T);
    munit_assert_true(cep_l1_fed_prepare_request(req, &run_meta));
    cepCell* req_pipeline = cep_cell_find_by_name(req, CEP_DTAW("CEP", "pipeline"));
    req_pipeline = req_pipeline ? cep_cell_resolve(req_pipeline) : NULL;
    munit_assert_not_null(req_pipeline);
    munit_assert_not_null(cep_cell_find_by_name(req_pipeline, CEP_DTAW("CEP", "stage_id")));

    cepPipelineMetadata missing_run_id = run_meta;
    missing_run_id.dag_run_id = 0u;
    cepCell* req_missing_run = cep_cell_ensure_dictionary_child(layout.flow_root, CEP_DTAW("CEP", "req_missrun"), CEP_STORAGE_RED_BLACK_T);
    munit_assert_false(cep_l1_fed_prepare_request(req_missing_run, &missing_run_id));

    cepPipelineMetadata missing_hop = run_meta;
    missing_hop.hop_index = 0u;
    cepCell* req_missing_hop = cep_cell_ensure_dictionary_child(layout.flow_root, CEP_DTAW("CEP", "req_misshop"), CEP_STORAGE_RED_BLACK_T);
    munit_assert_false(cep_l1_fed_prepare_request(req_missing_hop, &missing_hop));

    cepPipelineMetadata missing_meta = {0};
    cepCell* bad_req = cep_cell_ensure_dictionary_child(layout.flow_root, CEP_DTAW("CEP", "req_missing"), CEP_STORAGE_RED_BLACK_T);
    munit_assert_false(cep_l1_fed_prepare_request(bad_req, &missing_meta));

    return MUNIT_OK;
}

static MunitResult test_l1_organs_coherence(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    test_runtime_enable_mock_cps();
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());
    if (!cep_l1_pack_bootstrap()) {
        test_runtime_disable_mock_cps();
        return MUNIT_SKIP;
    }

    cepL1SchemaLayout layout = {0};
    munit_assert_true(cep_l1_schema_ensure(&layout));
    munit_assert_not_null(layout.coh_root);
    munit_assert_not_null(layout.coh_root->store);
    cepDT coh_store = cep_organ_store_dt("coh_root");
    munit_assert_true(cep_dt_compare(&layout.coh_root->store->dt, &coh_store) == 0);

    cepDT ctx_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("pipeline_edge")};
    cepCell* ctx_rules = cep_cell_find_by_name(layout.coh_context_rules, &ctx_dt);
    ctx_rules = ctx_rules ? cep_cell_resolve(ctx_rules) : NULL;
    munit_assert_not_null(ctx_rules);
    cepCell* roles = cep_cell_find_by_name(ctx_rules, CEP_DTAW("CEP", "roles"));
    roles = roles ? cep_cell_resolve(roles) : NULL;
    munit_assert_not_null(roles);

    const char* required_roles[] = {"pipeline", "from_stage", "to_stage"};
    for (size_t i = 0; i < sizeof(required_roles) / sizeof(required_roles[0]); ++i) {
        cepDT role_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(required_roles[i])};
        cepCell* role_entry = cep_cell_find_by_name(roles, &role_dt);
        role_entry = role_entry ? cep_cell_resolve(role_entry) : NULL;
        munit_assert_not_null(role_entry);
        bool required = false;
        munit_assert_true(read_bool_field(role_entry, CEP_DTAW("CEP", "required"), &required));
        munit_assert_true(required);
    }

    munit_assert_true(cep_l1_pack_coh_sweep());
    (void)cep_l1_pack_shutdown();
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

static MunitResult test_l1_organs_flow_spec(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    test_runtime_enable_mock_cps();
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());
    if (!cep_l1_pack_bootstrap()) {
        test_runtime_disable_mock_cps();
        return MUNIT_SKIP;
    }

    const char* pipeline_id = "org/pipeline";
    munit_assert_int(run_organ_enzyme("org:flow_spec_l1:ensure_pipeline", pipeline_id), ==, CEP_ENZYME_SUCCESS);

    cepL1SchemaLayout layout = {0};
    munit_assert_true(cep_l1_schema_ensure(&layout));
    cepDT pipeline_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(pipeline_id)};
    cepCell* pipeline = cep_cell_find_by_name(layout.flow_pipelines, &pipeline_dt);
    pipeline = pipeline ? cep_cell_resolve(pipeline) : NULL;
    munit_assert_not_null(pipeline);
    munit_assert_uint64(read_u64_field(pipeline, CEP_DTAW("CEP", "rev")), >=, 1u);

    cepL1PipelineLayout pl_layout = {0};
    munit_assert_true(cep_l1_pipeline_layout_from_root(pipeline, &pl_layout));
    munit_assert_true(cep_l1_pipeline_stage_stub(&pl_layout, "stageA", NULL));
    munit_assert_true(cep_l1_pipeline_stage_stub(&pl_layout, "stageB", NULL));
    munit_assert_true(cep_l1_pipeline_stage_set_role(&pl_layout, "stageA", "prepare_features"));
    munit_assert_true(cep_l1_pipeline_stage_set_role(&pl_layout, "stageB", "call_learner"));
    munit_assert_true(cep_l1_pipeline_add_edge(&pl_layout, "stageA", "stageB", "org test edge"));

    munit_assert_int(run_organ_enzyme("org:flow_spec_l1:normalize_edges", pipeline_id), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(run_organ_enzyme("org:flow_spec_l1:rebuild_provenance", pipeline_id), ==, CEP_ENZYME_SUCCESS);

    char pipeline_being[128] = {0};
    munit_assert_true(cep_l1_coh_make_being_key("pipeline", pipeline_id, pipeline_being, sizeof pipeline_being));
    cepDT pipeline_being_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(pipeline_being)};
    munit_assert_not_null(cep_cell_find_by_name(layout.coh_beings, &pipeline_being_dt));

    char owner_being[64] = {0};
    munit_assert_true(cep_l1_coh_make_being_key("owner", "unknown", owner_being, sizeof owner_being));
    char owner_bond[256] = {0};
    munit_assert_true(cep_l1_coh_make_bond_key("owned_by", pipeline_being, owner_being, owner_bond, sizeof owner_bond));
    cepDT owner_bond_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr(owner_bond)};
    munit_assert_not_null(cep_cell_find_by_name(layout.coh_bonds, &owner_bond_dt));

    (void)cep_l1_pack_shutdown();
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

static MunitResult test_l1_organs_flow_runtime(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    test_runtime_enable_mock_cps();
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());
    if (!cep_l1_pack_bootstrap()) {
        test_runtime_disable_mock_cps();
        return MUNIT_SKIP;
    }

    cepL1SchemaLayout layout = {0};
    munit_assert_true(cep_l1_schema_ensure(&layout));

    const char* pipeline_id = "org/runtime";
    cepL1PipelineMeta meta = {.owner = "ops", .province = "dev", .version = "v1", .kind = "application", .revision = 1u};
    cepL1PipelineLayout pl = {0};
    munit_assert_true(cep_l1_pipeline_ensure(layout.flow_pipelines, pipeline_id, &meta, &pl));
    munit_assert_true(cep_l1_pipeline_stage_stub(&pl, "stageA", NULL));
    munit_assert_true(cep_l1_pipeline_stage_stub(&pl, "stageB", NULL));
    munit_assert_true(cep_l1_pipeline_stage_set_role(&pl, "stageA", "prepare_features"));
    munit_assert_true(cep_l1_pipeline_stage_set_role(&pl, "stageB", "call_learner"));
    munit_assert_true(cep_l1_pipeline_add_edge(&pl, "stageA", "stageB", NULL));

    cepPipelineMetadata run_meta = {
        .pipeline_id = cep_namepool_intern_cstr(pipeline_id),
        .stage_id = cep_namepool_intern_cstr("stageA"),
        .dag_run_id = 5u,
        .hop_index = 1u,
    };
    cepCell* run = NULL;
    munit_assert_true(cep_l1_runtime_record_run(layout.flow_runs, pipeline_id, 5u, "ist:run", &run_meta, &run));
    munit_assert_not_null(run);

    munit_assert_int(run_organ_enzyme("org:flow_runtime_l1:vl", "tgt:runtime"), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(run_organ_enzyme("org:flow_runtime_l1:verify_edges", "tgt:runtime"), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(run_organ_enzyme("org:flow_runtime_l1:gc_runs", "tgt:runtime"), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(run_organ_enzyme("org:flow_runtime_l1:rollup_metrics", "tgt:runtime"), ==, CEP_ENZYME_SUCCESS);

    (void)cep_l1_pack_shutdown();
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

static MunitResult test_l1_cross_branch_hydration(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    test_runtime_enable_mock_cps();
    clear_diag_mailbox();
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());

    cepCell* data_root = cep_heartbeat_data_root();
    munit_assert_not_null(data_root);

    cepDT consumer_dt = cep_ops_make_dt("coh_consumer");
    cepDT source_dt = cep_ops_make_dt("coh_source");
    cepCell* consumer_branch = cep_cell_ensure_dictionary_child(data_root, &consumer_dt, CEP_STORAGE_RED_BLACK_T);
    cepCell* source_branch = cep_cell_ensure_dictionary_child(data_root, &source_dt, CEP_STORAGE_RED_BLACK_T);
    consumer_branch = consumer_branch ? cep_cell_resolve(consumer_branch) : NULL;
    source_branch = source_branch ? cep_cell_resolve(source_branch) : NULL;
    munit_assert_not_null(consumer_branch);
    munit_assert_not_null(source_branch);

    cepBranchController* consumer_ctrl = cep_branch_controller_for_cell(consumer_branch);
    cepBranchController* source_ctrl = cep_branch_controller_for_cell(source_branch);
    munit_assert_not_null(consumer_ctrl);
    munit_assert_not_null(source_ctrl);

    const cepBranchPersistPolicy* consumer_base = cep_branch_controller_policy(consumer_ctrl);
    const cepBranchPersistPolicy* source_base = cep_branch_controller_policy(source_ctrl);
    munit_assert_not_null(consumer_base);
    munit_assert_not_null(source_base);

    cepBranchPersistPolicy consumer_policy = *consumer_base;
    cepBranchPersistPolicy source_policy = *source_base;
    source_policy.mode = CEP_BRANCH_PERSIST_VOLATILE;
    consumer_policy.allow_volatile_reads = false;
    cep_branch_controller_set_policy(source_ctrl, &source_policy);
    cep_branch_controller_set_policy(consumer_ctrl, &consumer_policy);

    cepCell* payload = cep_cell_ensure_dictionary_child(source_branch, CEP_DTAW("CEP", "payload"), CEP_STORAGE_RED_BLACK_T);
    payload = payload ? cep_cell_resolve(payload) : NULL;
    munit_assert_not_null(payload);

    cep_cell_ref_t ref = {
        .branch_dt = source_dt,
        .cell = payload,
        .path = NULL,
        .is_canonical = false,
    };
    cepEnzymeContext ctx = {
        .branch_dt = consumer_dt,
        .qos = 0u,
        .has_pipeline = true,
        .pipeline = {
            .pipeline_id = cep_namepool_intern_cstr("demo/pipeline"),
            .stage_id = cep_namepool_intern_cstr("stageX"),
            .dag_run_id = 42u,
            .hop_index = 3u,
        },
    };

    char topic_buffer[64] = {0};
    munit_assert_false(cep_l1_coh_hydrate_safe(&ref, &ctx, false, false));
    munit_assert_true(find_diag_topic("coh.hydrate.fail", topic_buffer, sizeof topic_buffer));

    clear_diag_mailbox();
    consumer_policy.allow_volatile_reads = false;
    cep_branch_controller_set_policy(consumer_ctrl, &consumer_policy);
    munit_assert_false(cep_l1_coh_hydrate_safe(&ref, &ctx, true, false));
    munit_assert_true(find_diag_topic("coh.hydrate.fail", topic_buffer, sizeof topic_buffer));

    clear_diag_mailbox();
    source_policy.mode = CEP_BRANCH_PERSIST_DURABLE;
    cep_branch_controller_set_policy(source_ctrl, &source_policy);
    cep_branch_controller_clear_dirty(source_ctrl);
    consumer_policy.allow_volatile_reads = true;
    cep_branch_controller_set_policy(consumer_ctrl, &consumer_policy);
    cepBranchPolicyResult allow_policy = cep_branch_policy_check_read(consumer_ctrl, source_ctrl);
    munit_assert_int(allow_policy.access, ==, CEP_BRANCH_POLICY_ACCESS_ALLOW);
    munit_assert_true(cep_l1_coh_hydrate_safe(&ref, &ctx, true, false));
    munit_assert_true(find_diag_topic("coh.cross_read", topic_buffer, sizeof topic_buffer));

    cep_cell_remove_hard(source_branch, NULL);
    cep_cell_remove_hard(consumer_branch, NULL);
    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

static MunitResult test_l1_fed_pipeline_rejection(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    test_runtime_enable_mock_cps();
    clear_diag_mailbox();
    if (!cep_cell_system_initialized()) {
        cep_cell_system_initiate();
    }
    munit_assert_true(cep_l0_bootstrap());

    cepPipelineMetadata meta = {
        .pipeline_id = cep_namepool_intern_cstr("demo/pipeline"),
        .stage_id = cep_namepool_intern_cstr("stageA"),
        .dag_run_id = 9u,
        .hop_index = 2u,
    };
    const cepFedInvokeRequest* fake_request = (const cepFedInvokeRequest*)0x1;
    cepFedInvokeSubmission submission = {0};
    munit_assert_false(cep_l1_fed_request_submit(fake_request, NULL, &meta, &submission));
    char topic_buffer[64] = {0};
    munit_assert_true(find_diag_topic("sec.pipeline.reject", topic_buffer, sizeof topic_buffer));

    clear_diag_mailbox();
    cepCell* req = cep_cell_ensure_dictionary_child(cep_heartbeat_data_root(), CEP_DTAW("CEP", "req_unappr"), CEP_STORAGE_RED_BLACK_T);
    req = req ? cep_cell_resolve(req) : NULL;
    munit_assert_not_null(req);
    cepPipelineMetadata missing_meta = {0};
    munit_assert_false(cep_l1_fed_prepare_request(req, &missing_meta));
    munit_assert_true(find_diag_topic("sec.pipeline.reject", topic_buffer, sizeof topic_buffer));

    test_runtime_disable_mock_cps();
    return MUNIT_OK;
}

static MunitTest l1_tests[] = {
    {(char*)"/l1/smoke/schema", test_l1_bootstrap_schema, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/l1/smoke/pipeline_run", test_l1_pipeline_and_run, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/l1/organs/coherence", test_l1_organs_coherence, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/l1/organs/flow_spec", test_l1_organs_flow_spec, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/l1/organs/flow_runtime", test_l1_organs_flow_runtime, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/l1/runtime/cross_branch_hydration", test_l1_cross_branch_hydration, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/l1/runtime/fed_pipeline_reject", test_l1_fed_pipeline_rejection, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL}
};

static const MunitSuite l1_suite = {
    (char*)"/CEP/l1", l1_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE
};

MunitSuite* test_suite_l1(void) {
    const char* enable = getenv("CEP_L1_TESTS");
    if (!enable || !*enable || *enable == '0') {
        return NULL;
    }
    return (MunitSuite*)&l1_suite;
}
