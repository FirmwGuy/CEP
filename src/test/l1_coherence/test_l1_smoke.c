#include "munit.h"

#include "../../l1_coherence/cep_l1_pack.h"
#include "../../l1_coherence/cep_l1_schema.h"
#include "../../l1_coherence/cep_l1_pipelines.h"
#include "../../l1_coherence/cep_l1_runtime.h"
#include "../../l1_coherence/cep_l1_coherence.h"
#include "../../l0_kernel/cep_runtime.h"
#include "../../l0_kernel/cep_heartbeat.h"
#include "../../l0_kernel/cep_namepool.h"

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

    cepL1PipelineLayout pl = {0};
    munit_assert_true(cep_l1_pipeline_ensure(layout.flow_pipelines, "demo/pipeline", &pl));
    munit_assert_not_null(pl.stages);
    cepCell* stage = NULL;
    munit_assert_true(cep_l1_pipeline_stage_stub(&pl, "stageA", &stage));
    munit_assert_true(cep_l1_pipeline_add_edge(&pl, "stageA", "stageB", "edge note"));
    munit_assert_true(cep_l1_pipeline_bind_coherence(&layout, &pl));
    munit_assert_not_null(stage);
    cepDT edge_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("stageA_stageB")};
    cepCell* edge = cep_cell_find_by_name(pl.edges, &edge_dt);
    edge = edge ? cep_cell_resolve(edge) : NULL;
    munit_assert_not_null(edge);

    cepCell* run = NULL;
    cepPipelineMetadata meta = {0};
    meta.pipeline_id = cep_namepool_intern_cstr("demo/pipeline");
    meta.stage_id = cep_namepool_intern_cstr("stageA");
    meta.hop_index = 1;
    munit_assert_true(cep_l1_runtime_record_run(layout.flow_runs,
                                                "demo/pipeline",
                                                1u,
                                                "ist:run",
                                                &meta,
                                                &run));
    munit_assert_not_null(run);
    munit_assert_true(cep_l1_runtime_record_stage_state(run, "stageA", "ist:ok", 1u));
    munit_assert_true(cep_l1_runtime_record_metric(layout.flow_metrics, "demo/pipeline", "metric/foo", 5u));
    munit_assert_true(cep_l1_runtime_add_annotation(layout.flow_annotations, "demo/pipeline", "note one"));
    munit_assert_true(cep_l1_coh_add_being(&layout, "being:alice", NULL));
    cepL1CohBinding binding = {.role = "actor", .being_id = "being:alice"};
    munit_assert_true(cep_l1_coh_add_context(&layout, "ctx:demo", "demo context", &binding, 1u, NULL));

    cepDT ctx_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("ctx:demo")};
    cepDT role_dt = {.domain = cep_namepool_intern_cstr("CEP"), .tag = cep_namepool_intern_cstr("actor")};
    cepCell* ctx_facets = cep_cell_find_by_name(layout.coh_facets, &ctx_dt);
    ctx_facets = ctx_facets ? cep_cell_resolve(ctx_facets) : NULL;
    munit_assert_not_null(ctx_facets);
    cepCell* facet = cep_cell_find_by_name(ctx_facets, &role_dt);
    facet = facet ? cep_cell_resolve(facet) : NULL;
    munit_assert_not_null(facet);
    return MUNIT_OK;
}

static MunitTest l1_tests[] = {
    {(char*)"/l1/smoke/schema", test_l1_bootstrap_schema, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/l1/smoke/pipeline_run", test_l1_pipeline_and_run, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
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
