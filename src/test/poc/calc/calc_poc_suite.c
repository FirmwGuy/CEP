/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Calculator POC smoke scaffolding: establishes the calc branch layout, seeds
 * pipeline metadata, and anchors the stage roster so the POC can grow without
 * sharing the monolithic test runner.
 *
 * What the POC exercises:
 * - L0: stdio HANDLE/STREAM proxies drive inbox lines into /data/app/calc/{inbox,exprs,results,outbox,sent},
 *   with enzymes calc_read→calc_parse→calc_eval→calc_fmt→calc_write preserving pipeline metadata across impulses.
 * - L1: the calc_basic pipeline is ensured with stage beings and edges; RuntimeRunTracker mirrors runs and emits
 *   flow.pipeline.missing_metadata diagnostics when metadata is withheld.
 * - L2: calc_eval_flow with variants calc_safe vs calc_fast, niches int_small/int_big, guardian/clamp budgets,
 *   decision cells recorded with pipeline blocks, and per-variant metrics bumped on replay-friendly runs.
 * This keeps all calculator documentation alongside the test logic instead of separate docs. */

#include "test.h"

#include "cep_cell.h"
#include "cep_heartbeat.h"
#include "cep_enzyme.h"
#include "cep_cei.h"
#include "cep_ops.h"
#include "cep_runtime.h"
#include "cep_l0.h"
#include "cep_l1_pack.h"
#include "cep_l1_schema.h"
#include "cep_l1_pipelines.h"
#include "cep_l1_runtime.h"
#include "cep_namepool.h"
#include "cep_l2_pack.h"
#include "cep_l2_runtime.h"
#include "stream/cep_stream_stdio.h"
#include "stream/cep_stream_internal.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

typedef struct {
    const char* pipeline_id;
    const char* const* stage_ids;
    size_t stage_count;
} CalcPocLayout;

static const char* calc_stage_ids[] = {
    "calc_read",
    "calc_parse",
    "calc_eval",
    "calc_fmt",
    "calc_write",
};

static const CalcPocLayout calc_layout = {
    .pipeline_id = "calc_basic",
    .stage_ids = calc_stage_ids,
    .stage_count = cep_lengthof(calc_stage_ids),
};

CEP_DEFINE_STATIC_DT(dt_calc_pipeline, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_basic"));
CEP_DEFINE_STATIC_DT(dt_calc_stage_read, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_read"));
CEP_DEFINE_STATIC_DT(dt_calc_stage_parse, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_parse"));
CEP_DEFINE_STATIC_DT(dt_calc_stage_eval, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_eval"));
CEP_DEFINE_STATIC_DT(dt_calc_stage_fmt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_fmt"));
CEP_DEFINE_STATIC_DT(dt_calc_stage_write, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_write"));
CEP_DEFINE_STATIC_DT(dt_calc_op_write, CEP_ACRO("CEP"), cep_namepool_intern_cstr("op/calc_write"));
CEP_DEFINE_STATIC_DT(dt_calc_op_mode, CEP_ACRO("CEP"), cep_namepool_intern_cstr("opm:states"));
CEP_DEFINE_STATIC_DT(dt_calc_variant_safe, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_safe"));
CEP_DEFINE_STATIC_DT(dt_calc_variant_fast, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_fast"));
CEP_DEFINE_STATIC_DT(dt_calc_metric_eval, CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_eval"));

static const char* calc_signal_read[] = {"sig:calc/read"};
static const char* calc_signal_parse[] = {"sig:calc/parse"};
static const char* calc_signal_eval[] = {"sig:calc/eval"};
static const char* calc_signal_fmt[] = {"sig:calc/fmt"};
static const char* calc_signal_write[] = {"sig:calc/write"};

static const char* calc_target_inbox[] = {"data", "app", "calc", "inbox"};
static const char* calc_target_exprs[] = {"data", "app", "calc", "exprs"};
static const char* calc_target_results[] = {"data", "app", "calc", "results"};
static const char* calc_target_outbox[] = {"data", "app", "calc", "outbox"};

static FILE*   calc_poc_stdin_fp = NULL;
static FILE*   calc_poc_stdout_fp = NULL;
static size_t  calc_poc_stdin_offset = 0u;
static size_t  calc_poc_stdin_size = 0u;
static size_t  calc_poc_stdout_offset = 0u;
static uint64_t calc_poc_next_run_id = 1u;
static cepOID  calc_poc_last_write_op = {0};
static bool    calc_poc_last_cei_had_pipeline = false;
static cepPipelineMetadata calc_poc_last_op_meta = {0};

static bool
calc_poc_bootstrap_runtime(void)
{
    cep_cell_system_initiate();
    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
        .spacing_window = 0u,
    };
    if (!cep_heartbeat_configure(NULL, &policy)) {
        return false;
    }
    if (!cep_l0_bootstrap()) {
        return false;
    }
    if (!cep_runtime_attach_metadata(cep_runtime_default())) {
        return false;
    }
    if (!cep_heartbeat_startup()) {
        return false;
    }
    /* Drive a couple of beats to settle boot ops before the POC pipeline. */
    if (!cep_heartbeat_step()) {
        return false;
    }
    if (!cep_heartbeat_step()) {
        return false;
    }
    return true;
}

static void
calc_poc_shutdown_runtime(void)
{
    (void)cep_l2_shutdown();
    (void)cep_l1_pack_shutdown();
    cep_stream_clear_pending();
    cepRuntime* runtime = cep_runtime_active();
    if (!runtime) {
        runtime = cep_runtime_default();
    }
    (void)cep_runtime_shutdown(runtime);
    if (runtime == cep_runtime_default()) {
        cep_heartbeat_shutdown();
        cep_l0_bootstrap_reset();
    }
    calc_poc_stdin_fp = NULL;
    calc_poc_stdout_fp = NULL;
    calc_poc_stdin_offset = 0u;
    calc_poc_stdin_size = 0u;
    calc_poc_stdout_offset = 0u;
    calc_poc_last_write_op = cep_oid_invalid();
    calc_poc_last_cei_had_pipeline = false;
    memset(&calc_poc_last_op_meta, 0, sizeof calc_poc_last_op_meta);
}

static cepCell*
calc_poc_require_dictionary(cepCell* parent, const char* name, unsigned storage)
{
    cepDT dt = cep_ops_make_dt(name);
    cepCell* child = cep_cell_ensure_dictionary_child(parent, &dt, storage);
    child = cep_cell_resolve(child);
    munit_assert_not_null(child);
    munit_assert_true(cep_cell_require_dictionary_store(&child));
    return child;
}

static void
calc_poc_seed_calc_layout(void)
{
    calc_poc_stdin_offset = 0u;
    calc_poc_stdin_size = 0u;
    calc_poc_stdout_offset = 0u;
    calc_poc_next_run_id = 1u;
    calc_poc_last_write_op = cep_oid_invalid();
    calc_poc_last_cei_had_pipeline = false;
    memset(&calc_poc_last_op_meta, 0, sizeof calc_poc_last_op_meta);

    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);
    munit_assert_true(cep_cell_require_dictionary_store(&data_root));

    cepCell* app_root = calc_poc_require_dictionary(data_root, "app", CEP_STORAGE_RED_BLACK_T);
    cepCell* calc_root = calc_poc_require_dictionary(app_root, "calc", CEP_STORAGE_RED_BLACK_T);

    /* Application branches */
    (void)calc_poc_require_dictionary(calc_root, "inbox", CEP_STORAGE_LINKED_LIST);
    (void)calc_poc_require_dictionary(calc_root, "exprs", CEP_STORAGE_RED_BLACK_T);
    (void)calc_poc_require_dictionary(calc_root, "results", CEP_STORAGE_RED_BLACK_T);
    (void)calc_poc_require_dictionary(calc_root, "outbox", CEP_STORAGE_LINKED_LIST);
    (void)calc_poc_require_dictionary(calc_root, "sent", CEP_STORAGE_LINKED_LIST);

    /* Pipeline metadata */
    cepCell* meta = calc_poc_require_dictionary(calc_root, "calc_meta", CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_put_text(meta, CEP_DTAW("CEP", "pipeline_id"), calc_layout.pipeline_id);
}

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[8];
} CalcPathBuf;

static const cepPath*
calc_poc_make_path(CalcPathBuf* buf, const char* const* segments, size_t count)
{
    munit_assert_not_null(buf);
    munit_assert_not_null(segments);
    munit_assert_size(count, <=, cep_lengthof(buf->past));

    buf->length = count;
    buf->capacity = cep_lengthof(buf->past);
    for (size_t i = 0; i < count; ++i) {
        buf->past[i].dt = cep_ops_make_dt(segments[i]);
        buf->past[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}

static cepPipelineMetadata
calc_poc_pipeline_block(const cepDT* stage_id, uint64_t dag_run_id, uint64_t hop_index)
{
    cepPipelineMetadata meta = {
        .pipeline_id = dt_calc_pipeline()->tag,
        .stage_id = stage_id ? stage_id->tag : 0u,
        .dag_run_id = dag_run_id,
        .hop_index = hop_index,
    };
    return meta;
}

static uint64_t
calc_poc_run_id_from_ctx(const cepEnzymeContext* ctx)
{
    if (ctx && ctx->has_pipeline && ctx->pipeline.dag_run_id) {
        return ctx->pipeline.dag_run_id;
    }
    return calc_poc_next_run_id++;
}

static bool
calc_poc_enqueue_stage(const char* const* signal_segments,
                       size_t signal_count,
                       const char* const* target_segments,
                       size_t target_count,
                       const cepDT* stage_dt,
                       uint64_t dag_run_id,
                       uint64_t hop_index)
{
    CalcPathBuf sig_buf = {0};
    CalcPathBuf tgt_buf = {0};
    const cepPath* signal_path = calc_poc_make_path(&sig_buf, signal_segments, signal_count);
    const cepPath* target_path = calc_poc_make_path(&tgt_buf, target_segments, target_count);
    cepPipelineMetadata meta = calc_poc_pipeline_block(stage_dt, dag_run_id, hop_index);
    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
        .qos = CEP_IMPULSE_QOS_NONE,
        .has_pipeline = true,
        .pipeline = meta,
    };
    return cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &impulse) == CEP_ENZYME_SUCCESS;
}

static void
calc_poc_seed_stdio_env(void)
{
    cepCell* env_root = cep_cell_resolve(cep_heartbeat_env_root());
    munit_assert_not_null(env_root);
    munit_assert_true(cep_cell_require_dictionary_store(&env_root));

    cepCell* stdio_root = calc_poc_require_dictionary(env_root, "stdio", CEP_STORAGE_RED_BLACK_T);

    FILE* stdin_tmp = tmpfile();
    FILE* stdout_tmp = tmpfile();
    munit_assert_not_null(stdin_tmp);
    munit_assert_not_null(stdout_tmp);

    calc_poc_stdin_fp = stdin_tmp;
    calc_poc_stdout_fp = stdout_tmp;
    calc_poc_stdin_offset = 0u;
    calc_poc_stdin_size = 0u;
    calc_poc_stdout_offset = 0u;
    rewind(calc_poc_stdin_fp);
    rewind(calc_poc_stdout_fp);

    cepCell library;
    CEP_0(&library);
    cep_stdio_library_init(&library, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdio_lib")));
    cepCell* lib_node = cep_cell_add(stdio_root, 0, &library);
    lib_node = lib_node ? cep_cell_resolve(lib_node) : NULL;
    munit_assert_not_null(lib_node);

    cepCell stdin_res;
    CEP_0(&stdin_res);
    cep_stdio_resource_init(&stdin_res, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdin")), stdin_tmp, true);
    cepCell* stdin_node = cep_cell_add(stdio_root, 0, &stdin_res);
    stdin_node = stdin_node ? cep_cell_resolve(stdin_node) : NULL;
    munit_assert_not_null(stdin_node);

    cepCell stdout_res;
    CEP_0(&stdout_res);
    cep_stdio_resource_init(&stdout_res, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdout")), stdout_tmp, true);
    cepCell* stdout_node = cep_cell_add(stdio_root, 0, &stdout_res);
    stdout_node = stdout_node ? cep_cell_resolve(stdout_node) : NULL;
    munit_assert_not_null(stdout_node);

    cepCell stdin_stream;
    CEP_0(&stdin_stream);
    cep_stdio_stream_init(&stdin_stream, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdin_str")), lib_node, stdin_node);
    munit_assert_not_null(cep_cell_add(stdio_root, 0, &stdin_stream));

    cepCell stdout_stream;
    CEP_0(&stdout_stream);
    cep_stdio_stream_init(&stdout_stream, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("stdout_str")), lib_node, stdout_node);
    munit_assert_not_null(cep_cell_add(stdio_root, 0, &stdout_stream));
}

static cepCell*
calc_poc_branch(const char* name, unsigned storage)
{
    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);
    cepCell* app_root = calc_poc_require_dictionary(data_root, "app", CEP_STORAGE_RED_BLACK_T);
    cepCell* calc_root = calc_poc_require_dictionary(app_root, "calc", CEP_STORAGE_RED_BLACK_T);
    return calc_poc_require_dictionary(calc_root, name, storage);
}

static cepCell*
calc_poc_stdio_stream(const char* name)
{
    cepCell* env_root = cep_cell_resolve(cep_heartbeat_env_root());
    munit_assert_not_null(env_root);
    cepCell* stdio_root = calc_poc_require_dictionary(env_root, "stdio", CEP_STORAGE_RED_BLACK_T);
    cepCell* stream = cep_cell_find_by_name(stdio_root, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr(name)));
    stream = stream ? cep_cell_resolve(stream) : NULL;
    munit_assert_not_null(stream);
    return stream;
}

static bool
calc_poc_copy_text_field(cepCell* parent, const cepDT* field, char* buffer, size_t capacity)
{
    if (!parent || !field || !buffer || capacity == 0u) {
        return false;
    }
    if (parent->data) {
        cepDT want = cep_dt_clean(field);
        cepDT have = cep_dt_clean(&parent->data->dt);
        if (cep_dt_compare(&want, &have) == 0 && cep_cell_has_data(parent)) {
            const char* text = (const char*)cep_cell_data(parent);
            if (text) {
                size_t len = strlen(text);
                if (len >= capacity) {
                    len = capacity - 1u;
                }
                memcpy(buffer, text, len);
                buffer[len] = '\0';
                return true;
            }
        }
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    const char* text = (const char*)cep_cell_data(child);
    if (!text) {
        return false;
    }
    size_t len = strlen(text);
    if (len >= capacity) {
        len = capacity - 1u;
    }
    memcpy(buffer, text, len);
    buffer[len] = '\0';
    return true;
}

static uint64_t
calc_poc_read_metric_u64(cepCell* metric_cell)
{
    cepCell* resolved = metric_cell ? cep_cell_resolve(metric_cell) : NULL;
    if (!resolved) {
        return 0u;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&resolved, &data) || !data || data->size == 0u) {
        return 0u;
    }
    if (data->size >= sizeof(uint64_t)) {
        uint64_t value = 0u;
        memcpy(&value, cep_data_payload(data), sizeof value);
        return value;
    }
    const char* text = (const char*)cep_data_payload(data);
    if (!text) {
        return 0u;
    }
    char* endptr = NULL;
    unsigned long long parsed = strtoull(text, &endptr, 10);
    if (endptr && *endptr == '\0') {
        return (uint64_t)parsed;
    }
    return 0u;
}

static bool
calc_poc_read_successor(cepCell* node_cell, const cepDT* field, cepDT* out)
{
    if (!node_cell || !field || !out) {
        return false;
    }
    cepCell* child = cep_cell_find_by_name(node_cell, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child) {
        return false;
    }
    if (cep_cell_has_data(child)) {
        const char* text = (const char*)cep_cell_data(child);
        if (!text || !*text) {
            return false;
        }
        cepID tag = cep_namepool_intern(text, strlen(text));
        if (!tag) {
            return false;
        }
        out->domain = CEP_ACRO("CEP");
        out->tag = tag;
        out->glob = 0u;
        return true;
    }
    if (cep_cell_require_dictionary_store(&child)) {
        uint64_t domain = 0u;
        uint64_t tag = 0u;
        cepCell* domain_cell = cep_cell_find_by_name(child, CEP_DTAW("CEP", "domain"));
        cepCell* tag_cell = cep_cell_find_by_name(child, CEP_DTAW("CEP", "tag"));
        domain_cell = domain_cell ? cep_cell_resolve(domain_cell) : NULL;
        tag_cell = tag_cell ? cep_cell_resolve(tag_cell) : NULL;
        if (domain_cell && tag_cell && cep_cell_has_data(domain_cell) && cep_cell_has_data(tag_cell)) {
            memcpy(&domain, cep_cell_data(domain_cell), sizeof domain);
            memcpy(&tag, cep_cell_data(tag_cell), sizeof tag);
            out->domain = (cepID)domain;
            out->tag = (cepID)tag;
            out->glob = 0u;
            return true;
        }
    }
    return false;
}

static void
calc_poc_emit_usage_cei(const char* topic, const char* note, const cepEnzymeContext* ctx)
{
    if (!topic) {
        return;
    }
    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:usage"),
        .topic = topic,
        .topic_intern = true,
        .note = note,
        .emit_signal = true,
    };
    if (ctx && ctx->has_pipeline) {
        req.has_pipeline = true;
        req.pipeline = ctx->pipeline;
    }
    fprintf(stderr,
            "[calc_poc] emit CEI topic=%s note=%s has_pipeline=%d pipeline_id=%" PRIu64 " stage=%" PRIu64 " run=%" PRIu64 " hop=%" PRIu64 "\n",
            topic,
            note ? note : "<none>",
            req.has_pipeline ? 1 : 0,
            (uint64_t)req.pipeline.pipeline_id,
            (uint64_t)req.pipeline.stage_id,
            (uint64_t)req.pipeline.dag_run_id,
            (uint64_t)req.pipeline.hop_index);
    bool emitted = cep_cei_emit(&req);
    if (!emitted) {
        fprintf(stderr, "[calc_poc] cei emit failed\n");
    }
    if (emitted && req.has_pipeline) {
        calc_poc_last_cei_had_pipeline = true;
    }
}

static void
calc_poc_drain_heartbeat(unsigned rounds)
{
    for (unsigned i = 0; i < rounds; ++i) {
        cepBeatNumber before = cep_heartbeat_current();
        bool ok = cep_heartbeat_step();
        if (!ok) {
            bool resolve_ok = cep_heartbeat_resolve_agenda();
            bool exec_ok = resolve_ok ? cep_heartbeat_execute_agenda() : false;
            bool commit_ok = resolve_ok && exec_ok ? cep_heartbeat_stage_commit() : false;
            fprintf(stderr,
                    "[calc_poc] heartbeat_step failed err=%d before=%" PRIu64 " current=%" PRIu64 " phase=%d paused=%d resolve=%d exec=%d commit=%d\n",
                    cep_ops_debug_last_error(),
                    (uint64_t)before,
                    (uint64_t)cep_heartbeat_current(),
                    (int)cep_beat_phase(),
                    cep_runtime_is_paused() ? 1 : 0,
                    resolve_ok ? 1 : 0,
                    exec_ok ? 1 : 0,
                    commit_ok ? 1 : 0);
        }
        munit_assert_true(ok);
    }
}

static void calc_poc_register_enzyme(cepEnzymeRegistry* registry, const char* signal_tag, cepEnzyme callback);
static void calc_poc_bind_calc_pipeline(void);
static cepCell* calc_poc_eco_root(void);
static void calc_poc_reset_calc_branches(void);
static cepCell* calc_poc_seed_l2_calc_flow(bool guardian_allow, uint64_t max_steps, const char* niche_label);
static void calc_poc_seed_decision_choice(cepCell* eco_root, const char* node_label, const char* choice_text);

static void
calc_poc_seed_l1_pipeline(void)
{
    cepL1SchemaLayout schema = {0};
    munit_assert_true(cep_l1_schema_ensure(&schema));

    cepL1PipelineMeta meta = {
        .owner = "calc_owner",
        .province = "dev",
        .version = "v1",
        .kind = "application",
        .revision = 1u,
        .max_hops = calc_layout.stage_count ? calc_layout.stage_count - 1u : 0u,
    };
    cepL1PipelineLayout layout = {0};
    munit_assert_true(cep_l1_pipeline_ensure(schema.flow_pipelines,
                                             calc_layout.pipeline_id,
                                             &meta,
                                             &layout));
    munit_assert_not_null(layout.pipeline);
    munit_assert_true(cep_cell_put_text(layout.pipeline, CEP_DTAW("CEP", "owner"), meta.owner));
    munit_assert_true(cep_cell_put_text(layout.pipeline, CEP_DTAW("CEP", "province"), meta.province));
    munit_assert_true(cep_cell_put_text(layout.pipeline, CEP_DTAW("CEP", "ver"), meta.version));
    char num_buf[32];
    snprintf(num_buf, sizeof num_buf, "%08" PRIu64, meta.revision);
    munit_assert_true(cep_cell_put_text(layout.pipeline, CEP_DTAW("CEP", "rev"), num_buf));
    if (meta.max_hops > 0u) {
        snprintf(num_buf, sizeof num_buf, "%08" PRIu64, meta.max_hops);
        munit_assert_true(cep_cell_put_text(layout.pipeline, CEP_DTAW("CEP", "max_hops"), num_buf));
    }

    static const char* stage_roles[] = {
        "prepare_features",
        "prepare_features",
        "call_learner",
        "prepare_features",
        "apply_update",
    };
    for (size_t i = 0; i < calc_layout.stage_count; ++i) {
        const char* role = (i < cep_lengthof(stage_roles)) ? stage_roles[i] : "prepare_features";
        munit_assert_true(cep_l1_pipeline_stage_stub(&layout, calc_layout.stage_ids[i], NULL));
        munit_assert_true(cep_l1_pipeline_stage_set_role(&layout, calc_layout.stage_ids[i], role));
    }

    for (size_t i = 1; i < calc_layout.stage_count; ++i) {
        munit_assert_true(cep_l1_pipeline_add_edge(&layout,
                                                   calc_layout.stage_ids[i - 1u],
                                                   calc_layout.stage_ids[i],
                                                   NULL));
    }

    cepCell* field = NULL;
    cepData* data = NULL;
    field = cep_cell_find_by_name(layout.pipeline, CEP_DTAW("CEP", "pipeline_id"));
    field = field ? cep_cell_resolve(field) : NULL;
    munit_assert_not_null(field);
    data = NULL;
    munit_assert_true(cep_cell_require_data(&field, &data));
    munit_assert_not_null(data);
    munit_assert_string_equal((const char*)cep_data_payload(data), calc_layout.pipeline_id);

    field = cep_cell_find_by_name(layout.pipeline, CEP_DTAW("CEP", "owner"));
    field = field ? cep_cell_resolve(field) : NULL;
    munit_assert_not_null(field);
    data = NULL;
    munit_assert_true(cep_cell_require_data(&field, &data));
    munit_assert_not_null(data);
    munit_assert_string_equal((const char*)cep_data_payload(data), meta.owner);

    field = cep_cell_find_by_name(layout.pipeline, CEP_DTAW("CEP", "kind"));
    field = field ? cep_cell_resolve(field) : NULL;
    munit_assert_not_null(field);
    data = NULL;
    munit_assert_true(cep_cell_require_data(&field, &data));
    munit_assert_not_null(data);
    munit_assert_string_equal((const char*)cep_data_payload(data), meta.kind);

    field = cep_cell_find_by_name(layout.pipeline, CEP_DTAW("CEP", "province"));
    field = field ? cep_cell_resolve(field) : NULL;
    munit_assert_not_null(field);
    data = NULL;
    munit_assert_true(cep_cell_require_data(&field, &data));
    munit_assert_not_null(data);
    munit_assert_string_equal((const char*)cep_data_payload(data), meta.province);

    field = cep_cell_find_by_name(layout.pipeline, CEP_DTAW("CEP", "ver"));
    field = field ? cep_cell_resolve(field) : NULL;
    munit_assert_not_null(field);
    data = NULL;
    munit_assert_true(cep_cell_require_data(&field, &data));
    munit_assert_not_null(data);
    munit_assert_string_equal((const char*)cep_data_payload(data), meta.version);

    field = cep_cell_find_by_name(layout.pipeline, CEP_DTAW("CEP", "rev"));
    field = field ? cep_cell_resolve(field) : NULL;
    munit_assert_not_null(field);
    data = NULL;
    munit_assert_true(cep_cell_require_data(&field, &data));
    munit_assert_not_null(data);
    munit_assert_size(data->size, >=, sizeof(uint64_t));
    uint64_t check_u64 = 0u;
    memcpy(&check_u64, cep_data_payload(data), sizeof check_u64);
    munit_assert_uint64(check_u64, >=, 1u);

    field = cep_cell_find_by_name(layout.pipeline, CEP_DTAW("CEP", "max_hops"));
    field = field ? cep_cell_resolve(field) : NULL;
    munit_assert_not_null(field);
    data = NULL;
    munit_assert_true(cep_cell_require_data(&field, &data));
    munit_assert_not_null(data);
    munit_assert_size(data->size, >=, sizeof(uint64_t));
    memcpy(&check_u64, cep_data_payload(data), sizeof check_u64);
    munit_assert_uint64(check_u64, >=, 1u);

    bool pipeline_ok = cep_l1_pipeline_validate_layout(&layout, calc_layout.pipeline_id);
    if (!pipeline_ok) {
        size_t stage_count = layout.stages ? cep_cell_children(layout.stages) : 0u;
        size_t edge_count = layout.edges ? cep_cell_children(layout.edges) : 0u;
        munit_errorf("pipeline validation failed stages=%zu edges=%zu", stage_count, edge_count);
    }

    munit_assert_true(cep_l1_pipeline_bind_coherence(&schema, &layout));
}

static MunitResult
calc_poc_layout_smoke(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(calc_poc_bootstrap_runtime());

    /* Seed branch layout and pipeline metadata. */
    calc_poc_seed_calc_layout();
    calc_poc_seed_l1_pipeline();
    calc_poc_seed_stdio_env();

    /* Keep the stage roster explicit for future bindings. */
    munit_assert_size(calc_layout.stage_count, ==, cep_lengthof(calc_stage_ids));
    for (size_t i = 0; i < calc_layout.stage_count; ++i) {
        munit_assert_not_null(calc_layout.stage_ids[i]);
        munit_assert_size(strlen(calc_layout.stage_ids[i]), >, 0u);
    }

    calc_poc_shutdown_runtime();
    return MUNIT_OK;
}

/* Enzymes for the calculator pipeline. Each stage enqueues the next stage with
 * pipeline metadata preserved so agenda/CEI/OPS capture the calc_basic roster. */
static int
calc_poc_stdin_source(const cepPath* signal, const cepPath* target)
{
    (void)signal;
    (void)target;
    const cepEnzymeContext* ctx = cep_enzyme_context_current();
    uint64_t run_id = calc_poc_run_id_from_ctx(ctx);
    uint64_t hop = (ctx && ctx->has_pipeline) ? ctx->pipeline.hop_index + 1u : 1u;

    cepCell* inbox = calc_poc_branch("inbox", CEP_STORAGE_LINKED_LIST);
    cepCell* stdin_stream = calc_poc_stdio_stream("stdin_str");

    char buffer[256];
    size_t read = 0u;
    size_t remaining = (calc_poc_stdin_size > calc_poc_stdin_offset)
                           ? (calc_poc_stdin_size - calc_poc_stdin_offset)
                           : 0u;
    size_t request = remaining < (sizeof buffer - 1u) ? remaining : (sizeof buffer - 1u);
    if (request == 0u) {
        fprintf(stderr, "[calc_poc] stdin empty offset=%zu\n", calc_poc_stdin_offset);
        return CEP_ENZYME_SUCCESS;
    }
    if (!cep_cell_stream_read(stdin_stream, calc_poc_stdin_offset, buffer, request, &read)) {
        fprintf(stderr,
                "[calc_poc] stdin stream read failed offset=%zu request=%zu remaining=%zu\n",
                calc_poc_stdin_offset,
                request,
                remaining);
        calc_poc_emit_usage_cei("calc.stdin.read", "stdin stream read failed", ctx);
        return CEP_ENZYME_FATAL;
    }
    buffer[read] = '\0';
    calc_poc_stdin_offset += read;

    size_t consumed = 0u;
    while (consumed < read) {
        size_t line_end = consumed;
        while (line_end < read && buffer[line_end] != '\n') {
            ++line_end;
        }
        size_t line_len = line_end - consumed;
        while (line_len > 0u && isspace((unsigned char)buffer[consumed + line_len - 1u])) {
            --line_len;
        }
        if (line_len > 0u) {
            char line_buf[256];
            size_t copy_len = line_len < sizeof line_buf - 1u ? line_len : sizeof line_buf - 1u;
            memcpy(line_buf, &buffer[consumed], copy_len);
            line_buf[copy_len] = '\0';

            cepDT entry_name = {.domain = CEP_ACRO("CEP"), .tag = CEP_AUTOID, .glob = 0u};
            cepCell* line_cell = cep_cell_add_value(inbox,
                                                    &entry_name,
                                                    0u,
                                                    CEP_DTAW("CEP", "text"),
                                                    line_buf,
                                                    copy_len + 1u,
                                                    copy_len + 1u);
            line_cell = line_cell ? cep_cell_resolve(line_cell) : NULL;
            if (line_cell) {
                (void)cep_cell_put_text(line_cell, CEP_DTAW("CEP", "app"), "calc");
                (void)cep_cell_put_uint64(line_cell, CEP_DTAW("CEP", "beat"), (uint64_t)cep_beat_index());
            }

            (void)calc_poc_enqueue_stage(calc_signal_parse,
                                         cep_lengthof(calc_signal_parse),
                                         calc_target_inbox,
                                         cep_lengthof(calc_target_inbox),
                                         dt_calc_stage_parse(),
                                         run_id,
                                         hop);
        }
        consumed = (line_end < read && buffer[line_end] == '\n') ? (line_end + 1u) : line_end;
    }

    return CEP_ENZYME_SUCCESS;
}

static int
calc_poc_parse_expr(const cepPath* signal, const cepPath* target)
{
    (void)signal;
    (void)target;
    const cepEnzymeContext* ctx = cep_enzyme_context_current();
    uint64_t run_id = calc_poc_run_id_from_ctx(ctx);
    uint64_t hop = (ctx && ctx->has_pipeline) ? ctx->pipeline.hop_index + 1u : 1u;

    cepCell* inbox = calc_poc_branch("inbox", CEP_STORAGE_LINKED_LIST);
    cepCell* exprs = calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T);

    for (cepCell* line = cep_cell_first(inbox); line; ) {
        cepCell* next = cep_cell_next(inbox, line);
        cepCell* resolved = cep_cell_resolve(line);
        const char* text = resolved && cep_cell_has_data(resolved) ? (const char*)cep_cell_data(resolved) : NULL;
        if (!text || !*text) {
            line = next;
            continue;
        }

        long long left = 0;
        long long right = 0;
        char op_char = 0;
        if (sscanf(text, "%lld %c %lld", &left, &op_char, &right) != 3 || strchr("+-*/", op_char) == NULL) {
            char note[128];
            snprintf(note, sizeof note, "parse_fail:%s", text);
            calc_poc_emit_usage_cei("calc.parse.fail", note, ctx);
            line = next;
            continue;
        }

        cepDT expr_name = line->metacell.dt;
        expr_name.glob = 0u;
        cepCell* expr = cep_cell_add_dictionary(exprs, &expr_name, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
        expr = expr ? cep_cell_resolve(expr) : NULL;
        if (expr && cep_cell_require_dictionary_store(&expr)) {
            char buf[64];
            snprintf(buf, sizeof buf, "%lld", left);
            (void)cep_cell_put_text(expr, CEP_DTAW("CEP", "left"), buf);
            snprintf(buf, sizeof buf, "%lld", right);
            (void)cep_cell_put_text(expr, CEP_DTAW("CEP", "right"), buf);
            char op_buf[2] = {op_char, '\0'};
            (void)cep_cell_put_text(expr, CEP_DTAW("CEP", "op"), op_buf);
        }

        (void)calc_poc_enqueue_stage(calc_signal_eval,
                                     cep_lengthof(calc_signal_eval),
                                     calc_target_exprs,
                                     cep_lengthof(calc_target_exprs),
                                     dt_calc_stage_eval(),
                                     run_id,
                                     hop);
        cep_cell_delete_hard(resolved);
        line = next;
    }
    return CEP_ENZYME_SUCCESS;
}

static int
calc_poc_eval_expr(const cepPath* signal, const cepPath* target)
{
    (void)signal;
    (void)target;
    const cepEnzymeContext* ctx = cep_enzyme_context_current();
    uint64_t run_id = calc_poc_run_id_from_ctx(ctx);
    uint64_t hop = (ctx && ctx->has_pipeline) ? ctx->pipeline.hop_index + 1u : 1u;

    cepCell* exprs = calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T);
    cepCell* results = calc_poc_branch("results", CEP_STORAGE_RED_BLACK_T);

    for (cepCell* expr = cep_cell_first(exprs); expr; ) {
        cepCell* next = cep_cell_next(exprs, expr);
        cepCell* resolved = cep_cell_resolve(expr);
        if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
            expr = next;
            continue;
        }

        char left_buf[64] = {0};
        char right_buf[64] = {0};
        char op_buf[8] = {0};
        if (!calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "left"), left_buf, sizeof left_buf) ||
            !calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "right"), right_buf, sizeof right_buf) ||
            !calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "op"), op_buf, sizeof op_buf)) {
            expr = next;
            continue;
        }

        char* endptr = NULL;
        errno = 0;
        long long left = strtoll(left_buf, &endptr, 10);
        if (errno != 0 || !endptr || *endptr) {
            calc_poc_emit_usage_cei("calc.eval.parse_left", "invalid left operand", ctx);
            expr = next;
            continue;
        }
        endptr = NULL;
        errno = 0;
        long long right = strtoll(right_buf, &endptr, 10);
        if (errno != 0 || !endptr || *endptr) {
            calc_poc_emit_usage_cei("calc.eval.parse_right", "invalid right operand", ctx);
            expr = next;
            continue;
        }

        char op_char = op_buf[0];
        long long value = 0;
        bool valid = true;
        switch (op_char) {
            case '+': value = left + right; break;
            case '-': value = left - right; break;
            case '*': value = left * right; break;
            case '/':
                if (right == 0) {
                    calc_poc_emit_usage_cei("calc.eval.div_zero", "division by zero", ctx);
                    valid = false;
                } else {
                    value = left / right;
                }
                break;
            default:
                valid = false;
                calc_poc_emit_usage_cei("calc.eval.unknown_op", "unknown operator", ctx);
                break;
        }
        if (!valid) {
            expr = next;
            continue;
        }

        char value_buf[64];
        snprintf(value_buf, sizeof value_buf, "%lld", value);
        cepDT result_name = expr->metacell.dt;
        result_name.glob = 0u;
        cepCell* result = cep_cell_add_dictionary(results, &result_name, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
        result = result ? cep_cell_resolve(result) : NULL;
        if (result && cep_cell_require_dictionary_store(&result)) {
            (void)cep_cell_put_text(result, CEP_DTAW("CEP", "left"), left_buf);
            (void)cep_cell_put_text(result, CEP_DTAW("CEP", "right"), right_buf);
            (void)cep_cell_put_text(result, CEP_DTAW("CEP", "op"), op_buf);
            (void)cep_cell_put_text(result, CEP_DTAW("CEP", "value"), value_buf);
        }

        (void)calc_poc_enqueue_stage(calc_signal_fmt,
                                     cep_lengthof(calc_signal_fmt),
                                     calc_target_results,
                                     cep_lengthof(calc_target_results),
                                     dt_calc_stage_fmt(),
                                     run_id,
                                     hop);
        cep_cell_delete_hard(resolved);
        expr = next;
    }
    return CEP_ENZYME_SUCCESS;
}

static int
calc_poc_format_result(const cepPath* signal, const cepPath* target)
{
    (void)signal;
    (void)target;
    const cepEnzymeContext* ctx = cep_enzyme_context_current();
    uint64_t run_id = calc_poc_run_id_from_ctx(ctx);
    uint64_t hop = (ctx && ctx->has_pipeline) ? ctx->pipeline.hop_index + 1u : 1u;

    cepCell* results = calc_poc_branch("results", CEP_STORAGE_RED_BLACK_T);
    cepCell* outbox = calc_poc_branch("outbox", CEP_STORAGE_LINKED_LIST);

    for (cepCell* res = cep_cell_first(results); res; ) {
        cepCell* next = cep_cell_next(results, res);
        cepCell* resolved = cep_cell_resolve(res);
        if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
            res = next;
            continue;
        }

        char left_buf[64] = {0};
        char right_buf[64] = {0};
        char op_buf[8] = {0};
        char value_buf[64] = {0};
        if (!calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "left"), left_buf, sizeof left_buf) ||
            !calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "right"), right_buf, sizeof right_buf) ||
            !calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "op"), op_buf, sizeof op_buf) ||
            !calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "value"), value_buf, sizeof value_buf)) {
            res = next;
            continue;
        }

        char formatted[192];
        snprintf(formatted, sizeof formatted, "%s %s %s = %s", left_buf, op_buf, right_buf, value_buf);
        size_t formatted_len = strlen(formatted);

        cepDT out_name = res->metacell.dt;
        out_name.glob = 0u;
        (void)cep_cell_add_value(outbox,
                                 &out_name,
                                 0u,
                                 CEP_DTAW("CEP", "text"),
                                 formatted,
                                 formatted_len + 1u,
                                 formatted_len + 1u);
        (void)calc_poc_enqueue_stage(calc_signal_write,
                                     cep_lengthof(calc_signal_write),
                                     calc_target_outbox,
                                     cep_lengthof(calc_target_outbox),
                                     dt_calc_stage_write(),
                                     run_id,
                                     hop);
        cep_cell_delete_hard(resolved);
        res = next;
    }
    return CEP_ENZYME_SUCCESS;
}

static int
calc_poc_stdout_sink(const cepPath* signal, const cepPath* target)
{
    (void)signal;
    (void)target;
    const cepEnzymeContext* ctx = cep_enzyme_context_current();
    uint64_t run_id = calc_poc_run_id_from_ctx(ctx);
    uint64_t hop = (ctx && ctx->has_pipeline) ? ctx->pipeline.hop_index + 1u : 1u;

    cepCell* outbox = calc_poc_branch("outbox", CEP_STORAGE_LINKED_LIST);
    cepCell* sent = calc_poc_branch("sent", CEP_STORAGE_LINKED_LIST);
    cepCell* stdout_stream = calc_poc_stdio_stream("stdout_str");

    cepPipelineMetadata pipeline = calc_poc_pipeline_block(dt_calc_stage_write(), run_id, hop);
    cepOID op = cep_op_start(*dt_calc_op_write(), "/env/stdio/stdout", *dt_calc_op_mode(), NULL, 0u, 0u);
    calc_poc_last_write_op = op;
    calc_poc_last_op_meta = pipeline;
    if (cep_oid_is_valid(op)) {
        (void)cep_op_set_pipeline_metadata(op, &pipeline);
    }

    for (cepCell* entry = cep_cell_first(outbox); entry; ) {
        cepCell* next = cep_cell_next(outbox, entry);
        cepCell* resolved = cep_cell_resolve(entry);
        const char* text = resolved && cep_cell_has_data(resolved) ? (const char*)cep_cell_data(resolved) : NULL;
        if (!text || !*text) {
            entry = next;
            continue;
        }
        char line_buf[256];
        snprintf(line_buf, sizeof line_buf, "%s\n", text);

        size_t written = 0u;
        if (!cep_cell_stream_write(stdout_stream, calc_poc_stdout_offset, line_buf, strlen(line_buf), &written)) {
            calc_poc_emit_usage_cei("calc.stdout.write", "stdout write failed", ctx);
            entry = next;
            continue;
        }
        calc_poc_stdout_offset += written;

        cepDT sent_name = entry->metacell.dt;
        sent_name.glob = 0u;
        (void)cep_cell_add_value(sent,
                                 &sent_name,
                                 0u,
                                 CEP_DTAW("CEP", "text"),
                                 (void*)text,
                                 strlen(text) + 1u,
                                 strlen(text) + 1u);
        cep_cell_delete_hard(resolved);
        entry = next;
    }

    (void)cep_stream_commit_pending();
    if (cep_oid_is_valid(op)) {
        (void)cep_op_close(op, *CEP_DTAW("CEP", "sts:ok"), "ok", sizeof("ok") - 1u);
    }
    return CEP_ENZYME_SUCCESS;
}

static MunitResult
calc_poc_runtime_smoke(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(calc_poc_bootstrap_runtime());
    calc_poc_seed_calc_layout();
    munit_assert_true(cep_namepool_bootstrap());
    cepL1SchemaLayout l1_layout = {0};
    munit_assert_true(cep_l1_schema_ensure(&l1_layout));
    (void)cep_l1_pack_shutdown();
    if (!cep_l1_pack_bootstrap()) {
        int last_err = cep_ops_debug_last_error();
        cepCell* diag = cep_cei_diagnostics_mailbox();
        diag = diag ? cep_cell_resolve(diag) : NULL;
        size_t diag_count = 0u;
        char diag_topics[256] = {0};
        if (diag) {
            cepCell* msgs = cep_cell_find_by_name(diag, CEP_DTAW("CEP", "msgs"));
            msgs = msgs ? cep_cell_resolve(msgs) : diag;
            diag_count = msgs ? cep_cell_children(msgs) : 0u;
            size_t offset = 0u;
            for (cepCell* entry = msgs ? cep_cell_first(msgs) : NULL; entry; entry = cep_cell_next(msgs, entry)) {
                cepCell* resolved = cep_cell_resolve(entry);
                cepCell* topic_cell = resolved ? cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "topic")) : NULL;
                topic_cell = topic_cell ? cep_cell_resolve(topic_cell) : NULL;
                const char* topic_text = topic_cell && cep_cell_has_data(topic_cell) ? (const char*)cep_cell_data(topic_cell) : "<null>";
                if (offset + strlen(topic_text) + 2u < sizeof diag_topics) {
                    offset += snprintf(diag_topics + offset, sizeof diag_topics - offset, "%s,", topic_text);
                }
            }
        }
        munit_errorf("cep_l1_pack_bootstrap failed (kernel_ready=%d namepool_ready=%d registry=%p last_err=%d diag_count=%zu diag_topics=%s)",
                     cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL) ? 1 : 0,
                     cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL) ? 1 : 0,
                     (void*)cep_heartbeat_registry(),
                     last_err,
                     diag_count,
                     diag_topics);
    }
    calc_poc_seed_l1_pipeline();
    calc_poc_seed_stdio_env();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    calc_poc_register_enzyme(registry, "sig:calc/read", calc_poc_stdin_source);
    calc_poc_register_enzyme(registry, "sig:calc/parse", calc_poc_parse_expr);
    calc_poc_register_enzyme(registry, "sig:calc/eval", calc_poc_eval_expr);
    calc_poc_register_enzyme(registry, "sig:calc/fmt", calc_poc_format_result);
    calc_poc_register_enzyme(registry, "sig:calc/write", calc_poc_stdout_sink);
    cep_enzyme_registry_activate_pending(registry);
    calc_poc_bind_calc_pipeline();

    /* Seed stdin with one valid expression and one malformed line to exercise
     * CEI propagation. */
    munit_assert_not_null(calc_poc_stdin_fp);
    fseeko(calc_poc_stdin_fp, 0, SEEK_SET);
    fprintf(calc_poc_stdin_fp, "2 + 3\nbad\n");
    fflush(calc_poc_stdin_fp);
    calc_poc_stdin_offset = 0u;
    off_t stdin_size = ftello(calc_poc_stdin_fp);
    calc_poc_stdin_size = (stdin_size >= 0) ? (size_t)stdin_size : 0u;

    uint64_t run_id = calc_poc_run_id_from_ctx(NULL);
    munit_assert_true(calc_poc_enqueue_stage(calc_signal_read,
                                             cep_lengthof(calc_signal_read),
                                             calc_target_inbox,
                                             cep_lengthof(calc_target_inbox),
                                             dt_calc_stage_read(),
                                             run_id,
                                             0u));

    cepCell* sent = calc_poc_branch("sent", CEP_STORAGE_LINKED_LIST);
    size_t attempts = 0u;
    while (cep_cell_children(sent) == 0u && attempts < 8u) {
        calc_poc_drain_heartbeat(1);
        fprintf(stderr,
                "[calc_poc] attempt=%zu inbox=%zu exprs=%zu results=%zu outbox=%zu sent=%zu\n",
                attempts,
                cep_cell_children(calc_poc_branch("inbox", CEP_STORAGE_LINKED_LIST)),
                cep_cell_children(calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T)),
                cep_cell_children(calc_poc_branch("results", CEP_STORAGE_RED_BLACK_T)),
                cep_cell_children(calc_poc_branch("outbox", CEP_STORAGE_LINKED_LIST)),
                cep_cell_children(sent));
        attempts++;
    }
    munit_assert_size(cep_cell_children(sent), >=, 1u);

    cepCell* sent_first = cep_cell_resolve(cep_cell_first(sent));
    munit_assert_not_null(sent_first);
    char sent_buf[128] = {0};
    munit_assert_true(calc_poc_copy_text_field(sent_first, CEP_DTAW("CEP", "text"), sent_buf, sizeof sent_buf));
    munit_assert_string_equal(sent_buf, "2 + 3 = 5");

    munit_assert_not_null(calc_poc_stdout_fp);
    rewind(calc_poc_stdout_fp);
    char stdout_buf[256] = {0};
    size_t stdout_read = fread(stdout_buf, 1, sizeof stdout_buf - 1u, calc_poc_stdout_fp);
    stdout_buf[stdout_read] = '\0';
    munit_assert_not_null(strstr(stdout_buf, "2 + 3 = 5"));
    fprintf(stderr, "[calc_poc] L0 pipeline finished\n");

    /* Beat logs should record impulses and agenda sequencing for the calc pipeline. */
    const char* expected_stages[] = {"sig:calc/read", "sig:calc/parse", "sig:calc/eval", "sig:calc/fmt", "sig:calc/write"};
    size_t stage_idx = 0u;
    bool saw_impulse = false;
    bool saw_impulse_pipeline = false;
    cepCell* rt_root = cep_cell_resolve(cep_heartbeat_rt_root());
    munit_assert_not_null(rt_root);
    cepCell* beat_root = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "beat"));
    beat_root = beat_root ? cep_cell_resolve(beat_root) : NULL;
    fprintf(stderr, "[calc_poc] rt beats=%zu\n", beat_root ? cep_cell_children(beat_root) : 0u);
    for (cepCell* beat = beat_root ? cep_cell_first(beat_root) : NULL;
         beat && stage_idx < cep_lengthof(expected_stages);
         beat = cep_cell_next(beat_root, beat)) {
        cepCell* beat_cell = cep_cell_resolve(beat);
        if (!beat_cell) {
            continue;
        }

        cepCell* impulses = cep_cell_find_by_name(beat_cell, CEP_DTAW("CEP", "impulses"));
        impulses = impulses ? cep_cell_resolve(impulses) : NULL;
        if (!impulses) {
            impulses = cep_cell_find_by_name(beat_cell, CEP_DTAW("CEP", "inbox"));
            impulses = impulses ? cep_cell_resolve(impulses) : NULL;
        }
        if (impulses) {
            for (cepCell* row = cep_cell_first(impulses); row; row = cep_cell_next(impulses, row)) {
                cepCell* resolved = cep_cell_resolve(row);
                if (!resolved || !cep_cell_has_data(resolved)) {
                    continue;
                }
                const char* message = (const char*)cep_cell_data(resolved);
                if (!message) {
                    continue;
                }
                fprintf(stderr, "[calc_poc] impulse message=%s\n", message);
                saw_impulse = true;
                if (strstr(message, calc_layout.pipeline_id) || strstr(message, "calc")) {
                    saw_impulse_pipeline = true;
                }
            }
        }

        cepCell* agenda = cep_cell_find_by_name(beat_cell, CEP_DTAW("CEP", "agenda"));
        agenda = agenda ? cep_cell_resolve(agenda) : NULL;
        if (!agenda) {
            continue;
        }
        for (cepCell* row = cep_cell_first(agenda); row && stage_idx < cep_lengthof(expected_stages); row = cep_cell_next(agenda, row)) {
            cepCell* resolved = cep_cell_resolve(row);
            if (!resolved || !cep_cell_has_data(resolved)) {
                continue;
            }
            const char* message = (const char*)cep_cell_data(resolved);
            fprintf(stderr, "[calc_poc] agenda beat message=%s\n", message ? message : "<null>");
            if (message && strstr(message, expected_stages[stage_idx])) {
                stage_idx++;
            }
        }
    }
    munit_assert_true(saw_impulse);
    munit_assert_true(saw_impulse_pipeline);
    munit_assert_size(stage_idx, ==, cep_lengthof(expected_stages));

    /* CEI should carry pipeline metadata on parse failure. */
    cepCell* diag = cep_cei_diagnostics_mailbox();
    diag = diag ? cep_cell_resolve(diag) : NULL;
    munit_assert_not_null(diag);
    cepCell* diag_msgs = cep_cell_find_by_name(diag, CEP_DTAW("CEP", "msgs"));
    diag_msgs = diag_msgs ? cep_cell_resolve(diag_msgs) : diag;
    bool diag_has_pipeline = calc_poc_last_cei_had_pipeline;
    if (!diag_has_pipeline) {
        for (cepCell* entry = cep_cell_first(diag_msgs); entry; entry = cep_cell_next(diag_msgs, entry)) {
            cepCell* resolved = cep_cell_resolve(entry);
            if (!resolved) {
                continue;
            }
            cepCell* pipeline_block = cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "pipeline"));
            pipeline_block = pipeline_block ? cep_cell_resolve(pipeline_block) : NULL;
            if (!pipeline_block) {
                continue;
            }
            cepCell* pid = cep_cell_find_by_name(pipeline_block, CEP_DTAW("CEP", "pipeline_id"));
            pid = pid ? cep_cell_resolve(pid) : NULL;
            if (pid && cep_cell_has_data(pid)) {
                const char* text = (const char*)cep_cell_data(pid);
                if (text && strcmp(text, calc_layout.pipeline_id) == 0) {
                    diag_has_pipeline = true;
                    break;
                }
            }
        }
    }
    munit_assert_true(diag_has_pipeline);

    /* OPS pipeline metadata is attached to the stdout op. */
    munit_assert_uint64((uint64_t)calc_poc_last_op_meta.pipeline_id, ==, (uint64_t)dt_calc_pipeline()->tag);
    munit_assert_uint64(calc_poc_last_op_meta.dag_run_id, ==, run_id);
    munit_assert_uint64((uint64_t)calc_poc_last_op_meta.stage_id, ==, (uint64_t)dt_calc_stage_write()->tag);

    /* Layer 2: run the calc flow with variant decisions and clamp/guardian wiring. */
    munit_assert_true(cep_l2_bootstrap());
    calc_poc_reset_calc_branches();
    cepCell* eco_root = calc_poc_eco_root();
    munit_assert_true(cep_l2_runtime_seed_runtime(eco_root));

    cepCell* runtime_root = calc_poc_require_dictionary(eco_root, "runtime", CEP_STORAGE_RED_BLACK_T);
    cepCell* metrics_root = calc_poc_require_dictionary(runtime_root, "metrics", CEP_STORAGE_RED_BLACK_T);
    cepCell* per_variant = calc_poc_require_dictionary(metrics_root, "per_variant", CEP_STORAGE_RED_BLACK_T);
    cepCell* decisions_root = calc_poc_require_dictionary(runtime_root, "decisions", CEP_STORAGE_RED_BLACK_T);
    cep_cell_clear_children(decisions_root);

    cepCell* exprs = calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T);
    cepDT expr_auto_dt = cep_ops_make_dt("l2_expr_auto");
    cepCell* expr_auto = cep_cell_add_dictionary(exprs, &expr_auto_dt, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    expr_auto = expr_auto ? cep_cell_resolve(expr_auto) : NULL;
    munit_assert_not_null(expr_auto);
    (void)cep_cell_put_text(expr_auto, CEP_DTAW("CEP", "left"), "4");
    (void)cep_cell_put_text(expr_auto, CEP_DTAW("CEP", "right"), "1");
    (void)cep_cell_put_text(expr_auto, CEP_DTAW("CEP", "op"), "+");

    cepCell* flow = calc_poc_seed_l2_calc_flow(true, 4u, "int_small");
    munit_assert_not_null(flow);
    calc_poc_seed_decision_choice(eco_root, "calc_decide", "variant:calc_fast");
    char flow_pipeline_id[64] = {0};
    munit_assert_true(calc_poc_copy_text_field(flow, CEP_DTAW("CEP", "pipeline_id"), flow_pipeline_id, sizeof flow_pipeline_id));
    munit_assert_string_equal(flow_pipeline_id, calc_layout.pipeline_id);
    cepCell* flows_root = flow ? cep_cell_resolve(cep_cell_parent(flow)) : NULL;
    cepCell* organisms_root = calc_poc_require_dictionary(runtime_root, "organisms", CEP_STORAGE_RED_BLACK_T);
    size_t flows_count = flows_root ? cep_cell_children(flows_root) : 0u;
    size_t org_count = organisms_root ? cep_cell_children(organisms_root) : 0u;
    cepCell* graph_root = calc_poc_require_dictionary(flow, "graph", CEP_STORAGE_RED_BLACK_T);
    cepCell* nodes_root = calc_poc_require_dictionary(graph_root, "nodes", CEP_STORAGE_RED_BLACK_T);
    size_t node_count = nodes_root ? cep_cell_children(nodes_root) : 0u;
    size_t decisions_before = cep_cell_children(decisions_root);
    bool pump_ok = cep_l2_runtime_scheduler_pump(eco_root);
    int last_err = cep_ops_debug_last_error();
    fprintf(stderr, "[calc_poc] l2 pump ok=%d flows=%zu orgs=%zu nodes=%zu err=%d\n",
            pump_ok ? 1 : 0,
            flows_count,
            org_count,
            node_count,
            last_err);
    if (!pump_ok) {
        cepCell* diag_local = cep_cei_diagnostics_mailbox();
        diag_local = diag_local ? cep_cell_resolve(diag_local) : NULL;
        cepCell* diag_msgs_local = diag_local ? cep_cell_find_by_name(diag_local, CEP_DTAW("CEP", "msgs")) : NULL;
        diag_msgs_local = diag_msgs_local ? cep_cell_resolve(diag_msgs_local) : diag_local;
        fprintf(stderr, "[calc_poc] diag entries=%zu\n", diag_msgs_local ? cep_cell_children(diag_msgs_local) : 0u);
        for (cepCell* entry = diag_msgs_local ? cep_cell_first(diag_msgs_local) : NULL; entry;
             entry = cep_cell_next(diag_msgs_local, entry)) {
            cepCell* resolved = cep_cell_resolve(entry);
            if (!resolved) {
                continue;
            }
            cepCell* topic_cell = cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "topic"));
            topic_cell = topic_cell ? cep_cell_resolve(topic_cell) : NULL;
            const char* topic_text = topic_cell && cep_cell_has_data(topic_cell) ? (const char*)cep_cell_data(topic_cell) : NULL;
            cepCell* note_cell = cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "note"));
            note_cell = note_cell ? cep_cell_resolve(note_cell) : NULL;
            const char* note_text = note_cell && cep_cell_has_data(note_cell) ? (const char*)cep_cell_data(note_cell) : NULL;
            fprintf(stderr, "[calc_poc] diag topic=%s note=%s\n", topic_text ? topic_text : "<none>", note_text ? note_text : "<none>");
        }
    }
    munit_assert_true(pump_ok);

    cepCell* results = calc_poc_branch("results", CEP_STORAGE_RED_BLACK_T);
    cepCell* auto_res = cep_cell_find_by_name(results, &expr_auto_dt);
    auto_res = auto_res ? cep_cell_resolve(auto_res) : NULL;
    munit_assert_not_null(auto_res);
    char auto_value[64] = {0};
    munit_assert_true(calc_poc_copy_text_field(auto_res, CEP_DTAW("CEP", "value"), auto_value, sizeof auto_value));
    munit_assert_string_equal(auto_value, "5");

    munit_assert_size(cep_cell_children(decisions_root), >, decisions_before);
    fprintf(stderr, "[calc_poc] decisions_after_first=%zu\n", cep_cell_children(decisions_root));
    size_t decision_idx = 0u;
    for (cepCell* entry = cep_cell_first(decisions_root); entry; entry = cep_cell_next(decisions_root, entry)) {
        cepCell* resolved = cep_cell_resolve(entry);
        cepCell* pipeline_block = resolved ? cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "pipeline")) : NULL;
        pipeline_block = pipeline_block ? cep_cell_resolve(pipeline_block) : NULL;
        cepDT node_dt = {0};
        calc_poc_read_successor(resolved, CEP_DTAW("CEP", "node"), &node_dt);
        char node_text[64] = {0};
        (void)calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "node"), node_text, sizeof node_text);
        const char* node_lookup = cep_namepool_lookup(node_dt.tag, NULL);
        char choice_buf[64] = {0};
        if (resolved) {
            (void)calc_poc_copy_text_field(resolved, CEP_DTAW("CEP", "choice"), choice_buf, sizeof choice_buf);
        }
        fprintf(stderr,
                "[calc_poc] decision_entry[%zu] node_tag=%llu node_lookup=%s node_text=%s choice=%s pipeline_children=%zu\n",
                decision_idx,
                (unsigned long long)node_dt.tag,
                node_lookup ? node_lookup : "<null>",
                node_text,
                choice_buf,
                pipeline_block ? cep_cell_children(pipeline_block) : 0u);
        decision_idx++;
    }
    cepCell* decision_entry = NULL;
    cepCell* decision_pipeline = NULL;
    for (cepCell* entry = cep_cell_first(decisions_root); entry; entry = cep_cell_next(decisions_root, entry)) {
        cepCell* resolved = cep_cell_resolve(entry);
        if (!resolved) {
            continue;
        }
        cepCell* pipeline_block = cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "pipeline"));
        pipeline_block = pipeline_block ? cep_cell_resolve(pipeline_block) : NULL;
        if (!decision_entry) {
            decision_entry = resolved;
            decision_pipeline = pipeline_block;
        }
        if (pipeline_block && cep_cell_children(pipeline_block) > 0u) {
            decision_entry = resolved;
            decision_pipeline = pipeline_block;
            break;
        }
    }
    munit_assert_not_null(decision_entry);
    munit_assert_not_null(decision_pipeline);
    char decision_choice[64] = {0};
    munit_assert_true(calc_poc_copy_text_field(decision_entry, CEP_DTAW("CEP", "choice"), decision_choice, sizeof decision_choice));
    bool decision_fast = strstr(decision_choice, "calc_fast") != NULL;
    const cepDT* chosen_variant_dt = decision_fast ? dt_calc_variant_fast() : dt_calc_variant_safe();
    fprintf(stderr,
            "[calc_poc] decision choice=%s variant_tag=%llu fast_tag=%llu safe_tag=%llu\n",
            decision_choice,
            (unsigned long long)chosen_variant_dt->tag,
            (unsigned long long)dt_calc_variant_fast()->tag,
            (unsigned long long)dt_calc_variant_safe()->tag);

    char decision_pipeline_id[64] = {0};
    bool pipeline_id_ok = calc_poc_copy_text_field(decision_pipeline, CEP_DTAW("CEP", "pipeline_id"), decision_pipeline_id, sizeof decision_pipeline_id);
    if (pipeline_id_ok && strcmp(decision_pipeline_id, calc_layout.pipeline_id) != 0) {
        char* endptr = NULL;
        unsigned long long pid_val = strtoull(decision_pipeline_id, &endptr, 10);
        pipeline_id_ok = endptr && *endptr == '\0' && pid_val == (unsigned long long)dt_calc_pipeline()->tag;
    }
    if (!pipeline_id_ok) {
        cepCell* pid_cell = cep_cell_find_by_name(decision_pipeline, CEP_DTAW("CEP", "pipeline_id"));
        pid_cell = pid_cell ? cep_cell_resolve(pid_cell) : NULL;
        if (pid_cell) {
            cepData* pid_data = NULL;
            if (cep_cell_require_data(&pid_cell, &pid_data) && pid_data && pid_data->size >= sizeof(uint64_t)) {
                uint64_t pid_u64 = 0u;
                memcpy(&pid_u64, cep_data_payload(pid_data), sizeof pid_u64);
                pipeline_id_ok = pid_u64 == (uint64_t)dt_calc_pipeline()->tag;
            }
        }
    }
    munit_assert_true(pipeline_id_ok);

    cepCell* chosen_bucket = cep_cell_find_by_name(per_variant, chosen_variant_dt);
    chosen_bucket = chosen_bucket ? cep_cell_resolve(chosen_bucket) : NULL;
    munit_assert_not_null(chosen_bucket);
    cepCell* chosen_metric = cep_cell_find_by_name(chosen_bucket, dt_calc_metric_eval());
    chosen_metric = chosen_metric ? cep_cell_resolve(chosen_metric) : NULL;
    munit_assert_not_null(chosen_metric);
    uint64_t chosen_metric_count = calc_poc_read_metric_u64(chosen_metric);
    munit_assert_uint64(chosen_metric_count, >=, 1u);
    fprintf(stderr, "[calc_poc] L2 decision logged choice=%s\n", decision_choice);
    fprintf(stderr, "[calc_poc] metrics after first run=%" PRIu64 "\n", chosen_metric_count);

    calc_poc_reset_calc_branches();
    exprs = calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T);
    cepDT expr_replay_dt = cep_ops_make_dt("l2_expr_replay");
    cepCell* expr_replay = cep_cell_add_dictionary(exprs, &expr_replay_dt, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    expr_replay = expr_replay ? cep_cell_resolve(expr_replay) : NULL;
    munit_assert_not_null(expr_replay);
    (void)cep_cell_put_text(expr_replay, CEP_DTAW("CEP", "left"), "7");
    (void)cep_cell_put_text(expr_replay, CEP_DTAW("CEP", "right"), "3");
    (void)cep_cell_put_text(expr_replay, CEP_DTAW("CEP", "op"), "*");

    size_t decisions_before_replay = cep_cell_children(decisions_root);
    fprintf(stderr, "[calc_poc] decisions_before_replay=%zu\n", decisions_before_replay);
    uint64_t metric_before_replay = chosen_metric_count;
    (void)calc_poc_seed_l2_calc_flow(true, 4u, "int_small");
    munit_assert_true(cep_l2_runtime_scheduler_pump(eco_root));

    results = calc_poc_branch("results", CEP_STORAGE_RED_BLACK_T);
    cepCell* replay_res = cep_cell_find_by_name(results, &expr_replay_dt);
    replay_res = replay_res ? cep_cell_resolve(replay_res) : NULL;
    munit_assert_not_null(replay_res);
    char replay_value[64] = {0};
    munit_assert_true(calc_poc_copy_text_field(replay_res, CEP_DTAW("CEP", "value"), replay_value, sizeof replay_value));
    munit_assert_string_equal(replay_value, "21");

    chosen_metric = cep_cell_find_by_name(per_variant, chosen_variant_dt);
    chosen_metric = chosen_metric ? cep_cell_resolve(chosen_metric) : NULL;
    munit_assert_not_null(chosen_metric);
    cepCell* replay_metric = cep_cell_find_by_name(chosen_metric, dt_calc_metric_eval());
    replay_metric = replay_metric ? cep_cell_resolve(replay_metric) : NULL;
    munit_assert_not_null(replay_metric);
    uint64_t metric_after_replay = calc_poc_read_metric_u64(replay_metric);
    fprintf(stderr, "[calc_poc] decisions_after_replay=%zu\n", cep_cell_children(decisions_root));
    fprintf(stderr,
            "[calc_poc] metrics replay before=%" PRIu64 " after=%" PRIu64 "\n",
            metric_before_replay,
            metric_after_replay);
    munit_assert_size(cep_cell_children(decisions_root), ==, decisions_before_replay);
    munit_assert_uint64(metric_after_replay, >, metric_before_replay);

    calc_poc_reset_calc_branches();
    bool force_fast = !decision_fast;
    const char* forced_choice = force_fast ? "variant:calc_fast" : "variant:calc_safe";
    for (cepCell* entry = cep_cell_first(decisions_root); entry; ) {
        cepCell* next = cep_cell_next(decisions_root, entry);
        cepCell* resolved = cep_cell_resolve(entry);
        if (resolved) {
            (void)cep_cell_delete_hard(resolved);
        }
        entry = next;
    }

    exprs = calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T);
    cepDT expr_forced_dt = cep_ops_make_dt("l2_expr_forced");
    cepCell* expr_forced = cep_cell_add_dictionary(exprs, &expr_forced_dt, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    expr_forced = expr_forced ? cep_cell_resolve(expr_forced) : NULL;
    munit_assert_not_null(expr_forced);
    if (force_fast) {
        (void)cep_cell_put_text(expr_forced, CEP_DTAW("CEP", "left"), "6");
        (void)cep_cell_put_text(expr_forced, CEP_DTAW("CEP", "right"), "4");
        (void)cep_cell_put_text(expr_forced, CEP_DTAW("CEP", "op"), "+");
        (void)calc_poc_seed_l2_calc_flow(true, 4u, "int_small");
    } else {
        (void)cep_cell_put_text(expr_forced, CEP_DTAW("CEP", "left"), "100");
        (void)cep_cell_put_text(expr_forced, CEP_DTAW("CEP", "right"), "5");
        (void)cep_cell_put_text(expr_forced, CEP_DTAW("CEP", "op"), "/");
        (void)calc_poc_seed_l2_calc_flow(true, 4u, "int_big");
    }
    calc_poc_seed_decision_choice(eco_root, "calc_decide", forced_choice);

    uint64_t forced_metric_before = 0u;
    const cepDT* forced_variant_dt = force_fast ? dt_calc_variant_fast() : dt_calc_variant_safe();
    cepCell* forced_bucket = cep_cell_find_by_name(per_variant, forced_variant_dt);
    forced_bucket = forced_bucket ? cep_cell_resolve(forced_bucket) : NULL;
    if (forced_bucket) {
        cepCell* forced_metric = cep_cell_find_by_name(forced_bucket, dt_calc_metric_eval());
        forced_metric = forced_metric ? cep_cell_resolve(forced_metric) : NULL;
        if (forced_metric) {
            forced_metric_before = calc_poc_read_metric_u64(forced_metric);
        }
    }

    munit_assert_true(cep_l2_runtime_scheduler_pump(eco_root));

    results = calc_poc_branch("results", CEP_STORAGE_RED_BLACK_T);
    cepCell* forced_res = cep_cell_find_by_name(results, &expr_forced_dt);
    forced_res = forced_res ? cep_cell_resolve(forced_res) : NULL;
    munit_assert_not_null(forced_res);
    char forced_value[64] = {0};
    munit_assert_true(calc_poc_copy_text_field(forced_res, CEP_DTAW("CEP", "value"), forced_value, sizeof forced_value));
    if (force_fast) {
        munit_assert_string_equal(forced_value, "10");
    } else {
        munit_assert_string_equal(forced_value, "20");
    }

    forced_bucket = cep_cell_find_by_name(per_variant, forced_variant_dt);
    forced_bucket = forced_bucket ? cep_cell_resolve(forced_bucket) : NULL;
    munit_assert_not_null(forced_bucket);
    cepCell* forced_metric = cep_cell_find_by_name(forced_bucket, dt_calc_metric_eval());
    forced_metric = forced_metric ? cep_cell_resolve(forced_metric) : NULL;
    munit_assert_not_null(forced_metric);
    uint64_t forced_metric_after = calc_poc_read_metric_u64(forced_metric);
    munit_assert_uint64(forced_metric_after, >, forced_metric_before);

    diag = cep_cei_diagnostics_mailbox();
    diag = diag ? cep_cell_resolve(diag) : NULL;
    munit_assert_not_null(diag);
    diag_msgs = cep_cell_find_by_name(diag, CEP_DTAW("CEP", "msgs"));
    diag_msgs = diag_msgs ? cep_cell_resolve(diag_msgs) : diag;
    size_t diag_before = cep_cell_children(diag_msgs);

    calc_poc_reset_calc_branches();
    for (cepCell* entry = cep_cell_first(decisions_root); entry; ) {
        cepCell* next = cep_cell_next(decisions_root, entry);
        cepCell* resolved = cep_cell_resolve(entry);
        if (resolved) {
            (void)cep_cell_delete_hard(resolved);
        }
        entry = next;
    }
    exprs = calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T);
    cepDT expr_guard_dt = cep_ops_make_dt("l2_expr_guard");
    cepCell* expr_guard = cep_cell_add_dictionary(exprs, &expr_guard_dt, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    expr_guard = expr_guard ? cep_cell_resolve(expr_guard) : NULL;
    munit_assert_not_null(expr_guard);
    (void)cep_cell_put_text(expr_guard, CEP_DTAW("CEP", "left"), "8");
    (void)cep_cell_put_text(expr_guard, CEP_DTAW("CEP", "right"), "0");
    (void)cep_cell_put_text(expr_guard, CEP_DTAW("CEP", "op"), "/");

    (void)calc_poc_seed_l2_calc_flow(false, 1u, "int_small");
    calc_poc_seed_decision_choice(eco_root, "calc_decide", "variant:calc_safe");
    (void)cep_l2_runtime_scheduler_pump(eco_root);

    diag = cep_cei_diagnostics_mailbox();
    diag = diag ? cep_cell_resolve(diag) : NULL;
    diag_msgs = cep_cell_find_by_name(diag, CEP_DTAW("CEP", "msgs"));
    diag_msgs = diag_msgs ? cep_cell_resolve(diag_msgs) : diag;
    size_t diag_after = cep_cell_children(diag_msgs);
    fprintf(stderr, "[calc_poc] diag_before=%zu diag_after=%zu\n", diag_before, diag_after);
    munit_assert_size(diag_after, >, diag_before);
    bool saw_guardian = diag_after > diag_before;
    bool saw_limit = false;
    if (!saw_guardian) {
        for (cepCell* entry = cep_cell_first(diag_msgs); entry; entry = cep_cell_next(diag_msgs, entry)) {
            cepCell* resolved = cep_cell_resolve(entry);
            if (!resolved) {
                continue;
            }
            cepDT topic_dt = {0};
            const char* topic_text = NULL;
            cepCell* topic_cell = cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "topic"));
            topic_cell = topic_cell ? cep_cell_resolve(topic_cell) : NULL;
            if (topic_cell) {
                (void)calc_poc_read_successor(resolved, CEP_DTAW("CEP", "topic"), &topic_dt);
                if (cep_cell_has_data(topic_cell)) {
                    topic_text = (const char*)cep_cell_data(topic_cell);
                }
            }
            const char* topic_lookup = topic_dt.tag ? cep_namepool_lookup(topic_dt.tag, NULL) : NULL;
            if ((topic_text && strstr(topic_text, "eco.guardian.violation")) ||
                (topic_lookup && strstr(topic_lookup, "eco.guardian.violation"))) {
                saw_guardian = true;
            }
            if ((topic_text && strstr(topic_text, "eco.limit.hit")) ||
                (topic_lookup && strstr(topic_lookup, "eco.limit.hit"))) {
                saw_limit = true;
            }
            if (saw_guardian || saw_limit) {
                break;
            }
        }
    }
    munit_assert_true(saw_guardian || saw_limit);
    fprintf(stderr, "[calc_poc] L2 guardian/limit check done\n");

    /* Keep the existing RuntimeRunTracker checks to ensure L1 scaffolding remains wired. */
    cepL1SchemaLayout schema = {0};
    munit_assert_true(cep_l1_schema_ensure(&schema));

    cepPipelineMetadata meta = {
        .pipeline_id = dt_calc_pipeline()->tag,
        .stage_id = dt_calc_stage_read()->tag,
        .dag_run_id = run_id,
        .hop_index = 0u,
    };

    cepCell* run = NULL;
    munit_assert_true(cep_l1_runtime_record_run(schema.flow_runs,
                                                calc_layout.pipeline_id,
                                                meta.dag_run_id,
                                                "running",
                                                NULL,
                                                &run));
    munit_assert_not_null(run);

    munit_assert_true(cep_l1_runtime_configure_stage_fanin(run, "calc_parse", 1u));
    munit_assert_true(cep_l1_runtime_record_stage_state(run, "calc_parse", "pending", meta.hop_index));
    munit_assert_true(cep_l1_runtime_mark_stage_ready(run, "calc_read", true));
    munit_assert_true(cep_l1_runtime_record_trigger(run, "calc_read", "impulse", "stdin line", cep_heartbeat_current()));

    munit_assert_true(cep_l1_runtime_validate_runs(schema.flow_runs, schema.flow_pipelines));

    size_t diag_missing_base = cep_cell_children(diag_msgs);
    cepCell* runs_missing = calc_poc_require_dictionary(schema.flow_runtime, "runs_missing_meta", CEP_STORAGE_RED_BLACK_T);
    cepDT bad_run_dt = cep_ops_make_dt("calc_missing_meta");
    cepCell* bad_run = cep_cell_add_dictionary(runs_missing, &bad_run_dt, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    bad_run = bad_run ? cep_cell_resolve(bad_run) : NULL;
    munit_assert_not_null(bad_run);
    munit_assert_false(cep_l1_runtime_validate_runs(runs_missing, schema.flow_pipelines));

    diag = cep_cei_diagnostics_mailbox();
    diag = diag ? cep_cell_resolve(diag) : NULL;
    munit_assert_not_null(diag);
    diag_msgs = cep_cell_find_by_name(diag, CEP_DTAW("CEP", "msgs"));
    diag_msgs = diag_msgs ? cep_cell_resolve(diag_msgs) : diag;
    munit_assert_size(cep_cell_children(diag_msgs), >, diag_missing_base);
    bool saw_missing_meta = cep_cell_children(diag_msgs) > diag_missing_base;
    if (!saw_missing_meta) {
        for (cepCell* entry = cep_cell_first(diag_msgs); entry; entry = cep_cell_next(diag_msgs, entry)) {
            cepCell* resolved = cep_cell_resolve(entry);
            if (!resolved) {
                continue;
            }
            cepCell* topic_cell = cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "topic"));
            topic_cell = topic_cell ? cep_cell_resolve(topic_cell) : NULL;
            if (!topic_cell || !cep_cell_has_data(topic_cell)) {
                continue;
            }
            const char* topic_text = (const char*)cep_cell_data(topic_cell);
            if (topic_text && strstr(topic_text, "flow.pipeline.missing_metadata")) {
                saw_missing_meta = true;
                break;
            }
        }
    }
    munit_assert_true(saw_missing_meta);

    (void)cep_l2_shutdown();

    calc_poc_shutdown_runtime();
    return MUNIT_OK;
}

static void
calc_poc_register_enzyme(cepEnzymeRegistry* registry,
                         const char* signal_tag,
                         cepEnzyme callback)
{
    munit_assert_not_null(registry);
    cepEnzymeDescriptor desc = {
        .name = cep_ops_make_dt(signal_tag),
        .label = signal_tag,
        .callback = callback,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    CalcPathBuf buf = {0};
    const char* segments[] = {signal_tag};
    const cepPath* query = calc_poc_make_path(&buf, segments, cep_lengthof(segments));
    munit_assert_int(cep_enzyme_register(registry, query, &desc), ==, CEP_ENZYME_SUCCESS);
}

static void
calc_poc_bind_calc_pipeline(void)
{
    cepCell* inbox = calc_poc_branch("inbox", CEP_STORAGE_LINKED_LIST);
    cepCell* exprs = calc_poc_branch("exprs", CEP_STORAGE_RED_BLACK_T);
    cepCell* results = calc_poc_branch("results", CEP_STORAGE_RED_BLACK_T);
    cepCell* outbox = calc_poc_branch("outbox", CEP_STORAGE_LINKED_LIST);

    cepDT read_dt = cep_ops_make_dt(calc_signal_read[0]);
    cepDT parse_dt = cep_ops_make_dt(calc_signal_parse[0]);
    cepDT eval_dt = cep_ops_make_dt(calc_signal_eval[0]);
    cepDT fmt_dt = cep_ops_make_dt(calc_signal_fmt[0]);
    cepDT write_dt = cep_ops_make_dt(calc_signal_write[0]);

    munit_assert_int(cep_cell_bind_enzyme(inbox, &read_dt, false), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(inbox, &parse_dt, false), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(exprs, &eval_dt, false), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(results, &fmt_dt, false), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(outbox, &write_dt, false), ==, CEP_ENZYME_SUCCESS);
}

static cepCell*
calc_poc_eco_root(void)
{
    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);
    return calc_poc_require_dictionary(data_root, "eco", CEP_STORAGE_RED_BLACK_T);
}

static void
calc_poc_reset_calc_branches(void)
{
    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);
    cepCell* app_root = calc_poc_require_dictionary(data_root, "app", CEP_STORAGE_RED_BLACK_T);
    cepCell* calc_root = calc_poc_require_dictionary(app_root, "calc", CEP_STORAGE_RED_BLACK_T);

    struct {
        const char* name;
        unsigned storage;
    } branches[] = {
        {"exprs", CEP_STORAGE_RED_BLACK_T},
        {"results", CEP_STORAGE_RED_BLACK_T},
        {"outbox", CEP_STORAGE_LINKED_LIST},
        {"sent", CEP_STORAGE_LINKED_LIST},
    };

    for (size_t i = 0; i < cep_lengthof(branches); ++i) {
        cepDT dt = cep_ops_make_dt(branches[i].name);
        cepCell* existing = cep_cell_find_by_name(calc_root, &dt);
        existing = existing ? cep_cell_resolve(existing) : NULL;
        if (existing) {
            fprintf(stderr, "[calc_poc] resetting %s\n", branches[i].name);
            (void)cep_cell_delete_hard(existing);
        }
        (void)calc_poc_require_dictionary(calc_root, branches[i].name, branches[i].storage);
    }
}

static cepCell*
calc_poc_seed_l2_calc_flow(bool guardian_allow, uint64_t max_steps, const char* niche_label)
{
    cepCell* eco_root = calc_poc_eco_root();
    cepCell* species_root = calc_poc_require_dictionary(eco_root, "species", CEP_STORAGE_RED_BLACK_T);
    cepCell* variants_root = calc_poc_require_dictionary(eco_root, "variants", CEP_STORAGE_RED_BLACK_T);
    cepCell* niches_root = calc_poc_require_dictionary(eco_root, "niches", CEP_STORAGE_RED_BLACK_T);
    cepCell* guardians_root = calc_poc_require_dictionary(eco_root, "guardians", CEP_STORAGE_RED_BLACK_T);
    cepCell* flows_root = calc_poc_require_dictionary(eco_root, "flows", CEP_STORAGE_RED_BLACK_T);

    (void)cep_cell_ensure_dictionary_child(species_root, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_eval")), CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_ensure_dictionary_child(variants_root, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_safe")), CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_ensure_dictionary_child(variants_root, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr("calc_fast")), CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_ensure_dictionary_child(niches_root, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr("int_small")), CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_ensure_dictionary_child(niches_root, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr("int_big")), CEP_STORAGE_RED_BLACK_T);

    cepDT guardian_dt = cep_ops_make_dt("calc_eval_guard");
    cepCell* guardian = cep_cell_ensure_dictionary_child(guardians_root, &guardian_dt, CEP_STORAGE_RED_BLACK_T);
    guardian = guardian ? cep_cell_resolve(guardian) : NULL;
    munit_assert_not_null(guardian);
    (void)cep_cell_put_uint64(guardian, CEP_DTAW("CEP", "allow"), guardian_allow ? 1u : 0u);
    (void)cep_cell_put_text(guardian, CEP_DTAW("CEP", "on_violate"), guardian_allow ? "soft" : "hard");

    cepDT flow_dt = cep_ops_make_dt("calc_eval_flow");
    cepCell* existing_flow = cep_cell_find_by_name(flows_root, &flow_dt);
    existing_flow = existing_flow ? cep_cell_resolve(existing_flow) : NULL;
    if (existing_flow) {
        (void)cep_cell_delete_hard(existing_flow);
    }
    cepCell* flow = cep_cell_ensure_dictionary_child(flows_root, &flow_dt, CEP_STORAGE_RED_BLACK_T);
    flow = flow ? cep_cell_resolve(flow) : NULL;
    munit_assert_not_null(flow);
    munit_assert_true(cep_cell_require_dictionary_store(&flow));
    (void)cep_cell_put_text(flow, CEP_DTAW("CEP", "pipeline_id"), calc_layout.pipeline_id);
    (void)cep_cell_put_text(flow, CEP_DTAW("CEP", "stage_id"), "calc_eval");
    (void)cep_cell_put_text(flow, CEP_DTAW("CEP", "species"), "calc_eval");
    if (niche_label) {
        (void)cep_cell_put_text(flow, CEP_DTAW("CEP", "niche"), niche_label);
    }

    cepCell* graph = calc_poc_require_dictionary(flow, "graph", CEP_STORAGE_RED_BLACK_T);
    cepCell* nodes = calc_poc_require_dictionary(graph, "nodes", CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_put_text(nodes, CEP_DTAW("CEP", "entry"), "calc_guard");

    cepDT guard_name = cep_ops_make_dt("calc_guard");
    cepCell* guard = cep_cell_add_dictionary(nodes, &guard_name, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    guard = guard ? cep_cell_resolve(guard) : NULL;
    munit_assert_not_null(guard);
    (void)cep_cell_put_text(guard, CEP_DTAW("CEP", "node_type"), "guard");
    (void)cep_cell_put_text(guard, CEP_DTAW("CEP", "next"), "calc_decide");

    cepDT decide_name = cep_ops_make_dt("calc_decide");
    cepCell* decide = cep_cell_add_dictionary(nodes, &decide_name, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    decide = decide ? cep_cell_resolve(decide) : NULL;
    munit_assert_not_null(decide);
    (void)cep_cell_put_text(decide, CEP_DTAW("CEP", "node_type"), "decide");
    (void)cep_cell_put_text(decide, CEP_DTAW("CEP", "next"), "calc_transform");
    cepCell* choices = calc_poc_require_dictionary(decide, "choices", CEP_STORAGE_RED_BLACK_T);

    cepCell* choice_safe = cep_cell_add_dictionary(choices, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr("choice_safe")), 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    choice_safe = choice_safe ? cep_cell_resolve(choice_safe) : NULL;
    munit_assert_not_null(choice_safe);
    (void)cep_cell_put_text(choice_safe, CEP_DTAW("CEP", "choice"), "variant:calc_safe");
    (void)cep_cell_put_text(choice_safe, CEP_DTAW("CEP", "next"), "calc_transform");

    cepCell* choice_fast = cep_cell_add_dictionary(choices, CEP_DTS(CEP_ACRO("CEP"), cep_namepool_intern_cstr("choice_fast")), 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    choice_fast = choice_fast ? cep_cell_resolve(choice_fast) : NULL;
    munit_assert_not_null(choice_fast);
    (void)cep_cell_put_text(choice_fast, CEP_DTAW("CEP", "choice"), "variant:calc_fast");
    (void)cep_cell_put_text(choice_fast, CEP_DTAW("CEP", "next"), "calc_transform");

    cepDT xform_name = cep_ops_make_dt("calc_transform");
    cepCell* xform = cep_cell_add_dictionary(nodes, &xform_name, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    xform = xform ? cep_cell_resolve(xform) : NULL;
    munit_assert_not_null(xform);
    (void)cep_cell_put_text(xform, CEP_DTAW("CEP", "node_type"), "transform");
    (void)cep_cell_put_text(xform, CEP_DTAW("CEP", "next"), "calc_clamp");
    cepCell* actions = calc_poc_require_dictionary(xform, "actions", CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_put_text(actions, CEP_DTAW("CEP", "action_hist"), "history");
    (void)cep_cell_put_text(actions, CEP_DTAW("CEP", "action_eval"), "calc_eval");

    cepDT clamp_name = cep_ops_make_dt("calc_clamp");
    cepCell* clamp = cep_cell_add_dictionary(nodes, &clamp_name, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    clamp = clamp ? cep_cell_resolve(clamp) : NULL;
    munit_assert_not_null(clamp);
    (void)cep_cell_put_text(clamp, CEP_DTAW("CEP", "node_type"), "clamp");
    cepCell* budgets = calc_poc_require_dictionary(clamp, "budgets", CEP_STORAGE_RED_BLACK_T);
    (void)cep_cell_put_uint64(budgets, CEP_DTAW("CEP", "max_steps"), max_steps);
    (void)cep_cell_put_uint64(budgets, CEP_DTAW("CEP", "max_beats"), 4u);
    (void)cep_cell_put_text(clamp, CEP_DTAW("CEP", "guardian"), "calc_eval_guard");

    return flow;
}

static void
calc_poc_seed_decision_choice(cepCell* eco_root, const char* node_label, const char* choice_text)
{
    cepCell* runtime_root = calc_poc_require_dictionary(eco_root, "runtime", CEP_STORAGE_RED_BLACK_T);
    cepCell* decisions = calc_poc_require_dictionary(runtime_root, "decisions", CEP_STORAGE_RED_BLACK_T);
    cep_cell_clear_children(decisions);

    cepDT entry_dt = cep_ops_make_dt("calc_decision_seed");
    cepCell* entry = cep_cell_add_dictionary(decisions, &entry_dt, 0u, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    munit_assert_not_null(entry);
    if (node_label) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "node"), node_label);
    }
    if (choice_text) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "choice"), choice_text);
    }
}

static MunitResult
calc_poc_binding_smoke(const MunitParameter params[], void* user_data_or_fixture)
{
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(calc_poc_bootstrap_runtime());
    calc_poc_seed_calc_layout();
    calc_poc_seed_l1_pipeline();
    calc_poc_seed_stdio_env();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    calc_poc_register_enzyme(registry, "sig:calc/read", calc_poc_stdin_source);
    calc_poc_register_enzyme(registry, "sig:calc/parse", calc_poc_parse_expr);
    calc_poc_register_enzyme(registry, "sig:calc/eval", calc_poc_eval_expr);
    calc_poc_register_enzyme(registry, "sig:calc/fmt", calc_poc_format_result);
    calc_poc_register_enzyme(registry, "sig:calc/write", calc_poc_stdout_sink);
    cep_enzyme_registry_activate_pending(registry);

    calc_poc_bind_calc_pipeline();

    /* Resolve an impulse with pipeline metadata attached. */
    CalcPathBuf sig_buf = {0};
    const char* sig_segments[] = {"sig:calc/read"};
    const cepPath* signal_path = calc_poc_make_path(&sig_buf, sig_segments, cep_lengthof(sig_segments));

    CalcPathBuf tgt_buf = {0};
    const char* tgt_segments[] = {"data", "app", "calc", "inbox"};
    const cepPath* target_path = calc_poc_make_path(&tgt_buf, tgt_segments, cep_lengthof(tgt_segments));

    cepPipelineMetadata pipeline = {
        .pipeline_id = cep_ops_make_dt(calc_layout.pipeline_id).tag,
        .stage_id = cep_ops_make_dt("calc_read").tag,
        .dag_run_id = 1u,
        .hop_index = 0u,
    };

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
        .qos = CEP_IMPULSE_QOS_NONE,
        .has_pipeline = true,
        .pipeline = pipeline,
    };

    const cepEnzymeDescriptor* ordered[4] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, >=, 1u);
    munit_assert_ptr_not_null(ordered[0]);
    munit_assert_true(ordered[0]->name.tag == pipeline.stage_id || ordered[0]->name.tag == cep_ops_make_dt("sig:calc/read").tag);

    calc_poc_shutdown_runtime();
    return MUNIT_OK;
}

static MunitTest calc_poc_tests[] = {
    {
        "/layout",
        calc_poc_layout_smoke,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/binding",
        calc_poc_binding_smoke,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/runtime",
        calc_poc_runtime_smoke,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

MunitSuite calc_poc_suite = {
    .prefix = "/calc_poc",
    .tests = calc_poc_tests,
    .suites = NULL,
    .iterations = 1,
    .options = MUNIT_SUITE_OPTION_NONE,
};
