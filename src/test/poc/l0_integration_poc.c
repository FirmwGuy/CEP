/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

#include "test.h"

#include "cep_cei.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_l0.h"
#include "cep_mailbox.h"
#include "cep_namepool.h"
#include "cep_ops.h"
#include "cep_organ.h"
#include "cep_serialization.h"
#include "cep_ep.h"
#include "stream/cep_stream_internal.h"
#include "stream/cep_stream_stdio.h"

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
    float position[3];
} IntegrationPoint;

typedef struct {
    cepOID   boot_oid;
    cepCell* poc_root;
    cepCell* catalog;
    cepCell* log_branch;
    cepCell* space_root;
    cepCell* space_entry;
    cepDT    item_type;
    cepDT    log_type;
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} IntegrationFixture;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  segments[6];
} IntegrationPathBuf;

typedef struct {
    uint64_t offset;
    uint64_t requested;
    uint64_t actual;
    uint64_t hash;
    uint32_t flags;
    uint32_t reserved;
    uint64_t unix_ts_ns;
} IntegrationStreamJournalEntry;

static const cepPath* integration_make_path(IntegrationPathBuf* buf,
                                            const cepDT* segments,
                                            unsigned count) {
    munit_assert_uint(count, <=, cep_lengthof(buf->segments));
    buf->length = count;
    buf->capacity = cep_lengthof(buf->segments);
    for (unsigned i = 0; i < count; ++i) {
        buf->segments[i].dt = segments[i];
        buf->segments[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}

static int integration_index_calls;
static int integration_aggregate_calls;
static int integration_continuation_calls;
static int integration_timeout_calls;
static int integration_call_order[8];
static size_t integration_call_count;
static int integration_prr_calls;
static int integration_organ_ctor_calls;
static int integration_organ_validator_calls;
static int integration_organ_destructor_calls;
static int integration_random_enzyme_count;
static void integration_debug_mark(const char* label, cepBeatNumber beat) {
    if (!label) {
        label = "";
    }
    CEP_DEBUG_PRINTF_STDOUT("[integration_poc] beat=%llu %s", (unsigned long long)beat, label);
}

static bool integration_organ_dts_ready;
static const char* integration_organ_kind = "integration_poc";
static cepDT integration_organ_store_dt;
static cepDT integration_organ_validator_dt;
static cepDT integration_organ_constructor_dt;
static cepDT integration_organ_destructor_dt;

typedef struct {
    IntegrationPathBuf signal_buf;
    IntegrationPathBuf target_buf;
    const cepPath*     signal_prefix;
    const cepPath*     target_path;
    cepDT              enzyme_index_dt;
    cepDT              enzyme_aggregate_dt;
    cepDT              after_list[1];
    cepEnzymeDescriptor index_desc;
    cepEnzymeDescriptor aggregate_desc;
    bool               registered;
    bool               bound;
    bool               queued;
} IntegrationCatalogPlan;

typedef struct {
    IntegrationPathBuf prefix_buf;
    IntegrationPathBuf target_buf;
    IntegrationPathBuf signal_bufs[8];
    const cepPath*     prefix_path;
    const cepPath*     target_path;
    cepDT              enzyme_dt;
    cepEnzymeDescriptor descriptor;
    uint32_t           seed;
    unsigned           planned;
    bool               registered;
    bool               bound;
} IntegrationRandomPlan;

typedef struct {
    IntegrationPathBuf cont_buf;
    IntegrationPathBuf tmo_buf;
    const cepPath*     cont_path;
    const cepPath*     tmo_path;
    cepEnzymeDescriptor cont_desc;
    cepEnzymeDescriptor tmo_desc;
    cepOID             op_oid;
    cepCell*           op_cell;
    bool               registered;
    bool               bound;
} IntegrationOpsContext;

typedef struct {
    cepCell* stream_root;
    cepCell* library_node;
    cepCell* resource_node;
    cepCell* stream_node;
    FILE*    backing;
    bool     prepared;
} IntegrationStreamContext;

typedef struct {
    cepCell* stream;
    size_t   offset;
    atomic_bool guard_result;
} IntegrationEpisodeProbe;

typedef struct {
    cepCell* target;
    cepPath* path;
    atomic_bool first_denied;
    atomic_bool second_allowed;
    atomic_bool third_denied;
} IntegrationLeaseProbe;
typedef struct {
    cepCell*    target;
    cepPath*    path;
    atomic_uint stage;
    atomic_bool promoted;
    atomic_bool demoted;
    atomic_bool ro_guard;
} IntegrationHybridProbe;


typedef struct {
    cepTxn txn;
    cepDT  txn_name;
    cepDT  staged_name;
    bool   began;
} IntegrationTxnContext;

typedef struct {
    IntegrationPathBuf signal_buf;
    IntegrationPathBuf target_buf;
    const cepPath*     signal_path;
    const cepPath*     target_path;
    cepEnzymeDescriptor desc;
    bool               registered;
    unsigned           committed;
} IntegrationPauseResumeContext;

static cepDT integration_named_dt(const char* tag);
static int integration_index_enzyme(const cepPath* signal, const cepPath* target);
static int integration_aggregate_enzyme(const cepPath* signal, const cepPath* target);
static int integration_random_enzyme_callback(const cepPath* signal, const cepPath* target);
static uint32_t integration_prng_next(uint32_t* state);
static int integration_ops_continuation(const cepPath* signal, const cepPath* target);
static int integration_ops_timeout(const cepPath* signal, const cepPath* target);
static cepCell* integration_find_op_cell(cepOID oid);
static cepCell* integration_diag_msgs(void);
static cepCell* integration_mailbox_runtime(void);
static void integration_mailbox_plan_retention(cepCell* mailbox_root, cepCell* message);
static int integration_prr_enzyme(const cepPath* signal, const cepPath* target);
static void integration_serialize_and_replay(IntegrationFixture* fix);
static void integration_exercise_organ_lifecycle(IntegrationFixture* fix);
static void integration_randomized_mutations(IntegrationFixture* fix);
static void integration_teardown_tree(IntegrationFixture* fix);

typedef struct {
    uint8_t* data;
    size_t   size;
} IntegrationCaptureChunk;

typedef struct {
    IntegrationCaptureChunk* chunks;
    size_t                   count;
    size_t                   capacity;
} IntegrationSerializationCapture;

static bool integration_capture_append(IntegrationSerializationCapture* capture,
                                       const uint8_t* chunk,
                                       size_t size) {
    if (!capture || !chunk || !size) {
        return false;
    }

    if (capture->count == capture->capacity) {
        size_t next = capture->capacity ? (capture->capacity * 2u) : 4u;
        IntegrationCaptureChunk* grown = capture->chunks
            ? cep_realloc(capture->chunks, next * sizeof *capture->chunks)
            : cep_malloc(next * sizeof *capture->chunks);
        if (!grown) {
            return false;
        }
        memset(grown + capture->capacity, 0, (next - capture->capacity) * sizeof *grown);
        capture->chunks = grown;
        capture->capacity = next;
    }

    uint8_t* copy = cep_malloc(size);
    if (!copy) {
        return false;
    }
    memcpy(copy, chunk, size);
    capture->chunks[capture->count].data = copy;
    capture->chunks[capture->count].size = size;
    capture->count += 1u;
    return true;
}

static bool integration_capture_sink(void* ctx, const uint8_t* chunk, size_t size) {
    return integration_capture_append((IntegrationSerializationCapture*)ctx, chunk, size);
}

static void integration_capture_clear(IntegrationSerializationCapture* capture) {
    if (!capture) {
        return;
    }
    if (capture->chunks) {
        for (size_t i = 0; i < capture->count; ++i) {
            cep_free(capture->chunks[i].data);
        }
        cep_free(capture->chunks);
    }
    capture->chunks = NULL;
    capture->count = 0u;
    capture->capacity = 0u;
}

static void integration_catalog_plan_setup(IntegrationCatalogPlan* plan,
                                           IntegrationFixture* fix) {
    if (!plan || !fix || !fix->catalog) {
        return;
    }
    memset(plan, 0, sizeof *plan);

    const cepDT signal_segments[] = {
        *CEP_DTAW("CEP", "sig"),
        *CEP_DTAW("CEP", "poc"),
        *CEP_DTAW("CEP", "reindex"),
    };
    plan->signal_prefix = integration_make_path(&plan->signal_buf,
                                                signal_segments,
                                                cep_lengthof(signal_segments));

    const cepDT target_segments[] = {
        *CEP_DTAW("CEP", "data"),
        *CEP_DTAW("CEP", "poc"),
        *CEP_DTAW("CEP", "catalog"),
    };
    plan->target_path = integration_make_path(&plan->target_buf,
                                              target_segments,
                                              cep_lengthof(target_segments));

    plan->enzyme_index_dt = *CEP_DTAW("CEP", "enz:poc_idx");
    plan->enzyme_aggregate_dt = *CEP_DTAW("CEP", "enz:poc_agg");
    plan->after_list[0] = plan->enzyme_index_dt;

    plan->index_desc = (cepEnzymeDescriptor){
        .name = plan->enzyme_index_dt,
        .label = "integration-index",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_index_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    plan->aggregate_desc = (cepEnzymeDescriptor){
        .name = plan->enzyme_aggregate_dt,
        .label = "integration-aggregate",
        .before = NULL,
        .before_count = 0u,
        .after = plan->after_list,
        .after_count = cep_lengthof(plan->after_list),
        .callback = integration_aggregate_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    integration_index_calls = 0;
    integration_aggregate_calls = 0;
    integration_call_count = 0u;
    memset(integration_call_order, 0, sizeof integration_call_order);

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_int(cep_enzyme_register(registry,
                                         plan->signal_prefix,
                                         &plan->index_desc),
                     ==,
                     CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry,
                                         plan->signal_prefix,
                                         &plan->aggregate_desc),
                     ==,
                     CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    plan->registered = true;

    munit_assert_int(cep_cell_bind_enzyme(fix->catalog,
                                          &plan->enzyme_index_dt,
                                          true),
                     ==,
                     CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(fix->catalog,
                                          &plan->enzyme_aggregate_dt,
                                          false),
                     ==,
                     CEP_ENZYME_SUCCESS);
    plan->bound = true;
}

static void integration_catalog_plan_queue_reindex(IntegrationCatalogPlan* plan) {
    munit_assert_not_null(plan);
    munit_assert_not_null(plan->target_path);
    munit_assert_not_null(plan->signal_prefix);
    munit_assert_false(plan->queued);

    munit_assert_int(cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                                  plan->signal_prefix,
                                                  plan->target_path),
                     ==,
                     CEP_ENZYME_SUCCESS);
    plan->queued = true;
}

static void integration_catalog_plan_verify(const IntegrationCatalogPlan* plan) {
    (void)plan;
    munit_assert_size(integration_call_count, ==, 2u);
    munit_assert_int(integration_call_order[0], ==, 1);
    munit_assert_int(integration_call_order[1], ==, 2);
    munit_assert_int(integration_index_calls, ==, 1);
    munit_assert_int(integration_aggregate_calls, ==, 1);
}

static void integration_catalog_plan_cleanup(IntegrationCatalogPlan* plan,
                                             IntegrationFixture* fix) {
    if (!plan) {
        return;
    }
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (plan->bound && fix && fix->catalog) {
        munit_assert_int(cep_cell_unbind_enzyme(fix->catalog,
                                                &plan->enzyme_index_dt),
                         ==,
                         CEP_ENZYME_SUCCESS);
        munit_assert_int(cep_cell_unbind_enzyme(fix->catalog,
                                                &plan->enzyme_aggregate_dt),
                         ==,
                         CEP_ENZYME_SUCCESS);
    }
    if (plan->registered && registry) {
        munit_assert_int(cep_enzyme_unregister(registry,
                                               plan->signal_prefix,
                                               &plan->aggregate_desc),
                         ==,
                         CEP_ENZYME_SUCCESS);
        munit_assert_int(cep_enzyme_unregister(registry,
                                               plan->signal_prefix,
                                               &plan->index_desc),
                         ==,
                         CEP_ENZYME_SUCCESS);
        cep_enzyme_registry_activate_pending(registry);
    }
    memset(plan, 0, sizeof *plan);
}

static void integration_random_plan_setup(IntegrationRandomPlan* plan,
                                          IntegrationFixture* fix) {
    if (!plan || !fix || !fix->catalog) {
        return;
    }
    memset(plan, 0, sizeof *plan);

    plan->seed = UINT32_C(0xA5C1E37B);
    plan->planned = cep_lengthof(plan->signal_bufs);
    plan->enzyme_dt = integration_named_dt("enz:poc_rand");

    const cepDT prefix_segments[] = {
        *CEP_DTAW("CEP", "sig"),
        *CEP_DTAW("CEP", "poc"),
        *CEP_DTAW("CEP", "rand"),
    };
    plan->prefix_path = integration_make_path(&plan->prefix_buf,
                                              prefix_segments,
                                              cep_lengthof(prefix_segments));

    const cepDT target_segments[] = {
        *CEP_DTAW("CEP", "data"),
        *CEP_DTAW("CEP", "poc"),
        *CEP_DTAW("CEP", "catalog"),
    };
    plan->target_path = integration_make_path(&plan->target_buf,
                                              target_segments,
                                              cep_lengthof(target_segments));

    plan->descriptor = (cepEnzymeDescriptor){
        .name = plan->enzyme_dt,
        .label = "integration-rand-enzyme",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_random_enzyme_callback,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    integration_random_enzyme_count = 0;

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_int(cep_enzyme_register(registry,
                                         plan->prefix_path,
                                         &plan->descriptor),
                     ==,
                     CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    plan->registered = true;

    munit_assert_int(cep_cell_bind_enzyme(fix->catalog,
                                          &plan->descriptor.name,
                                          false),
                     ==,
                     CEP_ENZYME_SUCCESS);
    plan->bound = true;

    CEP_DEBUG_PRINTF_STDOUT("[integration_poc] rand_seed=0x%08x planned=%u",
                            plan->seed,
                            plan->planned);
}

static void integration_random_plan_queue(IntegrationRandomPlan* plan) {
    munit_assert_not_null(plan);
    munit_assert_true(plan->registered);
    munit_assert_true(plan->bound);

    for (unsigned i = 0; i < plan->planned; ++i) {
        uint32_t roll = integration_prng_next(&plan->seed);
        char suffix[16];
        snprintf(suffix, sizeof suffix, "rand_%02u", (unsigned)(roll & 0x3F));
        cepDT dynamic_dt = integration_named_dt(suffix);

        const cepDT signal_segments[] = {
            *CEP_DTAW("CEP", "sig"),
            *CEP_DTAW("CEP", "poc"),
            *CEP_DTAW("CEP", "rand"),
            dynamic_dt,
        };
        const cepPath* signal_path = integration_make_path(&plan->signal_bufs[i],
                                                            signal_segments,
                                                            cep_lengthof(signal_segments));
        munit_assert_int(cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                                      signal_path,
                                                      plan->target_path),
                         ==,
                         CEP_ENZYME_SUCCESS);
    }
}

static void integration_random_plan_verify(const IntegrationRandomPlan* plan) {
    munit_assert_not_null(plan);
    munit_assert_size((size_t)integration_random_enzyme_count,
                      ==,
                      (size_t)plan->planned);
}

static void integration_random_plan_cleanup(IntegrationRandomPlan* plan,
                                            IntegrationFixture* fix) {
    if (!plan) {
        return;
    }
    if (plan->bound && fix && fix->catalog) {
        munit_assert_int(cep_cell_unbind_enzyme(fix->catalog,
                                                &plan->descriptor.name),
                         ==,
                         CEP_ENZYME_SUCCESS);
    }
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (plan->registered && registry) {
        munit_assert_int(cep_enzyme_unregister(registry,
                                               plan->prefix_path,
                                               &plan->descriptor),
                         ==,
                         CEP_ENZYME_SUCCESS);
        cep_enzyme_registry_activate_pending(registry);
    }
    memset(plan, 0, sizeof *plan);
}

static void integration_ops_ctx_setup(IntegrationOpsContext* ctx,
                                      IntegrationFixture* fix) {
    if (!ctx || !fix) {
        return;
    }
    memset(ctx, 0, sizeof *ctx);

    const cepDT cont_segments[] = { cep_ops_make_dt("op/cont") };
    const cepDT tmo_segments[] = { cep_ops_make_dt("op/tmo") };
    ctx->cont_path = integration_make_path(&ctx->cont_buf,
                                           cont_segments,
                                           cep_lengthof(cont_segments));
    ctx->tmo_path = integration_make_path(&ctx->tmo_buf,
                                          tmo_segments,
                                          cep_lengthof(tmo_segments));

    const cepDT cont_signal_dt = cont_segments[0];
    const cepDT tmo_signal_dt = tmo_segments[0];

    ctx->cont_desc = (cepEnzymeDescriptor){
        .name = cont_signal_dt,
        .label = "integration-op-cont",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_ops_continuation,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    ctx->tmo_desc = (cepEnzymeDescriptor){
        .name = tmo_signal_dt,
        .label = "integration-op-tmo",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_ops_timeout,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    integration_continuation_calls = 0;
    integration_timeout_calls = 0;

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_int(cep_enzyme_register(registry,
                                         ctx->cont_path,
                                         &ctx->cont_desc),
                     ==,
                     CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry,
                                         ctx->tmo_path,
                                         &ctx->tmo_desc),
                     ==,
                     CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    ctx->registered = true;

    cepDT op_verb = cep_ops_make_dt("op/poc");
    cepDT op_mode = cep_ops_make_dt("opm:states");
    ctx->op_oid = cep_op_start(op_verb,
                                "/data/poc/catalog",
                                op_mode,
                                NULL,
                                0u,
                                0u);
    munit_assert_true(cep_oid_is_valid(ctx->op_oid));

    ctx->op_cell = integration_find_op_cell(ctx->op_oid);
    munit_assert_not_null(ctx->op_cell);
    munit_assert_int(cep_cell_bind_enzyme(ctx->op_cell,
                                          &cont_signal_dt,
                                          false),
                     ==,
                     CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(ctx->op_cell,
                                          &tmo_signal_dt,
                                          false),
                     ==,
                     CEP_ENZYME_SUCCESS);
    ctx->bound = true;

    cepDT watchers_name = cep_ops_make_dt("watchers");
    cepCell* watchers = cep_cell_find_by_name(ctx->op_cell, &watchers_name);
    munit_assert_not_null(watchers);
    watchers = cep_cell_resolve(watchers);

    munit_assert_true(cep_op_await(ctx->op_oid,
                                   cep_ops_make_dt("ist:ok"),
                                   0u,
                                   cont_signal_dt,
                                   NULL,
                                   0u));
    munit_assert_true(cep_op_await(ctx->op_oid,
                                   cep_ops_make_dt("ist:ok"),
                                   1u,
                                   tmo_signal_dt,
                                   NULL,
                                   0u));
    (void)watchers;
}

static void integration_ops_ctx_mark_ok(IntegrationOpsContext* ctx) {
    munit_assert_not_null(ctx);
    munit_assert_true(cep_op_state_set(ctx->op_oid,
                                       cep_ops_make_dt("ist:ok"),
                                       0,
                                       "integration-ok"));
}

static void integration_ops_ctx_emit_cei(IntegrationOpsContext* ctx,
                                         IntegrationFixture* fix) {
    munit_assert_not_null(ctx);
    munit_assert_not_null(fix);

    cepCeiRequest cei_req = {
        .severity = *CEP_DTAW("CEP", "sev:crit"),
        .note = "catalog consistency failure",
        .topic = "poc.catalog",
        .topic_len = 0u,
        .topic_intern = true,
        .origin_name = CEP_DTAW("CEP", "poc"),
        .origin_kind = "integration",
        .subject = fix->catalog,
        .has_code = true,
        .code = 7u,
        .emit_signal = true,
        .attach_to_op = true,
        .op = ctx->op_oid,
        .has_ttl_beats = true,
        .ttl_beats = 1u,
    };
    munit_assert_true(cep_cei_emit(&cei_req));

    cepCell* msgs = integration_diag_msgs();
    cepCell* latest = cep_cell_last_all(msgs);
    munit_assert_not_null(latest);
    latest = cep_cell_resolve(latest);

    integration_mailbox_plan_retention(cep_cei_diagnostics_mailbox(), latest);
}

static void integration_ops_ctx_verify(const IntegrationOpsContext* ctx) {
    munit_assert_not_null(ctx);
    munit_assert_int(integration_timeout_calls, ==, 1);

    cepDT watchers_name = cep_ops_make_dt("watchers");
    cepCell* watchers = cep_cell_find_by_name(ctx->op_cell, &watchers_name);
    if (watchers) {
        watchers = cep_cell_resolve(watchers);
        size_t live_watchers = 0u;
        for (cepCell* entry = cep_cell_first_all(watchers);
             entry;
             entry = cep_cell_next_all(watchers, entry)) {
            cepCell* resolved_entry = cep_cell_resolve(entry);
            if (resolved_entry && !cep_cell_is_deleted(resolved_entry)) {
                live_watchers += 1u;
            }
        }
        munit_assert_size(live_watchers, <=, 1u);
    }

    munit_assert_int(integration_continuation_calls, ==, 1);

    cepCell* op_cell = integration_find_op_cell(ctx->op_oid);
    cepCell* status = cep_cell_find_by_name(op_cell, CEP_DTAW("CEP", "status"));
    if (status) {
        status = cep_cell_resolve(status);
        if (status && cep_cell_has_data(status)) {
            const cepDT* recorded = (const cepDT*)cep_cell_data(status);
            if (recorded) {
                cepDT cleaned = cep_dt_clean(recorded);
                munit_assert_int(cep_dt_compare(&cleaned, CEP_DTAW("CEP", "sts:fail")), ==, 0);
            }
        }
    }
}

static void integration_ops_ctx_cleanup(IntegrationOpsContext* ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->bound) {
        ctx->op_cell = integration_find_op_cell(ctx->op_oid);
        const cepDT cont_dt = cep_ops_make_dt("op/cont");
        const cepDT tmo_dt = cep_ops_make_dt("op/tmo");
        if (ctx->op_cell) {
            (void)cep_cell_unbind_enzyme(ctx->op_cell, &cont_dt);
            (void)cep_cell_unbind_enzyme(ctx->op_cell, &tmo_dt);
        }
    }
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (ctx->registered && registry) {
        (void)cep_enzyme_unregister(registry, ctx->tmo_path, &ctx->tmo_desc);
        (void)cep_enzyme_unregister(registry, ctx->cont_path, &ctx->cont_desc);
        cep_enzyme_registry_activate_pending(registry);
    }
    memset(ctx, 0, sizeof *ctx);
}

static void integration_stream_ctx_prepare(IntegrationStreamContext* ctx,
                                           IntegrationFixture* fix) {
    if (!ctx || !fix || !fix->poc_root) {
        return;
    }
    memset(ctx, 0, sizeof *ctx);

    cepCell* poc_root = cep_cell_resolve(fix->poc_root);
    munit_assert_not_null(poc_root);

    cepCell* stream_root = cep_cell_find_by_name(poc_root, CEP_DTAW("CEP", "stream"));
    if (!stream_root) {
        cepDT stream_store_type = integration_named_dt("poc_stream_root");
        stream_root = cep_cell_add_dictionary(poc_root,
                                              CEP_DTAW("CEP", "stream"),
                                              0,
                                              &stream_store_type,
                                              CEP_STORAGE_RED_BLACK_T);
    }
    munit_assert_not_null(stream_root);
    ctx->stream_root = cep_cell_resolve(stream_root);
    munit_assert_not_null(ctx->stream_root);

    ctx->backing = tmpfile();
    munit_assert_not_null(ctx->backing);

    cepCell library;
    CEP_0(&library);
    cep_stdio_library_init(&library, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("io_lib")));
    ctx->library_node = cep_cell_add(ctx->stream_root, 0, &library);
    munit_assert_not_null(ctx->library_node);
    ctx->library_node = cep_cell_resolve(ctx->library_node);

    cepCell resource;
    CEP_0(&resource);
    cep_stdio_resource_init(&resource,
                            CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("io_res")),
                            ctx->backing,
                            true);
    ctx->resource_node = cep_cell_add(ctx->stream_root, 0, &resource);
    munit_assert_not_null(ctx->resource_node);
    ctx->resource_node = cep_cell_resolve(ctx->resource_node);

    cepCell stream_cell;
    CEP_0(&stream_cell);
    cep_stdio_stream_init(&stream_cell,
                          CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("io_stream")),
                          ctx->library_node,
                          ctx->resource_node);
    ctx->stream_node = cep_cell_add(ctx->stream_root, 0, &stream_cell);
    munit_assert_not_null(ctx->stream_node);
    ctx->stream_node = cep_cell_resolve(ctx->stream_node);

    const char* prefix = "phase-one:";
    const char* suffix = "payload";
    size_t written = 0u;
    munit_assert_true(cep_cell_stream_write(ctx->stream_node,
                                            0u,
                                            prefix,
                                            strlen(prefix),
                                            &written));
    munit_assert_size(written, ==, strlen(prefix));
    munit_assert_true(cep_cell_stream_write(ctx->stream_node,
                                            strlen(prefix),
                                            suffix,
                                            strlen(suffix),
                                            &written));
    munit_assert_size(written, ==, strlen(suffix));
    munit_assert_true(cep_stream_commit_pending());
    ctx->prepared = true;
}

static void integration_episode_guard_task(void* ctx) {
    IntegrationEpisodeProbe* probe = ctx;
    munit_assert_not_null(probe);
    munit_assert_not_null(probe->stream);

    size_t written = 0u;
    bool result = cep_ep_stream_write(probe->stream,
                                      probe->offset,
                                      "ro-denied",
                                      strlen("ro-denied"),
                                      &written);
    atomic_store_explicit(&probe->guard_result, result, memory_order_relaxed);
    munit_assert_size(written, ==, 0u);
}

static void integration_episode_executor_checks(IntegrationStreamContext* ctx) {
    if (!ctx || !ctx->prepared) {
        return;
    }

    const char* baseline = "phase-one:payload";
    size_t baseline_len = strlen(baseline);

    munit_assert_true(cep_executor_init());

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    IntegrationEpisodeProbe probe = {
        .stream = ctx->stream_node,
        .offset = baseline_len,
    };
    atomic_init(&probe.guard_result, true);

    cepExecutorTicket ticket = 0u;
    munit_assert_true(cep_executor_submit_ro(integration_episode_guard_task,
                                             &probe,
                                             &policy,
                                             &ticket));
    munit_assert_uint64(ticket, !=, 0u);
    munit_assert_true(test_executor_wait_until_empty(128));
    if (atomic_load_explicit(&probe.guard_result, memory_order_relaxed)) {
        munit_assert_true(cep_heartbeat_stage_commit());
        munit_assert_true(cep_heartbeat_step());
        test_executor_relax();
    }
    munit_assert_false(atomic_load_explicit(&probe.guard_result, memory_order_relaxed));

    const char* slices[] = {
        ":episode-0",
        ":episode-1",
        ":episode-2",
    };

    cepEpExecutionContext rw_ctx = {
        .profile = CEP_EP_PROFILE_RW,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
        .user_data = NULL,
        .cpu_consumed_ns = 0u,
        .io_consumed_bytes = 0u,
        .ticket = 0,
    };
    atomic_init(&rw_ctx.cancel_requested, false);

    size_t offset = baseline_len;
    for (size_t i = 0; i < cep_lengthof(slices); ++i) {
        const char* slice = slices[i];
        size_t slice_len = strlen(slice);

        cep_executor_context_set(&rw_ctx);
        size_t written = 0u;
        munit_assert_true(cep_ep_stream_write(ctx->stream_node,
                                              offset,
                                              slice,
                                              slice_len,
                                              &written));
        munit_assert_size(written, ==, slice_len);
        cep_executor_context_clear();
        munit_assert_true(cep_ep_stream_commit_pending());

        offset += slice_len;
    }

    cepEpExecutionContext budget_ctx = {
        .profile = CEP_EP_PROFILE_RO,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = 8u,
        .user_data = NULL,
        .cpu_consumed_ns = 0u,
        .io_consumed_bytes = 0u,
        .ticket = 0,
    };
    atomic_init(&budget_ctx.cancel_requested, false);
    cep_executor_context_set(&budget_ctx);
    cep_ep_account_io(16u);
    munit_assert_true(cep_ep_check_cancel());
    cep_ep_request_cancel();
    munit_assert_true(cep_ep_check_cancel());
    cep_executor_context_clear();

    cep_executor_shutdown();
}

static void
integration_episode_lease_task(cepEID eid, void* ctx)
{
    IntegrationLeaseProbe* probe = ctx;
    cepDT field = cep_ops_make_dt("lease-field");

    bool ok = cep_cell_put_text(probe->target, &field, "no-lease");
    atomic_store_explicit(&probe->first_denied, !ok, memory_order_relaxed);

    (void)cep_ep_request_lease(eid, probe->path, true, false, true);

    ok = cep_cell_put_text(probe->target, &field, "with-lease");
    atomic_store_explicit(&probe->second_allowed, ok, memory_order_relaxed);

    (void)cep_ep_release_lease(eid, probe->path);

    ok = cep_cell_put_text(probe->target, &field, "post-release");
    atomic_store_explicit(&probe->third_denied, !ok, memory_order_relaxed);

    cepDT status = cep_ops_make_dt("sts:ok");
    (void)cep_ep_close(eid, status, NULL, 0u);
}

static void
integration_episode_hybrid_task(cepEID eid, void* ctx)
{
    IntegrationHybridProbe* probe = ctx;
    munit_assert_not_null(probe);
    munit_assert_not_null(probe->target);
    unsigned stage = atomic_load_explicit(&probe->stage, memory_order_relaxed);

    cepDT field = cep_ops_make_dt("hyb_field");

    if (stage == 0u) {
        cepEpLeaseRequest request = {
            .path = probe->path,
            .cell = probe->target,
            .lock_store = true,
            .lock_data = false,
            .include_descendants = false,
        };
        munit_assert_true(cep_ep_promote_to_rw(eid, &request, 1u, CEP_EP_PROMOTE_FLAG_NONE));
        atomic_store_explicit(&probe->promoted, true, memory_order_relaxed);
        atomic_store_explicit(&probe->stage, 1u, memory_order_relaxed);
        return;
    }

    if (stage == 1u) {
        munit_assert_true(cep_cell_put_text(probe->target, &field, "rw-mutated"));
        munit_assert_true(cep_ep_release_lease(eid, probe->path));
        munit_assert_true(cep_ep_demote_to_ro(eid, CEP_EP_DEMOTE_FLAG_NONE));
        atomic_store_explicit(&probe->demoted, true, memory_order_relaxed);
        atomic_store_explicit(&probe->stage, 2u, memory_order_relaxed);
        return;
    }

    if (stage == 2u) {
        bool ok = cep_cell_put_text(probe->target, &field, "post-demote");
        munit_assert_false(ok);
        cepDT status = cep_ops_make_dt("sts:ok");
        munit_assert_true(cep_ep_close(eid, status, NULL, 0u));
        atomic_store_explicit(&probe->ro_guard, true, memory_order_relaxed);
        atomic_store_explicit(&probe->stage, 3u, memory_order_relaxed);
        return;
    }
}

static void
integration_episode_hybrid_flow(IntegrationFixture* fix)
{
    munit_assert_not_null(fix);

    cepCell* data_root = cep_cell_ensure_dictionary_child(cep_root(),
                                                          CEP_DTAW("CEP", "data"),
                                                          CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(data_root);
    data_root = cep_cell_resolve(data_root);

    cepCell* hybrid_target = cep_cell_ensure_dictionary_child(data_root,
                                                             CEP_DTAW("CEP", "int_hybrid"),
                                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(hybrid_target);
    hybrid_target = cep_cell_resolve(hybrid_target);

    cepPath* hybrid_path = NULL;
    munit_assert_true(cep_cell_path(hybrid_target, &hybrid_path));

    IntegrationHybridProbe probe = {
        .target = hybrid_target,
        .path = hybrid_path,
    };
    atomic_init(&probe.stage, 0u);
    atomic_init(&probe.promoted, false);
    atomic_init(&probe.demoted, false);
    atomic_init(&probe.ro_guard, false);

    IntegrationPathBuf signal_buf = {0};
    IntegrationPathBuf target_buf = {0};
    const cepPath* signal_path = integration_make_path(&signal_buf,
                                                       (const cepDT[]){ integration_named_dt("sig:integration/hybrid") }, 1u);
    const cepPath* target_path = integration_make_path(&target_buf,
                                                       (const cepDT[]){ integration_named_dt("rt:integration/hybrid") }, 1u);

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_HYBRID,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepEID eid = cep_oid_invalid();
    munit_assert_true(cep_ep_start(&eid,
                                   signal_path,
                                   target_path,
                                   integration_episode_hybrid_task,
                                   &probe,
                                   &policy,
                                   0u));

    unsigned spins = 0u;
    while (atomic_load_explicit(&probe.stage, memory_order_relaxed) < 3u && spins < 32u) {
        munit_assert_true(cep_heartbeat_stage_commit());
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        spins += 1u;
    }
    munit_assert_uint(atomic_load_explicit(&probe.stage, memory_order_relaxed), ==, 3u);
    munit_assert_true(atomic_load_explicit(&probe.promoted, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.demoted, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.ro_guard, memory_order_relaxed));

    cepDT field = cep_ops_make_dt("hyb_field");
    cepCell* field_cell = cep_cell_find_by_name(hybrid_target, &field);
    munit_assert_not_null(field_cell);
    field_cell = cep_cell_resolve(field_cell);
    munit_assert_not_null(field_cell);
    const char* final_text = (const char*)cep_cell_data(field_cell);
    munit_assert_not_null(final_text);
    munit_assert_string_equal(final_text, "rw-mutated");

    cep_free(hybrid_path);
}

static void
integration_episode_lease_flow(IntegrationFixture* fix)
{
    munit_assert_not_null(fix);

    cepCell* data_root = cep_cell_ensure_dictionary_child(cep_root(),
                                                          CEP_DTAW("CEP", "data"),
                                                          CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(data_root);
    data_root = cep_cell_resolve(data_root);
    munit_assert_not_null(data_root);

    cepCell* lease_target = cep_cell_ensure_dictionary_child(data_root,
                                                             CEP_DTAW("CEP", "int_lease"),
                                                             CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(lease_target);
    lease_target = cep_cell_resolve(lease_target);
    munit_assert_not_null(lease_target);

    cepPath* lease_path = NULL;
    munit_assert_true(cep_cell_path(lease_target, &lease_path));
    munit_assert_not_null(lease_path);

    IntegrationLeaseProbe probe = {
        .target = lease_target,
        .path = lease_path,
    };
    atomic_init(&probe.first_denied, false);
    atomic_init(&probe.second_allowed, false);
    atomic_init(&probe.third_denied, false);

    IntegrationPathBuf signal_buf = {0};
    IntegrationPathBuf target_buf = {0};
    const cepPath* signal_path = integration_make_path(&signal_buf,
                                                       (const cepDT[]){ integration_named_dt("sig:integration/lease") }, 1u);
    const cepPath* target_path = integration_make_path(&target_buf,
                                                       (const cepDT[]){ integration_named_dt("rt:integration/lease") }, 1u);

    cepEpExecutionPolicy policy = {
        .profile = CEP_EP_PROFILE_RW,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
    };

    cepEID eid = cep_oid_invalid();
    munit_assert_true(cep_ep_start(&eid,
                                   signal_path,
                                   target_path,
                                   integration_episode_lease_task,
                                   &probe,
                                   &policy,
                                   0u));

    munit_assert_true(test_executor_wait_until_empty(128));
    munit_assert_true(atomic_load_explicit(&probe.first_denied, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.second_allowed, memory_order_relaxed));
    munit_assert_true(atomic_load_explicit(&probe.third_denied, memory_order_relaxed));

    cep_free(lease_path);
}

static void integration_stream_ctx_verify(IntegrationStreamContext* ctx) {
    munit_assert_not_null(ctx);
    munit_assert_not_null(ctx->stream_node);

    char buffer[80] = {0};
    size_t read = 0u;
    const char* expected = "phase-one:payload:episode-0:episode-1:episode-2";
    munit_assert_true(cep_cell_stream_read(ctx->stream_node,
                                           0u,
                                           buffer,
                                           strlen(expected),
                                           &read));
    munit_assert_size(read, ==, strlen(expected));
    buffer[read] = '\0';
    munit_assert_string_equal(buffer, expected);

    cepCell* journal = cep_cell_find_by_name(ctx->stream_node, CEP_DTAW("CEP", "journal"));
    munit_assert_not_null(journal);
    journal = cep_cell_resolve(journal);
    munit_assert_not_null(journal);
    munit_assert_size(cep_cell_children(journal), >, 0u);

    cepCell* outcome = cep_cell_find_by_name(ctx->stream_node, CEP_DTAW("CEP", "outcome"));
    munit_assert_not_null(outcome);
    outcome = cep_cell_resolve(outcome);
    munit_assert_not_null(outcome);

    bool matched_result = false;
    for (cepCell* node = cep_cell_last_all(outcome);
         node && !matched_result;
         node = cep_cell_prev_all(outcome, node)) {
        cepCell* resolved = cep_cell_resolve(node);
        if (!resolved || !cep_cell_has_data(resolved)) {
            continue;
        }
        const cepStreamOutcomeEntry* candidate = (const cepStreamOutcomeEntry*)cep_cell_data(resolved);
        if (!candidate) {
            continue;
        }
        CEP_DEBUG_PRINTF_STDOUT(
            "[integration_poc] stream_outcome len=%llu payload=%016llx expected=%016llx result=%016llx flags=%u",
            (unsigned long long)candidate->length,
            (unsigned long long)candidate->payload_hash,
            (unsigned long long)candidate->expected_hash,
            (unsigned long long)candidate->resulting_hash,
            (unsigned)candidate->flags);
        if (candidate->resulting_hash != 0u) {
            matched_result = true;
        }
    }
    munit_assert_true(matched_result);
}

static void integration_stream_ctx_cleanup(IntegrationStreamContext* ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->backing) {
        fflush(ctx->backing);
        // The stream resource owns the FILE handle; leave it open.
        ctx->backing = NULL;
    }
    if (ctx->stream_node) {
        cep_cell_delete(ctx->stream_node);
        cep_cell_remove_hard(ctx->stream_node, NULL);
        ctx->stream_node = NULL;
    }
    if (ctx->resource_node) {
        cep_cell_delete(ctx->resource_node);
        cep_cell_remove_hard(ctx->resource_node, NULL);
        ctx->resource_node = NULL;
    }
    if (ctx->library_node) {
        cep_cell_delete(ctx->library_node);
        cep_cell_remove_hard(ctx->library_node, NULL);
        ctx->library_node = NULL;
    }
    memset(ctx, 0, sizeof *ctx);
}

static void integration_txn_ctx_begin(IntegrationTxnContext* ctx,
                                      IntegrationFixture* fix) {
    if (!ctx || !fix || !fix->poc_root) {
        return;
    }
    memset(ctx, 0, sizeof *ctx);

    ctx->txn_name = *CEP_DTAW("CEP", "txn_branch");
    cepDT txn_type = integration_named_dt("poc_txn");
    munit_assert_true(cep_txn_begin(fix->poc_root,
                                    &ctx->txn_name,
                                    &txn_type,
                                    &ctx->txn));
    munit_assert_not_null(ctx->txn.root);
    munit_assert_true(cep_cell_is_veiled(ctx->txn.root));

    ctx->staged_name = *CEP_DTAW("CEP", "txn_item");
    IntegrationPoint staged_point = {{2.0f, -3.0f, 1.0f}};
    cepCell* staged_child = cep_cell_add_value(ctx->txn.root,
                                               &ctx->staged_name,
                                               0,
                                               &fix->item_type,
                                               &staged_point,
                                               sizeof staged_point,
                                               sizeof staged_point);
    munit_assert_not_null(staged_child);
    ctx->began = true;

    cepCell* visible_lookup = cep_cell_find_by_name(fix->poc_root, &ctx->staged_name);
    munit_assert_null(visible_lookup);

    cepCell* veiled_branch = cep_cell_find_by_name_all(fix->poc_root, &ctx->txn_name);
    munit_assert_not_null(veiled_branch);
    veiled_branch = cep_cell_resolve(veiled_branch);
    munit_assert_not_null(veiled_branch);
    munit_assert_true(cep_cell_is_veiled(veiled_branch));

    cepCell* raw_lookup = cep_cell_find_by_name_all(veiled_branch, &ctx->staged_name);
    munit_assert_not_null(raw_lookup);
    raw_lookup = cep_cell_resolve(raw_lookup);
    munit_assert_not_null(raw_lookup);
    munit_assert_true(cep_cell_is_veiled(raw_lookup));

    bool found_in_all = false;
    for (cepCell* node = cep_cell_first_all(ctx->txn.root); node && !found_in_all; node = cep_cell_next_all(ctx->txn.root, node)) {
        cepCell* resolved = cep_cell_resolve(node);
        if (!resolved) {
            continue;
        }
        const cepDT* enumerated_name = cep_cell_get_name(resolved);
        if (enumerated_name && cep_dt_compare(enumerated_name, &ctx->staged_name) == 0) {
            found_in_all = true;
        }
    }
    munit_assert_true(found_in_all);
}

static void integration_txn_ctx_commit(IntegrationTxnContext* ctx,
                                       IntegrationFixture* fix) {
    munit_assert_not_null(ctx);
    munit_assert_not_null(fix);
    if (!ctx->began) {
        return;
    }

    munit_assert_true(cep_txn_mark_ready(&ctx->txn));
    munit_assert_true(cep_txn_commit(&ctx->txn));

    cepCell* published_root = cep_cell_find_by_name(fix->poc_root, &ctx->txn_name);
    munit_assert_not_null(published_root);
    published_root = cep_cell_resolve(published_root);
    munit_assert_not_null(published_root);

    cepCell* unveiled = cep_cell_find_by_name(published_root, &ctx->staged_name);
    munit_assert_not_null(unveiled);
    unveiled = cep_cell_resolve(unveiled);
    munit_assert_not_null(unveiled);
    munit_assert_false(cep_cell_is_veiled(unveiled));

    cepCell* raw_after = cep_cell_find_by_name_all(published_root, &ctx->staged_name);
    if (raw_after) {
        raw_after = cep_cell_resolve(raw_after);
        munit_assert_not_null(raw_after);
        munit_assert_false(cep_cell_is_veiled(raw_after));
    }

    CEP_0(&ctx->txn);
    ctx->began = false;
}

static void integration_prr_ctx_setup(IntegrationPauseResumeContext* ctx,
                                      IntegrationFixture* fix) {
    if (!ctx || !fix || !fix->poc_root) {
        return;
    }
    memset(ctx, 0, sizeof *ctx);

    cepCell* poc_root = cep_cell_resolve(fix->poc_root);
    munit_assert_not_null(poc_root);
    cepCell* prr_root = cep_cell_ensure_dictionary_child(poc_root,
                                                         CEP_DTAW("CEP", "prr_pause"),
                                                         CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(prr_root);
    (void)prr_root;

    const cepDT signal_segments[] = {
        *CEP_DTAW("CEP", "sig"),
        *CEP_DTAW("CEP", "poc"),
        *CEP_DTAW("CEP", "prr"),
    };
    ctx->signal_path = integration_make_path(&ctx->signal_buf,
                                             signal_segments,
                                             cep_lengthof(signal_segments));

    const cepDT target_segments[] = {
        *CEP_DTAW("CEP", "data"),
        *CEP_DTAW("CEP", "poc"),
        *CEP_DTAW("CEP", "prr_pause"),
    };
    ctx->target_path = integration_make_path(&ctx->target_buf,
                                             target_segments,
                                             cep_lengthof(target_segments));

    ctx->desc = (cepEnzymeDescriptor){
        .name = *CEP_DTAW("CEP", "sig:poc/prr"),
        .label = "integration-prr-signal",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_prr_enzyme,
        .flags = CEP_ENZYME_FLAG_NONE,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    integration_prr_calls = 0;

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_int(cep_enzyme_register(registry,
                                         ctx->signal_path,
                                         &ctx->desc),
                     ==,
                     CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
    ctx->registered = true;
}

static void integration_prr_ctx_execute(IntegrationPauseResumeContext* ctx) {
    munit_assert_not_null(ctx);
    if (!ctx->registered) {
        return;
    }

    munit_assert_true(cep_runtime_pause());
    for (unsigned i = 0; i < 2u; ++i) {
        munit_assert_true(cep_heartbeat_step());
        integration_debug_mark("prr:paused", cep_heartbeat_current());
    }
    munit_assert_true(cep_runtime_is_paused());

    cepImpulse backlog = {
        .signal_path = ctx->signal_path,
        .target_path = ctx->target_path,
        .qos = CEP_IMPULSE_QOS_RETAIN_ON_PAUSE,
    };
    munit_assert_int(cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &backlog),
                     ==,
                     CEP_ENZYME_SUCCESS);

    cepImpulse discardable = backlog;
    discardable.qos |= CEP_IMPULSE_QOS_DISCARD_ON_ROLLBACK;
    munit_assert_int(cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &discardable),
                     ==,
                     CEP_ENZYME_SUCCESS);
    munit_assert_int(integration_prr_calls, ==, 0);

    cepBeatNumber current = cep_heartbeat_current();
    cepBeatNumber rollback_target = current ? (current - 1u) : current;
    munit_assert_true(cep_runtime_rollback(rollback_target));
    munit_assert_true(cep_runtime_is_paused());

    if (!cep_runtime_resume()) {
        munit_logf(MUNIT_LOG_INFO,
                   "%s",
                   "PRR resume unavailable; skipping deterministic drain");
        return;
    }

    unsigned attempts = 0u;
    while (integration_prr_calls == 0 && attempts < 32u) {
        munit_assert_true(cep_heartbeat_step());
        attempts += 1u;
        integration_debug_mark("prr:resume", cep_heartbeat_current());
    }
    munit_assert_int(integration_prr_calls, ==, 1);
    ctx->committed += 1u;
}

static void integration_prr_ctx_cleanup(IntegrationPauseResumeContext* ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->registered) {
        cepEnzymeRegistry* registry = cep_heartbeat_registry();
        if (registry) {
            (void)cep_enzyme_unregister(registry,
                                        ctx->signal_path,
                                        &ctx->desc);
            cep_enzyme_registry_activate_pending(registry);
        }
    }
    memset(ctx, 0, sizeof *ctx);
}

static void integration_execute_interleaved_timeline(IntegrationFixture* fix) {
    munit_assert_not_null(fix);

    IntegrationCatalogPlan catalog_plan;
    IntegrationRandomPlan random_plan;
    IntegrationOpsContext ops_ctx;
    IntegrationStreamContext stream_ctx;
    IntegrationTxnContext txn_ctx;
    IntegrationPauseResumeContext prr_ctx;

    integration_catalog_plan_setup(&catalog_plan, fix);
    integration_random_plan_setup(&random_plan, fix);
    integration_ops_ctx_setup(&ops_ctx, fix);
    integration_stream_ctx_prepare(&stream_ctx, fix);
    integration_txn_ctx_begin(&txn_ctx, fix);
    integration_prr_ctx_setup(&prr_ctx, fix);

    integration_catalog_plan_queue_reindex(&catalog_plan);
    integration_random_plan_queue(&random_plan);

    munit_assert_true(cep_heartbeat_stage_commit());
    integration_debug_mark("timeline:stage0", cep_heartbeat_current());

    munit_assert_true(cep_heartbeat_step());
    integration_debug_mark("timeline:beat0", cep_heartbeat_current());
    munit_assert_true(cep_heartbeat_step());
    integration_debug_mark("timeline:beat1", cep_heartbeat_current());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_true(cep_heartbeat_stage_commit());

    munit_assert_true(cep_heartbeat_step());
    integration_debug_mark("timeline:beat2", cep_heartbeat_current());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_process_impulses());
    integration_catalog_plan_verify(&catalog_plan);
    integration_random_plan_verify(&random_plan);

    integration_ops_ctx_mark_ok(&ops_ctx);
    integration_ops_ctx_emit_cei(&ops_ctx, fix);

    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_step());
    integration_debug_mark("timeline:beat3", cep_heartbeat_current());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_true(cep_heartbeat_stage_commit());

    integration_ops_ctx_verify(&ops_ctx);
    integration_episode_executor_checks(&stream_ctx);
    integration_episode_lease_flow(fix);
    integration_episode_hybrid_flow(fix);
    integration_stream_ctx_verify(&stream_ctx);
    integration_txn_ctx_commit(&txn_ctx, fix);
    integration_serialize_and_replay(fix);
    integration_exercise_organ_lifecycle(fix);
    integration_randomized_mutations(fix);
    integration_prr_ctx_execute(&prr_ctx);
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_process_impulses());

    integration_catalog_plan_cleanup(&catalog_plan, fix);
    integration_random_plan_cleanup(&random_plan, fix);
    integration_ops_ctx_cleanup(&ops_ctx);
    integration_stream_ctx_cleanup(&stream_ctx);
    integration_prr_ctx_cleanup(&prr_ctx);
}

static cepDT integration_named_dt(const char* tag) {
    cepDT dt = {
        .domain = cep_namepool_intern_cstr("CEP"),
        .tag = cep_namepool_intern_cstr(tag),
        .glob = 0u,
    };
    return dt;
}

static void integration_organ_init_dts(void) {
    if (integration_organ_dts_ready) {
        return;
    }
    integration_organ_store_dt = cep_organ_store_dt(integration_organ_kind);
    integration_organ_validator_dt = integration_named_dt("org:poc:val");
    integration_organ_constructor_dt = integration_named_dt("org:poc:ctor");
    integration_organ_destructor_dt = integration_named_dt("org:poc:dtor");
    integration_organ_dts_ready = true;
}

static uint32_t integration_prng_next(uint32_t* state) {
    uint32_t value = *state;
    value = value * UINT32_C(1664525) + UINT32_C(1013904223);
    *state = value;
    return value;
}

static int integration_index_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_call_order[integration_call_count++] = 1;
    integration_index_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_aggregate_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_call_order[integration_call_count++] = 2;
    integration_aggregate_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_ops_continuation(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_continuation_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_ops_timeout(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_timeout_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_prr_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_prr_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_organ_ctor_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_organ_ctor_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_organ_validator_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_organ_validator_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_organ_destructor_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_organ_destructor_calls += 1;
    return CEP_ENZYME_SUCCESS;
}

static int integration_random_enzyme_callback(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    integration_random_enzyme_count += 1;
    return CEP_ENZYME_SUCCESS;
}

static cepCell* integration_diag_msgs(void) {
    cepCell* mailbox = cep_cei_diagnostics_mailbox();
    munit_assert_not_null(mailbox);
    mailbox = cep_cell_resolve(mailbox);
    munit_assert_not_null(mailbox);
    cepCell* msgs = cep_cell_find_by_name(mailbox, CEP_DTAW("CEP", "msgs"));
    munit_assert_not_null(msgs);
    return cep_cell_resolve(msgs);
}

static cepCell* integration_mailbox_runtime(void) {
    cepCell* diag_root = cep_cell_resolve(cep_cei_diagnostics_mailbox());
    munit_assert_not_null(diag_root);
    cepCell* meta = cep_cell_find_by_name(diag_root, CEP_DTAW("CEP", "meta"));
    munit_assert_not_null(meta);
    meta = cep_cell_resolve(meta);
    cepCell* runtime = cep_cell_find_by_name(meta, CEP_DTAW("CEP", "runtime"));
    munit_assert_not_null(runtime);
    return cep_cell_resolve(runtime);
}

static void integration_mailbox_plan_retention(cepCell* mailbox_root,
                                               cepCell* message) {
    munit_assert_not_null(mailbox_root);
    munit_assert_not_null(message);

    mailbox_root = cep_cell_resolve(mailbox_root);
    munit_assert_not_null(mailbox_root);

    cepMailboxTTLContext ctx = {0};
    munit_assert_true(cep_mailbox_ttl_context_init(&ctx));

    cepMailboxTTLSpec message_spec = {
        .forever = false,
        .has_beats = true,
        .ttl_beats = 1u,
        .has_unix_ns = false,
        .ttl_unix_ns = 0u,
    };
    cepMailboxTTLResolved resolved = {0};
    munit_assert_true(cep_mailbox_resolve_ttl(&message_spec,
                                              NULL,
                                              NULL,
                                              &ctx,
                                              &resolved));

    cepDT message_id = cep_dt_clean(cep_cell_get_name(message));
    munit_assert_true(message_id.domain != 0u);
    munit_assert_true(resolved.beats_active);

    cepMailboxRetentionPlan plan;
    CEP_0(&plan);
    munit_assert_true(cep_mailbox_plan_retention(mailbox_root, &ctx, &plan));

    bool found = false;
    for (size_t i = 0; i < plan.beats_count; ++i) {
        const cepMailboxExpiryRecord* record = &plan.beats[i];
        if (cep_dt_compare(&record->message_id, &message_id) == 0) {
            munit_assert_false(record->from_wallclock);
            found = true;
            break;
        }
    }
    if (!found) {
        cepCell* runtime = integration_mailbox_runtime();
        cepCell* expiries = cep_cell_find_by_name(runtime, CEP_DTAW("CEP", "expiries"));
        if (expiries) {
            expiries = cep_cell_resolve(expiries);
            for (cepCell* bucket = cep_cell_first_all(expiries);
                 bucket && !found;
                 bucket = cep_cell_next_all(expiries, bucket)) {
                cepCell* resolved = cep_cell_resolve(bucket);
                cepCell* link = cep_cell_find_by_name(resolved, &message_id);
                if (link) {
                    found = true;
                    break;
                }
            }
        }
    }
    munit_assert_true(found);
    cep_mailbox_retention_plan_reset(&plan);
}

/* Capture a deterministic snapshot of a DT-typed field underneath @parent. */
static cepDT integration_read_dt_field(cepCell* parent, const char* field_name) {
    cepDT lookup = cep_ops_make_dt(field_name);
    lookup.glob = 0u;
    cepCell* node = cep_cell_find_by_name(parent, &lookup);
    munit_assert_not_null(node);
    munit_assert_true(cep_cell_has_data(node));
    const cepDT* payload = (const cepDT*)cep_cell_data(node);
    munit_assert_not_null(payload);
    return cep_dt_clean(payload);
}

/* Walk /rt/ops to find the operation cell backing @oid. */
static cepCell* integration_find_op_cell(cepOID oid) {
    cepCell* rt_root = cep_cell_resolve(cep_heartbeat_rt_root());
    munit_assert_not_null(rt_root);
    cepCell* ops_root = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops_root);
    cepDT lookup = {
        .domain = oid.domain,
        .tag = oid.tag,
        .glob = 0u,
    };
    cepCell* op = cep_cell_find_by_name(ops_root, &lookup);
    munit_assert_not_null(op);
    return cep_cell_resolve(op);
}

/* Read a recorded operation OID such as boot/shutdown from /sys/state. */
static cepOID integration_read_oid(const char* field_name) {
    cepCell* sys_root = cep_cell_resolve(cep_heartbeat_sys_root());
    munit_assert_not_null(sys_root);

    cepCell* state_root = cep_cell_find_by_name(sys_root, CEP_DTAW("CEP", "state"));
    if (!state_root) {
        state_root = cep_cell_ensure_dictionary_child(sys_root, CEP_DTAW("CEP", "state"), CEP_STORAGE_RED_BLACK_T);
    }
    munit_assert_not_null(state_root);
    state_root = cep_cell_resolve(state_root);

    cepDT lookup = cep_ops_make_dt(field_name);
    lookup.glob = 0u;
    cepCell* entry = cep_cell_find_by_name(state_root, &lookup);
    if (entry && cep_cell_has_data(entry)) {
        const cepOID* stored = (const cepOID*)cep_cell_data(entry);
        if (stored && cep_oid_is_valid(*stored)) {
            return *stored;
        }
    }

    const cepDT* expected_verb = NULL;
    if (strcmp(field_name, "boot_oid") == 0) {
        expected_verb = CEP_DTAW("CEP", "op/boot");
    } else if (strcmp(field_name, "shdn_oid") == 0) {
        expected_verb = CEP_DTAW("CEP", "op/shdn");
    }
    if (!expected_verb) {
        return cep_oid_invalid();
    }

    cepCell* rt_root = cep_cell_resolve(cep_heartbeat_rt_root());
    munit_assert_not_null(rt_root);
    cepCell* ops_root = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    munit_assert_not_null(ops_root);
    ops_root = cep_cell_resolve(ops_root);

    for (cepCell* op = cep_cell_first_all(ops_root); op; op = cep_cell_next_all(ops_root, op)) {
        cepCell* resolved = cep_cell_resolve(op);
        cepCell* envelope = cep_cell_find_by_name(resolved, CEP_DTAW("CEP", "envelope"));
        if (!envelope) {
            continue;
        }
        cepDT verb = integration_read_dt_field(cep_cell_resolve(envelope), "verb");
        if (cep_dt_compare(&verb, expected_verb) != 0) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name) {
            continue;
        }
        cepDT cleaned = cep_dt_clean(name);
        cepOID oid = {
            .domain = cleaned.domain,
            .tag = cleaned.tag,
        };
        if (cep_oid_is_valid(oid)) {
            return oid;
        }
    }

    return cep_oid_invalid();
}

/* Count entries in an operation's history that match @expected sequence. */
static void integration_assert_op_history(cepOID oid,
                                          const char* const* expected_states,
                                          size_t expected_count) {
    cepCell* op = integration_find_op_cell(oid);
    cepCell* history = cep_cell_find_by_name(op, CEP_DTAW("CEP", "history"));
    munit_assert_not_null(history);
    history = cep_cell_resolve(history);

    size_t matched = 0u;
    uint64_t previous_beat = 0;
    bool have_previous = false;

    for (cepCell* entry = cep_cell_first_all(history);
         entry && matched < expected_count;
         entry = cep_cell_next_all(history, entry)) {
        cepCell* resolved = cep_cell_resolve(entry);
        cepDT state = integration_read_dt_field(resolved, "state");
        const char* expected_tag = expected_states[matched];
        cepDT expected_raw = cep_ops_make_dt(expected_tag);
        cepDT expected = cep_dt_clean(&expected_raw);
        if (cep_dt_compare(&state, &expected) != 0) {
            continue;
        }

        cepDT beat_dt = cep_ops_make_dt("beat");
        beat_dt.glob = 0u;
        cepCell* beat_node = cep_cell_find_by_name(resolved, &beat_dt);
        munit_assert_not_null(beat_node);
        munit_assert_true(cep_cell_has_data(beat_node));
        const uint64_t* beat_value = (const uint64_t*)cep_cell_data(beat_node);
        munit_assert_not_null(beat_value);
        if (have_previous) {
            munit_assert_uint64(*beat_value, >=, previous_beat);
        }
        previous_beat = *beat_value;
        have_previous = true;
        matched += 1u;
    }

    munit_assert_size(matched, ==, expected_count);
}

/* Count payload history revisions for @cell. */
static size_t integration_data_history_depth(const cepCell* cell) {
    if (!cell || !cell->data) {
        return 0u;
    }
    const cepData* data = cell->data;
    const cepDataNode* node = (const cepDataNode*)&data->modified;
    size_t depth = 0u;
    for (; node; node = node->past) {
        depth += 1u;
    }
    return depth;
}

/* Count store layout snapshots (including the live view) for @cell. */
static size_t integration_store_history_depth(const cepCell* cell) {
    if (!cell || !cell->store) {
        return 0u;
    }
    const cepStore* store = cell->store;
    const cepStoreNode* node = (const cepStoreNode*)&store->modified;
    size_t depth = 0u;
    for (; node; node = node->past) {
        depth += 1u;
    }
    return depth;
}

/* Measure backlinks pointing at @cell, tracking single vs multi-link storage. */
static size_t integration_backlink_count(const cepCell* cell) {
    if (!cell) {
        return 0u;
    }
    if (cell->store) {
        if (cell->store->shadow) {
            return cell->store->shadow->count;
        }
        return cell->store->linked ? 1u : 0u;
    }
    if (cell->shadow) {
        return cell->shadow->count;
    }
    return cell->linked ? 1u : 0u;
}

/* Order catalog entries by their stored IntegrationPoint payload. */
static int integration_catalog_compare(const cepCell* lhs,
                                       const cepCell* rhs,
                                       void* user_data) {
    (void)user_data;
    cepCell* left = lhs ? cep_cell_resolve((cepCell*)lhs) : NULL;
    cepCell* right = rhs ? cep_cell_resolve((cepCell*)rhs) : NULL;
    if (!left || !right || !cep_cell_is_normal(left) || !cep_cell_is_normal(right) ||
        !cep_cell_has_data(left) || !cep_cell_has_data(right)) {
        return 0;
    }
    const IntegrationPoint* a = (const IntegrationPoint*)cep_cell_data(left);
    const IntegrationPoint* b = (const IntegrationPoint*)cep_cell_data(right);
    munit_assert_not_null(a);
    munit_assert_not_null(b);
    if (a->position[0] < b->position[0]) {
        return -1;
    }
    if (a->position[0] > b->position[0]) {
        return 1;
    }
    return 0;
}

/* Keep octree ordering stable by comparing the first axis of recorded points. */
static int integration_octree_compare(const cepCell* lhs,
                                      const cepCell* rhs,
                                      void* user_data) {
    (void)user_data;
    cepCell* left = lhs ? cep_cell_resolve((cepCell*)lhs) : NULL;
    cepCell* right = rhs ? cep_cell_resolve((cepCell*)rhs) : NULL;
    if (!left || !right || !cep_cell_is_normal(left) || !cep_cell_is_normal(right) ||
        !cep_cell_has_data(left) || !cep_cell_has_data(right)) {
        return 0;
    }
    const IntegrationPoint* a = (const IntegrationPoint*)cep_cell_data(left);
    const IntegrationPoint* b = (const IntegrationPoint*)cep_cell_data(right);
    if (!a || !b) {
        return 0;
    }
    if (a->position[0] < b->position[0]) {
        return -1;
    }
    if (a->position[0] > b->position[0]) {
        return 1;
    }
    return 0;
}

/* Configure the runtime from a clean slate and drive the boot operation to completion. */
static void integration_runtime_boot(IntegrationFixture* fix) {
    munit_assert_not_null(fix);

    fix->runtime = cep_runtime_create();
    munit_assert_not_null(fix->runtime);
    fix->previous_runtime = cep_runtime_set_active(fix->runtime);
    cep_cell_system_initiate();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
        .spacing_window = 0u,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());
    munit_assert_true(cep_namepool_bootstrap());
    munit_assert_true(cep_runtime_attach_metadata(fix->runtime));
    munit_assert_true(cep_heartbeat_startup());

    fix->boot_oid = integration_read_oid("boot_oid");
    munit_assert_true(cep_oid_is_valid(fix->boot_oid));

    for (unsigned step = 0; step < 6; ++step) {
        munit_assert_true(cep_heartbeat_step());
    }

    const char* expected_states[] = {
        "ist:run",
        "ist:kernel",
        "ist:store",
        "ist:packs",
        "ist:ok",
    };
    integration_assert_op_history(fix->boot_oid, expected_states, cep_lengthof(expected_states));
}

static void integration_runtime_cleanup(IntegrationFixture* fix) {
    if (!fix || !fix->runtime) {
        return;
    }

    cep_runtime_set_active(fix->runtime);
    cep_stream_clear_pending();
    cep_runtime_shutdown(fix->runtime);
    cep_runtime_restore_active(fix->previous_runtime);
    cep_runtime_destroy(fix->runtime);
    fix->runtime = NULL;
    fix->previous_runtime = NULL;
}

/* Ensure `/data/poc/catalog` contains predictable entries before other phases run. */
static cepCell* integration_seed_catalog(cepCell* poc_root,
                                         cepCell** out_item_a) {
    cepCell* catalog = cep_cell_add_dictionary(poc_root,
                                               CEP_DTAW("CEP", "catalog"),
                                               0,
                                               CEP_DTAW("CEP", "poc_catalog"),
                                               CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(catalog);
    catalog = cep_cell_resolve(catalog);
    munit_assert_not_null(catalog->store);
    munit_assert_int(catalog->store->storage, ==, CEP_STORAGE_RED_BLACK_T);
    munit_assert_int(catalog->store->indexing, ==, CEP_INDEX_BY_NAME);

    cepDT item_type = *CEP_DTAW("CEP", "poc_item");

    IntegrationPoint point_a = {{1.0f, 0.0f, 0.0f}};
    cepCell* item_a = cep_cell_add_value(catalog,
                                         CEP_DTAW("CEP", "item_a"),
                                         0,
                                         &item_type,
                                         &point_a,
                                         sizeof point_a,
                                         sizeof point_a);
    munit_assert_not_null(item_a);
    item_a = cep_cell_resolve(item_a);
    munit_assert_not_null(item_a);

    IntegrationPoint point_b = {{-2.0f, 1.0f, 0.0f}};
    munit_assert_not_null(cep_cell_add_value(catalog,
                                             CEP_DTAW("CEP", "item_b"),
                                             0,
                                             &item_type,
                                             &point_b,
                                             sizeof point_b,
                                             sizeof point_b));

    IntegrationPoint point_c = {{3.5f, 4.0f, 1.0f}};
    munit_assert_not_null(cep_cell_add_value(catalog,
                                             CEP_DTAW("CEP", "item_c"),
                                             0,
                                             &item_type,
                                             &point_c,
                                             sizeof point_c,
                                             sizeof point_c));

    if (out_item_a) {
        *out_item_a = item_a;
    }
    return catalog;
}

/* Assemble the `/data/poc` subtree for structural history, link, and lock tests. */
static void integration_build_tree(IntegrationFixture* fix) {
    munit_assert_not_null(fix);
    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);

    cepCell* poc_root = cep_cell_ensure_dictionary_child(data_root,
                                                         CEP_DTAW("CEP", "poc"),
                                                         CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(poc_root);
    poc_root = cep_cell_resolve(poc_root);
    fix->poc_root = poc_root;

    cepDT item_type = *CEP_DTAW("CEP", "poc_item");

    cepDT log_name = *CEP_DTAW("CEP", "log");
    cepDT log_store_type = *CEP_DTAW("CEP", "poc_log");
    cepCell* log_branch = cep_cell_add_list(poc_root,
                                            &log_name,
                                            0,
                                            &log_store_type,
                                            CEP_STORAGE_ARRAY,
                                            (size_t)8);
    munit_assert_not_null(log_branch);
    log_branch = cep_cell_resolve(log_branch);
    munit_assert_not_null(log_branch->store);
    munit_assert_int(log_branch->store->storage, ==, CEP_STORAGE_ARRAY);
    munit_assert_int(log_branch->store->indexing, ==, CEP_INDEX_BY_INSERTION);

    cepDT log_type = *CEP_DTAW("CEP", "poc_event");
    cepDT entry_names[] = {
        *CEP_DTAW("CEP", "entry_a"),
        *CEP_DTAW("CEP", "entry_b"),
        *CEP_DTAW("CEP", "entry_c"),
    };
    const char* log_messages[] = {"boot:start", "catalog:seeded", "log:stable"};
    for (unsigned i = 0; i < cep_lengthof(log_messages); ++i) {
        size_t len = strlen(log_messages[i]) + 1u;
        char message[32];
        munit_assert_size(len, <=, sizeof message);
        memcpy(message, log_messages[i], len);
        munit_assert_not_null(cep_cell_add_value(log_branch,
                                                 &entry_names[i],
                                                 0,
                                                 &log_type,
                                                 message,
                                                 len,
                                                 len));
    }
    fix->log_branch = log_branch;
    fix->log_type = log_type;

    cepCell* item_a = NULL;
    cepCell* catalog = integration_seed_catalog(poc_root, &item_a);
    munit_assert_not_null(item_a);
    item_a = cep_cell_resolve(item_a);
    munit_assert_not_null(item_a);
    fix->catalog = catalog;
    fix->item_type = item_type;

    size_t history_before = integration_data_history_depth(item_a);

    cepLockToken data_token;
    munit_assert_true(cep_data_lock(item_a, &data_token));
    IntegrationPoint unchanged = {{1.0f, 0.0f, 0.0f}};
    munit_assert_null(cep_cell_update_value(item_a, sizeof unchanged, &unchanged));
    cep_data_unlock(item_a, &data_token);

    munit_assert_not_null(cep_cell_update_value(item_a, sizeof unchanged, &unchanged));
    munit_assert_size(integration_data_history_depth(item_a), ==, history_before);

    IntegrationPoint updated = {{5.0f, 0.0f, 2.5f}};
    munit_assert_not_null(cep_cell_update_value(item_a, sizeof updated, &updated));
    munit_assert_size(integration_data_history_depth(item_a), ==, history_before + 1u);

    size_t store_before = integration_store_history_depth(catalog);
    munit_assert_true(store_before >= 1u);
    cep_cell_sort(catalog, integration_catalog_compare, NULL);
    catalog = cep_cell_resolve(catalog);
    munit_assert_not_null(catalog);
    munit_assert_not_null(catalog->store);
    munit_assert_int(catalog->store->indexing, ==, CEP_INDEX_BY_FUNCTION);
    fix->catalog = catalog;
    size_t store_after = integration_store_history_depth(catalog);
    munit_assert_size(store_after, >=, store_before);

    IntegrationPoint point_d = {{-1.5f, -1.0f, 0.5f}};
    cepCell* new_item = cep_cell_add_value(catalog,
                                           CEP_DTAW("CEP", "item_d"),
                                           0,
                                           &item_type,
                                           &point_d,
                                           sizeof point_d,
                                           sizeof point_d);
    munit_assert_not_null(new_item);


    cepCell* link_target = cep_cell_add_dictionary(poc_root,
                                                   CEP_DTAW("CEP", "link_tgt"),
                                                   0,
                                                   CEP_DTAW("CEP", "poc_link"),
                                                   CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(link_target);
    link_target = cep_cell_resolve(link_target);
    munit_assert_not_null(link_target);
    size_t link_backlinks_before = integration_backlink_count(link_target);

    cepCell* link = cep_cell_add_link(poc_root,
                                      CEP_DTAW("CEP", "link_value"),
                                      0,
                                      link_target);
    munit_assert_not_null(link);
    munit_assert_true(cep_cell_is_link(link));

    cepCell* link_resolved = cep_cell_resolve(link);
    munit_assert_ptr_equal(link_resolved, link_target);
    size_t link_backlinks_after = integration_backlink_count(link_resolved);
    munit_assert_size(link_backlinks_after, >=, link_backlinks_before);
    munit_assert_size(link_backlinks_after - link_backlinks_before, >=, 1u);

    cep_cell_delete(link_target);
    munit_assert_uint(link->metacell.targetDead, ==, 1u);

    cep_cell_remove_hard(link, NULL);
    munit_assert_size(integration_backlink_count(link_resolved), ==, link_backlinks_before);

    IntegrationPoint revived = {{6.0f, -1.5f, 0.0f}};
    munit_assert_not_null(cep_cell_update_value(item_a, sizeof revived, &revived));

    cepLockToken store_token;
    munit_assert_true(cep_store_lock(catalog, &store_token));

    cepCell blocked_child;
    CEP_0(&blocked_child);
    IntegrationPoint blocked_origin = {{0.0f, 0.0f, 0.0f}};
    cep_cell_initialize_value(&blocked_child,
                              CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("blocked")),
                              &item_type,
                              &blocked_origin,
                              sizeof blocked_origin,
                              sizeof blocked_origin);
    cepCell* rejected = cep_store_add_child(catalog->store, 0u, &blocked_child);
    munit_assert_null(rejected);
    cep_cell_finalize_hard(&blocked_child);

    cep_store_unlock(catalog, &store_token);

    IntegrationPoint trailing = {{7.5f, 1.0f, 3.0f}};
    munit_assert_not_null(cep_cell_add_value(catalog,
                                             CEP_DTAW("CEP", "item_e"),
                                             0,
                                             &item_type,
                                             &trailing,
                                             sizeof trailing,
                                             sizeof trailing));

    IntegrationPoint origin = {{0.0f, 0.0f, 0.0f}};
    cepCell spatial;
    CEP_0(&spatial);
    cep_cell_initialize_spatial(&spatial,
                                CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("space")),
                                CEP_DTAW("CEP", "oct_root"),
                                origin.position,
                                8.0f,
                                integration_octree_compare);
    cepCell* inserted_space = cep_store_add_child(poc_root->store, 0u, &spatial);
    munit_assert_not_null(inserted_space);
    inserted_space = cep_cell_resolve(inserted_space);
    fix->space_root = inserted_space;
    if (!cep_cell_is_void(&spatial)) {
        cep_cell_finalize_hard(&spatial);
    }

    cepDT space_type = *CEP_DTAW("CEP", "oct_point");
    IntegrationPoint space_payload = {{0.25f, 0.5f, -0.5f}};
    cepCell* oct_entry = cep_cell_add_value(inserted_space,
                                            CEP_DTAW("CEP", "space_entry"),
                                            0,
                                            &space_type,
                                            &space_payload,
                                            sizeof space_payload,
                                            sizeof space_payload);
    munit_assert_not_null(oct_entry);
    fix->space_entry = cep_cell_resolve(oct_entry);
}

/* Remove the `/data/poc` subtree (and replay clone) so catalog payloads, including
 * `item_e`, release their allocations before the runtime shuts down. Deletes and
 * hard-removes the roots to ensure stores drain their owned nodes, then clears the
 * fixture pointers so later cleanup can re-bootstrap safely. */
static void integration_teardown_tree(IntegrationFixture* fix) {
    if (!fix) {
        return;
    }

    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    if (!data_root) {
        return;
    }

    if (fix->space_entry) {
        cepCell* entry = cep_cell_resolve(fix->space_entry);
        if (entry && !cep_cell_is_root(entry)) {
            cep_cell_delete(entry);
            cep_cell_remove_hard(entry, NULL);
        }
        fix->space_entry = NULL;
    }

    if (fix->space_root) {
        cepCell* space_root = cep_cell_resolve(fix->space_root);
        if (space_root && !cep_cell_is_root(space_root)) {
            cep_cell_delete(space_root);
            cep_cell_remove_hard(space_root, NULL);
        }
        fix->space_root = NULL;
    }

    bool removed_poc = false;
    if (fix->poc_root) {
        cepCell* poc_root = cep_cell_resolve(fix->poc_root);
        if (poc_root && !cep_cell_is_root(poc_root)) {
            cep_cell_delete(poc_root);
            cep_cell_remove_hard(poc_root, NULL);
            removed_poc = true;
        }
        fix->poc_root = NULL;
        fix->catalog = NULL;
        fix->log_branch = NULL;
    }

    if (!removed_poc) {
        cepCell* poc_root = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "poc"));
        if (poc_root) {
            poc_root = cep_cell_resolve(poc_root);
            if (poc_root && !cep_cell_is_root(poc_root)) {
                cep_cell_delete(poc_root);
                cep_cell_remove_hard(poc_root, NULL);
                removed_poc = true;
            }
        }
    }

    munit_assert_null(cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "poc")));

    cepCell* replay_root = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "poc_replay"));
    if (replay_root) {
        replay_root = cep_cell_resolve(replay_root);
        if (replay_root && !cep_cell_is_root(replay_root)) {
            cep_cell_delete(replay_root);
            cep_cell_remove_hard(replay_root, NULL);
        }
    }

    munit_assert_null(cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "poc_replay")));
}



/* Emit the `/data/poc` subtree, ingest it into a fresh sibling root, and assert the serialized chunk stream matches byte-for-byte. */
static void integration_serialize_and_replay(IntegrationFixture* fix) {
    munit_assert_not_null(fix);
    munit_assert_not_null(fix->poc_root);

    IntegrationSerializationCapture capture = {0};
    munit_assert_true(cep_serialization_emit_cell(fix->poc_root,
                                                  NULL,
                                                  integration_capture_sink,
                                                  &capture,
                                                  0));
    munit_assert_size(capture.count, >, 0u);

    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);

    cepDT replay_name = *CEP_DTAW("CEP", "poc_replay");
    cepCell* existing = cep_cell_find_by_name(data_root, &replay_name);
    if (existing) {
        existing = cep_cell_resolve(existing);
        if (existing) {
            cep_cell_delete(existing);
            cep_cell_remove_hard(existing, NULL);
        }
    }

    cepDT store_type = fix->poc_root->store ? fix->poc_root->store->dt : integration_named_dt("poc_replay_store");
    cepCell* replay_root = cep_cell_add_dictionary(data_root,
                                                   &replay_name,
                                                   0,
                                                   &store_type,
                                                   CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(replay_root);
    replay_root = cep_cell_resolve(replay_root);
    munit_assert_not_null(replay_root);

    cepSerializationReader* reader = cep_serialization_reader_create(replay_root);
    munit_assert_not_null(reader);
    for (size_t i = 0; i < capture.count; ++i) {
        munit_assert_true(cep_serialization_reader_ingest(reader,
                                                          capture.chunks[i].data,
                                                          capture.chunks[i].size));
    }
    munit_assert_true(cep_serialization_reader_commit(reader));
    cep_serialization_reader_destroy(reader);

    IntegrationSerializationCapture replay_capture = {0};
    munit_assert_true(cep_serialization_emit_cell(replay_root,
                                                  NULL,
                                                  integration_capture_sink,
                                                  &replay_capture,
                                                  0));
    munit_assert_size(replay_capture.count, ==, capture.count);
    for (size_t i = 0; i < capture.count; ++i) {
        const IntegrationCaptureChunk* original = &capture.chunks[i];
        const IntegrationCaptureChunk* replay_chunk = &replay_capture.chunks[i];
        munit_assert_size(replay_chunk->size, ==, original->size);
        if (original->size >= sizeof(uint64_t) && replay_chunk->size >= sizeof(uint64_t)) {
            uint64_t original_id = 0u;
            uint64_t replay_id = 0u;
            memcpy(&original_id, original->data, sizeof original_id);
            memcpy(&replay_id, replay_chunk->data, sizeof replay_id);
            munit_assert_uint64(replay_id, ==, original_id);
        }
    }

    integration_capture_clear(&replay_capture);
    integration_capture_clear(&capture);

    cep_cell_delete(replay_root);
    cep_cell_remove_hard(replay_root, NULL);
}



/* Register a synthetic `organ:poc` descriptor, run ctor/validator/dtor enzymes, and validate heartbeat integration counters. */
static void integration_exercise_organ_lifecycle(IntegrationFixture* fix) {
    munit_assert_not_null(fix);
    cepCell* poc_root = cep_cell_resolve(fix->poc_root);
    munit_assert_not_null(poc_root);

    integration_organ_init_dts();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);

    munit_assert_true(cep_organ_runtime_bootstrap());

    const cepDT validator_segments[] = { integration_organ_validator_dt };
    IntegrationPathBuf validator_buf = {0};
    const cepPath* validator_path = integration_make_path(&validator_buf,
                                                          validator_segments,
                                                          cep_lengthof(validator_segments));

    const cepDT ctor_segments[] = { integration_organ_constructor_dt };
    IntegrationPathBuf ctor_buf = {0};
    const cepPath* ctor_path = integration_make_path(&ctor_buf,
                                                     ctor_segments,
                                                     cep_lengthof(ctor_segments));

    const cepDT dtor_segments[] = { integration_organ_destructor_dt };
    IntegrationPathBuf dtor_buf = {0};
    const cepPath* dtor_path = integration_make_path(&dtor_buf,
                                                     dtor_segments,
                                                     cep_lengthof(dtor_segments));

    cepEnzymeDescriptor validator_desc = {
        .name = integration_organ_validator_dt,
        .label = "integration-organ-validator",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_organ_validator_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    cepEnzymeDescriptor ctor_desc = {
        .name = integration_organ_constructor_dt,
        .label = "integration-organ-ctor",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_organ_ctor_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    cepEnzymeDescriptor dtor_desc = {
        .name = integration_organ_destructor_dt,
        .label = "integration-organ-dtor",
        .before = NULL,
        .before_count = 0u,
        .after = NULL,
        .after_count = 0u,
        .callback = integration_organ_destructor_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    cepOrganDescriptor organ_desc = {
        .kind = integration_organ_kind,
        .label = "integration.organ.integration_poc",
        .store = integration_organ_store_dt,
        .validator = integration_organ_validator_dt,
        .constructor = integration_organ_constructor_dt,
        .destructor = integration_organ_destructor_dt,
    };
    if (!cep_organ_register(&organ_desc)) {
        const cepOrganDescriptor* existing_desc = cep_organ_descriptor(&integration_organ_store_dt);
        munit_assert_not_null(existing_desc);
    }

    munit_assert_int(cep_enzyme_register(registry, validator_path, &validator_desc), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, ctor_path, &ctor_desc), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_register(registry, dtor_path, &dtor_desc), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);

    cepCell* organ_root = cep_cell_add_dictionary(poc_root,
                                                  CEP_DTAW("CEP", "organ_int"),
                                                  0,
                                                  &integration_organ_store_dt,
                                                  CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(organ_root);
    organ_root = cep_cell_resolve(organ_root);
    munit_assert_not_null(organ_root);

    munit_assert_int(cep_cell_bind_enzyme(organ_root, &integration_organ_validator_dt, true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(organ_root, &integration_organ_constructor_dt, true), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_cell_bind_enzyme(organ_root, &integration_organ_destructor_dt, true), ==, CEP_ENZYME_SUCCESS);

    integration_organ_ctor_calls = 0;
    integration_organ_validator_calls = 0;
    integration_organ_destructor_calls = 0;

    CEP_DEBUG_PRINTF_STDOUT(
        "[integration_poc] organ kind=%s store=%016llx/%016llx",
        integration_organ_kind,
        (unsigned long long)cep_id(integration_organ_store_dt.domain),
        (unsigned long long)cep_id(integration_organ_store_dt.tag));

    munit_assert_true(cep_organ_request_constructor(organ_root));
    unsigned attempts = 0u;
    munit_assert_true(cep_heartbeat_stage_commit());
    while (integration_organ_ctor_calls == 0 && attempts < 32u) {
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        attempts += 1u;
        if (integration_organ_ctor_calls == 0) {
            munit_assert_true(cep_heartbeat_stage_commit());
        }
    }
    munit_assert_int(integration_organ_ctor_calls, ==, 1);

    munit_assert_true(cep_organ_request_validation(organ_root));
    attempts = 0u;
    munit_assert_true(cep_heartbeat_stage_commit());
    while (integration_organ_validator_calls == 0 && attempts < 32u) {
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        attempts += 1u;
        if (integration_organ_validator_calls == 0) {
            munit_assert_true(cep_heartbeat_stage_commit());
        }
    }
    munit_assert_int(integration_organ_validator_calls, ==, 1);

    munit_assert_true(cep_organ_request_destructor(organ_root));
    attempts = 0u;
    munit_assert_true(cep_heartbeat_stage_commit());
    while (integration_organ_destructor_calls == 0 && attempts < 32u) {
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        attempts += 1u;
        if (integration_organ_destructor_calls == 0) {
            munit_assert_true(cep_heartbeat_stage_commit());
        }
    }
    munit_assert_int(integration_organ_destructor_calls, ==, 1);

    cepCell* organ_after = cep_cell_find_by_name(poc_root, CEP_DTAW("CEP", "organ_int"));
    if (organ_after) {
        organ_after = cep_cell_resolve(organ_after);
        if (organ_after) {
            munit_assert_true(cep_cell_is_deleted(organ_after) || cep_cell_children(organ_after) == 0u);
            (void)cep_cell_unbind_enzyme(organ_after, &integration_organ_validator_dt);
            (void)cep_cell_unbind_enzyme(organ_after, &integration_organ_constructor_dt);
            (void)cep_cell_unbind_enzyme(organ_after, &integration_organ_destructor_dt);
        }
    }

    munit_assert_int(cep_enzyme_unregister(registry, dtor_path, &dtor_desc), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_unregister(registry, ctor_path, &ctor_desc), ==, CEP_ENZYME_SUCCESS);
    munit_assert_int(cep_enzyme_unregister(registry, validator_path, &validator_desc), ==, CEP_ENZYME_SUCCESS);
    cep_enzyme_registry_activate_pending(registry);
}

/* Apply deterministic pseudo-random mutations to log and catalog branches, logging the seed for reproducibility. */
static void integration_randomized_mutations(IntegrationFixture* fix) {
    munit_assert_not_null(fix);
    cepCell* catalog = cep_cell_resolve(fix->catalog);
    cepCell* log_branch = cep_cell_resolve(fix->log_branch);
    munit_assert_not_null(catalog);
    munit_assert_not_null(log_branch);

    uint32_t seed = UINT32_C(0xC0FFEE21);
    CEP_DEBUG_PRINTF_STDOUT("[integration_poc] mutation_seed=0x%08x", seed);
    uint32_t state = seed;

    static const char* const catalog_targets[] = {
        "item_a",
        "item_b",
        "item_c",
        "item_d",
        "item_e",
    };

    for (size_t i = 0; i < 4u; ++i) {
        uint32_t roll = integration_prng_next(&state);
        size_t index = roll % cep_lengthof(catalog_targets);
        cepDT target_name = integration_named_dt(catalog_targets[index]);
        cepCell* node = cep_cell_find_by_name(catalog, &target_name);
        if (!node) {
            continue;
        }
        node = cep_cell_resolve(node);
        if (!node) {
            continue;
        }
        IntegrationPoint mutated = {{
            ((int32_t)(roll & 0xFF) - 128) / 16.0f,
            ((int32_t)((roll >> 8) & 0xFF) - 128) / 16.0f,
            ((int32_t)((roll >> 16) & 0xFF) - 128) / 16.0f,
        }};
        munit_assert_not_null(cep_cell_update_value(node, sizeof mutated, &mutated));
    }

    for (size_t i = 0; i < 3u; ++i) {
        uint32_t roll = integration_prng_next(&state);
        char name_buf[24];
        snprintf(name_buf, sizeof name_buf, "rand_entry_%zu", i);
        cepDT entry_name = integration_named_dt(name_buf);

        char message[40];
        snprintf(message, sizeof message, "rand-log:%08x:%zu", roll, i);
        size_t message_len = strlen(message) + 1u;

        munit_assert_not_null(cep_cell_add_value(log_branch,
                                                 &entry_name,
                                                 0,
                                                 &fix->log_type,
                                                 message,
                                                 message_len,
                                                 message_len));
    }

    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_step());
}

/**
 * Validates the bootstrap timeline, append-only payload/store history,
 * link/shadow bookkeeping, and lock enforcement while building the `/data/poc`
 * tree that later phases extend.
 */
static MunitResult test_l0_integration(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    IntegrationFixture fixture = {.boot_oid = cep_oid_invalid()};
    integration_runtime_boot(&fixture);
    integration_build_tree(&fixture);
    integration_execute_interleaved_timeline(&fixture);
    integration_teardown_tree(&fixture);
    integration_runtime_cleanup(&fixture);

    return MUNIT_OK;
}

static MunitTest integration_poc_tests[] = {
    {
        "/l0/integration",
        test_l0_integration,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

MunitSuite integration_poc_suite = {
    .prefix = "/integration_poc",
    .tests = integration_poc_tests,
    .suites = NULL,
    .iterations = 1,
    .options = MUNIT_SUITE_OPTION_NONE,
};
