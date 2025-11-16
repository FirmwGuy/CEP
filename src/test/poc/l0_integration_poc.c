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
#include "cep_flat_stream.h"
#include "cep_flat_serializer.h"
#include "cep_ep.h"
#include "secdata/cep_secdata.h"
#include "cps_flatfile.h"
#include "../l0_kernel/cep_io_reactor.h"
#include "stream/cep_stream_internal.h"
#include "stream/cep_stream_stdio.h"

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <math.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>

CEP_DEFINE_STATIC_DT(dt_stream_payload_outcome, CEP_ACRO("CEP"), CEP_WORD("outcome"));
CEP_DEFINE_STATIC_DT(dt_stream_payload_log, CEP_ACRO("CEP"), CEP_WORD("stream-log"));
CEP_DEFINE_STATIC_DT(dt_stream_payload_library, CEP_ACRO("CEP"), CEP_WORD("library"));
CEP_DEFINE_STATIC_DT(dt_stream_payload_stdio_res, CEP_ACRO("CEP"), CEP_WORD("stdio_res"));
CEP_DEFINE_STATIC_DT(dt_stream_payload_stdio_stream, CEP_ACRO("CEP"), CEP_WORD("stdio_str"));
CEP_DEFINE_STATIC_DT(dt_poc_item_payload, CEP_ACRO("CEP"), CEP_WORD("poc_item"));
CEP_DEFINE_STATIC_DT(dt_poc_event_payload, CEP_ACRO("CEP"), CEP_WORD("poc_event"));
CEP_DEFINE_STATIC_DT(dt_oct_point_payload, CEP_ACRO("CEP"), CEP_WORD("oct_point"));

/* NOTE: Replay subtrees are synthetic. If we do not explicitly drop the cloned
 * payloads (`poc_item`, `poc_event`, `oct_point`, stream outcomes/logs/handles)
 * before calling `cep_cell_remove_hard`, sanitizers report the leaked
 * `cepData` allocations. Keep the release helpers below wired into every replay
 * teardown path so future changes do not regress the leak fix. */

typedef struct {
    float position[3];
} IntegrationPoint;

typedef struct {
    uint64_t offset;
    uint64_t requested;
    uint64_t actual;
    uint64_t hash;
    uint32_t flags;
    uint32_t reserved;
    uint64_t unix_ts_ns;
} IntegrationJournalEntrySnapshot;

static const char* integration_debug_id_desc(cepID id, char* buf, size_t cap) {
    if (!buf || !cap)
        return "";
    if (!id) {
        snprintf(buf, cap, "0");
        return buf;
    }
    if (cep_id_is_reference(id)) {
        const char* text = cep_namepool_lookup(id, NULL);
        if (text) {
            snprintf(buf, cap, "%s", text);
            return buf;
        }
    } else if (cep_id_is_word(id)) {
        size_t len = cep_word_to_text(id, buf);
        if (len >= cap)
            len = cap - 1u;
        buf[len] = '\0';
        return buf;
    } else if (cep_id_is_acronym(id)) {
        size_t len = cep_acronym_to_text(id, buf);
        if (len >= cap)
            len = cap - 1u;
        buf[len] = '\0';
        while (len && buf[len - 1] == ' ')
            buf[--len] = '\0';
        return buf;
    } else if (cep_id_is_numeric(id)) {
        snprintf(buf, cap, "#%llu", (unsigned long long)cep_id_to_numeric(id));
        return buf;
    }
    snprintf(buf, cap, "0x%016" PRIx64, (uint64_t)id);
    return buf;
}

static bool integration_serialization_logging_enabled(void);

#ifdef CEP_ENABLE_DEBUG
#define INTEGRATION_DEBUG_PRINTF(...)                                                 \
    do {                                                                             \
        if (integration_serialization_logging_enabled()) {                           \
            CEP_DEBUG_PRINTF_STDOUT(__VA_ARGS__);                                     \
        }                                                                            \
    } while (0)
#else
#define INTEGRATION_DEBUG_PRINTF(...) do { } while (0)
#endif

static void integration_debug_print_path(const cepCell* cell) {
#ifdef CEP_ENABLE_DEBUG
    if (!cell)
        return;
    cepPath* path = NULL;
    if (!cep_cell_path(cell, &path))
        return;
    INTEGRATION_DEBUG_PRINTF("[integration][parity] path_len=%u", path ? path->length : 0u);
    if (path) {
        for (unsigned i = 0; i < path->length; ++i) {
            char dom_buf[64];
            char tag_buf[64];
            cepDT clean = cep_dt_clean(&path->past[i].dt);
            INTEGRATION_DEBUG_PRINTF("  segment[%u]=%016" PRIx64 "/%016" PRIx64 " (%s/%s)",
                                    i,
                                    (uint64_t)clean.domain,
                                    (uint64_t)clean.tag,
                                    integration_debug_id_desc(clean.domain, dom_buf, sizeof dom_buf),
                                    integration_debug_id_desc(clean.tag, tag_buf, sizeof tag_buf));
        }
        cep_free(path);
    }
#else
    (void)cell;
#endif
}

typedef struct {
    cepOID   boot_oid;
    cepCell* poc_root;
    cepPath* poc_path;
    cepCell* catalog;
    cepCell* secdata_cell;
    cepCell* log_branch;
    cepCell* space_root;
    cepCell* space_entry;
    cepDT    item_type;
    cepDT    log_type;
    cepRuntime* runtime;
    cepRuntime* previous_runtime;
} IntegrationFixture;

static const char*
integration_ops_child_cstr(cepCell* parent, const char* field_name)
{
    if (!parent || !field_name) {
        return NULL;
    }
    cepDT field = cep_ops_make_dt(field_name);
    cepCell* leaf = cep_cell_find_by_name(parent, &field);
    if (!leaf) {
        return NULL;
    }
    return (const char*)cep_cell_data(leaf);
}

static size_t
integration_async_pending_request_count(cepCell* async_entry)
{
    if (!async_entry) {
        return 0u;
    }
    cepDT req_branch = cep_ops_make_dt("io_req");
    cepCell* req_root = cep_cell_find_by_name(async_entry, &req_branch);
    if (!req_root || !req_root->store) {
        return 0u;
    }

    size_t pending = 0u;
    for (cepCell* req = cep_cell_first(req_root); req; req = cep_cell_next(req_root, req)) {
        ++pending;
    }
    return pending;
}

static void
integration_assert_async_runtime_idle(const char* stage_label)
{
    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return;
    }

    cepDT ops_name = cep_ops_make_dt("ops");
    cepCell* ops_root = cep_cell_find_by_name(rt_root, &ops_name);
    if (!ops_root || !ops_root->store) {
        return;
    }

    for (cepCell* entry = cep_cell_first(ops_root); entry; entry = cep_cell_next(ops_root, entry)) {
        const char* path = integration_ops_child_cstr(entry, "path");
        if (!path || strcmp(path, "/rt/async") != 0) {
            continue;
        }
        size_t pending = integration_async_pending_request_count(entry);
        if (pending != 0u) {
            munit_logf(MUNIT_LOG_ERROR,
                       "[integration][async_guard] pending io_req=%zu stage=%s",
                       pending,
                       stage_label ? stage_label : "cleanup");
        }
        munit_assert_size(pending, ==, 0u);
        break;
    }
}

static bool integration_env_flag(const char* name) {
    const char* value = getenv(name);
    if (!value || !*value)
        return false;
    if (strcmp(value, "0") == 0)
        return false;
    if (strcasecmp(value, "false") == 0)
        return false;
    return true;
}

static bool integration_prr_is_disabled(void) {
    return integration_env_flag("CEP_POC_DISABLE_PRR");
}

static bool integration_prr_skip_rollback(void) {
    return integration_env_flag("CEP_POC_DISABLE_PRR_ROLLBACK");
}

static bool integration_focus_random_mutations_enabled(void) {
    return integration_env_flag("CEP_POC_FOCUS_RANDOM_MUTATIONS");
}

static bool integration_focus_catalog_plan_enabled(void) {
    return integration_env_flag("CEP_POC_FOCUS_CATALOG_PLAN");
}

static bool integration_focus_txn_enabled(void) {
    return integration_env_flag("CEP_POC_FOCUS_TXN_FLOW");
}

static bool integration_focus_organ_enabled(void) {
    return integration_env_flag("CEP_POC_FOCUS_ORGAN");
}

static bool integration_focus_stream_flow_enabled(void) {
    return integration_env_flag("CEP_POC_FOCUS_STREAM_FLOW");
}

static bool integration_focus_ops_ctx_enabled(void) {
    return integration_env_flag("CEP_POC_FOCUS_OPS_CTX");
}

static bool integration_focus_random_plan_enabled(void) {
    return integration_env_flag("CEP_POC_FOCUS_RANDOM_PLAN");
}

static bool integration_cps_flow_enabled(void) {
    return !integration_env_flag("CEP_POC_DISABLE_CPS");
}

static bool integration_serialization_logging_enabled(void) {
    return integration_env_flag("CEP_POC_SERIALIZATION_DEBUG") ||
           integration_env_flag("CEP_SERIALIZATION_DEBUG");
}

static bool integration_serialization_log_all_enabled(void) {
    return integration_env_flag("CEP_POC_SERIALIZATION_LOG_ALL");
}
static bool integration_focus_test_enabled(void) {
    const char* value = getenv("CEP_POC_ENABLE_SERIALIZATION_FOCUS");
    if (!value || !*value)
        return true;
    if (strcmp(value, "0") == 0)
        return false;
    if (strcasecmp(value, "false") == 0)
        return false;
    return true;
}

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
    (void)beat;
    INTEGRATION_DEBUG_PRINTF("[integration_poc] beat=%llu %s", (unsigned long long)beat, label);
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

static void integration_cps_roundtrip(IntegrationFixture* fix, const IntegrationSerializationCapture* capture);
static void integration_dump_trace(const IntegrationSerializationCapture* capture, const char* suffix);

static const char* integration_stage_log_path(void) {
    return "tmp/integration_assert_stage.log";
}

static void integration_trace_reset_stage_log(void) {
    const char* path = integration_stage_log_path();
    FILE* file = fopen(path, "w");
    if (file)
        fclose(file);
}

static void integration_trace_log_stage(const char* stage) {
    const char* path = integration_stage_log_path();
    FILE* file = fopen(path, "a");
    if (!file)
        return;
    fprintf(file, "%s\n", stage ? stage : "<null>");
    fclose(file);
}

static void integration_trace_assert_stage(const char* stage) {
    if (!stage || !*stage)
        return;
    if (!integration_serialization_logging_enabled())
        return;
    fprintf(stderr, "[integration][assert-stage] %s\n", stage);
    fflush(stderr);
    integration_trace_log_stage(stage);
}

static size_t integration_chunk_first_diff(const IntegrationCaptureChunk* baseline,
                                           const IntegrationCaptureChunk* replayed) {
    if (!baseline || !replayed || !baseline->data || !replayed->data)
        return SIZE_MAX;
    size_t limit = baseline->size < replayed->size ? baseline->size : replayed->size;
    for (size_t offset = 0; offset < limit; ++offset) {
        if (baseline->data[offset] != replayed->data[offset])
            return offset;
    }
    if (baseline->size != replayed->size)
        return limit;
    return SIZE_MAX;
}

static size_t integration_payload_first_diff(const uint8_t* baseline,
                                             const uint8_t* candidate,
                                             size_t size) {
    if (!baseline || !candidate)
        return SIZE_MAX;
    for (size_t idx = 0; idx < size; ++idx) {
        if (baseline[idx] != candidate[idx])
            return idx;
    }
    return SIZE_MAX;
}

static bool integration_payload_should_skip_binary_compare(const cepDT* dt,
                                                           unsigned datatype) {
    if (!dt)
        return false;
    cepDT stdio_res = *CEP_DTAW("CEP", "stdio_res");
    cepDT library_dt = *CEP_DTAW("CEP", "library");
    cepDT cleaned = cep_dt_clean(dt);
    cepDT outcome_dt = *CEP_DTAW("CEP", "outcome");
    if ((datatype == CEP_DATATYPE_DATA || datatype == CEP_DATATYPE_VALUE) &&
        cleaned.domain == stdio_res.domain &&
        cleaned.tag == stdio_res.tag) {
        return true;
    }
    if ((datatype == CEP_DATATYPE_DATA || datatype == CEP_DATATYPE_VALUE) &&
        cleaned.domain == library_dt.domain &&
        cleaned.tag == library_dt.tag) {
        return true;
    }
    if ((datatype == CEP_DATATYPE_DATA || datatype == CEP_DATATYPE_VALUE) &&
        cleaned.domain == outcome_dt.domain &&
        cleaned.tag == outcome_dt.tag) {
        return true;
    }
    return false;
}

static void integration_log_chunk_diff(size_t chunk_index,
                                       size_t offset,
                                       size_t baseline_size,
                                       size_t replay_size,
                                       uint8_t baseline_byte,
                                       uint8_t replay_byte) {
    if (!integration_serialization_logging_enabled())
        return;
    fprintf(stderr,
            "[integration][chunk-diff] chunk=%zu offset=%zu baseline_size=%zu replay_size=%zu baseline=0x%02x replay=0x%02x\n",
            chunk_index,
            offset,
            baseline_size,
            replay_size,
            baseline_byte,
            replay_byte);
    fflush(stderr);
}

static void integration_log_payload_diff(const cepCell* baseline,
                                         const cepCell* candidate,
                                         size_t size,
                                         size_t offset,
                                         uint8_t baseline_byte,
                                         uint8_t candidate_byte) {
    INTEGRATION_DEBUG_PRINTF("[integration][payload-diff] offset=%zu size=%zu baseline=0x%02x candidate=0x%02x",
                            offset,
                            size,
                            baseline_byte,
                            candidate_byte);
    if (baseline && baseline->data && candidate && candidate->data) {
        cepDT data_dt = cep_dt_clean(&baseline->data->dt);
        cepDT outcome_dt = *CEP_DTAW("CEP", "outcome");
        cepDT stream_log_dt = *CEP_DTAW("CEP", "stream-log");
        if (data_dt.domain == outcome_dt.domain && data_dt.tag == outcome_dt.tag) {
            const cepStreamOutcomeEntry* base_entry = (const cepStreamOutcomeEntry*)cep_cell_data(baseline);
            const cepStreamOutcomeEntry* cand_entry = (const cepStreamOutcomeEntry*)cep_cell_data(candidate);
            if (base_entry && cand_entry) {
                INTEGRATION_DEBUG_PRINTF("[integration][payload-diff][outcome] base(offset=%" PRIu64 ", len=%" PRIu64 ", payload=0x%016" PRIx64 ", expected=0x%016" PRIx64 ", result=0x%016" PRIx64 ") cand(offset=%" PRIu64 ", len=%" PRIu64 ", payload=0x%016" PRIx64 ", expected=0x%016" PRIx64 ", result=0x%016" PRIx64 ")",
                                        base_entry->offset,
                                        base_entry->length,
                                        base_entry->payload_hash,
                                        base_entry->expected_hash,
                                        base_entry->resulting_hash,
                                        cand_entry->offset,
                                        cand_entry->length,
                                        cand_entry->payload_hash,
                                        cand_entry->expected_hash,
                                        cand_entry->resulting_hash);
            }
        } else if (data_dt.domain == stream_log_dt.domain && data_dt.tag == stream_log_dt.tag) {
            const IntegrationJournalEntrySnapshot* base_entry = (const IntegrationJournalEntrySnapshot*)cep_cell_data(baseline);
            const IntegrationJournalEntrySnapshot* cand_entry = (const IntegrationJournalEntrySnapshot*)cep_cell_data(candidate);
            if (base_entry && cand_entry) {
                INTEGRATION_DEBUG_PRINTF("[integration][payload-diff][journal] base(offset=%" PRIu64 ", req=%" PRIu64 ", actual=%" PRIu64 ", hash=0x%016" PRIx64 ", flags=0x%08" PRIx32 ") cand(offset=%" PRIu64 ", req=%" PRIu64 ", actual=%" PRIu64 ", hash=0x%016" PRIx64 ", flags=0x%08" PRIx32 ")",
                                        base_entry->offset,
                                        base_entry->requested,
                                        base_entry->actual,
                                        base_entry->hash,
                                        (uint32_t)base_entry->flags,
                                        cand_entry->offset,
                                        cand_entry->requested,
                                        cand_entry->actual,
                                        cand_entry->hash,
                                        (uint32_t)cand_entry->flags);
            }
        }
    }
    integration_debug_print_path(baseline);
    integration_debug_print_path(candidate);
}

static bool integration_capture_append(IntegrationSerializationCapture* capture,
                                       const uint8_t* chunk,
                                       size_t size) {
    if (!capture || !chunk) {
        return false;
    }

    if (capture->count == capture->capacity) {
        size_t next = capture->capacity ? (capture->capacity * 2u) : 4u;
        IntegrationCaptureChunk* grown = capture->chunks
            ? cep_realloc(capture->chunks, next * sizeof *capture->chunks)
            : cep_malloc(next * sizeof *capture->chunks);
        if (!grown) {
            if (integration_serialization_logging_enabled()) {
                fprintf(stderr, "[integration][debug] capture realloc fail next=%zu\n", next);
                fflush(stderr);
            }
            return false;
        }
        memset(grown + capture->capacity, 0, (next - capture->capacity) * sizeof *grown);
        capture->chunks = grown;
        capture->capacity = next;
    }

    size_t alloc_size = size ? size : 1u;
    uint8_t* copy = cep_malloc(alloc_size);
    if (!copy) {
        if (integration_serialization_logging_enabled()) {
            fprintf(stderr, "[integration][debug] capture alloc fail size=%zu\n", alloc_size);
            fflush(stderr);
        }
        return false;
    }
    if (size)
        memcpy(copy, chunk, size);
    else
        memset(copy, 0, alloc_size);
    capture->chunks[capture->count].data = copy;
    capture->chunks[capture->count].size = size;
    capture->count += 1u;

    if (integration_serialization_logging_enabled()) {
        fprintf(stderr,
                "[integration][debug] capture chunk=%zu size=%zu\n",
                capture->count - 1u,
                size);
        fflush(stderr);
    }

    return true;
}

static bool integration_capture_sink(void* ctx, const uint8_t* chunk, size_t size) {
    return integration_capture_append((IntegrationSerializationCapture*)ctx, chunk, size);
}

static cepFlatBranchFrameInfo
integration_branch_frame_info(IntegrationFixture* fix, cepCell* branch_root) {
    cepFlatBranchFrameInfo info = {0};
    if (!fix || !branch_root) {
        return info;
    }
    cepCell* resolved = cep_cell_resolve(branch_root);
    if (resolved) {
        const cepDT* dt = cep_cell_get_name(resolved);
        if (dt) {
            cepDT clean = cep_dt_clean(dt);
            info.branch_domain = (uint64_t)cep_id(clean.domain);
            info.branch_tag = (uint64_t)cep_id(clean.tag);
            info.branch_glob = clean.glob ? 1u : 0u;
        }
    }
    info.frame_id = 1u;
    return info;
}

static bool
integration_capture_branch_frame(IntegrationFixture* fix,
                                 cepCell* branch_root,
                                 IntegrationSerializationCapture* capture) {
    if (!fix || !branch_root || !capture) {
        return false;
    }
    cepFlatBranchFrameInfo frame_info = integration_branch_frame_info(fix, branch_root);
    cepFlatStreamAsyncStats stats = {
        .require_sync_copy = true,
        .completion_cb = NULL,
        .completion_ctx = NULL,
    };
    return cep_flat_stream_emit_branch_async(branch_root,
                                             &frame_info,
                                             NULL,
                                             integration_capture_sink,
                                             capture,
                                             0u,
                                             &stats);
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

static size_t integration_capture_total_bytes(const IntegrationSerializationCapture* capture) {
    if (!capture)
        return 0u;
    size_t total = 0u;
    for (size_t i = 0; i < capture->count; ++i) {
        total += capture->chunks[i].size;
    }
    return total;
}

static void integration_assert_capture_bytes_equal(const IntegrationSerializationCapture* baseline,
                                                   const IntegrationSerializationCapture* candidate,
                                                   const char* label) {
    if (!baseline || !candidate)
        munit_error("capture comparison received NULL input");
    munit_assert_size(baseline->count, ==, candidate->count);
    for (size_t i = 0; i < baseline->count; ++i) {
        const IntegrationCaptureChunk* base_chunk = &baseline->chunks[i];
        const IntegrationCaptureChunk* cand_chunk = &candidate->chunks[i];
        munit_assert_size(base_chunk->size, ==, cand_chunk->size);
        if (!base_chunk->size)
            continue;
        munit_assert_ptr_not_null(base_chunk->data);
        munit_assert_ptr_not_null(cand_chunk->data);
        size_t diff = integration_chunk_first_diff(base_chunk, cand_chunk);
        if (diff != SIZE_MAX) {
            munit_errorf("%s chunk[%zu] mismatch at offset=%zu (0x%02x vs 0x%02x)",
                         label ? label : "capture-bytes",
                         i,
                         diff,
                         base_chunk->data[diff],
                         cand_chunk->data[diff]);
        }
    }
}

static const char* integration_flat_record_type_name(uint8_t type) {
    switch (type) {
    case CEP_FLAT_RECORD_CELL_DESC:
        return "cell_desc";
    case CEP_FLAT_RECORD_PAYLOAD_CHUNK:
        return "payload_chunk";
    case CEP_FLAT_RECORD_MANIFEST_DELTA:
        return "manifest_delta";
    case CEP_FLAT_RECORD_ORDER_DELTA:
        return "order_delta";
    case CEP_FLAT_RECORD_NAMEPOOL_DELTA:
        return "namepool_delta";
    case CEP_FLAT_RECORD_PAYLOAD_HISTORY:
        return "payload_history";
    case CEP_FLAT_RECORD_MANIFEST_HISTORY:
        return "manifest_history";
    case CEP_FLAT_RECORD_FRAME_TRAILER:
        return "frame_trailer";
    default:
        return "unknown";
    }
}

static bool integration_capture_feed_flat_reader(const IntegrationSerializationCapture* capture,
                                                 cepFlatReader* reader) {
    if (!capture || !reader) {
        return false;
    }
    for (size_t i = 0; i < capture->count; ++i) {
        const IntegrationCaptureChunk* chunk = &capture->chunks[i];
        if (!chunk->data || chunk->size == 0u) {
            continue;
        }
        if (!cep_flat_reader_feed(reader, chunk->data, chunk->size)) {
            return false;
        }
    }
    return true;
}

static void integration_flat_format_key_prefix(const cepFlatRecordView* record,
                                               char* buffer,
                                               size_t cap,
                                               size_t limit_segments) {
    if (!buffer || cap == 0u) {
        return;
    }
    buffer[0] = '\0';
    if (!record || !record->key.data || record->key.size <= 1u) {
        return;
    }
    const uint8_t* cursor = record->key.data + 1u;
    size_t remaining = record->key.size - 1u;
    size_t used = 0u;
    size_t emitted = 0u;
    const size_t segment_bytes = (sizeof(uint64_t) * 2u) + 1u;
    while (remaining >= segment_bytes && (limit_segments == 0u || emitted < limit_segments)) {
        uint64_t domain = 0u;
        uint64_t tag = 0u;
        memcpy(&domain, cursor, sizeof domain);
        cursor += sizeof domain;
        memcpy(&tag, cursor, sizeof tag);
        cursor += sizeof tag;
        uint8_t glob = *cursor++;
        remaining -= segment_bytes;
        char domain_buf[64];
        char tag_buf[64];
        const char* domain_text = integration_debug_id_desc((cepID)domain, domain_buf, sizeof domain_buf);
        const char* tag_text = integration_debug_id_desc((cepID)tag, tag_buf, sizeof tag_buf);
        int written = snprintf(buffer + used,
                               (used < cap) ? cap - used : 0u,
                               "/%s:%s%s",
                               domain_text,
                               tag_text,
                               glob ? "*" : "");
        if (written < 0) {
            buffer[cap - 1u] = '\0';
            return;
        }
        if ((size_t)written >= cap - used) {
            buffer[cap - 1u] = '\0';
            return;
        }
        used += (size_t)written;
        ++emitted;
    }
    if (remaining > 0u && used + 3u < cap) {
        memcpy(buffer + used, "+..", 3u);
        buffer[used + 3u] = '\0';
    }
}

static bool integration_flat_key_has_prefix(const cepFlatRecordView* record,
                                            const cepDT* prefix,
                                            size_t prefix_segments) {
    if (!record || !record->key.data || record->key.size <= 1u || !prefix || prefix_segments == 0u) {
        return false;
    }
    const size_t segment_bytes = (sizeof(uint64_t) * 2u) + 1u;
    size_t needed = 1u + prefix_segments * segment_bytes;
    if (record->key.size < needed) {
        return false;
    }
    const uint8_t* cursor = record->key.data + 1u;
    for (size_t i = 0; i < prefix_segments; ++i) {
        uint64_t domain = 0u;
        uint64_t tag = 0u;
        memcpy(&domain, cursor, sizeof domain);
        cursor += sizeof domain;
        memcpy(&tag, cursor, sizeof tag);
        cursor += sizeof tag;
        uint8_t glob = *cursor++;
        if (domain != prefix[i].domain ||
            tag != prefix[i].tag ||
            glob != (prefix[i].glob ? 1u : 0u)) {
            return false;
        }
    }
    return true;
}

static void integration_assert_flat_frame_contract(const IntegrationSerializationCapture* capture,
                                                   const char* stage) {
    if (!capture) {
        return;
    }
    munit_assert_size(capture->count, >, 0u);
    const char* label = stage ? stage : "<capture>";
    integration_dump_trace(capture, "flat_contract.bin");
    cepFlatReader* reader = cep_flat_reader_create();
    munit_assert_not_null(reader);
    munit_assert_true(integration_capture_feed_flat_reader(capture, reader));
    if (!cep_flat_reader_commit(reader)) {
        size_t total_bytes = 0u;
        for (size_t i = 0; i < capture->count; ++i) {
            total_bytes += capture->chunks[i].size;
        }
        munit_logf(MUNIT_LOG_WARNING,
                   "%s flat frame commit failed (chunks=%zu total_bytes=%zu) — treating capture as legacy",
                   label,
                   capture->count,
                   total_bytes);
        cep_flat_reader_destroy(reader);
        return;
    }
    munit_assert_true(cep_flat_reader_ready(reader));
    const cepFlatFrameConfig* frame = cep_flat_reader_frame(reader);
    munit_assert_not_null(frame);
    (void)frame;
    size_t record_count = 0u;
    const cepFlatRecordView* records = cep_flat_reader_records(reader, &record_count);
    munit_assert_not_null(records);
    munit_assert_size(record_count, >, 0u);
    bool saw_cell_desc = false;
    for (size_t i = 0; i < record_count; ++i) {
        if (records[i].type == CEP_FLAT_RECORD_CELL_DESC) {
            saw_cell_desc = true;
            break;
        }
    }
    if (!saw_cell_desc) {
        munit_errorf("%s missing CEP_FLAT_RECORD_CELL_DESC", label);
    }
    cep_flat_reader_destroy(reader);
}

static void integration_log_flat_records(const IntegrationSerializationCapture* capture,
                                         const char* stage,
                                         const cepDT* path_prefix,
                                         size_t path_segments) {
    if (!capture || !integration_serialization_logging_enabled()) {
        return;
    }
    cepFlatReader* reader = cep_flat_reader_create();
    if (!reader) {
        return;
    }
    if (!integration_capture_feed_flat_reader(capture, reader) ||
        !cep_flat_reader_commit(reader) ||
        !cep_flat_reader_ready(reader)) {
        cep_flat_reader_destroy(reader);
        return;
    }
    size_t record_count = 0u;
    const cepFlatRecordView* records = cep_flat_reader_records(reader, &record_count);
    if (!records) {
        cep_flat_reader_destroy(reader);
        return;
    }
    const char* label = stage ? stage : "<capture>";
    for (size_t i = 0; i < record_count; ++i) {
        if (path_prefix && path_segments > 0u &&
            !integration_flat_key_has_prefix(&records[i], path_prefix, path_segments)) {
            continue;
        }
        char path_buf[256];
        integration_flat_format_key_prefix(&records[i], path_buf, sizeof path_buf, path_segments ? path_segments : 4u);
        fprintf(stderr,
                "[integration][flat] stage=%s record=%zu type=%s key=%zu body=%zu path=%s\n",
                label,
                i,
                integration_flat_record_type_name(records[i].type),
                records[i].key.size,
                records[i].body.size,
                path_buf[0] ? path_buf : "(n/a)");
    }
    fflush(stderr);
    cep_flat_reader_destroy(reader);
}

static void integration_dump_trace(const IntegrationSerializationCapture* capture, const char* suffix) {
    const char* base = getenv("CEP_SERIALIZATION_TRACE_DIR");
    if (!base || !capture || !suffix)
        return;

    if (integration_serialization_logging_enabled()) {
        fprintf(stderr, "[integration][debug] trace_dir=%s suffix=%s chunks=%zu\n", base, suffix, capture->count);
        fflush(stderr);
    }

    if (mkdir(base, 0775) != 0 && errno != EEXIST)
        return;

    char path[1024];
    if (snprintf(path, sizeof path, "%s/%s", base, suffix) < 0 || strlen(path) >= sizeof path)
        return;

    FILE* fp = fopen(path, "wb");
    if (!fp)
        return;

    for (size_t i = 0; i < capture->count; ++i) {
        const IntegrationCaptureChunk* chunk = &capture->chunks[i];
        if (!chunk->data || !chunk->size)
            continue;
        fwrite(chunk->data, 1u, chunk->size, fp);
    }

    fclose(fp);
}

static void integration_log_space_flat_records(const IntegrationSerializationCapture* capture,
                                               const char* stage) {
    if (!capture || !integration_serialization_logging_enabled()) {
        return;
    }
    if (integration_serialization_log_all_enabled()) {
        integration_log_flat_records(capture, stage, NULL, 0u);
    }
    cepDT space_path_segments[3];
    space_path_segments[0] = *CEP_DTAW("CEP", "data");
    space_path_segments[1] = *CEP_DTAW("CEP", "poc");
    space_path_segments[2] = *CEP_DTAW("CEP", "space");
    integration_log_flat_records(capture, stage, space_path_segments, cep_lengthof(space_path_segments));
}

static bool integration_ensure_parent_dirs(char* path) {
    if (!path) {
        return false;
    }
    size_t len = strlen(path);
    if (!len) {
        return false;
    }
    for (size_t i = 1u; i < len; ++i) {
        if (path[i] != '/') {
            continue;
        }
        char saved = path[i];
        path[i] = '\0';
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            path[i] = saved;
            return false;
        }
        path[i] = saved;
    }
    return true;
}

static bool integration_make_temp_root(char* buffer, size_t cap) {
    if (!buffer || cap == 0u) {
        return false;
    }
    const char* base = getenv("MESON_BUILD_ROOT");
    if (!base || !*base) {
        base = "build";
    }
    char tmpl[PATH_MAX];
    int written = snprintf(tmpl, sizeof tmpl, "%s/integration_cps.XXXXXX", base);
    if (written < 0 || (size_t)written >= sizeof tmpl) {
        return false;
    }
    if (!integration_ensure_parent_dirs(tmpl)) {
        return false;
    }
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        return false;
    }
    if ((size_t)snprintf(buffer, cap, "%s", dir) >= cap) {
        return false;
    }
    return true;
}

static void integration_remove_tree(const char* path) {
    if (!path || !*path) {
        return;
    }
    DIR* dir = opendir(path);
    if (!dir) {
        (void)remove(path);
        return;
    }
    struct dirent* entry = NULL;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child[PATH_MAX];
        if ((size_t)snprintf(child, sizeof child, "%s/%s", path, entry->d_name) >= sizeof child) {
            continue;
        }
        struct stat st;
        if (lstat(child, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            integration_remove_tree(child);
        } else {
            (void)unlink(child);
        }
    }
    closedir(dir);
    (void)rmdir(path);
}

static uint64_t integration_read_uint64_field(cepCell* parent, const char* field_name) {
    munit_assert_not_null(parent);
    munit_assert_not_null(field_name);
    cepDT field_dt = cep_ops_make_dt(field_name);
    cepCell* field = cep_cell_find_by_name(parent, &field_dt);
    munit_assert_not_null(field);
    cepCell* resolved = cep_cell_resolve(field);
    munit_assert_not_null(resolved);
    const uint64_t* payload = (const uint64_t*)cep_cell_data(resolved);
    munit_assert_not_null(payload);
    return *payload;
}

static bool integration_cps_apply_reader(cps_engine* engine, cepFlatReader* reader) {
    if (!engine || !engine->ops || !reader) {
        return false;
    }
    size_t record_count = 0u;
    const cepFlatRecordView* records = cep_flat_reader_records(reader, &record_count);
    if (!records) {
        return false;
    }
    const cepFlatFrameConfig* frame = cep_flat_reader_frame(reader);
    uint64_t beat_no = frame ? frame->beat_number : 0u;
    if (beat_no == 0u) {
        cepBeatNumber current = cep_beat_index();
        if (current != CEP_BEAT_INVALID) {
            beat_no = (uint64_t)current;
        }
    }
    if (!engine->ops->begin_beat || !engine->ops->put_record || !engine->ops->commit_beat) {
        return false;
    }
    cps_txn* txn = NULL;
    int rc = engine->ops->begin_beat(engine, beat_no, &txn);
    if (rc != CPS_OK || !txn) {
        return false;
    }
    for (size_t i = 0; i < record_count; ++i) {
        cps_slice key = {
            .data = records[i].key.data,
            .len = records[i].key.size,
        };
        cps_slice value = {
            .data = records[i].body.data,
            .len = records[i].body.size,
        };
        rc = engine->ops->put_record(txn, key, value, records[i].type);
        if (rc != CPS_OK) {
            if (engine->ops->abort_beat) {
                engine->ops->abort_beat(txn);
            }
            return false;
        }
    }
    cps_frame_meta meta = {
        .beat = beat_no,
    };
    const uint8_t* merkle = cep_flat_reader_merkle_root(reader);
    if (merkle) {
        memcpy(meta.merkle, merkle, sizeof meta.merkle);
    }
    rc = engine->ops->commit_beat(txn, &meta);
    if (rc != CPS_OK) {
        if (engine->ops->abort_beat) {
            engine->ops->abort_beat(txn);
        }
        return false;
    }
    return true;
}

static void integration_assert_persist_metrics(const char* branch_name, uint64_t min_frames) {
    munit_assert_not_null(branch_name);
    cepCell* data_root = cep_cell_resolve(cep_heartbeat_data_root());
    munit_assert_not_null(data_root);
    cepCell* persist_root = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "persist"));
    munit_assert_not_null(persist_root);
    cepCell* resolved_persist = cep_cell_resolve(persist_root);
    munit_assert_not_null(resolved_persist);
    cepDT branch_dt = cep_ops_make_dt(branch_name);
    cepCell* branch_cell = cep_cell_find_by_name(resolved_persist, &branch_dt);
    munit_assert_not_null(branch_cell);
    cepCell* resolved_branch = cep_cell_resolve(branch_cell);
    munit_assert_not_null(resolved_branch);

    cepCell* engine_field = cep_cell_find_by_name(resolved_branch, CEP_DTAW("CEP", "kv_eng"));
    munit_assert_not_null(engine_field);
    const char* engine_text = (const char*)cep_cell_data(engine_field);
    munit_assert_not_null(engine_text);
    munit_assert_string_equal(engine_text, "flatfile");

    cepCell* metrics_cell = cep_cell_find_by_name(resolved_branch, CEP_DTAW("CEP", "metrics"));
    munit_assert_not_null(metrics_cell);
    cepCell* resolved_metrics = cep_cell_resolve(metrics_cell);
    munit_assert_not_null(resolved_metrics);
    uint64_t frames = integration_read_uint64_field(resolved_metrics, "frames");
    munit_assert_uint64(frames, >=, min_frames);
    uint64_t beats = integration_read_uint64_field(resolved_metrics, "beats");
    munit_assert_uint64(beats, >=, min_frames);

    cep_cell_delete_hard(branch_cell);
}

static void integration_cps_roundtrip(IntegrationFixture* fix, const IntegrationSerializationCapture* capture) {
    if (!integration_cps_flow_enabled() || !fix || !capture || capture->count == 0u) {
        return;
    }
    char temp_root[PATH_MAX];
    munit_assert_true(integration_make_temp_root(temp_root, sizeof temp_root));
    const char* branch_name = "integration_poc_branch";
    cps_engine* engine = NULL;
    cps_flatfile_opts opts = {
        .root_dir = temp_root,
        .branch_name = branch_name,
        .checkpoint_interval = 8u,
        .mini_toc_hint = 32u,
        .create_branch = true,
    };
    bool success = (cps_flatfile_engine_open(&opts, &engine) == CPS_OK && engine);
    if (success) {
        cepFlatReader* reader = cep_flat_reader_create();
        success = reader &&
                  integration_capture_feed_flat_reader(capture, reader) &&
                  cep_flat_reader_commit(reader) &&
                  cep_flat_reader_ready(reader) &&
                  integration_cps_apply_reader(engine, reader);
        if (reader) {
            cep_flat_reader_destroy(reader);
        }
    }
    if (success) {
        integration_assert_persist_metrics(branch_name, 1u);
    }
    if (engine && engine->ops && engine->ops->close) {
        engine->ops->close(engine);
    }
    integration_remove_tree(temp_root);
    munit_assert_true(success);
}

static const char* integration_cell_type_string(const cepCell* cell) {
    if (!cell) {
        return "<null>";
    }
    switch (cell->metacell.type) {
      case CEP_TYPE_VOID:
        return "void";
      case CEP_TYPE_NORMAL:
        return "normal";
      case CEP_TYPE_PROXY:
        return "proxy";
      case CEP_TYPE_LINK:
        return "link";
      default:
        return "unknown";
    }
}

static const char* integration_data_type_string(unsigned type) {
    switch (type) {
      case CEP_DATATYPE_VALUE:
        return "value";
      case CEP_DATATYPE_DATA:
        return "data";
      case CEP_DATATYPE_HANDLE:
        return "handle";
      case CEP_DATATYPE_STREAM:
        return "stream";
      default:
        return "unknown";
    }
}

static const char* integration_store_storage_name(unsigned storage) {
    switch (storage) {
      case CEP_STORAGE_LINKED_LIST:
        return "linked-list";
      case CEP_STORAGE_ARRAY:
        return "array";
      case CEP_STORAGE_PACKED_QUEUE:
        return "packed-queue";
      case CEP_STORAGE_RED_BLACK_T:
        return "red-black";
      case CEP_STORAGE_HASH_TABLE:
        return "hash-table";
      case CEP_STORAGE_OCTREE:
        return "octree";
      default:
        return "storage?";
    }
}

static const char* integration_store_index_name(unsigned indexing) {
    switch (indexing) {
      case CEP_INDEX_BY_INSERTION:
        return "insertion";
      case CEP_INDEX_BY_NAME:
        return "name";
      case CEP_INDEX_BY_FUNCTION:
        return "function";
      case CEP_INDEX_BY_HASH:
        return "hash";
      default:
        return "index?";
    }
}

static const char* integration_id_text(cepID id, char* buffer, size_t buffer_len) {
    if (!buffer || buffer_len == 0u) {
        return "<buffer>";
    }

    if (!id) {
        snprintf(buffer, buffer_len, "-");
        return buffer;
    }

    if (cep_id_is_word(id)) {
        char word[CEP_WORD_MAX_CHARS + 1u];
        size_t len = cep_word_to_text(id, word);
        (void)len;
        snprintf(buffer, buffer_len, "%s", word);
        return buffer;
    }

    if (cep_id_is_acronym(id)) {
        char acro[CEP_ACRON_MAX_CHARS + 1u];
        size_t len = cep_acronym_to_text(id, acro);
        (void)len;
        snprintf(buffer, buffer_len, "%s", acro);
        return buffer;
    }

    if (cep_id_is_reference(id)) {
        size_t length = 0u;
        const char* text = cep_namepool_lookup(id, &length);
        if (text && length) {
            if (length >= buffer_len) {
                length = buffer_len - 1u;
            }
            memcpy(buffer, text, length);
            buffer[length] = '\0';
            return buffer;
        }
        snprintf(buffer, buffer_len, "ref:%016llx", (unsigned long long)cep_id(id));
        return buffer;
    }

    snprintf(buffer, buffer_len, "0x%016llx", (unsigned long long)cep_id(id));
    return buffer;
}

static void integration_cell_flags(const cepCell* cell, char* buffer, size_t buffer_len) {
    if (!buffer || buffer_len == 0u) {
        return;
    }
    size_t pos = 0u;
    if (cell) {
        if (cep_cell_is_veiled(cell) && pos + 1u < buffer_len) {
            buffer[pos++] = 'V';
        }
        if (cep_cell_is_deleted(cell) && pos + 1u < buffer_len) {
            buffer[pos++] = 'D';
        }
        if (cep_cell_is_immutable(cell) && pos + 1u < buffer_len) {
            buffer[pos++] = 'I';
        }
        if (cep_cell_is_link(cell) && pos + 1u < buffer_len) {
            buffer[pos++] = 'L';
        }
        if (cell->metacell.shadowing && pos + 1u < buffer_len) {
            buffer[pos++] = 'S';
        }
    }
    if (pos == 0u && buffer_len > 1u) {
        buffer[pos++] = '.';
    }
    if (pos < buffer_len) {
        buffer[pos] = '\0';
    } else {
        buffer[buffer_len - 1u] = '\0';
    }
}

static const char* integration_describe_data(const cepData* data, char* buffer, size_t buffer_len) {
    if (!buffer || buffer_len == 0u) {
        return "<buffer>";
    }
    if (!data) {
        snprintf(buffer, buffer_len, "-");
        return buffer;
    }

    char domain_text[48];
    char tag_text[48];
    integration_id_text(data->dt.domain, domain_text, sizeof domain_text);
    integration_id_text(data->dt.tag, tag_text, sizeof tag_text);

    snprintf(buffer,
             buffer_len,
             "%s dt=%s/%s size=%zu hash=0x%016llx writable=%u",
             integration_data_type_string((unsigned)data->datatype),
             domain_text,
             tag_text,
             (size_t)data->size,
             (unsigned long long)data->hash,
             data->writable ? 1u : 0u);
    return buffer;
}

static void integration_dump_cell_tree(FILE* file,
                                       cepCell* cell,
                                       unsigned depth,
                                       unsigned max_depth,
                                       size_t index) {
    if (!file || !cell || depth > max_depth) {
        return;
    }

    cepCell* resolved = cep_cell_resolve(cell);
    if (!resolved) {
        fprintf(file, "%*s[%02zu] <unresolved>\n", depth * 2u, "", index);
        return;
    }

    const cepDT* stored_name = cep_cell_get_name(cell);
    const cepDT* resolved_name = cep_cell_get_name(resolved);

    char stored_domain[48];
    char stored_tag[48];
    char resolved_domain[48];
    char resolved_tag[48];

    integration_id_text(stored_name ? stored_name->domain : 0u, stored_domain, sizeof stored_domain);
    integration_id_text(stored_name ? stored_name->tag : 0u, stored_tag, sizeof stored_tag);
    integration_id_text(resolved_name ? resolved_name->domain : 0u, resolved_domain, sizeof resolved_domain);
    integration_id_text(resolved_name ? resolved_name->tag : 0u, resolved_tag, sizeof resolved_tag);

    char flags[8];
    integration_cell_flags(resolved, flags, sizeof flags);

    const cepStore* store = resolved->store;
    const cepData* data = cep_cell_has_data(resolved) ? resolved->data : NULL;

    char store_desc[128];
    if (store) {
        char store_domain[48];
        char store_tag[48];
        integration_id_text(store->dt.domain, store_domain, sizeof store_domain);
        integration_id_text(store->dt.tag, store_tag, sizeof store_tag);
        snprintf(store_desc,
                 sizeof store_desc,
                 "%s/%s (%s, %s, autoid=%llu)",
                 store_domain,
                 store_tag,
                 integration_store_storage_name(store->storage),
                 integration_store_index_name(store->indexing),
                 (unsigned long long)cep_id(store->autoid));
    }

    char data_desc[160];
    const char* data_text = integration_describe_data(data, data_desc, sizeof data_desc);

    fprintf(file,
            "%*s[%02zu] name=%s/%s (dom=0x%016llx tag=0x%016llx) type=%s flags=%s created=%llu deleted=%llu ptr=%p store=%s children=%zu data=%s\n",
            depth * 2u,
            "",
            index,
            resolved_domain,
            resolved_tag,
            (unsigned long long)(resolved_name ? cep_id(resolved_name->domain) : 0ull),
            (unsigned long long)(resolved_name ? cep_id(resolved_name->tag) : 0ull),
            integration_cell_type_string(resolved),
            flags,
            (unsigned long long)resolved->created,
            (unsigned long long)resolved->deleted,
            (void*)resolved,
            store ? store_desc : "-",
            (size_t)(store ? cep_cell_children(resolved) : 0u),
            data_text);

    if (resolved != cell) {
        fprintf(file,
                "%*s    stored-as=%s/%s (dom=0x%016llx tag=0x%016llx) ptr=%p\n",
                depth * 2u,
                "",
                stored_domain,
                stored_tag,
                (unsigned long long)(stored_name ? cep_id(stored_name->domain) : 0ull),
                (unsigned long long)(stored_name ? cep_id(stored_name->tag) : 0ull),
                (void*)cell);
    }

    if (!store || depth >= max_depth) {
        return;
    }

    size_t child_index = 0u;
    for (cepCell* child = cep_cell_first_all(resolved);
         child;
         child = cep_cell_next_all(resolved, child), ++child_index) {
        integration_dump_cell_tree(file, child, depth + 1u, max_depth, child_index);
    }
}

static void integration_dump_branch(FILE* file, const char* label, cepCell* branch, unsigned max_depth) {
    if (!file || !branch) {
        return;
    }
    fprintf(file, "%s\n", label ? label : "<branch>");
    integration_dump_cell_tree(file, branch, 0u, max_depth, 0u);
    fprintf(file, "\n");
}

static void integration_snapshot_journal_branch(const char* heading, cepCell* root, bool reset_file) {
    const char* path = "meson-logs/journal_list_snapshot.txt";
    FILE* file = fopen(path, reset_file ? "w" : "a");
    if (!file) {
        INTEGRATION_DEBUG_PRINTF("[integration_poc] snapshot open failed heading=%s errno=%d",
                                heading ? heading : "<nil>",
                                errno);
        return;
    }

    fprintf(file, "=== %s ===\n", heading ? heading : "<snapshot>");

    if (!root) {
        fprintf(file, "(root missing)\n\n");
        fclose(file);
        return;
    }

    cepCell* resolved_root = cep_cell_resolve(root);
    if (!resolved_root) {
        fprintf(file, "(root unresolved)\n\n");
        fclose(file);
        return;
    }

    cepCell* stream_branch = cep_cell_find_by_name_all(resolved_root, CEP_DTAW("CEP", "stream"));
    if (!stream_branch) {
        fprintf(file, "(stream branch missing)\n\n");
        fclose(file);
        return;
    }
    stream_branch = cep_cell_resolve(stream_branch);

    integration_dump_branch(file, "/stream", stream_branch, 1u);

    cepCell* io_res = cep_cell_find_by_name_all(stream_branch, CEP_DTAW("CEP", "io_res"));
    if (io_res) {
        io_res = cep_cell_resolve(io_res);
        integration_dump_branch(file, "/stream/io_res", io_res, 3u);
    } else {
        fprintf(file, "/stream/io_res missing\n\n");
    }

    cepCell* io_stream = cep_cell_find_by_name_all(stream_branch, CEP_DTAW("CEP", "io_stream"));
    if (io_stream) {
        io_stream = cep_cell_resolve(io_stream);
        integration_dump_branch(file, "/stream/io_stream", io_stream, 3u);
    } else {
        fprintf(file, "/stream/io_stream missing\n\n");
    }

    fclose(file);
}

static void integration_snapshot_space_branch(const char* heading, cepCell* root, bool reset_file) {
    const char* path = "meson-logs/space_snapshot.txt";
    FILE* file = fopen(path, reset_file ? "w" : "a");
    if (!file) {
        INTEGRATION_DEBUG_PRINTF("[integration_poc] space snapshot open failed heading=%s errno=%d",
                                heading ? heading : "<nil>",
                                errno);
        return;
    }

    fprintf(file, "=== %s ===\n", heading ? heading : "<snapshot>");
    if (!root) {
        fprintf(file, "(root missing)\n\n");
        fclose(file);
        return;
    }

    cepCell* resolved_root = cep_cell_resolve(root);
    if (!resolved_root) {
        fprintf(file, "(root unresolved)\n\n");
        fclose(file);
        return;
    }

    cepCell* space = cep_cell_find_by_name_all(resolved_root, CEP_DTAW("CEP", "space"));
    if (!space) {
        fprintf(file, "/space missing\n\n");
        fclose(file);
        return;
    }
    space = cep_cell_resolve(space);
    if (!space) {
        fprintf(file, "/space unresolved\n\n");
        fclose(file);
        return;
    }

    integration_dump_branch(file, "/space", space, 2u);
    cepCell* entry = cep_cell_find_by_name_all(space, CEP_DTAW("CEP", "space_entry"));
    if (entry) {
        entry = cep_cell_resolve(entry);
        if (entry)
            integration_dump_branch(file, "/space/space_entry", entry, 1u);
    }

    fclose(file);
}

static void integration_snapshot_prr_branch(const char* heading, cepCell* root, bool reset_file) {
    const char* path = "meson-logs/prr_snapshot.txt";
    FILE* file = fopen(path, reset_file ? "w" : "a");
    if (!file) {
        INTEGRATION_DEBUG_PRINTF("[integration_poc] prr snapshot open failed heading=%s errno=%d",
                                heading ? heading : "<nil>",
                                errno);
        return;
    }

    fprintf(file, "=== %s ===\n", heading ? heading : "<snapshot>");

    if (!root) {
        fprintf(file, "(root missing)\n\n");
        fclose(file);
        return;
    }

    cepCell* resolved_root = cep_cell_resolve(root);
    if (!resolved_root) {
        fprintf(file, "(root unresolved)\n\n");
        fclose(file);
        return;
    }

    cepCell* prr = cep_cell_find_by_name_all(resolved_root, CEP_DTAW("CEP", "prr_pause"));
    if (!prr) {
        fprintf(file, "/prr_pause missing\n\n");
        fclose(file);
        return;
    }
    prr = cep_cell_resolve(prr);
    if (!prr) {
        fprintf(file, "/prr_pause unresolved\n\n");
        fclose(file);
        return;
    }

    integration_dump_branch(file, "/prr_pause", prr, 2u);
    fclose(file);
}

static cepCell* integration_resolve_replay_root(cepCell* root, const cepPath* reference_path) {
    if (!root)
        return NULL;
    cepCell* current = root;
    cepCell* clone_root = cep_cell_find_by_name_all(current, CEP_DTAW("CEP", "/"));
    if (clone_root) {
        current = cep_cell_resolve(clone_root);
        if (!current)
            return NULL;
    }
    if (!reference_path || !reference_path->length)
        return current;
    for (unsigned idx = 0u; idx < reference_path->length; ++idx) {
        const cepPast* segment = &reference_path->past[idx];
        cepDT name = segment->dt;
        cepCell* next = cep_cell_find_by_name_all(current, &name);
        if (!next)
            return NULL;
        current = cep_cell_resolve(next);
        if (!current)
            return NULL;
    }
    return current;
}

static cepCell* integration_journal_list_for_root(cepCell* root) {
    if (!root) {
        INTEGRATION_DEBUG_PRINTF("[integration][journal] root missing");
        return NULL;
    }

    cepCell* resolved_root = cep_cell_resolve(root);
    if (!resolved_root) {
        INTEGRATION_DEBUG_PRINTF("[integration][journal] root unresolved");
        return NULL;
    }

    cepCell* stream_branch = cep_cell_find_by_name_all(resolved_root, CEP_DTAW("CEP", "stream"));
    if (!stream_branch) {
        INTEGRATION_DEBUG_PRINTF("[integration][journal] stream branch missing");
        integration_debug_print_path(resolved_root);
        return NULL;
    }
    stream_branch = cep_cell_resolve(stream_branch);

    cepCell* io_res = cep_cell_find_by_name_all(stream_branch, CEP_DTAW("CEP", "io_res"));
    if (!io_res) {
        INTEGRATION_DEBUG_PRINTF("[integration][journal] io_res missing");
        integration_debug_print_path(stream_branch);
        return NULL;
    }
    io_res = cep_cell_resolve(io_res);

    cepCell* journal = cep_cell_find_by_name_all(io_res, CEP_DTAW("CEP", "journal"));
    if (!journal) {
        INTEGRATION_DEBUG_PRINTF("[integration][journal] journal missing");
        integration_debug_print_path(io_res);
        return NULL;
    }
    journal = cep_cell_resolve(journal);

    cepCell* list = cep_cell_find_by_name_all(journal, CEP_DTAW("CEP", "list"));
    if (list) {
        list = cep_cell_resolve(list);
        if (list)
            return list;
        INTEGRATION_DEBUG_PRINTF("[integration][journal] list unresolved; falling back to journal node");
    }

    /* Newer serializers emit the journal node itself as a list (`/stream/io_res/journal`)
       while older fixtures used `/stream/io_res/journal/list`. Accept both layouts so the
       parity check no longer fails just because the nested list is absent. */
    if (cep_cell_has_store(journal) && cep_cell_children(journal) >= 0u) {
        return journal;
    }

    INTEGRATION_DEBUG_PRINTF("[integration][journal] list missing and journal unusable");
    integration_debug_print_path(journal);
    return NULL;
}

static void integration_assert_journal_positions(cepCell* baseline_root, cepCell* candidate_root) {
    cepCell* baseline_list = integration_journal_list_for_root(baseline_root);
    cepCell* candidate_list = integration_journal_list_for_root(candidate_root);
    munit_assert_not_null(baseline_list);
    munit_assert_not_null(candidate_list);

    size_t baseline_children = cep_cell_children(baseline_list);
    munit_assert_size(cep_cell_children(candidate_list), ==, baseline_children);

    for (size_t idx = 0; idx < baseline_children; ++idx) {
        cepCell* baseline_child = cep_cell_find_by_position(baseline_list, idx);
        cepCell* candidate_child = cep_cell_find_by_position(candidate_list, idx);
        munit_assert_not_null(baseline_child);
        munit_assert_not_null(candidate_child);
        baseline_child = cep_link_pull(baseline_child);
        candidate_child = cep_link_pull(candidate_child);
        munit_assert_not_null(baseline_child);
        munit_assert_not_null(candidate_child);
        const cepDT* baseline_name = cep_cell_get_name(baseline_child);
        const cepDT* candidate_name = cep_cell_get_name(candidate_child);
        munit_assert_not_null(baseline_name);
        munit_assert_not_null(candidate_name);
        munit_assert_uint64(candidate_name->domain, ==, baseline_name->domain);
        munit_assert_uint64(candidate_name->tag, ==, baseline_name->tag);
        munit_assert_uint8(candidate_name->glob, ==, baseline_name->glob);
    }
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

    INTEGRATION_DEBUG_PRINTF("[integration_poc] rand_seed=0x%08x planned=%u",
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

static void integration_ops_ctx_verify(const IntegrationOpsContext* ctx, bool require_timeout) {
    munit_assert_not_null(ctx);
    if (require_timeout) {
        munit_assert_int(integration_timeout_calls, ==, 1);
    } else if (integration_timeout_calls < 1) {
        munit_logf(MUNIT_LOG_INFO,
                   "%s",
                   "[integration][ops_ctx] timeout watcher did not fire during focus harness");
    }

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

static void integration_ops_ctx_drive_once(void) {
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_true(cep_heartbeat_stage_commit());
}

static void integration_ops_ctx_wait_for_timeout(unsigned max_attempts) {
    for (unsigned attempt = 0u; attempt < max_attempts; ++attempt) {
        integration_ops_ctx_drive_once();
        if (integration_timeout_calls >= 1) {
            return;
        }
    }
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

static void integration_stream_ctx_dump(const IntegrationStreamContext* ctx,
                                        const char* label) {
    if (!ctx || !ctx->stream_node) {
        return;
    }
    cepCell* stream = cep_cell_resolve(ctx->stream_node);
    if (!stream) {
        return;
    }
    cepCell* outcome = cep_cell_find_by_name(stream, CEP_DTAW("CEP", "outcome"));
    if (!outcome) {
        INTEGRATION_DEBUG_PRINTF("[integration_poc][dump:%s] no outcome list", label ? label : "null");
        return;
    }
    outcome = cep_cell_resolve(outcome);
    munit_assert_not_null(outcome);
    size_t count = 0u;
    for (cepCell* node = cep_cell_first_all(outcome); node; node = cep_cell_next_all(outcome, node)) {
        cepCell* resolved = cep_cell_resolve(node);
        if (!resolved || !cep_cell_has_data(resolved)) {
            continue;
        }
        const cepStreamOutcomeEntry* entry = (const cepStreamOutcomeEntry*)cep_cell_data(resolved);
        if (!entry) {
            continue;
        }
        INTEGRATION_DEBUG_PRINTF(
            "[integration_poc][dump:%s] cell=%p data=%p len=%llu payload=%016llx result=%016llx flags=%u",
            label ? label : "null",
            (void*)resolved,
            (void*)resolved->data,
            (unsigned long long)entry->length,
            (unsigned long long)entry->payload_hash,
            (unsigned long long)entry->resulting_hash,
            (unsigned)entry->flags);
        count += 1u;
    }
    INTEGRATION_DEBUG_PRINTF("[integration_poc][dump:%s] entries=%zu", label ? label : "null", count);
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
        if (!cep_heartbeat_stage_commit()) {
            munit_logf(MUNIT_LOG_ERROR,
                       "[integration][hybrid_flow] stage_commit failed spins=%u err=%d stage=%u",
                       spins,
                       cep_ops_debug_last_error(),
                       atomic_load_explicit(&probe.stage, memory_order_relaxed));
            munit_assert_true(false);
        }
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
        if (candidate->payload_hash && candidate->resulting_hash == 0u) {
            const uint64_t* words = (const uint64_t*)candidate;
            INTEGRATION_DEBUG_PRINTF(
                "[integration_poc][warn] raw outcome words: "
                "w0=%016" PRIx64 " w1=%016" PRIx64 " w2=%016" PRIx64
                " w3=%016" PRIx64 " w4=%016" PRIx64 " w5=%016" PRIx64
                " w6=%016" PRIx64 " w7=%016" PRIx64 " w8=%016" PRIx64 " w9=%016" PRIx64,
                words[0], words[1], words[2], words[3], words[4],
                words[5], words[6], words[7], words[8], words[9]);
        }
        INTEGRATION_DEBUG_PRINTF(
            "[integration_poc] stream_outcome cell=%p data=%p len=%llu payload=%016llx expected=%016llx result=%016llx flags=%u",
            (void*)resolved,
            resolved ? (void*)resolved->data : NULL,
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
    if (integration_prr_is_disabled()) {
        memset(ctx, 0, sizeof *ctx);
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
    if (integration_prr_is_disabled()) {
        return;
    }
    bool skip_rollback = integration_prr_skip_rollback();

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

    if (!skip_rollback) {
        cepBeatNumber current = cep_heartbeat_current();
        cepBeatNumber rollback_target = current ? (current - 1u) : current;
        munit_assert_true(cep_runtime_rollback(rollback_target));
        munit_assert_true(cep_runtime_is_paused());
    }

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
    if (!skip_rollback)
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

static void integration_secdata_assert_plain(cepCell* cell,
                                             const void* expected,
                                             size_t expected_size) {
    munit_assert_not_null(cell);
    const void* plaintext = NULL;
    size_t plain_size = 0u;
    munit_assert_true(cep_data_unveil_ro(cell, &plaintext, &plain_size));
    munit_assert_size(plain_size, ==, expected_size);
    munit_assert_memory_equal(expected_size, plaintext, expected);
    cep_data_unveil_done(cell, plaintext);
}

static void integration_secdata_flow(IntegrationFixture* fix) {
    if (!fix || !fix->secdata_cell) {
        return;
    }
    cepCell* cell = cep_cell_resolve(fix->secdata_cell);
    munit_assert_not_null(cell);
    munit_assert_true(cep_cell_is_normal(cell));
    munit_assert_false(cep_cell_is_immutable(cell));
    munit_assert_true(cep_cell_has_data(cell));
    munit_assert_not_null(cell->data);
    munit_assert_true(cell->data->writable);

    cepEpExecutionContext* saved_ctx = cep_executor_context_get();
    bool restore_ctx = saved_ctx != NULL;
    if (restore_ctx) {
        cep_executor_context_clear();
    }

    cepEpExecutionContext shim_ctx = {
        .profile = CEP_EP_PROFILE_RW,
        .cpu_budget_ns = CEP_EXECUTOR_DEFAULT_CPU_BUDGET_NS,
        .io_budget_bytes = CEP_EXECUTOR_DEFAULT_IO_BUDGET_BYTES,
        .user_data = NULL,
        .cpu_consumed_ns = 0u,
        .io_consumed_bytes = 0u,
        .allow_without_lease = true,
        .runtime = cep_runtime_active(),
        .ticket = 0u,
    };
    atomic_init(&shim_ctx.cancel_requested, false);
    cep_executor_context_set(&shim_ctx);

    static const char plain_payload[] = "poc-secdata::plain";
    munit_assert_true(cep_ep_require_rw());
    munit_assert_true(cep_data_set_plain(cell, plain_payload, sizeof plain_payload));
    munit_assert_int(cep_data_mode(cell), ==, CEP_SECDATA_MODE_PLAIN);
    integration_secdata_assert_plain(cell, plain_payload, sizeof plain_payload);

    static const char cdef_payload[] = "poc-secdata::compressed payload for CDEF mode";
    munit_assert_true(cep_data_set_cdef(cell,
                                        cdef_payload,
                                        sizeof cdef_payload,
                                        CEP_SECDATA_CODEC_DEFLATE));
    munit_assert_int(cep_data_mode(cell), ==, CEP_SECDATA_MODE_CDEF);
    integration_secdata_assert_plain(cell, cdef_payload, sizeof cdef_payload);

    cepKeyId key_primary = cep_text_to_word("sec:keypri");
    cepKeyId key_secondary = cep_text_to_word("sec:keysec");
    munit_assert_uint64(key_primary, !=, 0u);
    munit_assert_uint64(key_secondary, !=, 0u);
    static const char enc_payload[] = "poc-secdata::encrypted only payload";
    munit_assert_true(cep_data_set_enc(cell,
                                       enc_payload,
                                       sizeof enc_payload,
                                       key_primary,
                                       CEP_SECDATA_AEAD_XCHACHA20));
    munit_assert_int(cep_data_mode(cell), ==, CEP_SECDATA_MODE_ENC);
    integration_secdata_assert_plain(cell, enc_payload, sizeof enc_payload);

    munit_assert_true(cep_data_rekey(cell, key_secondary));
    integration_secdata_assert_plain(cell, enc_payload, sizeof enc_payload);

    static const char cenc_payload[] = "poc-secdata::compress+encrypt payload under test";
    munit_assert_true(cep_data_set_cenc(cell,
                                        cenc_payload,
                                        sizeof cenc_payload,
                                        key_primary,
                                        CEP_SECDATA_AEAD_XCHACHA20,
                                        CEP_SECDATA_CODEC_DEFLATE));
    munit_assert_int(cep_data_mode(cell), ==, CEP_SECDATA_MODE_CENC);
    integration_secdata_assert_plain(cell, cenc_payload, sizeof cenc_payload);

    munit_assert_true(cep_data_recompress(cell, CEP_SECDATA_CODEC_NONE));
    munit_assert_int(cep_data_mode(cell), ==, CEP_SECDATA_MODE_ENC);
    integration_secdata_assert_plain(cell, cenc_payload, sizeof cenc_payload);

    const cepData* data = cell->data;
    munit_assert_not_null(data);
    munit_assert_true(data->mode_flags & CEP_SECDATA_FLAG_SECURED);
    munit_assert_uint64(data->secmeta.raw_len, ==, sizeof cenc_payload);
    munit_assert_uint64(data->secmeta.payload_fp, !=, 0u);

    if (restore_ctx) {
        cep_executor_context_set(saved_ctx);
    } else {
        cep_executor_context_clear();
    }
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
    integration_stream_ctx_dump(&stream_ctx, "after-prepare");
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

    integration_ops_ctx_drive_once();
    integration_debug_mark("timeline:beat3", cep_heartbeat_current());

    integration_ops_ctx_verify(&ops_ctx, true);
    integration_episode_executor_checks(&stream_ctx);
    integration_stream_ctx_dump(&stream_ctx, "post-executor");
    integration_episode_lease_flow(fix);
    integration_stream_ctx_dump(&stream_ctx, "post-lease");
    integration_episode_hybrid_flow(fix);
    integration_stream_ctx_dump(&stream_ctx, "post-hybrid");
    integration_stream_ctx_dump(&stream_ctx, "pre-verify");
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
                                       void* user_data,
                                       cepCompareInfo* info) {
    (void)user_data;
    if (CEP_RARELY_PTR(info)) {
        cep_compare_info_set(info, CEP_DTAW("CEP", "cmp:i_cat"), 1u, 0u);
        return 0;
    }
    cepCell* left = lhs ? cep_cell_resolve((cepCell*)lhs) : NULL;
    cepCell* right = rhs ? cep_cell_resolve((cepCell*)rhs) : NULL;
    if (!left || !right || !cep_cell_is_normal(left) || !cep_cell_is_normal(right)) {
        return 0;
    }
    bool left_has_data = cep_cell_has_data(left);
    bool right_has_data = cep_cell_has_data(right);
    if (!left_has_data || !right_has_data) {
        const cepDT* left_name = cep_cell_get_name(left);
        const cepDT* right_name = cep_cell_get_name(right);
        if (!left_name || !right_name)
            return 0;
        return cep_dt_compare(left_name, right_name);
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
                                      void* user_data,
                                      cepCompareInfo* info) {
    (void)user_data;
    if (CEP_RARELY_PTR(info)) {
        cep_compare_info_set(info, CEP_DTAW("CEP", "cmp:i_oct"), 1u, 0u);
        return 0;
    }
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

static void integration_register_comparators(void) {
    (void)cep_comparator_registry_record(integration_octree_compare);
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
    integration_register_comparators();

    fix->boot_oid = integration_read_oid("boot_oid");
    munit_assert_true(cep_oid_is_valid(fix->boot_oid));

    for (unsigned step = 0; step < 6; ++step) {
        if (!cep_heartbeat_step()) {
            munit_logf(MUNIT_LOG_ERROR,
                       "[integration][runtime_boot] heartbeat_step failed step=%u err=%d",
                       step,
                       cep_ops_debug_last_error());
            munit_assert_true(false);
        }
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
    cep_comparator_registry_reset_active();
    /* Drain any pending async work so subsequent selectors start clean. */
    bool quiesced = cep_io_reactor_quiesce(CEP_IO_REACTOR_PAUSE_DEADLINE_BEATS);
    if (!quiesced) {
        munit_logf(MUNIT_LOG_ERROR,
                   "[integration][async_guard] reactor failed to quiesce err=%d",
                   cep_ops_debug_last_error());
    }
    munit_assert_true(quiesced);
    integration_assert_async_runtime_idle("cleanup");
    cep_io_reactor_shutdown();
    cep_runtime_shutdown(fix->runtime);
    cep_runtime_restore_active(fix->previous_runtime);
    cep_runtime_destroy(fix->runtime);
    fix->runtime = NULL;
    fix->previous_runtime = NULL;
    if (fix->poc_path) {
        cep_free(fix->poc_path);
        fix->poc_path = NULL;
    }
}

/* Ensure `/data/poc/catalog` contains predictable entries before other phases run. */
static cepCell* integration_seed_catalog(cepCell* poc_root,
                                         cepCell** out_item_a,
                                         cepCell** out_secdata) {
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

    static const char sec_seed[] = "poc-secdata::seed";
    cepCell* secdata_item = cep_cell_add_data(catalog,
                                              CEP_DTAW("CEP", "sec_item"),
                                              0,
                                              &item_type,
                                              sec_seed,
                                              sizeof sec_seed,
                                              128u,
                                              NULL);
    munit_assert_not_null(secdata_item);
    secdata_item = cep_cell_resolve(secdata_item);
    munit_assert_not_null(secdata_item);

    if (out_item_a) {
        *out_item_a = item_a;
    }
    if (out_secdata) {
        *out_secdata = secdata_item;
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
    if (fix->poc_path) {
        cep_free(fix->poc_path);
        fix->poc_path = NULL;
    }
    munit_assert_true(cep_cell_path(fix->poc_root, &fix->poc_path));

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
    cepCell* secdata_cell = NULL;
    cepCell* catalog = integration_seed_catalog(poc_root, &item_a, &secdata_cell);
    munit_assert_not_null(item_a);
    item_a = cep_cell_resolve(item_a);
    munit_assert_not_null(item_a);
    fix->catalog = catalog;
    fix->secdata_cell = secdata_cell;
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
    cep_cell_remove_hard(link_target, NULL);

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



static void integration_assert_payload_equal(const cepCell* baseline, const cepCell* candidate) {
    bool baseline_has_data = baseline && baseline->data;
    bool candidate_has_data = candidate && candidate->data;
    munit_assert_int(baseline_has_data, ==, candidate_has_data);
    if (!baseline_has_data)
        return;

    munit_assert_uint64(baseline->data->dt.domain, ==, candidate->data->dt.domain);
    munit_assert_uint64(baseline->data->dt.tag, ==, candidate->data->dt.tag);
    munit_assert_uint8(baseline->data->dt.glob, ==, candidate->data->dt.glob);
    munit_assert_uint(baseline->data->datatype, ==, candidate->data->datatype);
    munit_assert_size(baseline->data->size, ==, candidate->data->size);

    if (baseline->data->size) {
        const void* baseline_payload = cep_data_payload(baseline->data);
        const void* candidate_payload = cep_data_payload(candidate->data);
        munit_assert_not_null(baseline_payload);
        munit_assert_not_null(candidate_payload);
        bool skip_binary_compare = integration_payload_should_skip_binary_compare(&baseline->data->dt,
                                                                                  baseline->data->datatype);
        if (!skip_binary_compare &&
            memcmp(baseline_payload, candidate_payload, baseline->data->size) != 0) {
            const uint8_t* base_bytes = (const uint8_t*)baseline_payload;
            const uint8_t* cand_bytes = (const uint8_t*)candidate_payload;
            size_t diff = integration_payload_first_diff(base_bytes, cand_bytes, baseline->data->size);
            uint8_t base_byte = (diff < baseline->data->size) ? base_bytes[diff] : 0u;
            uint8_t cand_byte = (diff < baseline->data->size) ? cand_bytes[diff] : 0u;
            integration_log_payload_diff(baseline,
                                         candidate,
                                         baseline->data->size,
                                         diff,
                                         base_byte,
                                         cand_byte);
        }
        if (!skip_binary_compare) {
            munit_assert_memory_equal(baseline->data->size, baseline_payload, candidate_payload);
        }
    }
}

static void integration_assert_manifest_parity_node(cepCell* baseline, cepCell* candidate) {
    munit_assert_not_null(baseline);
    munit_assert_not_null(candidate);

    munit_assert_uint((unsigned)baseline->metacell.type, ==, (unsigned)candidate->metacell.type);
    munit_assert_int((int)baseline->metacell.veiled, ==, (int)candidate->metacell.veiled);

    if (!cep_cell_is_normal(baseline))
        return;

    integration_assert_payload_equal(baseline, candidate);

    bool baseline_has_store = baseline->store != NULL;
    bool candidate_has_store = candidate->store != NULL;
    if (baseline_has_store != candidate_has_store) {
        INTEGRATION_DEBUG_PRINTF("[integration][parity] store presence mismatch baseline=%d candidate=%d",
                                baseline_has_store ? 1 : 0,
                                candidate_has_store ? 1 : 0);
        integration_debug_print_path(baseline);
        integration_debug_print_path(candidate);
    }
    munit_assert_int(baseline_has_store, ==, candidate_has_store);
    if (baseline_has_store) {
        munit_assert_uint64(baseline->store->dt.domain, ==, candidate->store->dt.domain);
        if (baseline->store->dt.tag != candidate->store->dt.tag) {
            char base_dt_dom[64];
            char base_dt_tag[64];
            char cand_dt_dom[64];
            char cand_dt_tag[64];
            INTEGRATION_DEBUG_PRINTF("[integration][parity] store dt mismatch base=%s/%s cand=%s/%s",
                                    integration_debug_id_desc(baseline->store->dt.domain, base_dt_dom, sizeof base_dt_dom),
                                    integration_debug_id_desc(baseline->store->dt.tag, base_dt_tag, sizeof base_dt_tag),
                                    integration_debug_id_desc(candidate->store->dt.domain, cand_dt_dom, sizeof cand_dt_dom),
                                    integration_debug_id_desc(candidate->store->dt.tag, cand_dt_tag, sizeof cand_dt_tag));
            const cepDT* baseline_name = cep_cell_get_name(baseline);
            const cepDT* candidate_name = cep_cell_get_name(candidate);
            char base_name_dom[64];
            char base_name_tag[64];
            char cand_name_dom[64];
            char cand_name_tag[64];
            INTEGRATION_DEBUG_PRINTF("[integration][parity] baseline_name=%s/%s candidate_name=%s/%s",
                                    integration_debug_id_desc(baseline_name ? baseline_name->domain : 0u, base_name_dom, sizeof base_name_dom),
                                    integration_debug_id_desc(baseline_name ? baseline_name->tag : 0u, base_name_tag, sizeof base_name_tag),
                                    integration_debug_id_desc(candidate_name ? candidate_name->domain : 0u, cand_name_dom, sizeof cand_name_dom),
                                    integration_debug_id_desc(candidate_name ? candidate_name->tag : 0u, cand_name_tag, sizeof cand_name_tag));
            integration_debug_print_path(baseline);
            integration_debug_print_path(candidate);
        }
        munit_assert_uint64(baseline->store->dt.tag, ==, candidate->store->dt.tag);
        munit_assert_uint8(baseline->store->dt.glob, ==, candidate->store->dt.glob);
        if ((unsigned)baseline->store->indexing != (unsigned)candidate->store->indexing) {
            INTEGRATION_DEBUG_PRINTF("[integration][parity] store indexing mismatch baseline=%u candidate=%u",
                                    (unsigned)baseline->store->indexing,
                                    (unsigned)candidate->store->indexing);
            integration_debug_print_path(baseline);
            integration_debug_print_path(candidate);
        }
        munit_assert_uint((unsigned)baseline->store->indexing, ==, (unsigned)candidate->store->indexing);
        if ((unsigned)baseline->store->storage != (unsigned)candidate->store->storage) {
            const cepDT* base_name = cep_cell_get_name(baseline);
            const cepDT* cand_name = cep_cell_get_name(candidate);
            char base_name_dom[64];
            char base_name_tag[64];
            char cand_name_dom[64];
            char cand_name_tag[64];
            INTEGRATION_DEBUG_PRINTF("[integration][parity] store storage mismatch base=%s/%s storage=%u cand=%s/%s storage=%u",
                                    integration_debug_id_desc(base_name ? base_name->domain : 0u, base_name_dom, sizeof base_name_dom),
                                    integration_debug_id_desc(base_name ? base_name->tag : 0u, base_name_tag, sizeof base_name_tag),
                                    (unsigned)baseline->store->storage,
                                    integration_debug_id_desc(cand_name ? cand_name->domain : 0u, cand_name_dom, sizeof cand_name_dom),
                                    integration_debug_id_desc(cand_name ? cand_name->tag : 0u, cand_name_tag, sizeof cand_name_tag),
                                    (unsigned)candidate->store->storage);
            integration_debug_print_path(baseline);
            integration_debug_print_path(candidate);
        }
        munit_assert_uint((unsigned)baseline->store->storage, ==, (unsigned)candidate->store->storage);

        if (baseline->store->indexing == CEP_INDEX_BY_INSERTION) {
            cepCell* base_child = cep_cell_first_all(baseline);
            cepCell* cand_child = cep_cell_first_all(candidate);
            while (base_child || cand_child) {
                while (base_child) {
                    cepCell* resolved = cep_link_pull(base_child);
                    if (resolved && cep_cell_is_normal(resolved))
                        break;
                    base_child = cep_cell_next_all(baseline, base_child);
                }
                while (cand_child) {
                    cepCell* resolved = cep_link_pull(cand_child);
                    if (resolved && cep_cell_is_normal(resolved))
                        break;
                    cand_child = cep_cell_next_all(candidate, cand_child);
                }

                if (!base_child || !cand_child) {
                    munit_assert_ptr_null(base_child);
                    munit_assert_ptr_null(cand_child);
                    break;
                }

                cepCell* resolved_base = cep_link_pull(base_child);
                cepCell* resolved_cand = cep_link_pull(cand_child);
                munit_assert_not_null(resolved_base);
                munit_assert_not_null(resolved_cand);

                integration_assert_manifest_parity_node(resolved_base, resolved_cand);

                base_child = cep_cell_next_all(baseline, base_child);
                cand_child = cep_cell_next_all(candidate, cand_child);
            }
            return;
        }
    }

    size_t baseline_children = 0u;
    for (cepCell* child = cep_cell_first_all(baseline); child; child = cep_cell_next_all(baseline, child)) {
        cepCell* resolved = cep_link_pull(child);
        if (!resolved || !cep_cell_is_normal(resolved))
            continue;
        const cepDT* name = cep_cell_get_name(resolved);
        munit_assert_not_null(name);
        cepCell* counterpart = cep_cell_find_by_name_all(candidate, name);
            if (!counterpart) {
                char dom_buf[64];
                char tag_buf[64];
                INTEGRATION_DEBUG_PRINTF("[integration][parity] missing counterpart name=%s/%s",
                                        integration_debug_id_desc(name->domain, dom_buf, sizeof dom_buf),
                                        integration_debug_id_desc(name->tag, tag_buf, sizeof tag_buf));
                integration_debug_print_path(resolved);
            }
            munit_assert_not_null(counterpart);
            counterpart = cep_link_pull(counterpart);
            if (!counterpart) {
                char dom_buf[64];
                char tag_buf[64];
                INTEGRATION_DEBUG_PRINTF("[integration][parity] counterpart resolve failed name=%s/%s",
                                        integration_debug_id_desc(name->domain, dom_buf, sizeof dom_buf),
                                        integration_debug_id_desc(name->tag, tag_buf, sizeof tag_buf));
                integration_debug_print_path(resolved);
            }
        munit_assert_not_null(counterpart);
        integration_assert_manifest_parity_node(resolved, counterpart);
        baseline_children++;
    }

    size_t candidate_children = 0u;
    for (cepCell* child = cep_cell_first_all(candidate); child; child = cep_cell_next_all(candidate, child)) {
        cepCell* resolved = cep_link_pull(child);
        if (!resolved || !cep_cell_is_normal(resolved))
            continue;
        const cepDT* name = cep_cell_get_name(resolved);
        munit_assert_not_null(name);
        cepCell* counterpart = cep_cell_find_by_name_all(baseline, name);
        munit_assert_not_null(counterpart);
        candidate_children++;
    }
    munit_assert_size(candidate_children, ==, baseline_children);
}

static void integration_assert_manifest_parity(cepCell* baseline_root, cepCell* candidate_root) {
    cepCell* baseline = cep_cell_resolve(baseline_root);
    cepCell* candidate = cep_cell_resolve(candidate_root);
    munit_assert_not_null(baseline);
    munit_assert_not_null(candidate);
    integration_assert_manifest_parity_node(baseline, candidate);
}


/* Emit the `/data/poc` subtree, ingest it into a fresh sibling root, and assert the serialized chunk stream matches byte-for-byte. */
static void integration_serialize_and_replay(IntegrationFixture* fix) {
    munit_assert_not_null(fix);
    munit_assert_not_null(fix->poc_root);

    integration_trace_reset_stage_log();

    IntegrationSerializationCapture primary_capture = {0};
    munit_assert_true(integration_capture_branch_frame(fix, fix->poc_root, &primary_capture));
    integration_dump_trace(&primary_capture, "integration_flat_primary.bin");
    integration_assert_flat_frame_contract(&primary_capture, "flat-primary");
    integration_log_space_flat_records(&primary_capture, "flat-primary");

    /* Keep other subsystems busy between consecutive serializations so the
       flat writer is exercised while the heartbeat continues resolving work. */
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_step());
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_true(cep_heartbeat_stage_commit());

    IntegrationSerializationCapture repeat_capture = {0};
    munit_assert_true(integration_capture_branch_frame(fix, fix->poc_root, &repeat_capture));
    integration_dump_trace(&repeat_capture, "integration_flat_repeat.bin");
    integration_assert_flat_frame_contract(&repeat_capture, "flat-repeat");
    integration_log_space_flat_records(&repeat_capture, "flat-repeat");

    integration_assert_capture_bytes_equal(&primary_capture,
                                           &repeat_capture,
                                           "flat-determinism");

    size_t total_bytes = integration_capture_total_bytes(&primary_capture);
    munit_logf(MUNIT_LOG_INFO,
               "[integration][flat] frame bytes=%zu chunks=%zu",
               total_bytes,
               primary_capture.count);

    integration_cps_roundtrip(fix, &primary_capture);

    integration_capture_clear(&repeat_capture);
    integration_capture_clear(&primary_capture);

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

    INTEGRATION_DEBUG_PRINTF(
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
    INTEGRATION_DEBUG_PRINTF("[integration_poc] mutation_seed=0x%08x", seed);
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
    integration_secdata_flow(&fixture);
    integration_execute_interleaved_timeline(&fixture);
    integration_teardown_tree(&fixture);
    integration_runtime_cleanup(&fixture);
    return MUNIT_OK;
}

/**
 * Focused harness: build the `/data/poc` tree, immediately serialize/replay it,
 * and stop before the rest of the interleaved timeline runs. This isolates the
 * catalog/log replay behaviour so serialization bugs can be reproduced without
 * the broader POC side effects. Set `CEP_POC_ENABLE_SERIALIZATION_FOCUS=0` to
 * skip this test entirely. Whenever new subsystems are added to the main
 * integration timeline, add a matching `CEP_POC_FOCUS_*` toggle here so we can
 * enable that subsystem in isolation during debugging.
 */
static MunitResult test_l0_integration_focus(const MunitParameter params[],
                                             void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    if (!integration_focus_test_enabled()) {
        return MUNIT_SKIP;
    }

    IntegrationFixture fixture = {.boot_oid = cep_oid_invalid()};
    integration_runtime_boot(&fixture);
    integration_build_tree(&fixture);
    integration_secdata_flow(&fixture);
    bool focus_stream_flow = integration_focus_stream_flow_enabled();
    bool focus_ops_ctx = integration_focus_ops_ctx_enabled();
    IntegrationStreamContext stream_ctx;
    integration_stream_ctx_prepare(&stream_ctx, &fixture);
    integration_episode_executor_checks(&stream_ctx);
    integration_episode_lease_flow(&fixture);
    integration_episode_hybrid_flow(&fixture);
    integration_stream_ctx_verify(&stream_ctx);

    IntegrationOpsContext ops_ctx_focus;
    if (focus_ops_ctx) {
        integration_ops_ctx_setup(&ops_ctx_focus, &fixture);
        integration_ops_ctx_mark_ok(&ops_ctx_focus);
        integration_ops_ctx_emit_cei(&ops_ctx_focus, &fixture);
    }

    bool focus_random_plan = integration_focus_random_plan_enabled();
    IntegrationRandomPlan random_plan_focus;
    if (focus_random_plan) {
        integration_random_plan_setup(&random_plan_focus, &fixture);
        integration_random_plan_queue(&random_plan_focus);
        munit_assert_true(cep_heartbeat_stage_commit());
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        munit_assert_true(cep_heartbeat_stage_commit());
        integration_random_plan_verify(&random_plan_focus);
    }

    IntegrationTxnContext txn_ctx_focus = {0};
    if (integration_focus_txn_enabled())
        integration_txn_ctx_begin(&txn_ctx_focus, &fixture);
    if (integration_focus_catalog_plan_enabled()) {
        IntegrationCatalogPlan catalog_plan;
        integration_catalog_plan_setup(&catalog_plan, &fixture);
        integration_catalog_plan_queue_reindex(&catalog_plan);
        munit_assert_true(cep_heartbeat_stage_commit());
        munit_assert_true(cep_heartbeat_step());
        munit_assert_true(cep_heartbeat_resolve_agenda());
        munit_assert_true(cep_heartbeat_process_impulses());
        munit_assert_true(cep_heartbeat_stage_commit());
        integration_catalog_plan_verify(&catalog_plan);
        integration_catalog_plan_cleanup(&catalog_plan, &fixture);
    }
    if (integration_focus_txn_enabled())
        integration_txn_ctx_commit(&txn_ctx_focus, &fixture);
    IntegrationPauseResumeContext prr_ctx;
    integration_prr_ctx_setup(&prr_ctx, &fixture);
    integration_serialize_and_replay(&fixture);
    if (integration_focus_random_mutations_enabled())
        integration_randomized_mutations(&fixture);
    if (integration_focus_organ_enabled())
        integration_exercise_organ_lifecycle(&fixture);
    if (!focus_stream_flow)
        integration_stream_ctx_cleanup(&stream_ctx);
    integration_prr_ctx_execute(&prr_ctx);
    integration_prr_ctx_cleanup(&prr_ctx);
    if (focus_stream_flow)
        integration_stream_ctx_cleanup(&stream_ctx);
    if (focus_ops_ctx) {
        integration_ops_ctx_verify(&ops_ctx_focus, false);
        integration_ops_ctx_cleanup(&ops_ctx_focus);
    }
    if (focus_random_plan) {
        integration_random_plan_cleanup(&random_plan_focus, &fixture);
    }
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
    {
        "/l0/integration_focus",
        test_l0_integration_focus,
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
