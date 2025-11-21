#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "sec_pipeline.h"
#pragma GCC diagnostic pop

#include "../l0_kernel/cep_enclave_policy.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_cei.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../l0_kernel/cep_security_tags.h"
#pragma GCC diagnostic pop

#include <stdio.h>
#include <string.h>

#define CEP_SEC_PIPELINE_NOTE_CAP 160u

typedef struct {
    char     stage_id[64];
    char     enclave[64];
    char     enzyme[96];
    uint64_t bud_cpu_ns;
    uint64_t bud_io_bytes;
    uint32_t max_beats;
    uint32_t max_wall_ms;
} cepSecPipelineStage;

typedef struct {
    char pack[64];
    char name[96];
} cepSecPipelineId;

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[1];
} cepSecPipelinePath;

CEP_DEFINE_STATIC_DT(dt_pipeline_state_field, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_pipeline_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));

static bool
cep_sec_pipeline_read_text(cepCell* parent,
                           const cepDT* field,
                           char* buffer,
                           size_t capacity)
{
    if (!parent || !field || !buffer || capacity == 0u) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node || !node->data) {
        return false;
    }
    cepData* data = node->data;
    const char* payload = (const char*)cep_data_payload(data);
    if (!payload || data->size == 0u) {
        return false;
    }
    size_t length = data->size;
    if (length >= capacity) {
        length = capacity - 1u;
    }
    memcpy(buffer, payload, length);
    buffer[length] = '\0';
    return true;
}

static bool
cep_sec_pipeline_read_u64(cepCell* parent, const cepDT* field, uint64_t* out_value)
{
    if (!parent || !field || !out_value) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node || !node->data) {
        return false;
    }
    cepData* data = node->data;
    const void* payload = cep_data_payload(data);
    if (!payload || data->size != sizeof(uint64_t)) {
        return false;
    }
    const cepDT expected = cep_ops_make_dt("val/u64");
    if (cep_dt_compare(&data->dt, &expected) != 0) {
        return false;
    }
    *out_value = *(const uint64_t*)payload;
    return true;
}

static void
cep_sec_pipeline_copy_reason(char* note, size_t note_cap, const char* message)
{
    if (!note || !note_cap) {
        return;
    }
    if (!message) {
        note[0] = '\0';
        return;
    }
    snprintf(note, note_cap, "%s", message);
}

static void
cep_sec_pipeline_publish_result(cepCell* pipeline_cell,
                                const char* state,
                                const char* note,
                                uint64_t policy_version)
{
    cepCell* approval = cep_cell_ensure_dictionary_child(pipeline_cell,
                                                         dt_sec_pipeline_approval_name(),
                                                         CEP_STORAGE_RED_BLACK_T);
    if (!approval) {
        return;
    }
    approval = cep_cell_resolve(approval);
    if (!approval || !cep_cell_require_dictionary_store(&approval)) {
        return;
    }
    if (state) {
        (void)cep_cell_put_text(approval, dt_pipeline_state_field(), state);
    }
    if (note) {
        (void)cep_cell_put_text(approval, dt_pipeline_note_field(), note);
    }
    (void)cep_cell_put_uint64(approval,
                              dt_sec_pipeline_version_field(),
                              policy_version);
    (void)cep_cell_put_uint64(approval,
                              dt_sec_pipeline_beat_field(),
                              (uint64_t)cep_heartbeat_current());
}

static bool
cep_sec_pipeline_split_id(const char* pipeline_id, cepSecPipelineId* out)
{
    if (!pipeline_id || !out) {
        return false;
    }
    const char* slash = strchr(pipeline_id, '/');
    if (!slash || slash == pipeline_id || !slash[1]) {
        return false;
    }
    size_t pack_len = (size_t)(slash - pipeline_id);
    if (pack_len == 0u || pack_len >= sizeof out->pack) {
        return false;
    }
    size_t name_len = strlen(slash + 1u);
    if (name_len == 0u || name_len >= sizeof out->name) {
        return false;
    }
    memcpy(out->pack, pipeline_id, pack_len);
    out->pack[pack_len] = '\0';
    memcpy(out->name, slash + 1u, name_len + 1u);
    return true;
}

static cepCell*
cep_sec_pipeline_resolve_child(cepCell* parent, const cepDT* name)
{
    if (!parent || !name) {
        return NULL;
    }
    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child) {
        return NULL;
    }
    return cep_cell_resolve(child);
}

static cepCell*
cep_sec_pipeline_data_root(void)
{
    cepCell* root = cep_cell_resolve(cep_heartbeat_data_root());
    if (!root || !cep_cell_require_dictionary_store(&root)) {
        return NULL;
    }
    return root;
}

static cepCell*
cep_sec_pipeline_resolve_from_id(const cepSecPipelineId* id)
{
    if (!id) {
        return NULL;
    }

    cepCell* pack_root = cep_sec_pipeline_data_root();
    if (!pack_root) {
        return NULL;
    }

    cepDT pack_dt = cep_ops_make_dt(id->pack);
    cepCell* pack_cell = cep_sec_pipeline_resolve_child(pack_root, &pack_dt);
    if (!pack_cell || !cep_cell_require_dictionary_store(&pack_cell)) {
        return NULL;
    }

    cepCell* policy = cep_sec_pipeline_resolve_child(pack_cell, dt_sec_policy_dir_name());
    if (!policy || !cep_cell_require_dictionary_store(&policy)) {
        return NULL;
    }

    cepCell* security = cep_sec_pipeline_resolve_child(policy, dt_security_root_name());
    if (!security || !cep_cell_require_dictionary_store(&security)) {
        return NULL;
    }

    cepCell* pipelines = cep_sec_pipeline_resolve_child(security, dt_sec_pipelines_name());
    if (!pipelines || !cep_cell_require_dictionary_store(&pipelines)) {
        return NULL;
    }

    cepDT pipeline_name = cep_ops_make_dt(id->name);
    cepCell* pipeline = cep_sec_pipeline_resolve_child(pipelines, &pipeline_name);
    if (!pipeline) {
        return NULL;
    }
    return cep_cell_resolve(pipeline);
}

static cepCell*
cep_sec_pipeline_resolve_target(const cepPath* target_path)
{
    if (!target_path) {
        return NULL;
    }
    cepCell* current = cep_root();
    current = current ? cep_cell_resolve(current) : NULL;
    if (!current) {
        return NULL;
    }

    unsigned start_index = 0u;
    if (target_path->length > 0u) {
        const cepDT* first = &target_path->past[0].dt;
        if (first && cep_dt_compare(first, &current->metacell.dt) == 0) {
            start_index = 1u;
        }
    }

    for (unsigned i = start_index; i < target_path->length; ++i) {
        const cepDT* segment = &target_path->past[i].dt;
        cepCell* child = cep_cell_find_by_name(current, segment);
        if (!child) {
            bool metadata = false;
            if (cep_cell_is_normal(current)) {
                if (cep_cell_has_store(current) && current->store) {
                    if (cep_dt_compare(segment, &current->store->dt) == 0) {
                        metadata = true;
                    }
                }
                if (!metadata && cep_cell_has_data(current) && current->data) {
                    if (cep_dt_compare(segment, &current->data->dt) == 0) {
                        metadata = true;
                    }
                }
            }
            if (metadata) {
                continue;
            }
            return NULL;
        }
        child = cep_cell_resolve(child);
        if (!child) {
            return NULL;
        }
        current = child;
    }
    return current;
}

static bool
cep_sec_pipeline_parse_stage(cepCell* node,
                             cepSecPipelineStage* out,
                             char* note,
                             size_t note_cap)
{
    if (!node || !out) {
        cep_sec_pipeline_copy_reason(note, note_cap, "invalid stage node");
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node || !cep_cell_require_dictionary_store(&node)) {
        cep_sec_pipeline_copy_reason(note, note_cap, "stage is not a dictionary");
        return false;
    }
    if (!cep_sec_pipeline_read_text(node, dt_sec_stage_id_field(), out->stage_id, sizeof out->stage_id)) {
        cep_sec_pipeline_copy_reason(note, note_cap, "stage missing id");
        return false;
    }
    if (!cep_sec_pipeline_read_text(node, dt_sec_stage_enclave_field(), out->enclave, sizeof out->enclave)) {
        cep_sec_pipeline_copy_reason(note, note_cap, "stage missing enclave");
        return false;
    }
    if (!cep_sec_pipeline_read_text(node, dt_sec_stage_enzyme_field(), out->enzyme, sizeof out->enzyme)) {
        cep_sec_pipeline_copy_reason(note, note_cap, "stage missing enzyme");
        return false;
    }
    (void)cep_sec_pipeline_read_u64(node, dt_sec_bud_cpu_name(), &out->bud_cpu_ns);
    (void)cep_sec_pipeline_read_u64(node, dt_sec_bud_io_name(), &out->bud_io_bytes);

    uint64_t tmp = 0u;
    if (cep_sec_pipeline_read_u64(node, dt_sec_max_beats_name(), &tmp)) {
        out->max_beats = (uint32_t)tmp;
    }
    tmp = 0u;
    if (cep_sec_pipeline_read_u64(node, dt_sec_max_wall_ms_name(), &tmp)) {
        out->max_wall_ms = (uint32_t)tmp;
    }
    return true;
}

static bool
cep_sec_pipeline_collect_stages(cepCell* stages_root,
                                cepSecPipelineStage** stages_out,
                                size_t* count_out,
                                char* note,
                                size_t note_cap)
{
    if (!stages_root || !stages_out || !count_out) {
        cep_sec_pipeline_copy_reason(note, note_cap, "stages missing");
        return false;
    }
    stages_root = cep_cell_resolve(stages_root);
    if (!stages_root || !cep_cell_require_dictionary_store(&stages_root)) {
        cep_sec_pipeline_copy_reason(note, note_cap, "stages is not a dictionary");
        return false;
    }

    size_t count = 0u;
    for (cepCell* entry = cep_cell_first(stages_root); entry; entry = cep_cell_next(stages_root, entry)) {
        ++count;
    }
    if (count == 0u) {
        cep_sec_pipeline_copy_reason(note, note_cap, "no stages defined");
        return false;
    }

    cepSecPipelineStage* stages = cep_malloc0(sizeof *stages * count);
    if (!stages) {
        cep_sec_pipeline_copy_reason(note, note_cap, "allocation failed");
        return false;
    }

    size_t index = 0u;
    for (cepCell* entry = cep_cell_first(stages_root);
         entry && index < count;
         entry = cep_cell_next(stages_root, entry)) {
        if (!cep_sec_pipeline_parse_stage(entry, &stages[index], note, note_cap)) {
            cep_free(stages);
            return false;
        }
        ++index;
    }

    *stages_out = stages;
    *count_out = index;
    return true;
}

static bool
cep_sec_pipeline_validate_edges(const cepSecPipelineStage* stages,
                                size_t stage_count,
                                char* note,
                                size_t note_cap)
{
    if (!stages || stage_count == 0u) {
        cep_sec_pipeline_copy_reason(note, note_cap, "missing stages");
        return false;
    }
    if (stage_count == 1u) {
        return true;
    }

    for (size_t i = 1u; i < stage_count; ++i) {
        const cepSecPipelineStage* prev = &stages[i - 1u];
        const cepSecPipelineStage* next = &stages[i];
        cepEnclavePolicyLimits resolved = {0};
        char reason[96] = {0};
        if (!cep_enclave_policy_check_edge(prev->enclave,
                                           next->enclave,
                                           next->enzyme,
                                           &resolved,
                                           reason,
                                           sizeof reason)) {
            char message[128];
            snprintf(message,
                     sizeof message,
                     "edge %.32s -> %.32s denied: %.32s",
                     prev->enclave,
                     next->enclave,
                     reason[0] ? reason : "policy rejected");
            cep_sec_pipeline_copy_reason(note, note_cap, message);
            return false;
        }
    }
    return true;
}

static uint64_t
cep_sec_pipeline_sum_u64(const cepSecPipelineStage* stages,
                         size_t count,
                         uint64_t (*field)(const cepSecPipelineStage* stage))
{
    uint64_t total = 0u;
    if (!stages || !field) {
        return total;
    }
    for (size_t i = 0u; i < count; ++i) {
        total += field(&stages[i]);
    }
    return total;
}

static uint64_t
cep_sec_pipeline_field_cpu(const cepSecPipelineStage* stage)
{
    return stage ? stage->bud_cpu_ns : 0u;
}

static uint64_t
cep_sec_pipeline_field_io(const cepSecPipelineStage* stage)
{
    return stage ? stage->bud_io_bytes : 0u;
}

static bool
cep_sec_pipeline_validate_ceilings(const cepSecPipelineStage* stages,
                                   size_t stage_count,
                                   cepCell* ceilings_node,
                                   char* note,
                                   size_t note_cap)
{
    const cepEnclavePipelineCeilings* ceilings = cep_enclave_policy_pipeline();
    if (!ceilings) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline ceilings unavailable");
        return false;
    }

    uint64_t requested_cpu = 0u;
    uint64_t requested_io = 0u;
    uint64_t requested_hops = (stage_count > 0u) ? (stage_count - 1u) : 0u;
    uint64_t requested_wall = 0u;

    if (ceilings_node) {
        (void)cep_sec_pipeline_read_u64(ceilings_node, dt_sec_total_cpu_name(), &requested_cpu);
        (void)cep_sec_pipeline_read_u64(ceilings_node, dt_sec_total_io_name(), &requested_io);
        uint64_t hops = 0u;
        if (cep_sec_pipeline_read_u64(ceilings_node, dt_sec_max_hops_name(), &hops)) {
            requested_hops = hops;
        }
        (void)cep_sec_pipeline_read_u64(ceilings_node, dt_sec_max_wall_ms_name(), &requested_wall);
    }

    if (requested_cpu == 0u) {
        requested_cpu = cep_sec_pipeline_sum_u64(stages, stage_count, cep_sec_pipeline_field_cpu);
    }
    if (requested_io == 0u) {
        requested_io = cep_sec_pipeline_sum_u64(stages, stage_count, cep_sec_pipeline_field_io);
    }

    if (ceilings->max_hops && requested_hops > ceilings->max_hops) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline exceeds hop ceiling");
        return false;
    }
    if (ceilings->total_cpu_ns && requested_cpu > ceilings->total_cpu_ns) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline exceeds CPU ceiling");
        return false;
    }
    if (ceilings->total_io_bytes && requested_io > ceilings->total_io_bytes) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline exceeds IO ceiling");
        return false;
    }
    if (ceilings->max_wall_ms && requested_wall > ceilings->max_wall_ms) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline exceeds wall-clock ceiling");
        return false;
    }

    return true;
}

static bool
cep_sec_pipeline_validate(cepCell* pipeline_cell,
                          char* note,
                          size_t note_cap,
                          char* pipeline_id_out,
                          size_t pipeline_id_cap)
{
    if (!pipeline_cell) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline missing");
        return false;
    }
    pipeline_cell = cep_cell_resolve(pipeline_cell);
    if (!pipeline_cell || !cep_cell_require_dictionary_store(&pipeline_cell)) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline is not a dictionary");
        return false;
    }
    if (!cep_enclave_policy_ready()) {
        cep_sec_pipeline_copy_reason(note, note_cap, "enclave policy not ready");
        return false;
    }

    char pipeline_id[128] = {0};
    if (!cep_sec_pipeline_read_text(pipeline_cell,
                                    dt_sec_pipeline_id_field(),
                                    pipeline_id,
                                    sizeof pipeline_id)) {
        cep_sec_pipeline_copy_reason(note, note_cap, "pipeline_id missing");
        return false;
    }

    cepCell* stages_root = cep_cell_find_by_name(pipeline_cell, dt_sec_pipeline_stages_name());
    if (!stages_root) {
        cep_sec_pipeline_copy_reason(note, note_cap, "stages node missing");
        return false;
    }

    cepSecPipelineStage* stages = NULL;
    size_t stage_count = 0u;
    if (!cep_sec_pipeline_collect_stages(stages_root, &stages, &stage_count, note, note_cap)) {
        return false;
    }

    cepCell* ceilings = cep_cell_find_by_name(pipeline_cell, dt_sec_pipeline_ceilings_name());
    bool ok = cep_sec_pipeline_validate_edges(stages, stage_count, note, note_cap);
    if (ok) {
        ok = cep_sec_pipeline_validate_ceilings(stages, stage_count, ceilings, note, note_cap);
    }

    if (ok && pipeline_id_out && pipeline_id_cap) {
        snprintf(pipeline_id_out, pipeline_id_cap, "%s", pipeline_id);
    }

    cep_free(stages);
    return ok;
}

static void
cep_sec_pipeline_emit_reject_cei(cepCell* pipeline_cell,
                                 const char* pipeline_id,
                                 const char* reason)
{
    const char* id = (pipeline_id && *pipeline_id) ? pipeline_id : "<unknown>";
    const char* detail = (reason && *reason) ? reason : "pipeline rejected";

    char note[CEP_SEC_PIPELINE_NOTE_CAP];
    snprintf(note, sizeof note, "pipeline=%s reason=%s", id, detail);

    cepCeiRequest req = {
        .severity = *dt_sec_pipeline_sev_warn(),
        .topic = "sec.pipeline.reject",
        .topic_intern = true,
        .note = note,
        .subject = pipeline_cell ? cep_cell_resolve(pipeline_cell) : NULL,
        .mailbox_root = cep_cei_diagnostics_mailbox(),
        .emit_signal = true,
        .ttl_forever = true,
    };
    (void)cep_cei_emit(&req);
}

static int
cep_sec_pipeline_preflight_enzyme(const cepPath* signal_path, const cepPath* target_path)
{
    (void)signal_path;
    cepCell* pipeline_cell = cep_sec_pipeline_resolve_target(target_path);
    if (!pipeline_cell) {
        return CEP_ENZYME_FATAL;
    }

    char note[CEP_SEC_PIPELINE_NOTE_CAP] = {0};
    char pipeline_id[128] = {0};
    const cepEnclavePolicySnapshot* snapshot = cep_enclave_policy_snapshot();
    uint64_t policy_version = snapshot ? snapshot->version : 0u;

    bool ok = cep_sec_pipeline_validate(pipeline_cell,
                                        note,
                                        sizeof note,
                                        pipeline_id,
                                        sizeof pipeline_id);

    if (ok) {
        cep_sec_pipeline_publish_result(pipeline_cell, "approved", "pipeline approved", policy_version);
    } else {
        const char* reason = note[0] ? note : "pipeline rejected";
        cep_sec_pipeline_emit_reject_cei(pipeline_cell, pipeline_id, reason);
        cep_sec_pipeline_publish_result(pipeline_cell, "rejected", reason, policy_version);
    }
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

bool
cep_sec_pipeline_bootstrap(void)
{
    static bool registered = false;
    if (registered) {
        return true;
    }
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return false;
    }

    cepSecPipelinePath query = {
        .length = 1u,
        .capacity = 1u,
        .past = {
            {
                .dt = cep_ops_make_dt("sig_sec/pipeline_preflight"),
                .timestamp = 0u,
            },
        },
    };

    cepEnzymeDescriptor descriptor = {
        .name = query.past[0].dt,
        .label = "sec.pipeline.preflight",
        .callback = cep_sec_pipeline_preflight_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    if (cep_enzyme_register(registry, (const cepPath*)&query, &descriptor) != CEP_ENZYME_SUCCESS) {
        return false;
    }
    registered = true;
    return true;
}

int
cep_sec_pipeline_run_preflight(const cepPath* target_path)
{
    return cep_sec_pipeline_preflight_enzyme(NULL, target_path);
}

bool
cep_sec_pipeline_approved(const char* pipeline_id,
                          uint64_t* approved_policy_version,
                          char* note,
                          size_t note_capacity)
{
    cepSecPipelineId parsed = {0};
    if (!pipeline_id || !cep_sec_pipeline_split_id(pipeline_id, &parsed)) {
        cep_sec_pipeline_copy_reason(note, note_capacity, "invalid pipeline_id");
        return false;
    }
    cepCell* pipeline = cep_sec_pipeline_resolve_from_id(&parsed);
    if (!pipeline) {
        cep_sec_pipeline_copy_reason(note, note_capacity, "pipeline spec missing");
        return false;
    }

    cepCell* approval = cep_cell_find_by_name(pipeline, dt_sec_pipeline_approval_name());
    if (!approval) {
        cep_sec_pipeline_copy_reason(note, note_capacity, "pipeline not approved");
        return false;
    }
    approval = cep_cell_resolve(approval);
    if (!approval || !cep_cell_require_dictionary_store(&approval)) {
        cep_sec_pipeline_copy_reason(note, note_capacity, "approval branch invalid");
        return false;
    }

    char state[32] = {0};
    if (!cep_sec_pipeline_read_text(approval, dt_pipeline_state_field(), state, sizeof state)) {
        cep_sec_pipeline_copy_reason(note, note_capacity, "approval state missing");
        return false;
    }
    if (strcmp(state, "approved") != 0) {
        cep_sec_pipeline_read_text(approval, dt_pipeline_note_field(), note, note_capacity);
        if (!note || !note[0]) {
            cep_sec_pipeline_copy_reason(note, note_capacity, "pipeline not approved");
        }
        return false;
    }

    uint64_t policy_version = 0u;
    (void)cep_sec_pipeline_read_u64(approval, dt_sec_pipeline_version_field(), &policy_version);
    const cepEnclavePolicySnapshot* snapshot = cep_enclave_policy_snapshot();
    uint64_t current_version = snapshot ? snapshot->version : 0u;
    if (snapshot && policy_version != snapshot->version) {
        if (cep_enclave_policy_is_frozen()) {
            policy_version = snapshot->version;
        } else {
            cep_sec_pipeline_copy_reason(note, note_capacity, "approval out of date");
            return false;
        }
    }

    if (approved_policy_version) {
        *approved_policy_version = policy_version ? policy_version : current_version;
    }
    if (note && note_capacity) {
        note[0] = '\0';
    }
    return true;
}
