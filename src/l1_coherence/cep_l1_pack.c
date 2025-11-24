/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_pack.h"

#include "cep_l1_schema.h"
#include "cep_l1_coherence.h"
#include "cep_l1_pipelines.h"
#include "cep_l1_runtime.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_runtime.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_organ.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_l1_boot_verb, CEP_ACRO("CEP"), CEP_WORD("op/l1_boot"));
CEP_DEFINE_STATIC_DT(dt_l1_shdn_verb, CEP_ACRO("CEP"), CEP_WORD("op/l1_shdn"));
CEP_DEFINE_STATIC_DT(dt_l1_coh_sweep_verb, CEP_ACRO("CEP"), cep_namepool_intern_cstr("op/coh_sweep"));
CEP_DEFINE_STATIC_DT(dt_l1_op_mode_states, CEP_ACRO("CEP"), CEP_WORD("opm:states"));
CEP_DEFINE_STATIC_DT(dt_l1_state_field, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_l1_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_l1_status_ok, CEP_ACRO("CEP"), CEP_WORD("sts:ok"));
CEP_DEFINE_STATIC_DT(dt_l1_status_fail, CEP_ACRO("CEP"), CEP_WORD("sts:fail"));
CEP_DEFINE_STATIC_DT(dt_l1_state_ok, CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_l1_state_halt, CEP_ACRO("CEP"), CEP_WORD("ist:halt"));
CEP_DEFINE_STATIC_DT(dt_l1_pipeline_id_field, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_l1_owner_field, CEP_ACRO("CEP"), CEP_WORD("owner"));
CEP_DEFINE_STATIC_DT(dt_l1_province_field, CEP_ACRO("CEP"), CEP_WORD("province"));
CEP_DEFINE_STATIC_DT(dt_l1_version_field, CEP_ACRO("CEP"), CEP_WORD("ver"));
CEP_DEFINE_STATIC_DT(dt_l1_revision_field, CEP_ACRO("CEP"), CEP_WORD("rev"));
CEP_DEFINE_STATIC_DT(dt_l1_max_hops_field, CEP_ACRO("CEP"), CEP_WORD("max_hops"));
CEP_DEFINE_STATIC_DT(dt_l1_required_field, CEP_ACRO("CEP"), CEP_WORD("required"));
CEP_DEFINE_STATIC_DT(dt_l1_role_field, CEP_ACRO("CEP"), CEP_WORD("role"));

CEP_DEFINE_STATIC_DT(dt_org_coh_root_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:coh_root:vl"));
CEP_DEFINE_STATIC_DT(dt_org_coh_root_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:coh_root:ct"));
CEP_DEFINE_STATIC_DT(dt_org_coh_root_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:coh_root:dt"));
CEP_DEFINE_STATIC_DT(dt_org_coh_root_sweep, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:coh_root:sweep"));
CEP_DEFINE_STATIC_DT(dt_org_coh_root_migrate, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:coh_root:migrate_schema"));

CEP_DEFINE_STATIC_DT(dt_org_flow_spec_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_spec_l1:vl"));
CEP_DEFINE_STATIC_DT(dt_org_flow_spec_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_spec_l1:ct"));
CEP_DEFINE_STATIC_DT(dt_org_flow_spec_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_spec_l1:dt"));
CEP_DEFINE_STATIC_DT(dt_org_flow_spec_ensure, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_spec_l1:ensure_pipeline"));
CEP_DEFINE_STATIC_DT(dt_org_flow_spec_normalize, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_spec_l1:normalize_edges"));
CEP_DEFINE_STATIC_DT(dt_org_flow_spec_rebuild, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_spec_l1:rebuild_provenance"));

CEP_DEFINE_STATIC_DT(dt_org_flow_runtime_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_runtime_l1:vl"));
CEP_DEFINE_STATIC_DT(dt_org_flow_runtime_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_runtime_l1:ct"));
CEP_DEFINE_STATIC_DT(dt_org_flow_runtime_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_runtime_l1:dt"));
CEP_DEFINE_STATIC_DT(dt_org_flow_runtime_gc, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_runtime_l1:gc_runs"));
CEP_DEFINE_STATIC_DT(dt_org_flow_runtime_rollup, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_runtime_l1:rollup_metrics"));
CEP_DEFINE_STATIC_DT(dt_org_flow_runtime_verify, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:flow_runtime_l1:verify_edges"));

typedef struct {
    bool              bootstrap_done;
    bool              organs_registered;
    cepOID            boot_oid;
    cepL1SchemaLayout layout;
} cepL1PackState;

static cepL1PackState g_l1_pack_state = {0};

static bool cep_l1_pack_prereqs_ready(void) {
    return cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL) &&
           cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL);
}

static bool cep_l1_pack_record_state(cepCell* state_root,
                                     const cepDT* state_value,
                                     const char* note) {
    if (!state_root || !state_value) {
        return false;
    }

    cepCell* resolved = cep_cell_resolve(state_root);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    if (!cep_cell_put_dt(resolved, dt_l1_state_field(), state_value)) {
        return false;
    }

    if (note && note[0]) {
        if (!cep_cell_put_text(resolved, dt_l1_note_field(), note)) {
            return false;
        }
    }

    return true;
}

static bool cep_l1_pack_copy_dt_text(const cepDT* dt, char* buffer, size_t buffer_size) {
    if (!dt || !buffer || buffer_size == 0u) {
        return false;
    }
    const char* text = cep_namepool_lookup(dt->tag, NULL);
    if (!text) {
        return false;
    }
    size_t len = strlen(text);
    if (len >= buffer_size) {
        len = buffer_size - 1u;
    }
    memcpy(buffer, text, len);
    buffer[len] = '\0';
    return true;
}

static bool cep_l1_pack_copy_text_field(cepCell* parent,
                                        const cepDT* field,
                                        char* buffer,
                                        size_t buffer_size) {
    if (!parent || !field || !buffer || buffer_size == 0u) {
        return false;
    }
    cepCell* field_cell = cep_cell_find_by_name(parent, field);
    field_cell = field_cell ? cep_cell_resolve(field_cell) : NULL;
    if (!field_cell) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&field_cell, &data) || !data || data->size == 0u) {
        return false;
    }
    size_t length = data->size;
    if (length >= buffer_size) {
        length = buffer_size - 1u;
    }
    memcpy(buffer, cep_data_payload(data), length);
    buffer[length] = '\0';
    return true;
}

static bool cep_l1_pack_copy_uint64_field(cepCell* parent, const cepDT* field, uint64_t* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* field_cell = cep_cell_find_by_name(parent, field);
    field_cell = field_cell ? cep_cell_resolve(field_cell) : NULL;
    if (!field_cell) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&field_cell, &data) || !data || data->size < sizeof(uint64_t)) {
        return false;
    }
    memcpy(out, cep_data_payload(data), sizeof(uint64_t));
    return true;
}

static bool cep_l1_pack_make_dt_text(const char* text, cepDT* out) {
    if (!text || !out) {
        return false;
    }
    cepID tag = cep_namepool_intern_cstr(text);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_pack_seed_required_rule(cepCell* ctx_rules_root,
                                           const char* ctx_kind,
                                           const char* bucket_name,
                                           const char* entry_name,
                                           bool required) {
    if (!ctx_rules_root || !ctx_kind || !bucket_name || !entry_name) {
        return false;
    }

    cepDT ctx_dt = {0};
    cepDT bucket_dt = {0};
    cepDT entry_dt = {0};
    if (!cep_l1_pack_make_dt_text(ctx_kind, &ctx_dt) ||
        !cep_l1_pack_make_dt_text(bucket_name, &bucket_dt) ||
        !cep_l1_pack_make_dt_text(entry_name, &entry_dt)) {
        return false;
    }

    cepCell* ctx_root = cep_cell_ensure_dictionary_child(ctx_rules_root, &ctx_dt, CEP_STORAGE_RED_BLACK_T);
    ctx_root = ctx_root ? cep_cell_resolve(ctx_root) : NULL;
    if (!ctx_root || !cep_cell_require_dictionary_store(&ctx_root)) {
        return false;
    }

    cepCell* bucket = cep_cell_ensure_dictionary_child(ctx_root, &bucket_dt, CEP_STORAGE_RED_BLACK_T);
    bucket = bucket ? cep_cell_resolve(bucket) : NULL;
    if (!bucket || !cep_cell_require_dictionary_store(&bucket)) {
        return false;
    }

    cepCell* entry = cep_cell_ensure_dictionary_child(bucket, &entry_dt, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    if (!cep_cell_find_by_name(entry, dt_l1_role_field())) {
        (void)cep_cell_put_text(entry, dt_l1_role_field(), entry_name);
    }

    cepCell* existing_required = cep_cell_find_by_name(entry, dt_l1_required_field());
    existing_required = existing_required ? cep_cell_resolve(existing_required) : NULL;
    bool has_required = existing_required && cep_cell_has_data(existing_required);
    if (!has_required) {
        (void)cep_cell_put_uint64(entry, dt_l1_required_field(), required ? 1u : 0u);
    }

    return true;
}

static bool cep_l1_pack_seed_pipeline_ctx_rules(cepCell* ctx_rules_root) {
    if (!ctx_rules_root) {
        return false;
    }
    bool ok = true;
    ok &= cep_l1_pack_seed_required_rule(ctx_rules_root, "pipeline_edge", "roles", "pipeline", true);
    ok &= cep_l1_pack_seed_required_rule(ctx_rules_root, "pipeline_edge", "roles", "from_stage", true);
    ok &= cep_l1_pack_seed_required_rule(ctx_rules_root, "pipeline_edge", "roles", "to_stage", true);
    return ok;
}

static bool cep_l1_pack_seed_ctx_rules(cepL1SchemaLayout* layout) {
    if (!layout || !layout->coh_context_rules) {
        return false;
    }
    cepCell* rules = cep_cell_resolve(layout->coh_context_rules);
    if (!rules || !cep_cell_require_dictionary_store(&rules)) {
        return false;
    }
    bool ok = true;
    ok &= cep_l1_pack_seed_pipeline_ctx_rules(rules);
    layout->coh_context_rules = rules;
    return ok;
}

static void cep_l1_pack_label_organ_root(cepCell* root, const char* kind) {
    if (!root || !kind || !*kind) {
        return;
    }
    cepCell* resolved = cep_cell_resolve(root);
    if (!resolved || !resolved->store) {
        return;
    }
    cepDT organ_dt = cep_organ_store_dt(kind);
    if (cep_dt_is_valid(&organ_dt)) {
        cep_store_set_dt(resolved->store, &organ_dt);
    }
}

static bool cep_l1_pack_make_pipeline_dt(const char* pipeline_id, cepDT* out) {
    if (!pipeline_id || !out) {
        return false;
    }
    size_t len = strlen(pipeline_id);
    if (len == 0u) {
        return false;
    }
    cepID tag = cep_namepool_intern(pipeline_id, len);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_pack_load_layout(cepL1SchemaLayout* layout) {
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return false;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    bool ok = cep_l1_schema_ensure(layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout->coh_root, "coh_root");
        cep_l1_pack_label_organ_root(layout->flow_pipelines, "flow_spec_l1");
        cep_l1_pack_label_organ_root(layout->flow_runtime, "flow_runtime_l1");
    }

    cep_runtime_restore_active(previous_scope);
    return ok;
}

static bool cep_l1_pack_register_enzyme(cepEnzymeRegistry* registry,
                                        const cepDT* name,
                                        const char* label,
                                        cepEnzyme callback) {
    if (!registry || !name || !label || !callback) {
        return false;
    }
    struct {
        cepPath path;
        cepPast past[1];
    } path_buf = {
        .path.length = 1u,
        .path.capacity = 1u,
        .past = {{.dt = *name, .timestamp = 0u}},
    };
    cepEnzymeDescriptor desc = {
        .name = *name,
        .label = label,
        .callback = callback,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    return cep_enzyme_register(registry, (const cepPath*)&path_buf, &desc) == CEP_ENZYME_SUCCESS;
}

static bool cep_l1_pack_register_organs(void);
static int cep_l1_pack_org_coh_ct(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_coh_vl(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_coh_dt(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_coh_sweep(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_coh_migrate(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_spec_ct(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_spec_vl(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_spec_dt(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_spec_ensure(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_spec_normalize(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_spec_rebuild(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_runtime_ct(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_runtime_vl(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_runtime_dt(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_runtime_gc(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_runtime_rollup(const cepPath* signal, const cepPath* target);
static int cep_l1_pack_org_flow_runtime_verify(const cepPath* signal, const cepPath* target);

static bool cep_l1_pack_start_boot_op(cepL1PackState* state) {
    if (!state) {
        return false;
    }
    if (cep_oid_is_valid(state->boot_oid)) {
        return true;
    }
    cepOID oid = cep_op_start(*dt_l1_boot_verb(),
                              "/data/flow",
                              *dt_l1_op_mode_states(),
                              NULL,
                              0u,
                              0u);
    if (!cep_oid_is_valid(oid)) {
        return false;
    }
    state->boot_oid = oid;
    return true;
}

static void cep_l1_pack_fail_boot_op(const cepL1PackState* state) {
    if (!state) {
        return;
    }
    if (!cep_oid_is_valid(state->boot_oid)) {
        return;
    }
    (void)cep_op_close(state->boot_oid, *dt_l1_status_fail(), NULL, 0u);
}

static bool cep_l1_pack_register_organs(void) {
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return false;
    }

    if (g_l1_pack_state.organs_registered) {
        return true;
    }

    cepOrganDescriptor coh_desc = {
        .kind = "coh_root",
        .label = "organ.coh_root",
        .store = cep_organ_store_dt("coh_root"),
        .validator = *dt_org_coh_root_vl(),
        .constructor = *dt_org_coh_root_ct(),
        .destructor = *dt_org_coh_root_dt(),
    };
    cepOrganDescriptor spec_desc = {
        .kind = "flow_spec_l1",
        .label = "organ.flow_spec_l1",
        .store = cep_organ_store_dt("flow_spec_l1"),
        .validator = *dt_org_flow_spec_vl(),
        .constructor = *dt_org_flow_spec_ct(),
        .destructor = *dt_org_flow_spec_dt(),
    };
    cepOrganDescriptor runtime_desc = {
        .kind = "flow_runtime_l1",
        .label = "organ.flow_runtime_l1",
        .store = cep_organ_store_dt("flow_runtime_l1"),
        .validator = *dt_org_flow_runtime_vl(),
        .constructor = *dt_org_flow_runtime_ct(),
        .destructor = *dt_org_flow_runtime_dt(),
    };

    if (!cep_organ_register(&coh_desc) ||
        !cep_organ_register(&spec_desc) ||
        !cep_organ_register(&runtime_desc)) {
        return false;
    }

    bool ok = true;
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_coh_root_ct(), "organ.coh_root.ct", cep_l1_pack_org_coh_ct);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_coh_root_vl(), "organ.coh_root.vl", cep_l1_pack_org_coh_vl);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_coh_root_dt(), "organ.coh_root.dt", cep_l1_pack_org_coh_dt);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_coh_root_sweep(), "organ.coh_root.sweep", cep_l1_pack_org_coh_sweep);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_coh_root_migrate(), "organ.coh_root.migrate", cep_l1_pack_org_coh_migrate);

    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_spec_ct(), "organ.flow_spec_l1.ct", cep_l1_pack_org_flow_spec_ct);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_spec_vl(), "organ.flow_spec_l1.vl", cep_l1_pack_org_flow_spec_vl);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_spec_dt(), "organ.flow_spec_l1.dt", cep_l1_pack_org_flow_spec_dt);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_spec_ensure(), "organ.flow_spec_l1.ensure", cep_l1_pack_org_flow_spec_ensure);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_spec_normalize(), "organ.flow_spec_l1.normalize", cep_l1_pack_org_flow_spec_normalize);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_spec_rebuild(), "organ.flow_spec_l1.rebuild", cep_l1_pack_org_flow_spec_rebuild);

    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_runtime_ct(), "organ.flow_runtime_l1.ct", cep_l1_pack_org_flow_runtime_ct);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_runtime_vl(), "organ.flow_runtime_l1.vl", cep_l1_pack_org_flow_runtime_vl);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_runtime_dt(), "organ.flow_runtime_l1.dt", cep_l1_pack_org_flow_runtime_dt);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_runtime_gc(), "organ.flow_runtime_l1.gc", cep_l1_pack_org_flow_runtime_gc);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_runtime_rollup(), "organ.flow_runtime_l1.rollup", cep_l1_pack_org_flow_runtime_rollup);
    ok &= cep_l1_pack_register_enzyme(registry, dt_org_flow_runtime_verify(), "organ.flow_runtime_l1.verify", cep_l1_pack_org_flow_runtime_verify);

    if (ok) {
        g_l1_pack_state.organs_registered = true;
    }
    return ok;
}

static void cep_l1_pack_target_pipeline_id(const cepPath* target, char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0u) {
        return;
    }
    buffer[0] = '\0';
    if (!target || target->length == 0u) {
        return;
    }
    const cepPast* tail = &target->past[target->length - 1u];
    (void)cep_l1_pack_copy_dt_text(&tail->dt, buffer, buffer_size);
}

static bool cep_l1_pack_resolve_pipeline(cepL1SchemaLayout* layout,
                                         const char* pipeline_id,
                                         cepCell** pipeline_out,
                                         cepL1PipelineLayout* pipeline_layout_out) {
    if (!layout || !pipeline_id || !*pipeline_id) {
        return false;
    }
    cepDT pipeline_dt = {0};
    if (!cep_l1_pack_make_pipeline_dt(pipeline_id, &pipeline_dt)) {
        return false;
    }
    cepCell* pipeline = cep_cell_find_by_name(layout->flow_pipelines, &pipeline_dt);
    pipeline = pipeline ? cep_cell_resolve(pipeline) : NULL;
    if (!pipeline || !cep_cell_require_dictionary_store(&pipeline)) {
        return false;
    }
    if (pipeline_out) {
        *pipeline_out = pipeline;
    }
    if (pipeline_layout_out) {
        (void)cep_l1_pipeline_layout_from_root(pipeline, pipeline_layout_out);
    }
    return true;
}

static void cep_l1_pack_fill_pipeline_meta_from_cell(cepCell* pipeline,
                                                     cepL1PipelineMeta* meta,
                                                     char* owner_buf,
                                                     size_t owner_cap,
                                                     char* province_buf,
                                                     size_t province_cap,
                                                     char* version_buf,
                                                     size_t version_cap) {
    if (!pipeline || !meta) {
        return;
    }
    if (owner_buf && owner_cap > 0u) {
        owner_buf[0] = '\0';
    }
    if (province_buf && province_cap > 0u) {
        province_buf[0] = '\0';
    }
    if (version_buf && version_cap > 0u) {
        version_buf[0] = '\0';
    }
    uint64_t revision = 0u;
    uint64_t max_hops = 0u;
    (void)cep_l1_pack_copy_text_field(pipeline, dt_l1_owner_field(), owner_buf, owner_cap);
    (void)cep_l1_pack_copy_text_field(pipeline, dt_l1_province_field(), province_buf, province_cap);
    (void)cep_l1_pack_copy_text_field(pipeline, dt_l1_version_field(), version_buf, version_cap);
    (void)cep_l1_pack_copy_uint64_field(pipeline, dt_l1_revision_field(), &revision);
    (void)cep_l1_pack_copy_uint64_field(pipeline, dt_l1_max_hops_field(), &max_hops);
    if (owner_buf && owner_buf[0]) {
        meta->owner = owner_buf;
    }
    if (province_buf && province_buf[0]) {
        meta->province = province_buf;
    }
    if (version_buf && version_buf[0]) {
        meta->version = version_buf;
    }
    if (revision > 0u) {
        meta->revision = revision;
    }
    if (max_hops > 0u) {
        meta->max_hops = max_hops;
    }
}

/* Bring the Layer 1 pack online by ensuring the coherence/flow layout exists,
   publishing a pack-scoped boot operation, and recording a ready state that
   higher layers can watch without touching kernel lifecycle scopes. The helper
   is idempotent so repeated bootstraps only refresh handles. */
bool cep_l1_pack_bootstrap(void) {
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return false;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    if (!cep_l1_pack_prereqs_ready()) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!cep_l1_pack_register_organs()) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!cep_l1_pack_load_layout(&g_l1_pack_state.layout)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    bool organs_ok = (cep_l1_pack_org_coh_ct(NULL, NULL) == CEP_ENZYME_SUCCESS) &&
                     (cep_l1_pack_org_flow_spec_ct(NULL, NULL) == CEP_ENZYME_SUCCESS) &&
                     (cep_l1_pack_org_flow_runtime_ct(NULL, NULL) == CEP_ENZYME_SUCCESS) &&
                     (cep_l1_pack_org_coh_vl(NULL, NULL) == CEP_ENZYME_SUCCESS) &&
                     (cep_l1_pack_org_flow_spec_vl(NULL, NULL) == CEP_ENZYME_SUCCESS) &&
                     (cep_l1_pack_org_flow_runtime_vl(NULL, NULL) == CEP_ENZYME_SUCCESS);

    if (organs_ok && cep_l1_pack_org_flow_spec_rebuild(NULL, NULL) != CEP_ENZYME_SUCCESS) {
        organs_ok = false;
    }

    if (g_l1_pack_state.bootstrap_done) {
        cep_runtime_restore_active(previous_scope);
        return organs_ok;
    }

    (void)cep_l1_coh_register_closure_enzyme();

    if (!cep_l1_pack_start_boot_op(&g_l1_pack_state)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!organs_ok) {
        cep_l1_pack_fail_boot_op(&g_l1_pack_state);
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!cep_l1_pack_record_state(g_l1_pack_state.layout.flow_state,
                                  dt_l1_state_ok(),
                                  "Layer 1 pack ready")) {
        cep_l1_pack_fail_boot_op(&g_l1_pack_state);
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!cep_op_close(g_l1_pack_state.boot_oid, *dt_l1_status_ok(), NULL, 0u)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    g_l1_pack_state.bootstrap_done = true;
    cep_runtime_restore_active(previous_scope);
    return true;
}

/* Run a coherence sweep over all contexts, recording an op dossier so callers
   can audit closure attempts. This is a light-weight maintenance helper and
   can run even when the pack was already bootstrapped. */
bool cep_l1_pack_coh_sweep(void) {
    return cep_l1_pack_org_coh_sweep(NULL, NULL) == CEP_ENZYME_SUCCESS;
}

/* Roll back the Layer 1 pack readiness markers so the next bootstrap can rebuild
   the layout and emit fresh readiness evidence without assuming prior state.
   No attempt is made to prune existing pipeline/runtime records yet. */
bool cep_l1_pack_shutdown(void) {
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return false;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    if (!cep_l1_schema_ensure(&layout)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    cepOID shutdown_oid = cep_op_start(*dt_l1_shdn_verb(),
                                       "/data/flow",
                                       *dt_l1_op_mode_states(),
                                       NULL,
                                       0u,
                                       0u);
    (void)cep_l1_pack_org_flow_runtime_dt(NULL, NULL);
    (void)cep_l1_pack_org_flow_spec_dt(NULL, NULL);
    (void)cep_l1_pack_org_coh_dt(NULL, NULL);
    if (cep_oid_is_valid(shutdown_oid)) {
        (void)cep_l1_pack_record_state(layout.flow_state,
                                       dt_l1_state_halt(),
                                       "Layer 1 pack shutdown");
        (void)cep_op_close(shutdown_oid, *dt_l1_status_ok(), NULL, 0u);
    }

    g_l1_pack_state.bootstrap_done = false;
    g_l1_pack_state.boot_oid = cep_oid_invalid();
    memset(&g_l1_pack_state.layout, 0, sizeof g_l1_pack_state.layout);

    cep_runtime_restore_active(previous_scope);
    return true;
}

static int cep_l1_pack_org_coh_ct(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.coh_root, "coh_root");
        ok = cep_l1_pack_seed_ctx_rules(&layout);
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_coh_vl(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    ok = ok && layout.coh_beings && layout.coh_bonds && layout.coh_contexts && layout.coh_facets && layout.coh_debts &&
         layout.coh_adj_by_being && layout.coh_adj_by_context && layout.coh_adj_by_facet_kind &&
         layout.coh_context_rules;
    ok = ok && cep_cell_require_dictionary_store(&layout.coh_beings) &&
         cep_cell_require_dictionary_store(&layout.coh_bonds) &&
         cep_cell_require_dictionary_store(&layout.coh_contexts) &&
         cep_cell_require_dictionary_store(&layout.coh_facets) &&
         cep_cell_require_dictionary_store(&layout.coh_debts) &&
         cep_cell_require_dictionary_store(&layout.coh_adj) &&
         cep_cell_require_dictionary_store(&layout.coh_adj_by_being) &&
         cep_cell_require_dictionary_store(&layout.coh_adj_by_context) &&
         cep_cell_require_dictionary_store(&layout.coh_adj_by_facet_kind) &&
         cep_cell_require_dictionary_store(&layout.coh_context_rules);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.coh_root, "coh_root");
        ok = cep_l1_pack_seed_ctx_rules(&layout) && cep_l1_coh_run_closure(&layout, NULL);
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_coh_dt(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.coh_root, "coh_root");
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_coh_sweep(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);

    cepOID oid = cep_op_start(*dt_l1_coh_sweep_verb(),
                              "/data/coh",
                              *dt_l1_op_mode_states(),
                              NULL,
                              0u,
                              0u);

    if (ok) {
        ok = cep_l1_coh_run_closure(&layout, NULL);
    }
    if (cep_oid_is_valid(oid)) {
        (void)cep_op_close(oid, ok ? *dt_l1_status_ok() : *dt_l1_status_fail(), NULL, 0u);
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_coh_migrate(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        ok = cep_l1_pack_seed_ctx_rules(&layout);
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_spec_ct(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.flow_pipelines, "flow_spec_l1");
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_spec_vl(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    ok = ok && layout.flow_pipelines && cep_cell_require_dictionary_store(&layout.flow_pipelines);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.flow_pipelines, "flow_spec_l1");
        for (cepCell* pipeline = cep_cell_first(layout.flow_pipelines); pipeline; pipeline = cep_cell_next(layout.flow_pipelines, pipeline)) {
            cepCell* resolved = cep_cell_resolve(pipeline);
            if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
                ok = false;
                continue;
            }
            cepL1PipelineLayout pl = {0};
            (void)cep_l1_pipeline_layout_from_root(resolved, &pl);
            char pipeline_id[128] = {0};
            (void)cep_l1_pack_copy_text_field(resolved, dt_l1_pipeline_id_field(), pipeline_id, sizeof pipeline_id);
            if (!cep_l1_pipeline_validate_layout(&pl, pipeline_id[0] ? pipeline_id : NULL)) {
                ok = false;
            }
        }
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_spec_dt(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.flow_pipelines, "flow_spec_l1");
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_spec_ensure(const cepPath* signal, const cepPath* target) {
    (void)signal;
    char pipeline_id[128] = {0};
    cep_l1_pack_target_pipeline_id(target, pipeline_id, sizeof pipeline_id);
    if (!pipeline_id[0]) {
        return CEP_ENZYME_FATAL;
    }

    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.flow_pipelines, "flow_spec_l1");
    }

    cepCell* existing = NULL;
    cepL1PipelineLayout pipeline_layout = {0};
    cepL1PipelineMeta meta = {.owner = "unknown", .province = "default", .version = "v0", .revision = 1u, .max_hops = 0u};
    char owner_buf[128] = {0};
    char prov_buf[128] = {0};
    char ver_buf[128] = {0};
    if (ok && cep_l1_pack_resolve_pipeline(&layout, pipeline_id, &existing, &pipeline_layout)) {
        cep_l1_pack_fill_pipeline_meta_from_cell(existing, &meta, owner_buf, sizeof owner_buf, prov_buf, sizeof prov_buf, ver_buf, sizeof ver_buf);
    }

    if (ok) {
        memset(&pipeline_layout, 0, sizeof pipeline_layout);
        ok = cep_l1_pipeline_ensure(layout.flow_pipelines, pipeline_id, &meta, &pipeline_layout);
    }
    if (ok) {
        ok = cep_l1_pipeline_validate_layout(&pipeline_layout, pipeline_id);
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_spec_normalize(const cepPath* signal, const cepPath* target) {
    (void)signal;
    char pipeline_id[128] = {0};
    cep_l1_pack_target_pipeline_id(target, pipeline_id, sizeof pipeline_id);
    if (!pipeline_id[0]) {
        return CEP_ENZYME_FATAL;
    }

    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    cepL1PipelineLayout pipeline_layout = {0};
    bool ok = cep_l1_schema_ensure(&layout) &&
              cep_l1_pack_resolve_pipeline(&layout, pipeline_id, NULL, &pipeline_layout) &&
              cep_l1_pipeline_validate_layout(&pipeline_layout, pipeline_id);

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_spec_rebuild(const cepPath* signal, const cepPath* target) {
    (void)signal;
    char pipeline_id[128] = {0};
    cep_l1_pack_target_pipeline_id(target, pipeline_id, sizeof pipeline_id);
    bool rebuild_all = pipeline_id[0] == '\0';

    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout) &&
              layout.flow_pipelines &&
              cep_cell_require_dictionary_store(&layout.flow_pipelines);
    if (ok && rebuild_all) {
        for (cepCell* pipeline = cep_cell_first(layout.flow_pipelines); pipeline; pipeline = cep_cell_next(layout.flow_pipelines, pipeline)) {
            cepCell* resolved = cep_cell_resolve(pipeline);
            if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
                ok = false;
                continue;
            }
            cepL1PipelineLayout pipeline_layout = {0};
            (void)cep_l1_pipeline_layout_from_root(resolved, &pipeline_layout);
            char pipeline_buffer[128] = {0};
            (void)cep_l1_pack_copy_text_field(resolved, dt_l1_pipeline_id_field(), pipeline_buffer, sizeof pipeline_buffer);
            if (!cep_l1_pipeline_validate_layout(&pipeline_layout, pipeline_buffer[0] ? pipeline_buffer : NULL) ||
                !cep_l1_pipeline_bind_coherence(&layout, &pipeline_layout)) {
                ok = false;
            }
        }
    } else if (ok) {
        cepL1PipelineLayout pipeline_layout = {0};
        ok = cep_l1_pack_resolve_pipeline(&layout, pipeline_id, NULL, &pipeline_layout) &&
             cep_l1_pipeline_validate_layout(&pipeline_layout, pipeline_id) &&
             cep_l1_pipeline_bind_coherence(&layout, &pipeline_layout);
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_runtime_ct(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.flow_runtime, "flow_runtime_l1");
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_runtime_vl(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout) &&
              layout.flow_runtime && layout.flow_runs && layout.flow_metrics && layout.flow_pipelines &&
              cep_cell_require_dictionary_store(&layout.flow_runtime) &&
              cep_cell_require_dictionary_store(&layout.flow_runs) &&
              cep_cell_require_dictionary_store(&layout.flow_metrics) &&
              cep_cell_require_dictionary_store(&layout.flow_pipelines);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.flow_runtime, "flow_runtime_l1");
        ok = cep_l1_runtime_validate_runs(layout.flow_runs, layout.flow_pipelines) &&
             cep_l1_runtime_verify_edges(layout.flow_runs, layout.flow_pipelines);
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_runtime_dt(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout);
    if (ok) {
        cep_l1_pack_label_organ_root(layout.flow_runtime, "flow_runtime_l1");
    }

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_runtime_gc(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout) &&
              layout.flow_runs &&
              cep_cell_require_dictionary_store(&layout.flow_runs) &&
              cep_l1_runtime_gc_runs(layout.flow_runs);

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_runtime_rollup(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout) &&
              layout.flow_runs && layout.flow_metrics &&
              cep_cell_require_dictionary_store(&layout.flow_runs) &&
              cep_cell_require_dictionary_store(&layout.flow_metrics) &&
              cep_l1_runtime_rollup_metrics(layout.flow_runs, layout.flow_metrics);

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_pack_org_flow_runtime_verify(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return CEP_ENZYME_FATAL;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    bool ok = cep_l1_schema_ensure(&layout) &&
              layout.flow_runs && layout.flow_pipelines &&
              cep_cell_require_dictionary_store(&layout.flow_runs) &&
              cep_cell_require_dictionary_store(&layout.flow_pipelines) &&
              cep_l1_runtime_verify_edges(layout.flow_runs, layout.flow_pipelines);

    cep_runtime_restore_active(previous_scope);
    return ok ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}
