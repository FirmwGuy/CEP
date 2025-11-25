/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_runtime.h"

#include "../l0_kernel/cep_organ.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_branch_controller.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l1_coherence/cep_l1_runtime.h"
#include "../l1_coherence/cep_l1_coherence.h"
#include "cep_l2_flow.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_org_eco_root_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root"));
CEP_DEFINE_STATIC_DT(dt_org_eco_root_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root:vl"));
CEP_DEFINE_STATIC_DT(dt_org_eco_root_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root:ct"));
CEP_DEFINE_STATIC_DT(dt_org_eco_root_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_root:dt"));

CEP_DEFINE_STATIC_DT(dt_org_eco_flows_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows"));
CEP_DEFINE_STATIC_DT(dt_org_eco_flows_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows:vl"));
CEP_DEFINE_STATIC_DT(dt_org_eco_flows_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows:ct"));
CEP_DEFINE_STATIC_DT(dt_org_eco_flows_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_flows:dt"));

CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime"));
CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime:vl"));
CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime:ct"));
CEP_DEFINE_STATIC_DT(dt_org_eco_runtime_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:eco_runtime:dt"));

CEP_DEFINE_STATIC_DT(dt_org_learn_models_store, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models"));
CEP_DEFINE_STATIC_DT(dt_org_learn_models_vl, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models:vl"));
CEP_DEFINE_STATIC_DT(dt_org_learn_models_ct, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models:ct"));
CEP_DEFINE_STATIC_DT(dt_org_learn_models_dt, CEP_ACRO("CEP"), cep_namepool_intern_cstr("org:learn_models:dt"));

CEP_DEFINE_STATIC_DT(dt_runtime_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_runtime_organisms, CEP_ACRO("CEP"), cep_namepool_intern_cstr("organisms"));
CEP_DEFINE_STATIC_DT(dt_runtime_metrics, CEP_ACRO("CEP"), cep_namepool_intern_cstr("metrics"));
CEP_DEFINE_STATIC_DT(dt_runtime_decisions, CEP_ACRO("CEP"), cep_namepool_intern_cstr("decisions"));
CEP_DEFINE_STATIC_DT(dt_runtime_sched, CEP_ACRO("CEP"), cep_namepool_intern_cstr("sched_queue"));
CEP_DEFINE_STATIC_DT(dt_runtime_history, CEP_ACRO("CEP"), cep_namepool_intern_cstr("history"));

CEP_DEFINE_STATIC_DT(dt_l1_flow_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("flow"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_pipelines, CEP_ACRO("CEP"), cep_namepool_intern_cstr("pipelines"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_runtime, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_runs, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runs"));
CEP_DEFINE_STATIC_DT(dt_l1_flow_metrics, CEP_ACRO("CEP"), cep_namepool_intern_cstr("metrics"));

CEP_DEFINE_STATIC_DT(dt_decision_beat_field, CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_decision_risk_field, CEP_ACRO("CEP"), CEP_WORD("risk"));
CEP_DEFINE_STATIC_DT(dt_decision_consumer_field, CEP_ACRO("CEP"), CEP_WORD("consumer"));
CEP_DEFINE_STATIC_DT(dt_decision_source_field, CEP_ACRO("CEP"), CEP_WORD("source"));
CEP_DEFINE_STATIC_DT(dt_decision_pipeline_field, CEP_ACRO("CEP"), CEP_WORD("pipeline"));
CEP_DEFINE_STATIC_DT(dt_decision_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_pipeline_id_field, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_stage_id_field, CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_dag_run_id_field, CEP_ACRO("CEP"), CEP_WORD("dag_run_id"));
CEP_DEFINE_STATIC_DT(dt_hop_index_field, CEP_ACRO("CEP"), CEP_WORD("hop_index"));
CEP_DEFINE_STATIC_DT(dt_species_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("species"));
CEP_DEFINE_STATIC_DT(dt_variant_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("variant"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_species, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_species"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_variant, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_variant"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_niche, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_niche"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_global, CEP_ACRO("CEP"), cep_namepool_intern_cstr("global"));
CEP_DEFINE_STATIC_DT(dt_flow_field, CEP_ACRO("CEP"), CEP_WORD("flow"));
CEP_DEFINE_STATIC_DT(dt_niche_field, CEP_ACRO("CEP"), CEP_WORD("niche"));
CEP_DEFINE_STATIC_DT(dt_status_field, CEP_ACRO("CEP"), CEP_WORD("status"));
CEP_DEFINE_STATIC_DT(dt_node_ptr_field, CEP_ACRO("CEP"), CEP_WORD("node_ptr"));
CEP_DEFINE_STATIC_DT(dt_created_bt_field, CEP_ACRO("CEP"), CEP_WORD("created_bt"));
CEP_DEFINE_STATIC_DT(dt_updated_bt_field, CEP_ACRO("CEP"), CEP_WORD("updated_bt"));
CEP_DEFINE_STATIC_DT(dt_episode_field, CEP_ACRO("CEP"), CEP_WORD("episode"));
CEP_DEFINE_STATIC_DT(dt_learn_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("learn"));
CEP_DEFINE_STATIC_DT(dt_eco_flows_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("flows"));
CEP_DEFINE_STATIC_DT(dt_eco_variants_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("variants"));
CEP_DEFINE_STATIC_DT(dt_l2_op_mode_states, CEP_ACRO("CEP"), CEP_WORD("opm:states"));
CEP_DEFINE_STATIC_DT(dt_org_state_running, CEP_ACRO("CEP"), CEP_WORD("running"));
CEP_DEFINE_STATIC_DT(dt_org_state_waiting, CEP_ACRO("CEP"), CEP_WORD("waiting"));
CEP_DEFINE_STATIC_DT(dt_org_state_finished, CEP_ACRO("CEP"), CEP_WORD("finished"));
CEP_DEFINE_STATIC_DT(dt_org_state_failed, CEP_ACRO("CEP"), CEP_WORD("failed"));
CEP_DEFINE_STATIC_DT(dt_topic_evolution, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco.evolution.proposed"));
CEP_DEFINE_STATIC_DT(dt_sev_info, CEP_ACRO("CEP"), CEP_WORD("sev:info"));

static cepDT cep_l2_runtime_autoid(void) {
    cepDT name = {0};
    name.domain = CEP_ACRO("CEP");
    name.tag = CEP_AUTOID;
    return name;
}

static cepCell* cep_l2_runtime_resolve_child(cepCell* parent, const cepDT* name);
static bool cep_l2_runtime_put_pipeline_block(cepCell* parent, const cepPipelineMetadata* pipeline);

static bool cep_l2_runtime_read_text(cepCell* parent, const cepDT* field, char* buffer, size_t buffer_size) {
    if (!parent || !field || !buffer || buffer_size == 0u) {
        return false;
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
    if (len >= buffer_size) {
        len = buffer_size - 1u;
    }
    memcpy(buffer, text, len);
    buffer[len] = '\0';
    return true;
}

static bool cep_l2_runtime_read_u64(cepCell* parent, const cepDT* field, uint64_t* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&child, &data) || !data || data->size < sizeof(uint64_t)) {
        return false;
    }
    uint64_t value = 0u;
    memcpy(&value, cep_data_payload(data), sizeof value);
    *out = value;
    return true;
}

static bool cep_l2_runtime_read_dt_field(cepCell* parent, const cepDT* field, cepDT* out) {
    if (!parent || !field || !out) {
        return false;
    }
    cepCell* container = cep_cell_find_by_name(parent, field);
    container = container ? cep_cell_resolve(container) : NULL;
    if (!container || !cep_cell_require_dictionary_store(&container)) {
        return false;
    }
    uint64_t domain = 0u;
    uint64_t tag = 0u;
    if (!cep_l2_runtime_read_u64(container, CEP_DTAW("CEP", "domain"), &domain) ||
        !cep_l2_runtime_read_u64(container, CEP_DTAW("CEP", "tag"), &tag)) {
        return false;
    }
    out->domain = (cepID)domain;
    out->tag = (cepID)tag;
    out->glob = 0u;
    return cep_dt_is_valid(out);
}

static cepCell* cep_l2_runtime_metrics_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    if (!runtime_root) {
        return NULL;
    }
    cepCell* metrics_root = cep_l2_runtime_resolve_child(runtime_root, dt_runtime_metrics());
    if (!metrics_root || !cep_cell_require_dictionary_store(&metrics_root)) {
        return NULL;
    }
    return metrics_root;
}

static cepCell* cep_l2_runtime_metrics_bucket(cepCell* metrics_root, const cepDT* bucket_name, const cepDT* id) {
    if (!metrics_root || !bucket_name) {
        return NULL;
    }
    cepCell* bucket = cep_cell_ensure_dictionary_child(metrics_root, bucket_name, CEP_STORAGE_RED_BLACK_T);
    bucket = bucket ? cep_cell_resolve(bucket) : NULL;
    if (!bucket || !cep_cell_require_dictionary_store(&bucket)) {
        return NULL;
    }
    if (!id || !cep_dt_is_valid(id)) {
        return bucket;
    }
    cepCell* entry = cep_cell_ensure_dictionary_child(bucket, id, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return NULL;
    }
    return entry;
}

static void cep_l2_runtime_bump_metric(cepCell* eco_root,
                                       const cepDT* bucket_dt,
                                       const cepDT* id,
                                       const char* metric_tag,
                                       uint64_t delta) {
    if (!eco_root || !metric_tag) {
        return;
    }
    cepCell* metrics_root = cep_l2_runtime_metrics_root(eco_root);
    if (!metrics_root) {
        return;
    }
    cepCell* bucket = cep_l2_runtime_metrics_bucket(metrics_root, bucket_dt, id);
    if (!bucket) {
        return;
    }
    cepID tag = cep_namepool_intern(metric_tag, strlen(metric_tag));
    if (!tag) {
        return;
    }
    cepDT metric_dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = tag,
        .glob = 0u,
    };
    uint64_t current = 0u;
    (void)cep_l2_runtime_read_u64(bucket, &metric_dt, &current);
    (void)cep_cell_put_uint64(bucket, &metric_dt, current + delta);
}

static void cep_l2_runtime_bump_all_metrics(cepCell* eco_root,
                                            const cepDT* species,
                                            const cepDT* variant,
                                            const cepDT* niche,
                                            const char* metric_tag,
                                            uint64_t delta) {
    cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_global(), NULL, metric_tag, delta);
    if (species && cep_dt_is_valid(species)) {
        cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_per_species(), species, metric_tag, delta);
    }
    if (variant && cep_dt_is_valid(variant)) {
        cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_per_variant(), variant, metric_tag, delta);
    }
    if (niche && cep_dt_is_valid(niche)) {
        cep_l2_runtime_bump_metric(eco_root, dt_eco_metrics_per_niche(), niche, metric_tag, delta);
    }
}

static void cep_l2_runtime_emit_evolution(const cepPipelineMetadata* pipeline,
                                          const cepDT* species,
                                          const cepDT* variant) {
    char note[128] = {0};
    const char* species_text = (species && cep_dt_is_valid(species)) ? cep_namepool_lookup(species->tag, NULL) : NULL;
    const char* variant_text = (variant && cep_dt_is_valid(variant)) ? cep_namepool_lookup(variant->tag, NULL) : NULL;
    snprintf(note,
             sizeof note,
             "species=%s variant=%s",
             species_text ? species_text : "<unset>",
             variant_text ? variant_text : "<unset>");
    cepCeiRequest req = {
        .severity = *dt_sev_info(),
        .topic = cep_namepool_lookup(dt_topic_evolution()->tag, NULL),
        .topic_len = 0u,
        .note = note,
        .note_len = 0u,
        .emit_signal = true,
    };
    if (pipeline) {
        req.has_pipeline = true;
        req.pipeline = *pipeline;
    }
    (void)cep_cei_emit(&req);
}

static cepCell* cep_l2_runtime_resolve_child(cepCell* parent, const cepDT* name) {
    cepCell* child = cep_cell_find_by_name(parent, name);
    child = child ? cep_cell_resolve(child) : NULL;
    return child;
}

static cepID cep_l2_runtime_intern_id(const char* text) {
    if (!text || !*text) {
        return 0u;
    }
    return cep_namepool_intern(text, strlen(text));
}

static void cep_l2_runtime_pipeline_from_flow(cepCell* flow_root,
                                              const cepDT* flow_id,
                                              cepPipelineMetadata* pipeline) {
    if (!pipeline) {
        return;
    }
    pipeline->pipeline_id = 0u;
    pipeline->stage_id = 0u;
    pipeline->dag_run_id = 0u;
    pipeline->hop_index = 0u;
    if (flow_id && cep_dt_is_valid(flow_id)) {
        pipeline->pipeline_id = flow_id->tag;
    }
    if (flow_root) {
        char buf[64];
        if (cep_l2_runtime_read_text(flow_root, dt_pipeline_id_field(), buf, sizeof buf)) {
            pipeline->pipeline_id = cep_l2_runtime_intern_id(buf);
        }
        if (cep_l2_runtime_read_text(flow_root, dt_stage_id_field(), buf, sizeof buf)) {
            pipeline->stage_id = cep_l2_runtime_intern_id(buf);
        }
        uint64_t dag_id = 0u;
        if (cep_l2_runtime_read_u64(flow_root, dt_dag_run_id_field(), &dag_id)) {
            pipeline->dag_run_id = dag_id;
        }
        uint64_t hop = 0u;
        if (cep_l2_runtime_read_u64(flow_root, dt_hop_index_field(), &hop)) {
            pipeline->hop_index = hop;
        }
    }
}

static void cep_l2_runtime_pipeline_from_run(cepCell* run_root, cepPipelineMetadata* pipeline) {
    if (!pipeline) {
        return;
    }
    pipeline->pipeline_id = 0u;
    pipeline->stage_id = 0u;
    pipeline->dag_run_id = 0u;
    pipeline->hop_index = 0u;
    if (!run_root) {
        return;
    }
    char buf[64];
    if (cep_l2_runtime_read_text(run_root, dt_pipeline_id_field(), buf, sizeof buf)) {
        pipeline->pipeline_id = cep_l2_runtime_intern_id(buf);
    }
    if (cep_l2_runtime_read_text(run_root, dt_stage_id_field(), buf, sizeof buf)) {
        pipeline->stage_id = cep_l2_runtime_intern_id(buf);
    }
    uint64_t dag_id = 0u;
    if (cep_l2_runtime_read_u64(run_root, dt_dag_run_id_field(), &dag_id)) {
        pipeline->dag_run_id = dag_id;
    }
    uint64_t hop = 0u;
    if (cep_l2_runtime_read_u64(run_root, dt_hop_index_field(), &hop)) {
        pipeline->hop_index = hop;
    }
}

static cepDT cep_l2_runtime_choose_species(cepCell* flow_root, const cepDT* flow_id) {
    cepDT species = {0};
    char buf[64];
    if (flow_root && cep_l2_runtime_read_text(flow_root, dt_species_field(), buf, sizeof buf)) {
        cepID tag = cep_l2_runtime_intern_id(buf);
        if (tag) {
            species.domain = CEP_ACRO("CEP");
            species.tag = tag;
        }
    }
    if (!cep_dt_is_valid(&species) && flow_id && cep_dt_is_valid(flow_id)) {
        species = *flow_id;
    }
    return species;
}

static cepDT cep_l2_runtime_choose_variant(cepCell* eco_root, cepCell* flow_root) {
    cepDT variant = {0};
    char buf[64];
    if (flow_root && cep_l2_runtime_read_text(flow_root, dt_variant_field(), buf, sizeof buf)) {
        cepID tag = cep_l2_runtime_intern_id(buf);
        if (tag) {
            variant.domain = CEP_ACRO("CEP");
            variant.tag = tag;
        }
    }
    if (cep_dt_is_valid(&variant)) {
        return variant;
    }
    cepCell* variants_root = cep_l2_runtime_resolve_child(eco_root, dt_eco_variants_root());
    if (variants_root && cep_cell_require_dictionary_store(&variants_root)) {
        cepCell* first = cep_cell_first(variants_root);
        if (first) {
            variant = first->metacell.dt;
            variant.glob = 0u;
        }
    }
    return variant;
}

static cepOID cep_l2_runtime_start_episode(const cepPipelineMetadata* pipeline) {
    cepOID eid = cep_op_start(*CEP_DTAW("CEP", "op/ep"),
                              "/data/eco/runtime/organisms",
                              *dt_l2_op_mode_states(),
                              NULL,
                              0u,
                              0u);
    if (cep_oid_is_valid(eid) && pipeline) {
        (void)cep_op_set_pipeline_metadata(eid, pipeline);
    }
    return eid;
}

static void cep_l2_runtime_store_episode(cepCell* organism, cepOID oid) {
    if (!organism || !cep_oid_is_valid(oid)) {
        return;
    }
    cepCell* ep = cep_cell_ensure_dictionary_child(organism, dt_episode_field(), CEP_STORAGE_RED_BLACK_T);
    ep = ep ? cep_cell_resolve(ep) : NULL;
    if (!ep || !cep_cell_require_dictionary_store(&ep)) {
        return;
    }
    (void)cep_cell_put_uint64(ep, CEP_DTAW("CEP", "domain"), cep_id(oid.domain));
    (void)cep_cell_put_uint64(ep, CEP_DTAW("CEP", "tag"), cep_id(oid.tag));
}

static bool cep_l2_runtime_prepare_context(cepCell* eco_root,
                                           cepCell* learn_root,
                                           cepCell* organisms_root,
                                           cepCell* flow_root,
                                           const cepDT* flow_id,
                                           const cepPipelineMetadata* pipeline,
                                           cepL2OrganismContext* ctx_out,
                                           bool* out_new) {
    if (!eco_root || !organisms_root || !flow_root || !flow_id || !ctx_out) {
        return false;
    }
    cepDT organism_id = *flow_id;
    bool new_org = false;
    cepCell* existing = cep_cell_find_by_name(organisms_root, &organism_id);
    cepCell* organism = existing ? cep_cell_resolve(existing)
                                 : cep_cell_add_dictionary(organisms_root,
                                                            &organism_id,
                                                            0u,
                                                            CEP_DTAW("CEP", "dictionary"),
                                                            CEP_STORAGE_RED_BLACK_T);
    organism = organism ? cep_cell_resolve(organism) : NULL;
    if (!organism || !cep_cell_require_dictionary_store(&organism)) {
        return false;
    }
    if (!existing) {
        new_org = true;
        uint64_t beat = (uint64_t)cep_beat_index();
        (void)cep_cell_put_uint64(organism, dt_created_bt_field(), beat);
        (void)cep_cell_put_dt(organism, dt_status_field(), dt_org_state_running());
        (void)cep_cell_put_dt(organism, dt_flow_field(), flow_id);
        cepDT species = cep_l2_runtime_choose_species(flow_root, flow_id);
        if (cep_dt_is_valid(&species)) {
            (void)cep_cell_put_dt(organism, dt_species_field(), &species);
        }
        cepDT variant = cep_l2_runtime_choose_variant(eco_root, flow_root);
        if (cep_dt_is_valid(&variant)) {
            (void)cep_cell_put_dt(organism, dt_variant_field(), &variant);
        }
        char niche_buf[64];
        if (cep_l2_runtime_read_text(flow_root, dt_niche_field(), niche_buf, sizeof niche_buf)) {
            cepID niche_id = cep_l2_runtime_intern_id(niche_buf);
            if (niche_id) {
                cepDT niche = {.domain = CEP_ACRO("CEP"), .tag = niche_id, .glob = 0u};
                (void)cep_cell_put_dt(organism, dt_niche_field(), &niche);
            }
        }
        (void)cep_l2_runtime_put_pipeline_block(organism, pipeline);
        cepOID episode = cep_l2_runtime_start_episode(pipeline);
        if (cep_oid_is_valid(episode)) {
            cep_l2_runtime_store_episode(organism, episode);
        }
    }

    memset(ctx_out, 0, sizeof(*ctx_out));
    ctx_out->eco_root = eco_root;
    ctx_out->learn_root = learn_root;
    ctx_out->organism_root = organisms_root;
    ctx_out->organism = organism;
    ctx_out->organism_id = organism_id;
    ctx_out->flow_root = flow_root;
    ctx_out->flow_id = *flow_id;
    ctx_out->pipeline = pipeline ? *pipeline : (cepPipelineMetadata){0};
    cepDT species_id = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_species_field(), &species_id)) {
        ctx_out->species_id = species_id;
    }
    cepDT variant_id = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_variant_field(), &variant_id)) {
        ctx_out->variant_id = variant_id;
    }
    cepDT niche_id = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_niche_field(), &niche_id)) {
        ctx_out->niche_id = niche_id;
    }
    cepDT node_ptr = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_node_ptr_field(), &node_ptr)) {
        ctx_out->current_node = node_ptr;
    }
    cepDT ep_dt = {0};
    if (cep_l2_runtime_read_dt_field(organism, dt_episode_field(), &ep_dt)) {
        ctx_out->episode_oid.domain = ep_dt.domain;
        ctx_out->episode_oid.tag = ep_dt.tag;
    }
    uint64_t created_bt = 0u;
    if (cep_l2_runtime_read_u64(organism, dt_created_bt_field(), &created_bt)) {
        ctx_out->created_beat = created_bt;
    }
    if (out_new) {
        *out_new = new_org;
    }
    return true;
}

static bool cep_l2_runtime_step_flow(cepCell* eco_root,
                                     cepCell* learn_root,
                                     cepCell* organisms_root,
                                     cepCell* flow_root,
                                     const cepDT* flow_id,
                                     const cepPipelineMetadata* pipeline,
                                     size_t step_budget) {
    cepL2OrganismContext ctx = {0};
    bool new_org = false;
    if (!cep_l2_runtime_prepare_context(eco_root, learn_root, organisms_root, flow_root, flow_id, pipeline, &ctx, &new_org)) {
        return false;
    }
    if (new_org) {
        cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_started", 1u);
        cep_l2_runtime_emit_evolution(pipeline, &ctx.species_id, &ctx.variant_id);
    }

    bool progressed = cep_l2_flow_step(&ctx, step_budget);
    if (progressed) {
        cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "flow_steps", 1u);
    }

    switch (ctx.status) {
        case CEP_L2_ORG_FINISHED:
            cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_finished", 1u);
            break;
        case CEP_L2_ORG_FAILED:
            cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_failed", 1u);
            break;
        case CEP_L2_ORG_WAITING:
            cep_l2_runtime_bump_all_metrics(eco_root, &ctx.species_id, &ctx.variant_id, &ctx.niche_id, "org_waiting", 1u);
            break;
        default:
            break;
    }
    return progressed;
}

static bool cep_l2_runtime_seed_metrics_branches(cepCell* metrics_root) {
    if (!metrics_root) {
        return false;
    }
    cepCell* per_species = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_per_species(), CEP_STORAGE_RED_BLACK_T);
    cepCell* per_variant = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_per_variant(), CEP_STORAGE_RED_BLACK_T);
    cepCell* per_niche = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_per_niche(), CEP_STORAGE_RED_BLACK_T);
    cepCell* global = cep_cell_ensure_dictionary_child(metrics_root, dt_eco_metrics_global(), CEP_STORAGE_RED_BLACK_T);
    return per_species && per_variant && per_niche && global;
}

static bool cep_l2_runtime_put_pipeline_block(cepCell* parent, const cepPipelineMetadata* pipeline) {
    if (!parent || !pipeline) {
        return true;
    }
    cepCell* pipeline_root = cep_cell_ensure_dictionary_child(parent, dt_decision_pipeline_field(), CEP_STORAGE_RED_BLACK_T);
    pipeline_root = pipeline_root ? cep_cell_resolve(pipeline_root) : NULL;
    if (!pipeline_root) {
        return false;
    }
    bool ok = true;
    if (pipeline->pipeline_id) {
        const char* text = cep_namepool_lookup(pipeline->pipeline_id, NULL);
        if (text) {
            ok &= cep_cell_put_text(pipeline_root, dt_pipeline_id_field(), text);
        }
    }
    if (pipeline->stage_id) {
        const char* text = cep_namepool_lookup(pipeline->stage_id, NULL);
        if (text) {
            ok &= cep_cell_put_text(pipeline_root, dt_stage_id_field(), text);
        }
    }
    if (pipeline->dag_run_id) {
        ok &= cep_cell_put_uint64(pipeline_root, dt_dag_run_id_field(), pipeline->dag_run_id);
    }
    if (pipeline->hop_index) {
        ok &= cep_cell_put_uint64(pipeline_root, dt_hop_index_field(), pipeline->hop_index);
    }
    return ok;
}

static cepCell* cep_l2_runtime_history_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    if (runtime_root) {
        cepCell* history = cep_l2_runtime_resolve_child(runtime_root, dt_runtime_history());
        if (history) {
            return history;
        }
    }
    return NULL;
}

static cepCell* cep_l2_runtime_decisions_root(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    if (!runtime_root) {
        return NULL;
    }
    return cep_l2_runtime_resolve_child(runtime_root, dt_runtime_decisions());
}

static bool cep_l2_runtime_log_decision(cepCell* decisions_root,
                                        const cepPipelineMetadata* pipeline,
                                        const cepDT* species_id,
                                        const cepDT* variant_id,
                                        const char* risk_label,
                                        const cepBranchController* consumer,
                                        const cepBranchController* source,
                                        bool decision_recorded) {
    if (!decisions_root || !risk_label || !consumer || !source) {
        return false;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT entry_name = cep_l2_runtime_autoid();
    cepCell* entry = cep_cell_add_dictionary(decisions_root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    bool ok = true;
    ok &= cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
    ok &= cep_cell_put_text(entry, dt_decision_risk_field(), risk_label);
    ok &= cep_cell_put_dt(entry, dt_decision_consumer_field(), &consumer->branch_dt);
    ok &= cep_cell_put_dt(entry, dt_decision_source_field(), &source->branch_dt);
    ok &= cep_l2_runtime_put_pipeline_block(entry, pipeline);
    if (species_id && cep_dt_is_valid(species_id)) {
        ok &= cep_cell_put_dt(entry, dt_species_field(), species_id);
    }
    if (variant_id && cep_dt_is_valid(variant_id)) {
        ok &= cep_cell_put_dt(entry, dt_variant_field(), variant_id);
    }

    char note[64];
    snprintf(note,
             sizeof note,
             "decision_recorded=%s",
             decision_recorded ? "true" : "false");
    ok &= cep_cell_put_text(entry, dt_decision_note_field(), note);
    return ok;
}


/* Registers L2 organ descriptors so pack-owned roots can attach constructors
 * and validators; keeps registration idempotent to mirror other packs. */
bool cep_l2_runtime_register_organs(void) {
    cepOrganDescriptor organs[] = {
        {
            .kind = "eco_root",
            .label = "L2 ecology root organ",
            .store = *dt_org_eco_root_store(),
            .validator = *dt_org_eco_root_vl(),
            .constructor = *dt_org_eco_root_ct(),
            .destructor = *dt_org_eco_root_dt(),
        },
        {
            .kind = "eco_flows",
            .label = "L2 flows organ",
            .store = *dt_org_eco_flows_store(),
            .validator = *dt_org_eco_flows_vl(),
            .constructor = *dt_org_eco_flows_ct(),
            .destructor = *dt_org_eco_flows_dt(),
        },
        {
            .kind = "eco_runtime",
            .label = "L2 runtime organ",
            .store = *dt_org_eco_runtime_store(),
            .validator = *dt_org_eco_runtime_vl(),
            .constructor = *dt_org_eco_runtime_ct(),
            .destructor = *dt_org_eco_runtime_dt(),
        },
        {
            .kind = "learn_models",
            .label = "L2 learning organ",
            .store = *dt_org_learn_models_store(),
            .validator = *dt_org_learn_models_vl(),
            .constructor = *dt_org_learn_models_ct(),
            .destructor = *dt_org_learn_models_dt(),
        },
    };

    const size_t organ_count = sizeof organs / sizeof organs[0];
    for (size_t i = 0; i < organ_count; ++i) {
        if (!cep_organ_register(&organs[i])) {
            return false;
        }
    }

    return true;
}

/* Seeds runtime subtrees to host organisms, metrics, decisions, and queues so
 * scheduler and Flow VM wiring can attach without chasing missing nodes. */
bool cep_l2_runtime_seed_runtime(cepCell* eco_root) {
    if (!eco_root) {
        return false;
    }

    cepCell* runtime_root = cep_cell_ensure_dictionary_child(eco_root, dt_runtime_root(), CEP_STORAGE_RED_BLACK_T);
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    if (!runtime_root) {
        return false;
    }

    cepCell* organisms = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_organisms(), CEP_STORAGE_RED_BLACK_T);
    cepCell* metrics = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_metrics(), CEP_STORAGE_RED_BLACK_T);
    cepCell* decisions = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_decisions(), CEP_STORAGE_RED_BLACK_T);
    cepCell* sched = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_sched(), CEP_STORAGE_RED_BLACK_T);
    cepCell* history = cep_cell_ensure_dictionary_child(runtime_root, dt_runtime_history(), CEP_STORAGE_RED_BLACK_T);
    bool metrics_ready = cep_l2_runtime_seed_metrics_branches(metrics);

    return organisms && metrics && decisions && sched && history && metrics_ready;
}

/* TODO: replace stub with trigger scanning and organism creation once the Flow
 * VM and scheduler inputs are connected. */
bool cep_l2_runtime_scheduler_pump(cepCell* eco_root, bool l1_present) {
    if (!eco_root) {
        return false;
    }

    cepCell* data_root = cep_cell_parent(eco_root);
    cepCell* learn_root = data_root ? cep_l2_runtime_resolve_child(data_root, dt_learn_root()) : NULL;
    cepCell* runtime_root = cep_l2_runtime_resolve_child(eco_root, dt_runtime_root());
    cepCell* organisms_root = runtime_root ? cep_l2_runtime_resolve_child(runtime_root, dt_runtime_organisms()) : NULL;
    cepCell* flows_root = cep_l2_runtime_resolve_child(eco_root, dt_eco_flows_root());

    cepCell* runs_root = NULL;
    cepCell* pipelines_root = NULL;
    cepCell* l1_metrics_root = NULL;
    if (l1_present) {
        cepCell* flow_root = data_root ? cep_l2_runtime_resolve_child(data_root, dt_l1_flow_root()) : NULL;
        if (flow_root) {
            pipelines_root = cep_l2_runtime_resolve_child(flow_root, dt_l1_flow_pipelines());
            cepCell* flow_runtime = cep_l2_runtime_resolve_child(flow_root, dt_l1_flow_runtime());
            runs_root = flow_runtime ? cep_l2_runtime_resolve_child(flow_runtime, dt_l1_flow_runs()) : NULL;
            l1_metrics_root = flow_root ? cep_l2_runtime_resolve_child(flow_root, dt_l1_flow_metrics()) : NULL;
            if (runs_root) {
                (void)cep_l1_runtime_gc_runs(runs_root);
                if (pipelines_root) {
                    (void)cep_l1_runtime_verify_edges(runs_root, pipelines_root);
                }
                if (l1_metrics_root) {
                    (void)cep_l1_runtime_rollup_metrics(runs_root, l1_metrics_root);
                }
            }
        }
    }

    if (!flows_root || !organisms_root) {
        return false;
    }

    bool ok = true;
    const size_t step_budget = 4u;
    cepCell* first_run = runs_root ? cep_cell_first(runs_root) : NULL;
    for (cepCell* flow = cep_cell_first(flows_root); flow; flow = cep_cell_next(flows_root, flow)) {
        cepCell* resolved = cep_cell_resolve(flow);
        if (!resolved) {
            continue;
        }
        cepDT flow_id = flow->metacell.dt;
        flow_id.glob = 0u;
        cepPipelineMetadata pipeline = {0};
        cep_l2_runtime_pipeline_from_flow(resolved, &flow_id, &pipeline);
        if (first_run) {
            cep_l2_runtime_pipeline_from_run(first_run, &pipeline);
        }
        if (!cep_l2_runtime_step_flow(eco_root, learn_root, organisms_root, resolved, &flow_id, &pipeline, step_budget)) {
            ok = false;
        }
    }

    return ok;
}

/* Appends a history entry under `/data/eco/runtime/history` capturing pipeline
 * metadata and ecological context so organism progress stays append-only and
 * replayable. The helper is best-effort: it returns false when the history
 * branch cannot be resolved but does not emit CEI. */
bool cep_l2_runtime_record_history(cepCell* eco_root,
                                   const cepPipelineMetadata* pipeline,
                                   const cepDT* species_id,
                                   const cepDT* variant_id,
                                   const char* note) {
    if (!eco_root) {
        return false;
    }
    cepCell* history_root = cep_l2_runtime_history_root(eco_root);
    if (!history_root) {
        return false;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT entry_name = cep_l2_runtime_autoid();
    cepCell* entry = cep_cell_add_dictionary(history_root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    bool ok = true;
    ok &= cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
    ok &= cep_l2_runtime_put_pipeline_block(entry, pipeline);
    if (species_id && cep_dt_is_valid(species_id)) {
        ok &= cep_cell_put_dt(entry, dt_species_field(), species_id);
    }
    if (variant_id && cep_dt_is_valid(variant_id)) {
        ok &= cep_cell_put_dt(entry, dt_variant_field(), variant_id);
    }
    if (note && note[0]) {
        ok &= cep_cell_put_text(entry, dt_decision_note_field(), note);
    }
    return ok;
}

/* Hydrates a cell for L2 flows with cross-branch policy enforcement and records
 * ecological context alongside Decision Cells when cross-branch reads occur.
 * The helper wraps the standard hydrate API but always enables cross-branch
 * allowance after running `cep_cell_svo_context_guard` so replay evidence is
 * preserved without double-recording decision entries. */
cepHydrateStatus cep_l2_runtime_hydrate_for_enzyme(cepCell* eco_root,
                                                   cep_cell_ref_t* ref,
                                                   const cepEnzymeContext* enz_ctx,
                                                   const cep_hydrate_opts_t* opts,
                                                   const cepPipelineMetadata* pipeline,
                                                   const cepDT* species_id,
                                                   const cepDT* variant_id) {
    if (!eco_root || !ref || !ref->cell) {
        return CEP_HYDRATE_STATUS_INVALID_ARGUMENT;
    }

    cepCellSvoContext guard_ctx;
    cep_cell_svo_context_init(&guard_ctx, "eco.hydrate");
    cep_cell_svo_context_set_consumer(&guard_ctx, eco_root);
    cep_cell_svo_context_set_source(&guard_ctx, ref->cell);

    if (!cep_cell_svo_context_guard(&guard_ctx, ref->cell, "cell.cross_read")) {
        return CEP_HYDRATE_STATUS_POLICY;
    }

    cep_hydrate_opts_t adjusted = {
        .view = CEP_HYDRATE_VIEW_LIVE,
        .allow_cross_branch = true,
        .require_decision_cell = false,
        .max_depth = 0u,
        .max_meta_bytes = 0u,
        .max_payload_bytes = 0u,
        .lock_ancestors_ro = false,
        .hydrate_children = false,
        .hydrate_payload = true,
    };
    if (opts) {
        adjusted = *opts;
        adjusted.allow_cross_branch = true;
        adjusted.require_decision_cell = false;
    }

    bool used_l1 = false;
    cepHydrateStatus status = CEP_HYDRATE_STATUS_OK;
    if (adjusted.allow_cross_branch || adjusted.view == CEP_HYDRATE_VIEW_SNAPSHOT_RO) {
        bool snapshot_only = (adjusted.view == CEP_HYDRATE_VIEW_SNAPSHOT_RO);
        if (cep_l1_coh_hydrate_safe(ref, enz_ctx, adjusted.allow_cross_branch, snapshot_only)) {
            used_l1 = true;
            status = CEP_HYDRATE_STATUS_OK;
        }
    }

    if (!used_l1) {
        cep_hydrate_result_t result = {0};
        status = cep_cell_hydrate_for_enzyme(ref, enz_ctx, &adjusted, &result);
        if (status != CEP_HYDRATE_STATUS_OK) {
            return status;
        }
    }

    const char* risk_label = cep_branch_policy_risk_label(guard_ctx.last_result.risk);
    if (!risk_label) {
        risk_label = "none";
    }
    cepCell* decisions_root = cep_l2_runtime_decisions_root(eco_root);
    if (decisions_root) {
        const cepBranchController* consumer = guard_ctx.consumer ? guard_ctx.consumer : guard_ctx.source;
        const cepBranchController* source = guard_ctx.source ? guard_ctx.source : guard_ctx.consumer;
        if (consumer && source) {
            (void)cep_l2_runtime_log_decision(decisions_root,
                                              pipeline,
                                              species_id,
                                              variant_id,
                                              risk_label,
                                              consumer,
                                              source,
                                              guard_ctx.decision_recorded);
        }
    }

    return status;
}
