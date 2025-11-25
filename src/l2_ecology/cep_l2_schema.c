/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_schema.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_branch_controller.h"
#include "../l0_kernel/cep_runtime.h"

CEP_DEFINE_STATIC_DT(dt_eco_schema, CEP_ACRO("CEP"), cep_namepool_intern_cstr("schema"));
CEP_DEFINE_STATIC_DT(dt_eco_species, CEP_ACRO("CEP"), cep_namepool_intern_cstr("species"));
CEP_DEFINE_STATIC_DT(dt_eco_variants, CEP_ACRO("CEP"), cep_namepool_intern_cstr("variants"));
CEP_DEFINE_STATIC_DT(dt_eco_niches, CEP_ACRO("CEP"), cep_namepool_intern_cstr("niches"));
CEP_DEFINE_STATIC_DT(dt_eco_guardians, CEP_ACRO("CEP"), cep_namepool_intern_cstr("guardians"));
CEP_DEFINE_STATIC_DT(dt_eco_flows, CEP_ACRO("CEP"), cep_namepool_intern_cstr("flows"));
CEP_DEFINE_STATIC_DT(dt_eco_runtime, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics, CEP_ACRO("CEP"), cep_namepool_intern_cstr("metrics"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_species, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_species"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_variant, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_variant"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_per_niche, CEP_ACRO("CEP"), cep_namepool_intern_cstr("per_niche"));
CEP_DEFINE_STATIC_DT(dt_eco_metrics_global, CEP_ACRO("CEP"), cep_namepool_intern_cstr("global"));
CEP_DEFINE_STATIC_DT(dt_eco_decisions, CEP_ACRO("CEP"), cep_namepool_intern_cstr("decisions"));
CEP_DEFINE_STATIC_DT(dt_eco_sched, CEP_ACRO("CEP"), cep_namepool_intern_cstr("sched_queue"));
CEP_DEFINE_STATIC_DT(dt_eco_history, CEP_ACRO("CEP"), cep_namepool_intern_cstr("history"));
CEP_DEFINE_STATIC_DT(dt_eco_meta, CEP_ACRO("CEP"), cep_namepool_intern_cstr("meta"));
CEP_DEFINE_STATIC_DT(dt_eco_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("eco"));
CEP_DEFINE_STATIC_DT(dt_learn_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("learn"));
CEP_DEFINE_STATIC_DT(dt_learn_models, CEP_ACRO("CEP"), cep_namepool_intern_cstr("models"));
CEP_DEFINE_STATIC_DT(dt_learn_revisions, CEP_ACRO("CEP"), cep_namepool_intern_cstr("revisions"));
CEP_DEFINE_STATIC_DT(dt_learn_provenance, CEP_ACRO("CEP"), cep_namepool_intern_cstr("provenance"));
CEP_DEFINE_STATIC_DT(dt_meta, CEP_ACRO("CEP"), cep_namepool_intern_cstr("meta"));
CEP_DEFINE_STATIC_DT(dt_state, CEP_ACRO("CEP"), cep_namepool_intern_cstr("state"));

static cepCell* cep_l2_schema_ensure_branch(cepCell* parent, const cepDT* name) {
    cepCell* root = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    return root ? cep_cell_resolve(root) : NULL;
}

static bool cep_l2_schema_seed_metrics(cepCell* metrics_root) {
    if (!metrics_root) {
        return false;
    }
    cepCell* per_species = cep_l2_schema_ensure_branch(metrics_root, dt_eco_metrics_per_species());
    cepCell* per_variant = cep_l2_schema_ensure_branch(metrics_root, dt_eco_metrics_per_variant());
    cepCell* per_niche = cep_l2_schema_ensure_branch(metrics_root, dt_eco_metrics_per_niche());
    cepCell* global = cep_l2_schema_ensure_branch(metrics_root, dt_eco_metrics_global());
    return per_species && per_variant && per_niche && global;
}

static bool cep_l2_schema_seed_eco_children(cepCell* eco_root) {
    cepCell* schema_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_schema());
    cepCell* species_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_species());
    cepCell* variants_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_variants());
    cepCell* niches_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_niches());
    cepCell* guardians_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_guardians());
    cepCell* flows_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_flows());
    cepCell* runtime_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_runtime());
    cepCell* metrics_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_metrics());
    cepCell* decisions_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_decisions());
    cepCell* sched_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_sched());
    cepCell* history_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_history());
    cepCell* meta_root = cep_l2_schema_ensure_branch(eco_root, dt_eco_meta());

    bool metrics_ready = cep_l2_schema_seed_metrics(metrics_root);
    return schema_root && species_root && variants_root && niches_root && guardians_root &&
           flows_root && runtime_root && metrics_root && decisions_root && sched_root &&
           history_root && meta_root && metrics_ready;
}

static bool cep_l2_schema_seed_learn_children(cepCell* learn_root) {
    if (!learn_root) {
        return false;
    }
    cepCell* models_root = cep_l2_schema_ensure_branch(learn_root, dt_learn_models());
    cepCell* revisions_root = cep_l2_schema_ensure_branch(learn_root, dt_learn_revisions());
    cepCell* provenance_root = cep_l2_schema_ensure_branch(learn_root, dt_learn_provenance());
    return models_root && revisions_root && provenance_root;
}

static bool cep_l2_schema_enforce_durable_policy(cepCell* branch_root) {
    if (!branch_root) {
        return false;
    }
    cepBranchController* controller = cep_runtime_track_data_branch(branch_root);
    const cepBranchPersistPolicy* existing_policy = controller ? cep_branch_controller_policy(controller) : NULL;
    if (!controller || !existing_policy) {
        return false;
    }
    cepBranchPersistPolicy durable = *existing_policy;
    durable.mode = CEP_BRANCH_PERSIST_DURABLE;
    durable.flush_on_shutdown = true;
    durable.allow_volatile_reads = false;
    cep_branch_controller_set_policy(controller, &durable);
    return true;
}

bool cep_l2_schema_seed_roots(cepCell* data_root,
                              bool l1_present,
                              cepCell** eco_root_out,
                              cepCell** learn_root_out) {
    (void)l1_present; /* layout is identical regardless of L1 presence; hooks stay optional. */

    if (!data_root) {
        return false;
    }
    cepCell* eco_root = cep_l2_schema_ensure_branch(data_root, dt_eco_root());
    cepCell* learn_root = cep_l2_schema_ensure_branch(data_root, dt_learn_root());
    if (!eco_root || !learn_root) {
        return false;
    }

    if (!cep_l2_schema_seed_eco_children(eco_root)) {
        return false;
    }

    if (!cep_l2_schema_seed_learn_children(learn_root)) {
        return false;
    }

    if (!cep_l2_schema_enforce_durable_policy(eco_root) ||
        !cep_l2_schema_enforce_durable_policy(learn_root)) {
        return false;
    }

    if (eco_root_out) {
        *eco_root_out = eco_root;
    }
    if (learn_root_out) {
        *learn_root_out = learn_root;
    }
    return true;
}

cepCell* cep_l2_schema_state_cell(cepCell* eco_root) {
    if (!eco_root) {
        return NULL;
    }
    cepCell* meta_root = cep_l2_schema_ensure_branch(eco_root, dt_meta());
    if (!meta_root) {
        return NULL;
    }
    return cep_l2_schema_ensure_branch(meta_root, dt_state());
}
