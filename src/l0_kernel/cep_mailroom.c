/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_mailroom.h"

#include "cep_cell.h"

static const cepDT* dt_data_root(void)      { return CEP_DTAW("CEP", "data"); }
static const cepDT* dt_sys_root(void)       { return CEP_DTAW("CEP", "sys"); }
static const cepDT* dt_inbox_root(void)     { return CEP_DTAW("CEP", "inbox"); }
static const cepDT* dt_mailroom_ns_coh(void){ return CEP_DTAW("CEP", "coh"); }
static const cepDT* dt_mailroom_ns_flow(void){ return CEP_DTAW("CEP", "flow"); }
static const cepDT* dt_be_create(void)      { return CEP_DTAW("CEP", "be_create"); }
static const cepDT* dt_bo_upsert(void)      { return CEP_DTAW("CEP", "bo_upsert"); }
static const cepDT* dt_ctx_upsert(void)     { return CEP_DTAW("CEP", "ctx_upsert"); }
static const cepDT* dt_fl_upsert(void)      { return CEP_DTAW("CEP", "fl_upsert"); }
static const cepDT* dt_ni_upsert(void)      { return CEP_DTAW("CEP", "ni_upsert"); }
static const cepDT* dt_inst_start(void)     { return CEP_DTAW("CEP", "inst_start"); }
static const cepDT* dt_inst_event(void)     { return CEP_DTAW("CEP", "inst_event"); }
static const cepDT* dt_inst_ctrl(void)      { return CEP_DTAW("CEP", "inst_ctrl"); }
static const cepDT* dt_err_cat(void)        { return CEP_DTAW("CEP", "err_cat"); }
static const cepDT* dt_sig_cell(void)       { return CEP_DTAW("CEP", "sig_cell"); }
static const cepDT* dt_op_add(void)         { return CEP_DTAW("CEP", "op_add"); }
static const cepDT* dt_mr_route(void)       { return CEP_DTAW("CEP", "mr_route"); }
static const cepDT* dt_coh_ing_be(void)     { return CEP_DTAW("CEP", "coh_ing_be"); }
static const cepDT* dt_coh_ing_bo(void)     { return CEP_DTAW("CEP", "coh_ing_bo"); }
static const cepDT* dt_coh_ing_ctx(void)    { return CEP_DTAW("CEP", "coh_ing_ctx"); }
static const cepDT* dt_fl_ing(void)         { return CEP_DTAW("CEP", "fl_ing"); }
static const cepDT* dt_ni_ing(void)         { return CEP_DTAW("CEP", "ni_ing"); }
static const cepDT* dt_inst_ing(void)       { return CEP_DTAW("CEP", "inst_ing"); }

static bool cep_mailroom_bindings_applied = false;
static cepEnzymeRegistry* cep_mailroom_registered_registry = NULL;

static cepCell* cep_mailroom_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        return existing;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT name_copy = *name;
    return cep_dict_add_dictionary(parent, &name_copy, &dict_type, storage);
}

static bool cep_mailroom_seed_namespace(cepCell* inbox,
                                        const cepDT* ns_name,
                                        const cepDT* const* buckets,
                                        size_t bucket_count) {
    if (!inbox || !ns_name || (bucket_count && !buckets)) {
        return false;
    }

    cepCell* ns_root = cep_mailroom_ensure_dictionary(inbox, ns_name, CEP_STORAGE_RED_BLACK_T);
    if (!ns_root) {
        return false;
    }

    for (size_t i = 0; i < bucket_count; ++i) {
        if (!cep_mailroom_ensure_dictionary(ns_root, buckets[i], CEP_STORAGE_RED_BLACK_T)) {
            return false;
        }
    }

    return true;
}

/* Prepare the unified mailroom branches so producers can target `/data/inbox`
 * while existing layers still receive intents under their traditional inboxes. */
bool cep_mailroom_bootstrap(void) {
    if (!cep_cell_system_initialized()) {
        return false;
    }

    cepCell* root = cep_root();
    if (!root) {
        return false;
    }

    cepCell* data_root = cep_mailroom_ensure_dictionary(root, dt_data_root(), CEP_STORAGE_RED_BLACK_T);
    if (!data_root) {
        return false;
    }

    cepCell* inbox_root = cep_mailroom_ensure_dictionary(data_root, dt_inbox_root(), CEP_STORAGE_RED_BLACK_T);
    if (!inbox_root) {
        return false;
    }

    const cepDT* coh_buckets[] = { dt_be_create(), dt_bo_upsert(), dt_ctx_upsert() };
    if (!cep_mailroom_seed_namespace(inbox_root, dt_mailroom_ns_coh(), coh_buckets, cep_lengthof(coh_buckets))) {
        return false;
    }

    const cepDT* flow_buckets[] = { dt_fl_upsert(), dt_ni_upsert(), dt_inst_start(), dt_inst_event(), dt_inst_ctrl() };
    if (!cep_mailroom_seed_namespace(inbox_root, dt_mailroom_ns_flow(), flow_buckets, cep_lengthof(flow_buckets))) {
        return false;
    }

    cepCell* sys_root = cep_mailroom_ensure_dictionary(root, dt_sys_root(), CEP_STORAGE_RED_BLACK_T);
    if (!sys_root) {
        return false;
    }

    if (!cep_mailroom_ensure_dictionary(sys_root, dt_err_cat(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    return true;
}

static bool cep_mailroom_namespace_supported(const cepCell* ns_node) {
    if (!ns_node) {
        return false;
    }
    return cep_cell_name_is(ns_node, dt_mailroom_ns_coh()) ||
           cep_cell_name_is(ns_node, dt_mailroom_ns_flow());
}

/* Relocate a freshly added intent from `/data/inbox` into the appropriate layer
 * inbox, leaving an audit link behind and annotating provenance so L1/L2 logic
 * observes the request exactly as before the migration. */
static int cep_mailroom_route(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;

    cepCell* txn = cep_cell_find_by_path(cep_root(), target_path);
    if (!txn || !cep_cell_is_normal(txn) || cep_cell_is_link(txn)) {
        return CEP_ENZYME_SUCCESS;
    }

    const cepDT* txn_name_dt = cep_cell_get_name(txn);
    if (!txn_name_dt) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* intent_bucket = cep_cell_parent(txn);
    cepCell* ns_node = intent_bucket ? cep_cell_parent(intent_bucket) : NULL;
    cepCell* inbox_root = ns_node ? cep_cell_parent(ns_node) : NULL;
    cepCell* data_root = inbox_root ? cep_cell_parent(inbox_root) : NULL;

    if (!intent_bucket || !ns_node || !inbox_root || !data_root) {
        return CEP_ENZYME_SUCCESS;
    }

    if (!cep_cell_name_is(inbox_root, dt_inbox_root()) || !cep_cell_name_is(data_root, dt_data_root())) {
        return CEP_ENZYME_SUCCESS;
    }

    if (!cep_mailroom_namespace_supported(ns_node)) {
        return CEP_ENZYME_SUCCESS;
    }

    const cepDT* dest_bucket_name = cep_cell_get_name(intent_bucket);
    if (!dest_bucket_name) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* layer_root = cep_cell_find_by_name(data_root, cep_cell_get_name(ns_node));
    if (!layer_root) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* layer_inbox = cep_cell_find_by_name(layer_root, dt_inbox_root());
    if (!layer_inbox) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* dest_bucket = cep_cell_find_by_name(layer_inbox, dest_bucket_name);
    if (!dest_bucket) {
        return CEP_ENZYME_SUCCESS;
    }

    if (cep_cell_find_by_name(dest_bucket, txn_name_dt)) {
        cep_cell_remove_hard(txn, NULL);
        return CEP_ENZYME_SUCCESS;
    }

    cepCell moved = {0};
    cep_cell_remove_hard(txn, &moved);
    cepCell* inserted = cep_cell_add(dest_bucket, 0, &moved);
    if (!inserted) {
        cep_cell_finalize_hard(&moved);
        return CEP_ENZYME_FATAL;
    }

    cepDT audit_name = *txn_name_dt;
    cepCell* audit_link = cep_dict_add_link(intent_bucket, &audit_name, inserted);
    if (audit_link) {
        cepCell* parents[] = { audit_link };
        (void)cep_cell_add_parents(inserted, parents, cep_lengthof(parents));
    }

    return CEP_ENZYME_SUCCESS;
}

/* Stage the mailroom router on the registry so routing happens before the L1
 * and L2 ingest packs execute, ensuring the unified inbox behaves transparently
 * for existing enzymes. */
bool cep_mailroom_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (!cep_mailroom_bootstrap()) {
        return false;
    }

    if (cep_mailroom_registered_registry == registry) {
        return true;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepPathStatic2;

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    cepDT before_list[] = {
        *dt_coh_ing_be(),
        *dt_coh_ing_bo(),
        *dt_coh_ing_ctx(),
        *dt_fl_ing(),
        *dt_ni_ing(),
        *dt_inst_ing(),
    };

    cepEnzymeDescriptor descriptor = {
        .name = *dt_mr_route(),
        .label = "mailroom.route",
        .before = before_list,
        .before_count = cep_lengthof(before_list),
        .callback = cep_mailroom_route,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    if (cep_enzyme_register(registry, (const cepPath*)&signal_path, &descriptor) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    cep_mailroom_registered_registry = registry;

    if (!cep_mailroom_bindings_applied) {
        cepCell* data_root = cep_cell_find_by_name(cep_root(), dt_data_root());
        cepCell* inbox_root = data_root ? cep_cell_find_by_name(data_root, dt_inbox_root()) : NULL;
        if (inbox_root) {
            (void)cep_cell_bind_enzyme(inbox_root, dt_mr_route(), true);
        }
        cep_mailroom_bindings_applied = true;
    }

    return true;
}
