/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_coherence.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/*  Domain and canonical tags                                                */
/* ------------------------------------------------------------------------- */

static cepID cep_domain_cep(void) {
    return CEP_ACRO("CEP");
}

static const cepDT* dt_dictionary(void)  { return CEP_DTAW("CEP", "dictionary"); }
static const cepDT* dt_text(void)        { return CEP_DTAW("CEP", "text"); }
static const cepDT* dt_kind(void)        { return CEP_DTAW("CEP", "kind"); }
static const cepDT* dt_type(void)        { return CEP_DTAW("CEP", "type"); }
static const cepDT* dt_roles(void)       { return CEP_DTAW("CEP", "roles"); }
static const cepDT* dt_facets(void)      { return CEP_DTAW("CEP", "facets"); }
static const cepDT* dt_src(void)         { return CEP_DTAW("CEP", "src"); }
static const cepDT* dt_dst(void)         { return CEP_DTAW("CEP", "dst"); }
static const cepDT* dt_directed(void)    { return CEP_DTAW("CEP", "directed"); }
static const cepDT* dt_inbox(void)       { return CEP_DTAW("CEP", "inbox"); }
static const cepDT* dt_be_create(void)   { return CEP_DTAW("CEP", "be_create"); }
static const cepDT* dt_bo_upsert(void)   { return CEP_DTAW("CEP", "bo_upsert"); }
static const cepDT* dt_ctx_upsert(void)  { return CEP_DTAW("CEP", "ctx_upsert"); }
static const cepDT* dt_being(void)       { return CEP_DTAW("CEP", "being"); }
static const cepDT* dt_bond(void)        { return CEP_DTAW("CEP", "bond"); }
static const cepDT* dt_context(void)     { return CEP_DTAW("CEP", "context"); }
static const cepDT* dt_facet_root(void)  { return CEP_DTAW("CEP", "facet"); }
static const cepDT* dt_debt(void)        { return CEP_DTAW("CEP", "debt"); }
static const cepDT* dt_index(void)       { return CEP_DTAW("CEP", "index"); }
static const cepDT* dt_coh(void)         { return CEP_DTAW("CEP", "coh"); }
static const cepDT* dt_data_root(void)   { return CEP_DTAW("CEP", "data"); }
static const cepDT* dt_tmp(void)         { return CEP_DTAW("CEP", "tmp"); }
static const cepDT* dt_adj(void)         { return CEP_DTAW("CEP", "adj"); }
static const cepDT* dt_by_being(void)    { return CEP_DTAW("CEP", "by_being"); }
static const cepDT* dt_signal_cell(void) { return CEP_DTAW("CEP", "sig_cell"); }
static const cepDT* dt_op_add(void)      { return CEP_DTAW("CEP", "op_add"); }
static const cepDT* dt_coh_ing_be(void)  { return CEP_DTAW("CEP", "coh_ing_be"); }
static const cepDT* dt_coh_ing_bo(void)  { return CEP_DTAW("CEP", "coh_ing_bo"); }
static const cepDT* dt_coh_ing_ctx(void) { return CEP_DTAW("CEP", "coh_ing_ctx"); }
static const cepDT* dt_coh_closure(void) { return CEP_DTAW("CEP", "coh_closure"); }
static const cepDT* dt_coh_index(void)   { return CEP_DTAW("CEP", "coh_index"); }
static const cepDT* dt_coh_adj(void)     { return CEP_DTAW("CEP", "coh_adj"); }
static const cepDT* dt_be_kind(void)     { return CEP_DTAW("CEP", "be_kind"); }
static const cepDT* dt_bo_pair(void)     { return CEP_DTAW("CEP", "bo_pair"); }
static const cepDT* dt_ctx_type(void)    { return CEP_DTAW("CEP", "ctx_type"); }
static const cepDT* dt_fa_ctx(void)      { return CEP_DTAW("CEP", "fa_ctx"); }
static const cepDT* dt_id(void)          { return CEP_DTAW("CEP", "id"); }
static const cepDT* dt_outcome(void)     { return CEP_DTAW("CEP", "outcome"); }
static const cepDT* dt_out_bonds(void)   { return CEP_DTAW("CEP", "out_bonds"); }
static const cepDT* dt_in_bonds(void)    { return CEP_DTAW("CEP", "in_bonds"); }
static const cepDT* dt_ctx_by_role(void) { return CEP_DTAW("CEP", "ctx_by_role"); }
static const cepDT* dt_required(void)    { return CEP_DTAW("CEP", "required"); }

static bool cep_l1_dt_to_text(const cepDT* dt, char* buffer, size_t cap);

/* ------------------------------------------------------------------------- */
/*  Small helpers                                                            */
/* ------------------------------------------------------------------------- */

static bool cep_l1_copy_string(const cepCell* value_cell, char* buffer, size_t cap) {
    if (!value_cell || !buffer || !cap) {
        return false;
    }

    if (!cep_cell_has_data(value_cell)) {
        return false;
    }

    const cepData* data = value_cell->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return false;
    }

    size_t copy = data->size;
    if (copy >= cap) {
        copy = cap - 1u;
    }
    memcpy(buffer, data->value, copy);
    buffer[copy] = '\0';
    return true;
}

static bool cep_l1_word_dt(const char* text, cepDT* out) {
    if (!text || !out) {
        return false;
    }

    cepID tag = cep_text_to_word(text);
    if (!tag) {
        return false;
    }

    out->domain = cep_domain_cep();
    out->tag = tag;
    return true;
}

static bool cep_l1_set_value_bytes(cepCell* parent, const cepDT* name, const cepDT* type, const void* bytes, size_t size) {
    if (!parent || !name || !type || (!bytes && size)) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing && cep_cell_has_data(existing)) {
        const cepData* data = existing->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size == size && (!size || memcmp(data->value, bytes, size) == 0)) {
            return true;
        }

        cep_cell_update(existing, size, size, (void*)bytes, false);
        cep_cell_content_hash(existing);
        return true;
    }

    cepDT type_copy = *type;
    cepDT name_copy = *name;
    void* payload = (void*)bytes;
    cepCell* value = cep_dict_add_value(parent, &name_copy, &type_copy, payload, size, size);
    if (!value) {
        return false;
    }
    cep_cell_content_hash(value);
    return true;
}

static bool cep_l1_set_string_value(cepCell* parent, const cepDT* name, const char* text) {
    return cep_l1_set_value_bytes(parent, name, dt_text(), text, strlen(text) + 1u);
}

static bool cep_l1_set_bool_value(cepCell* parent, const cepDT* name, bool flag) {
    uint8_t payload = flag ? 1u : 0u;
    return cep_l1_set_value_bytes(parent, name, dt_text(), &payload, sizeof payload);
}

static cepCell* cep_l1_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        return existing;
    }

    cepDT type = *dt_dictionary();
    cepDT name_copy = *name;
    return cep_dict_add_dictionary(parent, &name_copy, &type, storage);
}

static void cep_l1_clear_children(cepCell* cell) {
    if (!cell || !cep_cell_has_store(cell)) {
        return;
    }

    bool writable = cell->store->writable;
    cell->store->writable = true;
    cep_store_delete_children_hard(cell->store);
    cell->store->writable = writable;
}

static void cep_l1_mark_outcome_ok(cepCell* request) {
    if (!request) {
        return;
    }

    cep_l1_set_string_value(request, dt_outcome(), "ok");
}

static void cep_l1_attach_request_parent(cepCell* target, cepCell* request) {
    if (!target || !request) {
        return;
    }

    cepCell* parents[1] = { request };
    cep_cell_add_parents(target, parents, 1u);
}

/* ------------------------------------------------------------------------- */
/*  Bootstrap                                                                */
/* ------------------------------------------------------------------------- */

static cepCell* cep_l1_data_root(void) {
    cepCell* root = cep_root();
    cepCell* data = cep_cell_find_by_name(root, dt_data_root());
    if (!data) {
        data = cep_l1_ensure_dictionary(root, dt_data_root(), CEP_STORAGE_RED_BLACK_T);
    }
    return data;
}

static cepCell* cep_l1_coh_root_cell(void) {
    cepCell* data = cep_l1_data_root();
    if (!data) {
        return NULL;
    }
    return cep_l1_ensure_dictionary(data, dt_coh(), CEP_STORAGE_RED_BLACK_T);
}

static bool cep_l1_bootstrap_indexes(cepCell* coh) {
    cepCell* index = cep_l1_ensure_dictionary(coh, dt_index(), CEP_STORAGE_RED_BLACK_T);
    if (!index) {
        return false;
    }

    if (!cep_l1_ensure_dictionary(index, dt_be_kind(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(index, dt_bo_pair(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(index, dt_ctx_type(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(index, dt_fa_ctx(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    return true;
}

static bool cep_l1_bootstrap_inbox(cepCell* coh) {
    cepCell* inbox = cep_l1_ensure_dictionary(coh, dt_inbox(), CEP_STORAGE_RED_BLACK_T);
    if (!inbox) {
        return false;
    }

    if (!cep_l1_ensure_dictionary(inbox, dt_be_create(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(inbox, dt_bo_upsert(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(inbox, dt_ctx_upsert(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    return true;
}

static bool cep_l1_bootstrap_tmp(void) {
    cepCell* root = cep_root();
    cepCell* tmp = cep_cell_find_by_name(root, dt_tmp());
    if (!tmp) {
        tmp = cep_l1_ensure_dictionary(root, dt_tmp(), CEP_STORAGE_RED_BLACK_T);
    }
    if (!tmp) {
        return false;
    }

    cepCell* coh_tmp = cep_l1_ensure_dictionary(tmp, dt_coh(), CEP_STORAGE_RED_BLACK_T);
    if (!coh_tmp) {
        return false;
    }

    cepCell* adj = cep_l1_ensure_dictionary(coh_tmp, dt_adj(), CEP_STORAGE_RED_BLACK_T);
    if (!adj) {
        return false;
    }

    if (!cep_l1_ensure_dictionary(adj, dt_by_being(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    return true;
}

bool cep_l1_coherence_bootstrap(void) {
    if (!cep_cell_system_initialized()) {
        return false;
    }

    cepCell* coh = cep_l1_coh_root_cell();
    if (!coh) {
        return false;
    }

    if (!cep_l1_ensure_dictionary(coh, dt_being(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(coh, dt_bond(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(coh, dt_context(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(coh, dt_facet_root(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l1_ensure_dictionary(coh, dt_debt(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    if (!cep_l1_bootstrap_indexes(coh)) {
        return false;
    }

    if (!cep_l1_bootstrap_inbox(coh)) {
        return false;
    }

    if (!cep_l1_bootstrap_tmp()) {
        return false;
    }

    cep_namepool_bootstrap();
    return true;
}

/* ------------------------------------------------------------------------- */
/*  Helper lookups                                                           */
/* ------------------------------------------------------------------------- */

static cepCell* cep_l1_coh_root(void) {
    return cep_l1_coh_root_cell();
}

static cepCell* cep_l1_index_root(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_index()) : NULL;
}

static cepCell* cep_l1_being_ledger(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_being()) : NULL;
}

static cepCell* cep_l1_bond_ledger(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_bond()) : NULL;
}

static cepCell* cep_l1_context_ledger(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_context()) : NULL;
}

static cepCell* cep_l1_facet_mirror(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_facet_root()) : NULL;
}

static cepCell* cep_l1_debt_root(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_debt()) : NULL;
}

static cepCell* cep_l1_adj_root(void) {
    cepCell* tmp = cep_cell_find_by_name(cep_root(), dt_tmp());
    if (!tmp) {
        return NULL;
    }

    cepCell* coh_tmp = cep_cell_find_by_name(tmp, dt_coh());
    if (!coh_tmp) {
        return NULL;
    }

    cepCell* adj = cep_cell_find_by_name(coh_tmp, dt_adj());
    if (!adj) {
        return NULL;
    }

    return cep_cell_find_by_name(adj, dt_by_being());
}

static bool cep_l1_link_child(cepCell* parent, const cepDT* name, cepCell* target) {
    if (!parent || !name || !target) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing && cep_cell_is_link(existing)) {
        cep_link_set(existing, target);
        return true;
    }

    cepDT name_copy = *name;
    return cep_dict_add_link(parent, &name_copy, target) != NULL;
}

static cepCell* cep_l1_ensure_adj_bucket(const cepDT* id_dt) {
    cepCell* adj_root = cep_l1_adj_root();
    if (!adj_root) {
        return NULL;
    }

    cepCell* bucket = cep_l1_ensure_dictionary(adj_root, id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        return NULL;
    }

    if (!cep_l1_ensure_dictionary(bucket, dt_out_bonds(), CEP_STORAGE_RED_BLACK_T)) {
        return NULL;
    }
    if (!cep_l1_ensure_dictionary(bucket, dt_in_bonds(), CEP_STORAGE_RED_BLACK_T)) {
        return NULL;
    }
    if (!cep_l1_ensure_dictionary(bucket, dt_ctx_by_role(), CEP_STORAGE_RED_BLACK_T)) {
        return NULL;
    }

    return bucket;
}

static bool cep_l1_index_being(cepCell* being, const cepDT* id_dt, const char* kind) {
    cepCell* index_root = cep_l1_index_root();
    if (!index_root || !being || !id_dt || !kind) {
        return false;
    }

    cepCell* be_kind = cep_l1_ensure_dictionary(index_root, dt_be_kind(), CEP_STORAGE_RED_BLACK_T);
    if (!be_kind) {
        return false;
    }

    cepDT kind_dt;
    if (!cep_l1_word_dt(kind, &kind_dt)) {
        return false;
    }

    cepCell* bucket = cep_l1_ensure_dictionary(be_kind, &kind_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        return false;
    }

    cepDT id_copy = *id_dt;
    return cep_l1_link_child(bucket, &id_copy, being);
}

static bool cep_l1_index_bond(cepCell* bond, const cepDT* id_dt, cepCell* src, cepCell* dst, const char* type_text, bool directed) {
    (void)id_dt;
    cepCell* index_root = cep_l1_index_root();
    if (!index_root || !bond || !id_dt || !src || !dst || !type_text) {
        return false;
    }

    cepCell* pairs = cep_l1_ensure_dictionary(index_root, dt_bo_pair(), CEP_STORAGE_RED_BLACK_T);
    if (!pairs) {
        return false;
    }

    char src_buf[32];
    char dst_buf[32];
    if (!cep_l1_dt_to_text(cep_cell_get_name(src), src_buf, sizeof src_buf)) {
        return false;
    }
    if (!cep_l1_dt_to_text(cep_cell_get_name(dst), dst_buf, sizeof dst_buf)) {
        return false;
    }

    char key_buf[96];
    snprintf(key_buf, sizeof key_buf, "%s:%s:%s:%c", src_buf, dst_buf, type_text, directed ? '1' : '0');
    cepID key_id = cep_namepool_intern_cstr(key_buf);
    cepDT key_dt = {.domain = cep_domain_cep(), .tag = key_id};

    return cep_l1_link_child(pairs, &key_dt, bond);
}

static bool cep_l1_index_context(cepCell* ctx, const cepDT* id_dt, const char* type_text) {
    cepCell* index_root = cep_l1_index_root();
    if (!index_root || !ctx || !id_dt || !type_text) {
        return false;
    }

    cepCell* ctx_type_root = cep_l1_ensure_dictionary(index_root, dt_ctx_type(), CEP_STORAGE_RED_BLACK_T);
    if (!ctx_type_root) {
        return false;
    }

    cepDT type_dt;
    if (!cep_l1_word_dt(type_text, &type_dt)) {
        return false;
    }

    cepCell* bucket = cep_l1_ensure_dictionary(ctx_type_root, &type_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        return false;
    }

    cepDT id_copy = *id_dt;
    return cep_l1_link_child(bucket, &id_copy, ctx);
}

static bool cep_l1_index_facets(cepCell* ctx, const cepDT* id_dt) {
    if (!ctx || !id_dt) {
        return false;
    }

    cepCell* facets = cep_cell_find_by_name(ctx, dt_facets());
    if (!facets || !cep_cell_has_store(facets)) {
        return true;
    }

    cepCell* index_root = cep_l1_index_root();
    if (!index_root) {
        return false;
    }

    cepCell* fa_ctx_root = cep_l1_ensure_dictionary(index_root, dt_fa_ctx(), CEP_STORAGE_RED_BLACK_T);
    if (!fa_ctx_root) {
        return false;
    }

    cepCell* ctx_bucket = cep_l1_ensure_dictionary(fa_ctx_root, id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!ctx_bucket) {
        return false;
    }

    cep_l1_clear_children(ctx_bucket);

    for (cepCell* facet = cep_cell_first(facets); facet; facet = cep_cell_next(facets, facet)) {
        cepDT facet_name = *cep_cell_get_name(facet);
        if (!cep_l1_link_child(ctx_bucket, &facet_name, facet)) {
            return false;
        }
    }

    return true;
}

static bool cep_l1_adj_being(cepCell* being, const cepDT* id_dt) {
    (void)being;
    return cep_l1_ensure_adj_bucket(id_dt) != NULL;
}

static bool cep_l1_adj_bond(cepCell* bond, const cepDT* id_dt, cepCell* src, cepCell* dst) {
    (void)id_dt;
    if (!bond || !src || !dst) {
        return false;
    }

    cepCell* src_bucket = cep_l1_ensure_adj_bucket(cep_cell_get_name(src));
    cepCell* dst_bucket = cep_l1_ensure_adj_bucket(cep_cell_get_name(dst));
    if (!src_bucket || !dst_bucket) {
        return false;
    }

    cepCell* out_dict = cep_cell_find_by_name(src_bucket, dt_out_bonds());
    cepCell* in_dict  = cep_cell_find_by_name(dst_bucket, dt_in_bonds());
    if (!out_dict || !in_dict) {
        return false;
    }

    cepDT bond_name = *cep_cell_get_name(bond);
    if (!cep_l1_link_child(out_dict, &bond_name, bond)) {
        return false;
    }
    if (!cep_l1_link_child(in_dict, &bond_name, bond)) {
        return false;
    }

    return true;
}

static bool cep_l1_adj_context(cepCell* ctx, const cepDT* id_dt) {
    if (!ctx || !id_dt) {
        return false;
    }

    cepCell* roles = cep_cell_find_by_name(ctx, dt_roles());
    if (!roles || !cep_cell_has_store(roles)) {
        return true;
    }

    for (cepCell* role = cep_cell_first(roles); role; role = cep_cell_next(roles, role)) {
        const cepDT* role_name = cep_cell_get_name(role);
        cepCell* being = cep_link_pull(role);
        if (!being) {
            return false;
        }

        cepCell* bucket = cep_l1_ensure_adj_bucket(cep_cell_get_name(being));
        if (!bucket) {
            return false;
        }

        cepCell* ctx_by_role_root = cep_cell_find_by_name(bucket, dt_ctx_by_role());
        if (!ctx_by_role_root) {
            return false;
        }

        cepCell* role_bucket = cep_l1_ensure_dictionary(ctx_by_role_root, role_name, CEP_STORAGE_RED_BLACK_T);
        if (!role_bucket) {
            return false;
        }

        cepDT ctx_name = *id_dt;
        if (!cep_l1_link_child(role_bucket, &ctx_name, ctx)) {
            return false;
        }
    }

    return true;
}

static bool cep_l1_record_debt(const cepDT* ctx_id, const cepDT* facet_id, cepCell* request) {
    cepCell* debt_root = cep_l1_debt_root();
    if (!debt_root || !ctx_id || !facet_id) {
        return false;
    }

    cepCell* ctx_bucket = cep_l1_ensure_dictionary(debt_root, ctx_id, CEP_STORAGE_RED_BLACK_T);
    if (!ctx_bucket) {
        return false;
    }

    cepCell* facet_bucket = cep_cell_find_by_name(ctx_bucket, facet_id);
    if (!facet_bucket) {
        cepDT facet_copy = *facet_id;
        cepDT dict_type = *dt_dictionary();
        facet_bucket = cep_dict_add_dictionary(ctx_bucket, &facet_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    if (!facet_bucket) {
        return false;
    }

    cep_l1_set_bool_value(facet_bucket, dt_required(), true);
    if (request) {
        cep_l1_attach_request_parent(facet_bucket, request);
    }
    return true;
}

static void cep_l1_clear_debt(const cepDT* ctx_id, const cepDT* facet_id) {
    cepCell* debt_root = cep_l1_debt_root();
    if (!debt_root || !ctx_id || !facet_id) {
        return;
    }

    cepCell* ctx_bucket = cep_cell_find_by_name(debt_root, ctx_id);
    if (!ctx_bucket) {
        return;
    }

    cepCell* facet_bucket = cep_cell_find_by_name(ctx_bucket, facet_id);
    if (facet_bucket) {
        cep_cell_child_take_hard(ctx_bucket, facet_bucket);
    }

    if (!cep_cell_children(ctx_bucket)) {
        cep_cell_child_take_hard(debt_root, ctx_bucket);
    }
}

static bool cep_l1_parse_facet_request(cepCell* node, cepCell** out_target, bool* out_required) {
    if (!out_target || !out_required) {
        return false;
    }

    *out_target = NULL;
    *out_required = false;

    if (!node) {
        return true;
    }

    if (cep_cell_is_link(node)) {
        *out_target = cep_link_pull(node);
        return true;
    }

    if (cep_cell_has_store(node)) {
        for (cepCell* child = cep_cell_first(node); child; child = cep_cell_next(node, child)) {
            if (cep_cell_is_link(child) && !*out_target) {
                *out_target = cep_link_pull(child);
            } else if (cep_cell_name_is(child, dt_required()) && cep_cell_has_data(child)) {
                const cepData* data = child->data;
                if (data->datatype == CEP_DATATYPE_VALUE && data->size > 0u) {
                    *out_required = data->value[0] != 0u;
                }
            }
        }
        return true;
    }

    if (cep_cell_has_data(node) && cep_cell_name_is(node, dt_required())) {
        const cepData* data = node->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size > 0u) {
            *out_required = data->value[0] != 0u;
        }
    }

    return true;
}

/* ------------------------------------------------------------------------- */
/*  Request parsing helpers                                                  */
/* ------------------------------------------------------------------------- */

static cepCell* cep_l1_resolve_request(const cepPath* target_path) {
    if (!target_path) {
        return NULL;
    }
    return cep_cell_find_by_path(cep_root(), target_path);
}

static bool cep_l1_request_guard(cepCell* request, const cepDT* bucket_name) {
    if (!request) {
        return false;
    }

    cepCell* bucket = cep_cell_parent(request);
    if (!bucket || !cep_cell_name_is(bucket, bucket_name)) {
        return false;
    }

    cepCell* inbox = cep_cell_parent(bucket);
    if (!inbox || !cep_cell_name_is(inbox, dt_inbox())) {
        return false;
    }

    cepCell* coh = cep_cell_parent(inbox);
    return coh && cep_cell_name_is(coh, dt_coh());
}

static bool cep_l1_request_word_field(cepCell* request, const cepDT* field, char* buffer, size_t cap) {
    if (!request) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(request, field);
    if (!node) {
        return false;
    }

    if (!cep_l1_copy_string(node, buffer, cap)) {
        return false;
    }

    return cep_text_to_word(buffer) != 0;
}

static bool cep_l1_request_bool_field(cepCell* request, const cepDT* field, bool* out_value) {
    if (!request || !out_value) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(request, field);
    if (!node || !cep_cell_has_data(node)) {
        return false;
    }

    const cepData* data = node->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return false;
    }

    *out_value = data->value[0] != 0u;
    return true;
}

static cepCell* cep_l1_request_link_field(cepCell* request, const cepDT* field) {
    if (!request) {
        return NULL;
    }

    cepCell* node = cep_cell_find_by_name(request, field);
    if (!node) {
        return NULL;
    }

    return cep_link_pull(node);
}

static bool cep_l1_dt_to_text(const cepDT* dt, char* buffer, size_t cap) {
    if (!dt || !buffer || !cap) {
        return false;
    }

    if (cep_id_is_word(dt->tag)) {
        size_t len = cep_word_to_text(dt->tag, buffer);
        buffer[len] = '\0';
        return true;
    }

    if (cep_id_is_reference(dt->tag)) {
        size_t len = 0u;
        const char* text = cep_namepool_lookup(dt->tag, &len);
        if (!text || len >= cap) {
            return false;
        }
        memcpy(buffer, text, len);
        buffer[len] = '\0';
        return true;
    }

    snprintf(buffer, cap, "#%" PRIX64, (uint64_t)cep_id(dt->tag));
    return true;
}

static bool cep_l1_set_link_field(cepCell* parent, const cepDT* name, cepCell* target) {
    if (!parent || !name || !target) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing && cep_cell_is_link(existing)) {
        cep_link_set(existing, target);
        return true;
    }

    cepDT name_copy = *name;
    return cep_dict_add_link(parent, &name_copy, target) != NULL;
}

/* ------------------------------------------------------------------------- */
/*  Enzyme callbacks                                                         */
/* ------------------------------------------------------------------------- */

static cepCell* cep_l1_index_root(void);
static cepCell* cep_l1_facet_mirror(void);
static cepCell* cep_l1_adj_root(void);

static bool cep_l1_link_child(cepCell* parent, const cepDT* name, cepCell* target);
static bool cep_l1_index_being(cepCell* being, const cepDT* id_dt, const char* kind);
static bool cep_l1_index_bond(cepCell* bond, const cepDT* id_dt, cepCell* src, cepCell* dst, const char* type_text, bool directed);
static bool cep_l1_index_context(cepCell* ctx, const cepDT* id_dt, const char* type_text);
static bool cep_l1_index_facets(cepCell* ctx, const cepDT* id_dt);
static bool cep_l1_adj_being(cepCell* being, const cepDT* id_dt);
static bool cep_l1_adj_bond(cepCell* bond, const cepDT* id_dt, cepCell* src, cepCell* dst);
static bool cep_l1_adj_context(cepCell* ctx, const cepDT* id_dt);

static int cep_l1_enzyme_ingest_be(const cepPath* signal_path, const cepPath* target_path);
static int cep_l1_enzyme_ingest_bo(const cepPath* signal_path, const cepPath* target_path);
static int cep_l1_enzyme_ingest_ctx(const cepPath* signal_path, const cepPath* target_path);
static int cep_l1_enzyme_closure(const cepPath* signal_path, const cepPath* target_path);
static int cep_l1_enzyme_index(const cepPath* signal_path, const cepPath* target_path);
static int cep_l1_enzyme_adj(const cepPath* signal_path, const cepPath* target_path);
static int cep_l1_enzyme_ingest_be(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_be_create())) {
        return CEP_ENZYME_SUCCESS;
    }

    char id_buf[32];
    char kind_buf[32];
    if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l1_request_word_field(request, dt_kind(), kind_buf, sizeof kind_buf)) {
        return CEP_ENZYME_FATAL;
    }

    cepDT id_dt;
    if (!cep_l1_word_dt(id_buf, &id_dt)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* ledger = cep_l1_being_ledger();
    if (!ledger) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* being = cep_l1_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!being) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l1_set_string_value(being, dt_kind(), kind_buf)) {
        return CEP_ENZYME_FATAL;
    }

    cep_l1_attach_request_parent(being, request);
    cep_l1_mark_outcome_ok(request);
    return CEP_ENZYME_SUCCESS;
}
static int cep_l1_enzyme_ingest_bo(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_bo_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    char id_buf[32];
    char type_buf[32];
    if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l1_request_word_field(request, dt_type(), type_buf, sizeof type_buf)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* src = cep_l1_request_link_field(request, dt_src());
    cepCell* dst = cep_l1_request_link_field(request, dt_dst());
    if (!src || !dst) {
        return CEP_ENZYME_FATAL;
    }

    bool directed = false;
    (void)cep_l1_request_bool_field(request, dt_directed(), &directed);

    cepDT id_dt;
    if (!cep_l1_word_dt(id_buf, &id_dt)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* ledger = cep_l1_bond_ledger();
    if (!ledger) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* bond = cep_l1_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bond) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l1_set_string_value(bond, dt_type(), type_buf)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l1_set_link_field(bond, dt_src(), src)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l1_set_link_field(bond, dt_dst(), dst)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l1_set_bool_value(bond, dt_directed(), directed)) {
        return CEP_ENZYME_FATAL;
    }

    cep_l1_attach_request_parent(bond, request);
    cep_l1_mark_outcome_ok(request);
    return CEP_ENZYME_SUCCESS;
}
static int cep_l1_enzyme_ingest_ctx(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_ctx_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    char id_buf[32];
    char type_buf[32];
    if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l1_request_word_field(request, dt_type(), type_buf, sizeof type_buf)) {
        return CEP_ENZYME_FATAL;
    }

    cepDT id_dt;
    if (!cep_l1_word_dt(id_buf, &id_dt)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* ledger = cep_l1_context_ledger();
    if (!ledger) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* ctx = cep_l1_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!ctx) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l1_set_string_value(ctx, dt_type(), type_buf)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* roles_req = cep_cell_find_by_name(request, dt_roles());
    if (roles_req && cep_cell_has_store(roles_req)) {
        cepCell* roles_dst = cep_l1_ensure_dictionary(ctx, dt_roles(), CEP_STORAGE_RED_BLACK_T);
        if (!roles_dst) {
            return CEP_ENZYME_FATAL;
        }
        cep_l1_clear_children(roles_dst);
        for (cepCell* role = cep_cell_first(roles_req); role; role = cep_cell_next(roles_req, role)) {
            const cepDT* role_name = cep_cell_get_name(role);
            if (!cep_id_is_word(role_name->tag)) {
                return CEP_ENZYME_FATAL;
            }
            cepCell* target = cep_link_pull(role);
            if (!target) {
                return CEP_ENZYME_FATAL;
            }
            cepDT role_copy = *role_name;
            cep_dict_add_link(roles_dst, &role_copy, target);
        }
    }

    cepCell* facets_req = cep_cell_find_by_name(request, dt_facets());
    if (facets_req && cep_cell_has_store(facets_req)) {
        cepCell* facets_dst = cep_l1_ensure_dictionary(ctx, dt_facets(), CEP_STORAGE_RED_BLACK_T);
        if (!facets_dst) {
            return CEP_ENZYME_FATAL;
        }
        cep_l1_clear_children(facets_dst);
        for (cepCell* facet = cep_cell_first(facets_req); facet; facet = cep_cell_next(facets_req, facet)) {
            cepDT facet_name_copy = *cep_cell_get_name(facet);
            cepCell* facet_target = NULL;
            bool facet_required = false;
            if (!cep_l1_parse_facet_request(facet, &facet_target, &facet_required)) {
                return CEP_ENZYME_FATAL;
            }
            if (facet_target) {
                if (!cep_l1_link_child(facets_dst, &facet_name_copy, facet_target)) {
                    return CEP_ENZYME_FATAL;
                }
            }
        }
    }

    cep_l1_attach_request_parent(ctx, request);
    cep_l1_mark_outcome_ok(request);
    return CEP_ENZYME_SUCCESS;
}
static int cep_l1_enzyme_closure(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_ctx_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    char id_buf[32];
    if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
        return CEP_ENZYME_FATAL;
    }

    cepDT id_dt;
    if (!cep_l1_word_dt(id_buf, &id_dt)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* ctx = cep_cell_find_by_name(cep_l1_context_ledger(), &id_dt);
    if (!ctx) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* facets_dst = cep_cell_find_by_name(ctx, dt_facets());
    if (facets_dst && cep_cell_has_store(facets_dst)) {
        cepCell* mirror = cep_l1_facet_mirror();
        if (!mirror) {
            return CEP_ENZYME_FATAL;
        }

        for (cepCell* facet = cep_cell_first(facets_dst); facet; facet = cep_cell_next(facets_dst, facet)) {
            const cepDT* facet_name = cep_cell_get_name(facet);
            cepCell* facet_target = cep_link_pull(facet);
            if (!facet_target) {
                continue;
            }

            char facet_buf[32];
            if (!cep_l1_dt_to_text(facet_name, facet_buf, sizeof facet_buf)) {
                return CEP_ENZYME_FATAL;
            }

            char key_buf[72];
            snprintf(key_buf, sizeof key_buf, "%s:%s", id_buf, facet_buf);
            cepID key_id = cep_namepool_intern_cstr(key_buf);
            cepDT key_dt = {.domain = cep_domain_cep(), .tag = key_id};

            if (!cep_l1_link_child(mirror, &key_dt, facet_target)) {
                return CEP_ENZYME_FATAL;
            }
        }
    }

    cepCell* facets_req = cep_cell_find_by_name(request, dt_facets());
    if (facets_req && cep_cell_has_store(facets_req)) {
        for (cepCell* facet_req = cep_cell_first(facets_req); facet_req; facet_req = cep_cell_next(facets_req, facet_req)) {
            const cepDT* facet_name = cep_cell_get_name(facet_req);
            cepCell* facet_target = NULL;
            bool facet_required = false;
            if (!cep_l1_parse_facet_request(facet_req, &facet_target, &facet_required)) {
                return CEP_ENZYME_FATAL;
            }

            bool satisfied = false;
            if (facets_dst) {
                cepCell* facet_entry = cep_cell_find_by_name(facets_dst, facet_name);
                if (facet_entry && cep_cell_is_link(facet_entry) && cep_link_pull(facet_entry)) {
                    satisfied = true;
                }
            }

            if (facet_required && !satisfied) {
                if (!cep_l1_record_debt(&id_dt, facet_name, request)) {
                    return CEP_ENZYME_FATAL;
                }
            } else {
                cep_l1_clear_debt(&id_dt, facet_name);
            }
        }
    }

    if (!cep_l1_index_facets(ctx, &id_dt)) {
        return CEP_ENZYME_FATAL;
    }

    cep_l1_mark_outcome_ok(request);
    return CEP_ENZYME_SUCCESS;
}
static int cep_l1_enzyme_index(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request = cep_l1_resolve_request(target_path);
    if (!request) {
        return CEP_ENZYME_SUCCESS;
    }

    bool handled = false;

    if (cep_l1_request_guard(request, dt_be_create())) {
        char id_buf[32];
        if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
            return CEP_ENZYME_FATAL;
        }

        cepDT id_dt;
        if (!cep_l1_word_dt(id_buf, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* being = cep_cell_find_by_name(cep_l1_being_ledger(), &id_dt);
        if (!being) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* kind_cell = cep_cell_find_by_name(being, dt_kind());
        char kind_buf[32];
        if (!kind_cell || !cep_l1_copy_string(kind_cell, kind_buf, sizeof kind_buf)) {
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_index_being(being, &id_dt, kind_buf)) {
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_bo_upsert())) {
        char id_buf[32];
        if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
            return CEP_ENZYME_FATAL;
        }

        cepDT id_dt;
        if (!cep_l1_word_dt(id_buf, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* bond = cep_cell_find_by_name(cep_l1_bond_ledger(), &id_dt);
        if (!bond) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* src_link = cep_cell_find_by_name(bond, dt_src());
        cepCell* dst_link = cep_cell_find_by_name(bond, dt_dst());
        if (!src_link || !dst_link) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* src = cep_link_pull(src_link);
        cepCell* dst = cep_link_pull(dst_link);
        if (!src || !dst) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* type_cell = cep_cell_find_by_name(bond, dt_type());
        char type_buf[32];
        if (!type_cell || !cep_l1_copy_string(type_cell, type_buf, sizeof type_buf)) {
            return CEP_ENZYME_FATAL;
        }

        bool directed = false;
        cepCell* dir_cell = cep_cell_find_by_name(bond, dt_directed());
        if (dir_cell && cep_cell_has_data(dir_cell) && dir_cell->data->datatype == CEP_DATATYPE_VALUE && dir_cell->data->size > 0u) {
            directed = dir_cell->data->value[0] != 0u;
        }

        if (!cep_l1_index_bond(bond, &id_dt, src, dst, type_buf, directed)) {
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_ctx_upsert())) {
        char id_buf[32];
        if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
            return CEP_ENZYME_FATAL;
        }

        cepDT id_dt;
        if (!cep_l1_word_dt(id_buf, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* ctx = cep_cell_find_by_name(cep_l1_context_ledger(), &id_dt);
        if (!ctx) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* type_cell = cep_cell_find_by_name(ctx, dt_type());
        char type_buf[32];
        if (!type_cell || !cep_l1_copy_string(type_cell, type_buf, sizeof type_buf)) {
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_index_context(ctx, &id_dt, type_buf)) {
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_index_facets(ctx, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    }

    if (handled) {
        cep_l1_mark_outcome_ok(request);
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_l1_enzyme_adj(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request = cep_l1_resolve_request(target_path);
    if (!request) {
        return CEP_ENZYME_SUCCESS;
    }

    bool handled = false;

    if (cep_l1_request_guard(request, dt_be_create())) {
        char id_buf[32];
        if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
            return CEP_ENZYME_FATAL;
        }

        cepDT id_dt;
        if (!cep_l1_word_dt(id_buf, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* being = cep_cell_find_by_name(cep_l1_being_ledger(), &id_dt);
        if (!being || !cep_l1_adj_being(being, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_bo_upsert())) {
        char id_buf[32];
        if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
            return CEP_ENZYME_FATAL;
        }

        cepDT id_dt;
        if (!cep_l1_word_dt(id_buf, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* bond = cep_cell_find_by_name(cep_l1_bond_ledger(), &id_dt);
        if (!bond) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* src_link = cep_cell_find_by_name(bond, dt_src());
        cepCell* dst_link = cep_cell_find_by_name(bond, dt_dst());
        if (!src_link || !dst_link) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* src = cep_link_pull(src_link);
        cepCell* dst = cep_link_pull(dst_link);
        if (!src || !dst) {
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_adj_bond(bond, &id_dt, src, dst)) {
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_ctx_upsert())) {
        char id_buf[32];
        if (!cep_l1_request_word_field(request, dt_id(), id_buf, sizeof id_buf)) {
            return CEP_ENZYME_FATAL;
        }

        cepDT id_dt;
        if (!cep_l1_word_dt(id_buf, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        cepCell* ctx = cep_cell_find_by_name(cep_l1_context_ledger(), &id_dt);
        if (!ctx) {
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_adj_context(ctx, &id_dt)) {
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    }

    if (handled) {
        cep_l1_mark_outcome_ok(request);
    }

    return CEP_ENZYME_SUCCESS;
}
/* ------------------------------------------------------------------------- */
/*  Registration bookkeeping                                                 */
/* ------------------------------------------------------------------------- */

typedef struct {
    cepEnzymeRegistry* registry;
    size_t             baseline;
} cepL1RegistryRecord;

static cepL1RegistryRecord* cep_l1_records = NULL;
static size_t cep_l1_record_count = 0u;
static size_t cep_l1_record_capacity = 0u;
static bool   cep_l1_bindings_applied = false;

static cepL1RegistryRecord* cep_l1_record_find(cepEnzymeRegistry* registry) {
    for (size_t i = 0; i < cep_l1_record_count; ++i) {
        if (cep_l1_records[i].registry == registry) {
            return &cep_l1_records[i];
        }
    }
    return NULL;
}

static cepL1RegistryRecord* cep_l1_record_append(cepEnzymeRegistry* registry, size_t baseline) {
    if (!registry) {
        return NULL;
    }

    if (cep_l1_record_count == cep_l1_record_capacity) {
        size_t new_capacity = cep_l1_record_capacity ? (cep_l1_record_capacity * 2u) : 4u;
        void* grown = realloc(cep_l1_records, new_capacity * sizeof *cep_l1_records);
        if (!grown) {
            return NULL;
        }
        cep_l1_records = grown;
        for (size_t i = cep_l1_record_capacity; i < new_capacity; ++i) {
            cep_l1_records[i].registry = NULL;
            cep_l1_records[i].baseline = 0u;
        }
        cep_l1_record_capacity = new_capacity;
    }

    cepL1RegistryRecord* record = &cep_l1_records[cep_l1_record_count++];
    record->registry = registry;
    record->baseline = baseline;
    return record;
}

/* ------------------------------------------------------------------------- */
/*  Registration                                                             */
/* ------------------------------------------------------------------------- */

bool cep_l1_coherence_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (!cep_l1_coherence_bootstrap()) {
        return false;
    }

    cepL1RegistryRecord* record = cep_l1_record_find(registry);
    if (record) {
        return true;
    }

    size_t baseline = cep_enzyme_registry_size(registry);
    record = cep_l1_record_append(registry, baseline);
    if (!record) {
        return false;
    }

    cepDT after_closure_buf[1] = { *dt_coh_ing_ctx() };
    cepDT after_index_buf[1] = { *dt_coh_closure() };
    cepDT after_adj_buf[1] = { *dt_coh_index() };

    cepEnzymeDescriptor descriptors[] = {
        {
            .name = *dt_coh_ing_be(),
            .label = "coh.ingest.be",
            .callback = cep_l1_enzyme_ingest_be,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_coh_ing_bo(),
            .label = "coh.ingest.bo",
            .callback = cep_l1_enzyme_ingest_bo,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_coh_ing_ctx(),
            .label = "coh.ingest.ctx",
            .callback = cep_l1_enzyme_ingest_ctx,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_coh_closure(),
            .label = "coh.closure",
            .callback = cep_l1_enzyme_closure,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_closure_buf,
            .after_count = 1u,
        },
        {
            .name = *dt_coh_index(),
            .label = "coh.index",
            .callback = cep_l1_enzyme_index,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_index_buf,
            .after_count = 1u,
        },
        {
            .name = *dt_coh_adj(),
            .label = "coh.adj",
            .callback = cep_l1_enzyme_adj,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_adj_buf,
            .after_count = 1u,
        },
    };

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepPathStatic2;

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_signal_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    for (size_t i = 0; i < sizeof descriptors / sizeof descriptors[0]; ++i) {
        if (cep_enzyme_register(registry, (const cepPath*)&signal_path, &descriptors[i]) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    if (!cep_l1_bindings_applied) {
        cepCell* coh = cep_l1_coh_root();
        if (!coh) {
            return false;
        }

        (void)cep_cell_bind_enzyme(coh, dt_coh_ing_be(), true);
        (void)cep_cell_bind_enzyme(coh, dt_coh_ing_bo(), true);
        (void)cep_cell_bind_enzyme(coh, dt_coh_ing_ctx(), true);
        (void)cep_cell_bind_enzyme(coh, dt_coh_closure(), true);
        (void)cep_cell_bind_enzyme(coh, dt_coh_index(), true);
        (void)cep_cell_bind_enzyme(coh, dt_coh_adj(), true);
        cep_l1_bindings_applied = true;
    }

    return true;
}
