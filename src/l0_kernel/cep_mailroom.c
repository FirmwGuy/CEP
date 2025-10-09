/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_mailroom.h"

#include "cep_cell.h"
#include "cep_namepool.h"

#include <string.h>

CEP_DEFINE_STATIC_DT(dt_data_root,      CEP_ACRO("CEP"), CEP_WORD("data"))
CEP_DEFINE_STATIC_DT(dt_sys_root,       CEP_ACRO("CEP"), CEP_WORD("sys"))
CEP_DEFINE_STATIC_DT(dt_inbox_root,     CEP_ACRO("CEP"), CEP_WORD("inbox"))
CEP_DEFINE_STATIC_DT(dt_mailroom_ns_coh, CEP_ACRO("CEP"), CEP_WORD("coh"))
CEP_DEFINE_STATIC_DT(dt_mailroom_ns_flow, CEP_ACRO("CEP"), CEP_WORD("flow"))

static bool cep_mailroom_dt_from_text(cepDT* dt, const char* tag) {
    if (!dt || !tag || !tag[0]) {
        return false;
    }

    cepID id = cep_text_to_word(tag);
    if (!id) {
        id = cep_namepool_intern(tag, strlen(tag));
    }
    if (!id) {
        return false;
    }

    dt->domain = CEP_ACRO("CEP");
    dt->tag = id;
    dt->glob = 0;
    return true;
}

typedef struct {
    cepDT namespace_dt;
    cepDT* bucket_dts;
    size_t bucket_count;
} cepMailroomNamespaceSpec;

static cepMailroomNamespaceSpec* cep_mailroom_extra_namespaces = NULL;
static size_t cep_mailroom_extra_namespace_count = 0u;

static cepDT* cep_mailroom_router_before_extra = NULL;
static size_t cep_mailroom_router_before_extra_count = 0u;

static bool cep_mailroom_bootstrap_done = false;
static bool cep_mailroom_seed_errors_enabled = true;

CEP_DEFINE_STATIC_DT(dt_sig_sys,  CEP_ACRO("CEP"), CEP_WORD("sig_sys"))
CEP_DEFINE_STATIC_DT(dt_sys_init, CEP_ACRO("CEP"), CEP_WORD("init"))
CEP_DEFINE_STATIC_DT(dt_err_cat,  CEP_ACRO("CEP"), CEP_WORD("err_cat"))
CEP_DEFINE_STATIC_DT(dt_dictionary, CEP_ACRO("CEP"), CEP_WORD("dictionary"))
CEP_DEFINE_STATIC_DT(dt_list,     CEP_ACRO("CEP"), CEP_WORD("list"))
CEP_DEFINE_STATIC_DT(dt_text,     CEP_ACRO("CEP"), CEP_WORD("text"))
CEP_DEFINE_STATIC_DT(dt_original, CEP_ACRO("CEP"), CEP_WORD("original"))
CEP_DEFINE_STATIC_DT(dt_outcome,  CEP_ACRO("CEP"), CEP_WORD("outcome"))
CEP_DEFINE_STATIC_DT(dt_meta,     CEP_ACRO("CEP"), CEP_WORD("meta"))
CEP_DEFINE_STATIC_DT(dt_parents,  CEP_ACRO("CEP"), CEP_WORD("parents"))
CEP_DEFINE_STATIC_DT(dt_sig_cell, CEP_ACRO("CEP"), CEP_WORD("sig_cell"))
CEP_DEFINE_STATIC_DT(dt_op_add,   CEP_ACRO("CEP"), CEP_WORD("op_add"))
CEP_DEFINE_STATIC_DT(dt_mr_route, CEP_ACRO("CEP"), CEP_WORD("mr_route"))
CEP_DEFINE_STATIC_DT(dt_mr_init,  CEP_ACRO("CEP"), CEP_WORD("mr_init"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_be,  CEP_ACRO("CEP"), CEP_WORD("coh_ing_be"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_bo,  CEP_ACRO("CEP"), CEP_WORD("coh_ing_bo"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_ctx, CEP_ACRO("CEP"), CEP_WORD("coh_ing_ctx"))
CEP_DEFINE_STATIC_DT(dt_fl_ing,   CEP_ACRO("CEP"), CEP_WORD("fl_ing"))
CEP_DEFINE_STATIC_DT(dt_ni_ing,   CEP_ACRO("CEP"), CEP_WORD("ni_ing"))
CEP_DEFINE_STATIC_DT(dt_inst_ing, CEP_ACRO("CEP"), CEP_WORD("inst_ing"))

typedef struct {
    const char* code;
    const char* message;
} cepMailroomErrorEntry;

static const cepMailroomErrorEntry CEP_MAILROOM_ERROR_COH[] = {
    {"attrs", "attributes branch missing"},
    {"attrs-copy", "failed to copy submitted attribute"},
    {"attrs-data", "attribute payload invalid"},
    {"attrs-lock", "unable to lock attribute dictionary"},
    {"attrs-name", "attribute name invalid"},
    {"attrs-value", "attribute value invalid"},
    {"being-lock", "unable to lock being entry"},
    {"bond-lock", "unable to lock bond entry"},
    {"bond-update", "failed to update bond payload"},
    {"create-failed", "failed to create ledger entry"},
    {"ctx-lock", "unable to lock context entry"},
    {"ctx-type", "context type invalid"},
    {"debt-lock", "unable to lock debt bucket"},
    {"decision-ledger", "decision ledger update failed"},
    {"facet-link", "failed to link facet target"},
    {"facet-lock", "unable to lock facet bucket"},
    {"facet-parse", "facet payload invalid"},
    {"facets", "facets dictionary missing"},
    {"facets-lock", "unable to lock facets dictionary"},
    {"invalid-role", "role identifier invalid"},
    {"ledger-lock", "unable to lock ledger"},
    {"missing-endpoint", "bond endpoint missing"},
    {"missing-ledger", "required ledger missing"},
    {"role-link", "failed to link role target"},
    {"role-target", "role target missing"},
    {"roles", "roles dictionary missing"},
    {"roles-lock", "unable to lock roles dictionary"},
    {"set-kind", "failed to store being kind"},
};

static const cepMailroomErrorEntry CEP_MAILROOM_ERROR_FLOW[] = {
    {"budget", "instance budget update failed"},
    {"copy-failed", "failed to copy payload into ledger"},
    {"entry-lock", "unable to lock ledger entry"},
    {"events", "unable to stage event metadata"},
    {"ledger-lock", "unable to lock flow ledger"},
    {"missing-action", "control intent missing action"},
    {"missing-id", "identifier missing from request"},
    {"missing-kind", "flow definition kind missing"},
    {"missing-ledger", "required flow ledger missing"},
    {"no-match", "no subscription matched the event"},
    {"pc", "program counter invalid"},
    {"state", "instance state invalid"},
    {"unknown-action", "control action not recognised"},
    {"unknown-instance", "instance not found"},
    {"unknown-kind", "flow definition kind unknown"},
    {"upsert-failed", "failed to upsert flow definition"},
};

static bool cep_mailroom_bindings_applied = false;
static cepEnzymeRegistry* cep_mailroom_registered_registry = NULL;

static void cep_mailroom_free_extra_namespaces(void) {
    if (!cep_mailroom_extra_namespaces) {
        cep_mailroom_extra_namespace_count = 0u;
        return;
    }

    for (size_t i = 0; i < cep_mailroom_extra_namespace_count; ++i) {
        cep_free(cep_mailroom_extra_namespaces[i].bucket_dts);
    }

    cep_free(cep_mailroom_extra_namespaces);
    cep_mailroom_extra_namespaces = NULL;
    cep_mailroom_extra_namespace_count = 0u;
}

static void cep_mailroom_free_router_before(void) {
    if (cep_mailroom_router_before_extra) {
        cep_free(cep_mailroom_router_before_extra);
        cep_mailroom_router_before_extra = NULL;
    }
    cep_mailroom_router_before_extra_count = 0u;
}

void cep_mailroom_shutdown(void) {
    cep_mailroom_free_extra_namespaces();
    cep_mailroom_free_router_before();
    cep_mailroom_bootstrap_done = false;
    cep_mailroom_seed_errors_enabled = true;
    cep_mailroom_bindings_applied = false;
    cep_mailroom_registered_registry = NULL;
}

static cepCell* cep_mailroom_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    cepDT lookup = *name;
    lookup.glob = 0u;

    cepCell* existing = cep_cell_find_by_name(parent, &lookup);
    if (existing) {
        return existing;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT name_copy = lookup;
    return cep_dict_add_dictionary(parent, &name_copy, &dict_type, storage);
}

static bool cep_mailroom_seed_namespace(cepCell* inbox,
                                        const cepDT* ns_name,
                                        const cepDT* buckets,
                                        size_t bucket_count) {
    if (!inbox || !ns_name || (bucket_count && !buckets)) {
        return false;
    }

    cepCell* ns_root = cep_mailroom_ensure_dictionary(inbox, ns_name, CEP_STORAGE_RED_BLACK_T);
    if (!ns_root) {
        return false;
    }

    for (size_t i = 0; i < bucket_count; ++i) {
        const cepDT* bucket_dt = &buckets[i];
        if (!cep_mailroom_ensure_dictionary(ns_root, bucket_dt, CEP_STORAGE_RED_BLACK_T)) {
            return false;
        }
    }

    return true;
}

static bool cep_mailroom_set_string_value(cepCell* parent, const cepDT* name, const char* text) {
    if (!parent || !name || !text) {
        return false;
    }

    size_t size = strlen(text) + 1u;
    cepDT lookup = *name;
    lookup.glob = 0u;

    cepCell* existing = cep_cell_find_by_name(parent, &lookup);
    if (existing) {
        if (cep_cell_has_data(existing)) {
            const cepData* data = existing->data;
            if (data->datatype == CEP_DATATYPE_VALUE && data->size == size && memcmp(data->value, text, size) == 0) {
                return true;
            }
        }
        cep_cell_remove_hard(parent, existing);
    }

    cepDT name_copy = lookup;
    cepDT text_dt = *dt_text();
    cepCell* node = cep_dict_add_value(parent, &name_copy, &text_dt, (void*)text, size, size);
    if (!node) {
        return false;
    }
    cep_cell_content_hash(node);
    return true;
}

static bool cep_mailroom_seed_error_entries(const cepMailroomErrorEntry* entries, size_t count) {
    if (!entries) {
        return false;
    }

    cepCell* root = cep_root();
    cepDT sys_dt = *dt_sys_root();
    sys_dt.glob = 0u;
    cepCell* sys = cep_cell_find_by_name(root, &sys_dt);
    if (!sys) {
        return false;
    }

    cepDT err_dt = *dt_err_cat();
    err_dt.glob = 0u;
    cepCell* catalog = cep_cell_find_by_name(sys, &err_dt);
    if (!catalog) {
        return false;
    }

    for (size_t i = 0; i < count; ++i) {
        const cepMailroomErrorEntry* entry = &entries[i];
        if (!entry->code || !entry->message) {
            continue;
        }

        cepDT code_dt = {0};
        if (!cep_mailroom_dt_from_text(&code_dt, entry->code)) {
            return false;
        }

        cepCell* bucket = cep_cell_find_by_name(catalog, &code_dt);
        if (!bucket) {
            cepDT dict_type = *dt_dictionary();
            cepDT name_copy = code_dt;
            bucket = cep_dict_add_dictionary(catalog, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        }
        if (!bucket) {
            return false;
        }

        if (!cep_mailroom_set_string_value(bucket, dt_text(), entry->message)) {
            return false;
        }
    }

    return true;
}

static bool cep_mailroom_ensure_shared_header(cepCell* request) {
    if (!request) {
        return false;
    }

    bool ok = true;

    cepCell* original = cep_cell_find_by_name(request, dt_original());
    if (!original) {
        cepDT dict_type = *dt_dictionary();
        cepDT name_copy = *dt_original();
        original = cep_dict_add_dictionary(request, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        ok = ok && (original != NULL);
    }

    cepCell* outcome = cep_cell_find_by_name(request, dt_outcome());
    if (!outcome || !cep_cell_has_data(outcome)) {
        ok = ok && cep_mailroom_set_string_value(request, dt_outcome(), "pending");
    }

    cepCell* meta = cep_cell_find_by_name(request, dt_meta());
    if (!meta) {
        cepDT dict_type = *dt_dictionary();
        cepDT meta_name = *dt_meta();
        meta = cep_dict_add_dictionary(request, &meta_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        ok = ok && (meta != NULL);
    }

    if (meta) {
        cepCell* parents = cep_cell_find_by_name(meta, dt_parents());
        if (!parents) {
            cepDT list_type = *dt_list();
            cepDT parent_name = *dt_parents();
            parents = cep_dict_add_list(meta, &parent_name, &list_type, CEP_STORAGE_LINKED_LIST);
            ok = ok && (parents != NULL);
        }
    }

    return ok;
}

/* Prepare the unified mailroom branches so producers can target `/data/inbox`
 * while existing layers still receive intents under their traditional inboxes. */
bool cep_mailroom_add_namespace(const char* namespace_tag,
                                const char* const bucket_tags[],
                                size_t bucket_count) {
    if (!namespace_tag || !namespace_tag[0]) {
        return false;
    }

    if (bucket_count && !bucket_tags) {
        return false;
    }

    cepDT namespace_dt = {0};
    if (!cep_mailroom_dt_from_text(&namespace_dt, namespace_tag)) {
        return false;
    }

    if (cep_dt_compare(&namespace_dt, dt_mailroom_ns_coh()) == 0 ||
        cep_dt_compare(&namespace_dt, dt_mailroom_ns_flow()) == 0) {
        /* Built-in namespaces already handled. */
        return true;
    }

    cepMailroomNamespaceSpec* spec = NULL;
    for (size_t i = 0; i < cep_mailroom_extra_namespace_count; ++i) {
        if (cep_dt_compare(&cep_mailroom_extra_namespaces[i].namespace_dt, &namespace_dt) == 0) {
            spec = &cep_mailroom_extra_namespaces[i];
            break;
        }
    }

    if (spec) {
        size_t unique_add = 0u;
        cepDT* pending = NULL;

        for (size_t i = 0; i < bucket_count; ++i) {
            const char* tag = bucket_tags ? bucket_tags[i] : NULL;
            if (!tag || !tag[0]) {
                continue;
            }

            cepDT bucket_dt = {0};
            if (!cep_mailroom_dt_from_text(&bucket_dt, tag)) {
                cep_free(pending);
                return false;
            }

            bool duplicate = false;
            for (size_t j = 0; j < spec->bucket_count && !duplicate; ++j) {
                if (cep_dt_compare(&spec->bucket_dts[j], &bucket_dt) == 0) {
                    duplicate = true;
                }
            }
            for (size_t j = 0; j < unique_add && !duplicate; ++j) {
                if (cep_dt_compare(&pending[j], &bucket_dt) == 0) {
                    duplicate = true;
                }
            }
            if (duplicate) {
                continue;
            }

            cepDT* grown = cep_realloc(pending, (unique_add + 1u) * sizeof(cepDT));
            if (!grown) {
                cep_free(pending);
                return false;
            }
            pending = grown;
            pending[unique_add++] = bucket_dt;
        }

        if (unique_add) {
            cepDT* grown = cep_realloc(spec->bucket_dts, (spec->bucket_count + unique_add) * sizeof(cepDT));
            if (!grown) {
                cep_free(pending);
                return false;
            }
            memcpy(grown + spec->bucket_count, pending, unique_add * sizeof(cepDT));
            spec->bucket_dts = grown;
            spec->bucket_count += unique_add;
        }
        cep_free(pending);
        /* If bootstrap already ran, reseed to ensure buckets exist. */
    } else {
        if (!bucket_count) {
            return false;
        }

        cepMailroomNamespaceSpec* grown = cep_realloc(cep_mailroom_extra_namespaces,
            (cep_mailroom_extra_namespace_count + 1u) * sizeof(cepMailroomNamespaceSpec));
        if (!grown) {
            return false;
        }
        cep_mailroom_extra_namespaces = grown;
        spec = &cep_mailroom_extra_namespaces[cep_mailroom_extra_namespace_count++];
        memset(spec, 0, sizeof *spec);
        spec->namespace_dt = namespace_dt;

        spec->bucket_dts = cep_malloc(bucket_count * sizeof(cepDT));
        if (!spec->bucket_dts) {
            --cep_mailroom_extra_namespace_count;
            return false;
        }

        size_t stored = 0u;
        for (size_t i = 0; i < bucket_count; ++i) {
            const char* tag = bucket_tags ? bucket_tags[i] : NULL;
            if (!tag || !tag[0]) {
                continue;
            }

            cepDT bucket_dt = {0};
            if (!cep_mailroom_dt_from_text(&bucket_dt, tag)) {
                cep_free(spec->bucket_dts);
                --cep_mailroom_extra_namespace_count;
                return false;
            }

            bool duplicate = false;
            for (size_t j = 0; j < stored; ++j) {
                if (cep_dt_compare(&spec->bucket_dts[j], &bucket_dt) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                continue;
            }
            spec->bucket_dts[stored++] = bucket_dt;
        }

        if (!stored) {
            cep_free(spec->bucket_dts);
            --cep_mailroom_extra_namespace_count;
            return false;
        }
        spec->bucket_count = stored;
    }

    if (cep_mailroom_bootstrap_done) {
        cepCell* root = cep_root();
        cepCell* data_root = root ? cep_cell_find_by_name(root, dt_data_root()) : NULL;
        cepCell* inbox_root = data_root ? cep_cell_find_by_name(data_root, dt_inbox_root()) : NULL;
        if (!inbox_root) {
            return false;
        }

        cepMailroomNamespaceSpec* target = spec;
        if (target->bucket_count) {
            if (!cep_mailroom_seed_namespace(inbox_root, &target->namespace_dt,
                                             target->bucket_dts, target->bucket_count)) {
                return false;
            }
        }
    }

    return true;
}

bool cep_mailroom_add_router_before(const char* enzyme_tag) {
    if (!enzyme_tag || !enzyme_tag[0]) {
        return false;
    }

    if (cep_mailroom_registered_registry) {
        /* Router already registered; enforce call order. */
        return false;
    }

    cepDT enzyme_dt = {0};
    if (!cep_mailroom_dt_from_text(&enzyme_dt, enzyme_tag)) {
        return false;
    }

    const cepDT* base_before[] = {
        dt_coh_ing_be(),
        dt_coh_ing_bo(),
        dt_coh_ing_ctx(),
        dt_fl_ing(),
        dt_ni_ing(),
        dt_inst_ing(),
    };
    for (size_t i = 0; i < cep_lengthof(base_before); ++i) {
        if (cep_dt_compare(base_before[i], &enzyme_dt) == 0) {
            return true;
        }
    }

    for (size_t i = 0; i < cep_mailroom_router_before_extra_count; ++i) {
        if (cep_dt_compare(&cep_mailroom_router_before_extra[i], &enzyme_dt) == 0) {
            return true;
        }
    }

    cepDT* grown = cep_realloc(cep_mailroom_router_before_extra,
                               (cep_mailroom_router_before_extra_count + 1u) * sizeof(cepDT));
    if (!grown) {
        return false;
    }
    cep_mailroom_router_before_extra = grown;
    cep_mailroom_router_before_extra[cep_mailroom_router_before_extra_count++] = enzyme_dt;
    return true;
}

bool cep_mailroom_bootstrap(void) {
    if (!cep_cell_system_initialized()) {
        return false;
    }

    cepCell* root = cep_root();
    if (!root) {
        return false;
    }

    cepDT data_dt = cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("data"));
    cepCell* data_root = cep_mailroom_ensure_dictionary(root, &data_dt, CEP_STORAGE_RED_BLACK_T);
    if (!data_root) {
        return false;
    }

    cepDT inbox_dt = cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("inbox"));
    cepCell* inbox_root = cep_mailroom_ensure_dictionary(data_root, &inbox_dt, CEP_STORAGE_RED_BLACK_T);
    if (!inbox_root) {
        return false;
    }

    const cepDT coh_buckets[] = {
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("be_create")),
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("bo_upsert")),
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("ctx_upsert")),
    };
    cepDT coh_ns = cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("coh"));
    if (!cep_mailroom_seed_namespace(inbox_root, &coh_ns, coh_buckets, cep_lengthof(coh_buckets))) {
        return false;
    }

    const cepDT flow_buckets[] = {
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("fl_upsert")),
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("ni_upsert")),
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("inst_start")),
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("inst_event")),
        cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("inst_ctrl")),
    };
    cepDT flow_ns = cep_dt_make(CEP_ACRO("CEP"), CEP_WORD("flow"));
    if (!cep_mailroom_seed_namespace(inbox_root, &flow_ns, flow_buckets, cep_lengthof(flow_buckets))) {
        return false;
    }

    for (size_t i = 0; i < cep_mailroom_extra_namespace_count; ++i) {
        const cepMailroomNamespaceSpec* spec = &cep_mailroom_extra_namespaces[i];
        if (!spec->bucket_count) {
            continue;
        }
        if (!cep_mailroom_seed_namespace(inbox_root, &spec->namespace_dt, spec->bucket_dts, spec->bucket_count)) {
            return false;
        }
    }

    cepCell* sys_root = cep_mailroom_ensure_dictionary(root, dt_sys_root(), CEP_STORAGE_RED_BLACK_T);
    if (!sys_root) {
        return false;
    }

    if (!cep_mailroom_ensure_dictionary(sys_root, dt_err_cat(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    /* FIXME: consolidate catalog seeding with future mailroom persistence work once shutdown/reset is reconciled. */
    if (cep_mailroom_seed_errors_enabled) {
        if (!cep_mailroom_seed_coh_errors()) {
            return false;
        }

        if (!cep_mailroom_seed_flow_errors()) {
            return false;
        }
    }

    cep_mailroom_bootstrap_done = true;
    return true;
}

bool cep_mailroom_seed_coh_errors(void) {
    return cep_mailroom_seed_error_entries(CEP_MAILROOM_ERROR_COH,
                                           sizeof CEP_MAILROOM_ERROR_COH / sizeof CEP_MAILROOM_ERROR_COH[0]);
}

bool cep_mailroom_seed_flow_errors(void) {
    return cep_mailroom_seed_error_entries(CEP_MAILROOM_ERROR_FLOW,
                                           sizeof CEP_MAILROOM_ERROR_FLOW / sizeof CEP_MAILROOM_ERROR_FLOW[0]);
}

static bool cep_mailroom_namespace_supported(const cepCell* ns_node) {
    if (!ns_node) {
        return false;
    }
    if (cep_cell_name_is(ns_node, dt_mailroom_ns_coh()) ||
        cep_cell_name_is(ns_node, dt_mailroom_ns_flow())) {
        return true;
    }

    const cepDT* ns_dt = cep_cell_get_name(ns_node);
    if (!ns_dt) {
        return false;
    }

    for (size_t i = 0; i < cep_mailroom_extra_namespace_count; ++i) {
        if (cep_dt_compare(&cep_mailroom_extra_namespaces[i].namespace_dt, ns_dt) == 0) {
            return true;
        }
    }

    return false;
}

static int cep_mailroom_enzyme_init(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    return cep_mailroom_bootstrap() ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
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

    if (!cep_mailroom_ensure_shared_header(inserted)) {
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

    cepPathStatic2 init_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_init(), .timestamp = 0u},
        },
    };

    cepEnzymeDescriptor init_descriptor = {
        .name = *dt_mr_init(),
        .label = "mailroom.init",
        .callback = cep_mailroom_enzyme_init,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    if (cep_enzyme_register(registry, (const cepPath*)&init_path, &init_descriptor) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    const cepDT* base_before[] = {
        dt_coh_ing_be(),
        dt_coh_ing_bo(),
        dt_coh_ing_ctx(),
        dt_fl_ing(),
        dt_ni_ing(),
        dt_inst_ing(),
    };

    size_t base_count = cep_lengthof(base_before);
    size_t total_before = base_count + cep_mailroom_router_before_extra_count;
    cepDT* before_list = cep_malloc(sizeof(*before_list) * total_before);
    if (!before_list) {
        return false;
    }

    for (size_t i = 0; i < base_count; ++i) {
        before_list[i] = *base_before[i];
    }
    for (size_t i = 0; i < cep_mailroom_router_before_extra_count; ++i) {
        before_list[base_count + i] = cep_mailroom_router_before_extra[i];
    }

    cepEnzymeDescriptor descriptor = {
        .name = *dt_mr_route(),
        .label = "mailroom.route",
        .before = before_list,
        .before_count = total_before,
        .callback = cep_mailroom_route,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_PREFIX,
    };

    int reg_result = cep_enzyme_register(registry, (const cepPath*)&signal_path, &descriptor);
    cep_free(before_list);
    if (reg_result != CEP_ENZYME_SUCCESS) {
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
