/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_mailroom.h"

#include "cep_cell.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

CEP_DEFINE_STATIC_DT(dt_data_root,      CEP_ACRO("CEP"), CEP_WORD("data"))
CEP_DEFINE_STATIC_DT(dt_sys_root,       CEP_ACRO("CEP"), CEP_WORD("sys"))
CEP_DEFINE_STATIC_DT(dt_inbox_root,     CEP_ACRO("CEP"), CEP_WORD("inbox"))
CEP_DEFINE_STATIC_DT(dt_mailroom_ns_coh, CEP_ACRO("CEP"), CEP_WORD("coh"))
CEP_DEFINE_STATIC_DT(dt_mailroom_ns_flow, CEP_ACRO("CEP"), CEP_WORD("flow"))
CEP_DEFINE_STATIC_DT(dt_sys_log,        CEP_ACRO("CEP"), CEP_WORD("sys_log"))
CEP_DEFINE_STATIC_DT(dt_dictionary,     CEP_ACRO("CEP"), CEP_WORD("dictionary"))
CEP_DEFINE_STATIC_DT(dt_list,           CEP_ACRO("CEP"), CEP_WORD("list"))
CEP_DEFINE_STATIC_DT(dt_original,       CEP_ACRO("CEP"), CEP_WORD("original"))
CEP_DEFINE_STATIC_DT(dt_outcome,        CEP_ACRO("CEP"), CEP_WORD("outcome"))
CEP_DEFINE_STATIC_DT(dt_meta,           CEP_ACRO("CEP"), CEP_WORD("meta"))
CEP_DEFINE_STATIC_DT(dt_parents,        CEP_ACRO("CEP"), CEP_WORD("parents"))
CEP_DEFINE_STATIC_DT(dt_sig_cell,       CEP_ACRO("CEP"), CEP_WORD("sig_cell"))
CEP_DEFINE_STATIC_DT(dt_op_add,         CEP_ACRO("CEP"), CEP_WORD("op_add"))
CEP_DEFINE_STATIC_DT(dt_mailroom_meta,  CEP_ACRO("CEP"), CEP_WORD("mailroom"))
CEP_DEFINE_STATIC_DT(dt_mailroom_buckets, CEP_ACRO("CEP"), CEP_WORD("buckets"))
CEP_DEFINE_STATIC_DT(dt_log_payload,    CEP_ACRO("CEP"), CEP_WORD("log"))

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

static bool cep_mailroom_id_to_text(cepID id, char* buffer, size_t capacity, size_t* len_out) {
    if (!buffer || capacity == 0u) {
        return false;
    }

    size_t len = 0u;

    if (cep_id_is_word(id)) {
        len = cep_word_to_text(id, buffer);
    } else if (cep_id_is_acronym(id)) {
        len = cep_acronym_to_text(id, buffer);
    } else if (cep_id_is_reference(id)) {
        size_t source_len = 0u;
        const char* text = cep_namepool_lookup(id, &source_len);
        if (!text || source_len + 1u > capacity) {
            return false;
        }
        memcpy(buffer, text, source_len);
        buffer[source_len] = '\0';
        len = source_len;
    } else {
        return false;
    }

    if (!len || len + 1u > capacity) {
        return false;
    }

    buffer[len] = '\0';
    if (len_out) {
        *len_out = len;
    }
    return true;
}

static bool cep_mailroom_scope_to_text(const cepDT* scope_dt, char* buffer, size_t capacity) {
    if (!scope_dt || !buffer || capacity == 0u) {
        return false;
    }

    char domain[32];
    char tag[64];
    size_t domain_len = 0u;
    size_t tag_len = 0u;

    if (!cep_mailroom_id_to_text(scope_dt->domain, domain, sizeof domain, &domain_len)) {
        return false;
    }
    if (!cep_mailroom_id_to_text(scope_dt->tag, tag, sizeof tag, &tag_len)) {
        return false;
    }

    size_t required = domain_len + 1u + tag_len + 1u;
    if (required > capacity) {
        return false;
    }

    memcpy(buffer, domain, domain_len);
    buffer[domain_len] = ':';
    memcpy(buffer + domain_len + 1u, tag, tag_len);
    buffer[domain_len + 1u + tag_len] = '\0';
    return true;
}

static void cep_mailroom_report_catalog_issue(const cepDT* scope_dt, const char* issue) {
    if (!issue || !issue[0]) {
        return;
    }

    cepCell* journal = cep_heartbeat_journal_root();
    if (!journal) {
        return;
    }

    cepCell* sys_log = cep_cell_find_by_name(journal, dt_sys_log());
    if (!sys_log) {
        cepDT name = *dt_sys_log();
        cepDT type = *dt_list();
        sys_log = cep_cell_add_list(journal, &name, 0, &type, CEP_STORAGE_LINKED_LIST);
        if (!sys_log)
            return;
    }

    const char* scope_text = "unknown";
    char scope_buffer[96];
    if (scope_dt && cep_mailroom_scope_to_text(scope_dt, scope_buffer, sizeof scope_buffer)) {
        scope_text = scope_buffer;
    }

    int written = snprintf(NULL, 0, "mailroom.catalog scope=%s issue=%s", scope_text, issue);
    if (written < 0) {
        return;
    }

    size_t size = (size_t)written + 1u;
    char* message = cep_malloc(size);
    if (!message) {
        return;
    }
    (void)snprintf(message, size, "mailroom.catalog scope=%s issue=%s", scope_text, issue);

    cepDT entry_name = {
        .domain = CEP_ACRO("HB"),
        .tag = CEP_AUTOID,
        .glob = 0u,
    };

    cepDT payload_type = *dt_log_payload();
    (void)cep_cell_append_value(sys_log, &entry_name, &payload_type, message, size, size);
    cep_free(message);
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

typedef struct {
    cepEnzymeRegistry* registry;
} cepMailroomRegistryEntry;

static cepMailroomRegistryEntry* cep_mailroom_registrations = NULL;
static size_t cep_mailroom_registration_count = 0u;

CEP_DEFINE_STATIC_DT(dt_sig_sys,  CEP_ACRO("CEP"), CEP_WORD("sig_sys"))
CEP_DEFINE_STATIC_DT(dt_sys_init, CEP_ACRO("CEP"), CEP_WORD("init"))
CEP_DEFINE_STATIC_DT(dt_err_cat,  CEP_ACRO("CEP"), CEP_WORD("err_cat"))
CEP_DEFINE_STATIC_DT(dt_mr_route, CEP_ACRO("CEP"), CEP_WORD("mr_route"))
CEP_DEFINE_STATIC_DT(dt_mr_init,  CEP_ACRO("CEP"), CEP_WORD("mr_init"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_be,  CEP_ACRO("CEP"), CEP_WORD("coh_ing_be"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_bo,  CEP_ACRO("CEP"), CEP_WORD("coh_ing_bo"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_ctx, CEP_ACRO("CEP"), CEP_WORD("coh_ing_ctx"))
CEP_DEFINE_STATIC_DT(dt_fl_ing,   CEP_ACRO("CEP"), CEP_WORD("fl_ing"))
CEP_DEFINE_STATIC_DT(dt_ni_ing,   CEP_ACRO("CEP"), CEP_WORD("ni_ing"))
CEP_DEFINE_STATIC_DT(dt_inst_ing, CEP_ACRO("CEP"), CEP_WORD("inst_ing"))

static bool cep_mailroom_bindings_applied = false;

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
    (void)cep_lifecycle_scope_mark_teardown(CEP_LIFECYCLE_SCOPE_MAILROOM);
    cep_mailroom_free_extra_namespaces();
    cep_mailroom_free_router_before();
    cep_free(cep_mailroom_registrations);
    cep_mailroom_registrations = NULL;
    cep_mailroom_registration_count = 0u;
    cep_mailroom_bootstrap_done = false;
    cep_mailroom_bindings_applied = false;
}

static cepCell* cep_mailroom_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }
    return cep_cell_ensure_dictionary_child(parent, name, storage ? storage : CEP_STORAGE_RED_BLACK_T);
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

static bool cep_mailroom_seed_from_catalog(cepCell* inbox_root,
                                           cepCell* err_catalog,
                                           bool* seeded_any_out) {
    if (!inbox_root || !err_catalog || !cep_cell_has_store(err_catalog)) {
        if (seeded_any_out) {
            *seeded_any_out = false;
        }
        return true;
    }

    bool seeded = false;

    for (cepCell* scope = cep_cell_first(err_catalog); scope; scope = cep_cell_next(err_catalog, scope)) {
        const cepDT* scope_dt = cep_cell_get_name(scope);
        if (!scope_dt) {
            continue;
        }

        if (!cep_cell_has_store(scope)) {
            cep_mailroom_report_catalog_issue(scope_dt, "scope-without-dictionary");
            return false;
        }

        cepCell* mailroom_cfg = cep_cell_find_by_name(scope, dt_mailroom_meta());
        if (!mailroom_cfg) {
            cep_mailroom_report_catalog_issue(scope_dt, "missing-mailroom-node");
            return false;
        }
        if (!cep_cell_has_store(mailroom_cfg)) {
            cep_mailroom_report_catalog_issue(scope_dt, "mailroom-node-not-dictionary");
            return false;
        }

        cepCell* buckets = cep_cell_find_by_name(mailroom_cfg, dt_mailroom_buckets());
        if (!buckets) {
            cep_mailroom_report_catalog_issue(scope_dt, "missing-mailroom-buckets");
            return false;
        }
        if (!cep_cell_has_store(buckets)) {
            cep_mailroom_report_catalog_issue(scope_dt, "mailroom-buckets-not-dictionary");
            return false;
        }

        cepCell* ns_root = cep_mailroom_ensure_dictionary(inbox_root, scope_dt, CEP_STORAGE_RED_BLACK_T);
        if (!ns_root) {
            return false;
        }

        bool scope_seeded = false;
        for (cepCell* bucket = cep_cell_first(buckets); bucket; bucket = cep_cell_next(buckets, bucket)) {
            const cepDT* bucket_dt = cep_cell_get_name(bucket);
            if (!bucket_dt) {
                continue;
            }
            if (!cep_mailroom_ensure_dictionary(ns_root, bucket_dt, CEP_STORAGE_RED_BLACK_T)) {
                return false;
            }
            scope_seeded = true;
            seeded = true;
        }

        if (!scope_seeded) {
            cep_mailroom_report_catalog_issue(scope_dt, "mailroom-buckets-empty");
            return false;
        }
    }

    if (seeded_any_out) {
        *seeded_any_out = seeded;
    }
    return true;
}

static bool cep_mailroom_seed_default_namespaces(cepCell* inbox_root) {
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

    return true;
}

static bool cep_mailroom_catalog_has_namespace(const cepDT* ns_dt) {
    if (!ns_dt) {
        return false;
    }

    cepCell* root = cep_root();
    if (!root) {
        return false;
    }

    cepCell* sys_root = cep_cell_find_by_name(root, dt_sys_root());
    if (!sys_root) {
        return false;
    }

    cepCell* err_catalog = cep_cell_find_by_name(sys_root, dt_err_cat());
    if (!err_catalog || !cep_cell_has_store(err_catalog)) {
        return false;
    }

    cepDT lookup = cep_dt_clean(ns_dt);
    lookup.glob = 0u;
    cepCell* scope = cep_cell_find_by_name(err_catalog, &lookup);
    if (!scope || !cep_cell_has_store(scope)) {
        return false;
    }

    cepCell* mailroom_cfg = cep_cell_find_by_name(scope, dt_mailroom_meta());
    if (!mailroom_cfg || !cep_cell_has_store(mailroom_cfg)) {
        return false;
    }

    cepCell* buckets = cep_cell_find_by_name(mailroom_cfg, dt_mailroom_buckets());
    if (!buckets || !cep_cell_has_store(buckets)) {
        return false;
    }

    return cep_cell_children(buckets) > 0u;
}

static bool cep_mailroom_set_string_value(cepCell* parent, const cepDT* name, const char* text) {
    if (!parent || !name || !text) {
        return false;
    }
    cepCell* resolved = parent;
    cepStore* store = NULL;
    if (!cep_cell_require_store(&resolved, &store)) {
        return false;
    }

    bool restore = false;
    unsigned previous = 0u;
    if (store && !store->writable) {
        previous = store->writable;
        store->writable = true;
        restore = true;
    }

    bool ok = cep_cell_put_text(resolved, name, text);

    if (restore) {
        store->writable = previous;
    }
    return ok;
}

/* Reseed the unified inbox so restarts and replays rebuild the lobby exactly
 * like a fresh bootstrap, mirroring error catalog buckets and any extra
 * namespaces packs queued ahead of time. */
static bool cep_mailroom_reseed_lobby(void) {
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

    cepCell* sys_root = cep_cell_find_by_name(root, dt_sys_root());
    if (!sys_root) {
        return false;
    }

    cepCell* err_catalog = cep_cell_find_by_name(sys_root, dt_err_cat());
    if (!err_catalog) {
        err_catalog = cep_mailroom_ensure_dictionary(sys_root, dt_err_cat(), CEP_STORAGE_RED_BLACK_T);
        if (!err_catalog) {
            return false;
        }
    }

    bool seeded_from_catalog = false;
    if (!cep_mailroom_seed_from_catalog(inbox_root, err_catalog, &seeded_from_catalog)) {
        return false;
    }

    if (!seeded_from_catalog) {
        if (!cep_mailroom_seed_default_namespaces(inbox_root)) {
            return false;
        }
    }

    for (size_t i = 0; i < cep_mailroom_extra_namespace_count; ++i) {
        const cepMailroomNamespaceSpec* spec = &cep_mailroom_extra_namespaces[i];
        if (!spec || !spec->bucket_count) {
            continue;
        }
        if (!cep_mailroom_seed_namespace(inbox_root,
                                         &spec->namespace_dt,
                                         spec->bucket_dts,
                                         spec->bucket_count)) {
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

    if (cep_mailroom_registration_count > 0u) {
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

bool cep_mailroom_enqueue_signal(const cepDT* namespace_dt,
                                 const cepDT* bucket_dt,
                                 const cepDT* txn_dt) {
    if (!namespace_dt || !bucket_dt || !txn_dt) {
        return false;
    }

    if (!cep_dt_is_valid(namespace_dt) || !cep_dt_is_valid(bucket_dt) || !cep_dt_is_valid(txn_dt)) {
        return false;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepPathStatic2;

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[5];
    } cepPathStatic5;

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    cepPathStatic5 target_path = {
        .length = 5u,
        .capacity = 5u,
        .past = {
            {.dt = *dt_data_root(), .timestamp = 0u},
            {.dt = *dt_inbox_root(), .timestamp = 0u},
            {.dt = *namespace_dt, .timestamp = 0u},
            {.dt = *bucket_dt, .timestamp = 0u},
            {.dt = *txn_dt, .timestamp = 0u},
        },
    };

    return cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                        (const cepPath*)&signal_path,
                                        (const cepPath*)&target_path) == CEP_ENZYME_SUCCESS;
}

bool cep_mailroom_bootstrap(void) {
    if (cep_mailroom_bootstrap_done) {
        (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_MAILROOM);
        return true;
    }

    if (!cep_mailroom_reseed_lobby()) {
        return false;
    }

    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_MAILROOM);
    cep_mailroom_bootstrap_done = true;
    return true;
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

    return cep_mailroom_catalog_has_namespace(ns_dt);
}

static int cep_mailroom_enzyme_init(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    if (!cep_mailroom_reseed_lobby()) {
        return CEP_ENZYME_FATAL;
    }
    cep_mailroom_bootstrap_done = true;
    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_MAILROOM);
    return CEP_ENZYME_SUCCESS;
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

    const cepDT* txn_name_ptr = cep_cell_get_name(txn);
    if (!txn_name_ptr) {
        return CEP_ENZYME_SUCCESS;
    }
    cepDT txn_name = cep_dt_clean(txn_name_ptr);

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
    cepDT dest_bucket_clean = cep_dt_clean(dest_bucket_name);

    const cepDT* ns_name_ptr = cep_cell_get_name(ns_node);
    if (!ns_name_ptr) {
        return CEP_ENZYME_SUCCESS;
    }
    cepDT ns_clean = cep_dt_clean(ns_name_ptr);

    cepCell* layer_root = cep_cell_find_by_name(data_root, &ns_clean);
    if (!layer_root) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* layer_inbox = cep_cell_find_by_name(layer_root, dt_inbox_root());
    if (!layer_inbox) {
        return CEP_ENZYME_SUCCESS;
    }

    cepCell* dest_bucket = cep_cell_find_by_name(layer_inbox, &dest_bucket_clean);
    if (!dest_bucket) {
        return CEP_ENZYME_SUCCESS;
    }

    if (cep_cell_find_by_name(dest_bucket, &txn_name)) {
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

    cepDT audit_name = txn_name;
    cepCell* audit_link = cep_dict_add_link(intent_bucket, &audit_name, inserted);
    if (audit_link) {
        cepCell* parents[] = { audit_link };
        (void)cep_cell_add_parents(inserted, parents, cep_lengthof(parents));
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepPathStatic2;

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[5];
    } cepPathStatic5;

    cepPathStatic2 signal_path_local = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    cepPathStatic5 target_path_local = {
        .length = 5u,
        .capacity = 5u,
        .past = {
            {.dt = *dt_data_root(), .timestamp = 0u},
            {.dt = ns_clean, .timestamp = 0u},
            {.dt = *dt_inbox_root(), .timestamp = 0u},
            {.dt = dest_bucket_clean, .timestamp = 0u},
            {.dt = txn_name, .timestamp = 0u},
        },
    };

    if (cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                     (const cepPath*)&signal_path_local,
                                     (const cepPath*)&target_path_local) != CEP_ENZYME_SUCCESS) {
        return CEP_ENZYME_FATAL;
    }

    fprintf(stderr, "[debug] routed %" PRIu64 " to inbox\n", (unsigned long long)txn_name.tag);

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

    for (size_t i = 0; i < cep_mailroom_registration_count; ++i) {
        if (cep_mailroom_registrations[i].registry == registry) {
            return true;
        }
    }

    cepMailroomRegistryEntry* grown = cep_realloc(
        cep_mailroom_registrations,
        (cep_mailroom_registration_count + 1u) * sizeof(*grown));
    if (!grown) {
        return false;
    }
    cep_mailroom_registrations = grown;

    size_t registration_slot = cep_mailroom_registration_count;

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
    cepDT* before_list = NULL;
    if (total_before) {
        before_list = cep_malloc(sizeof(*before_list) * total_before);
        if (!before_list) {
            return false;
        }

        for (size_t i = 0; i < base_count; ++i) {
            before_list[i] = *base_before[i];
        }
        for (size_t i = 0; i < cep_mailroom_router_before_extra_count; ++i) {
            before_list[base_count + i] = cep_mailroom_router_before_extra[i];
        }
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

    cep_mailroom_registrations[registration_slot].registry = registry;
    ++cep_mailroom_registration_count;

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
