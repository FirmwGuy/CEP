/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_coherence.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_identifier.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_l0.h"
#include "../l0_kernel/cep_mailroom.h"
#include "../l0_kernel/cep_namepool.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/* ------------------------------------------------------------------------- */
/*  Domain and canonical tags                                                */
/* ------------------------------------------------------------------------- */

static bool cep_l1_bindings_applied = false;

static cepID cep_domain_cep(void) {
    return CEP_ACRO("CEP");
}

CEP_DEFINE_STATIC_DT(dt_dictionary, CEP_ACRO("CEP"), CEP_WORD("dictionary"))
CEP_DEFINE_STATIC_DT(dt_text, CEP_ACRO("CEP"), CEP_WORD("text"))
CEP_DEFINE_STATIC_DT(dt_kind, CEP_ACRO("CEP"), CEP_WORD("kind"))
CEP_DEFINE_STATIC_DT(dt_type, CEP_ACRO("CEP"), CEP_WORD("type"))
CEP_DEFINE_STATIC_DT(dt_roles, CEP_ACRO("CEP"), CEP_WORD("roles"))
CEP_DEFINE_STATIC_DT(dt_facets, CEP_ACRO("CEP"), CEP_WORD("facets"))
CEP_DEFINE_STATIC_DT(dt_src, CEP_ACRO("CEP"), CEP_WORD("src"))
CEP_DEFINE_STATIC_DT(dt_dst, CEP_ACRO("CEP"), CEP_WORD("dst"))
CEP_DEFINE_STATIC_DT(dt_directed, CEP_ACRO("CEP"), CEP_WORD("directed"))
CEP_DEFINE_STATIC_DT(dt_original, CEP_ACRO("CEP"), CEP_WORD("original"))
CEP_DEFINE_STATIC_DT(dt_target, CEP_ACRO("CEP"), CEP_WORD("target"))
CEP_DEFINE_STATIC_DT(dt_inbox, CEP_ACRO("CEP"), CEP_WORD("inbox"))
CEP_DEFINE_STATIC_DT(dt_be_create, CEP_ACRO("CEP"), CEP_WORD("be_create"))
CEP_DEFINE_STATIC_DT(dt_bo_upsert, CEP_ACRO("CEP"), CEP_WORD("bo_upsert"))
CEP_DEFINE_STATIC_DT(dt_ctx_upsert, CEP_ACRO("CEP"), CEP_WORD("ctx_upsert"))
CEP_DEFINE_STATIC_DT(dt_being, CEP_ACRO("CEP"), CEP_WORD("being"))
CEP_DEFINE_STATIC_DT(dt_bond, CEP_ACRO("CEP"), CEP_WORD("bond"))
CEP_DEFINE_STATIC_DT(dt_context, CEP_ACRO("CEP"), CEP_WORD("context"))
CEP_DEFINE_STATIC_DT(dt_facet_root, CEP_ACRO("CEP"), CEP_WORD("facet"))
CEP_DEFINE_STATIC_DT(dt_debt, CEP_ACRO("CEP"), CEP_WORD("debt"))
CEP_DEFINE_STATIC_DT(dt_decision, CEP_ACRO("CEP"), CEP_WORD("decision"))
CEP_DEFINE_STATIC_DT(dt_index, CEP_ACRO("CEP"), CEP_WORD("index"))
CEP_DEFINE_STATIC_DT(dt_coh, CEP_ACRO("CEP"), CEP_WORD("coh"))
CEP_DEFINE_STATIC_DT(dt_data_root, CEP_ACRO("CEP"), CEP_WORD("data"))
CEP_DEFINE_STATIC_DT(dt_sys, CEP_ACRO("CEP"), CEP_WORD("sys"))
CEP_DEFINE_STATIC_DT(dt_tmp, CEP_ACRO("CEP"), CEP_WORD("tmp"))
CEP_DEFINE_STATIC_DT(dt_adj, CEP_ACRO("CEP"), CEP_WORD("adj"))
CEP_DEFINE_STATIC_DT(dt_by_being, CEP_ACRO("CEP"), CEP_WORD("by_being"))
CEP_DEFINE_STATIC_DT(dt_signal_cell, CEP_ACRO("CEP"), CEP_WORD("sig_cell"))
CEP_DEFINE_STATIC_DT(dt_op_add, CEP_ACRO("CEP"), CEP_WORD("op_add"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_be, CEP_ACRO("CEP"), CEP_WORD("coh_ing_be"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_bo, CEP_ACRO("CEP"), CEP_WORD("coh_ing_bo"))
CEP_DEFINE_STATIC_DT(dt_coh_ing_ctx, CEP_ACRO("CEP"), CEP_WORD("coh_ing_ctx"))
CEP_DEFINE_STATIC_DT(dt_coh_closure, CEP_ACRO("CEP"), CEP_WORD("coh_closure"))
CEP_DEFINE_STATIC_DT(dt_coh_index, CEP_ACRO("CEP"), CEP_WORD("coh_index"))
CEP_DEFINE_STATIC_DT(dt_coh_adj, CEP_ACRO("CEP"), CEP_WORD("coh_adj"))
CEP_DEFINE_STATIC_DT(dt_be_kind, CEP_ACRO("CEP"), CEP_WORD("be_kind"))
CEP_DEFINE_STATIC_DT(dt_bo_pair, CEP_ACRO("CEP"), CEP_WORD("bo_pair"))
CEP_DEFINE_STATIC_DT(dt_ctx_type, CEP_ACRO("CEP"), CEP_WORD("ctx_type"))
CEP_DEFINE_STATIC_DT(dt_fa_ctx, CEP_ACRO("CEP"), CEP_WORD("fa_ctx"))
CEP_DEFINE_STATIC_DT(dt_id, CEP_ACRO("CEP"), CEP_WORD("id"))
CEP_DEFINE_STATIC_DT(dt_outcome, CEP_ACRO("CEP"), CEP_WORD("outcome"))
CEP_DEFINE_STATIC_DT(dt_out_bonds, CEP_ACRO("CEP"), CEP_WORD("out_bonds"))
CEP_DEFINE_STATIC_DT(dt_in_bonds, CEP_ACRO("CEP"), CEP_WORD("in_bonds"))
CEP_DEFINE_STATIC_DT(dt_ctx_by_role, CEP_ACRO("CEP"), CEP_WORD("ctx_by_role"))
CEP_DEFINE_STATIC_DT(dt_required, CEP_ACRO("CEP"), CEP_WORD("required"))
CEP_DEFINE_STATIC_DT(dt_attrs, CEP_ACRO("CEP"), CEP_WORD("attrs"))
CEP_DEFINE_STATIC_DT(dt_latency, CEP_ACRO("CEP"), CEP_WORD("latency"))
CEP_DEFINE_STATIC_DT(dt_lat_window, CEP_ACRO("CEP"), CEP_WORD("lat_window"))
CEP_DEFINE_STATIC_DT(dt_err_window, CEP_ACRO("CEP"), CEP_WORD("err_window"))
CEP_DEFINE_STATIC_DT(dt_choice, CEP_ACRO("CEP"), CEP_WORD("choice"))
CEP_DEFINE_STATIC_DT(dt_retain_mode, CEP_ACRO("CEP"), CEP_WORD("retain_mode"))
CEP_DEFINE_STATIC_DT(dt_retain_ttl, CEP_ACRO("CEP"), CEP_WORD("retain_ttl"))
CEP_DEFINE_STATIC_DT(dt_retain_upto, CEP_ACRO("CEP"), CEP_WORD("retain_upto"))
CEP_DEFINE_STATIC_DT(dt_retention_root, CEP_ACRO("CEP"), CEP_WORD("retention"))
CEP_DEFINE_STATIC_DT(dt_sig_sys, CEP_ACRO("CEP"), CEP_WORD("sig_sys"))
CEP_DEFINE_STATIC_DT(dt_sys_init, CEP_ACRO("CEP"), CEP_WORD("init"))
CEP_DEFINE_STATIC_DT(dt_coh_init, CEP_ACRO("CEP"), CEP_WORD("coh_init"))
CEP_DEFINE_STATIC_DT(dt_sys_teardown, CEP_ACRO("CEP"), CEP_WORD("teardown"))
CEP_DEFINE_STATIC_DT(dt_scope_l1, CEP_ACRO("CEP"), CEP_WORD("l1"))
CEP_DEFINE_STATIC_DT(dt_coh_shutdown, CEP_ACRO("CEP"), CEP_WORD("coh_shut"))
CEP_DEFINE_STATIC_DT(dt_sys_ready, CEP_ACRO("CEP"), CEP_WORD("ready"))
static const cepDT* dt_l1_ready(void) {
    static cepDT value;
    static bool initialized = false;
    if (!initialized) {
        static const char tag_text[] = "l1_ready";
        value.domain = CEP_ACRO("CEP");
        value.tag = cep_namepool_intern_static(tag_text, sizeof(tag_text) - 1u);
        if (!value.tag) {
            (void)cep_namepool_bootstrap();
            value.tag = cep_namepool_intern(tag_text, sizeof(tag_text) - 1u);
        }
        value.glob = cep_id_has_glob_char(value.tag);
        initialized = true;
    }
    return &value;
}

#define CEP_L1_WINDOW_CAP 8u

typedef struct {
    size_t beat;
    size_t value;
    size_t flag;
} cepL1WindowSample;

typedef enum {
    CEP_L1_RETAIN_UNSPECIFIED = 0,
    CEP_L1_RETAIN_PERMANENT,
    CEP_L1_RETAIN_TTL,
    CEP_L1_RETAIN_ARCHIVE,
} cepL1RetentionMode;

static cepL1WindowSample cep_l1_index_metrics[CEP_L1_WINDOW_CAP];
static size_t            cep_l1_index_metric_count = 0u;
static cepL1WindowSample cep_l1_adj_metrics[CEP_L1_WINDOW_CAP];
static size_t            cep_l1_adj_metric_count = 0u;

static bool cep_l1_set_string_value(cepCell* parent, const cepDT* name, const char* text);
static bool cep_l1_ensure_retention_config(void);
static bool cep_l1_decision_apply_retention(cepCell* entry, cepCell* request, cepBeatNumber decision_beat);
static bool cep_l1_retention_fetch_config(const char** mode_out, size_t* ttl_out, size_t* upto_out);
static const char* cep_l1_get_string(cepCell* parent, const cepDT* field);
static bool cep_l1_parse_size_text(const char* text, size_t* out_value);
static void cep_l1_remove_field(cepCell* parent, const cepDT* field);
static int cep_l1_enzyme_init(const cepPath* signal, const cepPath* target);
static int cep_l1_enzyme_shutdown(const cepPath* signal, const cepPath* target);
static void cep_l1_reset_runtime_state(void);
static bool cep_l1_emit_scope_ready_signal(void);


typedef struct {
    cepCell*    cell;
    cepLockToken token;
    bool         locked;
} cepL1StoreLock;

typedef struct {
    cepCell*    cell;
    cepLockToken token;
    bool         locked;
} cepL1DataLock;

static void cep_l1_store_unlock(cepL1StoreLock* guard);
static void cep_l1_data_unlock(cepL1DataLock* guard);

static bool cep_l1_store_lock(cepCell* cell, cepL1StoreLock* guard) {
    if (!guard) {
        return false;
    }

    guard->cell = NULL;
    guard->locked = false;

    if (!cell || !cep_cell_has_store(cell)) {
        return false;
    }

    if (!cep_store_lock(cell, &guard->token)) {
        return false;
    }

    guard->cell = cell;
    guard->locked = true;
    return true;
}

static void cep_l1_store_unlock(cepL1StoreLock* guard) {
    if (!guard || !guard->locked || !guard->cell) {
        return;
    }
    cep_store_unlock(guard->cell, &guard->token);
    guard->cell = NULL;
    guard->locked = false;
}

static bool cep_l1_data_lock(cepCell* cell, cepL1DataLock* guard) {
    if (!guard) {
        return false;
    }

    guard->cell = NULL;
    guard->locked = false;

    if (!cell || !cep_cell_has_data(cell)) {
        return false;
    }

    if (!cep_data_lock(cell, &guard->token)) {
        return false;
    }

    guard->cell = cell;
    guard->locked = true;
    return true;
}

static void cep_l1_data_unlock(cepL1DataLock* guard) {
    if (!guard || !guard->locked || !guard->cell) {
        return;
    }
    cep_data_unlock(guard->cell, &guard->token);
    guard->cell = NULL;
    guard->locked = false;
}

static void cep_l1_mark_outcome_error(cepCell* request, const char* code);
static bool cep_l1_require_role_name(const cepDT* role_name, cepCell* request);
static bool cep_l1_text_to_dt_bytes(const char* text, size_t length, cepDT* out);
static bool cep_l1_extract_identifier(cepCell* request,
                                      const cepDT* field,
                                      const char* missing_code,
                                      const char* invalid_code,
                                      cepDT* out_dt,
                                      const cepData** out_data);
static char* cep_l1_dt_to_owned_cstr(const cepDT* dt, size_t* out_len);
static cepCell* cep_l1_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage);
static void cep_l1_clear_children(cepCell* cell);
static cepCell* cep_l1_index_root(void);
static cepCell* cep_l1_adj_root(void);

/* ------------------------------------------------------------------------- */
/*  Small helpers                                                            */
/* ------------------------------------------------------------------------- */

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

        cepL1DataLock data_lock;
        if (!cep_l1_data_lock(existing, &data_lock)) {
            return false;
        }

        cepCell* updated = cep_cell_update(existing, size, size, (void*)bytes, false);
        cep_l1_data_unlock(&data_lock);
        if (!updated) {
            return false;
        }

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

/* Copy the `attrs` dictionary from the request into the ledger node so callers
   can persist arbitrary attributes alongside beings without poking internals. */
static void cep_l1_mark_outcome_error(cepCell* request, const char* code) {
    if (!request) {
        return;
    }
    if (!code) {
        code = "error";
    }
    cep_l1_set_string_value(request, dt_outcome(), code);
}

static bool cep_l1_text_to_dt_bytes(const char* text, size_t length, cepDT* out) {
    if (!text || !length || !out) {
        return false;
    }

    CEP_DT_CLEAN_COPY(out, NULL);

    cepID id = cep_namepool_intern(text, length);
    if (!id) {
        return false;
    }

    out->domain = cep_domain_cep();
    out->tag = id;
    return true;
}

/* Delegate identifier composition to the shared L0 helper so every layer
 * normalises tokens identically without duplicating validation logic. */
bool cep_l1_compose_identifier(const char* const tokens[],
                               size_t token_count,
                               char* out_buffer,
                               size_t out_cap) {
    return cep_compose_identifier(tokens, token_count, out_buffer, out_cap);
}

bool cep_l1_tokens_to_dt(const char* const tokens[], size_t token_count, cepDT* out_dt) {
    if (!out_dt) {
        return false;
    }

    char canonical[CEP_L1_IDENTIFIER_MAX + 1u];
    if (!cep_l1_compose_identifier(tokens, token_count, canonical, sizeof canonical)) {
        return false;
    }

    CEP_DT_CLEAN_COPY(out_dt, NULL);
    cepID word = cep_text_to_word(canonical);
    if (word) {
        out_dt->domain = cep_domain_cep();
        out_dt->tag = word;
        return true;
    }

    size_t length = strlen(canonical);
    cepID reference = cep_namepool_intern(canonical, length);
    if (!reference) {
        return false;
    }
    out_dt->domain = cep_domain_cep();
    out_dt->tag = reference;
    return true;
}

static cepCell* cep_l1_coh_root(void);
static cepCell* cep_l1_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage);
static bool     cep_l1_set_link_field(cepCell* parent, const cepDT* name, cepCell* target);

static bool cep_l1_tokens_compose_original(const char* const tokens[],
                                           size_t token_count,
                                           char* out_buffer,
                                           size_t out_cap) {
    if (!tokens || !token_count || !out_buffer || out_cap == 0u) {
        return false;
    }

    size_t pos = 0u;
    for (size_t i = 0; i < token_count; ++i) {
        const char* token = tokens[i];
        if (!token) {
            return false;
        }

        while (*token == ' ' || *token == '\t' || *token == '\n' || *token == '\r') {
            ++token;
        }

        size_t len = strlen(token);
        while (len && (token[len - 1u] == ' ' || token[len - 1u] == '\t' || token[len - 1u] == '\n' || token[len - 1u] == '\r')) {
            --len;
        }
        if (!len) {
            return false;
        }

        for (size_t j = 0; j < len; ++j) {
            unsigned char ch = (unsigned char)token[j];
            if (ch == ':') {
                return false;
            }
            if (!((ch >= 'a' && ch <= 'z') ||
                  (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') ||
                  ch == '-' || ch == '_' || ch == '.' || ch == '/')) {
                return false;
            }

            if (pos >= out_cap - 1u || pos >= CEP_L1_IDENTIFIER_MAX) {
                return false;
            }
            out_buffer[pos++] = (char)ch;
        }

        if (i + 1u < token_count) {
            if (pos >= out_cap - 1u || pos >= CEP_L1_IDENTIFIER_MAX) {
                return false;
            }
            out_buffer[pos++] = ':';
        }
    }

    if (!pos) {
        return false;
    }
    out_buffer[pos] = '\0';
    return true;
}

static cepCell* cep_l1_inbox_bucket(const cepDT* bucket_name) {
    if (!bucket_name) {
        return NULL;
    }

    cepCell* root = cep_root();
    cepCell* data = cep_cell_find_by_name(root, dt_data_root());
    if (!data) {
        return NULL;
    }

    cepCell* mailroom = cep_cell_find_by_name(data, dt_inbox());
    if (!mailroom || !cep_cell_has_store(mailroom)) {
        return NULL;
    }

    cepCell* coh_ns = cep_cell_find_by_name(mailroom, dt_coh());
    if (!coh_ns || !cep_cell_has_store(coh_ns)) {
        return NULL;
    }

    return cep_cell_find_by_name(coh_ns, bucket_name);
}

static bool cep_l1_store_original_value(cepCell* original_root,
                                        const cepDT* field,
                                        const char* const tokens[],
                                        size_t token_count) {
    if (!original_root || !field) {
        return true;
    }

    char original_buffer[CEP_L1_IDENTIFIER_MAX + 1u];
    if (!cep_l1_tokens_compose_original(tokens, token_count, original_buffer, sizeof original_buffer)) {
        return false;
    }

    return cep_l1_set_string_value(original_root, field, original_buffer);
}

static bool cep_l1_store_original_child(cepCell* original_root,
                                        const cepDT* branch_name,
                                        const cepDT* entry_name,
                                        const char* const tokens[],
                                        size_t token_count) {
    if (!original_root || !branch_name || !entry_name) {
        return true;
    }

    cepCell* branch = cep_l1_ensure_dictionary(original_root, branch_name, CEP_STORAGE_RED_BLACK_T);
    if (!branch) {
        return false;
    }

    char original_buffer[CEP_L1_IDENTIFIER_MAX + 1u];
    if (!cep_l1_tokens_compose_original(tokens, token_count, original_buffer, sizeof original_buffer)) {
        return false;
    }

    return cep_l1_set_string_value(branch, entry_name, original_buffer);
}

static bool cep_l1_assign_identifier_field(cepCell* request,
                                           cepCell* original_root,
                                           const cepDT* field,
                                           const char* const tokens[],
                                           size_t token_count,
                                           cepDT* out_dt) {
    if (!request || !field || !tokens || !token_count || !out_dt) {
        return false;
    }

    if (!cep_l1_tokens_to_dt(tokens, token_count, out_dt)) {
        return false;
    }

    char* canonical = cep_l1_dt_to_owned_cstr(out_dt, NULL);
    if (!canonical) {
        return false;
    }

    bool ok = cep_l1_set_string_value(request, field, canonical);
    cep_free(canonical);
    if (!ok) {
        return false;
    }

    if (original_root && !cep_l1_store_original_value(original_root, field, tokens, token_count)) {
        cepCell* existing = cep_cell_find_by_name(request, field);
        if (existing) {
            cep_cell_child_take_hard(request, existing);
        }
        return false;
    }
    return true;
}

static void cep_l1_intent_abort(cepCell* request) {
    if (!request) {
        return;
    }
    cepCell* parent = cep_cell_parent(request);
    if (parent) {
        cep_cell_child_take_hard(parent, request);
    }
}

/* Build a fresh `be_create` request, canonicalising identifiers and exposing
   the attrs branch so callers can extend the payload without touching stores
   directly. The helper also records the original spelling for audit trails. */
bool cep_l1_being_intent_init(cepL1BeingIntent* intent,
                              const char* txn_word,
                              const char* const id_tokens[], size_t id_token_count,
                              const char* const kind_tokens[], size_t kind_token_count) {
    if (!intent || !txn_word || !id_tokens || !id_token_count || !kind_tokens || !kind_token_count) {
        return false;
    }

    memset(intent, 0, sizeof *intent);

    cepCell* bucket = cep_l1_inbox_bucket(dt_be_create());
    if (!bucket || !cep_cell_has_store(bucket)) {
        return false;
    }

    cepID txn_tag = cep_text_to_word(txn_word);
    if (!txn_tag) {
        return false;
    }

    cepDT txn_dt = {
        .domain = cep_domain_cep(),
        .tag = txn_tag,
    };

    if (cep_cell_find_by_name(bucket, &txn_dt)) {
        return false;
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    bool success = false;
    cepCell* original_root = NULL;

    do {
        original_root = cep_l1_ensure_dictionary(request, dt_original(), CEP_STORAGE_RED_BLACK_T);
        if (!original_root) {
            break;
        }

        if (!cep_l1_assign_identifier_field(request, original_root, dt_id(), id_tokens, id_token_count, &intent->id_dt)) {
            break;
        }

        if (!cep_l1_assign_identifier_field(request, original_root, dt_kind(), kind_tokens, kind_token_count, &intent->kind_dt)) {
            break;
        }

        intent->attrs = cep_l1_ensure_dictionary(request, dt_attrs(), CEP_STORAGE_RED_BLACK_T);
        if (!intent->attrs) {
            break;
        }

        intent->request = request;
        intent->original = original_root;
        success = true;
    } while (false);

    if (!success) {
        cep_l1_intent_abort(request);
        memset(intent, 0, sizeof *intent);
        return false;
    }

    if (!cep_mailroom_enqueue_signal(CEP_DTAW("CEP", "coh"), dt_be_create(), &txn_dt)) {
        cep_l1_intent_abort(request);
        memset(intent, 0, sizeof *intent);
        return false;
    }

    return true;
}

/* Assemble a `bo_upsert` request, wiring canonical identifiers, endpoints, and
   the directed flag so callers can focus on business data instead of boilerplate. */
bool cep_l1_bond_intent_init(cepL1BondIntent* intent,
                             const char* txn_word,
                             const char* const id_tokens[], size_t id_token_count,
                             const char* const type_tokens[], size_t type_token_count,
                             cepCell* src,
                             cepCell* dst,
                             bool directed) {
    if (!intent || !txn_word || !id_tokens || !id_token_count || !type_tokens || !type_token_count || !src || !dst) {
        return false;
    }

    memset(intent, 0, sizeof *intent);

    cepCell* bucket = cep_l1_inbox_bucket(dt_bo_upsert());
    if (!bucket || !cep_cell_has_store(bucket)) {
        return false;
    }

    cepID txn_tag = cep_text_to_word(txn_word);
    if (!txn_tag) {
        return false;
    }

    cepDT txn_dt = {
        .domain = cep_domain_cep(),
        .tag = txn_tag,
    };

    if (cep_cell_find_by_name(bucket, &txn_dt)) {
        return false;
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    bool success = false;
    cepCell* original_root = NULL;

    do {
        original_root = cep_l1_ensure_dictionary(request, dt_original(), CEP_STORAGE_RED_BLACK_T);
        if (!original_root) {
            break;
        }

        if (!cep_l1_assign_identifier_field(request, original_root, dt_id(), id_tokens, id_token_count, &intent->id_dt)) {
            break;
        }

        if (!cep_l1_assign_identifier_field(request, original_root, dt_type(), type_tokens, type_token_count, &intent->type_dt)) {
            break;
        }

        if (!cep_l1_set_link_field(request, dt_src(), src) || !cep_l1_set_link_field(request, dt_dst(), dst)) {
            break;
        }

        if (!cep_l1_set_bool_value(request, dt_directed(), directed)) {
            break;
        }

        intent->request = request;
        intent->original = original_root;
        intent->directed = directed;
        success = true;
    } while (false);

    if (!success) {
        cep_l1_intent_abort(request);
        memset(intent, 0, sizeof *intent);
        return false;
    }

    if (!cep_mailroom_enqueue_signal(CEP_DTAW("CEP", "coh"), dt_bo_upsert(), &txn_dt)) {
        cep_l1_intent_abort(request);
        memset(intent, 0, sizeof *intent);
        return false;
    }

    return true;
}

/* Prepare a `ctx_upsert` request with canonical identifiers and ready-made
   role/facet containers so collaborators can add relationships without
   touching raw dictionary plumbing. */
bool cep_l1_context_intent_init(cepL1ContextIntent* intent,
                                const char* txn_word,
                                const char* const id_tokens[], size_t id_token_count,
                                const char* const type_tokens[], size_t type_token_count) {
    if (!intent || !txn_word || !id_tokens || !id_token_count || !type_tokens || !type_token_count) {
        return false;
    }

    memset(intent, 0, sizeof *intent);

    cepCell* bucket = cep_l1_inbox_bucket(dt_ctx_upsert());
    if (!bucket || !cep_cell_has_store(bucket)) {
        return false;
    }

    cepID txn_tag = cep_text_to_word(txn_word);
    if (!txn_tag) {
        return false;
    }

    cepDT txn_dt = {
        .domain = cep_domain_cep(),
        .tag = txn_tag,
    };

    if (cep_cell_find_by_name(bucket, &txn_dt)) {
        return false;
    }

    cepDT dict_type = *dt_dictionary();
    cepDT txn_copy = txn_dt;
    cepCell* request = cep_dict_add_dictionary(bucket, &txn_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!request) {
        return false;
    }

    bool success = false;
    cepCell* original_root = NULL;

    do {
        original_root = cep_l1_ensure_dictionary(request, dt_original(), CEP_STORAGE_RED_BLACK_T);
        if (!original_root) {
            break;
        }

        if (!cep_l1_assign_identifier_field(request, original_root, dt_id(), id_tokens, id_token_count, &intent->id_dt)) {
            break;
        }

        if (!cep_l1_assign_identifier_field(request, original_root, dt_type(), type_tokens, type_token_count, &intent->type_dt)) {
            break;
        }

        intent->roles = cep_l1_ensure_dictionary(request, dt_roles(), CEP_STORAGE_RED_BLACK_T);
        if (!intent->roles) {
            break;
        }

        intent->facets = cep_l1_ensure_dictionary(request, dt_facets(), CEP_STORAGE_RED_BLACK_T);
        if (!intent->facets) {
            break;
        }

        intent->request = request;
        intent->original = original_root;
        success = true;
    } while (false);

    if (!success) {
        cep_l1_intent_abort(request);
        memset(intent, 0, sizeof *intent);
        return false;
    }

    if (!cep_mailroom_enqueue_signal(CEP_DTAW("CEP", "coh"), dt_ctx_upsert(), &txn_dt)) {
        cep_l1_intent_abort(request);
        memset(intent, 0, sizeof *intent);
        return false;
    }

    return true;
}

/* Attach a canonicalised role link and preserve the submitted spelling for
   audits. The helper updates the existing role entry if present. */
bool cep_l1_context_intent_add_role(cepL1ContextIntent* intent,
                                    const char* const role_tokens[], size_t role_token_count,
                                    cepCell* target,
                                    cepCell** out_role_link) {
    if (!intent || !intent->roles || !role_tokens || !role_token_count || !target) {
        return false;
    }

    cepDT role_dt = {0};
    if (!cep_l1_tokens_to_dt(role_tokens, role_token_count, &role_dt)) {
        return false;
    }

    if (!cep_l1_set_link_field(intent->roles, &role_dt, target)) {
        return false;
    }

    if (!cep_l1_store_original_child(intent->original, dt_roles(), &role_dt, role_tokens, role_token_count)) {
        cepCell* link = cep_cell_find_by_name(intent->roles, &role_dt);
        if (link) {
            cep_cell_child_take_hard(intent->roles, link);
        }
        return false;
    }

    if (out_role_link) {
        cepCell* link = cep_cell_find_by_name(intent->roles, &role_dt);
        if (!link) {
            return false;
        }
        *out_role_link = link;
    }
    return true;
}

/* Add or refresh a facet entry, optionally wiring a target link and toggling
   the `required` flag. Original spellings are mirrored under
   `original/facets` so audit trails can recover the submitted casing. */
bool cep_l1_context_intent_add_facet(cepL1ContextIntent* intent,
                                     const char* const facet_tokens[], size_t facet_token_count,
                                     cepCell* target,
                                     bool required,
                                     cepCell** out_facet_cell) {
    if (!intent || !intent->facets || !facet_tokens || !facet_token_count) {
        return false;
    }

    cepDT facet_dt = {0};
    if (!cep_l1_tokens_to_dt(facet_tokens, facet_token_count, &facet_dt)) {
        return false;
    }

    cepCell* facet_node = cep_l1_ensure_dictionary(intent->facets, &facet_dt, CEP_STORAGE_RED_BLACK_T);
    if (!facet_node) {
        return false;
    }

    if (target) {
        if (!cep_l1_set_link_field(facet_node, dt_target(), target)) {
            return false;
        }
    } else {
        cepCell* existing_target = cep_cell_find_by_name(facet_node, dt_target());
        if (existing_target) {
            cep_cell_child_take_hard(facet_node, existing_target);
        }
    }

    if (required) {
        if (!cep_l1_set_bool_value(facet_node, dt_required(), true)) {
            return false;
        }
    } else {
        cepCell* existing_required = cep_cell_find_by_name(facet_node, dt_required());
        if (existing_required) {
            cep_cell_child_take_hard(facet_node, existing_required);
        }
    }

    if (!cep_l1_store_original_child(intent->original, dt_facets(), &facet_dt, facet_tokens, facet_token_count)) {
        cep_cell_child_take_hard(intent->facets, facet_node);
        return false;
    }

    if (out_facet_cell) {
        *out_facet_cell = facet_node;
    }
    return true;
}

static bool cep_l1_extract_identifier(cepCell* request,
                                      const cepDT* field,
                                      const char* missing_code,
                                      const char* invalid_code,
                                      cepDT* out_dt,
                                      const cepData** out_data) {
    if (!request || !field || !out_dt) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(request, field);
    if (!node) {
        if (missing_code) {
            cep_l1_mark_outcome_error(request, missing_code);
        }
        return false;
    }

    if (!cep_cell_has_data(node)) {
        if (invalid_code) {
            cep_l1_mark_outcome_error(request, invalid_code);
        }
        return false;
    }

    const cepData* data = node->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        if (invalid_code) {
            cep_l1_mark_outcome_error(request, invalid_code);
        }
        return false;
    }

    size_t length = data->size;
    const char* bytes = (const char*)data->value;
    if (!bytes) {
        if (invalid_code) {
            cep_l1_mark_outcome_error(request, invalid_code);
        }
        return false;
    }

    if (length > 0u && bytes[length - 1u] == '\0') {
        length -= 1u;
    }

    if (length == 0u) {
        if (invalid_code) {
            cep_l1_mark_outcome_error(request, invalid_code);
        }
        return false;
    }

    if (!cep_l1_text_to_dt_bytes(bytes, length, out_dt)) {
        if (invalid_code) {
            cep_l1_mark_outcome_error(request, invalid_code);
        }
        return false;
    }

    if (out_data) {
        *out_data = data;
    }
    return true;
}

static char* cep_l1_dt_to_owned_cstr(const cepDT* dt, size_t* out_len) {
    if (!dt) {
        return NULL;
    }

    if (cep_id_is_word(dt->tag)) {
        char stack[CEP_WORD_MAX_CHARS + 1u];
        size_t len = cep_word_to_text(dt->tag, stack);
        char* copy = cep_malloc(len + 1u);
        memcpy(copy, stack, len);
        copy[len] = '\0';
        if (out_len) {
            *out_len = len;
        }
        return copy;
    }

    if (cep_id_is_acronym(dt->tag)) {
        char stack[CEP_ACRON_MAX_CHARS + 1u];
        size_t len = cep_acronym_to_text(dt->tag, stack);
        char* copy = cep_malloc(len + 1u);
        memcpy(copy, stack, len);
        copy[len] = '\0';
        if (out_len) {
            *out_len = len;
        }
        return copy;
    }

    if (cep_id_is_reference(dt->tag)) {
        size_t len = 0u;
        const char* text = cep_namepool_lookup(dt->tag, &len);
        if (!text) {
            return NULL;
        }
        char* copy = cep_malloc(len + 1u);
        memcpy(copy, text, len);
        copy[len] = '\0';
        if (out_len) {
            *out_len = len;
        }
        return copy;
    }

    if (cep_id_is_numeric(dt->tag)) {
        char stack[32];
        int written = snprintf(stack, sizeof stack, "%" PRIu64, (uint64_t)cep_id(dt->tag));
        if (written < 0) {
            return NULL;
        }
        size_t len = (size_t)written;
        char* copy = cep_malloc(len + 1u);
        memcpy(copy, stack, len);
        copy[len] = '\0';
        if (out_len) {
            *out_len = len;
        }
        return copy;
    }

    char fallback[32];
    int written = snprintf(fallback, sizeof fallback, "#%" PRIX64, (uint64_t)cep_id(dt->tag));
    if (written < 0) {
        return NULL;
    }
    size_t len = (size_t)written;
    char* copy = cep_malloc(len + 1u);
    memcpy(copy, fallback, len);
    copy[len] = '\0';
    if (out_len) {
        *out_len = len;
    }
    return copy;
}

static bool cep_l1_data_to_identifier(const cepData* data, cepDT* out_dt) {
    if (!data || !out_dt) {
        return false;
    }

    if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return false;
    }

    size_t length = data->size;
    const char* bytes = (const char*)cep_data_payload(data);
    if (!bytes) {
        return false;
    }

    if (length > 0u && bytes[length - 1u] == '\0') {
        length -= 1u;
    }

    if (length == 0u) {
        return false;
    }

    return cep_l1_text_to_dt_bytes(bytes, length, out_dt);
}

static bool cep_l1_require_role_name(const cepDT* role_name, cepCell* request) {
    if (!role_name) {
        cep_l1_mark_outcome_error(request, "invalid-role");
        return false;
    }

    cepID tag = role_name->tag;
    if (!(cep_id_is_word(tag) || cep_id_is_acronym(tag) || cep_id_is_reference(tag) || cep_id_is_numeric(tag))) {
        cep_l1_mark_outcome_error(request, "invalid-role");
        return false;
    }
    return true;
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

static bool cep_l1_set_number_value(cepCell* parent, const cepDT* name, size_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%zu", value);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    if (!name || !cep_dt_is_valid(name)) {
        return false;
    }
    return cep_l1_set_string_value(parent, name, buffer);
}

static void cep_l1_window_insert(cepL1WindowSample* samples,
                                 size_t* count,
                                 size_t beat,
                                 size_t value,
                                 size_t flag) {
    if (!samples || !count) {
        return;
    }

    if (*count > 0u && samples[0].beat == beat) {
        samples[0].value += value;
        samples[0].flag += flag;
        return;
    }

    cepL1WindowSample sample = {
        .beat = beat,
        .value = value,
        .flag = flag,
    };

    size_t n = *count;
    if (n < CEP_L1_WINDOW_CAP) {
        samples[n++] = sample;
    } else if (beat > samples[n - 1u].beat) {
        samples[n - 1u] = sample;
    } else {
        return;
    }

    if (n > CEP_L1_WINDOW_CAP) {
        n = CEP_L1_WINDOW_CAP;
    }

    size_t idx = (n < CEP_L1_WINDOW_CAP) ? (n - 1u) : (CEP_L1_WINDOW_CAP - 1u);
    while (idx > 0u && samples[idx].beat > samples[idx - 1u].beat) {
        cepL1WindowSample tmp = samples[idx - 1u];
        samples[idx - 1u] = samples[idx];
        samples[idx] = tmp;
        --idx;
    }

    *count = n;
}

static bool cep_l1_window_write(cepCell* parent,
                                const cepDT* window_name,
                                const cepL1WindowSample* samples,
                                size_t count,
                                bool use_flag) {
    if (!parent || !window_name) {
        return false;
    }

    cepCell* window = cep_l1_ensure_dictionary(parent, window_name, CEP_STORAGE_RED_BLACK_T);
    if (!window) {
        return false;
    }

    cep_l1_clear_children(window);

    for (size_t i = 0u; i < count && i < CEP_L1_WINDOW_CAP; ++i) {
        char key_buf[4];
        int written = snprintf(key_buf, sizeof key_buf, "%02zu", i);
        if (written <= 0 || (size_t)written >= sizeof key_buf) {
            return false;
        }

        cepDT key_dt = {0};
        if (!cep_l1_text_to_dt_bytes(key_buf, (size_t)written, &key_dt)) {
            return false;
        }

        size_t value = use_flag ? samples[i].flag : samples[i].value;
        if (!cep_l1_set_number_value(window, &key_dt, value)) {
            return false;
        }
    }

    return true;
}

static void cep_l1_metrics_publish(cepCell* node,
                                   const cepL1WindowSample* samples,
                                   size_t count) {
    if (!node) {
        return;
    }

    size_t latest_value = (count > 0u) ? samples[0].value : 0u;

    (void)cep_l1_set_number_value(node, dt_latency(), latest_value);
    (void)cep_l1_window_write(node, dt_lat_window(), samples, count, false);
    (void)cep_l1_window_write(node, dt_err_window(), samples, count, true);
}

static void cep_l1_metrics_record_index(size_t successes, size_t failures) {
    if (!successes && !failures) {
        return;
    }

    size_t beat = (size_t)cep_heartbeat_current();
    cep_l1_window_insert(cep_l1_index_metrics, &cep_l1_index_metric_count, beat, successes, failures);
    cep_l1_metrics_publish(cep_l1_index_root(), cep_l1_index_metrics, cep_l1_index_metric_count);
}

static void cep_l1_metrics_record_adj(size_t successes, size_t failures) {
    if (!successes && !failures) {
        return;
    }

    size_t beat = (size_t)cep_heartbeat_current();
    cep_l1_window_insert(cep_l1_adj_metrics, &cep_l1_adj_metric_count, beat, successes, failures);
    cep_l1_metrics_publish(cep_l1_adj_root(), cep_l1_adj_metrics, cep_l1_adj_metric_count);
}

static const char* cep_l1_get_string(cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return NULL;
    }

    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node || !cep_cell_has_data(node)) {
        return NULL;
    }

    const cepData* data = node->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return NULL;
    }

    return (const char*)data->value;
}

static bool cep_l1_parse_size_text(const char* text, size_t* out_value) {
    if (!text || !out_value) {
        return false;
    }

    char* end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }

    *out_value = (size_t)parsed;
    return true;
}

static cepL1RetentionMode cep_l1_retention_mode_from_text(const char* text) {
    if (!text) {
        return CEP_L1_RETAIN_UNSPECIFIED;
    }

    char buffer[16];
    size_t len = strlen(text);
    if (len >= sizeof buffer) {
        len = sizeof buffer - 1u;
    }
    for (size_t i = 0; i < len; ++i) {
        buffer[i] = (char)tolower((unsigned char)text[i]);
    }
    buffer[len] = '\0';

    if (strcmp(buffer, "permanent") == 0) {
        return CEP_L1_RETAIN_PERMANENT;
    }
    if (strcmp(buffer, "ttl") == 0) {
        return CEP_L1_RETAIN_TTL;
    }
    if (strcmp(buffer, "archive") == 0) {
        return CEP_L1_RETAIN_ARCHIVE;
    }

    return CEP_L1_RETAIN_UNSPECIFIED;
}

static const char* cep_l1_retention_mode_to_text(cepL1RetentionMode mode) {
    switch (mode) {
    case CEP_L1_RETAIN_TTL:
        return "ttl";
    case CEP_L1_RETAIN_ARCHIVE:
        return "archive";
    case CEP_L1_RETAIN_PERMANENT:
    default:
        return "permanent";
    }
}

static void cep_l1_remove_field(cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return;
    }

    cepCell* node = cep_cell_find_by_name(parent, field);
    if (node) {
        cep_cell_child_take_hard(parent, node);
    }
}

static int cep_l1_enzyme_init(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    return cep_l1_coherence_bootstrap() ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static int cep_l1_enzyme_shutdown(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cep_l1_reset_runtime_state();

    (void)cep_lifecycle_scope_mark_teardown(CEP_LIFECYCLE_SCOPE_L1);
    return CEP_ENZYME_SUCCESS;
}

static bool cep_l1_retention_fetch_config(const char** mode_out, size_t* ttl_out, size_t* upto_out) {
    cepCell* root = cep_root();
    cepCell* sys = cep_cell_find_by_name(root, dt_sys());
    if (!sys) {
        return false;
    }

    cepCell* retention = cep_cell_find_by_name(sys, dt_retention_root());
    if (!retention) {
        return false;
    }

    cepCell* coh_cfg = cep_cell_find_by_name(retention, dt_coh());
    if (!coh_cfg) {
        return false;
    }

    bool found = false;

    const char* mode = cep_l1_get_string(coh_cfg, dt_retain_mode());
    if (mode && mode_out) {
        *mode_out = mode;
        found = true;
    }

    const char* ttl_text = cep_l1_get_string(coh_cfg, dt_retain_ttl());
    if (ttl_text && ttl_out && cep_l1_parse_size_text(ttl_text, ttl_out)) {
        found = true;
    }

    const char* upto_text = cep_l1_get_string(coh_cfg, dt_retain_upto());
    if (upto_text && upto_out && cep_l1_parse_size_text(upto_text, upto_out)) {
        found = true;
    }

    return found;
}

static bool cep_l1_ensure_retention_config(void) {
    cepCell* sys = cep_cell_find_by_name(cep_root(), dt_sys());
    if (!sys) {
        return false;
    }

    cepCell* retention = cep_l1_ensure_dictionary(sys, dt_retention_root(), CEP_STORAGE_RED_BLACK_T);
    if (!retention) {
        return false;
    }

    cepCell* coh_cfg = cep_l1_ensure_dictionary(retention, dt_coh(), CEP_STORAGE_RED_BLACK_T);
    if (!coh_cfg) {
        return false;
    }

    if (!cep_cell_find_by_name(coh_cfg, dt_retain_mode())) {
        (void)cep_l1_set_string_value(coh_cfg, dt_retain_mode(), "permanent");
    }
    if (!cep_cell_find_by_name(coh_cfg, dt_retain_ttl())) {
        (void)cep_l1_set_number_value(coh_cfg, dt_retain_ttl(), 0u);
    }
    if (!cep_cell_find_by_name(coh_cfg, dt_retain_upto())) {
        (void)cep_l1_set_number_value(coh_cfg, dt_retain_upto(), 0u);
    }

    return true;
}

static bool cep_l1_decision_apply_retention(cepCell* node,
                                            cepCell* request,
                                            cepBeatNumber decision_beat) {
    if (!node) {
        return false;
    }

    cepL1RetentionMode mode = CEP_L1_RETAIN_UNSPECIFIED;
    size_t ttl = 0u;
    size_t upto = 0u;

    const char* request_mode = cep_l1_get_string(request, dt_retain_mode());
    if (request_mode && *request_mode) {
        mode = cep_l1_retention_mode_from_text(request_mode);
        if (mode == CEP_L1_RETAIN_UNSPECIFIED) {
            return false;
        }
    }

    const char* request_ttl = cep_l1_get_string(request, dt_retain_ttl());
    if (request_ttl && *request_ttl) {
        if (!cep_l1_parse_size_text(request_ttl, &ttl)) {
            return false;
        }
    }

    const char* request_upto = cep_l1_get_string(request, dt_retain_upto());
    if (request_upto && *request_upto) {
        if (!cep_l1_parse_size_text(request_upto, &upto)) {
            return false;
        }
    }

    const char* config_mode = NULL;
    size_t cfg_ttl = 0u;
    size_t cfg_upto = 0u;
    if (mode == CEP_L1_RETAIN_UNSPECIFIED) {
        if (cep_l1_retention_fetch_config(&config_mode, &cfg_ttl, &cfg_upto)) {
            mode = cep_l1_retention_mode_from_text(config_mode);
            ttl = (ttl == 0u) ? cfg_ttl : ttl;
            if (upto == 0u) {
                upto = cfg_upto;
            }
        } else {
            mode = CEP_L1_RETAIN_PERMANENT;
        }
    }

    if (mode == CEP_L1_RETAIN_UNSPECIFIED) {
        mode = CEP_L1_RETAIN_PERMANENT;
    }

    if ((mode == CEP_L1_RETAIN_TTL || mode == CEP_L1_RETAIN_ARCHIVE) && ttl == 0u) {
        mode = CEP_L1_RETAIN_PERMANENT;
    }

    if ((mode == CEP_L1_RETAIN_TTL || mode == CEP_L1_RETAIN_ARCHIVE) && ttl > 0u && upto == 0u) {
        upto = (size_t)decision_beat + ttl;
    }

    const char* mode_text = cep_l1_retention_mode_to_text(mode);

    if (!cep_l1_set_string_value(node, dt_retain_mode(), mode_text)) {
        return false;
    }

    if (mode == CEP_L1_RETAIN_PERMANENT) {
        cep_l1_remove_field(node, dt_retain_ttl());
        cep_l1_remove_field(node, dt_retain_upto());
        return true;
    }

    if (!cep_l1_set_number_value(node, dt_retain_ttl(), ttl)) {
        return false;
    }
    if (!cep_l1_set_number_value(node, dt_retain_upto(), upto)) {
        return false;
    }

    return true;
}

/* Copy the `attrs` dictionary from the request into the ledger node so callers
   can persist arbitrary attributes alongside beings without poking internals. */
static bool cep_l1_apply_attrs_from_request(cepCell* request, cepCell* attrs_dst) {
    if (!request || !attrs_dst) {
        return false;
    }

    cepCell* attrs_req = cep_cell_find_by_name(request, dt_attrs());
    if (!attrs_req || !cep_cell_has_store(attrs_req)) {
        return true;
    }

    cepL1StoreLock attrs_lock = {0};
    if (!cep_l1_store_lock(attrs_dst, &attrs_lock)) {
        cep_l1_mark_outcome_error(request, "attrs-lock");
        return false;
    }

    bool success = true;
    cep_l1_clear_children(attrs_dst);

    for (cepCell* attr = cep_cell_first(attrs_req); attr && success; attr = cep_cell_next(attrs_req, attr)) {
        const cepDT* attr_name = cep_cell_get_name(attr);
        if (!attr_name) {
            cep_l1_mark_outcome_error(request, "attrs-name");
            success = false;
            break;
        }

        if (!cep_cell_has_data(attr)) {
            cep_l1_mark_outcome_error(request, "attrs-data");
            success = false;
            break;
        }

        const cepData* data = attr->data;
        if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
            cep_l1_mark_outcome_error(request, "attrs-value");
            success = false;
            break;
        }

        if (!cep_l1_set_value_bytes(attrs_dst, attr_name, &data->dt, data->value, data->size)) {
            cep_l1_mark_outcome_error(request, "attrs-copy");
            success = false;
            break;
        }
    }

    cep_l1_store_unlock(&attrs_lock);
    return success;
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

    if (!cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_MAILROOM)) {
        return false;
    }

    if (!cep_l1_ensure_retention_config()) {
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
    if (!cep_l1_ensure_dictionary(coh, dt_decision(), CEP_STORAGE_RED_BLACK_T)) {
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

    if (!cep_l1_bindings_applied) {
        cepCell* coh = cep_l1_coh_root();
        if (coh) {
            (void)cep_cell_bind_enzyme(coh, dt_coh_ing_be(), true);
            (void)cep_cell_bind_enzyme(coh, dt_coh_ing_bo(), true);
            (void)cep_cell_bind_enzyme(coh, dt_coh_ing_ctx(), true);
            (void)cep_cell_bind_enzyme(coh, dt_coh_closure(), true);
            (void)cep_cell_bind_enzyme(coh, dt_coh_index(), true);
            (void)cep_cell_bind_enzyme(coh, dt_coh_adj(), true);
            cep_l1_bindings_applied = true;
        }
    }
    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_L1);

    /* Best-effort: queuing the readiness pulse should not block bootstrap if the
       heartbeat runtime is still configuring. */
    (void)cep_l1_emit_scope_ready_signal();
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

static bool cep_l1_emit_scope_ready_signal(void) {
    if (!cep_dt_is_valid(dt_sig_sys()) ||
        !cep_dt_is_valid(dt_sys_ready()) ||
        !cep_dt_is_valid(dt_l1_ready()) ||
        !cep_dt_is_valid(dt_data_root()) ||
        !cep_dt_is_valid(dt_coh())) {
        return false;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast past[3];
    } cepPathStatic3;

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast past[2];
    } cepPathStatic2;

    cepPathStatic3 signal_path = {
        .length = 3u,
        .capacity = 3u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_ready(), .timestamp = 0u},
            {.dt = *dt_l1_ready(), .timestamp = 0u},
        },
    };

    cepPathStatic3 legacy_signal_path = {
        .length = 3u,
        .capacity = 3u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_ready(), .timestamp = 0u},
            {.dt = *dt_scope_l1(), .timestamp = 0u},
        },
    };

    cepPathStatic2 target_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_data_root(), .timestamp = 0u},
            {.dt = *dt_coh(), .timestamp = 0u},
        },
    };

    bool ok_new = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                               (const cepPath*)&signal_path,
                                               (const cepPath*)&target_path) == CEP_ENZYME_SUCCESS;
    bool ok_legacy = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                                  (const cepPath*)&legacy_signal_path,
                                                  (const cepPath*)&target_path) == CEP_ENZYME_SUCCESS;
    return ok_new || ok_legacy;
}

static bool cep_l1_enqueue_ready_signal(cepCell* request) {
    if (!request) {
        return false;
    }

    const cepDT* txn_dt = cep_cell_get_name(request);
    cepCell* bucket = cep_cell_parent(request);
    cepCell* inbox = bucket ? cep_cell_parent(bucket) : NULL;
    cepCell* layer = inbox ? cep_cell_parent(inbox) : NULL;
    cepCell* data_root = layer ? cep_cell_parent(layer) : NULL;

    if (!txn_dt || !bucket || !inbox || !layer || !data_root) {
        return false;
    }

    if (!cep_cell_name_is(inbox, dt_inbox()) ||
        !cep_cell_name_is(layer, dt_coh()) ||
        !cep_cell_name_is(data_root, dt_data_root())) {
        return false;
    }

    const cepDT* bucket_dt = cep_cell_get_name(bucket);
    if (!bucket_dt) {
        return false;
    }

    cepDT txn_clean = cep_dt_clean(txn_dt);
    cepDT bucket_clean = cep_dt_clean(bucket_dt);

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast past[5];
    } cepPathStatic5;

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast past[3];
    } cepPathStatic3;

    cepPathStatic3 signal_path = {
        .length = 3u,
        .capacity = 3u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_ready(), .timestamp = 0u},
            {.dt = *dt_l1_ready(), .timestamp = 0u},
        },
    };

    cepPathStatic3 legacy_signal_path = {
        .length = 3u,
        .capacity = 3u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_ready(), .timestamp = 0u},
            {.dt = *dt_scope_l1(), .timestamp = 0u},
        },
    };

    cepPathStatic5 target_path = {
        .length = 5u,
        .capacity = 5u,
        .past = {
            {.dt = *dt_data_root(), .timestamp = 0u},
            {.dt = *dt_coh(), .timestamp = 0u},
            {.dt = *dt_inbox(), .timestamp = 0u},
            {.dt = bucket_clean, .timestamp = 0u},
            {.dt = txn_clean, .timestamp = 0u},
        },
    };

    bool ok_new = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                               (const cepPath*)&signal_path,
                                               (const cepPath*)&target_path) == CEP_ENZYME_SUCCESS;
    bool ok_legacy = cep_heartbeat_enqueue_signal(CEP_BEAT_INVALID,
                                                  (const cepPath*)&legacy_signal_path,
                                                  (const cepPath*)&target_path) == CEP_ENZYME_SUCCESS;
    return ok_new || ok_legacy;
}

static cepCell* cep_l1_facet_mirror(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_facet_root()) : NULL;
}

static cepCell* cep_l1_debt_root(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_debt()) : NULL;
}

/* This helper composes a stable `ctx:facet` key for mirrors and decisions so we
   rely on the namepool instead of ad-hoc buffers spread across the code. */

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

/* This helper composes a stable `ctx:facet` key for mirrors and decisions so we
   rely on the namepool instead of ad-hoc buffers spread across the code. */
static bool cep_l1_compose_key(const cepDT* lhs, const cepDT* rhs, cepDT* out_key) {
    if (!lhs || !rhs || !out_key) {
        return false;
    }

    size_t lhs_len = 0u;
    size_t rhs_len = 0u;
    char* lhs_text = cep_l1_dt_to_owned_cstr(lhs, &lhs_len);
    char* rhs_text = cep_l1_dt_to_owned_cstr(rhs, &rhs_len);
    if (!lhs_text || !rhs_text) {
        cep_free(lhs_text);
        cep_free(rhs_text);
        return false;
    }

    size_t key_len = lhs_len + 1u + rhs_len;
    char* key_buf = cep_malloc(key_len + 1u);
    memcpy(key_buf, lhs_text, lhs_len);
    key_buf[lhs_len] = ':';
    memcpy(key_buf + lhs_len + 1u, rhs_text, rhs_len);
    key_buf[key_len] = '\0';

    cepID key_id = cep_namepool_intern(key_buf, key_len);

    cep_free(key_buf);
    cep_free(lhs_text);
    cep_free(rhs_text);

    if (!key_id) {
        return false;
    }

    out_key->domain = cep_domain_cep();
    out_key->tag = key_id;
    return true;
}

/* The decision ledger keeps track of tie-breaks for replay, mirroring how facet
   mirrors hang off the coherence root. */
static cepCell* cep_l1_decision_ledger(void) {
    cepCell* coh = cep_l1_coh_root();
    return coh ? cep_cell_find_by_name(coh, dt_decision()) : NULL;
}

/* Quickly locate a decision entry for a given context+facet pair so the
   selection logic can reuse existing choices when they exist. */
static cepCell* cep_l1_decision_entry(const cepDT* ctx_id, const cepDT* facet_id) {
    cepCell* ledger = cep_l1_decision_ledger();
    if (!ledger) {
        return NULL;
    }

    cepDT key_dt = {0};
    if (!cep_l1_compose_key(ctx_id, facet_id, &key_dt)) {
        return NULL;
    }

    return cep_cell_find_by_name(ledger, &key_dt);
}

/* Resolve the target stored in the decision ledger, returning NULL if no
   decision or link is present. */
static cepCell* cep_l1_decision_target(const cepDT* ctx_id, const cepDT* facet_id) {
    cepCell* entry = cep_l1_decision_entry(ctx_id, facet_id);
    if (!entry || !cep_cell_has_store(entry)) {
        return NULL;
    }
    cepCell* choice = cep_cell_find_by_name(entry, dt_choice());
    if (!choice || !cep_cell_is_link(choice)) {
        return NULL;
    }
    return cep_link_pull(choice);
}

/* Persist the chosen candidate for a facet so deterministic replays can
   consult the same tie-break without relying on incidental ordering. */
static bool cep_l1_decision_record(const cepDT* ctx_id,
                                   const cepDT* facet_id,
                                   cepCell* target,
                                   cepCell* request) {
    if (!ctx_id || !facet_id || !target) {
        return false;
    }

    cepCell* ledger = cep_l1_decision_ledger();
    if (!ledger) {
        return false;
    }

    cepDT key_dt = {0};
    if (!cep_l1_compose_key(ctx_id, facet_id, &key_dt)) {
        return false;
    }

    cepCell* entry = NULL;
    cepL1StoreLock ledger_lock = {0};
    if (!cep_l1_store_lock(ledger, &ledger_lock)) {
        return false;
    }

    entry = cep_cell_find_by_name(ledger, &key_dt);
    if (!entry) {
        cepDT dict_type = *dt_dictionary();
        cepDT key_copy = key_dt;
        entry = cep_dict_add_dictionary(ledger, &key_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    cep_l1_store_unlock(&ledger_lock);
    if (!entry) {
        return false;
    }

    cepL1StoreLock entry_lock = {0};
    if (!cep_l1_store_lock(entry, &entry_lock)) {
        return false;
    }

    cepCell* existing_choice = cep_cell_find_by_name(entry, dt_choice());
    if (existing_choice) {
        cep_cell_child_take_hard(entry, existing_choice);
    }

    bool ok = cep_l1_link_child(entry, dt_choice(), target);
    if (ok) {
        ok = cep_l1_decision_apply_retention(entry, request, cep_heartbeat_current());
    }

    cep_l1_store_unlock(&entry_lock);
    if (!ok) {
        return false;
    }

    if (request) {
        cep_l1_attach_request_parent(entry, request);
    }
    return true;
}

/* Remove a persisted decision once the tie is gone so the ledger only carries
   active tie-breaks. */
static bool cep_l1_decision_clear(const cepDT* ctx_id, const cepDT* facet_id) {
    if (!ctx_id || !facet_id) {
        return false;
    }

    cepCell* ledger = cep_l1_decision_ledger();
    if (!ledger) {
        return false;
    }

    cepDT key_dt = {0};
    if (!cep_l1_compose_key(ctx_id, facet_id, &key_dt)) {
        return false;
    }

    cepL1StoreLock ledger_lock = {0};
    if (!cep_l1_store_lock(ledger, &ledger_lock)) {
        return false;
    }

    cepCell* entry = cep_cell_find_by_name(ledger, &key_dt);
    if (entry) {
        cep_cell_child_take_hard(ledger, entry);
    }

    cep_l1_store_unlock(&ledger_lock);
    return true;
}

static void cep_l1_facet_mirror_clear_ctx_locked(cepCell* mirror, const cepDT* ctx_id) {
    if (!mirror || !ctx_id) {
        return;
    }

    size_t ctx_len = 0u;
    char* ctx_text = cep_l1_dt_to_owned_cstr(ctx_id, &ctx_len);
    if (!ctx_text || ctx_len == 0u) {
        cep_free(ctx_text);
        return;
    }

    for (cepCell* entry = cep_cell_first(mirror); entry;) {
        cepCell* next = cep_cell_next(mirror, entry);
        const cepDT* entry_name = cep_cell_get_name(entry);
        if (!entry_name) {
            entry = next;
            continue;
        }

        size_t key_len = 0u;
        char* key_text = cep_l1_dt_to_owned_cstr(entry_name, &key_len);
        if (!key_text) {
            entry = next;
            continue;
        }

        if (key_len > ctx_len && key_text[ctx_len] == ':' && strncmp(key_text, ctx_text, ctx_len) == 0) {
            cep_cell_child_take_hard(mirror, entry);
        }

        cep_free(key_text);
        entry = next;
    }

    cep_free(ctx_text);
}

static cepCell* cep_l1_ensure_adj_bucket(const cepDT* id_dt) {
    cepL1StoreLock root_lock = {0};
    cepL1StoreLock bucket_lock = {0};

    cepCell* adj_root = cep_l1_adj_root();
    if (!adj_root) {
        return NULL;
    }

    if (!cep_l1_store_lock(adj_root, &root_lock)) {
        return NULL;
    }
    cepCell* bucket = cep_l1_ensure_dictionary(adj_root, id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_l1_store_unlock(&root_lock);
    if (!bucket) {
        return NULL;
    }

    if (!cep_l1_store_lock(bucket, &bucket_lock)) {
        return NULL;
    }

    bool ok = true;
    if (!cep_l1_ensure_dictionary(bucket, dt_out_bonds(), CEP_STORAGE_RED_BLACK_T)) {
        ok = false;
    } else if (!cep_l1_ensure_dictionary(bucket, dt_in_bonds(), CEP_STORAGE_RED_BLACK_T)) {
        ok = false;
    } else if (!cep_l1_ensure_dictionary(bucket, dt_ctx_by_role(), CEP_STORAGE_RED_BLACK_T)) {
        ok = false;
    }

    cep_l1_store_unlock(&bucket_lock);

    return ok ? bucket : NULL;
}

static bool cep_l1_index_being(cepCell* being, const cepDT* id_dt, const cepDT* kind_dt) {
    cepL1StoreLock root_lock = {0};
    cepL1StoreLock kind_lock = {0};
    cepL1StoreLock bucket_lock = {0};
    bool success = false;

    cepCell* index_root = cep_l1_index_root();
    if (!index_root || !being || !id_dt || !kind_dt) {
        return false;
    }

    if (!cep_l1_store_lock(index_root, &root_lock)) {
        return false;
    }
    cepCell* be_kind = cep_l1_ensure_dictionary(index_root, dt_be_kind(), CEP_STORAGE_RED_BLACK_T);
    if (!be_kind) {
        goto done_root;
    }

    if (!cep_l1_store_lock(be_kind, &kind_lock)) {
        goto done_root;
    }

    cepCell* bucket = cep_l1_ensure_dictionary(be_kind, kind_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        goto done_kind;
    }

    /* Purge this being from all buckets before relinking. */
    for (cepCell* kind_bucket = cep_cell_first(be_kind); kind_bucket; kind_bucket = cep_cell_next(be_kind, kind_bucket)) {
        if (!cep_cell_has_store(kind_bucket)) {
            continue;
        }

        cepCell* entry = NULL;
        cepL1StoreLock bucket_purge_lock = {0};
        if (!cep_l1_store_lock(kind_bucket, &bucket_purge_lock)) {
            goto done_kind;
        }

        entry = cep_cell_find_by_name(kind_bucket, id_dt);
        if (entry) {
            cep_cell_child_take_hard(kind_bucket, entry);
        }

        cep_l1_store_unlock(&bucket_purge_lock);
    }

    if (!cep_l1_store_lock(bucket, &bucket_lock)) {
        goto done_kind;
    }

    cepDT id_copy = *id_dt;
    success = cep_l1_link_child(bucket, &id_copy, being);

done_kind:
    cep_l1_store_unlock(&bucket_lock);
    cep_l1_store_unlock(&kind_lock);

done_root:
    cep_l1_store_unlock(&root_lock);
    return success;
}

static bool cep_l1_index_bond(cepCell* bond, const cepDT* id_dt, cepCell* src, cepCell* dst, const cepDT* type_dt, bool directed) {
    (void)id_dt;
    cepL1StoreLock root_lock = {0};
    cepL1StoreLock pairs_lock = {0};
    bool success = false;

    cepCell* index_root = cep_l1_index_root();
    if (!index_root || !bond || !id_dt || !src || !dst || !type_dt) {
        return false;
    }

    if (!cep_l1_store_lock(index_root, &root_lock)) {
        return false;
    }
    cepCell* pairs = cep_l1_ensure_dictionary(index_root, dt_bo_pair(), CEP_STORAGE_RED_BLACK_T);
    cep_l1_store_unlock(&root_lock);
    if (!pairs) {
        goto done;
    }

    size_t src_len = 0u;
    size_t dst_len = 0u;
    size_t type_len = 0u;
    char* src_text = cep_l1_dt_to_owned_cstr(cep_cell_get_name(src), &src_len);
    char* dst_text = cep_l1_dt_to_owned_cstr(cep_cell_get_name(dst), &dst_len);
    char* type_text_str = cep_l1_dt_to_owned_cstr(type_dt, &type_len);
    if (!src_text || !dst_text || !type_text_str) {
        cep_free(src_text);
        cep_free(dst_text);
        cep_free(type_text_str);
        goto done;
    }

    size_t key_len = src_len + 1u + dst_len + 1u + type_len + 2u;
    char* key_buf = cep_malloc(key_len + 1u);
    size_t offset = 0u;
    memcpy(key_buf + offset, src_text, src_len);
    offset += src_len;
    key_buf[offset++] = ':';
    memcpy(key_buf + offset, dst_text, dst_len);
    offset += dst_len;
    key_buf[offset++] = ':';
    memcpy(key_buf + offset, type_text_str, type_len);
    offset += type_len;
    key_buf[offset++] = ':';
    key_buf[offset++] = directed ? '1' : '0';
    key_buf[offset] = '\0';

    cepID key_id = cep_namepool_intern(key_buf, offset);
    cep_free(src_text);
    cep_free(dst_text);
    cep_free(type_text_str);
    cep_free(key_buf);
    if (!key_id) {
        goto done;
    }

    cepDT key_dt = cep_dt_make(cep_domain_cep(), key_id);

    if (!cep_l1_store_lock(pairs, &pairs_lock)) {
        goto done;
    }

    /* Remove links that no longer match this bond before inserting the new key. */
    for (cepCell* pair_entry = cep_cell_first(pairs); pair_entry; ) {
        cepCell* next = cep_cell_next(pairs, pair_entry);
        if (cep_cell_is_link(pair_entry) && cep_link_pull(pair_entry) == bond) {
            cep_cell_child_take_hard(pairs, pair_entry);
        }
        pair_entry = next;
    }

    success = cep_l1_link_child(pairs, &key_dt, bond);

done:
    cep_l1_store_unlock(&pairs_lock);
    cep_l1_store_unlock(&root_lock);
    return success;
}

static bool cep_l1_index_context(cepCell* ctx, const cepDT* id_dt, const cepDT* type_dt) {
    cepL1StoreLock root_lock = {0};
    cepL1StoreLock type_root_lock = {0};
    cepL1StoreLock bucket_lock = {0};
    bool success = false;

    cepCell* index_root = cep_l1_index_root();
    if (!index_root || !ctx || !id_dt || !type_dt) {
        return false;
    }

    if (!cep_l1_store_lock(index_root, &root_lock)) {
        return false;
    }
    cepCell* ctx_type_root = cep_l1_ensure_dictionary(index_root, dt_ctx_type(), CEP_STORAGE_RED_BLACK_T);
    if (!ctx_type_root) {
        goto done_root;
    }

    if (!cep_l1_store_lock(ctx_type_root, &type_root_lock)) {
        goto done_root;
    }

    cepCell* bucket = cep_l1_ensure_dictionary(ctx_type_root, type_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bucket) {
        goto done_type_root;
    }

    for (cepCell* type_bucket = cep_cell_first(ctx_type_root); type_bucket; type_bucket = cep_cell_next(ctx_type_root, type_bucket)) {
        if (!cep_cell_has_store(type_bucket)) {
            continue;
        }

        cepL1StoreLock purge_lock = {0};
        if (!cep_l1_store_lock(type_bucket, &purge_lock)) {
            goto done_type_root;
        }

        cepCell* entry = cep_cell_find_by_name(type_bucket, id_dt);
        if (entry) {
            cep_cell_child_take_hard(type_bucket, entry);
        }

        cep_l1_store_unlock(&purge_lock);
    }

    if (!cep_l1_store_lock(bucket, &bucket_lock)) {
        goto done_type_root;
    }

    cepDT id_copy = *id_dt;
    success = cep_l1_link_child(bucket, &id_copy, ctx);

done_type_root:
    cep_l1_store_unlock(&bucket_lock);
    cep_l1_store_unlock(&type_root_lock);

done_root:
    cep_l1_store_unlock(&root_lock);
    return success;
}

static bool cep_l1_index_facets(cepCell* ctx, const cepDT* id_dt) {
    cepL1StoreLock root_lock = {0};
    cepL1StoreLock fa_ctx_lock = {0};
    cepL1StoreLock bucket_lock = {0};
    bool success = false;

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

    if (!cep_l1_store_lock(index_root, &root_lock)) {
        return false;
    }
    cepCell* fa_ctx_root = cep_l1_ensure_dictionary(index_root, dt_fa_ctx(), CEP_STORAGE_RED_BLACK_T);
    cep_l1_store_unlock(&root_lock);
    if (!fa_ctx_root) {
        goto done;
    }

    if (!cep_l1_store_lock(fa_ctx_root, &fa_ctx_lock)) {
        goto done;
    }
    cepCell* ctx_bucket = cep_l1_ensure_dictionary(fa_ctx_root, id_dt, CEP_STORAGE_RED_BLACK_T);
    cep_l1_store_unlock(&fa_ctx_lock);
    if (!ctx_bucket) {
        goto done;
    }

    if (!cep_l1_store_lock(ctx_bucket, &bucket_lock)) {
        goto done;
    }

    cep_l1_clear_children(ctx_bucket);

    success = true;
    for (cepCell* facet = cep_cell_first(facets); facet && success; facet = cep_cell_next(facets, facet)) {
        cepDT facet_name = cep_dt_clean(cep_cell_get_name(facet));
        if (!cep_l1_link_child(ctx_bucket, &facet_name, facet)) {
            success = false;
        }
    }

done:
    cep_l1_store_unlock(&bucket_lock);
    cep_l1_store_unlock(&fa_ctx_lock);
    cep_l1_store_unlock(&root_lock);
    return success;
}

static bool cep_l1_adj_being(cepCell* being, const cepDT* id_dt) {
    (void)being;
    return cep_l1_ensure_adj_bucket(id_dt) != NULL;
}

static bool cep_l1_adjacency_purge_bond(const cepDT* id_dt) {
    cepCell* adj_root = cep_l1_adj_root();
    if (!adj_root || !id_dt) {
        return true;
    }

    cepL1StoreLock root_lock = {0};
    if (!cep_l1_store_lock(adj_root, &root_lock)) {
        return false;
    }

    bool ok = true;
    for (cepCell* bucket = cep_cell_first(adj_root); bucket && ok; bucket = cep_cell_next(adj_root, bucket)) {
        if (!cep_cell_has_store(bucket)) {
            continue;
        }

        cepL1StoreLock bucket_lock = {0};
        if (!cep_l1_store_lock(bucket, &bucket_lock)) {
            ok = false;
            break;
        }

        cepCell* out_dict = cep_cell_find_by_name(bucket, dt_out_bonds());
        cepCell* in_dict  = cep_cell_find_by_name(bucket, dt_in_bonds());

        if (out_dict && cep_cell_has_store(out_dict)) {
            cepCell* existing = cep_cell_find_by_name(out_dict, id_dt);
            if (existing) {
                cep_cell_child_take_hard(out_dict, existing);
            }
        }

        if (in_dict && cep_cell_has_store(in_dict)) {
            cepCell* existing = cep_cell_find_by_name(in_dict, id_dt);
            if (existing) {
                cep_cell_child_take_hard(in_dict, existing);
            }
        }

        cep_l1_store_unlock(&bucket_lock);
    }

    cep_l1_store_unlock(&root_lock);
    return ok;
}

static bool cep_l1_adj_bond(cepCell* bond, const cepDT* id_dt, cepCell* src, cepCell* dst) {
    (void)id_dt;
    if (!bond || !src || !dst) {
        return false;
    }

    const cepDT* bond_name_ptr = cep_cell_get_name(bond);
    if (!cep_l1_adjacency_purge_bond(bond_name_ptr)) {
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

    cepDT bond_name = *bond_name_ptr;
    cepL1StoreLock out_lock = {0};
    cepL1StoreLock in_lock = {0};

    if (!cep_l1_store_lock(out_dict, &out_lock)) {
        return false;
    }
    bool out_ok = cep_l1_link_child(out_dict, &bond_name, bond);
    cep_l1_store_unlock(&out_lock);
    if (!out_ok) {
        return false;
    }

    if (!cep_l1_store_lock(in_dict, &in_lock)) {
        return false;
    }
    bool in_ok = cep_l1_link_child(in_dict, &bond_name, bond);
    cep_l1_store_unlock(&in_lock);
    return in_ok;
}

static bool cep_l1_adjacency_purge_context(const cepDT* ctx_id) {
    cepCell* adj_root = cep_l1_adj_root();
    if (!adj_root || !ctx_id) {
        return true;
    }

    cepL1StoreLock root_lock = {0};
    if (!cep_l1_store_lock(adj_root, &root_lock)) {
        return false;
    }

    bool ok = true;
    for (cepCell* bucket = cep_cell_first(adj_root); bucket && ok; bucket = cep_cell_next(adj_root, bucket)) {
        if (!cep_cell_has_store(bucket)) {
            continue;
        }

        cepL1StoreLock bucket_lock = {0};
        if (!cep_l1_store_lock(bucket, &bucket_lock)) {
            ok = false;
            break;
        }

        cepCell* ctx_by_role_root = cep_cell_find_by_name(bucket, dt_ctx_by_role());
        if (ctx_by_role_root && cep_cell_has_store(ctx_by_role_root)) {
            for (cepCell* role_bucket = cep_cell_first(ctx_by_role_root); role_bucket; role_bucket = cep_cell_next(ctx_by_role_root, role_bucket)) {
                if (!cep_cell_has_store(role_bucket)) {
                    continue;
                }

                cepL1StoreLock role_lock = {0};
                if (!cep_l1_store_lock(role_bucket, &role_lock)) {
                    ok = false;
                    break;
                }

                cepCell* existing = cep_cell_find_by_name(role_bucket, ctx_id);
                if (existing) {
                    cep_cell_child_take_hard(role_bucket, existing);
                }

                cep_l1_store_unlock(&role_lock);
            }
        }

        cep_l1_store_unlock(&bucket_lock);
    }

    cep_l1_store_unlock(&root_lock);
    return ok;
}

static bool cep_l1_adj_context(cepCell* ctx, const cepDT* id_dt) {
    if (!ctx || !id_dt) {
        return false;
    }

    if (!cep_l1_adjacency_purge_context(id_dt)) {
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

        cepL1StoreLock ctx_by_role_lock = {0};
        if (!cep_l1_store_lock(ctx_by_role_root, &ctx_by_role_lock)) {
            return false;
        }
        cepCell* role_bucket = cep_l1_ensure_dictionary(ctx_by_role_root, role_name, CEP_STORAGE_RED_BLACK_T);
        cep_l1_store_unlock(&ctx_by_role_lock);
        if (!role_bucket) {
            return false;
        }

        cepL1StoreLock role_lock = {0};
        if (!cep_l1_store_lock(role_bucket, &role_lock)) {
            return false;
        }

        cepDT ctx_name = *id_dt;
        bool ok = cep_l1_link_child(role_bucket, &ctx_name, ctx);
        cep_l1_store_unlock(&role_lock);
        if (!ok) {
            return false;
        }
    }

    return true;
}

static bool cep_l1_record_debt(const cepDT* ctx_id, const cepDT* facet_id, cepCell* request) {
    cepL1StoreLock debt_lock = {0};
    cepL1StoreLock ctx_lock = {0};
    cepL1StoreLock facet_lock = {0};
    bool success = false;

    cepCell* debt_root = cep_l1_debt_root();
    if (!debt_root || !ctx_id || !facet_id) {
        return false;
    }

    if (!cep_l1_store_lock(debt_root, &debt_lock)) {
        cep_l1_mark_outcome_error(request, "debt-lock");
        goto done;
    }

    cepCell* ctx_bucket = cep_l1_ensure_dictionary(debt_root, ctx_id, CEP_STORAGE_RED_BLACK_T);
    cep_l1_store_unlock(&debt_lock);
    if (!ctx_bucket) {
        goto done;
    }

    if (!cep_l1_store_lock(ctx_bucket, &ctx_lock)) {
        cep_l1_mark_outcome_error(request, "debt-lock");
        goto done;
    }

    cepCell* facet_bucket = cep_cell_find_by_name(ctx_bucket, facet_id);
    if (!facet_bucket) {
        cepDT facet_copy = *facet_id;
        cepDT dict_type = *dt_dictionary();
        facet_bucket = cep_dict_add_dictionary(ctx_bucket, &facet_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    cep_l1_store_unlock(&ctx_lock);
    if (!facet_bucket) {
        goto done;
    }

    if (!cep_l1_store_lock(facet_bucket, &facet_lock)) {
        cep_l1_mark_outcome_error(request, "debt-lock");
        goto done;
    }

    if (!cep_l1_set_bool_value(facet_bucket, dt_required(), true)) {
        goto done;
    }
    if (request) {
        cep_l1_attach_request_parent(facet_bucket, request);
    }
    success = true;

done:
    cep_l1_store_unlock(&facet_lock);
    cep_l1_store_unlock(&ctx_lock);
    cep_l1_store_unlock(&debt_lock);
    return success;
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

    cepL1StoreLock ctx_lock = {0};
    if (!cep_l1_store_lock(ctx_bucket, &ctx_lock)) {
        return;
    }

    cepCell* facet_bucket = cep_cell_find_by_name(ctx_bucket, facet_id);
    if (facet_bucket) {
        cep_cell_child_take_hard(ctx_bucket, facet_bucket);
    }

    bool empty_after = cep_cell_children(ctx_bucket) == 0u;
    cep_l1_store_unlock(&ctx_lock);

    if (empty_after) {
        cepL1StoreLock debt_lock = {0};
        if (cep_l1_store_lock(debt_root, &debt_lock)) {
            cepCell* ctx_check = cep_cell_find_by_name(debt_root, ctx_id);
            if (ctx_check && !cep_cell_children(ctx_check)) {
                cep_cell_child_take_hard(debt_root, ctx_check);
            }
            cep_l1_store_unlock(&debt_lock);
        }
    }
}

static bool cep_l1_parse_facet_request(const cepDT* ctx_id,
                                       const cepDT* facet_id,
                                       cepCell* request,
                                       cepCell* node,
                                       cepCell** out_target,
                                       bool* out_required,
                                       bool* out_multi) {
    if (!out_target || !out_required) {
        return false;
    }

    *out_target = NULL;
    *out_required = false;
    if (out_multi) {
        *out_multi = false;
    }

    if (!node) {
        if (ctx_id && facet_id) {
            if (!cep_l1_decision_clear(ctx_id, facet_id)) {
                if (request) {
                    cep_l1_mark_outcome_error(request, "decision-ledger");
                }
                return false;
            }
        }
        return true;
    }

    if (cep_cell_is_link(node)) {
        *out_target = cep_link_pull(node);
        if (ctx_id && facet_id) {
            if (!cep_l1_decision_clear(ctx_id, facet_id)) {
                if (request) {
                    cep_l1_mark_outcome_error(request, "decision-ledger");
                }
                return false;
            }
        }
        return true;
    }

    cepCell* decision_choice = NULL;
    if (ctx_id && facet_id) {
        decision_choice = cep_l1_decision_target(ctx_id, facet_id);
    }

    size_t candidate_count = 0u;
    cepCell* chosen = NULL;

    if (cep_cell_has_store(node)) {
        for (cepCell* child = cep_cell_first(node); child; child = cep_cell_next(node, child)) {
            if (cep_cell_is_link(child)) {
                cepCell* candidate = cep_link_pull(child);
                if (!candidate) {
                    continue;
                }
                ++candidate_count;
                if (decision_choice && candidate == decision_choice) {
                    chosen = candidate;
                } else if (!chosen) {
                    chosen = candidate;
                }
            } else if (cep_cell_name_is(child, dt_required()) && cep_cell_has_data(child)) {
                const cepData* data = child->data;
                if (data->datatype == CEP_DATATYPE_VALUE && data->size > 0u) {
                    *out_required = data->value[0] != 0u;
                }
            }
        }
    } else if (cep_cell_has_data(node) && cep_cell_name_is(node, dt_required())) {
        const cepData* data = node->data;
        if (data->datatype == CEP_DATATYPE_VALUE && data->size > 0u) {
            *out_required = data->value[0] != 0u;
        }
    }

    if (!chosen) {
        chosen = decision_choice;
    }

    *out_target = chosen;
    if (out_multi) {
        *out_multi = candidate_count > 1u;
    }

    if (!ctx_id || !facet_id) {
        return true;
    }

    bool ok = true;
    if (candidate_count > 1u && chosen) {
        ok = cep_l1_decision_record(ctx_id, facet_id, chosen, request);
    } else {
        ok = cep_l1_decision_clear(ctx_id, facet_id);
    }

    if (!ok && request) {
        cep_l1_mark_outcome_error(request, "decision-ledger");
    }
    return ok;
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
static bool cep_l1_index_being(cepCell* being, const cepDT* id_dt, const cepDT* kind_dt);
static bool cep_l1_index_bond(cepCell* bond, const cepDT* id_dt, cepCell* src, cepCell* dst, const cepDT* type_dt, bool directed);
static bool cep_l1_index_context(cepCell* ctx, const cepDT* id_dt, const cepDT* type_dt);
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
    int result = CEP_ENZYME_FATAL;
    cepL1StoreLock being_lock = {0};

    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_be_create())) {
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_l1_extract_identifier(request, dt_id(), "missing-id", "invalid-id", &id_dt, NULL)) {
        goto done;
    }

    const cepData* kind_data = NULL;
    cepDT kind_dt = {0};
    if (!cep_l1_extract_identifier(request, dt_kind(), "missing-kind", "invalid-kind", &kind_dt, &kind_data)) {
        goto done;
    }
    (void)kind_dt;

    cepCell* ledger = cep_l1_being_ledger();
    if (!ledger) {
        cep_l1_mark_outcome_error(request, "missing-ledger");
        goto done;
    }

    cepCell* being = cep_l1_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!being) {
        cep_l1_mark_outcome_error(request, "create-failed");
        goto done;
    }

    if (!cep_l1_store_lock(being, &being_lock)) {
        cep_l1_mark_outcome_error(request, "being-lock");
        goto done;
    }

    if (!cep_l1_set_value_bytes(being, dt_kind(), &kind_data->dt, kind_data->value, kind_data->size)) {
        cep_l1_mark_outcome_error(request, "set-kind");
        goto done;
    }

    cepCell* attrs = cep_l1_ensure_dictionary(being, dt_attrs(), CEP_STORAGE_RED_BLACK_T);
    if (!attrs) {
        cep_l1_mark_outcome_error(request, "attrs");
        goto done;
    }

    if (!cep_l1_apply_attrs_from_request(request, attrs)) {
        goto done;
    }

    cep_l1_attach_request_parent(being, request);
    cep_l1_mark_outcome_ok(request);
    result = CEP_ENZYME_SUCCESS;
    (void)cep_l1_enqueue_ready_signal(request);

done:
    cep_l1_store_unlock(&being_lock);
    return result;
}
static int cep_l1_enzyme_ingest_bo(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    int result = CEP_ENZYME_FATAL;
    cepL1StoreLock bond_lock = {0};

    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_bo_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_l1_extract_identifier(request, dt_id(), "missing-id", "invalid-id", &id_dt, NULL)) {
        goto done;
    }

    const cepData* type_data = NULL;
    cepDT type_dt = {0};
    if (!cep_l1_extract_identifier(request, dt_type(), "missing-type", "invalid-type", &type_dt, &type_data)) {
        goto done;
    }

    cepCell* src = cep_l1_request_link_field(request, dt_src());
    cepCell* dst = cep_l1_request_link_field(request, dt_dst());
    if (!src || !dst) {
        cep_l1_mark_outcome_error(request, "missing-endpoint");
        goto done;
    }

    bool directed = false;
    (void)cep_l1_request_bool_field(request, dt_directed(), &directed);
    (void)type_dt;

    cepCell* ledger = cep_l1_bond_ledger();
    if (!ledger) {
        cep_l1_mark_outcome_error(request, "missing-ledger");
        goto done;
    }

    cepCell* bond = cep_l1_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!bond) {
        cep_l1_mark_outcome_error(request, "create-failed");
        goto done;
    }

    if (!cep_l1_store_lock(bond, &bond_lock)) {
        cep_l1_mark_outcome_error(request, "bond-lock");
        goto done;
    }

    if (!cep_l1_set_value_bytes(bond, dt_type(), &type_data->dt, type_data->value, type_data->size)
        || !cep_l1_set_link_field(bond, dt_src(), src)
        || !cep_l1_set_link_field(bond, dt_dst(), dst)
        || !cep_l1_set_bool_value(bond, dt_directed(), directed)) {
        cep_l1_mark_outcome_error(request, "bond-update");
        goto done;
    }

    cep_l1_attach_request_parent(bond, request);
    cep_l1_mark_outcome_ok(request);
    result = CEP_ENZYME_SUCCESS;
    (void)cep_l1_enqueue_ready_signal(request);

done:
    cep_l1_store_unlock(&bond_lock);
    return result;
}
static int cep_l1_enzyme_ingest_ctx(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    int result = CEP_ENZYME_FATAL;
    cepL1StoreLock ctx_lock = {0};
    cepL1StoreLock roles_lock = {0};
    cepL1StoreLock facets_lock = {0};

    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_ctx_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_l1_extract_identifier(request, dt_id(), "missing-id", "invalid-id", &id_dt, NULL)) {
        goto done;
    }

    const cepData* type_data = NULL;
    cepDT type_dt = {0};
    if (!cep_l1_extract_identifier(request, dt_type(), "missing-type", "invalid-type", &type_dt, &type_data)) {
        goto done;
    }
    (void)type_dt;

    cepCell* ledger = cep_l1_context_ledger();
    if (!ledger) {
        cep_l1_mark_outcome_error(request, "missing-ledger");
        goto done;
    }

    cepCell* ctx = cep_l1_ensure_dictionary(ledger, &id_dt, CEP_STORAGE_RED_BLACK_T);
    if (!ctx) {
        cep_l1_mark_outcome_error(request, "create-failed");
        goto done;
    }

    if (!cep_l1_set_value_bytes(ctx, dt_type(), &type_data->dt, type_data->value, type_data->size)) {
        cep_l1_mark_outcome_error(request, "ctx-type");
        goto done;
    }

    cepCell* roles_req = cep_cell_find_by_name(request, dt_roles());
    if (roles_req && cep_cell_has_store(roles_req)) {
        if (!cep_l1_store_lock(ctx, &ctx_lock)) {
            cep_l1_mark_outcome_error(request, "ctx-lock");
            goto done;
        }
        cepCell* roles_dst = cep_l1_ensure_dictionary(ctx, dt_roles(), CEP_STORAGE_RED_BLACK_T);
        cep_l1_store_unlock(&ctx_lock);
        if (!roles_dst) {
            cep_l1_mark_outcome_error(request, "roles");
            goto done;
        }

        if (!cep_l1_store_lock(roles_dst, &roles_lock)) {
            cep_l1_mark_outcome_error(request, "roles-lock");
            goto done;
        }

        cep_l1_clear_children(roles_dst);
        for (cepCell* role = cep_cell_first(roles_req); role; role = cep_cell_next(roles_req, role)) {
            const cepDT* role_name = cep_cell_get_name(role);
            if (!cep_l1_require_role_name(role_name, request)) {
                goto done;
            }
            cepCell* target = cep_link_pull(role);
            if (!target) {
                cep_l1_mark_outcome_error(request, "role-target");
                goto done;
            }
            cepDT role_copy = *role_name;
            if (!cep_l1_link_child(roles_dst, &role_copy, target)) {
                cep_l1_mark_outcome_error(request, "role-link");
                goto done;
            }
        }

        cep_l1_store_unlock(&roles_lock);
    }

    cepCell* facets_req = cep_cell_find_by_name(request, dt_facets());
    if (facets_req && cep_cell_has_store(facets_req)) {
        if (!cep_l1_store_lock(ctx, &ctx_lock)) {
            cep_l1_mark_outcome_error(request, "ctx-lock");
            goto done;
        }
        cepCell* facets_dst = cep_l1_ensure_dictionary(ctx, dt_facets(), CEP_STORAGE_RED_BLACK_T);
        cep_l1_store_unlock(&ctx_lock);
        if (!facets_dst) {
            cep_l1_mark_outcome_error(request, "facets");
            goto done;
        }

        if (!cep_l1_store_lock(facets_dst, &facets_lock)) {
            cep_l1_mark_outcome_error(request, "facets-lock");
            goto done;
        }

        cep_l1_clear_children(facets_dst);
        for (cepCell* facet = cep_cell_first(facets_req); facet; facet = cep_cell_next(facets_req, facet)) {
            const cepDT* facet_name = cep_cell_get_name(facet);
            cepDT facet_name_copy = *facet_name;
            cepCell* facet_target = NULL;
            bool facet_required = false;
            if (!cep_l1_parse_facet_request(&id_dt, facet_name, request, facet, &facet_target, &facet_required, NULL)) {
                cep_l1_mark_outcome_error(request, "facet-parse");
                goto done;
            }
            if (facet_target) {
                if (!cep_l1_link_child(facets_dst, &facet_name_copy, facet_target)) {
                    cep_l1_mark_outcome_error(request, "facet-link");
                    goto done;
                }
                if (facet_required) {
                    cep_l1_clear_debt(&id_dt, &facet_name_copy);
                }
            } else if (facet_required) {
                if (!cep_l1_record_debt(&id_dt, &facet_name_copy, request)) {
                    goto done;
                }
            }
        }

        cep_l1_store_unlock(&facets_lock);
    }

    cep_l1_attach_request_parent(ctx, request);
    cep_l1_mark_outcome_ok(request);
    result = CEP_ENZYME_SUCCESS;
    (void)cep_l1_enqueue_ready_signal(request);

done:
    cep_l1_store_unlock(&facets_lock);
    cep_l1_store_unlock(&roles_lock);
    cep_l1_store_unlock(&ctx_lock);
    return result;
}
static int cep_l1_enzyme_closure(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    int result = CEP_ENZYME_FATAL;
    cepL1StoreLock mirror_lock = {0};

    cepCell* request = cep_l1_resolve_request(target_path);
    if (!cep_l1_request_guard(request, dt_ctx_upsert())) {
        return CEP_ENZYME_SUCCESS;
    }

    cepDT id_dt = {0};
    if (!cep_l1_extract_identifier(request, dt_id(), "missing-id", "invalid-id", &id_dt, NULL)) {
        goto done;
    }

    cepCell* ctx = cep_cell_find_by_name(cep_l1_context_ledger(), &id_dt);
    if (!ctx) {
        goto done;
    }

    cepCell* facets_dst = cep_cell_find_by_name(ctx, dt_facets());
    if (facets_dst && cep_cell_has_store(facets_dst)) {
        cepCell* mirror = cep_l1_facet_mirror();
        if (!mirror) {
            goto done;
        }
        if (!cep_l1_store_lock(mirror, &mirror_lock)) {
            cep_l1_mark_outcome_error(request, "facet-lock");
            goto done;
        }

        cep_l1_facet_mirror_clear_ctx_locked(mirror, &id_dt);

        for (cepCell* facet = cep_cell_first(facets_dst); facet; facet = cep_cell_next(facets_dst, facet)) {
            const cepDT* facet_name = cep_cell_get_name(facet);
            cepCell* facet_target = cep_link_pull(facet);
            if (!facet_target) {
                continue;
            }

            cepDT key_dt = {0};
            if (!cep_l1_compose_key(&id_dt, facet_name, &key_dt)) {
                goto done;
            }

            if (!cep_l1_link_child(mirror, &key_dt, facet_target)) {
                goto done;
            }
        }

        cep_l1_store_unlock(&mirror_lock);
    }

    cepCell* facets_req = cep_cell_find_by_name(request, dt_facets());
    if (facets_req && cep_cell_has_store(facets_req)) {
        for (cepCell* facet_req = cep_cell_first(facets_req); facet_req; facet_req = cep_cell_next(facets_req, facet_req)) {
            const cepDT* facet_name = cep_cell_get_name(facet_req);
            cepCell* facet_target = NULL;
            bool facet_required = false;
            bool facet_multi = false;
            if (!cep_l1_parse_facet_request(&id_dt, facet_name, request, facet_req, &facet_target, &facet_required, &facet_multi)) {
                goto done;
            }

            bool satisfied = false;
            if (facets_dst) {
                cepCell* facet_entry = cep_cell_find_by_name(facets_dst, facet_name);
                if (facet_entry && cep_cell_is_link(facet_entry) && cep_link_pull(facet_entry)) {
                    satisfied = true;
                }
            }

            if (facet_required && !satisfied) {
                if (facet_multi && facet_target) {
                    if (!cep_l1_decision_record(&id_dt, facet_name, facet_target, request)) {
                        cep_l1_mark_outcome_error(request, "decision-ledger");
                        goto done;
                    }
                }
                if (!cep_l1_record_debt(&id_dt, facet_name, request)) {
                    goto done;
                }
            } else {
                if (!facet_multi && !cep_l1_decision_clear(&id_dt, facet_name)) {
                    cep_l1_mark_outcome_error(request, "decision-ledger");
                    goto done;
                }
                cep_l1_clear_debt(&id_dt, facet_name);
            }
        }
    }

    if (!cep_l1_index_facets(ctx, &id_dt)) {
        goto done;
    }

    cep_l1_mark_outcome_ok(request);
    result = CEP_ENZYME_SUCCESS;

done:
    cep_l1_store_unlock(&mirror_lock);
    return result;
}
static int cep_l1_enzyme_index(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cepCell* request = cep_l1_resolve_request(target_path);
    if (!request) {
        return CEP_ENZYME_SUCCESS;
    }

    bool handled = false;

    if (cep_l1_request_guard(request, dt_be_create())) {
        cepDT id_dt = {0};
        if (!cep_l1_extract_identifier(request, dt_id(), NULL, NULL, &id_dt, NULL)) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* being = cep_cell_find_by_name(cep_l1_being_ledger(), &id_dt);
        if (!being) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* kind_cell = cep_cell_find_by_name(being, dt_kind());
        if (!kind_cell || !cep_cell_has_data(kind_cell)) {
            return CEP_ENZYME_RETRY;
        }

        cepDT kind_dt = {0};
        if (!cep_l1_data_to_identifier(kind_cell->data, &kind_dt)) {
            cep_l1_metrics_record_index(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_index_being(being, &id_dt, &kind_dt)) {
            cep_l1_metrics_record_index(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_bo_upsert())) {
        cepDT id_dt = {0};
        if (!cep_l1_extract_identifier(request, dt_id(), NULL, NULL, &id_dt, NULL)) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* bond = cep_cell_find_by_name(cep_l1_bond_ledger(), &id_dt);
        if (!bond) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* src_link = cep_cell_find_by_name(bond, dt_src());
        cepCell* dst_link = cep_cell_find_by_name(bond, dt_dst());
        if (!src_link || !dst_link) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* src = cep_link_pull(src_link);
        cepCell* dst = cep_link_pull(dst_link);
        if (!src || !dst) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* type_cell = cep_cell_find_by_name(bond, dt_type());
        if (!type_cell || !cep_cell_has_data(type_cell)) {
            return CEP_ENZYME_RETRY;
        }

        cepDT type_dt = {0};
        if (!cep_l1_data_to_identifier(type_cell->data, &type_dt)) {
            cep_l1_metrics_record_index(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        bool directed = false;
        cepCell* dir_cell = cep_cell_find_by_name(bond, dt_directed());
        if (dir_cell && cep_cell_has_data(dir_cell) && dir_cell->data->datatype == CEP_DATATYPE_VALUE && dir_cell->data->size > 0u) {
            directed = dir_cell->data->value[0] != 0u;
        }

        if (!cep_l1_index_bond(bond, &id_dt, src, dst, &type_dt, directed)) {
            cep_l1_metrics_record_index(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_ctx_upsert())) {
        cepDT id_dt = {0};
        if (!cep_l1_extract_identifier(request, dt_id(), NULL, NULL, &id_dt, NULL)) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* ctx = cep_cell_find_by_name(cep_l1_context_ledger(), &id_dt);
        if (!ctx) {
            return CEP_ENZYME_RETRY;
        }

        cepCell* type_cell = cep_cell_find_by_name(ctx, dt_type());
        if (!type_cell || !cep_cell_has_data(type_cell)) {
            return CEP_ENZYME_RETRY;
        }

        cepDT type_dt = {0};
        if (!cep_l1_data_to_identifier(type_cell->data, &type_dt)) {
            cep_l1_metrics_record_index(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_index_context(ctx, &id_dt, &type_dt)) {
            cep_l1_metrics_record_index(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_index_facets(ctx, &id_dt)) {
            cep_l1_metrics_record_index(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    }

    if (handled) {
        cep_l1_metrics_record_index(1u, 0u);
        cep_l1_mark_outcome_ok(request);
        (void)cep_l1_enqueue_ready_signal(request);
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
        cepDT id_dt = {0};
        if (!cep_l1_extract_identifier(request, dt_id(), NULL, NULL, &id_dt, NULL)) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        cepCell* being = cep_cell_find_by_name(cep_l1_being_ledger(), &id_dt);
        if (!being || !cep_l1_adj_being(being, &id_dt)) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_bo_upsert())) {
        cepDT id_dt = {0};
        if (!cep_l1_extract_identifier(request, dt_id(), NULL, NULL, &id_dt, NULL)) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        cepCell* bond = cep_cell_find_by_name(cep_l1_bond_ledger(), &id_dt);
        if (!bond) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        cepCell* src_link = cep_cell_find_by_name(bond, dt_src());
        cepCell* dst_link = cep_cell_find_by_name(bond, dt_dst());
        if (!src_link || !dst_link) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        cepCell* src = cep_link_pull(src_link);
        cepCell* dst = cep_link_pull(dst_link);
        if (!src || !dst) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_adj_bond(bond, &id_dt, src, dst)) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    } else if (cep_l1_request_guard(request, dt_ctx_upsert())) {
        cepDT id_dt = {0};
        if (!cep_l1_extract_identifier(request, dt_id(), NULL, NULL, &id_dt, NULL)) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        cepCell* ctx = cep_cell_find_by_name(cep_l1_context_ledger(), &id_dt);
        if (!ctx) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        if (!cep_l1_adj_context(ctx, &id_dt)) {
            cep_l1_metrics_record_adj(0u, 1u);
            return CEP_ENZYME_FATAL;
        }

        handled = true;
    }

    if (handled) {
        cep_l1_metrics_record_adj(1u, 0u);
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
    cepDT              after_mailroom[1];
} cepL1RegistryRecord;

static cepL1RegistryRecord* cep_l1_records = NULL;
static size_t cep_l1_record_count = 0u;
static size_t cep_l1_record_capacity = 0u;

static void cep_l1_reset_runtime_state(void) {
    cepCell* adj_root = cep_l1_adj_root();
    if (adj_root && cep_cell_has_store(adj_root)) {
        cep_cell_delete_children_hard(adj_root);
    }

    cep_l1_index_metric_count = 0u;
    cep_l1_adj_metric_count = 0u;
    cep_l1_bindings_applied = false;

    cepCell* coh_root = cep_l1_coh_root();
    if (coh_root) {
        (void)cep_cell_unbind_enzyme(coh_root, dt_coh_ing_be());
        (void)cep_cell_unbind_enzyme(coh_root, dt_coh_ing_bo());
        (void)cep_cell_unbind_enzyme(coh_root, dt_coh_ing_ctx());
        (void)cep_cell_unbind_enzyme(coh_root, dt_coh_closure());
        (void)cep_cell_unbind_enzyme(coh_root, dt_coh_index());
        (void)cep_cell_unbind_enzyme(coh_root, dt_coh_adj());
    }

    if (cep_l1_records) {
        free(cep_l1_records);
        cep_l1_records = NULL;
    }
    cep_l1_record_count = 0u;
    cep_l1_record_capacity = 0u;
}

/* Expose the teardown helper so tests and manual restarts can scrub Layer 1
 * caches and bookkeeping without waiting for the heartbeat. The function wipes
 * adjacency mirrors, drops registry bookkeeping, and flips the lifecycle flag
 * so the next bootstrap observes a clean start. */
void cep_l1_coherence_shutdown(void) {
    /* Keep the callable helper in sync with the shutdown enzyme so callers
       can tear Layer 1 down explicitly during tests or manual restarts. */
    cep_l1_reset_runtime_state();
    (void)cep_lifecycle_scope_mark_teardown(CEP_LIFECYCLE_SCOPE_L1);
}

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
        cep_l1_records[i].after_mailroom[0].domain = 0u;
        cep_l1_records[i].after_mailroom[0].tag = 0u;
        cep_l1_records[i].after_mailroom[0].glob = 0u;
    }
        cep_l1_record_capacity = new_capacity;
    }

    cepL1RegistryRecord* record = &cep_l1_records[cep_l1_record_count++];
    record->registry = registry;
    record->baseline = baseline;
    record->after_mailroom[0].domain = 0u;
    record->after_mailroom[0].tag = 0u;
    record->after_mailroom[0].glob = 0u;
    return record;
}

/* ------------------------------------------------------------------------- */
/*  Registration                                                             */
/* ------------------------------------------------------------------------- */

bool cep_l1_coherence_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (!cep_mailroom_register(registry)) {
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
    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[3];
    } cepPathStatic3;

    cepPathStatic2 init_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_init(), .timestamp = 0u},
        },
    };

    cepEnzymeDescriptor init_descriptor = {
        .name = *dt_coh_init(),
        .label = "coh.init",
        .callback = cep_l1_enzyme_init,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
        .after = record->after_mailroom,
        .after_count = cep_lengthof(record->after_mailroom),
    };

    record->after_mailroom[0] = *CEP_DTAW("CEP", "mr_init");

    if (cep_enzyme_register(registry, (const cepPath*)&init_path, &init_descriptor) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    cepPathStatic3 teardown_path = {
        .length = 3u,
        .capacity = 3u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_teardown(), .timestamp = 0u},
            {.dt = *dt_scope_l1(), .timestamp = 0u},
        },
    };

    cepEnzymeDescriptor shutdown_descriptor = {
        .name = *dt_coh_shutdown(),
        .label = "coh.shutdown",
        .callback = cep_l1_enzyme_shutdown,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    if (cep_enzyme_register(registry, (const cepPath*)&teardown_path, &shutdown_descriptor) != CEP_ENZYME_SUCCESS) {
        return false;
    }

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_signal_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    cepPathStatic3 ready_signal_path = {
        .length = 3u,
        .capacity = 3u,
        .past = {
            {.dt = *dt_sig_sys(), .timestamp = 0u},
            {.dt = *dt_sys_ready(), .timestamp = 0u},
            {.dt = *dt_scope_l1(), .timestamp = 0u},
        },
    };

    for (size_t i = 0; i < sizeof descriptors / sizeof descriptors[0]; ++i) {
        const cepPath* path = (const cepPath*)&signal_path;
        if (cep_dt_compare(&descriptors[i].name, dt_coh_adj()) == 0 ||
            cep_dt_compare(&descriptors[i].name, dt_coh_index()) == 0) {
            path = (const cepPath*)&ready_signal_path;
        }

        if (cep_enzyme_register(registry, path, &descriptors[i]) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    return true;
}
