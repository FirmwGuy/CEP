#include "cep_error.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cep_heartbeat.h"
#include "cep_identifier.h"
#include "cep_namepool.h"
#include "cep_molecule.h"

CEP_DEFINE_STATIC_DT(dt_sig_err,        CEP_ACRO("CEP"), CEP_WORD("sig_err"));
CEP_DEFINE_STATIC_DT(dt_err_scope,      CEP_ACRO("CEP"), CEP_WORD("kernel"));
CEP_DEFINE_STATIC_DT(dt_err_root,       CEP_ACRO("CEP"), CEP_WORD("err"));
CEP_DEFINE_STATIC_DT(dt_err_stage,      CEP_ACRO("CEP"), CEP_WORD("stage"));
CEP_DEFINE_STATIC_DT(dt_err_cat,        CEP_ACRO("CEP"), CEP_WORD("err_cat"));
CEP_DEFINE_STATIC_DT(dt_dictionary,     CEP_ACRO("CEP"), CEP_WORD("dictionary"));
CEP_DEFINE_STATIC_DT(dt_list,           CEP_ACRO("CEP"), CEP_WORD("list"));
CEP_DEFINE_STATIC_DT(dt_text,           CEP_ACRO("CEP"), CEP_WORD("text"));
CEP_DEFINE_STATIC_DT(dt_field_code,     CEP_ACRO("CEP"), CEP_WORD("code"));
CEP_DEFINE_STATIC_DT(dt_field_message,  CEP_ACRO("CEP"), CEP_WORD("message"));
CEP_DEFINE_STATIC_DT(dt_field_level,    CEP_ACRO("CEP"), CEP_WORD("level"));
CEP_DEFINE_STATIC_DT(dt_field_scope,    CEP_ACRO("CEP"), CEP_WORD("scope"));
CEP_DEFINE_STATIC_DT(dt_field_beat,     CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_field_target,   CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_field_parents,  CEP_ACRO("CEP"), CEP_WORD("parents"));
CEP_DEFINE_STATIC_DT(dt_field_detail,   CEP_ACRO("CEP"), CEP_WORD("detail"));
CEP_DEFINE_STATIC_DT(dt_field_emitter,  CEP_ACRO("CEP"), CEP_WORD("emitter"));
CEP_DEFINE_STATIC_DT(dt_field_emit_kind, CEP_ACRO("CEP"), CEP_WORD("emit_kind"));
CEP_DEFINE_STATIC_DT(dt_field_emit_label, CEP_ACRO("CEP"), CEP_WORD("emit_label"));

CEP_DEFINE_STATIC_DT(dt_level_fatal,    CEP_ACRO("CEP"), CEP_WORD("fatal"));
CEP_DEFINE_STATIC_DT(dt_level_critical, CEP_ACRO("CEP"), CEP_WORD("critical"));
CEP_DEFINE_STATIC_DT(dt_level_usage,    CEP_ACRO("CEP"), CEP_WORD("usage"));
CEP_DEFINE_STATIC_DT(dt_level_warn,     CEP_ACRO("CEP"), CEP_WORD("warn"));
CEP_DEFINE_STATIC_DT(dt_level_log,      CEP_ACRO("CEP"), CEP_WORD("log"));

static const char* cep_error_level_text(cepErrLevel level) {
    switch (level) {
        case CEP_ERR_FATAL:    return "fatal";
        case CEP_ERR_CRITICAL: return "critical";
        case CEP_ERR_USAGE:    return "usage";
        case CEP_ERR_WARN:     return "warn";
        case CEP_ERR_LOG:      return "log";
        default:               return NULL;
    }
}

static const cepDT* cep_error_level_dt(cepErrLevel level) {
    switch (level) {
        case CEP_ERR_FATAL:    return dt_level_fatal();
        case CEP_ERR_CRITICAL: return dt_level_critical();
        case CEP_ERR_USAGE:    return dt_level_usage();
        case CEP_ERR_WARN:     return dt_level_warn();
        case CEP_ERR_LOG:      return dt_level_log();
        default:               return NULL;
    }
}

static bool cep_error_id_to_text(cepID id, char* buffer, size_t capacity, size_t* len_out) {
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
    } else if (cep_id_is_numeric(id)) {
        int rc = snprintf(buffer, capacity, "%" PRIu64, (unsigned long long)cep_id(id));
        if (rc <= 0) {
            return false;
        }
        len = (size_t)rc;
    } else {
        if (capacity < 2u) {
            return false;
        }
        buffer[0] = '?';
        buffer[1] = '\0';
        len = 1u;
    }

    if (len_out) {
        *len_out = len;
    }
    return len + 1u <= capacity;
}

static bool cep_error_dt_to_text(const cepDT* dt, char* buffer, size_t capacity) {
    if (!dt || !buffer) {
        return false;
    }

    char domain[64];
    size_t domain_len = 0u;
    if (!cep_error_id_to_text(dt->domain, domain, sizeof domain, &domain_len)) {
        return false;
    }

    char tag[64];
    size_t tag_len = 0u;
    if (!cep_error_id_to_text(dt->tag, tag, sizeof tag, &tag_len)) {
        return false;
    }

    size_t needed = domain_len + 1u + tag_len;
    if (needed + 1u > capacity) {
        return false;
    }

    memcpy(buffer, domain, domain_len);
    buffer[domain_len] = ':';
    memcpy(buffer + domain_len + 1u, tag, tag_len);
    buffer[needed] = '\0';
    return true;
}

static bool cep_error_store_text(cepCell* dict, const cepDT* name, const char* text) {
    if (!dict || !name || !text) {
        return false;
    }
    size_t len = strlen(text) + 1u;
    cepDT name_copy = cep_dt_clean(name);
    cepDT payload_type = *dt_text();
    return cep_dict_add_value(dict, &name_copy, &payload_type, (void*)text, len, len) != NULL;
}

static bool cep_error_store_number(cepCell* dict, const cepDT* name, uint64_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%" PRIu64, (unsigned long long)value);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return cep_error_store_text(dict, name, buffer);
}

static bool cep_error_store_dt(cepCell* dict, const cepDT* name, const cepDT* value) {
    char buffer[128];
    if (!cep_error_dt_to_text(value, buffer, sizeof buffer)) {
        return false;
    }
    return cep_error_store_text(dict, name, buffer);
}

static cepCell* cep_error_ensure_dictionary(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* node = cep_cell_find_by_name(parent, name);
    if (!node) {
        cepDT type = *dt_dictionary();
        cepDT name_copy = cep_dt_clean(name);
        node = cep_cell_add_dictionary(parent, &name_copy, 0, &type, CEP_STORAGE_RED_BLACK_T);
    } else if (!cep_cell_has_store(node) || node->store->indexing != CEP_INDEX_BY_NAME) {
        cep_cell_to_dictionary(node);
    }
    return node;
}

static cepCell* cep_error_stage_root(void) {
    cepCell* tmp_root = cep_heartbeat_tmp_root();
    if (!tmp_root) {
        return NULL;
    }

    cepCell* err_root = cep_error_ensure_dictionary(tmp_root, dt_err_root());
    if (!err_root) {
        return NULL;
    }

    return cep_error_ensure_dictionary(err_root, dt_err_stage());
}

static bool cep_error_code_exists(const cepDT* scope_dt, const cepDT* code_dt) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    if (!sys_root) {
        return false;
    }

    cepCell* catalog = cep_cell_find_by_name(sys_root, dt_err_cat());
    if (!catalog || !cep_cell_has_store(catalog)) {
        return false;
    }

    cepDT scope_lookup = cep_dt_clean(scope_dt);
    cepCell* scope_node = cep_cell_find_by_name(catalog, &scope_lookup);
    if (!scope_node || !cep_cell_has_store(scope_node)) {
        return false;
    }

    cepDT code_lookup = cep_dt_clean(code_dt);
    return cep_cell_find_by_name(scope_node, &code_lookup) != NULL;
}

static bool cep_error_attach_parents(cepCell* event, cepCell** parents, size_t count) {
    if (!event || !parents || !count) {
        return false;
    }

    cepDT list_type = *dt_list();
    cepDT parents_name = cep_dt_clean(dt_field_parents());
    cepCell* parent_list = cep_dict_add_list(event, &parents_name, &list_type, CEP_STORAGE_LINKED_LIST);
    if (!parent_list) {
        return false;
    }

    for (size_t i = 0; i < count; ++i) {
        cepCell* parent = parents[i];
        if (!parent) {
            continue;
        }
        cepDT entry_name = {
            .domain = CEP_ACRO("CEP"),
            .tag = CEP_AUTOID,
            .glob = 0u,
        };
        if (!cep_cell_append_link(parent_list, &entry_name, parent)) {
            return false;
        }
    }

    return true;
}

static cepCell* cep_error_clone_detail(cepCell* detail_source) {
    if (!detail_source) {
        return NULL;
    }
    return cep_cell_clone_deep(detail_source);
}

bool cep_error_emit(cepErrLevel level, const cepErrorSpec* spec) {
    if (!spec) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    const cepDT* level_dt = cep_error_level_dt(level);
    const char* level_text = cep_error_level_text(level);
    if (!level_dt || !level_text) {
        return false;
    }

    cepDT scope_dt = cep_dt_clean(cep_dt_is_valid(&spec->scope) ? &spec->scope : dt_err_scope());
    if (!cep_dt_is_valid(&scope_dt)) {
        scope_dt = *dt_err_scope();
    }

    if (!cep_dt_is_valid(&spec->code)) {
        return false;
    }

    if (!cep_error_code_exists(&scope_dt, &spec->code)) {
        return false;
    }

    if (spec->parent_count > 0 && !spec->parents) {
        return false;
    }

    cepCell* stage_root = cep_error_stage_root();
    if (!stage_root) {
        return false;
    }

    cepDT event_name = {
        .domain = CEP_ACRO("CEP"),
        .tag = CEP_AUTOID,
        .glob = 0u,
    };
    cepDT dict_type = *dt_dictionary();
    cepCell* event = cep_cell_append_dictionary(stage_root, &event_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!event) {
        return false;
    }

    bool success = false;
    cepCell* detail_clone = NULL;
    cepPath* target_path = NULL;

    const cepEnzymeDescriptor* emitter = cep_enzyme_current();
    const char* message = spec->message ? spec->message : "";
    char* prefixed_message = NULL;

    if (!emitter) {
        const char* prefix = "CEP-L0: ";
        size_t prefix_len = strlen(prefix);
        size_t msg_len = strlen(message);
        prefixed_message = cep_malloc(prefix_len + msg_len + 1u);
        if (!prefixed_message) {
            goto cleanup;
        }
        memcpy(prefixed_message, prefix, prefix_len);
        memcpy(prefixed_message + prefix_len, message, msg_len + 1u);
        message = prefixed_message;
    }

    if (!cep_error_store_dt(event, dt_field_code(), &spec->code)) {
        goto cleanup;
    }
    if (!cep_error_store_text(event, dt_field_message(), message)) {
        goto cleanup;
    }
    if (!cep_error_store_text(event, dt_field_level(), level_text)) {
        goto cleanup;
    }
    if (!cep_error_store_dt(event, dt_field_scope(), &scope_dt)) {
        goto cleanup;
    }

    cepBeatNumber beat = cep_heartbeat_current();
    if (beat == CEP_BEAT_INVALID) {
        beat = cep_heartbeat_next();
        if (beat == CEP_BEAT_INVALID) {
            beat = 0u;
        }
    }
    if (!cep_error_store_number(event, dt_field_beat(), beat)) {
        goto cleanup;
    }

    const char* emitter_kind = emitter ? "enzyme" : "kernel";
    if (!cep_error_store_text(event, dt_field_emit_kind(), emitter_kind)) {
        goto cleanup;
    }

    if (emitter) {
        if (!cep_error_store_dt(event, dt_field_emitter(), &emitter->name)) {
            goto cleanup;
        }
        if (emitter->label && !cep_error_store_text(event, dt_field_emit_label(), emitter->label)) {
            goto cleanup;
        }
    } else {
        if (!cep_error_store_dt(event, dt_field_emitter(), dt_err_scope())) {
            goto cleanup;
        }
    }

    if (spec->target) {
        cepDT target_name = cep_dt_clean(dt_field_target());
        if (!cep_dict_add_link(event, &target_name, spec->target)) {
            goto cleanup;
        }
    }

    if (spec->parent_count > 0) {
        if (!cep_error_attach_parents(event, spec->parents, spec->parent_count)) {
            goto cleanup;
        }
    }

    if (spec->detail) {
        detail_clone = cep_error_clone_detail(spec->detail);
        if (!detail_clone) {
            goto cleanup;
        }
        detail_clone->metacell.domain = dt_field_detail()->domain;
        detail_clone->metacell.tag = dt_field_detail()->tag;
        detail_clone->metacell.glob = dt_field_detail()->glob;
        if (!cep_dict_add(event, detail_clone)) {
            goto cleanup;
        }
        detail_clone = NULL;
    }

    if (!cep_cell_path(event, &target_path)) {
        goto cleanup;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[3];
    } cepStaticPath3;

    cepStaticPath3 signal_path = {
        .length = 3u,
        .capacity = 3u,
        .past = {
            { .dt = *dt_sig_err(),        .timestamp = 0u },
            { .dt = *level_dt, .timestamp = 0u },
            { .dt = scope_dt, .timestamp = 0u },
        },
    };

    cepImpulse impulse = {
        .signal_path = (const cepPath*)&signal_path,
        .target_path = target_path,
    };

    if (cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &impulse) != CEP_ENZYME_SUCCESS) {
        goto cleanup;
    }

    success = true;

cleanup:
    CEP_FREE(prefixed_message);
    if (target_path) {
        CEP_FREE(target_path);
    }
    if (!success) {
        if (detail_clone) {
            cep_cell_finalize_hard(detail_clone);
            CEP_FREE(detail_clone);
        }
        if (event) {
            cep_cell_remove_hard(stage_root, event);
        }
    }

    return success;
}
