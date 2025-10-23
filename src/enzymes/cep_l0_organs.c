#include "cep_l0_organs.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_organ.h"
#include "cep_cell_operations.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));
CEP_DEFINE_STATIC_DT(dt_meta_name, CEP_ACRO("CEP"), CEP_WORD("meta"));
CEP_DEFINE_STATIC_DT(dt_schema_name, CEP_ACRO("CEP"), CEP_WORD("schema"));
CEP_DEFINE_STATIC_DT(dt_schema_summary, CEP_ACRO("CEP"), CEP_WORD("summary"));
CEP_DEFINE_STATIC_DT(dt_schema_layout, CEP_ACRO("CEP"), CEP_WORD("layout"));
CEP_DEFINE_STATIC_DT(dt_inbox_name, CEP_ACRO("CEP"), CEP_WORD("inbox"));
CEP_DEFINE_STATIC_DT(dt_agenda_name, CEP_ACRO("CEP"), CEP_WORD("agenda"));
CEP_DEFINE_STATIC_DT(dt_stage_name, CEP_ACRO("CEP"), CEP_WORD("stage"));
CEP_DEFINE_STATIC_DT(dt_ops_envelope_name, CEP_ACRO("CEP"), CEP_WORD("envelope"));
CEP_DEFINE_STATIC_DT(dt_ops_verb_field, CEP_ACRO("CEP"), CEP_WORD("verb"));
CEP_DEFINE_STATIC_DT(dt_ops_target_field, CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_ops_mode_field, CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_ops_state_field, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_ops_close_name, CEP_ACRO("CEP"), CEP_WORD("close"));
CEP_DEFINE_STATIC_DT(dt_ops_status_field, CEP_ACRO("CEP"), CEP_WORD("status"));

static cepCell* cep_l0_ops_root(void);

static const char* const CEP_L0_SCHEMA_RT_BEAT_SUMMARY     = "Heartbeat beat ledger capturing inbox, agenda, and stage evidence per beat.";
static const char* const CEP_L0_SCHEMA_RT_BEAT_LAYOUT      = "<beat>/inbox|agenda|stage lists preserve capture, compute, commit ordering.";
static const char* const CEP_L0_SCHEMA_JOURNAL_SUMMARY     = "Append-only runtime journal for organ operations and stream evidence.";
static const char* const CEP_L0_SCHEMA_JOURNAL_LAYOUT      = "Child dictionaries map channels to insertion-ordered ledger lists.";
typedef enum {
    CEP_L0_ORGAN_SYS_STATE = 0,
    CEP_L0_ORGAN_SYS_ORGANS,
    CEP_L0_ORGAN_RT_OPS,
    CEP_L0_ORGAN_RT_BEAT,
    CEP_L0_ORGAN_JOURNAL,
    CEP_L0_ORGAN_ENV,
    CEP_L0_ORGAN_CAS,
    CEP_L0_ORGAN_LIB,
    CEP_L0_ORGAN_TMP,
    CEP_L0_ORGAN_ENZYMES,
    CEP_L0_ORGAN_COUNT,
} cepL0OrganId;

typedef struct {
    const char* kind;
    const char* label;
    const char* path_text;
    cepEnzyme   callback;
    cepEnzyme   constructor_cb;
    cepEnzyme   destructor_cb;
    const char* constructor_label;
    const char* destructor_label;
    cepDT       path_segments[3];
    size_t      segment_count;
    cepDT       validator_name;
    cepDT       constructor_name;
    cepDT       destructor_name;
    bool        validator_ready;
    bool        constructor_ready;
    bool        destructor_ready;
} cepL0OrganDefinition;

static cepCell* cep_l0_organ_resolve_root_from_segments(const cepL0OrganDefinition* def);

typedef struct {
    cepOID                      oid;
    bool                        ok;
    size_t                      issues;
    size_t                      checked_nodes;
    size_t                      checked_values;
    char                        first_issue[160];
    const cepL0OrganDefinition* def;
} cepL0OrganValidationRun;

typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     past[1];
} cepPathConst1;

static int cep_l0_organ_vl_sys_state(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_sys_organs(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_rt_ops(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_rt_beat(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_journal(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_env(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_cas(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_lib(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_tmp(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_enzymes(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_ct_rt_beat(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_dt_rt_beat(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_ct_journal(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_dt_journal(const cepPath* signal_path, const cepPath* target_path);

static cepL0OrganDefinition CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_COUNT] = {
    [CEP_L0_ORGAN_SYS_STATE] = {
        .kind       = "sys_state",
        .label      = "organ.sys_state.vl",
        .path_text  = "/sys/state",
        .callback   = cep_l0_organ_vl_sys_state,
    },
    [CEP_L0_ORGAN_SYS_ORGANS] = {
        .kind       = "sys_organs",
        .label      = "organ.sys_organs.vl",
        .path_text  = "/sys/organs",
        .callback   = cep_l0_organ_vl_sys_organs,
    },
    [CEP_L0_ORGAN_RT_OPS] = {
        .kind       = "rt_ops",
        .label      = "organ.rt_ops.vl",
        .path_text  = "/rt/ops",
        .callback   = cep_l0_organ_vl_rt_ops,
    },
    [CEP_L0_ORGAN_RT_BEAT] = {
        .kind              = "rt_beat",
        .label             = "organ.rt_beat.vl",
        .path_text         = "/rt/beat",
        .callback          = cep_l0_organ_vl_rt_beat,
        .constructor_cb    = cep_l0_organ_ct_rt_beat,
        .destructor_cb     = cep_l0_organ_dt_rt_beat,
        .constructor_label = "organ.rt_beat.ct",
        .destructor_label  = "organ.rt_beat.dt",
    },
    [CEP_L0_ORGAN_JOURNAL] = {
        .kind              = "journal",
        .label             = "organ.journal.vl",
        .path_text         = "/journal",
        .callback          = cep_l0_organ_vl_journal,
        .constructor_cb    = cep_l0_organ_ct_journal,
        .destructor_cb     = cep_l0_organ_dt_journal,
        .constructor_label = "organ.journal.ct",
        .destructor_label  = "organ.journal.dt",
    },
    [CEP_L0_ORGAN_ENV] = {
        .kind       = "env",
        .label      = "organ.env.vl",
        .path_text  = "/env",
        .callback   = cep_l0_organ_vl_env,
    },
    [CEP_L0_ORGAN_CAS] = {
        .kind       = "cas",
        .label      = "organ.cas.vl",
        .path_text  = "/cas",
        .callback   = cep_l0_organ_vl_cas,
    },
    [CEP_L0_ORGAN_LIB] = {
        .kind       = "lib",
        .label      = "organ.lib.vl",
        .path_text  = "/lib",
        .callback   = cep_l0_organ_vl_lib,
    },
    [CEP_L0_ORGAN_TMP] = {
        .kind       = "tmp",
        .label      = "organ.tmp.vl",
        .path_text  = "/tmp",
        .callback   = cep_l0_organ_vl_tmp,
    },
    [CEP_L0_ORGAN_ENZYMES] = {
        .kind       = "enzymes",
        .label      = "organ.enzymes.vl",
        .path_text  = "/enzymes",
        .callback   = cep_l0_organ_vl_enzymes,
    },
};

static void cep_l0_organs_initialise(void) {
    static bool initialised = false;
    if (initialised) {
        return;
    }

    cepL0OrganDefinition* sys_state = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_SYS_STATE];
    sys_state->path_segments[0] = *CEP_DTAW("CEP", "sys");
    sys_state->path_segments[1] = *CEP_DTAW("CEP", "state");
    sys_state->segment_count = 2u;

    cepL0OrganDefinition* sys_organs = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_SYS_ORGANS];
   sys_organs->path_segments[0] = *CEP_DTAW("CEP", "sys");
   sys_organs->path_segments[1] = *CEP_DTAW("CEP", "organs");
   sys_organs->segment_count = 2u;

    cepL0OrganDefinition* rt_ops = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_RT_OPS];
    rt_ops->path_segments[0] = *CEP_DTAW("CEP", "rt");
    rt_ops->path_segments[1] = *CEP_DTAW("CEP", "ops");
    rt_ops->segment_count = 2u;

    cepL0OrganDefinition* rt_beat = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_RT_BEAT];
    rt_beat->path_segments[0] = *CEP_DTAW("CEP", "rt");
    rt_beat->path_segments[1] = *CEP_DTAW("CEP", "beat");
    rt_beat->segment_count = 2u;

    cepL0OrganDefinition* journal = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_JOURNAL];
    journal->path_segments[0] = *CEP_DTAW("CEP", "journal");
    journal->segment_count = 1u;

    cepL0OrganDefinition* env = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_ENV];
    env->path_segments[0] = *CEP_DTAW("CEP", "env");
    env->segment_count = 1u;

    cepL0OrganDefinition* cas = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_CAS];
    cas->path_segments[0] = *CEP_DTAW("CEP", "cas");
    cas->segment_count = 1u;

    cepL0OrganDefinition* lib = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_LIB];
    lib->path_segments[0] = *CEP_DTAW("CEP", "lib");
    lib->segment_count = 1u;

    cepL0OrganDefinition* tmp = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_TMP];
    tmp->path_segments[0] = *CEP_DTAW("CEP", "tmp");
    tmp->segment_count = 1u;

    cepL0OrganDefinition* enzymes = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_ENZYMES];
    enzymes->path_segments[0] = *CEP_DTAW("CEP", "enzymes");
    enzymes->segment_count = 1u;

    initialised = true;
}

void cep_l0_organs_invalidate_signals(void) {
    cep_l0_organs_initialise();
    for (size_t i = 0; i < CEP_L0_ORGAN_COUNT; ++i) {
        cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[i];
        def->validator_ready = false;
        def->constructor_ready = false;
        def->destructor_ready = false;
        def->validator_name = (cepDT){0};
        def->constructor_name = (cepDT){0};
        def->destructor_name = (cepDT){0};
    }
}

void cep_l0_organs_refresh_store_dts(void) {
    cep_l0_organs_initialise();
    for (size_t i = 0; i < CEP_L0_ORGAN_COUNT; ++i) {
        const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[i];
        cepCell* root = cep_l0_organ_resolve_root_from_segments(def);
        if (!root) {
            continue;
        }
        cepCell* resolved = cep_cell_resolve(root);
        if (!resolved) {
            continue;
        }
        if (!cep_cell_require_dictionary_store(&resolved) || !resolved->store) {
            continue;
        }
        cepDT store_dt = cep_organ_store_dt(def->kind);
        if (!cep_dt_is_valid(&store_dt)) {
            continue;
        }
        cep_store_set_dt(resolved->store, &store_dt);
        CEP_DEBUG_PRINTF_STDOUT("[refresh_store_dts] kind=%s store=%08x/%08x\n",
                                def->kind ? def->kind : "<null>",
                                (unsigned)resolved->store->dt.domain,
                                (unsigned)resolved->store->dt.tag);
    }
}

static cepDT cep_l0_organs_make_signal_dt(const char* kind, const char* suffix) {
    if (!kind || !*kind || !suffix || !*suffix) {
        return (cepDT){0};
    }

    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "org:%s:%s", kind, suffix);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return (cepDT){0};
    }

    return cep_ops_make_dt(buffer);
}

static bool cep_l0_organ_id_to_text(cepID id, char* buffer, size_t capacity, size_t* out_len) {
    if (!buffer || capacity == 0u) {
        return false;
    }

    size_t len = 0u;

    if (cep_id_is_reference(id)) {
        size_t ref_len = 0u;
        const char* text = cep_namepool_lookup(id, &ref_len);
        if (!text || ref_len + 1u > capacity) {
            return false;
        }
        memcpy(buffer, text, ref_len);
        buffer[ref_len] = '\0';
        len = ref_len;
    } else if (cep_id_is_word(id)) {
        len = cep_word_to_text(id, buffer);
    } else if (cep_id_is_acronym(id)) {
        len = cep_acronym_to_text(id, buffer);
    } else if (cep_id_is_numeric(id)) {
        uint64_t value = (uint64_t)cep_id(id);
        int written = snprintf(buffer, capacity, "%" PRIu64, value);
        if (written < 0) {
            return false;
        }
        len = (size_t)written;
    } else {
        if (capacity < 2u) {
            return false;
        }
        buffer[0] = '?';
        buffer[1] = '\0';
        len = 1u;
    }

    if (out_len) {
        *out_len = len;
    }
    return true;
}

static bool cep_l0_organ_path_to_text(const cepPath* path, char* buffer, size_t capacity) {
    if (!buffer || capacity == 0u) {
        return false;
    }
    if (!path || path->length == 0u) {
        if (capacity < 2u) {
            return false;
        }
        buffer[0] = '/';
        buffer[1] = '\0';
        return true;
    }

    size_t used = 0u;
    buffer[0] = '\0';

    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        char domain_buf[32];
        char tag_buf[64];
        size_t domain_len = 0u;
        size_t tag_len = 0u;

        if (!cep_l0_organ_id_to_text(segment->dt.domain, domain_buf, sizeof domain_buf, &domain_len)) {
            return false;
        }
        if (!cep_l0_organ_id_to_text(segment->dt.tag, tag_buf, sizeof tag_buf, &tag_len)) {
            return false;
        }

        size_t needed = 1u + tag_len + ((domain_len && strncmp(domain_buf, "CEP", domain_len) != 0) ? (domain_len + 1u) : 0u);
        if (used + needed + 1u > capacity) {
            return false;
        }

        buffer[used++] = '/';
        if (domain_len && strncmp(domain_buf, "CEP", domain_len) != 0) {
            memcpy(buffer + used, domain_buf, domain_len);
            used += domain_len;
            buffer[used++] = ':';
        }
        memcpy(buffer + used, tag_buf, tag_len);
        used += tag_len;
        buffer[used] = '\0';
    }

    return true;
}

static bool cep_l0_organ_emit_op_text(const char* target_text, const char* verb_tag, const char* stage_label) {
    if (!target_text || !*target_text || !verb_tag || !*verb_tag) {
        return false;
    }

    cepCell* ops_root = cep_l0_ops_root();
    if (!ops_root) {
        cep_heartbeat_stage_note("organ:dossier ops_root missing");
        return false;
    }

    cepDT verb = cep_ops_make_dt(verb_tag);
    cepDT mode = cep_ops_make_dt("opm:states");
    if (!cep_dt_is_valid(&verb) || !cep_dt_is_valid(&mode)) {
        cep_heartbeat_stage_note("organ:dossier invalid op dt");
        return false;
    }

    cepTxn txn = {0};
    cepDT dict_type = *dt_dictionary_type();
    cepDT op_name = {
        .domain = CEP_ACRO("OPS"),
        .tag = CEP_AUTOID,
        .glob = 0u,
    };

    if (!cep_txn_begin(ops_root, &op_name, &dict_type, &txn)) {
        cep_heartbeat_stage_note("organ:dossier txn_begin_failed");
        return false;
    }

    bool ok = true;
    do {
        cepCell* op_resolved = txn.root;
        if (!op_resolved) {
            ok = false;
            break;
        }

        cepDT envelope_name = *dt_ops_envelope_name();
        cepCell* envelope = cep_cell_add_dictionary(op_resolved, &envelope_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!envelope) {
            ok = false;
            break;
        }
        envelope = cep_cell_resolve(envelope);
        if (!envelope) {
            ok = false;
            break;
        }

        cepDT value_dt = cep_ops_make_dt("val/dt");
        cepDT verb_field = *dt_ops_verb_field();
        if (!cep_dict_add_value(envelope, &verb_field, &value_dt, &verb, sizeof verb, sizeof verb)) {
            ok = false;
            break;
        }

        cepDT target_field = *dt_ops_target_field();
        cepDT str_type = cep_ops_make_dt("val/str");
        size_t target_len = strlen(target_text) + 1u;
        if (!cep_dict_add_value(envelope, &target_field, &str_type, (void*)target_text, target_len, target_len)) {
            ok = false;
            break;
        }

        cepDT mode_field = *dt_ops_mode_field();
        if (!cep_dict_add_value(envelope, &mode_field, &value_dt, &mode, sizeof mode, sizeof mode)) {
            ok = false;
            break;
        }

        cepDT state_field = *dt_ops_state_field();
        cepDT ist_ok = cep_ops_make_dt("ist:ok");
        if (!cep_dict_add_value(op_resolved, &state_field, &value_dt, &ist_ok, sizeof ist_ok, sizeof ist_ok)) {
            ok = false;
            break;
        }

        cepDT close_name = *dt_ops_close_name();
        cepCell* close = cep_cell_add_dictionary(op_resolved, &close_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!close) {
            ok = false;
            break;
        }
        close = cep_cell_resolve(close);
        if (!close) {
            ok = false;
            break;
        }

        cepDT status_field = *dt_ops_status_field();
        cepDT sts_ok = cep_ops_make_dt("sts:ok");
        if (!cep_dict_add_value(close, &status_field, &value_dt, &sts_ok, sizeof sts_ok, sizeof sts_ok)) {
            ok = false;
            break;
        }
    } while (0);

    if (!ok || !cep_txn_mark_ready(&txn) || !cep_txn_commit(&txn)) {
        cep_txn_abort(&txn);
        char note[160];
        snprintf(note, sizeof note, "%s manual_op_commit_failed", stage_label ? stage_label : "organ:dossier");
        cep_heartbeat_stage_note(note);
        return false;
    }

    return true;
}

static bool cep_l0_organ_emit_op(const cepPath* target_path, const char* verb_tag, const char* stage_label) {
    if (!target_path || !verb_tag) {
        return false;
    }

    char path_text[192];
    if (!cep_l0_organ_path_to_text(target_path, path_text, sizeof path_text)) {
        cep_heartbeat_stage_note("organ:dossier path_to_text_failed");
        return false;
    }

    return cep_l0_organ_emit_op_text(path_text, verb_tag, stage_label);
}

static cepCell* cep_l0_organ_schema_ensure(cepCell* root) {
    if (!root) {
        return NULL;
    }

    cepCell* resolved_root = cep_cell_resolve(root);
    if (!resolved_root) {
        return NULL;
    }
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        return NULL;
    }

    cepStore* root_store = resolved_root->store;
    unsigned root_writable_before = root_store ? root_store->writable : 0u;
    if (root_store && !root_store->writable) {
        root_store->writable = 1u;
    }

    cepCell* meta = cep_cell_find_by_name(resolved_root, dt_meta_name());
    if (!meta) {
        cepDT meta_name = *dt_meta_name();
        cepDT dict_type = *dt_dictionary_type();
        meta = cep_cell_add_dictionary(resolved_root, &meta_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    if (!meta) {
        if (root_store) {
            root_store->writable = root_writable_before;
        }
        CEP_DEBUG_PRINTF_STDOUT("[schema ensure] meta ensure failed root=%p\n", (void*)resolved_root);
        return NULL;
    }

    meta = cep_cell_resolve(meta);
    if (!meta || !cep_cell_require_dictionary_store(&meta)) {
        if (root_store) {
            root_store->writable = root_writable_before;
        }
        CEP_DEBUG_PRINTF_STDOUT("[schema ensure] meta resolve/store failed meta=%p\n", (void*)meta);
        return NULL;
    }

    cepCell* schema = cep_cell_find_by_name(meta, dt_schema_name());
    if (schema) {
        cepCell* existing = cep_cell_resolve(schema);
        if (!existing || !cep_cell_require_dictionary_store(&existing)) {
            cep_cell_remove_hard(schema, NULL);
            schema = NULL;
        } else {
            schema = existing;
        }
    }
    if (!schema) {
        cepDT schema_name = *dt_schema_name();
        cepDT dict_type = *dt_dictionary_type();
        schema = cep_cell_add_dictionary(meta, &schema_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    if (!schema) {
        if (root_store) {
            root_store->writable = root_writable_before;
        }
        CEP_DEBUG_PRINTF_STDOUT("[schema ensure] schema create failed meta=%p\n", (void*)meta);
        return NULL;
    }

    cepCell* resolved_schema = cep_cell_resolve(schema);
    if (!resolved_schema || !cep_cell_require_dictionary_store(&resolved_schema)) {
        if (root_store) {
            root_store->writable = root_writable_before;
        }
        CEP_DEBUG_PRINTF_STDOUT("[schema ensure] schema resolve/store failed schema=%p\n", (void*)schema);
        return NULL;
    }

    if (resolved_schema->store) {
        cep_store_delete_children_hard(resolved_schema->store);
    }

    if (root_store) {
        root_store->writable = root_writable_before;
    }

    return resolved_schema;
}

static bool cep_l0_organ_schema_add_text(cepCell* schema, const cepDT* field, const char* text) {
    if (!schema || !field || !text) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(schema, field);
    if (existing) {
        cep_cell_remove_hard(existing, NULL);
    }

    cepDT type = cep_ops_make_dt("val/str");
    size_t len = strlen(text) + 1u;
    cepDT field_copy = *field;
    return cep_dict_add_value(schema, &field_copy, &type, (void*)text, len, len) != NULL;
}

static bool cep_l0_organ_bind_signal(cepCell* root, const cepDT* signal_dt) {
    if (!root || !signal_dt || !cep_dt_is_valid(signal_dt)) {
        return true;
    }

    int rc = cep_cell_bind_enzyme(root, signal_dt, true);
    if (rc == CEP_ENZYME_SUCCESS) {
        return true;
    }

    bool already_bound = false;
    const cepEnzymeBinding* binding = cep_cell_enzyme_bindings(root);
    for (const cepEnzymeBinding* node = binding; node; node = node->next) {
        if ((node->flags & CEP_ENZYME_BIND_TOMBSTONE) != 0u) {
            continue;
        }
        if (cep_dt_compare(&node->name, signal_dt) == 0) {
            already_bound = true;
            break;
        }
    }

    return already_bound;
}

static cepCell* cep_l0_ops_root(void) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return NULL;
    }
    cepCell* ops = cep_cell_find_by_name(rt_root, CEP_DTAW("CEP", "ops"));
    if (!ops) {
        return NULL;
    }
    return cep_cell_resolve(ops);
}

static bool cep_l0_ops_contains(cepOID oid) {
    if (!cep_oid_is_valid(oid)) {
        return false;
    }

    cepCell* ops_root = cep_l0_ops_root();
    if (!ops_root) {
        return false;
    }

    cepDT lookup = {
        .domain = oid.domain,
        .tag = oid.tag,
        .glob = 0u,
    };
    return cep_cell_find_by_name(ops_root, &lookup) != NULL;
}

static cepCell* cep_l0_organ_resolve_root_from_segments(const cepL0OrganDefinition* def) {
    if (!def) {
        return NULL;
    }

    cepCell* current = cep_root();
    if (!current) {
        return NULL;
    }

    for (size_t i = 0; i < def->segment_count; ++i) {
        cepDT lookup = cep_dt_clean(&def->path_segments[i]);
        cepCell* child = cep_cell_find_by_name(current, &lookup);
        if (!child) {
            return NULL;
        }
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            return NULL;
        }
        current = resolved;
    }
    return current;
}

static void cep_l0_validation_issue(cepL0OrganValidationRun* run, const char* fmt, ...) {
    if (!run || !fmt) {
        return;
    }

    run->issues += 1u;
    run->ok = false;

    if (!run->first_issue[0]) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(run->first_issue, sizeof(run->first_issue), fmt, args);
        va_end(args);
    }
}

static bool cep_l0_validation_prepare(const cepPath* target_path,
                                      const cepL0OrganDefinition* def,
                                      cepL0OrganValidationRun* run,
                                      cepCell** out_root) {
    if (!def || !run) {
        return false;
    }

    memset(run, 0, sizeof(*run));
    run->def = def;
    run->ok = true;

    cepCell* target_cell = NULL;
    if (target_path && target_path->length) {
        target_cell = cep_cell_find_by_path_past(cep_root(), target_path, 0);
    }

    if (!target_cell) {
        cep_l0_validation_issue(run, "target path unresolved");
        return false;
    }

    cepOrganRoot organ = {0};
    if (!cep_organ_root_for_cell(target_cell, &organ) || !organ.root || !organ.descriptor) {
        cep_l0_validation_issue(run, "organ metadata unavailable");
        return false;
    }

    if (strcmp(organ.descriptor->kind, def->kind) != 0) {
        cep_l0_validation_issue(run,
                                "kind mismatch expected=%s actual=%s",
                                def->kind,
                                organ.descriptor->kind ? organ.descriptor->kind : "<null>");
        return false;
    }

    cepCell* root = cep_cell_resolve(organ.root);
    if (!root) {
        cep_l0_validation_issue(run, "organ root unresolved");
        return false;
    }

    cepDT verb = cep_ops_make_dt("op/vl");
    cepDT mode = cep_ops_make_dt("opm:states");
    run->oid = cep_op_start(verb, def->path_text, mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(run->oid)) {
        cep_l0_validation_issue(run, "failed to start validator dossier");
        return false;
    }

    (void)cep_op_state_set(run->oid, cep_ops_make_dt("ist:scan"), 0, NULL);

    if (out_root) {
        *out_root = root;
    }
    return true;
}

static int cep_l0_validation_finish(cepL0OrganValidationRun* run) {
    if (!run) {
        return CEP_ENZYME_FATAL;
    }

    const bool success = (run->issues == 0u) && run->ok;
    const char* summary = (run->first_issue[0]) ? run->first_issue : NULL;
    size_t summary_len = summary ? (strlen(summary) + 1u) : 0u;

    if (cep_oid_is_valid(run->oid)) {
        cepDT state = cep_ops_make_dt(success ? "ist:ok" : "ist:fail");
        (void)cep_op_state_set(run->oid, state, 0, summary);

        cepDT status = cep_ops_make_dt(success ? "sts:ok" : "sts:fail");
        (void)cep_op_close(run->oid, status, summary, summary_len);
    }

    char stage[256];
    snprintf(stage,
             sizeof(stage),
             "organ=%s status=%s nodes=%zu values=%zu issues=%zu",
             run->def && run->def->kind ? run->def->kind : "<unknown>",
             success ? "ok" : "fail",
             run->checked_nodes,
             run->checked_values,
             run->issues);

    if (!success && run->first_issue[0]) {
        size_t used = strlen(stage);
        if (used + 2u < sizeof(stage)) {
            snprintf(stage + used, sizeof(stage) - used, " first=\"%s\"", run->first_issue);
        }
        CEP_DEBUG_PRINTF_STDOUT("[organ validation fatal] %s\n", stage);
    }
    cep_heartbeat_stage_note(stage);
    CEP_DEBUG_PRINTF_STDOUT("[organ validation] %s\n", stage);

    return success ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
}

static cepCell* cep_l0_check_schema_present(cepCell* root, cepL0OrganValidationRun* run, const char* label) {
    if (!root) {
        return NULL;
    }

    cepCell* meta = cep_cell_find_by_name(root, dt_meta_name());
    if (!meta) {
        cep_l0_validation_issue(run, "%s missing meta", label ? label : "organ");
        return NULL;
    }
    run->checked_nodes += 1u;

    cepCell* resolved_meta = cep_cell_resolve(meta);
    if (!resolved_meta) {
        cep_l0_validation_issue(run, "%s meta unresolved", label ? label : "organ");
        return NULL;
    }
    if (!cep_cell_require_dictionary_store(&resolved_meta)) {
        cep_l0_validation_issue(run, "%s meta not dictionary", label ? label : "organ");
        return NULL;
    }

    cepCell* schema = cep_cell_find_by_name(resolved_meta, dt_schema_name());
    if (!schema) {
        cep_l0_validation_issue(run, "%s schema absent", label ? label : "organ");
        return NULL;
    }
    run->checked_nodes += 1u;

    cepCell* resolved_schema = cep_cell_resolve(schema);
    if (!resolved_schema) {
        cep_l0_validation_issue(run, "%s schema unresolved", label ? label : "organ");
        return NULL;
    }
    if (!cep_cell_require_dictionary_store(&resolved_schema)) {
        cep_l0_validation_issue(run, "%s schema not dictionary", label ? label : "organ");
        return NULL;
    }

    return resolved_schema;
}

static bool cep_l0_check_schema_field_string(cepCell* schema, cepL0OrganValidationRun* run, const cepDT* field, const char* label) {
    if (!schema || !field) {
        return false;
    }

    cepCell* node = cep_cell_find_by_name(schema, field);
    if (!node) {
        cep_l0_validation_issue(run, "%s schema field missing", label ? label : "schema");
        return false;
    }
    run->checked_nodes += 1u;

    cepCell* resolved = cep_cell_resolve(node);
    if (!resolved) {
        cep_l0_validation_issue(run, "%s schema field unresolved", label ? label : "schema");
        return false;
    }
    if (!cep_cell_has_data(resolved)) {
        cep_l0_validation_issue(run, "%s schema field lacks payload", label ? label : "schema");
        return false;
    }

    const cepData* data = resolved->data;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        cep_l0_validation_issue(run, "%s schema field not VALUE", label ? label : "schema");
        return false;
    }
    run->checked_values += 1u;
    return true;
}

static bool cep_l0_check_sys_state(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    for (cepCell* child = cep_cell_first_all(root); child; child = cep_cell_next_all(root, child)) {
        run->checked_nodes += 1u;
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            cep_l0_validation_issue(run, "dangling state child pointer");
            ok = false;
            continue;
        }

        if (!cep_cell_has_data(resolved)) {
            cep_l0_validation_issue(run,
                                    "state entry domain=0x%llx tag=0x%llx lacks payload",
                                    (unsigned long long)resolved->metacell.dt.domain,
                                    (unsigned long long)resolved->metacell.dt.tag);
            ok = false;
            continue;
        }

        const cepData* data = resolved->data;
        if (data->datatype != CEP_DATATYPE_VALUE || data->size != sizeof(cepOID)) {
            cep_l0_validation_issue(run,
                                    "state entry domain=0x%llx tag=0x%llx has invalid payload type=%d size=%zu",
                                    (unsigned long long)resolved->metacell.dt.domain,
                                    (unsigned long long)resolved->metacell.dt.tag,
                                    data->datatype,
                                    data->size);
            ok = false;
            continue;
        }

        run->checked_values += 1u;

        cepOID oid = cep_oid_invalid();
        memcpy(&oid, data->value, sizeof oid);
        if (!cep_oid_is_valid(oid)) {
            cep_l0_validation_issue(run,
                                    "state entry domain=0x%llx tag=0x%llx stores invalid oid",
                                    (unsigned long long)resolved->metacell.dt.domain,
                                    (unsigned long long)resolved->metacell.dt.tag);
            ok = false;
            continue;
        }

        if (!cep_l0_ops_contains(oid)) {
            cep_l0_validation_issue(run,
                                    "state entry domain=0x%llx tag=0x%llx references missing op dossier",
                                    (unsigned long long)resolved->metacell.dt.domain,
                                    (unsigned long long)resolved->metacell.dt.tag);
            ok = false;
        }
    }
    return ok;
}

static bool cep_l0_check_sys_organs(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepDT spec_dt = *CEP_DTAW("CEP", "spec");
    cepDT store_field = *CEP_DTAW("CEP", "store");
    cepDT validator_field = *CEP_DTAW("CEP", "validator");
    cepDT kind_field = *CEP_DTAW("CEP", "kind");
    cepDT ctor_field = *CEP_DTAW("CEP", "ctor");
    cepDT dtor_field = *CEP_DTAW("CEP", "dtor");

    for (cepCell* entry = cep_cell_first_all(root); entry; entry = cep_cell_next_all(root, entry)) {
        run->checked_nodes += 1u;
        cepCell* kind_root = cep_cell_resolve(entry);
        if (!kind_root) {
            cep_l0_validation_issue(run, "organ spec entry unresolved");
            ok = false;
            continue;
        }

        if (!cep_cell_require_dictionary_store(&kind_root)) {
            cep_l0_validation_issue(run, "organ spec entry lacks dictionary store");
            ok = false;
            continue;
        }

        cepCell* spec_node = cep_cell_find_by_name(kind_root, &spec_dt);
        if (!spec_node) {
            cep_l0_validation_issue(run, "organ spec node missing 'spec' branch");
            ok = false;
            continue;
        }
        spec_node = cep_cell_resolve(spec_node);
        if (!spec_node) {
            cep_l0_validation_issue(run, "organ spec branch unresolved");
            ok = false;
            continue;
        }
        if (!cep_cell_is_immutable(spec_node)) {
            cep_l0_validation_issue(run, "organ spec branch not sealed immutable");
            ok = false;
        }

        const cepDT* store_dt_ptr = &kind_root->store->dt;
        const cepOrganDescriptor* descriptor = cep_organ_descriptor(store_dt_ptr);
        if (!descriptor) {
            cep_l0_validation_issue(run, "organ spec entry lacks registered descriptor");
            ok = false;
            continue;
        }

        cepDT expected_store = cep_organ_store_dt(descriptor->kind);
        if (cep_dt_compare(store_dt_ptr, &expected_store) != 0) {
            cep_l0_validation_issue(run, "organ spec entry store dt mismatch");
            ok = false;
        }

        cepCell* store_value = cep_cell_find_by_name(spec_node, &store_field);
        if (!store_value || !cep_cell_has_data(store_value) || store_value->data->size != sizeof(cepDT)) {
            cep_l0_validation_issue(run, "organ spec missing store field");
            ok = false;
        } else {
            cepDT stored_dt = {0};
            memcpy(&stored_dt, store_value->data->value, sizeof stored_dt);
            if (cep_dt_compare(&stored_dt, &expected_store) != 0) {
                cep_l0_validation_issue(run, "organ spec store field mismatch");
                ok = false;
            }
        }

        cepCell* validator_value = cep_cell_find_by_name(spec_node, &validator_field);
        if (!validator_value || !cep_cell_has_data(validator_value) || validator_value->data->size != sizeof(cepDT)) {
            cep_l0_validation_issue(run, "organ spec missing validator field");
            ok = false;
        } else {
            cepDT stored_validator = {0};
            memcpy(&stored_validator, validator_value->data->value, sizeof stored_validator);
            if (cep_dt_compare(&stored_validator, &descriptor->validator) != 0) {
                cep_l0_validation_issue(run, "organ spec validator mismatch");
                ok = false;
            }
        }

        cepCell* kind_value = cep_cell_find_by_name(spec_node, &kind_field);
        if (!kind_value || !cep_cell_has_data(kind_value)) {
            cep_l0_validation_issue(run, "organ spec missing kind label");
            ok = false;
        } else {
            const cepData* data = kind_value->data;
            if (data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
                cep_l0_validation_issue(run, "organ spec kind label malformed");
                ok = false;
            } else {
                const char* text = (const char*)data->value;
                if (!text || text[data->size - 1u] != '\0') {
                    cep_l0_validation_issue(run, "organ spec kind label not null terminated");
                    ok = false;
                } else if (strcmp(text, descriptor->kind) != 0) {
                    cep_l0_validation_issue(run, "organ spec kind label mismatch");
                    ok = false;
                }
            }
        }

        if (cep_dt_is_valid(&descriptor->constructor)) {
            cepCell* ctor_value = cep_cell_find_by_name(spec_node, &ctor_field);
            if (!ctor_value || !cep_cell_has_data(ctor_value) || ctor_value->data->size != sizeof(cepDT)) {
                cep_l0_validation_issue(run, "organ spec missing constructor field");
                ok = false;
            } else {
                cepDT stored_ctor = {0};
                memcpy(&stored_ctor, ctor_value->data->value, sizeof stored_ctor);
                if (cep_dt_compare(&stored_ctor, &descriptor->constructor) != 0) {
                    cep_l0_validation_issue(run, "organ spec constructor mismatch");
                    ok = false;
                }
            }
        }

        if (cep_dt_is_valid(&descriptor->destructor)) {
            cepCell* dtor_value = cep_cell_find_by_name(spec_node, &dtor_field);
            if (!dtor_value || !cep_cell_has_data(dtor_value) || dtor_value->data->size != sizeof(cepDT)) {
                cep_l0_validation_issue(run, "organ spec missing destructor field");
                ok = false;
            } else {
                cepDT stored_dtor = {0};
                memcpy(&stored_dtor, dtor_value->data->value, sizeof stored_dtor);
                if (cep_dt_compare(&stored_dtor, &descriptor->destructor) != 0) {
                    cep_l0_validation_issue(run, "organ spec destructor mismatch");
                    ok = false;
                }
            }
        }
    }
    return ok;
}

static bool cep_l0_check_rt_ops(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepDT envelope_dt = *CEP_DTAW("CEP", "envelope");
    cepDT history_dt = *CEP_DTAW("CEP", "history");
    cepDT watchers_dt = *CEP_DTAW("CEP", "watchers");
    cepDT state_dt = *CEP_DTAW("CEP", "state");
    cepDT close_dt = *CEP_DTAW("CEP", "close");

    for (cepCell* op = cep_cell_first_all(root); op; op = cep_cell_next_all(root, op)) {
        run->checked_nodes += 1u;
        cepCell* op_root = cep_cell_resolve(op);
        if (!op_root) {
            cep_l0_validation_issue(run, "op dossier unresolved");
            ok = false;
            continue;
        }

        cepCell* envelope = cep_cell_find_by_name(op_root, &envelope_dt);
        if (!envelope) {
            cep_l0_validation_issue(run, "op dossier missing envelope");
            ok = false;
        } else {
            envelope = cep_cell_resolve(envelope);
            if (!envelope || !cep_cell_is_immutable(envelope)) {
                cep_l0_validation_issue(run, "op dossier envelope not immutable");
                ok = false;
            }
        }

        cepCell* history = cep_cell_find_by_name(op_root, &history_dt);
        if (!history) {
            cep_l0_validation_issue(run, "op dossier missing history");
            ok = false;
        } else {
            history = cep_cell_resolve(history);
            if (!history || !history->store || history->store->indexing != CEP_INDEX_BY_INSERTION) {
                cep_l0_validation_issue(run, "op dossier history not a list");
                ok = false;
            } else {
                for (cepCell* h = cep_cell_first_all(history); h; h = cep_cell_next_all(history, h)) {
                    run->checked_values += 1u;
                }
            }
        }

        cepCell* watchers = cep_cell_find_by_name(op_root, &watchers_dt);
        if (!watchers) {
            cep_l0_validation_issue(run, "op dossier missing watchers");
            ok = false;
        } else {
            watchers = cep_cell_resolve(watchers);
            if (!watchers || !cep_cell_require_dictionary_store(&watchers)) {
                cep_l0_validation_issue(run, "op dossier watchers not dictionary");
                ok = false;
            } else {
                for (cepCell* watcher = cep_cell_first_all(watchers); watcher; watcher = cep_cell_next_all(watchers, watcher)) {
                    run->checked_values += 1u;
                }
            }
        }

        cepCell* state = cep_cell_find_by_name(op_root, &state_dt);
        if (!state || !cep_cell_has_data(state) || state->data->size != sizeof(cepDT)) {
            cep_l0_validation_issue(run, "op dossier missing state value");
            ok = false;
        }

        cepCell* close = cep_cell_find_by_name(op_root, &close_dt);
        if (close) {
            close = cep_cell_resolve(close);
            if (!close || !cep_cell_is_immutable(close)) {
                cep_l0_validation_issue(run, "op dossier close branch not immutable");
                ok = false;
            }
        }
    }

    return ok;
}
static bool cep_l0_check_rt_beat(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepCell* resolved_root = root;
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        cep_l0_validation_issue(run, "rt_beat root not dictionary");
        return false;
    }

    cepDT expected_dt = cep_organ_store_dt("rt_beat");
    if (resolved_root->store && cep_dt_is_valid(&expected_dt) && cep_dt_compare(&resolved_root->store->dt, &expected_dt) != 0) {
        cep_l0_validation_issue(run, "rt_beat unexpected store tag");
        ok = false;
    }

    cepCell* schema = cep_l0_check_schema_present(resolved_root, run, "rt_beat");
    if (!schema) {
        ok = false;
    } else {
        ok = cep_l0_check_schema_field_string(schema, run, dt_schema_summary(), "rt_beat summary") && ok;
        ok = cep_l0_check_schema_field_string(schema, run, dt_schema_layout(), "rt_beat layout") && ok;
    }

    for (cepCell* beat = cep_cell_first_all(resolved_root); beat; beat = cep_cell_next_all(resolved_root, beat)) {
        run->checked_nodes += 1u;
        const cepDT* child_name = cep_cell_get_name(beat);
        if (child_name && cep_dt_compare(child_name, dt_meta_name()) == 0) {
            continue;
        }

        cepCell* resolved = cep_cell_resolve(beat);
        if (!resolved) {
            cep_l0_validation_issue(run, "rt_beat child unresolved");
            ok = false;
            continue;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            cep_l0_validation_issue(run, "rt_beat child not dictionary");
            ok = false;
            continue;
        }

        cepCell* lists[] = {
            cep_cell_find_by_name(resolved, dt_inbox_name()),
            cep_cell_find_by_name(resolved, dt_agenda_name()),
            cep_cell_find_by_name(resolved, dt_stage_name()),
        };

        for (size_t idx = 0; idx < cep_lengthof(lists); ++idx) {
            cepCell* node = lists[idx];
            if (!node) {
                cep_l0_validation_issue(run, "rt_beat ledger list missing");
                ok = false;
                continue;
            }
            run->checked_nodes += 1u;
            cepCell* resolved_node = cep_cell_resolve(node);
            if (!resolved_node || !resolved_node->store || resolved_node->store->indexing != CEP_INDEX_BY_INSERTION) {
                cep_l0_validation_issue(run, "rt_beat ledger list invalid");
                ok = false;
                continue;
            }
            for (cepCell* entry = cep_cell_first_all(resolved_node); entry; entry = cep_cell_next_all(resolved_node, entry)) {
                run->checked_values += 1u;
            }
        }
    }

    return ok;
}

static bool cep_l0_check_children_are_lists(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepCell* schema = cep_l0_check_schema_present(root, run, "journal");
    if (!schema) {
        ok = false;
    } else {
        ok = cep_l0_check_schema_field_string(schema, run, dt_schema_summary(), "journal summary") && ok;
        ok = cep_l0_check_schema_field_string(schema, run, dt_schema_layout(), "journal layout") && ok;
    }
    for (cepCell* child = cep_cell_first_all(root); child; child = cep_cell_next_all(root, child)) {
        run->checked_nodes += 1u;
        const cepDT* child_name = cep_cell_get_name(child);
        if (child_name && cep_dt_compare(child_name, dt_meta_name()) == 0) {
            continue;
        }

        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            cep_l0_validation_issue(run, "journal child unresolved");
            ok = false;
            continue;
        }
        if (!resolved->store || resolved->store->indexing != CEP_INDEX_BY_INSERTION) {
            cep_l0_validation_issue(run, "journal child not a list");
            ok = false;
            continue;
        }
        for (cepCell* entry = cep_cell_first_all(resolved); entry; entry = cep_cell_next_all(resolved, entry)) {
            run->checked_values += 1u;
        }
    }
    return ok;
}

static bool cep_l0_check_env(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepCell* resolved_root = root;
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        cep_l0_validation_issue(run, "env organ root not dictionary");
        return false;
    }
    for (cepCell* child = cep_cell_first_all(resolved_root); child; child = cep_cell_next_all(resolved_root, child)) {
        run->checked_nodes += 1u;
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            cep_l0_validation_issue(run, "env child unresolved");
            ok = false;
            continue;
        }
        if (!cep_cell_has_store(resolved) && !cep_cell_has_data(resolved)) {
            cep_l0_validation_issue(run, "env child empty");
            ok = false;
        }
        if (cep_cell_has_data(resolved)) {
            run->checked_values += 1u;
        }
    }
    return ok;
}

static bool cep_l0_check_cas_like(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepCell* resolved_root = root;
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        cep_l0_validation_issue(run, "cas/lib organ root not dictionary");
        return false;
    }
    for (cepCell* bucket = cep_cell_first_all(resolved_root); bucket; bucket = cep_cell_next_all(resolved_root, bucket)) {
        run->checked_nodes += 1u;
        cepCell* resolved = cep_cell_resolve(bucket);
        if (!resolved) {
            cep_l0_validation_issue(run, "cas/lib bucket unresolved");
            ok = false;
            continue;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            cep_l0_validation_issue(run, "cas/lib bucket not dictionary");
            ok = false;
            continue;
        }
        for (cepCell* item = cep_cell_first_all(resolved); item; item = cep_cell_next_all(resolved, item)) {
            run->checked_values += 1u;
            cepCell* entry = cep_cell_resolve(item);
            if (entry && cep_cell_has_data(entry)) {
                const cepData* data = entry->data;
                if (data->datatype != CEP_DATATYPE_DATA) {
                    cep_l0_validation_issue(run, "cas/lib item payload not DATA");
                    ok = false;
                }
            }
        }
    }
    return ok;
}

static bool cep_l0_check_tmp(cepCell* root, cepL0OrganValidationRun* run) {
    if (!root || !root->store || root->store->indexing != CEP_INDEX_BY_INSERTION) {
        cep_l0_validation_issue(run, "tmp organ not backed by insertion-order list");
        return false;
    }
    for (cepCell* entry = cep_cell_first_all(root); entry; entry = cep_cell_next_all(root, entry)) {
        run->checked_nodes += 1u;
        cepCell* resolved = cep_cell_resolve(entry);
        if (!resolved) {
            cep_l0_validation_issue(run, "tmp entry unresolved");
            return false;
        }
        if (cep_cell_has_data(resolved)) {
            run->checked_values += 1u;
        }
    }
    return true;
}

static bool cep_l0_check_enzymes(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepCell* resolved_root = root;
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        cep_l0_validation_issue(run, "enzymes organ root not dictionary");
        return false;
    }
    for (cepCell* child = cep_cell_first_all(resolved_root); child; child = cep_cell_next_all(resolved_root, child)) {
        run->checked_nodes += 1u;
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            cep_l0_validation_issue(run, "enzyme manifest child unresolved");
            ok = false;
            continue;
        }
        if (!cep_cell_has_store(resolved) && !cep_cell_has_data(resolved)) {
            cep_l0_validation_issue(run, "enzyme manifest entry empty");
            ok = false;
        }
        if (cep_cell_has_data(resolved)) {
            run->checked_values += 1u;
        }
    }
    return ok;
}

static int cep_l0_organ_dt_rt_beat(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    if (!target_path) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* target = cep_cell_find_by_path_past(cep_root(), target_path, 0);
    cepCell* resolved = target ? cep_cell_resolve(target) : NULL;
    if (!resolved || !cep_cell_require_dictionary_store(&resolved) || !resolved->store) {
        cep_heartbeat_stage_note("organ.rt_beat.dt:root_unresolved");
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_organ_emit_op(target_path, "op/dt", "organ.rt_beat.dt")) {
        CEP_DEBUG_PRINTF_STDOUT("[organ dt] rt_beat emit failed err=%d\n", cep_ops_debug_last_error());
        return CEP_ENZYME_FATAL;
    }
    CEP_DEBUG_PRINTF_STDOUT("[organ dt] rt_beat success\n");
    cepDT expected_store = cep_organ_store_dt("rt_beat");
    if (resolved->store && cep_dt_is_valid(&expected_store)) {
        cep_store_set_dt(resolved->store, &expected_store);
    }
    if (!cep_organ_clear_root(resolved)) {
        cep_heartbeat_stage_note("organ.rt_beat.dt:clear_failed");
        return CEP_ENZYME_FATAL;
    }
    cepCell* schema = cep_l0_organ_schema_ensure(resolved);
    if (!schema) {
        cep_heartbeat_stage_note("organ.rt_beat.dt:schema_prepare_failed");
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l0_organ_schema_add_text(schema, dt_schema_summary(), CEP_L0_SCHEMA_RT_BEAT_SUMMARY)) {
        cep_heartbeat_stage_note("organ.rt_beat.dt:summary_failed");
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l0_organ_schema_add_text(schema, dt_schema_layout(), CEP_L0_SCHEMA_RT_BEAT_LAYOUT)) {
        cep_heartbeat_stage_note("organ.rt_beat.dt:layout_failed");
        return CEP_ENZYME_FATAL;
    }
    (void)cep_organ_request_constructor(resolved);
    cep_heartbeat_stage_note("organ.rt_beat.dt:success");
    return CEP_ENZYME_SUCCESS;
}

static int cep_l0_organ_ct_rt_beat(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    if (!target_path) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* target = cep_cell_find_by_path_past(cep_root(), target_path, 0);
    cepCell* resolved = target ? cep_cell_resolve(target) : NULL;
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        CEP_DEBUG_PRINTF_STDOUT("[organ ctor rt_beat] root unresolved target=%p resolved=%p\n",
                                (void*)target,
                                (void*)resolved);
        cep_heartbeat_stage_note("organ.rt_beat.ct:root_unresolved");
        return CEP_ENZYME_FATAL;
    }

    cepDT expected_dt = cep_organ_store_dt("rt_beat");
    if (resolved->store && cep_dt_is_valid(&expected_dt)) {
        cep_store_set_dt(resolved->store, &expected_dt);
    }

    cepCell* schema = cep_l0_organ_schema_ensure(resolved);
    if (!schema) {
        cep_heartbeat_stage_note("organ.rt_beat.ct:schema_prepare_failed");
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_organ_schema_add_text(schema, dt_schema_summary(), CEP_L0_SCHEMA_RT_BEAT_SUMMARY)) {
        cep_heartbeat_stage_note("organ.rt_beat.ct:summary_failed");
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l0_organ_schema_add_text(schema, dt_schema_layout(), CEP_L0_SCHEMA_RT_BEAT_LAYOUT)) {
        cep_heartbeat_stage_note("organ.rt_beat.ct:layout_failed");
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_organ_emit_op(target_path, "op/ct", "organ.rt_beat.ct")) {
        CEP_DEBUG_PRINTF_STDOUT("[organ ctor rt_beat] emit_op failed\n");
        return CEP_ENZYME_FATAL;
    }
    return CEP_ENZYME_SUCCESS;
}

static int cep_l0_organ_dt_journal(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    if (!target_path) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* target = cep_cell_find_by_path_past(cep_root(), target_path, 0);
    cepCell* resolved = target ? cep_cell_resolve(target) : NULL;
    if (!resolved || !cep_cell_require_dictionary_store(&resolved) || !resolved->store) {
        cep_heartbeat_stage_note("organ.journal.dt:root_unresolved");
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_organ_emit_op(target_path, "op/dt", "organ.journal.dt")) {
        CEP_DEBUG_PRINTF_STDOUT("[organ dt] journal emit failed err=%d\n", cep_ops_debug_last_error());
        return CEP_ENZYME_FATAL;
    }
    CEP_DEBUG_PRINTF_STDOUT("[organ dt] journal success\n");
    cepDT expected_store = cep_organ_store_dt("journal");
    if (resolved->store && cep_dt_is_valid(&expected_store)) {
        cep_store_set_dt(resolved->store, &expected_store);
    }
    if (!cep_organ_clear_root(resolved)) {
        cep_heartbeat_stage_note("organ.journal.dt:clear_failed");
        return CEP_ENZYME_FATAL;
    }
    cepCell* schema = cep_l0_organ_schema_ensure(resolved);
    if (!schema) {
        cep_heartbeat_stage_note("organ.journal.dt:schema_prepare_failed");
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l0_organ_schema_add_text(schema, dt_schema_summary(), CEP_L0_SCHEMA_JOURNAL_SUMMARY)) {
        cep_heartbeat_stage_note("organ.journal.dt:summary_failed");
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l0_organ_schema_add_text(schema, dt_schema_layout(), CEP_L0_SCHEMA_JOURNAL_LAYOUT)) {
        cep_heartbeat_stage_note("organ.journal.dt:layout_failed");
        return CEP_ENZYME_FATAL;
    }
    (void)cep_organ_request_constructor(resolved);
    cep_heartbeat_stage_note("organ.journal.dt:success");
    return CEP_ENZYME_SUCCESS;
}

static int cep_l0_organ_ct_journal(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    if (!target_path) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* target = cep_cell_find_by_path_past(cep_root(), target_path, 0);
    cepCell* resolved = target ? cep_cell_resolve(target) : NULL;
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        CEP_DEBUG_PRINTF_STDOUT("[organ ctor journal] root unresolved target=%p resolved=%p\n",
                                (void*)target,
                                (void*)resolved);
        cep_heartbeat_stage_note("organ.journal.ct:root_unresolved");
        return CEP_ENZYME_FATAL;
    }

    cepDT expected_dt = cep_organ_store_dt("journal");
    if (resolved->store && cep_dt_is_valid(&expected_dt)) {
        cep_store_set_dt(resolved->store, &expected_dt);
    }

    cepCell* schema = cep_l0_organ_schema_ensure(resolved);
    if (!schema) {
        cep_heartbeat_stage_note("organ.journal.ct:schema_prepare_failed");
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_organ_schema_add_text(schema, dt_schema_summary(), CEP_L0_SCHEMA_JOURNAL_SUMMARY)) {
        cep_heartbeat_stage_note("organ.journal.ct:summary_failed");
        return CEP_ENZYME_FATAL;
    }
    if (!cep_l0_organ_schema_add_text(schema, dt_schema_layout(), CEP_L0_SCHEMA_JOURNAL_LAYOUT)) {
        cep_heartbeat_stage_note("organ.journal.ct:layout_failed");
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_organ_emit_op(target_path, "op/ct", "organ.journal.ct")) {
        CEP_DEBUG_PRINTF_STDOUT("[organ ctor journal] emit_op failed\n");
        return CEP_ENZYME_FATAL;
    }
    return CEP_ENZYME_SUCCESS;
}

static int cep_l0_organ_vl_sys_state(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_SYS_STATE];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            (void)cep_l0_check_sys_state(root, &run);
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_sys_organs(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_SYS_ORGANS];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_sys_organs(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "organ registry root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_rt_ops(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_RT_OPS];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_rt_ops(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "ops root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_rt_beat(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_RT_BEAT];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_rt_beat(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "rt_beat root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_journal(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_JOURNAL];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_children_are_lists(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "journal root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_env(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_ENV];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_env(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "env root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_cas(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_CAS];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_cas_like(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "cas root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_lib(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_LIB];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_cas_like(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "lib root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_tmp(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_TMP];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_tmp(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "tmp root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_vl_enzymes(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_ENZYMES];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_enzymes(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "enzymes root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

/* Register validator descriptors for every Layer 0 organ so the heartbeat
 * dispatcher can route `op/vl` impulses through the Stage E adoption checks.
 * The helper populates the registry once per process, caching the generated
 * `org:<kind>:vl` identifiers to avoid repeated namepool work. */
bool cep_l0_organs_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    cep_l0_organs_initialise();

    for (size_t i = 0; i < CEP_L0_ORGAN_COUNT; ++i) {
        cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[i];

        if (!def->validator_ready) {
            def->validator_name = cep_l0_organs_make_signal_dt(def->kind, "vl");
            def->validator_ready = true;
        }

        cepPathConst1 validator_path = {
            .length = 1u,
            .capacity = 1u,
            .past = {
                { .dt = def->validator_name, .timestamp = 0u },
            },
        };

        cepEnzymeDescriptor validator_desc = {
            .name    = def->validator_name,
            .label   = def->label,
            .before  = NULL,
            .before_count = 0u,
            .after   = NULL,
            .after_count = 0u,
            .callback = def->callback,
            .flags    = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
            .match    = CEP_ENZYME_MATCH_EXACT,
        };

        if (cep_enzyme_register(registry, (const cepPath*)&validator_path, &validator_desc) != CEP_ENZYME_SUCCESS) {
            return false;
        }

        if (def->constructor_cb) {
            if (!def->constructor_ready) {
                def->constructor_name = cep_l0_organs_make_signal_dt(def->kind, "ct");
                def->constructor_ready = true;
            }
            cepPathConst1 ctor_path = {
                .length = 1u,
                .capacity = 1u,
                .past = {
                    { .dt = def->constructor_name, .timestamp = 0u },
                },
            };
            cepEnzymeDescriptor ctor_desc = {
                .name    = def->constructor_name,
                .label   = def->constructor_label ? def->constructor_label : def->label,
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = def->constructor_cb,
                .flags    = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
                .match    = CEP_ENZYME_MATCH_EXACT,
            };
            if (cep_enzyme_register(registry, (const cepPath*)&ctor_path, &ctor_desc) != CEP_ENZYME_SUCCESS) {
                return false;
            }
        }

        if (def->destructor_cb) {
            if (!def->destructor_ready) {
                def->destructor_name = cep_l0_organs_make_signal_dt(def->kind, "dt");
                def->destructor_ready = true;
            }
            cepPathConst1 dtor_path = {
                .length = 1u,
                .capacity = 1u,
                .past = {
                    { .dt = def->destructor_name, .timestamp = 0u },
                },
            };
            cepEnzymeDescriptor dtor_desc = {
                .name    = def->destructor_name,
                .label   = def->destructor_label ? def->destructor_label : def->label,
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = def->destructor_cb,
                .flags    = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
                .match    = CEP_ENZYME_MATCH_EXACT,
            };
            if (cep_enzyme_register(registry, (const cepPath*)&dtor_path, &dtor_desc) != CEP_ENZYME_SUCCESS) {
                return false;
            }
        }
    }

    return true;
}

/* Ensure each organ root carries a propagated binding to its validator enzyme,
 * letting organ-level impulses resolve deterministically without requiring
 * callers to attach bindings manually. Executed during bootstrap after the
 * runtime directories exist. */
bool cep_l0_organs_bind_roots(void) {
    cep_l0_organs_initialise();

    for (size_t i = 0; i < CEP_L0_ORGAN_COUNT; ++i) {
        cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[i];
        if (!def->validator_ready) {
            def->validator_name = cep_l0_organs_make_signal_dt(def->kind, "vl");
            def->validator_ready = true;
        }

        cepCell* root = cep_l0_organ_resolve_root_from_segments(def);
        if (!root) {
            return false;
        }

        if (!cep_l0_organ_bind_signal(root, &def->validator_name)) {
            return false;
        }

        if (def->constructor_cb) {
            if (!def->constructor_ready) {
                def->constructor_name = cep_l0_organs_make_signal_dt(def->kind, "ct");
                def->constructor_ready = true;
            }
            if (!cep_l0_organ_bind_signal(root, &def->constructor_name)) {
                return false;
            }
        }

        if (def->destructor_cb) {
            if (!def->destructor_ready) {
                def->destructor_name = cep_l0_organs_make_signal_dt(def->kind, "dt");
                def->destructor_ready = true;
            }
            if (!cep_l0_organ_bind_signal(root, &def->destructor_name)) {
                return false;
            }
        }
    }

    return true;
}
