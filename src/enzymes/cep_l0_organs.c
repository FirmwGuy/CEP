#include "cep_l0_organs.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_organ.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    CEP_L0_ORGAN_SYS_STATE = 0,
    CEP_L0_ORGAN_SYS_ORGANS,
    CEP_L0_ORGAN_SYS_NAMEPOOL,
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
    const char* ctor_label;
    const char* dtor_label;
    cepEnzyme   ctor_callback;
    cepEnzyme   dtor_callback;
    cepDT       path_segments[3];
    size_t      segment_count;
    cepDT       validator_name;
    cepDT       constructor_name;
    cepDT       destructor_name;
    bool        validator_ready;
    bool        constructor_ready;
    bool        destructor_ready;
} cepL0OrganDefinition;

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
static int cep_l0_organ_vl_sys_namepool(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_ct_sys_namepool(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_dt_sys_namepool(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_rt_ops(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_rt_beat(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_ct_rt_beat(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_dt_rt_beat(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_journal(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_ct_journal(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_dt_journal(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_env(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_cas(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_lib(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_tmp(const cepPath* signal_path, const cepPath* target_path);
static int cep_l0_organ_vl_enzymes(const cepPath* signal_path, const cepPath* target_path);
static void cep_l0_validation_issue(cepL0OrganValidationRun* run, const char* fmt, ...);

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
    [CEP_L0_ORGAN_SYS_NAMEPOOL] = {
        .kind          = "sys_namepool",
        .label         = "organ.sys_namepool.vl",
        .ctor_label    = "organ.sys_namepool.ct",
        .dtor_label    = "organ.sys_namepool.dt",
        .path_text     = "/sys/namepool",
        .callback      = cep_l0_organ_vl_sys_namepool,
        .ctor_callback = cep_l0_organ_ct_sys_namepool,
        .dtor_callback = cep_l0_organ_dt_sys_namepool,
    },
    [CEP_L0_ORGAN_RT_OPS] = {
        .kind       = "rt_ops",
        .label      = "organ.rt_ops.vl",
        .path_text  = "/rt/ops",
        .callback   = cep_l0_organ_vl_rt_ops,
    },
    [CEP_L0_ORGAN_RT_BEAT] = {
        .kind          = "rt_beat",
        .label         = "organ.rt_beat.vl",
        .ctor_label    = "organ.rt_beat.ct",
        .dtor_label    = "organ.rt_beat.dt",
        .path_text     = "/rt/beat",
        .callback      = cep_l0_organ_vl_rt_beat,
        .ctor_callback = cep_l0_organ_ct_rt_beat,
        .dtor_callback = cep_l0_organ_dt_rt_beat,
    },
    [CEP_L0_ORGAN_JOURNAL] = {
        .kind       = "journal",
        .label      = "organ.journal.vl",
        .ctor_label = "organ.journal.ct",
        .dtor_label = "organ.journal.dt",
        .path_text  = "/journal",
        .callback   = cep_l0_organ_vl_journal,
        .ctor_callback = cep_l0_organ_ct_journal,
        .dtor_callback = cep_l0_organ_dt_journal,
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

    cepL0OrganDefinition* sys_namepool = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_SYS_NAMEPOOL];
    sys_namepool->path_segments[0] = *CEP_DTAW("CEP", "sys");
    sys_namepool->path_segments[1] = *CEP_DTAW("CEP", "namepool");
    sys_namepool->segment_count = 2u;

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

static cepCell* cep_l0_organ_resolve_target_root(const cepPath* target_path, const char* expected_kind) {
    if (!target_path || !target_path->length) {
        return NULL;
    }

    cepCell* target = cep_cell_find_by_path_past(cep_root(), target_path, 0);
    if (!target) {
        return NULL;
    }

    cepCell* resolved = cep_cell_resolve(target);
    if (!resolved) {
        return NULL;
    }

    if (!expected_kind) {
        return resolved;
    }

    cepOrganRoot info = {0};
    if (!cep_organ_root_for_cell(resolved, &info) || !info.descriptor || !info.descriptor->kind) {
        return NULL;
    }

    if (strcmp(info.descriptor->kind, expected_kind) != 0) {
        return NULL;
    }

    return resolved;
}

static bool cep_l0_data_matches_string(const cepCell* cell, const char* expected) {
    if (!cell || !expected || !cep_cell_has_data(cell)) {
        return false;
    }

    const cepData* data = cell->data;
    size_t length = strlen(expected) + 1u;
    if (data->datatype != CEP_DATATYPE_VALUE || data->size != length) {
        return false;
    }

    return memcmp(data->value, expected, length) == 0;
}

static bool cep_l0_meta_validate_schema(cepCell* meta, const char* schema_label, cepL0OrganValidationRun* run) {
    if (!meta || !schema_label) {
        return true;
    }

    cepCell* resolved = cep_cell_resolve(meta);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        if (run) {
            cep_l0_validation_issue(run, "meta branch unresolved or not dictionary");
        }
        return false;
    }

    cepDT schema_name = *CEP_DTAW("CEP", "schema");
    cepCell* schema_cell = cep_cell_find_by_name(resolved, &schema_name);
    if (!schema_cell) {
        if (run) {
            cep_l0_validation_issue(run, "meta/schema missing");
        }
        return false;
    }

    schema_cell = cep_cell_resolve(schema_cell);
    if (!schema_cell) {
        if (run) {
            cep_l0_validation_issue(run, "meta/schema unresolved");
        }
        return false;
    }

    if (!cep_l0_data_matches_string(schema_cell, schema_label)) {
        if (run) {
            cep_l0_validation_issue(run, "meta/schema mismatch expected=%s", schema_label);
        }
        return false;
    }

    if (run) {
        run->checked_values += 1u;
    }
    return true;
}

static bool cep_l0_meta_set_schema(cepCell* root, const char* schema_label) {
    if (!root || !schema_label) {
        return false;
    }

    cepCell* resolved = root;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepDT meta_name = *CEP_DTAW("CEP", "meta");
    cepCell* meta = cep_cell_find_by_name(resolved, &meta_name);

    bool restore_root_writable = resolved->store ? resolved->store->writable : true;
    if (resolved->store && !resolved->store->writable) {
        resolved->store->writable = 1u;
    }

    if (!meta) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        meta = cep_cell_add_dictionary(resolved, &meta_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!meta) {
            if (resolved->store) {
                resolved->store->writable = restore_root_writable;
            }
            return false;
        }
    } else {
        meta = cep_cell_resolve(meta);
        if (!meta || !cep_cell_require_dictionary_store(&meta)) {
            if (resolved->store) {
                resolved->store->writable = restore_root_writable;
            }
            return false;
        }
    }

    if (resolved->store) {
        resolved->store->writable = restore_root_writable;
    }

    bool restore_meta_writable = meta->store ? meta->store->writable : true;
    if (meta->store && !meta->store->writable) {
        meta->store->writable = 1u;
    }

    cepDT schema_name = *CEP_DTAW("CEP", "schema");
    cepCell* schema_cell = cep_cell_find_by_name(meta, &schema_name);
    size_t length = strlen(schema_label) + 1u;
    cepDT string_type = cep_ops_make_dt("val/str");

    if (!schema_cell) {
        if (!cep_dict_add_value(meta, &schema_name, &string_type, (void*)schema_label, length, length)) {
            if (meta->store) {
                meta->store->writable = restore_meta_writable;
            }
            return false;
        }
    } else {
        schema_cell = cep_cell_resolve(schema_cell);
        if (!schema_cell || !cep_cell_has_data(schema_cell)) {
            if (meta->store) {
                meta->store->writable = restore_meta_writable;
            }
            return false;
        }
        if (!cep_cell_update(schema_cell, length, length, (void*)schema_label, false)) {
            if (meta->store) {
                meta->store->writable = restore_meta_writable;
            }
            return false;
        }
    }

    if (meta->store) {
        meta->store->writable = restore_meta_writable;
    }

    return true;
}

static bool cep_l0_meta_drop(cepCell* root) {
    if (!root) {
        return true;
    }

    cepCell* resolved = cep_cell_resolve(root);
    if (!resolved || !resolved->store) {
        return false;
    }

    cepDT meta_name = *CEP_DTAW("CEP", "meta");
    cepCell* meta = cep_cell_find_by_name(resolved, &meta_name);
    if (!meta) {
        return true;
    }

    meta = cep_cell_resolve(meta);
    if (!meta) {
        return false;
    }

    bool restore_root_writable = resolved->store ? resolved->store->writable : true;
    if (!resolved->store->writable) {
        resolved->store->writable = 1u;
    }

    cep_cell_finalize_hard(meta);
    cep_cell_remove_hard(meta, NULL);

    resolved->store->writable = restore_root_writable;
    return true;
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
    }
    cep_heartbeat_stage_note(stage);

    return success ? CEP_ENZYME_SUCCESS : CEP_ENZYME_FATAL;
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
static bool cep_l0_check_children_are_lists(cepCell* root, cepL0OrganValidationRun* run, const char* meta_schema) {
    bool ok = true;
    cepDT meta_name = *CEP_DTAW("CEP", "meta");
    bool meta_seen = false;
    for (cepCell* child = cep_cell_first_all(root); child; child = cep_cell_next_all(root, child)) {
        run->checked_nodes += 1u;
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            cep_l0_validation_issue(run, "journal child unresolved");
            ok = false;
            continue;
        }
        const cepDT* child_name = cep_cell_get_name(child);
        if (child_name && cep_dt_compare(child_name, &meta_name) == 0) {
            meta_seen = true;
            if (!cep_l0_meta_validate_schema(resolved, meta_schema, run)) {
                ok = false;
            }
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
    if (meta_schema && !meta_seen) {
        cep_l0_validation_issue(run, "meta/schema missing");
        ok = false;
    }
    return ok;
}

static bool cep_l0_check_namepool(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepCell* resolved_root = root;
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        cep_l0_validation_issue(run, "namepool root not dictionary");
        return false;
    }

    cepDT meta_name = *CEP_DTAW("CEP", "meta");
    bool meta_seen = false;

    for (cepCell* child = cep_cell_first_all(resolved_root); child; child = cep_cell_next_all(resolved_root, child)) {
        run->checked_nodes += 1u;
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            cep_l0_validation_issue(run, "namepool child unresolved");
            ok = false;
            continue;
        }

        const cepDT* name = cep_cell_get_name(child);
        if (name && cep_dt_compare(name, &meta_name) == 0) {
            meta_seen = true;
            if (!cep_l0_meta_validate_schema(resolved, "cep:sys-namepool:v1", run)) {
                ok = false;
            }
            continue;
        }

        if (!name || name->domain != CEP_ACRO("NP")) {
            cep_l0_validation_issue(run, "namepool child has unexpected domain");
            ok = false;
            continue;
        }

        if (!cep_cell_require_dictionary_store(&resolved)) {
            cep_l0_validation_issue(run, "namepool page not dictionary");
            ok = false;
            continue;
        }

        for (cepCell* slot = cep_cell_first_all(resolved); slot; slot = cep_cell_next_all(resolved, slot)) {
            run->checked_values += 1u;
            cepCell* entry = cep_cell_resolve(slot);
            if (!entry || !cep_cell_has_data(entry)) {
                cep_l0_validation_issue(run, "namepool slot missing data");
                ok = false;
                continue;
            }

            const cepData* data = entry->data;
            if (data->datatype != CEP_DATATYPE_DATA || data->size == 0u) {
                cep_l0_validation_issue(run, "namepool slot payload invalid");
                ok = false;
            }
        }
    }

    if (!meta_seen) {
        cep_l0_validation_issue(run, "namepool meta/schema missing");
        ok = false;
    }

    return ok;
}

static bool cep_l0_check_rt_beat(cepCell* root, cepL0OrganValidationRun* run) {
    bool ok = true;
    cepCell* resolved_root = root;
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        cep_l0_validation_issue(run, "rt/beat root not dictionary");
        return false;
    }

    cepDT meta_name = *CEP_DTAW("CEP", "meta");
    cepDT inbox_name = *CEP_DTAW("CEP", "inbox");
    cepDT agenda_name = *CEP_DTAW("CEP", "agenda");
    cepDT stage_name = *CEP_DTAW("CEP", "stage");
    bool meta_seen = false;

    for (cepCell* child = cep_cell_first_all(resolved_root); child; child = cep_cell_next_all(resolved_root, child)) {
        run->checked_nodes += 1u;
        cepCell* beat = cep_cell_resolve(child);
        if (!beat) {
            cep_l0_validation_issue(run, "rt/beat child unresolved");
            ok = false;
            continue;
        }

        const cepDT* name = cep_cell_get_name(child);
        if (name && cep_dt_compare(name, &meta_name) == 0) {
            meta_seen = true;
            if (!cep_l0_meta_validate_schema(beat, "cep:rt-beat:v1", run)) {
                ok = false;
            }
            continue;
        }

        if (!cep_cell_require_dictionary_store(&beat)) {
            cep_l0_validation_issue(run, "beat ledger node not dictionary");
            ok = false;
            continue;
        }

        cepCell* inbox = cep_cell_find_by_name(beat, &inbox_name);
        cepCell* agenda = cep_cell_find_by_name(beat, &agenda_name);
        cepCell* stage = cep_cell_find_by_name(beat, &stage_name);

        if (!inbox || !agenda || !stage) {
            cep_l0_validation_issue(run, "beat ledger missing inbox/agenda/stage");
            ok = false;
        }

        cepCell* lists[] = { inbox ? cep_cell_resolve(inbox) : NULL,
                             agenda ? cep_cell_resolve(agenda) : NULL,
                             stage ? cep_cell_resolve(stage) : NULL };
        for (size_t i = 0; i < 3; ++i) {
            cepCell* list = lists[i];
            if (!list || !list->store || list->store->indexing != CEP_INDEX_BY_INSERTION) {
                cep_l0_validation_issue(run, "beat ledger list invalid");
                ok = false;
                continue;
            }
            for (cepCell* entry = cep_cell_first_all(list); entry; entry = cep_cell_next_all(list, entry)) {
                run->checked_values += 1u;
            }
        }
    }

    if (!meta_seen) {
        cep_l0_validation_issue(run, "rt/beat meta/schema missing");
        ok = false;
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

static int cep_l0_organ_vl_sys_namepool(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = NULL;
    cepL0OrganValidationRun run;
    const cepL0OrganDefinition* def = &CEP_L0_ORGAN_DEFS[CEP_L0_ORGAN_SYS_NAMEPOOL];
    if (cep_l0_validation_prepare(target_path, def, &run, &root)) {
        if (root) {
            cepCell* resolved = cep_cell_resolve(root);
            if (resolved) {
                (void)cep_l0_check_namepool(resolved, &run);
            } else {
                cep_l0_validation_issue(&run, "namepool root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_ct_sys_namepool(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = cep_l0_organ_resolve_target_root(target_path, "sys_namepool");
    if (!root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_meta_set_schema(root, "cep:sys-namepool:v1")) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_l0_organ_dt_sys_namepool(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = cep_l0_organ_resolve_target_root(target_path, "sys_namepool");
    if (!root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_meta_drop(root)) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
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
                cep_l0_validation_issue(&run, "rt/beat root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_ct_rt_beat(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = cep_l0_organ_resolve_target_root(target_path, "rt_beat");
    if (!root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_meta_set_schema(root, "cep:rt-beat:v1")) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_l0_organ_dt_rt_beat(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = cep_l0_organ_resolve_target_root(target_path, "rt_beat");
    if (!root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_meta_drop(root)) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
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
                (void)cep_l0_check_children_are_lists(resolved, &run, "cep:stream-ledger:v1");
            } else {
                cep_l0_validation_issue(&run, "journal root unresolved");
            }
        }
    }
    return cep_l0_validation_finish(&run);
}

static int cep_l0_organ_ct_journal(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = cep_l0_organ_resolve_target_root(target_path, "journal");
    if (!root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_meta_set_schema(root, "cep:stream-ledger:v1")) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}

static int cep_l0_organ_dt_journal(const cepPath* signal_path, const cepPath* target_path) {
    (void)signal_path;
    cep_l0_organs_initialise();

    cepCell* root = cep_l0_organ_resolve_target_root(target_path, "journal");
    if (!root) {
        return CEP_ENZYME_FATAL;
    }

    if (!cep_l0_meta_drop(root)) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
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
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "org:%s:vl", def->kind);
            def->validator_name = cep_ops_make_dt(buffer);
            def->validator_ready = true;
        }

        cepPathConst1 query = {
            .length = 1u,
            .capacity = 1u,
            .past = {
                { .dt = def->validator_name, .timestamp = 0u },
            },
        };

        cepEnzymeDescriptor descriptor = {
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

        if (cep_enzyme_register(registry, (const cepPath*)&query, &descriptor) != CEP_ENZYME_SUCCESS) {
            return false;
        }

        if (def->ctor_callback) {
            if (!def->constructor_ready) {
                char buffer[32];
                snprintf(buffer, sizeof(buffer), "org:%s:ct", def->kind);
                def->constructor_name = cep_ops_make_dt(buffer);
                def->constructor_ready = true;
            }

            cepPathConst1 ctor_query = {
                .length = 1u,
                .capacity = 1u,
                .past = {
                    { .dt = def->constructor_name, .timestamp = 0u },
                },
            };

            cepEnzymeDescriptor ctor_descriptor = {
                .name    = def->constructor_name,
                .label   = def->ctor_label,
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = def->ctor_callback,
                .flags    = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
                .match    = CEP_ENZYME_MATCH_EXACT,
            };

            if (cep_enzyme_register(registry, (const cepPath*)&ctor_query, &ctor_descriptor) != CEP_ENZYME_SUCCESS) {
                return false;
            }
        }

        if (def->dtor_callback) {
            if (!def->destructor_ready) {
                char buffer[32];
                snprintf(buffer, sizeof(buffer), "org:%s:dt", def->kind);
                def->destructor_name = cep_ops_make_dt(buffer);
                def->destructor_ready = true;
            }

            cepPathConst1 dtor_query = {
                .length = 1u,
                .capacity = 1u,
                .past = {
                    { .dt = def->destructor_name, .timestamp = 0u },
                },
            };

            cepEnzymeDescriptor dtor_descriptor = {
                .name    = def->destructor_name,
                .label   = def->dtor_label,
                .before  = NULL,
                .before_count = 0u,
                .after   = NULL,
                .after_count = 0u,
                .callback = def->dtor_callback,
                .flags    = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
                .match    = CEP_ENZYME_MATCH_EXACT,
            };

            if (cep_enzyme_register(registry, (const cepPath*)&dtor_query, &dtor_descriptor) != CEP_ENZYME_SUCCESS) {
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
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "org:%s:vl", def->kind);
            def->validator_name = cep_ops_make_dt(buffer);
            def->validator_ready = true;
        }

        cepCell* root = cep_l0_organ_resolve_root_from_segments(def);
        if (!root) {
            return false;
        }

        int rc = cep_cell_bind_enzyme(root, &def->validator_name, true);
        if (rc != CEP_ENZYME_SUCCESS) {
            bool already_bound = false;
            const cepEnzymeBinding* binding = cep_cell_enzyme_bindings(root);
            for (const cepEnzymeBinding* node = binding; node; node = node->next) {
                if ((node->flags & CEP_ENZYME_BIND_TOMBSTONE) != 0u) {
                    continue;
                }
                if (cep_dt_compare(&node->name, &def->validator_name) == 0) {
                    already_bound = true;
                    break;
                }
            }
            if (!already_bound) {
                return false;
            }
        }

        if (def->ctor_callback) {
            if (!def->constructor_ready) {
                char buffer[32];
                snprintf(buffer, sizeof(buffer), "org:%s:ct", def->kind);
                def->constructor_name = cep_ops_make_dt(buffer);
                def->constructor_ready = true;
            }

            rc = cep_cell_bind_enzyme(root, &def->constructor_name, true);
            if (rc != CEP_ENZYME_SUCCESS) {
                bool already_bound = false;
                const cepEnzymeBinding* binding = cep_cell_enzyme_bindings(root);
                for (const cepEnzymeBinding* node = binding; node; node = node->next) {
                    if ((node->flags & CEP_ENZYME_BIND_TOMBSTONE) != 0u) {
                        continue;
                    }
                    if (cep_dt_compare(&node->name, &def->constructor_name) == 0) {
                        already_bound = true;
                        break;
                    }
                }
                if (!already_bound) {
                    return false;
                }
            }
        }

        if (def->dtor_callback) {
            if (!def->destructor_ready) {
                char buffer[32];
                snprintf(buffer, sizeof(buffer), "org:%s:dt", def->kind);
                def->destructor_name = cep_ops_make_dt(buffer);
                def->destructor_ready = true;
            }

            rc = cep_cell_bind_enzyme(root, &def->destructor_name, true);
            if (rc != CEP_ENZYME_SUCCESS) {
                bool already_bound = false;
                const cepEnzymeBinding* binding = cep_cell_enzyme_bindings(root);
                for (const cepEnzymeBinding* node = binding; node; node = node->next) {
                    if ((node->flags & CEP_ENZYME_BIND_TOMBSTONE) != 0u) {
                        continue;
                    }
                    if (cep_dt_compare(&node->name, &def->destructor_name) == 0) {
                        already_bound = true;
                        break;
                    }
                }
                if (!already_bound) {
                    return false;
                }
            }
        }
    }

    return true;
}
