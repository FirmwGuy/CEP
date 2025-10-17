#include "cep_ops.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cep_enzyme.h"
#include "cep_namepool.h"

CEP_DEFINE_STATIC_DT(dt_ops_root_name,      CEP_ACRO("CEP"), CEP_WORD("ops"));
CEP_DEFINE_STATIC_DT(dt_envelope_name,      CEP_ACRO("CEP"), CEP_WORD("envelope"));
CEP_DEFINE_STATIC_DT(dt_close_name,         CEP_ACRO("CEP"), CEP_WORD("close"));
CEP_DEFINE_STATIC_DT(dt_history_name,       CEP_ACRO("CEP"), CEP_WORD("history"));
CEP_DEFINE_STATIC_DT(dt_watchers_name,      CEP_ACRO("CEP"), CEP_WORD("watchers"));
CEP_DEFINE_STATIC_DT(dt_state_field,        CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_code_field,         CEP_ACRO("CEP"), CEP_WORD("code"));
CEP_DEFINE_STATIC_DT(dt_note_field,         CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_verb_field,         CEP_ACRO("CEP"), CEP_WORD("verb"));
CEP_DEFINE_STATIC_DT(dt_target_field,       CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_mode_field,         CEP_ACRO("CEP"), CEP_WORD("mode"));
CEP_DEFINE_STATIC_DT(dt_ttl_field,          CEP_ACRO("CEP"), CEP_WORD("ttl"));
CEP_DEFINE_STATIC_DT(dt_issued_field,       CEP_ACRO("CEP"), CEP_WORD("issued_beat"));
CEP_DEFINE_STATIC_DT(dt_beat_field,         CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_payload_field,      CEP_ACRO("CEP"), CEP_WORD("payload_id"));
CEP_DEFINE_STATIC_DT(dt_status_field_ops,   CEP_ACRO("CEP"), CEP_WORD("status"));
CEP_DEFINE_STATIC_DT(dt_closed_field,       CEP_ACRO("CEP"), CEP_WORD("closed_beat"));
CEP_DEFINE_STATIC_DT(dt_summary_field,      CEP_ACRO("CEP"), CEP_WORD("summary_id"));
CEP_DEFINE_STATIC_DT(dt_want_field,         CEP_ACRO("CEP"), CEP_WORD("want"));
CEP_DEFINE_STATIC_DT(dt_deadline_field,     CEP_ACRO("CEP"), CEP_WORD("deadline"));
CEP_DEFINE_STATIC_DT(dt_cont_field,         CEP_ACRO("CEP"), CEP_WORD("cont"));
CEP_DEFINE_STATIC_DT(dt_payload_watcher,    CEP_ACRO("CEP"), CEP_WORD("payload_id"));
CEP_DEFINE_STATIC_DT(dt_origin_field,       CEP_ACRO("CEP"), CEP_WORD("origin"));
CEP_DEFINE_STATIC_DT(dt_origin_enzyme,      CEP_ACRO("CEP"), CEP_WORD("enzyme"));
CEP_DEFINE_STATIC_DT(dt_ready_field,        CEP_ACRO("CEP"), CEP_WORD("armed"));

static int cep_ops_debug_last_error_code = 0;

int cep_ops_debug_last_error(void) {
    return cep_ops_debug_last_error_code;
}

cepDT cep_ops_make_dt(const char* tag) {
    cepDT dt = {0};
    dt.domain = cep_namepool_intern_cstr("CEP");
    dt.tag = tag ? cep_namepool_intern_cstr(tag) : 0u;
    return dt;
}

static cepDT cep_ops_clean_dt(const cepDT* dt) {
    return dt ? cep_dt_clean(dt) : (cepDT){0};
}

static cepDT cep_ops_auto_name(cepID domain) {
    cepDT name = {0};
    name.domain = domain;
    name.tag = CEP_AUTOID;
    return name;
}

static cepDT cep_ops_oid_to_dt(cepOID oid) {
    cepDT dt = {0};
    dt.domain = oid.domain;
    dt.tag = oid.tag;
    return dt;
}

static cepOID cep_ops_oid_from_cell(const cepCell* cell) {
    cepOID oid = cep_oid_invalid();
    if (!cell) {
        return oid;
    }
    cepDT dt = cep_dt_clean(&cell->metacell.dt);
    oid.domain = dt.domain;
    oid.tag = dt.tag;
    return oid;
}

static cepCell* cep_ops_root(bool create) {
    if (!cep_heartbeat_bootstrap()) {
        return NULL;
    }
    cepCell* rt = cep_heartbeat_rt_root();
    if (!rt) {
        return NULL;
    }
    cepDT name = cep_ops_clean_dt(dt_ops_root_name());
    if (create) {
        return cep_cell_ensure_dictionary_child(rt, &name, CEP_STORAGE_RED_BLACK_T);
    }
    return cep_cell_find_by_name(rt, &name);
}

static cepCell* cep_ops_find(cepOID oid) {
    if (!cep_oid_is_valid(oid)) {
        return NULL;
    }
    cepCell* ops_root = cep_ops_root(false);
    if (!ops_root) {
        return NULL;
    }
    cepDT lookup = cep_ops_oid_to_dt(oid);
    lookup.glob = 0u;
    return cep_cell_find_by_name(ops_root, &lookup);
}

static bool cep_ops_write_value(cepCell* parent,
                                const cepDT* field,
                                const char* type_tag,
                                const void* data,
                                size_t size) {
    if (!parent || !field || !type_tag || !data || !size) {
        return false;
    }
    cepDT lookup = cep_ops_clean_dt(field);
    cepCell* existing = cep_cell_find_by_name(parent, &lookup);
    if (existing) {
        return cep_cell_update(existing, size, size, (void*)data, false) != NULL;
    }
    cepDT name_copy = lookup;
    cepDT type_copy = cep_ops_make_dt(type_tag);
    return cep_dict_add_value(parent, &name_copy, &type_copy, (void*)data, size, size) != NULL;
}

static bool cep_ops_write_bool(cepCell* parent, const cepDT* field, bool value) {
    return cep_ops_write_value(parent, field, "val/bool", &value, sizeof value);
}

static bool cep_ops_write_u64(cepCell* parent, const cepDT* field, uint64_t value) {
    return cep_ops_write_value(parent, field, "val/u64", &value, sizeof value);
}

static bool cep_ops_write_i64(cepCell* parent, const cepDT* field, int64_t value) {
    return cep_ops_write_value(parent, field, "val/i64", &value, sizeof value);
}

static bool cep_ops_write_dt(cepCell* parent, const cepDT* field, const cepDT* value) {
    cepDT cleaned = cep_ops_clean_dt(value);
    return cep_ops_write_value(parent, field, "val/dt", &cleaned, sizeof cleaned);
}

static bool cep_ops_write_bytes(cepCell* parent, const cepDT* field, const void* payload, size_t len) {
    if (!payload || !len) {
        return true;
    }
    return cep_ops_write_value(parent, field, "val/bytes", payload, len);
}

static bool cep_ops_write_string(cepCell* parent, const cepDT* field, const char* text) {
    if (!text) {
        return true;
    }
    size_t len = strlen(text) + 1u;
    return cep_ops_write_value(parent, field, "val/str", text, len);
}

static bool cep_ops_read_value(const cepCell* parent, const cepDT* field, void* out, size_t size) {
    if (!parent || !field || !out || !size) {
        return false;
    }
    cepDT lookup = cep_ops_clean_dt(field);
    cepCell* child = cep_cell_find_by_name((cepCell*)parent, &lookup);
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    const void* payload = cep_cell_data(child);
    if (!payload) {
        return false;
    }
    memcpy(out, payload, size);
    return true;
}

static bool cep_ops_read_u64(const cepCell* parent, const cepDT* field, uint64_t* out) {
    return out && cep_ops_read_value(parent, field, out, sizeof *out);
}

static bool cep_ops_read_bool(const cepCell* parent, const cepDT* field, bool* out) {
    return out && cep_ops_read_value(parent, field, out, sizeof *out);
}

static bool cep_ops_read_dt(const cepCell* parent, const cepDT* field, cepDT* out) {
    return out && cep_ops_read_value(parent, field, out, sizeof *out);
}

static cepCell* cep_ops_history_root(cepCell* op) {
    if (!op) {
        return NULL;
    }
    cepDT name = cep_ops_clean_dt(dt_history_name());
    return cep_cell_find_by_name(op, &name);
}

static cepCell* cep_ops_watchers_root(cepCell* op) {
    if (!op) {
        return NULL;
    }
    cepDT name = cep_ops_clean_dt(dt_watchers_name());
    return cep_cell_find_by_name(op, &name);
}

static bool cep_ops_has_close(cepCell* op) {
    if (!op) {
        return false;
    }
    cepDT name = cep_ops_clean_dt(dt_close_name());
    return cep_cell_find_by_name(op, &name) != NULL;
}

static bool cep_ops_history_tail_matches(cepCell* history, const cepDT* state, uint64_t beat) {
    if (!history) {
        return false;
    }
    cepCell* last = cep_cell_last(history);
    if (!last) {
        return false;
    }
    cepDT recorded = {0};
    if (!cep_ops_read_dt(last, dt_state_field(), &recorded)) {
        return false;
    }
    if (cep_dt_compare(&recorded, state) != 0) {
        return false;
    }
    uint64_t tail_beat = 0u;
    if (!cep_ops_read_u64(last, dt_beat_field(), &tail_beat)) {
        return false;
    }
    return tail_beat == beat;
}

static bool cep_ops_append_history(cepCell* op,
                                   cepCell* history,
                                   const cepDT* state,
                                   int code,
                                   const char* note) {
    if (!op || !history || !state) {
        return false;
    }
    uint64_t beat = (uint64_t)cep_beat_index();
    if (cep_ops_history_tail_matches(history, state, beat)) {
        return true;
    }

    cepDT entry_name = cep_ops_auto_name(CEP_ACRO("OPH"));
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* entry = cep_cell_append_dictionary(history,
                                                &entry_name,
                                                &dict_type,
                                                CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        return false;
    }

    if (!cep_ops_write_u64(entry, dt_beat_field(), beat)) {
        return false;
    }
    if (!cep_ops_write_dt(entry, dt_state_field(), state)) {
        return false;
    }

    if (!cep_ops_write_i64(entry, dt_code_field(), (int64_t)code)) {
        return false;
    }

    if (note && !cep_ops_write_string(entry, dt_note_field(), note)) {
        return false;
    }

    return true;
}

static bool cep_ops_status_to_state(const cepDT* status, cepDT* out_state) {
    if (!status || !out_state) {
        return false;
    }
    if (cep_dt_compare(status, CEP_DTAW("CEP", "sts:ok")) == 0) {
        *out_state = cep_ops_clean_dt(CEP_DTAW("CEP", "ist:ok"));
        return true;
    }
    if (cep_dt_compare(status, CEP_DTAW("CEP", "sts:fail")) == 0) {
        *out_state = cep_ops_clean_dt(CEP_DTAW("CEP", "ist:fail"));
        return true;
    }
    if (cep_dt_compare(status, CEP_DTAW("CEP", "sts:cnl")) == 0) {
        *out_state = cep_ops_clean_dt(CEP_DTAW("CEP", "ist:cnl"));
        return true;
    }
    return false;
}

static bool cep_ops_is_status(const cepDT* dt) {
    if (!dt) {
        return false;
    }
    return cep_dt_compare(dt, CEP_DTAW("CEP", "sts:ok")) == 0 ||
           cep_dt_compare(dt, CEP_DTAW("CEP", "sts:fail")) == 0 ||
           cep_dt_compare(dt, CEP_DTAW("CEP", "sts:cnl")) == 0;
}

static cepPath* cep_ops_alloc_path(unsigned segments) {
    size_t bytes = sizeof(cepPath) + ((size_t)segments * sizeof(cepPast));
    cepPath* path = cep_malloc(bytes);
    if (!path) {
        return NULL;
    }
    path->length = segments;
    path->capacity = segments;
    return path;
}

static cepPath* cep_ops_make_signal_path(const cepDT* signal_dt) {
    cepPath* path = cep_ops_alloc_path(1u);
    if (!path) {
        return NULL;
    }
    path->past[0].dt = cep_ops_clean_dt(signal_dt);
    path->past[0].timestamp = 0u;
    return path;
}

static cepPath* cep_ops_make_target_path(cepOID oid) {
    cepPath* path = cep_ops_alloc_path(3u);
    if (!path) {
        return NULL;
    }

    path->past[0].dt = cep_ops_clean_dt(CEP_DTAW("CEP", "rt"));
    path->past[0].timestamp = 0u;

    path->past[1].dt = cep_ops_clean_dt(dt_ops_root_name());
    path->past[1].timestamp = 0u;

    path->past[2].dt = cep_ops_oid_to_dt(oid);
    path->past[2].timestamp = 0u;

    return path;
}

static bool cep_ops_enqueue_signal(cepOID oid, const cepDT* signal_dt) {
    cepPath* signal_path = cep_ops_make_signal_path(signal_dt);
    if (!signal_path) {
        return false;
    }
    cepPath* target_path = cep_ops_make_target_path(oid);
    if (!target_path) {
        cep_free(signal_path);
        return false;
    }

    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
    };

    int rc = cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &impulse);
    cep_free(signal_path);
    cep_free(target_path);
    return rc == CEP_ENZYME_SUCCESS;
}

static bool cep_ops_fire_watcher_entry(cepCell* entry, cepOID oid, bool timeout) {
    if (!entry || !cep_oid_is_valid(oid)) {
        return false;
    }

    cepDT signal = {0};
    if (!timeout) {
        if (!cep_ops_read_dt(entry, dt_cont_field(), &signal)) {
            return false;
        }
        return cep_ops_enqueue_signal(oid, &signal);
    }

    cepDT timeout_dt = cep_ops_make_dt("op/tmo");
    signal = cep_ops_clean_dt(&timeout_dt);
    return cep_ops_enqueue_signal(oid, &signal);
}

static bool cep_ops_notify_watchers(cepCell* op,
                                    cepOID oid,
                                    const cepDT* event_dt,
                                    bool for_status) {
    (void)oid;
    cepCell* watchers = cep_ops_watchers_root(op);
    if (!watchers) {
        return true;
    }

    bool ok = true;

    for (cepCell* entry = cep_cell_first_all(watchers); entry; ) {
        cepCell* next = cep_cell_next_all(watchers, entry);

        cepDT want = {0};
        if (!cep_ops_read_dt(entry, dt_want_field(), &want)) {
            entry = next;
            continue;
        }

        if (for_status != cep_ops_is_status(&want)) {
            entry = next;
            continue;
        }

        if (cep_dt_compare(&want, event_dt) != 0) {
            entry = next;
            continue;
        }

        bool armed = false;
        (void)cep_ops_read_bool(entry, dt_ready_field(), &armed);
        if (!armed && !cep_ops_write_bool(entry, dt_ready_field(), true)) {
            ok = false;
        }
        entry = next;
    }

    return ok;
}

static bool cep_ops_fire_ready_watchers(cepCell* op, cepOID oid) {
    cepCell* watchers = cep_ops_watchers_root(op);
    if (!watchers) {
        return true;
    }

    bool ok = true;

    for (cepCell* entry = cep_cell_first_all(watchers); entry; ) {
        cepCell* next = cep_cell_next_all(watchers, entry);

        bool armed = false;
        if (!cep_ops_read_bool(entry, dt_ready_field(), &armed) || !armed) {
            entry = next;
            continue;
        }

        if (!cep_ops_fire_watcher_entry(entry, oid, false)) {
            ok = false;
        }
        cep_cell_delete_hard(entry);
        entry = next;
    }

    return ok;
}

static bool cep_ops_expire_watchers(cepCell* op, cepOID oid, uint64_t beat) {
    cepCell* watchers = cep_ops_watchers_root(op);
    if (!watchers) {
        return true;
    }

    bool ok = true;

    for (cepCell* entry = cep_cell_first_all(watchers); entry; ) {
        cepCell* next = cep_cell_next_all(watchers, entry);

        bool armed = false;
        if (cep_ops_read_bool(entry, dt_ready_field(), &armed) && armed) {
            entry = next;
            continue;
        }

        uint64_t deadline = 0u;
        if (!cep_ops_read_u64(entry, dt_deadline_field(), &deadline) || !deadline) {
            entry = next;
            continue;
        }

        if (beat < deadline) {
            entry = next;
            continue;
        }

        if (!cep_ops_fire_watcher_entry(entry, oid, true)) {
            ok = false;
        }
        cep_cell_delete_hard(entry);
        entry = next;
    }

    return ok;
}

static bool cep_ops_install_watcher(cepCell* op,
                                    const cepDT* want,
                                    uint32_t ttl_beats,
                                    const cepDT* continuation,
                                    const void* payload,
                                    size_t payload_len,
                                    bool armed_initial) {
    if (!op || !want || !continuation) {
        cep_ops_debug_last_error_code = 52;
        return false;
    }

    cepCell* watchers = cep_ops_watchers_root(op);
    if (!watchers) {
        cep_ops_debug_last_error_code = 53;
        return false;
    }

    cepDT entry_name = cep_ops_auto_name(CEP_ACRO("OPW"));
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* entry = cep_cell_add_dictionary(watchers,
                                             &entry_name,
                                             0,
                                             &dict_type,
                                             CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        cep_ops_debug_last_error_code = 54;
        return false;
    }

    if (!cep_ops_write_dt(entry, dt_want_field(), want)) {
        cep_ops_debug_last_error_code = 55;
        goto fail;
    }
    if (!cep_ops_write_dt(entry, dt_cont_field(), continuation)) {
        cep_ops_debug_last_error_code = 56;
        goto fail;
    }
    if (!cep_ops_write_bool(entry, dt_ready_field(), armed_initial)) {
        cep_ops_debug_last_error_code = 57;
        goto fail;
    }
    if (!cep_ops_write_bytes(entry, dt_payload_watcher(), payload, payload_len)) {
        cep_ops_debug_last_error_code = 58;
        goto fail;
    }

    uint64_t deadline = ttl_beats ? (uint64_t)cep_beat_index() + ttl_beats : 0u;
    if (!cep_ops_write_u64(entry, dt_deadline_field(), deadline)) {
        cep_ops_debug_last_error_code = 59;
        goto fail;
    }

    const cepEnzymeDescriptor* origin = cep_enzyme_current();
    if (origin && origin->label) {
        cepDT origin_name = cep_ops_clean_dt(dt_origin_field());
        cepCell* origin_dict = cep_cell_add_dictionary(entry,
                                                       &origin_name,
                                                       0,
                                                       &dict_type,
                                                       CEP_STORAGE_RED_BLACK_T);
        if (origin_dict) {
            (void)cep_ops_write_string(origin_dict, dt_origin_enzyme(), origin->label);
        }
    }

    return true;

fail:
    cep_cell_delete_hard(entry);
    if (!cep_ops_debug_last_error_code) {
        cep_ops_debug_last_error_code = 60;
    }
    return false;
}

static bool cep_ops_populate_branch(cepCell* op_root,
                                    const cepDT* verb,
                                    const char* target,
                                    const cepDT* mode,
                                    const void* payload,
                                    size_t payload_len,
                                    uint32_t ttl_beats) {
    if (!op_root || !verb || !mode || !target) {
        return false;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");

    cepDT envelope_name = cep_ops_clean_dt(dt_envelope_name());
    cepCell* envelope = cep_cell_add_dictionary(op_root,
                                                &envelope_name,
                                                0,
                                                &dict_type,
                                                CEP_STORAGE_RED_BLACK_T);
    if (!envelope) {
        cep_ops_debug_last_error_code = 10;
        return false;
    }

    if (!cep_ops_write_dt(envelope, dt_verb_field(), verb)) {
        cep_ops_debug_last_error_code = 11;
        return false;
    }
    if (!cep_ops_write_string(envelope, dt_target_field(), target)) {
        cep_ops_debug_last_error_code = 12;
        return false;
    }
    if (!cep_ops_write_dt(envelope, dt_mode_field(), mode)) {
        cep_ops_debug_last_error_code = 13;
        return false;
    }
    if (!cep_ops_write_u64(envelope, dt_ttl_field(), ttl_beats)) {
        cep_ops_debug_last_error_code = 14;
        return false;
    }
    uint64_t issued = (uint64_t)cep_beat_index();
    if (!cep_ops_write_u64(envelope, dt_issued_field(), issued)) {
        cep_ops_debug_last_error_code = 15;
        return false;
    }
    if (!cep_ops_write_bytes(envelope, dt_payload_field(), payload, payload_len)) {
        cep_ops_debug_last_error_code = 16;
        return false;
    }

    cepSealOptions seal_opt = {.recursive = true};
    if (!cep_branch_seal_immutable(envelope, seal_opt)) {
        cep_ops_debug_last_error_code = 17;
        return false;
    }

    cepDT state_name = cep_ops_clean_dt(dt_state_field());
    cepDT state_val = cep_ops_clean_dt(CEP_DTAW("CEP", "ist:run"));
    if (!cep_ops_write_dt(op_root, &state_name, &state_val)) {
        cep_ops_debug_last_error_code = 18;
        return false;
    }

    cepDT code_name = cep_ops_clean_dt(dt_code_field());
    if (!cep_ops_write_i64(op_root, &code_name, 0)) {
        cep_ops_debug_last_error_code = 19;
        return false;
    }

    cepDT history_name = cep_ops_clean_dt(dt_history_name());
    cepDT list_type = *CEP_DTAW("CEP", "list");
    cepCell* history = cep_cell_add_list(op_root,
                                         &history_name,
                                         0,
                                         &list_type,
                                         CEP_STORAGE_LINKED_LIST);
    if (!history) {
        cep_ops_debug_last_error_code = 20;
        return false;
    }

    cepDT watchers_name = cep_ops_clean_dt(dt_watchers_name());
    cepCell* watchers = cep_cell_add_dictionary(op_root,
                                                &watchers_name,
                                                0,
                                                &dict_type,
                                                CEP_STORAGE_RED_BLACK_T);
    if (!watchers) {
        cep_ops_debug_last_error_code = 21;
        return false;
    }
    (void)watchers;

    if (!cep_ops_append_history(op_root,
                                history,
                                &state_val,
                                0,
                                NULL)) {
        cep_ops_debug_last_error_code = 22;
        return false;
    }

    return true;
}

cepOID cep_op_start(cepDT verb,
                    const char* target,
                    cepDT mode,
                    const void* payload,
                    size_t payload_len,
                    uint32_t ttl_beats) {
    cep_ops_debug_last_error_code = 0;
    cepOID oid = cep_oid_invalid();

    if (!cep_dt_is_valid(&verb) || !target || !cep_dt_is_valid(&mode)) {
        cep_ops_debug_last_error_code = 1;
        return oid;
    }

    cepCell* ops_root = cep_ops_root(true);
    if (!ops_root) {
        cep_ops_debug_last_error_code = 2;
        return oid;
    }

    cepTxn txn = {0};
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT op_name = cep_ops_auto_name(CEP_ACRO("OPS"));
    if (!cep_txn_begin(ops_root, &op_name, &dict_type, &txn)) {
        cep_ops_debug_last_error_code = 5;
        return oid;
    }

    if (!cep_ops_populate_branch(txn.root,
                                 &verb,
                                 target,
                                 &mode,
                                 payload,
                                 payload_len,
                                 ttl_beats)) {
        if (!cep_ops_debug_last_error_code) {
            cep_ops_debug_last_error_code = 3;
        }
        cep_txn_abort(&txn);
        return oid;
    }

    if (!cep_txn_mark_ready(&txn)) {
        cep_ops_debug_last_error_code = 23;
        cep_txn_abort(&txn);
        return oid;
    }

    cepOID committed_oid = cep_ops_oid_from_cell(txn.root);

    if (!cep_txn_commit(&txn)) {
        cep_ops_debug_last_error_code = 24;
        cep_txn_abort(&txn);
        return oid;
    }

    oid = committed_oid;
    return oid;
}

bool cep_op_state_set(cepOID oid, cepDT state, int code, const char* note) {
    if (!cep_oid_is_valid(oid) || !cep_dt_is_valid(&state)) {
        return false;
    }

    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 42;
        return false;
    }

    if (cep_ops_has_close(op)) {
        return false;
    }

    cepDT cleaned_state = cep_ops_clean_dt(&state);
    cepDT previous_state = {0};
    (void)cep_ops_read_dt(op, dt_state_field(), &previous_state);

    cepCell* history = cep_ops_history_root(op);
    if (!history) {
        cep_ops_debug_last_error_code = 41;
        return false;
    }

    uint64_t beat = (uint64_t)cep_beat_index();
    bool duplicate = (cep_dt_compare(&previous_state, &cleaned_state) == 0) &&
                     cep_ops_history_tail_matches(history, &cleaned_state, beat);

    if (!cep_ops_write_dt(op, dt_state_field(), &cleaned_state)) {
        return false;
    }

    if (!cep_ops_write_i64(op, dt_code_field(), (int64_t)code)) {
        return false;
    }

    if (note && !cep_ops_write_string(op, dt_note_field(), note)) {
        return false;
    }

    if (!duplicate) {
        if (!cep_ops_append_history(op, history, &cleaned_state, code, note)) {
            return false;
        }
        if (!cep_ops_notify_watchers(op, oid, &cleaned_state, false)) {
            return false;
        }
    }

    return true;
}

bool cep_op_await(cepOID oid,
                  cepDT want,
                  uint32_t ttl_beats,
                  cepDT continuation_signal,
                  const void* payload,
                  size_t payload_len) {
    cep_ops_debug_last_error_code = 0;
    if (!cep_oid_is_valid(oid) ||
        !cep_dt_is_valid(&want) ||
        !cep_dt_is_valid(&continuation_signal)) {
        return false;
    }

    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 51;
        return false;
    }

    cepDT clean_want = cep_ops_clean_dt(&want);
    bool satisfied = false;

    if (cep_ops_is_status(&clean_want)) {
        cepDT close_name = cep_ops_clean_dt(dt_close_name());
        cepCell* close_branch = cep_cell_find_by_name(op, &close_name);
        if (close_branch) {
            cepDT stored_status = {0};
            if (cep_ops_read_dt(close_branch, dt_status_field_ops(), &stored_status) &&
                cep_dt_compare(&stored_status, &clean_want) == 0) {
                satisfied = true;
            }
        }
    } else {
        cepDT current_state = {0};
        if (cep_ops_read_dt(op, dt_state_field(), &current_state) &&
            cep_dt_compare(&current_state, &clean_want) == 0) {
            satisfied = true;
        }
    }

    if (satisfied) {
        cepDT cont = cep_ops_clean_dt(&continuation_signal);
        return cep_ops_install_watcher(op, &clean_want, 0u, &cont, payload, payload_len, true);
    }

    cepDT cont = cep_ops_clean_dt(&continuation_signal);
    return cep_ops_install_watcher(op, &clean_want, ttl_beats, &cont, payload, payload_len, false);
}

bool cep_op_close(cepOID oid,
                  cepDT status,
                  const void* summary,
                  size_t summary_len) {
    cep_ops_debug_last_error_code = 0;
    if (!cep_oid_is_valid(oid) || !cep_dt_is_valid(&status)) {
        cep_ops_debug_last_error_code = 30;
        return false;
    }

    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 43;
        return false;
    }

    cepDT cleaned_status = cep_ops_clean_dt(&status);
    cepDT final_state = {0};
    if (!cep_ops_status_to_state(&cleaned_status, &final_state)) {
        cep_ops_debug_last_error_code = 31;
        return false;
    }

    cepDT close_name = cep_ops_clean_dt(dt_close_name());
    cepCell* existing = cep_cell_find_by_name(op, &close_name);
    if (existing) {
        cepDT stored_status = {0};
        if (cep_ops_read_dt(existing, dt_status_field_ops(), &stored_status) &&
            cep_dt_compare(&stored_status, &cleaned_status) == 0) {
            return true;
        }
        cep_ops_debug_last_error_code = 44;
        return false;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepTxn close_txn = {0};
    if (!cep_txn_begin(op, &close_name, &dict_type, &close_txn)) {
        cep_ops_debug_last_error_code = 45;
        return false;
    }

    cepCell* close_root = close_txn.root;

    if (!cep_ops_write_dt(close_root, dt_status_field_ops(), &cleaned_status)) {
        cep_ops_debug_last_error_code = 32;
        goto abort_close;
    }
    uint64_t beat = (uint64_t)cep_beat_index();
    if (!cep_ops_write_u64(close_root, dt_closed_field(), beat)) {
        cep_ops_debug_last_error_code = 33;
        goto abort_close;
    }
    if (!cep_ops_write_bytes(close_root, dt_summary_field(), summary, summary_len)) {
        cep_ops_debug_last_error_code = 34;
        goto abort_close;
    }

    if (!cep_txn_mark_ready(&close_txn)) {
        cep_ops_debug_last_error_code = 46;
        goto abort_close;
    }

    cepSealOptions seal_opt = {.recursive = true};
    if (!cep_branch_seal_immutable(close_root, seal_opt)) {
        cep_ops_debug_last_error_code = 35;
        goto abort_close;
    }

    if (!cep_txn_commit(&close_txn)) {
        cep_ops_debug_last_error_code = 47;
        goto abort_close;
    }

    if (!cep_ops_write_dt(op, dt_state_field(), &final_state)) {
        cep_ops_debug_last_error_code = 37;
        return false;
    }

    cepCell* history = cep_ops_history_root(op);
    if (!history) {
        return false;
    }
    if (!cep_ops_append_history(op, history, &final_state, 0, NULL)) {
        cep_ops_debug_last_error_code = 38;
        return false;
    }

    if (!cep_ops_notify_watchers(op, oid, &final_state, false)) {
        cep_ops_debug_last_error_code = 39;
        return false;
    }
    if (!cep_ops_notify_watchers(op, oid, &cleaned_status, true)) {
        cep_ops_debug_last_error_code = 40;
        return false;
    }

    return true;

abort_close:
    cep_txn_abort(&close_txn);
    return false;
}

bool cep_op_get(cepOID oid, char* buffer, size_t capacity) {
    cep_ops_debug_last_error_code = 0;
    if (!buffer || capacity == 0u || !cep_oid_is_valid(oid)) {
        return false;
    }

    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 61;
        return false;
    }

    cepDT state = {0};
    (void)cep_ops_read_dt(op, dt_state_field(), &state);

    bool closed = false;
    cepDT status = {0};
    cepDT close_name = cep_ops_clean_dt(dt_close_name());
    cepCell* close_branch = cep_cell_find_by_name(op, &close_name);
    if (close_branch) {
        closed = true;
        (void)cep_ops_read_dt(close_branch, dt_status_field_ops(), &status);
    }

    cepCell* watchers = cep_ops_watchers_root(op);
    size_t watcher_count = 0u;
    if (watchers && watchers->store) {
        watcher_count = watchers->store->chdCount;
    }

    int written = snprintf(buffer,
                           capacity,
                           "oid=0x%llx:0x%llx state=0x%llx:0x%llx closed=%d status=0x%llx:0x%llx watchers=%zu",
                           (unsigned long long)oid.domain,
                           (unsigned long long)oid.tag,
                           (unsigned long long)state.domain,
                           (unsigned long long)state.tag,
                           closed ? 1 : 0,
                           (unsigned long long)status.domain,
                           (unsigned long long)status.tag,
                           watcher_count);
    return written > 0 && (size_t)written < capacity;
}

bool cep_ops_stage_commit(void) {
    cepCell* ops_root = cep_ops_root(false);
    if (!ops_root) {
        return true;
    }

    uint64_t beat = (uint64_t)cep_beat_index();

    bool ok = true;
    for (cepCell* op = cep_cell_first_all(ops_root); op; op = cep_cell_next_all(ops_root, op)) {
        cepOID oid = cep_ops_oid_from_cell(op);
        if (!cep_ops_fire_ready_watchers(op, oid)) {
            ok = false;
        }
        if (!cep_ops_expire_watchers(op, oid, beat)) {
            ok = false;
        }
    }
    return ok;
}
