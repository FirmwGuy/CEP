/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_ops.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cep_enzyme.h"
#include "cep_cei.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_organ.h"

#define CEP_OPS_DEBUG(...) ((void)0)

CEP_DEFINE_STATIC_DT(dt_ops_root_name,      CEP_ACRO("CEP"), CEP_WORD("ops"));
CEP_DEFINE_STATIC_DT(dt_envelope_name,      CEP_ACRO("CEP"), CEP_WORD("envelope"));
CEP_DEFINE_STATIC_DT(dt_close_name,         CEP_ACRO("CEP"), CEP_WORD("close"));
CEP_DEFINE_STATIC_DT(dt_history_name,       CEP_ACRO("CEP"), CEP_WORD("history"));
CEP_DEFINE_STATIC_DT(dt_watchers_name,      CEP_ACRO("CEP"), CEP_WORD("watchers"));
CEP_DEFINE_STATIC_DT(dt_state_field,        CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_code_field,         CEP_ACRO("CEP"), CEP_WORD("code"));
CEP_DEFINE_STATIC_DT(dt_note_field,         CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_unix_ts_field,      CEP_ACRO("CEP"), CEP_WORD("unix_ts_ns"));
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
CEP_DEFINE_STATIC_DT(dt_history_next_field, CEP_ACRO("CEP"), CEP_WORD("hist_next"));
CEP_DEFINE_STATIC_DT(dt_want_field,         CEP_ACRO("CEP"), CEP_WORD("want"));
CEP_DEFINE_STATIC_DT(dt_deadline_field,     CEP_ACRO("CEP"), CEP_WORD("deadline"));
CEP_DEFINE_STATIC_DT(dt_cont_field,         CEP_ACRO("CEP"), CEP_WORD("cont"));
CEP_DEFINE_STATIC_DT(dt_payload_watcher,    CEP_ACRO("CEP"), CEP_WORD("payload_id"));
CEP_DEFINE_STATIC_DT(dt_origin_field,       CEP_ACRO("CEP"), CEP_WORD("origin"));
CEP_DEFINE_STATIC_DT(dt_origin_enzyme,      CEP_ACRO("CEP"), CEP_WORD("enzyme"));
CEP_DEFINE_STATIC_DT(dt_ready_field,        CEP_ACRO("CEP"), CEP_WORD("armed"));
CEP_DEFINE_STATIC_DT(dt_sev_warn,           CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_io_req_name,        CEP_ACRO("CEP"), CEP_WORD("io_req"));
CEP_DEFINE_STATIC_DT(dt_io_chan_name,       CEP_ACRO("CEP"), CEP_WORD("io_chan"));
CEP_DEFINE_STATIC_DT(dt_io_reactor_name,    CEP_ACRO("CEP"), CEP_WORD("io_reactor"));
CEP_DEFINE_STATIC_DT(dt_channel_field_ops,  CEP_ACRO("CEP"), CEP_WORD("channel"));
CEP_DEFINE_STATIC_DT(dt_opcode_field_ops,   CEP_ACRO("CEP"), CEP_WORD("opcode"));
CEP_DEFINE_STATIC_DT(dt_beats_budget_field, CEP_ACRO("CEP"), CEP_WORD("beat_budget"));
CEP_DEFINE_STATIC_DT(dt_deadline_bt_field,  CEP_ACRO("CEP"), CEP_WORD("deadline_bt"));
CEP_DEFINE_STATIC_DT(dt_deadline_ns_field,  CEP_ACRO("CEP"), CEP_WORD("deadline_ns"));
CEP_DEFINE_STATIC_DT(dt_bytes_expected,     CEP_ACRO("CEP"), CEP_WORD("bytes_exp"));
CEP_DEFINE_STATIC_DT(dt_bytes_done,         CEP_ACRO("CEP"), CEP_WORD("bytes_done"));
CEP_DEFINE_STATIC_DT(dt_errno_field,        CEP_ACRO("CEP"), CEP_WORD("errno_code"));
CEP_DEFINE_STATIC_DT(dt_telemetry_field,    CEP_ACRO("CEP"), CEP_WORD("telemetry"));
CEP_DEFINE_STATIC_DT(dt_target_path_field,  CEP_ACRO("CEP"), CEP_WORD("target_path"));
CEP_DEFINE_STATIC_DT(dt_provider_field,     CEP_ACRO("CEP"), CEP_WORD("provider"));
CEP_DEFINE_STATIC_DT(dt_reactor_field,      CEP_ACRO("CEP"), CEP_WORD("reactor"));
CEP_DEFINE_STATIC_DT(dt_caps_field,         CEP_ACRO("CEP"), CEP_WORD("caps"));
CEP_DEFINE_STATIC_DT(dt_shim_field,         CEP_ACRO("CEP"), CEP_WORD("shim"));
CEP_DEFINE_STATIC_DT(dt_draining_field,     CEP_ACRO("CEP"), CEP_WORD("draining"));
CEP_DEFINE_STATIC_DT(dt_paused_field_ops,   CEP_ACRO("CEP"), CEP_WORD("paused"));
CEP_DEFINE_STATIC_DT(dt_shutdn_field,       CEP_ACRO("CEP"), CEP_WORD("shutdn"));

static bool cep_ops_read_dt(const cepCell* parent, const cepDT* field, cepDT* out);

static void cep_ops_emit_watcher_timeout(cepCell* watcher_entry, cepOID oid) {
    if (!watcher_entry || !cep_oid_is_valid(oid)) {
        return;
    }

    cepDT want = {0};
    (void)cep_ops_read_dt(watcher_entry, dt_want_field(), &want);

    const char* want_text = NULL;
    if (want.tag) {
        want_text = cep_namepool_lookup(want.tag, NULL);
    }
    if (!want_text || !want_text[0]) {
        want_text = "(unknown)";
    }

    char note[192];
    snprintf(note,
             sizeof note,
             "watcher timeout on oid=%llu:%llu want=%s",
             (unsigned long long)oid.domain,
             (unsigned long long)oid.tag,
             want_text);

    cepCeiRequest req = {
        .severity = *dt_sev_warn(),
        .note = note,
        .topic = "ops/watchers",
        .topic_intern = true,
        .attach_to_op = true,
        .op = oid,
        .emit_signal = true,
        .ttl_forever = true,
    };

    (void)cep_cei_emit(&req);
}

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
        CEP_DEBUG_PRINTF_STDOUT("[ops root] bootstrap failed\n");
        return NULL;
    }
    cepCell* rt = cep_heartbeat_rt_root();
    if (!rt) {
        CEP_DEBUG_PRINTF_STDOUT("[ops root] rt_root missing\n");
        return NULL;
    }
    cepDT name = cep_ops_clean_dt(dt_ops_root_name());
    if (create) {
        cepCell* existing = cep_cell_find_by_name(rt, &name);
        cepDT organ_dt = cep_organ_store_dt("rt_ops");
        if (!existing) {
            cepCell* veiled = cep_cell_find_by_name_all(rt, &name);
            if (veiled) {
                existing = cep_cell_resolve(veiled);
                if (existing && cep_cell_is_normal(existing) && cep_cell_require_dictionary_store(&existing)) {
                    if (existing->store) {
                        if (existing->store->owner != existing) {
                            existing->store->owner = existing;
                        }
                        if (!existing->store->writable) {
                            existing->store->writable = 1u;
                        }
                        if (existing->store->lock) {
                            existing->store->lock = 0u;
                        }
                    }
                    if (existing->metacell.veiled) {
                        existing->metacell.veiled = 0u;
                    }
                    if (existing->deleted) {
                        existing->deleted = 0u;
                    }
                    if (existing->created == 0u) {
                        existing->created = cep_cell_timestamp_next();
                    }
                    cep_store_set_dt(existing->store, &organ_dt);
                    return existing;
                }
            }
            cepDT name_copy = name;
            cepCell* added = cep_cell_add_dictionary(rt, &name_copy, 0, &organ_dt, CEP_STORAGE_RED_BLACK_T);
            if (!added) {
                CEP_DEBUG_PRINTF_STDOUT("[ops root] add_dictionary failed\n");
            }
            return added;
        }
        cepCell* resolved = cep_cell_resolve(existing);
        if (!resolved) {
            CEP_DEBUG_PRINTF_STDOUT("[ops root] resolve existing failed\n");
            return NULL;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            CEP_DEBUG_PRINTF_STDOUT("[ops root] require store failed\n");
            return NULL;
        }
        if (resolved->store) {
            cep_store_set_dt(resolved->store, &organ_dt);
        }
        return resolved;
    }
    cepCell* root_existing = cep_cell_find_by_name(rt, &name);
    if (!root_existing) {
        cepCell* veiled = cep_cell_find_by_name_all(rt, &name);
        if (!veiled) {
            return NULL;
        }
        cepCell* revived = cep_cell_resolve(veiled);
        if (!revived || !cep_cell_is_normal(revived)) {
            return NULL;
        }
        if (!cep_cell_require_dictionary_store(&revived)) {
            return NULL;
        }
        if (revived->store) {
            if (revived->store->owner != revived) {
                revived->store->owner = revived;
            }
            if (!revived->store->writable) {
                revived->store->writable = 1u;
            }
            if (revived->store->lock) {
                revived->store->lock = 0u;
            }
        }
        if (revived->metacell.veiled) {
            revived->metacell.veiled = 0u;
        }
        if (revived->deleted) {
            revived->deleted = 0u;
        }
        if (revived->created == 0u) {
            revived->created = cep_cell_timestamp_next();
        }
        return revived;
    }
    return cep_cell_resolve(root_existing);
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
    cepCell* op = cep_cell_find_by_name(ops_root, &lookup);
    if (!op) {
        cepCell* veiled = cep_cell_find_by_name_all(ops_root, &lookup);
        if (!veiled) {
            return NULL;
        }
        cepCell* revived = cep_cell_resolve(veiled);
        if (!revived || !cep_cell_is_normal(revived)) {
            return NULL;
        }
        if (!cep_cell_require_dictionary_store(&revived)) {
            return NULL;
        }
        if (revived->store) {
            if (revived->store->owner != revived) {
                revived->store->owner = revived;
            }
            if (!revived->store->writable) {
                revived->store->writable = 1u;
            }
            if (revived->store->lock) {
                revived->store->lock = 0u;
            }
        }
        if (revived->metacell.veiled) {
            revived->metacell.veiled = 0u;
        }
        if (revived->deleted) {
            revived->deleted = 0u;
        }
        if (revived->created == 0u) {
            revived->created = cep_cell_timestamp_next();
        }
        return revived;
    }
    cepCell* resolved = cep_cell_resolve(op);
    if (!resolved || !cep_cell_is_normal(resolved)) {
        return NULL;
    }
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return NULL;
    }
    return resolved;
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
        if (cep_cell_update(existing, size, size, (void*)data, false) != NULL) {
            return true;
        }
        return false;
    }
    cepDT name_copy = lookup;
    cepDT type_copy = cep_ops_make_dt(type_tag);
    cepCell* inserted =
        cep_dict_add_value(parent, &name_copy, &type_copy, (void*)data, size, size);
    if (!inserted) {
    }
    return inserted != NULL;
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

static bool cep_ops_write_dt_if_valid(cepCell* parent,
                                      const cepDT* field,
                                      const cepDT* value) {
    if (!value || !cep_dt_is_valid(value)) {
        return true;
    }
    cepDT cleaned = cep_ops_clean_dt(value);
    return cep_ops_write_dt(parent, field, &cleaned);
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
    uint64_t persisted_next = 0u;
    bool has_persisted = cep_ops_read_u64(op, dt_history_next_field(), &persisted_next);
cepDT name = cep_ops_clean_dt(dt_history_name());
    cepCell* history = cep_cell_find_by_name(op, &name);
    if (!history) {
        history = cep_cell_find_by_name_all(op, &name);
    }
    if (!history) {
        return NULL;
    }

    cepCell* resolved = cep_cell_resolve(history);
    if (!resolved) {
        return NULL;
    }

    if (!cep_cell_require_store(&resolved, NULL)) {
        return NULL;
    }

    cepStore* store = resolved->store;
    if (!store) {
        return NULL;
    }

    if (store->owner != resolved) {
        store->owner = resolved;
    }
    if (!store->writable) {
        store->writable = 1u;
    }
    if (store->lock) {
        store->lock = 0u;
        store->lockOwner = NULL;
    }

    if (cep_cell_is_veiled(resolved)) {
        resolved->metacell.veiled = 0u;
    }
    if (cep_cell_is_immutable(resolved)) {
        resolved->metacell.immutable = 0u;
    }
    if (resolved->created == 0u) {
        resolved->created = cep_cell_timestamp_next();
    }
    if (resolved->deleted) {
        resolved->deleted = 0u;
    }

    if (store->created == 0u) {
        store->created = resolved->created ? resolved->created : cep_cell_timestamp_next();
    }
    if (store->deleted) {
        store->deleted = 0u;
    }

    uint64_t next_auto = store->autoid ? (uint64_t)store->autoid : 1u;
    if (next_auto == 0u) {
        next_auto = 1u;
    }

    for (cepCell* raw = cep_cell_first_all(resolved); raw; raw = cep_cell_next_all(resolved, raw)) {
        cepCell* child = cep_cell_resolve(raw);
        if (!child) {
            continue;
        }
        const cepDT* child_name = cep_cell_get_name(child);
        if (!child_name || !cep_id_is_numeric(child_name->tag)) {
            CEP_OPS_DEBUG(
                    "[ops_history_root] child_skip history=%p child=%p name=%016llx/%016llx\n",
                    (void*)resolved,
                    (void*)child,
                    child_name ? (unsigned long long)cep_id(child_name->domain) : 0ull,
                    child_name ? (unsigned long long)cep_id(child_name->tag) : 0ull);
            continue;
        }
        CEP_OPS_DEBUG(
                "[ops_history_root] child history=%p child=%p name=%016llx/%016llx\n",
                (void*)resolved,
                (void*)child,
                (unsigned long long)cep_id(child_name->domain),
                (unsigned long long)cep_id(child_name->tag));
        uint64_t payload = cep_id(child_name->tag);
        if (payload == 0u || payload >= CEP_AUTOID_MAX) {
            continue;
        }
        if (payload >= next_auto) {
            uint64_t candidate = payload + 1u;
            if (candidate > CEP_AUTOID_MAX) {
                candidate = CEP_AUTOID_MAX;
            }
            next_auto = candidate;
        }
    }

    if (has_persisted && persisted_next > next_auto) {
        next_auto = persisted_next;
    }

    if (next_auto > CEP_AUTOID_MAX) {
        next_auto = CEP_AUTOID_MAX;
    }
    if (next_auto > (uint64_t)store->autoid) {
        store->autoid = (cepID)next_auto;
    } else if (store->autoid == 0u) {
        store->autoid = 1u;
    }
    if (store->autoid > 0u) {
        cepDT next_field = cep_ops_clean_dt(dt_history_next_field());
        (void)cep_ops_write_u64(op, &next_field, (uint64_t)store->autoid);
    }

    return resolved;
}

static cepCell* cep_ops_watchers_root(cepCell* op) {
    if (!op) {
        return NULL;
    }
    cepDT name = cep_ops_clean_dt(dt_watchers_name());
    cepCell* watchers = cep_cell_find_by_name(op, &name);
    if (!watchers) {
        watchers = cep_cell_find_by_name_all(op, &name);
    }
    if (!watchers) {
        return NULL;
    }

    cepCell* resolved = cep_cell_resolve(watchers);
    if (!resolved) {
        return NULL;
    }

    if (!cep_cell_require_dictionary_store(&resolved)) {
        return NULL;
    }

    if (resolved->store) {
        if (resolved->store->owner != resolved) {
            resolved->store->owner = resolved;
        }
        if (!resolved->store->writable) {
            resolved->store->writable = 1u;
        }
        if (resolved->store->lock) {
            resolved->store->lock = 0u;
            resolved->store->lockOwner = NULL;
        }
        if (resolved->store->created == 0u) {
            resolved->store->created = resolved->created ? resolved->created : cep_cell_timestamp_next();
        }
        if (resolved->store->deleted) {
            resolved->store->deleted = 0u;
        }
    }

    if (cep_cell_is_veiled(resolved)) {
        resolved->metacell.veiled = 0u;
    }
    if (resolved->created == 0u) {
        resolved->created = cep_cell_timestamp_next();
    }
    if (resolved->deleted) {
        resolved->deleted = 0u;
    }

    return resolved;
}

static cepCell* cep_ops_async_branch(cepCell* op, const cepDT* branch_name) {
    if (!op || !branch_name) {
        return NULL;
    }
    return cep_cell_ensure_dictionary_child(op, branch_name, CEP_STORAGE_RED_BLACK_T);
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
    if (history && history->store) {
        CEP_OPS_DEBUG(
                "[ops_append_history] history=%p store=%p writable=%u lock=%u owner=%p owner_lock=%u\n",
                (void*)history,
                (void*)history->store,
                history->store->writable ? 1u : 0u,
                history->store->lock ? 1u : 0u,
                (void*)history->store->owner,
                (history->store->owner && history->store->owner->store)
                    ? (history->store->owner->store->lock ? 1u : 0u)
                    : 0u);
    }
    cepCell* entry = cep_cell_append_dictionary(history,
                                                &entry_name,
                                                &dict_type,
                                                CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        CEP_OPS_DEBUG("[ops_append_history] append_dictionary failed history=%p\n", (void*)history);
        return false;
    }
    if (!cep_cell_require_dictionary_store(&entry)) {
        CEP_OPS_DEBUG("[ops_append_history] require_dictionary_store failed entry=%p\n", (void*)entry);
        return false;
    }
    if (!cep_ops_write_u64(entry, dt_beat_field(), beat)) {
        CEP_OPS_DEBUG("[ops_append_history] write beat failed entry=%p\n", (void*)entry);
        return false;
    }
    uint64_t unix_ts = 0u;
    if (cep_heartbeat_beat_to_unix((cepBeatNumber)beat, &unix_ts)) {
        if (!cep_ops_write_u64(entry, dt_unix_ts_field(), unix_ts)) {
            CEP_OPS_DEBUG("[ops_append_history] write unix failed entry=%p\n", (void*)entry);
            return false;
        }
    }
    if (!cep_ops_write_dt(entry, dt_state_field(), state)) {
        CEP_OPS_DEBUG("[ops_append_history] write state failed entry=%p\n", (void*)entry);
        return false;
    }

    if (!cep_ops_write_i64(entry, dt_code_field(), (int64_t)code)) {
        CEP_OPS_DEBUG("[ops_append_history] write code failed entry=%p\n", (void*)entry);
        return false;
    }

    if (note && !cep_ops_write_string(entry, dt_note_field(), note)) {
        CEP_OPS_DEBUG("[ops_append_history] write note failed entry=%p\n", (void*)entry);
        return false;
    }

    if (history && history->store && history->store->autoid > 0u) {
        uint64_t next_auto = (uint64_t)history->store->autoid;
        cepDT next_field = cep_ops_clean_dt(dt_history_next_field());
        (void)cep_ops_write_u64(op, &next_field, next_auto);
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
        *out_state = cep_ops_clean_dt(CEP_DTAW("CEP", "ist:cxl"));
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
        .qos = (CEP_IMPULSE_QOS_CONTROL | CEP_IMPULSE_QOS_RETAIN_ON_PAUSE),
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
        signal = cep_ops_clean_dt(&signal);
    } else {
        cepDT timeout_dt = cep_ops_make_dt("op/tmo");
        signal = cep_ops_clean_dt(&timeout_dt);
    }

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

        cep_ops_emit_watcher_timeout(entry, oid);
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
    CEP_OPS_DEBUG(
            "[ops_populate_branch] history=%p store=%p owner=%p\n",
            (void*)history,
            history ? (void*)history->store : NULL,
            (history && history->store) ? (void*)history->store->owner : NULL);
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
        CEP_DEBUG_PRINTF("[op_state_set] invalid inputs\n");
        return false;
    }

    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 42;
        CEP_DEBUG_PRINTF("[op_state_set] op not found oid=%llu:%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return false;
    }

    if (cep_ops_has_close(op)) {
        CEP_DEBUG_PRINTF("[op_state_set] op already closed oid=%llu:%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return false;
    }

    cepDT cleaned_state = cep_ops_clean_dt(&state);
    cepDT previous_state = {0};
    (void)cep_ops_read_dt(op, dt_state_field(), &previous_state);

    cepCell* history = cep_ops_history_root(op);
    if (!history) {
        cep_ops_debug_last_error_code = 41;
        CEP_DEBUG_PRINTF("[op_state_set] history root missing oid=%llu:%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return false;
    }

    uint64_t beat = (uint64_t)cep_beat_index();
    bool duplicate = (cep_dt_compare(&previous_state, &cleaned_state) == 0) &&
                     cep_ops_history_tail_matches(history, &cleaned_state, beat);

    if (!cep_ops_write_dt(op, dt_state_field(), &cleaned_state)) {
        CEP_DEBUG_PRINTF("[op_state_set] write state failed oid=%llu:%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return false;
    }

    if (!cep_ops_write_i64(op, dt_code_field(), (int64_t)code)) {
        CEP_DEBUG_PRINTF("[op_state_set] write code failed oid=%llu:%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return false;
    }

    if (note && !cep_ops_write_string(op, dt_note_field(), note)) {
        CEP_DEBUG_PRINTF("[op_state_set] write note failed oid=%llu:%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return false;
    }

    if (!duplicate) {
        if (!cep_ops_append_history(op, history, &cleaned_state, code, note)) {
            CEP_DEBUG_PRINTF("[op_state_set] append history failed oid=%llu:%llu\n",
                             (unsigned long long)oid.domain,
                             (unsigned long long)oid.tag);
            return false;
        }
        if (!cep_ops_notify_watchers(op, oid, &cleaned_state, false)) {
            CEP_DEBUG_PRINTF("[op_state_set] notify watchers failed oid=%llu:%llu\n",
                             (unsigned long long)oid.domain,
                             (unsigned long long)oid.tag);
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
        cep_ops_debug_last_error_code = 62;
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

bool cep_op_async_record_request(cepOID oid,
                                 const cepDT* request_name,
                                 const cepOpsAsyncIoReqInfo* info) {
    cep_ops_debug_last_error_code = 0;
    if (!info || !request_name || !cep_oid_is_valid(oid)) {
        cep_ops_debug_last_error_code = 200;
        return false;
    }
    if (!cep_dt_is_valid(request_name) || !cep_dt_is_valid(&info->state)) {
        cep_ops_debug_last_error_code = 201;
        return false;
    }
    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 202;
        return false;
    }
    cepCell* req_root = cep_ops_async_branch(op, dt_io_req_name());
    if (!req_root) {
        cep_ops_debug_last_error_code = 203;
        return false;
    }
    cepDT clean_name = cep_ops_clean_dt(request_name);
    cepCell* req_entry = cep_cell_ensure_dictionary_child(req_root,
                                                         &clean_name,
                                                         CEP_STORAGE_RED_BLACK_T);
    if (!req_entry) {
        cep_ops_debug_last_error_code = 204;
        return false;
    }
    cepDT clean_state = cep_ops_clean_dt(&info->state);
    if (!cep_ops_write_dt(req_entry, dt_state_field(), &clean_state)) {
        cep_ops_debug_last_error_code = 205;
        return false;
    }
    if (!cep_ops_write_dt_if_valid(req_entry, dt_channel_field_ops(), &info->channel)) {
        cep_ops_debug_last_error_code = 206;
        return false;
    }
    if (!cep_ops_write_dt_if_valid(req_entry, dt_opcode_field_ops(), &info->opcode)) {
        cep_ops_debug_last_error_code = 207;
        return false;
    }
    if (info->has_beats_budget &&
        !cep_ops_write_u64(req_entry, dt_beats_budget_field(), (uint64_t)info->beats_budget)) {
        cep_ops_debug_last_error_code = 208;
        return false;
    }
    if (info->has_deadline_beat &&
        !cep_ops_write_u64(req_entry, dt_deadline_bt_field(), info->deadline_beat)) {
        cep_ops_debug_last_error_code = 209;
        return false;
    }
    if (info->has_deadline_unix_ns &&
        !cep_ops_write_u64(req_entry, dt_deadline_ns_field(), info->deadline_unix_ns)) {
        cep_ops_debug_last_error_code = 210;
        return false;
    }
    if (info->has_bytes_expected &&
        !cep_ops_write_u64(req_entry, dt_bytes_expected(), info->bytes_expected)) {
        cep_ops_debug_last_error_code = 211;
        return false;
    }
    if (info->has_bytes_done &&
        !cep_ops_write_u64(req_entry, dt_bytes_done(), info->bytes_done)) {
        cep_ops_debug_last_error_code = 212;
        return false;
    }
    if (info->has_errno &&
        !cep_ops_write_i64(req_entry, dt_errno_field(), (int64_t)info->errno_code)) {
        cep_ops_debug_last_error_code = 213;
        return false;
    }
    if (info->has_telemetry &&
        !cep_ops_write_dt_if_valid(req_entry, dt_telemetry_field(), &info->telemetry)) {
        cep_ops_debug_last_error_code = 214;
        return false;
    }
    return true;
}

bool cep_op_async_record_channel(cepOID oid,
                                 const cepDT* channel_name,
                                 const cepOpsAsyncChannelInfo* info) {
    cep_ops_debug_last_error_code = 0;
    if (!info || !channel_name || !cep_oid_is_valid(oid)) {
        cep_ops_debug_last_error_code = 220;
        return false;
    }
    if (!cep_dt_is_valid(channel_name)) {
        cep_ops_debug_last_error_code = 221;
        return false;
    }
    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 222;
        return false;
    }
    cepCell* chan_root = cep_ops_async_branch(op, dt_io_chan_name());
    if (!chan_root) {
        cep_ops_debug_last_error_code = 223;
        return false;
    }
    cepDT clean_name = cep_ops_clean_dt(channel_name);
    cepCell* chan_entry = cep_cell_ensure_dictionary_child(chan_root,
                                                          &clean_name,
                                                          CEP_STORAGE_RED_BLACK_T);
    if (!chan_entry) {
        cep_ops_debug_last_error_code = 224;
        return false;
    }
    if (info->has_target_path &&
        !cep_ops_write_string(chan_entry, dt_target_path_field(), info->target_path)) {
        cep_ops_debug_last_error_code = 225;
        return false;
    }
    if (info->has_provider &&
        !cep_ops_write_dt_if_valid(chan_entry, dt_provider_field(), &info->provider)) {
        cep_ops_debug_last_error_code = 226;
        return false;
    }
    if (info->has_reactor &&
        !cep_ops_write_dt_if_valid(chan_entry, dt_reactor_field(), &info->reactor)) {
        cep_ops_debug_last_error_code = 227;
        return false;
    }
    if (info->has_caps &&
        !cep_ops_write_dt_if_valid(chan_entry, dt_caps_field(), &info->caps)) {
        cep_ops_debug_last_error_code = 228;
        return false;
    }
    if (info->shim_known &&
        !cep_ops_write_bool(chan_entry, dt_shim_field(), info->shim)) {
        cep_ops_debug_last_error_code = 229;
        return false;
    }
    if (!cep_cell_ensure_dictionary_child(chan_entry,
                                          dt_watchers_name(),
                                          CEP_STORAGE_RED_BLACK_T)) {
        cep_ops_debug_last_error_code = 230;
        return false;
    }
    return true;
}

bool cep_op_async_set_reactor_state(cepOID oid,
                                    const cepOpsAsyncReactorState* state) {
    cep_ops_debug_last_error_code = 0;
    if (!state || !cep_oid_is_valid(oid)) {
        cep_ops_debug_last_error_code = 240;
        return false;
    }
    cepCell* op = cep_ops_find(oid);
    if (!op) {
        cep_ops_debug_last_error_code = 241;
        return false;
    }
    cepCell* reactor_root = cep_ops_async_branch(op, dt_io_reactor_name());
    if (!reactor_root) {
        cep_ops_debug_last_error_code = 242;
        return false;
    }
    if (state->draining_known &&
        !cep_ops_write_bool(reactor_root, dt_draining_field(), state->draining)) {
        cep_ops_debug_last_error_code = 243;
        return false;
    }
    if (state->paused_known &&
        !cep_ops_write_bool(reactor_root, dt_paused_field_ops(), state->paused)) {
        cep_ops_debug_last_error_code = 244;
        return false;
    }
    if (state->shutting_known &&
        !cep_ops_write_bool(reactor_root, dt_shutdn_field(), state->shutting_down)) {
        cep_ops_debug_last_error_code = 245;
        return false;
    }
    if (state->deadline_known &&
        !cep_ops_write_u64(reactor_root, dt_deadline_bt_field(), (uint64_t)state->deadline_beats)) {
        cep_ops_debug_last_error_code = 246;
        return false;
    }
    return true;
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
