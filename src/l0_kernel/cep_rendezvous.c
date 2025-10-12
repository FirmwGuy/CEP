#include "cep_rendezvous.h"

#include "cep_molecule.h"
#include "cep_namepool.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static cepRvSpawnStatus rv_last_status = CEP_RV_SPAWN_STATUS_OK;

CEP_DEFINE_STATIC_DT(dt_dictionary, CEP_ACRO("CEP"), CEP_WORD("dictionary"))
CEP_DEFINE_STATIC_DT(dt_text,        CEP_ACRO("CEP"), CEP_WORD("text"))
CEP_DEFINE_STATIC_DT(dt_rv_root,     CEP_ACRO("CEP"), CEP_WORD("rv"))
CEP_DEFINE_STATIC_DT(dt_state,       CEP_ACRO("CEP"), CEP_WORD("state"))
CEP_DEFINE_STATIC_DT(dt_prof,        CEP_ACRO("CEP"), CEP_WORD("prof"))
CEP_DEFINE_STATIC_DT(dt_spawn_beat,  CEP_ACRO("CEP"), CEP_WORD("spawn_beat"))
CEP_DEFINE_STATIC_DT(dt_due,         CEP_ACRO("CEP"), CEP_WORD("due"))
CEP_DEFINE_STATIC_DT(dt_epoch_k,     CEP_ACRO("CEP"), CEP_WORD("epoch_k"))
CEP_DEFINE_STATIC_DT(dt_input_fp,    CEP_ACRO("CEP"), CEP_WORD("input_fp"))
CEP_DEFINE_STATIC_DT(dt_deadline,    CEP_ACRO("CEP"), CEP_WORD("deadline"))
CEP_DEFINE_STATIC_DT(dt_grace_delta, CEP_ACRO("CEP"), CEP_WORD("grace_delta"))
CEP_DEFINE_STATIC_DT(dt_max_grace,   CEP_ACRO("CEP"), CEP_WORD("max_grace"))
CEP_DEFINE_STATIC_DT(dt_kill_wait,   CEP_ACRO("CEP"), CEP_WORD("kill_wait"))
CEP_DEFINE_STATIC_DT(dt_on_miss,     CEP_ACRO("CEP"), CEP_WORD("on_miss"))
CEP_DEFINE_STATIC_DT(dt_kill_mode,   CEP_ACRO("CEP"), CEP_WORD("kill_mode"))
CEP_DEFINE_STATIC_DT(dt_cas_hash,    CEP_ACRO("CEP"), CEP_WORD("cas_hash"))
CEP_DEFINE_STATIC_DT(dt_grace_used,  CEP_ACRO("CEP"), CEP_WORD("grace_used"))
CEP_DEFINE_STATIC_DT(dt_signal_path, CEP_ACRO("CEP"), CEP_WORD("signal_path"))
CEP_DEFINE_STATIC_DT(dt_inst_id,     CEP_ACRO("CEP"), CEP_WORD("inst_id"))
CEP_DEFINE_STATIC_DT(dt_telemetry,   CEP_ACRO("CEP"), CEP_WORD("telemetry"))

static cepCell* rv_ensure_dictionary_child(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(name);
    cepCell* node = cep_cell_find_by_name(parent, &lookup);
    if (node) {
        if (!cep_cell_has_store(node) || node->store->indexing != CEP_INDEX_BY_NAME) {
            cep_cell_to_dictionary(node);
        }
        return node;
    }

    cepDT type = *dt_dictionary();
    return cep_dict_add_dictionary(parent, &lookup, &type, CEP_STORAGE_RED_BLACK_T);
}

static cepCell* rv_ledger(void) {
    cep_cell_system_ensure();
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return NULL;
    }
    return rv_ensure_dictionary_child(data_root, dt_rv_root());
}

static bool rv_id_to_text(cepID id, char* buffer, size_t capacity) {
    if (!buffer || capacity == 0u) {
        return false;
    }

    if (cep_id_is_reference(id)) {
        size_t len = 0u;
        const char* text = cep_namepool_lookup(id, &len);
        if (!text || len + 1u > capacity) {
            return false;
        }
        memcpy(buffer, text, len);
        buffer[len] = '\0';
        return true;
    }

    if (cep_id_is_word(id)) {
        size_t written = cep_word_to_text(id, buffer);
        if (written + 1u > capacity) {
            return false;
        }
        buffer[written] = '\0';
        return true;
    }

    if (cep_id_is_acronym(id)) {
        size_t written = cep_acronym_to_text(id, buffer);
        if (written + 1u > capacity) {
            return false;
        }
        buffer[written] = '\0';
        return true;
    }

    if (cep_id_is_numeric(id)) {
        int rc = snprintf(buffer, capacity, "%" PRIu64, (unsigned long long)cep_id(id));
        return rc > 0 && (size_t)rc < capacity;
    }

    return false;
}

static bool rv_store_string(cepCell* entry, const cepDT* field, const char* text) {
    if (!entry || !field || !text) {
        return false;
    }

    cepDT lookup = cep_dt_clean(field);
    cepCell* existing = cep_cell_find_by_name(entry, &lookup);
    if (existing) {
        cep_cell_remove_hard(entry, existing);
    }

    size_t len = strlen(text) + 1u;
    cepDT payload_type = *dt_text();

    if (len <= sizeof(((cepData*)0)->value)) {
        return cep_dict_add_value(entry, &lookup, &payload_type, (void*)text, len, len) != NULL;
    }

    char* copy = cep_malloc(len);
    if (!copy) {
        return false;
    }
    memcpy(copy, text, len);
    cepCell* node = cep_dict_add_data(entry, &lookup, &payload_type, copy, len, len, cep_free);
    if (!node) {
        cep_free(copy);
        return false;
    }
    return true;
}

static bool rv_store_number(cepCell* entry, const cepDT* field, uint64_t value) {
    char buffer[32];
    int rc = snprintf(buffer, sizeof buffer, "%" PRIu64, (unsigned long long)value);
    if (rc <= 0 || (size_t)rc >= sizeof buffer) {
        return false;
    }
    return rv_store_string(entry, field, buffer);
}

static cepCell* rv_find_entry(cepCell* ledger, const cepDT* key_dt) {
    if (!ledger || !key_dt) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(key_dt);
    if (!cep_id(lookup.domain)) {
        lookup.domain = CEP_ACRO("CEP");
    }
    if (!cep_id(lookup.tag)) {
        return NULL;
    }

    cepCell* entry = cep_cell_find_by_name(ledger, &lookup);
    if (entry) {
        if (!cep_cell_has_store(entry) || entry->store->indexing != CEP_INDEX_BY_NAME) {
            cep_cell_to_dictionary(entry);
        }
        return entry;
    }

    cepDT type = *dt_dictionary();
    return cep_dict_add_dictionary(ledger, &lookup, &type, CEP_STORAGE_RED_BLACK_T);
}

static void rv_clear_children(cepCell* cell) {
    if (!cell || !cep_cell_has_store(cell)) {
        return;
    }
    while (cep_cell_children(cell) > 0u) {
        cepCell* child = cep_cell_first(cell);
        cep_cell_remove_hard(cell, child);
    }
}

static void rv_seed_defaults(cepCell* entry) {
    rv_store_number(entry, dt_epoch_k(),   0u);
    rv_store_number(entry, dt_input_fp(), 0u);
    rv_store_number(entry, dt_deadline(), 0u);
    rv_store_number(entry, dt_grace_delta(), 0u);
    rv_store_number(entry, dt_max_grace(), 0u);
    rv_store_number(entry, dt_kill_wait(), 0u);
    rv_store_string(entry, dt_on_miss(),  "timeout");
    rv_store_string(entry, dt_kill_mode(), "none");
    rv_store_string(entry, dt_cas_hash(), "");
    rv_store_number(entry, dt_grace_used(), 0u);

    cepCell* telemetry = rv_ensure_dictionary_child(entry, dt_telemetry());
    if (telemetry) {
        rv_clear_children(telemetry);
    }
}

bool cep_rv_bootstrap(void) {
    cepCell* ledger = rv_ledger();
    rv_last_status = ledger ? CEP_RV_SPAWN_STATUS_OK : CEP_RV_SPAWN_STATUS_LEDGER_MISSING;
    return ledger != NULL;
}

cepRvSpawnStatus cep_rv_last_spawn_status(void) {
    return rv_last_status;
}

static const char* rv_default_or(const char* text, const char* fallback) {
    return (text && *text) ? text : fallback;
}

bool cep_rv_spawn(const cepRvSpec* spec, cepID key) {
    if (!spec) {
        rv_last_status = CEP_RV_SPAWN_STATUS_NO_SPEC;
        return false;
    }

    cepCell* ledger = rv_ledger();
    if (!ledger) {
        rv_last_status = CEP_RV_SPAWN_STATUS_LEDGER_MISSING;
        return false;
    }

    cepDT entry_dt = cep_dt_clean(&spec->key_dt);
    if (!cep_id(entry_dt.tag)) {
        if (!key) {
            rv_last_status = CEP_RV_SPAWN_STATUS_NO_SPEC;
            return false;
        }
        entry_dt.tag = key;
    }
    if (!cep_id(entry_dt.domain)) {
        entry_dt.domain = CEP_ACRO("CEP");
    }

    cepCell* entry = rv_find_entry(ledger, &entry_dt);
    if (!entry) {
        rv_last_status = CEP_RV_SPAWN_STATUS_ENTRY_ALLOC;
        return false;
    }

    if (!rv_store_string(entry, dt_state(), "pending")) {
        rv_last_status = CEP_RV_SPAWN_STATUS_ENTRY_ALLOC;
        return false;
    }

    cepBeatNumber beat = cep_heartbeat_current();
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }
    rv_store_number(entry, dt_spawn_beat(), (uint64_t)beat);
    rv_store_number(entry, dt_due(), spec->due);

    rv_store_number(entry, dt_epoch_k(), spec->epoch_k);
    rv_store_number(entry, dt_input_fp(), spec->input_fp);
    rv_store_number(entry, dt_deadline(), spec->deadline);
    rv_store_number(entry, dt_grace_delta(), spec->grace_delta);
    rv_store_number(entry, dt_max_grace(), spec->max_grace);
    rv_store_number(entry, dt_kill_wait(), spec->kill_wait);

    char buffer[128];
    if (rv_id_to_text(spec->prof, buffer, sizeof buffer)) {
        rv_store_string(entry, dt_prof(), buffer);
    } else {
        rv_store_string(entry, dt_prof(), "rv-fixed");
    }

    if (rv_id_to_text(spec->on_miss, buffer, sizeof buffer)) {
        rv_store_string(entry, dt_on_miss(), buffer);
    } else {
        rv_store_string(entry, dt_on_miss(), "timeout");
    }

    if (rv_id_to_text(spec->kill_mode, buffer, sizeof buffer)) {
        rv_store_string(entry, dt_kill_mode(), buffer);
    } else {
        rv_store_string(entry, dt_kill_mode(), "none");
    }

    rv_store_string(entry, dt_cas_hash(), rv_default_or(spec->cas_hash, ""));
    rv_store_number(entry, dt_grace_used(), 0u);

    if (spec->signal_path && *spec->signal_path) {
        rv_store_string(entry, dt_signal_path(), spec->signal_path);
    } else {
        char path[128];
        if (cep_rv_signal_for_key(&entry_dt, path, sizeof path)) {
            rv_store_string(entry, dt_signal_path(), path);
        }
    }

    if (cep_id(spec->instance_dt.tag) || cep_id(spec->instance_dt.domain)) {
        char inst_buf[128];
        if (rv_id_to_text(spec->instance_dt.domain, inst_buf, sizeof inst_buf)) {
            size_t len = strlen(inst_buf);
            inst_buf[len++] = ':';
            if (rv_id_to_text(spec->instance_dt.tag, inst_buf + len, sizeof inst_buf - len)) {
                rv_store_string(entry, dt_inst_id(), inst_buf);
            }
        }
    }

    rv_seed_defaults(entry);

    if (spec->telemetry) {
        cepCell* dest = rv_ensure_dictionary_child(entry, dt_telemetry());
        if (dest) {
            rv_clear_children(dest);
            for (cepCell* child = cep_cell_first((cepCell*)spec->telemetry); child; child = cep_cell_next((cepCell*)spec->telemetry, child)) {
                cepCell* clone = cep_cell_clone_deep(child);
                if (!clone) {
                    continue;
                }
                cep_cell_add(dest, 0, clone);
                cep_free(clone);
            }
        }
    }

    rv_last_status = CEP_RV_SPAWN_STATUS_OK;
    return true;
}

bool cep_rv_signal_for_key(const cepDT* key, char* buffer, size_t capacity) {
    if (!key || !buffer || capacity == 0u) {
        return false;
    }

    cepDT clean = cep_dt_clean(key);
    char tag_text[96];
    if (!rv_id_to_text(clean.tag, tag_text, sizeof tag_text)) {
        return false;
    }

    int rc = snprintf(buffer, capacity, "CEP:sig_rv/%s", tag_text);
    return rc > 0 && (size_t)rc < capacity;
}

bool cep_rv_resched(cepID key, uint32_t delta) {
    if (delta == 0u) {
        return true;
    }

    cepCell* ledger = rv_ledger();
    if (!ledger) {
        return false;
    }

    cepDT lookup = cep_dt_make(CEP_ACRO("CEP"), key);
    cepCell* entry = rv_find_entry(ledger, &lookup);
    if (!entry) {
        return false;
    }

    cepCell* due_node = cep_cell_find_by_name(entry, dt_due());
    uint64_t due_value = 0u;
    if (due_node && cep_cell_has_data(due_node)) {
        const char* text = (const char*)cep_cell_data(due_node);
        if (text) {
            due_value = strtoull(text, NULL, 10);
        }
    }

    due_value += delta;
    return rv_store_number(entry, dt_due(), due_value);
}

bool cep_rv_kill(cepID key, cepID mode, uint32_t wait_beats) {
    cepCell* ledger = rv_ledger();
    if (!ledger) {
        return false;
    }

    cepDT lookup = cep_dt_make(CEP_ACRO("CEP"), key);
    cepCell* entry = rv_find_entry(ledger, &lookup);
    if (!entry) {
        return false;
    }

    char buffer[64];
    if (rv_id_to_text(mode, buffer, sizeof buffer)) {
        rv_store_string(entry, dt_kill_mode(), buffer);
    }
    return rv_store_number(entry, dt_kill_wait(), wait_beats);
}

bool cep_rv_report(cepID key, const cepCell* telemetry_node) {
    cepCell* ledger = rv_ledger();
    if (!ledger) {
        return false;
    }

    cepDT lookup = cep_dt_make(CEP_ACRO("CEP"), key);
    cepCell* entry = rv_find_entry(ledger, &lookup);
    if (!entry) {
        return false;
    }

    cepCell* telemetry = rv_ensure_dictionary_child(entry, dt_telemetry());
    if (!telemetry) {
        return false;
    }

    rv_clear_children(telemetry);

    if (!telemetry_node || !cep_cell_has_store((cepCell*)telemetry_node)) {
        return true;
    }

    for (cepCell* child = cep_cell_first((cepCell*)telemetry_node); child; child = cep_cell_next((cepCell*)telemetry_node, child)) {
        cepCell* clone = cep_cell_clone_deep(child);
        if (!clone) {
            continue;
        }
        cep_cell_add(telemetry, 0, clone);
        cep_free(clone);
    }

    return true;
}

bool cep_rv_capture_scan(void) {
    return true;
}

bool cep_rv_commit_apply(void) {
    return true;
}

bool cep_rendezvous_register(cepEnzymeRegistry* registry) {
    (void)registry;
    return true;
}

bool cep_rv_prepare_spec(cepRvSpec* out_spec,
                         const cepCell* spec_node,
                         const cepDT* instance_dt,
                         cepBeatNumber now,
                         char* signal_buffer,
                         size_t signal_capacity) {
    if (!out_spec) {
        return false;
    }

    memset(out_spec, 0, sizeof *out_spec);
    if (instance_dt) {
        out_spec->instance_dt = *instance_dt;
    }
    if (signal_buffer && signal_capacity > 0u) {
        signal_buffer[0] = '\0';
    }
    (void)spec_node;
    (void)now;
    return true;
}
