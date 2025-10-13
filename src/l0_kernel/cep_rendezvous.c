#include "cep_rendezvous.h"

#include "cep_molecule.h"
#include "cep_namepool.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cepRvSpawnStatus rv_last_status = CEP_RV_SPAWN_STATUS_OK;

CEP_DEFINE_STATIC_DT(dt_rv_root,          CEP_ACRO("CEP"), CEP_WORD("rv"))
CEP_DEFINE_STATIC_DT(dt_text,             CEP_ACRO("CEP"), CEP_WORD("text"))
CEP_DEFINE_STATIC_DT(dt_state,            CEP_ACRO("CEP"), CEP_WORD("state"))
CEP_DEFINE_STATIC_DT(dt_prof,             CEP_ACRO("CEP"), CEP_WORD("prof"))
CEP_DEFINE_STATIC_DT(dt_spawn_beat,       CEP_ACRO("CEP"), CEP_WORD("spawn_beat"))
CEP_DEFINE_STATIC_DT(dt_due,              CEP_ACRO("CEP"), CEP_WORD("due"))
CEP_DEFINE_STATIC_DT(dt_epoch_k,          CEP_ACRO("CEP"), CEP_WORD("epoch_k"))
CEP_DEFINE_STATIC_DT(dt_input_fp,         CEP_ACRO("CEP"), CEP_WORD("input_fp"))
CEP_DEFINE_STATIC_DT(dt_deadline,         CEP_ACRO("CEP"), CEP_WORD("deadline"))
CEP_DEFINE_STATIC_DT(dt_grace_delta,      CEP_ACRO("CEP"), CEP_WORD("grace_delta"))
CEP_DEFINE_STATIC_DT(dt_max_grace,        CEP_ACRO("CEP"), CEP_WORD("max_grace"))
CEP_DEFINE_STATIC_DT(dt_kill_wait,        CEP_ACRO("CEP"), CEP_WORD("kill_wait"))
CEP_DEFINE_STATIC_DT(dt_on_miss,          CEP_ACRO("CEP"), CEP_WORD("on_miss"))
CEP_DEFINE_STATIC_DT(dt_kill_mode,        CEP_ACRO("CEP"), CEP_WORD("kill_mode"))
CEP_DEFINE_STATIC_DT(dt_cas_hash,         CEP_ACRO("CEP"), CEP_WORD("cas_hash"))
CEP_DEFINE_STATIC_DT(dt_grace_used,       CEP_ACRO("CEP"), CEP_WORD("grace_used"))
CEP_DEFINE_STATIC_DT(dt_event_flag,       CEP_ACRO("CEP"), CEP_WORD("event_flag"))
CEP_DEFINE_STATIC_DT(dt_signal_path,      CEP_ACRO("CEP"), CEP_WORD("signal_path"))
CEP_DEFINE_STATIC_DT(dt_inst_id,          CEP_ACRO("CEP"), CEP_WORD("inst_id"))
CEP_DEFINE_STATIC_DT(dt_telemetry,        CEP_ACRO("CEP"), CEP_WORD("telemetry"))
CEP_DEFINE_STATIC_DT(dt_inbox_root,       CEP_ACRO("CEP"), CEP_WORD("inbox"))
CEP_DEFINE_STATIC_DT(dt_flow_ns,          CEP_ACRO("CEP"), CEP_WORD("flow"))
CEP_DEFINE_STATIC_DT(dt_flow_inst_event,  CEP_ACRO("CEP"), CEP_WORD("inst_event"))
CEP_DEFINE_STATIC_DT(dt_outcome,          CEP_ACRO("CEP"), CEP_WORD("outcome"))

typedef enum {
    RV_STATE_PENDING,
    RV_STATE_READY,
    RV_STATE_APPLIED,
    RV_STATE_LATE,
    RV_STATE_TIMEOUT,
    RV_STATE_KILLED,
    RV_STATE_QUARANTINE,
    RV_STATE_UNKNOWN
} rvState;

typedef struct {
    cepCell* entry;
    rvState  current_state;
    rvState  new_state;
    bool     change_state;
    bool     update_due;
    uint64_t due_value;
    bool     update_grace_used;
    uint64_t grace_used_value;
    bool     update_kill_wait;
    uint64_t kill_wait_value;
    const char* kill_mode_text;
    bool     emit_event;
    rvState  event_state;
    bool     ensure_event_flag;
    bool     clear_event_flag;
} rvPendingUpdate;

typedef struct {
    rvPendingUpdate* items;
    size_t           count;
    size_t           capacity;
} rvPendingQueue;

static rvPendingQueue rv_updates = {0};

static inline bool rv_text_equals(const char* lhs, const char* rhs) {
    if (!lhs || !rhs) {
        return lhs == rhs;
    }
    return strcmp(lhs, rhs) == 0;
}

static const char* rv_state_to_text(rvState state) {
    switch (state) {
        case RV_STATE_PENDING:    return "pending";
        case RV_STATE_READY:      return "ready";
        case RV_STATE_APPLIED:    return "applied";
        case RV_STATE_LATE:       return "late";
        case RV_STATE_TIMEOUT:    return "timeout";
        case RV_STATE_KILLED:     return "killed";
        case RV_STATE_QUARANTINE: return "quarantine";
        case RV_STATE_UNKNOWN:    break;
    }
    return "pending";
}

static rvState rv_state_from_text(const char* text) {
    if (!text || !*text) {
        return RV_STATE_PENDING;
    }
    if (rv_text_equals(text, "pending")) {
        return RV_STATE_PENDING;
    }
    if (rv_text_equals(text, "ready")) {
        return RV_STATE_READY;
    }
    if (rv_text_equals(text, "applied")) {
        return RV_STATE_APPLIED;
    }
    if (rv_text_equals(text, "late")) {
        return RV_STATE_LATE;
    }
    if (rv_text_equals(text, "timeout")) {
        return RV_STATE_TIMEOUT;
    }
    if (rv_text_equals(text, "killed")) {
        return RV_STATE_KILLED;
    }
    if (rv_text_equals(text, "quarantine")) {
        return RV_STATE_QUARANTINE;
    }
    return RV_STATE_UNKNOWN;
}

static cepID rv_intern_word(const char* text) {
    if (!text || !*text) {
        return 0u;
    }

    cepID id = cep_text_to_word(text);
    if (id) {
        return id;
    }
    return cep_namepool_intern(text, strlen(text));
}

static const char* rv_read_text(const cepCell* entry, const cepDT* field) {
    if (!entry || !field) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(field);
    cepCell* node = cep_cell_find_by_name((cepCell*)entry, &lookup);
    if (!node || !cep_cell_has_data(node)) {
        return NULL;
    }
    return (const char*)cep_cell_data(node);
}

static bool rv_read_uint64(const cepCell* entry, const cepDT* field, uint64_t* value_out) {
    if (!entry || !field || !value_out) {
        return false;
    }

    const char* text = rv_read_text(entry, field);
    if (!text) {
        return false;
    }

    char* end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (end == text || (end && *end != '\0')) {
        return false;
    }
    *value_out = (uint64_t)parsed;
    return true;
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
        cepCell* node = cep_dict_add_value(entry, &lookup, &payload_type, (void*)text, len, len);
        if (node) {
            cep_cell_content_hash(node);
            return true;
        }
        return false;
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
    cep_cell_content_hash(node);
    return true;
}

static bool rv_store_number(cepCell* entry, const cepDT* field, uint64_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%" PRIu64, (unsigned long long)value);
    if (written < 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return rv_store_string(entry, field, buffer);
}

static bool rv_queue_reserve(size_t desired) {
    if (rv_updates.capacity >= desired) {
        return true;
    }

    size_t new_capacity = rv_updates.capacity ? rv_updates.capacity : 8u;
    while (new_capacity < desired) {
        new_capacity <<= 1u;
    }

    rvPendingUpdate* resized = rv_updates.items
        ? cep_realloc(rv_updates.items, new_capacity * sizeof *resized)
        : cep_malloc(new_capacity * sizeof *resized);
    if (!resized) {
        return false;
    }

    rv_updates.items = resized;
    rv_updates.capacity = new_capacity;
    return true;
}

static void rv_queue_reset(void) {
    rv_updates.count = 0u;
}

static bool rv_queue_push(const rvPendingUpdate* update) {
    if (!rv_queue_reserve(rv_updates.count + 1u)) {
        return false;
    }
    rv_updates.items[rv_updates.count++] = *update;
    return true;
}

static cepCell* rv_ensure_dictionary_child(cepCell* parent, const cepDT* name) {
    return cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
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

    if (!cep_id(id)) {
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

static cepCell* rv_find_entry(cepCell* ledger, const cepDT* key_dt) {
    if (!ledger || !key_dt) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(key_dt);
    if (!cep_id(lookup.tag)) {
        return NULL;
    }
    if (!cep_id(lookup.domain)) {
        lookup.domain = CEP_ACRO("CEP");
    }

    cepCell* entry = rv_ensure_dictionary_child(ledger, &lookup);
    if (!entry) {
        return NULL;
    }

    cepDT name_copy = lookup;
    cep_cell_set_name(entry, &name_copy);
    return entry;
}

static void rv_seed_defaults(cepCell* entry) {
    rv_store_number(entry, dt_epoch_k(),        0u);
    rv_store_number(entry, dt_input_fp(),       0u);
    rv_store_number(entry, dt_deadline(),       0u);
    rv_store_number(entry, dt_grace_delta(),    0u);
    rv_store_number(entry, dt_max_grace(),      0u);
    rv_store_number(entry, dt_kill_wait(),      0u);
    rv_store_number(entry, dt_event_flag(),     0u);
    rv_store_number(entry, dt_grace_used(),     0u);
    rv_store_string(entry, dt_on_miss(),        "timeout");
    rv_store_string(entry, dt_kill_mode(),      "none");
    rv_store_string(entry, dt_cas_hash(),       "");

    cepCell* telemetry = rv_ensure_dictionary_child(entry, dt_telemetry());
    if (telemetry) {
        cep_cell_clear_children(telemetry);
    }
}

static bool rv_state_emits_event(rvState state) {
    return state == RV_STATE_APPLIED
        || state == RV_STATE_TIMEOUT
        || state == RV_STATE_KILLED;
}

static bool rv_emit_flow_event(cepCell* entry, rvState state) {
    if (!entry || !rv_state_emits_event(state)) {
        return true;
    }

    const cepDT* key_dt = cep_cell_get_name(entry);
    if (!key_dt) {
        return false;
    }

    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return false;
    }

    cepCell* inbox_root = rv_ensure_dictionary_child(data_root, dt_inbox_root());
    if (!inbox_root) {
        return false;
    }

    cepCell* flow_ns = rv_ensure_dictionary_child(inbox_root, dt_flow_ns());
    if (!flow_ns) {
        return false;
    }

    cepCell* inst_event = rv_ensure_dictionary_child(flow_ns, dt_flow_inst_event());
    if (!inst_event) {
        return false;
    }

    cepDT key_name = cep_dt_clean(key_dt);
    if (!cep_id(key_name.domain)) {
        key_name.domain = CEP_ACRO("CEP");
    }

    cepCell* dest = rv_ensure_dictionary_child(inst_event, &key_name);
    if (!dest) {
        return false;
    }

    const char* outcome = rv_state_to_text(state);
    if (!rv_store_string(dest, dt_outcome(), outcome)) {
        return false;
    }
    if (!rv_store_string(dest, dt_state(), outcome)) {
        return false;
    }

    const char* signal_path = rv_read_text(entry, dt_signal_path());
    if (signal_path && !rv_store_string(dest, dt_signal_path(), signal_path)) {
        return false;
    }

    const char* inst_id = rv_read_text(entry, dt_inst_id());
    if (inst_id && !rv_store_string(dest, dt_inst_id(), inst_id)) {
        return false;
    }

    cepCell* src_telemetry = cep_cell_find_by_name(entry, dt_telemetry());
    cepCell* dest_telemetry = rv_ensure_dictionary_child(dest, dt_telemetry());
    if (!dest_telemetry) {
        return false;
    }
    if (!cep_cell_copy_children(src_telemetry, dest_telemetry, true)) {
        return false;
    }

    return true;
}

static bool rv_entry_evaluate(cepCell* entry, cepBeatNumber now, rvPendingUpdate* update) {
    if (!entry || !update) {
        return false;
    }

    cepBeatNumber beat = (now == CEP_BEAT_INVALID) ? 0u : now;

    memset(update, 0, sizeof *update);
    update->entry = entry;

    const char* state_text = rv_read_text(entry, dt_state());
    rvState state = rv_state_from_text(state_text);
    if (state == RV_STATE_UNKNOWN) {
        state = RV_STATE_PENDING;
    }
    update->current_state = state;
    update->new_state = state;

    uint64_t due = 0u;
    uint64_t grace_delta = 0u;
    uint64_t max_grace = 0u;
    uint64_t grace_used = 0u;
    uint64_t kill_wait = 0u;
    uint64_t event_flag = 0u;

    rv_read_uint64(entry, dt_due(), &due);
    rv_read_uint64(entry, dt_grace_delta(), &grace_delta);
    rv_read_uint64(entry, dt_max_grace(), &max_grace);
    rv_read_uint64(entry, dt_grace_used(), &grace_used);
    rv_read_uint64(entry, dt_kill_wait(), &kill_wait);
    rv_read_uint64(entry, dt_event_flag(), &event_flag);

    const char* kill_mode_text = rv_read_text(entry, dt_kill_mode());
    const char* on_miss_text = rv_read_text(entry, dt_on_miss());

    bool event_pending = event_flag > 0u;
    bool changed = false;

    bool kill_requested = kill_mode_text && !rv_text_equals(kill_mode_text, "none");
    if (kill_requested && state != RV_STATE_KILLED) {
        uint64_t next_wait = kill_wait;
        if (next_wait > 0u) {
            next_wait -= 1u;
            update->update_kill_wait = true;
            update->kill_wait_value = next_wait;
            kill_wait = next_wait;
            changed = true;
        }
        if (next_wait == 0u) {
            update->new_state = RV_STATE_KILLED;
            if (state != RV_STATE_KILLED) {
                update->change_state = true;
                changed = true;
                state = RV_STATE_KILLED;
            }
            update->kill_mode_text = "none";
            update->emit_event = true;
            update->event_state = state;
            update->ensure_event_flag = (event_flag == 0u);
            update->clear_event_flag = true;
            event_pending = true;
        }
    }

    if (state == RV_STATE_PENDING || state == RV_STATE_READY || state == RV_STATE_LATE) {
        if (beat >= due) {
            if (state == RV_STATE_PENDING) {
                update->new_state = RV_STATE_READY;
                update->change_state = true;
                changed = true;
                state = RV_STATE_READY;
            }

            if (beat > due) {
                bool exhausted_grace = false;

                if (max_grace > 0u) {
                    if (grace_used < max_grace) {
                        uint64_t next_grace = grace_used + 1u;
                        update->update_grace_used = true;
                        update->grace_used_value = next_grace;
                        grace_used = next_grace;
                        changed = true;

                        if (grace_delta > 0u) {
                            uint64_t extended_due = due;
                            if (UINT64_MAX - due < grace_delta) {
                                extended_due = UINT64_MAX;
                            } else {
                                extended_due += grace_delta;
                            }
                            update->update_due = true;
                            update->due_value = extended_due;
                            due = extended_due;
                        }
                    } else {
                        exhausted_grace = true;
                    }
                } else {
                    exhausted_grace = false;
                }

                if (exhausted_grace) {
                    const char* policy = on_miss_text ? on_miss_text : "timeout";
                    if (rv_text_equals(policy, "kill")) {
                        update->new_state = RV_STATE_KILLED;
                        if (state != RV_STATE_KILLED) {
                            update->change_state = true;
                            state = RV_STATE_KILLED;
                        }
                        update->kill_mode_text = "none";
                    } else {
                        update->new_state = RV_STATE_TIMEOUT;
                        if (state != RV_STATE_TIMEOUT) {
                            update->change_state = true;
                            state = RV_STATE_TIMEOUT;
                        }
                    }
                    update->emit_event = true;
                    update->event_state = update->new_state;
                    update->ensure_event_flag = (event_flag == 0u);
                    update->clear_event_flag = true;
                    changed = true;
                    event_pending = true;
                }
            }
        }
    }

    if (!update->emit_event && event_pending) {
        rvState current = update->change_state ? update->new_state : state;
        if (rv_state_emits_event(current)) {
            update->emit_event = true;
            update->event_state = current;
            update->clear_event_flag = true;
        }
    }

    return update->emit_event
        || update->change_state
        || update->update_due
        || update->update_grace_used
        || update->update_kill_wait
        || update->kill_mode_text != NULL
        || update->ensure_event_flag
        || changed;
}

static const char* rv_default_or(const char* text, const char* fallback) {
    return (text && *text) ? text : fallback;
}

/** Establish the rendezvous ledger root so later helpers can rely on the
    `/data/rv` dictionary existing even before any work is spawned. The helper
    records a status code for diagnostics so callers understand why bootstrap
    failed without having to re-run setup logic. */
bool cep_rv_bootstrap(void) {
    cepCell* ledger = rv_ledger();
    rv_last_status = ledger ? CEP_RV_SPAWN_STATUS_OK : CEP_RV_SPAWN_STATUS_LEDGER_MISSING;
    return ledger != NULL;
}

/** Surface the most recent rendezvous spawn status so callers can examine the
    failure reason from their last interaction without having to inspect the
    ledger directly. */
cepRvSpawnStatus cep_rv_last_spawn_status(void) {
    return rv_last_status;
}

/** Populate or update a rendezvous entry with the provided specification,
    recording deterministic defaults and telemetry so replay tooling observes a
    consistent ledger. The function seeds bookkeeping fields, normalises IDs,
    and keeps optional strings in place even when the caller omits them. */
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

    rv_store_number(entry, dt_epoch_k(),   spec->epoch_k);
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
            if (len + 2u < sizeof inst_buf) {
                inst_buf[len++] = ':';
                if (rv_id_to_text(spec->instance_dt.tag, inst_buf + len, sizeof inst_buf - len)) {
                    rv_store_string(entry, dt_inst_id(), inst_buf);
                }
            }
        }
    }

    rv_seed_defaults(entry);

    if (spec->telemetry) {
        cepCell* dest = rv_ensure_dictionary_child(entry, dt_telemetry());
        if (dest) {
            cep_cell_copy_children(spec->telemetry, dest, true);
        }
    }

    rv_last_status = CEP_RV_SPAWN_STATUS_OK;
    return true;
}

/** Produce the rendezvous signal path for the supplied ledger key so flows can
    subscribe to completion events deterministically. The helper formats
    `CEP:sig_rv/<tag>` using the canonical domain/tag packing rules. */
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

/** Delay the rendezvous deadline by the requested delta, returning true even
    when the entry does not exist so callers can issue best-effort reschedules
    without additional lookup boilerplate. */
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

/** Register a kill request for the rendezvous identified by `key`, updating the
    ledger with the requested mode and wait beats so evaluation honours the
    caller’s policy. */
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

/** Copy telemetry produced by the worker back into the rendezvous ledger,
    automatically marking the job as applied and arming the event flag so the
    heartbeat mirrors the completion into the flow inbox on the next beat. */
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

    if (!cep_cell_copy_children(telemetry_node, telemetry, true)) {
        return false;
    }

    if (!rv_store_string(entry, dt_state(), "applied")) {
        return false;
    }
    return rv_store_number(entry, dt_event_flag(), 1u);
}

/** Scan rendezvous entries at the start of the capture phase, staging state
    transitions and event emissions so commit can apply them without violating
    deterministic beat ordering. */
bool cep_rv_capture_scan(void) {
    rv_queue_reset();

    cepCell* ledger = rv_ledger();
    if (!ledger) {
        return true;
    }

    if (!cep_cell_require_dictionary_store(&ledger)) {
        return true;
    }

    cepBeatNumber now = cep_heartbeat_current();

    for (cepCell* node = cep_cell_first(ledger); node; node = cep_cell_next(ledger, node)) {
        cepCell* entry = cep_cell_resolve(node);
        if (!entry) {
            continue;
        }
        if (!cep_cell_require_dictionary_store(&entry)) {
            continue;
        }

        rvPendingUpdate update;
        if (rv_entry_evaluate(entry, now, &update)) {
            if (!rv_queue_push(&update)) {
                return false;
            }
        }
    }

    return true;
}

/** Apply staged rendezvous mutations during the resolve phase, updating ledger
    state and emitting flow events when completions, timeouts, or kills are
    observed. The function clears the event flag after mirroring so repeated
    beats do not duplicate flow impulses. */
bool cep_rv_commit_apply(void) {
    if (rv_updates.count == 0u) {
        return true;
    }

    for (size_t i = 0; i < rv_updates.count; ++i) {
        rvPendingUpdate* update = &rv_updates.items[i];
        cepCell* entry = update->entry;
        bool ok = true;

        if (update->change_state) {
            ok = rv_store_string(entry, dt_state(), rv_state_to_text(update->new_state));
        }
        if (ok && update->update_due) {
            ok = rv_store_number(entry, dt_due(), update->due_value);
        }
        if (ok && update->update_grace_used) {
            ok = rv_store_number(entry, dt_grace_used(), update->grace_used_value);
        }
        if (ok && update->update_kill_wait) {
            ok = rv_store_number(entry, dt_kill_wait(), update->kill_wait_value);
        }
        if (ok && update->kill_mode_text) {
            ok = rv_store_string(entry, dt_kill_mode(), update->kill_mode_text);
        }
        if (ok && update->ensure_event_flag) {
            ok = rv_store_number(entry, dt_event_flag(), 1u);
        }
        if (!ok) {
            rv_queue_reset();
            return false;
        }

        if (update->emit_event) {
            uint64_t flag_value = 0u;
            if (!rv_read_uint64(entry, dt_event_flag(), &flag_value) || flag_value == 0u) {
                if (!rv_store_number(entry, dt_event_flag(), 1u)) {
                    rv_queue_reset();
                    return false;
                }
            }

            if (!rv_emit_flow_event(entry, update->event_state)) {
                rv_queue_reset();
                return false;
            }

            if (update->clear_event_flag) {
                if (!rv_store_number(entry, dt_event_flag(), 0u)) {
                    rv_queue_reset();
                    return false;
                }
            }
        }
    }

    rv_queue_reset();
    return true;
}

/** Register rendezvous bootstrap and routing enzymes with the supplied
    registry, ensuring the ledger exists ahead of time. The current kernel
    build handles routing internally, so registration is a bootstrap no-op
    beyond guaranteeing the ledger is ready. */
bool cep_rendezvous_register(cepEnzymeRegistry* registry) {
    (void)registry;
    return cep_rv_bootstrap();
}

/** Merge rendezvous specification cells into a `cepRvSpec` structure, applying
    defaults when fields are missing and deriving helper values such as signal
    paths. The helper tolerates sparse dictionaries so flows can provide only
    the knobs they care about. */
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
    out_spec->prof = CEP_WORD("rv-fixed");
    out_spec->on_miss = CEP_WORD("timeout");
    out_spec->kill_mode = CEP_WORD("none");
    if (instance_dt) {
        out_spec->instance_dt = *instance_dt;
    }

    if (spec_node && cep_cell_has_store((cepCell*)spec_node)) {
        const char* text = rv_read_text(spec_node, dt_prof());
        if (text && *text) {
            out_spec->prof = rv_intern_word(text);
        }

        text = rv_read_text(spec_node, dt_on_miss());
        if (text && *text) {
            out_spec->on_miss = rv_intern_word(text);
        }

        text = rv_read_text(spec_node, dt_kill_mode());
        if (text && *text) {
            out_spec->kill_mode = rv_intern_word(text);
        }

        text = rv_read_text(spec_node, dt_signal_path());
        if (text && *text) {
            out_spec->signal_path = text;
        }

        text = rv_read_text(spec_node, dt_cas_hash());
        if (text && *text) {
            out_spec->cas_hash = text;
        }

        rv_read_uint64(spec_node, dt_due(), &out_spec->due);
        rv_read_uint64(spec_node, dt_deadline(), &out_spec->deadline);
        rv_read_uint64(spec_node, dt_input_fp(), &out_spec->input_fp);

        uint64_t tmp = 0u;
        if (rv_read_uint64(spec_node, dt_epoch_k(), &tmp)) {
            out_spec->epoch_k = (uint32_t)tmp;
        }
        tmp = 0u;
        if (rv_read_uint64(spec_node, dt_grace_delta(), &tmp)) {
            out_spec->grace_delta = (uint32_t)tmp;
        }
        tmp = 0u;
        if (rv_read_uint64(spec_node, dt_max_grace(), &tmp)) {
            out_spec->max_grace = (uint32_t)tmp;
        }
        tmp = 0u;
        if (rv_read_uint64(spec_node, dt_kill_wait(), &tmp)) {
            out_spec->kill_wait = (uint32_t)tmp;
        }

        cepCell* telemetry = cep_cell_find_by_name((cepCell*)spec_node, dt_telemetry());
        if (telemetry && cep_cell_has_store(telemetry)) {
            out_spec->telemetry = telemetry;
        }
    }

    if (!cep_id(out_spec->instance_dt.domain) && instance_dt) {
        out_spec->instance_dt.domain = instance_dt->domain;
    }
    if (!cep_id(out_spec->instance_dt.tag) && instance_dt) {
        out_spec->instance_dt.tag = instance_dt->tag;
    }

    if (signal_buffer && signal_capacity > 0u) {
        signal_buffer[0] = '\0';
        if (cep_id(out_spec->key_dt.tag) && cep_rv_signal_for_key(&out_spec->key_dt, signal_buffer, signal_capacity)) {
            out_spec->signal_path = signal_buffer;
        }
    }

    (void)now;
    return true;
}
