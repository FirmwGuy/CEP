/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_enclave_policy.h"

#include "cep_security_tags.h"
#include "cep_ops.h"
#include "cep_cei.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_crc32c.h"

#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <inttypes.h>

#ifdef CEP_ENABLE_DEBUG
#include <execinfo.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define CEP_ENCLAVE_POLICY_TIER_MAX  (sizeof(((cepEnclaveDescriptor*)0)->trust_tier))
#define CEP_ENCLAVE_BRANCH_PATH_MAX 512u
#define CEP_ENCLAVE_BRANCH_SEGMENT_MAX 64u
#define CEP_ENCLAVE_RULE_ID_MAX 96u
#define CEP_ENCLAVE_SUBJECT_NAME_MAX 96u

CEP_DEFINE_STATIC_DT(dt_rt_root_name_sec, CEP_ACRO("CEP"), CEP_WORD("rt"));
CEP_DEFINE_STATIC_DT(dt_sys_root_name_sec, CEP_ACRO("CEP"), CEP_WORD("sys"));
CEP_DEFINE_STATIC_DT(dt_state_root_name_sec, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_analytics_root_name_sec, CEP_ACRO("CEP"), CEP_WORD("analytics"));
CEP_DEFINE_STATIC_DT(dt_state_field_sec, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_state_note_field_sec, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_state_fault_field_sec, CEP_ACRO("CEP"), CEP_WORD("fault"));
CEP_DEFINE_STATIC_DT(dt_state_version_field_sec, CEP_ACRO("CEP"), CEP_WORD("version"));
CEP_DEFINE_STATIC_DT(dt_state_beat_field_sec, CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_sec_analytics_root_name, CEP_ACRO("CEP"), CEP_WORD("security"));
CEP_DEFINE_STATIC_DT(dt_sec_analytics_beats_name, CEP_ACRO("CEP"), CEP_WORD("beats"));
CEP_DEFINE_STATIC_DT(dt_sec_allow_field, CEP_ACRO("CEP"), CEP_WORD("allow"));
CEP_DEFINE_STATIC_DT(dt_sec_deny_field, CEP_ACRO("CEP"), CEP_WORD("deny"));
CEP_DEFINE_STATIC_DT(dt_sec_limits_field, CEP_ACRO("CEP"), CEP_WORD("limits"));
CEP_DEFINE_STATIC_DT(dt_sec_label_field, CEP_ACRO("CEP"), CEP_WORD("label"));

static bool
cep_enclave_policy_read_text(cepCell* parent,
                             const cepDT* field,
                             char* buffer,
                             size_t capacity);

typedef struct {
    bool     allow;
    uint32_t verbs_mask;
    cepID*   pack_ids;
    size_t   pack_count;
    char*    rule_id;
} cepEnclaveBranchRule;

struct cepEnclaveBranchEntry {
    char*                 path_pattern;
    char*                 enclave_label;
    bool                  default_allow;
    cepEnclaveBranchRule* rules;
    size_t                rule_count;
};

typedef struct {
    cepEnclavePolicySnapshot snapshot;
    cepCell*                 security_root;
    bool                     dirty;
    bool                     ready;
    uint32_t                 freeze_count;
    bool                     pending_dirty;
} cepEnclavePolicyRuntime;

static cepEnclavePolicyRuntime g_enclave_policy = {0};

#ifdef CEP_ENABLE_DEBUG
#define CEP_ENCLAVE_POLICY_TRACE_DIR  "/tmp/cep_trace"
#define CEP_ENCLAVE_POLICY_TRACE_FILE CEP_ENCLAVE_POLICY_TRACE_DIR "/enclave_policy_trace.log"

static FILE*
cep_enclave_policy_trace_open(void)
{
    static bool dir_ready = false;
    if (!dir_ready) {
        if (mkdir(CEP_ENCLAVE_POLICY_TRACE_DIR, 0777) != 0 && errno != EEXIST) {
            return NULL;
        }
        dir_ready = true;
    }
    return fopen(CEP_ENCLAVE_POLICY_TRACE_FILE, "a");
}

static void
cep_enclave_policy_trace_dump_stack(FILE* stream)
{
    if (!stream) {
        return;
    }
    void* frames[16] = {0};
    int captured = backtrace(frames, (int)(sizeof(frames) / sizeof(frames[0])));
    if (captured <= 0) {
        return;
    }
    for (int i = 0; i < captured; ++i) {
        Dl_info info = {0};
        const void* addr = frames[i];
        if (dladdr(addr, &info) != 0 && info.dli_sname) {
            ptrdiff_t offset = (const char*)addr - (const char*)info.dli_saddr;
            fprintf(stream,
                    "        #%02d %p %s+0x%tx\n",
                    i,
                    addr,
                    info.dli_sname,
                    offset);
        } else {
            fprintf(stream, "        #%02d %p\n", i, addr);
        }
    }
}
#endif

static void
cep_enclave_policy_trace_log(const char* event,
                             const char* detail,
                             bool capture_stack)
{
#if defined(CEP_ENABLE_DEBUG)
    if (!event) {
        return;
    }
    FILE* log = cep_enclave_policy_trace_open();
    if (!log) {
        return;
    }
    cepBeatNumber beat = cep_beat_index();
    uint64_t beat_number = (beat == CEP_BEAT_INVALID) ? 0u : (uint64_t)beat;
    uint64_t version = g_enclave_policy.snapshot.version;
    fprintf(log,
            "[policy-trace:%s] beat=%" PRIu64 " version=%" PRIu64 " dirty=%u ready=%u\n",
            event,
            beat_number,
            version,
            g_enclave_policy.dirty ? 1u : 0u,
            g_enclave_policy.ready ? 1u : 0u);
    if (detail && *detail) {
        fprintf(log, "    %s\n", detail);
    }
    if (capture_stack) {
        fputs("    stack:\n", log);
        cep_enclave_policy_trace_dump_stack(log);
    }
    fclose(log);
#else
    (void)event;
    (void)detail;
    (void)capture_stack;
#endif
}

void
cep_enclave_policy_trace_stage(const char* stage)
{
    if (!stage) {
        return;
    }
    cep_enclave_policy_trace_log(stage, NULL, false);
}

#if defined(CEP_ENABLE_DEBUG)
static const char*
cep_enclave_policy_trace_id_desc(cepID id, char* buf, size_t cap)
{
    if (!buf || !cap) {
        return "<buf>";
    }
    if (!id) {
        snprintf(buf, cap, "0");
        return buf;
    }
    if (cep_id_is_reference(id)) {
        const char* text = cep_namepool_lookup(id, NULL);
        if (text) {
            snprintf(buf, cap, "%s", text);
            return buf;
        }
    } else if (cep_id_is_word(id)) {
        size_t len = cep_word_to_text(id, buf);
        if (len >= cap) {
            len = cap - 1u;
        }
        buf[len] = '\0';
        return buf;
    } else if (cep_id_is_acronym(id)) {
        size_t len = cep_acronym_to_text(id, buf);
        if (len >= cap) {
            len = cap - 1u;
        }
        buf[len] = '\0';
        while (len && buf[len - 1] == ' ') {
            buf[--len] = '\0';
        }
        return buf;
    } else if (cep_id_is_numeric(id)) {
        snprintf(buf, cap, "#%llu", (unsigned long long)cep_id_to_numeric(id));
        return buf;
    }
    snprintf(buf, cap, "0x%016" PRIX64, (uint64_t)id);
    return buf;
}
#endif

void
cep_enclave_policy_freeze_enter(const char* reason)
{
    g_enclave_policy.freeze_count += 1u;
    if (g_enclave_policy.freeze_count == 1u && g_enclave_policy.dirty) {
        g_enclave_policy.pending_dirty = true;
        g_enclave_policy.dirty = false;
    }
    cep_enclave_policy_trace_log("freeze_enter", reason, false);
}

void
cep_enclave_policy_freeze_leave(void)
{
    if (!g_enclave_policy.freeze_count) {
        return;
    }
    g_enclave_policy.freeze_count -= 1u;
    cep_enclave_policy_trace_log("freeze_exit", NULL, false);
    if (!g_enclave_policy.freeze_count && g_enclave_policy.pending_dirty) {
        g_enclave_policy.dirty = true;
        g_enclave_policy.pending_dirty = false;
        cep_enclave_policy_trace_log("freeze_pending_dirty", NULL, false);
    }
}

bool
cep_enclave_policy_is_frozen(void)
{
    return g_enclave_policy.freeze_count != 0u;
}

static void
cep_enclave_policy_trace_format_path(const cepCell* cell,
                                     char* buffer,
                                     size_t capacity)
{
#if defined(CEP_ENABLE_DEBUG)
    if (!buffer || !capacity) {
        return;
    }
    buffer[0] = '\0';
    if (!cell) {
        return;
    }
    char segments[32][64];
    unsigned segment_count = 0u;
    const cepCell* cursor = cell;
    const unsigned max_segments = (unsigned)(sizeof segments / sizeof segments[0]);
    while (cursor && !cep_cell_is_root((cepCell*)cursor) && segment_count < max_segments) {
        const cepDT* cursor_name = cep_cell_get_name(cursor);
        if (cursor_name) {
            char dom_buf[64];
            char tag_buf[64];
            const char* dom = cep_enclave_policy_trace_id_desc(cursor_name->domain, dom_buf, sizeof dom_buf);
            const char* tag = cep_enclave_policy_trace_id_desc(cursor_name->tag, tag_buf, sizeof tag_buf);
            snprintf(segments[segment_count], sizeof segments[segment_count], "%s/%s", dom, tag);
        } else {
            snprintf(segments[segment_count], sizeof segments[segment_count], "<anon>");
        }
        ++segment_count;
        cursor = cep_cell_parent(cursor);
    }
    if (!segment_count) {
        snprintf(buffer, capacity, "/");
        return;
    }
    size_t used = 0u;
    for (unsigned idx = segment_count; idx-- > 0u;) {
        int written = snprintf(buffer + used,
                               (used < capacity) ? capacity - used : 0u,
                               "/%s",
                               segments[idx]);
        if (written < 0) {
            buffer[0] = '\0';
            return;
        }
        if ((size_t)written >= ((used < capacity) ? (capacity - used) : 0u)) {
            if (capacity) {
                buffer[capacity - 1u] = '\0';
            }
            return;
        }
        used += (size_t)written;
    }
#else
    (void)cell;
    if (buffer && capacity) {
        buffer[0] = '\0';
    }
#endif
}

static cepCell*
cep_enclave_policy_state_cell(void)
{
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    cepCell* sys = cep_cell_ensure_dictionary_child(root, dt_sys_root_name_sec(), CEP_STORAGE_RED_BLACK_T);
    if (!sys) {
        return NULL;
    }
    sys = cep_cell_resolve(sys);
    if (!sys || !cep_cell_require_dictionary_store(&sys)) {
        return NULL;
    }
    cepCell* state_root = cep_cell_ensure_dictionary_child(sys, dt_state_root_name_sec(), CEP_STORAGE_RED_BLACK_T);
    if (!state_root) {
        return NULL;
    }
    state_root = cep_cell_resolve(state_root);
    if (!state_root || !cep_cell_require_dictionary_store(&state_root)) {
        return NULL;
    }
    cepCell* security = cep_cell_ensure_dictionary_child(state_root,
                                                         dt_security_root_name(),
                                                         CEP_STORAGE_RED_BLACK_T);
    if (!security) {
        return NULL;
    }
    security = cep_cell_resolve(security);
    if (!security || !cep_cell_require_dictionary_store(&security)) {
        return NULL;
    }
    return security;
}

static void
cep_enclave_policy_state_clear_fault(cepCell* cell)
{
    if (!cell) {
        return;
    }
    cepDT fault_name = *dt_state_fault_field_sec();
    cepCell* fault = cep_cell_find_by_name(cell, &fault_name);
    if (fault) {
        cep_cell_remove_hard(fault, NULL);
    }
}

static void
cep_enclave_policy_publish_state(const char* state,
                                 const char* note,
                                 const char* fault,
                                 uint64_t version)
{
    cepCell* status = cep_enclave_policy_state_cell();
    if (!status) {
        return;
    }
    if (state) {
        (void)cep_cell_put_text(status, dt_state_field_sec(), state);
    }
    if (note) {
        (void)cep_cell_put_text(status, dt_state_note_field_sec(), note);
    }
    if (fault && *fault) {
        (void)cep_cell_put_text(status, dt_state_fault_field_sec(), fault);
    } else {
        cep_enclave_policy_state_clear_fault(status);
    }
    (void)cep_cell_put_uint64(status, dt_state_version_field_sec(), version);
    cepBeatNumber beat = cep_beat_index();
    if (beat == CEP_BEAT_INVALID) {
        beat = cep_heartbeat_current();
    }
    uint64_t beat_val = (beat == CEP_BEAT_INVALID) ? 0u : (uint64_t)beat;
    (void)cep_cell_put_uint64(status, dt_state_beat_field_sec(), beat_val);
}

static void
cep_enclave_policy_publish_fault(const char* reason)
{
    const char* message = (reason && *reason) ? reason : "security policy fault";
    cep_enclave_policy_publish_state("error",
                                     message,
                                     message,
                                     g_enclave_policy.snapshot.version);
}

static cepCell*
cep_enclave_policy_security_ensure_branch(cepCell* parent, const cepDT* name)
{
    if (!parent || !name) {
        return NULL;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    if (!child) {
        return NULL;
    }
    child = cep_cell_resolve(child);
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return NULL;
    }
    return child;
}

static cepCell*
cep_enclave_policy_security_analytics_root(void)
{
    cepCell* root = cep_root();
    if (!root) {
        return NULL;
    }
    cepCell* rt = cep_cell_ensure_dictionary_child(root, dt_rt_root_name_sec(), CEP_STORAGE_RED_BLACK_T);
    if (!rt) {
        return NULL;
    }
    rt = cep_cell_resolve(rt);
    if (!rt || !cep_cell_require_dictionary_store(&rt)) {
        return NULL;
    }
    cepCell* analytics = cep_cell_ensure_dictionary_child(rt,
                                                          dt_analytics_root_name_sec(),
                                                          CEP_STORAGE_RED_BLACK_T);
    if (!analytics) {
        return NULL;
    }
    analytics = cep_cell_resolve(analytics);
    if (!analytics || !cep_cell_require_dictionary_store(&analytics)) {
        return NULL;
    }
    return cep_enclave_policy_security_ensure_branch(analytics, dt_sec_analytics_root_name());
}

static bool
cep_enclave_policy_security_increment_counter(cepCell* parent, const cepDT* field, uint64_t delta)
{
    if (!parent || !field) {
        return false;
    }
    uint64_t next = delta;
    cepCell* existing = cep_cell_find_by_name(parent, field);
    if (existing) {
        existing = cep_cell_resolve(existing);
        if (existing && existing->data) {
            cepData* data = existing->data;
            if (data->size == sizeof(uint64_t)) {
                const uint64_t* payload = (const uint64_t*)cep_data_payload(data);
                if (payload) {
                    next += *payload;
                }
            }
        }
    }
    return cep_cell_put_uint64(parent, field, next);
}

static cepDT
cep_enclave_policy_security_hash_name(const char* name, uint32_t salt)
{
    cepDT hashed = {0};
    if (!name) {
        return hashed;
    }
    uint32_t hash = cep_crc32c((const uint8_t*)name, strlen(name), 0u);
    hash ^= salt * 0x9e3779b9u;
    cepID numeric = (cepID)((hash % CEP_NAME_MAXVAL) + 1u);
    hashed.domain = CEP_ACRO("CEP");
    hashed.tag = cep_id_to_numeric(numeric);
    hashed.glob = 0u;
    return hashed;
}

static cepCell*
cep_enclave_policy_security_ensure_named_child(cepCell* parent, const char* name)
{
    if (!parent || !name || !*name) {
        return NULL;
    }
    for (uint32_t salt = 0u; salt < 1024u; ++salt) {
        cepDT dt = cep_enclave_policy_security_hash_name(name, salt);
        cepCell* child = cep_cell_ensure_dictionary_child(parent, &dt, CEP_STORAGE_RED_BLACK_T);
        if (!child) {
            return NULL;
        }
        child = cep_cell_resolve(child);
        if (!child || !cep_cell_require_dictionary_store(&child)) {
            return NULL;
        }
        char existing[CEP_ENCLAVE_BRANCH_PATH_MAX] = {0};
        if (!cep_enclave_policy_read_text(child, dt_sec_label_field(), existing, sizeof existing)) {
            (void)cep_cell_put_text(child, dt_sec_label_field(), name);
            return child;
        }
        if (strcmp(existing, name) == 0) {
            return child;
        }
    }
    return NULL;
}

static bool
cep_enclave_policy_security_make_beat_name(cepDT* out_name, cepBeatNumber beat)
{
    if (!out_name) {
        return false;
    }
    cepBeatNumber effective = (beat == CEP_BEAT_INVALID) ? 0u : beat;
    cepID numeric = (cepID)((effective % CEP_AUTOID_MAXVAL) + 1u);
    out_name->domain = CEP_ACRO("CEP");
    out_name->tag = cep_id_to_numeric(numeric);
    out_name->glob = 0u;
    return true;
}

static void
cep_enclave_policy_security_record_beat(uint64_t allow_delta,
                                        uint64_t deny_delta,
                                        uint64_t limit_delta)
{
    if (allow_delta == 0u && deny_delta == 0u && limit_delta == 0u) {
        return;
    }
    cepCell* analytics = cep_enclave_policy_security_analytics_root();
    if (!analytics) {
        return;
    }
    cepCell* beats = cep_enclave_policy_security_ensure_branch(analytics, dt_sec_analytics_beats_name());
    if (!beats) {
        return;
    }
    cepBeatNumber beat = cep_beat_index();
    if (beat == CEP_BEAT_INVALID) {
        beat = cep_heartbeat_current();
    }
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }
    cepDT beat_name = {0};
    if (!cep_enclave_policy_security_make_beat_name(&beat_name, beat)) {
        return;
    }
    cepCell* entry = cep_enclave_policy_security_ensure_branch(beats, &beat_name);
    if (!entry) {
        return;
    }
    if (allow_delta) {
        (void)cep_enclave_policy_security_increment_counter(entry, dt_sec_allow_field(), allow_delta);
    }
    if (deny_delta) {
        (void)cep_enclave_policy_security_increment_counter(entry, dt_sec_deny_field(), deny_delta);
    }
    if (limit_delta) {
        (void)cep_enclave_policy_security_increment_counter(entry, dt_sec_limits_field(), limit_delta);
    }
}

static const char*
cep_enclave_policy_normalize_label(const char* text, const char* fallback)
{
    return (text && *text) ? text : fallback;
}

static void
cep_enclave_policy_security_record_edge(const char* from_enclave,
                                        const char* to_enclave,
                                        const char* gateway_id,
                                        bool allowed)
{
    cepCell* analytics = cep_enclave_policy_security_analytics_root();
    if (!analytics) {
        return;
    }

    const char* from_label = cep_enclave_policy_normalize_label(from_enclave, "enclave:<unknown>");
    const char* to_label = cep_enclave_policy_normalize_label(to_enclave, "enclave:<unknown>");
    const char* gateway_label = cep_enclave_policy_normalize_label(gateway_id, "gateway:<unknown>");

    cepCell* edges = cep_enclave_policy_security_ensure_branch(analytics, dt_sec_edges_name());
    if (edges) {
        cepCell* from_cell = cep_enclave_policy_security_ensure_named_child(edges, from_label);
        if (from_cell) {
            cepCell* to_cell = cep_enclave_policy_security_ensure_named_child(from_cell, to_label);
            if (to_cell) {
                (void)cep_enclave_policy_security_increment_counter(to_cell,
                                                                    allowed ? dt_sec_allow_field()
                                                                            : dt_sec_deny_field(),
                                                                    1u);
            }
        }
    }

    cepCell* gateways = cep_enclave_policy_security_ensure_branch(analytics, dt_sec_gateways_name());
    if (gateways) {
        cepCell* gateway_cell = cep_enclave_policy_security_ensure_named_child(gateways, gateway_label);
        if (gateway_cell) {
            (void)cep_enclave_policy_security_increment_counter(gateway_cell,
                                                                allowed ? dt_sec_allow_field()
                                                                        : dt_sec_deny_field(),
                                                                1u);
        }
    }

    cep_enclave_policy_security_record_beat(allowed ? 1u : 0u,
                                            allowed ? 0u : 1u,
                                            0u);
}

static void
cep_enclave_policy_branch_dispose(cepEnclaveBranchTable* table)
{
    if (!table || !table->entries) {
        return;
    }
    for (size_t i = 0; i < table->count; ++i) {
        cepEnclaveBranchEntry* entry = &table->entries[i];
        if (entry->rules) {
            for (size_t r = 0; r < entry->rule_count; ++r) {
                cepEnclaveBranchRule* rule = &entry->rules[r];
                if (rule->pack_ids) {
                    cep_free(rule->pack_ids);
                    rule->pack_ids = NULL;
                }
                if (rule->rule_id) {
                    cep_free(rule->rule_id);
                    rule->rule_id = NULL;
                }
            }
            cep_free(entry->rules);
            entry->rules = NULL;
        }
        if (entry->path_pattern) {
            cep_free(entry->path_pattern);
            entry->path_pattern = NULL;
        }
        if (entry->enclave_label) {
            cep_free(entry->enclave_label);
            entry->enclave_label = NULL;
        }
        entry->rule_count = 0u;
        entry->default_allow = false;
    }
    cep_free(table->entries);
    table->entries = NULL;
    table->count = 0u;
}

static void
cep_enclave_policy_snapshot_dispose(cepEnclavePolicySnapshot* snapshot)
{
    if (!snapshot) {
        return;
    }
    if (snapshot->enclaves) {
        cep_free(snapshot->enclaves);
        snapshot->enclaves = NULL;
    }
    snapshot->enclave_count = 0u;
    cep_enclave_policy_branch_dispose(&snapshot->branches);
}

static bool
cep_enclave_policy_read_text(cepCell* parent,
                             const cepDT* field,
                             char* buffer,
                             size_t capacity)
{
    if (!parent || !field || !buffer || capacity == 0u) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&node, &data)) {
        return false;
    }
    const char* payload = (const char*)cep_data_payload(data);
    if (!payload || data->size == 0u) {
        return false;
    }
    size_t length = data->size;
    if (length >= capacity) {
        length = capacity - 1u;
    }
    memcpy(buffer, payload, length);
    buffer[length] = '\0';
    return true;
}

static char*
cep_enclave_policy_dup_text_node(cepCell* parent, const cepDT* field)
{
    if (!parent || !field) {
        return NULL;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return NULL;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        return NULL;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&node, &data)) {
        return NULL;
    }
    const char* payload = (const char*)cep_data_payload(data);
    if (!payload || data->size == 0u) {
        return NULL;
    }
    size_t length = data->size;
    char* copy = cep_malloc(length + 1u);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, payload, length);
    copy[length] = '\0';
    return copy;
}

static void
cep_enclave_policy_trim(char* text)
{
    if (!text) {
        return;
    }
    size_t len = strlen(text);
    while (len > 0u && isspace((unsigned char)text[len - 1u])) {
        text[--len] = '\0';
    }
    size_t start = 0u;
    while (text[start] && isspace((unsigned char)text[start])) {
        ++start;
    }
    if (start) {
        memmove(text, &text[start], strlen(&text[start]) + 1u);
    }
}

static char*
cep_enclave_policy_strdup(const char* text)
{
    if (!text) {
        return NULL;
    }
    size_t length = strlen(text);
    char* copy = cep_malloc(length + 1u);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, text, length + 1u);
    return copy;
}

static bool
cep_enclave_policy_read_u64(cepCell* parent, const cepDT* field, uint64_t* out_value)
{
    if (!parent || !field || !out_value) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node) {
        return false;
    }
    node = cep_cell_resolve(node);
    if (!node) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&node, &data)) {
        return false;
    }
    const void* payload = cep_data_payload(data);
    if (!payload) {
        return false;
    }
    if (data->size == sizeof(uint64_t)) {
        memcpy(out_value, payload, sizeof(uint64_t));
        return true;
    }
    if (data->size == sizeof(uint32_t)) {
        uint32_t temp = 0u;
        memcpy(&temp, payload, sizeof(uint32_t));
        *out_value = temp;
        return true;
    }
    return false;
}

static size_t
cep_enclave_policy_count_children(cepCell* dictionary)
{
    size_t count = 0u;
    if (!dictionary) {
        return count;
    }
    for (cepCell* child = cep_cell_first(dictionary);
         child;
         child = cep_cell_next(dictionary, child)) {
        ++count;
    }
    return count;
}

typedef struct {
    size_t count;
    char   storage[CEP_ENCLAVE_BRANCH_PATH_MAX];
    char*  segments[CEP_ENCLAVE_BRANCH_SEGMENT_MAX];
} cepEnclaveBranchPathTokens;

static bool
cep_enclave_policy_tokenize_path(const char* text,
                                 cepEnclaveBranchPathTokens* tokens)
{
    if (!text || !tokens) {
        return false;
    }
    memset(tokens, 0, sizeof *tokens);
    size_t length = strnlen(text, CEP_ENCLAVE_BRANCH_PATH_MAX);
    if (length >= CEP_ENCLAVE_BRANCH_PATH_MAX) {
        return false;
    }
    memcpy(tokens->storage, text, length);
    tokens->storage[length] = '\0';
    size_t index = 0u;
    char* cursor = tokens->storage;
    while (*cursor && index < CEP_ENCLAVE_BRANCH_SEGMENT_MAX) {
        while (*cursor == '/') {
            ++cursor;
        }
        if (!*cursor) {
            break;
        }
        tokens->segments[index++] = cursor;
        while (*cursor && *cursor != '/') {
            ++cursor;
        }
        if (*cursor == '/') {
            *cursor = '\0';
            ++cursor;
        }
    }
    tokens->count = index;
    return true;
}

static bool
cep_enclave_policy_segment_matches(const char* pattern,
                                   const char* candidate)
{
    if (!pattern || !candidate) {
        return false;
    }
    if (strcmp(pattern, "*") == 0) {
        return true;
    }
    size_t plen = strlen(pattern);
    size_t clen = strlen(candidate);
    return cep_word_glob_match_text(pattern, plen, candidate, clen);
}

static bool
cep_enclave_policy_match_tokens(const cepEnclaveBranchPathTokens* pattern,
                                const cepEnclaveBranchPathTokens* subject,
                                size_t pi,
                                size_t si)
{
    if (pi >= pattern->count) {
        return si == subject->count;
    }
    const char* segment = pattern->segments[pi];
    if (segment && strcmp(segment, "**") == 0) {
        if (pi + 1u >= pattern->count) {
            return true;
        }
        for (size_t skip = si; skip <= subject->count; ++skip) {
            if (cep_enclave_policy_match_tokens(pattern, subject, pi + 1u, skip)) {
                return true;
            }
        }
        return false;
    }
    if (si >= subject->count) {
        return false;
    }
    if (!cep_enclave_policy_segment_matches(segment, subject->segments[si])) {
        return false;
    }
    return cep_enclave_policy_match_tokens(pattern, subject, pi + 1u, si + 1u);
}

static bool
cep_enclave_policy_path_matches(const char* pattern_text,
                                const char* path_text)
{
    if (!pattern_text || !path_text) {
        return false;
    }
    cepEnclaveBranchPathTokens pattern = {0};
    cepEnclaveBranchPathTokens path = {0};
    if (!cep_enclave_policy_tokenize_path(pattern_text, &pattern)) {
        return false;
    }
    if (!cep_enclave_policy_tokenize_path(path_text, &path)) {
        return false;
    }
    return cep_enclave_policy_match_tokens(&pattern, &path, 0u, 0u);
}

static bool
cep_enclave_policy_parse_enclaves(cepCell* security_root,
                                  cepEnclavePolicySnapshot* next)
{
    if (!security_root || !next) {
        return false;
    }
    cepCell* enclaves = cep_cell_find_by_name(security_root, dt_sec_enclaves_name());
    if (!enclaves) {
        next->enclaves = NULL;
        next->enclave_count = 0u;
        return true;
    }
    enclaves = cep_cell_resolve(enclaves);
    if (!enclaves) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&enclaves)) {
        return false;
    }

    size_t count = cep_enclave_policy_count_children(enclaves);
    if (count == 0u) {
        next->enclaves = NULL;
        next->enclave_count = 0u;
        return true;
    }

    cepEnclaveDescriptor* descriptors =
        cep_malloc0(count * sizeof *descriptors);
    if (!descriptors) {
        return false;
    }

    size_t index = 0u;
    for (cepCell* child = cep_cell_first(enclaves);
         child && index < count;
         child = cep_cell_next(enclaves, child)) {
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved) {
            continue;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            continue;
        }
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name) {
            continue;
        }
        descriptors[index].name = *name;
        memset(descriptors[index].trust_tier, 0, CEP_ENCLAVE_POLICY_TIER_MAX);
        if (!cep_enclave_policy_read_text(resolved,
                                          dt_sec_tier_field(),
                                          descriptors[index].trust_tier,
                                          CEP_ENCLAVE_POLICY_TIER_MAX)) {
            (void)cep_enclave_policy_read_text(resolved,
                                               dt_sec_trust_field(),
                                               descriptors[index].trust_tier,
                                               CEP_ENCLAVE_POLICY_TIER_MAX);
        }
        ++index;
    }

    next->enclaves = descriptors;
    next->enclave_count = index;
    return true;
}

static uint32_t
cep_enclave_policy_verb_bit(const char* text)
{
    if (!text) {
        return 0u;
    }
    if (strcasecmp(text, "read") == 0) {
        return CEP_ENCLAVE_VERB_READ;
    }
    if (strcasecmp(text, "write") == 0) {
        return CEP_ENCLAVE_VERB_WRITE;
    }
    if (strcasecmp(text, "execute") == 0) {
        return CEP_ENCLAVE_VERB_EXECUTE;
    }
    if (strcasecmp(text, "link") == 0) {
        return CEP_ENCLAVE_VERB_LINK;
    }
    if (strcasecmp(text, "delete") == 0) {
        return CEP_ENCLAVE_VERB_DELETE;
    }
    return 0u;
}

static uint32_t
cep_enclave_policy_parse_verb_mask(cepCell* verbs_root)
{
    if (!verbs_root) {
        return 0u;
    }
    cepCell* resolved = cep_cell_resolve(verbs_root);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return 0u;
    }
    uint32_t mask = 0u;
    for (cepCell* child = cep_cell_first(resolved);
         child;
         child = cep_cell_next(resolved, child)) {
        cepCell* value = cep_cell_resolve(child);
        if (!value || !cep_cell_has_data(value)) {
            continue;
        }
        cepData* data = value->data;
        if (!data) {
            continue;
        }
        char buffer[32];
        size_t length = data->size;
        if (length >= sizeof buffer) {
            length = sizeof buffer - 1u;
        }
        memcpy(buffer, cep_data_payload(data), length);
        buffer[length] = '\0';
        cep_enclave_policy_trim(buffer);
        mask |= cep_enclave_policy_verb_bit(buffer);
    }
    return mask;
}

static bool
cep_enclave_policy_parse_subject_packs(cepCell* subjects_root,
                                       cepEnclaveBranchRule* rule)
{
    if (!subjects_root || !rule) {
        return true;
    }
    cepCell* resolved = cep_cell_resolve(subjects_root);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }
    cepCell* packs = cep_cell_find_by_name(resolved, dt_sec_rule_subject_packs_name());
    if (!packs) {
        return true;
    }
    packs = cep_cell_resolve(packs);
    if (!packs || !cep_cell_require_dictionary_store(&packs)) {
        return false;
    }
    size_t count = cep_enclave_policy_count_children(packs);
    if (!count) {
        return true;
    }
    cepID* ids = cep_malloc0(count * sizeof *ids);
    if (!ids) {
        return false;
    }
    size_t index = 0u;
    for (cepCell* child = cep_cell_first(packs);
         child && index < count;
         child = cep_cell_next(packs, child)) {
        cepCell* value = cep_cell_resolve(child);
        if (!value || !cep_cell_has_data(value)) {
            continue;
        }
        cepData* data = value->data;
        if (!data) {
            continue;
        }
        char buffer[CEP_ENCLAVE_SUBJECT_NAME_MAX];
        size_t length = data->size;
        if (length >= sizeof buffer) {
            length = sizeof buffer - 1u;
        }
        memcpy(buffer, cep_data_payload(data), length);
        buffer[length] = '\0';
        cep_enclave_policy_trim(buffer);
        if (!buffer[0]) {
            continue;
        }
        ids[index++] = cep_namepool_intern_cstr(buffer);
    }
    rule->pack_ids = ids;
    rule->pack_count = index;
    return true;
}

static char*
cep_enclave_policy_auto_rule_id(const char* path,
                                size_t entry_index,
                                size_t rule_index)
{
    if (!path) {
        path = "<path>";
    }
    char buffer[CEP_ENCLAVE_RULE_ID_MAX];
    int written = snprintf(buffer,
                           sizeof buffer,
                           "%s#r%zu",
                           path,
                           rule_index);
    if (written < 0) {
        return NULL;
    }
    if ((size_t)written >= sizeof buffer) {
        buffer[sizeof buffer - 1u] = '\0';
    }
    return cep_enclave_policy_strdup(buffer);
}

static bool
cep_enclave_policy_parse_branch_rule(cepCell* rule_cell,
                                     cepEnclaveBranchRule* rule,
                                     const char* path,
                                     size_t entry_index,
                                     size_t rule_index)
{
    if (!rule_cell || !rule) {
        return false;
    }
    cepCell* resolved = cep_cell_resolve(rule_cell);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }
    char* decision = cep_enclave_policy_dup_text_node(resolved, dt_sec_rule_decision_field());
    if (decision) {
        cep_enclave_policy_trim(decision);
    }
    rule->allow = decision && strcasecmp(decision, "allow") == 0;
    if (decision) {
        cep_free(decision);
    }
    cepCell* verbs = cep_cell_find_by_name(resolved, dt_sec_rule_verbs_name());
    rule->verbs_mask = cep_enclave_policy_parse_verb_mask(verbs);
    cepCell* subjects = cep_cell_find_by_name(resolved, dt_sec_rule_subjects_name());
    if (!cep_enclave_policy_parse_subject_packs(subjects, rule)) {
        return false;
    }
    char* explicit_id = cep_enclave_policy_dup_text_node(resolved, dt_sec_rule_id_field());
    if (explicit_id) {
        cep_enclave_policy_trim(explicit_id);
        if (explicit_id[0]) {
            rule->rule_id = explicit_id;
        } else {
            cep_free(explicit_id);
            explicit_id = NULL;
        }
    } else {
        rule->rule_id = cep_enclave_policy_auto_rule_id(path, entry_index, rule_index);
    }
    if (!rule->rule_id) {
        return false;
    }
    return true;
}

static char*
cep_enclave_policy_normalize_path(char* path_text)
{
    if (!path_text) {
        return NULL;
    }
    cep_enclave_policy_trim(path_text);
    if (path_text[0] == '/') {
        return path_text;
    }
    size_t length = strlen(path_text);
    char* normalized = cep_malloc(length + 2u);
    if (!normalized) {
        cep_free(path_text);
        return NULL;
    }
    normalized[0] = '/';
    memcpy(&normalized[1], path_text, length + 1u);
    cep_free(path_text);
    return normalized;
}

static bool
cep_enclave_policy_parse_branch_entry(cepCell* entry_cell,
                                      cepEnclaveBranchEntry* entry,
                                      size_t entry_index)
{
    if (!entry_cell || !entry) {
        return false;
    }
    cepCell* resolved = cep_cell_resolve(entry_cell);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }
    entry->enclave_label = cep_enclave_policy_dup_text_node(resolved, dt_sec_branch_enclave_field());
    if (entry->enclave_label) {
        cep_enclave_policy_trim(entry->enclave_label);
    }
    char* path = cep_enclave_policy_dup_text_node(resolved, dt_sec_branch_path_field());
    entry->path_pattern = cep_enclave_policy_normalize_path(path);
    if (!entry->path_pattern) {
        return false;
    }
    char* default_decision = cep_enclave_policy_dup_text_node(resolved, dt_sec_branch_default_field());
    if (default_decision) {
        cep_enclave_policy_trim(default_decision);
    }
    entry->default_allow = default_decision && strcasecmp(default_decision, "allow") == 0;
    if (default_decision) {
        cep_free(default_decision);
    }
    cepCell* rules_root = cep_cell_find_by_name(resolved, dt_sec_branch_rules_name());
    if (!rules_root) {
        entry->rules = NULL;
        entry->rule_count = 0u;
        return true;
    }
    rules_root = cep_cell_resolve(rules_root);
    if (!rules_root || !cep_cell_require_dictionary_store(&rules_root)) {
        return false;
    }
    size_t rule_count = cep_enclave_policy_count_children(rules_root);
    if (!rule_count) {
        entry->rules = NULL;
        entry->rule_count = 0u;
        return true;
    }
    cepEnclaveBranchRule* rules = cep_malloc0(rule_count * sizeof *rules);
    if (!rules) {
        return false;
    }
    size_t index = 0u;
    for (cepCell* child = cep_cell_first(rules_root);
         child && index < rule_count;
         child = cep_cell_next(rules_root, child)) {
        if (!cep_enclave_policy_parse_branch_rule(child,
                                                  &rules[index],
                                                  entry->path_pattern,
                                                  entry_index,
                                                  index)) {
            cep_free(rules);
            return false;
        }
        ++index;
    }
    entry->rules = rules;
    entry->rule_count = index;
    return true;
}

static bool
cep_enclave_policy_parse_branches(cepCell* security_root,
                                  cepEnclavePolicySnapshot* next)
{
    if (!security_root || !next) {
        return false;
    }
    cepCell* branches = cep_cell_find_by_name(security_root, dt_sec_branches_name());
    if (!branches) {
        next->branches.entries = NULL;
        next->branches.count = 0u;
        return true;
    }
    branches = cep_cell_resolve(branches);
    if (!branches || !cep_cell_require_dictionary_store(&branches)) {
        return false;
    }
    size_t count = cep_enclave_policy_count_children(branches);
    if (!count) {
        next->branches.entries = NULL;
        next->branches.count = 0u;
        return true;
    }
    cepEnclaveBranchEntry* entries = cep_malloc0(count * sizeof *entries);
    if (!entries) {
        return false;
    }
    size_t index = 0u;
    for (cepCell* child = cep_cell_first(branches);
         child && index < count;
         child = cep_cell_next(branches, child)) {
        if (!cep_enclave_policy_parse_branch_entry(child, &entries[index], index)) {
            cepEnclaveBranchTable temp = {
                .entries = entries,
                .count = index,
            };
            cep_enclave_policy_branch_dispose(&temp);
            return false;
        }
        ++index;
    }
    next->branches.entries = entries;
    next->branches.count = index;
    return true;
}

static void
cep_enclave_policy_parse_rate(cepCell* rate_root,
                              cepEnclavePolicySnapshot* next)
{
    if (!rate_root || !next) {
        return;
    }
    uint64_t value = 0u;
    if (cep_enclave_policy_read_u64(rate_root, dt_sec_rate_subject_name(), &value)) {
        next->defaults.rate_per_subject_qps = (uint32_t)value;
    }
    if (cep_enclave_policy_read_u64(rate_root, dt_sec_rate_enzyme_name(), &value)) {
        next->defaults.rate_per_enzyme_qps = (uint32_t)value;
    }
    if (cep_enclave_policy_read_u64(rate_root, dt_sec_rate_edge_name(), &value)) {
        next->defaults.rate_per_edge_qps = (uint32_t)value;
    }
}

static void
cep_enclave_policy_parse_ttl(cepCell* ttl_root,
                             cepEnclavePolicySnapshot* next)
{
    if (!ttl_root || !next) {
        return;
    }
    uint64_t value = 0u;
    if (cep_enclave_policy_read_u64(ttl_root, dt_sec_mailbox_beats_name(), &value)) {
        next->defaults.mailbox_max_beats = (uint32_t)value;
    }
    if (cep_enclave_policy_read_u64(ttl_root, dt_sec_episode_beats_name(), &value)) {
        next->defaults.episode_max_beats = (uint32_t)value;
    }
}

static void
cep_enclave_policy_parse_budgets(cepCell* budgets_root,
                                 cepEnclavePolicySnapshot* next)
{
    if (!budgets_root || !next) {
        return;
    }
    uint64_t value = 0u;
    if (cep_enclave_policy_read_u64(budgets_root, dt_sec_bud_cpu_name(), &value)) {
        next->defaults.bud_cpu_ns = value;
    }
    if (cep_enclave_policy_read_u64(budgets_root, dt_sec_bud_io_name(), &value)) {
        next->defaults.bud_io_bytes = value;
    }
    if (cep_enclave_policy_read_u64(budgets_root, dt_sec_max_beats_name(), &value)) {
        next->defaults.max_beats = (uint32_t)value;
    }
}

static void
cep_enclave_policy_parse_defaults(cepCell* security_root,
                                  cepEnclavePolicySnapshot* next)
{
    if (!security_root || !next) {
        return;
    }
    cepCell* defaults = cep_cell_find_by_name(security_root, dt_sec_defaults_name());
    if (!defaults) {
        return;
    }
    defaults = cep_cell_resolve(defaults);
    if (!defaults) {
        return;
    }
    if (!cep_cell_require_dictionary_store(&defaults)) {
        return;
    }

    cepCell* budgets = cep_cell_find_by_name(defaults, dt_sec_budgets_name());
    if (budgets) {
        budgets = cep_cell_resolve(budgets);
        if (budgets && cep_cell_require_dictionary_store(&budgets)) {
            cep_enclave_policy_parse_budgets(budgets, next);
        }
    }

    cepCell* ttl = cep_cell_find_by_name(defaults, dt_sec_ttl_name());
    if (ttl) {
        ttl = cep_cell_resolve(ttl);
        if (ttl && cep_cell_require_dictionary_store(&ttl)) {
            cep_enclave_policy_parse_ttl(ttl, next);
        }
    }

    cepCell* rate = cep_cell_find_by_name(defaults, dt_sec_rate_name());
    if (rate) {
        rate = cep_cell_resolve(rate);
        if (rate && cep_cell_require_dictionary_store(&rate)) {
            cep_enclave_policy_parse_rate(rate, next);
        }
    }
}

static void
cep_enclave_policy_parse_pipeline(cepCell* security_root,
                                  cepEnclavePolicySnapshot* next)
{
    if (!security_root || !next) {
        return;
    }
    cepCell* pipeline = cep_cell_find_by_name(security_root, dt_sec_pipeline_name());
    if (!pipeline) {
        return;
    }
    pipeline = cep_cell_resolve(pipeline);
    if (!pipeline) {
        return;
    }
    if (!cep_cell_require_dictionary_store(&pipeline)) {
        return;
    }

    uint64_t value = 0u;
    if (cep_enclave_policy_read_u64(pipeline, dt_sec_total_cpu_name(), &value)) {
        next->pipeline.total_cpu_ns = value;
    }
    if (cep_enclave_policy_read_u64(pipeline, dt_sec_total_io_name(), &value)) {
        next->pipeline.total_io_bytes = value;
    }
    if (cep_enclave_policy_read_u64(pipeline, dt_sec_max_hops_name(), &value)) {
        next->pipeline.max_hops = (uint32_t)value;
    }
    if (cep_enclave_policy_read_u64(pipeline, dt_sec_max_wall_ms_name(), &value)) {
        next->pipeline.max_wall_ms = (uint32_t)value;
    }
}

bool
cep_enclave_policy_reload(cepCell* security_root)
{
    if (!security_root) {
        g_enclave_policy.ready = false;
        cep_enclave_policy_publish_fault("security policy root missing");
        return false;
    }
    cepCell* resolved = cep_cell_resolve(security_root);
    if (!resolved) {
        g_enclave_policy.ready = false;
        cep_enclave_policy_publish_fault("security policy unresolved");
        return false;
    }
    if (!cep_cell_require_dictionary_store(&resolved)) {
        g_enclave_policy.ready = false;
        cep_enclave_policy_publish_fault("security policy storage invalid");
        return false;
    }
    g_enclave_policy.security_root = resolved;
    cep_enclave_policy_publish_state("loading",
                                     "security policy reloading",
                                     NULL,
                                     g_enclave_policy.snapshot.version);

    cepEnclavePolicySnapshot next = {0};
    next.version = g_enclave_policy.snapshot.version + 1u;

    if (!cep_enclave_policy_parse_enclaves(resolved, &next)) {
        cep_enclave_policy_snapshot_dispose(&next);
        g_enclave_policy.ready = false;
        cep_enclave_policy_publish_fault("security enclaves parse failure");
        return false;
    }
    cep_enclave_policy_parse_defaults(resolved, &next);
    cep_enclave_policy_parse_pipeline(resolved, &next);
    if (!cep_enclave_policy_parse_branches(resolved, &next)) {
        cep_enclave_policy_snapshot_dispose(&next);
        g_enclave_policy.ready = false;
        cep_enclave_policy_publish_fault("security branch policy parse failure");
        return false;
    }

    cep_enclave_policy_snapshot_dispose(&g_enclave_policy.snapshot);
    g_enclave_policy.snapshot = next;
    g_enclave_policy.ready = true;
    cep_enclave_policy_publish_state("ready",
                                     "security policy ready",
                                     NULL,
                                     g_enclave_policy.snapshot.version);
    return true;
}

bool
cep_enclave_policy_init(cepCell* security_root)
{
    g_enclave_policy.security_root = security_root ? cep_cell_resolve(security_root) : NULL;
    g_enclave_policy.dirty = true;
    if (!g_enclave_policy.security_root) {
        g_enclave_policy.ready = false;
        cep_enclave_policy_publish_fault("security policy root missing");
        return false;
    }
    cep_enclave_policy_publish_state("loading",
                                     "security policy initializing",
                                     NULL,
                                     g_enclave_policy.snapshot.version);
    bool ok = cep_enclave_policy_reload(g_enclave_policy.security_root);
    g_enclave_policy.dirty = false;
    return ok;
}

const cepEnclavePolicySnapshot*
cep_enclave_policy_snapshot(void)
{
    if (!g_enclave_policy.ready) {
        return NULL;
    }
    return &g_enclave_policy.snapshot;
}

bool
cep_enclave_policy_lookup_enclave(const cepDT* name,
                                  cepEnclaveDescriptor* out_descriptor)
{
    if (!name || !out_descriptor) {
        return false;
    }
    if (!g_enclave_policy.ready) {
        return false;
    }
    const cepEnclavePolicySnapshot* snapshot = cep_enclave_policy_snapshot();
    if (!snapshot || snapshot->enclave_count == 0u) {
        return false;
    }
    for (size_t i = 0; i < snapshot->enclave_count; ++i) {
        if (cep_dt_compare(&snapshot->enclaves[i].name, name) == 0) {
            *out_descriptor = snapshot->enclaves[i];
            return true;
        }
    }
    return false;
}

const cepEnclavePolicyLimits*
cep_enclave_policy_defaults(void)
{
    if (!g_enclave_policy.ready) {
        return NULL;
    }
    return &g_enclave_policy.snapshot.defaults;
}

const cepEnclavePipelineCeilings*
cep_enclave_policy_pipeline(void)
{
    if (!g_enclave_policy.ready) {
        return NULL;
    }
    return &g_enclave_policy.snapshot.pipeline;
}

void
cep_enclave_policy_mark_dirty(void)
{
    cep_enclave_policy_mark_dirty_reason(NULL, NULL);
}

void
cep_enclave_policy_mark_dirty_reason(const char* reason, const cepCell* source_cell)
{
    char detail[256];
    const char* source = reason ? reason : "<unspecified>";
    char path_buf[512];
    path_buf[0] = '\0';
    if (source_cell) {
        cep_enclave_policy_trace_format_path(source_cell, path_buf, sizeof path_buf);
    }
    if (path_buf[0] != '\0') {
        snprintf(detail,
                 sizeof detail,
                 "dirty_before=%u source=%s path=%s",
                 g_enclave_policy.dirty ? 1u : 0u,
                 source,
                 path_buf);
    } else {
        snprintf(detail,
                 sizeof detail,
                 "dirty_before=%u source=%s",
                 g_enclave_policy.dirty ? 1u : 0u,
                 source);
    }
    if (cep_enclave_policy_is_frozen()) {
        g_enclave_policy.pending_dirty = true;
        cep_enclave_policy_trace_log("mark_dirty_pending", detail, true);
        return;
    }
    cep_enclave_policy_trace_log("mark_dirty", detail, true);
    g_enclave_policy.dirty = true;
}

void
cep_enclave_policy_on_capture(void)
{
    if (!g_enclave_policy.security_root) {
        cep_enclave_policy_trace_log("capture_skip_no_root", NULL, false);
        return;
    }
    if (!g_enclave_policy.dirty) {
        cep_enclave_policy_trace_log("capture_skip_clean", NULL, false);
        return;
    }
    if (cep_enclave_policy_is_frozen()) {
        cep_enclave_policy_trace_log("capture_skip_frozen", NULL, false);
        return;
    }
    cep_enclave_policy_trace_log("reload_begin", NULL, false);
    if (!cep_enclave_policy_reload(g_enclave_policy.security_root)) {
        g_enclave_policy.ready = false;
        cep_enclave_policy_trace_log("reload_fail", NULL, false);
    } else {
        cep_enclave_policy_trace_log("reload_complete", NULL, false);
    }
    g_enclave_policy.dirty = false;
}

bool
cep_enclave_policy_ready(void)
{
    return g_enclave_policy.ready;
}

static bool
cep_enclave_policy_has_enclave_label(const char* label)
{
    if (!label || !*label) {
        return false;
    }
    if (!g_enclave_policy.ready) {
        return false;
    }
    const cepEnclavePolicySnapshot* snapshot = cep_enclave_policy_snapshot();
    if (!snapshot || snapshot->enclave_count == 0u) {
        return false;
    }
    cepDT needle = cep_ops_make_dt(label);
    for (size_t i = 0; i < snapshot->enclave_count; ++i) {
        if (cep_dt_compare(&snapshot->enclaves[i].name, &needle) == 0) {
            return true;
        }
    }
    return false;
}

static cepCell*
cep_enclave_policy_decisions_root(void)
{
    cepCell* journal = cep_heartbeat_journal_root();
    if (!journal) {
        return NULL;
    }
    cepCell* decisions = cep_cell_ensure_dictionary_child(journal,
                                                          CEP_DTAW("CEP", "decisions"),
                                                          CEP_STORAGE_RED_BLACK_T);
    if (!decisions) {
        return NULL;
    }
    return cep_cell_ensure_dictionary_child(decisions,
                                            CEP_DTAW("CEP", "sec"),
                                            CEP_STORAGE_RED_BLACK_T);
}

static void
cep_enclave_policy_append_edge_denial(const char* from_enclave,
                                      const char* to_enclave,
                                      const char* gateway_id,
                                      const char* subject_id,
                                      const char* reason)
{
    cepCell* root = cep_enclave_policy_decisions_root();
    if (!root) {
        return;
    }
    cepDT auto_name = {
        .domain = CEP_ACRO("CEP"),
        .tag = CEP_AUTOID,
    };
    cepCell* entry = cep_cell_add_dictionary(root,
                                             &auto_name,
                                             0,
                                             CEP_DTAW("CEP", "dictionary"),
                                             CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        return;
    }
    if (from_enclave) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "from"), from_enclave);
    }
    if (to_enclave) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "to"), to_enclave);
    }
    if (gateway_id) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "gateway"), gateway_id);
    }
    if (subject_id) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "subject"), subject_id);
    }
    if (reason) {
        (void)cep_cell_put_text(entry, CEP_DTAW("CEP", "reason"), reason);
    }
    cepBeatNumber beat = cep_beat_index();
    uint64_t beat_number = (beat == CEP_BEAT_INVALID) ? 0u : (uint64_t)beat;
    (void)cep_cell_put_uint64(entry, CEP_DTAW("CEP", "beat"), beat_number);
}

static void
cep_enclave_policy_emit_edge_denial(const char* from_enclave,
                                    const char* to_enclave,
                                    const char* gateway_id,
                                    const char* subject_id,
                                    const char* reason)
{
    char note[256] = {0};
    const char* from_text = from_enclave ? from_enclave : "<none>";
    const char* to_text = to_enclave ? to_enclave : "<none>";
    const char* gateway_text = gateway_id ? gateway_id : "<none>";
    const char* subject_text = subject_id ? subject_id : "<none>";
    const char* reason_text = reason ? reason : "unspecified";
    snprintf(note,
             sizeof note,
             "from=%s to=%s gateway=%s subject=%s reason=%s",
             from_text,
             to_text,
             gateway_text,
             subject_text,
             reason_text);

    cepCeiRequest req = {
        .severity = cep_ops_make_dt("sev/warn"),
        .topic = "sec.edge.deny",
        .topic_intern = true,
        .note = note,
        .note_len = 0u,
        .mailbox_root = cep_cei_diagnostics_mailbox(),
        .emit_signal = true,
        .attach_to_op = false,
        .ttl_forever = true,
    };
    (void)cep_cei_emit(&req);
}

bool
cep_enclave_policy_check_edge(const char* from_enclave,
                              const char* to_enclave,
                              const char* gateway_id,
                              cepEnclavePolicyLimits* resolved_limits,
                              char* deny_reason,
                              size_t deny_capacity)
{
    if (resolved_limits) {
        memset(resolved_limits, 0, sizeof *resolved_limits);
    }
    if (deny_reason && deny_capacity) {
        deny_reason[0] = '\0';
    }
    if (!from_enclave || !*from_enclave ||
        !to_enclave || !*to_enclave ||
        !gateway_id || !*gateway_id) {
        if (deny_reason && deny_capacity) {
            snprintf(deny_reason, deny_capacity, "missing enclave identifiers");
        }
        return false;
    }
    if (!cep_enclave_policy_ready()) {
        if (deny_reason && deny_capacity) {
            snprintf(deny_reason, deny_capacity, "enclave policy not ready");
        }
        return false;
    }
    const cepEnclavePolicySnapshot* snapshot = cep_enclave_policy_snapshot();
    bool allow_all_enclaves = snapshot && snapshot->enclave_count == 0u;
    if (!allow_all_enclaves && !cep_enclave_policy_has_enclave_label(from_enclave)) {
        if (deny_reason && deny_capacity) {
            snprintf(deny_reason, deny_capacity, "source enclave '%s' not registered", from_enclave);
        }
        return false;
    }
    if (!allow_all_enclaves && !cep_enclave_policy_has_enclave_label(to_enclave)) {
        if (deny_reason && deny_capacity) {
            snprintf(deny_reason, deny_capacity, "target enclave '%s' not registered", to_enclave);
        }
        return false;
    }
    const cepEnclavePolicyLimits* defaults = cep_enclave_policy_defaults();
    if (resolved_limits && defaults) {
        *resolved_limits = *defaults;
    }
    (void)gateway_id; /* TODO: evaluate gateway-specific rules when edges are parsed. */
    return true;
}

void
cep_enclave_policy_record_edge_denial(const char* from_enclave,
                                      const char* to_enclave,
                                      const char* gateway_id,
                                      const char* subject_id,
                                      const char* reason)
{
    cep_enclave_policy_emit_edge_denial(from_enclave,
                                        to_enclave,
                                        gateway_id,
                                        subject_id,
                                        reason);
    cep_enclave_policy_append_edge_denial(from_enclave,
                                          to_enclave,
                                          gateway_id,
                                          subject_id,
                                          reason);
    cep_enclave_policy_security_record_edge(from_enclave,
                                            to_enclave,
                                            gateway_id,
                                            false);
}

cepEnclaveBranchResult
cep_enclave_policy_check_branch(const char* path_text,
                                cepID subject_pack,
                                uint32_t verb_mask,
                                cepEnclaveBranchDecision* decision,
                                char* deny_reason,
                                size_t deny_capacity)
{
    if (decision) {
        decision->path_pattern = NULL;
        decision->rule_id = NULL;
    }
    if (!cep_enclave_policy_ready()) {
        return CEP_ENCLAVE_BRANCH_RESULT_SKIP;
    }
    if (!path_text || !*path_text) {
        return CEP_ENCLAVE_BRANCH_RESULT_SKIP;
    }
    const cepEnclavePolicySnapshot* snapshot = cep_enclave_policy_snapshot();
    if (!snapshot || !snapshot->branches.entries || snapshot->branches.count == 0u) {
        return CEP_ENCLAVE_BRANCH_RESULT_SKIP;
    }
    for (size_t i = 0; i < snapshot->branches.count; ++i) {
        cepEnclaveBranchEntry* entry = &snapshot->branches.entries[i];
        if (!entry->path_pattern) {
            continue;
        }
        if (!cep_enclave_policy_path_matches(entry->path_pattern, path_text)) {
            continue;
        }
        const char* matched_rule = NULL;
        bool matched = false;
        bool allow = entry->default_allow;
        const char* deny_note = entry->default_allow ? NULL : "branch default deny";
        if (entry->rules && entry->rule_count) {
            for (size_t r = 0; r < entry->rule_count; ++r) {
                cepEnclaveBranchRule* rule = &entry->rules[r];
                bool verb_ok = (rule->verbs_mask == 0u) || (verb_mask == 0u) ||
                               ((rule->verbs_mask & verb_mask) != 0u);
                if (!verb_ok) {
                    continue;
                }
                bool subject_ok = true;
                if (rule->pack_count) {
                    subject_ok = false;
                    if (subject_pack) {
                        for (size_t p = 0; p < rule->pack_count; ++p) {
                            if (cep_id(rule->pack_ids[p]) == cep_id(subject_pack)) {
                                subject_ok = true;
                                break;
                            }
                        }
                    }
                }
                if (!subject_ok) {
                    continue;
                }
                allow = rule->allow;
                matched_rule = rule->rule_id;
                matched = true;
                deny_note = rule->allow ? NULL : "branch rule deny";
                break;
            }
        }
        if (decision) {
            decision->path_pattern = entry->path_pattern;
            decision->rule_id = matched_rule;
        }
        if (allow) {
            return CEP_ENCLAVE_BRANCH_RESULT_ALLOW;
        }
        if (deny_reason && deny_capacity) {
            const char* note = deny_note ? deny_note : "branch policy denied access";
            snprintf(deny_reason,
                     deny_capacity,
                     "%s for %s",
                     note,
                     entry->path_pattern);
        }
        return matched ? CEP_ENCLAVE_BRANCH_RESULT_DENY
                       : (entry->default_allow ? CEP_ENCLAVE_BRANCH_RESULT_ALLOW
                                               : CEP_ENCLAVE_BRANCH_RESULT_DENY);
    }
    return CEP_ENCLAVE_BRANCH_RESULT_SKIP;
}
