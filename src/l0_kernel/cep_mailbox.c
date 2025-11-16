/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_mailbox.h"

#include "cep_identifier.h"
#include "cep_namepool.h"
#include "cep_runtime.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_meta_name,        CEP_ACRO("CEP"), CEP_WORD("meta"));
CEP_DEFINE_STATIC_DT(dt_msgs_name,        CEP_ACRO("CEP"), CEP_WORD("msgs"));
CEP_DEFINE_STATIC_DT(dt_runtime_name,     CEP_ACRO("CEP"), CEP_WORD("runtime"));
CEP_DEFINE_STATIC_DT(dt_next_msg_id_name, CEP_ACRO("CEP"), CEP_WORD("next_msg_id"));
CEP_DEFINE_STATIC_DT(dt_expiries_name,    CEP_ACRO("CEP"), CEP_WORD("expiries"));
CEP_DEFINE_STATIC_DT(dt_exp_wall_name,    CEP_ACRO("CEP"), CEP_WORD("exp_wall"));
CEP_DEFINE_STATIC_DT(dt_envelope_name,    CEP_ACRO("CEP"), CEP_WORD("envelope"));
CEP_DEFINE_STATIC_DT(dt_interval_ns_name, CEP_ACRO("CEP"), CEP_WORD("interval_ns"));
CEP_DEFINE_STATIC_DT(dt_analytics_root,   CEP_ACRO("CEP"), CEP_WORD("analytics"));
CEP_DEFINE_STATIC_DT(dt_spacing_root,     CEP_ACRO("CEP"), CEP_WORD("spacing"));

#define CEP_MAILBOX_SETTINGS        (cep_runtime_mailbox_settings(cep_runtime_default()))
#define CEP_MAILBOX_WALLCLOCK_DISABLED (CEP_MAILBOX_SETTINGS->wallclock_disabled)
#define CEP_MAILBOX_BEAT_LOOKAHEAD      (CEP_MAILBOX_SETTINGS->beat_lookahead)
#define CEP_MAILBOX_SPACING_SAMPLES     (CEP_MAILBOX_SETTINGS->spacing_samples)

typedef struct {
    uint64_t beat;
    uint64_t interval;
} cepMailboxSpacingSample;

static int cep_mailbox_spacing_sample_cmp(const void* lhs, const void* rhs) {
    const cepMailboxSpacingSample* a = (const cepMailboxSpacingSample*)lhs;
    const cepMailboxSpacingSample* b = (const cepMailboxSpacingSample*)rhs;
    if (a->beat < b->beat) {
        return -1;
    }
    if (a->beat > b->beat) {
        return 1;
    }
    return 0;
}

static cepCell* cep_mailbox_resolve(cepCell* cell) {
    if (!cell) {
        return NULL;
    }
    return cep_cell_resolve(cell);
}

static bool cep_mailbox_set_numeric_name(cepDT* name, uint64_t value) {
    if (!name) {
        return false;
    }
    if (value >= CEP_AUTOID_MAX) {
        return false;
    }
    name->domain = CEP_ACRO("CEP");
    name->tag = cep_id_to_numeric((cepID)(value + 1u));
    name->glob = 0u;
    return true;
}

static bool cep_mailbox_numeric_from_name(const cepDT* name, uint64_t* out) {
    if (!name || !out) {
        return false;
    }
    if (!cep_id_is_numeric(name->tag)) {
        return false;
    }
    cepID payload = cep_id(name->tag);
    if (!payload) {
        return false;
    }
    *out = (uint64_t)(payload - 1u);
    return true;
}

static bool cep_mailbox_parse_u64_text(cepID id, uint64_t* out) {
    if (!out) {
        return false;
    }
    const char* text = NULL;
    char buffer[32];
    if (cep_id_is_reference(id)) {
        text = cep_namepool_lookup(id, NULL);
    } else if (cep_id_is_word(id)) {
        size_t len = cep_word_to_text(cep_id(id), buffer);
        buffer[len] = '\0';
        text = buffer;
    } else if (cep_id_is_acronym(id)) {
        size_t len = cep_acronym_to_text(cep_id(id), buffer);
        buffer[len] = '\0';
        text = buffer;
    } else {
        return false;
    }
    if (!text) {
        return false;
    }
    char* endptr = NULL;
    uint64_t value = strtoull(text, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }
    *out = value;
    return true;
}

static bool cep_mailbox_format_decimal(char* buffer, size_t cap, uint64_t value) {
    if (!buffer || cap == 0u) {
        return false;
    }
    int written = snprintf(buffer, cap, "%" PRIu64, value);
    return written > 0 && (size_t)written < cap;
}

static cepCell* cep_mailbox_ensure_dictionary(cepCell* parent, const cepDT* name) {
    cepCell* resolved = cep_mailbox_resolve(parent);
    if (!resolved || !cep_cell_is_normal(resolved)) {
        return NULL;
    }
    return cep_cell_ensure_dictionary_child(resolved, name, CEP_STORAGE_RED_BLACK_T);
}

static bool cep_mailbox_validate_id(const cepDT* id) {
    if (!id) {
        return false;
    }
    if (id->glob) {
        return false;
    }
    if (!cep_id_text_valid(id->tag)) {
        return false;
    }
    if (cep_id_is_numeric(id->tag) || cep_id_is_auto(id->tag)) {
        return false;
    }
    if (cep_id_has_glob_char(id->tag)) {
        return false;
    }
    return true;
}

static bool cep_mailbox_message_digest(cepCell* envelope, uint8_t digest[32]) {
    if (!envelope || !digest) {
        return false;
    }
    cepCell* resolved = cep_mailbox_resolve(envelope);
    if (!resolved || !cep_cell_is_immutable(resolved)) {
        return false;
    }
    return cep_cell_digest(resolved, CEP_DIGEST_SHA256, digest);
}

static bool cep_mailbox_digest_to_slug(const uint8_t digest[32],
                                       unsigned take_bytes,
                                       char* slug,
                                       size_t cap) {
    if (!digest || !slug || take_bytes == 0u) {
        return false;
    }
    size_t needed = take_bytes * 2u + 1u;
    if (cap < needed) {
        return false;
    }
    for (unsigned i = 0u; i < take_bytes; ++i) {
        snprintf(slug + (i * 2u), 3u, "%02x", digest[i]);
    }
    return true;
}

static bool cep_mailbox_compare_envelopes(cepCell* msgs_root,
                                          const cepDT* message_id,
                                          const uint8_t digest[32],
                                          bool* match) {
    if (!msgs_root || !message_id || !digest || !match) {
        return false;
    }
    cepCell* existing = cep_cell_find_by_name(msgs_root, message_id);
    if (!existing) {
        *match = false;
        return true;
    }
    existing = cep_mailbox_resolve(existing);
    if (!existing) {
        return false;
    }
    cepCell* envelope = cep_cell_find_by_name(existing, dt_envelope_name());
    if (!envelope) {
        return false;
    }
    uint8_t prior[32];
    if (!cep_mailbox_message_digest(envelope, prior)) {
        return false;
    }
    *match = (memcmp(prior, digest, sizeof prior) == 0);
    return true;
}

static bool cep_mailbox_assign_candidate(cepCell* msgs_root,
                                         const cepDT* candidate,
                                         const uint8_t digest[32],
                                         cepMailboxMessageId* out_id,
                                         cepMailboxIdMode mode) {
    bool identical = false;
    if (digest) {
        if (!cep_mailbox_compare_envelopes(msgs_root, candidate, digest, &identical)) {
            return false;
        }
        if (identical) {
            out_id->id = cep_dt_clean(candidate);
            out_id->mode = CEP_MAILBOX_ID_REUSED;
            out_id->collision_detected = false;
            return true;
        }
        if (cep_cell_find_by_name(msgs_root, candidate)) {
            return false;
        }
    } else if (cep_cell_find_by_name(msgs_root, candidate)) {
        return false;
    }

    out_id->id = cep_dt_clean(candidate);
    out_id->mode = mode;
    out_id->collision_detected = false;
    return true;
}

static bool cep_mailbox_counter_value(cepCell* runtime,
                                      uint64_t* value,
                                      bool increment) {
    if (!runtime || !value) {
        return false;
    }
    cepCell* node = cep_cell_find_by_name(runtime, dt_next_msg_id_name());
    uint64_t current = 1u;
    if (node && cep_cell_has_data(node)) {
        const char* text = (const char*)cep_cell_data(node);
        if (text) {
            char* endptr = NULL;
            uint64_t parsed = strtoull(text, &endptr, 10);
            if (endptr && *endptr == '\0') {
                current = parsed;
            }
        }
    }
    *value = current;
    if (increment) {
        if (!cep_cell_put_uint64(runtime, dt_next_msg_id_name(), current + 1u)) {
            return false;
        }
    }
    return true;
}

static bool cep_mailbox_counter_claim(cepCell* msgs_root,
                                      cepCell* runtime,
                                      cepMailboxMessageId* out_id,
                                      bool* collision) {
    if (!msgs_root || !runtime || !out_id || !collision) {
        return false;
    }
    *collision = false;

    for (;;) {
        uint64_t value = 0u;
        if (!cep_mailbox_counter_value(runtime, &value, true)) {
            return false;
        }

        char slug[32];
        if (!cep_mailbox_format_decimal(slug, sizeof slug, value)) {
            return false;
        }
        char identifier[40];
        int written = snprintf(identifier, sizeof identifier, "msg-%s", slug);
        if (written <= 0 || (size_t)written >= sizeof identifier) {
            return false;
        }

        cepDT candidate = {0};
        candidate.domain = cep_namepool_intern_cstr("CEP");
        candidate.tag = cep_namepool_intern_cstr(identifier);
        candidate.glob = 0u;

        if (cep_cell_find_by_name(msgs_root, &candidate)) {
            *collision = true;
            continue;
        }

        out_id->id = cep_dt_clean(&candidate);
        out_id->mode = CEP_MAILBOX_ID_COUNTER;
        out_id->collision_detected = *collision;
        return true;
    }
}

bool cep_mailbox_select_message_id(cepCell* mailbox_root,
                                   const cepDT* explicit_id,
                                   const cepCell* envelope,
                                   cepMailboxMessageId* out_id) {
    if (!mailbox_root || !out_id) {
        return false;
    }
    memset(out_id, 0, sizeof *out_id);

    cepCell* resolved_mailbox = cep_mailbox_resolve((cepCell*)mailbox_root);
    CEP_DEBUG_PRINTF("[mailbox_select] root=%p resolved=%p\n",
                     (void*)mailbox_root,
                     (void*)resolved_mailbox);
    if (!resolved_mailbox) {
        return false;
    }
    cepCell* msgs = cep_mailbox_ensure_dictionary(resolved_mailbox, dt_msgs_name());
    if (!msgs) {
        return false;
    }
    cepCell* runtime = NULL;
    cepCell* meta = cep_mailbox_ensure_dictionary(resolved_mailbox, dt_meta_name());
    if (meta) {
        runtime = cep_mailbox_ensure_dictionary(meta, dt_runtime_name());
    }

    uint8_t digest[32];
    bool digest_ready = envelope && cep_mailbox_message_digest((cepCell*)envelope, digest);

    if (explicit_id && cep_mailbox_validate_id(explicit_id)) {
        if (digest_ready) {
            if (cep_mailbox_assign_candidate(msgs, explicit_id, digest, out_id, CEP_MAILBOX_ID_EXPLICIT)) {
                return true;
            }
            out_id->collision_detected = true;
            return false;
        }
        if (!cep_cell_find_by_name(msgs, explicit_id)) {
            out_id->id = cep_dt_clean(explicit_id);
            out_id->mode = CEP_MAILBOX_ID_EXPLICIT;
            out_id->collision_detected = false;
            return true;
        }
        out_id->collision_detected = true;
        return false;
    }

    if (digest_ready) {
        for (unsigned attempt = 0u; attempt < 4u; ++attempt) {
            char slug[32] = {0};
            if (!cep_mailbox_digest_to_slug(digest, 12u, slug, sizeof slug)) {
                break;
            }
            char identifier[64];
            if (attempt == 0u) {
                snprintf(identifier, sizeof identifier, "msg-%s", slug);
            } else {
                snprintf(identifier, sizeof identifier, "msg-%s-%u", slug, attempt);
            }
            cepDT candidate = {0};
            candidate.domain = cep_namepool_intern_cstr("CEP");
            candidate.tag = cep_namepool_intern_cstr(identifier);
            candidate.glob = 0u;
            if (cep_mailbox_assign_candidate(msgs, &candidate, digest, out_id, CEP_MAILBOX_ID_DIGEST)) {
                out_id->collision_detected = (attempt != 0u);
                return true;
            }
        }
    }

    if (!runtime) {
        return false;
    }

    bool counter_collision = false;
    if (!cep_mailbox_counter_claim(msgs, runtime, out_id, &counter_collision)) {
        return false;
    }
    out_id->collision_detected = counter_collision;
    return true;
}

bool cep_mailbox_ttl_context_init(cepMailboxTTLContext* ctx) {
    if (!ctx) {
        return false;
    }
    memset(ctx, 0, sizeof *ctx);
    ctx->issued_beat = cep_heartbeat_current();
    ctx->current_beat = ctx->issued_beat;
    ctx->issued_has_unix = false;
    ctx->current_has_unix = false;

    if (ctx->current_beat != CEP_BEAT_INVALID) {
        uint64_t unix_ts = 0u;
        if (cep_heartbeat_beat_to_unix(ctx->current_beat, &unix_ts)) {
            ctx->current_has_unix = true;
            ctx->current_unix_ns = unix_ts;
            ctx->issued_has_unix = true;
            ctx->issued_unix_ns = unix_ts;
        }
    }

    return true;
}

void cep_mailbox_disable_wallclock(bool disabled) {
    CEP_MAILBOX_WALLCLOCK_DISABLED = disabled;
}

void cep_mailbox_set_expiry_windows(uint32_t beat_lookahead, uint32_t spacing_samples) {
    CEP_MAILBOX_BEAT_LOOKAHEAD = beat_lookahead;
    CEP_MAILBOX_SPACING_SAMPLES = spacing_samples;
}

void cep_mailbox_get_expiry_windows(uint32_t* beat_lookahead, uint32_t* spacing_samples) {
    if (beat_lookahead) {
        *beat_lookahead = CEP_MAILBOX_BEAT_LOOKAHEAD;
    }
    if (spacing_samples) {
        *spacing_samples = CEP_MAILBOX_SPACING_SAMPLES;
    }
}

static bool cep_mailbox_average_spacing(uint64_t* interval_ns_out) {
    if (!interval_ns_out) {
        return false;
    }
    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return false;
    }
    cepCell* analytics = cep_cell_find_by_name(rt_root, dt_analytics_root());
    if (!analytics) {
        return false;
    }
    analytics = cep_mailbox_resolve(analytics);
    if (!analytics) {
        return false;
    }
    cepCell* spacing = cep_cell_find_by_name(analytics, dt_spacing_root());
    if (!spacing) {
        return false;
    }
    spacing = cep_mailbox_resolve(spacing);
    if (!spacing || !cep_cell_has_store(spacing)) {
        return false;
    }

    size_t capacity = 0u;
    size_t count = 0u;
    cepMailboxSpacingSample* samples = NULL;

    for (cepCell* entry = cep_cell_first(spacing); entry; entry = cep_cell_next(spacing, entry)) {
        entry = cep_mailbox_resolve(entry);
        if (!entry) {
            continue;
        }
        uint64_t beat = 0u;
        if (!cep_mailbox_numeric_from_name(&entry->metacell.dt, &beat)) {
            continue;
        }
        cepCell* interval_cell = cep_cell_find_by_name(entry, dt_interval_ns_name());
        if (!interval_cell || !cep_cell_has_data(interval_cell)) {
            continue;
        }
        const char* text = (const char*)cep_cell_data(interval_cell);
        if (!text) {
            continue;
        }
        char* endptr = NULL;
        uint64_t interval = strtoull(text, &endptr, 10);
        if (!endptr || *endptr != '\0') {
            continue;
        }
        if (count == capacity) {
            size_t new_capacity = capacity ? capacity * 2u : 16u;
            cepMailboxSpacingSample* resized = samples
                ? cep_realloc(samples, new_capacity * sizeof *resized)
                : cep_malloc(new_capacity * sizeof *resized);
            if (!resized) {
                cep_free(samples);
                return false;
            }
            samples = resized;
            capacity = new_capacity;
        }
        samples[count].beat = beat;
        samples[count].interval = interval;
        ++count;
    }

    if (count == 0u) {
        cep_free(samples);
        return false;
    }

    qsort(samples, count, sizeof *samples, cep_mailbox_spacing_sample_cmp);

    uint64_t total = 0u;
    size_t used = 0u;
    size_t start = 0u;
    if (CEP_MAILBOX_SPACING_SAMPLES && CEP_MAILBOX_SPACING_SAMPLES < count) {
        start = count - CEP_MAILBOX_SPACING_SAMPLES;
    }
    for (size_t i = start; i < count; ++i) {
        total += samples[i].interval;
        ++used;
    }

    cep_free(samples);

    if (!used) {
        return false;
    }

    *interval_ns_out = total / used;
    return *interval_ns_out != 0u;
}

bool cep_mailbox_resolve_ttl(const cepMailboxTTLSpec* message,
                             const cepMailboxTTLSpec* mailbox,
                             const cepMailboxTTLSpec* topology,
                             const cepMailboxTTLContext* ctx,
                             cepMailboxTTLResolved* resolved) {
    if (!ctx || !resolved) {
        return false;
    }
    memset(resolved, 0, sizeof *resolved);

    cepMailboxTTLSource beats_scope = CEP_MAILBOX_TTL_SCOPE_NONE;
    cepMailboxTTLSource wall_scope = CEP_MAILBOX_TTL_SCOPE_NONE;
    const cepMailboxTTLSpec* beats_spec = NULL;
    const cepMailboxTTLSpec* wall_spec = NULL;

    const cepMailboxTTLSpec* precedence[3] = {message, mailbox, topology};
    cepMailboxTTLSource scopes[3] = {
        CEP_MAILBOX_TTL_SCOPE_MESSAGE,
        CEP_MAILBOX_TTL_SCOPE_MAILBOX,
        CEP_MAILBOX_TTL_SCOPE_TOPOLOGY,
    };

    for (size_t i = 0; i < 3; ++i) {
        const cepMailboxTTLSpec* spec = precedence[i];
        if (!spec) {
            continue;
        }
        if (!beats_spec && spec->has_beats) {
            beats_spec = spec;
            beats_scope = scopes[i];
        }
        if (!wall_spec && spec->has_unix_ns) {
            wall_spec = spec;
            wall_scope = scopes[i];
        }
        if (spec->forever) {
            resolved->is_forever = true;
            return true;
        }
    }

    if (beats_spec && beats_spec->has_beats && beats_spec->ttl_beats > 0u) {
        resolved->beats_active = true;
        resolved->ttl_beats = beats_spec->ttl_beats;
        resolved->beats_source = beats_scope;
    }

    if (wall_spec && wall_spec->has_unix_ns && wall_spec->ttl_unix_ns > 0u) {
        resolved->wallclock_active = true;
        resolved->ttl_unix_ns = wall_spec->ttl_unix_ns;
        resolved->wallclock_source = wall_scope;
    }

    if (!resolved->beats_active && !resolved->wallclock_active && !resolved->is_forever) {
        return true;
    }

    cepBeatNumber origin_beat = ctx->issued_beat != CEP_BEAT_INVALID
        ? ctx->issued_beat
        : ctx->current_beat;

    if (resolved->beats_active) {
        if (origin_beat == CEP_BEAT_INVALID) {
            return false;
        }
        resolved->beat_deadline = origin_beat + resolved->ttl_beats;
    }

    uint64_t origin_unix = ctx->issued_has_unix ? ctx->issued_unix_ns : 0u;
    if (!origin_unix && ctx->issued_beat != CEP_BEAT_INVALID) {
        (void)cep_heartbeat_beat_to_unix(ctx->issued_beat, &origin_unix);
    }
    if (!origin_unix && ctx->current_has_unix) {
        origin_unix = ctx->current_unix_ns;
    }

    if (resolved->wallclock_active) {
        if (!origin_unix) {
            return false;
        }
        resolved->wallclock_deadline = origin_unix + resolved->ttl_unix_ns;
    }

    if (!resolved->beats_active &&
        resolved->wallclock_active &&
        !CEP_MAILBOX_WALLCLOCK_DISABLED &&
        ctx->current_has_unix &&
        ctx->current_beat != CEP_BEAT_INVALID) {
        uint64_t average = 0u;
        if (cep_mailbox_average_spacing(&average) && average > 0u) {
            int64_t delta = (int64_t)(resolved->wallclock_deadline - ctx->current_unix_ns);
            uint64_t steps = 0u;
            if (delta <= 0) {
                steps = 0u;
            } else {
                steps = (uint64_t)((delta + (int64_t)average - 1) / (int64_t)average);
            }
            if (steps > CEP_MAILBOX_BEAT_LOOKAHEAD && CEP_MAILBOX_BEAT_LOOKAHEAD > 0u) {
                steps = CEP_MAILBOX_BEAT_LOOKAHEAD;
            }
            resolved->beats_active = true;
            resolved->beat_deadline = ctx->current_beat + steps;
            resolved->beat_from_wallclock = true;
            resolved->heuristics_used = true;
            resolved->heuristic_interval_ns = average;
        }
    }

    return true;
}

static bool cep_mailbox_add_link_unique(cepCell* bucket, const cepDT* message_id, cepCell* target) {
    if (!bucket || !message_id || !target) {
        return false;
    }
    cepDT name = cep_dt_clean(message_id);
    cepCell* existing = cep_cell_find_by_name(bucket, &name);
    if (existing) {
        return true;
    }
    cepCell* link = cep_dict_add_link(bucket, &name, target);
    return link != NULL;
}

bool cep_mailbox_record_expiry(cepCell* mailbox_root,
                               const cepDT* message_id,
                               const cepMailboxTTLResolved* resolved) {
    if (!mailbox_root || !message_id || !resolved) {
        return false;
    }
    if (!resolved->beats_active && !resolved->wallclock_active) {
        return true;
    }

    cepCell* resolved_mailbox = cep_mailbox_resolve(mailbox_root);
    if (!resolved_mailbox) {
        return false;
    }

    cepCell* msgs = cep_cell_find_by_name(resolved_mailbox, dt_msgs_name());
    if (!msgs) {
        return false;
    }
    msgs = cep_mailbox_resolve(msgs);
    if (!msgs) {
        return false;
    }
    cepCell* message_cell = cep_cell_find_by_name(msgs, message_id);
    if (!message_cell) {
        return false;
    }
    message_cell = cep_mailbox_resolve(message_cell);
    if (!message_cell) {
        return false;
    }

    cepCell* meta = cep_mailbox_ensure_dictionary(resolved_mailbox, dt_meta_name());
    if (!meta) {
        return false;
    }
    cepCell* runtime = cep_mailbox_ensure_dictionary(meta, dt_runtime_name());
    if (!runtime) {
        return false;
    }

    if (resolved->beats_active) {
        cepCell* expiries = cep_mailbox_ensure_dictionary(runtime, dt_expiries_name());
        if (!expiries) {
            return false;
        }
        cepDT bucket_name = {0};
        if (!cep_mailbox_set_numeric_name(&bucket_name, resolved->beat_deadline)) {
            return false;
        }
        cepCell* bucket = cep_mailbox_ensure_dictionary(expiries, &bucket_name);
        if (!bucket) {
            return false;
        }
        if (!cep_mailbox_add_link_unique(bucket, message_id, message_cell)) {
            return false;
        }
    }

    if (resolved->wallclock_active) {
        cepCell* expiries = cep_mailbox_ensure_dictionary(runtime, dt_exp_wall_name());
        if (!expiries) {
            return false;
        }
        char text[32];
        if (!cep_mailbox_format_decimal(text, sizeof text, resolved->wallclock_deadline)) {
            return false;
        }
        cepDT bucket_name = {0};
        bucket_name.domain = cep_namepool_intern_cstr("CEP");
        bucket_name.tag = cep_namepool_intern_cstr(text);
        bucket_name.glob = 0u;
        cepCell* bucket = cep_mailbox_ensure_dictionary(expiries, &bucket_name);
        if (!bucket) {
            return false;
        }
        if (!cep_mailbox_add_link_unique(bucket, message_id, message_cell)) {
            return false;
        }
    }

    return true;
}

void cep_mailbox_retention_plan_reset(cepMailboxRetentionPlan* plan) {
    if (!plan) {
        return;
    }
    cep_free(plan->beats);
    cep_free(plan->wallclock);
    memset(plan, 0, sizeof *plan);
}

static bool cep_mailbox_plan_push(cepMailboxExpiryRecord** array,
                                  size_t* count,
                                  size_t* capacity,
                                  const cepMailboxExpiryRecord* record) {
    if (!array || !count || !capacity || !record) {
        return false;
    }
    if (*count == *capacity) {
        size_t new_cap = *capacity ? (*capacity * 2u) : 8u;
        cepMailboxExpiryRecord* resized = *array
            ? cep_realloc(*array, new_cap * sizeof *resized)
            : cep_malloc(new_cap * sizeof *resized);
        if (!resized) {
            return false;
        }
        *array = resized;
        *capacity = new_cap;
    }
    (*array)[*count] = *record;
    ++(*count);
    return true;
}

static void cep_mailbox_plan_bucket(cepCell* bucket,
                                    bool from_wallclock,
                                    uint64_t deadline,
                                    cepMailboxRetentionPlan* plan,
                                    bool due) {
    if (!bucket || !plan) {
        return;
    }
    bucket = cep_mailbox_resolve(bucket);
    if (!bucket || !cep_cell_has_store(bucket)) {
        return;
    }
    for (cepCell* entry = cep_cell_first(bucket); entry; entry = cep_cell_next(bucket, entry)) {
        entry = cep_mailbox_resolve(entry);
        if (!entry) {
            continue;
        }
        cepMailboxExpiryRecord record = {0};
        record.message_id = cep_dt_clean(&entry->metacell.dt);
        record.from_wallclock = from_wallclock;
        if (from_wallclock) {
            record.wallclock_deadline = deadline;
        } else {
            record.beat_deadline = (cepBeatNumber)deadline;
        }
        if (due) {
            if (from_wallclock) {
                (void)cep_mailbox_plan_push(&plan->wallclock,
                                            &plan->wallclock_count,
                                            &plan->wallclock_capacity,
                                            &record);
            } else {
                (void)cep_mailbox_plan_push(&plan->beats,
                                            &plan->beats_count,
                                            &plan->beats_capacity,
                                            &record);
            }
        } else {
            if (from_wallclock) {
                plan->has_future_wallclock = true;
            } else {
                plan->has_future_beats = true;
            }
        }
    }
}

bool cep_mailbox_plan_retention(cepCell* mailbox_root,
                                const cepMailboxTTLContext* ctx,
                                cepMailboxRetentionPlan* plan) {
    if (!mailbox_root || !ctx || !plan) {
        return false;
    }

    cepCell* resolved_mailbox = cep_mailbox_resolve(mailbox_root);
    if (!resolved_mailbox) {
        return false;
    }

    cepCell* meta = cep_cell_find_by_name(resolved_mailbox, dt_meta_name());
    if (!meta) {
        return true;
    }
    meta = cep_mailbox_resolve(meta);
    if (!meta) {
        return false;
    }
    cepCell* runtime = cep_cell_find_by_name(meta, dt_runtime_name());
    if (!runtime) {
        return true;
    }
    runtime = cep_mailbox_resolve(runtime);
    if (!runtime) {
        return false;
    }

    cepCell* beat_buckets = cep_cell_find_by_name(runtime, dt_expiries_name());
    if (beat_buckets) {
        beat_buckets = cep_mailbox_resolve(beat_buckets);
        if (!beat_buckets) {
            return false;
        }
        for (cepCell* bucket = cep_cell_first(beat_buckets); bucket; bucket = cep_cell_next(beat_buckets, bucket)) {
            uint64_t beat = 0u;
            if (!cep_mailbox_numeric_from_name(&bucket->metacell.dt, &beat)) {
                continue;
            }
            bool due = ctx->current_beat != CEP_BEAT_INVALID && beat <= ctx->current_beat;
            cep_mailbox_plan_bucket(bucket, false, beat, plan, due);
            if (!due) {
                plan->has_future_beats = true;
            }
        }
    }

    cepCell* wall_buckets = cep_cell_find_by_name(runtime, dt_exp_wall_name());
    if (wall_buckets) {
        wall_buckets = cep_mailbox_resolve(wall_buckets);
        if (!wall_buckets) {
            return false;
        }
        for (cepCell* bucket = cep_cell_first(wall_buckets); bucket; bucket = cep_cell_next(wall_buckets, bucket)) {
            uint64_t unix_deadline = 0u;
            if (!cep_mailbox_parse_u64_text(bucket->metacell.dt.tag, &unix_deadline)) {
                continue;
            }
            bool due = ctx->current_has_unix && unix_deadline <= ctx->current_unix_ns;
            if (!ctx->current_has_unix) {
                plan->has_future_wallclock = true;
                continue;
            }
            cep_mailbox_plan_bucket(bucket, true, unix_deadline, plan, due);
            if (!due) {
                plan->has_future_wallclock = true;
            }
        }
    }

    return true;
}
