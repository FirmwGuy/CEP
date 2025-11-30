/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_focus.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_namepool.h"
#include "blake3.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    const char* name;
    double      value;
} cepL2FocusSignal;

CEP_DEFINE_STATIC_DT(dt_runtime_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_signal_field_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("signal_field"));
CEP_DEFINE_STATIC_DT(dt_signal_field_current, CEP_ACRO("CEP"), cep_namepool_intern_cstr("current"));
CEP_DEFINE_STATIC_DT(dt_mode_field, CEP_ACRO("CEP"), CEP_WORD("mode"));

static cepCell* cep_l2_focus_resolve_signal_root(cepCell* eco_root) {
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    if (!runtime_root || !cep_cell_require_dictionary_store(&runtime_root)) {
        return NULL;
    }
    cepCell* signal_root = cep_cell_find_by_name(runtime_root, dt_signal_field_root());
    signal_root = signal_root ? cep_cell_resolve(signal_root) : NULL;
    if (!signal_root || !cep_cell_require_dictionary_store(&signal_root)) {
        return NULL;
    }
    cepCell* current = cep_cell_find_by_name(signal_root, dt_signal_field_current());
    current = current ? cep_cell_resolve(current) : NULL;
    if (!current || !cep_cell_require_dictionary_store(&current)) {
        return NULL;
    }
    return current;
}

bool cep_l2_focus_read_signal(cepCell* signals, const char* name, double* out) {
    if (!signals || !name || !*name || !out) {
        return false;
    }
    cepID tag = cep_namepool_intern(name, strlen(name));
    if (!tag) {
        return false;
    }
    cepDT dt = {.domain = CEP_ACRO("CEP"), .tag = tag, .glob = 0u};
    cepCell* field = cep_cell_find_by_name(signals, &dt);
    field = field ? cep_cell_resolve(field) : NULL;
    if (!field || !cep_cell_has_data(field)) {
        return false;
    }
    const char* text = (const char*)cep_cell_data(field);
    if (!text) {
        return false;
    }
    char* end = NULL;
    double parsed = strtod(text, &end);
    if (!end || end == text) {
        return false;
    }
    *out = parsed;
    return true;
}

static void cep_l2_focus_collect_signals(cepCell* signals,
                                         const char* const* names,
                                         size_t name_count,
                                         cepL2FocusSignal* out) {
    if (!signals || !names || !out) {
        return;
    }
    for (size_t i = 0u; i < name_count; ++i) {
        out[i].name = names[i];
        out[i].value = 0.0;
        (void)cep_l2_focus_read_signal(signals, names[i], &out[i].value);
    }
}

static void cep_l2_focus_append_field(char* buf, size_t buf_len, size_t* used, const char* label, const char* value) {
    if (!buf || buf_len == 0u || !used || !label) {
        return;
    }
    const char* val = value ? value : "";
    int written = snprintf(buf + *used, buf_len > *used ? buf_len - *used : 0u, "%s=%s;", label, val);
    if (written > 0) {
        *used += (size_t)written;
    }
}

static void cep_l2_focus_append_signals(char* buf, size_t buf_len, size_t* used, const cepL2FocusSignal* signals, size_t count) {
    if (!buf || !used || !signals) {
        return;
    }
    for (size_t i = 0u; i < count; ++i) {
        int written = snprintf(buf + *used,
                               buf_len > *used ? buf_len - *used : 0u,
                               "%s=%.6f;",
                               signals[i].name,
                               signals[i].value);
        if (written > 0) {
            *used += (size_t)written;
        }
    }
}

static bool cep_l2_focus_hash_key(const char* skill_id,
                                  const cepL2FocusContext* ctx,
                                  const cepL2FocusSignal* signals,
                                  size_t signal_count,
                                  char* focus_key,
                                  size_t focus_key_len) {
    if (!skill_id || !*skill_id || !ctx || !signals || signal_count == 0u || !focus_key || focus_key_len == 0u) {
        return false;
    }

    char preimage[512];
    size_t used = 0u;
    int written = snprintf(preimage, sizeof preimage, "skill=%s;", skill_id);
    if (written <= 0) {
        return false;
    }
    used = (size_t)written;

    cep_l2_focus_append_field(preimage, sizeof preimage, &used, "mode", ctx->mode_id);
    cep_l2_focus_append_field(preimage, sizeof preimage, &used, "rat", ctx->rat_id);
    cep_l2_focus_append_field(preimage, sizeof preimage, &used, "maze", ctx->maze_id);
    cep_l2_focus_append_field(preimage, sizeof preimage, &used, "region", ctx->region_id);
    cep_l2_focus_append_field(preimage, sizeof preimage, &used, "province", ctx->province_id);
    cep_l2_focus_append_signals(preimage, sizeof preimage, &used, signals, signal_count);

    blake3_hasher hasher;
    unsigned char digest[16];
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, preimage, used);
    blake3_hasher_finalize(&hasher, digest, sizeof digest);

    char hex[33];
    for (size_t i = 0u; i < sizeof digest; ++i) {
        snprintf(hex + (i * 2u), sizeof hex - (i * 2u), "%02x", digest[i]);
    }
    hex[32] = '\0';

    int final_written = snprintf(focus_key, focus_key_len, "focus_%s_%s", skill_id, hex);
    return final_written > 0 && (size_t)final_written < focus_key_len;
}

static void cep_l2_focus_fetch_mode(cepCell* signals, cepL2FocusContext* ctx) {
    if (!signals || !ctx) {
        return;
    }
    cepCell* mode_cell = cep_cell_find_by_name(signals, dt_mode_field());
    mode_cell = mode_cell ? cep_cell_resolve(mode_cell) : NULL;
    if (!mode_cell || !cep_cell_has_data(mode_cell)) {
        return;
    }
    const char* text = (const char*)cep_cell_data(mode_cell);
    if (text && *text) {
        ctx->mode_id = text;
    }
}

static bool cep_l2_focus_build_core(cepCell* eco_root,
                                    const char* skill_id,
                                    const char* const* signal_names,
                                    size_t signal_count,
                                    cepL2FocusContext* ctx,
                                    char* focus_key,
                                    size_t focus_key_len) {
    if (!eco_root || !skill_id || !signal_names || signal_count == 0u || !ctx || !focus_key || focus_key_len == 0u) {
        return false;
    }
    cepCell* signals = cep_l2_focus_resolve_signal_root(eco_root);
    if (!signals) {
        return false;
    }

    cep_l2_focus_fetch_mode(signals, ctx);

    cepL2FocusSignal slices[8];
    if (signal_count > sizeof slices / sizeof slices[0]) {
        return false;
    }
    cep_l2_focus_collect_signals(signals, signal_names, signal_count, slices);
    return cep_l2_focus_hash_key(skill_id, ctx, slices, signal_count, focus_key, focus_key_len);
}

/* Builds a navigation focus key using risk/fast/fatigue/low_noise and spatial
   hints so movement choices can cluster on corridor stability and pace. */
bool cep_l2_focus_build_nav(cepCell* eco_root,
                            const cepL2FocusContext* ctx_in,
                            char* focus_key,
                            size_t focus_key_len) {
    if (!ctx_in || !focus_key) {
        return false;
    }
    const char* signals[] = {"risk", "fast", "fatigue", "low_noise"};
    cepL2FocusContext ctx = *ctx_in;
    return cep_l2_focus_build_core(eco_root, "nav", signals, sizeof signals / sizeof signals[0], &ctx, focus_key, focus_key_len);
}

/* Builds an exploration manager focus key from curiosity/risk/hunger/mode so
   exploration bias can respond to safety and appetite. */
bool cep_l2_focus_build_exploration(cepCell* eco_root,
                                    const cepL2FocusContext* ctx_in,
                                    char* focus_key,
                                    size_t focus_key_len) {
    if (!ctx_in || !focus_key) {
        return false;
    }
    const char* signals[] = {"curiosity", "risk", "hunger", "low_noise"};
    cepL2FocusContext ctx = *ctx_in;
    return cep_l2_focus_build_core(eco_root, "explore", signals, sizeof signals / sizeof signals[0], &ctx, focus_key, focus_key_len);
}

/* Builds a memory/risk-avoidance focus key that clusters on risk/hunger/fatigue
   and local region so recall can emphasize unsafe areas. */
bool cep_l2_focus_build_memory(cepCell* eco_root,
                               const cepL2FocusContext* ctx_in,
                               char* focus_key,
                               size_t focus_key_len) {
    if (!ctx_in || !focus_key) {
        return false;
    }
    const char* signals[] = {"risk", "hunger", "fatigue", "low_noise"};
    cepL2FocusContext ctx = *ctx_in;
    return cep_l2_focus_build_core(eco_root, "memory", signals, sizeof signals / sizeof signals[0], &ctx, focus_key, focus_key_len);
}

/* Builds a social follow/lead focus key keyed on social_trust/teach/low_noise
   plus province/mode so group dynamics stay stable across arenas. */
bool cep_l2_focus_build_social(cepCell* eco_root,
                               const cepL2FocusContext* ctx_in,
                               char* focus_key,
                               size_t focus_key_len) {
    if (!ctx_in || !focus_key) {
        return false;
    }
    const char* signals[] = {"social_trust", "teach", "low_noise"};
    cepL2FocusContext ctx = *ctx_in;
    return cep_l2_focus_build_core(eco_root, "social", signals, sizeof signals / sizeof signals[0], &ctx, focus_key, focus_key_len);
}

/* Builds a warning/trust focus key using risk/social_trust/low_noise/mode so
   warning emission and trust evaluation align with current volatility. */
bool cep_l2_focus_build_warning(cepCell* eco_root,
                                const cepL2FocusContext* ctx_in,
                                char* focus_key,
                                size_t focus_key_len) {
    if (!ctx_in || !focus_key) {
        return false;
    }
    const char* signals[] = {"risk", "social_trust", "low_noise"};
    cepL2FocusContext ctx = *ctx_in;
    return cep_l2_focus_build_core(eco_root, "warning", signals, sizeof signals / sizeof signals[0], &ctx, focus_key, focus_key_len);
}
