/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_stream_internal.h"

#include <string.h>

typedef struct cepStreamWriteIntent {
    cepCell*   stream;
    cepCell*   library;
    cepCell*   resource;
    uint64_t   offset;
    size_t     size;
    uint64_t   payload_hash;
    uint64_t   expected_hash;
    uint64_t   idempotency_key;
    uint64_t   staged_at;
    uint8_t*   payload;
    cepCell*   intent_cell;
} cepStreamWriteIntent;

static cepStreamWriteIntent* g_stream_intents;
static size_t                g_stream_intent_count;
static size_t                g_stream_intent_capacity;

static cepCell* cep_stream_get_intent_list(cepCell* owner) {
    cepCell* list = cep_cell_find_by_name(owner, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("intent")));
    if (!list) {
        list = cep_cell_add_list(owner,
                                 CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("intent")),
                                 0,
                                 CEP_DTAW("CEP", "intent"),
                                 CEP_STORAGE_LINKED_LIST);
    }
    return list;
}

static cepCell* cep_stream_get_outcome_list(cepCell* owner) {
    cepCell* list = cep_cell_find_by_name(owner, CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("outcome")));
    if (!list) {
        list = cep_cell_add_list(owner,
                                 CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("outcome")),
                                 0,
                                 CEP_DTAW("CEP", "outcome"),
                                 CEP_STORAGE_LINKED_LIST);
    }
    return list;
}

static cepCell* cep_stream_append_intent(cepCell* owner, cepStreamIntentEntry* entry) {
    cepCell* list = cep_stream_get_intent_list(owner);
    if (!list)
        return NULL;
    return cep_cell_append_value(list,
                                 CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("entry")),
                                 CEP_DTAW("CEP", "intent"),
                                 (void*)entry,
                                 sizeof *entry,
                                 sizeof *entry);
}

static void cep_stream_append_outcome(cepCell* owner, const cepStreamOutcomeEntry* entry) {
    cepCell* list = cep_stream_get_outcome_list(owner);
    if (!list)
        return;
    cep_cell_append_value(list,
                          CEP_DTS(CEP_ACRO("CEP"), CEP_WORD("entry")),
                          CEP_DTAW("CEP", "outcome"),
                          (void*)entry,
                          sizeof *entry,
                          sizeof *entry);
}

static bool cep_stream_intent_reserve(size_t additional) {
    size_t required = g_stream_intent_count + additional;
    if (required <= g_stream_intent_capacity)
        return true;
    size_t capacity = g_stream_intent_capacity ? g_stream_intent_capacity : 4;
    while (capacity < required) {
        capacity *= 2;
    }
    cepStreamWriteIntent* intents = g_stream_intents
        ? cep_realloc(g_stream_intents, capacity * sizeof *intents)
        : cep_malloc(capacity * sizeof *intents);
    if (!intents)
        return false;
    if (capacity > g_stream_intent_capacity) {
        memset(intents + g_stream_intent_capacity, 0, (capacity - g_stream_intent_capacity) * sizeof *intents);
    }
    g_stream_intents = intents;
    g_stream_intent_capacity = capacity;
    return true;
}

bool cep_stream_stage_write(cepCell* owner,
                            cepCell* library,
                            cepCell* resource,
                            uint64_t offset,
                            const void* payload,
                            size_t size,
                            uint64_t expected_hash) {
    if (!owner || !library || !resource || !payload || !size)
        return false;

    if (!cep_stream_intent_reserve(1))
        return false;

    uint8_t* copy = cep_malloc(size);
    if (!copy)
        return false;
    memcpy(copy, payload, size);

    cepStreamWriteIntent intent = {
        .stream         = owner,
        .library        = library,
        .resource       = resource,
        .offset         = offset,
        .size           = size,
        .payload_hash   = cep_hash_bytes(copy, size),
        .expected_hash  = expected_hash,
        .idempotency_key= cep_cell_timestamp_next(),
        .staged_at      = cep_cell_timestamp(),
        .payload        = copy,
        .intent_cell    = NULL,
    };

    cepStreamIntentEntry entry = {
        .offset           = offset,
        .requested        = size,
        .actual           = 0,
        .payload_hash     = intent.payload_hash,
        .expected_hash    = expected_hash,
        .idempotency_key  = intent.idempotency_key,
        .staged_at        = intent.staged_at,
        .flags            = CEP_STREAM_INTENT_PENDING,
        .reserved         = 0,
    };

    intent.intent_cell = cep_stream_append_intent(owner, &entry);
    if (!intent.intent_cell) {
        cep_free(copy);
        return false;
    }

    g_stream_intents[g_stream_intent_count++] = intent;
    return true;
}

static void cep_stream_record_outcome(cepStreamWriteIntent* intent, bool committed, size_t actual_written, uint64_t resulting_hash) {
    if (!intent)
        return;

    cepStreamOutcomeEntry outcome = {
        .offset           = intent->offset,
        .length           = actual_written,
        .payload_hash     = intent->payload_hash,
        .expected_hash    = intent->expected_hash,
        .resulting_hash   = resulting_hash,
        .idempotency_key  = intent->idempotency_key,
        .committed_at     = cep_cell_timestamp_next(),
        .flags            = committed ? CEP_STREAM_INTENT_COMMITTED : CEP_STREAM_INTENT_DIVERGED,
        .reserved         = 0,
    };

    cep_stream_append_outcome(intent->stream, &outcome);

    if (intent->intent_cell)
        cep_cell_delete_hard(intent->intent_cell);
}

bool cep_stream_commit_pending(void) {
    bool all_ok = true;

    for (size_t i = 0; i < g_stream_intent_count; ++i) {
        cepStreamWriteIntent* intent = &g_stream_intents[i];
        const cepLibraryBinding* binding = cep_library_binding(intent->library);
        size_t written = 0;
        bool ok = false;
        uint64_t resulting_hash = intent->payload_hash;

        bool diverged = false;
        if (binding && binding->ops && binding->ops->stream_expected_hash && intent->expected_hash) {
            uint64_t current_hash = 0;
            if (!binding->ops->stream_expected_hash(binding, intent->resource, intent->offset, intent->size, &current_hash) ||
                current_hash != intent->expected_hash) {
                diverged = true;
            }
        }

        if (!diverged && binding && binding->ops && binding->ops->stream_write) {
            ok = binding->ops->stream_write(binding,
                                            intent->resource,
                                            intent->offset,
                                            intent->payload,
                                            intent->size,
                                            &written);
        }

        if (diverged || !ok || written != intent->size) {
            all_ok = false;
            resulting_hash = 0;
            ok = false;
        }

        cep_stream_journal(intent->stream,
                           ok ? (CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_COMMIT)
                              : (CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_ERROR),
                           intent->offset,
                           intent->size,
                           ok ? written : 0,
                           ok ? intent->payload_hash : 0);

        cep_stream_record_outcome(intent, ok && written == intent->size, written, resulting_hash);
        cep_free(intent->payload);
        intent->payload = NULL;
        intent->intent_cell = NULL;
    }

    g_stream_intent_count = 0;
    return all_ok;
}

void cep_stream_clear_pending(void) {
    for (size_t i = 0; i < g_stream_intent_count; ++i) {
        cepStreamWriteIntent* intent = &g_stream_intents[i];
        if (intent->payload)
            cep_free(intent->payload);
        if (intent->intent_cell)
            cep_cell_delete_hard(intent->intent_cell);
    }
    g_stream_intent_count = 0;
}

size_t cep_stream_pending_count(void) {
    return g_stream_intent_count;
}
