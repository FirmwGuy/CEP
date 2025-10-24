/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_STREAM_INTERNAL_H
#define CEP_STREAM_INTERNAL_H

#include "cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CEP_STREAM_JOURNAL_READ   = 1u << 0,
    CEP_STREAM_JOURNAL_WRITE  = 1u << 1,
    CEP_STREAM_JOURNAL_ERROR  = 1u << 2,
    CEP_STREAM_JOURNAL_COMMIT = 1u << 3,
};

typedef struct cepStreamWriteIntent cepStreamWriteIntent;

typedef struct {
    uint64_t offset;
    uint64_t requested;
    uint64_t actual;
    uint64_t payload_hash;
    uint64_t expected_hash;
    uint64_t idempotency_key;
    uint64_t staged_at;
    uint32_t flags;
    uint32_t reserved;
} cepStreamIntentEntry;

typedef struct {
    uint64_t offset;
    uint64_t length;
    uint64_t payload_hash;
    uint64_t expected_hash;
    uint64_t resulting_hash;
    uint64_t idempotency_key;
    uint64_t committed_at;
    uint32_t flags;
    uint32_t reserved;
    uint64_t unix_ts_ns;
} cepStreamOutcomeEntry;

enum {
    CEP_STREAM_INTENT_PENDING   = 1u << 0,
    CEP_STREAM_INTENT_COMMITTED = 1u << 1,
    CEP_STREAM_INTENT_DIVERGED  = 1u << 2,
};

void cep_stream_journal(cepCell* owner, unsigned flags, uint64_t offset, size_t requested, size_t actual, uint64_t hash);

bool cep_stream_stage_write(cepCell* owner,
                            cepCell* library,
                            cepCell* resource,
                            uint64_t offset,
                            const void* payload,
                            size_t size,
                            uint64_t expected_hash);

bool cep_stream_commit_pending(void);
void cep_stream_clear_pending(void);
size_t cep_stream_pending_count(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_STREAM_INTERNAL_H */
