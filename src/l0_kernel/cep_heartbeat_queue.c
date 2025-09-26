/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include <stdint.h>
#include <string.h>

#include "cep_heartbeat_internal.h"

static cepPath* cep_heartbeat_path_clone(const cepPath* path) {
    if (!path) {
        return NULL;
    }

    size_t bytes = sizeof(cepPath) + (size_t)path->length * sizeof(cepPast);
    cepPath* clone = cep_malloc(bytes);
    if (!clone) {
        return NULL;
    }

    clone->length = path->length;
    clone->capacity = path->length;
    memcpy(clone->past, path->past, (size_t)path->length * sizeof(cepPast));
    return clone;
}

void cep_heartbeat_impulse_record_clear(cepHeartbeatImpulseRecord* record) {
    if (!record) {
        return;
    }

    CEP_FREE(record->signal_path);
    CEP_FREE(record->target_path);
    CEP_0(record);
}

void cep_heartbeat_impulse_queue_reset(cepHeartbeatImpulseQueue* queue) {
    if (!queue || !queue->records) {
        if (queue) {
            queue->count = 0u;
        }
        return;
    }

    for (size_t i = 0; i < queue->count; ++i) {
        cep_heartbeat_impulse_record_clear(&queue->records[i]);
    }
    queue->count = 0u;
}

void cep_heartbeat_impulse_queue_destroy(cepHeartbeatImpulseQueue* queue) {
    if (!queue) {
        return;
    }

    if (queue->records) {
        for (size_t i = 0; i < queue->capacity; ++i) {
            cep_heartbeat_impulse_record_clear(&queue->records[i]);
        }
        CEP_FREE(queue->records);
    }

    queue->records = NULL;
    queue->count = 0u;
    queue->capacity = 0u;
}

static bool cep_heartbeat_impulse_queue_reserve(cepHeartbeatImpulseQueue* queue, size_t capacity) {
    if (!queue) {
        return false;
    }

    if (queue->capacity >= capacity) {
        return true;
    }

    size_t new_capacity = queue->capacity ? queue->capacity * 2u : 8u;
    if (new_capacity < capacity) {
        new_capacity = capacity;
    }

    size_t bytes = new_capacity * sizeof(*queue->records);
    cepHeartbeatImpulseRecord* records = queue->records ? cep_realloc(queue->records, bytes) : cep_malloc(bytes);
    if (!records) {
        return false;
    }

    if (new_capacity > queue->capacity) {
        size_t old_bytes = queue->capacity * sizeof(*queue->records);
        memset(((uint8_t*)records) + old_bytes, 0, bytes - old_bytes);
    }

    queue->records = records;
    queue->capacity = new_capacity;
    return true;
}

bool cep_heartbeat_impulse_queue_append(cepHeartbeatImpulseQueue* queue, const cepImpulse* impulse) {
    if (!queue || !impulse) {
        return false;
    }

    if (!cep_heartbeat_impulse_queue_reserve(queue, queue->count + 1u)) {
        return false;
    }

    cepHeartbeatImpulseRecord* record = &queue->records[queue->count];
    CEP_0(record);

    if (impulse->signal_path) {
        record->signal_path = cep_heartbeat_path_clone(impulse->signal_path);
        if (!record->signal_path) {
            cep_heartbeat_impulse_record_clear(record);
            return false;
        }
    }

    if (impulse->target_path) {
        record->target_path = cep_heartbeat_path_clone(impulse->target_path);
        if (!record->target_path) {
            cep_heartbeat_impulse_record_clear(record);
            return false;
        }
    }

    queue->count += 1u;
    return true;
}

void cep_heartbeat_impulse_queue_swap(cepHeartbeatImpulseQueue* a, cepHeartbeatImpulseQueue* b) {
    if (!a || !b) {
        return;
    }

    CEP_SWAP(*a, *b);
}

