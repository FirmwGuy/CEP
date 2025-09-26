/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_HEARTBEAT_INTERNAL_H
#define CEP_HEARTBEAT_INTERNAL_H

#include "cep_heartbeat.h"

#ifdef __cplusplus
extern "C" {
#endif

void                cep_heartbeat_impulse_record_clear(cepHeartbeatImpulseRecord* record);
void                cep_heartbeat_impulse_queue_reset(cepHeartbeatImpulseQueue* queue);
void                cep_heartbeat_impulse_queue_destroy(cepHeartbeatImpulseQueue* queue);
bool                cep_heartbeat_impulse_queue_append(cepHeartbeatImpulseQueue* queue, const cepImpulse* impulse);
void                cep_heartbeat_impulse_queue_swap(cepHeartbeatImpulseQueue* a, cepHeartbeatImpulseQueue* b);

#ifdef __cplusplus
}
#endif

#endif
