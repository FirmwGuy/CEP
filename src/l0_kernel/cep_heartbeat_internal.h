/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

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
