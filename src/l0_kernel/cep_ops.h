/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_OPS_H
#define CEP_OPS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cep_cell.h"
#include "cep_heartbeat.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    cepID domain;
    cepID tag;
} cepOID;

static inline cepOID cep_oid_invalid(void) {
    cepOID oid = {0u, 0u};
    return oid;
}

static inline bool cep_oid_is_valid(cepOID oid) {
    return oid.domain != 0u && oid.tag != 0u && !cep_id_is_auto(oid.tag);
}

cepOID cep_op_start(cepDT verb,
                    const char* target,
                    cepDT mode,
                    const void* payload,
                    size_t payload_len,
                    uint32_t ttl_beats);

bool cep_op_state_set(cepOID oid, cepDT state, int code, const char* note);

bool cep_op_await(cepOID oid,
                  cepDT want,
                  uint32_t ttl_beats,
                  cepDT continuation_signal,
                  const void* payload,
                  size_t payload_len);

bool cep_op_close(cepOID oid,
                  cepDT status,
                  const void* summary,
                  size_t summary_len);

bool cep_op_get(cepOID oid, char* buffer, size_t capacity);

bool cep_ops_stage_commit(void);

int cep_ops_debug_last_error(void);

cepDT cep_ops_make_dt(const char* tag);

typedef struct {
    cepDT   state;
    cepDT   channel;
    cepDT   opcode;
    uint32_t beats_budget;
    bool    has_beats_budget;
    uint64_t deadline_beat;
    bool    has_deadline_beat;
    uint64_t deadline_unix_ns;
    bool    has_deadline_unix_ns;
    uint64_t bytes_expected;
    bool    has_bytes_expected;
    uint64_t bytes_done;
    bool    has_bytes_done;
    int32_t errno_code;
    bool    has_errno;
    cepDT   telemetry;
    bool    has_telemetry;
} cepOpsAsyncIoReqInfo;

typedef struct {
    const char* target_path;
    bool        has_target_path;
    cepDT       provider;
    bool        has_provider;
    cepDT       reactor;
    bool        has_reactor;
    cepDT       caps;
    bool        has_caps;
    bool        shim;
    bool        shim_known;
} cepOpsAsyncChannelInfo;

typedef struct {
    bool     draining;
    bool     draining_known;
    bool     paused;
    bool     paused_known;
    bool     shutting_down;
    bool     shutting_known;
    uint32_t deadline_beats;
    bool     deadline_known;
} cepOpsAsyncReactorState;

bool cep_op_async_record_request(cepOID oid,
                                 const cepDT* request_name,
                                 const cepOpsAsyncIoReqInfo* info);

bool cep_op_async_record_channel(cepOID oid,
                                 const cepDT* channel_name,
                                 const cepOpsAsyncChannelInfo* info);

bool cep_op_async_set_reactor_state(cepOID oid,
                                    const cepOpsAsyncReactorState* state);

#ifdef __cplusplus
}
#endif

#endif /* CEP_OPS_H */
