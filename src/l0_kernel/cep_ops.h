#ifndef CEP_OPS_H
#define CEP_OPS_H

#include <stddef.h>

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

#ifdef __cplusplus
}
#endif

#endif /* CEP_OPS_H */
