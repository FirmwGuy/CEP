#ifndef CEP_EP_H
#define CEP_EP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cep_cell.h"
#include "cep_executor.h"
#include "cep_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef cepOID cepEID;

typedef void (*cepEpCallback)(cepEID eid, void* user_context);

bool cep_ep_start(cepEID* out_eid,
                  const cepPath* signal_path,
                  const cepPath* target_path,
                  cepEpCallback callback,
                  void* user_context,
                  const cepEpExecutionPolicy* policy,
                  uint64_t max_beats);

bool cep_ep_yield(cepEID eid, const char* note);
bool cep_ep_await(cepEID eid,
                  cepOID awaited_oid,
                  cepDT want_state,
                  uint32_t ttl_beats,
                  const char* note);
bool cep_ep_close(cepEID eid, cepDT status, const void* summary, size_t summary_len);
bool cep_ep_cancel(cepEID eid, int code, const char* note);
bool cep_ep_request_lease(cepEID eid,
                          const cepPath* root,
                          bool lock_store,
                          bool lock_data,
                          bool include_descendants);
bool cep_ep_release_lease(cepEID eid, const cepPath* root);

bool cep_ep_stream_write(cepCell* cell, uint64_t offset, const void* src, size_t size, size_t* out_written);
bool cep_ep_stream_commit_pending(void);
void cep_ep_stream_clear_pending(void);
size_t cep_ep_stream_pending_count(void);
bool cep_ep_cancel_ticket(cepExecutorTicket ticket);
void cep_ep_request_cancel(void);

bool cep_ep_check_cancel(void);
void cep_ep_account_io(size_t bytes);

bool cep_ep_handle_continuation(const cepDT* continuation, cepOID target_oid);
void cep_ep_runtime_reset(void);

bool cep_ep_episode_has_active_lease(const void* episode_ptr);
bool cep_ep_episode_record_violation(void* episode_ptr);
void cep_ep_episode_clear_violation(void* episode_ptr);

#ifdef __cplusplus
}
#endif

#endif /* CEP_EP_H */
