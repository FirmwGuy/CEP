#ifndef CEP_EP_H
#define CEP_EP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cep_cell.h"
#include "cep_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

bool cep_ep_stream_write(cepCell* cell, uint64_t offset, const void* src, size_t size, size_t* out_written);
bool cep_ep_stream_commit_pending(void);
void cep_ep_stream_clear_pending(void);
size_t cep_ep_stream_pending_count(void);
bool cep_ep_cancel_ticket(cepExecutorTicket ticket);
void cep_ep_request_cancel(void);

bool cep_ep_check_cancel(void);
void cep_ep_account_io(size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* CEP_EP_H */
