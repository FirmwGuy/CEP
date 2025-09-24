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

void cep_stream_journal(cepCell* owner, unsigned flags, uint64_t offset, size_t requested, size_t actual, uint64_t hash);

#ifdef __cplusplus
}
#endif

#endif /* CEP_STREAM_INTERNAL_H */
