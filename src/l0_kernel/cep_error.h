#ifndef CEP_ERROR_H
#define CEP_ERROR_H

#include <stddef.h>
#include "cep_cell.h"
#include "cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CEP_ERR_FATAL = 0,
    CEP_ERR_CRITICAL,
    CEP_ERR_USAGE,
    CEP_ERR_WARN,
    CEP_ERR_LOG,
} cepErrLevel;

typedef struct {
    cepDT        code;
    const char*  message;
    cepCell*     target;
    cepCell**    parents;
    size_t       parent_count;
    cepCell*     detail;
    cepDT        scope;
} cepErrorSpec;

bool cep_error_emit(cepErrLevel level, const cepErrorSpec* spec);

#ifdef __cplusplus
}
#endif

#endif
