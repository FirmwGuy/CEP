#ifndef CEP_STREAM_ZIP_H
#define CEP_STREAM_ZIP_H

#include "cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CEP_HAS_LIBZIP

bool cep_zip_library_open(cepCell* library, cepDT* name, const char* archive_path, int flags);
void cep_zip_library_close(cepCell* library);
bool cep_zip_entry_init(cepCell* resource, cepDT* name, cepCell* library, const char* entry_name, bool create_if_missing);
void cep_zip_stream_init(cepCell* stream, cepDT* name, cepCell* library, cepCell* entry);

#endif /* CEP_HAS_LIBZIP */

#ifdef __cplusplus
}
#endif

#endif /* CEP_STREAM_ZIP_H */
