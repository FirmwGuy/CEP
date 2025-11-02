#ifndef CEP_FED_MIRROR_ORGAN_H
#define CEP_FED_MIRROR_ORGAN_H

#include "fed_transport_manager.h"
#include "../l0_kernel/cep_cell.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool cep_fed_mirror_organ_init(cepFedTransportManager* manager,
                               cepCell* net_root);

int cep_fed_mirror_validator(const cepPath* signal_path,
                             const cepPath* target_path);

int cep_fed_mirror_destructor(const cepPath* signal_path,
                              const cepPath* target_path);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FED_MIRROR_ORGAN_H */
