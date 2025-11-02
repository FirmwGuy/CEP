#ifndef CEP_FED_PACK_H
#define CEP_FED_PACK_H

#include "../l0_kernel/cep_cell.h"
#include "fed_transport_manager.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bootstrap the federation pack layout and organ descriptors. */
bool cep_fed_pack_bootstrap(void);

/* Ensure key `/net` branches exist relative to the provided root. */
bool cep_fed_pack_ensure_roots(cepCell* net_root,
                               cepCell** peers_root,
                               cepCell** catalog_root,
                               cepCell** telemetry_root,
                               cepCell** organs_root);

/* Retrieve the shared federation transport manager initialised during bootstrap. */
cepFedTransportManager* cep_fed_pack_manager(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FED_PACK_H */
