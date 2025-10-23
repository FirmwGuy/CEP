#ifndef CEP_L0_ORGANS_H
#define CEP_L0_ORGANS_H

#include "../l0_kernel/cep_enzyme.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool cep_l0_organs_register(cepEnzymeRegistry* registry);
bool cep_l0_organs_bind_roots(void);
void cep_l0_organs_invalidate_signals(void);
void cep_l0_organs_refresh_store_dts(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L0_ORGANS_H */
