/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef CEP_CPS_RUNTIME_H
#define CEP_CPS_RUNTIME_H

#include <stdbool.h>

#include "cps_engine.h"

bool        cps_runtime_bootstrap(void);
void        cps_runtime_shutdown(void);
bool        cps_runtime_is_ready(void);
cps_engine* cps_runtime_engine(void);

#endif /* CEP_CPS_RUNTIME_H */
