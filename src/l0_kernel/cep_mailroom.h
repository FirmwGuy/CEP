/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_MAILROOM_H
#define CEP_MAILROOM_H

#include <stdbool.h>
#include <stddef.h>

#include "cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

bool cep_mailroom_bootstrap(void);
void cep_mailroom_shutdown(void);
bool cep_mailroom_register(cepEnzymeRegistry* registry);
bool cep_mailroom_add_namespace(const char* namespace_tag,
                                const char* const bucket_tags[],
                                size_t bucket_count);
bool cep_mailroom_add_router_before(const char* enzyme_tag);
bool cep_mailroom_enqueue_signal(const cepDT* namespace_dt,
                                 const cepDT* bucket_dt,
                                 const cepDT* txn_dt);

#ifdef __cplusplus
}
#endif

#endif /* CEP_MAILROOM_H */
