/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l0.h"

#include "cep_cell.h"
#include "cep_heartbeat.h"
#include "cep_namepool.h"
#include "cep_runtime.h"
#include "../enzymes/fed_pack.h"

bool cep_l0_bootstrap(void) {
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return false;
    }

    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    if (!cep_cell_system_initialized()) {
        cep_runtime_bootstrap_mark_done(runtime, false);
    }

    if (cep_runtime_bootstrap_is_done(runtime)) {
        cep_runtime_restore_active(previous_scope);
        return true;
    }

    if (!cep_fed_pack_bootstrap()) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_KERNEL);

    if (!cep_namepool_bootstrap()) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL);

    cep_runtime_bootstrap_mark_done(runtime, true);
    cep_runtime_restore_active(previous_scope);
    return true;
}

void cep_l0_bootstrap_reset(void) {
    cepRuntime* runtime = cep_runtime_default();
    if (runtime) {
        cepRuntime* previous_scope = cep_runtime_set_active(runtime);
        cep_runtime_bootstrap_mark_done(runtime, false);
        cep_runtime_restore_active(previous_scope);
    }
}
