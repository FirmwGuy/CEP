#include "cep_l0.h"

#include "cep_cell.h"
#include "cep_heartbeat.h"
#include "cep_mailroom.h"
#include "cep_namepool.h"

static bool cep_l0_bootstrap_done = false;

bool cep_l0_bootstrap(void) {
    if (!cep_cell_system_initialized()) {
        cep_l0_bootstrap_done = false;
    }

    if (cep_l0_bootstrap_done) {
        return true;
    }

    cep_cell_system_ensure();

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_KERNEL);

    if (!cep_namepool_bootstrap()) {
        return false;
    }

    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL);

    if (!cep_mailroom_bootstrap()) {
        return false;
    }

    cep_l0_bootstrap_done = true;
    return true;
}

void cep_l0_bootstrap_reset(void) {
    cep_l0_bootstrap_done = false;
}
