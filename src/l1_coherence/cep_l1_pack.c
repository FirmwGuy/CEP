/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_pack.h"

#include "cep_l1_schema.h"
#include "cep_l1_coherence.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_runtime.h"

#include <string.h>

CEP_DEFINE_STATIC_DT(dt_l1_boot_verb, CEP_ACRO("CEP"), CEP_WORD("op/l1_boot"));
CEP_DEFINE_STATIC_DT(dt_l1_shdn_verb, CEP_ACRO("CEP"), CEP_WORD("op/l1_shdn"));
CEP_DEFINE_STATIC_DT(dt_l1_op_mode_states, CEP_ACRO("CEP"), CEP_WORD("opm:states"));
CEP_DEFINE_STATIC_DT(dt_l1_state_field, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_l1_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_l1_status_ok, CEP_ACRO("CEP"), CEP_WORD("sts:ok"));
CEP_DEFINE_STATIC_DT(dt_l1_status_fail, CEP_ACRO("CEP"), CEP_WORD("sts:fail"));
CEP_DEFINE_STATIC_DT(dt_l1_state_ok, CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_l1_state_halt, CEP_ACRO("CEP"), CEP_WORD("ist:halt"));

typedef struct {
    bool              bootstrap_done;
    cepOID            boot_oid;
    cepL1SchemaLayout layout;
} cepL1PackState;

static cepL1PackState g_l1_pack_state = {0};

static bool cep_l1_pack_prereqs_ready(void) {
    return cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL) &&
           cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL);
}

static bool cep_l1_pack_record_state(cepCell* state_root,
                                     const cepDT* state_value,
                                     const char* note) {
    if (!state_root || !state_value) {
        return false;
    }

    cepCell* resolved = cep_cell_resolve(state_root);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    if (!cep_cell_put_dt(resolved, dt_l1_state_field(), state_value)) {
        return false;
    }

    if (note && note[0]) {
        if (!cep_cell_put_text(resolved, dt_l1_note_field(), note)) {
            return false;
        }
    }

    return true;
}

static bool cep_l1_pack_start_boot_op(cepL1PackState* state) {
    if (!state) {
        return false;
    }
    if (cep_oid_is_valid(state->boot_oid)) {
        return true;
    }
    cepOID oid = cep_op_start(*dt_l1_boot_verb(),
                              "/data/flow",
                              *dt_l1_op_mode_states(),
                              NULL,
                              0u,
                              0u);
    if (!cep_oid_is_valid(oid)) {
        return false;
    }
    state->boot_oid = oid;
    return true;
}

static void cep_l1_pack_fail_boot_op(const cepL1PackState* state) {
    if (!state) {
        return;
    }
    if (!cep_oid_is_valid(state->boot_oid)) {
        return;
    }
    (void)cep_op_close(state->boot_oid, *dt_l1_status_fail(), NULL, 0u);
}

/* Bring the Layer 1 pack online by ensuring the coherence/flow layout exists,
   publishing a pack-scoped boot operation, and recording a ready state that
   higher layers can watch without touching kernel lifecycle scopes. The helper
   is idempotent so repeated bootstraps only refresh handles. */
bool cep_l1_pack_bootstrap(void) {
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return false;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    if (!cep_l1_pack_prereqs_ready()) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (g_l1_pack_state.bootstrap_done) {
        (void)cep_l1_schema_ensure(&g_l1_pack_state.layout);
        cep_runtime_restore_active(previous_scope);
        return true;
    }

    if (!cep_l1_schema_ensure(&g_l1_pack_state.layout)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    (void)cep_l1_coh_register_closure_enzyme();

    if (!cep_l1_pack_start_boot_op(&g_l1_pack_state)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!cep_l1_pack_record_state(g_l1_pack_state.layout.flow_state,
                                  dt_l1_state_ok(),
                                  "Layer 1 pack ready")) {
        cep_l1_pack_fail_boot_op(&g_l1_pack_state);
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    if (!cep_op_close(g_l1_pack_state.boot_oid, *dt_l1_status_ok(), NULL, 0u)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    g_l1_pack_state.bootstrap_done = true;
    cep_runtime_restore_active(previous_scope);
    return true;
}

/* Roll back the Layer 1 pack readiness markers so the next bootstrap can rebuild
   the layout and emit fresh readiness evidence without assuming prior state.
   No attempt is made to prune existing pipeline/runtime records yet. */
bool cep_l1_pack_shutdown(void) {
    cepRuntime* runtime = cep_runtime_default();
    if (!runtime) {
        return false;
    }
    cepRuntime* previous_scope = cep_runtime_set_active(runtime);

    cepL1SchemaLayout layout = {0};
    if (!cep_l1_schema_ensure(&layout)) {
        cep_runtime_restore_active(previous_scope);
        return false;
    }

    cepOID shutdown_oid = cep_op_start(*dt_l1_shdn_verb(),
                                       "/data/flow",
                                       *dt_l1_op_mode_states(),
                                       NULL,
                                       0u,
                                       0u);
    if (cep_oid_is_valid(shutdown_oid)) {
        (void)cep_l1_pack_record_state(layout.flow_state,
                                       dt_l1_state_halt(),
                                       "Layer 1 pack shutdown");
        (void)cep_op_close(shutdown_oid, *dt_l1_status_ok(), NULL, 0u);
    }

    g_l1_pack_state.bootstrap_done = false;
    g_l1_pack_state.boot_oid = cep_oid_invalid();
    memset(&g_l1_pack_state.layout, 0, sizeof g_l1_pack_state.layout);

    cep_runtime_restore_active(previous_scope);
    return true;
}
