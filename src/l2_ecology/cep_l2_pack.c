/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_pack.h"

#include "cep_l2_schema.h"
#include "cep_l2_runtime.h"
#include "../l0_kernel/cep_runtime.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_ops.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_organ.h"

typedef struct {
    bool   bootstrap_done;
    bool   l1_present;
    cepOID boot_oid;
    cepOID shdn_oid;
} cepL2PackState;

static cepL2PackState g_l2_pack_state = {0};

CEP_DEFINE_STATIC_DT(dt_l2_boot_verb, CEP_ACRO("CEP"), cep_namepool_intern_cstr("op/l2_boot"));
CEP_DEFINE_STATIC_DT(dt_l2_shdn_verb, CEP_ACRO("CEP"), cep_namepool_intern_cstr("op/l2_shdn"));
CEP_DEFINE_STATIC_DT(dt_l2_op_mode_states, CEP_ACRO("CEP"), CEP_WORD("opm:states"));
CEP_DEFINE_STATIC_DT(dt_l2_state_field, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_l2_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_l2_status_ok, CEP_ACRO("CEP"), CEP_WORD("sts:ok"));
CEP_DEFINE_STATIC_DT(dt_l2_status_fail, CEP_ACRO("CEP"), CEP_WORD("sts:fail"));
CEP_DEFINE_STATIC_DT(dt_l2_state_ready, CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_l2_state_halt, CEP_ACRO("CEP"), CEP_WORD("ist:halt"));

/* Writes `state` and optional `note` into the supplied cell, enforcing that the
 * target is a dictionary to keep layout consistent with other packs. */
static bool cep_l2_pack_record_state(cepCell* state_root,
                                     const cepDT* state_value,
                                     const char* note) {
    if (!state_root || !state_value) {
        return false;
    }

    cepCell* resolved = cep_cell_resolve(state_root);
    if (!resolved || !cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    if (!cep_cell_put_dt(resolved, dt_l2_state_field(), state_value)) {
        return false;
    }

    if (note && *note) {
        if (!cep_cell_put_text(resolved, dt_l2_note_field(), note)) {
            return false;
        }
    }

    return true;
}

/* Detects whether L1 coherence/pipeline organs are registered so L2 can wire
 * optional integrations without probing internals. */
static bool cep_l2_pack_detect_l1(void) {
    cepDT l1_store = cep_organ_store_dt("flow_spec_l1");
    const cepOrganDescriptor* desc = cep_dt_is_valid(&l1_store) ? cep_organ_descriptor(&l1_store) : NULL;
    return desc != NULL;
}

bool cep_l2_bootstrap(void) {
    if (g_l2_pack_state.bootstrap_done) {
        return true;
    }

    if (!cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL) ||
        !cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL)) {
        return false;
    }

    cepRuntime* runtime = cep_runtime_active();
    if (!runtime) {
        runtime = cep_runtime_default();
    }
    cepHeartbeatTopology* topo = runtime ? cep_runtime_default_topology(runtime) : NULL;
    if (!topo || !topo->data) {
        return false;
    }

    g_l2_pack_state.boot_oid = cep_op_start(*dt_l2_boot_verb(),
                                            "/data/eco",
                                            *dt_l2_op_mode_states(),
                                            NULL,
                                            0u,
                                            0u);

    g_l2_pack_state.l1_present = cep_l2_pack_detect_l1();

    cepCell* eco_root = NULL;
    cepCell* learn_root = NULL;
    if (!cep_l2_schema_seed_roots(topo->data, g_l2_pack_state.l1_present, &eco_root, &learn_root)) {
        (void)cep_op_close(g_l2_pack_state.boot_oid, *dt_l2_status_fail(), "schema_seed_failed", sizeof("schema_seed_failed") - 1u);
        return false;
    }
    (void)learn_root; /* kept for symmetry; future work will seed models. */

    if (!cep_l2_runtime_register_organs()) {
        (void)cep_op_close(g_l2_pack_state.boot_oid, *dt_l2_status_fail(), "organ_register_failed", sizeof("organ_register_failed") - 1u);
        return false;
    }

    if (!cep_l2_runtime_seed_runtime(eco_root)) {
        (void)cep_op_close(g_l2_pack_state.boot_oid, *dt_l2_status_fail(), "runtime_seed_failed", sizeof("runtime_seed_failed") - 1u);
        return false;
    }

    if (!cep_l2_runtime_scheduler_pump(eco_root, g_l2_pack_state.l1_present)) {
        (void)cep_op_close(g_l2_pack_state.boot_oid, *dt_l2_status_fail(), "scheduler_init_failed", sizeof("scheduler_init_failed") - 1u);
        return false;
    }

    cepCell* state_cell = cep_l2_schema_state_cell(eco_root);
    if (!state_cell || !cep_l2_pack_record_state(state_cell, dt_l2_state_ready(), "L2 ready")) {
        (void)cep_op_close(g_l2_pack_state.boot_oid, *dt_l2_status_fail(), "state_record_failed", sizeof("state_record_failed") - 1u);
        return false;
    }

    (void)cep_op_close(g_l2_pack_state.boot_oid, *dt_l2_status_ok(), "ok", sizeof("ok") - 1u);
    g_l2_pack_state.bootstrap_done = true;
    return true;
}

bool cep_l2_shutdown(void) {
    if (!g_l2_pack_state.bootstrap_done) {
        return true;
    }

    g_l2_pack_state.shdn_oid = cep_op_start(*dt_l2_shdn_verb(),
                                            "/data/eco",
                                            *dt_l2_op_mode_states(),
                                            NULL,
                                            0u,
                                            0u);

    cepRuntime* runtime = cep_runtime_active();
    if (!runtime) {
        runtime = cep_runtime_default();
    }
    cepHeartbeatTopology* topo = runtime ? cep_runtime_default_topology(runtime) : NULL;
    cepCell* eco_root = topo ? topo->data : NULL;
    cepCell* state_cell = eco_root ? cep_l2_schema_state_cell(eco_root) : NULL;
    if (state_cell) {
        (void)cep_l2_pack_record_state(state_cell, dt_l2_state_halt(), "L2 shutdown");
    }

    (void)cep_op_close(g_l2_pack_state.shdn_oid, *dt_l2_status_ok(), "ok", sizeof("ok") - 1u);
    g_l2_pack_state.bootstrap_done = false;
    return true;
}

bool cep_l2_l1_present(void) {
    return g_l2_pack_state.l1_present;
}
