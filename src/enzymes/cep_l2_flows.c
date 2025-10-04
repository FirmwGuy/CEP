/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_flows.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/*  Canonical tags                                                           */
/* ------------------------------------------------------------------------- */

/* These accessors keep tag lookups lazy so the compiler can fold the DT
 * constants while keeping call sites clean and consistent with the L1 module. */
static const cepDT* dt_data_root(void)   { return CEP_DTAW("CEP", "data"); }
static const cepDT* dt_tmp_root(void)    { return CEP_DTAW("CEP", "tmp"); }
static const cepDT* dt_dictionary(void)  { return CEP_DTAW("CEP", "dictionary"); }
static const cepDT* dt_flow(void)        { return CEP_DTAW("CEP", "flow"); }
static const cepDT* dt_program(void)     { return CEP_DTAW("CEP", "program"); }
static const cepDT* dt_policy(void)      { return CEP_DTAW("CEP", "policy"); }
static const cepDT* dt_variant(void)     { return CEP_DTAW("CEP", "variant"); }
static const cepDT* dt_niche(void)       { return CEP_DTAW("CEP", "niche"); }
static const cepDT* dt_guardian(void)    { return CEP_DTAW("CEP", "guardian"); }
static const cepDT* dt_instance(void)    { return CEP_DTAW("CEP", "instance"); }
static const cepDT* dt_decision(void)    { return CEP_DTAW("CEP", "decision"); }
static const cepDT* dt_index(void)       { return CEP_DTAW("CEP", "index"); }
static const cepDT* dt_inbox(void)       { return CEP_DTAW("CEP", "inbox"); }
static const cepDT* dt_adj(void)         { return CEP_DTAW("CEP", "adj"); }
static const cepDT* dt_signal_cell(void) { return CEP_DTAW("CEP", "sig_cell"); }
static const cepDT* dt_op_add(void)      { return CEP_DTAW("CEP", "op_add"); }
static const cepDT* dt_fl_upsert(void)   { return CEP_DTAW("CEP", "fl_upsert"); }
static const cepDT* dt_ni_upsert(void)   { return CEP_DTAW("CEP", "ni_upsert"); }
static const cepDT* dt_inst_start(void)  { return CEP_DTAW("CEP", "inst_start"); }
static const cepDT* dt_inst_event(void)  { return CEP_DTAW("CEP", "inst_event"); }
static const cepDT* dt_inst_ctrl(void)   { return CEP_DTAW("CEP", "inst_ctrl"); }
static const cepDT* dt_fl_ing(void)      { return CEP_DTAW("CEP", "fl_ing"); }
static const cepDT* dt_ni_ing(void)      { return CEP_DTAW("CEP", "ni_ing"); }
static const cepDT* dt_inst_ing(void)    { return CEP_DTAW("CEP", "inst_ing"); }
static const cepDT* dt_fl_wake(void)     { return CEP_DTAW("CEP", "fl_wake"); }
static const cepDT* dt_fl_step(void)     { return CEP_DTAW("CEP", "fl_step"); }
static const cepDT* dt_fl_index(void)    { return CEP_DTAW("CEP", "fl_index"); }
static const cepDT* dt_fl_adj(void)      { return CEP_DTAW("CEP", "fl_adj"); }

/* ------------------------------------------------------------------------- */
/*  Local state                                                              */
/* ------------------------------------------------------------------------- */

static bool cep_l2_bindings_applied = false;

/* ------------------------------------------------------------------------- */
/*  Small helpers                                                            */
/* ------------------------------------------------------------------------- */

/* This helper mirrors the L1 dictionary bootstrap behaviour by creating the
 * requested child when missing while staying idempotent when the node already
 * exists. It keeps bootstrap call sites compact and readable. */
static cepCell* cep_l2_ensure_dictionary(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        return existing;
    }

    cepDT type = *dt_dictionary();
    cepDT copy = *name;
    return cep_dict_add_dictionary(parent, &copy, &type, storage);
}


/* ------------------------------------------------------------------------- */
/*  Bootstrap                                                                */
/* ------------------------------------------------------------------------- */

/* This helper materialises `/data` so subsequent bootstrap steps can create
 * the flow subtree regardless of the order in which higher layers initialise
 * the runtime. */
static cepCell* cep_l2_data_root(void) {
    cepCell* root = cep_root();
    cepCell* data = cep_cell_find_by_name(root, dt_data_root());
    if (!data) {
        data = cep_l2_ensure_dictionary(root, dt_data_root(), CEP_STORAGE_RED_BLACK_T);
    }
    return data;
}

/* This helper creates (or retrieves) `/data/flow`, serving as the anchor for
 * L2 ledgers. */
static cepCell* cep_l2_flow_root(void) {
    cepCell* data = cep_l2_data_root();
    if (!data) {
        return NULL;
    }
    return cep_l2_ensure_dictionary(data, dt_flow(), CEP_STORAGE_RED_BLACK_T);
}

/* This helper creates all durable ledgers that L2 relies on so that ingest and
 * stepper callbacks can assume the directories already exist. */
static bool cep_l2_bootstrap_ledgers(cepCell* flow_root) {
    if (!flow_root) {
        return false;
    }

    if (!cep_l2_ensure_dictionary(flow_root, dt_program(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_policy(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_variant(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_niche(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_guardian(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_instance(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_decision(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(flow_root, dt_index(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    cepCell* inbox = cep_l2_ensure_dictionary(flow_root, dt_inbox(), CEP_STORAGE_RED_BLACK_T);
    if (!inbox) {
        return false;
    }

    if (!cep_l2_ensure_dictionary(inbox, dt_fl_upsert(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_ni_upsert(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_inst_start(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_inst_event(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_l2_ensure_dictionary(inbox, dt_inst_ctrl(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }

    return true;
}

/* This helper mirrors the L1 pattern for `/tmp`, allowing L2 to host transient
 * caches without polluting durable ledgers. */
static bool cep_l2_bootstrap_tmp(void) {
    cepCell* root = cep_root();
    if (!root) {
        return false;
    }

    cepCell* tmp_root = cep_l2_ensure_dictionary(root, dt_tmp_root(), CEP_STORAGE_RED_BLACK_T);
    if (!tmp_root) {
        return false;
    }

    cepCell* flow_tmp = cep_l2_ensure_dictionary(tmp_root, dt_flow(), CEP_STORAGE_RED_BLACK_T);
    if (!flow_tmp) {
        return false;
    }

    cepCell* adj_root = cep_l2_ensure_dictionary(flow_tmp, dt_adj(), CEP_STORAGE_RED_BLACK_T);
    if (!adj_root) {
        return false;
    }

    /* Additional adjacency buckets will be created on demand by the enzymes. */
    return true;
}

/* This helper coordinates the whole bootstrap sequence so callers can rely on
 * a single public function to prepare the flow layer. */
bool cep_l2_flows_bootstrap(void) {
    if (!cep_cell_system_initialized()) {
        return false;
    }

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return false;
    }

    if (!cep_l2_bootstrap_ledgers(flow_root)) {
        return false;
    }

    if (!cep_l2_bootstrap_tmp()) {
        return false;
    }

    cep_namepool_bootstrap();
    return true;
}

/* ------------------------------------------------------------------------- */
/*  Enzyme callbacks (skeletons)                                             */
/* ------------------------------------------------------------------------- */

/* The ingest enzyme will eventually canonicalise flow definitions. For now we
 * stage a placeholder so the agenda wiring compiles while leaving TODO markers
 * for the substantive work. */
static int cep_l2_enzyme_fl_ingest(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement ingestion for flow programs, variants, policies, and guardians.
    return CEP_ENZYME_SUCCESS;
}

/* The niche ingest enzyme will resolve routing maps once implemented. */
static int cep_l2_enzyme_ni_ingest(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement ingestion for niche intents.
    return CEP_ENZYME_SUCCESS;
}

/* Instance ingestion will start and control state machines when the runtime is
 * fully wired; currently it only marks the future work. */
static int cep_l2_enzyme_inst_ingest(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement ingestion for instance start/control intents.
    return CEP_ENZYME_SUCCESS;
}

/* Event wakeups will later match subscriptions. */
static int cep_l2_enzyme_fl_wake(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement wakeup matching between inst_event intents and wait subscriptions.
    return CEP_ENZYME_SUCCESS;
}

/* The VM stepper will eventually execute Guard/Transform/Wait/Decide/Clamp. */
static int cep_l2_enzyme_fl_step(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement the deterministic Flow VM stepper.
    return CEP_ENZYME_SUCCESS;
}

/* Index rebuilding keeps durable lookup tables fresh once the ingest logic is
 * active. */
static int cep_l2_enzyme_fl_index(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement durable index maintenance for Layer 2.
    return CEP_ENZYME_SUCCESS;
}

/* Transient cache refresh mirrors the index pattern for `/tmp/flow/adj`. */
static int cep_l2_enzyme_fl_adj(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    // TODO(l2): Implement cache refresh for transient adjacency structures.
    return CEP_ENZYME_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/*  Registration                                                             */
/* ------------------------------------------------------------------------- */

/* This helper binds all L2 enzyme identifiers onto the `/data/flow` subtree so
 * resolve scoring favours the intended handlers when multiple candidates
 * compete. */
static bool cep_l2_apply_bindings(void) {
    if (cep_l2_bindings_applied) {
        return true;
    }

    cepCell* flow_root = cep_l2_flow_root();
    if (!flow_root) {
        return false;
    }

    (void)cep_cell_bind_enzyme(flow_root, dt_fl_ing(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_ni_ing(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_inst_ing(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_wake(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_step(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_index(), true);
    (void)cep_cell_bind_enzyme(flow_root, dt_fl_adj(), true);

    cep_l2_bindings_applied = true;
    return true;
}

/* This helper stages the seven descriptors on the registry, wiring before/after
 * dependencies to mirror the agenda detailed in L2.md. */
bool cep_l2_flows_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return false;
    }

    if (!cep_l2_flows_bootstrap()) {
        return false;
    }

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast  past[2];
    } cepPathStatic2;

    cepPathStatic2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_signal_cell(), .timestamp = 0u},
            {.dt = *dt_op_add(), .timestamp = 0u},
        },
    };

    cepDT after_ni[] = { *dt_fl_ing() };
    cepDT after_inst[] = { *dt_ni_ing() };
    cepDT after_wake[] = { *dt_inst_ing() };
    cepDT after_step[] = { *dt_fl_wake() };
    cepDT after_index[] = { *dt_fl_step() };
    cepDT after_adj[] = { *dt_fl_index() };

    cepEnzymeDescriptor descriptors[] = {
        {
            .name = *dt_fl_ing(),
            .label = "l2.fl.ingest",
            .callback = cep_l2_enzyme_fl_ingest,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        },
        {
            .name = *dt_ni_ing(),
            .label = "l2.ni.ingest",
            .callback = cep_l2_enzyme_ni_ingest,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_ni,
            .after_count = sizeof after_ni / sizeof after_ni[0],
        },
        {
            .name = *dt_inst_ing(),
            .label = "l2.inst.ingest",
            .callback = cep_l2_enzyme_inst_ingest,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_inst,
            .after_count = sizeof after_inst / sizeof after_inst[0],
        },
        {
            .name = *dt_fl_wake(),
            .label = "l2.fl.wake",
            .callback = cep_l2_enzyme_fl_wake,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_wake,
            .after_count = sizeof after_wake / sizeof after_wake[0],
        },
        {
            .name = *dt_fl_step(),
            .label = "l2.fl.step",
            .callback = cep_l2_enzyme_fl_step,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_step,
            .after_count = sizeof after_step / sizeof after_step[0],
        },
        {
            .name = *dt_fl_index(),
            .label = "l2.fl.index",
            .callback = cep_l2_enzyme_fl_index,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_index,
            .after_count = sizeof after_index / sizeof after_index[0],
        },
        {
            .name = *dt_fl_adj(),
            .label = "l2.fl.adj",
            .callback = cep_l2_enzyme_fl_adj,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
            .after = after_adj,
            .after_count = sizeof after_adj / sizeof after_adj[0],
        },
    };

    for (size_t i = 0; i < sizeof descriptors / sizeof descriptors[0]; ++i) {
        if (cep_enzyme_register(registry, (const cepPath*)&signal_path, &descriptors[i]) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    if (!cep_l2_apply_bindings()) {
        return false;
    }

    return true;
}
