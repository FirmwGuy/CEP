/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l1_coherence.h"

#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../l0_kernel/cep_heartbeat.h"

#include <stdio.h>
#include <string.h>

CEP_DEFINE_STATIC_DT(dt_being_id_field,   CEP_ACRO("CEP"), CEP_WORD("being_id"));
CEP_DEFINE_STATIC_DT(dt_bond_id_field,    CEP_ACRO("CEP"), CEP_WORD("bond_id"));
CEP_DEFINE_STATIC_DT(dt_context_id_field, CEP_ACRO("CEP"), CEP_WORD("ctx_id"));
CEP_DEFINE_STATIC_DT(dt_role_field,       CEP_ACRO("CEP"), CEP_WORD("role"));
CEP_DEFINE_STATIC_DT(dt_note_field_coh,   CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_state_field_coh,  CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_debt_state_open,  CEP_ACRO("CEP"), CEP_WORD("ist:open"));
CEP_DEFINE_STATIC_DT(dt_debt_state_done,  CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_closure_signal,   CEP_ACRO("CEP"), CEP_WORD("coh:close"));
CEP_DEFINE_STATIC_DT(dt_participants_name, CEP_ACRO("CEP"), CEP_WORD("beings"));
CEP_DEFINE_STATIC_DT(dt_target_field_coh, CEP_ACRO("CEP"), CEP_WORD("target"));

static bool cep_l1_coh_make_dt(const char* id, cepDT* out) {
    if (!id || !out) {
        return false;
    }
    size_t len = strlen(id);
    if (len == 0u) {
        return false;
    }
    cepID tag = cep_namepool_intern(id, len);
    if (!tag) {
        return false;
    }
    out->domain = cep_namepool_intern_cstr("CEP");
    out->tag = tag;
    return cep_dt_is_valid(out);
}

static bool cep_l1_coh_require_dict(cepCell* parent,
                                    const cepDT* name,
                                    cepCell** out) {
    if (!parent || !name) {
        return false;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return false;
    }
    if (out) {
        *out = child;
    }
    return true;
}

static bool cep_l1_coh_copy_dt_text(const cepDT* dt, char* buffer, size_t buffer_size) {
    if (!dt || !buffer || buffer_size == 0u) {
        return false;
    }
    size_t length = 0u;
    const char* text = cep_namepool_lookup(dt->tag, &length);
    if (!text || length == 0u) {
        return false;
    }
    if (length >= buffer_size) {
        length = buffer_size - 1u;
    }
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    return true;
}

static bool cep_l1_coh_copy_text_field(cepCell* parent,
                                       const cepDT* field,
                                       char* buffer,
                                       size_t buffer_size) {
    if (!parent || !field || !buffer || buffer_size == 0u) {
        return false;
    }
    cepCell* field_cell = cep_cell_find_by_name(parent, field);
    field_cell = field_cell ? cep_cell_resolve(field_cell) : NULL;
    if (!field_cell) {
        return false;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&field_cell, &data) || !data || data->size == 0u) {
        return false;
    }
    size_t length = data->size;
    if (length >= buffer_size) {
        length = buffer_size - 1u;
    }
    memcpy(buffer, cep_data_payload(data), length);
    buffer[length] = '\0';
    return true;
}

static cepCell* cep_l1_coh_find_debt_cell(cepL1SchemaLayout* layout, const cepDT* ctx_dt) {
    if (!layout || !layout->coh_debts || !ctx_dt) {
        return NULL;
    }
    cepCell* debt = cep_cell_find_by_name(layout->coh_debts, ctx_dt);
    debt = debt ? cep_cell_resolve(debt) : NULL;
    if (!debt || !cep_cell_require_dictionary_store(&debt)) {
        return NULL;
    }
    return debt;
}

static void cep_l1_coh_mark_debt_state(cepL1SchemaLayout* layout,
                                       const char* context_id,
                                       const cepDT* state,
                                       const char* note) {
    if (!layout || !layout->coh_debts || !context_id || !state) {
        return;
    }
    cepDT ctx_dt = {0};
    if (!cep_l1_coh_make_dt(context_id, &ctx_dt)) {
        return;
    }
    cepCell* debt = cep_l1_coh_find_debt_cell(layout, &ctx_dt);
    if (!debt) {
        return;
    }
    (void)cep_cell_put_dt(debt, dt_state_field_coh(), state);
    if (note && *note) {
        (void)cep_cell_put_text(debt, dt_note_field_coh(), note);
    }
}

static bool cep_l1_coh_materialize_facet(cepL1SchemaLayout* layout,
                                         cepCell* context_cell,
                                         const char* context_id,
                                         const char* role,
                                         const char* target_being) {
    if (!layout || !layout->coh_facets || !context_cell || !context_id || !role || !target_being) {
        return false;
    }
    cepDT ctx_dt = {0};
    if (!cep_l1_coh_make_dt(context_id, &ctx_dt)) {
        return false;
    }
    cepCell* ctx_facets = NULL;
    if (!cep_l1_coh_require_dict(layout->coh_facets, &ctx_dt, &ctx_facets)) {
        return false;
    }

    cepDT role_dt = {0};
    if (!cep_l1_coh_make_dt(role, &role_dt)) {
        return false;
    }
    cepCell* facet = cep_cell_ensure_dictionary_child(ctx_facets, &role_dt, CEP_STORAGE_RED_BLACK_T);
    facet = facet ? cep_cell_resolve(facet) : NULL;
    if (!facet || !cep_cell_require_dictionary_store(&facet)) {
        return false;
    }

    (void)cep_cell_put_text(facet, dt_role_field(), role);
    (void)cep_cell_put_text(facet, dt_target_field_coh(), target_being);
    (void)cep_cell_put_text(facet, dt_context_id_field(), context_id);

    cepCell* parents[] = {context_cell};
    (void)cep_cell_add_parents(facet, parents, 1u);
    return true;
}

bool cep_l1_coh_add_being(cepL1SchemaLayout* layout,
                          const char* being_id,
                          cepCell** being_out) {
    /* Create or refresh a being entry under `/data/coh/beings`, keeping the
       dictionary store available and copying the provided identifier into a
        text field for quick inspection. */
    if (!layout || !layout->coh_beings || !being_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_beings)) {
        return false;
    }
    cepDT being_dt = {0};
    if (!cep_l1_coh_make_dt(being_id, &being_dt)) {
        return false;
    }
    cepCell* being = cep_cell_ensure_dictionary_child(layout->coh_beings, &being_dt, CEP_STORAGE_RED_BLACK_T);
    being = being ? cep_cell_resolve(being) : NULL;
    if (!being || !cep_cell_require_dictionary_store(&being)) {
        return false;
    }
    (void)cep_cell_put_text(being, dt_being_id_field(), being_id);
    if (being_out) {
        *being_out = being;
    }
    return true;
}

bool cep_l1_coh_add_bond(cepL1SchemaLayout* layout,
                         const char* bond_id,
                         const char* role,
                         const char* from_being,
                         const char* to_being,
                         cepCell** bond_out) {
    /* Create or refresh a bond entry tying beings with a role label. This keeps
       the bonds dictionary populated and opportunistically ensures referenced
       beings exist so later closure passes can trust the identifiers. */
    if (!layout || !layout->coh_bonds || !bond_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_bonds)) {
        return false;
    }
    bool ok = true;
    cepDT bond_dt = {0};
    if (!cep_l1_coh_make_dt(bond_id, &bond_dt)) {
        return false;
    }
    cepCell* bond = cep_cell_ensure_dictionary_child(layout->coh_bonds, &bond_dt, CEP_STORAGE_RED_BLACK_T);
    bond = bond ? cep_cell_resolve(bond) : NULL;
    if (!bond || !cep_cell_require_dictionary_store(&bond)) {
        return false;
    }
    (void)cep_cell_put_text(bond, dt_bond_id_field(), bond_id);
    if (role) {
        (void)cep_cell_put_text(bond, dt_role_field(), role);
    }
    if (from_being) {
        ok = ok && cep_l1_coh_add_being(layout, from_being, NULL);
        (void)cep_cell_put_text(bond, CEP_DTAW("CEP", "source"), from_being);
    }
    if (to_being) {
        ok = ok && cep_l1_coh_add_being(layout, to_being, NULL);
        (void)cep_cell_put_text(bond, CEP_DTAW("CEP", "target"), to_being);
    }
    if (bond_out) {
        *bond_out = bond;
    }
    return ok;
}

bool cep_l1_coh_add_context(cepL1SchemaLayout* layout,
                            const char* context_id,
                            const char* note,
                            const cepL1CohBinding* bindings,
                            size_t binding_count,
                            cepCell** context_out) {
    /* Create or refresh a context entry, attach optional role→being bindings,
       and seed debts when required identifiers are missing so adjacency closure
       has a deterministic backlog to clear. */
    if (!layout || !layout->coh_contexts || !context_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_contexts)) {
        return false;
    }
    cepDT ctx_dt = {0};
    if (!cep_l1_coh_make_dt(context_id, &ctx_dt)) {
        return false;
    }
    cepCell* ctx = cep_cell_ensure_dictionary_child(layout->coh_contexts, &ctx_dt, CEP_STORAGE_RED_BLACK_T);
    ctx = ctx ? cep_cell_resolve(ctx) : NULL;
    if (!ctx || !cep_cell_require_dictionary_store(&ctx)) {
        return false;
    }
    (void)cep_cell_put_text(ctx, dt_context_id_field(), context_id);
    if (note && *note) {
        (void)cep_cell_put_text(ctx, dt_note_field_coh(), note);
    }

    cepCell* ctx_participants = NULL;
    if (bindings && binding_count > 0u) {
        ctx_participants = cep_cell_ensure_dictionary_child(ctx, dt_participants_name(), CEP_STORAGE_RED_BLACK_T);
        ctx_participants = ctx_participants ? cep_cell_resolve(ctx_participants) : NULL;
        if (!ctx_participants || !cep_cell_require_dictionary_store(&ctx_participants)) {
            return false;
        }
    }

    bool ok = true;
    for (size_t i = 0; bindings && i < binding_count; ++i) {
        const cepL1CohBinding* binding = &bindings[i];
        if (!binding->role || !binding->being_id) {
            (void)cep_l1_coh_record_debt(layout, context_id, "missing role or being in binding");
            ok = false;
            continue;
        }

        cepDT role_dt = {0};
        if (!cep_l1_coh_make_dt(binding->role, &role_dt)) {
            (void)cep_l1_coh_record_debt(layout, context_id, "role name invalid");
            ok = false;
            continue;
        }
        if (!cep_l1_coh_add_being(layout, binding->being_id, NULL)) {
            (void)cep_l1_coh_record_debt(layout, context_id, "failed to ensure being");
            ok = false;
        }

        if (!ctx_participants) {
            continue;
        }

        cepCell* role_entry = cep_cell_ensure_dictionary_child(ctx_participants, &role_dt, CEP_STORAGE_RED_BLACK_T);
        role_entry = role_entry ? cep_cell_resolve(role_entry) : NULL;
        if (!role_entry || !cep_cell_require_dictionary_store(&role_entry)) {
            (void)cep_l1_coh_record_debt(layout, context_id, "failed to attach role binding");
            ok = false;
            continue;
        }

        (void)cep_cell_put_text(role_entry, dt_role_field(), binding->role);
        (void)cep_cell_put_text(role_entry, dt_target_field_coh(), binding->being_id);
        (void)cep_cell_put_text(role_entry, dt_being_id_field(), binding->being_id);
        if (binding->bond_id) {
            (void)cep_cell_put_text(role_entry, dt_bond_id_field(), binding->bond_id);
        }
    }

    if (ok) {
        /* Run a local closure pass immediately so facets appear alongside the
           context creation; debts remain open when bindings were incomplete. */
        if (!cep_l1_coh_run_closure(layout, context_id)) {
            ok = false;
        }
    }

    if (context_out) {
        *context_out = ctx;
    }
    return ok;
}

bool cep_l1_coh_record_debt(cepL1SchemaLayout* layout,
                            const char* context_id,
                            const char* note) {
    /* Track an outstanding adjacency debt for the provided context so later
       closure passes can retry facet materialisation deterministically. This
       keeps a single debt record per context for now; append-only history will
       replace this mutation once the backlog flow matures. */
    if (!layout || !layout->coh_debts || !context_id) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_debts)) {
        return false;
    }
    cepDT ctx_dt = {0};
    if (!cep_l1_coh_make_dt(context_id, &ctx_dt)) {
        return false;
    }
    cepCell* debt = cep_cell_ensure_dictionary_child(layout->coh_debts, &ctx_dt, CEP_STORAGE_RED_BLACK_T);
    debt = debt ? cep_cell_resolve(debt) : NULL;
    if (!debt || !cep_cell_require_dictionary_store(&debt)) {
        return false;
    }
    (void)cep_cell_put_dt(debt, dt_state_field_coh(), dt_debt_state_open());
    if (note && *note) {
        (void)cep_cell_put_text(debt, dt_note_field_coh(), note);
    }
    return true;
}

/* TODO: Implement actual adjacency closure; this placeholder keeps the call
   surface alive for future enzyme wiring. */
bool cep_l1_coh_run_closure(cepL1SchemaLayout* layout, const char* context_id) {
    /* Sweep contexts (or a single context when targeted) to materialise facet
       mirrors and refresh debts. Missing beings or bindings keep debts open so
       later passes can retry deterministically. */
    if (!layout || !layout->coh_contexts || !layout->coh_beings || !layout->coh_facets || !layout->coh_debts) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&layout->coh_contexts) ||
        !cep_cell_require_dictionary_store(&layout->coh_beings) ||
        !cep_cell_require_dictionary_store(&layout->coh_facets) ||
        !cep_cell_require_dictionary_store(&layout->coh_debts)) {
        return false;
    }

    char ctx_id_buffer[128] = {0};
    bool ok = true;

    if (context_id && *context_id) {
        cepDT ctx_dt = {0};
        if (!cep_l1_coh_make_dt(context_id, &ctx_dt)) {
            return false;
        }
        cepCell* ctx = cep_cell_find_by_name(layout->coh_contexts, &ctx_dt);
        ctx = ctx ? cep_cell_resolve(ctx) : NULL;
        if (!ctx) {
            return false;
        }
        if (!cep_cell_require_dictionary_store(&ctx)) {
            return false;
        }
        strncpy(ctx_id_buffer, context_id, sizeof ctx_id_buffer - 1u);
        ctx_id_buffer[sizeof ctx_id_buffer - 1u] = '\0';

        bool missing = false;
        cepCell* participants = cep_cell_find_by_name(ctx, dt_participants_name());
        participants = participants ? cep_cell_resolve(participants) : NULL;
        if (!participants || !cep_cell_require_dictionary_store(&participants)) {
            (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "context has no participants to close");
            return true;
        }

        for (cepCell* binding = cep_cell_first(participants); binding; binding = cep_cell_next(participants, binding)) {
            char role_buffer[64] = {0};
            char target_buffer[128] = {0};
            (void)cep_l1_coh_copy_text_field(binding, dt_role_field(), role_buffer, sizeof role_buffer);
            if (!role_buffer[0]) {
                (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(binding), role_buffer, sizeof role_buffer);
            }
            if (!cep_l1_coh_copy_text_field(binding, dt_target_field_coh(), target_buffer, sizeof target_buffer)) {
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "missing target being for role");
                missing = true;
                continue;
            }

            cepDT being_dt = {0};
            if (!cep_l1_coh_make_dt(target_buffer, &being_dt)) {
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "invalid being identifier");
                missing = true;
                continue;
            }
            cepCell* being_cell = cep_cell_find_by_name(layout->coh_beings, &being_dt);
            being_cell = being_cell ? cep_cell_resolve(being_cell) : NULL;
            if (!being_cell) {
                char note[256];
                snprintf(note, sizeof note, "missing being %s for role %s", target_buffer, role_buffer[0] ? role_buffer : "?");
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, note);
                missing = true;
                continue;
            }

            if (!cep_l1_coh_materialize_facet(layout, ctx, ctx_id_buffer, role_buffer, target_buffer)) {
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "failed to materialize facet");
                missing = true;
            }
        }

        if (!missing) {
            cep_l1_coh_mark_debt_state(layout, ctx_id_buffer, dt_debt_state_done(), "closure satisfied");
        }
        return ok;
    }

    for (cepCell* ctx = cep_cell_first(layout->coh_contexts); ctx; ctx = cep_cell_next(layout->coh_contexts, ctx)) {
        ctx = cep_cell_resolve(ctx);
        if (!ctx || !cep_cell_require_dictionary_store(&ctx)) {
            ok = false;
            continue;
        }

        memset(ctx_id_buffer, 0, sizeof ctx_id_buffer);
        if (!cep_l1_coh_copy_text_field(ctx, dt_context_id_field(), ctx_id_buffer, sizeof ctx_id_buffer)) {
            (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(ctx), ctx_id_buffer, sizeof ctx_id_buffer);
        }
        if (!ctx_id_buffer[0]) {
            strncpy(ctx_id_buffer, "ctx:unknown", sizeof ctx_id_buffer - 1u);
            ctx_id_buffer[sizeof ctx_id_buffer - 1u] = '\0';
        }

        cepCell* participants = cep_cell_find_by_name(ctx, dt_participants_name());
        participants = participants ? cep_cell_resolve(participants) : NULL;
        if (!participants || !cep_cell_require_dictionary_store(&participants)) {
            (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "context has no participants to close");
            continue;
        }

        bool missing = false;
        for (cepCell* binding = cep_cell_first(participants); binding; binding = cep_cell_next(participants, binding)) {
            char role_buffer[64] = {0};
            char target_buffer[128] = {0};
            (void)cep_l1_coh_copy_text_field(binding, dt_role_field(), role_buffer, sizeof role_buffer);
            if (!role_buffer[0]) {
                (void)cep_l1_coh_copy_dt_text(cep_cell_get_name(binding), role_buffer, sizeof role_buffer);
            }
            if (!cep_l1_coh_copy_text_field(binding, dt_target_field_coh(), target_buffer, sizeof target_buffer)) {
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "missing target being for role");
                missing = true;
                continue;
            }

            cepDT being_dt = {0};
            if (!cep_l1_coh_make_dt(target_buffer, &being_dt)) {
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "invalid being identifier");
                missing = true;
                continue;
            }
            cepCell* being_cell = cep_cell_find_by_name(layout->coh_beings, &being_dt);
            being_cell = being_cell ? cep_cell_resolve(being_cell) : NULL;
            if (!being_cell) {
                char note[256];
                snprintf(note, sizeof note, "missing being %s for role %s", target_buffer, role_buffer[0] ? role_buffer : "?");
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, note);
                missing = true;
                continue;
            }

            if (!cep_l1_coh_materialize_facet(layout, ctx, ctx_id_buffer, role_buffer, target_buffer)) {
                (void)cep_l1_coh_record_debt(layout, ctx_id_buffer, "failed to materialize facet");
                missing = true;
            }
        }

        if (!missing) {
            cep_l1_coh_mark_debt_state(layout, ctx_id_buffer, dt_debt_state_done(), "closure satisfied");
        }
    }

    return ok;
}
static int cep_l1_coh_closure_enzyme(const cepPath* signal, const cepPath* target) {
    (void)signal;
    cepL1SchemaLayout layout = {0};
    if (!cep_l1_schema_ensure(&layout)) {
        return CEP_ENZYME_FATAL;
    }
    const char* ctx_id = NULL;
    char ctx_buffer[128] = {0};
    if (target && target->length > 0u) {
        const cepPast* tail = &target->past[target->length - 1u];
        if (cep_l1_coh_copy_dt_text(&tail->dt, ctx_buffer, sizeof ctx_buffer)) {
            ctx_id = ctx_buffer;
        }
    }

    if (!cep_l1_coh_run_closure(&layout, ctx_id)) {
        return CEP_ENZYME_FATAL;
    }
    return CEP_ENZYME_SUCCESS;
}

bool cep_l1_coh_register_closure_enzyme(void) {
    /* Register the adjacency-closure enzyme so pack bootstrap can rely on an
       opt-in signal (`coh:close`) to replay facet materialisation when new
       contexts or bindings arrive. */
    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    if (!registry) {
        return false;
    }
    cepPath* path = cep_malloc(sizeof(cepPath) + sizeof(cepPast));
    if (!path) {
        return false;
    }
    path->length = 1u;
    path->capacity = 1u;
    path->past[0].dt = *dt_closure_signal();
    path->past[0].timestamp = 0u;

    cepEnzymeDescriptor descriptor = {
        .name = path->past[0].dt,
        .label = "coh.close",
        .callback = cep_l1_coh_closure_enzyme,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT | CEP_ENZYME_FLAG_EMIT_SIGNALS,
        .match = CEP_ENZYME_MATCH_EXACT,
    };

    int rc = cep_enzyme_register(registry, (const cepPath*)path, &descriptor);
    cep_free(path);
    return rc == CEP_ENZYME_SUCCESS;
}
