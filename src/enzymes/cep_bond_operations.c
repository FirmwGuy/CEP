/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_bond_operations.h"

#include "../l1_bond/cep_bond.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_heartbeat.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    unsigned    length;
    unsigned    capacity;
    cepPast     past[2];
} cepBondOpPath2;

typedef struct {
    cepEnzymeRegistry* registry;
    size_t             baseline;
} cepBondOperationsRegistryRecord;

static cepBondOperationsRegistryRecord* cep_bond_operations_registry_records = NULL;
static size_t cep_bond_operations_registry_record_count = 0u;
static size_t cep_bond_operations_registry_record_capacity = 0u;
static cepEnzymeRegistry* cep_bond_operations_active_registry = NULL;

static cepBondOperationsRegistryRecord* cep_bond_operations_registry_record_find(cepEnzymeRegistry* registry) {
    if (!registry || !cep_bond_operations_registry_records) {
        return NULL;
    }

    for (size_t i = 0; i < cep_bond_operations_registry_record_count; ++i) {
        if (cep_bond_operations_registry_records[i].registry == registry) {
            return &cep_bond_operations_registry_records[i];
        }
    }

    return NULL;
}

static cepBondOperationsRegistryRecord* cep_bond_operations_registry_record_append(cepEnzymeRegistry* registry, size_t baseline) {
    if (!registry) {
        return NULL;
    }

    if (cep_bond_operations_registry_record_count == cep_bond_operations_registry_record_capacity) {
        size_t new_capacity = cep_bond_operations_registry_record_capacity ? (cep_bond_operations_registry_record_capacity * 2u) : 4u;
        size_t previous_bytes = cep_bond_operations_registry_record_capacity * sizeof(*cep_bond_operations_registry_records);
        size_t bytes = new_capacity * sizeof(*cep_bond_operations_registry_records);
        cepBondOperationsRegistryRecord* grown = cep_bond_operations_registry_records ? cep_realloc(cep_bond_operations_registry_records, bytes) : cep_malloc0(bytes);
        if (cep_bond_operations_registry_records) {
            memset(((uint8_t*)grown) + previous_bytes, 0, bytes - previous_bytes);
        }
        cep_bond_operations_registry_records = grown;
        cep_bond_operations_registry_record_capacity = new_capacity;
    }

    cepBondOperationsRegistryRecord* record = &cep_bond_operations_registry_records[cep_bond_operations_registry_record_count++];
    record->registry = registry;
    record->baseline = baseline;
    return record;
}


static const cepDT* dt_sig_bond_be(void) { return CEP_DTAW("CEP", "sig_bond_be"); }
static const cepDT* dt_sig_bond_bd(void) { return CEP_DTAW("CEP", "sig_bond_bd"); }
static const cepDT* dt_sig_ctx_pr(void)  { return CEP_DTAW("CEP", "sig_ctx_pr"); }
static const cepDT* dt_sig_fct_reg(void){ return CEP_DTAW("CEP", "sig_fct_reg"); }
static const cepDT* dt_sig_fct_run(void){ return CEP_DTAW("CEP", "sig_fct_run"); }
static const cepDT* dt_sig_bond_mt(void){ return CEP_DTAW("CEP", "sig_bond_mt"); }

static const cepDT* dt_op_claim(void)    { return CEP_DTAW("CEP", "op_claim"); }
static const cepDT* dt_op_upsert(void)   { return CEP_DTAW("CEP", "op_upsert"); }
static const cepDT* dt_op_register(void) { return CEP_DTAW("CEP", "op_reg" ); }
static const cepDT* dt_op_dispatch(void) { return CEP_DTAW("CEP", "op_disp"); }
static const cepDT* dt_op_tick(void)     { return CEP_DTAW("CEP", "op_tick"); }

static const cepDT* dt_enz_be_claim(void){ return CEP_DTAW("CEP", "enz_beclm"); }
static const cepDT* dt_enz_bond_upsert(void) { return CEP_DTAW("CEP", "enz_bdupst"); }
static const cepDT* dt_enz_ctx_upsert(void)  { return CEP_DTAW("CEP", "enz_ctxupst"); }
static const cepDT* dt_enz_fct_register(void){ return CEP_DTAW("CEP", "enz_fctreg"); }
static const cepDT* dt_enz_fct_dispatch(void){ return CEP_DTAW("CEP", "enz_fctdsp"); }
static const cepDT* dt_enz_l1_tick(void)     { return CEP_DTAW("CEP", "enz_l1tick"); }

static const cepDT* dt_arg_name(void)     { return CEP_DTAW("CEP", "arg_name"); }
static const cepDT* dt_arg_tag(void)      { return CEP_DTAW("CEP", "arg_tag"); }
static const cepDT* dt_arg_roles(void)    { return CEP_DTAW("CEP", "arg_roles"); }
static const cepDT* dt_arg_facets(void)   { return CEP_DTAW("CEP", "arg_facets"); }
static const cepDT* dt_arg_mat(void)      { return CEP_DTAW("CEP", "arg_mat"); }
static const cepDT* dt_arg_policy(void)   { return CEP_DTAW("CEP", "arg_policy"); }
static const cepDT* dt_arg_root(void)     { return CEP_DTAW("CEP", "arg_root"); }
static const cepDT* dt_arg_causal(void)   { return CEP_DTAW("CEP", "arg_causal"); }
static const cepDT* dt_arg_ctx(void)      { return CEP_DTAW("CEP", "arg_ctx"); }
static const cepDT* dt_arg_runtime(void)  { return CEP_DTAW("CEP", "arg_runtime"); }
static const cepDT* dt_role_a_tag(void)   { return CEP_DTAW("CEP", "role_a_tag"); }
static const cepDT* dt_role_b_tag(void)   { return CEP_DTAW("CEP", "role_b_tag"); }


static cepCell* cep_bond_enzyme_resolve(const cepPath* path) {
    if (!path || !path->length) {
        return NULL;
    }
    return cep_cell_find_by_path_past(cep_root(), path, 0);
}

static cepCell* cep_bond_enzyme_resolve_link(cepCell* cell) {
    if (!cell) {
        return NULL;
    }
    return cep_link_pull(cell);
}

static cepCell* cep_bond_enzyme_request_link(cepCell* request, const cepDT* name) {
    if (!request || !name) {
        return NULL;
    }

    cepCell* entry = cep_cell_find_by_name(request, name);
    if (!entry) {
        return NULL;
    }

    return cep_bond_enzyme_resolve_link(entry);
}

static bool cep_bond_enzyme_request_text(cepCell* request, const cepDT* name, const char** out_text) {
    if (!request || !name || !out_text) {
        return false;
    }

    cepCell* entry = cep_cell_find_by_name(request, name);
    if (!entry || !cep_cell_has_data(entry)) {
        return false;
    }

    const cepData* data = entry->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size < 1u) {
        return false;
    }

    const char* text = (const char*)data->value;
    if (!text || text[data->size - 1u] != '\0') {
        return false;
    }

    *out_text = text;
    return true;
}

static bool cep_bond_enzyme_request_u64(cepCell* request, const cepDT* name, uint64_t* out_value) {
    if (!request || !name || !out_value) {
        return false;
    }

    cepCell* entry = cep_cell_find_by_name(request, name);
    if (!entry || !cep_cell_has_data(entry)) {
        return false;
    }

    const cepData* data = entry->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size != sizeof(uint64_t)) {
        return false;
    }

    uint64_t value = 0u;
    memcpy(&value, data->value, sizeof value);
    *out_value = value;
    return true;
}

static bool cep_bond_enzyme_request_enzyme(cepCell* request, const cepDT* name, cepEnzyme* out_callback) {
    if (!request || !name || !out_callback) {
        return false;
    }

    cepCell* entry = cep_cell_find_by_name(request, name);
    if (!entry || !cep_cell_has_data(entry)) {
        return false;
    }

    const cepData* data = entry->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size != sizeof(*out_callback)) {
        return false;
    }

    memcpy(out_callback, data->value, sizeof(*out_callback));
    return *out_callback != NULL;
}

static bool cep_bond_enzyme_request_pointer(cepCell* request, const cepDT* name, void** out_pointer) {
    if (!request || !name || !out_pointer) {
        return false;
    }

    cepCell* entry = cep_cell_find_by_name(request, name);
    if (!entry || !cep_cell_has_data(entry)) {
        return false;
    }

    const cepData* data = entry->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size != sizeof(void*)) {
        return false;
    }

    void* pointer = NULL;
    memcpy(&pointer, data->value, sizeof pointer);
    *out_pointer = pointer;
    return true;
}

static bool cep_bond_enzyme_parse_dt(const char* text, cepDT* out_dt) {
    if (!text || !*text || !out_dt) {
        return false;
    }

    const char* colon = strchr(text, ':');
    cepID domain_id = 0;
    const char* tag_text = text;

    if (colon) {
        size_t domain_len = (size_t)(colon - text);
        if (domain_len == 0u || domain_len >= 12u) {
            return false;
        }

        char domain_buffer[12] = {0};
        memcpy(domain_buffer, text, domain_len);
        for (size_t i = 0; i < domain_len; ++i) {
            domain_buffer[i] = (char)toupper((unsigned char)domain_buffer[i]);
        }

        domain_id = cep_text_to_acronym(domain_buffer);
        if (!domain_id) {
            domain_id = cep_text_to_word(domain_buffer);
        }

        tag_text = colon + 1;
    } else {
        domain_id = CEP_ACRO("CEP");
    }

    if (!tag_text || !*tag_text) {
        return false;
    }

    cepID tag_id = cep_text_to_word(tag_text);
    if (!tag_id) {
        tag_id = cep_text_to_acronym(tag_text);
    }

    if (!domain_id || !tag_id) {
        return false;
    }

    out_dt->domain = domain_id;
    out_dt->tag = tag_id;
    return true;
}

static bool cep_bond_enzyme_request_dt(cepCell* request, const cepDT* name, cepDT* out_dt) {
    const char* text = NULL;
    if (!cep_bond_enzyme_request_text(request, name, &text)) {
        return false;
    }
    return cep_bond_enzyme_parse_dt(text, out_dt);
}

/* Drive `cep_being_claim` off a request dictionary so impulses can assert a Layer 1
   identity without invoking the API directly. */
static int cep_bond_enzyme_being_claim(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_bond_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepDT being_name = (cepDT){0};
    if (!cep_bond_enzyme_request_dt(request, dt_arg_name(), &being_name)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* root = cep_bond_enzyme_request_link(request, dt_arg_root());

    const char* label = NULL;
    (void)cep_bond_enzyme_request_text(request, CEP_DTAW("CEP", "being_label"), &label);

    const char* kind = NULL;
    (void)cep_bond_enzyme_request_text(request, CEP_DTAW("CEP", "being_kind"), &kind);

    const char* external_id = NULL;
    (void)cep_bond_enzyme_request_text(request, CEP_DTAW("CEP", "being_ext"), &external_id);

    cepCell* metadata = cep_bond_enzyme_request_link(request, CEP_DTAW("CEP", "meta"));

    uint64_t causal = 0u;
    cepOpCount causal_op = 0u;
    if (cep_bond_enzyme_request_u64(request, dt_arg_causal(), &causal)) {
        causal_op = (cepOpCount)causal;
    }

    cepBeingSpec spec = {
        .label = label,
        .kind = kind,
        .external_id = external_id,
        .metadata = metadata,
    };

    cepBeingHandle handle = {0};
    cepL1Result rc = cep_being_claim(root, &being_name, &spec, &handle);
    if (rc != CEP_L1_OK) {
        return CEP_ENZYME_FATAL;
    }

    (void)causal_op; /* Reserved for future journaling. */
    return CEP_ENZYME_SUCCESS;
}

/* Invoke `cep_bond_upsert` so impulses can wire or refresh pair bonds between
   beings while maintaining adjacency mirrors. */
static int cep_bond_enzyme_bond_upsert(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_bond_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepDT bond_tag = (cepDT){0};
    if (!cep_bond_enzyme_request_dt(request, dt_arg_tag(), &bond_tag)) {
        return CEP_ENZYME_FATAL;
    }

    cepDT role_a_tag = (cepDT){0};
    cepDT role_b_tag = (cepDT){0};
    if (!cep_bond_enzyme_request_dt(request, dt_role_a_tag(), &role_a_tag)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_bond_enzyme_request_dt(request, dt_role_b_tag(), &role_b_tag)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* role_a = cep_bond_enzyme_request_link(request, CEP_DTAW("CEP", "role_a"));
    cepCell* role_b = cep_bond_enzyme_request_link(request, CEP_DTAW("CEP", "role_b"));
    if (!role_a || !role_b) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* metadata = cep_bond_enzyme_request_link(request, CEP_DTAW("CEP", "meta"));

    const char* label = NULL;
    (void)cep_bond_enzyme_request_text(request, CEP_DTAW("CEP", "bond_label"), &label);

    const char* note = NULL;
    (void)cep_bond_enzyme_request_text(request, CEP_DTAW("CEP", "bond_note"), &note);

    uint64_t causal = 0u;
    cepOpCount causal_op = 0u;
    if (cep_bond_enzyme_request_u64(request, dt_arg_causal(), &causal)) {
        causal_op = (cepOpCount)causal;
    }

    cepCell* root = cep_bond_enzyme_request_link(request, dt_arg_root());

    cepBondSpec spec = {
        .tag = &bond_tag,
        .role_a_tag = &role_a_tag,
        .role_a = role_a,
        .role_b_tag = &role_b_tag,
        .role_b = role_b,
        .metadata = metadata,
        .causal_op = causal_op,
        .label = label,
        .note = note,
    };

    cepBondHandle handle = {0};
    cepL1Result rc = cep_bond_upsert(root, &spec, &handle);
    if (rc != CEP_L1_OK) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}
/* Route context definitions through `cep_context_upsert` so impulses can stage
   multi-party simplices, queue facets, and update adjacency mirrors. */
static int cep_bond_enzyme_context_upsert(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_bond_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepDT context_tag = (cepDT){0};
    if (!cep_bond_enzyme_request_dt(request, dt_arg_tag(), &context_tag)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* roles_dict = cep_cell_find_by_name(request, dt_arg_roles());
    if (!roles_dict || !roles_dict->store) {
        return CEP_ENZYME_FATAL;
    }

    size_t role_count = cep_cell_children(roles_dict);
    if (!role_count) {
        return CEP_ENZYME_FATAL;
    }

    const cepDT** role_tags = cep_malloc(role_count * sizeof(*role_tags));
    const cepCell** role_targets = cep_malloc(role_count * sizeof(*role_targets));
    if (!role_tags || !role_targets) {
        cep_free((void*)role_tags);
        cep_free((void*)role_targets);
        return CEP_ENZYME_FATAL;
    }

    for (size_t i = 0; i < role_count; ++i) {
        cepCell* entry = cep_cell_find_by_position(roles_dict, i);
        if (!entry) {
            cep_free((void*)role_tags);
            cep_free((void*)role_targets);
            return CEP_ENZYME_FATAL;
        }

        const cepDT* role_name = cep_cell_get_name(entry);
        cepCell* target_cell = cep_bond_enzyme_resolve_link(entry);
        if (!role_name || !target_cell) {
            cep_free((void*)role_tags);
            cep_free((void*)role_targets);
            return CEP_ENZYME_FATAL;
        }

        role_tags[i] = role_name;
        role_targets[i] = target_cell;
    }

    cepCell* metadata = cep_bond_enzyme_request_link(request, CEP_DTAW("CEP", "meta"));

    cepCell* facets_dict = cep_cell_find_by_name(request, dt_arg_facets());
    size_t facet_count = facets_dict ? cep_cell_children(facets_dict) : 0u;
    const cepDT** facet_tags = NULL;
    if (facet_count) {
        facet_tags = cep_malloc(facet_count * sizeof(*facet_tags));
        if (!facet_tags) {
            cep_free((void*)role_tags);
            cep_free((void*)role_targets);
            return CEP_ENZYME_FATAL;
        }

        for (size_t i = 0; i < facet_count; ++i) {
            cepCell* entry = cep_cell_find_by_position(facets_dict, i);
            if (!entry) {
                cep_free((void*)facet_tags);
                cep_free((void*)role_tags);
                cep_free((void*)role_targets);
                return CEP_ENZYME_FATAL;
            }
            facet_tags[i] = cep_cell_get_name(entry);
        }
    }

    const char* label = NULL;
    (void)cep_bond_enzyme_request_text(request, CEP_DTAW("CEP", "ctx_label"), &label);

    uint64_t causal = 0u;
    cepOpCount causal_op = 0u;
    if (cep_bond_enzyme_request_u64(request, dt_arg_causal(), &causal)) {
        causal_op = (cepOpCount)causal;
    }

    cepCell* root = cep_bond_enzyme_request_link(request, dt_arg_root());

    cepContextSpec spec = {
        .tag = &context_tag,
        .role_count = role_count,
        .role_tags = role_tags,
        .role_targets = role_targets,
        .metadata = metadata,
        .facet_tags = facet_tags,
        .facet_count = facet_count,
        .causal_op = causal_op,
        .label = label,
    };

    cepContextHandle handle = {0};
    cepL1Result rc = cep_context_upsert(root, &spec, &handle);

    cep_free((void*)facet_tags);
    cep_free((void*)role_tags);
    cep_free((void*)role_targets);

    if (rc != CEP_L1_OK) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}
/* Allow impulses to register facet materialisers by forwarding the request to
   `cep_facet_register`, accepting enzyme pointers encoded as raw values. */
static int cep_bond_enzyme_facet_register(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_bond_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepDT facet_tag = (cepDT){0};
    cepDT context_tag = (cepDT){0};
    if (!cep_bond_enzyme_request_dt(request, dt_arg_tag(), &facet_tag)) {
        return CEP_ENZYME_FATAL;
    }
    if (!cep_bond_enzyme_request_dt(request, dt_arg_ctx(), &context_tag)) {
        return CEP_ENZYME_FATAL;
    }

    cepEnzyme materialiser = NULL;
    if (!cep_bond_enzyme_request_enzyme(request, dt_arg_mat(), &materialiser)) {
        return CEP_ENZYME_FATAL;
    }

    uint64_t policy_raw = (uint64_t)CEP_FACET_POLICY_DEFAULT;
    cepFacetPolicy policy = CEP_FACET_POLICY_DEFAULT;
    if (cep_bond_enzyme_request_u64(request, dt_arg_policy(), &policy_raw)) {
        policy = (cepFacetPolicy)(policy_raw & 0xFFFFFFFFu);
    }

    cepFacetSpec spec = {
        .facet_tag = &facet_tag,
        .source_context_tag = &context_tag,
        .materialiser = materialiser,
        .policy = policy,
    };

    cepL1Result rc = cep_facet_register(&spec);
    if (rc != CEP_L1_OK) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}
/* Permit impulses to trigger a specific facet dispatch by name, letting queue
   entries advance without invoking the C helpers manually. */
static int cep_bond_enzyme_facet_dispatch(const cepPath* signal, const cepPath* target) {
    (void)signal;

    cepCell* request = cep_bond_enzyme_resolve(target);
    if (!request) {
        return CEP_ENZYME_FATAL;
    }

    cepDT facet_tag = (cepDT){0};
    if (!cep_bond_enzyme_request_dt(request, dt_arg_tag(), &facet_tag)) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* context = cep_bond_enzyme_request_link(request, dt_arg_ctx());
    if (!context) {
        return CEP_ENZYME_FATAL;
    }

    const cepDT* context_name = cep_cell_get_name(context);
    if (!context_name) {
        return CEP_ENZYME_FATAL;
    }

    cepCell* root = cep_bond_enzyme_request_link(request, dt_arg_root());

    cepL1Result rc = cep_facet_dispatch(root, &facet_tag, context_name);
    if (rc != CEP_L1_OK) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}
/* Bridge `cep_tick_l1` so a heartbeat impulse can prune adjacency mirrors and
   advance facet queues without going through the direct API. */
static int cep_bond_enzyme_tick_l1(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;

    cepCell* request = cep_bond_enzyme_resolve(target);

    cepHeartbeatRuntime* runtime = NULL;
    if (request) {
        void* runtime_pointer = NULL;
        if (cep_bond_enzyme_request_pointer(request, dt_arg_runtime(), &runtime_pointer)) {
            runtime = (cepHeartbeatRuntime*)runtime_pointer;
        }
    }

    cepL1Result rc = cep_tick_l1(runtime);
    if (rc != CEP_L1_OK) {
        return CEP_ENZYME_FATAL;
    }

    return CEP_ENZYME_SUCCESS;
}
typedef struct {
    cepBondOpPath2        path;
    cepEnzymeDescriptor   descriptor;
} cepBondOperationsEntry;

static bool cep_bond_operations_populate(cepEnzymeRegistry* registry) {
    cepBondOperationsEntry entries[6];
    memset(entries, 0, sizeof entries);

    entries[0].path.length = 2u;
    entries[0].path.capacity = 2u;
    entries[0].path.past[0].dt = *dt_sig_bond_be();
    entries[0].path.past[1].dt = *dt_op_claim();
    entries[0].descriptor.name = *dt_enz_be_claim();
    entries[0].descriptor.label = "l1.being.claim";
    entries[0].descriptor.callback = cep_bond_enzyme_being_claim;
    entries[0].descriptor.flags = CEP_ENZYME_FLAG_NONE;
    entries[0].descriptor.match = CEP_ENZYME_MATCH_EXACT;

    entries[1].path.length = 2u;
    entries[1].path.capacity = 2u;
    entries[1].path.past[0].dt = *dt_sig_bond_bd();
    entries[1].path.past[1].dt = *dt_op_upsert();
    entries[1].descriptor.name = *dt_enz_bond_upsert();
    entries[1].descriptor.label = "l1.bond.upsert";
    entries[1].descriptor.callback = cep_bond_enzyme_bond_upsert;
    entries[1].descriptor.flags = CEP_ENZYME_FLAG_NONE;
    entries[1].descriptor.match = CEP_ENZYME_MATCH_EXACT;

    entries[2].path.length = 2u;
    entries[2].path.capacity = 2u;
    entries[2].path.past[0].dt = *dt_sig_ctx_pr();
    entries[2].path.past[1].dt = *dt_op_upsert();
    entries[2].descriptor.name = *dt_enz_ctx_upsert();
    entries[2].descriptor.label = "l1.context.upsert";
    entries[2].descriptor.callback = cep_bond_enzyme_context_upsert;
    entries[2].descriptor.flags = CEP_ENZYME_FLAG_NONE;
    entries[2].descriptor.match = CEP_ENZYME_MATCH_EXACT;

    entries[3].path.length = 2u;
    entries[3].path.capacity = 2u;
    entries[3].path.past[0].dt = *dt_sig_fct_reg();
    entries[3].path.past[1].dt = *dt_op_register();
    entries[3].descriptor.name = *dt_enz_fct_register();
    entries[3].descriptor.label = "l1.facet.register";
    entries[3].descriptor.callback = cep_bond_enzyme_facet_register;
    entries[3].descriptor.flags = CEP_ENZYME_FLAG_NONE;
    entries[3].descriptor.match = CEP_ENZYME_MATCH_EXACT;

    entries[4].path.length = 2u;
    entries[4].path.capacity = 2u;
    entries[4].path.past[0].dt = *dt_sig_fct_run();
    entries[4].path.past[1].dt = *dt_op_dispatch();
    entries[4].descriptor.name = *dt_enz_fct_dispatch();
    entries[4].descriptor.label = "l1.facet.dispatch";
    entries[4].descriptor.callback = cep_bond_enzyme_facet_dispatch;
    entries[4].descriptor.flags = CEP_ENZYME_FLAG_NONE;
    entries[4].descriptor.match = CEP_ENZYME_MATCH_EXACT;

    entries[5].path.length = 2u;
    entries[5].path.capacity = 2u;
    entries[5].path.past[0].dt = *dt_sig_bond_mt();
    entries[5].path.past[1].dt = *dt_op_tick();
    entries[5].descriptor.name = *dt_enz_l1_tick();
    entries[5].descriptor.label = "l1.tick";
    entries[5].descriptor.callback = cep_bond_enzyme_tick_l1;
    entries[5].descriptor.flags = CEP_ENZYME_FLAG_NONE;
    entries[5].descriptor.match = CEP_ENZYME_MATCH_EXACT;

    for (size_t i = 0; i < 6u; ++i) {
        const cepPath* path = (const cepPath*)&entries[i].path;
        if (cep_enzyme_register(registry, path, &entries[i].descriptor) != CEP_ENZYME_SUCCESS) {
            return false;
        }
    }

    return true;
}

/* Register the impulse-accessible Layer 1 bond enzymes on the supplied registry
   so beats can drive `cep_being_claim`, `cep_bond_upsert`, `cep_context_upsert`,
   facet helpers, and `cep_tick_l1` without calling the C API directly. */
bool cep_bond_operations_register(cepEnzymeRegistry* registry) {
    if (!registry) {
        return true;
    }

    const size_t expected = 6u;
    cepBondOperationsRegistryRecord* record = cep_bond_operations_registry_record_find(registry);
    size_t current_size = cep_enzyme_registry_size(registry);

    if (record && current_size >= record->baseline) {
        return true;
    }

    if (!record && current_size >= expected) {
        (void)cep_bond_operations_registry_record_append(registry, current_size);
        return true;
    }

    if (cep_bond_operations_active_registry == registry) {
        return true;
    }

    cepEnzymeRegistry* previous_active = cep_bond_operations_active_registry;
    cep_bond_operations_active_registry = registry;

    size_t size_before = current_size;
    bool ok = cep_bond_operations_populate(registry);

    cep_bond_operations_active_registry = previous_active;

    if (!ok) {
        return false;
    }

    size_t size_after = cep_enzyme_registry_size(registry);
    size_t baseline = (size_after > size_before) ? size_after : (size_before + expected);

    if (record) {
        record->baseline = baseline;
    } else {
        (void)cep_bond_operations_registry_record_append(registry, baseline);
    }

    return true;
}
