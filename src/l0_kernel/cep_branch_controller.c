/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cep_branch_controller.h"

#include <string.h>
#include <stdio.h>

#include "cep_cei.h"

CEP_DEFINE_STATIC_DT(dt_svo_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_svo_sev_info, CEP_ACRO("CEP"), CEP_WORD("sev:info"));

static const char k_branch_policy_topic[] = "cell.cross_read";



struct cepBranchControllerRegistry {
    cepBranchController** entries;
    size_t                count;
    size_t                capacity;
    uint64_t              generation;
};

static cepBranchPersistPolicy
cep_branch_policy_defaults(void)
{
    return (cepBranchPersistPolicy){
        .mode = CEP_BRANCH_PERSIST_DURABLE,
        .flush_every_beats = 1u,
        .flush_on_shutdown = true,
        .lazy_load_at_boot = false,
        .allow_volatile_reads = false,
    };
}

static void
cep_branch_dirty_index_reset(cepBranchDirtyIndex* index)
{
    if (!index) {
        return;
    }
    if (index->entries) {
        cep_free(index->entries);
    }
    index->entries = NULL;
    index->count = 0u;
    index->capacity = 0u;
}

static void
cep_branch_controller_destroy(cepBranchController* controller)
{
    if (!controller) {
        return;
    }
    cep_branch_dirty_index_reset(&controller->dirty_index);
    cep_free(controller);
}

static bool
cep_branch_dirty_index_grow(cepBranchDirtyIndex* index, size_t min_capacity)
{
    if (!index) {
        return false;
    }
    size_t desired = index->capacity ? (index->capacity * 2u) : 4u;
    if (desired < min_capacity) {
        desired = min_capacity;
    }
    size_t bytes = desired * sizeof(*index->entries);
    cepBranchDirtyEntry* grown = index->entries
        ? cep_realloc(index->entries, bytes)
        : cep_malloc(bytes);
    if (!grown) {
        return false;
    }
    index->entries = grown;
    index->capacity = desired;
    return true;
}

static cepBranchDirtyEntry*
cep_branch_dirty_index_find(cepBranchDirtyIndex* index, const cepCell* cell)
{
    if (!index || !cell) {
        return NULL;
    }
    for (size_t i = 0; i < index->count; ++i) {
        cepBranchDirtyEntry* entry = &index->entries[i];
        if (entry->cell == cell) {
            return entry;
        }
    }
    return NULL;
}

static uint32_t
cep_branch_controller_pin_delta(uint32_t flags)
{
    uint32_t pins = 0u;
    if (flags & CEP_BRANCH_DIRTY_FLAG_DATA) {
        ++pins;
    }
    if (flags & CEP_BRANCH_DIRTY_FLAG_STORE) {
        ++pins;
    }
    return pins;
}

static uint64_t
cep_branch_controller_estimate_data_bytes(const cepCell* cell)
{
    if (!cell || !cep_cell_is_normal(cell)) {
        return 0u;
    }
    const cepData* data = cell->data;
    if (!data) {
        return 0u;
    }
    return (uint64_t)data->size;
}

static uint64_t
cep_branch_controller_estimate_store_bytes(const cepCell* cell)
{
    if (!cell || !cep_cell_is_normal(cell)) {
        return 0u;
    }
    const cepStore* store = cell->store;
    if (!store) {
        return 0u;
    }
    uint64_t base = sizeof(*store);
    uint64_t per_child = sizeof(cepStoreNode);
    uint64_t logical_children = (uint64_t)store->totCount;
    return base + (per_child * logical_children);
}

static uint64_t
cep_branch_controller_estimate_bytes(const cepCell* cell, uint32_t flags)
{
    uint64_t total = 0u;
    if (flags & CEP_BRANCH_DIRTY_FLAG_DATA) {
        total += cep_branch_controller_estimate_data_bytes(cell);
    }
    if (flags & CEP_BRANCH_DIRTY_FLAG_STORE) {
        total += cep_branch_controller_estimate_store_bytes(cell);
    }
    return total;
}

static void
cep_branch_controller_apply_dirty_delta(cepBranchController* controller,
                                        cepCell* cell,
                                        uint32_t flags)
{
    if (!controller || !cell || !flags) {
        return;
    }
    controller->dirty_bytes += cep_branch_controller_estimate_bytes(cell, flags);
    controller->pins += cep_branch_controller_pin_delta(flags);
}

static bool
cep_branch_registry_grow(cepBranchControllerRegistry* registry, size_t min_capacity)
{
    if (!registry) {
        return false;
    }
    size_t desired = registry->capacity ? (registry->capacity * 2u) : 4u;
    if (desired < min_capacity) {
        desired = min_capacity;
    }
    size_t bytes = desired * sizeof(*registry->entries);
    cepBranchController** grown = registry->entries
        ? cep_realloc(registry->entries, bytes)
        : cep_malloc(bytes);
    if (!grown) {
        return false;
    }
    registry->entries = grown;
    registry->capacity = desired;
    return true;
}

static cepBranchController*
cep_branch_controller_at(const cepBranchControllerRegistry* registry, size_t index)
{
    if (!registry || index >= registry->count) {
        return NULL;
    }
    return registry->entries[index];
}

cepBranchControllerRegistry*
cep_branch_registry_create(void)
{
    return cep_malloc0(sizeof(cepBranchControllerRegistry));
}

void
cep_branch_registry_destroy(cepBranchControllerRegistry* registry)
{
    if (!registry) {
        return;
    }
    cep_branch_registry_reset(registry);
    cep_free(registry);
}

void
cep_branch_registry_reset(cepBranchControllerRegistry* registry)
{
    if (!registry) {
        return;
    }
    if (registry->entries) {
        for (size_t index = 0; index < registry->count; ++index) {
            cep_branch_controller_destroy(registry->entries[index]);
        }
        cep_free(registry->entries);
    }
    registry->entries = NULL;
    registry->count = 0u;
    registry->capacity = 0u;
    registry->generation = 0u;
}

size_t
cep_branch_registry_count(const cepBranchControllerRegistry* registry)
{
    return registry ? registry->count : 0u;
}

static bool
cep_branch_dt_equals(const cepDT* lhs, const cepDT* rhs)
{
    if (!lhs || !rhs) {
        return false;
    }
    return cep_dt_compare(lhs, rhs) == 0;
}

cepBranchController*
cep_branch_registry_find_by_root(const cepBranchControllerRegistry* registry,
                                 const cepCell* branch_root)
{
    if (!registry || !branch_root) {
        return NULL;
    }
    for (size_t index = 0; index < registry->count; ++index) {
        cepBranchController* controller = cep_branch_controller_at(registry, index);
        if (controller && controller->branch_root == branch_root) {
            return controller;
        }
    }
    return NULL;
}

cepBranchController*
cep_branch_registry_find_by_dt(const cepBranchControllerRegistry* registry,
                               const cepDT* branch_dt)
{
    if (!registry || !branch_dt || !cep_dt_is_valid(branch_dt)) {
        return NULL;
    }
    for (size_t index = 0; index < registry->count; ++index) {
        cepBranchController* controller = cep_branch_controller_at(registry, index);
        if (controller && cep_dt_is_valid(&controller->branch_dt) &&
            cep_branch_dt_equals(branch_dt, &controller->branch_dt)) {
            return controller;
        }
    }
    return NULL;
}

const cepBranchPersistPolicy*
cep_branch_controller_policy(const cepBranchController* controller)
{
    if (!controller) {
        return NULL;
    }
    return &controller->policy;
}

void
cep_branch_controller_set_policy(cepBranchController* controller,
                                 const cepBranchPersistPolicy* policy)
{
    if (!controller) {
        return;
    }
    controller->policy = policy ? *policy : cep_branch_policy_defaults();
}

bool
cep_branch_controller_mark_dirty(cepBranchController* controller,
                                 cepCell* cell,
                                 uint32_t flags)
{
    if (!controller || !cell || !flags) {
        return false;
    }
    cepBranchDirtyIndex* index = &controller->dirty_index;
    cepBranchDirtyEntry* entry = cep_branch_dirty_index_find(index, cell);
    if (entry) {
        uint32_t new_bits = flags & ~entry->flags;
        if (!new_bits) {
            return true;
        }
        cep_branch_controller_apply_dirty_delta(controller, cell, new_bits);
        entry->flags |= new_bits;
        controller->pending_mutations += 1u;
        return true;
    }
    if (index->count == index->capacity &&
        !cep_branch_dirty_index_grow(index, index->count + 1u)) {
        return false;
    }
    cepBranchDirtyEntry new_entry = {
        .cell = cell,
        .flags = 0u,
        .stamp = cep_cell_timestamp(),
    };
    index->entries[index->count++] = new_entry;
    cepBranchDirtyEntry* inserted = &index->entries[index->count - 1u];
    cep_branch_controller_apply_dirty_delta(controller, cell, flags);
    inserted->flags = flags;
    controller->dirty_entry_count = index->count;
    controller->pending_mutations += 1u;
    return true;
}

static bool
cep_branch_controller_init(cepBranchController* controller,
                           cepCell* branch_root,
                           const cepDT* branch_name)
{
    if (!controller || !branch_root || !branch_root->store) {
        return false;
    }
    controller->branch_root = branch_root;
    if (branch_name && cep_dt_is_valid(branch_name)) {
        controller->branch_dt = cep_dt_clean(branch_name);
    } else {
        controller->branch_dt = cep_dt_clean(&branch_root->metacell.dt);
    }
    controller->policy = cep_branch_policy_defaults();
    controller->dirty_index = (cepBranchDirtyIndex){0};
    controller->last_persisted_bt = CEP_BEAT_INVALID;
    controller->flush_scheduled_bt = CEP_BEAT_INVALID;
    controller->periodic_anchor_bt = CEP_BEAT_INVALID;
    controller->dirty_entry_count = 0u;
    controller->dirty_bytes = 0u;
    controller->pending_mutations = 0u;
    controller->pins = 0u;
    controller->last_flush_bytes = 0u;
    controller->last_flush_pins = 0u;
    controller->version = 0u;
    controller->last_frame_id = 0u;
    controller->last_flush_cause = CEP_BRANCH_FLUSH_CAUSE_UNKNOWN;
    controller->registered = false;
    controller->pinned = false;
    controller->force_flush = false;
    return true;
}

cepBranchController*
cep_branch_registry_register(cepBranchControllerRegistry* registry,
                             cepCell* branch_root,
                             const cepDT* branch_name)
{
    if (!registry || !branch_root || !branch_root->store) {
        return NULL;
    }

    cepBranchController* existing = cep_branch_registry_find_by_root(registry, branch_root);
    if (existing) {
        return existing;
    }

    cepDT candidate_dt = {0};
    if (branch_name && cep_dt_is_valid(branch_name)) {
        candidate_dt = cep_dt_clean(branch_name);
    } else {
        candidate_dt = cep_dt_clean(&branch_root->metacell.dt);
    }

    if (!cep_dt_is_valid(&candidate_dt)) {
        return NULL;
    }

    existing = cep_branch_registry_find_by_dt(registry, &candidate_dt);
    if (existing) {
        existing->branch_root = branch_root;
        return existing;
    }

    if (registry->count == registry->capacity &&
        !cep_branch_registry_grow(registry, registry->count + 1u)) {
        return NULL;
    }

    cepBranchController* controller = cep_malloc0(sizeof *controller);
    if (!controller) {
        return NULL;
    }

    if (!cep_branch_controller_init(controller, branch_root, branch_name)) {
        cep_branch_controller_destroy(controller);
        return NULL;
    }

    controller->branch_dt = candidate_dt;
    controller->registered = true;
    controller->version = ++registry->generation;

    registry->entries[registry->count++] = controller;
    return controller;
}

bool
cep_branch_registry_bind_existing_children(cepBranchControllerRegistry* registry,
                                           cepCell* data_root)
{
    if (!registry || !data_root) {
        return false;
    }

    cepCell* resolved_data = cep_cell_resolve(data_root);
    if (!resolved_data || !resolved_data->store) {
        return false;
    }

    bool success = true;
    for (cepCell* child = cep_cell_first_all(resolved_data);
         child;
         child = cep_cell_next_all(resolved_data, child)) {
        if (!child || !cep_cell_is_normal(child)) {
            continue;
        }
        if (!child->store || child->store->indexing != CEP_INDEX_BY_NAME) {
            continue;
        }
        cepBranchController* controller =
            cep_branch_registry_register(registry, child, &child->metacell.dt);
        if (!controller) {
            success = false;
            continue;
        }
    }
    return success;
}

cepBranchController*
cep_branch_registry_controller(const cepBranchControllerRegistry* registry,
                               size_t index)
{
    return cep_branch_controller_at(registry, index);
}

const cepBranchDirtyEntry*
cep_branch_controller_dirty_entries(const cepBranchController* controller,
                                    size_t* count)
{
    if (!controller || !count) {
        return NULL;
    }
    *count = controller->dirty_index.count;
    return controller->dirty_index.entries;
}

void
cep_branch_controller_clear_dirty(cepBranchController* controller)
{
    if (!controller) {
        return;
    }
    controller->dirty_index.count = 0u;
    controller->dirty_entry_count = 0u;
    controller->pending_mutations = 0u;
    controller->dirty_bytes = 0u;
    controller->pins = 0u;
    controller->periodic_anchor_bt = controller->last_persisted_bt;
}

static bool
cep_branch_controller_risky_dirty(const cepBranchController* controller)
{
    if (!controller) {
        return false;
    }
    return controller->dirty_entry_count > 0u || controller->pending_mutations > 0u;
}

static bool
cep_branch_controller_risky_mode(const cepBranchController* controller)
{
    if (!controller) {
        return false;
    }
    const cepBranchPersistPolicy* policy = cep_branch_controller_policy(controller);
    if (!policy) {
        return false;
    }
    return policy->mode == CEP_BRANCH_PERSIST_VOLATILE;
}

cepBranchPolicyResult
cep_branch_policy_check_read(const cepBranchController* consumer,
                             const cepBranchController* source)
{
    cepBranchPolicyResult result = {
        .access = CEP_BRANCH_POLICY_ACCESS_ALLOW,
        .risk = CEP_BRANCH_POLICY_RISK_NONE,
    };

    if (!consumer || !source || consumer == source) {
        return result;
    }

    bool source_dirty = cep_branch_controller_risky_dirty(source);
    bool source_volatile = cep_branch_controller_risky_mode(source);
    if (!source_dirty && !source_volatile) {
        return result;
    }

    result.risk = source_volatile ? CEP_BRANCH_POLICY_RISK_VOLATILE : CEP_BRANCH_POLICY_RISK_DIRTY;

    const cepBranchPersistPolicy* consumer_policy = cep_branch_controller_policy(consumer);
    bool allow_reads = consumer_policy && consumer_policy->allow_volatile_reads;
    result.access = allow_reads ? CEP_BRANCH_POLICY_ACCESS_DECISION : CEP_BRANCH_POLICY_ACCESS_DENY;
    return result;
}

const char*
cep_branch_policy_risk_label(cepBranchPolicyRisk risk)
{
    switch (risk) {
        case CEP_BRANCH_POLICY_RISK_DIRTY:
            return "dirty";
        case CEP_BRANCH_POLICY_RISK_VOLATILE:
            return "volatile";
        case CEP_BRANCH_POLICY_RISK_NONE:
        default:
            return "none";
    }
}

void
cep_branch_controller_format_label(const cepBranchController* controller,
                                   char* buffer,
                                   size_t capacity)
{
    if (!buffer || capacity == 0u) {
        return;
    }
    if (!controller) {
        (void)snprintf(buffer, capacity, "<none>");
        return;
    }
    const cepDT* dt = &controller->branch_dt;
    unsigned long long domain = dt ? (unsigned long long)cep_id(dt->domain) : 0ull;
    unsigned long long tag = dt ? (unsigned long long)cep_id(dt->tag) : 0ull;
    (void)snprintf(buffer, capacity, "%016llx/%016llx",
                   domain,
                   tag);
}

void
cep_cell_svo_context_init(cepCellSvoContext* ctx, const char* verb)
{
    if (!ctx) {
        return;
    }
    ctx->consumer = NULL;
    ctx->source = NULL;
    ctx->verb = verb;
    ctx->last_result = (cepBranchPolicyResult){
        .access = CEP_BRANCH_POLICY_ACCESS_ALLOW,
        .risk = CEP_BRANCH_POLICY_RISK_NONE,
    };
}

void
cep_cell_svo_context_set_consumer(cepCellSvoContext* ctx, const cepCell* consumer_cell)
{
    if (!ctx) {
        return;
    }
    ctx->consumer = cep_branch_controller_for_cell(consumer_cell);
}

void
cep_cell_svo_context_set_source(cepCellSvoContext* ctx, const cepCell* source_cell)
{
    if (!ctx) {
        return;
    }
    ctx->source = cep_branch_controller_for_cell(source_cell);
}

bool
cep_cell_svo_context_guard(cepCellSvoContext* ctx,
                           const cepCell* fallback_source,
                           const char* topic)
{
    const cepBranchController* source_controller = NULL;
    const cepBranchController* consumer_controller = NULL;
    if (ctx) {
        source_controller = ctx->source;
        consumer_controller = ctx->consumer;
    }
    if (!source_controller && fallback_source) {
        source_controller = cep_branch_controller_for_cell(fallback_source);
    }

    cepBranchPolicyResult policy =
        cep_branch_policy_check_read(consumer_controller, source_controller);
    if (ctx) {
        ctx->last_result = policy;
    }

    if (policy.access == CEP_BRANCH_POLICY_ACCESS_ALLOW ||
        policy.risk == CEP_BRANCH_POLICY_RISK_NONE) {
        return true;
    }

    const char* resolved_topic = topic ? topic : k_branch_policy_topic;
    const char* verb = (ctx && ctx->verb) ? ctx->verb : "cellop";

    char consumer_label[64];
    char source_label[64];
    cep_branch_controller_format_label(consumer_controller, consumer_label, sizeof consumer_label);
    cep_branch_controller_format_label(source_controller, source_label, sizeof source_label);
    const char* risk_label = cep_branch_policy_risk_label(policy.risk);
    const char* action = (policy.access == CEP_BRANCH_POLICY_ACCESS_DECISION) ? "decision" : "deny";

    char note[256];
    snprintf(note,
             sizeof note,
             "verb=%s consumer=%s source=%s risk=%s action=%s",
             verb,
             consumer_label,
             source_label,
             risk_label,
             action);

    const cepDT* severity = (policy.access == CEP_BRANCH_POLICY_ACCESS_DECISION)
                              ? dt_svo_sev_info()
                              : dt_svo_sev_warn();

    cepCeiRequest req = {
        .severity = *severity,
        .topic = resolved_topic,
        .topic_len = 0u,
        .topic_intern = false,
        .note = note,
        .note_len = 0u,
        .origin_kind = "cell.ops",
        .emit_signal = false,
        .ttl_forever = true,
    };
    (void)cep_cei_emit(&req);

    return policy.access != CEP_BRANCH_POLICY_ACCESS_DENY;
}
