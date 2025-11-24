/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cep_branch_controller.h"
#include "cep_enclave_policy.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <inttypes.h>

#include "cep_flat_stream.h"
#include "cep_cei.h"
#include "cep_runtime.h"
#include "cep_namepool.h"

CEP_DEFINE_STATIC_DT(dt_svo_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_svo_sev_info, CEP_ACRO("CEP"), CEP_WORD("sev:info"));
CEP_DEFINE_STATIC_DT(dt_decision_root_name, CEP_ACRO("CEP"), CEP_WORD("decisions"));
CEP_DEFINE_STATIC_DT(dt_decision_consumer_field, CEP_ACRO("CEP"), CEP_WORD("consumer"));
CEP_DEFINE_STATIC_DT(dt_decision_source_field, CEP_ACRO("CEP"), CEP_WORD("source"));
CEP_DEFINE_STATIC_DT(dt_decision_verb_field, CEP_ACRO("CEP"), CEP_WORD("verb"));
CEP_DEFINE_STATIC_DT(dt_decision_risk_field, CEP_ACRO("CEP"), CEP_WORD("risk"));
CEP_DEFINE_STATIC_DT(dt_decision_beat_field, CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_lazy_persist_root_name, CEP_ACRO("CEP"), CEP_WORD("persist"));
CEP_DEFINE_STATIC_DT(dt_lazy_persist_config_name, CEP_ACRO("CEP"), CEP_WORD("config"));
CEP_DEFINE_STATIC_DT(dt_lazy_policy_mode_field, CEP_ACRO("CEP"), CEP_WORD("policy_mode"));
CEP_DEFINE_STATIC_DT(dt_persist_snapshot_field, CEP_ACRO("CEP"), CEP_WORD("snapshot_ro"));

#define CEP_BRANCH_PATH_TEXT_MAX 512u

static const char k_branch_policy_topic[] = "cell.cross_read";
static const char k_branch_evict_topic[] = "persist.evict";
static const char k_branch_deny_topic[] = "sec.branch.deny";

static void
cep_branch_controller_set_veil_recursive(cepCell* node, bool veiled)
{
    if (!node || !cep_cell_is_normal(node)) {
        return;
    }
    node->metacell.veiled = veiled ? 1u : 0u;
    if (!node->store) {
        return;
    }
    for (cepCell* child = cep_cell_first(node);
         child;
         child = cep_cell_next(node, child)) {
        cep_branch_controller_set_veil_recursive(child, veiled);
    }
}

typedef struct {
    bool     active;
    cepCell* root;
    cepCell* cursor;
} cepDecisionReplayState;

static cepDecisionReplayState g_decision_replay_state = {0};

typedef struct {
    const cepBranchPersistPolicy* policy;
    cepBeatNumber                 current_beat;
    cepBeatNumber                 floor_beat;
    uint32_t                      kept_versions;
    uint64_t                      kept_bytes;
    cepBeatNumber                 oldest_kept;
    uint32_t                      evicted_versions;
    uint64_t                      evicted_bytes;
    bool                          quota_reset;
} cepBranchEvictContext;

static void cep_branch_controller_apply_history_policy_to_cell(cepCell* cell,
                                                               cepBranchEvictContext* ctx);
static bool cep_branch_controller_evict_entry(cepEntry* entry, void* context);
static bool cep_branch_controller_clear_history_entry(cepEntry* entry, void* context);
static void cep_branch_controller_clear_branch_history(cepCell* root);
static void cep_branch_controller_emit_eviction_cei(const cepBranchController* controller,
                                                    const cepBranchEvictContext* ctx);

typedef struct {
    cepDT dt;
} cepBranchLazyBootEntry;

static cepBranchLazyBootEntry* g_lazy_boot_entries = NULL;
static size_t                  g_lazy_boot_count = 0u;
static size_t                  g_lazy_boot_capacity = 0u;

static bool
cep_branch_lazy_boot_grow(size_t min_capacity)
{
    size_t desired = g_lazy_boot_capacity ? (g_lazy_boot_capacity * 2u) : 4u;
    if (desired < min_capacity) {
        desired = min_capacity;
    }
    size_t bytes = desired * sizeof *g_lazy_boot_entries;
    cepBranchLazyBootEntry* grown = g_lazy_boot_entries
        ? cep_realloc(g_lazy_boot_entries, bytes)
        : cep_malloc(bytes);
    if (!grown) {
        return false;
    }
    g_lazy_boot_entries = grown;
    g_lazy_boot_capacity = desired;
    return true;
}

bool
cep_branch_lazy_boot_register(const cepDT* branch_dt)
{
    if (!branch_dt || !cep_dt_is_valid(branch_dt)) {
        return false;
    }
    cepDT normalized = cep_dt_clean(branch_dt);
    for (size_t i = 0; i < g_lazy_boot_count; ++i) {
        if (cep_dt_compare(&g_lazy_boot_entries[i].dt, &normalized) == 0) {
            return true;
        }
    }
    if (g_lazy_boot_count == g_lazy_boot_capacity &&
        !cep_branch_lazy_boot_grow(g_lazy_boot_count + 1u)) {
        return false;
    }
    g_lazy_boot_entries[g_lazy_boot_count++].dt = normalized;
    return true;
}

bool
cep_branch_lazy_boot_claim(const cepDT* branch_dt)
{
    if (!branch_dt || !cep_dt_is_valid(branch_dt)) {
        return false;
    }
    cepDT normalized = cep_dt_clean(branch_dt);
    for (size_t i = 0; i < g_lazy_boot_count; ++i) {
        if (cep_dt_compare(&g_lazy_boot_entries[i].dt, &normalized) == 0) {
            if (g_lazy_boot_count > 1u) {
                g_lazy_boot_entries[i] = g_lazy_boot_entries[g_lazy_boot_count - 1u];
            }
            g_lazy_boot_count -= 1u;
            if (g_lazy_boot_count == 0u) {
                cep_branch_lazy_boot_reset();
            }
            return true;
        }
    }
    return false;
}

void
cep_branch_lazy_boot_reset(void)
{
    if (g_lazy_boot_entries) {
        cep_free(g_lazy_boot_entries);
    }
    g_lazy_boot_entries = NULL;
    g_lazy_boot_count = 0u;
    g_lazy_boot_capacity = 0u;
}

static cepCell*
cep_branch_lazy_boot_resolve_child(cepCell* parent, const cepDT* name)
{
    if (!parent || !name) {
        return NULL;
    }
    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child) {
        child = cep_cell_find_by_name_all(parent, name);
    }
    if (!child) {
        return NULL;
    }
    return cep_cell_resolve(child);
}

static bool
cep_branch_lazy_boot_policy_requested(const cepDT* branch_dt)
{
    if (!branch_dt || !cep_dt_is_valid(branch_dt)) {
        return false;
    }
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return false;
    }
    cepCell* resolved_data = cep_cell_resolve(data_root);
    if (!resolved_data) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&resolved_data)) {
        return false;
    }
    cepCell* persist_root =
        cep_branch_lazy_boot_resolve_child(resolved_data, dt_lazy_persist_root_name());
    if (!persist_root) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&persist_root)) {
        return false;
    }
    cepDT normalized = cep_dt_clean(branch_dt);
    cepCell* branch_cell =
        cep_branch_lazy_boot_resolve_child(persist_root, &normalized);
    if (!branch_cell) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&branch_cell)) {
        return false;
    }
    cepCell* config_cell =
        cep_branch_lazy_boot_resolve_child(branch_cell, dt_lazy_persist_config_name());
    if (!config_cell) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&config_cell)) {
        return false;
    }
    cepCell* mode_cell =
        cep_branch_lazy_boot_resolve_child(config_cell, dt_lazy_policy_mode_field());
    if (!mode_cell || !cep_cell_has_data(mode_cell) || !mode_cell->data) {
        return false;
    }
    const char* text = (const char*)cep_cell_data(mode_cell);
    if (!text) {
        return false;
    }
    return strcmp(text, "lazy_load") == 0;
}

bool
cep_branch_snapshot_policy_requested(const cepDT* branch_dt)
{
    if (!branch_dt || !cep_dt_is_valid(branch_dt)) {
        return false;
    }
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return false;
    }
    cepCell* resolved_data = cep_cell_resolve(data_root);
    if (!resolved_data) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&resolved_data)) {
        return false;
    }
    cepCell* persist_root =
        cep_branch_lazy_boot_resolve_child(resolved_data, dt_lazy_persist_root_name());
    if (!persist_root) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&persist_root)) {
        return false;
    }
    cepDT normalized = cep_dt_clean(branch_dt);
    cepCell* branch_cell =
        cep_branch_lazy_boot_resolve_child(persist_root, &normalized);
    if (!branch_cell) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&branch_cell)) {
        return false;
    }
    cepCell* config_cell =
        cep_branch_lazy_boot_resolve_child(branch_cell, dt_lazy_persist_config_name());
    if (!config_cell) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&config_cell)) {
        return false;
    }
    cepCell* snapshot_cell =
        cep_branch_lazy_boot_resolve_child(config_cell, dt_persist_snapshot_field());
    if (snapshot_cell && cep_cell_has_data(snapshot_cell)) {
        const char* text = (const char*)cep_cell_data(snapshot_cell);
        if (text && text[0] != '\0') {
            errno = 0;
            char* endptr = NULL;
            unsigned long long parsed = strtoull(text, &endptr, 10);
            if (errno == 0 && endptr && *endptr == '\0') {
                return parsed != 0u;
            }
            if (strcasecmp(text, "true") == 0 ||
                strcasecmp(text, "on") == 0 ||
                strcasecmp(text, "enable") == 0) {
                return true;
            }
        }
    }
    cepCell* mode_cell =
        cep_branch_lazy_boot_resolve_child(config_cell, dt_lazy_policy_mode_field());
    if (mode_cell && cep_cell_has_data(mode_cell)) {
        const char* text = (const char*)cep_cell_data(mode_cell);
        if (text && strcmp(text, "ro_snapshot") == 0) {
            return true;
        }
    }
    return false;
}

bool
cep_branch_controller_enable_snapshot_mode(cepBranchController* controller)
{
    if (!controller || !controller->branch_root) {
        return false;
    }
    if (controller->policy.mode == CEP_BRANCH_PERSIST_RO_SNAPSHOT) {
        return true;
    }
    cepSealOptions opt = {.recursive = true};
    cepCell* branch_root = controller->branch_root;
    bool forced_veil = false;
    if (!cep_cell_is_floating(branch_root) &&
        !cep_cell_is_veiled(branch_root)) {
        cep_branch_controller_set_veil_recursive(branch_root, true);
        forced_veil = true;
    }
    bool sealed = cep_branch_seal_immutable(branch_root, opt);
    if (forced_veil && !sealed) {
        cep_branch_controller_set_veil_recursive(branch_root, false);
    }
    if (!sealed) {
        return false;
    }
    controller->policy.mode = CEP_BRANCH_PERSIST_RO_SNAPSHOT;
    controller->force_flush = false;
    controller->flush_scheduled_bt = CEP_BEAT_INVALID;
    controller->periodic_anchor_bt = CEP_BEAT_INVALID;
    return true;
}

static void
cep_branch_controller_apply_history_policy_to_cell(cepCell* cell,
                                                   cepBranchEvictContext* ctx)
{
    if (!cell || !ctx || !cep_cell_is_normal(cell)) {
        return;
    }

    if (cell->data) {
        cep_data_history_apply_policy(cell->data,
                                      ctx->floor_beat,
                                      ctx->policy->history_ram_versions,
                                      &ctx->kept_versions,
                                      &ctx->kept_bytes,
                                      &ctx->oldest_kept,
                                       &ctx->evicted_versions,
                                       &ctx->evicted_bytes);
    }

    if (cell->store) {
        cep_store_history_apply_policy(cell->store,
                                       ctx->floor_beat,
                                       ctx->policy->history_ram_versions,
                                       &ctx->kept_versions,
                                       &ctx->kept_bytes,
                                       &ctx->oldest_kept,
                                       &ctx->evicted_versions,
                                       &ctx->evicted_bytes);
    }
}

static bool
cep_branch_controller_evict_entry(cepEntry* entry, void* context)
{
    cepBranchEvictContext* ctx = context;
    if (!ctx || !entry) {
        return true;
    }
    cep_branch_controller_apply_history_policy_to_cell(entry->cell, ctx);
    return true;
}

static bool
cep_branch_controller_clear_history_entry(cepEntry* entry, void* context)
{
    (void)context;
    if (!entry || !entry->cell || !cep_cell_is_normal(entry->cell)) {
        return true;
    }
    if (entry->cell->data) {
        cep_data_history_clear(entry->cell->data);
    }
    if (entry->cell->store) {
        cep_store_history_clear_all(entry->cell->store);
    }
    return true;
}

static void
cep_branch_controller_clear_branch_history(cepCell* root)
{
    if (!root) {
        return;
    }
    if (root->data) {
        cep_data_history_clear(root->data);
    }
    if (root->store) {
        cep_store_history_clear_all(root->store);
    }
    cepEntry entry = {0};
    (void)cep_cell_deep_traverse_all(root,
                                     cep_branch_controller_clear_history_entry,
                                     NULL,
                                     NULL,
                                     &entry);
}

static void
cep_branch_controller_emit_eviction_cei(const cepBranchController* controller,
                                        const cepBranchEvictContext* ctx)
{
    if (!controller || !ctx ||
        (!ctx->evicted_versions && !ctx->quota_reset)) {
        return;
    }

    char label[64];
    cep_branch_controller_format_label(controller, label, sizeof label);

    char note[256];
    snprintf(note,
             sizeof note,
             "branch=%s evicted_versions=%u evicted_bytes=%llu limits(beats=%u versions=%u quota=%llu) quota_reset=%u",
             label,
             ctx->evicted_versions,
             (unsigned long long)ctx->evicted_bytes,
             ctx->policy->history_ram_beats,
             ctx->policy->history_ram_versions,
             (unsigned long long)ctx->policy->ram_quota_bytes,
             ctx->quota_reset ? 1u : 0u);

    cepCeiRequest req = {
        .severity = *dt_svo_sev_info(),
        .topic = k_branch_evict_topic,
        .topic_intern = true,
        .note = note,
        .subject = controller->branch_root,
        .emit_signal = false,
        .ttl_forever = true,
    };
    (void)cep_cei_emit(&req);
}

void
cep_branch_controller_apply_eviction(cepBranchController* controller)
{
    if (!controller || !controller->branch_root) {
        return;
    }
    const cepBranchPersistPolicy* policy = cep_branch_controller_policy(controller);
    if (!policy) {
        return;
    }
    if (policy->mode == CEP_BRANCH_PERSIST_VOLATILE) {
        return;
    }
    if (!policy->history_ram_beats &&
        !policy->history_ram_versions &&
        !policy->ram_quota_bytes) {
        return;
    }

    cepCell* branch_root = cep_cell_resolve(controller->branch_root);
    if (!branch_root) {
        return;
    }

    cepBeatNumber current_beat = cep_beat_index();
    if (current_beat != CEP_BEAT_INVALID &&
        controller->last_eviction_bt == current_beat) {
        return;
    }
    cepBeatNumber floor_beat = 0u;
    if (policy->history_ram_beats &&
        current_beat != CEP_BEAT_INVALID &&
        current_beat > (cepBeatNumber)policy->history_ram_beats) {
        floor_beat = current_beat - policy->history_ram_beats;
    }

    cepBranchEvictContext ctx = {
        .policy = policy,
        .current_beat = current_beat,
        .floor_beat = floor_beat,
        .kept_versions = 0u,
        .kept_bytes = 0u,
        .oldest_kept = 0u,
        .evicted_versions = 0u,
        .evicted_bytes = 0u,
        .quota_reset = false,
    };

    cep_branch_controller_apply_history_policy_to_cell(branch_root, &ctx);
    cepEntry entry = {0};
    if (!cep_cell_deep_traverse_all(branch_root,
                                    cep_branch_controller_evict_entry,
                                    NULL,
                                    &ctx,
                                    &entry)) {
        return;
    }

    if (policy->ram_quota_bytes &&
        ctx.kept_bytes > policy->ram_quota_bytes) {
        /* TODO(cpcl-eviction-quota): Instead of clearing all cached history,
         * implement a proportional trimming strategy that sheds the oldest
         * histories until usage falls under the quota. */
        cep_branch_controller_clear_branch_history(branch_root);
        ctx.evicted_versions += ctx.kept_versions;
        ctx.evicted_bytes += ctx.kept_bytes;
        ctx.kept_versions = 0u;
        ctx.kept_bytes = 0u;
        ctx.oldest_kept = 0u;
        ctx.quota_reset = true;
    }

    if (ctx.kept_versions && ctx.oldest_kept &&
        current_beat != CEP_BEAT_INVALID &&
        current_beat >= ctx.oldest_kept) {
        controller->cached_history_beats =
            (uint32_t)(current_beat - ctx.oldest_kept);
    } else {
        controller->cached_history_beats = 0u;
    }
    controller->cached_history_versions = ctx.kept_versions;
    controller->cached_history_bytes = ctx.kept_bytes;
    controller->last_eviction_bt = (current_beat != CEP_BEAT_INVALID)
                                      ? current_beat
                                      : CEP_BEAT_INVALID;

    if (ctx.evicted_versions || ctx.quota_reset) {
        cep_branch_controller_emit_eviction_cei(controller, &ctx);
    }
}



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
        .history_ram_beats = 0u,
        .history_ram_versions = 0u,
        .ram_quota_bytes = 0u,
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
    cep_branch_lazy_boot_reset();
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
    const cepBranchPersistPolicy* policy = cep_branch_controller_policy(controller);
    if (policy && policy->mode == CEP_BRANCH_PERSIST_RO_SNAPSHOT) {
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
    controller->last_eviction_bt = CEP_BEAT_INVALID;
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
    controller->cached_history_beats = 0u;
    controller->cached_history_versions = 0u;
    controller->cached_history_bytes = 0u;
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
        bool snapshot_policy = cep_branch_snapshot_policy_requested(&child->metacell.dt);
        bool lazy_boot = !snapshot_policy &&
                         cep_branch_lazy_boot_policy_requested(&child->metacell.dt);
        if (lazy_boot && cep_branch_lazy_boot_register(&child->metacell.dt)) {
            continue;
        }
        cepBranchController* controller =
            cep_branch_registry_register(registry, child, &child->metacell.dt);
        if (!controller) {
            success = false;
            continue;
        }
        if (snapshot_policy) {
            (void)cep_branch_controller_enable_snapshot_mode(controller);
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

static cepCell*
cep_decision_cells_root(void)
{
    cepCell* journal = cep_heartbeat_journal_root();
    if (!journal) {
        return NULL;
    }
    return cep_cell_ensure_dictionary_child(journal,
                                            dt_decision_root_name(),
                                            CEP_STORAGE_RED_BLACK_T);
}

static cepCell*
cep_decision_cells_root_resolved(void)
{
    cepCell* root = cep_decision_cells_root();
    if (!root) {
        return NULL;
    }
    cepCell* resolved = cep_cell_resolve(root);
    if (!resolved) {
        return NULL;
    }
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return NULL;
    }
    return resolved;
}

static cepDT
cep_decision_auto_name(void)
{
    cepDT name = {0};
    name.domain = CEP_ACRO("DEC");
    name.tag = CEP_AUTOID;
    return name;
}

static bool
cep_decision_cell_append_entry(const cepBranchController* consumer,
                               const cepBranchController* source,
                               const char* verb,
                               const char* risk_label)
{
    if (!consumer || !source || !verb || !risk_label) {
        return false;
    }

    cepCell* root = cep_decision_cells_root_resolved();
    if (!root) {
        return false;
    }

    cepDT entry_name = cep_decision_auto_name();
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* entry = cep_cell_add_dictionary(root, &entry_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    bool ok = true;
    ok &= cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
    ok &= cep_cell_put_text(entry, dt_decision_verb_field(), verb);
    ok &= cep_cell_put_text(entry, dt_decision_risk_field(), risk_label);
    ok &= cep_cell_put_dt(entry, dt_decision_consumer_field(), &consumer->branch_dt);
    ok &= cep_cell_put_dt(entry, dt_decision_source_field(), &source->branch_dt);
    return ok;
}

static bool
cep_decision_cell_append_security_entry(const cepDT* branch_dt,
                                        const char* verb,
                                        const char* subject,
                                        const char* path,
                                        const char* rule_id,
                                        bool allowed,
                                        const char* reason)
{
    if (!branch_dt || !verb) {
        return false;
    }

    cepCell* root = cep_decision_cells_root_resolved();
    if (!root) {
        return false;
    }

    cepCell* sec_root = cep_cell_ensure_dictionary_child(root,
                                                         CEP_DTAW("CEP", "sec"),
                                                         CEP_STORAGE_RED_BLACK_T);
    if (!sec_root) {
        return false;
    }
    sec_root = cep_cell_resolve(sec_root);
    if (!sec_root || !cep_cell_require_dictionary_store(&sec_root)) {
        return false;
    }

    cepDT entry_name = cep_decision_auto_name();
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* entry = cep_cell_add_dictionary(sec_root, &entry_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        return false;
    }
    if (!cep_cell_require_dictionary_store(&entry)) {
        return false;
    }

    const char* status = allowed ? "allow" : "deny";

    bool ok = true;
    ok &= cep_cell_put_uint64(entry, dt_decision_beat_field(), (uint64_t)cep_beat_index());
    ok &= cep_cell_put_text(entry, dt_decision_verb_field(), verb);
    ok &= cep_cell_put_text(entry, CEP_DTAW("CEP", "status"), status);
    if (subject) {
        ok &= cep_cell_put_text(entry, CEP_DTAW("CEP", "subject"), subject);
    }
    if (path) {
        ok &= cep_cell_put_text(entry, CEP_DTAW("CEP", "path"), path);
    }
    if (rule_id) {
        ok &= cep_cell_put_text(entry, CEP_DTAW("CEP", "rule"), rule_id);
    }
    if (reason) {
        ok &= cep_cell_put_text(entry, CEP_DTAW("CEP", "note"), reason);
    }
    ok &= cep_cell_put_dt(entry, CEP_DTAW("CEP", "branch"), branch_dt);
    return ok;
}

void
cep_enclave_policy_record_branch_decision(const cepDT* branch_dt,
                                          const char* verb,
                                          const char* subject_id,
                                          const char* path_text,
                                          const cepEnclaveBranchDecision* decision,
                                          bool allowed,
                                          const char* reason)
{
    const char* subject = subject_id ? subject_id : "pack:<unknown>";
    const char* rule_id = (decision && decision->rule_id) ? decision->rule_id : NULL;
    const char* path = (path_text && *path_text) ? path_text : NULL;

    (void)cep_decision_cell_append_security_entry(branch_dt,
                                                  verb ? verb : "cellop",
                                                  subject,
                                                  path,
                                                  rule_id,
                                                  allowed,
                                                  reason);

    if (!allowed) {
        char note[256];
        snprintf(note,
                 sizeof note,
                 "verb=%s subject=%s path=%s rule=%s reason=%s",
                 verb ? verb : "cellop",
                 subject,
                 path ? path : "<unknown>",
                 rule_id ? rule_id : "<default>",
                 reason ? reason : "denied");

        cepCeiRequest req = {
            .severity = *dt_svo_sev_warn(),
            .topic = k_branch_deny_topic,
            .topic_intern = true,
            .note = note,
            .note_len = 0u,
            .emit_signal = true,
            .ttl_forever = true,
        };
        (void)cep_cei_emit(&req);
    }
}

static bool
cep_decision_cell_read_u64(const cepCell* parent, const cepDT* field, uint64_t* out)
{
    if (!parent || !field || !out) {
        return false;
    }
    cepDT lookup = cep_dt_clean(field);
    cepCell* child = cep_cell_find_by_name((cepCell*)parent, &lookup);
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    const char* text = (const char*)cep_cell_data(child);
    if (!text) {
        return false;
    }
    errno = 0;
    char* endptr = NULL;
    unsigned long long parsed = strtoull(text, &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') {
        return false;
    }
    *out = (uint64_t)parsed;
    return true;
}

static bool
cep_decision_cell_read_text(const cepCell* parent, const cepDT* field, const char** out)
{
    if (!parent || !field || !out) {
        return false;
    }
    cepDT lookup = cep_dt_clean(field);
    cepCell* child = cep_cell_find_by_name((cepCell*)parent, &lookup);
    if (!child || !cep_cell_has_data(child)) {
        return false;
    }
    const char* text = (const char*)cep_cell_data(child);
    if (!text) {
        return false;
    }
    *out = text;
    return true;
}

static bool
cep_decision_cell_read_dt(const cepCell* parent, const cepDT* field, cepDT* out)
{
    if (!parent || !field || !out) {
        return false;
    }
    cepDT lookup = cep_dt_clean(field);
    cepCell* container = cep_cell_find_by_name((cepCell*)parent, &lookup);
    if (!container) {
        return false;
    }
    cepCell* resolved = cep_cell_resolve(container);
    if (!resolved) {
        return false;
    }
    uint64_t domain = 0u;
    uint64_t tag = 0u;
    if (!cep_decision_cell_read_u64(resolved, CEP_DTAW("CEP", "domain"), &domain) ||
        !cep_decision_cell_read_u64(resolved, CEP_DTAW("CEP", "tag"), &tag)) {
        return false;
    }
    out->domain = (cepID)domain;
    out->tag = (cepID)tag;
    out->glob = 0u;
    return true;
}

static bool
cep_decision_cell_replay_consume(const cepBranchController* consumer,
                                 const cepBranchController* source,
                                 const char* verb,
                                 const char* risk_label)
{
    if (!consumer || !source || !verb || !risk_label) {
        return false;
    }
    if (!g_decision_replay_state.active) {
        return false;
    }
    if (!g_decision_replay_state.root) {
        cepCell* resolved = cep_decision_cells_root_resolved();
        if (!resolved) {
            return false;
        }
        g_decision_replay_state.root = resolved;
        g_decision_replay_state.cursor = cep_cell_first(resolved);
    }
    cepCell* entry = g_decision_replay_state.cursor;
    if (!entry) {
        return false;
    }

    bool ok = true;
    cepDT recorded_consumer = {0};
    cepDT recorded_source = {0};
    ok &= cep_decision_cell_read_dt(entry, dt_decision_consumer_field(), &recorded_consumer);
    ok &= cep_decision_cell_read_dt(entry, dt_decision_source_field(), &recorded_source);
    const char* recorded_verb = NULL;
    ok &= cep_decision_cell_read_text(entry, dt_decision_verb_field(), &recorded_verb);
    const char* recorded_risk = NULL;
    ok &= cep_decision_cell_read_text(entry, dt_decision_risk_field(), &recorded_risk);
    uint64_t recorded_beat = 0u;
    ok &= cep_decision_cell_read_u64(entry, dt_decision_beat_field(), &recorded_beat);
    if (!ok) {
        return false;
    }

    if (cep_dt_compare(&recorded_consumer, &consumer->branch_dt) != 0 ||
        cep_dt_compare(&recorded_source, &source->branch_dt) != 0) {
        return false;
    }

    if (!recorded_verb || strcmp(recorded_verb, verb) != 0) {
        return false;
    }
    if (!recorded_risk || strcmp(recorded_risk, risk_label) != 0) {
        return false;
    }

    uint64_t current = (uint64_t)cep_beat_index();
    if (recorded_beat != current) {
        return false;
    }

    g_decision_replay_state.cursor =
        cep_cell_next(g_decision_replay_state.root, entry);
    return true;
}

bool
cep_decision_cell_record_cross_branch(const cepBranchController* consumer,
                                      const cepBranchController* source,
                                      const char* verb,
                                      cepBranchPolicyRisk risk)
{
    if (!consumer || !source) {
        return false;
    }
    const char* resolved_verb = verb ? verb : "cellop";
    const char* risk_label = cep_branch_policy_risk_label(risk);
    if (!risk_label) {
        risk_label = "none";
    }

    if (g_decision_replay_state.active) {
        return cep_decision_cell_replay_consume(consumer, source, resolved_verb, risk_label);
    }

    return cep_decision_cell_append_entry(consumer, source, resolved_verb, risk_label);
}

bool
cep_decision_cell_replay_begin(void)
{
    cepCell* root = cep_decision_cells_root_resolved();
    if (!root) {
        return false;
    }
    g_decision_replay_state.active = true;
    g_decision_replay_state.root = root;
    g_decision_replay_state.cursor = cep_cell_first(root);
    cep_flat_stream_mark_decision_replay();
    return true;
}

void
cep_decision_cell_replay_end(void)
{
    g_decision_replay_state.active = false;
    g_decision_replay_state.root = NULL;
    g_decision_replay_state.cursor = NULL;
}

static const char*
cep_branch_controller_subject_label(const cepBranchController* controller,
                                    char* buffer,
                                    size_t capacity)
{
    if (!buffer || capacity == 0u) {
        return NULL;
    }
    if (!controller) {
        (void)snprintf(buffer, capacity, "pack:<unknown>");
        return buffer;
    }
    const cepDT* dt = &controller->branch_dt;
    const char* tag_text = dt ? cep_namepool_lookup(dt->tag, NULL) : NULL;
    if (tag_text && tag_text[0]) {
        (void)snprintf(buffer, capacity, "pack:%s", tag_text);
        return buffer;
    }
    (void)snprintf(buffer,
                   capacity,
                   "pack:%016llx",
                   (unsigned long long)cep_id(dt ? dt->tag : 0u));
    return buffer;
}

static bool
cep_branch_controller_path_to_string(const cepPath* path,
                                     char* buffer,
                                     size_t capacity)
{
    if (!path || !buffer || capacity == 0u) {
        return false;
    }
    size_t used = 0u;
    buffer[used++] = '/';
    for (unsigned i = 1u; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        const cepDT* dt = &segment->dt;
        const char* tag_text = dt ? cep_namepool_lookup(dt->tag, NULL) : NULL;
        char fallback[32];
        if (!tag_text || !tag_text[0]) {
            (void)snprintf(fallback,
                           sizeof fallback,
                           "%016llx",
                           (unsigned long long)cep_id(dt ? dt->tag : 0u));
            tag_text = fallback;
        }
        size_t len = strlen(tag_text);
        if (used + len >= capacity) {
            return false;
        }
        memcpy(&buffer[used], tag_text, len);
        used += len;
        if (i + 1u < path->length) {
            if (used + 1u >= capacity) {
                return false;
            }
            buffer[used++] = '/';
        }
    }
    if (used >= capacity) {
        return false;
    }
    buffer[used] = '\0';
    return true;
}

static bool
cep_branch_controller_format_cell_path(const cepCell* cell,
                                       char* buffer,
                                       size_t capacity)
{
    if (!cell || !buffer || capacity == 0u) {
        return false;
    }
    cepPath* path = NULL;
    if (!cep_cell_path(cell, &path)) {
        return false;
    }
    bool ok = cep_branch_controller_path_to_string(path, buffer, capacity);
    cep_free(path);
    return ok;
}

static uint32_t
cep_branch_controller_resolve_svo_verb(const char* verb)
{
    if (!verb) {
        return CEP_ENCLAVE_VERB_READ;
    }
    if (strstr(verb, "delete")) {
        return CEP_ENCLAVE_VERB_DELETE;
    }
    if (strstr(verb, "move")) {
        return CEP_ENCLAVE_VERB_LINK;
    }
    if (strstr(verb, "update") || strstr(verb, "write")) {
        return CEP_ENCLAVE_VERB_WRITE;
    }
    return CEP_ENCLAVE_VERB_READ;
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
    ctx->decision_required = false;
    ctx->decision_recorded = false;
    ctx->security_branch = NULL;
    ctx->subject_id = NULL;
    ctx->subject_label[0] = '\0';
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
    const cepDT* security_branch_dt = ctx ? ctx->security_branch : NULL;
    const char* subject_id = ctx ? ctx->subject_id : NULL;
    if (ctx && !subject_id) {
        const char* label = cep_branch_controller_subject_label(consumer_controller,
                                                                ctx->subject_label,
                                                                sizeof ctx->subject_label);
        if (label && label[0]) {
            ctx->subject_id = label;
            subject_id = ctx->subject_id;
        }
    }
    if (!subject_id) {
        subject_id = "pack:<unknown>";
    }
    char branch_path[CEP_BRANCH_PATH_TEXT_MAX];
    branch_path[0] = '\0';
    bool source_under_security = fallback_source &&
                                 cep_cell_is_under_security_branch(fallback_source);
    bool has_branch_path = source_under_security &&
                           cep_branch_controller_format_cell_path(fallback_source,
                                                                  branch_path,
                                                                  sizeof branch_path);
    CEP_DEBUG_PRINTF("[svo_guard] fallback=%p under_security=%d has_path=%d topic=%s\n",
                     (const void*)fallback_source,
                     source_under_security ? 1 : 0,
                     has_branch_path ? 1 : 0,
                     topic ? topic : (source_under_security ? k_branch_deny_topic : k_branch_policy_topic));
    const char* resolved_topic =
        topic ? topic : (source_under_security ? k_branch_deny_topic : k_branch_policy_topic);
    cepEnclaveBranchDecision branch_decision = {0};
    char branch_reason[128];
    branch_reason[0] = '\0';
    cepEnclaveBranchResult branch_result = CEP_ENCLAVE_BRANCH_RESULT_SKIP;
    const cepBranchController* policy_branch = source_controller;

    cepBranchController* security_controller = NULL;
    if (!source_controller && source_under_security) {
        security_controller = cep_branch_controller_for_security_cell(fallback_source);
        if (!policy_branch) {
            policy_branch = security_controller;
        }
    }
    if (has_branch_path) {
        cepID subject_pack = policy_branch ? policy_branch->branch_dt.tag : 0u;
        uint32_t branch_verb = cep_branch_controller_resolve_svo_verb(ctx ? ctx->verb : NULL);
        branch_result = cep_enclave_policy_check_branch(branch_path,
                                                        subject_pack,
                                                        branch_verb,
                                                        &branch_decision,
                                                        branch_reason,
                                                        sizeof branch_reason);
        CEP_DEBUG_PRINTF("[svo_guard] policy_check path=%s verb=%u subject=%016llx result=%d reason=%s\n",
                         branch_path,
                         (unsigned)branch_verb,
                         (unsigned long long)subject_pack,
                         (int)branch_result,
                         branch_reason[0] ? branch_reason : "<none>");
        if (branch_result == CEP_ENCLAVE_BRANCH_RESULT_DENY ||
            branch_result == CEP_ENCLAVE_BRANCH_RESULT_ERROR) {
            const char* reason = branch_reason[0] ? branch_reason : "branch policy denied access";
            cep_enclave_policy_record_branch_decision(policy_branch ? &policy_branch->branch_dt : NULL,
                                                      ctx && ctx->verb ? ctx->verb : "cellop",
                                                      subject_id,
                                                      branch_path,
                                                      &branch_decision,
                                                      false,
                                                      reason);

            char consumer_label[64];
            char source_label[64];
            cep_branch_controller_format_label(consumer_controller,
                                               consumer_label,
                                               sizeof consumer_label);
            cep_branch_controller_format_label(source_controller ? source_controller : security_controller,
                                               source_label,
                                               sizeof source_label);
            const char* verb = (ctx && ctx->verb) ? ctx->verb : "cellop";
            char note[256];
            enum { label_note_limit = 32, branch_note_limit = 48, reason_note_limit = 48 };
            char consumer_snippet[label_note_limit + 1];
            size_t consumer_len = strnlen(consumer_label, label_note_limit);
            memcpy(consumer_snippet, consumer_label, consumer_len);
            consumer_snippet[consumer_len] = '\0';
            if (consumer_label[consumer_len] != '\0' && consumer_len >= 3u) {
                consumer_snippet[consumer_len - 3u] = '.';
                consumer_snippet[consumer_len - 2u] = '.';
                consumer_snippet[consumer_len - 1u] = '.';
            }
            char source_snippet[label_note_limit + 1];
            size_t source_len = strnlen(source_label, label_note_limit);
            memcpy(source_snippet, source_label, source_len);
            source_snippet[source_len] = '\0';
            if (source_label[source_len] != '\0' && source_len >= 3u) {
                source_snippet[source_len - 3u] = '.';
                source_snippet[source_len - 2u] = '.';
                source_snippet[source_len - 1u] = '.';
            }
            char branch_snippet[branch_note_limit + 1];
            size_t branch_len = strnlen(branch_path, branch_note_limit);
            memcpy(branch_snippet, branch_path, branch_len);
            branch_snippet[branch_len] = '\0';
            if (branch_path[branch_len] != '\0' && branch_len >= 3u) {
                branch_snippet[branch_len - 3u] = '.';
                branch_snippet[branch_len - 2u] = '.';
                branch_snippet[branch_len - 1u] = '.';
            }
            char reason_snippet[reason_note_limit + 1];
            size_t reason_len = strnlen(reason, reason_note_limit);
            memcpy(reason_snippet, reason, reason_len);
            reason_snippet[reason_len] = '\0';
            if (reason[reason_len] != '\0' && reason_len >= 3u) {
                reason_snippet[reason_len - 3u] = '.';
                reason_snippet[reason_len - 2u] = '.';
                reason_snippet[reason_len - 1u] = '.';
            }
            snprintf(note,
                     sizeof note,
                     "verb=%s consumer=%s source=%s branch=%s reason=%s action=deny",
                     verb,
                     consumer_snippet,
                     source_snippet,
                     branch_snippet,
                     reason_snippet);

            CEP_DEBUG_PRINTF("[svo_guard] branch_deny topic=%s note=%s\n",
                             resolved_topic,
                             note);
            cepCeiRequest req = {
                .severity = *dt_svo_sev_warn(),
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
            return false;
        }
    }

    cepBranchPolicyResult policy =
        cep_branch_policy_check_read(consumer_controller, source_controller);
    if (ctx) {
        ctx->last_result = policy;
        ctx->decision_required = (policy.access == CEP_BRANCH_POLICY_ACCESS_DECISION);
        ctx->decision_recorded = false;
    }

    if (policy.access == CEP_BRANCH_POLICY_ACCESS_ALLOW ||
        policy.risk == CEP_BRANCH_POLICY_RISK_NONE) {
        if (branch_result == CEP_ENCLAVE_BRANCH_RESULT_ALLOW && has_branch_path) {
            cep_enclave_policy_record_branch_decision(policy_branch ? &policy_branch->branch_dt : NULL,
                                                      ctx && ctx->verb ? ctx->verb : "cellop",
                                                      subject_id,
                                                      branch_path,
                                                      &branch_decision,
                                                      true,
                                                      NULL);
        }
        if (security_branch_dt && consumer_controller) {
            cep_decision_cell_append_security_entry(security_branch_dt,
                                                    ctx && ctx->verb ? ctx->verb : "cellop",
                                                    subject_id,
                                                    NULL,
                                                    NULL,
                                                    true,
                                                    NULL);
        }
        return true;
    }

    const char* verb = (ctx && ctx->verb) ? ctx->verb : "cellop";
    bool decision_recorded = true;
    if (policy.access == CEP_BRANCH_POLICY_ACCESS_DECISION) {
        decision_recorded = cep_decision_cell_record_cross_branch(consumer_controller,
                                                                  source_controller,
                                                                  verb,
                                                                  policy.risk);
        if (ctx) {
            ctx->decision_recorded = decision_recorded;
        }
        if (decision_recorded &&
            branch_result == CEP_ENCLAVE_BRANCH_RESULT_ALLOW &&
            has_branch_path) {
            cep_enclave_policy_record_branch_decision(policy_branch ? &policy_branch->branch_dt : NULL,
                                                      verb,
                                                      subject_id,
                                                      branch_path,
                                                      &branch_decision,
                                                      true,
                                                      NULL);
        }
        if (security_branch_dt && consumer_controller) {
            cep_decision_cell_append_security_entry(security_branch_dt,
                                                    verb,
                                                    subject_id,
                                                    NULL,
                                                    NULL,
                                                    decision_recorded,
                                                    decision_recorded ? "vol_read" : "deny");
        }
    }

    char consumer_label[64];
    char source_label[64];
    cep_branch_controller_format_label(consumer_controller, consumer_label, sizeof consumer_label);
    cep_branch_controller_format_label(source_controller, source_label, sizeof source_label);
    const char* risk_label = cep_branch_policy_risk_label(policy.risk);
    const char* action = "deny";
    if (policy.access == CEP_BRANCH_POLICY_ACCESS_DECISION) {
        action = decision_recorded ? "decision" : "decision-missing";
    }

    char note[256];
    snprintf(note,
             sizeof note,
             "verb=%s consumer=%s source=%s risk=%s action=%s",
             verb,
             consumer_label,
             source_label,
             risk_label,
             action);

    const cepDT* severity = dt_svo_sev_warn();
    if (policy.access == CEP_BRANCH_POLICY_ACCESS_DECISION && decision_recorded) {
        severity = dt_svo_sev_info();
    }

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
    CEP_DEBUG_PRINTF("[svo_guard] branch_policy emit topic=%s note=%s access=%d risk=%d decision=%d\n",
                     resolved_topic,
                     note,
                     (int)policy.access,
                     (int)policy.risk,
                     decision_recorded ? 1 : 0);
    (void)cep_cei_emit(&req);

    return decision_recorded && (policy.access != CEP_BRANCH_POLICY_ACCESS_DENY);
}
