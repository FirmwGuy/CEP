/* Selects a playbook action for a learner, recording a Decision Cell with
   pipeline/species/variant context and imaginate breadcrumbs. Deterministic
   given identical inputs; imaginate sampling uses a BLAKE3 seed over focus key,
   pipeline metadata, beat, and prior imaginate state. */
/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_l2_playbook.h"

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_namepool.h"
#include "blake3.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

CEP_DEFINE_STATIC_DT(dt_runtime_root, CEP_ACRO("CEP"), cep_namepool_intern_cstr("runtime"));
CEP_DEFINE_STATIC_DT(dt_runtime_playbooks, CEP_ACRO("CEP"), cep_namepool_intern_cstr("playbooks"));
CEP_DEFINE_STATIC_DT(dt_runtime_decisions, CEP_ACRO("CEP"), cep_namepool_intern_cstr("decisions"));
CEP_DEFINE_STATIC_DT(dt_actions_field, CEP_ACRO("CEP"), CEP_WORD("actions"));
CEP_DEFINE_STATIC_DT(dt_imaginate_state_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_state"));
CEP_DEFINE_STATIC_DT(dt_exploration_bias_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("exploration_bias"));
CEP_DEFINE_STATIC_DT(dt_last_seed_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("last_seed"));
CEP_DEFINE_STATIC_DT(dt_last_sample_rank_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("last_sample_rank"));
CEP_DEFINE_STATIC_DT(dt_last_update_bt_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("last_update_bt"));
CEP_DEFINE_STATIC_DT(dt_attempts_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("attempts"));
CEP_DEFINE_STATIC_DT(dt_success_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("success"));
CEP_DEFINE_STATIC_DT(dt_avg_cost_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("avg_cost"));
CEP_DEFINE_STATIC_DT(dt_last_bt_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("last_bt"));
CEP_DEFINE_STATIC_DT(dt_imaginate_flag_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate_used"));
CEP_DEFINE_STATIC_DT(dt_pipeline_field, CEP_ACRO("CEP"), CEP_WORD("pipeline"));
CEP_DEFINE_STATIC_DT(dt_pipeline_id_field, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_stage_id_field, CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_dag_run_id_field, CEP_ACRO("CEP"), CEP_WORD("dag_run_id"));
CEP_DEFINE_STATIC_DT(dt_hop_index_field, CEP_ACRO("CEP"), CEP_WORD("hop_index"));
CEP_DEFINE_STATIC_DT(dt_species_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("species"));
CEP_DEFINE_STATIC_DT(dt_variant_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("variant"));
CEP_DEFINE_STATIC_DT(dt_focus_key_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("focus_key"));
CEP_DEFINE_STATIC_DT(dt_learner_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("learner"));
CEP_DEFINE_STATIC_DT(dt_skill_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("skill"));
CEP_DEFINE_STATIC_DT(dt_action_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("action"));
CEP_DEFINE_STATIC_DT(dt_action_rank_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("action_rank"));
CEP_DEFINE_STATIC_DT(dt_action_space_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("action_space"));
CEP_DEFINE_STATIC_DT(dt_imaginate_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("imaginate"));
CEP_DEFINE_STATIC_DT(dt_used_field, CEP_ACRO("CEP"), CEP_WORD("used"));
CEP_DEFINE_STATIC_DT(dt_seed_field, CEP_ACRO("CEP"), CEP_WORD("seed"));
CEP_DEFINE_STATIC_DT(dt_sample_rank_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("sample_rank"));
CEP_DEFINE_STATIC_DT(dt_stats_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("stats_snapshot"));
CEP_DEFINE_STATIC_DT(dt_note_field, CEP_ACRO("CEP"), CEP_WORD("note"));
CEP_DEFINE_STATIC_DT(dt_playbook_rev_field, CEP_ACRO("CEP"), cep_namepool_intern_cstr("playbook_rev"));

static cepCell* cep_l2_playbook_require_dict(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }
    cepCell* child = cep_cell_ensure_dictionary_child(parent, name, CEP_STORAGE_RED_BLACK_T);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_require_dictionary_store(&child)) {
        return NULL;
    }
    return child;
}

static cepCell* cep_l2_playbook_row(cepCell* eco_root, const char* learner_id, const char* focus_key, cepCell** actions_out, cepCell** imaginate_state_out) {
    if (!eco_root || !learner_id || !focus_key) {
        return NULL;
    }
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    if (!runtime_root) {
        return NULL;
    }
    cepCell* playbooks_root = cep_l2_playbook_require_dict(runtime_root, dt_runtime_playbooks());
    if (!playbooks_root) {
        return NULL;
    }

    cepDT learner_dt = {.domain = CEP_ACRO("CEP"), .tag = cep_namepool_intern_cstr(learner_id), .glob = 0u};
    cepCell* learner = cep_l2_playbook_require_dict(playbooks_root, &learner_dt);
    if (!learner) {
        return NULL;
    }

    cepDT focus_dt = {.domain = CEP_ACRO("CEP"), .tag = cep_namepool_intern_cstr(focus_key), .glob = 0u};
    cepCell* row = cep_l2_playbook_require_dict(learner, &focus_dt);
    if (!row) {
        return NULL;
    }

    if (actions_out) {
        *actions_out = cep_l2_playbook_require_dict(row, dt_actions_field());
    }
    if (imaginate_state_out) {
        *imaginate_state_out = cep_l2_playbook_require_dict(row, dt_imaginate_state_field());
    }
    return row;
}

static bool cep_l2_playbook_put_pipeline_block(cepCell* parent, const cepPipelineMetadata* pipeline) {
    if (!parent || !pipeline) {
        return false;
    }
    cepCell* block = cep_l2_playbook_require_dict(parent, dt_pipeline_field());
    if (!block) {
        return false;
    }
    if (pipeline->pipeline_id) {
        const char* text = cep_namepool_lookup(pipeline->pipeline_id, NULL);
        if (text) {
            (void)cep_cell_put_text(block, dt_pipeline_id_field(), text);
        }
    }
    if (pipeline->stage_id) {
        const char* text = cep_namepool_lookup(pipeline->stage_id, NULL);
        if (text) {
            (void)cep_cell_put_text(block, dt_stage_id_field(), text);
        }
    }
    if (pipeline->dag_run_id > 0u) {
        (void)cep_cell_put_uint64(block, dt_dag_run_id_field(), pipeline->dag_run_id);
    }
    if (pipeline->hop_index > 0u) {
        (void)cep_cell_put_uint64(block, dt_hop_index_field(), pipeline->hop_index);
    }
    return true;
}

static bool cep_l2_playbook_put_dt_field(cepCell* parent, const cepDT* field, const cepDT* value) {
    if (!parent || !field || !value || !cep_dt_is_valid(value)) {
        return false;
    }
    return cep_cell_put_dt(parent, field, value);
}

static bool cep_l2_playbook_put_text_field(cepCell* parent, const cepDT* field, const char* text) {
    if (!parent || !field || !text || !*text) {
        return false;
    }
    return cep_cell_put_text(parent, field, text);
}

static uint64_t cep_l2_playbook_sum_uint64(uint64_t a, uint64_t b) {
    uint64_t res = a + b;
    if (res < a) {
        res = UINT64_MAX;
    }
    return res;
}

static uint64_t cep_l2_playbook_read_u64(cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return 0u;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child) {
        return 0u;
    }
    cepData* data = NULL;
    if (!cep_cell_require_data(&child, &data) || !data || data->size < sizeof(uint64_t)) {
        return 0u;
    }
    uint64_t value = 0u;
    memcpy(&value, cep_data_payload(data), sizeof value);
    return value;
}

static double cep_l2_playbook_read_double(cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return 0.0;
    }
    cepCell* child = cep_cell_find_by_name(parent, field);
    child = child ? cep_cell_resolve(child) : NULL;
    if (!child || !cep_cell_has_data(child)) {
        return 0.0;
    }
    const char* text = (const char*)cep_cell_data(child);
    if (!text) {
        return 0.0;
    }
    char* end = NULL;
    double parsed = strtod(text, &end);
    return (end && end != text) ? parsed : 0.0;
}

static void cep_l2_playbook_store_imaginate_state(cepCell* state_root,
                                                  double exploration_bias,
                                                  uint64_t seed,
                                                  size_t sample_rank) {
    if (!state_root) {
        return;
    }
    char bias_buf[32];
    snprintf(bias_buf, sizeof bias_buf, "%.6f", exploration_bias);
    (void)cep_cell_put_text(state_root, dt_exploration_bias_field(), bias_buf);
    (void)cep_cell_put_uint64(state_root, dt_last_seed_field(), seed);
    (void)cep_cell_put_uint64(state_root, dt_last_sample_rank_field(), (uint64_t)sample_rank);
    (void)cep_cell_put_uint64(state_root, dt_last_update_bt_field(), (uint64_t)cep_beat_index());
}

static uint64_t cep_l2_playbook_hash_seed(const cepL2DecisionRequest* req, uint64_t last_seed) {
    if (!req || !req->focus_key || !req->learner_id) {
        return 0u;
    }
    blake3_hasher hasher;
    unsigned char digest[16];
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, req->focus_key, strlen(req->focus_key));
    blake3_hasher_update(&hasher, req->learner_id, strlen(req->learner_id));
    if (req->pipeline) {
        const char* pid = req->pipeline->pipeline_id ? cep_namepool_lookup(req->pipeline->pipeline_id, NULL) : NULL;
        const char* sid = req->pipeline->stage_id ? cep_namepool_lookup(req->pipeline->stage_id, NULL) : NULL;
        if (pid) {
            blake3_hasher_update(&hasher, pid, strlen(pid));
        }
        if (sid) {
            blake3_hasher_update(&hasher, sid, strlen(sid));
        }
        blake3_hasher_update(&hasher, &req->pipeline->dag_run_id, sizeof req->pipeline->dag_run_id);
        blake3_hasher_update(&hasher, &req->pipeline->hop_index, sizeof req->pipeline->hop_index);
    }
    uint64_t beat = (uint64_t)cep_beat_index();
    blake3_hasher_update(&hasher, &beat, sizeof beat);
    blake3_hasher_update(&hasher, &last_seed, sizeof last_seed);
    blake3_hasher_finalize(&hasher, digest, sizeof digest);
    uint64_t seed = 0u;
    memcpy(&seed, digest, sizeof seed);
    return seed;
}

static cepCell* cep_l2_playbook_record_decision(cepCell* eco_root,
                                                cepCell* playbook_row,
                                                const cepL2DecisionRequest* req,
                                                const char* action_id,
                                                size_t action_rank,
                                                size_t action_space,
                                                bool imaginate_used,
                                                uint64_t seed,
                                                size_t sample_rank,
                                                uint64_t playbook_rev) {
    if (!eco_root || !req || !action_id) {
        return NULL;
    }
    cepCell* runtime_root = cep_cell_find_by_name(eco_root, dt_runtime_root());
    runtime_root = runtime_root ? cep_cell_resolve(runtime_root) : NULL;
    if (!runtime_root) {
        return NULL;
    }
    cepCell* decisions_root = cep_l2_playbook_require_dict(runtime_root, dt_runtime_decisions());
    if (!decisions_root) {
        return NULL;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT entry_name = {
        .domain = CEP_ACRO("CEP"),
        .tag = CEP_AUTOID,
        .glob = 0u,
    };
    cepCell* entry = cep_cell_add_dictionary(decisions_root, &entry_name, 0u, &dict_type, CEP_STORAGE_RED_BLACK_T);
    entry = entry ? cep_cell_resolve(entry) : NULL;
    if (!entry || !cep_cell_require_dictionary_store(&entry)) {
        return NULL;
    }

    (void)cep_cell_put_uint64(entry, CEP_DTAW("CEP", "beat"), (uint64_t)cep_beat_index());
    (void)cep_l2_playbook_put_text_field(entry, dt_focus_key_field(), req->focus_key);
    (void)cep_l2_playbook_put_text_field(entry, dt_learner_field(), req->learner_id);
    if (req->skill_id) {
        (void)cep_l2_playbook_put_text_field(entry, dt_skill_field(), req->skill_id);
    }
    (void)cep_l2_playbook_put_text_field(entry, dt_action_field(), action_id);
    (void)cep_cell_put_uint64(entry, dt_action_rank_field(), (uint64_t)action_rank);
    (void)cep_cell_put_uint64(entry, dt_action_space_field(), (uint64_t)action_space);

    if (req->pipeline) {
        (void)cep_l2_playbook_put_pipeline_block(entry, req->pipeline);
    }
    (void)cep_l2_playbook_put_dt_field(entry, dt_species_field(), req->species_id);
    (void)cep_l2_playbook_put_dt_field(entry, dt_variant_field(), req->variant_id);

    cepCell* imaginate = cep_l2_playbook_require_dict(entry, dt_imaginate_field());
    if (imaginate) {
        (void)cep_cell_put_uint64(imaginate, dt_used_field(), imaginate_used ? 1u : 0u);
        (void)cep_cell_put_uint64(imaginate, dt_seed_field(), seed);
        (void)cep_cell_put_uint64(imaginate, dt_sample_rank_field(), (uint64_t)sample_rank);
        char bias_buf[32];
        snprintf(bias_buf, sizeof bias_buf, "%.6f", req->exploration_bias);
        (void)cep_cell_put_text(imaginate, dt_exploration_bias_field(), bias_buf);
    }

    cepCell* stats = cep_l2_playbook_require_dict(entry, dt_stats_field());
    if (stats && playbook_row) {
        cepCell* actions_root = cep_cell_find_by_name(playbook_row, dt_actions_field());
        actions_root = actions_root ? cep_cell_resolve(actions_root) : NULL;
        if (actions_root && cep_cell_require_dictionary_store(&actions_root)) {
            cepDT action_dt = {.domain = CEP_ACRO("CEP"), .tag = cep_namepool_intern_cstr(action_id), .glob = 0u};
            cepCell* action_cell = cep_cell_find_by_name(actions_root, &action_dt);
            action_cell = action_cell ? cep_cell_resolve(action_cell) : NULL;
            if (action_cell && cep_cell_require_dictionary_store(&action_cell)) {
                (void)cep_cell_put_uint64(stats, dt_attempts_field(), cep_l2_playbook_read_u64(action_cell, dt_attempts_field()));
                (void)cep_cell_put_uint64(stats, dt_success_field(), cep_l2_playbook_read_u64(action_cell, dt_success_field()));
                (void)cep_cell_put_uint64(stats, dt_imaginate_flag_field(), cep_l2_playbook_read_u64(action_cell, dt_imaginate_flag_field()));
                double avg_cost = cep_l2_playbook_read_double(action_cell, dt_avg_cost_field());
                char avg_buf[32];
                snprintf(avg_buf, sizeof avg_buf, "%.6f", avg_cost);
                (void)cep_cell_put_text(stats, dt_avg_cost_field(), avg_buf);
                (void)cep_cell_put_uint64(stats, dt_last_bt_field(), cep_l2_playbook_read_u64(action_cell, dt_last_bt_field()));
            }
        }
    }

    if (playbook_row) {
        cepCell* parents[] = {playbook_row};
        (void)cep_cell_add_parents(entry, parents, 1u);
    }
    (void)cep_cell_put_uint64(entry, dt_playbook_rev_field(), playbook_rev);
    (void)cep_cell_put_text(entry, dt_note_field(), "decision_recorded");
    return entry;
}

bool cep_l2_playbook_select(const cepL2DecisionRequest* req, cepL2DecisionResult* out) {
    if (!req || !req->eco_root || !req->learner_id || !req->focus_key || !req->actions || req->action_count == 0u || !out) {
        return false;
    }

    memset(out, 0, sizeof *out);

    cepCell* actions_root = NULL;
    cepCell* imaginate_state = NULL;
    cepCell* row = cep_l2_playbook_row(req->eco_root, req->learner_id, req->focus_key, &actions_root, &imaginate_state);
    if (!row || !actions_root) {
        return false;
    }

    uint64_t last_seed = imaginate_state ? cep_l2_playbook_read_u64(imaginate_state, dt_last_seed_field()) : 0u;
    bool can_imaginate = req->allow_imaginate && req->exploration_bias > 0.0 && req->action_count > 1u;
    uint64_t seed = can_imaginate ? cep_l2_playbook_hash_seed(req, last_seed) : 0u;
    size_t sample_rank = can_imaginate ? (size_t)(seed % req->action_count) : 0u;
    size_t chosen_index = can_imaginate ? sample_rank : 0u;
    if (req->guardian_allow) {
        size_t attempts = 0u;
        while (attempts < req->action_count) {
            const char* cand = req->actions[chosen_index];
            if (cand && req->guardian_allow(cand, req->guardian_user)) {
                break;
            }
            chosen_index = (chosen_index + 1u) % req->action_count;
            ++attempts;
        }
        if (attempts >= req->action_count) {
            return false;
        }
    }

    const char* action_id = req->actions[chosen_index];
    if (!action_id) {
        return false;
    }

    /* Ensure the chosen action entry exists for provenance/stats snapshots. */
    cepDT action_dt = {.domain = CEP_ACRO("CEP"), .tag = cep_namepool_intern_cstr(action_id), .glob = 0u};
    cepCell* action_cell = cep_l2_playbook_require_dict(actions_root, &action_dt);
    if (!action_cell) {
        return false;
    }

    cep_l2_playbook_store_imaginate_state(imaginate_state, req->exploration_bias, seed, sample_rank);

    uint64_t attempts_prev = cep_l2_playbook_read_u64(action_cell, dt_attempts_field());
    uint64_t playbook_rev = cep_l2_playbook_sum_uint64(attempts_prev, 1u);

    cepCell* decision_cell = cep_l2_playbook_record_decision(req->eco_root,
                                                             row,
                                                             req,
                                                             action_id,
                                                             chosen_index,
                                                             req->action_count,
                                                             can_imaginate,
                                                             seed,
                                                             sample_rank,
                                                             playbook_rev);
    if (!decision_cell) {
        return false;
    }

    out->chosen_index = chosen_index;
    out->imaginate_used = can_imaginate;
    out->seed = seed;
    out->sample_rank = sample_rank;
    out->action_id = action_id;
    out->playbook_row = row;
    out->decision_cell = decision_cell;
    return true;
}

/* Updates a playbook row after a decision outcome, incrementing attempts,
   successes, imaginate counters, avg_cost (running mean), and last_bt. Keeps
   stats append-only within the playbook row and can attach the Decision Cell
   for lineage. */
bool cep_l2_playbook_update_stats(cepCell* eco_root,
                                  const char* learner_id,
                                  const char* focus_key,
                                  const char* action_id,
                                  bool success,
                                  double cost,
                                  bool imaginate_used,
                                  cepCell* decision_cell) {
    if (!eco_root || !learner_id || !focus_key || !action_id) {
        return false;
    }

    cepCell* actions_root = NULL;
    cepCell* imaginate_state = NULL;
    cepCell* row = cep_l2_playbook_row(eco_root, learner_id, focus_key, &actions_root, &imaginate_state);
    if (!row || !actions_root) {
        return false;
    }

    cepDT action_dt = {.domain = CEP_ACRO("CEP"), .tag = cep_namepool_intern_cstr(action_id), .glob = 0u};
    cepCell* action_cell = cep_l2_playbook_require_dict(actions_root, &action_dt);
    if (!action_cell) {
        return false;
    }

    uint64_t attempts = cep_l2_playbook_sum_uint64(cep_l2_playbook_read_u64(action_cell, dt_attempts_field()), 1u);
    uint64_t successes = cep_l2_playbook_sum_uint64(cep_l2_playbook_read_u64(action_cell, dt_success_field()), success ? 1u : 0u);
    uint64_t imaginate_hits = cep_l2_playbook_sum_uint64(cep_l2_playbook_read_u64(action_cell, dt_imaginate_flag_field()), imaginate_used ? 1u : 0u);
    double prev_cost = cep_l2_playbook_read_double(action_cell, dt_avg_cost_field());
    double avg_cost = prev_cost;
    if (attempts > 0u) {
        double total_cost = prev_cost * (double)(attempts > 0u ? (attempts - 1u) : 0u);
        total_cost += cost;
        avg_cost = total_cost / (double)attempts;
    }

    char cost_buf[32];
    snprintf(cost_buf, sizeof cost_buf, "%.6f", avg_cost);

    bool ok = true;
    ok &= cep_cell_put_uint64(action_cell, dt_attempts_field(), attempts);
    ok &= cep_cell_put_uint64(action_cell, dt_success_field(), successes);
    ok &= cep_cell_put_uint64(action_cell, dt_imaginate_flag_field(), imaginate_hits);
    ok &= cep_cell_put_text(action_cell, dt_avg_cost_field(), cost_buf);
    ok &= cep_cell_put_uint64(action_cell, dt_last_bt_field(), (uint64_t)cep_beat_index());

    if (decision_cell) {
        cepCell* parents[] = {decision_cell};
        (void)cep_cell_add_parents(action_cell, parents, 1u);
    }
    return ok;
}
