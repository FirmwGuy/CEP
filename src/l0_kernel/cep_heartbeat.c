/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_heartbeat.h"
#include "cep_cei.h"
#include "cep_heartbeat_internal.h"
#include "cep_executor.h"
#include "cep_ep.h"
#include "cep_namepool.h"
#include "../enzymes/cep_cell_operations.h"
#include "../enzymes/cep_l0_organs.h"
#include "cep_mailbox.h"
#include "cep_ops.h"
#include "cep_organ.h"
#include "stream/cep_stream_internal.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>



static const cepDT* dt_state_root(void);
static const cepDT* dt_mailbox_root_name(void);
static const cepDT* dt_impulse_mailbox_name(void);
static const cepDT* dt_meta_name(void);
static const cepDT* dt_kind_name(void);
static const cepDT* dt_runtime_name(void);
static const cepDT* dt_msgs_name(void);
static const cepDT* dt_envelope_name(void);
static const cepDT* dt_signal_field(void);
static const cepDT* dt_target_field_control(void);
static const cepDT* dt_qos_field(void);
static const cepDT* dt_issued_field(void);
static const cepDT* dt_dictionary_type(void);
static const cepDT* dt_domain_field(void);
static const cepDT* dt_tag_field(void);
static const cepDT* dt_timestamp_field(void);
static const cepDT* dt_op_stamp_name(void);
static const cepDT* dt_signal_op_pause(void);
static const cepDT* dt_signal_op_resume(void);
static const cepDT* dt_signal_op_rollback(void);
static const cepDT* dt_signal_op_shutdown(void);
static const cepDT* dt_signal_op_cont(void);
static const cepDT* dt_signal_op_tmo(void);
static const cepDT* dt_allow_signal_cei(void);
static const cepDT* dt_paused_field(void);
static const cepDT* dt_view_horizon_field(void);
static const cepDT* dt_ops_rt_name(void);
#if defined(CEP_ENABLE_DEBUG)
static const cepDT* dt_debug_root_name(void);
static const cepDT* dt_debug_stage_field(void);
static const cepDT* dt_debug_note_field(void);
static const cepDT* dt_debug_phase_field(void);
static const cepDT* dt_debug_ready_field(void);
static const cepDT* dt_debug_beat_field(void);
#endif
static const cepDT* dt_ist_plan(void);
static const cepDT* dt_ist_quiesce(void);
static const cepDT* dt_ist_paused(void);
static const cepDT* dt_ist_cutover(void);
static const cepDT* dt_ist_run(void);
static cepCell* cep_lifecycle_get_dictionary(cepCell* parent, const cepDT* name, bool create);
static cepCell* cep_control_mailbox(void);
static cepCell* cep_control_mailbox_msgs(void);
static bool cep_control_path_write(cepCell* parent, const cepDT* field, const cepPath* path);
static cepPath* cep_control_path_read(const cepCell* parent, const cepDT* field);
static char* cep_heartbeat_path_to_string(const cepPath* path);
static bool cep_heartbeat_record_op_stamp(cepBeatNumber beat, cepOpCount stamp);
static bool cep_heartbeat_beat_to_op_stamp(cepBeatNumber beat, cepOpCount* stamp_out);
static bool cep_control_op_is_closed(cepOID oid);
static bool cep_control_op_closed_ok(cepOID oid);

static cepHeartbeatRuntime CEP_RUNTIME = {
    .current = CEP_BEAT_INVALID,
    .phase   = CEP_BEAT_CAPTURE,
    .deferred_activations = 0u,
    .sys_shutdown_emitted = false,
    .current_descriptor = NULL,
    .last_wallclock_beat = CEP_BEAT_INVALID,
    .last_wallclock_ns = 0u,
    .view_horizon = CEP_BEAT_INVALID,
    .view_horizon_stamp = 0u,
    .view_horizon_floor_stamp = 0u,
};

static cepHeartbeatTopology CEP_DEFAULT_TOPOLOGY;

typedef enum {
    CEP_CTRL_PHASE_IDLE = 0,
    CEP_CTRL_PHASE_PLAN,
    CEP_CTRL_PHASE_APPLY,
    CEP_CTRL_PHASE_STEADY,
    CEP_CTRL_PHASE_CLOSING,
} cepControlPhase;

typedef enum {
    CEP_ROLLBACK_STAGE_IDLE = 0,
    CEP_ROLLBACK_STAGE_EXAMINE,
    CEP_ROLLBACK_STAGE_PRUNE,
    CEP_ROLLBACK_STAGE_CUTOVER,
    CEP_ROLLBACK_STAGE_STEADY,
    CEP_ROLLBACK_STAGE_FAILED,
} cepRollbackStage;

typedef struct {
    cepOID          oid;
    bool            started;
    bool            closed;
    bool            failed;
    cepControlPhase phase;
    cepBeatNumber   last_beat;
    cepDT           verb_dt;
    bool            diag_emitted;
} cepControlOpState;

typedef struct {
    cepControlOpState pause;
    cepControlOpState resume;
    cepControlOpState rollback;
    bool              gating_active;
    bool              paused_published;
    bool              locks_acquired;
    bool              drain_requested;
    bool              backlog_dirty;
    bool              agenda_noted;
    bool              cleanup_pending;
    bool              backlog_cleanup_pending;
    bool              data_cleanup_pending;
    bool              gc_pending;
    cepLockToken      store_lock;
    cepLockToken      data_lock;
    cepBeatNumber     rollback_target;
    cepRollbackStage  rollback_stage;
} cepControlRuntimeState;

static cepControlRuntimeState CEP_CONTROL_STATE;

/* Refresh the aggregated cleanup flag so callers can gate control verbs on the
   presence of any outstanding backlog, data revival, or GC work. */
static inline void cep_control_cleanup_update_flag(void) {
    CEP_CONTROL_STATE.cleanup_pending =
        CEP_CONTROL_STATE.backlog_cleanup_pending ||
        CEP_CONTROL_STATE.data_cleanup_pending ||
        CEP_CONTROL_STATE.gc_pending;
}

static void cep_control_reset_state(void) {
    CEP_0(&CEP_CONTROL_STATE);
    CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_IDLE;
    cep_control_cleanup_update_flag();
    CEP_DEBUG_PRINTF("[ctrl] reset control state\n");
}

static void cep_control_op_clear(cepControlOpState* op) {
    if (!op) {
        return;
    }
    CEP_0(op);
    if (op == &CEP_CONTROL_STATE.rollback) {
        CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_IDLE;
    }
    CEP_DEBUG_PRINTF("[ctrl] op_clear op=%p\n", (void*)op);
}

static bool cep_control_ready_for_next(const cepControlOpState* op);
#if defined(CEP_ENABLE_DEBUG)
static void cep_control_debug_log(const cepControlOpState* op,
                                  const char* stage,
                                  const char* note);
static void cep_control_debug_clear(const cepControlOpState* op);
#else
static inline void cep_control_debug_log(const cepControlOpState* op,
                                         const char* stage,
                                         const char* note) {
    (void)op;
    (void)stage;
    (void)note;
}
static inline void cep_control_debug_clear(const cepControlOpState* op) {
    (void)op;
}
#endif

#if defined(CEP_ENABLE_DEBUG)
static void cep_control_debug_snapshot(const char* stage,
                                       const cepControlOpState* op,
                                       int success_hint) {
    if (!stage) {
        stage = "<null>";
    }
    if (!op) {
        CEP_DEBUG_PRINTF("[ctrl] stage=%s op=null success_hint=%d\n", stage, success_hint);
        return;
    }

    const char* phase = "idle";
    switch (op->phase) {
        case CEP_CTRL_PHASE_IDLE:     phase = "idle";     break;
        case CEP_CTRL_PHASE_PLAN:     phase = "plan";     break;
        case CEP_CTRL_PHASE_APPLY:    phase = "apply";    break;
        case CEP_CTRL_PHASE_STEADY:   phase = "steady";   break;
        case CEP_CTRL_PHASE_CLOSING:  phase = "closing";  break;
    }

    uint64_t beat = (op->last_beat == CEP_BEAT_INVALID)
        ? UINT64_MAX
        : (uint64_t)op->last_beat;

    CEP_DEBUG_PRINTF("[ctrl] stage=%s op=%p success_hint=%d started=%d closed=%d "
                     "failed=%d phase=%s last_beat=%" PRIu64 " diag=%d\n",
                     stage,
                     (void*)op,
                     success_hint,
                     op->started ? 1 : 0,
                     op->closed ? 1 : 0,
                     op->failed ? 1 : 0,
                     phase,
                     beat,
                     op->diag_emitted ? 1 : 0);
}
#else
static inline void cep_control_debug_snapshot(const char* stage,
                                              const cepControlOpState* op,
                                              int success_hint) {
    (void)stage;
    (void)op;
    (void)success_hint;
}
#endif

static cepCell* cep_control_state_root(void) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    if (!sys_root) {
        return NULL;
    }
    return cep_lifecycle_get_dictionary(sys_root, dt_state_root(), true);
}

static bool cep_control_state_write_bool(const cepDT* field, bool value) {
    cepCell* state_root = cep_control_state_root();
    if (!state_root || !field) {
return false;
    }

    cepDT lookup = cep_dt_clean(field);
    cepCell* existing = cep_cell_find_by_name(state_root, &lookup);
    const char* type_tag = "val/bool";

    if (existing) {
return cep_cell_update(existing, sizeof value, sizeof value, (void*)&value, false) != NULL;
    }

    cepDT name_copy = lookup;
    cepDT type_copy = cep_ops_make_dt(type_tag);
return cep_dict_add_value(state_root, &name_copy, &type_copy, (void*)&value, sizeof value, sizeof value) != NULL;
}

static bool cep_control_state_write_u64(const cepDT* field, uint64_t value) {
    cepCell* state_root = cep_control_state_root();
    if (!state_root || !field) {
return false;
    }

    cepDT lookup = cep_dt_clean(field);
    cepCell* existing = cep_cell_find_by_name(state_root, &lookup);
    const char* type_tag = "val/u64";

    if (existing) {
return cep_cell_update(existing, sizeof value, sizeof value, (void*)&value, false) != NULL;
    }

    cepDT name_copy = lookup;
    cepDT type_copy = cep_ops_make_dt(type_tag);
return cep_dict_add_value(state_root, &name_copy, &type_copy, (void*)&value, sizeof value, sizeof value) != NULL;
}

static bool cep_control_set_numeric_name(cepDT* name, size_t index) {
    if (!name) {
        return false;
    }
    if (index >= CEP_AUTOID_MAX) {
        return false;
    }
    name->domain = CEP_ACRO("CEP");
    name->glob = 0u;
    name->tag = cep_id_to_numeric((cepID)(index + 1u));
    return true;
}

static cepCell* cep_control_mailbox(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return NULL;
    }

    cepCell* mailboxes = cep_cell_ensure_dictionary_child(data_root,
                                                          dt_mailbox_root_name(),
                                                          CEP_STORAGE_RED_BLACK_T);
    if (!mailboxes) {
        return NULL;
    }

    cepCell* impulses = cep_cell_ensure_dictionary_child(mailboxes,
                                                         dt_impulse_mailbox_name(),
                                                         CEP_STORAGE_RED_BLACK_T);
    if (!impulses) {
        return NULL;
    }

    cepCell* meta = cep_cell_ensure_dictionary_child(impulses, dt_meta_name(), CEP_STORAGE_RED_BLACK_T);
    if (!meta) {
        return NULL;
    }

    cepCell* kind = cep_cell_find_by_name(meta, dt_kind_name());
    if (!kind || !cep_cell_has_data(kind)) {
        if (!cep_cell_put_text(meta, dt_kind_name(), "impulse_backlog")) {
            return NULL;
        }
    }

    cepCell* runtime = cep_cell_ensure_dictionary_child(meta, dt_runtime_name(), CEP_STORAGE_RED_BLACK_T);
    if (!runtime) {
        return NULL;
    }
    (void)runtime; /* runtime metadata reserved for TTL bookkeeping. */

    cepCell* msgs = cep_cell_ensure_dictionary_child(impulses, dt_msgs_name(), CEP_STORAGE_RED_BLACK_T);
    if (!msgs) {
        return NULL;
    }

    return cep_cell_resolve(impulses);
}

static cepCell* cep_control_mailbox_msgs(void) {
    cepCell* mailbox = cep_control_mailbox();
    if (!mailbox) {
        CEP_DEBUG_PRINTF("[prr] mailbox_msgs: mailbox missing\n");
        return NULL;
    }
    if (!cep_cell_require_dictionary_store(&mailbox)) {
        CEP_DEBUG_PRINTF("[prr] mailbox_msgs: mailbox store unavailable mailbox=%p\n", (void*)mailbox);
        return NULL;
    }

    cepCell* msgs = cep_cell_find_by_name(mailbox, dt_msgs_name());
    bool fallback = false;
    if (!msgs) {
        msgs = cep_cell_find_by_name_all(mailbox, dt_msgs_name());
        fallback = true;
        if (!msgs) {
            const cepDT* name = cep_cell_get_name(mailbox);
            CEP_DEBUG_PRINTF("[prr] mailbox_msgs: msgs lookup failed mailbox=%p name=%s deleted=%lu veiled=%u\n",
                             (void*)mailbox,
                             name ? "mailbox" : "<unnamed>",
                             (unsigned long)(mailbox && mailbox->deleted ? mailbox->deleted : 0u),
                             mailbox ? mailbox->metacell.veiled : 0u);
            return NULL;
        }
    }
    cepCell* resolved = cep_cell_resolve(msgs);
    CEP_DEBUG_PRINTF("[prr] mailbox_msgs: resolved=%p store=%p deleted=%lu veiled=%u fallback=%d\n",
                     (void*)resolved,
                     resolved ? (void*)resolved->store : NULL,
                     resolved ? (unsigned long)resolved->deleted : 0ul,
                     resolved ? resolved->metacell.veiled : 0u,
                     fallback ? 1 : 0);
    return resolved;
}

static bool cep_control_path_write(cepCell* parent, const cepDT* field, const cepPath* path) {
    if (!parent || !field) {
        return false;
    }

    cepCell* resolved = cep_cell_resolve(parent);
    if (!resolved || !cep_cell_is_normal(resolved)) {
        return false;
    }

    if (!cep_cell_require_dictionary_store(&resolved)) {
        return false;
    }

    cepCell* branch = cep_cell_ensure_dictionary_child(resolved, field, CEP_STORAGE_RED_BLACK_T);
    if (!branch) {
        return false;
    }

    branch = cep_cell_resolve(branch);
    if (!branch) {
        return false;
    }

    cep_cell_delete_children(branch);

    if (!path || path->length == 0u) {
        return true;
    }

    for (unsigned i = 0u; i < path->length; ++i) {
        cepDT entry_name = {0};
        if (!cep_control_set_numeric_name(&entry_name, i)) {
            return false;
        }
        cepDT type = *dt_dictionary_type();
        cepCell* segment = cep_dict_add_dictionary(branch, &entry_name, &type, CEP_STORAGE_RED_BLACK_T);
        if (!segment) {
            return false;
        }
        const cepPast* part = &path->past[i];
        uint64_t domain_value = (uint64_t)part->dt.domain;
        uint64_t tag_value = (uint64_t)part->dt.tag;

        if (!cep_cell_put_uint64(segment, dt_domain_field(), domain_value)) {
            return false;
        }
        if (!cep_cell_put_uint64(segment, dt_tag_field(), tag_value)) {
            return false;
        }
        if (!cep_cell_put_uint64(segment, dt_timestamp_field(), (uint64_t)part->timestamp)) {
            return false;
        }
    }

    CEP_DEBUG_PRINTF("[prr] soft_delete: completed\n");
    return true;
}

static cepPath* cep_control_path_read(const cepCell* parent, const cepDT* field) {
    if (!parent || !field) {
        return NULL;
    }

    cepCell* branch = cep_cell_find_by_name(parent, field);
    if (!branch) {
        branch = cep_cell_find_by_name_all(parent, field);
        if (!branch) {
            CEP_DEBUG_PRINTF("[prr] path_read: missing branch for field\n");
            return NULL;
        }
        CEP_DEBUG_PRINTF("[prr] path_read: fallback branch for field\n");
    }
    branch = cep_cell_resolve(branch);
    if (!branch) {
        CEP_DEBUG_PRINTF("[prr] path_read: resolve branch failed\n");
        return NULL;
    }

    size_t count = 0u;
    for (cepCell* child = cep_cell_first_all(branch); child; child = cep_cell_next_all(branch, child)) {
        count += 1u;
    }
    CEP_DEBUG_PRINTF("[prr] path_read: child count=%zu\n", count);
    size_t bytes = sizeof(cepPath) + count * sizeof(cepPast);
    cepPath* path = (cepPath*)cep_malloc(bytes);
    if (!path) {
        return NULL;
    }
    path->length = 0u;
    path->capacity = count;

    const cepDT* domain_dt = dt_domain_field();
    const cepDT* tag_dt = dt_tag_field();
    const cepDT* ts_dt = dt_timestamp_field();

    size_t index = 0u;
    for (cepCell* child = cep_cell_first_all(branch); child; child = cep_cell_next_all(branch, child)) {
        cepPath* target = path;
        if (index >= count) {
            break;
        }
        cepCell* resolved_child = cep_cell_resolve(child);
        if (!resolved_child) {
            resolved_child = child;
        }
        cepPast* segment = &target->past[index];
        uint64_t domain_id = 0u;
        uint64_t tag_id = 0u;
        uint64_t timestamp = 0u;

        cepDT domain_lookup = cep_dt_clean(domain_dt);
        cepDT tag_lookup = cep_dt_clean(tag_dt);
        cepDT ts_lookup = cep_dt_clean(ts_dt);

        cepCell* domain_cell = cep_cell_find_by_name_all(resolved_child, &domain_lookup);
        cepCell* tag_cell = cep_cell_find_by_name_all(resolved_child, &tag_lookup);
        cepCell* ts_cell = cep_cell_find_by_name_all(resolved_child, &ts_lookup);

        if (domain_cell) {
            domain_cell = cep_cell_resolve(domain_cell);
        }
        if (tag_cell) {
            tag_cell = cep_cell_resolve(tag_cell);
        }
        if (ts_cell) {
            ts_cell = cep_cell_resolve(ts_cell);
        }

        const char* domain_text = (domain_cell && domain_cell->data)
            ? (const char*)cep_data(domain_cell->data)
            : NULL;
        const char* tag_text = (tag_cell && tag_cell->data)
            ? (const char*)cep_data(tag_cell->data)
            : NULL;
        const char* ts_text = (ts_cell && ts_cell->data)
            ? (const char*)cep_data(ts_cell->data)
            : NULL;

        if (!domain_text || !tag_text) {
            CEP_DEBUG_PRINTF("[prr] path_read: missing domain/tag data for child\n");
            cep_free(path);
            return NULL;
        }

        domain_id = strtoull(domain_text, NULL, 10);
        tag_id = strtoull(tag_text, NULL, 10);
        if (ts_text) {
            timestamp = strtoull(ts_text, NULL, 10);
        }

        segment->dt.domain = CEP_ID(domain_id);
        segment->dt.tag = CEP_ID(tag_id);
        CEP_DEBUG_PRINTF("[prr] path_read segment idx=%zu domain=%llu tag=%llu\n",
                         (unsigned long)index,
                         (unsigned long long)domain_id,
                         (unsigned long long)tag_id);
        segment->dt.glob = cep_id_has_glob_char(segment->dt.tag) ? 1u : 0u;
        segment->timestamp = (cepOpCount)timestamp;

        ++index;
    }

    path->length = index;
    path->capacity = index;
    return path;
}

static bool cep_control_backlog_store(const cepImpulse* impulse) {
    if (!impulse) {
        CEP_DEBUG_PRINTF("[backlog] invalid impulse\n");
        return false;
    }

    cepCell* data_root = NULL;
    bool relock_store = false;
    bool relock_data = false;

    if (CEP_CONTROL_STATE.locks_acquired) {
        data_root = cep_heartbeat_data_root();
        if (data_root) {
            data_root = cep_cell_resolve(data_root);
        }
        if (data_root) {
            if (CEP_CONTROL_STATE.data_lock.owner) {
                cep_data_unlock(data_root, &CEP_CONTROL_STATE.data_lock);
                relock_data = true;
            }
            if (CEP_CONTROL_STATE.store_lock.owner) {
                cep_store_unlock(data_root, &CEP_CONTROL_STATE.store_lock);
                relock_store = true;
            }
        }
    }

    bool success = false;

    cepCell* mailbox = cep_control_mailbox();
    if (!mailbox) {
        CEP_DEBUG_PRINTF("[backlog] control mailbox unavailable\n");
        goto cleanup;
    }

    cepMailboxMessageId message_id = {0};
    if (!cep_mailbox_select_message_id(mailbox, NULL, NULL, &message_id)) {
        CEP_DEBUG_PRINTF("[backlog] select_message_id failed\n");
        goto cleanup;
    }

    cepCell* msgs = cep_control_mailbox_msgs();
    if (!msgs) {
        CEP_DEBUG_PRINTF("[backlog] mailbox msgs branch missing\n");
        goto cleanup;
    }

    cepDT message_lookup = cep_dt_clean(&message_id.id);
    cepCell* message_root = cep_cell_find_by_name(msgs, &message_lookup);
    cepDT dict_type = *dt_dictionary_type();

    if (message_root) {
        message_root = cep_cell_resolve(message_root);
        if (!message_root) {
            CEP_DEBUG_PRINTF("[backlog] resolve existing message failed\n");
            goto cleanup;
        }
        cep_cell_delete_children(message_root);
    } else {
        cepDT name_copy = message_lookup;
        message_root = cep_dict_add_dictionary(msgs, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!message_root) {
            CEP_DEBUG_PRINTF("[backlog] add message dictionary failed\n");
            goto cleanup;
        }
    }

    cepCell* envelope = cep_cell_ensure_dictionary_child(message_root, dt_envelope_name(), CEP_STORAGE_RED_BLACK_T);
    if (!envelope) {
        CEP_DEBUG_PRINTF("[backlog] ensure envelope failed\n");
        goto cleanup;
    }

    envelope = cep_cell_resolve(envelope);
    if (!envelope) {
        CEP_DEBUG_PRINTF("[backlog] resolve envelope failed\n");
        goto cleanup;
    }

    cep_cell_delete_children(envelope);

    if (!cep_control_path_write(envelope, dt_signal_field(), impulse->signal_path)) {
        CEP_DEBUG_PRINTF("[backlog] write signal path failed\n");
        goto cleanup;
    }

    if (!cep_control_path_write(envelope, dt_target_field_control(), impulse->target_path)) {
        CEP_DEBUG_PRINTF("[backlog] write target path failed\n");
        goto cleanup;
    }

    uint64_t qos_value = (uint64_t)impulse->qos;
    if (!cep_cell_put_uint64(envelope, dt_qos_field(), qos_value)) {
        CEP_DEBUG_PRINTF("[backlog] write qos failed\n");
        goto cleanup;
    }

    cepBeatNumber beat = cep_heartbeat_current();
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }
    if (!cep_cell_put_uint64(envelope, dt_issued_field(), (uint64_t)beat)) {
        CEP_DEBUG_PRINTF("[backlog] write issued beat failed\n");
        goto cleanup;
    }

    CEP_CONTROL_STATE.backlog_dirty = true;
    success = true;

cleanup:
    {
        bool relock_ok = true;
        if (data_root) {
            if (relock_store) {
                if (!cep_store_lock(data_root, &CEP_CONTROL_STATE.store_lock)) {
                    CEP_DEBUG_PRINTF("[backlog] failed to re-lock store\n");
                    relock_ok = false;
                }
            }
            if (relock_data) {
                if (!cep_data_lock(data_root, &CEP_CONTROL_STATE.data_lock)) {
                    CEP_DEBUG_PRINTF("[backlog] failed to re-lock data\n");
                    relock_ok = false;
                }
            }
        }
        if (!relock_ok) {
            success = false;
        }
    }

    return success;
}

static void cep_control_backlog_gc_deleted(cepCell* msgs) {
    if (!msgs) {
        return;
    }

    bool removed = false;
    for (cepCell* message = cep_cell_first_all(msgs); message; ) {
        cepCell* next = cep_cell_next_all(msgs, message);
        cepCell* resolved = cep_cell_resolve(message);
        if (resolved && cep_cell_is_deleted(resolved)) {
            cep_cell_remove_hard(resolved, NULL);
            removed = true;
        }
        message = next;
    }

    if (removed) {
        CEP_CONTROL_STATE.backlog_dirty = true;
    }
    CEP_CONTROL_STATE.backlog_cleanup_pending = false;
    cep_control_cleanup_update_flag();
}

static bool cep_control_backlog_drain(void) {
    cepCell* msgs = cep_control_mailbox_msgs();
    if (!msgs) {
        CEP_DEBUG_PRINTF("[prr] backlog_drain: msgs missing\n");
        return true;
    }

    size_t pending = cep_cell_children(msgs);
    CEP_DEBUG_PRINTF("[prr] backlog_drain entry: messages=%zu gating=%d paused=%d cleanup=%d dirty=%d\n",
                     pending,
                     CEP_CONTROL_STATE.gating_active ? 1 : 0,
                     CEP_RUNTIME.paused ? 1 : 0,
                     CEP_CONTROL_STATE.cleanup_pending ? 1 : 0,
                     CEP_CONTROL_STATE.backlog_dirty ? 1 : 0);

    if (CEP_CONTROL_STATE.backlog_cleanup_pending) {
        cep_control_backlog_gc_deleted(msgs);
    }

    cepCell* next = NULL;
    for (cepCell* message = cep_cell_first_all(msgs); message; message = next) {
        next = cep_cell_next_all(msgs, message);
        CEP_DEBUG_PRINTF("[prr] backlog_drain visit message=%p\n", (void*)message);
        cepCell* resolved = cep_cell_resolve(message);
        if (!resolved) {
            CEP_DEBUG_PRINTF("[prr] backlog_drain resolve message failed gating=%d paused=%d cleanup=%d\n",
                             CEP_CONTROL_STATE.gating_active ? 1 : 0,
                             CEP_RUNTIME.paused ? 1 : 0,
                             CEP_CONTROL_STATE.cleanup_pending ? 1 : 0);
            return false;
        }
        const cepDT* message_name = cep_cell_get_name(resolved);
        CEP_DEBUG_PRINTF("[prr] backlog_drain resolved message=%p name=%s deleted=%lu veiled=%u\n",
                         (void*)resolved,
                         message_name ? "msg" : "<unnamed>",
                         (unsigned long)resolved->deleted,
                         resolved->metacell.veiled);

        cepCell* envelope = cep_cell_find_by_name(resolved, dt_envelope_name());
        if (!envelope) {
            envelope = cep_cell_find_by_name_all(resolved, dt_envelope_name());
            if (!envelope) {
                CEP_DEBUG_PRINTF("[prr] backlog_drain missing envelope for message=%p\n", (void*)resolved);
                cep_cell_remove_hard(resolved, NULL);
                continue;
            }
        }

        envelope = cep_cell_resolve(envelope);
        if (!envelope) {
            CEP_DEBUG_PRINTF("[prr] backlog_drain resolve envelope failed gating=%d paused=%d cleanup=%d\n",
                             CEP_CONTROL_STATE.gating_active ? 1 : 0,
                             CEP_RUNTIME.paused ? 1 : 0,
                             CEP_CONTROL_STATE.cleanup_pending ? 1 : 0);
            return false;
        }

        cepPath* signal_path = cep_control_path_read(envelope, dt_signal_field());
        cepPath* target_path = cep_control_path_read(envelope, dt_target_field_control());

        cepDT qos_lookup = cep_dt_clean(dt_qos_field());
        void* qos_data = cep_cell_data_find_by_name(envelope, &qos_lookup);
        uint64_t qos_value = 0u;
        if (qos_data) {
            qos_value = strtoull((const char*)qos_data, NULL, 10);
        }

        char* dbg_signal_path = cep_heartbeat_path_to_string(signal_path);
        char* dbg_target_path = cep_heartbeat_path_to_string(target_path);
        CEP_DEBUG_PRINTF("[prr] backlog replay gating=%d paused=%d cleanup=%d signal=%s target=%s qos=%llu\n",
                         CEP_CONTROL_STATE.gating_active ? 1 : 0,
                         CEP_RUNTIME.paused ? 1 : 0,
                         CEP_CONTROL_STATE.cleanup_pending ? 1 : 0,
                         dbg_signal_path ? dbg_signal_path : "<null>",
                         dbg_target_path ? dbg_target_path : "<null>",
                         (unsigned long long)(qos_value & 0xFFu));

        cepImpulse impulse = {
            .signal_path = signal_path,
            .target_path = target_path,
            .qos = (cepImpulseQoS)(qos_value & 0xFFu),
        };

        if (cep_heartbeat_enqueue_impulse(CEP_BEAT_INVALID, &impulse) != CEP_ENZYME_SUCCESS) {
            CEP_DEBUG_PRINTF("[prr] backlog_drain enqueue failed gating=%d paused=%d cleanup=%d signal=%p target=%p qos=%u\n",
                             CEP_CONTROL_STATE.gating_active ? 1 : 0,
                             CEP_RUNTIME.paused ? 1 : 0,
                             CEP_CONTROL_STATE.cleanup_pending ? 1 : 0,
                             (void*)signal_path,
                             (void*)target_path,
                             (unsigned)impulse.qos);
            cep_free(signal_path);
            cep_free(target_path);
            return false;
        }

        if (signal_path) {
            for (unsigned i = 0; i < signal_path->length; ++i) {
                signal_path->past[i].dt.glob = 0u;
            }
        }

        cep_free(dbg_signal_path);
        cep_free(dbg_target_path);
        cep_free(signal_path);
        cep_free(target_path);
        cep_cell_remove_hard(resolved, NULL);
    }

    CEP_CONTROL_STATE.backlog_dirty = false;
    return true;
}

static bool cep_control_backlog_prune_discard(void) {
    cepCell* msgs = cep_control_mailbox_msgs();
    if (!msgs) {
        return true;
    }

    cepCell* next = NULL;
    bool pruned_any = false;

    for (cepCell* message = cep_cell_first(msgs); message; message = next) {
        next = cep_cell_next(msgs, message);
        cepCell* resolved = cep_cell_resolve(message);
        if (!resolved) {
            return false;
        }

        cepCell* envelope = cep_cell_find_by_name(resolved, dt_envelope_name());
        if (!envelope) {
            cep_cell_delete(resolved);
            pruned_any = true;
            continue;
        }

        envelope = cep_cell_resolve(envelope);
        if (!envelope) {
            return false;
        }

        cepDT qos_lookup = cep_dt_clean(dt_qos_field());
        void* qos_data = cep_cell_data_find_by_name(envelope, &qos_lookup);
        uint64_t qos_value = 0u;
        if (qos_data) {
            qos_value = strtoull((const char*)qos_data, NULL, 10);
        }

        if (((cepImpulseQoS)qos_value) & CEP_IMPULSE_QOS_DISCARD_ON_ROLLBACK) {
            cep_cell_delete(resolved);
            pruned_any = true;
        }
    }

    if (pruned_any) {
        CEP_CONTROL_STATE.backlog_dirty = true;
        CEP_CONTROL_STATE.backlog_cleanup_pending = true;
        cep_control_cleanup_update_flag();
    }

    return true;
}

static bool cep_control_signal_matches(const cepPath* path, const cepDT* dt) {
    if (!path || path->length == 0u || !dt) {
        return false;
    }
    cepDT wanted = cep_dt_clean(dt);
    cepDT actual = cep_dt_clean(&path->past[0].dt);
    return cep_dt_compare(&wanted, &actual) == 0;
}

/* Restore a soft-deleted cell so post-rollback traversals can treat it as live
   again. Clears tombstone metadata stamped after the horizon, reinstates store
   ownership, and flips writability flags so new mutations succeed. */
static bool cep_control_rehydrate_node(cepCell* cell, cepOpCount floor_stamp) {
    if (!cell) {
        return true;
    }

#if defined(CEP_ENABLE_DEBUG)
    const cepDT* dbg_name = cep_cell_get_name(cell);
    uint64_t dbg_domain = dbg_name ? (uint64_t)cep_id(dbg_name->domain) : 0u;
    uint64_t dbg_tag = dbg_name ? (uint64_t)cep_id(dbg_name->tag) : 0u;
#endif

    if (cep_cell_is_veiled(cell)) {
        cell->metacell.veiled = 0u;
    }

    if (cell->deleted && (!floor_stamp || cell->deleted > floor_stamp)) {
        cell->deleted = 0u;
    }

    if (!cell->created && floor_stamp) {
        cell->created = floor_stamp;
    }

    if (cep_cell_has_data(cell)) {
        cepData* data = cell->data;
        if (data->deleted && (!floor_stamp || data->deleted > floor_stamp)) {
            CEP_DEBUG_PRINTF("[rehydrate-data] cell=%p nm=%016" PRIx64 "/%016" PRIx64
                             " data_deleted=%" PRIu64 " floor=%" PRIu64 "\n",
                             (void*)cell,
                             dbg_domain,
                             dbg_tag,
                             (uint64_t)data->deleted,
                             (uint64_t)floor_stamp);
            data->deleted = 0u;
        }
        if (!data->created && floor_stamp) {
            data->created = floor_stamp;
        }
        if (!data->writable) {
            data->writable = 1u;
        }
        data->lockOwner = NULL;
        if (data->lock) {
            data->lock = 0u;
        }
    }

    if (cep_cell_has_store(cell)) {
        cepStore* store = cell->store;
        if (store->owner != cell) {
            store->owner = cell;
        }
        if (!store->writable) {
            store->writable = 1u;
        }
        if (store->lock) {
            store->lock = 0u;
            store->lockOwner = NULL;
        } else {
            store->lockOwner = NULL;
        }
        if (store->deleted && (!floor_stamp || store->deleted > floor_stamp)) {
            CEP_DEBUG_PRINTF("[rehydrate-store] cell=%p nm=%016" PRIx64 "/%016" PRIx64
                             " store_deleted=%" PRIu64 " floor=%" PRIu64 "\n",
                             (void*)cell,
                             dbg_domain,
                             dbg_tag,
                             (uint64_t)store->deleted,
                             (uint64_t)floor_stamp);
            store->deleted = 0u;
        }
        if (!store->created) {
            cepOpCount stamp = cell->created ? cell->created : floor_stamp;
            if (!stamp) {
                stamp = cep_cell_timestamp();
            }
            store->created = stamp;
        }
        if (store->autoid == 0u) {
            store->autoid = 1u;
        }
    }

    return true;
}

/* Depth-first walk that revives every descendant under the supplied cell,
   ensuring hidden dictionary branches become usable during resume. */
static bool cep_control_rehydrate_branch(cepCell* cell, cepOpCount floor_stamp) {
    if (!cell) {
        return true;
    }

    cepCell* resolved = cep_cell_resolve(cell);
    if (!resolved) {
        return false;
    }

    if (!cep_control_rehydrate_node(resolved, floor_stamp)) {
        return false;
    }

    if (!cep_cell_is_normal(resolved) || !resolved->store) {
        return true;
    }

    for (cepCell* child = cep_cell_first_all(resolved);
         child;
         child = cep_cell_next_all(resolved, child)) {
        if (!cep_control_rehydrate_branch(child, floor_stamp)) {
            return false;
        }
    }

    return true;
}

static void cep_control_mark_deleted_node(cepCell* cell, cepOpCount stamp) {
    if (!cell) {
        return;
    }

    if (!stamp) {
        stamp = cep_cell_timestamp();
    }

    if (!cell->deleted || cell->deleted < stamp) {
        cell->deleted = stamp;
    }
    cep_cell_shadow_mark_target_dead(cell, true);

    if (cep_cell_has_data(cell)) {
        cepData* data = cell->data;
        if (!data->deleted || data->deleted < stamp) {
            data->deleted = stamp;
        }
        data->writable = 0u;
        data->lock = 0u;
        data->lockOwner = NULL;
    }

    if (cep_cell_has_store(cell)) {
        cepStore* store = cell->store;
        if (!store->deleted || store->deleted < stamp) {
            store->deleted = stamp;
        }
        store->writable = false;
        store->lock = 0u;
        store->lockOwner = NULL;
    }
}

static bool cep_control_mark_branch_deleted(cepCell* cell, cepOpCount stamp) {
    if (!cell) {
        return true;
    }

    cepCell* resolved = cep_cell_resolve(cell);
    if (!resolved) {
        return false;
    }

    cep_control_mark_deleted_node(resolved, stamp);

    if (!resolved->store) {
        return true;
    }

    for (cepCell* child = cep_cell_first_all(resolved); child; ) {
        cepCell* next = cep_cell_next_all(resolved, child);
        if (!cep_control_mark_branch_deleted(child, stamp)) {
            return false;
        }
        child = next;
    }

    return true;
}

/* Soft-delete application dictionaries under /data during rollback so the
   subsequent cleanup pass can revive their prior state deterministically. */
static bool cep_control_soft_delete_data(void) {
    CEP_DEBUG_PRINTF("[prr-soft-delete] enter\n");
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return true;
    }

    cepCell* resolved = cep_cell_resolve(data_root);
    if (!resolved) {
        return false;
    }
    if (!cep_cell_has_store(resolved)) {
        return true;
    }

    const cepDT* mailbox_name = dt_mailbox_root_name();

    for (cepCell* child = cep_cell_first(resolved);
         child;
         child = cep_cell_next(resolved, child)) {
        cepCell* node = cep_cell_resolve(child);
        if (!node) {
            CEP_DEBUG_PRINTF("[prr] soft_delete: resolve child failed\n");
            return false;
        }

        const cepDT* name = cep_cell_get_name(node);
        if (mailbox_name && name && cep_dt_compare(mailbox_name, name) == 0) {
            continue; /* Preserve backlog mailbox while paused. */
        }

        uint64_t dbg_domain = 0u;
        uint64_t dbg_tag = 0u;
#if defined(CEP_ENABLE_DEBUG)
        const cepDT* cell_name = cep_cell_get_name(node);
        dbg_domain = cell_name ? (uint64_t)cep_id(cell_name->domain) : 0u;
        dbg_tag = cell_name ? (uint64_t)cep_id(cell_name->tag) : 0u;
#endif
        cepOpCount horizon_stamp = cep_runtime_view_horizon_stamp();
        cepOpCount stamp = cep_cell_timestamp();
        if (horizon_stamp && (!stamp || stamp <= horizon_stamp)) {
            stamp = horizon_stamp + 1u;
        }
        if (!stamp) {
            stamp = 1u;
        }
        CEP_DEBUG_PRINTF("[prr-soft-delete] node=%p nm=%016" PRIx64 "/%016" PRIx64
                         " delete_stamp=%" PRIu64 " horizon=%" PRIu64 "\n",
                         (void*)node,
                         dbg_domain,
                         dbg_tag,
                         (uint64_t)stamp,
                         (uint64_t)horizon_stamp);
        (void)dbg_domain;
        (void)dbg_tag;
        if (!cep_control_mark_branch_deleted(node, stamp)) {
            return false;
        }
    }

    return true;
}

/* Rehydrate application dictionaries rooted under /data so their stores regain
   writable ownership before the heartbeat accepts new work after resume. */
static bool cep_control_rehydrate_data(cepOpCount floor_stamp) {
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return true;
    }

    cepCell* resolved = cep_cell_resolve(data_root);
    if (!resolved) {
        return false;
    }

    if (!cep_control_rehydrate_node(resolved, floor_stamp)) {
        return false;
    }

    return cep_control_rehydrate_branch(resolved, floor_stamp);
}

/* Clear the published view horizon marker in /sys/state once cleanup finishes.
   Runtime caches keep their last reported values so in-flight observers can
   still query the previous target beat without racing the GC pass. */
static bool cep_control_clear_view_horizon(void) {
    return cep_control_state_write_u64(dt_view_horizon_field(), 0u);
}

/* Execute a single post-resume cleanup step: revive application dictionaries,
   release backlog tombstones, and clear the view horizon once everything is
   stable again. Gated by the cleanup flags tracked in CEP_CONTROL_STATE. */
static bool cep_control_cleanup_step(void) {
    bool resume_finished = CEP_CONTROL_STATE.resume.started && CEP_CONTROL_STATE.resume.closed;

    if (!resume_finished) {
        return true;
    }

    if (CEP_CONTROL_STATE.data_cleanup_pending) {
        cepOpCount floor_stamp = cep_runtime_view_horizon_floor_stamp();
        if (!floor_stamp) {
            floor_stamp = cep_runtime_view_horizon_stamp();
        }
        if (!cep_control_rehydrate_data(floor_stamp)) {
            return false;
        }
        CEP_CONTROL_STATE.data_cleanup_pending = false;
        cep_control_cleanup_update_flag();
    }

    if (!CEP_CONTROL_STATE.data_cleanup_pending &&
        !CEP_CONTROL_STATE.backlog_cleanup_pending &&
        CEP_CONTROL_STATE.gc_pending &&
        CEP_CONTROL_STATE.resume.started &&
        CEP_CONTROL_STATE.resume.closed) {
        if (!cep_control_clear_view_horizon()) {
            return false;
        }
        CEP_CONTROL_STATE.gc_pending = false;
        cep_control_cleanup_update_flag();
#if defined(CEP_ENABLE_DEBUG)
        cep_control_debug_clear(&CEP_CONTROL_STATE.rollback);
        cep_control_debug_clear(&CEP_CONTROL_STATE.resume);
#endif
    }

    return true;
}

static bool cep_control_impulse_allowed(const cepImpulse* impulse) {
    if (!impulse) {
        return true;
    }
    if (impulse->qos & CEP_IMPULSE_QOS_CONTROL) {
        return true;
    }
    if (cep_control_signal_matches(impulse->signal_path, dt_signal_op_pause())) {
        return true;
    }
    if (cep_control_signal_matches(impulse->signal_path, dt_signal_op_resume())) {
        return true;
    }
    if (cep_control_signal_matches(impulse->signal_path, dt_signal_op_rollback())) {
        return true;
    }
    if (cep_control_signal_matches(impulse->signal_path, dt_signal_op_shutdown())) {
        return true;
    }
    if (cep_control_signal_matches(impulse->signal_path, dt_signal_op_cont())) {
        return true;
    }
    if (cep_control_signal_matches(impulse->signal_path, dt_signal_op_tmo())) {
        return true;
    }
    if (cep_control_signal_matches(impulse->signal_path, dt_allow_signal_cei())) {
        return true;
    }
    return false;
}

static bool cep_control_should_gate(const cepImpulse* impulse) {
    if (!CEP_CONTROL_STATE.gating_active) {
        return false;
    }
    return !cep_control_impulse_allowed(impulse);
}

static bool cep_control_apply_locks(void) {
    if (CEP_CONTROL_STATE.locks_acquired) {
        return true;
    }

    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return false;
    }

    data_root = cep_cell_resolve(data_root);
    if (!data_root || !cep_cell_is_normal(data_root)) {
        return false;
    }

    if (!cep_cell_require_dictionary_store(&data_root)) {
        return false;
    }
    if (cep_cell_store_locked_hierarchy(data_root)) {
        return false;
    }
    cepLockToken store_token = {0};
    cepLockToken data_token = {0};

    if (!cep_store_lock(data_root, &store_token)) {
        return false;
    }

    if (cep_cell_has_data(data_root)) {
        if (cep_cell_data_locked_hierarchy(data_root)) {
            cep_store_unlock(data_root, &store_token);
            return false;
        }

        if (!cep_data_lock(data_root, &data_token)) {
            cep_store_unlock(data_root, &store_token);
            return false;
        }
    }

    CEP_CONTROL_STATE.store_lock = store_token;
    CEP_CONTROL_STATE.data_lock = data_token;
    CEP_CONTROL_STATE.locks_acquired = true;
    return true;
}

static void cep_control_release_locks(void) {
    if (!CEP_CONTROL_STATE.locks_acquired) {
        return;
    }

    cepCell* data_root = cep_heartbeat_data_root();
    if (data_root) {
        cep_data_unlock(data_root, &CEP_CONTROL_STATE.data_lock);
        cep_store_unlock(data_root, &CEP_CONTROL_STATE.store_lock);
    }

    CEP_CONTROL_STATE.locks_acquired = false;
    CEP_0(&CEP_CONTROL_STATE.store_lock);
    CEP_0(&CEP_CONTROL_STATE.data_lock);
}

#if defined(CEP_ENABLE_DEBUG)
static bool cep_control_debug_prepare_node(cepCell** node) {
    if (!node || !*node) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] prepare_node missing pointer\n");
        return false;
    }

    cepCell* resolved = cep_cell_resolve(*node);
    if (!resolved || !cep_cell_is_normal(resolved)) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] prepare_node resolve failed\n");
        return false;
    }

    if (!cep_cell_require_dictionary_store(&resolved)) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] prepare_node require store failed\n");
        return false;
    }

    if (resolved->store) {
        if (resolved->store->owner != resolved) {
            resolved->store->owner = resolved;
        }
        if (!resolved->store->writable) {
            resolved->store->writable = 1u;
        }
        if (resolved->store->lock) {
            resolved->store->lock = 0u;
        }
    }

    if (resolved->metacell.veiled) {
        resolved->metacell.veiled = 0u;
    }
    if (resolved->deleted) {
        resolved->deleted = 0u;
    }
    if (resolved->created == 0u) {
        resolved->created = cep_cell_timestamp_next();
    }

    *node = resolved;
    return true;
}

static cepCell* cep_control_debug_resolve_op(cepOID oid) {
    if (!cep_oid_is_valid(oid)) {
        return NULL;
    }

    if (!cep_heartbeat_bootstrap()) {
        return NULL;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return NULL;
    }

    cepCell* ops_node = cep_cell_find_by_name(rt_root, dt_ops_rt_name());
    if (!ops_node) {
        ops_node = cep_cell_find_by_name_all(rt_root, dt_ops_rt_name());
    }
    if (!ops_node) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] ops_root missing\n");
        return NULL;
    }

    if (!cep_control_debug_prepare_node(&ops_node)) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] ops_root prepare failed\n");
        return NULL;
    }

    cepDT lookup = {
        .domain = oid.domain,
        .tag = oid.tag,
        .glob = 0u,
    };

    cepCell* dossier = cep_cell_find_by_name(ops_node, &lookup);
    if (!dossier) {
        dossier = cep_cell_find_by_name_all(ops_node, &lookup);
    }
    if (!dossier) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] dossier missing domain=%llu tag=%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return NULL;
    }

    if (!cep_control_debug_prepare_node(&dossier)) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] dossier prepare failed domain=%llu tag=%llu\n",
                         (unsigned long long)oid.domain,
                         (unsigned long long)oid.tag);
        return NULL;
    }

    return dossier;
}

static void cep_control_debug_log(const cepControlOpState* op,
                                  const char* stage,
                                  const char* note) {
    if (!op || !stage || !cep_oid_is_valid(op->oid)) {
        return;
    }

    CEP_DEBUG_PRINTF("[prr-debug-meta] log request oid=%llu:%llu stage=%s\n",
                     (unsigned long long)op->oid.domain,
                     (unsigned long long)op->oid.tag,
                     stage);

    cepCell* dossier = cep_control_debug_resolve_op(op->oid);
    if (!dossier) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] resolve failed oid=%llu:%llu\n",
                         (unsigned long long)op->oid.domain,
                         (unsigned long long)op->oid.tag);
        return;
    }

    cepCell* meta = cep_cell_find_by_name(dossier, dt_meta_name());
    if (!meta) {
        cepDT meta_name = *dt_meta_name();
        cepDT meta_type = *dt_dictionary_type();
        meta = cep_cell_add_dictionary(dossier, &meta_name, 0u, &meta_type, CEP_STORAGE_RED_BLACK_T);
        if (!meta) {
            CEP_DEBUG_PRINTF("[prr-debug-meta] meta create failed\n");
            return;
        }
    }
    meta = cep_cell_resolve(meta);
    if (!meta) {
        meta = cep_cell_find_by_name_all(dossier, dt_meta_name());
        if (!meta || !cep_control_debug_prepare_node(&meta)) {
            CEP_DEBUG_PRINTF("[prr-debug-meta] meta resolve failed\n");
            return;
        }
    } else {
        if (!cep_control_debug_prepare_node(&meta)) {
            CEP_DEBUG_PRINTF("[prr-debug-meta] meta prepare failed\n");
            return;
        }
    }

    cepCell* debug_root = cep_cell_ensure_dictionary_child(meta, dt_debug_root_name(), CEP_STORAGE_RED_BLACK_T);
    if (!debug_root) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] ensure debug root failed\n");
        return;
    }

    if (!cep_control_debug_prepare_node(&debug_root)) {
        return;
    }

    size_t index = cep_cell_children(debug_root);
    CEP_DEBUG_PRINTF("[prr-debug-meta] debug_root children=%zu\n", index);
    cepDT entry_name = {0};
    if (!cep_control_set_numeric_name(&entry_name, index)) {
        entry_name = cep_ops_make_dt("debug_entry");
    }

    cepDT dict_type = *dt_dictionary_type();
    cepCell* entry = cep_cell_add_dictionary(debug_root,
                                             &entry_name,
                                             0u,
                                             &dict_type,
                                             CEP_STORAGE_RED_BLACK_T);
    if (!entry) {
        CEP_DEBUG_PRINTF("[prr-debug-meta] add_dictionary failed stage=%s\n", stage);
        return;
    }

    if (!cep_control_debug_prepare_node(&entry)) {
        return;
    }

    CEP_DEBUG_PRINTF("[prr-debug-meta] entry ready stage=%s\n", stage);

    cep_cell_put_text(entry, dt_debug_stage_field(), stage);
    if (note && note[0] != '\0') {
        (void)cep_cell_put_text(entry, dt_debug_note_field(), note);
    }

    cep_cell_put_uint64(entry, dt_debug_phase_field(), (uint64_t)op->phase);
    cep_cell_put_uint64(entry, dt_debug_ready_field(), cep_control_ready_for_next(op) ? 1u : 0u);
    cep_cell_put_uint64(entry, dt_debug_beat_field(), (uint64_t)cep_heartbeat_current());
    CEP_DEBUG_PRINTF("[prr-debug-meta] oid=%llu:%llu stage=%s note=%s\n",
                     (unsigned long long)op->oid.domain,
                     (unsigned long long)op->oid.tag,
                     stage,
                     note ? note : "<none>");
}

static void cep_control_debug_clear(const cepControlOpState* op) {
    if (!op || !cep_oid_is_valid(op->oid)) {
        return;
    }

    cepCell* dossier = cep_control_debug_resolve_op(op->oid);
    if (!dossier) {
        return;
    }

    cepCell* meta = cep_cell_find_by_name(dossier, dt_meta_name());
    if (!meta) {
        meta = cep_cell_find_by_name_all(dossier, dt_meta_name());
    }
    if (!meta) {
        return;
    }

    cepCell* resolved = cep_cell_resolve(meta);
    if (!resolved) {
        return;
    }

    cepCell* debug_root = cep_cell_find_by_name(resolved, dt_debug_root_name());
    if (!debug_root) {
        return;
    }

    debug_root = cep_cell_resolve(debug_root);
    if (!debug_root) {
        return;
    }

    cep_cell_remove_hard(debug_root, NULL);
    CEP_DEBUG_PRINTF("[prr-debug-meta] oid=%llu:%llu cleared debug branch\n",
                     (unsigned long long)op->oid.domain,
                     (unsigned long long)op->oid.tag);
}
#endif

static bool cep_control_op_is_closed(cepOID oid) {
    char info[160];
    if (!cep_op_get(oid, info, sizeof info)) {
        return false;
    }
    return strstr(info, "closed=1") != NULL;
}

static bool cep_control_op_closed_ok(cepOID oid) {
    char info[160];
    if (!cep_op_get(oid, info, sizeof info)) {
        return false;
    }

    const char* closed = strstr(info, "closed=1");
    if (!closed) {
        return false;
    }

    unsigned long long status_dom = 0u;
    unsigned long long status_tag = 0u;
    (void)sscanf(info, "%*[^ ] status=0x%llx:0x%llx", &status_dom, &status_tag);
    const char* status_text = NULL;
    char status_buf[32] = {0};
    const char* status_type = "unknown";
    if (status_tag != 0u) {
        cepID tag_id = (cepID)status_tag;
        if (cep_id_is_reference(tag_id)) {
            status_text = cep_namepool_lookup(tag_id, NULL);
            status_type = "reference";
        } else if (cep_id_is_word(tag_id)) {
            cep_word_to_text(tag_id, status_buf);
            status_text = status_buf;
            status_type = "word";
        } else if (cep_id_is_acronym(tag_id)) {
            cep_acronym_to_text(tag_id, status_buf);
            status_text = status_buf;
            status_type = "acronym";
        } else if (cep_id_is_numeric(tag_id)) {
            snprintf(status_buf, sizeof status_buf, "#%llu", (unsigned long long)cep_id(tag_id));
            status_text = status_buf;
            status_type = "numeric";
        } else if (cep_id_is_auto(tag_id)) {
            status_type = "auto";
        }
    }

    cepDT ok_status = cep_ops_make_dt("sts:ok");
    bool match = (status_dom == (unsigned long long)ok_status.domain) &&
                 (status_tag == (unsigned long long)ok_status.tag);

    CEP_DEBUG_PRINTF("[prr] op_get(%llu:%llu) info=\"%s\" status_text=%s status_type=%s match_ok=%d (sts:ok=0x%llx:0x%llx)\n",
                     (unsigned long long)oid.domain,
                     (unsigned long long)oid.tag,
                     info,
                     status_text ? status_text : "<null>",
                     status_type,
                     match ? 1 : 0,
                     (unsigned long long)ok_status.domain,
                     (unsigned long long)ok_status.tag);
    return match;
}

static const char* CEP_CONTROL_TARGET = "/sys/state";

/* Emit a CEI fact when the control heartbeat fails during a specific phase.
   The helper records the active verb, attaches the owning operation, and
   assigns a critical severity so shutdown follows the same path as other
   integrity failures. */
static void cep_control_emit_failure_cei(cepControlOpState* op,
                                         const char* phase,
                                         const char* reason) {
    if (!op || !phase || !reason) {
        return;
    }
    if (op->diag_emitted) {
        int dup_err = cep_ops_debug_last_error();
        CEP_DEBUG_PRINTF("[prr] control failure (dup) phase=%s reason=%s err=%d\n",
                         phase,
                         reason,
                         dup_err);
        return;
    }

    int err = cep_ops_debug_last_error();
    CEP_DEBUG_PRINTF("[prr] control failure phase=%s reason=%s horizon=%lld err=%d\n",
                     phase,
                     reason,
                     (long long)CEP_RUNTIME.view_horizon,
                     err);

    if (CEP_RUNTIME.view_horizon != CEP_BEAT_INVALID) {
        /* Avoid duplicating CEI facts while the control loop already owns a
           valid horizon; the debug log above still records the failure. */
        op->diag_emitted = true;
        return;
    }

    const char* verb_text = "control";
    if (cep_dt_is_valid(&op->verb_dt)) {
        const char* text = cep_namepool_lookup(op->verb_dt.tag, NULL);
        if (text && text[0]) {
            verb_text = text;
        }
    }

    char note[256];
    snprintf(note,
             sizeof note,
             "%s failure during %s: %s (oid=%llu:%llu err=%d)",
             verb_text,
             phase,
             reason,
             (unsigned long long)op->oid.domain,
             (unsigned long long)op->oid.tag,
             err);
    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:crit"),
        .note = note,
        .topic = "control/prr",
        .topic_intern = true,
        .attach_to_op = cep_oid_is_valid(op->oid),
        .op = op->oid,
        .emit_signal = true,
        .ttl_forever = true,
    };

    (void)cep_cei_emit(&req);
    op->diag_emitted = true;
}

/* Emit a guard diagnostics note when a control verb is rejected before the
   operation starts. Used for cleanup/GC gating to surface cadence issues
   without relying on an active control dossier. */
static void cep_control_emit_guard_cei(cepControlOpState* op, const char* reason) {
    if (!op || !reason) {
        return;
    }
    if (op->diag_emitted) {
        return;
    }

    const char* verb_text = "control";
    if (!cep_dt_is_valid(&op->verb_dt)) {
        /* Assign a default verb so the diagnostic stays descriptive. */
        op->verb_dt = cep_ops_make_dt("op/control");
    } else {
        const char* text = cep_namepool_lookup(op->verb_dt.tag, NULL);
        if (text && text[0]) {
            verb_text = text;
        }
    }

    char note[256];
    snprintf(note,
             sizeof note,
             "%s rejected: %s",
             verb_text,
             reason);

    cepCeiRequest req = {
        .severity = *CEP_DTAW("CEP", "sev:crit"),
        .note = note,
        .topic = "control/prr",
        .topic_intern = true,
        .attach_to_op = cep_oid_is_valid(op->oid),
        .op = op->oid,
        .emit_signal = true,
        .ttl_forever = true,
    };

    (void)cep_cei_emit(&req);
    op->diag_emitted = true;
}

static bool cep_control_start_op(cepControlOpState* op, cepDT verb) {
    if (!op) {
        return false;
    }
    if (!cep_dt_is_valid(&verb)) {        op->failed = true;
        op->verb_dt = verb;
        cep_control_emit_failure_cei(op, "start", "invalid verb dt");
        return false;
    }
    if (op->started && !op->failed) {
        return true;
    }

    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, CEP_CONTROL_TARGET, mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(oid)) {
        op->failed = true;
        op->verb_dt = verb;
        cep_control_emit_failure_cei(op, "start", "op_start failed");
        return false;
    }
    CEP_DEBUG_PRINTF("[prr] control_start verb=%s oid=%llu:%llu\n",
                     cep_namepool_lookup(verb.tag, NULL),
                     (unsigned long long)oid.domain,
                     (unsigned long long)oid.tag);

    cepDT plan_state = *dt_ist_plan();
    if (!cep_op_state_set(oid, plan_state, 0, NULL)) {
        op->failed = true;
        op->verb_dt = verb;
        cep_control_emit_failure_cei(op, "start", "state_set failed");
        return false;
    }

    op->oid = oid;
    op->started = true;
    op->closed = false;
    op->failed = false;
    op->phase = CEP_CTRL_PHASE_PLAN;
    op->last_beat = cep_heartbeat_current();
    if (op->last_beat == CEP_BEAT_INVALID) {
        op->last_beat = 0u;
    }
    op->verb_dt = verb;
    op->diag_emitted = false;
    return true;
}

static bool cep_control_start_pause(void) {
    cepDT verb = cep_ops_make_dt("op/pause");
    return cep_control_start_op(&CEP_CONTROL_STATE.pause, verb);
}

static bool cep_control_start_resume(void) {
    cepDT verb = cep_ops_make_dt("op/resume");
    return cep_control_start_op(&CEP_CONTROL_STATE.resume, verb);
}

static bool cep_control_start_rollback(cepBeatNumber to) {
    CEP_CONTROL_STATE.rollback_target = to;
    CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_EXAMINE;
    cepDT verb = cep_ops_make_dt("op/rollback");
    if (!cep_control_start_op(&CEP_CONTROL_STATE.rollback, verb)) {
        CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_IDLE;
        return false;
    }
    return true;
}

static bool cep_control_ready_for_next(const cepControlOpState* op) {
    if (!op) {
        return false;
    }
    cepBeatNumber current = cep_heartbeat_current();
    if (current == CEP_BEAT_INVALID) {
        current = 0u;
    }
    if (op->last_beat == CEP_BEAT_INVALID) {
        return true;
    }
    return current != op->last_beat;
}

static bool cep_control_close_op(cepControlOpState* op, bool success) {
    if (!op || !op->started || op->closed) {
        return true;
    }

    cepDT status = cep_ops_make_dt(success ? "sts:ok" : "sts:fail");
    cep_control_debug_snapshot("close_op-entry", op, success ? 1 : 0);
if (!success) {
        cep_control_emit_failure_cei(op, "close", "operation closed with failure");
    }
    if (!cep_op_close(op->oid, status, NULL, 0u)) {
        return false;
    }

    op->closed = true;
    op->phase = CEP_CTRL_PHASE_CLOSING;
    op->last_beat = cep_heartbeat_current();
    if (op->last_beat == CEP_BEAT_INVALID) {
        op->last_beat = 0u;
    }
    if (success) {
        op->diag_emitted = false;
    }
    if (op == &CEP_CONTROL_STATE.rollback) {
        CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_IDLE;
    }
    cep_control_debug_snapshot("close_op-after", op, success ? 1 : 0);
#if defined(CEP_ENABLE_DEBUG)
    if (!CEP_CONTROL_STATE.cleanup_pending) {
        cep_control_debug_clear(op);
    }
#endif
    return true;
}

static bool cep_control_progress(void) {
    bool ok = true;

    CEP_DEBUG_PRINTF("[prr] control_progress entry\n");
    CEP_DEBUG_PRINTF("[prr] rollback flags started=%d closed=%d failed=%d phase=%d\n",
                     CEP_CONTROL_STATE.rollback.started ? 1 : 0,
                     CEP_CONTROL_STATE.rollback.closed ? 1 : 0,
                     CEP_CONTROL_STATE.rollback.failed ? 1 : 0,
                     CEP_CONTROL_STATE.rollback.phase);

#if defined(CEP_ENABLE_DEBUG)
    if (CEP_CONTROL_STATE.rollback.started && cep_oid_is_valid(CEP_CONTROL_STATE.rollback.oid)) {
        char note[80];
        const char* stage_label = "rollback-progress";
        if (CEP_CONTROL_STATE.rollback.closed) {
            stage_label = "rollback-closed";
        } else {
            switch (CEP_CONTROL_STATE.rollback_stage) {
                case CEP_ROLLBACK_STAGE_EXAMINE: stage_label = "rollback-progress-examine"; break;
                case CEP_ROLLBACK_STAGE_PRUNE:   stage_label = "rollback-progress-prune";   break;
                case CEP_ROLLBACK_STAGE_CUTOVER: stage_label = "rollback-progress-cutover"; break;
                case CEP_ROLLBACK_STAGE_STEADY:  stage_label = "rollback-progress-steady";  break;
                case CEP_ROLLBACK_STAGE_FAILED:  stage_label = "rollback-progress-failed";  break;
                case CEP_ROLLBACK_STAGE_IDLE:
                default:
                    stage_label = "rollback-progress";
                    break;
            }
        }
        int written = snprintf(note,
                               sizeof note,
                               "cleanup=%d gating=%d paused=%d",
                               CEP_CONTROL_STATE.cleanup_pending ? 1 : 0,
                               CEP_CONTROL_STATE.gating_active ? 1 : 0,
                               CEP_RUNTIME.paused ? 1 : 0);
        const char* payload = (written > 0 && (size_t)written < sizeof note) ? note : NULL;
        cep_control_debug_log(&CEP_CONTROL_STATE.rollback, stage_label, payload);
    }
    if (CEP_CONTROL_STATE.resume.started && cep_oid_is_valid(CEP_CONTROL_STATE.resume.oid)) {
        char note[80];
        int written = snprintf(note,
                               sizeof note,
                               "cleanup=%d backlog=%d paused=%d",
                               CEP_CONTROL_STATE.cleanup_pending ? 1 : 0,
                               CEP_CONTROL_STATE.backlog_cleanup_pending ? 1 : 0,
                               CEP_RUNTIME.paused ? 1 : 0);
        const char* payload = (written > 0 && (size_t)written < sizeof note) ? note : NULL;
        const char* stage = CEP_CONTROL_STATE.resume.closed ? "resume-closed" : "resume-progress";
        cep_control_debug_log(&CEP_CONTROL_STATE.resume, stage, payload);
    }
#endif

    cepBeatNumber current = cep_heartbeat_current();
    if (current == CEP_BEAT_INVALID) {
        current = 0u;
    }

    if (!cep_control_cleanup_step()) {
        return false;
    }

    /* Pause */
    if (CEP_CONTROL_STATE.pause.started && !CEP_CONTROL_STATE.pause.closed) {
        cepControlOpState* op = &CEP_CONTROL_STATE.pause;

        if (!op->failed && op->phase == CEP_CTRL_PHASE_PLAN && cep_control_ready_for_next(op)) {
            if (!cep_control_apply_locks()) {
                op->failed = true;
                cep_control_emit_failure_cei(op, "quiesce", "lock acquisition failed");
                ok = false;
            } else {
                CEP_CONTROL_STATE.gating_active = true;
                cepDT quiesce = *dt_ist_quiesce();
                if (!cep_op_state_set(op->oid, quiesce, 0, NULL)) {
                    op->failed = true;
                    cep_control_emit_failure_cei(op, "quiesce", "state transition failed");
                    ok = false;
                } else {
                    op->phase = CEP_CTRL_PHASE_APPLY;
                    op->last_beat = current;
                }
            }
        }

        if (!op->failed && op->phase == CEP_CTRL_PHASE_APPLY && cep_control_ready_for_next(op)) {
            CEP_RUNTIME.paused = true;
            CEP_CONTROL_STATE.paused_published = true;
            if (!cep_control_state_write_bool(dt_paused_field(), true)) {
                op->failed = true;
                cep_control_emit_failure_cei(op, "publish", "paused state write failed");
                ok = false;
            } else {
                cepDT paused = *dt_ist_paused();
                if (!cep_op_state_set(op->oid, paused, 0, NULL)) {
                    op->failed = true;
                    cep_control_emit_failure_cei(op, "publish", "state transition failed");
                    ok = false;
                } else {
                    op->phase = CEP_CTRL_PHASE_STEADY;
                    op->last_beat = current;
                }
            }
        }

        if (op->phase == CEP_CTRL_PHASE_STEADY || op->failed) {
            ok = cep_control_close_op(op, !op->failed) && ok;
        }
    }

    /* Rollback */
    if (CEP_CONTROL_STATE.rollback.started && !CEP_CONTROL_STATE.rollback.closed) {
        cepControlOpState* op = &CEP_CONTROL_STATE.rollback;

        CEP_DEBUG_PRINTF("[prr] rollback phase=%d failed=%d ready=%d\n",
                         (int)op->phase,
                         op->failed ? 1 : 0,
                         cep_control_ready_for_next(op) ? 1 : 0);

        if (!op->failed && op->phase == CEP_CTRL_PHASE_PLAN && cep_control_ready_for_next(op)) {
            if (CEP_CONTROL_STATE.rollback_stage == CEP_ROLLBACK_STAGE_EXAMINE) {
#if defined(CEP_ENABLE_DEBUG)
                cep_control_debug_log(op, "rollback-examine", "advance-to-prune");
#endif
                CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_PRUNE;
                op->last_beat = current;
            } else if (CEP_CONTROL_STATE.rollback_stage == CEP_ROLLBACK_STAGE_PRUNE) {
#if defined(CEP_ENABLE_DEBUG)
                cep_control_debug_log(op, "rollback-prune", "enter");
#endif
                if (!cep_control_backlog_prune_discard()) {
                    op->failed = true;
                    CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_FAILED;
                    CEP_DEBUG_PRINTF("[prr] rollback failure: backlog prune\n");
#if defined(CEP_ENABLE_DEBUG)
                    cep_control_debug_log(op, "rollback-prune", "backlog prune failed");
#endif
                    cep_control_emit_failure_cei(op, "cutover", "backlog prune failed");
                    ok = false;
                } else {
                    CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_CUTOVER;
                    op->last_beat = current;
#if defined(CEP_ENABLE_DEBUG)
                    cep_control_debug_log(op, "rollback-prune", "complete");
#endif
                }
            } else if (CEP_CONTROL_STATE.rollback_stage == CEP_ROLLBACK_STAGE_CUTOVER) {
                cepBeatNumber target = CEP_CONTROL_STATE.rollback_target;
                cepOpCount horizon_stamp = 0u;
                cepOpCount horizon_floor = 0u;
#if defined(CEP_ENABLE_DEBUG)
                cep_control_debug_log(op, "rollback-cutover", "enter");
#endif
                if (!cep_heartbeat_beat_to_op_stamp(target, &horizon_stamp)) {
                    op->failed = true;
                    CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_FAILED;
                    CEP_DEBUG_PRINTF("[prr] rollback failure: view horizon stamp unavailable target=%llu\n",
                                     (unsigned long long)target);
#if defined(CEP_ENABLE_DEBUG)
                    cep_control_debug_log(op, "rollback-cutover", "view horizon stamp unavailable");
#endif
                    cep_control_emit_failure_cei(op, "cutover", "view horizon stamp unavailable");
                    ok = false;
                } else {
                    if (target > 0u) {
                        if (!cep_heartbeat_beat_to_op_stamp(target - 1u, &horizon_floor)) {
                            horizon_floor = 0u;
                        }
                    } else {
                        horizon_floor = horizon_stamp;
                    }

                    if (!cep_control_state_write_u64(dt_view_horizon_field(), (uint64_t)target)) {
                        op->failed = true;
                        CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_FAILED;
                        CEP_DEBUG_PRINTF("[prr] rollback failure: view horizon write\n");
#if defined(CEP_ENABLE_DEBUG)
                        cep_control_debug_log(op, "rollback-cutover", "view horizon write failed");
#endif
                        cep_control_emit_failure_cei(op, "cutover", "view horizon write failed");
                        ok = false;
                    } else {
                        cepDT cutover = *dt_ist_cutover();
                        if (!cep_op_state_set(op->oid, cutover, 0, NULL)) {
                            op->failed = true;
                            CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_FAILED;
                            CEP_DEBUG_PRINTF("[prr] rollback failure: state set cutover\n");
                            cep_control_emit_failure_cei(op, "cutover", "state transition failed");
                            ok = false;
                        } else {
                            CEP_RUNTIME.view_horizon = target;
                            CEP_RUNTIME.view_horizon_stamp = horizon_stamp;
                            CEP_RUNTIME.view_horizon_floor_stamp = horizon_floor;
                            CEP_DEBUG_PRINTF("[prr] horizon set target=%llu stamp=%llu floor=%llu\n",
                                             (unsigned long long)target,
                                             (unsigned long long)horizon_stamp,
                                             (unsigned long long)horizon_floor);
#if defined(CEP_ENABLE_DEBUG)
                            char note_buf[96];
                            snprintf(note_buf,
                                     sizeof note_buf,
                                     "target=%llu stamp=%llu floor=%llu",
                                     (unsigned long long)target,
                                     (unsigned long long)horizon_stamp,
                                     (unsigned long long)horizon_floor);
                            cep_control_debug_log(op, "rollback-cutover", note_buf);
#endif
                            if (!cep_control_soft_delete_data()) {
                                op->failed = true;
                                CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_FAILED;
                                CEP_DEBUG_PRINTF("[prr] rollback failure: soft delete\n");
#if defined(CEP_ENABLE_DEBUG)
                                cep_control_debug_log(op, "rollback-cutover", "soft delete failed");
#endif
                                cep_control_emit_failure_cei(op, "cutover", "soft delete failed");
                                ok = false;
                            } else {
                                CEP_CONTROL_STATE.data_cleanup_pending = true;
                                CEP_CONTROL_STATE.gc_pending = true;
                                cep_control_cleanup_update_flag();
                                CEP_CONTROL_STATE.rollback_stage = CEP_ROLLBACK_STAGE_STEADY;
                                op->phase = CEP_CTRL_PHASE_APPLY;
                                op->last_beat = current;
#if defined(CEP_ENABLE_DEBUG)
                                cep_control_debug_log(op, "rollback-cutover", "complete");
#endif
                            }
                        }
                    }
                }
            }
        }

        if (!op->failed && op->phase == CEP_CTRL_PHASE_APPLY && cep_control_ready_for_next(op)) {
#if defined(CEP_ENABLE_DEBUG)
            cep_control_debug_log(op, "rollback-apply", "ready");
#endif
            cepDT ok_state = cep_ops_make_dt("ist:ok");
            if (cep_control_op_closed_ok(op->oid)) {
                CEP_DEBUG_PRINTF("[prr] rollback op %llu:%llu already closed (sts:ok)\n",
                                 (unsigned long long)op->oid.domain,
                                 (unsigned long long)op->oid.tag);
#if defined(CEP_ENABLE_DEBUG)
                cep_control_debug_log(op, "rollback-apply", "dossier already closed");
#endif
                op->phase = CEP_CTRL_PHASE_STEADY;
                op->closed = true;
                op->last_beat = current;
            } else if (cep_control_op_is_closed(op->oid)) {
                CEP_DEBUG_PRINTF("[prr] rollback op %llu:%llu already closed (non-ok)\n",
                                 (unsigned long long)op->oid.domain,
                                 (unsigned long long)op->oid.tag);
#if defined(CEP_ENABLE_DEBUG)
                cep_control_debug_log(op, "rollback-apply", "dossier closed (non-ok)");
#endif
                op->phase = CEP_CTRL_PHASE_STEADY;
                op->closed = true;
                op->failed = true;
                op->last_beat = current;
            } else if (!cep_op_state_set(op->oid, ok_state, 0, NULL)) {
                op->failed = true;
                CEP_DEBUG_PRINTF("[prr] rollback failure: state set ok\n");
#if defined(CEP_ENABLE_DEBUG)
                cep_control_debug_log(op, "rollback-apply", "state transition failed");
#endif
                cep_control_emit_failure_cei(op, "cutover", "state transition failed");
                ok = false;
            } else {
#if defined(CEP_ENABLE_DEBUG)
                cep_control_debug_log(op, "rollback-apply", "state set ok");
#endif
                op->phase = CEP_CTRL_PHASE_STEADY;
                op->last_beat = current;
            }
        }

        if (op->phase == CEP_CTRL_PHASE_STEADY || op->failed) {
            if (!op->closed) {
#if defined(CEP_ENABLE_DEBUG)
                if (!op->failed && CEP_CONTROL_STATE.cleanup_pending) {
                    cep_control_debug_log(op, "rollback-wait-cleanup", "cleanup pending");
                } else {
                    cep_control_debug_log(op, "rollback-close", op->failed ? "closing after failure" : "closing ok");
                }
#endif
                if (op->failed || !CEP_CONTROL_STATE.cleanup_pending) {
                    ok = cep_control_close_op(op, !op->failed) && ok;
                }
            }
        }
    }

    /* Resume */
    if (CEP_CONTROL_STATE.resume.started && !CEP_CONTROL_STATE.resume.closed) {
        cepControlOpState* op = &CEP_CONTROL_STATE.resume;

        if (!op->failed && op->phase == CEP_CTRL_PHASE_PLAN && cep_control_ready_for_next(op)) {
            cep_control_debug_snapshot("resume-plan-before", op, -1);
            CEP_CONTROL_STATE.gating_active = false;
            cep_control_release_locks();
            CEP_RUNTIME.paused = false;
            CEP_CONTROL_STATE.paused_published = false;
            cepBeatNumber prior_horizon = CEP_RUNTIME.view_horizon;
            cepOpCount prior_stamp = CEP_RUNTIME.view_horizon_stamp;
            cepOpCount prior_floor = CEP_RUNTIME.view_horizon_floor_stamp;
            if (!cep_control_state_write_bool(dt_paused_field(), false)) {
                op->failed = true;
                cep_control_emit_failure_cei(op, "resume", "paused state write failed");
                ok = false;
            } else {
                cepDT run_state = *dt_ist_run();
                if (!cep_op_state_set(op->oid, run_state, 0, NULL)) {
                    CEP_RUNTIME.view_horizon = prior_horizon;
                    CEP_RUNTIME.view_horizon_stamp = prior_stamp;
                    CEP_RUNTIME.view_horizon_floor_stamp = prior_floor;
                    op->failed = true;
                    cep_control_emit_failure_cei(op, "resume", "state transition failed");
                    ok = false;
                } else {
                    CEP_RUNTIME.view_horizon = prior_horizon;
                    CEP_RUNTIME.view_horizon_stamp = prior_stamp;
                    CEP_RUNTIME.view_horizon_floor_stamp = prior_floor;
                    op->phase = CEP_CTRL_PHASE_APPLY;
                    op->last_beat = current;
                    cep_control_debug_snapshot("resume-plan-after", op, -1);
                }
            }
        }

        if (!op->failed && op->phase == CEP_CTRL_PHASE_APPLY && cep_control_ready_for_next(op)) {
            cep_control_debug_snapshot("resume-apply-before", op, -1);
            if (!cep_control_backlog_drain()) {
                op->failed = true;
                cep_control_emit_failure_cei(op, "resume", "backlog drain failed");
                ok = false;
            } else {
                op->phase = CEP_CTRL_PHASE_STEADY;
                op->last_beat = current;
                cep_control_debug_snapshot("resume-apply-after", op, -1);
            }
        }

        if (op->phase == CEP_CTRL_PHASE_STEADY || op->failed) {
            cep_control_debug_snapshot("resume-close-trigger", op, -1);
            ok = cep_control_close_op(op, !op->failed) && ok;
        }
    }

    if (!ok) {
        CEP_DEBUG_PRINTF(
            "[prr] control_progress failure pause(s=%d f=%d) resume(s=%d f=%d) rollback(s=%d f=%d) gating=%d\n",
            CEP_CONTROL_STATE.pause.started,
            CEP_CONTROL_STATE.pause.failed,
            CEP_CONTROL_STATE.resume.started,
            CEP_CONTROL_STATE.resume.failed,
            CEP_CONTROL_STATE.rollback.started,
            CEP_CONTROL_STATE.rollback.failed,
            CEP_CONTROL_STATE.gating_active);
    }

    return ok;
}

CEP_DEFINE_STATIC_DT(dt_scope_kernel,   CEP_ACRO("CEP"), CEP_WORD("kernel"));
CEP_DEFINE_STATIC_DT(dt_scope_namepool, CEP_ACRO("CEP"), CEP_WORD("namepool"));
CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));
CEP_DEFINE_STATIC_DT(dt_list_type,      CEP_ACRO("CEP"), CEP_WORD("list"));
CEP_DEFINE_STATIC_DT(dt_log_payload,    CEP_ACRO("CEP"), CEP_WORD("log"));
CEP_DEFINE_STATIC_DT(dt_state_root,     CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_sys_root_name,  CEP_ACRO("CEP"), CEP_WORD("sys"));
CEP_DEFINE_STATIC_DT(dt_rt_root_name,   CEP_ACRO("CEP"), CEP_WORD("rt"));
CEP_DEFINE_STATIC_DT(dt_ops_rt_name,   CEP_ACRO("CEP"), CEP_WORD("ops"));
CEP_DEFINE_STATIC_DT(dt_journal_root_name, CEP_ACRO("CEP"), CEP_WORD("journal"));
CEP_DEFINE_STATIC_DT(dt_env_root_name,  CEP_ACRO("CEP"), CEP_WORD("env"));
CEP_DEFINE_STATIC_DT(dt_cas_root_name,  CEP_ACRO("CEP"), CEP_WORD("cas"));
CEP_DEFINE_STATIC_DT(dt_lib_root_name,  CEP_ACRO("CEP"), CEP_WORD("lib"));
CEP_DEFINE_STATIC_DT(dt_data_root_name, CEP_ACRO("CEP"), CEP_WORD("data"));
CEP_DEFINE_STATIC_DT(dt_tmp_root_name,  CEP_ACRO("CEP"), CEP_WORD("tmp"));
CEP_DEFINE_STATIC_DT(dt_enzymes_root_name, CEP_ACRO("CEP"), CEP_WORD("enzymes"));
CEP_DEFINE_STATIC_DT(dt_organs_root_name,  CEP_ACRO("CEP"), CEP_WORD("organs"));
CEP_DEFINE_STATIC_DT(dt_beat_root_name, CEP_ACRO("CEP"), CEP_WORD("beat"));
CEP_DEFINE_STATIC_DT(dt_impulses_name,  CEP_ACRO("CEP"), CEP_WORD("impulses"));
CEP_DEFINE_STATIC_DT(dt_inbox_legacy_name, CEP_ACRO("CEP"), CEP_WORD("inbox"));
CEP_DEFINE_STATIC_DT(dt_agenda_name,    CEP_ACRO("CEP"), CEP_WORD("agenda"));
CEP_DEFINE_STATIC_DT(dt_stage_name,     CEP_ACRO("CEP"), CEP_WORD("stage"));
CEP_DEFINE_STATIC_DT(dt_boot_oid_field, CEP_ACRO("CEP"), CEP_WORD("boot_oid"));
CEP_DEFINE_STATIC_DT(dt_shdn_oid_field, CEP_ACRO("CEP"), CEP_WORD("shdn_oid"));
CEP_DEFINE_STATIC_DT(dt_ist_kernel,     CEP_ACRO("CEP"), CEP_WORD("ist:kernel"));
CEP_DEFINE_STATIC_DT(dt_ist_store,      CEP_ACRO("CEP"), CEP_WORD("ist:store"));
CEP_DEFINE_STATIC_DT(dt_ist_plan,       CEP_ACRO("CEP"), CEP_WORD("ist:plan"));
CEP_DEFINE_STATIC_DT(dt_ist_quiesce,    CEP_ACRO("CEP"), CEP_WORD("ist:quiesce"));
CEP_DEFINE_STATIC_DT(dt_ist_paused,     CEP_ACRO("CEP"), CEP_WORD("ist:paused"));
CEP_DEFINE_STATIC_DT(dt_ist_cutover,    CEP_ACRO("CEP"), CEP_WORD("ist:cutover"));
CEP_DEFINE_STATIC_DT(dt_ist_run,        CEP_ACRO("CEP"), CEP_WORD("ist:run"));
CEP_DEFINE_STATIC_DT(dt_meta_name,      CEP_ACRO("CEP"), CEP_WORD("meta"));
CEP_DEFINE_STATIC_DT(dt_unix_ts_name, CEP_ACRO("CEP"), CEP_WORD("unix_ts_ns"));
CEP_DEFINE_STATIC_DT(dt_analytics_root_name, CEP_ACRO("CEP"), CEP_WORD("analytics"));
CEP_DEFINE_STATIC_DT(dt_spacing_name,   CEP_ACRO("CEP"), CEP_WORD("spacing"));
CEP_DEFINE_STATIC_DT(dt_interval_ns_name, CEP_ACRO("CEP"), CEP_WORD("interval_ns"));
CEP_DEFINE_STATIC_DT(dt_op_stamp_name, CEP_ACRO("CEP"), CEP_WORD("op_stamp"));
CEP_DEFINE_STATIC_DT(dt_paused_field,   CEP_ACRO("CEP"), CEP_WORD("paused"));
CEP_DEFINE_STATIC_DT(dt_view_horizon_field, CEP_ACRO("CEP"), CEP_WORD("view_hzn"));
CEP_DEFINE_STATIC_DT(dt_mailbox_root_name, CEP_ACRO("CEP"), CEP_WORD("mailbox"));
CEP_DEFINE_STATIC_DT(dt_impulse_mailbox_name, CEP_ACRO("CEP"), CEP_WORD("impulses"));
CEP_DEFINE_STATIC_DT(dt_msgs_name, CEP_ACRO("CEP"), CEP_WORD("msgs"));
CEP_DEFINE_STATIC_DT(dt_kind_name, CEP_ACRO("CEP"), CEP_WORD("kind"));
CEP_DEFINE_STATIC_DT(dt_runtime_name, CEP_ACRO("CEP"), CEP_WORD("runtime"));
CEP_DEFINE_STATIC_DT(dt_envelope_name, CEP_ACRO("CEP"), CEP_WORD("envelope"));
CEP_DEFINE_STATIC_DT(dt_qos_field, CEP_ACRO("CEP"), CEP_WORD("qos"));
CEP_DEFINE_STATIC_DT(dt_signal_field, CEP_ACRO("CEP"), CEP_WORD("signal"));
CEP_DEFINE_STATIC_DT(dt_target_field_control, CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_timestamp_field, CEP_ACRO("CEP"), CEP_WORD("timestamp"));
CEP_DEFINE_STATIC_DT(dt_domain_field, CEP_ACRO("CEP"), CEP_WORD("domain"));
CEP_DEFINE_STATIC_DT(dt_tag_field, CEP_ACRO("CEP"), CEP_WORD("tag"));
CEP_DEFINE_STATIC_DT(dt_allow_signal_cei, CEP_ACRO("CEP"), CEP_WORD("sig_cei"));
CEP_DEFINE_STATIC_DT(dt_signal_op_pause, CEP_ACRO("CEP"), CEP_WORD("op/pause"));
CEP_DEFINE_STATIC_DT(dt_signal_op_resume, CEP_ACRO("CEP"), CEP_WORD("op/resume"));
CEP_DEFINE_STATIC_DT(dt_signal_op_rollback, CEP_ACRO("CEP"), CEP_WORD("op/rollback"));
CEP_DEFINE_STATIC_DT(dt_signal_op_shutdown, CEP_ACRO("CEP"), CEP_WORD("op/shdn"));
CEP_DEFINE_STATIC_DT(dt_signal_op_cont, CEP_ACRO("CEP"), CEP_WORD("op/cont"));
CEP_DEFINE_STATIC_DT(dt_signal_op_tmo, CEP_ACRO("CEP"), CEP_WORD("op/tmo"));
CEP_DEFINE_STATIC_DT(dt_issued_field, CEP_ACRO("CEP"), CEP_WORD("issued_beat"));
#if defined(CEP_ENABLE_DEBUG)
CEP_DEFINE_STATIC_DT(dt_debug_root_name,   CEP_ACRO("CEP"), CEP_WORD("debug"));
CEP_DEFINE_STATIC_DT(dt_debug_stage_field, CEP_ACRO("CEP"), CEP_WORD("dbg_stage"));
CEP_DEFINE_STATIC_DT(dt_debug_note_field,  CEP_ACRO("CEP"), CEP_WORD("dbg_note"));
CEP_DEFINE_STATIC_DT(dt_debug_phase_field, CEP_ACRO("CEP"), CEP_WORD("dbg_phase"));
CEP_DEFINE_STATIC_DT(dt_debug_ready_field, CEP_ACRO("CEP"), CEP_WORD("dbg_ready"));
CEP_DEFINE_STATIC_DT(dt_debug_beat_field,  CEP_ACRO("CEP"), CEP_WORD("dbg_beat"));
#endif

typedef struct {
    const char* kind;
    const char* label;
    bool        has_constructor;
    bool        has_destructor;
} cepHeartbeatOrganDescriptorInit;

#define CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT 256u

static cepCell* ensure_root_dictionary(cepCell* root, const cepDT* name, const cepDT* store_dt);
static cepCell* ensure_root_list(cepCell* root, const cepDT* name, const cepDT* store_dt);

static cepDT cep_heartbeat_make_signal_dt(const char* kind, const char* suffix) {
    if (!kind || !*kind || !suffix || !*suffix) {
        return (cepDT){0};
    }

    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "org:%s:%s", kind, suffix);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return (cepDT){0};
    }
    return cep_ops_make_dt(buffer);
}

static cepDT cep_heartbeat_make_validator_dt(const char* kind) {
    return cep_heartbeat_make_signal_dt(kind, "vl");
}

static bool cep_heartbeat_register_l0_organs(void) {
    static const cepHeartbeatOrganDescriptorInit descriptors[] = {
        { "sys_state",     "Kernel state organ",            false, false },
        { "sys_organs",    "Organ descriptor registry",     false, false },
        { "rt_ops",        "Runtime operations organ",      false, false },
        { "rt_beat",       "Heartbeat beat organ",          true,  true  },
        { "journal",       "Beat journal organ",            true,  true  },
        { "env",           "Environment organ",             false, false },
        { "cas",           "Content store organ",           false, false },
        { "lib",           "Library organ",                 false, false },
        { "tmp",           "Scratch queue organ",           false, false },
        { "enzymes",       "Enzyme manifest organ",         false, false },
    };

    size_t count = sizeof descriptors / sizeof descriptors[0];
    for (size_t index = 0; index < count; ++index) {
        const cepHeartbeatOrganDescriptorInit* init = &descriptors[index];
        cepDT store_dt = cep_organ_store_dt(init->kind);
        cepDT validator_dt = cep_heartbeat_make_validator_dt(init->kind);

        if (!cep_dt_is_valid(&store_dt) || !cep_dt_is_valid(&validator_dt)) {
            return false;
        }

        cepOrganDescriptor descriptor;
        memset(&descriptor, 0, sizeof descriptor);
        descriptor.kind = init->kind;
        descriptor.label = init->label;
        descriptor.store = store_dt;
        descriptor.validator = validator_dt;
        if (init->has_constructor) {
            descriptor.constructor = cep_heartbeat_make_signal_dt(init->kind, "ct");
        }
        if (init->has_destructor) {
            descriptor.destructor = cep_heartbeat_make_signal_dt(init->kind, "dt");
        }
if (!cep_organ_register(&descriptor)) {
return false;
        }
    }

    return true;
}
CEP_DEFINE_STATIC_DT(dt_ist_packs,      CEP_ACRO("CEP"), CEP_WORD("ist:packs"));
CEP_DEFINE_STATIC_DT(dt_ist_stop,       CEP_ACRO("CEP"), CEP_WORD("ist:stop"));
CEP_DEFINE_STATIC_DT(dt_ist_flush,      CEP_ACRO("CEP"), CEP_WORD("ist:flush"));
CEP_DEFINE_STATIC_DT(dt_ist_halt,       CEP_ACRO("CEP"), CEP_WORD("ist:halt"));
CEP_DEFINE_STATIC_DT(dt_sts_ok,         CEP_ACRO("CEP"), CEP_WORD("sts:ok"));
CEP_DEFINE_STATIC_DT(dt_sts_fail,       CEP_ACRO("CEP"), CEP_WORD("sts:fail"));

typedef struct {
    const char*             label;
    const cepDT*          (*scope_dt)(void);
    const cepLifecycleScope*dependencies;
    size_t                  dependency_count;
} cepLifecycleScopeInfo;

typedef struct {
    bool            ready;
    bool            teardown;
    cepBeatNumber   ready_beat;
    cepBeatNumber   td_beat;
} cepLifecycleScopeState;

typedef enum {
    CEP_BOOT_PHASE_NONE = 0,
    CEP_BOOT_PHASE_KERNEL,
    CEP_BOOT_PHASE_STORE,
    CEP_BOOT_PHASE_PACKS,
    CEP_BOOT_PHASE_CLOSED,
} cepBootPhase;

typedef enum {
    CEP_SHDN_PHASE_NONE = 0,
    CEP_SHDN_PHASE_STOP,
    CEP_SHDN_PHASE_FLUSH,
    CEP_SHDN_PHASE_HALT,
    CEP_SHDN_PHASE_CLOSED,
} cepShutdownPhase;

typedef struct {
    cepOID          boot_oid;
    cepOID          shdn_oid;
    bool            boot_started;
    bool            boot_closed;
    bool            shdn_started;
    bool            shdn_closed;
    bool            boot_failed;
    bool            shdn_failed;
    cepBootPhase    boot_phase;
    cepShutdownPhase shdn_phase;
    cepBeatNumber   boot_last_beat;
    cepBeatNumber   shdn_last_beat;
    bool            boot_kernel_ready;
    bool            boot_namepool_ready;
    size_t          shdn_scopes_marked;
} cepLifecycleOpsState;

static const cepLifecycleScope CEP_SCOPE_DEPS_NAMEPOOL[] = {
    CEP_LIFECYCLE_SCOPE_KERNEL,
};

static const cepLifecycleScopeInfo CEP_LIFECYCLE_SCOPE_INFO[CEP_LIFECYCLE_SCOPE_COUNT] = {
    [CEP_LIFECYCLE_SCOPE_KERNEL] = {
        .label = "kernel",
        .scope_dt = dt_scope_kernel,
        .dependencies = NULL,
        .dependency_count = 0u,
    },
    [CEP_LIFECYCLE_SCOPE_NAMEPOOL] = {
        .label = "namepool",
        .scope_dt = dt_scope_namepool,
        .dependencies = CEP_SCOPE_DEPS_NAMEPOOL,
        .dependency_count = cep_lengthof(CEP_SCOPE_DEPS_NAMEPOOL),
    },
};

static cepLifecycleScopeState CEP_LIFECYCLE_STATE[CEP_LIFECYCLE_SCOPE_COUNT];
static cepLifecycleOpsState CEP_LIFECYCLE_OPS_STATE;
static const cepLifecycleScope CEP_LIFECYCLE_TEARDOWN_ORDER[] = {
    CEP_LIFECYCLE_SCOPE_NAMEPOOL,
    CEP_LIFECYCLE_SCOPE_KERNEL,
};

static void cep_lifecycle_reset_state(void);
static bool cep_lifecycle_scope_dependencies_ready(cepLifecycleScope scope);
static cepCell* cep_lifecycle_get_dictionary(cepCell* parent, const cepDT* name, bool create);
static void cep_lifecycle_reload_state(void);
static void cep_boot_ops_reset(void);
static cepBeatNumber cep_boot_ops_effective_beat(void);
static bool cep_boot_ops_ready_for_next(cepBeatNumber last);
static bool cep_boot_ops_progress(void);
static bool cep_boot_ops_record_state(cepOID oid, const cepDT* state_dt, bool* failure_flag);
static bool cep_boot_ops_close_boot(bool success);
static bool cep_boot_ops_close_shutdown(bool success);

static cepCell* cep_heartbeat_ensure_list_child(cepCell* parent, const cepDT* name);
static bool cep_heartbeat_append_list_message(cepCell* list, const char* message);
static char* cep_heartbeat_path_to_string(const cepPath* path);


static int cep_heartbeat_path_compare(const cepPath* lhs, const cepPath* rhs) {
    if (lhs == rhs) {
        return 0;
    }
    if (!lhs) {
        return rhs ? -1 : 0;
    }
    if (!rhs) {
        return 1;
    }

    if (lhs->length < rhs->length) {
        return -1;
    }
    if (lhs->length > rhs->length) {
        return 1;
    }

    for (unsigned i = 0; i < lhs->length; ++i) {
        int cmp = cep_dt_compare(&lhs->past[i].dt, &rhs->past[i].dt);
        if (cmp != 0) {
            return cmp;
        }
    }

    return 0;
}


static uint64_t cep_heartbeat_hash_mix(uint64_t hash, uint64_t value) {
    hash ^= value + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    return hash;
}


static uint64_t cep_heartbeat_path_hash(const cepPath* path) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    if (!path) {
        return hash;
    }

    hash = cep_heartbeat_hash_mix(hash, path->length);
    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        hash = cep_heartbeat_hash_mix(hash, segment->dt.domain);
        hash = cep_heartbeat_hash_mix(hash, segment->dt.tag);
        hash = cep_heartbeat_hash_mix(hash, segment->timestamp);
    }

    return hash;
}


static uint64_t cep_heartbeat_impulse_hash(const cepHeartbeatImpulseRecord* record) {
    uint64_t hash = 0x84222325cbf29ce4ULL;
    if (!record) {
        return hash;
    }

    hash = cep_heartbeat_hash_mix(hash, cep_heartbeat_path_hash(record->signal_path));
    hash = cep_heartbeat_hash_mix(hash, cep_heartbeat_path_hash(record->target_path));
    return hash;
}


static bool cep_heartbeat_policy_use_dirs(void) {
    return CEP_RUNTIME.policy.ensure_directories;
}


static bool cep_heartbeat_id_to_string(cepID id, char* buffer, size_t capacity, size_t* out_len) {
    if (!buffer || capacity == 0u) {
        return false;
    }

    size_t len = 0u;

    if (cep_id_is_reference(id)) {
        size_t ref_len = 0u;
        const char* text = cep_namepool_lookup(id, &ref_len);
        if (!text) {
            return false;
        }
        if (ref_len + 1u > capacity) {
            return false;
        }
        memcpy(buffer, text, ref_len);
        buffer[ref_len] = '\0';
        if (out_len) {
            *out_len = ref_len;
        }
        return true;
    } else if (cep_id_is_word(id)) {
        len = cep_word_to_text(id, buffer);
    } else if (cep_id_is_acronym(id)) {
        len = cep_acronym_to_text(id, buffer);
    } else if (cep_id_is_numeric(id)) {
        uint64_t value = (uint64_t)cep_id(id);
        int written = snprintf(buffer, capacity, "%" PRIu64, (uint64_t)value);
        if (written < 0) {
            return false;
        }
        len = (size_t)written;
    } else {
        if (capacity < 2u) {
            return false;
        }
        buffer[0] = '?';
        buffer[1] = '\0';
        len = 1u;
    }

    if (len + 1u > capacity) {
        return false;
    }

    if (out_len) {
        *out_len = len;
    }

    return true;
}


static bool cep_heartbeat_dt_to_string(const cepDT* dt, char* buffer, size_t capacity) {
    if (!dt) {
        return false;
    }

    char domain_buf[32];
    char tag_buf[32];
    size_t domain_len = 0u;
    size_t tag_len = 0u;

    if (!cep_heartbeat_id_to_string(dt->domain, domain_buf, sizeof(domain_buf), &domain_len)) {
        return false;
    }

    if (!cep_heartbeat_id_to_string(dt->tag, tag_buf, sizeof(tag_buf), &tag_len)) {
        return false;
    }

    size_t needed = domain_len + 1u + tag_len;
    if (needed + 1u > capacity) {
        return false;
    }

    memcpy(buffer, domain_buf, domain_len);
    buffer[domain_len] = ':';
    memcpy(buffer + domain_len + 1u, tag_buf, tag_len);
    buffer[needed] = '\0';
    return true;
}


static char* cep_heartbeat_path_to_string(const cepPath* path) {
    if (!path || path->length == 0u) {
        char* empty = cep_malloc(2u);
        if (!empty) {
            return NULL;
        }
        empty[0] = '-';
        empty[1] = '\0';
        return empty;
    }

    size_t capacity = (size_t)path->length * 80u + 2u;
    char* text = cep_malloc(capacity);
    if (!text) {
        return NULL;
    }

    size_t pos = 0u;
    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];

        if (pos + 1u >= capacity) {
            cep_free(text);
            return NULL;
        }
        text[pos++] = '/';

        char domain_buf[32];
        size_t domain_len = 0u;
        if (!cep_heartbeat_id_to_string(segment->dt.domain, domain_buf, sizeof(domain_buf), &domain_len)) {
            cep_free(text);
            return NULL;
        }
        if (pos + domain_len >= capacity) {
            cep_free(text);
            return NULL;
        }
        memcpy(text + pos, domain_buf, domain_len);
        pos += domain_len;

        if (pos + 1u >= capacity) {
            cep_free(text);
            return NULL;
        }
        text[pos++] = ':';

        char tag_buf[32];
        size_t tag_len = 0u;
        if (!cep_heartbeat_id_to_string(segment->dt.tag, tag_buf, sizeof(tag_buf), &tag_len)) {
            cep_free(text);
            return NULL;
        }
        if (pos + tag_len >= capacity) {
            cep_free(text);
            return NULL;
        }
        memcpy(text + pos, tag_buf, tag_len);
        pos += tag_len;

        if (segment->timestamp) {
            int written = snprintf(text + pos, capacity - pos, "@%" PRIu64, (uint64_t)segment->timestamp);
            if (written < 0) {
                cep_free(text);
                return NULL;
            }
            size_t w = (size_t)written;
            if (pos + w >= capacity) {
                cep_free(text);
                return NULL;
            }
            pos += w;
        }
    }

    if (pos == 0u) {
        text[pos++] = '/';
    }

    if (pos >= capacity) {
        cep_free(text);
        return NULL;
    }

    text[pos] = '\0';
    return text;
}


static bool cep_heartbeat_append_list_message(cepCell* list, const char* message) {
    if (!list || !message) {
        return false;
    }

    size_t len = strlen(message);
    size_t size = len + 1u;
    char* buffer = cep_malloc(size);
    if (!buffer) {
        return false;
    }

    memcpy(buffer, message, len);
    buffer[len] = '\0';

    cepDT name = {
        .domain = CEP_ACRO("HB"),
        .tag    = CEP_AUTOID,
    };

    cepDT payload_type = *dt_log_payload();
    cepCell* entry = cep_cell_append_value(list, &name, &payload_type, buffer, size, size);
    cep_free(buffer);
    return entry != NULL;
}


static cepCell* cep_heartbeat_ensure_dictionary_child(cepCell* parent, const cepDT* name, bool* created) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child) {
        cepDT dict_type = *dt_dictionary_type();
        cepDT name_copy = cep_dt_clean(name);
        child = cep_cell_add_dictionary(parent, &name_copy, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (created) {
            *created = true;
        }
    } else if (created) {
        *created = false;
    }

    return child;
}


static cepCell* cep_heartbeat_ensure_list_child(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }

    cepCell* child = cep_cell_find_by_name(parent, name);
    if (!child) {
        cepDT list_type = *dt_list_type();
        cepDT name_copy = cep_dt_clean(name);
        child = cep_cell_add_list(parent, &name_copy, 0, &list_type, CEP_STORAGE_LINKED_LIST);
    }
    return child;
}

static cepCell* cep_heartbeat_ensure_meta_child(cepCell* beat_cell) {
    if (!beat_cell) {
        return NULL;
    }

    cepCell* meta = cep_cell_find_by_name(beat_cell, dt_meta_name());
    if (!meta) {
        cepDT meta_name = cep_dt_clean(dt_meta_name());
        cepDT dict_type = *dt_dictionary_type();
        meta = cep_cell_add_dictionary(beat_cell, &meta_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
    } else {
        meta = cep_cell_resolve(meta);
    }

    if (!meta) {
        return NULL;
    }

    if (!cep_cell_require_dictionary_store(&meta)) {
        return NULL;
    }

    return meta;
}

static bool cep_heartbeat_ensure_legacy_inbox_alias(cepCell* beat_cell, cepCell* impulses_cell) {
    if (!beat_cell || !impulses_cell) {
        return false;
    }

    cepCell* legacy = cep_cell_find_by_name(beat_cell, dt_inbox_legacy_name());
    if (!legacy) {
        cepDT alias_name = cep_dt_clean(dt_inbox_legacy_name());
        cepCell* alias = cep_cell_add_link(beat_cell, &alias_name, 0, impulses_cell);
        if (!alias) {
            return false;
        }
        /* FIXME: Drop the legacy `inbox` alias once downstream tooling is updated.
         * The link survives for one release to keep older consumers alive. */
        cep_link_set(alias, impulses_cell);
        return true;
    }

    cepCell* resolved = cep_cell_resolve(legacy);
    if (resolved != impulses_cell) {
        if (cep_cell_is_link(legacy)) {
            cep_link_set(legacy, impulses_cell);
        } else {
            cepDT new_name = cep_dt_clean(dt_impulses_name());
            cep_cell_set_name(legacy, &new_name);
            return cep_heartbeat_ensure_legacy_inbox_alias(beat_cell, impulses_cell);
        }
    }

    return true;
}

static cepCell* cep_heartbeat_resolve_impulse_log(cepCell* beat_cell) {
    if (!beat_cell) {
        return NULL;
    }

    cepCell* impulses = cep_cell_find_by_name(beat_cell, dt_impulses_name());
    if (impulses && cep_cell_is_link(impulses)) {
        impulses = cep_cell_resolve(impulses);
    }

    if (!impulses) {
        cepCell* legacy = cep_cell_find_by_name(beat_cell, dt_inbox_legacy_name());
        if (legacy && !cep_cell_is_link(legacy)) {
            cepDT new_name = cep_dt_clean(dt_impulses_name());
            cep_cell_set_name(legacy, &new_name);
            impulses = legacy;
        }
    }

    if (!impulses) {
        impulses = cep_heartbeat_ensure_list_child(beat_cell, dt_impulses_name());
    }

    if (!impulses) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_legacy_inbox_alias(beat_cell, impulses)) {
        return NULL;
    }

    return impulses;
}


static bool cep_heartbeat_set_numeric_name(cepDT* name, cepBeatNumber beat) {
    if (!name || beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (beat >= CEP_AUTOID_MAX) {
        return false;
    }

    name->glob = 0u;
    name->domain = CEP_ACRO("HB");
    name->tag = cep_id_to_numeric((cepID)(beat + 1u));
    return true;
}


static cepCell* cep_heartbeat_ensure_beat_node(cepBeatNumber beat) {
    if (!cep_heartbeat_policy_use_dirs() || beat == CEP_BEAT_INVALID) {
        return NULL;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return NULL;
    }

    cepCell* beat_root = cep_heartbeat_ensure_dictionary_child(rt_root, dt_beat_root_name(), NULL);
    if (!beat_root) {
        return NULL;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return NULL;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_dictionary_child(beat_root, &beat_name, NULL);
    if (!beat_cell) {
        return NULL;
    }

    if (!cep_heartbeat_resolve_impulse_log(beat_cell)) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_list_child(beat_cell, dt_agenda_name())) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_list_child(beat_cell, dt_stage_name())) {
        return NULL;
    }

    if (!cep_heartbeat_ensure_meta_child(beat_cell)) {
        return NULL;
    }

    return beat_cell;
}


static bool cep_heartbeat_record_impulse_entry(cepBeatNumber beat, const cepImpulse* impulse) {
    if (!cep_heartbeat_policy_use_dirs() || beat == CEP_BEAT_INVALID || !impulse) {
        return true;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    cepCell* impulses = cep_heartbeat_resolve_impulse_log(beat_cell);
    if (!impulses) {
        return false;
    }

    char* signal = cep_heartbeat_path_to_string(impulse->signal_path);
    char* target = cep_heartbeat_path_to_string(impulse->target_path);
    if (!signal || !target) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    int written = snprintf(NULL, 0, "signal=%s target=%s", signal, target);
    if (written < 0) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    size_t size = (size_t)written + 1u;
    char* message = cep_malloc(size);
    if (!message) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    snprintf(message, size, "signal=%s target=%s", signal, target);
    bool ok = cep_heartbeat_append_list_message(impulses, message);

    cep_free(message);
    cep_free(signal);
    cep_free(target);
    return ok;
}


static const char* cep_heartbeat_descriptor_label(const cepEnzymeDescriptor* descriptor, char* buffer, size_t capacity) {
    if (!descriptor) {
        return "no-match";
    }

    if (descriptor->label && descriptor->label[0]) {
        return descriptor->label;
    }

    if (cep_heartbeat_dt_to_string(&descriptor->name, buffer, capacity)) {
        return buffer;
    }

    return "(unnamed)";
}


static bool cep_heartbeat_record_agenda_entry(cepBeatNumber beat, const cepEnzymeDescriptor* descriptor, int rc, const cepImpulse* impulse) {
    if (!cep_heartbeat_policy_use_dirs()) {
        return true;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    cepCell* agenda = cep_cell_find_by_name(beat_cell, dt_agenda_name());
    if (!agenda) {
        agenda = cep_heartbeat_ensure_list_child(beat_cell, dt_agenda_name());
        if (!agenda) {
            return false;
        }
    }

    char* signal = cep_heartbeat_path_to_string(impulse ? impulse->signal_path : NULL);
    char* target = cep_heartbeat_path_to_string(impulse ? impulse->target_path : NULL);
    if (!signal || !target) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    char name_buf[64];
    const char* name = cep_heartbeat_descriptor_label(descriptor, name_buf, sizeof(name_buf));

    int written;
    if (descriptor) {
        written = snprintf(NULL, 0, "enzyme=%s rc=%d signal=%s target=%s", name, rc, signal, target);
    } else {
        written = snprintf(NULL, 0, "no-match signal=%s target=%s", signal, target);
    }

    if (written < 0) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    size_t size = (size_t)written + 1u;
    char* message = cep_malloc(size);
    if (!message) {
        cep_free(signal);
        cep_free(target);
        return false;
    }

    if (descriptor) {
        snprintf(message, size, "enzyme=%s rc=%d signal=%s target=%s", name, rc, signal, target);
    } else {
        snprintf(message, size, "no-match signal=%s target=%s", signal, target);
    }

    bool ok = cep_heartbeat_append_list_message(agenda, message);

    cep_free(message);
    cep_free(signal);
    cep_free(target);
    return ok;
}


static bool cep_heartbeat_record_stage_entry(cepBeatNumber beat, const char* message) {
    if (!cep_heartbeat_policy_use_dirs() || !message) {
        return true;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    cepCell* stage = cep_cell_find_by_name(beat_cell, dt_stage_name());
    if (!stage) {
        stage = cep_heartbeat_ensure_list_child(beat_cell, dt_stage_name());
        if (!stage) {
            return false;
        }
    }

    return cep_heartbeat_append_list_message(stage, message);
}

bool cep_heartbeat_stage_note(const char* message) {
    if (!message)
        return false;

    if (!cep_heartbeat_policy_use_dirs())
        return true;

    cepBeatNumber beat = (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : CEP_RUNTIME.current;
    const char* final_message = message;
    char* formatted = NULL;

    cepCell* beat_cell = cep_heartbeat_ensure_beat_node(beat);
    if (!beat_cell) {
        return false;
    }

    uint64_t unix_ts = 0u;
    bool have_unix_ts = cep_heartbeat_beat_to_unix(beat, &unix_ts);
    if (!have_unix_ts) {
        cepCell* meta = cep_cell_find_by_name(beat_cell, dt_meta_name());
        if (meta) {
            meta = cep_cell_resolve(meta);
            if (meta) {
                cepCell* ts_cell = cep_cell_find_by_name(meta, dt_unix_ts_name());
                if (ts_cell) {
                    ts_cell = cep_cell_resolve(ts_cell);
                    if (ts_cell && cep_cell_has_data(ts_cell)) {
                        const char* stored_text = (const char*)cep_cell_data(ts_cell);
                        if (stored_text) {
                            char* endptr = NULL;
                            uint64_t parsed = (uint64_t)strtoull(stored_text, &endptr, 10);
                            if (endptr && *endptr == '\0') {
                                unix_ts = parsed;
                                have_unix_ts = true;
                            }
                        }
                    }
                }
            }
        }
    }

    if (have_unix_ts) {
        int written = snprintf(NULL, 0, "%s ts=%" PRIu64, message, unix_ts);
        if (written > 0) {
            formatted = cep_malloc((size_t)written + 1u);
            if (formatted) {
                snprintf(formatted, (size_t)written + 1u, "%s ts=%" PRIu64, message, unix_ts);
                final_message = formatted;
            }
        }
    }

    bool ok = cep_heartbeat_record_stage_entry(beat, final_message);
    cep_free(formatted);
    return ok;
}


static bool cep_heartbeat_scratch_ensure_ordered(cepHeartbeatScratch* scratch, size_t required) {
    if (!scratch) {
        return false;
    }
    if (required == 0u) {
        return true;
    }
    if (scratch->ordered_capacity >= required) {
        return true;
    }

    size_t bytes = required * sizeof(*scratch->ordered);
    const cepEnzymeDescriptor** buffer = scratch->ordered ? cep_realloc(scratch->ordered, bytes) : cep_malloc(bytes);
    if (!buffer) {
        return false;
    }

    scratch->ordered = buffer;
    scratch->ordered_capacity = required;
    return true;
}


static bool cep_heartbeat_dispatch_cache_reserve(cepHeartbeatScratch* scratch, size_t min_capacity) {
    if (!scratch || min_capacity == 0u) {
        return true;
    }

    if (scratch->entry_capacity >= min_capacity) {
        return true;
    }

    size_t capacity = scratch->entry_capacity ? scratch->entry_capacity : 8u;
    while (capacity < min_capacity && capacity < (SIZE_MAX >> 1)) {
        capacity <<= 1u;
    }
    if (capacity < min_capacity) {
        capacity = min_capacity;
    }

    size_t bytes = capacity * sizeof(*scratch->entries);
    cepHeartbeatDispatchCacheEntry* entries = scratch->entries ? cep_realloc(scratch->entries, bytes) : cep_malloc(bytes);
    if (!entries) {
        return false;
    }

    if (capacity > scratch->entry_capacity) {
        size_t old_capacity = scratch->entry_capacity;
        memset(entries + old_capacity, 0, (capacity - old_capacity) * sizeof(*entries));
    }

    scratch->entries = entries;
    scratch->entry_capacity = capacity;
    return true;
}


static void cep_heartbeat_dispatch_cache_destroy(cepHeartbeatScratch* scratch) {
    if (!scratch) {
        return;
    }

    if (scratch->entries) {
        for (size_t i = 0; i < scratch->entry_capacity; ++i) {
            CEP_FREE(scratch->entries[i].descriptors);
            scratch->entries[i].descriptors = NULL;
            scratch->entries[i].descriptor_capacity = 0u;
            scratch->entries[i].descriptor_count = 0u;
            scratch->entries[i].signal_path = NULL;
            scratch->entries[i].target_path = NULL;
            CEP_FREE(scratch->entries[i].memo);
            scratch->entries[i].memo = NULL;
            scratch->entries[i].memo_capacity = 0u;
            scratch->entries[i].memo_count = 0u;
            scratch->entries[i].used = 0u;
            scratch->entries[i].stamp = 0u;
            scratch->entries[i].hash = 0u;
        }
        CEP_FREE(scratch->entries);
    }

    CEP_FREE(scratch->ordered);

    memset(scratch, 0, sizeof(*scratch));
}


static void cep_heartbeat_scratch_next_generation(cepHeartbeatScratch* scratch) {
    if (!scratch) {
        return;
    }

    scratch->generation += 1u;
    if (scratch->generation == 0u) {
        scratch->generation = 1u;
        if (scratch->entries) {
            for (size_t i = 0; i < scratch->entry_capacity; ++i) {
                scratch->entries[i].stamp = 0u;
                scratch->entries[i].used = 0u;
                scratch->entries[i].hash = 0u;
                scratch->entries[i].signal_path = NULL;
                scratch->entries[i].target_path = NULL;
                scratch->entries[i].descriptor_count = 0u;
                scratch->entries[i].memo_count = 0u;
            }
        }
    }
}


/*
    Ensure dispatch cache entries keep memo buffers large enough to hold per
    descriptor execution state so duplicate impulses within a beat can be
    short-circuited safely. The allocator grows geometrically, zero-filling the
    newly added tail while preserving prior observations for descriptors that
    already ran this generation.
*/
static bool cep_heartbeat_dispatch_entry_reserve_memo(cepHeartbeatDispatchCacheEntry* entry, size_t required) {
    if (!entry) {
        return required == 0u;
    }

    if (required == 0u || entry->memo_capacity >= required) {
        return true;
    }

    size_t new_capacity = entry->memo_capacity ? entry->memo_capacity : 4u;
    while (new_capacity < required) {
        new_capacity <<= 1u;
    }

    size_t bytes = new_capacity * sizeof(*entry->memo);
    cepHeartbeatDescriptorMemo* memo = entry->memo ?
        cep_realloc(entry->memo, bytes) :
        cep_malloc(bytes);
    if (!memo) {
        return false;
    }

    if (new_capacity > entry->memo_capacity) {
        size_t old_bytes = entry->memo_capacity * sizeof(*entry->memo);
        memset(((uint8_t*)memo) + old_bytes, 0, bytes - old_bytes);
    }

    entry->memo = memo;
    entry->memo_capacity = new_capacity;
    return true;
}


static cepHeartbeatDispatchCacheEntry* cep_heartbeat_dispatch_cache_acquire(cepHeartbeatScratch* scratch, const cepHeartbeatImpulseRecord* record, uint64_t hash, bool* fresh) {
    if (!scratch || !scratch->entries || scratch->entry_capacity == 0u) {
        return NULL;
    }

    size_t mask = scratch->entry_capacity - 1u;
    size_t index = (size_t)hash & mask;

    for (size_t probe = 0; probe < scratch->entry_capacity; ++probe) {
        cepHeartbeatDispatchCacheEntry* entry = &scratch->entries[index];
        if (entry->stamp != scratch->generation || !entry->used) {
            entry->used = 1u;
            entry->stamp = scratch->generation;
            entry->hash = hash;
            entry->signal_path = record ? record->signal_path : NULL;
            entry->target_path = record ? record->target_path : NULL;
            entry->descriptor_count = 0u;
            entry->memo_count = 0u;
            if (fresh) {
                *fresh = true;
            }
            return entry;
        }

        if (entry->hash == hash &&
            cep_heartbeat_path_compare(entry->signal_path, record ? record->signal_path : NULL) == 0 &&
            cep_heartbeat_path_compare(entry->target_path, record ? record->target_path : NULL) == 0) {
            if (fresh) {
                *fresh = false;
            }
            return entry;
        }

        index = (index + 1u) & mask;
    }

    return NULL;
}


static void cep_heartbeat_dispatch_cache_cleanup_generation(cepHeartbeatScratch* scratch) {
    if (!scratch || !scratch->entries) {
        return;
    }

    for (size_t i = 0; i < scratch->entry_capacity; ++i) {
        cepHeartbeatDispatchCacheEntry* entry = &scratch->entries[i];
        if (entry->stamp == scratch->generation && entry->used) {
            entry->used = 0u;
            entry->hash = 0u;
            entry->signal_path = NULL;
            entry->target_path = NULL;
            entry->descriptor_count = 0u;
            entry->memo_count = 0u;
        }
    }
}


static bool cep_runtime_has_registry(void) {
    return CEP_RUNTIME.registry != NULL;
}


static void cep_runtime_reset_state(bool destroy_registry) {
    if (destroy_registry && cep_runtime_has_registry()) {
        cep_enzyme_registry_destroy(CEP_RUNTIME.registry);
        CEP_RUNTIME.registry = NULL;
    }

    cep_ep_runtime_reset();

    cep_heartbeat_impulse_queue_destroy(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_destroy(&CEP_RUNTIME.impulses_next);
    cep_heartbeat_dispatch_cache_destroy(&CEP_RUNTIME.scratch);

    CEP_RUNTIME.current = CEP_BEAT_INVALID;
    CEP_RUNTIME.running = false;
    
    memset(&CEP_RUNTIME.topology, 0, sizeof(CEP_RUNTIME.topology));
    memset(&CEP_RUNTIME.policy, 0, sizeof(CEP_RUNTIME.policy));
    CEP_RUNTIME.policy.ensure_directories = true;
    CEP_RUNTIME.policy.boot_ops = true;
    CEP_RUNTIME.policy.spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    CEP_RUNTIME.deferred_activations = 0u;
    CEP_RUNTIME.sys_shutdown_emitted = false;
    CEP_RUNTIME.bootstrapping = false;
    CEP_RUNTIME.last_wallclock_beat = CEP_BEAT_INVALID;
    CEP_RUNTIME.last_wallclock_ns = 0u;
    CEP_RUNTIME.spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    CEP_RUNTIME.paused = false;
    CEP_RUNTIME.view_horizon = CEP_BEAT_INVALID;
    CEP_RUNTIME.view_horizon_stamp = 0u;
    CEP_RUNTIME.view_horizon_floor_stamp = 0u;

    cep_lifecycle_reset_state();
    cep_organ_runtime_reset();
    cep_control_reset_state();
}


static void cep_runtime_reset_defaults(void) {
    memset(&CEP_DEFAULT_TOPOLOGY, 0, sizeof(CEP_DEFAULT_TOPOLOGY));
}

void cep_heartbeat_detach_topology(void) {
    cep_runtime_reset_state(true);
    cep_runtime_reset_defaults();
}


static cepCell* ensure_root_dictionary(cepCell* root, const cepDT* name, const cepDT* store_dt) {
    if (!root || !name) {
        return NULL;
    }

    cepCell* candidate = cep_cell_find_by_name(root, name);
    if (!candidate) {
        candidate = cep_cell_find_by_name_all(root, name);
    }

    if (!candidate) {
        cepDT dict_type = store_dt ? cep_dt_clean(store_dt) : *dt_dictionary_type();
        cepDT name_copy = cep_dt_clean(name);
        candidate = cep_cell_add_dictionary(root, &name_copy, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!candidate) {
            return NULL;
        }
    }

    cepCell* resolved = candidate;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return NULL;
    }

    if (store_dt && resolved->store) {
        if (cep_dt_compare(&resolved->store->dt, store_dt) != 0) {
            cep_store_set_dt(resolved->store, store_dt);
        }
    }

    if (resolved->store) {
        if (resolved->store->owner != resolved) {
            resolved->store->owner = resolved;
        }
        if (!resolved->store->writable) {
            resolved->store->writable = 1u;
        }
        if (resolved->store->lock) {
            resolved->store->lock = 0u;
            resolved->store->lockOwner = NULL;
        }
    }

    bool needs_unveil = cep_cell_is_veiled(resolved);
    bool needs_cell_created = (resolved->created == 0u);
    bool needs_store_created = resolved->store && resolved->store->created == 0u;

    if (resolved->deleted) {
        resolved->deleted = 0u;
    }
    if (resolved->store && resolved->store->deleted) {
        resolved->store->deleted = 0u;
    }

    if (!resolved->data) {
        cepDT payload_type = cep_ops_make_dt("val/dt");
        cepDT stored_dt = resolved->store ? resolved->store->dt : *dt_dictionary_type();
        cepDT stored_copy = cep_dt_clean(&stored_dt);
        cepData* revived_data = cep_data_new(&payload_type,
                                             CEP_DATATYPE_VALUE,
                                             true,
                                             NULL,
                                             &stored_copy,
                                             sizeof stored_copy,
                                             sizeof stored_copy);
        if (revived_data) {
            resolved->data = revived_data;
            revived_data->lockOwner = NULL;
            if (!revived_data->writable) {
                revived_data->writable = 1u;
            }
        }
    }

    if (cep_cell_is_immutable(resolved)) {
        resolved->metacell.immutable = 0u;
    }

    if (needs_unveil) {
        resolved->metacell.veiled = 0u;
    }

    cepOpCount stamp = 0u;
    if (needs_cell_created || needs_store_created) {
        stamp = cep_cell_timestamp_next();
    }
    if (needs_cell_created) {
        if (!stamp) {
            stamp = cep_cell_timestamp_next();
        }
        resolved->created = stamp;
        if (resolved->data) {
            resolved->data->created = stamp;
        }
    }
    if (resolved->store && needs_store_created) {
        if (!stamp) {
            stamp = cep_cell_timestamp_next();
        }
        resolved->store->created = stamp;
    }

    return resolved;
}


static cepCell* ensure_root_list(cepCell* root, const cepDT* name, const cepDT* store_dt) {
    cepCell* cell = cep_cell_find_by_name(root, name);
    if (!cell) {
        CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] missing name ptr=%p domain=%016llx tag=%016llx\n",
                                (void*)name,
                                name ? (unsigned long long)cep_id(name->domain) : 0ull,
                                name ? (unsigned long long)cep_id(name->tag) : 0ull);
        cepDT list_type = store_dt ? cep_dt_clean(store_dt) : *dt_list_type();
        cepDT name_copy = cep_dt_clean(name);
        cell = cep_cell_add_list(root, &name_copy, 0, &list_type, CEP_STORAGE_LINKED_LIST);
        if (!cell) {
            CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] add_list failed domain=%08x tag=%08x\n",
                                    (unsigned)name_copy.domain,
                                    (unsigned)name_copy.tag);
        }
    } else {
        cepCell* resolved = cep_cell_resolve(cell);
        if (!resolved) {
            CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] resolve failed domain=%08x tag=%08x\n",
                                    name ? (unsigned)name->domain : 0u,
                                    name ? (unsigned)name->tag : 0u);
            return NULL;
        }
        if (resolved->store && resolved->store->indexing != CEP_INDEX_BY_INSERTION) {
            CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] rebuilding list name=%016llx/%016llx indexing=%d\n",
                                    (unsigned long long)cep_id(name ? name->domain : (cepID)0),
                                    (unsigned long long)cep_id(name ? name->tag : (cepID)0),
                                    resolved->store->indexing);
            if (!cep_cell_is_root(resolved)) {
                cep_cell_remove_hard(resolved, NULL);
            }
            cepDT list_type = store_dt ? cep_dt_clean(store_dt) : *dt_list_type();
            cepDT name_copy = cep_dt_clean(name);
            cell = cep_cell_add_list(root, &name_copy, 0, &list_type, CEP_STORAGE_LINKED_LIST);
            if (!cell) {
                CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] rebuild add_list failed\n");
                return NULL;
            }
            resolved = cep_cell_resolve(cell);
            if (!resolved || !resolved->store || resolved->store->indexing != CEP_INDEX_BY_INSERTION) {
                CEP_DEBUG_PRINTF_STDOUT("[ensure_root_list] rebuild produced invalid list\n");
                return NULL;
            }
        }
        if (store_dt && resolved->store) {
            cep_store_set_dt(resolved->store, store_dt);
        }
        cell = resolved;
    }
    return cell;
}

static void cep_heartbeat_prune_spacing(cepCell* spacing) {
    if (!spacing) {
        return;
    }

    size_t target_window = CEP_RUNTIME.spacing_window ? CEP_RUNTIME.spacing_window : CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    if (target_window == 0u) {
        target_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    }

    size_t count = 0u;
    cepCell* oldest_entry = NULL;
    cepBeatNumber oldest_beat = CEP_BEAT_INVALID;
    for (cepCell* entry = cep_cell_first_all(spacing);
         entry;
         entry = cep_cell_next_all(spacing, entry)) {
        count += 1u;
        const cepDT* name = cep_cell_get_name(entry);
        if (!name || !cep_id_is_numeric(name->tag)) {
            continue;
        }
        cepBeatNumber beat = (cepBeatNumber)(cep_id(name->tag) - 1u);
        if (oldest_entry == NULL || beat < oldest_beat) {
            oldest_entry = entry;
            oldest_beat = beat;
        }
    }

    while (count > target_window && oldest_entry) {
        cep_cell_remove_hard(oldest_entry, NULL);
        count -= 1u;

        if (count <= target_window) {
            break;
        }

        oldest_entry = NULL;
        oldest_beat = CEP_BEAT_INVALID;
        for (cepCell* entry = cep_cell_first_all(spacing);
             entry;
             entry = cep_cell_next_all(spacing, entry)) {
            const cepDT* name = cep_cell_get_name(entry);
            if (!name || !cep_id_is_numeric(name->tag)) {
                continue;
            }
            cepBeatNumber beat = (cepBeatNumber)(cep_id(name->tag) - 1u);
            if (oldest_entry == NULL || beat < oldest_beat) {
                oldest_entry = entry;
                oldest_beat = beat;
            }
        }
    }
}

static bool cep_heartbeat_record_spacing(cepBeatNumber beat, uint64_t interval_ns) {
    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return false;
    }

    cepCell* analytics_root = ensure_root_dictionary(rt_root, dt_analytics_root_name(), NULL);
    if (!analytics_root) {
        return false;
    }

    cepCell* spacing = ensure_root_dictionary(analytics_root, dt_spacing_name(), NULL);
    if (!spacing) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* entry = cep_heartbeat_ensure_dictionary_child(spacing, &beat_name, NULL);
    if (!entry) {
        return false;
    }

    if (!cep_cell_put_uint64(entry, dt_interval_ns_name(), interval_ns)) {
        return false;
    }

    /* FIXME: Replace hard-prune once L1 predators/regulators manage analytics retention. */
    cep_heartbeat_prune_spacing(spacing);
    return true;
}

static void cep_lifecycle_reset_state(void) {
    cep_boot_ops_reset();
    for (size_t i = 0; i < CEP_LIFECYCLE_SCOPE_COUNT; ++i) {
        CEP_LIFECYCLE_STATE[i].ready = false;
        CEP_LIFECYCLE_STATE[i].teardown = false;
        CEP_LIFECYCLE_STATE[i].ready_beat = 0u;
        CEP_LIFECYCLE_STATE[i].td_beat = 0u;
    }
}

static bool cep_lifecycle_scope_dependencies_ready(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }

    const cepLifecycleScopeInfo* info = &CEP_LIFECYCLE_SCOPE_INFO[scope];
    for (size_t i = 0; i < info->dependency_count; ++i) {
        cepLifecycleScope dep = info->dependencies[i];
        if (dep >= CEP_LIFECYCLE_SCOPE_COUNT) {
            return false;
        }
        if (!CEP_LIFECYCLE_STATE[dep].ready) {
            return false;
        }
    }
    return true;
}

static cepCell* cep_lifecycle_get_dictionary(cepCell* parent, const cepDT* name, bool create) {
    if (!parent || !name) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(name);
    lookup.glob = 0u;

    cepCell* existing = cep_cell_find_by_name(parent, &lookup);
    if (!create) {
        if (!existing) {
            existing = cep_cell_find_by_name_all(parent, &lookup);
            if (existing) {
                existing = cep_cell_resolve(existing);
            }
        } else {
            existing = cep_cell_resolve(existing);
        }
        return existing;
    }

    cepDT state_name = *dt_state_root();
    bool is_state_root = (cep_dt_compare(&lookup, &state_name) == 0);
    cepDT organ_dt = is_state_root ? cep_organ_store_dt("sys_state") : *dt_dictionary_type();

    if (existing) {
        cepCell* resolved = cep_cell_resolve(existing);
        if (!resolved) {
            return NULL;
        }
        if (!cep_cell_require_dictionary_store(&resolved)) {
            return NULL;
        }
        if (is_state_root && resolved->store) {
            cep_store_set_dt(resolved->store, &organ_dt);
        }
        return resolved;
    }

    cepDT name_copy = lookup;
    cepCell* added = cep_cell_add_dictionary(parent, &name_copy, 0, &organ_dt, CEP_STORAGE_RED_BLACK_T);
    if (!added) {
        return NULL;
    }

    cepCell* resolved_added = added;
    if (!cep_cell_require_dictionary_store(&resolved_added)) {
        return NULL;
    }
    return resolved_added;
}

static bool cep_boot_ops_enabled(void) {
    return CEP_RUNTIME.policy.boot_ops;
}

static void cep_boot_ops_reset(void) {
    CEP_LIFECYCLE_OPS_STATE.boot_oid = cep_oid_invalid();
    CEP_LIFECYCLE_OPS_STATE.shdn_oid = cep_oid_invalid();
    CEP_LIFECYCLE_OPS_STATE.boot_started = false;
    CEP_LIFECYCLE_OPS_STATE.boot_closed = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_started = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_closed = false;
    CEP_LIFECYCLE_OPS_STATE.boot_failed = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_failed = false;
    CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_NONE;
    CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_NONE;
    CEP_LIFECYCLE_OPS_STATE.boot_last_beat = CEP_BEAT_INVALID;
    CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = CEP_BEAT_INVALID;
    CEP_LIFECYCLE_OPS_STATE.boot_kernel_ready = false;
    CEP_LIFECYCLE_OPS_STATE.boot_namepool_ready = false;
    CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked = 0u;
}

static cepBeatNumber cep_boot_ops_effective_beat(void) {
    cepBeatNumber beat = cep_beat_index();
    return (beat == CEP_BEAT_INVALID) ? 0u : beat;
}

static bool cep_boot_ops_ready_for_next(cepBeatNumber last) {
    if (last == CEP_BEAT_INVALID) {
        return true;
    }
    return cep_boot_ops_effective_beat() > last;
}

static bool cep_boot_ops_progress_boot(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.boot_started) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_failed &&
        !CEP_LIFECYCLE_OPS_STATE.boot_closed &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        if (!cep_boot_ops_close_boot(false)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_closed = true;
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_closed) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_phase == CEP_BOOT_PHASE_KERNEL &&
        CEP_LIFECYCLE_OPS_STATE.boot_kernel_ready &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.boot_oid,
                                       dt_ist_store(),
                                       &CEP_LIFECYCLE_OPS_STATE.boot_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_STORE;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_phase == CEP_BOOT_PHASE_STORE &&
        CEP_LIFECYCLE_OPS_STATE.boot_namepool_ready &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.boot_oid,
                                       dt_ist_packs(),
                                       &CEP_LIFECYCLE_OPS_STATE.boot_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_PACKS;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.boot_phase == CEP_BOOT_PHASE_PACKS &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.boot_last_beat)) {
        bool success = !CEP_LIFECYCLE_OPS_STATE.boot_failed;
        if (!cep_boot_ops_close_boot(success)) {
            CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.boot_closed = true;
        CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    return true;
}

static bool cep_boot_ops_progress_shutdown(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.shdn_started) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_failed &&
        !CEP_LIFECYCLE_OPS_STATE.shdn_closed &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        if (!cep_boot_ops_close_shutdown(false)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_closed = true;
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_closed) {
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_phase == CEP_SHDN_PHASE_STOP &&
        CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked > 0u &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.shdn_oid,
                                       dt_ist_flush(),
                                       &CEP_LIFECYCLE_OPS_STATE.shdn_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_FLUSH;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    size_t expected = cep_lengthof(CEP_LIFECYCLE_TEARDOWN_ORDER);
    if (CEP_LIFECYCLE_OPS_STATE.shdn_phase == CEP_SHDN_PHASE_FLUSH &&
        CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked >= expected &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        if (!cep_boot_ops_record_state(CEP_LIFECYCLE_OPS_STATE.shdn_oid,
                                       dt_ist_halt(),
                                       &CEP_LIFECYCLE_OPS_STATE.shdn_failed)) {
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_HALT;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    if (CEP_LIFECYCLE_OPS_STATE.shdn_phase == CEP_SHDN_PHASE_HALT &&
        cep_boot_ops_ready_for_next(CEP_LIFECYCLE_OPS_STATE.shdn_last_beat)) {
        bool success = !CEP_LIFECYCLE_OPS_STATE.shdn_failed;
        if (!cep_boot_ops_close_shutdown(success)) {
            CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
            return false;
        }
        CEP_LIFECYCLE_OPS_STATE.shdn_closed = true;
        CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_CLOSED;
        CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
        return true;
    }

    return true;
}

static bool cep_boot_ops_progress(void) {
    bool ok = cep_boot_ops_progress_boot();
    ok = cep_boot_ops_progress_shutdown() && ok;
    return ok;
}

static bool cep_boot_ops_publish_oid(const cepDT* field_name, cepOID oid) {
    cepCell* sys_root = cep_heartbeat_sys_root();
    if (!sys_root) {
        return false;
    }

    cepCell* state_root = cep_lifecycle_get_dictionary(sys_root, dt_state_root(), true);
    if (!state_root) {
        return false;
    }

    cepDT lookup = cep_dt_clean(field_name);
    lookup.glob = 0u;
    cepCell* existing = cep_cell_find_by_name(state_root, &lookup);
    if (existing) {
        cep_cell_remove_hard(existing, NULL);
    }

    cepDT name_copy = lookup;
    cepDT type = cep_ops_make_dt("val/bytes");
    cepCell* node = cep_dict_add_value(state_root,
                                       &name_copy,
                                       &type,
                                       &oid,
                                       sizeof oid,
                                       sizeof oid);
    if (!node) {
        return false;
    }
    cep_cell_content_hash(node);
    return true;
}

static bool cep_boot_ops_record_state(cepOID oid, const cepDT* state_dt, bool* failure_flag) {
    if (!cep_oid_is_valid(oid) || !state_dt) {
        if (failure_flag) {
            *failure_flag = true;
        }
        return false;
    }

    if (!cep_op_state_set(oid, *state_dt, 0, NULL)) {
        CEP_DEBUG_PRINTF(
            "[boot_ops] state_set failed oid=%llu:%llu state=%llu:%llu\n",
            (unsigned long long)oid.domain,
            (unsigned long long)oid.tag,
            (unsigned long long)state_dt->domain,
            (unsigned long long)state_dt->tag);
        if (failure_flag) {
            *failure_flag = true;
        }
        return false;
    }

    return true;
}

static bool cep_boot_ops_start_boot(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.boot_started) {
        return true;
    }

    const char* target = "/sys/state";
    cepDT verb = cep_ops_make_dt("op/boot");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, target, mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(oid)) {
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
        return false;
    }

    if (!cep_boot_ops_publish_oid(dt_boot_oid_field(), oid)) {
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
        return false;
    }

    if (!cep_boot_ops_record_state(oid, dt_ist_kernel(), &CEP_LIFECYCLE_OPS_STATE.boot_failed)) {
        return false;
    }

    CEP_LIFECYCLE_OPS_STATE.boot_oid = oid;
    CEP_LIFECYCLE_OPS_STATE.boot_started = true;
    CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_KERNEL;
    CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
    return true;
}

static bool cep_boot_ops_start_shutdown(void) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.shdn_started) {
        return true;
    }

    const char* target = "/sys/state";
    cepDT verb = cep_ops_make_dt("op/shdn");
    cepDT mode = cep_ops_make_dt("opm:states");
    cepOID oid = cep_op_start(verb, target, mode, NULL, 0u, 0u);
    if (!cep_oid_is_valid(oid)) {
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
        return false;
    }

    if (!cep_boot_ops_publish_oid(dt_shdn_oid_field(), oid)) {
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
        return false;
    }

    if (!cep_boot_ops_record_state(oid, dt_ist_stop(), &CEP_LIFECYCLE_OPS_STATE.shdn_failed)) {
        return false;
    }

    CEP_LIFECYCLE_OPS_STATE.shdn_oid = oid;
    CEP_LIFECYCLE_OPS_STATE.shdn_started = true;
    CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_STOP;
    CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
    return true;
}

static bool cep_boot_ops_close_boot(bool success) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.boot_started) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.boot_closed) {
        return true;
    }

    bool ok = cep_op_close(CEP_LIFECYCLE_OPS_STATE.boot_oid,
                           success ? *dt_sts_ok() : *dt_sts_fail(),
                           NULL,
                           0u);
    if (!ok) {
        CEP_DEBUG_PRINTF("[boot_ops] op_close boot failed success=%d\n", success ? 1 : 0);
        fflush(stderr);
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
        return false;
    }
    CEP_LIFECYCLE_OPS_STATE.boot_closed = true;
    CEP_LIFECYCLE_OPS_STATE.boot_phase = CEP_BOOT_PHASE_CLOSED;
    CEP_LIFECYCLE_OPS_STATE.boot_last_beat = cep_boot_ops_effective_beat();
    if (!success) {
        CEP_LIFECYCLE_OPS_STATE.boot_failed = true;
    }
    return true;
}

static bool cep_boot_ops_close_shutdown(bool success) {
    if (!cep_boot_ops_enabled()) {
        return true;
    }
    if (!CEP_LIFECYCLE_OPS_STATE.shdn_started) {
        return true;
    }
    if (CEP_LIFECYCLE_OPS_STATE.shdn_closed) {
        return true;
    }

    bool ok = cep_op_close(CEP_LIFECYCLE_OPS_STATE.shdn_oid,
                           success ? *dt_sts_ok() : *dt_sts_fail(),
                           NULL,
                           0u);
    if (!ok) {
        CEP_DEBUG_PRINTF("[boot_ops] op_close shutdown failed success=%d\n", success ? 1 : 0);
        fflush(stderr);
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
        return false;
    }
    CEP_LIFECYCLE_OPS_STATE.shdn_closed = true;
    CEP_LIFECYCLE_OPS_STATE.shdn_phase = CEP_SHDN_PHASE_CLOSED;
    CEP_LIFECYCLE_OPS_STATE.shdn_last_beat = cep_boot_ops_effective_beat();
    if (!success) {
        CEP_LIFECYCLE_OPS_STATE.shdn_failed = true;
    }
    return true;
}


typedef struct {
    cepStore store;
    void*    head;
    void*    tail;
} cepListView;

static const cepDT* cep_cas_store_dt(void) {
    static cepDT cached = {0};
    if (!cep_dt_is_valid(&cached)) {
        cached = cep_organ_store_dt("cas");
    }
    return &cached;
}

static void cep_lifecycle_reload_state(void) {
    cep_lifecycle_reset_state();
}


static void cep_heartbeat_clear_store(cepCell* cell) {
    if (!cell) {
        return;
    }

    if (cell->store) {
        bool is_cas = false;
        const cepDT* cas_dt = cep_cas_store_dt();
        if (cas_dt && cep_dt_is_valid(&cell->store->dt) && cep_dt_compare(&cell->store->dt, cas_dt) == 0) {
            is_cas = true;
        } else if (cell == CEP_RUNTIME.topology.cas) {
            is_cas = true;
        }
        if (is_cas) {
#if defined(CEP_ENABLE_DEBUG)
            if (cell->store->storage == CEP_STORAGE_LINKED_LIST) {
                const cepListView* list = (const cepListView*)cell->store;
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_before] store=%p chd=%zu head=%p tail=%p\n",
                       (void*)cell->store,
                       cell->store->chdCount,
                       (void*)list->head,
                       (void*)list->tail);
            } else {
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_before] store=%p storage=%u chd=%zu\n",
                       (void*)cell->store,
                       cell->store->storage,
                       cell->store->chdCount);
            }
#endif
        }
        cep_store_delete_children_hard(cell->store);
        if (is_cas) {
#if defined(CEP_ENABLE_DEBUG)
            if (cell->store->storage == CEP_STORAGE_LINKED_LIST) {
                const cepListView* list = (const cepListView*)cell->store;
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_after] store=%p chd=%zu head=%p tail=%p\n",
                       (void*)cell->store,
                       cell->store->chdCount,
                       (void*)list->head,
                       (void*)list->tail);
            } else {
                CEP_DEBUG_PRINTF_STDOUT("[cas_clear_after] store=%p storage=%u chd=%zu\n",
                       (void*)cell->store,
                       cell->store->storage,
                       cell->store->chdCount);
            }
#endif
        }
    }
}


static void cep_heartbeat_reset_runtime_cells(void) {
    /* Keep the structural nodes but clear their contents. */
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.rt);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.journal);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.tmp);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.data);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.cas);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.env);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.lib);
    cep_heartbeat_clear_store(CEP_RUNTIME.topology.enzymes);
}


/* Establishes the heartbeat runtime by wiring up the root cells and lazy
 * allocating the enzyme registry so every public entry point works from a
 * consistent topology baseline.
 */
/** Create the runtime directories and initialise scratch buffers so future
    beats can rely on the topology without performing lazy checks. The routine
    is idempotent and safe to call before tests exercise the runtime. */
bool cep_heartbeat_bootstrap(void) {
#define CEP_BOOT_FAIL(reason)   do { fail_reason = (reason); goto fail; } while (0)
    if (CEP_RUNTIME.bootstrapping) {
        return true;
    }

    bool success = false;
    static const char* fail_reason = NULL;
    CEP_RUNTIME.bootstrapping = true;

    bool first_bootstrap = (CEP_RUNTIME.topology.root == NULL);

    cep_cell_system_ensure();

    cepCell* root = cep_root();
    if (!root) {
        CEP_BOOT_FAIL("root");
    }

    CEP_DEFAULT_TOPOLOGY.root = root;
    if (!CEP_RUNTIME.topology.root) {
        CEP_RUNTIME.topology.root = root;
    }

    const cepDT* sys_name = dt_sys_root_name();
    cepCell* sys = ensure_root_dictionary(root, sys_name, NULL);
    if (!sys) {
        CEP_BOOT_FAIL("sys dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.sys = sys;
    if (!CEP_RUNTIME.topology.sys) {
        CEP_RUNTIME.topology.sys = sys;
    }

    cepCell* state_root = cep_lifecycle_get_dictionary(sys, dt_state_root(), true);
    if (!state_root) {
        CEP_DEBUG_PRINTF("[bootstrap] state_root revive failed\n");
        CEP_BOOT_FAIL("state_root");
    }

    cepDT organs_store = cep_organ_store_dt("sys_organs");
    const cepDT* organs_name = dt_organs_root_name();
    cepCell* organs = ensure_root_dictionary(sys, organs_name, &organs_store);
    if (!organs) {
        CEP_BOOT_FAIL("organs dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.organs = organs;
    if (!CEP_RUNTIME.topology.organs) {
        CEP_RUNTIME.topology.organs = organs;
    }

    const cepDT* rt_name = dt_rt_root_name();
    cepCell* rt = ensure_root_dictionary(root, rt_name, NULL);
    if (!rt) {
        CEP_BOOT_FAIL("rt dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.rt = rt;
    if (!CEP_RUNTIME.topology.rt) {
        CEP_RUNTIME.topology.rt = rt;
    }

    cepDT beat_store = cep_organ_store_dt("rt_beat");
    const cepDT* beat_name = dt_beat_root_name();
    cepCell* beat_root = ensure_root_dictionary(rt, beat_name, &beat_store);
    if (!beat_root) {
        CEP_BOOT_FAIL("beat dictionary");
    }

    (void)cep_cell_ensure_dictionary_child(rt, dt_ops_rt_name(), CEP_STORAGE_RED_BLACK_T);

    cepDT journal_store = cep_organ_store_dt("journal");
    const cepDT* journal_name = dt_journal_root_name();
    cepCell* journal = ensure_root_dictionary(root, journal_name, &journal_store);
    if (!journal) {
        CEP_BOOT_FAIL("journal dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.journal = journal;
    if (!CEP_RUNTIME.topology.journal) {
        CEP_RUNTIME.topology.journal = journal;
    }

    cepDT env_store = cep_organ_store_dt("env");
    const cepDT* env_name = dt_env_root_name();
    cepCell* env = ensure_root_dictionary(root, env_name, &env_store);
    if (!env) {
        CEP_BOOT_FAIL("env dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.env = env;
    if (!CEP_RUNTIME.topology.env) {
        CEP_RUNTIME.topology.env = env;
    }

    cepDT cas_store = cep_organ_store_dt("cas");
    const cepDT* cas_name = dt_cas_root_name();
    cepCell* cas = ensure_root_dictionary(root, cas_name, &cas_store);
    if (!cas) {
        CEP_BOOT_FAIL("cas dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.cas = cas;
    if (!CEP_RUNTIME.topology.cas) {
        CEP_RUNTIME.topology.cas = cas;
    }

    cepDT lib_store = cep_organ_store_dt("lib");
    const cepDT* lib_name = dt_lib_root_name();
    cepCell* lib = ensure_root_dictionary(root, lib_name, &lib_store);
    if (!lib) {
        CEP_BOOT_FAIL("lib dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.lib = lib;
    if (!CEP_RUNTIME.topology.lib) {
        CEP_RUNTIME.topology.lib = lib;
    }

    const cepDT* data_name = dt_data_root_name();
    cepCell* data = ensure_root_dictionary(root, data_name, NULL);
    if (!data) {
        CEP_BOOT_FAIL("data dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.data = data;
    if (!CEP_RUNTIME.topology.data) {
        CEP_RUNTIME.topology.data = data;
    }
    if (!cep_cei_diagnostics_mailbox()) {
        CEP_BOOT_FAIL("cei diagnostics mailbox");
    }

    cepDT tmp_store = cep_organ_store_dt("tmp");
    const cepDT* tmp_name = dt_tmp_root_name();
    CEP_DEBUG_PRINTF("[bootstrap tmp] tmp_name=%p domain=%016llx tag=%016llx store=%016llx/%016llx\n",
            (void*)tmp_name,
            tmp_name ? (unsigned long long)cep_id(tmp_name->domain) : 0ull,
            tmp_name ? (unsigned long long)cep_id(tmp_name->tag) : 0ull,
            (unsigned long long)cep_id(tmp_store.domain),
            (unsigned long long)cep_id(tmp_store.tag));
    cepCell* tmp = ensure_root_list(root, tmp_name, &tmp_store);
    if (!tmp) {
        CEP_BOOT_FAIL("tmp list");
    }
    CEP_DEFAULT_TOPOLOGY.tmp = tmp;
    if (!CEP_RUNTIME.topology.tmp) {
        CEP_RUNTIME.topology.tmp = tmp;
    }

    cepDT enzymes_store = cep_organ_store_dt("enzymes");
    const cepDT* enzymes_name = dt_enzymes_root_name();
    cepCell* enzymes = ensure_root_dictionary(root, enzymes_name, &enzymes_store);
    if (!enzymes) {
        CEP_BOOT_FAIL("enzymes dictionary");
    }
    CEP_DEFAULT_TOPOLOGY.enzymes = enzymes;
    if (!CEP_RUNTIME.topology.enzymes) {
        CEP_RUNTIME.topology.enzymes = enzymes;
    }

    if (first_bootstrap) {
        cep_lifecycle_reload_state();
    }

    if (!cep_runtime_has_registry()) {
        CEP_RUNTIME.registry = cep_enzyme_registry_create();
        if (!CEP_RUNTIME.registry) {
            CEP_BOOT_FAIL("registry create");
        }
    }

    if (!cep_cell_operations_register(CEP_RUNTIME.registry)) {
        CEP_BOOT_FAIL("ops register");
    }

    if (!cep_organ_runtime_bootstrap()) {
        CEP_BOOT_FAIL("organ runtime bootstrap");
    }

    if (!cep_heartbeat_register_l0_organs()) {
        CEP_BOOT_FAIL("register l0 organs");
    }

    if (!cep_l0_organs_register(CEP_RUNTIME.registry)) {
        CEP_BOOT_FAIL("organs register");
    }

    if (!cep_l0_organs_bind_roots()) {
        CEP_BOOT_FAIL("bind roots");
    }

    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_KERNEL);
    success = true;

fail:
    CEP_RUNTIME.bootstrapping = false;
    if (!success && fail_reason) {
        CEP_DEBUG_PRINTF_STDOUT("[bootstrap] fail: %s\n", fail_reason);
        CEP_DEBUG_PRINTF("[bootstrap] fail: %s\n", fail_reason);
        fflush(stderr);
        fail_reason = NULL;
    }
#undef CEP_BOOT_FAIL
    return success;
}


/* Merges caller supplied topology and policy values with the defaults so the
 * runtime can respect overrides without losing the safety of fully initialised
 * fallback structures.
 */
/** Configure the heartbeat runtime before any directories are created so the
    engine knows which roots to mount and which policy knobs to honour. The
    function copies the user-provided topology/policy and primes the registry
    pointer for later bootstrap work. */
bool cep_heartbeat_configure(const cepHeartbeatTopology* topology, const cepHeartbeatPolicy* policy) {
    if (!policy) {
        return false;
    }

    if (!policy->boot_ops) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepHeartbeatTopology merged = CEP_DEFAULT_TOPOLOGY;
    if (topology) {
        if (topology->root)     merged.root     = topology->root;
        if (topology->sys)      merged.sys      = topology->sys;
        if (topology->rt)       merged.rt       = topology->rt;
        if (topology->journal)  merged.journal  = topology->journal;
        if (topology->env)      merged.env      = topology->env;
        if (topology->cas)      merged.cas      = topology->cas;
        if (topology->lib)      merged.lib      = topology->lib;
        if (topology->data)     merged.data     = topology->data;
        if (topology->tmp)      merged.tmp      = topology->tmp;
        if (topology->enzymes)  merged.enzymes  = topology->enzymes;
        if (topology->organs)   merged.organs   = topology->organs;
    }

    CEP_RUNTIME.topology = merged;
    CEP_RUNTIME.policy   = *policy;
    CEP_RUNTIME.policy.boot_ops = policy->boot_ops;
    if (CEP_RUNTIME.policy.spacing_window == 0u) {
        CEP_RUNTIME.policy.spacing_window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    }
    CEP_RUNTIME.spacing_window = CEP_RUNTIME.policy.spacing_window;
    return true;
}


/* Starts the heartbeat loop at the configured entry point so the scheduler can
 * begin advancing beats using the state prepared during configuration.
 */
/** Start the heartbeat loop after configuration, wiring the registry and
    resetting state so the first beat observes a clean slate. */
bool cep_heartbeat_startup(void) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.current = CEP_RUNTIME.policy.start_at;
    CEP_RUNTIME.running = true;
    CEP_RUNTIME.spacing_window = (CEP_RUNTIME.policy.spacing_window != 0u)
        ? CEP_RUNTIME.policy.spacing_window
        : CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    if (cep_boot_ops_enabled()) {
        (void)cep_boot_ops_start_boot();
    }
    cep_beat_begin_capture();
    if (!cep_boot_ops_progress()) {
        return false;
    }
    if (!cep_control_progress()) {
        return false;
    }
    return true;
}


/* Restarts execution by clearing per-run cells and resetting the beat counter
 * so a fresh cycle can reuse the existing topology without leaking data.
 */
/** Restart the heartbeat runtime without tearing down directories so callers
    can recover from transient failures while preserving topology. */
bool cep_heartbeat_restart(void) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cep_heartbeat_reset_runtime_cells();

    CEP_RUNTIME.current = CEP_RUNTIME.policy.start_at;
    CEP_RUNTIME.running = true;
    CEP_RUNTIME.spacing_window = (CEP_RUNTIME.policy.spacing_window != 0u)
        ? CEP_RUNTIME.policy.spacing_window
        : CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    if (cep_boot_ops_enabled()) {
        (void)cep_boot_ops_start_boot();
    }
    cep_beat_begin_capture();
    if (!cep_boot_ops_progress()) {
        return false;
    }
    if (!cep_control_progress()) {
        return false;
    }
    return true;
}


/* Forces the runtime to begin at an explicit beat to support manual recovery or
 * replay scenarios where the caller chooses the next cadence.
 */
/** Prepare runtime bookkeeping for the selected beat number so resolve and
    execution have fresh impulse queues and caches. */
bool cep_heartbeat_begin(cepBeatNumber beat) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.current = beat;
    CEP_RUNTIME.running = true;
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_current);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    if (cep_boot_ops_enabled()) {
        (void)cep_boot_ops_start_boot();
    }
    cep_beat_begin_capture();
    if (!cep_boot_ops_progress()) {
        return false;
    }
    if (!cep_control_progress()) {
        return false;
    }
    return true;
}


/* Resolves the agenda for the current beat by activating deferred enzyme
 * registrations and draining the impulse queue into deterministic execution order.
 */
/** Resolve the execution agenda for the current beat by draining the impulse queue,
    matching impulses, and building the ordered list of enzymes to run. */
bool cep_heartbeat_resolve_agenda(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    if (!cep_boot_ops_progress()) {
        return false;
    }
    if (!cep_control_progress()) {
        return false;
    }

    cep_beat_begin_compute();

    if (CEP_RUNTIME.registry) {
        cep_enzyme_registry_activate_pending(CEP_RUNTIME.registry);
    }

    return cep_heartbeat_process_impulses();
}


/* Executes the resolved agenda; for now it simply mirrors the running flag so
 * callers can already chain the step flow before real executors arrive.
 */
/** Execute the enzymes scheduled for this beat, short-circuiting on fatal
    errors while allowing retries to propagate to the agenda statistics. */
bool cep_heartbeat_execute_agenda(void) {
    // Enzyme callbacks run during cep_heartbeat_process_impulses(); keep this
    // shim in sync if we refactor execution into its own phase.
    return CEP_RUNTIME.running;
}


/* Commits staged work by rotating the impulse queues so signals emitted during
 * beat N become visible to the dispatcher at beat N+1.
 */
/** Stage committed writes so they become visible at the next beat boundary,
    flushing staged caches and journaling the results. */
bool cep_heartbeat_stage_commit(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    cep_beat_begin_commit();

    cep_executor_service();

    if (!cep_stream_commit_pending()) {
        CEP_DEBUG_PRINTF("[stage_commit] stream commit failed\n");
        fflush(stderr);
        return false;
    }

    if (cep_heartbeat_policy_use_dirs()) {
        size_t promoted = CEP_RUNTIME.impulses_next.count;
        const char* plural = (promoted == 1u) ? "" : "s";
        cepBeatNumber current = (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : CEP_RUNTIME.current;
        cepBeatNumber next = (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : CEP_RUNTIME.current + 1u;
        int written = snprintf(NULL, 0, "commit: promoted %zu impulse%s -> beat %" PRIu64,
                                promoted, plural, (uint64_t)next);
        if (written < 0) {
            CEP_DEBUG_PRINTF("[stage_commit] snprintf size failed\n");
            fflush(stderr);
            return false;
        }

        size_t size = (size_t)written + 1u;
        char* message = cep_malloc(size);
        if (!message) {
            CEP_DEBUG_PRINTF("[stage_commit] message alloc failed\n");
            fflush(stderr);
            return false;
        }

        snprintf(message, size, "commit: promoted %zu impulse%s -> beat %" PRIu64,
                 promoted, plural, (uint64_t)next);

        bool recorded = cep_heartbeat_record_stage_entry(current, message);
        cep_free(message);
        if (!recorded) {
            CEP_DEBUG_PRINTF("[stage_commit] record stage entry failed\n");
            fflush(stderr);
            return false;
        }
    }

    if (!cep_ops_stage_commit()) {
        CEP_DEBUG_PRINTF("[stage_commit] ops stage commit failed err=%d\n", cep_ops_debug_last_error());
        fflush(stderr);
        return false;
    }

    if (!cep_control_progress()) {
        CEP_DEBUG_PRINTF("[stage_commit] control progress failed\n");
        fflush(stderr);
        return false;
    }

    cep_executor_service();

    if (CEP_RUNTIME.current != CEP_BEAT_INVALID) {
        cepOpCount stamp = cep_cell_timestamp();
        if (!cep_heartbeat_record_op_stamp(CEP_RUNTIME.current, stamp)) {
            CEP_DEBUG_PRINTF("[stage_commit] record op stamp failed\n");
            fflush(stderr);
            return false;
        }
    }

    cep_heartbeat_impulse_queue_swap(&CEP_RUNTIME.impulses_current, &CEP_RUNTIME.impulses_next);
    cep_heartbeat_impulse_queue_reset(&CEP_RUNTIME.impulses_next);
    cep_beat_begin_capture();
    return true;
}


/** Publish the beat index without exposing the runtime structure so callers can
    tag journal entries or error messages with a stable counter. During
    bootstrap the heartbeat number is undefined, therefore the helper reports
    zero until the scheduler advances at least once. */
cepOpCount cep_beat_index(void) {
    return (CEP_RUNTIME.current == CEP_BEAT_INVALID) ? 0u : (cepOpCount)CEP_RUNTIME.current;
}


/** Report which heartbeat phase is currently active so Layer 0 services can
    gate actions (for example, ingest vs. compute mutations) without tracking
    scheduler calls manually. The value reflects the most recent *_begin_* hook
    that ran. */
cepBeatPhase cep_beat_phase(void) {
    return CEP_RUNTIME.phase;
}


/** Surface how many enzyme registrations were deferred into this beat so tests
    and diagnostics can assert the agenda freeze contract stays intact during
    mid-cycle registrations. The value resets when the next Capture phase
    begins. */
size_t cep_beat_deferred_activation_count(void) {
    return CEP_RUNTIME.deferred_activations;
}


/** Accumulate the number of enzymes promoted out of the pending queue so the
    debug counter reflects mid-beat registrations that will only execute on the
    next cycle. Callers pass zero when nothing was promoted to avoid touching the
    counter unnecessarily. */
void cep_beat_note_deferred_activation(size_t count) {
    if (!count) {
        return;
    }

    CEP_RUNTIME.deferred_activations += count;
}


/** Mark the beginning of the capture phase so ingestion helpers can freeze
    inputs deterministically. The helper also clears the deferred activation
    counter because a fresh beat will tally its own promotions. */
void cep_beat_begin_capture(void) {
    CEP_RUNTIME.phase = CEP_BEAT_CAPTURE;
    CEP_RUNTIME.deferred_activations = 0u;
    CEP_CONTROL_STATE.agenda_noted = false;
}


/** Switch the runtime into the compute phase so enzyme resolution and
    execution can proceed while asserts keep an eye on phase transitions. */
void cep_beat_begin_compute(void) {
    CEP_RUNTIME.phase = CEP_BEAT_COMPUTE;
}


/** Enter the commit phase so staging helpers can flush writes and diagnostics
    can confirm that agenda execution reached the last step for the beat. */
void cep_beat_begin_commit(void) {
    CEP_RUNTIME.phase = CEP_BEAT_COMMIT;
}


/* Drives a full beat by cascading resolve, execute, and commit stages and bumps
 * the counter when everything succeeds so the loop progresses deterministically.
 */
/** Convenience helper that performs resolve, execute, and stage for a single
    beat, returning false if any phase fails. */
bool cep_heartbeat_step(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    bool ok = cep_heartbeat_resolve_agenda();
    if (!ok) {
        CEP_DEBUG_PRINTF("[heartbeat_step] resolve agenda failed\n");
        fflush(stderr);
        return false;
    }

    ok = cep_heartbeat_execute_agenda();
    if (!ok) {
        CEP_DEBUG_PRINTF("[heartbeat_step] execute agenda failed\n");
        fflush(stderr);
        return false;
    }

    ok = cep_heartbeat_stage_commit();
    if (!ok) {
        CEP_DEBUG_PRINTF("[heartbeat_step] stage commit failed\n");
        fflush(stderr);
        return false;
    }

    if (ok && CEP_RUNTIME.current != CEP_BEAT_INVALID) {
        CEP_RUNTIME.current += 1u;
    }

    return ok;
}


bool cep_heartbeat_emit_shutdown(void) {
    if (CEP_RUNTIME.sys_shutdown_emitted) {
        return true;
    }

    if (!cep_runtime_has_registry()) {
        CEP_RUNTIME.sys_shutdown_emitted = true;
        return true;
    }

    if (!CEP_RUNTIME.running) {
        return false;
    }

    bool ok = cep_boot_ops_start_shutdown();

    for (size_t i = 0; i < cep_lengthof(CEP_LIFECYCLE_TEARDOWN_ORDER); ++i) {
        ok = cep_lifecycle_scope_mark_teardown(CEP_LIFECYCLE_TEARDOWN_ORDER[i]) && ok;
    }

    ok = cep_boot_ops_progress() && ok;
    ok = ok && !CEP_LIFECYCLE_OPS_STATE.shdn_failed;

    if (ok) {
        CEP_RUNTIME.sys_shutdown_emitted = true;
    }
    return ok;
}

/** Stop the heartbeat runtime and release scratch buffers so subsequent
    start-ups begin from a clean state. */
void cep_heartbeat_shutdown(void) {
    (void)cep_heartbeat_emit_shutdown();

    cep_runtime_reset_state(true);
    cep_runtime_reset_defaults();
    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
}


/** Drain the in-memory impulse queue and move entries into the agenda cache so
    resolve and execute phases operate on stable snapshots. */
bool cep_heartbeat_process_impulses(void) {
    if (!CEP_RUNTIME.running) {
        return false;
    }

    cepEnzymeRegistry* registry = CEP_RUNTIME.registry;
    size_t registry_size = registry ? cep_enzyme_registry_size(registry) : 0u;
    cepHeartbeatScratch* scratch = &CEP_RUNTIME.scratch;

    if (registry_size > 0u) {
        if (!cep_heartbeat_scratch_ensure_ordered(scratch, registry_size)) {
            CEP_DEBUG_PRINTF("[process_impulses] ensure ordered failed registry_size=%zu\n", registry_size);
            fflush(stderr);
            return false;
        }
    }

    cepHeartbeatImpulseQueue* queue = &CEP_RUNTIME.impulses_current;
    size_t impulse_count = queue->count;

    if (CEP_CONTROL_STATE.gating_active && !CEP_CONTROL_STATE.agenda_noted) {
        (void)cep_heartbeat_stage_note("paused agenda (control-only)");
        CEP_CONTROL_STATE.agenda_noted = true;
    }

    if (impulse_count == 0u) {
        cep_heartbeat_scratch_next_generation(scratch);
        cep_heartbeat_dispatch_cache_cleanup_generation(scratch);
        return true;
    }

    size_t desired_slots = impulse_count * 2u;
    if (desired_slots < 8u) {
        desired_slots = 8u;
    }
    size_t reserve = cep_next_pow_of_two(desired_slots);
    if (!cep_heartbeat_dispatch_cache_reserve(scratch, reserve)) {
        CEP_DEBUG_PRINTF("[process_impulses] dispatch reserve failed reserve=%zu\n", reserve);
        fflush(stderr);
        return false;
    }

    cep_heartbeat_scratch_next_generation(scratch);

    bool ok = true;

    for (size_t i = 0; i < impulse_count && ok; ++i) {
        cepHeartbeatImpulseRecord* record = &queue->records[i];
        cepImpulse impulse = {
            .signal_path = record->signal_path,
            .target_path = record->target_path,
            .qos = record->qos,
        };

        if (cep_control_should_gate(&impulse)) {
            if (!cep_control_backlog_store(&impulse)) {
                CEP_DEBUG_PRINTF("[process_impulses] backlog store failed\n");
                fflush(stderr);
                ok = false;
            }
            char* signal_text = cep_heartbeat_path_to_string(impulse.signal_path);
            char* target_text = cep_heartbeat_path_to_string(impulse.target_path);
            if (signal_text && target_text) {
                char message[256];
                snprintf(message, sizeof message, "pause: parked signal=%s target=%s qos=%u",
                         signal_text,
                         target_text,
                         (unsigned)impulse.qos);
                (void)cep_heartbeat_stage_note(message);
            }
            cep_free(signal_text);
            cep_free(target_text);
            cep_heartbeat_impulse_record_clear(record);
            continue;
        }

        bool fresh = false;
        uint64_t hash = cep_heartbeat_impulse_hash(record);
        cepHeartbeatDispatchCacheEntry* entry = cep_heartbeat_dispatch_cache_acquire(scratch, record, hash, &fresh);
        if (!entry) {
            CEP_DEBUG_PRINTF("[process_impulses] dispatch entry acquire failed\n");
            fflush(stderr);
            ok = false;
            break;
        }

        if (fresh) {
            size_t resolved = 0u;
            if (registry && registry_size > 0u) {
                resolved = cep_enzyme_resolve(registry, &impulse, scratch->ordered, scratch->ordered_capacity);
                char* dbg_signal = cep_heartbeat_path_to_string(impulse.signal_path);
                CEP_DEBUG_PRINTF("[prr] process_impulses resolved=%zu signal=%s qos=%u gating=%d paused=%d\n",
                                 resolved,
                                 dbg_signal ? dbg_signal : "<null>",
                                 (unsigned)impulse.qos,
                                 CEP_CONTROL_STATE.gating_active ? 1 : 0,
                                 CEP_RUNTIME.paused ? 1 : 0);
                cep_free(dbg_signal);
            }

            if (resolved > 0u) {
                if (entry->descriptor_capacity < resolved) {
                    size_t bytes = resolved * sizeof(*entry->descriptors);
                    const cepEnzymeDescriptor** buffer = entry->descriptors ?
                        cep_realloc(entry->descriptors, bytes) :
                        cep_malloc(bytes);
                    if (!buffer) {
                        ok = false;
                        break;
                    }
                    entry->descriptors = buffer;
                    entry->descriptor_capacity = resolved;
                }

                if (!cep_heartbeat_dispatch_entry_reserve_memo(entry, resolved)) {
                    CEP_DEBUG_PRINTF("[process_impulses] memo reserve failed resolved=%zu\n", resolved);
                    fflush(stderr);
                    ok = false;
                    break;
                }

                memcpy(entry->descriptors, scratch->ordered, resolved * sizeof(*scratch->ordered));
                memset(entry->memo, 0, resolved * sizeof(*entry->memo));
                entry->memo_count = resolved;
            } else {
                entry->memo_count = 0u;
            }
            entry->descriptor_count = resolved;
        } else if (entry->descriptor_count > entry->memo_count) {
            size_t previous = entry->memo_count;
            if (!cep_heartbeat_dispatch_entry_reserve_memo(entry, entry->descriptor_count)) {
                CEP_DEBUG_PRINTF("[process_impulses] memo reserve expansion failed count=%zu\n", entry->descriptor_count);
                fflush(stderr);
                ok = false;
                break;
            }
            memset(entry->memo + previous, 0, (entry->descriptor_count - previous) * sizeof(*entry->memo));
            entry->memo_count = entry->descriptor_count;
        }

        if (!ok) {
            break;
        }

        if (entry->descriptor_count == 0u && cep_heartbeat_policy_use_dirs()) {
            ok = cep_heartbeat_record_agenda_entry(CEP_RUNTIME.current, NULL, CEP_ENZYME_SUCCESS, &impulse);
            if (!ok) {
                CEP_DEBUG_PRINTF("[process_impulses] record agenda entry failed (no-match)\n");
                fflush(stderr);
            }
        }

        if (entry->descriptor_count > 0u && entry->descriptors) {
            cepHeartbeatDescriptorMemo* memo_array = entry->memo;
            for (size_t j = 0; j < entry->descriptor_count && ok; ++j) {
                const cepEnzymeDescriptor* descriptor = entry->descriptors[j];
                if (!descriptor || !descriptor->callback) {
                    continue;
                }

                cepHeartbeatDescriptorMemo* memo = (memo_array && j < entry->memo_count) ? &memo_array[j] : NULL;
                bool executed_before = memo && memo->executed;
                bool should_run = true;
                unsigned flags = descriptor->flags;

                if (executed_before && should_run) {
                    if (flags & CEP_ENZYME_FLAG_STATEFUL) {
                        should_run = false;
                    }
                    if (should_run && (flags & CEP_ENZYME_FLAG_EMIT_SIGNALS) && memo->emitted) {
                        should_run = false;
                    }
                    if (should_run && (flags & CEP_ENZYME_FLAG_IDEMPOTENT) && memo->last_rc == CEP_ENZYME_SUCCESS) {
                        should_run = false;
                    }
                }

                if (!should_run) {
                    if (cep_heartbeat_policy_use_dirs()) {
                        int rc_log = memo ? memo->last_rc : CEP_ENZYME_SUCCESS;
                    if (!cep_heartbeat_record_agenda_entry(CEP_RUNTIME.current, descriptor, rc_log, &impulse)) {
                        CEP_DEBUG_PRINTF("[process_impulses] record agenda entry failed (skip)\n");
                        fflush(stderr);
                        ok = false;
                        break;
                    }
                    }
                    continue;
                }

                CEP_RUNTIME.current_descriptor = descriptor;
                size_t before_signals = CEP_RUNTIME.impulses_next.count;
                int rc = descriptor->callback(impulse.signal_path, impulse.target_path);
                CEP_RUNTIME.current_descriptor = NULL;
                CEP_DEBUG_PRINTF("DEBUG heartbeat: descriptor %llu:%llu callback=%p rc=%d\n",
                        (unsigned long long)descriptor->name.domain,
                        (unsigned long long)descriptor->name.tag,
                        (void*)descriptor->callback,
                        rc);
                size_t after_signals = CEP_RUNTIME.impulses_next.count;
                bool emitted = after_signals > before_signals;

                if (memo) {
                    memo->executed = 1u;
                    memo->last_rc = rc;
                    if (emitted) {
                        memo->emitted = 1u;
                    }
                }

                if (cep_heartbeat_policy_use_dirs()) {
                    if (!cep_heartbeat_record_agenda_entry(CEP_RUNTIME.current, descriptor, rc, &impulse)) {
                        CEP_DEBUG_PRINTF("[process_impulses] record agenda entry failed rc=%d\n", rc);
                        ok = false;
                        break;
                    }
                }
                if (rc == CEP_ENZYME_FATAL) {
#if defined(CEP_ENABLE_DEBUG)
                    char fatal_label[64];
                    const char* fatal_name = cep_heartbeat_descriptor_label(descriptor, fatal_label, sizeof fatal_label);
                    CEP_DEBUG_PRINTF("[process_impulses] descriptor fatal rc label=%s\n",
                                     fatal_name ? fatal_name : "<null>");
#endif
                    ok = false;
                    break;
                }

                if (rc == CEP_ENZYME_RETRY) {
                    if (!cep_heartbeat_impulse_queue_append(&CEP_RUNTIME.impulses_next, &impulse)) {
                        ok = false;
                        break;
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < impulse_count; ++i) {
        cep_heartbeat_impulse_record_clear(&queue->records[i]);
    }
    queue->count = 0u;

    cep_heartbeat_dispatch_cache_cleanup_generation(scratch);

    /* TODO: Feed this resolver cache with real-time stats—e.g. track miss ratios,
     * impulse uniqueness, and registry churn—to adapt cache sizes, fall back to
     * direct dispatch when reuse is low, or pre-populate hot pairs before the beat.
     * */
     
    return ok;
}


bool cep_heartbeat_publish_wallclock(cepBeatNumber beat, uint64_t unix_timestamp_ns) {
    if (beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return false;
    }

    cepCell* beat_root = ensure_root_dictionary(rt_root, dt_beat_root_name(), NULL);
    if (!beat_root) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_dictionary_child(beat_root, &beat_name, NULL);
    if (!beat_cell) {
        return false;
    }

    cepCell* meta = cep_heartbeat_ensure_meta_child(beat_cell);
    if (!meta) {
        return false;
    }

    cepCell* existing = cep_cell_find_by_name(meta, dt_unix_ts_name());
    if (existing) {
        existing = cep_cell_resolve(existing);
    }
    if (existing && cep_cell_has_data(existing)) {
        const char* stored_text = (const char*)cep_cell_data(existing);
        if (stored_text) {
            char* endptr = NULL;
            uint64_t parsed = strtoull(stored_text, &endptr, 10);
            if (endptr && *endptr == '\0' && parsed == unix_timestamp_ns) {
                return true;
            }
        }
        return false;
    }

    if (!cep_cell_put_uint64(meta, dt_unix_ts_name(), unix_timestamp_ns)) {
        return false;
    }

    if (CEP_RUNTIME.last_wallclock_beat != CEP_BEAT_INVALID &&
        beat > CEP_RUNTIME.last_wallclock_beat) {
        uint64_t interval = (unix_timestamp_ns >= CEP_RUNTIME.last_wallclock_ns)
            ? (unix_timestamp_ns - CEP_RUNTIME.last_wallclock_ns)
            : 0u;
        if (!cep_heartbeat_record_spacing(beat, interval)) {
            return false;
        }
    }

    if (CEP_RUNTIME.last_wallclock_beat == CEP_BEAT_INVALID ||
        beat >= CEP_RUNTIME.last_wallclock_beat) {
        CEP_RUNTIME.last_wallclock_beat = beat;
        CEP_RUNTIME.last_wallclock_ns = unix_timestamp_ns;
    }

    return true;
}


bool cep_heartbeat_beat_to_unix(cepBeatNumber beat, uint64_t* unix_timestamp_ns) {
    if (!unix_timestamp_ns || beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (!cep_cell_system_initialized()) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root || cep_cell_is_void(rt_root)) {
        return false;
    }

    cepCell* beat_root = cep_cell_find_by_name(rt_root, dt_beat_root_name());
    if (!beat_root || cep_cell_is_void(beat_root)) {
        return false;
    }

    cepCell* resolved_root = cep_cell_resolve(beat_root);
    if (!resolved_root || cep_cell_is_void(resolved_root) || !resolved_root->store) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* beat_cell = cep_cell_find_by_name(resolved_root, &beat_name);
    if (!beat_cell) {
        beat_cell = cep_cell_find_by_name_all(resolved_root, &beat_name);
    }
    if (!beat_cell || cep_cell_is_void(beat_cell)) {
        return false;
    }

    beat_cell = cep_cell_resolve(beat_cell);
    if (!beat_cell || cep_cell_is_void(beat_cell)) {
        return false;
    }

    cepCell* meta = cep_cell_find_by_name(beat_cell, dt_meta_name());
    if (!meta) {
        meta = cep_cell_find_by_name_all(beat_cell, dt_meta_name());
    }
    if (!meta || cep_cell_is_void(meta)) {
        return false;
    }

    meta = cep_cell_resolve(meta);
    if (!meta || cep_cell_is_void(meta)) {
        return false;
    }

    cepCell* timestamp = cep_cell_find_by_name(meta, dt_unix_ts_name());
    if (!timestamp || cep_cell_is_void(timestamp)) {
        return false;
    }

    timestamp = cep_cell_resolve(timestamp);
    if (!timestamp || !cep_cell_has_data(timestamp)) {
        return false;
    }

    const char* stored_text = (const char*)cep_cell_data(timestamp);
    if (!stored_text) {
        return false;
    }

    char* endptr = NULL;
    uint64_t parsed = (uint64_t)strtoull(stored_text, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }

    *unix_timestamp_ns = parsed;
    return true;
}

static bool cep_heartbeat_record_op_stamp(cepBeatNumber beat, cepOpCount stamp) {
    if (beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return false;
    }

    cepCell* beat_root = ensure_root_dictionary(rt_root, dt_beat_root_name(), NULL);
    if (!beat_root) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* beat_cell = cep_heartbeat_ensure_dictionary_child(beat_root, &beat_name, NULL);
    if (!beat_cell) {
        return false;
    }

    cepCell* meta = cep_heartbeat_ensure_meta_child(beat_cell);
    if (!meta) {
        return false;
    }

    cepCell* runtime = cep_cell_ensure_dictionary_child(meta, dt_runtime_name(), CEP_STORAGE_RED_BLACK_T);
    if (!runtime) {
        return false;
    }

    cepDT stamp_field = cep_dt_clean(dt_op_stamp_name());
    cepCell* existing = cep_cell_find_by_name(runtime, &stamp_field);
    if (existing) {
        existing = cep_cell_resolve(existing);
        if (existing && cep_cell_has_data(existing)) {
            const char* stored_text = (const char*)cep_cell_data(existing);
            if (stored_text) {
                char* endptr = NULL;
                uint64_t parsed = strtoull(stored_text, &endptr, 10);
                if (endptr && *endptr == '\0' && parsed == (uint64_t)stamp) {
                    return true;
                }
            }
        }
    }

    return cep_cell_put_uint64(runtime, dt_op_stamp_name(), (uint64_t)stamp);
}

static bool cep_heartbeat_beat_to_op_stamp(cepBeatNumber beat, cepOpCount* stamp_out) {
    if (!stamp_out || beat == CEP_BEAT_INVALID) {
        return false;
    }

    if (!cep_cell_system_initialized()) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root || cep_cell_is_void(rt_root)) {
        return false;
    }

    cepCell* beat_root = cep_cell_find_by_name(rt_root, dt_beat_root_name());
    if (!beat_root || cep_cell_is_void(beat_root)) {
        return false;
    }

    cepCell* resolved_root = cep_cell_resolve(beat_root);
    if (!resolved_root || cep_cell_is_void(resolved_root) || !resolved_root->store) {
        return false;
    }

    cepDT beat_name;
    if (!cep_heartbeat_set_numeric_name(&beat_name, beat)) {
        return false;
    }

    cepCell* beat_cell = cep_cell_find_by_name(resolved_root, &beat_name);
    if (!beat_cell || cep_cell_is_void(beat_cell)) {
        return false;
    }

    beat_cell = cep_cell_resolve(beat_cell);
    if (!beat_cell || cep_cell_is_void(beat_cell)) {
        return false;
    }

    cepCell* meta = cep_cell_find_by_name(beat_cell, dt_meta_name());
    if (!meta || cep_cell_is_void(meta)) {
        return false;
    }

    meta = cep_cell_resolve(meta);
    if (!meta || cep_cell_is_void(meta)) {
        return false;
    }

    cepCell* runtime = cep_cell_find_by_name(meta, dt_runtime_name());
    if (!runtime) {
        runtime = cep_cell_find_by_name_all(meta, dt_runtime_name());
    }
    if (!runtime || cep_cell_is_void(runtime)) {
        return false;
    }

    runtime = cep_cell_resolve(runtime);
    if (!runtime || cep_cell_is_void(runtime)) {
        return false;
    }

    cepCell* stamp_cell = cep_cell_find_by_name(runtime, dt_op_stamp_name());
    if (!stamp_cell) {
        stamp_cell = cep_cell_find_by_name_all(runtime, dt_op_stamp_name());
    }
    if (!stamp_cell || cep_cell_is_void(stamp_cell)) {
        return false;
    }

    stamp_cell = cep_cell_resolve(stamp_cell);
    if (!stamp_cell || !cep_cell_has_data(stamp_cell)) {
        return false;
    }

    const char* stored_text = (const char*)cep_cell_data(stamp_cell);
    if (!stored_text) {
        return false;
    }

    char* endptr = NULL;
    uint64_t parsed = strtoull(stored_text, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }

    *stamp_out = (cepOpCount)parsed;
    return true;
}


size_t cep_heartbeat_get_spacing_window(void) {
    size_t window = CEP_RUNTIME.spacing_window;
    if (window == 0u) {
        window = CEP_RUNTIME.policy.spacing_window;
    }
    if (window == 0u) {
        window = CEP_HEARTBEAT_SPACING_WINDOW_DEFAULT;
    }
    return window;
}


bool cep_heartbeat_set_spacing_window(size_t window) {
    if (window == 0u) {
        return false;
    }

    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    CEP_RUNTIME.spacing_window = window;
    CEP_RUNTIME.policy.spacing_window = window;

    cepCell* rt_root = cep_heartbeat_rt_root();
    if (!rt_root) {
        return true;
    }

    cepCell* analytics_root = cep_cell_find_by_name(rt_root, dt_analytics_root_name());
    if (!analytics_root) {
        return true;
    }
    analytics_root = cep_cell_resolve(analytics_root);
    if (!analytics_root) {
        return false;
    }

    cepCell* spacing = cep_cell_find_by_name(analytics_root, dt_spacing_name());
    if (!spacing) {
        return true;
    }
    spacing = cep_cell_resolve(spacing);
    if (!spacing) {
        return false;
    }

    cep_heartbeat_prune_spacing(spacing);
    return true;
}


/** Expose the currently active beat so observers can align their work with the
    scheduler state. */
cepBeatNumber cep_heartbeat_current(void) {
    return CEP_RUNTIME.current;
}


/** Compute the next beat index while guarding against the invalid sentinel so
    callers never advance past an uninitialised state. */
cepBeatNumber cep_heartbeat_next(void) {
    if (CEP_RUNTIME.current == CEP_BEAT_INVALID) {
        return CEP_BEAT_INVALID;
    }

    return CEP_RUNTIME.current + 1u;
}


/** Return a pointer to the current policy so readers can inspect timing rules
    without taking ownership of the underlying storage. */
const cepHeartbeatPolicy* cep_heartbeat_policy(void) {
    return &CEP_RUNTIME.policy;
}


/** Return the active topology structure so clients can access shared roots the
    runtime prepared during bootstrap. */
const cepHeartbeatTopology* cep_heartbeat_topology(void) {
    return &CEP_RUNTIME.topology;
}


/** Ensure the runtime is initialised and expose the shared enzyme registry so
    listeners can register dispatchers without duplicating bootstrap checks. */
cepEnzymeRegistry* cep_heartbeat_registry(void) {
    if (!cep_heartbeat_bootstrap()) {
        return NULL;
    }
    return CEP_RUNTIME.registry;
}


/** Queue a signal/target pair to be processed on the requested beat, cloning
    the paths so callers can reuse their buffers immediately. */
int cep_heartbeat_enqueue_signal(cepBeatNumber beat, const cepPath* signal_path, const cepPath* target_path) {
    cepImpulse impulse = {
        .signal_path = signal_path,
        .target_path = target_path,
        .qos = CEP_IMPULSE_QOS_RETAIN_ON_PAUSE,
    };

    return cep_heartbeat_enqueue_impulse(beat, &impulse);
}


/** Queue a fully materialised impulse that already contains cloned paths,
    keeping the internal impulse queue layout consistent with the signal helper. */
int cep_heartbeat_enqueue_impulse(cepBeatNumber beat, const cepImpulse* impulse) {
    if (!cep_heartbeat_bootstrap()) {
        CEP_DEBUG_PRINTF("[enqueue_impulse] bootstrap failed\n");
        fflush(stderr);
        return CEP_ENZYME_FATAL;
    }

    if (!impulse || (!impulse->signal_path && !impulse->target_path)) {
        CEP_DEBUG_PRINTF("[enqueue_impulse] invalid impulse\n");
        fflush(stderr);
        return CEP_ENZYME_FATAL;
    }

    cepImpulse normalized = *impulse;
    if ((normalized.qos & (CEP_IMPULSE_QOS_CONTROL | CEP_IMPULSE_QOS_RETAIN_ON_PAUSE | CEP_IMPULSE_QOS_DISCARD_ON_ROLLBACK)) == 0u) {
        normalized.qos |= CEP_IMPULSE_QOS_RETAIN_ON_PAUSE;
    }
    impulse = &normalized;

    if (cep_control_should_gate(impulse)) {
        if (!cep_control_backlog_store(impulse)) {
            CEP_DEBUG_PRINTF("[enqueue_impulse] backlog store failed\n");
            fflush(stderr);
            return CEP_ENZYME_FATAL;
        }
        char* signal_text = cep_heartbeat_path_to_string(impulse->signal_path);
        char* target_text = cep_heartbeat_path_to_string(impulse->target_path);
        if (signal_text && target_text) {
            char message[256];
            snprintf(message, sizeof message, "pause: parked signal=%s target=%s qos=%u",
                     signal_text,
                     target_text,
                     (unsigned)impulse->qos);
            (void)cep_heartbeat_stage_note(message);
        }
        cep_free(signal_text);
        cep_free(target_text);
        return CEP_ENZYME_SUCCESS;
    }

    cepBeatNumber record_beat = beat;
    if (record_beat == CEP_BEAT_INVALID) {
        record_beat = cep_heartbeat_next();
        if (record_beat == CEP_BEAT_INVALID) {
            record_beat = 0u;
        }
    }

    if (cep_heartbeat_policy_use_dirs() && record_beat != CEP_BEAT_INVALID) {
        if (!cep_heartbeat_ensure_beat_node(record_beat)) {
            CEP_DEBUG_PRINTF("[enqueue_impulse] ensure beat node failed beat=%llu\n", (unsigned long long)record_beat);
            fflush(stderr);
            return CEP_ENZYME_FATAL;
        }
    }

    if (!cep_heartbeat_impulse_queue_append(&CEP_RUNTIME.impulses_next, impulse)) {
        CEP_DEBUG_PRINTF("[enqueue_impulse] queue append failed\n");
        fflush(stderr);
        return CEP_ENZYME_FATAL;
    }

    if (cep_heartbeat_policy_use_dirs() && record_beat != CEP_BEAT_INVALID) {
        if (!cep_heartbeat_record_impulse_entry(record_beat, impulse)) {
            CEP_DEBUG_PRINTF("[enqueue_impulse] record impulse entry failed\n");
            fflush(stderr);
            return CEP_ENZYME_FATAL;
        }
    }

    return CEP_ENZYME_SUCCESS;
}


/* Provides the root cell for the sys namespace so integrations can attach
 * system-level state without digging through runtime internals.
 */
/** Return the root cell of the system subtree defined in the configured
    topology. */
cepCell* cep_heartbeat_sys_root(void) {
    return CEP_RUNTIME.topology.sys;
}


/* Shares the runtime root cell to support modules that need direct access to
 * transient execution state.
 */
/** Return the runtime staging subtree root prepared during bootstrap. */
cepCell* cep_heartbeat_rt_root(void) {
    return CEP_RUNTIME.topology.rt;
}


/* Returns the journal root so persistence helpers can append entries in the
 * same tree the scheduler maintains.
 */
/** Return the journal subtree used to persist heartbeat logs. */
cepCell* cep_heartbeat_journal_root(void) {
    return CEP_RUNTIME.topology.journal;
}


/* Supplies the environment root cell so configuration loaders can coordinate on
 * a single namespace.
 */
/** Return the environment subtree that exposes external resources. */
cepCell* cep_heartbeat_env_root(void) {
    return CEP_RUNTIME.topology.env;
}


/* Exposes the data root so consumers can store long-lived datasets alongside
 * the runtime without guessing the internal layout.
 */
/** Return the durable data subtree that holds committed facts. */
cepCell* cep_heartbeat_data_root(void) {
    return CEP_RUNTIME.topology.data;
}


/* Returns the content-addressable storage root to let utilities share cached
 * assets with the engine-provided store.
 */
/** Return the CAS subtree storing opaque blobs by content hash. */
cepCell* cep_heartbeat_cas_root(void) {
    return CEP_RUNTIME.topology.cas;
}


/* Provides the temporary root so callers can manage short-lived buffers in the
 * same compartment the runtime clears between runs.
 */
/** Return the temporary workspace subtree used for scratch cells. */
cepCell* cep_heartbeat_tmp_root(void) {
    return CEP_RUNTIME.topology.tmp;
}

bool cep_runtime_pause(void) {
    if (!cep_heartbeat_bootstrap()) {
        return false;
    }

    if (CEP_CONTROL_STATE.pause.started && CEP_CONTROL_STATE.pause.closed && CEP_RUNTIME.paused) {
        return true;
    }

    if (CEP_CONTROL_STATE.pause.started && CEP_CONTROL_STATE.pause.closed) {
        cep_control_op_clear(&CEP_CONTROL_STATE.pause);
    }

    if (CEP_CONTROL_STATE.pause.started && !CEP_CONTROL_STATE.pause.failed) {
        return true;
    }

    if (CEP_CONTROL_STATE.resume.started && !CEP_CONTROL_STATE.resume.closed) {
        return false;
    }

    return cep_control_start_pause();
}

bool cep_runtime_resume(void) {
    bool result = false;

    if (!cep_heartbeat_bootstrap()) {
        goto exit;
    }
cep_control_debug_snapshot("runtime_resume-enter", &CEP_CONTROL_STATE.resume, 0);

    if (CEP_CONTROL_STATE.cleanup_pending &&
        !CEP_CONTROL_STATE.resume.started &&
        !CEP_RUNTIME.paused &&
        !CEP_CONTROL_STATE.gating_active) {
        if (!cep_dt_is_valid(&CEP_CONTROL_STATE.resume.verb_dt)) {
            CEP_CONTROL_STATE.resume.verb_dt = cep_ops_make_dt("op/resume");
        }
        cep_control_emit_guard_cei(&CEP_CONTROL_STATE.resume, "cleanup pending");
        result = false;
        goto exit;
    }

    if (CEP_CONTROL_STATE.resume.started && CEP_CONTROL_STATE.resume.closed && !CEP_RUNTIME.paused && !CEP_CONTROL_STATE.gating_active) {
        result = true;
        goto exit;
    }

    if (CEP_CONTROL_STATE.resume.started && CEP_CONTROL_STATE.resume.closed) {
        cep_control_op_clear(&CEP_CONTROL_STATE.resume);
    }

    if (!CEP_RUNTIME.paused && !CEP_CONTROL_STATE.gating_active) {
        result = true;
        goto exit;
    }

    if (CEP_CONTROL_STATE.resume.started && !CEP_CONTROL_STATE.resume.failed) {
        result = true;
        goto exit;
    }

    if (!CEP_CONTROL_STATE.pause.started || !CEP_CONTROL_STATE.pause.closed) {
        result = false;
        goto exit;
    }

    result = cep_control_start_resume();

exit:
cep_control_debug_snapshot("runtime_resume-exit", &CEP_CONTROL_STATE.resume, result ? 1 : 0);
    return result;
}

bool cep_runtime_rollback(cepBeatNumber to) {
    bool result = false;

    if (!cep_heartbeat_bootstrap()) {
        goto exit;
    }
cep_control_debug_snapshot("runtime_rollback-enter", &CEP_CONTROL_STATE.rollback, 0);

    if (CEP_CONTROL_STATE.rollback.started && CEP_CONTROL_STATE.rollback.closed) {
        cep_control_op_clear(&CEP_CONTROL_STATE.rollback);
    }

    if (CEP_CONTROL_STATE.cleanup_pending) {
        if (!cep_dt_is_valid(&CEP_CONTROL_STATE.rollback.verb_dt)) {
            CEP_CONTROL_STATE.rollback.verb_dt = cep_ops_make_dt("op/rollback");
        }
        cep_control_emit_guard_cei(&CEP_CONTROL_STATE.rollback, "cleanup pending");
        if (CEP_CONTROL_STATE.rollback.started && cep_oid_is_valid(CEP_CONTROL_STATE.rollback.oid)) {
            char info[160];
            if (cep_op_get(CEP_CONTROL_STATE.rollback.oid, info, sizeof info)) {
                CEP_DEBUG_PRINTF("[prr] rollback guard cleanup_pending oid=%llu:%llu info=\"%s\"\n",
                                 (unsigned long long)CEP_CONTROL_STATE.rollback.oid.domain,
                                 (unsigned long long)CEP_CONTROL_STATE.rollback.oid.tag,
                                 info);
            }
        }
        result = false;
        goto exit;
    }

    if (!CEP_RUNTIME.paused && !CEP_CONTROL_STATE.gating_active) {
result = false;
        goto exit;
    }

    if (CEP_CONTROL_STATE.rollback.started && !CEP_CONTROL_STATE.rollback.failed) {
        CEP_CONTROL_STATE.rollback_target = to;
        result = true;
        goto exit;
    }

    if (CEP_CONTROL_STATE.resume.started && !CEP_CONTROL_STATE.resume.closed) {
result = false;
        goto exit;
    }

    result = cep_control_start_rollback(to);
    CEP_DEBUG_PRINTF("[prr] start_rollback result=%d started=%d closed=%d\n",
                     result ? 1 : 0,
                     CEP_CONTROL_STATE.rollback.started ? 1 : 0,
                     CEP_CONTROL_STATE.rollback.closed ? 1 : 0);

exit:
cep_control_debug_snapshot("runtime_rollback-exit", &CEP_CONTROL_STATE.rollback, result ? 1 : 0);
    return result;
}

bool cep_runtime_is_paused(void) {
    return CEP_RUNTIME.paused || CEP_CONTROL_STATE.gating_active;
}

cepBeatNumber cep_runtime_view_horizon(void) {
    return CEP_RUNTIME.view_horizon;
}

cepOpCount cep_runtime_view_horizon_stamp(void) {
    cepOpCount stamp = CEP_RUNTIME.view_horizon_stamp;
    if (stamp) {
        return stamp;
    }

    cepBeatNumber horizon = CEP_RUNTIME.view_horizon;
    if (horizon == CEP_BEAT_INVALID) {
        return 0u;
    }

    if (cep_heartbeat_beat_to_op_stamp(horizon, &stamp)) {
        return stamp;
    }

    return 0u;
}

cepOpCount cep_runtime_view_horizon_floor_stamp(void) {
    return CEP_RUNTIME.view_horizon_floor_stamp;
}


/* Shares the enzymes root dictionary so tooling can inspect or organise enzyme
 * metadata alongside the registry.
 */
/** Return the subtree that stores enzyme metadata visible to tooling. */
cepCell* cep_heartbeat_enzymes_root(void) {
    return CEP_RUNTIME.topology.enzymes;
}

const cepEnzymeDescriptor* cep_enzyme_current(void) {
    return CEP_RUNTIME.current_descriptor;
}

bool cep_lifecycle_scope_mark_ready(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }

    cepLifecycleScopeState* state = &CEP_LIFECYCLE_STATE[scope];
    const cepLifecycleScopeInfo* info = &CEP_LIFECYCLE_SCOPE_INFO[scope];

    if (state->ready) {
        return true;
    }

    if (!cep_lifecycle_scope_dependencies_ready(scope)) {
        for (size_t i = 0; i < info->dependency_count; ++i) {
            cepLifecycleScope dep = info->dependencies[i];
            if (dep < CEP_LIFECYCLE_SCOPE_COUNT) {
                (void)cep_lifecycle_scope_mark_ready(dep);
            }
        }
    }

    if (!cep_boot_ops_start_boot()) {
        return false;
    }

    cepBeatNumber beat = cep_beat_index();
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }

    state->ready = true;
    state->ready_beat = beat;
    state->teardown = false;
    if (scope == CEP_LIFECYCLE_SCOPE_KERNEL) {
        CEP_LIFECYCLE_OPS_STATE.boot_kernel_ready = true;
    } else if (scope == CEP_LIFECYCLE_SCOPE_NAMEPOOL) {
        CEP_LIFECYCLE_OPS_STATE.boot_namepool_ready = true;
    }

    return true;
}

bool cep_lifecycle_scope_mark_teardown(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }

    cepLifecycleScopeState* state = &CEP_LIFECYCLE_STATE[scope];

    if (state->teardown) {
        return true;
    }

    if (!cep_boot_ops_start_shutdown()) {
        return false;
    }

    cepBeatNumber beat = cep_beat_index();
    if (beat == CEP_BEAT_INVALID) {
        beat = 0u;
    }

    state->ready = false;
    state->teardown = true;
    state->td_beat = beat;

    CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked += 1u;
    size_t expected = cep_lengthof(CEP_LIFECYCLE_TEARDOWN_ORDER);
    if (CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked > expected) {
        CEP_LIFECYCLE_OPS_STATE.shdn_scopes_marked = expected;
    }

    return true;
}

bool cep_lifecycle_scope_is_ready(cepLifecycleScope scope) {
    if (scope >= CEP_LIFECYCLE_SCOPE_COUNT) {
        return false;
    }
    return CEP_LIFECYCLE_STATE[scope].ready;
}


static void cep_heartbeat_auto_shutdown(void) CEP_AT_SHUTDOWN_(101);

static void cep_heartbeat_auto_shutdown(void) {
    cep_heartbeat_shutdown();
}
