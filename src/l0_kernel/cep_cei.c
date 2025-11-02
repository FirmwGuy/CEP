/* Common Error Interface helper implementation. Builds structured Error Facts,
   delivers them through the diagnostics mailbox and heartbeat impulses, and
   updates OPS dossiers when severity policies demand it. */

#include "cep_cei.h"

#include "cep_heartbeat.h"
#include "cep_mailbox.h"
#include "cep_namepool.h"
#include "cep_runtime.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

int cep_cei_debug_last_error(void) {
    cepMailboxRuntimeSettings* settings = cep_runtime_mailbox_settings(cep_runtime_default());
    if (!settings) {
        return 0;
    }
    return settings->cei_debug_last_error;
}

CEP_DEFINE_STATIC_DT(dt_mailbox_root,      CEP_ACRO("CEP"), CEP_WORD("mailbox"))
CEP_DEFINE_STATIC_DT(dt_diag_mailbox,      CEP_ACRO("CEP"), CEP_WORD("diag"))
CEP_DEFINE_STATIC_DT(dt_meta_name,         CEP_ACRO("CEP"), CEP_WORD("meta"))
CEP_DEFINE_STATIC_DT(dt_kind_name,         CEP_ACRO("CEP"), CEP_WORD("kind"))
CEP_DEFINE_STATIC_DT(dt_msgs_name,         CEP_ACRO("CEP"), CEP_WORD("msgs"))
CEP_DEFINE_STATIC_DT(dt_runtime_name,      CEP_ACRO("CEP"), CEP_WORD("runtime"))
CEP_DEFINE_STATIC_DT(dt_envelope_name,     CEP_ACRO("CEP"), CEP_WORD("envelope"))
CEP_DEFINE_STATIC_DT(dt_err_name,          CEP_ACRO("CEP"), CEP_WORD("err"))
CEP_DEFINE_STATIC_DT(dt_sev_field,         CEP_ACRO("CEP"), CEP_WORD("sev"))
CEP_DEFINE_STATIC_DT(dt_note_field,        CEP_ACRO("CEP"), CEP_WORD("note"))
CEP_DEFINE_STATIC_DT(dt_topic_field,       CEP_ACRO("CEP"), CEP_WORD("topic"))
CEP_DEFINE_STATIC_DT(dt_origin_field,      CEP_ACRO("CEP"), CEP_WORD("origin"))
CEP_DEFINE_STATIC_DT(dt_name_field,        CEP_ACRO("CEP"), CEP_WORD("name"))
CEP_DEFINE_STATIC_DT(dt_role_subj_field,   CEP_ACRO("CEP"), CEP_WORD("role_subj"))
CEP_DEFINE_STATIC_DT(dt_issued_beat_field, CEP_ACRO("CEP"), CEP_WORD("issued_beat"))
CEP_DEFINE_STATIC_DT(dt_issued_unix_field, CEP_ACRO("CEP"), CEP_WORD("issued_unix"))
CEP_DEFINE_STATIC_DT(dt_code_field,        CEP_ACRO("CEP"), CEP_WORD("code"))
CEP_DEFINE_STATIC_DT(dt_payload_field,     CEP_ACRO("CEP"), CEP_WORD("payload_id"))
CEP_DEFINE_STATIC_DT(dt_ttl_field,         CEP_ACRO("CEP"), CEP_WORD("ttl"))
CEP_DEFINE_STATIC_DT(dt_ttl_beats_field,   CEP_ACRO("CEP"), CEP_WORD("ttl_beats"))
CEP_DEFINE_STATIC_DT(dt_ttl_unix_field,    CEP_ACRO("CEP"), CEP_WORD("ttl_unix_ns"))
CEP_DEFINE_STATIC_DT(dt_ttl_mode_field,    CEP_ACRO("CEP"), CEP_WORD("ttl_mode"))
CEP_DEFINE_STATIC_DT(dt_sig_cei_root,      CEP_ACRO("CEP"), CEP_WORD("sig_cei"))
CEP_DEFINE_STATIC_DT(dt_sts_fail,          CEP_ACRO("CEP"), CEP_WORD("sts:fail"))
CEP_DEFINE_STATIC_DT(dt_sev_fatal,         CEP_ACRO("CEP"), CEP_WORD("sev:fatal"))
CEP_DEFINE_STATIC_DT(dt_sev_crit,          CEP_ACRO("CEP"), CEP_WORD("sev:crit"))
CEP_DEFINE_STATIC_DT(dt_sev_usage,         CEP_ACRO("CEP"), CEP_WORD("sev:usage"))

typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[2];
} cepPathConst2;

static bool cep_cei_severity_equals(const cepDT* severity, const cepDT* expected) {
    if (!severity || !expected) {
        return false;
    }
    return cep_dt_compare(severity, expected) == 0;
}

static cepCell* cep_cei_mailbox_root(cepCell* data_root) {
    if (!data_root) {
        return NULL;
    }
    return cep_cell_ensure_dictionary_child(data_root, dt_mailbox_root(), CEP_STORAGE_RED_BLACK_T);
}

static bool cep_cei_mailbox_seed_meta(cepCell* mailbox) {
    cepCell* meta = cep_cell_ensure_dictionary_child(mailbox, dt_meta_name(), CEP_STORAGE_RED_BLACK_T);
    if (!meta) {
        return false;
    }
    cepCell* kind_field = cep_cell_find_by_name(meta, dt_kind_name());
    if (!kind_field || !cep_cell_has_data(kind_field)) {
        if (!cep_cell_put_text(meta, dt_kind_name(), "diagnostic")) {
            return false;
        }
    }
    if (!cep_cell_ensure_dictionary_child(meta, dt_runtime_name(), CEP_STORAGE_RED_BLACK_T)) {
        return false;
    }
    if (!cep_cell_find_by_name(mailbox, dt_msgs_name())) {
        if (!cep_cell_ensure_dictionary_child(mailbox, dt_msgs_name(), CEP_STORAGE_RED_BLACK_T)) {
            return false;
        }
    }
    return true;
}

static cepCell* cep_cei_mailbox_resolve(void) {
    cepCell* data_root = cep_heartbeat_data_root();
    if (!data_root) {
        return NULL;
    }
    cepCell* mailboxes = cep_cei_mailbox_root(data_root);
    if (!mailboxes) {
        return NULL;
    }
    cepCell* diagnostics = cep_cell_ensure_dictionary_child(mailboxes,
                                                            dt_diag_mailbox(),
                                                            CEP_STORAGE_RED_BLACK_T);
    if (!diagnostics) {
        return NULL;
    }
    if (!cep_cei_mailbox_seed_meta(diagnostics)) {
        return NULL;
    }
    return cep_cell_resolve(diagnostics);
}

/* Resolve (and bootstrap when needed) the default diagnostics mailbox so CEI
   emissions have a deterministic sink even when callers do not provide one. */
cepCell* cep_cei_diagnostics_mailbox(void) {
    return cep_cei_mailbox_resolve();
}

static size_t cep_cei_string_length(const char* text, size_t explicit_len) {
    if (!text) {
        return 0u;
    }
    if (explicit_len != 0u) {
        return explicit_len;
    }
    return strlen(text);
}

static bool cep_cei_populate_envelope(cepCell* envelope,
                                      cepBeatNumber beat,
                                      bool has_unix,
                                      uint64_t unix_ns,
                                      const cepCeiRequest* request) {
    if (!envelope || !request) {
        return false;
    }
    if (!cep_cell_put_uint64(envelope, dt_issued_beat_field(), (uint64_t)beat)) {
        return false;
    }
    if (has_unix) {
        if (!cep_cell_put_uint64(envelope, dt_issued_unix_field(), unix_ns)) {
            return false;
        }
    }
    if (request->ttl_forever || request->has_ttl_beats || request->has_ttl_unix_ns) {
        cepCell* ttl = cep_cell_ensure_dictionary_child(envelope, dt_ttl_field(), CEP_STORAGE_RED_BLACK_T);
        if (!ttl) {
            return false;
        }
        if (request->ttl_forever) {
            if (!cep_cell_put_text(ttl, dt_ttl_mode_field(), "forever")) {
                return false;
            }
        }
        if (request->has_ttl_beats) {
            if (!cep_cell_put_uint64(ttl, dt_ttl_beats_field(), (uint64_t)request->ttl_beats)) {
                return false;
            }
        }
        if (request->has_ttl_unix_ns) {
            if (!cep_cell_put_uint64(ttl, dt_ttl_unix_field(), request->ttl_unix_ns)) {
                return false;
            }
        }
    }
    return true;
}

static bool cep_cei_attach_subject(cepCell* err_root, cepCell* subject) {
    if (!err_root || !subject) {
        return true;
    }
    cepCell* canonical = cep_link_pull(subject);
    if (!canonical) {
        return false;
    }
    cepCell* existing = cep_cell_find_by_name(err_root, dt_role_subj_field());
    if (existing) {
        existing = cep_cell_resolve(existing);
        if (!existing || !cep_cell_is_link(existing)) {
            return false;
        }
        cep_link_set(existing, canonical);
        return true;
    }
    cepDT link_name = *dt_role_subj_field();
    return cep_dict_add_link(err_root, &link_name, canonical) != NULL;
}

static bool cep_cei_populate_origin(cepCell* err_root, const cepCeiRequest* request) {
    if (!err_root || !request) {
        return false;
    }
    if (!request->origin_name && !request->origin_kind) {
        return true;
    }
    cepCell* origin = cep_cell_ensure_dictionary_child(err_root, dt_origin_field(), CEP_STORAGE_RED_BLACK_T);
    if (!origin) {
        return false;
    }
    if (request->origin_name && cep_dt_is_valid(request->origin_name)) {
        if (!cep_cell_put_dt(origin, dt_name_field(), request->origin_name)) {
            return false;
        }
    }
    if (request->origin_kind && *request->origin_kind) {
        if (!cep_cell_put_text(origin, dt_kind_name(), request->origin_kind)) {
            return false;
        }
    }
    return true;
}

static bool cep_cei_populate_fact(cepCell* err_root,
                                  const cepCeiRequest* request,
                                  cepBeatNumber beat,
                                  bool has_unix,
                                  uint64_t unix_ns,
                                  cepCell* subject) {
    if (!err_root || !request) {
        return false;
    }
    if (!cep_cell_put_dt(err_root, dt_sev_field(), &request->severity)) {
        return false;
    }
    if (!cep_cell_put_uint64(err_root, dt_issued_beat_field(), (uint64_t)beat)) {
        return false;
    }
    if (has_unix) {
        if (!cep_cell_put_uint64(err_root, dt_issued_unix_field(), unix_ns)) {
            return false;
        }
    }
    size_t note_len = cep_cei_string_length(request->note, request->note_len);
    if (note_len > 0u && request->note) {
        if (!cep_cell_put_text(err_root, dt_note_field(), request->note)) {
            return false;
        }
    }
    size_t topic_len = cep_cei_string_length(request->topic, request->topic_len);
    if (topic_len > 0u && request->topic) {
        if (request->topic_intern) {
            (void)cep_namepool_intern(request->topic, topic_len);
        }
        if (!cep_cell_put_text(err_root, dt_topic_field(), request->topic)) {
            return false;
        }
    }
    if (request->has_code) {
        if (!cep_cell_put_uint64(err_root, dt_code_field(), request->code)) {
            return false;
        }
    }
    if (request->payload_id && *request->payload_id) {
        if (!cep_cell_put_text(err_root, dt_payload_field(), request->payload_id)) {
            return false;
        }
    }
    if (!cep_cei_populate_origin(err_root, request)) {
        return false;
    }
    if (!cep_cei_attach_subject(err_root, subject)) {
        return false;
    }
    return true;
}

static bool cep_cei_record_ttl(cepCell* mailbox_root,
                               const cepDT* message_id,
                               const cepCeiRequest* request,
                               cepBeatNumber beat,
                               bool has_unix,
                               uint64_t unix_ns) {
    if (!mailbox_root || !message_id || !request) {
        return false;
    }
    if (!request->ttl_forever && !request->has_ttl_beats && !request->has_ttl_unix_ns) {
        return true;
    }
    cepMailboxTTLSpec message_spec = {0};
    message_spec.forever = request->ttl_forever;
    if (request->has_ttl_beats) {
        message_spec.has_beats = true;
        message_spec.ttl_beats = request->ttl_beats;
    }
    if (request->has_ttl_unix_ns) {
        message_spec.has_unix_ns = true;
        message_spec.ttl_unix_ns = request->ttl_unix_ns;
    }
    cepMailboxTTLContext ctx = {0};
    if (!cep_mailbox_ttl_context_init(&ctx)) {
        return false;
    }
    ctx.issued_beat = beat;
    ctx.current_beat = beat;
    if (has_unix) {
        ctx.issued_has_unix = true;
        ctx.issued_unix_ns = unix_ns;
        ctx.current_has_unix = true;
        ctx.current_unix_ns = unix_ns;
    }
    cepMailboxTTLResolved resolved = {0};
    if (!cep_mailbox_resolve_ttl(&message_spec, NULL, NULL, &ctx, &resolved)) {
        return false;
    }
    if (resolved.is_forever || (!resolved.beats_active && !resolved.wallclock_active)) {
        return true;
    }
    return cep_mailbox_record_expiry(mailbox_root, message_id, &resolved);
}

static bool cep_cei_emit_signal_if_requested(const cepCeiRequest* request,
                                             const cepDT* severity,
                                             const cepPath* target_path) {
    if (!request || !severity) {
        return false;
    }
    if (!request->emit_signal) {
        return true;
    }
    cepPathConst2 signal_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            {.dt = *dt_sig_cei_root(), .timestamp = 0u},
            {.dt = *severity, .timestamp = 0u},
        },
    };
    cepBeatNumber due = cep_heartbeat_next();
    return cep_heartbeat_enqueue_signal(due, (const cepPath*)&signal_path, target_path) == CEP_ENZYME_SUCCESS;
}

static bool cep_cei_close_operation_if_requested(const cepCeiRequest* request,
                                                 const cepDT* severity,
                                                 const char* summary) {
    if (!request || !severity) {
        return false;
    }
    if (!request->attach_to_op || !cep_oid_is_valid(request->op)) {
        return true;
    }
    if (!summary) {
        summary = "";
    }
    if (cep_cei_severity_equals(severity, dt_sev_fatal()) ||
        cep_cei_severity_equals(severity, dt_sev_crit()) ||
        cep_cei_severity_equals(severity, dt_sev_usage())) {
        if (!cep_op_close(request->op, *dt_sts_fail(), summary, strlen(summary))) {
            return false;
        }
    }
    return true;
}

static void cep_cei_maybe_trigger_shutdown(const cepDT* severity) {
    if (!severity) {
        return;
    }
    if (cep_cei_severity_equals(severity, dt_sev_fatal())) {
        (void)cep_heartbeat_emit_shutdown();
    }
}

static bool cep_cei_format_summary(const cepDT* severity,
                                   const cepDT* message_id,
                                   char* buffer,
                                   size_t capacity) {
    if (!buffer || capacity == 0u || !severity || !message_id) {
        return false;
    }
    char sev_text[12] = {0};
    char id_text[32] = {0};
    size_t sev_len = cep_word_to_text(cep_id(severity->tag), sev_text);
    size_t id_len = cep_word_to_text(cep_id(message_id->tag), id_text);
    if (sev_len == 0u || id_len == 0u) {
        return false;
    }
    int written = snprintf(buffer,
                           capacity,
                           "CEI %.*s message=%.*s",
                           (int)sev_len,
                           sev_text,
                           (int)id_len,
                           id_text);
    return written > 0 && (size_t)written < capacity;
}

/* Compose an Error Fact in the diagnostics mailbox, queue optional impulses,
   and enforce severity policies such as OPS attachment and fatal shutdown. */
bool cep_cei_emit(const cepCeiRequest* request) {
    cepMailboxRuntimeSettings* settings = cep_runtime_mailbox_settings(cep_runtime_default());
    if (settings) settings->cei_debug_last_error = 0;

    if (!request || !cep_dt_is_valid(&request->severity)) {
        if (settings) settings->cei_debug_last_error = 100;
        return false;
    }

    cepCell* mailbox_root = request->mailbox_root ? cep_cell_resolve(request->mailbox_root)
                                                  : cep_cei_diagnostics_mailbox();
    if (!mailbox_root) {
        if (settings) settings->cei_debug_last_error = 1;
        return false;
    }

    cepPath* owned_subject_path = NULL;
    const cepPath* target_path = request->subject_path;
    if (!target_path && request->subject) {
        if (!cep_cell_path(request->subject, &owned_subject_path)) {
            cep_free(owned_subject_path);
            return false;
        }
        target_path = owned_subject_path;
    }

    cepBeatNumber beat = cep_heartbeat_current();
    if (beat == CEP_BEAT_INVALID) {
        beat = (cepBeatNumber)cep_beat_index();
    }
    uint64_t unix_ns = 0u;
    bool has_unix = cep_heartbeat_beat_to_unix(beat, &unix_ns);

    cepMailboxMessageId message_id = {0};
    if (!cep_mailbox_select_message_id(mailbox_root, NULL, NULL, &message_id)) {
        if (settings) settings->cei_debug_last_error = 2;
        cepCell* meta_debug = cep_cell_find_by_name(mailbox_root, dt_meta_name());
#if defined(CEP_ENABLE_DEBUG)
        cepCell* runtime_debug = meta_debug ? cep_cell_find_by_name(meta_debug, dt_runtime_name()) : NULL;
        CEP_DEBUG_PRINTF("[cei_emit] select id failed meta=%p runtime=%p\n",
                         (void*)meta_debug,
                         (void*)runtime_debug);
#endif
        cep_free(owned_subject_path);
        return false;
    }

    cepCell* msgs = cep_cell_find_by_name(mailbox_root, dt_msgs_name());
    if (!msgs) {
        if (settings) settings->cei_debug_last_error = 3;
        cep_free(owned_subject_path);
        return false;
    }
    msgs = cep_cell_resolve(msgs);
    if (!msgs) {
        if (settings) settings->cei_debug_last_error = 4;
        cep_free(owned_subject_path);
        return false;
    }

    cepTxn txn = {0};
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    if (!cep_txn_begin(msgs, &message_id.id, &dict_type, &txn)) {
        if (settings) settings->cei_debug_last_error = 5;
        cep_free(owned_subject_path);
        return false;
    }

    bool success = false;
    cepCell* message_root = txn.root;
    cepCell* envelope = cep_cell_ensure_dictionary_child(message_root, dt_envelope_name(), CEP_STORAGE_RED_BLACK_T);
    cepCell* err_root = envelope ? cep_cell_ensure_dictionary_child(message_root, dt_err_name(), CEP_STORAGE_RED_BLACK_T) : NULL;
    if (!envelope || !err_root) {
        if (settings) settings->cei_debug_last_error = 6;
        goto cleanup;
    }

    if (!cep_cei_populate_envelope(envelope, beat, has_unix, unix_ns, request)) {
        if (settings) settings->cei_debug_last_error = 7;
        goto cleanup;
    }
    if (!cep_cell_set_immutable(envelope)) {
        if (settings) settings->cei_debug_last_error = 8;
        goto cleanup;
    }

    if (!cep_cei_populate_fact(err_root, request, beat, has_unix, unix_ns, request->subject)) {
        if (settings) settings->cei_debug_last_error = 9;
        goto cleanup;
    }
    if (!cep_cell_set_immutable(err_root)) {
        if (settings) settings->cei_debug_last_error = 10;
        goto cleanup;
    }

    if (!cep_txn_mark_ready(&txn)) {
        if (settings) settings->cei_debug_last_error = 11;
        goto cleanup;
    }
    if (!cep_txn_commit(&txn)) {
        if (settings) settings->cei_debug_last_error = 12;
        goto cleanup;
    }
    txn.root = NULL;
    txn.parent = NULL;

    if (!cep_cei_record_ttl(mailbox_root, &message_id.id, request, beat, has_unix, unix_ns)) {
        if (settings) settings->cei_debug_last_error = 13;
        goto cleanup;
    }

    char summary[96] = {0};
    if (!cep_cei_format_summary(&request->severity, &message_id.id, summary, sizeof summary)) {
        summary[0] = '\0';
    }
    if (!cep_cei_close_operation_if_requested(request, &request->severity, summary)) {
        if (settings) settings->cei_debug_last_error = 14;
        goto cleanup;
    }

    if (!cep_cei_emit_signal_if_requested(request, &request->severity, target_path)) {
        if (settings) settings->cei_debug_last_error = 15;
        goto cleanup;
    }

    cep_cei_maybe_trigger_shutdown(&request->severity);
    success = true;

cleanup:
    if (!success) {
        cep_txn_abort(&txn);
    }
    cep_free(owned_subject_path);
    return success;
}
