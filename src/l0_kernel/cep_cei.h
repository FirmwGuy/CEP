/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/* Common Error Interface (CEI) public API for Layer 0 helpers. The helper
   builds structured Error Facts, routes them through mailboxes and heartbeat
   impulses, and updates OPS dossiers so severe faults become visible without
   inventing new logging subsystems. */

#ifndef CEP_CEI_H
#define CEP_CEI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cep_cell.h"
#include "cep_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct cepCeiRequest
 * @brief Parameters describing a Common Error Interface emission.
 *
 * The helper composes an Error Fact under `err/`, optionally delivers it to a
 * mailbox, queues a `sig_cei/<severity>` impulse, and updates an operation dossier when
 * requested. Callers populate this structure on the stack and pass it to
 * cep_cei_emit().
 */
typedef struct {
    cepDT          severity;         /**< Required severity tag (`sev:*`). */
    const char*    note;             /**< Optional human readable message. */
    size_t         note_len;         /**< Length of @p note (0 for strlen). */
    const char*    topic;            /**< Optional routing topic. */
    size_t         topic_len;        /**< Length of @p topic (0 for strlen). */
    bool           topic_intern;     /**< Intern @p topic before storing. */
    const cepDT*   origin_name;      /**< Optional origin identifier DT. */
    const char*    origin_kind;      /**< Optional origin kind text. */
    cepCell*       subject;          /**< Optional subject cell for role link. */
    const cepPath* subject_path;     /**< Optional explicit target path. */
    bool           has_code;         /**< Emits numeric code when true. */
    uint64_t       code;             /**< Numeric diagnostic code. */
    const char*    payload_id;       /**< Optional payload identifier text. */
    cepCell*       mailbox_root;     /**< Override mailbox root (else default). */
    bool           emit_signal;      /**< Emit `sig_cei/<severity>` impulse. */
    bool           attach_to_op;     /**< Attach CEI fact to operation dossier. */
    cepOID         op;               /**< Operation identifier when attaching. */
    bool           ttl_forever;      /**< Mark mailbox entry as non-expiring. */
    bool           has_ttl_beats;    /**< Provide beat TTL if true. */
    uint32_t       ttl_beats;        /**< Beat TTL for mailbox routing. */
    bool           has_ttl_unix_ns;  /**< Provide unix TTL if true. */
    uint64_t       ttl_unix_ns;      /**< Wallclock TTL for mailbox routing. */
} cepCeiRequest;

/**
 * @brief Ensure the default diagnostics mailbox exists and return it.
 */
cepCell* cep_cei_diagnostics_mailbox(void);

/**
 * @brief Compose and emit a Common Error Interface fact.
 */
bool cep_cei_emit(const cepCeiRequest* request);

/**
 * @brief Retrieve the most recent internal error code set by cep_cei_emit().
 */
int cep_cei_debug_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* CEP_CEI_H */
