/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_MAILBOX_H
#define CEP_MAILBOX_H

#include "cep_cell.h"
#include "cep_heartbeat.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief Helper APIs for mailbox message identity, TTL planning, and retention bookkeeping.
 */

/**
 * @brief Enumerates the strategy chosen for a mailbox message identifier.
 */
typedef enum {
    CEP_MAILBOX_ID_EXPLICIT = 0,
    CEP_MAILBOX_ID_DIGEST,
    CEP_MAILBOX_ID_COUNTER,
    CEP_MAILBOX_ID_REUSED,
} cepMailboxIdMode;

/**
 * @brief Summarises the outcome of selecting a mailbox message identifier.
 */
typedef struct {
    cepDT            id;
    cepMailboxIdMode mode;
    bool             collision_detected;
} cepMailboxMessageId;

/**
 * Select a mailbox message identifier while enforcing the preferred precedence:
 * caller-supplied IDs come first, deterministic envelope digests follow, and a
 * monotonically increasing counter fills any remaining gaps. The helper guards
 * against collisions by comparing sealed envelope digests, increments the
 * mailbox counter when needed, and records whether a collision was detected so
 * callers can emit diagnostics.
 */
bool cep_mailbox_select_message_id(cepCell* mailbox_root,
                                   const cepDT* explicit_id,
                                   const cepCell* envelope,
                                   cepMailboxMessageId* out_id);

/**
 * @brief Declares which scope supplied a TTL configuration.
 */
typedef enum {
    CEP_MAILBOX_TTL_SCOPE_NONE = 0,
    CEP_MAILBOX_TTL_SCOPE_MESSAGE,
    CEP_MAILBOX_TTL_SCOPE_MAILBOX,
    CEP_MAILBOX_TTL_SCOPE_TOPOLOGY,
} cepMailboxTTLSource;

/**
 * @brief Captures TTL inputs gathered from headers, mailbox policy, or topology defaults.
 */
typedef struct {
    bool     forever;
    bool     has_beats;
    uint32_t ttl_beats;
    bool     has_unix_ns;
    uint64_t ttl_unix_ns;
} cepMailboxTTLSpec;

/**
 * @brief Records the heartbeat baseline used to resolve TTLs.
 */
typedef struct {
    cepBeatNumber issued_beat;
    bool          issued_has_unix;
    uint64_t      issued_unix_ns;
    cepBeatNumber current_beat;
    bool          current_has_unix;
    uint64_t      current_unix_ns;
} cepMailboxTTLContext;

/**
 * Initialise a TTL context by sampling the heartbeat timeline so TTL helpers
 * can translate relative durations into absolute deadlines. The helper reads
 * the current beat and its unix timestamp when available; callers may override
 * the issued beat/unix fields afterwards if a message carries explicit values.
 */
bool cep_mailbox_ttl_context_init(cepMailboxTTLContext* ctx);

/**
 * @brief Synthesises the resolved TTL deadlines for enforcement and retention.
 */
typedef struct {
    bool                is_forever;
    bool                beats_active;
    uint32_t            ttl_beats;
    cepBeatNumber       beat_deadline;
    cepMailboxTTLSource beats_source;
    bool                wallclock_active;
    uint64_t            ttl_unix_ns;
    uint64_t            wallclock_deadline;
    cepMailboxTTLSource wallclock_source;
    bool                beat_from_wallclock;
    bool                heuristics_used;
    uint64_t            heuristic_interval_ns;
} cepMailboxTTLResolved;

/**
 * Resolve TTL sources (message → mailbox policy → topology) into actionable
 * deadlines. The helper honours the "forever" sentinel, computes absolute beat
 * and unix deadlines relative to the issued beat/timestamp, and can project a
 * beat deadline from wallclock data when heartbeat analytics expose spacing
 * estimates. The caller receives the chosen sources plus a flag if heuristics
 * were required so diagnostics and retention enzymes can react accordingly.
 */
bool cep_mailbox_resolve_ttl(const cepMailboxTTLSpec* message,
                             const cepMailboxTTLSpec* mailbox,
                             const cepMailboxTTLSpec* topology,
                             const cepMailboxTTLContext* ctx,
                             cepMailboxTTLResolved* resolved);

/**
 * Disable or re-enable wallclock heuristics when debugging beats without
 * deterministic unix timestamps. When disabled, TTL resolution records
 * wallclock inputs but skips projecting beat deadlines from spacing analytics.
 */
void cep_mailbox_disable_wallclock(bool disabled);

/**
 * Configure the retention planner's lookahead behaviour. The first parameter
 * limits how many beats ahead wallclock projections are allowed to stretch,
 * while the second caps how many spacing samples are considered when deriving
 * average beat intervals from `/rt/analytics/spacing`.
 */
void cep_mailbox_set_expiry_windows(uint32_t beat_lookahead, uint32_t spacing_samples);

/**
 * Return the retention planner knobs previously set via
 * cep_mailbox_set_expiry_windows; useful for diagnostics and tooling.
 */
void cep_mailbox_get_expiry_windows(uint32_t* beat_lookahead, uint32_t* spacing_samples);

/**
 * Record the deadlines for a message inside the mailbox runtime metadata so
 * retention enzymes can pick them up later. The helper materialises beat and
 * unix timestamp buckets under `meta/runtime/expiries*`, stores links to the
 * message, and keeps the buckets idempotent.
 */
bool cep_mailbox_record_expiry(cepCell* mailbox_root,
                               const cepDT* message_id,
                               const cepMailboxTTLResolved* resolved);

/**
 * @brief One expiry record to hand back to retention enzymes.
 */
typedef struct {
    cepDT          message_id;
    bool           from_wallclock;
    cepBeatNumber  beat_deadline;
    uint64_t       wallclock_deadline;
} cepMailboxExpiryRecord;

/**
 * @brief Aggregated retention plan split by beat-first and wallclock-only queues.
 */
typedef struct {
    cepMailboxExpiryRecord* beats;
    size_t                  beats_count;
    size_t                  beats_capacity;
    cepMailboxExpiryRecord* wallclock;
    size_t                  wallclock_count;
    size_t                  wallclock_capacity;
    bool                    has_future_beats;
    bool                    has_future_wallclock;
} cepMailboxRetentionPlan;

/**
 * Reset a retention plan to the empty state, releasing any heap allocations so
 * callers can reuse the structure across beats without leaking memory.
 */
void cep_mailbox_retention_plan_reset(cepMailboxRetentionPlan* plan);

/**
 * Inspect the recorded expiry buckets and assemble the workload for the current
 * beat. Due beat buckets land in the `beats` partition, wallclock deadlines go
 * into the second queue, and the helper keeps track of future buckets so
 * enzymes can decide whether to reschedule themselves. FIXME: Once L1
 * regulators own retention, extend this planner to hand off backlog slices in
 * streaming fashion rather than returning copies.
 */
bool cep_mailbox_plan_retention(cepCell* mailbox_root,
                                const cepMailboxTTLContext* ctx,
                                cepMailboxRetentionPlan* plan);

#ifdef __cplusplus
}
#endif

#endif /* CEP_MAILBOX_H */

