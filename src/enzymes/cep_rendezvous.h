/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_RENDEZVOUS_H
#define CEP_RENDEZVOUS_H

#include <stdbool.h>
#include <stdint.h>

#include "../l0_kernel/cep_cell.h"

#include "../l0_kernel/cep_heartbeat.h"
#include "../l0_kernel/cep_enzyme.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Rendezvous profile descriptor used when spawning background work.
 */
typedef struct {
    cepID        prof;          /**< Rendezvous profile identifier. */
    cepID        on_miss;       /**< Policy when rendezvous is missed. */
    cepID        kill_mode;     /**< Policy to apply when a kill is requested. */
    cepDT        key_dt;        /**< Dictionary key used for the ledger entry. */
    cepDT        instance_dt;   /**< Owning flow instance identifier. */
    const char*  signal_path;   /**< Optional signal path override (default derived from key). */
    const char*  cas_hash;      /**< Optional CAS hash used for rv-cas payloads. */
    const cepCell* telemetry;   /**< Optional telemetry dictionary to copy. */
    uint64_t     input_fp;      /**< Fingerprint of inputs/code. */
    uint64_t     due;           /**< Due beat for the rendezvous. */
    uint64_t     deadline;      /**< Optional hard deadline beat (0 to ignore). */
    uint32_t     epoch_k;       /**< Rendezvous cadence for rv-epoch profiles (0 to disable). */
    uint32_t     grace_delta;   /**< Grace window delta in beats. */
    uint32_t     max_grace;     /**< Maximum number of grace extensions. */
    uint32_t     kill_wait;     /**< Beats to wait after a kill request before escalation. */
} cepRvSpec;

typedef enum {
    CEP_RV_SPAWN_STATUS_OK = 0,
    CEP_RV_SPAWN_STATUS_NO_SPEC,
    CEP_RV_SPAWN_STATUS_DATA_ROOT,
    CEP_RV_SPAWN_STATUS_LEDGER_MISSING,
    CEP_RV_SPAWN_STATUS_LEDGER_LOCK,
    CEP_RV_SPAWN_STATUS_ENTRY_ALLOC,
    CEP_RV_SPAWN_STATUS_ENTRY_LOCK,
} cepRvSpawnStatus;

bool cep_rv_bootstrap(void);

/**
 * Build a rendezvous spec from a transform dictionary, merging any
 * profile-specific defaults so callers can hand a ready-to-spawn descriptor
 * directly to `cep_rv_spawn`. The scratch buffer is used when the helper needs
 * to synthesise the signal path from the rendezvous key.
 */
bool cep_rv_prepare_spec(cepRvSpec* out_spec,
                         const cepCell* spec_node,
                         const cepDT* instance_dt,
                         cepBeatNumber now,
                         char* signal_buffer,
                         size_t signal_capacity);

bool cep_rv_spawn(const cepRvSpec* spec, cepID key);
cepRvSpawnStatus cep_rv_last_spawn_status(void);
bool cep_rv_resched(cepID key, uint32_t delta);
bool cep_rv_kill(cepID key, cepID mode, uint32_t wait_beats);
bool cep_rv_report(cepID key, const cepCell* telemetry_node);

bool cep_rv_capture_scan(void);
bool cep_rv_commit_apply(void);

/**
 * @brief Compute the default rendezvous signal path for a given ledger key.
 *
 * The helper writes a canonical path of the form `CEP:sig_rv/<key>` into the
 * supplied buffer and returns true on success.
 */
bool cep_rv_signal_for_key(const cepDT* key, char* buffer, size_t capacity);

bool cep_rendezvous_register(cepEnzymeRegistry* registry);

#ifdef __cplusplus
}
#endif

#endif /* CEP_RENDEZVOUS_H */
