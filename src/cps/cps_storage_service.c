/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cps_storage_service.h"

#include "cps_engine.h"
#include "cps_runtime.h"
#include "cps_flatfile.h"

#include "blake3.h"
#include "cep_cell.h"
#include "cep_cei.h"
#include "cep_flat_stream.h"
#include "cep_flat_serializer.h"
#include "cep_heartbeat.h"
#include "cep_ops.h"
#include "cep_runtime.h"
#include "../l0_kernel/cep_branch_controller.h"
#include "../l0_kernel/cep_namepool.h"
#include "../l0_kernel/cep_async.h"

#include <ctype.h>
#include <strings.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if defined(_WIN32)
#include <io.h>
#include <direct.h>
#define fsync _commit
static char*
cep_realpath_portable(const char* path, char* resolved)
{
    return _fullpath(resolved, path, PATH_MAX);
}
#define realpath(path, resolved) cep_realpath_portable(path, resolved)
static int
cep_mkdir_portable(const char* path, mode_t mode)
{
    (void)mode;
    return _mkdir(path);
}
#else
static int
cep_mkdir_portable(const char* path, mode_t mode)
{
    return mkdir(path, mode);
}
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char k_cps_topic_storage_commit[] = "persist.commit";
static const char k_cps_topic_storage_async[] = "persist.async";
static const char k_cps_topic_branch_flush_begin[] = "persist.flush.begin";
static const char k_cps_topic_branch_flush_done[] = "persist.flush.done";
static const char k_cps_topic_branch_flush_fail[] = "persist.flush.fail";
static const char k_cps_topic_branch_defer[] = "persist.defer";
static const char k_cps_topic_branch_snapshot[] = "persist.snapshot";

#define CPS_STORAGE_ASYNC_COMMIT_TIMEOUT_MS 500u
#define CPS_STORAGE_ASYNC_WAIT_POLL_NS 1000000L

static void cps_storage_emit_async_cei(const char *detail);
static void cps_storage_emit_topic_cei(const cepDT* severity,
                                       const char* topic,
                                       const char* detail);
static void cps_storage_emit_cei(const cepDT *severity, const char *detail);
static const char* cps_storage_policy_mode_label(cepBranchPersistMode mode);
static const char* cps_storage_flush_cause_label(cepBranchFlushCause cause);
typedef struct cpsStorageAsyncCommitCtx cpsStorageAsyncCommitCtx;
static bool cps_storage_async_register_request(const cepDT* opcode,
                                               size_t expected_bytes,
                                               cepDT* out_name);
static void cps_storage_async_finish_request(const cepDT* name,
                                             const cepDT* opcode,
                                             bool success,
                                             uint64_t bytes,
                                             int error_code);
static void cps_storage_async_commit_on_complete(bool success,
                                                 uint64_t bytes,
                                                 int error_code,
                                                 void* context);
static cpsStorageAsyncCommitCtx* cps_storage_async_commit_ctx_create(const cepDT* request_name);
static void cps_storage_async_commit_ctx_addref(cpsStorageAsyncCommitCtx* ctx);
static void cps_storage_async_commit_ctx_release(cpsStorageAsyncCommitCtx* ctx);
static void cps_storage_async_finalize_success(cpsStorageAsyncCommitCtx* ctx);
static void cps_storage_async_mark_failed(cpsStorageAsyncCommitCtx* ctx,
                                          uint64_t bytes,
                                          int error_code,
                                          const char* detail);
static bool cps_storage_async_wait_for_commit(cpsStorageAsyncCommitCtx* ctx);
static bool cps_storage_run_branch_snapshot_op(cepOID oid,
                                               const char* branch_name,
                                               bool enable);
static bool cps_storage_read_bool_field(cepCell* envelope,
                                        const cepDT* field,
                                        bool default_value,
                                        bool* out);

CEP_DEFINE_STATIC_DT(dt_cps_storage_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_cps_storage_sev_info, CEP_ACRO("CEP"), CEP_WORD("sev:info"));
CEP_DEFINE_STATIC_DT(dt_cps_storage_sev_crit, CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_ops_root_name_cps, CEP_ACRO("CEP"), CEP_WORD("ops"));
CEP_DEFINE_STATIC_DT(dt_envelope_name_cps, CEP_ACRO("CEP"), CEP_WORD("envelope"));
CEP_DEFINE_STATIC_DT(dt_close_name_cps, CEP_ACRO("CEP"), CEP_WORD("close"));
CEP_DEFINE_STATIC_DT(dt_state_field_cps, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_verb_field_cps, CEP_ACRO("CEP"), CEP_WORD("verb"));
CEP_DEFINE_STATIC_DT(dt_target_field_cps, CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_branch_beats_field, CEP_ACRO("CEP"), CEP_WORD("beats"));
CEP_DEFINE_STATIC_DT(dt_bundle_field_cps, CEP_ACRO("CEP"), CEP_WORD("bundle"));
CEP_DEFINE_STATIC_DT(dt_hist_beats_field_cps, CEP_ACRO("CEP"), CEP_WORD("hist_beats"));
CEP_DEFINE_STATIC_DT(dt_payload_field_cps, CEP_ACRO("CEP"), CEP_WORD("payload_id"));
CEP_DEFINE_STATIC_DT(dt_op_checkpt_dt, CEP_ACRO("CEP"), CEP_WORD("op/checkpt"));
CEP_DEFINE_STATIC_DT(dt_op_compact_dt, CEP_ACRO("CEP"), CEP_WORD("op/compact"));
CEP_DEFINE_STATIC_DT(dt_op_sync_dt, CEP_ACRO("CEP"), CEP_WORD("op/sync"));
CEP_DEFINE_STATIC_DT(dt_op_import_dt, CEP_ACRO("CEP"), CEP_WORD("op/import"));
CEP_DEFINE_STATIC_DT(dt_op_branch_flush_dt, CEP_ACRO("CEP"), CEP_WORD("op/br_flush"));
CEP_DEFINE_STATIC_DT(dt_op_branch_schedule_dt, CEP_ACRO("CEP"), CEP_WORD("op/br_sched"));
CEP_DEFINE_STATIC_DT(dt_op_branch_defer_dt, CEP_ACRO("CEP"), CEP_WORD("op/br_defer"));
CEP_DEFINE_STATIC_DT(dt_op_branch_snapshot_dt, CEP_ACRO("CEP"), CEP_WORD("op/br_snap"));
CEP_DEFINE_STATIC_DT(dt_ist_run_dt, CEP_ACRO("CEP"), CEP_WORD("ist:run"));
CEP_DEFINE_STATIC_DT(dt_ist_exec_dt, CEP_ACRO("CEP"), CEP_WORD("ist:exec"));
CEP_DEFINE_STATIC_DT(dt_ist_ok_dt, CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_ist_fail_dt, CEP_ACRO("CEP"), CEP_WORD("ist:fail"));
CEP_DEFINE_STATIC_DT(dt_sts_ok_dt, CEP_ACRO("CEP"), CEP_WORD("sts:ok"));
CEP_DEFINE_STATIC_DT(dt_sts_fail_dt, CEP_ACRO("CEP"), CEP_WORD("sts:fail"));
CEP_DEFINE_STATIC_DT(dt_cps_async_chan_serial, CEP_ACRO("CEP"), CEP_WORD("chn:serial"));
CEP_DEFINE_STATIC_DT(dt_cps_async_op_serial, CEP_ACRO("CEP"), CEP_WORD("op:serial"));
CEP_DEFINE_STATIC_DT(dt_cps_async_op_commit, CEP_ACRO("CEP"), CEP_WORD("op:commit"));
CEP_DEFINE_STATIC_DT(dt_cps_async_provider, CEP_ACRO("CEP"), CEP_WORD("prov:cps"));
CEP_DEFINE_STATIC_DT(dt_cps_async_reactor, CEP_ACRO("CEP"), CEP_WORD("react:cps"));
CEP_DEFINE_STATIC_DT(dt_cps_async_caps, CEP_ACRO("CEP"), CEP_WORD("caps:sync"));
CEP_DEFINE_STATIC_DT(dt_persist_root_name, CEP_ACRO("CEP"), CEP_WORD("persist"));
CEP_DEFINE_STATIC_DT(dt_persist_metrics_name, CEP_ACRO("CEP"), CEP_WORD("metrics"));
CEP_DEFINE_STATIC_DT(dt_persist_engine_field, CEP_ACRO("CEP"), CEP_WORD("kv_eng"));
CEP_DEFINE_STATIC_DT(dt_persist_frames_field, CEP_ACRO("CEP"), CEP_WORD("frames"));
CEP_DEFINE_STATIC_DT(dt_persist_beats_field, CEP_ACRO("CEP"), CEP_WORD("beats"));
CEP_DEFINE_STATIC_DT(dt_persist_bytes_idx_field, CEP_ACRO("CEP"), CEP_WORD("bytes_idx"));
CEP_DEFINE_STATIC_DT(dt_persist_bytes_dat_field, CEP_ACRO("CEP"), CEP_WORD("bytes_dat"));
CEP_DEFINE_STATIC_DT(dt_persist_status_name, CEP_ACRO("CEP"), CEP_WORD("branch_stat"));
CEP_DEFINE_STATIC_DT(dt_persist_config_name, CEP_ACRO("CEP"), CEP_WORD("config"));
CEP_DEFINE_STATIC_DT(dt_persist_mode_field, CEP_ACRO("CEP"), CEP_WORD("policy_mode"));
CEP_DEFINE_STATIC_DT(dt_persist_flush_every_field, CEP_ACRO("CEP"), CEP_WORD("flush_every"));
CEP_DEFINE_STATIC_DT(dt_persist_flush_on_shutdown_field, CEP_ACRO("CEP"), CEP_WORD("flush_shdn"));
CEP_DEFINE_STATIC_DT(dt_persist_allow_volatile_field, CEP_ACRO("CEP"), CEP_WORD("allow_vol"));
CEP_DEFINE_STATIC_DT(dt_persist_schedule_bt_field, CEP_ACRO("CEP"), CEP_WORD("schedule_bt"));
CEP_DEFINE_STATIC_DT(dt_persist_last_bt_field, CEP_ACRO("CEP"), CEP_WORD("last_bt"));
CEP_DEFINE_STATIC_DT(dt_persist_pending_mut_field, CEP_ACRO("CEP"), CEP_WORD("pend_mut"));
CEP_DEFINE_STATIC_DT(dt_persist_dirty_ents_field, CEP_ACRO("CEP"), CEP_WORD("dirty_ents"));
CEP_DEFINE_STATIC_DT(dt_persist_dirty_bytes_field, CEP_ACRO("CEP"), CEP_WORD("dirty_bytes"));
CEP_DEFINE_STATIC_DT(dt_persist_pin_count_field, CEP_ACRO("CEP"), CEP_WORD("pin_count"));
CEP_DEFINE_STATIC_DT(dt_persist_last_frame_field, CEP_ACRO("CEP"), CEP_WORD("frame_last"));
CEP_DEFINE_STATIC_DT(dt_persist_last_cause_field, CEP_ACRO("CEP"), CEP_WORD("cause_last"));
CEP_DEFINE_STATIC_DT(dt_persist_flush_bytes_field, CEP_ACRO("CEP"), CEP_WORD("flush_bytes"));
CEP_DEFINE_STATIC_DT(dt_persist_flush_pins_field, CEP_ACRO("CEP"), CEP_WORD("flush_pins"));
CEP_DEFINE_STATIC_DT(dt_persist_snapshot_field, CEP_ACRO("CEP"), CEP_WORD("snapshot_ro"));
CEP_DEFINE_STATIC_DT(dt_branch_snapshot_enable_field, CEP_ACRO("CEP"), CEP_WORD("snapshot"));
CEP_DEFINE_STATIC_DT(dt_persist_hist_ram_beats_field, CEP_ACRO("CEP"), CEP_WORD("hist_ram_bt"));
CEP_DEFINE_STATIC_DT(dt_persist_hist_ram_versions_field, CEP_ACRO("CEP"), CEP_WORD("hist_ram_v"));
CEP_DEFINE_STATIC_DT(dt_persist_ram_quota_field, CEP_ACRO("CEP"), CEP_WORD("ram_quota"));
CEP_DEFINE_STATIC_DT(dt_persist_cached_beats_field, CEP_ACRO("CEP"), CEP_WORD("cache_bt"));
CEP_DEFINE_STATIC_DT(dt_persist_cached_versions_field, CEP_ACRO("CEP"), CEP_WORD("cache_ver"));
CEP_DEFINE_STATIC_DT(dt_persist_cached_bytes_field, CEP_ACRO("CEP"), CEP_WORD("cache_bytes"));

#define CPS_STORAGE_COPY_CHUNK 65536u

static const char k_cps_storage_engine_name[] = "flatfile";

typedef struct {
  const char *name;
  uint8_t hash[32];
  uint64_t bytes;
  bool present;
} cps_storage_bundle_artifact;

typedef struct {
  char name[128];
  uint8_t hash[32];
  uint64_t bytes;
} cps_storage_manifest_entry;

static bool cps_storage_manifest_push(cps_storage_manifest_entry **entries,
                                      size_t *len,
                                      size_t *cap,
                                      const cps_storage_manifest_entry *src) {
  if (!entries || !len || !cap || !src) {
    return false;
  }
  if (*len == *cap) {
    size_t new_cap = (*cap == 0u) ? 4u : (*cap * 2u);
    cps_storage_manifest_entry *grown =
      (cps_storage_manifest_entry *)realloc(*entries, new_cap * sizeof(**entries));
    if (!grown) {
      return false;
    }
    *entries = grown;
    *cap = new_cap;
  }
  (*entries)[(*len)++] = *src;
  return true;
}

static bool cps_storage_format_timestamp(char *buffer, size_t length) {
  if (!buffer || length == 0u) {
    return false;
  }
  time_t now = time(NULL);
  if (now == (time_t)-1) {
    return false;
  }
  struct tm tm_snapshot;
#if defined(_POSIX_VERSION)
  if (!gmtime_r(&now, &tm_snapshot)) {
    return false;
  }
#else
  struct tm *tmp = gmtime(&now);
  if (!tmp) {
    return false;
  }
  tm_snapshot = *tmp;
#endif
  size_t written = strftime(buffer, length, "%Y%m%d-%H%M%S", &tm_snapshot);
  return written > 0u;
}

static void cps_storage_hash_to_hex(const uint8_t hash[32], char out[65]) {
  static const char k_hex[] = "0123456789abcdef";
  if (!out) {
    return;
  }
  for (size_t i = 0; i < 32u; ++i) {
    uint8_t byte = hash ? hash[i] : 0u;
    out[i * 2u] = k_hex[(byte >> 4u) & 0x0Fu];
    out[i * 2u + 1u] = k_hex[byte & 0x0Fu];
  }
  out[64] = '\0';
}

static bool cps_storage_hex_to_hash(const char *hex, uint8_t out[32]) {
  if (!hex || !out) {
    return false;
  }
  for (size_t i = 0; i < 32u; ++i) {
    char hi = hex[i * 2u];
    char lo = hex[i * 2u + 1u];
    if (!hi || !lo) {
      return false;
    }
    int hv = isdigit((unsigned char)hi) ? hi - '0'
             : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
             : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
    int lv = isdigit((unsigned char)lo) ? lo - '0'
             : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
             : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
    if (hv < 0 || lv < 0) {
      return false;
    }
    out[i] = (uint8_t)((hv << 4u) | lv);
  }
  return true;
}

static bool
cps_storage_ensure_persist_cells(const cepDT* branch_dt,
                                 cepCell** branch_cell_out,
                                 cepCell** metrics_cell_out,
                                 cepCell** status_cell_out,
                                 cepCell** config_cell_out)
{
  if (!branch_dt || !cep_dt_is_valid(branch_dt)) {
    return false;
  }
  cepCell *data_root = cep_heartbeat_data_root();
  if (!data_root) {
    return false;
  }
  cepCell *resolved_data = cep_cell_resolve(data_root);
  if (!resolved_data) {
    return false;
  }
  if (!cep_cell_require_dictionary_store(&resolved_data)) {
    return false;
  }
  cepCell *persist_root = cep_cell_ensure_dictionary_child(resolved_data,
                                                           dt_persist_root_name(),
                                                           CEP_STORAGE_RED_BLACK_T);
  if (!persist_root) {
    return false;
  }
  cepCell *branch_cell = cep_cell_ensure_dictionary_child(persist_root,
                                                          branch_dt,
                                                          CEP_STORAGE_RED_BLACK_T);
  if (!branch_cell) {
    return false;
  }
  cepCell *metrics_cell = NULL;
  cepCell *status_cell = NULL;
  cepCell *config_cell = NULL;
  if (metrics_cell_out) {
    metrics_cell = cep_cell_ensure_dictionary_child(branch_cell,
                                                    dt_persist_metrics_name(),
                                                    CEP_STORAGE_RED_BLACK_T);
    if (!metrics_cell) {
      return false;
    }
  }
  if (status_cell_out) {
    status_cell = cep_cell_ensure_dictionary_child(branch_cell,
                                                   dt_persist_status_name(),
                                                   CEP_STORAGE_RED_BLACK_T);
    if (!status_cell) {
      return false;
    }
  }
  if (config_cell_out) {
    config_cell = cep_cell_ensure_dictionary_child(branch_cell,
                                                   dt_persist_config_name(),
                                                   CEP_STORAGE_RED_BLACK_T);
    if (!config_cell) {
      return false;
    }
  }
  if (branch_cell_out) {
    *branch_cell_out = branch_cell;
  }
  if (metrics_cell_out) {
    *metrics_cell_out = metrics_cell;
  }
  if (status_cell_out) {
    *status_cell_out = status_cell;
  }
  if (config_cell_out) {
    *config_cell_out = config_cell;
  }
  return true;
}

static bool
cps_storage_publish_branch_metrics(cepBranchController* controller,
                                   const cps_stats* stats)
{
  if (!controller || !controller->branch_root) {
    return false;
  }

  cepCell *branch_cell = NULL;
  cepCell *metrics_cell = NULL;
  cepCell *status_cell = NULL;
  cepCell *config_cell = NULL;
  if (!cps_storage_ensure_persist_cells(&controller->branch_dt,
                                        &branch_cell,
                                        &metrics_cell,
                                        &status_cell,
                                        &config_cell)) {
    return false;
  }

  bool ok = true;
  ok &= cep_cell_put_text(branch_cell,
                          dt_persist_engine_field(),
                          k_cps_storage_engine_name);

  const cps_stats zero_stats = {0};
  const cps_stats *effective_stats = stats ? stats : &zero_stats;
  if (metrics_cell) {
    ok &= cep_cell_put_uint64(metrics_cell,
                              dt_persist_frames_field(),
                              effective_stats->stat_frames);
    ok &= cep_cell_put_uint64(metrics_cell,
                              dt_persist_beats_field(),
                              effective_stats->stat_beats);
    ok &= cep_cell_put_uint64(metrics_cell,
                              dt_persist_bytes_idx_field(),
                              effective_stats->stat_bytes_idx);
    ok &= cep_cell_put_uint64(metrics_cell,
                              dt_persist_bytes_dat_field(),
                              effective_stats->stat_bytes_dat);
  }

  if (status_cell) {
    uint64_t last_bt = (controller->last_persisted_bt == CEP_BEAT_INVALID)
                         ? 0u
                         : controller->last_persisted_bt;
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_last_bt_field(),
                              last_bt);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_pending_mut_field(),
                              controller->pending_mutations);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_dirty_ents_field(),
                              controller->dirty_entry_count);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_dirty_bytes_field(),
                              controller->dirty_bytes);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_pin_count_field(),
                              controller->pins);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_last_frame_field(),
                              controller->last_frame_id);
    const char* cause = cps_storage_flush_cause_label(controller->last_flush_cause);
    ok &= cep_cell_put_text(status_cell,
                            dt_persist_last_cause_field(),
                            cause);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_flush_bytes_field(),
                              controller->last_flush_bytes);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_flush_pins_field(),
                              controller->last_flush_pins);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_cached_beats_field(),
                              controller->cached_history_beats);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_cached_versions_field(),
                              controller->cached_history_versions);
    ok &= cep_cell_put_uint64(status_cell,
                              dt_persist_cached_bytes_field(),
                              controller->cached_history_bytes);
  }

  if (config_cell) {
    const cepBranchPersistPolicy* policy = cep_branch_controller_policy(controller);
    if (policy) {
      ok &= cep_cell_put_text(config_cell,
                              dt_persist_mode_field(),
                              cps_storage_policy_mode_label(policy->mode));
      ok &= cep_cell_put_uint64(config_cell,
                                dt_persist_flush_every_field(),
                                policy->flush_every_beats);
      ok &= cep_cell_put_uint64(config_cell,
                                dt_persist_flush_on_shutdown_field(),
                                policy->flush_on_shutdown ? 1u : 0u);
      ok &= cep_cell_put_uint64(config_cell,
                                dt_persist_allow_volatile_field(),
                                policy->allow_volatile_reads ? 1u : 0u);
      ok &= cep_cell_put_uint64(config_cell,
                                dt_persist_snapshot_field(),
                                policy->mode == CEP_BRANCH_PERSIST_RO_SNAPSHOT ? 1u : 0u);
      ok &= cep_cell_put_uint64(config_cell,
                                dt_persist_hist_ram_beats_field(),
                                policy->history_ram_beats);
      ok &= cep_cell_put_uint64(config_cell,
                                dt_persist_hist_ram_versions_field(),
                                policy->history_ram_versions);
      ok &= cep_cell_put_uint64(config_cell,
                                dt_persist_ram_quota_field(),
                                policy->ram_quota_bytes);
    }
    uint64_t schedule_bt = (controller->flush_scheduled_bt == CEP_BEAT_INVALID)
                             ? 0u
                             : (uint64_t)controller->flush_scheduled_bt;
    ok &= cep_cell_put_uint64(config_cell,
                              dt_persist_schedule_bt_field(),
                              schedule_bt);
  }

  return ok;
}

static void
cps_storage_publish_branch_state(cepBranchController* controller,
                                 cps_engine* engine)
{
  if (!controller) {
    return;
  }

  cps_stats stats = {0};
  const cps_stats *stats_ptr = NULL;
  if (engine && engine->ops && engine->ops->stats) {
    if (engine->ops->stats(engine, &stats) == CPS_OK) {
      stats_ptr = &stats;
    }
  }

  if (!cps_storage_publish_branch_metrics(controller, stats_ptr)) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(),
                         "persist metrics publish failed");
  }
}

static const char*
cps_storage_policy_mode_label(cepBranchPersistMode mode)
{
  switch (mode) {
    case CEP_BRANCH_PERSIST_VOLATILE:
      return "volatile";
    case CEP_BRANCH_PERSIST_COMMIT_ONCE:
      /* TODO(cpcl-commit-once): Reserve the label now but defer implementing the
       * commit-once semantics until lazy-load + eviction + snapshot policies
       * are in place so RAM usage remains bounded. */
      return "commit_once";
    case CEP_BRANCH_PERSIST_LAZY_LOAD:
      return "lazy_load";
    case CEP_BRANCH_PERSIST_LAZY_SAVE:
      return "lazy_save";
    case CEP_BRANCH_PERSIST_SCHEDULED_SAVE:
      return "scheduled";
    case CEP_BRANCH_PERSIST_ON_DEMAND:
      return "on_demand";
    case CEP_BRANCH_PERSIST_RO_SNAPSHOT:
      return "ro_snapshot";
    case CEP_BRANCH_PERSIST_DURABLE:
    default:
      return "durable";
  }
}

static const char*
cps_storage_flush_cause_label(cepBranchFlushCause cause)
{
  switch (cause) {
    case CEP_BRANCH_FLUSH_CAUSE_MANUAL:
      return "manual";
    case CEP_BRANCH_FLUSH_CAUSE_SCHEDULED:
      return "scheduled";
    case CEP_BRANCH_FLUSH_CAUSE_AUTOMATIC:
      return "automatic";
    default:
      return "unknown";
  }
}

static const char*
cps_storage_branch_label(const cepBranchController* controller,
                         char* buffer,
                         size_t capacity)
{
  if (!controller || !buffer || capacity == 0u) {
    return "<unknown>";
  }
  const cepDT* dt = &controller->branch_dt;
  unsigned long long domain = dt ? (unsigned long long)cep_id(dt->domain) : 0ull;
  unsigned long long tag = dt ? (unsigned long long)cep_id(dt->tag) : 0ull;
  int written = snprintf(buffer, capacity, "%016llx/%016llx", domain, tag);
  if (written < 0) {
    buffer[0] = '\0';
  }
  return buffer;
}

static bool cps_storage_path_exists(const char *path) {
  if (!path) {
    return false;
  }
  struct stat st;
  return stat(path, &st) == 0;
}

static bool cps_storage_mkdirs(const char *path) {
  if (!path || *path == '\0') {
    return false;
  }
  char temp[PATH_MAX];
  int need = snprintf(temp, sizeof temp, "%s", path);
  if (need < 0 || (size_t)need >= sizeof temp) {
    return false;
  }
  size_t len = strlen(temp);
  if (len == 0u) {
    return false;
  }
  for (size_t i = 1u; i < len; ++i) {
    if (temp[i] == '/' || temp[i] == '\\') {
      char saved = temp[i];
      temp[i] = '\0';
      if (temp[0] != '\0' && cep_mkdir_portable(temp, 0755) != 0 && errno != EEXIST) {
        return false;
      }
      temp[i] = saved;
    }
  }
  if (cep_mkdir_portable(temp, 0755) != 0 && errno != EEXIST) {
    return false;
  }
  return true;
}

static bool cps_storage_normalize_path(const char *path, char *buffer, size_t cap) {
  if (!path || !buffer || cap == 0u) {
    return false;
  }
  if (realpath(path, buffer)) {
#if defined(_WIN32)
    for (size_t i = 0u; buffer[i]; ++i) {
      if (buffer[i] == '\\') {
        buffer[i] = '/';
      }
    }
#endif
    return true;
  }
  if (path[0] != '/') {
    return false;
  }
  size_t need = strlen(path);
  if (need >= cap) {
    return false;
  }
  memcpy(buffer, path, need + 1u);
  return true;
}

static bool cps_storage_is_absolute_path(const char *path) {
  if (!path || !*path) {
    return false;
  }
#if defined(_WIN32)
  if ((isalpha((unsigned char)path[0]) && path[1] == ':') || (path[0] == '\\' && path[1] == '\\')) {
    return true;
  }
#endif
  return path[0] == '/';
}

static bool cps_storage_path_has_prefix(const char *path, const char *prefix) {
  if (!path || !prefix || !*prefix) {
    return false;
  }
  size_t prefix_len = strlen(prefix);
  if (strncmp(path, prefix, prefix_len) != 0) {
    return false;
  }
  char next = path[prefix_len];
  return next == '\0' || next == '/';
}

static bool cps_storage_is_external_path(const char *path) {
  if (!path || !*path) {
    return false;
  }
  if (!cps_storage_is_absolute_path(path)) {
    return false;
  }
  char normalized[PATH_MAX];
  if (!cps_storage_normalize_path(path, normalized, sizeof normalized)) {
    return false;
  }
  if (!cps_storage_path_has_prefix(normalized, "/data")) {
    return true;
  }
  return false;
}

static bool cps_storage_hash_file(const char *path, uint8_t hash_out[32], uint64_t *bytes_out) {
  if (!path || !hash_out) {
    return false;
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return false;
  }
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  uint8_t buffer[CPS_STORAGE_COPY_CHUNK];
  uint64_t total = 0u;
  bool ok = true;
  for (;;) {
    ssize_t rd = read(fd, buffer, sizeof buffer);
    if (rd == 0) {
      break;
    }
    if (rd < 0) {
      if (errno == EINTR) {
        continue;
      }
      ok = false;
      break;
    }
    blake3_hasher_update(&hasher, buffer, (size_t)rd);
    total += (uint64_t)rd;
  }
  close(fd);
  if (!ok) {
    return false;
  }
  blake3_hasher_finalize(&hasher, hash_out, 32u);
  if (bytes_out) {
    *bytes_out = total;
  }
  return true;
}

static bool cps_storage_copy_file(const char *src_path,
                                  const char *dst_path,
                                  uint64_t *bytes_out,
                                  uint8_t hash_out[32]) {
  if (!src_path || !dst_path) {
    return false;
  }
  int src_fd = open(src_path, O_RDONLY);
  if (src_fd < 0) {
    return false;
  }
  int dst_fd = open(dst_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (dst_fd < 0) {
    close(src_fd);
    return false;
  }
  blake3_hasher hasher;
  bool hash_enabled = (hash_out != NULL);
  if (hash_enabled) {
    blake3_hasher_init(&hasher);
  }
  uint8_t buffer[CPS_STORAGE_COPY_CHUNK];
  bool ok = true;
  for (;;) {
    ssize_t rd = read(src_fd, buffer, sizeof buffer);
    if (rd == 0) {
      break;
    }
    if (rd < 0) {
      if (errno == EINTR) {
        continue;
      }
      ok = false;
      break;
    }
    if (hash_enabled) {
      blake3_hasher_update(&hasher, buffer, (size_t)rd);
    }
    size_t written_total = 0u;
    while (written_total < (size_t)rd) {
      ssize_t wr = write(dst_fd, buffer + written_total, (size_t)rd - written_total);
      if (wr < 0) {
        if (errno == EINTR) {
          continue;
        }
        ok = false;
        break;
      }
      written_total += (size_t)wr;
      if (bytes_out) {
        *bytes_out += (uint64_t)wr;
      }
    }
    if (!ok) {
      break;
    }
  }
  if (ok && fsync(dst_fd) != 0) {
    ok = false;
  }
  if (ok && hash_enabled) {
    blake3_hasher_finalize(&hasher, hash_out, 32u);
  }
  close(dst_fd);
  close(src_fd);
  return ok;
}

static bool cps_storage_copy_directory(const char *src_dir,
                                       const char *dst_dir,
                                       uint64_t *bytes_out) {
  if (!src_dir || !dst_dir) {
    return false;
  }
  DIR *dir = opendir(src_dir);
  if (!dir) {
    if (errno == ENOENT) {
      return true;
    }
    return false;
  }
  if (!cps_storage_mkdirs(dst_dir)) {
    closedir(dir);
    return false;
  }
  struct dirent *entry = NULL;
  bool ok = true;
  while (ok && (entry = readdir(dir))) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    char src_path[PATH_MAX];
    char dst_path[PATH_MAX];
    int need = snprintf(src_path, sizeof src_path, "%s/%s", src_dir, entry->d_name);
    if (need < 0 || (size_t)need >= sizeof src_path) {
      ok = false;
      break;
    }
    need = snprintf(dst_path, sizeof dst_path, "%s/%s", dst_dir, entry->d_name);
    if (need < 0 || (size_t)need >= sizeof dst_path) {
      ok = false;
      break;
    }
    struct stat st = {0};
    if (stat(src_path, &st) != 0) {
      ok = false;
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      ok = cps_storage_copy_directory(src_path, dst_path, bytes_out);
    } else if (S_ISREG(st.st_mode)) {
      ok = cps_storage_copy_file(src_path, dst_path, bytes_out, NULL);
    }
  }
  closedir(dir);
  return ok;
}

static bool cps_storage_merge_cas_directory(const char *src_dir,
                                            const char *dst_dir,
                                            uint64_t *bytes_out) {
  if (!src_dir || !dst_dir) {
    return false;
  }
  DIR *dir = opendir(src_dir);
  if (!dir) {
    if (errno == ENOENT) {
      return true;
    }
    return false;
  }
  if (!cps_storage_mkdirs(dst_dir)) {
    closedir(dir);
    return false;
  }
  struct dirent *entry = NULL;
  bool ok = true;
  while (ok && (entry = readdir(dir))) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    char src_path[PATH_MAX];
    char dst_path[PATH_MAX];
    int need = snprintf(src_path, sizeof src_path, "%s/%s", src_dir, entry->d_name);
    if (need < 0 || (size_t)need >= sizeof src_path) {
      ok = false;
      break;
    }
    need = snprintf(dst_path, sizeof dst_path, "%s/%s", dst_dir, entry->d_name);
    if (need < 0 || (size_t)need >= sizeof dst_path) {
      ok = false;
      break;
    }
    struct stat st = {0};
    if (stat(src_path, &st) != 0) {
      ok = false;
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      ok = cps_storage_merge_cas_directory(src_path, dst_path, bytes_out);
    } else if (S_ISREG(st.st_mode)) {
      if (cps_storage_path_exists(dst_path)) {
        continue;
      }
      ok = cps_storage_copy_file(src_path, dst_path, bytes_out, NULL);
    }
  }
  closedir(dir);
  return ok;
}

static int cps_storage_compact_bundle(const char *bundle_dir, uint64_t history_window_beats) {
  if (!bundle_dir || history_window_beats == 0u) {
    return CPS_OK;
  }
  size_t len = strlen(bundle_dir);
  while (len > 0u && bundle_dir[len - 1u] == '/') {
    --len;
  }
  if (len == 0u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  size_t leaf_start = 0u;
  for (size_t i = 0u; i < len; ++i) {
    if (bundle_dir[i] == '/') {
      leaf_start = i + 1u;
    }
  }
  if (leaf_start >= len) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  char parent[PATH_MAX];
  if (leaf_start == 0u) {
    snprintf(parent, sizeof parent, ".");
  } else {
    size_t parent_len = (leaf_start > sizeof parent - 1u) ? (sizeof parent - 1u) : leaf_start;
    memcpy(parent, bundle_dir, parent_len);
    parent[parent_len] = '\0';
    if (parent_len > 0u && parent[parent_len - 1u] == '/') {
      parent[parent_len - 1u] = '\0';
    }
  }
  const char *leaf = bundle_dir + leaf_start;

  cps_flatfile_opts opts = {
    .root_dir = parent,
    .branch_name = leaf,
    .checkpoint_interval = 128u,
    .mini_toc_hint = 64u,
    .create_branch = false,
  };

  cps_engine *engine = NULL;
  int rc = cps_flatfile_engine_open(&opts, &engine);
  if (rc != CPS_OK || !engine) {
    return rc ? rc : CPS_ERR_IO;
  }
  cps_caps_t caps = engine->caps;
  if (!engine->ops || !engine->ops->compact || !(caps & CPS_CAP_COMPACTION)) {
    engine->ops->close(engine);
    return CPS_OK;
  }
  cps_compact_opts compact_opts = {
    .history_window_beats = history_window_beats,
  };
  cps_compact_stat compact_stat = {0};
  rc = engine->ops->compact(engine, &compact_opts, &compact_stat);
  engine->ops->close(engine);
  if (rc == CPS_ERR_NOT_IMPLEMENTED) {
    return CPS_OK;
  }
  return rc;
}

static bool cps_storage_refresh_artifacts(const char *bundle_dir,
                                          cps_storage_bundle_artifact *artifacts,
                                          size_t artifact_count,
                                          uint64_t *total_bytes_out) {
  if (!bundle_dir || !artifacts) {
    return false;
  }
  uint64_t total_bytes = 0u;
  for (size_t i = 0; i < artifact_count; ++i) {
    cps_storage_bundle_artifact *artifact = &artifacts[i];
    char path[PATH_MAX];
    int need = snprintf(path, sizeof path, "%s/%s", bundle_dir, artifact->name);
    if (need < 0 || (size_t)need >= sizeof path) {
      return false;
    }
    if (!cps_storage_path_exists(path)) {
      artifact->present = false;
      artifact->bytes = 0u;
      memset(artifact->hash, 0, sizeof artifact->hash);
      continue;
    }
    artifact->present = true;
    if (!cps_storage_hash_file(path, artifact->hash, &artifact->bytes)) {
      return false;
    }
    total_bytes += artifact->bytes;
  }
  if (total_bytes_out) {
    *total_bytes_out = total_bytes;
  }
  return true;
}

static void cps_storage_sanitize_component(const char *input, char *output, size_t capacity) {
  if (!output || capacity == 0u) {
    return;
  }
  if (!input) {
    output[0] = '\0';
    return;
  }
  size_t oi = 0u;
  for (size_t i = 0u; input[i] != '\0' && oi + 1u < capacity; ++i) {
    unsigned char ch = (unsigned char)input[i];
    if (ch == '/' || ch == '\\' || ch == ':' || ch == ' ') {
      output[oi++] = '_';
      continue;
    }
    if (!isalnum(ch) && ch != '_' && ch != '-' && ch != '.') {
      output[oi++] = '_';
      continue;
    }
    output[oi++] = (char)ch;
  }
  output[oi] = '\0';
}

static bool cps_storage_id_to_text(cepID id, char *buffer, size_t capacity, size_t *out_len) {
  if (!buffer || capacity == 0u) {
    return false;
  }
  size_t len = 0u;
  if (cep_id_is_word(id)) {
    len = cep_word_to_text(cep_id(id), buffer);
  } else if (cep_id_is_acronym(id)) {
    len = cep_acronym_to_text(cep_id(id), buffer);
  } else if (cep_id_is_reference(id)) {
    size_t ref_len = 0u;
    const char *ref_text = cep_namepool_lookup(id, &ref_len);
    if (!ref_text || ref_len + 1u > capacity) {
      return false;
    }
    memcpy(buffer, ref_text, ref_len);
    buffer[ref_len] = '\0';
    len = ref_len;
  } else if (cep_id_is_numeric(id)) {
    int written = snprintf(buffer, capacity, "%" PRIu64, (uint64_t)cep_id(id));
    if (written < 0 || (size_t)written >= capacity) {
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
  if (out_len) {
    *out_len = len;
  }
  return true;
}

static bool cps_storage_dt_to_text(const cepDT *dt, char *buffer, size_t capacity) {
  if (!dt || !buffer || capacity == 0u) {
    return false;
  }
  char domain[32];
  char tag[32];
  size_t domain_len = 0u;
  size_t tag_len = 0u;
  if (!cps_storage_id_to_text(dt->domain, domain, sizeof domain, &domain_len)) {
    return false;
  }
  if (!cps_storage_id_to_text(dt->tag, tag, sizeof tag, &tag_len)) {
    return false;
  }
  size_t needed = domain_len + 1u + tag_len;
  if (needed + 1u > capacity) {
    return false;
  }
  memcpy(buffer, domain, domain_len);
  buffer[domain_len] = ':';
  memcpy(buffer + domain_len + 1u, tag, tag_len);
  buffer[needed] = '\0';
  return true;
}

static bool cps_storage_write_manifest(const char *bundle_dir,
                                       const char *branch_name,
                                       uint64_t branch_bytes,
                                       uint64_t cas_blobs,
                                       uint64_t cas_bytes,
                                       const cps_storage_bundle_artifact *artifacts,
                                       size_t artifact_count) {
  if (!bundle_dir || !branch_name) {
    return false;
  }
  char manifest_path[PATH_MAX];
  int need = snprintf(manifest_path, sizeof manifest_path, "%s/manifest.txt", bundle_dir);
  if (need < 0 || (size_t)need >= sizeof manifest_path) {
    return false;
  }
  FILE *fp = fopen(manifest_path, "w");
  if (!fp) {
    return false;
  }
  char timestamp[32];
  if (!cps_storage_format_timestamp(timestamp, sizeof timestamp)) {
    snprintf(timestamp, sizeof timestamp, "unknown");
  }
  const char *root_dir = cps_runtime_root_dir();
  fprintf(fp,
          "branch=%s\nroot=%s\ncreated=%sZ\nbranch_bytes=%" PRIu64 "\ncas_blobs=%" PRIu64 "\ncas_bytes=%" PRIu64 "\n",
          branch_name,
          root_dir ? root_dir : "-",
          timestamp,
          branch_bytes,
          cas_blobs,
          cas_bytes);
  if (artifact_count > 0u && artifacts) {
    size_t present_count = 0u;
    for (size_t i = 0; i < artifact_count; ++i) {
      if (artifacts[i].present) {
        ++present_count;
      }
    }
    fprintf(fp, "artifacts=%zu\n", present_count);
    for (size_t i = 0; i < artifact_count; ++i) {
      const cps_storage_bundle_artifact *artifact = &artifacts[i];
      if (!artifact->name || !artifact->present) {
        continue;
      }
      char hex[65];
      cps_storage_hash_to_hex(artifact->hash, hex);
      fprintf(fp,
              "artifact %s bytes=%" PRIu64 " blake3=%s\n",
              artifact->name,
              artifact->bytes,
              hex);
    }
  }
  fclose(fp);
  return true;
}

static bool cps_storage_parse_artifact_line(const char *line, cps_storage_manifest_entry *entry) {
  if (!line || !entry) {
    return false;
  }
  if (strncmp(line, "artifact ", 9) != 0) {
    return false;
  }
  const char *cursor = line + 9;
  while (*cursor == ' ') {
    ++cursor;
  }
  const char *name_end = strchr(cursor, ' ');
  if (!name_end) {
    return false;
  }
  size_t name_len = (size_t)(name_end - cursor);
  if (name_len == 0u) {
    return false;
  }
  if (name_len >= sizeof(entry->name)) {
    name_len = sizeof(entry->name) - 1u;
  }
  memcpy(entry->name, cursor, name_len);
  entry->name[name_len] = '\0';

  const char *bytes_ptr = strstr(name_end, "bytes=");
  if (!bytes_ptr) {
    return false;
  }
  bytes_ptr += 6;
  errno = 0;
  char *bytes_end = NULL;
  uint64_t byte_count = strtoull(bytes_ptr, &bytes_end, 10);
  if (errno != 0) {
    return false;
  }
  entry->bytes = byte_count;

  const char *hash_ptr = strstr(name_end, "blake3=");
  if (!hash_ptr) {
    return false;
  }
  hash_ptr += 7;
  char hex[65];
  size_t hex_len = 0u;
  while (hex_len < 64u && hash_ptr[hex_len] &&
         hash_ptr[hex_len] != '\n' &&
         hash_ptr[hex_len] != '\r' &&
         hash_ptr[hex_len] != ' ') {
    hex[hex_len] = hash_ptr[hex_len];
    ++hex_len;
  }
  if (hex_len != 64u) {
    return false;
  }
  hex[64] = '\0';
  return cps_storage_hex_to_hash(hex, entry->hash);
}

static void cps_storage_manifest_entries_free(cps_storage_manifest_entry *entries) {
  free(entries);
}

static int cps_storage_verify_bundle(const char *bundle_dir) {
  if (!bundle_dir) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  char manifest_path[PATH_MAX];
  int need = snprintf(manifest_path, sizeof manifest_path, "%s/manifest.txt", bundle_dir);
  if (need < 0 || (size_t)need >= sizeof manifest_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  FILE *fp = fopen(manifest_path, "r");
  if (!fp) {
    return CPS_ERR_IO;
  }

  cps_storage_manifest_entry *entries = NULL;
  size_t entry_len = 0u;
  size_t entry_cap = 0u;
  size_t declared_count = 0u;
  bool declared_set = false;
  char line[256];
  int rc = CPS_OK;

  while (fgets(line, sizeof line, fp)) {
    if (strncmp(line, "artifacts=", 10) == 0) {
      declared_count = (size_t)strtoull(line + 10, NULL, 10);
      declared_set = true;
      continue;
    }
    if (strncmp(line, "artifact ", 9) == 0) {
      cps_storage_manifest_entry parsed = {0};
      if (!cps_storage_parse_artifact_line(line, &parsed)) {
        rc = CPS_ERR_VERIFY;
        goto done;
      }
      if (!cps_storage_manifest_push(&entries, &entry_len, &entry_cap, &parsed)) {
        rc = CPS_ERR_NOMEM;
        goto done;
      }
    }
  }

  if (declared_set && declared_count != entry_len) {
    rc = CPS_ERR_VERIFY;
    goto done;
  }

  for (size_t i = 0; i < entry_len; ++i) {
    char artifact_path[PATH_MAX];
    need = snprintf(artifact_path, sizeof artifact_path, "%s/%s", bundle_dir, entries[i].name);
    if (need < 0 || (size_t)need >= sizeof artifact_path) {
      rc = CPS_ERR_INVALID_ARGUMENT;
      goto done;
    }
    uint8_t hash[32];
    uint64_t bytes = 0u;
    if (!cps_storage_hash_file(artifact_path, hash, &bytes)) {
      rc = CPS_ERR_IO;
      goto done;
    }
    if (bytes != entries[i].bytes || memcmp(hash, entries[i].hash, sizeof hash) != 0) {
      rc = CPS_ERR_VERIFY;
      goto done;
    }
  }

done:
  if (fp) {
    fclose(fp);
  }
  cps_storage_manifest_entries_free(entries);
  return rc;
}

static int cps_storage_export_cas_blobs(const char *bundle_dir,
                                        uint64_t *cas_bytes,
                                        uint64_t *cas_blobs) {
  if (!bundle_dir) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cepCell *cas_root = cep_heartbeat_cas_root();
  if (!cas_root) {
    return CPS_ERR_NOT_FOUND;
  }
  cepCell *resolved_root = cep_cell_resolve(cas_root);
  if (!resolved_root || !cep_cell_require_dictionary_store(&resolved_root)) {
    return CPS_ERR_NOT_FOUND;
  }
  char cas_dir[PATH_MAX];
  int need = snprintf(cas_dir, sizeof cas_dir, "%s/cas", bundle_dir);
  if (need < 0 || (size_t)need >= sizeof cas_dir) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (!cps_storage_mkdirs(cas_dir)) {
    return CPS_ERR_IO;
  }
  char manifest_path[PATH_MAX];
  need = snprintf(manifest_path, sizeof manifest_path, "%s/cas_manifest.txt", bundle_dir);
  if (need < 0 || (size_t)need >= sizeof manifest_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  FILE *manifest = fopen(manifest_path, "w");
  if (!manifest) {
    return CPS_ERR_IO;
  }
  uint64_t local_bytes = 0u;
  uint64_t local_blobs = 0u;
  for (cepCell *bucket = cep_cell_first_all(resolved_root);
       bucket;
       bucket = cep_cell_next_all(resolved_root, bucket)) {
    cepCell *resolved_bucket = cep_cell_resolve(bucket);
    if (!resolved_bucket || !cep_cell_require_dictionary_store(&resolved_bucket)) {
      continue;
    }
    char bucket_name[96];
    if (!cps_storage_dt_to_text(cep_cell_get_name(bucket), bucket_name, sizeof bucket_name)) {
      snprintf(bucket_name, sizeof bucket_name, "bucket");
    }
    char sanitized_bucket[96];
    cps_storage_sanitize_component(bucket_name, sanitized_bucket, sizeof sanitized_bucket);
    char bucket_dir[PATH_MAX];
    need = snprintf(bucket_dir, sizeof bucket_dir, "%s/%s", cas_dir, sanitized_bucket);
    if (need < 0 || (size_t)need >= sizeof bucket_dir) {
      fclose(manifest);
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_mkdirs(bucket_dir)) {
      fclose(manifest);
      return CPS_ERR_IO;
    }
    for (cepCell *item = cep_cell_first_all(resolved_bucket);
         item;
         item = cep_cell_next_all(resolved_bucket, item)) {
      cepCell *entry = cep_cell_resolve(item);
      if (!entry || !cep_cell_has_data(entry) || !entry->data) {
        continue;
      }
      const cepData *data = entry->data;
      if (data->datatype != CEP_DATATYPE_DATA && data->datatype != CEP_DATATYPE_VALUE) {
        continue;
      }
      const void *payload = cep_data_payload(data);
      size_t payload_size = data->size;
      if (!payload || payload_size == 0u) {
        continue;
      }
      char entry_name[96];
      if (!cps_storage_dt_to_text(cep_cell_get_name(entry), entry_name, sizeof entry_name)) {
        snprintf(entry_name, sizeof entry_name, "entry");
      }
      char sanitized_entry[96];
      cps_storage_sanitize_component(entry_name, sanitized_entry, sizeof sanitized_entry);
      char blob_path[PATH_MAX];
      need = snprintf(blob_path, sizeof blob_path, "%s/%s.bin", bucket_dir, sanitized_entry);
      if (need < 0 || (size_t)need >= sizeof blob_path) {
        fclose(manifest);
        return CPS_ERR_INVALID_ARGUMENT;
      }
      FILE *blob = fopen(blob_path, "wb");
      if (!blob) {
        fclose(manifest);
        return CPS_ERR_IO;
      }
      size_t written = fwrite(payload, 1u, payload_size, blob);
      fclose(blob);
      if (written != payload_size) {
        fclose(manifest);
        return CPS_ERR_IO;
      }
      local_bytes += payload_size;
      local_blobs += 1u;
      fprintf(manifest,
              "%s/%s size=%zu hash=%" PRIx64 "\n",
              bucket_name,
              entry_name,
              payload_size,
              data->hash);
    }
  }
  fclose(manifest);
  if (cas_bytes) {
    *cas_bytes = local_bytes;
  }
  if (cas_blobs) {
    *cas_blobs = local_blobs;
  }
  return (local_blobs > 0u) ? CPS_OK : CPS_ERR_NOT_FOUND;
}

static int cps_storage_export_branch_bundle(const char *branch_dir,
                                            const char *branch_name,
                                            const char *target_path,
                                            uint64_t history_window_beats,
                                            bool external_target,
                                            char *bundle_path,
                                            size_t bundle_path_len,
                                            uint64_t *copied_bytes,
                                            uint64_t *cas_bytes,
                                            uint64_t *cas_blobs) {
#ifdef CEP_ENABLE_DEBUG
  const bool env_debug = getenv("EXPORT_DEBUG") != NULL;
#else
  const bool env_debug = false;
#endif
  if (!branch_dir || !branch_name || !bundle_path || bundle_path_len == 0u) {
    CEP_DEBUG_PRINTF_IF(env_debug,
                        "[export_bundle] missing args branch_dir=%p branch_name=%p bundle_path=%p len=%zu\n",
                        (void *)branch_dir,
                        (void *)branch_name,
                        (void *)bundle_path,
                        bundle_path_len);
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (copied_bytes) {
    *copied_bytes = 0u;
  }
  if (cas_bytes) {
    *cas_bytes = 0u;
  }
  if (cas_blobs) {
    *cas_blobs = 0u;
  }
  char bundle_dir[PATH_MAX];
  if (target_path && *target_path) {
    int need = snprintf(bundle_dir, sizeof bundle_dir, "%s", target_path);
    if (need < 0 || (size_t)need >= sizeof bundle_dir) {
      CEP_DEBUG_PRINTF_IF(env_debug,
                          "[export_bundle] target path overflow need=%d cap=%zu\n",
                          need,
                          sizeof bundle_dir);
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (external_target && !cps_storage_is_absolute_path(bundle_dir)) {
      CEP_DEBUG_PRINTF_IF(env_debug, "[export_bundle] external target not absolute\n");
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (cps_storage_path_exists(bundle_dir)) {
      return CPS_ERR_CONFLICT;
    }
    if (!cps_storage_mkdirs(bundle_dir)) {
      return CPS_ERR_IO;
    }
  } else {
    char exports_dir[PATH_MAX];
    int need = snprintf(exports_dir, sizeof exports_dir, "%s/exports", branch_dir);
    if (need < 0 || (size_t)need >= sizeof exports_dir) {
      CEP_DEBUG_PRINTF_IF(env_debug,
                          "[export_bundle] exports dir overflow need=%d cap=%zu\n",
                          need,
                          sizeof exports_dir);
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_mkdirs(exports_dir)) {
      return CPS_ERR_IO;
    }
    char timestamp[32];
    if (!cps_storage_format_timestamp(timestamp, sizeof timestamp)) {
      return CPS_ERR_IO;
    }
    char branch_slug[96];
    cps_storage_sanitize_component(branch_name, branch_slug, sizeof branch_slug);
    if (branch_slug[0] == '\0') {
      snprintf(branch_slug, sizeof branch_slug, "branch");
    }
    int need_dir = snprintf(bundle_dir, sizeof bundle_dir, "%s/%s-%s", exports_dir, branch_slug, timestamp);
    if (need_dir < 0 || (size_t)need_dir >= sizeof bundle_dir) {
      CEP_DEBUG_PRINTF_IF(env_debug,
                          "[export_bundle] bundle dir overflow need=%d cap=%zu\n",
                          need_dir,
                          sizeof bundle_dir);
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_mkdirs(bundle_dir)) {
      return CPS_ERR_IO;
    }
  }
  cps_storage_bundle_artifact artifacts[] = {
    {.name = "branch.meta"},
    {.name = "branch.idx"},
    {.name = "branch.dat"},
    {.name = "branch.ckp"},
    {.name = "branch.frames"},
  };
  int need = 0;
  for (size_t i = 0; i < sizeof artifacts / sizeof artifacts[0]; ++i) {
    cps_storage_bundle_artifact *artifact = &artifacts[i];
    char src_path[PATH_MAX];
    need = snprintf(src_path, sizeof src_path, "%s/%s", branch_dir, artifact->name);
    if (need < 0 || (size_t)need >= sizeof src_path) {
      CEP_DEBUG_PRINTF_IF(env_debug,
                          "[export_bundle] src path overflow need=%d cap=%zu\n",
                          need,
                          sizeof src_path);
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_path_exists(src_path)) {
      continue;
    }
    struct stat st = {0};
    if (stat(src_path, &st) == 0 && S_ISREG(st.st_mode)) {
      artifact->bytes = (uint64_t)st.st_size;
    } else {
      artifact->bytes = 0u;
    }
    char dst_path[PATH_MAX];
    need = snprintf(dst_path, sizeof dst_path, "%s/%s", bundle_dir, artifact->name);
    if (need < 0 || (size_t)need >= sizeof dst_path) {
      CEP_DEBUG_PRINTF_IF(env_debug,
                          "[export_bundle] dst path overflow need=%d cap=%zu\n",
                          need,
                          sizeof dst_path);
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_copy_file(src_path, dst_path, copied_bytes, artifact->hash)) {
      return CPS_ERR_IO;
    }
    artifact->present = true;
  }
  uint64_t local_cas_bytes = 0u;
  uint64_t local_cas_blobs = 0u;
  int cas_rc = cps_storage_export_cas_blobs(bundle_dir, &local_cas_bytes, &local_cas_blobs);
  if (cas_rc != CPS_OK && cas_rc != CPS_ERR_NOT_FOUND) {
    return cas_rc;
  }
  if (cas_bytes) {
    *cas_bytes = local_cas_bytes;
  }
  if (cas_blobs) {
    *cas_blobs = local_cas_blobs;
  }
  uint64_t total_branch_bytes = 0u;
  bool want_compact = history_window_beats > 0u;
  bool have_idx = false;
  bool have_dat = false;
  for (size_t i = 0; i < sizeof artifacts / sizeof artifacts[0]; ++i) {
    if (!artifacts[i].present) {
      continue;
    }
    if (strcmp(artifacts[i].name, "branch.idx") == 0) {
      have_idx = true;
    } else if (strcmp(artifacts[i].name, "branch.dat") == 0) {
      have_dat = true;
    }
  }
  if (want_compact && (!have_idx || !have_dat)) {
    want_compact = false;
  }
  if (want_compact) {
    int compact_rc = cps_storage_compact_bundle(bundle_dir, history_window_beats);
    if (compact_rc != CPS_OK) {
      return compact_rc;
    }
  }
  if (!cps_storage_refresh_artifacts(bundle_dir,
                                     artifacts,
                                     sizeof artifacts / sizeof artifacts[0],
                                     &total_branch_bytes)) {
    return CPS_ERR_IO;
  }
  if (!cps_storage_write_manifest(bundle_dir,
                                  branch_name,
                                  total_branch_bytes,
                                  local_cas_blobs,
                                  local_cas_bytes,
                                  artifacts,
                                  sizeof artifacts / sizeof artifacts[0])) {
    return CPS_ERR_IO;
  }
  int verify_rc = cps_storage_verify_bundle(bundle_dir);
  if (verify_rc != CPS_OK) {
    return verify_rc;
  }
  if (copied_bytes) {
    *copied_bytes = total_branch_bytes;
  }
  if (cas_bytes) {
    *cas_bytes = local_cas_bytes;
  }
  if (cas_blobs) {
    *cas_blobs = local_cas_blobs;
  }
  int path_need = snprintf(bundle_path, bundle_path_len, "%s", bundle_dir);
  if (path_need < 0 || (size_t)path_need >= bundle_path_len) {
    CEP_DEBUG_PRINTF_IF(env_debug,
                        "[export_bundle] bundle path overflow need=%d cap=%zu\n",
                        path_need,
                        bundle_path_len);
    return CPS_ERR_INVALID_ARGUMENT;
  }
  return CPS_OK;
}

static int cps_storage_stage_bundle(const char *branch_dir,
                                    const char *bundle_dir,
                                    char *stage_dir,
                                    size_t stage_dir_len,
                                    uint64_t *staged_bytes) {
  if (!branch_dir || !bundle_dir || !stage_dir || stage_dir_len == 0u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (staged_bytes) {
    *staged_bytes = 0u;
  }

  int verify_rc = cps_storage_verify_bundle(bundle_dir);
  if (verify_rc != CPS_OK) {
    return verify_rc;
  }

  char imports_dir[PATH_MAX];
  int need = snprintf(imports_dir, sizeof imports_dir, "%s/imports", branch_dir);
  if (need < 0 || (size_t)need >= sizeof imports_dir) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (!cps_storage_mkdirs(imports_dir)) {
    return CPS_ERR_IO;
  }

  const char *label = strrchr(bundle_dir, '/');
  label = label ? (label[1] ? label + 1 : label) : bundle_dir;
  char label_slug[96];
  cps_storage_sanitize_component(label, label_slug, sizeof label_slug);
  if (label_slug[0] == '\0') {
    snprintf(label_slug, sizeof label_slug, "bundle");
  }

  char timestamp[32];
  if (!cps_storage_format_timestamp(timestamp, sizeof timestamp)) {
    return CPS_ERR_IO;
  }

  char stage_path[PATH_MAX];
  need = snprintf(stage_path, sizeof stage_path, "%s/%s-%s", imports_dir, label_slug, timestamp);
  if (need < 0 || (size_t)need >= sizeof stage_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (!cps_storage_mkdirs(stage_path)) {
    return CPS_ERR_IO;
  }

  static const char *k_artifacts[] = {
    "branch.meta",
    "branch.idx",
    "branch.dat",
    "branch.ckp",
    "branch.frames",
  };

  for (size_t i = 0; i < sizeof k_artifacts / sizeof k_artifacts[0]; ++i) {
    char src_path[PATH_MAX];
    need = snprintf(src_path, sizeof src_path, "%s/%s", bundle_dir, k_artifacts[i]);
    if (need < 0 || (size_t)need >= sizeof src_path) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_path_exists(src_path)) {
      continue;
    }
    char dst_path[PATH_MAX];
    need = snprintf(dst_path, sizeof dst_path, "%s/%s", stage_path, k_artifacts[i]);
    if (need < 0 || (size_t)need >= sizeof dst_path) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_copy_file(src_path, dst_path, staged_bytes, NULL)) {
      return CPS_ERR_IO;
    }
  }

  char bundle_manifest[PATH_MAX];
  need = snprintf(bundle_manifest, sizeof bundle_manifest, "%s/cas_manifest.txt", bundle_dir);
  if (need < 0 || (size_t)need >= sizeof bundle_manifest) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (cps_storage_path_exists(bundle_manifest)) {
    char staged_manifest[PATH_MAX];
    need = snprintf(staged_manifest, sizeof staged_manifest, "%s/cas_manifest.txt", stage_path);
    if (need < 0 || (size_t)need >= sizeof staged_manifest) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_copy_file(bundle_manifest, staged_manifest, staged_bytes, NULL)) {
      return CPS_ERR_IO;
    }
  }

  char cas_src[PATH_MAX];
  need = snprintf(cas_src, sizeof cas_src, "%s/cas", bundle_dir);
  if (need < 0 || (size_t)need >= sizeof cas_src) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  char cas_dst[PATH_MAX];
  need = snprintf(cas_dst, sizeof cas_dst, "%s/cas", stage_path);
  if (need < 0 || (size_t)need >= sizeof cas_dst) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (!cps_storage_copy_directory(cas_src, cas_dst, staged_bytes)) {
    return CPS_ERR_IO;
  }

  int copy_need = snprintf(stage_dir, stage_dir_len, "%s", stage_path);
  if (copy_need < 0 || (size_t)copy_need >= stage_dir_len) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  return CPS_OK;
}

static int cps_storage_promote_bundle(const char *stage_dir) {
  if (!stage_dir) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  const char *branch_dir = cps_runtime_branch_dir();
  if (!branch_dir) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  static const char *k_artifacts[] = {
    "branch.meta",
    "branch.idx",
    "branch.dat",
    "branch.ckp",
    "branch.frames",
  };

  for (size_t i = 0; i < sizeof k_artifacts / sizeof k_artifacts[0]; ++i) {
    char src_path[PATH_MAX];
    int need = snprintf(src_path, sizeof src_path, "%s/%s", stage_dir, k_artifacts[i]);
    if (need < 0 || (size_t)need >= sizeof src_path) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_path_exists(src_path)) {
      if (strcmp(k_artifacts[i], "branch.idx") == 0 || strcmp(k_artifacts[i], "branch.dat") == 0) {
        return CPS_ERR_VERIFY;
      }
      continue;
    }
    char dst_path[PATH_MAX];
    need = snprintf(dst_path, sizeof dst_path, "%s/%s", branch_dir, k_artifacts[i]);
    if (need < 0 || (size_t)need >= sizeof dst_path) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    char tmp_path[PATH_MAX];
    need = snprintf(tmp_path, sizeof tmp_path, "%s.import", dst_path);
    if (need < 0 || (size_t)need >= sizeof tmp_path) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_copy_file(src_path, tmp_path, NULL, NULL)) {
      return CPS_ERR_IO;
    }
    if (rename(tmp_path, dst_path) != 0) {
      unlink(tmp_path);
      return CPS_ERR_IO;
    }
  }
  char stage_cas[PATH_MAX];
  int need = snprintf(stage_cas, sizeof stage_cas, "%s/cas", stage_dir);
  if (need < 0 || (size_t)need >= sizeof stage_cas) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (cps_storage_path_exists(stage_cas)) {
    char branch_cas[PATH_MAX];
    need = snprintf(branch_cas, sizeof branch_cas, "%s/cas", branch_dir);
    if (need < 0 || (size_t)need >= sizeof branch_cas) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    if (!cps_storage_merge_cas_directory(stage_cas, branch_cas, NULL)) {
      return CPS_ERR_IO;
    }
  }
  return CPS_OK;
}

typedef struct {
  cepFlatReader *reader;
  uint64_t bytes_written;
} cpsStorageSink;

typedef struct {
  cepBranchController* controller;
  cepFlatBranchFrameInfo frame_info;
  cepBranchFlushCause reason;
  bool clear_force_request;
  bool clear_schedule_request;
} cpsBranchFrameRequest;

static bool
cps_storage_clear_dirty_entry_cb(cepEntry* entry, void* ctx)
{
  (void)ctx;
  if (!entry || !entry->cell) {
    return true;
  }
  cepCell* resolved = cep_cell_resolve(entry->cell);
  if (!resolved) {
    return true;
  }
  if (resolved->data) {
    resolved->data->dirty = 0u;
  }
  if (resolved->store) {
    resolved->store->dirty = 0u;
  }
  return true;
}

static void
cps_storage_clear_dirty_flags_for_root(cepCell* root)
{
  if (!root) {
    return;
  }
  cepCell* resolved = cep_cell_resolve(root);
  if (!resolved) {
    return;
  }
  cepEntry entry = {0};
  (void)cep_cell_deep_traverse_all(resolved,
                                   cps_storage_clear_dirty_entry_cb,
                                   NULL,
                                   NULL,
                                   &entry);
}

static void
cps_storage_clear_branch_dirty_flags(cepBranchController* controller)
{
  if (!controller || !controller->branch_root) {
    return;
  }
  cps_storage_clear_dirty_flags_for_root(controller->branch_root);
  cep_branch_controller_clear_dirty(controller);
}


static atomic_uint_fast64_t g_cps_async_req_counter = 0;
static cepOID g_cps_async_channel_oid = {0};

struct cpsStorageAsyncCommitCtx {
  uint32_t refcount;
  bool     registered;
  bool     pending;
  bool     completed;
  bool     success;
  int      error_code;
  uint64_t bytes_done;
  cepDT    request_name;
};

static void cps_storage_async_mark_failed(cpsStorageAsyncCommitCtx* ctx,
                                          uint64_t bytes,
                                          int error_code,
                                          const char* detail);

static void cps_storage_async_ensure_channel(void) {
  cepOID current_oid = cep_async_ops_oid();
  if (!cep_oid_is_valid(current_oid)) {
    return;
  }
  if (cep_oid_is_valid(g_cps_async_channel_oid) &&
      current_oid.domain == g_cps_async_channel_oid.domain &&
      current_oid.tag == g_cps_async_channel_oid.tag) {
    return;
  }
  cepOpsAsyncChannelInfo info = {
    .target_path = "/data/persist",
    .has_target_path = true,
    .provider = *dt_cps_async_provider(),
    .has_provider = true,
    .reactor = *dt_cps_async_reactor(),
    .has_reactor = true,
    .caps = *dt_cps_async_caps(),
    .has_caps = true,
    .shim = true,
    .shim_known = true,
  };
  if (cep_async_register_channel(current_oid, dt_cps_async_chan_serial(), &info)) {
    g_cps_async_channel_oid = current_oid;
  }
}

static cepDT cps_storage_async_make_request_name(void) {
  uint64_t id = atomic_fetch_add(&g_cps_async_req_counter, 1u);
  char label[12];
  uint64_t suffix = id % 100000000ULL;
  (void)snprintf(label, sizeof label, "sr%08" PRIu64, (uint64_t)suffix);
  return cep_ops_make_dt(label);
}

static bool cps_storage_async_register_request(const cepDT* opcode,
                                               size_t expected_bytes,
                                               cepDT* out_name) {
  if (!out_name || !opcode) {
    return false;
  }
  cps_storage_async_ensure_channel();
  *out_name = cps_storage_async_make_request_name();
  cepOpsAsyncIoReqInfo info = {
    .state = *dt_ist_exec_dt(),
    .channel = *dt_cps_async_chan_serial(),
    .opcode = *opcode,
    .beats_budget = 1u,
    .has_beats_budget = true,
  };
  if (expected_bytes > 0u) {
    info.has_bytes_expected = true;
    info.bytes_expected = expected_bytes;
  }
  return cep_async_register_request(cep_async_ops_oid(), out_name, &info);
}

static void cps_storage_async_finish_request(const cepDT* name,
                                             const cepDT* opcode,
                                             bool success,
                                             uint64_t bytes,
                                             int error_code) {
  if (!name) {
    return;
  }
  cepOpsAsyncIoReqInfo done = {
    .state = success ? *dt_ist_ok_dt() : *dt_ist_fail_dt(),
    .channel = *dt_cps_async_chan_serial(),
    .opcode = opcode ? *opcode : *dt_cps_async_op_serial(),
    .has_bytes_done = true,
    .bytes_done = bytes,
  };
  if (!success) {
    done.has_errno = true;
    done.errno_code = error_code;
  }
  (void)cep_async_post_completion(cep_async_ops_oid(), name, &done);
}

static void cps_storage_async_commit_on_complete(bool success,
                                                 uint64_t bytes,
                                                 int error_code,
                                                 void* context) {
  cpsStorageAsyncCommitCtx* commit = (cpsStorageAsyncCommitCtx*)context;
  if (!commit) {
    return;
  }
  if (commit->completed) {
    commit->pending = false;
    cps_storage_async_commit_ctx_release(commit);
    return;
  }
  if (!success) {
    cps_storage_async_mark_failed(commit, bytes, error_code, "serializer async completion failed");
    cps_storage_async_commit_ctx_release(commit);
    return;
  }
  commit->pending = false;
  commit->completed = true;
  commit->success = true;
  commit->error_code = error_code;
  commit->bytes_done = bytes;
  cps_storage_async_commit_ctx_release(commit);
}

static cpsStorageAsyncCommitCtx*
cps_storage_async_commit_ctx_create(const cepDT* request_name) {
  if (!request_name) {
    return NULL;
  }
  cpsStorageAsyncCommitCtx* ctx = cep_malloc0(sizeof *ctx);
  if (!ctx) {
    return NULL;
  }
  ctx->refcount = 1u;
  ctx->registered = true;
  ctx->pending = true;
  ctx->completed = false;
  ctx->success = false;
  ctx->error_code = 0;
  ctx->bytes_done = 0u;
  ctx->request_name = *request_name;
  return ctx;
}

static void cps_storage_async_commit_ctx_addref(cpsStorageAsyncCommitCtx* ctx) {
  if (!ctx) {
    return;
  }
  ++ctx->refcount;
}

static void cps_storage_async_commit_ctx_release(cpsStorageAsyncCommitCtx* ctx) {
  if (!ctx) {
    return;
  }
  if (ctx->refcount == 0u) {
    return;
  }
  --ctx->refcount;
  if (ctx->refcount == 0u) {
    cep_free(ctx);
  }
}

static void cps_storage_async_finalize_success(cpsStorageAsyncCommitCtx* ctx) {
  if (!ctx) {
    return;
  }
  ctx->pending = false;
  if (ctx->registered) {
    cps_storage_async_finish_request(&ctx->request_name,
                                     dt_cps_async_op_commit(),
                                     true,
                                     ctx->bytes_done,
                                     ctx->error_code);
    ctx->registered = false;
  }
}

static void cps_storage_async_mark_failed(cpsStorageAsyncCommitCtx* ctx,
                                          uint64_t bytes,
                                          int error_code,
                                          const char* detail) {
  if (detail) {
    cps_storage_emit_async_cei(detail);
  }
  if (!ctx) {
    return;
  }
  ctx->pending = false;
  ctx->completed = true;
  ctx->success = false;
  ctx->error_code = error_code;
  ctx->bytes_done = bytes;
  if (ctx->registered) {
    cps_storage_async_finish_request(&ctx->request_name,
                                     dt_cps_async_op_commit(),
                                     false,
                                     bytes,
                                     error_code);
    ctx->registered = false;
  }
}

static uint64_t cps_storage_elapsed_ms(const struct timespec* start,
                                       const struct timespec* now) {
  if (!start || !now) {
    return 0u;
  }
  time_t sec = now->tv_sec - start->tv_sec;
  long nsec = now->tv_nsec - start->tv_nsec;
  if (nsec < 0) {
    --sec;
    nsec += 1000000000L;
  }
  uint64_t elapsed = (uint64_t)sec * 1000u;
  elapsed += (uint64_t)(nsec / 1000000L);
  return elapsed;
}

static bool cps_storage_async_wait_for_commit(cpsStorageAsyncCommitCtx* ctx) {
  if (!ctx) {
    return true;
  }
  cepAsyncRuntimeState* async_state = cep_runtime_async_state(cep_runtime_default());
  if (!async_state) {
    cps_storage_async_mark_failed(ctx, ctx->bytes_done, -EIO, "async runtime unavailable");
    return false;
  }
  struct timespec start = {0};
  (void)clock_gettime(CLOCK_MONOTONIC, &start);
  while (ctx->pending) {
    cep_async_runtime_on_phase(async_state, CEP_BEAT_COMPUTE);
    if (!ctx->pending) {
      break;
    }
    struct timespec now = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t elapsed_ms = cps_storage_elapsed_ms(&start, &now);
    if (elapsed_ms >= CPS_STORAGE_ASYNC_COMMIT_TIMEOUT_MS) {
      cps_storage_async_mark_failed(ctx, ctx->bytes_done, -ETIMEDOUT, "async commit timed out");
      return false;
    }
    struct timespec sleep_ts = {.tv_sec = 0, .tv_nsec = CPS_STORAGE_ASYNC_WAIT_POLL_NS};
    (void)nanosleep(&sleep_ts, NULL);
  }
  if (!ctx->completed) {
    cps_storage_async_mark_failed(ctx, ctx->bytes_done, -EIO, "async commit callback missing");
    return false;
  }
  return ctx->success;
}

static void
cps_storage_emit_topic_cei(const cepDT* severity,
                           const char* topic,
                           const char* detail)
{
  if (!severity || !topic || !detail) {
    return;
  }
  cepCeiRequest req = {
    .severity = *severity,
    .topic = topic,
    .topic_len = 0u,
    .topic_intern = true,
    .note = detail,
    .note_len = 0u,
    .origin_kind = "cps_storage",
    .emit_signal = false,
    .attach_to_op = false,
    .ttl_forever = true,
  };
  (void)cep_cei_emit(&req);
}

static void
cps_storage_emit_cei(const cepDT *severity, const char *detail)
{
  cps_storage_emit_topic_cei(severity, k_cps_topic_storage_commit, detail);
}

static void cps_storage_emit_async_cei(const char *detail) {
  if (!detail) {
    return;
  }
  cepCeiRequest req = {
    .severity = *dt_cps_storage_sev_warn(),
    .topic = k_cps_topic_storage_async,
    .topic_len = 0u,
    .topic_intern = true,
    .note = detail,
    .note_len = 0u,
    .origin_kind = "cps_storage",
    .emit_signal = false,
    .attach_to_op = false,
    .ttl_forever = true,
  };
  (void)cep_cei_emit(&req);
}

static bool cps_storage_reader_sink(void *context, const uint8_t *chunk, size_t size) {
  cpsStorageSink *sink = (cpsStorageSink *)context;
  if (!sink || !sink->reader || !chunk || size == 0u) {
    return false;
  }
  if (!cep_flat_reader_feed(sink->reader, chunk, size)) {
    return false;
  }
  sink->bytes_written += size;
  return true;
}

static bool cps_storage_apply_reader(cps_engine *engine,
                                     cepFlatReader *reader,
                                     const char** error_stage,
                                     int* error_code) {
  if (!engine || !engine->ops || !reader) {
    return false;
  }

  size_t record_count = 0u;
  const cepFlatRecordView *records = cep_flat_reader_records(reader, &record_count);
  const cepFlatFrameConfig *frame = cep_flat_reader_frame(reader);
  uint64_t beat_no = frame ? frame->beat_number : 0u;
  if (beat_no == 0u) {
    cepBeatNumber current = cep_beat_index();
    if (current != CEP_BEAT_INVALID) {
      beat_no = (uint64_t)current;
    }
  }

  cps_txn *txn = NULL;
  if (!engine->ops->begin_beat || !engine->ops->put_record || !engine->ops->commit_beat) {
    return false;
  }
  int rc = engine->ops->begin_beat(engine, beat_no, &txn);
  if (rc != CPS_OK || !txn) {
    if (error_stage)
      *error_stage = "begin_beat";
    if (error_code)
      *error_code = rc;
    return false;
  }

  for (size_t i = 0; i < record_count; ++i) {
    cps_slice key = {
      .data = records[i].key.data,
      .len = records[i].key.size,
    };
    cps_slice value = {
      .data = records[i].body.data,
      .len = records[i].body.size,
    };
    rc = engine->ops->put_record(txn, key, value, records[i].type);
    if (rc != CPS_OK) {
      if (engine->ops->abort_beat) {
        engine->ops->abort_beat(txn);
      }
      if (error_stage)
        *error_stage = "put_record";
      if (error_code)
        *error_code = rc;
      return false;
    }
  }

  cps_frame_meta meta = {0};
  meta.beat = beat_no;
  const uint8_t *merkle = cep_flat_reader_merkle_root(reader);
  if (merkle) {
    memcpy(meta.merkle, merkle, sizeof meta.merkle);
  }
  rc = engine->ops->commit_beat(txn, &meta);
  if (rc != CPS_OK) {
    if (error_stage)
      *error_stage = "commit_beat";
    if (error_code)
      *error_code = rc;
    return false;
  }
  txn = NULL;
  return true;
}

static bool
cps_storage_branch_requests_append(cpsBranchFrameRequest** requests,
                                   size_t* count,
                                   size_t* capacity,
                                   const cpsBranchFrameRequest* candidate)
{
  if (!requests || !count || !capacity || !candidate) {
    return false;
  }
  if (*count == *capacity) {
    size_t new_cap = *capacity ? (*capacity * 2u) : 4u;
    cpsBranchFrameRequest* grown =
        (cpsBranchFrameRequest*)realloc(*requests,
                                        new_cap * sizeof **requests);
    if (!grown) {
      return false;
    }
    *requests = grown;
    *capacity = new_cap;
  }
  (*requests)[(*count)++] = *candidate;
  return true;
}

static bool
cps_storage_emit_branch_frame(cepCell* target,
                              const cepFlatBranchFrameInfo* branch_info,
                              cps_engine* engine)
{
  if (!target || !engine || !engine->ops) {
    return false;
  }

  if (!branch_info) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(),
                         "branch frame emission missing metadata");
    return false;
  }

  cepCell* resolved = cep_cell_resolve(target);
  if (!resolved) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(), "serializer target resolve failed");
    return false;
  }

  cepFlatReader* reader = cep_flat_reader_create();
  if (!reader) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(), "failed to allocate flat reader for persistence");
    return false;
  }

  cpsStorageSink sink = {
    .reader = reader,
    .bytes_written = 0u,
  };

  cepDT async_commit_req = {0};
  cpsStorageAsyncCommitCtx* async_commit_ctx = NULL;
  bool ok = false;
  bool callback_ref_taken = false;

  if (!cps_storage_async_register_request(dt_cps_async_op_commit(),
                                          0u,
                                          &async_commit_req)) {
    cps_storage_emit_async_cei("async commit registration failed");
    goto out;
  }

  async_commit_ctx = cps_storage_async_commit_ctx_create(&async_commit_req);
  if (!async_commit_ctx) {
    cps_storage_emit_async_cei("async commit context allocation failed");
    cps_storage_async_finish_request(&async_commit_req,
                                     dt_cps_async_op_commit(),
                                     false,
                                     0u,
                                     -ENOMEM);
    goto out;
  }

  cepFlatStreamAsyncStats stream_stats = {
    .require_sync_copy = false,
    .completion_cb = cps_storage_async_commit_on_complete,
    .completion_ctx = async_commit_ctx,
  };

  cps_storage_async_commit_ctx_addref(async_commit_ctx);
  callback_ref_taken = true;

  bool emitted = cep_flat_stream_emit_branch_async(resolved,
                                                   branch_info,
                                                   NULL,
                                                   cps_storage_reader_sink,
                                                   &sink,
                                                   CEP_FLAT_STREAM_DEFAULT_BLOB_PAYLOAD,
                                                   &stream_stats);
  if (!emitted) {
    cps_storage_emit_cei(dt_cps_storage_sev_crit(), "serializer frame emit/parse failed");
    cps_storage_async_mark_failed(async_commit_ctx,
                                  sink.bytes_written,
                                  -EIO,
                                  "serializer async emission failed");
    if (callback_ref_taken) {
      cps_storage_async_commit_ctx_release(async_commit_ctx);
      callback_ref_taken = false;
    }
    goto out;
  }

  if (!stream_stats.async_mode || stream_stats.fallback_used) {
    cps_storage_async_mark_failed(async_commit_ctx,
                                  sink.bytes_written,
                                  -EIO,
                                  "serializer fallback triggered");
    goto out;
  }

  if (!cps_storage_async_wait_for_commit(async_commit_ctx)) {
    goto out;
  }

  if (!cep_flat_reader_commit(reader) || !cep_flat_reader_ready(reader)) {
    cps_storage_emit_cei(dt_cps_storage_sev_crit(), "serializer frame emit/parse failed");
    cps_storage_async_mark_failed(async_commit_ctx,
                                  sink.bytes_written,
                                  -EIO,
                                  "serializer async reader incomplete");
    goto out;
  }

  const char* commit_error_stage = NULL;
  int commit_error_code = CPS_OK;
  ok = cps_storage_apply_reader(engine, reader, &commit_error_stage, &commit_error_code);
  if (!ok) {
    char note[128];
    if (commit_error_stage) {
      snprintf(note,
               sizeof note,
               "CPS engine commit failed stage=%s rc=%d",
               commit_error_stage,
               commit_error_code);
      cps_storage_emit_cei(dt_cps_storage_sev_crit(), note);
    } else {
      cps_storage_emit_cei(dt_cps_storage_sev_crit(), "CPS engine commit failed");
    }
    cps_storage_async_mark_failed(async_commit_ctx,
                                  sink.bytes_written,
                                  -EIO,
                                  "CPS commit failed after async completion");
    goto out;
  }

  cps_storage_async_finalize_success(async_commit_ctx);
  ok = true;

out:
  if (async_commit_ctx) {
    if (async_commit_ctx->registered) {
      cps_storage_async_finish_request(&async_commit_ctx->request_name,
                                       dt_cps_async_op_commit(),
                                       false,
                                       sink.bytes_written,
                                       async_commit_ctx->error_code ? async_commit_ctx->error_code : -EIO);
      async_commit_ctx->registered = false;
    }
    cps_storage_async_commit_ctx_release(async_commit_ctx);
  }
  cep_flat_reader_destroy(reader);
  return ok;
}

static bool
cps_storage_commit_branch_requests(cpsBranchFrameRequest* requests,
                                   size_t request_count,
                                   cps_engine* engine)
{
  if (!requests || !engine || !engine->ops) {
    return false;
  }
  for (size_t i = 0; i < request_count; ++i) {
    cpsBranchFrameRequest* request = &requests[i];
    if (!request || !request->controller || !request->controller->branch_root) {
      return false;
    }
    char branch_label[64];
    const char* branch_str = cps_storage_branch_label(request->controller,
                                                      branch_label,
                                                      sizeof branch_label);
    char note[192];
    const char* cause_label = cps_storage_flush_cause_label(request->reason);
    snprintf(note,
             sizeof note,
             "branch=%s cause=%s frame=%llu",
             branch_str ? branch_str : "<unknown>",
             cause_label ? cause_label : "unknown",
             (unsigned long long)request->frame_info.frame_id);
    cps_storage_emit_topic_cei(dt_cps_storage_sev_info(),
                               k_cps_topic_branch_flush_begin,
                               note);
    if (!cps_storage_emit_branch_frame(request->controller->branch_root,
                                       &request->frame_info,
                                       engine)) {
      cps_storage_emit_topic_cei(dt_cps_storage_sev_warn(),
                                 k_cps_topic_branch_flush_fail,
                                 note);
      return false;
    }
    request->controller->last_frame_id = (cepOpCount)request->frame_info.frame_id;
    request->controller->last_persisted_bt = cep_beat_index();
    request->controller->last_flush_cause = request->reason;
    if (request->clear_force_request) {
      request->controller->force_flush = false;
    }
    if (request->clear_schedule_request) {
      request->controller->flush_scheduled_bt = CEP_BEAT_INVALID;
    }
    request->controller->last_flush_bytes = request->controller->dirty_bytes;
    request->controller->last_flush_pins = request->controller->pins;
    cps_storage_clear_branch_dirty_flags(request->controller);
    cps_storage_publish_branch_state(request->controller, engine);
    cps_storage_emit_topic_cei(dt_cps_storage_sev_info(),
                               k_cps_topic_branch_flush_done,
                               note);
  }
  return true;
}

static cepCell *cps_storage_ops_root(void) {
  cepCell *rt_root = cep_heartbeat_rt_root();
  if (!rt_root) {
    return NULL;
  }
  cepCell *ops = cep_cell_find_by_name(rt_root, dt_ops_root_name_cps());
  if (!ops) {
    ops = cep_cell_find_by_name_all(rt_root, dt_ops_root_name_cps());
  }
  if (!ops) {
    return NULL;
  }
  ops = cep_cell_resolve(ops);
  if (!ops || !cep_cell_is_normal(ops)) {
    return NULL;
  }
  if (!ops->store) {
    return NULL;
  }
  if (ops->store->owner != ops) {
    ops->store->owner = ops;
  }
  return ops;
}

static bool cps_storage_op_is_closed(cepCell *op) {
  cepCell *close = cep_cell_find_by_name(op, dt_close_name_cps());
  if (!close) {
    close = cep_cell_find_by_name_all(op, dt_close_name_cps());
  }
  if (!close) {
    return false;
  }
  close = cep_cell_resolve(close);
  return close && !cep_cell_is_deleted(close);
}

static cepOID cps_storage_oid_from_cell(const cepCell *cell) {
  cepOID oid = cep_oid_invalid();
  if (!cell) {
    return oid;
  }
  cepDT name = cep_dt_clean(&cell->metacell.dt);
  oid.domain = name.domain;
  oid.tag = name.tag;
  return oid;
}

static bool cps_storage_read_dt_field(cepCell *parent, const cepDT *field, cepDT *out) {
  if (!parent || !field || !out) {
    return false;
  }
  cepCell *child = cep_cell_find_by_name(parent, field);
  if (!child) {
    child = cep_cell_find_by_name_all(parent, field);
  }
  if (!child) {
    return false;
  }
  child = cep_cell_resolve(child);
  if (!child || !cep_cell_has_data(child)) {
    return false;
  }
  const cepDT *payload = (const cepDT *)cep_cell_data(child);
  if (!payload) {
    return false;
  }
  *out = cep_dt_clean(payload);
  return true;
}

static const char *cps_storage_read_text_field(cepCell *parent, const cepDT *field) {
  if (!parent || !field) {
    return NULL;
  }
  cepCell *child = cep_cell_find_by_name(parent, field);
  if (!child) {
    child = cep_cell_find_by_name_all(parent, field);
  }
  if (!child) {
    return NULL;
  }
  child = cep_cell_resolve(child);
  if (!child || !cep_cell_has_data(child)) {
    return NULL;
  }
  return (const char *)cep_cell_data(child);
}

static bool cps_storage_read_u64_field(cepCell *parent, const cepDT *field, uint64_t *out) {
  if (!parent || !field || !out) {
    return false;
  }
  const char *text = cps_storage_read_text_field(parent, field);
  if (!text || text[0] == '\0') {
    return false;
  }
  char *end = NULL;
  uint64_t value = strtoull(text, &end, 10);
  if (end == text || (end && *end && *end != '\n' && *end != '\r')) {
    return false;
  }
  *out = value;
  return true;
}

static bool cps_storage_read_payload_text(cepCell *envelope, char *buffer, size_t buffer_len) {
  if (!envelope || !buffer || buffer_len == 0u) {
    return false;
  }
  cepCell *payload = cep_cell_find_by_name(envelope, dt_payload_field_cps());
  if (!payload) {
    payload = cep_cell_find_by_name_all(envelope, dt_payload_field_cps());
  }
  if (!payload) {
    return false;
  }
  payload = cep_cell_resolve(payload);
  if (!payload || !cep_cell_has_data(payload)) {
    return false;
  }
  const cepData *data = payload->data;
  if (!data || data->size == 0u) {
    return false;
  }
  size_t copy = (data->size < buffer_len) ? data->size : (buffer_len - 1u);
  memcpy(buffer, cep_data_payload(data), copy);
  buffer[copy] = '\0';
  return true;
}

static const char *cps_storage_active_branch(void) {
  const char *name = cps_runtime_branch_name();
  return (name && name[0] != '\0') ? name : "default";
}

int cps_storage_export_active_branch(const cpsStorageSaveOptions* opts,
                                     char* bundle_path,
                                     size_t bundle_path_len,
                                     uint64_t* copied_bytes,
                                     uint64_t* cas_bytes,
                                     uint64_t* cas_blobs)
{
#ifdef CEP_ENABLE_DEBUG
  const bool env_debug = getenv("EXPORT_DEBUG") != NULL;
#else
  const bool env_debug = false;
#endif
  const char* branch_name = cps_storage_active_branch();
  const char* branch_dir = cps_runtime_branch_dir();
  char branch_dir_buf[PATH_MAX];
  if (!branch_dir || branch_dir[0] == '\0') {
    const char* root_dir = cps_runtime_root_dir();
    int need = snprintf(branch_dir_buf, sizeof branch_dir_buf, "%s/%s", root_dir, branch_name);
    if (need < 0 || (size_t)need >= sizeof branch_dir_buf) {
      CEP_DEBUG_PRINTF_IF(env_debug,
                          "[export_active] branch dir overflow root=\"%s\" branch=\"%s\"\n",
                          root_dir,
                          branch_name);
      return CPS_ERR_INVALID_ARGUMENT;
    }
    branch_dir = branch_dir_buf;
  }
  if (!cps_storage_path_exists(branch_dir)) {
    CEP_DEBUG_PRINTF_IF(env_debug, "[export_active] branch dir missing \"%s\"\n", branch_dir);
    return CPS_ERR_INVALID_ARGUMENT;
  }
  const char* target_path = (opts && opts->target_path && opts->target_path[0]) ? opts->target_path : NULL;
  uint64_t history_window = opts ? opts->history_window_beats : 0u;
  bool external_target = cps_storage_is_external_path(target_path);
  char scratch_path[PATH_MAX];
  char* path_out = bundle_path ? bundle_path : scratch_path;
  size_t path_out_len = bundle_path ? bundle_path_len : sizeof scratch_path;
  char normalized_target[PATH_MAX];
  int rc = cps_storage_export_branch_bundle(branch_dir,
                                            branch_name,
                                            (external_target && target_path &&
                                             cps_storage_normalize_path(target_path,
                                                                        normalized_target,
                                                                        sizeof normalized_target))
                                                ? normalized_target
                                                : target_path,
                                            history_window,
                                            external_target,
                                            path_out,
                                            path_out_len,
                                            copied_bytes,
                                            cas_bytes,
                                            cas_blobs);
  return rc;
}

static bool cps_storage_ops_enabled(void) {
  static int cached = -1;
  if (cached == -1) {
    const char *env = getenv("CEP_CPS_OPS_ENABLE");
    cached = (!env || strcmp(env, "0") != 0) ? 1 : 0;
  }
  return cached == 1;
}

static bool cps_storage_parse_branch(const char *target, char *out, size_t out_len) {
  if (!out || out_len == 0u) {
    return false;
  }
  if (!target || target[0] == '\0') {
    snprintf(out, out_len, "%s", cps_storage_active_branch());
    return true;
  }

  const char *cursor = target;
  if (strncmp(cursor, "/persist", 8) == 0) {
    cursor += 8;
  } else if (strncmp(cursor, "persist", 7) == 0) {
    cursor += 7;
  }
  if (*cursor == '/') {
    ++cursor;
  }

  if (*cursor == '\0') {
    snprintf(out, out_len, "%s", cps_storage_active_branch());
    return true;
  }

  size_t span = strcspn(cursor, "/");
  if (span >= out_len) {
    span = out_len - 1u;
  }
  memcpy(out, cursor, span);
  out[span] = '\0';
  return true;
}

static cepBranchController*
cps_storage_find_controller_by_name(const char* branch_name)
{
  const char* effective = (branch_name && branch_name[0] != '\0')
                            ? branch_name
                            : cps_storage_active_branch();
  if (!effective || effective[0] == '\0') {
    return NULL;
  }
  cepBranchControllerRegistry* registry = cep_runtime_branch_registry(NULL);
  if (!registry) {
    return NULL;
  }
  cepDT branch_dt = cep_ops_make_dt(effective);
  return cep_branch_registry_find_by_dt(registry, &branch_dt);
}

static bool
cps_storage_read_beats_field(cepCell* envelope, uint64_t* beats_out)
{
  if (!beats_out) {
    return false;
  }
  const char* text = cps_storage_read_text_field(envelope, dt_branch_beats_field());
  if (!text || text[0] == '\0') {
    *beats_out = 1u;
    return true;
  }
  errno = 0;
  char* end = NULL;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (errno != 0 || !end || *end != '\0') {
    return false;
  }
  *beats_out = parsed;
  return true;
}

typedef struct {
  char bundle_path[PATH_MAX];
  bool has_bundle;
  uint64_t history_window_beats;
  bool has_history_window;
} cpsStorageOpParams;

static void
cps_storage_parse_payload_options(const char* payload,
                                  cpsStorageOpParams* params)
{
  if (!payload || !params) {
    return;
  }
  const char* cursor = payload;
  while (*cursor) {
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r' || *cursor == ';') {
      ++cursor;
    }
    if (*cursor == '\0') {
      break;
    }
    const char* eq = strchr(cursor, '=');
    if (!eq) {
      if (!params->has_bundle) {
        size_t len = strnlen(cursor, sizeof params->bundle_path - 1u);
        memcpy(params->bundle_path, cursor, len);
        params->bundle_path[len] = '\0';
        params->has_bundle = true;
      }
      break;
    }
    const char* key = cursor;
    const char* value = eq + 1;
    const char* end = strpbrk(value, " \t\n\r;");
    size_t key_len = (size_t)(eq - key);
    size_t val_len = end ? (size_t)(end - value) : strlen(value);
    if (key_len == strlen("bundle") && strncmp(key, "bundle", key_len) == 0) {
      if (!params->has_bundle) {
        size_t copy = (val_len < sizeof params->bundle_path - 1u) ? val_len : (sizeof params->bundle_path - 1u);
        memcpy(params->bundle_path, value, copy);
        params->bundle_path[copy] = '\0';
        params->has_bundle = true;
      }
    } else if (key_len == strlen("hist_beats") && strncmp(key, "hist_beats", key_len) == 0) {
      char tmp[32];
      size_t copy = (val_len < sizeof tmp - 1u) ? val_len : (sizeof tmp - 1u);
      memcpy(tmp, value, copy);
      tmp[copy] = '\0';
      char* endptr = NULL;
      uint64_t parsed = strtoull(tmp, &endptr, 10);
      if (endptr && endptr != tmp && *endptr == '\0') {
        params->history_window_beats = parsed;
        params->has_history_window = true;
      }
    }
    cursor = end ? end : (value + val_len);
  }
}

static void
cps_storage_extract_op_params(cepCell* envelope, cpsStorageOpParams* params)
{
  if (!params) {
    return;
  }
  memset(params, 0, sizeof *params);
  const char* bundle_text = cps_storage_read_text_field(envelope, dt_bundle_field_cps());
  if (bundle_text && bundle_text[0] != '\0') {
    snprintf(params->bundle_path, sizeof params->bundle_path, "%s", bundle_text);
    params->has_bundle = true;
  }
  uint64_t hist = 0u;
  if (cps_storage_read_u64_field(envelope, dt_hist_beats_field_cps(), &hist)) {
    params->history_window_beats = hist;
    params->has_history_window = true;
  }
  char payload_buf[PATH_MAX];
  if (cps_storage_read_payload_text(envelope, payload_buf, sizeof payload_buf)) {
    cps_storage_parse_payload_options(payload_buf, params);
  }
}

static bool
cps_storage_branch_should_flush(cepBranchController* controller,
                                cepBeatNumber current_beat,
                                cepBranchFlushCause* cause_out,
                                bool* clear_schedule_out,
                                bool* clear_force_out)
{
  if (!controller) {
    return false;
  }
  if (!controller->dirty_entry_count && !controller->pending_mutations) {
    return false;
  }
  cepBeatNumber reference = (current_beat == CEP_BEAT_INVALID) ? 0u : current_beat;
  bool scheduled = false;
  if (controller->flush_scheduled_bt != CEP_BEAT_INVALID) {
    scheduled = controller->flush_scheduled_bt <= reference;
  }
  bool forced = controller->force_flush;
  const cepBranchPersistPolicy* policy = cep_branch_controller_policy(controller);
  cepBranchPersistMode mode = policy ? policy->mode : CEP_BRANCH_PERSIST_DURABLE;
  uint32_t flush_every = policy ? policy->flush_every_beats : 0u;
  bool periodic = false;
  if (mode == CEP_BRANCH_PERSIST_SCHEDULED_SAVE &&
      flush_every > 1u &&
      current_beat != CEP_BEAT_INVALID) {
    cepBeatNumber anchor = controller->last_persisted_bt;
    if (anchor == CEP_BEAT_INVALID) {
      if (controller->periodic_anchor_bt == CEP_BEAT_INVALID) {
        controller->periodic_anchor_bt = current_beat;
      }
      anchor = controller->periodic_anchor_bt;
    } else {
      controller->periodic_anchor_bt = anchor;
    }
    if (anchor != CEP_BEAT_INVALID) {
      uint64_t current64 = (uint64_t)current_beat;
      uint64_t anchor64 = (uint64_t)anchor;
      if (current64 >= anchor64) {
        periodic = (current64 - anchor64) >= (uint64_t)flush_every;
      }
    }
  } else if (mode == CEP_BRANCH_PERSIST_SCHEDULED_SAVE) {
    controller->periodic_anchor_bt = controller->last_persisted_bt;
  }
  bool should_flush = true;
  switch (mode) {
    case CEP_BRANCH_PERSIST_VOLATILE:
      should_flush = false;
      break;
    case CEP_BRANCH_PERSIST_RO_SNAPSHOT:
      should_flush = false;
      break;
    case CEP_BRANCH_PERSIST_ON_DEMAND:
    case CEP_BRANCH_PERSIST_SCHEDULED_SAVE:
      should_flush = scheduled || forced || periodic;
      break;
    default:
      should_flush = true;
      break;
  }
  if (!should_flush) {
    return false;
  }
  if (clear_schedule_out) {
    *clear_schedule_out = scheduled;
  }
  if (clear_force_out) {
    *clear_force_out = forced;
  }
  if (cause_out) {
    bool periodic_trigger = periodic && !scheduled && !forced;
    if (forced) {
      *cause_out = CEP_BRANCH_FLUSH_CAUSE_MANUAL;
    } else if (scheduled || periodic_trigger) {
      *cause_out = CEP_BRANCH_FLUSH_CAUSE_SCHEDULED;
    } else {
      *cause_out = CEP_BRANCH_FLUSH_CAUSE_AUTOMATIC;
    }
  }
  return true;
}

static bool
cps_storage_read_bool_field(cepCell* envelope,
                            const cepDT* field,
                            bool default_value,
                            bool* out)
{
  if (!out) {
    return false;
  }
  const char* text = cps_storage_read_text_field(envelope, field);
  if (!text || text[0] == '\0') {
    *out = default_value;
    return true;
  }
  if (strcasecmp(text, "true") == 0 ||
      strcasecmp(text, "on") == 0 ||
      strcasecmp(text, "enable") == 0) {
    *out = true;
    return true;
  }
  if (strcasecmp(text, "false") == 0 ||
      strcasecmp(text, "off") == 0 ||
      strcasecmp(text, "disable") == 0) {
    *out = false;
    return true;
  }
  errno = 0;
  char* endptr = NULL;
  unsigned long long parsed = strtoull(text, &endptr, 10);
  if (errno == 0 && endptr && *endptr == '\0') {
    *out = parsed != 0u;
    return true;
  }
  return false;
}

static const cepDT *cps_storage_severity_for_status(int rc) {
  switch (rc) {
    case CPS_ERR_IO:
    case CPS_ERR_VERIFY:
      return dt_cps_storage_sev_crit();
    default:
      return dt_cps_storage_sev_warn();
  }
}

static bool cps_storage_mark_state(cepOID oid, const cepDT *state, const char *note, int code) {
  if (!cep_oid_is_valid(oid) || !state) {
    return false;
  }
  return cep_op_state_set(oid, *state, code, note);
}

static void cps_storage_close_status(cepOID oid, const cepDT *status, const char *summary) {
  if (!cep_oid_is_valid(oid) || !status) {
    return;
  }
  size_t len = summary ? (strlen(summary) + 1u) : 0u;
  (void)cep_op_close(oid, *status, summary, len);
}

static void cps_storage_complete_success(cepOID oid, const char *verb_label, const char *summary) {
  const char *note = summary ? summary : verb_label;
  if (!note) {
    note = "completed";
  }
  (void)cps_storage_mark_state(oid, dt_ist_ok_dt(), note, 0);
  cps_storage_close_status(oid, dt_sts_ok_dt(), summary);
}

static void cps_storage_fail_operation(cepOID oid,
                                       const char *verb_label,
                                       const char *branch,
                                       int rc,
                                       const char *detail) {
  char note[192];
  snprintf(note,
           sizeof note,
           "%s failed branch=%s rc=%d%s%s",
           verb_label ? verb_label : "operation",
           branch ? branch : cps_storage_active_branch(),
           rc,
           detail ? " detail=" : "",
           detail ? detail : "");
  (void)cps_storage_mark_state(oid, dt_ist_fail_dt(), note, rc);
  cps_storage_close_status(oid, dt_sts_fail_dt(), note);
  cps_storage_emit_cei(cps_storage_severity_for_status(rc), note);
}

static bool cps_storage_run_checkpoint_op(cepOID oid, const char *branch) {
  cps_engine *engine = cps_runtime_engine();
  if (!engine || !engine->ops || !engine->ops->checkpoint) {
    cps_storage_fail_operation(oid, "checkpoint", branch, CPS_ERR_NOT_IMPLEMENTED, "engine missing checkpoint hook");
    return false;
  }

  cps_ckpt_opts opts = {
    .every_beats = 0u,
  };
  cps_ckpt_stat stat = {0};
  int rc = engine->ops->checkpoint(engine, &opts, &stat);
  if (rc != CPS_OK) {
    cps_storage_fail_operation(oid, "checkpoint", branch, rc, NULL);
    return false;
  }

  char summary[160];
  snprintf(summary,
           sizeof summary,
           "branch=%s entries=%" PRIu64 " bytes=%" PRIu64,
           branch ? branch : cps_storage_active_branch(),
           stat.written_entries,
           stat.written_bytes);
  cps_storage_complete_success(oid, "checkpoint", summary);
  return true;
}

static bool cps_storage_run_compact_op(cepOID oid, const char *branch) {
  cps_engine *engine = cps_runtime_engine();
  if (!engine || !engine->ops || !engine->ops->compact) {
    cps_storage_fail_operation(oid, "compact", branch, CPS_ERR_NOT_IMPLEMENTED, "engine missing compaction hook");
    return false;
  }

  cps_compact_opts opts = {
    .history_window_beats = 0u,
  };
  cps_compact_stat stat = {0};
  int rc = engine->ops->compact(engine, &opts, &stat);
  if (rc != CPS_OK) {
    cps_storage_fail_operation(oid, "compact", branch, rc, NULL);
    return false;
  }

  char summary[160];
  snprintf(summary,
           sizeof summary,
           "branch=%s reclaimed_bytes=%" PRIu64,
           branch ? branch : cps_storage_active_branch(),
           stat.reclaimed_bytes);
  cps_storage_complete_success(oid, "compact", summary);
  return true;
}

static bool cps_storage_run_sync_op(cepOID oid,
                                    const char *branch,
                                    const char *bundle_override,
                                    uint64_t history_window_beats,
                                    bool external_target) {
  const char *effective_branch = (branch && branch[0] != '\0') ? branch : cps_storage_active_branch();
  char bundle_path[PATH_MAX];
  uint64_t copied_bytes = 0u;
  uint64_t cas_bytes = 0u;
  uint64_t cas_blobs = 0u;
  const char* target_arg = bundle_override;
  char normalized_target[PATH_MAX];
  if (external_target && bundle_override && bundle_override[0] != '\0') {
    if (!cps_storage_normalize_path(bundle_override, normalized_target, sizeof normalized_target)) {
      cps_storage_fail_operation(oid, "sync", effective_branch, CPS_ERR_INVALID_ARGUMENT, "external target invalid");
      return false;
    }
    target_arg = normalized_target;
  }
  cpsStorageSaveOptions opts = {
    .target_path = target_arg,
    .history_window_beats = history_window_beats,
  };
  int rc = cps_storage_export_branch_bundle(cps_runtime_branch_dir(),
                                            effective_branch,
                                            opts.target_path,
                                            opts.history_window_beats,
                                            external_target,
                                            bundle_path,
                                            sizeof bundle_path,
                                            &copied_bytes,
                                            &cas_bytes,
                                            &cas_blobs);
  if (rc != CPS_OK) {
    cps_storage_fail_operation(oid, "sync", effective_branch, rc, "export failed");
    return false;
  }
  cps_stats stats = {0};
  cps_engine *engine = cps_runtime_engine();
  if (engine && engine->ops && engine->ops->stats) {
    (void)engine->ops->stats(engine, &stats);
  }
  const char *bundle_label = bundle_path;
  const char *slash = strrchr(bundle_path, '/');
  if (slash && slash[1] != '\0') {
    bundle_label = slash + 1;
  }
  char summary[256];
  snprintf(summary,
           sizeof summary,
           "branch=%.48s bundle=%.64s files_bytes=%" PRIu64 " cas_blobs=%" PRIu64 " cas_bytes=%" PRIu64 " frames=%" PRIu64 " hist_bt=%" PRIu64,
           effective_branch ? effective_branch : "-",
           bundle_label ? bundle_label : "-",
           copied_bytes,
           cas_blobs,
           cas_bytes,
           stats.stat_frames,
           history_window_beats);
  cps_storage_complete_success(oid, "sync", summary);
  return true;
}

static bool cps_storage_run_import_op(cepOID oid,
                                      const char *branch,
                                      const char *bundle_path,
                                      bool external_source) {
  if (!bundle_path || bundle_path[0] == '\0') {
    cps_storage_fail_operation(oid, "import", branch, CPS_ERR_INVALID_ARGUMENT, "bundle path missing");
    return false;
  }
  const char* use_path = bundle_path;
  char normalized[PATH_MAX];
  if (external_source) {
    if (!cps_storage_normalize_path(bundle_path, normalized, sizeof normalized)) {
      cps_storage_fail_operation(oid, "import", branch, CPS_ERR_INVALID_ARGUMENT, "external bundle path invalid");
      return false;
    }
    use_path = normalized;
  }
  char staged_path[PATH_MAX];
  if (!cps_storage_stage_bundle_dir(use_path, staged_path, sizeof staged_path)) {
    cps_storage_fail_operation(oid, "import", branch, CPS_ERR_VERIFY, "bundle verify/stage failed");
    return false;
  }
  int promote_rc = cps_storage_promote_bundle(staged_path);
  if (promote_rc != CPS_OK) {
    cps_storage_fail_operation(oid, "import", branch, promote_rc, "bundle promotion failed");
    return false;
  }
  char summary[256];
  snprintf(summary,
           sizeof summary,
           "branch=%.48s bundle=%.64s staged=%.64s",
           branch ? branch : cps_storage_active_branch(),
           use_path,
           staged_path);
  cps_storage_complete_success(oid, "import", summary);
  return true;
}

static bool
cps_storage_run_branch_flush_op(cepOID oid, const char* branch_name)
{
  cepBranchController* controller = cps_storage_find_controller_by_name(branch_name);
  if (!controller) {
    cps_storage_fail_operation(oid, "branch flush", branch_name, CPS_ERR_INVALID_ARGUMENT, "branch missing");
    return false;
  }
  controller->force_flush = true;
  char label[64];
  const char* branch_label = cps_storage_branch_label(controller, label, sizeof label);
  char summary[128];
  snprintf(summary,
           sizeof summary,
           "branch=%s flush queued",
           branch_label ? branch_label : "<unknown>");
  cps_storage_complete_success(oid, "branch flush", summary);
  return true;
}

void
cps_storage_request_shutdown_flushes(void)
{
  cepBranchControllerRegistry* registry = cep_runtime_branch_registry(NULL);
  if (!registry) {
    return;
  }
  size_t count = cep_branch_registry_count(registry);
  for (size_t i = 0; i < count; ++i) {
    cepBranchController* controller = cep_branch_registry_controller(registry, i);
    if (!controller) {
      continue;
    }
    const cepBranchPersistPolicy* policy = cep_branch_controller_policy(controller);
    if (!policy || !policy->flush_on_shutdown) {
      continue;
    }
    if (!controller->dirty_entry_count && !controller->pending_mutations) {
      continue;
    }
    controller->force_flush = true;
  }
}

static bool
cps_storage_run_branch_schedule_op(cepOID oid,
                                   const char* branch_name,
                                   cepCell* envelope)
{
  cepBranchController* controller = cps_storage_find_controller_by_name(branch_name);
  if (!controller) {
    cps_storage_fail_operation(oid, "branch schedule", branch_name, CPS_ERR_INVALID_ARGUMENT, "branch missing");
    return false;
  }
  uint64_t beats = 1u;
  if (!cps_storage_read_beats_field(envelope, &beats)) {
    cps_storage_fail_operation(oid, "branch schedule", branch_name, CPS_ERR_INVALID_ARGUMENT, "beats parse failed");
    return false;
  }
  cepBeatNumber current = cep_beat_index();
  uint64_t base = (current == CEP_BEAT_INVALID) ? 0u : (uint64_t)current;
  uint64_t target = (beats > (UINT64_MAX - base)) ? UINT64_MAX : (base + beats);
  controller->flush_scheduled_bt = (cepBeatNumber)target;
  controller->force_flush = false;
  controller->policy.mode = CEP_BRANCH_PERSIST_SCHEDULED_SAVE;
  char label[64];
  const char* branch_label = cps_storage_branch_label(controller, label, sizeof label);
  char summary[192];
  snprintf(summary,
           sizeof summary,
           "branch=%s schedule_bt=%llu beats=%llu",
           branch_label ? branch_label : "<unknown>",
           (unsigned long long)controller->flush_scheduled_bt,
           (unsigned long long)beats);
  cps_storage_complete_success(oid, "branch schedule", summary);
  return true;
}

static bool
cps_storage_run_branch_defer_op(cepOID oid, const char* branch_name)
{
  cepBranchController* controller = cps_storage_find_controller_by_name(branch_name);
  if (!controller) {
    cps_storage_fail_operation(oid, "branch defer", branch_name, CPS_ERR_INVALID_ARGUMENT, "branch missing");
    return false;
  }
  controller->policy.mode = CEP_BRANCH_PERSIST_ON_DEMAND;
  controller->flush_scheduled_bt = CEP_BEAT_INVALID;
  controller->force_flush = false;
  char label[64];
  const char* branch_label = cps_storage_branch_label(controller, label, sizeof label);
  char summary[160];
  snprintf(summary,
           sizeof summary,
           "branch=%s deferred",
           branch_label ? branch_label : "<unknown>");
  cps_storage_emit_topic_cei(dt_cps_storage_sev_info(),
                             k_cps_topic_branch_defer,
                             summary);
  cps_storage_complete_success(oid, "branch defer", summary);
  return true;
}

static bool
cps_storage_run_branch_snapshot_op(cepOID oid,
                                   const char* branch_name,
                                   bool enable)
{
  cepBranchController* controller = cps_storage_find_controller_by_name(branch_name);
  if (!controller) {
    cps_storage_fail_operation(oid, "branch snapshot", branch_name, CPS_ERR_INVALID_ARGUMENT, "branch missing");
    return false;
  }
  if (!enable) {
    cps_storage_fail_operation(oid, "branch snapshot", branch_name, CPS_ERR_INVALID_ARGUMENT, "disable unsupported");
    return false;
  }
  if (controller->dirty_entry_count || controller->pending_mutations) {
    cps_storage_fail_operation(oid, "branch snapshot", branch_name, CPS_ERR_INVALID_ARGUMENT, "branch dirty");
    return false;
  }
  if (!cep_branch_controller_enable_snapshot_mode(controller)) {
    cps_storage_fail_operation(oid, "branch snapshot", branch_name, CPS_ERR_IO, "snapshot seal failed");
    return false;
  }
  cps_storage_publish_branch_state(controller, cps_runtime_engine());

  char label[64];
  const char* branch_label = cps_storage_branch_label(controller, label, sizeof label);
  char summary[192];
  snprintf(summary,
           sizeof summary,
           "branch=%s ro_snapshot=enabled",
           branch_label ? branch_label : "<unknown>");
  cps_storage_emit_topic_cei(dt_cps_storage_sev_info(),
                             k_cps_topic_branch_snapshot,
                             summary);
  cps_storage_complete_success(oid, "branch snapshot", summary);
  return true;
}

static bool cps_storage_state_allows_execution(cepCell *op) {
  cepDT state = {0};
  if (!cps_storage_read_dt_field(op, dt_state_field_cps(), &state)) {
    return true;
  }
  if (cep_dt_compare(&state, dt_ist_run_dt()) == 0) {
    return true;
  }
  if (cep_dt_compare(&state, dt_ist_exec_dt()) == 0) {
    return false;
  }
  return false;
}

static void cps_storage_handle_op(cepCell *op) {
  if (!op || cps_storage_op_is_closed(op)) {
    return;
  }
  if (!cps_storage_state_allows_execution(op)) {
    return;
  }

  cepCell *envelope = cep_cell_find_by_name(op, dt_envelope_name_cps());
  if (!envelope) {
    envelope = cep_cell_find_by_name_all(op, dt_envelope_name_cps());
  }
  if (!envelope) {
    return;
  }
  envelope = cep_cell_resolve(envelope);
  if (!envelope) {
    return;
  }

  cepDT verb = {0};
  if (!cps_storage_read_dt_field(envelope, dt_verb_field_cps(), &verb)) {
    return;
  }
  cepOID oid = cps_storage_oid_from_cell(op);
  if (!cep_oid_is_valid(oid)) {
    return;
  }

  bool is_checkpoint = (cep_dt_compare(&verb, dt_op_checkpt_dt()) == 0);
  bool is_compact = (cep_dt_compare(&verb, dt_op_compact_dt()) == 0);
  bool is_sync = (cep_dt_compare(&verb, dt_op_sync_dt()) == 0);
  bool is_import = (cep_dt_compare(&verb, dt_op_import_dt()) == 0);
  bool is_branch_flush = (cep_dt_compare(&verb, dt_op_branch_flush_dt()) == 0);
  bool is_branch_schedule = (cep_dt_compare(&verb, dt_op_branch_schedule_dt()) == 0);
  bool is_branch_defer = (cep_dt_compare(&verb, dt_op_branch_defer_dt()) == 0);
  bool is_branch_snapshot = (cep_dt_compare(&verb, dt_op_branch_snapshot_dt()) == 0);
  if (!is_checkpoint && !is_compact && !is_sync && !is_import &&
      !is_branch_flush && !is_branch_schedule && !is_branch_defer &&
      !is_branch_snapshot) {
    return;
  }

  const char *target = cps_storage_read_text_field(envelope, dt_target_field_cps());
  char branch_buf[64];
  if (!cps_storage_parse_branch(target, branch_buf, sizeof branch_buf)) {
    return;
  }

  const char *active_branch = cps_storage_active_branch();
  if (branch_buf[0] != '\0' && strcmp(branch_buf, active_branch) != 0) {
    cps_storage_fail_operation(oid, "persist", branch_buf, CPS_ERR_INVALID_ARGUMENT, "branch mismatch");
    return;
  }

  cpsStorageOpParams op_params;
  cps_storage_extract_op_params(envelope, &op_params);
  const char* bundle_override = op_params.has_bundle ? op_params.bundle_path : NULL;
  uint64_t history_window = op_params.has_history_window ? op_params.history_window_beats : 0u;
  bool external_target = bundle_override ? cps_storage_is_external_path(bundle_override) : false;

  if (cep_dt_compare(&verb, dt_op_checkpt_dt()) == 0) {
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_checkpoint_op(oid, branch_buf);
    }
  } else if (cep_dt_compare(&verb, dt_op_compact_dt()) == 0) {
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_compact_op(oid, branch_buf);
    }
  } else if (cep_dt_compare(&verb, dt_op_sync_dt()) == 0) {
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_sync_op(oid, branch_buf, bundle_override, history_window, external_target);
    }
  } else if (cep_dt_compare(&verb, dt_op_import_dt()) == 0) {
    const char *bundle_path = bundle_override;
    if (!bundle_path || bundle_path[0] == '\0') {
      cps_storage_fail_operation(oid, "import", branch_buf, CPS_ERR_INVALID_ARGUMENT, "bundle path missing");
      return;
    }
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_import_op(oid, branch_buf, bundle_path, external_target);
    }
  } else if (cep_dt_compare(&verb, dt_op_branch_flush_dt()) == 0) {
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_branch_flush_op(oid, branch_buf);
    }
  } else if (cep_dt_compare(&verb, dt_op_branch_schedule_dt()) == 0) {
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_branch_schedule_op(oid, branch_buf, envelope);
    }
  } else if (cep_dt_compare(&verb, dt_op_branch_defer_dt()) == 0) {
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_branch_defer_op(oid, branch_buf);
    }
  } else if (cep_dt_compare(&verb, dt_op_branch_snapshot_dt()) == 0) {
    bool enable_snapshot = true;
    if (!cps_storage_read_bool_field(envelope,
                                     dt_branch_snapshot_enable_field(),
                                     true,
                                     &enable_snapshot)) {
      cps_storage_fail_operation(oid, "branch snapshot", branch_buf, CPS_ERR_INVALID_ARGUMENT, "snapshot flag invalid");
      return;
    }
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_branch_snapshot_op(oid, branch_buf, enable_snapshot);
    }
  }
}

static void cps_storage_process_ops(void) {
  if (!cps_runtime_is_ready() || !cps_storage_ops_enabled()) {
    return;
  }
  cepCell *ops_root = cps_storage_ops_root();
  if (!ops_root) {
    return;
  }
  for (cepCell *cursor = cep_cell_first(ops_root); cursor; cursor = cep_cell_next(ops_root, cursor)) {
    cepCell *op = cep_cell_resolve(cursor);
    if (!op) {
      continue;
    }
    cps_storage_handle_op(op);
  }
}

bool cps_storage_verify_bundle_dir(const char *bundle_dir) {
  if (!bundle_dir || bundle_dir[0] == '\0') {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(), "bundle verify path missing");
    return false;
  }
  int rc = cps_storage_verify_bundle(bundle_dir);
  if (rc != CPS_OK) {
    char note[192];
    snprintf(note, sizeof note, "bundle verify failed path=%s rc=%d", bundle_dir, rc);
    cps_storage_emit_cei(cps_storage_severity_for_status(rc), note);
    return false;
  }
  return true;
}

bool cps_storage_stage_bundle_dir(const char *bundle_dir, char *staged_path, size_t staged_path_len) {
  if (!bundle_dir || bundle_dir[0] == '\0') {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(), "bundle stage path missing");
    return false;
  }
  const char *branch_dir = cps_runtime_branch_dir();
  if (!branch_dir) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(), "bundle stage branch path unavailable");
    return false;
  }
  char stage_dir[PATH_MAX];
  uint64_t staged_bytes = 0u;
  int rc = cps_storage_stage_bundle(branch_dir, bundle_dir, stage_dir, sizeof stage_dir, &staged_bytes);
  if (rc != CPS_OK) {
    char note[192];
    snprintf(note, sizeof note, "bundle stage failed path=%s rc=%d", bundle_dir, rc);
    cps_storage_emit_cei(cps_storage_severity_for_status(rc), note);
    return false;
  }
  if (staged_path && staged_path_len > 0u) {
    int need = snprintf(staged_path, staged_path_len, "%s", stage_dir);
    if (need < 0 || (size_t)need >= staged_path_len) {
      cps_storage_emit_cei(dt_cps_storage_sev_warn(), "bundle stage path truncation");
      return false;
    }
  }
  return true;
}

bool cps_storage_commit_current_beat(void) {
  if (!cps_runtime_is_ready()) {
    return true;
  }

  cepBranchControllerRegistry* branch_registry = cep_runtime_branch_registry(NULL);
  if (!branch_registry) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(),
                         "branch registry unavailable for persistence");
    return false;
  }

  cps_engine *engine = cps_runtime_engine();
  if (!engine || !engine->ops) {
    return false;
  }

  cepBeatNumber current_beat = cep_beat_index();

  bool ok = true;
  cpsBranchFrameRequest* requests = NULL;
  size_t request_count = 0u;
  size_t request_capacity = 0u;

  size_t controller_count = cep_branch_registry_count(branch_registry);
  for (size_t i = 0; i < controller_count; ++i) {
    cepBranchController* controller = cep_branch_registry_controller(branch_registry, i);
    if (!controller || !controller->branch_root) {
      continue;
    }
    cep_branch_controller_apply_eviction(controller);
    cepBranchFlushCause reason = CEP_BRANCH_FLUSH_CAUSE_UNKNOWN;
    bool clear_schedule = false;
    bool clear_force = false;
    if (!cps_storage_branch_should_flush(controller,
                                         current_beat,
                                         &reason,
                                         &clear_schedule,
                                         &clear_force)) {
      continue;
    }
    cepFlatBranchFrameInfo frame_info = {
      .branch_domain = controller->branch_dt.domain,
      .branch_tag = controller->branch_dt.tag,
      .branch_glob = controller->branch_dt.glob ? 1u : 0u,
      .frame_id = controller->last_frame_id ? (controller->last_frame_id + 1u) : 1u,
    };
    cpsBranchFrameRequest request = {
      .controller = controller,
      .frame_info = frame_info,
      .reason = reason,
      .clear_force_request = clear_force,
      .clear_schedule_request = clear_schedule,
    };
    if (!cps_storage_branch_requests_append(&requests,
                                            &request_count,
                                            &request_capacity,
                                            &request)) {
      free(requests);
      return false;
    }
  }

  if (request_count > 0u) {
    ok = cps_storage_commit_branch_requests(requests, request_count, engine);
  }

  free(requests);

  cps_storage_process_ops();
  return ok;
}
