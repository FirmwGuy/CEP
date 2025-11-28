/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef CPS_STORAGE_SERVICE_H
#define CPS_STORAGE_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  /* Optional target path for the exported bundle directory. When NULL, the
   * export lands under <branch_dir>/exports/<slug>-<timestamp>. When set, the
   * path must point to a directory that does not already exist. */
  const char* target_path;
  /* Optional history window (in beats). Zero keeps full history; non-zero
   * compacts the exported bundle down to the requested window after copying. */
  uint64_t history_window_beats;
} cpsStorageSaveOptions;

/* Persist the current beat by serializing the runtime branch and applying the
 * resulting flat frame to the active CPS engine. Returns true when persistence
 * completed or was skipped because CPS is not ready yet.
 */
bool cps_storage_commit_current_beat(void);

/* Verify that the exported bundle rooted at bundle_dir passes the manifest
 * hashes/byte checks so operators can confirm integrity before importing.
 * Returns true on success and emits a CEI warning before returning false.
 */
bool cps_storage_verify_bundle_dir(const char *bundle_dir);

/* Verify and stage an exported bundle under the active branch's imports/
 * directory so a future op/import can atomically swap files. Returns true
 * when staging succeeded and (optionally) copies the staging-path string
 * into staged_path/staged_path_len.
 */
bool cps_storage_stage_bundle_dir(const char *bundle_dir, char *staged_path, size_t staged_path_len);

/* Export the active runtime branch to a bundle directory. When opts is NULL,
 * the bundle is written under <branch_dir>/exports/<slug>-<timestamp> with
 * full history preserved. When opts is provided, target_path overrides the
 * destination directory and history_window_beats triggers windowed export on
 * the copied bundle. Returns a CPS status code and fills bundle_path (if provided)
 * with the path to the created bundle.
 */
int cps_storage_export_active_branch(const cpsStorageSaveOptions* opts,
                                     char* bundle_path,
                                     size_t bundle_path_len,
                                     uint64_t* copied_bytes,
                                     uint64_t* cas_bytes,
                                     uint64_t* cas_blobs);
void cps_storage_request_shutdown_flushes(void);

#endif /* CPS_STORAGE_SERVICE_H */
