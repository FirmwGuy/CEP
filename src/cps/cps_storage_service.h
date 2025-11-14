/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef CPS_STORAGE_SERVICE_H
#define CPS_STORAGE_SERVICE_H

#include <stdbool.h>
#include <stddef.h>

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

#endif /* CPS_STORAGE_SERVICE_H */
