/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cps_runtime.h"

#include "cps_flatfile.h"

#include "cep_cell.h"
#include "cep_cei.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CPS_RUNTIME_DEFAULT_ROOT   "build/cps"
#define CPS_RUNTIME_DEFAULT_BRANCH "default"
#define CPS_RUNTIME_DEFAULT_CKPT   128u
#define CPS_RUNTIME_DEFAULT_TOC    64u

CEP_DEFINE_STATIC_DT(dt_cps_runtime_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));

typedef struct {
  cps_engine *engine;
  bool ready;
  char *branch_name;
  char *root_dir;
  char *branch_path;
} cpsRuntimeState;

static cpsRuntimeState g_cps_state = {0};
static bool g_cps_force_mock_mode = false;

static const char *cps_runtime_env_or_default(const char *name, const char *fallback) {
  const char *value = getenv(name);
  if (value && *value) {
    return value;
  }
  return fallback;
}

static uint32_t cps_runtime_env_u32(const char *name, uint32_t fallback) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }
  errno = 0;
  char *end = NULL;
  unsigned long parsed = strtoul(value, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed == 0ul || parsed > UINT32_MAX) {
    return fallback;
  }
  return (uint32_t)parsed;
}

static void cps_runtime_emit_cei(const char *detail) {
  static const char k_topic[] = "persist.bootstrap";
  cepCeiRequest req = {
    .severity = *dt_cps_runtime_sev_warn(),
    .topic = k_topic,
    .topic_intern = true,
    .note = detail,
    .note_len = detail ? 0u : 0u,
    .origin_kind = "cps_runtime",
    .emit_signal = false,
    .attach_to_op = false,
    .ttl_forever = true,
  };
  (void)cep_cei_emit(&req);
}

static void cps_runtime_clear_paths(void) {
  free(g_cps_state.branch_name);
  g_cps_state.branch_name = NULL;
  free(g_cps_state.root_dir);
  g_cps_state.root_dir = NULL;
  free(g_cps_state.branch_path);
  g_cps_state.branch_path = NULL;
}

static char *cps_runtime_join_branch_path(const char *root_dir, const char *branch_name) {
  const char *safe_root = (root_dir && *root_dir) ? root_dir : CPS_RUNTIME_DEFAULT_ROOT;
  const char *safe_branch = (branch_name && *branch_name) ? branch_name : CPS_RUNTIME_DEFAULT_BRANCH;
  size_t root_len = strlen(safe_root);
  size_t branch_len = strlen(safe_branch);
  bool needs_sep = true;
  if (root_len == 0u) {
    needs_sep = false;
  } else {
    char last = safe_root[root_len - 1u];
    if (last == '/' || last == '\\') {
      needs_sep = false;
    }
  }
  size_t total = root_len + (needs_sep ? 1u : 0u) + branch_len + 1u;
  char *joined = (char *)malloc(total);
  if (!joined) {
    return NULL;
  }
  size_t pos = 0u;
  if (root_len > 0u) {
    memcpy(joined, safe_root, root_len);
    pos += root_len;
  }
  if (needs_sep) {
    joined[pos++] = '/';
  }
  if (branch_len > 0u) {
    memcpy(joined + pos, safe_branch, branch_len);
    pos += branch_len;
  }
  joined[pos] = '\0';
  return joined;
}

static bool cps_runtime_store_paths(const char *root_dir, const char *branch_name) {
  const char *effective_root = (root_dir && *root_dir) ? root_dir : CPS_RUNTIME_DEFAULT_ROOT;
  const char *effective_branch = (branch_name && *branch_name) ? branch_name : CPS_RUNTIME_DEFAULT_BRANCH;
  char *root_copy = strdup(effective_root);
  char *branch_copy = strdup(effective_branch);
  char *branch_path = cps_runtime_join_branch_path(effective_root, effective_branch);
  if (!root_copy || !branch_copy || !branch_path) {
    free(root_copy);
    free(branch_copy);
    free(branch_path);
    return false;
  }
  cps_runtime_clear_paths();
  g_cps_state.root_dir = root_copy;
  g_cps_state.branch_name = branch_copy;
  g_cps_state.branch_path = branch_path;
  return true;
}

static bool cps_runtime_env_wants_mock_mode(void) {
  const char *mode = getenv("CEP_TEST_MODE");
  if (!mode || !*mode) {
    return false;
  }
  const char *match = strstr(mode, "mock_cps");
  if (!match) {
    return false;
  }
  char prev = (match == mode) ? '\0' : match[-1];
  char next = match[8];
  bool prev_ok = (prev == '\0' || prev == ',' || prev == ':' || prev == ';' || prev == ' ');
  bool next_ok = (next == '\0' || next == ',' || next == ':' || next == ';' || next == ' ');
  return prev_ok && next_ok;
}

static bool cps_runtime_mock_mode_enabled(void) {
  if (g_cps_force_mock_mode) {
    return true;
  }
  return cps_runtime_env_wants_mock_mode();
}

void cps_runtime_force_mock_mode(bool enable) {
  if (g_cps_force_mock_mode == enable) {
    return;
  }
  g_cps_force_mock_mode = enable;
  if (enable) {
    cps_runtime_shutdown();
  }
}

bool cps_runtime_bootstrap(void) {
  if (g_cps_state.engine) {
    return true;
  }

  if (cps_runtime_mock_mode_enabled()) {
    g_cps_state.ready = false;
    return true;
  }

  const char *root_dir = cps_runtime_env_or_default("CEP_CPS_ROOT", CPS_RUNTIME_DEFAULT_ROOT);
  const char *branch_name = cps_runtime_env_or_default("CEP_CPS_BRANCH", CPS_RUNTIME_DEFAULT_BRANCH);
  uint32_t checkpoint_interval = cps_runtime_env_u32("CEP_CPS_CKPT_INTERVAL", CPS_RUNTIME_DEFAULT_CKPT);
  uint32_t mini_toc_hint = cps_runtime_env_u32("CEP_CPS_TOC_HINT", CPS_RUNTIME_DEFAULT_TOC);

  cps_flatfile_opts opts = {
    .root_dir = root_dir,
    .branch_name = branch_name,
    .checkpoint_interval = checkpoint_interval,
    .mini_toc_hint = mini_toc_hint,
    .create_branch = true,
  };

  cps_engine *engine = NULL;
  int rc = cps_flatfile_engine_open(&opts, &engine);
  if (rc != CPS_OK || !engine) {
    cps_runtime_emit_cei("flatfile engine open failed");
    return false;
  }

  g_cps_state.engine = engine;
  g_cps_state.ready = true;
  if (!cps_runtime_store_paths(root_dir, branch_name)) {
    cps_runtime_shutdown();
    return false;
  }
  return true;
}

void cps_runtime_shutdown(void) {
  if (g_cps_state.engine) {
    if (g_cps_state.engine->ops && g_cps_state.engine->ops->close) {
      g_cps_state.engine->ops->close(g_cps_state.engine);
    } else {
      free(g_cps_state.engine);
    }
    g_cps_state.engine = NULL;
  }
  g_cps_state.ready = false;
  cps_runtime_clear_paths();
}

bool cps_runtime_is_ready(void) {
  return g_cps_state.ready && g_cps_state.engine;
}

cps_engine *cps_runtime_engine(void) {
  return g_cps_state.engine;
}

const char *cps_runtime_branch_name(void) {
  if (g_cps_state.branch_name && g_cps_state.branch_name[0] != '\0') {
    return g_cps_state.branch_name;
  }
  return CPS_RUNTIME_DEFAULT_BRANCH;
}

const char *cps_runtime_root_dir(void) {
  if (g_cps_state.root_dir && g_cps_state.root_dir[0] != '\0') {
    return g_cps_state.root_dir;
  }
  return CPS_RUNTIME_DEFAULT_ROOT;
}

const char *cps_runtime_branch_dir(void) {
  if (g_cps_state.branch_path && g_cps_state.branch_path[0] != '\0') {
    return g_cps_state.branch_path;
  }
  return NULL;
}
