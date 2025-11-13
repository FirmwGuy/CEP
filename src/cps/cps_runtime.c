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
} cpsRuntimeState;

static cpsRuntimeState g_cps_state = {0};

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

bool cps_runtime_bootstrap(void) {
  if (g_cps_state.engine) {
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
  return true;
}

void cps_runtime_shutdown(void) {
  if (!g_cps_state.engine) {
    g_cps_state.ready = false;
    return;
  }

  if (g_cps_state.engine->ops && g_cps_state.engine->ops->close) {
    g_cps_state.engine->ops->close(g_cps_state.engine);
  } else {
    free(g_cps_state.engine);
  }
  g_cps_state.engine = NULL;
  g_cps_state.ready = false;
}

bool cps_runtime_is_ready(void) {
  return g_cps_state.ready && g_cps_state.engine;
}

cps_engine *cps_runtime_engine(void) {
  return g_cps_state.engine;
}
