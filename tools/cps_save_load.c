/* Helper CLI to export/import CPS branches with explicit bundle targets. It
 * bootstraps a minimal runtime, normalises paths (requiring absolute paths
 * when targeting external sinks), and invokes the CPS export/stage helpers so
 * operators can trigger save/load outside the test harness.
 */

#include "cps_storage_service.h"
#include "cps_runtime.h"

#include "cep_heartbeat.h"
#include "cep_l0.h"
#include "cep_namepool.h"
#include "cep_runtime.h"
#include "stream/cep_stream_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#define fsync _commit
static char* tool_realpath(const char* path, char* resolved) {
  return _fullpath(resolved, path, PATH_MAX);
}
#define realpath(path, resolved) tool_realpath(path, resolved)
static int tool_mkdir(const char* path, mode_t mode) {
  (void)mode;
  return _mkdir(path);
}
static bool tool_setenv(const char* name, const char* value) {
  return _putenv_s(name, value ? value : "") == 0;
}
static bool tool_unsetenv(const char* name) {
  return _putenv_s(name, "") == 0;
}
#else
static int tool_mkdir(const char* path, mode_t mode) {
  return mkdir(path, mode);
}
static bool tool_setenv(const char* name, const char* value) {
  return setenv(name, value, 1) == 0;
}
static bool tool_unsetenv(const char* name) {
  return unsetenv(name) == 0;
}
#endif

#define setenv(name, value, overwrite) tool_setenv(name, value)
#define unsetenv(name) tool_unsetenv(name)

typedef struct {
  cepRuntime *runtime;
  cepRuntime *previous;
} CepToolRuntime;

static void tool_usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s (--save|--load) --bundle <path> [--branch <name>] "
          "[--hist-beats <beats>] [--root <path>]\n",
          prog);
  fprintf(stderr, "  --save         Export active branch to bundle path\n");
  fprintf(stderr, "  --load         Import bundle into active branch\n");
  fprintf(stderr, "  --bundle       Target path (save) or source bundle (load)\n");
  fprintf(stderr, "  --branch       Branch name (defaults to CEP_CPS_BRANCH or 'default')\n");
  fprintf(stderr, "  --hist-beats   Optional history window when saving\n");
  fprintf(stderr, "  --root         Override CEP_CPS_ROOT for this invocation\n");
}

static bool tool_make_abs_path(const char *input, char *buffer, size_t cap) {
  if (!input || !buffer || cap == 0u) {
    return false;
  }
  if (input[0] == '/') {
    int need = snprintf(buffer, cap, "%s", input);
    return need >= 0 && (size_t)need < cap;
  }
  if (realpath(input, buffer)) {
    return true;
  }
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) {
    return false;
  }
  int need = snprintf(buffer, cap, "%s/%s", cwd, input);
  return need >= 0 && (size_t)need < cap;
}

static bool tool_path_is_external(const char *abs_path) {
  if (!abs_path || abs_path[0] != '/') {
    return false;
  }
  const char *prefix = "/data";
  size_t prefix_len = strlen(prefix);
  if (strncmp(abs_path, prefix, prefix_len) != 0) {
    return true;
  }
  char next = abs_path[prefix_len];
  return !(next == '\0' || next == '/');
}

static CepToolRuntime tool_runtime_start(void) {
  CepToolRuntime scope = {.runtime = NULL, .previous = NULL};
  scope.runtime = cep_runtime_create();
  if (!scope.runtime) {
    return scope;
  }
  scope.previous = cep_runtime_set_active(scope.runtime);

  cep_cell_system_initiate();
  if (!cep_l0_bootstrap() ||
      !cep_namepool_bootstrap() ||
      !cep_runtime_attach_metadata(scope.runtime)) {
    cep_runtime_restore_active(scope.previous);
    cep_runtime_destroy(scope.runtime);
    scope.runtime = NULL;
    scope.previous = NULL;
    return scope;
  }

  cepHeartbeatPolicy policy = {
    .start_at = 0u,
    .ensure_directories = true,
    .enforce_visibility = false,
    .boot_ops = true,
  };
  if (!cep_heartbeat_configure(NULL, &policy) || !cep_heartbeat_startup()) {
    cep_runtime_restore_active(scope.previous);
    cep_runtime_destroy(scope.runtime);
    scope.runtime = NULL;
    scope.previous = NULL;
    return scope;
  }
  return scope;
}

static void tool_runtime_stop(CepToolRuntime *scope) {
  if (!scope || !scope->runtime) {
    return;
  }
  cep_runtime_set_active(scope->runtime);
  cep_stream_clear_pending();
  cep_heartbeat_shutdown();
  (void)cep_runtime_shutdown(scope->runtime);
  cep_runtime_restore_active(scope->previous);
  cep_runtime_destroy(scope->runtime);
  scope->runtime = NULL;
  scope->previous = NULL;
}

static bool tool_copy_file(const char *src_path, const char *dst_path) {
  int src_fd = open(src_path, O_RDONLY);
  if (src_fd < 0) {
    return false;
  }
  int dst_fd = open(dst_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (dst_fd < 0) {
    close(src_fd);
    return false;
  }
  char buffer[65536];
  ssize_t rd = 0;
  bool ok = true;
  while ((rd = read(src_fd, buffer, sizeof buffer)) > 0) {
    ssize_t wr_total = 0;
    while (wr_total < rd) {
      ssize_t wr = write(dst_fd, buffer + wr_total, (size_t)(rd - wr_total));
      if (wr < 0) {
        ok = false;
        break;
      }
      wr_total += wr;
    }
    if (!ok) {
      break;
    }
  }
  if (rd < 0) {
    ok = false;
  }
  if (fsync(dst_fd) != 0) {
    ok = false;
  }
  close(dst_fd);
  close(src_fd);
  return ok;
}

static bool tool_copy_tree(const char *src_dir, const char *dst_dir) {
  struct stat st = {0};
  if (stat(src_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
    return false;
  }
  if (stat(dst_dir, &st) != 0) {
    if (tool_mkdir(dst_dir, 0755) != 0) {
      return false;
    }
  }

  DIR *dir = opendir(src_dir);
  if (!dir) {
    return false;
  }
  struct dirent *ent = NULL;
  char src_path[PATH_MAX];
  char dst_path[PATH_MAX];
  bool ok = true;
  while ((ent = readdir(dir)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
      continue;
    }
    int need_src = snprintf(src_path, sizeof src_path, "%s/%s", src_dir, ent->d_name);
    int need_dst = snprintf(dst_path, sizeof dst_path, "%s/%s", dst_dir, ent->d_name);
    if (need_src < 0 || need_dst < 0 ||
        (size_t)need_src >= sizeof src_path || (size_t)need_dst >= sizeof dst_path) {
      ok = false;
      break;
    }
    struct stat child_st = {0};
    if (stat(src_path, &child_st) != 0) {
      ok = false;
      break;
    }
    if (S_ISDIR(child_st.st_mode)) {
      if (!tool_copy_tree(src_path, dst_path)) {
        ok = false;
        break;
      }
    } else if (S_ISREG(child_st.st_mode)) {
      if (!tool_copy_file(src_path, dst_path)) {
        ok = false;
        break;
      }
    }
  }
  closedir(dir);
  return ok;
}

static bool tool_promote_stage(const char *stage_dir) {
  if (!stage_dir) {
    return false;
  }
  const char *branch_dir = cps_runtime_branch_dir();
  if (!branch_dir) {
    return false;
  }
  static const char *artifacts[] = {
    "branch.meta",
    "branch.idx",
    "branch.dat",
    "branch.ckp",
    "branch.frames",
  };
  for (size_t i = 0; i < sizeof artifacts / sizeof artifacts[0]; ++i) {
    char src_path[PATH_MAX];
    char dst_path[PATH_MAX];
    char tmp_path[PATH_MAX];
    int need_src = snprintf(src_path, sizeof src_path, "%s/%s", stage_dir, artifacts[i]);
    int need_dst = snprintf(dst_path, sizeof dst_path, "%s/%s", branch_dir, artifacts[i]);
    int need_tmp = snprintf(tmp_path, sizeof tmp_path, "%s.import", dst_path);
    if (need_src < 0 || need_dst < 0 || need_tmp < 0 ||
        (size_t)need_src >= sizeof src_path ||
        (size_t)need_dst >= sizeof dst_path ||
        (size_t)need_tmp >= sizeof tmp_path) {
      return false;
    }
    struct stat st = {0};
    if (stat(src_path, &st) != 0) {
      if (strcmp(artifacts[i], "branch.idx") == 0 || strcmp(artifacts[i], "branch.dat") == 0) {
        return false;
      }
      continue;
    }
    if (!tool_copy_file(src_path, tmp_path)) {
      return false;
    }
    if (rename(tmp_path, dst_path) != 0) {
      unlink(tmp_path);
      return false;
    }
  }

  char stage_cas[PATH_MAX];
  char branch_cas[PATH_MAX];
  int need_stage = snprintf(stage_cas, sizeof stage_cas, "%s/cas", stage_dir);
  int need_branch = snprintf(branch_cas, sizeof branch_cas, "%s/cas", branch_dir);
  if (need_stage < 0 || need_branch < 0 ||
      (size_t)need_stage >= sizeof stage_cas ||
      (size_t)need_branch >= sizeof branch_cas) {
    return false;
  }
  struct stat cas_st = {0};
  if (stat(stage_cas, &cas_st) == 0 && S_ISDIR(cas_st.st_mode)) {
    if (!tool_copy_tree(stage_cas, branch_cas)) {
      return false;
    }
  }
  return true;
}

int main(int argc, char **argv) {
  bool do_save = false;
  bool do_load = false;
  const char *bundle_arg = NULL;
  const char *branch_arg = NULL;
  const char *root_arg = NULL;
  uint64_t hist_beats = 0u;
  bool has_hist = false;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--save") == 0) {
      do_save = true;
    } else if (strcmp(argv[i], "--load") == 0) {
      do_load = true;
    } else if (strcmp(argv[i], "--bundle") == 0 && i + 1 < argc) {
      bundle_arg = argv[++i];
    } else if (strcmp(argv[i], "--branch") == 0 && i + 1 < argc) {
      branch_arg = argv[++i];
    } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
      root_arg = argv[++i];
    } else if (strcmp(argv[i], "--hist-beats") == 0 && i + 1 < argc) {
      const char *text = argv[++i];
      char *end = NULL;
      hist_beats = strtoull(text, &end, 10);
      if (!text || end == text || (end && *end)) {
        fprintf(stderr, "invalid hist-beats value: %s\n", text ? text : "(null)");
        return 1;
      }
      has_hist = true;
    } else {
      tool_usage(argv[0]);
      return 1;
    }
  }

  if (do_save == do_load || !bundle_arg) {
    tool_usage(argv[0]);
    return 1;
  }
  if (do_load && has_hist) {
    fprintf(stderr, "--hist-beats is only valid with --save\n");
    return 1;
  }

  char bundle_path[PATH_MAX];
  if (!tool_make_abs_path(bundle_arg, bundle_path, sizeof bundle_path)) {
    fprintf(stderr, "invalid bundle path: %s\n", bundle_arg);
    return 1;
  }
  bool external = tool_path_is_external(bundle_path);
  if (external && bundle_path[0] != '/') {
    fprintf(stderr, "external bundle paths must be absolute: %s\n", bundle_arg);
    return 1;
  }

  char root_path[PATH_MAX];
  if (root_arg) {
    if (!tool_make_abs_path(root_arg, root_path, sizeof root_path)) {
      fprintf(stderr, "invalid root path: %s\n", root_arg);
      return 1;
    }
    setenv("CEP_CPS_ROOT", root_path, 1);
  }
  if (branch_arg) {
    setenv("CEP_CPS_BRANCH", branch_arg, 1);
  }

  CepToolRuntime runtime = tool_runtime_start();
  if (!runtime.runtime) {
    fprintf(stderr, "failed to bootstrap runtime\n");
    return 1;
  }
  if (!cps_runtime_is_ready() || !cep_heartbeat_rt_root()) {
    fprintf(stderr, "CPS runtime not ready (check CEP_CPS_ROOT/branch)\n");
    tool_runtime_stop(&runtime);
    return 1;
  }

  int rc = CPS_OK;
  if (do_save) {
    cpsStorageSaveOptions opts = {
      .target_path = bundle_path,
      .history_window_beats = has_hist ? hist_beats : 0u,
    };
    uint64_t copied_bytes = 0u;
    uint64_t cas_bytes = 0u;
    uint64_t cas_blobs = 0u;
    char bundle_out[PATH_MAX];
    rc = cps_storage_export_active_branch(&opts,
                                          bundle_out,
                                          sizeof bundle_out,
                                          &copied_bytes,
                                          &cas_bytes,
                                          &cas_blobs);
    if (rc == CPS_OK) {
      printf("save ok bundle=%s files_bytes=%" PRIu64 " cas_bytes=%" PRIu64 " cas_blobs=%" PRIu64 "\n",
             bundle_out,
             copied_bytes,
             cas_bytes,
             cas_blobs);
      if (external) {
        printf("external path (absolute enforced): %s\n", bundle_out);
      }
    }
  } else {
    char staged_path[PATH_MAX];
    if (!cps_storage_stage_bundle_dir(bundle_path, staged_path, sizeof staged_path)) {
      rc = CPS_ERR_VERIFY;
    } else if (!tool_promote_stage(staged_path)) {
      rc = CPS_ERR_IO;
    } else {
      printf("load ok staged=%s\n", bundle_path);
    }
  }

  tool_runtime_stop(&runtime);
  if (rc != CPS_OK) {
    fprintf(stderr, "operation failed rc=%d\n", rc);
    return 1;
  }
  return 0;
}
