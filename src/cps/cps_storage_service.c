/* Copyright (c) 2025 Victor M. Barrientos
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cps_storage_service.h"

#include "cps_engine.h"
#include "cps_runtime.h"

#include "blake3.h"
#include "cep_cell.h"
#include "cep_cei.h"
#include "cep_flat_stream.h"
#include "cep_flat_serializer.h"
#include "cep_heartbeat.h"
#include "cep_ops.h"
#include "cep_runtime.h"
#include "../l0_kernel/cep_namepool.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char k_cps_topic_storage_commit[] = "persist.commit";

CEP_DEFINE_STATIC_DT(dt_cps_storage_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_cps_storage_sev_crit, CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_ops_root_name_cps, CEP_ACRO("CEP"), CEP_WORD("ops"));
CEP_DEFINE_STATIC_DT(dt_envelope_name_cps, CEP_ACRO("CEP"), CEP_WORD("envelope"));
CEP_DEFINE_STATIC_DT(dt_close_name_cps, CEP_ACRO("CEP"), CEP_WORD("close"));
CEP_DEFINE_STATIC_DT(dt_state_field_cps, CEP_ACRO("CEP"), CEP_WORD("state"));
CEP_DEFINE_STATIC_DT(dt_verb_field_cps, CEP_ACRO("CEP"), CEP_WORD("verb"));
CEP_DEFINE_STATIC_DT(dt_target_field_cps, CEP_ACRO("CEP"), CEP_WORD("target"));
CEP_DEFINE_STATIC_DT(dt_bundle_field_cps, CEP_ACRO("CEP"), CEP_WORD("bundle"));
CEP_DEFINE_STATIC_DT(dt_op_checkpt_dt, CEP_ACRO("CEP"), CEP_WORD("op/checkpt"));
CEP_DEFINE_STATIC_DT(dt_op_compact_dt, CEP_ACRO("CEP"), CEP_WORD("op/compact"));
CEP_DEFINE_STATIC_DT(dt_op_sync_dt, CEP_ACRO("CEP"), CEP_WORD("op/sync"));
CEP_DEFINE_STATIC_DT(dt_op_import_dt, CEP_ACRO("CEP"), CEP_WORD("op/import"));
CEP_DEFINE_STATIC_DT(dt_ist_run_dt, CEP_ACRO("CEP"), CEP_WORD("ist:run"));
CEP_DEFINE_STATIC_DT(dt_ist_exec_dt, CEP_ACRO("CEP"), CEP_WORD("ist:exec"));
CEP_DEFINE_STATIC_DT(dt_ist_ok_dt, CEP_ACRO("CEP"), CEP_WORD("ist:ok"));
CEP_DEFINE_STATIC_DT(dt_ist_fail_dt, CEP_ACRO("CEP"), CEP_WORD("ist:fail"));
CEP_DEFINE_STATIC_DT(dt_sts_ok_dt, CEP_ACRO("CEP"), CEP_WORD("sts:ok"));
CEP_DEFINE_STATIC_DT(dt_sts_fail_dt, CEP_ACRO("CEP"), CEP_WORD("sts:fail"));

#define CPS_STORAGE_COPY_CHUNK 65536u

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
      if (temp[0] != '\0' && mkdir(temp, 0755) != 0 && errno != EEXIST) {
        return false;
      }
      temp[i] = saved;
    }
  }
  if (mkdir(temp, 0755) != 0 && errno != EEXIST) {
    return false;
  }
  return true;
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
    fprintf(fp, "artifacts=%zu\n", artifact_count);
    for (size_t i = 0; i < artifact_count; ++i) {
      const cps_storage_bundle_artifact *artifact = &artifacts[i];
      if (!artifact->name) {
        continue;
      }
      if (!artifact->present) {
        fprintf(fp, "artifact %s missing\n", artifact->name);
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
                                            char *bundle_path,
                                            size_t bundle_path_len,
                                            uint64_t *copied_bytes,
                                            uint64_t *cas_bytes,
                                            uint64_t *cas_blobs) {
  if (!branch_dir || !branch_name || !bundle_path || bundle_path_len == 0u) {
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
  char exports_dir[PATH_MAX];
  int need = snprintf(exports_dir, sizeof exports_dir, "%s/exports", branch_dir);
  if (need < 0 || (size_t)need >= sizeof exports_dir) {
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
  char bundle_dir[PATH_MAX];
  need = snprintf(bundle_dir, sizeof bundle_dir, "%s/%s-%s", exports_dir, branch_slug, timestamp);
  if (need < 0 || (size_t)need >= sizeof bundle_dir) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (!cps_storage_mkdirs(bundle_dir)) {
    return CPS_ERR_IO;
  }
  cps_storage_bundle_artifact artifacts[] = {
    {.name = "branch.meta"},
    {.name = "branch.idx"},
    {.name = "branch.dat"},
    {.name = "branch.ckp"},
    {.name = "branch.frames"},
  };
  for (size_t i = 0; i < sizeof artifacts / sizeof artifacts[0]; ++i) {
    cps_storage_bundle_artifact *artifact = &artifacts[i];
    char src_path[PATH_MAX];
    need = snprintf(src_path, sizeof src_path, "%s/%s", branch_dir, artifact->name);
    if (need < 0 || (size_t)need >= sizeof src_path) {
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
  uint64_t total_branch_bytes = copied_bytes ? *copied_bytes : 0u;
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
  int path_need = snprintf(bundle_path, bundle_path_len, "%s", bundle_dir);
  if (path_need < 0 || (size_t)path_need >= bundle_path_len) {
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
} cpsStorageSink;

static void cps_storage_emit_cei(const cepDT *severity, const char *detail) {
  if (!severity || !detail) {
    return;
  }
  cepCeiRequest req = {
    .severity = *severity,
    .topic = k_cps_topic_storage_commit,
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
  return cep_flat_reader_feed(sink->reader, chunk, size);
}

static bool cps_storage_apply_reader(cps_engine *engine, cepFlatReader *reader) {
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
    if (engine->ops->abort_beat) {
      engine->ops->abort_beat(txn);
    }
    return false;
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

static const char *cps_storage_active_branch(void) {
  const char *name = cps_runtime_branch_name();
  return (name && name[0] != '\0') ? name : "default";
}

static bool cps_storage_ops_enabled(void) {
  static int cached = -1;
  if (cached == -1) {
    const char *env = getenv("CEP_CPS_OPS_ENABLE");
    cached = (env && env[0] && strcmp(env, "0") != 0) ? 1 : 0;
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

static bool cps_storage_run_sync_op(cepOID oid, const char *branch) {
  const char *effective_branch = (branch && branch[0] != '\0') ? branch : cps_storage_active_branch();
  const char *branch_dir = cps_runtime_branch_dir();
  if (!branch_dir) {
    cps_storage_fail_operation(oid, "sync", effective_branch, CPS_ERR_INVALID_ARGUMENT, "branch directory unavailable");
    return false;
  }
  char bundle_path[PATH_MAX];
  uint64_t copied_bytes = 0u;
  uint64_t cas_bytes = 0u;
  uint64_t cas_blobs = 0u;
  int rc = cps_storage_export_branch_bundle(branch_dir,
                                            effective_branch,
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
           "branch=%.48s bundle=%.64s files_bytes=%" PRIu64 " cas_blobs=%" PRIu64 " cas_bytes=%" PRIu64 " frames=%" PRIu64,
           effective_branch ? effective_branch : "-",
           bundle_label ? bundle_label : "-",
           copied_bytes,
           cas_blobs,
           cas_bytes,
           stats.stat_frames);
  cps_storage_complete_success(oid, "sync", summary);
  return true;
}

static bool cps_storage_run_import_op(cepOID oid, const char *branch, const char *bundle_path) {
  if (!bundle_path || bundle_path[0] == '\0') {
    cps_storage_fail_operation(oid, "import", branch, CPS_ERR_INVALID_ARGUMENT, "bundle path missing");
    return false;
  }
  char staged_path[PATH_MAX];
  if (!cps_storage_stage_bundle_dir(bundle_path, staged_path, sizeof staged_path)) {
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
           bundle_path,
           staged_path);
  cps_storage_complete_success(oid, "import", summary);
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
  if (!is_checkpoint && !is_compact && !is_sync && !is_import) {
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
      (void)cps_storage_run_sync_op(oid, branch_buf);
    }
  } else if (cep_dt_compare(&verb, dt_op_import_dt()) == 0) {
    const char *bundle_path = cps_storage_read_text_field(envelope, dt_bundle_field_cps());
    if (!bundle_path || bundle_path[0] == '\0') {
      cps_storage_fail_operation(oid, "import", branch_buf, CPS_ERR_INVALID_ARGUMENT, "bundle path missing");
      return;
    }
    if (cps_storage_mark_state(oid, dt_ist_exec_dt(), "processing", 0)) {
      (void)cps_storage_run_import_op(oid, branch_buf, bundle_path);
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

  cps_engine *engine = cps_runtime_engine();
  if (!engine || !engine->ops) {
    return false;
  }

  cepCell *root = cep_root();
  if (!root) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(), "root cell missing during persistence");
    return false;
  }

  cepFlatReader *reader = cep_flat_reader_create();
  if (!reader) {
    cps_storage_emit_cei(dt_cps_storage_sev_warn(), "failed to allocate flat reader for persistence");
    return false;
  }

  cpsStorageSink sink = {
    .reader = reader,
  };

  bool emitted = cep_flat_stream_emit_cell(root,
                                           NULL,
                                           cps_storage_reader_sink,
                                           &sink,
                                           CEP_FLAT_STREAM_DEFAULT_BLOB_PAYLOAD);
  if (!emitted || !cep_flat_reader_commit(reader) || !cep_flat_reader_ready(reader)) {
    cps_storage_emit_cei(dt_cps_storage_sev_crit(), "serializer frame emit/parse failed");
    cep_flat_reader_destroy(reader);
    return false;
  }

  bool ok = cps_storage_apply_reader(engine, reader);
  if (!ok) {
    cps_storage_emit_cei(dt_cps_storage_sev_crit(), "CPS engine commit failed");
  }
  cep_flat_reader_destroy(reader);
  cps_storage_process_ops();
  return ok;
}
