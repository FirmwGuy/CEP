/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cps_flatfile.h"

#include "blake3.h"
#include "cep_cell.h"
#include "cep_cei.h"
#include "cep_crc32c.h"
#include "cep_heartbeat.h"
#include "cep_flat_serializer.h"
#include "cep_flat_stream.h"
#include "cep_ops.h"

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(_WIN32)
#include <io.h>
#include <direct.h>
#endif
#include <zlib.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif
#define CPS_OPEN_FLAGS(flags) ((flags) | O_BINARY)

static const char k_cps_topic_frame_io[] = "persist.frame.io";
static const char k_cps_topic_checkpoint[] = "persist.checkpoint";
static const char k_cps_topic_recover[] = "persist.recover";
static const char k_cps_topic_bootstrap[] = "persist.bootstrap";
CEP_DEFINE_STATIC_DT(dt_cps_sev_crit, CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_cps_sev_warn, CEP_ACRO("CEP"), CEP_WORD("sev:warn"));
CEP_DEFINE_STATIC_DT(dt_cps_sev_debug, CEP_ACRO("CEP"), CEP_WORD("sev:debug"));
CEP_DEFINE_STATIC_DT(dt_persist_root_name, CEP_ACRO("CEP"), CEP_WORD("persist"));
CEP_DEFINE_STATIC_DT(dt_persist_metrics_name, CEP_ACRO("CEP"), CEP_WORD("metrics"));
CEP_DEFINE_STATIC_DT(dt_persist_engine_field, CEP_ACRO("CEP"), CEP_WORD("kv_eng"));
CEP_DEFINE_STATIC_DT(dt_persist_frames_field, CEP_ACRO("CEP"), CEP_WORD("frames"));
CEP_DEFINE_STATIC_DT(dt_persist_beats_field, CEP_ACRO("CEP"), CEP_WORD("beats"));
CEP_DEFINE_STATIC_DT(dt_persist_bytes_idx_field, CEP_ACRO("CEP"), CEP_WORD("bytes_idx"));
CEP_DEFINE_STATIC_DT(dt_persist_bytes_dat_field, CEP_ACRO("CEP"), CEP_WORD("bytes_dat"));
CEP_DEFINE_STATIC_DT(dt_persist_cas_hits_field, CEP_ACRO("CEP"), CEP_WORD("cas_hits"));
CEP_DEFINE_STATIC_DT(dt_persist_cas_miss_field, CEP_ACRO("CEP"), CEP_WORD("cas_miss"));
CEP_DEFINE_STATIC_DT(dt_persist_cas_latency_field, CEP_ACRO("CEP"), CEP_WORD("cas_lat_ns"));

#define CPS_FLATFILE_META_MAGIC    0x43505331u /* "CPS1" */
#define CPS_FLATFILE_META_VERSION  1u
#define CPS_FLATFILE_TOC_MAGIC     0x544F4331u /* "TOC1" */
#define CPS_FLATFILE_TRAIL_MAGIC   0x54524C31u /* "TRL1" */
#define CPS_FLATFILE_CKP_MAGIC     0x434B5031u /* "CKP1" */
#define CPS_FLATFILE_CAS_MANIFEST_MAGIC 0x4341534Du /* "CASM" */
#define CPS_FLATFILE_CAS_MANIFEST_VERSION 1u

#define CPS_RECORD_TYPE_CELL_DESC  0x01u
#define CPS_RECORD_TYPE_PAYLOAD    0x02u

#define CPS_FLATFILE_TOC_FLAG_CAS_REF  0x00000001u

#define CPS_FLATFILE_PAYLOAD_FLAG_KIND_MASK  0x000000FFu
#define CPS_FLATFILE_PAYLOAD_FLAG_AEAD_SHIFT 8u
#define CPS_FLATFILE_PAYLOAD_FLAG_AEAD_MASK  (0x000000FFu << CPS_FLATFILE_PAYLOAD_FLAG_AEAD_SHIFT)

#if defined(_WIN32)
/* Provide POSIX-like helpers on Windows toolchains. */
#define fsync _commit
static ssize_t
cep_pread_win(int fd, void* buf, size_t count, off_t offset)
{
    if (_lseeki64(fd, offset, SEEK_SET) < 0) {
        return -1;
    }
    return _read(fd, buf, (unsigned int)count);
}
#define pread(fd, buf, count, offset) cep_pread_win(fd, buf, count, offset)
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

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t format_ver;
  uint16_t engine_id;
  uint64_t branch_id_hi;
  uint64_t branch_id_lo;
  uint64_t head_idx_ofs;
  uint64_t head_idx_len;
  uint64_t head_dat_ofs;
  uint64_t head_dat_len;
  uint64_t last_beat;
  uint64_t head_frame_id;
  uint8_t head_merkle[32];
  uint32_t checkpoint_gen;
  uint32_t flags;
  uint8_t reserved[140];
  uint32_t crc32c;
} cps_flatfile_meta;

_Static_assert(sizeof(cps_flatfile_meta) == 256u, "branch.meta must stay 256 bytes");

typedef struct __attribute__((packed)) {
  uint64_t beat;
  uint64_t frame_id;
  uint64_t idx_ofs;
  uint64_t idx_len;
  uint64_t dat_ofs;
  uint64_t dat_len;
} cps_flatfile_frame_dir_entry_disk;

_Static_assert(sizeof(cps_flatfile_frame_dir_entry_disk) == 48u,
               "frame directory entries must stay packed");

typedef struct {
  cps_flatfile_frame_dir_entry_disk *entries;
  size_t count;
} cps_flatfile_frame_dir_snapshot;

typedef struct {
  uint8_t hash[CEP_FLAT_HASH_SIZE];
  uint64_t payload_size;
  uint8_t codec;
  uint8_t aead_mode;
} cps_flatfile_cas_manifest_entry;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t version;
  uint16_t reserved;
  uint64_t entry_count;
} cps_flatfile_cas_manifest_header_disk;

typedef struct __attribute__((packed)) {
  uint8_t hash[CEP_FLAT_HASH_SIZE];
  uint64_t payload_size;
  uint8_t codec;
  uint8_t aead_mode;
  uint8_t reserved[6];
} cps_flatfile_cas_manifest_entry_disk;

typedef struct {
  char *root_dir;
  char *branch_name;
  char *branch_dir;
  char *tmp_dir;
  char *idx_path;
  char *dat_path;
  char *meta_path;
  char *meta_tmp_path;
  char *ckp_path;
  char *dir_path;
  char *cas_dir;
  char *cas_manifest_path;
  uint32_t checkpoint_interval;
  uint32_t mini_toc_hint;
  bool create_branch;
  uint64_t next_frame_id;
  uint64_t last_checkpoint_beat;
  cps_flatfile_meta meta;
  uint64_t stat_frames;
  uint64_t stat_beats;
  uint64_t stat_bytes_idx;
  uint64_t stat_bytes_dat;
  uint64_t stat_cas_hits;
  uint64_t stat_cas_misses;
  uint64_t stat_cas_lookup_ns;
  cps_flatfile_cas_manifest_entry *cas_entries;
  size_t cas_entry_count;
  size_t cas_entry_cap;
  bool cas_manifest_dirty;
} cps_flatfile_state;

typedef struct {
  uint64_t key_hash;
  uint64_t key_ofs;
  uint64_t val_ofs;
  uint32_t key_len;
  uint32_t val_len;
  uint32_t rtype;
  uint32_t flags;
} cps_flatfile_toc_entry;

typedef struct __attribute__((packed)) {
  uint32_t rtype;
  uint32_t key_len;
  uint32_t val_len;
  uint32_t flags;
} cps_flatfile_record_header;

typedef struct __attribute__((packed)) {
  uint64_t key_hash;
  uint64_t chunk_offset;
  uint64_t chunk_total;
  uint32_t chunk_ordinal;
  uint32_t chunk_size;
  uint32_t chunk_crc32;
  uint32_t reserved;
} cps_flatfile_payload_header;

typedef struct {
  uint64_t total_size;
  uint64_t chunk_offset;
  uint64_t chunk_size;
  uint64_t ordinal;
  uint8_t payload_kind;
  uint8_t aead_mode;
  const uint8_t *chunk_bytes;
  size_t chunk_bytes_len;
} cps_flatfile_chunk_info;

typedef struct {
  cepFlatPayloadRefKind kind;
  cepFlatHashAlgorithm  hash_alg;
  uint8_t               codec;
  uint8_t               aead_mode;
  uint64_t              payload_size;
  const uint8_t        *hash_bytes;
  size_t                hash_len;
} cps_flatfile_payload_ref_info;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t entry_count;
} cps_flatfile_toc_header_disk;

typedef struct __attribute__((packed)) {
  uint64_t key_hash;
  uint64_t key_ofs;
  uint64_t val_ofs;
  uint32_t key_len;
  uint32_t val_len;
  uint32_t rtype;
  uint32_t flags;
} cps_flatfile_toc_entry_disk;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t reserved;
  uint64_t beat;
  uint64_t frame_id;
  uint32_t toc_count;
  uint32_t flags;
  uint8_t merkle[32];
} cps_flatfile_trailer_disk;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t entry_count;
  uint64_t beat;
  uint64_t frame_id;
  uint64_t dat_ofs;
  uint64_t idx_ofs;
} cps_flatfile_ckp_header_disk;

typedef struct {
  cps_flatfile_ckp_header_disk header;
  cps_flatfile_toc_entry_disk *entries;
} cps_flatfile_checkpoint_block;

typedef struct {
  uint64_t hash;
  uint32_t key_len;
  uint8_t *key;
} cps_flatfile_scanned_key;

typedef struct {
  cps_flatfile_state *owner;
  uint64_t beat;
  uint64_t frame_id;
  int dat_fd;
  int idx_fd;
  char *frame_dir;
  char *dat_tmp_path;
  char *idx_tmp_path;
  size_t dat_bytes;
  size_t idx_bytes;
  blake3_hasher merkle;
  bool merkle_ready;
  uint32_t crc32;
  bool crc_ready;
  cps_flatfile_toc_entry *toc_entries;
  size_t toc_len;
  size_t toc_cap;
} cps_flatfile_txn_state;

static cps_flatfile_state *cps_flatfile_state_from(cps_engine *engine);
static cps_flatfile_txn_state *cps_flatfile_txn_from(cps_txn *txn);
static int cps_flatfile_ensure_directories(cps_flatfile_state *state);
static int cps_flatfile_prepare_txn_files(cps_flatfile_txn_state *txn);
static void cps_flatfile_txn_cleanup(cps_flatfile_txn_state *txn);
static int cps_flatfile_toc_push(cps_flatfile_txn_state *txn, uint32_t rtype, uint64_t key_hash, uint64_t key_ofs, uint32_t key_len, uint64_t val_ofs, uint32_t val_len);
static uint64_t cps_flatfile_key_hash(const uint8_t *data, size_t len);
static size_t cps_flatfile_record_header_span(uint32_t rtype);
static int cps_flatfile_extract_chunk_info(cps_slice key, cps_slice value, cps_flatfile_chunk_info *info);
static bool cps_flatfile_decode_chunk_key(const uint8_t *key, size_t key_len, size_t *base_len, uint64_t *ordinal);
static bool cps_flatfile_read_varint(const uint8_t *data, size_t size, size_t *offset, uint64_t *value);
static bool cps_flatfile_parse_cell_desc_payload_ref(cps_slice value,
                                                     uint8_t *payload_kind,
                                                     uint64_t *payload_fp,
                                                     cps_flatfile_payload_ref_info *ref_info);
static bool cps_flatfile_publish_metrics(cps_flatfile_state *state);
static cepDT cps_flatfile_branch_dt(const cps_flatfile_state *state);
static int cps_flatfile_checkpoint_finalize(cps_flatfile_state *state, uint64_t beat);
static int cps_flatfile_iterate_checkpoints(cps_flatfile_state *state,
                                            bool (*cb)(const cps_flatfile_ckp_header_disk *,
                                                       const cps_flatfile_toc_entry_disk *,
                                                       void *user),
                                            void *user);
static bool cps_flatfile_checkpoint_scan_cb(const cps_flatfile_ckp_header_disk *header,
                                            const cps_flatfile_toc_entry_disk *entries,
                                            void *user);
typedef struct {
  cps_flatfile_state *state;
  int idx_fd;
  int dat_fd;
  cps_slice prefix;
  cps_scan_cb cb;
  void *user;
  cps_flatfile_scanned_key **visited;
  size_t *visited_len;
  size_t *visited_cap;
  int rc;
} cps_flatfile_checkpoint_scan_ctx;
static int cps_flatfile_validate_head_trailer(const cps_flatfile_state *state, int idx_fd);
static int cps_flatfile_reset_branch(cps_flatfile_state *state, int idx_fd, int dat_fd);
static int cps_flatfile_recover_branch(cps_flatfile_state *state);
static int cps_flatfile_fetch_entry_value(int idx_fd,
                                          int dat_fd,
                                          const cps_flatfile_toc_entry_disk *entry,
                                          cps_slice key,
                                          cps_buf *out);
static int cps_flatfile_lookup_checkpoint_record(cps_flatfile_state *state, cps_slice key, cps_buf *out);
static bool cps_flatfile_scan_keys_contains(cps_flatfile_scanned_key *keys, size_t len, const uint8_t *key, uint32_t key_len, uint64_t hash);
static int cps_flatfile_scan_keys_add(cps_flatfile_scanned_key **keys,
                                      size_t *len,
                                      size_t *cap,
                                      const uint8_t *key,
                                      uint32_t key_len,
                                      uint64_t hash);
static void cps_flatfile_scan_keys_clear(cps_flatfile_scanned_key *keys, size_t len);
static int cps_flatfile_scan_entries_with_prefix(cps_flatfile_state *state,
                                                 int idx_fd,
                                                 int dat_fd,
                                                 const cps_flatfile_toc_entry_disk *entries,
                                                 uint32_t entry_count,
                                                 cps_slice prefix,
                                                 cps_scan_cb cb,
                                                 void *user,
                                                 cps_flatfile_scanned_key **visited,
                                                 size_t *visited_len,
                                                 size_t *visited_cap);
static int cps_flatfile_write_mini_toc_and_trailer(cps_flatfile_txn_state *txn,
                                                   const uint8_t merkle[32],
                                                   uint64_t dat_base,
                                                   uint64_t idx_base,
                                                   uint64_t *out_bytes);
static int cps_flatfile_write_checkpoint_snapshot(cps_flatfile_state *state,
                                                  uint64_t beat,
                                                  uint64_t frame_id,
                                                  uint64_t dat_ofs,
                                                  uint64_t idx_ofs,
                                                  const cps_flatfile_toc_entry *entries,
                                                  size_t entry_count);
static int cps_flatfile_write_all(int fd, const uint8_t *data, size_t len);
static int cps_flatfile_append_file(const char *dst_path, const char *src_path, uint64_t *out_offset, uint64_t *out_len);
static int cps_flatfile_read_exact_fd(int fd, uint64_t ofs, void *buf, size_t len);
static void cps_flatfile_frame_dir_snapshot_destroy(cps_flatfile_frame_dir_snapshot *snapshot);
static int cps_flatfile_frame_dir_snapshot_load(const cps_flatfile_state *state,
                                                cps_flatfile_frame_dir_snapshot *snapshot);
static int cps_flatfile_frame_dir_append(const cps_flatfile_state *state,
                                         uint64_t beat,
                                         uint64_t frame_id,
                                         uint64_t idx_ofs,
                                         uint64_t idx_len,
                                         uint64_t dat_ofs,
                                         uint64_t dat_len);
static int cps_flatfile_frame_dir_trim_to_fit(cps_flatfile_state *state,
                                              uint64_t idx_size,
                                              uint64_t dat_size,
                                              cps_flatfile_frame_dir_entry_disk *out_tail);
static int cps_flatfile_frame_dir_seed_from_meta(cps_flatfile_state *state);
static int cps_flatfile_apply_tail_entry(cps_flatfile_state *state,
                                         int idx_fd,
                                         const cps_flatfile_frame_dir_entry_disk *entry);
static int cps_flatfile_load_frame_entries(int idx_fd,
                                           uint64_t frame_ofs,
                                           uint64_t frame_len,
                                           cps_flatfile_toc_entry_disk **entries_out,
                                           uint32_t *entry_count);
static int cps_flatfile_lookup_frame_record_fd(int idx_fd,
                                               int dat_fd,
                                               uint64_t frame_ofs,
                                               uint64_t frame_len,
                                               cps_slice key,
                                               cps_buf *out);
static int cps_flatfile_try_cas_read(cps_engine *engine, cps_slice key, cps_buf *out);
static bool cps_flatfile_parse_cell_desc_payload_ref(cps_slice value,
                                                     uint8_t *payload_kind,
                                                     uint64_t *payload_fp,
                                                     cps_flatfile_payload_ref_info *ref_info);
static bool cps_flatfile_hash_bytes(const void *data, size_t len, uint8_t out[CEP_FLAT_HASH_SIZE]);
static bool cps_flatfile_buf_reserve(cps_buf *buf, size_t extra);
static bool cps_flatfile_buf_append(cps_buf *buf, const void *data, size_t len);
static bool cps_flatfile_buf_append_u8(cps_buf *buf, uint8_t value);
static bool cps_flatfile_buf_append_varint(cps_buf *buf, uint64_t value);
static size_t cps_flatfile_varint_length(uint64_t value);
static uint8_t *cps_flatfile_write_varint_bytes(uint64_t value, uint8_t *dst);
static int cps_flatfile_build_cas_chunk(cps_slice chunk_key,
                                        uint8_t payload_kind,
                                        uint64_t payload_fp,
                                        const cps_flatfile_payload_ref_info *ref_info,
                                        cps_buf *payload,
                                        cps_buf *out);
static int cps_flatfile_build_cas_record(cps_flatfile_state *state, cps_slice key, cps_buf *out);
static int cps_flatfile_lookup_head_record(cps_flatfile_state *state, cps_slice key, cps_buf *out);
static char *cps_flatfile_join2(const char *base, const char *leaf);
static int cps_flatfile_stat_path(const char *path, struct stat *st);
static int cps_flatfile_mkdir_p(const char *path, mode_t mode);
static void cps_flatfile_emit_cei(const cps_flatfile_state *state,
                                  const cepDT *severity,
                                  const char *topic,
                                  const char *detail);
static void cps_flatfile_meta_init(cps_flatfile_state *state);
static uint32_t cps_flatfile_meta_crc(const cps_flatfile_meta *meta);
static int cps_flatfile_meta_store(cps_flatfile_state *state);
static int cps_flatfile_meta_load(cps_flatfile_state *state);
static int cps_flatfile_meta_commit(cps_flatfile_state *state,
                                    const cps_flatfile_txn_state *txn,
                                    uint64_t dat_ofs,
                                    uint64_t dat_len,
                                    uint64_t idx_ofs,
                                    uint64_t idx_len,
                                    const uint8_t merkle[32]);
static int cps_flatfile_cas_manifest_load(cps_flatfile_state *state);
static int cps_flatfile_cas_manifest_store(cps_flatfile_state *state);
static cps_flatfile_cas_manifest_entry *cps_flatfile_cas_manifest_find(cps_flatfile_state *state,
                                                                       const uint8_t hash[CEP_FLAT_HASH_SIZE]);
static int cps_flatfile_cas_manifest_record(cps_flatfile_state *state,
                                            const cps_flatfile_payload_ref_info *ref,
                                            size_t payload_len);
static bool cps_flatfile_cas_hash_to_hex(const uint8_t hash[CEP_FLAT_HASH_SIZE], char hex[65]);
static int cps_flatfile_build_cas_cache_path(const cps_flatfile_state *state,
                                             const uint8_t hash[CEP_FLAT_HASH_SIZE],
                                             char *buffer,
                                             size_t buflen,
                                             bool ensure_parent);
static int cps_flatfile_store_cas_blob(cps_flatfile_state *state,
                                       const cps_flatfile_payload_ref_info *ref,
                                       const uint8_t *payload,
                                       size_t len);
static int cps_flatfile_load_cas_blob_from_cache(cps_flatfile_state *state,
                                                 const cps_flatfile_payload_ref_info *ref,
                                                 cps_buf *out);
static int cps_flatfile_fetch_cas_blob_runtime(const cps_flatfile_payload_ref_info *ref, cps_buf *out);
static int cps_flatfile_fetch_cas_blob_bytes(cps_flatfile_state *state,
                                             const cps_flatfile_payload_ref_info *ref,
                                             cps_buf *out);
static int cps_flatfile_normalize_cas_payload(const cps_flatfile_payload_ref_info *ref, cps_buf *payload);
static bool cps_flatfile_u64_to_size(uint64_t value, size_t *out);
static uint64_t cps_flatfile_monotonic_ns(void);

static cps_flatfile_state *cps_flatfile_state_from(cps_engine *engine) {
  return engine ? (cps_flatfile_state *)engine->state : NULL;
}

static cps_flatfile_txn_state *cps_flatfile_txn_from(cps_txn *txn) {
  return txn ? (cps_flatfile_txn_state *)txn->state : NULL;
}

static char *cps_strdup_or_default(const char *text, const char *fallback) {
  const char *source = text ? text : fallback;
  if (!source) {
    return NULL;
  }
  size_t len = strlen(source) + 1;
  char *copy = (char *)malloc(len);
  if (!copy) {
    return NULL;
  }
  memcpy(copy, source, len);
  return copy;
}

static void cps_flatfile_state_destroy(cps_flatfile_state *state) {
  if (!state) {
    return;
  }
  if (state->cas_manifest_dirty) {
    (void)cps_flatfile_cas_manifest_store(state);
  }
  free(state->root_dir);
  free(state->branch_name);
  free(state->branch_dir);
  free(state->tmp_dir);
  free(state->idx_path);
  free(state->dat_path);
  free(state->meta_path);
  free(state->meta_tmp_path);
  free(state->ckp_path);
  free(state->dir_path);
  free(state->cas_dir);
  free(state->cas_manifest_path);
  if (state->cas_entries) {
    free(state->cas_entries);
  }
  free(state);
}

static bool cps_flatfile_u64_to_size(uint64_t value, size_t *out) {
  if (!out) {
    return false;
  }
  if (value > SIZE_MAX) {
    return false;
  }
  *out = (size_t)value;
  return true;
}

static uint64_t cps_flatfile_monotonic_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0u;
  }
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static bool cps_flatfile_cas_hash_to_hex(const uint8_t hash[CEP_FLAT_HASH_SIZE], char hex[65]) {
  static const char digits[] = "0123456789abcdef";
  if (!hash || !hex) {
    return false;
  }
  for (size_t i = 0; i < CEP_FLAT_HASH_SIZE; ++i) {
    hex[i * 2u] = digits[(hash[i] >> 4u) & 0x0Fu];
    hex[i * 2u + 1u] = digits[hash[i] & 0x0Fu];
  }
  hex[64] = '\0';
  return true;
}

static int cps_flatfile_build_cas_cache_path(const cps_flatfile_state *state,
                                             const uint8_t hash[CEP_FLAT_HASH_SIZE],
                                             char *buffer,
                                             size_t buflen,
                                             bool ensure_parent) {
  if (!state || !state->cas_dir || !hash || !buffer) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  char hex[65];
  if (!cps_flatfile_cas_hash_to_hex(hash, hex)) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  char subdir_path[PATH_MAX];
  int dir_need = snprintf(subdir_path, sizeof subdir_path, "%s/%c%c", state->cas_dir, hex[0], hex[1]);
  if (dir_need < 0 || (size_t)dir_need >= sizeof subdir_path) {
    return CPS_ERR_IO;
  }
  if (ensure_parent) {
    if (cps_flatfile_mkdir_p(subdir_path, 0755) != 0 && errno != EEXIST) {
      return CPS_ERR_IO;
    }
  }
  int need = snprintf(buffer, buflen, "%s/%s.blob", subdir_path, hex);
  if (need < 0 || (size_t)need >= buflen) {
    return CPS_ERR_IO;
  }
  return CPS_OK;
}

static cps_flatfile_cas_manifest_entry *cps_flatfile_cas_manifest_find(cps_flatfile_state *state,
                                                                       const uint8_t hash[CEP_FLAT_HASH_SIZE]) {
  if (!state || !hash || !state->cas_entries) {
    return NULL;
  }
  for (size_t i = 0; i < state->cas_entry_count; ++i) {
    if (memcmp(state->cas_entries[i].hash, hash, CEP_FLAT_HASH_SIZE) == 0) {
      return &state->cas_entries[i];
    }
  }
  return NULL;
}

static int cps_flatfile_cas_manifest_store(cps_flatfile_state *state) {
  if (!state || !state->cas_manifest_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int fd = open(state->cas_manifest_path, CPS_OPEN_FLAGS(O_CREAT | O_TRUNC | O_WRONLY), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_cas_manifest_header_disk header = {
    .magic = CPS_FLATFILE_CAS_MANIFEST_MAGIC,
    .version = CPS_FLATFILE_CAS_MANIFEST_VERSION,
    .reserved = 0u,
    .entry_count = state->cas_entry_count,
  };

  int rc = cps_flatfile_write_all(fd, (const uint8_t *)&header, sizeof header);
  if (rc == CPS_OK) {
    for (size_t i = 0; i < state->cas_entry_count && rc == CPS_OK; ++i) {
      cps_flatfile_cas_manifest_entry_disk disk = {
        .payload_size = state->cas_entries[i].payload_size,
        .codec = state->cas_entries[i].codec,
        .aead_mode = state->cas_entries[i].aead_mode,
        .reserved = {0},
      };
      memcpy(disk.hash, state->cas_entries[i].hash, CEP_FLAT_HASH_SIZE);
      rc = cps_flatfile_write_all(fd, (const uint8_t *)&disk, sizeof disk);
    }
  }

  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  if (rc != CPS_OK) {
    return rc;
  }
  state->cas_manifest_dirty = false;
  return CPS_OK;
}

static int cps_flatfile_cas_manifest_load(cps_flatfile_state *state) {
  if (!state || !state->cas_manifest_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int fd = open(state->cas_manifest_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (fd < 0) {
    if (errno == ENOENT) {
      return CPS_OK;
    }
    return CPS_ERR_IO;
  }

  cps_flatfile_cas_manifest_header_disk header;
  int rc = cps_flatfile_read_exact_fd(fd, 0u, &header, sizeof header);
  if (rc != CPS_OK) {
    close(fd);
    return rc;
  }
  if (header.magic != CPS_FLATFILE_CAS_MANIFEST_MAGIC ||
      header.version != CPS_FLATFILE_CAS_MANIFEST_VERSION) {
    close(fd);
    return CPS_ERR_VERIFY;
  }

  if (header.entry_count > 0u) {
    cps_flatfile_cas_manifest_entry *entries =
      (cps_flatfile_cas_manifest_entry *)calloc((size_t)header.entry_count, sizeof *entries);
    if (!entries) {
      close(fd);
      return CPS_ERR_NOMEM;
    }
    off_t offset = (off_t)sizeof header;
    for (uint64_t i = 0u; i < header.entry_count; ++i) {
      cps_flatfile_cas_manifest_entry_disk disk = {0};
      rc = cps_flatfile_read_exact_fd(fd, offset, &disk, sizeof disk);
      if (rc != CPS_OK) {
        free(entries);
        close(fd);
        return rc;
      }
      offset += (off_t)sizeof disk;
      memcpy(entries[i].hash, disk.hash, CEP_FLAT_HASH_SIZE);
      entries[i].payload_size = disk.payload_size;
      entries[i].codec = disk.codec;
      entries[i].aead_mode = disk.aead_mode;
    }
    free(state->cas_entries);
    state->cas_entries = entries;
    state->cas_entry_count = (size_t)header.entry_count;
    state->cas_entry_cap = (size_t)header.entry_count;
  }
  close(fd);
  state->cas_manifest_dirty = false;
  return CPS_OK;
}

static int cps_flatfile_cas_manifest_record(cps_flatfile_state *state,
                                            const cps_flatfile_payload_ref_info *ref,
                                            size_t payload_len) {
  if (!state || !ref || !ref->hash_len || ref->hash_len != CEP_FLAT_HASH_SIZE) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cps_flatfile_cas_manifest_entry *entry = cps_flatfile_cas_manifest_find(state, ref->hash_bytes);
  if (!entry) {
    if (state->cas_entry_count == state->cas_entry_cap) {
      size_t new_cap = state->cas_entry_cap ? (state->cas_entry_cap * 2u) : 8u;
      cps_flatfile_cas_manifest_entry *grown =
        (cps_flatfile_cas_manifest_entry *)realloc(state->cas_entries, new_cap * sizeof *grown);
      if (!grown) {
        return CPS_ERR_NOMEM;
      }
      state->cas_entries = grown;
      state->cas_entry_cap = new_cap;
    }
    entry = &state->cas_entries[state->cas_entry_count++];
    memset(entry, 0, sizeof *entry);
    memcpy(entry->hash, ref->hash_bytes, CEP_FLAT_HASH_SIZE);
  }
  entry->payload_size = ref->payload_size ? ref->payload_size : (uint64_t)payload_len;
  entry->codec = ref->codec;
  entry->aead_mode = ref->aead_mode;
  state->cas_manifest_dirty = true;
  return cps_flatfile_cas_manifest_store(state);
}

static int cps_flatfile_store_cas_blob(cps_flatfile_state *state,
                                       const cps_flatfile_payload_ref_info *ref,
                                       const uint8_t *payload,
                                       size_t len) {
  if (!state || !ref || !payload || len == 0u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  char path[PATH_MAX];
  int rc = cps_flatfile_build_cas_cache_path(state, ref->hash_bytes, path, sizeof path, true);
  if (rc != CPS_OK) {
    return rc;
  }
  int fd = open(path, CPS_OPEN_FLAGS(O_CREAT | O_TRUNC | O_WRONLY), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  rc = cps_flatfile_write_all(fd, payload, len);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  if (rc != CPS_OK) {
    return rc;
  }
  return cps_flatfile_cas_manifest_record(state, ref, len);
}

static int cps_flatfile_load_cas_blob_from_cache(cps_flatfile_state *state,
                                                 const cps_flatfile_payload_ref_info *ref,
                                                 cps_buf *out) {
  if (!state || !ref || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  char path[PATH_MAX];
  int rc = cps_flatfile_build_cas_cache_path(state, ref->hash_bytes, path, sizeof path, false);
  if (rc != CPS_OK) {
    return rc;
  }
  int fd = open(path, CPS_OPEN_FLAGS(O_RDONLY));
  if (fd < 0) {
    return (errno == ENOENT) ? CPS_ERR_NOT_FOUND : CPS_ERR_IO;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size <= 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return CPS_ERR_IO;
  }
  size_t file_size = (size_t)st.st_size;
  uint8_t *buffer = (uint8_t *)malloc(file_size);
  if (!buffer) {
    close(fd);
    return CPS_ERR_NOMEM;
  }
  size_t total = 0u;
  while (total < file_size) {
    ssize_t rd = read(fd, buffer + total, file_size - total);
    if (rd < 0) {
      if (errno == EINTR) {
        continue;
      }
      free(buffer);
      int saved_errno = errno;
      close(fd);
      errno = saved_errno;
      return CPS_ERR_IO;
    }
    if (rd == 0) {
      break;
    }
    total += (size_t)rd;
  }
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  if (total != file_size) {
    free(buffer);
    return CPS_ERR_IO;
  }
  free(out->data);
  out->data = buffer;
  out->len = file_size;
  out->cap = file_size;
  return CPS_OK;
}

static int cps_flatfile_fetch_cas_blob_runtime(const cps_flatfile_payload_ref_info *ref, cps_buf *out) {
  if (!ref || !out || !ref->hash_bytes || ref->hash_len == 0u) {
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

  uint8_t hash_buf[CEP_FLAT_HASH_SIZE];
  for (cepCell *bucket = cep_cell_first_all(resolved_root);
       bucket;
       bucket = cep_cell_next_all(resolved_root, bucket)) {
    cepCell *resolved_bucket = cep_cell_resolve(bucket);
    if (!resolved_bucket || !cep_cell_require_dictionary_store(&resolved_bucket)) {
      continue;
    }
    for (cepCell *item = cep_cell_first_all(resolved_bucket);
         item;
         item = cep_cell_next_all(resolved_bucket, item)) {
      cepCell *entry = cep_cell_resolve(item);
      if (!entry || !cep_cell_has_data(entry) || !entry->data) {
        continue;
      }
      const cepData *data = entry->data;
      if (data->size == 0u) {
        continue;
      }
      const void *payload = cep_data_payload(data);
      if (!payload) {
        continue;
      }
      if (ref->payload_size && data->size != ref->payload_size) {
        continue;
      }
      if (!cps_flatfile_hash_bytes(payload, data->size, hash_buf)) {
        continue;
      }
      if (ref->hash_len == CEP_FLAT_HASH_SIZE &&
          memcmp(hash_buf, ref->hash_bytes, CEP_FLAT_HASH_SIZE) == 0) {
        if (!cps_flatfile_buf_reserve(out, data->size)) {
          return CPS_ERR_NOMEM;
        }
        memcpy(out->data, payload, data->size);
        out->len = data->size;
        return CPS_OK;
      }
    }
  }
  return CPS_ERR_NOT_FOUND;
}

static int cps_flatfile_fetch_cas_blob_bytes(cps_flatfile_state *state,
                                             const cps_flatfile_payload_ref_info *ref,
                                             cps_buf *out) {
  if (!state || !ref || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  uint64_t start_ns = cps_flatfile_monotonic_ns();
  int rc = cps_flatfile_load_cas_blob_from_cache(state, ref, out);
  if (rc == CPS_OK) {
    state->stat_cas_hits += 1u;
  } else if (rc == CPS_ERR_NOT_FOUND) {
    rc = cps_flatfile_fetch_cas_blob_runtime(ref, out);
    if (rc == CPS_OK) {
      (void)cps_flatfile_store_cas_blob(state, ref, out->data, out->len);
    } else {
      cps_flatfile_emit_cei(state,
                            dt_cps_sev_warn(),
                            k_cps_topic_recover,
                            "cas blob not found in cache or runtime");
    }
    state->stat_cas_misses += 1u;
  }
  uint64_t end_ns = cps_flatfile_monotonic_ns();
  if (end_ns >= start_ns) {
    state->stat_cas_lookup_ns += (end_ns - start_ns);
  }
  (void)cps_flatfile_publish_metrics(state);
  return rc;
}

static int cps_flatfile_normalize_cas_payload(const cps_flatfile_payload_ref_info *ref, cps_buf *payload) {
  if (!ref || !payload || !payload->data) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (ref->codec == CEP_FLAT_COMPRESSION_NONE) {
    return CPS_OK;
  }
  if (ref->codec == CEP_FLAT_COMPRESSION_DEFLATE) {
    if (ref->payload_size == 0u) {
      return CPS_ERR_VERIFY;
    }
    size_t expected = 0u;
    if (!cps_flatfile_u64_to_size(ref->payload_size, &expected)) {
      return CPS_ERR_VERIFY;
    }
    uint8_t *decoded = (uint8_t *)malloc(expected);
    if (!decoded) {
      return CPS_ERR_NOMEM;
    }
    uLongf dest_len = (uLongf)expected;
    int zrc = uncompress(decoded, &dest_len, payload->data, (uLong)payload->len);
    if (zrc != Z_OK || dest_len != expected) {
      free(decoded);
      return CPS_ERR_VERIFY;
    }
    free(payload->data);
    payload->data = decoded;
    payload->len = expected;
    payload->cap = expected;
    return CPS_OK;
  }
  return CPS_ERR_NOT_IMPLEMENTED;
}
static void cps_flatfile_close(cps_engine *engine) {
  if (!engine) {
    return;
  }
  cps_flatfile_state_destroy(cps_flatfile_state_from(engine));
  free(engine);
}

/* begin_beat() allocates a transaction shell for beat staging, preparing the
 * append-only part files that will accumulate structural and payload records
 * before the commit path promotes them into the branch files. */
static int cps_flatfile_begin_beat(cps_engine *engine, uint64_t beat_no, cps_txn **out) {
  if (!engine || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  cps_flatfile_state *state = cps_flatfile_state_from(engine);
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  cps_txn *handle = (cps_txn *)calloc(1, sizeof(*handle));
  cps_flatfile_txn_state *txn = (cps_flatfile_txn_state *)calloc(1, sizeof(*txn));
  if (!handle || !txn) {
    free(handle);
    free(txn);
    return CPS_ERR_NOMEM;
  }

  txn->owner = state;
  txn->beat = beat_no;
  txn->frame_id = state->next_frame_id;
  txn->dat_fd = -1;
  txn->idx_fd = -1;
  txn->toc_entries = NULL;
  txn->toc_len = 0u;
  txn->toc_cap = 0u;
  handle->state = txn;

  int status = cps_flatfile_prepare_txn_files(txn);
  if (status != CPS_OK) {
    cps_flatfile_txn_cleanup(txn);
    free(handle);
    return status;
  }

  blake3_hasher_init(&txn->merkle);
  txn->merkle_ready = true;
  txn->crc32 = 0u;
  txn->crc_ready = true;

  state->next_frame_id += 1u;
  *out = handle;
  return CPS_OK;
}

/* put_record() currently writes a simple length-prefixed envelope to the
 * per-beat part files so future history work can re-scan the staged bytes. */
static int cps_flatfile_put_record(cps_txn *txn_handle, cps_slice key, cps_slice value, uint32_t rtype) {
  cps_flatfile_txn_state *txn = cps_flatfile_txn_from(txn_handle);
  if (!txn) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  if (key.len > UINT32_MAX || value.len > UINT32_MAX) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  bool is_payload = (rtype == CPS_RECORD_TYPE_PAYLOAD);
  int fd = is_payload ? txn->dat_fd : txn->idx_fd;
  if (fd < 0) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  uint64_t key_hash = cps_flatfile_key_hash(key.data, key.len);

  size_t extra_header_bytes = cps_flatfile_record_header_span(rtype) - sizeof(cps_flatfile_record_header);
  cps_flatfile_chunk_info chunk_info = {0};
  cps_flatfile_payload_header payload_meta = {0};
  cps_flatfile_record_header header = {
    .rtype = rtype,
    .key_len = (uint32_t)key.len,
    .val_len = (uint32_t)value.len,
    .flags = 0u,
  };

  if (is_payload) {
    int chunk_rc = cps_flatfile_extract_chunk_info(key, value, &chunk_info);
    if (chunk_rc != CPS_OK) {
      return chunk_rc;
    }
    if (chunk_info.chunk_size > UINT32_MAX || chunk_info.ordinal > UINT32_MAX) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
    header.flags = (uint32_t)chunk_info.payload_kind |
                   ((uint32_t)chunk_info.aead_mode << CPS_FLATFILE_PAYLOAD_FLAG_AEAD_SHIFT);
    payload_meta.key_hash = key_hash;
    payload_meta.chunk_offset = chunk_info.chunk_offset;
    payload_meta.chunk_total = chunk_info.total_size;
    payload_meta.chunk_ordinal = (uint32_t)chunk_info.ordinal;
    payload_meta.chunk_size = (uint32_t)chunk_info.chunk_size;
    payload_meta.chunk_crc32 = cep_crc32c(chunk_info.chunk_bytes, chunk_info.chunk_bytes_len, 0u);
    payload_meta.reserved = 0u;
  }

  int rc = cps_flatfile_write_all(fd, (const uint8_t *)&header, sizeof header);
  if (rc != CPS_OK) {
    return rc;
  }
  if (txn->merkle_ready) {
    blake3_hasher_update(&txn->merkle, (const uint8_t *)&header, sizeof header);
  }
  if (txn->crc_ready) {
    txn->crc32 = cep_crc32c(&header, sizeof header, txn->crc32);
  }

  if (is_payload) {
    rc = cps_flatfile_write_all(fd, (const uint8_t *)&payload_meta, sizeof payload_meta);
    if (rc != CPS_OK) {
      return rc;
    }
    if (txn->merkle_ready) {
      blake3_hasher_update(&txn->merkle, (const uint8_t *)&payload_meta, sizeof payload_meta);
    }
    if (txn->crc_ready) {
      txn->crc32 = cep_crc32c(&payload_meta, sizeof payload_meta, txn->crc32);
    }
  }

  if (key.len > 0u) {
    rc = cps_flatfile_write_all(fd, key.data, key.len);
    if (rc != CPS_OK) {
      return rc;
    }
    if (txn->merkle_ready) {
      blake3_hasher_update(&txn->merkle, key.data, key.len);
    }
    if (txn->crc_ready) {
      txn->crc32 = cep_crc32c(key.data, key.len, txn->crc32);
    }
  }

  if (value.len > 0u) {
    rc = cps_flatfile_write_all(fd, value.data, value.len);
    if (rc != CPS_OK) {
      return rc;
    }
    if (txn->merkle_ready) {
      blake3_hasher_update(&txn->merkle, value.data, value.len);
    }
    if (txn->crc_ready) {
      txn->crc32 = cep_crc32c(value.data, value.len, txn->crc32);
    }
  }

  uint64_t key_ofs = is_payload ? txn->dat_bytes : txn->idx_bytes;
  size_t record_bytes = sizeof header + extra_header_bytes + key.len + value.len;
  if (is_payload) {
    txn->dat_bytes += record_bytes;
  } else {
    txn->idx_bytes += record_bytes;
  }

  uint64_t val_ofs = key_ofs + sizeof header + extra_header_bytes + key.len;
  int push_rc = cps_flatfile_toc_push(txn, rtype, key_hash, key_ofs, (uint32_t)key.len, val_ofs, (uint32_t)value.len);
  if (push_rc != CPS_OK) {
    return push_rc;
  }
  if (rtype == CPS_RECORD_TYPE_CELL_DESC) {
    cps_flatfile_payload_ref_info ref_info = {0};
    uint8_t parsed_payload_kind = 0u;
    uint64_t parsed_payload_fp = 0u;
    if (cps_flatfile_parse_cell_desc_payload_ref(value,
                                                 &parsed_payload_kind,
                                                 &parsed_payload_fp,
                                                 &ref_info) &&
        ref_info.kind != CEP_FLAT_PAYLOAD_REF_INLINE) {
      cps_flatfile_toc_entry *entry = &txn->toc_entries[txn->toc_len - 1u];
      entry->flags |= CPS_FLATFILE_TOC_FLAG_CAS_REF;
    }
  }
  return CPS_OK;
}

/* commit_beat() flushes the staged part files and appends them to the branch
 * files in the documented order (dat → idx → meta). */
static int cps_flatfile_commit_beat(cps_txn *txn_handle, cps_frame_meta *out_meta) {
  cps_flatfile_txn_state *txn = cps_flatfile_txn_from(txn_handle);
  if (!txn) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cps_flatfile_state *state = txn->owner;

  uint8_t merkle[32] = {0};
  if (txn->merkle_ready) {
    blake3_hasher_finalize(&txn->merkle, merkle, sizeof merkle);
    txn->merkle_ready = false;
  }

  int rc = CPS_OK;
  const char *error_topic = NULL;
  const char *error_detail = NULL;
  const cepDT *error_severity = dt_cps_sev_crit();
  if (txn->dat_fd >= 0) {
    if (fsync(txn->dat_fd) != 0) {
      rc = CPS_ERR_IO;
      error_topic = k_cps_topic_frame_io;
      error_detail = "fsync branch.dat failed";
    }
    close(txn->dat_fd);
    txn->dat_fd = -1;
  }
  if (rc == CPS_OK && txn->idx_fd >= 0) {
    if (fsync(txn->idx_fd) != 0) {
      rc = CPS_ERR_IO;
      error_topic = k_cps_topic_frame_io;
      error_detail = "fsync branch.idx failed";
    }
    close(txn->idx_fd);
    txn->idx_fd = -1;
  }

  uint64_t dat_ofs = 0u, dat_len = 0u;
  uint64_t idx_ofs = 0u, idx_len = 0u;
  if (rc == CPS_OK) {
    rc = cps_flatfile_append_file(txn->owner->dat_path, txn->dat_tmp_path, &dat_ofs, &dat_len);
    if (rc != CPS_OK) {
      error_topic = k_cps_topic_frame_io;
      error_detail = "append branch.dat failed";
    }
  }
  if (rc == CPS_OK) {
    rc = cps_flatfile_append_file(txn->owner->idx_path, txn->idx_tmp_path, &idx_ofs, &idx_len);
    if (rc != CPS_OK && !error_topic) {
      error_topic = k_cps_topic_frame_io;
      error_detail = "append branch.idx failed";
    }
  }
  if (rc == CPS_OK) {
    uint64_t extra_idx = 0u;
    rc = cps_flatfile_write_mini_toc_and_trailer(txn, merkle, dat_ofs, idx_ofs, &extra_idx);
    idx_len += extra_idx;
    if (rc != CPS_OK && !error_topic) {
      error_topic = k_cps_topic_frame_io;
      error_detail = "write mini-TOC/trailer failed";
    }
    if (rc == CPS_OK) {
      struct stat st = {0};
      if (cps_flatfile_stat_path(txn->owner->idx_path, &st) != 0 || (uint64_t)st.st_size < idx_ofs) {
        rc = CPS_ERR_IO;
        error_topic = k_cps_topic_frame_io;
        error_detail = "stat branch.idx failed after trailer";
      } else {
        idx_len = (uint64_t)st.st_size - idx_ofs;
      }
    }
  }
  if (rc == CPS_OK) {
    rc = cps_flatfile_meta_commit(txn->owner, txn, dat_ofs, dat_len, idx_ofs, idx_len, merkle);
    if (rc != CPS_OK && !error_topic) {
      error_topic = k_cps_topic_frame_io;
      error_detail = "branch.meta update failed";
    }
  }
  if (rc == CPS_OK) {
    rc = cps_flatfile_frame_dir_append(txn->owner,
                                       txn->beat,
                                       txn->frame_id,
                                       idx_ofs,
                                       idx_len,
                                       dat_ofs,
                                       dat_len);
    if (rc != CPS_OK && !error_topic) {
      error_topic = k_cps_topic_frame_io;
      error_detail = "frame directory update failed";
      error_severity = dt_cps_sev_warn();
    }
  }
  if (rc == CPS_OK && txn->owner->checkpoint_interval > 0 &&
      (txn->frame_id % txn->owner->checkpoint_interval) == 0) {
    rc = cps_flatfile_write_checkpoint_snapshot(txn->owner, txn->beat, txn->frame_id,
                                               dat_ofs, idx_ofs,
                                               txn->toc_entries, txn->toc_len);
    if (rc != CPS_OK) {
      error_topic = k_cps_topic_checkpoint;
      error_detail = "auto-checkpoint failed";
      error_severity = dt_cps_sev_warn();
    } else {
      int meta_rc = cps_flatfile_checkpoint_finalize(state, txn->beat);
      if (meta_rc != CPS_OK) {
        rc = meta_rc;
        error_topic = k_cps_topic_checkpoint;
        error_detail = "checkpoint metadata update failed";
        error_severity = dt_cps_sev_warn();
      }
    }
  }

  if (out_meta) {
    memset(out_meta, 0, sizeof(*out_meta));
    out_meta->beat = txn->beat;
    out_meta->frame_id = txn->frame_id;
    memcpy(out_meta->merkle, merkle, sizeof merkle);
  }

  if (rc == CPS_OK && state) {
    state->stat_frames += 1u;
    state->stat_beats += 1u;
    state->stat_bytes_dat += dat_len;
    state->stat_bytes_idx += idx_len;
    (void)cps_flatfile_publish_metrics(state);
  }

  cps_flatfile_txn_cleanup(txn);
  free(txn_handle);
  if (rc != CPS_OK && error_topic) {
    cps_flatfile_emit_cei(state, error_severity, error_topic, error_detail);
  }
  return rc;
}

/* abort_beat() removes the staged part files so a failed ingestion leaves
 * no observable tail for recovery to inspect. */
static void cps_flatfile_abort_beat(cps_txn *txn_handle) {
  cps_flatfile_txn_state *txn = cps_flatfile_txn_from(txn_handle);
  if (!txn) {
    return;
  }
  cps_flatfile_txn_cleanup(txn);
  free(txn_handle);
}

/* get_record() performs a simple scan over the branch files written so far and
 * returns the newest matching record payload. This is a placeholder until the
 * mini-TOC and checkpoint indexes land. */
static int cps_flatfile_get_record(cps_engine *engine, cps_slice key, cps_buf *out) {
  if (!engine || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  cps_flatfile_state *state = cps_flatfile_state_from(engine);
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  int rc = cps_flatfile_lookup_head_record(state, key, out);
  if (rc == CPS_ERR_NOT_FOUND) {
    rc = cps_flatfile_lookup_checkpoint_record(state, key, out);
  }

  if (rc == CPS_ERR_NOT_FOUND) {
    cps_flatfile_frame_dir_snapshot snapshot = {0};
    int snap_rc = cps_flatfile_frame_dir_snapshot_load(state, &snapshot);
    if (snap_rc == CPS_OK && snapshot.count > 0u) {
      int idx_fd = open(state->idx_path, CPS_OPEN_FLAGS(O_RDONLY));
      int dat_fd = open(state->dat_path, CPS_OPEN_FLAGS(O_RDONLY));
      if (idx_fd < 0 || dat_fd < 0) {
        if (idx_fd >= 0) close(idx_fd);
        if (dat_fd >= 0) close(dat_fd);
        rc = CPS_ERR_IO;
      } else {
        for (size_t i = snapshot.count; i > 0u; --i) {
          cps_flatfile_frame_dir_entry_disk *entry = &snapshot.entries[i - 1u];
          if (entry->idx_len == 0u) {
            continue;
          }
          if (entry->idx_ofs == state->meta.head_idx_ofs &&
              entry->idx_len == state->meta.head_idx_len &&
              entry->frame_id == state->meta.head_frame_id) {
            continue; /* Already scanned head frame. */
          }
          rc = cps_flatfile_lookup_frame_record_fd(idx_fd,
                                                   dat_fd,
                                                   entry->idx_ofs,
                                                   entry->idx_len,
                                                   key,
                                                   out);
          if (rc == CPS_OK || rc != CPS_ERR_NOT_FOUND) {
            break;
          }
        }
        close(dat_fd);
        close(idx_fd);
      }
    } else if (snap_rc != CPS_OK) {
      rc = snap_rc;
    }
    cps_flatfile_frame_dir_snapshot_destroy(&snapshot);
  }
  if (rc == CPS_ERR_NOT_FOUND) {
    rc = cps_flatfile_try_cas_read(engine, key, out);
  }
  return rc;
}

static int cps_flatfile_scan_prefix(cps_engine *engine, cps_slice prefix, cps_scan_cb cb, void *user) {
  if (!engine || !cb) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cps_flatfile_state *state = cps_flatfile_state_from(engine);
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  int idx_fd = open(state->idx_path, CPS_OPEN_FLAGS(O_RDONLY));
  int dat_fd = open(state->dat_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (idx_fd < 0 || dat_fd < 0) {
    if (idx_fd >= 0) close(idx_fd);
    if (dat_fd >= 0) close(dat_fd);
    return CPS_ERR_IO;
  }

  cps_flatfile_scanned_key *visited = NULL;
  size_t visited_len = 0u;
  size_t visited_cap = 0u;
  int rc = CPS_ERR_NOT_FOUND;

  /* Scan head mini-TOC entries first (latest beat). */
  cps_flatfile_toc_entry_disk *head_entries = NULL;
  cps_flatfile_toc_header_disk toc_header = {0};
  do {
    if (state->meta.head_idx_len == 0u) {
      break;
    }
    const uint64_t frame_ofs = state->meta.head_idx_ofs;
    const uint64_t frame_len = state->meta.head_idx_len;
    if (frame_len < sizeof(cps_flatfile_trailer_disk)) {
      rc = CPS_ERR_VERIFY;
      break;
    }
    const uint64_t trailer_ofs = frame_ofs + frame_len - sizeof(cps_flatfile_trailer_disk);
    cps_flatfile_trailer_disk trailer;
    if (cps_flatfile_read_exact_fd(idx_fd, trailer_ofs, &trailer, sizeof trailer) != CPS_OK ||
        trailer.magic != CPS_FLATFILE_TRAIL_MAGIC) {
      rc = CPS_ERR_VERIFY;
      break;
    }
    const size_t toc_bytes = sizeof(cps_flatfile_toc_header_disk) + (size_t)trailer.toc_count * sizeof(cps_flatfile_toc_entry_disk);
    if (frame_len < toc_bytes + sizeof(cps_flatfile_trailer_disk)) {
      rc = CPS_ERR_VERIFY;
      break;
    }
    const uint64_t toc_ofs = trailer_ofs - toc_bytes;
    if (cps_flatfile_read_exact_fd(idx_fd, toc_ofs, &toc_header, sizeof toc_header) != CPS_OK ||
        toc_header.magic != CPS_FLATFILE_TOC_MAGIC) {
      rc = CPS_ERR_VERIFY;
      break;
    }
    if (toc_header.entry_count == 0u) {
      break;
    }
    size_t entries_size = (size_t)toc_header.entry_count * sizeof(cps_flatfile_toc_entry_disk);
    head_entries = (cps_flatfile_toc_entry_disk *)malloc(entries_size);
    if (!head_entries) {
      rc = CPS_ERR_NOMEM;
      break;
    }
    if (cps_flatfile_read_exact_fd(idx_fd, toc_ofs + sizeof toc_header, head_entries, entries_size) != CPS_OK) {
      free(head_entries);
      head_entries = NULL;
      rc = CPS_ERR_IO;
      break;
    }
    int head_rc = cps_flatfile_scan_entries_with_prefix(state,
                                                        idx_fd,
                                                        dat_fd,
                                                        head_entries,
                                                        toc_header.entry_count,
                                                        prefix,
                                                        cb,
                                                        user,
                                                        &visited,
                                                        &visited_len,
                                                        &visited_cap);
    if (head_rc == CPS_OK) {
      rc = CPS_OK;
    } else if (head_rc != CPS_ERR_NOT_FOUND) {
      rc = head_rc;
      break;
    }
  } while (0);
  free(head_entries);

  if (rc == CPS_OK || rc == CPS_ERR_NOT_FOUND) {
    cps_flatfile_checkpoint_scan_ctx ctx = {
      .state = state,
      .idx_fd = idx_fd,
      .dat_fd = dat_fd,
      .prefix = prefix,
      .cb = cb,
      .user = user,
      .visited = &visited,
      .visited_len = &visited_len,
      .visited_cap = &visited_cap,
      .rc = rc,
    };

    int iter_rc = cps_flatfile_iterate_checkpoints(state, cps_flatfile_checkpoint_scan_cb, &ctx);
    if (ctx.rc == CPS_OK) {
      rc = CPS_OK;
    } else if (iter_rc != CPS_OK && iter_rc != CPS_ERR_NOT_FOUND) {
      rc = iter_rc;
    } else if (ctx.rc != CPS_ERR_NOT_FOUND && rc != CPS_OK) {
      rc = ctx.rc;
    }
  }

  if (rc == CPS_OK || rc == CPS_ERR_NOT_FOUND) {
    cps_flatfile_frame_dir_snapshot snapshot = {0};
    int snap_rc = cps_flatfile_frame_dir_snapshot_load(state, &snapshot);
    if (snap_rc == CPS_OK && snapshot.count > 0u) {
      for (size_t i = snapshot.count; i > 0u; --i) {
        cps_flatfile_frame_dir_entry_disk *entry = &snapshot.entries[i - 1u];
        if (entry->idx_len == 0u) {
          continue;
        }
        if (entry->frame_id == state->meta.head_frame_id &&
            entry->idx_ofs == state->meta.head_idx_ofs &&
            entry->idx_len == state->meta.head_idx_len) {
          continue;
        }
        cps_flatfile_toc_entry_disk *frame_entries = NULL;
        uint32_t entry_count = 0u;
        int load_rc = cps_flatfile_load_frame_entries(idx_fd,
                                                      entry->idx_ofs,
                                                      entry->idx_len,
                                                      &frame_entries,
                                                      &entry_count);
        if (load_rc != CPS_OK) {
          rc = load_rc;
          break;
        }
        if (entry_count == 0u || !frame_entries) {
          free(frame_entries);
          continue;
        }
        int frame_rc = cps_flatfile_scan_entries_with_prefix(state,
                                                             idx_fd,
                                                             dat_fd,
                                                             frame_entries,
                                                             entry_count,
                                                             prefix,
                                                             cb,
                                                             user,
                                                             &visited,
                                                             &visited_len,
                                                             &visited_cap);
        free(frame_entries);
        if (frame_rc == CPS_OK) {
          rc = CPS_OK;
        } else if (frame_rc != CPS_ERR_NOT_FOUND) {
          rc = frame_rc;
          break;
        }
      }
    } else if (snap_rc != CPS_OK) {
      rc = snap_rc;
    }
    cps_flatfile_frame_dir_snapshot_destroy(&snapshot);
  }

  cps_flatfile_scan_keys_clear(visited, visited_len);
  free(visited);
  close(dat_fd);
  close(idx_fd);
  return rc;
}

static int cps_flatfile_checkpoint(cps_engine *engine, const cps_ckpt_opts *opts, cps_ckpt_stat *out) {
  (void)opts;
  if (!engine || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cps_flatfile_state *state = cps_flatfile_state_from(engine);
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  memset(out, 0, sizeof(*out));
  if (state->meta.head_idx_len == 0u) {
    return CPS_OK;
  }

  int idx_fd = -1;
  int dat_fd = -1;
  cps_flatfile_toc_entry_disk *disk_entries = NULL;
  cps_flatfile_toc_entry *rel_entries = NULL;
  cps_flatfile_trailer_disk trailer = {0};
  cps_flatfile_toc_header_disk toc_header = {0};
  const char *error_detail = NULL;
  const cepDT *error_severity = dt_cps_sev_crit();
  int rc = CPS_OK;
  bool checkpoint_written = false;
  uint64_t min_interval = (opts && opts->every_beats) ? opts->every_beats : 0u;

  idx_fd = open(state->idx_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (idx_fd < 0) {
    rc = CPS_ERR_IO;
    error_detail = "open branch.idx failed";
    goto done;
  }
  dat_fd = open(state->dat_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (dat_fd < 0) {
    rc = CPS_ERR_IO;
    error_detail = "open branch.dat failed";
    goto done;
  }

  const uint64_t frame_ofs = state->meta.head_idx_ofs;
  const uint64_t frame_len = state->meta.head_idx_len;
  if (frame_len < sizeof(cps_flatfile_trailer_disk)) {
    rc = CPS_ERR_VERIFY;
    error_detail = "invalid frame length";
    goto done;
  }
  const uint64_t trailer_ofs = frame_ofs + frame_len - sizeof(cps_flatfile_trailer_disk);

  rc = cps_flatfile_read_exact_fd(idx_fd, trailer_ofs, &trailer, sizeof trailer);
  if (rc != CPS_OK || trailer.magic != CPS_FLATFILE_TRAIL_MAGIC) {
    rc = CPS_ERR_VERIFY;
    error_detail = "read frame trailer failed";
    goto done;
  }

  if (min_interval > 0u && state->last_checkpoint_beat != 0u) {
    uint64_t next_allowed = state->last_checkpoint_beat + min_interval;
    if (trailer.beat < next_allowed) {
      goto done;
    }
  }

  const size_t toc_bytes = sizeof(cps_flatfile_toc_header_disk) +
                           (size_t)trailer.toc_count * sizeof(cps_flatfile_toc_entry_disk);
  const uint64_t toc_ofs = trailer_ofs - toc_bytes;
  rc = cps_flatfile_read_exact_fd(idx_fd, toc_ofs, &toc_header, sizeof toc_header);
  if (rc != CPS_OK || toc_header.magic != CPS_FLATFILE_TOC_MAGIC) {
    rc = CPS_ERR_VERIFY;
    error_detail = "read mini-TOC header failed";
    goto done;
  }

  if (toc_header.entry_count > 0u) {
    size_t entries_size = (size_t)toc_header.entry_count * sizeof(cps_flatfile_toc_entry_disk);
    disk_entries = (cps_flatfile_toc_entry_disk *)malloc(entries_size);
    rel_entries = (cps_flatfile_toc_entry *)malloc((size_t)toc_header.entry_count * sizeof(*rel_entries));
    if (!disk_entries || !rel_entries) {
      rc = CPS_ERR_NOMEM;
      error_detail = "checkpoint allocation failed";
      goto done;
    }
    rc = cps_flatfile_read_exact_fd(idx_fd, toc_ofs + sizeof toc_header, disk_entries, entries_size);
    if (rc != CPS_OK) {
      error_detail = "read mini-TOC entries failed";
      goto done;
    }
    for (uint32_t i = 0; i < toc_header.entry_count; ++i) {
      const cps_flatfile_toc_entry_disk *disk_entry = &disk_entries[i];
      cps_flatfile_toc_entry *rel = &rel_entries[i];
      bool is_payload = disk_entry->rtype == CPS_RECORD_TYPE_PAYLOAD;
      uint64_t base = is_payload ? state->meta.head_dat_ofs : state->meta.head_idx_ofs;
      rel->rtype = disk_entry->rtype;
      rel->key_hash = disk_entry->key_hash;
      rel->key_ofs = disk_entry->key_ofs - base;
      rel->val_ofs = disk_entry->val_ofs - base;
      rel->key_len = disk_entry->key_len;
      rel->val_len = disk_entry->val_len;
      rel->flags = disk_entry->flags;
    }
  }

  rc = cps_flatfile_write_checkpoint_snapshot(state,
                                              trailer.beat,
                                              trailer.frame_id,
                                              state->meta.head_dat_ofs,
                                              state->meta.head_idx_ofs,
                                              rel_entries,
                                              toc_header.entry_count);
  if (rc != CPS_OK) {
    error_detail = "write checkpoint snapshot failed";
    goto done;
  }
  checkpoint_written = true;

  rc = cps_flatfile_checkpoint_finalize(state, trailer.beat);
  if (rc != CPS_OK) {
    error_detail = "checkpoint metadata update failed";
    error_severity = dt_cps_sev_warn();
    goto done;
  }

  out->written_entries = toc_header.entry_count;
  out->written_bytes = sizeof(cps_flatfile_ckp_header_disk) +
                       (uint64_t)toc_header.entry_count * sizeof(cps_flatfile_toc_entry_disk);

done:
  free(disk_entries);
  free(rel_entries);
  if (idx_fd >= 0) {
    close(idx_fd);
  }
  if (dat_fd >= 0) {
    close(dat_fd);
  }

  if (rc == CPS_OK && checkpoint_written) {
    char note[160];
    snprintf(note, sizeof note, "checkpoint beat=%" PRIu64 " entries=%" PRIu32,
             trailer.beat, toc_header.entry_count);
    cps_flatfile_emit_cei(state, dt_cps_sev_debug(), k_cps_topic_checkpoint, note);
  } else if (error_detail) {
    cps_flatfile_emit_cei(state, error_severity, k_cps_topic_checkpoint, error_detail);
  }
  return rc;
}

static int cps_flatfile_compact(cps_engine *engine, const cps_compact_opts *opts, cps_compact_stat *out) {
  (void)engine;
  (void)opts;
  if (out) {
    memset(out, 0, sizeof(*out));
  }
  return CPS_ERR_NOT_IMPLEMENTED;
}

static int cps_flatfile_stats(cps_engine *engine, cps_stats *out) {
  if (!engine || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cps_flatfile_state *state = cps_flatfile_state_from(engine);
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  out->stat_frames = state->stat_frames;
  out->stat_beats = state->stat_beats;
  out->stat_bytes_idx = state->stat_bytes_idx;
  out->stat_bytes_dat = state->stat_bytes_dat;
  return CPS_OK;
}

static cps_caps_t cps_flatfile_caps(const cps_engine *engine) {
  if (!engine) {
    return 0;
  }
  return engine->caps;
}

static const cps_vtable cps_flatfile_vtable = {
  .open = NULL,
  .close = cps_flatfile_close,
  .begin_beat = cps_flatfile_begin_beat,
  .put_record = cps_flatfile_put_record,
  .commit_beat = cps_flatfile_commit_beat,
  .abort_beat = cps_flatfile_abort_beat,
  .get_record = cps_flatfile_get_record,
  .scan_prefix = cps_flatfile_scan_prefix,
  .checkpoint = cps_flatfile_checkpoint,
  .compact = cps_flatfile_compact,
  .stats = cps_flatfile_stats,
  .caps = cps_flatfile_caps,
};

int cps_flatfile_engine_open(const cps_flatfile_opts *opts, cps_engine **out) {
  const char *default_branch_name = "default";
  if (!opts || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  cps_engine *engine = (cps_engine *)calloc(1, sizeof(*engine));
  if (!engine) {
    return CPS_ERR_NOMEM;
  }

  cps_flatfile_state *state = (cps_flatfile_state *)calloc(1, sizeof(*state));
  if (!state) {
    free(engine);
    return CPS_ERR_NOMEM;
  }

  state->root_dir = cps_strdup_or_default(opts->root_dir, ".");
  state->branch_name = cps_strdup_or_default(opts->branch_name, default_branch_name);
  if (!state->root_dir || !state->branch_name) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return CPS_ERR_NOMEM;
  }

  state->branch_dir = cps_flatfile_join2(state->root_dir, state->branch_name);
  state->tmp_dir = cps_flatfile_join2(state->branch_dir, "tmp");
  state->idx_path = cps_flatfile_join2(state->branch_dir, "branch.idx");
  state->dat_path = cps_flatfile_join2(state->branch_dir, "branch.dat");
  state->meta_path = cps_flatfile_join2(state->branch_dir, "branch.meta");
  state->meta_tmp_path = cps_flatfile_join2(state->branch_dir, "branch.meta.new");
  state->ckp_path = cps_flatfile_join2(state->branch_dir, "branch.ckp");
  state->dir_path = cps_flatfile_join2(state->branch_dir, "branch.frames");
  state->cas_dir = cps_flatfile_join2(state->branch_dir, "cas");
  state->cas_manifest_path = cps_flatfile_join2(state->cas_dir, "manifest.bin");
  if (!state->branch_dir || !state->tmp_dir || !state->idx_path || !state->dat_path ||
      !state->meta_path || !state->meta_tmp_path || !state->ckp_path ||
      !state->dir_path || !state->cas_dir || !state->cas_manifest_path) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return CPS_ERR_NOMEM;
  }

  state->checkpoint_interval = opts->checkpoint_interval ? opts->checkpoint_interval : 128;
  state->mini_toc_hint = opts->mini_toc_hint ? opts->mini_toc_hint : 64;
  state->create_branch = opts->create_branch;

  int status = cps_flatfile_ensure_directories(state);
  if (status != CPS_OK) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return status;
  }

  status = cps_flatfile_meta_load(state);
  if (status != CPS_OK) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return status;
  }
  status = cps_flatfile_cas_manifest_load(state);
  if (status != CPS_OK) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return status;
  }
  status = cps_flatfile_recover_branch(state);
  if (status != CPS_OK) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return status;
  }
  state->next_frame_id = state->meta.head_frame_id + 1u;

  status = cps_flatfile_frame_dir_seed_from_meta(state);
  if (status != CPS_OK) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return status;
  }

  engine->ops = &cps_flatfile_vtable;
  engine->state = state;
  engine->caps = CPS_CAP_BEAT_ATOMIC |
                 CPS_CAP_PREFIX_SCAN |
                 CPS_CAP_CHECKPOINT |
                 CPS_CAP_COMPACTION |
                 CPS_CAP_CRC32C |
                 CPS_CAP_MERKLE |
                 CPS_CAP_AEAD |
                 CPS_CAP_DEFLATE |
                 CPS_CAP_HISTORY_PAYLOAD |
                 CPS_CAP_HISTORY_MANIFEST |
                 CPS_CAP_NAMEPOOL_MAP;

  if (!cps_flatfile_publish_metrics(state)) {
    cps_flatfile_emit_cei(state, dt_cps_sev_debug(), k_cps_topic_bootstrap, "persist metrics publish deferred");
  }
  if (!cep_boot_ops_mark_store_ready()) {
    cps_flatfile_emit_cei(state, dt_cps_sev_debug(), k_cps_topic_bootstrap, "boot ops store-ready deferred");
  }

  *out = engine;
  return CPS_OK;
}

static int cps_flatfile_prepare_txn_files(cps_flatfile_txn_state *txn) {
  if (!txn || !txn->owner) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  char frame_suffix[64];
  snprintf(frame_suffix, sizeof frame_suffix, "frame_%llu_%llu", (unsigned long long)txn->beat, (unsigned long long)txn->frame_id);

  txn->frame_dir = cps_flatfile_join2(txn->owner->tmp_dir, frame_suffix);
  if (!txn->frame_dir) {
    return CPS_ERR_NOMEM;
  }
  if (cps_flatfile_mkdir_p(txn->frame_dir, 0755) != 0) {
    free(txn->frame_dir);
    txn->frame_dir = NULL;
    return CPS_ERR_IO;
  }

  txn->dat_tmp_path = cps_flatfile_join2(txn->frame_dir, "branch.dat.part");
  txn->idx_tmp_path = cps_flatfile_join2(txn->frame_dir, "branch.idx.part");
  if (!txn->dat_tmp_path || !txn->idx_tmp_path) {
    return CPS_ERR_NOMEM;
  }

  txn->dat_fd = open(txn->dat_tmp_path, CPS_OPEN_FLAGS(O_CREAT | O_TRUNC | O_RDWR), 0644);
  if (txn->dat_fd < 0) {
    return CPS_ERR_IO;
  }

  txn->idx_fd = open(txn->idx_tmp_path, CPS_OPEN_FLAGS(O_CREAT | O_TRUNC | O_RDWR), 0644);
  if (txn->idx_fd < 0) {
    close(txn->dat_fd);
    txn->dat_fd = -1;
    return CPS_ERR_IO;
  }

  return CPS_OK;
}

static void cps_flatfile_txn_cleanup(cps_flatfile_txn_state *txn) {
  if (!txn) {
    return;
  }
  if (txn->dat_fd >= 0) {
    close(txn->dat_fd);
    txn->dat_fd = -1;
  }
  if (txn->idx_fd >= 0) {
    close(txn->idx_fd);
    txn->idx_fd = -1;
  }
  if (txn->dat_tmp_path) {
    unlink(txn->dat_tmp_path);
    free(txn->dat_tmp_path);
    txn->dat_tmp_path = NULL;
  }
  if (txn->idx_tmp_path) {
    unlink(txn->idx_tmp_path);
    free(txn->idx_tmp_path);
    txn->idx_tmp_path = NULL;
  }
  if (txn->frame_dir) {
    rmdir(txn->frame_dir);
    free(txn->frame_dir);
    txn->frame_dir = NULL;
  }
  free(txn->toc_entries);
  free(txn);
}

static int cps_flatfile_ensure_directories(cps_flatfile_state *state) {
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  struct stat st;
  if (cps_flatfile_stat_path(state->branch_dir, &st) != 0) {
    if (!state->create_branch) {
      return CPS_ERR_IO;
    }
    if (cps_flatfile_mkdir_p(state->branch_dir, 0755) != 0) {
      return CPS_ERR_IO;
    }
  } else if (!S_ISDIR(st.st_mode)) {
    return CPS_ERR_IO;
  }

  if (cps_flatfile_stat_path(state->tmp_dir, &st) != 0) {
    if (cps_flatfile_mkdir_p(state->tmp_dir, 0755) != 0) {
      return CPS_ERR_IO;
    }
  } else if (!S_ISDIR(st.st_mode)) {
    return CPS_ERR_IO;
  }

  int fd;
  fd = open(state->idx_path, CPS_OPEN_FLAGS(O_CREAT | O_APPEND), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  close(fd);

  fd = open(state->dat_path, CPS_OPEN_FLAGS(O_CREAT | O_APPEND), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  close(fd);

  fd = open(state->meta_path, CPS_OPEN_FLAGS(O_CREAT), 0644);
  if (fd < 0 && errno != EEXIST) {
    return CPS_ERR_IO;
  }
  if (fd >= 0) {
    close(fd);
  }

  fd = open(state->ckp_path, CPS_OPEN_FLAGS(O_CREAT | O_APPEND), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  close(fd);

  if (state->dir_path) {
    fd = open(state->dir_path, CPS_OPEN_FLAGS(O_CREAT | O_APPEND), 0644);
    if (fd < 0) {
      return CPS_ERR_IO;
    }
    close(fd);
  }
  if (state->cas_dir) {
    if (cps_flatfile_stat_path(state->cas_dir, &st) != 0) {
      if (cps_flatfile_mkdir_p(state->cas_dir, 0755) != 0) {
        return CPS_ERR_IO;
      }
    } else if (!S_ISDIR(st.st_mode)) {
      return CPS_ERR_IO;
    }
  }
  return CPS_OK;
}

static uint64_t cps_flatfile_key_hash(const uint8_t *data, size_t len) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  if (data && len > 0u) {
    blake3_hasher_update(&hasher, data, len);
  }
  uint8_t digest[16];
  blake3_hasher_finalize(&hasher, digest, sizeof digest);
  uint64_t hash = 0u;
  memcpy(&hash, digest, sizeof hash);
  return hash;
}

static size_t cps_flatfile_record_header_span(uint32_t rtype) {
  size_t span = sizeof(cps_flatfile_record_header);
  if (rtype == CPS_RECORD_TYPE_PAYLOAD) {
    span += sizeof(cps_flatfile_payload_header);
  }
  return span;
}

static bool cps_flatfile_read_varint(const uint8_t *data, size_t size, size_t *offset, uint64_t *value) {
  if (!data || !offset || !value) {
    return false;
  }
  uint64_t acc = 0u;
  unsigned shift = 0u;
  size_t cursor = *offset;
  while (cursor < size) {
    uint8_t byte = data[cursor++];
    acc |= ((uint64_t)(byte & 0x7Fu)) << shift;
    if ((byte & 0x80u) == 0u) {
      *offset = cursor;
      *value = acc;
      return true;
    }
    shift += 7u;
    if (shift >= 64u) {
      return false;
    }
  }
  return false;
}

static bool cps_flatfile_parse_cell_desc_payload_ref(cps_slice value,
                                                     uint8_t *payload_kind,
                                                     uint64_t *payload_fp,
                                                     cps_flatfile_payload_ref_info *ref_info) {
  if (!value.data || value.len == 0u || !ref_info) {
    return false;
  }
  size_t offset = 0u;
  if (value.len < 1u + sizeof(uint16_t)) {
    return false;
  }
  offset += 1u; /* cell type */
  offset += sizeof(uint16_t); /* store descriptor */

  uint64_t tmp = 0u;
  if (!cps_flatfile_read_varint(value.data, value.len, &offset, &tmp)) {
    return false;
  }
  if (!cps_flatfile_read_varint(value.data, value.len, &offset, &tmp)) {
    return false;
  }
  if (value.len - offset < 16u) {
    return false;
  }
  offset += 16u; /* revision */
  if (value.len - offset < 1u) {
    return false;
  }
  uint8_t local_payload_kind = value.data[offset++];
  if (payload_kind) {
    *payload_kind = local_payload_kind;
  }

  uint64_t fp_len = 0u;
  if (!cps_flatfile_read_varint(value.data, value.len, &offset, &fp_len)) {
    return false;
  }
  uint64_t local_payload_fp = 0u;
  if (fp_len > 0u) {
    if (fp_len != sizeof local_payload_fp || value.len - offset < fp_len) {
      return false;
    }
    memcpy(&local_payload_fp, value.data + offset, sizeof local_payload_fp);
    offset += fp_len;
  }
  if (payload_fp) {
    *payload_fp = local_payload_fp;
  }

  uint64_t inline_len = 0u;
  if (!cps_flatfile_read_varint(value.data, value.len, &offset, &inline_len)) {
    return false;
  }
  if (inline_len > value.len - offset) {
    return false;
  }
  offset += (size_t)inline_len;

  uint64_t payload_ref_len = 0u;
  if (!cps_flatfile_read_varint(value.data, value.len, &offset, &payload_ref_len)) {
    return false;
  }
  if (payload_ref_len == 0u || payload_ref_len > value.len - offset) {
    return false;
  }

  const uint8_t *ref_base = value.data + offset;
  size_t ref_size = (size_t)payload_ref_len;
  if (ref_size < 4u) {
    return false;
  }
  size_t ref_cursor = 0u;
  ref_info->kind = (cepFlatPayloadRefKind)ref_base[ref_cursor++];
  ref_info->hash_alg = (cepFlatHashAlgorithm)ref_base[ref_cursor++];
  ref_info->codec = ref_base[ref_cursor++];
  ref_info->aead_mode = ref_base[ref_cursor++];
  if (!cps_flatfile_read_varint(ref_base, ref_size, &ref_cursor, &ref_info->payload_size)) {
    return false;
  }
  uint64_t hash_len = 0u;
  if (!cps_flatfile_read_varint(ref_base, ref_size, &ref_cursor, &hash_len)) {
    return false;
  }
  if (hash_len == 0u || hash_len > ref_size - ref_cursor) {
    return false;
  }
  ref_info->hash_bytes = ref_base + ref_cursor;
  ref_info->hash_len = (size_t)hash_len;
  return true;
}

static size_t cps_flatfile_varint_length(uint64_t value) {
  size_t length = 1u;
  while (value >= 0x80u) {
    value >>= 7u;
    length += 1u;
  }
  return length;
}

static uint8_t *cps_flatfile_write_varint_bytes(uint64_t value, uint8_t *dst) {
  do {
    uint8_t byte = (uint8_t)(value & 0x7Fu);
    value >>= 7u;
    if (value != 0u) {
      byte |= 0x80u;
    }
    *dst++ = byte;
  } while (value != 0u);
  return dst;
}

static bool cps_flatfile_buf_reserve(cps_buf *buf, size_t extra) {
  if (!buf) {
    return false;
  }
  size_t needed = buf->len + extra;
  if (needed <= buf->cap) {
    return true;
  }
  size_t new_cap = buf->cap ? buf->cap : 64u;
  while (new_cap < needed) {
    size_t grown = new_cap << 1u;
    if (grown <= new_cap) {
      new_cap = needed;
      break;
    }
    new_cap = grown;
  }
  uint8_t *grown_buf = (uint8_t *)realloc(buf->data, new_cap);
  if (!grown_buf) {
    return false;
  }
  buf->data = grown_buf;
  buf->cap = new_cap;
  return true;
}

static bool cps_flatfile_buf_append(cps_buf *buf, const void *data, size_t len) {
  if (!buf || (len && !data)) {
    return false;
  }
  if (len == 0u) {
    return true;
  }
  if (!cps_flatfile_buf_reserve(buf, len)) {
    return false;
  }
  memcpy(buf->data + buf->len, data, len);
  buf->len += len;
  return true;
}

static bool cps_flatfile_buf_append_u8(cps_buf *buf, uint8_t value) {
  return cps_flatfile_buf_append(buf, &value, 1u);
}

static bool cps_flatfile_buf_append_varint(cps_buf *buf, uint64_t value) {
  size_t needed = cps_flatfile_varint_length(value);
  if (!cps_flatfile_buf_reserve(buf, needed)) {
    return false;
  }
  uint8_t *dst = buf->data + buf->len;
  cps_flatfile_write_varint_bytes(value, dst);
  buf->len += needed;
  return true;
}

static bool cps_flatfile_hash_bytes(const void *data, size_t len, uint8_t out[CEP_FLAT_HASH_SIZE]) {
  if (!data || len == 0u || !out) {
    return false;
  }
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, data, len);
  blake3_hasher_finalize(&hasher, out, CEP_FLAT_HASH_SIZE);
  return true;
}

static bool cps_flatfile_decode_chunk_key(const uint8_t *key, size_t key_len, size_t *base_len, uint64_t *ordinal) {
  if (!key || key_len == 0u || !base_len || !ordinal) {
    return false;
  }
  size_t idx = key_len;
  uint64_t value = 0u;
  unsigned shift = 0u;
  while (idx > 0u) {
    uint8_t byte = key[--idx];
    value |= ((uint64_t)(byte & 0x7Fu)) << shift;
    if ((byte & 0x80u) == 0u) {
      *base_len = idx;
      *ordinal = value;
      return true;
    }
    shift += 7u;
    if (shift >= 64u) {
      return false;
    }
  }
  return false;
}

static int cps_flatfile_extract_chunk_info(cps_slice key, cps_slice value, cps_flatfile_chunk_info *info) {
  if (!info || !key.data || key.len == 0u || !value.data) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  memset(info, 0, sizeof *info);

  size_t base_len = 0u;
  uint64_t ordinal = 0u;
  if (!cps_flatfile_decode_chunk_key(key.data, key.len, &base_len, &ordinal) || base_len == 0u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  info->ordinal = ordinal;

  const uint8_t *body = value.data;
  size_t body_size = value.len;
  if (body_size < 1u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  size_t offset = 0u;
  info->payload_kind = body[offset++];

  if (!cps_flatfile_read_varint(body, body_size, &offset, &info->total_size)) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (!cps_flatfile_read_varint(body, body_size, &offset, &info->chunk_offset)) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (!cps_flatfile_read_varint(body, body_size, &offset, &info->chunk_size)) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (info->chunk_size == 0u || info->chunk_offset + info->chunk_size > info->total_size) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  uint64_t fingerprint_len = 0u;
  if (!cps_flatfile_read_varint(body, body_size, &offset, &fingerprint_len)) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (body_size - offset < fingerprint_len) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  offset += (size_t)fingerprint_len;

  if (body_size - offset < 1u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  info->aead_mode = body[offset++];
  if (info->aead_mode > CEP_FLAT_AEAD_XCHACHA20_POLY1305) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  uint64_t nonce_len = 0u;
  if (!cps_flatfile_read_varint(body, body_size, &offset, &nonce_len)) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (info->aead_mode == CEP_FLAT_AEAD_NONE) {
    if (nonce_len != 0u) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
  } else if (info->aead_mode == CEP_FLAT_AEAD_CHACHA20_POLY1305) {
    if (nonce_len != crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
  } else if (info->aead_mode == CEP_FLAT_AEAD_XCHACHA20_POLY1305) {
    if (nonce_len != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
      return CPS_ERR_INVALID_ARGUMENT;
    }
  }
  if (body_size - offset < nonce_len + CEP_FLAT_HASH_SIZE) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  offset += (size_t)nonce_len;
  offset += CEP_FLAT_HASH_SIZE;

  if (body_size - offset == 0u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  info->chunk_bytes = body + offset;
  info->chunk_bytes_len = body_size - offset;
  return CPS_OK;
}

static int cps_flatfile_checkpoint_blocks_push(cps_flatfile_checkpoint_block **blocks,
                                               size_t *len,
                                               size_t *cap,
                                               const cps_flatfile_ckp_header_disk *header,
                                               cps_flatfile_toc_entry_disk *entries) {
  if (!blocks || !len || !cap || !header) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (*len == *cap) {
    size_t new_cap = (*cap == 0u) ? 4u : (*cap * 2u);
    cps_flatfile_checkpoint_block *grown =
      (cps_flatfile_checkpoint_block *)realloc(*blocks, new_cap * sizeof(**blocks));
    if (!grown) {
      return CPS_ERR_NOMEM;
    }
    *blocks = grown;
    *cap = new_cap;
  }
  cps_flatfile_checkpoint_block *slot = &(*blocks)[(*len)++];
  slot->header = *header;
  slot->entries = entries;
  return CPS_OK;
}

static void cps_flatfile_checkpoint_blocks_destroy(cps_flatfile_checkpoint_block *blocks, size_t len) {
  if (!blocks) {
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    free(blocks[i].entries);
    blocks[i].entries = NULL;
  }
  free(blocks);
}

static int cps_flatfile_iterate_checkpoints(cps_flatfile_state *state,
                                            bool (*cb)(const cps_flatfile_ckp_header_disk *,
                                                       const cps_flatfile_toc_entry_disk *,
                                                       void *user),
                                            void *user) {
  if (!state || !state->ckp_path || !cb) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  int fd = open(state->ckp_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (fd < 0) {
    if (errno == ENOENT) {
      return CPS_ERR_NOT_FOUND;
    }
    return CPS_ERR_IO;
  }

  cps_flatfile_checkpoint_block *blocks = NULL;
  size_t len = 0u;
  size_t cap = 0u;
  off_t offset = 0;
  int rc = CPS_OK;

  for (;;) {
    cps_flatfile_ckp_header_disk header = {0};
    ssize_t rd = pread(fd, &header, sizeof header, offset);
    if (rd == 0) {
      break;
    }
    if (rd < 0) {
      if (errno == EINTR) {
        continue;
      }
      rc = CPS_ERR_IO;
      goto done;
    }
    if ((size_t)rd != sizeof header || header.magic != CPS_FLATFILE_CKP_MAGIC) {
      rc = CPS_ERR_VERIFY;
      goto done;
    }
    offset += sizeof header;

    size_t entries_size = (size_t)header.entry_count * sizeof(cps_flatfile_toc_entry_disk);
    cps_flatfile_toc_entry_disk *entries = NULL;
    if (entries_size > 0u) {
      entries = (cps_flatfile_toc_entry_disk *)malloc(entries_size);
      if (!entries) {
        rc = CPS_ERR_NOMEM;
        goto done;
      }
      ssize_t erd = pread(fd, entries, entries_size, offset);
      if (erd != (ssize_t)entries_size) {
        free(entries);
        rc = CPS_ERR_IO;
        goto done;
      }
    }
    offset += (off_t)entries_size;

    rc = cps_flatfile_checkpoint_blocks_push(&blocks, &len, &cap, &header, entries);
    if (rc != CPS_OK) {
      free(entries);
      goto done;
    }
  }

  for (size_t i = len; i > 0u; --i) {
    cps_flatfile_checkpoint_block *block = &blocks[i - 1u];
    bool cont = cb(&block->header, block->entries, user);
    if (!cont) {
      break;
    }
  }

done:
  close(fd);
  cps_flatfile_checkpoint_blocks_destroy(blocks, len);
  return rc;
}

static int cps_flatfile_checkpoint_finalize(cps_flatfile_state *state, uint64_t beat) {
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  state->last_checkpoint_beat = beat;
  state->meta.checkpoint_gen += 1u;
  return cps_flatfile_meta_store(state);
}

static void cps_flatfile_emit_cei(const cps_flatfile_state *state,
                                  const cepDT *severity,
                                  const char *topic,
                                  const char *detail) {
  if (!severity || !topic) {
    return;
  }
  const char *note_ptr = NULL;
  char note[192];
  if (detail && state && state->branch_name) {
    snprintf(note, sizeof note, "%s (branch=%s)", detail, state->branch_name);
    note_ptr = note;
  } else if (detail) {
    snprintf(note, sizeof note, "%s", detail);
    note_ptr = note;
  } else if (state && state->branch_name) {
    snprintf(note, sizeof note, "branch=%s", state->branch_name);
    note_ptr = note;
  }

  cepCeiRequest req = {
    .severity = *severity,
    .topic = topic,
    .topic_len = 0u,
    .topic_intern = true,
    .note = note_ptr,
    .note_len = note_ptr ? 0u : 0u,
    .origin_kind = "cps_flatfile",
    .emit_signal = false,
    .attach_to_op = false,
    .ttl_forever = true,
  };
  (void)cep_cei_emit(&req);
}

static cepDT cps_flatfile_branch_dt(const cps_flatfile_state *state) {
  const char *name = (state && state->branch_name && state->branch_name[0] != '\0')
                       ? state->branch_name
                       : "default";
  cepDT dt = cep_ops_make_dt(name);
  if (dt.tag == 0u) {
    dt = cep_ops_make_dt("persist_branch");
  }
  return dt;
}

static bool cps_flatfile_publish_metrics(cps_flatfile_state *state) {
  if (!state) {
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

  cepDT branch_dt = cps_flatfile_branch_dt(state);
  cepCell *branch_cell = cep_cell_ensure_dictionary_child(persist_root,
                                                          &branch_dt,
                                                          CEP_STORAGE_RED_BLACK_T);
  if (!branch_cell) {
    return false;
  }

  cepCell *metrics_cell = cep_cell_ensure_dictionary_child(branch_cell,
                                                           dt_persist_metrics_name(),
                                                           CEP_STORAGE_RED_BLACK_T);
  if (!metrics_cell) {
    return false;
  }

  bool ok = true;
  ok &= cep_cell_put_text(branch_cell, dt_persist_engine_field(), "flatfile");
  ok &= cep_cell_put_uint64(metrics_cell, dt_persist_frames_field(), state->stat_frames);
  ok &= cep_cell_put_uint64(metrics_cell, dt_persist_beats_field(), state->stat_beats);
  ok &= cep_cell_put_uint64(metrics_cell, dt_persist_bytes_idx_field(), state->stat_bytes_idx);
  ok &= cep_cell_put_uint64(metrics_cell, dt_persist_bytes_dat_field(), state->stat_bytes_dat);
  uint64_t cas_lookups = state->stat_cas_hits + state->stat_cas_misses;
  uint64_t cas_latency = cas_lookups ? (state->stat_cas_lookup_ns / cas_lookups) : 0u;
  ok &= cep_cell_put_uint64(metrics_cell, dt_persist_cas_hits_field(), state->stat_cas_hits);
  ok &= cep_cell_put_uint64(metrics_cell, dt_persist_cas_miss_field(), state->stat_cas_misses);
  ok &= cep_cell_put_uint64(metrics_cell, dt_persist_cas_latency_field(), cas_latency);
  return ok;
}

static int cps_flatfile_validate_head_trailer(const cps_flatfile_state *state, int idx_fd) {
  if (!state || idx_fd < 0) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (state->meta.head_idx_len == 0u) {
    return CPS_OK;
  }
  if (state->meta.head_idx_len < sizeof(cps_flatfile_trailer_disk)) {
    return CPS_ERR_VERIFY;
  }

  uint64_t trailer_ofs = state->meta.head_idx_ofs + state->meta.head_idx_len - sizeof(cps_flatfile_trailer_disk);
  cps_flatfile_trailer_disk trailer;
  int rc = cps_flatfile_read_exact_fd(idx_fd, trailer_ofs, &trailer, sizeof trailer);
  if (rc != CPS_OK) {
    return rc;
  }
  if (trailer.magic != CPS_FLATFILE_TRAIL_MAGIC) {
    return CPS_ERR_VERIFY;
  }
  if (memcmp(trailer.merkle, state->meta.head_merkle, sizeof trailer.merkle) != 0) {
    return CPS_ERR_VERIFY;
  }
  if (state->meta.head_frame_id && trailer.frame_id != state->meta.head_frame_id) {
    return CPS_ERR_VERIFY;
  }
  if (state->meta.last_beat && trailer.beat != state->meta.last_beat) {
    return CPS_ERR_VERIFY;
  }
  return CPS_OK;
}

static int cps_flatfile_reset_branch(cps_flatfile_state *state, int idx_fd, int dat_fd) {
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (idx_fd >= 0 && ftruncate(idx_fd, 0) != 0) {
    return CPS_ERR_IO;
  }
  if (dat_fd >= 0 && ftruncate(dat_fd, 0) != 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_meta *meta = &state->meta;
  meta->head_idx_ofs = 0u;
  meta->head_idx_len = 0u;
  meta->head_dat_ofs = 0u;
  meta->head_dat_len = 0u;
  meta->last_beat = 0u;
  meta->head_frame_id = 0u;
  memset(meta->head_merkle, 0, sizeof meta->head_merkle);
  meta->checkpoint_gen = 0u;

  state->next_frame_id = 0u;
  state->last_checkpoint_beat = 0u;
  if (state->dir_path) {
    int dir_fd = open(state->dir_path, CPS_OPEN_FLAGS(O_RDWR | O_CREAT), 0644);
    if (dir_fd >= 0) {
      (void)ftruncate(dir_fd, 0);
      close(dir_fd);
    }
  }
  return cps_flatfile_meta_store(state);
}

static int cps_flatfile_recover_branch(cps_flatfile_state *state) {
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int idx_fd = open(state->idx_path, CPS_OPEN_FLAGS(O_RDWR));
  int dat_fd = open(state->dat_path, CPS_OPEN_FLAGS(O_RDWR));
  if (idx_fd < 0 || dat_fd < 0) {
    if (idx_fd >= 0) close(idx_fd);
    if (dat_fd >= 0) close(dat_fd);
    return CPS_ERR_IO;
  }

  int rc = CPS_OK;
  bool reset = false;
  uint64_t idx_end = state->meta.head_idx_ofs + state->meta.head_idx_len;
  uint64_t dat_end = state->meta.head_dat_ofs + state->meta.head_dat_len;

  off_t idx_size = lseek(idx_fd, 0, SEEK_END);
  off_t dat_size = lseek(dat_fd, 0, SEEK_END);
  if (idx_size < 0 || dat_size < 0) {
    rc = CPS_ERR_IO;
    goto done;
  }

  cps_flatfile_frame_dir_entry_disk tail_entry = {0};
  bool have_tail = false;
  if (state->dir_path) {
    int trim_rc = cps_flatfile_frame_dir_trim_to_fit(state,
                                                     (uint64_t)idx_size,
                                                     (uint64_t)dat_size,
                                                     &tail_entry);
    if (trim_rc == CPS_OK) {
      have_tail = true;
    } else if (trim_rc != CPS_ERR_NOT_FOUND) {
      rc = trim_rc;
      goto done;
    }
  }

  bool idx_overflow = state->meta.head_idx_ofs > UINT64_MAX - state->meta.head_idx_len;
  bool dat_overflow = state->meta.head_dat_ofs > UINT64_MAX - state->meta.head_dat_len;
  if (idx_overflow) {
    idx_end = UINT64_MAX;
  }
  if (dat_overflow) {
    dat_end = UINT64_MAX;
  }

  bool head_valid = true;
  if (state->meta.head_idx_len > 0u) {
    if (idx_overflow || dat_overflow ||
        (uint64_t)idx_size < idx_end ||
        (uint64_t)dat_size < dat_end) {
      head_valid = false;
    } else {
      int validate_rc = cps_flatfile_validate_head_trailer(state, idx_fd);
      head_valid = (validate_rc == CPS_OK);
    }
  }

  if (!head_valid && have_tail) {
    int repair_rc = cps_flatfile_apply_tail_entry(state, idx_fd, &tail_entry);
    if (repair_rc == CPS_OK) {
      head_valid = true;
      idx_end = state->meta.head_idx_ofs + state->meta.head_idx_len;
      dat_end = state->meta.head_dat_ofs + state->meta.head_dat_len;
    } else {
      cps_flatfile_emit_cei(state, dt_cps_sev_warn(), k_cps_topic_recover, "failed to repair head; resetting branch");
      reset = true;
      rc = repair_rc;
    }
  }

  if (!head_valid) {
    reset = true;
  } else {
    rc = CPS_OK;
  }

  if (reset) {
    cps_flatfile_emit_cei(state, dt_cps_sev_crit(), k_cps_topic_recover, "head damaged; resetting branch");
    rc = cps_flatfile_reset_branch(state, idx_fd, dat_fd);
    goto done;
  }

  if ((uint64_t)idx_size > idx_end) {
    if (ftruncate(idx_fd, (off_t)idx_end) != 0) {
      rc = CPS_ERR_IO;
      goto done;
    }
  }
  if ((uint64_t)dat_size > dat_end) {
    if (ftruncate(dat_fd, (off_t)dat_end) != 0) {
      rc = CPS_ERR_IO;
      goto done;
    }
  }

done:
  close(idx_fd);
  close(dat_fd);
  return rc;
}

static int cps_flatfile_fetch_entry_value(int idx_fd,
                                          int dat_fd,
                                          const cps_flatfile_toc_entry_disk *entry,
                                          cps_slice key,
                                          cps_buf *out) {
  if (!entry || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  bool is_payload = entry->rtype == CPS_RECORD_TYPE_PAYLOAD;
  int record_fd = is_payload ? dat_fd : idx_fd;
  if (record_fd < 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_record_header header = {0};
  if (cps_flatfile_read_exact_fd(record_fd, entry->key_ofs, &header, sizeof header) != CPS_OK) {
    return CPS_ERR_IO;
  }
  if (header.rtype != entry->rtype ||
      header.key_len != entry->key_len ||
      header.val_len != entry->val_len) {
    return CPS_ERR_VERIFY;
  }

  size_t extra_header = cps_flatfile_record_header_span(header.rtype) - sizeof header;
  if (entry->key_len != key.len) {
    return CPS_ERR_NOT_FOUND;
  }

  bool match = true;
  if (entry->key_len > 0u) {
    uint8_t *key_buf = (uint8_t *)malloc(entry->key_len);
    if (!key_buf) {
      return CPS_ERR_NOMEM;
    }
    int key_rc = cps_flatfile_read_exact_fd(record_fd,
                                            entry->key_ofs + sizeof header + extra_header,
                                            key_buf,
                                            entry->key_len);
    if (key_rc != CPS_OK) {
      free(key_buf);
      return key_rc;
    }
    match = memcmp(key_buf, key.data, entry->key_len) == 0;
    free(key_buf);
  }
  if (!match) {
    return CPS_ERR_NOT_FOUND;
  }

  if (entry->val_len > 0u) {
    if (out->cap < entry->val_len) {
      uint8_t *grown = (uint8_t *)realloc(out->data, entry->val_len);
      if (!grown) {
        return CPS_ERR_NOMEM;
      }
      out->data = grown;
      out->cap = entry->val_len;
    }
    int val_rc = cps_flatfile_read_exact_fd(record_fd, entry->val_ofs, out->data, entry->val_len);
    if (val_rc != CPS_OK) {
      return val_rc;
    }
  }
  out->len = entry->val_len;
  return CPS_OK;
}

static bool cps_flatfile_scan_keys_contains(cps_flatfile_scanned_key *keys,
                                            size_t len,
                                            const uint8_t *key,
                                            uint32_t key_len,
                                            uint64_t hash) {
  for (size_t i = 0; i < len; ++i) {
    if (keys[i].hash != hash || keys[i].key_len != key_len) {
      continue;
    }
    if (key_len == 0u) {
      return true;
    }
    if (memcmp(keys[i].key, key, key_len) == 0) {
      return true;
    }
  }
  return false;
}

static int cps_flatfile_scan_keys_add(cps_flatfile_scanned_key **keys,
                                      size_t *len,
                                      size_t *cap,
                                      const uint8_t *key,
                                      uint32_t key_len,
                                      uint64_t hash) {
  if (!keys || !len || !cap) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (*len == *cap) {
    size_t new_cap = *cap ? (*cap * 2u) : 8u;
    cps_flatfile_scanned_key *grown = (cps_flatfile_scanned_key *)realloc(*keys, new_cap * sizeof(**keys));
    if (!grown) {
      return CPS_ERR_NOMEM;
    }
    *keys = grown;
    *cap = new_cap;
  }
  cps_flatfile_scanned_key *slot = &(*keys)[(*len)++];
  slot->hash = hash;
  slot->key_len = key_len;
  if (key_len > 0u) {
    slot->key = (uint8_t *)malloc(key_len);
    if (!slot->key) {
      --(*len);
      return CPS_ERR_NOMEM;
    }
    memcpy(slot->key, key, key_len);
  } else {
    slot->key = NULL;
  }
  return CPS_OK;
}

static void cps_flatfile_scan_keys_clear(cps_flatfile_scanned_key *keys, size_t len) {
  if (!keys) {
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    free(keys[i].key);
    keys[i].key = NULL;
    keys[i].key_len = 0u;
  }
}

static int cps_flatfile_scan_entries_with_prefix(cps_flatfile_state *state,
                                                 int idx_fd,
                                                 int dat_fd,
                                                 const cps_flatfile_toc_entry_disk *entries,
                                                 uint32_t entry_count,
                                                 cps_slice prefix,
                                                 cps_scan_cb cb,
                                                 void *user,
                                                 cps_flatfile_scanned_key **visited,
                                                 size_t *visited_len,
                                                 size_t *visited_cap) {
  if (!entries || entry_count == 0u || !cb || !visited || !visited_len || !visited_cap) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  uint8_t *key_buf = NULL;
  size_t key_cap = 0u;
  cps_buf value = {0};
  int rc = CPS_ERR_NOT_FOUND;

  for (uint32_t i = 0; i < entry_count; ++i) {
    const cps_flatfile_toc_entry_disk *entry = &entries[i];
    int record_fd = (entry->rtype == CPS_RECORD_TYPE_PAYLOAD) ? dat_fd : idx_fd;
    if (record_fd < 0) {
      rc = CPS_ERR_IO;
      break;
    }

    cps_flatfile_record_header header = {0};
    if (cps_flatfile_read_exact_fd(record_fd, entry->key_ofs, &header, sizeof header) != CPS_OK) {
      continue;
    }
    if (header.rtype != entry->rtype || header.key_len != entry->key_len) {
      continue;
    }
    size_t extra_header = cps_flatfile_record_header_span(header.rtype) - sizeof header;
    if (header.key_len > 0u) {
      if (key_cap < header.key_len) {
        uint8_t *grown = (uint8_t *)realloc(key_buf, header.key_len);
        if (!grown) {
          rc = CPS_ERR_NOMEM;
          break;
        }
        key_buf = grown;
        key_cap = header.key_len;
      }
      if (cps_flatfile_read_exact_fd(record_fd,
                                     entry->key_ofs + sizeof header + extra_header,
                                     key_buf,
                                     header.key_len) != CPS_OK) {
        continue;
      }
    }

    if (prefix.len > header.key_len) {
      continue;
    }
    if (prefix.len > 0u && memcmp(key_buf, prefix.data, prefix.len) != 0) {
      continue;
    }

    uint64_t hash = cps_flatfile_key_hash(key_buf, header.key_len);
    if (cps_flatfile_scan_keys_contains(*visited, *visited_len, key_buf, header.key_len, hash)) {
      continue;
    }

    value.len = 0u;
    value.cap = 0u;
    value.data = NULL;
    cps_slice key_slice = { .data = key_buf, .len = header.key_len };
    int val_rc = cps_flatfile_fetch_entry_value(idx_fd,
                                                dat_fd,
                                                entry,
                                                key_slice,
                                                &value);
    if (val_rc == CPS_ERR_NOT_FOUND && state &&
        (entry->flags & CPS_FLATFILE_TOC_FLAG_CAS_REF) != 0u &&
        entry->rtype == CPS_RECORD_TYPE_PAYLOAD) {
      val_rc = cps_flatfile_build_cas_record(state, key_slice, &value);
    }
    if (val_rc != CPS_OK) {
      free(value.data);
      value.data = NULL;
      value.cap = 0u;
      continue;
    }

    cps_slice value_slice = { .data = value.data, .len = value.len };
    int cb_rc = cb(key_slice, value_slice, user);
    free(value.data);
    value.data = NULL;
    value.cap = 0u;
    if (cb_rc != 0) {
      rc = cb_rc;
      break;
    }

    rc = CPS_OK;
    int track_rc = cps_flatfile_scan_keys_add(visited, visited_len, visited_cap, key_buf, header.key_len, hash);
    if (track_rc != CPS_OK) {
      rc = track_rc;
      break;
    }
  }

  free(key_buf);
  free(value.data);
  return rc;
}

static int cps_flatfile_toc_push(cps_flatfile_txn_state *txn, uint32_t rtype, uint64_t key_hash, uint64_t key_ofs, uint32_t key_len, uint64_t val_ofs, uint32_t val_len) {
  if (!txn) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (txn->toc_len == txn->toc_cap) {
    size_t new_cap = txn->toc_cap ? txn->toc_cap * 2u : 32u;
    cps_flatfile_toc_entry *grown = (cps_flatfile_toc_entry *)realloc(txn->toc_entries, new_cap * sizeof(*txn->toc_entries));
    if (!grown) {
      return CPS_ERR_NOMEM;
    }
    txn->toc_entries = grown;
    txn->toc_cap = new_cap;
  }
  cps_flatfile_toc_entry *entry = &txn->toc_entries[txn->toc_len++];
  entry->rtype = rtype;
  entry->key_hash = key_hash;
  entry->key_ofs = key_ofs;
  entry->key_len = key_len;
  entry->val_ofs = val_ofs;
  entry->val_len = val_len;
  entry->flags = 0u;
  return CPS_OK;
}

static int cps_flatfile_write_mini_toc_and_trailer(cps_flatfile_txn_state *txn,
                                                   const uint8_t merkle[32],
                                                   uint64_t dat_base,
                                                   uint64_t idx_base,
                                                   uint64_t *out_bytes) {
  if (!txn || !merkle || !txn->owner || !txn->owner->idx_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int fd = open(txn->owner->idx_path, CPS_OPEN_FLAGS(O_WRONLY | O_APPEND));
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_toc_header_disk header = {
    .magic = CPS_FLATFILE_TOC_MAGIC,
    .entry_count = (uint32_t)txn->toc_len,
  };
  int rc = cps_flatfile_write_all(fd, (const uint8_t *)&header, sizeof header);
  size_t bytes_written = sizeof header;

  for (size_t i = 0; rc == CPS_OK && i < txn->toc_len; ++i) {
    bool is_payload = txn->toc_entries[i].rtype == CPS_RECORD_TYPE_PAYLOAD;
    uint64_t base = is_payload ? dat_base : idx_base;
    cps_flatfile_toc_entry_disk entry = {
      .key_hash = txn->toc_entries[i].key_hash,
      .key_ofs = base + txn->toc_entries[i].key_ofs,
      .val_ofs = base + txn->toc_entries[i].val_ofs,
      .key_len = txn->toc_entries[i].key_len,
      .val_len = txn->toc_entries[i].val_len,
      .rtype = txn->toc_entries[i].rtype,
      .flags = txn->toc_entries[i].flags,
    };
    rc = cps_flatfile_write_all(fd, (const uint8_t *)&entry, sizeof entry);
    bytes_written += sizeof entry;
  }

  if (rc == CPS_OK) {
    cps_flatfile_trailer_disk trailer = {
      .magic = CPS_FLATFILE_TRAIL_MAGIC,
      .reserved = 0u,
      .beat = txn->beat,
      .frame_id = txn->frame_id,
      .toc_count = (uint32_t)txn->toc_len,
      .flags = 0u,
    };
    memcpy(trailer.merkle, merkle, sizeof trailer.merkle);
    rc = cps_flatfile_write_all(fd, (const uint8_t *)&trailer, sizeof trailer);
    bytes_written += sizeof trailer;
  }

  if (rc == CPS_OK && fsync(fd) != 0) {
    rc = CPS_ERR_IO;
  }
  close(fd);

  if (rc == CPS_OK && out_bytes) {
    *out_bytes = bytes_written;
  }
  return rc;
}

static int cps_flatfile_write_checkpoint_snapshot(cps_flatfile_state *state,
                                                  uint64_t beat,
                                                  uint64_t frame_id,
                                                  uint64_t dat_ofs,
                                                  uint64_t idx_ofs,
                                                  const cps_flatfile_toc_entry *entries,
                                                  size_t entry_count) {
  if (!state || !state->ckp_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int fd = open(state->ckp_path, CPS_OPEN_FLAGS(O_WRONLY | O_APPEND | O_CREAT), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_ckp_header_disk header = {
    .magic = CPS_FLATFILE_CKP_MAGIC,
    .entry_count = (uint32_t)entry_count,
    .beat = beat,
    .frame_id = frame_id,
    .dat_ofs = dat_ofs,
    .idx_ofs = idx_ofs,
  };

  int rc = cps_flatfile_write_all(fd, (const uint8_t *)&header, sizeof header);
  if (rc != CPS_OK) {
    close(fd);
    return rc;
  }

  for (size_t i = 0; i < entry_count; ++i) {
    const cps_flatfile_toc_entry *entry = &entries[i];
    bool is_payload = entry->rtype == CPS_RECORD_TYPE_PAYLOAD;
    uint64_t base = is_payload ? dat_ofs : idx_ofs;
    cps_flatfile_toc_entry_disk disk_entry = {
      .key_hash = entry->key_hash,
      .key_ofs = base + entry->key_ofs,
      .val_ofs = base + entry->val_ofs,
      .key_len = entry->key_len,
      .val_len = entry->val_len,
      .rtype = entry->rtype,
      .flags = entry->flags,
    };
    rc = cps_flatfile_write_all(fd, (const uint8_t *)&disk_entry, sizeof disk_entry);
    if (rc != CPS_OK) {
      close(fd);
      return rc;
    }
  }

  if (fsync(fd) != 0) {
    rc = CPS_ERR_IO;
  }
  close(fd);
  return rc;
}

static int cps_flatfile_write_all(int fd, const uint8_t *data, size_t len) {
  while (len > 0u) {
    ssize_t wrote = write(fd, data, len);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      return CPS_ERR_IO;
    }
    data += (size_t)wrote;
    len -= (size_t)wrote;
  }
  return CPS_OK;
}

static int cps_flatfile_append_file(const char *dst_path, const char *src_path, uint64_t *out_offset, uint64_t *out_len) {
  if (!dst_path || !src_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  int src_fd = open(src_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (src_fd < 0) {
    return CPS_ERR_IO;
  }

  int dst_fd = open(dst_path, CPS_OPEN_FLAGS(O_WRONLY | O_CREAT), 0644);
  if (dst_fd < 0) {
    close(src_fd);
    return CPS_ERR_IO;
  }

  off_t offset = lseek(dst_fd, 0, SEEK_END);
  if (offset < 0) {
    close(dst_fd);
    close(src_fd);
    return CPS_ERR_IO;
  }

  uint8_t buffer[64 * 1024];
  uint64_t total = 0u;
  int rc = CPS_OK;
  for (;;) {
    ssize_t rd = read(src_fd, buffer, sizeof buffer);
    if (rd < 0) {
      if (errno == EINTR) {
        continue;
      }
      rc = CPS_ERR_IO;
      break;
    }
    if (rd == 0) {
      break;
    }
    rc = cps_flatfile_write_all(dst_fd, buffer, (size_t)rd);
    if (rc != CPS_OK) {
      break;
    }
    total += (uint64_t)rd;
  }

  if (rc == CPS_OK && fsync(dst_fd) != 0) {
    rc = CPS_ERR_IO;
  }

  close(dst_fd);
  close(src_fd);

  if (out_offset) {
    *out_offset = (uint64_t)offset;
  }
  if (out_len) {
    *out_len = total;
  }
  return rc;
}

static void cps_flatfile_frame_dir_snapshot_destroy(cps_flatfile_frame_dir_snapshot *snapshot) {
  if (!snapshot) {
    return;
  }
  free(snapshot->entries);
  snapshot->entries = NULL;
  snapshot->count = 0u;
}

static int cps_flatfile_frame_dir_snapshot_load(const cps_flatfile_state *state,
                                                cps_flatfile_frame_dir_snapshot *snapshot) {
  if (!state || !state->dir_path || !snapshot) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  memset(snapshot, 0, sizeof *snapshot);

  int fd = open(state->dir_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  off_t size = lseek(fd, 0, SEEK_END);
  if (size < 0) {
    close(fd);
    return CPS_ERR_IO;
  }
  if ((size_t)size % sizeof(cps_flatfile_frame_dir_entry_disk) != 0u) {
    close(fd);
    return CPS_ERR_VERIFY;
  }
  if (size == 0) {
    close(fd);
    return CPS_OK;
  }

  size_t count = (size_t)size / sizeof(cps_flatfile_frame_dir_entry_disk);
  cps_flatfile_frame_dir_entry_disk *entries = (cps_flatfile_frame_dir_entry_disk *)malloc(count * sizeof *entries);
  if (!entries) {
    close(fd);
    return CPS_ERR_NOMEM;
  }

  ssize_t rd = pread(fd, entries, size, 0);
  close(fd);
  if (rd != size) {
    free(entries);
    return CPS_ERR_IO;
  }

  snapshot->entries = entries;
  snapshot->count = count;
  return CPS_OK;
}

static int cps_flatfile_frame_dir_append(const cps_flatfile_state *state,
                                         uint64_t beat,
                                         uint64_t frame_id,
                                         uint64_t idx_ofs,
                                         uint64_t idx_len,
                                         uint64_t dat_ofs,
                                         uint64_t dat_len) {
  if (!state || !state->dir_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  int fd = open(state->dir_path, CPS_OPEN_FLAGS(O_WRONLY | O_APPEND | O_CREAT), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_frame_dir_entry_disk entry = {
    .beat = beat,
    .frame_id = frame_id,
    .idx_ofs = idx_ofs,
    .idx_len = idx_len,
    .dat_ofs = dat_ofs,
    .dat_len = dat_len,
  };

  int rc = cps_flatfile_write_all(fd, (const uint8_t *)&entry, sizeof entry);
  if (rc == CPS_OK && fsync(fd) != 0) {
    rc = CPS_ERR_IO;
  }
  close(fd);
  return rc;
}

static bool cps_flatfile_frame_dir_entry_matches_meta(const cps_flatfile_frame_dir_entry_disk *entry,
                                                      const cps_flatfile_meta *meta) {
  if (!entry || !meta) {
    return false;
  }
  return entry->frame_id == meta->head_frame_id &&
         entry->idx_ofs == meta->head_idx_ofs &&
         entry->idx_len == meta->head_idx_len &&
         entry->dat_ofs == meta->head_dat_ofs &&
         entry->dat_len == meta->head_dat_len;
}

static int cps_flatfile_frame_dir_tail(const cps_flatfile_state *state,
                                       cps_flatfile_frame_dir_entry_disk *entry) {
  if (!state || !state->dir_path || !entry) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int fd = open(state->dir_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  off_t size = lseek(fd, 0, SEEK_END);
  if (size < 0) {
    close(fd);
    return CPS_ERR_IO;
  }
  if (size == 0) {
    close(fd);
    return CPS_ERR_NOT_FOUND;
  }
  if ((size_t)size % sizeof *entry != 0u) {
    close(fd);
    return CPS_ERR_VERIFY;
  }
  off_t ofs = size - (off_t)sizeof *entry;
  ssize_t rd = pread(fd, entry, sizeof *entry, ofs);
  close(fd);
  if (rd != sizeof *entry) {
    return CPS_ERR_IO;
  }
  return CPS_OK;
}

static int cps_flatfile_frame_dir_trim_to_fit(cps_flatfile_state *state,
                                              uint64_t idx_size,
                                              uint64_t dat_size,
                                              cps_flatfile_frame_dir_entry_disk *out_tail) {
  if (!state || !state->dir_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int fd = open(state->dir_path, CPS_OPEN_FLAGS(O_RDWR | O_CREAT), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  off_t size = lseek(fd, 0, SEEK_END);
  if (size < 0) {
    close(fd);
    return CPS_ERR_IO;
  }

  const off_t entry_size = (off_t)sizeof(cps_flatfile_frame_dir_entry_disk);
  while (size >= entry_size) {
    off_t ofs = size - entry_size;
    cps_flatfile_frame_dir_entry_disk entry = {0};
    if (pread(fd, &entry, sizeof entry, ofs) != sizeof entry) {
      /* Partial tail entry; truncate the damaged tail and retry. */
      if (ftruncate(fd, ofs) != 0) {
        close(fd);
        return CPS_ERR_IO;
      }
      size = ofs;
      continue;
    }

    bool overflow = (entry.idx_len > 0u && entry.idx_ofs > UINT64_MAX - entry.idx_len) ||
                    (entry.dat_len > 0u && entry.dat_ofs > UINT64_MAX - entry.dat_len);
    uint64_t idx_end = overflow ? UINT64_MAX : entry.idx_ofs + entry.idx_len;
    uint64_t dat_end = overflow ? UINT64_MAX : entry.dat_ofs + entry.dat_len;
    if (!overflow && idx_end <= idx_size && dat_end <= dat_size) {
      if (out_tail) {
        *out_tail = entry;
      }
      close(fd);
      return CPS_OK;
    }

    size -= entry_size;
    if (ftruncate(fd, size) != 0) {
      close(fd);
      return CPS_ERR_IO;
    }
  }

  close(fd);
  if (out_tail) {
    memset(out_tail, 0, sizeof *out_tail);
  }
  return CPS_ERR_NOT_FOUND;
}

static int cps_flatfile_frame_dir_seed_from_meta(cps_flatfile_state *state) {
  if (!state || !state->dir_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (state->meta.head_idx_len == 0u && state->meta.head_dat_len == 0u) {
    return CPS_OK;
  }

  cps_flatfile_frame_dir_entry_disk tail = {0};
  int tail_rc = cps_flatfile_frame_dir_tail(state, &tail);
  if (tail_rc == CPS_OK && cps_flatfile_frame_dir_entry_matches_meta(&tail, &state->meta)) {
    return CPS_OK;
  }
  return cps_flatfile_frame_dir_append(state,
                                       state->meta.last_beat,
                                       state->meta.head_frame_id,
                                       state->meta.head_idx_ofs,
                                       state->meta.head_idx_len,
                                       state->meta.head_dat_ofs,
                                       state->meta.head_dat_len);
}

static int cps_flatfile_apply_tail_entry(cps_flatfile_state *state,
                                         int idx_fd,
                                         const cps_flatfile_frame_dir_entry_disk *entry) {
  if (!state || idx_fd < 0 || !entry) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (entry->idx_len < sizeof(cps_flatfile_trailer_disk)) {
    return CPS_ERR_VERIFY;
  }
  uint64_t trailer_ofs = entry->idx_ofs + entry->idx_len - sizeof(cps_flatfile_trailer_disk);
  cps_flatfile_trailer_disk trailer = {0};
  int rc = cps_flatfile_read_exact_fd(idx_fd, trailer_ofs, &trailer, sizeof trailer);
  if (rc != CPS_OK) {
    return rc;
  }
  if (trailer.magic != CPS_FLATFILE_TRAIL_MAGIC) {
    return CPS_ERR_VERIFY;
  }

  state->meta.head_idx_ofs = entry->idx_ofs;
  state->meta.head_idx_len = entry->idx_len;
  state->meta.head_dat_ofs = entry->dat_ofs;
  state->meta.head_dat_len = entry->dat_len;
  state->meta.head_frame_id = entry->frame_id;
  state->meta.last_beat = entry->beat;
  memcpy(state->meta.head_merkle, trailer.merkle, sizeof trailer.merkle);
  return cps_flatfile_meta_store(state);
}


static int cps_flatfile_load_frame_entries(int idx_fd,
                                           uint64_t frame_ofs,
                                           uint64_t frame_len,
                                           cps_flatfile_toc_entry_disk **entries_out,
                                           uint32_t *entry_count) {
  if (idx_fd < 0 || !entries_out || !entry_count) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  *entries_out = NULL;
  *entry_count = 0u;
  if (frame_len < sizeof(cps_flatfile_trailer_disk)) {
    return CPS_ERR_VERIFY;
  }

  const uint64_t trailer_ofs = frame_ofs + frame_len - sizeof(cps_flatfile_trailer_disk);
  cps_flatfile_trailer_disk trailer = {0};
  int rc = cps_flatfile_read_exact_fd(idx_fd, trailer_ofs, &trailer, sizeof trailer);
  if (rc != CPS_OK) {
    return rc;
  }
  if (trailer.magic != CPS_FLATFILE_TRAIL_MAGIC) {
    return CPS_ERR_VERIFY;
  }

  const size_t toc_bytes = sizeof(cps_flatfile_toc_header_disk) +
                           (size_t)trailer.toc_count * sizeof(cps_flatfile_toc_entry_disk);
  if (frame_len < toc_bytes + sizeof(cps_flatfile_trailer_disk)) {
    return CPS_ERR_VERIFY;
  }

  const uint64_t toc_ofs = trailer_ofs - toc_bytes;
  cps_flatfile_toc_header_disk toc_header;
  rc = cps_flatfile_read_exact_fd(idx_fd, toc_ofs, &toc_header, sizeof toc_header);
  if (rc != CPS_OK) {
    return rc;
  }
  if (toc_header.magic != CPS_FLATFILE_TOC_MAGIC || toc_header.entry_count != trailer.toc_count) {
    return CPS_ERR_VERIFY;
  }
  if (toc_header.entry_count == 0u) {
    return CPS_ERR_NOT_FOUND;
  }

  const size_t entries_size = (size_t)toc_header.entry_count * sizeof(cps_flatfile_toc_entry_disk);
  cps_flatfile_toc_entry_disk *entries = (cps_flatfile_toc_entry_disk *)malloc(entries_size);
  if (!entries) {
    return CPS_ERR_NOMEM;
  }
  rc = cps_flatfile_read_exact_fd(idx_fd, toc_ofs + sizeof toc_header, entries, entries_size);
  if (rc != CPS_OK) {
    free(entries);
    return rc;
  }

  *entries_out = entries;
  *entry_count = toc_header.entry_count;
  return CPS_OK;
}

static int cps_flatfile_lookup_frame_record_fd(int idx_fd,
                                               int dat_fd,
                                               uint64_t frame_ofs,
                                               uint64_t frame_len,
                                               cps_slice key,
                                               cps_buf *out) {
  if (idx_fd < 0 || dat_fd < 0 || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  cps_flatfile_toc_entry_disk *entries = NULL;
  uint32_t entry_count = 0u;
  int rc = cps_flatfile_load_frame_entries(idx_fd, frame_ofs, frame_len, &entries, &entry_count);
  if (rc != CPS_OK) {
    return rc;
  }

  for (uint32_t i = 0; i < entry_count; ++i) {
    rc = cps_flatfile_fetch_entry_value(idx_fd, dat_fd, &entries[i], key, out);
    if (rc == CPS_OK || rc != CPS_ERR_NOT_FOUND) {
      break;
    }
  }

  free(entries);
  return rc;
}

static int cps_flatfile_lookup_head_record(cps_flatfile_state *state, cps_slice key, cps_buf *out) {
  if (!state || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (state->meta.head_idx_len == 0u) {
    return CPS_ERR_NOT_FOUND;
  }

  int idx_fd = open(state->idx_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (idx_fd < 0) {
    return CPS_ERR_IO;
  }
  int dat_fd = open(state->dat_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (dat_fd < 0) {
    close(idx_fd);
    return CPS_ERR_IO;
  }

  int rc = cps_flatfile_lookup_frame_record_fd(idx_fd,
                                               dat_fd,
                                               state->meta.head_idx_ofs,
                                               state->meta.head_idx_len,
                                               key,
                                               out);
  close(dat_fd);
  close(idx_fd);
  return rc;
}

typedef struct {
  cps_slice key;
  cps_buf *out;
  int idx_fd;
  int dat_fd;
  uint64_t key_hash;
  int rc;
} cps_flatfile_checkpoint_lookup_ctx;

static bool cps_flatfile_checkpoint_lookup_cb(const cps_flatfile_ckp_header_disk *header,
                                              const cps_flatfile_toc_entry_disk *entries,
                                              void *user) {
  cps_flatfile_checkpoint_lookup_ctx *ctx = (cps_flatfile_checkpoint_lookup_ctx *)user;
  if (!header || !ctx) {
    if (ctx) ctx->rc = CPS_ERR_INVALID_ARGUMENT;
    return false;
  }
  for (uint32_t i = 0; i < header->entry_count; ++i) {
    const cps_flatfile_toc_entry_disk *entry = &entries[i];
    if (entry->key_hash != ctx->key_hash || entry->key_len != ctx->key.len) {
      continue;
    }
    ctx->rc = cps_flatfile_fetch_entry_value(ctx->idx_fd, ctx->dat_fd, entry, ctx->key, ctx->out);
    if (ctx->rc == CPS_ERR_NOT_FOUND) {
      continue;
    }
    return false;
  }
  return true;
}

static bool cps_flatfile_checkpoint_scan_cb(const cps_flatfile_ckp_header_disk *header,
                                            const cps_flatfile_toc_entry_disk *entries,
                                            void *user_ctx) {
  cps_flatfile_checkpoint_scan_ctx *ctx = (cps_flatfile_checkpoint_scan_ctx *)user_ctx;
  if (!ctx || !header) {
    if (ctx) ctx->rc = CPS_ERR_INVALID_ARGUMENT;
    return false;
  }
  if (header->entry_count == 0u || !entries) {
    return true;
  }
  int scan_rc = cps_flatfile_scan_entries_with_prefix(ctx->state,
                                                      ctx->idx_fd,
                                                      ctx->dat_fd,
                                                      entries,
                                                      header->entry_count,
                                                      ctx->prefix,
                                                      ctx->cb,
                                                      ctx->user,
                                                      ctx->visited,
                                                      ctx->visited_len,
                                                      ctx->visited_cap);
  if (scan_rc == CPS_OK) {
    ctx->rc = CPS_OK;
    return true;
  }
  if (scan_rc == CPS_ERR_NOT_FOUND) {
    if (ctx->rc != CPS_OK) {
      ctx->rc = CPS_ERR_NOT_FOUND;
    }
    return true;
  }
  ctx->rc = scan_rc;
  return false;
}

static int cps_flatfile_lookup_checkpoint_record(cps_flatfile_state *state, cps_slice key, cps_buf *out) {
  if (!state || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  int idx_fd = open(state->idx_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (idx_fd < 0) {
    return CPS_ERR_IO;
  }
  int dat_fd = open(state->dat_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (dat_fd < 0) {
    close(idx_fd);
    return CPS_ERR_IO;
  }

  cps_flatfile_checkpoint_lookup_ctx ctx = {
    .key = key,
    .out = out,
    .idx_fd = idx_fd,
    .dat_fd = dat_fd,
    .key_hash = cps_flatfile_key_hash(key.data, key.len),
    .rc = CPS_ERR_NOT_FOUND,
  };

  int iter_rc = cps_flatfile_iterate_checkpoints(state, cps_flatfile_checkpoint_lookup_cb, &ctx);
  close(dat_fd);
  close(idx_fd);
  if (iter_rc == CPS_ERR_NOT_FOUND && ctx.rc == CPS_ERR_NOT_FOUND) {
    return CPS_ERR_NOT_FOUND;
  }
  if (iter_rc != CPS_OK && iter_rc != CPS_ERR_NOT_FOUND) {
    return iter_rc;
  }
  return ctx.rc;
}

static int cps_flatfile_build_cas_chunk(cps_slice chunk_key,
                                        uint8_t payload_kind,
                                        uint64_t payload_fp,
                                        const cps_flatfile_payload_ref_info *ref_info,
                                        cps_buf *payload,
                                        cps_buf *out) {
  if (!chunk_key.data || chunk_key.len == 0u || !ref_info || !payload || !payload->data || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  uint64_t total_size = ref_info->payload_size ? ref_info->payload_size : payload->len;
  if (payload->len < total_size) {
    return CPS_ERR_VERIFY;
  }
  size_t base_len = 0u;
  uint64_t ordinal = 0u;
  if (!cps_flatfile_decode_chunk_key(chunk_key.data, chunk_key.len, &base_len, &ordinal) || base_len == 0u) {
    return CPS_ERR_NOT_FOUND;
  }
  const uint64_t chunk_limit = CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD ? CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD : 4096u;
  uint64_t chunk_offset = chunk_limit * ordinal;
  if (chunk_offset >= total_size) {
    return CPS_ERR_NOT_FOUND;
  }
  uint64_t remaining = total_size - chunk_offset;
  uint64_t chunk_size = remaining < chunk_limit ? remaining : chunk_limit;
  if (chunk_offset + chunk_size > payload->len) {
    return CPS_ERR_VERIFY;
  }

  out->len = 0u;
  if (!cps_flatfile_buf_append_u8(out, payload_kind) ||
      !cps_flatfile_buf_append_varint(out, total_size) ||
      !cps_flatfile_buf_append_varint(out, chunk_offset) ||
      !cps_flatfile_buf_append_varint(out, chunk_size)) {
    return CPS_ERR_NOMEM;
  }

  if (payload_fp != 0u) {
    if (!cps_flatfile_buf_append_varint(out, sizeof payload_fp) ||
        !cps_flatfile_buf_append(out, &payload_fp, sizeof payload_fp)) {
      return CPS_ERR_NOMEM;
    }
  } else if (!cps_flatfile_buf_append_varint(out, 0u)) {
    return CPS_ERR_NOMEM;
  }

  uint8_t aad_hash[CEP_FLAT_HASH_SIZE];
  if (ref_info->aead_mode != CEP_FLAT_AEAD_NONE) {
    if (!cep_flat_stream_aead_ready()) {
      return CPS_ERR_VERIFY;
    }
    if (cep_flat_stream_active_aead_mode() != ref_info->aead_mode) {
      return CPS_ERR_VERIFY;
    }
    uint8_t nonce_buf[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0};
    size_t nonce_len = 0u;
    uint8_t *cipher = NULL;
    size_t cipher_len = 0u;
    if (!cep_flat_stream_aead_encrypt_chunk(chunk_key.data,
                                            chunk_key.len,
                                            payload_fp,
                                            chunk_offset,
                                            chunk_size,
                                            total_size,
                                            payload->data + chunk_offset,
                                            &cipher,
                                            &cipher_len,
                                            nonce_buf,
                                            &nonce_len,
                                            aad_hash)) {
      if (cipher) {
        sodium_memzero(cipher, cipher_len);
        free(cipher);
      }
      return CPS_ERR_VERIFY;
    }
    bool ok = true;
    ok &= cps_flatfile_buf_append_u8(out, (uint8_t)ref_info->aead_mode);
    ok &= cps_flatfile_buf_append_varint(out, nonce_len);
    if (ok && nonce_len) {
      ok &= cps_flatfile_buf_append(out, nonce_buf, nonce_len);
    }
    ok &= cps_flatfile_buf_append(out, aad_hash, sizeof aad_hash);
    if (ok) {
      ok &= cps_flatfile_buf_append(out, cipher, cipher_len);
    }
    sodium_memzero(cipher, cipher_len);
    free(cipher);
    if (!ok) {
      return CPS_ERR_NOMEM;
    }
  } else {
    cep_flat_stream_compute_chunk_aad_hash(chunk_key.data, chunk_key.len, aad_hash);
    if (!cps_flatfile_buf_append_u8(out, (uint8_t)ref_info->aead_mode) ||
        !cps_flatfile_buf_append_varint(out, 0u) ||
        !cps_flatfile_buf_append(out, aad_hash, sizeof aad_hash)) {
      return CPS_ERR_NOMEM;
    }
    if (!cps_flatfile_buf_append(out, payload->data + chunk_offset, (size_t)chunk_size)) {
      return CPS_ERR_NOMEM;
    }
  }
  return CPS_OK;
}

static int cps_flatfile_build_cas_record(cps_flatfile_state *state, cps_slice key, cps_buf *out) {
  if (!state || !out || !key.data || key.len == 0u) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  size_t base_len = 0u;
  uint64_t ordinal = 0u;
  if (!cps_flatfile_decode_chunk_key(key.data, key.len, &base_len, &ordinal) || base_len == 0u) {
    return CPS_ERR_NOT_FOUND;
  }
  cps_slice base_key = {
    .data = key.data,
    .len = base_len,
  };

  cps_buf desc = {0};
  int rc = cps_flatfile_lookup_head_record(state, base_key, &desc);
  if (rc == CPS_ERR_NOT_FOUND) {
    rc = cps_flatfile_lookup_checkpoint_record(state, base_key, &desc);
  }

  if (rc == CPS_ERR_NOT_FOUND) {
    cps_flatfile_frame_dir_snapshot snapshot = {0};
    int snap_rc = cps_flatfile_frame_dir_snapshot_load(state, &snapshot);
    if (snap_rc == CPS_OK && snapshot.count > 0u) {
      int idx_fd = open(state->idx_path, CPS_OPEN_FLAGS(O_RDONLY));
      int dat_fd = open(state->dat_path, CPS_OPEN_FLAGS(O_RDONLY));
      if (idx_fd < 0 || dat_fd < 0) {
        if (idx_fd >= 0) close(idx_fd);
        if (dat_fd >= 0) close(dat_fd);
        snap_rc = CPS_ERR_IO;
      } else {
        for (size_t i = snapshot.count; i > 0u && rc == CPS_ERR_NOT_FOUND; --i) {
          cps_flatfile_frame_dir_entry_disk *entry = &snapshot.entries[i - 1u];
          if (entry->idx_len == 0u) {
            continue;
          }
          if (entry->frame_id == state->meta.head_frame_id &&
              entry->idx_ofs == state->meta.head_idx_ofs &&
              entry->idx_len == state->meta.head_idx_len) {
            continue;
          }
          rc = cps_flatfile_lookup_frame_record_fd(idx_fd,
                                                   dat_fd,
                                                   entry->idx_ofs,
                                                   entry->idx_len,
                                                   base_key,
                                                   &desc);
          if (rc == CPS_OK || rc != CPS_ERR_NOT_FOUND) {
            break;
          }
        }
        close(dat_fd);
        close(idx_fd);
      }
    }
    if (rc == CPS_ERR_NOT_FOUND && snap_rc != CPS_OK && snap_rc != CPS_ERR_NOT_FOUND) {
      rc = snap_rc;
    }
    cps_flatfile_frame_dir_snapshot_destroy(&snapshot);
  }

  if (rc != CPS_OK) {
    free(desc.data);
    return rc;
  }

  cps_flatfile_payload_ref_info ref_info = {0};
  uint8_t payload_kind = 0u;
  uint64_t payload_fp = 0u;
  if (!cps_flatfile_parse_cell_desc_payload_ref((cps_slice){ .data = desc.data, .len = desc.len },
                                                &payload_kind,
                                                &payload_fp,
                                                &ref_info) ||
      ref_info.kind != CEP_FLAT_PAYLOAD_REF_CAS) {
    free(desc.data);
    return CPS_ERR_NOT_FOUND;
  }

  cps_buf cas_payload = {0};
  rc = cps_flatfile_fetch_cas_blob_bytes(state, &ref_info, &cas_payload);
  if (rc != CPS_OK) {
    free(desc.data);
    free(cas_payload.data);
    return rc;
  }
  rc = cps_flatfile_normalize_cas_payload(&ref_info, &cas_payload);
  if (rc != CPS_OK) {
    free(desc.data);
    free(cas_payload.data);
    return rc;
  }

  rc = cps_flatfile_build_cas_chunk(key, payload_kind, payload_fp, &ref_info, &cas_payload, out);
  free(desc.data);
  free(cas_payload.data);
  return rc;
}

static int cps_flatfile_try_cas_read(cps_engine *engine, cps_slice key, cps_buf *out) {
  if (!engine || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cps_flatfile_state *state = cps_flatfile_state_from(engine);
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  return cps_flatfile_build_cas_record(state, key, out);
}
static int cps_flatfile_read_exact_fd(int fd, uint64_t ofs, void *buf, size_t len) {
  uint8_t *cursor = (uint8_t *)buf;
  size_t remaining = len;
  while (remaining > 0u) {
    ssize_t rd = pread(fd, cursor, remaining, (off_t)ofs);
    if (rd < 0) {
      if (errno == EINTR) {
        continue;
      }
      return CPS_ERR_IO;
    }
    if (rd == 0) {
      return CPS_ERR_IO;
    }
    cursor += (size_t)rd;
    ofs += (uint64_t)rd;
    remaining -= (size_t)rd;
  }
  return CPS_OK;
}

static void cps_flatfile_meta_init(cps_flatfile_state *state) {
  if (!state) {
    return;
  }
  cps_flatfile_meta *meta = &state->meta;
  memset(meta, 0, sizeof(*meta));
  meta->magic = CPS_FLATFILE_META_MAGIC;
  meta->format_ver = CPS_FLATFILE_META_VERSION;
  meta->engine_id = 1u;

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  if (state->branch_dir) {
    blake3_hasher_update(&hasher, (const uint8_t *)state->branch_dir, strlen(state->branch_dir));
  }
  uint8_t digest[32];
  blake3_hasher_finalize(&hasher, digest, sizeof digest);
  memcpy(&meta->branch_id_hi, digest, sizeof(meta->branch_id_hi));
  memcpy(&meta->branch_id_lo, digest + sizeof(meta->branch_id_hi), sizeof(meta->branch_id_lo));
}

static uint32_t cps_flatfile_meta_crc(const cps_flatfile_meta *meta) {
  size_t bytes = sizeof(*meta) - sizeof(meta->crc32c);
  cps_flatfile_meta copy = *meta;
  copy.crc32c = 0u;
  return cep_crc32c(&copy, bytes, 0u);
}

static int cps_flatfile_meta_store(cps_flatfile_state *state) {
  if (!state || !state->meta_tmp_path || !state->meta_path) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  cps_flatfile_meta meta = state->meta;
  meta.magic = CPS_FLATFILE_META_MAGIC;
  meta.format_ver = CPS_FLATFILE_META_VERSION;
  meta.engine_id = 1u;
  meta.crc32c = cps_flatfile_meta_crc(&meta);

  int fd = open(state->meta_tmp_path, CPS_OPEN_FLAGS(O_CREAT | O_TRUNC | O_WRONLY), 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  int rc = cps_flatfile_write_all(fd, (const uint8_t *)&meta, sizeof meta);
  if (rc == CPS_OK && fsync(fd) != 0) {
    rc = CPS_ERR_IO;
  }
  close(fd);

  if (rc == CPS_OK && rename(state->meta_tmp_path, state->meta_path) != 0) {
    /* Windows refuses to overwrite existing targets; drop the stale meta and retry. */
    if (errno == EEXIST || errno == EACCES) {
      (void)unlink(state->meta_path);
      if (rename(state->meta_tmp_path, state->meta_path) != 0) {
        rc = CPS_ERR_IO;
      }
    } else {
      rc = CPS_ERR_IO;
    }
  }
  if (rc != CPS_OK) {
    unlink(state->meta_tmp_path);
    return rc;
  }

  state->meta = meta;
  return CPS_OK;
}

static int cps_flatfile_meta_load(cps_flatfile_state *state) {
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  struct stat st;
  if (cps_flatfile_stat_path(state->meta_path, &st) != 0) {
    if (errno != ENOENT) {
      return CPS_ERR_IO;
    }
    cps_flatfile_meta_init(state);
    return cps_flatfile_meta_store(state);
  }

  if ((size_t)st.st_size != sizeof(cps_flatfile_meta)) {
    cps_flatfile_meta_init(state);
    return cps_flatfile_meta_store(state);
  }

  int fd = open(state->meta_path, CPS_OPEN_FLAGS(O_RDONLY));
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_meta meta;
  ssize_t rd = read(fd, &meta, sizeof meta);
  close(fd);
  if (rd != sizeof meta) {
    cps_flatfile_meta_init(state);
    return cps_flatfile_meta_store(state);
  }

  uint32_t stored_crc = meta.crc32c;
  meta.crc32c = 0u;
  if (meta.magic != CPS_FLATFILE_META_MAGIC ||
      meta.format_ver != CPS_FLATFILE_META_VERSION ||
      stored_crc != cps_flatfile_meta_crc(&meta)) {
    cps_flatfile_meta_init(state);
    return cps_flatfile_meta_store(state);
  }

  meta.crc32c = stored_crc;
  state->meta = meta;
  return CPS_OK;
}

static int cps_flatfile_meta_commit(cps_flatfile_state *state,
                                    const cps_flatfile_txn_state *txn,
                                    uint64_t dat_ofs,
                                    uint64_t dat_len,
                                    uint64_t idx_ofs,
                                    uint64_t idx_len,
                                    const uint8_t merkle[32]) {
  if (!state || !txn || !merkle) {
    return CPS_ERR_INVALID_ARGUMENT;
  }

  state->meta.magic = CPS_FLATFILE_META_MAGIC;
  state->meta.format_ver = CPS_FLATFILE_META_VERSION;
  state->meta.engine_id = 1u;
  state->meta.head_dat_ofs = dat_ofs;
  state->meta.head_dat_len = dat_len;
  state->meta.head_idx_ofs = idx_ofs;
  state->meta.head_idx_len = idx_len;
  state->meta.last_beat = txn->beat;
  state->meta.head_frame_id = txn->frame_id;
  memcpy(state->meta.head_merkle, merkle, 32);
  return cps_flatfile_meta_store(state);
}

static char *cps_flatfile_join2(const char *base, const char *leaf) {
  if (!base || !leaf) {
    return NULL;
  }
  size_t len_base = strlen(base);
  bool needs_sep = len_base > 0u && base[len_base - 1u] != '/';
  size_t total = len_base + (needs_sep ? 1u : 0u) + strlen(leaf) + 1u;
  char *joined = (char *)malloc(total);
  if (!joined) {
    return NULL;
  }
  if (needs_sep) {
    snprintf(joined, total, "%s/%s", base, leaf);
  } else {
    snprintf(joined, total, "%s%s", base, leaf);
  }
  return joined;
}

static int cps_flatfile_stat_path(const char *path, struct stat *st) {
  if (!path || !st) {
    errno = EINVAL;
    return -1;
  }
  return stat(path, st);
}

static int cps_flatfile_mkdir_p(const char *path, mode_t mode) {
  if (!path || !*path) {
    errno = EINVAL;
    return -1;
  }
  char *dup = strdup(path);
  if (!dup) {
    errno = ENOMEM;
    return -1;
  }
  char *cursor = dup;
  if (*cursor == '/') {
    ++cursor;
  }
  for (; *cursor; ++cursor) {
    if (*cursor == '/') {
      *cursor = '\0';
      if (strlen(dup) > 0u) {
        if (cep_mkdir_portable(dup, mode) != 0 && errno != EEXIST) {
          *cursor = '/';
          free(dup);
          return -1;
        }
      }
      *cursor = '/';
    }
  }
  if (cep_mkdir_portable(dup, mode) != 0 && errno != EEXIST) {
    free(dup);
    return -1;
  }
  free(dup);
  return 0;
}
#define CPS_FLATFILE_CAS_MAX_SUBDIR 256u
