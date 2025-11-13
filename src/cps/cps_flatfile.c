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
#include "cep_ops.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

#define CPS_FLATFILE_META_MAGIC    0x43505331u /* "CPS1" */
#define CPS_FLATFILE_META_VERSION  1u
#define CPS_FLATFILE_TOC_MAGIC     0x544F4331u /* "TOC1" */
#define CPS_FLATFILE_TRAIL_MAGIC   0x54524C31u /* "TRL1" */
#define CPS_FLATFILE_CKP_MAGIC     0x434B5031u /* "CKP1" */

#define CPS_RECORD_TYPE_PAYLOAD    0x02u

#define CPS_FLATFILE_PAYLOAD_FLAG_KIND_MASK  0x000000FFu
#define CPS_FLATFILE_PAYLOAD_FLAG_AEAD_SHIFT 8u
#define CPS_FLATFILE_PAYLOAD_FLAG_AEAD_MASK  (0x000000FFu << CPS_FLATFILE_PAYLOAD_FLAG_AEAD_SHIFT)

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
} cps_flatfile_state;

typedef struct {
  uint64_t key_hash;
  uint64_t key_ofs;
  uint64_t val_ofs;
  uint32_t key_len;
  uint32_t val_len;
  uint32_t rtype;
  uint32_t reserved;
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
  uint32_t reserved;
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
} cps_flatfile_checkpoint_view;

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
static bool cps_flatfile_publish_metrics(cps_flatfile_state *state);
static cepDT cps_flatfile_branch_dt(const cps_flatfile_state *state);
static int cps_flatfile_checkpoint_finalize(cps_flatfile_state *state, uint64_t beat);
static void cps_flatfile_checkpoint_view_destroy(cps_flatfile_checkpoint_view *view);
static int cps_flatfile_load_last_checkpoint(cps_flatfile_state *state, cps_flatfile_checkpoint_view *view);
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
static int cps_flatfile_scan_entries_with_prefix(int idx_fd,
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
  free(state->root_dir);
  free(state->branch_name);
  free(state->branch_dir);
  free(state->tmp_dir);
  free(state->idx_path);
  free(state->dat_path);
  free(state->meta_path);
  free(state->meta_tmp_path);
  free(state->ckp_path);
  free(state);
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
  }
  if (rc == CPS_OK) {
    rc = cps_flatfile_meta_commit(txn->owner, txn, dat_ofs, dat_len, idx_ofs, idx_len, merkle);
    if (rc != CPS_OK && !error_topic) {
      error_topic = k_cps_topic_frame_io;
      error_detail = "branch.meta update failed";
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

  int idx_fd = open(state->idx_path, O_RDONLY);
  int dat_fd = open(state->dat_path, O_RDONLY);
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
    int head_rc = cps_flatfile_scan_entries_with_prefix(idx_fd,
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
    cps_flatfile_checkpoint_view view = {0};
    int view_rc = cps_flatfile_load_last_checkpoint(state, &view);
    if (view_rc == CPS_OK && view.header.entry_count > 0u && view.entries) {
      int ck_rc = cps_flatfile_scan_entries_with_prefix(idx_fd,
                                                        dat_fd,
                                                        view.entries,
                                                        view.header.entry_count,
                                                        prefix,
                                                        cb,
                                                        user,
                                                        &visited,
                                                        &visited_len,
                                                        &visited_cap);
      if (ck_rc == CPS_OK) {
        rc = CPS_OK;
      } else if (ck_rc != CPS_ERR_NOT_FOUND) {
        rc = ck_rc;
      }
    }
    cps_flatfile_checkpoint_view_destroy(&view);
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

  idx_fd = open(state->idx_path, O_RDONLY);
  if (idx_fd < 0) {
    rc = CPS_ERR_IO;
    error_detail = "open branch.idx failed";
    goto done;
  }
  dat_fd = open(state->dat_path, O_RDONLY);
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
      rel->reserved = 0u;
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
  if (!state->branch_dir || !state->tmp_dir || !state->idx_path || !state->dat_path || !state->meta_path || !state->meta_tmp_path || !state->ckp_path) {
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
  status = cps_flatfile_recover_branch(state);
  if (status != CPS_OK) {
    cps_flatfile_state_destroy(state);
    free(engine);
    return status;
  }
  state->next_frame_id = state->meta.head_frame_id + 1u;

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

  txn->dat_fd = open(txn->dat_tmp_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (txn->dat_fd < 0) {
    return CPS_ERR_IO;
  }

  txn->idx_fd = open(txn->idx_tmp_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
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
  fd = open(state->idx_path, O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  close(fd);

  fd = open(state->dat_path, O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  close(fd);

  fd = open(state->meta_path, O_CREAT, 0644);
  if (fd < 0 && errno != EEXIST) {
    return CPS_ERR_IO;
  }
  if (fd >= 0) {
    close(fd);
  }

  fd = open(state->ckp_path, O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }
  close(fd);
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

static void cps_flatfile_checkpoint_view_destroy(cps_flatfile_checkpoint_view *view) {
  if (!view) {
    return;
  }
  free(view->entries);
  view->entries = NULL;
  memset(&view->header, 0, sizeof(view->header));
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
  return ok;
}

static int cps_flatfile_load_last_checkpoint(cps_flatfile_state *state, cps_flatfile_checkpoint_view *view) {
  if (!state || !state->ckp_path || !view) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int fd = open(state->ckp_path, O_RDONLY);
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  cps_flatfile_checkpoint_view_destroy(view);
  uint64_t offset = 0u;
  int rc = CPS_ERR_NOT_FOUND;

  for (;;) {
    cps_flatfile_ckp_header_disk header = {0};
    ssize_t rd = pread(fd, &header, sizeof header, (off_t)offset);
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
      if (pread(fd, entries, entries_size, (off_t)offset) != (ssize_t)entries_size) {
        free(entries);
        rc = CPS_ERR_IO;
        goto done;
      }
    }
    offset += entries_size;

    cps_flatfile_checkpoint_view_destroy(view);
    view->header = header;
    view->entries = entries;
    rc = CPS_OK;
  }

done:
  close(fd);
  if (rc != CPS_OK) {
    cps_flatfile_checkpoint_view_destroy(view);
  }
  return rc;
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
  return cps_flatfile_meta_store(state);
}

static int cps_flatfile_recover_branch(cps_flatfile_state *state) {
  if (!state) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  int idx_fd = open(state->idx_path, O_RDWR);
  int dat_fd = open(state->dat_path, O_RDWR);
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

  if (idx_end > 0u && (uint64_t)idx_size < idx_end) {
    reset = true;
  }
  if (dat_end > 0u && (uint64_t)dat_size < dat_end) {
    reset = true;
  }

  if (!reset && state->meta.head_idx_len > 0u) {
    rc = cps_flatfile_validate_head_trailer(state, idx_fd);
    if (rc != CPS_OK) {
      reset = true;
    }
  }
  if (rc != CPS_OK && !reset) {
    goto done;
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

static int cps_flatfile_scan_entries_with_prefix(int idx_fd,
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
    int val_rc = cps_flatfile_fetch_entry_value(idx_fd,
                                                dat_fd,
                                                entry,
                                                (cps_slice){ .data = key_buf, .len = header.key_len },
                                                &value);
    if (val_rc != CPS_OK) {
      free(value.data);
      value.data = NULL;
      value.cap = 0u;
      continue;
    }

    cps_slice key_slice = { .data = key_buf, .len = header.key_len };
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
  int fd = open(txn->owner->idx_path, O_WRONLY | O_APPEND);
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
      .reserved = 0u,
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
  int fd = open(state->ckp_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
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
      .reserved = 0u,
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

  int src_fd = open(src_path, O_RDONLY);
  if (src_fd < 0) {
    return CPS_ERR_IO;
  }

  int dst_fd = open(dst_path, O_WRONLY | O_CREAT, 0644);
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


static int cps_flatfile_lookup_head_record(cps_flatfile_state *state, cps_slice key, cps_buf *out) {
  if (!state || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  if (state->meta.head_idx_len == 0u) {
    return CPS_ERR_NOT_FOUND;
  }

  int idx_fd = open(state->idx_path, O_RDONLY);
  if (idx_fd < 0) {
    return CPS_ERR_IO;
  }
  int dat_fd = open(state->dat_path, O_RDONLY);
  if (dat_fd < 0) {
    close(idx_fd);
    return CPS_ERR_IO;
  }

  int rc = CPS_ERR_NOT_FOUND;
  const uint64_t frame_ofs = state->meta.head_idx_ofs;
  const uint64_t frame_len = state->meta.head_idx_len;
  if (frame_len < sizeof(cps_flatfile_trailer_disk)) {
    rc = CPS_ERR_VERIFY;
    goto done;
  }

  const uint64_t trailer_ofs = frame_ofs + frame_len - sizeof(cps_flatfile_trailer_disk);
  cps_flatfile_trailer_disk trailer = {0};
  rc = cps_flatfile_read_exact_fd(idx_fd, trailer_ofs, &trailer, sizeof trailer);
  if (rc != CPS_OK) {
    goto done;
  }
  if (trailer.magic != CPS_FLATFILE_TRAIL_MAGIC) {
    rc = CPS_ERR_VERIFY;
    goto done;
  }

  const size_t toc_bytes = sizeof(cps_flatfile_toc_header_disk) + (size_t)trailer.toc_count * sizeof(cps_flatfile_toc_entry_disk);
  if (frame_len < toc_bytes + sizeof(cps_flatfile_trailer_disk)) {
    rc = CPS_ERR_VERIFY;
    goto done;
  }

  const uint64_t toc_ofs = trailer_ofs - toc_bytes;
  cps_flatfile_toc_header_disk toc_header;
  rc = cps_flatfile_read_exact_fd(idx_fd, toc_ofs, &toc_header, sizeof toc_header);
  if (rc != CPS_OK) {
    goto done;
  }
  if (toc_header.magic != CPS_FLATFILE_TOC_MAGIC || toc_header.entry_count != trailer.toc_count) {
    rc = CPS_ERR_VERIFY;
    goto done;
  }

  if (toc_header.entry_count == 0u) {
    rc = CPS_ERR_NOT_FOUND;
    goto done;
  }

  const size_t entries_size = (size_t)toc_header.entry_count * sizeof(cps_flatfile_toc_entry_disk);
  cps_flatfile_toc_entry_disk *entries = (cps_flatfile_toc_entry_disk *)malloc(entries_size);
  if (!entries) {
    rc = CPS_ERR_NOMEM;
    goto done;
  }

  rc = cps_flatfile_read_exact_fd(idx_fd, toc_ofs + sizeof toc_header, entries, entries_size);
  if (rc != CPS_OK) {
    free(entries);
    goto done;
  }

  for (uint32_t i = 0; i < toc_header.entry_count; ++i) {
    rc = cps_flatfile_fetch_entry_value(idx_fd, dat_fd, &entries[i], key, out);
    if (rc == CPS_OK || rc != CPS_ERR_NOT_FOUND) {
      break;
    }
  }

  free(entries);

done:
  close(dat_fd);
  close(idx_fd);
  return rc;
}

static int cps_flatfile_lookup_checkpoint_record(cps_flatfile_state *state, cps_slice key, cps_buf *out) {
  if (!state || !out) {
    return CPS_ERR_INVALID_ARGUMENT;
  }
  cps_flatfile_checkpoint_view view = {0};
  int view_rc = cps_flatfile_load_last_checkpoint(state, &view);
  if (view_rc != CPS_OK) {
    return view_rc;
  }

  if (view.header.entry_count == 0u || !view.entries) {
    cps_flatfile_checkpoint_view_destroy(&view);
    return CPS_ERR_NOT_FOUND;
  }

  int idx_fd = open(state->idx_path, O_RDONLY);
  int dat_fd = open(state->dat_path, O_RDONLY);
  if (idx_fd < 0 || dat_fd < 0) {
    if (idx_fd >= 0) close(idx_fd);
    if (dat_fd >= 0) close(dat_fd);
    cps_flatfile_checkpoint_view_destroy(&view);
    return CPS_ERR_IO;
  }

  uint64_t target_hash = cps_flatfile_key_hash(key.data, key.len);
  int rc = CPS_ERR_NOT_FOUND;
  for (uint32_t i = 0; i < view.header.entry_count; ++i) {
    const cps_flatfile_toc_entry_disk *entry = &view.entries[i];
    if (entry->key_hash != target_hash || entry->key_len != key.len) {
      continue;
    }
    rc = cps_flatfile_fetch_entry_value(idx_fd, dat_fd, entry, key, out);
    if (rc == CPS_OK) {
      break;
    }
  }

  close(idx_fd);
  close(dat_fd);
  cps_flatfile_checkpoint_view_destroy(&view);
  return rc;
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

  int fd = open(state->meta_tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    return CPS_ERR_IO;
  }

  int rc = cps_flatfile_write_all(fd, (const uint8_t *)&meta, sizeof meta);
  if (rc == CPS_OK && fsync(fd) != 0) {
    rc = CPS_ERR_IO;
  }
  close(fd);

  if (rc == CPS_OK && rename(state->meta_tmp_path, state->meta_path) != 0) {
    rc = CPS_ERR_IO;
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

  int fd = open(state->meta_path, O_RDONLY);
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
        if (mkdir(dup, mode) != 0 && errno != EEXIST) {
          *cursor = '/';
          free(dup);
          return -1;
        }
      }
      *cursor = '/';
    }
  }
  if (mkdir(dup, mode) != 0 && errno != EEXIST) {
    free(dup);
    return -1;
  }
  free(dup);
  return 0;
}
