/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_CPS_ENGINE_H
#define CEP_CPS_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t cps_caps_t;

typedef struct {
  const uint8_t *data;
  size_t len;
} cps_slice;

typedef struct {
  uint8_t *data;
  size_t len;
  size_t cap;
} cps_buf;

typedef struct cps_engine cps_engine;
typedef struct cps_txn cps_txn;

typedef struct {
  uint64_t beat;
  uint64_t frame_id;
  uint8_t merkle[32];
} cps_frame_meta;

typedef int (*cps_scan_cb)(cps_slice key, cps_slice value, void *user);

typedef struct {
  const char *branch_path;
  bool create_if_missing;
} cps_open_opts;

typedef struct {
  uint64_t every_beats;
} cps_ckpt_opts;

typedef struct {
  uint64_t written_entries;
  uint64_t written_bytes;
} cps_ckpt_stat;

typedef struct {
  uint64_t history_window_beats;
} cps_compact_opts;

typedef struct {
  uint64_t reclaimed_bytes;
} cps_compact_stat;

typedef struct {
  uint64_t stat_frames;
  uint64_t stat_beats;
  uint64_t stat_bytes_idx;
  uint64_t stat_bytes_dat;
} cps_stats;

typedef enum {
  CPS_OK = 0,
  CPS_ERR_INVALID_ARGUMENT = -1,
  CPS_ERR_NOMEM = -2,
  CPS_ERR_IO = -3,
  CPS_ERR_CAPABILITY_MISMATCH = -4,
  CPS_ERR_VERIFY = -5,
  CPS_ERR_CONFLICT = -6,
  CPS_ERR_NOT_IMPLEMENTED = -7,
  CPS_ERR_NOT_FOUND = -8,
} cps_status;

#define CPS_CAP_BEAT_ATOMIC        (1ull << 0)
#define CPS_CAP_PREFIX_SCAN        (1ull << 1)
#define CPS_CAP_CHECKPOINT         (1ull << 2)
#define CPS_CAP_COMPACTION         (1ull << 3)
#define CPS_CAP_CRC32C             (1ull << 4)
#define CPS_CAP_MERKLE             (1ull << 5)
#define CPS_CAP_AEAD               (1ull << 6)
#define CPS_CAP_DEFLATE            (1ull << 7)
#define CPS_CAP_CAS_DEDUP          (1ull << 8)
#define CPS_CAP_REMOTE             (1ull << 9)
#define CPS_CAP_HISTORY_PAYLOAD    (1ull << 10)
#define CPS_CAP_HISTORY_MANIFEST   (1ull << 11)
#define CPS_CAP_NAMEPOOL_MAP       (1ull << 12)

typedef struct {
  int   (*open)(const cps_open_opts *opts, cps_engine **out);
  void  (*close)(cps_engine *engine);

  int   (*begin_beat)(cps_engine *engine, uint64_t beat_no, cps_txn **out);
  int   (*put_record)(cps_txn *txn, cps_slice key, cps_slice value, uint32_t rtype);
  int   (*commit_beat)(cps_txn *txn, cps_frame_meta *out_meta);
  void  (*abort_beat)(cps_txn *txn);

  int   (*get_record)(cps_engine *engine, cps_slice key, cps_buf *out);
  int   (*scan_prefix)(cps_engine *engine, cps_slice prefix, cps_scan_cb cb, void *user);

  int   (*checkpoint)(cps_engine *engine, const cps_ckpt_opts *opts, cps_ckpt_stat *out);
  int   (*compact)(cps_engine *engine, const cps_compact_opts *opts, cps_compact_stat *out);
  int   (*stats)(cps_engine *engine, cps_stats *out);

  cps_caps_t (*caps)(const cps_engine *engine);
} cps_vtable;

struct cps_engine {
  const cps_vtable *ops;
  cps_caps_t caps;
  void *state;
};

struct cps_txn {
  void *state;
};

#endif /* CEP_CPS_ENGINE_H */
