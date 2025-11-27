/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Shared fixture definitions for CPS/serializer tests. */

#ifndef CPS_FIXTURE_DEFS_H
#define CPS_FIXTURE_DEFS_H

#include <stddef.h>
#include <stdint.h>

#define CPS_FIXTURE_INLINE_NAME            "payload_ref_inline"
#define CPS_FIXTURE_CAS_PLAIN_NAME         "payload_ref_cas_plain"
#define CPS_FIXTURE_CAS_DEFLATE_NAME       "payload_ref_cas_deflate"

#define CPS_FIXTURE_INLINE_FRAME_PATH      "fixtures/cps/frames/payload_ref_inline.frame"
#define CPS_FIXTURE_CAS_PLAIN_FRAME_PATH   "fixtures/cps/frames/payload_ref_cas_plain.frame"
#define CPS_FIXTURE_CAS_DEFLATE_FRAME_PATH "fixtures/cps/frames/payload_ref_cas_deflate.frame"

#define CPS_FIXTURE_CAS_PLAIN_BLOB_PATH    "fixtures/cps/cas/payload_ref_cas_plain.blob"
#define CPS_FIXTURE_CAS_DEFLATE_BLOB_PATH  "fixtures/cps/cas/payload_ref_cas_deflate.blob"

#define CPS_FIXTURE_BRANCH_NAME            "cps_fixture_branch"
#define CPS_FIXTURE_AEAD_MODE              "xchacha20"
#define CPS_FIXTURE_AEAD_KEY_HEX           "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

extern const uint8_t k_cps_fixture_inline_cell_key[];
extern const size_t  k_cps_fixture_inline_cell_key_len;

extern const uint8_t k_cps_fixture_cas_plain_cell_key[];
extern const size_t  k_cps_fixture_cas_plain_cell_key_len;
extern const uint8_t k_cps_fixture_cas_plain_chunk_key[];
extern const size_t  k_cps_fixture_cas_plain_chunk_key_len;

extern const uint8_t k_cps_fixture_cas_deflate_cell_key[];
extern const size_t  k_cps_fixture_cas_deflate_cell_key_len;
extern const uint8_t k_cps_fixture_cas_deflate_chunk_key[];
extern const size_t  k_cps_fixture_cas_deflate_chunk_key_len;

extern const uint8_t k_cps_fixture_inline_payload[];
extern const size_t  k_cps_fixture_inline_payload_len;

extern const uint8_t k_cps_fixture_cas_plain_payload[];
extern const size_t  k_cps_fixture_cas_plain_payload_len;

extern const uint8_t k_cps_fixture_cas_deflate_payload[];
extern const size_t  k_cps_fixture_cas_deflate_payload_len;

#endif /* CPS_FIXTURE_DEFS_H */
