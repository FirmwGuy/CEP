/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_FLAT_HELPERS_H
#define CEP_FLAT_HELPERS_H

#include "cep_flat_serializer.h"
#include "cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    cepDT       name;
    uint8_t     flags;
    uint16_t    position;
    bool        has_fingerprint;
    uint64_t    fingerprint;
    uint8_t     cell_type;
    uint8_t     delta_flags;
} cepFlatChildDescriptor;

typedef struct {
    struct {
        cepID      id;
        uint16_t   length;
        uint8_t    flags;
        char*      text;
    } *entries;
    size_t count;
    size_t capacity;
    size_t emit_index;
} cepFlatNamepoolCollector;

bool cep_flat_namepool_register_id(cepFlatNamepoolCollector* collector, cepID id);
void cep_flat_namepool_clear(cepFlatNamepoolCollector* collector);
bool cep_flat_namepool_emit(cepFlatNamepoolCollector* collector, cepFlatSerializer* serializer);

uint16_t cep_flat_store_descriptor(const cepCell* cell);
void cep_flat_compute_revision_id(const cepCell* cell,
                                  const cepData* data,
                                  uint16_t store_descriptor,
                                  uint16_t meta_mask,
                                  uint64_t payload_fp,
                                  const void* inline_payload,
                                  size_t inline_length,
                                  uint8_t out[16]);

bool cep_flat_collect_children(const cepCell* cell,
                               cepFlatChildDescriptor** out_children,
                               size_t* out_count,
                               uint8_t* out_organiser);

bool cep_flat_emit_manifest_delta(cepFlatSerializer* serializer,
                                  const cepCell* parent,
                                  const cepFlatChildDescriptor* children,
                                  size_t child_count,
                                  uint8_t organiser,
                                  cepFlatNamepoolCollector* names);

bool cep_flat_emit_order_delta(cepFlatSerializer* serializer,
                               const cepCell* parent,
                               const cepFlatChildDescriptor* children,
                               size_t child_count,
                               uint8_t organiser,
                               cepFlatNamepoolCollector* names);

bool cep_flat_build_key(const cepCell* cell,
                        uint8_t record_type,
                        cepFlatNamepoolCollector* names,
                        uint8_t** out_key,
                        size_t* out_key_size);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FLAT_HELPERS_H */
