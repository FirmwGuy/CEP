/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_PIPELINES_H
#define CEP_L1_PIPELINES_H

#include "../l0_kernel/cep_cell.h"
#include "cep_l1_schema.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* owner;
    const char* province;
    const char* version;
    uint64_t    revision;
} cepL1PipelineMeta;

typedef struct {
    cepCell* pipeline;
    cepCell* stages;
    cepCell* edges;
} cepL1PipelineLayout;

bool cep_l1_pipeline_ensure(cepCell* pipelines_root,
                            const char* pipeline_id,
                            const cepL1PipelineMeta* meta,
                            cepL1PipelineLayout* layout);

bool cep_l1_pipeline_stage_stub(cepL1PipelineLayout* layout,
                                const char* stage_id,
                                cepCell** stage_out);

bool cep_l1_pipeline_add_edge(cepL1PipelineLayout* layout,
                              const char* from_stage,
                              const char* to_stage,
                              const char* note);

bool cep_l1_pipeline_bind_coherence(cepL1SchemaLayout* schema,
                                    cepL1PipelineLayout* pipeline);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L1_PIPELINES_H */
