/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L1_RUNTIME_H
#define CEP_L1_RUNTIME_H

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_enzyme.h"
#include "../enzymes/fed_invoke.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool cep_l1_runtime_record_run(cepCell* runs_root,
                               const char* pipeline_id,
                               uint64_t dag_run_id,
                               const char* state_tag,
                               const cepPipelineMetadata* metadata,
                               cepCell** run_out);

bool cep_l1_runtime_record_stage_state(cepCell* run_root,
                                       const char* stage_id,
                                       const char* state_tag,
                                       uint64_t hop_index);

bool cep_l1_runtime_mark_stage_ready(cepCell* run_root,
                                     const char* stage_id,
                                     bool ready);

bool cep_l1_runtime_record_trigger(cepCell* run_root,
                                   const char* stage_id,
                                   const char* trigger_kind,
                                   const char* note,
                                   uint64_t beat);

bool cep_l1_runtime_configure_stage_fanin(cepCell* run_root,
                                          const char* stage_id,
                                          uint64_t expected);

bool cep_l1_runtime_record_metric(cepCell* metrics_root,
                                  const char* pipeline_id,
                                  const char* metric_tag,
                                  uint64_t value);

bool cep_l1_runtime_add_annotation(cepCell* annotations_root,
                                   const char* pipeline_id,
                                   const char* note);

bool cep_l1_runtime_record_stage_metric(cepCell* run_root,
                                        const char* stage_id,
                                        const char* metric_tag,
                                        uint64_t value);

bool cep_l1_runtime_add_stage_annotation(cepCell* run_root,
                                         const char* stage_id,
                                         const char* note);

bool cep_l1_runtime_emit_impulse(const cepPath* signal,
                                 const cepPath* target,
                                 const char* pipeline_id,
                                 const char* stage_id,
                                 uint64_t dag_run_id,
                                 uint64_t hop_index,
                                 cepImpulseQoS qos);

bool cep_l1_runtime_dispatch_if_ready(cepCell* run_root,
                                      const char* stage_id,
                                      const cepPath* signal,
                                      const cepPath* target,
                                      const cepPipelineMetadata* metadata,
                                      cepImpulseQoS qos);

bool cep_l1_fed_prepare_request(cepCell* request_cell,
                                const cepPipelineMetadata* metadata);

bool cep_l1_fed_request_submit(const cepFedInvokeRequest* request,
                               cepCell* request_cell,
                               const cepPipelineMetadata* metadata,
                               const cepFedInvokeSubmission* submission);

bool cep_l1_fed_mount_attach_pipeline(cepFedTransportManagerMount* mount,
                                      const cepPipelineMetadata* metadata);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L1_RUNTIME_H */
