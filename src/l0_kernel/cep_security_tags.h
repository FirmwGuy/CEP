/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_SECURITY_TAGS_H
#define CEP_SECURITY_TAGS_H

#include "cep_cell.h"

CEP_DEFINE_STATIC_DT(dt_security_root_name,    CEP_ACRO("CEP"), CEP_WORD("security"));
CEP_DEFINE_STATIC_DT(dt_sec_enclaves_name,     CEP_ACRO("CEP"), CEP_WORD("enclaves"));
CEP_DEFINE_STATIC_DT(dt_sec_edges_name,        CEP_ACRO("CEP"), CEP_WORD("edges"));
CEP_DEFINE_STATIC_DT(dt_sec_gateways_name,     CEP_ACRO("CEP"), CEP_WORD("gateways"));
CEP_DEFINE_STATIC_DT(dt_sec_branches_name,     CEP_ACRO("CEP"), CEP_WORD("branches"));
CEP_DEFINE_STATIC_DT(dt_sec_defaults_name,     CEP_ACRO("CEP"), CEP_WORD("defaults"));
CEP_DEFINE_STATIC_DT(dt_sec_env_name,          CEP_ACRO("CEP"), CEP_WORD("env"));
CEP_DEFINE_STATIC_DT(dt_sec_branch_enclave_field, CEP_ACRO("CEP"), CEP_WORD("enclave"));
CEP_DEFINE_STATIC_DT(dt_sec_branch_path_field, CEP_ACRO("CEP"), CEP_WORD("path"));
CEP_DEFINE_STATIC_DT(dt_sec_branch_default_field, CEP_ACRO("CEP"), CEP_WORD("default"));
CEP_DEFINE_STATIC_DT(dt_sec_branch_rules_name, CEP_ACRO("CEP"), CEP_WORD("rules"));
CEP_DEFINE_STATIC_DT(dt_sec_rule_decision_field, CEP_ACRO("CEP"), CEP_WORD("decision"));
CEP_DEFINE_STATIC_DT(dt_sec_rule_verbs_name,   CEP_ACRO("CEP"), CEP_WORD("verbs_any"));
CEP_DEFINE_STATIC_DT(dt_sec_rule_subjects_name, CEP_ACRO("CEP"), CEP_WORD("subjects"));
CEP_DEFINE_STATIC_DT(dt_sec_rule_subject_packs_name, CEP_ACRO("CEP"), CEP_WORD("packs_any"));
CEP_DEFINE_STATIC_DT(dt_sec_rule_id_field,     CEP_ACRO("CEP"), CEP_WORD("rule_id"));
CEP_DEFINE_STATIC_DT(dt_sec_env_prod_name,     CEP_ACRO("CEP"), CEP_WORD("prod"));
CEP_DEFINE_STATIC_DT(dt_sec_env_staging_name,  CEP_ACRO("CEP"), CEP_WORD("staging"));
CEP_DEFINE_STATIC_DT(dt_sec_env_dev_name,      CEP_ACRO("CEP"), CEP_WORD("dev"));
CEP_DEFINE_STATIC_DT(dt_sec_tier_field,        CEP_ACRO("CEP"), CEP_WORD("tier"));
CEP_DEFINE_STATIC_DT(dt_sec_trust_field,       CEP_ACRO("CEP"), CEP_WORD("trust"));
CEP_DEFINE_STATIC_DT(dt_sec_limits_name,       CEP_ACRO("CEP"), CEP_WORD("limits"));
CEP_DEFINE_STATIC_DT(dt_sec_budgets_name,      CEP_ACRO("CEP"), CEP_WORD("budgets"));
CEP_DEFINE_STATIC_DT(dt_sec_ttl_name,          CEP_ACRO("CEP"), CEP_WORD("ttl"));
CEP_DEFINE_STATIC_DT(dt_sec_rate_name,         CEP_ACRO("CEP"), CEP_WORD("rate"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_name,     CEP_ACRO("CEP"), CEP_WORD("pipeline"));
CEP_DEFINE_STATIC_DT(dt_sec_total_cpu_name,    CEP_ACRO("CEP"), CEP_WORD("tot_cpu_ns"));
CEP_DEFINE_STATIC_DT(dt_sec_total_io_name,     CEP_ACRO("CEP"), CEP_WORD("total_io_by"));
CEP_DEFINE_STATIC_DT(dt_sec_max_hops_name,     CEP_ACRO("CEP"), CEP_WORD("max_hops"));
CEP_DEFINE_STATIC_DT(dt_sec_max_wall_ms_name,  CEP_ACRO("CEP"), CEP_WORD("max_wall_ms"));
CEP_DEFINE_STATIC_DT(dt_sec_max_beats_name,    CEP_ACRO("CEP"), CEP_WORD("max_beats"));
CEP_DEFINE_STATIC_DT(dt_sec_mailbox_beats_name, CEP_ACRO("CEP"), CEP_WORD("mbox_max_bt"));
CEP_DEFINE_STATIC_DT(dt_sec_episode_beats_name, CEP_ACRO("CEP"), CEP_WORD("ep_max_bt"));
CEP_DEFINE_STATIC_DT(dt_sec_rate_subject_name, CEP_ACRO("CEP"), CEP_WORD("rsub_qps"));
CEP_DEFINE_STATIC_DT(dt_sec_rate_enzyme_name,  CEP_ACRO("CEP"), CEP_WORD("renz_qps"));
CEP_DEFINE_STATIC_DT(dt_sec_rate_edge_name,    CEP_ACRO("CEP"), CEP_WORD("redge_qps"));
CEP_DEFINE_STATIC_DT(dt_sec_bud_cpu_name,      CEP_ACRO("CEP"), CEP_WORD("bud_cpu_ns"));
CEP_DEFINE_STATIC_DT(dt_sec_bud_io_name,       CEP_ACRO("CEP"), CEP_WORD("bud_io_by"));
CEP_DEFINE_STATIC_DT(dt_sec_policy_dir_name,   CEP_ACRO("CEP"), CEP_WORD("policy"));
CEP_DEFINE_STATIC_DT(dt_sec_pipelines_name,    CEP_ACRO("CEP"), CEP_WORD("pipelines"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_id_field, CEP_ACRO("CEP"), CEP_WORD("pipeline_id"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_stages_name, CEP_ACRO("CEP"), CEP_WORD("stages"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_ceilings_name, CEP_ACRO("CEP"), CEP_WORD("ceilings"));
CEP_DEFINE_STATIC_DT(dt_sec_stage_id_field,    CEP_ACRO("CEP"), CEP_WORD("stage_id"));
CEP_DEFINE_STATIC_DT(dt_sec_stage_enclave_field, CEP_ACRO("CEP"), CEP_WORD("stg_encl"));
CEP_DEFINE_STATIC_DT(dt_sec_stage_enzyme_field, CEP_ACRO("CEP"), CEP_WORD("stg_enz"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_approval_name, CEP_ACRO("CEP"), CEP_WORD("approval"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_version_field, CEP_ACRO("CEP"), CEP_WORD("pol_ver"));
CEP_DEFINE_STATIC_DT(dt_sec_pipeline_beat_field, CEP_ACRO("CEP"), CEP_WORD("appr_bt"));
CEP_DEFINE_STATIC_DT(dt_pipeline_envelope_field, CEP_ACRO("CEP"), CEP_WORD("pipeline"));
CEP_DEFINE_STATIC_DT(dt_pipeline_run_field, CEP_ACRO("CEP"), CEP_WORD("dag_run_id"));
CEP_DEFINE_STATIC_DT(dt_pipeline_hop_field, CEP_ACRO("CEP"), CEP_WORD("hop_index"));

#endif /* CEP_SECURITY_TAGS_H */
