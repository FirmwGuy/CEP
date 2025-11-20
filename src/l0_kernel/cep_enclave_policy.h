#ifndef CEP_ENCLAVE_POLICY_H
#define CEP_ENCLAVE_POLICY_H

#include "cep_cell.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    cepDT     name;
    char      trust_tier[32];
} cepEnclaveDescriptor;

typedef struct {
    uint64_t  bud_cpu_ns;
    uint64_t  bud_io_bytes;
    uint32_t  max_beats;
    uint32_t  mailbox_max_beats;
    uint32_t  episode_max_beats;
    uint32_t  rate_per_subject_qps;
    uint32_t  rate_per_enzyme_qps;
    uint32_t  rate_per_edge_qps;
} cepEnclavePolicyLimits;

typedef struct {
    uint64_t total_cpu_ns;
    uint64_t total_io_bytes;
    uint32_t max_hops;
    uint32_t max_wall_ms;
} cepEnclavePipelineCeilings;

typedef struct cepEnclaveBranchEntry cepEnclaveBranchEntry;

typedef struct {
    cepEnclaveBranchEntry* entries;
    size_t                 count;
} cepEnclaveBranchTable;

typedef struct {
    cepEnclaveDescriptor*      enclaves;
    size_t                     enclave_count;
    cepEnclavePolicyLimits     defaults;
    cepEnclavePipelineCeilings pipeline;
    uint64_t                   version;
    cepEnclaveBranchTable      branches;
} cepEnclavePolicySnapshot;

typedef enum {
    CEP_ENCLAVE_BRANCH_RESULT_SKIP = 0,
    CEP_ENCLAVE_BRANCH_RESULT_ALLOW,
    CEP_ENCLAVE_BRANCH_RESULT_DENY,
    CEP_ENCLAVE_BRANCH_RESULT_ERROR,
} cepEnclaveBranchResult;

typedef struct {
    const char* path_pattern;
    const char* rule_id;
} cepEnclaveBranchDecision;

enum {
    CEP_ENCLAVE_VERB_READ    = 1u << 0,
    CEP_ENCLAVE_VERB_WRITE   = 1u << 1,
    CEP_ENCLAVE_VERB_EXECUTE = 1u << 2,
    CEP_ENCLAVE_VERB_LINK    = 1u << 3,
    CEP_ENCLAVE_VERB_DELETE  = 1u << 4,
};

bool  cep_enclave_policy_init(cepCell* security_root);
bool  cep_enclave_policy_reload(cepCell* security_root);
void  cep_enclave_policy_mark_dirty(void);
void  cep_enclave_policy_mark_dirty_reason(const char* reason, const cepCell* source_cell);
void  cep_enclave_policy_on_capture(void);
void  cep_enclave_policy_trace_stage(const char* stage);
void  cep_enclave_policy_freeze_enter(const char* reason);
void  cep_enclave_policy_freeze_leave(void);
bool  cep_enclave_policy_is_frozen(void);
bool  cep_enclave_policy_ready(void);
const cepEnclavePolicySnapshot* cep_enclave_policy_snapshot(void);
bool  cep_enclave_policy_lookup_enclave(const cepDT* name, cepEnclaveDescriptor* out);
const cepEnclavePolicyLimits* cep_enclave_policy_defaults(void);
const cepEnclavePipelineCeilings* cep_enclave_policy_pipeline(void);
bool  cep_enclave_policy_check_edge(const char* from_enclave,
                                    const char* to_enclave,
                                    const char* gateway_id,
                                    cepEnclavePolicyLimits* resolved_limits,
                                    char* deny_reason,
                                    size_t deny_capacity);
void  cep_enclave_policy_record_edge_denial(const char* from_enclave,
                                            const char* to_enclave,
                                            const char* gateway_id,
                                            const char* subject_id,
                                            const char* reason);
cepEnclaveBranchResult
cep_enclave_policy_check_branch(const char* path_text,
                                cepID subject_pack,
                                uint32_t verb_mask,
                                cepEnclaveBranchDecision* decision,
                                char* deny_reason,
                                size_t deny_capacity);
void
cep_enclave_policy_record_branch_decision(const cepDT* branch_dt,
                                          const char* verb,
                                          const char* subject_id,
                                          const char* path_text,
                                          const cepEnclaveBranchDecision* decision,
                                          bool allowed,
                                          const char* reason);

#endif /* CEP_ENCLAVE_POLICY_H */
