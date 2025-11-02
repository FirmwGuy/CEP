#ifndef CEP_NAMEPOOL_RUNTIME_H
#define CEP_NAMEPOOL_RUNTIME_H

#ifdef __cplusplus
extern "C" {
#endif

struct cepNamePoolRuntimeState;

struct cepNamePoolRuntimeState* cep_namepool_state_create(void);
void cep_namepool_state_destroy(struct cepNamePoolRuntimeState* state);

#ifdef __cplusplus
}
#endif

#endif /* CEP_NAMEPOOL_RUNTIME_H */
