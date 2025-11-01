#ifndef CEP_FED_TRANSPORT_PROVIDERS_H
#define CEP_FED_TRANSPORT_PROVIDERS_H

#include "fed_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

bool cep_fed_transport_register_tcp_provider(void);
bool cep_fed_transport_register_pipe_provider(void);
bool cep_fed_transport_register_mock_provider(void);

void cep_fed_transport_mock_reset(void);
size_t cep_fed_transport_mock_outbound_count(const char* peer_id,
                                             const char* mount_id);
bool cep_fed_transport_mock_pop_outbound(const char* peer_id,
                                         const char* mount_id,
                                         uint8_t* buffer,
                                         size_t buffer_capacity,
                                         size_t* out_len,
                                         cepFedFrameMode* out_mode);
bool cep_fed_transport_mock_enqueue_inbound(const char* peer_id,
                                            const char* mount_id,
                                            const uint8_t* payload,
                                            size_t payload_len,
                                            cepFedFrameMode mode);
bool cep_fed_transport_mock_signal_ready(const char* peer_id,
                                         const char* mount_id);

#ifdef __cplusplus
}
#endif

#endif /* CEP_FED_TRANSPORT_PROVIDERS_H */
