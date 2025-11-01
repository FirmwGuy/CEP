#include "fed_transport_providers.h"

#include "../l0_kernel/cep_molecule.h"

#include <string.h>

typedef struct cepFedTransportFrameNode {
    uint8_t* payload;
    size_t   len;
    cepFedFrameMode mode;
    struct cepFedTransportFrameNode* next;
} cepFedTransportFrameNode;

typedef struct cepFedTransportProviderState cepFedTransportProviderState;

struct cepFedTransportChannel {
    cepFedTransportProviderState* provider;
    cepFedTransportFrameNode*     outbound_head;
    cepFedTransportFrameNode*     outbound_tail;
    cepFedTransportFrameNode*     inbound_head;
    cepFedTransportFrameNode*     inbound_tail;
    size_t                        outbound_count;
    size_t                        inbound_count;
    size_t                        outbound_limit;
    bool                          backpressured;
    bool                          closed;
    cepFedTransportCallbacks      callbacks;
    void*                         manager_ctx;
    char*                         peer_id;
    char*                         mount_id;
    char*                         local_node_id;
};

struct cepFedTransportProviderState {
    cepFedTransportProvider descriptor;
    size_t                  queue_limit;
    bool                    registered;
    bool                    is_mock;
    cepFedTransportChannel** channels;
    size_t                  channel_count;
    size_t                  channel_capacity;
};

static cepFedTransportProviderState cep_fed_transport_tcp_state;
static cepFedTransportProviderState cep_fed_transport_pipe_state;
static cepFedTransportProviderState cep_fed_transport_mock_state;

static char* cep_fed_transport_provider_strdup(const char* text) {
    if (!text) {
        return NULL;
    }
    size_t len = strlen(text);
    char* copy = cep_malloc(len + 1u);
    memcpy(copy, text, len + 1u);
    return copy;
}

static void cep_fed_transport_frame_free(cepFedTransportFrameNode* node) {
    while (node) {
        cepFedTransportFrameNode* next = node->next;
        if (node->payload) {
            cep_free(node->payload);
        }
        cep_free(node);
        node = next;
    }
}

static bool cep_fed_transport_provider_add_channel(cepFedTransportProviderState* state,
                                                   cepFedTransportChannel* channel) {
    if (!state || !channel) {
        return false;
    }
    if (state->channel_count == state->channel_capacity) {
        size_t new_capacity = state->channel_capacity ? state->channel_capacity * 2u : 4u;
        size_t bytes = new_capacity * sizeof *state->channels;
        cepFedTransportChannel** grown = state->channels
            ? cep_realloc(state->channels, bytes)
            : cep_malloc0(bytes);
        if (!grown) {
            return false;
        }
        state->channels = grown;
        state->channel_capacity = new_capacity;
    }
    state->channels[state->channel_count++] = channel;
    return true;
}

static void cep_fed_transport_provider_remove_channel(cepFedTransportProviderState* state,
                                                      cepFedTransportChannel* channel) {
    if (!state || !channel || state->channel_count == 0u) {
        return;
    }
    for (size_t i = 0; i < state->channel_count; ++i) {
        if (state->channels[i] == channel) {
            state->channels[i] = state->channels[state->channel_count - 1u];
            state->channels[state->channel_count - 1u] = NULL;
            --state->channel_count;
            break;
        }
    }
}

static cepFedTransportProviderState* cep_fed_transport_state_from_ctx(void* provider_ctx) {
    return (cepFedTransportProviderState*)provider_ctx;
}

static bool cep_fed_transport_provider_open(void* provider_ctx,
                                            const cepFedTransportOpenArgs* args,
                                            const cepFedTransportCallbacks* callbacks,
                                            void* manager_ctx,
                                            cepFedTransportChannel** out_channel) {
    cepFedTransportProviderState* state = cep_fed_transport_state_from_ctx(provider_ctx);
    if (!state || !args || !callbacks || !out_channel) {
        return false;
    }

    cepFedTransportChannel* channel = cep_malloc0(sizeof *channel);
    channel->provider = state;
    channel->callbacks = *callbacks;
    channel->manager_ctx = manager_ctx;
    channel->outbound_limit = state->queue_limit ? state->queue_limit : 8u;
    channel->peer_id = cep_fed_transport_provider_strdup(args->peer_id);
    channel->mount_id = cep_fed_transport_provider_strdup(args->mount_id);
    channel->local_node_id = cep_fed_transport_provider_strdup(args->local_node_id);
    channel->closed = false;

    if ((args->required_caps & state->descriptor.caps) != args->required_caps) {
        cep_fed_transport_frame_free(channel->outbound_head);
        cep_fed_transport_frame_free(channel->inbound_head);
        if (channel->peer_id) {
            cep_free(channel->peer_id);
        }
        if (channel->mount_id) {
            cep_free(channel->mount_id);
        }
        if (channel->local_node_id) {
            cep_free(channel->local_node_id);
        }
        cep_free(channel);
        return false;
    }

    if (!cep_fed_transport_provider_add_channel(state, channel)) {
        if (channel->peer_id) {
            cep_free(channel->peer_id);
        }
        if (channel->mount_id) {
            cep_free(channel->mount_id);
        }
        if (channel->local_node_id) {
            cep_free(channel->local_node_id);
        }
        cep_free(channel);
        return false;
    }

    *out_channel = channel;

    if (channel->callbacks.on_event) {
        channel->callbacks.on_event(channel->manager_ctx,
                                    channel,
                                    CEP_FED_TRANSPORT_EVENT_READY_RX,
                                    "provider-open");
    }
    return true;
}

static bool cep_fed_transport_provider_send(void* provider_ctx,
                                            cepFedTransportChannel* channel,
                                            const uint8_t* payload,
                                            size_t payload_len,
                                            cepFedFrameMode mode,
                                            uint64_t deadline_beat) {
    (void)provider_ctx;
    (void)deadline_beat;
    if (!channel || !payload || payload_len == 0u || channel->closed) {
        return false;
    }

    const cepFedTransportProviderState* state = channel->provider;
    if (state && state->descriptor.max_payload_bytes > 0u && payload_len > state->descriptor.max_payload_bytes) {
        return false;
    }

    if (channel->outbound_limit > 0u && channel->outbound_count >= channel->outbound_limit) {
        channel->backpressured = true;
        if (channel->callbacks.on_event) {
            channel->callbacks.on_event(channel->manager_ctx,
                                        channel,
                                        CEP_FED_TRANSPORT_EVENT_BACKPRESSURE,
                                        "queue-limit");
        }
        return false;
    }

    cepFedTransportFrameNode* node = cep_malloc(sizeof *node);
    node->payload = cep_malloc(payload_len);
    memcpy(node->payload, payload, payload_len);
    node->len = payload_len;
    node->mode = mode;
    node->next = NULL;

    if (channel->outbound_tail) {
        channel->outbound_tail->next = node;
    } else {
        channel->outbound_head = node;
    }
    channel->outbound_tail = node;
    ++channel->outbound_count;
    return true;
}

static bool cep_fed_transport_provider_request_receive(void* provider_ctx,
                                                       cepFedTransportChannel* channel) {
    (void)provider_ctx;
    if (!channel || channel->closed) {
        return false;
    }
    cepFedTransportFrameNode* node = channel->inbound_head;
    if (!node) {
        return false;
    }

    channel->inbound_head = node->next;
    if (!channel->inbound_head) {
        channel->inbound_tail = NULL;
    }
    --channel->inbound_count;

    if (channel->callbacks.on_frame) {
        channel->callbacks.on_frame(channel->manager_ctx,
                                    channel,
                                    node->payload,
                                    node->len,
                                    node->mode);
    }
    cep_free(node->payload);
    cep_free(node);
    return true;
}

static bool cep_fed_transport_provider_close(void* provider_ctx,
                                             cepFedTransportChannel* channel,
                                             const char* reason) {
    (void)reason;
    cepFedTransportProviderState* state = cep_fed_transport_state_from_ctx(provider_ctx);
    if (!state || !channel) {
        return false;
    }
    if (channel->closed) {
        return true;
    }

    channel->closed = true;
    cep_fed_transport_provider_remove_channel(state, channel);
    cep_fed_transport_frame_free(channel->outbound_head);
    cep_fed_transport_frame_free(channel->inbound_head);
    if (channel->peer_id) {
        cep_free(channel->peer_id);
    }
    if (channel->mount_id) {
        cep_free(channel->mount_id);
    }
    if (channel->local_node_id) {
        cep_free(channel->local_node_id);
    }
    cep_free(channel);
    return true;
}

static const cepFedTransportVTable cep_fed_transport_provider_vtable = {
    .open = cep_fed_transport_provider_open,
    .send = cep_fed_transport_provider_send,
    .request_receive = cep_fed_transport_provider_request_receive,
    .close = cep_fed_transport_provider_close,
};

static bool cep_fed_transport_register_provider(cepFedTransportProviderState* state,
                                                const char* provider_id,
                                                cepFedTransportCaps caps,
                                                size_t max_payload,
                                                size_t queue_limit,
                                                bool is_mock) {
    if (!state || !provider_id) {
        return false;
    }
    if (state->registered) {
        return true;
    }
    state->descriptor.provider_id = provider_id;
    state->descriptor.caps = caps;
    state->descriptor.max_payload_bytes = max_payload;
    state->descriptor.vtable = &cep_fed_transport_provider_vtable;
    state->queue_limit = queue_limit;
    state->is_mock = is_mock;
    state->channels = NULL;
    state->channel_count = 0u;
    state->channel_capacity = 0u;

    if (!cep_fed_transport_register(&state->descriptor, state)) {
        return false;
    }
    state->registered = true;
    return true;
}

/* cep_fed_transport_register_tcp_provider installs a deterministic stub TCP provider
   whose capability flags mirror a reliable remote stream so mounts can exercise the
   negotiation path without a real socket implementation. */
bool cep_fed_transport_register_tcp_provider(void) {
    return cep_fed_transport_register_provider(&cep_fed_transport_tcp_state,
                                               "tcp",
                                               CEP_FED_TRANSPORT_CAP_RELIABLE |
                                               CEP_FED_TRANSPORT_CAP_ORDERED |
                                               CEP_FED_TRANSPORT_CAP_STREAMING |
                                               CEP_FED_TRANSPORT_CAP_REMOTE_NET,
                                               65536u,
                                               8u,
                                               false);
}

/* cep_fed_transport_register_pipe_provider registers a local IPC transport stub that
   advertises reliable semantics so mounts preferring shared-memory style transports can
   verify capability scoring. */
bool cep_fed_transport_register_pipe_provider(void) {
    return cep_fed_transport_register_provider(&cep_fed_transport_pipe_state,
                                               "pipe",
                                               CEP_FED_TRANSPORT_CAP_RELIABLE |
                                               CEP_FED_TRANSPORT_CAP_ORDERED |
                                               CEP_FED_TRANSPORT_CAP_LOCAL_IPC,
                                               32768u,
                                               6u,
                                               false);
}

/* cep_fed_transport_register_mock_provider installs an unreliable provider used by
   tests to probe upd_latest coalescing and failure paths without external I/O. */
bool cep_fed_transport_register_mock_provider(void) {
    return cep_fed_transport_register_provider(&cep_fed_transport_mock_state,
                                               "mock",
                                               CEP_FED_TRANSPORT_CAP_ORDERED |
                                               CEP_FED_TRANSPORT_CAP_UNRELIABLE |
                                               CEP_FED_TRANSPORT_CAP_LOCAL_IPC,
                                               16384u,
                                               2u,
                                               true);
}

static cepFedTransportChannel* cep_fed_transport_mock_find(const char* peer_id,
                                                           const char* mount_id) {
    cepFedTransportProviderState* state = &cep_fed_transport_mock_state;
    if (!peer_id || !mount_id || !state->registered) {
        return NULL;
    }
    for (size_t i = 0; i < state->channel_count; ++i) {
        cepFedTransportChannel* channel = state->channels[i];
        if (!channel || channel->closed) {
            continue;
        }
        if (channel->peer_id && channel->mount_id &&
            strcmp(channel->peer_id, peer_id) == 0 &&
            strcmp(channel->mount_id, mount_id) == 0) {
            return channel;
        }
    }
    return NULL;
}

/* cep_fed_transport_mock_reset purges in-memory queues so each test starts with a clean slate. */
void cep_fed_transport_mock_reset(void) {
    cepFedTransportProviderState* state = &cep_fed_transport_mock_state;
    for (size_t i = 0; i < state->channel_count; ++i) {
        cepFedTransportChannel* channel = state->channels[i];
        if (!channel) {
            continue;
        }
        cep_fed_transport_frame_free(channel->outbound_head);
        channel->outbound_head = NULL;
        channel->outbound_tail = NULL;
        channel->outbound_count = 0u;
        channel->backpressured = false;
        cep_fed_transport_frame_free(channel->inbound_head);
        channel->inbound_head = NULL;
        channel->inbound_tail = NULL;
        channel->inbound_count = 0u;
    }
}

size_t cep_fed_transport_mock_outbound_count(const char* peer_id,
                                             const char* mount_id) {
    cepFedTransportChannel* channel = cep_fed_transport_mock_find(peer_id, mount_id);
    return channel ? channel->outbound_count : 0u;
}

bool cep_fed_transport_mock_pop_outbound(const char* peer_id,
                                         const char* mount_id,
                                         uint8_t* buffer,
                                         size_t buffer_capacity,
                                         size_t* out_len,
                                         cepFedFrameMode* out_mode) {
    cepFedTransportChannel* channel = cep_fed_transport_mock_find(peer_id, mount_id);
    if (!channel || !channel->outbound_head) {
        return false;
    }

    cepFedTransportFrameNode* node = channel->outbound_head;
    channel->outbound_head = node->next;
    if (!channel->outbound_head) {
        channel->outbound_tail = NULL;
    }
    --channel->outbound_count;

    if (out_len) {
        *out_len = node->len;
    }
    if (out_mode) {
        *out_mode = node->mode;
    }
    if (buffer && buffer_capacity >= node->len) {
        memcpy(buffer, node->payload, node->len);
    }
    cep_free(node->payload);
    cep_free(node);

    if (channel->backpressured && channel->outbound_count < channel->outbound_limit) {
        channel->backpressured = false;
        if (channel->callbacks.on_event) {
            channel->callbacks.on_event(channel->manager_ctx,
                                        channel,
                                        CEP_FED_TRANSPORT_EVENT_READY_RX,
                                        "mock-pump");
        }
    }
    return true;
}

bool cep_fed_transport_mock_enqueue_inbound(const char* peer_id,
                                            const char* mount_id,
                                            const uint8_t* payload,
                                            size_t payload_len,
                                            cepFedFrameMode mode) {
    cepFedTransportChannel* channel = cep_fed_transport_mock_find(peer_id, mount_id);
    if (!channel || !payload || payload_len == 0u) {
        return false;
    }

    cepFedTransportFrameNode* node = cep_malloc(sizeof *node);
    node->payload = cep_malloc(payload_len);
    memcpy(node->payload, payload, payload_len);
    node->len = payload_len;
    node->mode = mode;
    node->next = NULL;

    if (channel->inbound_tail) {
        channel->inbound_tail->next = node;
    } else {
        channel->inbound_head = node;
    }
    channel->inbound_tail = node;
    ++channel->inbound_count;

    if (channel->callbacks.on_event) {
        channel->callbacks.on_event(channel->manager_ctx,
                                    channel,
                                    CEP_FED_TRANSPORT_EVENT_READY_RX,
                                    "mock-inbound");
    }
    return true;
}

bool cep_fed_transport_mock_signal_ready(const char* peer_id,
                                         const char* mount_id) {
    cepFedTransportChannel* channel = cep_fed_transport_mock_find(peer_id, mount_id);
    if (!channel) {
        return false;
    }
    channel->backpressured = false;
    if (channel->callbacks.on_event) {
        channel->callbacks.on_event(channel->manager_ctx,
                                    channel,
                                    CEP_FED_TRANSPORT_EVENT_READY_RX,
                                    "mock-ready");
    }
    return true;
}
