#include "cep_serialization.h"
#include "cep_cell.h"

#include <string.h>

static inline uint16_t cep_serial_to_be16(uint16_t value) {
    return __builtin_bswap16(value);
}

static inline uint32_t cep_serial_to_be32(uint32_t value) {
    return __builtin_bswap32(value);
}

static inline uint64_t cep_serial_to_be64(uint64_t value) {
    return __builtin_bswap64(value);
}

static inline uint16_t cep_serial_from_be16(uint16_t value) {
    return __builtin_bswap16(value);
}

static inline uint32_t cep_serial_from_be32(uint32_t value) {
    return __builtin_bswap32(value);
}

static inline uint64_t cep_serial_from_be64(uint64_t value) {
    return __builtin_bswap64(value);
}

static size_t cep_serialization_header_payload_size(const cepSerializationHeader* header) {
    assert(header);
    return CEP_SERIALIZATION_HEADER_BASE + (size_t) header->metadata_length;
}

size_t cep_serialization_header_chunk_size(const cepSerializationHeader* header) {
    /* Report the total number of bytes required for the control header chunk so callers can size buffers before attempting to encode it. */
    if (!header)
        return 0;

    size_t payload = cep_serialization_header_payload_size(header);
    if (payload > SIZE_MAX - CEP_SERIALIZATION_CHUNK_OVERHEAD)
        return 0;

    return payload + CEP_SERIALIZATION_CHUNK_OVERHEAD;
}

bool cep_serialization_header_write(const cepSerializationHeader* header,
                                    uint8_t* dst,
                                    size_t capacity,
                                    size_t* out_size) {
    /* Emit a self-identifying control chunk that plants the CEP magic, format version, and negotiated options at the start of a stream so readers can validate or resynchronize before processing the rest of the payload. */
    if (!header || !dst)
        return false;

    if (header->metadata_length && !header->metadata)
        return false;

    uint16_t version = header->version ? header->version : CEP_SERIALIZATION_VERSION;
    uint8_t order = header->byte_order;
    if (order != CEP_SERIAL_ENDIAN_BIG && order != CEP_SERIAL_ENDIAN_LITTLE)
        return false;

    size_t payload = cep_serialization_header_payload_size(header);
    size_t required = payload + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    if (capacity < required)
        return false;

    uint64_t chunk_id = cep_serialization_chunk_id(CEP_CHUNK_CLASS_CONTROL, 0u, 0u);

    uint8_t* p = dst;
    uint64_t size_be = cep_serial_to_be64((uint64_t) payload);
    memcpy(p, &size_be, sizeof size_be);
    p += sizeof size_be;

    uint64_t id_be = cep_serial_to_be64(chunk_id);
    memcpy(p, &id_be, sizeof id_be);
    p += sizeof id_be;

    uint64_t magic = header->magic ? header->magic : CEP_SERIALIZATION_MAGIC;
    uint64_t magic_be = cep_serial_to_be64(magic);
    memcpy(p, &magic_be, sizeof magic_be);
    p += sizeof magic_be;

    uint16_t version_be = cep_serial_to_be16(version);
    memcpy(p, &version_be, sizeof version_be);
    p += sizeof version_be;

    *p++ = order;
    *p++ = header->flags;

    uint32_t metadata_len_be = cep_serial_to_be32(header->metadata_length);
    memcpy(p, &metadata_len_be, sizeof metadata_len_be);
    p += sizeof metadata_len_be;

    if (header->metadata_length) {
        memcpy(p, header->metadata, header->metadata_length);
        p += header->metadata_length;
    }

    if (out_size)
        *out_size = required;

    return true;
}

bool cep_serialization_header_read(const uint8_t* chunk,
                                   size_t chunk_size,
                                   cepSerializationHeader* header) {
    /* Parse the control chunk at the head of a stream so tools can confirm the magic, inspect the format version, and pull option metadata without guessing the layout. */
    if (!chunk || !header)
        return false;

    if (chunk_size < CEP_SERIALIZATION_CHUNK_OVERHEAD + CEP_SERIALIZATION_HEADER_BASE)
        return false;

    const uint8_t* p = chunk;
    uint64_t payload_be = 0;
    memcpy(&payload_be, p, sizeof payload_be);
    p += sizeof payload_be;
    size_t payload = (size_t) cep_serial_from_be64(payload_be);

    if (payload + CEP_SERIALIZATION_CHUNK_OVERHEAD != chunk_size)
        return false;

    uint64_t id_be = 0;
    memcpy(&id_be, p, sizeof id_be);
    p += sizeof id_be;
    uint64_t chunk_id = cep_serial_from_be64(id_be);

    if (cep_serialization_chunk_class(chunk_id) != CEP_CHUNK_CLASS_CONTROL ||
        cep_serialization_chunk_transaction(chunk_id) != 0u ||
        cep_serialization_chunk_sequence(chunk_id) != 0u)
        return false;

    uint64_t magic_be = 0;
    memcpy(&magic_be, p, sizeof magic_be);
    p += sizeof magic_be;
    uint64_t magic = cep_serial_from_be64(magic_be);
    if (magic != CEP_SERIALIZATION_MAGIC)
        return false;

    uint16_t version_be = 0;
    memcpy(&version_be, p, sizeof version_be);
    p += sizeof version_be;
    uint16_t version = cep_serial_from_be16(version_be);

    uint8_t byte_order = *p++;
    uint8_t flags = *p++;

    if (byte_order != CEP_SERIAL_ENDIAN_BIG && byte_order != CEP_SERIAL_ENDIAN_LITTLE)
        return false;

    uint32_t metadata_len_be = 0;
    memcpy(&metadata_len_be, p, sizeof metadata_len_be);
    p += sizeof metadata_len_be;
    uint32_t metadata_len = cep_serial_from_be32(metadata_len_be);

    if ((size_t)metadata_len > payload - CEP_SERIALIZATION_HEADER_BASE)
        return false;
    if ((size_t)metadata_len > chunk_size - (size_t)(p - chunk))
        return false;

    const uint8_t* metadata = metadata_len ? p : NULL;

    header->magic = magic;
    header->version = version;
    header->byte_order = byte_order;
    header->flags = flags;
    header->metadata_length = metadata_len;
    header->metadata = metadata;

    return true;
}

typedef struct {
    cepSerializationWriteFn write;
    void*                  context;
    uint32_t               transaction;
    uint16_t               sequence;
    size_t                 blob_limit;
} cepSerializationEmitter;

static inline void cep_serialization_emitter_reset(cepSerializationEmitter* emitter, uint32_t transaction) {
    assert(emitter);
    emitter->transaction = transaction;
    emitter->sequence = 0;
}

static inline bool cep_serialization_emitter_emit(cepSerializationEmitter* emitter,
                                                  uint16_t chunk_class,
                                                  const uint8_t* payload,
                                                  size_t payload_size) {
    assert(emitter && emitter->write);
    if (payload_size && !payload)
        return false;

    if (payload_size > UINT64_MAX - CEP_SERIALIZATION_CHUNK_OVERHEAD)
        return false;

    if (emitter->sequence == UINT16_MAX) {
        emitter->transaction++;
        emitter->sequence = 0;
    }

    emitter->sequence++;

    size_t total = payload_size + CEP_SERIALIZATION_CHUNK_OVERHEAD;
    uint8_t* buffer = cep_malloc(total);

    uint64_t size_be = cep_serial_to_be64((uint64_t)payload_size);
    memcpy(buffer, &size_be, sizeof size_be);

    uint64_t chunk_id = cep_serialization_chunk_id(chunk_class, emitter->transaction, emitter->sequence);
    uint64_t id_be = cep_serial_to_be64(chunk_id);
    memcpy(buffer + sizeof size_be, &id_be, sizeof id_be);

    if (payload_size)
        memcpy(buffer + CEP_SERIALIZATION_CHUNK_OVERHEAD, payload, payload_size);

    bool ok = emitter->write(emitter->context, buffer, total);
    cep_free(buffer);
    return ok;
}

static bool cep_serialization_emit_manifest(cepSerializationEmitter* emitter,
                                            const cepCell* cell,
                                            const cepPath* path) {
    assert(emitter && cell && path);

    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical)
        return false;

    uint16_t segments = (uint16_t)path->length;
    if ((unsigned)path->length > UINT16_MAX)
        return false;

    size_t payload_size = sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t)
                        + (size_t)segments * (sizeof(uint64_t) * 2u);
    uint8_t* payload = cep_malloc(payload_size);
    uint8_t* p = payload;

    uint16_t count_be = cep_serial_to_be16(segments);
    memcpy(p, &count_be, sizeof count_be);
    p += sizeof count_be;

    *p++ = (uint8_t)canonical->metacell.type;

    uint8_t flags = 0;
    if (canonical->metacell.hidden)
        flags |= 0x01u;
    flags |= (uint8_t)((canonical->metacell.shadowing & 0x03u) << 1);
    if (cep_cell_is_normal(canonical) && canonical->data)
        flags |= 0x08u;
    if (cep_cell_is_normal(canonical) && canonical->store && canonical->store->chdCount)
        flags |= 0x10u;
    if (cep_cell_is_proxy(canonical))
        flags |= 0x20u;
    *p++ = flags;

    uint16_t reserved = 0;
    memcpy(p, &reserved, sizeof reserved);
    p += sizeof reserved;

    for (unsigned i = 0; i < path->length; ++i) {
        const cepPast* segment = &path->past[i];
        uint64_t domain_be = cep_serial_to_be64(segment->dt.domain);
        memcpy(p, &domain_be, sizeof domain_be);
        p += sizeof domain_be;
        uint64_t tag_be = cep_serial_to_be64(segment->dt.tag);
        memcpy(p, &tag_be, sizeof tag_be);
        p += sizeof tag_be;
    }

    bool ok = cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_STRUCTURE, payload, payload_size);
    cep_free(payload);
    return ok;
}

static bool cep_serialization_emit_data(cepSerializationEmitter* emitter,
                                        const cepCell* cell) {
    assert(emitter && cell);

    cepCell* canonical = cep_link_pull((cepCell*)cell);
    if (!canonical)
        return false;

    if (cep_cell_is_proxy(canonical)) {
        cepProxySnapshot snapshot;
        if (!cep_proxy_snapshot(canonical, &snapshot))
            return false;

        size_t payload_size = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t);
        if (snapshot.size) {
            if (!snapshot.payload) {
                cep_proxy_release_snapshot(canonical, &snapshot);
                return false;
            }
            if (payload_size > SIZE_MAX - snapshot.size) {
                cep_proxy_release_snapshot(canonical, &snapshot);
                return false;
            }
            payload_size += snapshot.size;
        }

        uint8_t* payload = cep_malloc(payload_size);
        uint8_t* p = payload;

        uint32_t flags_be = cep_serial_to_be32(snapshot.flags);
        memcpy(p, &flags_be, sizeof flags_be);
        p += sizeof flags_be;

        uint32_t reserved = 0;
        uint32_t reserved_be = cep_serial_to_be32(reserved);
        memcpy(p, &reserved_be, sizeof reserved_be);
        p += sizeof reserved_be;

        uint64_t size_be = cep_serial_to_be64((uint64_t)snapshot.size);
        memcpy(p, &size_be, sizeof size_be);
        p += sizeof size_be;

        if (snapshot.size)
            memcpy(p, snapshot.payload, snapshot.size);

        bool ok = cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_LIBRARY, payload, payload_size);
        cep_free(payload);
        cep_proxy_release_snapshot(canonical, &snapshot);
        return ok;
    }

    if (!cep_cell_is_normal(canonical))
        return false;

    cepData* data = canonical->data;
    if (!data)
        return true;

    if (data->datatype != CEP_DATATYPE_VALUE && data->datatype != CEP_DATATYPE_DATA)
        return false;

    size_t blob_limit = emitter->blob_limit ? emitter->blob_limit : CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD;
    if (blob_limit < 16u)
        blob_limit = 16u;

    size_t total_size = data->size;
    const uint8_t* bytes = (const uint8_t*)cep_data_payload(data);
    if (total_size && !bytes)
        return false;

    bool chunked = total_size > blob_limit;

    size_t header_payload = sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t)
                           + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t);
    size_t inline_size = chunked ? 0u : total_size;
    if (!chunked)
        header_payload += inline_size;

    if (header_payload > SIZE_MAX - CEP_SERIALIZATION_CHUNK_OVERHEAD)
        return false;

    uint8_t* payload = cep_malloc(header_payload);
    uint8_t* p = payload;

    uint16_t datatype_be = cep_serial_to_be16((uint16_t)data->datatype);
    memcpy(p, &datatype_be, sizeof datatype_be);
    p += sizeof datatype_be;

    uint16_t flags = chunked ? UINT16_C(0x0001) : UINT16_C(0x0000);
    uint16_t flags_be = cep_serial_to_be16(flags);
    memcpy(p, &flags_be, sizeof flags_be);
    p += sizeof flags_be;

    uint32_t inline_be = cep_serial_to_be32((uint32_t)(inline_size & UINT32_C(0xFFFFFFFF)));
    memcpy(p, &inline_be, sizeof inline_be);
    p += sizeof inline_be;

    uint64_t total_be = cep_serial_to_be64((uint64_t)total_size);
    memcpy(p, &total_be, sizeof total_be);
    p += sizeof total_be;

    uint64_t hash_be = cep_serial_to_be64(data->hash);
    memcpy(p, &hash_be, sizeof hash_be);
    p += sizeof hash_be;

    uint64_t dt_domain_be = cep_serial_to_be64(data->_dt.domain);
    memcpy(p, &dt_domain_be, sizeof dt_domain_be);
    p += sizeof dt_domain_be;

    uint64_t dt_tag_be = cep_serial_to_be64(data->_dt.tag);
    memcpy(p, &dt_tag_be, sizeof dt_tag_be);
    p += sizeof dt_tag_be;

    if (!chunked && inline_size) {
        memcpy(p, bytes, inline_size);
        p += inline_size;
    }

    if (!cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_STRUCTURE, payload, header_payload)) {
        cep_free(payload);
        return false;
    }
    cep_free(payload);

    if (!chunked || !total_size)
        return true;

    uint64_t offset = 0;
    size_t remaining = total_size;
    while (remaining) {
        size_t slice = remaining < blob_limit ? remaining : blob_limit;
        size_t blob_payload = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + slice;
        uint8_t* blob = cep_malloc(blob_payload);
        uint8_t* bp = blob;

        uint64_t offset_be = cep_serial_to_be64(offset);
        memcpy(bp, &offset_be, sizeof offset_be);
        bp += sizeof offset_be;

        uint32_t length_be = cep_serial_to_be32((uint32_t)(slice & UINT32_C(0xFFFFFFFF)));
        memcpy(bp, &length_be, sizeof length_be);
        bp += sizeof length_be;

        uint32_t reserved = 0;
        memcpy(bp, &reserved, sizeof reserved);
        bp += sizeof reserved;

        memcpy(bp, bytes + offset, slice);

        if (!cep_serialization_emitter_emit(emitter, CEP_CHUNK_CLASS_BLOB, blob, blob_payload)) {
            cep_free(blob);
            return false;
        }

        cep_free(blob);
        offset += (uint64_t)slice;
        remaining -= slice;
    }

    return true;
}

/* Serialise a single cell into the chunked wire format described in
   SERIALIZATION-AND-STREAMS.md. The function emits the mandatory header chunk,
   a manifest that captures the cell's path and metadata, and either an inline or
   chunked data descriptor depending on payload size. Callers supply a sink that
   receives fully framed chunks, letting them forward bytes to files, sockets, or
   higher-level transports without exposing the traversal mechanics. */
bool cep_serialization_emit_cell(const cepCell* cell,
                                 const cepSerializationHeader* header,
                                 cepSerializationWriteFn write,
                                 void* context,
                                 size_t blob_payload_bytes) {
    if (!cell || !write)
        return false;

    cepSerializationHeader local = header ? *header : (cepSerializationHeader){0};
    if (!local.magic)
        local.magic = CEP_SERIALIZATION_MAGIC;
    if (!local.version)
        local.version = CEP_SERIALIZATION_VERSION;
    if (!local.byte_order)
        local.byte_order = CEP_SERIAL_ENDIAN_BIG;

    size_t header_size = cep_serialization_header_chunk_size(&local);
    if (!header_size)
        return false;

    uint8_t* header_chunk = cep_malloc(header_size);
    size_t written = 0;
    if (!cep_serialization_header_write(&local, header_chunk, header_size, &written)) {
        cep_free(header_chunk);
        return false;
    }

    bool ok = write(context, header_chunk, written);
    cep_free(header_chunk);
    if (!ok)
        return false;

    cepSerializationEmitter emitter = {
        .write = write,
        .context = context,
        .blob_limit = blob_payload_bytes ? blob_payload_bytes : CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD,
    };
    cep_serialization_emitter_reset(&emitter, 1u);

    cepPath* path = NULL;
    bool success = false;

    if (!cep_cell_path(cell, &path))
        goto cleanup;

    if (!cep_serialization_emit_manifest(&emitter, cell, path))
        goto cleanup;

    if (!cep_serialization_emit_data(&emitter, cell))
        goto cleanup;

    if (!cep_serialization_emitter_emit(&emitter, CEP_CHUNK_CLASS_CONTROL, NULL, 0u))
        goto cleanup;

    success = true;

cleanup:
    if (path)
        cep_free(path);
    return success;
}


typedef struct {
    bool        needed;
    bool        header_received;
    bool        chunked;
    bool        complete;
    uint16_t    datatype;
    uint16_t    flags;
    cepDT       dt;
    uint64_t    total_size;
    uint64_t    hash;
    uint8_t*    buffer;
    size_t      size;
    uint64_t    next_offset;
} cepSerializationStageData;

typedef struct {
    bool        needed;
    bool        complete;
    uint32_t    flags;
    uint8_t*    buffer;
    size_t      size;
} cepSerializationStageProxy;

typedef struct {
    cepPath*                     path;
    uint8_t                      cell_type;
    uint8_t                      manifest_flags;
    uint32_t                     transaction;
    cepSerializationStageData    data;
    cepSerializationStageProxy   proxy;
} cepSerializationStage;

typedef struct {
    uint32_t                 id;
    uint16_t                 last_sequence;
    bool                     active;
    cepSerializationStage*   pending_stage;
} cepSerializationTxState;

struct cepSerializationReader {
    cepCell*                    root;
    bool                        header_seen;
    bool                        pending_commit;
    bool                        error;
    cepSerializationHeader      header;

    cepSerializationTxState*    transactions;
    size_t                      transaction_count;
    size_t                      transaction_capacity;

    cepSerializationStage*      stages;
    size_t                      stage_count;
    size_t                      stage_capacity;
};

static uint16_t cep_serial_read_be16_buf(const uint8_t* src) {
    uint16_t temp;
    memcpy(&temp, src, sizeof temp);
    return cep_serial_from_be16(temp);
}

static uint32_t cep_serial_read_be32_buf(const uint8_t* src) {
    uint32_t temp;
    memcpy(&temp, src, sizeof temp);
    return cep_serial_from_be32(temp);
}

static uint64_t cep_serial_read_be64_buf(const uint8_t* src) {
    uint64_t temp;
    memcpy(&temp, src, sizeof temp);
    return cep_serial_from_be64(temp);
}

static void cep_serialization_stage_data_dispose(cepSerializationStageData* data) {
    if (!data)
        return;

    if (data->buffer) {
        cep_free(data->buffer);
        data->buffer = NULL;
    }

    memset(data, 0, sizeof(*data));
}

static void cep_serialization_stage_proxy_dispose(cepSerializationStageProxy* proxy) {
    if (!proxy)
        return;

    if (proxy->buffer) {
        cep_free(proxy->buffer);
        proxy->buffer = NULL;
    }

    memset(proxy, 0, sizeof(*proxy));
}

static void cep_serialization_stage_dispose(cepSerializationStage* stage) {
    if (!stage)
        return;

    if (stage->path) {
        cep_free(stage->path);
        stage->path = NULL;
    }

    cep_serialization_stage_data_dispose(&stage->data);
    cep_serialization_stage_proxy_dispose(&stage->proxy);
    memset(stage, 0, sizeof(*stage));
}

static void cep_serialization_reader_clear_transactions(cepSerializationReader* reader) {
    if (!reader)
        return;

    if (reader->transactions) {
        memset(reader->transactions, 0, reader->transaction_capacity * sizeof(*reader->transactions));
    }
    reader->transaction_count = 0;
}

static void cep_serialization_reader_clear_stages(cepSerializationReader* reader) {
    if (!reader)
        return;

    if (reader->stages) {
        for (size_t i = 0; i < reader->stage_count; ++i)
            cep_serialization_stage_dispose(&reader->stages[i]);
    }
    reader->stage_count = 0;
}

static void cep_serialization_reader_init(cepSerializationReader* reader, cepCell* root) {
    assert(reader);
    memset(reader, 0, sizeof(*reader));
    reader->root = root ? cep_link_pull(root) : NULL;
}

cepSerializationReader* cep_serialization_reader_create(cepCell* root) {
    cepSerializationReader* reader = cep_malloc0(sizeof *reader);
    if (!reader)
        return NULL;
    cep_serialization_reader_init(reader, root);
    return reader;
}

void cep_serialization_reader_destroy(cepSerializationReader* reader) {
    if (!reader)
        return;

    cep_serialization_reader_reset(reader);

    if (reader->transactions) {
        cep_free(reader->transactions);
        reader->transactions = NULL;
        reader->transaction_capacity = 0;
    }

    if (reader->stages) {
        cep_free(reader->stages);
        reader->stages = NULL;
        reader->stage_capacity = 0;
    }

    cep_free(reader);
}


void cep_serialization_reader_reset(cepSerializationReader* reader) {
    if (!reader)
        return;

    cep_serialization_reader_clear_stages(reader);
    cep_serialization_reader_clear_transactions(reader);

    reader->header_seen = false;
    reader->pending_commit = false;
    reader->error = false;
    memset(&reader->header, 0, sizeof(reader->header));
}

static bool cep_serialization_reader_ensure_stage_capacity(cepSerializationReader* reader, size_t needed) {
    if (reader->stage_capacity >= needed)
        return true;

    size_t capacity = reader->stage_capacity ? reader->stage_capacity : 4u;
    while (capacity < needed && capacity < (SIZE_MAX >> 1))
        capacity <<= 1u;
    if (capacity < needed)
        capacity = needed;

    size_t bytes = capacity * sizeof(*reader->stages);
    cepSerializationStage* stages = reader->stages ? cep_realloc(reader->stages, bytes) : cep_malloc(bytes);
    if (!stages)
        return false;

    if (capacity > reader->stage_capacity) {
        size_t old_bytes = reader->stage_capacity * sizeof(*reader->stages);
        memset((uint8_t*)stages + old_bytes, 0, bytes - old_bytes);
    }

    reader->stages = stages;
    reader->stage_capacity = capacity;
    return true;
}

static bool cep_serialization_reader_ensure_tx_capacity(cepSerializationReader* reader, size_t needed) {
    if (reader->transaction_capacity >= needed)
        return true;

    size_t capacity = reader->transaction_capacity ? reader->transaction_capacity : 4u;
    while (capacity < needed && capacity < (SIZE_MAX >> 1))
        capacity <<= 1u;
    if (capacity < needed)
        capacity = needed;

    size_t bytes = capacity * sizeof(*reader->transactions);
    cepSerializationTxState* txs = reader->transactions ? cep_realloc(reader->transactions, bytes) : cep_malloc(bytes);
    if (!txs)
        return false;

    if (capacity > reader->transaction_capacity) {
        size_t old_bytes = reader->transaction_capacity * sizeof(*reader->transactions);
        memset((uint8_t*)txs + old_bytes, 0, bytes - old_bytes);
    }

    reader->transactions = txs;
    reader->transaction_capacity = capacity;
    return true;
}

static cepSerializationTxState* cep_serialization_reader_find_tx(cepSerializationReader* reader, uint32_t id) {
    for (size_t i = 0; i < reader->transaction_count; ++i) {
        if (reader->transactions[i].id == id)
            return &reader->transactions[i];
    }
    return NULL;
}

static cepSerializationTxState* cep_serialization_reader_get_tx(cepSerializationReader* reader, uint32_t id) {
    cepSerializationTxState* state = cep_serialization_reader_find_tx(reader, id);
    if (state)
        return state;

    if (!cep_serialization_reader_ensure_tx_capacity(reader, reader->transaction_count + 1u))
        return NULL;

    state = &reader->transactions[reader->transaction_count++];
    memset(state, 0, sizeof(*state));
    state->id = id;
    state->active = true;
    state->last_sequence = 0;
    state->pending_stage = NULL;
    return state;
}

static bool cep_serialization_reader_record_manifest(cepSerializationReader* reader,
                                                     cepSerializationTxState* tx,
                                                     uint32_t transaction,
                                                     const uint8_t* payload,
                                                     size_t payload_size) {
    if (payload_size < 6u)
        return false;

    uint16_t segments = cep_serial_read_be16_buf(payload);
    uint8_t cell_type = payload[2];
    uint8_t manifest_flags = payload[3];
    uint16_t reserved = cep_serial_read_be16_buf(payload + 4);
    (void)reserved;

    size_t expected_bytes = (size_t)segments * (sizeof(uint64_t) * 2u);
    if ((size_t)6u + expected_bytes > payload_size)
        return false;

    if (!segments)
        return false;

    if (!cep_serialization_reader_ensure_stage_capacity(reader, reader->stage_count + 1u))
        return false;

    cepSerializationStage* stage = &reader->stages[reader->stage_count++];
    memset(stage, 0, sizeof(*stage));
    stage->cell_type = cell_type;
    stage->manifest_flags = manifest_flags;
    stage->transaction = transaction;

    size_t path_bytes = sizeof(cepPath) + (size_t)segments * sizeof(cepPast);
    cepPath* path = cep_malloc(path_bytes);
    if (!path)
        return false;
    path->length = segments;
    path->capacity = segments;

    const uint8_t* cursor = payload + 6u;
    for (uint16_t i = 0; i < segments; ++i) {
        cepPast* segment = &path->past[i];
        segment->dt.domain = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        segment->dt.tag = cep_serial_read_be64_buf(cursor);
        cursor += sizeof(uint64_t);
        segment->timestamp = 0;
    }
    stage->path = path;

    bool wants_data = (manifest_flags & 0x08u) != 0u;
    bool wants_proxy = (manifest_flags & 0x20u) != 0u;
    if (wants_data && wants_proxy)
        return false;

    stage->proxy.needed = wants_proxy;
    stage->proxy.complete = !wants_proxy;
    stage->proxy.flags = 0;
    stage->proxy.buffer = NULL;
    stage->proxy.size = 0;

    if (wants_data) {
        stage->data.needed = true;
        stage->data.dt.domain = 0;
        stage->data.dt.tag = 0;
        stage->data.total_size = 0;
        stage->data.hash = 0;
        stage->data.buffer = NULL;
        stage->data.size = 0;
        stage->data.next_offset = 0;
        stage->data.header_received = false;
        stage->data.chunked = false;
        stage->data.complete = false;
        tx->pending_stage = stage;
    } else {
        stage->data.needed = false;
        stage->data.complete = true;
        if (wants_proxy)
            tx->pending_stage = stage;
        else
            tx->pending_stage = NULL;
    }

    return true;
}

static bool cep_serialization_stage_allocate_buffer(cepSerializationStageData* data, size_t size) {
    if (!data)
        return false;

    if (!size) {
        data->buffer = NULL;
        data->size = 0;
        data->next_offset = 0;
        return true;
    }

    data->buffer = cep_malloc(size);
    if (!data->buffer)
        return false;

    data->size = 0;
    data->next_offset = 0;
    return true;
}

static bool cep_serialization_reader_record_data_header(cepSerializationStageData* data,
                                                        const uint8_t* payload,
                                                        size_t payload_size,
                                                        const uint8_t* inline_bytes,
                                                        size_t inline_size) {
    if (!data || !payload)
        return false;

    if (payload_size < (sizeof(uint16_t) * 2u) + sizeof(uint32_t) + (sizeof(uint64_t) * 4u))
        return false;

    data->datatype = cep_serial_read_be16_buf(payload);
    data->flags = cep_serial_read_be16_buf(payload + 2u);
    data->chunked = (data->flags & UINT16_C(0x0001)) != 0;
    uint32_t inline_len = cep_serial_read_be32_buf(payload + 4u);
    data->total_size = cep_serial_read_be64_buf(payload + 8u);
    data->hash = cep_serial_read_be64_buf(payload + 16u);
    data->dt.domain = cep_serial_read_be64_buf(payload + 24u);
    data->dt.tag = cep_serial_read_be64_buf(payload + 32u);

    size_t header_bytes = (sizeof(uint16_t) * 2u) + sizeof(uint32_t) + (sizeof(uint64_t) * 4u);
    size_t expected_inline = payload_size - header_bytes;

    if (!data->chunked) {
        if ((size_t)inline_len != inline_size || inline_size != expected_inline)
            return false;
        if ((uint64_t)inline_size != data->total_size)
            return false;
        if (!cep_serialization_stage_allocate_buffer(data, inline_size ? inline_size : 1u))
            return false;
        if (inline_size)
            memcpy(data->buffer, inline_bytes, inline_size);
        data->size = inline_size;
        data->complete = true;
    } else {
        if (inline_len != 0u || expected_inline != 0u)
            return false;
        if (!cep_serialization_stage_allocate_buffer(data, (size_t)data->total_size))
            return false;
        data->complete = (data->total_size == 0u);
    }

    data->header_received = true;
    return true;
}

static bool cep_serialization_reader_record_data_chunk(cepSerializationStageData* data,
                                                       const uint8_t* payload,
                                                       size_t payload_size) {
    if (!data || !payload)
        return false;
    if (!data->header_received || !data->chunked)
        return false;

    if (payload_size < sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t))
        return false;

    uint64_t offset = cep_serial_read_be64_buf(payload);
    uint32_t length = cep_serial_read_be32_buf(payload + sizeof(uint64_t));
    (void)cep_serial_read_be32_buf(payload + sizeof(uint64_t) + sizeof(uint32_t));

    size_t slice = (size_t)length;
    size_t expected = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + slice;
    if (expected != payload_size)
        return false;

    if (offset != data->next_offset)
        return false;

    if (slice && data->buffer)
        memcpy(data->buffer + data->next_offset, payload + expected - slice, slice);

    data->next_offset += slice;
    data->size += slice;

    if (data->next_offset == data->total_size)
        data->complete = true;

    return true;
}

static bool cep_serialization_reader_check_hash(const cepSerializationStageData* data) {
    if (!data)
        return false;
    if (!data->hash)
        return true;
    if (data->total_size && !data->buffer)
        return false;

    uint64_t computed = cep_hash_bytes(data->buffer, (size_t)data->total_size);
    return computed == data->hash;
}

static bool cep_serialization_reader_apply_stage(const cepSerializationReader* reader,
                                                 cepSerializationStage* stage) {
    if (!reader || !stage || !reader->root)
        return false;

    cepCell* current = reader->root;
    for (unsigned idx = 0; idx < stage->path->length; ++idx) {
        const cepPast* segment = &stage->path->past[idx];
        cepDT name = {.domain = segment->dt.domain, .tag = segment->dt.tag};
        cepCell* child = cep_cell_find_by_name(current, &name);
        if (!child) {
            bool final_segment = (idx + 1u == stage->path->length);
            if (final_segment && stage->cell_type == CEP_TYPE_PROXY)
                return false;

            if (!final_segment) {
                child = cep_cell_add_dictionary(current,
                                                &name,
                                                0,
                                                CEP_DTAW("CEP", "dictionary"),
                                                CEP_STORAGE_RED_BLACK_T);
            } else {
                child = cep_cell_add_empty(current, &name, 0);
            }
        }
        if (!child)
            return false;
        current = cep_link_pull(child);
    }

    if (!current)
        return false;

    if ((uint8_t)current->metacell.type != stage->cell_type)
        return false;

    current->metacell.hidden = (stage->manifest_flags & 0x01u) ? 1u : 0u;

    if (stage->data.needed) {
        if (!stage->data.complete)
            return false;
        if (!cep_serialization_reader_check_hash(&stage->data))
            return false;

        if (current->data) {
            cep_data_del(current->data);
            current->data = NULL;
        }

        size_t size = (size_t)stage->data.total_size;
        size_t capacity = size ? size : 1u;
        cepData* payload = NULL;
        if (stage->data.datatype == CEP_DATATYPE_VALUE) {
            payload = cep_data_new(&stage->data.dt,
                                   CEP_DATATYPE_VALUE,
                                   true,
                                   NULL,
                                   stage->data.buffer,
                                   size,
                                   capacity);
            if (!payload)
                return false;
        } else if (stage->data.datatype == CEP_DATATYPE_DATA) {
            uint8_t* owned = NULL;
            if (size) {
                owned = cep_malloc(size);
                memcpy(owned, stage->data.buffer, size);
            }
            payload = cep_data_new(&stage->data.dt,
                                   CEP_DATATYPE_DATA,
                                   true,
                                   NULL,
                                   owned,
                                   size,
                                   capacity,
                                   size ? cep_free : NULL);
            if (!payload) {
                if (owned)
                    cep_free(owned);
                return false;
            }
            stage->data.buffer = NULL;
        } else {
            return false;
        }

        current->data = payload;
    }

    if (stage->proxy.needed) {
        if (!stage->proxy.complete)
            return false;
        if (!cep_cell_is_proxy(current))
            return false;

        cepProxySnapshot snapshot = {
            .payload = stage->proxy.buffer,
            .size = stage->proxy.size,
            .flags = stage->proxy.flags,
            .ticket = NULL,
        };

        if (!cep_proxy_restore(current, &snapshot))
            return false;
    }

    return true;
}

static void cep_serialization_reader_fail(cepSerializationReader* reader) {
    if (!reader)
        return;

    reader->error = true;
    reader->pending_commit = false;
    cep_serialization_reader_clear_stages(reader);
    cep_serialization_reader_clear_transactions(reader);
}

bool cep_serialization_reader_ingest(cepSerializationReader* reader, const uint8_t* chunk, size_t chunk_size) {
    if (!reader || !chunk || chunk_size < CEP_SERIALIZATION_CHUNK_OVERHEAD)
        return false;

    uint64_t payload_be = 0;
    memcpy(&payload_be, chunk, sizeof payload_be);
    size_t payload_size = (size_t)cep_serial_from_be64(payload_be);
    if (payload_size + CEP_SERIALIZATION_CHUNK_OVERHEAD != chunk_size)
        return false;

    uint64_t id_be = 0;
    memcpy(&id_be, chunk + sizeof(uint64_t), sizeof(uint64_t));
    uint64_t chunk_id = cep_serial_from_be64(id_be);
    uint16_t chunk_class = cep_serialization_chunk_class(chunk_id);
    uint32_t transaction = cep_serialization_chunk_transaction(chunk_id);
    uint16_t sequence = cep_serialization_chunk_sequence(chunk_id);

    const uint8_t* payload = chunk + CEP_SERIALIZATION_CHUNK_OVERHEAD;

    if (chunk_class == CEP_CHUNK_CLASS_CONTROL && transaction == 0u && sequence == 0u) {
        if (!cep_serialization_header_read(chunk, chunk_size, &reader->header)) {
            cep_serialization_reader_fail(reader);
            return false;
        }
        cep_serialization_reader_clear_stages(reader);
        cep_serialization_reader_clear_transactions(reader);
        reader->header_seen = true;
        reader->pending_commit = false;
        reader->error = false;
        return true;
    }

    if (reader->error)
        return false;

    if (!reader->header_seen)
        return false;

    if (!sequence) {
        cep_serialization_reader_fail(reader);
        return false;
    }

    cepSerializationTxState* tx = cep_serialization_reader_get_tx(reader, transaction);
    if (!tx) {
        cep_serialization_reader_fail(reader);
        return false;
    }

    if ((uint16_t)(tx->last_sequence + 1u) != sequence) {
        cep_serialization_reader_fail(reader);
        return false;
    }
    tx->last_sequence = sequence;

    switch (chunk_class) {
      case CEP_CHUNK_CLASS_STRUCTURE: {
        if (!tx->pending_stage || tx->pending_stage->data.header_received) {
            if (!cep_serialization_reader_record_manifest(reader, tx, transaction, payload, payload_size)) {
                cep_serialization_reader_fail(reader);
                return false;
            }
        } else {
            size_t header_bytes = (sizeof(uint16_t) * 2u) + sizeof(uint32_t) + (sizeof(uint64_t) * 4u);
            if (payload_size < header_bytes) {
                cep_serialization_reader_fail(reader);
                return false;
            }
            size_t inline_size = payload_size - header_bytes;
            const uint8_t* inline_bytes = payload + header_bytes;
            if (!cep_serialization_reader_record_data_header(&tx->pending_stage->data,
                                                             payload,
                                                             payload_size,
                                                             inline_bytes,
                                                             inline_size)) {
                cep_serialization_reader_fail(reader);
                return false;
            }
            if (tx->pending_stage->data.complete)
                tx->pending_stage = NULL;
        }
        break;
      }
      case CEP_CHUNK_CLASS_BLOB: {
        if (!tx->pending_stage || !tx->pending_stage->data.header_received) {
            cep_serialization_reader_fail(reader);
            return false;
        }
        if (!cep_serialization_reader_record_data_chunk(&tx->pending_stage->data, payload, payload_size)) {
            cep_serialization_reader_fail(reader);
            return false;
        }
        if (tx->pending_stage->data.complete)
            tx->pending_stage = NULL;
        break;
      }
      case CEP_CHUNK_CLASS_CONTROL: {
        reader->pending_commit = true;
        break;
      }
      case CEP_CHUNK_CLASS_LIBRARY: {
        if (!tx->pending_stage || !tx->pending_stage->proxy.needed || tx->pending_stage->proxy.complete) {
            cep_serialization_reader_fail(reader);
            return false;
        }
        if (tx->pending_stage->data.needed && !tx->pending_stage->data.complete) {
            cep_serialization_reader_fail(reader);
            return false;
        }

        size_t header_bytes = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t);
        if (payload_size < header_bytes) {
            cep_serialization_reader_fail(reader);
            return false;
        }

        uint32_t flags = cep_serial_read_be32_buf(payload);
        uint64_t size = cep_serial_read_be64_buf(payload + sizeof(uint32_t) + sizeof(uint32_t));

        size_t remaining = payload_size - header_bytes;
        if (size > SIZE_MAX) {
            cep_serialization_reader_fail(reader);
            return false;
        }
        if ((uint64_t)remaining != size) {
            cep_serialization_reader_fail(reader);
            return false;
        }

        cepSerializationStage* stage = tx->pending_stage;
        stage->proxy.flags = flags;
        stage->proxy.size = (size_t)size;

        if (stage->proxy.buffer) {
            cep_free(stage->proxy.buffer);
            stage->proxy.buffer = NULL;
        }

        if (stage->proxy.size) {
            stage->proxy.buffer = cep_malloc(stage->proxy.size);
            if (!stage->proxy.buffer) {
                cep_serialization_reader_fail(reader);
                return false;
            }
            memcpy(stage->proxy.buffer, payload + header_bytes, stage->proxy.size);
        }

        stage->proxy.complete = true;
        tx->pending_stage = NULL;
        break;
      }
      default:
        cep_serialization_reader_fail(reader);
        return false;
    }

    return true;
}

bool cep_serialization_reader_commit(cepSerializationReader* reader) {
    if (!reader)
        return false;
    if (reader->error)
        return false;
    if (!reader->pending_commit)
        return false;

    for (size_t i = 0; i < reader->stage_count; ++i) {
        cepSerializationStage* stage = &reader->stages[i];
        if (!cep_serialization_reader_apply_stage(reader, stage)) {
            cep_serialization_reader_fail(reader);
            return false;
        }
        cep_serialization_stage_dispose(stage);
    }

    reader->stage_count = 0;
    reader->pending_commit = false;
    reader->transaction_count = 0;
    if (reader->transactions)
        memset(reader->transactions, 0, reader->transaction_capacity * sizeof(*reader->transactions));
    return true;
}

bool cep_serialization_reader_pending(const cepSerializationReader* reader) {
    if (!reader)
        return false;
    return reader->pending_commit;
}
