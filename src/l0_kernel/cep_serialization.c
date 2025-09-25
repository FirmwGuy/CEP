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
    assert(emitter && emitter->write && payload);

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
                           + sizeof(uint64_t) + sizeof(uint64_t);
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

    success = true;

cleanup:
    if (path)
        cep_free(path);
    return success;
}

