#ifndef CEP_SERIALIZATION_H
#define CEP_SERIALIZATION_H

/**
 * @file
 * @brief Binary serialization helpers for CEP cell graphs.
 */

#include "cep_molecule.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cepSerializationReader cepSerializationReader;

typedef struct _cepCell cepCell;

#define CEP_SERIALIZATION_MAGIC   UINT64_C(0x4345503000000000)
#define CEP_SERIALIZATION_VERSION UINT16_C(0x0001)

#define CEP_SERIALIZATION_CHUNK_OVERHEAD 16u
#define CEP_SERIALIZATION_HEADER_BASE    16u

typedef bool (*cepSerializationWriteFn)(void* context, const uint8_t* chunk, size_t size);

#define CEP_SERIALIZATION_DEFAULT_BLOB_PAYLOAD 4096u

/**
 * @brief Logical chunk classes used by the CEP serialization envelope.
 */
enum {
    CEP_CHUNK_CLASS_CONTROL   = 0x0000u,
    CEP_CHUNK_CLASS_STRUCTURE = 0x0001u,
    CEP_CHUNK_CLASS_BLOB      = 0x0002u,
    CEP_CHUNK_CLASS_LIBRARY   = 0x0003u,
};

typedef enum {
    CEP_SERIAL_ENDIAN_BIG    = 0,
    CEP_SERIAL_ENDIAN_LITTLE = 1,
} cepSerializationByteOrder;

/**
 * @struct cepSerializationHeader
 * @brief Metadata that precedes a stream of CEP serialization chunks.
 */
typedef struct {
    uint64_t     magic;
    uint16_t     version;
    uint8_t      byte_order;
    uint8_t      flags;
    uint32_t     metadata_length;
    const uint8_t* metadata;
} cepSerializationHeader;

static inline uint64_t cep_serialization_chunk_id(uint16_t chunk_class, uint32_t transaction, uint16_t sequence) {
    return ((uint64_t)chunk_class << 48) | ((uint64_t)transaction << 16) | sequence;
}

static inline uint16_t cep_serialization_chunk_class(uint64_t chunk_id) {
    return (uint16_t)(chunk_id >> 48);
}

static inline uint32_t cep_serialization_chunk_transaction(uint64_t chunk_id) {
    return (uint32_t)((chunk_id >> 16) & UINT64_C(0xFFFFFFFF));
}

static inline uint16_t cep_serialization_chunk_sequence(uint64_t chunk_id) {
    return (uint16_t)(chunk_id & UINT64_C(0xFFFF));
}

/**
 * @brief Compute the size in bytes required to emit @p header.
 */
size_t cep_serialization_header_chunk_size(const cepSerializationHeader* header);

/**
 * @brief Serialize @p header into @p dst.
 */
bool cep_serialization_header_write(const cepSerializationHeader* header,
                                    uint8_t* dst,
                                    size_t capacity,
                                    size_t* out_size);

/**
 * @brief Parse a header chunk back into its structured representation.
 */
bool cep_serialization_header_read(const uint8_t* chunk,
                                   size_t chunk_size,
                                   cepSerializationHeader* header);

/**
 * @brief Emit a sequence of chunks describing @p cell and its subtree.
 */
bool cep_serialization_emit_cell(const cepCell* cell,
                                   const cepSerializationHeader* header,
                                   cepSerializationWriteFn write,
                                   void* context,
                                   size_t blob_payload_bytes);

/**
 * @brief Allocate a reader that rehydrates cells from incoming chunks.
 */
cepSerializationReader* cep_serialization_reader_create(cepCell* root);

/**
 * @brief Destroy a reader instance and free owned buffers.
 */
void cep_serialization_reader_destroy(cepSerializationReader* reader);

/**
 * @brief Reset a reader to its initial state while preserving allocations.
 */
void cep_serialization_reader_reset(cepSerializationReader* reader);

/**
 * @brief Feed a serialized chunk into the reader state machine.
 */
bool cep_serialization_reader_ingest(cepSerializationReader* reader, const uint8_t* chunk, size_t size);

/**
 * @brief Commit staged chunks, applying them to the destination tree.
 */
bool cep_serialization_reader_commit(cepSerializationReader* reader);

/**
 * @brief Return true when the reader still has unapplied chunks.
 */
bool cep_serialization_reader_pending(const cepSerializationReader* reader);

#ifdef __cplusplus
}
#endif

#endif /* CEP_SERIALIZATION_H */
