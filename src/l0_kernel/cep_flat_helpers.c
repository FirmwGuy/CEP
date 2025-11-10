/* Copyright (c) 2025 Victor M. Barrientos */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_flat_helpers.h"
#include "cep_molecule.h"
#include "cep_namepool.h"
#include "cep_identifier.h"
#include "blake3.h"
#include <string.h>

#define CEP_FLAT_CELL_META_TOMBSTONE 0x0001u
#define CEP_FLAT_CELL_META_VEILED    0x0002u

#define CEP_FLAT_NAMEPOOL_FLAG_GLOB  0x01u

#define CEP_FLAT_ORGANISER_INSERTION       0x01u
#define CEP_FLAT_ORGANISER_NAME            0x02u
#define CEP_FLAT_ORGANISER_FUNCTION        0x03u
#define CEP_FLAT_ORGANISER_HASH            0x04u
#define CEP_FLAT_ORGANISER_FUNCTION_OCTREE 0x05u

#define CEP_FLAT_CHILD_PAGE_TARGET_OPS 64u

typedef struct {
    uint64_t domain;
    uint64_t tag;
    uint64_t size;
    uint64_t payload;
} cepFlatPayloadFingerprint;

static void cep_flat_write_name_bytes(uint8_t* dst, const cepDT* name) {
    if (!dst)
        return;
    cepDT clean = name ? cep_dt_clean(name) : (cepDT){0};
    uint64_t domain = clean.domain;
    uint64_t tag = clean.tag;
    memcpy(dst, &domain, sizeof domain);
    memcpy(dst + sizeof domain, &tag, sizeof tag);
    dst[16] = clean.glob ? 1u : 0u;
}

static void cep_flat_fill_child_revision(const cepFlatChildDescriptor* child,
                                         uint8_t out[16]) {
    memset(out, 0, 16);
    if (!child || !child->has_fingerprint)
        return;
    memcpy(out, &child->fingerprint, sizeof child->fingerprint);
}

static uint16_t cep_flat_child_meta_mask(const cepFlatChildDescriptor* child) {
    if (!child)
        return 0u;
    uint16_t mask = 0u;
    if ((child->flags & CEP_FLAT_CELL_META_TOMBSTONE) != 0u)
        mask |= CEP_FLAT_CELL_META_TOMBSTONE;
    if ((child->flags & CEP_FLAT_CELL_META_VEILED) != 0u)
        mask |= CEP_FLAT_CELL_META_VEILED;
    return mask;
}

static bool cep_flat_body_reserve(uint8_t** buffer, size_t* capacity, size_t needed) {
    if (!buffer || !capacity)
        return false;
    if (needed <= *capacity)
        return true;
    size_t new_cap = *capacity ? *capacity : 64u;
    while (new_cap < needed) {
        new_cap <<= 1u;
    }
    uint8_t* grown = cep_realloc(*buffer, new_cap);
    if (!grown)
        return false;
    *buffer = grown;
    *capacity = new_cap;
    return true;
}

static size_t cep_flat_varint_length(uint64_t value) {
    size_t length = 1u;
    while (value >= 0x80u) {
        value >>= 7u;
        length++;
    }
    return length;
}

static uint8_t* cep_flat_write_varint(uint64_t value, uint8_t* dst) {
    do {
        uint8_t byte = (uint8_t)(value & 0x7Fu);
        value >>= 7u;
        if (value)
            byte |= 0x80u;
        *dst++ = byte;
    } while (value);
    return dst;
}

static bool cep_flat_append_varint_suffix(uint8_t** buffer, size_t* size, uint64_t value) {
    if (!buffer || !*buffer || !size)
        return false;
    size_t extra = cep_flat_varint_length(value);
    uint8_t* grown = cep_realloc(*buffer, *size + extra);
    if (!grown)
        return false;
    cep_flat_write_varint(value, grown + *size);
    *buffer = grown;
    *size += extra;
    return true;
}

static bool cep_flat_emit_manifest_delta_page(cepFlatSerializer* serializer,
                                              const cepCell* parent,
                                              const cepFlatChildDescriptor* children,
                                              size_t child_count,
                                              const cepFlatChildDescriptor* next_child,
                                              uint8_t organiser,
                                              cepFlatNamepoolCollector* names,
                                              uint64_t page_id);

static bool cep_flat_emit_order_delta_page(cepFlatSerializer* serializer,
                                           const cepCell* parent,
                                           const cepFlatChildDescriptor* children,
                                           size_t child_count,
                                           uint8_t organiser,
                                           cepFlatNamepoolCollector* names,
                                           uint8_t projection_kind,
                                           uint64_t page_id);

bool cep_flat_namepool_register_id(cepFlatNamepoolCollector* collector, cepID id) {
    if (!collector || !cep_id_is_reference(id))
        return true;
    for (size_t i = 0; i < collector->count; ++i) {
        if (collector->entries[i].id == id)
            return true;
    }

    size_t length = 0u;
    const char* text = cep_namepool_lookup(id, &length);
    if (!text || length > UINT16_MAX)
        return false;

    if (collector->count == collector->capacity) {
        size_t new_cap = collector->capacity ? collector->capacity << 1u : 16u;
        void* resized = cep_realloc(collector->entries, new_cap * sizeof *collector->entries);
        if (!resized)
            return false;
        collector->entries = resized;
        collector->capacity = new_cap;
    }

    char* copy = NULL;
    if (length) {
        copy = cep_malloc(length);
        if (!copy)
            return false;
        memcpy(copy, text, length);
    }

    collector->entries[collector->count++] = (typeof(*collector->entries)){
        .id = id,
        .length = (uint16_t)length,
        .flags = cep_namepool_reference_is_glob(id) ? CEP_FLAT_NAMEPOOL_FLAG_GLOB : 0u,
        .text = copy,
    };
    return true;
}

static int cep_flat_name_entry_cmp(const void* lhs, const void* rhs) {
    const typeof(((cepFlatNamepoolCollector*)0)->entries[0])* a = lhs;
    const typeof(((cepFlatNamepoolCollector*)0)->entries[0])* b = rhs;
    if (a->id < b->id)
        return -1;
    if (a->id > b->id)
        return 1;
    return 0;
}

bool cep_flat_namepool_emit(cepFlatNamepoolCollector* collector, cepFlatSerializer* serializer) {
    if (!collector || !collector->count)
        return true;

    qsort(collector->entries, collector->count, sizeof *collector->entries, cep_flat_name_entry_cmp);
    cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_NAMEPOOL_MAP);

    for (size_t i = 0; i < collector->count; ++i) {
        const typeof(*collector->entries)* entry = &collector->entries[i];
        uint8_t key[1 + sizeof(uint64_t)];
        key[0] = CEP_FLAT_RECORD_NAMEPOOL_DELTA;
        uint64_t id_le = entry->id;
        memcpy(key + 1, &id_le, sizeof id_le);

        uint8_t* body = NULL;
        size_t capacity = 0u;
        size_t len = entry->length;
        size_t varint_len = cep_flat_varint_length(len);
        if (!cep_flat_body_reserve(&body, &capacity, varint_len + 1u + len)) {
            cep_free(body);
            return false;
        }
        cep_flat_write_varint(len, body);
        body[varint_len] = entry->flags;
        if (len) {
            memcpy(body + varint_len + 1u, entry->text, len);
        }

        cepFlatRecordSpec spec = {
            .type = CEP_FLAT_RECORD_NAMEPOOL_DELTA,
            .version = CEP_FLAT_SERIALIZER_VERSION,
            .flags = 0u,
            .key = {
                .data = key,
                .size = sizeof key,
            },
            .body = {
                .data = body,
                .size = varint_len + 1u + len,
            },
        };

        if (!cep_flat_serializer_emit(serializer, &spec)) {
            cep_free(body);
            return false;
        }
        cep_free(body);
    }
    return true;
}

void cep_flat_namepool_clear(cepFlatNamepoolCollector* collector) {
    if (!collector)
        return;
    for (size_t i = 0; i < collector->count; ++i) {
        cep_free(collector->entries[i].text);
    }
    cep_free((void*)collector->entries);
    collector->entries = NULL;
    collector->count = 0u;
    collector->capacity = 0u;
    collector->emit_index = 0u;
}

uint16_t cep_flat_store_descriptor(const cepCell* cell) {
    if (!cell || !cep_cell_is_normal(cell) || !cell->store)
        return 0u;

    uint8_t organiser = 0u;
    switch (cell->store->indexing) {
      case CEP_INDEX_BY_INSERTION:
        organiser = CEP_FLAT_ORGANISER_INSERTION;
        break;
      case CEP_INDEX_BY_NAME:
        organiser = CEP_FLAT_ORGANISER_NAME;
        break;
      case CEP_INDEX_BY_FUNCTION:
        organiser = (cell->store->storage == CEP_STORAGE_OCTREE)
                        ? CEP_FLAT_ORGANISER_FUNCTION_OCTREE
                        : CEP_FLAT_ORGANISER_FUNCTION;
        break;
      case CEP_INDEX_BY_HASH:
        organiser = CEP_FLAT_ORGANISER_HASH;
        break;
      default:
        organiser = 0u;
        break;
    }

    uint8_t storage = 0u;
    switch (cell->store->storage) {
      case CEP_STORAGE_LINKED_LIST:
        storage = 0x01u;
        break;
      case CEP_STORAGE_RED_BLACK_T:
        storage = 0x02u;
        break;
      case CEP_STORAGE_ARRAY:
        storage = 0x03u;
        break;
      case CEP_STORAGE_PACKED_QUEUE:
        storage = 0x04u;
        break;
      case CEP_STORAGE_HASH_TABLE:
        storage = 0x05u;
        break;
      case CEP_STORAGE_OCTREE:
        storage = 0x06u;
        break;
      default:
        storage = 0u;
        break;
    }
    return (uint16_t)(((uint16_t)organiser << 8) | (uint16_t)storage);
}

void cep_flat_compute_revision_id(const cepCell* cell,
                                  const cepData* data,
                                  uint16_t store_descriptor,
                                  uint16_t meta_mask,
                                  uint64_t payload_fp,
                                  const void* inline_payload,
                                  size_t inline_length,
                                  uint8_t out[16]) {
    struct {
        uint16_t cell_type;
        uint16_t meta_mask;
        uint16_t store_descriptor;
        uint16_t data_tag_hint;
        uint32_t store_children;
        uint32_t store_total;
        uint64_t created;
        uint64_t latest;
        uint64_t payload_fp;
        uint64_t store_created;
        uint64_t store_modified;
        uint64_t inline_hash;
    } seed = {
        .cell_type = cell ? cell->metacell.type : 0u,
        .meta_mask = meta_mask,
        .store_descriptor = store_descriptor,
        .data_tag_hint = data ? (uint16_t)((uint16_t)(data->dt.tag & 0xFFFFu) ^
                                           (uint16_t)(data->dt.domain & 0xFFFFu)) : 0u,
        .store_children = (uint32_t)(cell && cell->store ? cep_cell_children(cell) : 0u),
        .store_total = (uint32_t)(cell && cell->store ? cell->store->totCount : 0u),
        .created = cell ? cell->created : 0u,
        .latest = cell ? cep_cell_latest_timestamp(cell) : 0u,
        .payload_fp = payload_fp,
        .store_created = (cell && cell->store) ? cell->store->created : 0u,
        .store_modified = (cell && cell->store) ? cell->store->modified : 0u,
        .inline_hash = (inline_payload && inline_length)
                           ? cep_hash_bytes(inline_payload, inline_length)
                           : 0u,
    };

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &seed, sizeof seed);
    if (cell && cell->store)
        blake3_hasher_update(&hasher, &cell->store->dt, sizeof cell->store->dt);
    if (data)
        blake3_hasher_update(&hasher, &data->dt, sizeof data->dt);
    blake3_hasher_finalize(&hasher, out, 16);
}

static bool cep_flat_compute_child_fingerprint(const cepCell* child, uint64_t* out_fp) {
    if (!child || !out_fp)
        return false;
    const cepData* data = child->data;
    uint64_t payload_hash = 0u;
    if (data && (data->datatype == CEP_DATATYPE_VALUE || data->datatype == CEP_DATATYPE_DATA)) {
        const void* payload = cep_data_payload(data);
        payload_hash = payload ? cep_hash_bytes(payload, data->size) : 0u;
    } else if (data && (data->datatype == CEP_DATATYPE_HANDLE || data->datatype == CEP_DATATYPE_STREAM)) {
        uintptr_t refs[2] = {
            (uintptr_t)(data->handle ? data->handle : data->stream),
            (uintptr_t)data->library,
        };
        payload_hash = cep_hash_bytes(refs, sizeof refs);
    }
    cepFlatPayloadFingerprint fp = {
        .domain = data ? data->dt.domain : 0u,
        .tag = data ? data->dt.tag : 0u,
        .size = data ? data->size : 0u,
        .payload = payload_hash,
    };
    *out_fp = cep_hash_bytes(&fp, sizeof fp);
    return true;
}

bool cep_flat_collect_children(const cepCell* cell,
                               cepFlatChildDescriptor** out_children,
                               size_t* out_count,
                               uint8_t* out_organiser) {
    if (!out_children || !out_count)
        return false;
    *out_children = NULL;
    *out_count = 0u;
    if (out_organiser)
        *out_organiser = 0u;

    if (!cell || !cep_cell_is_normal(cell) || !cell->store || !cell->store->chdCount)
        return true;

    size_t capacity = cell->store->chdCount;
    cepFlatChildDescriptor* children = cep_malloc(capacity * sizeof *children);
    if (!children)
        return false;

    uint8_t organiser = cep_flat_store_descriptor(cell) >> 8;
    if (out_organiser)
        *out_organiser = organiser;

    size_t index = 0u;
    uint32_t next_position = 0u;
    bool positional = (organiser == CEP_FLAT_ORGANISER_INSERTION);

    for (cepCell* child = cep_cell_first_all(cell); child; child = cep_cell_next_all(cell, child)) {
        cepCell* resolved = cep_link_pull(child);
        if (!resolved)
            continue;
        const cepDT* name = cep_cell_get_name(resolved);
        if (!name)
            continue;

        uint32_t assigned_position = positional ? next_position : (uint32_t)index;
        if (positional) {
            size_t ordinal = 0u;
            if (cep_cell_indexof((cepCell*)cell, resolved, &ordinal)) {
                assigned_position = ordinal > (size_t)UINT32_MAX ? UINT32_MAX : (uint32_t)ordinal;
            }
        }
        if (next_position < UINT32_MAX)
            next_position++;

        cepFlatChildDescriptor desc = {
            .name = *name,
            .flags = 0u,
            .position = (uint16_t)((assigned_position > UINT16_MAX) ? UINT16_MAX : assigned_position),
            .has_fingerprint = false,
            .fingerprint = 0u,
            .cell_type = (uint8_t)resolved->metacell.type,
            .delta_flags = 0u,
        };

        if (resolved->metacell.veiled)
            desc.flags |= CEP_FLAT_CELL_META_VEILED;

        bool tombstone = cep_cell_is_deleted(resolved);
        if (tombstone) {
            desc.flags |= CEP_FLAT_CELL_META_TOMBSTONE;
            desc.delta_flags = 2u; /* REMOVE */
        } else {
            uint64_t fingerprint = 0u;
            if (cep_flat_compute_child_fingerprint(resolved, &fingerprint)) {
                desc.has_fingerprint = true;
                desc.fingerprint = fingerprint;
            }
            desc.delta_flags = 1u; /* ADD */
        }

        children[index++] = desc;
    }

    if (!index) {
        cep_free(children);
        return true;
    }

    *out_children = children;
    *out_count = index;
    return true;
}

static uint8_t cep_flat_range_kind(uint8_t organiser) {
    return organiser == CEP_FLAT_ORGANISER_HASH ? 1u : 0u;
}

static uint8_t cep_flat_projection_kind(uint8_t organiser) {
    switch (organiser) {
      case CEP_FLAT_ORGANISER_INSERTION:
        return 1u;
      case CEP_FLAT_ORGANISER_HASH:
        return 2u;
      default:
        return 0u;
    }
}

bool cep_flat_emit_manifest_delta(cepFlatSerializer* serializer,
                                  const cepCell* parent,
                                  const cepFlatChildDescriptor* children,
                                  size_t child_count,
                                  uint8_t organiser,
                                  cepFlatNamepoolCollector* names) {
    if (!serializer || !parent)
        return false;
    if (!children || !child_count)
        return true;

    cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_PAGED_CHILDSET);

    size_t page_limit = CEP_FLAT_CHILD_PAGE_TARGET_OPS ? CEP_FLAT_CHILD_PAGE_TARGET_OPS : child_count;
    if (page_limit == 0u)
        page_limit = child_count ? child_count : 1u;

    size_t offset = 0u;
    uint64_t page_id = 0u;
    while (offset < child_count) {
        size_t page_count = child_count - offset;
        if (page_count > page_limit)
            page_count = page_limit;
        const cepFlatChildDescriptor* next_child = (offset + page_count < child_count)
                                                       ? &children[offset + page_count]
                                                       : NULL;
        if (!cep_flat_emit_manifest_delta_page(serializer,
                                               parent,
                                               children + offset,
                                               page_count,
                                               next_child,
                                               organiser,
                                               names,
                                               page_id)) {
            return false;
        }
        offset += page_count;
        page_id++;
    }
    return true;
}

bool cep_flat_emit_order_delta(cepFlatSerializer* serializer,
                               const cepCell* parent,
                               const cepFlatChildDescriptor* children,
                               size_t child_count,
                               uint8_t organiser,
                               cepFlatNamepoolCollector* names) {
    if (!serializer || !parent)
        return false;
    if (!children || !child_count)
        return true;

    cep_flat_serializer_add_caps(serializer, CEP_FLAT_CAP_PAGED_ORDER);

    uint8_t projection_kind = cep_flat_projection_kind(organiser);
    size_t page_limit = CEP_FLAT_CHILD_PAGE_TARGET_OPS ? CEP_FLAT_CHILD_PAGE_TARGET_OPS : child_count;
    if (page_limit == 0u)
        page_limit = child_count ? child_count : 1u;

    size_t offset = 0u;
    uint64_t page_id = 0u;
    while (offset < child_count) {
        size_t page_count = child_count - offset;
        if (page_count > page_limit)
            page_count = page_limit;
        if (!cep_flat_emit_order_delta_page(serializer,
                                            parent,
                                            children + offset,
                                            page_count,
                                            organiser,
                                            names,
                                            projection_kind,
                                            page_id)) {
            return false;
        }
        offset += page_count;
        page_id++;
    }
    return true;
}

bool cep_flat_build_key(const cepCell* cell,
                        uint8_t record_type,
                        cepFlatNamepoolCollector* names,
                        uint8_t** out_key,
                        size_t* out_key_size) {
    if (!cell || !out_key || !out_key_size)
        return false;

    cepPath* path = NULL;
    uint8_t* key = NULL;
    bool ok = false;

    if (!cep_cell_path(cell, &path))
        goto cleanup;

    size_t segments = path ? path->length : 0u;
    size_t key_bytes = 1u + segments * (sizeof(uint64_t) * 2u + 1u);
    key = cep_malloc(key_bytes);
    if (!key)
        goto cleanup;
    uint8_t* cursor = key;
    *cursor++ = record_type;

    for (size_t i = 0; i < segments; ++i) {
        const cepPast* segment = &path->past[i];
        if (names) {
            if (!cep_flat_namepool_register_id(names, segment->dt.domain) ||
                !cep_flat_namepool_register_id(names, segment->dt.tag)) {
                goto cleanup;
            }
        }
        uint8_t name_bytes[sizeof(uint64_t) * 2u + 1u];
        cep_flat_write_name_bytes(name_bytes, &segment->dt);
        memcpy(cursor, name_bytes, sizeof name_bytes);
        cursor += sizeof name_bytes;
    }

    *out_key = key;
    *out_key_size = key_bytes;
    key = NULL;
    ok = true;

cleanup:
    if (path)
        cep_free(path);
    if (!ok && key)
        cep_free(key);
    return ok;
}

static bool cep_flat_emit_manifest_delta_page(cepFlatSerializer* serializer,
                                              const cepCell* parent,
                                              const cepFlatChildDescriptor* children,
                                              size_t child_count,
                                              const cepFlatChildDescriptor* next_child,
                                              uint8_t organiser,
                                              cepFlatNamepoolCollector* names,
                                              uint64_t page_id) {
    uint8_t* key = NULL;
    size_t key_size = 0u;
    if (!cep_flat_build_key(parent, CEP_FLAT_RECORD_MANIFEST_DELTA, names, &key, &key_size))
        return false;
    bool ok = false;
    if (!cep_flat_append_varint_suffix(&key, &key_size, page_id)) {
        cep_free(key);
        return false;
    }

    uint8_t* body = NULL;
    size_t capacity = 0u;
    size_t size = 0u;

#define MAN_BODY_RESERVE(extra) \
    do { \
        if (!cep_flat_body_reserve(&body, &capacity, size + (extra))) \
            goto manifest_cleanup; \
    } while (0)
#define MAN_BODY_APPEND_U8(value) \
    do { MAN_BODY_RESERVE(1u); body[size++] = (uint8_t)(value); } while (0)
#define MAN_BODY_APPEND_U16(value) \
    do { uint16_t v__ = (uint16_t)(value); MAN_BODY_RESERVE(sizeof v__); memcpy(body + size, &v__, sizeof v__); size += sizeof v__; } while (0)
#define MAN_BODY_APPEND_VARINT(value) \
    do { size_t len__ = cep_flat_varint_length((uint64_t)(value)); MAN_BODY_RESERVE(len__); cep_flat_write_varint((uint64_t)(value), body + size); size += len__; } while (0)
#define MAN_BODY_APPEND_BYTES(ptr, len) \
    do { size_t len__ = (size_t)(len); if (len__) { MAN_BODY_RESERVE(len__); memcpy(body + size, (ptr), len__); size += len__; } } while (0)

    uint64_t epoch = parent->store ? parent->store->modified : cep_cell_latest_timestamp(parent);
    MAN_BODY_APPEND_VARINT(epoch);
    MAN_BODY_APPEND_U8(cep_flat_range_kind(organiser));

    uint8_t range_min[17] = {0};
    uint8_t range_max[17] = {0};
    size_t range_min_len = 0u;
    size_t range_max_len = 0u;
    if (child_count) {
        cep_flat_write_name_bytes(range_min, &children[0].name);
        range_min_len = sizeof range_min;
        if (names) {
            (void)cep_flat_namepool_register_id(names, children[0].name.domain);
            (void)cep_flat_namepool_register_id(names, children[0].name.tag);
        }
    }
    if (next_child) {
        cep_flat_write_name_bytes(range_max, &next_child->name);
        range_max_len = sizeof range_max;
        if (names) {
            (void)cep_flat_namepool_register_id(names, next_child->name.domain);
            (void)cep_flat_namepool_register_id(names, next_child->name.tag);
        }
    }

    MAN_BODY_APPEND_VARINT(range_min_len);
    MAN_BODY_APPEND_BYTES(range_min, range_min_len);
    MAN_BODY_APPEND_VARINT(range_max_len);
    MAN_BODY_APPEND_BYTES(range_max, range_max_len);

    MAN_BODY_APPEND_VARINT(child_count);

    for (size_t i = 0; i < child_count; ++i) {
        const cepFlatChildDescriptor* child = &children[i];
        if (names) {
            (void)cep_flat_namepool_register_id(names, child->name.domain);
            (void)cep_flat_namepool_register_id(names, child->name.tag);
        }
        uint8_t op_code = child->delta_flags ? child->delta_flags : 1u;
        MAN_BODY_APPEND_U8(op_code);
        uint8_t name_bytes[17];
        cep_flat_write_name_bytes(name_bytes, &child->name);
        MAN_BODY_APPEND_BYTES(name_bytes, sizeof name_bytes);
        MAN_BODY_APPEND_U16(cep_flat_child_meta_mask(child));
        uint8_t revision[16];
        cep_flat_fill_child_revision(child, revision);
        MAN_BODY_APPEND_BYTES(revision, sizeof revision);
    }

    {
        cepFlatRecordSpec spec = {
            .type = CEP_FLAT_RECORD_MANIFEST_DELTA,
            .version = CEP_FLAT_SERIALIZER_VERSION,
            .flags = 0u,
            .key = {.data = key, .size = key_size},
            .body = {.data = body, .size = size},
        };
        ok = cep_flat_serializer_emit(serializer, &spec);
    }

manifest_cleanup:
    if (body)
        cep_free(body);
    if (key)
        cep_free(key);
#undef MAN_BODY_RESERVE
#undef MAN_BODY_APPEND_U8
#undef MAN_BODY_APPEND_U16
#undef MAN_BODY_APPEND_VARINT
#undef MAN_BODY_APPEND_BYTES
    return ok;
}

static bool cep_flat_emit_order_delta_page(cepFlatSerializer* serializer,
                                           const cepCell* parent,
                                           const cepFlatChildDescriptor* children,
                                           size_t child_count,
                                           uint8_t organiser,
                                           cepFlatNamepoolCollector* names,
                                           uint8_t projection_kind,
                                           uint64_t page_id) {
    (void)organiser;
    uint8_t* key = NULL;
    size_t key_size = 0u;
    if (!cep_flat_build_key(parent, CEP_FLAT_RECORD_ORDER_DELTA, names, &key, &key_size))
        return false;
    bool ok = false;
    if (!cep_flat_append_varint_suffix(&key, &key_size, projection_kind)) {
        cep_free(key);
        return false;
    }
    if (!cep_flat_append_varint_suffix(&key, &key_size, page_id)) {
        cep_free(key);
        return false;
    }

    uint8_t* body = NULL;
    size_t capacity = 0u;
    size_t size = 0u;
#define ORD_BODY_RESERVE(extra) \
    do { if (!cep_flat_body_reserve(&body, &capacity, size + (extra))) goto order_cleanup; } while (0)
#define ORD_BODY_APPEND_U8(value) \
    do { ORD_BODY_RESERVE(1u); body[size++] = (uint8_t)(value); } while (0)
#define ORD_BODY_APPEND_VARINT(value) \
    do { size_t len__ = cep_flat_varint_length((uint64_t)(value)); ORD_BODY_RESERVE(len__); \
         cep_flat_write_varint((uint64_t)(value), body + size); size += len__; } while (0)
#define ORD_BODY_APPEND_BYTES(ptr, len) \
    do { size_t len__ = (size_t)(len); if (len__) { ORD_BODY_RESERVE(len__); memcpy(body + size, (ptr), len__); size += len__; } } while (0)

    uint64_t epoch = parent->store ? parent->store->modified : cep_cell_latest_timestamp(parent);
    ORD_BODY_APPEND_U8(projection_kind);
    ORD_BODY_APPEND_VARINT(epoch);
    uint64_t rank_min = child_count ? children[0].position : 0u;
    ORD_BODY_APPEND_VARINT(rank_min);
    ORD_BODY_APPEND_VARINT(child_count);

    for (size_t i = 0; i < child_count; ++i) {
        const cepFlatChildDescriptor* child = &children[i];
        if (names) {
            (void)cep_flat_namepool_register_id(names, child->name.domain);
            (void)cep_flat_namepool_register_id(names, child->name.tag);
        }
        uint8_t op_code = ((child->delta_flags & 0x02u) != 0u) ? 2u : 1u;
        ORD_BODY_APPEND_U8(op_code);
        uint8_t name_buf[17];
        cep_flat_write_name_bytes(name_buf, &child->name);
        ORD_BODY_APPEND_BYTES(name_buf, sizeof name_buf);
        ORD_BODY_APPEND_VARINT(child->position);
        /* TODO(FLAT-SORTKEY): emit caller-provided sort key bytes when projections request them. */
        ORD_BODY_APPEND_VARINT(0u);
    }

    {
        cepFlatRecordSpec spec = {
            .type = CEP_FLAT_RECORD_ORDER_DELTA,
            .version = CEP_FLAT_SERIALIZER_VERSION,
            .flags = 0u,
            .key = {.data = key, .size = key_size},
            .body = {.data = body, .size = size},
        };
        ok = cep_flat_serializer_emit(serializer, &spec);
    }

order_cleanup:
    if (body)
        cep_free(body);
    if (key)
        cep_free(key);
#undef ORD_BODY_RESERVE
#undef ORD_BODY_APPEND_U8
#undef ORD_BODY_APPEND_VARINT
#undef ORD_BODY_APPEND_BYTES
    return ok;
}
