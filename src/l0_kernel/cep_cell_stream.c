/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


/*
 * Stream and foreign-library bindings for Layer 0 cells. This module keeps the
 * adapter plumbing and journaling helpers out of the core cell implementation
 * so cep_cell.c stays focused on structural concerns.
 */

#include "cep_cell.h"
#include "stream/cep_stream_internal.h"

CEP_DEFINE_STATIC_DT(dt_journal_name, CEP_ACRO("CEP"), CEP_WORD("journal"));
CEP_DEFINE_STATIC_DT(dt_journal_entry_name, CEP_ACRO("CEP"), CEP_WORD("entry"));
CEP_DEFINE_STATIC_DT(dt_stream_log_type, CEP_ACRO("CEP"), CEP_WORD("stream-log"));
CEP_DEFINE_STATIC_DT(dt_library_type, CEP_ACRO("CEP"), CEP_WORD("library"));
CEP_DEFINE_STATIC_DT(dt_list_type,    CEP_ACRO("CEP"), CEP_WORD("list"));
CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));

typedef struct {
    const cepLibraryBinding* library;
    cepCell*                 resource;
} cepStreamBinding;

static inline cepStreamBinding cep_stream_binding_prepare(const cepData* data) {
    cepStreamBinding binding = {0};

    if (!data)
        return binding;

    if (data->datatype != CEP_DATATYPE_HANDLE && data->datatype != CEP_DATATYPE_STREAM)
        return binding;

    binding.resource = (data->datatype == CEP_DATATYPE_HANDLE)? data->handle: data->stream;
    if (!binding.resource)
        return binding;

    binding.library = data->library? cep_library_binding(data->library): NULL;
    return binding;
}

static inline bool cep_stream_binding_ready(const cepStreamBinding* binding) {
    return binding && binding->library && binding->library->ops && binding->resource;
}

static cepCell* cep_stream_journal_node(cepCell* owner) {
    owner = cep_link_pull(owner);
    if (!owner || !cep_cell_is_normal(owner))
        return NULL;

    if (!owner->store) {
        cepDT dict_type = *dt_dictionary_type();
        cepStore* store = cep_store_new(&dict_type, CEP_STORAGE_RED_BLACK_T, CEP_INDEX_BY_NAME);
        if (!store)
            return NULL;
        store->owner = owner;
        owner->store = store;
    }

    cepCell* journal = cep_cell_find_by_name(owner, dt_journal_name());
    if (!journal) {
        cepDT name_copy = *dt_journal_name();
        cepDT list_type = *dt_list_type();
        journal = cep_cell_add_list(owner,
                                    &name_copy,
                                    0,
                                    &list_type,
                                    CEP_STORAGE_LINKED_LIST);
    }
    return journal;
}


typedef struct {
    uint64_t    offset;
    uint64_t    requested;
    uint64_t    actual;
    uint64_t    hash;
    uint32_t    flags;
    uint32_t    reserved;
} cepStreamJournalEntry;

static const cepLibraryBinding* cep_library_binding_const(const cepCell* library);
static cepLibraryBinding*       cep_library_binding_mut(cepCell* library);


/** Seed a library cell with an adapter binding so HANDLE/STREAM payloads can
    delegate back into foreign integrations. The binding owns both the vtable
    and any opaque context, letting adapters update their state without
    micromanaging lifetime. */
void cep_library_initialize(cepCell* library, cepDT* name, const cepLibraryOps* ops, void* context) {
    assert(library && ops);

    cepLibraryBinding* binding = cep_malloc0(sizeof *binding);
    binding->ops = ops;
    binding->ctx = context;

    cepDT library_type = *dt_library_type();
    cep_cell_initialize_data(library,
                             name,
                             &library_type,
                             binding,
                             sizeof *binding,
                             sizeof *binding,
                             cep_free);
}


/** Retrieve the immutable binding for a library cell. Links are resolved so
    adapters can be referenced through aliases without losing access to their
    vtable or context. */
const cepLibraryBinding* cep_library_binding(const cepCell* library) {
    return cep_library_binding_const(library);
}


/** Surface the adapter context stored with a library binding so callers can
    pass state to custom operations without cracking open the binding structure
    themselves. */
void* cep_library_context(const cepCell* library) {
    const cepLibraryBinding* binding = cep_library_binding_const(library);
    return binding? binding->ctx: NULL;
}


/** Update the opaque context associated with a library binding. Integrations
    can refresh handles or swap delegates while keeping the registered vtable in
    place. */
void cep_library_set_context(cepCell* library, void* context) {
    cepLibraryBinding* binding = cep_library_binding_mut(library);
    if (binding)
        binding->ctx = context;
}


static const cepLibraryBinding* cep_library_binding_const(const cepCell* library) {
    if (!library)
        return NULL;

    library = cep_link_pull(CEP_P(library));

    if (!cep_cell_is_normal(library) || !cep_cell_has_data(library))
        return NULL;

    const cepData* data = library->data;
    if (!data || !cep_data_valid(data))
        return NULL;

    return (const cepLibraryBinding*) cep_data(data);
}


static cepLibraryBinding* cep_library_binding_mut(cepCell* library) {
    return (cepLibraryBinding*) cep_library_binding_const(library);
}


void cep_stream_journal(cepCell* owner, unsigned flags, uint64_t offset, size_t requested, size_t actual, uint64_t hash) {
    assert(owner);

    owner = cep_link_pull(owner);
    if (!cep_cell_is_normal(owner))
        return;

    cepCell* journal = cep_stream_journal_node(owner);
    if (!journal)
        return;

    cepStreamJournalEntry entry = {
        .offset    = offset,
        .requested = requested,
        .actual    = actual,
        .hash      = hash,
        .flags     = flags,
        .reserved  = 0,
    };

    cep_cell_append_value(journal,
                          (cepDT*)dt_journal_entry_name(),
                          (cepDT*)dt_stream_log_type(),
                          &entry,
                          sizeof entry,
                          sizeof entry);
}


typedef struct {
    cepData* data;
    size_t   length;
    void*    backup;
} cepStreamMapToken;


/** Read a window from a cell's payload while keeping journaling and delegation
    consistent across VALUE, DATA, HANDLE, and STREAM representations. Memory
    backed cells copy bytes directly; external handles route through the
    library's adapter. Each call records a journal entry with the requested and
    actual byte counts plus a content hash of the bytes observed. */
bool cep_cell_stream_read(cepCell* cell, uint64_t offset, void* dst, size_t size, size_t* out_read) {
    assert(cell);

    if (!size) {
        if (out_read)
            *out_read = 0;
        return true;
    }

    if (!dst)
        return false;

    cell = cep_link_pull(cell);

    cepData* data = cell->data;
    if (!data)
        return false;

    size_t actual = 0;
    uint64_t hash = 0;
    bool ok = false;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE:
      case CEP_DATATYPE_DATA: {
        if (offset > SIZE_MAX)
            break;

        const uint8_t* base = (data->datatype == CEP_DATATYPE_VALUE)? data->value: (const uint8_t*)data->data;
        if (!base)
            break;

        size_t payloadSize = data->size;
        if (offset >= payloadSize) {
            actual = 0;
            ok = true;
            break;
        }

        size_t available = payloadSize - (size_t)offset;
        actual = size < available? size: available;
        memcpy(dst, base + offset, actual);
        hash = actual? cep_hash_bytes(base + offset, actual): 0;
        ok = true;
        break;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        cepStreamBinding binding = cep_stream_binding_prepare(data);
        if (!cep_stream_binding_ready(&binding) || !binding.library->ops->stream_read)
            break;

        ok = binding.library->ops->stream_read(binding.library, binding.resource, offset, dst, size, &actual);
        hash = (ok && actual)? cep_hash_bytes(dst, actual): 0;
        break;
      }

      default:
        break;
    }

    if (out_read)
        *out_read = actual;

    cep_stream_journal(cell,
                       ok? CEP_STREAM_JOURNAL_READ: (CEP_STREAM_JOURNAL_READ | CEP_STREAM_JOURNAL_ERROR),
                       offset,
                       size,
                       actual,
                       hash);

    return ok;
}


/** Write a window into a cell's payload, updating history for VALUE/DATA
    buffers and delegating to adapters for HANDLE/STREAM cells. Successful
    writes refresh hashes and modified timestamps and emit a journal entry
    describing the mutation so downstream tooling can audit the change. */
bool cep_cell_stream_write(cepCell* cell, uint64_t offset, const void* src, size_t size, size_t* out_written) {
    assert(cell);

    if (!size) {
        if (out_written)
            *out_written = 0;
        cep_stream_journal(cell, CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_COMMIT, offset, 0, 0, 0);
        return true;
    }

    if (!src)
        return false;

    cell = cep_link_pull(cell);

    cepData* data = cell->data;
    if (!data || !data->writable)
        return false;

    if (cep_cell_data_locked_hierarchy(cell))
        return false;

    size_t actual = 0;
    uint64_t hash = 0;
    bool ok = false;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE:
      case CEP_DATATYPE_DATA: {
        if (offset > SIZE_MAX)
            break;

        uint8_t* base = (data->datatype == CEP_DATATYPE_VALUE)? data->value: (uint8_t*)data->data;
        if (!base)
            break;

        size_t capacity = data->capacity;
        if (offset >= capacity)
            break;

        size_t writable = capacity - (size_t)offset;
        actual = size < writable? size: writable;
        if (!actual)
            break;

        cep_data_history_push(data);
        memcpy(base + offset, src, actual);

        size_t newSize = (size_t)offset + actual;
        if (newSize > data->size)
            data->size = newSize;

        data->hash = cep_data_compute_hash(data);
        data->modified = cep_cell_timestamp_next();

        hash = cep_hash_bytes(src, actual);
        ok = true;
        break;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        cepStreamBinding binding = cep_stream_binding_prepare(data);
        if (!cep_stream_binding_ready(&binding))
            break;

        uint64_t expected_hash = 0;
        if (binding.library->ops->stream_expected_hash) {
            binding.library->ops->stream_expected_hash(binding.library, binding.resource, offset, size, &expected_hash);
        }

        if (!cep_stream_stage_write(cell, data->library, binding.resource, offset, src, size, expected_hash)) {
            if (binding.library->ops->stream_write) {
                ok = binding.library->ops->stream_write(binding.library, binding.resource, offset, src, size, &actual);
                hash = (ok && actual)? cep_hash_bytes(src, actual): 0;
            }
            break;
        }

        if (out_written)
            *out_written = size;
        return true;
      }

      default:
        break;
    }

    if (out_written)
        *out_written = actual;

    cep_stream_journal(cell,
                       ok? (CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_COMMIT)
                          : (CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_ERROR),
                       offset,
                       size,
                       ok? actual: 0,
                       hash);

    return ok;
}


/** Map a stream window into memory. VALUE/DATA payloads expose direct pointers
    with an optional copy-on-write backup so unmap can roll back on failed
    commits. HANDLE/STREAM payloads defer to the registered adapter. */
bool cep_cell_stream_map(cepCell* cell, uint64_t offset, size_t size, unsigned access, cepStreamView* view) {
    assert(cell && view);

    cell = cep_link_pull(cell);

    cepData* data = cell->data;
    if (!data)
        return false;

    if ((access & CEP_STREAM_ACCESS_WRITE) && cep_cell_data_locked_hierarchy(cell))
        return false;

    memset(view, 0, sizeof *view);
    view->offset = offset;
    view->access = access;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE:
      case CEP_DATATYPE_DATA: {
        if (offset > SIZE_MAX)
            return false;
        if ((access & CEP_STREAM_ACCESS_WRITE) && !data->writable)
            return false;

        uint8_t* base = (data->datatype == CEP_DATATYPE_VALUE)? data->value: (uint8_t*)data->data;
        if (!base)
            return false;

        size_t capacity = data->capacity;
        if (offset >= capacity)
            return false;

        size_t span = capacity - (size_t)offset;
        if (size && size < span)
            span = size;

        view->address = base + offset;
        view->length  = span;

        cepStreamMapToken* token = cep_malloc0(sizeof *token);
        token->data   = data;
        token->length = span;

        if ((access & CEP_STREAM_ACCESS_WRITE) && span) {
            token->backup = cep_malloc(span);
            memcpy(token->backup, base + offset, span);
        }

        view->token = token;
        return true;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        cepStreamBinding binding = cep_stream_binding_prepare(data);
        if (!cep_stream_binding_ready(&binding) || !binding.library->ops->stream_map)
            return false;

        return binding.library->ops->stream_map(binding.library, binding.resource, offset, size, access, view);
      }

      default:
        break;
    }

    return false;
}


/** Finalise a mapped stream window. Commit writes by updating VALUE/DATA hashes
    and timestamps; aborts restore the backed-up bytes. Library-backed maps are
    handed back to the adapter. Journaling captures committed writes while
    read-only maps remain side-effect free. */
bool cep_cell_stream_unmap(cepCell* cell, cepStreamView* view, bool commit) {
    assert(cell && view);

    cell = cep_link_pull(cell);

    cepData* data = cell->data;
    if (!data)
        return false;

    bool locked = cep_cell_data_locked_hierarchy(cell);
    bool commit_allowed = commit && !locked;
    bool forced_abort = commit && locked;

    bool ok = false;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE:
      case CEP_DATATYPE_DATA: {
        cepStreamMapToken* token = (cepStreamMapToken*) view->token;
        if (!token || token->data != data)
            break;

        uint8_t* base = (data->datatype == CEP_DATATYPE_VALUE)? data->value: (uint8_t*)data->data;
        size_t length = token->length;
        uint64_t voffset = view->offset;

        if (token->backup && (!commit || !(view->access & CEP_STREAM_ACCESS_WRITE))) {
            memcpy(base + voffset, token->backup, length);
        }

        if ((view->access & CEP_STREAM_ACCESS_WRITE) && commit_allowed) {
            size_t end = (size_t)voffset + length;
            if (end > data->capacity) {
                memcpy(base + voffset, token->backup, length);
                break;
            }

            if (end > data->size)
                data->size = end;

            data->hash = cep_data_compute_hash(data);
            data->modified = cep_cell_timestamp_next();

            uint64_t hash = length? cep_hash_bytes(base + voffset, length): 0;
            cep_stream_journal(cell,
                               CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_COMMIT,
                               voffset,
                               length,
                               length,
                               hash);
        } else if ((view->access & CEP_STREAM_ACCESS_WRITE) && !commit_allowed) {
            uint64_t hash = (token->backup && length)? cep_hash_bytes(token->backup, length): 0;
            cep_stream_journal(cell,
                               CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_ERROR,
                               voffset,
                               length,
                               0,
                               hash);
        }

        if ((view->access & CEP_STREAM_ACCESS_READ) && length) {
            const uint8_t* snapshot = token->backup? (const uint8_t*)token->backup: base + voffset;
            uint64_t hash = cep_hash_bytes(snapshot, length);
            cep_stream_journal(cell,
                               CEP_STREAM_JOURNAL_READ,
                               voffset,
                               length,
                               length,
                               hash);
        }

        if (token->backup)
            cep_free(token->backup);
        cep_free(token);
        ok = true;
        break;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        cepStreamBinding binding = cep_stream_binding_prepare(data);
        if (!cep_stream_binding_ready(&binding) || !binding.library->ops->stream_unmap)
            break;

        ok = binding.library->ops->stream_unmap(binding.library, binding.resource, view, commit_allowed);
        break;
      }

      default:
        break;
    }

    view->address = NULL;
    view->token   = NULL;
    view->length  = 0;

    return ok && !forced_abort;
}
