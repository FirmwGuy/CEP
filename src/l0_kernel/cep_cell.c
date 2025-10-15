/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_cell.h"
#include "cep_heartbeat.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

typedef struct _cepStoreHistoryEntry cepStoreHistoryEntry;
typedef struct _cepStoreHistory      cepStoreHistory;

struct _cepStoreHistoryEntry {
    cepDT                   name;
    cepCell*                cell;
    cepOpCount              modified;
    bool                    alive;
    cepStoreHistoryEntry*   past;
};

struct _cepStoreHistory {
    cepStoreNode            node;
    size_t                  entryCount;
    cepStoreHistoryEntry*   entries;
};

struct _cepProxy {
    const cepProxyOps*  ops;
    void*               context;
};





static inline int cell_compare_by_name(const cepCell* restrict key, const cepCell* restrict rec, void* unused) {
    (void)unused;
    int cmp = cep_dt_compare(CEP_DT_PTR(key), CEP_DT_PTR(rec));
    if (cmp)
        return cmp;

    bool keyHasTimeline = !cep_cell_is_void(key) && cep_cell_is_normal(key)
                        && (key->data || key->store || key->parent);
    bool recHasTimeline = !cep_cell_is_void(rec) && cep_cell_is_normal(rec)
                        && (rec->data || rec->store || rec->parent);

    if (keyHasTimeline && recHasTimeline)
        return cep_cell_order_compare(key, rec);

    return 0;
}

static cepCell* cep_store_replace_child(cepStore* store, cepCell* existing, cepCell* incoming);


static cepStoreHistory*     cep_store_history_snapshot(const cepStore* store, const cepStoreHistory* previous);
static void                 cep_store_history_free(cepStoreHistory* history);
static void                 cep_store_history_push(cepStore* store);
static void                 cep_store_history_clear(cepStore* store);
static void                 cep_enzyme_binding_list_destroy(cepEnzymeBinding* bindings);
static bool                 cep_store_hierarchy_locked(const cepCell* cell);
static bool                 cep_data_hierarchy_locked(const cepCell* cell);
static cepData*             cep_data_clone_payload(const cepData* data);
static cepStore*            cep_store_clone_structure(const cepStore* store);
static bool                 cep_cell_clone_children(const cepCell* src, cepCell* dst);
static void                 cep_cell_clone_cleanup(cepCell* cell);
static bool                 cep_cell_clone_into(const cepCell* src, cepCell* dst, bool deep);

static inline cepStoreHistory* cep_store_history_from_node(cepStoreNode* node) {
    return node? (cepStoreHistory*)cep_ptr_dif(node, offsetof(cepStoreHistory, node)): NULL;
}

static inline const cepStoreHistory* cep_store_history_from_const_node(const cepStoreNode* node) {
    return node? (const cepStoreHistory*)cep_ptr_dif(node, offsetof(cepStoreHistory, node)): NULL;
}

static bool cep_cell_structural_equal(const cepCell* existing, const cepCell* incoming);
static bool cep_data_structural_equal(const cepData* existing, const cepData* incoming);

static inline cepCell* store_find_child_by_name(const cepStore* store, const cepDT* name);
static inline cepCell* store_find_child_by_key(const cepStore* store, cepCell* key, cepCompare compare, void* context);
static inline cepCell* store_find_child_by_position(const cepStore* store, size_t position);
static inline cepCell* store_first_child(const cepStore* store);
static inline cepCell* store_last_child(const cepStore* store);
static inline cepCell* store_next_child(const cepStore* store, cepCell* child);
static inline cepCell* store_first_child_internal(const cepStore* store);
static inline cepCell* store_next_child_internal(const cepStore* store, cepCell* child);
static inline bool store_traverse_internal(cepStore* store, cepTraverse func, void* context, cepEntry* entry);
static inline void cep_cell_apply_parent_veil(cepCell* child, const cepCell* parent);
static const cepCell* cep_cell_top_veiled_ancestor(const cepCell* cell);

static void cep_enzyme_binding_list_destroy(cepEnzymeBinding* bindings) {
    while (bindings) {
        cepEnzymeBinding* next = bindings->next;
        cep_free(bindings);
        bindings = next;
    }
}

static void cep_shadow_break_all(cepCell* target);
static void cep_shadow_rebind_links(cepCell* target);

#define CEP_MAX_FAST_STACK_DEPTH  16

#define cepFunc     void*

typedef struct {
    cepEntry* data;
    cepEntry  fast[CEP_MAX_FAST_STACK_DEPTH];
    size_t    capacity;
    bool      heap;
} cepEntryStack;

static inline void cep_entry_stack_init(cepEntryStack* stack) {
    assert(stack);
    stack->data = stack->fast;
    stack->capacity = CEP_MAX_FAST_STACK_DEPTH;
    stack->heap = false;
    memset(stack->fast, 0, sizeof stack->fast);
}

static inline bool cep_entry_stack_reserve(cepEntryStack* stack, size_t requiredDepth) {
    assert(stack);

    if (requiredDepth < stack->capacity)
        return true;

    size_t newCapacity = stack->capacity;
    while (newCapacity <= requiredDepth)
        newCapacity <<= 1u;

    cepEntry* resized;
    if (stack->heap) {
        resized = cep_realloc(stack->data, newCapacity * sizeof *resized);
        if (!resized)
            return false;
    } else {
        resized = cep_malloc(newCapacity * sizeof *resized);
        if (!resized)
            return false;
        memcpy(resized, stack->data, stack->capacity * sizeof *resized);
        stack->heap = true;
    }

    memset(resized + stack->capacity, 0, (newCapacity - stack->capacity) * sizeof *resized);
    stack->data = resized;
    stack->capacity = newCapacity;
    return true;
}

static inline void cep_entry_stack_destroy(cepEntryStack* stack) {
    assert(stack);

    if (stack->heap && stack->data)
        cep_free(stack->data);

    stack->data = stack->fast;
    stack->capacity = CEP_MAX_FAST_STACK_DEPTH;
    stack->heap = false;
}


/** Construct a proxy cell by wiring a proxy vtable to the generic cell
    initializer so callers can expose virtual payloads without touching the
    regular data/store fields. The helper allocates the lightweight proxy
    descriptor, stashes the user context, and keeps the cell free from
    accidental normal-type invariants so later helpers recognise the proxy
    flavour. */
void cep_proxy_initialize(cepCell* cell, cepDT* name, const cepProxyOps* ops, void* context) {
    assert(cell && name && cep_dt_is_valid(name));
    assert(ops);

    cep_cell_initialize(cell, CEP_TYPE_PROXY, name, NULL, NULL);

    cepProxy* proxy = cep_malloc0(sizeof *proxy);
    proxy->ops = ops;
    proxy->context = context;
    cell->proxy = proxy;
}

/** Update or seed the opaque context stored with a proxy cell so adapters can
    keep per-instance state (like handles or configuration) without reaching
    past the public API. Context assignment lazily allocates the proxy wrapper
    when the cell was promoted from a raw initializer, keeping the invariant
    that proxy storage always exists when needed. */
void cep_proxy_set_context(cepCell* cell, void* context) {
    assert(cell && cep_cell_is_proxy(cell));

    cepProxy* proxy = cell->proxy;
    if (!proxy) {
        proxy = cep_malloc0(sizeof *proxy);
        cell->proxy = proxy;
    }

    proxy->context = context;
}

/** Return the adapter-defined context associated with a proxy cell so callers
    can retrieve live bindings without poking at the proxy internals. The helper
    shields users from NULL checks when a proxy was initialised without context,
    making subsequent calls simpler. */
void* cep_proxy_context(const cepCell* cell) {
    assert(cell && cep_cell_is_proxy(cell));

    const cepProxy* proxy = cell->proxy;
    return proxy ? proxy->context : NULL;
}

/** Surface the proxy operations table configured for a cell so subsystems such
    as serialization and streaming can dispatch through the appropriate callback
    set. Returning NULL signals a placeholder proxy that cannot yet serve calls,
    giving callers a quick readiness check. */
const cepProxyOps* cep_proxy_ops(const cepCell* cell) {
    assert(cell && cep_cell_is_proxy(cell));

    const cepProxy* proxy = cell->proxy;
    return proxy ? proxy->ops : NULL;
}

/** Ask the proxy to materialise a snapshot of its payload, which may be an
    inline buffer or an external ticket depending on the adapter flags. The
    output structure is zeroed before delegation so callers always see a fully
    initialised snapshot even when the adapter declines to produce one. */
bool cep_proxy_snapshot(cepCell* cell, cepProxySnapshot* snapshot) {
    assert(cell && cep_cell_is_proxy(cell));
    assert(snapshot);

    memset(snapshot, 0, sizeof *snapshot);

    cepProxy* proxy = cell->proxy;
    if (!proxy || !proxy->ops || !proxy->ops->snapshot)
        return false;

    return proxy->ops->snapshot(cell, snapshot);
}

/** Allow adapters to tear down resources associated with a previously emitted
    snapshot, ensuring ephemeral buffers or handles do not leak once the caller
    (for example the serializer) is done using them. The helper tolerates
    missing release callbacks so simple proxies can rely on stack-allocated data
    without extra bookkeeping. */
void cep_proxy_release_snapshot(cepCell* cell, cepProxySnapshot* snapshot) {
    assert(cell && cep_cell_is_proxy(cell));
    assert(snapshot);

    bool handled = false;
    cepProxy* proxy = cell->proxy;
    if (proxy && proxy->ops && proxy->ops->release) {
        proxy->ops->release(cell, snapshot);
        handled = true;
    }

    if (!handled && (snapshot->flags & CEP_PROXY_SNAPSHOT_INLINE) && snapshot->payload)
        cep_free((void*)snapshot->payload);

    memset(snapshot, 0, sizeof *snapshot);
}

/** Restore a proxy cell from a serialized snapshot so deserialisation can bring
    virtual payloads back online. Adapters decide how to interpret the bytes or
    tickets; a missing restore hook means the proxy cannot be reconstructed and
    signals failure to the caller. */
bool cep_proxy_restore(cepCell* cell, const cepProxySnapshot* snapshot) {
    assert(cell && cep_cell_is_proxy(cell));
    assert(snapshot);

    cepProxy* proxy = cell->proxy;
    if (!proxy || !proxy->ops || !proxy->ops->restore)
        return false;

    return proxy->ops->restore(cell, snapshot);
}

typedef struct {
    cepCell*    library;
    cepCell*    resource;
    bool        isStream;
} cepProxyLibraryCtx;

static cepProxyLibraryCtx* cep_proxy_library_ctx(cepCell* cell) {
    if (!cell)
        return NULL;

    cepProxy* proxy = cell->proxy;
    return proxy? (cepProxyLibraryCtx*)proxy->context: NULL;
}

static const cepLibraryBinding* cep_proxy_library_binding(const cepProxyLibraryCtx* ctx) {
    if (!ctx || !ctx->library)
        return NULL;

    return cep_library_binding(ctx->library);
}

static bool cep_proxy_library_set_resource(cepCell* cell, cepProxyLibraryCtx* ctx, cepCell* resource) {
    (void)cell;

    if (!ctx)
        return false;

    const cepLibraryBinding* binding = cep_proxy_library_binding(ctx);
    cepCell* canonical = resource? cep_link_pull(resource): NULL;

    if (ctx->resource == canonical)
        return true;

    if (ctx->resource && binding && binding->ops && binding->ops->handle_release)
        binding->ops->handle_release(binding, ctx->resource);

    ctx->resource = canonical;

    if (ctx->resource && binding && binding->ops && binding->ops->handle_retain)
        binding->ops->handle_retain(binding, ctx->resource);

    return true;
}

static bool cep_proxy_library_snapshot(cepCell* cell, cepProxySnapshot* snapshot) {
    cepProxyLibraryCtx* ctx = cep_proxy_library_ctx(cell);
    if (!ctx)
        return false;

    const cepLibraryBinding* binding = cep_proxy_library_binding(ctx);
    if (!binding || !binding->ops)
        return false;

    if (!ctx->resource)
        return false;

    if (ctx->isStream) {
        if (!binding->ops->stream_snapshot)
            return false;
        return binding->ops->stream_snapshot(binding, ctx->resource, snapshot);
    }

    if (!binding->ops->handle_snapshot)
        return false;

    return binding->ops->handle_snapshot(binding, ctx->resource, snapshot);
}

static void cep_proxy_library_release(cepCell* cell, cepProxySnapshot* snapshot) {
    (void)cell;

    if ((snapshot->flags & CEP_PROXY_SNAPSHOT_INLINE) && snapshot->payload)
        cep_free((void*)snapshot->payload);
}

static bool cep_proxy_library_restore(cepCell* cell, const cepProxySnapshot* snapshot) {
    cepProxyLibraryCtx* ctx = cep_proxy_library_ctx(cell);
    if (!ctx)
        return false;

    const cepLibraryBinding* binding = cep_proxy_library_binding(ctx);
    if (!binding || !binding->ops)
        return false;

    cepCell* restored = NULL;
    bool ok;

    if (ctx->isStream) {
        if (!binding->ops->stream_restore)
            return false;
        ok = binding->ops->stream_restore(binding, snapshot, &restored);
    } else {
        if (!binding->ops->handle_restore)
            return false;
        ok = binding->ops->handle_restore(binding, snapshot, &restored);
    }

    if (!ok)
        return false;

    return cep_proxy_library_set_resource(cell, ctx, restored);
}

static void cep_proxy_library_finalize(cepCell* cell) {
    if (!cell || !cep_cell_is_proxy(cell))
        return;

    cepProxy* proxy = cell->proxy;
    if (!proxy)
        return;

    cepProxyLibraryCtx* ctx = (cepProxyLibraryCtx*)proxy->context;
    if (!ctx)
        return;

    cep_proxy_library_set_resource(cell, ctx, NULL);
    proxy->context = NULL;
    cep_free(ctx);
}

static const cepProxyOps cep_proxy_library_ops = {
    .snapshot = cep_proxy_library_snapshot,
    .release  = cep_proxy_library_release,
    .restore  = cep_proxy_library_restore,
    .finalize = cep_proxy_library_finalize,
};

/** Prepare a proxy-backed HANDLE so adapters can front opaque resources while
    still benefiting from proxy lifecycle management. The helper wires the
    library context, retains the source cell if provided, and records whether
    later operations should treat the resource as stream-less. */
void cep_proxy_initialize_handle(cepCell* cell, cepDT* name, cepCell* handle, cepCell* library) {
    assert(cell && name && cep_dt_is_valid(name));
    assert(library);

    cepProxyLibraryCtx* ctx = cep_malloc0(sizeof *ctx);
    ctx->library = library? cep_link_pull(library): NULL;
    ctx->resource = NULL;
    ctx->isStream = false;

    cep_proxy_initialize(cell, name, &cep_proxy_library_ops, ctx);

    if (handle)
        cep_proxy_library_set_resource(cell, ctx, handle);
}

/** Prepare a proxy-backed STREAM using the same library wiring as the handle
    helper but flagging the context so adapters expose streaming callbacks. The
    proxy is initialised first and then seeded with the optional stream resource
    so consumers can reach the live window immediately. */
void cep_proxy_initialize_stream(cepCell* cell, cepDT* name, cepCell* stream, cepCell* library) {
    assert(cell && name && cep_dt_is_valid(name));
    assert(library);

    cepProxyLibraryCtx* ctx = cep_malloc0(sizeof *ctx);
    ctx->library = library? cep_link_pull(library): NULL;
    ctx->resource = NULL;
    ctx->isStream = true;

    cep_proxy_initialize(cell, name, &cep_proxy_library_ops, ctx);

    if (stream)
        cep_proxy_library_set_resource(cell, ctx, stream);
}


void cep_data_history_push(cepData* data) {
    assert(data);

    if (!data->modified)
        return;

    cepDataNode* past = cep_malloc(sizeof *past);
    memcpy(past, (const cepDataNode*) &data->modified, sizeof *past);
    past->past = data->past;
    past->bindings = NULL;
    data->past = past;
}

void cep_data_history_clear(cepData* data) {
    if (!data)
        return;

    for (cepDataNode* node = data->past; node; ) {
        cepDataNode* previous = node->past;
        cep_free(node);
        node = previous;
    }

    data->past = NULL;
}


/*
    Include child storage techs
*/
#include "storage/cep_linked_list.h"
#include "storage/cep_dynamic_array.h"
#include "storage/cep_packed_queue.h"
#include "storage/cep_red_black_tree.h"
#include "storage/cep_hash_table.h"
#include "storage/cep_octree.h"

CEP_DEFINE_STATIC_DT(dt_meta_name,       CEP_ACRO("CEP"), CEP_WORD("meta"));
CEP_DEFINE_STATIC_DT(dt_parents_name,    CEP_ACRO("CEP"), CEP_WORD("parents"));
CEP_DEFINE_STATIC_DT(dt_parent_tag,      CEP_ACRO("CEP"), CEP_WORD("parent"));
CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));
CEP_DEFINE_STATIC_DT(dt_list_type,       CEP_ACRO("CEP"), CEP_WORD("list"));
CEP_DEFINE_STATIC_DT(dt_txn_name,        CEP_ACRO("CEP"), CEP_WORD("txn"));
CEP_DEFINE_STATIC_DT(dt_txn_state_name,  CEP_ACRO("CEP"), CEP_WORD("state"));



/***********************************************
 *                                             *
 * CEP Layer 0: Cells                          *
 *                                             *
 ***********************************************/


/* Allocate and initialise a cepData payload for a cell. Select the proper 
   storage strategy via the datatype, pull sizing/destructor arguments, seed 
   metadata, and expose the data pointer when requested. Centralise payload 
   allocation rules so all cells share consistent memory and timestamp semantics.
*/

#define VALUE_CAP_MIN       (sizeof((cepData){}.value))
#define DATA_HEAD_SIZE      (sizeof(cepData) - VALUE_CAP_MIN)

cepData* cep_data_new(  cepDT* type, unsigned datatype, bool writable,
                        void** dataloc, void* value, ...  ) {
    assert(cep_dt_is_valid(type) && (datatype < CEP_DATATYPE_COUNT));
    assert(!type->glob && "Glob tags are not legal for data descriptors");

    cepData* data;
    void*    address;
    va_list  args;
    va_start(args, value);

    switch (datatype) {
      case CEP_DATATYPE_VALUE: {
        size_t size     = va_arg(args, size_t);
        size_t capacity = va_arg(args, size_t);
        assert(capacity  &&  (capacity >= size));

        size_t dmax  = cep_max(VALUE_CAP_MIN, capacity);
        size_t alocz = DATA_HEAD_SIZE + dmax;

        if (size) {
            data = cep_malloc(alocz);
            memset(data, 0, DATA_HEAD_SIZE);
            memcpy(data->value, value, size);
        } else {
            data = cep_malloc0(alocz);
            size = capacity;
        }
        data->capacity = dmax;
        data->size     = size;

        address = data->value;
        break;
      }

      case CEP_DATATYPE_DATA: {
        size_t size       = va_arg(args, size_t);
        size_t capacity   = va_arg(args, size_t);
        cepDel destructor = va_arg(args, cepDel);
        assert(capacity  &&  (capacity >= size));

        data = cep_malloc0(sizeof(cepData));

        if (destructor) {
            data->data       = value;
            data->destructor = destructor;
        } else {
            if (size) {
                data->data = cep_malloc(capacity);
                memcpy(data->data, value, size);
            } else {
                data->data = cep_malloc0(capacity);
            }
            data->destructor = cep_free;
        }
        data->capacity = capacity;
        data->size     = size;

        address = data->data;
        break;
      }

      case CEP_DATATYPE_HANDLE: {
        cepCell* handle  = va_arg(args, cepCell*);
        cepCell* library = va_arg(args, cepCell*);
        assert(handle && library);

        data = cep_malloc0(sizeof(cepData));

        data->handle  = handle;
        data->library = library;
        data->capacity = 1;
        data->size = 0;

        const cepLibraryBinding* binding = cep_library_binding(library);
        if (binding && binding->ops && binding->ops->handle_retain)
            binding->ops->handle_retain(binding, handle);

        address = cep_cell_data(handle);
        break;
      }

      case CEP_DATATYPE_STREAM: {
        cepCell* stream  = va_arg(args, cepCell*);
        cepCell* library = va_arg(args, cepCell*);
        assert(stream && library);

        data = cep_malloc0(sizeof(cepData));

        data->stream  = stream;
        data->library = library;
        data->capacity = 1;
        data->size = 0;

        const cepLibraryBinding* binding = cep_library_binding(library);
        if (binding && binding->ops && binding->ops->handle_retain)
            binding->ops->handle_retain(binding, stream);

        address = cep_cell_data(stream);
        break;
      }
    }

    va_end(args);

    data->domain    = type->domain;
    data->tag       = type->tag;
    data->glob      = type->glob;
    data->datatype  = datatype;
    data->writable  = writable;
    data->lock      = 0u;
    data->lockOwner = NULL;
    
    cepOpCount timestamp = cep_cell_timestamp_next();
    data->created   = timestamp;
    data->modified  = timestamp;
    data->hash      = cep_data_compute_hash(data);
    data->bindings  = NULL;

    CEP_PTR_SEC_SET(dataloc, address);

    return data;
}


/* Release a cepData payload and its historical snapshots. Dispatch the stored 
   destructor for owned buffers, clear past nodes, and free the container. Prevent 
   memory leaks when a cell discards or replaces its payload.
*/
void cep_data_del(cepData* data) {
    assert(data);

    data->lock = 0u;
    data->lockOwner = NULL;

    switch (data->datatype) {
      case CEP_DATATYPE_DATA: {
        if (data->destructor)
            data->destructor(data->data);
        break;
      }
      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        if (data->library) {
            const cepLibraryBinding* binding = cep_library_binding(data->library);
            if (binding && binding->ops && binding->ops->handle_release) {
                cepCell* resource = (data->datatype == CEP_DATATYPE_HANDLE)? data->handle: data->stream;
                if (resource)
                    binding->ops->handle_release(binding, resource);
            }
        }
        break;
      }
    }

    cep_data_history_clear(data);
    cep_enzyme_binding_list_destroy(data->bindings);
    cep_free(data);
}


/* Retrieve the public pointer for a cell's payload. Switch on the datatype to 
   expose inline values or heap buffers while leaving handles/streams for 
   specialised APIs. Offer a single accessor so callers do not need to inspect 
   cepData internals.
*/
void* cep_data(const cepData* data) {
    assert(cep_data_valid(data));

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE: {
        return CEP_P(data->value);
      }

      case CEP_DATATYPE_DATA: {
        return data->data;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        // ToDo: pending!
        break;
      }
    }

    return NULL;
}



static cepData* cep_data_clone_payload(const cepData* data) {
    if (!data)
        return NULL;

    cepDT dt = data->dt;
    cepData* clone = NULL;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE: {
        clone = cep_data_new(&dt, CEP_DATATYPE_VALUE, data->writable, NULL, CEP_P(data->value), data->size, data->capacity);
        break;
      }

      case CEP_DATATYPE_DATA: {
        if (data->destructor && data->destructor != cep_free)
            return NULL;
        clone = cep_data_new(&dt, CEP_DATATYPE_DATA, data->writable, NULL, data->data, data->size, data->capacity, NULL);
        break;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        return NULL;
      }

      default:
        return NULL;
    }

    if (!clone)
        return NULL;

    clone->hash      = data->hash;
    clone->modified  = data->modified;
    clone->created   = data->created;
    clone->deleted   = data->deleted;
    clone->bindings  = NULL;
    clone->past      = NULL;
    clone->lock      = 0u;
    clone->lockOwner = NULL;
    clone->writable  = data->writable;

    return clone;
}


static cepStore* cep_store_clone_structure(const cepStore* store) {
    if (!cep_store_valid(store))
        return NULL;

    cepDT dt = store->dt;
    cepStore* clone = NULL;

    unsigned storage = store->storage;
    unsigned indexing = store->indexing;
    bool requiresCompare = (indexing == CEP_INDEX_BY_FUNCTION || indexing == CEP_INDEX_BY_HASH);
    cepCompare compare = store->compare;

    if (requiresCompare && !compare)
        return NULL;

    switch (storage) {
      case CEP_STORAGE_LINKED_LIST:
      case CEP_STORAGE_RED_BLACK_T: {
        if (requiresCompare)
            clone = cep_store_new(&dt, storage, indexing, compare);
        else
            clone = cep_store_new(&dt, storage, indexing);
        break;
      }

      case CEP_STORAGE_ARRAY: {
        size_t capacity = ((const cepArray*) store)->capacity;
        if (!capacity)
            capacity = cep_max(store->chdCount, (size_t)1);
        if (requiresCompare)
            clone = cep_store_new(&dt, storage, indexing, capacity, compare);
        else
            clone = cep_store_new(&dt, storage, indexing, capacity);
        break;
      }

      case CEP_STORAGE_PACKED_QUEUE: {
        size_t capacity = ((const cepPackedQ*) store)->nodeCapacity;
        if (!capacity)
            capacity = cep_max(store->chdCount, (size_t)1);
        clone = cep_store_new(&dt, storage, indexing, (int)capacity);
        break;
      }

      case CEP_STORAGE_HASH_TABLE: {
        size_t bucketHint = ((const cepHashTable*) store)->bucketCount;
        if (!bucketHint)
            bucketHint = cep_max(store->chdCount, (size_t)8);
        clone = cep_store_new(&dt, storage, indexing, bucketHint, compare);
        break;
      }

      case CEP_STORAGE_OCTREE: {
        const cepOctree* oct = (const cepOctree*) store;
        cepOctreeBound bound = oct->root.bound;
        clone = cep_store_new(&dt, storage, indexing, bound.center, (double)bound.subwide, compare);
        if (clone) {
            cepOctree* octClone = (cepOctree*) clone;
            octClone->maxDepth   = oct->maxDepth;
            octClone->maxPerNode = oct->maxPerNode;
            octClone->minSubwide = oct->minSubwide;
        }
        break;
      }

      default:
        return NULL;
    }

    if (!clone)
        return NULL;

    clone->autoid    = store->autoid;
    clone->created   = store->created;
    clone->deleted   = store->deleted;
    clone->modified  = store->modified;
    clone->writable  = store->writable;
    clone->lock      = 0u;
    clone->lockOwner = NULL;
    clone->bindings  = NULL;
    clone->past      = NULL;
    clone->chdCount  = 0;
    clone->totCount  = 0;
    clone->compare   = compare;

    return clone;
}


static void cep_cell_clone_cleanup(cepCell* cell) {
    if (!cell)
        return;

    if (cep_cell_is_normal(cell)) {
        if (cell->store) {
            bool writable = cell->store->writable;
            cell->store->writable = true;
            cep_store_delete_children_hard(cell->store);
            cell->store->writable = writable;
            cep_store_del(cell->store);
            cell->store = NULL;
        }
        if (cell->data) {
            cep_data_del(cell->data);
            cell->data = NULL;
        }
    }

    CEP_0(cell);
}


static bool cep_cell_clone_children(const cepCell* src, cepCell* dst) {
    if (!src || !dst || !src->store || !dst->store)
        return true;

    cepStore* store = dst->store;
    bool originalWritable = store->writable;
    store->writable = true;

    for (cepCell* child = cep_cell_first((cepCell*) src);
         child;
         child = cep_cell_next((cepCell*) src, child)) {
        cepCell temp = {0};
        if (!cep_cell_clone_into(child, &temp, true)) {
            store->writable = originalWritable;
            cep_cell_finalize_hard(&temp);
            return false;
        }

        cepCell* inserted;
        if (store->indexing == CEP_INDEX_BY_INSERTION)
            inserted = cep_cell_append(dst, false, &temp);
        else
            inserted = cep_cell_add(dst, 0, &temp);

        if (!inserted) {
            store->writable = originalWritable;
            cep_cell_finalize_hard(&temp);
            return false;
        }
    }

    store->writable = originalWritable;
    store->autoid   = src->store->autoid;
    store->created  = src->store->created;
    store->deleted  = src->store->deleted;
    store->modified = src->store->modified;
    store->totCount = src->store->totCount;
    store->lock     = 0u;
    store->lockOwner = NULL;
    store->bindings = NULL;
    store->past     = NULL;

    return true;
}


static bool cep_cell_clone_into(const cepCell* src, cepCell* dst, bool deep) {
    if (!src || !dst || !cep_cell_is_normal(src))
        return false;

    CEP_0(dst);

    bool resourceLink = (src->data && (src->data->datatype == CEP_DATATYPE_HANDLE || src->data->datatype == CEP_DATATYPE_STREAM));

    if (resourceLink) {
        /* Resource-backed payloads cannot be duplicated deterministically;
           represent the clone as a link to the original cell so both trees share
           the same upstream producer while still forming a navigable structure. */
        dst->metacell = src->metacell;
        dst->metacell.type        = CEP_TYPE_LINK;
        dst->metacell.shadowing   = CEP_SHADOW_NONE;
        dst->metacell.targetDead  = 0u;
        dst->parent = NULL;
        dst->link   = NULL;
        dst->created = src->created;
        dst->deleted = src->deleted;
        cep_link_set(dst, (cepCell*)src);
        return true;
    }

    dst->metacell = src->metacell;
    dst->metacell.shadowing  = CEP_SHADOW_NONE;
    dst->metacell.targetDead = 0u;
    dst->parent = NULL;
    dst->data   = NULL;
    dst->store  = NULL;
    dst->created = src->created;
    dst->deleted = src->deleted;

    if (src->data) {
        cepData* dataClone = cep_data_clone_payload(src->data);
        if (!dataClone)
            return false;
        dst->data = dataClone;
    }

    if (deep && src->store) {
        cepStore* storeClone = cep_store_clone_structure(src->store);
        if (!storeClone) {
            cep_cell_clone_cleanup(dst);
            return false;
        }

        cep_cell_set_store(dst, storeClone);

        if (!cep_cell_clone_children(src, dst)) {
            cep_cell_clone_cleanup(dst);
            return false;
        }
    }

    if (dst->data) {
        dst->data->hash      = src->data->hash;
        dst->data->modified  = src->data->modified;
        dst->data->created   = src->data->created;
        dst->data->deleted   = src->data->deleted;
        dst->data->writable  = src->data->writable;
        dst->data->lock      = 0u;
        dst->data->lockOwner = NULL;
    }

    return true;
}


/*
   Updates the data
*/
static inline void* cep_data_update(cepData* data, size_t size, size_t capacity, void* value, bool swap) {
    assert(cep_data_valid(data) && size && capacity);

    if (!data->writable)
        return NULL;

    if (data->lock)
        return NULL;

    if (!swap) {
        switch (data->datatype) {
          case CEP_DATATYPE_VALUE:
          case CEP_DATATYPE_DATA:
            if (cep_data_equals_bytes(data, value, size))
                return (void*)cep_data_payload(data);
            break;

          default:
            break;
        }
    }

    void* result = NULL;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE: {
        cep_data_history_push(data);
        assert(data->capacity >= capacity);
        memcpy(data->value, value, size);
        data->size = size;
        result = data->value;
        break;
      }

      case CEP_DATATYPE_DATA: {
        cep_data_history_push(data);
        assert(value);
        if (swap) {
            if (data->destructor)
                data->destructor(data->data);
            data->data     = value;
            data->capacity = capacity;
        } else {
            assert(data->capacity >= capacity);
            memcpy(data->data, value, size);
        }
        data->size = size;
        result = data->data;
        break;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        // ToDo: pending!
        break;
      }
    }

    if (result) {
        data->hash = cep_data_compute_hash(data);
        data->modified = cep_cell_timestamp_next();
    }

    return result;
}


static cepStoreHistoryEntry* cep_store_history_find_entry(const cepStoreHistory* history, const cepDT* name)
{
    if (!history || !history->entries)
        return NULL;

    for (size_t i = 0; i < history->entryCount; i++) {
        cepStoreHistoryEntry* entry = (cepStoreHistoryEntry*)&history->entries[i];
        if ((entry->name.domain == name->domain)
         && (entry->name.tag == name->tag))
            return entry;
    }

    return NULL;
}

static cepStoreHistory* cep_store_history_snapshot(const cepStore* store, const cepStoreHistory* previous)
{
    assert(store);

    cepStoreHistory* history = cep_malloc0(sizeof *history);
    memcpy(&history->node, (const cepStoreNode*)&store->modified, sizeof(history->node));
    history->node.past   = previous? (cepStoreNode*)&previous->node: NULL;
    history->node.linked = NULL;
    history->node.bindings = NULL;
    history->entryCount  = store->chdCount;

    if (history->entryCount) {
        history->entries = cep_malloc0(history->entryCount * sizeof *history->entries);
        size_t index = 0;
        for (cepCell* child = store_first_child(store); child; child = store_next_child(store, child)) {
            cepStoreHistoryEntry* entry = &history->entries[index++];
            entry->name     = cep_dt_clean(cep_cell_get_name(child));
            entry->modified = store->modified;
            entry->alive    = true;
            entry->cell     = child;
            entry->past     = previous? cep_store_history_find_entry(previous, &entry->name): NULL;
        }
    }

    return history;
}

static void cep_store_history_free(cepStoreHistory* history)
{
    if (!history)
        return;

    if (history->entries)
        cep_free(history->entries);

    cep_free(history);
}

/* Clone the current store layout so reindexing can replay the previous order.
   Regular edits never call this helper; timestamps alone carry history for
   append-only mutations. */
static void cep_store_history_push(cepStore* store)
{
    assert(store);

    if (!store->chdCount)
        return;

    const cepStoreHistory* previous = cep_store_history_from_const_node(store->past);
    cepStoreHistory* history = cep_store_history_snapshot(store, previous);
    history->node.past = store->past;
    store->past = &history->node;
}

static void cep_store_history_clear(cepStore* store)
{
    if (!store)
        return;

    for (cepStoreNode* node = store->past; node; ) {
        cepStoreHistory* history = cep_store_history_from_node(node);
        node = node->past;
        cep_store_history_free(history);
    }

    store->past = NULL;
}


#define CEP_SHADOW_INITIAL_CAPACITY   4U

static inline cepCell** cep_shadow_single_slot(cepCell* target) {
    return target->store? &target->store->linked: &target->linked;
}

static inline cepShadow** cep_shadow_multi_slot(cepCell* target) {
    return target->store? &target->store->shadow: &target->shadow;
}

static inline cepShadow* cep_shadow_multi_bucket(cepCell* target)
{
    cepShadow** slot = cep_shadow_multi_slot(target);
    return slot? *slot: NULL;
}

static cepShadow* cep_shadow_reserve(cepShadow* shadow, unsigned needed)
{
    unsigned capacity = shadow? shadow->capacity: 0U;
    if (capacity >= needed)
        return shadow;

    unsigned newCapacity = capacity? capacity: CEP_SHADOW_INITIAL_CAPACITY;
    while (newCapacity < needed)
        newCapacity *= 2U;

    size_t size = sizeof(cepShadow) + (size_t)newCapacity * sizeof(shadow->cell[0]);
    if (!shadow) {
        shadow = cep_malloc0(size);
    } else {
        unsigned oldCapacity = shadow->capacity;
        CEP_REALLOC(shadow, size);
        memset(&shadow->cell[oldCapacity], 0, (newCapacity - oldCapacity) * sizeof(shadow->cell[0]));
    }

    shadow->capacity = newCapacity;
    return shadow;
}

static void cep_shadow_attach(cepCell* target, cepCell* link)
{
    if (!target || !link)
        return;

    if (cep_cell_is_link(target)) {
        target = cep_link_pull(target);
        if (!target)
            return;
    }

    assert(cep_cell_is_link(link));

    cepCell** singleSlot   = cep_shadow_single_slot(target);
    cepShadow** multiSlot  = cep_shadow_multi_slot(target);

    cepShadow* bucket = multiSlot ? *multiSlot : NULL;
    cepCell* existingSingle = singleSlot ? *singleSlot : NULL;

    if (target->metacell.shadowing == CEP_SHADOW_NONE) {
        if (bucket && bucket->count) {
            target->metacell.shadowing = CEP_SHADOW_MULTIPLE;
        } else if (existingSingle) {
            target->metacell.shadowing = CEP_SHADOW_SINGLE;
        } else if (bucket) {
            *multiSlot = NULL;
            cep_free(bucket);
            bucket = NULL;
        }
    }

    if (target->metacell.shadowing == CEP_SHADOW_SINGLE && !existingSingle) {
        target->metacell.shadowing = CEP_SHADOW_NONE;
    } else if (target->metacell.shadowing == CEP_SHADOW_MULTIPLE && (!bucket || !bucket->count)) {
        if (bucket) {
            cep_free(bucket);
            *multiSlot = NULL;
            bucket = NULL;
        }
        if (existingSingle) {
            target->metacell.shadowing = CEP_SHADOW_SINGLE;
        } else {
            target->metacell.shadowing = CEP_SHADOW_NONE;
        }
    }

    switch (target->metacell.shadowing) {
      case CEP_SHADOW_NONE: {
        if (existingSingle && existingSingle == link)
            break;
        if (existingSingle && existingSingle != link) {
            cepShadow* shadow = cep_shadow_reserve(NULL, 2U);
            shadow->count = 0U;
            shadow->cell[shadow->count++] = existingSingle;
            shadow->cell[shadow->count++] = link;
            if (singleSlot)
                *singleSlot = NULL;
            if (multiSlot)
                *multiSlot = shadow;
            target->metacell.shadowing = CEP_SHADOW_MULTIPLE;
            break;
        }
        if (singleSlot)
            *singleSlot = link;
        target->metacell.shadowing = CEP_SHADOW_SINGLE;
        break;
      }

      case CEP_SHADOW_SINGLE: {
        cepCell* existing = existingSingle;
        if (!existing) {
            if (singleSlot)
                *singleSlot = link;
            break;
        }
        if (existing == link)
            break;

        cepShadow* shadow = cep_shadow_reserve(NULL, 2U);
        shadow->count = 0U;
        shadow->cell[shadow->count++] = existing;
        shadow->cell[shadow->count++] = link;

        if (singleSlot)
            *singleSlot = NULL;
        if (multiSlot)
            *multiSlot  = shadow;
        target->metacell.shadowing = CEP_SHADOW_MULTIPLE;
        break;
      }

      case CEP_SHADOW_MULTIPLE: {
        cepShadow* shadow = bucket;
        if (!shadow) {
            shadow = cep_shadow_reserve(NULL, 2U);
            shadow->count = 0U;
            if (existingSingle)
                shadow->cell[shadow->count++] = existingSingle;
        }

        for (unsigned i = 0; i < shadow->count; i++)
            if (shadow->cell[i] == link) {
                if (!bucket && multiSlot)
                    *multiSlot = shadow;
                goto shadow_done;
            }

        shadow = cep_shadow_reserve(shadow, shadow->count + 1U);
        shadow->cell[shadow->count++] = link;
        if (multiSlot)
            *multiSlot = shadow;
        break;
      }
    }

shadow_done:
    link->metacell.targetDead = cep_cell_is_deleted(target);
}

static void cep_shadow_detach(cepCell* target, const cepCell* link)
{
    if (!target || !link)
        return;

    cepCell** singleSlot   = cep_shadow_single_slot(target);
    cepShadow** multiSlot  = cep_shadow_multi_slot(target);

    switch (target->metacell.shadowing) {
      case CEP_SHADOW_NONE:
        break;

      case CEP_SHADOW_SINGLE: {
        assert(singleSlot);
        assert(*singleSlot == link);
        ((cepCell*)link)->metacell.targetDead = 0;
        *singleSlot = NULL;
        target->metacell.shadowing = CEP_SHADOW_NONE;
        break;
      }

      case CEP_SHADOW_MULTIPLE: {
        cepShadow* shadow = *multiSlot;
        assert(shadow && shadow->count);

        unsigned index = shadow->count;
        for (unsigned i = 0; i < shadow->count; i++) {
            if (shadow->cell[i] == link) {
                index = i;
                break;
            }
        }

        assert(index < shadow->count);

        ((cepCell*)link)->metacell.targetDead = 0;

        unsigned last = shadow->count - 1U;
        if (index != last)
            shadow->cell[index] = shadow->cell[last];
        shadow->cell[last] = NULL;
        shadow->count = last;

        if (!shadow->count) {
            target->metacell.shadowing = CEP_SHADOW_NONE;
            *singleSlot = NULL;
            *multiSlot  = NULL;
            cep_free(shadow);
        } else if (shadow->count == 1U) {
            target->metacell.shadowing = CEP_SHADOW_SINGLE;
            *singleSlot = shadow->cell[0];
            *multiSlot  = NULL;
            cep_free(shadow);
        } else {
            *multiSlot = shadow;
        }
        break;
      }
    }
}

/** Flag link shadows when a target cell dies so lookups avoid stale entries and
    resurrected cells clear the state consistently. The helper walks the shadow
    list and mirrors the @p dead flag onto every referencing link, keeping link
    callers in sync with the origin cell's visibility. */
void cep_cell_shadow_mark_target_dead(cepCell* target, bool dead) {
    if (!target || cep_cell_is_void(target))
        return;

    if (!cep_cell_is_normal(target) || !cep_cell_is_shadowed(target))
        return;

    switch (target->metacell.shadowing) {
      case CEP_SHADOW_SINGLE: {
        cepCell** slot = cep_shadow_single_slot(target);
        cepCell* link = slot ? *slot : NULL;
        if (link) {
            assert(cep_cell_is_link(link));
            link->metacell.targetDead = dead;
        }
        break;
      }

      case CEP_SHADOW_MULTIPLE: {
        cepShadow* shadow = cep_shadow_multi_bucket(target);
        if (!shadow)
            break;
        for (unsigned i = 0; i < shadow->count; ++i) {
            cepCell* link = shadow->cell[i];
            if (link) {
                assert(cep_cell_is_link(link));
                link->metacell.targetDead = dead;
            }
        }
        break;
      }

      case CEP_SHADOW_NONE:
        break;
    }
}


static void cep_shadow_break_all(cepCell* target)
{
    if (!target)
        return;

    while (cep_cell_is_shadowed(target)) {
        switch (target->metacell.shadowing) {
          case CEP_SHADOW_SINGLE: {
            cepCell** slot = cep_shadow_single_slot(target);
            cepCell* link = slot? *slot: NULL;
            assert(link);
            cep_link_set(link, NULL);
            break;
          }

          case CEP_SHADOW_MULTIPLE: {
            cepShadow* shadow = cep_shadow_multi_bucket(target);
            assert(shadow && shadow->count);
            cepCell* link = shadow->cell[shadow->count - 1];
            assert(link);
            cep_link_set(link, NULL);
            break;
          }

          case CEP_SHADOW_NONE:
            return;
        }
    }
}


static void cep_shadow_rebind_links(cepCell* target)
{
    if (!target || !cep_cell_is_shadowed(target))
        return;

    switch (target->metacell.shadowing) {
      case CEP_SHADOW_SINGLE: {
        cepCell** slot = cep_shadow_single_slot(target);
        cepCell* link = slot? *slot: NULL;
        assert(link);
        link->link = target;
        link->metacell.targetDead = cep_cell_is_deleted(target);
        break;
      }

      case CEP_SHADOW_MULTIPLE: {
        cepShadow* shadow = cep_shadow_multi_bucket(target);
        assert(shadow);
        for (unsigned i = 0; i < shadow->count; i++) {
            cepCell* link = shadow->cell[i];
            assert(link);
            link->link = target;
            link->metacell.targetDead = cep_cell_is_deleted(target);
        }
        break;
      }

      case CEP_SHADOW_NONE:
        break;
    }
}


void cep_link_set(cepCell* link, cepCell* target)
{
    assert(link && cep_cell_is_link(link));

    cepCell* resolved = NULL;
    if (target) {
        assert(target != link);
        resolved = cep_link_pull(target);
        assert(resolved && !cep_cell_is_void(resolved));
        assert(!cep_cell_is_link(resolved));
        assert(resolved != link);
        assert(cep_cell_parent(resolved));   // Links to root are not allowed.

        const cepCell* target_veil_root = cep_cell_top_veiled_ancestor(resolved);
        if (target_veil_root) {
            if (target_veil_root == resolved) {
                assert(!"Cannot link to a veiled root before it is unveiled");
                return;
            }
            const cepCell* link_veil_root = cep_cell_top_veiled_ancestor(link);
            if (link_veil_root != target_veil_root) {
                assert(!"Links to veiled subtrees must remain inside the veiled ancestor");
                return;
            }
        }
    }

    cepCell* current = link->link;
    if (current == resolved)
        return;

    if (current)
        cep_shadow_detach(current, link);

    if (resolved) {
        link->metacell.targetDead = cep_cell_is_deleted(resolved);
    } else {
        link->metacell.targetDead = 0;
    }

    link->link = resolved;

    if (resolved)
        cep_shadow_attach(resolved, link);
}


void cep_link_initialize(cepCell* link, cepDT* name, cepCell* target)
{
    assert(link);
    cep_cell_initialize(link, CEP_TYPE_LINK, name, (cepData*) target, NULL);
}


cepCell* cep_link_pull(cepCell* link)
{
    assert(link);

    while (cep_cell_is_link(link)) {
        cepCell* next = link->link;
        assert(next && !cep_cell_is_void(next));
        assert(next != link);
        link = next;
    }

    return link;
}

bool cep_cell_require_store(cepCell** cell_ptr, cepStore** store_out) {
    if (!cell_ptr || !*cell_ptr) {
        return false;
    }

    cepCell* cell = *cell_ptr;
    if (cep_cell_is_void(cell)) {
        return false;
    }

    cell = cep_link_pull(cell);
    if (!cep_cell_is_normal(cell) || !cell->store) {
        return false;
    }

    *cell_ptr = cell;
    if (store_out) {
        *store_out = cell->store;
    }
    return true;
}

bool cep_cell_require_dictionary_store(cepCell** cell_ptr) {
    cepStore* store = NULL;
    if (!cep_cell_require_store(cell_ptr, &store)) {
        return false;
    }

    if (store->indexing == CEP_INDEX_BY_NAME) {
        return true;
    }

    cep_cell_to_dictionary(*cell_ptr);
    return cep_cell_require_store(cell_ptr, NULL);
}

bool cep_cell_require_data(cepCell** cell_ptr, cepData** data_out) {
    if (!cell_ptr || !*cell_ptr) {
        return false;
    }

    cepCell* cell = *cell_ptr;
    if (cep_cell_is_void(cell)) {
        return false;
    }

    cell = cep_link_pull(cell);
    if (!cep_cell_is_normal(cell) || !cell->data) {
        return false;
    }

    *cell_ptr = cell;
    if (data_out) {
        *data_out = cell->data;
    }
    return true;
}

cepCell* cep_cell_resolve(cepCell* cell) {
    if (!cell) {
        return NULL;
    }
    return cep_link_pull(cell);
}

cepCell* cep_cell_resolve_child(cepCell* parent, cepCell* child) {
    if (!parent || !child) {
        return NULL;
    }

    if (!cep_cell_require_store(&parent, NULL)) {
        return NULL;
    }

    child = cep_link_pull(child);
    if (!child) {
        return NULL;
    }

    return (child->parent == parent->store) ? child : NULL;
}

bool cep_cell_child_belongs_to(const cepCell* parent, const cepCell* child) {
    if (!parent || !child) {
        return false;
    }
    cepCell* resolved_parent = cep_cell_resolve((cepCell*)parent);
    cepCell* resolved_child = cep_cell_resolve((cepCell*)child);
    if (!resolved_parent || !resolved_child) {
        return false;
    }
    if (!cep_cell_has_store(resolved_parent)) {
        return false;
    }
    return resolved_child->parent == resolved_parent->store;
}

cepCell* cep_cell_ensure_dictionary_child(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    /* Ensure the child is a writable dictionary before mutating; see the
       append-only guidelines in docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md. */
    if (!cep_cell_require_store(&parent, NULL)) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(name);
    cepCell* child = cep_cell_find_by_name(parent, &lookup);
    if (child) {
        if (!cep_cell_require_dictionary_store(&child)) {
            return NULL;
        }
        return child;
    }

    cepDT name_copy = lookup;
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    unsigned store_kind = storage ? storage : CEP_STORAGE_RED_BLACK_T;
    return cep_dict_add_dictionary(parent, &name_copy, &dict_type, store_kind);
}

cepCell* cep_cell_ensure_list_child(cepCell* parent, const cepDT* name, unsigned storage) {
    if (!parent || !name) {
        return NULL;
    }

    if (!cep_cell_require_store(&parent, NULL)) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(name);
    cepCell* child = cep_cell_find_by_name(parent, &lookup);
    if (child) {
        cepCell* resolved = cep_cell_resolve(child);
        if (!resolved || !cep_cell_has_store(resolved)) {
            return NULL;
        }
        if (resolved->store->indexing != CEP_INDEX_BY_INSERTION) {
            return NULL;
        }
        return resolved;
    }

    cepDT name_copy = lookup;
    cepDT list_type = *CEP_DTAW("CEP", "list");
    unsigned store_kind = storage ? storage : CEP_STORAGE_ARRAY;
    return cep_dict_add_list(parent, &name_copy, &list_type, store_kind);
}

bool cep_cell_put_text(cepCell* parent, const cepDT* field, const char* text) {
    if (!parent || !field || !text) {
        return false;
    }

    if (!cep_cell_require_dictionary_store(&parent)) {
        return false;
    }

    cepStore* store = NULL;
    if (!cep_cell_require_store(&parent, &store)) {
        return false;
    }

    bool restore_writable = false;
    unsigned writable_before = 0u;
    if (store && !store->writable) {
        writable_before = store->writable;
        store->writable = true;
        restore_writable = true;
    }

    bool success = false;
    cepDT lookup = cep_dt_clean(field);
    cepCell* existing = cep_cell_find_by_name(parent, &lookup);
    if (existing) {
        cep_cell_remove_hard(parent, existing);
    }

    size_t len = strlen(text) + 1u;
    const cepDT* payload_ref = CEP_DTAW("CEP", "text");
    cepDT payload_type = *payload_ref;

    cepCell* node = NULL;

    if (len <= sizeof(((cepData*)0)->value)) {
        node = cep_dict_add_value(parent, &lookup, &payload_type, (void*)text, len, len);
        success = (node != NULL);
    } else {
        char* copy = cep_malloc(len);
        if (copy) {
            memcpy(copy, text, len);
            node = cep_dict_add_data(parent, &lookup, &payload_type, copy, len, len, cep_free);
            if (!node) {
                cep_free(copy);
            } else {
                success = true;
            }
        }
    }

    if (node) {
        cep_cell_content_hash(node);
    }

    if (restore_writable) {
        store->writable = writable_before;
    }

    return success;
}

bool cep_cell_put_uint64(cepCell* parent, const cepDT* field, uint64_t value) {
    char buffer[32];
    int written = snprintf(buffer, sizeof buffer, "%" PRIu64, (unsigned long long)value);
    if (written <= 0 || (size_t)written >= sizeof buffer) {
        return false;
    }
    return cep_cell_put_text(parent, field, buffer);
}

bool cep_cell_put_dt(cepCell* parent, const cepDT* field, const cepDT* value) {
    if (!parent || !field || !value) {
        return false;
    }

    cepCell* container = cep_cell_ensure_dictionary_child(parent, field, CEP_STORAGE_RED_BLACK_T);
    if (!container) {
        return false;
    }

    if (!cep_cell_put_uint64(container, CEP_DTAW("CEP", "domain"), cep_id(value->domain))) {
        return false;
    }
    return cep_cell_put_uint64(container, CEP_DTAW("CEP", "tag"), cep_id(value->tag));
}

void cep_cell_clear_children(cepCell* cell) {
    if (!cep_cell_require_store(&cell, NULL)) {
        return;
    }

    while (cep_cell_children(cell) > 0u) {
        cepCell* child = cep_cell_first(cell);
        cep_cell_remove_hard(cell, child);
    }
}

bool cep_cell_copy_children(const cepCell* source, cepCell* dest, bool deep_clone) {
    if (!dest) {
        return false;
    }

    if (!cep_cell_require_store(&dest, NULL)) {
        return false;
    }

    cep_cell_clear_children(dest);

    if (!source) {
        return true;
    }

    cepCell* resolved_source = cep_cell_resolve((cepCell*)source);
    if (!resolved_source || !cep_cell_has_store(resolved_source)) {
        return true;
    }

    for (cepCell* child = cep_cell_first(resolved_source); child; child = cep_cell_next(resolved_source, child)) {
        cepCell* clone = deep_clone ? cep_cell_clone_deep(child) : cep_cell_clone(child);
        if (!clone) {
            continue;
        }
        cep_cell_add(dest, 0, clone);
        cep_free(clone);
    }
    return true;
}


static bool cep_data_structural_equal(const cepData* existing, const cepData* incoming)
{
    if (existing == incoming)
        return true;
    if (!existing || !incoming)
        return false;

    if (existing->datatype != incoming->datatype)
        return false;

    if (existing->size != incoming->size)
        return false;

    switch (existing->datatype) {
      case CEP_DATATYPE_VALUE:
      case CEP_DATATYPE_DATA:
        return cep_data_equals_bytes(existing, cep_data_payload(incoming), incoming->size);

      case CEP_DATATYPE_HANDLE:
        return existing->handle == incoming->handle
            && existing->library == incoming->library;

      case CEP_DATATYPE_STREAM:
        return existing->stream == incoming->stream
            && existing->library == incoming->library;
    }

    return false;
}


/* Construct a child store backend for a cell. Allocate the requested storage 
   engine via varargs configuration and seed store metadata and timestamps. 
   Centralise child container creation so indexing behaviour stays consistent 
   across storage types.

    Creates a new child store for cells:
    ------------------------------------
    
    Parameters:
    
    - dt:      Domain/Tag that describes children stored here.
    
    - storage: One of CEP_STORAGE_* (data structure used).
        - CEP_STORAGE_LINKED_LIST:
            No extra arguments.
        - CEP_STORAGE_ARRAY:
            size_t capacity.
        - CEP_STORAGE_PACKED_QUEUE:
            size_t capacity.
            Notes: indexing must be CEP_INDEX_BY_INSERTION.
        - CEP_STORAGE_RED_BLACK_T:
            No storage-specific arguments.
            Notes: indexing cannot be CEP_INDEX_BY_INSERTION.
        - CEP_STORAGE_HASH_TABLE:
            size_t capacity.
            Notes: indexing must be CEP_INDEX_BY_HASH.
        - CEP_STORAGE_OCTREE:
            float* center, double subwide, cepCompare compare.
            Notes: indexing must be CEP_INDEX_BY_FUNCTION. The compare callback
                   checks whether a child fits within the bound (return > 0 when
                   it fits; <= 0 otherwise). The extra arguments carry the bound
                   centre (XYZ) and half-width.

    - indexing: One of CEP_INDEX_* (ordering strategy).
        - If 'indexing' is CEP_INDEX_BY_FUNCTION or CEP_INDEX_BY_HASH, append a
          cepCompare compare callback. This is used to order or look up children.
          CEP_INDEX_BY_NAME uses the default domain/tag comparison; CEP_INDEX_BY_INSERTION
          requires no comparator.
*/
cepStore* cep_store_new(cepDT* dt, unsigned storage, unsigned indexing, ...) {
    assert(cep_dt_is_valid(dt) && !dt->glob && (storage < CEP_STORAGE_COUNT) && (indexing < CEP_INDEX_COUNT));

    cepStore* store;
    va_list  args;
    va_start(args, indexing);

    switch (storage) {
      case CEP_STORAGE_LINKED_LIST: {
        store = (cepStore*) list_new();
        break;
      }
      case CEP_STORAGE_ARRAY: {
        size_t capacity = va_arg(args, size_t);
        assert(capacity);
        store = (cepStore*) array_new(capacity);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        size_t capacity = va_arg(args, size_t);
        assert(capacity  &&  (indexing == CEP_INDEX_BY_INSERTION));
        store =(cepStore*) packed_q_new(capacity);
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        assert(indexing != CEP_INDEX_BY_INSERTION);
        store = (cepStore*) rb_tree_new();
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        size_t capacity = va_arg(args, size_t);
        assert(capacity && indexing == CEP_INDEX_BY_HASH);
        store = (cepStore*) hash_table_new(capacity);
        break;
      }
      case CEP_STORAGE_OCTREE: {
        float* center  = va_arg(args, float*);
        float  subwide = va_arg(args, double);
        assert(center  &&  (indexing == CEP_INDEX_BY_FUNCTION));
        cepOctreeBound bound;
        bound.subwide = subwide;
        memcpy(&bound.center, center, sizeof(bound.center));
        store = (cepStore*) octree_new(&bound);
        break;
      }
    }

    if (indexing == CEP_INDEX_BY_FUNCTION
     || indexing == CEP_INDEX_BY_HASH) {
        cepCompare compare = va_arg(args, cepCompare);
        assert(compare);
        store->compare = compare;
    }

    va_end(args);

    store->domain   = dt->domain;
    store->tag      = dt->tag;
    store->glob     = dt->glob;
    store->storage  = storage;
    store->indexing = indexing;
    store->writable = true;
    store->autoid   = 1;
    store->chdCount = 0;
    store->totCount = 0;
    store->lock     = 0u;
    store->lockOwner = NULL;

    cepOpCount timestamp = cep_cell_timestamp_next();
    store->created  = timestamp;
    store->modified = timestamp;
    store->bindings = NULL;

    return store;
}


/* Dispose of a child store and all of its managed cells. Clear historical 
   snapshots, stamp a deletion heartbeat, and call the backend-specific 
   destructors. Ensure store teardown releases every child resource and records 
   the event for history queries.
*/
void cep_store_del(cepStore* store) {
    assert(cep_store_valid(store));

    // ToDo: cleanup shadows.

    store->lock = 0u;
    store->lockOwner = NULL;

    cep_store_history_clear(store);
    cep_enzyme_binding_list_destroy(store->bindings);
    store->bindings = NULL;

    store->deleted = cep_cell_timestamp_next();

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        list_del_all_children((cepList*) store);
        list_del((cepList*) store);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        array_del_all_children((cepArray*) store);
        array_del((cepArray*) store);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        packed_q_del_all_children((cepPackedQ*) store);
        packed_q_del((cepPackedQ*) store);
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        rb_tree_del_all_children((cepRbTree*) store);
        rb_tree_del((cepRbTree*) store);
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        hash_table_del_all_children((cepHashTable*) store);
        hash_table_del((cepHashTable*) store);
        break;
      }
      case CEP_STORAGE_OCTREE: {
        octree_del_all_children((cepOctree*) store);
        octree_del((cepOctree*) store);
        break;
      }
    }
}


/* Remove every child cell from a store while preserving the store itself.
   This is a destructive GC helper: we bypass append-only guarantees and wipe
   the backing container directly, so callers should use the soft delete path
   whenever history needs to stay observable.
*/
void cep_store_delete_children_hard(cepStore* store) {
    assert(cep_store_valid(store));

    bool had_children = store->chdCount;

    if (!had_children || cep_store_hierarchy_locked(store->owner))
        return;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        list_del_all_children((cepList*) store);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        array_del_all_children((cepArray*) store);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        packed_q_del_all_children((cepPackedQ*) store);
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        rb_tree_del_all_children((cepRbTree*) store);
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        hash_table_del_all_children((cepHashTable*) store);
        break;
      }
      case CEP_STORAGE_OCTREE: {
        octree_del_all_children((cepOctree*) store);
        break;
      }
    }

    store->chdCount = 0;
    store->autoid   = 1;

    if (had_children)
        store->modified = cep_cell_timestamp_next();
}


/*
    Assign auto-id if necessary:
    Cells that want CEP to pick the numeric tag should prime their metacell tag
    with CEP_AUTOID before insertion; user-assigned numeric tags skip this path.
*/
static inline void store_check_auto_id(cepStore* store, cepCell* child) {
    if (cep_cell_id_is_pending(child)) {
        child->metacell.tag = cep_id_to_numeric(store->autoid++);
        child->metacell.glob = 0;
        return;
    }

    cepID tag = cep_id(child->metacell.tag);
    if (tag) {
        if (tag > CEP_AUTOID_MAXVAL) {
            assert(!"Requested tag exceeds CEP auto-id range");
            return;
        }
        cepID next = cep_id_to_numeric(store->autoid);
        if (tag >= next) {
            store->autoid = (tag + 1u);
        }
    }
}


static cepCell* cep_store_replace_child(cepStore* store, cepCell* existing, cepCell* incoming) {
    assert(cep_store_valid(store));
    assert(existing && incoming);
    assert(cep_cell_is_normal(existing) && cep_cell_is_normal(incoming));

    cepOpCount timestamp = cep_cell_timestamp_next();

    cep_cell_finalize_hard(existing);
    CEP_0(existing);

    cep_cell_transfer(incoming, existing);
    CEP_0(incoming);

    store_check_auto_id(store, existing);

    existing->parent = store;
    cep_cell_apply_parent_veil(existing, store->owner);
    store->modified = timestamp;

    return existing;
}


/* Insert a child cell into a store according to its indexing policy.
   Deduplicate structural matches, then delegate to the backend-specific helper
   before updating metadata. Append-only invariant: mutations must leave the
   sibling ordering intact so historical traversals can rebuild the directory
   (see docs/L0_KERNEL/APPEND-ONLY-AND-IDEMPOTENCY.md).
*/
/* Insert a child into a parent store, keeping append-only invariants intact.
   Behaviour is documented in docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md. */
cepCell* cep_store_add_child(cepStore* store, uintptr_t context, cepCell* child) {
    if (!cep_store_valid(store) || cep_cell_is_void(child)) {
        fprintf(stderr,
            "DEBUG store_add_child invalid store=%p valid=%d child=%p child_type=%u\n",
            (void*)store,
            (int)cep_store_valid(store),
            (void*)child,
            child ? child->metacell.type : 0u);
        fflush(stderr);
        assert(cep_store_valid(store) && !cep_cell_is_void(child));
    }

    if (!store->writable || cep_store_hierarchy_locked(store->owner))
        return NULL;

    cepCell* existing = NULL;

    if (store->indexing == CEP_INDEX_BY_NAME) {
        existing = store_find_child_by_name(store, cep_cell_get_name(child));
    } else if (store->indexing == CEP_INDEX_BY_INSERTION) {
        if (store->chdCount && store->chdCount > (size_t)context) {
            existing = store_find_child_by_position(store, (size_t)context);
        }
    } else if (store->indexing == CEP_INDEX_BY_FUNCTION
            || store->indexing == CEP_INDEX_BY_HASH) {
        assert(store->compare);
        existing = store_find_child_by_key(store, child, store->compare, (void*)context);
    }

    if (existing) {
        if (cep_cell_structural_equal(existing, child))
            return existing;
        if (store->indexing != CEP_INDEX_BY_INSERTION)
            return cep_store_replace_child(store, existing, child);
        existing = NULL;
    }

    cepCell* cell;

    switch (store->indexing) {
      case CEP_INDEX_BY_INSERTION:
      {
        assert(store->chdCount >= (size_t)context);

        switch (store->storage) {
          case CEP_STORAGE_LINKED_LIST: {
            cell = list_insert((cepList*) store, child, (size_t)context);
            break;
          }
          case CEP_STORAGE_ARRAY: {
            cell = array_insert((cepArray*) store, child, (size_t)context);
            break;
          }
          default: {
            assert(store->storage < CEP_STORAGE_PACKED_QUEUE);
            return NULL;
          }
        }
        break;
      }

      case CEP_INDEX_BY_NAME:
      {
        switch (store->storage) {
          case CEP_STORAGE_LINKED_LIST: {
            cell = list_named_insert((cepList*) store, child);
            break;
          }
          case CEP_STORAGE_ARRAY: {
            cell = array_named_insert((cepArray*) store, child);
            break;
          }
          case CEP_STORAGE_RED_BLACK_T: {
            cell = rb_tree_named_insert((cepRbTree*) store, child);
            break;
          }
          default: {
            assert(store->indexing != CEP_INDEX_BY_NAME);
            return NULL;
          }
        }
        break;
      }

      case CEP_INDEX_BY_FUNCTION:
      case CEP_INDEX_BY_HASH:
      {
        switch (store->storage) {
          case CEP_STORAGE_LINKED_LIST: {
            cell = list_sorted_insert((cepList*) store, child, store->compare, (void*)context);
            break;
          }
          case CEP_STORAGE_ARRAY: {
            cell = array_sorted_insert((cepArray*) store, child, store->compare, (void*)context);
            break;
          }
          case CEP_STORAGE_PACKED_QUEUE: {
            assert(store->storage != CEP_STORAGE_PACKED_QUEUE);
            return NULL;
          }
          case CEP_STORAGE_RED_BLACK_T: {
            cell = rb_tree_sorted_insert((cepRbTree*) store, child, store->compare, (void*)context);
            break;
          }
          case CEP_STORAGE_HASH_TABLE: {
            cell = hash_table_sorted_insert((cepHashTable*) store, child, store->compare, (void*)context);
            break;
          }
          case CEP_STORAGE_OCTREE: {
            cell = octree_sorted_insert((cepOctree*) store, child, store->compare, (void*)context);
            break;
          }
        }
        break;
      }
    }

    store_check_auto_id(store, cell);

    //cep_cell_transfer(child, cell);
    CEP_0(child);      // This avoids deleting children during move operations.

    cell->parent = store;
    cep_cell_apply_parent_veil(cell, store->owner);
    store->chdCount++;
    store->totCount++;

    store->modified = cep_cell_timestamp_next();   // Append-only trail lives in timestamps.

    return cell;
}


/* Append or prepend a child cell into an insertion-ordered store. Optionally
   deduplicate, call the backend append helper, then patch parent pointers and
   metadata. Keep the append-only contract: we rely on timestamps instead of
   snapshots, so ordering must not be disturbed.
*/
cepCell* cep_store_append_child(cepStore* store, bool prepend, cepCell* child) {
    assert(cep_store_valid(store) && !cep_cell_is_void(child));

    if (!store->writable || cep_store_hierarchy_locked(store->owner))
        return NULL;

    if (store->indexing == CEP_INDEX_BY_INSERTION && store->chdCount) {
        cepCell* existing = prepend? store_first_child(store): store_last_child(store);
        if (existing && cep_cell_structural_equal(existing, child))
            return existing;
    }

    cepCell* cell;

    if (store->indexing != CEP_INDEX_BY_INSERTION) {
        assert(store->indexing == CEP_INDEX_BY_INSERTION);
        return NULL;
    }

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        cell = list_append((cepList*) store, child, prepend);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        cell = array_append((cepArray*) store, child, prepend);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        cell = packed_q_append((cepPackedQ*) store, child, prepend);
        break;
      }
      default: {
        assert(store->storage < CEP_STORAGE_RED_BLACK_T);
        return NULL;
      }
    }

    store_check_auto_id(store, cell);

    //cep_cell_transfer(child, cell);
    CEP_0(child);

    cell->parent = store;
    cep_cell_apply_parent_veil(cell, store->owner);
    store->chdCount++;
    store->totCount++;

    store->modified = cep_cell_timestamp_next();   // Append-only trail lives in timestamps.

    return cell;
}


/* Retrieve the first child visible at a given snapshot. Resolve the parent 
   store (following links) and iterate from the head until a child satisfies the 
   snapshot filter. Anchor snapshot-aware traversal at the beginning of the 
   sibling list.
*/
static inline cepCell* store_first_child(const cepStore* store) {
    assert(cep_store_valid(store));

    if (!store->chdCount)
        return NULL;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_first((cepList*) store);
      }
      case CEP_STORAGE_ARRAY: {
        return array_first((cepArray*) store);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_first((cepPackedQ*) store);
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_first((cepRbTree*) store);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_first((cepHashTable*) store);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_first((cepOctree*) store);
      }
    }
    return NULL;
}


/*
    Gets the last child cell from store
*/
static inline cepCell* store_last_child(const cepStore* store) {
    assert(cep_store_valid(store));

    if (!store->chdCount)
        return NULL;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_last((cepList*) store);
      }
      case CEP_STORAGE_ARRAY: {
        return array_last((cepArray*) store);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_last((cepPackedQ*) store);
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_last((cepRbTree*) store);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_last((cepHashTable*) store);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_last((cepOctree*) store);
      }
    }
    return NULL;
}


/*
    Retrieves a child cell by its ID
*/
static inline cepCell* store_find_child_by_name(const cepStore* store, const cepDT* name) {
    assert(cep_store_valid(store) && cep_dt_is_valid(name));

    if (!store->chdCount)
        return NULL;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_find_by_name((cepList*) store, name);
      }
      case CEP_STORAGE_ARRAY: {
        return array_find_by_name((cepArray*) store, name);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_find_by_name((cepPackedQ*) store, name);
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_find_by_name((cepRbTree*) store, name);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_find_by_name((cepHashTable*) store, name);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_find_by_name((cepOctree*) store, name);
      }
    }
    return NULL;
}



/* Locate a child that matches an arbitrary compare function. Resolve the 
   parent store and delegate to the backend key search helper. Allow callers to 
   reuse store ordering without reimplementing comparisons.
*/
static inline cepCell* store_find_child_by_key(const cepStore* store, cepCell* key, cepCompare compare, void* context) {
    assert(cep_store_valid(store) && !cep_cell_is_void(key) && compare);

    if (!store->chdCount)
        return NULL;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_find_by_key((cepList*) store, key, compare, context);
      }
      case CEP_STORAGE_ARRAY: {
        return array_find_by_key((cepArray*) store, key, compare, context);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        assert(store->storage != CEP_STORAGE_PACKED_QUEUE);   // Unsupported.
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_find_by_key((cepRbTree*) store, key, compare, context);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_find_by_key((cepHashTable*) store, key, compare, context);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_find_by_key((cepOctree*) store, key, compare, context);
      }
    }
    return NULL;
}


/*
    Gets the cell at index position from store
*/
static inline cepCell* store_find_child_by_position(const cepStore* store, size_t position) {
    assert(cep_store_valid(store));

    if (store->chdCount <= position)
        return NULL;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_find_by_position((cepList*) store, position);
      }
      case CEP_STORAGE_ARRAY: {
        return array_find_by_position((cepArray*) store, position);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_find_by_position((cepPackedQ*) store, position);
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_find_by_position((cepRbTree*) store, position);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_find_by_position((cepHashTable*) store, position);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_find_by_position((cepOctree*) store, position);
      }
    }

    return NULL;
}


/* Return the previous sibling that exists at a snapshot. Walk backward from 
   the given child, skipping entries that do not match the snapshot filter. 
   Support bidirectional snapshot traversal across siblings.
*/
static inline cepCell* store_prev_child(const cepStore* store, cepCell* child) {
    assert(!cep_cell_is_void(child));

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_prev(child);
      }
      case CEP_STORAGE_ARRAY: {
        return array_prev((cepArray*) store, child);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_prev((cepPackedQ*) store, child);
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_prev(child);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_prev((cepHashTable*) store, child);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_prev(child);
      }
    }

    return NULL;
}


/* Return the next sibling that exists at a snapshot. Walk forward from the 
   given child, ignoring siblings that are invisible at the requested timestamp. 
   Enable forward iteration that honours historical visibility rules.
*/
static inline cepCell* store_next_child(const cepStore* store, cepCell* child) {
    assert(!cep_cell_is_void(child));

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_next(child);
      }
      case CEP_STORAGE_ARRAY: {
        return array_next((cepArray*) store, child);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_next((cepPackedQ*) store, child);
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_next(child);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_next((cepHashTable*) store, child);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_next(child);
      }
    }

    return NULL;
}




/* Iterate over children that share the same name across snapshots. Delegate to 
   the store helper that tracks iteration state and snapshot filtering. Allow 
   repeated lookups without restarting scans from the beginning.
*/
static inline cepCell* store_find_next_child_by_name(const cepStore* store, cepDT* name, uintptr_t* childIdx) {
    assert(cep_store_valid(store) && cep_dt_is_valid(name));

    if (!store->chdCount)
        return NULL;

    if (store->indexing == CEP_INDEX_BY_NAME  ||  !childIdx) {
        CEP_PTR_SEC_SET(childIdx, 0);
        return store_find_child_by_name(store, name);
    }

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_next_by_name((cepList*) store, name, (cepListNode**)childIdx);
      }
      case CEP_STORAGE_ARRAY: {
        return array_next_by_name((cepArray*) store, name, childIdx);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_next_by_name((cepPackedQ*) store, name, (cepPackedQNode**)childIdx);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_next_by_name((cepHashTable*) store, name, childIdx);
      }
      case CEP_STORAGE_RED_BLACK_T: {    // Unused.
        break;
      }
      case CEP_STORAGE_OCTREE: {
        //return octree_next_by_name(store, id, (cepListNode**)childIdx);
      }
    }

    return NULL;
}


/*
    Traverses all the children in a store, applying a function to each one
*/
static inline bool store_traverse(cepStore* store, cepTraverse func, void* context, cepEntry* entry) {
    assert(cep_store_valid(store) && func);

    size_t children = store->chdCount;
    if (!children)
        return true;

    if (!entry)
        entry = cep_alloca(sizeof(cepEntry));
    CEP_0(entry);

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        return list_traverse((cepList*) store, func, context, entry);
      }
      case CEP_STORAGE_ARRAY: {
        return array_traverse((cepArray*) store, func, context, entry);
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        return packed_q_traverse((cepPackedQ*) store, func, context, entry);
      }
      case CEP_STORAGE_RED_BLACK_T: {
        return rb_tree_traverse((cepRbTree*) store, cep_bitson(children) + 2, func, context, entry);
      }
      case CEP_STORAGE_HASH_TABLE: {
        return hash_table_traverse((cepHashTable*) store, func, context, entry);
      }
      case CEP_STORAGE_OCTREE: {
        return octree_traverse((cepOctree*) store, func, context, entry);
      }
    }

    return true;
}


static inline bool store_traverse_internal(cepStore* store, cepTraverse func, void* context, cepEntry* entry) {
    assert(cep_store_valid(store) && func);

    if (store->chdCount <= 1)
        return store_traverse(store, func, context, entry);

    switch (store->storage) {
      case CEP_STORAGE_RED_BLACK_T:
        return rb_tree_traverse_internal((cepRbTree*) store, func, context, entry);

      case CEP_STORAGE_HASH_TABLE:
        return hash_table_traverse_internal((cepHashTable*) store, func, context, entry);

      default:
        return store_traverse(store, func, context, entry);
    }
}




typedef struct {
    cepTraverse func;
    void*       context;
    cepEntry*   userEntry;
} cepTraverseFilterCtx;

static bool cep_traverse_visible_filter(cepEntry* entry, void* context) {
    cepTraverseFilterCtx* ctx = context;
    if (!ctx || !entry)
        return true;

    if (!entry->cell || !cep_cell_visible_latest(entry->cell, CEP_VIS_DEFAULT))
        return true;

    *ctx->userEntry = *entry;
    return ctx->func(ctx->userEntry, ctx->context);
}



typedef struct {
    cepTraverse     func;
    void*           context;
    cepOpCount    timestamp;
    cepEntry        pending;
    cepEntry*       userEntry;
    cepCell*        prev;
    size_t          position;
    bool            hasPending;
    bool            aborted;
} cepTraversePastCtx;


static inline const cepDataNode* cep_data_chain_find_snapshot(const cepData* data, cepOpCount snapshot) {
    if (!data)
        return NULL;

    if (data->deleted) {
        cepOpCount deleted = data->deleted;
        if (!snapshot || deleted <= snapshot)
            return NULL;
    }

    const cepDataNode* node = (const cepDataNode*) &data->modified;

    if (!snapshot)
        return node;

    while (node) {
        if (node->modified <= snapshot)
            return node;
        node = node->past;
    }

    return NULL;
}

static inline void* cep_data_node_payload(const cepData* owner, const cepDataNode* node) {
    if (!owner || !node)
        return NULL;

    switch (owner->datatype) {
      case CEP_DATATYPE_VALUE:
        return CEP_P(((cepDataNode*) node)->value);

      case CEP_DATATYPE_DATA:
        return ((cepDataNode*) node)->data;

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM:
        // ToDo: provide snapshot payloads for handle and stream datatypes.
        break;
    }

    return NULL;
}

static inline bool cep_data_alive_at(const cepData* data, cepOpCount timestamp) {
    if (!data)
        return false;

    if (!timestamp)
        return true;

    if (data->created && timestamp < data->created)
        return false;

    if (data->deleted && timestamp >= data->deleted)
        return false;

    return true;
}

static inline bool cep_store_alive_at(const cepStore* store, cepOpCount timestamp) {
    if (!store)
        return false;

    if (!timestamp)
        return true;

    if (store->created && timestamp < store->created)
        return false;

    if (store->deleted && timestamp >= store->deleted)
        return false;

    return true;
}

static inline bool cep_cell_alive_at(const cepCell* cell, cepOpCount timestamp) {
    if (!cell)
        return false;

    if (!timestamp)
        return true;

    if (cell->created && timestamp < cell->created)
        return false;

    if (cell->deleted && timestamp >= cell->deleted)
        return false;

    if (!cep_cell_is_normal(cell))
        return true;

    bool hasData = (cell->data != NULL);
    bool hasStore = (cell->store != NULL);

    bool dataAlive = hasData ? cep_data_alive_at(cell->data, timestamp) : false;
    bool storeAlive = hasStore ? cep_store_alive_at(cell->store, timestamp) : false;

    if (hasData || hasStore)
        return dataAlive || storeAlive;

    return true;
}

bool cep_cell_visible_latest(const cepCell* cell, cepVisibilityMask mask) {
    return cep_cell_visible_past(cell, 0, mask);
}

bool cep_cell_visible_past(const cepCell* cell, cepOpCount timestamp, cepVisibilityMask mask) {
    if (!cell)
        return false;

    bool alive = cep_cell_alive_at(cell, timestamp);
    if (!alive && !(mask & CEP_VIS_INCLUDE_DEAD))
        return false;

    if (cep_cell_is_veiled(cell) && !(mask & CEP_VIS_INCLUDE_VEILED))
        return false;

    return alive || (mask & CEP_VIS_INCLUDE_DEAD);
}

static void cep_cell_mark_subtree_veiled(cepCell* cell) {
    if (!cell)
        return;

    cell->metacell.veiled = 1u;

    if (cep_cell_is_normal(cell)) {
        cell->created = 0;

        if (cell->store) {
            for (cepCell* child = store_first_child(cell->store); child; child = store_next_child(cell->store, child)) {
                cep_cell_mark_subtree_veiled(child);
            }
        }
    }
}

static inline void cep_cell_apply_parent_veil(cepCell* child, const cepCell* parent) {
    if (!child || !parent)
        return;

    if (!cep_cell_is_veiled(parent))
        return;

    cep_cell_mark_subtree_veiled(child);
}

static void cep_cell_unveil_subtree(cepCell* cell, cepOpCount stamp) {
    if (!cell)
        return;

    cell->metacell.veiled = 0u;

    if (cep_cell_is_normal(cell)) {
        if (!cell->created)
            cell->created = stamp;

        if (cell->store) {
            for (cepCell* child = store_first_child(cell->store); child; child = store_next_child(cell->store, child)) {
                cep_cell_unveil_subtree(child, stamp);
            }
        }
    }
}

static cepCell* cep_txn_ensure_bucket(cepCell* root) {
    if (!root)
        return NULL;

    cepCell* meta = cep_cell_find_by_name(root, dt_meta_name());
    if (!meta) {
        cepDT meta_name = *dt_meta_name();
        cepDT dict_type = *dt_dictionary_type();
        meta = cep_cell_add_dictionary(root, &meta_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!meta)
            return NULL;
    }

    cepCell* bucket = cep_cell_find_by_name(meta, dt_txn_name());
    if (!bucket) {
        cepDT txn_name = *dt_txn_name();
        cepDT dict_type = *dt_dictionary_type();
        bucket = cep_cell_add_dictionary(meta, &txn_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!bucket)
            return NULL;
    }

    return bucket;
}

static bool cep_txn_update_state(cepCell* root, const char* state) {
    cepCell* bucket = cep_txn_ensure_bucket(root);
    if (!bucket || !state)
        return false;

    cepDT state_field = *dt_txn_state_name();
    return cep_cell_put_text(bucket, &state_field, state);
}

static const cepCell* cep_cell_top_veiled_ancestor(const cepCell* cell) {
    const cepCell* top = NULL;
    for (const cepCell* current = cell; current; current = cep_cell_parent(current)) {
        if (cep_cell_is_veiled(current)) {
            top = current;
        } else if (top) {
            break;
        }
    }
    return top;
}

static inline bool cep_entry_has_timestamp(const cepEntry* entry, cepOpCount timestamp) {
    assert(entry);

    if (!timestamp)
        return false;

    const cepCell* cell = entry->cell;
    if (!cell || !cep_cell_alive_at(cell, timestamp))
        return false;

    const cepCell* parentCell = entry->parent;
    if (parentCell && !cep_cell_alive_at(parentCell, timestamp))
        return false;

    const cepStore* container = cell->parent;
    if (container && !cep_store_alive_at(container, timestamp))
        return false;

    return true;
}

static inline bool cep_cell_matches_snapshot(const cepCell* cell, cepOpCount snapshot) {
    return cep_cell_visible_past(cell, snapshot, CEP_VIS_DEFAULT);
}

static inline cepCell* store_find_child_by_name_past(const cepStore* store, const cepDT* name, cepOpCount snapshot) {
    if (!store || !cep_dt_is_valid(name) || !cep_dt_is_valid(&store->dt)) {
        return NULL;
    }

    if (!store->chdCount)
        return NULL;

    cepCell* cell = store_find_child_by_name(store, name);
    if (cell && cep_cell_matches_snapshot(cell, snapshot))
        return cell;

    return NULL;
}

static inline cepCell* store_find_child_by_position_past(const cepStore* store, size_t position, cepOpCount snapshot) {
    assert(cep_store_valid(store));

    if (!store->chdCount)
        return NULL;

    size_t index = 0;
    for (cepCell* child = store_first_child(store); child; child = store_next_child(store, child)) {
        if (!cep_cell_matches_snapshot(child, snapshot))
            continue;
        if (index == position)
            return child;
        index++;
    }

    return NULL;
}

static inline cepCell* store_find_next_child_by_name_past(const cepStore* store, cepDT* name, uintptr_t* childIdx, cepOpCount snapshot) {
    assert(cep_store_valid(store) && cep_dt_is_valid(name));

    if (!store->chdCount)
        return NULL;

    if (!childIdx) {
        cepDT lookup = cep_dt_clean(name);
        for (cepCell* child = store_first_child(store); child; child = store_next_child(store, child)) {
            const cepDT* child_name = cep_cell_get_name(child);
            if (cep_dt_compare(child_name, &lookup) != 0)
                continue;
            if (cep_cell_matches_snapshot(child, snapshot))
                return child;
        }
        return NULL;
    }

    cepCell* cell;
    while ((cell = store_find_next_child_by_name(store, name, childIdx))) {
        if (cep_cell_matches_snapshot(cell, snapshot))
            return cell;
    }

    return NULL;
}


static inline bool cep_traverse_past_flush(cepTraversePastCtx* ctx, cepCell* nextCell) {
    ctx->pending.next = nextCell;
    *ctx->userEntry   = ctx->pending;
    ctx->hasPending   = false;

    if (!ctx->func(ctx->userEntry, ctx->context)) {
        ctx->aborted = true;
        return false;
    }

    ctx->prev = ctx->pending.cell;
    ctx->position++;
    return true;
}


static inline bool cep_traverse_past_proxy(cepEntry* entry, void* ctxPtr) {
    cepTraversePastCtx* ctx = ctxPtr;

    if (!entry->cell)
        return true;

    bool match = cep_entry_has_timestamp(entry, ctx->timestamp);
    if (!match)
        return true;

    if (ctx->hasPending) {
        if (!cep_traverse_past_flush(ctx, entry->cell))
            return false;
    }

    ctx->pending          = *entry;
    ctx->pending.prev     = ctx->prev;
    ctx->pending.position = ctx->position;
    ctx->pending.next     = NULL;
    ctx->hasPending       = true;

    return true;
}


typedef struct {
    cepEntry    pending;
   cepEntry    lastEmitted;
    cepCell*    prev;
    size_t      position;
    bool        hasPending;
    bool        emitted;
} cepTraversePastFrame;

typedef struct {
    cepTraversePastFrame* data;
    cepTraversePastFrame  fast[CEP_MAX_FAST_STACK_DEPTH + 1u];
    unsigned capacity;
    bool heap;
} cepTraversePastFrameBuffer;

static inline void cep_traverse_past_frame_buffer_init(cepTraversePastFrameBuffer* buffer) {
    assert(buffer);
    buffer->data = buffer->fast;
    buffer->capacity = CEP_MAX_FAST_STACK_DEPTH + 1u;
    buffer->heap = false;
    memset(buffer->fast, 0, sizeof buffer->fast);
}

static inline bool cep_traverse_past_frame_buffer_reserve(cepTraversePastFrameBuffer* buffer, unsigned requiredDepth) {
    assert(buffer);

    if (requiredDepth < buffer->capacity)
        return true;

    unsigned newCapacity = buffer->capacity;
    while (newCapacity <= requiredDepth)
        newCapacity <<= 1u;

    cepTraversePastFrame* resized;
    if (buffer->heap) {
        resized = cep_realloc(buffer->data, (size_t)newCapacity * sizeof *resized);
        if (!resized)
            return false;
    } else {
        resized = cep_malloc((size_t)newCapacity * sizeof *resized);
        if (!resized)
            return false;
        memcpy(resized, buffer->data, (size_t)buffer->capacity * sizeof *resized);
        buffer->heap = true;
    }

    memset(resized + buffer->capacity, 0, (size_t)(newCapacity - buffer->capacity) * sizeof *resized);
    buffer->data = resized;
    buffer->capacity = newCapacity;
    return true;
}

static inline void cep_traverse_past_frame_buffer_destroy(cepTraversePastFrameBuffer* buffer) {
    assert(buffer);

    if (buffer->heap && buffer->data)
        cep_free(buffer->data);

    buffer->data = buffer->fast;
    buffer->capacity = CEP_MAX_FAST_STACK_DEPTH + 1u;
    buffer->heap = false;
}


typedef struct {
    cepTraverse             nodeFunc;
    cepTraverse             endFunc;
    void*                   context;
    cepOpCount            timestamp;
    cepEntry*               userEntry;
    cepEntry                endEntry;
    cepTraversePastFrameBuffer* frameBuffer;
    unsigned                maxDepthInUse;
    bool                    aborted;
} cepDeepTraversePastCtx;


static inline bool cep_deep_traverse_past_flush_frame(cepDeepTraversePastCtx* ctx, unsigned depth, cepCell* nextCell) {
    assert(ctx);

    if (!cep_traverse_past_frame_buffer_reserve(ctx->frameBuffer, depth))
        return false;

    cepTraversePastFrame* frame = &ctx->frameBuffer->data[depth];

    frame->pending.next = nextCell;
    *ctx->userEntry     = frame->pending;
    frame->lastEmitted  = frame->pending;
    frame->hasPending   = false;
    frame->emitted      = true;

    if (ctx->nodeFunc) {
        if (!ctx->nodeFunc(ctx->userEntry, ctx->context)) {
            ctx->aborted = true;
            return false;
        }
    }

    frame->prev = frame->pending.cell;
    frame->position++;

    return true;
}


static inline bool cep_deep_traverse_past_sync_depth(cepDeepTraversePastCtx* ctx, unsigned depth) {
    assert(ctx);

    for (unsigned d = ctx->maxDepthInUse; d > depth; d--) {
        if (!cep_traverse_past_frame_buffer_reserve(ctx->frameBuffer, d))
            return false;

        cepTraversePastFrame* frame = &ctx->frameBuffer->data[d];

        if (frame->hasPending) {
            if (!cep_deep_traverse_past_flush_frame(ctx, d, NULL))
                return false;
        }

        frame->prev     = NULL;
        frame->position = 0;
        frame->emitted  = false;
    }

    if (ctx->maxDepthInUse > depth)
        ctx->maxDepthInUse = depth;

    return true;
}


static inline bool cep_deep_traverse_past_proxy(cepEntry* entry, void* ctxPtr) {
    cepDeepTraversePastCtx* ctx = ctxPtr;

    if (!entry->cell)
        return true;

    unsigned depth = entry->depth;
    if (!cep_traverse_past_frame_buffer_reserve(ctx->frameBuffer, depth))
        return false;

    if (!cep_deep_traverse_past_sync_depth(ctx, depth))
        return false;

    if (depth > ctx->maxDepthInUse)
        ctx->maxDepthInUse = depth;

    if (!cep_entry_has_timestamp(entry, ctx->timestamp))
        return true;

    if (depth) {
        if (!cep_traverse_past_frame_buffer_reserve(ctx->frameBuffer, depth - 1))
            return false;
        if (ctx->frameBuffer->data[depth - 1].hasPending) {
            if (!cep_deep_traverse_past_flush_frame(ctx, depth - 1, entry->cell))
                return false;
        }
    }

    cepTraversePastFrame* frame = &ctx->frameBuffer->data[depth];

    if (frame->hasPending) {
        if (!cep_deep_traverse_past_flush_frame(ctx, depth, entry->cell))
            return false;
    }

    frame->pending          = *entry;
    frame->pending.prev     = frame->prev;
    frame->pending.position = frame->position;
    frame->pending.next     = NULL;
    frame->hasPending       = true;

    return true;
}


static inline bool cep_deep_traverse_past_end_proxy(cepEntry* entry, void* ctxPtr) {
    cepDeepTraversePastCtx* ctx = ctxPtr;

    unsigned depth = entry->depth;
    if (!cep_traverse_past_frame_buffer_reserve(ctx->frameBuffer, depth))
        return false;

    if (!cep_deep_traverse_past_sync_depth(ctx, depth))
        return false;

    cepTraversePastFrame* frame = &ctx->frameBuffer->data[depth];
    if (!ctx->endFunc || !frame->emitted)
        return true;

    ctx->endEntry = frame->lastEmitted;

    if (!ctx->endFunc(&ctx->endEntry, ctx->context)) {
        ctx->aborted = true;
        return false;
    }

    return true;
}




static bool cep_cell_structural_equal(const cepCell* existing, const cepCell* incoming)
{
    if (existing == incoming)
        return true;

    if (!existing || !incoming)
        return false;

    if (memcmp(&existing->metacell, &incoming->metacell, sizeof(cepMetacell)) != 0)
        return false;

    if (cep_cell_is_link(existing))
        return existing->link == incoming->link;

    bool existingHasData = cep_cell_is_normal(existing) && cep_cell_has_data(existing);
    bool incomingHasData = cep_cell_is_normal(incoming) && cep_cell_has_data(incoming);
    if (existingHasData != incomingHasData)
        return false;
    if (existingHasData && !cep_data_structural_equal(existing->data, incoming->data))
        return false;

    bool existingHasStore = cep_cell_is_normal(existing) && cep_cell_has_store(existing);
    bool incomingHasStore = cep_cell_is_normal(incoming) && cep_cell_has_store(incoming);
    if (existingHasStore != incomingHasStore)
        return false;

    if (existingHasStore) {
        if (existing->store->indexing != incoming->store->indexing)
            return false;
        if (existing->store->chdCount != incoming->store->chdCount)
            return false;

        cepCell* exChild = store_first_child(existing->store);
        cepCell* inChild = store_first_child(incoming->store);
        while (exChild && inChild) {
            if (!cep_cell_structural_equal(exChild, inChild))
                return false;
            exChild = store_next_child(existing->store, exChild);
            inChild = store_next_child(incoming->store, inChild);
        }

        if (exChild || inChild)
            return false;
    }

    return true;
}



/*
    Converts an unsorted store into a dictionary
*/
static inline void store_to_dictionary(cepStore* store) {
    assert(cep_store_valid(store));

    if (store->indexing == CEP_INDEX_BY_NAME)
        return;

    if (cep_store_hierarchy_locked(store->owner))
        return;

    cep_store_history_push(store);   // Only snapshot when the indexing scheme changes (re-sorts rewrite sibling order).

    store->indexing = CEP_INDEX_BY_NAME;
    store->modified = cep_cell_timestamp_next();

    if (store->chdCount <= 1)
        return;

    // WARNING: reindexing reorders siblings; see append-only note in the docs.
    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        list_sort((cepList*) store, cell_compare_by_name, NULL);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        array_sort((cepArray*) store, cell_compare_by_name, NULL);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        assert(store->storage != CEP_STORAGE_PACKED_QUEUE);    // Unsupported.
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        assert(store->storage != CEP_STORAGE_HASH_TABLE);    // Unsupported.
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {    // Unneeded.
        break;
      }
      case CEP_STORAGE_OCTREE: {
        assert(store->storage != CEP_STORAGE_OCTREE);    // Unsupported.
        break;
      }
    }
}


/*
    Sorts unsorted store according to a user defined function
*/
static inline void store_sort(cepStore* store, cepCompare compare, void* context) {
    assert(cep_store_valid(store) && compare);

    if (store->indexing == CEP_INDEX_BY_FUNCTION)
        return;

    if (cep_store_hierarchy_locked(store->owner))
        return;

    unsigned previousIndex = store->indexing;

    cep_store_history_push(store);   // Snapshot current layout before re-sorting by custom comparator.

    store->compare  = compare;
    store->indexing = CEP_INDEX_BY_FUNCTION;
    store->modified = cep_cell_timestamp_next();

    if (store->chdCount <= 1)
        return;

    // WARNING: reindexing reorders siblings; see append-only note in the docs.
    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        list_sort((cepList*) store, compare, context);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        array_sort((cepArray*) store, compare, context);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        assert(store->storage == CEP_STORAGE_PACKED_QUEUE);    // Unsupported.
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        assert(store->storage != CEP_STORAGE_HASH_TABLE);    // Unsupported.
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        if (previousIndex == CEP_INDEX_BY_HASH)
            (void)rb_tree_reindex_with_compare(store, compare, context);
        break;
      }
      case CEP_STORAGE_OCTREE: {                            // Unneeded.
        break;
      }
    }
}


/*
    Removes last child from store (re-organizing siblings).
    Hard-delete helper used by *_hard callers; history is already captured via
    per-cell timestamps, so we purposely skip any cloning.
*/
static inline bool store_take_cell(cepStore* store, cepCell* target) {
    assert(cep_store_valid(store) && target);

    if (!store->chdCount || !store->writable || cep_store_hierarchy_locked(store->owner))
        return false;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        list_take((cepList*) store, target);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        array_take((cepArray*) store, target);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        packed_q_take((cepPackedQ*) store, target);
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        rb_tree_take((cepRbTree*) store, target);
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        hash_table_take((cepHashTable*) store, target);
        break;
      }
      case CEP_STORAGE_OCTREE: {
        octree_take((cepOctree*) store, target);
        break;
      }
    }

    store->chdCount--;
    store->modified = cep_cell_timestamp_next();   // Hard path still logs via timestamp only.

    return true;
}


/*
    Removes first child from store (re-organizing siblings).
    Same hard-delete contract as store_take_cell – rely on timestamps only.
*/
static inline bool store_pop_child(cepStore* store, cepCell* target) {
    assert(cep_store_valid(store) && target);

    if (!store->chdCount || !store->writable || cep_store_hierarchy_locked(store->owner))
        return false;

    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        list_pop((cepList*) store, target);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        array_pop((cepArray*) store, target);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        packed_q_pop((cepPackedQ*) store, target);
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        rb_tree_pop((cepRbTree*) store, target);
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        hash_table_pop((cepHashTable*) store, target);
        break;
      }
      case CEP_STORAGE_OCTREE: {
        octree_pop((cepOctree*) store, target);
        break;
      }
    }

    store->chdCount--;
    store->modified = cep_cell_timestamp_next();   // Hard path still logs via timestamp only.

    return true;
}


/*
    Deletes a cell and all its children re-organizing (sibling) storage.
    GC path: ensure callers understand we mutate in place and depend on the
    append-only timestamps for historical visibility.
*/
static inline void store_remove_child(cepStore* store, cepCell* cell, cepCell* target) {
    assert(cep_store_valid(store) && store->chdCount);

    if (cep_store_hierarchy_locked(store->owner))
        return;

    if (target)
        cep_cell_transfer(cell, target);  // Save cell.
    else
        cep_cell_finalize_hard(cell);          // Delete cell (along children, if any).

    // Remove this cell from its parent (re-organizing siblings).
    switch (store->storage) {
      case CEP_STORAGE_LINKED_LIST: {
        list_remove_cell((cepList*) store, cell);
        break;
      }
      case CEP_STORAGE_ARRAY: {
        array_remove_cell((cepArray*) store, cell);
        break;
      }
      case CEP_STORAGE_PACKED_QUEUE: {
        packed_q_remove_cell((cepPackedQ*) store, cell);
        break;
      }
      case CEP_STORAGE_RED_BLACK_T: {
        rb_tree_remove_cell((cepRbTree*) store, cell);
        break;
      }
      case CEP_STORAGE_HASH_TABLE: {
        hash_table_remove_cell((cepHashTable*) store, cell);
        break;
      }
      case CEP_STORAGE_OCTREE: {
        octree_remove_cell((cepOctree*) store, cell);
        break;
      }
    }

    store->chdCount--;
    store->modified = cep_cell_timestamp_next();   // Even for GC deletes we only rely on timestamps.
}




/** Initialise a cell with its type, name, payload, and optional child store so
    callers funnel every new node through a single invariant-enforcing path.
    The routine validates inputs, stamps the metacell, attaches payload/store
    pointers, and transfers ownership, ensuring freshly created cells are ready
    for insertion without additional bookkeeping. */
void cep_cell_initialize(cepCell* cell, unsigned type, cepDT* name, cepData* data, cepStore* store) {
    assert(cell && cep_dt_is_valid(name) && (type && type < CEP_TYPE_COUNT));
    assert(!name->glob && "Glob tags are not legal for concrete cell names");
    bool isLink = (type == CEP_TYPE_LINK);
    assert(isLink? (!store): ((data? cep_data_valid(data): true)  &&  (store? cep_store_valid(store): true)));

    cell->metacell.domain    = name->domain;
    cell->metacell.tag       = name->tag;
    cell->metacell.glob      = name->glob;
    cell->metacell.type      = type;
    cell->metacell.shadowing = CEP_SHADOW_NONE;

    cell->parent = NULL;
    cell->data   = NULL;
    cell->store  = NULL;

    if (isLink) {
        cell->link = NULL;
        if (data)
            cep_link_set(cell, (cepCell*) data);
    } else {
        cell->data = data;
        cell->store = store;
        if (store)
            store->owner = cell;
    }

    cepOpCount timestamp = cep_cell_timestamp_next();
    cell->created = timestamp;
    cell->deleted = 0;
}


void cep_cell_transfer(cepCell* src, cepCell* dst)
{
    assert(!cep_cell_is_void(src) && dst);

    bool wasLink = cep_cell_is_link(src);
    bool hadShadow = (!wasLink) && cep_cell_is_shadowed(src);
    cepCell* linkTarget = wasLink? src->link: NULL;

    *dst = *src;

    if (wasLink && linkTarget) {
        cep_shadow_detach(linkTarget, src);
        cep_shadow_attach(linkTarget, dst);
        src->link = NULL;
    } else if (hadShadow) {
        cep_shadow_rebind_links(dst);
    }

    if (!cep_cell_is_link(dst) && dst->store) {
        dst->store->owner = dst;
        if (dst->store->lockOwner == src)
            dst->store->lockOwner = dst;

        if (dst->store->chdCount)
            cep_cell_relink_storage(dst);
    }

    if (!cep_cell_is_link(dst) && dst->data && dst->data->lockOwner == src)
        dst->data->lockOwner = dst;

    // ToDo: relink self list.
}


/** Seed a clone cell with the metadata of an existing cell so callers can set
    up a matching shell before deciding how much history to replicate. The
    helper validates the source, zeros the destination, and mirrors metacell
    timestamps while deferring payload/store duplication for specialised clone
    helpers. */
void cep_cell_initialize_clone(cepCell* clone, cepDT* name, cepCell* cell) {
    assert(clone && cep_cell_is_normal(cell));
    (void)name;

    assert(!cep_cell_has_data(cell) && !cep_cell_has_store(cell));

    // ToDo: Clone data Pending!

    CEP_0(clone);

    clone->metacell = cell->metacell;
    clone->created  = cell->created;
    clone->deleted  = cell->deleted;
}


/** Create a heap-backed duplicate of a normal cell without copying its
   descendants. VALUE/DATA payloads are deep-copied; HANDLE/STREAM payloads turn
   into link cells that reference the original node so external resources stay
   unified. We clear shadowing bits on the copy and return NULL when allocation
   fails or the payload cannot be cloned. Callers own the returned cell and
   should eventually pass it through cep_cell_finalize before releasing it.
 */
cepCell* cep_cell_clone(const cepCell* cell) {
    if (!cell || !cep_cell_is_normal(cell))
        return NULL;

    CEP_NEW(cepCell, clone);
    if (!clone)
        return NULL;

    if (!cep_cell_clone_into(cell, clone, false)) {
        cep_free(clone);
        return NULL;
    }

    return clone;
}


/** Deep-copy a normal cell subtree, producing an independent hierarchy whose
   VALUE/DATA payloads and child stores no longer reference the original.
   HANDLE/STREAM payloads become link cells pointing back to their source so the
   shared resource remains authoritative. The clone keeps structural metadata
   (names, timestamps, auto-id cursors) but intentionally drops runtime-only
   details such as bindings, locks, and history chains so the new tree starts
   clean. The caller assumes ownership of the returned root and should finalise
   it when done.
 */
cepCell* cep_cell_clone_deep(const cepCell* cell) {
    if (!cell || !cep_cell_is_normal(cell))
        return NULL;

    CEP_NEW(cepCell, clone);
    if (!clone)
        return NULL;

    if (!cep_cell_clone_into(cell, clone, true)) {
        cep_free(clone);
        return NULL;
    }

    return clone;
}


static void cep_cell_release_contents(cepCell* cell) {
    assert(cell);

    switch (cell->metacell.type) {
      case CEP_TYPE_NORMAL: {
        cepStore* store = cell->store;
        if (store) {
            // ToDo: clean shadow.
            cep_store_del(store);
            cell->store = NULL;
        }

        cepData* data = cell->data;
        if (data) {
            cep_data_del(data);
            cell->data = NULL;
        }
        break;
      }

      case CEP_TYPE_PROXY: {
        cepProxy* proxy = cell->proxy;
        if (proxy) {
            if (proxy->ops && proxy->ops->finalize)
                proxy->ops->finalize(cell);
            cep_free(proxy);
            cell->proxy = NULL;
        }
        break;
      }

      case CEP_TYPE_LINK: {
        if (cell->link)
            cep_link_set(cell, NULL);
        break;
      }
    }
}


/** Finalise a cell that is guaranteed to have no backlinks. Callers must ensure
    shadow invariants hold before invoking this helper; it will assert if any
    links still reference the cell. */
void cep_cell_finalize(cepCell* cell) {
    assert(!cep_cell_is_void(cell));

    bool shadowed = cep_cell_is_shadowed(cell);
    CEP_ASSERT(!shadowed);
    if (shadowed)
        return;

    cep_cell_release_contents(cell);
}


/** Forcefully finalise a cell, breaking backlinks when necessary. Intended for
    aborting in-flight construction or reclaiming detached cells before they are
    made visible to the hierarchy. */
void cep_cell_finalize_hard(cepCell* cell) {
    assert(!cep_cell_is_void(cell));

    if (cep_cell_is_shadowed(cell))
        cep_shadow_break_all(cell);

    cep_cell_release_contents(cell);
}




#define CELL_FOLLOW_LINK_TO_STORE(cell, store, ...)                            \
    if (cep_cell_is_void(cell)) {                                              \
        fprintf(stderr, "DEBUG cell_follow void parent=%p\n", (void*)(cell)); \
        fflush(stderr);                                                       \
    }                                                                         \
    assert(!cep_cell_is_void(cell));                                           \
    cell = cep_link_pull(CEP_P(cell));                                         \
    cepStore* store = cell->store;                                             \
    if (!store)                                                                \
        return __VA_ARGS__


/* Insert a child cell into a parent at a specific position or key. Follow 
   links to the owning store and call cep_store_add_child with the supplied 
   context. Let callers compose structures without handling storage-specific 
   mechanics. Behaviour constraints described in
   docs/L0_KERNEL/topics/APPEND-ONLY-AND-IDEMPOTENCY.md.
*/
cepCell* cep_cell_add(cepCell* cell, uintptr_t context, cepCell* child) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    cepCell* inserted = cep_store_add_child(store, context, child);
    if (inserted && !inserted->created) {
        cepCell* parentCell = store->owner;
        if (parentCell && !cep_cell_is_floating(parentCell) && !cep_cell_is_veiled(parentCell))
            inserted->created = store->modified;
    }
    return inserted;
}


/* Append or prepend a child cell relative to its siblings. Resolve the parent 
   store (following links) and invoke cep_store_append_child with the prepend 
   flag. Provide a simple ordered mutation helper for insertion-mode stores.
*/
cepCell* cep_cell_append(cepCell* cell, bool prepend, cepCell* child) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    cepCell* inserted = cep_store_append_child(store, prepend, child);
    if (inserted && !inserted->created) {
        cepCell* parentCell = store->owner;
        if (parentCell && !cep_cell_is_floating(parentCell) && !cep_cell_is_veiled(parentCell))
            inserted->created = store->modified;
    }
    return inserted;
}


/** Populate the provenance bucket for @p derived so recorded cells remember the
    parents they were derived from. The helper ensures `meta/parents` exists,
    clears any previous entries, and then appends link cells that reference each
    supplied parent. Returns the number of attached parents or -1 when
    allocation fails. */
int cep_cell_add_parents(cepCell* derived, cepCell* const* parents, size_t count) {
    if (!derived || (count && !parents)) {
        return -1;
    }

    derived = cep_link_pull(derived);
    if (!derived || !cep_cell_is_normal(derived)) {
        return -1;
    }

    cepCell* meta = cep_cell_find_by_name(derived, dt_meta_name());
    if (!meta) {
        cepDT meta_name = *dt_meta_name();
        cepDT dict_type = *dt_dictionary_type();
        meta = cep_cell_add_dictionary(derived, &meta_name, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!meta) {
            return -1;
        }
    }

    bool meta_writable = true;
    if (meta->store) {
        meta_writable = meta->store->writable;
        meta->store->writable = true;
    }

    cepCell* bucket = cep_cell_find_by_name(meta, dt_parents_name());
    if (!bucket) {
        cepDT parents_name = *dt_parents_name();
        cepDT list_type = *dt_list_type();
        bucket = cep_cell_add_list(meta, &parents_name, 0, &list_type, CEP_STORAGE_LINKED_LIST);
        if (!bucket) {
            if (meta->store) {
                meta->store->writable = meta_writable;
            }
            return -1;
        }
    }

    if (meta->store) {
        meta->store->writable = meta_writable;
    }

    if (bucket->store) {
        bool writable = bucket->store->writable;
        bucket->store->writable = true;
        cep_store_delete_children_hard(bucket->store);
        bucket->store->writable = writable;
    }

    int attached = 0;
    for (size_t i = 0; i < count; ++i) {
        cepCell* parent = parents[i];
        if (!parent) {
            continue;
        }

        cepCell* canonical = cep_link_pull(parent);
        if (!canonical || cep_cell_is_void(canonical)) {
            continue;
        }

        cepDT parent_tag = *dt_parent_tag();
        cepCell* link = cep_cell_append_link(bucket, &parent_tag, canonical);
        if (!link) {
            return -1;
        }

        if (attached == INT_MAX) {
            return -1;
        }

        attached += 1;
    }

    return attached;
}


/** Compute and persist the payload hash for @p cell so optional integrity
    checks align with CEP's internal data node. Non-value payloads and empty
    cells return zero, letting callers skip hash-aware flows when they are not
    applicable. */
uint64_t cep_cell_content_hash(cepCell* cell) {
    if (!cell) {
        return 0u;
    }

    cell = cep_link_pull(cell);
    if (!cell || !cep_cell_is_normal(cell) || !cep_cell_has_data(cell)) {
        return 0u;
    }

    cepData* data = cell->data;
    if (!data || (data->datatype != CEP_DATATYPE_VALUE && data->datatype != CEP_DATATYPE_DATA)) {
        return 0u;
    }

    uint64_t hash = cep_data_compute_hash(data);
    data->hash = hash;
    return hash;
}


/** Override the stored payload hash with an externally supplied checksum so
    replay tools can carry authoritative digests without mutating the payload
    itself. Reports 0 on success or -1 when the cell lacks hashable data. */
int cep_cell_set_content_hash(cepCell* cell, uint64_t hash) {
    if (!cell) {
        return -1;
    }

    cell = cep_link_pull(cell);
    if (!cell || !cep_cell_is_normal(cell) || !cep_cell_has_data(cell)) {
        return -1;
    }

    cepData* data = cell->data;
    if (!data || (data->datatype != CEP_DATATYPE_VALUE && data->datatype != CEP_DATATYPE_DATA)) {
        return -1;
    }

    data->hash = hash;
    return 0;
}


/* Fetch the live payload pointer for a cell. Follow links to the concrete 
   cell and return its cepData buffer through cep_data(). Give callers a direct 
   way to inspect a cell's value without duplicating link resolution logic.
*/
void* cep_cell_data(const cepCell* cell) {
    assert(!cep_cell_is_void(cell));

    cell = cep_link_pull(CEP_P(cell));

    cepData* data = cell->data;
    if (!data)
        return NULL;

    return cep_data(data);
}


/* Retrieve a child's payload by name at a given snapshot. Resolve the target 
   cell for the requested heartbeat and read the appropriate history node before 
   exposing the payload. Support temporal queries so callers can inspect prior 
   states without altering the live cell.
*/
void* cep_cell_data_find_by_name_past(const cepCell* cell, cepDT* name, cepOpCount snapshot) {
    assert(!cep_cell_is_void(cell) && cep_dt_is_valid(name));

    cepCell* found = cep_cell_find_by_name_past(cell, name, snapshot);
    if (!found)
        return NULL;

    if (!snapshot)
        return cep_cell_data(found);

    found = cep_link_pull(found);

    if (!cep_cell_is_normal(found))
        return NULL;

    if (!cep_cell_has_data(found))
        return NULL;

    const cepData* data = found->data;
    const cepDataNode* node = cep_data_chain_find_snapshot(data, snapshot);
    if (!node)
        return NULL;

    return cep_data_node_payload(data, node);
}


/*
   Updates the data of a cell while preserving historical payload snapshots.
*/
void* cep_cell_update(cepCell* cell, size_t size, size_t capacity, void* value, bool swap) {
    assert(!cep_cell_is_void(cell) && size && capacity);

    cell = cep_link_pull(cell);

    cepData* data = cell->data;
    if CEP_NOT_ASSERT(data)
        return NULL;

    if (cep_data_hierarchy_locked(cell))
        return NULL;

    if (!data->writable)
        return NULL;

    if (!swap && (data->datatype == CEP_DATATYPE_VALUE || data->datatype == CEP_DATATYPE_DATA)) {
        if (cep_data_equals_bytes(data, value, size)) {
            const void* payload = cep_data_payload(data);
            return payload ? (void*)payload : NULL;
        }
    }

    if (data->datatype == CEP_DATATYPE_DATA && swap) {
        if (data->data == value && data->size == size && data->capacity == capacity)
            return data->data;
    }

    cepDataNode* snapshot = cep_malloc0(sizeof *snapshot);
    memcpy(snapshot, (const cepDataNode*) &data->modified, sizeof *snapshot);
    snapshot->past = data->past;

    bool snapshotOwnsCopy = false;

    if (data->datatype == CEP_DATATYPE_DATA && snapshot->data && snapshot->size) {
        if (!swap) {
            size_t allocSize = snapshot->capacity ? snapshot->capacity : snapshot->size;
            void* copy = cep_malloc(allocSize);
            memcpy(copy, snapshot->data, snapshot->size);
            snapshot->data = copy;
            snapshot->destructor = cep_free;
            snapshotOwnsCopy = true;
        }
        // For swap=true we keep the original pointer so history owns it via the copied descriptor.
    }

    data->past = snapshot;

    void* result = NULL;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE: {
        assert(data->capacity >= capacity);
        memcpy(data->value, value, size);
        data->size = size;
        result = data->value;
        break;
      }

      case CEP_DATATYPE_DATA: {
        assert(value);
        if (swap) {
            data->data     = value;
            data->capacity = capacity;
        } else {
            assert(data->capacity >= capacity);
            memcpy(data->data, value, size);
        }
        data->size = size;
        result = data->data;
        break;
      }

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        // ToDo: provide snapshot support for handle/stream datatypes.
        break;
      }
    }

    if (!result) {
        data->past = snapshot->past;
        if (snapshotOwnsCopy && snapshot->data && snapshot->destructor)
            snapshot->destructor(snapshot->data);
        cep_free(snapshot);
        return NULL;
    }

    data->hash = cep_data_compute_hash(data);
    data->modified = cep_cell_timestamp_next();

    return result;
}


/* Overwrite a cell's payload without recording history. Resolve the live 
   cepData instance and delegate to cep_data_update for an in-place modification. 
   Provide a faster option for callers that intentionally discard previous values.
*/
void* cep_cell_update_hard(cepCell* cell, size_t size, size_t capacity, void* value, bool swap) {
    assert(!cep_cell_is_void(cell) && size && capacity);

    cell = cep_link_pull(cell);

    cepData* data = cell->data;
    if CEP_NOT_ASSERT(data)
        return NULL;

    if (cep_data_hierarchy_locked(cell))
        return NULL;

    return cep_data_update(data, size, capacity, value, swap);
}






/* Build the domain/tag path from the root down to a cell. Walk ancestor 
   pointers into a temporary buffer, growing it on demand, then normalise the 
   sequence into the caller-provided cepPath. Expose a stable identifier for cells 
   so higher layers can reference or persist locations.
*/
bool cep_cell_path(const cepCell* cell, cepPath** path) {
    assert(cell && path);

    unsigned initialCapacity = CEP_MAX_FAST_STACK_DEPTH;
    cepPath* tempPath = *path;

    if (tempPath) {
        if (!tempPath->capacity) {
            size_t bytes = sizeof(cepPath) + ((size_t)initialCapacity * sizeof(cepPast));
            cepPath* resized = cep_realloc(tempPath, bytes);
            if (!resized)
                return false;
            memset(resized->past, 0, (size_t)initialCapacity * sizeof(cepPast));
            resized->capacity = initialCapacity;
            tempPath = resized;
            *path = tempPath;
        }
    } else {
        tempPath = cep_dyn_malloc0(cepPath, cepPast, initialCapacity);
        if (!tempPath)
            return false;
        tempPath->capacity = initialCapacity;
        *path = tempPath;
    }
    tempPath->length = 0;

    // Traverse up the hierarchy to construct the path in reverse order
    for (const cepCell* current = cell;  current;  current = cep_cell_parent(current)) {
        if (tempPath->length >= tempPath->capacity) {
            unsigned newCapacity = tempPath->capacity * 2;
            size_t bytes = sizeof(cepPath) + ((size_t)newCapacity * sizeof(cepPast));
            cepPath* resized = cep_realloc(tempPath, bytes);
            if (!resized)
                return false;

            if (tempPath->length) {
                unsigned used = tempPath->length;
                unsigned start = tempPath->capacity - used;
                memmove(&resized->past[newCapacity - used], &resized->past[start], used * sizeof(cepPast));
            }

            tempPath = resized;
            tempPath->capacity = newCapacity;
            *path = tempPath;
        }

        // Prepend the current cell's id to the path
        cepPast* segment = &tempPath->past[tempPath->capacity - tempPath->length - 1];
        segment->dt.domain = current->metacell.domain;
        segment->dt.tag    = current->metacell.tag;
        segment->dt.glob   = current->metacell.glob;
        segment->timestamp = 0;

        tempPath->length++;
    }

    if (tempPath->length) {
        unsigned start = tempPath->capacity - tempPath->length;
        if (start)
            memmove(tempPath->past, &tempPath->past[start], tempPath->length * sizeof(cepPast));
    }

    const cepCell* leaf = cell;
    if (leaf && cep_cell_is_normal(leaf)) {
        if (leaf->data && cep_dt_is_valid(&leaf->data->dt)) {
            if (tempPath->length >= tempPath->capacity) {
                unsigned newCapacity = tempPath->capacity ? (tempPath->capacity << 1u) : 4u;
                if (newCapacity < tempPath->length + 1u) {
                    newCapacity = tempPath->length + 1u;
                }
                size_t bytes = sizeof(cepPath) + ((size_t)newCapacity * sizeof(cepPast));
                cepPath* resized = cep_realloc(tempPath, bytes);
                if (!resized) {
                    return false;
                }
                tempPath = resized;
                tempPath->capacity = newCapacity;
                *path = tempPath;
            }

            cepPast* segment = &tempPath->past[tempPath->length++];
            segment->dt.domain = leaf->data->dt.domain;
            segment->dt.tag = leaf->data->dt.tag;
            segment->dt.glob = leaf->data->dt.glob;
            segment->timestamp = 0u;
        }

        const cepStore* store = leaf->store;
        if (store && store->chdCount && cep_dt_is_valid(&store->dt)) {
            if (tempPath->length >= tempPath->capacity) {
                unsigned newCapacity = tempPath->capacity ? (tempPath->capacity << 1u) : 4u;
                if (newCapacity < tempPath->length + 1u) {
                    newCapacity = tempPath->length + 1u;
                }
                size_t bytes = sizeof(cepPath) + ((size_t)newCapacity * sizeof(cepPast));
                cepPath* resized = cep_realloc(tempPath, bytes);
                if (!resized) {
                    return false;
                }
                tempPath = resized;
                tempPath->capacity = newCapacity;
                *path = tempPath;
            }

            cepPast* segment = &tempPath->past[tempPath->length++];
            segment->dt.domain = store->dt.domain;
            segment->dt.tag = store->dt.tag;
            segment->dt.glob = store->dt.glob;
            segment->timestamp = 0u;
        }
    }

    return true;
}




/* Retrieve the first child visible at a given snapshot. Resolve the parent 
   store (following links) and iterate from the head until a child satisfies the 
   snapshot filter. Anchor snapshot-aware traversal at the beginning of the 
   sibling list.
*/
cepCell* cep_cell_first_past(const cepCell* cell, cepOpCount snapshot) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    for (cepCell* child = store_first_child(store); child; child = store_next_child(store, child)) {
        if (cep_cell_matches_snapshot(child, snapshot))
            return child;
    }

    return NULL;
}


/* Retrieve the last child visible at a given snapshot. Resolve the parent 
   store and walk backwards from the tail until a child matches the snapshot 
   filter. Support reverse traversal while respecting historical visibility.
*/
cepCell* cep_cell_last_past(const cepCell* cell, cepOpCount snapshot) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    for (cepCell* child = store_last_child(store); child; child = store_prev_child(store, child)) {
        if (cep_cell_matches_snapshot(child, snapshot))
            return child;
    }

    return NULL;
}


/* Find a child by domain/tag for a given snapshot. Resolve the parent store 
   and ask it for the snapshot-aware lookup. Provide snapshot-consistent name 
   lookups without exposing store internals.
*/
cepCell* cep_cell_find_by_name_past(const cepCell* cell, const cepDT* name, cepOpCount snapshot) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    return store_find_child_by_name_past(store, name, snapshot);
}


/*
    Finds a child cell based on specified key
*/
cepCell* cep_cell_find_by_key(const cepCell* cell, cepCell* key, cepCompare compare, void* context) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    
    if (!compare)
        compare = store->compare;
    cepCell* found = store_find_child_by_key(store, key, compare, context);
    if (!found && compare && compare != store->compare && store->compare)
        found = store_find_child_by_key(store, key, store->compare, context);
    return found;
}


static inline cepCell* store_first_child_internal(const cepStore* store) {
    assert(cep_store_valid(store));

    if (!store->chdCount)
        return NULL;

    switch (store->storage) {
      case CEP_STORAGE_RED_BLACK_T:
        return rb_tree_internal_first((cepRbTree*) store);

      case CEP_STORAGE_HASH_TABLE:
        return hash_table_internal_first((cepHashTable*) store);

      default:
        return store_first_child(store);
    }
}


static inline cepCell* store_next_child_internal(const cepStore* store, cepCell* child) {
    assert(cep_store_valid(store));
    if (!child)
        return NULL;

    switch (store->storage) {
      case CEP_STORAGE_RED_BLACK_T:
        return rb_tree_internal_next(child);

      case CEP_STORAGE_HASH_TABLE:
        return hash_table_internal_next((cepHashTable*) store, child);

      default:
        return store_next_child(store, child);
    }
}


/* Fetch a child by positional index for a snapshot. Resolve the store and 
   iterate through snapshot-visible children until the requested position is 
   reached. Enable snapshot-stable positional addressing within sibling lists.
*/
cepCell* cep_cell_find_by_position_past(const cepCell* cell, size_t position, cepOpCount snapshot) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    return store_find_child_by_position_past(store, position, snapshot);
}


/* Report the logical position of a live child within an insertion-ordered
   parent. Resolve links, make sure the child belongs to the same store, and
   walk siblings in positional order until the target is reached. */
bool cep_cell_indexof(const cepCell* parent, const cepCell* child, size_t* position) {
    if (!parent || !child || cep_cell_is_void(parent) || cep_cell_is_void(child))
        return false;

    cepCell* resolvedParent = cep_link_pull((cepCell*)parent);
    cepStore* store = resolvedParent->store;
    if (!store || store->indexing != CEP_INDEX_BY_INSERTION)
        return false;

    cepCell* resolvedChild = cep_link_pull((cepCell*)child);
    if (resolvedChild->parent != store)
        return false;

    size_t index = 0;
    for (cepCell* current = store_first_child(store); current; current = store_next_child(store, current)) {
        if (!cep_cell_visible_latest(current, CEP_VIS_DEFAULT))
            continue;
        if (current == resolvedChild) {
            CEP_PTR_SEC_SET(position, index);
            return true;
        }
        index++;
    }

    return false;
}

bool cep_txn_begin(cepCell* parent, const cepDT* name, const cepDT* type, cepTxn* txn) {
    if (!parent || !name || !cep_dt_is_valid(name) || !txn)
        return false;

    CEP_0(txn);

    cepCell* resolved = cep_link_pull(parent);
    if (!resolved || !cep_cell_is_normal(resolved))
        return false;

    cepStore* store = NULL;
    if (!cep_cell_require_store(&resolved, &store))
        return false;

    cepDT name_copy = cep_dt_clean(name);
    if (store_find_child_by_name(store, &name_copy))
        return false;

    cepDT type_copy = type ? cep_dt_clean(type) : *dt_dictionary_type();

    bool restore_writable = false;
    unsigned writable_before = 0u;
    if (store && !store->writable) {
        writable_before = store->writable;
        store->writable = 1u;
        restore_writable = true;
    }

    cepCell* root = cep_cell_add_dictionary(resolved, &name_copy, 0, &type_copy, CEP_STORAGE_RED_BLACK_T);

    if (restore_writable)
        store->writable = writable_before;

    if (!root)
        return false;

    cep_cell_mark_subtree_veiled(root);
    cep_txn_update_state(root, "building");

    txn->root = root;
    txn->parent = resolved;
    txn->begin_beat = cep_beat_index();
    return true;
}

bool cep_txn_mark_ready(cepTxn* txn) {
    if (!txn || !txn->root)
        return false;

    return cep_txn_update_state(txn->root, "ready");
}

bool cep_txn_commit(cepTxn* txn) {
    if (!txn || !txn->root)
        return false;

    cepCell* root = cep_link_pull(txn->root);
    if (!root)
        return false;

    cepLockToken lock = {0};
    bool locked = false;
    if (cep_cell_is_normal(root) && root->store) {
        locked = cep_store_lock(root, &lock);
        if (!locked)
            return false;
    }

    cepOpCount stamp = cep_cell_timestamp_next();
    cep_cell_unveil_subtree(root, stamp);

    if (locked)
        cep_store_unlock(root, &lock);

    cep_txn_update_state(root, "committed");

    char note[128];
    snprintf(note, sizeof note, "txn commit: root=%p beat=%" PRIu64, (void*)root, (unsigned long long)txn->begin_beat);
    cep_heartbeat_stage_note(note);

    txn->root = NULL;
    txn->parent = NULL;
    txn->begin_beat = 0;
    return true;
}

void cep_txn_abort(cepTxn* txn) {
    if (!txn || !txn->root)
        return;

    cepCell* root = cep_link_pull(txn->root);
    if (!root)
        return;

    cep_txn_update_state(root, "aborted");
    char note[128];
    snprintf(note, sizeof note, "txn abort: root=%p beat=%" PRIu64, (void*)root, (unsigned long long)txn->begin_beat);
    cep_heartbeat_stage_note(note);
    cep_cell_remove_hard(root, NULL);

    txn->root = NULL;
    txn->parent = NULL;
    txn->begin_beat = 0;
}


/* Resolve a descendant cell that matches a recorded path. Step through each 
   path segment, performing snapshot-aware name lookups per depth. Allow callers 
   to replay stored paths against historical tree states.
*/
cepCell* cep_cell_find_by_path_past(const cepCell* start, const cepPath* path, cepOpCount snapshot) {
    assert(!cep_cell_is_void(start) && path && path->length);
    if (!cep_cell_children(start))
        return NULL;
    cepCell* cell = CEP_P(start);

    unsigned depth = 0u;
    for (; depth < path->length; ++depth) {
        const cepPast* segment = &path->past[depth];
        cepOpCount segSnapshot = segment->timestamp ? segment->timestamp : snapshot;
        cepCell* next = cep_cell_find_by_name_past(cell, &segment->dt, segSnapshot);
        if (!next) {
            break;
        }
        cell = next;
    }

    if (depth == path->length) {
        return cell;
    }

    if (!cell || !cep_cell_is_normal(cell)) {
        return NULL;
    }

    bool data_consumed = false;
    bool store_consumed = false;

    for (; depth < path->length; ++depth) {
        const cepPast* segment = &path->past[depth];
        bool matched = false;

        if (!data_consumed && cell->data && cep_dt_compare(&cell->data->dt, &segment->dt) == 0) {
            data_consumed = true;
            matched = true;
        } else if (!store_consumed && cell->store && cep_dt_compare(&cell->store->dt, &segment->dt) == 0) {
            store_consumed = true;
            matched = true;
        }

        if (!matched) {
            return NULL;
        }
    }

    return cell;
}




/* Return the previous sibling that exists at a snapshot. Walk backward from 
   the given child, skipping entries that are invisible (veiled or out of
   scope) at the requested timestamp. Support reverse iteration across siblings
   under historical views.
*/
cepCell* cep_cell_prev_past(const cepCell* cell, cepCell* child, cepOpCount snapshot) {
    if (!cell)
        cell = cep_cell_parent(child);
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);

    cepCell* prev = store_prev_child(store, child);
    while (prev && !cep_cell_matches_snapshot(prev, snapshot))
        prev = store_prev_child(store, prev);

    return prev;
}


/* Return the next sibling that exists at a snapshot. Walk forward from the 
   given child, ignoring siblings invisible at the requested timestamp. Support 
   forward iteration across siblings while respecting history filters.
*/
cepCell* cep_cell_next_past(const cepCell* cell, cepCell* child, cepOpCount snapshot) {
    if (!cell)
        cell = cep_cell_parent(child);
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);

    cepCell* next = store_next_child(store, child);
    while (next && !cep_cell_matches_snapshot(next, snapshot))
        next = store_next_child(store, next);

    return next;
}




/* Iterate over children that share a given name across snapshots. Delegate to 
   store helpers that maintain iteration state and snapshot filtering. Allow 
   callers to enumerate name collisions without restarting the search.
*/
cepCell* cep_cell_find_next_by_name_past(const cepCell* cell, cepDT* name, uintptr_t* childIdx, cepOpCount snapshot) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    return store_find_next_child_by_name_past(store, name, childIdx, snapshot);
}


/* Walk a stored path and produce the next matching descendant for each branch. 
   Maintain per-depth iteration state while issuing snapshot-aware name lookups 
   down the path. Support cursor-style enumeration of repeated path matches 
   through the tree.
*/
cepCell* cep_cell_find_next_by_path_past(const cepCell* start, cepPath* path, uintptr_t* prev, cepOpCount snapshot) {
    assert(cep_cell_children(start) && path && path->length);
    if (!cep_cell_children(start))
        return NULL;

    size_t depthCount = path->length;
    size_t parentCount = depthCount + 1;

    cepCell* parentLocal[CEP_MAX_FAST_STACK_DEPTH + 1];
    cepCell** parents = parentLocal;
    bool parentsHeap = false;
    if (parentCount > CEP_MAX_FAST_STACK_DEPTH + 1) {
        parents = cep_malloc(parentCount * sizeof(*parents));
        parentsHeap = true;
    }

    uintptr_t stateLocal[CEP_MAX_FAST_STACK_DEPTH];
    uintptr_t* states = prev;
    bool stateHeap = false;
    if (!states) {
        if (depthCount <= CEP_MAX_FAST_STACK_DEPTH) {
            states = stateLocal;
        } else {
            states = cep_malloc(depthCount * sizeof(*states));
            stateHeap = true;
        }
        memset(states, 0, depthCount * sizeof(*states));
    }

    parents[0] = (cepCell*)CEP_P(start);

#define CEP_CLEAN_FIND_PATH()                                                  \
    do {                                                                       \
        if (!prev && stateHeap)                                                \
            cep_free(states);                                                  \
        if (parentsHeap)                                                       \
            cep_free(parents);                                                 \
    } while (0)

    unsigned depth = 0;
    while (true) {
        assert(depth < depthCount);
        cepCell* parent = parents[depth];
        uintptr_t* statePtr = states? &states[depth]: NULL;

        cepPast* segment = &path->past[depth];
        cepOpCount segSnapshot = segment->timestamp? segment->timestamp: snapshot;
        cepCell* child = cep_cell_find_next_by_name_past(parent, &segment->dt, statePtr, segSnapshot);
        if (!child) {
            if (statePtr)
                *statePtr = 0;
            if (depth == 0) {
                CEP_CLEAN_FIND_PATH();
                return NULL;
            }
            depth--;
            continue;
        }

        parents[depth + 1] = child;

        if (depth + 1 == depthCount) {
            CEP_CLEAN_FIND_PATH();
            return child;
        }

        depth++;
        if (states)
            states[depth] = 0;
    }

#undef CEP_CLEAN_FIND_PATH
}


/* Visit each direct child of a cell in storage order. Resolve through links to 
   the owning store and delegate to store_traverse with the provided callback. 
   Expose a shallow iteration primitive without leaking storage-specific details.
*/
/** Walk the immediate children of @p cell and invoke @p func for each entry,
    wiring enough metadata into @p entry so callbacks understand position and
    depth. Returning false from the callback aborts the traversal early. */
bool cep_cell_traverse(cepCell* cell, cepTraverse func, void* context, cepEntry* entry) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, NULL);
    if (!func)
        return false;

    cepEntry localEntry;
    if (!entry) {
        entry = &localEntry;
        CEP_0(entry);
    }

    cepTraverseFilterCtx ctx = {
        .func = func,
        .context = context,
        .userEntry = entry,
    };

    return store_traverse(store, cep_traverse_visible_filter, &ctx, NULL);
}

/* Visit direct children using the storage's native layout. Tree stores surface
   their physical pre-order (root, left, right), hash tables iterate buckets in
   allocation order, and other backends fall back to the logical traversal when
   both orders coincide. */
bool cep_cell_traverse_internal(cepCell* cell, cepTraverse func, void* context, cepEntry* entry) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, true);
    if (!func)
        return false;

    cepEntry localEntry;
    if (!entry) {
        entry = &localEntry;
        CEP_0(entry);
    }

    cepTraverseFilterCtx ctx = {
        .func = func,
        .context = context,
        .userEntry = entry,
    };

    return store_traverse_internal(store, cep_traverse_visible_filter, &ctx, NULL);
}


/* Traverse children as they existed at a specific time. Build a filtering 
   context around store_traverse that emits only entries visible at the requested 
   timestamp. Allow observers to inspect historical states without mutating the 
   structure.
*/
/** Replay the child list as it looked at @p timestamp and invoke @p func for
    each entry, allowing callers to inspect historical topologies without
    mutating the live tree. */
bool cep_cell_traverse_past(cepCell* cell, cepOpCount timestamp, cepTraverse func, void* context, cepEntry* entry) {
    assert(!cep_cell_is_void(cell) && func && timestamp);

    CELL_FOLLOW_LINK_TO_STORE(cell, store, true);

    cepEntry* userEntry = entry;
    if (!userEntry)
        userEntry = cep_alloca(sizeof(cepEntry));
    CEP_0(userEntry);

    cepEntry iterEntry;

    cepTraversePastCtx ctx = {
        .func = func,
        .context = context,
        .timestamp = timestamp,
        .userEntry = userEntry,
    };

    bool ok = store_traverse(store, cep_traverse_past_proxy, &ctx, &iterEntry);

    if (ok && ctx.hasPending)
        ok = cep_traverse_past_flush(&ctx, NULL);

    if (!ok)
        return false;

    return !ctx.aborted;
}


/* Perform a depth-first traversal of a cell hierarchy for a given snapshot. 
   Allocate per-depth frames, wrap callbacks with snapshot-aware proxies, and 
   reuse the generic deep traversal engine. Support history analyses that need 
   recursive inspection without altering the tree.
*/
/** Replay the entire subtree as it existed at @p timestamp, calling @p func for
    each node and @p endFunc at the end of sibling lists so historical traversals
    mimic the live API. */
bool cep_cell_deep_traverse_past(cepCell* cell, cepOpCount timestamp, cepTraverse func, cepTraverse endFunc, void* context, cepEntry* entry) {
    assert(!cep_cell_is_void(cell) && timestamp && (func || endFunc));

    CELL_FOLLOW_LINK_TO_STORE(cell, store, true);

    cepEntry* userEntry = entry;
    if (!userEntry)
        userEntry = cep_alloca(sizeof(cepEntry));
    CEP_0(userEntry);

    cepTraversePastFrameBuffer frameBuffer;
    cep_traverse_past_frame_buffer_init(&frameBuffer);

    cepDeepTraversePastCtx ctx = {
        .nodeFunc      = func,
        .endFunc       = endFunc,
        .context       = context,
        .timestamp     = timestamp,
        .userEntry     = userEntry,
        .frameBuffer   = &frameBuffer,
        .maxDepthInUse = 0,
    };

    cepEntry iterEntry;
    bool ok = cep_cell_deep_traverse(cell,
                                     cep_deep_traverse_past_proxy,
                                     (endFunc? cep_deep_traverse_past_end_proxy: NULL),
                                     &ctx,
                                     &iterEntry);

    if (ok) {
        if (!cep_deep_traverse_past_sync_depth(&ctx, 0))
            ok = false;
    }

    if (ok) {
        if (!cep_traverse_past_frame_buffer_reserve(ctx.frameBuffer, 0)) {
            ok = false;
        } else if (ctx.frameBuffer->data[0].hasPending) {
            ok = cep_deep_traverse_past_flush_frame(&ctx, 0, NULL);
        }
    }

    cep_traverse_past_frame_buffer_destroy(&frameBuffer);

    if (!ok)
        return false;

    return !ctx.aborted;
}


/*
    Traverses each child branch and *sub-branch* of a cell, applying a function to each one
*/
/** Walk a cell and its descendants depth-first, calling @p func for each node
    and @p endFunc when a sibling list finishes so callers can maintain custom
    stacks or emit delimiters. */
bool cep_cell_deep_traverse(cepCell* cell, cepTraverse func, cepTraverse endFunc, void* context, cepEntry* entry) {
    assert(!cep_cell_is_void(cell) && (func || endFunc));

    if (!cep_cell_children(cell))
        return true;

    bool ok = true;
    cepCell* child;
    unsigned depth = 0;
    if (!entry)
        entry = cep_alloca(sizeof(cepEntry));
    CEP_0(entry);
    entry->parent = cell;
    entry->cell = cep_cell_first(cell);

    // Non-recursive version of branch descent:
    cepEntryStack stack;
    cep_entry_stack_init(&stack);

    for (;;) {
        // Ascend to parent if no more siblings in branch.
        if (!entry->cell) {
            if CEP_RARELY(!depth)  break;    // endFunc is never called on root book.
            depth--;

            if (endFunc) {
                ok = endFunc(&stack.data[depth], context);
                if (!ok)  break;
            }

            // Next cell.
            entry->cell     = stack.data[depth].next;
            entry->parent   = stack.data[depth].parent;
            entry->prev     = stack.data[depth].cell;
            entry->next     = NULL;
            entry->position = stack.data[depth].position + 1;
            entry->depth    = depth;
            continue;
        }

      NEXT_SIBLING:   // Get sibling
        switch (entry->parent->store->storage) {
          case CEP_STORAGE_LINKED_LIST: {
            entry->next = list_next(entry->cell);
            break;
          }
          case CEP_STORAGE_ARRAY: {
            entry->next = array_next((cepArray*) entry->parent->store, entry->cell);
            break;
          }
          case CEP_STORAGE_PACKED_QUEUE: {
            entry->next = packed_q_next((cepPackedQ*) entry->parent->store, entry->cell);
            break;
          }
          case CEP_STORAGE_RED_BLACK_T: {
            entry->next = rb_tree_next(entry->cell);
            break;
          }
          case CEP_STORAGE_OCTREE: {
            entry->next = octree_next(entry->cell);
            break;
          }
        }

        if (func) {
            ok = func(entry, context);
            if (!ok)  break;
        }

        // Descent to children if it's a book.
        if (cep_cell_children(entry->cell)
        && ((child = cep_cell_first(entry->cell)))) {
            if (!cep_entry_stack_reserve(&stack, depth)) {
                ok = false;
                break;
            }

            stack.data[depth++] = *entry;

            entry->parent   = entry->cell;
            entry->cell     = child;
            entry->prev     = NULL;
            entry->position = 0;
            entry->depth    = depth;

            goto NEXT_SIBLING;
        }

        // Next cell.
        entry->prev   = entry->cell;
        entry->cell = entry->next;
        entry->position += 1;
    }

    cep_entry_stack_destroy(&stack);

return ok;
}


/* Depth-first traversal that respects the storage's physical ordering. Tree
   backends walk their node layout in pre-order and hash tables scan bucket
   chains so callers can inspect structural shape; other backends defer to the
   standard deep traversal when physical and logical orders already align. */
bool cep_cell_deep_traverse_internal(cepCell* cell, cepTraverse func, cepTraverse endFunc, void* context, cepEntry* entry) {
    assert(!cep_cell_is_void(cell) && (func || endFunc));

    CELL_FOLLOW_LINK_TO_STORE(cell, store, true);
    if (!store->chdCount)
        return true;

    bool ok = true;
    cepCell* child;
    unsigned depth = 0;
    if (!entry)
        entry = cep_alloca(sizeof(cepEntry));
    CEP_0(entry);
    entry->parent = cell;
    entry->cell = store_first_child_internal(store);
    entry->prev = NULL;
    entry->position = 0;
    entry->depth = 0;

    cepEntryStack stack;
    cep_entry_stack_init(&stack);

    for (;;) {
        if (!entry->cell) {
            if CEP_RARELY(!depth)  break;
            depth--;

            if (endFunc) {
                ok = endFunc(&stack.data[depth], context);
                if (!ok)  break;
            }

            entry->cell   = stack.data[depth].next;
            entry->parent = stack.data[depth].parent;
            entry->prev   = stack.data[depth].cell;
            entry->next   = NULL;
            entry->position = stack.data[depth].position + 1;
            entry->depth  = depth;
            continue;
        }

      NEXT_SIBLING:
        entry->next = store_next_child_internal(entry->parent->store, entry->cell);

        if (func) {
            ok = func(entry, context);
            if (!ok)  break;
        }

        if (entry->cell->store && entry->cell->store->chdCount
        && ((child = store_first_child_internal(entry->cell->store)))) {
            if (!cep_entry_stack_reserve(&stack, depth)) {
                ok = false;
                break;
            }

            stack.data[depth++] = *entry;

            entry->parent   = entry->cell;
            entry->cell     = child;
            entry->prev     = NULL;
            entry->position = 0;
            entry->depth    = depth;

            goto NEXT_SIBLING;
        }

        entry->prev   = entry->cell;
        entry->cell   = entry->next;
        entry->position += 1;
    }

    cep_entry_stack_destroy(&stack);

    return ok;
}




/* Reindex a cell's children as a dictionary keyed by name. Resolve the child 
   store and invoke store_to_dictionary to rebuild its indexing mode. Enable 
   name-based lookups after data was initially appended without ordering 
   constraints.
*/
void cep_cell_to_dictionary(cepCell* cell) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store);
    store_to_dictionary(store);
}


/* Order a cell's children using a caller supplied comparator. Resolve the 
   underlying store and delegate to store_sort with the provided function and 
   context. Allow collections to impose deterministic ordering beyond insertion 
   order.
*/
void cep_cell_sort(cepCell* cell, cepCompare compare, void* context) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store);
    store_sort(store, compare, context);
}




/* Soft-remove the last child while keeping historical access. Mark the child 
   deleted, stamp a snapshot, and initialise the target as a link to the archived 
   cell. Preserve history without reshaping sibling order when popping from the 
   tail.
*/
bool cep_cell_child_take(cepCell* cell, cepCell* target) {
    if (!target)
        return false;

    CELL_FOLLOW_LINK_TO_STORE(cell, store, false);

    if (!store->writable || !store->chdCount || cep_store_hierarchy_locked(store->owner))
        return false;

    cepCell* child = store_last_child(store);
    if (!child)
        return false;

    bool childAlreadyDeleted = cep_cell_is_deleted(child);
    cepOpCount snapshot = childAlreadyDeleted? cep_cell_timestamp(): cep_cell_timestamp_next();
    if (!childAlreadyDeleted)
        cep_cell_delete(child);
    store->modified = snapshot;

    CEP_0(target);
    cepDT name = cep_dt_clean(cep_cell_get_name(child));
    cep_link_initialize(target, &name, child);

    // ToDo: attach link to the snapshot metadata once snapshot-aware links are implemented.

    return true;
}


/* Soft-remove the first child while keeping a link back to it. Mark the head 
   child deleted, capture the heartbeat, and transform the target into a link 
   pointing at the archived cell. Allow queue-like semantics without losing access 
   to prior state.
*/
bool cep_cell_child_pop(cepCell* cell, cepCell* target) {
    if (!target)
        return false;

    CELL_FOLLOW_LINK_TO_STORE(cell, store, false);

    if (!store->writable || !store->chdCount || cep_store_hierarchy_locked(store->owner))
        return false;

    cepCell* child = store_first_child(store);
    if (!child)
        return false;

    bool childAlreadyDeleted = cep_cell_is_deleted(child);
    cepOpCount snapshot = childAlreadyDeleted? cep_cell_timestamp(): cep_cell_timestamp_next();
    if (!childAlreadyDeleted)
        cep_cell_delete(child);
    store->modified = snapshot;

    CEP_0(target);
    cepDT name = cep_dt_clean(cep_cell_get_name(child));
    cep_link_initialize(target, &name, child);

    // ToDo: attach link to the snapshot metadata once snapshot-aware links are implemented.

    return true;
}


/* Physically remove the last child from a store. Resolve the store and call
   the backend take helper which also shifts sibling metadata. GC-only: history
   retention relies on the per-cell timestamps instead of cloned snapshots.
*/
bool cep_cell_child_take_hard(cepCell* cell, cepCell* target) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, false);
    return store_take_cell(store, target);
}


/* Physically remove the first child from a store. Resolve the store and use
   the backend pop helper to unlink the head entry and rebalance metadata. Same
   GC caveat as cep_cell_child_take_hard.
*/
bool cep_cell_child_pop_hard(cepCell* cell, cepCell* target) {
    CELL_FOLLOW_LINK_TO_STORE(cell, store, false);
    return store_pop_child(store, target);
}


/* Remove a cell from its parent and destroy its subtree. Optionally transfer
   the cell, then invoke storage-specific removal hooks and decrement counters.
   Destructive path: the append-only audit trail is carried by timestamps alone.
*/
void cep_cell_remove_hard(cepCell* cell, cepCell* target) {
    assert(cell && !cep_cell_is_root(cell));
    cepStore* store = cell->parent;
    store_remove_child(store, cell, target);
}





/*
   Encoding of names to/from 6-bit values:
   Decode an acronym identifier into readable text. Walk the 6-bit segments 
   stored in the ID, translate them to ASCII, and trim trailing padding spaces. 
   Present acronym-based cell names in human-friendly form.
*/
CEP_TEXT_TO_ACRONYM_(cep_text_to_acronym)

size_t cep_acronym_to_text(cepID acro, char s[10]) {
    assert(cep_id_text_valid(acro));
    cepID coded = cep_id(acro);

    unsigned length;
    for (length = 0; length < CEP_ACRON_MAX_CHARS; length++) {
        char c = (char)((coded >> (6 * ((CEP_ACRON_MAX_CHARS - 1) - length))) & 0x3F);  // Extract 6 bits for each character (starting from the highest bits).

        s[length] = c + 0x20;   // Restore the original ASCII character.
    }
    s[length] = '\0';

    while (length > 0  &&  s[length - 1] == ' ') {
        s[--length] = '\0';     // Replace trailing spaces with null characters.
    }

    return length;
}




/*
   Encoding of names to/from 5-bit values:
   Decode a word identifier into lowercase text. Iterate through 5-bit 
   segments, map them to characters or punctuation, and return the effective 
   length. Allow tooling to display word-based names stored in compact ID form.
*/ 
CEP_TEXT_TO_WORD_(cep_text_to_word)

size_t cep_word_to_text(cepID word, char s[12]) {
    assert(cep_id_text_valid(word));
    cepID coded = cep_id(word);

    const char* translation_table = ":_-.*";    // Reverse translation table for values 27-31.
    unsigned length;
    for (length = 0; length < CEP_WORD_MAX_CHARS; length++) {
        uint8_t encoded_char = (coded >> (5 * ((CEP_WORD_MAX_CHARS - 1) - length))) & 0x1F; // Extract each 5-bit segment, starting from the most significant bits.

        if (encoded_char >= 1  &&  encoded_char <= 26) {
            s[length] = (char)(encoded_char - 1 + 0x61);            // 'a' - 'z'.
        } else if (encoded_char == 0) {
            s[length] = ' ';                                        // Space.
        } else if (encoded_char >= 27  &&  encoded_char <= 31) {
            s[length] = translation_table[encoded_char - 27];       // Map 27-31 using table.
        }
    }
    s[length] = '\0';

    while (length > 0  &&  s[length - 1] == ' ') {
        s[--length] = '\0';     // Replace trailing spaces with null characters.
    }

    return length;
}
static bool cep_store_hierarchy_locked(const cepCell* cell) {
    return cep_cell_store_locked_hierarchy(cell);
}

static bool cep_data_hierarchy_locked(const cepCell* cell) {
    return cep_cell_data_locked_hierarchy(cell);
}

bool cep_store_lock(cepCell* cell, cepLockToken* token) {
    assert(cell && token);
    token->owner = NULL;
    cell = cep_link_pull(cell);
    if (!cep_cell_is_normal(cell) || !cell->store)
        return false;

    if (cep_store_hierarchy_locked(cell))
        return false;

    cell->store->lock = 1u;
    cell->store->lockOwner = cell;
    token->owner = cell;
    return true;
}

void cep_store_unlock(cepCell* cell, cepLockToken* token) {
    if (!cell || !token)
        return;

    cell = cep_link_pull(cell);
    if (!cep_cell_is_normal(cell) || !cell->store)
        return;

    if (cell->store->lock && cell->store->lockOwner == cell) {
        cell->store->lock = 0u;
        cell->store->lockOwner = NULL;
        token->owner = NULL;
    }
}

bool cep_data_lock(cepCell* cell, cepLockToken* token) {
    assert(cell && token);
    token->owner = NULL;
    cell = cep_link_pull(cell);
    if (!cep_cell_is_normal(cell) || !cell->data)
        return false;

    if (cep_data_hierarchy_locked(cell))
        return false;

    cell->data->lock = 1u;
    cell->data->lockOwner = cell;
    token->owner = cell;
    return true;
}

void cep_data_unlock(cepCell* cell, cepLockToken* token) {
    if (!cell || !token)
        return;

    cell = cep_link_pull(cell);
    if (!cep_cell_is_normal(cell) || !cell->data)
        return;

    if (cell->data->lock && cell->data->lockOwner == cell) {
        cell->data->lock = 0u;
        cell->data->lockOwner = NULL;
        token->owner = NULL;
    }
}
