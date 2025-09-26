/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


typedef struct _cepHashNode    cepHashNode;

struct _cepHashNode {
    cepHashNode*        bucketNext;     // Next node in the bucket chain.
    cepHashNode*        orderNext;      // Next node in the global ordering list.
    cepHashNode*        orderPrev;      // Previous node in the global ordering list.
    uint64_t            hash;           // Cached hash for quick bucket dispatch.
    cepCell             cell;           // Stored cell payload.
};

typedef struct {
    cepStore            store;          // Parent info header – keeps metadata shared with cepStore.
    cepHashNode**       buckets;        // Bucket table used for hash lookups.
    size_t              bucketCount;    // Number of buckets – always a power of two.
    size_t              bucketMask;     // bucketCount - 1, used to map hashes into buckets.
    cepHashNode*        head;           // First node in sorted iteration order.
    cepHashNode*        tail;           // Last node in sorted iteration order.
} cepHashTable;


/* Derive a load-friendly bucket count from the requested capacity so lookups
   stay close to O(1). We round up to the next power of two and clamp to a
   sensible minimum to keep rehashing rare for tiny collections.
*/
static inline size_t hash_table_ideal_bucket_count(size_t capacity) {
    size_t desired = cep_max(capacity, (size_t)8);
    return cep_next_pow_of_two(desired);
}


/* Compute the primary hash used by this storage backend. Normal cells prefer
   the cached payload hash when data is present; otherwise we fall back to the
   Domain/Tag tuple so lookups stay deterministic for structural-only nodes.
*/
static inline uint64_t hash_table_cell_hash(const cepCell* cell) {
    assert(cell);

    if (cep_cell_is_normal(cell) && cell->data)
        return cell->data->hash;

    return cep_hash_bytes(&cell->metacell._dt, sizeof(cell->metacell._dt));
}


/* Map a cell pointer taken from client code back to the owning node so we can
   hop between iteration order and bucket chains without leaking implementation
   details outside the storage backend.
*/
static inline cepHashNode* hash_table_node_from_cell(const cepCell* cell) {
    assert(cell);
    return cep_ptr_dif(cell, offsetof(cepHashNode, cell));
}


/* Insert a node into the bucket list associated with its hash. We prepend to
   keep the code simple—the global ordering list preserves deterministic
   iteration, so bucket order does not matter.
*/
static inline void hash_table_bucket_link(cepHashTable* table, cepHashNode* node) {
    assert(table && node && table->bucketMask);
    size_t index = node->hash & table->bucketMask;
    node->bucketNext = table->buckets[index];
    table->buckets[index] = node;
}


/* Remove a node from its bucket chain while leaving iteration wiring intact.
   We linearly scan the short bucket list because rehashing keeps load factors
   bounded, making this removal O(1) on average.
*/
static inline void hash_table_bucket_unlink(cepHashTable* table, cepHashNode* node) {
    assert(table && node && table->bucketMask);
    size_t index = node->hash & table->bucketMask;
    cepHashNode* iter = table->buckets[index];
    cepHashNode* prev = NULL;
    while (iter) {
        if (iter == node) {
            if (prev)
                prev->bucketNext = iter->bucketNext;
            else
                table->buckets[index] = iter->bucketNext;
            return;
        }
        prev = iter;
        iter = iter->bucketNext;
    }
    assert(!"Node missing from hash bucket chain");
}


/* Stitch a node into the global ordering list so traversal remains sorted by
   hash first and comparator second. This keeps iteration deterministic and
   makes positional lookups meaningful even in a hashed container.
*/
static inline void hash_table_order_link(cepHashTable* table, cepHashNode* node, cepCompare compare, void* context) {
    assert(table && node);

    cepHashNode* iter = table->head;
    cepHashNode* prev = NULL;
    while (iter) {
        if (node->hash < iter->hash)
            break;
        if (node->hash == iter->hash && compare) {
            int cmp = compare(&node->cell, &iter->cell, context);
            if (cmp < 0)
                break;
        }
        prev = iter;
        iter = iter->orderNext;
    }

    node->orderPrev = prev;
    node->orderNext = iter;

    if (iter)
        iter->orderPrev = node;
    else
        table->tail = node;

    if (prev)
        prev->orderNext = node;
    else
        table->head = node;
}


/* Unlink a node from the ordering list, updating neighbours and head/tail as
   needed. Buckets are left untouched; callers combine this with bucket removal
   when tearing nodes down.
*/
static inline void hash_table_order_unlink(cepHashTable* table, cepHashNode* node) {
    assert(table && node);

    cepHashNode* next = node->orderNext;
    cepHashNode* prev = node->orderPrev;

    if (next)
        next->orderPrev = prev;
    else
        table->tail = prev;

    if (prev)
        prev->orderNext = next;
    else
        table->head = next;

    node->orderNext = node->orderPrev = NULL;
}


/* Grow the bucket table when the container gets crowded so lookups remain
   efficient. Nodes keep their global ordering; we simply rebuild the bucket
   chains against the new mask.
*/
static inline void hash_table_rehash(cepHashTable* table, size_t newBucketCount) {
    assert(table && newBucketCount && cep_is_pow_of_two(newBucketCount));

    cepHashNode** buckets = cep_malloc0(newBucketCount * sizeof *buckets);
    cepHashNode* node = table->head;
    size_t mask = newBucketCount - 1;
    while (node) {
        size_t index = node->hash & mask;
        node->bucketNext = buckets[index];
        buckets[index] = node;
        node = node->orderNext;
    }

    cep_free(table->buckets);
    table->buckets = buckets;
    table->bucketCount = newBucketCount;
    table->bucketMask = mask;
}


/* Ensure the table's load factor stays healthy by doubling the bucket count
   whenever we would exceed a 1.0 load factor. The combination keeps operations
   fast without complicating the allocator model.
*/
static inline void hash_table_maybe_grow(cepHashTable* table) {
    assert(table);
    if (!table->bucketCount || table->store.chdCount < table->bucketCount)
        return;
    hash_table_rehash(table, table->bucketCount << 1);
}


/* Allocate a fresh hash table with enough buckets to honour the requested
   capacity. Buckets start zeroed and the ordering list is empty, ready to host
   inserted cells.
*/
static inline cepHashTable* hash_table_new(size_t capacity) {
    CEP_NEW(cepHashTable, table);
    size_t bucketCount = hash_table_ideal_bucket_count(capacity);
    table->bucketCount = bucketCount;
    table->bucketMask = bucketCount - 1;
    table->buckets = cep_malloc0(bucketCount * sizeof *table->buckets);
    table->head = table->tail = NULL;
    return table;
}


/* Release every node held by the table while preserving the table structure
   for reuse. Children are finalised before we release their nodes so ownership
   is honoured across storage backends.
*/
static inline void hash_table_del_all_children(cepHashTable* table) {
    assert(table);
    cepHashNode* node = table->head;
    while (node) {
        cepHashNode* next = node->orderNext;
        cep_cell_finalize_hard(&node->cell);
        cep_free(node);
        node = next;
    }
    table->head = table->tail = NULL;
    if (table->buckets)
        memset(table->buckets, 0, table->bucketCount * sizeof *table->buckets);
}


/* Tear down a hash table entirely, first clearing its children and then
   releasing the bucket array alongside the table header itself.
*/
static inline void hash_table_del(cepHashTable* table) {
    if (!table)
        return;
    hash_table_del_all_children(table);
    cep_free(table->buckets);
    cep_free(table);
}


/* Insert a cell using the hash/comparator ordering so keyed lookups and
   traversal stay deterministic. The caller already checked for duplicates, so
   we simply move the payload, grow buckets when needed, and link the node in.
*/
static inline cepCell* hash_table_sorted_insert(cepHashTable* table, cepCell* cell, cepCompare compare, void* context) {
    assert(table && cell && compare);

    hash_table_maybe_grow(table);

    CEP_NEW(cepHashNode, node);
    node->hash = hash_table_cell_hash(cell);
    node->bucketNext = node->orderNext = node->orderPrev = NULL;

    cep_cell_transfer(cell, &node->cell);

    hash_table_bucket_link(table, node);
    hash_table_order_link(table, node, compare, context);

    return &node->cell;
}


/* Locate a child by hashed key, falling back to the comparator when collisions
   occur. Buckets are thin, so we can linearly scan them without impacting the
   expected O(1) behaviour.
*/
static inline cepCell* hash_table_find_by_key(cepHashTable* table, cepCell* key, cepCompare compare, void* context) {
    assert(table && key && compare);

    if (!table->bucketCount)
        return NULL;

    uint64_t hash = hash_table_cell_hash(key);
    size_t index = hash & table->bucketMask;
    for (cepHashNode* node = table->buckets[index]; node; node = node->bucketNext) {
        if (node->hash != hash)
            continue;
        if (compare(key, &node->cell, context) == 0)
            return &node->cell;
    }
    return NULL;
}


/* Fetch the first child following hash ordering so callers can start
   traversing from the beginning without peeking into implementation details.
*/
static inline cepCell* hash_table_first(cepHashTable* table) {
    assert(table);
    return table->head? &table->head->cell: NULL;
}


/* Fetch the last child following hash ordering, useful for pop/take helpers
   and reverse iteration.
*/
static inline cepCell* hash_table_last(cepHashTable* table) {
    assert(table);
    return table->tail? &table->tail->cell: NULL;
}


/* Iterate linearly until the desired position is reached. The ordering list is
   already deterministic, so positional lookups remain predictable even in a
   hash-backed container.
*/
static inline cepCell* hash_table_find_by_position(cepHashTable* table, size_t position) {
    assert(table);
    cepHashNode* node = table->head;
    size_t index = 0;
    while (node) {
        if (index == position)
            return &node->cell;
        node = node->orderNext;
        index++;
    }
    return NULL;
}


/* Scan ordered nodes looking for a matching Domain/Tag pair. This is slower
   than a dictionary store but still acceptable for occasional lookups on hash
   tables where names are secondary.
*/
static inline cepCell* hash_table_find_by_name(cepHashTable* table, const cepDT* name) {
    assert(table && name);
    for (cepHashNode* node = table->head; node; node = node->orderNext) {
        if (cep_cell_name_is(&node->cell, name))
            return &node->cell;
    }
    return NULL;
}


/* Step backwards in hash order from the supplied cell. We recover the owning
   node and follow its ordering links so callers receive the immediate previous
   sibling or NULL when none exists.
*/
static inline cepCell* hash_table_prev(cepHashTable* table, cepCell* cell) {
    assert(table && cell);
    cepHashNode* node = hash_table_node_from_cell(cell);
    cepHashNode* prev = node->orderPrev;
    return prev? &prev->cell: NULL;
}


/* Step forward in hash order from the supplied cell. This keeps sibling walks
   fast without exposing the internal node representation to the caller.
*/
static inline cepCell* hash_table_next(cepHashTable* table, cepCell* cell) {
    assert(table && cell);
    cepHashNode* node = hash_table_node_from_cell(cell);
    cepHashNode* next = node->orderNext;
    return next? &next->cell: NULL;
}


/* Iterate over siblings sharing the same name. We resume from the previously
   returned node when the caller supplies `childIdx`, enabling efficient
   multi-match scans without restarting from the head.
*/
static inline cepCell* hash_table_next_by_name(cepHashTable* table, cepDT* name, uintptr_t* childIdx) {
    assert(table && name);

    cepHashNode* node;
    if (!childIdx || !*childIdx)
        node = table->head;
    else
        node = ((cepHashNode*)(*childIdx))->orderNext;

    while (node) {
        if (cep_cell_name_is(&node->cell, name)) {
            CEP_PTR_SEC_SET(childIdx, (uintptr_t)node);
            return &node->cell;
        }
        node = node->orderNext;
    }

    CEP_PTR_SEC_SET(childIdx, 0);
    return NULL;
}


/* Traverse all children in hash order and invoke the provided callback on each
   entry. We reuse the shared `cepEntry` layout so higher layers see the same
   traversal semantics as with other storage backends.
*/
static inline bool hash_table_traverse(cepHashTable* table, cepTraverse func, void* context, cepEntry* entry) {
    assert(table && func);

    if (!table->store.chdCount)
        return true;

    cepEntry localEntry;
    if (!entry) {
        CEP_0(&localEntry);
        entry = &localEntry;
    } else {
        CEP_0(entry);
    }

    entry->parent = table->store.owner;
    entry->depth = 0;
    entry->position = 0;
    entry->prev = NULL;

    cepHashNode* node = table->head;
    entry->next = node? &node->cell: NULL;

    while (node) {
        entry->cell = &node->cell;
        entry->next = node->orderNext? &node->orderNext->cell: NULL;
        if (!func(entry, context))
            return false;
        entry->prev = entry->cell;
        entry->position++;
        node = node->orderNext;
    }

    return true;
}


static inline cepCell* hash_table_internal_first(cepHashTable* table) {
    assert(table);
    if (!table->store.chdCount)
        return NULL;
    if (!table->bucketCount)
        return hash_table_first(table);
    for (size_t i = 0; i < table->bucketCount; ++i) {
        cepHashNode* node = table->buckets[i];
        if (node)
            return &node->cell;
    }
    return NULL;
}


static inline cepCell* hash_table_internal_next(cepHashTable* table, cepCell* cell) {
    assert(table && cell);

    cepHashNode* node = hash_table_node_from_cell(cell);
    if (node->bucketNext)
        return &node->bucketNext->cell;

    if (!table->bucketCount)
        return hash_table_next(table, cell);

    size_t index = node->hash & table->bucketMask;
    for (size_t i = index + 1; i < table->bucketCount; ++i) {
        cepHashNode* next = table->buckets[i];
        if (next)
            return &next->cell;
    }

    return NULL;
}


static inline bool hash_table_traverse_internal(cepHashTable* table, cepTraverse func, void* context, cepEntry* entry) {
    assert(table && func);

    if (!table->store.chdCount)
        return true;

    if (!table->bucketCount)
        return hash_table_traverse(table, func, context, entry);

    cepEntry localEntry;
    if (!entry) {
        CEP_0(&localEntry);
        entry = &localEntry;
    } else {
        CEP_0(entry);
    }

    entry->parent = table->store.owner;
    entry->depth  = 0;
    entry->position = 0;
    entry->prev = NULL;
    entry->cell = NULL;
    entry->next = NULL;

    for (size_t bucket = 0; bucket < table->bucketCount; ++bucket) {
        for (cepHashNode* node = table->buckets[bucket]; node; node = node->bucketNext) {
            if (entry->cell) {
                if (!func(entry, context))
                    return false;
                entry->position++;
                entry->prev = entry->cell;
            }

            entry->cell = &node->cell;

            cepHashNode* peek = node->bucketNext;
            size_t peekBucket = bucket;
            while (!peek && ++peekBucket < table->bucketCount)
                peek = table->buckets[peekBucket];
            entry->next = peek? &peek->cell: NULL;
        }
    }

    return func(entry, context);
}


/* Remove the last child from the table, return its payload to the caller, and
   free the underlying node. Buckets and ordering links are updated so the
   structure stays consistent.
*/
static inline void hash_table_take(cepHashTable* table, cepCell* target) {
    assert(table && table->tail && target);

    cepHashNode* node = table->tail;
    hash_table_order_unlink(table, node);
    hash_table_bucket_unlink(table, node);

    cep_cell_transfer(&node->cell, target);
    cep_free(node);
}


/* Remove the first child from the table, mirroring pop-front semantics used by
   other storage engines. The payload moves into `target` before the node is
   reclaimed.
*/
static inline void hash_table_pop(cepHashTable* table, cepCell* target) {
    assert(table && table->head && target);

    cepHashNode* node = table->head;
    hash_table_order_unlink(table, node);
    hash_table_bucket_unlink(table, node);

    cep_cell_transfer(&node->cell, target);
    cep_free(node);
}


/* Remove an arbitrary child whose payload has already been handled by the
   caller. We only need to adjust bookkeeping links and release the node.
*/
static inline void hash_table_remove_cell(cepHashTable* table, cepCell* cell) {
    assert(table && cell);

    cepHashNode* node = hash_table_node_from_cell(cell);
    hash_table_order_unlink(table, node);
    hash_table_bucket_unlink(table, node);
    cep_free(node);
}
