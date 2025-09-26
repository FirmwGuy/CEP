/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include <stdbool.h>
#include <string.h>

/*
    Packed queues keep children in fixed-size chunks that behave like a deque.
    Each chunk contains `nodeCapacity` contiguous cells, giving cache-friendly
    iteration while still allowing prepend/append without moving existing data.
    Nodes are recycled to limit allocations; the queue stays compact by moving
    the tail element into arbitrary removed slots when necessary.

    Policy knob: `packed_q_new(capacity)` selects how many cells each chunk can
    hold. For workloads with steady queue sizes, pick a capacity that matches the
    average burst to reduce node churn. Call `packed_q_del_all_children` to wipe
    entries while keeping the queue for reuse, or `packed_q_del` to release
    everything including recycled nodes.
*/

typedef struct _cepPackedQNode  cepPackedQNode;

struct _cepPackedQNode {
    cepPackedQNode* next;       /**< Pointer to the next node in the list. */
    cepPackedQNode* prev;       /**< Previous node. */
    cepCell*        first;      /**< Current first live cell. */
    cepCell*        last;       /**< Current last live cell. */
    size_t          count;      /**< Number of live cells in this node. */
    cepPackedQNode* recycleNext;/**< Next node in the recycle list when not active. */
    cepCell         cell[];     /**< Fixed-size buffer for this node. */
};

typedef struct {
    cepStore        store;      /**< Parent info. */
    size_t          nodeSize;   /**< Node storage size in bytes. */
    size_t          nodeCapacity; /**< Number of cells per node. */
    cepPackedQNode* head;       /**< Head of the buffer list. */
    cepPackedQNode* tail;       /**< Tail of the buffer list. */
    cepPackedQNode* freeNodes;  /**< Recycled nodes ready for reuse. */
} cepPackedQ;




/*
    Packed Queue implementation
*/

static inline cepPackedQ* packed_q_new(int capacity) {
    CEP_NEW(cepPackedQ, pkdq);
    pkdq->nodeCapacity = (size_t)cep_max(1, capacity);
    pkdq->nodeSize = pkdq->nodeCapacity * sizeof(cepCell);
    pkdq->head = pkdq->tail = pkdq->freeNodes = NULL;
    return pkdq;
}


static inline cepPackedQNode* packed_q_node_acquire(cepPackedQ* pkdq) {
    cepPackedQNode* node = pkdq->freeNodes;
    if (node) {
        pkdq->freeNodes = node->recycleNext;
        memset(node, 0, sizeof *node + pkdq->nodeSize);
        return node;
    }
    return (cepPackedQNode*)cep_malloc0(sizeof(cepPackedQNode) + pkdq->nodeSize);
}

static inline void packed_q_node_release(cepPackedQ* pkdq, cepPackedQNode* node) {
    if (!node)
        return;
    node->next = node->prev = NULL;
    node->first = node->last = NULL;
    node->count = 0;
    node->recycleNext = pkdq->freeNodes;
    pkdq->freeNodes = node;
}


static inline cepPackedQNode* packed_q_node_from_cell(cepPackedQ* pkdq, cepCell* cell) {
    for (cepPackedQNode* node = pkdq->head; node; node = node->next) {
        if (node->first <= cell && node->last >= cell)
            return node;
    }
    return NULL;
}


static inline cepCell* packed_q_node_begin(cepPackedQNode* node) {
    return node->cell;
}

static inline cepCell* packed_q_node_end(cepPackedQNode* node, size_t nodeCapacity) {
    return node->cell + (nodeCapacity - 1);
}

static inline cepCell* packed_q_append(cepPackedQ* pkdq, cepCell* cell, bool prepend) {
    cepPackedQNode* node;
    cepCell* child;

    if (pkdq->store.chdCount) {
        if (prepend) {
            node = pkdq->head;
            cepCell* begin = packed_q_node_begin(node);
            if (node->count < pkdq->nodeCapacity && node->first > begin) {
                node->first--;
            } else {
                cepPackedQNode* newNode = packed_q_node_acquire(pkdq);
                newNode->first = newNode->last = packed_q_node_end(newNode, pkdq->nodeCapacity);
                newNode->count = 0;
                newNode->next = node;
                newNode->prev = NULL;
                node->prev = newNode;
                pkdq->head = newNode;
                node = newNode;
            }
            child = node->first;
        } else {
            node = pkdq->tail;
            cepCell* end = packed_q_node_end(node, pkdq->nodeCapacity);
            if (node->count < pkdq->nodeCapacity && node->last < end) {
                node->last++;
            } else {
                cepPackedQNode* newNode = packed_q_node_acquire(pkdq);
                newNode->first = newNode->last = newNode->cell;
                newNode->count = 0;
                newNode->prev = node;
                newNode->next = NULL;
                node->next = newNode;
                pkdq->tail = newNode;
                node = newNode;
            }
            child = node->last;
        }
    } else {
        node = packed_q_node_acquire(pkdq);
        node->first = node->last = node->cell;
        node->count = 0;
        node->next = node->prev = NULL;
        pkdq->head = pkdq->tail = node;
        child = node->cell;
    }

    cep_cell_transfer(cell, child);
    if (node->count == 0) {
        node->first = node->last = child;
    }
    node->count++;

    return child;
}


static inline cepCell* packed_q_first(cepPackedQ* pkdq) {
    return pkdq->head ? pkdq->head->first : NULL;
}


static inline cepCell* packed_q_last(cepPackedQ* pkdq) {
    return pkdq->tail ? pkdq->tail->last : NULL;
}


static inline cepCell* packed_q_find_by_name(cepPackedQ* pkdq, const cepDT* name) {
    for (cepPackedQNode* node = pkdq->head; node; node = node->next) {
        for (cepCell* cell = node->first; cell <= node->last; ++cell) {
            if (cep_cell_name_is(cell, name))
                return cell;
        }
    }
    return NULL;
}


static inline cepCell* packed_q_find_by_position(cepPackedQ* pkdq, size_t position) {
    for (cepPackedQNode* node = pkdq->head; node; node = node->next) {
        size_t chunk = node->count;
        if (chunk > position) {
            return node->first + position;
        }
        position -= chunk;
    }
    return NULL;
}


static inline cepCell* packed_q_prev(cepPackedQ* pkdq, cepCell* cell) {
    cepPackedQNode* node = packed_q_node_from_cell(pkdq, cell);
    assert(node);
    if (node->first == cell)
        return NULL;
    return cell - 1;
}


static inline cepCell* packed_q_next(cepPackedQ* pkdq, cepCell* cell) {
    cepPackedQNode* node = packed_q_node_from_cell(pkdq, cell);
    assert(node);
    if (node->last == cell)
        return NULL;
    return cell + 1;
}


static inline cepCell* packed_q_next_by_name(cepPackedQ* pkdq, cepDT* name, cepPackedQNode** prev) {
    for (cepPackedQNode* node = prev? (*prev)->next: pkdq->head; node; node = node->next) {
        for (cepCell* cell = node->first; cell <= node->last; ++cell) {
            if (cep_cell_name_is(cell, name)) {
                if (prev)
                    *prev = node;
                return cell;
            }
        }
    }
    if (prev)
        *prev = NULL;
    return NULL;
}


static inline bool packed_q_traverse(cepPackedQ* pkdq, cepTraverse func, void* context, cepEntry* entry) {
    entry->parent = pkdq->store.owner;
    entry->depth  = 0;
    entry->cell = entry->next = NULL;
    for (cepPackedQNode* node = pkdq->head; node; node = node->next) {
        entry->next = node->first;
        do {
            if (entry->cell) {
                if (!func(entry, context))
                    return false;
                entry->position++;
                entry->prev = entry->cell;
            }
            entry->cell = entry->next;
            entry->next++;
        } while (entry->next <= node->last);
    }
    entry->next = NULL;
    return func(entry, context);
}


static inline void packed_q_take(cepPackedQ* pkdq, cepCell* target) {
    cepPackedQNode* node = pkdq->tail;
    cepCell* last = node->last;
    cep_cell_transfer(last, target);
    if (node->count > 1) {
        node->last--;
        node->count--;
        CEP_0(last);
    } else {
        node->last = node->first = NULL;
        node->count = 0;
        pkdq->tail = node->prev;
        if (pkdq->tail)
            pkdq->tail->next = NULL;
        else
            pkdq->head = NULL;
        packed_q_node_release(pkdq, node);
    }
}


static inline void packed_q_pop(cepPackedQ* pkdq, cepCell* target) {
    cepPackedQNode* node = pkdq->head;
    cepCell* first = node->first;
    cep_cell_transfer(first, target);
    if (node->count > 1) {
        node->first++;
        node->count--;
        CEP_0(first);
    } else {
        node->first = node->last = NULL;
        node->count = 0;
        pkdq->head = node->next;
        if (pkdq->head)
            pkdq->head->prev = NULL;
        else
            pkdq->tail = NULL;
        packed_q_node_release(pkdq, node);
    }
}


static inline void packed_q_remove_cell(cepPackedQ* pkdq, cepCell* cell) {
    cepPackedQNode* node = packed_q_node_from_cell(pkdq, cell);
    assert(node);

    cepCell* cursor = cell;
    for (;;) {
        if (cursor < node->last) {
            cep_cell_transfer(cursor + 1, cursor);
            cursor++;
            continue;
        }

        if (node->next) {
            cepCell* nextFirst = node->next->first;
            cep_cell_transfer(nextFirst, cursor);
            node = node->next;
            cursor = node->first;
            continue;
        }

        // Removing the logical tail element.
        CEP_0(cursor);
        node->count--;
        if (node->count) {
            node->last--;
        } else {
            node->first = node->last = NULL;
            if (node->prev)
                node->prev->next = NULL;
            else
                pkdq->head = NULL;
            pkdq->tail = node->prev;
            packed_q_node_release(pkdq, node);
        }
        break;
    }
}


static inline void packed_q_del_all_children(cepPackedQ* pkdq) {
    cepPackedQNode* node = pkdq->head;
    while (node) {
        if (node->count) {
            for (cepCell* cell = node->first; cell <= node->last; ++cell)
                cep_cell_finalize(cell);
        }
        cepPackedQNode* next = node->next;
        packed_q_node_release(pkdq, node);
        node = next;
    }
    pkdq->head = pkdq->tail = NULL;
}

static inline void packed_q_del(cepPackedQ* pkdq) {
    if (!pkdq)
        return;
    packed_q_del_all_children(pkdq);
    while (pkdq->freeNodes) {
        cepPackedQNode* next = pkdq->freeNodes->recycleNext;
        cep_free(pkdq->freeNodes);
        pkdq->freeNodes = next;
    }
    cep_free(pkdq);
}
