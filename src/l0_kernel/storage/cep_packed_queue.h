/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 * 
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */


typedef struct _cepPackedQNode  cepPackedQNode;

struct _cepPackedQNode {
    cepPackedQNode* pNext;      // Pointer to the next node in the list.
    cepPackedQNode* pPrev;      // Previous node.
    cepCell*        first;      // Points to the first cell in buffer.
    cepCell*        last;       // The last cell.
    //
    cepCell         cell[];     // Fixed-size buffer for this node.
};

typedef struct {
    cepStore        store;      // Parent info.
    //
    size_t          pSize;      // Pack (node) size in bytes.
    cepPackedQNode* pHead;      // Head of the buffer list.
    cepPackedQNode* pTail;      // Tail of the buffer list.
} cepPackedQ;




/*
    Packed Queue implementation
*/

static inline cepPackedQ* packed_q_new(int capacity) {
    CEP_NEW(cepPackedQ, pkdq);
    pkdq->pSize = capacity * sizeof(cepCell);
    return pkdq;
}


#define packed_q_del              cep_free
#define packed_q_node_new(pkdq)   cep_malloc0(sizeof(cepPackedQNode) + (pkdq)->pSize)
#define packed_q_node_del         cep_free


static inline cepPackedQNode* packed_q_node_from_cell(cepPackedQ* pkdq, cepCell* cell) {
    for (cepPackedQNode* pNode = pkdq->pHead;  pNode;  pNode = pNode->pNext) {
        if (pNode->first <= cell  &&  pNode->last >= cell)
            return pNode;
    }
    return NULL;
}


static inline cepCell* packed_q_append(cepPackedQ* pkdq, cepCell* cell, bool prepend) {
    cepCell* child;

    if (pkdq->store.chdCount) {
        if (prepend) {
            if (pkdq->pHead->first > pkdq->pHead->cell) {
                pkdq->pHead->first--;
            } else {
                cepPackedQNode* pNode = packed_q_node_new(pkdq);
                pNode->first = pNode->last = cep_ptr_off(pNode->cell, pkdq->pSize - sizeof(cepCell));
                pNode->pNext = pkdq->pHead;
                pkdq->pHead->pPrev = pNode;
                pkdq->pHead = pNode;
            }
            child = pkdq->pHead->first;
        } else {
            if (pkdq->pTail->last < (cepCell*)cep_ptr_off(pkdq->pTail->cell, pkdq->pSize - sizeof(cepCell))) {
                pkdq->pTail->last++;
            } else {
                cepPackedQNode* pNode = packed_q_node_new(pkdq);
                pNode->last  = pNode->first = pNode->cell;
                pNode->pPrev = pkdq->pTail;
                pkdq->pTail->pNext = pNode;
                pkdq->pTail = pNode;
            }
            child = pkdq->pTail->last;
        }
    } else {
        assert(!pkdq->pTail);
        cepPackedQNode* pNode = packed_q_node_new(pkdq);
        pNode->last = pNode->first = pNode->cell;
        pkdq->pTail = pkdq->pHead = pNode;
        child = pNode->last;
    }

    cep_cell_transfer(cell, child);

    return child;
}


static inline cepCell* packed_q_first(cepPackedQ* pkdq) {
    return pkdq->pHead->first;
}


static inline cepCell* packed_q_last(cepPackedQ* pkdq) {
    return pkdq->pTail->last;
}


static inline cepCell* packed_q_find_by_name(cepPackedQ* pkdq, const cepDT* name) {
    for (cepPackedQNode* pNode = pkdq->pHead;  pNode;  pNode = pNode->pNext) {
        for (cepCell* cell = pNode->first;  cell <= pNode->last;  cell++) {
            if (cep_cell_name_is(cell, name))
                return cell;
        }
    }
    return NULL;
}


static inline cepCell* packed_q_find_by_position(cepPackedQ* pkdq, size_t position) {
    // ToDo: use from tail to head if index is closer to it.
    for (cepPackedQNode* pNode = pkdq->pHead;  pNode;  pNode = pNode->pNext) {
        size_t chunk = cep_ptr_idx(pNode->first, pNode->last, sizeof(cepCell)) + 1;
        if (chunk > position) {
            return &pNode->first[position];
        }
        position -= chunk;
    }
    return NULL;
}


static inline cepCell* packed_q_prev(cepPackedQ* pkdq, cepCell* cell) {
    cepPackedQNode* pNode = packed_q_node_from_cell(pkdq, cell);
    assert(pNode);
    if (pNode->first == cell)
        return NULL;
    return cell - 1;
}


static inline cepCell* packed_q_next(cepPackedQ* pkdq, cepCell* cell) {
    cepPackedQNode* pNode = packed_q_node_from_cell(pkdq, cell);
    assert(pNode);
    if (pNode->last == cell)
        return NULL;
    return cell + 1;
}


static inline cepCell* packed_q_next_by_name(cepPackedQ* pkdq, cepDT* name, cepPackedQNode** prev) {
    for (cepPackedQNode* pNode = prev? (*prev)->pNext: pkdq->pHead;  pNode;  pNode = pNode->pNext) {
        for (cepCell* cell = pNode->first;  cell <= pNode->last;  cell++) {
            if (cep_cell_name_is(cell, name))
                return cell;
        }
    }
    return NULL;
}


static inline bool packed_q_traverse(cepPackedQ* pkdq, cepTraverse func, void* context, cepEntry* entry) {
    entry->parent = pkdq->store.owner;
    entry->depth  = 0;
    cepPackedQNode* pNode = pkdq->pHead;
    do {
        entry->next = pNode->first;
        do {
            if (entry->cell) {
                if (!func(entry, context))
                    return false;
                entry->position++;
                entry->prev = entry->cell;
            }
            entry->cell = entry->next;
            entry->next++;
        } while (entry->next <= pNode->last);
        pNode = pNode->pNext;
    } while (pNode);
    entry->next = NULL;
    return func(entry, context);
}


static inline void packed_q_take(cepPackedQ* pkdq, cepCell* target) {
    cepCell* last = pkdq->pTail->last;
    cep_cell_transfer(last, target);
    pkdq->pTail->last--;
    if (pkdq->pTail->last >= pkdq->pTail->first) {
        CEP_0(last);
    } else {
        cepPackedQNode* pNode = pkdq->pTail;
        pkdq->pTail = pkdq->pTail->pPrev;
        if (pkdq->pTail)
            pkdq->pTail->pNext = NULL;
        else
            pkdq->pHead = NULL;
        packed_q_node_del(pNode);
    }
}


static inline void packed_q_pop(cepPackedQ* pkdq, cepCell* target) {
    cepCell* first = pkdq->pHead->first;
    cep_cell_transfer(first, target);
    pkdq->pHead->first++;
    if (pkdq->pHead->first <= pkdq->pHead->last) {
        CEP_0(first);
    } else {
        cepPackedQNode* pNode = pkdq->pHead;
        pkdq->pHead = pkdq->pHead->pNext;
        if (pkdq->pHead)
            pkdq->pHead->pPrev = NULL;
        else
            pkdq->pTail = NULL;
        packed_q_node_del(pNode);       //ToDo: keep last node for re-use.
    }
}


static inline void packed_q_remove_cell(cepPackedQ* pkdq, cepCell* cell) {
    cepCell dummy;
    if (cell == pkdq->pHead->first) {
        packed_q_pop(pkdq, &dummy);
    } else if (cell == pkdq->pTail->last) {
        packed_q_take(pkdq, &dummy);
    } else {
        // Only removing first/last is allowed for this.
        assert(cell == pkdq->pHead->first || cell == pkdq->pTail->last);
    }
}


static inline void packed_q_del_all_children(cepPackedQ* pkdq) {
    cepPackedQNode* pNode = pkdq->pHead, *toDel;
    if (pNode) {
        do {
            for (cepCell* cell = pNode->first;  cell <= pNode->last;  cell++) {
                cep_cell_finalize(cell);
            }
            toDel = pNode;
            pNode = pNode->pNext;
            packed_q_node_del(toDel);
        } while (pNode);
        pkdq->pHead = pkdq->pTail = NULL;
    }
}

