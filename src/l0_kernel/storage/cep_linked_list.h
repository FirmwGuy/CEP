/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


typedef struct _cepListNode     cepListNode;

struct _cepListNode {
    cepListNode*  next;         // Next node.
    cepListNode*  prev;         // Previous node.
    //
    cepCell       cell;         // Child cell.
};

typedef struct {
    cepStore      store;        // Parent info.
    //
    cepListNode*  head;         // Head of the doubly linked list
    cepListNode*  tail;         // Tail of the doubly linked list for quick append
} cepList;




/*
    Double linked list implementation
*/

#define list_new()      cep_new(cepList)
#define list_del        cep_free


static inline cepListNode* list_node_new(cepCell* cell) {
    CEP_NEW(cepListNode, node);
    cep_cell_transfer(cell, &node->cell);
    return node;
}

#define list_node_del   cep_free


static inline cepListNode* list_node_from_cell(const cepCell* cell) {
    return cep_ptr_dif(cell, offsetof(cepListNode, cell));
}




static inline void list_prepend_node(cepList* list, cepListNode* node) {
    node->next = list->head;
    if (list->head)
        list->head->prev = node;
    else
        list->tail = node;
    list->head = node;
}

static inline void list_append_node(cepList* list, cepListNode* node) {
    node->prev = list->tail;
    if (list->tail)
        list->tail->next = node;
    else
        list->head = node;
    list->tail = node;
}

static inline void list_insert_node_before_next(cepList* list, cepListNode* node, cepListNode* next) {
    if (next->prev) {
        next->prev->next = node;
        node->prev = next->prev;
    } else {
        list->head = node;
    }
    next->prev = node;
    node->next = next;
}




static inline cepCell* list_insert(cepList* list, cepCell* cell, size_t position) {
    cepListNode* node = list_node_new(cell);
    size_t n = 0;
    cepListNode* next;
    for (next = list->head;  next;  next = next->next, n++) {
        if (n == position) {
            list_insert_node_before_next(list, node, next);
            break;
        }
    }
    if (!next)
        list_append_node(list, node);

    return &node->cell;
}


static inline cepCell* list_named_insert(cepList* list, cepCell* cell) {
    cepListNode* node = list_node_new(cell);
    cepListNode* next;
    for (next = list->head;  next;  next = next->next) {
        int cmp = cell_compare_by_name(&node->cell, &next->cell, NULL);
        if (0 > cmp) {
            list_insert_node_before_next(list, node, next);
            break;
        }
        assert(0 != cmp);   // Duplicates are not allowed.
    }
    if (!next)
        list_append_node(list, node);

    return &node->cell;
}


static inline cepCell* list_sorted_insert(cepList* list, cepCell* cell, cepCompare compare, void* context) {
    cepListNode* node = list_node_new(cell);
    cepListNode* next;
    for (next = list->head;  next;  next = next->next) {
        int cmp = compare(&node->cell, &next->cell, context);
        if (0 > cmp) {
            list_insert_node_before_next(list, node, next);
            break;
        }
        assert(0 != cmp);   // Duplicates are not allowed.
    }
    if (!next)
        list_append_node(list, node);

    return &node->cell;
}


static inline cepCell* list_append(cepList* list, cepCell* cell, bool prepend) {
    cepListNode* node = list_node_new(cell);

    if (list->store.chdCount) {
        if (prepend)
            list_prepend_node(list, node);
        else
            list_append_node(list, node);
    } else {
        list->head = list->tail = node;
    }

    return &node->cell;
}




static inline cepCell* list_first(cepList* list) {
   return &list->head->cell;
}


static inline cepCell* list_last(cepList* list) {
   return &list->tail->cell;
}


static inline cepCell* list_find_by_name(cepList* list, const cepDT* name) {
    for (cepListNode* node = list->head;  node;  node = node->next) {
        if (cep_cell_name_is(&node->cell, name))
            return &node->cell;
    }
    return NULL;
}



static inline cepCell* list_find_by_key(cepList* list, cepCell* key, cepCompare compare, void* context) {
    for (cepListNode* node = list->head;  node;  node = node->next) {
        if (0 == compare(key, &node->cell, context))
            return &node->cell;
    }
    return NULL;
}


static inline cepCell* list_find_by_position(cepList* list, size_t position) {
    // ToDo: use from tail to head if index is closer to it.
    size_t n = 0;
    for (cepListNode* node = list->head;  node;  node = node->next, n++) {
        if (n == position)
            return &node->cell;
    }
    return NULL;
}


static inline cepCell* list_prev(const cepCell* cell) {
    cepListNode* node = list_node_from_cell(cell);
    return node->prev? &node->prev->cell: NULL;
}


static inline cepCell* list_next(const cepCell* cell) {
    cepListNode* node = list_node_from_cell(cell);
    return node->next? &node->next->cell: NULL;
}


static inline cepCell* list_next_by_name(cepList* list, cepDT* name, cepListNode** prev) {
    cepListNode* node = *prev?  (*prev)->next:  list->head;
    while (node) {
        if (cep_cell_name_is(&node->cell, name)) {
            *prev = node;
            return &node->cell;
        }
        node = node->next;
    }
    *prev = NULL;
    return NULL;
}


static inline bool list_traverse(cepList* list, cepTraverse func, void* context, cepEntry* entry) {
    entry->parent = list->store.owner;
    entry->depth  = 0;
    cepListNode* node = list->head, *next;
    do {
        next = node->next;
        entry->cell = &node->cell;
        entry->next = next? &next->cell: NULL;
        if (!func(entry, context))
            return false;
        entry->position++;
        entry->prev = entry->cell;
        node = next;
    } while (node);
    return true;
}


static inline void list_sort(cepList* list, cepCompare compare, void* context) {
    cepListNode* prev = list->head, *next;
    cepListNode* node = prev->next, *smal;
    while (node) {
        if (0 > compare(&node->cell, &prev->cell, context)) {
            // Unlink node.
            next = node->next;
            prev->next = next;
            if (next) next->prev = prev;

            // Look backwards for a smaller id.
            for (smal = prev->prev;  smal;  smal = smal->prev) {
                if (0 <= compare(&node->cell, &smal->cell, context))
                    break;
            }
            if (smal) {
                // Insert node after smaller.
                node->prev = smal;
                node->next = smal->next;
                smal->next->prev = node;
                smal->next = node;
            } else {
                // Make node the new list head.
                node->prev = NULL;
                node->next = list->head;
                list->head->prev = node;
                list->head = node;
            }
            node = prev->next;
        } else {
            prev = node;
            node = node->next;
        }
    }
}


static inline void list_take(cepList* list, cepCell* target) {
    assert(list && list->tail);
    cepListNode* node = list->tail;
    cepListNode* prev = node->prev;

    // Unlink node.
    list->tail = prev;
    if (prev)
        prev->next = NULL;
    else
        list->head = NULL;

    cep_cell_transfer(&node->cell, target);
    list_node_del(node);
}


static inline void list_pop(cepList* list, cepCell* target) {
    assert(list && list->head);
    cepListNode* node = list->head;
    cepListNode* next = node->next;

    // Unlink node.
    list->head = next;
    if (next)
        next->prev = NULL;
    else
        list->tail = NULL;

    cep_cell_transfer(&node->cell, target);
    list_node_del(node);
}


static inline void list_remove_cell(cepList* list, cepCell* cell) {
    assert(list && list->head);
    cepListNode* node = list_node_from_cell(cell);
    cepListNode* next = node->next;
    cepListNode* prev = node->prev;

    // Unlink node.
    if (next) next->prev = prev;
    else      list->tail = prev;
    if (prev) prev->next = next;
    else      list->head = next;

    list_node_del(node);
}


static inline void list_del_all_children(cepList* list) {
    cepListNode* node = list->head, *toDel;
    if (node) {
        do {
            cep_cell_finalize_hard(&node->cell);
            toDel = node;
            node = node->next;
            list_node_del(toDel);
        } while (node);
        list->head = list->tail = NULL;
    }
}
