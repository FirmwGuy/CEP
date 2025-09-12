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


typedef struct _cepOctreeList   cepOctreeList;
typedef struct _cepOctreeNode   cepOctreeNode;

struct _cepOctreeList {
    cepOctreeList*  next;           // Next child in current sector.
    cepOctreeList*  prev;           // Previous child in current sector.
    cepOctreeNode*  onode;          // Node owning this list.
    //cepOctreeList*  self;           // Next self in other sectors.
    //
    cepCell         cell;           // Child cell.
};

typedef struct {
    float           subwide;        // Half the width/height/depth of the bounding space.
    float           center[3];      // Center of the bounding space (XYZ coords).
} cepOctreeBound;

struct _cepOctreeNode {
    cepOctreeNode*  children[8];    // Pointers to child nodes.
    cepOctreeNode*  parent;         // Parent node.
    cepOctreeList*  list;           // List of cells in this node.
    cepOctreeBound  bound;          // Bounding space covered by this node.
    unsigned        index;          // Child index of this node in parent.
};

typedef struct {
    cepStore        store;          // Storage info.
    //
    cepOctreeNode   root;           // The root node.
    unsigned        depth;          // Maximum tree depth (ever used).
} cepOctree;


#define EPSILON     (1e-10)




/*
    Octree implementation
*/

static inline cepOctreeNode* octree_node_new(cepOctreeNode* parent, cepOctreeBound* bound, unsigned index) {
    assert(bound && bound->subwide > EPSILON);
    CEP_NEW(cepOctreeNode, onode);
    onode->parent = parent;
    onode->bound  = *bound;
    onode->index  = index;
    return onode;
}


static inline void octree_node_del(cepOctreeNode* onode);

static inline void octree_node_clean(cepOctreeNode* onode) {
    for (unsigned n = 0;  n < 8;  n++) {
        if (onode->children[n])
            octree_node_del(onode->children[n]);
    }

    cepOctreeList* list = onode->list;
    while (list) {
        cepOctreeList* next = list->next;
        cep_free(list);
        list = next;
    }
}


static inline void octree_node_del(cepOctreeNode* onode) {
    octree_node_clean(onode);
    cep_free(onode);
}


static inline cepOctree* octree_new(cepOctreeBound* bound) {
    assert(bound && bound->subwide > EPSILON);
    CEP_NEW(cepOctree, octree);
    octree->root.bound = *bound;
    octree->depth = 1;
    return octree;
}


static inline void octree_del(cepOctree* octree){
    if (!octree) return;
    octree_node_clean(&octree->root);
    cep_free(octree);
}



static inline cepOctreeList* octree_list_from_cell(cepCell* cell) {
    return cep_ptr_dif(cell, offsetof(cepOctreeList, cell));
}


#define BOUND_CENTER_QUADRANT(bound, onode, opX, opY, opZ)              \
    do {                                                                \
        bound.center[0] = onode->bound.center[0] opX bound.subwide;     \
        bound.center[1] = onode->bound.center[1] opY bound.subwide;     \
        bound.center[2] = onode->bound.center[2] opZ bound.subwide;     \
    } while(0)


static inline cepCell* octree_sorted_insert(cepOctree* octree, cepCell* cell, cepCompare compare, void* context) {
    CEP_NEW(cepOctreeList, list);
    cep_cell_transfer(cell, &list->cell);

    cepOctreeNode* onode = &octree->root;
    unsigned depth = 1;
    unsigned n;
    do {
        for (n = 0;  n < 8;  n++) {
            if (onode->children[n]) {
                if (0 < compare(&list->cell, context, &onode->children[n]->bound)) {
                    onode = onode->children[n];
                    depth++;
                    break;
                }
            } else {
                cepOctreeBound bound;
                bound.subwide = onode->bound.subwide / 2.0f;
                assert(bound.subwide > EPSILON);

                switch (n) {
                  case 0:   BOUND_CENTER_QUADRANT(bound, onode, +, +, +);   break;
                  case 1:   BOUND_CENTER_QUADRANT(bound, onode, +, -, +);   break;
                  case 2:   BOUND_CENTER_QUADRANT(bound, onode, -, -, +);   break;
                  case 3:   BOUND_CENTER_QUADRANT(bound, onode, -, +, +);   break;
                  case 4:   BOUND_CENTER_QUADRANT(bound, onode, +, +, -);   break;
                  case 5:   BOUND_CENTER_QUADRANT(bound, onode, +, -, -);   break;
                  case 6:   BOUND_CENTER_QUADRANT(bound, onode, -, -, -);   break;
                  case 7:   BOUND_CENTER_QUADRANT(bound, onode, -, +, -);   break;
                }

                if (0 < compare(&list->cell, context, &bound)) {
                    onode->children[n] = octree_node_new(onode, &bound, n);
                    onode = onode->children[n];
                    depth++;
                    break;
                }
            }
        }
    } while (n < 8);

    // Insert list item
    list->onode = onode;
    list->next  = onode->list;
    if (list->next)
        list->next->prev = list;
    onode->list = list;

    if (octree->depth < depth)
        octree->depth = depth;

    return &list->cell;
}


static inline cepCell* octree_first(cepOctree* octree) {
    cepOctreeNode* onode = &octree->root;
    for (;;) {
        if (onode->list)
            return &onode->list->cell;

        // Check children for a node with cells
        bool hasChildren = false;
        for (unsigned n = 0;  n < 8;  n++) {
            if (onode->children[n]) {
                onode = onode->children[n];
                hasChildren = true;
                break;
            }
        }
        if (!hasChildren)
            break;
    }

    return NULL;
}


static inline cepCell* octree_last(cepOctree* octree) {
    cepOctreeNode* onode = &octree->root;
    cepOctreeList* last  = NULL;
    for (;;) {
        // Find the last node in the current node's list
        if (onode->list) {
            for (last = onode->list;  last->next;  last = last->next);
        }

        // Check children for deeper nodes
        bool hasChildren = false;
        for (int i = 7;  i >= 0;  i--) {    // Start from the last child.
            if (onode->children[i]) {
                onode = onode->children[i];
                hasChildren = true;
                break;
            }
        }
        if (!hasChildren) {
            break;
        }
    }

    return last? &last->cell: NULL;
}


static inline bool octree_traverse(cepOctree* octree, cepTraverse func, void* context, cepEntry* entry) {
    assert(octree && func);

    cepOctreeNode* onode = &octree->root;

    entry->parent = octree->store.owner;
    entry->depth  = 0;
    do {
        // Process all cells in the current node
        for (cepOctreeList* list = onode->list;  list;  list = list->next) {
            if (entry->next) {
                entry->prev   = entry->cell;
                entry->cell = entry->next;
                entry->next   = &list->cell;
                if (!func(entry, context))
                    return true;
            } else {
                entry->next = &list->cell;
            }
            entry->position++;
        }

        // Move to the first child node if available
        bool hasChild = false;
        for (unsigned n = 0;  n < 8;  n++) {
            if (onode->children[n]) {
                onode = onode->children[n];
                hasChild = true;
                break;
            }
        }
        if (!hasChild) {
            // Backtrack to the next sibling or parent
            while (onode && onode->parent) {
                unsigned n = onode->index + 1;
                while (n < 8  &&  !onode->parent->children[n]) {
                    n++;
                }
                if (n < 8) {
                    onode = onode->parent->children[n];
                    break;
                }

                onode = onode->parent;
            }
        }
    } while (onode);

    entry->prev   = entry->cell;
    entry->cell = entry->next;
    entry->next   = NULL;
    return func(entry, context);
}


static inline cepCell* octree_find_by_name(cepOctree* octree, const cepDT* name) {
    cepEntry entry = {0};
    if (!octree_traverse(octree, (cepFunc) rb_traverse_func_break_at_name, cep_v2p(name), &entry))
        return entry.cell;
    return NULL;
}


static inline cepCell* octree_find_by_key(cepOctree* octree, cepCell* key, cepCompare compare, void* context) {
    cepEntry entry = {0};
    if (!octree_traverse(octree, (cepFunc) compare, key, &entry))
        return entry.cell;
    return NULL;
}


static inline cepCell* octree_find_by_position(cepOctree* octree, size_t position) {
    cepEntry entry = {0};
    if (!octree_traverse(octree, (void*) rb_traverse_func_break_at_position, cep_v2p(position), &entry))
        return entry.cell;
    return NULL;
}


static inline cepCell* octree_prev(cepCell* cell) {
    cepOctreeList* list = octree_list_from_cell(cell);
    if (list->prev)
        return &list->prev->cell;

    // Find the previous sibling node or parent with cells
    cepOctreeNode* onode = list->onode;
    while (onode) {
        unsigned index = onode->index;
        onode = onode->parent;
        if (!onode)
            break; // Root node reached.

        for (int i = (int)index - 1;  i >= 0;  i--) {
            if (onode->children[i]) {
                cepOctreeNode* sibling = onode->children[i];
                while (sibling) {
                    // Find the last cell in this subtree
                    if (sibling->list) {
                        cepOctreeList* last = sibling->list;
                        while (last->next) {
                            last = last->next;
                        }
                        return &last->cell;
                    }

                    // Descend into the last child node
                    bool hasChildren = false;
                    for (int j = 7;  j >= 0;  j--) {
                        if (sibling->children[j]) {
                            sibling = sibling->children[j];
                            hasChildren = true;
                            break;
                        }
                    }
                    if (!hasChildren)
                        break;
                }
            }
        }
    }

    return NULL;
}


static inline cepCell* octree_next(cepCell* cell) {
    cepOctreeList* list = octree_list_from_cell(cell);
    if (list->next)
        return &list->next->cell;

    // Find the next sibling node or parent with cells
    cepOctreeNode* onode = list->onode;
    while (onode) {
        for (unsigned n = onode->index + 1;  n < 8;  n++) {
            if (onode->parent->children[n]) {
                cepOctreeNode* next = onode->parent->children[n];
                while (next) {
                    if (next->list)
                        return &next->list->cell;

                    bool hasChildren = false;
                    for (unsigned m = 0;  m < 8;  m++) {
                        if (next->children[m]) {
                            next = next->children[m];
                            hasChildren = true;
                            break;
                        }
                    }
                    if (!hasChildren)
                        break;
                }
            }
        }

        onode = onode->parent;
    }

    return NULL;
}


static inline void octree_remove_cell(cepOctree* octree, cepCell* cell) {
    cepOctreeList* list  = octree_list_from_cell(cell);
    cepOctreeNode* onode = list->onode;

    // Remove list item
    if (list->prev) {
        list->prev->next = list->next;
    } else {
        list->onode->list = list->next;
    }
    if (list->next) {
        list->next->prev = list->prev;
    }

    cep_free(list);

    // Remove empty nodes
    for(;;) {
        if (onode->list)
            break;

        bool hasChildren = false;
        for (unsigned n = 0;  n < 8;  n++) {
            if (onode->children[n]) {
                hasChildren = true;
                break;
            }
        }
        if (hasChildren)
            break;

        // If the node is empty, remove it
        cepOctreeNode* parent = onode->parent;
        if (parent) {
            parent->children[onode->index] = NULL;
            cep_free(onode);
            onode = parent;
        } else {
            octree->depth = 1;
            break;
        }
    }
}


static inline void octree_take(cepOctree* octree, cepCell* target) {
    cepCell* last = octree_last(octree);
    cep_cell_transfer(last, target);
    octree_remove_cell(octree, last);
}


static inline void octree_pop(cepOctree* octree, cepCell* target) {
    cepCell* first = octree_first(octree);
    cep_cell_transfer(first, target);
    octree_remove_cell(octree, first);
}


#define OCTREE_MIN_DEPTH    128

static inline void octree_del_all_children(cepOctree* octree) {
    size_t      stackSize = octree->depth * sizeof(void*);
    cepOctreeNode** stack = (octree->depth > OCTREE_MIN_DEPTH)? cep_malloc(stackSize): cep_alloca(stackSize);
    unsigned          top = 0;

    // Push all root's children onto the stack
    for (unsigned n = 0;  n < 8;  n++) {
        if (octree->root.children[n]) {
            stack[top++] = octree->root.children[n];
            octree->root.children[n] = NULL;
        }
    }

    // Delete all child nodes
    while (top > 0) {
        cepOctreeNode* onode = stack[--top];

        // Free all cells in this node
        cepOctreeList* list = onode->list;
        while (list) {
            cepOctreeList* next = list->next;
            cep_cell_finalize(&list->cell);
            cep_free(list);
            list = next;
        }

        // Push all children of the current node onto the stack
        for (unsigned n = 0;  n < 8;  n++) {
            if (onode->children[n]) {
                stack[top++] = onode->children[n];
                onode->children[n] = NULL;
            }
        }

        cep_free(onode);
    }

    if (octree->depth > OCTREE_MIN_DEPTH)
        cep_free(stack);

    octree->depth = 1;
}

