/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include <stdbool.h>

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
    unsigned        count;          // Number of cells stored directly in this node.
};

enum {
    CEP_OCTREE_MAX_DEPTH_DEFAULT     = 8,
    CEP_OCTREE_MAX_PER_NODE_DEFAULT  = 16,
};

#define CEP_OCTREE_MIN_SUBWIDE_DEFAULT   (1e-5f)

typedef struct {
    cepStore        store;          // Storage info.
    //
    cepOctreeNode   root;           // The root node.
    unsigned        depth;          // Maximum tree depth (ever used).
    unsigned        maxDepth;       // Policy: deepest subdivision allowed.
    unsigned        maxPerNode;     // Policy: split nodes after this many cells.
    float           minSubwide;     // Policy: stop subdividing when subwide below this.
} cepOctree;


#define EPSILON     (1e-10)




/*
    Octree implementation
    ---------------------

    CEP's octree acts as a spatial directory for child cells. Callers provide a
    comparator that receives the candidate cell, an optional user context, and
    the bounding box of a quadrant; it must return >0 when the cell fits fully
    inside that bound. Inserting a cell walks the tree, creating child nodes
    where the comparator reports a fit. If no child accepts the cell (because it
    straddles multiple quadrants or the box reached the minimum size), the cell
    stays in the current node's bucket list.

    Policy knobs:
      * `maxDepth`    – cap recursive subdivision; defaults to 8 levels.
      * `maxPerNode`  – maximum cells stored in a node before attempting to
                         subdivide; defaults to 16.
      * `minSubwide`  – lower bound on half-width for new quadrants to avoid
                         degenerate floating-point subdivisions; defaults to 1e-5f.

    Call `octree_set_policy` after construction to override the defaults. The
    restructuring logic is adaptive: once a node exceeds `maxPerNode` and the
    depth/minSubwide constraints allow it, the node redistributes its residents
    into freshly created children. Removal prunes empty branches so the tree does
    not balloon during GC.

    Iteration helpers (`octree_first`, `octree_next`, etc.) give deterministic
    orderings by walking the tree front-to-back. These functions expect the
    caller to maintain a separate traversal state (`cepEntry`) when interacting
    with the generic store APIs.
*/

static inline cepOctreeNode* octree_node_new(cepOctreeNode* parent, cepOctreeBound* bound, unsigned index) {
    assert(bound && bound->subwide > EPSILON);
    CEP_NEW(cepOctreeNode, onode);
    onode->parent = parent;
    onode->bound  = *bound;
    onode->index  = index;
    onode->count  = 0;
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
    onode->list = NULL;
    onode->count = 0;
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
    octree->maxDepth = CEP_OCTREE_MAX_DEPTH_DEFAULT;
    octree->maxPerNode = CEP_OCTREE_MAX_PER_NODE_DEFAULT;
    octree->minSubwide = CEP_OCTREE_MIN_SUBWIDE_DEFAULT;
    return octree;
}

static inline void octree_set_policy(cepOctree* octree, unsigned maxDepth, unsigned maxPerNode, float minSubwide) {
    assert(octree);
    if (maxDepth)
        octree->maxDepth = maxDepth;
    if (maxPerNode)
        octree->maxPerNode = maxPerNode;
    if (minSubwide > 0.0f)
        octree->minSubwide = minSubwide;
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


static inline int octree_choose_child(cepOctreeNode* onode, unsigned index, const cepOctreeBound* bound, cepOctreeList* entry, cepCompare compare, void* context) {
    (void)onode;
    (void)index;
    // Comparator contract: positive value means the cell fits inside the bound.
    return compare(&entry->cell, (const cepCell*)(const void*)bound, context);
}

static inline cepOctreeNode* octree_ensure_child(cepOctreeNode* onode, unsigned index, const cepOctreeBound* bound) {
    if (!onode->children[index])
        onode->children[index] = octree_node_new(onode, (cepOctreeBound*)bound, index);
    return onode->children[index];
}

static inline cepCell* octree_descend_entry(cepOctree* octree,
                                            cepOctreeNode* onode,
                                            unsigned depth,
                                            cepOctreeList* entry,
                                            cepCompare compare,
                                            void* context,
                                            bool allowSplit);

static inline void octree_try_split(cepOctree* octree,
                                    cepOctreeNode* onode,
                                    unsigned depth,
                                    cepCompare compare,
                                    void* context) {
    if (onode->count <= octree->maxPerNode)
        return;
    if (depth >= octree->maxDepth)
        return;

    float nextSubwide = onode->bound.subwide * 0.5f;
    if (nextSubwide <= octree->minSubwide)
        return;

    cepOctreeList* list = onode->list;
    onode->list = NULL;
    onode->count = 0;

    bool moved = false;
    while (list) {
        cepOctreeList* next = list->next;
        list->next = list->prev = NULL;
        cepOctreeNode* original = list->onode;
        cepCell* placed = octree_descend_entry(octree, onode, depth, list, compare, context, false);
        (void)placed;
        if (list->onode != original)
            moved = true;
        list = next;
    }

    if (!moved) {
        // Rebuild original ordering if nothing could be moved out; ensure count is recomputed.
        cepOctreeList* iter = onode->list;
        onode->count = 0;
        while (iter) {
            onode->count++;
            iter = iter->next;
        }
        return;
    }

    for (unsigned idx = 0; idx < 8; ++idx) {
        if (onode->children[idx])
            octree_try_split(octree, onode->children[idx], depth + 1, compare, context);
    }
}

static inline cepCell* octree_descend_entry(cepOctree* octree,
                                            cepOctreeNode* onode,
                                            unsigned depth,
                                            cepOctreeList* entry,
                                            cepCompare compare,
                                            void* context,
                                            bool allowSplit) {
    // Attempt to descend into a fitting child.
    for (unsigned idx = 0; idx < 8; ++idx) {
        const cepOctreeNode* child = onode->children[idx];
        cepOctreeBound bound;

        if (child) {
            if (octree_choose_child(onode, idx, &child->bound, entry, compare, context) > 0) {
                cepCell* result = octree_descend_entry(octree, onode->children[idx], depth + 1, entry, compare, context, allowSplit);
                if (octree->depth < depth + 1)
                    octree->depth = depth + 1;
                if (allowSplit)
                    octree_try_split(octree, onode->children[idx], depth + 1, compare, context);
                return result;
            }
            continue;
        }

        bound.subwide = onode->bound.subwide * 0.5f;
        if (bound.subwide <= octree->minSubwide)
            continue;

        switch (idx) {
          case 0: BOUND_CENTER_QUADRANT(bound, onode, +, +, +); break;
          case 1: BOUND_CENTER_QUADRANT(bound, onode, +, -, +); break;
          case 2: BOUND_CENTER_QUADRANT(bound, onode, -, -, +); break;
          case 3: BOUND_CENTER_QUADRANT(bound, onode, -, +, +); break;
          case 4: BOUND_CENTER_QUADRANT(bound, onode, +, +, -); break;
          case 5: BOUND_CENTER_QUADRANT(bound, onode, +, -, -); break;
          case 6: BOUND_CENTER_QUADRANT(bound, onode, -, -, -); break;
          case 7: BOUND_CENTER_QUADRANT(bound, onode, -, +, -); break;
        }

        if (octree_choose_child(onode, idx, &bound, entry, compare, context) > 0) {
            cepOctreeNode* childNode = octree_ensure_child(onode, idx, &bound);
            cepCell* result = octree_descend_entry(octree, childNode, depth + 1, entry, compare, context, allowSplit);
            if (octree->depth < depth + 1)
                octree->depth = depth + 1;
            if (allowSplit)
                octree_try_split(octree, childNode, depth + 1, compare, context);
            return result;
        }
    }

    // Place entry in current node.
    entry->onode = onode;
    entry->prev = NULL;
    entry->next = onode->list;
    if (entry->next)
        entry->next->prev = entry;
    onode->list = entry;
    onode->count++;

    if (allowSplit)
        octree_try_split(octree, onode, depth, compare, context);
    return &entry->cell;
}

static inline cepCell* octree_sorted_insert(cepOctree* octree, cepCell* cell, cepCompare compare, void* context) {
    CEP_NEW(cepOctreeList, list);
    cep_cell_transfer(cell, &list->cell);
    list->next = list->prev = NULL;
    return octree_descend_entry(octree, &octree->root, 1u, list, compare, context, true);
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
    (void)context;

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
    if (onode->count)
        onode->count--;

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
            cep_cell_finalize_hard(&list->cell);
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
