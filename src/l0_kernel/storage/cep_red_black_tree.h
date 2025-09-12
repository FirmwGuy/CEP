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


typedef struct _cepRbTreeNode   cepRbTreeNode;

struct _cepRbTreeNode {
    cepRbTreeNode*  left;         // Left node.
    cepRbTreeNode*  right;        // Right node.
    cepRbTreeNode*  tParent;      // Parent node.
    bool            isRed;        // True if node is red.
    //
    cepCell         cell;         // Child cell.
};

typedef struct {
    cepStore        store;        // Parent info.
    //
    cepRbTreeNode*  root;         // The root node.
    //cepRbTreeNode*  maximum;      // Node holding the maximum data.
    //cepRbTreeNode*  minimum;      // Node holding the minimum data.
} cepRbTree;




/*
    Red-black tree implementation
*/

#define rb_tree_new()     cep_new(cepRbTree)
#define rb_tree_del       cep_free


static inline cepRbTreeNode* rb_tree_node_new(cepCell* cell) {
    CEP_NEW(cepRbTreeNode, tnode);
    tnode->isRed = true;
    cep_cell_transfer(cell, &tnode->cell);
    return tnode;
}


static inline cepRbTreeNode* rb_tree_node_from_cell(cepCell* cell) {
    return cep_ptr_dif(cell, offsetof(cepRbTreeNode, cell));
}


static inline void rb_tree_rotate_left(cepRbTree* tree, cepRbTreeNode* x) {
    cepRbTreeNode* y = x->right;
    x->right = y->left;
    if (y->left)
        y->left->tParent = x;
    y->tParent = x->tParent;
    if (!x->tParent) {
        tree->root = y;
    } else if (x == x->tParent->left) {
        x->tParent->left = y;
    } else {
        x->tParent->right = y;
    }
    y->left = x;
    x->tParent = y;
}

static inline void rb_tree_rotate_right(cepRbTree* tree, cepRbTreeNode* x) {
    cepRbTreeNode* y = x->left;
    x->left = y->right;
    if (y->right)
        y->right->tParent = x;
    y->tParent = x->tParent;
    if (!x->tParent) {
        tree->root = y;
    } else if (x == x->tParent->right) {
        x->tParent->right = y;
    } else {
        x->tParent->left = y;
    }
    y->right = x;
    x->tParent = y;
}

static inline void rb_tree_fix_insert(cepRbTree* tree, cepRbTreeNode* z) {
    while (z != tree->root && z->tParent->isRed) {
        if (z->tParent == z->tParent->tParent->left) {
            cepRbTreeNode* y = z->tParent->tParent->right;
            if (y && y->isRed) {
                z->tParent->isRed = false;
                y->isRed = false;
                z->tParent->tParent->isRed = true;
                z = z->tParent->tParent;
            } else {
                if (z == z->tParent->right) {
                    z = z->tParent;
                    rb_tree_rotate_left(tree, z);
                }
                z->tParent->isRed = false;
                z->tParent->tParent->isRed = true;
                rb_tree_rotate_right(tree, z->tParent->tParent);
            }
        } else {
            cepRbTreeNode* y = z->tParent->tParent->left;
            if (y && y->isRed) {
                z->tParent->isRed = false;
                y->isRed = false;
                z->tParent->tParent->isRed = true;
                z = z->tParent->tParent;
            } else {
                if (z == z->tParent->left) {
                    z = z->tParent;
                    rb_tree_rotate_right(tree, z);
                }
                z->tParent->isRed = false;
                z->tParent->tParent->isRed = true;
                rb_tree_rotate_left(tree, z->tParent->tParent);
            }
        }
    }
    tree->root->isRed = false;
}


static inline void rb_tree_sorted_insert_tnode(cepRbTree* tree, cepRbTreeNode* tnode, cepCompare compare, void* context) {
    if (tree->root) {
        cepRbTreeNode* x = tree->root, *y;
        do {
            y = x;
            int cmp = compare(&tnode->cell, &x->cell, context);
            if (0 > cmp) {
                x = x->left;
            } else if (0 < cmp) {
                x = x->right;
            } else {
                // FixMe: delete children.
                assert(0 == cmp);
            }
        } while (x);
        tnode->tParent = y;
        if (0 > compare(&tnode->cell, &y->cell, context)) {
            y->left = tnode;
        } else {
            y->right = tnode;
        }
    } else {
        tree->root = tnode;
    }
    rb_tree_fix_insert(tree, tnode);
}


static inline cepCell* rb_tree_named_insert(cepRbTree* tree, cepCell* cell) {
    cepRbTreeNode* tnode = rb_tree_node_new(cell);
    rb_tree_sorted_insert_tnode(tree, tnode, cell_compare_by_name, NULL);
    return &tnode->cell;
}


static inline cepCell* rb_tree_sorted_insert(cepRbTree* tree, cepCell* cell, cepCompare compare, void* context) {
    cepRbTreeNode* tnode = rb_tree_node_new(cell);
    rb_tree_sorted_insert_tnode(tree, tnode, compare, context);
    return &tnode->cell;
}


static inline cepCell* rb_tree_first(cepRbTree* tree) {
    cepRbTreeNode* tnode = tree->root;
    while (tnode->left)   tnode = tnode->left;
    return &tnode->cell;
}


static inline cepCell* rb_tree_last(cepRbTree* tree) {
    cepRbTreeNode* tnode = tree->root;
    while (tnode->right)  tnode = tnode->right;
    return &tnode->cell;
}


#define RB_TREE_MIN_DEPTH   64

static inline bool rb_tree_traverse(cepRbTree* tree, unsigned maxDepth, cepTraverse func, void* context, cepEntry* entry) {
    cepRbTreeNode*  tnode = tree->root, *tnodePrev = NULL;
    size_t      stackSize = maxDepth * sizeof(void*);
    cepRbTreeNode** stack = (maxDepth > RB_TREE_MIN_DEPTH)?  cep_malloc(stackSize):  cep_alloca(stackSize);
    int top = -1;  // Stack index initialized to empty.

    entry->parent = tree->store.owner;
    entry->depth  = 0;
    do {
        if (tnode) {
            assert(top < ((int)maxDepth - 1));
            stack[++top] = tnode;
            tnode = tnode->left;
        } else {
            tnode = stack[top--];
            if (tnodePrev) {
                entry->next   = &tnode->cell;
                entry->cell = &tnodePrev->cell;
                if (!func(entry, context)) {
                    if (maxDepth > RB_TREE_MIN_DEPTH)
                        cep_free(stack);
                    return false;
                }
                entry->position++;
                entry->prev = entry->cell;
            }
            tnodePrev = tnode;
            tnode = tnode->right;
        }
    } while (top != -1 || tnode);

    if (maxDepth > RB_TREE_MIN_DEPTH)
        cep_free(stack);

    entry->next   = NULL;
    entry->cell = &tnodePrev->cell;
    return func(entry, context);
}


static inline int rb_traverse_func_break_at_name(cepEntry* entry, uintptr_t name) {
    return !cep_cell_name_is(entry->cell, name);
}


static inline cepCell* rb_tree_find_by_dt(cepRbTree* tree, const cepDT* dt) {
    cepCell key = {.metacell.domain = dt->domain, .metacell.tag = dt->tag};
    cepRbTreeNode* tnode = tree->root;
    do {
        int cmp = cell_compare_by_name(&key, &tnode->cell, NULL);
        if (0 > cmp) {
            tnode = tnode->left;
        } else if (0 < cmp) {
            tnode = tnode->right;
        } else {
            return &tnode->cell;
        }
    } while (tnode);
    return NULL;
}


static inline cepCell* rb_tree_find_by_name(cepRbTree* tree, const cepDT* name) {
    if (cep_store_is_dictionary(&tree->store)) {
        return rb_tree_find_by_dt(tree, name);
    } else {
        cepEntry entry = {0};
        if (!rb_tree_traverse(tree, cep_bitson(tree->store.chdCount) + 2, (cepFunc) rb_traverse_func_break_at_name, cep_v2p(name), &entry))
            return entry.cell;
    }
    return NULL;
}


static inline cepCell* rb_tree_find_by_key(cepRbTree* tree, cepCell* key, cepCompare compare, void* context) {
    cepRbTreeNode* tnode = tree->root;
    do {
        int cmp = compare(key, &tnode->cell, context);
        if (0 > cmp) {
            tnode = tnode->left;
        } else if (0 < cmp) {
            tnode = tnode->right;
        } else {
            return &tnode->cell;
        }
    } while (tnode);
    return NULL;
}


static inline int rb_traverse_func_break_at_position(cepEntry* entry, uintptr_t position) {
    return (entry->position != position);
}

static inline cepCell* rb_tree_find_by_position(cepRbTree* tree, size_t position) {
    cepEntry entry = {0};
    if (!rb_tree_traverse(tree, cep_bitson(tree->store.chdCount) + 2, (void*) rb_traverse_func_break_at_position, cep_v2p(position), &entry))
        return entry.cell;
    return NULL;
}


static inline cepCell* rb_tree_prev(cepCell* cell) {
    cepRbTreeNode* tnode = rb_tree_node_from_cell(cell);
    if (tnode->left) {
        tnode = tnode->left;
        while (tnode->right) tnode = tnode->right;
        return &tnode->cell;
    }
    cepRbTreeNode* tParent = tnode->tParent;
    while (tParent && tnode == tParent->left) {
        tnode = tParent;
        tParent = tParent->tParent;
    }
    return tParent? &tParent->cell: NULL;
}


static inline cepCell* rb_tree_next(cepCell* cell) {
    cepRbTreeNode* tnode = rb_tree_node_from_cell(cell);
    if (tnode->right) {
        tnode = tnode->right;
        while (tnode->left) tnode = tnode->left;
        return &tnode->cell;
    }
    cepRbTreeNode* tParent = tnode->tParent;
    while (tParent && tnode == tParent->right) {
        tnode = tParent;
        tParent = tParent->tParent;
    }
    return tParent? &tParent->cell: NULL;
}


static inline void rb_tree_transplant(cepRbTree* tree, cepRbTreeNode* u, cepRbTreeNode* v) {
    if (!u->tParent) {
        tree->root = v;
    } else if (u == u->tParent->left) {
        u->tParent->left = v;
    } else {
        u->tParent->right = v;
    }
    if (v)
        v->tParent = u->tParent;
}

static inline void rb_tree_fixremove_node(cepRbTree* tree, cepRbTreeNode* x) {
    while (x != tree->root && !x->isRed) {
        if (x == x->tParent->left) {
            cepRbTreeNode* w = x->tParent->right;
            if (!w) break;
            if (w->isRed) {
                w->isRed = false;
                x->tParent->isRed = true;
                rb_tree_rotate_left(tree, x->tParent);
                w = x->tParent->right;
            }
            if (!w || !w->left || !w->right) break;
            if (!w->left->isRed && !w->right->isRed) {
                w->isRed = true;
                x = x->tParent;
            } else {
                if (!w->right->isRed) {
                    w->left->isRed = false;
                    w->isRed = true;
                    rb_tree_rotate_right(tree, w);
                    w = x->tParent->right;
                }
                w->isRed = x->tParent->isRed;
                x->tParent->isRed = false;
                w->right->isRed = false;
                rb_tree_rotate_left(tree, x->tParent);
                x = tree->root;
            }
        } else {
            cepRbTreeNode* w = x->tParent->left;
            if (!w) break;
            if (w->isRed) {
                w->isRed = false;
                x->tParent->isRed = true;
                rb_tree_rotate_right(tree, x->tParent);
                w = x->tParent->left;
            }
            if (!w || !w->right || !w->left) break;
            if (!w->right->isRed && !w->left->isRed) {
                w->isRed = true;
                x = x->tParent;
            } else {
                if (!w->left->isRed) {
                    w->right->isRed = false;
                    w->isRed = true;
                    rb_tree_rotate_left(tree, w);
                    w = x->tParent->left;
                }
                w->isRed = x->tParent->isRed;
                x->tParent->isRed = false;
                w->left->isRed = false;
                rb_tree_rotate_right(tree, x->tParent);
                x = tree->root;
            }
        }
    }
    x->isRed = false;
}

static inline void rb_tree_remove_cell(cepRbTree* tree, cepCell* cell) {
    cepRbTreeNode* tnode = rb_tree_node_from_cell(cell);
    cepRbTreeNode* y = tnode, *x;
    bool wasRed = tnode->isRed;

    if (!tnode->left) {
        x = tnode->right;
        rb_tree_transplant(tree, tnode, x);
    } else if (!tnode->right) {
        x = tnode->left;
        rb_tree_transplant(tree, tnode, x);
    } else {
        for (y = tnode->right;  y->left;  y = y->left);
        wasRed = y->isRed;
        x = y->right;

        if (y->tParent == tnode) {
            if (x)  x->tParent = y;
        } else {
            rb_tree_transplant(tree, y, x);
            y->right = tnode->right;
            y->right->tParent = y;
        }
        rb_tree_transplant(tree, tnode, y);
        y->left = tnode->left;
        y->left->tParent = y;
        y->isRed = tnode->isRed;
    }
    if (x && !wasRed)
        rb_tree_fixremove_node(tree, x);

    cep_free(tnode);
}


static inline void rb_tree_take(cepRbTree* tree, cepCell* target) {
    cepCell* last = rb_tree_last(tree);
    cep_cell_transfer(last, target);
    rb_tree_remove_cell(tree, last);
}


static inline void rb_tree_pop(cepRbTree* tree, cepCell* target) {
    cepCell* first = rb_tree_first(tree);
    cep_cell_transfer(first, target);
    rb_tree_remove_cell(tree, first);
}


static inline void rb_tree_del_all_children_recursively(cepRbTreeNode* tnode) {
    if (tnode->left)
        rb_tree_del_all_children_recursively(tnode->left);

    cep_cell_finalize(&tnode->cell);

    if (tnode->right)
        rb_tree_del_all_children_recursively(tnode->right);

    cep_free(tnode);
}

static inline void rb_tree_del_all_children(cepRbTree* tree) {
    if (tree->root) {
        rb_tree_del_all_children_recursively(tree->root);
        tree->root = NULL;
    }
}
