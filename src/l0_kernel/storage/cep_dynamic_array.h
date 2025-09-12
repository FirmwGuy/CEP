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


typedef struct {
    cepStore    store;          // Parent info.
    //
    size_t      capacity;       // Total capacity of the array to manage allocations
    //
    cepCell*    cell;           // Children Cell
} cepArray;




/*
    Dynamic array implementation
*/

static inline cepArray* array_new(int capacity) {
    CEP_NEW(cepArray, array);
    array->capacity = capacity;
    array->cell = cep_malloc0(capacity * sizeof(cepCell));
    return array;
}


static inline void array_del(cepArray* array) {
    cep_free(array->cell);
    cep_free(array);
}


static inline cepCell* array_search(cepArray* array, const void* key, cepCompare compare, void* context, size_t* index) {
    size_t imax = (index && *index)? *index - 1: array->store.chdCount - 1;
    size_t imin = 0, i;
    cepCell* cell;
    do {
        i = (imax + imin) >> 1;  // (max + min) / 2
        cell = &array->cell[i];
        int res = compare(key, cell, context);
        if (0 > res) {
            if (!i) break;
            imax = i - 1;
        } else if (0 < res) {
            imin = ++i;
        } else {
            CEP_PTR_SEC_SET(index, i);
            return cell;
        }
    } while (imax >= imin);
    CEP_PTR_SEC_SET(index, i);
    return NULL;
}


static inline void array_update_children_parent_ptr(cepCell* cell, cepCell* last) {
    for (;  cell <= last;  cell++) {
        if (cep_cell_children(cell))
            cep_cell_relink_storage(cell);
    }
}


static inline void array_grow(cepArray* array) {
      assert(array->capacity);
      array->capacity *= 2;
      CEP_REALLOC(array->cell, array->capacity * sizeof(cepCell));
      memset(&array->cell[array->store.chdCount], 0, array->store.chdCount * sizeof(cepCell));
      array_update_children_parent_ptr(array->cell, &array->cell[array->store.chdCount - 1]);
}


static inline cepCell* array_sorted_insert_cell(cepArray* array, const cepCell* cell, cepCompare compare, void* context) {
    size_t index = 0;
    cepCell* prev = array_search(array, cell, compare, context, &index);
    if (prev) {
        // FixMe: delete children.
        assert(prev);
    }
    cepCell* child = &array->cell[index];
    if (index < array->store.chdCount) {
        memmove(child + 1, child, array->store.chdCount * sizeof(cepCell));
        array_update_children_parent_ptr(child + 1, &array->cell[array->store.chdCount]);
        CEP_0(child);
    }
    return child;
}


static inline cepCell* array_insert(cepArray* array, cepCell* cell, size_t position) {
    if (array->capacity == array->store.chdCount)
        array_grow(array);

    cepCell* child;

    if (array->store.chdCount) {
        child = &array->cell[position];
        size_t tomove = array->store.chdCount - position;
        if (tomove) {
            memmove(child + 1, child, tomove * sizeof(cepCell));
            array_update_children_parent_ptr(child + 1,  &array->cell[array->store.chdCount]);
        }
        CEP_0(child);
    } else {
        child = array->cell;
    }

    cep_cell_transfer(cell, child);

    return child;
}


static inline cepCell* array_named_insert(cepArray* array, cepCell* cell) {
    if (array->capacity == array->store.chdCount)
        array_grow(array);

    cepCell* child;

    if (array->store.chdCount) {
        child = array_sorted_insert_cell(array, cell, cell_compare_by_name, NULL);
    } else {
        child = array->cell;
    }

    cep_cell_transfer(cell, child);

    return child;
}


static inline cepCell* array_sorted_insert(cepArray* array, cepCell* cell, cepCompare compare, void* context) {
    if (array->capacity == array->store.chdCount)
        array_grow(array);

    cepCell* child;

    if (array->store.chdCount)
        child = array_sorted_insert_cell(array, cell, compare, context);
    else
        child = array->cell;

    cep_cell_transfer(cell, child);

    return child;
}


static inline cepCell* array_append(cepArray* array, cepCell* cell, bool prepend) {
    if (array->capacity == array->store.chdCount)
        array_grow(array);

    cepCell* child;

    if (array->store.chdCount) {
        if (prepend) {
            child = array->cell;
            memmove(child + 1, child, array->store.chdCount * sizeof(cepCell));
            array_update_children_parent_ptr(child + 1, &array->cell[array->store.chdCount]);
            CEP_0(child);
        } else {
            child = &array->cell[array->store.chdCount];
        }
    } else {
        child = array->cell;
    }

    cep_cell_transfer(cell, child);

    return child;
}


static inline cepCell* array_first(cepArray* array) {
    return array->cell;
}


static inline cepCell* array_last(cepArray* array) {
    return &array->cell[array->store.chdCount - 1];
}


static inline cepCell* array_find_by_name(cepArray* array, const cepDT* name) {
    if (cep_store_is_dictionary(&array->store)) {
        cepCell key = {.metacell.domain = name->domain, .metacell.tag = name->tag};
        return array_search(array, &key, cell_compare_by_name, NULL, NULL);
    } else {
        cepCell* cell = array->cell;
        for (size_t i = 0; i < array->store.chdCount; i++, cell++) {
            if (cep_cell_name_is(cell, name))
                return cell;
        }
    }
    return NULL;
}


static inline cepCell* array_find_by_key(cepArray* array, cepCell* key, cepCompare compare, void* context) {
    return array_search(array, key, compare, context, NULL);
}


static inline cepCell* array_find_by_position(cepArray* array, size_t position) {
    return &array->cell[position];
}


static inline cepCell* array_prev(cepArray* array, cepCell* cell) {
    return (cell > array->cell)? cell - 1: NULL;
}


static inline cepCell* array_next(cepArray* array, cepCell* cell) {
    cepCell* last = &array->cell[array->store.chdCount - 1];
    return (cell < last)? cell + 1: NULL;
}


static inline cepCell* array_next_by_name(cepArray* array, cepDT* name, uintptr_t* prev) {
    cepCell* cell = array->cell;
    for (size_t i = prev? (*prev + 1): 0;  i < array->store.chdCount;  i++, cell++){
        if (cep_cell_name_is(cell, name))
            return cell;
    }
    return NULL;
}

static inline bool array_traverse(cepArray* array, cepTraverse func, void* context, cepEntry* entry) {
    assert(array && array->capacity >= array->store.chdCount);
    entry->parent = array->store.owner;
    entry->depth  = 0;
    entry->next   = array->cell;
    cepCell* last = &array->cell[array->store.chdCount - 1];
    do {
        if (entry->cell) {
            if (!func(entry, context))
                return false;
            entry->position++;
            entry->prev = entry->cell;
        }
        entry->cell = entry->next;
        entry->next++;
    } while (entry->next <= last);
    entry->next = NULL;
    return func(entry, context);
}


static inline void array_sort(cepArray* array, cepCompare compare, void* context) {
  #ifdef _GNU_SOURCE
    qsort_r
  #else
    qsort_s
  #endif
        (array->cell, array->store.chdCount, sizeof(cepCell), (cepFunc) compare, context);

    array_update_children_parent_ptr(array->cell, &array->cell[array->store.chdCount - 1]);
}


static inline void array_take(cepArray* array, cepCell* target) {
    assert(array && array->capacity >= array->store.chdCount);
    cepCell* last = &array->cell[array->store.chdCount - 1];
    cep_cell_transfer(last, target);
    CEP_0(last);
}


static inline void array_pop(cepArray* array, cepCell* target) {
    assert(array && array->capacity >= array->store.chdCount);
    cepCell* first = array->cell;
    cepCell* last = &array->cell[array->store.chdCount - 1];
    cep_cell_transfer(first, target);
    if (first < last) {
        memmove(first, first + 1, (size_t) cep_ptr_dif(last, first));
        array_update_children_parent_ptr(first, last - 1);
    }
    CEP_0(last);
}


static inline void array_remove_cell(cepArray* array, cepCell* cell) {
    assert(array && array->capacity >= array->store.chdCount);
    cepCell* last = &array->cell[array->store.chdCount - 1];
    if (cell < last) {
        memmove(cell, cell + 1, (size_t) cep_ptr_dif(last, cell));
        array_update_children_parent_ptr(cell, last - 1);
    }
    CEP_0(last);
}


static inline void array_del_all_children(cepArray* array) {
    cepCell* child = array->cell;
    for (size_t n = 0; n < array->store.chdCount; n++, child++) {
        cep_cell_finalize(child);
        CEP_0(child);   // ToDo: this may be skipped.
    }
}
