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




#include "test.h"
#include "cep_cell.h"
#include <stdio.h>      // sprintf()




enum {
    CEP_NAME_ENUMERATION = 100,
    CEP_NAME_TEMP,

    CEP_NAME_Z_COUNT
};



static void test_cell_print(cepCell* cell, char *sval) {
    if (!cell) {
        strcpy(sval, "Void");
    } else if (cep_cell_is_dictionary(cell)) {
        sprintf(sval, "{%"PRIX64"}", (cepID)(cep_cell_get_name(cell)->tag));
    } else if (cep_cell_children(cell)) {
        sprintf(sval, "[%"PRIX64"]", (cepID)(cep_cell_get_name(cell)->tag));
    } else if (cep_cell_has_data(cell)) {
        uint32_t val = *(uint32_t*)cep_cell_data(cell);
        sprintf(sval, "%u", val);
    }
}

static bool print_values(cepEntry* entry, void* unused) {
    assert_not_null(entry->cell);
    char this[16], prev[16], next[16];
    test_cell_print(entry->cell, this);
    test_cell_print(entry->prev, prev);
    test_cell_print(entry->next, next);
    munit_logf(MUNIT_LOG_DEBUG, "(%u):  %s  <%s, %s>\n", (unsigned)entry->position, this, prev, next);
    return true;
}


static void test_cell_value(cepCell* rec, uint32_t trueval) {
    cepData* data = rec->data;
    uint32_t vread = *(uint32_t*)data->value;
    uint32_t value = *(uint32_t*)cep_cell_data(rec);
    assert_size(data->capacity, ==, sizeof((cepData){}.value));
    assert_size(data->size, ==, sizeof(trueval));
    assert_uint(trueval, ==, value);
    assert_uint(trueval, ==, vread);
}




static void test_cell_zero_item_ops(cepCell* cell) {
    assert_false(cep_cell_children(cell));
    assert_null(cep_cell_last(cell));
    assert_null(cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION)));
    assert_null(cep_cell_find_by_position(cell, 0));
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepID)));
    path->length = 1;
    path->capacity = 1;
    path->dt[0] = (cepDT){0};
    assert_null(cep_cell_find_by_path(cell, path));
    assert_true(cep_cell_traverse(cell, print_values, NULL, NULL));
}


static void test_cell_one_item_ops(cepCell* cell, cepCell* item) {
    assert_true(cep_cell_children(cell));
    cepCell* found = cep_cell_last(cell);
    assert_ptr_equal(found, item);
    found = cep_cell_find_by_name(cell, cep_cell_get_name(item));
    assert_ptr_equal(found, item);
    found = cep_cell_find_by_position(cell, 0);
    assert_ptr_equal(found, item);
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepID)));
    path->length = 1;
    path->capacity = 1;
    path->dt[0] = *cep_cell_get_name(item);
    found = cep_cell_find_by_path(cell, path);
    assert_ptr_equal(found, item);
    assert_true(cep_cell_traverse(cell, print_values, NULL, NULL));
}


static void test_cell_nested_one_item_ops(cepCell* cat, cepID name, cepCell* item) {
    cepCell* cell  = cep_cell_last(cat);
    cepCell* found = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    assert_ptr_equal(found, item);

    cell = cep_cell_find_by_name(cat, CEP_DTS(CEP_ACRO("CEP"), name));
    found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    assert_ptr_equal(found, item);

    cell = cep_cell_find_by_position(cat, 0);
    found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    assert_ptr_equal(found, item);

    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepID)));
    path->length = 1;
    path->capacity = 1;
    path->dt[0] = *CEP_DTS(CEP_ACRO("CEP"), name);
    cell = cep_cell_find_by_path(cat, path);
    found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    assert_ptr_equal(found, item);

    assert_true(cep_cell_traverse(cell, print_values, NULL, NULL));
}




static void test_cell_tech_list(unsigned storage) {
    cepCell* list = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), 0, CEP_DTAW("CEP", "list"), storage, 20);

    /* One item operations */

    // Append, lookups and delete
    test_cell_zero_item_ops(list);
    uint32_t  value = 1;
    cepCell* item = cep_cell_append_value(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    test_cell_one_item_ops(list, item);
    cep_cell_delete(item);

    // Push and lookups
    test_cell_zero_item_ops(list);
    value = 1;
    item = cep_cell_prepend_value(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    test_cell_one_item_ops(list, item);

    // Multi-item ops
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepID)));
    path->length = 1;
    path->capacity = 1;
    cepCell* found;
    uint32_t first = 1, last = 1;
    size_t index;

    for (unsigned n = 1; n < 10;  n++) {
        if (cep_cell_children(list) > 2) {
            switch (munit_rand_int_range(0, 2)) {
              case 1:
                cep_cell_delete(cep_cell_first(list));
                found = cep_cell_first(list);
                first = *(uint32_t*)cep_cell_data(found);
                break;
              case 2:
                cep_cell_delete(cep_cell_last(list));
                found = cep_cell_last(list);
                last  = *(uint32_t*)cep_cell_data(found);
                break;
            }
        }

        value = (n + 1);
        if (munit_rand_uint32() & 1) {
            index = cep_cell_children(list);

            item = cep_cell_append_value(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+n), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+n), &value, sizeof(uint32_t), sizeof(uint32_t));
            test_cell_value(item, value);

            found = cep_cell_first(list);
            test_cell_value(found, first);
            found = cep_cell_last(list);
            test_cell_value(found, value);

            last = value;
        } else {
            index = 0;

            item = cep_cell_prepend_value(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+n), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+n), &value, sizeof(uint32_t), sizeof(uint32_t));
            test_cell_value(item, value);

            found = cep_cell_first(list);
            test_cell_value(found, value);
            found = cep_cell_last(list);
            test_cell_value(found, last);

            first = value;
        }

        found = cep_cell_find_by_name(list, cep_cell_get_name(item));
        assert_ptr_equal(found, item);

        found = cep_cell_find_by_position(list, index);
        assert_ptr_equal(found, item);

        path->dt[0] = *cep_cell_get_name(item);
        found = cep_cell_find_by_path(list, path);
        assert_ptr_equal(found, item);

        assert_true(cep_cell_traverse(list, print_values, NULL, NULL));
    }

    /* Nested cell */

    cepCell* child = cep_cell_append_list(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), CEP_DTAW("CEP", "list"), storage, 20);
    item = cep_cell_prepend_value(child, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+30), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+30), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    assert_true(cep_cell_deep_traverse(list, print_values, NULL, NULL, NULL));

    cep_cell_delete(list);
}


static void test_cell_tech_dictionary(unsigned storage) {
    cepCell* dict = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), 0, CEP_DTAW("CEP", "dictionary"), storage, 20);

    /* One item operations */

    // Isert, lookups and delete
    test_cell_zero_item_ops(dict);
    uint32_t value = 1;
    cepCell* item = cep_cell_add_value(dict, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), 0, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    test_cell_one_item_ops(dict, item);
    cep_cell_delete(item);

    // Multi-item ops
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepID)));
    path->length = 1;
    path->capacity = 1;
    cepCell* found;
    uint32_t vmax = 1, vmin = 1000;
    cepID name;

    for (unsigned n = 1; n < 10;  n++) {
        if (cep_cell_children(dict) > 2) {
            switch (munit_rand_int_range(0, 2)) {
              case 1:
                cep_cell_delete(cep_cell_first(dict));
                found = cep_cell_first(dict);
                vmin = *(uint32_t*)cep_cell_data(found);
                break;
              case 2:
                cep_cell_delete(cep_cell_last(dict));
                found = cep_cell_last(dict);
                vmax = *(uint32_t*)cep_cell_data(found);
                break;
            }
        }

        do {
            value = munit_rand_int_range(1, 1000);
            name = CEP_NAME_ENUMERATION + value;
            found = cep_cell_find_by_name(dict, CEP_DTS(CEP_ACRO("CEP"), name));
        } while (found);
        if (value < vmin)   vmin = value;
        if (value > vmax)   vmax = value;

        item = cep_cell_add_value(dict, CEP_DTS(CEP_ACRO("CEP"), name), 0, CEP_DTS(CEP_ACRO("CEP"), name), &value, sizeof(uint32_t), sizeof(uint32_t));
        test_cell_value(item, value);

        found = cep_cell_find_by_name(dict, cep_cell_get_name(item));
        assert_ptr_equal(found, item);

        found = cep_cell_first(dict);
        test_cell_value(found, vmin);

        found = cep_cell_find_by_position(dict, 0);
        test_cell_value(found, vmin);

        found = cep_cell_last(dict);
        test_cell_value(found, vmax);

        found = cep_cell_find_by_position(dict, cep_cell_children(dict) - 1);
        test_cell_value(found, vmax);

        path->dt[0] = *cep_cell_get_name(item);
        found = cep_cell_find_by_path(dict, path);
        assert_ptr_equal(found, item);

        assert_true(cep_cell_traverse(dict, print_values, NULL, NULL));
    }

    /* Nested cell */

    cepCell* child = cep_cell_add_dictionary(dict, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+2000), 0, CEP_DTAW("CEP", "dictionary"), storage, 20);
    item = cep_cell_add_value(child, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), 0, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    assert_true(cep_cell_deep_traverse(dict, print_values, NULL, NULL, NULL));

    cep_cell_delete(dict);
}


static cepCell* tech_catalog_create_structure(cepID name, int32_t value) {
    static cepCell cell;
    CEP_0(&cell);
    cep_cell_initialize_dictionary(&cell, CEP_DTS(CEP_ACRO("CEP"), name), CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_ARRAY, 2);
    cepCell* item = cep_cell_add_value(&cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), 0, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(int32_t), sizeof(int32_t));
    test_cell_value(item, value);
    return &cell;
}

static int tech_catalog_compare(const cepCell* key, const cepCell* cell, void* unused) {
    cepCell* itemK = cep_cell_find_by_name(key, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    cepCell* itemB = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    assert(itemK && itemB);
    return *(int32_t*)cep_cell_data(itemK) - *(int32_t*)cep_cell_data(itemB);
}

static void test_cell_tech_catalog(unsigned storage) {
    cepCell* cat;
    if (storage == CEP_STORAGE_ARRAY) {
        cat = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), 0, CEP_DTAW("CEP", "catalog"), storage, 20, tech_catalog_compare);
    } else {
        cat = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), 0, CEP_DTAW("CEP", "catalog"), storage, tech_catalog_compare);
    }

    /* One item operations */

    // Isert, lookups and delete
    test_cell_zero_item_ops(cat);
    int32_t value = 1;
    cepCell* cell = cep_cell_add(cat, 0, tech_catalog_create_structure(CEP_NAME_TEMP, value));
    cepCell* item = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    test_cell_nested_one_item_ops(cat, CEP_NAME_TEMP, item);
    cep_cell_delete(cell);

    // Multi-item ops
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepID)));
    path->length = 1;
    path->capacity = 1;
    cepCell* found;
    int32_t vmax = 1, vmin = 1000;
    cepID name;

    for (unsigned n = 1; n < 10;  n++) {
        if (cep_cell_children(cat) > 2) {
            switch (munit_rand_int_range(0, 2)) {
              case 1:
                cep_cell_delete(cep_cell_first(cat));
                cell = cep_cell_first(cat);
                found = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
                vmin = *(int32_t*)cep_cell_data(found);
                break;
              case 2:
                cep_cell_delete(cep_cell_last(cat));
                cell = cep_cell_last(cat);
                found = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
                vmax = *(int32_t*)cep_cell_data(found);
                break;
            }
        }

        do {
            value = munit_rand_int_range(1, 1000);
            name = CEP_NAME_TEMP + value;
            cell = cep_cell_find_by_name(cat, CEP_DTS(CEP_ACRO("CEP"), name));
        } while (cell);
        if (value < vmin)   vmin = value;
        if (value > vmax)   vmax = value;

        cell = cep_cell_add(cat, 0, tech_catalog_create_structure(name, value));
        item   = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        test_cell_value(item, value);

        cell = cep_cell_find_by_name(cat, CEP_DTS(CEP_ACRO("CEP"), name));
        found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        assert_ptr_equal(found, item);

        cell = cep_cell_first(cat);
        found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        test_cell_value(found, vmin);

        cell = cep_cell_find_by_position(cat, 0);
        found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        test_cell_value(found, vmin);

        cell = cep_cell_last(cat);
        found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        test_cell_value(found, vmax);

        cell = cep_cell_find_by_position(cat, cep_cell_children(cat) - 1);
        found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        test_cell_value(found, vmax);

        path->dt[0] = *CEP_DTS(CEP_ACRO("CEP"), name);
        cell = cep_cell_find_by_path(cat, path);
        found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        assert_ptr_equal(found, item);

        assert_true(cep_cell_traverse(cat, print_values, NULL, NULL));
    }

    /* Nested cell */
    assert_true(cep_cell_deep_traverse(cat, print_values, NULL, NULL, NULL));

    cep_cell_delete(cat);
}




static void test_cell_tech_sequencing_list(void) {
    size_t maxItems = munit_rand_int_range(2, 100);

    cepCell* bookL = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+1), 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_LINKED_LIST);
    cepCell* bookA = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+2), 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_ARRAY, maxItems);

    cepCell* foundL, *foundA;

    for (unsigned n = 0; n < maxItems;  n++) {
        uint32_t value = 1 + (munit_rand_uint32() % (maxItems>>1));
        cepID name = CEP_NAME_ENUMERATION + value;

        if ((foundL = cep_cell_find_by_name(bookL, CEP_DTS(CEP_ACRO("CEP"), name))))
            cep_cell_delete(foundL);
        if ((foundA = cep_cell_find_by_name(bookA, CEP_DTS(CEP_ACRO("CEP"), name))))
            cep_cell_delete(foundA);
        assert((!foundL && !foundA) || (foundL && foundA));

        if (cep_cell_children(bookL)) {
            switch (munit_rand_int_range(0, 4)) {
              case 1:
                cep_cell_delete(cep_cell_first(bookL));
                cep_cell_delete(cep_cell_first(bookA));
                break;
              case 2:
                cep_cell_delete(cep_cell_last(bookL));
                cep_cell_delete(cep_cell_last(bookA));
                break;
            }
        }

        cep_cell_add_value(bookL, CEP_DTS(CEP_ACRO("CEP"), name), 0, CEP_DTS(CEP_ACRO("CEP"), name), &value, sizeof(uint32_t), sizeof(uint32_t));
        cep_cell_add_value(bookA, CEP_DTS(CEP_ACRO("CEP"), name), 0, CEP_DTS(CEP_ACRO("CEP"), name), &value, sizeof(uint32_t), sizeof(uint32_t));

        cepCell* cellL = cep_cell_first(bookL);
        cepCell* cellA = cep_cell_first(bookA);

        do {
            assert(cellL && cellA);

            value = *(uint32_t*)cep_cell_data(cellL);
            test_cell_value(cellA, value);

            cellL = cep_cell_next(bookL, cellL);
            cellA = cep_cell_next(bookA, cellA);
        } while (cellL);
    }

    cep_cell_delete(bookA);
    cep_cell_delete(bookL);
}


static void test_cell_tech_sequencing_dictionary(void) {
    size_t maxItems = munit_rand_int_range(2, 100);

    cepCell* dictL = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+1), 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_LINKED_LIST);
    cepCell* dictA = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+2), 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_ARRAY, maxItems);
    cepCell* dictT = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+3), 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_RED_BLACK_T);

    cepCell* foundL, *foundA, *foundT;

    for (unsigned n = 0; n < maxItems;  n++) {
        uint32_t value = 1 + (munit_rand_uint32() % (maxItems>>1));
        cepID name = CEP_NAME_ENUMERATION + value;

        if ((foundL = cep_cell_find_by_name(dictL, CEP_DTS(CEP_ACRO("CEP"), name)))) 
            cep_cell_delete(foundL);
        if ((foundA = cep_cell_find_by_name(dictA, CEP_DTS(CEP_ACRO("CEP"), name)))) 
            cep_cell_delete(foundA);
        if ((foundT = cep_cell_find_by_name(dictT, CEP_DTS(CEP_ACRO("CEP"), name)))) 
            cep_cell_delete(foundT);
        assert((!foundL && !foundA && !foundT) || (foundL && foundA && foundT));

        if (cep_cell_children(dictL)) {
            switch (munit_rand_int_range(0, 4)) {
              case 1:
                cep_cell_delete(cep_cell_first(dictL));
                cep_cell_delete(cep_cell_first(dictA));
                cep_cell_delete(cep_cell_first(dictT));
                break;
              case 2:
                cep_cell_delete(cep_cell_last(dictL));
                cep_cell_delete(cep_cell_last(dictA));
                cep_cell_delete(cep_cell_last(dictT));
                break;
            }
        }

        cep_cell_add_value(dictL, CEP_DTS(CEP_ACRO("CEP"), name), 0, CEP_DTS(CEP_ACRO("CEP"), name), &value, sizeof(uint32_t), sizeof(uint32_t));
        cep_cell_add_value(dictA, CEP_DTS(CEP_ACRO("CEP"), name), 0, CEP_DTS(CEP_ACRO("CEP"), name), &value, sizeof(uint32_t), sizeof(uint32_t));
        cep_cell_add_value(dictT, CEP_DTS(CEP_ACRO("CEP"), name), 0, CEP_DTS(CEP_ACRO("CEP"), name), &value, sizeof(uint32_t), sizeof(uint32_t));

        cepCell* cellL = cep_cell_first(dictL);
        cepCell* cellA = cep_cell_first(dictA);
        cepCell* cellT = cep_cell_first(dictT);

        do {
            assert(cellL && cellA && cellT);

            value = *(uint32_t*)cep_cell_data(cellL);
            test_cell_value(cellA, value);
            test_cell_value(cellT, value);

            cellL = cep_cell_next(dictL, cellL);
            cellA = cep_cell_next(dictA, cellA);
            cellT = cep_cell_next(dictT, cellT);
        } while (cellL);
    }

    cep_cell_delete(dictT);
    cep_cell_delete(dictA);
    cep_cell_delete(dictL);
}


static void test_cell_tech_sequencing_catalog(void) {
    size_t maxItems = munit_rand_int_range(2, 100);

    cepCell* catL = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+1), 0, CEP_DTAW("CEP", "catalog"), CEP_STORAGE_LINKED_LIST, tech_catalog_compare);
    cepCell* catA = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+2), 0, CEP_DTAW("CEP", "catalog"), CEP_STORAGE_ARRAY, maxItems, tech_catalog_compare);
    cepCell* catT = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+3), 0, CEP_DTAW("CEP", "catalog"), CEP_STORAGE_RED_BLACK_T, tech_catalog_compare);

    cepCell* foundL, *foundA, *foundT;
    cepCell  key = *tech_catalog_create_structure(CEP_NAME_TEMP, 0);
    cepCell* item = cep_cell_find_by_name(&key, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));

    for (unsigned n = 0; n < maxItems;  n++) {
        int32_t value = 1 + (munit_rand_uint32() % (maxItems>>1));
        cepID name = CEP_NAME_ENUMERATION + value;
        cep_cell_update_value(item, sizeof(int32_t), &value);

        if ((foundL = cep_cell_find_by_key(catL, &key, tech_catalog_compare, NULL)))    cep_cell_delete(foundL);
        if ((foundA = cep_cell_find_by_key(catA, &key, tech_catalog_compare, NULL)))    cep_cell_delete(foundA);
        if ((foundT = cep_cell_find_by_key(catT, &key, tech_catalog_compare, NULL)))    cep_cell_delete(foundT);
        assert((!foundL && !foundA && !foundT) || (foundL && foundA && foundT));

        if (cep_cell_children(catL)) {
            switch (munit_rand_int_range(0, 4)) {
              case 1:
                cep_cell_delete(cep_cell_first(catL));
                cep_cell_delete(cep_cell_first(catA));
                cep_cell_delete(cep_cell_first(catT));
                break;
              case 2:
                cep_cell_delete(cep_cell_last(catL));
                cep_cell_delete(cep_cell_last(catA));
                cep_cell_delete(cep_cell_last(catT));
                break;
            }
        }

        cep_cell_add(catL, 0, tech_catalog_create_structure(name, value));
        cep_cell_add(catA, 0, tech_catalog_create_structure(name, value));
        cep_cell_add(catT, 0, tech_catalog_create_structure(name, value));

        cepCell* bookL = cep_cell_first(catL);
        cepCell* bookA = cep_cell_first(catA);
        cepCell* bookT = cep_cell_first(catT);

        do {
            cepCell*cellL = cep_cell_find_by_name(bookL, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
            cepCell*cellA = cep_cell_find_by_name(bookA, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
            cepCell*cellT = cep_cell_find_by_name(bookT, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
            assert(cellL && cellA && cellT);

            value = *(int32_t*)cep_cell_data(cellL);
            test_cell_value(cellA, value);
            test_cell_value(cellT, value);

            bookL = cep_cell_next(catL, bookL);
            bookA = cep_cell_next(catA, bookA);
            bookT = cep_cell_next(catT, bookT);
        } while (bookL);
    }

    cep_cell_finalize(&key);

    cep_cell_delete(catT);
    cep_cell_delete(catA);
    cep_cell_delete(catL);
}


MunitResult test_cell(const MunitParameter params[], void* user_data_or_fixture) {
    cep_cell_system_initiate();

    test_cell_tech_list(CEP_STORAGE_LINKED_LIST);
    test_cell_tech_list(CEP_STORAGE_ARRAY);
    test_cell_tech_list(CEP_STORAGE_PACKED_QUEUE);
    test_cell_tech_sequencing_list();

    test_cell_tech_dictionary(CEP_STORAGE_LINKED_LIST);
    test_cell_tech_dictionary(CEP_STORAGE_ARRAY);
    test_cell_tech_dictionary(CEP_STORAGE_RED_BLACK_T);
    test_cell_tech_sequencing_dictionary();

    test_cell_tech_catalog(CEP_STORAGE_LINKED_LIST);
    test_cell_tech_catalog(CEP_STORAGE_ARRAY);
    test_cell_tech_catalog(CEP_STORAGE_RED_BLACK_T);
    test_cell_tech_sequencing_catalog();

    cep_cell_system_shutdown();
    return MUNIT_OK;
}

