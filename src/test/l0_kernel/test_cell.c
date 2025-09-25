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
#include <string.h>     // memset()
#include <inttypes.h>   // PRIX64



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
    (void)unused;

    assert_not_null(entry->cell);
    char this[16], prev[16], next[16];
    test_cell_print(entry->cell, this);
    test_cell_print(entry->prev, prev);
    test_cell_print(entry->next, next);
    munit_logf(MUNIT_LOG_DEBUG, "(%u):  %s  <%s, %s>\n", (unsigned)entry->position, this, prev, next);
    return true;
}



static int hash_value_compare(const cepCell* first, const cepCell* second, void* context) {
    (void)context;

    assert(first && second);

    const uint32_t left  = *(const uint32_t*)cep_cell_data(first);
    const uint32_t right = *(const uint32_t*)cep_cell_data(second);
    if (left < right)
        return -1;
    if (left > right)
        return 1;
    return 0;
}


static cepCell* hash_index_add_value(cepCell* table, cepID name, uint32_t value) {
    cepCell child = {0};
    cep_cell_initialize_value(&child,
                              CEP_DTS(CEP_ACRO("CEP"), name),
                              CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION),
                              &value,
                              sizeof value,
                              sizeof value);
    cepCell* inserted = cep_cell_add(table, 0, &child);
    assert_not_null(inserted);
    return inserted;
}


typedef struct {
    uint64_t    sum;
    size_t      count;
} HashVisit;

static bool hash_table_visit_sum(cepEntry* entry, void* context) {
    if (!entry->cell)
        return true;

    HashVisit* visit = context;
    visit->sum += *(uint32_t*)cep_cell_data(entry->cell);
    visit->count++;
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
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepPast)));
    path->length = 1;
    path->capacity = 1;
    path->past[0].dt = (cepDT){0};
    path->past[0].timestamp = 0;
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
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepPast)));
    path->length = 1;
    path->capacity = 1;
    path->past[0].dt = *cep_cell_get_name(item);
    path->past[0].timestamp = 0;
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

    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepPast)));
    path->length = 1;
    path->capacity = 1;
    path->past[0].dt = *CEP_DTS(CEP_ACRO("CEP"), name);
    path->past[0].timestamp = 0;
    cell = cep_cell_find_by_path(cat, path);
    found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
    assert_ptr_equal(found, item);

    assert_true(cep_cell_traverse(cell, print_values, NULL, NULL));
}



/* Exercise link shadow bookkeeping across creation, retargeting, and teardown
   so a single backlink transitions cleanly between targets and leaves no stale
   references once removed. */
static void test_cell_links_shadowing(void) {
    cepCell* list = cep_cell_add_list(cep_root(),
                                      CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 4000),
                                      0,
                                      CEP_DTAW("CEP", "list"),
                                      CEP_STORAGE_LINKED_LIST,
                                      8);

    cepCell* payloadA = cep_cell_append_list(list,
                                             CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 4001),
                                             CEP_DTAW("CEP", "list"),
                                             CEP_STORAGE_LINKED_LIST,
                                             4);

    cepCell* linkA = cep_cell_append_link(list,
                                          CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 4010),
                                          payloadA);

    assert_int(payloadA->metacell.shadowing, ==, CEP_SHADOW_SINGLE);
    assert_ptr_equal(payloadA->store->linked, linkA);
    assert_ptr_equal(cep_link_pull(linkA), payloadA);

    cepCell* payloadB = cep_cell_append_list(list,
                                             CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 4002),
                                             CEP_DTAW("CEP", "list"),
                                             CEP_STORAGE_LINKED_LIST,
                                             4);

    cep_link_set(linkA, payloadB);

    assert_int(payloadA->metacell.shadowing, ==, CEP_SHADOW_NONE);
    assert_null(payloadA->store->linked);
    assert_ptr_equal(linkA->link, payloadB);
    assert_ptr_equal(cep_link_pull(linkA), payloadB);
    assert_int(payloadB->metacell.shadowing, ==, CEP_SHADOW_SINGLE);
    assert_ptr_equal(payloadB->store->linked, linkA);

    cep_cell_delete_hard(linkA);

    assert_int(payloadB->metacell.shadowing, ==, CEP_SHADOW_NONE);
    assert_null(payloadB->store->linked);
    assert_null(payloadB->store->shadow);

    assert_int(payloadA->metacell.shadowing, ==, CEP_SHADOW_NONE);
    assert_null(payloadA->store->linked);
    assert_null(payloadA->store->shadow);

    cep_cell_delete_hard(payloadB);
    cep_cell_delete_hard(payloadA);
    assert_false(cep_cell_children(list));
    cep_cell_delete_hard(list);
}



/*
 * List verification block: stresses append/prepend/delete paths to prove that
 * every list backend (linked list, array, packed queue) keeps ordering and
 * lookup semantics consistent while IDs churn under randomised edits.
 */
 
static void test_cell_tech_list(unsigned storage) {
    cepCell* list = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), 0, CEP_DTAW("CEP", "list"), storage, 20);

    /* One item operations */

    // Append, lookups and delete
    test_cell_zero_item_ops(list);
    uint32_t  value = 1;
    cepCell* item = cep_cell_append_value(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    test_cell_one_item_ops(list, item);
    cep_cell_delete_hard(item);

    // Push and lookups
    test_cell_zero_item_ops(list);
    value = 1;
    item = cep_cell_prepend_value(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    test_cell_one_item_ops(list, item);

    // Multi-item ops
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepPast)));
    path->length = 1;
    path->capacity = 1;
    path->past[0].timestamp = 0;
    cepCell* found;
    uint32_t first = 1, last = 1;
    size_t index;

    for (unsigned n = 1; n < 10;  n++) {
        if (cep_cell_children(list) > 2) {
            switch (munit_rand_int_range(0, 2)) {
              case 1:
                cep_cell_delete_hard(cep_cell_first(list));
                found = cep_cell_first(list);
                first = *(uint32_t*)cep_cell_data(found);
                break;
              case 2:
                cep_cell_delete_hard(cep_cell_last(list));
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

        path->past[0].dt = *cep_cell_get_name(item);
        path->past[0].timestamp = 0;
        found = cep_cell_find_by_path(list, path);
        assert_ptr_equal(found, item);

        assert_true(cep_cell_traverse(list, print_values, NULL, NULL));
    }

    /* Nested cell */

    cepCell* child = cep_cell_append_list(list, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), CEP_DTAW("CEP", "list"), storage, 20);
    item = cep_cell_prepend_value(child, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+30), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_Z_COUNT+30), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    assert_true(cep_cell_deep_traverse(list, print_values, NULL, NULL, NULL));

    cep_cell_delete_hard(list);
}




/*
 * Dictionary coverage overview: validates that by-name stores across storage
 * backends honour uniqueness, replacement, and mixed deletion/insert regimes
 * while maintaining stable lookups and sibling pointers.
 */
 
static void test_cell_tech_dictionary(unsigned storage) {
    cepCell* dict = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP), 0, CEP_DTAW("CEP", "dictionary"), storage, 20);

    /* One item operations */

    // Isert, lookups and delete
    test_cell_zero_item_ops(dict);
    uint32_t value = 1;
    cepCell* item = cep_cell_add_value(dict, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), 0, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    test_cell_one_item_ops(dict, item);
    cep_cell_delete_hard(item);

    // Multi-item ops
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepPast)));
    path->length = 1;
    path->capacity = 1;
    path->past[0].timestamp = 0;
    cepCell* found;
    uint32_t vmax = 1, vmin = 1000;
    cepID name;

    for (unsigned n = 1; n < 10;  n++) {
        if (cep_cell_children(dict) > 2) {
            switch (munit_rand_int_range(0, 2)) {
              case 1:
                cep_cell_delete_hard(cep_cell_first(dict));
                found = cep_cell_first(dict);
                vmin = *(uint32_t*)cep_cell_data(found);
                break;
              case 2:
                cep_cell_delete_hard(cep_cell_last(dict));
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

        path->past[0].dt = *cep_cell_get_name(item);
        path->past[0].timestamp = 0;
        found = cep_cell_find_by_path(dict, path);
        assert_ptr_equal(found, item);

        assert_true(cep_cell_traverse(dict, print_values, NULL, NULL));
    }

    /* Nested cell */

    cepCell* child = cep_cell_add_dictionary(dict, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+2000), 0, CEP_DTAW("CEP", "dictionary"), storage, 20);
    item = cep_cell_add_value(child, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), 0, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(uint32_t), sizeof(uint32_t));
    test_cell_value(item, value);
    assert_true(cep_cell_deep_traverse(dict, print_values, NULL, NULL, NULL));

    cep_cell_delete_hard(dict);
}




/* Hash-table backend coverage: confirm hash-indexed stores honour structural
 * deduplication, keyed lookups, and traversal bookkeeping while rehashing under
 * load. Focuses on collision handling via comparator equality and verifies that
 * the ordered walk stays consistent with the items committed.
 */
static cepStore* hash_index_store_new(unsigned storage, size_t capacity) {
    switch (storage) {
      case CEP_STORAGE_LINKED_LIST:
      case CEP_STORAGE_RED_BLACK_T:
        return cep_store_new(CEP_DTAW("CEP", "hash"), storage, CEP_INDEX_BY_HASH, hash_value_compare);

      case CEP_STORAGE_ARRAY:
        assert(capacity);
        return cep_store_new(CEP_DTAW("CEP", "hash"), storage, CEP_INDEX_BY_HASH, capacity, hash_value_compare);

      case CEP_STORAGE_HASH_TABLE:
        assert(capacity);
        return cep_store_new(CEP_DTAW("CEP", "hash"), storage, CEP_INDEX_BY_HASH, capacity, hash_value_compare);
    }

    // Unsupported storage for hash indexing in tests.
    return NULL;
}


static void test_cell_tech_hash(unsigned storage, size_t capacity) {
    cepStore* store = hash_index_store_new(storage, capacity);
    assert_not_null(store);

    cepCell* hash = cep_cell_add_child(cep_root(),
                                       CEP_TYPE_NORMAL,
                                       CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 3000 + storage),
                                       0,
                                       NULL,
                                       store);

    test_cell_zero_item_ops(hash);

    uint32_t value = 1;
    cepCell* item = hash_index_add_value(hash, CEP_NAME_ENUMERATION, value);
    test_cell_value(item, value);
    test_cell_one_item_ops(hash, item);

    cepCell* duplicate = hash_index_add_value(hash, CEP_NAME_ENUMERATION, value);
    assert_ptr_equal(duplicate, item);
    assert_size(cep_cell_children(hash), ==, 1);

    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepPast)));
    path->length = 1;
    path->capacity = 1;
    path->past[0].timestamp = 0;

    uint64_t expectedSum = value;
    size_t   expectedCount = 1;

    for (unsigned n = 1; n <= 16; n++) {
        value = (uint32_t)(n * 7u + 3u);
        cepID name = CEP_NAME_Z_COUNT + n;

        item = hash_index_add_value(hash, name, value);
        test_cell_value(item, value);

        cepCell* found = cep_cell_find_by_name(hash, CEP_DTS(CEP_ACRO("CEP"), name));
        assert_ptr_equal(found, item);

        cepCell key = {0};
        cep_cell_initialize_value(&key,
                                  CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 6000),
                                  CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION),
                                  &value,
                                  sizeof value,
                                  sizeof value);
        found = cep_cell_find_by_key(hash, &key, hash_value_compare, NULL);
        assert_ptr_equal(found, item);
        cep_cell_finalize(&key);

        path->past[0].dt = *CEP_DTS(CEP_ACRO("CEP"), name);
        found = cep_cell_find_by_path(hash, path);
        assert_ptr_equal(found, item);

        expectedSum += value;
        expectedCount++;
        assert_size(cep_cell_children(hash), ==, expectedCount);
    }

    HashVisit visit = {0};
    assert_true(cep_cell_traverse(hash, hash_table_visit_sum, &visit, NULL));
    assert_size(visit.count, ==, expectedCount);
    assert_uint64(visit.sum, ==, expectedSum);

    cepCell* first = cep_cell_first(hash);
    assert_not_null(first);
    expectedSum -= *(uint32_t*)cep_cell_data(first);
    expectedCount--;
    cep_cell_delete_hard(first);

    cepCell* last = cep_cell_last(hash);
    assert_not_null(last);
    expectedSum -= *(uint32_t*)cep_cell_data(last);
    expectedCount--;
    cep_cell_delete_hard(last);

    visit = (HashVisit){0};
    assert_true(cep_cell_traverse(hash, hash_table_visit_sum, &visit, NULL));
    assert_size(visit.count, ==, expectedCount);
    assert_uint64(visit.sum, ==, expectedSum);

    cep_cell_delete_hard(hash);
}



/*
 * Catalog scenarios: ensure comparator-driven stores agree across
 * implementations, keeping sorted order, replacement symmetry, and key-based
 * lookups intact even as catalog entries shuffle.
 */
 
cepCell* tech_catalog_create_structure(cepID name, int32_t value) {
    static cepCell cell;
    CEP_0(&cell);
    cep_cell_initialize_dictionary(&cell, CEP_DTS(CEP_ACRO("CEP"), name), CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_ARRAY, 2);
    cepCell* item = cep_cell_add_value(&cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), 0, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION), &value, sizeof(int32_t), sizeof(int32_t));
    test_cell_value(item, value);
    return &cell;
}

int tech_catalog_compare(const cepCell* key, const cepCell* cell, void* unused) {
    (void)unused;

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
    cep_cell_delete_hard(cell);

    // Multi-item ops
    cepPath* path = cep_alloca(sizeof(cepPath) + (1 * sizeof(cepPast)));
    path->length = 1;
    path->capacity = 1;
    path->past[0].timestamp = 0;
    cepCell* found;
    int32_t vmax = 1, vmin = 1000;
    cepID name;

    for (unsigned n = 1; n < 10;  n++) {
        if (cep_cell_children(cat) > 2) {
            switch (munit_rand_int_range(0, 2)) {
              case 1:
                cep_cell_delete_hard(cep_cell_first(cat));
                cell = cep_cell_first(cat);
                found = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
                vmin = *(int32_t*)cep_cell_data(found);
                break;
              case 2:
                cep_cell_delete_hard(cep_cell_last(cat));
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

        path->past[0].dt = *CEP_DTS(CEP_ACRO("CEP"), name);
        path->past[0].timestamp = 0;
        cell = cep_cell_find_by_path(cat, path);
        found  = cep_cell_find_by_name(cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        assert_ptr_equal(found, item);

        assert_true(cep_cell_traverse(cat, print_values, NULL, NULL));
    }

    /* Nested cell */
    assert_true(cep_cell_deep_traverse(cat, print_values, NULL, NULL, NULL));

    cep_cell_delete_hard(cat);
}




/* Extra item sequencing checks for different back ends.
 */
  
static void test_cell_tech_sequencing_list(void) {
    size_t maxItems = munit_rand_int_range(2, 100);

    cepCell* bookL = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+1), 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_LINKED_LIST);
    cepCell* bookA = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP+2), 0, CEP_DTAW("CEP", "list"), CEP_STORAGE_ARRAY, maxItems);

    cepCell* foundL, *foundA;

    for (unsigned n = 0; n < maxItems;  n++) {
        uint32_t value = 1 + (munit_rand_uint32() % (maxItems>>1));
        cepID name = CEP_NAME_ENUMERATION + value;

        if ((foundL = cep_cell_find_by_name(bookL, CEP_DTS(CEP_ACRO("CEP"), name))))
            cep_cell_delete_hard(foundL);
        if ((foundA = cep_cell_find_by_name(bookA, CEP_DTS(CEP_ACRO("CEP"), name))))
            cep_cell_delete_hard(foundA);
        assert((!foundL && !foundA) || (foundL && foundA));

        if (cep_cell_children(bookL)) {
            switch (munit_rand_int_range(0, 4)) {
              case 1:
                cep_cell_delete_hard(cep_cell_first(bookL));
                cep_cell_delete_hard(cep_cell_first(bookA));
                break;
              case 2:
                cep_cell_delete_hard(cep_cell_last(bookL));
                cep_cell_delete_hard(cep_cell_last(bookA));
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

    cep_cell_delete_hard(bookA);
    cep_cell_delete_hard(bookL);
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
            cep_cell_delete_hard(foundL);
        if ((foundA = cep_cell_find_by_name(dictA, CEP_DTS(CEP_ACRO("CEP"), name)))) 
            cep_cell_delete_hard(foundA);
        if ((foundT = cep_cell_find_by_name(dictT, CEP_DTS(CEP_ACRO("CEP"), name)))) 
            cep_cell_delete_hard(foundT);
        assert((!foundL && !foundA && !foundT) || (foundL && foundA && foundT));

        if (cep_cell_children(dictL)) {
            switch (munit_rand_int_range(0, 4)) {
              case 1:
                cep_cell_delete_hard(cep_cell_first(dictL));
                cep_cell_delete_hard(cep_cell_first(dictA));
                cep_cell_delete_hard(cep_cell_first(dictT));
                break;
              case 2:
                cep_cell_delete_hard(cep_cell_last(dictL));
                cep_cell_delete_hard(cep_cell_last(dictA));
                cep_cell_delete_hard(cep_cell_last(dictT));
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

    cep_cell_delete_hard(dictT);
    cep_cell_delete_hard(dictA);
    cep_cell_delete_hard(dictL);
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

        if ((foundL = cep_cell_find_by_key(catL, &key, tech_catalog_compare, NULL)))    cep_cell_delete_hard(foundL);
        if ((foundA = cep_cell_find_by_key(catA, &key, tech_catalog_compare, NULL)))    cep_cell_delete_hard(foundA);
        if ((foundT = cep_cell_find_by_key(catT, &key, tech_catalog_compare, NULL)))    cep_cell_delete_hard(foundT);
        assert((!foundL && !foundA && !foundT) || (foundL && foundA && foundT));

        if (cep_cell_children(catL)) {
            switch (munit_rand_int_range(0, 4)) {
              case 1:
                cep_cell_delete_hard(cep_cell_first(catL));
                cep_cell_delete_hard(cep_cell_first(catA));
                cep_cell_delete_hard(cep_cell_first(catT));
                break;
              case 2:
                cep_cell_delete_hard(cep_cell_last(catL));
                cep_cell_delete_hard(cep_cell_last(catA));
                cep_cell_delete_hard(cep_cell_last(catT));
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

    cep_cell_delete_hard(catT);
    cep_cell_delete_hard(catA);
    cep_cell_delete_hard(catL);
}




MunitResult test_cell(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;

    TestWatchdog* watchdog = user_data_or_fixture;
    (void)watchdog;

    cep_cell_system_initiate();

    test_cell_tech_list(CEP_STORAGE_LINKED_LIST);
    test_cell_tech_list(CEP_STORAGE_ARRAY);
    test_cell_tech_list(CEP_STORAGE_PACKED_QUEUE);
    test_cell_tech_sequencing_list();

    test_cell_tech_dictionary(CEP_STORAGE_LINKED_LIST);
    test_cell_tech_dictionary(CEP_STORAGE_ARRAY);
    test_cell_tech_dictionary(CEP_STORAGE_RED_BLACK_T);
    test_cell_tech_hash(CEP_STORAGE_LINKED_LIST, 0);
    test_cell_tech_hash(CEP_STORAGE_ARRAY, 24);
    test_cell_tech_hash(CEP_STORAGE_RED_BLACK_T, 0);
    test_cell_tech_hash(CEP_STORAGE_HASH_TABLE, 16);
    test_cell_tech_sequencing_dictionary();

    test_cell_tech_catalog(CEP_STORAGE_LINKED_LIST);
    test_cell_tech_catalog(CEP_STORAGE_ARRAY);
    test_cell_tech_catalog(CEP_STORAGE_RED_BLACK_T);
    test_cell_tech_sequencing_catalog();

    test_cell_links_shadowing();


    if (watchdog)
        test_watchdog_signal(watchdog);

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
