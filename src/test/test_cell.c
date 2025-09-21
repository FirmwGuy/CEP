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
#include <stdlib.h>     // qsort()
#include <stdatomic.h>
#if defined(_WIN32)
#  include <windows.h>
#  include <process.h>
#else
#  include <pthread.h>
#  include <unistd.h>
#  include <time.h>
#endif




enum {
    CEP_NAME_ENUMERATION = 100,
    CEP_NAME_TEMP,

    CEP_NAME_Z_COUNT
};



typedef struct {
    atomic_bool done;
    unsigned    timeoutSeconds;
#if defined(_WIN32)
    HANDLE      thread;
#else
    pthread_t   thread;
#endif
} TestWatchdog;

#define TEST_CELL_TIMEOUT_SECONDS  60u

#if defined(_WIN32)
static unsigned __stdcall test_watchdog_thread(void* param) {
    TestWatchdog* wd = param;
    for (unsigned elapsed = 0; elapsed < wd->timeoutSeconds; elapsed++) {
        Sleep(1000);
        if (atomic_load_explicit(&wd->done, memory_order_acquire))
            return 0;
    }

    fputs("test_cell timed out after 60 seconds\n", stderr);
    fflush(stderr);
    _Exit(EXIT_FAILURE);
}
#else
static void* test_watchdog_thread(void* param) {
    TestWatchdog* wd = param;
    for (unsigned elapsed = 0; elapsed < wd->timeoutSeconds; elapsed++) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        if (atomic_load_explicit(&wd->done, memory_order_acquire))
            return NULL;
    }

    fputs("test_cell timed out after 60 seconds\n", stderr);
    fflush(stderr);
    _Exit(EXIT_FAILURE);
    return NULL;
}
#endif

static void test_watchdog_start(TestWatchdog* wd, unsigned seconds) {
    atomic_init(&wd->done, false);
    wd->timeoutSeconds = seconds;
#if defined(_WIN32)
    uintptr_t handle = _beginthreadex(NULL, 0, test_watchdog_thread, wd, 0, NULL);
    assert(handle);
    wd->thread = (HANDLE)handle;
#else
    int rc = pthread_create(&wd->thread, NULL, test_watchdog_thread, wd);
    assert(rc == 0);
#endif
}

static void test_watchdog_signal(TestWatchdog* wd) {
    atomic_store_explicit(&wd->done, true, memory_order_release);
}

static void test_watchdog_stop(TestWatchdog* wd) {
    test_watchdog_signal(wd);
#if defined(_WIN32)
    WaitForSingleObject(wd->thread, INFINITE);
    CloseHandle(wd->thread);
#else
    pthread_join(wd->thread, NULL);
#endif
}

void* test_cell_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    TestWatchdog* wd = munit_malloc(sizeof *wd);
    test_watchdog_start(wd, TEST_CELL_TIMEOUT_SECONDS);
    return wd;
}

void test_cell_tear_down(void* fixture) {
    if (!fixture)
        return;

    TestWatchdog* wd = fixture;
    test_watchdog_stop(wd);
    free(wd);
}


#define RANDOM_TRAVERSE_ITEMS 16

typedef struct {
    cepCell*    container;
    unsigned    storage;
    size_t      total;
    cepID       snapshots[RANDOM_TRAVERSE_ITEMS][RANDOM_TRAVERSE_ITEMS];
    size_t      counts[RANDOM_TRAVERSE_ITEMS];
    cepOpCount  timestamps[RANDOM_TRAVERSE_ITEMS];
    cepID       finalTags[RANDOM_TRAVERSE_ITEMS];
    uint32_t    finalValues[RANDOM_TRAVERSE_ITEMS];
} RandomListDataset;

typedef struct {
    cepCell*    container;
    unsigned    storage;
    size_t      total;
    cepID       snapshots[RANDOM_TRAVERSE_ITEMS][RANDOM_TRAVERSE_ITEMS];
    size_t      counts[RANDOM_TRAVERSE_ITEMS];
    cepOpCount  timestamps[RANDOM_TRAVERSE_ITEMS];
    cepID       finalTags[RANDOM_TRAVERSE_ITEMS];
    uint32_t    finalValues[RANDOM_TRAVERSE_ITEMS];
} RandomDictionaryDataset;

typedef struct {
    cepCell*    container;
    unsigned    storage;
    size_t      total;
    int32_t     valueSnapshots[RANDOM_TRAVERSE_ITEMS][RANDOM_TRAVERSE_ITEMS];
    size_t      counts[RANDOM_TRAVERSE_ITEMS];
    cepOpCount  timestamps[RANDOM_TRAVERSE_ITEMS];
    cepID       finalTags[RANDOM_TRAVERSE_ITEMS];
    int32_t     finalValues[RANDOM_TRAVERSE_ITEMS];
} RandomCatalogDataset;


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

    cep_cell_delete_hard(dict);
}




/*
 * Catalog scenarios: ensure comparator-driven stores agree across
 * implementations, keeping sorted order, replacement symmetry, and key-based
 * lookups intact even as catalog entries shuffle.
 */
 
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
    cep_cell_delete_hard(cell);

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

        path->dt[0] = *CEP_DTS(CEP_ACRO("CEP"), name);
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




/*
 * Traversal focus: capture callbacks record neighbour metadata so we can assert
 * that shallow and timestamped traversals walk children in the intended order
 * and honour early abort semantics.
 */
#define TRAVERSE_CAPTURE_MAX  64

typedef struct {
    cepCell*    cell;
    cepCell*    prev;
    cepCell*    next;
    cepCell*    parent;
    size_t      position;
    unsigned    depth;
    cepID       tag;
} TraverseCaptureEntry;

typedef struct {
    TraverseCaptureEntry entry[TRAVERSE_CAPTURE_MAX];
    size_t               count;
} TraverseCapture;

static bool traverse_capture_cb(cepEntry* entry, void* ctx) {
    TraverseCapture* capture = ctx;
    assert_size(capture->count, <, TRAVERSE_CAPTURE_MAX);

    TraverseCaptureEntry* slot = &capture->entry[capture->count++];
    slot->cell     = entry->cell;
    slot->prev     = entry->prev;
    slot->next     = entry->next;
    slot->parent   = entry->parent;
    slot->position = entry->position;
    slot->depth    = entry->depth;
    slot->tag      = entry->cell? cep_cell_get_name(entry->cell)->tag: 0;

    return true;
}

static bool traverse_stop_after_first(cepEntry* entry, void* ctx) {
    size_t* calls = ctx;
    (void)entry;
    (*calls)++;
    return false;
}

static int compare_cep_id(const void* a, const void* b) {
    cepID lhs = *(const cepID*)a;
    cepID rhs = *(const cepID*)b;
    if (lhs < rhs)
        return -1;
    if (lhs > rhs)
        return 1;
    return 0;
}

static int compare_int32(const void* a, const void* b) {
    int32_t lhs = *(const int32_t*)a;
    int32_t rhs = *(const int32_t*)b;
    if (lhs < rhs)
        return -1;
    if (lhs > rhs)
        return 1;
    return 0;
}

static void test_cell_traverse_sequences(void) {
    cepCell* list = cep_cell_add_list(cep_root(),
                                      CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 32),
                                      0,
                                      CEP_DTAW("CEP", "list"),
                                      CEP_STORAGE_LINKED_LIST,
                                      8);
    assert_not_null(list);

    cepCell* expected[3] = {0};
    cepID    expectedTags[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        uint32_t value = (uint32_t)(i + 1);
        cepID nameId = (cepID)(CEP_NAME_TEMP + 100 + (cepID)i);
        expected[i] = cep_cell_append_value(list,
                                            CEP_DTS(CEP_ACRO("CEP"), nameId),
                                            CEP_DTS(CEP_ACRO("CEP"), nameId),
                                            &value,
                                            sizeof value,
                                            sizeof value);
        assert_not_null(expected[i]);
        expectedTags[i] = cep_cell_get_name(expected[i])->tag;
    }

    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};

    assert_true(cep_cell_traverse(list, traverse_capture_cb, &capture, &iterEntry));
    assert_size(capture.count, ==, 3);

    for (size_t i = 0; i < capture.count; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->parent, list);
        assert_ptr_equal(rec->cell, expected[i]);
        assert_uint(rec->depth, ==, 0);
        assert_size(rec->position, ==, i);
        assert_true(rec->tag == expectedTags[i]);

        if (!i)
            assert_null(rec->prev);
        else
            assert_ptr_equal(rec->prev, expected[i - 1]);

        if (i + 1 < capture.count)
            assert_ptr_equal(rec->next, expected[i + 1]);
        else
            assert_null(rec->next);
    }

    size_t callCount = 0;
    assert_false(cep_cell_traverse(list, traverse_stop_after_first, &callCount, NULL));
    assert_size(callCount, ==, 1);

    cep_cell_delete_hard(list);
}

static void test_cell_traverse_past_timelines(void) {
    cepCell* list = cep_cell_add_list(cep_root(),
                                      CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 48),
                                      0,
                                      CEP_DTAW("CEP", "list"),
                                      CEP_STORAGE_LINKED_LIST,
                                      8);
    assert_not_null(list);

    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};

    cepID nameBase = (cepID)(CEP_NAME_TEMP + 200);

    uint32_t valueA = 10;
    cepCell* first = cep_cell_append_value(list,
                                           CEP_DTS(CEP_ACRO("CEP"), nameBase + (cepID)0),
                                           CEP_DTS(CEP_ACRO("CEP"), nameBase + (cepID)0),
                                           &valueA,
                                           sizeof valueA,
                                           sizeof valueA);
    assert_not_null(first);
    cepID tagFirst = cep_cell_get_name(first)->tag;

    uint32_t valueB = 20;
    cepCell* second = cep_cell_append_value(list,
                                            CEP_DTS(CEP_ACRO("CEP"), nameBase + (cepID)1),
                                            CEP_DTS(CEP_ACRO("CEP"), nameBase + (cepID)1),
                                            &valueB,
                                            sizeof valueB,
                                            sizeof valueB);
    assert_not_null(second);
    cepID tagSecond = cep_cell_get_name(second)->tag;

    uint32_t valueBUpdated = 30;
    cep_cell_update_value(second, sizeof valueBUpdated, &valueBUpdated);
    cepOpCount tsUpdateB = cep_cell_timestamp();

    list->store->past = NULL;
    assert_true(cep_cell_traverse_past(list, tsUpdateB, traverse_capture_cb, &capture, &iterEntry));
    assert_size(capture.count, ==, 1);
    assert_ptr_equal(capture.entry[0].cell, second);
    assert_ptr_equal(capture.entry[0].parent, list);
    assert_true(capture.entry[0].tag == tagSecond);
    assert_size(capture.entry[0].position, ==, 0);
    assert_uint(capture.entry[0].depth, ==, 0);
    assert_null(capture.entry[0].prev);
    assert_null(capture.entry[0].next);

    size_t pastCalls = 0;
    list->store->past = NULL;
    assert_false(cep_cell_traverse_past(list, tsUpdateB, traverse_stop_after_first, &pastCalls, NULL));
    assert_size(pastCalls, ==, 1);

    capture = (TraverseCapture){0};
    iterEntry = (cepEntry){0};

    uint32_t valueAUpdated = 40;
    cep_cell_update_value(first, sizeof valueAUpdated, &valueAUpdated);
    cepOpCount tsUpdateA = cep_cell_timestamp();

    list->store->past = NULL;
    assert_true(cep_cell_traverse_past(list, tsUpdateA, traverse_capture_cb, &capture, &iterEntry));
    assert_size(capture.count, ==, 1);
    assert_ptr_equal(capture.entry[0].cell, first);
    assert_ptr_equal(capture.entry[0].parent, list);
    assert_true(capture.entry[0].tag == tagFirst);
    assert_size(capture.entry[0].position, ==, 0);
    assert_uint(capture.entry[0].depth, ==, 0);
    assert_null(capture.entry[0].prev);
    assert_null(capture.entry[0].next);

    cep_cell_delete_hard(list);
}


static void random_list_dataset_init(RandomListDataset* dataset, unsigned storage) {
    assert(storage != CEP_STORAGE_PACKED_QUEUE);
    dataset->storage = storage;
    dataset->total = RANDOM_TRAVERSE_ITEMS;

    unsigned capacity = 48;
    if (storage == CEP_STORAGE_ARRAY)
        dataset->container = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 64), 0, CEP_DTAW("CEP", "list"), storage, capacity);
    else
        dataset->container = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 64), 0, CEP_DTAW("CEP", "list"), storage, capacity);
    assert_not_null(dataset->container);

    cepID order[RANDOM_TRAVERSE_ITEMS] = {0};
    uint32_t valueOrder[RANDOM_TRAVERSE_ITEMS] = {0};
    size_t used = 0;

    for (size_t step = 0; step < dataset->total; step++) {
        size_t position = used? (size_t)munit_rand_int_range(0, (int)(used + 1)): 0;
        if (position > used)
            position = used;

        cepID tag = (cepID)(CEP_NAME_TEMP + 1000 + (cepID)step);
        uint32_t value = (uint32_t)munit_rand_uint32();
        cepCell* cell = cep_cell_add_value(dataset->container,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           position,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           &value,
                                           sizeof value,
                                           sizeof value);
        assert_not_null(cell);

        if (used > position) {
            memmove(&order[position + 1], &order[position], (used - position) * sizeof order[0]);
            memmove(&valueOrder[position + 1], &valueOrder[position], (used - position) * sizeof valueOrder[0]);
        }
        order[position] = tag;
        valueOrder[position] = value;
        used++;

        dataset->timestamps[step] = cep_cell_timestamp();
        dataset->counts[step] = used;
        memcpy(dataset->snapshots[step], order, used * sizeof order[0]);
    }

    memcpy(dataset->finalTags, order, used * sizeof order[0]);
    memcpy(dataset->finalValues, valueOrder, used * sizeof valueOrder[0]);
}

static void random_list_dataset_cleanup(RandomListDataset* dataset) {
    if (dataset->container) {
        cep_cell_delete_hard(dataset->container);
        dataset->container = NULL;
    }
}

static void test_cell_traverse_random_lists_current(const RandomListDataset* dataset) {
    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};
    assert_true(cep_cell_traverse(dataset->container, traverse_capture_cb, &capture, &iterEntry));

    size_t finalCount = dataset->counts[dataset->total - 1];
    assert_size(capture.count, ==, finalCount);

    for (size_t i = 0; i < finalCount; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->parent, dataset->container);
        assert_size(rec->position, ==, i);
        assert_true(rec->tag == dataset->snapshots[dataset->total - 1][i]);
    }
}

static void test_cell_traverse_past_random_lists(RandomListDataset* dataset) {
    size_t finalCount = dataset->counts[dataset->total - 1];
    for (size_t i = 0; i < finalCount; i++) {
        unsigned storage = dataset->storage;
        unsigned capacity = 48;
        cepCell* list;
        if (storage == CEP_STORAGE_ARRAY)
            list = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2000 + (cepID)i), 0, CEP_DTAW("CEP", "list"), storage, capacity);
        else
            list = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2000 + (cepID)i), 0, CEP_DTAW("CEP", "list"), storage, capacity);
        assert_not_null(list);

        cepID tag = dataset->finalTags[i];
        uint32_t value = dataset->finalValues[i];
        cepCell* cell = cep_cell_add_value(list,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           0,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           &value,
                                           sizeof value,
                                           sizeof value);
        assert_not_null(cell);

        cepOpCount ts = list->store->modified;
        TraverseCapture capture = {0};
        cepEntry iterEntry = {0};
        list->store->past = NULL;
        assert_true(cep_cell_traverse_past(list,
                                           ts,
                                           traverse_capture_cb,
                                           &capture,
                                           &iterEntry));

        if (capture.count) {
            TraverseCaptureEntry* rec = &capture.entry[0];
            assert_true(rec->tag == tag);
        }

        cep_cell_delete_hard(list);
    }
}

static void random_dictionary_dataset_init(RandomDictionaryDataset* dataset, unsigned storage) {
    dataset->storage = storage;
    dataset->total = RANDOM_TRAVERSE_ITEMS;

    unsigned capacity = 64;
    if (storage == CEP_STORAGE_ARRAY)
        dataset->container = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 96), 0, CEP_DTAW("CEP", "dictionary"), storage, capacity);
    else
        dataset->container = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 96), 0, CEP_DTAW("CEP", "dictionary"), storage, capacity);
    assert_not_null(dataset->container);

    cepID inserted[RANDOM_TRAVERSE_ITEMS] = {0};
    uint32_t valuesInserted[RANDOM_TRAVERSE_ITEMS] = {0};
    size_t used = 0;
    size_t step = 0;

    while (step < dataset->total) {
        cepID tag = (cepID)(CEP_NAME_TEMP + 2000 + (cepID)munit_rand_int_range(0, 512));
        bool duplicate = false;
        for (size_t i = 0; i < used; i++) {
            if (inserted[i] == tag) {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;

        uint32_t value = (uint32_t)munit_rand_uint32();
        cepCell* cell = cep_cell_add_value(dataset->container,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           0,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           &value,
                                           sizeof value,
                                           sizeof value);
        assert_not_null(cell);

        inserted[used] = tag;
        valuesInserted[used] = value;
        used++;

        dataset->timestamps[step] = cep_cell_timestamp();
        dataset->counts[step] = used;

        cepID temp[RANDOM_TRAVERSE_ITEMS];
        memcpy(temp, inserted, used * sizeof temp[0]);
        qsort(temp, used, sizeof temp[0], compare_cep_id);
        memcpy(dataset->snapshots[step], temp, used * sizeof temp[0]);

        step++;
    }

    for (size_t i = 0; i < used; i++) {
        dataset->finalTags[i] = inserted[i];
        dataset->finalValues[i] = valuesInserted[i];
    }

    for (size_t i = 0; i < used; i++) {
        for (size_t j = i + 1; j < used; j++) {
            if (dataset->finalTags[j] < dataset->finalTags[i]) {
                cepID tmpTag = dataset->finalTags[i];
                dataset->finalTags[i] = dataset->finalTags[j];
                dataset->finalTags[j] = tmpTag;

                uint32_t tmpVal = dataset->finalValues[i];
                dataset->finalValues[i] = dataset->finalValues[j];
                dataset->finalValues[j] = tmpVal;
            }
        }
    }
}

static void random_dictionary_dataset_cleanup(RandomDictionaryDataset* dataset) {
    if (dataset->container) {
        cep_cell_delete_hard(dataset->container);
        dataset->container = NULL;
    }
}

static void test_cell_traverse_random_dictionaries_current(const RandomDictionaryDataset* dataset) {
    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};
    assert_true(cep_cell_traverse(dataset->container, traverse_capture_cb, &capture, &iterEntry));

    size_t finalCount = dataset->counts[dataset->total - 1];
    assert_size(capture.count, ==, finalCount);

    for (size_t i = 0; i < finalCount; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->parent, dataset->container);
        assert_size(rec->position, ==, i);
        assert_true(rec->tag == dataset->snapshots[dataset->total - 1][i]);
    }
}

static void test_cell_traverse_past_random_dictionaries(RandomDictionaryDataset* dataset) {
    size_t finalCount = dataset->counts[dataset->total - 1];
    for (size_t i = 0; i < finalCount; i++) {
        unsigned storage = dataset->storage;
        unsigned capacity = 64;
        cepCell* dict;
        if (storage == CEP_STORAGE_ARRAY)
            dict = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2100 + (cepID)i), 0, CEP_DTAW("CEP", "dictionary"), storage, capacity);
        else
            dict = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2100 + (cepID)i), 0, CEP_DTAW("CEP", "dictionary"), storage, capacity);
        assert_not_null(dict);

        cepID tag = dataset->finalTags[i];
        uint32_t value = dataset->finalValues[i];
        cepCell* cell = cep_cell_add_value(dict,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           0,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           &value,
                                           sizeof value,
                                           sizeof value);
        assert_not_null(cell);

        cepOpCount ts = dict->store->modified;
        dict->store->past = NULL;

        TraverseCapture capture = {0};
        cepEntry iterEntry = {0};
        assert_true(cep_cell_traverse_past(dict,
                                           ts,
                                           traverse_capture_cb,
                                           &capture,
                                           &iterEntry));

        if (capture.count) {
            TraverseCaptureEntry* rec = &capture.entry[0];
            assert_true(rec->tag == tag);
        }

        cep_cell_delete_hard(dict);
    }
}

static void random_catalog_dataset_init(RandomCatalogDataset* dataset, unsigned storage) {
    dataset->storage = storage;
    dataset->total = RANDOM_TRAVERSE_ITEMS;

    unsigned capacity = 48;
    if (storage == CEP_STORAGE_ARRAY)
        dataset->container = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 128), 0, CEP_DTAW("CEP", "catalog"), storage, capacity, tech_catalog_compare);
    else
        dataset->container = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 128), 0, CEP_DTAW("CEP", "catalog"), storage, tech_catalog_compare);
    assert_not_null(dataset->container);

    int32_t inserted[RANDOM_TRAVERSE_ITEMS] = {0};
    cepID names[RANDOM_TRAVERSE_ITEMS] = {0};
    size_t used = 0;
    size_t step = 0;

    while (step < dataset->total) {
        int32_t value = (int32_t)munit_rand_int_range(-2000, 2000);
        bool duplicate = false;
        for (size_t i = 0; i < used; i++) {
            if (inserted[i] == value) {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;

        cepID name = (cepID)(CEP_NAME_TEMP + 3000 + (cepID)step);
        cepCell* entry = cep_cell_add(dataset->container, 0, tech_catalog_create_structure(name, value));
        assert_not_null(entry);

        names[used] = name;
        inserted[used] = value;
        used++;

        dataset->timestamps[step] = cep_cell_timestamp();
        dataset->counts[step] = used;

        int32_t temp[RANDOM_TRAVERSE_ITEMS];
        memcpy(temp, inserted, used * sizeof temp[0]);
        qsort(temp, used, sizeof temp[0], compare_int32);
        memcpy(dataset->valueSnapshots[step], temp, used * sizeof temp[0]);

        step++;
    }

    for (size_t i = 0; i < used; i++) {
        dataset->finalTags[i] = names[i];
        dataset->finalValues[i] = inserted[i];
    }

    for (size_t i = 0; i < used; i++) {
        for (size_t j = i + 1; j < used; j++) {
            if (dataset->finalValues[j] < dataset->finalValues[i]) {
                int32_t valTmp = dataset->finalValues[i];
                dataset->finalValues[i] = dataset->finalValues[j];
                dataset->finalValues[j] = valTmp;

                cepID tagTmp = dataset->finalTags[i];
                dataset->finalTags[i] = dataset->finalTags[j];
                dataset->finalTags[j] = tagTmp;
            }
        }
    }
}

static void random_catalog_dataset_cleanup(RandomCatalogDataset* dataset) {
    if (dataset->container) {
        cep_cell_delete_hard(dataset->container);
        dataset->container = NULL;
    }
}

static void test_cell_traverse_random_catalogs_current(const RandomCatalogDataset* dataset) {
    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};
    assert_true(cep_cell_traverse(dataset->container, traverse_capture_cb, &capture, &iterEntry));

    size_t finalCount = dataset->counts[dataset->total - 1];
    assert_size(capture.count, ==, finalCount);

    for (size_t i = 0; i < finalCount; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->parent, dataset->container);
        assert_size(rec->position, ==, i);

        cepCell* item = cep_cell_find_by_name(rec->cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        assert_not_null(item);
        int32_t cellValue = *(int32_t*)cep_cell_data(item);
        assert_int32(cellValue, ==, dataset->valueSnapshots[dataset->total - 1][i]);
    }
}

static void test_cell_traverse_past_random_catalogs(RandomCatalogDataset* dataset) {
    size_t finalCount = dataset->counts[dataset->total - 1];
    for (size_t i = 0; i < finalCount; i++) {
        unsigned storage = dataset->storage;
        unsigned capacity = 48;
        cepCell* cat;
        if (storage == CEP_STORAGE_ARRAY)
            cat = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2200 + (cepID)i), 0, CEP_DTAW("CEP", "catalog"), storage, capacity, tech_catalog_compare);
        else
            cat = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2200 + (cepID)i), 0, CEP_DTAW("CEP", "catalog"), storage, tech_catalog_compare);
        assert_not_null(cat);

        cepID tag = dataset->finalTags[i];
        int32_t value = dataset->finalValues[i];
        cepCell* entry = cep_cell_add(cat, 0, tech_catalog_create_structure(tag, value));
        assert_not_null(entry);

        cepCell* item = cep_cell_find_by_name(entry, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        assert_not_null(item);
        assert_not_null(item->data);

        cepOpCount ts = cat->store->modified;
        cat->store->past = NULL;
        if (entry->store)
            entry->store->past = NULL;

        TraverseCapture capture = {0};
        cepEntry iterEntry = {0};
        assert_true(cep_cell_traverse_past(cat,
                                           ts,
                                           traverse_capture_cb,
                                           &capture,
                                           &iterEntry));

        if (capture.count) {
            cepCell* pastEntry = capture.entry[0].cell;
            assert_not_null(pastEntry);
            cepCell* pastItem = cep_cell_find_by_name(pastEntry, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
            assert_not_null(pastItem);
            int32_t pastValue = *(int32_t*)cep_cell_data(pastItem);
            assert_int32(pastValue, ==, value);
        }

        cep_cell_delete_hard(cat);
    }
}

static void test_cell_traverse_random_lists(unsigned storage) {
    RandomListDataset dataset = {0};
    random_list_dataset_init(&dataset, storage);
    test_cell_traverse_random_lists_current(&dataset);
    test_cell_traverse_past_random_lists(&dataset);
    random_list_dataset_cleanup(&dataset);
}

static void test_cell_traverse_random_dictionaries(unsigned storage) {
    RandomDictionaryDataset dataset = {0};
    random_dictionary_dataset_init(&dataset, storage);
    test_cell_traverse_random_dictionaries_current(&dataset);
    test_cell_traverse_past_random_dictionaries(&dataset);
    random_dictionary_dataset_cleanup(&dataset);
}

static void test_cell_traverse_random_catalogs(unsigned storage) {
    RandomCatalogDataset dataset = {0};
    random_catalog_dataset_init(&dataset, storage);
    test_cell_traverse_random_catalogs_current(&dataset);
    test_cell_traverse_past_random_catalogs(&dataset);
    random_catalog_dataset_cleanup(&dataset);
}



MunitResult test_cell(const MunitParameter params[], void* user_data_or_fixture) {
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
    test_cell_tech_sequencing_dictionary();

    test_cell_tech_catalog(CEP_STORAGE_LINKED_LIST);
    test_cell_tech_catalog(CEP_STORAGE_ARRAY);
    test_cell_tech_catalog(CEP_STORAGE_RED_BLACK_T);
    test_cell_tech_sequencing_catalog();

    test_cell_traverse_sequences();
    test_cell_traverse_past_timelines();
    test_cell_traverse_random_lists(CEP_STORAGE_LINKED_LIST);
    test_cell_traverse_random_lists(CEP_STORAGE_ARRAY);
    test_cell_traverse_random_dictionaries(CEP_STORAGE_LINKED_LIST);
    test_cell_traverse_random_dictionaries(CEP_STORAGE_ARRAY);
    test_cell_traverse_random_dictionaries(CEP_STORAGE_RED_BLACK_T);
    test_cell_traverse_random_catalogs(CEP_STORAGE_LINKED_LIST);
    test_cell_traverse_random_catalogs(CEP_STORAGE_ARRAY);
    test_cell_traverse_random_catalogs(CEP_STORAGE_RED_BLACK_T);

    if (watchdog)
        test_watchdog_signal(watchdog);

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
