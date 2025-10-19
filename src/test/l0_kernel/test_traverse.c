/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Exercises deep traversal APIs across complex hierarchies. */





#include "test.h"
#include "cep_cell.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



extern cepCell* tech_catalog_insert(cepCell* catalog, cepID name, int32_t value);
extern int      tech_catalog_compare(const cepCell* key, const cepCell* cell, void* unused);


#define TEST_TIMEOUT_SECONDS  20u


/* test_cell_setup arms a watchdog per test case so the randomized loops bail out if they overrun the agreed timeout. */
void* test_cell_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;

    const unsigned seconds = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    return test_watchdog_create(seconds);
}

/* test_cell_tear_down stops the watchdog fixture so background threads never leak between unit tests. */
void test_cell_tear_down(void* fixture) {
    test_watchdog_destroy(fixture);
}

/* test_traverse_setup mirrors the cell setup and gives traversal cases their own watchdog to clamp long fuzz loops. */
void* test_traverse_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;

    const unsigned seconds = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    return test_watchdog_create(seconds);
}

/* test_traverse_tear_down releases the watchdog once traversal assertions finish so later suites start clean. */
void test_traverse_tear_down(void* fixture) {
    test_watchdog_destroy(fixture);
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

typedef struct {
    TraverseCapture* nodeCapture;
    TraverseCapture* endCapture;
} DeepTraverseCaptureCtx;

static bool deep_traverse_node_capture(cepEntry* entry, void* ctx) {
    DeepTraverseCaptureCtx* capture = ctx;
    if (!capture || !capture->nodeCapture)
        return true;
    return traverse_capture_cb(entry, capture->nodeCapture);
}

static bool deep_traverse_end_capture(cepEntry* entry, void* ctx) {
    DeepTraverseCaptureCtx* capture = ctx;
    if (!capture || !capture->endCapture)
        return true;
    return traverse_capture_cb(entry, capture->endCapture);
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

typedef struct {
    cepCell* root;
    cepCell* first;
    cepCell* branch;
    cepCell* branchLeaf;
    cepCell* branchDictionary;
    cepCell* dictionaryValue;
    cepCell* third;
} DeepTraverseFixture;

static void deep_traverse_fixture_init(DeepTraverseFixture* fixture) {
    assert(fixture != NULL);
    memset(fixture, 0, sizeof *fixture);

    fixture->root = cep_cell_add_list(cep_root(),
                                      CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 40000),
                                      0,
                                      CEP_DTAW("CEP", "list"),
                                      CEP_STORAGE_LINKED_LIST,
                                      8);
    assert_not_null(fixture->root);

    cepID base = (cepID)(CEP_NAME_TEMP + 40500);

    uint32_t firstValue = 101u;
    fixture->first = cep_cell_append_value(fixture->root,
                                           CEP_DTS(CEP_ACRO("CEP"), base + (cepID)0),
                                           CEP_DTS(CEP_ACRO("CEP"), base + (cepID)0),
                                           &firstValue,
                                           sizeof firstValue,
                                           sizeof firstValue);
    assert_not_null(fixture->first);

    fixture->branch = cep_cell_append_list(fixture->root,
                                           CEP_DTS(CEP_ACRO("CEP"), base + (cepID)1),
                                           CEP_DTAW("CEP", "list"),
                                           CEP_STORAGE_LINKED_LIST,
                                           4);
    assert_not_null(fixture->branch);

    uint32_t branchLeafValue = 202u;
    fixture->branchLeaf = cep_cell_append_value(fixture->branch,
                                                CEP_DTS(CEP_ACRO("CEP"), base + (cepID)2),
                                                CEP_DTS(CEP_ACRO("CEP"), base + (cepID)2),
                                                &branchLeafValue,
                                                sizeof branchLeafValue,
                                                sizeof branchLeafValue);
    assert_not_null(fixture->branchLeaf);

    fixture->branchDictionary = cep_cell_append_dictionary(fixture->branch,
                                                           CEP_DTS(CEP_ACRO("CEP"), base + (cepID)3),
                                                           CEP_DTAW("CEP", "dictionary"),
                                                           CEP_STORAGE_ARRAY,
                                                           4);
    assert_not_null(fixture->branchDictionary);

    uint32_t dictionaryValue = 303u;
    fixture->dictionaryValue = cep_cell_add_value(fixture->branchDictionary,
                                                  CEP_DTS(CEP_ACRO("CEP"), base + (cepID)4),
                                                  0,
                                                  CEP_DTS(CEP_ACRO("CEP"), base + (cepID)4),
                                                  &dictionaryValue,
                                                  sizeof dictionaryValue,
                                                  sizeof dictionaryValue);
    assert_not_null(fixture->dictionaryValue);

    uint32_t thirdValue = 404u;
    fixture->third = cep_cell_append_value(fixture->root,
                                           CEP_DTS(CEP_ACRO("CEP"), base + (cepID)5),
                                           CEP_DTS(CEP_ACRO("CEP"), base + (cepID)5),
                                           &thirdValue,
                                           sizeof thirdValue,
                                           sizeof thirdValue);
    assert_not_null(fixture->third);
}

static void deep_traverse_fixture_reset_past(const DeepTraverseFixture* fixture) {
    if (!fixture)
        return;
    if (fixture->root && fixture->root->store)
        fixture->root->store->past = NULL;
    if (fixture->branch && fixture->branch->store)
        fixture->branch->store->past = NULL;
    if (fixture->branchDictionary && fixture->branchDictionary->store)
        fixture->branchDictionary->store->past = NULL;
}

static void deep_traverse_fixture_cleanup(DeepTraverseFixture* fixture) {
    if (!fixture)
        return;
    if (fixture->root) {
        cep_cell_delete_hard(fixture->root);
        fixture->root = NULL;
    }
}

/*
 * Validates forward traversal over a simple list to guarantee neighbour metadata and
 * position reporting stay consistent, underscoring why list consumers can trust
 * shallow iteration for ordered data access.
 */
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

/*
 * Exercises timestamp-gated traversal to prove we can reconstruct the set of
 * children alive at a given operation count, ensuring historical queries replay
 * the full view that callers would have observed at that time.
 */
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
    assert_size(capture.count, ==, 2);

    TraverseCaptureEntry* recFirst = &capture.entry[0];
    TraverseCaptureEntry* recSecond = &capture.entry[1];

    assert_ptr_equal(recFirst->cell, first);
    assert_ptr_equal(recFirst->parent, list);
    assert_true(recFirst->tag == tagFirst);
    assert_size(recFirst->position, ==, 0);
    assert_uint(recFirst->depth, ==, 0);
    assert_null(recFirst->prev);
    assert_ptr_equal(recFirst->next, second);

    assert_ptr_equal(recSecond->cell, second);
    assert_ptr_equal(recSecond->parent, list);
    assert_true(recSecond->tag == tagSecond);
    assert_size(recSecond->position, ==, 1);
    assert_uint(recSecond->depth, ==, 0);
    assert_ptr_equal(recSecond->prev, first);
    assert_null(recSecond->next);

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
    assert_size(capture.count, ==, 2);

    recFirst = &capture.entry[0];
    recSecond = &capture.entry[1];

    assert_ptr_equal(recFirst->cell, first);
    assert_ptr_equal(recFirst->parent, list);
    assert_true(recFirst->tag == tagFirst);
    assert_size(recFirst->position, ==, 0);
    assert_uint(recFirst->depth, ==, 0);
    assert_null(recFirst->prev);
    assert_ptr_equal(recFirst->next, second);

    assert_ptr_equal(recSecond->cell, second);
    assert_ptr_equal(recSecond->parent, list);
    assert_true(recSecond->tag == tagSecond);
    assert_size(recSecond->position, ==, 1);
    assert_uint(recSecond->depth, ==, 0);
    assert_ptr_equal(recSecond->prev, first);
    assert_null(recSecond->next);

    cep_cell_delete_hard(list);
}


/*
 * Walks a crafted multi-level hierarchy using deep traversal to check that node
 * callbacks observe depth transitions, neighbour wiring, and sibling ordering,
 * confirming recursive structure navigation behaves predictably across levels.
 */
static void test_cell_deep_traverse_sequences(void) {
    DeepTraverseFixture fixture;
    deep_traverse_fixture_init(&fixture);

    TraverseCapture nodeCapture = {0};
    TraverseCapture endCapture = {0};
    DeepTraverseCaptureCtx ctx = {
        .nodeCapture = &nodeCapture,
        .endCapture  = &endCapture,
    };

    cepEntry iterEntry = {0};
    assert_true(cep_cell_deep_traverse(fixture.root,
                                       deep_traverse_node_capture,
                                       deep_traverse_end_capture,
                                       &ctx,
                                       &iterEntry));

    cepCell* expectedNodes[] = {
        fixture.first,
        fixture.branch,
        fixture.branchLeaf,
        fixture.branchDictionary,
        fixture.dictionaryValue,
        fixture.third,
    };
    size_t expectedCount = sizeof expectedNodes / sizeof expectedNodes[0];
    assert_size(nodeCapture.count, ==, expectedCount);

    cepCell* expectedParents[] = {
        fixture.root,
        fixture.root,
        fixture.branch,
        fixture.branch,
        fixture.branchDictionary,
        fixture.root,
    };
    unsigned expectedDepths[] = {0u, 0u, 1u, 1u, 2u, 0u};
    size_t expectedPositions[] = {0u, 1u, 0u, 1u, 0u, 2u};
    cepCell* expectedPrev[] = {
        NULL,
        fixture.first,
        NULL,
        fixture.branchLeaf,
        NULL,
        fixture.branch,
    };
    cepCell* expectedNext[] = {
        fixture.branch,
        fixture.third,
        fixture.branchDictionary,
        NULL,
        NULL,
        NULL,
    };

    for (size_t i = 0; i < expectedCount; i++) {
        TraverseCaptureEntry* rec = &nodeCapture.entry[i];

        assert_ptr_equal(rec->cell, expectedNodes[i]);
        assert_ptr_equal(rec->parent, expectedParents[i]);
        assert_uint(rec->depth, ==, expectedDepths[i]);
        assert_size(rec->position, ==, expectedPositions[i]);

        if (expectedPrev[i])
            assert_ptr_equal(rec->prev, expectedPrev[i]);
        else
            assert_null(rec->prev);

        if (expectedNext[i])
            assert_ptr_equal(rec->next, expectedNext[i]);
        else
            assert_null(rec->next);
    }

    assert_size(endCapture.count, ==, 2);

    TraverseCaptureEntry* dictEnd = &endCapture.entry[0];
    assert_ptr_equal(dictEnd->cell, fixture.branchDictionary);
    assert_ptr_equal(dictEnd->parent, fixture.branch);
    assert_uint(dictEnd->depth, ==, 1);
    assert_size(dictEnd->position, ==, 1);
    assert_ptr_equal(dictEnd->prev, fixture.branchLeaf);
    assert_null(dictEnd->next);

    TraverseCaptureEntry* branchEnd = &endCapture.entry[1];
    assert_ptr_equal(branchEnd->cell, fixture.branch);
    assert_ptr_equal(branchEnd->parent, fixture.root);
    assert_uint(branchEnd->depth, ==, 0);
    assert_size(branchEnd->position, ==, 1);
    assert_ptr_equal(branchEnd->prev, fixture.first);
    assert_ptr_equal(branchEnd->next, fixture.third);

    size_t callCount = 0;
    assert_false(cep_cell_deep_traverse(fixture.root,
                                        traverse_stop_after_first,
                                        NULL,
                                        &callCount,
                                        NULL));
    assert_size(callCount, ==, 1);

    deep_traverse_fixture_cleanup(&fixture);
}


/*
 * Replays deep traversal history filters to verify timestamp scoping walks the
 * full hierarchy that existed at a given beat, ensuring historical deep scans
 * surface every descendant that was alive at that time.
 */
static void test_cell_deep_traverse_past_timelines(void) {
    DeepTraverseFixture fixture;
    deep_traverse_fixture_init(&fixture);

    uint32_t updatedDictionaryValue = 505u;
    cep_cell_update_value(fixture.dictionaryValue, sizeof updatedDictionaryValue, &updatedDictionaryValue);
    cepOpCount tsDictionary = cep_cell_timestamp();

    deep_traverse_fixture_reset_past(&fixture);

    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};
    assert_true(cep_cell_deep_traverse_past(fixture.root,
                                            tsDictionary,
                                            traverse_capture_cb,
                                            NULL,
                                            &capture,
                                            &iterEntry));

    cepCell* expectedNodes[] = {
        fixture.first,
        fixture.branch,
        fixture.branchLeaf,
        fixture.branchDictionary,
        fixture.dictionaryValue,
        fixture.third,
    };
    cepCell* expectedParents[] = {
        fixture.root,
        fixture.root,
        fixture.branch,
        fixture.branch,
        fixture.branchDictionary,
        fixture.root,
    };
    unsigned expectedDepths[] = {0u, 0u, 1u, 1u, 2u, 0u};
    size_t expectedPositions[] = {0u, 1u, 0u, 1u, 0u, 2u};
    size_t expectedCount = sizeof expectedNodes / sizeof expectedNodes[0];
    assert_size(capture.count, ==, expectedCount);

    for (size_t i = 0; i < expectedCount; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->cell, expectedNodes[i]);
        assert_ptr_equal(rec->parent, expectedParents[i]);
        assert_uint(rec->depth, ==, expectedDepths[i]);
        assert_size(rec->position, ==, expectedPositions[i]);
    }

    size_t callCount = 0;
    deep_traverse_fixture_reset_past(&fixture);
    assert_false(cep_cell_deep_traverse_past(fixture.root,
                                             tsDictionary,
                                             traverse_stop_after_first,
                                             NULL,
                                             &callCount,
                                             NULL));
    assert_size(callCount, ==, 1);

    uint32_t updatedThirdValue = 606u;
    cep_cell_update_value(fixture.third, sizeof updatedThirdValue, &updatedThirdValue);
    cepOpCount tsThird = cep_cell_timestamp();

    deep_traverse_fixture_reset_past(&fixture);

    capture = (TraverseCapture){0};
    iterEntry = (cepEntry){0};
    assert_true(cep_cell_deep_traverse_past(fixture.root,
                                            tsThird,
                                            traverse_capture_cb,
                                            NULL,
                                            &capture,
                                            &iterEntry));
    assert_size(capture.count, ==, expectedCount);

    for (size_t i = 0; i < expectedCount; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->cell, expectedNodes[i]);
        assert_ptr_equal(rec->parent, expectedParents[i]);
        assert_uint(rec->depth, ==, expectedDepths[i]);
        assert_size(rec->position, ==, expectedPositions[i]);
    }

    deep_traverse_fixture_cleanup(&fixture);
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
        cepStore* store_before = dataset->container->store;
        size_t chd_before = store_before ? store_before->chdCount : 0;

        cepCell* cell = cep_cell_add_value(dataset->container,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           position,
                                           CEP_DTS(CEP_ACRO("CEP"), tag),
                                           &value,
                                           sizeof value,
                                           sizeof value);
        assert_not_null(cell);

        cepStore* store_after = dataset->container->store;
        size_t chd_after = store_after ? store_after->chdCount : 0;

        printf("[dataset:list] step=%zu used=%zu position=%zu chdBefore=%zu chdAfter=%zu store=%p cell=%p\n",
               step,
               used,
               position,
               chd_before,
               chd_after,
               (void*)store_after,
               (void*)cell);
        fflush(stdout);

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

/*
 * Samples randomly mutated lists to assert shallow traversal reflects the final
 * insertion order, bolstering confidence that dynamic list edits still produce
 * deterministic iteration surfaces.
 */
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

/*
 * Reconstructs recorded list states to ensure past traversal isolates entries
 * tied to specific modification stamps, validating history playback for list
 * storage backends under varied insertion orders.
 */
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

/*
 * Uses deep traversal on random list datasets to make sure recursive walkers
 * still visit flat structures in the same deterministic order, reinforcing the
 * expectation that deep traversals are stable even without nested children.
 */
static void test_cell_deep_traverse_random_lists_current(const RandomListDataset* dataset) {
    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};
    assert_true(cep_cell_deep_traverse(dataset->container,
                                       traverse_capture_cb,
                                       NULL,
                                       &capture,
                                       &iterEntry));

    size_t finalCount = dataset->counts[dataset->total - 1];
    assert_size(capture.count, ==, finalCount);

    for (size_t i = 0; i < finalCount; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->parent, dataset->container);
        assert_uint(rec->depth, ==, 0);
        assert_size(rec->position, ==, i);
        assert_true(rec->tag == dataset->snapshots[dataset->total - 1][i]);
    }
}

/*
 * Rehydrates per-element list histories and uses deep traversal filtering to
 * confirm only cells updated at the tracked timestamp surface, demonstrating
 * that history-aware deep walks behave identically to their shallow siblings.
 */
static void test_cell_deep_traverse_past_random_lists(RandomListDataset* dataset) {
    size_t finalCount = dataset->counts[dataset->total - 1];
    for (size_t i = 0; i < finalCount; i++) {
        unsigned storage = dataset->storage;
        unsigned capacity = 48;
        cepCell* list;
        if (storage == CEP_STORAGE_ARRAY)
            list = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2600 + (cepID)i), 0, CEP_DTAW("CEP", "list"), storage, capacity);
        else
            list = cep_cell_add_list(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2600 + (cepID)i), 0, CEP_DTAW("CEP", "list"), storage, capacity);
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
        assert_true(cep_cell_deep_traverse_past(list,
                                                ts,
                                                traverse_capture_cb,
                                                NULL,
                                                &capture,
                                                &iterEntry));

        if (capture.count) {
            TraverseCaptureEntry* rec = &capture.entry[0];
            assert_ptr_equal(rec->cell, cell);
            assert_ptr_equal(rec->parent, list);
            assert_uint(rec->depth, ==, 0);
            assert_size(rec->position, ==, 0);
            assert_null(rec->prev);
            assert_null(rec->next);
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

/*
 * Checks that shallow traversal over dictionaries preserves comparator ordering
 * after randomized insertions, demonstrating why name-indexed stores remain
 * predictably ordered for consumer iterators.
 */
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

/*
 * Verifies historical dictionary traversals only surface entries aligned with a
 * reference timestamp, safeguarding time-travel queries from leaking unrelated
 * dictionary members.
 */
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

/*
 * Applies deep traversal to dictionary datasets to double-check that node
 * callbacks mirror shallow traversal ordering while reporting the expected
 * metadata for top-level entries.
 */
static void test_cell_deep_traverse_random_dictionaries_current(const RandomDictionaryDataset* dataset) {
    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};
    assert_true(cep_cell_deep_traverse(dataset->container,
                                       traverse_capture_cb,
                                       NULL,
                                       &capture,
                                       &iterEntry));

    size_t finalCount = dataset->counts[dataset->total - 1];
    assert_size(capture.count, ==, finalCount);

    for (size_t i = 0; i < finalCount; i++) {
        TraverseCaptureEntry* rec = &capture.entry[i];
        assert_ptr_equal(rec->parent, dataset->container);
        assert_uint(rec->depth, ==, 0);
        assert_size(rec->position, ==, i);
        assert_true(rec->tag == dataset->snapshots[dataset->total - 1][i]);
    }
}

/*
 * Rebuilds timestamped dictionary snapshots and replays deep traversal to
 * guarantee that history queries still isolate the correct entry while keeping
 * depth and neighbour metadata intact.
 */
static void test_cell_deep_traverse_past_random_dictionaries(RandomDictionaryDataset* dataset) {
    size_t finalCount = dataset->counts[dataset->total - 1];
    for (size_t i = 0; i < finalCount; i++) {
        unsigned storage = dataset->storage;
        unsigned capacity = 64;
        cepCell* dict;
        if (storage == CEP_STORAGE_ARRAY)
            dict = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2800 + (cepID)i), 0, CEP_DTAW("CEP", "dictionary"), storage, capacity);
        else
            dict = cep_cell_add_dictionary(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 2800 + (cepID)i), 0, CEP_DTAW("CEP", "dictionary"), storage, capacity);
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
        assert_true(cep_cell_deep_traverse_past(dict,
                                                ts,
                                                traverse_capture_cb,
                                                NULL,
                                                &capture,
                                                &iterEntry));

        if (capture.count) {
            TraverseCaptureEntry* rec = &capture.entry[0];
            assert_ptr_equal(rec->cell, cell);
            assert_ptr_equal(rec->parent, dict);
            assert_uint(rec->depth, ==, 0);
            assert_size(rec->position, ==, 0);
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
        cepCell* entry = tech_catalog_insert(dataset->container, name, value);
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

/*
 * Ensures catalog traversals respect comparator-driven ordering after random
 * insertions, reinforcing guarantees that sorted catalog views iterate in the
 * expected value sequence.
 */
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

/*
 * Confirms catalog history playback yields nodes modified at a target moment,
 * illustrating how deep comparator-backed stores support precise temporal
 * inspection.
 */
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
        cepCell* entry = tech_catalog_insert(cat, tag, value);
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

/*
 * Runs deep traversal against catalog datasets so we can confirm recursive walks
 * yield sorted entries followed immediately by their enumeration payloads,
 * guaranteeing predictable sequencing through multi-level catalog cells.
 */
static void test_cell_deep_traverse_random_catalogs_current(const RandomCatalogDataset* dataset) {
    TraverseCapture capture = {0};
    cepEntry iterEntry = {0};
    assert_true(cep_cell_deep_traverse(dataset->container,
                                       traverse_capture_cb,
                                       NULL,
                                       &capture,
                                       &iterEntry));

    size_t finalCount = dataset->counts[dataset->total - 1];
    assert_size(capture.count, ==, finalCount * 2);

    for (size_t i = 0; i < finalCount; i++) {
        TraverseCaptureEntry* entryRec = &capture.entry[i * 2];
        assert_ptr_equal(entryRec->parent, dataset->container);
        assert_uint(entryRec->depth, ==, 0);
        assert_size(entryRec->position, ==, i);

        cepCell* item = cep_cell_find_by_name(entryRec->cell, CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_ENUMERATION));
        assert_not_null(item);
        int32_t cellValue = *(int32_t*)cep_cell_data(item);
        assert_int32(cellValue, ==, dataset->valueSnapshots[dataset->total - 1][i]);

        TraverseCaptureEntry* valueRec = &capture.entry[i * 2 + 1];
        assert_ptr_equal(valueRec->cell, item);
        assert_ptr_equal(valueRec->parent, entryRec->cell);
        assert_uint(valueRec->depth, ==, 1);
        assert_size(valueRec->position, ==, 0);
    }
}

/*
 * Reconstructs catalog entries and replays deep traversal past queries to ensure
 * both the catalog entry and its enumeration payload appear when filtering by
 * the captured modification timestamp.
 */
static void test_cell_deep_traverse_past_random_catalogs(RandomCatalogDataset* dataset) {
    size_t finalCount = dataset->counts[dataset->total - 1];
    for (size_t i = 0; i < finalCount; i++) {
        unsigned storage = dataset->storage;
        unsigned capacity = 48;
        cepCell* cat;
        if (storage == CEP_STORAGE_ARRAY)
            cat = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 3400 + (cepID)i), 0, CEP_DTAW("CEP", "catalog"), storage, capacity, tech_catalog_compare);
        else
            cat = cep_cell_add_catalog(cep_root(), CEP_DTS(CEP_ACRO("CEP"), CEP_NAME_TEMP + 3400 + (cepID)i), 0, CEP_DTAW("CEP", "catalog"), storage, tech_catalog_compare);
        assert_not_null(cat);

        cepID tag = dataset->finalTags[i];
        int32_t value = dataset->finalValues[i];
        cepCell* entry = tech_catalog_insert(cat, tag, value);
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
        assert_true(cep_cell_deep_traverse_past(cat,
                                                ts,
                                                traverse_capture_cb,
                                                NULL,
                                                &capture,
                                                &iterEntry));

        if (capture.count) {
            TraverseCaptureEntry* entryRec = &capture.entry[0];
            assert_ptr_equal(entryRec->cell, entry);
            assert_ptr_equal(entryRec->parent, cat);
            assert_uint(entryRec->depth, ==, 0);
            assert_size(entryRec->position, ==, 0);

            if (capture.count > 1) {
                TraverseCaptureEntry* valueRec = &capture.entry[1];
                assert_ptr_equal(valueRec->cell, item);
                assert_ptr_equal(valueRec->parent, entry);
                assert_uint(valueRec->depth, ==, 1);
            }
        }

        cep_cell_delete_hard(cat);
    }
}

/*
 * Drives the random list dataset through current and historical shallow
 * traversal checks for a given storage mode, proving coverage across back-end
 * implementations.
 */
static void test_cell_traverse_random_lists(unsigned storage) {
    RandomListDataset dataset = {0};
    random_list_dataset_init(&dataset, storage);
    test_cell_traverse_random_lists_current(&dataset);
    test_cell_traverse_past_random_lists(&dataset);
    random_list_dataset_cleanup(&dataset);
}

/*
 * Mirrors the random list coverage with deep traversal to ensure recursive
 * walkers behave consistently across storage implementations, both for live and
 * historical views.
 */
static void test_cell_deep_traverse_random_lists(unsigned storage) {
    RandomListDataset dataset = {0};
    random_list_dataset_init(&dataset, storage);
    test_cell_deep_traverse_random_lists_current(&dataset);
    test_cell_deep_traverse_past_random_lists(&dataset);
    random_list_dataset_cleanup(&dataset);
}

/*
 * Aggregates dictionary traversal scenarios for each storage backend so we can
 * spot regressions across both live and historical iterations under varying
 * ordering strategies.
 */
static void test_cell_traverse_random_dictionaries(unsigned storage) {
    RandomDictionaryDataset dataset = {0};
    random_dictionary_dataset_init(&dataset, storage);
    test_cell_traverse_random_dictionaries_current(&dataset);
    test_cell_traverse_past_random_dictionaries(&dataset);
    random_dictionary_dataset_cleanup(&dataset);
}

/*
 * Extends dictionary traversal coverage into the deep traversal path so nested
 * history logic is exercised for each storage backend.
 */
static void test_cell_deep_traverse_random_dictionaries(unsigned storage) {
    RandomDictionaryDataset dataset = {0};
    random_dictionary_dataset_init(&dataset, storage);
    test_cell_deep_traverse_random_dictionaries_current(&dataset);
    test_cell_deep_traverse_past_random_dictionaries(&dataset);
    random_dictionary_dataset_cleanup(&dataset);
}

/*
 * Runs catalog traversal sweeps for the selected storage type to ensure
 * comparator-based stores maintain stable iteration semantics across current
 * and replayed timelines.
 */
static void test_cell_traverse_random_catalogs(unsigned storage) {
    RandomCatalogDataset dataset = {0};
    random_catalog_dataset_init(&dataset, storage);
    test_cell_traverse_random_catalogs_current(&dataset);
    test_cell_traverse_past_random_catalogs(&dataset);
    random_catalog_dataset_cleanup(&dataset);
}

/*
 * Replays random catalog scenarios using deep traversal so that nested catalog
 * payloads and their historical timelines stay validated across storage backends.
 */
static void test_cell_deep_traverse_random_catalogs(unsigned storage) {
    RandomCatalogDataset dataset = {0};
    random_catalog_dataset_init(&dataset, storage);
    test_cell_deep_traverse_random_catalogs_current(&dataset);
    test_cell_deep_traverse_past_random_catalogs(&dataset);
    random_catalog_dataset_cleanup(&dataset);
}

/*
 * Central test entry that wires up traversal exercises, ensuring the suite
 * initiates CEP and executes every shallow and deep traversal scenario within a
 * unified watchdog-managed session.
 */
MunitResult test_traverse(const MunitParameter params[], void* user_data_or_fixture) {
    test_boot_cycle_prepare(params);

    TestWatchdog* watchdog = user_data_or_fixture;

    cep_cell_system_initiate();

    test_cell_traverse_sequences();
    test_cell_traverse_past_timelines();
    test_cell_deep_traverse_sequences();
    test_cell_deep_traverse_past_timelines();
    test_cell_traverse_random_lists(CEP_STORAGE_LINKED_LIST);
    test_cell_traverse_random_lists(CEP_STORAGE_ARRAY);
    test_cell_deep_traverse_random_lists(CEP_STORAGE_LINKED_LIST);
    test_cell_deep_traverse_random_lists(CEP_STORAGE_ARRAY);
    test_cell_traverse_random_dictionaries(CEP_STORAGE_LINKED_LIST);
    test_cell_traverse_random_dictionaries(CEP_STORAGE_ARRAY);
    test_cell_traverse_random_dictionaries(CEP_STORAGE_RED_BLACK_T);
    test_cell_deep_traverse_random_dictionaries(CEP_STORAGE_LINKED_LIST);
    test_cell_deep_traverse_random_dictionaries(CEP_STORAGE_ARRAY);
    test_cell_deep_traverse_random_dictionaries(CEP_STORAGE_RED_BLACK_T);
    test_cell_traverse_random_catalogs(CEP_STORAGE_LINKED_LIST);
    test_cell_traverse_random_catalogs(CEP_STORAGE_ARRAY);
    test_cell_traverse_random_catalogs(CEP_STORAGE_RED_BLACK_T);
    test_cell_deep_traverse_random_catalogs(CEP_STORAGE_LINKED_LIST);
    test_cell_deep_traverse_random_catalogs(CEP_STORAGE_ARRAY);
    test_cell_deep_traverse_random_catalogs(CEP_STORAGE_RED_BLACK_T);

    if (watchdog)
        test_watchdog_signal(watchdog);

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
