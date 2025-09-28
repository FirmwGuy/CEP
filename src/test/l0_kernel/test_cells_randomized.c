/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/*
 *  Randomized cell tests rebuild mixed storage subtrees while forcing name
 *  lookups, positional traversal, and payload updates to agree after every
 *  mutation. The fixture keeps a watchdog alive so fuzzier sequences never
 *  stall the suite.
 */
/* Randomized stress tests that mutate cells under varied operations. */


#include "test.h"
#include "watchdog.h"

#include "cep_cell.h"
#include "cep_namepool.h"

#include <math.h>
#include <stdbool.h>
#include <string.h>


#define TEST_TIMEOUT_SECONDS        60u
#define MAX_TREE_DEPTH              4u
#define MAX_TREE_CANDIDATES         96u
#define RANDOM_ITERATIONS           96u
#define PACKED_QUEUE_ITERATIONS     64u
#define MAX_PACKED_QUEUE_CHILDREN   64u
#define OCTREE_ITERATIONS           64u
#define MAX_OCTREE_CHILDREN         64u

typedef struct {
    TestWatchdog* watchdog;
    cepCell       root;
    cepID         next_numeric;
} CellRandomFixture;

typedef struct {
    float position[3];
} OctreePoint;

typedef struct {
    float subwide;
    float center[3];
} cepOctreeBound;

static cepDT make_random_child_name(CellRandomFixture* fix) {
    cepDT name = {0};
    if (munit_rand_uint32() & 1u)
        name.domain = CEP_WORD("rand");
    else
        name.domain = CEP_ACRO("RND");

    if (!fix->next_numeric || fix->next_numeric > CEP_AUTOID_MAX)
        fix->next_numeric = CEP_ID(1);
    name.tag = cep_id_to_numeric(fix->next_numeric++);
    return name;
}

static unsigned random_dictionary_storage(void) {
    switch (munit_rand_int_range(0, 3)) {
    case 0:
        return CEP_STORAGE_LINKED_LIST;
    case 1:
        return CEP_STORAGE_ARRAY;
    default:
        return CEP_STORAGE_RED_BLACK_T;
    }
}

static cepCell* add_random_value(CellRandomFixture* fix, cepCell* parent) {
    if (!parent || !cep_cell_has_store(parent))
        return NULL;

    cepDT name = make_random_child_name(fix);
    uint8_t payload[32];
    size_t size = (size_t)munit_rand_int_range(1, 16);
    munit_rand_memory(size, payload);

    cepCell* inserted = cep_cell_add_value(parent,
                                           &name,
                                           0,
                                           CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("RND")),
                                           payload,
                                           size,
                                           sizeof payload);
    if (!inserted)
        return NULL;

    void* stored = cep_cell_data(inserted);
    munit_assert_not_null(stored);
    munit_assert_memory_equal(size, payload, stored);
    return inserted;
}

static cepCell* add_random_container(CellRandomFixture* fix, cepCell* parent, unsigned parent_depth) {
    if (!parent || !cep_cell_has_store(parent))
        return NULL;
    if (parent_depth >= MAX_TREE_DEPTH)
        return NULL;

    cepDT name = make_random_child_name(fix);
    unsigned storage = random_dictionary_storage();

    cepCell* container = NULL;
    switch (storage) {
    case CEP_STORAGE_ARRAY: {
        size_t capacity = (size_t)munit_rand_int_range(4, 12);
        container = cep_cell_add_dictionary(parent,
                                            &name,
                                            0,
                                            CEP_DTAW("CEP", "dict"),
                                            CEP_STORAGE_ARRAY,
                                            capacity);
        break;
    }
    case CEP_STORAGE_RED_BLACK_T:
        container = cep_cell_add_dictionary(parent,
                                            &name,
                                            0,
                                            CEP_DTAW("CEP", "dict"),
                                            CEP_STORAGE_RED_BLACK_T);
        break;
    default:
        container = cep_cell_add_dictionary(parent,
                                            &name,
                                            0,
                                            CEP_DTAW("CEP", "dict"),
                                            CEP_STORAGE_LINKED_LIST);
        break;
    }

    if (container && (munit_rand_uint32() & 1u))
        (void)add_random_value(fix, container);
    return container;
}

static size_t collect_containers(cepCell* node, cepCell** out, size_t capacity, size_t count) {
    if (!node || count >= capacity)
        return count;

    if (cep_cell_has_store(node)) {
        out[count++] = node;
        for (cepCell* child = cep_cell_first(node);
             child && count < capacity;
             child = cep_cell_next(node, child)) {
            count = collect_containers(child, out, capacity, count);
        }
    }
    return count;
}

static size_t collect_value_nodes(cepCell* node, cepCell** out, size_t capacity, size_t count) {
    if (!node || count >= capacity)
        return count;

    if (cep_cell_has_data(node))
        out[count++] = node;

    if (cep_cell_has_store(node)) {
        for (cepCell* child = cep_cell_first(node);
             child && count < capacity;
             child = cep_cell_next(node, child)) {
            count = collect_value_nodes(child, out, capacity, count);
        }
    }
    return count;
}

/*
 *  Octree comparators treat the second argument as a bounding volume. Returning
 *  a positive value keeps the traversal within that quadrant, so points that
 *  fit entirely inside the box report success while anything straddling the
 *  boundary forces the caller to stay at the current node.
 */
static int octree_point_compare(const cepCell* cell, const cepCell* bound_cell, void* context) {
    (void)context;
    const OctreePoint* point = cep_cell_data(cell);
    const cepOctreeBound* bound = (const cepOctreeBound*)(const void*)bound_cell;
    if (!point || !bound)
        return 0;

    for (unsigned axis = 0; axis < 3; ++axis) {
        float delta = point->position[axis] - bound->center[axis];
        if (fabsf(delta) > bound->subwide)
            return 0;
    }
    return 1;
}

static unsigned node_depth(const cepCell* node) {
    unsigned depth = 0;
    for (const cepCell* current = node; current && !cep_cell_is_root((cepCell*)current); current = cep_cell_parent(current))
        ++depth;
    return depth;
}

static cepCell* pick_container(CellRandomFixture* fix, unsigned max_depth, bool require_children) {
    cepCell* candidates[MAX_TREE_CANDIDATES];
    size_t count = collect_containers(&fix->root, candidates, cep_lengthof(candidates), 0u);
    if (!count)
        return &fix->root;

    for (size_t attempt = 0; attempt < count; ++attempt) {
        size_t index = (size_t)munit_rand_int_range(0, (int)count);
        if (index >= count)
            index = count - 1u;
        cepCell* candidate = candidates[index];
        if (!candidate)
            continue;
        if (require_children && !cep_cell_children(candidate))
            continue;
        if (max_depth && node_depth(candidate) >= max_depth)
            continue;
        return candidate;
    }
    return &fix->root;
}

static void mutate_random_value(CellRandomFixture* fix) {
    cepCell* nodes[MAX_TREE_CANDIDATES];
    size_t count = collect_value_nodes(&fix->root, nodes, cep_lengthof(nodes), 0u);
    if (!count)
        return;

    size_t index = (size_t)munit_rand_int_range(0, (int)count);
    if (index >= count)
        index = count - 1u;
    cepCell* node = nodes[index];

    size_t size = (size_t)munit_rand_int_range(1, 16);
    uint8_t payload[32];
    munit_rand_memory(size, payload);

    void* stored = cep_cell_update(node, size, sizeof payload, payload, false);
    munit_assert_not_null(stored);
    munit_assert_memory_equal(size, payload, stored);
}

static void drop_random_child(CellRandomFixture* fix) {
    cepCell* parent = pick_container(fix, 0u, true);
    if (!parent || !cep_cell_children(parent))
        return;

    size_t count = cep_cell_children(parent);
    size_t index = (size_t)munit_rand_int_range(0, (int)count);
    if (index >= count)
        index = count - 1u;

    cepCell* child = cep_cell_find_by_position(parent, index);
    if (!child)
        return;

    cepDT name_copy = *cep_cell_get_name(child);
    cep_cell_delete_hard(child);
    munit_assert_null(cep_cell_find_by_name(parent, &name_copy));
}

static void verify_store_consistency(cepCell* parent) {
    if (!parent || !cep_cell_has_store(parent))
        return;

    size_t expected = cep_cell_children(parent);
    size_t index = 0u;

    for (cepCell* child = cep_cell_first(parent);
         child;
         child = cep_cell_next(parent, child)) {
        cepCell* by_position = cep_cell_find_by_position(parent, index);
        munit_assert_ptr_equal(by_position, child);

        const cepDT* name = cep_cell_get_name(child);
        cepCell* by_name = cep_cell_find_by_name(parent, name);
        munit_assert_ptr_equal(by_name, child);

        ++index;
        verify_store_consistency(child);
    }

    munit_assert_size(index, ==, expected);
}

/*
 *  Packed queue coverage inserts, updates, and deletes cells at arbitrary
 *  positions while mirroring the expected ordering in a shadow array so the
 *  test can prove that packed queues keep positional lookups and name
 *  searches consistent across node splits and recycling.
 */
static void exercise_packed_queue_random(CellRandomFixture* fix) {
    cepCell list;
    CEP_0(&list);

    cepDT list_name = *CEP_DTAW("CEP", "pq_root");
    cepDT store_name = *CEP_DTAW("CEP", "pq_buffer");
    cep_cell_initialize_list(&list, &list_name, &store_name, CEP_STORAGE_PACKED_QUEUE, 8);

    cepDT names[MAX_PACKED_QUEUE_CHILDREN];
    uint32_t values[MAX_PACKED_QUEUE_CHILDREN];
    size_t count = 0;

    for (unsigned iter = 0; iter < PACKED_QUEUE_ITERATIONS; ++iter) {
        bool can_insert = count < MAX_PACKED_QUEUE_CHILDREN;
        bool do_insert = (count == 0) || (can_insert && (munit_rand_uint32() & 1u));

        if (do_insert) {
            size_t position = count ? (size_t)munit_rand_int_range(0, (int)(count + 1)) : 0u;
            if (position > count)
                position = count;

            cepDT child_name = make_random_child_name(fix);
            uint32_t payload = munit_rand_uint32();

            cepCell* inserted = cep_cell_add_value(&list,
                                                   &child_name,
                                                   position,
                                                   CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("PKQ")),
                                                   &payload,
                                                   sizeof payload,
                                                   sizeof payload);
            munit_assert_not_null(inserted);

            for (size_t idx = count; idx > position; --idx) {
                names[idx] = names[idx - 1u];
                values[idx] = values[idx - 1u];
            }
            names[position] = child_name;
            values[position] = payload;
            ++count;
        } else {
            size_t position = (size_t)munit_rand_int_range(0, (int)(count - 1));
            cepCell* victim = cep_cell_find_by_position(&list, position);
            munit_assert_not_null(victim);

            cepCell* by_name = cep_cell_find_by_name(&list, &names[position]);
            munit_assert_ptr_equal(by_name, victim);

            cep_cell_delete_hard(victim);

            for (size_t idx = position; idx + 1u < count; ++idx) {
                names[idx] = names[idx + 1u];
                values[idx] = values[idx + 1u];
            }
            --count;
        }

        munit_assert_size(count, ==, cep_cell_children(&list));

        for (size_t idx = 0; idx < count; ++idx) {
            cepCell* by_position = cep_cell_find_by_position(&list, idx);
            munit_assert_not_null(by_position);

            cepCell* by_name = cep_cell_find_by_name(&list, &names[idx]);
            munit_assert_ptr_equal(by_name, by_position);

            uint32_t stored = *(uint32_t*)cep_cell_data(by_position);
            munit_assert_uint32(stored, ==, values[idx]);
        }

        test_watchdog_signal(fix->watchdog);
    }

    while (cep_cell_children(&list)) {
        cepCell* child = cep_cell_first(&list);
        cep_cell_delete_hard(child);
    }
    cep_cell_finalize_hard(&list);
}

/*
 *  Octree fuzzing sprays points throughout a bounded cube, letting the spatial
 *  comparator place them inside sub-quadrants. The test mirrors coordinates to
 *  ensure restored payloads stay intact and that lookups by name succeed after
 *  random insert/remove cycles.
 */
static void exercise_octree_random(CellRandomFixture* fix) {
    cepCell spatial;
    CEP_0(&spatial);

    cepDT root_name = *CEP_DTAW("CEP", "oct_root");
    cepDT store_name = *CEP_DTAW("CEP", "oct_space");
    float center[3] = {0.0f, 0.0f, 0.0f};
    float subwide = 8.0f;

    cep_cell_initialize_spatial(&spatial,
                                &root_name,
                                &store_name,
                                center,
                                subwide,
                                octree_point_compare);

    typedef struct {
        cepDT       name;
        OctreePoint point;
    } OctreeEntry;

    OctreeEntry entries[MAX_OCTREE_CHILDREN];
    size_t count = 0;

    for (unsigned iter = 0; iter < OCTREE_ITERATIONS; ++iter) {
        bool can_insert = count < MAX_OCTREE_CHILDREN;
        bool do_insert = (count == 0) || (can_insert && (munit_rand_uint32() & 1u));

        if (do_insert) {
            OctreeEntry entry;
            entry.name = make_random_child_name(fix);
            for (unsigned axis = 0; axis < 3; ++axis) {
                int raw = munit_rand_int_range(-700, 700);
                entry.point.position[axis] = (float)raw / 100.0f;
            }

            cepCell* inserted = cep_cell_add_value(&spatial,
                                                   &entry.name,
                                                   0,
                                                   CEP_DTS(CEP_ACRO("VAL"), CEP_ACRO("OCT")),
                                                   &entry.point,
                                                   sizeof entry.point,
                                                   sizeof entry.point);
            munit_assert_not_null(inserted);

            entries[count++] = entry;
        } else {
            size_t index = (size_t)munit_rand_int_range(0, (int)(count - 1));
            cepCell* victim = cep_cell_find_by_name(&spatial, &entries[index].name);
            munit_assert_not_null(victim);

            cep_cell_delete_hard(victim);

            for (size_t idx = index; idx + 1u < count; ++idx)
                entries[idx] = entries[idx + 1u];
            --count;
        }

        munit_assert_size(count, ==, cep_cell_children(&spatial));

        for (size_t idx = 0; idx < count; ++idx) {
            cepCell* child = cep_cell_find_by_name(&spatial, &entries[idx].name);
            munit_assert_not_null(child);
            munit_assert_memory_equal(sizeof entries[idx].point,
                                      &entries[idx].point,
                                      cep_cell_data(child));
        }

        test_watchdog_signal(fix->watchdog);
    }

    while (cep_cell_children(&spatial)) {
        cepCell* child = cep_cell_first(&spatial);
        cep_cell_delete_hard(child);
    }
    cep_cell_finalize_hard(&spatial);
}

static void exercise_random_mutations(CellRandomFixture* fix) {
    for (unsigned iter = 0; iter < RANDOM_ITERATIONS; ++iter) {
        unsigned op = (unsigned)munit_rand_int_range(0, 4);
        switch (op) {
        case 0: {
            cepCell* parent = pick_container(fix, MAX_TREE_DEPTH, false);
            (void)add_random_value(fix, parent);
            break;
        }
        case 1: {
            cepCell* parent = pick_container(fix, MAX_TREE_DEPTH - 1u, false);
            unsigned depth = node_depth(parent);
            (void)add_random_container(fix, parent, depth);
            break;
        }
        case 2:
            mutate_random_value(fix);
            break;
        default:
            drop_random_child(fix);
            break;
        }

        verify_store_consistency(&fix->root);
        test_watchdog_signal(fix->watchdog);
    }
}

static void dismantle_tree(cepCell* node) {
    if (!node || !cep_cell_has_store(node))
        return;

    while (cep_cell_children(node)) {
        cepCell* child = cep_cell_first(node);
        dismantle_tree(child);
        cep_cell_delete_hard(child);
    }
}

static void verify_inline_naming(void) {
    char text[16];

    cepID word = CEP_WORD("random");
    size_t len = cep_word_to_text(word, text);
    text[len] = '\0';
    munit_assert_string_equal(text, "random");

    cepID acro = CEP_ACRO("RND");
    len = cep_acronym_to_text(acro, text);
    text[len] = '\0';
    while (len && text[len - 1] == ' ')
        text[--len] = '\0';
    munit_assert_string_equal(text, "RND");
}

void* test_cells_randomized_setup(const MunitParameter params[], void* user_data) {
    (void)user_data;
    CellRandomFixture* fix = munit_malloc(sizeof *fix);
    unsigned timeout = test_watchdog_resolve_timeout(params, TEST_TIMEOUT_SECONDS);
    fix->watchdog = test_watchdog_create(timeout ? timeout : TEST_TIMEOUT_SECONDS);

    cep_cell_system_initiate();
    CEP_0(&fix->root);

    cepDT root_name = *CEP_DTAW("CEP", "sys_root");
    cepDT store_name = *CEP_DTAW("CEP", "sys_child");
    cep_cell_initialize_dictionary(&fix->root,
                                   &root_name,
                                   &store_name,
                                   CEP_STORAGE_RED_BLACK_T);
    fix->next_numeric = CEP_ID(1);

    unsigned seeds = (unsigned)munit_rand_int_range(2, 5);
    for (unsigned i = 0; i < seeds; ++i) {
        if (munit_rand_uint32() & 1u)
            (void)add_random_value(fix, &fix->root);
        else
            (void)add_random_container(fix, &fix->root, 0u);
    }

    verify_store_consistency(&fix->root);
    return fix;
}

void test_cells_randomized_tear_down(void* fixture) {
    CellRandomFixture* fix = fixture;
    if (!fix)
        return;

    dismantle_tree(&fix->root);
    cep_cell_finalize_hard(&fix->root);
    cep_cell_system_shutdown();

    test_watchdog_destroy(fix->watchdog);
    free(fix);
}

MunitResult test_cells_randomized(const MunitParameter params[], void* fixture) {
    (void)params;
    CellRandomFixture* fix = fixture;
    munit_assert_not_null(fix);

    exercise_random_mutations(fix);
    exercise_packed_queue_random(fix);
    exercise_octree_random(fix);
    verify_inline_naming();
    return MUNIT_OK;
}

MunitResult test_cells_naming(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;
    cep_cell_system_initiate();
    verify_inline_naming();
    cep_cell_system_shutdown();
    return MUNIT_OK;
}
