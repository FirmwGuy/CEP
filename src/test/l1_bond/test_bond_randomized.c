/* Randomized bond tests fuzz the Layer 1 public API to confirm adjacency mirrors stay consistent as we shuffle beings and bonds. Each iteration seeds fresh identities, rebuilds the topology, and then validates that runtime mirrors exactly match the expected summaries derived from external identifiers. */

#include "test.h"

#include "cep_bond.h"
#include "cep_cell.h"
#include "cep_namepool.h"

#include <stdio.h>

#include <stdlib.h>
#include <string.h>

#define MAX_RANDOM_BEINGS 6
#define MAX_RANDOM_BONDS  8
#define RANDOM_BOND_ITERATIONS 18

typedef struct {
    cepCell* dictionary;
    cepDT    entry_tag;
    char     expected[48];
} MetadataFixture;

static MetadataFixture metadata_fixture(cepCell* arena, cepID base, const char* value) {
    munit_assert_not_null(arena);
    munit_assert_not_null(value);

    MetadataFixture fixture = {0};

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT dict_name = {0};
    dict_name.domain = CEP_ACRO("CEP");
    dict_name.tag = cep_id_to_numeric(base);
    fixture.dictionary = cep_cell_add_dictionary(arena, &dict_name, 0, &dict_type, CEP_STORAGE_LINKED_LIST);
    munit_assert_not_null(fixture.dictionary);

    fixture.entry_tag.domain = CEP_ACRO("CEP");
    fixture.entry_tag.tag = cep_id_to_numeric(base + 1u);

    size_t len = strlen(value);
    munit_assert_size(len, <, sizeof fixture.expected);
    cepDT text_type = *CEP_DTAW("CEP", "text");
    cepCell* entry = cep_cell_add_value(fixture.dictionary, &fixture.entry_tag, 0, &text_type, (void*)value, len + 1u, len + 1u);
    munit_assert_not_null(entry);

    memcpy(fixture.expected, value, len + 1u);
    return fixture;
}

static cepDT random_being_dt(size_t index) {
    munit_assert_size(index, <, MAX_RANDOM_BEINGS);
    switch (index) {
    case 0: return *CEP_DTAW("CEP", "tst_bea");
    case 1: return *CEP_DTAW("CEP", "tst_beb");
    case 2: return *CEP_DTAW("CEP", "tst_bec");
    case 3: return *CEP_DTAW("CEP", "tst_bed");
    case 4: return *CEP_DTAW("CEP", "tst_bee");
    case 5: return *CEP_DTAW("CEP", "tst_bef");
    default: break;
    }
    munit_error("unexpected being index");
    return (cepDT){0};
}

static cepDT random_bond_dt(size_t index) {
    munit_assert_size(index, <, MAX_RANDOM_BONDS);
    switch (index) {
    case 0: return *CEP_DTAW("CEP", "tst_bnda");
    case 1: return *CEP_DTAW("CEP", "tst_bndb");
    case 2: return *CEP_DTAW("CEP", "tst_bndc");
    case 3: return *CEP_DTAW("CEP", "tst_bndd");
    case 4: return *CEP_DTAW("CEP", "tst_bnde");
    case 5: return *CEP_DTAW("CEP", "tst_bndf");
    case 6: return *CEP_DTAW("CEP", "tst_bndg");
    case 7: return *CEP_DTAW("CEP", "tst_bndh");
    default: break;
    }
    munit_error("unexpected bond index");
    return (cepDT){0};
}

typedef struct {
    cepDT           name;
    cepBeingHandle  handle;
    char            label[32];
    char            kind[16];
    char            external_id[32];
    MetadataFixture metadata;
} RandomBeing;

typedef struct {
    size_t          a_index;
    size_t          b_index;
    cepDT           tag;
    cepDT           key;
    char            summary_a[64];
    char            summary_b[64];
    MetadataFixture metadata;
} RandomBond;

/* expect_value_for_name fetches a named child from a dictionary and asserts it carries text data. */
static const char* expect_value_for_name(cepCell* parent, const cepDT* name) {
    cepCell* cell = cep_cell_find_by_name(parent, name);
    munit_assert_not_null(cell);
    munit_assert_true(cep_cell_is_normal(cell));
    munit_assert_true(cep_cell_has_data(cell));
    return (const char*)cep_cell_data(cell);
}

/* seed_being_spec initialises deterministic but distinct metadata for each random being. */
static void seed_being_spec(cepCell* root, RandomBeing* being, size_t index, cepBeingSpec* spec) {
    snprintf(being->label, sizeof being->label, "Being %u", (unsigned)index);
    snprintf(being->kind, sizeof being->kind, "kind%u", (unsigned)(index % 7u));
    snprintf(being->external_id, sizeof being->external_id, "ext-%u", (unsigned)index);

    char meta_text[32];
    snprintf(meta_text, sizeof meta_text, "meta-being-%u", (unsigned)index);
    being->metadata = metadata_fixture(root, CEP_ID(0x600u + (cepID)(index * 4u)), meta_text);

    *spec = (cepBeingSpec){
        .label = being->label,
        .kind = being->kind,
        .external_id = being->external_id,
        .metadata = being->metadata.dictionary,
    };
}

/* build_summary composes the adjacency summary text expected for a bond participant. */
static void build_summary(const cepDT* bond_tag, const char* partner_id, char buffer[64]) {
    char tag_text[12] = {0};
    cep_word_to_text(bond_tag->tag, tag_text);
    snprintf(buffer, 64u, "%s:%s", tag_text, partner_id);
}

/* locate_l1_roots resolves the Layer 1 directories under the root cell so the randomized test can inspect them. */
static void locate_l1_roots(cepCell* root,
                            cepCell** beings_root,
                            cepCell** bonds_root,
                            cepCell** adjacency_root) {
    cepCell* data_root = cep_cell_find_by_name(root, CEP_DTAW("CEP", "data"));
    munit_assert_not_null(data_root);
    cepCell* namespace_root = cep_cell_find_by_name(data_root, CEP_DTAA("CEP", "CEP"));
    munit_assert_not_null(namespace_root);
    cepCell* l1_root = cep_cell_find_by_name(namespace_root, CEP_DTAA("CEP", "L1"));
    munit_assert_not_null(l1_root);
    *beings_root = cep_cell_find_by_name(l1_root, CEP_DTAW("CEP", "beings"));
    munit_assert_not_null(*beings_root);
    *bonds_root = cep_cell_find_by_name(l1_root, CEP_DTAW("CEP", "bonds"));
    munit_assert_not_null(*bonds_root);

    cepCell* runtime_bonds = cep_cell_find_by_name(root, CEP_DTAW("CEP", "bonds"));
    munit_assert_not_null(runtime_bonds);
    *adjacency_root = cep_cell_find_by_name(runtime_bonds, CEP_DTAW("CEP", "adjacency"));
    munit_assert_not_null(*adjacency_root);
}

MunitResult test_bond_randomized(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }

    for (size_t iteration = 0; iteration < RANDOM_BOND_ITERATIONS; ++iteration) {
        cepL1Result init_rc = cep_init_l1(NULL, NULL);
        munit_assert_int(init_rc, ==, CEP_L1_OK);

        cepCell* root = cep_root();
        cepCell* beings_root = NULL;
        cepCell* bonds_root = NULL;
        cepCell* adjacency_root = NULL;
        locate_l1_roots(root, &beings_root, &bonds_root, &adjacency_root);

        size_t being_count = (size_t)munit_rand_int_range(3, MAX_RANDOM_BEINGS);
        RandomBeing beings[MAX_RANDOM_BEINGS] = {0};

        for (size_t idx = 0; idx < being_count; ++idx) {
            beings[idx].name = random_being_dt(idx);
            cepBeingSpec spec = {0};
            seed_being_spec(root, &beings[idx], idx, &spec);
            cepL1Result claim_rc = cep_being_claim(root, &beings[idx].name, &spec, &beings[idx].handle);
            munit_assert_int(claim_rc, ==, CEP_L1_OK);
            munit_assert_not_null(beings[idx].handle.cell);
        }

        RandomBond bonds[MAX_RANDOM_BONDS] = {0};
        size_t bond_count = 0;
        for (size_t a = 0; a < being_count && bond_count < MAX_RANDOM_BONDS; ++a) {
            for (size_t b = a + 1; b < being_count && bond_count < MAX_RANDOM_BONDS; ++b) {
                int take_pair = munit_rand_int_range(0, 2);
                if (!take_pair && bond_count > 0) {
                    continue;
                }

                RandomBond* bond = &bonds[bond_count];
                bond->a_index = a;
                bond->b_index = b;
                bond->tag = random_bond_dt(bond_count);

                build_summary(&bond->tag, beings[b].external_id, bond->summary_a);
                build_summary(&bond->tag, beings[a].external_id, bond->summary_b);

                char label[32];
                snprintf(label, sizeof label, "bond-%u-%u", (unsigned)a, (unsigned)b);
                char meta_text[32];
                snprintf(meta_text, sizeof meta_text, "meta-bond-%u", (unsigned)bond_count);
                bond->metadata = metadata_fixture(root, CEP_ID(0x700u + (cepID)(bond_count * 4u)), meta_text);

                cepBondSpec spec = {
                    .tag = &bond->tag,
                    .role_a_tag = CEP_DTAW("CEP", "role_a"),
                    .role_a = beings[a].handle.cell,
                    .role_b_tag = CEP_DTAW("CEP", "role_b"),
                    .role_b = beings[b].handle.cell,
                    .metadata = bond->metadata.dictionary,
                    .causal_op = 0,
                    .label = label,
                    .note = "randomized",
                };

                cepBondHandle handle = {0};
                cepL1Result bond_rc = cep_bond_upsert(root, &spec, &handle);
                munit_assert_int(bond_rc, ==, CEP_L1_OK);
                munit_assert_not_null(handle.cell);

                const cepDT digest[] = {
                    *spec.tag,
                    *spec.role_a_tag,
                    *cep_cell_get_name(beings[a].handle.cell),
                    *spec.role_b_tag,
                    *cep_cell_get_name(beings[b].handle.cell),
                };
                uint64_t hash = cep_hash_bytes(digest, sizeof digest);
                bond->key.domain = CEP_ACRO("CEP");
                bond->key.tag = cep_id_to_numeric((cepID)(hash & CEP_NAME_MAXVAL));
                ++bond_count;
            }
        }

        munit_assert_size(bond_count, >, 0);
        size_t total_instances = 0;
        for (cepCell* family = cep_cell_first(bonds_root);
             family;
             family = cep_cell_next(bonds_root, family)) {
            if (!cep_cell_is_dictionary(family)) {
                continue;
            }
            total_instances += cep_cell_children(family);
        }
        munit_assert_size(total_instances, ==, bond_count);
        for (size_t idx = 0; idx < being_count; ++idx) {
            cepCell* adjacency_bucket = cep_cell_find_by_name(adjacency_root, &beings[idx].name);

            size_t expected_entries = 0;
            for (size_t bond_idx = 0; bond_idx < bond_count; ++bond_idx) {
                const RandomBond* bond = &bonds[bond_idx];
                if (bond->a_index == idx || bond->b_index == idx) {
                    munit_assert_not_null(adjacency_bucket);
                    cepCell* entry = cep_cell_find_by_name(adjacency_bucket, &bond->key);
                    munit_assert_not_null(entry);
                    const char* summary = expect_value_for_name(entry, CEP_DTAW("CEP", "value"));
                    const char* expected = (bond->a_index == idx) ? bond->summary_a : bond->summary_b;
                    munit_assert_string_equal(summary, expected);
                    ++expected_entries;
                }
            }

            cepCell* being_record = cep_cell_find_by_name(beings_root, &beings[idx].name);
            munit_assert_not_null(being_record);
            cepCell* being_meta = cep_cell_find_by_name(being_record, CEP_DTAW("CEP", "meta"));
            munit_assert_not_null(being_meta);
            const char* being_meta_value = expect_value_for_name(being_meta, &beings[idx].metadata.entry_tag);
            munit_assert_string_equal(being_meta_value, beings[idx].metadata.expected);

            if (expected_entries == 0) {
                munit_assert_null(adjacency_bucket);
                continue;
            }
            munit_assert_size(cep_cell_children(adjacency_bucket), ==, expected_entries);
        }

        for (size_t bond_idx = 0; bond_idx < bond_count; ++bond_idx) {
            const RandomBond* bond = &bonds[bond_idx];
            cepCell* bond_family = cep_cell_find_by_name(bonds_root, &bond->tag);
            munit_assert_not_null(bond_family);
            cepCell* bond_record = cep_cell_find_by_name(bond_family, &bond->key);
            munit_assert_not_null(bond_record);
            cepCell* bond_meta = cep_cell_find_by_name(bond_record, CEP_DTAW("CEP", "meta"));
            munit_assert_not_null(bond_meta);
            const char* bond_meta_value = expect_value_for_name(bond_meta, &bond->metadata.entry_tag);
            munit_assert_string_equal(bond_meta_value, bond->metadata.expected);
        }

        cep_cell_system_shutdown();
    }

    return MUNIT_OK;
}
