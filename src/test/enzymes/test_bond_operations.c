/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Exercise the Layer 1 bond operation enzyme registration so the dispatch
   catalogue stays wired to the six public helpers when impulse tests depend on
   them. The test validates descriptor labels, signal paths, and idempotent
   registration to mirror the runtime contract used by heartbeats. */


#include "test.h"
#include "cep_enzyme.h"
#include "../../enzymes/cep_bond_operations.h"

#include <stddef.h>
#include <string.h>


typedef struct {
    cepDT   key;
    size_t  offset;
    size_t  count;
} cepEnzymeIndexBucketTest;

typedef struct {
    cepPath*            query;
    cepEnzymeDescriptor descriptor;
    size_t              registration_order;
} cepEnzymeEntryTest;

struct _cepEnzymeRegistry {
    cepEnzymeEntryTest*        entries;
    size_t                     entry_count;
    size_t                     entry_capacity;
    size_t                     next_registration_order;
    cepEnzymeEntryTest*        pending_entries;
    size_t                     pending_count;
    size_t                     pending_capacity;
    size_t*                    index_by_name;
    size_t                     index_by_name_count;
    cepEnzymeIndexBucketTest*  name_buckets;
    size_t                     name_bucket_count;
    size_t*                    index_by_signal;
    size_t                     index_by_signal_count;
    cepEnzymeIndexBucketTest*  signal_buckets;
    size_t                     signal_bucket_count;
};


static const cepDT* dt_sig_bond_be(void) { return CEP_DTAW("CEP", "sig_bond_be"); }
static const cepDT* dt_sig_bond_bd(void) { return CEP_DTAW("CEP", "sig_bond_bd"); }
static const cepDT* dt_sig_ctx_pr(void)  { return CEP_DTAW("CEP", "sig_ctx_pr"); }
static const cepDT* dt_sig_fct_reg(void){ return CEP_DTAW("CEP", "sig_fct_reg"); }
static const cepDT* dt_sig_fct_run(void){ return CEP_DTAW("CEP", "sig_fct_run"); }
static const cepDT* dt_sig_bond_mt(void){ return CEP_DTAW("CEP", "sig_bond_mt"); }

static const cepDT* dt_op_claim(void)    { return CEP_DTAW("CEP", "op_claim"); }
static const cepDT* dt_op_upsert(void)   { return CEP_DTAW("CEP", "op_upsert"); }
static const cepDT* dt_op_register(void) { return CEP_DTAW("CEP", "op_reg"); }
static const cepDT* dt_op_dispatch(void) { return CEP_DTAW("CEP", "op_disp"); }
static const cepDT* dt_op_tick(void)     { return CEP_DTAW("CEP", "op_tick"); }

static bool cep_bond_op_path_matches(const cepPath* query, const cepDT segments[2]) {
    if (!query || query->length != 2u) {
        return false;
    }

    if (cep_dt_compare(&query->past[0].dt, &segments[0]) != 0) {
        return false;
    }

    if (cep_dt_compare(&query->past[1].dt, &segments[1]) != 0) {
        return false;
    }

    return true;
}

MunitResult test_bond_operations_enzymes(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    munit_assert_true(cep_bond_operations_register(NULL));

    cep_cell_system_initiate();

    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    munit_assert_true(cep_bond_operations_register(registry));
    cep_enzyme_registry_activate_pending(registry);

    size_t registered = cep_enzyme_registry_size(registry);
    munit_assert_size(registered, ==, 6u);

    for (size_t entry_index = 0; entry_index < registry->entry_count; ++entry_index) {
        const cepEnzymeEntryTest* entry = &registry->entries[entry_index];
        munit_assert_not_null(entry->query);
        munit_assert_uint(entry->query->length, ==, 2u);
        munit_assert_not_null(entry->descriptor.label);
    }

    const struct {
        cepDT segments[2];
        const char*  label;
    } expectations[] = {
        {{ *dt_sig_bond_be(), *dt_op_claim()    }, "l1.being.claim"    },
        {{ *dt_sig_bond_bd(), *dt_op_upsert()   }, "l1.bond.upsert"    },
        {{ *dt_sig_ctx_pr(),  *dt_op_upsert()   }, "l1.context.upsert" },
        {{ *dt_sig_fct_reg(), *dt_op_register() }, "l1.facet.register" },
        {{ *dt_sig_fct_run(), *dt_op_dispatch() }, "l1.facet.dispatch" },
        {{ *dt_sig_bond_mt(), *dt_op_tick()     }, "l1.tick"           },
    };

    for (size_t i = 0; i < cep_lengthof(expectations); ++i) {
        bool label_seen = false;
        for (size_t entry_index = 0; entry_index < registry->entry_count; ++entry_index) {
            const cepEnzymeEntryTest* entry = &registry->entries[entry_index];
            if (strcmp(entry->descriptor.label, expectations[i].label) == 0) {
                label_seen = true;
                break;
            }
        }
        munit_assert_true(label_seen);
    }

    for (size_t i = 0; i < cep_lengthof(expectations); ++i) {
        bool matched = false;
        const cepDT* segments = expectations[i].segments;

        for (size_t entry_index = 0; entry_index < registry->entry_count; ++entry_index) {
            const cepEnzymeEntryTest* entry = &registry->entries[entry_index];
            if (!entry->query || !entry->descriptor.label) {
                continue;
            }

            if (strcmp(entry->descriptor.label, expectations[i].label) != 0) {
                continue;
            }

            munit_assert_uint(entry->query->past[0].dt.domain, ==, segments[0].domain);
            munit_assert_uint(entry->query->past[1].dt.domain, ==, segments[1].domain);

            if (!cep_bond_op_path_matches(entry->query, segments)) {
                char expected_signal_text[12] = {0};
                char actual_signal_text[12] = {0};
                cep_word_to_text(segments[0].tag, expected_signal_text);
                cep_word_to_text(entry->query->past[0].dt.tag, actual_signal_text);
                munit_assert_string_equal(actual_signal_text, expected_signal_text);

                char expected_op_text[12] = {0};
                char actual_op_text[12] = {0};
                cep_word_to_text(segments[1].tag, expected_op_text);
                cep_word_to_text(entry->query->past[1].dt.tag, actual_op_text);
                munit_assert_string_equal(actual_op_text, expected_op_text);
                continue;
            }

            munit_assert_int(entry->descriptor.match, ==, CEP_ENZYME_MATCH_EXACT);
            matched = true;
            break;
        }

        munit_assert_true(matched);
    }

    size_t size_before = cep_enzyme_registry_size(registry);
    munit_assert_true(cep_bond_operations_register(registry));
    cep_enzyme_registry_activate_pending(registry);
    size_t size_after = cep_enzyme_registry_size(registry);
    munit_assert_size(size_after, ==, size_before);

    cep_enzyme_registry_destroy(registry);
    cep_cell_system_shutdown();
    return MUNIT_OK;
}
