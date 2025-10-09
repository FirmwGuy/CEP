/* Exercise mailroom namespace expansion and catalog seeding to make sure the
 * helper behaves after repeated bootstrap calls. */

#include "test.h"
#include "cep_l0.h"
#include "cep_mailroom.h"
#include "cep_enzyme.h"
#include "cep_namepool.h"
#include "cep_l1_coherence.h"

#ifdef CEP_HAS_L2_TESTS
#include "cep_l2_flows.h"
#endif

#include <stdbool.h>
#include <string.h>

static cepDT mailroom_dt_from_text(const char* text) {
    cepID id = cep_text_to_word(text);
    if (!id) {
        id = cep_namepool_intern_cstr(text);
        munit_assert_uint64(id, !=, 0u);
    }
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = id,
    };
    return dt;
}

static cepCell* mailroom_expect_dictionary(cepCell* parent, const char* tag) {
    munit_assert_not_null(parent);
    munit_assert_true(cep_cell_has_store(parent));

    cepDT name = mailroom_dt_from_text(tag);
    cepCell* node = cep_cell_find_by_name(parent, &name);
    munit_assert_not_null(node);
    munit_assert_true(cep_cell_has_store(node));
    return node;
}

MunitResult test_mailroom(const MunitParameter params[], void* fixture) {
    test_boot_cycle_prepare(params);
    (void)fixture;

    const char* ops_buckets[] = { "ingest", "audit" };

    for (size_t cycle = 0; cycle < 3u; ++cycle) {
        munit_assert_true(cep_l0_bootstrap());
        munit_assert_true(cep_mailroom_bootstrap());

        cepCell* root = cep_root();
        cepCell* data_root = mailroom_expect_dictionary(root, "data");
        cepCell* inbox_root = mailroom_expect_dictionary(data_root, "inbox");
        cepCell* sys_root = mailroom_expect_dictionary(root, "sys");
        cepCell* err_catalog = mailroom_expect_dictionary(sys_root, "err_cat");
        (void)err_catalog;

        cepCell* coh_ns = mailroom_expect_dictionary(inbox_root, "coh");
        mailroom_expect_dictionary(coh_ns, "be_create");
        mailroom_expect_dictionary(coh_ns, "bo_upsert");
        mailroom_expect_dictionary(coh_ns, "ctx_upsert");

        cepCell* flow_ns = mailroom_expect_dictionary(inbox_root, "flow");
        mailroom_expect_dictionary(flow_ns, "fl_upsert");
        mailroom_expect_dictionary(flow_ns, "ni_upsert");
        mailroom_expect_dictionary(flow_ns, "inst_start");
        mailroom_expect_dictionary(flow_ns, "inst_event");
        mailroom_expect_dictionary(flow_ns, "inst_ctrl");

        munit_assert_true(cep_mailroom_add_namespace("ops", ops_buckets, cep_lengthof(ops_buckets)));
        cepCell* ops_ns = mailroom_expect_dictionary(inbox_root, "ops");
        mailroom_expect_dictionary(ops_ns, "ingest");
        mailroom_expect_dictionary(ops_ns, "audit");

        munit_assert_true(cep_mailroom_add_router_before("coh_ing_be"));

        munit_assert_true(cep_l1_coherence_bootstrap());
        mailroom_expect_dictionary(data_root, "coh");

#ifdef CEP_HAS_L2_TESTS
        munit_assert_true(cep_l2_flows_bootstrap());
        mailroom_expect_dictionary(data_root, "flow");
#endif

        if (cycle < 2u) {
            cep_cell_system_shutdown();
        }
    }

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
