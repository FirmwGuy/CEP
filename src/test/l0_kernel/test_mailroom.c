/* Exercise mailroom namespace expansion and catalog seeding to make sure the
 * helper behaves after repeated bootstrap calls. */

#include "test.h"
#include "cep_mailroom.h"
#include "cep_enzyme.h"
#include "cep_namepool.h"

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

static cepCell* mailroom_require_dictionary(cepCell* parent, const char* tag) {
    cepDT name = mailroom_dt_from_text(tag);
    cepCell* node = cep_cell_find_by_name(parent, &name);
    if (!node) {
        cepDT dict_type = mailroom_dt_from_text("dictionary");
        node = cep_dict_add_dictionary(parent, &name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    }
    munit_assert_not_null(node);
    return node;
}

static void mailroom_reset_system(void) {
    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
    cep_cell_system_initiate();
    munit_assert_true(cep_namepool_bootstrap());
}

MunitResult test_mailroom(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    mailroom_reset_system();

    cepCell* root = cep_root();
    cepCell* data_root = mailroom_require_dictionary(root, "data");
    cepCell* inbox_root = mailroom_require_dictionary(data_root, "inbox");
    cepCell* sys_root = mailroom_require_dictionary(root, "sys");
    cepCell* err_catalog = mailroom_require_dictionary(sys_root, "err_cat");
    munit_assert_not_null(err_catalog);
    munit_assert_true(cep_cell_has_store(err_catalog));

    /* Namespace helper should be idempotent. */
    const char* pre_ns_buckets[] = { "ingest", "audit" };
    munit_assert_true(cep_mailroom_add_namespace("ops", pre_ns_buckets, cep_lengthof(pre_ns_buckets)));
    munit_assert_true(cep_mailroom_add_namespace("ops", pre_ns_buckets, cep_lengthof(pre_ns_buckets)));

    cepCell* ops_ns = mailroom_require_dictionary(inbox_root, "ops");
    mailroom_require_dictionary(ops_ns, "ingest");
    mailroom_require_dictionary(ops_ns, "audit");

    /* Router-before helper tolerates duplicates. */
    munit_assert_true(cep_mailroom_add_router_before("coh_ing_be"));
    munit_assert_true(cep_mailroom_add_router_before("coh_ing_be"));

    cep_cell_system_shutdown();
    return MUNIT_OK;
}
