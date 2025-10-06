/* Exercise mailroom namespace expansion and routing metadata helpers without
 * relying on the full bootstrap path (which currently asserts when invoked
 * against a bare cell system). */

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
    cepDT dict_type = mailroom_dt_from_text("dictionary");
    cepCell* node = cep_cell_find_by_name(parent, &name);
    if (node) {
        return node;
    }
    node = cep_dict_add_dictionary(parent, &name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(node);
    return node;
}

MunitResult test_mailroom(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
    cep_cell_system_initiate();
    munit_assert_true(cep_namepool_bootstrap());

    cepCell* root = cep_root();
    cepCell* data = mailroom_require_dictionary(root, "data");
    cepCell* inbox = mailroom_require_dictionary(data, "inbox");
    cepCell* sys = mailroom_require_dictionary(root, "sys");
    (void)mailroom_require_dictionary(sys, "err_cat");

    const char* pre_ns_buckets[] = { "ingest", "audit" };
    munit_assert_true(cep_mailroom_add_namespace("ops", pre_ns_buckets, cep_lengthof(pre_ns_buckets)));
    munit_assert_true(cep_mailroom_add_namespace("ops", pre_ns_buckets, cep_lengthof(pre_ns_buckets)));

    cepCell* ops_ns = mailroom_require_dictionary(inbox, "ops");
    mailroom_require_dictionary(ops_ns, "ingest");
    mailroom_require_dictionary(ops_ns, "audit");

    munit_assert_true(cep_mailroom_add_router_before("coh_ing_be"));
    munit_assert_true(cep_mailroom_add_router_before("test_after"));
    munit_assert_true(cep_mailroom_add_router_before("test_after"));

    /* TODO: cover cep_mailroom_register() once the bootstrap helper no longer
     * asserts when it seeds the default namespaces on a completely fresh test
     * fixture. */

    cep_cell_system_shutdown();
    return MUNIT_OK;
}

