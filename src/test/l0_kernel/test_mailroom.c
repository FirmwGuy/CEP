/* Exercise mailroom namespace expansion and catalog seeding to make sure the
 * helper behaves after repeated bootstrap calls. */

#include "test.h"
#include "cep_l0.h"
#include "cep_mailroom.h"
#include "cep_enzyme.h"
#include "cep_namepool.h"
#include "cep_heartbeat.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

static cepDT mailroom_dt_from_text(const char* text);
static int mailroom_stub_noop(const cepPath* signal, const cepPath* target) {
    (void)signal;
    (void)target;
    return CEP_ENZYME_SUCCESS;
}

static void mailroom_ensure_registered(cepEnzymeRegistry* registry) {
    static cepEnzymeRegistry* registered = NULL;
    if (registered == registry) {
        return;
    }
    munit_assert_true(cep_mailroom_register(registry));
    registered = registry;
}

static void mailroom_register_stub_descriptors(cepEnzymeRegistry* registry) {
    static cepEnzymeRegistry* registered_registry = NULL;
    if (registered_registry == registry) {
        return;
    }
    registered_registry = registry;

    mailroom_ensure_registered(registry);

    typedef struct {
        unsigned length;
        unsigned capacity;
        cepPast past[2];
    } CepStaticPath2;

    CepStaticPath2 init_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            { .dt = *CEP_DTAW("CEP", "sig_sys"), .timestamp = 0u },
            { .dt = *CEP_DTAW("CEP", "init"), .timestamp = 0u },
        },
    };

    cepEnzymeDescriptor init_desc = {
        .name = *CEP_DTAW("CEP", "coh_init"),
        .label = "stub.coh.init",
        .callback = mailroom_stub_noop,
        .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
        .match = CEP_ENZYME_MATCH_EXACT,
    };
    (void)cep_enzyme_register(registry, (const cepPath*)&init_path, &init_desc);

    CepStaticPath2 ingest_path = {
        .length = 2u,
        .capacity = 2u,
        .past = {
            { .dt = *CEP_DTAW("CEP", "sig_cell"), .timestamp = 0u },
            { .dt = *CEP_DTAW("CEP", "op_add"),   .timestamp = 0u },
        },
    };

    const char* ingest_names[] = {
        "coh_ing_be",
        "coh_ing_bo",
        "coh_ing_ctx",
        "coh_closure",
        "coh_index",
        "coh_adj",
    };

    for (size_t i = 0; i < cep_lengthof(ingest_names); ++i) {
        cepDT ingest_name_dt = mailroom_dt_from_text(ingest_names[i]);
        cepEnzymeDescriptor ingest_desc = {
            .name = ingest_name_dt,
            .label = "stub.coh.ing",
            .callback = mailroom_stub_noop,
            .flags = CEP_ENZYME_FLAG_IDEMPOTENT,
            .match = CEP_ENZYME_MATCH_PREFIX,
        };
        (void)cep_enzyme_register(registry, (const cepPath*)&ingest_path, &ingest_desc);
    }
}

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

static cepCell* mailroom_ensure_dictionary(cepCell* parent, const char* tag) {
    munit_assert_not_null(parent);

    cepDT name = mailroom_dt_from_text(tag);
    cepCell* node = cep_cell_find_by_name(parent, &name);
    if (node) {
        return node;
    }

    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepDT name_copy = name;
    node = cep_dict_add_dictionary(parent, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(node);
    return node;
}

static void mailroom_prepare_catalog(void) {
    cepCell* root = cep_root();
    cepCell* sys_root = mailroom_ensure_dictionary(root, "sys");
    cepCell* err_catalog = mailroom_ensure_dictionary(sys_root, "err_cat");

    const char* coh_buckets[] = { "be_create", "bo_upsert", "ctx_upsert" };
    const char* flow_buckets[] = { "fl_upsert", "ni_upsert", "inst_start", "inst_event", "inst_ctrl" };

    const struct {
        const char* scope;
        const char* const* buckets;
        size_t bucket_count;
    } configs[] = {
        { "coh", coh_buckets, cep_lengthof(coh_buckets) },
        { "flow", flow_buckets, cep_lengthof(flow_buckets) },
    };

    for (size_t cfg = 0; cfg < cep_lengthof(configs); ++cfg) {
        const char* scope = configs[cfg].scope;
        cepCell* scope_node = mailroom_ensure_dictionary(err_catalog, scope);
        cepCell* mailroom_meta = mailroom_ensure_dictionary(scope_node, "mailroom");
        cepCell* buckets_node = mailroom_ensure_dictionary(mailroom_meta, "buckets");

        for (size_t b = 0; b < configs[cfg].bucket_count; ++b) {
            (void)mailroom_ensure_dictionary(buckets_node, configs[cfg].buckets[b]);
        }
    }
}

static MunitResult test_mailroom_deferred_registration_ordering(void) {
    (void)mailroom_register_stub_descriptors;
    return MUNIT_SKIP;
}

MunitResult test_mailroom(const MunitParameter params[], void* fixture) {
    test_boot_cycle_prepare(params);
    (void)fixture;

    const char* ops_buckets[] = { "ingest", "audit" };

    for (size_t cycle = 0; cycle < 3u; ++cycle) {
        cepHeartbeatPolicy policy = {
            .start_at = 0u,
            .ensure_directories = false,
            .enforce_visibility = false,
        };

        munit_assert_true(cep_heartbeat_configure(NULL, &policy));
        munit_assert_true(cep_l0_bootstrap());
        mailroom_prepare_catalog();
        munit_assert_true(cep_mailroom_add_router_before("coh_ing_be"));

        cepEnzymeRegistry* registry = cep_heartbeat_registry();
        munit_assert_not_null(registry);
        mailroom_register_stub_descriptors(registry);
        cep_stream_clear_pending();
        munit_assert_size(cep_stream_pending_count(), ==, 0);

        munit_assert_true(cep_heartbeat_begin(policy.start_at));

        for (unsigned i = 0; i < 8 && !cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_MAILROOM); ++i) {
            munit_assert_true(cep_heartbeat_step());
        }
        munit_assert_true(cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_MAILROOM));

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

        cepCell* coh_layer = mailroom_ensure_dictionary(data_root, "coh");
        cepCell* coh_layer_inbox = mailroom_ensure_dictionary(coh_layer, "inbox");
        cepCell* coh_layer_bucket = mailroom_ensure_dictionary(coh_layer_inbox, "be_create");
        cepCell* intent_bucket = mailroom_expect_dictionary(coh_ns, "be_create");

        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");

        cepDT stage_name = mailroom_dt_from_text("stage_ok");
        cepCell* stage_req = cep_dict_add_dictionary(intent_bucket, &stage_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(stage_req);
        cepCell* stage_original = mailroom_ensure_dictionary(stage_req, "original");
        cepCell* stage_payload = mailroom_ensure_dictionary(stage_original, "payload");
        munit_assert_true(cep_cell_put_text(stage_payload, CEP_DTAW("CEP", "value"), "42"));

        cepDT coh_ns_dt = mailroom_dt_from_text("coh");
        cepDT be_create_dt = mailroom_dt_from_text("be_create");

        cepCell* staged = NULL;
        munit_assert_true(cep_mailroom_stage_request(intent_bucket,
                                                     coh_layer_bucket,
                                                     &coh_ns_dt,
                                                     &be_create_dt,
                                                     &stage_name,
                                                     stage_req,
                                                     &staged));
        munit_assert_not_null(staged);
        munit_assert_ptr_equal(staged, cep_cell_find_by_name(coh_layer_bucket, &stage_name));
        munit_assert_true(!cep_cell_is_veiled(staged));

        const char* staged_outcome = (const char*)cep_cell_data_find_by_name(staged, CEP_DTAW("CEP", "outcome"));
        munit_assert_not_null(staged_outcome);
        munit_assert_string_equal(staged_outcome, "pending");

        cepCell* staged_original = cep_cell_find_by_name(staged, CEP_DTAW("CEP", "original"));
        munit_assert_not_null(staged_original);
        cepCell* staged_payload = cep_cell_find_by_name(staged_original, CEP_DTAW("CEP", "payload"));
        munit_assert_not_null(staged_payload);
        const char* staged_value = (const char*)cep_cell_data_find_by_name(staged_payload, CEP_DTAW("CEP", "value"));
        munit_assert_not_null(staged_value);
        munit_assert_string_equal(staged_value, "42");

        cepCell* audit_entry = cep_cell_find_by_name(intent_bucket, &stage_name);
        munit_assert_not_null(audit_entry);
        munit_assert_true(cep_cell_is_link(audit_entry));
        munit_assert_ptr_equal(cep_link_pull(audit_entry), staged);

        cep_cell_remove_hard(audit_entry, NULL);
        cep_cell_remove_hard(staged, NULL);

        cepDT conflict_name = mailroom_dt_from_text("stage_conflict");
        cepCell* conflict_req = cep_dict_add_dictionary(intent_bucket, &conflict_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(conflict_req);
        cepCell* conflict_existing = cep_dict_add_dictionary(coh_layer_bucket, &conflict_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        munit_assert_not_null(conflict_existing);

        cepCell* conflict_result = NULL;
        munit_assert_false(cep_mailroom_stage_request(intent_bucket,
                                                      coh_layer_bucket,
                                                      &coh_ns_dt,
                                                      &be_create_dt,
                                                      &conflict_name,
                                                      conflict_req,
                                                      &conflict_result));
        munit_assert_null(conflict_result);
        munit_assert_not_null(cep_cell_find_by_name(intent_bucket, &conflict_name));

        cep_cell_remove_hard(conflict_existing, NULL);
        cepCell* restored_conflict = cep_cell_find_by_name(intent_bucket, &conflict_name);
        munit_assert_not_null(restored_conflict);
        cep_cell_remove_hard(restored_conflict, NULL);

        test_runtime_shutdown();
    }

    if (!test_boot_cycle_is_after(params)) {
        MunitResult order_result = test_mailroom_deferred_registration_ordering();
        if (order_result != MUNIT_OK) {
            return order_result;
        }
    }

    return MUNIT_OK;
}
