/* Exercise mailroom namespace expansion and catalog seeding to make sure the
 * helper behaves after repeated bootstrap calls. */

#include "test.h"
#include "cep_l0.h"
#include "cep_mailroom.h"
#include "cep_enzyme.h"
#include "cep_namepool.h"
#include "cep_heartbeat.h"
#include "cep_l1_coherence.h"
#include "cep_l2_flows.h"

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
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = false,
        .enforce_visibility = false,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());

    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    munit_assert_true(cep_mailroom_register(registry));
    munit_assert_true(cep_l1_coherence_register(registry));

    cep_enzyme_registry_activate_pending(registry);

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

    cepImpulse impulse = {
        .signal_path = (const cepPath*)&init_path,
        .target_path = NULL,
    };

    const cepEnzymeDescriptor* ordered[16] = {0};
    size_t resolved = cep_enzyme_resolve(registry, &impulse, ordered, cep_lengthof(ordered));
    munit_assert_size(resolved, >, 0u);

    size_t idx_mr_init = SIZE_MAX;
    size_t idx_coh_init = SIZE_MAX;
    for (size_t i = 0; i < resolved; ++i) {
        const cepEnzymeDescriptor* descriptor = ordered[i];
        if (!descriptor) {
            continue;
        }
        if (cep_dt_compare(&descriptor->name, CEP_DTAW("CEP", "mr_init")) == 0) {
            idx_mr_init = i;
        } else if (cep_dt_compare(&descriptor->name, CEP_DTAW("CEP", "coh_init")) == 0) {
            idx_coh_init = i;
        }
    }

    munit_assert_size(idx_mr_init, !=, SIZE_MAX);
    munit_assert_size(idx_coh_init, !=, SIZE_MAX);
    munit_assert_true(idx_mr_init < idx_coh_init);

    cep_enzyme_registry_destroy(registry);

    cepEnzymeRegistry* second = cep_enzyme_registry_create();
    munit_assert_not_null(second);
    munit_assert_true(cep_mailroom_register(second));
    munit_assert_true(cep_mailroom_register(second));
    cep_enzyme_registry_destroy(second);
    test_runtime_shutdown();
    return MUNIT_OK;
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
        munit_assert_true(cep_l1_coherence_register(registry));
        munit_assert_true(cep_l2_flows_register(registry));

        cep_stream_clear_pending();
        munit_assert_size(cep_stream_pending_count(), ==, 0);

        munit_assert_true(cep_heartbeat_begin(policy.start_at));

        bool l1_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L1);
        bool l2_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L2);
        bool step_failed = false;
        for (unsigned i = 0; i < 8 && (!l1_ready || !l2_ready); ++i) {
            if (!cep_heartbeat_step()) {
                step_failed = true;
                break;
            }
            l1_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L1);
            l2_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L2);
        }
        if (step_failed) {
            munit_assert_size(cep_stream_pending_count(), ==, 0);
        }
        if (!l1_ready) {
            munit_assert_true(cep_l1_coherence_bootstrap());
            l1_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L1);
        }
        if (!l2_ready) {
            munit_assert_true(cep_l2_flows_bootstrap());
            l2_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L2);
        }
        munit_assert_true(l1_ready);
        munit_assert_true(l2_ready);
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
