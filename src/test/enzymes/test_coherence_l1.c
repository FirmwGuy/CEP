/* Layer 1 coherence tests stage the mailroom and heartbeat to exercise ingest,
 * ledger maintenance, and the shutdown hook that clears adjacency mirrors. The
 * suite feeds real intents through the helpers so we observe agenda ordering
 * and lifecycle signals exactly as production would. */

#include "test.h"

#include "cep_cell.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_mailroom.h"
#include "cep_l0.h"
#include "cep_l1_coherence.h"
#include "cep_namepool.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool initialized;
} CohFixture;

static cepCell* coh_require_inbox_bucket(const char* bucket_name) {
    cepCell* data = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    if (!data) {
        return NULL;
    }
    cepCell* coh = cep_cell_find_by_name(data, CEP_DTAW("CEP", "coh"));
    if (!coh) {
        return NULL;
    }
    cepCell* inbox = cep_cell_find_by_name(coh, CEP_DTAW("CEP", "inbox"));
    if (!inbox) {
        inbox = cep_dict_add_dictionary(coh, CEP_DTAW("CEP", "inbox"), CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
        if (!inbox) {
            return NULL;
        }
    }
    cepDT name_dt = cep_dt_make(CEP_ACRO("CEP"), cep_text_to_word(bucket_name));
    cepCell* bucket = cep_cell_find_by_name(inbox, &name_dt);
    if (!bucket) {
        bucket = cep_dict_add_dictionary(inbox, &name_dt, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    }
    return bucket;
}

static const char* coh_make_identifier(const char* prefix, unsigned value) {
    static char buffer[64];
    char suffix[32];
    size_t idx = 0u;
    unsigned n = value;
    do {
        unsigned digit = n % 26u;
        suffix[idx++] = (char)('a' + digit);
        n /= 26u;
    } while (n > 0u && idx < cep_lengthof(suffix) - 1u);
    suffix[idx] = '\0';
    for (size_t i = 0u; i < idx / 2u; ++i) {
        char tmp = suffix[i];
        suffix[i] = suffix[idx - 1u - i];
        suffix[idx - 1u - i] = tmp;
    }
    snprintf(buffer, sizeof buffer, "%s_%s", prefix, suffix);
    return buffer;
}

static void coh_seed_namespace(void) {
    static const char* buckets[] = {
        "be_create",
        "bo_upsert",
        "ctx_upsert",
    };
    munit_assert_true(cep_mailroom_add_namespace("coh", buckets, cep_lengthof(buckets)));
}

static cepCell* coh_adj_by_being_root(void) {
    cepCell* tmp = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "tmp"));
    if (!tmp) {
        return NULL;
    }

    cepCell* coh_tmp = cep_cell_find_by_name(tmp, CEP_DTAW("CEP", "coh"));
    if (!coh_tmp) {
        return NULL;
    }

    cepCell* adj = cep_cell_find_by_name(coh_tmp, CEP_DTAW("CEP", "adj"));
    if (!adj) {
        return NULL;
    }

    return cep_cell_find_by_name(adj, CEP_DTAW("CEP", "by_being"));
}

static bool coh_set_string_value(cepCell* parent, const cepDT* field, const char* text) {
    if (!parent || !field || !text) {
        return false;
    }

    size_t len = strlen(text) + 1u;
    cepDT text_type = *CEP_DTAW("CEP", "text");
    cepDT name_copy = *field;

    cepCell* existing = cep_cell_find_by_name(parent, field);
    if (existing && cep_cell_has_data(existing) && existing->data->capacity >= len) {
        memcpy(existing->data->value, text, len);
        existing->data->size = len;
        return true;
    }

    if (existing) {
        cep_cell_remove_hard(existing, NULL);
    }

    return cep_dict_add_value(parent, &name_copy, &text_type, (void*)text, len, len) != NULL;
}

static bool coh_ensure_shared_header(cepCell* request) {
    if (!request) {
        return false;
    }

    bool ok = true;

    cepCell* original = cep_cell_find_by_name(request, CEP_DTAW("CEP", "original"));
    if (!original) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT name_copy = *CEP_DTAW("CEP", "original");
        original = cep_dict_add_dictionary(request, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        ok = ok && (original != NULL);
    }

    cepCell* outcome = cep_cell_find_by_name(request, CEP_DTAW("CEP", "outcome"));
    if (!outcome || !cep_cell_has_data(outcome)) {
        ok = ok && coh_set_string_value(request, CEP_DTAW("CEP", "outcome"), "pending");
    }

    cepCell* meta = cep_cell_find_by_name(request, CEP_DTAW("CEP", "meta"));
    if (!meta) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT meta_name = *CEP_DTAW("CEP", "meta");
        meta = cep_dict_add_dictionary(request, &meta_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        ok = ok && (meta != NULL);
    }

    if (meta) {
        cepCell* parents = cep_cell_find_by_name(meta, CEP_DTAW("CEP", "parents"));
        if (!parents) {
            cepDT list_type = *CEP_DTAW("CEP", "list");
            cepDT parent_name = *CEP_DTAW("CEP", "parents");
            parents = cep_dict_add_list(meta, &parent_name, &list_type, CEP_STORAGE_LINKED_LIST);
            ok = ok && (parents != NULL);
        }
    }

    return ok;
}

static const cepDT* coh_bucket_dt(const char* bucket) {
    if (!bucket) {
        return NULL;
    }

    if (strcmp(bucket, "be_create") == 0) {
        return CEP_DTAW("CEP", "be_create");
    }
    if (strcmp(bucket, "bo_upsert") == 0) {
        return CEP_DTAW("CEP", "bo_upsert");
    }
    if (strcmp(bucket, "ctx_upsert") == 0) {
        return CEP_DTAW("CEP", "ctx_upsert");
    }
    return NULL;
}

static cepCell* coh_layer_bucket(const char* bucket) {
    const cepDT* bucket_dt = coh_bucket_dt(bucket);
    if (!bucket_dt) {
        munit_logf(MUNIT_LOG_ERROR, "coh_layer_bucket unknown bucket %s", bucket ? bucket : "<null>");
        return NULL;
    }

    cepCell* data_root = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    if (!data_root) {
        munit_log(MUNIT_LOG_ERROR, "coh_layer_bucket missing /data");
        return NULL;
    }

    cepCell* coh_root = cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "coh"));
    if (!coh_root) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT name_copy = *CEP_DTAW("CEP", "coh");
        coh_root = cep_dict_add_dictionary(data_root, &name_copy, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!coh_root) {
            munit_log(MUNIT_LOG_ERROR, "coh_layer_bucket failed to create /data/coh");
            return NULL;
        }
    }

    cepCell* inbox_root = cep_cell_find_by_name(coh_root, CEP_DTAW("CEP", "inbox"));
    if (!inbox_root) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT inbox_name = *CEP_DTAW("CEP", "inbox");
        inbox_root = cep_dict_add_dictionary(coh_root, &inbox_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!inbox_root) {
            munit_log(MUNIT_LOG_ERROR, "coh_layer_bucket failed to create /data/coh/inbox");
            return NULL;
        }
    }

    cepCell* bucket_cell = cep_cell_find_by_name(inbox_root, bucket_dt);
    if (!bucket_cell) {
        cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
        cepDT bucket_name = *bucket_dt;
        bucket_cell = cep_dict_add_dictionary(inbox_root, &bucket_name, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!bucket_cell) {
            munit_logf(MUNIT_LOG_ERROR, "coh_layer_bucket failed to create bucket %s", bucket);
        }
    }
    return bucket_cell;
}

static cepCell* coh_move_request_to_layer(cepCell* request, const char* bucket) {
    if (!request || !bucket) {
        return NULL;
    }

    const cepDT* txn_name_dt = cep_cell_get_name(request);
    if (!txn_name_dt) {
        return NULL;
    }

    cepCell* dest_bucket = coh_layer_bucket(bucket);
    if (!dest_bucket) {
        munit_logf(MUNIT_LOG_ERROR, "coh_move_request_to_layer missing bucket %s", bucket);
        return NULL;
    }

    if (cep_cell_find_by_name(dest_bucket, txn_name_dt)) {
        cep_cell_remove_hard(request, NULL);
        return cep_cell_find_by_name(dest_bucket, txn_name_dt);
    }

    cepCell moved = {0};
    cep_cell_remove_hard(request, &moved);
    cepCell* inserted = cep_cell_add(dest_bucket, 0u, &moved);
    if (!inserted) {
        munit_logf(MUNIT_LOG_ERROR, "coh_move_request_to_layer insert failed bucket %s", bucket);
        cep_cell_finalize_hard(&moved);
        return NULL;
    }

    if (!coh_ensure_shared_header(inserted)) {
        munit_logf(MUNIT_LOG_ERROR, "coh_move_request_to_layer header failed bucket %s", bucket);
        return NULL;
    }

    return inserted;
}

/* Spin up a fresh heartbeat with the mailroom and Layer 1 packs so tests can
 * enqueue intents and observe teardown behaviour exactly like the runtime
 * would. The helper boots the kernel, registers the enzyme packs, waits for the
 * readiness pulses, and returns a fixture that tracks whether teardown is
 * required. */
void* coh_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    CohFixture* fixture = munit_malloc(sizeof *fixture);
    fixture->initialized = false;

    if (cep_cell_system_initialized()) {
        cep_cell_system_shutdown();
    }
    cep_cell_system_initiate();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
    };
    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_l0_bootstrap());

    coh_seed_namespace();

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_true(cep_mailroom_register(registry));
    munit_assert_true(cep_l1_coherence_register(registry));

    munit_assert_true(cep_heartbeat_begin(policy.start_at));

    bool mailroom_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_MAILROOM);
    bool l1_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L1);
    for (unsigned attempt = 0u; (!mailroom_ready || !l1_ready) && attempt < 8u; ++attempt) {
        munit_assert_true(cep_heartbeat_step());
        mailroom_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_MAILROOM);
        l1_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L1);
    }
    if (!mailroom_ready) {
        munit_assert_true(cep_mailroom_bootstrap());
        mailroom_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_MAILROOM);
    }
    if (!l1_ready) {
        munit_assert_true(cep_l1_coherence_bootstrap());
        l1_ready = cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_L1);
    }
    munit_assert_true(mailroom_ready);
    munit_assert_true(l1_ready);

    fixture->initialized = true;
    return fixture;
}

/* Release heartbeat state between tests so adjacency mirrors and lifecycle
 * caches return to a known baseline. Teardown emits the shutdown pulse, drives
 * the heartbeat cleanup, and frees the fixture. */
void coh_teardown(void* fixture_ptr) {
    CohFixture* fixture = fixture_ptr;
    if (fixture && fixture->initialized) {
        cep_l1_coherence_shutdown();
        test_runtime_shutdown();
        fixture->initialized = false;
    }
    free(fixture);
}

static void coh_run_single_beat(void) {
    munit_assert_true(cep_heartbeat_step());
}

static void coh_run_beats(unsigned count) {
    for (unsigned i = 0u; i < count; ++i) {
        coh_run_single_beat();
    }
}

static void coh_submit_being(const char* txn_id, const char* being_id, const char* kind) {
    munit_assert_not_null(coh_require_inbox_bucket("be_create"));

    const char* id_parts[] = { being_id };
    const char* kind_parts[] = { kind };

    cepL1BeingIntent intent = {0};
    munit_assert_true(cep_l1_being_intent_init(&intent,
                                               txn_id,
                                               id_parts,
                                               1u,
                                               kind_parts,
                                               1u));
    munit_assert_not_null(coh_move_request_to_layer(intent.request, "be_create"));
}

static void coh_submit_bond(const char* txn_id,
                            const char* bond_id,
                            const char* type,
                            cepCell* src,
                            cepCell* dst,
                            bool directed) {
    munit_assert_not_null(coh_require_inbox_bucket("bo_upsert"));

    const char* id_parts[] = { bond_id };
    const char* type_parts[] = { type };

    cepL1BondIntent intent = {0};
    munit_assert_true(cep_l1_bond_intent_init(&intent,
                                              txn_id,
                                              id_parts,
                                              1u,
                                              type_parts,
                                              1u,
                                              src,
                                              dst,
                                              directed));
    munit_assert_not_null(coh_move_request_to_layer(intent.request, "bo_upsert"));
}

static void coh_submit_context(const char* txn_id,
                               const char* ctx_id,
                               const char* ctx_type) {
    munit_assert_not_null(coh_require_inbox_bucket("ctx_upsert"));

    const char* id_parts[] = { ctx_id };
    const char* type_parts[] = { ctx_type };

    cepL1ContextIntent intent = {0};
    munit_assert_true(cep_l1_context_intent_init(&intent,
                                                 txn_id,
                                                 id_parts,
                                                 1u,
                                                 type_parts,
                                                 1u));
    munit_assert_not_null(coh_move_request_to_layer(intent.request, "ctx_upsert"));
}

static cepCell* coh_being(const char* being_id) {
    cepCell* ledger = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "coh")) : NULL;
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "being")) : NULL;
    if (!ledger) {
        return NULL;
    }
    cepID id = cep_namepool_intern_cstr(being_id);
    cepDT dt = { .domain = CEP_ACRO("CEP"), .tag = id };
    return cep_cell_find_by_name(ledger, &dt);
}

static cepCell* coh_bond(const char* bond_id) {
    cepCell* ledger = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "coh")) : NULL;
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "bond")) : NULL;
    if (!ledger) {
        return NULL;
    }
    cepID id = cep_namepool_intern_cstr(bond_id);
    cepDT dt = { .domain = CEP_ACRO("CEP"), .tag = id };
    return cep_cell_find_by_name(ledger, &dt);
}

static cepCell* coh_context(const char* ctx_id) {
    cepCell* ledger = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "coh")) : NULL;
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "context")) : NULL;
    if (!ledger) {
        return NULL;
    }
    cepID id = cep_namepool_intern_cstr(ctx_id);
    cepDT dt = { .domain = CEP_ACRO("CEP"), .tag = id };
    return cep_cell_find_by_name(ledger, &dt);
}

static MunitResult test_coh_ingest_cycle(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    const char* txn_be_a = coh_make_identifier("be", 1u);
    const char* being_id = "being_alpha";
    coh_submit_being(txn_be_a, being_id, "kind_core");
    coh_run_beats(5u);
    munit_assert_not_null(coh_being(being_id));

    const char* txn_be_b = coh_make_identifier("be", 2u);
    const char* partner_id = "being_beta";
    coh_submit_being(txn_be_b, partner_id, "kind_core");
    coh_run_beats(5u);

    cepCell* src_be = coh_being(being_id);
    cepCell* dst_be = coh_being(partner_id);
    munit_assert_not_null(src_be);
    munit_assert_not_null(dst_be);

    const char* bond_id = "bond-sync";
    const char* txn_bo = coh_make_identifier("bo", 1u);
    coh_submit_bond(txn_bo, bond_id, "type_peer", src_be, dst_be, false);
    coh_run_beats(5u);
    munit_assert_not_null(coh_bond(bond_id));

    const char* txn_ctx = coh_make_identifier("ctx", 1u);
    const char* ctx_id = "ctx_sync";
    coh_submit_context(txn_ctx, ctx_id, "session");
    coh_run_beats(5u);
    munit_assert_not_null(coh_context(ctx_id));

    return MUNIT_OK;
}

/* Confirm that the explicit shutdown helper drops adjacency mirrors so
 * successive bootstraps never inherit stale neighbourhood snapshots. */
static MunitResult test_coh_shutdown_clears_adj(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    CohFixture* fixture = fixture_ptr;
    if (!fixture || !fixture->initialized) {
        return MUNIT_SKIP;
    }

    const char* txn_be_a = coh_make_identifier("be", 10u);
    const char* being_a = "being_gamma";
    coh_submit_being(txn_be_a, being_a, "kind_core");
    coh_run_beats(5u);

    const char* txn_be_b = coh_make_identifier("be", 11u);
    const char* being_b = "being_delta";
    coh_submit_being(txn_be_b, being_b, "kind_core");
    coh_run_beats(5u);

    cepCell* src_be = coh_being(being_a);
    cepCell* dst_be = coh_being(being_b);
    munit_assert_not_null(src_be);
    munit_assert_not_null(dst_be);

    const char* txn_bo = coh_make_identifier("bo", 10u);
    coh_submit_bond(txn_bo, "bond-link", "type_peer", src_be, dst_be, false);
    coh_run_beats(5u);

    cepCell* adj_by_being = coh_adj_by_being_root();
    munit_assert_not_null(adj_by_being);
    munit_assert_true(cep_cell_has_store(adj_by_being));
    munit_assert_not_null(cep_cell_first(adj_by_being));

    cep_l1_coherence_shutdown();

    adj_by_being = coh_adj_by_being_root();
    munit_assert_not_null(adj_by_being);
    if (cep_cell_has_store(adj_by_being)) {
        munit_assert_null(cep_cell_first(adj_by_being));
    }

    test_runtime_shutdown();
    fixture->initialized = false;
    return MUNIT_OK;
}

static MunitTest coherence_tests[] = {
    {
        "/coherence/ingest_cycle",
        test_coh_ingest_cycle,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/shutdown_clears_adj",
        test_coh_shutdown_clears_adj,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite coherence_suite = {
    "/CEP",
    coherence_tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[]) {
    return munit_suite_main(&coherence_suite, NULL, argc, argv);
}
