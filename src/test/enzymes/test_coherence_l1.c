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

static cepCell* coh_mailroom_request(const char* bucket, const char* txn_word) {
    if (!bucket || !txn_word) {
        return NULL;
    }

    const cepDT* bucket_dt = coh_bucket_dt(bucket);
    if (!bucket_dt) {
        return NULL;
    }

    cepCell* data_root = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    cepCell* inbox_root = data_root ? cep_cell_find_by_name(data_root, CEP_DTAW("CEP", "inbox")) : NULL;
    cepCell* namespace_cell = inbox_root ? cep_cell_find_by_name(inbox_root, CEP_DTAW("CEP", "coh")) : NULL;
    if (!namespace_cell) {
        return NULL;
    }

    cepCell* bucket_cell = cep_cell_find_by_name(namespace_cell, bucket_dt);
    if (!bucket_cell) {
        return NULL;
    }

    cepID txn_tag = cep_text_to_word(txn_word);
    if (!txn_tag) {
        txn_tag = cep_namepool_intern_cstr(txn_word);
    }
    if (!txn_tag) {
        return NULL;
    }

    cepDT txn_dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = txn_tag,
    };
    return cep_cell_find_by_name(bucket_cell, &txn_dt);
}

static const char* coh_request_outcome(cepCell* request) {
    if (!request) {
        return NULL;
    }

    cepCell* outcome = cep_cell_find_by_name(request, CEP_DTAW("CEP", "outcome"));
    if (!outcome || !cep_cell_has_data(outcome)) {
        return NULL;
    }

    const cepData* data = outcome->data;
    if (!data || data->datatype != CEP_DATATYPE_VALUE || data->size == 0u) {
        return NULL;
    }

    return (const char*)data->value;
}

static const char* coh_ledger_outcome(cepCell* ledger_entry) {
    if (!ledger_entry) {
        return NULL;
    }

    cepCell* meta = cep_cell_find_by_name(ledger_entry, CEP_DTAW("CEP", "meta"));
    if (!meta || !cep_cell_has_store(meta)) {
        return NULL;
    }

    cepCell* parents = cep_cell_find_by_name(meta, CEP_DTAW("CEP", "parents"));
    if (!parents || !cep_cell_has_store(parents)) {
        return NULL;
    }

    cepCell* parent_link = cep_cell_first(parents);
    if (!parent_link) {
        return NULL;
    }

    cepCell* request = cep_link_pull(parent_link);
    return coh_request_outcome(request);
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
    munit_assert_true(cep_heartbeat_resolve_agenda());
    munit_assert_true(cep_heartbeat_stage_commit());
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
}

static cepCell* coh_being(const char* being_id) {
    cepCell* ledger = cep_cell_find_by_name(cep_root(), CEP_DTAW("CEP", "data"));
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "coh")) : NULL;
    ledger = ledger ? cep_cell_find_by_name(ledger, CEP_DTAW("CEP", "being")) : NULL;
    if (!ledger) {
        return NULL;
    }
    cepID id = cep_text_to_word(being_id);
    if (!id) {
        id = cep_namepool_intern_cstr(being_id);
    }
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
    cepID id = cep_text_to_word(bond_id);
    if (!id) {
        id = cep_namepool_intern_cstr(bond_id);
    }
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
    cepID id = cep_text_to_word(ctx_id);
    if (!id) {
        id = cep_namepool_intern_cstr(ctx_id);
    }
    cepDT dt = { .domain = CEP_ACRO("CEP"), .tag = id };
    return cep_cell_find_by_name(ledger, &dt);
}

static MunitResult test_coh_ingest_cycle(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    const char* txn_be_a = coh_make_identifier("be", 1u);
    char txn_be_a_buf[64];
    snprintf(txn_be_a_buf, sizeof txn_be_a_buf, "%s", txn_be_a);
    const char* being_id = "being_alpha";
    coh_submit_being(txn_be_a_buf, being_id, "kind_core");
    coh_run_beats(5u);
    munit_assert_null(coh_mailroom_request("be_create", txn_be_a_buf));
    cepCell* ledger_be_a = coh_being(being_id);
    munit_assert_not_null(ledger_be_a);
    const char* ledger_be_a_outcome = coh_ledger_outcome(ledger_be_a);
    munit_assert_not_null(ledger_be_a_outcome);
    munit_assert_string_equal(ledger_be_a_outcome, "ok");

    const char* txn_be_b = coh_make_identifier("be", 2u);
    char txn_be_b_buf[64];
    snprintf(txn_be_b_buf, sizeof txn_be_b_buf, "%s", txn_be_b);
    const char* partner_id = "being_beta";
    coh_submit_being(txn_be_b_buf, partner_id, "kind_core");
    coh_run_beats(5u);
    munit_assert_null(coh_mailroom_request("be_create", txn_be_b_buf));
    cepCell* ledger_be_b = coh_being(partner_id);
    munit_assert_not_null(ledger_be_b);
    const char* ledger_be_b_outcome = coh_ledger_outcome(ledger_be_b);
    munit_assert_not_null(ledger_be_b_outcome);
    munit_assert_string_equal(ledger_be_b_outcome, "ok");

    cepCell* src_be = coh_being(being_id);
    cepCell* dst_be = coh_being(partner_id);
    munit_assert_not_null(src_be);
    munit_assert_not_null(dst_be);

    const char* bond_id = "bond-sync";
    const char* txn_bo = coh_make_identifier("bo", 1u);
    char txn_bo_buf[64];
    snprintf(txn_bo_buf, sizeof txn_bo_buf, "%s", txn_bo);
    coh_submit_bond(txn_bo_buf, bond_id, "type_peer", src_be, dst_be, false);
    coh_run_beats(5u);
    munit_assert_null(coh_mailroom_request("bo_upsert", txn_bo_buf));
    cepCell* ledger_bond = coh_bond(bond_id);
    munit_assert_not_null(ledger_bond);
    const char* ledger_bond_outcome = coh_ledger_outcome(ledger_bond);
    munit_assert_not_null(ledger_bond_outcome);
    munit_assert_string_equal(ledger_bond_outcome, "ok");

    const char* txn_ctx = coh_make_identifier("ctx", 1u);
    char txn_ctx_buf[64];
    snprintf(txn_ctx_buf, sizeof txn_ctx_buf, "%s", txn_ctx);
    const char* ctx_id = "ctx_sync";
    coh_submit_context(txn_ctx_buf, ctx_id, "session");
    coh_run_beats(5u);
    munit_assert_null(coh_mailroom_request("ctx_upsert", txn_ctx_buf));
    cepCell* ledger_ctx = coh_context(ctx_id);
    munit_assert_not_null(ledger_ctx);
    const char* ledger_ctx_outcome = coh_ledger_outcome(ledger_ctx);
    munit_assert_not_null(ledger_ctx_outcome);
    munit_assert_string_equal(ledger_ctx_outcome, "ok");

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

/* Smoke test that exercises bootstrap without submitting intents so we can
 * confirm the mailroom/L1 stacks coordinate cleanly through a few beats. The
 * focus stays on the startup contract: run a handful of beats and ensure the
 * L1 roots remain accessible before teardown resets the fixture. */
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
