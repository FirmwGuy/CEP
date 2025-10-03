/* Acceptance tests for the CEP Layer 1 coherence enzymes ensure the public
 * contract stays wired: we spin up a fresh heartbeat, drive intents through the
 * inbox, and assert the resulting ledgers, debts, mirrors, and beat agendas.
 * Each test builds real ledger state so regressions surface as behaviour
 * changes instead of silent drift. */

#include "test.h"

#include "cep_cell.h"
#include "cep_enzyme.h"
#include "cep_heartbeat.h"
#include "cep_l1_coherence.h"
#include "cep_namepool.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    bool initialized;
} CohFixture;

static cepDT dt_word_from(const char* tag) {
    cepID word = cep_text_to_word(tag);
    munit_assert_uint64(word, !=, 0);
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = word,
    };
    return dt;
}

static cepCell* coh_find_mandatory(cepCell* parent, const cepDT* name) {
    cepCell* cell = cep_cell_find_by_name(parent, name);
    munit_assert_not_null(cell);
    return cell;
}

static cepCell* coh_require_inbox_bucket(const char* bucket) {
    cepCell* data = coh_find_mandatory(cep_root(), CEP_DTAW("CEP", "data"));
    cepCell* coh = coh_find_mandatory(data, CEP_DTAW("CEP", "coh"));
    cepCell* inbox = coh_find_mandatory(coh, CEP_DTAW("CEP", "inbox"));
    cepDT bucket_dt = dt_word_from(bucket);
    return coh_find_mandatory(inbox, &bucket_dt);
}

static cepCell* coh_ledger(const char* ledger) {
    cepCell* data = coh_find_mandatory(cep_root(), CEP_DTAW("CEP", "data"));
    cepCell* coh = coh_find_mandatory(data, CEP_DTAW("CEP", "coh"));
    cepDT ledger_dt = dt_word_from(ledger);
    return coh_find_mandatory(coh, &ledger_dt);
}

static cepCell* coh_debt_root(void) {
    return coh_ledger("debt");
}

static cepCell* coh_append_dictionary(cepCell* parent, const cepDT* name) {
    cepCell* existing = cep_cell_find_by_name(parent, name);
    if (existing) {
        return existing;
    }
    cepDT dict_type = *CEP_DTAW("CEP", "dictionary");
    cepCell* dict = cep_dict_add_dictionary(parent, (cepDT*)name, &dict_type, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(dict);
    return dict;
}

static cepCell* coh_set_string_field(cepCell* parent, const char* name, const char* text) {
    cepDT name_dt = dt_word_from(name);
    cepDT text_dt = *CEP_DTAW("CEP", "text");
    size_t size = strlen(text) + 1u;
    cepCell* cell = cep_dict_add_value(parent, &name_dt, &text_dt, (void*)text, size, size);
    munit_assert_not_null(cell);
    return cell;
}

static cepCell* coh_set_bool_field(cepCell* parent, const char* name, bool flag) {
    cepDT name_dt = dt_word_from(name);
    cepDT text_dt = *CEP_DTAW("CEP", "text");
    uint8_t payload = flag ? 1u : 0u;
    cepCell* cell = cep_dict_add_value(parent, &name_dt, &text_dt, &payload, sizeof payload, sizeof payload);
    munit_assert_not_null(cell);
    return cell;
}

static cepCell* coh_add_link_field(cepCell* parent, const char* name, cepCell* target) {
    cepDT name_dt = dt_word_from(name);
    cepCell* link = cep_dict_add_link(parent, &name_dt, target);
    munit_assert_not_null(link);
    return link;
}

static void coh_run_single_beat(void) {
    munit_assert_true(cep_heartbeat_stage_commit());
    munit_assert_true(cep_heartbeat_process_impulses());
    munit_assert_true(cep_heartbeat_process_impulses());
}

static void coh_clear_children(cepCell* node) {
    if (node && cep_cell_has_store(node)) {
        cep_cell_delete_children_hard(node);
    }
}

static void coh_clear_state(void) {
    cepCell* root = cep_root();
    cepCell* data = cep_cell_find_by_name(root, CEP_DTAW("CEP", "data"));
    if (data) {
        cepCell* coh = cep_cell_find_by_name(data, CEP_DTAW("CEP", "coh"));
        if (coh) {
            const char* ledgers[] = {"being", "bond", "context", "facet", "debt"};
            for (size_t i = 0; i < cep_lengthof(ledgers); ++i) {
                cepDT name_dt = dt_word_from(ledgers[i]);
                cepCell* ledger = cep_cell_find_by_name(coh, &name_dt);
                coh_clear_children(ledger);
            }

            cepCell* index = cep_cell_find_by_name(coh, CEP_DTAW("CEP", "index"));
            coh_clear_children(index);

            cepCell* inbox = cep_cell_find_by_name(coh, CEP_DTAW("CEP", "inbox"));
            if (inbox && cep_cell_has_store(inbox)) {
                for (cepCell* bucket = cep_cell_first(inbox); bucket; bucket = cep_cell_next(inbox, bucket)) {
                    coh_clear_children(bucket);
                }
            }
        }
    }

    cepCell* tmp = cep_cell_find_by_name(root, CEP_DTAW("CEP", "tmp"));
    if (tmp) {
        cepCell* coh_tmp = cep_cell_find_by_name(tmp, CEP_DTAW("CEP", "coh"));
        if (coh_tmp) {
            cepCell* adj = cep_cell_find_by_name(coh_tmp, CEP_DTAW("CEP", "adj"));
            if (adj) {
                cepCell* by_being = cep_cell_find_by_name(adj, CEP_DTAW("CEP", "by_being"));
                coh_clear_children(by_being);
            }
        }
    }
}

void* coh_setup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

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
    munit_assert_true(cep_heartbeat_startup());

    cepEnzymeRegistry* registry = cep_heartbeat_registry();
    munit_assert_not_null(registry);
    munit_assert_true(cep_l1_coherence_register(registry));
    cep_enzyme_registry_activate_pending(registry);

    coh_clear_state();

    CohFixture* fixture = munit_malloc(sizeof *fixture);
    fixture->initialized = true;
    return fixture;
}

void coh_teardown(void* fixture_ptr) {
    CohFixture* fixture = fixture_ptr;
    if (fixture && fixture->initialized) {
        coh_clear_state();
        cep_heartbeat_shutdown();
        cep_cell_system_shutdown();
    }
    free(fixture);
}

static cepCell* coh_submit_being(const char* txn_id, const char* being_id, const char* kind) {
    cepDT txn_dt = dt_word_from(txn_id);
    cepCell* request = coh_append_dictionary(coh_require_inbox_bucket("be_create"), &txn_dt);
    coh_set_string_field(request, "id", being_id);
    coh_set_string_field(request, "kind", kind);
    coh_run_single_beat();
    return request;
}

static cepCell* coh_submit_bond(const char* txn_id,
                                const char* bond_id,
                                const char* type,
                                cepCell* src,
                                cepCell* dst,
                                bool directed) {
    cepDT txn_dt = dt_word_from(txn_id);
    cepCell* request = coh_append_dictionary(coh_require_inbox_bucket("bo_upsert"), &txn_dt);
    coh_set_string_field(request, "id", bond_id);
    coh_set_string_field(request, "type", type);
    coh_add_link_field(request, "src", src);
    coh_add_link_field(request, "dst", dst);
    coh_set_bool_field(request, "directed", directed);
    coh_run_single_beat();
    return request;
}

static cepCell* coh_submit_context(const char* txn_id,
                                   const char* ctx_id,
                                   const char* ctx_type,
                                   void (*decorate)(cepCell* request, void* user),
                                   void* decorate_ctx) {
    cepDT txn_dt = dt_word_from(txn_id);
    cepCell* request = coh_append_dictionary(coh_require_inbox_bucket("ctx_upsert"), &txn_dt);
    coh_set_string_field(request, "id", ctx_id);
    coh_set_string_field(request, "type", ctx_type);
    if (decorate) {
        decorate(request, decorate_ctx);
    }
    coh_run_single_beat();
    return request;
}

static const char* coh_outcome(cepCell* request) {
    cepCell* outcome = cep_cell_find_by_name(request, CEP_DTAW("CEP", "outcome"));
    return (outcome && cep_cell_has_data(outcome)) ? (const char*)outcome->data->value : NULL;
}

static cepCell* coh_being_cell(const char* being_id) {
    cepDT id_dt = dt_word_from(being_id);
    return cep_cell_find_by_name(coh_ledger("being"), &id_dt);
}

static cepCell* coh_context_cell(const char* ctx_id) {
    cepDT id_dt = dt_word_from(ctx_id);
    return cep_cell_find_by_name(coh_ledger("context"), &id_dt);
}

static cepCell* coh_bond_cell(const char* bond_id) {
    cepDT id_dt = dt_word_from(bond_id);
    return cep_cell_find_by_name(coh_ledger("bond"), &id_dt);
}

static void decorate_roles_word(cepCell* request, void* user) {
    const struct {
        const char* role_name;
        cepCell* target;
    }* payload = user;
    cepCell* roles = coh_append_dictionary(request, CEP_DTAW("CEP", "roles"));
    coh_add_link_field(roles, payload->role_name, payload->target);
}

static void decorate_roles_custom_dt(cepCell* request, void* user) {
    const struct {
        cepDT role_dt;
        cepCell* target;
    }* payload = user;
    cepCell* roles = coh_append_dictionary(request, CEP_DTAW("CEP", "roles"));
    cepDT role_copy = payload->role_dt;
    cepCell* link = cep_dict_add_link(roles, &role_copy, payload->target);
    munit_assert_not_null(link);
}

static void decorate_facets_required_only(cepCell* request, void* user) {
    (void)user;
    cepCell* facets = coh_append_dictionary(request, CEP_DTAW("CEP", "facets"));
    cepDT facet_dt = dt_word_from("confirm");
    cepCell* facet = coh_append_dictionary(facets, &facet_dt);
    coh_set_bool_field(facet, "required", true);
}

static void decorate_facets_with_target(cepCell* request, void* user) {
    cepCell* target = user;
    cepCell* facets = coh_append_dictionary(request, CEP_DTAW("CEP", "facets"));
    cepDT facet_dt = dt_word_from("confirm");
    cepCell* facet = coh_append_dictionary(facets, &facet_dt);
    coh_add_link_field(facet, "target", target);
    coh_set_bool_field(facet, "required", true);
}

static const char* coh_extract_enzyme_label(const char* message) {
    if (!message) {
        return NULL;
    }
    const char* start = strstr(message, "enzyme=");
    if (!start) {
        return NULL;
    }
    start += 7u;
    const char* end = strchr(start, ' ');
    static char buffer[32];
    size_t len = end ? (size_t)(end - start) : strlen(start);
    if (len >= sizeof buffer) {
        len = sizeof buffer - 1u;
    }
    memcpy(buffer, start, len);
    buffer[len] = '\0';
    return buffer;
}

MunitResult test_coh_word_guard(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    coh_submit_being("txn_be_guard", "be_guard", "agent");
    cepCell* being = coh_being_cell("be_guard");
    munit_assert_not_null(being);

    struct {
        cepDT role_dt;
        cepCell* target;
    } invalid_role = {
        .role_dt = {
            .domain = CEP_ACRO("CEP"),
            .tag = cep_namepool_intern_cstr("reviewer_super"),
        },
        .target = being,
    };

    cepCell* bad_request = coh_submit_context("txn_ctx_guard_bad",
                                             "ctx_guard",
                                             "review",
                                             decorate_roles_custom_dt,
                                             &invalid_role);
    munit_assert_string_equal(coh_outcome(bad_request), "invalid-role");
    munit_assert_null(coh_context_cell("ctx_guard"));

    struct {
        const char* role_name;
        cepCell* target;
    } valid_role = {
        .role_name = "reviewer",
        .target = being,
    };

    cepCell* good_request = coh_submit_context("txn_ctx_guard_ok",
                                              "ctx_guard",
                                              "review",
                                              decorate_roles_word,
                                              &valid_role);
    munit_assert_string_equal(coh_outcome(good_request), "ok");

    cepCell* ctx = coh_context_cell("ctx_guard");
    munit_assert_not_null(ctx);
    cepCell* roles = coh_find_mandatory(ctx, CEP_DTAW("CEP", "roles"));
    cepDT reviewer_dt = dt_word_from("reviewer");
    cepCell* role_link = coh_find_mandatory(roles, &reviewer_dt);
    munit_assert_true(cep_cell_is_link(role_link));
    munit_assert_ptr_equal(cep_link_pull(role_link), being);

    return MUNIT_OK;
}

MunitResult test_coh_replay_identity(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    coh_submit_being("txn_be_replay", "be_replay", "agent");
    cepCell* being = coh_being_cell("be_replay");
    munit_assert_not_null(being);

    struct {
        const char* role_name;
        cepCell* target;
    } role = {
        .role_name = "owner",
        .target = being,
    };

    cepCell* first_request = coh_submit_context("txn_ctx_replay_a",
                                               "ctx_replay",
                                               "session",
                                               decorate_roles_word,
                                               &role);
    munit_assert_string_equal(coh_outcome(first_request), "ok");

    cepCell* ctx = coh_context_cell("ctx_replay");
    munit_assert_not_null(ctx);
    size_t child_count_before = cep_cell_children(ctx);
    cepCell* type_cell = coh_find_mandatory(ctx, CEP_DTAW("CEP", "type"));
    uint64_t type_hash_before = cep_cell_content_hash(type_cell);

    cepCell* roles = coh_find_mandatory(ctx, CEP_DTAW("CEP", "roles"));
    cepDT owner_dt = dt_word_from("owner");
    cepCell* role_link = coh_find_mandatory(roles, &owner_dt);
    munit_assert_ptr_equal(cep_link_pull(role_link), being);

    cepCell* second_request = coh_submit_context("txn_ctx_replay_b",
                                                "ctx_replay",
                                                "session",
                                                decorate_roles_word,
                                                &role);
    munit_assert_string_equal(coh_outcome(second_request), "ok");

    cepCell* ctx_again = coh_context_cell("ctx_replay");
    munit_assert_ptr_equal(ctx_again, ctx);
    munit_assert_size(cep_cell_children(ctx_again), ==, child_count_before);
    munit_assert_uint64(cep_cell_content_hash(type_cell), ==, type_hash_before);

    return MUNIT_OK;
}

MunitResult test_coh_closure_debt(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    coh_submit_being("txn_be_debt", "be_debt", "agent");
    cepCell* being = coh_being_cell("be_debt");
    munit_assert_not_null(being);

    struct {
        const char* role_name;
        cepCell* target;
    } role = {
        .role_name = "owner",
        .target = being,
    };

    cepCell* missing = coh_submit_context("txn_ctx_debt_a",
                                         "ctx_debt",
                                         "session",
                                         decorate_roles_word,
                                         &role);
    decorate_facets_required_only(missing, NULL);
    coh_run_single_beat();
    munit_assert_string_equal(coh_outcome(missing), "ok");

    cepCell* debt_root = coh_debt_root();
    cepDT ctx_dt = dt_word_from("ctx_debt");
    cepCell* ctx_bucket = coh_find_mandatory(debt_root, &ctx_dt);
    cepDT facet_dt = dt_word_from("confirm");
    cepCell* facet_bucket = coh_find_mandatory(ctx_bucket, &facet_dt);
    cepCell* required_flag = coh_find_mandatory(facet_bucket, CEP_DTAW("CEP", "required"));
    munit_assert_true(cep_cell_has_data(required_flag));
    munit_assert_uint8(required_flag->data->value[0], ==, 1u);

    cepCell* provided = coh_submit_context("txn_ctx_debt_b",
                                          "ctx_debt",
                                          "session",
                                          decorate_roles_word,
                                          &role);
    decorate_facets_with_target(provided, being);
    coh_run_single_beat();
    munit_assert_string_equal(coh_outcome(provided), "ok");

    debt_root = coh_debt_root();
    ctx_bucket = cep_cell_find_by_name(debt_root, &ctx_dt);
    if (ctx_bucket) {
        facet_dt = dt_word_from("confirm");
        munit_assert_null(cep_cell_find_by_name(ctx_bucket, &facet_dt));
    }

    cepCell* facets_global = coh_ledger("facet");
    char key_buf[48];
    snprintf(key_buf, sizeof key_buf, "%s:%s", "ctx_debt", "confirm");
    cepDT mirror_dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = cep_namepool_intern_cstr(key_buf),
    };
    cepCell* mirror = cep_cell_find_by_name(facets_global, &mirror_dt);
    munit_assert_not_null(mirror);
    munit_assert_ptr_equal(cep_link_pull(mirror), being);

    return MUNIT_OK;
}

MunitResult test_coh_link_lifecycle(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    coh_submit_being("txn_be_src", "be_src", "agent");
    coh_submit_being("txn_be_dst", "be_dst", "agent");
    cepCell* src = coh_being_cell("be_src");
    cepCell* dst = coh_being_cell("be_dst");
    munit_assert_not_null(src);
    munit_assert_not_null(dst);

    coh_submit_bond("txn_bond", "bond_link", "ally", src, dst, false);
    cepCell* bond = coh_bond_cell("bond_link");
    munit_assert_not_null(bond);

    struct {
        const char* role_name;
        cepCell* target;
    } role = {
        .role_name = "partner",
        .target = dst,
    };

    coh_submit_context("txn_ctx_link", "ctx_link", "pact", decorate_roles_word, &role);
    cepCell* ctx = coh_context_cell("ctx_link");
    munit_assert_not_null(ctx);

    cepCell* bond_dst_link = coh_find_mandatory(bond, CEP_DTAW("CEP", "dst"));
    munit_assert_true(cep_cell_is_link(bond_dst_link));
    munit_assert_uint(bond_dst_link->metacell.targetDead, ==, 0u);

    cepCell* ctx_roles = coh_find_mandatory(ctx, CEP_DTAW("CEP", "roles"));
    cepDT partner_dt = dt_word_from("partner");
    cepCell* ctx_role_link = coh_find_mandatory(ctx_roles, &partner_dt);
    munit_assert_true(cep_cell_is_link(ctx_role_link));
    munit_assert_uint(ctx_role_link->metacell.targetDead, ==, 0u);

    cep_cell_delete(dst);
    coh_run_single_beat();

    munit_assert_uint(bond_dst_link->metacell.targetDead, ==, 1u);
    munit_assert_uint(ctx_role_link->metacell.targetDead, ==, 1u);

    return MUNIT_OK;
}

MunitResult test_coh_agenda_order(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    coh_submit_being("txn_be_agenda", "be_agenda", "agent");
    cepCell* being = coh_being_cell("be_agenda");
    munit_assert_not_null(being);

    struct {
        const char* role_name;
        cepCell* target;
    } role = {
        .role_name = "owner",
        .target = being,
    };

    cepCell* ctx_request = coh_submit_context("txn_ctx_agenda",
                                             "ctx_agenda",
                                             "session",
                                             decorate_roles_word,
                                             &role);
    decorate_facets_with_target(ctx_request, being);
    coh_run_single_beat();

    cepBeatNumber beat = cep_heartbeat_current();
    munit_assert_uint64(beat, !=, CEP_BEAT_INVALID);

    cepCell* rt = coh_find_mandatory(cep_root(), CEP_DTAW("CEP", "rt"));
    cepCell* beat_root = coh_find_mandatory(rt, CEP_DTAW("CEP", "beat"));
    cepDT beat_dt = {
        .domain = CEP_ACRO("HB"),
        .tag = cep_id_to_numeric((cepID)(beat + 1u)),
    };
    cepCell* beat_cell = coh_find_mandatory(beat_root, &beat_dt);
    cepCell* agenda = coh_find_mandatory(beat_cell, CEP_DTAW("CEP", "agenda"));

    const char* expected[] = {
        "coh.ingest.ctx",
        "coh.closure",
        "coh.index",
        "coh.adj",
    };
    size_t expected_idx = 0u;

    for (cepCell* entry = cep_cell_first(agenda); entry && expected_idx < cep_lengthof(expected);
         entry = cep_cell_next(agenda, entry)) {
        if (!cep_cell_has_data(entry) || entry->data->datatype != CEP_DATATYPE_VALUE) {
            continue;
        }
        const char* label = coh_extract_enzyme_label((const char*)entry->data->value);
        if (!label) {
            continue;
        }
        if (strstr(label, "coh.")) {
            munit_assert_string_equal(label, expected[expected_idx]);
            ++expected_idx;
        }
    }

    munit_assert_size(expected_idx, ==, cep_lengthof(expected));
    return MUNIT_OK;
}

static MunitTest coherence_tests[] = {
    {
        "/coherence/word_guard",
        test_coh_word_guard,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/replay_identity",
        test_coh_replay_identity,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/closure_debt",
        test_coh_closure_debt,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/link_lifecycle",
        test_coh_link_lifecycle,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/agenda_order",
        test_coh_agenda_order,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
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
