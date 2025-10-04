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

static cepDT dt_identifier_from(const char* text) {
    cepID id = cep_namepool_intern_cstr(text);
    munit_assert_uint64(id, !=, 0u);
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = id,
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

static cepCell* coh_index_branch(const char* name) {
    cepCell* data = coh_find_mandatory(cep_root(), CEP_DTAW("CEP", "data"));
    cepCell* coh = coh_find_mandatory(data, CEP_DTAW("CEP", "coh"));
    cepCell* index_root = coh_find_mandatory(coh, CEP_DTAW("CEP", "index"));
    cepDT branch_dt = dt_word_from(name);
    cepCell* branch = cep_cell_find_by_name(index_root, &branch_dt);
    munit_assert_not_null(branch);
    return branch;
}

static cepDT coh_namepool_key(const char* text) {
    cepID tag = cep_namepool_intern_cstr(text);
    munit_assert_uint64(tag, !=, 0u);
    cepDT dt = {
        .domain = CEP_ACRO("CEP"),
        .tag = tag,
    };
    return dt;
}

static cepDT coh_bo_pair_key(const char* src,
                             const char* dst,
                             const char* type,
                             bool directed) {
    char key_buf[96];
    snprintf(key_buf, sizeof key_buf, "%s:%s:%s:%c", src, dst, type, directed ? '1' : '0');
    return coh_namepool_key(key_buf);
}

static cepDT coh_context_facet_key(const char* ctx_id, const char* facet) {
    char key_buf[72];
    snprintf(key_buf, sizeof key_buf, "%s:%s", ctx_id, facet);
    return coh_namepool_key(key_buf);
}

static cepCell* coh_adj_root(void) {
    cepCell* tmp = coh_find_mandatory(cep_root(), CEP_DTAW("CEP", "tmp"));
    cepCell* coh_tmp = coh_find_mandatory(tmp, CEP_DTAW("CEP", "coh"));
    cepCell* adj = coh_find_mandatory(coh_tmp, CEP_DTAW("CEP", "adj"));
    return coh_find_mandatory(adj, CEP_DTAW("CEP", "by_being"));
}

static cepCell* coh_adj_bucket(const char* being_id) {
    cepDT id_dt = dt_identifier_from(being_id);
    return cep_cell_find_by_name(coh_adj_root(), &id_dt);
}

static bool coh_adj_bond_contains(const char* being_id, const char* dict_name, const char* bond_id) {
    cepCell* bucket = coh_adj_bucket(being_id);
    if (!bucket) {
        return false;
    }
    cepCell* dict = cep_cell_find_by_name(bucket, CEP_DTAW("CEP", dict_name));
    if (!dict) {
        return false;
    }
    cepDT bond_dt = dt_identifier_from(bond_id);
    return cep_cell_find_by_name(dict, &bond_dt) != NULL;
}

static bool coh_adj_ctx_role_contains(const char* being_id, const char* role_name, const char* ctx_id) {
    cepCell* bucket = coh_adj_bucket(being_id);
    if (!bucket) {
        return false;
    }
    cepCell* ctx_by_role = cep_cell_find_by_name(bucket, CEP_DTAW("CEP", "ctx_by_role"));
    if (!ctx_by_role) {
        return false;
    }
    cepDT role_dt = dt_identifier_from(role_name);
    cepCell* role_bucket = cep_cell_find_by_name(ctx_by_role, &role_dt);
    if (!role_bucket) {
        return false;
    }
    cepDT ctx_dt = dt_identifier_from(ctx_id);
    cepCell* link = cep_cell_find_by_name(role_bucket, &ctx_dt);
    return link && cep_cell_is_link(link);
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

static MunitResult test_coh_identifier_helper_word(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    char buffer[CEP_L1_IDENTIFIER_MAX + 1u];
    munit_assert_true(CEP_L1_COMPOSE(buffer, sizeof buffer, "Team", "A"));
    munit_assert_string_equal(buffer, "team:a");

    cepDT dt = {0};
    munit_assert_true(CEP_L1_TOKENS_TO_DT(&dt, "Team", "A"));
    munit_assert_true(cep_id_is_word(dt.tag));
    char decoded[CEP_WORD_MAX_CHARS + 1u];
    cep_word_to_text(dt.tag, decoded);
    munit_assert_string_equal(decoded, "team:a");

    return MUNIT_OK;
}

static MunitResult test_coh_identifier_helper_reference(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    char buffer[CEP_L1_IDENTIFIER_MAX + 1u];
    munit_assert_true(CEP_L1_COMPOSE(buffer, sizeof buffer, "Customer", "Region-West", "2025"));
    munit_assert_string_equal(buffer, "customer:region-west:2025");

    cepDT dt = {0};
    munit_assert_true(CEP_L1_TOKENS_TO_DT(&dt, "Customer", "Region-West", "2025"));
    munit_assert_true(cep_id_is_reference(dt.tag));
    size_t len = 0u;
    const char* stored = cep_namepool_lookup(dt.tag, &len);
    munit_assert_not_null(stored);
    munit_assert_size(len, ==, strlen(buffer));
    munit_assert_memory_equal(len, buffer, stored);

    return MUNIT_OK;
}

static MunitResult test_coh_identifier_helper_invalid(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    const char* tokens_bad[] = { "lead", "phase:alpha" };
    char buffer[CEP_L1_IDENTIFIER_MAX + 1u];
    munit_assert_false(cep_l1_compose_identifier(tokens_bad, 2u, buffer, sizeof buffer));

    const char* tokens_space[] = { "  ", "alpha" };
    munit_assert_false(cep_l1_compose_identifier(tokens_space, 2u, buffer, sizeof buffer));

    return MUNIT_OK;
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
    cepDT id_dt = dt_identifier_from(being_id);
    return cep_cell_find_by_name(coh_ledger("being"), &id_dt);
}

static cepCell* coh_context_cell(const char* ctx_id) {
    cepDT id_dt = dt_identifier_from(ctx_id);
    return cep_cell_find_by_name(coh_ledger("context"), &id_dt);
}

static cepCell* coh_bond_cell(const char* bond_id) {
    cepDT id_dt = dt_identifier_from(bond_id);
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

static void decorate_facets_empty(cepCell* request, void* user) {
    (void)user;
    (void)coh_append_dictionary(request, CEP_DTAW("CEP", "facets"));
}

typedef struct {
    const char* role_name;
    cepCell* role_target;
    const char* facet_name;
    cepCell* facet_target;
    bool facet_required;
} CohContextDecorator;

static void decorate_roles_and_custom_facet(cepCell* request, void* user) {
    const CohContextDecorator* payload = user;
    cepCell* roles = coh_append_dictionary(request, CEP_DTAW("CEP", "roles"));
    cepDT role_dt = dt_identifier_from(payload->role_name);
    cepDT role_copy = role_dt;
    cepCell* role_link = cep_dict_add_link(roles, &role_copy, payload->role_target);
    munit_assert_not_null(role_link);

    cepCell* facets = coh_append_dictionary(request, CEP_DTAW("CEP", "facets"));
    cepDT facet_dt = dt_identifier_from(payload->facet_name);
    cepCell* facet = coh_append_dictionary(facets, &facet_dt);
    if (payload->facet_target) {
        coh_add_link_field(facet, "target", payload->facet_target);
    }
    if (payload->facet_required) {
        coh_set_bool_field(facet, "required", true);
    }
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

MunitResult test_coh_role_identifiers(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    coh_submit_being("txn_be_guard", "be_guard", "agent");
    cepCell* being = coh_being_cell("be_guard");
    munit_assert_not_null(being);

    struct {
        cepDT role_dt;
        cepCell* target;
    } invalid_role = {
        .role_dt = { .domain = 0u, .tag = 0u },
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

    const char* long_role_name = "stakeholder/primary/region-east";
    struct {
        cepDT role_dt;
        cepCell* target;
    } long_role = {
        .role_dt = dt_identifier_from(long_role_name),
        .target = being,
    };

    cepCell* long_request = coh_submit_context("txn_ctx_guard_long",
                                             "ctx_guard_long",
                                             "review",
                                             decorate_roles_custom_dt,
                                             &long_role);
    munit_assert_string_equal(coh_outcome(long_request), "ok");

    cepCell* long_ctx = coh_context_cell("ctx_guard_long");
    munit_assert_not_null(long_ctx);
    cepCell* long_roles = coh_find_mandatory(long_ctx, CEP_DTAW("CEP", "roles"));
    cepCell* long_role_link = coh_find_mandatory(long_roles, &long_role.role_dt);
    munit_assert_true(cep_cell_is_link(long_role_link));
    munit_assert_ptr_equal(cep_link_pull(long_role_link), being);

    return MUNIT_OK;
}

MunitResult test_coh_long_identifiers(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    const char* be_primary_id = "being:sales:north-america:primary";
    const char* be_secondary_id = "being:support:central-hub";
    const char* long_kind = "team/operations/2025-q2";

    cepCell* be_primary_req = coh_submit_being("txn_be_long_a", be_primary_id, long_kind);
    munit_assert_string_equal(coh_outcome(be_primary_req), "ok");
    cepCell* be_secondary_req = coh_submit_being("txn_be_long_b", be_secondary_id, "team/support/2025");
    munit_assert_string_equal(coh_outcome(be_secondary_req), "ok");

    cepDT be_primary_dt = dt_identifier_from(be_primary_id);
    cepCell* be_primary = coh_find_mandatory(coh_ledger("being"), &be_primary_dt);
    cepCell* kind_cell = coh_find_mandatory(be_primary, CEP_DTAW("CEP", "kind"));
    munit_assert_string_equal((const char*)kind_cell->data->value, long_kind);

    cepCell* be_kind_idx = coh_index_branch("be_kind");
    cepDT kind_dt = dt_identifier_from(long_kind);
    cepCell* kind_bucket = coh_find_mandatory(be_kind_idx, &kind_dt);
    cepCell* kind_entry = coh_find_mandatory(kind_bucket, &be_primary_dt);
    munit_assert_true(cep_cell_is_link(kind_entry));
    munit_assert_ptr_equal(cep_link_pull(kind_entry), be_primary);

    const char* bond_id = "bond:mentorship:spring-2025";
    const char* bond_type = "mentorship/seasonal:2025";
    cepCell* bond_req = coh_submit_bond("txn_bo_long",
                                       bond_id,
                                       bond_type,
                                       be_primary,
                                       coh_being_cell(be_secondary_id),
                                       false);
    munit_assert_string_equal(coh_outcome(bond_req), "ok");

    cepDT bond_dt = dt_identifier_from(bond_id);
    cepCell* bond = coh_find_mandatory(coh_ledger("bond"), &bond_dt);
    cepCell* bond_type_cell = coh_find_mandatory(bond, CEP_DTAW("CEP", "type"));
    munit_assert_string_equal((const char*)bond_type_cell->data->value, bond_type);

    cepCell* bo_pair = coh_index_branch("bo_pair");
    cepDT pair_dt = coh_bo_pair_key(be_primary_id, be_secondary_id, bond_type, false);
    cepCell* pair_entry = coh_find_mandatory(bo_pair, &pair_dt);
    munit_assert_true(cep_cell_is_link(pair_entry));
    munit_assert_ptr_equal(cep_link_pull(pair_entry), bond);

    munit_assert_true(coh_adj_bond_contains(be_primary_id, "out_bonds", bond_id));
    munit_assert_true(coh_adj_bond_contains(be_secondary_id, "in_bonds", bond_id));

    const char* ctx_id = "context:engagement:trial-phase:2025";
    const char* ctx_type = "engagement/trial-phase";
    const char* role_name = "owner::primary";
    const char* facet_name = "deliverable::kickoff";

    CohContextDecorator ctx_payload = {
        .role_name = role_name,
        .role_target = be_primary,
        .facet_name = facet_name,
        .facet_target = bond,
        .facet_required = true,
    };

    cepCell* ctx_request = coh_submit_context("txn_ctx_long",
                                             ctx_id,
                                             ctx_type,
                                             decorate_roles_and_custom_facet,
                                             &ctx_payload);
    munit_assert_string_equal(coh_outcome(ctx_request), "ok");

    cepDT ctx_dt = dt_identifier_from(ctx_id);
    cepCell* ctx = coh_find_mandatory(coh_ledger("context"), &ctx_dt);
    cepCell* ctx_type_cell = coh_find_mandatory(ctx, CEP_DTAW("CEP", "type"));
    munit_assert_string_equal((const char*)ctx_type_cell->data->value, ctx_type);

    cepCell* roles = coh_find_mandatory(ctx, CEP_DTAW("CEP", "roles"));
    cepDT role_dt = dt_identifier_from(role_name);
    cepCell* role_link = coh_find_mandatory(roles, &role_dt);
    munit_assert_true(cep_cell_is_link(role_link));
    munit_assert_ptr_equal(cep_link_pull(role_link), be_primary);

    cepCell* facets = coh_find_mandatory(ctx, CEP_DTAW("CEP", "facets"));
    cepDT facet_dt = dt_identifier_from(facet_name);
    cepCell* facet_entry = coh_find_mandatory(facets, &facet_dt);
    cepCell* facet_target = coh_find_mandatory(facet_entry, CEP_DTAW("CEP", "target"));
    munit_assert_true(cep_cell_is_link(facet_target));
    munit_assert_ptr_equal(cep_link_pull(facet_target), bond);

    cepDT mirror_dt = coh_context_facet_key(ctx_id, facet_name);
    cepCell* mirror_link = coh_find_mandatory(coh_ledger("facet"), &mirror_dt);
    munit_assert_true(cep_cell_is_link(mirror_link));
    munit_assert_ptr_equal(cep_link_pull(mirror_link), bond);

    cepCell* ctx_type_idx = coh_index_branch("ctx_type");
    cepCell* type_bucket = coh_find_mandatory(ctx_type_idx, &dt_identifier_from(ctx_type));
    cepCell* ctx_index_entry = coh_find_mandatory(type_bucket, &ctx_dt);
    munit_assert_true(cep_cell_is_link(ctx_index_entry));
    munit_assert_ptr_equal(cep_link_pull(ctx_index_entry), ctx);

    cepCell* fa_ctx = coh_index_branch("fa_ctx");
    cepCell* fa_bucket = coh_find_mandatory(fa_ctx, &ctx_dt);
    cepCell* facet_link = coh_find_mandatory(fa_bucket, &facet_dt);
    munit_assert_true(cep_cell_is_link(facet_link));
    munit_assert_ptr_equal(cep_link_pull(facet_link), facet_entry);

    munit_assert_true(coh_adj_ctx_role_contains(be_primary_id, role_name, ctx_id));

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

MunitResult test_coh_indexes_and_adjacency(const MunitParameter params[], void* fixture_ptr) {
    (void)params;
    (void)fixture_ptr;

    coh_submit_being("txn_be_idx_a1", "be_idxa", "agent");
    coh_submit_being("txn_be_idx_b1", "be_idxb", "agent");
    coh_submit_being("txn_be_idx_c1", "be_idxc", "agent");

    cepCell* retyped = coh_submit_being("txn_be_idx_a2", "be_idxa", "speaker");
    munit_assert_string_equal(coh_outcome(retyped), "ok");

    cepCell* be_kind = coh_index_branch("be_kind");
    cepDT alice_dt = dt_word_from("be_idxa");
    cepDT agent_dt = dt_word_from("agent");
    cepCell* agent_bucket = cep_cell_find_by_name(be_kind, &agent_dt);
    if (agent_bucket) {
        munit_assert_null(cep_cell_find_by_name(agent_bucket, &alice_dt));
    }
    cepDT speaker_dt = dt_word_from("speaker");
    cepCell* speaker_bucket = coh_find_mandatory(be_kind, &speaker_dt);
    munit_assert_not_null(cep_cell_find_by_name(speaker_bucket, &alice_dt));

    cepCell* src_be = coh_being_cell("be_idxa");
    cepCell* dst_be = coh_being_cell("be_idxb");
    cepCell* new_dst_be = coh_being_cell("be_idxc");
    munit_assert_not_null(src_be);
    munit_assert_not_null(dst_be);
    munit_assert_not_null(new_dst_be);

    coh_submit_bond("txn_bond_idx_a", "bond_idx", "mentor", src_be, dst_be, false);
    cepCell* bond = coh_bond_cell("bond_idx");
    munit_assert_not_null(bond);

    cepCell* bo_pair = coh_index_branch("bo_pair");
    cepDT pair_initial = coh_bo_pair_key("be_idxa", "be_idxb", "mentor", false);
    cepCell* pair_entry = coh_find_mandatory(bo_pair, &pair_initial);
    munit_assert_ptr_equal(cep_link_pull(pair_entry), bond);

    munit_assert_true(coh_adj_bond_contains("be_idxa", "out_bonds", "bond_idx"));
    munit_assert_true(coh_adj_bond_contains("be_idxb", "in_bonds", "bond_idx"));

    cepCell* rebond = coh_submit_bond("txn_bond_idx_b", "bond_idx", "mentor", src_be, new_dst_be, false);
    munit_assert_string_equal(coh_outcome(rebond), "ok");

    cepCell* old_pair = cep_cell_find_by_name(bo_pair, &pair_initial);
    munit_assert_null(old_pair);
    cepDT pair_updated = coh_bo_pair_key("be_idxa", "be_idxc", "mentor", false);
    cepCell* updated_entry = coh_find_mandatory(bo_pair, &pair_updated);
    munit_assert_ptr_equal(cep_link_pull(updated_entry), bond);

    munit_assert_true(coh_adj_bond_contains("be_idxa", "out_bonds", "bond_idx"));
    munit_assert(!coh_adj_bond_contains("be_idxb", "in_bonds", "bond_idx"));
    munit_assert_true(coh_adj_bond_contains("be_idxc", "in_bonds", "bond_idx"));

    struct {
        const char* role_name;
        cepCell* target;
    } role_initial = {
        .role_name = "owner",
        .target = new_dst_be,
    };

    cepCell* ctx_request = coh_submit_context("txn_ctx_idx_a",
                                             "ctx_idx",
                                             "session",
                                             decorate_roles_word,
                                             &role_initial);
    decorate_facets_with_target(ctx_request, bond);
    coh_run_single_beat();

    cepCell* ctx = coh_context_cell("ctx_idx");
    munit_assert_not_null(ctx);

    cepCell* ctx_type = coh_index_branch("ctx_type");
    cepDT session_dt = dt_word_from("session");
    cepCell* session_bucket = coh_find_mandatory(ctx_type, &session_dt);
    cepDT ctx_dt = dt_word_from("ctx_idx");
    munit_assert_not_null(cep_cell_find_by_name(session_bucket, &ctx_dt));

    cepCell* fa_ctx = coh_index_branch("fa_ctx");
    cepCell* fa_bucket = coh_find_mandatory(fa_ctx, &ctx_dt);
    cepDT facet_dt = dt_word_from("confirm");
    cepCell* fa_entry = coh_find_mandatory(fa_bucket, &facet_dt);
    munit_assert_ptr_equal(cep_link_pull(fa_entry), bond);

    cepCell* facets_global = coh_ledger("facet");
    cepDT mirror_dt = coh_context_facet_key("ctx_idx", "confirm");
    cepCell* mirror_link = coh_find_mandatory(facets_global, &mirror_dt);
    munit_assert_ptr_equal(cep_link_pull(mirror_link), bond);

    munit_assert_true(coh_adj_ctx_role_contains("be_idxc", "owner", "ctx_idx"));

    struct {
        const char* role_name;
        cepCell* target;
    } role_update = {
        .role_name = "owner",
        .target = src_be,
    };

    cepCell* ctx_update = coh_submit_context("txn_ctx_idx_b",
                                            "ctx_idx",
                                            "meeting",
                                            decorate_roles_word,
                                            &role_update);
    decorate_facets_empty(ctx_update, NULL);
    coh_run_single_beat();

    munit_assert_null(cep_cell_find_by_name(session_bucket, &ctx_dt));
    cepDT meeting_dt = dt_word_from("meeting");
    cepCell* meeting_bucket = coh_find_mandatory(ctx_type, &meeting_dt);
    munit_assert_not_null(cep_cell_find_by_name(meeting_bucket, &ctx_dt));

    fa_bucket = cep_cell_find_by_name(fa_ctx, &ctx_dt);
    if (fa_bucket) {
        munit_assert_size(cep_cell_children(fa_bucket), ==, 0u);
    }

    munit_assert_null(cep_cell_find_by_name(facets_global, &mirror_dt));

    cepCell* debt_root = coh_debt_root();
    cepCell* debt_bucket = cep_cell_find_by_name(debt_root, &ctx_dt);
    if (debt_bucket) {
        munit_assert_null(cep_cell_find_by_name(debt_bucket, &facet_dt));
    }

    munit_assert(!coh_adj_ctx_role_contains("be_idxc", "owner", "ctx_idx"));
    munit_assert_true(coh_adj_ctx_role_contains("be_idxa", "owner", "ctx_idx"));

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
        "/coherence/identifier_helper_word",
        test_coh_identifier_helper_word,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/identifier_helper_reference",
        test_coh_identifier_helper_reference,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/identifier_helper_invalid",
        test_coh_identifier_helper_invalid,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/role_identifiers",
        test_coh_role_identifiers,
        coh_setup,
        coh_teardown,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {
        "/coherence/long_identifiers",
        test_coh_long_identifiers,
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
        "/coherence/indexes_and_adjacency",
        test_coh_indexes_and_adjacency,
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
