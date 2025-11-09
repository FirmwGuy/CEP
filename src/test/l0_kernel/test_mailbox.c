/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Mailbox helper coverage: validate message ID precedence, TTL resolution, and
   retention planning for both public boards and private inboxes. */

#include "test.h"
#include "cep_mailbox.h"

#include <inttypes.h>
#include <stdio.h>

static void mailbox_runtime_start(void) {
    test_runtime_shutdown();

    cepHeartbeatPolicy policy = {
        .start_at = 0u,
        .ensure_directories = true,
        .enforce_visibility = false,
        .boot_ops = true,
        .spacing_window = 32u,
    };

    munit_assert_true(cep_heartbeat_configure(NULL, &policy));
    munit_assert_true(cep_heartbeat_startup());

    /* Seed wallclock spacing analytics so TTL heuristics have data. */
    munit_assert_true(cep_heartbeat_publish_wallclock(0u, 1000u));
    munit_assert_true(cep_heartbeat_publish_wallclock(1u, 2500u));
}

static cepDT mailbox_dt(const char* tag) {
    cepDT dt = {0};
    dt.domain = cep_namepool_intern_cstr("CEP");
    dt.tag = cep_namepool_intern_cstr(tag);
    dt.glob = cep_id_has_glob_char(dt.tag) ? 1u : 0u;
    return dt;
}

static cepCell* mailbox_root_named(const char* slug, const char* kind) {
    cepCell* data_root = cep_cell_ensure_dictionary_child(cep_root(),
                                                          CEP_DTAW("CEP", "data"),
                                                          CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(data_root);

    cepCell* mailbox_dir = cep_cell_ensure_dictionary_child(data_root,
                                                            CEP_DTAW("CEP", "mailbox"),
                                                            CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(mailbox_dir);

    cepDT slug_dt = mailbox_dt(slug);
    cepCell* mailbox = cep_cell_ensure_dictionary_child(mailbox_dir, &slug_dt, CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(mailbox);

    cepCell* meta = cep_cell_ensure_dictionary_child(mailbox, CEP_DTAW("CEP", "meta"), CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(meta);
    munit_assert_true(cep_cell_put_text(meta, CEP_DTAW("CEP", "kind"), kind));

    cep_cell_ensure_dictionary_child(meta, CEP_DTAW("CEP", "runtime"), CEP_STORAGE_RED_BLACK_T);
    cep_cell_ensure_dictionary_child(mailbox, CEP_DTAW("CEP", "msgs"), CEP_STORAGE_RED_BLACK_T);
    return mailbox;
}

static cepCell* mailbox_board_news(void) {
    return mailbox_root_named("news", "board");
}

static cepCell* mailbox_private_direct(void) {
    cepCell* mailbox = mailbox_root_named("direct", "private");
    cepCell* meta = cep_cell_find_by_name(mailbox, CEP_DTAW("CEP", "meta"));
    munit_assert_not_null(meta);
    meta = cep_cell_resolve(meta);
    cepCell* policy = cep_cell_ensure_dictionary_child(meta, CEP_DTAW("CEP", "policy"), CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(policy);
    munit_assert_true(cep_cell_put_text(policy, CEP_DTAW("CEP", "ttl_mode"), "forever"));
    return mailbox;
}

static cepCell* mailbox_make_envelope(const char* stem, bool immutable) {
    static unsigned counter = 0u;
    cepDT name_dt = *CEP_DTAW("CEP", "envelope");
    cepCell* envelope = cep_malloc0(sizeof *envelope);
    cep_cell_initialize_dictionary(envelope,
                                   &name_dt,
                                   CEP_DTAW("CEP", "dictionary"),
                                   CEP_STORAGE_RED_BLACK_T);
    char topic[64];
    snprintf(topic, sizeof topic, "%s_%u", stem, counter++);
    munit_assert_true(cep_cell_put_text(envelope, CEP_DTAW("CEP", "topic"), topic));
    if (immutable) {
        munit_assert_true(cep_cell_set_immutable(envelope));
    }
    return envelope;
}

static void mailbox_free_envelope(cepCell* envelope) {
    if (!envelope) {
        return;
    }
    cep_cell_finalize_hard(envelope);
    cep_free(envelope);
}

static cepCell* mailbox_msgs_branch(cepCell* mailbox) {
    cepCell* msgs = cep_cell_find_by_name(mailbox, CEP_DTAW("CEP", "msgs"));
    munit_assert_not_null(msgs);
    return cep_cell_resolve(msgs);
}

static void mailbox_store_envelope(cepCell* message_cell, const cepCell* source_envelope) {
    cepCell* envelope = cep_cell_ensure_dictionary_child(message_cell,
                                                         CEP_DTAW("CEP", "envelope"),
                                                         CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(envelope);
    cep_cell_clear_children(envelope);
    if (source_envelope) {
        munit_assert_true(cep_cell_copy_children(source_envelope, envelope, true));
    }
    envelope->metacell.veiled = 1u;
    envelope->metacell.immutable = 0u;
    if (envelope->store) {
        envelope->store->writable = 1u;
    }
    munit_assert_true(cep_cell_set_immutable(envelope));
    envelope->metacell.veiled = 0u;
}

static void mailbox_expect_board_workflow(const MunitParameter params[]) {
    test_boot_cycle_prepare(params);
    mailbox_runtime_start();

    cepCell* board = mailbox_board_news();
    cepCell* msgs = mailbox_msgs_branch(board);

    /* Explicit ID honoured. */
    cepCell* explicit_env = mailbox_make_envelope("explicit", true);
    cepMailboxMessageId explicit_id = {0};
    munit_assert_true(cep_mailbox_select_message_id(board,
                                                    CEP_DTAW("CEP", "msgalpha"),
                                                    explicit_env,
                                                    &explicit_id));
    munit_assert_int(explicit_id.mode, ==, CEP_MAILBOX_ID_EXPLICIT);
    munit_assert_false(explicit_id.collision_detected);

    cepDT explicit_name = explicit_id.id;
    cepCell* message = cep_cell_add_dictionary(msgs,
                                               &explicit_name,
                                               0,
                                               CEP_DTAW("CEP", "dictionary"),
                                               CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(message);
    mailbox_store_envelope(message, explicit_env);
    cepCell* stored_env = cep_cell_find_by_name(message, CEP_DTAW("CEP", "envelope"));
    munit_assert_not_null(stored_env);
    stored_env = cep_cell_resolve(stored_env);
    cepCell* stored_topic = cep_cell_find_by_name(stored_env, CEP_DTAW("CEP", "topic"));
    munit_assert_not_null(stored_topic);
    munit_assert_true(cep_cell_has_data(stored_topic));
    mailbox_free_envelope(explicit_env);

    /* Changing the envelope triggers a collision. */
    cepMailboxMessageId collision = {0};
    cepCell* collision_env = mailbox_make_envelope("explicit-new", true);
    munit_assert_false(cep_mailbox_select_message_id(board,
                                                     &explicit_name,
                                                     collision_env,
                                                     &collision));
    munit_assert_true(collision.collision_detected);
    mailbox_free_envelope(collision_env);

    /* Digest-based identifier for new message. */
    cepCell* digest_env = mailbox_make_envelope("digest", true);
    cepMailboxMessageId digest_id = {0};
    munit_assert_true(cep_mailbox_select_message_id(board, NULL, digest_env, &digest_id));
    munit_assert_false(digest_id.collision_detected);
    munit_assert_true(digest_id.mode == CEP_MAILBOX_ID_DIGEST ||
                      digest_id.mode == CEP_MAILBOX_ID_COUNTER);
    cepDT digest_name = digest_id.id;
    cepCell* digest_msg = cep_cell_add_dictionary(msgs,
                                                  &digest_name,
                                                  0,
                                                  CEP_DTAW("CEP", "dictionary"),
                                                  CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(digest_msg);
    mailbox_store_envelope(digest_msg, digest_env);
    mailbox_free_envelope(digest_env);

    /* TTL resolution and retention scheduling using beat deadlines. */
    cepMailboxTTLContext ctx;
    munit_assert_true(cep_mailbox_ttl_context_init(&ctx));
    ctx.issued_beat = 1u;
    ctx.current_beat = 1u;
    ctx.issued_has_unix = true;
    ctx.issued_unix_ns = 2500u;
    ctx.current_has_unix = true;
    ctx.current_unix_ns = 2500u;

    cepMailboxTTLSpec msg_spec = {
        .forever = false,
        .has_beats = true,
        .ttl_beats = 3u,
        .has_unix_ns = false,
    };

    cepMailboxTTLResolved resolved = {0};
    munit_assert_true(cep_mailbox_resolve_ttl(&msg_spec,
                                              NULL,
                                              NULL,
                                              &ctx,
                                              &resolved));
    munit_assert_true(resolved.beats_active);
    munit_assert_uint32(resolved.ttl_beats, ==, 3u);
    munit_assert_uint64(resolved.beat_deadline, ==, 4u);
    munit_assert_false(resolved.wallclock_active);

    munit_assert_true(cep_mailbox_record_expiry(board, &digest_name, &resolved));


    test_runtime_shutdown();
}

static void mailbox_expect_private_workflow(const MunitParameter params[]) {
    test_boot_cycle_prepare(params);
    mailbox_runtime_start();

    cepCell* inbox = mailbox_private_direct();
    cepCell* msgs = mailbox_msgs_branch(inbox);

    /* Forever sentinel honoured out of mailbox policy. */
    cepMailboxTTLContext ctx;
    munit_assert_true(cep_mailbox_ttl_context_init(&ctx));
    ctx.issued_has_unix = true;
    ctx.issued_unix_ns = 5000u;
    ctx.current_has_unix = true;
    ctx.current_unix_ns = 5000u;

    cepMailboxTTLSpec forever_spec = {
        .forever = true,
    };

    cepMailboxTTLResolved resolved = {0};
    munit_assert_true(cep_mailbox_resolve_ttl(&forever_spec,
                                              NULL,
                                              NULL,
                                              &ctx,
                                              &resolved));
    munit_assert_true(resolved.is_forever);
    munit_assert_false(resolved.beats_active);
    munit_assert_false(resolved.wallclock_active);

    /* Wallclock-only TTL with heuristics disabled stays wallclock-only. */
    cep_mailbox_disable_wallclock(true);
    cepMailboxTTLSpec wall_spec = {
        .forever = false,
        .has_unix_ns = true,
        .ttl_unix_ns = 7500u,
    };
    cepMailboxTTLResolved wall_resolved = {0};
    munit_assert_true(cep_mailbox_resolve_ttl(&wall_spec,
                                              NULL,
                                              NULL,
                                              &ctx,
                                              &wall_resolved));
    munit_assert_false(wall_resolved.beats_active);
    munit_assert_true(wall_resolved.wallclock_active);
    munit_assert_uint64(wall_resolved.wallclock_deadline, ==, ctx.issued_unix_ns + wall_spec.ttl_unix_ns);
    cep_mailbox_disable_wallclock(false);

    /* Record + plan wallclock expiries. */
    cepCell* wall_env = mailbox_make_envelope("wallclock", true);
    cepMailboxMessageId wall_id = {0};
    munit_assert_true(cep_mailbox_select_message_id(inbox, NULL, wall_env, &wall_id));
    cepDT wall_name = wall_id.id;

    cepCell* message = cep_cell_add_dictionary(msgs,
                                               &wall_name,
                                               0,
                                               CEP_DTAW("CEP", "dictionary"),
                                               CEP_STORAGE_RED_BLACK_T);
    munit_assert_not_null(message);
    mailbox_store_envelope(message, wall_env);
    mailbox_free_envelope(wall_env);

    munit_assert_true(cep_mailbox_record_expiry(inbox, &wall_name, &wall_resolved));

    cepMailboxTTLContext plan_ctx = ctx;
    plan_ctx.current_has_unix = true;
    plan_ctx.current_unix_ns = wall_resolved.wallclock_deadline;


    test_runtime_shutdown();
}

MunitResult test_mailbox_board(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    mailbox_expect_board_workflow(params);
    return MUNIT_OK;
}

MunitResult test_mailbox_private(const MunitParameter params[], void* user_data_or_fixture) {
    (void)user_data_or_fixture;
    mailbox_expect_private_workflow(params);
    return MUNIT_OK;
}
