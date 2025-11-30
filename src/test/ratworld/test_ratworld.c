/* Ratworld API tests: determinism, solvability, renderer, and tick mechanics. */

#include "test.h"
#include "ratworld.h"
#include "ratworld_text.h"

#include <stdlib.h>
#include <string.h>

static ratworldRunConfig test_rw_config(uint64_t seed, ratworldFloorSpec *specs, size_t floor_count)
{
    ratworldRunConfig cfg;

    cfg.run_id = "testrun";
    cfg.seed = seed;
    cfg.floors = specs;
    cfg.floor_count = floor_count;
    cfg.max_rats = 1;
    return cfg;
}

static void test_rw_fill_floor(ratworldTile *tiles, uint32_t w, uint32_t h, ratworldTileType fill)
{
    size_t total = (size_t)w * h;
    for (size_t i = 0; i < total; ++i) {
        tiles[i].type = fill;
        tiles[i].tags = RATWORLD_TILE_TAG_NONE;
    }
}

static void test_rw_write_u64(uint8_t **p, uint64_t v) { memcpy(*p, &v, sizeof(v)); *p += sizeof(v); }
static void test_rw_write_u32(uint8_t **p, uint32_t v) { memcpy(*p, &v, sizeof(v)); *p += sizeof(v); }
static void test_rw_write_u16(uint8_t **p, uint16_t v) { memcpy(*p, &v, sizeof(v)); *p += sizeof(v); }
static void test_rw_write_u8(uint8_t **p, uint8_t v) { memcpy(*p, &v, sizeof(v)); *p += sizeof(v); }
static void test_rw_write_double(uint8_t **p, double v) { memcpy(*p, &v, sizeof(v)); *p += sizeof(v); }

/* Build a manual snapshot with 1 floor and 1 rat so tick mechanics can run on a known map. */
static uint32_t test_rw_checksum32(const uint8_t *data, size_t len)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

static ratworldSnapshot test_rw_build_manual_snapshot(void)
{
    /* Layout:
     * (0,0) EXIT   (1,0) FLOOR   (2,0) FLOOR
     * (0,1) FOOD   (1,1) HOME    (2,1) TRAP
     * (0,2) FLOOR  (1,2) FLOOR   (2,2) FLOOR
     */
    ratworldTile tiles[9];
    uint8_t *buf;
    uint8_t *p;
    ratworldSnapshot snap;
    ratworldActionEconomy econ = {
        .hunger_base_inc = 0.01,
        .hunger_move_inc = 0.01,
        .hunger_food_boost = 0.5,
        .stamina_move_cost = 0.05,
        .stamina_wait_recover = 0.02,
        .stamina_home_recover = 0.1,
        .hunger_home_recover = 0.1,
        .trap_damage = 0.3,
        .hunger_health_cost = 0.05,
    };
    ratworldChallengeManifest manifest = {
        .home_x = 1, .home_y = 1,
        .exit_x = 0, .exit_y = 0,
        .exit_floor = 0,
        .stair_pairs = 0,
    };
    const char *rat_id = "rat0";
    size_t buf_len;
    size_t idx;

    test_rw_fill_floor(tiles, 3, 3, RATWORLD_TILE_FLOOR);
    tiles[0].type = RATWORLD_TILE_EXIT;
    tiles[1].type = RATWORLD_TILE_FLOOR;
    tiles[2].type = RATWORLD_TILE_FLOOR;
    tiles[3].type = RATWORLD_TILE_FOOD;
    tiles[4].type = RATWORLD_TILE_HOME;
    tiles[5].type = RATWORLD_TILE_TRAP;
    tiles[6].type = RATWORLD_TILE_FLOOR;
    tiles[7].type = RATWORLD_TILE_FLOOR;
    tiles[8].type = RATWORLD_TILE_FLOOR;

    buf_len = sizeof(uint32_t) * 2 /* header */ +
              sizeof(uint64_t) * 3 /* seed, tick, rng */ +
              sizeof(uint32_t) * 2 /* floor_count, rat_count */ +
              sizeof(ratworldActionEconomy) +
              sizeof(ratworldChallengeManifest) +
              sizeof(uint32_t) * 2 /* w,h */ +
              (sizeof(uint8_t) + sizeof(uint32_t)) * 9 /* tiles */ +
              sizeof(uint16_t) + strlen(rat_id) /* id */ +
              sizeof(uint32_t) * 3 /* floor_z,x,y */ +
              sizeof(uint8_t) +
              sizeof(double) * 3;
    buf = malloc(buf_len);
    munit_assert_not_null(buf);
    p = buf;
    test_rw_write_u32(&p, RATWORLD_SNAPSHOT_VERSION); /* version */
    uint8_t *checksum_pos = p;
    test_rw_write_u32(&p, 0); /* checksum placeholder */

    uint8_t *payload = p;
    test_rw_write_u64(&p, 1234); /* seed */
    test_rw_write_u64(&p, 0);    /* tick */
    test_rw_write_u64(&p, 0);    /* rng */
    test_rw_write_u32(&p, 1);    /* floors */
    test_rw_write_u32(&p, 1);    /* rats */
    memcpy(p, &econ, sizeof(econ));
    p += sizeof(econ);
    memcpy(p, &manifest, sizeof(manifest));
    p += sizeof(manifest);
    test_rw_write_u32(&p, 3);    /* width */
    test_rw_write_u32(&p, 3);    /* height */
    for (idx = 0; idx < 9; ++idx) {
        test_rw_write_u8(&p, (uint8_t)tiles[idx].type);
        test_rw_write_u32(&p, tiles[idx].tags);
    }
    test_rw_write_u16(&p, (uint16_t)strlen(rat_id));
    memcpy(p, rat_id, strlen(rat_id));
    p += strlen(rat_id);
    test_rw_write_u32(&p, 0); /* floor_z */
    test_rw_write_u32(&p, 1); /* x */
    test_rw_write_u32(&p, 1); /* y */
    test_rw_write_u8(&p, 1);  /* alive */
    test_rw_write_double(&p, 1.0); /* health */
    test_rw_write_double(&p, 1.0); /* stamina */
    test_rw_write_double(&p, 0.0); /* hunger */

    uint32_t checksum = test_rw_checksum32(payload, (size_t)(buf + buf_len - payload));
    memcpy(checksum_pos, &checksum, sizeof(uint32_t));

    snap.seed = 1234;
    snap.tick = 0;
    snap.opaque_state = buf;
    snap.opaque_state_len = buf_len;
    return snap;
}

MunitResult test_ratworld_determinism(const MunitParameter params[], void *fixture)
{
    (void)params;
    (void)fixture;

    ratworldServiceConfig svc_cfg = { .max_runs = 4, .max_rats_per_run = 4, .max_floors = 10 };
    ratworldService *svc = NULL;
    ratworldFloorSpec floor = { .width = 7, .height = 7, .max_food_tiles = 2, .max_trap_tiles = 2, .max_exit_tiles = 1, .allow_cycles = false };
    ratworldRunConfig cfg = test_rw_config(42, &floor, 1);
    ratworldRun *run1 = NULL;
    ratworldRun *run2 = NULL;
    ratworldSnapshot snap1 = {0}, snap2 = {0};

    munit_assert_int(ratworld_service_create(&svc_cfg, &svc), ==, RATWORLD_STATUS_OK);
    munit_assert_int(ratworld_run_create(svc, &cfg, &run1), ==, RATWORLD_STATUS_OK);
    munit_assert_int(ratworld_run_create(svc, &cfg, &run2), ==, RATWORLD_STATUS_OK);

    munit_assert_int(ratworld_run_snapshot(run1, &snap1), ==, RATWORLD_STATUS_OK);
    munit_assert_int(ratworld_run_snapshot(run2, &snap2), ==, RATWORLD_STATUS_OK);
    munit_assert_size(snap1.opaque_state_len, ==, snap2.opaque_state_len);
    munit_assert_memory_equal(snap1.opaque_state_len, snap1.opaque_state, snap2.opaque_state);

    ratworld_snapshot_release(&snap1);
    ratworld_snapshot_release(&snap2);
    ratworld_run_destroy(run1);
    ratworld_run_destroy(run2);
    ratworld_service_destroy(svc);
    return MUNIT_OK;
}

MunitResult test_ratworld_solvable(const MunitParameter params[], void *fixture)
{
    (void)params;
    (void)fixture;

    ratworldServiceConfig svc_cfg = { .max_runs = 4, .max_rats_per_run = 4, .max_floors = 10 };
    ratworldService *svc = NULL;
    ratworldFloorSpec floors[2] = {
        {.width = 7, .height = 7, .max_food_tiles = 1, .max_trap_tiles = 1, .max_exit_tiles = 0, .allow_cycles = false},
        {.width = 7, .height = 7, .max_food_tiles = 0, .max_trap_tiles = 0, .max_exit_tiles = 1, .allow_cycles = false},
    };
    ratworldRunConfig cfg = test_rw_config(99, floors, 2);
    ratworldRun *run = NULL;
    munit_assert_int(ratworld_service_create(&svc_cfg, &svc), ==, RATWORLD_STATUS_OK);
    munit_assert_int(ratworld_run_create(svc, &cfg, &run), ==, RATWORLD_STATUS_OK);

    /* BFS from HOME to EXIT using public floor accessors. */
    size_t total = 0;
    for (size_t f = 0; f < cfg.floor_count; ++f) {
        total += (size_t)floors[f].width * floors[f].height;
    }
    uint8_t *visited = calloc(total, 1);
    munit_assert_not_null(visited);
    typedef struct { uint32_t f, x, y; } node;
    node *queue = malloc(total * sizeof(*queue));
    munit_assert_not_null(queue);
    size_t qh = 0, qt = 0;

    const ratworldTile *tiles0 = NULL;
    uint32_t w0 = 0, h0 = 0;
    munit_assert_int(ratworld_run_get_floor(run, 0, &tiles0, &w0, &h0), ==, RATWORLD_STATUS_OK);
    size_t start_idx = 0;
    for (size_t i = 0; i < (size_t)w0 * h0; ++i) {
        if (tiles0[i].type == RATWORLD_TILE_HOME) {
            start_idx = i;
            break;
        }
    }
    queue[qt++] = (node){0, (uint32_t)(start_idx % w0), (uint32_t)(start_idx / w0)};
    int found = 0;
    while (qh < qt && !found) {
        node cur = queue[qh++];
        const ratworldTile *tiles = NULL;
        uint32_t w = 0, h = 0;
        munit_assert_int(ratworld_run_get_floor(run, cur.f, &tiles, &w, &h), ==, RATWORLD_STATUS_OK);
        size_t base = 0;
        for (size_t f = 0; f < cur.f; ++f) {
            base += (size_t)floors[f].width * floors[f].height;
        }
        size_t gidx = base + (size_t)cur.y * w + cur.x;
        if (visited[gidx]) continue;
        visited[gidx] = 1;
        if (tiles[(size_t)cur.y * w + cur.x].type == RATWORLD_TILE_EXIT) {
            found = 1;
            break;
        }
        const int dx[4] = {1,-1,0,0};
        const int dy[4] = {0,0,1,-1};
        for (int d = 0; d < 4; ++d) {
            int32_t nx = (int32_t)cur.x + dx[d];
            int32_t ny = (int32_t)cur.y + dy[d];
            if (nx < 0 || ny < 0 || nx >= (int32_t)w || ny >= (int32_t)h) continue;
            ratworldTileType t = tiles[(size_t)ny * w + (size_t)nx].type;
            if (t != RATWORLD_TILE_WALL) {
                queue[qt++] = (node){cur.f, (uint32_t)nx, (uint32_t)ny};
            }
        }
        ratworldTileType here = tiles[(size_t)cur.y * w + cur.x].type;
        if (here == RATWORLD_TILE_STAIR_UP && cur.f + 1 < cfg.floor_count) {
            queue[qt++] = (node){cur.f + 1, cur.x, cur.y};
        }
        if (here == RATWORLD_TILE_STAIR_DOWN && cur.f > 0) {
            queue[qt++] = (node){cur.f - 1, cur.x, cur.y};
        }
    }
    free(queue);
    free(visited);
    ratworld_run_destroy(run);
    ratworld_service_destroy(svc);
    munit_assert_true(found != 0);
    return MUNIT_OK;
}

MunitResult test_ratworld_renderer(const MunitParameter params[], void *fixture)
{
    (void)params;
    (void)fixture;
    ratworldTile tiles[6];
    ratworldTextFloor floor;
    ratworldTextGlyphs glyphs;
    ratworldRatState rats[1];
    char buffer[32];
    const char *expected = ".@^\nH>%\n";

    test_rw_fill_floor(tiles, 3, 2, RATWORLD_TILE_FLOOR);
    tiles[1].type = RATWORLD_TILE_STAIR_UP;
    tiles[2].type = RATWORLD_TILE_TRAP;
    tiles[3].type = RATWORLD_TILE_HOME;
    tiles[4].type = RATWORLD_TILE_EXIT;
    tiles[5].type = RATWORLD_TILE_FOOD;

    floor.width = 3;
    floor.height = 2;
    floor.floor_z = 0;
    floor.tiles = tiles;

    ratworld_text_default_glyphs(&glyphs);
    rats[0].rat_id = "rat0";
    rats[0].floor_z = 0;
    rats[0].x = 1;
    rats[0].y = 0;
    rats[0].alive = true;

    munit_assert_int(ratworld_text_render_floor(&floor, &glyphs, rats, 1, buffer, sizeof(buffer)), ==, RATWORLD_STATUS_OK);
    munit_assert_string_equal(buffer, expected);
    return MUNIT_OK;
}

MunitResult test_ratworld_tick_mechanics(const MunitParameter params[], void *fixture)
{
    (void)params;
    (void)fixture;

    ratworldServiceConfig svc_cfg = { .max_runs = 2, .max_rats_per_run = 2, .max_floors = 10 };
    ratworldService *svc = NULL;
    ratworldFloorSpec floor = { .width = 3, .height = 3, .max_food_tiles = 0, .max_trap_tiles = 0, .max_exit_tiles = 0, .allow_cycles = false };
    ratworldRunConfig cfg = test_rw_config(1234, &floor, 1);
    ratworldSnapshot snap = test_rw_build_manual_snapshot();
    ratworldRun *run = NULL;
    ratworldEvent events[8];
    ratworldEventBuffer evbuf = { events, 0, 8 };
    ratworldObservation obs[4];
    ratworldObservationBuffer obuf = { obs, 0, 4 };
    ratworldRunState state;
    ratworldAction action = { .rat_id = "rat0", .kind = RATWORLD_ACTION_MOVE_E };

    munit_assert_int(ratworld_service_create(&svc_cfg, &svc), ==, RATWORLD_STATUS_OK);
    /* Branch from manual snapshot to control tiles/rat position. */
    munit_assert_int(ratworld_run_branch(svc, &snap, &cfg, &run), ==, RATWORLD_STATUS_OK);

    munit_assert_int(ratworld_run_stage_actions(run, &action, 1), ==, RATWORLD_STATUS_OK);
    munit_assert_int(ratworld_run_tick(run, &evbuf, &obuf, &state), ==, RATWORLD_STATUS_OK);
    munit_assert_size(evbuf.event_count, >=, 2);
    munit_assert_size(obuf.observation_count, ==, 1);
    munit_assert_int(obuf.items[0].x, ==, 2);
    munit_assert_int(obuf.items[0].y, ==, 1);
    munit_assert_double_equal(obuf.items[0].health, 0.7, 12);
    munit_assert_double_equal(obuf.items[0].stamina, 0.95, 12);
    munit_assert_double_equal(obuf.items[0].hunger, 0.02, 12);

    evbuf.event_count = 0;
    obuf.observation_count = 0;
    action.kind = RATWORLD_ACTION_WAIT;
    munit_assert_int(ratworld_run_stage_actions(run, &action, 1), ==, RATWORLD_STATUS_OK);
    munit_assert_int(ratworld_run_tick(run, &evbuf, &obuf, &state), ==, RATWORLD_STATUS_OK);
    munit_assert_double_equal(obuf.items[0].stamina, 0.97, 12);
    munit_assert_double_equal(obuf.items[0].hunger, 0.03, 12);

    ratworld_run_destroy(run);
    ratworld_snapshot_release(&snap);
    ratworld_service_destroy(svc);
    return MUNIT_OK;
}
#include <inttypes.h>
