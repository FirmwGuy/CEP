/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


/*
 *  CEP Name Pool - Interned string support for CEP_NAMING_REFERENCE.
 */

#include "cep_namepool.h"
#include "cep_cei.h"
#include "cep_heartbeat.h"
#include "cep_organ.h"
#include "cep_runtime.h"
#include "cep_namepool_runtime.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <stdarg.h>
#include <inttypes.h>

CEP_DEFINE_STATIC_DT(dt_dictionary_type, CEP_ACRO("CEP"), CEP_WORD("dictionary"));
CEP_DEFINE_STATIC_DT(dt_text_type, CEP_ACRO("CEP"), CEP_WORD("text"));
CEP_DEFINE_STATIC_DT(dt_sys_root_name, CEP_ACRO("CEP"), CEP_WORD("sys"));
CEP_DEFINE_STATIC_DT(dt_namepool_root_name, CEP_ACRO("CEP"), CEP_WORD("namepool"));
CEP_DEFINE_STATIC_DT(dt_sev_namepool_crit, CEP_ACRO("CEP"), CEP_WORD("sev:crit"));

#define CEP_NAMEPOOL_MAX_LENGTH          256u
#define CEP_NAMEPOOL_SLOT_BITS           12u
#define CEP_NAMEPOOL_SLOTS_PER_PAGE      (1u << CEP_NAMEPOOL_SLOT_BITS)
#define CEP_NAMEPOOL_SLOT_MASK           (CEP_NAMEPOOL_SLOTS_PER_PAGE - 1u)
#define CEP_NAMEPOOL_INITIAL_BUCKETS     64u

typedef struct {
    cepID       id;
    uint32_t    page;
    uint32_t    slot;
    uint64_t    hash;
    size_t      length;
    const char* bytes;
    cepCell*    cell;
    uint32_t    refcount;
    bool        is_static;
    bool        glob;
} cepNamePoolEntry;

typedef struct {
    cepNamePoolEntry entries[CEP_NAMEPOOL_SLOTS_PER_PAGE];
} cepNamePoolPage;

typedef struct {
    uint64_t            hash;
    cepNamePoolEntry*   entry;
} cepNamePoolBucket;

typedef struct cepNamePoolRuntimeState {
    cepNamePoolPage**   pages;
    size_t              page_count;
    size_t              page_cap;
    cepNamePoolBucket*  buckets;
    size_t              bucket_cap;
    size_t              bucket_count;
    size_t              bucket_threshold;
    cepCell*            root;
} cepNamePoolRuntimeState;

static cepNamePoolRuntimeState*
cep_namepool_state(void)
{
    cepNamePoolRuntimeState* state = cep_runtime_namepool_state(cep_runtime_default());
    CEP_ASSERT(state);
    return state;
}

#define name_pages            (cep_namepool_state()->pages)
#define name_page_count       (cep_namepool_state()->page_count)
#define name_page_cap         (cep_namepool_state()->page_cap)
#define name_buckets          (cep_namepool_state()->buckets)
#define name_bucket_cap       (cep_namepool_state()->bucket_cap)
#define name_bucket_count     (cep_namepool_state()->bucket_count)
#define name_bucket_threshold (cep_namepool_state()->bucket_threshold)
#define namepool_root         (cep_namepool_state()->root)

/* Namepool bootstrap runs before the diagnostics mailbox exists; guard CEI
   emissions until the kernel scope is ready so bootstrap callers do not trip
   fatal diagnostics while the runtime wiring is incomplete. */
static bool cep_namepool_can_emit_cei(void) {
    return cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL);
}

/* Emit a diagnostics fact describing a namepool failure. The helper selects the
   diagnostics mailbox, formats the note, and attaches the namepool root when
   available so dashboards can pivot straight to the failing subject. */
static void cep_namepool_emit_failure(const char* topic, const char* detail_fmt, ...) {
    if (!topic || !detail_fmt) {
        return;
    }
    if (!cep_namepool_can_emit_cei()) {
        return;
    }

    char note[256];
    va_list args;
    va_start(args, detail_fmt);
    vsnprintf(note, sizeof note, detail_fmt, args);
    va_end(args);

    cepCell* subject = namepool_root ? cep_link_pull(namepool_root) : NULL;
    if (!subject) {
        subject = namepool_root;
    }

    cepCeiRequest req = {
        .severity = *dt_sev_namepool_crit(),
        .note = note,
        .topic = topic,
        .topic_intern = true,
        .subject = subject,
        .emit_signal = true,
        .ttl_forever = true,
    };
    (void)cep_cei_emit(&req);
}

static cepID cep_namepool_try_compact(const char* text, size_t length) {
    if (!text || length == 0u) {
        return 0;
    }

    uint64_t value = 0u;
    bool is_numeric = true;
    for (size_t i = 0; i < length; ++i) {
        char c = text[i];
        if (c < '0' || c > '9') {
            is_numeric = false;
            break;
        }
        uint64_t digit = (uint64_t)(c - '0');
        if (value > (CEP_AUTOID_MAX - digit) / 10u) {
            is_numeric = false;
            break;
        }
        value = value * 10u + digit;
    }

    if (is_numeric && value > 0u && value <= CEP_AUTOID_MAX && value != cep_id(CEP_AUTOID)) {
        return cep_id_to_numeric((cepID)value);
    }

    if (length <= CEP_WORD_MAX_CHARS) {
        char buffer[CEP_WORD_MAX_CHARS + 1u];
        memcpy(buffer, text, length);
        buffer[length] = '\0';
        cepID word = cep_text_to_word(buffer);
        if (word) {
            return word;
        }
    }

    if (length <= 9u) {
        char buffer[10u];
        memcpy(buffer, text, length);
        buffer[length] = '\0';
        cepID acro = cep_text_to_acronym(buffer);
        if (acro) {
            return acro;
        }
    }

    return 0;
}

static inline cepID cep_namepool_make_id(uint64_t page, uint32_t slot) {
    uint64_t payload = ((page + 1ull) << CEP_NAMEPOOL_SLOT_BITS) | ((uint64_t)slot + 1ull);
    payload &= CEP_AUTOID_MAXVAL;
    if (!payload) {
        payload = 1ull;
    }
    return (cepID)(payload | cep_id_from_naming(CEP_NAMING_REFERENCE));
}

static inline bool cep_namepool_decode(cepID id, uint64_t* page_out, uint32_t* slot_out) {
    uint64_t payload = cep_id(id);
    if (!payload) {
        return false;
    }

    uint64_t page = payload >> CEP_NAMEPOOL_SLOT_BITS;
    uint64_t slot = payload & CEP_NAMEPOOL_SLOT_MASK;

    if (page == 0u || slot == 0u) {
        return false;
    }

    if (page_out) {
        *page_out = page - 1u;
    }
    if (slot_out) {
        *slot_out = (uint32_t)(slot - 1u);
    }

    return true;
}

static bool cep_namepool_reserve_pages(size_t capacity) {
    if (capacity <= name_page_cap) {
        return true;
    }

    size_t new_cap = name_page_cap ? name_page_cap : 4u;
    while (new_cap < capacity) {
        new_cap <<= 1u;
    }

    cepNamePoolPage** pages = name_pages ? cep_realloc(name_pages, new_cap * sizeof(*pages)) : cep_malloc(new_cap * sizeof(*pages));
    if (!pages) {
        cep_namepool_emit_failure("namepool.pages.alloc",
                                  "failed to grow page array to %zu entries",
                                  new_cap);
        return false;
    }

    for (size_t i = name_page_cap; i < new_cap; ++i) {
        pages[i] = NULL;
    }

    name_pages = pages;
    name_page_cap = new_cap;
    return true;
}

static bool cep_namepool_allocate_page(size_t index) {
    if (index < name_page_count && name_pages[index]) {
        return true;
    }

    if (!cep_namepool_reserve_pages(index + 1u)) {
        return false;
    }

    cepNamePoolPage* page = cep_malloc0(sizeof(*page));
    if (!page) {
        cep_namepool_emit_failure("namepool.page.alloc",
                                  "failed to allocate page index=%zu",
                                  index);
        return false;
    }

    name_pages[index] = page;
    if (index >= name_page_count) {
        name_page_count = index + 1u;
    }
    return true;
}

static bool cep_namepool_reserve_buckets(size_t capacity) {
    if (capacity <= name_bucket_cap) {
        return true;
    }

    size_t new_cap = name_bucket_cap ? name_bucket_cap : CEP_NAMEPOOL_INITIAL_BUCKETS;
    while (new_cap < capacity) {
        new_cap <<= 1u;
    }

    cepNamePoolBucket* buckets = cep_malloc0(new_cap * sizeof(*buckets));
    if (!buckets) {
        cep_namepool_emit_failure("namepool.buckets.alloc",
                                  "failed to grow bucket table to %zu entries",
                                  new_cap);
        return false;
    }

    size_t migrated = 0u;
    if (name_buckets) {
        for (size_t i = 0; i < name_bucket_cap; ++i) {
            cepNamePoolBucket* bucket = &name_buckets[i];
            if (bucket->entry) {
                size_t mask = new_cap - 1u;
                size_t idx = (size_t)bucket->hash & mask;
                while (buckets[idx].entry) {
                    idx = (idx + 1u) & mask;
                }
                buckets[idx] = *bucket;
                migrated += 1u;
            }
        }
        cep_free(name_buckets);
    }

    name_buckets = buckets;
    name_bucket_cap = new_cap;
    name_bucket_count = migrated;
    name_bucket_threshold = (new_cap * 3u) / 4u;
    if (name_bucket_threshold == 0u) {
        name_bucket_threshold = new_cap - 1u;
    }
    return true;
}

static void cep_namepool_clear_entry(cepNamePoolEntry* entry) {
    if (!entry) {
        return;
    }
    if (!entry->is_static && entry->bytes) {
        cep_free((void*)entry->bytes);
    }
    entry->id = 0;
    entry->page = 0;
    entry->slot = 0;
    entry->hash = 0;
    entry->length = 0;
    entry->bytes = NULL;
    entry->cell = NULL;
    entry->refcount = 0;
    entry->is_static = false;
    entry->glob = false;
}

static void cep_namepool_remove_bucket(size_t index) {
    if (!name_buckets || name_bucket_cap == 0u) {
        return;
    }

    size_t mask = name_bucket_cap - 1u;
    cepNamePoolBucket* bucket = &name_buckets[index];
    if (!bucket->entry) {
        return;
    }

    bucket->entry = NULL;
    bucket->hash = 0u;
    if (name_bucket_count) {
        name_bucket_count -= 1u;
    }

    size_t next = (index + 1u) & mask;
    while (name_buckets[next].entry) {
        cepNamePoolEntry* entry = name_buckets[next].entry;
        uint64_t hash = name_buckets[next].hash;
        name_buckets[next].entry = NULL;
        name_buckets[next].hash = 0u;
        if (name_bucket_count) {
            name_bucket_count -= 1u;
        }

        size_t dest = (size_t)hash & mask;
        while (name_buckets[dest].entry) {
            dest = (dest + 1u) & mask;
        }
        name_buckets[dest].entry = entry;
        name_buckets[dest].hash = hash;
        name_bucket_count += 1u;

        next = (next + 1u) & mask;
    }
}

static cepCell* cep_namepool_ensure_dictionary(cepCell* parent, const cepDT* name) {
    if (!parent || !name) {
        return NULL;
    }

    cepDT lookup = cep_dt_clean(name);
    lookup.glob = 0u;

    cepCell* stored = cep_cell_find_by_name(parent, &lookup);
    bool revived = false;
    if (!stored) {
        stored = cep_cell_find_by_name_all(parent, &lookup);
        if (stored) {
            revived = true;
        }
    }

    if (!stored) {
        cepDT dict_type = *dt_dictionary_type();
        cepDT name_copy = lookup;
        stored = cep_cell_add_dictionary(parent, &name_copy, 0, &dict_type, CEP_STORAGE_RED_BLACK_T);
        if (!stored) {
            return NULL;
        }
    }

    cepCell* resolved = stored;
    if (!cep_cell_require_dictionary_store(&resolved)) {
        return NULL;
    }

    cepStore* store = resolved->store;
    if (store) {
        if (store->owner != resolved) {
            store->owner = resolved;
        }
        if (!store->writable) {
            store->writable = 1u;
        }
        if (store->lock) {
            store->lock = 0u;
            store->lockOwner = NULL;
        }
        if (revived) {
            cepDT dict_type = *dt_dictionary_type();
            cep_store_set_dt(store, &dict_type);
        }
        if (!store->created) {
            store->created = resolved->created ? resolved->created : cep_cell_timestamp_next();
        }
        if (store->deleted) {
            store->deleted = 0u;
        }
        if (store->autoid == 0u) {
            store->autoid = 1u;
        }
    }

    if (cep_cell_is_veiled(resolved)) {
        resolved->metacell.veiled = 0u;
    }
    if (!resolved->created) {
        resolved->created = store && store->created ? store->created : cep_cell_timestamp_next();
    }
    if (resolved->deleted) {
        resolved->deleted = 0u;
    }

    return resolved;
}

static bool cep_namepool_store_entry(cepNamePoolEntry* entry, const char* text, size_t length) {
    if (!namepool_root) {
        cep_namepool_emit_failure("namepool.store.uninitialised",
                                  "attempted to store entry before bootstrap (page=%u slot=%u)",
                                  (unsigned)entry->page,
                                  (unsigned)entry->slot);
        return false;
    }

    cepDT page_name = {
        .domain = CEP_ACRO("NP"),
        .tag    = cep_id_to_numeric((cepID)(entry->page + 1u)),
    };
    cepCell* page_cell = cep_namepool_ensure_dictionary(namepool_root, &page_name);
    if (!page_cell) {
        cep_namepool_emit_failure("namepool.store.page",
                                  "failed to ensure page cell page=%u",
                                  (unsigned)entry->page);
        return false;
    }

    cepDT slot_name = {
        .domain = CEP_ACRO("NP"),
        .tag    = cep_id_to_numeric((cepID)(entry->slot + 1u)),
    };

    char* copy = cep_malloc(length + 1u);
    if (!copy) {
        cep_namepool_emit_failure("namepool.store.alloc",
                                  "failed to duplicate name (len=%zu)",
                                  length);
        return false;
    }
    memcpy(copy, text, length);
    copy[length] = '\0';

    cepDT slot_name_copy = slot_name;
    cepDT text_type = *dt_text_type();
    cepCell* value_cell = cep_cell_add_data(page_cell,
        &slot_name_copy,
        0,
        &text_type,
        copy,
        length,
        length + 1u,
        NULL
    );

    if (!value_cell || !cep_cell_has_data(value_cell)) {
        cep_free(copy);
        cep_namepool_emit_failure("namepool.store.slot",
                                  "failed to add slot cell page=%u slot=%u",
                                  (unsigned)entry->page,
                                  (unsigned)entry->slot);
        return false;
    }

    cepCell* resolved = cep_cell_resolve(value_cell);
    if (!resolved || !cep_cell_has_data(resolved)) {
        cep_cell_remove_hard(value_cell, NULL);
        cep_free(copy);
        cep_namepool_emit_failure("namepool.store.resolve",
                                  "failed to resolve slot cell page=%u slot=%u",
                                  (unsigned)entry->page,
                                  (unsigned)entry->slot);
        return false;
    }

    cepData* stored = resolved->data;
    if (!stored) {
        cep_cell_remove_hard(resolved, NULL);
        cep_free(copy);
        cep_namepool_emit_failure("namepool.store.payload",
                                  "resolved slot missing payload page=%u slot=%u",
                                  (unsigned)entry->page,
                                  (unsigned)entry->slot);
        return false;
    }

    entry->cell = resolved;
    entry->bytes = copy;
    entry->length = length;
    entry->refcount = 1u;
    entry->is_static = false;

    return entry->bytes != NULL;
}

static cepCell*
cep_namepool_locate_slot_cell(uint64_t page_index, uint32_t slot_index)
{
    if (!namepool_root) {
        return NULL;
    }

    cepCell* root = cep_cell_resolve(namepool_root);
    if (!root) {
        return NULL;
    }
    cepCell* resolved_root = root;
    if (!cep_cell_require_dictionary_store(&resolved_root)) {
        return NULL;
    }

    cepDT page_name = {
        .domain = CEP_ACRO("NP"),
        .tag = cep_id_to_numeric((cepID)(page_index + 1u)),
    };
    cepCell* page_cell = cep_cell_find_by_name(resolved_root, &page_name);
    if (!page_cell) {
        return NULL;
    }
    page_cell = cep_cell_resolve(page_cell);
    if (!page_cell) {
        return NULL;
    }
    if (!cep_cell_require_dictionary_store(&page_cell)) {
        return NULL;
    }

    cepDT slot_name = {
        .domain = CEP_ACRO("NP"),
        .tag = cep_id_to_numeric((cepID)(slot_index + 1u)),
    };
    cepCell* slot_cell = cep_cell_find_by_name(page_cell, &slot_name);
    if (!slot_cell) {
        return NULL;
    }
    return cep_cell_resolve(slot_cell);
}

static cepNamePoolEntry* cep_namepool_new_entry(uint64_t hash, const char* text, size_t length, bool is_static, bool glob) {
    size_t page_index = 0u;
    uint32_t slot_index = 0u;

    for (size_t p = 0; p < name_page_count; ++p) {
        cepNamePoolPage* page = name_pages[p];
        if (!page) {
            continue;
        }
        for (uint32_t s = 0; s < CEP_NAMEPOOL_SLOTS_PER_PAGE; ++s) {
            if (page->entries[s].id == 0) {
                page_index = p;
                slot_index = s;
                goto SLOT_FOUND;
            }
        }
    }

    page_index = name_page_count;
    if (!cep_namepool_allocate_page(page_index)) {
        return NULL;
    }
    slot_index = 0u;

SLOT_FOUND:
    if (!name_pages[page_index]) {
        cep_namepool_emit_failure("namepool.page.missing",
                                  "page %zu missing after allocation",
                                  page_index);
        return NULL;
    }

    cepNamePoolEntry* entry = &name_pages[page_index]->entries[slot_index];
    memset(entry, 0, sizeof(*entry));
    entry->page = (uint32_t)page_index;
    entry->slot = slot_index;
    entry->hash = hash;
    entry->length = length;
    entry->glob = glob;

    if (is_static) {
        entry->bytes = text;
        entry->cell = NULL;
        entry->refcount = UINT32_MAX;
        entry->is_static = true;
    } else {
        if (!cep_namepool_store_entry(entry, text, length)) {
            memset(entry, 0, sizeof(*entry));
            cep_namepool_emit_failure("namepool.entry.store",
                                      "failed to store entry (len=%zu)",
                                      length);
            return NULL;
        }
    }

    entry->id = cep_namepool_make_id(page_index, slot_index);
    return entry;
}

static cepID cep_namepool_intern_common(const char* text, size_t length, bool is_static, bool mark_glob) {
    if (!text || length == 0u || length > CEP_NAMEPOOL_MAX_LENGTH) {
        return 0;
    }

    if (!mark_glob) {
        cepID compact = cep_namepool_try_compact(text, length);
        if (compact) {
            return compact;
        }
    }

    if (!cep_namepool_bootstrap()) {
        cep_namepool_emit_failure("namepool.bootstrap.fail",
                                  "bootstrap failed while interning len=%zu",
                                  length);
        CEP_DEBUG_PRINTF_STDOUT("[namepool] bootstrap failed while interning '%.*s'\n",
                                (int)length,
                                text ? text : "");
        return 0;
    }

    if (name_bucket_cap == 0u) {
        if (!cep_namepool_reserve_buckets(CEP_NAMEPOOL_INITIAL_BUCKETS)) {
            cep_namepool_emit_failure("namepool.buckets.init",
                                      "initial bucket reserve failed len=%zu",
                                      length);
            CEP_DEBUG_PRINTF_STDOUT("[namepool] reserve buckets failed initial for '%.*s'\n",
                                    (int)length,
                                    text ? text : "");
            return 0;
        }
    }

    uint64_t hash = cep_hash_bytes(text, length);
    bool glob_hint = mark_glob;

    if (name_bucket_count >= name_bucket_threshold) {
        if (!cep_namepool_reserve_buckets(name_bucket_cap ? (name_bucket_cap << 1u) : CEP_NAMEPOOL_INITIAL_BUCKETS)) {
            cep_namepool_emit_failure("namepool.buckets.grow",
                                      "bucket growth failed current=%zu threshold=%zu",
                                      name_bucket_cap,
                                      name_bucket_threshold);
            CEP_DEBUG_PRINTF_STDOUT("[namepool] grow buckets failed for '%.*s'\n",
                                    (int)length,
                                    text ? text : "");
            return 0;
        }
    }

    size_t mask = name_bucket_cap - 1u;
    size_t index = (size_t)hash & mask;

    while (true) {
        cepNamePoolBucket* bucket = &name_buckets[index];
        if (!bucket->entry) {
            cepNamePoolEntry* entry = cep_namepool_new_entry(hash, text, length, is_static, glob_hint);
            if (!entry) {
                CEP_DEBUG_PRINTF_STDOUT("[namepool] new entry failed for '%.*s'\n",
                                        (int)length,
                                        text ? text : "");
                return 0;
            }
            bucket->hash = hash;
            bucket->entry = entry;
            name_bucket_count += 1u;
            return entry->id;
        }

        if (bucket->hash == hash) {
            cepNamePoolEntry* entry = bucket->entry;
            if (entry && entry->glob == glob_hint && entry->length == length && memcmp(entry->bytes, text, length) == 0) {
                if (!entry->is_static && entry->refcount < UINT32_MAX) {
                    entry->refcount += 1u;
                }
                return entry->id;
            }
        }

        index = (index + 1u) & mask;
    }
}

static cepNamePoolEntry* cep_namepool_lookup_entry(cepID id) {
    if (!cep_id_is_reference(id)) {
        return NULL;
    }

    uint64_t page = 0u;
    uint32_t slot = 0u;
    if (!cep_namepool_decode(id, &page, &slot)) {
        return NULL;
    }

    if (page >= name_page_count) {
        return NULL;
    }

    cepNamePoolPage* page_ptr = name_pages[page];
    if (!page_ptr) {
        return NULL;
    }

    cepNamePoolEntry* entry = &page_ptr->entries[slot];
    if (entry->id != id) {
        return NULL;
    }

    return entry;
}

/** Ensure the name pool backing structures exist so reference IDs can be
    issued on demand. Subsequent calls are cheap and simply confirm the state. */
bool cep_namepool_bootstrap(void) {
    if (namepool_root) {
        return true;
    }

    cep_cell_system_ensure();

    cepCell* root = cep_root();
    if (!root) {
        cep_namepool_emit_failure("namepool.bootstrap.root",
                                  "cep_root unavailable during bootstrap");
        return false;
    }

    cepDT sys_name = *dt_sys_root_name();
    cepCell* sys = cep_namepool_ensure_dictionary(root, &sys_name);
    if (!sys) {
        cep_namepool_emit_failure("namepool.bootstrap.sys",
                                  "failed to create /sys for namepool");
        return false;
    }

    cepDT pool_name = *dt_namepool_root_name();
    cepCell* pool = cep_namepool_ensure_dictionary(sys, &pool_name);
    if (!pool) {
        cep_namepool_emit_failure("namepool.bootstrap.pool",
                                  "failed to ensure /sys/namepool");
        return false;
    }

    namepool_root = pool;

    if (pool->store) {
        cepDT pool_store = cep_organ_store_dt("sys_namepool");
        cep_store_set_dt(pool->store, &pool_store);
    }
    (void)cep_lifecycle_scope_mark_ready(CEP_LIFECYCLE_SCOPE_NAMEPOOL);
    return true;
}

/** Intern a UTF-8 buffer and return a CEP_NAMING_REFERENCE identifier, compact
    encoding to word/acronym/numeric when possible before falling back to the
    pool. */
cepID cep_namepool_intern(const char* text, size_t length) {
    return cep_namepool_intern_common(text, length, false, false);
}

/** Convenience wrapper around cep_namepool_intern for null-terminated strings. */
cepID cep_namepool_intern_cstr(const char* text) {
    if (!text) {
        return 0;
    }
    cepID id = cep_namepool_intern(text, strlen(text));
    if (!id) {
        CEP_DEBUG_PRINTF_STDOUT("[namepool] intern_cstr failed text='%s'\n", text ? text : "<null>");
    }
    return id;
}

/** Register a static caller-owned string without copying it into the pool so
    adapters can reference compile-time text cheaply. */
cepID cep_namepool_intern_static(const char* text, size_t length) {
    return cep_namepool_intern_common(text, length, true, false);
}

/** Offer the wildcard-friendly variant of namepool interning so call sites can
    request glob semantics explicitly while still reusing the shared storage. */
cepID cep_namepool_intern_pattern(const char* text, size_t length) {
    return cep_namepool_intern_common(text, length, false, true);
}

/** Null-terminated helper that mirrors cep_namepool_intern_pattern for callers
    who build pattern strings at runtime without separately tracking lengths. */
cepID cep_namepool_intern_pattern_cstr(const char* text) {
    if (!text) {
        return 0;
    }
    return cep_namepool_intern_common(text, strlen(text), false, true);
}

/** Static counterpart for pattern strings so compile-time constants can be
    registered once and reused without copying the underlying bytes. */
cepID cep_namepool_intern_pattern_static(const char* text, size_t length) {
    return cep_namepool_intern_common(text, length, true, true);
}

/** Resolve a reference ID back into its stored bytes, returning the length when
    requested so callers can avoid strlen() on binary data. */
const char* cep_namepool_lookup(cepID id, size_t* length) {
    cepNamePoolEntry* entry = cep_namepool_lookup_entry(id);
    if (!entry) {
        return NULL;
    }
    if (length) {
        *length = entry->length;
    }
    return entry->bytes;
}

/** Decrement the reference count for @p id and reclaim the slot when the count
    reaches zero, allowing dynamic names to disappear once no consumers remain. */
bool cep_namepool_release(cepID id) {
    if (!cep_id_is_reference(id)) {
        return true;
    }

    cepNamePoolEntry* entry = cep_namepool_lookup_entry(id);
    if (!entry) {
        return false;
    }

    if (entry->is_static) {
        return true;
    }

    if (entry->refcount > 1u) {
        entry->refcount -= 1u;
        return true;
    }

    uint64_t page = 0u;
    uint32_t slot = 0u;
    if (!cep_namepool_decode(id, &page, &slot)) {
        return false;
    }

    cepCell* slot_cell = cep_namepool_locate_slot_cell(page, slot);
    if (slot_cell) {
        cep_cell_remove_hard(slot_cell, NULL);
    }
    entry->cell = NULL;

    if (name_buckets && name_bucket_cap) {
        size_t mask = name_bucket_cap - 1u;
        size_t index = (size_t)entry->hash & mask;
        while (name_buckets[index].entry) {
            if (name_buckets[index].entry == entry) {
                cep_namepool_remove_bucket(index);
                break;
            }
            index = (index + 1u) & mask;
        }
    }

    if (page < name_page_count && name_pages[page]) {
        cepNamePoolEntry* slot_entry = &name_pages[page]->entries[slot];
        if (slot_entry == entry) {
            cep_namepool_clear_entry(slot_entry);
        }
    }

    return true;
}

/** Report whether the given reference identifier carries the glob intent flag
    so pattern-aware lookups can defer to text matching only when requested. */
bool cep_namepool_reference_is_glob(cepID id) {
    cepNamePoolEntry* entry = cep_namepool_lookup_entry(id);
    if (!entry) {
        return false;
    }
    return entry->glob;
}

static void cep_namepool_free_pages(void) {
    if (!name_pages) {
        return;
    }

    for (size_t i = 0; i < name_page_count; ++i) {
        cepNamePoolPage* page = name_pages[i];
        if (!page) {
            continue;
        }
        for (size_t slot = 0u; slot < CEP_NAMEPOOL_SLOTS_PER_PAGE; ++slot) {
            cep_namepool_clear_entry(&page->entries[slot]);
        }
        CEP_DEBUG_PRINTF_STDOUT("[namepool:page_free] index=%zu page=%p\n", i, (void*)page);
        cep_free(page);
        name_pages[i] = NULL;
    }
    cep_free(name_pages);
    name_pages = NULL;
    name_page_count = 0u;
    name_page_cap = 0u;
}

static void cep_namepool_free_buckets(void) {
    if (!name_buckets) {
        return;
    }
    CEP_DEBUG_PRINTF_STDOUT("[namepool:buckets_free] table=%p cap=%zu count=%zu\n",
           (void*)name_buckets,
           name_bucket_cap,
           name_bucket_count);
    cep_free(name_buckets);
    name_buckets = NULL;
    name_bucket_cap = 0u;
    name_bucket_count = 0u;
    name_bucket_threshold = 0u;
}

void cep_namepool_clear_cache(void) {
    CEP_DEBUG_PRINTF_STDOUT("[namepool:clear_cache] root=%p pages=%p bucketTable=%p\n",
           (void*)namepool_root,
           (void*)name_pages,
           (void*)name_buckets);
    cep_namepool_free_pages();
    cep_namepool_free_buckets();
}

/** Reset cached namepool metadata so a fresh bootstrap can rebuild dictionaries
    after the cell system shuts down. */
void cep_namepool_reset(void) {
    CEP_DEBUG_PRINTF_STDOUT("[namepool:reset] root=%p pages=%p pageCount=%zu bucketTable=%p bucketCap=%zu bucketCount=%zu threshold=%zu\n",
           (void*)namepool_root,
           (void*)name_pages,
           name_page_count,
           (void*)name_buckets,
           name_bucket_cap,
           name_bucket_count,
           name_bucket_threshold);
    cep_namepool_free_pages();
    cep_namepool_free_buckets();
    namepool_root = NULL;

    CEP_DEBUG_PRINTF_STDOUT("[namepool:reset_done] root=%p pages=%p bucketTable=%p\n",
           (void*)namepool_root,
           (void*)name_pages,
           (void*)name_buckets);
}

struct cepNamePoolRuntimeState*
cep_namepool_state_create(void)
{
    return cep_malloc0(sizeof(cepNamePoolRuntimeState));
}

void
cep_namepool_state_destroy(struct cepNamePoolRuntimeState* state)
{
    if (!state) {
        return;
    }

    if (state->pages) {
        for (size_t i = 0; i < state->page_count; ++i) {
            cepNamePoolPage* page = state->pages[i];
            if (!page) {
                continue;
            }
            for (size_t slot = 0; slot < CEP_NAMEPOOL_SLOTS_PER_PAGE; ++slot) {
                cep_namepool_clear_entry(&page->entries[slot]);
            }
            cep_free(page);
        }
        cep_free(state->pages);
        state->pages = NULL;
    }
    state->page_count = 0u;
    state->page_cap = 0u;

    if (state->buckets) {
        cep_free(state->buckets);
        state->buckets = NULL;
    }
    state->bucket_cap = 0u;
    state->bucket_count = 0u;
    state->bucket_threshold = 0u;
    state->root = NULL;

    cep_free(state);
}
