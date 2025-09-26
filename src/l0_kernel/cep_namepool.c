/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


/*
 *  CEP Name Pool - Interned string support for CEP_NAMING_REFERENCE.
 */

#include "cep_namepool.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

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
} cepNamePoolEntry;

typedef struct {
    cepNamePoolEntry entries[CEP_NAMEPOOL_SLOTS_PER_PAGE];
} cepNamePoolPage;

typedef struct {
    uint64_t            hash;
    cepNamePoolEntry*   entry;
} cepNamePoolBucket;

static cepNamePoolPage**    name_pages        = NULL;
static size_t               name_page_count   = 0u;
static size_t               name_page_cap     = 0u;

static cepNamePoolBucket*   name_buckets      = NULL;
static size_t               name_bucket_cap   = 0u;
static size_t               name_bucket_count = 0u;
static size_t               name_bucket_threshold = 0u;

static cepCell*             namepool_root     = NULL;

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

    if (is_numeric && value <= CEP_AUTOID_MAX && value != cep_id(CEP_AUTOID)) {
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
    entry->id = 0;
    entry->page = 0;
    entry->slot = 0;
    entry->hash = 0;
    entry->length = 0;
    entry->bytes = NULL;
    entry->cell = NULL;
    entry->refcount = 0;
    entry->is_static = false;
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
    cepCell* cell = cep_cell_find_by_name(parent, name);
    if (!cell) {
        cell = cep_cell_add_dictionary(parent, (cepDT*)name, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
    }
    return cell;
}

static bool cep_namepool_store_entry(cepNamePoolEntry* entry, const char* text, size_t length) {
    if (!namepool_root) {
        return false;
    }

    cepDT page_name = {
        .domain = CEP_ACRO("NP"),
        .tag    = cep_id_to_numeric((cepID)(entry->page + 1u)),
    };
    cepCell* page_cell = cep_namepool_ensure_dictionary(namepool_root, &page_name);
    if (!page_cell) {
        return false;
    }

    cepDT slot_name = {
        .domain = CEP_ACRO("NP"),
        .tag    = cep_id_to_numeric((cepID)(entry->slot + 1u)),
    };

    char* copy = cep_malloc(length + 1u);
    if (!copy) {
        return false;
    }
    memcpy(copy, text, length);
    copy[length] = '\0';

    cepCell* value_cell = cep_cell_add_data(page_cell,
        &slot_name,
        0,
        CEP_DTAW("CEP", "text"),
        copy,
        length,
        length + 1u,
        (cepDel)cep_free
    );

    if (!value_cell || !cep_cell_has_data(value_cell)) {
        cep_free(copy);
        return false;
    }

    entry->cell = value_cell;
    entry->bytes = cep_cell_data(value_cell);
    entry->length = value_cell->data->size;
    entry->refcount = 1u;
    entry->is_static = false;
    return entry->bytes != NULL;
}

static cepNamePoolEntry* cep_namepool_new_entry(uint64_t hash, const char* text, size_t length, bool is_static) {
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
        return NULL;
    }

    cepNamePoolEntry* entry = &name_pages[page_index]->entries[slot_index];
    memset(entry, 0, sizeof(*entry));
    entry->page = (uint32_t)page_index;
    entry->slot = slot_index;
    entry->hash = hash;
    entry->length = length;

    if (is_static) {
        entry->bytes = text;
        entry->cell = NULL;
        entry->refcount = UINT32_MAX;
        entry->is_static = true;
    } else {
        if (!cep_namepool_store_entry(entry, text, length)) {
            memset(entry, 0, sizeof(*entry));
            return NULL;
        }
    }

    entry->id = cep_namepool_make_id(page_index, slot_index);
    return entry;
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
        return false;
    }

    cepDT sys_name = *CEP_DTAW("CEP", "sys");
    cepCell* sys = cep_cell_find_by_name(root, &sys_name);
    if (!sys) {
        sys = cep_cell_add_dictionary(root, &sys_name, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
        if (!sys) {
            return false;
        }
    }

    cepDT pool_name = *CEP_DTAW("CEP", "namepool");
    cepCell* pool = cep_cell_find_by_name(sys, &pool_name);
    if (!pool) {
        pool = cep_cell_add_dictionary(sys, &pool_name, 0, CEP_DTAW("CEP", "dictionary"), CEP_STORAGE_RED_BLACK_T);
        if (!pool) {
            return false;
        }
    }

    namepool_root = pool;
    return true;
}

/** Intern a UTF-8 buffer and return a CEP_NAMING_REFERENCE identifier, compact
    encoding to word/acronym/numeric when possible before falling back to the
    pool. */
cepID cep_namepool_intern(const char* text, size_t length) {
    if (!text || length == 0u || length > CEP_NAMEPOOL_MAX_LENGTH) {
        return 0;
    }

    cepID compact = cep_namepool_try_compact(text, length);
    if (compact) {
        return compact;
    }

    if (!cep_namepool_bootstrap()) {
        return 0;
    }

    if (name_bucket_cap == 0u) {
        if (!cep_namepool_reserve_buckets(CEP_NAMEPOOL_INITIAL_BUCKETS)) {
            return 0;
        }
    }

    uint64_t hash = cep_hash_bytes(text, length);

    if (name_bucket_count >= name_bucket_threshold) {
        if (!cep_namepool_reserve_buckets(name_bucket_cap ? (name_bucket_cap << 1u) : CEP_NAMEPOOL_INITIAL_BUCKETS)) {
            return 0;
        }
    }

    size_t mask = name_bucket_cap - 1u;
    size_t index = (size_t)hash & mask;

    while (true) {
        cepNamePoolBucket* bucket = &name_buckets[index];
        if (!bucket->entry) {
            cepNamePoolEntry* entry = cep_namepool_new_entry(hash, text, length, false);
            if (!entry) {
                return 0;
            }
            bucket->hash = hash;
            bucket->entry = entry;
            name_bucket_count += 1u;
            return entry->id;
        }

        if (bucket->hash == hash) {
            cepNamePoolEntry* entry = bucket->entry;
            if (entry && entry->length == length && memcmp(entry->bytes, text, length) == 0) {
                if (!entry->is_static && entry->refcount < UINT32_MAX) {
                    entry->refcount += 1u;
                }
                return entry->id;
            }
        }

        index = (index + 1u) & mask;
    }
}

/** Convenience wrapper around cep_namepool_intern for null-terminated strings. */
cepID cep_namepool_intern_cstr(const char* text) {
    if (!text) {
        return 0;
    }
    return cep_namepool_intern(text, strlen(text));
}

/** Register a static caller-owned string without copying it into the pool so
    adapters can reference compile-time text cheaply. */
cepID cep_namepool_intern_static(const char* text, size_t length) {
    if (!text || length == 0u || length > CEP_NAMEPOOL_MAX_LENGTH) {
        return 0;
    }

    cepID compact = cep_namepool_try_compact(text, length);
    if (compact) {
        return compact;
    }

    if (!cep_namepool_bootstrap()) {
        return 0;
    }

    if (name_bucket_cap == 0u) {
        if (!cep_namepool_reserve_buckets(CEP_NAMEPOOL_INITIAL_BUCKETS)) {
            return 0;
        }
    }

    uint64_t hash = cep_hash_bytes(text, length);

    if (name_bucket_count >= name_bucket_threshold) {
        if (!cep_namepool_reserve_buckets(name_bucket_cap ? (name_bucket_cap << 1u) : CEP_NAMEPOOL_INITIAL_BUCKETS)) {
            return 0;
        }
    }

    size_t mask = name_bucket_cap - 1u;
    size_t index = (size_t)hash & mask;

    while (true) {
        cepNamePoolBucket* bucket = &name_buckets[index];
        if (!bucket->entry) {
            cepNamePoolEntry* entry = cep_namepool_new_entry(hash, text, length, true);
            if (!entry) {
                return 0;
            }
            bucket->hash = hash;
            bucket->entry = entry;
            name_bucket_count += 1u;
            return entry->id;
        }

        if (bucket->hash == hash) {
            cepNamePoolEntry* entry = bucket->entry;
            if (entry && entry->length == length && memcmp(entry->bytes, text, length) == 0) {
                return entry->id;
            }
        }

        index = (index + 1u) & mask;
    }
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

    if (entry->cell) {
        cep_cell_remove_hard(entry->cell, NULL);
    }

    uint64_t page = 0u;
    uint32_t slot = 0u;
    if (!cep_namepool_decode(id, &page, &slot)) {
        return false;
    }

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
