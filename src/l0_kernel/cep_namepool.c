/*
 *  CEP Name Pool - Interned string support for CEP_NAMING_REFERENCE.
 */

#include "cep_namepool.h"

#include <stdint.h>
#include <string.h>

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

static cepCell*             namepool_root     = NULL;

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
    return true;
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

    char* copy = cep_malloc(length);
    if (!copy) {
        return false;
    }
    memcpy(copy, text, length);

    cepCell* value_cell = cep_cell_add_value(page_cell,
        &slot_name,
        0,
        CEP_DTAW("CEP", "text"),
        copy,
        length,
        length
    );

    cep_free(copy);

    if (!value_cell || !cep_cell_has_data(value_cell)) {
        return false;
    }

    entry->cell = value_cell;
    entry->bytes = cep_cell_data(value_cell);
    entry->length = value_cell->data->size;
    return entry->bytes != NULL;
}

static cepNamePoolEntry* cep_namepool_new_entry(uint64_t hash, const char* text, size_t length) {
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

    if (!cep_namepool_store_entry(entry, text, length)) {
        memset(entry, 0, sizeof(*entry));
        return NULL;
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

cepID cep_namepool_intern(const char* text, size_t length) {
    if (!text || length == 0u || length > CEP_NAMEPOOL_MAX_LENGTH) {
        return 0;
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

    if ((name_bucket_count * 2u) >= name_bucket_cap) {
        if (!cep_namepool_reserve_buckets(name_bucket_cap << 1u)) {
            return 0;
        }
    }

    size_t mask = name_bucket_cap - 1u;
    size_t index = (size_t)hash & mask;

    while (true) {
        cepNamePoolBucket* bucket = &name_buckets[index];
        if (!bucket->entry) {
            cepNamePoolEntry* entry = cep_namepool_new_entry(hash, text, length);
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

cepID cep_namepool_intern_cstr(const char* text) {
    if (!text) {
        return 0;
    }
    return cep_namepool_intern(text, strlen(text));
}

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
