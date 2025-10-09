/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#ifndef CEP_CELL_H
#define CEP_CELL_H


#include "cep_molecule.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file
 * @brief Core Layer-0 data structures and utilities for CEP cells.
 */


typedef struct _cepData       cepData;
typedef struct _cepStore      cepStore;
typedef struct _cepCell       cepCell;
typedef struct _cepProxy      cepProxy;

typedef int (*cepCompare)(const cepCell* restrict, const cepCell* restrict, void*);

typedef uint64_t  cepOpCount;         // CEP per-cell operation id number.


/*
 *  Domain-Tag (DT) Naming
 */

typedef uint64_t  cepID;

#define CEP_ID(v)   ((cepID)(v))

#define CEP_NAME_BITS           58
#define CEP_NAME_MAXVAL         (~(((cepID)(-1)) << CEP_NAME_BITS))
#define CEP_NAMECONV_BITS       2
#define CEP_AUTOID_BITS         (CEP_NAME_BITS - CEP_NAMECONV_BITS)
#define CEP_AUTOID_MAXVAL       (~(((cepID)(-1)) << CEP_AUTOID_BITS))
#define CEP_AUTOID_MAX          (CEP_AUTOID_MAXVAL - 1)

/**
 * @struct cepDT
 * @brief Packed domain/tag identifier used to name cells within a store.
 *
 * The structure uses two 58-bit fields to encode the human visible domain and
 * tag while reserving 6 bits on each side for system metadata. Helper macros
 * expose conversion helpers for common naming schemes (word, acronym,
 * references, numeric IDs).
 */
typedef struct {
    struct {
        cepID           _sysbits1:  6,  /**< Used by other parts of CEP system. */
                        domain:     CEP_NAME_BITS;
    };
    struct {
        cepID           _sysbits2:  5,  /**< Used by other parts of CEP system. */
                        glob:       1,  /**< Glob character present. */
                        tag:        CEP_NAME_BITS;
    };
} cepDT;

#define CEP_DT_PTR(p)       ((cepDT*)(p))

static inline int cep_dt_compare(const cepDT* restrict key, const cepDT* restrict dt)
{
    if (key->domain > dt->domain)
        return 1;
    if (key->domain < dt->domain)
        return -1;
    if (key->tag > dt->tag)
        return 1;
    if (key->tag < dt->tag)
        return -1;
    
    return 0;
}


/*
 *  Cell Meta
 */

/**
 * @struct cepMetacell
 * @brief Lightweight metadata that summarises a cell's type and naming bits.
 */
typedef struct {
  union {
    cepDT       dt;
    
    struct {
      struct {
        cepID   type:       2,    /**< Type of cell (dictionary, link, etc). */
                hidden:     1,    /**< Cell won't appear on listings (it can only be accessed directly). */
                shadowing:  2,    /**< If cell has shadowing cells (links pointing to it). */
                targetDead: 1,    /**< Set (1) if this cell is a link and the target died. */

                domain:     CEP_NAME_BITS;
      };
      struct {
        cepID   _reserved:  5,
                glob:       1,    /**< Glob character present. */
                tag:        CEP_NAME_BITS;
      };
    };
  };
} cepMetacell;

static_assert(sizeof(cepMetacell) == sizeof(cepDT), "System bits can't exceed 2 pairs of 6 bits!");


/**
 * @brief Runtime types a cell instance can assume.
 */
enum _cepCellType {
    CEP_TYPE_VOID,              /**< A void (uninitialized) cell. */
    CEP_TYPE_NORMAL,            /**< Regular cell. */
    CEP_TYPE_PROXY,             /**< Virtual cell whose payload is mediated through proxy callbacks. */
    CEP_TYPE_LINK,              /**< Link to another cell. */
    //
    CEP_TYPE_COUNT
};

/**
 * @brief State of the backlink list that records link shadows.
 */
enum _cepCellShadowing {
    CEP_SHADOW_NONE,            /**< No shadow cells. */
    CEP_SHADOW_SINGLE,          /**< Single shadow cell. */
    CEP_SHADOW_MULTIPLE,        /**< Multiple shadows. */
};

/**
 * @brief Encodings supported by the Domain-Tag naming system.
 */
enum _cepCellNaming {
    CEP_NAMING_WORD,            /**< Lowercase text value, 11 chars max (it must be the first in this enum!). */
    CEP_NAMING_ACRONYM,         /**< Uppercase/numeric text, 9 characters maximum. */
    CEP_NAMING_REFERENCE,       /**< Numerical reference to text cell (a pointer in 32bit systems). */
    CEP_NAMING_NUMERIC,         /**< Per-parent numerical ID. */

    CEP_NAMING_COUNT
};


#define cep_id_from_naming(naming)      (((cepID)((naming) & 3)) << CEP_AUTOID_BITS)
#define CEP_NAMING_MASK                 cep_id_from_naming(3)

#define cep_id_to_word(word)            ((word) | cep_id_from_naming(CEP_NAMING_WORD))
#define cep_id_to_acronym(acro)         ((acro) | cep_id_from_naming(CEP_NAMING_ACRONYM))
#define cep_id_to_reference(ref)        ((ref)  | cep_id_from_naming(CEP_NAMING_REFERENCE))
#define cep_id_to_numeric(numb)         ((numb) | cep_id_from_naming(CEP_NAMING_NUMERIC))

/* Reserved identifiers that behave as wildcard sentinels during signal
   matching. They occupy the highest reference-space values so namepool entries
   never collide with them. */
#define CEP_ID_GLOB_MULTI               cep_id_to_reference(CEP_AUTOID_MAXVAL)
#define CEP_ID_GLOB_STAR                cep_id_to_reference(CEP_AUTOID_MAXVAL - 1u)
#define CEP_ID_GLOB_QUESTION            cep_id_to_reference(CEP_AUTOID_MAXVAL - 2u)

#define cep_id(name)                    ((name) & CEP_AUTOID_MAXVAL)
#define CEP_ID_SET(name, id)            do{ name = ((name) & CEP_NAMING_MASK) | cep_id(id); }while(0)

#define CEP_AUTOID_USE                  CEP_AUTOID_MAXVAL
#define CEP_AUTOID                      cep_id_to_numeric(CEP_AUTOID_USE)

#define cep_id_is_auto(name)            ((name) == CEP_AUTOID)
#define cep_id_is_word(name)            ((CEP_NAMING_MASK & (name)) == cep_id_from_naming(CEP_NAMING_WORD))
#define cep_id_is_acronym(name)         ((CEP_NAMING_MASK & (name)) == cep_id_from_naming(CEP_NAMING_ACRONYM))
#define cep_id_is_reference(name)       ((CEP_NAMING_MASK & (name)) == cep_id_from_naming(CEP_NAMING_REFERENCE))
#define cep_id_is_numeric(name)         ((CEP_NAMING_MASK & (name)) == cep_id_from_naming(CEP_NAMING_NUMERIC))

#define cep_id_valid(id)                (cep_id(id) && ((id) <= CEP_AUTOID))
#define cep_id_text_valid(name)         (cep_id(name) && (cep_id_is_word(name) || cep_id_is_acronym(name) || cep_id_is_reference(name)))
#define cep_id_naming(name)             (((name) >> CEP_AUTOID_BITS) & 3)

static inline bool cep_id_is_glob_multi(cepID id) {
    return cep_id_is_reference(id) && cep_id(id) == CEP_AUTOID_MAXVAL;
}

static inline bool cep_id_is_glob_star(cepID id) {
    return cep_id_is_reference(id) && cep_id(id) == (CEP_AUTOID_MAXVAL - 1u);
}

static inline bool cep_id_is_glob_question(cepID id) {
    return cep_id_is_reference(id) && cep_id(id) == (CEP_AUTOID_MAXVAL - 2u);
}

#define CEP_WORD_MAX_CHARS      11
#define CEP_ACRON_MAX_CHARS     9

size_t cep_word_to_text(cepID coded, char s[12]);
size_t cep_acronym_to_text(cepID acro, char s[10]);

const char* cep_namepool_lookup(cepID id, size_t* length);
bool        cep_namepool_reference_is_glob(cepID id);

#define CEP_WORD_GLOB_SENTINEL    31u

static inline bool cep_id_has_glob_char(cepID id) {
    if (cep_id_is_word(id)) {
        cepID payload = cep_id(id);
        for (unsigned i = 0; i < CEP_WORD_MAX_CHARS; ++i) {
            unsigned shift = 5u * ((CEP_WORD_MAX_CHARS - 1u) - i);
            uint8_t encoded = (uint8_t)((payload >> shift) & 0x1Fu);
            if (encoded == CEP_WORD_GLOB_SENTINEL) {
                return true;
            }
        }

        return false;
    }

    if (cep_id_is_acronym(id)) {
        cepID payload = cep_id(id);
        for (unsigned i = 0; i < CEP_ACRON_MAX_CHARS; ++i) {
            unsigned shift = 6u * ((CEP_ACRON_MAX_CHARS - 1u) - i);
            uint8_t encoded = (uint8_t)((payload >> shift) & 0x3Fu);
            if (encoded == (uint8_t)('*' - 0x20)) {
                return true;
            }
        }

        return false;
    }

    if (cep_id_is_reference(id)) {
        return cep_namepool_reference_is_glob(id);
    }

    return false;
}

static inline bool cep_word_glob_match_text(const char* pattern, size_t pattern_len, const char* text, size_t text_len) {
    size_t pi = 0u;
    size_t ti = 0u;
    size_t star = (size_t)-1;
    size_t match = 0u;

    while (ti < text_len) {
        if (pi < pattern_len && pattern[pi] == '*') {
            star = pi++;
            match = ti;
            continue;
        }

        if (pi < pattern_len && pattern[pi] == text[ti]) {
            ++pi;
            ++ti;
            continue;
        }

        if (star != (size_t)-1) {
            pi = star + 1u;
            ++match;
            ti = match;
            continue;
        }

        return false;
    }

    while (pi < pattern_len && pattern[pi] == '*') {
        ++pi;
    }

    return pi == pattern_len;
}

static inline bool cep_id_matches(cepID pattern, cepID observed) {
    if (cep_id_is_glob_multi(pattern)) {
        return true;
    }

    if (cep_id_is_glob_star(pattern) || cep_id_is_glob_question(pattern)) {
        return true;
    }

    if (pattern == observed) {
        return true;
    }

    if (cep_id_has_glob_char(pattern)) {
        if (cep_id_is_word(pattern)) {
            if (!cep_id_is_word(observed)) {
                return false;
            }

            char pattern_buf[CEP_WORD_MAX_CHARS + 1u];
            char observed_buf[CEP_WORD_MAX_CHARS + 1u];
            size_t pattern_len = cep_word_to_text(pattern, pattern_buf);
            size_t observed_len = cep_word_to_text(observed, observed_buf);
            return cep_word_glob_match_text(pattern_buf, pattern_len, observed_buf, observed_len);
        }

        if (cep_id_is_acronym(pattern)) {
            if (!cep_id_is_acronym(observed)) {
                return false;
            }

            char pattern_buf[CEP_ACRON_MAX_CHARS + 1u];
            char observed_buf[CEP_ACRON_MAX_CHARS + 1u];
            size_t pattern_len = cep_acronym_to_text(pattern, pattern_buf);
            size_t observed_len = cep_acronym_to_text(observed, observed_buf);
            return cep_word_glob_match_text(pattern_buf, pattern_len, observed_buf, observed_len);
        }

        if (cep_id_is_reference(pattern)) {
            if (!cep_id_is_reference(observed)) {
                return false;
            }

            size_t pattern_len = 0u;
            size_t observed_len = 0u;
            const char* pattern_text = cep_namepool_lookup(pattern, &pattern_len);
            const char* observed_text = cep_namepool_lookup(observed, &observed_len);
            if (!pattern_text || !observed_text) {
                return false;
            }

            return cep_word_glob_match_text(pattern_text, pattern_len, observed_text, observed_len);
        }
    }

    return false;
}

static inline bool cep_dt_is_valid(const cepDT* dt) {
    return dt && cep_id_text_valid(dt->domain) && cep_id_valid(dt->tag) && (!dt->glob || cep_id_has_glob_char(dt->tag));
}


// Converting C text strings to/from cepID

/* Acronym character chart (ASCII lower set):
 H \  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
 - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
2x \  SP  !   "   #   $   %   &   '   (   )   *   +   ,   -   .   /
3x \  0   1   2   3   4   5   6   7   8   9   :   ;   <   =   >   ?
4x \  @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
5x \  P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
*/
#define CEP_TEXT_TO_ACRONYM_(name)                                             \
    cepID name(const char *s) {                                                \
        assert(s && *s);                                                       \
                                                                               \
        while (*s == ' ') {                                                    \
            s++;            /* Trim leading spaces. */                         \
        }                                                                      \
        if (!*s)                                                               \
            return 0;                                                          \
                                                                               \
        size_t len = strlen(s);                                                \
        while (len > 0  &&  s[len - 1] == ' ') {                               \
            len--;          /* Trim trailing spaces. */                        \
        }                                                                      \
                                                                               \
        if (len > CEP_ACRON_MAX_CHARS)                                         \
            return 0;       /* Limit to max allowed characters. */             \
                                                                               \
        cepID coded = 0;                                                       \
        int allDigits = 1;                                                     \
        for (size_t n = 0; n < len; n++) {                                     \
            char c = s[n];                                                     \
                                                                              \
            if (c < 0x20  ||  c > 0x5F)                                        \
                return 0;   /* Uncodable characters. */                        \
                                                                              \
            /* Shift and encode each character: */                             \
            coded |= (cepID)(c - 0x20) << (6 * ((CEP_ACRON_MAX_CHARS-1) - n)); \
            if (c < '0' || c > '9')                                           \
                allDigits = 0;                                                \
        }                                                                      \
        if (allDigits)                                                         \
            return 0;                                                          \
                                                                              \
        return cep_id_to_acronym(coded);                                       \
    }


/* Word character chart (ASCII upper set):
 H \  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
 - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
6x \ [SP] a   b   c   d   e   f   g   h   i   j   k   l   m   n   o
7x \  p   q   r   s   t   u   v   w   x   y   z  [:] [_] [-] [.] [*]
    Note: characters in square brackets replacing originals.
*/
#define CEP_TEXT_TO_WORD_(name)                                                \
    cepID name(const char *s) {                                                \
        assert(s && *s);                                                       \
                                                                               \
        while (*s == ' ') {                                                    \
            s++;            /* Trim leading spaces. */                         \
        }                                                                      \
        if (!*s)                                                               \
            return 0;                                                          \
                                                                               \
        size_t len = strlen(s);                                                \
        while (len > 0  &&  s[len - 1] == ' ') {                               \
            len--;          /* Trim trailing spaces. */                        \
        }                                                                      \
        if (len > CEP_WORD_MAX_CHARS)                                          \
            return 0;       /* Limit to max allowed characters. */             \
                                                                               \
        bool hasLowercase = false;                                             \
        cepID coded = 0;                                                       \
        for (size_t n = 0; n < len; n++) {                                     \
            char c = s[n];                                                     \
                                                                               \
            uint8_t encoded_char;                                              \
            if (c >= 0x61  &&  c <= 0x7A) {                                    \
                encoded_char = c - 0x61 + 1;        /* Map 'a'-'z' to 1-26. */ \
                hasLowercase = true;                                           \
            } else switch (c) {                                                \
              case ' ': encoded_char = 0;   break;  /* Encode space as 0. */   \
              case ':': encoded_char = 27;  break;                             \
              case '_': encoded_char = 28;  break;                             \
              case '-': encoded_char = 29;  break;                             \
              case '.': encoded_char = 30;  break;                             \
              case '*': encoded_char = 31;  break;                             \
                                                                               \
              default:                                                         \
                return 0;   /* Uncodable characters. */                        \
            }                                                                  \
                                                                               \
            /* Shift and encode each character: */                             \
            coded |= (cepID)encoded_char << (5 * ((CEP_WORD_MAX_CHARS-1) - n));\
        }                                                                      \
        if (!hasLowercase)                                                     \
            return 0;       /* Can't be a pure symbolic word. */               \
                                                                               \
        return cep_id_to_word(coded);                                          \
    }

static inline CEP_CONST_FUNC CEP_TEXT_TO_ACRONYM_(CEP_ACRO_constant)
static inline CEP_CONST_FUNC CEP_TEXT_TO_WORD_(CEP_WORD_constant)

#define CEP_ACRO(s)     ({static_assert(strlen(s) > 0 && strlen(s) <= 9,  "Acronym IDs must be 9 characters or less!"); CEP_ACRO_constant(s);})
#define CEP_WORD(s)     ({static_assert(strlen(s) > 0 && strlen(s) <= 11, "Word IDs must be 11 characters or less!"); CEP_WORD_constant(s);})

static inline cepDT cep_dt_make(cepID domain, cepID tag) {
    cepDT dt = {.domain = domain, .tag = tag};
    dt.glob = cep_id_has_glob_char(tag);
    return dt;
}

#define CEP_DTS(d, t)   (&(cepDT){.domain=(d), .tag=(t), .glob=cep_id_has_glob_char(t)})
#define CEP_DTWW(d, t)  CEP_DTS(CEP_WORD(d), CEP_WORD(t))
#define CEP_DTWA(d, t)  CEP_DTS(CEP_WORD(d), CEP_ACRO(t))
#define CEP_DTAA(d, t)  CEP_DTS(CEP_ACRO(d), CEP_ACRO(t))
#define CEP_DTAW(d, t)  CEP_DTS(CEP_ACRO(d), CEP_WORD(t))

#define CEP_DEFINE_STATIC_DT(fn_name, domain_expr, tag_expr)                  \
    static const cepDT* fn_name(void) {                                       \
        static cepDT value;                                                   \
        static bool initialized = false;                                      \
        if (!initialized) {                                                   \
            value.domain = (domain_expr);                                     \
            value.tag = (tag_expr);                                           \
            value.glob = cep_id_has_glob_char(value.tag);                     \
            initialized = true;                                               \
        }                                                                     \
        return &value;                                                        \
    }

cepID  cep_text_to_acronym(const char *s);

cepID  cep_text_to_word(const char *s);


/*
    Cell Data
*/

typedef struct _cepEnzymeBinding cepEnzymeBinding;

/**
 * @brief Bit flags tagged onto enzyme bindings stored on cells.
 */
enum {
    CEP_ENZYME_BIND_PROPAGATE = 1u << 0, /**< Inherit binding to descendants. */
    CEP_ENZYME_BIND_TOMBSTONE = 1u << 1, /**< Marks an unbound/tombstoned entry. */
};

/**
 * @struct _cepEnzymeBinding
 * @brief Node describing a single enzyme binding appended to a cell timeline.
 */
struct _cepEnzymeBinding {
    cepEnzymeBinding*   next;       /**< Next binding in the append-only list. */
    cepDT               name;       /**< Enzyme identity. */
    uint32_t            flags;      /**< Binding behaviour flags. */
    cepOpCount          modified;   /**< Heartbeat when this binding became visible. */
};

typedef struct _cepDataNode  cepDataNode;
struct _cepDataNode {
    cepOpCount          modified;       /**< CEP heartbeat in which data was modified (including creation/deletion). */
    cepDataNode*        past;           /**< Pointer to past data content history. */
    
    cepEnzymeBinding*   bindings;       /**< List of enzyme bindings. */
    
    size_t              size;           /**< Data size in bytes. */
    size_t              capacity;       /**< Buffer capacity in bytes. */
    uint64_t            hash;           /**< Hash value of content. */

    union {
        struct {
            void*       data;           /**< Points to container of data value. */
            cepDel      destructor;     /**< Data container destruction function. */
        };
        struct {
          union {
            cepCell*    handle;         /**< Resource cell id (used with external libraries). */
            cepCell*    stream;         /**< Data window to streamed content. */
          };
          cepCell*      library;        /**< Library where the resource is located. */
        };
        uint8_t         value[2 * sizeof(void*)];  /**< Data value may start from here. */
    };
};

struct _cepData {
    union {
      cepDT             dt;
      
      struct {
        struct {
          cepID         datatype:   2,  /**< Type of data (see _cepDataType). */
                        _unused:    4, 

                        domain:     CEP_NAME_BITS;
        };
        struct {
          cepID         writable:   1,  /**< If data can be updated. */
                        lock:       1,  /**< Lock on data content. */
                        _reserved:  3,
                        glob:       1,  /**< Glob character present. */
                        
                        tag:        CEP_NAME_BITS;
        };
      };
    };
    
    cepOpCount          created;        /**< Data content creation time. */
    cepOpCount          deleted;        /**< Data content deletion time (if any). */

    cepDataNode;
    cepCell*            lockOwner;      /**< Cell that currently holds the payload lock (if any). */
};

enum _cepDataType {
    CEP_DATATYPE_VALUE,         /**< Data starts at "value" field of cepData. */
    CEP_DATATYPE_DATA,          /**< Data is in address pointed by "data" field. */
    CEP_DATATYPE_HANDLE,        /**< Data is just a handle to an opaque (library internal) resource. */
    CEP_DATATYPE_STREAM,        /**< Data is a window to a larger (library internal) stream. */
    //
    CEP_DATATYPE_COUNT
};

static inline uint64_t cep_hash_bytes(const void* data, size_t size) {
    if (!data || !size)
        return 0;

    const uint8_t* bytes = data;
    uint64_t hash = 1469598103934665603ULL;  // FNV-1a offset basis.
    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;            // FNV-1a prime.
    }
    return hash;
}

static inline const void* cep_data_payload(const cepData* data) {
    assert(data);

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE:
        return data->value;

      case CEP_DATATYPE_DATA:
        return data->data;

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM:
        break;
    }

    return NULL;
}

static inline bool cep_data_equals_bytes(const cepData* data, const void* bytes, size_t size) {
    assert(data);

    if (data->size != size)
        return false;

    if (!size)
        return true;

    const void* payload = cep_data_payload(data);
    if (!payload || !bytes)
        return false;

    return memcmp(payload, bytes, size) == 0;
}

static inline uint64_t cep_data_compute_hash(const cepData* data) {
    assert(data);

    uint64_t payloadHash = 0;

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE:
      case CEP_DATATYPE_DATA:
        payloadHash = cep_hash_bytes(cep_data_payload(data), data->size);
        break;

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        uintptr_t refs[2] = {
            (uintptr_t)data->handle,
            (uintptr_t)data->library,
        };
        payloadHash = cep_hash_bytes(refs, sizeof refs);
        break;
      }
    }

    struct {
        uint64_t domain;
        uint64_t tag;
        uint64_t size;
        uint64_t payload;
    } key = {
        .domain  = data->dt.domain,
        .tag     = data->dt.tag,
        .size    = data->size,
        .payload = payloadHash,
    };

    return cep_hash_bytes(&key, sizeof key);
}

typedef struct {
    void*       address;        /**< Backing memory exposed to the caller. */
    size_t      length;         /**< Span length mapped into the caller's address space. */
    uint64_t    offset;         /**< Stream offset associated with the view. */
    unsigned    access;         /**< Access flags requested for the view. */
    void*       token;          /**< Library or kernel specific handle to release resources. */
} cepStreamView;

enum {
    CEP_STREAM_ACCESS_READ   = 1u << 0,
    CEP_STREAM_ACCESS_WRITE  = 1u << 1,
};

typedef struct {
    const void* payload;        /**< Snapshot payload bytes (may point to an external buffer). */
    size_t      size;           /**< Size of the payload bytes. */
    uint32_t    flags;          /**< Snapshot flags describing the payload semantics. */
    void*       ticket;         /**< Opaque handle passed back to the proxy when releasing the snapshot. */
} cepProxySnapshot;

enum {
    CEP_PROXY_SNAPSHOT_INLINE   = 1u << 0,   /**< Payload is in-memory and owned by the proxy module. */
    CEP_PROXY_SNAPSHOT_EXTERNAL = 1u << 1,   /**< Payload references external state that must be refetched. */
};

typedef struct cepLibraryBinding cepLibraryBinding;

typedef struct {
    bool (*handle_retain)(const cepLibraryBinding* binding, cepCell* handle);
    void (*handle_release)(const cepLibraryBinding* binding, cepCell* handle);
    bool (*stream_read)(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, void* dst, size_t size, size_t* out_read);
    bool (*stream_write)(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, const void* src, size_t size, size_t* out_written);
    bool (*stream_expected_hash)(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, size_t size, uint64_t* out_hash);
    bool (*stream_map)(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, size_t size, unsigned access, cepStreamView* view);
    bool (*stream_unmap)(const cepLibraryBinding* binding, cepCell* stream, cepStreamView* view, bool commit);
    bool (*handle_snapshot)(const cepLibraryBinding* binding, cepCell* handle, cepProxySnapshot* snapshot);
    bool (*handle_restore)(const cepLibraryBinding* binding, const cepProxySnapshot* snapshot, cepCell** out_handle);
    bool (*stream_snapshot)(const cepLibraryBinding* binding, cepCell* stream, cepProxySnapshot* snapshot);
    bool (*stream_restore)(const cepLibraryBinding* binding, const cepProxySnapshot* snapshot, cepCell** out_stream);
} cepLibraryOps;

struct cepLibraryBinding {
    const cepLibraryOps* ops;   /**< Adapter vtable registered by the foreign library. */
    void*                ctx;   /**< Library defined context passed back on every invocation. */
};


typedef struct cepProxyOps {
    bool (*snapshot)(cepCell* proxy, cepProxySnapshot* snapshot);
    void (*release)(cepCell* proxy, cepProxySnapshot* snapshot);
    bool (*restore)(cepCell* proxy, const cepProxySnapshot* snapshot);
    void (*finalize)(cepCell* proxy);
} cepProxyOps;


cepData* cep_data_new(  cepDT* type, unsigned datatype, bool writable,
                        void** dataloc, void* value, ...  );
void     cep_data_del(cepData* data);
void*    cep_data(const cepData* data);
#define  cep_data_valid(d)                             ((d) && (d)->capacity && cep_dt_is_valid(&(d)->dt))
#define  cep_data_new_value(dt, value, z)              ({size_t _z = z;  cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, _z, _z);})
void     cep_data_history_push(cepData* data);
void     cep_data_history_clear(cepData* data);

void  cep_library_initialize(cepCell* library, cepDT* name, const cepLibraryOps* ops, void* context);
const cepLibraryBinding* cep_library_binding(const cepCell* library);
void* cep_library_context(const cepCell* library);
void  cep_library_set_context(cepCell* library, void* context);
bool  cep_cell_stream_read(cepCell* cell, uint64_t offset, void* dst, size_t size, size_t* out_read);
bool  cep_cell_stream_write(cepCell* cell, uint64_t offset, const void* src, size_t size, size_t* out_written);
bool  cep_cell_stream_map(cepCell* cell, uint64_t offset, size_t size, unsigned access, cepStreamView* view);
bool  cep_cell_stream_unmap(cepCell* cell, cepStreamView* view, bool commit);


void  cep_proxy_initialize(cepCell* cell, cepDT* name, const cepProxyOps* ops, void* context);
void  cep_proxy_set_context(cepCell* cell, void* context);
void* cep_proxy_context(const cepCell* cell);
const cepProxyOps* cep_proxy_ops(const cepCell* cell);

bool  cep_proxy_snapshot(cepCell* cell, cepProxySnapshot* snapshot);
void  cep_proxy_release_snapshot(cepCell* cell, cepProxySnapshot* snapshot);
bool  cep_proxy_restore(cepCell* cell, const cepProxySnapshot* snapshot);

void  cep_proxy_initialize_handle(cepCell* cell, cepDT* name, cepCell* handle, cepCell* library);
void  cep_proxy_initialize_stream(cepCell* cell, cepDT* name, cepCell* stream, cepCell* library);


/*
    Cell Storage (for children)
*/

typedef struct {
    unsigned        count;      /**< Number of cell pointers. */
    unsigned        capacity;   /**< Capacity of array. */
    cepCell*        cell[];     /**< Array of cells shadowing this one. */
} cepShadow;

typedef struct {
    cepCell* owner;
} cepLockToken;


bool cep_store_lock(cepCell* cell, cepLockToken* token);
void cep_store_unlock(cepCell* cell, cepLockToken* token);
bool cep_data_lock(cepCell* cell, cepLockToken* token);
void cep_data_unlock(cepCell* cell, cepLockToken* token);

typedef struct _cepStoreNode  cepStoreNode;

struct _cepStoreNode {
    union {
        cepCell*        linked;     /**< A linked shadow cell (when children, see in cepCell otherwise). */
        cepShadow*      shadow;     /**< Shadow structure (if cell has children). */
    };

    cepOpCount          modified;   /**< CEP heartbeat in which store was modified (including creation/deletion). */
    
    cepStoreNode*       past;       /**< Points to the previous store index in history (only used if catalog is re-sorted/indexed with different sorting function). */

    cepEnzymeBinding*   bindings; /**< List of enzyme bindings. */

    size_t              chdCount;   /**< Number of child cells. */
    size_t              totCount;   /**< Number of all cells included dead ones. */
    cepCompare          compare;    /**< Compare function for indexing children. */
    cepCell*            lockOwner;  /**< Cell that currently holds the structural lock (if any). */

    // The specific storage structure will follow after this...
};

struct _cepStore {
    union {
      cepDT         dt;
      
      struct {
        struct {
        cepID       storage:    3,              /**< Data structure for children storage (array, linked-list, etc). */
                    indexing:   2,              /**< Indexing (sorting) criteria for children. */
                    _unused:    1,

                    domain:     CEP_NAME_BITS;
        };
        struct {
        cepID       writable:   1,              /**< If chidren can be added/deleted. */
                    lock:       1,              /**< Lock on children operations. */
                    _reserved:  3,
                    glob:       1,              /**< Glob character present. */

                    tag:        CEP_NAME_BITS;
        };
      };
    };

    cepCell*        owner;      /**< Cell owning this child storage. */

    cepOpCount      created;    /**< CEP heartbeat in which store was created. */
    cepOpCount      deleted;    /**< CEP heartbeat in which store was deleted (if any). */

    cepID           autoid;     /**< Auto-increment ID for inserting new child cells. */

    cepStoreNode;
};

enum _cepCellStorage {
    CEP_STORAGE_LINKED_LIST,    /**< Children stored in a doubly linked list. */
    CEP_STORAGE_ARRAY,          /**< Children stored in an array. */
    CEP_STORAGE_PACKED_QUEUE,   /**< Children stored in a packed queue. */
    CEP_STORAGE_RED_BLACK_T,    /**< Children stored in a red-black tree. */
    CEP_STORAGE_HASH_TABLE,     /**< Children stored in a hash table with ordered buckets. */
    CEP_STORAGE_OCTREE,         /**< Children stored in an octree spatial index. */
    //
    CEP_STORAGE_COUNT
};

enum _cepCellIndexing {
    CEP_INDEX_BY_INSERTION,      /**< Children indexed by their insertion order (the default). */
    CEP_INDEX_BY_NAME,           /**< Children indexed by their unique name (a dicionary). */
    CEP_INDEX_BY_FUNCTION,       /**< Children indexed by a custom comparation function. */
    CEP_INDEX_BY_HASH,           /**< Children indexed by data hash value (first) and then by a comparation function (second). */
    //
    CEP_INDEX_COUNT
};


cepStore* cep_store_new(cepDT* dt, unsigned storage, unsigned indexing, ...);
void      cep_store_del(cepStore* store);
void      cep_store_delete_children_hard(cepStore* store);
#define   cep_store_valid(s)      ((s) && cep_dt_is_valid(&(s)->dt))

static inline bool cep_store_is_insertable(cepStore* store)   {assert(cep_store_valid(store));  return (store->indexing == CEP_INDEX_BY_INSERTION);}
static inline bool cep_store_is_dictionary(cepStore* store)   {assert(cep_store_valid(store));  return (store->indexing == CEP_INDEX_BY_NAME);}
static inline bool cep_store_is_f_sorted(cepStore* store)     {assert(cep_store_valid(store));  return (store->indexing == CEP_INDEX_BY_FUNCTION  ||  store->indexing == CEP_INDEX_BY_HASH);}
static inline bool cep_store_is_sorted(cepStore* store)       {assert(cep_store_valid(store));  return (store->indexing != CEP_INDEX_BY_INSERTION);}
static inline bool cep_store_is_empty(cepStore* store)        {assert(cep_store_valid(store));  return !store->chdCount;}

cepCell* cep_store_add_child(cepStore* store, uintptr_t context, cepCell* child);
cepCell* cep_store_append_child(cepStore* store, bool prepend, cepCell* child);


/*
    Cell
*/

typedef struct {
    cepDT           dt;         /**< Path segment identifier. */
    cepOpCount      timestamp;  /**< Snapshot timestamp for this segment (0 means latest). */
} cepPast;

typedef struct {
    unsigned        length;
    unsigned        capacity;
    cepPast         past[];
} cepPath;


struct _cepCell {
    cepMetacell     metacell;   /**< Meta about this cell entry (including name (DT), system bits, etc). */
    cepStore*       parent;     /**< Parent structure (list, array, etc) where this cell is stored in. */

    union {
        cepData*    data;       /**< Address of cepData structure. */

        cepCell*    link;       /**< Link to another cell. */

        cepProxy*   proxy;      /**< Proxy definition mediating externalised payloads. */
    };

    union {
        cepStore*   store;      /**< Address of cepStore structure. */

        cepCell*    linked;     /**< A linked shadow cell (if no children, see in cepStore otherwise). */
        cepShadow*  shadow;     /**< Structure for multiple linked cells (if no children). */

        //cepCell*  instance;   // Agent instance this cell belongs to (if cell is a Link).
    };

    cepOpCount      created;    /**< Timestamp when this cell became visible. */
    cepOpCount      deleted;    /**< Timestamp when this cell was soft-deleted (0 = alive). */
};


typedef struct {
    cepCell*        cell;
    cepCell*        next;
    cepCell*        prev;
    cepCell*        parent;
    size_t          position;
    unsigned        depth;
} cepEntry;

typedef bool (*cepTraverse)(cepEntry*, void*);


/*
 * Cell Operations
 */

// Initiate cells
void cep_cell_initialize(cepCell* cell, unsigned type, cepDT* name, cepData* data, cepStore* store);
void cep_cell_initialize_clone(cepCell* newClone, cepDT* name, cepCell* cell);
void cep_cell_finalize(cepCell* cell);          // Internal: asserts no backlinks remain.
void cep_cell_finalize_hard(cepCell* cell);     // Public hard teardown for aborted cells.
void cep_cell_shadow_mark_target_dead(cepCell* cell, bool dead);
cepCell* cep_cell_clone(const cepCell* cell);
cepCell* cep_cell_clone_deep(const cepCell* cell);

#define cep_cell_initialize_empty(r, name)                                                            cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, NULL)
#define cep_cell_initialize_value(r, name, dt, value, size, capacity)                cep_cell_initialize(r, CEP_TYPE_NORMAL, name, cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, size, capacity), NULL)
#define cep_cell_initialize_data(r, name, dt, value, size, capacity, destructor)     cep_cell_initialize(r, CEP_TYPE_NORMAL, name, cep_data_new(dt, CEP_DATATYPE_DATA, true, NULL, value, size, capacity, destructor), NULL)

// name -> cell metacell, type_dt -> store label (record type); keep identity and structure separated.
#define cep_cell_initialize_list(r, name, type_dt, storage, ...)                  cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_initialize_dictionary(r, name, type_dt, storage, ...)            cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_initialize_catalog(r, name, type_dt, storage, ...)               cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))
#define cep_cell_initialize_spatial(r, name, type_dt, center, subwide, compare)   cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(type_dt, CEP_STORAGE_OCTREE, CEP_INDEX_BY_FUNCTION, center, subwide, compare))

static inline void  cep_cell_set_tag_id(cepCell* cell, cepID id)      {assert(cell && cep_id_valid(id));  CEP_ID_SET(cell->metacell.tag, id);}
static inline void  cep_cell_set_name(cepCell* cell, cepDT* name)     {
    assert(cell && cep_dt_is_valid(name));
    cell->metacell.domain = name->domain;
    CEP_ID_SET(cell->metacell.tag, name->tag);
}
//static inline cepDT cep_cell_get_name(const cepCell* cell)        {assert(cell);  return cell->metacell.name;}
#define cep_cell_get_tag_id(r)    cep_id(CEP_DT_PTR(r)->tag)

#define cep_cell_is_void(r)       (((r)->metacell.type == CEP_TYPE_VOID) || !cep_dt_is_valid(&(r)->metacell.dt))
#define cep_cell_is_normal(r)     ((r)->metacell.type == CEP_TYPE_NORMAL)
#define cep_cell_is_proxy(r)      ((r)->metacell.type == CEP_TYPE_PROXY)
#define cep_cell_is_link(r)       ((r)->metacell.type == CEP_TYPE_LINK)

#define cep_cell_is_shadowed(r)   ((r)->metacell.shadowing)
/* #define cep_cell_is_private(r)    ((r)->metacell.priv) */  /* Commented out: 'priv' bitfield is not defined in cepMetacell; avoid invalid access. */
/* #define cep_cell_is_system(r)     ((r)->metacell.system) */ /* Commented out: 'system' bitfield is not defined in cepMetacell; avoid invalid access. */

static inline bool cep_cell_has_data(const cepCell* cell)     {assert(cep_cell_is_normal(cell));  return cell->data;}
static inline bool cep_cell_has_store(const cepCell* cell)    {assert(cep_cell_is_normal(cell));  return cell->store;}

static inline bool cep_cell_is_deleted(const cepCell* cell) {
    assert(cell && !cep_cell_is_void(cell));

    if (cell->deleted)
        return true;

    if (!cep_cell_is_normal(cell))
        return false;

    bool hasData = (cell->data != NULL);
    bool hasStore = (cell->store != NULL);

    bool dataAlive = hasData && !cell->data->deleted;
    bool storeAlive = hasStore && !cell->store->deleted;

    if (hasData || hasStore)
        return !(dataAlive || storeAlive);

    return false;
}

static inline cepOpCount cep_cell_latest_timestamp(const cepCell* cell) {
    if (!cell || cep_cell_is_void(cell))
        return 0;

    cepOpCount latest = 0;

    if (cep_cell_is_normal(cell)) {
        if (cell->data) {
            if (cell->data->modified > latest)
                latest = cell->data->modified;
            if (cell->data->deleted > latest)
                latest = cell->data->deleted;
            if (cell->data->created > latest)
                latest = cell->data->created;
        }

        if (cell->store) {
            if (cell->store->modified > latest)
                latest = cell->store->modified;
            if (cell->store->deleted > latest)
                latest = cell->store->deleted;
            if (cell->store->created > latest)
                latest = cell->store->created;
        }
    }

    if (cell->parent && cell->parent->modified > latest)
        latest = cell->parent->modified;

    return latest;
}

static inline int cep_cell_order_compare(const cepCell* lhs, const cepCell* rhs) {
    if (lhs == rhs)
        return 0;

    bool lhsDead = cep_cell_is_deleted(lhs);
    bool rhsDead = cep_cell_is_deleted(rhs);
    if (lhsDead != rhsDead)
        return lhsDead? 1: -1;   // Alive entries come first.

    cepOpCount lhsTs = cep_cell_latest_timestamp(lhs);
    cepOpCount rhsTs = cep_cell_latest_timestamp(rhs);
    if (lhsTs > rhsTs)
        return -1;
    if (lhsTs < rhsTs)
        return 1;

    uintptr_t lhsAddr = (uintptr_t) lhs;
    uintptr_t rhsAddr = (uintptr_t) rhs;
    if (lhsAddr == rhsAddr)
        return 0;
    return (lhsAddr < rhsAddr)? -1: 1;
}

static inline int cep_store_compare_cells(const cepCell* lhs, const cepCell* rhs, cepCompare compare, void* context) {
    int cmp = compare? compare(lhs, rhs, context): 0;
    if (!cmp && lhs && rhs && !cep_cell_is_void(lhs) && !cep_cell_is_void(rhs)) {
        if (lhs->parent && lhs->parent == rhs->parent)
            cmp = cep_cell_order_compare(lhs, rhs);
    }
    return cmp;
}

static inline void cep_cell_set_data(cepCell* cell, cepData* data) {
    assert(!cep_cell_has_data(cell) && cep_data_valid(data));
    cell->data = data;
    cep_cell_shadow_mark_target_dead(cell, cep_cell_is_deleted(cell));
}
static inline void cep_cell_set_store(cepCell* cell, cepStore* store) {
    assert(!cep_cell_has_store(cell) && cep_store_valid(store));
    store->owner = cell;
    cell->store = store;
    cep_cell_shadow_mark_target_dead(cell, cep_cell_is_deleted(cell));
}

static inline cepCell*   cep_cell_parent  (const cepCell* cell)   {assert(cell);  return CEP_EXPECT_PTR(cell->parent)? cell->parent->owner: NULL;}
static inline size_t     cep_cell_siblings(const cepCell* cell)   {assert(cell);  return CEP_EXPECT_PTR(cell->parent)? cell->parent->chdCount: 0;}
static inline size_t     cep_cell_children(const cepCell* cell)   {assert(cell);  return cep_cell_has_store(cell)? cell->store->chdCount: 0;}

static inline bool cep_cell_store_locked_hierarchy(const cepCell* cell) {
    for (const cepCell* current = cell; current; current = cep_cell_parent(current)) {
        if (!cep_cell_is_normal(current))
            continue;
        const cepStore* store = current->store;
        if (store && store->lock)
            return true;
    }
    return false;
}

static inline bool cep_cell_data_locked_hierarchy(const cepCell* cell) {
    for (const cepCell* current = cell; current; current = cep_cell_parent(current)) {
        if (!cep_cell_is_normal(current))
            continue;
        const cepData* data = current->data;
        if (data && data->lock)
            return true;
    }
    return false;
}

#define cep_cell_id_is_pending(r)   cep_id_is_auto((r)->metacell.tag)
static inline void  cep_cell_set_autoid(const cepCell* cell, cepID id)  {assert(cep_cell_has_store(cell) && (cell->store->autoid < id)  &&  (id <= CEP_AUTOID_MAX)); cell->store->autoid = id;}
static inline cepID cep_cell_get_autoid(const cepCell* cell)            {assert(cep_cell_has_store(cell));  return cell->store->autoid;}

#define cep_cell_name_is(cell, name)        (0 == cep_dt_compare(CEP_DT_PTR(&(cell)->metacell), CEP_DT_PTR(name)))
static inline const cepDT* cep_cell_get_name(const cepCell* cell) {
    assert(cell);
    ((cepCell*)cell)->metacell._reserved = 0;
    return &cell->metacell.dt;
}


static inline void cep_cell_relink_storage(cepCell* cell)     {assert(cep_cell_has_store(cell));  cell->store->owner = cell;}     // Re-links cell with its own children storage.

/* Move the state from one cell into another, preserving store ownership and
   link shadow bookkeeping so references continue to point at the relocated
   cell without breaking backlink invariants. The transfer keeps parent and
   shadow metadata coherent so callers can treat the move as an atomic swap. */
void cep_cell_transfer(cepCell* src, cepCell* dst);

static inline void cep_cell_replace(cepCell* oldr, cepCell* newr) {
    cep_cell_finalize(oldr);
    cep_cell_transfer(newr, oldr);
}


// Root dictionary
static inline cepCell* cep_root(void)  {extern cepCell CEP_ROOT; assert(!cep_cell_is_void(&CEP_ROOT));  return &CEP_ROOT;}
cepOpCount  cep_cell_timestamp_next(void);
void        cep_cell_timestamp_reset(void);
static inline cepOpCount cep_cell_timestamp(void)  {extern cepOpCount CEP_OP_COUNT; return CEP_OP_COUNT;}


// Links
/* Redirect a link so it targets the resolved destination while updating the
   target's shadow metadata, ensuring backlink state remains consistent and the
   final cell always reflects who references it. This normalises any intermediate
   links so the target observes only concrete linkers and can enforce lifecycle
   invariants. */
void cep_link_set(cepCell* link, cepCell* target);

/* Initialise a link cell with the provided name and optional target, relying on
   the shared constructor while immediately normalising and recording backlink
   information when a target is supplied. This keeps freshly minted links fully
   integrated with the shadow tracking model from the moment they exist. */
void cep_link_initialize(cepCell* link, cepDT* name, cepCell* target);

/* Follow a chain of links until the first non-link cell is found so callers act
   on the canonical target while asserting the chain has no breaks or cycles.
   The helper hides the aliasing layer so higher APIs always touch the base cell.
 */
cepCell* cep_link_pull(cepCell* link);

static inline bool cep_cell_is_insertable(cepCell* cell)  {assert(cep_cell_has_store(cell));  return cell->store? cep_store_is_insertable(cell->store): false;}
static inline bool cep_cell_is_dictionary(cepCell* cell)  {assert(cep_cell_is_normal(cell));  return cell->store? cep_store_is_dictionary(cell->store): false;}
static inline bool cep_cell_is_f_sorted(cepCell* cell)    {assert(cep_cell_is_normal(cell));  return cell->store? cep_store_is_f_sorted(cell->store): false;}
static inline bool cep_cell_is_sorted(cepCell* cell)      {assert(cep_cell_is_normal(cell));  return cell->store? cep_store_is_sorted(cell->store): false;}

static inline bool cep_cell_is_empty(cepCell* cell)       {assert(cep_cell_is_normal(cell));  return (!cell->data && !cep_cell_children(cell));}
static inline bool cep_cell_is_unset(cepCell* cell)       {assert(cep_cell_is_normal(cell));  return (!cell->data && !cell->store);}
static inline bool cep_cell_is_root(cepCell* cell)        {assert(cell);  return (cell == cep_root());}
static inline bool cep_cell_is_floating(cepCell* cell)    {assert(cell);  return (cep_cell_is_void(cell)  ||  (!cep_cell_parent(cell) && !cep_cell_is_root(cell)));}


// Appends/prepends or inserts a (copy of) cell into another cell
cepCell* cep_cell_add(cepCell* cell, uintptr_t context, cepCell* child);
cepCell* cep_cell_append(cepCell* cell, bool prepend, cepCell* child);

#define cep_cell_add_child(cell, type, name, context, data, store)             \
    ({cepCell child__={0}; cep_cell_initialize(&child__, type, name, data, store); cep_cell_add(cell, context, &child__);})

#define cep_cell_add_empty(cell, name, context)                                                         cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), NULL, NULL)
#define cep_cell_add_value(cell, name, context, dt, value, size, capacity)                              cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, size, capacity), NULL)
#define cep_cell_add_data(cell, name, context, dt, value, size, capacity, destructor)                   cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), cep_data_new(dt, CEP_DATATYPE_DATA,  true, NULL, value, size, capacity, destructor), NULL)

#define cep_cell_add_list(cell, name, context, type_dt, storage, ...)                                        cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_add_dictionary(cell, name, context, type_dt, storage, ...)                                  cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_add_catalog(cell, name, context, type_dt, storage, ...)                                     cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))

#define cep_cell_add_link(cell, name, context, source)                                                  cep_cell_add_child(cell, CEP_TYPE_LINK, name, (uintptr_t)(context), CEP_P(source), NULL)

#define cep_dict_add(cell, child)                                                                       cep_cell_add(cell, 0, child)
#define cep_dict_add_empty(cell, name)                                                                  cep_cell_add_empty(cell, name, 0)
#define cep_dict_add_value(cell, name, dt, value, size, capacity)                                       cep_cell_add_value(cell, name, 0, dt, value, size, capacity)
#define cep_dict_add_data(cell, name, dt, value, size, capacity, destructor)                            cep_cell_add_data(cell, name, 0, dt, value, size, capacity, destructor)
#define cep_dict_add_list(cell, name, type_dt, storage, ...)                                                 cep_cell_add_list(cell, name, 0, type_dt, storage, ##__VA_ARGS__)
#define cep_dict_add_dictionary(cell, name, type_dt, storage, ...)                                           cep_cell_add_dictionary(cell, name, 0, type_dt, storage, ##__VA_ARGS__)
#define cep_dict_add_catalog(cell, name, type_dt, storage, ...)                                              cep_cell_add_catalog(cell, name, 0, type_dt, storage, ##__VA_ARGS__)
#define cep_dict_add_link(cell, name, source)                                                           cep_cell_add_link(cell, name, 0, source)

#define cep_cell_append_child(cell, type, name, prepend, data, store)          \
    ({cepCell child__={0}; cep_cell_initialize(&child__, type, name, data, store); cep_cell_append(cell, prepend, &child__);})

#define cep_cell_append_empty(cell, name)                                                               cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, NULL)
#define cep_cell_append_value(cell, name, dt, value, size, capacity)                                    cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, size, capacity), NULL)
#define cep_cell_append_data(cell, name, dt, value, size, capacity, destructor)                         cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, cep_data_new(dt, CEP_DATATYPE_DATA,  true, NULL, value, size, capacity, destructor), NULL)

#define cep_cell_append_list(cell, name, type_dt, storage, ...)                                              cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_append_dictionary(cell, name, type_dt, storage, ...)                                        cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_append_catalog(cell, name, type_dt, storage, ...)                                           cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))

#define cep_cell_append_link(cell, name, source)                                                        cep_cell_append_child(cell, CEP_TYPE_LINK, name, false, CEP_P(source), NULL)

#define cep_cell_prepend_empty(cell, name)                                                              cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, NULL)
#define cep_cell_prepend_value(cell, name, dt, value, size, capacity)                                   cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, size, capacity), NULL)
#define cep_cell_prepend_data(cell, name, dt, value, size, capacity, destructor)                        cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, cep_data_new(dt, CEP_DATATYPE_DATA,  true, NULL, value, size, capacity, destructor), NULL)

#define cep_cell_prepend_list(cell, name, type_dt, storage, ...)                                             cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_prepend_dictionary(cell, name, type_dt, storage, ...)                                       cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_prepend_catalog(cell, name, type_dt, storage, ...)                                          cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, cep_store_new(type_dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))

#define cep_cell_prepend_link(cell, name, source)                                                       cep_cell_append_child(cell, CEP_TYPE_LINK, name, true, CEP_P(source), NULL)


int      cep_cell_add_parents(cepCell* derived, cepCell* const* parents, size_t count);
uint64_t cep_cell_content_hash(cepCell* cell);
int      cep_cell_set_content_hash(cepCell* cell, uint64_t hash);


// Constructs the full path (sequence of ids) for a given cell, returning the depth
bool cep_cell_path(const cepCell* cell, cepPath** path);


// Accessing branched cells
cepCell* cep_cell_first_past(const cepCell* cell, cepOpCount snapshot);
#define  cep_cell_first(cell)           cep_cell_first_past((cell), 0)
cepCell* cep_cell_last_past (const cepCell* cell, cepOpCount snapshot);
#define  cep_cell_last(cell)            cep_cell_last_past((cell), 0)

cepCell* cep_cell_find_by_name_past(const cepCell* cell, const cepDT* name, cepOpCount snapshot);
#define  cep_cell_find_by_name(cell, name)                  cep_cell_find_by_name_past((cell), (name), 0)
cepCell* cep_cell_find_by_key(const cepCell* cell, cepCell* key, cepCompare compare, void* context);
cepCell* cep_cell_find_by_position_past(const cepCell* cell, size_t position, cepOpCount snapshot);
#define  cep_cell_find_by_position(cell, position)          cep_cell_find_by_position_past((cell), (position), 0)
cepCell* cep_cell_find_by_path_past(const cepCell* start, const cepPath* path, cepOpCount snapshot);
#define  cep_cell_find_by_path(start, path)                 cep_cell_find_by_path_past((start), (path), 0)

bool cep_cell_indexof(const cepCell* parent, const cepCell* child, size_t* position);

cepCell* cep_cell_prev_past(const cepCell* cell, cepCell* child, cepOpCount snapshot);
#define  cep_cell_prev(cell, child)     cep_cell_prev_past((cell), (child), 0)
cepCell* cep_cell_next_past(const cepCell* cell, cepCell* child, cepOpCount snapshot);
#define  cep_cell_next(cell, child)     cep_cell_next_past((cell), (child), 0)

cepCell* cep_cell_find_next_by_name_past(const cepCell* cell, cepDT* name, uintptr_t* childIdx, cepOpCount snapshot);
#define  cep_cell_find_next_by_name(cell, name, childIdx)   cep_cell_find_next_by_name_past((cell), (name), (childIdx), 0)
cepCell* cep_cell_find_next_by_path_past(const cepCell* start, cepPath* path, uintptr_t* prev, cepOpCount snapshot);
#define  cep_cell_find_next_by_path(start, path, prev)      cep_cell_find_next_by_path_past((start), (path), (prev), 0)

bool cep_cell_traverse      (cepCell* cell, cepTraverse func, void* context, cepEntry* entry);
bool cep_cell_traverse_internal(cepCell* cell, cepTraverse func, void* context, cepEntry* entry);
bool cep_cell_traverse_past (cepCell* cell, cepOpCount timestamp, cepTraverse func, void* context, cepEntry* entry);

bool cep_cell_deep_traverse_past(cepCell* cell, cepOpCount timestamp, cepTraverse func, cepTraverse listEnd, void* context, cepEntry* entry);
bool cep_cell_deep_traverse (cepCell* cell, cepTraverse func, cepTraverse listEnd, void* context, cepEntry* entry);
bool cep_cell_deep_traverse_internal(cepCell* cell, cepTraverse func, cepTraverse listEnd, void* context, cepEntry* entry);


// Removing cells
bool cep_cell_child_take(cepCell* cell, cepCell* target);
bool cep_cell_child_pop(cepCell* cell, cepCell* target);
bool cep_cell_child_take_hard(cepCell* cell, cepCell* target);
bool cep_cell_child_pop_hard(cepCell* cell, cepCell* target);
void cep_cell_remove_hard(cepCell* cell, cepCell* target);

static inline void cep_cell_delete_data(cepCell* cell) {
    if (!cell || cep_cell_is_void(cell) || !cep_cell_is_normal(cell) || !cell->data)
        return;

    if (cep_cell_data_locked_hierarchy(cell))
        return;

    if (!cell->data->deleted)
        cell->data->deleted = cep_cell_timestamp();

    cell->data->writable = false;

    cep_cell_shadow_mark_target_dead(cell, cep_cell_is_deleted(cell));
}

static inline void cep_cell_delete_data_hard(cepCell* cell) {
    if (!cep_cell_has_data(cell))
        return;

    if (cep_cell_data_locked_hierarchy(cell))
        return;

    cep_cell_delete_data(cell);
    cep_data_del(cell->data);
    cell->data = NULL;

    cep_cell_shadow_mark_target_dead(cell, cep_cell_is_deleted(cell));
}

static inline void cep_cell_delete_store(cepCell* cell) {
    if (!cell || cep_cell_is_void(cell) || !cep_cell_is_normal(cell) || !cell->store)
        return;

    if (cep_cell_store_locked_hierarchy(cell))
        return;

    if (!cell->store->deleted)
        cell->store->deleted = cep_cell_timestamp();

    cell->store->writable = false;

    cep_cell_shadow_mark_target_dead(cell, cep_cell_is_deleted(cell));
}

static inline void cep_cell_delete_store_hard(cepCell* cell) {
    if (!cep_cell_has_store(cell))
        return;

    if (cep_cell_store_locked_hierarchy(cell))
        return;

    cep_cell_delete_store(cell);
    cep_store_del(cell->store);
    cell->store = NULL;

    cep_cell_shadow_mark_target_dead(cell, cep_cell_is_deleted(cell));
}

static inline void cep_cell_delete(cepCell* cell);

static inline void cep_cell_delete_children(cepCell* cell) {
    if (!cell || cep_cell_is_void(cell) || !cep_cell_is_normal(cell) || !cell->store)
        return;

    if (cep_cell_store_locked_hierarchy(cell))
        return;

    for (cepCell* child = cep_cell_first(cell); child; child = cep_cell_next(cell, child)) {
        if (!cep_cell_is_deleted(child))
            cep_cell_delete(child);
    }
}

static inline void cep_cell_delete_children_hard(cepCell* cell) {
    assert(cep_cell_has_store(cell));
    cep_cell_delete_children(cell);
    cep_store_delete_children_hard(cell->store);
}

static inline void cep_cell_delete(cepCell* cell) {
    if (!cell || cep_cell_is_void(cell) || cep_cell_is_root(cell))
        return;

    if (!cep_cell_is_normal(cell))
        return;

    if (cep_cell_data_locked_hierarchy(cell) || cep_cell_store_locked_hierarchy(cell))
        return;

    if (cep_cell_has_data(cell))
        cep_cell_delete_data(cell);

    if (cep_cell_has_store(cell)) {
        cep_cell_delete_children(cell);
        cep_cell_delete_store(cell);
    }

    if (!cell->deleted)
        cell->deleted = cep_cell_timestamp();

    cep_cell_shadow_mark_target_dead(cell, cep_cell_is_deleted(cell));
}

static inline void cep_cell_delete_hard(cepCell* cell) {
    if (!cell || cep_cell_is_void(cell) || cep_cell_is_root(cell))
        return;

    cep_cell_delete(cell);
    cep_cell_remove_hard(cell, NULL);
}

static inline void cep_cell_dispose(cepCell* cell) {
    if (!cell || cep_cell_is_void(cell) || cep_cell_is_root(cell))
        return;

    cep_cell_delete(cell);
}

static inline void cep_cell_dispose_hard(cepCell* cell) {
    if (!cell || cep_cell_is_void(cell) || cep_cell_is_root(cell))
        return;

    cep_cell_dispose(cell);

    if (cep_cell_parent(cell))
        cep_cell_remove_hard(cell, NULL);
    else
        cep_cell_finalize_hard(cell);
}


// Accessing data
void* cep_cell_data(const cepCell* cell);
void* cep_cell_data_find_by_name_past(const cepCell* cell, cepDT* name, cepOpCount snapshot);

static inline void* cep_cell_data_find_by_name(const cepCell* cell, cepDT* name) {
    return cep_cell_data_find_by_name_past(cell, name, 0);
}

void* cep_cell_update(cepCell* cell, size_t size, size_t capacity, void* value, bool swap);
void* cep_cell_update_hard(cepCell* cell, size_t size, size_t capacity, void* value, bool swap);
#define cep_cell_update_value(r, z, v)    cep_cell_update(r, (z), sizeof(*(v)), v, false)
//#define cep_cell_update_attribute(r, a)   do{ assert(cep_cell_has_data(r));  (r)->data.attribute.id = CEP_ID(a); }while(0)


// Converts an unsorted cell into a sorted one
void cep_cell_to_dictionary(cepCell* cell);
void cep_cell_sort(cepCell* cell, cepCompare compare, void* context);


// Initiate and shutdown cell system
void cep_cell_system_initiate(void);
void cep_cell_system_shutdown(void);
bool cep_cell_system_initialized(void);
void cep_cell_system_ensure(void);


// Namepool helpers (mirrored for convenience)
bool        cep_namepool_bootstrap(void);
cepID       cep_namepool_intern(const char* text, size_t length);
cepID       cep_namepool_intern_cstr(const char* text);
cepID       cep_namepool_intern_static(const char* text, size_t length);
cepID       cep_namepool_intern_pattern(const char* text, size_t length);
cepID       cep_namepool_intern_pattern_cstr(const char* text);
cepID       cep_namepool_intern_pattern_static(const char* text, size_t length);
bool        cep_namepool_release(cepID id);
bool        cep_namepool_reference_is_glob(cepID id);


#ifdef __cplusplus
}
#endif


#endif
