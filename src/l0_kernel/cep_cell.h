/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */

#ifndef CEP_CELL_H
#define CEP_CELL_H


#include "cep_molecule.h"


#ifdef __cplusplus
extern "C" {
#endif


/*
    CEP - Layer 0 - Cell implementation
    -----------------------------------

    This is designed to represent and manage hierarchical data structures in a 
    distributed execution environment, similar in flexibility to representing 
    complex XML or JSON data models. It facilitates the storage, navigation, 
    and manipulation of records, which can point to data values (holding actual 
    information) and to branches of other records (acting as nodes in the 
    hierarchical structure).

    Key Components
    --------------

    * Cell: The fundamental unit within the system, capable of storing data
    and having children cells at the same time.

    * Link: A record that points to another cell.

    * Metacell: Each cell contains meta, including flags that specify the 
    cell's characteristics, and a name identifier indicating the cell's role or 
    ID within its parent.

    * Data: This is where the actual data (value) being hold by the cell is 
    located. It has its own metadata.

    * Store: Storage for children cells according to different indexing 
    techniques.

    The system supports navigating from any cell to the root of the database, 
    reconstructing paths within the data hierarchy based on field identifiers 
    in parent cells.

    Children Storage Techniques
    ---------------------------

    * Store Metadata: Stores serve as a versatile container within the system,
    holding child cells through diverse storage strategies. Each storage can
    adopt one of several mechanisms, determined by the structure indicator in
    its metadata. This design enables tailored optimization based on specific
    needs, such as operation frequency, data volume, and access patterns.

    * Storage Types: Each storage type is selected to optimize specific aspects
    of data management, addressing the system's goals of flexibility,
    efficiency, and navigability.

      Doubly Linked List: Provides flexibility for frequent insertions
      and deletions at arbitrary positions with minimal overhead per
      operation.

      Array: Offers fast access and efficient cache utilization for
      densely packed records. Ideal for situations where the number of
      children is relatively static and operations are predominantly at
      the tail end.

      Packed Queue: Strikes a balance between the cache efficiency of
      arrays and the flexibility of linked lists. It's optimized for
      scenarios where operations in head and tail are common.

      Red-Black Tree: Ensures balanced tree structure for ordered data,
      offering logarithmic time complexity for insertions, deletions,
      and lookups. Particularly useful for datasets requiring sorted
      access.

      Octree: Used for (3D) spatial indexing according to contained data.
      It only needs a comparation function able to determine if the record
      fully fits inside a quadrant or not.
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

typedef struct {
    struct {
        cepID           _sysbits1:  6,  // Used by other parts of CEP system.
                        domain:     CEP_NAME_BITS;
    };
    struct {
        cepID           _sysbits2:  6,  // Used by other parts of CEP system.
                        tag:        CEP_NAME_BITS;
    };
} cepDT;

#define CEP_DT(p)       ((cepDT*)(p))

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

typedef struct {
  union {
    cepDT       _dt;
    
    struct {
      struct {
        cepID   type:       2,    // Type of cell (dictionary, link, etc).
                hidden:     1,    // Cell won't appear on listings (it can only be accessed directly).
                shadowing:  2,    // If cell has shadowing cells (links pointing to it).
                targetDead: 1,    // Set (1) if this cell is a link and the target died.

                domain:     CEP_NAME_BITS;
      };
      struct {
        cepID   _reserved:  6,
                tag:        CEP_NAME_BITS;
      };
    };
  };
} cepMetacell;

static_assert(sizeof(cepMetacell) == sizeof(cepDT), "System bits can't exceed 2 pairs of 6 bits!");


enum _cepCellType {
    CEP_TYPE_VOID,              // A void (uninitialized) cell.
    CEP_TYPE_NORMAL,            // Regular cell.
    CEP_TYPE_PROXY,             // Virtual cell whose payload is mediated through proxy callbacks.
    CEP_TYPE_LINK,              // Link to another cell.
    //
    CEP_TYPE_COUNT
};

enum _cepCellShadowing {
    CEP_SHADOW_NONE,            // No shadow cells.
    CEP_SHADOW_SINGLE,          // Single shadow cell.
    CEP_SHADOW_MULTIPLE,        // Multiple shadows.
};

enum _cepCellNaming {
    CEP_NAMING_WORD,            // Lowercase text value, 11 chars max (it must be the first in this enum!).
    CEP_NAMING_ACRONYM,         // Uppercase/numeric text, 9 characters maximum.
    CEP_NAMING_REFERENCE,       // Numerical reference to text cell (a pointer in 32bit systems).
    CEP_NAMING_NUMERIC,         // Per-parent numerical ID.

    CEP_NAMING_COUNT
};


#define cep_id_from_naming(naming)      (((cepID)((naming) & 3)) << CEP_AUTOID_BITS)
#define CEP_NAMING_MASK                 cep_id_from_naming(3)

#define cep_id_to_word(word)            ((word) | cep_id_from_naming(CEP_NAMING_WORD))
#define cep_id_to_acronym(acro)         ((acro) | cep_id_from_naming(CEP_NAMING_ACRONYM))
#define cep_id_to_reference(ref)        ((ref)  | cep_id_from_naming(CEP_NAMING_REFERENCE))
#define cep_id_to_numeric(numb)         ((numb) | cep_id_from_naming(CEP_NAMING_NUMERIC))

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
#define cep_id_text_valid(name)         (cep_id(name) && !cep_id_is_numeric(name))
#define cep_id_naming(name)             (((name) >> CEP_AUTOID_BITS) & 3)

#define cep_dt_valid(dt)                ((dt) && cep_id_text_valid((dt)->domain) && cep_id_valid((dt)->tag))


// Converting C text strings to/from cepID

/* Acronym character chart (ASCII lower set):
 H \  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
 - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
2x \  SP  !   "   #   $   %   &   '   (   )   *   +   ,   -   .   /
3x \  0   1   2   3   4   5   6   7   8   9   :   ;   <   =   >   ?
4x \  @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
5x \  P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
*/
#define CEP_ACRON_MAX_CHARS     9

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
        for (size_t n = 0; n < len; n++) {                                     \
            char c = s[n];                                                     \
                                                                               \
            if (c < 0x20  ||  c > 0x5F)                                        \
                return 0;   /* Uncodable characters. */                        \
                                                                               \
            /* Shift and encode each character: */                             \
            coded |= (cepID)(c - 0x20) << (6 * ((CEP_ACRON_MAX_CHARS-1) - n)); \
        }                                                                      \
                                                                               \
        return cep_id_to_acronym(coded);                                       \
    }


/* Word character chart (ASCII upper set):
 H \  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
 - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
6x \ [SP] a   b   c   d   e   f   g   h   i   j   k   l   m   n   o
7x \  p   q   r   s   t   u   v   w   x   y   z  [:] [_] [-] [.] [/]
    Note: characters in square brackets replacing originals.
*/
#define CEP_WORD_MAX_CHARS      11

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
              case '/': encoded_char = 31;  break;                             \
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

#define CEP_DTS(d, t)   (&(cepDT){.domain=(d), .tag=(t)})
#define CEP_DTWW(d, t)  CEP_DTS(CEP_WORD(d), CEP_WORD(t))
#define CEP_DTWA(d, t)  CEP_DTS(CEP_WORD(d), CEP_ACRO(t))
#define CEP_DTAA(d, t)  CEP_DTS(CEP_ACRO(d), CEP_ACRO(t))
#define CEP_DTAW(d, t)  CEP_DTS(CEP_ACRO(d), CEP_WORD(t))

cepID  cep_text_to_acronym(const char *s);
size_t cep_acronym_to_text(cepID acro, char s[10]);

cepID  cep_text_to_word(const char *s);
size_t cep_word_to_text(cepID coded, char s[12]);


/*
    Cell Data
*/

typedef struct _cepEnzymeBinding cepEnzymeBinding;

enum {
    CEP_ENZYME_BIND_PROPAGATE = 1u << 0,
    CEP_ENZYME_BIND_TOMBSTONE = 1u << 1,
};

struct _cepEnzymeBinding {
    cepEnzymeBinding*   next;
    cepDT               name;
    uint32_t            flags;
    cepOpCount          modified;
};

typedef struct _cepDataNode  cepDataNode;
struct _cepDataNode {
    cepOpCount          modified;       // CEP heartbeat in which data was modified (including creation/deletion). 
    cepDataNode*        past;           // Pointer to past data content history.
    
    cepEnzymeBinding*   bindings;       // List of enzyme bindings.
    
    size_t              size;           // Data size in bytes.
    size_t              capacity;       // Buffer capacity in bytes.
    uint64_t            hash;           // Hash value of content.

    union {
        struct {
            void*       data;           // Points to container of data value.
            cepDel      destructor;     // Data container destruction function.
        };
        struct {
          union {
            cepCell*    handle;         // Resource cell id (used with external libraries).
            cepCell*    stream;         // Data window to streamed content.
          };
          cepCell*      library;        // Library where the resource is located.
        };
        uint8_t         value[2 * sizeof(void*)];  // Data value may start from here.
    };
};

struct _cepData {
    union {
      cepDT             _dt;
      
      struct {
        struct {
          cepID         datatype:   2,  // Type of data (see _cepDataType).
                        _unused:    4, 

                        domain:     CEP_NAME_BITS;
        };
        struct {
          cepID         writable:   1,  // If data can be updated.
                        lock:       1,  // Lock on data content.
                        _reserved:  4,
                        
                        tag:        CEP_NAME_BITS;
        };
      };
    };
    
    cepOpCount          created;        // Data content creation time.
    cepOpCount          deleted;        // Data content deletion time (if any).

    cepDataNode;
    cepCell*            lockOwner;      // Cell that currently holds the payload lock (if any).
};

enum _cepDataType {
    CEP_DATATYPE_VALUE,         // Data starts at "value" field of cepData.
    CEP_DATATYPE_DATA,          // Data is in address pointed by "data" field.
    CEP_DATATYPE_HANDLE,        // Data is just a handle to an opaque (library internal) resource.
    CEP_DATATYPE_STREAM,        // Data is a window to a larger (library internal) stream.
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

    switch (data->datatype) {
      case CEP_DATATYPE_VALUE:
      case CEP_DATATYPE_DATA:
        return cep_hash_bytes(cep_data_payload(data), data->size);

      case CEP_DATATYPE_HANDLE:
      case CEP_DATATYPE_STREAM: {
        uint64_t hash = 0;
        hash ^= cep_hash_bytes(&data->handle, sizeof data->handle);
        hash ^= cep_hash_bytes(&data->library, sizeof data->library);
        return hash;
      }
    }

    return 0;
}

typedef struct {
    void*       address;        // Backing memory exposed to the caller.
    size_t      length;         // Span length mapped into the caller's address space.
    uint64_t    offset;         // Stream offset associated with the view.
    unsigned    access;         // Access flags requested for the view.
    void*       token;          // Library or kernel specific handle to release resources.
} cepStreamView;

enum {
    CEP_STREAM_ACCESS_READ   = 1u << 0,
    CEP_STREAM_ACCESS_WRITE  = 1u << 1,
};

typedef struct {
    const void* payload;        // Snapshot payload bytes (may point to an external buffer).
    size_t      size;           // Size of the payload bytes.
    uint32_t    flags;          // Snapshot flags describing the payload semantics.
    void*       ticket;         // Opaque handle passed back to the proxy when releasing the snapshot.
} cepProxySnapshot;

enum {
    CEP_PROXY_SNAPSHOT_INLINE   = 1u << 0,   // Payload is in-memory and owned by the proxy module.
    CEP_PROXY_SNAPSHOT_EXTERNAL = 1u << 1,   // Payload references external state that must be refetched.
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
    const cepLibraryOps* ops;   // Adapter vtable registered by the foreign library.
    void*                ctx;   // Library defined context passed back on every invocation.
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
#define  cep_data_valid(d)                             ((d) && (d)->capacity && cep_dt_valid(&(d)->_dt))
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
    unsigned        count;      // Number of cell pointers.
    unsigned        capacity;   // Capacity of array.
    cepCell*        cell[];     // Array of cells shadowing this one.
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
        cepCell*        linked;     // A linked shadow cell (when children, see in cepCell otherwise).
        cepShadow*      shadow;     // Shadow structure (if cell has children).
    };

    cepOpCount          modified;   // CEP heartbeat in which store was modified (including creation/deletion). 
    
    cepStoreNode*       past;       // Points to the previous store index in history (only used if catalog is re-sorted/indexed with different sorting function).

    cepEnzymeBinding*   bindings; // List of enzyme bindings.

    size_t              chdCount;   // Number of child cells.
    size_t              totCount;   // Number of all cells included dead ones.
    cepCompare          compare;    // Compare function for indexing children.
    cepCell*            lockOwner;  // Cell that currently holds the structural lock (if any).

    // The specific storage structure will follow after this...
};

struct _cepStore {
    union {
      cepDT         _dt;
      
      struct {
        struct {
        cepID       storage:    3,              // Data structure for children storage (array, linked-list, etc).
                    indexing:   2,              // Indexing (sorting) criteria for children.
                    _unused:    1,

                    domain:     CEP_NAME_BITS;
        };
        struct {
        cepID       writable:   1,              // If chidren can be added/deleted.
                    lock:       1,              // Lock on children operations.
                    _reserved:  4,

                    tag:        CEP_NAME_BITS;
        };
      };
    };

    cepCell*        owner;      // Cell owning this child storage.

    cepOpCount      created;    // CEP heartbeat in which store was created. 
    cepOpCount      deleted;    // CEP heartbeat in which store was deleted (if any). 

    cepID           autoid;     // Auto-increment ID for inserting new child cells.

    cepStoreNode;
};

enum _cepCellStorage {
    CEP_STORAGE_LINKED_LIST,    // Children stored in a doubly linked list.
    CEP_STORAGE_ARRAY,          // Children stored in an array.
    CEP_STORAGE_PACKED_QUEUE,   // Children stored in a packed queue.
    CEP_STORAGE_RED_BLACK_T,    // Children stored in a red-black tree.
    CEP_STORAGE_OCTREE,         // Children stored in an octree spatial index.
    //
    CEP_STORAGE_COUNT
};

enum _cepCellIndexing {
    CEP_INDEX_BY_INSERTION,      // Children indexed by their insertion order (the default).
    CEP_INDEX_BY_NAME,           // Children indexed by their unique name (a dicionary).
    CEP_INDEX_BY_FUNCTION,       // Children indexed by a custom comparation function.
    CEP_INDEX_BY_HASH,           // Children indexed by data hash value (first) and then by a comparation function (second).
    //
    CEP_INDEX_COUNT
};


cepStore* cep_store_new(cepDT* dt, unsigned storage, unsigned indexing, ...);
void      cep_store_del(cepStore* store);
void      cep_store_delete_children_hard(cepStore* store);
#define   cep_store_valid(s)      ((s) && cep_dt_valid(&(s)->_dt))

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
    cepDT           dt;         // Path segment identifier.
    cepOpCount      timestamp;  // Snapshot timestamp for this segment (0 means latest).
} cepPast;

typedef struct {
    unsigned        length;
    unsigned        capacity;
    cepPast         past[];
} cepPath;


struct _cepCell {
    cepMetacell     metacell;   // Meta about this cell entry (including name (DT), system bits, etc).
    cepStore*       parent;     // Parent structure (list, array, etc) where this cell is stored in.

    union {
        cepData*    data;       // Address of cepData structure.

        cepCell*    link;       // Link to another cell.

        cepProxy*   proxy;      // Proxy definition mediating externalised payloads.
    };

    union {
        cepStore*   store;      // Address of cepStore structure.

        cepCell*    linked;     // A linked shadow cell (if no children, see in cepStore otherwise).
        cepShadow*  shadow;     // Structure for multiple linked cells (if no children).

        //cepCell*  instance;   // Agent instance this cell belongs to (if cell is a Link).
    };
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
void cep_cell_finalize(cepCell* cell);
void cep_cell_shadow_mark_target_dead(cepCell* cell, bool dead);

#define cep_cell_initialize_empty(r, name)                                                            cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, NULL)
#define cep_cell_initialize_value(r, name, dt, value, size, capacity)                cep_cell_initialize(r, CEP_TYPE_NORMAL, name, cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, size, capacity), NULL)
#define cep_cell_initialize_data(r, name, dt, value, size, capacity, destructor)     cep_cell_initialize(r, CEP_TYPE_NORMAL, name, cep_data_new(dt, CEP_DATATYPE_DATA, true, NULL, value, size, capacity, destructor), NULL)

#define cep_cell_initialize_list(r, name, dt, storage, ...)                  cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_initialize_dictionary(r, name, dt, storage, ...)            cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_initialize_catalog(r, name, dt, storage, ...)               cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))
#define cep_cell_initialize_spatial(r, name, dt, center, subwide, compare)   cep_cell_initialize(r, CEP_TYPE_NORMAL, name, NULL, cep_store_new(dt, CEP_STORAGE_OCTREE, CEP_INDEX_BY_FUNCTION, center, subwide, compare))

static inline void  cep_cell_set_tag_id(cepCell* cell, cepID id)      {assert(cell && cep_id_valid(id));  CEP_ID_SET(cell->metacell.tag, id);}
static inline void  cep_cell_set_name(cepCell* cell, cepDT* name)     {assert(cell && cep_dt_valid(name));  cell->metacell.domain = name->domain; cell->metacell.tag = name->tag;}    // FixMe: mask 'name->tag' before assignation.
//static inline cepDT cep_cell_get_name(const cepCell* cell)        {assert(cell);  return cell->metacell.name;}
#define cep_cell_get_tag_id(r)    cep_id(CEP_DT(r)->tag)

#define cep_cell_is_void(r)       (((r)->metacell.type == CEP_TYPE_VOID) || !cep_dt_valid(&(r)->metacell._dt))
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

    if (!cep_cell_is_normal(cell))
        return false;

    bool dataDeleted  = !cell->data  || cell->data->deleted;
    bool storeDeleted = !cell->store || cell->store->deleted;

    return dataDeleted && storeDeleted;
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

#define cep_cell_name_is(cell, name)        (0 == cep_dt_compare(CEP_DT(&(cell)->metacell), CEP_DT(name)))
#define cep_cell_get_name(cell)             (&(cell)->metacell._dt)     /* FixMe: filter sysbits out? */


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

#define cep_cell_add_list(cell, name, context, dt, storage, ...)                                        cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), NULL, cep_store_new(dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_add_dictionary(cell, name, context, dt, storage, ...)                                  cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), NULL, cep_store_new(dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_add_catalog(cell, name, context, dt, storage, ...)                                     cep_cell_add_child(cell, CEP_TYPE_NORMAL, name, (uintptr_t)(context), NULL, cep_store_new(dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))

#define cep_cell_add_link(cell, name, context, source)                                                  cep_cell_add_child(cell, CEP_TYPE_LINK, name, (uintptr_t)(context), CEP_P(source), NULL)

#define cep_dict_add(cell, child)                                                                       cep_cell_add(cell, 0, child)
#define cep_dict_add_empty(cell, name)                                                                  cep_cell_add_empty(cell, name, 0)
#define cep_dict_add_value(cell, name, dt, value, size, capacity)                                       cep_cell_add_value(cell, name, 0, dt, value, size, capacity)
#define cep_dict_add_data(cell, name, dt, value, size, capacity, destructor)                            cep_cell_add_data(cell, name, 0, dt, value, size, capacity, destructor)
#define cep_dict_add_list(cell, name, dt, storage, ...)                                                 cep_cell_add_list(cell, name, 0, dt, storage, ##__VA_ARGS__)
#define cep_dict_add_dictionary(cell, name, dt, storage, ...)                                           cep_cell_add_dictionary(cell, name, 0, dt, storage, ##__VA_ARGS__)
#define cep_dict_add_catalog(cell, name, dt, storage, ...)                                              cep_cell_add_catalog(cell, name, 0, dt, storage, ##__VA_ARGS__)
#define cep_dict_add_link(cell, name, source)                                                           cep_cell_add_link(cell, name, 0, source)

#define cep_cell_append_child(cell, type, name, prepend, data, store)          \
    ({cepCell child__={0}; cep_cell_initialize(&child__, type, name, data, store); cep_cell_append(cell, prepend, &child__);})

#define cep_cell_append_empty(cell, name)                                                               cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, NULL)
#define cep_cell_append_value(cell, name, dt, value, size, capacity)                                    cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, size, capacity), NULL)
#define cep_cell_append_data(cell, name, dt, value, size, capacity, destructor)                         cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, cep_data_new(dt, CEP_DATATYPE_DATA,  true, NULL, value, size, capacity, destructor), NULL)

#define cep_cell_append_list(cell, name, dt, storage, ...)                                              cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_append_dictionary(cell, name, dt, storage, ...)                                        cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_append_catalog(cell, name, dt, storage, ...)                                           cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, false, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))

#define cep_cell_append_link(cell, name, source)                                                        cep_cell_append_child(cell, CEP_TYPE_LINK, name, false, CEP_P(source), NULL)

#define cep_cell_prepend_empty(cell, name)                                                              cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, NULL)
#define cep_cell_prepend_value(cell, name, dt, value, size, capacity)                                   cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, cep_data_new(dt, CEP_DATATYPE_VALUE, true, NULL, value, size, capacity), NULL)
#define cep_cell_prepend_data(cell, name, dt, value, size, capacity, destructor)                        cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, cep_data_new(dt, CEP_DATATYPE_DATA,  true, NULL, value, size, capacity, destructor), NULL)

#define cep_cell_prepend_list(cell, name, dt, storage, ...)                                             cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_INSERTION, ##__VA_ARGS__))
#define cep_cell_prepend_dictionary(cell, name, dt, storage, ...)                                       cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_NAME, ##__VA_ARGS__))
#define cep_cell_prepend_catalog(cell, name, dt, storage, ...)                                          cep_cell_append_child(cell, CEP_TYPE_NORMAL, name, true, NULL, cep_store_new(dt, storage, CEP_INDEX_BY_FUNCTION, ##__VA_ARGS__))

#define cep_cell_prepend_link(cell, name, source)                                                       cep_cell_append_child(cell, CEP_TYPE_LINK, name, true, CEP_P(source), NULL)


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

cepCell* cep_cell_prev_past(const cepCell* cell, cepCell* child, cepOpCount snapshot);
#define  cep_cell_prev(cell, child)     cep_cell_prev_past((cell), (child), 0)
cepCell* cep_cell_next_past(const cepCell* cell, cepCell* child, cepOpCount snapshot);
#define  cep_cell_next(cell, child)     cep_cell_next_past((cell), (child), 0)

cepCell* cep_cell_find_next_by_name_past(const cepCell* cell, cepDT* name, uintptr_t* childIdx, cepOpCount snapshot);
#define  cep_cell_find_next_by_name(cell, name, childIdx)   cep_cell_find_next_by_name_past((cell), (name), (childIdx), 0)
cepCell* cep_cell_find_next_by_path_past(const cepCell* start, cepPath* path, uintptr_t* prev, cepOpCount snapshot);
#define  cep_cell_find_next_by_path(start, path, prev)      cep_cell_find_next_by_path_past((start), (path), (prev), 0)

bool cep_cell_traverse      (cepCell* cell, cepTraverse func, void* context, cepEntry* entry);
bool cep_cell_traverse_past (cepCell* cell, cepOpCount timestamp, cepTraverse func, void* context, cepEntry* entry);
bool cep_cell_deep_traverse_past(cepCell* cell, cepOpCount timestamp, cepTraverse func, cepTraverse listEnd, void* context, cepEntry* entry);
bool cep_cell_deep_traverse (cepCell* cell, cepTraverse func, cepTraverse listEnd, void* context, cepEntry* entry);


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
        cep_cell_finalize(cell);
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


/*
    TODO:
    - Implement a 'one-member only' dictionary, intended for organizational purposes.
    - Implement range queries (between a minimum and a maximum key) for cells.
    - Implement clone (deep copy) cells.
    - Traverse book in internal (stoTech) order.
    - Add indexof() for cells.
    - Update MAX_DEPTH based on path/traverse operations.
    - If a cell is added with its name explicitly above "auto_id", then that must be updated.
*/

#ifdef __cplusplus
}
#endif


#endif
