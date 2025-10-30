/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_stream_zip.h"
#include "cep_stream_internal.h"
#include "cep_cei.h"
#include "cep_heartbeat.h"

#ifdef CEP_HAS_LIBZIP

#include <zip.h>

CEP_DEFINE_STATIC_DT(dt_zip_entry_type,   CEP_ACRO("CEP"), CEP_WORD("zip_entry"));
CEP_DEFINE_STATIC_DT(dt_zip_stream_type,  CEP_ACRO("CEP"), CEP_WORD("zip_stream"));
CEP_DEFINE_STATIC_DT(dt_zip_sev_crit,     CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_zip_sev_usage,    CEP_ACRO("CEP"), CEP_WORD("sev:usage"));

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>

static char* cep_zip_strdup(const char* s) {
    if (!s)
        return NULL;
    size_t len = strlen(s) + 1u;
    char* copy = cep_malloc(len);
    if (copy)
        memcpy(copy, s, len);
    return copy;
}

typedef struct {
    zip_t*     archive;
    char*      path;
    unsigned   refcount;
    bool       owner;
} cepZipArchive;

typedef struct {
    cepZipArchive* archive;
    zip_uint64_t   index;
    char*          name;
} cepZipEntry;

/* Guard CEI emissions until the runtime has finished bootstrap, otherwise zip
   resource probes during startup would produce fatal diagnostics prematurely. */
static bool cep_zip_can_emit_cei(void) {
    return cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL);
}

/* Emit a CEI fact describing a libzip-backed stream failure. Critical I/O
   faults stay pinned in the mailbox, while usage mistakes are recorded as
   advisory entries so tooling can alert without forcing shutdown. */
static void cep_zip_emit_failure(bool io_fault,
                                 cepCell* subject,
                                 const char* topic,
                                 const char* detail_fmt,
                                 ...) {
    if (!topic || !detail_fmt) {
        return;
    }
    if (!cep_zip_can_emit_cei()) {
        return;
    }

    char note[256];
    va_list args;
    va_start(args, detail_fmt);
    vsnprintf(note, sizeof note, detail_fmt, args);
    va_end(args);

    cepCell* canonical = subject ? cep_link_pull(subject) : NULL;
    if (!canonical) {
        canonical = subject;
    }
    if (canonical && !cep_cell_is_normal(canonical)) {
        canonical = NULL;
    }
    if (canonical && (!cep_cell_parent(canonical) || cep_cell_is_root(canonical))) {
        canonical = NULL;
    }

    const cepDT* severity = io_fault ? dt_zip_sev_crit() : dt_zip_sev_usage();
    cepCeiRequest req = {
        .severity = *severity,
        .note = note,
        .topic = topic,
        .topic_intern = true,
        .subject = canonical,
        .emit_signal = true,
        .ttl_forever = io_fault,
    };
    (void)cep_cei_emit(&req);
}

static const char* cep_zip_error_desc(zip_t* archive) {
    if (!archive) {
        return "zip:unknown";
    }
    const char* text = zip_strerror(archive);
    return text ? text : "zip:unknown";
}

static void cep_zip_entry_destructor(void* data) {
    cepZipEntry* entry = data;
    if (!entry)
        return;

    if (entry->archive && entry->archive->refcount)
        entry->archive->refcount--;

    if (entry->name)
        cep_free(entry->name);

    cep_free(entry);
}

static cepZipEntry* cep_zip_entry_from_cell(cepCell* cell) {
    if (!cell || !cep_cell_has_data(cell))
        return NULL;

    cepData* data = cell->data;
    if (!data || data->datatype != CEP_DATATYPE_DATA)
        return NULL;

    return (cepZipEntry*) data->data;
}

static bool cep_zip_stream_read(const cepLibraryBinding* binding, cepCell* resource, uint64_t offset, void* dst, size_t size, size_t* out_read);
static bool cep_zip_stream_write(const cepLibraryBinding* binding, cepCell* resource, uint64_t offset, const void* src, size_t size, size_t* out_written);
static bool cep_zip_stream_expected_hash(const cepLibraryBinding* binding, cepCell* resource, uint64_t offset, size_t size, uint64_t* out_hash);

static const cepLibraryOps cep_zip_ops = {
    .handle_retain = NULL,
    .handle_release = NULL,
    .stream_read = cep_zip_stream_read,
    .stream_write = cep_zip_stream_write,
    .stream_expected_hash = cep_zip_stream_expected_hash,
    .stream_map = NULL,
    .stream_unmap = NULL,
    .handle_snapshot = NULL,
    .handle_restore = NULL,
    .stream_snapshot = NULL,
    .stream_restore = NULL,
};

bool cep_zip_library_open(cepCell* library, cepDT* name, const char* archive_path, int flags) {
    if (!library || !archive_path)
        return false;

    int error = 0;
    zip_t* archive = zip_open(archive_path, flags, &error);
    if (!archive)
        return false;

    cepZipArchive* desc = cep_malloc0(sizeof *desc);
    desc->archive = archive;
    desc->owner = true;
    desc->refcount = 0;
    desc->path = cep_zip_strdup(archive_path);

    cep_library_initialize(library,
                           name,
                           &cep_zip_ops,
                           desc);

    return true;
}

void cep_zip_library_close(cepCell* library) {
    if (!library)
        return;

    const cepLibraryBinding* binding = cep_library_binding(library);
    if (!binding)
        return;

    cepZipArchive* desc = (cepZipArchive*) binding->ctx;
    if (!desc)
        return;

    if (desc->archive) {
        zip_close(desc->archive);
        desc->archive = NULL;
    }
    if (desc->refcount == 0) {
        if (desc->path)
            cep_free(desc->path);
        cep_library_set_context(library, NULL);
        cep_free(desc);
    }
}

bool cep_zip_entry_init(cepCell* resource, cepDT* name, cepCell* library, const char* entry_name, bool create_if_missing) {
    if (!resource || !library || !entry_name)
        return false;

    const cepLibraryBinding* binding = cep_library_binding(library);
    if (!binding)
        return false;

    cepZipArchive* desc = (cepZipArchive*) binding->ctx;
    if (!desc || !desc->archive)
        return false;

    zip_int64_t index = zip_name_locate(desc->archive, entry_name, ZIP_FL_ENC_UTF_8);
    if (index < 0 && create_if_missing) {
        zip_source_t* source = zip_source_buffer(desc->archive, NULL, 0, 0);
        if (!source)
            return false;
        index = zip_file_add(desc->archive, entry_name, source, ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE);
        if (index < 0) {
            zip_source_free(source);
            return false;
        }
    }

    if (index < 0)
        return false;

    cepZipEntry* entry = cep_malloc0(sizeof *entry);
    entry->archive = desc;
    entry->index = (zip_uint64_t) index;
    entry->name = cep_zip_strdup(entry_name);
    if (!entry->name) {
        cep_free(entry);
        return false;
    }
    desc->refcount++;

    cepDT entry_type = *dt_zip_entry_type();
    cep_cell_initialize_data(resource,
                             name,
                             &entry_type,
                             entry,
                             sizeof *entry,
                             sizeof *entry,
                             cep_zip_entry_destructor);
    return true;
}

void cep_zip_stream_init(cepCell* stream, cepDT* name, cepCell* library, cepCell* entry) {
    assert(stream && library && entry);

    cepDT stream_type = *dt_zip_stream_type();
    cepData* data = cep_data_new(&stream_type,
                                 CEP_DATATYPE_STREAM,
                                 true,
                                 NULL,
                                 NULL,
                                 entry,
                                 library);
    cep_cell_initialize(stream, CEP_TYPE_NORMAL, name, data, NULL);
}

static cepZipEntry* cep_zip_entry(cepCell* resource) {
    return cep_zip_entry_from_cell(resource);
}

static bool cep_zip_stream_read(const cepLibraryBinding* binding, cepCell* resource, uint64_t offset, void* dst, size_t size, size_t* out_read) {
    (void)binding;
    if (!dst && size) {
        cep_zip_emit_failure(false,
                             resource,
                             "stream.zip.read.args",
                             "null destination for size=%zu",
                             size);
        return false;
    }

    cepZipEntry* entry = cep_zip_entry(resource);
    cepZipArchive* archive = entry ? entry->archive : NULL;
    if (!archive || !archive->archive) {
        cep_zip_emit_failure(false,
                             resource,
                             "stream.zip.read.resource",
                             "zip entry missing archive handle");
        return false;
    }

    zip_file_t* file = zip_fopen_index(archive->archive, entry->index, ZIP_FL_ENC_UTF_8);
    if (!file) {
        cep_zip_emit_failure(true,
                             resource,
                             "stream.zip.read.open",
                             "zip_fopen_index failed: %s",
                             cep_zip_error_desc(archive->archive));
        return false;
    }

    uint64_t skipped = 0;
    char buffer[4096];
    while (skipped < offset) {
        uint64_t remain = offset - skipped;
        size_t chunk = remain < sizeof buffer ? (size_t)remain : sizeof buffer;
        zip_int64_t r = zip_fread(file, buffer, chunk);
        if (r <= 0) {
            if (r < 0) {
                cep_zip_emit_failure(true,
                                     resource,
                                     "stream.zip.read.seek",
                                     "zip_fread error while skipping: %s",
                                     cep_zip_error_desc(archive->archive));
            } else {
                cep_zip_emit_failure(false,
                                     resource,
                                     "stream.zip.read.seek",
                                     "offset %" PRIu64 " beyond end of entry",
                                     offset);
            }
            zip_fclose(file);
            return false;
        }
        skipped += (uint64_t)r;
        if ((uint64_t)r < chunk)
            break;
    }

    size_t total = 0;
    zip_int64_t last_read = 0;
    while (total < size) {
        size_t chunk = size - total;
        last_read = zip_fread(file, (char*)dst + total, chunk);
        if (last_read <= 0)
            break;
        total += (size_t)last_read;
        if ((size_t)last_read < chunk)
            break;
    }

    zip_fclose(file);
    if (out_read)
        *out_read = total;

    if (total != size) {
        if (last_read < 0) {
            cep_zip_emit_failure(true,
                                 resource,
                                 "stream.zip.read.io",
                                 "zip_fread error after %zu/%zu bytes: %s",
                                 total,
                                 size,
                                 cep_zip_error_desc(archive->archive));
        } else {
            cep_zip_emit_failure(false,
                                 resource,
                                 "stream.zip.read.short",
                                 "short read %zu/%zu bytes",
                                 total,
                                 size);
        }
        return false;
    }

    return true;
}

static uint64_t cep_hash_bytes_update(uint64_t hash, const uint8_t* data, size_t size) {
    const uint64_t prime = 1099511628211ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= prime;
    }
    return hash;
}

static bool cep_zip_stream_expected_hash(const cepLibraryBinding* binding, cepCell* resource, uint64_t offset, size_t size, uint64_t* out_hash) {
    (void)binding;
    (void)offset;
    (void)size;

    cepZipEntry* entry = cep_zip_entry(resource);
    cepZipArchive* archive = entry ? entry->archive : NULL;
    if (!archive || !archive->archive || !out_hash)
        return false;

    zip_file_t* file = zip_fopen_index(archive->archive, entry->index, ZIP_FL_ENC_UTF_8);
    if (!file)
        return false;

    uint64_t hash = 1469598103934665603ULL;
    uint8_t buffer[4096];
    zip_int64_t r;
    while ((r = zip_fread(file, buffer, sizeof buffer)) > 0) {
        hash = cep_hash_bytes_update(hash, buffer, (size_t) r);
    }
    zip_fclose(file);

    if (r < 0)
        return false;

    *out_hash = hash;
    return true;
}

static bool cep_zip_stream_write(const cepLibraryBinding* binding, cepCell* resource, uint64_t offset, const void* src, size_t size, size_t* out_written) {
    (void)binding;
    if (offset != 0) {
        cep_zip_emit_failure(false,
                             resource,
                             "stream.zip.write.offset",
                             "non-zero offset %" PRIu64 " not supported",
                             offset);
        return false;
    }

    cepZipEntry* entry = cep_zip_entry(resource);
    cepZipArchive* archive = entry ? entry->archive : NULL;
    if (!archive || !archive->archive) {
        cep_zip_emit_failure(false,
                             resource,
                             "stream.zip.write.resource",
                             "zip entry missing archive handle");
        return false;
    }

    zip_source_t* source = zip_source_buffer(archive->archive, src, size, 0);
    if (!source) {
        cep_zip_emit_failure(true,
                             resource,
                             "stream.zip.write.source",
                             "zip_source_buffer failed: %s",
                             cep_zip_error_desc(archive->archive));
        return false;
    }

    if (zip_file_replace(archive->archive, entry->index, source, ZIP_FL_ENC_UTF_8) != 0) {
        zip_source_free(source);
        cep_zip_emit_failure(true,
                             resource,
                             "stream.zip.write.replace",
                             "zip_file_replace failed: %s",
                             cep_zip_error_desc(archive->archive));
        return false;
    }

    if (out_written)
        *out_written = size;
    return true;
}

#else /* CEP_HAS_LIBZIP */

bool cep_zip_library_open(cepCell* library, cepDT* name, const char* archive_path, int flags) {
    (void)library; (void)name; (void)archive_path; (void)flags;
    return false;
}

void cep_zip_library_close(cepCell* library) {
    (void)library;
}

bool cep_zip_entry_init(cepCell* resource, cepDT* name, cepCell* library, const char* entry_name, bool create_if_missing) {
    (void)resource; (void)name; (void)library; (void)entry_name; (void)create_if_missing;
    return false;
}

void cep_zip_stream_init(cepCell* stream, cepDT* name, cepCell* library, cepCell* entry) {
    (void)stream; (void)name; (void)library; (void)entry;
}

#endif /* CEP_HAS_LIBZIP */
