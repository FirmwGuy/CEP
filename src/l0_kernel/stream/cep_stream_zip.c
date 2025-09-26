/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_stream_zip.h"
#include "cep_stream_internal.h"

#ifdef CEP_HAS_LIBZIP

#include <zip.h>

#include <errno.h>
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

    cep_cell_initialize_data(resource,
                             name,
                             CEP_DTAW("CEP", "zip_entry"),
                             entry,
                             sizeof *entry,
                             sizeof *entry,
                             cep_zip_entry_destructor);
    return true;
}

void cep_zip_stream_init(cepCell* stream, cepDT* name, cepCell* library, cepCell* entry) {
    assert(stream && library && entry);

    cepData* data = cep_data_new(CEP_DTAW("CEP", "zip_stream"),
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
    if (!dst && size)
        return false;

    cepZipEntry* entry = cep_zip_entry(resource);
    cepZipArchive* archive = entry ? entry->archive : NULL;
    if (!archive || !archive->archive)
        return false;

    zip_file_t* file = zip_fopen_index(archive->archive, entry->index, ZIP_FL_ENC_UTF_8);
    if (!file)
        return false;

    uint64_t skipped = 0;
    char buffer[4096];
    while (skipped < offset) {
        uint64_t remain = offset - skipped;
        size_t chunk = remain < sizeof buffer ? (size_t) remain : sizeof buffer;
        zip_int64_t r = zip_fread(file, buffer, chunk);
        if (r <= 0) {
            zip_fclose(file);
            return false;
        }
        skipped += (uint64_t) r;
        if ((uint64_t) r < chunk)
            break;
    }

    size_t total = 0;
    while (total < size) {
        size_t chunk = size - total;
        zip_int64_t r = zip_fread(file, (char*) dst + total, chunk);
        if (r <= 0)
            break;
        total += (size_t) r;
        if ((size_t) r < chunk)
            break;
    }

    zip_fclose(file);
    if (out_read)
        *out_read = total;

    return total == size;
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
    if (offset != 0)
        return false;

    cepZipEntry* entry = cep_zip_entry(resource);
    cepZipArchive* archive = entry ? entry->archive : NULL;
    if (!archive || !archive->archive)
        return false;

    zip_source_t* source = zip_source_buffer(archive->archive, src, size, 0);
    if (!source)
        return false;

    if (zip_file_replace(archive->archive, entry->index, source, ZIP_FL_ENC_UTF_8) != 0) {
        zip_source_free(source);
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
