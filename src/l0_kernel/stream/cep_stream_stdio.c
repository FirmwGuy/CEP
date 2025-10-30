/* Copyright (c) 2024–2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


#include "cep_stream_stdio.h"
#include "cep_stream_internal.h"
#include "cep_cei.h"
#include "cep_heartbeat.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>

CEP_DEFINE_STATIC_DT(dt_stdio_resource_type, CEP_ACRO("CEP"), CEP_WORD("stdio_res"));
CEP_DEFINE_STATIC_DT(dt_stdio_stream_type,   CEP_ACRO("CEP"), CEP_WORD("stdio_str"));
CEP_DEFINE_STATIC_DT(dt_sev_stdio_crit,      CEP_ACRO("CEP"), CEP_WORD("sev:crit"));
CEP_DEFINE_STATIC_DT(dt_sev_stdio_usage,     CEP_ACRO("CEP"), CEP_WORD("sev:usage"));

typedef struct {
    FILE*     file;
    bool      owner;
    unsigned  refcount;
} cepStdioResource;

static void cep_stdio_resource_destructor(void* data);
static cepStdioResource* cep_stdio_resource(cepCell* cell);
static bool cep_stdio_seek(FILE* file, uint64_t offset);
static bool cep_stdio_handle_retain(const cepLibraryBinding* binding, cepCell* handle);
static void cep_stdio_handle_release(const cepLibraryBinding* binding, cepCell* handle);
static bool cep_stdio_stream_read(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, void* dst, size_t size, size_t* out_read);
static bool cep_stdio_stream_write(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, const void* src, size_t size, size_t* out_written);
static bool cep_stdio_stream_map(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, size_t size, unsigned access, cepStreamView* view);
static bool cep_stdio_stream_unmap(const cepLibraryBinding* binding, cepCell* stream, cepStreamView* view, bool commit);

/* Streams bootstrap before CEI mailboxes exist; skip diagnostics until the
   kernel lifecycle scope is live so early resource failures do not crash
   bootstrap. */
static bool cep_stdio_can_emit_cei(void) {
    return cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL);
}

/* Emit a diagnostics note describing an stdio stream failure. Critical I/O
   faults request perpetual retention while usage mistakes (such as invalid
   arguments) remain advisory. */
static void cep_stdio_emit_failure(bool io_fault,
                                   cepCell* subject,
                                   const char* topic,
                                   const char* detail_fmt,
                                   ...) {
    if (!topic || !detail_fmt) {
        return;
    }
    if (!cep_stdio_can_emit_cei()) {
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

    const cepDT* severity = io_fault ? dt_sev_stdio_crit() : dt_sev_stdio_usage();
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

static const cepLibraryOps cep_stdio_ops = {
    .handle_retain = cep_stdio_handle_retain,
    .handle_release = cep_stdio_handle_release,
    .stream_read = cep_stdio_stream_read,
    .stream_write = cep_stdio_stream_write,
    .stream_expected_hash = NULL,
    .stream_map = cep_stdio_stream_map,
    .stream_unmap = cep_stdio_stream_unmap,
    .handle_snapshot = NULL,
    .handle_restore = NULL,
    .stream_snapshot = NULL,
    .stream_restore = NULL,
};

void cep_stdio_library_init(cepCell* library, cepDT* name) {
    cep_library_initialize(library, name, &cep_stdio_ops, NULL);
}


void cep_stdio_resource_init(cepCell* resource, cepDT* name, FILE* file, bool close_on_release) {
    assert(resource && file);

    cepStdioResource* res = cep_malloc0(sizeof *res);
    res->file = file;
    res->owner = close_on_release;
    res->refcount = 0;

    cepDT resource_type = *dt_stdio_resource_type();
    cep_cell_initialize_data(resource,
                             name,
                             &resource_type,
                             res,
                             sizeof *res,
                             sizeof *res,
                             cep_stdio_resource_destructor);
}


void cep_stdio_stream_init(cepCell* stream, cepDT* name, cepCell* library, cepCell* resource) {
    assert(stream && library && resource);

    cepDT stream_type = *dt_stdio_stream_type();
    cepData* data = cep_data_new(&stream_type,
                                 CEP_DATATYPE_STREAM,
                                 true,
                                 NULL,
                                 NULL,
                                 resource,
                                 library);

    cep_cell_initialize(stream, CEP_TYPE_NORMAL, name, data, NULL);
}


static void cep_stdio_resource_destructor(void* data) {
    cepStdioResource* res = data;
    if (!res)
        return;

    if (res->owner && res->file) {
        fclose(res->file);
        res->file = NULL;
    }

    cep_free(res);
}


static cepStdioResource* cep_stdio_resource(cepCell* cell) {
    if (!cell || !cep_cell_has_data(cell))
        return NULL;

    cepData* data = cell->data;
    if (!data || data->datatype != CEP_DATATYPE_DATA)
        return NULL;

    return (cepStdioResource*) data->data;
}


static bool cep_stdio_handle_retain(const cepLibraryBinding* binding, cepCell* handle) {
    (void)binding;

    cepStdioResource* res = cep_stdio_resource(handle);
    if (!res)
        return false;

    res->refcount++;
    return true;
}


static void cep_stdio_handle_release(const cepLibraryBinding* binding, cepCell* handle) {
    (void)binding;

    cepStdioResource* res = cep_stdio_resource(handle);
    if (!res || !res->refcount)
        return;

    res->refcount--;
    if (!res->refcount && res->owner && res->file) {
        fclose(res->file);
        res->file = NULL;
    }
}


static bool cep_stdio_seek(FILE* file, uint64_t offset) {
#if defined(_WIN32) || defined(_WIN64)
    return _fseeki64(file, (long long)offset, SEEK_SET) == 0;
#else
    return fseeko(file, (off_t)offset, SEEK_SET) == 0;
#endif
}


static cepStdioResource* cep_stdio_resource_from_binding(const cepLibraryBinding* binding, cepCell* stream) {
    (void)binding;

    stream = cep_link_pull(stream);
    return cep_stdio_resource(stream);
}


static bool cep_stdio_stream_read(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, void* dst, size_t size, size_t* out_read) {
    if (!dst && size) {
        cep_stdio_emit_failure(false,
                               stream,
                               "stream.stdio.read.args",
                               "null destination for size=%zu",
                               size);
        return false;
    }

    cepStdioResource* res = cep_stdio_resource_from_binding(binding, stream);
    if (!res || !res->file) {
        cep_stdio_emit_failure(false,
                               stream,
                               "stream.stdio.read.resource",
                               "stdio resource missing file handle");
        return false;
    }

    if (!size) {
        if (out_read)
            *out_read = 0;
        return true;
    }

    if (!cep_stdio_seek(res->file, offset)) {
        int err = errno;
        cep_stdio_emit_failure(true,
                               stream,
                               "stream.stdio.read.seek",
                               "seek failed offset=%" PRIu64 " err=%d",
                               offset,
                               err);
        return false;
    }

    size_t read = fread(dst, 1, size, res->file);
    if (out_read)
        *out_read = read;

    if (read != size) {
        if (ferror(res->file)) {
            int err = errno;
            cep_stdio_emit_failure(true,
                                   stream,
                                   "stream.stdio.read.io",
                                   "I/O error after %zu/%zu bytes err=%d",
                                   read,
                                   size,
                                   err);
            clearerr(res->file);
            return false;
        }
        cep_stdio_emit_failure(false,
                               stream,
                               "stream.stdio.read.short",
                               "short read %zu/%zu bytes",
                               read,
                               size);
        return false;
    }

    cep_stream_journal(stream,
                       read == size? CEP_STREAM_JOURNAL_READ: (CEP_STREAM_JOURNAL_READ | CEP_STREAM_JOURNAL_ERROR),
                       offset,
                       size,
                       read,
                       (read && dst)? cep_hash_bytes(dst, read): 0);

    return true;
}


static bool cep_stdio_stream_write(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, const void* src, size_t size, size_t* out_written) {
    if (!src && size) {
        cep_stdio_emit_failure(false,
                               stream,
                               "stream.stdio.write.args",
                               "null source for size=%zu",
                               size);
        return false;
    }

    cepStdioResource* res = cep_stdio_resource_from_binding(binding, stream);
    if (!res || !res->file) {
        cep_stdio_emit_failure(false,
                               stream,
                               "stream.stdio.write.resource",
                               "stdio resource missing file handle");
        return false;
    }

    if (!size) {
        if (out_written)
            *out_written = 0;
        return true;
    }

    if (!cep_stdio_seek(res->file, offset)) {
        int err = errno;
        cep_stdio_emit_failure(true,
                               stream,
                               "stream.stdio.write.seek",
                               "seek failed offset=%" PRIu64 " err=%d",
                               offset,
                               err);
        return false;
    }

    size_t written = fwrite(src, 1, size, res->file);
    if (out_written)
        *out_written = written;

    if (written != size) {
        if (ferror(res->file)) {
            int err = errno;
            cep_stdio_emit_failure(true,
                                   stream,
                                   "stream.stdio.write.io",
                                   "I/O error after %zu/%zu bytes err=%d",
                                   written,
                                   size,
                                   err);
            clearerr(res->file);
            return false;
        }
        cep_stdio_emit_failure(false,
                               stream,
                               "stream.stdio.write.short",
                               "short write %zu/%zu bytes",
                               written,
                               size);
        return false;
    }

    if (fflush(res->file) != 0) {
        int err = errno;
        cep_stdio_emit_failure(true,
                               stream,
                               "stream.stdio.write.flush",
                               "fflush failed err=%d",
                               err);
        return false;
    }

    cep_stream_journal(stream,
                       CEP_STREAM_JOURNAL_WRITE | CEP_STREAM_JOURNAL_COMMIT,
                       offset,
                       size,
                       written,
                       (written && src)? cep_hash_bytes(src, written): 0);

    return true;
}


static bool cep_stdio_stream_map(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, size_t size, unsigned access, cepStreamView* view) {
    (void)binding;
    (void)stream;
    (void)offset;
    (void)size;
    (void)access;
    (void)view;
    return false;
}


static bool cep_stdio_stream_unmap(const cepLibraryBinding* binding, cepCell* stream, cepStreamView* view, bool commit) {
    (void)binding;
    (void)stream;
    (void)view;
    (void)commit;
    return false;
}
