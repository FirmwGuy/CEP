#include "cep_stream_stdio.h"
#include "cep_stream_internal.h"

#include <errno.h>

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

static const cepLibraryOps cep_stdio_ops = {
    .handle_retain = cep_stdio_handle_retain,
    .handle_release = cep_stdio_handle_release,
    .stream_read = cep_stdio_stream_read,
    .stream_write = cep_stdio_stream_write,
    .stream_expected_hash = NULL,
    .stream_map = cep_stdio_stream_map,
    .stream_unmap = cep_stdio_stream_unmap,
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

    cep_cell_initialize_data(resource,
                             name,
                             CEP_DTAW("CEP", "stdio_res"),
                             res,
                             sizeof *res,
                             sizeof *res,
                             cep_stdio_resource_destructor);
}


void cep_stdio_stream_init(cepCell* stream, cepDT* name, cepCell* library, cepCell* resource) {
    assert(stream && library && resource);

    cepData* data = cep_data_new(CEP_DTAW("CEP", "stdio_str"),
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
    if (!dst && size)
        return false;

    cepStdioResource* res = cep_stdio_resource_from_binding(binding, stream);
    if (!res || !res->file)
        return false;

    if (!size) {
        if (out_read)
            *out_read = 0;
        return true;
    }

    if (!cep_stdio_seek(res->file, offset))
        return false;

    size_t read = fread(dst, 1, size, res->file);
    if (out_read)
        *out_read = read;

    if (read != size && ferror(res->file))
        return false;

    cep_stream_journal(stream,
                       read == size? CEP_STREAM_JOURNAL_READ: (CEP_STREAM_JOURNAL_READ | CEP_STREAM_JOURNAL_ERROR),
                       offset,
                       size,
                       read,
                       (read && dst)? cep_hash_bytes(dst, read): 0);

    return read == size;
}


static bool cep_stdio_stream_write(const cepLibraryBinding* binding, cepCell* stream, uint64_t offset, const void* src, size_t size, size_t* out_written) {
    if (!src && size)
        return false;

    cepStdioResource* res = cep_stdio_resource_from_binding(binding, stream);
    if (!res || !res->file)
        return false;

    if (!size) {
        if (out_written)
            *out_written = 0;
        return true;
    }

    if (!cep_stdio_seek(res->file, offset))
        return false;

    size_t written = fwrite(src, 1, size, res->file);
    if (out_written)
        *out_written = written;

    if (written != size)
        return false;

    if (fflush(res->file) != 0)
        return false;

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

