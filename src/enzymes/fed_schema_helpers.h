/* Shared helpers for federation schema tags. */

#ifndef CEP_FED_SCHEMA_HELPERS_H
#define CEP_FED_SCHEMA_HELPERS_H

#include "../l0_kernel/cep_cell.h"
#include "../l0_kernel/cep_namepool.h"

#define CEP_FED_TAG_CAPS             "caps"
#define CEP_FED_TAG_REQUIRED         "required"
#define CEP_FED_TAG_PREFERRED        "preferred"
#define CEP_FED_TAG_UPD_LATEST       "upd_latest"
#define CEP_FED_TAG_TRANSPORT        "transport"
#define CEP_FED_TAG_PROVIDER         "provider"
#define CEP_FED_TAG_SELECTED_CAPS    "prov_caps"
#define CEP_FED_TAG_SERIALIZER       "serializer"
#define CEP_FED_TAG_BP_FLAG          "bp_flag"

#define CEP_FED_TAG_CAP_RELIABLE     "reliable"
#define CEP_FED_TAG_CAP_ORDERED      "ordered"
#define CEP_FED_TAG_CAP_STREAMING    "streaming"
#define CEP_FED_TAG_CAP_DATAGRAM     "datagram"
#define CEP_FED_TAG_CAP_MULTICAST    "multicast"
#define CEP_FED_TAG_CAP_LOW_LATENCY  "low_latency"
#define CEP_FED_TAG_CAP_LOCAL_IPC    "local_ipc"
#define CEP_FED_TAG_CAP_REMOTE_NET   "remote_net"
#define CEP_FED_TAG_CAP_UNRELIABLE   "unreliable"

#define CEP_FED_TAG_SER_CRC32C_OK    "crc32c_ok"
#define CEP_FED_TAG_SER_DEFLATE_OK   "deflate_ok"
#define CEP_FED_TAG_SER_AEAD_OK      "aead_ok"
#define CEP_FED_TAG_SER_WARN_DOWN    "warn_down"
#define CEP_FED_TAG_SER_CMP_MAX      "cmp_max_ver"
#define CEP_FED_TAG_SER_PAY_HIST     "pay_hist_bt"
#define CEP_FED_TAG_SER_MAN_HIST     "man_hist_bt"

static inline cepCell* cep_fed_schema_find_field(cepCell* parent,
                                                 const cepDT* field,
                                                 const char* tag_text) {
    if (!parent || !field) {
        return NULL;
    }
    cepCell* node = cep_cell_find_by_name(parent, field);
    if (!node && tag_text) {
        cepID word = cep_text_to_word(tag_text);
        if (word) {
            cepDT alias = {
                .domain = field->domain ? field->domain : cep_namepool_intern_cstr("CEP"),
                .tag = word,
            };
            node = cep_cell_find_by_name(parent, &alias);
        }
    }
    return node ? cep_cell_resolve(node) : NULL;
}

#endif /* CEP_FED_SCHEMA_HELPERS_H */
