/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_identifier.h"

#include <string.h>

/* Compose a canonical identifier by trimming each token, lowercasing allowed
 * characters, and joining the cleaned segments with ':' so every caller lands
 * on the same ledger-friendly string. Reject empty tokens, embedded
 * separators, or unsupported characters to keep downstream namepool entries
 * predictable. */
bool cep_compose_identifier(const char* const tokens[],
                            size_t token_count,
                            char* out_buffer,
                            size_t out_cap) {
    if (!tokens || !token_count || !out_buffer || out_cap == 0u) {
        return false;
    }

    size_t pos = 0u;
    for (size_t i = 0; i < token_count; ++i) {
        const char* token = tokens[i];
        if (!token) {
            return false;
        }

        while (*token == ' ' || *token == '\t' || *token == '\n' || *token == '\r') {
            ++token;
        }

        size_t len = strlen(token);
        while (len && (token[len - 1u] == ' ' || token[len - 1u] == '\t' ||
                        token[len - 1u] == '\n' || token[len - 1u] == '\r')) {
            --len;
        }
        if (!len) {
            return false;
        }

        for (size_t j = 0; j < len; ++j) {
            unsigned char ch = (unsigned char)token[j];
            if (ch == ':') {
                return false;
            }
            if (ch >= 'A' && ch <= 'Z') {
                ch = (unsigned char)(ch - 'A' + 'a');
            }
            if (!((ch >= 'a' && ch <= 'z') ||
                  (ch >= '0' && ch <= '9') ||
                  ch == '-' || ch == '_' || ch == '.' || ch == '/')) {
                return false;
            }

            if (pos >= out_cap - 1u || pos >= CEP_IDENTIFIER_MAX) {
                return false;
            }
            out_buffer[pos++] = (char)ch;
        }

        if (i + 1u < token_count) {
            if (pos >= out_cap - 1u || pos >= CEP_IDENTIFIER_MAX) {
                return false;
            }
            out_buffer[pos++] = ':';
        }
    }

    if (!pos) {
        return false;
    }
    out_buffer[pos] = '\0';
    return true;
}
