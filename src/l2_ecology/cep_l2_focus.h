/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_L2_FOCUS_H
#define CEP_L2_FOCUS_H

#include <stdbool.h>
#include <stddef.h>
#include "../l0_kernel/cep_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* rat_id;
    const char* maze_id;
    const char* region_id;
    const char* province_id;
    const char* mode_id;
} cepL2FocusContext;

bool cep_l2_focus_build_nav(cepCell* eco_root,
                            const cepL2FocusContext* ctx,
                            char* focus_key,
                            size_t focus_key_len);

bool cep_l2_focus_build_exploration(cepCell* eco_root,
                                    const cepL2FocusContext* ctx,
                                    char* focus_key,
                                    size_t focus_key_len);

bool cep_l2_focus_build_memory(cepCell* eco_root,
                               const cepL2FocusContext* ctx,
                               char* focus_key,
                               size_t focus_key_len);

bool cep_l2_focus_read_signal(cepCell* signals, const char* name, double* out);

bool cep_l2_focus_build_social(cepCell* eco_root,
                               const cepL2FocusContext* ctx,
                               char* focus_key,
                               size_t focus_key_len);

bool cep_l2_focus_build_warning(cepCell* eco_root,
                                const cepL2FocusContext* ctx,
                                char* focus_key,
                                size_t focus_key_len);

#ifdef __cplusplus
}
#endif

#endif /* CEP_L2_FOCUS_H */
