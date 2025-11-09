/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef CEP_SYNC_H
#define CEP_SYNC_H

#include <stdbool.h>

#if defined(_WIN32)
#  include <windows.h>
typedef struct {
    CRITICAL_SECTION native;
} cepMutex;

typedef struct {
    CONDITION_VARIABLE native;
} cepCond;

typedef HANDLE cepThreadHandle;
#else
#  include <pthread.h>
typedef struct {
    pthread_mutex_t native;
} cepMutex;

typedef struct {
    pthread_cond_t native;
} cepCond;

typedef pthread_t cepThreadHandle;
#endif

typedef struct {
    cepMutex mutex;
    cepCond  cond;
    unsigned value;
} cepSemaphore;

typedef struct {
    cepThreadHandle handle;
    bool            joined;
} cepThread;

typedef void* (*cepThreadStart)(void* arg);

bool cep_mutex_init(cepMutex* mutex);
void cep_mutex_destroy(cepMutex* mutex);
void cep_mutex_lock(cepMutex* mutex);
void cep_mutex_unlock(cepMutex* mutex);

bool cep_cond_init(cepCond* cond);
void cep_cond_destroy(cepCond* cond);
void cep_cond_wait(cepCond* cond, cepMutex* mutex);
void cep_cond_signal(cepCond* cond);
void cep_cond_broadcast(cepCond* cond);

bool cep_semaphore_init(cepSemaphore* sem, unsigned initial);
void cep_semaphore_destroy(cepSemaphore* sem);
bool cep_semaphore_wait(cepSemaphore* sem);
void cep_semaphore_post(cepSemaphore* sem);

bool cep_thread_start(cepThread* thread, cepThreadStart fn, void* arg);
bool cep_thread_join(cepThread* thread);
void cep_thread_detach(cepThread* thread);

unsigned cep_cpu_count(void);

#endif /* CEP_SYNC_H */
