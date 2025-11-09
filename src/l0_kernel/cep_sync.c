/* Copyright (c) 2025 Victor M. Barrientos (https://github.com/FirmwGuy/CEP) */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "cep_sync.h"

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <errno.h>
#  include <unistd.h>
#endif

#include <stdlib.h>

bool
cep_mutex_init(cepMutex* mutex)
{
    if (!mutex) {
        return false;
    }
#if defined(_WIN32)
    InitializeCriticalSection(&mutex->native);
    return true;
#else
    return pthread_mutex_init(&mutex->native, NULL) == 0;
#endif
}

void
cep_mutex_destroy(cepMutex* mutex)
{
    if (!mutex) {
        return;
    }
#if defined(_WIN32)
    DeleteCriticalSection(&mutex->native);
#else
    (void)pthread_mutex_destroy(&mutex->native);
#endif
}

void
cep_mutex_lock(cepMutex* mutex)
{
    if (!mutex) {
        return;
    }
#if defined(_WIN32)
    EnterCriticalSection(&mutex->native);
#else
    (void)pthread_mutex_lock(&mutex->native);
#endif
}

void
cep_mutex_unlock(cepMutex* mutex)
{
    if (!mutex) {
        return;
    }
#if defined(_WIN32)
    LeaveCriticalSection(&mutex->native);
#else
    (void)pthread_mutex_unlock(&mutex->native);
#endif
}

bool
cep_cond_init(cepCond* cond)
{
    if (!cond) {
        return false;
    }
#if defined(_WIN32)
    InitializeConditionVariable(&cond->native);
    return true;
#else
    return pthread_cond_init(&cond->native, NULL) == 0;
#endif
}

void
cep_cond_destroy(cepCond* cond)
{
    if (!cond) {
        return;
    }
#if !defined(_WIN32)
    (void)pthread_cond_destroy(&cond->native);
#else
    (void)cond;
#endif
}

void
cep_cond_wait(cepCond* cond, cepMutex* mutex)
{
    if (!cond || !mutex) {
        return;
    }
#if defined(_WIN32)
    SleepConditionVariableCS(&cond->native, &mutex->native, INFINITE);
#else
    (void)pthread_cond_wait(&cond->native, &mutex->native);
#endif
}

void
cep_cond_signal(cepCond* cond)
{
    if (!cond) {
        return;
    }
#if defined(_WIN32)
    WakeConditionVariable(&cond->native);
#else
    (void)pthread_cond_signal(&cond->native);
#endif
}

void
cep_cond_broadcast(cepCond* cond)
{
    if (!cond) {
        return;
    }
#if defined(_WIN32)
    WakeAllConditionVariable(&cond->native);
#else
    (void)pthread_cond_broadcast(&cond->native);
#endif
}

bool
cep_semaphore_init(cepSemaphore* sem, unsigned initial)
{
    if (!sem) {
        return false;
    }
    if (!cep_mutex_init(&sem->mutex)) {
        return false;
    }
    if (!cep_cond_init(&sem->cond)) {
        cep_mutex_destroy(&sem->mutex);
        return false;
    }
    sem->value = initial;
    return true;
}

void
cep_semaphore_destroy(cepSemaphore* sem)
{
    if (!sem) {
        return;
    }
    cep_cond_destroy(&sem->cond);
    cep_mutex_destroy(&sem->mutex);
}

bool
cep_semaphore_wait(cepSemaphore* sem)
{
    if (!sem) {
        return false;
    }
    cep_mutex_lock(&sem->mutex);
    while (sem->value == 0u) {
        cep_cond_wait(&sem->cond, &sem->mutex);
    }
    sem->value -= 1u;
    cep_mutex_unlock(&sem->mutex);
    return true;
}

void
cep_semaphore_post(cepSemaphore* sem)
{
    if (!sem) {
        return;
    }
    cep_mutex_lock(&sem->mutex);
    sem->value += 1u;
    cep_cond_signal(&sem->cond);
    cep_mutex_unlock(&sem->mutex);
}

#if defined(_WIN32)
typedef struct {
    cepThreadStart fn;
    void*          arg;
} cepThreadThunk;

static DWORD WINAPI
cep_thread_trampoline(LPVOID param)
{
    cepThreadThunk* thunk = (cepThreadThunk*)param;
    void* (*fn)(void*) = thunk->fn;
    void* arg = thunk->arg;
    free(thunk);
    if (fn) {
        (void)fn(arg);
    }
    return 0;
}
#endif

bool
cep_thread_start(cepThread* thread, cepThreadStart fn, void* arg)
{
    if (!thread || !fn) {
        return false;
    }
    thread->joined = false;
#if defined(_WIN32)
    cepThreadThunk* thunk = (cepThreadThunk*)malloc(sizeof *thunk);
    if (!thunk) {
        return false;
    }
    thunk->fn = fn;
    thunk->arg = arg;
    HANDLE handle = CreateThread(NULL, 0, cep_thread_trampoline, thunk, 0, NULL);
    if (!handle) {
        free(thunk);
        return false;
    }
    thread->handle = handle;
    return true;
#else
    return pthread_create(&thread->handle, NULL, fn, arg) == 0;
#endif
}

bool
cep_thread_join(cepThread* thread)
{
    if (!thread || thread->joined) {
        return false;
    }
#if defined(_WIN32)
    WaitForSingleObject(thread->handle, INFINITE);
    CloseHandle(thread->handle);
#else
    (void)pthread_join(thread->handle, NULL);
#endif
    thread->joined = true;
    return true;
}

void
cep_thread_detach(cepThread* thread)
{
    if (!thread || thread->joined) {
        return;
    }
#if defined(_WIN32)
    CloseHandle(thread->handle);
#else
    (void)pthread_detach(thread->handle);
#endif
    thread->joined = true;
}

unsigned
cep_cpu_count(void)
{
#if defined(_WIN32)
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return (info.dwNumberOfProcessors > 0) ? (unsigned)info.dwNumberOfProcessors : 1u;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n <= 0) {
        return 1u;
    }
    return (unsigned)n;
#endif
}
