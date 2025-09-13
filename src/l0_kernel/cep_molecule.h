/*
 *  Copyright (c) 2021-2025 Victor M. Barrientos
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

#ifndef CEP_MOLECULE_H
#define CEP_MOLECULE_H


#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>


#define     CEPPASTIT(a,b)            a##b
#define     CEPPASTE(a,b)             CEPPASTIT(a, b)
#define     CEP(_, i)                 CEPPASTE(__##i, _)

#define     CEP_EXPECT(exp)           (__builtin_expect((long)(exp), true))
#define     CEP_EXPECT_PTR(p)         CEP_EXPECT((p) != NULL)
#define     CEP_RARELY(exp)           (__builtin_expect((long)(exp), false))
#define     CEP_RARELY_PTR(p)         CEP_RARELY((p) != NULL)


/*
 * Variable Initialization
 */

#define     CEP_T(v, x, ...)          __auto_type (x) __VA_ARGS__ = (v)
#define     CEP_U(_, x, v, ...)       CEP_T(v, CEP(_,x), ##__VA_ARGS__)
#define     CEP_I(T, p, a, ...)       T* (p) __VA_ARGS__ = (T*) (a)

#define     CEP_TLS   __thread



/*
 * Memory Initialization
 */

#if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
  #error    unsoported target platform!
#else
  static inline void*   cep_malloc(size_t z)                   {void* p = malloc(z);       if CEP_RARELY(!p)  abort();  return p;}
  static inline void*   cep_calloc(size_t n, size_t z)         {void* p = calloc(n, z);    if CEP_RARELY(!p)  abort();  return p;}
  static inline void*   cep_realloc(void* p, size_t z)         {void* r = realloc(p, z);   if CEP_RARELY(!r)  abort();  return r;}
  #define   cep_alloca  __builtin_alloca
  #define   cep_free    free
#endif
#define     cep_malloc0(z, ...)       cep_calloc(1, z __VA_ARGS__)


#define     cep_new(T, ...)           cep_malloc0(sizeof(T) __VA_ARGS__)
#define     CEP_NEW(T, p, ...)        CEP_I(T, p, cep_new(T, ##__VA_ARGS__))
#define     CEP_REALLOC(p, z)         ({(p) = cep_realloc(p, z);})
#define     CEP_FREE(p)               do{ cep_free(p); (p) = NULL; }while (0)
#define     CEP_AUTOFREE(T, p, ...)   T* (p) __attribute__((cleanup(cep_free))) __VA_ARGS__


static inline void  cep_cpy_or_0(void* q, void* p, size_t z)  {assert(q);  if (p) memcpy(q, p, z); else memset(q, 0, z);}

#define     CEP_CLONE(T, d, p)        T* (d) = cep_clone(p, sizeof(T))
#define     CEP_0(p)                  memset(p, 0, sizeof(*(p)))
#define     _CEP_SWAP(_, a, b)        do{ CEP_U(_,c, a); (a) = (b); (b) = CEP(_,c); }while(0)
#define     CEP_SWAP(...)             _CEP_SWAP(__COUNTER__, __VA_ARGS__)

typedef void (*cepDel)(void*);



/*
 * Pointer Utilities
 */

#define     CEP_P(p)                  ((void*)(p))
#define     cep_v2p(v)                ((void*)(uintptr_t)(v))
#define     cep_p2v(p)                ((uintptr_t)(p))

#define     _cep_align_to(_, u, _a)   ({CEP_U(_,a, _a);  assert(0 < CEP(_,a));  ((u) + (CEP(_,a) - 1)) & ~(CEP(_,a) - 1);})
#define     cep_align_to(...)         _cep_align_to(__COUNTER__, __VA_ARGS__)
#define     cep_align_max(u)          cep_align_to(u, __BIGGEST_ALIGNMENT__)
#define     cep_aligned(t)            cep_align_to(sizeof(t), __alignof__(t))
#define     CEP_ALIGN_TO(u, a)        ((u) = cep_align_to(u, a))

#define     cep_ptr_align_to(p, a)    ((void*)cep_align_to((uintptr_t)(p), a))
#define     cep_ptr_aligned(p)        ((void*)cep_aligned((uintptr_t)(p)))
#define     cep_ptr_off(p, off)       ((void*)(((uint8_t*)(p)) + (off)))
#define     CEP_PTR_OFF(p, off)       ((p) = cep_ptr_off(p, off))
#define     cep_ptr_dif(p1, p2)       ((void*)(((uint8_t*)(p1)) - ((uint8_t*)(p2))))
#define     cep_ptr_idx(p, o, z)      ((size_t)cep_ptr_dif(o, p) / (z))
#define     cep_ptr_adr(p, i, z)      cep_ptr_off(p, (i)*(z))
#define     cep_ptr_sec_get(p, v)     ((p)? *(p): (n))
#define     CEP_PTR_SEC_SET(p, n)     ({if (p) *(p)=(n);})
#define     CEP_PTR_OVERW(p, n)       ({cep_free(p); (p)=(n);})


#define     cep_popcount(v)           __builtin_choose_expr(sizeof(v) <= sizeof(int), __builtin_popcount(v), __builtin_choose_expr(sizeof(v) == sizeof(long int), __builtin_popcountl(v), __builtin_popcountll(v)))
#define     cep_clz(v)                __builtin_choose_expr(sizeof(v) <= sizeof(int), __builtin_clz(v), __builtin_choose_expr(sizeof(v) == sizeof(long int), __builtin_clzl(v), __builtin_clzll(v)))
#define     cep_ctz(v)                __builtin_choose_expr(sizeof(v) <= sizeof(int), __builtin_ctz(v), __builtin_choose_expr(sizeof(v) == sizeof(long int), __builtin_ctzl(v), __builtin_ctzll(v)))

#define     cep_bitsof(T)             (sizeof(T) << 3)
#define     cep_bitson(v)             (cep_bitsof(v) - cep_clz(v))
#define     cep_lengthof(a)           (sizeof(a)/sizeof(*a))

#define     cep_dyn_size(Ts, Tm, l)   (sizeof(Ts) + ((l) * sizeof(Tm)))
#define     cep_dyn_malloc(Ts, Tm, l) cep_malloc(cep_dyn_size(Ts, Tm, l))
#define     cep_dyn_malloc0(Ts,Tm,l)  cep_malloc0(cep_dyn_size(Ts, Tm, l))

#define     cep_is_pow_of_two(u)      (1 == cep_popcount(u))
#define     cep_max_pow_of_two(u)     (((typeof(u))1) << (cep_bitsof(u) - 1))
#define     cep_prev_pow_of_two(u)    (cep_max_pow_of_two(u) >> cep_clz(u))
#define     cep_next_pow_of_two(u)    (cep_is_pow_of_two(u)? u: (cep_max_pow_of_two(u) >> (cep_clz(u) - 1)))



/*
 * Value Checking
 */

#define     cep_const_min(a, b)       ((a < b)? a: b)
#define     cep_const_max(a, b)       ((a > b)? a: b)
#define     _cep_min(_, _a, _b)       ({CEP_U(_,a, _a); CEP_U(_,b, _b);  cep_const_min(CEP(_,a), CEP(_,b));})
#define     _cep_max(_, _a, _b)       ({CEP_U(_,a, _a); CEP_U(_,b, _b);  cep_const_max(CEP(_,a), CEP(_,b));})
#define     cep_min(...)              _cep_min(__COUNTER__, __VA_ARGS__)
#define     cep_max(...)              _cep_max(__COUNTER__, __VA_ARGS__)

#define     cep_is_set(v, f)          (((v) & (f)) != 0)


/*
 * Function Utilities
 */

#define  CEP_AT_STARTUP_(...)         __attribute__((constructor(__VA_ARGS__)))
#define  CEP_AT_SHUTDOWN_(...)        __attribute__((destructor(__VA_ARGS__)))

#define  CEP_CONST_FUNC               __attribute__((const))


#ifdef NDEBUG
  #define CEP_DEBUG()
  #define CEP_ASSERT(exp)       (exp)
#else
  #define CEP_DEBUG(code)       do{ code; }while(0)
  #define CEP_ASSERT(exp)       (({bool e = (bool)(exp);  if (!e) assert(#exp && e);  e;}))
#endif
#define   CEP_NOT_ASSERT(exp)   (!CEP_ASSERT(exp))


#endif
