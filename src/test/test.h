/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
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


/*  This test program uses Munit, which is MIT licensed. Please see munit.h file
 *  for a complete license information.
 */
#define MUNIT_ENABLE_ASSERT_ALIASES
#include "munit.h"


typedef struct TestWatchdog TestWatchdog;

enum {
    CEP_NAME_ENUMERATION = 100,
    CEP_NAME_TEMP,
    CEP_NAME_Z_COUNT
};


MunitResult test_cell(const MunitParameter params[], void* user_data_or_fixture);
void*       test_cell_setup(const MunitParameter params[], void* user_data);
void        test_cell_tear_down(void* fixture);

MunitResult test_traverse(const MunitParameter params[], void* user_data_or_fixture);
void*       test_traverse_setup(const MunitParameter params[], void* user_data);
void        test_traverse_tear_down(void* fixture);

void        test_watchdog_signal(TestWatchdog* wd);

MunitResult test_wordacron(const MunitParameter params[], void* user_data_or_fixture);

MunitResult test_enzyme(const MunitParameter params[], void* user_data_or_fixture);
void*       test_enzyme_setup(const MunitParameter params[], void* user_data);
void        test_enzyme_tear_down(void* fixture);

MunitResult test_heartbeat(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_serialization(const MunitParameter params[], void* user_data_or_fixture);
MunitResult test_stream_stdio(const MunitParameter params[], void* user_data_or_fixture);
#ifdef CEP_HAS_LIBZIP
MunitResult test_stream_zip(const MunitParameter params[], void* user_data_or_fixture);
#endif
MunitResult test_stream_stdio(const MunitParameter params[], void* user_data_or_fixture);
