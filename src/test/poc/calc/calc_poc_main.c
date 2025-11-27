/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Entry point for the calculator POC tests; runs only the calc_poc suite so the
 * POC can iterate without pulling the entire test harness. */

#include "munit.h"

extern MunitSuite calc_poc_suite;

int main(int argC, char* argV[MUNIT_ARRAY_PARAM(argC + 1)]) {
    return munit_suite_main(&calc_poc_suite, NULL, argC, argV);
}
