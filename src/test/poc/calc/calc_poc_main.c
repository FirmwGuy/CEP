/* Entry point for the calculator POC tests; runs only the calc_poc suite so the
 * POC can iterate without pulling the entire test harness. */

#include "munit.h"

extern MunitSuite calc_poc_suite;

int main(int argC, char* argV[MUNIT_ARRAY_PARAM(argC + 1)]) {
    return munit_suite_main(&calc_poc_suite, NULL, argC, argV);
}
