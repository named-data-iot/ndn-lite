
/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef UTIL_TESTS_DEF_H
#define UTIL_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "util-tests.h"

#define UTIL_NUM_TESTS 1

extern char *util_test_names[UTIL_NUM_TESTS];

extern bool util_test_results[UTIL_NUM_TESTS];

extern util_test_t util_tests[UTIL_NUM_TESTS];

#endif // UTIL_TESTS_DEF_H
