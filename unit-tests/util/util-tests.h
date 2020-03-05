
/*
 * Copyright (C) 2019 Xinyu Ma, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef UTIL_TESTS_H
#define UTIL_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_util_tests(void);

// add util test suite to CUnit registry
void add_util_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  bool *passed;
} util_test_t;


#endif // UTIL_TESTS_H
