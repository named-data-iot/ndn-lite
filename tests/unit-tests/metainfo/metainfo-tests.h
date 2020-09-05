
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef METAINFO_TESTS_H
#define METAINFO_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_metainfo_tests(void);

// add metainfo test suite to CUnit registry
void add_metainfo_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  bool *passed;
} metainfo_test_t;


#endif // METAINFO_TESTS_H
