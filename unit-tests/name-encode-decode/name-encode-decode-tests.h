
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NAME_ENCODE_DECODE_TESTS_H
#define NAME_ENCODE_DECODE_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_name_encode_decode_tests(void);

// add name encode-decode test suite to CUnit registry
void add_name_encode_decode_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  bool *passed;
} name_encode_decode_test_t;


#endif // NAME_ENCODE_DECODE_TESTS_H
