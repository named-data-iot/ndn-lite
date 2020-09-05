
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FRAGMENTATION_SUPPORT_TESTS_H
#define FRAGMENTATION_SUPPORT_TESTS_H

#include <stdbool.h>
#include <stdint.h>

#define FRAGMENTATION_SUPPORT_TEST_PAYLOAD_SIZE 104
#define FRAGMENTATION_SUPPORT_NUM_TESTS 1

// returns true if all tests passed, false otherwise
bool run_fragmentation_support_tests(void);

// add forwarder test suite to CUnit registry
void add_fragmentation_support_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  const uint8_t *payload;
  uint32_t payload_size;
  bool *passed;
} fragmentation_support_test_t;


#endif // FRAGMENTATION_SUPPORT_TESTS_H
