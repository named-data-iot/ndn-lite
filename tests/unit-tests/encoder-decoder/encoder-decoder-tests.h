
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef ENCODER_DECODER_TESTS_H
#define ENCODER_DECODER_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_encoder_decoder_tests(void);

// add encode decoder test suite to CUnit registry
void add_encoder_decoder_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  bool *passed;
} encoder_decoder_test_t;


#endif // ENCODER_DECODER_TESTS_H
