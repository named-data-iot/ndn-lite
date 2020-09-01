
/*
 * Copyright (C) 2018 Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef RANDOM_TESTS_DEF_H
#define RANDOM_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "random-tests.h"

#define RANDOM_NUM_TESTS 1
#define SECP160R1_PRV_KEY_SIZE 21
#define SECP160R1_PUB_KEY_SIZE 40

extern char *random_test_names[RANDOM_NUM_TESTS];

extern bool random_test_results[RANDOM_NUM_TESTS];

extern random_test_t random_tests[RANDOM_NUM_TESTS];

extern const uint8_t random_test_ecc_secp160r1_pub_key[SECP160R1_PUB_KEY_SIZE];

extern const uint8_t random_test_ecc_secp160r1_prv_key[SECP160R1_PRV_KEY_SIZE];

#endif // RANDOM_TESTS_DEF_H
