
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef INTEREST_TESTS_DEF_H
#define INTEREST_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "interest-tests.h"

#define SECP256R1_PRV_KEY_SIZE 32
#define SECP256R1_PUB_KEY_SIZE 64
#define INTEREST_TEST_HMAC_KEY_SIZE 10

#define INTEREST_NUM_TESTS 1

extern char *interest_test_names[INTEREST_NUM_TESTS];

extern bool interest_test_results[INTEREST_NUM_TESTS];

extern interest_test_t interest_tests[INTEREST_NUM_TESTS];

extern const uint8_t interest_test_ecc_secp256r1_pub_key[SECP256R1_PUB_KEY_SIZE];

extern const uint8_t interest_test_ecc_secp256r1_prv_key[SECP256R1_PRV_KEY_SIZE];

extern const uint8_t interest_test_hmac_key[INTEREST_TEST_HMAC_KEY_SIZE];

#endif // INTEREST_TESTS_DEF_H
