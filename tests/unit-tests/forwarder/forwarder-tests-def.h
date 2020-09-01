
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_TESTS_DEF_H
#define FORWARDER_TESTS_DEF_H

#include "forwarder-tests.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FORWARDER_NUM_TESTS 1
#define SECP256R1_PRI_KEY_SIZE 32
#define SECP256R1_PUB_KEY_SIZE 64

extern char *forwarder_test_names[FORWARDER_NUM_TESTS];

extern bool forwarder_test_results[FORWARDER_NUM_TESTS];

extern forwarder_test_t forwarder_tests[FORWARDER_NUM_TESTS];

extern const uint8_t test_ecc_secp256r1_private_raw_1[SECP256R1_PRI_KEY_SIZE];

extern const uint8_t test_ecc_secp256r1_public_raw_1[SECP256R1_PUB_KEY_SIZE];

#endif // FORWARDER_TESTS_DEF_H
