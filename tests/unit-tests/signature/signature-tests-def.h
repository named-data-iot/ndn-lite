
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef SIGNATURE_TESTS_DEF_H
#define SIGNATURE_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "signature-tests.h"

#define SIGNATURE_NUM_TESTS 1
#define SECP256R1_PUB_KEY_SIZE 64

extern char *signature_test_names[SIGNATURE_NUM_TESTS];

extern bool signature_test_results[SIGNATURE_NUM_TESTS];

extern signature_test_t signature_tests[SIGNATURE_NUM_TESTS];

extern const uint8_t dummy_signature_1[SECP256R1_PUB_KEY_SIZE];

#endif // SIGNATURE_TESTS_DEF_H
