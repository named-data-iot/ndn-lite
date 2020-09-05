
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NAME_ENCODE_DECODE_TESTS_DEF_H
#define NAME_ENCODE_DECODE_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "name-encode-decode-tests.h"

#define NAME_ENCODE_DECODE_NUM_TESTS 1

extern char *name_encode_decode_test_names[NAME_ENCODE_DECODE_NUM_TESTS];

extern bool name_encode_decode_test_results[NAME_ENCODE_DECODE_NUM_TESTS];

extern name_encode_decode_test_t name_encode_decode_tests[NAME_ENCODE_DECODE_NUM_TESTS];

#endif // NAME_ENCODE_DECODE_TESTS_DEF_H
