/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef HMAC_TESTS_H
#define HMAC_TESTS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// add hmac test suite to CUnit registry
void add_hmac_test_suite(void);

#endif // HMAC_TESTS_H