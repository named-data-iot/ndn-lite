/*
 * Copyright (C) Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_VERIFY_TESTS_H
#define SIGN_VERIFY_TESTS_H

#include <stdio.h>
#include <stdbool.h>

// returns true if all tests passed, false otherwise
bool run_sign_verify_tests(void);

// add Sign Verify test suite to CUnit registry
void add_sign_verify_test_suite(void);

#endif // SIGN_VERIFY_TESTS_H
