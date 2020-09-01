
/*
 * Copyright (C) Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sha256-sign-verify-tests.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "../../CUnit/CUnit.h"

#include "sha256-sign-verify-tests-def.h"
#include "../../test-helpers.h"
#include "../../print-helpers.h"

#include "../../../ndn-lite/ndn-constants.h"
#include "../../../ndn-lite/ndn-error-code.h"
#include "../../../ndn-lite/security/ndn-lite-sha.h"
#include "../../../ndn-lite/security/ndn-lite-sec-config.h"

#define TEST_HASH_BUFFER_LEN 500

static uint8_t test_message[10] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

static uint8_t test_hash_buffer[TEST_HASH_BUFFER_LEN];

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_sha256_sign_verify_test(sha256_sign_verify_test_t *test);

bool run_sha256_sign_verify_tests(void)
{
  memset(sha256_sign_verify_test_results, 0, sizeof(bool) * SHA256_SIGN_VERIFY_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < SHA256_SIGN_VERIFY_NUM_TESTS; i++)
  {
    _run_sha256_sign_verify_test(&sha256_sign_verify_tests[i]);
  }
  return check_all_tests_passed(sha256_sign_verify_test_results, sha256_sign_verify_test_names,
                                SHA256_SIGN_VERIFY_NUM_TESTS);
}

void _run_sha256_sign_verify_test(sha256_sign_verify_test_t *test)
{

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  ndn_security_init();

  int ret_val = -1;

  uint32_t hash_size = 0;
  ret_val = ndn_sha256_sign(test_message, sizeof(test_message),
                            test_hash_buffer, sizeof(test_hash_buffer),
                            &hash_size);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _all_function_calls_succeeded = false;
    print_error(_current_test_name, "_run_sha256_sign_verify_test", "ndn_sha256_sign", ret_val);
  }

  ret_val = ndn_sha256_verify(test_message, sizeof(test_message),
                              test_hash_buffer, hash_size);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _all_function_calls_succeeded = false;
    print_error(_current_test_name, "_run_sha256_sign_verify_test", "ndn_sha256_verify", ret_val);
  }

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else
  {
    *test->passed = false;
  }
}

void sha256_sign_verify_multi_test(void)
{
  run_sha256_sign_verify_tests();
}