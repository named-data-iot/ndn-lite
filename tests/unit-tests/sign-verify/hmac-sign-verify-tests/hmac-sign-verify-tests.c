
/*
 * Copyright (C) Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "hmac-sign-verify-tests.h"

#include <stdio.h>
#include <string.h>
#include "../../CUnit/CUnit.h"

#include "hmac-sign-verify-tests-def.h"
#include "../../test-helpers.h"
#include "../../print-helpers.h"

#include "../../../ndn-lite/ndn-constants.h"
#include "../../../ndn-lite/ndn-enums.h"
#include "../../../ndn-lite/ndn-error-code.h"
#include "../../../ndn-lite/security/ndn-lite-hmac.h"

#define TEST_SIGNATURE_BUFFER_LEN 500

static uint8_t test_message[10] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

static const uint32_t test_arbitrary_key_id = 666;

static uint8_t test_signature_buffer[TEST_SIGNATURE_BUFFER_LEN];

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_hmac_sign_verify_test(hmac_sign_verify_test_t *test);

bool run_hmac_sign_verify_tests(void) {
  memset(hmac_sign_verify_test_results, 0, sizeof(bool)*HMAC_SIGN_VERIFY_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < HMAC_SIGN_VERIFY_NUM_TESTS; i++) {
    _run_hmac_sign_verify_test(&hmac_sign_verify_tests[i]);
  }
  return check_all_tests_passed(hmac_sign_verify_test_results, hmac_sign_verify_test_names,
                                HMAC_SIGN_VERIFY_NUM_TESTS);
}

void _run_hmac_sign_verify_test(hmac_sign_verify_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  ndn_security_init();

  int ret_val = -1;

  ndn_hmac_key_t hmac_key;
  ndn_hmac_key_init(&hmac_key, test->key_val, test->key_len, test_arbitrary_key_id);

  uint32_t signature_size = 0;
  ret_val = ndn_hmac_sign(test_message, sizeof(test_message), 
                test_signature_buffer, sizeof(test_signature_buffer), 
                &hmac_key, &signature_size);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    _all_function_calls_succeeded = false;
    print_error(_current_test_name, "_run_hmac_sign_verify_test", "ndn_hmac_sign", ret_val);
  }
  
  ret_val = ndn_hmac_verify(test_message, sizeof(test_message), 
                            test_signature_buffer, signature_size, 
                            &hmac_key);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    _all_function_calls_succeeded = false;
    print_error(_current_test_name, "_run_hmac_sign_verify_test", "ndn_hmac_verify", ret_val);
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

void hmac_multi_test()
{
  run_hmac_sign_verify_tests();
}
