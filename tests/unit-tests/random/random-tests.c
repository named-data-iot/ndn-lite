
/*
 * Copyright (C) 2018 Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "random-tests.h"

#include <stdio.h>

#include "random-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"

#include <stdio.h>
#include "ndn-lite/security/ndn-lite-hmac.h"
#include "ndn-lite/ndn-constants.h"
#include <string.h>
#include "../CUnit/CUnit.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_random_test(random_test_t *test);

bool run_random_tests(void)
{
  memset(random_test_results, 0, sizeof(bool) * RANDOM_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < RANDOM_NUM_TESTS; i++)
  {
    _run_random_test(&random_tests[i]);
  }

  return check_all_tests_passed(random_test_results, random_test_names,
                                RANDOM_NUM_TESTS);
}

void _run_random_test(random_test_t *test)
{

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  ndn_security_init();

  uint8_t shared[NDN_SEC_ECC_MIN_PUBLIC_KEY_SIZE];
  uint8_t tsk[NDN_SEC_ECC_MIN_PRIVATE_KEY_SIZE];
  uint8_t salt[8];
  memcpy(shared, test->ecc_prv_key_val, sizeof(shared));
  memcpy(tsk, test->ecc_pub_key_val, sizeof(tsk));
  memcpy(salt, test->ecc_pub_key_val, sizeof(salt));

  ret_val = ndn_hkdf(shared, sizeof(shared), tsk, sizeof(tsk),
                     salt, sizeof(salt), NULL, 0);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    print_error(_current_test_name, "_run_random_test", "ndn_hkdf", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("HMAC key generation\n");
  uint8_t i = 0;
  while (i < sizeof(tsk))
  {
    printf("0x%02x ", tsk[i++]);
  }
  puts("\n");

  uint8_t *personalization = (uint8_t *)"ndn-iot-access-control";
  uint8_t *additional_input = (uint8_t *)"additional-input";
  uint8_t *seed = (uint8_t *)"seed";
  ret_val = ndn_hmacprng(personalization, sizeof(personalization),
                         salt, sizeof(salt), seed, sizeof(seed),
                         additional_input, sizeof(additional_input));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    print_error(_current_test_name, "_run_random_test", "ndn_hmacprng", ret_val);
    _all_function_calls_succeeded = false;
  }

  printf("Salt generation\n");
  uint8_t j = 0;
  while (j < sizeof(salt))
  {
    printf("0x%02x ", salt[j++]);
  }

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else
  {
    printf("In _run_random_test, something went wrong.\n");
    *test->passed = false;
  }
}

void add_random_test_suite(void)
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Random Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "random_tests", (void (*)(void))run_random_tests))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}
