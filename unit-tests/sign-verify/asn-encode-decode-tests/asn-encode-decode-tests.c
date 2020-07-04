
/*
 * Copyright (C) Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "asn-encode-decode-tests.h"

#include <stdio.h>
#include <string.h>
#include "../../CUnit/CUnit.h"

#include "asn-encode-decode-tests-def.h"
#include "../../test-helpers.h"
#include "../../print-helpers.h"

#include "../../../ndn-lite/ndn-error-code.h"
#include "../../../ndn-lite/security/ndn-lite-sec-config.h"
#include "../../../ndn-lite/security/ndn-lite-sec-utils.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;
static CU_pSuite pSuite;

void _run_asn_encode_decode_test(asn_encode_decode_test_t *test);

bool run_asn_encode_decode_tests(void)
{
  memset(asn_encode_decode_test_results, 0, sizeof(bool) * ASN_ENCODE_DECODE_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < ASN_ENCODE_DECODE_NUM_TESTS; i++)
  {
    _run_asn_encode_decode_test(&asn_encode_decode_tests[i]);
  }
  return check_all_tests_passed(asn_encode_decode_test_results, asn_encode_decode_test_names,
                                ASN_ENCODE_DECODE_NUM_TESTS);
}

void _run_asn_encode_decode_test(asn_encode_decode_test_t *test)
{
  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  ndn_security_init();

  char *test_name = test->test_names[test->test_name_index];

  uint32_t asn1_encoded_sig_len = 0;
  int ret_val = 0;
  uint32_t decoded_sig_len = 0;

  bool test_sig_asn_encoding_size_probe = false;
  bool test_sig_asn_encoding_success = false;
  bool test_sig_asn_decoding_success = false;
  ret_val = ndn_asn1_probe_ecdsa_signature_encoding_size(test->sig, test->sig_len, &asn1_encoded_sig_len);
  if (ret_val == NDN_SUCCESS)
  {
    if (asn1_encoded_sig_len == test->sig_asn_encoded_probe_length_expected)
    {
      test_sig_asn_encoding_size_probe = true;
    }
    else
    {
      char error_message[128];
      sprintf(error_message, "In _run_asn_encode_decode_test, did not get expec"
                             "ted value from ndn_asn1_probe_ecdsa_signature_encoding_size "
                             "for %s. Expected %d, got %d\n",
              test_name, test->sig_asn_encoded_probe_length_expected,
              asn1_encoded_sig_len);
      CU_FAIL(error_message);
    }
  }
  else
  {
    char error_message[128];
    sprintf(error_message, "%s failed: %s=%d", "_run_asn_encode_decode_test",
            "ndn_asn1_probe_ecdsa_signature_encoding_size", ret_val);
    CU_FAIL(error_message);
  }
  ret_val = ndn_asn1_encode_ecdsa_signature(test->sig, test->sig_len, test->sig_buf_len);
  if (ret_val == NDN_SUCCESS)
  {
    if (asn1_encoded_sig_len == test->sig_asn_encoded_expected_len &&
        memcmp(test->sig, test->sig_asn_encoded_expected, asn1_encoded_sig_len) == 0)
    {
      test_sig_asn_encoding_success = true;
    }
    else
    {
      char error_message[128];
      sprintf(error_message, "In _run_asn_encode_decode_test, memcmp between "
                             "%s after encoding and expected asn encoding did"
                             "n't return 0, or\nasn encoded signature length "
                             "did not match expected asn encoded signature length.\n",
              test_name);
      CU_FAIL(error_message);
      print_hex("Value of asn encoded signature:", test->sig, asn1_encoded_sig_len);
      print_hex("Expected value of asn encoded signature:",
                test->sig_asn_encoded_expected, test->sig_asn_encoded_expected_len);
      printf("Encoded signature length: %d, expected encoded signature length: %d\n",
             asn1_encoded_sig_len, test->sig_asn_encoded_expected_len);
    }
  }
  else
  {
    CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
    print_error(_current_test_name, "_run_asn_encode_decode_test", "ndn_asn1_encode_ecdsa_signature", ret_val);
  }
  ret_val = ndn_asn1_decode_ecdsa_signature(test->sig, asn1_encoded_sig_len, test->sig_decoded, test->sig_decoded_buf_len,
                                            &decoded_sig_len);
  if (ret_val == NDN_SUCCESS)
  {
    if (decoded_sig_len == test->sig_decoded_expected_len &&
        memcmp(test->sig_decoded, test->sig_decoded_expected, decoded_sig_len) == 0)
    {
      test_sig_asn_decoding_success = true;
    }
    else
    {
      CU_ASSERT_EQUAL(decoded_sig_len, test->sig_decoded_expected_len);
      CU_ASSERT_EQUAL(memcmp(test->sig_decoded, test->sig_decoded_expected, decoded_sig_len), 0);
      printf("In _run_asn_encode_decode_test, memcmp between decoded %s and expected decoded test signature didn't return 0, or\n"
             "decoded signature length and expected decoded signature length did not match.\n",
             test_name);
      print_hex("Value of decoded signature:", test->sig_decoded, decoded_sig_len);
      print_hex("Expected decoded signature:", test->sig_decoded_expected, test->sig_decoded_expected_len);
      printf("Decoded signature length: %d, expected decoded signature length: %d\n",
             decoded_sig_len, test->sig_decoded_expected_len);
    }
  }
  else
  {
    CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
    print_error(_current_test_name, "_run_asn_encode_decode_test", "ndn_asn1_decode_ecdsa_signature", ret_val);
  }
  if (test_sig_asn_encoding_size_probe &&
      test_sig_asn_encoding_success &&
      test_sig_asn_decoding_success)
  {
    *test->passed = true;
  }
  else
  {
    *test->passed = false;
  }
}

void asn_encode_decode_multi_test()
{
  run_asn_encode_decode_tests();
}