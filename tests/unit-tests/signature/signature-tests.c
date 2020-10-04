/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "signature-tests.h"
#include <stdio.h>
#include "../CUnit/CUnit.h"
#include "signature-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/signature.h"
#include "ndn-lite/security/ndn-lite-sec-config.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_signature_test(signature_test_t *test);

bool run_signature_tests(void) {
  printf("\n");
  memset(signature_test_results, 0, sizeof(bool)*SIGNATURE_NUM_TESTS);
  for (int i = 0; i < SIGNATURE_NUM_TESTS; i++) {
    _run_signature_test(&signature_tests[i]);
  }

  return check_all_tests_passed(signature_test_results, signature_test_names,
                                SIGNATURE_NUM_TESTS);
}

void _run_signature_test(signature_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  ndn_security_init();

  //ndn_security_init();
  // name init
  char key_name_string[] = "/smarthome/controller/key/001";
  ndn_name_t name;
  ret_val = ndn_name_from_string(&name, key_name_string, sizeof(key_name_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("signature info key locator name: \n");
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  // signature init
  ndn_signature_t signature1;
  ret_val = ndn_signature_init(&signature1, false);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_signature_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_signature_set_signature_type(&signature1, NDN_SIG_TYPE_ECDSA_SHA256);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_signature_set_signature_type", ret_val);
    _all_function_calls_succeeded = false;
  }
  char not_before[] = "20181031T000001";
  char not_after[] = "20191031T000001";
  ndn_signature_set_validity_period(&signature1, (uint8_t*)not_before, (uint8_t*)not_after);
  ndn_signature_set_key_locator(&signature1, &name);
  // set signature nonce
  ndn_signature_set_signature_nonce(&signature1, 0);
  // set timestamp
  ndn_signature_set_timestamp(&signature1, 0);

  // signature info encoding
  uint32_t sig1_info_block_size = ndn_signature_info_probe_block_size(&signature1);
  uint8_t sig1_info_block[sig1_info_block_size];
  ndn_encoder_t encoder;
  encoder_init(&encoder, sig1_info_block, sig1_info_block_size);
  ret_val = ndn_signature_info_tlv_encode(&encoder, &signature1);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_signature_info_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***signature info encoding***\n");
  printf("signature info block size: %d\n", (int) sig1_info_block_size);
  printf("signature info block content: \n");
  for (size_t i = 0; i < sig1_info_block_size; i++) {
    printf("%d ", sig1_info_block[i]);
  }

  // signature info decoding
  ndn_signature_t signature1_check;
  ndn_decoder_t decoder;
  decoder_init(&decoder, sig1_info_block, sig1_info_block_size);
  ret_val = ndn_signature_info_tlv_decode(&decoder, &signature1_check);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_signature_info_tlv_decode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***signature info decoding***\n");
  printf("signature info key locator content: \n");
  for (size_t i = 0; i < signature1_check.key_locator_name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) signature1_check.key_locator_name.components[i].type);
    for (size_t j = 0; j < signature1_check.key_locator_name.components[i].size; j++) {
      printf("%d ", signature1_check.key_locator_name.components[i].value[j]);
    }
    printf("\n");
  }
  if (signature1_check.enable_ValidityPeriod)
    printf("successfully decode validity period\n");
  printf("signature validity period, not before:  \n");
  for (int i = 0; i < 15; i++) {
    printf("%d ",  signature1_check.validity_period.not_before[i]);
  }
  printf("\nsignature validity period, not after: \n");
  for (int i = 0; i < 15; i++) {
    printf("%d ",  signature1_check.validity_period.not_after[i]);
  }

  // signature value init
  ret_val = ndn_signature_set_signature_value(&signature1, test->dummy_signature, test->dummy_signature_len);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_signature_set_signature", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\nsignature value: \n");
  for (size_t i = 0; i < signature1.sig_size; i++) {
    printf("%d ", signature1.sig_value[i]);
  }

  // signature value encoding
  uint32_t sig1_value_block_size = ndn_signature_value_probe_block_size(&signature1);
  uint8_t sig1_value_block[sig1_value_block_size];
  encoder_init(&encoder, sig1_value_block, sig1_value_block_size);
  ret_val = ndn_signature_value_tlv_encode(&encoder, &signature1);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_signature_value_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***signature value encoding***\n");
  printf("signature value block size: %d\n", (int) sig1_value_block_size);
  printf("signature value block content: \n");
  for (size_t i = 0; i < sig1_value_block_size; i++) {
    printf("%d ", sig1_value_block[i]);
  }

  // signature value decoding
  decoder_init(&decoder, sig1_value_block, sig1_value_block_size);
  ret_val = ndn_signature_value_tlv_decode(&decoder, &signature1_check);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_signature_test", "ndn_signature_value_tlv_decode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***signature value decoding***\n");
  printf("signature value: \n");
  for (size_t i = 0; i < signature1_check.sig_size; i++) {
    printf("%d ", signature1_check.sig_value[i]);
  }

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_signature_test, something went wrong.\n");
    *test->passed = false;
  }

}

void add_signature_test_suite(void)
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Signature Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "signature_tests", (void (*)(void))run_signature_tests))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}
