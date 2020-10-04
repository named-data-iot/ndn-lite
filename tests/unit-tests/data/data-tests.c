/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "data-tests.h"
#include <stdio.h>
#include "../CUnit/CUnit.h"
#include "data-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/key-storage.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;
static bool _decrypted_text_matched_original_text = false;
static bool _decrypted_text_matched_original_key = false;
static bool _encrypted_text_different_from_original_text = false;

void _run_data_test(data_test_t *test);

bool run_data_tests(void) {
  memset(data_test_results, 0, sizeof(bool)*DATA_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < DATA_NUM_TESTS; i++) {
    _run_data_test(&data_tests[i]);
  }

  return check_all_tests_passed(data_test_results, data_test_names,
                                DATA_NUM_TESTS);
}

void _run_data_test(data_test_t *test) {
  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ndn_ecdsa_curve = test->ndn_ecdsa_curve;

  int ret_val = -1;

  // tests start
  ndn_security_init();

  uint8_t buf[16] = {2,2,2,2,2,2,2,2,2,2};
  uint8_t block_value[1024];
  ndn_encoder_t encoder;

  ndn_data_t data;
  ret_val = ndn_data_set_content(&data, buf, sizeof(buf));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_set_content", ret_val);
    _all_function_calls_succeeded = false;
  }

  // set name
  char name_string[] = "/smarthome/controller/zhiyi-phone";
  ret_val = ndn_name_from_string(&data.name, name_string, sizeof(name_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  /* printf("***init data name*** \n"); */
  /* for (size_t i = 0; i < data.name.components_size; i++) { */
  /*   printf("comp type %u\n", (unsigned int) data.name.components[i].type); */
  /*   for (size_t j = 0; j < data.name.components[i].size; j++) { */
  /*     printf("%d ", data.name.components[i].value[j]); */
  /*   } */
  /*   printf("\n"); */
  /* } */
  encoder_init(&encoder, block_value, 1024);
  ret_val = ndn_name_tlv_encode(&encoder, &data.name);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_name_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }

  /* printf("name block content: \n"); */
  /* for (size_t i = 0; i < encoder.offset; i++) { */
  /*   printf("%d ", block_value[i]); */
  /* } */

  // set metainfo
  ndn_metainfo_init(&data.metainfo);
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);
  // encoding digest
  encoder_init(&encoder, block_value, 1024);
  //printf("\n***data encoding with digest sig***\n");
  ret_val = ndn_data_tlv_encode_digest_sign(&encoder, &data);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_tlv_encode_digest_sign", ret_val);
    _all_function_calls_succeeded = false;
  }

  /* printf("data block length: %d \n", (int) encoder.offset); */
  /* printf("data block content: \n"); */
  /* for (size_t i = 0; i < encoder.offset; i++) { */
  /*   printf("%d ", block_value[i]); */
  /* } */
  /* printf("\n"); */

  ndn_data_t data_check;
  ret_val = ndn_data_tlv_decode_no_verify(&data_check, block_value, encoder.offset, NULL, NULL);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_tlv_decode_no_verify", ret_val);
    _all_function_calls_succeeded = false;
  }

  ret_val = ndn_data_tlv_decode_digest_verify(&data_check, block_value, encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_tlv_decode_digest_verify", ret_val);
    _all_function_calls_succeeded = false;
  }

  const uint8_t *prv_key_raw = test->ecc_prv_key;
  uint32_t prv_key_raw_size = test->ecc_prv_key_size;
  // encoding ecdsa
  ndn_ecc_prv_t prv_key;
  ret_val = ndn_ecc_prv_init(&prv_key, prv_key_raw, prv_key_raw_size, ndn_ecdsa_curve, 1234);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_ecc_prv_init", ret_val);
    _all_function_calls_succeeded = false;
  }

  char id_string[] = "/smarthome/zhiyi";
  ndn_name_t identity;
  ret_val = ndn_name_from_string(&identity, id_string, sizeof(id_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  /* printf("\n***init identity name*** \n"); */
  /* for (size_t i = 0; i < identity.components_size; i++) { */
  /*   printf("comp type %u\n", (unsigned int) identity.components[i].type); */
  /*   for (size_t j = 0; j < identity.components[i].size; j++) { */
  /*     printf("%d ", identity.components[i].value[j]); */
  /*   } */
  /*   printf("\n"); */
  /* } */

  encoder_init(&encoder, block_value, 1024);
  //printf("\n***data encoding with ecdsa sig***\n");
  ret_val = ndn_data_tlv_encode_ecdsa_sign(&encoder, &data, &identity, &prv_key);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_tlv_encode_ecdsa_sign", ret_val);
    _all_function_calls_succeeded = false;
  }

  /* printf("data block length: %d \n", (int) encoder.offset); */
  /* printf("data block content: \n"); */
  /* for (size_t i = 0; i < encoder.offset; i++) { */
  /*   printf("%d ", block_value[i]); */
  /* } */
  /* printf("\n"); */

  const uint8_t *public = test->ecc_pub_key;
  uint32_t pub_size = test->ecc_pub_key_size;
  ndn_ecc_pub_t pub_key;
  ret_val = ndn_ecc_pub_init(&pub_key, public, pub_size, ndn_ecdsa_curve, 1234);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_ecc_pub_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_data_tlv_decode_ecdsa_verify(&data_check, block_value, encoder.offset, &pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_tlv_decode_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }

  // encoding hmac
  ndn_hmac_key_t hmac_key;
  ret_val = ndn_hmac_key_init(&hmac_key, prv_key_raw, prv_key_raw_size, 5678);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_hmac_key_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_ecc_prv_init(&prv_key, prv_key_raw, prv_key_raw_size, ndn_ecdsa_curve, 1234);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_ecc_prv_init", ret_val);
    _all_function_calls_succeeded = false;
  }

  encoder_init(&encoder, block_value, 1024);
  //printf("\n***data encoding with hmac sig***\n");
  ret_val = ndn_data_tlv_encode_hmac_sign(&encoder, &data, &identity, &hmac_key);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_tlv_encode_hmac_sign", ret_val);
    _all_function_calls_succeeded = false;
  }

  /* printf("data block length: %d \n", (int) encoder.offset); */
  /* printf("data block content: \n"); */
  /* for (size_t i = 0; i < encoder.offset; i++) { */
  /*   printf("%d ", block_value[i]); */
  /* } */
  /* printf("\n"); */

  ret_val = ndn_data_tlv_decode_hmac_verify(&data_check, block_value, encoder.offset, &hmac_key);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_tlv_decode_hmac_verify", ret_val);
    _all_function_calls_succeeded = false;
  }

  const uint8_t *aes_key_raw = test->aes_key;
  uint32_t aes_key_raw_size = test->aes_key_size;

  // Encrypted Data
  //printf("\n***Encrypted Data Tests*** \n");
  ndn_aes_key_t* aes = ndn_key_storage_get_empty_aes_key();
  ret_val = ndn_aes_key_init(aes, aes_key_raw, aes_key_raw_size, 1234);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_aes_key_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  ndn_name_append_string_component(&identity, "KEY", strlen("KEY"));
  ndn_name_append_keyid(&identity, 1234);

  /* printf("\n***data content before encryption with aes***\n"); */
  /* printf("data content block length: %d \n", data.content_size); */
  /* printf("data content block content: \n"); */
  /* for (size_t i = 0; i < data.content_size; i++) { */
  /*   printf("%d ", data.content_value[i]); */
  /* } */
  uint8_t *iv = test->iv;
  ret_val = ndn_data_set_encrypted_content(&data, buf, sizeof(buf), &identity, iv, DATA_TEST_IV_SIZE);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_set_encrypted_content", ret_val);
    _all_function_calls_succeeded = false;
  }

  if (memcmp(data.content_value, buf, data.content_size) != 0) {
    _encrypted_text_different_from_original_text = true;
  }

  /* printf("\n***data content after encryption with aes***\n"); */
  /* printf("data content block length: %d \n", data.content_size); */
  /* printf("data content block content: \n"); */
  /* for (size_t i = 0; i < data.content_size; i++) { */
  /*   printf("%d ", data.content_value[i]); */
  /* } */

  ndn_name_t obtained_key_name;
  uint8_t decrypt_output[50] = {0};
  uint32_t used = 0;
  ret_val = ndn_data_parse_encrypted_content(&data, decrypt_output, &used, &obtained_key_name);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_data_test", "ndn_data_parse_encrypted_content", ret_val);
    _all_function_calls_succeeded = false;
  }

  if (memcmp(decrypt_output, buf, used) == 0) {
    _decrypted_text_matched_original_text = true;
  }
  else {
    printf("In _run_data_test, decrypted text did not match original text.\n");
  }
  if (ndn_name_compare(&identity, &obtained_key_name) == 0) {
    _decrypted_text_matched_original_key = true;
  }
  else {
    printf("In _run_data_test, key name did not match original key name.\n");
  }
  /* printf("\n***data content after parsing***\n"); */
  /* printf("data content block length: %d \n", data.content_size); */
  /* printf("data content block content: \n"); */
  /* for (size_t i = 0; i < used; i++) { */
  /*   printf("%d ", decrypt_output[i]); */
  /* } */
  /* printf("\nTest End"); */

  if (_all_function_calls_succeeded &&
      _decrypted_text_matched_original_text &&
      _decrypted_text_matched_original_key &&
      _encrypted_text_different_from_original_text
  )
  {
    *test->passed = true;
  }
  else {
    printf("In _run_data_test, something went wrong.\n");
    *test->passed = false;
  }
}

void add_data_test_suite()
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Data Test", (int (*)(void))ndn_security_init, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "data_tests", (void (*)(void))run_data_tests))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}
