/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name-encode-decode-tests.h"
#include <stdio.h>
#include <string.h>
#include "../CUnit/CUnit.h"
#include "name-encode-decode-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/encode/name.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_name_encode_decode_test(name_encode_decode_test_t *test);

bool run_name_encode_decode_tests(void) {
  memset(name_encode_decode_test_results, 0, sizeof(bool)*NAME_ENCODE_DECODE_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < NAME_ENCODE_DECODE_NUM_TESTS; i++) {
    _run_name_encode_decode_test(&name_encode_decode_tests[i]);
  }

  return check_all_tests_passed(name_encode_decode_test_results, name_encode_decode_test_names,
                                NAME_ENCODE_DECODE_NUM_TESTS);
}

void _run_name_encode_decode_test(name_encode_decode_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  // component initialization
  char comp1[] = "aaaaaa";
  name_component_t component;
  ret_val = name_component_from_string(&component, comp1, sizeof(comp1));
  CU_ASSERT_EQUAL(ret_val, 0);
  ret_val += name_component_from_version(&component, 255);
  CU_ASSERT_EQUAL(ret_val, 0);
  ret_val += name_component_from_timestamp(&component, 256);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***component init***\ncheck type %u\n", (unsigned int) component.type);
  printf("check length %u\n", component.size);
  printf("check buffer content\n");
  for (size_t i = 0; i < component.size; i++) {
    printf("%d ", component.value[i]);
  }

  // component encoding
  uint8_t check_block[NDN_NAME_COMPONENT_BLOCK_SIZE];
  ndn_encoder_t comp_encoder;
  encoder_init(&comp_encoder, check_block, NDN_NAME_COMPONENT_BLOCK_SIZE);
  ret_val = name_component_tlv_encode(&comp_encoder, &component);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***component encoding***\n");
  printf("check block length %u\n", comp_encoder.offset);
  printf("check block content\n");
  for (size_t i = 0; i < comp_encoder.offset; i++) {
    printf("%d ", check_block[i]);
  }

  // component decoding
  name_component_t check_component;
  ret_val = name_component_from_block(&check_component, check_block, comp_encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);
  uint64_t check_value = name_component_to_timestamp(&check_component);
  if (ret_val != 0 || check_value != 256) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***component decoding***\n");
  printf("check type %u\n", (unsigned int) check_component.type);
  printf("check length %u\n", check_component.size);
  printf("check buffer content\n");
  for (size_t i = 0; i < check_component.size; i++) {
    printf("%d ", check_component.value[i]);
  }

  // name initialization
  ndn_name_t name;
  ndn_name_init(&name);
  ndn_name_append_string_component(&name, "bbbbbb", strlen("bbbbbb"));
  ndn_name_append_string_component(&name, "cccccc", strlen("cccccc"));
  ndn_name_append_string_component(&name, "123456", strlen("123456"));
  printf("\n***name init***\ncheck name comp size %u\n", name.components_size);
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  // name append
  uint32_t temp = 123;
  ret_val = ndn_name_append_bytes_component(&name, (uint8_t*)&temp, sizeof(uint32_t));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "ndn_name_append_component", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***name append comp***\ncheck name comp size %u\n", name.components_size);
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  // name encode
  size_t name_block_size = ndn_name_probe_block_size(&name);
  uint8_t name_block_value[name_block_size];
  ndn_encoder_t name_encoder;
  encoder_init(&name_encoder, name_block_value, name_block_size);
  ret_val = ndn_name_tlv_encode(&name_encoder, &name);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "ndn_name_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***name encoding***\n");
  printf("check block length %u\n", name_encoder.offset);
  printf("check block content\n");
  for (size_t i = 0; i < name_encoder.offset; i++) {
    printf("%d ", name_block_value[i]);
  }

  // name decode
  ndn_name_t check_name;
  ret_val = ndn_name_from_block(&check_name, name_block_value, name_block_size);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "ndn_name_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***name decoding***\n");
  for (size_t i = 0; i < check_name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) check_name.components[i].type);
    for (size_t j = 0; j < check_name.components[i].size; j++) {
      printf("%d ", check_name.components[i].value[j]);
    }
    printf("\n");
  }

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_name_encode_decode_test, something went wrong.\n");
    *test->passed = false;
  }
}

void add_name_encode_decode_test_suite(void)
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Name Encode/Decode Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "name_encode_decode_tests", (void (*)(void))run_name_encode_decode_tests))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}