
/*
 * Copyright (C) 2019 Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "trust-schema-tests.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "trust-schema-tests-def.h"
#include "../test-helpers.h"
#include "../print-helpers.h"

#include "../../ndn-lite/encode/name.h"
#include "../../ndn-lite/ndn-error-code.h"
#include "../../ndn-lite/app-support/ndn-trust-schema.h"
#include "../../ndn-lite/encode/trust-schema/ndn-trust-schema-pattern-component.h"
#include "../../ndn-lite/encode/ndn-rule-storage.h"

#include "../../ndn-lite/util/re.h"
#include "../CUnit/CUnit.h"

static const char *_current_test_name;

static ndn_trust_schema_rule_t article_rule;
static ndn_trust_schema_rule_t author_rule;
static ndn_trust_schema_rule_t admin_rule;
static ndn_trust_schema_rule_t root_rule;

void _run_trust_schema_test(trust_schema_test_t *test);

bool init_trust_schema_tests(void) {

  int ret_val = -1;

  ndn_rule_storage_init();

  ret_val = ndn_trust_schema_rule_from_strings(&article_rule,
  					       article_rule_data_pattern_string, strlen(article_rule_data_pattern_string),
  					       article_rule_key_pattern_string, strlen(article_rule_key_pattern_string));
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_trust_schema_rule_from_strings failed, return code: %d\n", ret_val);
    return false;
  }

  ret_val = ndn_trust_schema_rule_from_strings(&author_rule,
  					       author_rule_data_pattern_string, strlen(author_rule_data_pattern_string),
  					       author_rule_key_pattern_string, strlen(author_rule_key_pattern_string));
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_trust_schema_rule_from_strings failed, return code: %d\n", ret_val);
    return false;
  }

  ret_val = ndn_trust_schema_rule_from_strings(&admin_rule,
  					       admin_rule_data_pattern_string, strlen(admin_rule_data_pattern_string),
  					       admin_rule_key_pattern_string, strlen(admin_rule_key_pattern_string));
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_trust_schema_rule_from_strings failed, return code: %d\n", ret_val);
    return false;
  }

  ret_val = ndn_trust_schema_rule_from_strings(&root_rule,
  					       root_rule_data_pattern_string, strlen(root_rule_data_pattern_string),
  					       root_rule_key_pattern_string, strlen(root_rule_key_pattern_string));
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_trust_schema_rule_from_strings failed, return code: %d\n", ret_val);
    return false;
  }

  ret_val = ndn_rule_storage_add_rule("article_rule", &article_rule);
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_storage_add_rule failed, return code: %d\n", ret_val);
    return false;
  }

  ret_val = ndn_rule_storage_add_rule("author_rule", &author_rule);
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_storage_add_rule failed, return code: %d\n", ret_val);
    return false;
  }

  ret_val = ndn_rule_storage_add_rule("admin_rule", &admin_rule);
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_storage_add_rule failed, return code: %d\n", ret_val);
    return false;
  }

  ret_val = ndn_rule_storage_add_rule("root_rule", &root_rule);
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    printf("In init_trust_schema_tests, ndn_storage_add_rule failed, return code: %d\n", ret_val);
    return false;
  }

  return true;

}

bool run_trust_schema_tests(void) {
  printf("\n");

  if (!init_trust_schema_tests())
    return false;

  memset(trust_schema_test_results, 0, sizeof(bool)*TRUST_SCHEMA_NUM_TESTS);
  for (int i = 0; i < TRUST_SCHEMA_NUM_TESTS; i++) {
    _run_trust_schema_test(&trust_schema_tests[i]);
  }

  return check_all_tests_passed(trust_schema_test_results, trust_schema_test_names,
                                TRUST_SCHEMA_NUM_TESTS);
}

static ndn_trust_schema_rule_t current_rule;
static ndn_name_t current_data_name;
static ndn_name_t current_key_name;

void _run_trust_schema_test(trust_schema_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];

  int ret_val = -1;

  /* printf("Running trust schema test for following parameters:\n"); */
  /* printf("Rule data pattern: %.*s\n", test->rule_data_pattern_string_size, test->rule_data_pattern_string); */
  /* printf("Rule key pattern: %.*s\n", test->rule_key_pattern_string_size, test->rule_key_pattern_string); */
  /* printf("Data name: %.*s\n", test->data_name_string_size, test->data_name_string); */
  /* printf("Key name: %.*s\n", test->key_name_string_size, test->key_name_string); */

  ret_val = ndn_name_from_string(&current_data_name, test->data_name_string, test->data_name_string_size);
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    print_error(_current_test_name, "_run_trust_schema_test", "ndn_name_from_string", ret_val);
    *test->passed = false;
    return;
  }

  ret_val = ndn_name_from_string(&current_key_name, test->key_name_string, test->key_name_string_size);
  CU_ASSERT_EQUAL(ret_val, NDN_SUCCESS);
  if (ret_val != NDN_SUCCESS) {
    print_error(_current_test_name, "_run_trust_schema_test", "ndn_name_from_string", ret_val);
    *test->passed = false;
    return;
  }

  ret_val = ndn_trust_schema_rule_from_strings(&current_rule,
  					       test->rule_data_pattern_string, test->rule_data_pattern_string_size,
  					       test->rule_key_pattern_string, test->rule_key_pattern_string_size);
  CU_ASSERT_EQUAL(ret_val, test->expected_rule_compilation_result);
  if (ret_val != test->expected_rule_compilation_result) {
    printf("In %s, rule compilation result was %d; expected a rule compilation result of %d.\n", _current_test_name, ret_val, test->expected_rule_compilation_result);
    *test->passed = false;
    return;
  }
  if (test->expected_rule_compilation_result != NDN_SUCCESS) {
    *test->passed = true;
    return;
  }

  ret_val = ndn_trust_schema_verify_data_name_key_name_pair(&current_rule, &current_data_name, &current_key_name);
  CU_ASSERT_EQUAL(ret_val, test->expected_match_result);
  if (ret_val != test->expected_match_result) {
    printf("In %s, match result was %d; expected a match result of %d.\n", _current_test_name, ret_val, test->expected_match_result);
    *test->passed = false;
    return;
  }

  *test->passed = true;

}

void add_trust_schema_test_suite(void)
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Trust Schema Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "trust_schema_tests", (void (*)(void))run_trust_schema_tests))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}