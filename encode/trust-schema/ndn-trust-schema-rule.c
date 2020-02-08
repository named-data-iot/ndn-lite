/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-trust-schema-rule.h"

int
ndn_trust_schema_rule_from_strings(ndn_trust_schema_rule_t* rule,
				                           const char* data_name_pattern_string, uint32_t data_name_pattern_string_size,
				                           const char* key_name_pattern_string, uint32_t key_name_pattern_string_size)
{
  int ret_val = -1;
  ret_val = ndn_trust_schema_pattern_from_string(&rule->data_pattern, data_name_pattern_string, data_name_pattern_string_size);
  if (ret_val != 0) {
    return ret_val;
  }

  ret_val = ndn_trust_schema_pattern_from_string(&rule->key_pattern, key_name_pattern_string, key_name_pattern_string_size);
  if (ret_val != 0) {
    return ret_val;
  }

  return 0;
}

int
ndn_trust_schema_rule_copy(const ndn_trust_schema_rule_t *lhs, ndn_trust_schema_rule_t *rhs)
{
  int ret_val = -1;

  ret_val = ndn_trust_schema_pattern_copy(&lhs->data_pattern, &rhs->data_pattern);
  if (ret_val != 0) return ret_val;

  ret_val = ndn_trust_schema_pattern_copy(&lhs->key_pattern, &rhs->key_pattern);
  if (ret_val != 0) return ret_val;

  return 0;
}
