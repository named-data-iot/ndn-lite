/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_TRUST_SCHEMA_RULE_H
#define NDN_TRUST_SCHEMA_RULE_H

#include <stdint.h>
#include <stddef.h>

#include "ndn-trust-schema-pattern.h"

typedef struct ndn_trust_schema_rule {
  /**
   * The NDN trust schema pattern which represents the required data name pattern of this rule.
   */
  ndn_trust_schema_pattern_t data_pattern;

  /**
   * The NDN trust schema pattern which represents the required key name pattern of this rule.
   */
  ndn_trust_schema_pattern_t key_pattern;

  // will probably eventually put some kind of handler to this rule so that it can be referenced by other
  // rules or itself
} ndn_trust_schema_rule_t;


/**
 * Init an NDN Trust Schema rule from two strings. This function will do memory copy and
 * only support regular string; not support URI currently.
 * @param rule. Output. The NDN Trust Schema rule to be inited.
 * @param data_name_pattern_string. Input. The string from which the data name ndn trust schema patter will be inited.
 * @param data_name_pattern_string_size. Input. Size of the data name pattern string.
 * @param key_name_pattern_string. Input. The string from which the key name ndn trust schema patter will be inited.
 * @param key_name_pattern_string_size. Input. Size of the key name pattern string.
 * @return 0 if there is no error.
 */
int
ndn_trust_schema_rule_from_strings(ndn_trust_schema_rule_t* rule,
				                           const char* data_name_pattern_string, uint32_t data_name_pattern_string_size,
				                           const char* key_name_pattern_string, uint32_t key_name_pattern_string_size);
/**
 * Copy the lhs rule to the rhs rule.
 * @param lhs. Input. The rule to be inited.
 * @param rhs. Output. The rule that will be copied to.
 * @return 0 if there is no error.
 */
int
ndn_trust_schema_rule_copy(const ndn_trust_schema_rule_t *lhs, ndn_trust_schema_rule_t *rhs);

#endif // NDN_TRUST_SCHEMA_RULE_H
