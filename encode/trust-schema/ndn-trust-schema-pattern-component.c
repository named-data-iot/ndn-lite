/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-trust-schema-pattern-component.h"

#include <string.h>
#include <stdlib.h>

#include "../../ndn-constants.h"
#include "../../ndn-error-code.h"

int
ndn_trust_schema_pattern_component_from_string(ndn_trust_schema_pattern_component_t* component, const char* string, uint32_t size)
{
  if (size+1 > NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE)
    return NDN_OVERSIZE;

  char temp_pattern_comp_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];

  memcpy(temp_pattern_comp_string_arr, string, size);
  temp_pattern_comp_string_arr[size] = '\0';

  uint32_t string_size = string[size - 1] == '\0' ? size-1 : size;

  int type = _probe_trust_schema_pattern_component_type(temp_pattern_comp_string_arr);

  if (type == NDN_TRUST_SCHEMA_PATTERN_COMPONENT_UNRECOGNIZED_TYPE)
    return type;

  switch (type) {
  case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
    component->type = type;
    memcpy(component->value, string+1, string_size-2);
    component->size = string_size-2;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
    component->type = type;
    component->size = 0;
    break;
  case NDN_TRUST_SCHEMA_SUBPATTERN_INDEX:
    component->type = type;
    *component->value = ((int) string[1]) - '0';
    component->size = NDN_TRUST_SCHEMA_PATTERN_COMPONENT_BUFFER_SIZE;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
    component->type = type;
    component->size = 0;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER:
    component->type = type;
    memcpy(component->value, string+1, string_size-2);
    component->size = string_size-2;
    break;
  case NDN_TRUST_SCHEMA_RULE_REF: {

    if (string_size > NDN_TRUST_SCHEMA_RULE_NAME_MAX_LENGTH) {
      return NDN_TRUST_SCHEMA_RULE_NAME_TOO_LONG;
    }

    memcpy(component->value, string, string_size-2);
    component->value[string_size-2] = '\0';
    component->type = type;
    component->size = string_size-2;

    break;
  }
  default:
    return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
  }

  return 0;

}

int
ndn_trust_schema_pattern_component_copy(const ndn_trust_schema_pattern_component_t *lhs, ndn_trust_schema_pattern_component_t *rhs)
{
  rhs->type = lhs->type;
  if (lhs->size > NDN_TRUST_SCHEMA_PATTERN_COMPONENT_BUFFER_SIZE)
    return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_INVALID_SIZE;
  memcpy(rhs->value, lhs->value, lhs->size);
  rhs->subpattern_info = lhs->subpattern_info;
  rhs->size = lhs->size;

  return 0;
}

int
ndn_trust_schema_pattern_component_compare(const ndn_trust_schema_pattern_component_t *pattern_component, const name_component_t *name_component) {

  // allocate arrays for checking wildcard specializers
  char temp_wildcard_specializer_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];
  char temp_name_component_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];

  switch (pattern_component->type) {
  case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
    return (memcmp(pattern_component->value, name_component->value, pattern_component->size) == 0 &&
	    pattern_component->size == name_component->size) ? 0 : -1;
  case NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER:
    memcpy(temp_wildcard_specializer_string_arr, pattern_component->value, pattern_component->size);
    temp_wildcard_specializer_string_arr[pattern_component->size] = '\0';
    memcpy(temp_name_component_string_arr, name_component->value, name_component->size);
    temp_name_component_string_arr[name_component->size] = '\0';
    int ret_val = re_match(temp_wildcard_specializer_string_arr, temp_name_component_string_arr);
    return (ret_val != TINY_REGEX_C_FAIL) ? 0 : -1;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
    return 0;
  case NDN_TRUST_SCHEMA_SUBPATTERN_INDEX:
  case NDN_TRUST_SCHEMA_RULE_REF:
    return -1;
  default:
    return -1;
  }
  return -1;
}
