/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-trust-schema-pattern.h"
#include <stdbool.h>
#include <stdio.h>

int
ndn_trust_schema_pattern_from_string(ndn_trust_schema_pattern_t* pattern,
                                     const char* string, uint32_t size)
{
  if (size == 0) return NDN_TRUST_SCHEMA_PATTERN_STRING_ZERO_LENGTH;

  if (string[size - 1] == '\0') size--;

  for (uint32_t i = 0; i < size - 1; i++) {
    if (string[i] == '\0')
      return NDN_TRUST_SCHEMA_PATTERN_STRING_PREMATURE_TERMINATION;
  }

  int ret_val = -1;

  pattern->components_size = 0;

  // first check if it's a rule reference
  if (string[0] != '<' && string[0] != '(' && string[0] != '['
      && string[0] != '\\') {
    ndn_trust_schema_pattern_component_t component;
    ret_val = ndn_trust_schema_pattern_component_from_string(&component, string, size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;
    return 0;
  }

  // flag to remember whether the pattern component being appended should be
  // marked as the beginning of a subpattern (SPB = Sub Pattern Beginning)
  bool should_add_SPB = false;
  // current subpattern index; will return error if more than
  // NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES subpatterns are found
  uint8_t current_subpattern_capture_begin_index = 0;
  uint8_t current_subpattern_capture_end_index = 0;
  const char* current_string = string;
  uint32_t last_type = NDN_TRUST_SCHEMA_NO_TYPE;
  uint32_t current_type = NDN_TRUST_SCHEMA_NO_TYPE;
  uint8_t num_subpattern_indexes = 0;
  // iterate through the schema pattern
  while ((uint32_t)(current_string - string) < size) {
    int pattern_comp_end_index = -1;
    switch (current_string[0]) {
      case '<':
        pattern_comp_end_index = re_match("^<>\\*", current_string);
        if (pattern_comp_end_index == TINY_REGEX_C_FAIL) {
          pattern_comp_end_index = re_match(">", current_string);
          if (pattern_comp_end_index == TINY_REGEX_C_FAIL)
            return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
          else
            current_type = (pattern_comp_end_index == 2)
                               ? NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT
                               : NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT;
        } else {
          current_type = NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE;
          pattern_comp_end_index += 2;
        }
        break;
      case '[':
        pattern_comp_end_index = re_match("]", current_string);
        if (pattern_comp_end_index == TINY_REGEX_C_FAIL)
          return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
        else
          current_type = NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER;
        break;
      case '\\':
        pattern_comp_end_index = re_match("[0-9]", current_string);
        if (pattern_comp_end_index == TINY_REGEX_C_FAIL)
          return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
        else
          current_type = NDN_TRUST_SCHEMA_SUBPATTERN_INDEX;
        num_subpattern_indexes++;
        break;
      case '(':
        // make sure that there is a corresponding end parentheses for this
        // subpattern
        pattern_comp_end_index = re_match(")", current_string);
        if (pattern_comp_end_index == TINY_REGEX_C_FAIL)
          return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
        should_add_SPB = true;
        current_string += 1;
        continue;
      case ')':
        // set the last pattern component's subpattern info to indicate that it
        // was the ending of a subpattern
        pattern->components[pattern->components_size - 1].subpattern_info |=
            (NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY << 6) |
            (current_subpattern_capture_end_index);
        current_subpattern_capture_end_index++;
        current_string += 1;
        continue;
      default:
        if (current_string[0] == '\0')
          break;
        else
          return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }

    // do not allow more than one consecutive wildcard name component sequences
    if (current_type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE
        && last_type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)
      return NDN_TRUST_SCHEMA_PATTERN_INVALID_FORMAT;
    last_type = current_type;

    int pattern_comp_string_len = pattern_comp_end_index + 1;

    ndn_trust_schema_pattern_component_t component;
    component.subpattern_info = 0;
    ret_val = ndn_trust_schema_pattern_component_from_string(
        &component, current_string, pattern_comp_string_len);
    if (ret_val != NDN_SUCCESS) return ret_val;

    if (should_add_SPB) {
      // set the current pattern component's subpattern info to indicate that it
      // was the beginning of a subpattern
      component.subpattern_info |=
          (NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY << 6) |
          (current_subpattern_capture_begin_index);
      current_subpattern_capture_begin_index++;
      if (current_subpattern_capture_begin_index + 1 >
          NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES) {
        return NDN_TRUST_SCHEMA_NUMBER_OF_SUBPATTERNS_EXCEEDS_LIMIT;
      }
      should_add_SPB = false;
    }

    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;

    current_string += pattern_comp_end_index + 1;
  }

  if (current_subpattern_capture_begin_index !=
      current_subpattern_capture_end_index) {
    return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
  }

  pattern->num_subpattern_captures = current_subpattern_capture_begin_index;
  pattern->num_subpattern_indexes = num_subpattern_indexes;

  return 0;
}

int
ndn_trust_schema_pattern_copy(const ndn_trust_schema_pattern_t* lhs,
                              ndn_trust_schema_pattern_t* rhs)
{
  rhs->components_size = lhs->components_size;
  rhs->num_subpattern_captures = lhs->num_subpattern_captures;
  rhs->num_subpattern_indexes = lhs->num_subpattern_indexes;

  int ret_val = -1;
  for (uint32_t i = 0; i < lhs->components_size; i++) {
    ret_val = ndn_trust_schema_pattern_component_copy(&lhs->components[i],
                                                      &rhs->components[i]);
    if (ret_val != 0) return ret_val;
  }

  return 0;
}

int
index_of_pattern_component_type(const ndn_trust_schema_pattern_t* pattern, uint32_t type)
{
  if (pattern->components_size == 0) return -1;

  for (uint32_t i = 0; i < pattern->components_size; i++) {
    if (pattern->components[i].type == type) return i;
  }

  return -1;
}

int
last_index_of_pattern_component_type(const ndn_trust_schema_pattern_t* pattern, uint32_t type)
{
  if (pattern->components_size == 0) return -1;

  for (int i = (int)((int)pattern->components_size - 1); i >= 0; i--) {
    if (pattern->components[i].type == type) return i;
  }

  return -1;
}
