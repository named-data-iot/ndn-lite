/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-rule-storage.h"

static ndn_rule_storage_t ndn_rule_storage;

// returns 0 if buffer contained only zeros
int _check_buffer_all_zeros(const uint8_t *buf, int buf_size) {
  int sum = 0;
  for (int i = 0; i < buf_size; i++) {
    sum |= buf[i];
  }
  return sum;
}

ndn_rule_storage_t*
ndn_rule_storage_get_instance(void) {
  return &ndn_rule_storage;
}

void
ndn_rule_storage_init(void) {
  for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
    memset(&ndn_rule_storage.rule_objects[i], 0, sizeof(ndn_trust_schema_rule_t));
    ndn_rule_storage.rule_names[i].name[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_BUFFER_SIZE-1] = '\0';
  }
}

const ndn_trust_schema_rule_t *
ndn_rule_storage_get_rule(const char *rule_name) {
  for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
    if (strcmp((const char *)&ndn_rule_storage.rule_names[i].name, rule_name) == 0 &&
	strlen((const char *)&ndn_rule_storage.rule_names[i].name) == strlen(rule_name)) {
      return &ndn_rule_storage.rule_objects[i];
    }
  }
  return NULL;
}

int
ndn_rule_storage_add_rule(const char* rule_name, const ndn_trust_schema_rule_t *rule)
{
  int ret_val = -1;
  int empty_index = -1;
  ndn_rule_storage_remove_rule(rule_name);
  for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
    if (_check_buffer_all_zeros((uint8_t *) &ndn_rule_storage.rule_objects[i], sizeof(ndn_trust_schema_rule_t)) == 0) {
      empty_index = i;
    }
  }

  if (empty_index == -1)
    return NDN_TRUST_SCHEMA_RULE_STORAGE_FULL;

  ret_val = ndn_trust_schema_rule_copy(rule, &ndn_rule_storage.rule_objects[empty_index]);
  if (ret_val != 0) return ret_val;
  if (strlen(rule_name) > NDN_TRUST_SCHEMA_RULE_NAME_MAX_LENGTH)
    return NDN_TRUST_SCHEMA_RULE_NAME_TOO_LONG;
  memcpy(&ndn_rule_storage.rule_names[empty_index].name, rule_name, strlen(rule_name));
  ndn_rule_storage.rule_names[empty_index].name[strlen(rule_name)] = '\0';
  return NDN_SUCCESS;
}

int
ndn_rule_storage_remove_rule(const char *rule_name)
{
  for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
    if (strcmp((const char *)&ndn_rule_storage.rule_names[i].name, rule_name) == 0
        && strlen((const char *)&ndn_rule_storage.rule_names[i].name) == strlen(rule_name)) {
      memset(&ndn_rule_storage.rule_objects[i], 0, sizeof(ndn_trust_schema_rule_t));
      ndn_rule_storage.rule_names[i].name[0] = '\0';
      return NDN_SUCCESS;
    }
  }
  return NDN_SUCCESS;
}
