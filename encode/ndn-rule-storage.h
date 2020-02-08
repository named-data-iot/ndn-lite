/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_RULE_STORAGE_H
#define NDN_RULE_STORAGE_H

#include "trust-schema/ndn-trust-schema-rule.h"
#include "../ndn-constants.h"

typedef struct {
  char name[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_BUFFER_SIZE];
} ndn_rule_name_t;

typedef struct {
  ndn_trust_schema_rule_t rule_objects[NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES];
  ndn_rule_name_t rule_names[NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES];
} ndn_rule_storage_t;

/**@brief There should be only one ndn_rule_storage_t. Use this function
 *          to get the singleton instance. If the instance has not been initialized,
 *          call ndn_rule_storage_init first.
 */
ndn_rule_storage_t*
ndn_rule_storage_get_instance(void);

/**
 * Init the rule storage singleton. This function will clear the rule storage.
 */
void
ndn_rule_storage_init(void);

/**
 * Get a rule from the rule storage.
 * @param rule_name. Input. The string representing the name of the rule to get from storage.
 * @return A pointer to the rule if it is found in storage. NULL otherwise.
 */
const ndn_trust_schema_rule_t *
ndn_rule_storage_get_rule(const char *rule_name);

/**
 * Add a rule to the rule storage. Will do a deep copy of the rule passed in.
 * @param rule_name. Input. The string to associate with the rule added. The storage will not allow
 *                          the adding of a rule with the same name as one already in storage.
 * @param rule. Input. The rule that will be deep copied into the rule storage.
 * @return 0 if the rule is successfully added.
 */
int
ndn_rule_storage_add_rule(const char* rule_name, const ndn_trust_schema_rule_t *rule);

/**
 * Remove a rule from the rule storage.
 * @param rule_name. Input. The name of the rule to remove.
 * @return NDN_SUCCESS if the rule corresponding to rule_name is successfully removed or there is no rule found
 */
int
ndn_rule_storage_remove_rule(const char* rule_name);

#endif // NDN_RULE_STORAGE_H
