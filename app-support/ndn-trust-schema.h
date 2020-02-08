/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_TRUST_SCHEMA_H
#define NDN_TRUST_SCHEMA_H

#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include "../encode/name.h"
#include "../util/re.h"
#include "../encode/trust-schema/ndn-trust-schema-rule.h"
#include "../encode/ndn-rule-storage.h"
#include <string.h>

/** Controller Only Command Policy
 */
#define cmd_controller_only_rule_data_name "(<>)<><CMD><>*"
#define cmd_controller_only_rule_key_name "\\0<KEY><>"

/** Same Room Only Command Policy
 */
#define cmd_same_room_rule_data_name "(<>)<><CMD>(<>)<>*"
#define cmd_same_room_rule_key_name "\\0<>\\1<><KEY><>"

/** Same Producer Content Policy
 */
#define content_same_producer_rule_data_name "(<>)(<>)<DATA>(<>)(<>)<>*"
#define content_same_producer_rule_key_name "\\0\\1\\2\\3<KEY><>"

/**
 * Register a prefix to listen to /<home>/POLICY/<room>/<device>/rule-name
 * If new content and can be verified, add it to the rule storage
 */
void
ndn_trust_schema_after_bootstrapping();

/**
 * Verify that a key name matches a data name based on a trust schema pattern.
 * @param rule. Output. The NDN Trust Schema rule to be used in verifying the data name and key name pair.
 * @param data_name. Input. The data name which will be checked against the key name based on the pattern.
 * @param key_name. Input. The name of the key to check the validity of based on the pattern.
 * @return 0 if the key's name is valid for the data's name given the trust schema pattern.
 */
int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule,
                                                const ndn_name_t* data_name,
                                                const ndn_name_t* key_name);

#endif // NDN_TRUST_SCHEMA_H
