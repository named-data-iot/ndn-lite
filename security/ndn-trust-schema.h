
#ifndef NDN_TRUST_SCHEMA_H
#define NDN_TRUST_SCHEMA_H

#include <string.h>

#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include "../encode/name.h"

#include "../util/re.h"

#include "../encode/trust-schema/ndn-trust-schema-rule.h"

/**
 * Verify that a key name matches a data name based on a trust schema pattern.
 * @param rule. Output. The NDN Trust Schema rule to be used in verifying the data name and key name pair.
 * @param data_name. Input. The data name which will be checked against the key name based on the pattern.
 * @param key_name. Input. The name of the key to check the validity of based on the pattern.
 * @return 0 if the key's name is valid for the data's name given the trust schema pattern.
 */
int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name);

#endif // NDN_TRUST_SCHEMA_H
