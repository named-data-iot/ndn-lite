/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_TRUST_SCHEMA_PATTERN_H
#define NDN_TRUST_SCHEMA_PATTERN_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "ndn-trust-schema-pattern-component.h"

#include "../../ndn-constants.h"
#include "../../ndn-error-code.h"

/**
 * The structure to represent the NDN Trust Schema pattern.
 * This structure is memory expensive so please be careful when using it.
 */
typedef struct ndn_trust_schema_pattern {
  /**
   * The array of schema components contained in this schema pattern (not including T and L)
   */
  ndn_trust_schema_pattern_component_t components[NDN_TRUST_SCHEMA_PATTERN_COMPONENTS_SIZE];
  /**
   * The number of schema components
   */
  uint32_t components_size;
  /**
   * The number of subpattern captures in the schema pattern.
   */
  uint8_t num_subpattern_captures;
  /**
   * The number of subpattern indexes in the schema pattern.
   */
  uint8_t num_subpattern_indexes;
} ndn_trust_schema_pattern_t;

/**
 * Appends a component to the end of a pattern. This function will do memory copy.
 * @param name. Output. The pattern to append to.
 * @param component. Input. The name component to append with.
 * @return 0 if there is no error.
 */
static inline int
ndn_trust_schema_pattern_append_component(ndn_trust_schema_pattern_t *pattern, const ndn_trust_schema_pattern_component_t* component)
{
  if (pattern->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(pattern->components + pattern->components_size, component, sizeof(ndn_trust_schema_pattern_component_t));
    pattern->components_size++;

    return 0;
  }
  else
    return NDN_OVERSIZE;
}

/**
 * Init an NDN Trust Schema pattern from a string. This function will do memory copy and
 * only support regular string; not support URI currently.
 * @param pattern. Output. The NDN Trust Schema pattern to be inited.
 * @param string. Input. The string from which the NDN Trust Schema pattern is inited.
 * @param size. Input. Size of the input string.
 * @return 0 if there is no error.
 */
int
ndn_trust_schema_pattern_from_string(ndn_trust_schema_pattern_t* pattern, const char* string, uint32_t size);

/**
 * Copy the lhs pattern to the rhs pattern.
 * @param lhs. Input. The pattern to be copied.
 * @param rhs. Output. The pattern that will be copied to.
 * @return 0 if there is no error.
 */
int
ndn_trust_schema_pattern_copy(const ndn_trust_schema_pattern_t *lhs, ndn_trust_schema_pattern_t *rhs);


/**
 * Find the first index in a trust schema pattern of a particular type.
 * @param pattern. Input. The NDN Trust Schema pattern to be parsed.
 * @param type. Input. The pattern component type to search for.
 * @return Index of first pattern component of given type if successfully found, -1 otherwise.
 */
int
index_of_pattern_component_type(const ndn_trust_schema_pattern_t* pattern, uint32_t type);

/**
 * Find the last index in a trust schema pattern of a particular type.
 * @param pattern. Input. The NDN Trust Schema pattern to be parsed.
 * @param type. Input. The pattern component type to search for.
 * @return Index of last pattern component of given type if successfully found, -1 otherwise.
 */
int
last_index_of_pattern_component_type(const ndn_trust_schema_pattern_t* pattern, uint32_t type);

#endif // NDN_TRUST_SCHEMA_PATTERN_H
