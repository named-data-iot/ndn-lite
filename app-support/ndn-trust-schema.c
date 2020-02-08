/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-trust-schema.h"
#include "../forwarder/forwarder.h"
#include "../encode/wrapper-api.h"
#include "../encode/signed-interest.h"
#include "../encode/key-storage.h"
#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include <stdbool.h>
#include <stdio.h>

#define ENABLE_NDN_LOG_INFO 1
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1

#include "../util/logger.h"

typedef struct {
  // the subpattern's associated name end index
  int SPE_ni;
  // the subpattern's associated name begin index
  int SPB_ni;
} subpattern_idx;

static uint8_t _pkt_buffer[256];

int
_ndn_trust_schema_on_new_schema(const uint8_t* raw_int, uint32_t raw_int_size, void* userdata)
{
  NDN_LOG_INFO("Trust Schema received new schema Interest:");
  ndn_interest_t interest;
  int ret = ndn_interest_from_block(&interest, raw_int, raw_int_size);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("Interest cannot be recognized. Error code: %d\n", ret);
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  NDN_LOG_INFO_NAME(&interest.name);
  ndn_key_storage_t* keys = ndn_key_storage_get_instance();
  ret = ndn_signed_interest_ecdsa_verify(&interest, &keys->trust_anchor_key);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("Schema Interest cannot be verified. Drop it. Error code: %d\n", ret);
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  char rule_name[32] = "";
  memcpy(rule_name, interest.name.components[interest.name.components_size - 2].value,
         interest.name.components[interest.name.components_size - 2].size);
  rule_name[interest.name.components[interest.name.components_size - 2].size] = '\0';

  ndn_decoder_t decoder;
  decoder_init(&decoder, interest.parameters.value, interest.parameters.size);
  uint32_t probe, data_str_len, key_str_len;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &data_str_len);
  const uint8_t* data_str_start = decoder.input_value + decoder.offset;
  decoder_move_forward(&decoder, data_str_len);
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &key_str_len);
  const uint8_t* key_str_start = decoder.input_value + decoder.offset;

  ndn_trust_schema_rule_t schema;
  ret = ndn_trust_schema_rule_from_strings(&schema, (const char*)data_str_start, data_str_len, (const char*)key_str_start, key_str_len);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("Schema cannot be recognized. Drop it. Error code: %d\n", ret);
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  ret = ndn_rule_storage_add_rule(rule_name, &schema);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("Schema cannot be added to the storage. Drop it. Error code: %d\n", ret);
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  NDN_LOG_INFO("Schema has been added successfully.");
  size_t used_size = 0;
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = tlv_make_data(_pkt_buffer, sizeof(_pkt_buffer), &used_size, 7,
                      TLV_DATAARG_NAME_PTR, &interest.name,
                      TLV_DATAARG_CONTENT_BUF, "200 OK",
                      TLV_DATAARG_CONTENT_SIZE, strlen("200 OK"),
                      TLV_DATAARG_FRESHNESSPERIOD_U64, (uint64_t)4000,
                      TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                      TLV_DATAARG_IDENTITYNAME_PTR, &storage->self_identity,
                      TLV_DATAARG_SIGKEY_PTR, &storage->self_identity_key);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("Schema update ack cannot be generated. Error code: %d\n", ret);
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  ret = ndn_forwarder_put_data(_pkt_buffer, used_size);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("Schema update ack cannot be sent. Error code: %d\n", ret);
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  return NDN_FWD_STRATEGY_SUPPRESS;
}

void
ndn_trust_schema_after_bootstrapping()
{
  // adding existing rules to rule storage
  ndn_trust_schema_rule_t schema;
  ndn_trust_schema_rule_from_strings(&schema, cmd_controller_only_rule_data_name, strlen(cmd_controller_only_rule_data_name),
                                     cmd_controller_only_rule_key_name, strlen(cmd_controller_only_rule_key_name));
  ndn_rule_storage_add_rule("controller-only", &schema);

  // register prefix /<home>/POLICY/<room>/<device>/rule-name
  ndn_name_t prefix_name;
  ndn_name_init(&prefix_name);
  ndn_key_storage_t* keys = ndn_key_storage_get_instance();
  ndn_name_append_component(&prefix_name, &keys->self_identity.components[0]);
  ndn_name_append_string_component(&prefix_name, "POLICY", strlen("POLICY"));
  ndn_name_append_component(&prefix_name, &keys->self_identity.components[1]);
  ndn_name_append_component(&prefix_name, &keys->self_identity.components[2]);
  NDN_LOG_INFO("About to register the prefix for policy update.")
  NDN_LOG_INFO_NAME(&prefix_name);
  int ret = ndn_forwarder_register_name_prefix(&prefix_name, _ndn_trust_schema_on_new_schema, NULL);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("Cannot register prefix to add new policies. Error code: %d\n", ret);
  }
}

int
no_wildcard_sequence_match_data_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p,
                                     int pb, int pe, subpattern_idx *subpattern_idxs)
{
  if (ne - nb != pe - pb) return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  for (int i = 0; i < ne - nb; i++) {
    if (p->components[pb + i].type !=
            NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT &&
        ndn_trust_schema_pattern_component_compare(&p->components[pb + i],
                                                   &n->components[nb + i]) != 0)
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
    if (p->components[pb + i].subpattern_info >> 6 &
        NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY)
      subpattern_idxs[p->components[pb + i].subpattern_info & 0x3F].SPB_ni =
          nb + i;
    if (p->components[pb + i].subpattern_info >> 6 &
        NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY)
      subpattern_idxs[p->components[pb + i].subpattern_info & 0x3F].SPE_ni =
          nb + i + 1;
  }
  return NDN_SUCCESS;
}

int
_index_of_key_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p, int pb, int pe,
                   const subpattern_idx *subpattern_idxs, int num_subpattern_captures,
                   const ndn_name_t *subpattern_name);

int
no_wildcard_sequence_match_key_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p,
                                    int pb, int pe, const subpattern_idx *subpattern_idxs,
                                    int num_subpattern_captures, const ndn_name_t *subpattern_name)
{
  if (p->num_subpattern_indexes == 0 && ne - nb != pe - pb)
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  int pattern_real_length = 0;
  int SPB_ni = -1, SPE_ni = -1;
  int i = 0, j = 0;
  int current_subpattern_index = 0;
  while (i < ne - nb && j < pe - pb) {
    if (p->components[pb + j].type == NDN_TRUST_SCHEMA_SUBPATTERN_INDEX) {
      current_subpattern_index = (int)*p->components[pb + j].value;
      if (current_subpattern_index >= num_subpattern_captures)
        return NDN_TRUST_SCHEMA_SUBPATTERN_INDEX_GREATER_THAN_NUMBER_OF_SUBPATTERN_CAPTURES;
      SPB_ni = subpattern_idxs[current_subpattern_index].SPB_ni;
      SPE_ni = subpattern_idxs[current_subpattern_index].SPE_ni;
      if (ndn_name_compare_sub_names(n, nb + i, nb + i + SPE_ni - SPB_ni, subpattern_name, SPB_ni, SPE_ni) != 0) {
        return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
      }
      pattern_real_length += SPE_ni - SPB_ni;
      i += pattern_real_length;
      j++;
    }
    else if (p->components[pb + j].type != NDN_TRUST_SCHEMA_SUBPATTERN_INDEX
             && p->components[pb + j].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT
             && ndn_trust_schema_pattern_component_compare(&p->components[pb + j], &n->components[nb + i]) != 0) {
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
    }
    else {
      pattern_real_length++;
      i++;
      j++;
    }
  }
  if (j < pe - pb || i < ne - nb) return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  return NDN_SUCCESS;
}

int
_index_of_data_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p,
                    int pb, int pe, subpattern_idx *subpattern_idxs)
{
  for (int i = nb; i < ne; i++) {
    if (i + pe - pb <= ne
        && no_wildcard_sequence_match_data_name(n, i, i + pe - pb, p, pb, pe, subpattern_idxs) == 0) {
      return i;
    }
  }
  return -1;
}

int
_index_of_key_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p, int pb, int pe,
                   const subpattern_idx *subpattern_idxs, int num_subpattern_captures, const ndn_name_t *subpattern_name)
{
  for (int i = nb; i < ne; i++) {
    if (i + pe - pb <= ne
        && no_wildcard_sequence_match_key_name(n, i, i + pe - pb, p, pb, pe, subpattern_idxs,
                                               num_subpattern_captures, subpattern_name) == 0) {
      return i;
    }
  }
  return -1;
}

int
_check_data_name_against_pattern(const ndn_trust_schema_pattern_t *pattern, const ndn_name_t *name,
                                 subpattern_idx *subpattern_idxs)
{
  if (pattern->components_size == 0 && name->components_size == 0) {
    return NDN_SUCCESS;
  }

  int pb = index_of_pattern_component_type(
      pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE);

  if (pb < 0) {
    return no_wildcard_sequence_match_data_name(
        name, 0, name->components_size, pattern, 0, pattern->components_size,
        subpattern_idxs);
  }

  int pe = last_index_of_pattern_component_type(pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) + 1;
  int nb = pb;
  int ne = name->components_size - (pattern->components_size - pe);

  if (nb > ne) return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  if (no_wildcard_sequence_match_data_name(name, 0, nb, pattern, 0, pb, subpattern_idxs) != 0
      || no_wildcard_sequence_match_data_name(name, ne, name->components_size, pattern, pe,
                                              pattern->components_size, subpattern_idxs) != 0) {
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  }

  bool found_SPE = false;
  int last_SPE_pattern_idx = -1;
  for (int i = pb; i < pe; i++) {
    while (i < pe && pattern->components[i].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
      if (pattern->components[i].subpattern_info >> 6 &
          NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY) {
        subpattern_idxs[pattern->components[i].subpattern_info & 0x3F].SPB_ni =
            nb;
      }
      if (pattern->components[i].subpattern_info >> 6 &
          NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY) {
        found_SPE = true;
        last_SPE_pattern_idx = i;
      }
      i++;
      pb = i;
    }
    if (i == pe) {
      if (found_SPE)
        subpattern_idxs
            [pattern->components[last_SPE_pattern_idx].subpattern_info & 0x3F]
                .SPE_ni = ne;
      return NDN_SUCCESS;
    }
    while (i < pe && pattern->components[i].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)
      i++;
    int j = _index_of_data_name(name, nb, ne, pattern, pb, i, subpattern_idxs);
    if (j == -1) {
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
    }
    if (found_SPE) {
      subpattern_idxs[pattern->components[last_SPE_pattern_idx].subpattern_info & 0x3F].SPE_ni = j;
      found_SPE = false;
    }
    nb = j + i - pb;
    pb = i + 1;
  }
  return NDN_SUCCESS;
}

int
_check_key_name_against_pattern(const ndn_trust_schema_pattern_t *pattern, const ndn_name_t *name,
                                const subpattern_idx *subpattern_idxs, const ndn_name_t *subpattern_name,
                                size_t num_subpattern_captures)
{
  if (pattern->components_size == 0 && name->components_size == 0) {
    return NDN_SUCCESS;
  }

  int pb = index_of_pattern_component_type(
      pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE);

  if (pb < 0) {
    return no_wildcard_sequence_match_key_name(
        name, 0, name->components_size, pattern, 0, pattern->components_size,
        subpattern_idxs, num_subpattern_captures, subpattern_name);
  }

  int pe = last_index_of_pattern_component_type(pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) + 1;
  int nb = pb;
  int ne = name->components_size - (pattern->components_size - pe);

  if (nb > ne) return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  if (no_wildcard_sequence_match_key_name(name, 0, nb, pattern, 0, pb, subpattern_idxs,
                                          num_subpattern_captures, subpattern_name) != 0
      || no_wildcard_sequence_match_key_name(name, ne, name->components_size, pattern, pe,
                                             pattern->components_size, subpattern_idxs, num_subpattern_captures,
                                             subpattern_name) != 0) {
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  }

  for (int i = pb; i < pe; i++) {
    while (i < pe && pattern->components[i].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
      i++;
      pb = i;
    }
    if (i == pe) return NDN_SUCCESS;
    while (i < pe && pattern->components[i].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)
      i++;
    int j = _index_of_key_name(name, nb, ne, pattern, pb, i, subpattern_idxs,
                               num_subpattern_captures, subpattern_name);
    if (j == -1) {
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
    }
    nb = j + i - pb;
    pb = i + 1;
  }
  return NDN_SUCCESS;
}

int ndn_trust_schema_verify_data_name_key_name_pair(
    const ndn_trust_schema_rule_t *rule, const ndn_name_t *data_name,
    const ndn_name_t *key_name) {
  int ret_val = -1;

  subpattern_idx data_name_subpattern_idxs[rule->data_pattern.num_subpattern_captures];
  ret_val = _check_data_name_against_pattern(&rule->data_pattern, data_name, data_name_subpattern_idxs);
  if (ret_val != NDN_SUCCESS) {
    return ret_val;
  }

  if (rule->key_pattern.components[0].type == NDN_TRUST_SCHEMA_RULE_REF) {
    const char *rule_name = (const char *)rule->key_pattern.components[0].value;

    const ndn_trust_schema_rule_t *rule_ref;
    rule_ref = ndn_rule_storage_get_rule(rule_name);
    if (rule_ref == NULL) return NDN_TRUST_SCHEMA_RULE_REF_NOT_FOUND;

    if (rule_ref->data_pattern.num_subpattern_captures !=
        rule->data_pattern.num_subpattern_captures)
      return NDN_TRUST_SCHEMA_RULE_REF_UNEQUAL_NUM_OF_SUBPATTERN_CAPTURES;

    printf("Rule reference not implemented yet.\n");

    return NDN_TRUST_SCHEMA_RULE_REFERENCING_NOT_IMPLEMENTED_YET;
  }
  else {
    return _check_key_name_against_pattern(
        &rule->key_pattern, key_name, data_name_subpattern_idxs, data_name,
        rule->data_pattern.num_subpattern_captures);
  }
}
