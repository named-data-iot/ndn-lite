/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sign-on-basic-tlv-helpers.h"

#include "sign-on-basic-tlv-impl-consts.h"

enum ParseTlvValueResultCode parseTlvValue(const uint8_t *tlvBlock, uint16_t tlvBlockLength, int tlvTypeToFindValueOf, 
                        uint16_t *tlvValueLength, uint16_t *tlvValueOffset) {

  int i = 0;

  while (i < tlvBlockLength) {

    uint8_t currentTlvType = tlvBlock[i];
    uint8_t currentTlvLength = tlvBlock[i + SIGN_ON_BASIC_TLV_TYPE_SIZE];

    if (currentTlvLength > SIGN_ON_BASIC_MAX_TLV_LENGTH) {
      return PARSING_OF_TLV_LENGTHS_LARGER_THAN_252_NOT_SUPPORTED;
    }
    if (currentTlvType == tlvTypeToFindValueOf) {
      *tlvValueLength = currentTlvLength;
      *tlvValueOffset = i + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;
      return PARSE_TLV_VALUE_SUCCESS;
    } else {
      i += SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + currentTlvLength;
    }
  }

  return TLV_VALUE_NOT_FOUND;
}