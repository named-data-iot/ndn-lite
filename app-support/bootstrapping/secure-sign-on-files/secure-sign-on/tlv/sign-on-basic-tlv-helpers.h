/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_TLV_HELPERS_H
#define SIGN_ON_BASIC_TLV_HELPERS_H

#include "sign-on-basic-tlv-consts.h"
#include <stdint.h>
#include <stddef.h>

/**@brief Result of calling parseTlvValue
 */
static enum ParseTlvValueResultCode {
  PARSE_TLV_VALUE_SUCCESS,
  PARSING_OF_TLV_LENGTHS_LARGER_THAN_252_NOT_SUPPORTED,
  TLV_VALUE_NOT_FOUND,
} ParseTlvValueResultCode;

/**@brief Function to parse a TLV (Type-length-value) encoded block for a particular type. This function parses according to
 *          the TLV encoding rules of NDN (https://named-data.net/doc/NDN-packet-spec/current/tlv.html), but assumes that
 *          no TLV value length will ever be larger than 252 (this is to simplify parsing, as this means that all TLV lengths
 *          will be one byte).
 *
 * @param[in]   tlvBlock                   TLV encoded block to parse.
 * @param[in]   tlvBlockLength             Length of tlvBlock.
 * @param[in]   tlvTypeToFindValueOf       TLV type to parse the TLV block for.
 * @param[in]   tlvValueLength             Length of the value of the TLV type that tlvBlock was parsed for will be
 *                                           stored here, if parsing is successful.
 * @param[in]   tlvValueOffset             Offset of the value of the TLV type within tlvBlock will be stored here,
 *                                           if parsing is successful.
 *
 */
enum ParseTlvValueResultCode parseTlvValue(const uint8_t *tlvBlock, uint32_t tlvBlockLength, int tlvTypeToFindValueOf,
                        uint32_t *tlvValueLength, uint32_t *tlvValueOffset);

#endif // SIGN_ON_BASIC_TLV_HELPERS_H