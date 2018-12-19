/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_TLV_IMPL_CONSTS_H
#define SIGN_ON_BASIC_TLV_IMPL_CONSTS_H

#define SIGN_ON_BASIC_TLV_TYPE_SIZE 1 ///< parseTlvValue assumes that the TLV type will be one byte
#define SIGN_ON_BASIC_TLV_LENGTH_SIZE 1 ///< parseTlvValue assumes that the TLV length will be one byte
#define SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE (SIGN_ON_BASIC_TLV_TYPE_SIZE + SIGN_ON_BASIC_TLV_LENGTH_SIZE)
#define SIGN_ON_BASIC_MAX_TLV_LENGTH 252 ///< parseTlvValue assumes that no TLV length will assume 252 bytes

#endif // SIGN_ON_BASIC_TLV_IMPL_CONSTS_H