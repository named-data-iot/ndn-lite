/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

// This file supplies temporary functions since new encoder is not there.
#ifndef NDN_ENCODING_FORWARD_HELPER_H
#define NDN_ENCODING_FORWARD_HELPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "name.h"

/**@defgroup NDNEncode Encoding
 * @brief Encoding and decoding functions.
 */

/** @defgroup NDNEncodeFwdHelper Forwarder helper
 * @brief Some helper functions and easy-to-use wrapping API.
 * @ingroup NDNEncode
 * @{
 */

/**
 * Interest options which the forwarder cares.
 * 
 * Currently only used in the forwarder.
 */
typedef struct interest_options{
  uint64_t lifetime;
  uint32_t nonce;
  uint8_t hop_limit;
  bool can_be_prefix;
  bool must_be_fresh;
}interest_options_t;

/** Get the first variable of type or length from a TLV encoded form.
 *
 * @param[in] buf The buffer containing the TLV encoded form.
 * @param[in] buflen The length of @c buf.
 * @param[out] var The decoded value.
 * @return If the function succeeds, return the size @c var takes.
 *         If the function fails, return 0.
 */
size_t
tlv_get_tlvar(uint8_t* buf, size_t buflen, uint32_t* var);

/** Get type and length from a TLV encoded form.
 *
 * @param[in] buf The buffer containing the TLV encoded form.
 * @param[in] buflen The length of @c buf.
 * @param[out] type The decoded type.
 * @param[out] length The decoded length.
 * @return If the function succeeds, return a pointer to its content.
 *         If the function fails, return @c NULL.
 */
uint8_t*
tlv_get_type_length(uint8_t* buf, size_t buflen, uint32_t* type, uint32_t* length);

/** Check the type and length of a TLV block.
 *
 * @param[in] buf [Optional] The buffer containing the TLV block.
 * @param[in] buflen The length of @c buf.
 * @param[in] type The required type.
 * @retval #NDN_SUCCESS The check succeeds.
 * @retval #NDN_INVALID_POINTER The @c buf is @c NULL.
 * @retval #NDN_OVERSIZE_VAR Either type of length in @c buf is truncated or malicious.
 * @retval #NDN_WRONG_TLV_TYPE The type of @c buf is different from @c type.
 * @retval #NDN_WRONG_TLV_LENGTH The length of @c buf is different from @c length.
 * @note This function will kindly check <tt>buf != NULL</tt>.
 */
int
tlv_check_type_length(uint8_t* buf, size_t buflen, uint32_t type);

/** Get the name and options of an Interest packet.
 *
 * @param[in] interest The Interest packet.
 * @param[in] buflen The length of @c interest.
 * @param[out] options [Optional] Options of @c interest.
 * @param[out] name A pointer to the name in @c interest.
 * @param[out] name_len The length of @c name.
 * @retval #NDN_SUCCESS The operation succeeds.
 * @retval #NDN_OVERSIZE_VAR Either type of length in @c buf is truncated or malicious.
 * @retval #NDN_WRONG_TLV_TYPE The type of @c buf is not #TLV_Interest.
 * @retval #NDN_WRONG_TLV_LENGTH The length of @c buf is different from @c length.
 * @retval #NDN_UNSUPPORTED_FORMAT The first element of @c interest is not #TLV_Name.
 */
int
tlv_interest_get_header(uint8_t* interest,
                        size_t buflen,
                        interest_options_t* options,
                        uint8_t** name,
                        size_t* name_len);

/** Get the name of a Data packet.
 *
 * @param[in] data The Data packet.
 * @param[in] buflen The length of @c data.
 * @param[out] name A pointer to the name in @c data.
 * @param[out] name_len The length of @c name.
* @retval #NDN_SUCCESS The operation succeeds.
 * @retval #NDN_OVERSIZE_VAR Either type of length in @c buf is truncated or malicious.
 * @retval #NDN_WRONG_TLV_TYPE The type of @c buf is not #TLV_Data.
 * @retval #NDN_WRONG_TLV_LENGTH The length of @c buf is different from @c length.
 * @retval #NDN_UNSUPPORTED_FORMAT The first element of @c interest is not #TLV_Name.
 */
int
tlv_data_get_name(uint8_t* data,
                  size_t buflen,
                  uint8_t** name,
                  size_t* name_len);

/** Get the pointer to hop limit field of a Interest packet.
 *
 * @param[in] interest The Interest packet.
 * @param[in] buflen The length of @c interest.
 * @return If the function succeeds, return a pointer to the hop limit.
 *         If @c interest doesn't contain a hop limit field, return @c NULL.
 * @pre #tlv_interest_get_header should succeed for @c interest.
 */
uint8_t*
tlv_interest_get_hoplimit_ptr(uint8_t* interest, size_t buflen);

// Xinyu Ma: It's very hard to write a elegant encoding/decoding part
// I don't think I can make it within one year
// So I decide to create a all-in-one API so you can change the
// backend in any way without spoiling the interface.

/**
 * The type of variant args of #tlv_make_data.
 */
enum TLV_MAKEDATA_ARG_TYPE{
  /**
   * A pointer to a name.
   *
   * Type: #ndn_name_t* @n
   * At least one Name is necessary, otherwise #NDN_INVALID_ARG is returned.
   * If multiple names are specified by mistake, the last one is used.
   */
  TLV_MAKEDATA_NAME_PTR,

  /**
   * A pointer to an encoded TLV name.
   *
   * Type: @c uint8_t* @n
   * It will automaticaly detect the length.
   */
  TLV_MAKEDATA_NAME_BUF,

  /**
   * Segment number.
   *
   * Type: @c uint64_t @n
   * It will be added after name.
   */
  TLV_MAKEDATA_NAME_SEGNO_U64,

  /**
   * Content type.
   *
   * Type: @c uint8_t promoted to @c uint32_t
   */
  TLV_MAKEDATA_CONTENTTYPE_U8,

  /**
   * Freshness period.
   *
   * Type: @c uint64_t
   */
  TLV_MAKEDATA_FRESHNESSPERIOD_U64,

  /**
   * A pointer to a final block id.
   *
   * Type: #name_component_t*
   */
  TLV_MAKEDATA_FINALBLOCKID_PTR,

  /**
   * A pointer to an encoded final block id.
   *
   * Type: @c uint8_t* @n
   * It will automaticaly detect the length.
   */
  TLV_MAKEDATA_FINALBLOCKID_BUF,

  /**
   * A pointer to a final block id, in form of segment number.
   *
   * Type: @c uint64_t
   */
  TLV_MAKEDATA_FINALBLOCKID_U64,

  /**
   * Payload.
   *
   * Type: @c uint8_t*
   */
  TLV_MAKEDATA_CONTENT_BUF,

  /**
   * The size of @c content.
   *
   * Type: @c size_t
   */
  TLV_MAKEDATA_CONTENT_SIZE,

  /**
   * Signature type.
   *
   * Type: @c uint8_t promoted to @c uint32_t @n
   * By default, #NDN_SIG_TYPE_DIGEST_SHA256 is used.
   */
  TLV_MAKEDATA_SIGTYPE_U8,

  /**
   * A pointer to the name of identity.
   *
   * Type: #ndn_name_t*
   */
  TLV_MAKEDATA_IDENTITYNAME_PTR,

  /**
   * A pointer to the key.
   *
   * Type: #ndn_ecc_prv_t* or #ndn_hmac_key_t* @n
   * Not necessary for #NDN_SIG_TYPE_DIGEST_SHA256.
   */
  TLV_MAKEDATA_KEY_PTR,

  /**
   * The signature timestamp.
   *
   * Type: @c uint64_t
   */
  TLV_MAKEDATA_SIGTIME_U64,
};

/** All-in-one function to generate a Data packet.
 *
 * This function uses variant args to input optional parameters.
 * The value of each variant arg should be given after its type.
 * See #TLV_MAKEDATA_ARG_TYPE for all supported variant arg types.
 * An example:
 * @code{.c}
 * tlv_make_data(buf, sizeof(buf), &output_size, 6, // 6 args following
 *               TLV_MAKEDATA_NAME_PTR,            &name,
 *               TLV_MAKEDATA_NAME_SEGNO_U64,      (uint64_t)i
 *               TLV_MAKEDATA_FRESHNESSPERIOD_U64, (uint64_t)15000,
 *               TLV_MAKEDATA_FINALBLOCKID_U64,    (uint64_t)(seg_count - 1),
 *               TLV_MAKEDATA_CONTENT_BUF,         content,
 *               TLV_MAKEDATA_CONTENT_SIZE,        sizeof(content));
 * // Create a Data packet with its payload = content,
 * // name = name + i (segment number), freshness period = 15s.
 * // And the data have seg_count segments in total.
 * @endcode
 * @param[out] buf The buffer where Data is stored. @c buflen bytes are written.
 * @param[in] buflen The available size of @c buf.
 * @param[out] result_size [Optional] The encoded size of the Data packet.
 * @param[in] argc The number of variant args, without counting the type.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_INVALID_ARG An unknown argument is given; or no name is given.
 * @retval #NDN_SEC_UNSUPPORT_SIGN_TYPE Unsupported signature type.
 * @retval #NDN_INVALID_POINTER A non-optional pointer argument is @c NULL.
 *                              Notice that some arguments are allowed to be @c NULL.
 * @post <tt>result_size <= buflen</tt>
 */
int
tlv_make_data(uint8_t* buf, size_t buflen, size_t* result_size, int argc, ...);

/*@}*/

#endif // NDN_ENCODING_FORWARD_HELPER_H