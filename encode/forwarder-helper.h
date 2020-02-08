/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_FORWARD_HELPER_H
#define NDN_ENCODING_FORWARD_HELPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**@defgroup NDNEncode Encoding
 * @brief Encoding and decoding functions.
 */

/** @defgroup NDNEncodeFwdHelper Forwarder helper
 * @brief Some helper functions used by the forwarder.
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

/** Decode an unsigned integer value.
 *
 * @param[in] buf Buffer pointing to the value, not including T and L.
 * @param[in] buflen The length of @c buf.
 * @return The value.
 */
uint64_t
tlv_get_uint(uint8_t* buf, size_t buflen);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_FORWARD_HELPER_H