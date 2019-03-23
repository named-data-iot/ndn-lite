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

typedef struct interest_options{
  uint64_t lifetime;
  uint32_t nonce;
  uint8_t hop_limit;
  bool can_be_prefix;
  bool must_be_fresh;
}interest_options_t;

/** Get the first variable of type or length from a TLV encoded form.
 *
 * @param buf [in] The buffer containing the TLV encoded form.
 * @param buflen [in] The length of @c buf .
 * @param var [out] The decoded value.
 * @return If the function succeeds, return the size @c var takes.
 *         If the function fails, return 0.
 */
size_t
tlv_get_tlvar(uint8_t* buf, size_t buflen, uint32_t* var);

/** Get type and length from a TLV encoded form.
 *
 * @param buf [in] The buffer containing the TLV encoded form.
 * @param buflen [in] The length of @c buf .
 * @param type [out] The decoded type.
 * @param length [out] The decoded length.
 * @return If the function succeeds, return a pointer to its content.
 *         If the function fails, return NULL.
 */
uint8_t*
tlv_get_type_length(uint8_t* buf, size_t buflen, uint32_t* type, uint32_t* length);

/** Check the type and length of a TLV block.
 *
 * @param buf [in, opt] The buffer containing the TLV block.
 * @param buflen [in] The length of @c buf .
 * @param type [in] The required type.
 * @retval NDN_SUCCESS The check succeeds.
 * @retval NDN_INVALID_POINTER The @c buf is @c NULL .
 * @retval NDN_OVERSIZE_VAR Either type of length in @c buf is truncated or malicious.
 * @retval NDN_WRONG_TLV_TYPE The type of @c buf is different from @c type .
 * @retval NDN_WRONG_TLV_LENGTH The length of @c buf is different from @c length .
 */
int
tlv_check_type_length(uint8_t* buf, size_t buflen, uint32_t type);

/** Get the name and options of an Interest packet.
 *
 * @param interest [in] The Interest packet.
 * @param buflen [in] The length of @c interest .
 * @param options [out, opt] Options of @c interest .
 * @param name [out] A pointer to the name in @c interest .
 * @param name_len [out] The length of @c name .
 */
int
tlv_interest_get_header(uint8_t* interest,
                        size_t buflen,
                        interest_options_t* options,
                        uint8_t** name,
                        size_t* name_len);

/** Get the name of a Data packet.
 *
 * @param data [in] The Data packet.
 * @param buflen [in] The length of @c data .
 * @param name [out] A pointer to the name in @c data .
 * @param name_len [out] The length of @c name .
 */
int
tlv_data_get_name(uint8_t* data,
                  size_t buflen,
                  uint8_t** name,
                  size_t* name_len);

uint8_t*
tlv_interest_get_hoplimit_ptr(uint8_t* interest, size_t buflen);

#endif // NDN_ENCODING_FORWARD_HELPER_H