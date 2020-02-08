/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_WRAPPER_API_H
#define NDN_ENCODING_WRAPPER_API_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "name.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNEncodeWrapperAPI Wrapper API
 * @brief High-level wrapper APIs providing convenience
 * @ingroup NDNEncode
 * @{
 */

/**
 * The type of variant args of #tlv_make_data and #tlv_parse_data.
 */
enum TLV_DATAARG_TYPE{
  /**
   * A pointer to a name.
   *
   * make_data: [in] #ndn_name_t* @n
   * At least one Name is necessary, otherwise #NDN_INVALID_ARG is returned.
   * If multiple names are specified by mistake, the last one is used.
   *
   * parse_data: [out] #ndn_name_t*
   */
  TLV_DATAARG_NAME_PTR,

  /**
   * A pointer to an encoded TLV name.
   *
   * make_data: [in] @c uint8_t* @n
   * It will automaticaly detect the length.
   *
   * parse_data: [out] @c uint8_t** @n
   * Output a pointer to where the name starts in @c buf.
   */
  TLV_DATAARG_NAME_BUF,

  /**
   * Segment number.
   *
   * make_data: [in] @c uint64_t @n
   * It will be added after name.
   *
   * parse_data: [out] @c uint64_t* @n
   * Output (uint64_t)-1 if the last component is not segment number.
   */
  TLV_DATAARG_NAME_SEGNO_U64,

  /**
   * Content type.
   *
   * make_data: [in] @c uint8_t (promoted)
   *
   * parse_data: [out] @c uint8_t* @n
   * Output 0xFF if not included in the packet.
   */
  TLV_DATAARG_CONTENTTYPE_U8,

  /**
   * Freshness period.
   *
   * make_data: [in] @c uint64_t
   *
   * parse_data: [out] @c uint64_t* @n
   * Output 0 if not included in the packet.
   */
  TLV_DATAARG_FRESHNESSPERIOD_U64,

  /**
   * A pointer to a final block id.
   *
   * make_data: [in] #name_component_t*
   *
   * parse_data: [out] #name_component_t* @n
   * Output <tt>size=0</tt> if not included.
   */
  TLV_DATAARG_FINALBLOCKID_PTR,

  /**
   * A pointer to an encoded final block id.
   *
   * make_data: [in] @c uint8_t* @n
   * It will automaticaly detect the length.
   *
   * parse_data: [out] @c uint8_t** @n
   * Output a pointer to where the FinalBlockId starts in @c buf.
   * @c NULL if not included.
   */
  TLV_DATAARG_FINALBLOCKID_BUF,

  /**
   * A pointer to a final block id, in form of segment number.
   *
   * make_data: [in] @c uint64_t
   *
   * parse_data: [out] @c uint64_t* @n
   * If it fails, (uint64_t)-1 will be set.
   */
  TLV_DATAARG_FINALBLOCKID_U64,

  /**
   * Payload.
   *
   * make_data: [in, opt] @c uint8_t*
   *
   * parse_data: [out] @c uint8_t** @n
   * Output a pointer to where the Content starts in @c buf.
   * @c NULL if not included.
   */
  TLV_DATAARG_CONTENT_BUF,

  /**
   * The size of @c content.
   *
   * make_data: [in] @c size_t
   *
   * parse_data: [out] @c size_t*
   */
  TLV_DATAARG_CONTENT_SIZE,

  /**
   * Signature type.
   *
   * make_data: [in] @c uint8_t (promoted) @n
   * By default, #NDN_SIG_TYPE_DIGEST_SHA256 is used.
   *
   * parse_data: [out] @c uint8_t*
   */
  TLV_DATAARG_SIGTYPE_U8,

  /**
   * A pointer to the name of identity.
   *
   * make_data: [in, opt] #ndn_name_t*
   *
   * parse_data: N/A
   */
  TLV_DATAARG_IDENTITYNAME_PTR,

  /**
   * A pointer to the key.
   *
   * make_data: [in, opt] #ndn_ecc_prv_t* or #ndn_hmac_key_t* @n
   * Not necessary for #NDN_SIG_TYPE_DIGEST_SHA256.
   *
   * parse_data: [in, opt] #ndn_ecc_pub_t* or #ndn_hmac_key_t* @n
   * Pass public key used by verification.
   */
  TLV_DATAARG_SIGKEY_PTR,

  /**
   * The signature timestamp.
   *
   * make_data: [in] @c uint64_t
   *
   * parse_data: [out] @c uint64_t* @n
   * Output 0 if not included.
   */
  TLV_DATAARG_SIGTIME_U64,

  /**
   * Verify the Data after decoding.
   *
   * make_data: N/A
   *
   * parse_data: [in] @c bool (promoted)
   */
  TLV_DATAARG_VERIFY,
};

/** All-in-one function to generate a Data packet.
 *
 * This function uses variant args to input optional parameters.
 * The value of each variant arg should be given after its type.
 * See #TLV_DATAARG_TYPE for all supported variant arg types.
 * An example:
 * @code{.c}
 * tlv_make_data(buf, sizeof(buf), &output_size, 6, // 6 args following
 *               TLV_DATAARG_NAME_PTR,            &name,
 *               TLV_DATAARG_NAME_SEGNO_U64,      (uint64_t)i
 *               TLV_DATAARG_FRESHNESSPERIOD_U64, (uint64_t)15000,
 *               TLV_DATAARG_FINALBLOCKID_U64,    (uint64_t)(seg_count - 1),
 *               TLV_DATAARG_CONTENT_BUF,         content,
 *               TLV_DATAARG_CONTENT_SIZE,        sizeof(content));
 * // Create a Data packet with its payload = content,
 * // name = name + i (segment number), freshness period = 15s.
 * // And the data have seg_count segments in total.
 * @endcode
 * @param[out] buf The buffer where Data is stored. @c result_size bytes are written.
 * @param[in] buflen The available size of @c buf.
 * @param[out] result_size [Optional] The encoded size of the Data packet.
 * @param[in] argc The number of variant args, without counting the type.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_INVALID_ARG An unknown argument is given; or no name is given.
 * @retval #NDN_SEC_UNSUPPORT_SIGN_TYPE Unsupported signature type.
 * @retval #NDN_INVALID_POINTER A non-optional pointer argument is @c NULL.
 *                              Notice that some arguments are allowed to be @c NULL.
 * @post <tt>result_size <= buflen</tt>
 * @remark Not fully tested yet. Besides, the ideal solution is to allow users pass
 *         NULL to @c buf to get @c result_size only, but this is not possible under
 *         current back end.
 */
int
tlv_make_data(uint8_t* buf, size_t buflen, size_t* result_size, int argc, ...);

/** All-in-one function to parse a Data packet.
 *
 * This function uses variant args as input and output optional parameters.
 * The value of each variant arg should be given after its type.
 * See #TLV_DATAARG_TYPE for all supported variant arg types.
 * An example:
 * @code{.c}
 * ndn_name_t name;
 * uint64_t segno, last_segno;
 * uint8_t *content;
 * size_t content_size;
 * tlv_parse_data(data_buf, data_size, 6,  // 6 args following
 *                TLV_DATAARG_NAME_PTR,         &name,
 *                TLV_DATAARG_NAME_SEGNO_U64,   &segno,
 *                TLV_DATAARG_FINALBLOCKID_U64, &last_segno,
 *                TLV_DATAARG_CONTENT_BUF,      &content,
 *                TLV_DATAARG_CONTENT_SIZE,     &content_size,
 *                TLV_DATAARG_VERIFY,           true);
 * Do not allocate any space for content buffer pointer. Only the address of the buffer pointer is needed.
 * @endcode
 * @param[in] buf The encoded TLV Data block.
 * @param[in] buflen The size of @c buf.
 * @param[in] argc The number of variant args, without counting the type.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_INVALID_ARG An unknown argument is given.
 * @retval #NDN_UNSUPPORTED_FORMAT Unsupported Data format.
 * @retval #NDN_SEC_UNSUPPORT_SIGN_TYPE Unsupported signature type.
 * @retval #NDN_INVALID_POINTER A non-optional pointer argument is @c NULL.
 *                              Notice that some arguments are allowed to be @c NULL.
 * @remark Not fully tested yet.
 */
int
tlv_parse_data(uint8_t* buf, size_t buflen, int argc, ...);

/**
 * The type of variant args of #tlv_make_interest.
 */
enum TLV_INTARG_TYPE{
  /**
   * A pointer to a name.
   *
   * make_interest: [in] #ndn_name_t* @n
   * At least one Name is necessary, otherwise #NDN_INVALID_ARG is returned.
   * If multiple names are specified by mistake, the last one is used.
   *
   * parse_interest: [out] #ndn_name_t*
   */
  TLV_INTARG_NAME_PTR,

  /**
   * A pointer to an encoded TLV name.
   *
   * make_interest: [in] @c uint8_t* @n
   * It will automaticaly detect the length.
   *
   * parse_interest: [out] @c uint8_t** @n
   * Output a pointer to where the name starts in @c buf.
   */
  TLV_INTARG_NAME_BUF,

  /**
   * Segment number.
   *
   * make_interest: [in] @c uint64_t @n
   * It will be added after name.
   *
   * parse_interest: [out] @c uint64_t* @n
   * Output (uint64_t)-1 if the last component is not segment number.
   */
  TLV_INTARG_NAME_SEGNO_U64,

  /**
   * CanBePrefix.
   *
   * make_interest: [in] @c bool (promoted) @n
   * False by default.
   *
   * parse_interest: [out] @c bool*
   */
  TLV_INTARG_CANBEPREFIX_BOOL,

  /**
   * MustBeFresh.
   *
   * make_interest: [in] @c bool (promoted) @n
   * False by default.
   *
   * parse_interest: [out] @c bool*
   */
  TLV_INTARG_MUSTBEFRESH_BOOL,

  /**
   * Interest lifetime in milliseconds.
   *
   * make_interest: [in] @c uint64_t @n
   * #NDN_DEFAULT_INTEREST_LIFETIME by default.
   *
   * parse_interest: [out] @c uint64_t*
   */
  TLV_INTARG_LIFETIME_U64,

  /**
   * Interest HopLimit.
   *
   * make_interest: [in] @c uint8_t (promoted)
   *
   * parse_interest: [out] @c uint8_t*
   * <tt>(uint8_t)-1</tt> by default.
   */
  TLV_INTARG_HOTLIMIT_U8,

  /**
   * Interest parameters.
   *
   * make_interest: [in, opt] @c uint8_t*
   *
   * parse_interest: [out] @c uint8_t** @n
   * Output a pointer to where the Interest parameters start in @c buf.
   * @c NULL if not included.
   */
  TLV_INTARG_PARAMS_BUF,

  /**
   * The size of Interest parameters.
   *
   * make_interest: [in] @c size_t
   *
   * parse_interest: [out] @c size_t*
   */
  TLV_INTARG_PARAMS_SIZE,

  /**
   * Signature type.
   *
   * make_interest: [in] @c uint8_t (promoted) @n
   * By default, the Interest won't be signed.
   *
   * parse_interest: [out] @c uint8_t*
   */
  TLV_INTARG_SIGTYPE_U8,

  /**
   * A pointer to the name of identity.
   *
   * make_interest: [in, opt] #ndn_name_t*
   *
   * parse_interest: N/A
   */
  TLV_INTARG_IDENTITYNAME_PTR,

  /**
   * A pointer to the key.
   *
   * make_interest: [in, opt] #ndn_ecc_prv_t* or #ndn_hmac_key_t* @n
   * Not necessary for #NDN_SIG_TYPE_DIGEST_SHA256.
   *
   * parse_interest: [in, opt] #ndn_ecc_prv_t* or #ndn_hmac_key_t* @n
   * Pass public key used by verification.
   */
  TLV_INTARG_SIGKEY_PTR,

  /**
   * Verify the Interest after decoding.
   *
   * make_interest: N/A
   *
   * parse_interest: [in] bool (promoted)
   */
  TLV_INTARG_VERIFY,
};

/** All-in-one function to generate an Interest packet.
 *
 * This function uses variant args to input optional parameters.
 * The value of each variant arg should be given after its type.
 * See #TLV_INTARG_TYPE for all supported variant arg types.
 * An example:
 * @code{.c}
 * tlv_make_interest(buf, sizeof(buf), &output_size, 5, // 5 args following
 *                   TLV_INTARG_NAME_PTR,         &name,
 *                   TLV_INTARG_NAME_SEGNO_U64,   (uint64_t)13,
 *                   TLV_INTARG_CANBEPREFIX_BOOL, true,
 *                   TLV_INTARG_MUSTBEFRESH_BOOL, true,
 *                   TLV_INTARG_LIFETIME_U64,     (uint64_t)60000);
 * // Create a Interest packet with its name = name/%00%13
 * // lifetime = 60s, CanBePrefix and MustBeFresh.
 * @endcode
 * @param[out] buf The buffer where Interest is stored. @c result_size bytes are written.
 * @param[in] buflen The available size of @c buf.
 * @param[out] result_size [Optional] The encoded size of the Interest packet.
 * @param[in] argc The number of variant args, without counting the type.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_INVALID_ARG An unknown argument is given; or no name is given.
 * @retval #NDN_SEC_UNSUPPORT_SIGN_TYPE Unsupported signature type.
 * @retval #NDN_INVALID_POINTER A non-optional pointer argument is @c NULL.
 *                              Notice that some arguments are allowed to be @c NULL.
 * @post <tt>result_size <= buflen</tt>
 * @remark Not fully tested yet. Besides, the ideal solution is to allow users pass
 *         NULL to @c buf to get @c result_size only, but this is not possible under
 *         current back end.
 */
int
tlv_make_interest(uint8_t* buf, size_t buflen, size_t* result_size, int argc, ...);

/** All-in-one function to parse an Interest packet.
 *
 * This function uses variant args as input and output optional parameters.
 * The value of each variant arg should be given after its type.
 * See #TLV_INTARG_TYPE for all supported variant arg types.
 * An example:
 * @code{.c}
 * ndn_name_t name;
 * uint64_t segno;
 * tlv_parse_data(interest_buf, interest_size, 2,     // 2 args following
 *                TLV_INTARG_NAME_PTR,       &name,
 *                TLV_INTARG_NAME_SEGNO_U64, &segno);
 * Do not allocate any space for content buffer pointer. Only the address of the buffer pointer is needed.
 * @endcode
 * @param[in] buf The encoded TLV Interest block.
 * @param[in] buflen The size of @c buf.
 * @param[in] argc The number of variant args, without counting the type.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_INVALID_ARG An unknown argument is given.
 * @retval #NDN_UNSUPPORTED_FORMAT Unsupported Interest format.
 * @retval #NDN_SEC_UNSUPPORT_SIGN_TYPE Unsupported signature type.
 * @retval #NDN_INVALID_POINTER A non-optional pointer argument is @c NULL.
 *                              Notice that some arguments are allowed to be @c NULL.
 * @remark Not fully tested yet.
 */
int
tlv_parse_interest(uint8_t* buf, size_t buflen, int argc, ...);

/** Encode a name component from a segment number.
 *
 * @param[out] comp Target component.
 * @param[in] val The segment number.
 */
void
tlv_encode_segno(name_component_t* comp, uint64_t val);

/** Decode a name component into a segment number.
 *
 * @param[in] comp Target component.
 * @return The segment number. <tt>(uint64_t)-1</tt> if fails.
 */
uint64_t
tlv_decode_segno(name_component_t* comp);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_WRAPPER_API_H
