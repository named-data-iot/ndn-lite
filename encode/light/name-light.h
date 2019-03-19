/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_LIGHT_NAME_H
#define NDN_ENCODING_LIGHT_NAME_H

#include "../decoder.h"
#include "../tlv.h"
#include "../../ndn-error-code.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************/
/*  Ultra Lightweight Encoding Functions                    */
/************************************************************/

/**
 * Compare two encoded Names.
 * @param lhs_block_value. Input. Left-hand-side encoded Name block value.
 * @param lhs_block_size. Input. Left-hand-side encoded Name block size.
 * @param rhs_block_value. Input. Right-hand-side encoded Name block value.
 * @param rhs_block_size. Input. Right-hand-side encoded Name block size.
 * @return 0 if @p lhs == @p rhs.
 * @return 1, if @p lhs > @p rhs and @p rhs is not a prefix of @p lhs.
 * @return 2, if @p lhs > @p rhs and @p rhs is a proper prefix of @p lhs.
 * @return -1, if @p lhs < @p rhs and @p lhs is not a prefix of @p rhs.
 * @return -2, if @p lhs < @p rhs and @p lhs is a proper prefix of @p rhs.
 */
int
ndn_name_compare_block(ndn_decoder_t* lhs_decoder, ndn_decoder_t* rhs_decoder);

/**
 * Probe the size of a Name TLV block before encoding it from URI.
 * This function is used to check whether the output buffer size is enough or not.
 * @param name. Input. URI to be probed.
 * @return the length of the expected Name TLV block if no errors occur.
 */
int
ndn_name_uri_tlv_probe_size(const char* uri, uint32_t len);

/**
 * Encode the URI into wire format (TLV block). This function will do memory copy.
 * Need to call ndn_name_uri_probe_block_size() to initialize encoder in advance.
 * @param encoder. Output. The encoder who keeps the encoding result and the state.
 * @param uri. Input. The URI to be encoded.
 * @param len. Input. Legnth of the string.
 * @return 0 if there is no error.
 */
int
ndn_name_uri_tlv_encode(ndn_encoder_t* encoder, const char* uri, uint32_t len);

/**
 * Prints out the TLV name block in URI format.
 * @param decoder Input. Encoded Name to print.
 */
void
ndn_name_print(ndn_decoder_t* decoder);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_LIGHT_NAME_H
