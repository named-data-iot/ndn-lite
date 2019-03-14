/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_LIGHT_INTEREST_H
#define NDN_ENCODING_LIGHT_INTEREST_H

#include "name-light.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* Compare two encoded Interests' names.
* @param lhs_block_value. Input. Left-hand-side encoded Interest block value.
* @param lhs_block_size. Input. Left-hand-side encoded Interest block size.
* @param rhs_block_value. Input. Right-hand-side encoded Interest block value.
* @param rhs_block_size. Input. Right-hand-side encoded Interest block size.
* @return 0 if @p lhs == @p rhs.
* @return 1, if @p lhs > @p rhs and @p rhs is not a prefix of @p lhs.
* @return 2, if @p lhs > @p rhs and @p rhs is a proper prefix of @p lhs.
* @return -1, if @p lhs < @p rhs and @p lhs is not a prefix of @p rhs.
* @return -2, if @p lhs < @p rhs and @p lhs is a proper prefix of @p rhs.
*/
int
ndn_interest_compare_block(ndn_decoder_t* lhs_decoder, ndn_decoder_t* rhs_decoder);

/**
* Compare two encoded Interests' names.
* @param lhs_block_value. Input. Left-hand-side encoded Interest block value.
* @param lhs_block_size. Input. Left-hand-side encoded Interest block size.
* @param rhs_block_value. Input. Right-hand-side encoded Interest block value.
* @param rhs_block_size. Input. Right-hand-side encoded Interest block size.
* @return 0 if @p lhs == @p rhs.
* @return 1, if @p lhs > @p rhs and @p rhs is not a prefix of @p lhs.
* @return 2, if @p lhs > @p rhs and @p rhs is a proper prefix of @p lhs.
* @return -1, if @p lhs < @p rhs and @p lhs is not a prefix of @p rhs.
* @return -2, if @p lhs < @p rhs and @p lhs is a proper prefix of @p rhs.
*/
int
ndn_interest_name_compare_block(ndn_decoder_t* interest_decoder, ndn_decoder_t* name_decoder);

/**
 * Encode the Interest into wire format (TLV block).
 * This function is only used for unsigned Interest.
 * @param encoder. Output. The encoder who keeps the encoding result and the state.
 * @param uri. Input. URI indicating Name
 * @param len. Input. Length of URI string.
 * @param lifetime. Input. Interest Lifetime.
 * @param nonce. Input. Interest Nonce.
 * @return 0 if there is no error.
 */
int
ndn_interest_uri_tlv_encode(ndn_encoder_t* encoder, const char* uri, uint32_t len,
                           uint32_t lifetime, uint32_t nonce);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_LIGHT_INTEREST_H
