/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_LIGHT_DATA_H
#define NDN_ENCODING_LIGHT_DATA_H

#include "interest-light.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compare two encoded Data's name with an encode Interest name.
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
ndn_data_interest_compare_block(ndn_decoder_t* data_decoder, ndn_decoder_t* interest_decoder);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_LIGHT_DATA_H
