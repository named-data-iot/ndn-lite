/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "data-light.h"

int
ndn_data_interest_compare_block(ndn_decoder_t* data_decoder, ndn_decoder_t* interest_decoder)
{
  if (data_decoder->input_value == NULL || data_decoder->input_size <= 0)
    return NDN_OVERSIZE;
  if (interest_decoder->input_value == NULL || interest_decoder->input_size <= 0)
    return NDN_OVERSIZE;

  uint32_t probe = 0;
  uint32_t data_buffer_size, interest_buffer_size = 0;
  int ret_val = -1;

  /* check Data type */
  decoder_get_type(data_decoder, &probe);
  if (probe != TLV_Data) return NDN_WRONG_TLV_TYPE;

  /* check Interest type */
  decoder_get_type(interest_decoder, &probe);
  if (probe != TLV_Interest) return NDN_WRONG_TLV_TYPE;

  /* check Data buffer length */
  ret_val = decoder_get_length(data_decoder, &data_buffer_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  /* check Interest buffer length */
  ret_val = decoder_get_length(interest_decoder, &interest_buffer_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  ret_val = ndn_name_compare_block(data_decoder, interest_decoder);
  return ret_val;
}
