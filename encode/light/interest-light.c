/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "interest-light.h"

/************************************************************/
/*  Definition of helper functions                          */
/************************************************************/
int
_interest_uri_tlv_probe_size(const char* uri, uint32_t len, uint32_t lifetime)
{
 int ret_val = ndn_name_uri_tlv_probe_size(uri, len);
 if (ret_val < 0) return ret_val;

 uint32_t interest_buffer_size = ret_val;
 // nonce
 interest_buffer_size += 6;
 // life time
 interest_buffer_size += 2 + encoder_probe_uint_length(lifetime); // lifetime
 return interest_buffer_size;
}


/************************************************************/
/*     Library Function Interfaces                          */
/************************************************************/
int
ndn_interest_compare_block(ndn_decoder_t* lhs_decoder, ndn_decoder_t* rhs_decoder)
{
 if (lhs_decoder->input_value == NULL || lhs_decoder->input_size <= 0)
   return NDN_OVERSIZE;
 if (rhs_decoder->input_value == NULL || rhs_decoder->input_size <= 0)
   return NDN_OVERSIZE;

 uint32_t probe = 0;
 uint32_t lhs_interest_buffer_length, rhs_interest_buffer_length = 0;
 int ret_val = -1;

 /* check left interest type */
 ret_val = decoder_get_type(lhs_decoder, &probe);
 if (ret_val != NDN_SUCCESS) return ret_val;
 if (probe != TLV_Interest) return NDN_WRONG_TLV_TYPE;

 /* check right interest type */
 ret_val = decoder_get_type(rhs_decoder, &probe);
 if (ret_val != NDN_SUCCESS) return ret_val;
 if (probe != TLV_Interest) return NDN_WRONG_TLV_TYPE;

 /* check left interest buffer length */
 ret_val = decoder_get_length(lhs_decoder, &lhs_interest_buffer_length);
 if (ret_val != NDN_SUCCESS) return ret_val;

 /* check right interest buffer length */
 ret_val = decoder_get_length(rhs_decoder, &rhs_interest_buffer_length);
 if (ret_val != NDN_SUCCESS) return ret_val;

 /* compare Names */
 ret_val = ndn_name_compare_block(lhs_decoder, rhs_decoder);
 return ret_val;
}

int
ndn_interest_name_compare_block(ndn_decoder_t* interest_decoder, ndn_decoder_t* name_decoder)
{
 if (interest_decoder->input_value == NULL || interest_decoder->input_size <= 0)
   return NDN_OVERSIZE;
 if (name_decoder->input_value == NULL || name_decoder->input_size <= 0)
   return NDN_OVERSIZE;

 uint32_t probe, interest_buffer_length = 0;
 int ret_val = -1;

 /* check interest type */
 ret_val = decoder_get_type(interest_decoder, &probe);
 if (probe != TLV_Interest) return NDN_WRONG_TLV_TYPE;

 /* check interest buffer length */
 ret_val = decoder_get_length(interest_decoder, &interest_buffer_length);
 if (ret_val != NDN_SUCCESS) return ret_val;

 /* compare Names */
 ret_val = ndn_name_compare_block(interest_decoder, name_decoder);
 return ret_val;
}

int
ndn_interest_uri_tlv_encode(ndn_encoder_t* encoder, const char* uri, uint32_t len,
                           uint32_t lifetime, uint32_t nonce)
{
 int ret_val = 0;
 if (encoder == NULL || uri == NULL || len <= 0)
   return NDN_OVERSIZE;

 // encode interest header
 encoder_append_type(encoder, TLV_Interest);
 ret_val = _interest_uri_tlv_probe_size(uri, len, lifetime);
 if (ret_val < 0) return ret_val;
 encoder_append_length(encoder, ret_val + encoder_get_var_size(ret_val));

 // encode name
 ret_val = ndn_name_uri_tlv_encode(encoder, uri, len);
 if (ret_val != NDN_SUCCESS) return ret_val;
 // nonce
 ret_val = encoder_append_type(encoder, TLV_Nonce);
 if (ret_val != NDN_SUCCESS) return ret_val;
 ret_val = encoder_append_length(encoder, 4);
 if (ret_val != NDN_SUCCESS) return ret_val;
 ret_val = encoder_append_uint32_value(encoder, nonce);
 if (ret_val != NDN_SUCCESS) return ret_val;
 // lifetime
 ret_val = encoder_append_type(encoder, TLV_InterestLifetime);
 if (ret_val != NDN_SUCCESS) return ret_val;
 ret_val = encoder_append_length(encoder, encoder_probe_uint_length(lifetime));
 if (ret_val != NDN_SUCCESS) return ret_val;
 ret_val = encoder_append_uint_value(encoder, lifetime);
 if (ret_val != NDN_SUCCESS) return ret_val;

 return NDN_SUCCESS;
}
